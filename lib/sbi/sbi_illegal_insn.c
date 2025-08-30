/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates.
 * Copyright (c) 2025 Benedikt Freisen*.
 *
 * Authors:
 *   Anup Patel <anup.patel@wdc.com>
 *   Benedikt Freisen <b.freisen@gmx.net>
 *
 * *) ISA extension emulation
 */

#include <sbi/riscv_asm.h>
#include <sbi/riscv_barrier.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_bitops.h>
#include <sbi/sbi_emulate_csr.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_illegal_atomic.h>
#include <sbi/sbi_illegal_insn.h>
#include <sbi/sbi_insn_emu.h>
#include <sbi/sbi_insn_emu_fp.h>
#include <sbi/sbi_insn_emu_v.h>
#include <sbi/sbi_pmu.h>
#include <sbi/sbi_trap.h>
#include <sbi/sbi_unpriv.h>
#include <sbi/sbi_console.h>

int truly_illegal_insn(ulong insn, struct sbi_trap_regs *regs)
{
	struct sbi_trap_info trap;

	trap.cause = CAUSE_ILLEGAL_INSTRUCTION;
	trap.tval  = insn;
	trap.tval2 = 0;
	trap.tinst = 0;
	trap.gva   = 0;

	return sbi_trap_redirect(regs, &trap);
}

static int misc_mem_opcode_insn(ulong insn, struct sbi_trap_regs *regs)
{
	/* Errata workaround: emulate `fence.tso` as `fence rw, rw`. */
	if ((insn & INSN_MASK_FENCE_TSO) == INSN_MATCH_FENCE_TSO) {
		smp_mb();
		regs->mepc += 4;
		return 0;
	}

	/* Errata workaround: C906, C910 fail to ignore reserved fields
	 * in the `fence` and `fence.i` encodings. [Thomas2024RISCVuzz] */
	if ((insn & INSN_MASK_FENCE) == INSN_MATCH_FENCE) {
		/* NOTE: Emulation should ideally preserve the `pred` and
		 * `succ` fields, but that is not easily possible here. */
		mb();
		regs->mepc += 4;
		return 0;
	}
	if ((insn & INSN_MASK_FENCE_I) == INSN_MATCH_FENCE_I) {
		RISCV_FENCE_I;
		regs->mepc += 4;
		return 0;
	}

	/* Delegate Zicbom and Zicboz emulation */
	return sbi_insn_emu_zicbom_zicboz(insn, regs);
}

static int system_opcode_insn(ulong insn, struct sbi_trap_regs *regs)
{
	bool do_write	= false;
	int rs1_num	= GET_RS1_NUM(insn);
	ulong rs1_val	= GET_RS1(insn, regs);
	int csr_num	= GET_CSR_NUM((u32)insn);
	ulong prev_mode = sbi_mstatus_prev_mode(regs->mstatus);
	ulong csr_val, new_csr_val;

	if (prev_mode == PRV_M) {
		sbi_printf("%s: Failed to access CSR %#x from M-mode", __func__,
			   csr_num);
		return SBI_EFAIL;
	}

	/* Ensure that we got CSR read/write instruction */
	int funct3 = GET_RM(insn);
	if (funct3 == 0 || funct3 == 4) {
		/* Handle "Zawrs" Wait-on-Reservation-Set */
		if (insn == INSN_MATCH_WRS_NTO || insn == INSN_MATCH_WRS_STO) {
			/* do nothing */
			regs->mepc += 4;
			return 0;
		}
		/* Handle "Zimop" May-Be-Operations */
		if ((insn & INSN_MASK_MOP_R_N) == INSN_MATCH_MOP_R_N ||
		    (insn & INSN_MASK_MOP_RR_N) == INSN_MATCH_MOP_RR_N) {
			SET_RD(insn, regs, 0);
			regs->mepc += 4;
			return 0;
		}

		/* Otherwise treat this as an error */
		sbi_printf("%s: Invalid opcode for CSR read/write instruction",
			   __func__);
		return truly_illegal_insn(insn, regs);
	}

	if (sbi_emulate_csr_read(csr_num, regs, &csr_val))
		return truly_illegal_insn(insn, regs);

	switch (funct3) {
	case CSRRW:
		new_csr_val = rs1_val;
		do_write    = true;
		break;
	case CSRRS:
		new_csr_val = csr_val | rs1_val;
		do_write    = (rs1_num != 0);
		break;
	case CSRRC:
		new_csr_val = csr_val & ~rs1_val;
		do_write    = (rs1_num != 0);
		break;
	case CSRRWI:
		new_csr_val = rs1_num;
		do_write    = true;
		break;
	case CSRRSI:
		new_csr_val = csr_val | rs1_num;
		do_write    = (rs1_num != 0);
		break;
	case CSRRCI:
		new_csr_val = csr_val & ~rs1_num;
		do_write    = (rs1_num != 0);
		break;
	default:
		return truly_illegal_insn(insn, regs);
	}

	if (do_write && sbi_emulate_csr_write(csr_num, regs, new_csr_val))
		return truly_illegal_insn(insn, regs);

	SET_RD(insn, regs, csr_val);

	regs->mepc += 4;

	return 0;
}

static const illegal_insn_func illegal_insn_table[32] = {
	truly_illegal_insn,	/* 0 */
	sbi_insn_emu_load_fp,	/* 1 */
	truly_illegal_insn,	/* 2 */
	misc_mem_opcode_insn,	/* 3 */
	sbi_insn_emu_op_imm,	/* 4 */
	truly_illegal_insn,	/* 5 */
	sbi_insn_emu_op_imm_32, /* 6 */
	truly_illegal_insn,	/* 7 */
	truly_illegal_insn,	/* 8 */
	sbi_insn_emu_store_fp,	/* 9 */
	truly_illegal_insn,	/* 10 */
	sbi_illegal_atomic,	/* 11 */
	sbi_insn_emu_op,	/* 12 */
	truly_illegal_insn,	/* 13 */
	sbi_insn_emu_op_32,	/* 14 */
	truly_illegal_insn,	/* 15 */
	truly_illegal_insn,	/* 16 */
	truly_illegal_insn,	/* 17 */
	truly_illegal_insn,	/* 18 */
	truly_illegal_insn,	/* 19 */
	sbi_insn_emu_op_fp,	/* 20 */
	sbi_insn_emu_op_v,	/* 21 */
	truly_illegal_insn,	/* 22 */
	truly_illegal_insn,	/* 23 */
	truly_illegal_insn,	/* 24 */
	truly_illegal_insn,	/* 25 */
	truly_illegal_insn,	/* 26 */
	truly_illegal_insn,	/* 27 */
	system_opcode_insn,	/* 28 */
	truly_illegal_insn,	/* 29 */
	truly_illegal_insn,	/* 30 */
	truly_illegal_insn	/* 31 */
};

static const illegal_insn_func illegal_insn16_table[24] = {
	truly_illegal_insn,	 /* 0 */
	truly_illegal_insn,	 /* 1 */
	truly_illegal_insn,	 /* 2 */
	truly_illegal_insn,	 /* 3 */
	sbi_insn_emu_c_reserved, /* 4 */
	truly_illegal_insn,	 /* 5 */
	truly_illegal_insn,	 /* 6 */
	truly_illegal_insn,	 /* 7 */
	truly_illegal_insn,	 /* 8 */
	truly_illegal_insn,	 /* 9 */
	truly_illegal_insn,	 /* 10 */
	sbi_insn_emu_c_mop,	 /* 11 */
	sbi_insn_emu_c_misc_alu, /* 12 */
	truly_illegal_insn,	 /* 13 */
	truly_illegal_insn,	 /* 14 */
	truly_illegal_insn,	 /* 15 */
	truly_illegal_insn,	 /* 16 */
	truly_illegal_insn,	 /* 17 */
	truly_illegal_insn,	 /* 18 */
	truly_illegal_insn,	 /* 19 */
	truly_illegal_insn,	 /* 20 */
	truly_illegal_insn,	 /* 21 */
	truly_illegal_insn,	 /* 22 */
	truly_illegal_insn	 /* 23 */
};

int sbi_illegal_insn_handler(struct sbi_trap_context *tcntx)
{
	struct sbi_trap_regs *regs = &tcntx->regs;
	ulong insn		   = tcntx->trap.tval;
	struct sbi_trap_info uptrap;

	/*
	 * We only deal with 32-bit (or longer) illegal instructions directly.
	 * If we see instruction is zero OR instruction is 16-bit then we fetch
	 * and check the instruction encoding using unprivilege access.
	 *
	 * The program counter (PC) in RISC-V world is always 2-byte aligned
	 * so handling only 32-bit (or longer) illegal instructions also help
	 * the case where MTVAL CSR contains instruction address for illegal
	 * instruction trap.
	 */

	sbi_pmu_ctr_incr_fw(SBI_PMU_FW_ILLEGAL_INSN);
	if (unlikely((insn & 3) != 3)) {
		insn = sbi_get_insn(regs->mepc, &uptrap);
		if (uptrap.cause)
			return sbi_trap_redirect(regs, &uptrap);
		if ((insn & 3) != 3)
			return illegal_insn16_table[(insn & 3) << 3 |
						    insn >> 13](insn, regs);
	}

	return illegal_insn_table[(insn & 0x7c) >> 2](insn, regs);
}
