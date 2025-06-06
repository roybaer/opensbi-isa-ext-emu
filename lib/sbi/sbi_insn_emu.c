/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Benedikt Freisen.
 *
 * Authors:
 *   Benedikt Freisen <b.freisen@gmx.net>
 */

#include <sbi/riscv_encoding.h>
#include <sbi/sbi_illegal_insn.h>
#include <sbi/sbi_trap.h>
#include <sbi/sbi_trap_ldst.h>
#include <sbi/sbi_unpriv.h>

#define MASK_SHAMT32 0x1f
#define MASK_SHAMT (__riscv_xlen - 1)
#define GET_SHAMT32(insn) ((insn >> 20) & MASK_SHAMT32)
#define GET_SHAMT(insn) ((insn >> 20) & MASK_SHAMT)

int sbi_insn_emu_op_imm(ulong insn, struct sbi_trap_context *tcntx)
{
	struct sbi_trap_regs *regs = &tcntx->regs;
	ulong rs1_val		   = GET_RS1(insn, regs);
	ulong rd_val;

	switch (insn & INSN_MASK_RTYPE_RD_RS1_RS2) {
	/* Emulate Zbs immediate instructions */
	case INSN_MATCH_BCLRI:
#if __riscv_xlen == 64
	case INSN_MATCH_BCLRI | 0x02000000:
#endif
		rd_val = rs1_val & ~(1ull << GET_SHAMT(insn));
		break;
	case INSN_MATCH_BEXTI:
#if __riscv_xlen == 64
	case INSN_MATCH_BEXTI | 0x02000000:
#endif
		rd_val = (rs1_val >> GET_SHAMT(insn)) & 1;
		break;
	case INSN_MATCH_BINVI:
#if __riscv_xlen == 64
	case INSN_MATCH_BINVI | 0x02000000:
#endif
		rd_val = rs1_val ^ (1ull << GET_SHAMT(insn));
		break;
	case INSN_MATCH_BSETI:
#if __riscv_xlen == 64
	case INSN_MATCH_BSETI | 0x02000000:
#endif
		rd_val = rs1_val | (1ull << GET_SHAMT(insn));
		break;
	/* Emulate Zbb immediate instructions */
	case INSN_MATCH_RORI:
#if __riscv_xlen == 64
	case INSN_MATCH_RORI | 0x02000000:
#endif
		rd_val = rs1_val >> GET_SHAMT(insn) |
			 rs1_val << (__riscv_xlen - GET_SHAMT(insn));
		break;
	default:
		switch (insn & INSN_MASK_ITYPE_RD_RS) {
		/* Emulate Zbb immediate instructions */
		case INSN_MATCH_CLZ:
			for (rd_val = 0; (long)rs1_val >= 0; rd_val++) {
				rs1_val <<= 1;
				if (rd_val == __riscv_xlen)
					break;
			}
			break;
		case INSN_MATCH_CTZ:
			for (rd_val = 0; (rs1_val & 1) == 0; rd_val++) {
				rs1_val >>= 1;
				if (rd_val == __riscv_xlen)
					break;
			}
			break;
		case INSN_MATCH_CPOP:
			for (rd_val = 0; rs1_val != 0; rs1_val <<= 1) {
				if ((long)rs1_val < 0)
					rd_val++;
			}
			break;
		case INSN_MATCH_ORC_B:
			rd_val = 0;
			for (ulong mask = 0xff; mask != 0; mask <<= 8) {
				if (rs1_val & mask)
					rd_val |= mask;
			}
			break;
#if __riscv_xlen == 64
		case INSN_MATCH_REV8_RV64:
#else
		case INSN_MATCH_REV8_RV32:
#endif
			rd_val = 0;
			for (int i = sizeof(rs1_val) - 1; i >= 0; i--) {
				rd_val <<= 8;
				rd_val |= rs1_val & 0xff;
				rs1_val >>= 8;
			}
			break;
		case INSN_MATCH_SEXT_B:
			rd_val = (long)(s8)rs1_val;
			break;
		case INSN_MATCH_SEXT_H:
			rd_val = (long)(s16)rs1_val;
			break;
		default:
			return truly_illegal_insn(insn, tcntx);
		}
	}

	SET_RD(insn, regs, rd_val);

	regs->mepc += 4;

	return 0;
}

int sbi_insn_emu_op(ulong insn, struct sbi_trap_context *tcntx)
{
	struct sbi_trap_regs *regs = &tcntx->regs;
	ulong rs1_val		   = GET_RS1(insn, regs);
	ulong rs2_val		   = GET_RS2(insn, regs);
	ulong rd_val;

	switch (insn & INSN_MASK_RTYPE_RD_RS1_RS2) {
	/* Emulate Zbs register instructions */
	case INSN_MATCH_BCLR:
		rd_val = rs1_val & ~(1ull << (rs2_val & MASK_SHAMT));
		break;
	case INSN_MATCH_BEXT:
		rd_val = (rs1_val >> (rs2_val & MASK_SHAMT)) & 1;
		break;
	case INSN_MATCH_BINV:
		rd_val = rs1_val ^ (1ull << (rs2_val & MASK_SHAMT));
		break;
	case INSN_MATCH_BSET:
		rd_val = rs1_val | (1ull << (rs2_val & MASK_SHAMT));
		break;
	/* Emulate Zbb register instructions */
	case INSN_MATCH_ANDN:
		rd_val = rs1_val & ~rs2_val;
		break;
	case INSN_MATCH_MAX:
		rd_val = (long)rs1_val > (long)rs2_val ? rs1_val : rs2_val;
		break;
	case INSN_MATCH_MAXU:
		rd_val = rs1_val > rs2_val ? rs1_val : rs2_val;
		break;
	case INSN_MATCH_MIN:
		rd_val = (long)rs1_val < (long)rs2_val ? rs1_val : rs2_val;
		break;
	case INSN_MATCH_MINU:
		rd_val = rs1_val < rs2_val ? rs1_val : rs2_val;
		break;
	case INSN_MATCH_ORN:
		rd_val = rs1_val | ~rs2_val;
		break;
	case INSN_MATCH_ROL:
		rd_val = rs1_val << (rs2_val & MASK_SHAMT) |
			 rs1_val >> (__riscv_xlen - (rs2_val & MASK_SHAMT));
		break;
	case INSN_MATCH_ROR:
		rd_val = rs1_val >> (rs2_val & MASK_SHAMT) |
			 rs1_val << (__riscv_xlen - (rs2_val & MASK_SHAMT));
		break;
	case INSN_MATCH_XNOR:
		rd_val = ~(rs1_val ^ rs2_val);
		break;
	/* Emulate Zba register instructions */
	case INSN_MATCH_SH1ADD:
		rd_val = rs2_val + (rs1_val << 1);
		break;
	case INSN_MATCH_SH2ADD:
		rd_val = rs2_val + (rs1_val << 2);
		break;
	case INSN_MATCH_SH3ADD:
		rd_val = rs2_val + (rs1_val << 3);
		break;
	/* Emulate Zicond instructions */
	case INSN_MATCH_CZERO_EQZ:
		rd_val = rs2_val ? rs1_val : 0;
		break;
	case INSN_MATCH_CZERO_NEZ:
		rd_val = rs2_val ? 0 : rs1_val;
		break;
	default:
		switch (insn & INSN_MASK_ITYPE_RD_RS) {
#if __riscv_xlen == 32
		/* Emulate Zbb register instructions */
		case INSN_MATCH_ZEXT_H_RV32:
			rd_val = (u16)rs1_val;
			break;
#endif
		default:
			return truly_illegal_insn(insn, tcntx);
		}
	}

	SET_RD(insn, regs, rd_val);

	regs->mepc += 4;

	return 0;
}

#if __riscv_xlen == 64
int sbi_insn_emu_op_32(ulong insn, struct sbi_trap_context *tcntx)
{
	struct sbi_trap_regs *regs = &tcntx->regs;
	ulong rs1_val		   = GET_RS1(insn, regs);
	ulong rs2_val		   = GET_RS2(insn, regs);
	ulong rd_val;

	switch (insn & INSN_MASK_RTYPE_RD_RS1_RS2) {
	/* Emulate Zba register word instructions */
	case INSN_MATCH_ADD_UW:
		rd_val = (rs1_val & 0xfffffffful) + rs2_val;
		break;
	case INSN_MATCH_SH1ADD_UW:
		rd_val = rs2_val + ((rs1_val & 0xfffffffful) << 1);
		break;
	case INSN_MATCH_SH2ADD_UW:
		rd_val = rs2_val + ((rs1_val & 0xfffffffful) << 2);
		break;
	case INSN_MATCH_SH3ADD_UW:
		rd_val = rs2_val + ((rs1_val & 0xfffffffful) << 3);
		break;
	/* Emulate Zbb register word instructions */
	case INSN_MATCH_ROLW:
		rd_val = (s64)(s32)((u32)rs1_val << (rs2_val & MASK_SHAMT32) |
				    (u32)rs1_val >>
					    (32 - (rs2_val & MASK_SHAMT32)));
		break;
	case INSN_MATCH_RORW:
		rd_val = (s64)(s32)((u32)rs1_val >> (rs2_val & MASK_SHAMT32) |
				    (u32)rs1_val
					    << (32 - (rs2_val & MASK_SHAMT32)));
		break;
	default:
		switch (insn & INSN_MASK_ITYPE_RD_RS) {
		/* Emulate Zbb register word instructions */
		case INSN_MATCH_ZEXT_H_RV64:
			rd_val = (u16)rs1_val;
			break;
		default:
			return truly_illegal_insn(insn, tcntx);
		}
	}

	SET_RD(insn, regs, rd_val);

	regs->mepc += 4;

	return 0;
}
#else
#define sbi_insn_emu_op_32 sbi_insn_truly_illegal
#endif

#if __riscv_xlen == 64
int sbi_insn_emu_op_imm_32(ulong insn, struct sbi_trap_context *tcntx)
{
	struct sbi_trap_regs *regs = &tcntx->regs;
	ulong rs1_val		   = GET_RS1(insn, regs);
	ulong rd_val;

	switch (insn & INSN_MASK_ITYPE_RD_RS) {
	/* Emulate Zbb immediate word instructions */
	case INSN_MATCH_CLZW:
		for (rd_val = 0; (s32)rs1_val >= 0; rd_val++) {
			rs1_val = (long)(s32)((u32)rs1_val << 1);
			if (rd_val == 32)
				break;
		}
		break;
	case INSN_MATCH_CTZW:
		for (rd_val = 0; (rs1_val & 1) == 0; rd_val++) {
			rs1_val >>= 1;
			if (rd_val == 32)
				break;
		}
		break;
	case INSN_MATCH_CPOPW:
		for (rd_val  = 0; (s32)rs1_val != 0;
		     rs1_val = (long)(s32)(rs1_val << 1)) {
			if ((s32)rs1_val < 0)
				rd_val++;
		}
		break;
	default:
		switch (insn & INSN_MASK_SLLI_UW) {
		/* Emulate Zba immediate word instructions */
		case INSN_MATCH_SLLI_UW:
			rd_val = (ulong)(u32)rs1_val << GET_SHAMT(insn);
			break;
		case INSN_MATCH_RORIW:
			rd_val =
				(s64)(s32)((u32)rs1_val >> GET_SHAMT32(insn) |
					   (u32)rs1_val
						   << (32 - GET_SHAMT32(insn)));
			break;
		default:
			return truly_illegal_insn(insn, tcntx);
		}
	}

	SET_RD(insn, regs, rd_val);

	regs->mepc += 4;

	return 0;
}
#else
#define sbi_insn_emu_op_imm_32 sbi_insn_truly_illegal
#endif

int sbi_insn_emu_c_reserved(ulong insn, struct sbi_trap_context *tcntx)
{
	struct sbi_trap_regs *regs = &tcntx->regs;
	ulong rs1_val		   = GET_RS1S(insn, regs);
	struct sbi_trap_info uptrap;
	ulong val;

	switch (insn & INSN_MASK_C_GENERIC_RXS_RXS) {
	/* Emulate Zcb additional compressed instructions */
	case INSN_MATCH_C_LBU:
		val = sbi_load_u8((void *)rs1_val, &uptrap);
		if (uptrap.cause)
			return sbi_trap_redirect(regs, &uptrap);
		SET_RD2S(insn, regs, val);
		break;
	case INSN_MATCH_C_LBU + 0x40:
		val = sbi_load_u8((void *)rs1_val + 1, &uptrap);
		if (uptrap.cause)
			return sbi_trap_redirect(regs, &uptrap);
		SET_RD2S(insn, regs, val);
		break;
	case INSN_MATCH_C_LBU + 0x20:
		val = sbi_load_u8((void *)rs1_val + 2, &uptrap);
		if (uptrap.cause)
			return sbi_trap_redirect(regs, &uptrap);
		SET_RD2S(insn, regs, val);
		break;
	case INSN_MATCH_C_LBU + 0x60:
		val = sbi_load_u8((void *)rs1_val + 3, &uptrap);
		if (uptrap.cause)
			return sbi_trap_redirect(regs, &uptrap);
		SET_RD2S(insn, regs, val);
		break;
	case INSN_MATCH_C_LHU:
	case INSN_MATCH_C_LHU + 0x20:
		tcntx->trap.cause = CAUSE_MISALIGNED_LOAD;
		tcntx->trap.tval  = rs1_val + ((insn >> 4) & 2);
		return sbi_misaligned_load_handler(tcntx);
	case INSN_MATCH_C_LH:
	case INSN_MATCH_C_LH + 0x20:
		tcntx->trap.cause = CAUSE_MISALIGNED_LOAD;
		tcntx->trap.tval  = rs1_val + ((insn >> 4) & 2);
		return sbi_misaligned_load_handler(tcntx);
	case INSN_MATCH_C_SB:
		val = GET_RS2S(insn, regs);
		sbi_store_u8((void *)rs1_val, val, &uptrap);
		if (uptrap.cause)
			return sbi_trap_redirect(regs, &uptrap);
		break;
	case INSN_MATCH_C_SB + 0x40:
		val = GET_RS2S(insn, regs);
		sbi_store_u8((void *)rs1_val + 1, val, &uptrap);
		if (uptrap.cause)
			return sbi_trap_redirect(regs, &uptrap);
		break;
	case INSN_MATCH_C_SB + 0x20:
		val = GET_RS2S(insn, regs);
		sbi_store_u8((void *)rs1_val + 2, val, &uptrap);
		if (uptrap.cause)
			return sbi_trap_redirect(regs, &uptrap);
		break;
	case INSN_MATCH_C_SB + 0x60:
		val = GET_RS2S(insn, regs);
		sbi_store_u8((void *)rs1_val + 3, val, &uptrap);
		if (uptrap.cause)
			return sbi_trap_redirect(regs, &uptrap);
		break;
	case INSN_MATCH_C_SH:
	case INSN_MATCH_C_SH + 0x20:
		tcntx->trap.cause = CAUSE_MISALIGNED_STORE;
		tcntx->trap.tval  = rs1_val + ((insn >> 4) & 2);
		return sbi_misaligned_store_handler(tcntx);
	default:
		return truly_illegal_insn(insn, tcntx);
	}

	regs->mepc += 2;

	return 0;
}

int sbi_insn_emu_c_mop(ulong insn, struct sbi_trap_context *tcntx)
{
	struct sbi_trap_regs *regs = &tcntx->regs;

	/* Emulate Zcmop compressed may-be operations */
	if ((insn & INSN_MASK_C_MOP_N) == INSN_MATCH_C_MOP_N) {
		/* do nothing */
		regs->mepc += 2;
		return 0;
	}

	return truly_illegal_insn(insn, tcntx);
}

int sbi_insn_emu_c_misc_alu(ulong insn, struct sbi_trap_context *tcntx)
{
	struct sbi_trap_regs *regs = &tcntx->regs;
	ulong rs1_val		   = GET_RS1S(insn, regs);

	switch (insn & INSN_MASK_C_GENERIC_RXS) {
	/* Emulate Zcb additional compressed instructions */
	case INSN_MATCH_C_ZEXT_B:
		SET_RD1S(insn, regs, (u8)rs1_val);
		break;
	case INSN_MATCH_C_SEXT_B:
		SET_RD1S(insn, regs, (long)(s8)rs1_val);
		break;
	case INSN_MATCH_C_ZEXT_H:
		SET_RD1S(insn, regs, (u16)rs1_val);
		break;
	case INSN_MATCH_C_SEXT_H:
		SET_RD1S(insn, regs, (long)(s16)rs1_val);
		break;
#if __riscv_xlen == 64
	case INSN_MATCH_C_ZEXT_W:
		SET_RD1S(insn, regs, (u32)rs1_val);
		break;
#endif
	case INSN_MATCH_C_NOT:
		SET_RD1S(insn, regs, ~rs1_val);
		break;
	default:
		switch (insn & INSN_MASK_C_GENERIC_RXS_RXS) {
		case INSN_MATCH_C_MUL:
			SET_RD1S(insn, regs,
				 (long)rs1_val * (long)GET_RS2S(insn, regs));
			break;
		default:
			return truly_illegal_insn(insn, tcntx);
		}
	}

	regs->mepc += 2;

	return 0;
}
