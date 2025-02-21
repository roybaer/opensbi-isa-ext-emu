/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Benedikt Freisen.
 *
 * Authors:
 *   Benedikt Freisen <b.freisen@gmx.net>
 */

#ifndef __SBI_INSN_EMU_H__
#define __SBI_INSN_EMU_H__

#include <sbi/sbi_types.h>

#if defined(CONFIG_EMU_ZBB) || defined(CONFIG_EMU_ZBS)
int sbi_insn_emu_op_imm(ulong insn, struct sbi_trap_regs *regs);
#else
#define sbi_insn_emu_op_imm truly_illegal_insn
#endif

#if defined(CONFIG_EMU_ZBA) || defined(CONFIG_EMU_ZBB) ||     \
	defined(CONFIG_EMU_ZBC) || defined(CONFIG_EMU_ZBS) || \
	defined(CONFIG_EMU_ZICOND)
int sbi_insn_emu_op(ulong insn, struct sbi_trap_regs *regs);
#else
#define sbi_insn_emu_op truly_illegal_insn
#endif

#if __riscv_xlen == 64 && (defined(CONFIG_EMU_ZBA) || defined(CONFIG_EMU_ZBB))
int sbi_insn_emu_op_32(ulong insn, struct sbi_trap_regs *regs);
#else
#define sbi_insn_emu_op_32 truly_illegal_insn
#endif

#if __riscv_xlen == 64 && (defined(CONFIG_EMU_ZBA) || defined(CONFIG_EMU_ZBB))
int sbi_insn_emu_op_imm_32(ulong insn, struct sbi_trap_regs *regs);
#else
#define sbi_insn_emu_op_imm_32 truly_illegal_insn
#endif

#ifdef CONFIG_EMU_ZCB
int sbi_insn_emu_c_reserved(ulong insn, struct sbi_trap_regs *regs);
#else
#define sbi_insn_emu_c_reserved truly_illegal_insn
#endif

#ifdef CONFIG_EMU_ZCB
int sbi_insn_emu_c_misc_alu(ulong insn, struct sbi_trap_regs *regs);
#else
#define sbi_insn_emu_c_misc_alu truly_illegal_insn
#endif

#ifdef CONFIG_EMU_ZCMOP
int sbi_insn_emu_c_mop(ulong insn, struct sbi_trap_regs *regs);
#else
#define sbi_insn_emu_c_mop truly_illegal_insn
#endif

#if defined(CONFIG_EMU_ZICBOM) || defined(CONFIG_EMU_ZICBOZ)
int sbi_insn_emu_zicbom_zicboz(ulong insn, struct sbi_trap_regs *regs);
#else
#define sbi_insn_emu_zicbom_zicboz truly_illegal_insn
#endif

#endif
