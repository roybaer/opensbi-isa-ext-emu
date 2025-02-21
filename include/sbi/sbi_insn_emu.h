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

int sbi_insn_emu_op_imm(ulong insn, struct sbi_trap_regs *regs);
int sbi_insn_emu_op(ulong insn, struct sbi_trap_regs *regs);
int sbi_insn_emu_op_32(ulong insn, struct sbi_trap_regs *regs);
int sbi_insn_emu_op_imm_32(ulong insn, struct sbi_trap_regs *regs);
int sbi_insn_emu_c_reserved(ulong insn, struct sbi_trap_regs *regs);
int sbi_insn_emu_c_mop(ulong insn, struct sbi_trap_regs *regs);
int sbi_insn_emu_c_misc_alu(ulong insn, struct sbi_trap_regs *regs);
int sbi_insn_emu_zicbom_zicboz(ulong insn, struct sbi_trap_regs *regs);

#endif
