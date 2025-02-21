/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Benedikt Freisen.
 *
 * Authors:
 *   Benedikt Freisen <b.freisen@gmx.net>
 */

#ifndef __SBI_INSN_EMU_FP_H__
#define __SBI_INSN_EMU_FP_H__

#include <sbi/sbi_types.h>

int sbi_insn_emu_load_fp(ulong insn, struct sbi_trap_regs *regs);
int sbi_insn_emu_store_fp(ulong insn, struct sbi_trap_regs *regs);
int sbi_insn_emu_op_fp(ulong insn, struct sbi_trap_regs *regs);

#endif
