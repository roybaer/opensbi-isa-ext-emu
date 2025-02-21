/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Benedikt Freisen.
 *
 * Authors:
 *   Benedikt Freisen <b.freisen@gmx.net>
 */

#ifndef __SBI_INSN_EMU_V_H__
#define __SBI_INSN_EMU_V_H__

#include <sbi/sbi_types.h>

#if __riscv_xlen == 64
int sbi_insn_emu_op_v(ulong insn, struct sbi_trap_regs *regs);
#else
#define sbi_insn_emu_op_v truly_illegal_insn
#endif

#endif
