/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *   Anup Patel <anup.patel@wdc.com>
 */

#ifndef __RISCV_FP_H__
#define __RISCV_FP_H__

#include <sbi/riscv_asm.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_types.h>

#define GET_PRECISION(insn) (((insn) >> 25) & 3)
#define PRECISION_S 0
#define PRECISION_D 1

#ifdef __riscv_flen

#define GET_F32_REG(insn, pos, regs)                                                                    \
	({                                                                                              \
		register s32 value asm("a0") =                                                          \
			SHIFT_RIGHT(insn, (pos)-3) & 0xf8;                                              \
		ulong tmp;                                                                              \
		asm("1: auipc %0, %%pcrel_hi(get_f32_reg); add %0, %0, %1; jalr t0, %0, %%pcrel_lo(1b)" \
		    : "=&r"(tmp), "+&r"(value)::"t0");                                                  \
		value;                                                                                  \
	})
#define SET_F32_REG(insn, pos, regs, val)                                                                   \
	({                                                                                                  \
		register u32 value asm("a0") = (val);                                                       \
		ulong offset = SHIFT_RIGHT(insn, (pos)-3) & 0xf8;                                           \
		ulong tmp;                                                                                  \
		asm volatile(                                                                               \
			"1: auipc %0, %%pcrel_hi(put_f32_reg); add %0, %0, %2; jalr t0, %0, %%pcrel_lo(1b)" \
			: "=&r"(tmp)                                                                        \
			: "r"(value), "r"(offset)                                                           \
			: "t0");                                                                            \
	})
#define init_fp_reg(i) SET_F32_REG((i) << 3, 3, 0, 0)

#if __riscv_xlen == 64
#define GET_F64_REG(insn, pos, regs)                                                                    \
	({                                                                                              \
		register ulong value asm("a0") = SHIFT_RIGHT(insn, (pos)-3) & 0xf8;                     \
		ulong tmp;                                                                              \
		asm("1: auipc %0, %%pcrel_hi(get_f64_reg); add %0, %0, %1; jalr t0, %0, %%pcrel_lo(1b)" \
		    : "=&r"(tmp), "+&r"(value)::"t0");                                                  \
		value;                                                                                  \
	})
#else
#define GET_F64_REG(insn, pos, regs)                                                                     \
	({                                                                                               \
		u64 value;                                                                               \
		ulong offset = SHIFT_RIGHT(insn, (pos)-3) & 0xf8;                                        \
		register ulong ptr asm("a0") = (ulong)&value;                                            \
		asm ("1: auipc t1, %%pcrel_hi(get_f64_reg); add t1, t1, %2; jalr t0, t1, %%pcrel_lo(1b)" \
		    : "=m"(value) : "r"(ptr), "r"(offset) : "t0", "t1");                                 \
		value;                                                                                   \
	})
#endif

#define SET_F64_REG(insn, pos, regs, val)                                                                   \
	({                                                                                                  \
		uint64_t __val = (val);                                                                     \
		register ulong value asm("a0") =                                                            \
			sizeof(ulong) == 4 ? (ulong)&__val : (ulong)__val;                                  \
		ulong offset = SHIFT_RIGHT(insn, (pos)-3) & 0xf8;                                           \
		ulong tmp;                                                                                  \
		asm volatile(                                                                               \
			"1: auipc %0, %%pcrel_hi(put_f64_reg); add %0, %0, %2; jalr t0, %0, %%pcrel_lo(1b)" \
			: "=&r"(tmp)                                                                        \
			: "r"(value), "r"(offset)                                                           \
			: "t0");                                                                            \
	})

#define GET_F16_REG(insn, pos, regs)                      \
	({                                                \
		u32 value = GET_F32_REG(insn, pos, regs); \
		if ((value & 0xffff0000) != 0xffff0000)   \
			value = 0x7c00;                   \
		(u16) value;                              \
	})

#define SET_F16_REG(insn, pos, regs, val) \
	(SET_F32_REG(insn, pos, regs, (val) | 0xffff0000))

#define GET_FCSR() csr_read(CSR_FCSR)
#define SET_FCSR(value) csr_write(CSR_FCSR, (value))
#define GET_FRM() csr_read(CSR_FRM)
#define SET_FRM(value) csr_write(CSR_FRM, (value))
#define GET_FFLAGS() csr_read(CSR_FFLAGS)
#define SET_FFLAGS(value) csr_write(CSR_FFLAGS, (value))

#define SET_FS_DIRTY(regs) (regs->mstatus |= MSTATUS_FS)

#define GET_F32_RS1(insn, regs) (GET_F32_REG(insn, 15, regs))
#define GET_F32_RS2(insn, regs) (GET_F32_REG(insn, 20, regs))
#define GET_F32_RS3(insn, regs) (GET_F32_REG(insn, 27, regs))
#define GET_F64_RS1(insn, regs) (GET_F64_REG(insn, 15, regs))
#define GET_F64_RS2(insn, regs) (GET_F64_REG(insn, 20, regs))
#define GET_F64_RS3(insn, regs) (GET_F64_REG(insn, 27, regs))
#define GET_F16_RS1(insn, regs) (GET_F16_REG(insn, 15, regs))
#define GET_F16_RS2(insn, regs) (GET_F16_REG(insn, 20, regs))
#define GET_F16_RS3(insn, regs) (GET_F16_REG(insn, 27, regs))

#define SET_F32_RD(insn, regs, val) \
	(SET_F32_REG(insn, 7, regs, val), SET_FS_DIRTY(regs))
#define SET_F64_RD(insn, regs, val) \
	(SET_F64_REG(insn, 7, regs, val), SET_FS_DIRTY(regs))
#define SET_F16_RD(insn, regs, val) \
	(SET_F16_REG(insn, 7, regs, val), SET_FS_DIRTY(regs))

#define GET_F32_RS2C(insn, regs) (GET_F32_REG(insn, 2, regs))
#define GET_F32_RS2S(insn, regs) (GET_F32_REG(RVC_RS2S(insn), 0, regs))
#define GET_F64_RS2C(insn, regs) (GET_F64_REG(insn, 2, regs))
#define GET_F64_RS2S(insn, regs) (GET_F64_REG(RVC_RS2S(insn), 0, regs))

#endif

#endif
