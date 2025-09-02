/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Benedikt Freisen.
 *
 * Authors:
 *   Benedikt Freisen <b.freisen@gmx.net>
 */

#include <sbi/riscv_encoding.h>
#include <sbi/riscv_fp.h>
#include <sbi/sbi_illegal_insn.h>
#include <sbi/sbi_trap.h>
#include <sbi/sbi_trap_ldst.h>

int sbi_insn_emu_load_fp(ulong insn, struct sbi_trap_regs *regs)
{
	struct sbi_trap_context *tcntx =
		container_of(regs, struct sbi_trap_context, regs);

	/* If floating point is available and insn is FLH,
	 * simply use the misaligned load handler */
	if ((regs->mstatus & MSTATUS_FS) != 0 &&
	    (sbi_mstatus_prev_mode(regs->mstatus) != PRV_U ||
	     (csr_read(CSR_SSTATUS) & SSTATUS_FS) != 0) &&
	    (insn & INSN_MASK_FLH) == INSN_MATCH_FLH) {
		tcntx->trap.cause = CAUSE_MISALIGNED_LOAD;
		tcntx->trap.tval  = GET_RS1(insn, regs) + IMM_I(insn);
		return sbi_misaligned_load_handler(tcntx);
	}

	return truly_illegal_insn(insn, regs);
}

int sbi_insn_emu_store_fp(ulong insn, struct sbi_trap_regs *regs)
{
	struct sbi_trap_context *tcntx =
		container_of(regs, struct sbi_trap_context, regs);

	/* If floating point is available and insn is FSH,
	 * simply use the misaligned store handler */
	if ((regs->mstatus & MSTATUS_FS) != 0 &&
	    (sbi_mstatus_prev_mode(regs->mstatus) != PRV_U ||
	     (csr_read(CSR_SSTATUS) & SSTATUS_FS) != 0) &&
	    (insn & INSN_MASK_FSH) == INSN_MATCH_FSH) {
		tcntx->trap.cause = CAUSE_MISALIGNED_LOAD;
		tcntx->trap.tval  = GET_RS1(insn, regs) + IMM_S(insn);
		return sbi_misaligned_store_handler(tcntx);
	}

	return truly_illegal_insn(insn, regs);
}

static const u16 f16_imm_lut[32] = {
	0xbc00, 0x0400, 0x0100, 0x0200, 0x1c00, 0x2000, 0x2c00, 0x3000,
	0x3400, 0x3500, 0x3600, 0x3700, 0x3800, 0x3900, 0x3a00, 0x3b00,
	0x3c00, 0x3d00, 0x3e00, 0x3f00, 0x4000, 0x4100, 0x4200, 0x4400,
	0x4800, 0x4c00, 0x5800, 0x5c00, 0x7800, 0x7c00, 0x7c00, 0x7e00
};

static const u32 f32_imm_lut[32] = {
	0xbf800000, 0x00800000, 0x37800000, 0x38000000, 0x3b800000, 0x3c000000,
	0x3d800000, 0x3e000000, 0x3e800000, 0x3ea00000, 0x3ec00000, 0x3ee00000,
	0x3f000000, 0x3f200000, 0x3f400000, 0x3f600000, 0x3f800000, 0x3fa00000,
	0x3fc00000, 0x3fe00000, 0x40000000, 0x40200000, 0x40400000, 0x40800000,
	0x41000000, 0x41800000, 0x43000000, 0x43800000, 0x47000000, 0x47800000,
	0x7f800000, 0x7fc00000
};

static const u64 f64_imm_lut[32] = {
	0xbc00000000000000, 0x0010000000000000, 0x3ef0000000000000,
	0x3f00000000000000, 0x3f70000000000000, 0x3f80000000000000,
	0x3fb0000000000000, 0x3fc0000000000000, 0x3fd0000000000000,
	0x3fd4000000000000, 0x3fd8000000000000, 0x3fdc000000000000,
	0x3fe0000000000000, 0x3fe4000000000000, 0x3fe8000000000000,
	0x3fec000000000000, 0x3ff0000000000000, 0x3ff4000000000000,
	0x3ff8000000000000, 0x3ffc000000000000, 0x4000000000000000,
	0x4004000000000000, 0x4008000000000000, 0x4010000000000000,
	0x4020000000000000, 0x4030000000000000, 0x4060000000000000,
	0x4070000000000000, 0x40e0000000000000, 0x40f0000000000000,
	0x7ff0000000000000, 0x7ff8000000000000
};

#define RM_FIELD_RNE 0
#define RM_FIELD_RTZ 1
#define RM_FIELD_RDN 2
#define RM_FIELD_RUP 3
#define RM_FIELD_RMM 4
#define RM_FIELD_DYN 7

#define FFLAG_INEXACT 0x01
#define FFLAG_UNDERFLOW 0x02
#define FFLAG_OVERFLOW 0x04
#define FFLAG_DIVIDE_BY_ZERO 0x08
#define FFLAG_INVALID_OPERATION 0x10

static u32 convert_f16_to_f32(u16 val, u32 *fcsr)
{
	/* special case: +/- zero */
	if ((val & 0x7fff) == 0)
		return (u32)val << 16;
	/* special case: +/- infinity */
	if ((val & 0x7fff) == 0x7c00)
		return ((s32)(s16)val << 13) | 0x7f800000;
	/* special case: NaN => output canonical NaN */
	if ((val & 0x7c00) == 0x7c00) {
		/* handle signaling NaN */
		if ((val & 0x0200) == 0)
			*fcsr |= FFLAG_INVALID_OPERATION;
		/* always return canonical NaN */
		return 0x7fc00000;
	}
	/* generic case or denormalized */
	u32 result = (((s32)(s16)val << 13) & 0x8fffffff) + 0x38000000;
	/* normalize denormalized */
	if ((val & 0x7c00) == 0) {
		u32 signexp = result & 0xff800000;
		result &= 0x007fffff;
		while (!(result & 0x00800000)) {
			signexp -= 0x00800000;
			result <<= 1;
		}
		result = (signexp + 0x00800000) | (result & 0x007fffff);
	}
	return result;
}

static u64 convert_f16_to_f64(u16 val, u32 *fcsr)
{
	/* special case: +/- zero */
	if ((val & 0x7fff) == 0)
		return (u64)val << 48;
	/* special case: +/- infinity */
	if ((val & 0x7fff) == 0x7c00)
		return ((s64)(s16)val << 42) | 0x7ff0000000000000;
	/* special case: NaN => output canonical NaN */
	if ((val & 0x7c00) == 0x7c00) {
		/* handle signaling NaN */
		if ((val & 0x0200) == 0)
			*fcsr |= FFLAG_INVALID_OPERATION;
		/* always return canonical NaN */
		return 0x7ff8000000000000;
	}
	/* generic case or denormalized */
	u64 result = (((s64)(s16)val << 42) & 0x81ffffffffffffff) +
		     0x3f00000000000000;
	/* normalize denormalized */
	if ((val & 0x7c00) == 0) {
		u64 signexp = result & 0xfff0000000000000;
		result &= 0x000fffffffffffff;
		while (!(result & 0x0010000000000000)) {
			signexp -= 0x0010000000000000;
			result <<= 1;
		}
		result = (signexp + 0x0010000000000000) |
			 (result & 0x000fffffffffffff);
	}
	return result;
}

static u16 convert_f32_to_f16(u32 val, u32 *fcsr, int rm)
{
	/* rounding bias to be added below what will be the LSB:
	 * sign, future LSB, rounding mode */
	static const u32 rm_bias[2][2][5] = {
		{ { 0x0fffffff, 0, 0, 0x1fffffff, 0x10000000 },
		  { 0x10000000, 0, 0, 0x1fffffff, 0x10000000 } },
		{ { 0x0fffffff, 0, 0x1fffffff, 0, 0x10000000 },
		  { 0x10000000, 0, 0x1fffffff, 0, 0x10000000 } }
	};

	/* values above the threshold (with masked sign) become infinity,
	 * unless the rounding mode says otherwise.
	 * sign, rounding mode */
	static const u32 inf_threshold[2][5] = {
		{ 0x477fefff, 0x477fffff, 0x477fffff, 0x477fe000, 0x477fefff },
		{ 0x477fefff, 0x477fffff, 0x477fe000, 0x477fffff, 0x477fefff }
	};

	/* the "infinity" value to be used.
	 * sign, rounding mode */
	static const u16 inf_or_max[2][5] = {
		{ 0x7c00, 0x7bff, 0x7bff, 0x7c00, 0x7c00 },
		{ 0xfc00, 0xfbff, 0xfc00, 0xfbff, 0xfc00 }
	};

	/* the "zero" value to be used.
	 * sign, rounding mode */
	static const u16 zero_or_one[2][5] = {
		{ 0x0000, 0x0000, 0x0000, 0x0001, 0x0000 },
		{ 0x8000, 0x8000, 0x8001, 0x8000, 0x8000 }
	};

	/* values below the threshold (with masked sign) become denormalized.
	 * sign, rounding mode */
	static const u32 subnorm_threshold[2][5] = {
		{ 0x387fefff, 0x387fffff, 0x387fffff, 0x387fe000, 0x387fefff },
		{ 0x387fefff, 0x387fffff, 0x387fe000, 0x387fffff, 0x387fefff }
	};

	int sign = val >> 31;

	/* special case: +/- zero */
	if ((val & 0x7fffffff) == 0)
		return val >> 16;
	/* special case: +/- infinity */
	if ((val & 0x7fffffff) == 0x7f800000)
		return (val >> 16) & 0xfc00;
	/* special case for NaN */
	if ((val & 0x7f800000) == 0x7f800000) {
		/* handle signaling NaN */
		if ((val & 0x00400000) == 0)
			*fcsr |= FFLAG_INVALID_OPERATION;
		/* always return canonical NaN */
		return 0x7e00;
	}
	/* replace too small numbers with +/- 0 or +/- 1 */
	if ((val & 0x7f800000) < 0x31800000) {
		*fcsr |= FFLAG_UNDERFLOW | FFLAG_INEXACT;
		return zero_or_one[sign][rm];
	}
	/* replace too big numbers with +/- infinity */
	if ((val & 0x7fffffff) > inf_threshold[sign][rm]) {
		*fcsr |= FFLAG_OVERFLOW | FFLAG_INEXACT;
		return inf_or_max[sign][rm];
	}
	/* handle numbers that become denormalized */
	if ((val & 0x7fffffff) <= subnorm_threshold[sign][rm]) {
		int shiftval = 113 - ((val >> 23) & 0xff);
		u32 mant     = (val & 0x007fffff) | 0x00800000;
		/* set inexact flag if needed */
		if (mant & (0x07ffffff >> (14 - shiftval)))
			*fcsr |= FFLAG_UNDERFLOW | FFLAG_INEXACT;
		return (sign << 15) |
		       ((mant +
			 (rm_bias[sign][(mant >> (13 + shiftval)) & 1][rm] >>
			  (16 - shiftval))) >>
			(13 + shiftval));
	}
	/* no special case */
	if (val & 0x1fff)
		*fcsr |= FFLAG_INEXACT;
	return (sign << 15) | ((((val & 0x7f800000) - 0x38000000) >> 13) +
			       (((val & 0x007fffff) +
				 (rm_bias[sign][(val >> 13) & 1][rm] >> 16)) >>
				13));
}

static u16 convert_f64_to_f16(u64 val, u32 *fcsr, int rm)
{
	/* rounding bias to be added below what will be the LSB:
	 * sign, future LSB, rounding mode */
	static const u64 rm_bias[2][2][5] = {
		{ { 0x1ffffffffffffff, 0, 0, 0x3ffffffffffffff,
		    0x200000000000000 },
		  { 0x200000000000000, 0, 0, 0x3ffffffffffffff,
		    0x200000000000000 } },
		{ { 0x1ffffffffffffff, 0, 0x3ffffffffffffff, 0,
		    0x200000000000000 },
		  { 0x200000000000000, 0, 0x3ffffffffffffff, 0,
		    0x200000000000000 } }
	};

	/* values above the threshold (with masked sign) become infinity,
	 * unless the rounding mode says otherwise.
	 * sign, rounding mode */
	static const u64 inf_threshold[2][5] = {
		{ 0x40effdffffffffff, 0x40efffffffffffff, 0x40efffffffffffff,
		  0x40effc0000000000, 0x40effdffffffffff },
		{ 0x40effdffffffffff, 0x40efffffffffffff, 0x40effc0000000000,
		  0x40efffffffffffff, 0x40effdffffffffff }
	};

	/* the "infinity" value to be used.
	 * sign, rounding mode */
	static const u16 inf_or_max[2][5] = {
		{ 0x7c00, 0x7bff, 0x7bff, 0x7c00, 0x7c00 },
		{ 0xfc00, 0xfbff, 0xfc00, 0xfbff, 0xfc00 }
	};

	/* the "zero" value to be used.
	 * sign, rounding mode */
	static const u16 zero_or_one[2][5] = {
		{ 0x0000, 0x0000, 0x0000, 0x0001, 0x0000 },
		{ 0x8000, 0x8000, 0x8001, 0x8000, 0x8000 }
	};

	/* values below the threshold (with masked sign) become denormalized.
	 * sign, rounding mode */
	static const u64 subnorm_threshold[2][5] = {
		{ 0x3f0ffdffffffffff, 0x3f0fffffffffffff, 0x3f0fffffffffffff,
		  0x3f0ffc0000000000, 0x3f0ffdffffffffff },
		{ 0x3f0ffdffffffffff, 0x3f0fffffffffffff, 0x3f0ffc0000000000,
		  0x3f0fffffffffffff, 0x3f0ffdffffffffff }
	};

	int sign = val >> 63;

	/* special case: +/- zero */
	if ((val & 0x7fffffffffffffff) == 0)
		return val >> 48;
	/* special case: +/- infinity */
	if ((val & 0x7fffffffffffffff) == 0x7ff0000000000000)
		return (val >> 48) & 0xfc00;
	/* special case for NaN */
	if ((val & 0x7ff0000000000000) == 0x7ff0000000000000) {
		/* handle signaling NaN */
		if ((val & 0x0008000000000000) == 0)
			*fcsr |= FFLAG_INVALID_OPERATION;
		/* always return canonical NaN */
		return 0x7e00;
	}
	/* replace too small numbers with +/- 0 or +/- 1 */
	if ((val & 0x7ff0000000000000) < 0x3e30000000000000) {
		*fcsr |= FFLAG_UNDERFLOW | FFLAG_INEXACT;
		return zero_or_one[sign][rm];
	}
	/* replace too big numbers with +/- infinity */
	if ((val & 0x7fffffffffffffff) > inf_threshold[sign][rm]) {
		*fcsr |= FFLAG_OVERFLOW | FFLAG_INEXACT;
		return inf_or_max[sign][rm];
	}
	/* handle numbers that become denormalized */
	if ((val & 0x7fffffffffffffff) <= subnorm_threshold[sign][rm]) {
		unsigned shiftval = 1009 - ((val >> 52) & 0x7ff);
		u64 mant = (val & 0x000fffffffffffff) | 0x0010000000000000;
		/* set inexact flag if needed */
		if (mant & (0x00ffffffffffffff >> (14 - shiftval)))
			*fcsr |= FFLAG_UNDERFLOW | FFLAG_INEXACT;
		return (sign << 15) |
		       ((mant +
			 (rm_bias[sign][(mant >> (42 + shiftval)) & 1][rm] >>
			  (16 - shiftval))) >>
			(42 + shiftval));
	}
	/* no special case */
	if (val & 0x3ffffffffff)
		*fcsr |= FFLAG_INEXACT;
	return (sign << 15) |
	       ((((val & 0x7ff0000000000000) - 0x3f00000000000000) >> 42) +
		(((val & 0x000fffffffffffff) +
		  (rm_bias[sign][(val >> 42) & 1][rm] >> 16)) >>
		 42));
}

static u32 round_f32(u32 val, u32 *fcsr, int rm, bool set_nx)
{
	/* rounding bias to be added below what will be the LSB:
	 * sign, future LSB, rounding mode */
	static const u32 rm_bias[2][2][5] = {
		{ { 0x3fffff, 0x000000, 0x000000, 0x7fffff, 0x400000 },
		  { 0x400000, 0x000000, 0x000000, 0x7fffff, 0x400000 } },
		{ { 0x3fffff, 0x000000, 0x7fffff, 0x000000, 0x400000 },
		  { 0x400000, 0x000000, 0x7fffff, 0x000000, 0x400000 } }
	};

	/* values >= this (with masked sign) become at least +/- 1
	 * sign, rounding mode */
	static const u32 one_threshold[2][5] = {
		{ 0x3effffff, 0x3f800000, 0x3f800000, 1, 0x3f000000 },
		{ 0x3effffff, 0x3f800000, 1, 0x3f800000, 0x3f000000 }
	};

	/* handle +/- zero */
	if ((val & 0x7fffffff) == 0)
		return val;
	/* handle NaNs */
	if ((val & 0x7fffffff) > 0x7f800000) {
		/* check for signaling NaN */
		if (!(val & 0x00400000))
			*fcsr |= FFLAG_INVALID_OPERATION;
		/* return canonical NaN */
		return 0x7fc00000;
	}
	/* handle values too big to have a fractional part */
	if ((val & 0x7f800000) >= 0x4b000000)
		return val;
	/* handle values that can only yield 0 or 1 */
	if ((val & 0x7fffffff) < 0x3f800000) {
		if (set_nx)
			*fcsr |= FFLAG_INEXACT;
		if ((val & 0x7f800000) >= one_threshold[val >> 31][rm])
			return (val & 0x80000000) | 0x3f800000;
		return val & 0x80000000;
	}
	/* handle all other values */
	unsigned sh = ((val & 0x7f800000) >> 23) - 127;
	u32 new_val = (val & 0x7fffff) | 0x800000;
	new_val += rm_bias[val >> 31][(new_val >> (23 - sh)) & 1][rm] >> sh;
	new_val &= ~(0x7fffff >> sh);
	if (new_val >= 0x1000000) {
		new_val >>= 1;
		new_val &= 0x7fffff;
		new_val |= (val & 0x7f800000) + 0x00800000;
	} else {
		new_val &= 0x7fffff;
		new_val |= val & 0x7f800000;
	}
	new_val |= val & 0x80000000;
	if (set_nx && new_val != val)
		*fcsr |= FFLAG_INEXACT;
	return new_val;
}

static u64 round_f64(u64 val, u32 *fcsr, int rm, bool set_nx)
{
	/* rounding bias to be added below what will be the LSB:
	 * sign, future LSB, rounding mode */
	static const u64 rm_bias[2][2][5] = {
		{ { 0x7ffffffffffff, 0, 0, 0xfffffffffffff, 0x8000000000000 },
		  { 0x8000000000000, 0, 0, 0xfffffffffffff, 0x8000000000000 } },
		{ { 0x7ffffffffffff, 0, 0xfffffffffffff, 0, 0x8000000000000 },
		  { 0x8000000000000, 0, 0xfffffffffffff, 0, 0x8000000000000 } }
	};

	/* values >= this (with masked sign) become at least +/- 1
	 * sign, rounding mode */
	static const u64 one_threshold[2][5] = {
		{ 0x3fdfffffffffffff, 0x3ff0000000000000, 0x3ff0000000000000, 1,
		  0x3fe0000000000000 },
		{ 0x3fdfffffffffffff, 0x3ff0000000000000, 1, 0x3ff0000000000000,
		  0x3fe0000000000000 }
	};

	/* handle +/- zero */
	if ((val & 0x7fffffffffffffff) == 0)
		return val;
	/* handle NaNs */
	if ((val & 0x7fffffffffffffff) > 0x7ff0000000000000) {
		/* check for signaling NaN */
		if (!(val & 0x0008000000000000))
			*fcsr |= FFLAG_INVALID_OPERATION;
		/* return canonical NaN */
		return 0x7ff8000000000000;
	}
	/* handle values too big to have a fractional part */
	if ((val & 0x7ff0000000000000) >= 0x4330000000000000)
		return val;
	/* handle values that can only yield 0 or 1 */
	if ((val & 0x7fffffffffffffff) < 0x3ff0000000000000) {
		if (set_nx)
			*fcsr |= FFLAG_INEXACT;
		if ((val & 0x7ff0000000000000) >= one_threshold[val >> 63][rm])
			return (val & 0x8000000000000000) | 0x3ff0000000000000;
		return val & 0x8000000000000000;
	}
	/* handle all other values */
	unsigned sh = ((val & 0x7ff0000000000000) >> 52) - 1023;
	u64 new_val = (val & 0x000fffffffffffff) | 0x0010000000000000;
	new_val += rm_bias[val >> 63][(new_val >> (52 - sh)) & 1][rm] >> sh;
	new_val &= ~(0x000fffffffffffff >> sh);
	if (new_val >= 0x0020000000000000) {
		new_val >>= 1;
		new_val &= 0x000fffffffffffff;
		new_val |= (val & 0x7ff0000000000000) + 0x0010000000000000;
	} else {
		new_val &= 0x000fffffffffffff;
		new_val |= val & 0x7ff0000000000000;
	}
	new_val |= val & 0x8000000000000000;
	if (set_nx && new_val != val)
		*fcsr |= FFLAG_INEXACT;
	return new_val;
}

static u16 round_f16(u16 val, u32 *fcsr, int rm, bool set_nx)
{
	/* rounding bias to be added below what will be the LSB:
	 * sign, future LSB, rounding mode */
	static const u16 rm_bias[2][2][5] = {
		{ { 0x1ff, 0x000, 0x000, 0x3ff, 0x200 },
		  { 0x200, 0x000, 0x000, 0x3ff, 0x200 } },
		{ { 0x1ff, 0x000, 0x3ff, 0x000, 0x200 },
		  { 0x200, 0x000, 0x3ff, 0x000, 0x200 } }
	};

	/* values >= this (with masked sign) become at least +/- 1
	 * sign, rounding mode */
	static const u16 one_threshold[2][5] = {
		{ 0x37ff, 0x3c00, 0x3c00, 0x0001, 0x3800 },
		{ 0x37ff, 0x3c00, 0x0001, 0x3c00, 0x3800 }
	};

	/* handle +/- zero */
	if ((val & 0x7fff) == 0)
		return val;
	/* handle NaNs */
	if ((val & 0x7fff) > 0x7c00) {
		/* check for signaling NaN */
		if (!(val & 0x0200))
			*fcsr |= FFLAG_INVALID_OPERATION;
		/* return canonical NaN */
		return 0x7e00;
	}
	/* handle values too big to have a fractional part */
	if ((val & 0x7c00) >= 0x6400)
		return val;
	/* handle values that can only yield 0 or 1 */
	if ((val & 0x7fff) < 0x3c00) {
		if (set_nx)
			*fcsr |= FFLAG_INEXACT;
		if ((val & 0x7fff) >= one_threshold[val >> 15][rm])
			return (val & 0x8000) | 0x3c00;
		return val & 0x8000;
	}
	/* handle all other values */
	unsigned sh = ((val & 0x7c00) >> 10) - 15;
	u16 new_val = (val & 0x3ff) | 0x400;
	new_val += rm_bias[val >> 15][(new_val >> (10 - sh)) & 1][rm] >> sh;
	new_val &= ~(0x3ff >> sh);
	if (new_val >= 0x800) {
		new_val >>= 1;
		new_val &= 0x3ff;
		new_val |= (val & 0x7c00) + 0x0400;
	} else {
		new_val &= 0x3ff;
		new_val |= val & 0x7c00;
	}
	new_val |= val & 0x8000;
	if (set_nx && new_val != val)
		*fcsr |= FFLAG_INEXACT;
	return new_val;
}

static s32 fcvtmod_f64(u64 val, u32 *fcsr)
{
	bool sign = val >> 63;
	val &= 0x7fffffffffffffff;

	/* handle +/- zero */
	if (val == 0)
		return 0;

	int exp = ((val >> 52) & 0x7ff) - 1023;
	/* handle values that become zero */
	if (exp < 0) {
		*fcsr |= FFLAG_INEXACT;
		return 0;
	}
	/* handle all bigger values */
	/* handle overflow */
	if (exp > 31)
		*fcsr |= FFLAG_INVALID_OPERATION;
	/* handle values so big that all relevant lower bits are 0 */
	if (exp > 52 + 31)
		return 0;

	u64 mant = (val & 0x000fffffffffffff) | 0x0010000000000000;

	/* handle all other values */
	if (exp >= 52) {
		mant = mant << (exp - 52);
	} else {
		if ((mant & (0x000fffffffffffff >> exp)) != 0)
			*fcsr |= FFLAG_INEXACT;
		mant = mant >> (52 - exp);
	}
	mant &= 0x7fffffff;
	return sign ? -mant : mant;
}

static u32 f32_handle_and_signal_nans(u32 rs1, u32 rs2)
{
	u32 val = 0;
	/* check first and second operand for NaN */
	if ((rs1 & 0x7fffffff) > 0x7f800000) {
		/* set canonical NaN */
		val = 0x7fc00000;
		/* check for signaling NaN */
		if (!(rs1 & 0x00400000))
			SET_FCSR(GET_FCSR() | FFLAG_INVALID_OPERATION);
	} else if ((rs2 & 0x7fffffff) > 0x7f800000) {
		/* set canonical NaN */
		val = 0x7fc00000;
		/* check for signaling NaN */
		if (!(rs2 & 0x00400000))
			SET_FCSR(GET_FCSR() | FFLAG_INVALID_OPERATION);
	}
	return val;
}

static u64 f64_handle_and_signal_nans(u64 rs1, u64 rs2)
{
	u64 val = 0;
	/* check first and second operand for NaN */
	if ((rs1 & 0x7fffffffffffffff) > 0x7ff0000000000000) {
		/* set canonical NaN */
		val = 0x7ff8000000000000;
		/* check for signaling NaN */
		if (!(rs1 & 0x0008000000000000))
			SET_FCSR(GET_FCSR() | FFLAG_INVALID_OPERATION);
	} else if ((rs2 & 0x7fffffffffffffff) > 0x7ff0000000000000) {
		/* set canonical NaN */
		val = 0x7ff8000000000000;
		/* check for signaling NaN */
		if (!(rs2 & 0x0008000000000000))
			SET_FCSR(GET_FCSR() | FFLAG_INVALID_OPERATION);
	}
	return val;
}

static u16 f16_handle_and_signal_nans(u16 rs1, u16 rs2)
{
	u16 val = 0;
	/* check first and second operand for NaN */
	if ((rs1 & 0x7fff) > 0x7c00) {
		/* set canonical NaN */
		val = 0x7e00;
		/* check for signaling NaN */
		if (!(rs1 & 0x0200))
			SET_FCSR(GET_FCSR() | FFLAG_INVALID_OPERATION);
	} else if ((rs2 & 0x7fff) > 0x7c00) {
		/* set canonical NaN */
		val = 0x7e00;
		/* check for signaling NaN */
		if (!(rs2 & 0x0200))
			SET_FCSR(GET_FCSR() | FFLAG_INVALID_OPERATION);
	}
	return val;
}

int sbi_insn_emu_op_fp(ulong insn, struct sbi_trap_regs *regs)
{
	u64 val;
	u32 fcsr;

	/* do not emulate floating point instructions when disabled */
	if ((regs->mstatus & MSTATUS_FS) == 0 ||
	    (sbi_mstatus_prev_mode(regs->mstatus) == PRV_U &&
	     (csr_read(CSR_SSTATUS) & SSTATUS_FS) == 0))
		return truly_illegal_insn(insn, regs);

	switch (insn & INSN_MASK_ITYPE_RD_RS) {
	/* Emulate Zfhmin instructions */
	case INSN_MATCH_FCVT_S_H | (RM_FIELD_RNE << 12):
	case INSN_MATCH_FCVT_S_H | (RM_FIELD_RTZ << 12):
	case INSN_MATCH_FCVT_S_H | (RM_FIELD_RDN << 12):
	case INSN_MATCH_FCVT_S_H | (RM_FIELD_RUP << 12):
	case INSN_MATCH_FCVT_S_H | (RM_FIELD_RMM << 12):
	case INSN_MATCH_FCVT_S_H | (RM_FIELD_DYN << 12):
		fcsr = GET_FCSR();
		val = GET_F16_RS1_OR_NAN(insn, regs);
		val = convert_f16_to_f32(val, &fcsr);
		SET_F32_RD(insn, regs, val);
		SET_FCSR(fcsr);
		break;
	case INSN_MATCH_FCVT_H_S | (RM_FIELD_RNE << 12):
	case INSN_MATCH_FCVT_H_S | (RM_FIELD_RTZ << 12):
	case INSN_MATCH_FCVT_H_S | (RM_FIELD_RDN << 12):
	case INSN_MATCH_FCVT_H_S | (RM_FIELD_RUP << 12):
	case INSN_MATCH_FCVT_H_S | (RM_FIELD_RMM << 12):
		fcsr = GET_FCSR();
		val  = GET_F32_RS1_OR_NAN(insn, regs);
		val  = convert_f32_to_f16(val, &fcsr, GET_RM(insn));
		SET_F16_RD(insn, regs, val);
		SET_FCSR(fcsr);
		break;
	case INSN_MATCH_FCVT_H_S | (RM_FIELD_DYN << 12):
		fcsr = GET_FCSR();
		if ((fcsr & 0xe0) == 0xa0 || (fcsr & 0xe0) == 0xc0)
			return truly_illegal_insn(insn, regs);
		val = GET_F32_RS1_OR_NAN(insn, regs);
		val = convert_f32_to_f16(val, &fcsr, (fcsr >> 5) & 7);
		SET_F16_RD(insn, regs, val);
		SET_FCSR(fcsr);
		break;
	case INSN_MATCH_FCVT_D_H | (RM_FIELD_RNE << 12):
	case INSN_MATCH_FCVT_D_H | (RM_FIELD_RTZ << 12):
	case INSN_MATCH_FCVT_D_H | (RM_FIELD_RDN << 12):
	case INSN_MATCH_FCVT_D_H | (RM_FIELD_RUP << 12):
	case INSN_MATCH_FCVT_D_H | (RM_FIELD_RMM << 12):
	case INSN_MATCH_FCVT_D_H | (RM_FIELD_DYN << 12):
		fcsr = GET_FCSR();
		val = GET_F16_RS1_OR_NAN(insn, regs);
		val = convert_f16_to_f64(val, &fcsr);
		SET_F64_RD(insn, regs, val);
		SET_FCSR(fcsr);
		break;
	case INSN_MATCH_FCVT_H_D | (RM_FIELD_RNE << 12):
	case INSN_MATCH_FCVT_H_D | (RM_FIELD_RTZ << 12):
	case INSN_MATCH_FCVT_H_D | (RM_FIELD_RDN << 12):
	case INSN_MATCH_FCVT_H_D | (RM_FIELD_RUP << 12):
	case INSN_MATCH_FCVT_H_D | (RM_FIELD_RMM << 12):
		fcsr = GET_FCSR();
		val  = GET_F64_RS1_OR_NAN(insn, regs);
		val  = convert_f64_to_f16(val, &fcsr, GET_RM(insn));
		SET_F16_RD(insn, regs, val);
		SET_FCSR(fcsr);
		break;
	case INSN_MATCH_FCVT_H_D | (RM_FIELD_DYN << 12):
		fcsr = GET_FCSR();
		if ((fcsr & 0xe0) == 0xa0 || (fcsr & 0xe0) == 0xc0)
			return truly_illegal_insn(insn, regs);
		val = GET_F64_RS1_OR_NAN(insn, regs);
		val = convert_f64_to_f16(val, &fcsr, (fcsr >> 5) & 7);
		SET_F16_RD(insn, regs, val);
		SET_FCSR(fcsr);
		break;
	case INSN_MATCH_FMV_X_H:
		val = GET_F16_RS1(insn, regs);
		SET_RD(insn, regs, (ulong)(long)(s16)(u16)val);
		break;
	case INSN_MATCH_FMV_H_X:
		val = GET_RS1(insn, regs);
		SET_F16_RD(insn, regs, val);
		break;
	/* Emulate Zfa instructions */
	case INSN_MATCH_FLI_H:
		val = GET_RS1_NUM(insn);
		val = f16_imm_lut[val];
		SET_F16_RD(insn, regs, val);
		break;
	case INSN_MATCH_FLI_S:
		val = GET_RS1_NUM(insn);
		val = f32_imm_lut[val];
		SET_F32_RD(insn, regs, val);
		break;
	case INSN_MATCH_FLI_D:
		val = GET_RS1_NUM(insn);
		val = f64_imm_lut[val];
		SET_F64_RD(insn, regs, val);
		break;
	case INSN_MATCH_FROUND_S | (RM_FIELD_RNE << 12):
	case INSN_MATCH_FROUND_S | (RM_FIELD_RTZ << 12):
	case INSN_MATCH_FROUND_S | (RM_FIELD_RDN << 12):
	case INSN_MATCH_FROUND_S | (RM_FIELD_RUP << 12):
	case INSN_MATCH_FROUND_S | (RM_FIELD_RMM << 12):
		fcsr = GET_FCSR();
		val  = GET_F32_RS1_OR_NAN(insn, regs);
		val  = round_f32(val, &fcsr, GET_RM(insn), false);
		SET_F32_RD(insn, regs, val);
		SET_FCSR(fcsr);
		break;
	case INSN_MATCH_FROUND_S | (RM_FIELD_DYN << 12):
		fcsr = GET_FCSR();
		if ((fcsr & 0xe0) == 0xa0 || (fcsr & 0xe0) == 0xc0)
			return truly_illegal_insn(insn, regs);
		val = GET_F32_RS1_OR_NAN(insn, regs);
		val = round_f32(val, &fcsr, (fcsr >> 5) & 7, false);
		SET_F32_RD(insn, regs, val);
		SET_FCSR(fcsr);
		break;
	case INSN_MATCH_FROUNDNX_S | (RM_FIELD_RNE << 12):
	case INSN_MATCH_FROUNDNX_S | (RM_FIELD_RTZ << 12):
	case INSN_MATCH_FROUNDNX_S | (RM_FIELD_RDN << 12):
	case INSN_MATCH_FROUNDNX_S | (RM_FIELD_RUP << 12):
	case INSN_MATCH_FROUNDNX_S | (RM_FIELD_RMM << 12):
		fcsr = GET_FCSR();
		val  = GET_F32_RS1_OR_NAN(insn, regs);
		val  = round_f32(val, &fcsr, GET_RM(insn), true);
		SET_F32_RD(insn, regs, val);
		SET_FCSR(fcsr);
		break;
	case INSN_MATCH_FROUNDNX_S | (RM_FIELD_DYN << 12):
		fcsr = GET_FCSR();
		if ((fcsr & 0xe0) == 0xa0 || (fcsr & 0xe0) == 0xc0)
			return truly_illegal_insn(insn, regs);
		val = GET_F32_RS1_OR_NAN(insn, regs);
		val = round_f32(val, &fcsr, (fcsr >> 5) & 7, true);
		SET_F32_RD(insn, regs, val);
		SET_FCSR(fcsr);
		break;
	case INSN_MATCH_FROUND_D | (RM_FIELD_RNE << 12):
	case INSN_MATCH_FROUND_D | (RM_FIELD_RTZ << 12):
	case INSN_MATCH_FROUND_D | (RM_FIELD_RDN << 12):
	case INSN_MATCH_FROUND_D | (RM_FIELD_RUP << 12):
	case INSN_MATCH_FROUND_D | (RM_FIELD_RMM << 12):
		fcsr = GET_FCSR();
		val  = GET_F64_RS1_OR_NAN(insn, regs);
		val  = round_f64(val, &fcsr, GET_RM(insn), false);
		SET_F64_RD(insn, regs, val);
		SET_FCSR(fcsr);
		break;
	case INSN_MATCH_FROUND_D | (RM_FIELD_DYN << 12):
		fcsr = GET_FCSR();
		if ((fcsr & 0xe0) == 0xa0 || (fcsr & 0xe0) == 0xc0)
			return truly_illegal_insn(insn, regs);
		val = GET_F64_RS1_OR_NAN(insn, regs);
		val = round_f64(val, &fcsr, (fcsr >> 5) & 7, false);
		SET_F64_RD(insn, regs, val);
		SET_FCSR(fcsr);
		break;
	case INSN_MATCH_FROUNDNX_D | (RM_FIELD_RNE << 12):
	case INSN_MATCH_FROUNDNX_D | (RM_FIELD_RTZ << 12):
	case INSN_MATCH_FROUNDNX_D | (RM_FIELD_RDN << 12):
	case INSN_MATCH_FROUNDNX_D | (RM_FIELD_RUP << 12):
	case INSN_MATCH_FROUNDNX_D | (RM_FIELD_RMM << 12):
		fcsr = GET_FCSR();
		val  = GET_F64_RS1_OR_NAN(insn, regs);
		val  = round_f64(val, &fcsr, GET_RM(insn), true);
		SET_F64_RD(insn, regs, val);
		SET_FCSR(fcsr);
		break;
	case INSN_MATCH_FROUNDNX_D | (RM_FIELD_DYN << 12):
		fcsr = GET_FCSR();
		if ((fcsr & 0xe0) == 0xa0 || (fcsr & 0xe0) == 0xc0)
			return truly_illegal_insn(insn, regs);
		val = GET_F64_RS1_OR_NAN(insn, regs);
		val = round_f64(val, &fcsr, (fcsr >> 5) & 7, true);
		SET_F64_RD(insn, regs, val);
		SET_FCSR(fcsr);
		break;
	case INSN_MATCH_FROUND_H | (RM_FIELD_RNE << 12):
	case INSN_MATCH_FROUND_H | (RM_FIELD_RTZ << 12):
	case INSN_MATCH_FROUND_H | (RM_FIELD_RDN << 12):
	case INSN_MATCH_FROUND_H | (RM_FIELD_RUP << 12):
	case INSN_MATCH_FROUND_H | (RM_FIELD_RMM << 12):
		fcsr = GET_FCSR();
		val  = GET_F16_RS1_OR_NAN(insn, regs);
		val  = round_f16(val, &fcsr, GET_RM(insn), false);
		SET_F16_RD(insn, regs, val);
		SET_FCSR(fcsr);
		break;
	case INSN_MATCH_FROUND_H | (RM_FIELD_DYN << 12):
		fcsr = GET_FCSR();
		if ((fcsr & 0xe0) == 0xa0 || (fcsr & 0xe0) == 0xc0)
			return truly_illegal_insn(insn, regs);
		val = GET_F16_RS1_OR_NAN(insn, regs);
		val = round_f16(val, &fcsr, (fcsr >> 5) & 7, false);
		SET_F16_RD(insn, regs, val);
		SET_FCSR(fcsr);
		break;
	case INSN_MATCH_FROUNDNX_H | (RM_FIELD_RNE << 12):
	case INSN_MATCH_FROUNDNX_H | (RM_FIELD_RTZ << 12):
	case INSN_MATCH_FROUNDNX_H | (RM_FIELD_RDN << 12):
	case INSN_MATCH_FROUNDNX_H | (RM_FIELD_RUP << 12):
	case INSN_MATCH_FROUNDNX_H | (RM_FIELD_RMM << 12):
		fcsr = GET_FCSR();
		val  = GET_F16_RS1_OR_NAN(insn, regs);
		val  = round_f16(val, &fcsr, GET_RM(insn), true);
		SET_F16_RD(insn, regs, val);
		SET_FCSR(fcsr);
		break;
	case INSN_MATCH_FROUNDNX_H | (RM_FIELD_DYN << 12):
		fcsr = GET_FCSR();
		if ((fcsr & 0xe0) == 0xa0 || (fcsr & 0xe0) == 0xc0)
			return truly_illegal_insn(insn, regs);
		val = GET_F16_RS1_OR_NAN(insn, regs);
		val = round_f16(val, &fcsr, (fcsr >> 5) & 7, true);
		SET_F16_RD(insn, regs, val);
		SET_FCSR(fcsr);
		break;
	case INSN_MATCH_FCVTMOD_W_D:
		fcsr = GET_FCSR();
		val  = GET_F64_RS1_OR_NAN(insn, regs);
		val  = (s64)fcvtmod_f64(val, &fcsr);
		SET_RD(insn, regs, val);
		SET_FCSR(fcsr);
		break;
	default:
		switch (insn & INSN_MASK_RTYPE_RD_RS1_RS2) {
		case INSN_MATCH_FMINM_H: {
			u16 rs1 = GET_F16_RS1_OR_NAN(insn, regs);
			u16 rs2 = GET_F16_RS2_OR_NAN(insn, regs);
			if (!(val = f16_handle_and_signal_nans(rs1, rs2)))
				val = ((rs1 < rs2) ^ ((rs1 | rs2) >> 15)) ? rs1
									  : rs2;
			SET_F16_RD(insn, regs, val);
			break;
		}
		case INSN_MATCH_FMAXM_H: {
			u16 rs1 = GET_F16_RS1_OR_NAN(insn, regs);
			u16 rs2 = GET_F16_RS2_OR_NAN(insn, regs);
			if (!(val = f16_handle_and_signal_nans(rs1, rs2)))
				val = ((rs1 > rs2) ^ ((rs1 | rs2) >> 15)) ? rs1
									  : rs2;
			SET_F16_RD(insn, regs, val);
			break;
		}
		case INSN_MATCH_FMINM_S: {
			u32 rs1 = GET_F32_RS1_OR_NAN(insn, regs);
			u32 rs2 = GET_F32_RS2_OR_NAN(insn, regs);
			if (!(val = f32_handle_and_signal_nans(rs1, rs2)))
				val = ((rs1 < rs2) ^ ((rs1 | rs2) >> 31)) ? rs1
									  : rs2;
			SET_F32_RD(insn, regs, val);
			break;
		}
		case INSN_MATCH_FMAXM_S: {
			u32 rs1 = GET_F32_RS1_OR_NAN(insn, regs);
			u32 rs2 = GET_F32_RS2_OR_NAN(insn, regs);
			if (!(val = f32_handle_and_signal_nans(rs1, rs2)))
				val = ((rs1 > rs2) ^ ((rs1 | rs2) >> 31)) ? rs1
									  : rs2;
			SET_F32_RD(insn, regs, val);
			break;
		}
		case INSN_MATCH_FMINM_D: {
			u64 rs1 = GET_F64_RS1_OR_NAN(insn, regs);
			u64 rs2 = GET_F64_RS2_OR_NAN(insn, regs);
			if (!(val = f64_handle_and_signal_nans(rs1, rs2)))
				val = ((rs1 < rs2) ^ ((rs1 | rs2) >> 63)) ? rs1
									  : rs2;
			SET_F64_RD(insn, regs, val);
			break;
		}
		case INSN_MATCH_FMAXM_D: {
			u64 rs1 = GET_F64_RS1_OR_NAN(insn, regs);
			u64 rs2 = GET_F64_RS2_OR_NAN(insn, regs);
			if (!(val = f64_handle_and_signal_nans(rs1, rs2)))
				val = ((rs1 > rs2) ^ ((rs1 | rs2) >> 63)) ? rs1
									  : rs2;
			SET_F64_RD(insn, regs, val);
			break;
		}
		case INSN_MATCH_FLTQ_H: {
			u16 rs1 = GET_F16_RS1_OR_NAN(insn, regs);
			u16 rs2 = GET_F16_RS2_OR_NAN(insn, regs);
			if ((val = !f16_handle_and_signal_nans(rs1, rs2)))
				val = (rs1 < rs2) ^ ((rs1 | rs2) >> 15);
			SET_RD(insn, regs, val);
			break;
		}
		case INSN_MATCH_FLEQ_H: {
			u16 rs1 = GET_F16_RS1_OR_NAN(insn, regs);
			u16 rs2 = GET_F16_RS2_OR_NAN(insn, regs);
			if ((val = !f16_handle_and_signal_nans(rs1, rs2)))
				val = !((rs1 > rs2) ^ ((rs1 | rs2) >> 15));
			SET_RD(insn, regs, val);
			break;
		}
		case INSN_MATCH_FLTQ_S: {
			u32 rs1 = GET_F32_RS1_OR_NAN(insn, regs);
			u32 rs2 = GET_F32_RS2_OR_NAN(insn, regs);
			if ((val = !f32_handle_and_signal_nans(rs1, rs2)))
				val = (rs1 < rs2) ^ ((rs1 | rs2) >> 31);
			SET_RD(insn, regs, val);
			break;
		}
		case INSN_MATCH_FLEQ_S: {
			u32 rs1 = GET_F32_RS1_OR_NAN(insn, regs);
			u32 rs2 = GET_F32_RS2_OR_NAN(insn, regs);
			if ((val = !f32_handle_and_signal_nans(rs1, rs2)))
				val = !((rs1 > rs2) ^ ((rs1 | rs2) >> 31));
			SET_RD(insn, regs, val);
			break;
		}
		case INSN_MATCH_FLTQ_D: {
			u64 rs1 = GET_F64_RS1_OR_NAN(insn, regs);
			u64 rs2 = GET_F64_RS2_OR_NAN(insn, regs);
			if ((val = !f64_handle_and_signal_nans(rs1, rs2)))
				val = (rs1 < rs2) ^ ((rs1 | rs2) >> 63);
			SET_RD(insn, regs, val);
			break;
		}
		case INSN_MATCH_FLEQ_D: {
			u64 rs1 = GET_F64_RS1_OR_NAN(insn, regs);
			u64 rs2 = GET_F64_RS2_OR_NAN(insn, regs);
			if ((val = !f64_handle_and_signal_nans(rs1, rs2)))
				val = !((rs1 > rs2) ^ ((rs1 | rs2) >> 63));
			SET_RD(insn, regs, val);
			break;
		}
		default:
			return truly_illegal_insn(insn, regs);
		}
	}

	regs->mepc += 4;

	return 0;
}
