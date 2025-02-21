/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Benedikt Freisen.
 *
 * Authors:
 *   Benedikt Freisen <b.freisen@gmx.net>
 */

#if __riscv_xlen == 64

#include <sbi/riscv_encoding.h>
#include <sbi/sbi_illegal_insn.h>
#include <sbi/sbi_trap.h>

/* TODO: make VLMAX_BYTES configurable */
#define VLMAX_BYTES (8 * 32)

typedef union {
	u8 u8[VLMAX_BYTES];
	u16 u16[VLMAX_BYTES / 2];
	u32 u32[VLMAX_BYTES / 4];
	u64 u64[VLMAX_BYTES / 8];
} sbi_vector_data;

#define INLINE_VSE8(nstr, dest)                    \
	asm volatile(".option push\n\t"            \
		     ".option arch, +v\n\t"        \
		     "vse8.v " nstr ", (%0)\n\t"   \
		     ".option pop\n\t" ::"r"(dest) \
		     : "memory");

#define CASE_N_INLINE_VSE8(n, nstr, dest) \
	case n:                           \
		INLINE_VSE8(nstr, dest);  \
		break;

#define INLINE_VSE16(nstr, dest)                   \
	asm volatile(".option push\n\t"            \
		     ".option arch, +v\n\t"        \
		     "vse16.v " nstr ", (%0)\n\t"  \
		     ".option pop\n\t" ::"r"(dest) \
		     : "memory");

#define CASE_N_INLINE_VSE16(n, nstr, dest) \
	case n:                            \
		INLINE_VSE16(nstr, dest);  \
		break;

#define INLINE_VSE32(nstr, dest)                   \
	asm volatile(".option push\n\t"            \
		     ".option arch, +v\n\t"        \
		     "vse32.v " nstr ", (%0)\n\t"  \
		     ".option pop\n\t" ::"r"(dest) \
		     : "memory");

#define CASE_N_INLINE_VSE32(n, nstr, dest) \
	case n:                            \
		INLINE_VSE32(nstr, dest);  \
		break;

#define INLINE_VSE64(nstr, dest)                   \
	asm volatile(".option push\n\t"            \
		     ".option arch, +v\n\t"        \
		     "vse64.v " nstr ", (%0)\n\t"  \
		     ".option pop\n\t" ::"r"(dest) \
		     : "memory");

#define CASE_N_INLINE_VSE64(n, nstr, dest) \
	case n:                            \
		INLINE_VSE64(nstr, dest);  \
		break;

static inline void get_vector_as_array_u8(int n, sbi_vector_data *dest)
{
	switch (n) {
		CASE_N_INLINE_VSE8(0, "v0", dest);
		CASE_N_INLINE_VSE8(1, "v1", dest);
		CASE_N_INLINE_VSE8(2, "v2", dest);
		CASE_N_INLINE_VSE8(3, "v3", dest);
		CASE_N_INLINE_VSE8(4, "v4", dest);
		CASE_N_INLINE_VSE8(5, "v5", dest);
		CASE_N_INLINE_VSE8(6, "v6", dest);
		CASE_N_INLINE_VSE8(7, "v7", dest);
		CASE_N_INLINE_VSE8(8, "v8", dest);
		CASE_N_INLINE_VSE8(9, "v9", dest);
		CASE_N_INLINE_VSE8(10, "v10", dest);
		CASE_N_INLINE_VSE8(11, "v11", dest);
		CASE_N_INLINE_VSE8(12, "v12", dest);
		CASE_N_INLINE_VSE8(13, "v13", dest);
		CASE_N_INLINE_VSE8(14, "v14", dest);
		CASE_N_INLINE_VSE8(15, "v15", dest);
		CASE_N_INLINE_VSE8(16, "v16", dest);
		CASE_N_INLINE_VSE8(17, "v17", dest);
		CASE_N_INLINE_VSE8(18, "v18", dest);
		CASE_N_INLINE_VSE8(19, "v19", dest);
		CASE_N_INLINE_VSE8(20, "v20", dest);
		CASE_N_INLINE_VSE8(21, "v21", dest);
		CASE_N_INLINE_VSE8(22, "v22", dest);
		CASE_N_INLINE_VSE8(23, "v23", dest);
		CASE_N_INLINE_VSE8(24, "v24", dest);
		CASE_N_INLINE_VSE8(25, "v25", dest);
		CASE_N_INLINE_VSE8(26, "v26", dest);
		CASE_N_INLINE_VSE8(27, "v27", dest);
		CASE_N_INLINE_VSE8(28, "v28", dest);
		CASE_N_INLINE_VSE8(29, "v29", dest);
		CASE_N_INLINE_VSE8(30, "v30", dest);
		CASE_N_INLINE_VSE8(31, "v31", dest);
	}
}

static inline void get_vector_as_array_u16(int n, sbi_vector_data *dest)
{
	switch (n) {
		CASE_N_INLINE_VSE16(0, "v0", dest);
		CASE_N_INLINE_VSE16(1, "v1", dest);
		CASE_N_INLINE_VSE16(2, "v2", dest);
		CASE_N_INLINE_VSE16(3, "v3", dest);
		CASE_N_INLINE_VSE16(4, "v4", dest);
		CASE_N_INLINE_VSE16(5, "v5", dest);
		CASE_N_INLINE_VSE16(6, "v6", dest);
		CASE_N_INLINE_VSE16(7, "v7", dest);
		CASE_N_INLINE_VSE16(8, "v8", dest);
		CASE_N_INLINE_VSE16(9, "v9", dest);
		CASE_N_INLINE_VSE16(10, "v10", dest);
		CASE_N_INLINE_VSE16(11, "v11", dest);
		CASE_N_INLINE_VSE16(12, "v12", dest);
		CASE_N_INLINE_VSE16(13, "v13", dest);
		CASE_N_INLINE_VSE16(14, "v14", dest);
		CASE_N_INLINE_VSE16(15, "v15", dest);
		CASE_N_INLINE_VSE16(16, "v16", dest);
		CASE_N_INLINE_VSE16(17, "v17", dest);
		CASE_N_INLINE_VSE16(18, "v18", dest);
		CASE_N_INLINE_VSE16(19, "v19", dest);
		CASE_N_INLINE_VSE16(20, "v20", dest);
		CASE_N_INLINE_VSE16(21, "v21", dest);
		CASE_N_INLINE_VSE16(22, "v22", dest);
		CASE_N_INLINE_VSE16(23, "v23", dest);
		CASE_N_INLINE_VSE16(24, "v24", dest);
		CASE_N_INLINE_VSE16(25, "v25", dest);
		CASE_N_INLINE_VSE16(26, "v26", dest);
		CASE_N_INLINE_VSE16(27, "v27", dest);
		CASE_N_INLINE_VSE16(28, "v28", dest);
		CASE_N_INLINE_VSE16(29, "v29", dest);
		CASE_N_INLINE_VSE16(30, "v30", dest);
		CASE_N_INLINE_VSE16(31, "v31", dest);
	}
}

static inline void get_vector_as_array_u32(int n, sbi_vector_data *dest)
{
	switch (n) {
		CASE_N_INLINE_VSE32(0, "v0", dest);
		CASE_N_INLINE_VSE32(1, "v1", dest);
		CASE_N_INLINE_VSE32(2, "v2", dest);
		CASE_N_INLINE_VSE32(3, "v3", dest);
		CASE_N_INLINE_VSE32(4, "v4", dest);
		CASE_N_INLINE_VSE32(5, "v5", dest);
		CASE_N_INLINE_VSE32(6, "v6", dest);
		CASE_N_INLINE_VSE32(7, "v7", dest);
		CASE_N_INLINE_VSE32(8, "v8", dest);
		CASE_N_INLINE_VSE32(9, "v9", dest);
		CASE_N_INLINE_VSE32(10, "v10", dest);
		CASE_N_INLINE_VSE32(11, "v11", dest);
		CASE_N_INLINE_VSE32(12, "v12", dest);
		CASE_N_INLINE_VSE32(13, "v13", dest);
		CASE_N_INLINE_VSE32(14, "v14", dest);
		CASE_N_INLINE_VSE32(15, "v15", dest);
		CASE_N_INLINE_VSE32(16, "v16", dest);
		CASE_N_INLINE_VSE32(17, "v17", dest);
		CASE_N_INLINE_VSE32(18, "v18", dest);
		CASE_N_INLINE_VSE32(19, "v19", dest);
		CASE_N_INLINE_VSE32(20, "v20", dest);
		CASE_N_INLINE_VSE32(21, "v21", dest);
		CASE_N_INLINE_VSE32(22, "v22", dest);
		CASE_N_INLINE_VSE32(23, "v23", dest);
		CASE_N_INLINE_VSE32(24, "v24", dest);
		CASE_N_INLINE_VSE32(25, "v25", dest);
		CASE_N_INLINE_VSE32(26, "v26", dest);
		CASE_N_INLINE_VSE32(27, "v27", dest);
		CASE_N_INLINE_VSE32(28, "v28", dest);
		CASE_N_INLINE_VSE32(29, "v29", dest);
		CASE_N_INLINE_VSE32(30, "v30", dest);
		CASE_N_INLINE_VSE32(31, "v31", dest);
	}
}

static inline void get_vector_as_array_u64(int n, sbi_vector_data *dest)
{
	switch (n) {
		CASE_N_INLINE_VSE64(0, "v0", dest);
		CASE_N_INLINE_VSE64(1, "v1", dest);
		CASE_N_INLINE_VSE64(2, "v2", dest);
		CASE_N_INLINE_VSE64(3, "v3", dest);
		CASE_N_INLINE_VSE64(4, "v4", dest);
		CASE_N_INLINE_VSE64(5, "v5", dest);
		CASE_N_INLINE_VSE64(6, "v6", dest);
		CASE_N_INLINE_VSE64(7, "v7", dest);
		CASE_N_INLINE_VSE64(8, "v8", dest);
		CASE_N_INLINE_VSE64(9, "v9", dest);
		CASE_N_INLINE_VSE64(10, "v10", dest);
		CASE_N_INLINE_VSE64(11, "v11", dest);
		CASE_N_INLINE_VSE64(12, "v12", dest);
		CASE_N_INLINE_VSE64(13, "v13", dest);
		CASE_N_INLINE_VSE64(14, "v14", dest);
		CASE_N_INLINE_VSE64(15, "v15", dest);
		CASE_N_INLINE_VSE64(16, "v16", dest);
		CASE_N_INLINE_VSE64(17, "v17", dest);
		CASE_N_INLINE_VSE64(18, "v18", dest);
		CASE_N_INLINE_VSE64(19, "v19", dest);
		CASE_N_INLINE_VSE64(20, "v20", dest);
		CASE_N_INLINE_VSE64(21, "v21", dest);
		CASE_N_INLINE_VSE64(22, "v22", dest);
		CASE_N_INLINE_VSE64(23, "v23", dest);
		CASE_N_INLINE_VSE64(24, "v24", dest);
		CASE_N_INLINE_VSE64(25, "v25", dest);
		CASE_N_INLINE_VSE64(26, "v26", dest);
		CASE_N_INLINE_VSE64(27, "v27", dest);
		CASE_N_INLINE_VSE64(28, "v28", dest);
		CASE_N_INLINE_VSE64(29, "v29", dest);
		CASE_N_INLINE_VSE64(30, "v30", dest);
		CASE_N_INLINE_VSE64(31, "v31", dest);
	}
}

#define INLINE_VLE8(nstr, src)                    \
	asm volatile(".option push\n\t"           \
		     ".option arch, +v\n\t"       \
		     "vle8.v " nstr ", (%0)\n\t"  \
		     ".option pop\n\t" ::"r"(src) \
		     : "memory");

#define CASE_N_INLINE_VLE8(n, nstr, src) \
	case n:                          \
		INLINE_VLE8(nstr, src);  \
		break;

#define INLINE_VLE16(nstr, src)                   \
	asm volatile(".option push\n\t"           \
		     ".option arch, +v\n\t"       \
		     "vle16.v " nstr ", (%0)\n\t" \
		     ".option pop\n\t" ::"r"(src) \
		     : "memory");

#define CASE_N_INLINE_VLE16(n, nstr, src) \
	case n:                           \
		INLINE_VLE16(nstr, src);  \
		break;

#define INLINE_VLE32(nstr, src)                   \
	asm volatile(".option push\n\t"           \
		     ".option arch, +v\n\t"       \
		     "vle32.v " nstr ", (%0)\n\t" \
		     ".option pop\n\t" ::"r"(src) \
		     : "memory");

#define CASE_N_INLINE_VLE32(n, nstr, src) \
	case n:                           \
		INLINE_VLE32(nstr, src);  \
		break;

#define INLINE_VLE64(nstr, src)                   \
	asm volatile(".option push\n\t"           \
		     ".option arch, +v\n\t"       \
		     "vle64.v " nstr ", (%0)\n\t" \
		     ".option pop\n\t" ::"r"(src) \
		     : "memory");

#define CASE_N_INLINE_VLE64(n, nstr, src) \
	case n:                           \
		INLINE_VLE64(nstr, src);  \
		break;

static inline void set_vector_from_array_u8(int n, sbi_vector_data *src)
{
	switch (n) {
		CASE_N_INLINE_VLE8(0, "v0", src);
		CASE_N_INLINE_VLE8(1, "v1", src);
		CASE_N_INLINE_VLE8(2, "v2", src);
		CASE_N_INLINE_VLE8(3, "v3", src);
		CASE_N_INLINE_VLE8(4, "v4", src);
		CASE_N_INLINE_VLE8(5, "v5", src);
		CASE_N_INLINE_VLE8(6, "v6", src);
		CASE_N_INLINE_VLE8(7, "v7", src);
		CASE_N_INLINE_VLE8(8, "v8", src);
		CASE_N_INLINE_VLE8(9, "v9", src);
		CASE_N_INLINE_VLE8(10, "v10", src);
		CASE_N_INLINE_VLE8(11, "v11", src);
		CASE_N_INLINE_VLE8(12, "v12", src);
		CASE_N_INLINE_VLE8(13, "v13", src);
		CASE_N_INLINE_VLE8(14, "v14", src);
		CASE_N_INLINE_VLE8(15, "v15", src);
		CASE_N_INLINE_VLE8(16, "v16", src);
		CASE_N_INLINE_VLE8(17, "v17", src);
		CASE_N_INLINE_VLE8(18, "v18", src);
		CASE_N_INLINE_VLE8(19, "v19", src);
		CASE_N_INLINE_VLE8(20, "v20", src);
		CASE_N_INLINE_VLE8(21, "v21", src);
		CASE_N_INLINE_VLE8(22, "v22", src);
		CASE_N_INLINE_VLE8(23, "v23", src);
		CASE_N_INLINE_VLE8(24, "v24", src);
		CASE_N_INLINE_VLE8(25, "v25", src);
		CASE_N_INLINE_VLE8(26, "v26", src);
		CASE_N_INLINE_VLE8(27, "v27", src);
		CASE_N_INLINE_VLE8(28, "v28", src);
		CASE_N_INLINE_VLE8(29, "v29", src);
		CASE_N_INLINE_VLE8(30, "v30", src);
		CASE_N_INLINE_VLE8(31, "v31", src);
	}
}

static inline void set_vector_from_array_u16(int n, sbi_vector_data *src)
{
	switch (n) {
		CASE_N_INLINE_VLE16(0, "v0", src);
		CASE_N_INLINE_VLE16(1, "v1", src);
		CASE_N_INLINE_VLE16(2, "v2", src);
		CASE_N_INLINE_VLE16(3, "v3", src);
		CASE_N_INLINE_VLE16(4, "v4", src);
		CASE_N_INLINE_VLE16(5, "v5", src);
		CASE_N_INLINE_VLE16(6, "v6", src);
		CASE_N_INLINE_VLE16(7, "v7", src);
		CASE_N_INLINE_VLE16(8, "v8", src);
		CASE_N_INLINE_VLE16(9, "v9", src);
		CASE_N_INLINE_VLE16(10, "v10", src);
		CASE_N_INLINE_VLE16(11, "v11", src);
		CASE_N_INLINE_VLE16(12, "v12", src);
		CASE_N_INLINE_VLE16(13, "v13", src);
		CASE_N_INLINE_VLE16(14, "v14", src);
		CASE_N_INLINE_VLE16(15, "v15", src);
		CASE_N_INLINE_VLE16(16, "v16", src);
		CASE_N_INLINE_VLE16(17, "v17", src);
		CASE_N_INLINE_VLE16(18, "v18", src);
		CASE_N_INLINE_VLE16(19, "v19", src);
		CASE_N_INLINE_VLE16(20, "v20", src);
		CASE_N_INLINE_VLE16(21, "v21", src);
		CASE_N_INLINE_VLE16(22, "v22", src);
		CASE_N_INLINE_VLE16(23, "v23", src);
		CASE_N_INLINE_VLE16(24, "v24", src);
		CASE_N_INLINE_VLE16(25, "v25", src);
		CASE_N_INLINE_VLE16(26, "v26", src);
		CASE_N_INLINE_VLE16(27, "v27", src);
		CASE_N_INLINE_VLE16(28, "v28", src);
		CASE_N_INLINE_VLE16(29, "v29", src);
		CASE_N_INLINE_VLE16(30, "v30", src);
		CASE_N_INLINE_VLE16(31, "v31", src);
	}
}

static inline void set_vector_from_array_u32(int n, sbi_vector_data *src)
{
	switch (n) {
		CASE_N_INLINE_VLE32(0, "v0", src);
		CASE_N_INLINE_VLE32(1, "v1", src);
		CASE_N_INLINE_VLE32(2, "v2", src);
		CASE_N_INLINE_VLE32(3, "v3", src);
		CASE_N_INLINE_VLE32(4, "v4", src);
		CASE_N_INLINE_VLE32(5, "v5", src);
		CASE_N_INLINE_VLE32(6, "v6", src);
		CASE_N_INLINE_VLE32(7, "v7", src);
		CASE_N_INLINE_VLE32(8, "v8", src);
		CASE_N_INLINE_VLE32(9, "v9", src);
		CASE_N_INLINE_VLE32(10, "v10", src);
		CASE_N_INLINE_VLE32(11, "v11", src);
		CASE_N_INLINE_VLE32(12, "v12", src);
		CASE_N_INLINE_VLE32(13, "v13", src);
		CASE_N_INLINE_VLE32(14, "v14", src);
		CASE_N_INLINE_VLE32(15, "v15", src);
		CASE_N_INLINE_VLE32(16, "v16", src);
		CASE_N_INLINE_VLE32(17, "v17", src);
		CASE_N_INLINE_VLE32(18, "v18", src);
		CASE_N_INLINE_VLE32(19, "v19", src);
		CASE_N_INLINE_VLE32(20, "v20", src);
		CASE_N_INLINE_VLE32(21, "v21", src);
		CASE_N_INLINE_VLE32(22, "v22", src);
		CASE_N_INLINE_VLE32(23, "v23", src);
		CASE_N_INLINE_VLE32(24, "v24", src);
		CASE_N_INLINE_VLE32(25, "v25", src);
		CASE_N_INLINE_VLE32(26, "v26", src);
		CASE_N_INLINE_VLE32(27, "v27", src);
		CASE_N_INLINE_VLE32(28, "v28", src);
		CASE_N_INLINE_VLE32(29, "v29", src);
		CASE_N_INLINE_VLE32(30, "v30", src);
		CASE_N_INLINE_VLE32(31, "v31", src);
	}
}

static inline void set_vector_from_array_u64(int n, sbi_vector_data *src)
{
	switch (n) {
		CASE_N_INLINE_VLE64(0, "v0", src);
		CASE_N_INLINE_VLE64(1, "v1", src);
		CASE_N_INLINE_VLE64(2, "v2", src);
		CASE_N_INLINE_VLE64(3, "v3", src);
		CASE_N_INLINE_VLE64(4, "v4", src);
		CASE_N_INLINE_VLE64(5, "v5", src);
		CASE_N_INLINE_VLE64(6, "v6", src);
		CASE_N_INLINE_VLE64(7, "v7", src);
		CASE_N_INLINE_VLE64(8, "v8", src);
		CASE_N_INLINE_VLE64(9, "v9", src);
		CASE_N_INLINE_VLE64(10, "v10", src);
		CASE_N_INLINE_VLE64(11, "v11", src);
		CASE_N_INLINE_VLE64(12, "v12", src);
		CASE_N_INLINE_VLE64(13, "v13", src);
		CASE_N_INLINE_VLE64(14, "v14", src);
		CASE_N_INLINE_VLE64(15, "v15", src);
		CASE_N_INLINE_VLE64(16, "v16", src);
		CASE_N_INLINE_VLE64(17, "v17", src);
		CASE_N_INLINE_VLE64(18, "v18", src);
		CASE_N_INLINE_VLE64(19, "v19", src);
		CASE_N_INLINE_VLE64(20, "v20", src);
		CASE_N_INLINE_VLE64(21, "v21", src);
		CASE_N_INLINE_VLE64(22, "v22", src);
		CASE_N_INLINE_VLE64(23, "v23", src);
		CASE_N_INLINE_VLE64(24, "v24", src);
		CASE_N_INLINE_VLE64(25, "v25", src);
		CASE_N_INLINE_VLE64(26, "v26", src);
		CASE_N_INLINE_VLE64(27, "v27", src);
		CASE_N_INLINE_VLE64(28, "v28", src);
		CASE_N_INLINE_VLE64(29, "v29", src);
		CASE_N_INLINE_VLE64(30, "v30", src);
		CASE_N_INLINE_VLE64(31, "v31", src);
	}
}

#define INLINE_VLE8_M(nstr, src)                       \
	asm volatile(".option push\n\t"                \
		     ".option arch, +v\n\t"            \
		     "vle8.v " nstr ", (%0), v0.t\n\t" \
		     ".option pop\n\t" ::"r"(src)      \
		     : "memory");

#define CASE_N_INLINE_VLE8_M(n, nstr, src) \
	case n:                            \
		INLINE_VLE8_M(nstr, src);  \
		break;

#define INLINE_VLE16_M(nstr, src)                       \
	asm volatile(".option push\n\t"                 \
		     ".option arch, +v\n\t"             \
		     "vle16.v " nstr ", (%0), v0.t\n\t" \
		     ".option pop\n\t" ::"r"(src)       \
		     : "memory");

#define CASE_N_INLINE_VLE16_M(n, nstr, src) \
	case n:                             \
		INLINE_VLE16_M(nstr, src);  \
		break;

#define INLINE_VLE32_M(nstr, src)                       \
	asm volatile(".option push\n\t"                 \
		     ".option arch, +v\n\t"             \
		     "vle32.v " nstr ", (%0), v0.t\n\t" \
		     ".option pop\n\t" ::"r"(src)       \
		     : "memory");

#define CASE_N_INLINE_VLE32_M(n, nstr, src) \
	case n:                             \
		INLINE_VLE32_M(nstr, src);  \
		break;

#define INLINE_VLE64_M(nstr, src)                       \
	asm volatile(".option push\n\t"                 \
		     ".option arch, +v\n\t"             \
		     "vle64.v " nstr ", (%0), v0.t\n\t" \
		     ".option pop\n\t" ::"r"(src)       \
		     : "memory");

#define CASE_N_INLINE_VLE64_M(n, nstr, src) \
	case n:                             \
		INLINE_VLE64_M(nstr, src);  \
		break;

static inline void set_masked_vector_from_array_u8(int n, sbi_vector_data *src)
{
	switch (n) {
		// CASE_N_INLINE_VLE8_M(0, "v0", src);
		CASE_N_INLINE_VLE8_M(1, "v1", src);
		CASE_N_INLINE_VLE8_M(2, "v2", src);
		CASE_N_INLINE_VLE8_M(3, "v3", src);
		CASE_N_INLINE_VLE8_M(4, "v4", src);
		CASE_N_INLINE_VLE8_M(5, "v5", src);
		CASE_N_INLINE_VLE8_M(6, "v6", src);
		CASE_N_INLINE_VLE8_M(7, "v7", src);
		CASE_N_INLINE_VLE8_M(8, "v8", src);
		CASE_N_INLINE_VLE8_M(9, "v9", src);
		CASE_N_INLINE_VLE8_M(10, "v10", src);
		CASE_N_INLINE_VLE8_M(11, "v11", src);
		CASE_N_INLINE_VLE8_M(12, "v12", src);
		CASE_N_INLINE_VLE8_M(13, "v13", src);
		CASE_N_INLINE_VLE8_M(14, "v14", src);
		CASE_N_INLINE_VLE8_M(15, "v15", src);
		CASE_N_INLINE_VLE8_M(16, "v16", src);
		CASE_N_INLINE_VLE8_M(17, "v17", src);
		CASE_N_INLINE_VLE8_M(18, "v18", src);
		CASE_N_INLINE_VLE8_M(19, "v19", src);
		CASE_N_INLINE_VLE8_M(20, "v20", src);
		CASE_N_INLINE_VLE8_M(21, "v21", src);
		CASE_N_INLINE_VLE8_M(22, "v22", src);
		CASE_N_INLINE_VLE8_M(23, "v23", src);
		CASE_N_INLINE_VLE8_M(24, "v24", src);
		CASE_N_INLINE_VLE8_M(25, "v25", src);
		CASE_N_INLINE_VLE8_M(26, "v26", src);
		CASE_N_INLINE_VLE8_M(27, "v27", src);
		CASE_N_INLINE_VLE8_M(28, "v28", src);
		CASE_N_INLINE_VLE8_M(29, "v29", src);
		CASE_N_INLINE_VLE8_M(30, "v30", src);
		CASE_N_INLINE_VLE8_M(31, "v31", src);
	}
}

static inline void set_masked_vector_from_array_u16(int n, sbi_vector_data *src)
{
	switch (n) {
		// CASE_N_INLINE_VLE16_M(0, "v0", src);
		CASE_N_INLINE_VLE16_M(1, "v1", src);
		CASE_N_INLINE_VLE16_M(2, "v2", src);
		CASE_N_INLINE_VLE16_M(3, "v3", src);
		CASE_N_INLINE_VLE16_M(4, "v4", src);
		CASE_N_INLINE_VLE16_M(5, "v5", src);
		CASE_N_INLINE_VLE16_M(6, "v6", src);
		CASE_N_INLINE_VLE16_M(7, "v7", src);
		CASE_N_INLINE_VLE16_M(8, "v8", src);
		CASE_N_INLINE_VLE16_M(9, "v9", src);
		CASE_N_INLINE_VLE16_M(10, "v10", src);
		CASE_N_INLINE_VLE16_M(11, "v11", src);
		CASE_N_INLINE_VLE16_M(12, "v12", src);
		CASE_N_INLINE_VLE16_M(13, "v13", src);
		CASE_N_INLINE_VLE16_M(14, "v14", src);
		CASE_N_INLINE_VLE16_M(15, "v15", src);
		CASE_N_INLINE_VLE16_M(16, "v16", src);
		CASE_N_INLINE_VLE16_M(17, "v17", src);
		CASE_N_INLINE_VLE16_M(18, "v18", src);
		CASE_N_INLINE_VLE16_M(19, "v19", src);
		CASE_N_INLINE_VLE16_M(20, "v20", src);
		CASE_N_INLINE_VLE16_M(21, "v21", src);
		CASE_N_INLINE_VLE16_M(22, "v22", src);
		CASE_N_INLINE_VLE16_M(23, "v23", src);
		CASE_N_INLINE_VLE16_M(24, "v24", src);
		CASE_N_INLINE_VLE16_M(25, "v25", src);
		CASE_N_INLINE_VLE16_M(26, "v26", src);
		CASE_N_INLINE_VLE16_M(27, "v27", src);
		CASE_N_INLINE_VLE16_M(28, "v28", src);
		CASE_N_INLINE_VLE16_M(29, "v29", src);
		CASE_N_INLINE_VLE16_M(30, "v30", src);
		CASE_N_INLINE_VLE16_M(31, "v31", src);
	}
}

static inline void set_masked_vector_from_array_u32(int n, sbi_vector_data *src)
{
	switch (n) {
		// CASE_N_INLINE_VLE32_M(0, "v0", src);
		CASE_N_INLINE_VLE32_M(1, "v1", src);
		CASE_N_INLINE_VLE32_M(2, "v2", src);
		CASE_N_INLINE_VLE32_M(3, "v3", src);
		CASE_N_INLINE_VLE32_M(4, "v4", src);
		CASE_N_INLINE_VLE32_M(5, "v5", src);
		CASE_N_INLINE_VLE32_M(6, "v6", src);
		CASE_N_INLINE_VLE32_M(7, "v7", src);
		CASE_N_INLINE_VLE32_M(8, "v8", src);
		CASE_N_INLINE_VLE32_M(9, "v9", src);
		CASE_N_INLINE_VLE32_M(10, "v10", src);
		CASE_N_INLINE_VLE32_M(11, "v11", src);
		CASE_N_INLINE_VLE32_M(12, "v12", src);
		CASE_N_INLINE_VLE32_M(13, "v13", src);
		CASE_N_INLINE_VLE32_M(14, "v14", src);
		CASE_N_INLINE_VLE32_M(15, "v15", src);
		CASE_N_INLINE_VLE32_M(16, "v16", src);
		CASE_N_INLINE_VLE32_M(17, "v17", src);
		CASE_N_INLINE_VLE32_M(18, "v18", src);
		CASE_N_INLINE_VLE32_M(19, "v19", src);
		CASE_N_INLINE_VLE32_M(20, "v20", src);
		CASE_N_INLINE_VLE32_M(21, "v21", src);
		CASE_N_INLINE_VLE32_M(22, "v22", src);
		CASE_N_INLINE_VLE32_M(23, "v23", src);
		CASE_N_INLINE_VLE32_M(24, "v24", src);
		CASE_N_INLINE_VLE32_M(25, "v25", src);
		CASE_N_INLINE_VLE32_M(26, "v26", src);
		CASE_N_INLINE_VLE32_M(27, "v27", src);
		CASE_N_INLINE_VLE32_M(28, "v28", src);
		CASE_N_INLINE_VLE32_M(29, "v29", src);
		CASE_N_INLINE_VLE32_M(30, "v30", src);
		CASE_N_INLINE_VLE32_M(31, "v31", src);
	}
}

static inline void set_masked_vector_from_array_u64(int n, sbi_vector_data *src)
{
	switch (n) {
		// CASE_N_INLINE_VLE64_M(0, "v0", src);
		CASE_N_INLINE_VLE64_M(1, "v1", src);
		CASE_N_INLINE_VLE64_M(2, "v2", src);
		CASE_N_INLINE_VLE64_M(3, "v3", src);
		CASE_N_INLINE_VLE64_M(4, "v4", src);
		CASE_N_INLINE_VLE64_M(5, "v5", src);
		CASE_N_INLINE_VLE64_M(6, "v6", src);
		CASE_N_INLINE_VLE64_M(7, "v7", src);
		CASE_N_INLINE_VLE64_M(8, "v8", src);
		CASE_N_INLINE_VLE64_M(9, "v9", src);
		CASE_N_INLINE_VLE64_M(10, "v10", src);
		CASE_N_INLINE_VLE64_M(11, "v11", src);
		CASE_N_INLINE_VLE64_M(12, "v12", src);
		CASE_N_INLINE_VLE64_M(13, "v13", src);
		CASE_N_INLINE_VLE64_M(14, "v14", src);
		CASE_N_INLINE_VLE64_M(15, "v15", src);
		CASE_N_INLINE_VLE64_M(16, "v16", src);
		CASE_N_INLINE_VLE64_M(17, "v17", src);
		CASE_N_INLINE_VLE64_M(18, "v18", src);
		CASE_N_INLINE_VLE64_M(19, "v19", src);
		CASE_N_INLINE_VLE64_M(20, "v20", src);
		CASE_N_INLINE_VLE64_M(21, "v21", src);
		CASE_N_INLINE_VLE64_M(22, "v22", src);
		CASE_N_INLINE_VLE64_M(23, "v23", src);
		CASE_N_INLINE_VLE64_M(24, "v24", src);
		CASE_N_INLINE_VLE64_M(25, "v25", src);
		CASE_N_INLINE_VLE64_M(26, "v26", src);
		CASE_N_INLINE_VLE64_M(27, "v27", src);
		CASE_N_INLINE_VLE64_M(28, "v28", src);
		CASE_N_INLINE_VLE64_M(29, "v29", src);
		CASE_N_INLINE_VLE64_M(30, "v30", src);
		CASE_N_INLINE_VLE64_M(31, "v31", src);
	}
}

static inline void foreach_velem_vv(int vl, int sew, bool masked, int vd,
				    int vs1, int vs2, u64 op(u64, u64))
{
	sbi_vector_data vs1_data;
	sbi_vector_data vs2_data;
	sbi_vector_data vd_data;

	/* treat as no-op if VL is 0 */
	if (vl == 0)
		return;

	switch (sew) {
	case 0:
		get_vector_as_array_u8(vs1, &vs1_data);
		get_vector_as_array_u8(vs2, &vs2_data);
		for (int i = 0; i < vl; i++)
			vd_data.u8[i] = op(vs1_data.u8[i], vs2_data.u8[i]);
		if (masked)
			set_masked_vector_from_array_u8(vd, &vd_data);
		else
			set_vector_from_array_u8(vd, &vd_data);
		break;
	case 1:
		get_vector_as_array_u16(vs1, &vs1_data);
		get_vector_as_array_u16(vs2, &vs2_data);
		for (int i = 0; i < vl; i++)
			vd_data.u16[i] = op(vs1_data.u16[i], vs2_data.u16[i]);
		if (masked)
			set_masked_vector_from_array_u16(vd, &vd_data);
		else
			set_vector_from_array_u16(vd, &vd_data);
		break;
	case 2:
		get_vector_as_array_u32(vs1, &vs1_data);
		get_vector_as_array_u32(vs2, &vs2_data);
		for (int i = 0; i < vl; i++)
			vd_data.u32[i] = op(vs1_data.u32[i], vs2_data.u32[i]);
		if (masked)
			set_masked_vector_from_array_u32(vd, &vd_data);
		else
			set_vector_from_array_u32(vd, &vd_data);
		break;
	case 3:
		get_vector_as_array_u64(vs1, &vs1_data);
		get_vector_as_array_u64(vs2, &vs2_data);
		for (int i = 0; i < vl; i++)
			vd_data.u64[i] = op(vs1_data.u64[i], vs2_data.u64[i]);
		if (masked)
			set_masked_vector_from_array_u64(vd, &vd_data);
		else
			set_vector_from_array_u64(vd, &vd_data);
		break;
	}
}

static inline void foreach_velem_vi(int vl, int sew, bool masked, int vd,
				    u64 imm, int vs2, u64 op(u64, u64))
{
	sbi_vector_data vs2_data;
	sbi_vector_data vd_data;

	/* treat as no-op if VL is 0 */
	if (vl == 0)
		return;

	switch (sew) {
	case 0:
		get_vector_as_array_u8(vs2, &vs2_data);
		for (int i = 0; i < vl; i++)
			vd_data.u8[i] = op(imm, vs2_data.u8[i]);
		if (masked)
			set_masked_vector_from_array_u8(vd, &vd_data);
		else
			set_vector_from_array_u8(vd, &vd_data);
		break;
	case 1:
		get_vector_as_array_u16(vs2, &vs2_data);
		for (int i = 0; i < vl; i++)
			vd_data.u16[i] = op(imm, vs2_data.u16[i]);
		if (masked)
			set_masked_vector_from_array_u16(vd, &vd_data);
		else
			set_vector_from_array_u16(vd, &vd_data);
		break;
	case 2:
		get_vector_as_array_u32(vs2, &vs2_data);
		for (int i = 0; i < vl; i++)
			vd_data.u32[i] = op(imm, vs2_data.u32[i]);
		if (masked)
			set_masked_vector_from_array_u32(vd, &vd_data);
		else
			set_vector_from_array_u32(vd, &vd_data);
		break;
	case 3:
		get_vector_as_array_u64(vs2, &vs2_data);
		for (int i = 0; i < vl; i++)
			vd_data.u64[i] = op(imm, vs2_data.u64[i]);
		if (masked)
			set_masked_vector_from_array_u64(vd, &vd_data);
		else
			set_vector_from_array_u64(vd, &vd_data);
		break;
	}
}

static inline void foreach_velem_v(int vl, int sew, bool masked, int vd,
				   int vs2, u64 op(u64))
{
	sbi_vector_data vs2_data;
	sbi_vector_data vd_data;

	/* treat as no-op if VL is 0 */
	if (vl == 0)
		return;

	switch (sew) {
	case 0:
		get_vector_as_array_u8(vs2, &vs2_data);
		for (int i = 0; i < vl; i++)
			vd_data.u8[i] = op(vs2_data.u8[i]);
		if (masked)
			set_masked_vector_from_array_u8(vd, &vd_data);
		else
			set_vector_from_array_u8(vd, &vd_data);
		break;
	case 1:
		get_vector_as_array_u16(vs2, &vs2_data);
		for (int i = 0; i < vl; i++)
			vd_data.u16[i] = op(vs2_data.u16[i]);
		if (masked)
			set_masked_vector_from_array_u16(vd, &vd_data);
		else
			set_vector_from_array_u16(vd, &vd_data);
		break;
	case 2:
		get_vector_as_array_u32(vs2, &vs2_data);
		for (int i = 0; i < vl; i++)
			vd_data.u32[i] = op(vs2_data.u32[i]);
		if (masked)
			set_masked_vector_from_array_u32(vd, &vd_data);
		else
			set_vector_from_array_u32(vd, &vd_data);
		break;
	case 3:
		get_vector_as_array_u64(vs2, &vs2_data);
		for (int i = 0; i < vl; i++)
			vd_data.u64[i] = op(vs2_data.u64[i]);
		if (masked)
			set_masked_vector_from_array_u64(vd, &vd_data);
		else
			set_vector_from_array_u64(vd, &vd_data);
		break;
	}
}

static inline bool foreach_velem_wvv(int vl, int sew, bool masked, int vd,
				     int vs1, int vs2, u64 op(u64, u64))
{
	sbi_vector_data vs1_data;
	sbi_vector_data vs2_data;
	sbi_vector_data vd_data;

	/* treat as no-op if VL is 0 */
	if (vl == 0)
		return true;
	/* back out if this VL combined with the widened SEW is too big */
	if (vl * (2 << sew) > VLMAX_BYTES)
		return false;

	switch (sew) {
	case 0:
		get_vector_as_array_u8(vs1, &vs1_data);
		get_vector_as_array_u8(vs2, &vs2_data);
		for (int i = 0; i < vl; i++)
			vd_data.u16[i] = op(vs1_data.u8[i], vs2_data.u8[i]);
		if (masked)
			set_masked_vector_from_array_u16(vd, &vd_data);
		else
			set_vector_from_array_u16(vd, &vd_data);
		break;
	case 1:
		get_vector_as_array_u16(vs1, &vs1_data);
		get_vector_as_array_u16(vs2, &vs2_data);
		for (int i = 0; i < vl; i++)
			vd_data.u32[i] = op(vs1_data.u16[i], vs2_data.u16[i]);
		if (masked)
			set_masked_vector_from_array_u32(vd, &vd_data);
		else
			set_vector_from_array_u32(vd, &vd_data);
		break;
	case 2:
		get_vector_as_array_u32(vs1, &vs1_data);
		get_vector_as_array_u32(vs2, &vs2_data);
		for (int i = 0; i < vl; i++)
			vd_data.u64[i] = op(vs1_data.u32[i], vs2_data.u32[i]);
		if (masked)
			set_masked_vector_from_array_u64(vd, &vd_data);
		else
			set_vector_from_array_u64(vd, &vd_data);
		break;
	}
	return true;
}

static inline bool foreach_velem_wvi(int vl, int sew, bool masked, int vd,
				     u64 imm, int vs2, u64 op(u64, u64))
{
	sbi_vector_data vs2_data;
	sbi_vector_data vd_data;

	/* treat as no-op if VL is 0 */
	if (vl == 0)
		return true;
	/* back out if this VL combined with the widened SEW is too big */
	if (vl * (2 << sew) > VLMAX_BYTES)
		return false;

	switch (sew) {
	case 0:
		get_vector_as_array_u8(vs2, &vs2_data);
		for (int i = 0; i < vl; i++)
			vd_data.u16[i] = op(imm, vs2_data.u8[i]);
		if (masked)
			set_masked_vector_from_array_u16(vd, &vd_data);
		else
			set_vector_from_array_u16(vd, &vd_data);
		break;
	case 1:
		get_vector_as_array_u16(vs2, &vs2_data);
		for (int i = 0; i < vl; i++)
			vd_data.u32[i] = op(imm, vs2_data.u16[i]);
		if (masked)
			set_masked_vector_from_array_u32(vd, &vd_data);
		else
			set_vector_from_array_u32(vd, &vd_data);
		break;
	case 2:
		get_vector_as_array_u32(vs2, &vs2_data);
		for (int i = 0; i < vl; i++)
			vd_data.u64[i] = op(imm, vs2_data.u32[i]);
		if (masked)
			set_masked_vector_from_array_u64(vd, &vd_data);
		else
			set_vector_from_array_u64(vd, &vd_data);
		break;
	}
	return true;
}

static inline u64 op_andn(u64 op1, u64 op2)
{
	return ~op1 & op2;
}

static inline u64 op_rol_u8(u64 op1, u64 op2)
{
	op2 &= 0xff;
	op1 &= 7;
	return ((op2 << op1) | (op2 >> (8 - op1))) & 0xff;
}

static inline u64 op_rol_u16(u64 op1, u64 op2)
{
	op2 &= 0xffff;
	op1 &= 0xf;
	return ((op2 << op1) | (op2 >> (16 - op1))) & 0xffff;
}

static inline u64 op_rol_u32(u64 op1, u64 op2)
{
	op2 &= 0xffffffff;
	op1 &= 0x1f;
	return ((op2 << op1) | (op2 >> (32 - op1))) & 0xffffffff;
}

static inline u64 op_rol_u64(u64 op1, u64 op2)
{
	op1 &= 0x3f;
	return (op2 << op1) | (op2 >> (64 - op1));
}

typeof(u64(u64, u64)) *ops_rol[4] = { op_rol_u8, op_rol_u16, op_rol_u32,
				      op_rol_u64 };

static inline u64 op_ror_u8(u64 op1, u64 op2)
{
	op2 &= 0xff;
	op1 &= 7;
	return ((op2 >> op1) | (op2 << (8 - op1))) & 0xff;
}

static inline u64 op_ror_u16(u64 op1, u64 op2)
{
	op2 &= 0xffff;
	op1 &= 0xf;
	return ((op2 >> op1) | (op2 << (16 - op1))) & 0xffff;
}

static inline u64 op_ror_u32(u64 op1, u64 op2)
{
	op2 &= 0xffffffff;
	op1 &= 0x1f;
	return ((op2 >> op1) | (op2 << (32 - op1))) & 0xffffffff;
}

static inline u64 op_ror_u64(u64 op1, u64 op2)
{
	op1 &= 0x3f;
	return (op2 >> op1) | (op2 << (64 - op1));
}

typeof(u64(u64, u64)) *ops_ror[4] = { op_ror_u8, op_ror_u16, op_ror_u32,
				      op_ror_u64 };

static inline u64 op_wsll_u8(u64 op1, u64 op2)
{
	op1 &= 0xf;
	return (op2 << op1) & 0xffff;
}

static inline u64 op_wsll_u16(u64 op1, u64 op2)
{
	op1 &= 0x1f;
	return (op2 << op1) & 0xffffffff;
}

static inline u64 op_wsll_u32(u64 op1, u64 op2)
{
	op1 &= 0x3f;
	return op2 << op1;
}

typeof(u64(u64, u64)) *ops_wsll[4] = { op_wsll_u8, op_wsll_u16, op_wsll_u32,
				       op_wsll_u32 };

static inline u64 op_brev8(u64 op)
{
	return ((op & 0x8080808080808080) >> 7) |
	       ((op & 0x4040404040404040) >> 5) |
	       ((op & 0x2020202020202020) >> 3) |
	       ((op & 0x1010101010101010) >> 1) |
	       ((op & 0x0808080808080808) << 1) |
	       ((op & 0x0404040404040404) << 3) |
	       ((op & 0x0202020202020202) << 5) |
	       ((op & 0x0101010101010101) << 7);
}

static inline u64 op_rev8(u64 op1, u64 op2)
{
	u64 result;
	asm volatile(".option push\n\t"
		     ".option arch, +zbb\n\t"
		     "rev8 %0, %2\n\t"
		     "srl %0, %0, %1\n\t"
		     ".option pop\n\t"
		     : "=r"(result)
		     : "r"(op1), "r"(op2));
	return result;
}

static inline u64 op_brev(u64 op1, u64 op2)
{
	return op_rev8(op1, op_brev8(op2));
}

static inline u64 op_clz(u64 op1, u64 op2)
{
	u64 result;
	asm volatile(".option push\n\t"
		     ".option arch, +zbb\n\t"
		     "clz %0, %2\n\t"
		     "sub %0, %0, %1\n\t"
		     ".option pop\n\t"
		     : "=r"(result)
		     : "r"(op1), "r"(op2));
	return result;
}

static inline u64 op_ctz(u64 op1, u64 op2)
{
	u64 result;
	asm volatile(".option push\n\t"
		     ".option arch, +zbb\n\t"
		     "ctz %0, %2\n\t"
		     "minu %0, %0, %1\n\t"
		     ".option pop\n\t"
		     : "=r"(result)
		     : "r"(op1), "r"(op2));
	return result;
}

static inline u64 op_cpop(u64 op)
{
	u64 result;
	asm volatile(".option push\n\t"
		     ".option arch, +zbb\n\t"
		     "cpop %0, %1\n\t"
		     ".option pop\n\t"
		     : "=r"(result)
		     : "r"(op));
	return result;
}

int sbi_insn_emu_op_v(ulong insn, struct sbi_trap_regs *regs)
{
	/* back out if vector unit is not available */
	if ((regs->mstatus & MSTATUS_VS) == 0 ||
	    (sbi_mstatus_prev_mode(regs->mstatus) == PRV_U &&
	     (csr_read(CSR_SSTATUS) & SSTATUS_VS) == 0))
		return truly_illegal_insn(insn, regs);

	int vl = csr_read(CSR_VL);
	int vs1 = GET_VS1(insn);
	int vs2 = GET_VS2(insn);
	int vd = GET_VD(insn);
	u32 vtype = csr_read(CSR_VTYPE);
	int sew = GET_VSEW(vtype);
	bool m = IS_MASKED(insn);
	u64 rs1 = GET_RS1(insn, regs);

	/* back out if this VL combined with this SEW is too big */
	if (vl * (1 << sew) > VLMAX_BYTES)
		return truly_illegal_insn(insn, regs);

	switch (insn & INSN_MASK_VXUNARY0) {
	/* Emulate Zvbb unary operations */
	case INSN_MATCH_VBREVV:
		foreach_velem_vi(vl, sew, m, vd, 64 - (8 << sew), vs2, op_brev);
		break;
	case INSN_MATCH_VBREV8V:
		foreach_velem_v(vl, sew, m, vd, vs2, op_brev8);
		break;
	case INSN_MATCH_VREV8V:
		foreach_velem_vi(vl, sew, m, vd, 64 - (8 << sew), vs2, op_rev8);
		break;
	case INSN_MATCH_VCLZV:
		foreach_velem_vi(vl, sew, m, vd, 64 - (8 << sew), vs2, op_clz);
		break;
	case INSN_MATCH_VCTZV:
		foreach_velem_vi(vl, sew, m, vd, 8 << sew, vs2, op_ctz);
		break;
	case INSN_MATCH_VCPOPV:
		foreach_velem_v(vl, sew, m, vd, vs2, op_cpop);
		break;
	default:
		switch (insn & INSN_MASK_VVBINARY0) {
		/* Emulate Zvbb binary operations */
		case INSN_MATCH_VANDNVV:
			foreach_velem_vv(vl, sew, m, vd, vs1, vs2, op_andn);
			break;
		case INSN_MATCH_VANDNVX:
			foreach_velem_vi(vl, sew, m, vd, rs1, vs2, op_andn);
			break;
		case INSN_MATCH_VROLVV:
			foreach_velem_vv(vl, sew, m, vd, vs1, vs2,
					 ops_rol[sew]);
			break;
		case INSN_MATCH_VROLVX:
			foreach_velem_vi(vl, sew, m, vd, rs1, vs2,
					 ops_rol[sew]);
			break;
		case INSN_MATCH_VRORVV:
			foreach_velem_vv(vl, sew, m, vd, vs1, vs2,
					 ops_ror[sew]);
			break;
		case INSN_MATCH_VRORVX:
			foreach_velem_vi(vl, sew, m, vd, rs1, vs2,
					 ops_ror[sew]);
			break;
		case INSN_MATCH_VRORVI:
		case INSN_MATCH_VRORVI | 0x04000000:
			foreach_velem_vi(vl, sew, m, vd,
					 GET_RS1_NUM(insn) |
						 ((insn & 0x04000000) >> 21),
					 vs2, ops_ror[sew]);
			break;
		case INSN_MATCH_VWSLLVV:
			if (!foreach_velem_wvv(vl, sew, m, vd, vs1, vs2,
					       ops_wsll[sew]))
				return truly_illegal_insn(insn, regs);
			break;
		case INSN_MATCH_VWSLLVX:
			if (!foreach_velem_wvi(vl, sew, m, vd, rs1, vs2,
					       ops_wsll[sew]))
				return truly_illegal_insn(insn, regs);
			break;
		case INSN_MATCH_VWSLLVI:
			if (!foreach_velem_wvi(vl, sew, m, vd,
					       GET_RS1_NUM(insn), vs2,
					       ops_wsll[sew]))
				return truly_illegal_insn(insn, regs);
			break;
		default:
			return truly_illegal_insn(insn, regs);
		}
	}

	regs->mepc += 4;

	return 0;
}

#endif
