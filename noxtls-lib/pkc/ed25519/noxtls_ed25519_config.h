/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Licensed under the GNU General Public License v2.0 or later,
* or alternatively under a commercial license from
* Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
*
* File:    noxtls_ed25519_config.h
* Summary: Tunable Ed25519 scalar-multiplication window configuration
*
*
*****************************************************************************/

/**
 * @file noxtls_ed25519_config.h
 * @brief Tunable constants for Ed25519 group arithmetic (may be adjusted later).
 * @ingroup noxtls_ed25519
 */

#ifndef NOXTLS_ED25519_CONFIG_H_
#define NOXTLS_ED25519_CONFIG_H_

#include <stdint.h>

/**
 * @defgroup noxtls_ed25519 NoxTLS Ed25519
 * @brief Ed25519 signatures and field/group arithmetic (RFC 8032).
 */

/** Ed25519 scalar / field bit length used by windowing helpers. */
#define NOXTLS_ED25519_SCALAR_BIT_LENGTH 256U

/**
 * Window width in bits for variable-base scalar multiplication.
 * Value 4 yields radix-16 (nibbles). May be tuned later for size vs speed.
 */
#ifndef NOXTLS_ED25519_SCALAR_WINDOW_BITS
#define NOXTLS_ED25519_SCALAR_WINDOW_BITS 4U
#endif

/** Radix for the selected window (2^window_bits). */
#define NOXTLS_ED25519_SCALAR_RADIX \
    (1U << (NOXTLS_ED25519_SCALAR_WINDOW_BITS))

/**
 * Number of precomputed multiples stored per variable base for unsigned windowing
 * (indices 0 .. RADIX-1, where index 0 is the identity).
 */
#define NOXTLS_ED25519_SCALAR_TABLE_ENTRIES NOXTLS_ED25519_SCALAR_RADIX

/** Number of windows in a 256-bit scalar. */
#define NOXTLS_ED25519_SCALAR_WINDOW_COUNT \
    (NOXTLS_ED25519_SCALAR_BIT_LENGTH / NOXTLS_ED25519_SCALAR_WINDOW_BITS)

/** Number of 26/25-bit limbs in a native field element (ref10 layout). */
#define NOXTLS_ED25519_FE_LIMBS 10U

/** Mask extracting one window digit from a packed scalar byte. */
#define NOXTLS_ED25519_SCALAR_WINDOW_MASK \
    ((uint8_t)(NOXTLS_ED25519_SCALAR_RADIX - 1U))

/**
 * Define `NOXTLS_ED25519_SMALL_BASE` to use a compact 16-entry extended base
 * table (2.5 KiB) instead of the Hamburg signed multi-comb fixed-base tables
 * (7.5 KiB). The small table makes keygen/sign about 3x slower.
 * Default (undefined): signed multi-comb (Mike Hamburg ePrint 2012/309).
 * Storage of either table is selected by `NOXTLS_ED25519_READONLY_COMB` /
 * `NOXTLS_ED25519_READONLY_SMALL_BASE` below.
 */
/* #define NOXTLS_ED25519_SMALL_BASE */

/**
 * Define `NOXTLS_ED25519_DUMP_BASE` when building a host dump tool that fills
 * mutable BSS tables and prints table `.inc` files to stdout.
 */
/* #define NOXTLS_ED25519_DUMP_BASE */

/**
 * Hamburg signed multi-comb parameters for fixed-base (sign/keygen).
 * Default (8,4,8): RANGE=256, 64 mixed adds + 7 doubles, 8-entry CT select
 * (same select width as ref10; ~7.5 KiB table). Prefer over (4,6,11) on M4
 * where wide CT table scans dominate the fewer-add savings.
 */
#ifndef NOXTLS_ED25519_COMB_BLOCKS
#define NOXTLS_ED25519_COMB_BLOCKS 8U
#endif
#ifndef NOXTLS_ED25519_COMB_TEETH
#define NOXTLS_ED25519_COMB_TEETH 4U
#endif
#ifndef NOXTLS_ED25519_COMB_SPACING
#define NOXTLS_ED25519_COMB_SPACING 8U
#endif

#define NOXTLS_ED25519_COMB_RANGE \
    (NOXTLS_ED25519_COMB_BLOCKS * NOXTLS_ED25519_COMB_TEETH * \
     NOXTLS_ED25519_COMB_SPACING)
#define NOXTLS_ED25519_COMB_POINTS (1U << (NOXTLS_ED25519_COMB_TEETH - 1U))
#define NOXTLS_ED25519_COMB_MASK (NOXTLS_ED25519_COMB_POINTS - 1U)

/** Signed radix-16 digit count for legacy ref10 dump tooling. */
#define NOXTLS_ED25519_BASE_DIGIT_COUNT 64U

/** Number of 16^i position tables for legacy ref10 dump tooling. */
#define NOXTLS_ED25519_BASE_POS_COUNT 32U

/**
 * Odd-multiple count for sliding-window verify tables (A,3A,...,15A).
 * Also used by legacy ref10 Bi dump tooling.
 */
#define NOXTLS_ED25519_BASE_ODD_COUNT 8U

/** Doublings between successive Bi positions (legacy dump tooling). */
#define NOXTLS_ED25519_BASE_POS_DBL_COUNT 8U

/**
 * Bytes per precomp entry (y+x, y-x, 2dxy): 3 field elements.
 * fe25519_native_t is NOXTLS_ED25519_FE_LIMBS * sizeof(int32_t).
 */
#define NOXTLS_ED25519_PRECOMP_BYTES \
    (3U * NOXTLS_ED25519_FE_LIMBS * (uint32_t)sizeof(int32_t))

/** Comb fixed-base table size in bytes. */
#define NOXTLS_ED25519_COMB_TABLE_BYTES \
    (NOXTLS_ED25519_COMB_BLOCKS * NOXTLS_ED25519_COMB_POINTS * \
     NOXTLS_ED25519_PRECOMP_BYTES)

/** Legacy ref10 Bi table size (dump tooling / optional fallback). */
#define NOXTLS_ED25519_BASE_TABLE_BYTES \
    (NOXTLS_ED25519_BASE_POS_COUNT * NOXTLS_ED25519_BASE_ODD_COUNT * \
     NOXTLS_ED25519_PRECOMP_BYTES)

/**
 * Public-domain GNU-syntax Cortex-M4 packed fe25519 mul/sqr assembly (opt-in).
 * When NOXTLS_ED25519_FE_USE_PACKED_ASM is defined on ARMv7E-M / ARMv8-M
 * Mainline with GCC, native_mul/sq/sq2 use asm/ after converting the 10-limb
 * representation to 8 packed words and back. Not enabled by default: the
 * conversion must produce the canonical encoding (the limbs are signed after
 * add / sub) and fold bit 255 of the asm result, and with those exact
 * conversions the path measured slower than the portable 10-limb SMULL path
 * on an nRF54LM20 (Cortex-M33, 128 MHz, -O2): Ed25519 verify 260 ms vs 113 ms.
 * Clang cannot use it (its integrated assembler rejects the divided syntax).
 */

/**
 * Sliding-window odd-multiple count of the base-point (B) verify table.
 * Digits of the [S]B scalar are in [-31,31]; the table holds B,3B,...,31B
 * (16 entries, const data by default). Wider than classic ref10
 * ([-15,15]/8) to cut Hamming weight on the verify ladder.
 */
#ifndef NOXTLS_ED25519_SLIDE_ODD_COUNT
#define NOXTLS_ED25519_SLIDE_ODD_COUNT 16U
#endif

/** Maximum absolute slide digit (inclusive) for the base-point scalar. */
#ifndef NOXTLS_ED25519_SLIDE_MAX_ABS
#define NOXTLS_ED25519_SLIDE_MAX_ABS 31
#endif

/**
 * Odd-multiple count of the per-verify variable-base (public key A) table
 * built on the stack by the verify double-scalar multiplication:
 * A,3A,...,(2N-1)A, 160 bytes per entry; [k]A digits are in [-(2N-1),2N-1].
 * The count trades verify stack against additions: 8 (default, 1280 B)
 * verifies as fast as 16 (2560 B; measured ~1.5% faster) because the 8 fewer
 * table additions offset the extra ladder additions; 4 (640 B) costs ~2%
 * verify time against 8. Range 1..16. Verify-only (public data).
 */
#ifndef NOXTLS_ED25519_VERIFY_A_ODD_COUNT
#define NOXTLS_ED25519_VERIFY_A_ODD_COUNT 8U
#endif
#if (NOXTLS_ED25519_VERIFY_A_ODD_COUNT < 1U) || (NOXTLS_ED25519_VERIFY_A_ODD_COUNT > 16U)
#error "NOXTLS_ED25519_VERIFY_A_ODD_COUNT must be in 1..16"
#endif

/**
 * Keep a helper out of line so its temporaries are not merged into the
 * (already large) frame of its caller: the helper's frame is only live while
 * it runs instead of for the caller's whole call chain. No speed effect: used
 * on helpers that run a handful of times per operation.
 */
#if defined(__GNUC__) || defined(__clang__)
#define NOXTLS_ED25519_NOINLINE __attribute__((noinline))
#else
#define NOXTLS_ED25519_NOINLINE
#endif

/** Maximum absolute slide digit (inclusive) for the public-key scalar. */
#define NOXTLS_ED25519_VERIFY_A_MAX_ABS \
    ((int32_t)(2U * NOXTLS_ED25519_VERIFY_A_ODD_COUNT) - 1)

/**
 * Store compact fixed-base and sliding-verify tables in read-only memory.
 * Only used with `NOXTLS_ED25519_SMALL_BASE` (2.5 KiB + 1.9 KiB flash, no
 * .bss). Zero keeps the small tables in lazily initialized RAM.
 */
#ifndef NOXTLS_ED25519_READONLY_SMALL_BASE
#define NOXTLS_ED25519_READONLY_SMALL_BASE 0
#endif
#if NOXTLS_ED25519_READONLY_SMALL_BASE
#if !defined(NOXTLS_ED25519_SMALL_BASE) || defined(NOXTLS_ED25519_DUMP_BASE)
#error "Read-only small tables require SMALL_BASE and exclude DUMP_BASE"
#endif
#if NOXTLS_ED25519_SCALAR_WINDOW_BITS != 4U || NOXTLS_ED25519_SLIDE_ODD_COUNT != 16U || \
    NOXTLS_ED25519_SLIDE_MAX_ABS != 31
#error "Read-only Ed25519 table geometry differs; regenerate and review first"
#endif
#endif

/**
 * Store the default signed multi-comb fixed-base table (7.5 KiB) and the
 * sliding-verify odd-B table (1.9 KiB) as const data generated offline
 * (noxtls_ed25519_comb_readonly.inc, tools/generate_ed25519_comb_base.c).
 * 1 (default): no Ed25519 table RAM and no first-use table build; same
 * sign/verify speed as the RAM tables. 0: legacy lazily built .bss tables
 * (9.6 KiB RAM; the first sign/keygen runs the 2.6 KiB-stack table builder).
 * Defaults to 0 with `NOXTLS_ED25519_SMALL_BASE` or `NOXTLS_ED25519_DUMP_BASE`,
 * which select other table layouts.
 */
#ifndef NOXTLS_ED25519_READONLY_COMB
#if defined(NOXTLS_ED25519_SMALL_BASE) || defined(NOXTLS_ED25519_DUMP_BASE)
#define NOXTLS_ED25519_READONLY_COMB 0
#else
#define NOXTLS_ED25519_READONLY_COMB 1
#endif
#endif
#if NOXTLS_ED25519_READONLY_COMB
#if defined(NOXTLS_ED25519_SMALL_BASE) || defined(NOXTLS_ED25519_DUMP_BASE)
#error "Read-only comb tables exclude SMALL_BASE and DUMP_BASE"
#endif
#if NOXTLS_ED25519_COMB_BLOCKS != 8U || NOXTLS_ED25519_COMB_TEETH != 4U || \
    NOXTLS_ED25519_COMB_SPACING != 8U || NOXTLS_ED25519_SLIDE_ODD_COUNT != 16U || \
    NOXTLS_ED25519_SLIDE_MAX_ABS != 31
#error "Read-only Ed25519 comb geometry differs; regenerate and review first"
#endif
#endif

/** Non-zero when every Ed25519 base table is const data (nothing built at run time). */
#if NOXTLS_ED25519_READONLY_SMALL_BASE || NOXTLS_ED25519_READONLY_COMB
#define NOXTLS_ED25519_READONLY_TABLES 1
#else
#define NOXTLS_ED25519_READONLY_TABLES 0
#endif

#endif /* NOXTLS_ED25519_CONFIG_H_ */
