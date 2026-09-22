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

#ifndef _NOXTLS_ED25519_CONFIG_H_
#define _NOXTLS_ED25519_CONFIG_H_

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
 * table (~2.5 KiB RAM) instead of the Hamburg signed multi-comb fixed-base tables.
 * Default (undefined): signed multi-comb (Mike Hamburg ePrint 2012/309).
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
 * Enable public-domain GNU-syntax Cortex-M4 packed fe25519 mul/sqr assembly.
 * When set on ARMv7E-M / ARMv8-M Mainline, native_mul/sq/sq2 use asm/ after
 * a fast limb pack. Clang defaults to the portable 10-limb SMULL path because
 * its integrated assembler does not accept this source's divided syntax.
 */
/* The build system defines NOXTLS_ED25519_FE_USE_PACKED_ASM only when the
 * matching ARM assembly sources are part of the PKC target. */

/**
 * Sliding-window max odd multiple index for verify double-scalar.
 * Digits in [-31,31]; table holds A,3A,...,31A (16 entries). Wider than
 * classic ref10 ([-15,15]/8) to cut Hamming weight on the verify ladder.
 */
#ifndef NOXTLS_ED25519_SLIDE_ODD_COUNT
#define NOXTLS_ED25519_SLIDE_ODD_COUNT 16U
#endif

/** Maximum absolute slide digit (inclusive). */
#ifndef NOXTLS_ED25519_SLIDE_MAX_ABS
#define NOXTLS_ED25519_SLIDE_MAX_ABS 31
#endif

#endif /* _NOXTLS_ED25519_CONFIG_H_ */
