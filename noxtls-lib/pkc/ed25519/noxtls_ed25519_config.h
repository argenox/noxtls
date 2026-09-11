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
 * table (~2.5 KiB RAM) instead of the ref10-style fixed-base flash tables.
 * Default (undefined): full SUPERCOP/ref10 Bi[32][8] precomp in .rodata (~30 KiB flash).
 */
/* #define NOXTLS_ED25519_SMALL_BASE */

/**
 * Define `NOXTLS_ED25519_DUMP_BASE` when building a host dump tool that fills
 * mutable BSS tables and prints `noxtls_ed25519_base_data.inc` to stdout.
 */
/* #define NOXTLS_ED25519_DUMP_BASE */

/** Signed radix-16 digit count for fixed-base (ref10). */
#define NOXTLS_ED25519_BASE_DIGIT_COUNT 64U

/** Number of 16^i position tables for fixed-base (ref10). */
#define NOXTLS_ED25519_BASE_POS_COUNT 32U

/**
 * Number of precomp entries per 256^i position for fixed-base (ref10):
 * stores 1B,2B,...,8B times 256^i (select by absolute digit 1..8).
 * Also used as odd-multiple count for sliding-window verify tables.
 */
#define NOXTLS_ED25519_BASE_ODD_COUNT 8U

/**
 * Doublings between successive Bi positions (256 = 2^8).
 */
#define NOXTLS_ED25519_BASE_POS_DBL_COUNT 8U

/**
 * Bytes per precomp entry (y+x, y-x, 2dxy): 3 field elements.
 * fe25519_native_t is NOXTLS_ED25519_FE_LIMBS * sizeof(int32_t).
 */
#define NOXTLS_ED25519_PRECOMP_BYTES \
    (3U * NOXTLS_ED25519_FE_LIMBS * (uint32_t)sizeof(int32_t))

/**
 * Full ref10 fixed-base table size: 32 positions * 8 multiples * precomp.
 * Bi[i][j] = (j+1)*256^i*B. Approximately 30 KiB in **flash /.rodata** by default
 * (`noxtls_ed25519_base_data.inc`). Not placed in RAM/BSS.
 * Define NOXTLS_ED25519_SMALL_BASE for a ~2.5 KiB RAM windowed table instead.
 * Define NOXTLS_ED25519_DUMP_BASE to regenerate the .inc from mutable BSS tables.
 */
#define NOXTLS_ED25519_BASE_TABLE_BYTES \
    (NOXTLS_ED25519_BASE_POS_COUNT * NOXTLS_ED25519_BASE_ODD_COUNT * \
     NOXTLS_ED25519_PRECOMP_BYTES)

/**
 * Sliding-window max odd multiple index for verify double-scalar (ref10 slide).
 * Digits in [-15,15]; table holds A,3A,...,15A (8 entries).
 */
#define NOXTLS_ED25519_SLIDE_ODD_COUNT 8U

/** Maximum absolute slide digit (inclusive). */
#define NOXTLS_ED25519_SLIDE_MAX_ABS 15

#endif /* _NOXTLS_ED25519_CONFIG_H_ */
