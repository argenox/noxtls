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
* File:    noxtls_ed25519_fe_arm.h
* Summary: Packed 8xuint32 FE helpers (ARM UMAAL path + portable C)
*
*
*****************************************************************************/

/**
 * @file noxtls_ed25519_fe_arm.h
 * @brief Packed little-endian 8×uint32 field helpers for Ed25519.
 * @ingroup noxtls_ed25519
 *
 * Conversion and portable schoolbook multiply live in @c noxtls_ed25519_fe_arm.c.
 * On Cortex-M4/M7 with @c NOXTLS_ED25519_FE_USE_HAASE_ASM, that file also
 * provides @c fe25519_native_mul / @c fe25519_native_sq / @c fe25519_native_sq2
 * via Haase CC0 packed UMAAL assembly.
 */

#ifndef _NOXTLS_ED25519_FE_ARM_H_
#define _NOXTLS_ED25519_FE_ARM_H_

#include <stdint.h>

#include "noxtls_ed25519_fe.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Pack native limbs to eight little-endian 32-bit words (bit 255 clear).
 *
 * Uses the same carry chain and packing as @ref fe25519_native_to_le.
 *
 * @param[out] out Eight LE limbs.
 * @param[in] in Native field element.
 */
void fe25519_limbs_to_u32(uint32_t out[8], const fe25519_native_t *in);

/**
 * @brief Unpack eight little-endian 32-bit words into native limbs.
 *
 * Equivalent to @ref fe25519_native_from_le on the 32 bytes of @p in.
 *
 * @param[out] out Native field element.
 * @param[in] in Eight LE limbs (bit 255 ignored / cleared).
 */
void fe25519_u32_to_limbs(fe25519_native_t *out, const uint32_t in[8]);

/**
 * @brief Field multiply on packed limbs: out = a * b mod (2^255-19), weakly reduced.
 *
 * Portable schoolbook on host; UMAAL product-scanning on Cortex-M4/M7.
 *
 * @param[out] out Product (8 limbs, bit 255 clear).
 * @param[in] a First factor.
 * @param[in] b Second factor.
 */
void fe25519_u32_mul(uint32_t out[8], const uint32_t a[8], const uint32_t b[8]);

/**
 * @brief Field square on packed limbs: out = a^2 mod (2^255-19), weakly reduced.
 *
 * @param[out] out Square (8 limbs, bit 255 clear).
 * @param[in] a Input.
 */
void fe25519_u32_sqr(uint32_t out[8], const uint32_t a[8]);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_ED25519_FE_ARM_H_ */
