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
* File:    noxtls_ed25519_fe.h
* Summary: Native GF(2^255-19) field element types and API
*
*
*****************************************************************************/

/**
 * @file noxtls_ed25519_fe.h
 * @brief Native limb field-element API for Ed25519 (RFC 8032 field arithmetic).
 * @ingroup noxtls_ed25519
 */

#ifndef _NOXTLS_ED25519_FE_H_
#define _NOXTLS_ED25519_FE_H_

#include <stdint.h>

#include "noxtls_ed25519.h"
#include "noxtls_ed25519_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Native field element: ten signed 26/25-bit limbs (ref10 layout). */
typedef struct
{
    int32_t v[NOXTLS_ED25519_FE_LIMBS];
} fe25519_native_t;

/**
 * @brief Copy a native field element.
 *
 * @param[out] dst Destination.
 * @param[in] src Source.
 */
void fe25519_native_copy(fe25519_native_t *dst, const fe25519_native_t *src);

/**
 * @brief Set a native field element to zero.
 *
 * @param[out] a Element to clear.
 */
void fe25519_native_zero(fe25519_native_t *a);

/**
 * @brief Set a native field element to one.
 *
 * @param[out] a Element to set.
 */
void fe25519_native_one(fe25519_native_t *a);

/**
 * @brief Load a little-endian 32-byte encoding into native limbs.
 *
 * @param[out] out Native field element.
 * @param[in] in Little-endian bytes (`NOXTLS_ED25519_FE25519_BYTES`).
 */
void fe25519_native_from_le(fe25519_native_t *out,
                            const uint8_t in[NOXTLS_ED25519_FE25519_BYTES]);

/**
 * @brief Store a native field element as little-endian 32 bytes.
 *
 * @param[out] out Little-endian bytes.
 * @param[in] in Native field element.
 */
void fe25519_native_to_le(uint8_t out[NOXTLS_ED25519_FE25519_BYTES],
                          const fe25519_native_t *in);

/**
 * @brief Load a big-endian 32-byte encoding into native limbs.
 *
 * @param[out] out Native field element.
 * @param[in] be Big-endian bytes.
 */
void fe25519_native_from_be(fe25519_native_t *out,
                            const uint8_t be[NOXTLS_ED25519_FE25519_BYTES]);

/**
 * @brief Store a native field element as big-endian 32 bytes.
 *
 * @param[out] be Big-endian bytes.
 * @param[in] in Native field element.
 */
void fe25519_native_to_be(uint8_t be[NOXTLS_ED25519_FE25519_BYTES],
                          const fe25519_native_t *in);

/**
 * @brief Field addition: out = a + b (unreduced limbs OK).
 *
 * @param[out] out Sum.
 * @param[in] a First addend.
 * @param[in] b Second addend.
 */
void fe25519_native_add(fe25519_native_t *out,
                        const fe25519_native_t *a,
                        const fe25519_native_t *b);

/**
 * @brief Field subtraction: out = a - b (unreduced limbs OK).
 *
 * @param[out] out Difference.
 * @param[in] a Minuend.
 * @param[in] b Subtrahend.
 */
void fe25519_native_sub(fe25519_native_t *out,
                        const fe25519_native_t *a,
                        const fe25519_native_t *b);

/**
 * @brief Field negation: out = -a.
 *
 * @param[out] out Negated value.
 * @param[in] a Input.
 */
void fe25519_native_neg(fe25519_native_t *out, const fe25519_native_t *a);

/**
 * @brief Field multiplication: out = a * b mod p.
 *
 * @param[out] out Product.
 * @param[in] a First factor.
 * @param[in] b Second factor.
 */
void fe25519_native_mul(fe25519_native_t *out,
                        const fe25519_native_t *a,
                        const fe25519_native_t *b);

/**
 * @brief Field square: out = a^2 mod p.
 *
 * @param[out] out Square.
 * @param[in] a Input.
 */
void fe25519_native_sq(fe25519_native_t *out, const fe25519_native_t *a);

/**
 * @brief Multiplicative inverse via Fermat: out = a^(p-2) mod p.
 *
 * @param[out] out Inverse.
 * @param[in] z Input (non-zero).
 */
void fe25519_native_inv(fe25519_native_t *out, const fe25519_native_t *z);

/**
 * @brief Compute out = z^((p-5)/8) via ref10-style addition chain (RFC 8032 §5.1.3).
 *
 * @param[out] out Power.
 * @param[in] z Input.
 */
void fe25519_native_pow22523(fe25519_native_t *out, const fe25519_native_t *z);

/**
 * @brief Constant-time conditional move: if b != 0 then f = g.
 *
 * @param[in,out] f Destination (unchanged when @p b is 0).
 * @param[in] g Source.
 * @param[in] b Selector bit (0 or 1).
 */
void fe25519_native_cmov(fe25519_native_t *f,
                         const fe25519_native_t *g,
                         unsigned int b);

/**
 * @brief Return the least significant bit of the canonical representative (sign bit helper).
 *
 * @param[in] f Field element.
 *
 * @return 0 or 1.
 */
unsigned int fe25519_native_isnegative(const fe25519_native_t *f);

/**
 * @brief Constant-time zero test after canonicalization.
 *
 * @param[in] f Field element.
 *
 * @return 1 if zero, else 0.
 */
unsigned int fe25519_native_iszero(const fe25519_native_t *f);

/**
 * @brief Compare two field elements for equality after canonicalization.
 *
 * @param[in] a First element.
 * @param[in] b Second element.
 *
 * @return 1 if equal, else 0.
 */
unsigned int fe25519_native_equal(const fe25519_native_t *a,
                                  const fe25519_native_t *b);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_ED25519_FE_H_ */
