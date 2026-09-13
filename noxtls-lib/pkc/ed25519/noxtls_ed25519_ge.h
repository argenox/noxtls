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
* File:    noxtls_ed25519_ge.h
* Summary: Ed25519 group element types and arithmetic API
*
*
*****************************************************************************/

/**
 * @file noxtls_ed25519_ge.h
 * @brief Extended Edwards group operations with native field limbs (RFC 8032).
 * @ingroup noxtls_ed25519
 */

#ifndef _NOXTLS_ED25519_GE_H_
#define _NOXTLS_ED25519_GE_H_

#include <stdint.h>

#include "noxtls_common.h"
#include "noxtls_ed25519.h"
#include "noxtls_ed25519_config.h"
#include "noxtls_ed25519_fe.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Extended homogeneous point (X : Y : Z : T) with T = XY/Z, native limbs.
 * Public ABI type @ref ge25519_pt_t remains big-endian byte arrays.
 */
typedef struct
{
    fe25519_native_t X;
    fe25519_native_t Y;
    fe25519_native_t Z;
    fe25519_native_t T;
} ge25519_n_t;

/**
 * @brief Convert a public BE point into native extended coordinates.
 *
 * @param[out] out Native point.
 * @param[in] in Big-endian extended point.
 */
void ge25519_n_from_pt(ge25519_n_t *out, const ge25519_pt_t *in);

/**
 * @brief Convert a native extended point into the public BE representation.
 *
 * @param[out] out Big-endian extended point.
 * @param[in] in Native point.
 */
void ge25519_n_to_pt(ge25519_pt_t *out, const ge25519_n_t *in);

/**
 * @brief Set a native point to the group identity.
 *
 * @param[out] p Point to clear.
 */
void ge25519_n_zero(ge25519_n_t *p);

/**
 * @brief Extended point addition for a = -1 (RFC 8032 §5.1.4).
 *
 * @param[out] r Sum p + q.
 * @param[in] p First summand.
 * @param[in] q Second summand.
 */
void ge25519_n_add(ge25519_n_t *r, const ge25519_n_t *p, const ge25519_n_t *q);

/**
 * @brief Extended point doubling (RFC 8032 §5.1.4).
 *
 * @param[out] r Double of p.
 * @param[in] p Input point.
 */
void ge25519_n_dbl(ge25519_n_t *r, const ge25519_n_t *p);

/**
 * @brief Negate a point: (X:Y:Z:T) -> (-X:Y:Z:-T).
 *
 * @param[out] r Negated point.
 * @param[in] p Input point.
 */
void ge25519_n_neg(ge25519_n_t *r, const ge25519_n_t *p);

/**
 * @brief Variable-base scalar multiplication R = s * P (windowed radix-16).
 *
 * Converts @p P from BE once and writes the BE result once.
 *
 * @param[out] R Result point (BE ABI).
 * @param[in] s_le Little-endian scalar (`NOXTLS_ED25519_FE25519_BYTES` bytes).
 * @param[in] P Base point (BE ABI).
 */
void ge25519_scalar_mult(ge25519_pt_t *R,
                         const uint8_t s_le[NOXTLS_ED25519_FE25519_BYTES],
                         const ge25519_pt_t *P);

/**
 * @brief Fixed-base scalar multiplication R = s * B using a lazy precomputed table.
 *
 * @param[out] R Result point (BE ABI).
 * @param[in] s_le Little-endian scalar.
 */
void ge25519_scalarmult_base(ge25519_pt_t *R,
                             const uint8_t s_le[NOXTLS_ED25519_FE25519_BYTES]);

/**
 * @brief Fixed-base scalar multiplication into native extended coordinates.
 *
 * @param[out] R Native result.
 * @param[in] s_le Little-endian scalar.
 */
void ge25519_scalarmult_base_n(ge25519_n_t *R,
                               const uint8_t s_le[NOXTLS_ED25519_FE25519_BYTES]);

/**
 * @brief Double-scalar: R = [a]P + [b]B (sliding-window, variable-time for verify).
 *
 * @param[out] R Result point (BE ABI).
 * @param[in] a_le Little-endian scalar for @p P.
 * @param[in] P Variable base (BE ABI).
 * @param[in] b_le Little-endian scalar for the RFC 8032 base point B.
 */
void ge25519_double_scalarmult(ge25519_pt_t *R,
                               const uint8_t a_le[NOXTLS_ED25519_FE25519_BYTES],
                               const ge25519_pt_t *P,
                               const uint8_t b_le[NOXTLS_ED25519_FE25519_BYTES]);

/**
 * @brief Double-scalar into native coordinates (ref10 p2 accumulator).
 *
 * @param[out] R Native result (X:Y:Z projective; encode via @ref ge25519_encode_n).
 * @param[in] a_le Little-endian scalar for @p P.
 * @param[in] P Native variable base.
 * @param[in] b_le Little-endian scalar for base point B.
 */
void ge25519_double_scalarmult_n(ge25519_n_t *R,
                                 const uint8_t a_le[NOXTLS_ED25519_FE25519_BYTES],
                                 const ge25519_n_t *P,
                                 const uint8_t b_le[NOXTLS_ED25519_FE25519_BYTES]);

/**
 * @brief Decode a 32-byte compressed Edwards-y encoding (RFC 8032 §5.1.3).
 *
 * @param[out] p Decoded point in BE extended coordinates.
 * @param[in] enc Compressed encoding (little-endian wire order).
 *
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` if invalid.
 */
noxtls_return_t ge25519_decode(ge25519_pt_t *p,
                               const uint8_t enc[NOXTLS_ED25519_FE25519_BYTES]);

/**
 * @brief Decode compressed point into native extended coordinates (RFC 8032 §5.1.3).
 *
 * @param[out] p Native decoded point.
 * @param[in] enc Compressed encoding (little-endian wire order).
 *
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` if invalid.
 */
noxtls_return_t ge25519_decode_n(ge25519_n_t *p,
                                 const uint8_t enc[NOXTLS_ED25519_FE25519_BYTES]);

/**
 * @brief Encode an extended point to 32-byte compressed form (RFC 8032 §5.1.2).
 *
 * @param[out] enc Compressed public encoding.
 * @param[in] p Point in BE extended coordinates.
 */
void ge25519_encode(uint8_t enc[NOXTLS_ED25519_FE25519_BYTES], const ge25519_pt_t *p);

/**
 * @brief Encode a native point to 32-byte compressed form (RFC 8032 §5.1.2).
 *
 * @param[out] enc Compressed public encoding.
 * @param[in] p Native point (projective X:Y:Z is sufficient).
 */
void ge25519_encode_n(uint8_t enc[NOXTLS_ED25519_FE25519_BYTES], const ge25519_n_t *p);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_ED25519_GE_H_ */
