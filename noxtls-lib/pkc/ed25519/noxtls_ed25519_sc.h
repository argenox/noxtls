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
* File:    noxtls_ed25519_sc.h
* Summary: Ed25519 scalar arithmetic mod L (RFC 8032 / SUPERCOP ref10)
*
*
*****************************************************************************/

/**
 * @file noxtls_ed25519_sc.h
 * @brief Scalar reduction and muladd modulo L for Ed25519.
 * @ingroup noxtls_ed25519
 *
 * Implements SUPERCOP/ref10 `sc_reduce` and `sc_muladd` for the group order
 * L = 2^252 + 27742317777372353535851937790883648493 (RFC 8032).
 * Inputs and outputs use little-endian wire encoding at the API edge.
 */

#ifndef _NOXTLS_ED25519_SC_H_
#define _NOXTLS_ED25519_SC_H_

#include <stdint.h>

#include "noxtls_ed25519.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Reduce a 64-byte little-endian integer modulo L (ref10 sc_reduce).
 *
 * @param[out] out_le Reduced 32-byte little-endian scalar.
 * @param[in] in_le 64-byte little-endian input.
 */
void sc25519_reduce(uint8_t out_le[NOXTLS_ED25519_FE25519_BYTES],
                    const uint8_t in_le[NOXTLS_ED25519_SHA512_DIGEST_BYTES]);

/**
 * @brief Compute out = (a*b + c) mod L (ref10 sc_muladd).
 *
 * @param[out] out_le Resulting 32-byte little-endian scalar.
 * @param[in] a_le First factor (32-byte LE).
 * @param[in] b_le Second factor (32-byte LE).
 * @param[in] c_le Addend (32-byte LE).
 */
void sc25519_muladd(uint8_t out_le[NOXTLS_ED25519_FE25519_BYTES],
                    const uint8_t a_le[NOXTLS_ED25519_FE25519_BYTES],
                    const uint8_t b_le[NOXTLS_ED25519_FE25519_BYTES],
                    const uint8_t c_le[NOXTLS_ED25519_FE25519_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_ED25519_SC_H_ */
