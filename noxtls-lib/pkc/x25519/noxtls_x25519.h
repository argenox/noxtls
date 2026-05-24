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
* File:    noxtls_x25519.h
* Summary: X25519 key agreement (Curve25519, RFC 7748) definition
*
*
*****************************************************************************/

#ifndef _NOXTLS_X25519_H_
#define _NOXTLS_X25519_H_

#include <stdint.h>

#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Key / field element size in bytes (RFC 7748). */
#define NOXTLS_X25519_KEY_SIZE              32U
/** Same as @ref NOXTLS_X25519_KEY_SIZE (Montgomery u-coordinate limb). */
#define NOXTLS_X25519_FE_BYTES              NOXTLS_X25519_KEY_SIZE
/** Bignum product buffer for 32-by-32 multiply modulo p. */
#define NOXTLS_X25519_BN_PRODUCT_BYTES      64U
/** Working buffer for field addition partial sum. */
#define NOXTLS_X25519_BN_SUM_BYTES          64U
/** Montgomery ladder loop: iterate t from this value down to 0 (RFC 7748, 255 bits). */
#define NOXTLS_X25519_SCALAR_LOOP_TOP       254U
/** Clamp first byte of scalar (RFC 7748). */
#define NOXTLS_X25519_CLAMP_BYTE0_MASK      248U
/** Clamp last byte of scalar, AND mask (RFC 7748). */
#define NOXTLS_X25519_CLAMP_BYTE31_AND      127U
/** Clamp last byte of scalar, OR mask (RFC 7748). */
#define NOXTLS_X25519_CLAMP_BYTE31_OR        64U
/** Clear high bit of peer u-coordinate (RFC 7748 decode). */
#define NOXTLS_X25519_U_COORD_HIGH_CLEAR    0x7FU
/** Clear high bit of shared secret / output u-coordinate (RFC 7748). */
#define NOXTLS_X25519_RESULT_HIGH_CLEAR     0x7FU
/** DRBG output length in bits for a 32-byte private key. */
#define NOXTLS_X25519_DRBG_SEED_BITS        256U
/** Entropy seed size for DRBG instantiation (implementation choice). */
#define NOXTLS_X25519_DRBG_ENTROPY_SEED_BYTES 48U

/**
 * @brief Clamp a 32-byte scalar for X25519 in place (RFC 7748).
 * @param k Little-endian scalar buffer (`NOXTLS_X25519_KEY_SIZE` bytes).
 * @return None.
 */
void noxtls_x25519_clamp_scalar(uint8_t k[NOXTLS_X25519_KEY_SIZE]);

/**
 * @brief Compute public key from private key: X25519(private_key, 9) (RFC 7748).
 * @param private_key 32-byte little-endian private key (should already be clamped for keygen output).
 * @param public_key 32-byte little-endian public u-coordinate output.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_x25519_public_key(const uint8_t private_key[NOXTLS_X25519_KEY_SIZE],
                                        uint8_t public_key[NOXTLS_X25519_KEY_SIZE]);

/**
 * @brief Compute shared secret: X25519(private_key, peer_public_key) (RFC 7748).
 * @param private_key 32-byte little-endian private key.
 * @param peer_public_key 32-byte little-endian peer public key.
 * @param shared_secret 32-byte little-endian shared secret output.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_x25519_shared_secret(const uint8_t private_key[NOXTLS_X25519_KEY_SIZE],
                                            const uint8_t peer_public_key[NOXTLS_X25519_KEY_SIZE],
                                            uint8_t shared_secret[NOXTLS_X25519_KEY_SIZE]);

/**
 * @brief Generate a random key pair (DRBG), clamp private key, derive public key.
 * @param private_key Output 32-byte little-endian private key.
 * @param public_key Output 32-byte little-endian public key.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_x25519_generate_key(uint8_t private_key[NOXTLS_X25519_KEY_SIZE],
                                           uint8_t public_key[NOXTLS_X25519_KEY_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_X25519_H_ */
