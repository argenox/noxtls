/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_x448.h
* Summary: X448 key agreement (Curve448, RFC 7748)
*
*/

#ifndef _NOXTLS_X448_H_
#define _NOXTLS_X448_H_

#include <stdint.h>

#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Key / field element size in bytes (RFC 7748). */
#define NOXTLS_X448_KEY_SIZE                56U
/** Same as @ref NOXTLS_X448_KEY_SIZE (Montgomery u-coordinate limb). */
#define NOXTLS_X448_FE_BYTES                NOXTLS_X448_KEY_SIZE
/** Bignum product buffer for 56-by-56 multiply modulo p. */
#define NOXTLS_X448_BN_PRODUCT_BYTES        112U
/** Working buffer for field addition partial sum. */
#define NOXTLS_X448_BN_SUM_BYTES            112U
/** Montgomery ladder: iterate t from this value down to 0 (RFC 7748, 448 bits). */
#define NOXTLS_X448_SCALAR_LOOP_TOP         447U
/** Clamp first byte of scalar (RFC 7748). */
#define NOXTLS_X448_CLAMP_BYTE0_MASK        252U
/** Set high bit on last byte of scalar (RFC 7748). */
#define NOXTLS_X448_CLAMP_HIGH_OR           128U
/** DRBG output length in bits for a 56-byte private key. */
#define NOXTLS_X448_DRBG_SEED_BITS          448U
/** Entropy seed size for DRBG instantiation (implementation choice). */
#define NOXTLS_X448_DRBG_ENTROPY_SEED_BYTES  48U

/**
 * @brief Clamp a 56-byte scalar for X448 in place (RFC 7748).
 * @param k Little-endian scalar buffer (`NOXTLS_X448_KEY_SIZE` bytes).
 * @return None.
 */
void noxtls_x448_clamp_scalar(uint8_t k[NOXTLS_X448_KEY_SIZE]);

/**
 * @brief Compute public key from private key: X448(private_key, 5) (RFC 7748).
 * @param private_key 56-byte little-endian private key.
 * @param public_key 56-byte little-endian public u-coordinate output.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_x448_public_key(const uint8_t private_key[NOXTLS_X448_KEY_SIZE],
                                       uint8_t public_key[NOXTLS_X448_KEY_SIZE]);

/**
 * @brief Compute shared secret: X448(private_key, peer_public_key) (RFC 7748).
 * @param private_key 56-byte little-endian private key.
 * @param peer_public_key 56-byte little-endian peer public key.
 * @param shared_secret 56-byte little-endian shared secret output.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_x448_shared_secret(const uint8_t private_key[NOXTLS_X448_KEY_SIZE],
                                          const uint8_t peer_public_key[NOXTLS_X448_KEY_SIZE],
                                          uint8_t shared_secret[NOXTLS_X448_KEY_SIZE]);

/**
 * @brief Generate a random key pair (DRBG), clamp private key, derive public key.
 * @param private_key Output 56-byte little-endian private key.
 * @param public_key Output 56-byte little-endian public key.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_x448_generate_key(uint8_t private_key[NOXTLS_X448_KEY_SIZE],
                                         uint8_t public_key[NOXTLS_X448_KEY_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_X448_H_ */
