/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
*
* File:    noxtls_x25519.h
* Summary: X25519 key agreement (Curve25519, RFC 7748)
*
*/

#ifndef _NOXTLS_X25519_H_
#define _NOXTLS_X25519_H_

#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NOXTLS_X25519_KEY_SIZE  32

/**
 * Clamp a 32-byte scalar for X25519 (in place).
 * k[0] &= 248; k[31] &= 127; k[31] |= 64.
 */
void noxtls_x25519_clamp_scalar(uint8_t k[32]);

/**
 * Compute public key from private key.
 * public_key = X25519(private_key, 9) where 9 is the base point u-coordinate.
 * All arrays are 32 bytes, little-endian.
 */
noxtls_return_t noxtls_x25519_public_key(const uint8_t private_key[32], uint8_t public_key[32]);

/**
 * Compute shared secret.
 * shared_secret = X25519(private_key, peer_public_key).
 * All arrays are 32 bytes, little-endian.
 */
noxtls_return_t noxtls_x25519_shared_secret(const uint8_t private_key[32],
                                            const uint8_t peer_public_key[32],
                                            uint8_t shared_secret[32]);

/**
 * Generate a key pair: random 32-byte private (clamped), then public key.
 * Uses the library DRBG for the private key.
 */
noxtls_return_t noxtls_x25519_generate_key(uint8_t private_key[32], uint8_t public_key[32]);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_X25519_H_ */
