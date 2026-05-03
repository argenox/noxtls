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

#define NOXTLS_X448_KEY_SIZE 56

/* Clamp a 56-byte scalar for X448 in place.
 * k[0] &= 252; k[55] |= 128.
 */
void noxtls_x448_clamp_scalar(uint8_t k[56]);

/* Compute public key from private key.
 * public_key = X448(private_key, 5), base point u=5.
 * All arrays are 56 bytes, little-endian.
 */
noxtls_return_t noxtls_x448_public_key(const uint8_t private_key[56], uint8_t public_key[56]);

/* Compute shared secret: X448(private_key, peer_public_key). */
noxtls_return_t noxtls_x448_shared_secret(const uint8_t private_key[56],
                                          const uint8_t peer_public_key[56],
                                          uint8_t shared_secret[56]);

/* Generate private/public key pair using DRBG. */
noxtls_return_t noxtls_x448_generate_key(uint8_t private_key[56], uint8_t public_key[56]);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_X448_H_ */
