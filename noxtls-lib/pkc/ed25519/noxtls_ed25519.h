/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
*
* File:    noxtls_ed25519.h
* Summary: Ed25519 digital signatures (RFC 8032)
*
*/

/** @addtogroup noxtls_pkc */
/** @{ */

#ifndef _NOXTLS_ED25519_H_
#define _NOXTLS_ED25519_H_

#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NOXTLS_ED25519_PRIVATE_KEY_SIZE  32
#define NOXTLS_ED25519_PUBLIC_KEY_SIZE   32
#define NOXTLS_ED25519_SIGNATURE_SIZE    64

/**
 * Generate an Ed25519 key pair.
 * private_key: 32 bytes (seed); public_key: 32 bytes. Uses library DRBG for the seed.
 */
noxtls_return_t noxtls_ed25519_generate_key(uint8_t private_key[32], uint8_t public_key[32]);

/**
 * Derive public key from a 32-byte private key (seed) per RFC 8032.
 * All arrays little-endian.
 */
noxtls_return_t noxtls_ed25519_public_key(const uint8_t private_key[32], uint8_t public_key[32]);

/**
 * Sign a message with Ed25519 (PureEdDSA).
 * private_key: 32 bytes; message: message_len bytes; signature: 64 bytes (R || S).
 */
noxtls_return_t noxtls_ed25519_sign(const uint8_t private_key[32],
                                    const uint8_t *message,
                                    uint32_t message_len,
                                    uint8_t signature[64]);

/**
 * Verify an Ed25519 signature.
 * public_key: 32 bytes; message: message_len bytes; signature: 64 bytes.
 */
noxtls_return_t noxtls_ed25519_verify(const uint8_t public_key[32],
                                      const uint8_t *message,
                                      uint32_t message_len,
                                      const uint8_t signature[64]);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_ED25519_H_ */
