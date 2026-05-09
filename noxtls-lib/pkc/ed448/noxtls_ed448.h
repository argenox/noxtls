/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_ed448.h
* Summary: Ed448 digital signatures (RFC 8032)
*
*/

/** @addtogroup noxtls_pkc */
/** @{ */

#ifndef _NOXTLS_ED448_H_
#define _NOXTLS_ED448_H_

#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NOXTLS_ED448_PRIVATE_KEY_SIZE  57
#define NOXTLS_ED448_PUBLIC_KEY_SIZE   57
#define NOXTLS_ED448_SIGNATURE_SIZE    114
#define NOXTLS_ED448_CONTEXT_MAX       255

/**
 * Generate an Ed448 key pair.
 * private_key: 57 bytes (seed); public_key: 57 bytes. Uses library DRBG for the seed.
 */
noxtls_return_t noxtls_ed448_generate_key(uint8_t private_key[57], uint8_t public_key[57]);

/**
 * Derive public key from a 57-byte private key (seed) per RFC 8032.
 */
noxtls_return_t noxtls_ed448_public_key(const uint8_t private_key[57], uint8_t public_key[57]);

/**
 * Sign a message with Ed448 (PureEdDSA).
 * private_key: 57 bytes; message: message_len bytes; signature: 114 bytes (R || S).
 */
noxtls_return_t noxtls_ed448_sign(const uint8_t private_key[57],
                                  const uint8_t *message,
                                  uint32_t message_len,
                                  uint8_t signature[114]);

/**
 * Verify an Ed448 signature.
 * public_key: 57 bytes; message: message_len bytes; signature: 114 bytes.
 */
noxtls_return_t noxtls_ed448_verify(const uint8_t public_key[57],
                                   const uint8_t *message,
                                   uint32_t message_len,
                                   const uint8_t signature[114]);

/** Ed448ctx (RFC 8032): context length 1..NOXTLS_ED448_CONTEXT_MAX. */
noxtls_return_t noxtls_ed448ctx_sign(const uint8_t private_key[57],
                                     const uint8_t *context,
                                     uint32_t context_len,
                                     const uint8_t *message,
                                     uint32_t message_len,
                                     uint8_t signature[114]);

noxtls_return_t noxtls_ed448ctx_verify(const uint8_t public_key[57],
                                        const uint8_t *context,
                                        uint32_t context_len,
                                        const uint8_t *message,
                                        uint32_t message_len,
                                        const uint8_t signature[114]);

/** Ed448ph: PH(M) = first 64 bytes of SHAKE256(M). */
noxtls_return_t noxtls_ed448ph_sign(const uint8_t private_key[57],
                                    const uint8_t *message,
                                    uint32_t message_len,
                                    uint8_t signature[114]);

noxtls_return_t noxtls_ed448ph_verify(const uint8_t public_key[57],
                                      const uint8_t *message,
                                      uint32_t message_len,
                                      const uint8_t signature[114]);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_ED448_H_ */
