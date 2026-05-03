/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
* 
*
* File:    noxtls_chacha20.h
* Summary: ChaCha20 Stream Cipher Algorithm
*
* Implementation of ChaCha20 as specified in RFC 7539
*
*/

/** @addtogroup noxtls_encryption */
/** @{ */

#ifndef _NOXTLS_CHACHA20_H_
#define _NOXTLS_CHACHA20_H_

/* Standard Includes */
#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NOXTLS_CHACHA20_DEBUG (0)

/* ChaCha20 Constants */
#define CHACHA20_KEY_SIZE       32  /* 256-bit key */
#define CHACHA20_NONCE_SIZE     12  /* 96-bit nonce (RFC 7539) */
#define CHACHA20_BLOCK_SIZE     64  /* 512-bit block */
#define CHACHA20_ROUNDS         20  /* 20 rounds (10 double rounds) */

/* ChaCha20 Context Structure */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    uint32_t state[16];      /* Internal state (16 x 32-bit words) */
    uint8_t keystream[64];   /* Current keystream block */
    uint32_t keystream_pos;  /* Position in current keystream block */
    uint64_t counter;        /* Block counter */
    uint8_t key[32];         /* Encryption key */
    uint8_t nonce[12];        /* Nonce */
} chacha20_context_t;
NOXTLS_MSVC_WARNING_POP

/**
 * @brief Initialize ChaCha20 context
 *
 * @param ctx ChaCha20 context to initialize
 * @param key Encryption key (32 bytes)
 * @param nonce Nonce (12 bytes)
 * @param counter Initial counter value (default: 0)
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL on failure
 */
noxtls_return_t chacha20_init(chacha20_context_t *ctx, 
                  const uint8_t *key, 
                  const uint8_t *nonce, 
                  uint64_t counter);

/**
 * @brief Encrypt/Decrypt data using ChaCha20
 *
 * ChaCha20 is a stream cipher, so encryption and decryption are identical
 * operations (XOR with keystream).
 *
 * @param ctx ChaCha20 context (must be initialized)
 * @param input Input data (plaintext for encryption, ciphertext for decryption)
 * @param output Output buffer (must be at least input_len bytes)
 * @param input_len Length of input data in bytes
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t chacha20_process(chacha20_context_t *ctx,
                     const uint8_t *input,
                     uint8_t *output,
                     uint32_t input_len);

/**
 * @brief Encrypt data using ChaCha20 (convenience function)
 *
 * @param key Encryption key (32 bytes)
 * @param nonce Nonce (12 bytes)
 * @param counter Initial counter value (default: 0)
 * @param input Plaintext data
 * @param input_len Length of plaintext in bytes
 * @param output Output buffer for ciphertext (must be at least input_len bytes)
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t chacha20_encrypt(const uint8_t *key,
                     const uint8_t *nonce,
                     uint64_t counter,
                     const uint8_t *input,
                     uint32_t input_len,
                     uint8_t *output);

/**
 * @brief Decrypt data using ChaCha20 (convenience function)
 *
 * @param key Encryption key (32 bytes)
 * @param nonce Nonce (12 bytes)
 * @param counter Initial counter value (default: 0)
 * @param input Ciphertext data
 * @param input_len Length of ciphertext in bytes
 * @param output Output buffer for plaintext (must be at least input_len bytes)
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t chacha20_decrypt(const uint8_t *key,
                     const uint8_t *nonce,
                     uint64_t counter,
                     const uint8_t *input,
                     uint32_t input_len,
                     uint8_t *output);

/**
 * @brief Self-test function
 *
 * @return NOXTLS_RETURN_SUCCESS on success (all tests passed)
 */
noxtls_return_t chacha20_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_CHACHA20_H_ */


