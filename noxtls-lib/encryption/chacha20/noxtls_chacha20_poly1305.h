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
* File:    noxtls_chacha20_poly1305.h
* Summary: ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD)
*
* Implementation of ChaCha20-Poly1305 as specified in RFC 8439
*
*/

/** @addtogroup noxtls_encryption */
/** @{ */

#ifndef _NOXTLS_CHACHA20_POLY1305_H_
#define _NOXTLS_CHACHA20_POLY1305_H_

/* Standard Includes */
#include <stdint.h>
#include "noxtls_common.h"
#include "noxtls_chacha20.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NOXTLS_CHACHA20_POLY1305_DEBUG (0)

/* ChaCha20-Poly1305 Constants */
#define CHACHA20_POLY1305_KEY_SIZE       32  /* 256-bit key */
#define CHACHA20_POLY1305_NONCE_SIZE     12  /* 96-bit nonce (RFC 8439) */
#define CHACHA20_POLY1305_TAG_SIZE       16  /* 128-bit authentication tag */

/* Poly1305 Constants */
#define POLY1305_KEY_SIZE                32  /* 256-bit key */
#define POLY1305_TAG_SIZE                16  /* 128-bit tag */

/* Poly1305 Context Structure */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    uint32_t r[5];          /* r clamped, 26-bit limbs */
    uint32_t h[5];          /* Accumulator, 26-bit limbs */
    uint32_t pad[4];        /* s (128 bits, little-endian words) */
    uint8_t buffer[16];     /* Partial block buffer */
    uint32_t buffer_len;    /* Bytes in buffer */
    uint8_t finished;       /* Final block processed */
} poly1305_context_t;
NOXTLS_MSVC_WARNING_POP

/**
 * @brief Initialize Poly1305 context
 *
 * @param ctx Poly1305 context to initialize
 * @param key MAC key (32 bytes)
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t poly1305_init(poly1305_context_t *ctx, const uint8_t *key);

/**
 * @brief Update Poly1305 with data
 *
 * @param ctx Poly1305 context (must be initialized)
 * @param data Data to authenticate
 * @param data_len Length of data in bytes
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t poly1305_update(poly1305_context_t *ctx, const uint8_t *data, uint32_t data_len);

/**
 * @brief Finalize Poly1305 and generate tag
 *
 * @param ctx Poly1305 context (must be initialized and updated)
 * @param tag Output tag (16 bytes)
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t poly1305_final(poly1305_context_t *ctx, uint8_t *tag);

/**
 * @brief Compute Poly1305 MAC (convenience function)
 *
 * @param key MAC key (32 bytes)
 * @param data Data to authenticate
 * @param data_len Length of data in bytes
 * @param tag Output tag (16 bytes)
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t poly1305_mac(const uint8_t *key, const uint8_t *data, uint32_t data_len, uint8_t *tag);

/**
 * @brief Encrypt and authenticate data using ChaCha20-Poly1305
 *
 * @param key Encryption key (32 bytes)
 * @param nonce Nonce (12 bytes)
 * @param aad Additional authenticated data (can be NULL if aad_len is 0)
 * @param aad_len Length of AAD in bytes
 * @param plaintext Plaintext to encrypt (can be NULL if plaintext_len is 0)
 * @param plaintext_len Length of plaintext in bytes
 * @param ciphertext Output buffer for ciphertext (must be at least plaintext_len bytes)
 * @param tag Output buffer for authentication tag (must be at least 16 bytes)
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t chacha20_poly1305_encrypt(const uint8_t *key,
                               const uint8_t *nonce,
                               const uint8_t *aad,
                               uint32_t aad_len,
                               const uint8_t *plaintext,
                               uint32_t plaintext_len,
                               uint8_t *ciphertext,
                               uint8_t *tag);

/**
 * @brief Decrypt and verify data using ChaCha20-Poly1305
 *
 * @param key Encryption key (32 bytes)
 * @param nonce Nonce (12 bytes)
 * @param aad Additional authenticated data (can be NULL if aad_len is 0)
 * @param aad_len Length of AAD in bytes
 * @param ciphertext Ciphertext to decrypt (can be NULL if ciphertext_len is 0)
 * @param ciphertext_len Length of ciphertext in bytes
 * @param tag Authentication tag to verify (16 bytes)
 * @param plaintext Output buffer for plaintext (must be at least ciphertext_len bytes)
 * @return NOXTLS_RETURN_SUCCESS on success (authentication verified), NOXTLS_RETURN_BAD_DATA on auth failure
 */
noxtls_return_t chacha20_poly1305_decrypt(const uint8_t *key,
                               const uint8_t *nonce,
                               const uint8_t *aad,
                               uint32_t aad_len,
                               const uint8_t *ciphertext,
                               uint32_t ciphertext_len,
                               const uint8_t *tag,
                               uint8_t *plaintext);

/**
 * @brief Self-test function
 *
 * @return NOXTLS_RETURN_SUCCESS on success (all tests passed)
 */
noxtls_return_t chacha20_poly1305_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_CHACHA20_POLY1305_H_ */


