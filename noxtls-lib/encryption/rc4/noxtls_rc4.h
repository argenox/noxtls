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
* File:    noxtls_rc4.h
* Summary: RC4 Stream Cipher Algorithm
*
* Implementation of RC4 (Rivest Cipher 4). Key length 1–256 bytes.
* Security note: RC4 is deprecated and weak; use only for legacy compatibility.
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */
/** @{ */

#ifndef _NOXTLS_RC4_H_
#define _NOXTLS_RC4_H_

/* Standard Includes */
#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NOXTLS_RC4_DEBUG (0)

/* RC4 key length: 1 to 256 bytes (typically 16 for 128-bit) */
#define NOXTLS_RC4_KEY_MIN_BYTES  1
#define NOXTLS_RC4_KEY_MAX_BYTES  256

/* RC4 Context Structure */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    uint8_t S[256];   /* State (permutation of 0..255) */
    uint8_t i;       /* Index i for PRGA */
    uint8_t j;       /* Index j for PRGA */
} noxtls_rc4_context_t;
NOXTLS_MSVC_WARNING_POP

/**
 * @brief Initialize RC4 context
 *
 * @param ctx RC4 context to initialize
 * @param key Key bytes (length between NOXTLS_RC4_KEY_MIN_BYTES and NOXTLS_RC4_KEY_MAX_BYTES)
 * @param key_len Key length in bytes (1–256)
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL or NOXTLS_RETURN_FAILED on invalid args
 */
noxtls_return_t noxtls_rc4_init(noxtls_rc4_context_t *ctx, const uint8_t *key, uint32_t key_len);

/**
 * @brief Encrypt/Decrypt data using RC4
 *
 * RC4 is a stream cipher; encryption and decryption are identical (XOR with keystream).
 *
 * @param ctx RC4 context (must be initialized)
 * @param input Input data (plaintext or ciphertext)
 * @param output Output buffer (must be at least input_len bytes)
 * @param input_len Length of input in bytes
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t noxtls_rc4_process(noxtls_rc4_context_t *ctx,
                            const uint8_t *input,
                            uint8_t *output,
                            uint32_t input_len);

/**
 * @brief Encrypt data using RC4 (convenience function)
 *
 * @param key Key bytes
 * @param key_len Key length (1–256)
 * @param input Plaintext
 * @param input_len Length of plaintext
 * @param output Output buffer for ciphertext (at least input_len bytes)
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t noxtls_rc4_encrypt(const uint8_t *key, uint32_t key_len,
                            const uint8_t *input, uint32_t input_len,
                            uint8_t *output);

/**
 * @brief Decrypt data using RC4 (convenience function)
 *
 * @param key Key bytes
 * @param key_len Key length (1–256)
 * @param input Ciphertext
 * @param input_len Length of ciphertext
 * @param output Output buffer for plaintext (at least input_len bytes)
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t noxtls_rc4_decrypt(const uint8_t *key, uint32_t key_len,
                            const uint8_t *input, uint32_t input_len,
                            uint8_t *output);

/**
 * @brief Self-test (RFC 6229 test vector)
 *
 * @return NOXTLS_RETURN_SUCCESS if all tests pass
 */
noxtls_return_t noxtls_rc4_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_RC4_H_ */
