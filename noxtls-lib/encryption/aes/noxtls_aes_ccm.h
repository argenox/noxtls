/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
*
* File:    noxtls_aes_ccm.h
* Summary: AES-CCM (Counter with CBC-MAC) mode - NIST SP 800-38C / RFC 3610
*
* CCM provides authenticated encryption. Supported:
*   - Nonce length 7..13 bytes (L = 15 - nonce_len; L in 2..8).
*   - Tag length 4, 6, 8, 10, 12, 14, or 16 bytes.
*   - Optional associated data (AAD).
*/

/** @addtogroup noxtls_encryption */
/** @{ */

#ifndef _NOXTLS_AES_CCM_H_
#define _NOXTLS_AES_CCM_H_

#include <stdint.h>
#include "noxtls_aes.h"
#include "noxtls_common.h"

#define NOXTLS_AES_BLOCK 16U

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief AES-CCM encrypt (authenticated encryption).
 *
 * @param key         AES key
 * @param type        AES key size (NOXTLS_AES_128_BIT, NOXTLS_AES_192_BIT, NOXTLS_AES_256_BIT)
 * @param nonce       Nonce (7..13 bytes; length must match L = 15 - nonce_len, L in 2..8)
 * @param nonce_len   Nonce length in bytes (7, 8, 9, 10, 11, 12, or 13)
 * @param aad         Optional associated data (may be NULL if aad_len == 0)
 * @param aad_len     Length of AAD in bytes
 * @param plaintext   Plaintext to encrypt
 * @param plaintext_len Length of plaintext (max 2^(8*L)-1 bytes for L = 15 - nonce_len)
 * @param ciphertext  Output ciphertext (same length as plaintext)
 * @param tag         Authentication tag (4, 6, 8, 10, 12, 14, or 16 bytes)
 * @param tag_len     Tag length in bytes
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_* on invalid parameters or failure
 */
noxtls_return_t noxtls_aes_ccm_encrypt(const uint8_t *key, noxtls_aes_type_t type,
                    const uint8_t *nonce, uint32_t nonce_len,
                    const uint8_t *aad, uint32_t aad_len,
                    const uint8_t *plaintext, uint32_t plaintext_len,
                    uint8_t *ciphertext,
                    uint8_t *tag, uint32_t tag_len);

/**
 * @brief AES-CCM decrypt (verify tag and decrypt).
 *
 * @param key         AES key
 * @param type        AES key size
 * @param nonce       Nonce (same length as used in encrypt)
 * @param nonce_len   Nonce length in bytes
 * @param aad         Optional associated data (may be NULL if aad_len == 0)
 * @param aad_len     Length of AAD in bytes
 * @param ciphertext  Ciphertext to decrypt
 * @param ciphertext_len Length of ciphertext
 * @param tag         Expected authentication tag
 * @param tag_len     Tag length in bytes
 * @param plaintext   Output plaintext (same length as ciphertext)
 * @return NOXTLS_RETURN_SUCCESS on success (tag verified), NOXTLS_RETURN_BAD_DATA on auth failure
 */
noxtls_return_t noxtls_aes_ccm_decrypt(const uint8_t *key, noxtls_aes_type_t type,
                    const uint8_t *nonce, uint32_t nonce_len,
                    const uint8_t *aad, uint32_t aad_len,
                    const uint8_t *ciphertext, uint32_t ciphertext_len,
                    const uint8_t *tag, uint32_t tag_len,
                    uint8_t *plaintext);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_AES_CCM_H_ */
