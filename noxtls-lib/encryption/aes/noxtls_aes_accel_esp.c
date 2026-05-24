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
* File:    noxtls_aes_accel_esp.c
* Summary: Platform AES acceleration hook (default fallback)
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */
/** @{ */

#include <stdint.h>

#include "noxtls_aes_accel.h"

/**
 * @brief Encrypt the block using the ESP hardware AES
 *
 * @param[in] key The key to encrypt the block with
 * @param[in] data The data to encrypt the block with
 * @param[out] output The output to encrypt the block into
 * @param[in] type The type of the block to encrypt
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_FAILED on failure,
 *         NOXTLS_RETURN_NULL if the key, data, or output is NULL
 */
noxtls_return_t noxtls_aes_accel_port_encrypt_block(const uint8_t *key,
                                                     const uint8_t *data,
                                                     uint8_t *output,
                                                     noxtls_aes_type_t type)
{
    (void)key;
    (void)data;
    (void)output;
    (void)type;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

/**
 * @brief Decrypt the block using the ESP hardware AES
 *
 * @param[in] key The key to decrypt the block with
 * @param[in] data The data to decrypt the block with
 * @param[out] output The output to decrypt the block into
 * @param[in] type The type of the block to decrypt
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_FAILED on failure,
 *         NOXTLS_RETURN_NULL if the key, data, or output is NULL
 */
noxtls_return_t noxtls_aes_accel_port_decrypt_block(const uint8_t *key,
                                                     const uint8_t *data,
                                                     uint8_t *output,
                                                     noxtls_aes_type_t type)
{
    (void)key;
    (void)data;
    (void)output;
    (void)type;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

/**
 * @brief Encrypt the blocks using the ESP hardware AES
 *
 * @param[in] key The key to encrypt the blocks with
 * @param[in] input The data to encrypt the blocks with
 * @param[out] output The output to encrypt the blocks into
 * @param[in] block_count The number of blocks to encrypt
 * @param[in] type The type of the blocks to encrypt
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_FAILED on failure,
 *         NOXTLS_RETURN_NULL if the key, input, or output is NULL
 */
noxtls_return_t noxtls_aes_accel_port_encrypt_blocks(const uint8_t *key,
                                                      const uint8_t *input,
                                                      uint8_t *output,
                                                      uint32_t block_count,
                                                      noxtls_aes_type_t type)
{
    (void)key;
    (void)input;
    (void)output;
    (void)block_count;
    (void)type;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

/**
 * @brief Encrypt the GCM using the ESP hardware AES
 *
 * @param[in] key The key to encrypt the GCM with
 * @param[in] type The type of the GCM to encrypt
 * @param[in] nonce The nonce to encrypt the GCM with
 * @param[in] aad The additional authentication data to encrypt the GCM with
 * @param[in] aad_len The length of the additional authentication data to encrypt the GCM with
 * @param[in] plaintext The plaintext to encrypt the GCM with
 * @param[in] plaintext_len The length of the plaintext to encrypt the GCM with
 * @param[out] ciphertext The ciphertext to encrypt the GCM into
 * @param[out] tag The tag to encrypt the GCM into
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_FAILED on failure,
 *         NOXTLS_RETURN_NULL if the key, nonce, plaintext, ciphertext, or tag is NULL
 */
noxtls_return_t noxtls_aes_gcm_encrypt_accel_port(const uint8_t *key,
                                                   noxtls_aes_type_t type,
                                                   const uint8_t nonce[12],
                                                   const uint8_t *aad,
                                                   uint32_t aad_len,
                                                   const uint8_t *plaintext,
                                                   uint32_t plaintext_len,
                                                   uint8_t *ciphertext,
                                                   uint8_t tag[16])
{
    (void)key;
    (void)type;
    (void)nonce;
    (void)aad;
    (void)aad_len;
    (void)plaintext;
    (void)plaintext_len;
    (void)ciphertext;
    (void)tag;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

/**
 * @brief Decrypt the GCM using the ESP hardware AES
 *
 * @param[in] key The key to decrypt the GCM with
 * @param[in] type The type of the GCM to decrypt
 * @param[in] nonce The nonce to decrypt the GCM with
 * @param[in] aad The additional authentication data to decrypt the GCM with
 * @param[in] aad_len The length of the additional authentication data to decrypt the GCM with
 * @param[in] ciphertext The ciphertext to decrypt the GCM with
 * @param[in] ciphertext_len The length of the ciphertext to decrypt the GCM with
 * @param[in] tag The tag to decrypt the GCM with
 * @param[out] plaintext The plaintext to decrypt the GCM into
 * @return NOXTLS_RETURN_SUCCESS on success,
 *         NOXTLS_RETURN_FAILED on failure,
 *         NOXTLS_RETURN_NULL if the key, nonce, ciphertext, plaintext, or tag is NULL,
 *         NOXTLS_RETURN_BAD_DATA if the tag verification fails
 */
noxtls_return_t noxtls_aes_gcm_decrypt_accel_port(const uint8_t *key,
                                                   noxtls_aes_type_t type,
                                                   const uint8_t nonce[12],
                                                   const uint8_t *aad,
                                                   uint32_t aad_len,
                                                   const uint8_t *ciphertext,
                                                   uint32_t ciphertext_len,
                                                   const uint8_t tag[16],
                                                   uint8_t *plaintext)
{
    (void)key;
    (void)type;
    (void)nonce;
    (void)aad;
    (void)aad_len;
    (void)ciphertext;
    (void)ciphertext_len;
    (void)tag;
    (void)plaintext;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

/** @} */