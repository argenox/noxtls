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
* File:    noxtls_aes_cbc.c
* Summary: AES Cipher Block Chaining (CBC) Mode Implementation
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */

#include <stdint.h>
#include <string.h>
#include "noxtls_aes.h"
#include "noxtls_aes_internal.h"
#include "noxtls_common.h"
#include "noxtls_ct.h"

#if NOXTLS_FEATURE_AES_CBC

/**
 * @brief AES Encrypt in CBC Mode
 *
 * Cipher Block Chaining mode: Each block is XORed with the previous
 * ciphertext (or IV for the first block) before encryption.
 *
 * @param key is a pointer to the encryption key
 * @param data is a pointer to the plaintext to be encrypted
 * @param data_len is the length of the plaintext in bytes
 * @param iv is the Initialization Vector (16 bytes). If NULL, zero IV is used.
 * @param output is the output buffer where the encrypted plaintext will be placed
 * @param type is the AES variant, 128, 192, 256
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_* on failure
 */
/* Block-indexed CBC encrypt; extents follow caller data_len / AES block size. */
noxtls_return_t noxtls_aes_encrypt_cbc(const uint8_t* key,
                    const uint8_t* data,
                    uint32_t data_len,
                    const uint8_t * iv,
                    uint8_t* output,
                    noxtls_aes_type_t type)
{
    uint32_t i;
    uint32_t cur_block = 0U;
    const uint8_t * iv_src = NULL;
    uint8_t temp_block[NOXTLS_AES_BLOCK_LENGTH];
    uint8_t zero_iv[NOXTLS_AES_BLOCK_LENGTH];
    const uint32_t block_sz = (uint32_t)NOXTLS_AES_BLOCK_LENGTH;

    for (cur_block = 0U; cur_block < data_len; cur_block += block_sz)
    {
        uint32_t remain = (uint32_t)(data_len - cur_block);
        uint32_t block_len = (uint32_t)((remain < block_sz) ? remain : block_sz);

        /* Cipher Block Chaining: XOR with previous ciphertext (or IV) */
        if (cur_block == 0U) {
            /* Use IV for first block */
            if (iv == NULL) {
                /* Zero IV if not provided */
                noxtls_secure_zero((zero_iv), (size_t)(block_sz));
                iv_src = zero_iv;
            }
            else {
                iv_src = iv;
            }
        }
        else {
            /* Previous Block Output */
            iv_src = &output[cur_block - block_sz];
        }

        /* XOR the input data with IV/previous ciphertext */
        noxtls_copy_u8(temp_block, sizeof(temp_block), &data[cur_block], (size_t)block_len);
        if (block_len < block_sz) {
            noxtls_secure_zero((&temp_block[block_len]), ((size_t)(block_sz - block_len)));
        }
        for (i = 0U; i < block_sz; i += 1U) {
            temp_block[i] = (uint8_t)(temp_block[i] ^ iv_src[i]);
        }

        (void)noxtls_aes_encrypt_block_internal(key, temp_block, &output[cur_block], type);
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief AES Decrypt in CBC Mode
 *
 * Cipher Block Chaining mode: Each ciphertext block is decrypted, then XORed
 * with the previous ciphertext block (or IV for the first block).
 *
 * @param key is a pointer to the decryption key
 * @param data is a pointer to the ciphertext to be decrypted
 * @param data_len is the length of the ciphertext in bytes (must be multiple of 16)
 * @param iv is the Initialization Vector (16 bytes). If NULL, zero IV is used.
 * @param output is the output buffer where the decrypted plaintext will be placed
 * @param type is the AES variant, 128, 192, 256
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_* on failure
 */
/* Block-indexed CBC decrypt; extents follow caller data_len / AES block size. */
noxtls_return_t noxtls_aes_decrypt_cbc(const uint8_t* key,
                    const uint8_t* data,
                    uint32_t data_len,
                    const uint8_t* iv,
                    uint8_t* output,
                    noxtls_aes_type_t type)
{
    uint32_t i;
    uint32_t cur_block = 0U;
    const uint8_t* iv_src = NULL;
    uint8_t temp_block[NOXTLS_AES_BLOCK_LENGTH];
    uint8_t zero_iv[NOXTLS_AES_BLOCK_LENGTH];
    const uint32_t block_sz = (uint32_t)NOXTLS_AES_BLOCK_LENGTH;

    for (cur_block = 0U; cur_block < data_len; cur_block += block_sz)
    {
        /* Decrypt current ciphertext block into temp */
        (void)noxtls_aes_decrypt_block_internal(key, &data[cur_block], temp_block, type);

        /* XOR with previous ciphertext (or IV for first block) */
        if (cur_block == 0U) {
            if (iv == NULL) {
                noxtls_secure_zero((zero_iv), (size_t)(block_sz));
                iv_src = zero_iv;
            } else {
                iv_src = iv;
            }
        } else {
            iv_src = &data[cur_block - block_sz];
        }

        for (i = 0U; i < block_sz; i += 1U) {
            output[cur_block + i] = (uint8_t)(temp_block[i] ^ iv_src[i]);
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_AES_CBC */
