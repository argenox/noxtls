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
#include "noxtls_aes_accel.h"
#include "noxtls_aes_internal.h"
#include "noxtls_common.h"
#include "common/noxtls_accel_port.h"
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
    if ((key == NULL) || (data == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if (data_len > UINT32_MAX - (NOXTLS_AES_BLOCK_LENGTH - 1U)) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }

    /* Preserve the existing zero-padding contract for CBC encryption. */
    const uint32_t output_span = ((data_len + NOXTLS_AES_BLOCK_LENGTH - 1U) /
        NOXTLS_AES_BLOCK_LENGTH) * NOXTLS_AES_BLOCK_LENGTH;

    uint32_t i;
    uint32_t cur_block = 0U;
    const uint8_t * iv_src = NULL;
    uint8_t temp_block[NOXTLS_AES_BLOCK_LENGTH];
    uint8_t zero_iv[NOXTLS_AES_BLOCK_LENGTH];
    const uint32_t block_sz = (uint32_t)NOXTLS_AES_BLOCK_LENGTH;

#if NOXTLS_PORT_AES_MODE_ACCEL
    {
        noxtls_return_t port_rc = noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_CBC, 0U, key, type, iv, data, data_len, output);
        if(port_rc != NOXTLS_RETURN_NOT_SUPPORTED) {
            return port_rc;
        }
    }
#endif
    /* Expand the key once for the whole buffer (wiped on every exit). */
    if (data_len == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }
    noxtls_aes_context_t actx;
    {
        noxtls_return_t prep_rc = noxtls_aes_prepare_context(&actx, key, type);
        if (prep_rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_secure_zero(&actx, sizeof(actx));
            noxtls_secure_zero(output, (size_t)data_len);
            return prep_rc;
        }
    }

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

        NOXTLS_AES_CHECK_CTX(noxtls_aes_encrypt_block_ctx_internal(&actx, temp_block, &output[cur_block]), &actx, output, output_span);
    }

    noxtls_secure_zero(&actx, sizeof(actx));
    noxtls_secure_zero(temp_block, sizeof(temp_block));
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
    if ((key == NULL) || (data == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if ((data_len % NOXTLS_AES_BLOCK_LENGTH) != 0U) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }

    uint32_t i;
    uint32_t cur_block = 0U;
    uint8_t temp_block[NOXTLS_AES_BLOCK_LENGTH];
    uint8_t chain[NOXTLS_AES_BLOCK_LENGTH];
    const uint32_t block_sz = (uint32_t)NOXTLS_AES_BLOCK_LENGTH;

#if NOXTLS_PORT_AES_MODE_ACCEL
    {
        noxtls_return_t port_rc = noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_CBC, 1U, key, type, iv, data, data_len, output);
        if(port_rc != NOXTLS_RETURN_NOT_SUPPORTED) {
            return port_rc;
        }
    }
#endif
    /* Expand the key once for the whole buffer (wiped on every exit). */
    if (data_len == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }
    noxtls_aes_context_t actx;
    {
        noxtls_return_t prep_rc = noxtls_aes_prepare_context(&actx, key, type);
        if (prep_rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_secure_zero(&actx, sizeof(actx));
            noxtls_secure_zero(output, (size_t)data_len);
            return prep_rc;
        }
    }

    for (cur_block = 0U; cur_block < data_len; cur_block += block_sz)
    {
        /* Decrypt current ciphertext block into temp */
        NOXTLS_AES_CHECK_CTX(noxtls_aes_decrypt_block_ctx_internal(&actx, &data[cur_block], temp_block), &actx, output, data_len);


        /* chain holds the previous ciphertext block (the IV for the first one).
         * Each ciphertext byte is saved before the output byte at the same
         * position is written, so exact in-place use (output == data) is safe. */
        if (cur_block == 0U) {
            if (iv == NULL) {
                noxtls_secure_zero((chain), (size_t)(block_sz));
            } else {
                noxtls_copy_u8(chain, sizeof(chain), iv, (size_t)block_sz);
            }
        }
        for (i = 0U; i < block_sz; i += 1U) {
            uint8_t ct = data[cur_block + i];
            output[cur_block + i] = (uint8_t)(temp_block[i] ^ chain[i]);
            chain[i] = ct;
        }
    }

    noxtls_secure_zero(&actx, sizeof(actx));
    noxtls_secure_zero(temp_block, sizeof(temp_block));
    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_AES_CBC */
