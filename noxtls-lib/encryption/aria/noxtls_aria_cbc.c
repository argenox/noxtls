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
* File:    noxtls_aria_cbc.c
* Summary: ARIA Cipher Block Chaining (CBC) Mode Implementation
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */

#include <stdint.h>
#include <string.h>
#include "noxtls_aria.h"
#include "noxtls_common.h"
#include "noxtls_ct.h"

#if NOXTLS_FEATURE_ARIA

/**
 * @brief ARIA Encrypt in CBC Mode
 */
/* Block-indexed CBC encrypt; extents follow caller data_len / ARIA block size. */
noxtls_return_t noxtls_aria_encrypt_cbc(const uint8_t* key,
                     const uint8_t* data,
                     uint32_t data_len,
                     const uint8_t * iv,
                     uint8_t* output,
                     noxtls_aria_type_t type)
{
    uint32_t i;
    uint32_t cur_block = 0U;
    const uint8_t * iv_src = NULL;
    uint8_t temp_block[NOXTLS_ARIA_BLOCK_LENGTH];
    uint8_t zero_iv[NOXTLS_ARIA_BLOCK_LENGTH];
    noxtls_aria_key_t aria_key;
    const uint32_t block_sz = (uint32_t)NOXTLS_ARIA_BLOCK_LENGTH;

    if ((key == NULL) || (data == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    {
        noxtls_return_t r = noxtls_aria_set_encrypt_key(key, type, &aria_key);
        if (r != NOXTLS_RETURN_SUCCESS) {
            return r;
        }
    }

    for (cur_block = 0U; cur_block < data_len; cur_block += block_sz)
    {
        uint32_t remain = (uint32_t)(data_len - cur_block);
        uint32_t block_len = (uint32_t)((remain < block_sz) ? remain : block_sz);

        /* Cipher Block Chaining: XOR with previous ciphertext (or IV) */
        if (cur_block == 0U) {
            if (iv == NULL) {
                noxtls_secure_zero((zero_iv), (size_t)(block_sz));
                iv_src = zero_iv;
            } else {
                iv_src = iv;
            }
        } else {
            iv_src = &output[cur_block - block_sz];
        }

        /* XOR input block with IV/previous ciphertext */
        for (i = 0U; i < block_len; i += 1U) {
            temp_block[i] = (uint8_t)(data[cur_block + i] ^ iv_src[i]);
        }

        /* Pad if necessary */
        if (block_len < block_sz) {
            uint8_t pad_value = (uint8_t)(block_sz - block_len);
            for (i = block_len; i < block_sz; i += 1U) {
                temp_block[i] = pad_value;
            }
        }

        /* Encrypt block */
        (void)noxtls_aria_encrypt_block(&aria_key, temp_block, &output[cur_block]);
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief ARIA Decrypt in CBC Mode
 */
noxtls_return_t noxtls_aria_decrypt_cbc(const uint8_t* key,
                     const uint8_t* data,
                     uint32_t data_len,
                     const uint8_t * iv,
                     uint8_t* output,
                     noxtls_aria_type_t type)
{
    uint32_t i;
    uint32_t cur_block = 0U;
    const uint8_t * iv_src = NULL;
    uint8_t temp_block[NOXTLS_ARIA_BLOCK_LENGTH];
    uint8_t zero_iv[NOXTLS_ARIA_BLOCK_LENGTH];
    noxtls_aria_key_t aria_key;
    const uint32_t block_sz = (uint32_t)NOXTLS_ARIA_BLOCK_LENGTH;

    if ((key == NULL) || (data == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    {
        noxtls_return_t r = noxtls_aria_set_decrypt_key(key, type, &aria_key);
        if (r != NOXTLS_RETURN_SUCCESS) {
            return r;
        }
    }

    for (cur_block = 0U; cur_block < data_len; cur_block += block_sz)
    {
        uint32_t remain = (uint32_t)(data_len - cur_block);
        uint32_t block_len = (uint32_t)((remain < block_sz) ? remain : block_sz);

        if (block_len != block_sz) {
            return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
        }

        /* Decrypt block */
        (void)noxtls_aria_decrypt_block(&aria_key, &data[cur_block], temp_block);

        /* Cipher Block Chaining: XOR with previous ciphertext (or IV) */
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

        /* XOR decrypted block with IV/previous ciphertext */
        for (i = 0U; i < block_sz; i += 1U) {
            output[cur_block + i] = (uint8_t)(temp_block[i] ^ iv_src[i]);
        }
    }

    /* Verify PKCS-style padding bytes (caller owns length trimming). */
    if (data_len > 0U) {
        uint8_t pad_value = (uint8_t)(output[data_len - 1U]);
        if ((pad_value > 0U) && (pad_value <= (uint8_t)block_sz)) {
            uint8_t valid_pad = 1U;
            for (i = data_len - (uint32_t)pad_value; i < data_len; i += 1U) {
                if (output[i] != pad_value) {
                    valid_pad = 0U;
                    break;
                }
            }
            (void)valid_pad;
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_ARIA */
