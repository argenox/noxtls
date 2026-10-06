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
* File:    noxtls_aria_cfb.c
* Summary: ARIA Cipher Feedback (CFB) Mode Implementation
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */

#include <stdint.h>
#include "common/noxtls_ct.h"
#include <string.h>
#include "noxtls_aria.h"
#include "noxtls_common.h"

#if NOXTLS_FEATURE_ARIA

/**
 * @brief ARIA Encrypt in CFB Mode
 */
/* Block-indexed CFB walk; extents follow caller data_len / ARIA block size. */
noxtls_return_t noxtls_aria_encrypt_cfb(const uint8_t* key,
                     const uint8_t* data,
                     uint32_t data_len,
                     const uint8_t * iv,
                     uint8_t* output,
                     noxtls_aria_type_t type)
{
    uint32_t i;
    uint32_t cur_block = 0U;
    uint8_t feedback[NOXTLS_ARIA_BLOCK_LENGTH];
    uint8_t keystream[NOXTLS_ARIA_BLOCK_LENGTH];
    noxtls_aria_key_t aria_key;
    const uint32_t block_sz = (uint32_t)NOXTLS_ARIA_BLOCK_LENGTH;

    if ((key == NULL) || (data == NULL) || (output == NULL) || (iv == NULL)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    {
        noxtls_return_t r = noxtls_aria_set_encrypt_key(key, type, &aria_key);
        if (r != NOXTLS_RETURN_SUCCESS) {
            return r;
        }
    }

    /* Initialize feedback register with IV */
    noxtls_copy_u8(feedback, (size_t)block_sz, iv, (size_t)block_sz);

    for (cur_block = 0U; cur_block < data_len; cur_block += block_sz)
    {
        uint32_t remain = (uint32_t)(data_len - cur_block);
        uint32_t block_len = (uint32_t)((remain < block_sz) ? remain : block_sz);

        /* Encrypt feedback to produce keystream */
        (void)noxtls_aria_encrypt_block(&aria_key, feedback, keystream);

        /* XOR keystream with plaintext */
        for (i = 0U; i < block_len; i += 1U) {
            output[cur_block + i] = (uint8_t)(data[cur_block + i] ^ keystream[i]);
        }

        /* Update feedback register */
        if (block_len == block_sz) {
            noxtls_copy_u8(feedback, (size_t)block_sz, &output[cur_block], (size_t)block_sz);
        } else {
            noxtls_move_u8(&feedback[0], sizeof(feedback), &feedback[block_len], (size_t)(block_sz - block_len));
            noxtls_copy_u8(&feedback[block_sz - block_len], (size_t)(block_len), &output[cur_block], (size_t)(block_len));
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief ARIA Decrypt in CFB Mode
 */
noxtls_return_t noxtls_aria_decrypt_cfb(const uint8_t* key,
                     const uint8_t* data,
                     uint32_t data_len,
                     const uint8_t * iv,
                     uint8_t* output,
                     noxtls_aria_type_t type)
{
    uint32_t i;
    uint32_t cur_block = 0U;
    uint8_t feedback[NOXTLS_ARIA_BLOCK_LENGTH];
    uint8_t keystream[NOXTLS_ARIA_BLOCK_LENGTH];
    noxtls_aria_key_t aria_key;
    const uint32_t block_sz = (uint32_t)NOXTLS_ARIA_BLOCK_LENGTH;

    if ((key == NULL) || (data == NULL) || (output == NULL) || (iv == NULL)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    {
        noxtls_return_t r = noxtls_aria_set_encrypt_key(key, type, &aria_key);
        if (r != NOXTLS_RETURN_SUCCESS) {
            return r;
        }
    }

    /* Initialize feedback register with IV */
    noxtls_copy_u8(feedback, (size_t)block_sz, iv, (size_t)block_sz);

    for (cur_block = 0U; cur_block < data_len; cur_block += block_sz)
    {
        uint32_t remain = (uint32_t)(data_len - cur_block);
        uint32_t block_len = (uint32_t)((remain < block_sz) ? remain : block_sz);

        /* Encrypt feedback to produce keystream */
        (void)noxtls_aria_encrypt_block(&aria_key, feedback, keystream);

        /* XOR keystream with ciphertext */
        for (i = 0U; i < block_len; i += 1U) {
            output[cur_block + i] = (uint8_t)(data[cur_block + i] ^ keystream[i]);
        }

        /* Update feedback register with ciphertext */
        if (block_len == block_sz) {
            noxtls_copy_u8(feedback, (size_t)block_sz, &data[cur_block], (size_t)block_sz);
        } else {
            noxtls_move_u8(&feedback[0], sizeof(feedback), &feedback[block_len], (size_t)(block_sz - block_len));
            noxtls_copy_u8(&feedback[block_sz - block_len], (size_t)(block_len), &data[cur_block], (size_t)(block_len));
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_ARIA */
