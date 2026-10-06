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
* File:    noxtls_camellia_cfb.c
* Summary: Camellia Cipher Feedback (CFB) Mode Implementation
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */

#include <stdint.h>
#include <string.h>
#include "noxtls_camellia.h"
#include "noxtls_camellia_internal.h"
#include "noxtls_common.h"
#include "noxtls_ct.h"

#if NOXTLS_FEATURE_CAMELLIA

/**
 * @brief Camellia Encrypt in CFB Mode
 */
/* Block-indexed CFB walk; extents follow caller data_len / Camellia block size. */
noxtls_return_t noxtls_camellia_encrypt_cfb(const uint8_t* key, 
                         const uint8_t* data, 
                         uint32_t data_len,
                         const uint8_t * iv,
                         uint8_t* output, 
                         noxtls_camellia_type_t type)
{
    uint32_t cur_block = 0U;
    uint32_t i;
    uint8_t feedback[NOXTLS_CAMELLIA_BLOCK_LENGTH];
    uint8_t keystream[NOXTLS_CAMELLIA_BLOCK_LENGTH];
    uint8_t zero_iv[NOXTLS_CAMELLIA_BLOCK_LENGTH];
    const uint8_t * iv_src = NULL;
    const uint32_t block_sz = (uint32_t)NOXTLS_CAMELLIA_BLOCK_LENGTH;

    /* Initialize feedback register with IV */
    if (iv == NULL) {
        noxtls_secure_zero((zero_iv), (size_t)(block_sz));
        iv_src = zero_iv;
    }
    else {
        iv_src = iv;
    }

    noxtls_copy_u8(feedback, (size_t)block_sz, iv_src, (size_t)block_sz);

    for (cur_block = 0U; cur_block < data_len; cur_block += block_sz)
    {
        uint32_t remain = (uint32_t)(data_len - cur_block);
        uint32_t block_len = (uint32_t)((remain < block_sz) ? remain : block_sz);

        /* Encrypt feedback register to generate keystream */
        (void)noxtls_camellia_encrypt_block_internal(key, feedback, keystream, type);

        /* XOR keystream with plaintext */
        for (i = 0U; i < block_len; i += 1U) {
            output[cur_block + i] = (uint8_t)(data[cur_block + i] ^ keystream[i]);
        }

        /* Update feedback register: shift left and insert ciphertext */
        if (block_len == block_sz) {
            noxtls_copy_u8(feedback, (size_t)block_sz, &output[cur_block], (size_t)block_sz);
        }
        else {
            noxtls_move_u8(&feedback[0], sizeof(feedback), &feedback[block_len], (size_t)(block_sz - block_len));
            noxtls_copy_u8(&feedback[block_sz - block_len], (size_t)(block_len), &output[cur_block], (size_t)(block_len));
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Camellia Decrypt in CFB Mode
 */
noxtls_return_t noxtls_camellia_decrypt_cfb(const uint8_t* key,
                         const uint8_t* data,
                         uint32_t data_len,
                         const uint8_t * iv,
                         uint8_t* output,
                         noxtls_camellia_type_t type)
{
    uint32_t cur_block;
    uint32_t i;
    uint8_t feedback[NOXTLS_CAMELLIA_BLOCK_LENGTH];
    uint8_t keystream[NOXTLS_CAMELLIA_BLOCK_LENGTH];
    uint8_t zero_iv[NOXTLS_CAMELLIA_BLOCK_LENGTH];
    const uint8_t * iv_src = NULL;
    const uint32_t block_sz = (uint32_t)NOXTLS_CAMELLIA_BLOCK_LENGTH;

    if (iv == NULL) {
        noxtls_secure_zero((zero_iv), (size_t)(block_sz));
        iv_src = zero_iv;
    } else {
        iv_src = iv;
    }
    noxtls_copy_u8(feedback, (size_t)block_sz, iv_src, (size_t)block_sz);

    for (cur_block = 0U; cur_block < data_len; cur_block += block_sz)
    {
        uint32_t remain = (uint32_t)(data_len - cur_block);
        uint32_t block_len = (uint32_t)((remain < block_sz) ? remain : block_sz);

        (void)noxtls_camellia_encrypt_block_internal(key, feedback, keystream, type);
        for (i = 0U; i < block_len; i += 1U) {
            output[cur_block + i] = (uint8_t)(data[cur_block + i] ^ keystream[i]);
        }

        if (block_len == block_sz) {
            noxtls_copy_u8(feedback, (size_t)block_sz, &data[cur_block], (size_t)block_sz);
        }
        else {
            noxtls_move_u8(&feedback[0], sizeof(feedback), &feedback[block_len], (size_t)(block_sz - block_len));
            noxtls_copy_u8(&feedback[block_sz - block_len], (size_t)(block_len), &data[cur_block], (size_t)(block_len));
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_CAMELLIA */
