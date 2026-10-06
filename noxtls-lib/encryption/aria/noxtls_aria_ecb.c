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
* File:    noxtls_aria_ecb.c
* Summary: ARIA Electronic Codebook (ECB) Mode Implementation
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
 * @brief ARIA Encrypt in ECB Mode
 */
/* Block-indexed ECB walk; extents follow caller data_len / ARIA block size. */
noxtls_return_t noxtls_aria_encrypt_ecb(const uint8_t* key,
                     const uint8_t* data,
                     uint32_t data_len,
                     const uint8_t * iv,
                     uint8_t* output,
                     noxtls_aria_type_t type)
{
    uint32_t cur_block = 0U;
    uint8_t temp_block[NOXTLS_ARIA_BLOCK_LENGTH];
    noxtls_aria_key_t aria_key;
    const uint32_t block_sz = (uint32_t)NOXTLS_ARIA_BLOCK_LENGTH;

    (void)iv;

    if ((key == NULL) || (data == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    /* Output is rounded up to a whole block; keep the block loop from wrapping. */
    if (data_len > (UINT32_MAX - (block_sz - 1U))) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
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

        noxtls_copy_u8(temp_block, sizeof(temp_block), &data[cur_block], (size_t)block_len);

        /* Pad if necessary */
        if (block_len < block_sz) {
            uint8_t pad_value = (uint8_t)(block_sz - block_len);
            {
            uint32_t pi = 0U;
            for(pi = 0U; pi < (uint32_t)pad_value; pi += 1U) {
                temp_block[block_len + pi] = (uint8_t)pad_value;
            }
        }
        }

        /* Encrypt block */
        (void)noxtls_aria_encrypt_block(&aria_key, temp_block, &output[cur_block]);
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief ARIA Decrypt in ECB Mode
 */
noxtls_return_t noxtls_aria_decrypt_ecb(const uint8_t* key,
                     const uint8_t* data,
                     uint32_t data_len,
                     const uint8_t * iv,
                     uint8_t* output,
                     noxtls_aria_type_t type)
{
    uint32_t cur_block = 0U;
    uint8_t temp_block[NOXTLS_ARIA_BLOCK_LENGTH];
    noxtls_aria_key_t aria_key;
    const uint32_t block_sz = (uint32_t)NOXTLS_ARIA_BLOCK_LENGTH;

    (void)iv;

    if ((key == NULL) || (data == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if ((data_len % block_sz) != 0U) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
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
        noxtls_copy_u8(&output[cur_block], (size_t)block_sz, temp_block, (size_t)block_sz);
    }

    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_ARIA */
