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
* File:    noxtls_camellia_cbc.c
* Summary: Camellia Cipher Block Chaining (CBC) Mode Implementation
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
 * @brief Camellia Encrypt in CBC Mode
 */
/* Block-indexed CBC encrypt; extents follow caller data_len / Camellia block size. */
noxtls_return_t noxtls_camellia_encrypt_cbc(const uint8_t* key, 
                         const uint8_t* data, 
                         uint32_t data_len,
                         const uint8_t * iv,
                         uint8_t* output, 
                         noxtls_camellia_type_t type)
{
    uint32_t i;
    uint32_t cur_block = 0U;
    const uint8_t * iv_src = NULL;
    uint8_t temp_block[NOXTLS_CAMELLIA_BLOCK_LENGTH];
    uint8_t zero_iv[NOXTLS_CAMELLIA_BLOCK_LENGTH];
    const uint32_t block_sz = (uint32_t)NOXTLS_CAMELLIA_BLOCK_LENGTH;

    {
        noxtls_return_t rc = noxtls_camellia_check_oneshot_args(key, data, output, type);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    /* Output is rounded up to a whole block; keep the block loop from wrapping. */
    if (data_len > (UINT32_MAX - (block_sz - 1U))) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
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
            }
            else {
                iv_src = iv;
            }
        }
        else {
            iv_src = &output[cur_block - block_sz];
        }

        noxtls_copy_u8(temp_block, sizeof(temp_block), &data[cur_block], (size_t)block_len);
        if (block_len < block_sz) {
            noxtls_secure_zero((&temp_block[block_len]), ((size_t)(block_sz - block_len)));
        }
        for (i = 0U; i < block_sz; i += 1U) {
            temp_block[i] = (uint8_t)(temp_block[i] ^ iv_src[i]);
        }

        {
            noxtls_return_t rc = noxtls_camellia_encrypt_block_internal(key, temp_block, &output[cur_block], type);
            if (rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_secure_zero(temp_block, sizeof(temp_block));
                noxtls_secure_zero(output, (size_t)(cur_block + block_sz));
                return rc;
            }
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Camellia Decrypt in CBC Mode
 */
noxtls_return_t noxtls_camellia_decrypt_cbc(const uint8_t* key,
                         const uint8_t* data,
                         uint32_t data_len,
                         const uint8_t * iv,
                         uint8_t* output,
                         noxtls_camellia_type_t type)
{
    uint32_t cur_block;
    uint32_t i;
    uint8_t temp_block[NOXTLS_CAMELLIA_BLOCK_LENGTH];
    uint8_t zero_iv[NOXTLS_CAMELLIA_BLOCK_LENGTH];
    const uint8_t * iv_src;
    const uint32_t block_sz = (uint32_t)NOXTLS_CAMELLIA_BLOCK_LENGTH;

    {
        noxtls_return_t rc = noxtls_camellia_check_oneshot_args(key, data, output, type);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    /* Ciphertext must be whole blocks: a partial tail would be over-read. */
    if ((data_len % block_sz) != 0U) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }

    for (cur_block = 0U; cur_block < data_len; cur_block += block_sz)
    {
        {
            noxtls_return_t rc = noxtls_camellia_decrypt_block_internal(key, &data[cur_block], temp_block, type);
            if (rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_secure_zero(output, (size_t)data_len);
                return rc;
            }
        }

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
    noxtls_secure_zero(temp_block, sizeof(temp_block));
    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_CAMELLIA */
