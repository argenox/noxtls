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
* File:    noxtls_des_cbc.c
* Summary: DES and 3DES Cipher Block Chaining (CBC) Mode
*
* The DES and 3DES Algorithms are broken and should not be used for new systems.
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */

#include <stdint.h>
#include <string.h>

#include "noxtls_des.h"
#include "noxtls_des_internal.h"
#include "noxtls_common.h"
#include "noxtls_ct.h"

#if NOXTLS_FEATURE_DES

/**
 * @brief DES CBC encryption
 */
/* Block-indexed DES CBC; extents follow caller data_len / DES block size. */
/* Directive: legacy-warning comment is documentation, not disabled code. */
noxtls_return_t noxtls_des_encrypt_cbc(const uint8_t *key,
                    const uint8_t *data,
                    uint32_t data_len,
                    const uint8_t *iv,
                    uint8_t *output)
{
    uint32_t cur = 0U;
    uint8_t block[NOXTLS_DES_BLOCK_LENGTH];
    uint8_t zero_iv[NOXTLS_DES_BLOCK_LENGTH];
    const uint8_t *prev = NULL;
    const uint32_t block_sz = (uint32_t)NOXTLS_DES_BLOCK_LENGTH;

    if ((key == NULL) || (data == NULL) || (output == NULL) || ((data_len % block_sz) != 0U)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    prev = iv;
    if (prev == NULL) {
        noxtls_secure_zero((zero_iv), (size_t)(block_sz));
        prev = zero_iv;
    }
    for (cur = 0U; cur < data_len; cur += block_sz) {
        uint32_t i = 0U;
        for (i = 0U; i < block_sz; i += 1U) {
            block[i] = (uint8_t)(data[cur + i] ^ prev[i]);
        }
        (void)noxtls_des_encrypt_block_internal(key, block, &output[cur]);
        prev = &output[cur];
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief DES CBC decryption
 */
noxtls_return_t noxtls_des_decrypt_cbc(const uint8_t *key,
                    const uint8_t *data,
                    uint32_t data_len,
                    const uint8_t *iv,
                    uint8_t *output)
{
    uint32_t cur = 0U;
    uint8_t block[NOXTLS_DES_BLOCK_LENGTH];
    uint8_t zero_iv[NOXTLS_DES_BLOCK_LENGTH];
    const uint8_t *prev = NULL;
    const uint32_t block_sz = (uint32_t)NOXTLS_DES_BLOCK_LENGTH;

    if ((key == NULL) || (data == NULL) || (output == NULL) || ((data_len % block_sz) != 0U)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    prev = iv;
    if (prev == NULL) {
        noxtls_secure_zero((zero_iv), (size_t)(block_sz));
        prev = zero_iv;
    }
    for (cur = 0U; cur < data_len; cur += block_sz) {
        uint32_t i = 0U;
        (void)noxtls_des_decrypt_block_internal(key, &data[cur], block);
        for (i = 0U; i < block_sz; i += 1U) {
            output[cur + i] = (uint8_t)(block[i] ^ prev[i]);
        }
        prev = &data[cur];
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Triple-DES CBC encryption (EDE per block)
 */
noxtls_return_t des3_encrypt_cbc(const uint8_t *key,
                     uint32_t key_len,
                     const uint8_t *data,
                     uint32_t data_len,
                     const uint8_t *iv,
                     uint8_t *output)
{
    uint32_t cur = 0U;
    uint8_t block[NOXTLS_DES_BLOCK_LENGTH];
    uint8_t zero_iv[NOXTLS_DES_BLOCK_LENGTH];
    const uint8_t *prev = NULL;
    const uint32_t block_sz = (uint32_t)NOXTLS_DES_BLOCK_LENGTH;

    if ((key == NULL) || (data == NULL) || (output == NULL) ||
        ((key_len != 16U) && (key_len != 24U)) || ((data_len % block_sz) != 0U)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    prev = iv;
    if (prev == NULL) {
        noxtls_secure_zero((zero_iv), (size_t)(block_sz));
        prev = zero_iv;
    }
    for (cur = 0U; cur < data_len; cur += block_sz) {
        uint32_t i = 0U;
        for (i = 0U; i < block_sz; i += 1U) {
            block[i] = (uint8_t)(data[cur + i] ^ prev[i]);
        }
        (void)noxtls_des3_encrypt_block(key, key_len, block, &output[cur]);
        prev = &output[cur];
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Triple-DES CBC decryption (DED per block)
 */
noxtls_return_t des3_decrypt_cbc(const uint8_t *key,
                     uint32_t key_len,
                     const uint8_t *data,
                     uint32_t data_len,
                     const uint8_t *iv,
                     uint8_t *output)
{
    uint32_t cur = 0U;
    uint8_t block[NOXTLS_DES_BLOCK_LENGTH];
    uint8_t zero_iv[NOXTLS_DES_BLOCK_LENGTH];
    const uint8_t *prev = NULL;
    const uint32_t block_sz = (uint32_t)NOXTLS_DES_BLOCK_LENGTH;

    if ((key == NULL) || (data == NULL) || (output == NULL) ||
        ((key_len != 16U) && (key_len != 24U)) || ((data_len % block_sz) != 0U)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    prev = iv;
    if (prev == NULL) {
        noxtls_secure_zero((zero_iv), (size_t)(block_sz));
        prev = zero_iv;
    }
    for (cur = 0U; cur < data_len; cur += block_sz) {
        uint32_t i = 0U;
        (void)noxtls_des3_decrypt_block(key, key_len, &data[cur], block);
        for (i = 0U; i < block_sz; i += 1U) {
            output[cur + i] = (uint8_t)(block[i] ^ prev[i]);
        }
        prev = &data[cur];
    }
    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_DES */
