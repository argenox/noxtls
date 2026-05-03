/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_des_cbc.c
* Summary: DES and 3DES Cipher Block Chaining (CBC) Mode
*
*/

/** @addtogroup noxtls_encryption */

#include <stdint.h>
#include <string.h>
#include "noxtls_des.h"
#include "noxtls_des_internal.h"
#include "noxtls_common.h"

#if NOXTLS_FEATURE_DES

#ifdef __cplusplus
extern "C" {
#endif

noxtls_return_t des_encrypt_cbc(const uint8_t *key,
                    const uint8_t *data,
                    uint32_t data_len,
                    const uint8_t *iv,
                    uint8_t *output)
{
    uint32_t cur;
    uint8_t block[DES_BLOCK_LENGTH];
    uint8_t zero_iv[DES_BLOCK_LENGTH];
    const uint8_t *prev;

    if (!key || !data || !output || (data_len % DES_BLOCK_LENGTH) != 0)
        return NOXTLS_RETURN_INVALID_PARAM;
    prev = iv;
    if (!prev) {
        memset(zero_iv, 0, DES_BLOCK_LENGTH);
        prev = zero_iv;
    }
    for (cur = 0; cur < data_len; cur += DES_BLOCK_LENGTH) {
        uint32_t i;
        for (i = 0; i < DES_BLOCK_LENGTH; i++)
            block[i] = data[cur + i] ^ prev[i];
        des_encrypt_block_internal(key, block, &output[cur]);
        prev = &output[cur];
    }
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t des_decrypt_cbc(const uint8_t *key,
                    const uint8_t *data,
                    uint32_t data_len,
                    const uint8_t *iv,
                    uint8_t *output)
{
    uint32_t cur;
    uint8_t block[DES_BLOCK_LENGTH];
    uint8_t zero_iv[DES_BLOCK_LENGTH];
    const uint8_t *prev;

    if (!key || !data || !output || (data_len % DES_BLOCK_LENGTH) != 0)
        return -1;
    prev = iv;
    if (!prev) {
        memset(zero_iv, 0, DES_BLOCK_LENGTH);
        prev = zero_iv;
    }
    for (cur = 0; cur < data_len; cur += DES_BLOCK_LENGTH) {
        uint32_t i;
        des_decrypt_block_internal(key, &data[cur], block);
        for (i = 0; i < DES_BLOCK_LENGTH; i++)
            output[cur + i] = block[i] ^ prev[i];
        prev = &data[cur];
    }
    return 0;
}

noxtls_return_t des3_encrypt_cbc(const uint8_t *key,
                     uint32_t key_len,
                     const uint8_t *data,
                     uint32_t data_len,
                     const uint8_t *iv,
                     uint8_t *output)
{
    uint32_t cur;
    uint8_t block[DES_BLOCK_LENGTH];
    uint8_t zero_iv[DES_BLOCK_LENGTH];
    const uint8_t *prev;

    if (!key || !data || !output || (key_len != 16 && key_len != 24) || (data_len % DES_BLOCK_LENGTH) != 0)
        return NOXTLS_RETURN_INVALID_PARAM;
    prev = iv;
    if (!prev) {
        memset(zero_iv, 0, DES_BLOCK_LENGTH);
        prev = zero_iv;
    }
    for (cur = 0; cur < data_len; cur += DES_BLOCK_LENGTH) {
        uint32_t i;
        for (i = 0; i < DES_BLOCK_LENGTH; i++)
            block[i] = data[cur + i] ^ prev[i];
        des3_encrypt_block(key, key_len, block, &output[cur]);
        prev = &output[cur];
    }
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t des3_decrypt_cbc(const uint8_t *key,
                     uint32_t key_len,
                     const uint8_t *data,
                     uint32_t data_len,
                     const uint8_t *iv,
                     uint8_t *output)
{
    uint32_t cur;
    uint8_t block[DES_BLOCK_LENGTH];
    uint8_t zero_iv[DES_BLOCK_LENGTH];
    const uint8_t *prev;

    if (!key || !data || !output || (key_len != 16 && key_len != 24) || (data_len % DES_BLOCK_LENGTH) != 0)
        return NOXTLS_RETURN_INVALID_PARAM;
    prev = iv;
    if (!prev) {
        memset(zero_iv, 0, DES_BLOCK_LENGTH);
        prev = zero_iv;
    }
    for (cur = 0; cur < data_len; cur += DES_BLOCK_LENGTH) {
        uint32_t i;
        des3_decrypt_block(key, key_len, &data[cur], block);
        for (i = 0; i < DES_BLOCK_LENGTH; i++)
            output[cur + i] = block[i] ^ prev[i];
        prev = &data[cur];
    }
    return NOXTLS_RETURN_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_FEATURE_DES */
