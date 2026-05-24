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

#if NOXTLS_FEATURE_DES

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief DES CBC encryption: each ciphertext block is E(P xor IV_prev); IV chain uses previous ciphertext (or supplied IV).
 * @param[in]  key Single-DES key (`NOXTLS_DES_KEY_LENGTH` bytes).
 * @param[in]  data Plaintext; length must be a multiple of `NOXTLS_DES_BLOCK_LENGTH`.
 * @param[in]  data_len Byte length of @p data.
 * @param[in]  iv Initialization vector (`NOXTLS_DES_BLOCK_LENGTH` bytes), or NULL to use an all-zero IV.
 * @param[out] output Ciphertext buffer; must hold @p data_len bytes (may overlap usage with @p data only if caller ensures safety).
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_INVALID_PARAM` if pointers are invalid or @p data_len is not block-aligned.
 */
noxtls_return_t noxtls_des_encrypt_cbc(const uint8_t *key,
                    const uint8_t *data,
                    uint32_t data_len,
                    const uint8_t *iv,
                    uint8_t *output)
{
    uint32_t cur;
    uint8_t block[NOXTLS_DES_BLOCK_LENGTH];
    uint8_t zero_iv[NOXTLS_DES_BLOCK_LENGTH];
    const uint8_t *prev;

    if(!key || !data || !output || (data_len % NOXTLS_DES_BLOCK_LENGTH) != 0)
        return NOXTLS_RETURN_INVALID_PARAM;
    prev = iv;
    if(!prev) {
        memset(zero_iv, 0, NOXTLS_DES_BLOCK_LENGTH);
        prev = zero_iv;
    }
    for(cur = 0; cur < data_len; cur += NOXTLS_DES_BLOCK_LENGTH) {
        uint32_t i;
        for(i = 0; i < NOXTLS_DES_BLOCK_LENGTH; i++)
            block[i] = data[cur + i] ^ prev[i];
        noxtls_des_encrypt_block_internal(key, block, &output[cur]);
        prev = &output[cur];
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief DES CBC decryption: each plaintext block is D(C) xor IV_prev; IV chain uses previous ciphertext (or supplied IV).
 * @param[in]  key Single-DES key (`NOXTLS_DES_KEY_LENGTH` bytes).
 * @param[in]  data Ciphertext; length must be a multiple of `NOXTLS_DES_BLOCK_LENGTH`.
 * @param[in]  data_len Byte length of @p data.
 * @param[in]  iv Initialization vector (`NOXTLS_DES_BLOCK_LENGTH` bytes), or NULL to use an all-zero IV.
 * @param[out] output Plaintext buffer; must hold @p data_len bytes.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_INVALID_PARAM` if pointers are invalid or @p data_len is not block-aligned.
 */
noxtls_return_t noxtls_des_decrypt_cbc(const uint8_t *key,
                    const uint8_t *data,
                    uint32_t data_len,
                    const uint8_t *iv,
                    uint8_t *output)
{
    uint32_t cur;
    uint8_t block[NOXTLS_DES_BLOCK_LENGTH];
    uint8_t zero_iv[NOXTLS_DES_BLOCK_LENGTH];
    const uint8_t *prev;

    if(!key || !data || !output || (data_len % NOXTLS_DES_BLOCK_LENGTH) != 0)
        return NOXTLS_RETURN_INVALID_PARAM;
    prev = iv;
    if(!prev) {
        memset(zero_iv, 0, NOXTLS_DES_BLOCK_LENGTH);
        prev = zero_iv;
    }
    for(cur = 0; cur < data_len; cur += NOXTLS_DES_BLOCK_LENGTH) {
        uint32_t i;
        noxtls_des_decrypt_block_internal(key, &data[cur], block);
        for(i = 0; i < NOXTLS_DES_BLOCK_LENGTH; i++)
            output[cur + i] = block[i] ^ prev[i];
        prev = &data[cur];
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Triple-DES CBC encryption (EDE per block); IV handling matches single-DES CBC.
 * @param[in]  key 3DES key material: `16` bytes (two-key EDE) or `24` bytes (three-key EDE).
 * @param[in]  key_len Length of @p key (`16` or `24`).
 * @param[in]  data Plaintext; length must be a multiple of `NOXTLS_DES_BLOCK_LENGTH`.
 * @param[in]  data_len Byte length of @p data.
 * @param[in]  iv Initialization vector (`NOXTLS_DES_BLOCK_LENGTH` bytes), or NULL for all-zero IV.
 * @param[out] output Ciphertext buffer; must hold @p data_len bytes.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_INVALID_PARAM` if pointers, @p key_len, or alignment are invalid.
 */
noxtls_return_t des3_encrypt_cbc(const uint8_t *key,
                     uint32_t key_len,
                     const uint8_t *data,
                     uint32_t data_len,
                     const uint8_t *iv,
                     uint8_t *output)
{
    uint32_t cur;
    uint8_t block[NOXTLS_DES_BLOCK_LENGTH];
    uint8_t zero_iv[NOXTLS_DES_BLOCK_LENGTH];
    const uint8_t *prev;

    if(!key || !data || !output || (key_len != 16 && key_len != 24) || (data_len % NOXTLS_DES_BLOCK_LENGTH) != 0)
        return NOXTLS_RETURN_INVALID_PARAM;
    prev = iv;
    if(!prev) {
        memset(zero_iv, 0, NOXTLS_DES_BLOCK_LENGTH);
        prev = zero_iv;
    }
    for(cur = 0; cur < data_len; cur += NOXTLS_DES_BLOCK_LENGTH) {
        uint32_t i;
        for(i = 0; i < NOXTLS_DES_BLOCK_LENGTH; i++)
            block[i] = data[cur + i] ^ prev[i];
        noxtls_des3_encrypt_block(key, key_len, block, &output[cur]);
        prev = &output[cur];
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Triple-DES CBC decryption (DED per block); IV handling matches single-DES CBC.
 * @param[in]  key 3DES key material: `16` bytes (two-key) or `24` bytes (three-key).
 * @param[in]  key_len Length of @p key (`16` or `24`).
 * @param[in]  data Ciphertext; length must be a multiple of `NOXTLS_DES_BLOCK_LENGTH`.
 * @param[in]  data_len Byte length of @p data.
 * @param[in]  iv Initialization vector (`NOXTLS_DES_BLOCK_LENGTH` bytes), or NULL for all-zero IV.
 * @param[out] output Plaintext buffer; must hold @p data_len bytes.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_INVALID_PARAM` if pointers, @p key_len, or alignment are invalid.
 */
noxtls_return_t des3_decrypt_cbc(const uint8_t *key,
                     uint32_t key_len,
                     const uint8_t *data,
                     uint32_t data_len,
                     const uint8_t *iv,
                     uint8_t *output)
{
    uint32_t cur;
    uint8_t block[NOXTLS_DES_BLOCK_LENGTH];
    uint8_t zero_iv[NOXTLS_DES_BLOCK_LENGTH];
    const uint8_t *prev;

    if(!key || !data || !output || (key_len != 16 && key_len != 24) || (data_len % NOXTLS_DES_BLOCK_LENGTH) != 0)
        return NOXTLS_RETURN_INVALID_PARAM;
    prev = iv;
    if(!prev) {
        memset(zero_iv, 0, NOXTLS_DES_BLOCK_LENGTH);
        prev = zero_iv;
    }
    for(cur = 0; cur < data_len; cur += NOXTLS_DES_BLOCK_LENGTH) {
        uint32_t i;
        noxtls_des3_decrypt_block(key, key_len, &data[cur], block);
        for(i = 0; i < NOXTLS_DES_BLOCK_LENGTH; i++)
            output[cur + i] = block[i] ^ prev[i];
        prev = &data[cur];
    }
    return NOXTLS_RETURN_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_FEATURE_DES */
