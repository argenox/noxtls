/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
* 
*
* File:    noxtls_camellia_ecb.c
* Summary: Camellia Electronic Codebook (ECB) Mode Implementation
*
*/

/** @addtogroup noxtls_encryption */

#include <stdint.h>
#include <string.h>
#include "noxtls_camellia.h"
#include "noxtls_camellia_internal.h"
#include "noxtls_common.h"

#if NOXTLS_FEATURE_CAMELLIA

/**
 * @brief Camellia Encrypt in ECB Mode
 *
 * Electronic Codebook mode: Each block is encrypted independently.
 * No IV is required or used.
 *
 * @param key is a pointer to the encryption key
 * @param data is a pointer to the plaintext to be encrypted
 * @param data_len is the length of the plaintext in bytes
 * @param iv is not used (can be NULL)
 * @param output is the output buffer where the encrypted plaintext will be placed
 * @param type is the Camellia variant, 128, 192, 256
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_* on failure
 */
noxtls_return_t noxtls_camellia_encrypt_ecb(const uint8_t* key, 
                         const uint8_t* data, 
                         uint32_t data_len,
                         const uint8_t * iv,
                         uint8_t* output, 
                         noxtls_camellia_type_t type)
{
    uint32_t cur_block = 0;
    
    (void)iv; /* IV not used in ECB mode */
    
    for(cur_block = 0; cur_block < data_len; cur_block += NOXTLS_CAMELLIA_BLOCK_LENGTH)
    {
        /* Electronic Codebook: Direct encryption of each block */
        noxtls_camellia_encrypt_block_internal(key, &data[cur_block], &output[cur_block], type);
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Camellia Decrypt in ECB Mode
 * @param key is a pointer to the decryption key
 * @param data is a pointer to the ciphertext to be decrypted
 * @param data_len is the length of the ciphertext in bytes
 * @param iv is not used (can be NULL)
 * @param output is the output buffer where the decrypted ciphertext will be placed
 * @param type is the Camellia variant, 128, 192, 256 @see noxtls_camellia_type_t
 *
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_* on failure
 */
noxtls_return_t noxtls_camellia_decrypt_ecb(const uint8_t* key,
                         const uint8_t* data,
                         uint32_t data_len,
                         const uint8_t * iv,
                         uint8_t* output,
                         noxtls_camellia_type_t type)
{
    uint32_t cur_block;

    (void)iv;
    for(cur_block = 0; cur_block < data_len; cur_block += NOXTLS_CAMELLIA_BLOCK_LENGTH)
        noxtls_camellia_decrypt_block_internal(key, &data[cur_block], &output[cur_block], type);
    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_CAMELLIA */
