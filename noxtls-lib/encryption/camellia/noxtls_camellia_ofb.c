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
* File:    noxtls_camellia_ofb.c
* Summary: Camellia Output Feedback (OFB) Mode Implementation
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
 * @brief Camellia Encrypt in OFB Mode
 *
 * Output Feedback mode: Generates a keystream by repeatedly encrypting
 * the IV or previous keystream block, which is XORed with the plaintext.
 *
 * @param key is a pointer to the encryption key
 * @param data is a pointer to the plaintext to be encrypted
 * @param data_len is the length of the plaintext in bytes
 * @param iv is the Initialization Vector (16 bytes). If NULL, zero IV is used.
 * @param output is the output buffer where the encrypted plaintext will be placed
 * @param type is the Camellia variant, 128, 192, 256
 * @return NOXTLS_RETURN_SUCCESS on success
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
noxtls_return_t noxtls_camellia_encrypt_ofb(const uint8_t* key, 
                         const uint8_t* data, 
                         uint32_t data_len,
                         const uint8_t * iv,
                         uint8_t* output, 
                         noxtls_camellia_type_t type)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint32_t cur_block = 0;
    uint32_t i;
    uint8_t keystream_block[NOXTLS_CAMELLIA_BLOCK_LENGTH];
    uint8_t zero_iv[NOXTLS_CAMELLIA_BLOCK_LENGTH];
    const uint8_t * iv_src = NULL;
    
    /* Initialize keystream block with IV */
    if(iv == NULL) {
        memset(zero_iv, 0, NOXTLS_CAMELLIA_BLOCK_LENGTH);
        iv_src = zero_iv;
    }
    else {
        iv_src = iv;
    }
    
    memcpy(keystream_block, iv_src, NOXTLS_CAMELLIA_BLOCK_LENGTH);
    
    for(cur_block = 0; cur_block < data_len; cur_block += NOXTLS_CAMELLIA_BLOCK_LENGTH)
    {
        uint32_t block_len = (data_len - cur_block < NOXTLS_CAMELLIA_BLOCK_LENGTH) ? 
                             (data_len - cur_block) : NOXTLS_CAMELLIA_BLOCK_LENGTH;
        
        /* Encrypt keystream block to generate next keystream */
        noxtls_camellia_encrypt_block_internal(key, keystream_block, keystream_block, type);
        
        /* XOR keystream with plaintext */
        for(i = 0; i < block_len; i++) {
            output[cur_block + i] = data[cur_block + i] ^ keystream_block[i];
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Camellia Decrypt in OFB Mode (same as encrypt: same keystream XOR with ciphertext)
 */
noxtls_return_t noxtls_camellia_decrypt_ofb(const uint8_t* key,
                         const uint8_t* data,
                         uint32_t data_len,
                         const uint8_t * iv,
                         uint8_t* output,
                         noxtls_camellia_type_t type)
{
    return noxtls_camellia_encrypt_ofb(key, data, data_len, iv, output, type);
}

#endif /* NOXTLS_FEATURE_CAMELLIA */
