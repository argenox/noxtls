/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
* 
*
* File:    noxtls_camellia_ctr.c
* Summary: Camellia Counter (CTR) Mode Implementation
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
 * @brief Camellia Encrypt in CTR Mode
 *
 * Counter mode: Encrypts a counter block to generate a keystream,
 * which is XORed with the plaintext.
 *
 * @param key is a pointer to the encryption key
 * @param data is a pointer to the plaintext to be encrypted
 * @param data_len is the length of the plaintext in bytes
 * @param iv is the Initialization Vector (16 bytes) used as the initial counter
 * @param output is the output buffer where the encrypted plaintext will be placed
 * @param type is the Camellia variant, 128, 192, 256
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t noxtls_camellia_encrypt_ctr(const uint8_t* key, 
                         const uint8_t* data, 
                         uint32_t data_len,
                         const uint8_t * iv,
                         uint8_t* output, 
                         noxtls_camellia_type_t type)
{
    uint32_t cur_block = 0;
    uint32_t i;
    uint8_t counter[NOXTLS_CAMELLIA_BLOCK_LENGTH];
    uint8_t keystream[NOXTLS_CAMELLIA_BLOCK_LENGTH];
    uint8_t zero_iv[NOXTLS_CAMELLIA_BLOCK_LENGTH];
    const uint8_t * iv_src = NULL;
    
    /* Initialize counter from IV */
    if(iv == NULL) {
        memset(zero_iv, 0, NOXTLS_CAMELLIA_BLOCK_LENGTH);
        iv_src = zero_iv;
    }
    else {
        iv_src = iv;
    }
    
    memcpy(counter, iv_src, NOXTLS_CAMELLIA_BLOCK_LENGTH);
    
    for(cur_block = 0; cur_block < data_len; cur_block += NOXTLS_CAMELLIA_BLOCK_LENGTH)
    {
        uint32_t block_len = (data_len - cur_block < NOXTLS_CAMELLIA_BLOCK_LENGTH) ? 
                             (data_len - cur_block) : NOXTLS_CAMELLIA_BLOCK_LENGTH;
        
        /* Encrypt counter to generate keystream */
        noxtls_camellia_encrypt_block_internal(key, counter, keystream, type);
        
        /* XOR keystream with plaintext */
        for(i = 0; i < block_len; i++) {
            output[cur_block + i] = data[cur_block + i] ^ keystream[i];
        }
        
        /* Increment counter (big-endian, incrementing last 64 bits) */
        uint64_t counter_value = ((uint64_t)counter[8] << 56) | ((uint64_t)counter[9] << 48) |
                        ((uint64_t)counter[10] << 40) | ((uint64_t)counter[11] << 32) |
                        ((uint64_t)counter[12] << 24) | ((uint64_t)counter[13] << 16) |
                        ((uint64_t)counter[14] << 8) | counter[15];
        counter_value++;
        counter[8] = (counter_value >> 56) & 0xFF;
        counter[9] = (counter_value >> 48) & 0xFF;
        counter[10] = (counter_value >> 40) & 0xFF;
        counter[11] = (counter_value >> 32) & 0xFF;
        counter[12] = (counter_value >> 24) & 0xFF;
        counter[13] = (counter_value >> 16) & 0xFF;
        counter[14] = (counter_value >> 8) & 0xFF;
        counter[15] = counter_value & 0xFF;
    }

    return 0;
}

/**
 * @brief Camellia Decrypt in CTR Mode (same as encrypt: XOR with keystream)
 * @param key is a pointer to the decryption key
 * @param data is a pointer to the ciphertext to be decrypted
 * @param data_len is the length of the ciphertext in bytes
 * @param iv is not used (can be NULL)
 * @param output is the output buffer where the decrypted ciphertext will be placed
 * @param type is the Camellia variant, 128, 192, 256  @see noxtls_camellia_type_t
 *
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t noxtls_camellia_decrypt_ctr(const uint8_t* key,
                         const uint8_t* data,
                         uint32_t data_len,
                         const uint8_t * iv,
                         uint8_t* output,
                         noxtls_camellia_type_t type)
{
    return noxtls_camellia_encrypt_ctr(key, data, data_len, iv, output, type);
}

#endif /* NOXTLS_FEATURE_CAMELLIA */
