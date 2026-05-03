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
* File:    noxtls_camellia_cfb.c
* Summary: Camellia Cipher Feedback (CFB) Mode Implementation
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
 * @brief Camellia Encrypt in CFB Mode
 *
 * Cipher Feedback mode: Encrypts the IV or previous ciphertext block
 * to generate a keystream, which is XORed with the plaintext.
 *
 * @param key is a pointer to the encryption key
 * @param data is a pointer to the plaintext to be encrypted
 * @param data_len is the length of the plaintext in bytes
 * @param iv is the Initialization Vector (16 bytes). If NULL, zero IV is used.
 * @param output is the output buffer where the encrypted plaintext will be placed
 * @param type is the Camellia variant, 128, 192, 256
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t camellia_encrypt_cfb(const uint8_t* key, 
                         const uint8_t* data, 
                         uint32_t data_len,
                         const uint8_t * iv,
                         uint8_t* output, 
                         camellia_type_t type)
{
    uint32_t cur_block = 0;
    uint32_t i;
    uint8_t feedback[CAMELLIA_BLOCK_LENGTH];
    uint8_t keystream[CAMELLIA_BLOCK_LENGTH];
    uint8_t zero_iv[CAMELLIA_BLOCK_LENGTH];
    const uint8_t * iv_src = NULL;
    
    /* Initialize feedback register with IV */
    if(iv == NULL) {
        memset(zero_iv, 0, CAMELLIA_BLOCK_LENGTH);
        iv_src = zero_iv;
    }
    else {
        iv_src = iv;
    }
    
    memcpy(feedback, iv_src, CAMELLIA_BLOCK_LENGTH);
    
    for (cur_block = 0; cur_block < data_len; cur_block += CAMELLIA_BLOCK_LENGTH)
    {
        uint32_t block_len = (data_len - cur_block < CAMELLIA_BLOCK_LENGTH) ? 
                             (data_len - cur_block) : CAMELLIA_BLOCK_LENGTH;
        
        /* Encrypt feedback register to generate keystream */
        camellia_encrypt_block_internal(key, feedback, keystream, type);
        
        /* XOR keystream with plaintext */
        for(i = 0; i < block_len; i++) {
            output[cur_block + i] = data[cur_block + i] ^ keystream[i];
        }
        
        /* Update feedback register: shift left and insert ciphertext */
        if(block_len == CAMELLIA_BLOCK_LENGTH) {
            memcpy(feedback, output + cur_block, CAMELLIA_BLOCK_LENGTH);
        }
        else {
            /* Partial block: shift feedback and insert ciphertext */
            memmove(feedback, feedback + block_len, CAMELLIA_BLOCK_LENGTH - block_len);
            memcpy(feedback + CAMELLIA_BLOCK_LENGTH - block_len, output + cur_block, block_len);
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Camellia Decrypt in CFB Mode (same structure as encrypt: encrypt feedback, XOR with ciphertext)
 * Same structure as encrypt: encrypt feedback, XOR with ciphertext
 *
 * @param key is a pointer to the decryption key
 * @param data is a pointer to the ciphertext to be decrypted
 * @param data_len is the length of the ciphertext in bytes
 * @param iv is not used (can be NULL)
 * @param output is the output buffer where the decrypted ciphertext will be placed
 * @param type is the Camellia variant, 128, 192, 256  @see camellia_type_t
 *
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t camellia_decrypt_cfb(const uint8_t* key,
                         const uint8_t* data,
                         uint32_t data_len,
                         const uint8_t * iv,
                         uint8_t* output,
                         camellia_type_t type)
{
    uint32_t cur_block;
    uint32_t i;
    uint8_t feedback[CAMELLIA_BLOCK_LENGTH];
    uint8_t keystream[CAMELLIA_BLOCK_LENGTH];
    uint8_t zero_iv[CAMELLIA_BLOCK_LENGTH];
    const uint8_t * iv_src = NULL;

    if (iv == NULL) {
        memset(zero_iv, 0, CAMELLIA_BLOCK_LENGTH);
        iv_src = zero_iv;
    } else {
        iv_src = iv;
    }
    memcpy(feedback, iv_src, CAMELLIA_BLOCK_LENGTH);

    for (cur_block = 0; cur_block < data_len; cur_block += CAMELLIA_BLOCK_LENGTH)
    {
        uint32_t block_len = (data_len - cur_block < CAMELLIA_BLOCK_LENGTH) ?
                             (data_len - cur_block) : CAMELLIA_BLOCK_LENGTH;

        camellia_encrypt_block_internal(key, feedback, keystream, type);
        for (i = 0; i < block_len; i++)
            output[cur_block + i] = data[cur_block + i] ^ keystream[i];

        if (block_len == CAMELLIA_BLOCK_LENGTH)
            memcpy(feedback, &data[cur_block], CAMELLIA_BLOCK_LENGTH);
        else {
            memmove(feedback, feedback + block_len, CAMELLIA_BLOCK_LENGTH - block_len);
            memcpy(feedback + CAMELLIA_BLOCK_LENGTH - block_len, &data[cur_block], block_len);
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_CAMELLIA */
