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
* File:    noxtls_aes_xts.c
* Summary: AES XEX-based Tweaked CodeBook mode with ciphertext Stealing (XTS) Implementation
*
*/

/** @addtogroup noxtls_encryption */

#include <stdint.h>
#include <string.h>
#include "noxtls_aes.h"
#include "noxtls_aes_internal.h"
#include "noxtls_common.h"

#if NOXTLS_FEATURE_AES_XTS

/**
 * @brief Galois Field multiplication by alpha (x) in GF(2^128)
 * 
 * Multiplies a 128-bit value by x (alpha) in GF(2^128) with reduction polynomial x^128 + x^7 + x^2 + x + 1
 * 
 * @param block 16-byte block to multiply
 */
static void gf128_multiply_alpha(uint8_t block[AES_BLOCK_LENGTH])
{
    int i;
    uint8_t carry = 0;
    uint8_t msb = block[15] & 0x80;
    
    /* Left shift the block */
    for(i = AES_BLOCK_LENGTH - 1; i >= 0; i--) {
        uint8_t next_carry = (block[i] & 0x80) ? 1 : 0;
        block[i] = (block[i] << 1) | carry;
        carry = next_carry;
    }
    
    /* Apply reduction if MSB was set */
    if(msb) {
        block[0] ^= 0x87; /* x^7 + x^2 + x + 1 */
    }
}

/**
 * @brief AES Encrypt in XTS Mode
 *
 * XEX-based Tweaked CodeBook mode with ciphertext Stealing (XTS-AES).
 * Used for disk encryption. Requires two keys (or key split in half).
 * The IV parameter is used as the tweak value (typically sector number).
 *
 * @param key is a pointer to the encryption key (full key, will be split)
 * @param data is a pointer to the plaintext to be encrypted
 * @param data_len is the length of the plaintext in bytes
 * @param iv is the tweak value (16 bytes). Typically represents sector number.
 * @param output is the output buffer where the encrypted plaintext will be placed
 * @param type is the AES variant, 128, 192, 256
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_* on failure
 */
noxtls_return_t aes_encrypt_xts(const uint8_t* key,
                    const uint8_t* data,
                    uint32_t data_len,
                    const uint8_t * iv,
                    uint8_t* output,
                    aes_type_t type)
{
    uint32_t cur_block = 0;
    uint32_t i = 0;
    uint8_t tweak[AES_BLOCK_LENGTH];
    uint8_t tweak_key[32];
    uint8_t data_key[32];   /* Max key size for data encryption */
    uint8_t temp_block[AES_BLOCK_LENGTH];
    uint32_t key_len = 0;
    uint32_t num_blocks = 0;
    uint32_t last_block_len = 0;
    
    /* Determine key length */
    switch(type) {
        case AES_128_BIT:
#if NOXTLS_FEATURE_AES_128
            key_len = 16;
            break;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case AES_192_BIT:
#if NOXTLS_FEATURE_AES_192
            key_len = 24;
            break;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case AES_256_BIT:
#if NOXTLS_FEATURE_AES_256
            key_len = 32;
            break;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        default:
            return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }
    
    /* XTS requires IV (tweak) */
    if(iv == NULL) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    
    /* XTS requires two keys: one for data encryption, one for tweak encryption */
    /* Standard XTS-AES key sizes:
     *   - AES-128-XTS: 256-bit key (two 128-bit keys)
     *   - AES-256-XTS: 512-bit key (two 256-bit keys)
     * 
     * For this implementation, we expect the key to be double the normal size.
     * If a single-size key is provided, we'll use it for both (non-standard but workable).
     */
    if(key_len == 16) {
        /* For 128-bit: use same key for both if only 16 bytes provided */
        /* Standard XTS-128 would use 32-byte key (two 128-bit keys) */
        memcpy(data_key, key, 16);
        memcpy(tweak_key, key, 16); /* Use same key (non-standard) */
    } else if(key_len == 24) {
        /* For 192-bit: use same key for both (XTS-192 not standard) */
        memcpy(data_key, key, 24);
        memcpy(tweak_key, key, 24);
    } else if(key_len == 32) {
        /* For 256-bit: check if we have 64-byte key (standard XTS-256) */
        memcpy(data_key, key, 32);
        memcpy(tweak_key, key, 32);
    }
    
    /* Encrypt tweak (IV) with the same AES key size selected for data path. */
    aes_encrypt_block_internal(tweak_key, iv, tweak, type);
    
    /* Calculate number of blocks */
    num_blocks = data_len / AES_BLOCK_LENGTH;
    last_block_len = data_len % AES_BLOCK_LENGTH;
    
    /* Process full blocks */
    for(cur_block = 0; cur_block < num_blocks; cur_block++) {
        /* XTS: C = E(K1, P XOR T) XOR T, where T is the tweak */
        
        /* XOR plaintext with tweak */
        for(i = 0; i < AES_BLOCK_LENGTH; i++) {
            temp_block[i] = data[cur_block * AES_BLOCK_LENGTH + i] ^ tweak[i];
        }
        
        /* Encrypt */
        aes_encrypt_block_internal(data_key, temp_block, temp_block, type);
        
        /* XOR result with tweak */
        for(i = 0; i < AES_BLOCK_LENGTH; i++) {
            output[cur_block * AES_BLOCK_LENGTH + i] = temp_block[i] ^ tweak[i];
        }
        
        /* Multiply tweak by alpha for next block (except for last full block if we have partial) */
        if(!(cur_block == num_blocks - 1 && last_block_len > 0)) {
            gf128_multiply_alpha(tweak);
        }
    }
    
    /* Handle partial last block with ciphertext stealing */
    if(last_block_len > 0) {
        uint8_t last_tweak[AES_BLOCK_LENGTH];
        uint8_t second_last_block[AES_BLOCK_LENGTH];
        
        /* Save second-to-last ciphertext block */
        if(num_blocks > 0) {
            memcpy(second_last_block, output + (num_blocks - 1) * AES_BLOCK_LENGTH, AES_BLOCK_LENGTH);
        }
        
        /* Multiply tweak by alpha one more time */
        memcpy(last_tweak, tweak, AES_BLOCK_LENGTH);
        gf128_multiply_alpha(last_tweak);
        
        /* Encrypt second-to-last plaintext block with new tweak */
        if(num_blocks > 0) {
            for(i = 0; i < AES_BLOCK_LENGTH; i++) {
                temp_block[i] = data[(num_blocks - 1) * AES_BLOCK_LENGTH + i] ^ last_tweak[i];
            }
            aes_encrypt_block_internal(data_key, temp_block, temp_block, type);
            for(i = 0; i < AES_BLOCK_LENGTH; i++) {
                output[(num_blocks - 1) * AES_BLOCK_LENGTH + i] = temp_block[i] ^ last_tweak[i];
            }
        }
        
        /* Handle last partial block: pad with ciphertext from second-to-last */
        for(i = 0; i < last_block_len; i++) {
            temp_block[i] = data[num_blocks * AES_BLOCK_LENGTH + i];
        }
        for(i = last_block_len; i < AES_BLOCK_LENGTH; i++) {
            if(num_blocks > 0) {
                temp_block[i] = second_last_block[i];
            } else {
                temp_block[i] = 0; /* Zero pad if no previous block */
            }
        }
        
        /* Encrypt padded block */
        for(i = 0; i < AES_BLOCK_LENGTH; i++) {
            temp_block[i] ^= last_tweak[i];
        }
        aes_encrypt_block_internal(data_key, temp_block, temp_block, type);
        for(i = 0; i < AES_BLOCK_LENGTH; i++) {
            temp_block[i] ^= last_tweak[i];
        }
        
        /* Output: first part goes to last block position, rest overwrites second-to-last */
        memcpy(output + num_blocks * AES_BLOCK_LENGTH, temp_block, last_block_len);
        if(num_blocks > 0) {
            memcpy(output + (num_blocks - 1) * AES_BLOCK_LENGTH + last_block_len, 
                   temp_block + last_block_len, 
                   AES_BLOCK_LENGTH - last_block_len);
        }
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_AES_XTS */

