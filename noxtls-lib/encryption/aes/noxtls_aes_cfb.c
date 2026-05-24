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
* File:    noxtls_aes_cfb.c
* Summary: AES Cipher Feedback (CFB) Mode Implementation
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */

#include <stdint.h>
#include <string.h>
#include "noxtls_aes.h"
#include "noxtls_aes_internal.h"
#include "noxtls_common.h"

#if NOXTLS_FEATURE_AES_CFB

/**
 * @brief AES Encrypt in CFB Mode
 *
 * Cipher Feedback mode: The previous ciphertext block (or IV for first block)
 * is encrypted to produce a keystream, which is XORed with the plaintext.
 * Supports arbitrary-length data.
 *
 * @param key is a pointer to the encryption key
 * @param data is a pointer to the plaintext to be encrypted
 * @param data_len is the length of the plaintext in bytes
 * @param iv is the Initialization Vector (16 bytes). Required.
 * @param output is the output buffer where the encrypted plaintext will be placed
 * @param type is the AES variant, 128, 192, 256
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_* on failure
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
noxtls_return_t noxtls_aes_encrypt_cfb(const uint8_t* key,
                    const uint8_t* data,
                    uint32_t data_len,
                    const uint8_t * iv,
                    uint8_t* output,
                    noxtls_aes_type_t type)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint32_t cur_block = 0;
    uint8_t keystream[NOXTLS_AES_BLOCK_LENGTH];
    
    /* CFB Mode requires IV */
    if(iv == NULL) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    
    for(cur_block = 0; cur_block < data_len; cur_block += NOXTLS_AES_BLOCK_LENGTH)
    {
        uint32_t block_len = (data_len - cur_block < NOXTLS_AES_BLOCK_LENGTH) ?
                             (data_len - cur_block) : NOXTLS_AES_BLOCK_LENGTH;
        
        if(cur_block == 0) {
            /* Encrypt IV for first block */
            noxtls_aes_encrypt_block_internal(key, iv, keystream, type);
        }
        else {
            /* Encrypt previous ciphertext block */
            noxtls_aes_encrypt_block_internal(key, &output[cur_block - NOXTLS_AES_BLOCK_LENGTH], keystream, type);
        }
        
        /* XOR keystream with plaintext */
        for(uint32_t byte_index = 0; byte_index < block_len; byte_index++) {
            output[cur_block + byte_index] = data[cur_block + byte_index] ^ keystream[byte_index];
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_AES_CFB */

