/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
*
* NOTICE:  All information contained herein, source code, binaries and
* derived works is, and remains
* the property of Argenox Technologies and its suppliers,
* if any.  The intellectual and technical concepts contained
* herein are proprietary to Argenox Technologies
* and its suppliers may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Argenox Technologies.
*
* THIS SOFTWARE IS PROVIDED BY ARGENOX "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL ARGENOX TECHNOLOGIES LLC BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
* CONTACT: info@argenox.com
* 
*
* File:    noxtls_aria_cbc.c
* Summary: ARIA Cipher Block Chaining (CBC) Mode Implementation
*
*/

/** @addtogroup noxtls_encryption */

#include <stdint.h>
#include <string.h>
#include "noxtls_aria.h"
#include "noxtls_common.h"

#if NOXTLS_FEATURE_ARIA

/**
 * @brief ARIA Encrypt in CBC Mode
 */
noxtls_return_t aria_encrypt_cbc(const uint8_t* key,
                     const uint8_t* data,
                     uint32_t data_len,
                     const uint8_t * iv,
                     uint8_t* output,
                     aria_type_t type)
{
    uint32_t i;
    uint32_t cur_block = 0;
    const uint8_t * iv_src = NULL;
    uint8_t temp_block[ARIA_BLOCK_LENGTH];
    uint8_t zero_iv[ARIA_BLOCK_LENGTH];
    aria_key_t aria_key;
    
    if(key == NULL || data == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    { noxtls_return_t r = aria_set_encrypt_key(key, type, &aria_key);
    if(r != NOXTLS_RETURN_SUCCESS) return r; }
    
    for (cur_block = 0; cur_block < data_len; cur_block += ARIA_BLOCK_LENGTH)
    {
        uint32_t block_len = (data_len - cur_block < ARIA_BLOCK_LENGTH) ?
                             (data_len - cur_block) : ARIA_BLOCK_LENGTH;
        
        /* Cipher Block Chaining: XOR with previous ciphertext (or IV) */
        if(cur_block == 0) {
            /* Use IV for first block */
            if(iv == NULL) {
                /* Zero IV if not provided */
                memset(zero_iv, 0, ARIA_BLOCK_LENGTH);
                iv_src = zero_iv;
            } else {
                iv_src = iv;
            }
        } else {
            /* Use previous ciphertext */
            iv_src = output + cur_block - ARIA_BLOCK_LENGTH;
        }
        
        /* XOR input block with IV/previous ciphertext */
        for(i = 0; i < block_len; i++) {
            temp_block[i] = data[cur_block + i] ^ iv_src[i];
        }
        
        /* Pad if necessary */
        if(block_len < ARIA_BLOCK_LENGTH) {
            uint8_t pad_value = (uint8_t)(ARIA_BLOCK_LENGTH - block_len);
            for(i = block_len; i < ARIA_BLOCK_LENGTH; i++) {
                temp_block[i] = pad_value;
            }
        }
        
        /* Encrypt block */
        aria_encrypt_block(&aria_key, temp_block, output + cur_block);
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief ARIA Decrypt in CBC Mode
 */
noxtls_return_t aria_decrypt_cbc(const uint8_t* key,
                     const uint8_t* data,
                     uint32_t data_len,
                     const uint8_t * iv,
                     uint8_t* output,
                     aria_type_t type)
{
    uint32_t i;
    uint32_t cur_block = 0;
    const uint8_t * iv_src = NULL;
    uint8_t temp_block[ARIA_BLOCK_LENGTH];
    uint8_t zero_iv[ARIA_BLOCK_LENGTH];
    aria_key_t aria_key;
    
    if(key == NULL || data == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    { noxtls_return_t r = aria_set_decrypt_key(key, type, &aria_key);
    if(r != NOXTLS_RETURN_SUCCESS) return r; }
    
    for (cur_block = 0; cur_block < data_len; cur_block += ARIA_BLOCK_LENGTH)
    {
        uint32_t block_len = (data_len - cur_block < ARIA_BLOCK_LENGTH) ?
                             (data_len - cur_block) : ARIA_BLOCK_LENGTH;
        
        if(block_len != ARIA_BLOCK_LENGTH) {
            return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
        }
        
        /* Decrypt block */
        aria_decrypt_block(&aria_key, data + cur_block, temp_block);
        
        /* Cipher Block Chaining: XOR with previous ciphertext (or IV) */
        if(cur_block == 0) {
            /* Use IV for first block */
            if(iv == NULL) {
                /* Zero IV if not provided */
                memset(zero_iv, 0, ARIA_BLOCK_LENGTH);
                iv_src = zero_iv;
            } else {
                iv_src = iv;
            }
        } else {
            /* Use previous ciphertext */
            iv_src = data + cur_block - ARIA_BLOCK_LENGTH;
        }
        
        /* XOR decrypted block with IV/previous ciphertext */
        for(i = 0; i < ARIA_BLOCK_LENGTH; i++) {
            output[cur_block + i] = temp_block[i] ^ iv_src[i];
        }
    }
    
    /* Remove padding */
    if(data_len > 0) {
        uint8_t pad_value = output[data_len - 1];
        if(pad_value > 0 && pad_value <= ARIA_BLOCK_LENGTH) {
            /* Verify padding */
            int valid_pad = 1;
            for(i = data_len - pad_value; i < data_len; i++) {
                if(output[i] != pad_value) {
                    valid_pad = 0;
                    break;
                }
            }
            if(valid_pad) {
                /* Padding is valid, but we don't modify output length here */
                /* Caller should handle padding removal */
            }
        }
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_ARIA */


