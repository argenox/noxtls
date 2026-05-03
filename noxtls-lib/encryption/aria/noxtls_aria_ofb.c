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
* File:    noxtls_aria_ofb.c
* Summary: ARIA Output Feedback (OFB) Mode Implementation
*
*/

/** @addtogroup noxtls_encryption */

#include <stdint.h>
#include <string.h>
#include "noxtls_aria.h"
#include "noxtls_common.h"

#if NOXTLS_FEATURE_ARIA

/**
 * @brief ARIA Encrypt/Decrypt in OFB Mode
 */
noxtls_return_t aria_encrypt_ofb(const uint8_t* key,
                     const uint8_t* data,
                     uint32_t data_len,
                     const uint8_t * iv,
                     uint8_t* output,
                     aria_type_t type)
{
    uint32_t i;
    uint32_t cur_block = 0;
    uint8_t feedback[ARIA_BLOCK_LENGTH];
    uint8_t keystream[ARIA_BLOCK_LENGTH];
    aria_key_t aria_key;
    
    if(key == NULL || data == NULL || output == NULL || iv == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    { noxtls_return_t r = aria_set_encrypt_key(key, type, &aria_key);
    if(r != NOXTLS_RETURN_SUCCESS) return r; }
    
    /* Initialize feedback register with IV */
    memcpy(feedback, iv, ARIA_BLOCK_LENGTH);
    
    for (cur_block = 0; cur_block < data_len; cur_block += ARIA_BLOCK_LENGTH)
    {
        uint32_t block_len = (data_len - cur_block < ARIA_BLOCK_LENGTH) ?
                             (data_len - cur_block) : ARIA_BLOCK_LENGTH;
        
        /* Encrypt feedback to produce keystream */
        aria_encrypt_block(&aria_key, feedback, keystream);
        
        /* XOR keystream with data */
        for(i = 0; i < block_len; i++) {
            output[cur_block + i] = data[cur_block + i] ^ keystream[i];
        }
        
        /* Update feedback register with keystream */
        memcpy(feedback, keystream, ARIA_BLOCK_LENGTH);
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief ARIA Decrypt in OFB Mode (same as encrypt)
 */
noxtls_return_t aria_decrypt_ofb(const uint8_t* key,
                     const uint8_t* data,
                     uint32_t data_len,
                     const uint8_t * iv,
                     uint8_t* output,
                     aria_type_t type)
{
    /* OFB mode: encryption and decryption are the same */
    return aria_encrypt_ofb(key, data, data_len, iv, output, type);
}

#endif /* NOXTLS_FEATURE_ARIA */

