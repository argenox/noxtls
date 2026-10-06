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
* File:    noxtls_aes_ctr.c
* Summary: AES Counter (CTR) Mode Implementation
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */

#include <stdint.h>
#include "common/noxtls_ct.h"
#include <string.h>
#include "noxtls_aes.h"
#include "noxtls_aes_accel.h"
#include "noxtls_aes_internal.h"
#include "noxtls_common.h"
#include "common/noxtls_accel_port.h"

#if NOXTLS_FEATURE_AES_CTR

/**
 * @brief AES Encrypt in CTR Mode
 *
 * Counter Mode: A counter is encrypted to produce a keystream,
 * which is XORed with the plaintext. Supports arbitrary-length data.
 *
 * @param key is a pointer to the encryption key
 * @param data is a pointer to the plaintext to be encrypted
 * @param data_len is the length of the plaintext in bytes
 * @param iv is the Initialization Vector (16 bytes) used as the initial counter. Required.
 * @param output is the output buffer where the encrypted plaintext will be placed
 * @param type is the AES variant, 128, 192, 256
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_* on failure
 */
/* Block-indexed CTR walk; extents follow caller data_len / AES block size. */
noxtls_return_t noxtls_aes_encrypt_ctr(const uint8_t* key,
                     const uint8_t* data,
                     uint32_t data_len,
                     const uint8_t * iv,
                     uint8_t* output,
                     noxtls_aes_type_t type)
{
    if ((key == NULL) || (data == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    int32_t i;
    uint32_t cur_block = 0U;
    uint8_t counter_block[NOXTLS_AES_BLOCK_LENGTH];
    uint8_t keystream[NOXTLS_AES_BLOCK_LENGTH];
    const uint32_t block_sz = (uint32_t)NOXTLS_AES_BLOCK_LENGTH;

    /* Counter Mode requires IV */
    if ((iv == NULL) || (data == NULL) || (output == NULL) || (key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
#if NOXTLS_PORT_AES_MODE_ACCEL
    {
        noxtls_return_t port_rc = noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_CTR, 0U, key, type, iv, data, data_len, output);
        if(port_rc != NOXTLS_RETURN_NOT_SUPPORTED) {
            return port_rc;
        }
    }
#endif

    /* Initialize counter from IV */
    noxtls_copy_u8(counter_block, sizeof(counter_block), iv, (size_t)block_sz);

    for (cur_block = 0U; cur_block < data_len; cur_block += block_sz)
    {
        uint32_t remain = (uint32_t)(data_len - cur_block);
        uint32_t block_len = (uint32_t)((remain < block_sz) ? remain : block_sz);

        /* Encrypt the counter to produce keystream */
        NOXTLS_AES_CHECK(noxtls_aes_encrypt_block_internal(key, counter_block, keystream, type), output, data_len, NULL, 0U);
        
        /* XOR keystream with plaintext */
        for (uint32_t byte_index = 0U; byte_index < block_len; byte_index += 1U) {
            output[cur_block + byte_index] = (uint8_t)(data[cur_block + byte_index] ^ keystream[byte_index]);
        }

        /* Increment counter (big-endian) */
        for (i = (int32_t)block_sz - 1; i >= 0; i -= 1) {
            counter_block[i] = (uint8_t)(counter_block[i] + 1U);
            if (counter_block[i] != 0U) {
                break;
            }
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_AES_CTR */
