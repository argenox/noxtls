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
* File:    noxtls_aria_ctr.c
* Summary: ARIA Counter (CTR) Mode Implementation
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */

#include <stdint.h>
#include "common/noxtls_ct.h"
#include <string.h>
#include "noxtls_aria.h"
#include "noxtls_common.h"

#if NOXTLS_FEATURE_ARIA

/**
 * @brief ARIA Encrypt/Decrypt in CTR Mode
 */
/* Block-indexed CTR walk; extents follow caller data_len / ARIA block size. */
noxtls_return_t noxtls_aria_encrypt_ctr(const uint8_t* key,
                     const uint8_t* data,
                     uint32_t data_len,
                     const uint8_t * iv,
                     uint8_t* output,
                     noxtls_aria_type_t type)
{
    uint32_t i;
    uint32_t cur_block = 0U;
    uint8_t counter_block[NOXTLS_ARIA_BLOCK_LENGTH];
    uint8_t keystream[NOXTLS_ARIA_BLOCK_LENGTH];
    noxtls_aria_key_t aria_key;
    const uint32_t block_sz = (uint32_t)NOXTLS_ARIA_BLOCK_LENGTH;

    if ((key == NULL) || (data == NULL) || (output == NULL) || (iv == NULL)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    {
        noxtls_return_t r = noxtls_aria_set_encrypt_key(key, type, &aria_key);
        if (r != NOXTLS_RETURN_SUCCESS) {
            return r;
        }
    }

    /* Initialize counter from IV */
    noxtls_copy_u8(counter_block, sizeof(counter_block), iv, (size_t)block_sz);

    for (cur_block = 0U; cur_block < data_len; cur_block += block_sz)
    {
        uint32_t remain = (uint32_t)(data_len - cur_block);
        uint32_t block_len = (uint32_t)((remain < block_sz) ? remain : block_sz);

        /* Encrypt counter to produce keystream */
        (void)noxtls_aria_encrypt_block(&aria_key, counter_block, keystream);

        /* XOR keystream with plaintext */
        for (i = 0U; i < block_len; i += 1U) {
            output[cur_block + i] = (uint8_t)(data[cur_block + i] ^ keystream[i]);
        }

        /* Increment counter (big-endian) */
        for (i = block_sz; i > 0U; i -= 1U) {
            counter_block[i - 1U] = (uint8_t)(counter_block[i - 1U] + 1U);
            if (counter_block[i - 1U] != 0U) {
                break;
            }
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief ARIA Decrypt in CTR Mode (same as encrypt)
 */
noxtls_return_t noxtls_aria_decrypt_ctr(const uint8_t* key,
                     const uint8_t* data,
                     uint32_t data_len,
                     const uint8_t * iv,
                     uint8_t* output,
                     noxtls_aria_type_t type)
{
    /* CTR mode: encryption and decryption are the same */
    return noxtls_aria_encrypt_ctr(key, data, data_len, iv, output, type);
}

#endif /* NOXTLS_FEATURE_ARIA */
