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
* File:    noxtls_camellia_ctr.c
* Summary: Camellia Counter (CTR) Mode Implementation
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */

#include <stdint.h>
#include <string.h>
#include "noxtls_camellia.h"
#include "noxtls_camellia_internal.h"
#include "noxtls_common.h"
#include "noxtls_ct.h"

#if NOXTLS_FEATURE_CAMELLIA

/**
 * @brief Camellia Encrypt in CTR Mode
 */
/* Block-indexed CTR walk; extents follow caller data_len / Camellia block size. */
noxtls_return_t noxtls_camellia_encrypt_ctr(const uint8_t* key, 
                         const uint8_t* data, 
                         uint32_t data_len,
                         const uint8_t * iv,
                         uint8_t* output, 
                         noxtls_camellia_type_t type)
{
    uint32_t cur_block = 0U;
    uint32_t i;
    uint8_t counter[NOXTLS_CAMELLIA_BLOCK_LENGTH];
    uint8_t keystream[NOXTLS_CAMELLIA_BLOCK_LENGTH];
    uint8_t zero_iv[NOXTLS_CAMELLIA_BLOCK_LENGTH];
    const uint8_t * iv_src = NULL;
    const uint32_t block_sz = (uint32_t)NOXTLS_CAMELLIA_BLOCK_LENGTH;

    {
        noxtls_return_t rc = noxtls_camellia_check_oneshot_args(key, data, output, type);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    /* Initialize counter from IV */
    if (iv == NULL) {
        noxtls_secure_zero((zero_iv), (size_t)(block_sz));
        iv_src = zero_iv;
    }
    else {
        iv_src = iv;
    }

    noxtls_copy_u8(counter, sizeof(counter), iv_src, (size_t)block_sz);

    for (cur_block = 0U; cur_block < data_len; cur_block += block_sz)
    {
        uint32_t remain = (uint32_t)(data_len - cur_block);
        uint32_t block_len = (uint32_t)((remain < block_sz) ? remain : block_sz);

        /* Encrypt counter to generate keystream */
        {
            noxtls_return_t rc = noxtls_camellia_encrypt_block_internal(key, counter, keystream, type);
            if (rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_secure_zero(output, (size_t)data_len);
                return rc;
            }
        }

        /* XOR keystream with plaintext */
        for (i = 0U; i < block_len; i += 1U) {
            output[cur_block + i] = (uint8_t)(data[cur_block + i] ^ keystream[i]);
        }

        /* Increment the full 128-bit counter block (big-endian), exactly like
         * the streaming API and AES/ARIA-CTR, so both keystreams agree across
         * a wrap of the low 64 bits. */
        noxtls_camellia_counter_inc(counter);
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Camellia Decrypt in CTR Mode (same as encrypt: XOR with keystream)
 */
noxtls_return_t noxtls_camellia_decrypt_ctr(const uint8_t* key,
                         const uint8_t* data,
                         uint32_t data_len,
                         const uint8_t * iv,
                         uint8_t* output,
                         noxtls_camellia_type_t type) { return noxtls_camellia_encrypt_ctr(key, data, data_len, iv, output, type); }

#endif /* NOXTLS_FEATURE_CAMELLIA */
