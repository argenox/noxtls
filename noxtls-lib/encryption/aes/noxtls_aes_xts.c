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
* File:    noxtls_aes_xts.c
* Summary: AES XEX-based Tweaked CodeBook mode with ciphertext Stealing (XTS)
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */

#include <stdint.h>
#include "common/noxtls_ct.h"
#include <string.h>
#include "noxtls_aes.h"
#include "noxtls_aes_internal.h"
#include "noxtls_common.h"

#if NOXTLS_FEATURE_AES_XTS

/**
 * @brief Galois Field multiplication by alpha (x) in GF(2^128)
 */
static void gf128_multiply_alpha(uint8_t block[NOXTLS_AES_BLOCK_LENGTH])
{
    int32_t i;
    uint8_t carry = 0U;
    uint8_t msb = (uint8_t)(block[15] & 0x80U);
    const int32_t block_sz = (int32_t)NOXTLS_AES_BLOCK_LENGTH;

    /* Left shift the block */
    for (i = block_sz - 1; i >= 0; i -= 1) {
        uint8_t next_carry = (uint8_t)((((block[i] & 0x80U) != 0U)) ? 1U : 0U);
        block[i] = (uint8_t)(((uint32_t)block[i] <<1U) | (uint32_t)carry);
        carry = next_carry;
    }

    /* Apply reduction if MSB was set */
    if (msb != 0U) {
        block[0] ^= 0x87U; /* x^7 + x^2 + x + 1 */
    }
}

/**
 * @brief AES Encrypt in XTS Mode
 */
/* XTS block walk with optional ciphertext stealing for partial final block. */
noxtls_return_t noxtls_aes_encrypt_xts(const uint8_t* key,
                    const uint8_t* data,
                    uint32_t data_len,
                    const uint8_t * iv,
                    uint8_t* output,
                    noxtls_aes_type_t type)
{
    uint32_t cur_block = 0U;
    uint32_t i = 0U;
    uint8_t tweak[NOXTLS_AES_BLOCK_LENGTH];
    uint8_t tweak_key[32];
    uint8_t data_key[32];
    uint8_t temp_block[NOXTLS_AES_BLOCK_LENGTH];
    uint32_t key_len = 0U;
    uint32_t num_blocks = 0U;
    uint32_t last_block_len = 0U;
    const uint32_t block_sz = (uint32_t)NOXTLS_AES_BLOCK_LENGTH;

    /* Determine key length */
    switch (type) {
        case NOXTLS_AES_128_BIT:
#if NOXTLS_FEATURE_AES_128
            key_len = 16U;
            break;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_AES_192_BIT:
#if NOXTLS_FEATURE_AES_192
            key_len = 24U;
            break;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_AES_256_BIT:
#if NOXTLS_FEATURE_AES_256
            key_len = 32U;
            break;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        default:
            return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }

    /* XTS requires IV (tweak) */
    if (iv == NULL) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    /*
     * XTS requires two keys. This implementation accepts a single-size key and
     * uses it for both data and tweak paths (non-standard but workable).
     */
    if (key_len == 16U) {
        noxtls_copy_u8(data_key, sizeof(data_key), key, (size_t)(16U));
        noxtls_copy_u8(tweak_key, sizeof(tweak_key), key, (size_t)(16U));
    } else if (key_len == 24U) {
        noxtls_copy_u8(data_key, sizeof(data_key), key, (size_t)(24U));
        noxtls_copy_u8(tweak_key, sizeof(tweak_key), key, (size_t)(24U));
    } else if (key_len == 32U) {
        noxtls_copy_u8(data_key, sizeof(data_key), key, (size_t)(32U));
        noxtls_copy_u8(tweak_key, sizeof(tweak_key), key, (size_t)(32U));
    } else {
         /* MISRA 15.7: final else path */
        return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }

    /* Encrypt tweak (IV) with the same AES key size selected for data path. */
    (void)noxtls_aes_encrypt_block_internal(tweak_key, iv, tweak, type);

    /* Calculate number of blocks */
    num_blocks = data_len / block_sz;
    last_block_len = data_len % block_sz;

    /* Process full blocks */
    for (cur_block = 0U; cur_block < num_blocks; cur_block += 1U) {
        uint32_t base = (uint32_t)(cur_block * block_sz);

        /* XOR plaintext with tweak */
        for (i = 0U; i < block_sz; i += 1U) {
            temp_block[i] = (uint8_t)(data[base + i] ^ tweak[i]);
        }

        /* Encrypt */
        (void)noxtls_aes_encrypt_block_internal(data_key, temp_block, temp_block, type);

        /* XOR result with tweak */
        for (i = 0U; i < block_sz; i += 1U) {
            output[base + i] = (uint8_t)(temp_block[i] ^ tweak[i]);
        }

        /* Multiply tweak by alpha for next block (except last full before partial) */
        if ((cur_block != (num_blocks - 1U)) || (last_block_len == 0U)) {
            gf128_multiply_alpha(tweak);
        }
    }

    /* Handle partial last block with ciphertext stealing */
    if (last_block_len > 0U) {
        uint8_t last_tweak[NOXTLS_AES_BLOCK_LENGTH];
        uint8_t second_last_block[NOXTLS_AES_BLOCK_LENGTH];

        /* Save second-to-last ciphertext block */
        if (num_blocks > 0U) {
            noxtls_copy_u8(second_last_block, sizeof(second_last_block), &output[(num_blocks - 1U) * block_sz], (size_t)(block_sz));
        }

        /* Multiply tweak by alpha one more time */
        noxtls_copy_u8(last_tweak, sizeof(last_tweak), tweak, (size_t)(block_sz));
        gf128_multiply_alpha(last_tweak);

        /* Encrypt second-to-last plaintext block with new tweak */
        if (num_blocks > 0U) {
            uint32_t prev_base = (uint32_t)((num_blocks - 1U) * block_sz);
            for (i = 0U; i < block_sz; i += 1U) {
                temp_block[i] = (uint8_t)(data[prev_base + i] ^ last_tweak[i]);
            }
            (void)noxtls_aes_encrypt_block_internal(data_key, temp_block, temp_block, type);
            for (i = 0U; i < block_sz; i += 1U) {
                output[prev_base + i] = (uint8_t)(temp_block[i] ^ last_tweak[i]);
            }
        }

        /* Handle last partial block: pad with ciphertext from second-to-last */
        {
            uint32_t partial_base = (uint32_t)(num_blocks * block_sz);
            for (i = 0U; i < last_block_len; i += 1U) {
                temp_block[i] = data[partial_base + i];
            }
            for (i = last_block_len; i < block_sz; i += 1U) {
                if (num_blocks > 0U) {
                    temp_block[i] = second_last_block[i];
                } else {
                    temp_block[i] = 0U;
                }
            }
        }

        /* Encrypt padded block */
        for (i = 0U; i < block_sz; i += 1U) {
            temp_block[i] = (uint8_t)(temp_block[i] ^ last_tweak[i]);
        }
        (void)noxtls_aes_encrypt_block_internal(data_key, temp_block, temp_block, type);
        for (i = 0U; i < block_sz; i += 1U) {
            temp_block[i] = (uint8_t)(temp_block[i] ^ last_tweak[i]);
        }

        /* Output: first part goes to last block position, rest overwrites second-to-last */
        noxtls_copy_u8(&output[num_blocks * block_sz], (size_t)last_block_len, temp_block, (size_t)last_block_len);
        if (num_blocks > 0U) {
            noxtls_copy_u8(&output[((num_blocks - 1U) * block_sz) + last_block_len],
                   (size_t)(block_sz - last_block_len),
                   &temp_block[last_block_len],
                   (size_t)(block_sz - last_block_len));
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_AES_XTS */
