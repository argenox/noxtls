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
*          as specified by IEEE Std 1619-2007 / NIST SP 800-38E.
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

/** Direction selector for the shared XTS walk. */
#define AES_XTS_DIR_ENCRYPT (0U)
#define AES_XTS_DIR_DECRYPT (1U)

/**
 * @brief Multiply an XTS tweak by alpha (x) in GF(2^128), IEEE 1619-2007 5.2.
 *
 * The tweak is a little-endian 128-bit value: byte 0 holds the least
 * significant bits and bit 7 of byte 15 is the coefficient of x^127. The
 * value is shifted one bit towards byte 15 and, when x^127 was set, reduced
 * with x^128 = x^7 + x^2 + x + 1 (0x87 into byte 0). The reduction is masked
 * rather than branched so the tweak (secret) does not steer control flow.
 *
 * @param block Tweak to update in place.
 */
static void gf128_multiply_alpha(uint8_t block[NOXTLS_AES_BLOCK_LENGTH])
{
    uint32_t i;
    uint32_t carry = 0U;

    for (i = 0U; i < (uint32_t)NOXTLS_AES_BLOCK_LENGTH; i += 1U) {
        uint32_t next_carry = ((uint32_t)block[i] >> 7U) & 1U;
        block[i] = (uint8_t)((((uint32_t)block[i] << 1U) | carry) & 0xFFU);
        carry = next_carry;
    }

    /* carry is 0 or 1: (0U - carry) is all-zeros or all-ones. */
    block[0] ^= (uint8_t)((0U - carry) & 0x87U);
}

/**
 * @brief Validate the AES key size selector for XTS.
 *
 * Key1 and Key2 are each one AES key of the selected size.
 *
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NOT_SUPPORTED for a disabled
 *         key size or NOXTLS_RETURN_INVALID_KEY_SIZE for an unknown selector.
 */
static noxtls_return_t aes_xts_check_type(noxtls_aes_type_t type)
{
    switch (type) {
        case NOXTLS_AES_128_BIT:
#if NOXTLS_FEATURE_AES_128
            return NOXTLS_RETURN_SUCCESS;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_AES_192_BIT:
#if NOXTLS_FEATURE_AES_192
            return NOXTLS_RETURN_SUCCESS;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_AES_256_BIT:
#if NOXTLS_FEATURE_AES_256
            return NOXTLS_RETURN_SUCCESS;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        default:
            return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }
}

/**
 * @brief Process one XTS block: out = E/D_K1(in ^ T) ^ T.
 *
 * @param key Data key (Key1).
 * @param tweak Current tweak T.
 * @param in Input block (may alias @p out).
 * @param out Output block.
 * @param type AES key size selector.
 * @param dir AES_XTS_DIR_ENCRYPT or AES_XTS_DIR_DECRYPT.
 * @return NOXTLS_RETURN_SUCCESS or the block cipher error.
 */
static noxtls_return_t aes_xts_block(const uint8_t *key,
                                     const uint8_t tweak[NOXTLS_AES_BLOCK_LENGTH],
                                     const uint8_t *in,
                                     uint8_t *out,
                                     noxtls_aes_type_t type,
                                     uint32_t dir)
{
    noxtls_return_t rc;
    uint8_t x[NOXTLS_AES_BLOCK_LENGTH];
    uint32_t i;

    for (i = 0U; i < (uint32_t)NOXTLS_AES_BLOCK_LENGTH; i += 1U) {
        x[i] = (uint8_t)(in[i] ^ tweak[i]);
    }
    if (dir == AES_XTS_DIR_DECRYPT) {
        rc = noxtls_aes_decrypt_block_internal(key, x, x, type);
    } else {
        rc = noxtls_aes_encrypt_block_internal(key, x, x, type);
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        for (i = 0U; i < (uint32_t)NOXTLS_AES_BLOCK_LENGTH; i += 1U) {
            out[i] = (uint8_t)(x[i] ^ tweak[i]);
        }
    }
    noxtls_secure_zero(x, sizeof(x));
    return rc;
}

/**
 * @brief Shared IEEE 1619 XTS-AES walk (encrypt or decrypt).
 *
 * Data unit of m = data_len / 16 full blocks plus a b = data_len % 16 byte
 * tail. Block j uses tweak T_j = E_K2(i) * alpha^j. When b != 0 the last two
 * blocks use ciphertext stealing (IEEE 1619-2007 5.3.2 / 5.4.2):
 *   encrypt: CC = XTS(K1, P_{m-1}, T_{m-1}); C_m = CC[0..b);
 *            C_{m-1} = XTS(K1, P_m || CC[b..16), T_m)
 *   decrypt: PP = XTS^-1(K1, C_{m-1}, T_m); P_m = PP[0..b);
 *            P_{m-1} = XTS^-1(K1, C_m || PP[b..16), T_{m-1})
 * Input and output may be the same buffer.
 */
static noxtls_return_t aes_xts_crypt(const uint8_t *data_key,
                                     const uint8_t *tweak_key,
                                     const uint8_t *data,
                                     uint32_t data_len,
                                     const uint8_t *iv,
                                     uint8_t *output,
                                     noxtls_aes_type_t type,
                                     uint32_t dir)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint8_t tweak[NOXTLS_AES_BLOCK_LENGTH];
    uint8_t prev_tweak[NOXTLS_AES_BLOCK_LENGTH];
    uint8_t steal[NOXTLS_AES_BLOCK_LENGTH];
    uint8_t last[NOXTLS_AES_BLOCK_LENGTH];
    uint32_t num_blocks = 0U;
    uint32_t full_blocks = 0U;
    uint32_t tail_len = 0U;
    uint32_t cur_block = 0U;
    uint32_t i = 0U;
    const uint32_t block_sz = (uint32_t)NOXTLS_AES_BLOCK_LENGTH;

    if ((data_key == NULL) || (tweak_key == NULL) || (data == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    rc = aes_xts_check_type(type);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    /* XTS requires the 128-bit tweak (data unit sequence number). */
    if (iv == NULL) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    /* IEEE 1619: a data unit is at least one full block (128 bits). */
    if (data_len < block_sz) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }

    num_blocks = data_len / block_sz;
    tail_len = data_len % block_sz;
    full_blocks = (tail_len == 0U) ? num_blocks : (num_blocks - 1U);

    /* T_0 = E_K2(i) */
    rc = noxtls_aes_encrypt_block_internal(tweak_key, iv, tweak, type);

    for (cur_block = 0U; (rc == NOXTLS_RETURN_SUCCESS) && (cur_block < full_blocks); cur_block += 1U) {
        uint32_t base = cur_block * block_sz;
        rc = aes_xts_block(data_key, tweak, &data[base], &output[base], type, dir);
        gf128_multiply_alpha(tweak);
    }

    if ((rc == NOXTLS_RETURN_SUCCESS) && (tail_len != 0U)) {
        /* Here tweak == T_{m-1} (index of the last full block, num_blocks - 1). */
        uint32_t prev_base = (num_blocks - 1U) * block_sz;
        uint32_t tail_base = num_blocks * block_sz;

        noxtls_copy_u8(prev_tweak, sizeof(prev_tweak), tweak, (size_t)block_sz);
        gf128_multiply_alpha(tweak); /* tweak == T_m */

        if (dir == AES_XTS_DIR_DECRYPT) {
            /* PP = XTS^-1(K1, C_{m-1}, T_m) */
            rc = aes_xts_block(data_key, tweak, &data[prev_base], steal, type, dir);
        } else {
            /* CC = XTS(K1, P_{m-1}, T_{m-1}) */
            rc = aes_xts_block(data_key, prev_tweak, &data[prev_base], steal, type, dir);
        }

        if (rc == NOXTLS_RETURN_SUCCESS) {
            /* Read the short input block before the output (it may alias) is written. */
            for (i = 0U; i < tail_len; i += 1U) {
                last[i] = data[tail_base + i];
            }
            for (i = tail_len; i < block_sz; i += 1U) {
                last[i] = steal[i];
            }
            /* Short output block = first tail_len bytes of the stolen block. */
            for (i = 0U; i < tail_len; i += 1U) {
                output[tail_base + i] = steal[i];
            }
            if (dir == AES_XTS_DIR_DECRYPT) {
                /* P_{m-1} = XTS^-1(K1, C_m || PP[b..16), T_{m-1}) */
                rc = aes_xts_block(data_key, prev_tweak, last, &output[prev_base], type, dir);
            } else {
                /* C_{m-1} = XTS(K1, P_m || CC[b..16), T_m) */
                rc = aes_xts_block(data_key, tweak, last, &output[prev_base], type, dir);
            }
        }
    }

    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(output, (size_t)data_len);
    }
    noxtls_secure_zero(tweak, sizeof(tweak));
    noxtls_secure_zero(prev_tweak, sizeof(prev_tweak));
    noxtls_secure_zero(steal, sizeof(steal));
    noxtls_secure_zero(last, sizeof(last));
    return rc;
}

/**
 * @brief XTS-AES encryption with independent data (Key1) and tweak (Key2) keys.
 */
noxtls_return_t noxtls_aes_xts_encrypt(const uint8_t *data_key,
                                       const uint8_t *tweak_key,
                                       const uint8_t *data,
                                       uint32_t data_len,
                                       const uint8_t *tweak,
                                       uint8_t *output,
                                       noxtls_aes_type_t type)
{
    return aes_xts_crypt(data_key, tweak_key, data, data_len, tweak, output, type, AES_XTS_DIR_ENCRYPT);
}

/**
 * @brief XTS-AES decryption with independent data (Key1) and tweak (Key2) keys.
 */
noxtls_return_t noxtls_aes_xts_decrypt(const uint8_t *data_key,
                                       const uint8_t *tweak_key,
                                       const uint8_t *data,
                                       uint32_t data_len,
                                       const uint8_t *tweak,
                                       uint8_t *output,
                                       noxtls_aes_type_t type)
{
    return aes_xts_crypt(data_key, tweak_key, data, data_len, tweak, output, type, AES_XTS_DIR_DECRYPT);
}

/**
 * @brief AES Encrypt in XTS Mode (single key used as both Key1 and Key2).
 */
noxtls_return_t noxtls_aes_encrypt_xts(const uint8_t* key,
                    const uint8_t* data,
                    uint32_t data_len,
                    const uint8_t * iv,
                    uint8_t* output,
                    noxtls_aes_type_t type)
{
    return aes_xts_crypt(key, key, data, data_len, iv, output, type, AES_XTS_DIR_ENCRYPT);
}

/**
 * @brief AES Decrypt in XTS Mode (single key used as both Key1 and Key2).
 */
noxtls_return_t noxtls_aes_decrypt_xts(const uint8_t* key,
                    const uint8_t* data,
                    uint32_t data_len,
                    const uint8_t * iv,
                    uint8_t* output,
                    noxtls_aes_type_t type)
{
    return aes_xts_crypt(key, key, data, data_len, iv, output, type, AES_XTS_DIR_DECRYPT);
}

#endif /* NOXTLS_FEATURE_AES_XTS */
