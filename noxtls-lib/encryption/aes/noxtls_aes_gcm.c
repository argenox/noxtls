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
* File:    noxtls_aes_gcm.c
* Summary: AES-GCM mode implementation
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */

#include <string.h>
#include "noxtls_aes_gcm.h"
#include "noxtls_aes_internal.h"
#include "noxtls_aes_accel.h"
#include "noxtls_common.h"
#include "common/noxtls_ct.h"
#include "noxtls_ct.h"

#if NOXTLS_FEATURE_AES_GCM

/**
 * @brief Increment the counter
 *
 * @param counter is the counter to increment
 *
 * @return None.
 */
static void gcm_inc32(uint8_t *counter)
{
    uint32_t n = (((uint32_t)counter[12]) << 24U)
               | (((uint32_t)counter[13]) << 16U)
               | (((uint32_t)counter[14]) << 8U)
               | ((uint32_t)counter[15]);
    n += 1U;
    counter[12] = (uint8_t)(n >> 24U);
    counter[13] = (uint8_t)(n >> 16U);
    counter[14] = (uint8_t)(n >> 8U);
    counter[15] = (uint8_t)n;
}

static void gcm_xor(uint8_t *out, const uint8_t *a, const uint8_t *b)
{
    uint32_t i = 0U;
    for (i = 0U; i < 16U; i += 1U) {
        out[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

static void gcm_xor_inplace(uint8_t *out, const uint8_t *in)
{
    uint32_t i = 0U;
    for (i = 0U; i < 16U; i += 1U) {
        out[i] = (uint8_t)(out[i] ^ in[i]);
    }
}

static void gcm_xor_stream_block(uint8_t *out, const uint8_t *in, const uint8_t *stream)
{
    uint32_t i = 0U;
    for (i = 0U; i < 16U; i += 1U) {
        out[i] = (uint8_t)(in[i] ^ stream[i]);
    }
}

static void gcm_xor_stream_partial(uint8_t *out, const uint8_t *in, const uint8_t *stream, uint32_t len)
{
    uint32_t i = 0U;
    for (i = 0U; i < len; i += 1U) {
        out[i] = (uint8_t)(in[i] ^ stream[i]);
    }
}

/**
 * @brief Shift the vector right
 *
 * @param v is the vector to shift
 *
 * @return None.
 */
static void gcm_shift_right(uint8_t *v)
{
    uint8_t carry = 0U;
    uint32_t i = 0U;
    for (i = 0U; i < 16U; i += 1U) {
        uint8_t new_carry = (uint8_t)(v[i] & 0x01U);
        v[i] = (uint8_t)(((uint32_t)(uint32_t)v[i] >> 1U) | (((uint32_t)carry) << 7U));
        carry = new_carry;
    }
}

/**
 * @brief Multiply the vector
 *
 * @param x is the vector to multiply
 * @param y is the vector to multiply
 *
 * @return None.
 */
static void gcm_mul_bitserial(uint8_t *x, const uint8_t *y)
{
    uint8_t z[16] = {0};
    uint8_t v[16];
    uint32_t i = 0U;
    noxtls_copy_u8(v, sizeof(v), y, 16U);

    {
    static const uint8_t s_msb8[8] = {
        0x80U, 0x40U, 0x20U, 0x10U, 0x08U, 0x04U, 0x02U, 0x01U
    };
    for (i = 0U; i < 128U; i += 1U) {
        uint32_t byte_idx = (uint32_t)(i >> 3U);
        /* s_msb8[0]=0x80 .. s_msb8[7]=0x01 matches MSB-first scan order. */
        if ((x[byte_idx] & s_msb8[i & 7U]) != 0U) {
            (void)gcm_xor(z, z, v);
        }
        {
            uint8_t lsb = (uint8_t)(v[15] & 1U);
            (void)gcm_shift_right(v);
            if (lsb != 0U) {
                v[0] ^= 0xE1U;
            }
        }
    }
    }
    noxtls_copy_u8(x, 16U, z, 16U);
}

/**
 * @brief Precompute the tables
 * 
 * @param[in] table The table to precompute.
 * @param[in] h The h value.
 * @return void
 */
static void gcm_table_store(uint32_t *dst, const uint8_t *src)
{
    dst[0] = ((uint32_t)src[0])
           | (((uint32_t)src[1]) << 8U)
           | (((uint32_t)src[2]) << 16U)
           | (((uint32_t)src[3]) << 24U);
    dst[1] = ((uint32_t)src[4])
           | (((uint32_t)src[5]) << 8U)
           | (((uint32_t)src[6]) << 16U)
           | (((uint32_t)src[7]) << 24U);
    dst[2] = ((uint32_t)src[8])
           | (((uint32_t)src[9]) << 8U)
           | (((uint32_t)src[10]) << 16U)
           | (((uint32_t)src[11]) << 24U);
    dst[3] = ((uint32_t)src[12])
           | (((uint32_t)src[13]) << 8U)
           | (((uint32_t)src[14]) << 16U)
           | (((uint32_t)src[15]) << 24U);
}

static const uint32_t (*gcm_precompute_tables(const uint8_t *h))[16][4]
{
    static uint8_t cache_valid = 0U;
    static uint8_t cache_h[16];
    static uint32_t table[32][16][4];
    uint8_t basis[16];
    uint8_t product[16];
    uint8_t h_local[16];
    uint32_t byte_idx = 0U;
    uint32_t nibble = 0U;

    noxtls_copy_u8(h_local, sizeof(h_local), (const uint8_t *)(h), sizeof(h_local));

    if (cache_valid != 0U) {
        if (memcmp(cache_h, h_local, sizeof(cache_h)) == 0) {
            return (const uint32_t (*)[16][4])(const void *)table;
        }
    }

    for (byte_idx = 0U; byte_idx < 16U; byte_idx += 1U) {
        for (nibble = 0U; nibble < 16U; nibble += 1U) {
            noxtls_secure_zero((basis), sizeof(basis));
            if (byte_idx < 16U) {
                basis[byte_idx] = (uint8_t)((nibble << 4U) & 0xFFU);
            }
            noxtls_copy_u8(product, sizeof(product), (const uint8_t *)(basis), sizeof(product));
            (void)gcm_mul_bitserial(product, h_local);
            (void)gcm_table_store(table[(size_t)byte_idx * 2U][nibble], product);

            noxtls_secure_zero((basis), sizeof(basis));
            if (byte_idx < 16U) {
                basis[byte_idx] = (uint8_t)(nibble & 0x0FU);
            }
            noxtls_copy_u8(product, sizeof(product), (const uint8_t *)(basis), sizeof(product));
            (void)gcm_mul_bitserial(product, h_local);
            (void)gcm_table_store(table[((size_t)byte_idx * 2U) + 1U][nibble], product);
        }
    }

    noxtls_copy_u8(cache_h, sizeof(cache_h), (const uint8_t *)(h_local), sizeof(cache_h));
    cache_valid = 1U;
    return (const uint32_t (*)[16][4])(const void *)table;
}

/**
 * @brief Multiply the vector
 * 
 * @param[in] x The vector to multiply.
 * @param[in] table The table to multiply.
 * @return void
 */
static void gcm_mul(uint8_t *x, const uint32_t (*table)[16][4])
{
    uint32_t z0 = 0U;
    uint32_t z1 = 0U;
    uint32_t z2 = 0U;
    uint32_t z3 = 0U;
    uint32_t byte_idx = 0U;

    for (byte_idx = 0U; byte_idx < 16U; byte_idx += 1U) {
        const uint8_t hi = (uint8_t)(((uint32_t)x[byte_idx]) >> 4U);
        const uint8_t lo = (uint8_t)(x[byte_idx] & 0x0FU);
        if (hi != 0U) {
            const uint32_t *t = table[(size_t)byte_idx * 2U][hi];
            z0 ^= t[0];
            z1 ^= t[1];
            z2 ^= t[2];
            z3 ^= t[3];
        }
        if (lo != 0U) {
            const uint32_t *t = table[((size_t)byte_idx * 2U) + 1U][lo];
            z0 ^= t[0];
            z1 ^= t[1];
            z2 ^= t[2];
            z3 ^= t[3];
        }
    }

    x[0] = (uint8_t)(z0 & 0xFFU);
    x[1] = (uint8_t)((z0 >> 8U) & 0xFFU);
    x[2] = (uint8_t)((z0 >> 16U) & 0xFFU);
    x[3] = (uint8_t)((z0 >> 24U) & 0xFFU);
    x[4] = (uint8_t)(z1 & 0xFFU);
    x[5] = (uint8_t)((z1 >> 8U) & 0xFFU);
    x[6] = (uint8_t)((z1 >> 16U) & 0xFFU);
    x[7] = (uint8_t)((z1 >> 24U) & 0xFFU);
    x[8] = (uint8_t)(z2 & 0xFFU);
    x[9] = (uint8_t)((z2 >> 8U) & 0xFFU);
    x[10] = (uint8_t)((z2 >> 16U) & 0xFFU);
    x[11] = (uint8_t)((z2 >> 24U) & 0xFFU);
    x[12] = (uint8_t)(z3 & 0xFFU);
    x[13] = (uint8_t)((z3 >> 8U) & 0xFFU);
    x[14] = (uint8_t)((z3 >> 16U) & 0xFFU);
    x[15] = (uint8_t)((z3 >> 24U) & 0xFFU);
}

/**
 * @brief Update the hash
 *
 * @param x is the hash to update
 * @param h is the hash to update
 * @param data is the data to update the hash with
 * @param len is the length of the data
 *
 * @return None.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static void ghash_update(uint8_t *x, const uint32_t (*table)[16][4], const uint8_t *data, uint32_t len)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint8_t block[16];
    uint32_t offset = 0U;

    while ((len - offset) >= 16U) {
        uint8_t full[16];
        noxtls_copy_u8(full, sizeof(full), &data[offset], sizeof(full));
        (void)gcm_xor_inplace(x, full);
        (void)gcm_mul(x, table);
        offset += 16U;
    }

    if (offset < len) {
        uint32_t take = (uint32_t)(len - offset);
        noxtls_secure_zero((block), sizeof(block));
        noxtls_copy_u8(block, sizeof(block), &data[offset], (size_t)take);
        (void)gcm_xor_inplace(x, block);
        (void)gcm_mul(x, table);
    }
}

/**
 * @brief Finalize the hash
 *
 * @param x is the hash to finalize
 * @param h is the hash to finalize
 * @param aad_bits is the length of the AAD
 * @param data_bits is the length of the data
 *
 * @return None.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static void ghash_finalize(uint8_t *x, const uint32_t (*table)[16][4], uint64_t aad_bits, uint64_t data_bits)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint8_t len_block[16];
    noxtls_secure_zero((len_block), sizeof(len_block));

    len_block[0] = (uint8_t)(aad_bits >> 56U);
    len_block[1] = (uint8_t)(aad_bits >> 48U);
    len_block[2] = (uint8_t)(aad_bits >> 40U);
    len_block[3] = (uint8_t)(aad_bits >> 32U);
    len_block[4] = (uint8_t)(aad_bits >> 24U);
    len_block[5] = (uint8_t)(aad_bits >> 16U);
    len_block[6] = (uint8_t)(aad_bits >> 8U);
    len_block[7] = (uint8_t)aad_bits;

    len_block[8] = (uint8_t)(data_bits >> 56U);
    len_block[9] = (uint8_t)(data_bits >> 48U);
    len_block[10] = (uint8_t)(data_bits >> 40U);
    len_block[11] = (uint8_t)(data_bits >> 32U);
    len_block[12] = (uint8_t)(data_bits >> 24U);
    len_block[13] = (uint8_t)(data_bits >> 16U);
    len_block[14] = (uint8_t)(data_bits >> 8U);
    len_block[15] = (uint8_t)data_bits;

    (void)gcm_xor_inplace(x, len_block);
    (void)gcm_mul(x, table);
}

/**
 * @brief Encrypt the block
 *
 * @param key is the key to use
 * @param type is the type of the key
 * @param in is the input to encrypt
 * @param out is the output to encrypt
 *
 * @return None.
 */
static noxtls_return_t aes_block(const noxtls_aes_context_t *ctx, const uint8_t *in, uint8_t *out) { return noxtls_aes_encrypt_block_ctx_software_internal(ctx, in, out); }

/**
 * @brief Encrypt the data
 *
 * @param key is the key to use
 * @param type is the type of the key
 * @param nonce is the nonce to use
 * @param aad is the AAD to use
 * @param aad_len is the length of the AAD
 * @param plaintext is the plaintext to encrypt
 * @param plaintext_len is the length of the plaintext
 * @param ciphertext is the ciphertext to encrypt
 * @param tag is the tag to use
 *
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_* on failure
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
noxtls_return_t noxtls_aes_gcm_encrypt(const uint8_t *key, noxtls_aes_type_t type,
                    const uint8_t *nonce,
                    const uint8_t *aad, uint32_t aad_len,
                    const uint8_t *plaintext, uint32_t plaintext_len,
                    uint8_t *ciphertext,
                    uint8_t *tag)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    noxtls_aes_context_t aes_ctx;
    uint8_t h[16];
    uint8_t j0[16];
    uint8_t ctr[16];
    uint8_t s[16];
    uint8_t x[16];
    const uint32_t (*ghash_table)[16][4];
    uint32_t offset = 0U;

    if ((key == NULL) || (nonce == NULL) || (plaintext == NULL) || (ciphertext == NULL) || (tag == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if (noxtls_aes_gcm_encrypt_accel_port(key, type, nonce, aad, aad_len, plaintext, plaintext_len, ciphertext, tag) ==
       NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_SUCCESS;
    }

    {
        noxtls_return_t rc = NOXTLS_RETURN_FAILED;
        noxtls_secure_zero(&aes_ctx, sizeof(aes_ctx));
        rc = noxtls_aes_prepare_context(&aes_ctx, key, type);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    noxtls_secure_zero((h), sizeof(h));
    if (aes_block(&aes_ctx, h, h) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    ghash_table = gcm_precompute_tables(h);

    noxtls_copy_u8(j0, sizeof(j0), nonce, 12U);
    j0[12] = 0x00U;
    j0[13] = 0x00U;
    j0[14] = 0x00U;
    j0[15] = 0x01U;

    noxtls_copy_u8(ctr, sizeof(ctr), j0, 16U);
    (void)gcm_inc32(ctr);

    noxtls_secure_zero((x), sizeof(x));
    if ((aad != NULL) && (aad_len > 0U)) {
        ghash_update(x, ghash_table, aad, aad_len);
    }

    while (offset < plaintext_len) {
        uint32_t remain = (uint32_t)(plaintext_len - offset);
        uint32_t take = (uint32_t)((remain >= 16U) ? 16U : remain);
        if (aes_block(&aes_ctx, ctr, s) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        if (take == 16U) {
            uint8_t in_blk[16];
            uint8_t out_blk[16];
            noxtls_copy_u8(in_blk, sizeof(in_blk), &plaintext[offset], 16U);
            (void)gcm_xor_stream_block(out_blk, in_blk, s);
            noxtls_copy_u8(&ciphertext[offset], 16U, out_blk, 16U);
            (void)gcm_xor_inplace(x, out_blk);
            (void)gcm_mul(x, ghash_table);
        } else {
            uint8_t block[16] = {0};
            (void)gcm_xor_stream_partial(&ciphertext[offset], &plaintext[offset], s, take);
            noxtls_copy_u8(block, sizeof(block), &ciphertext[offset], (size_t)take);
            (void)gcm_xor_inplace(x, block);
            (void)gcm_mul(x, ghash_table);
        }
        offset += take;
        (void)gcm_inc32(ctr);
    }

    (void)ghash_finalize(x, ghash_table, ((uint64_t)aad_len) * 8U, ((uint64_t)plaintext_len) * 8U);

    if (aes_block(&aes_ctx, j0, s) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    (void)gcm_xor(tag, x, s);

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Decrypt the data
 *
 * @param key is the key to use
 * @param type is the type of the key
 * @param nonce is the nonce to use
 * @param aad is the AAD to use
 * @param aad_len is the length of the AAD
 * @param ciphertext is the ciphertext to decrypt
 * @param ciphertext_len is the length of the ciphertext
 * @param tag is the tag to use
 * @param plaintext is the plaintext to decrypt
 *
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_BAD_DATA on auth failure
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
noxtls_return_t noxtls_aes_gcm_decrypt(const uint8_t *key, noxtls_aes_type_t type,
                    const uint8_t *nonce,
                    const uint8_t *aad, uint32_t aad_len,
                    const uint8_t *ciphertext, uint32_t ciphertext_len,
                    const uint8_t *tag,
                    uint8_t *plaintext)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    noxtls_aes_context_t aes_ctx;
    uint8_t h[16];
    uint8_t j0[16];
    uint8_t ctr[16];
    uint8_t s[16];
    uint8_t x[16];
    uint8_t expected_tag[16];
    const uint32_t (*ghash_table)[16][4];
    uint32_t offset = 0U;

    if ((key == NULL) || (nonce == NULL) || (ciphertext == NULL) || (plaintext == NULL) || (tag == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    {
        noxtls_return_t port_rc = noxtls_aes_gcm_decrypt_accel_port(key, type, nonce, aad, aad_len,
                                                                     ciphertext, ciphertext_len, tag, plaintext);
        if ((port_rc == NOXTLS_RETURN_SUCCESS) || (port_rc == NOXTLS_RETURN_BAD_DATA)) {
            return port_rc;
        }
    }

    {
        noxtls_return_t rc = NOXTLS_RETURN_FAILED;
        noxtls_secure_zero(&aes_ctx, sizeof(aes_ctx));
        rc = noxtls_aes_prepare_context(&aes_ctx, key, type);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    noxtls_secure_zero((h), sizeof(h));
    if (aes_block(&aes_ctx, h, h) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    ghash_table = gcm_precompute_tables(h);

    noxtls_copy_u8(j0, sizeof(j0), nonce, 12U);
    j0[12] = 0x00U;
    j0[13] = 0x00U;
    j0[14] = 0x00U;
    j0[15] = 0x01U;

    noxtls_secure_zero((x), sizeof(x));
    if ((aad != NULL) && (aad_len > 0U)) {
        ghash_update(x, ghash_table, aad, aad_len);
    }
    ghash_update(x, ghash_table, ciphertext, ciphertext_len);
    (void)ghash_finalize(x, ghash_table, ((uint64_t)aad_len) * 8U, ((uint64_t)ciphertext_len) * 8U);

    if (aes_block(&aes_ctx, j0, s) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    (void)gcm_xor(expected_tag, x, s);

    if (noxtls_secret_memcmp(expected_tag, tag, (size_t)(16)) != 0) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    noxtls_copy_u8(ctr, sizeof(ctr), j0, 16U);
    (void)gcm_inc32(ctr);

    while (offset < ciphertext_len) {
        uint32_t remain = (uint32_t)(ciphertext_len - offset);
        uint32_t take = (uint32_t)((remain >= 16U) ? 16U : remain);
        if (aes_block(&aes_ctx, ctr, s) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        if (take == 16U) {
            uint8_t in_blk[16];
            uint8_t out_blk[16];
            noxtls_copy_u8(in_blk, sizeof(in_blk), &ciphertext[offset], 16U);
            (void)gcm_xor_stream_block(out_blk, in_blk, s);
            noxtls_copy_u8(&plaintext[offset], 16U, out_blk, 16U);
        } else {
            (void)gcm_xor_stream_partial(&plaintext[offset], &ciphertext[offset], s, take);
        }
        offset += take;
        (void)gcm_inc32(ctr);
    }

    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_AES_GCM */
