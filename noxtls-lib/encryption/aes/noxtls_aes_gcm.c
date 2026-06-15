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

#if NOXTLS_FEATURE_AES_GCM

/**
 * @brief Increment the counter
 *
 * @param counter is the counter to increment
 *
 * @return None.
 */
static void gcm_inc32(uint8_t counter[16])
{
    uint32_t n = ((uint32_t)counter[12] << 24) |
                 ((uint32_t)counter[13] << 16) |
                 ((uint32_t)counter[14] << 8) |
                 (uint32_t)counter[15];
    n++;
    counter[12] = (uint8_t)(n >> 24);
    counter[13] = (uint8_t)(n >> 16);
    counter[14] = (uint8_t)(n >> 8);
    counter[15] = (uint8_t)n;
}


/**
 * @brief XOR two 16-byte GCM blocks.
 * @param out Output block that receives a XOR b.
 * @param a First input block.
 * @param b Second input block.
 * @return None.
 */
static void gcm_xor(uint8_t out[16], const uint8_t a[16], const uint8_t b[16])
{
    for(int i = 0; i < 16; i++) {
        out[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

/**
 * @brief Shift the vector right
 *
 * @param v is the vector to shift
 *
 * @return None.
 */
static void gcm_shift_right(uint8_t v[16])
{
    uint8_t carry = 0;
    for(int i = 0; i < 16; i++) {
        uint8_t new_carry = (uint8_t)(v[i] & 0x01);
        v[i] = (uint8_t)((v[i] >> 1) | (carry << 7));
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
static void gcm_mul_bitserial(uint8_t x[16], const uint8_t y[16])
{
    uint8_t z[16] = {0};
    uint8_t v[16];
    memcpy(v, y, 16);

    for(int i = 0; i < 128; i++) {
        int byte_idx = i >> 3;
        int bit_idx = 7 - (i & 7);
        if((x[byte_idx] >> bit_idx) & 1) {
            gcm_xor(z, z, v);
        }
        uint8_t lsb = (uint8_t)(v[15] & 1);
        gcm_shift_right(v);
        if(lsb) {
            v[0] ^= 0xE1;
        }
    }
    memcpy(x, z, 16);
}

/**
 * @brief Precompute the tables
 * 
 * @param[in] table The table to precompute.
 * @param[in] h The h value.
 * @return void
 */
static const uint8_t (*gcm_precompute_tables(const uint8_t h[16]))[16][16]
{
    static uint8_t cache_valid;
    static uint8_t cache_h[16];
    static uint8_t table[32][16][16];
    uint8_t basis[16];
    int byte_idx;
    int nibble;

    if(cache_valid != 0U && memcmp(cache_h, h, 16) == 0) {
        return table;
    }

    for(byte_idx = 0; byte_idx < 16; byte_idx++) {
        for(nibble = 0; nibble < 16; nibble++) {
            memset(basis, 0, sizeof(basis));
            basis[byte_idx] = (uint8_t)(nibble << 4);
            memcpy(table[byte_idx * 2][nibble], basis, sizeof(basis));
            gcm_mul_bitserial(table[byte_idx * 2][nibble], h);

            memset(basis, 0, sizeof(basis));
            basis[byte_idx] = (uint8_t)nibble;
            memcpy(table[(byte_idx * 2) + 1][nibble], basis, sizeof(basis));
            gcm_mul_bitserial(table[(byte_idx * 2) + 1][nibble], h);
        }
    }

    memcpy(cache_h, h, sizeof(cache_h));
    cache_valid = 1U;
    return table;
}

/**
 * @brief Multiply the vector
 * 
 * @param[in] x The vector to multiply.
 * @param[in] table The table to multiply.
 * @return void
 */
static void gcm_mul(uint8_t x[16], const uint8_t table[32][16][16])
{
    uint8_t z[16] = {0};
    int byte_idx;

    for(byte_idx = 0; byte_idx < 16; byte_idx++) {
        const uint8_t hi = (uint8_t)(x[byte_idx] >> 4);
        const uint8_t lo = (uint8_t)(x[byte_idx] & 0x0F);
        if(hi != 0U) {
            gcm_xor(z, z, table[byte_idx * 2][hi]);
        }
        if(lo != 0U) {
            gcm_xor(z, z, table[(byte_idx * 2) + 1][lo]);
        }
    }

    memcpy(x, z, sizeof(z));
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
static void ghash_update(uint8_t x[16], const uint8_t table[32][16][16], const uint8_t *data, uint32_t len)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint8_t block[16];
    uint32_t offset = 0;

    while(offset < len) {
        uint32_t take = (len - offset >= 16) ? 16 : (len - offset);
        memset(block, 0, sizeof(block));
        memcpy(block, data + offset, take);
        gcm_xor(x, x, block);
        gcm_mul(x, table);
        offset += take;
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
static void ghash_finalize(uint8_t x[16], const uint8_t table[32][16][16], uint64_t aad_bits, uint64_t data_bits)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint8_t len_block[16];
    memset(len_block, 0, sizeof(len_block));

    len_block[0] = (uint8_t)(aad_bits >> 56);
    len_block[1] = (uint8_t)(aad_bits >> 48);
    len_block[2] = (uint8_t)(aad_bits >> 40);
    len_block[3] = (uint8_t)(aad_bits >> 32);
    len_block[4] = (uint8_t)(aad_bits >> 24);
    len_block[5] = (uint8_t)(aad_bits >> 16);
    len_block[6] = (uint8_t)(aad_bits >> 8);
    len_block[7] = (uint8_t)(aad_bits);

    len_block[8] = (uint8_t)(data_bits >> 56);
    len_block[9] = (uint8_t)(data_bits >> 48);
    len_block[10] = (uint8_t)(data_bits >> 40);
    len_block[11] = (uint8_t)(data_bits >> 32);
    len_block[12] = (uint8_t)(data_bits >> 24);
    len_block[13] = (uint8_t)(data_bits >> 16);
    len_block[14] = (uint8_t)(data_bits >> 8);
    len_block[15] = (uint8_t)(data_bits);

    gcm_xor(x, x, len_block);
    gcm_mul(x, table);
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
static noxtls_return_t aes_block(const noxtls_aes_context_t *ctx, const uint8_t in[16], uint8_t out[16])
{
    uint8_t tmp_in[16];
    memcpy(tmp_in, in, 16);
    return noxtls_aes_encrypt_block_ctx_internal(ctx, tmp_in, out);
}

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
                    const uint8_t nonce[12],
                    const uint8_t *aad, uint32_t aad_len,
                    const uint8_t *plaintext, uint32_t plaintext_len,
                    uint8_t *ciphertext,
                    uint8_t tag[16])
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    noxtls_aes_context_t aes_ctx;
    uint8_t h[16];
    uint8_t j0[16];
    uint8_t ctr[16];
    uint8_t s[16];
    uint8_t x[16];
    const uint8_t (*ghash_table)[16][16];
    uint32_t offset = 0;

    if(key == NULL || nonce == NULL || plaintext == NULL || ciphertext == NULL || tag == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(noxtls_aes_gcm_encrypt_accel_port(key, type, nonce, aad, aad_len, plaintext, plaintext_len, ciphertext, tag) ==
       NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_SUCCESS;
    }

    {
        noxtls_return_t rc;
        memset(&aes_ctx, 0, sizeof(aes_ctx));
        rc = noxtls_aes_prepare_context(&aes_ctx, key, type);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    memset(h, 0, sizeof(h));
    if(aes_block(&aes_ctx, h, h) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    ghash_table = gcm_precompute_tables(h);

    memcpy(j0, nonce, 12);
    j0[12] = 0x00;
    j0[13] = 0x00;
    j0[14] = 0x00;
    j0[15] = 0x01;

    memcpy(ctr, j0, 16);
    gcm_inc32(ctr);

    while(offset < plaintext_len) {
        uint32_t take = (plaintext_len - offset >= 16) ? 16 : (plaintext_len - offset);
        if(aes_block(&aes_ctx, ctr, s) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        for(uint32_t i = 0; i < take; i++) {
            ciphertext[offset + i] = (uint8_t)(plaintext[offset + i] ^ s[i]);
        }
        offset += take;
        gcm_inc32(ctr);
    }

    memset(x, 0, sizeof(x));
    if(aad != NULL && aad_len > 0) {
        ghash_update(x, ghash_table, aad, aad_len);
    }
    ghash_update(x, ghash_table, ciphertext, plaintext_len);
    ghash_finalize(x, ghash_table, (uint64_t)aad_len * 8U, (uint64_t)plaintext_len * 8U);

    if(aes_block(&aes_ctx, j0, s) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    gcm_xor(tag, x, s);

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
                    const uint8_t nonce[12],
                    const uint8_t *aad, uint32_t aad_len,
                    const uint8_t *ciphertext, uint32_t ciphertext_len,
                    const uint8_t tag[16],
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
    const uint8_t (*ghash_table)[16][16];
    uint32_t offset = 0;

    if(key == NULL || nonce == NULL || ciphertext == NULL || plaintext == NULL || tag == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    {
        noxtls_return_t port_rc = noxtls_aes_gcm_decrypt_accel_port(key, type, nonce, aad, aad_len,
                                                                     ciphertext, ciphertext_len, tag, plaintext);
        if(port_rc == NOXTLS_RETURN_SUCCESS || port_rc == NOXTLS_RETURN_BAD_DATA) {
            return port_rc;
        }
    }

    {
        noxtls_return_t rc;
        memset(&aes_ctx, 0, sizeof(aes_ctx));
        rc = noxtls_aes_prepare_context(&aes_ctx, key, type);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    memset(h, 0, sizeof(h));
    if(aes_block(&aes_ctx, h, h) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    ghash_table = gcm_precompute_tables(h);

    memcpy(j0, nonce, 12);
    j0[12] = 0x00;
    j0[13] = 0x00;
    j0[14] = 0x00;
    j0[15] = 0x01;

    memset(x, 0, sizeof(x));
    if(aad != NULL && aad_len > 0) {
        ghash_update(x, ghash_table, aad, aad_len);
    }
    ghash_update(x, ghash_table, ciphertext, ciphertext_len);
    ghash_finalize(x, ghash_table, (uint64_t)aad_len * 8U, (uint64_t)ciphertext_len * 8U);

    if(aes_block(&aes_ctx, j0, s) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    gcm_xor(expected_tag, x, s);

    if(noxtls_secret_memcmp(expected_tag, tag, 16) != 0) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    memcpy(ctr, j0, 16);
    gcm_inc32(ctr);

    while(offset < ciphertext_len) {
        uint32_t take = (ciphertext_len - offset >= 16) ? 16 : (ciphertext_len - offset);
        if(aes_block(&aes_ctx, ctr, s) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        for(uint32_t i = 0; i < take; i++) {
            plaintext[offset + i] = (uint8_t)(ciphertext[offset + i] ^ s[i]);
        }
        offset += take;
        gcm_inc32(ctr);
    }

    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_AES_GCM */
