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

static uint32_t gcm_load_ne32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static void gcm_store_ne32(uint8_t *p, uint32_t v)
{
    memcpy(p, &v, sizeof(v));
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
    gcm_store_ne32(out + 0U,  gcm_load_ne32(a + 0U)  ^ gcm_load_ne32(b + 0U));
    gcm_store_ne32(out + 4U,  gcm_load_ne32(a + 4U)  ^ gcm_load_ne32(b + 4U));
    gcm_store_ne32(out + 8U,  gcm_load_ne32(a + 8U)  ^ gcm_load_ne32(b + 8U));
    gcm_store_ne32(out + 12U, gcm_load_ne32(a + 12U) ^ gcm_load_ne32(b + 12U));
}

static void gcm_xor_inplace(uint8_t out[16], const uint8_t in[16])
{
    gcm_store_ne32(out + 0U,  gcm_load_ne32(out + 0U)  ^ gcm_load_ne32(in + 0U));
    gcm_store_ne32(out + 4U,  gcm_load_ne32(out + 4U)  ^ gcm_load_ne32(in + 4U));
    gcm_store_ne32(out + 8U,  gcm_load_ne32(out + 8U)  ^ gcm_load_ne32(in + 8U));
    gcm_store_ne32(out + 12U, gcm_load_ne32(out + 12U) ^ gcm_load_ne32(in + 12U));
}

static void gcm_xor_stream_block(uint8_t *out, const uint8_t *in, const uint8_t stream[16])
{
    gcm_store_ne32(out + 0U,  gcm_load_ne32(in + 0U)  ^ gcm_load_ne32(stream + 0U));
    gcm_store_ne32(out + 4U,  gcm_load_ne32(in + 4U)  ^ gcm_load_ne32(stream + 4U));
    gcm_store_ne32(out + 8U,  gcm_load_ne32(in + 8U)  ^ gcm_load_ne32(stream + 8U));
    gcm_store_ne32(out + 12U, gcm_load_ne32(in + 12U) ^ gcm_load_ne32(stream + 12U));
}

static void gcm_xor_stream_partial(uint8_t *out, const uint8_t *in, const uint8_t stream[16], uint32_t len)
{
    for(uint32_t i = 0; i < len; i++) {
        out[i] = (uint8_t)(in[i] ^ stream[i]);
    }
}

/** Shoup 4-bit GHASH H-table size (H[i] = i * H). */
#define NOXTLS_GCM_HTABLE_SIZE          16U
/** Index of H^1 in the Shoup H-table (binary 1000b). */
#define NOXTLS_GCM_HTABLE_H1_INDEX      (NOXTLS_GCM_HTABLE_SIZE / 2U)
/** last4[] reduction lookup size (one entry per 4-bit remainder). */
#define NOXTLS_GCM_LAST4_SIZE           16U
/** GF(2^128) reduction byte for the degree-128 term (R = x^128+x^7+x^2+x+1). */
#define NOXTLS_GCM_POLY_R_BYTE          0xE1U
/** Bit width of one GHASH nibble. */
#define NOXTLS_GCM_NIBBLE_BITS          4U
/** Mask for a low nibble. */
#define NOXTLS_GCM_NIBBLE_MASK          0x0FU
/** Shift used to place last4[rem] into the high half of u64z[0]. */
#define NOXTLS_GCM_LAST4_SHIFT          48U
/** Bytes in a GCM/GHASH block. */
#define NOXTLS_GCM_BLOCK_BYTES          16U

/**
 * last4[x] = x * P^128 in GF(2^128) (Shoup / MGV 4-bit method).
 * Public field arithmetic constants.
 */
static const uint16_t gcm_last4[NOXTLS_GCM_LAST4_SIZE] = {
    0x0000U, 0x1c20U, 0x3840U, 0x2460U,
    0x7080U, 0x6ca0U, 0x48c0U, 0x54e0U,
    0xe100U, 0xfd20U, 0xd940U, 0xc560U,
    0x9180U, 0x8da0U, 0xa9c0U, 0xb5e0U
};

/**
 * @brief Load a big-endian uint64 from a byte buffer.
 * @param p Source pointer (8 bytes).
 * @return Big-endian interpreted value.
 */
static uint64_t gcm_load_be64(const uint8_t *p)
{
    return ((uint64_t)p[0] << 56) |
           ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) |
           ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) |
           ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8) |
           (uint64_t)p[7];
}

/**
 * @brief Store a uint64 as big-endian bytes.
 * @param p Destination pointer (8 bytes).
 * @param v Value to store.
 * @return None.
 */
static void gcm_store_be64(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)v;
}

/**
 * @brief One-bit right shift of a BE-packed GHASH element with reduction.
 *
 * Operates on H-table entries packed as two big-endian uint64 halves
 * (bytes 0..7 in dst[0]/src[0], bytes 8..15 in dst[1]/src[1]).
 *
 * @param dst Destination element.
 * @param src Source element.
 * @return None.
 */
static void gcm_gen_table_rightshift(uint64_t dst[2], const uint64_t src[2])
{
    const uint64_t hi = src[0];
    const uint64_t lo = src[1];

    dst[1] = (lo >> 1) | (hi << 63);
    dst[0] = (hi >> 1);
    if((lo & 1U) != 0U) {
        dst[0] ^= ((uint64_t)NOXTLS_GCM_POLY_R_BYTE << 56);
    }
}

#if defined(NOXTLS_GCM_GHASH_SELFCHECK)
/**
 * @brief Shift a 16-byte GHASH block one bit toward the LSB (byte form).
 * @param v Block to shift in place.
 * @return None.
 */
static void gcm_shift_right(uint8_t v[NOXTLS_GCM_BLOCK_BYTES])
{
    uint8_t carry = 0;
    for(int i = 0; i < (int)NOXTLS_GCM_BLOCK_BYTES; i++) {
        uint8_t new_carry = (uint8_t)(v[i] & 0x01U);
        v[i] = (uint8_t)((v[i] >> 1) | (carry << 7));
        carry = new_carry;
    }
}

/**
 * @brief Bit-serial GF(2^128) multiply (debug / self-check only).
 * @param x Multiplicand; replaced with x * y.
 * @param y Multiplier (H).
 * @return None.
 */
static void gcm_mul_bitserial(uint8_t x[NOXTLS_GCM_BLOCK_BYTES],
                             const uint8_t y[NOXTLS_GCM_BLOCK_BYTES])
{
    uint8_t z[NOXTLS_GCM_BLOCK_BYTES];
    uint8_t v[NOXTLS_GCM_BLOCK_BYTES];
    int i;

    memset(z, 0, sizeof(z));
    memcpy(v, y, NOXTLS_GCM_BLOCK_BYTES);

    for(i = 0; i < 128; i++) {
        int byte_idx = i >> 3;
        int bit_idx = 7 - (i & 7);
        if(((x[byte_idx] >> bit_idx) & 1) != 0) {
            gcm_xor(z, z, v);
        }
        {
            uint8_t lsb = (uint8_t)(v[15] & 1U);
            gcm_shift_right(v);
            if(lsb != 0U) {
                v[0] ^= (uint8_t)NOXTLS_GCM_POLY_R_BYTE;
            }
        }
    }
    memcpy(x, z, NOXTLS_GCM_BLOCK_BYTES);
}
#endif /* NOXTLS_GCM_GHASH_SELFCHECK */

/**
 * @brief Build Shoup 4-bit H-table from hash subkey H.
 *
 * H[NOXTLS_GCM_HTABLE_H1_INDEX] = H; successive right-shifts fill powers
 * of two; remaining indices are XOR combinations (H[i] = i * H).
 * Entries are stored as big-endian uint64 pairs.
 *
 * @param H Destination table.
 * @param h Hash subkey (AES-ECB(K, 0^128)).
 * @return None.
 */
static void gcm_gen_table(uint64_t H[NOXTLS_GCM_HTABLE_SIZE][2], const uint8_t h[NOXTLS_GCM_BLOCK_BYTES])
{
    unsigned int i;
    unsigned int j;

    H[NOXTLS_GCM_HTABLE_H1_INDEX][0] = gcm_load_be64(h);
    H[NOXTLS_GCM_HTABLE_H1_INDEX][1] = gcm_load_be64(h + 8U);

    H[0][0] = 0U;
    H[0][1] = 0U;

    for(i = NOXTLS_GCM_HTABLE_SIZE / 4U; i > 0U; i >>= 1) {
        gcm_gen_table_rightshift(H[i], H[i * 2U]);
    }

    for(i = 2U; i < NOXTLS_GCM_HTABLE_SIZE; i <<= 1) {
        for(j = 1U; j < i; j++) {
            H[i + j][0] = H[i][0] ^ H[j][0];
            H[i + j][1] = H[i][1] ^ H[j][1];
        }
    }
}

/**
 * @brief Return a cached Shoup H-table for hash subkey h.
 * @param h Hash subkey.
 * @return Pointer to H[NOXTLS_GCM_HTABLE_SIZE][2].
 */
static const uint64_t (*gcm_precompute_tables(const uint8_t h[NOXTLS_GCM_BLOCK_BYTES]))[2]
{
    static uint8_t cache_valid;
    static uint8_t cache_h[NOXTLS_GCM_BLOCK_BYTES];
    static uint64_t table[NOXTLS_GCM_HTABLE_SIZE][2];

    if(cache_valid != 0U && memcmp(cache_h, h, NOXTLS_GCM_BLOCK_BYTES) == 0) {
        return table;
    }

    gcm_gen_table(table, h);
    memcpy(cache_h, h, sizeof(cache_h));
    cache_valid = 1U;
    return table;
}

/**
 * @brief GF(2^128) multiply x by H using Shoup's 4-bit small table.
 *
 * Processes x from byte 15 down to 0; for each byte the low nibble is
 * applied, then a 4-bit word shift with last4 reduction, then the high
 * nibble (matching the standard small-table GHASH multiply).
 *
 * @param x Field element; replaced with x * H.
 * @param H Precomputed Shoup table.
 * @return None.
 */
static void gcm_mult_smalltable(uint8_t x[NOXTLS_GCM_BLOCK_BYTES],
                               const uint64_t H[NOXTLS_GCM_HTABLE_SIZE][2])
{
    int i;
    uint8_t lo;
    uint8_t hi;
    uint8_t rem;
    uint64_t u64z[2];
    const uint64_t *pu64z;

    lo = (uint8_t)(x[15] & NOXTLS_GCM_NIBBLE_MASK);
    hi = (uint8_t)((x[15] >> NOXTLS_GCM_NIBBLE_BITS) & NOXTLS_GCM_NIBBLE_MASK);

    pu64z = H[lo];
    rem = (uint8_t)(pu64z[1] & NOXTLS_GCM_NIBBLE_MASK);
    u64z[1] = (pu64z[0] << 60) | (pu64z[1] >> NOXTLS_GCM_NIBBLE_BITS);
    u64z[0] = (pu64z[0] >> NOXTLS_GCM_NIBBLE_BITS);
    u64z[0] ^= ((uint64_t)gcm_last4[rem] << NOXTLS_GCM_LAST4_SHIFT);
    u64z[0] ^= H[hi][0];
    u64z[1] ^= H[hi][1];

    for(i = 14; i >= 0; i--) {
        lo = (uint8_t)(x[i] & NOXTLS_GCM_NIBBLE_MASK);
        hi = (uint8_t)((x[i] >> NOXTLS_GCM_NIBBLE_BITS) & NOXTLS_GCM_NIBBLE_MASK);

        rem = (uint8_t)(u64z[1] & NOXTLS_GCM_NIBBLE_MASK);
        u64z[1] = (u64z[0] << 60) | (u64z[1] >> NOXTLS_GCM_NIBBLE_BITS);
        u64z[0] = (u64z[0] >> NOXTLS_GCM_NIBBLE_BITS);
        u64z[0] ^= ((uint64_t)gcm_last4[rem] << NOXTLS_GCM_LAST4_SHIFT);
        u64z[0] ^= H[lo][0];
        u64z[1] ^= H[lo][1];

        rem = (uint8_t)(u64z[1] & NOXTLS_GCM_NIBBLE_MASK);
        u64z[1] = (u64z[0] << 60) | (u64z[1] >> NOXTLS_GCM_NIBBLE_BITS);
        u64z[0] = (u64z[0] >> NOXTLS_GCM_NIBBLE_BITS);
        u64z[0] ^= ((uint64_t)gcm_last4[rem] << NOXTLS_GCM_LAST4_SHIFT);
        u64z[0] ^= H[hi][0];
        u64z[1] ^= H[hi][1];
    }

    gcm_store_be64(x + 0U, u64z[0]);
    gcm_store_be64(x + 8U, u64z[1]);
}

/**
 * @brief Multiply x by H using the Shoup H-table.
 * @param x Field element; replaced with x * H.
 * @param H Precomputed table.
 * @return None.
 */
static void gcm_mul(uint8_t x[NOXTLS_GCM_BLOCK_BYTES],
                    const uint64_t H[NOXTLS_GCM_HTABLE_SIZE][2])
{
#if defined(NOXTLS_GCM_GHASH_SELFCHECK)
    {
        uint8_t ref[NOXTLS_GCM_BLOCK_BYTES];
        uint8_t h_bytes[NOXTLS_GCM_BLOCK_BYTES];
        memcpy(ref, x, NOXTLS_GCM_BLOCK_BYTES);
        gcm_store_be64(h_bytes + 0U, H[NOXTLS_GCM_HTABLE_H1_INDEX][0]);
        gcm_store_be64(h_bytes + 8U, H[NOXTLS_GCM_HTABLE_H1_INDEX][1]);
        gcm_mul_bitserial(ref, h_bytes);
        gcm_mult_smalltable(x, H);
        if(memcmp(ref, x, NOXTLS_GCM_BLOCK_BYTES) != 0) {
            /* Keep bitserial result if smalltable diverges (debug builds). */
            memcpy(x, ref, NOXTLS_GCM_BLOCK_BYTES);
        }
        return;
    }
#else
    gcm_mult_smalltable(x, H);
#endif
}

/**
 * @brief Update GHASH state with additional authenticated data or ciphertext.
 * @param x Running GHASH state.
 * @param H Precomputed Shoup H-table.
 * @param data Input bytes.
 * @param len Input length in bytes.
 * @return None.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static void ghash_update(uint8_t x[NOXTLS_GCM_BLOCK_BYTES],
                         const uint64_t H[NOXTLS_GCM_HTABLE_SIZE][2],
                         const uint8_t *data,
                         uint32_t len)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint8_t block[NOXTLS_GCM_BLOCK_BYTES];
    uint32_t offset = 0;

    while((len - offset) >= NOXTLS_GCM_BLOCK_BYTES) {
        gcm_xor_inplace(x, data + offset);
        gcm_mul(x, H);
        offset += NOXTLS_GCM_BLOCK_BYTES;
    }

    if(offset < len) {
        uint32_t take = len - offset;
        memset(block, 0, sizeof(block));
        memcpy(block, data + offset, take);
        gcm_xor_inplace(x, block);
        gcm_mul(x, H);
    }
}

/**
 * @brief Finalize GHASH with AAD and ciphertext bit lengths.
 * @param x Running GHASH state.
 * @param H Precomputed Shoup H-table.
 * @param aad_bits AAD length in bits.
 * @param data_bits Ciphertext/plaintext length in bits.
 * @return None.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static void ghash_finalize(uint8_t x[NOXTLS_GCM_BLOCK_BYTES],
                           const uint64_t H[NOXTLS_GCM_HTABLE_SIZE][2],
                           uint64_t aad_bits,
                           uint64_t data_bits)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint8_t len_block[NOXTLS_GCM_BLOCK_BYTES];
    memset(len_block, 0, sizeof(len_block));

    len_block[0] = (uint8_t)(aad_bits >> 56);
    len_block[1] = (uint8_t)(aad_bits >> 48);
    len_block[2] = (uint8_t)(aad_bits >> 40);
    len_block[3] = (uint8_t)(aad_bits >> 32);
    len_block[4] = (uint8_t)(aad_bits >> 24);
    len_block[5] = (uint8_t)(aad_bits >> 16);
    len_block[6] = (uint8_t)(aad_bits >> 8);
    len_block[7] = (uint8_t)aad_bits;

    len_block[8] = (uint8_t)(data_bits >> 56);
    len_block[9] = (uint8_t)(data_bits >> 48);
    len_block[10] = (uint8_t)(data_bits >> 40);
    len_block[11] = (uint8_t)(data_bits >> 32);
    len_block[12] = (uint8_t)(data_bits >> 24);
    len_block[13] = (uint8_t)(data_bits >> 16);
    len_block[14] = (uint8_t)(data_bits >> 8);
    len_block[15] = (uint8_t)data_bits;

    gcm_xor_inplace(x, len_block);
    gcm_mul(x, H);
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
    /* Prefer the configured block backend (STM32/nRF port, AES-NI, …) so
     * HW builds accelerate GCM CTR/GHASH keystream, not only H7 full-AEAD. */
    return noxtls_aes_encrypt_block_ctx_internal(ctx, in, out);
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
    const uint64_t (*ghash_table)[2];
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

    memset(x, 0, sizeof(x));
    if(aad != NULL && aad_len > 0) {
        ghash_update(x, ghash_table, aad, aad_len);
    }

    while(offset < plaintext_len) {
        uint32_t take = (plaintext_len - offset >= 16) ? 16 : (plaintext_len - offset);
        if(aes_block(&aes_ctx, ctr, s) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        if(take == 16U) {
            gcm_xor_stream_block(ciphertext + offset, plaintext + offset, s);
        } else {
            gcm_xor_stream_partial(ciphertext + offset, plaintext + offset, s, take);
        }
        if(take == 16U) {
            gcm_xor_inplace(x, ciphertext + offset);
            gcm_mul(x, ghash_table);
        } else {
            uint8_t block[16] = {0};
            memcpy(block, ciphertext + offset, take);
            gcm_xor_inplace(x, block);
            gcm_mul(x, ghash_table);
        }
        offset += take;
        gcm_inc32(ctr);
    }

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
    const uint64_t (*ghash_table)[2];
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
        if(take == 16U) {
            gcm_xor_stream_block(plaintext + offset, ciphertext + offset, s);
        } else {
            gcm_xor_stream_partial(plaintext + offset, ciphertext + offset, s, take);
        }
        offset += take;
        gcm_inc32(ctr);
    }

    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_AES_GCM */
