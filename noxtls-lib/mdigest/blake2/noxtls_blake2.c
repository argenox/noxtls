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
* File:    noxtls_blake2.c
* Summary: BLAKE2s and BLAKE2b (RFC 7693)
*
*
*****************************************************************************/

/** @addtogroup noxtls_mdigest */

#include <stdint.h>
#include <string.h>
#include "noxtls_common.h"
#include "noxtls_blake2.h"

#if NOXTLS_FEATURE_BLAKE2

/* BLAKE2s IV (same as SHA-256 IV) */
static const uint32_t blake2s_iv[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
};

/* BLAKE2b IV (same as SHA-512 IV) */
static const uint64_t blake2b_iv[8] = {
    UINT64_C(0x6A09E667F3BCC908), UINT64_C(0xBB67AE8584CAA73B),
    UINT64_C(0x3C6EF372FE94F82B), UINT64_C(0xA54FF53A5F1D36F1),
    UINT64_C(0x510E527FADE682D1), UINT64_C(0x9B05688C2B3E6C1F),
    UINT64_C(0x1F83D9ABFB41BD6B), UINT64_C(0x5BE0CD19137E2179)
};

/* Message schedule sigma (RFC 7693 Section 2.7) - same for both */
static const uint8_t blake2_sigma[BLAKE2_SIGMA_ROWS][BLAKE2_MSG_WORDS] = {
    { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 }
};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

/* BLAKE2s G: R1=16, R2=12, R3=8, R4=7 */
#define B2S_G(v, a, b, c, d, x, y) do { \
    (v)[a] = (v)[a] + (v)[b] + (x); \
    (v)[d] = ROTR32((v)[d] ^ (v)[a], 16); \
    (v)[c] = (v)[c] + (v)[d]; \
    (v)[b] = ROTR32((v)[b] ^ (v)[c], 12); \
    (v)[a] = (v)[a] + (v)[b] + (y); \
    (v)[d] = ROTR32((v)[d] ^ (v)[a], 8); \
    (v)[c] = (v)[c] + (v)[d]; \
    (v)[b] = ROTR32((v)[b] ^ (v)[c], 7); \
} while(0)

/* BLAKE2b G: R1=32, R2=24, R3=16, R4=63 */
#define B2B_G(v, a, b, c, d, x, y) do { \
    (v)[a] = (v)[a] + (v)[b] + (x); \
    (v)[d] = ROTR64((v)[d] ^ (v)[a], 32); \
    (v)[c] = (v)[c] + (v)[d]; \
    (v)[b] = ROTR64((v)[b] ^ (v)[c], 24); \
    (v)[a] = (v)[a] + (v)[b] + (y); \
    (v)[d] = ROTR64((v)[d] ^ (v)[a], 16); \
    (v)[c] = (v)[c] + (v)[d]; \
    (v)[b] = ROTR64((v)[b] ^ (v)[c], 63); \
} while(0)

/**
 * @brief BLAKE2s compression function (process one 64-byte block).
 * @internal
 * @param ctx BLAKE2s context; state is updated in place.
 * @param block Pointer to 64-byte (BLAKE2S_BLOCK_BYTES) noxtls_message block.
 * @param last 1 if this is the last block, 0 otherwise.
 */
static void blake2s_compress(noxtls_blake2_ctx_t * ctx, const uint8_t * block, int last)
{
    uint32_t m[BLAKE2_MSG_WORDS];
    uint32_t v[BLAKE2_V_WORDS];
    int i;
    int r;

    for(i = 0; i < BLAKE2_MSG_WORDS; i++) {
        size_t off = (size_t)i * BLAKE2S_WORD_BYTES;
        m[i] = (uint32_t)block[off] | ((uint32_t)block[off + 1U] << 8) |
               ((uint32_t)block[off + 2U] << 16) | ((uint32_t)block[off + 3U] << 24);
    }

    for(i = 0; i < BLAKE2_CHAINING_WORDS; i++) {
        v[i] = ctx->h.h32[i];
        v[i + BLAKE2_CHAINING_WORDS] = blake2s_iv[i];
    }
    v[BLAKE2_V_INDEX_T0] ^= (uint32_t)(ctx->total & 0xFFFFFFFFu);
    v[BLAKE2_V_INDEX_T1] ^= (uint32_t)(ctx->total >> 32);
    if(last)
        v[BLAKE2_V_INDEX_F] ^= 0xFFFFFFFFu;

    for(r = 0; r < BLAKE2S_ROUNDS; r++) {
        const uint8_t * s = blake2_sigma[r];
        B2S_G(v, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]]);
        B2S_G(v, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]]);
        B2S_G(v, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]]);
        B2S_G(v, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]]);
        B2S_G(v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]]);
        B2S_G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        B2S_G(v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
        B2S_G(v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
    }

    for(i = 0; i < BLAKE2_CHAINING_WORDS; i++)
        ctx->h.h32[i] ^= v[i] ^ v[i + BLAKE2_CHAINING_WORDS];
}

/**
 * @brief BLAKE2b compression function (process one 128-byte block).
 * @internal
 * @param ctx BLAKE2b context; state is updated in place.
 * @param block Pointer to 128-byte (BLAKE2B_BLOCK_BYTES) noxtls_message block.
 * @param last 1 if this is the last block, 0 otherwise.
 */
static void blake2b_compress(noxtls_blake2_ctx_t * ctx, const uint8_t * block, int last)
{
    uint64_t m[BLAKE2_MSG_WORDS];
    uint64_t v[BLAKE2_V_WORDS];
    int i;
    int r;

    for(i = 0; i < BLAKE2_MSG_WORDS; i++)
    {
        size_t off = (size_t)i * BLAKE2B_WORD_BYTES;
        m[i] = (uint64_t)block[off] | ((uint64_t)block[off + 1U] << 8) |
               ((uint64_t)block[off + 2U] << 16) | ((uint64_t)block[off + 3U] << 24) |
               ((uint64_t)block[off + 4U] << 32) | ((uint64_t)block[off + 5U] << 40) |
               ((uint64_t)block[off + 6U] << 48) | ((uint64_t)block[off + 7U] << 56);
    }

    for(i = 0; i < BLAKE2_CHAINING_WORDS; i++) {
        v[i] = ctx->h.h64[i];
        v[i + BLAKE2_CHAINING_WORDS] = blake2b_iv[i];
    }
    
    v[BLAKE2_V_INDEX_T0] ^= (uint64_t)(ctx->total & 0xFFFFFFFFu);
    v[BLAKE2_V_INDEX_T1] ^= (uint64_t)(ctx->total >> 32);
    if(last)
        v[BLAKE2_V_INDEX_F] ^= UINT64_MAX;

    for(r = 0; r < BLAKE2B_ROUNDS; r++) {
        const uint8_t * s = blake2_sigma[r % BLAKE2_SIGMA_ROWS];
        B2B_G(v, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]]);
        B2B_G(v, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]]);
        B2B_G(v, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]]);
        B2B_G(v, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]]);
        B2B_G(v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]]);
        B2B_G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        B2B_G(v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
        B2B_G(v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
    }

    for(i = 0; i < BLAKE2_CHAINING_WORDS; i++)
        ctx->h.h64[i] ^= v[i] ^ v[i + BLAKE2_CHAINING_WORDS];
}

/**
 * @brief Initialize BLAKE2s for a 256-bit (32-byte) digest (RFC 7693).
 * @param ctx Context to initialize; must not be NULL.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL.
 */
noxtls_return_t noxtls_blake2s_256_init(noxtls_blake2_ctx_t * ctx)
{
    if(ctx == NULL)
        return NOXTLS_RETURN_NULL;

    ctx->is_blake2b = 0;
    ctx->outlen = 32;
    ctx->buflen = 0;
    ctx->total = 0;
    memcpy(ctx->h.h32, blake2s_iv, sizeof(blake2s_iv));
    /* Parameter block: 0x01010000 ^ (kk<<8) ^ nn -> 0x01010020 for unkeyed 32-byte hash */
    ctx->h.h32[0] ^= 0x01010020u;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Initialize BLAKE2b for a 512-bit (64-byte) digest (RFC 7693).
 * @param ctx Context to initialize; must not be NULL.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL.
 */
noxtls_return_t noxtls_blake2b_512_init(noxtls_blake2_ctx_t * ctx)
{
    if(ctx == NULL)
        return NOXTLS_RETURN_NULL;

    ctx->is_blake2b = 1;
    ctx->outlen = 64;
    ctx->buflen = 0;
    ctx->total = 0;
    memcpy(ctx->h.h64, blake2b_iv, sizeof(blake2b_iv));
    ctx->h.h64[0] ^= UINT64_C(0x01010040); /* unkeyed, 64-byte digest */
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Feed data into the BLAKE2 (BLAKE2s or BLAKE2b) hash.
 * @param ctx Initialized BLAKE2 context from noxtls_blake2s_256_init or noxtls_blake2b_512_init.
 * @param data Input data; may be NULL only if len is 0.
 * @param len Number of bytes to hash.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL or data is NULL with len non-zero.
 */
noxtls_return_t noxtls_blake2_update(noxtls_blake2_ctx_t * ctx, const uint8_t * data, uint32_t len)
{
    uint32_t block_bytes;
    uint32_t fill;

    if(ctx == NULL)
        return NOXTLS_RETURN_NULL;
    if(data == NULL && len != 0)
        return NOXTLS_RETURN_NULL;

    block_bytes = ctx->is_blake2b ? BLAKE2B_BLOCK_BYTES : BLAKE2S_BLOCK_BYTES;

    if(len == 0)
        return NOXTLS_RETURN_SUCCESS;

    ctx->total += len;
    fill = block_bytes - ctx->buflen;

    if(ctx->buflen > 0 && len >= fill) {
        memcpy(ctx->buf + ctx->buflen, data, fill);
        if(ctx->is_blake2b)
            blake2b_compress(ctx, ctx->buf, 0);
        else
            blake2s_compress(ctx, ctx->buf, 0);
        ctx->buflen = 0;
        data += fill;
        len -= fill;
    }

    while(len >= block_bytes) {
        if(ctx->is_blake2b)
            blake2b_compress(ctx, data, 0);
        else
            blake2s_compress(ctx, data, 0);
        data += block_bytes;
        len -= block_bytes;
    }

    if(len > 0)
        memcpy(ctx->buf + ctx->buflen, data, len);
    ctx->buflen += len;

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Finalize BLAKE2 and write the digest.
 * @param ctx Initialized BLAKE2 context (from noxtls_blake2s_256_init or noxtls_blake2b_512_init).
 * @param hash Output buffer; must hold at least 32 bytes for BLAKE2s-256 or 64 bytes for BLAKE2b-512.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx or hash is NULL.
 */
noxtls_return_t noxtls_blake2_finish(noxtls_blake2_ctx_t * ctx, uint8_t * hash)
{
    uint32_t block_bytes;
    uint32_t i;

    if(ctx == NULL || hash == NULL)
        return NOXTLS_RETURN_NULL;

    block_bytes = ctx->is_blake2b ? BLAKE2B_BLOCK_BYTES : BLAKE2S_BLOCK_BYTES;

    memset(ctx->buf + ctx->buflen, 0, block_bytes - ctx->buflen);

    if(ctx->is_blake2b)
        blake2b_compress(ctx, ctx->buf, 1);
    else
        blake2s_compress(ctx, ctx->buf, 1);

    if(ctx->is_blake2b) {
        for(i = 0; i < ctx->outlen; i++)
            hash[i] = (uint8_t)((ctx->h.h64[i >> 3] >> (8 * (i & 7))) & 0xFFu);
    } else {
        for(i = 0; i < ctx->outlen; i++)
            hash[i] = (uint8_t)((ctx->h.h32[i >> 2] >> (8 * (i & 3))) & 0xFFu);
    }

    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_BLAKE2 */
