/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
*
* File:    noxtls_ripemd160.c
* Summary: RIPEMD-160 (ISO/IEC 10118-3:2004)
*
*/

/** @addtogroup noxtls_mdigest */

#include <stdint.h>
#include <string.h>

#include "noxtls_common.h"
#include "noxtls_sha.h"
#include "noxtls_ripemd160.h"

#if NOXTLS_FEATURE_RIPEMD160

#define RIPEMD160_ROTL(X, N) (((X) << (N)) | ((X) >> (32 - (N))))

/* f(j,x,y,z) for rounds 0-15, 16-31, 32-47, 48-63, 64-79 */
#define F0(x, y, z) ((x) ^ (y) ^ (z))
#define F1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define F2(x, y, z) (((x) | (~(y))) ^ (z))
#define F3(x, y, z) (((x) & (z)) | ((y) & (~(z))))
#define F4(x, y, z) ((x) ^ ((y) | (~(z))))

static const uint32_t ripemd160_kl[5] = {
    0x00000000u, 0x5A827999u, 0x6ED9EBA1u, 0x8F1BBCDCu, 0xA953FD4Eu
};
static const uint32_t ripemd160_kr[5] = {
    0x50A28BE6u, 0x5C4DD124u, 0x6D703EF3u, 0x7A6D76E9u, 0x00000000u
};

static const uint8_t ripemd160_rl[80] = {
    11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
     7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
    11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
    11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
     9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6
};

static const uint8_t ripemd160_rr[80] = {
     8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
     9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
     9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
    15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
     8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11
};

static const uint8_t ripemd160_xl[80] = {
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
     7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
     3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
     1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
     4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13
};

static const uint8_t ripemd160_xr[80] = {
     5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
     6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
    15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
     8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
    12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11
};

/**
 * @brief RIPEMD-160 round function (process one 64-byte block).
 * @internal
 * @param ctx RIPEMD-160 context (noxtls_sha_ctx_t); state is updated in place.
 * @param block Pointer to 64-byte (RIPEMD160_BLOCK_SIZE_BYTES) noxtls_message block.
 * @return NOXTLS_RETURN_SUCCESS, or NOXTLS_RETURN_NULL if ctx or block is NULL.
 */
static noxtls_return_t noxtls_ripemd160_round(noxtls_sha_ctx_t * ctx, const uint8_t * block)
{
    uint32_t al;
    uint32_t bl;
    uint32_t cl;
    uint32_t dl;
    uint32_t el;
    uint32_t ar;
    uint32_t br;
    uint32_t cr;
    uint32_t dr;
    uint32_t er;
    uint32_t tl;
    uint32_t w[RIPEMD160_WORDS_PER_BLOCK];
    uint32_t h[RIPEMD160_STATE_WORDS];
    uint32_t j;

    if(ctx == NULL || block == NULL)
        return NOXTLS_RETURN_NULL;

    for(j = 0; j < RIPEMD160_WORDS_PER_BLOCK; j++) {
        size_t off = (size_t)j * RIPEMD160_WORD_BYTES;
        w[j] = (uint32_t)block[off] |
               ((uint32_t)block[off + 1u] << 8) |
               ((uint32_t)block[off + 2u] << 16) |
               ((uint32_t)block[off + 3u] << 24);
    }

    al = h[0] = ctx->h[0];
    bl = h[1] = ctx->h[1];
    cl = h[2] = ctx->h[2];
    dl = h[3] = ctx->h[3];
    el = h[4] = ctx->h[4];
    ar = al; br = bl; cr = cl; dr = dl; er = el;

    for(j = 0; j < 80; j++) {
        uint32_t fl;
        uint32_t fr;
        uint32_t kl = ripemd160_kl[j >> 4];
        uint32_t kr = ripemd160_kr[j >> 4];
        uint32_t tr;

        switch(j >> 4) {
            case 0: fl = F0(bl, cl, dl); fr = F4(br, cr, dr); break;
            case 1: fl = F1(bl, cl, dl); fr = F3(br, cr, dr); break;
            case 2: fl = F2(bl, cl, dl); fr = F2(br, cr, dr); break;
            case 3: fl = F3(bl, cl, dl); fr = F1(br, cr, dr); break;
            default: fl = F4(bl, cl, dl); fr = F0(br, cr, dr); break;
        }

        tl = RIPEMD160_ROTL(al + fl + w[ripemd160_xl[j]] + kl, ripemd160_rl[j]) + el;
        tr = RIPEMD160_ROTL(ar + fr + w[ripemd160_xr[j]] + kr, ripemd160_rr[j]) + er;

        al = el; el = dl; dl = RIPEMD160_ROTL(cl, 10); cl = bl; bl = tl;
        ar = er; er = dr; dr = RIPEMD160_ROTL(cr, 10); cr = br; br = tr;
    }

    tl = ctx->h[1] + cl + dr;
    ctx->h[1] = ctx->h[2] + dl + er;
    ctx->h[2] = ctx->h[3] + el + ar;
    ctx->h[3] = ctx->h[4] + al + br;
    ctx->h[4] = ctx->h[0] + bl + cr;
    ctx->h[0] = tl;

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Initialize RIPEMD-160 hashing (ISO/IEC 10118-3).
 * @param ctx Context to initialize; uses noxtls_sha_ctx_t. Must not be NULL.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL.
 */
noxtls_return_t noxtls_ripemd160_init(noxtls_sha_ctx_t * ctx)
{
    if(ctx == NULL)
        return NOXTLS_RETURN_NULL;

    ctx->algo = NOXTLS_HASH_RIPEMD160;
    ctx->h[0] = RIPEMD160_IV0;
    ctx->h[1] = RIPEMD160_IV1;
    ctx->h[2] = RIPEMD160_IV2;
    ctx->h[3] = RIPEMD160_IV3;
    ctx->h[4] = RIPEMD160_IV4;
    memset(ctx->data, 0, RIPEMD160_BLOCK_SIZE_BYTES);
    ctx->data_len = 0;
    ctx->length = 0;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Feed data into the RIPEMD-160 hash.
 * @param ctx Initialized RIPEMD-160 context from noxtls_ripemd160_init.
 * @param input Input data; may be NULL only if len is 0.
 * @param len Number of bytes to hash.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL or input is NULL with len non-zero.
 */
noxtls_return_t noxtls_ripemd160_update(noxtls_sha_ctx_t * ctx, const uint8_t * input, uint32_t len)
{
    uint32_t fill;

    if(ctx == NULL)
        return NOXTLS_RETURN_NULL;
    if(input == NULL && len != 0)
        return NOXTLS_RETURN_NULL;

    if(len == 0)
        return NOXTLS_RETURN_SUCCESS;

    fill = RIPEMD160_BLOCK_SIZE_BYTES - ctx->data_len;

    if(ctx->data_len > 0 && len >= fill) {
        memcpy(ctx->data + ctx->data_len, input, fill);
        noxtls_ripemd160_round(ctx, ctx->data);
        ctx->length += RIPEMD160_BLOCK_SIZE_BYTES;
        ctx->data_len = 0;
        input += fill;
        len -= fill;
    }

    while(len >= RIPEMD160_BLOCK_SIZE_BYTES) {
        noxtls_ripemd160_round(ctx, input);
        ctx->length += RIPEMD160_BLOCK_SIZE_BYTES;
        input += RIPEMD160_BLOCK_SIZE_BYTES;
        len -= RIPEMD160_BLOCK_SIZE_BYTES;
    }

    if(len > 0) {
        memcpy(ctx->data + ctx->data_len, input, len);
        ctx->data_len += (uint8_t)len;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Finalize RIPEMD-160 and write the 20-byte digest.
 * @param ctx Initialized RIPEMD-160 context.
 * @param hash Output buffer; must hold at least HASH_RIPEMD160_OUT_LEN (20) bytes.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx or hash is NULL.
 */
noxtls_return_t noxtls_ripemd160_finish(noxtls_sha_ctx_t * ctx, uint8_t * hash)
{
    uint32_t total_bits_lo;
    uint32_t total_bits_hi;
    uint32_t i;

    if(ctx == NULL || hash == NULL)
        return NOXTLS_RETURN_NULL;

    total_bits_lo = (ctx->length + ctx->data_len) << 3;
    total_bits_hi = 0;

    ctx->data[ctx->data_len++] = 0x80u;

    if(ctx->data_len > RIPEMD160_BLOCK_SIZE_BYTES - 8) {
        memset(ctx->data + ctx->data_len, 0, RIPEMD160_BLOCK_SIZE_BYTES - ctx->data_len);
        noxtls_ripemd160_round(ctx, ctx->data);
        ctx->data_len = 0;
    }

    memset(ctx->data + ctx->data_len, 0, RIPEMD160_BLOCK_SIZE_BYTES - ctx->data_len - 8);
    ctx->data[RIPEMD160_BLOCK_SIZE_BYTES - 8] = (uint8_t)(total_bits_lo & 0xFFu);
    ctx->data[RIPEMD160_BLOCK_SIZE_BYTES - 7] = (uint8_t)((total_bits_lo >> 8) & 0xFFu);
    ctx->data[RIPEMD160_BLOCK_SIZE_BYTES - 6] = (uint8_t)((total_bits_lo >> 16) & 0xFFu);
    ctx->data[RIPEMD160_BLOCK_SIZE_BYTES - 5] = (uint8_t)((total_bits_lo >> 24) & 0xFFu);
    ctx->data[RIPEMD160_BLOCK_SIZE_BYTES - 4] = (uint8_t)(total_bits_hi & 0xFFu);
    ctx->data[RIPEMD160_BLOCK_SIZE_BYTES - 3] = (uint8_t)((total_bits_hi >> 8) & 0xFFu);
    ctx->data[RIPEMD160_BLOCK_SIZE_BYTES - 2] = (uint8_t)((total_bits_hi >> 16) & 0xFFu);
    ctx->data[RIPEMD160_BLOCK_SIZE_BYTES - 1] = (uint8_t)((total_bits_hi >> 24) & 0xFFu);
    noxtls_ripemd160_round(ctx, ctx->data);

    for(i = 0; i < RIPEMD160_STATE_WORDS; i++) {
        hash[i*4 + 0] = (uint8_t)(ctx->h[i] & 0xFFu);
        hash[i*4 + 1] = (uint8_t)((ctx->h[i] >> 8) & 0xFFu);
        hash[i*4 + 2] = (uint8_t)((ctx->h[i] >> 16) & 0xFFu);
        hash[i*4 + 3] = (uint8_t)((ctx->h[i] >> 24) & 0xFFu);
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Compute RIPEMD-160 of data and compare to expected digest.
 * @param data Input data to hash; may be NULL only if len is 0.
 * @param len Number of bytes to hash.
 * @param expected Expected 20-byte RIPEMD-160 digest for comparison.
 * @return NOXTLS_RETURN_SUCCESS if digest matches, NOXTLS_RETURN_FAILED otherwise or on error.
 */
noxtls_return_t noxtls_ripemd160_verify(const uint8_t * data, uint32_t len, const uint8_t * expected)
{
    uint8_t out[HASH_RIPEMD160_OUT_LEN];
    noxtls_sha_ctx_t ctx;

    if(noxtls_ripemd160_init(&ctx) != NOXTLS_RETURN_SUCCESS)
        return NOXTLS_RETURN_FAILED;
    if(noxtls_ripemd160_update(&ctx, data, len) != NOXTLS_RETURN_SUCCESS)
        return NOXTLS_RETURN_FAILED;
    if(noxtls_ripemd160_finish(&ctx, out) != NOXTLS_RETURN_SUCCESS)
        return NOXTLS_RETURN_FAILED;
    return (memcmp(out, expected, HASH_RIPEMD160_OUT_LEN) == 0) ?
           NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
}

#endif /* NOXTLS_FEATURE_RIPEMD160 */
