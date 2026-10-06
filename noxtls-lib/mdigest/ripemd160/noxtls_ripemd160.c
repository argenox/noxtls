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
* File:    noxtls_md5.h
* Summary: Message Digest Algorithm 5 (MD5)
* Defined in RFC 1321
*
* File:    noxtls_ripemd160.c
* Summary: RIPEMD-160 (ISO/IEC 10118-3:2004)
*
*
*****************************************************************************/

/** @addtogroup noxtls_mdigest */

#include <stdint.h>
#include <string.h>

#include "noxtls_common.h"
#include "noxtls_sha.h"
#include "noxtls_ripemd160.h"
#include "noxtls_ct.h"

#if NOXTLS_FEATURE_RIPEMD160

#define RIPEMD160_ROTL(X, N) (((X) << ((uint32_t)(N) & 31U)) | ((X) >> ((32U - (uint32_t)(N)) & 31U)))

static uint32_t ripemd160_rotl_amt(uint32_t x, uint32_t amt)
{
    switch(amt) {
    case 1U: return (uint32_t)((x << 1U) | (x >> 31U));
    case 2U: return (uint32_t)((x << 2U) | (x >> 30U));
    case 3U: return (uint32_t)((x << 3U) | (x >> 29U));
    case 4U: return (uint32_t)((x << 4U) | (x >> 28U));
    case 5U: return (uint32_t)((x << 5U) | (x >> 27U));
    case 6U: return (uint32_t)((x << 6U) | (x >> 26U));
    case 7U: return (uint32_t)((x << 7U) | (x >> 25U));
    case 8U: return (uint32_t)((x << 8U) | (x >> 24U));
    case 9U: return (uint32_t)((x << 9U) | (x >> 23U));
    case 10U: return (uint32_t)((x << 10U) | (x >> 22U));
    case 11U: return (uint32_t)((x << 11U) | (x >> 21U));
    case 12U: return (uint32_t)((x << 12U) | (x >> 20U));
    case 13U: return (uint32_t)((x << 13U) | (x >> 19U));
    case 14U: return (uint32_t)((x << 14U) | (x >> 18U));
    case 15U: return (uint32_t)((x << 15U) | (x >> 17U));
    case 16U: return (uint32_t)((x << 16U) | (x >> 16U));
    case 17U: return (uint32_t)((x << 17U) | (x >> 15U));
    case 18U: return (uint32_t)((x << 18U) | (x >> 14U));
    case 19U: return (uint32_t)((x << 19U) | (x >> 13U));
    case 20U: return (uint32_t)((x << 20U) | (x >> 12U));
    case 21U: return (uint32_t)((x << 21U) | (x >> 11U));
    case 22U: return (uint32_t)((x << 22U) | (x >> 10U));
    case 23U: return (uint32_t)((x << 23U) | (x >> 9U));
    case 24U: return (uint32_t)((x << 24U) | (x >> 8U));
    case 25U: return (uint32_t)((x << 25U) | (x >> 7U));
    case 26U: return (uint32_t)((x << 26U) | (x >> 6U));
    case 27U: return (uint32_t)((x << 27U) | (x >> 5U));
    case 28U: return (uint32_t)((x << 28U) | (x >> 4U));
    case 29U: return (uint32_t)((x << 29U) | (x >> 3U));
    case 30U: return (uint32_t)((x << 30U) | (x >> 2U));
    case 31U: return (uint32_t)((x << 31U) | (x >> 1U));
    default: return x;
    }
}


/* f(j,x,y,z) for rounds 0-15, 16-31, 32-47, 48-63, 64-79 */
#define F0(x, y, z) ((x) ^ (y) ^ (z))
#define F1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define F2(x, y, z) ((((x) | (~(y))) ^ (z)))
#define F3(x, y, z) (((x) & (z)) | ((y) & (~(z))))
#define F4(x, y, z) ((x) ^ ((y) | (~(z))))

/**
 * @brief RIPEMD-160 round function (process one 64-byte block).
 * @internal
 * @param ctx RIPEMD-160 context (noxtls_sha_ctx_t); state is updated in place.
 * @param block Pointer to 64-byte (RIPEMD160_BLOCK_SIZE_BYTES) noxtls_message block.
 * @return NOXTLS_RETURN_SUCCESS, or NOXTLS_RETURN_NULL if ctx or block is NULL.
 */
static noxtls_return_t noxtls_ripemd160_round(noxtls_sha_ctx_t * ctx, const uint8_t * block)
{
    /* Round tables local to this function (Rule 8.9). */
    static const uint32_t ripemd160_kl[5] = {
        0x00000000U, 0x5A827999U, 0x6ED9EBA1U, 0x8F1BBCDCU, 0xA953FD4EU
    };
    static const uint32_t ripemd160_kr[5] = {
        0x50A28BE6U, 0x5C4DD124U, 0x6D703EF3U, 0x7A6D76E9U, 0x00000000U
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


    uint32_t al = 0U;
    uint32_t bl = 0U;
    uint32_t cl = 0U;
    uint32_t dl = 0U;
    uint32_t el = 0U;
    uint32_t ar = 0U;
    uint32_t br = 0U;
    uint32_t cr = 0U;
    uint32_t dr = 0U;
    uint32_t er = 0U;
    uint32_t tl = 0U;
    uint32_t w[RIPEMD160_WORDS_PER_BLOCK];
    uint32_t h[RIPEMD160_STATE_WORDS];
    uint32_t j = 0U;

    if ((ctx == NULL) || (block == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    for (j = 0U; j < RIPEMD160_WORDS_PER_BLOCK; j += 1U) {
        size_t off = (size_t)j * RIPEMD160_WORD_BYTES;
        w[j] = (uint32_t)block[off] |
               ((uint32_t)block[off + 1U] <<8U) |
               ((uint32_t)block[off + 2U] <<16U) |
               ((uint32_t)block[off + 3U] <<24U);
    }

    h[0] = ctx->h[0];
    h[1] = ctx->h[1];
    h[2] = ctx->h[2];
    h[3] = ctx->h[3];
    h[4] = ctx->h[4];
    al = h[0];
    bl = h[1];
    cl = h[2];
    dl = h[3];
    el = h[4];
    ar = al; br = bl; cr = cl; dr = dl; er = el;

    for (j = 0U; j < 80U; j += 1U) {
        uint32_t fl = 0U;
        uint32_t fr = 0U;
        uint32_t kl = (uint32_t)(ripemd160_kl[(uint32_t)j >> 4U]);
        uint32_t kr = (uint32_t)(ripemd160_kr[(uint32_t)j >> 4U]);
        uint32_t tr = 0U;

        {
            uint32_t round = (uint32_t)j >> 4U;
            if (round == 0U) {
                fl = F0(bl, cl, dl);
                fr = F4(br, cr, dr);
            } else if (round == 1U) {
                fl = F1(bl, cl, dl);
                fr = F3(br, cr, dr);
            } else if (round == 2U) {
                fl = F2(bl, cl, dl);
                fr = F2(br, cr, dr);
            } else if (round == 3U) {
                fl = F3(bl, cl, dl);
                fr = F1(br, cr, dr);
            } else {
                fl = F4(bl, cl, dl);
                fr = F0(br, cr, dr);
            }
        }

        tl = ripemd160_rotl_amt(al + fl + w[ripemd160_xl[j]] + kl, (uint32_t)ripemd160_rl[j]) + el;
        tr = ripemd160_rotl_amt(ar + fr + w[ripemd160_xr[j]] + kr, (uint32_t)ripemd160_rr[j]) + er;

        al = el; el = dl; dl = RIPEMD160_ROTL(cl, 10U); cl = bl; bl = tl;
        ar = er; er = dr; dr = RIPEMD160_ROTL(cr, 10U); cr = br; br = tr;
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
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    ctx->algo = NOXTLS_HASH_RIPEMD160;
    ctx->h[0] = RIPEMD160_IV0;
    ctx->h[1] = RIPEMD160_IV1;
    ctx->h[2] = RIPEMD160_IV2;
    ctx->h[3] = RIPEMD160_IV3;
    ctx->h[4] = RIPEMD160_IV4;
    noxtls_secure_zero((ctx->data), (size_t)(RIPEMD160_BLOCK_SIZE_BYTES));
    ctx->data_len = 0U;
    ctx->length = 0U;
  return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Feed data into the RIPEMD-160 hash.
 * @param ctx Initialized RIPEMD-160 context from noxtls_ripemd160_init.
 * @param data Input data; may be NULL only if len is 0.
 * @param len Number of bytes to hash.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL or data is NULL with len non-zero.
 */
noxtls_return_t noxtls_ripemd160_update(noxtls_sha_ctx_t * ctx, const uint8_t * data, uint32_t len)
{
    uint32_t fill = 0U;
    const uint8_t *in_ptr = data;
    uint32_t in_left = len;

    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if ((in_ptr == NULL) && (in_left != 0U)) {
        return NOXTLS_RETURN_NULL;
    }

    if (in_left == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }

    fill = (uint32_t)(RIPEMD160_BLOCK_SIZE_BYTES - (uint32_t)ctx->data_len);

    if ((ctx->data_len > 0U) && (in_left >= fill)) {
        noxtls_copy_u8(&ctx->data[ctx->data_len], sizeof(ctx->data) - (size_t)(ctx->data_len), in_ptr, (size_t)fill);
        (void)noxtls_ripemd160_round(ctx, ctx->data);
        ctx->length += RIPEMD160_BLOCK_SIZE_BYTES;
        ctx->data_len = 0U;
        in_ptr = &in_ptr[fill];
        in_left -= fill;
    }

    while (in_left >= RIPEMD160_BLOCK_SIZE_BYTES) {
        (void)noxtls_ripemd160_round(ctx, in_ptr);
        ctx->length += RIPEMD160_BLOCK_SIZE_BYTES;
        in_ptr = &in_ptr[RIPEMD160_BLOCK_SIZE_BYTES];
        in_left -= RIPEMD160_BLOCK_SIZE_BYTES;
    }

    if (in_left > 0U) {
        noxtls_copy_u8(&ctx->data[ctx->data_len], sizeof(ctx->data) - (size_t)(ctx->data_len), in_ptr, (size_t)in_left);
        ctx->data_len += (uint8_t)in_left;
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
    uint32_t total_bits_lo = 0U;
    uint32_t total_bits_hi = 0U;
    uint32_t i = 0U;

    if ((ctx == NULL) || (hash == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    {
        /* 64-bit bit count: (length + data_len) * 8 overflows 32 bits at 512 MiB. */
        uint64_t total_bits = ((uint64_t)ctx->length + (uint64_t)ctx->data_len) << 3U;
        total_bits_lo = (uint32_t)(total_bits & 0xFFFFFFFFU);
        total_bits_hi = (uint32_t)(total_bits >> 32U);
    }

    ctx->data[ctx->data_len] = 0x80U;

    ctx->data_len += 1U;

    if (ctx->data_len > (RIPEMD160_BLOCK_SIZE_BYTES - 8U)) {
        {
            size_t pad_len = (size_t)(RIPEMD160_BLOCK_SIZE_BYTES - (uint32_t)ctx->data_len);
            noxtls_secure_zero((&ctx->data[ctx->data_len]), (pad_len));
        }
        (void)noxtls_ripemd160_round(ctx, ctx->data);
        ctx->data_len = 0U;
    }

    {
        size_t pad_len = (size_t)((RIPEMD160_BLOCK_SIZE_BYTES - (uint32_t)ctx->data_len) - 8U);
        noxtls_secure_zero((&ctx->data[ctx->data_len]), (pad_len));
    }
    ctx->data[RIPEMD160_BLOCK_SIZE_BYTES - 8U] = (uint8_t)(total_bits_lo & 0xFFU);
    ctx->data[RIPEMD160_BLOCK_SIZE_BYTES - 7U] = (uint8_t)((total_bits_lo >> 8U) & 0xFFU);
    ctx->data[RIPEMD160_BLOCK_SIZE_BYTES - 6U] = (uint8_t)((total_bits_lo >> 16U) & 0xFFU);
    ctx->data[RIPEMD160_BLOCK_SIZE_BYTES - 5U] = (uint8_t)((total_bits_lo >> 24U) & 0xFFU);
    ctx->data[RIPEMD160_BLOCK_SIZE_BYTES - 4U] = (uint8_t)(total_bits_hi & 0xFFU);
    ctx->data[RIPEMD160_BLOCK_SIZE_BYTES - 3U] = (uint8_t)((total_bits_hi >>8U) & 0xFFU);
    ctx->data[RIPEMD160_BLOCK_SIZE_BYTES - 2U] = (uint8_t)((total_bits_hi >>16U) & 0xFFU);
    ctx->data[RIPEMD160_BLOCK_SIZE_BYTES - 1U] = (uint8_t)((total_bits_hi >>24U) & 0xFFU);
    (void)noxtls_ripemd160_round(ctx, ctx->data);

    for (i = 0U; i < RIPEMD160_STATE_WORDS; i += 1U) {
        hash[(i * 4U) + 0U] = (uint8_t)(ctx->h[i] & 0xFFU);
        hash[(i * 4U) + 1U] = (uint8_t)((ctx->h[(uint32_t)i] >> 8U) & 0xFFU);
        hash[(i * 4U) + 2U] = (uint8_t)((ctx->h[(uint32_t)i] >> 16U) & 0xFFU);
        hash[(i * 4U) + 3U] = (uint8_t)((ctx->h[(uint32_t)i] >> 24U) & 0xFFU);
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

    if (noxtls_ripemd160_init(&ctx) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if (noxtls_ripemd160_update(&ctx, data, len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if (noxtls_ripemd160_finish(&ctx, out) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    return (noxtls_ct_equal(out, expected, (size_t)HASH_RIPEMD160_OUT_LEN) != 0) ?
           NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
}

#endif /* NOXTLS_FEATURE_RIPEMD160 */
