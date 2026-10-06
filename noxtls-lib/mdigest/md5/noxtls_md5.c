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
* File:    noxtls_md5.c
* Summary: Message Digest Algorithm 5 (MD5)
* Defined in RFC 1321
*
* MD5 is cryptographically broken and should not be used.
*
*
*****************************************************************************/

/** @addtogroup noxtls_mdigest */

#include <stdint.h>
#include <string.h>

#include "string_common.h"
#include "noxtls_common.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_md5.h"
#include "noxtls_ct.h"

#if NOXTLS_FEATURE_MD5

/* Module Debug Level */
static uint8_t md5_debug_lvl = 0U;

/* MD5 Operations */
#define MD5_F(X, Y, Z)     (((X) & (Y)) | ((~(X)) & (Z)))
#define MD5_G(X, Y, Z)     (((X) & (Z)) | ((Y) & (~(Z))))
#define MD5_H(X, Y, Z)     ((X) ^ (Y) ^ (Z))
#define MD5_I(X, Y, Z)     ((Y) ^ ((X) | (~(Z))))


static noxtls_return_t noxtls_md5_round(noxtls_sha_ctx_t * ctx, const uint8_t * input);

// s specifies the per-round shift amounts
/**
 * @brief Initialize the MD5 context for incremental hashing (RFC 1321).
 *
 * @param[in,out] ctx Context to reset; must not be NULL.
 *
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if ctx is NULL.
 */
noxtls_return_t noxtls_md5_init(noxtls_sha_ctx_t * ctx)
{
	if (ctx == NULL) {
		return NOXTLS_RETURN_NULL;
	}
    
    ctx->algo = NOXTLS_HASH_MD5;
    
    noxtls_secure_zero((ctx->h), sizeof(ctx->h));
        
    ctx->h[0] = 0x67452301U;
    ctx->h[1] = 0xefcdab89U;
    ctx->h[2] = 0x98badcfeU;
    ctx->h[3] = 0x10325476U;

    if (md5_debug_lvl > 0U) {
        (void)noxtls_debug_printf((const uint8_t *)"ctx->h[0] = %x", ctx->h[0]);
    }

    noxtls_secure_zero((&ctx->data), (size_t)(MD5_BLOCK_SIZE_BYTES));
    ctx->data_len = 0U;
    ctx->length = 0U;
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Feed noxtls_message bytes into the MD5 context (RFC 1321).
 *
 * @details May be called any number of times with arbitrary lengths. Bytes
 *          are processed in order: a pending partial block is completed
 *          first, then whole blocks are compressed directly from data, and
 *          the remainder is buffered for the next update or finish.
 *
 * @param[in,out] ctx MD5 context; must not be NULL.
 * @param[in] data Message bytes; must point to at least len bytes when len > 0.
 * @param[in] len Number of bytes from input to absorb.
 *
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if ctx is NULL, or data is NULL with len non-zero.
 * @return Any error code propagated from noxtls_md5_round() if compression fails.
 */
noxtls_return_t noxtls_md5_update(noxtls_sha_ctx_t * ctx, const uint8_t * data, uint32_t len)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    const uint8_t * in_ptr = data;
    uint32_t in_left = len;

    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if (in_left == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }
    if (in_ptr == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if ((uint32_t)ctx->data_len >= (uint32_t)MD5_BLOCK_SIZE_BYTES) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }

    /* 1. Complete a pending partial block first (preserves byte order). */
    if (ctx->data_len > 0U) {
        uint32_t space = (uint32_t)MD5_BLOCK_SIZE_BYTES - (uint32_t)ctx->data_len;
        uint32_t to_copy = (in_left < space) ? in_left : space;

        noxtls_copy_u8(&ctx->data[ctx->data_len], sizeof(ctx->data) - (size_t)(ctx->data_len), in_ptr, (size_t)to_copy);
        ctx->data_len = (uint8_t)((uint32_t)ctx->data_len + to_copy);
        in_ptr = &in_ptr[to_copy];
        in_left -= to_copy;

        if ((uint32_t)ctx->data_len == (uint32_t)MD5_BLOCK_SIZE_BYTES) {
            rc = noxtls_md5_round(ctx, ctx->data);
            if (rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            ctx->length += (uint32_t)MD5_BLOCK_SIZE_BYTES;
            ctx->data_len = 0U;
        }
    }

    /* 2. Whole blocks straight from the input. */
    while (in_left >= (uint32_t)MD5_BLOCK_SIZE_BYTES) {
        rc = noxtls_md5_round(ctx, in_ptr);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        ctx->length += (uint32_t)MD5_BLOCK_SIZE_BYTES;
        in_ptr = &in_ptr[MD5_BLOCK_SIZE_BYTES];
        in_left -= (uint32_t)MD5_BLOCK_SIZE_BYTES;
    }

    /* 3. Buffer the remainder (data_len is 0 here whenever in_left > 0). */
    if (in_left > 0U) {
        noxtls_copy_u8(&ctx->data[ctx->data_len], sizeof(ctx->data) - (size_t)(ctx->data_len), in_ptr, (size_t)in_left);
        ctx->data_len = (uint8_t)((uint32_t)ctx->data_len + in_left);
    }

    return rc;
}

/**
 * @brief Compress one 512-bit (64-byte) MD5 block into the context state (RFC 1321).
 *
 * @param[in,out] ctx MD5 context; chain variables ctx->h[] are updated. Must not be NULL.
 * @param[in] input Exactly one block (MD5_BLOCK_SIZE_BYTES bytes), little-endian word layout.
 *
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if ctx is NULL.
 */
/**
 * @brief MD5 left-rotate by a fixed table amount (MISRA 12.2).
 */
static uint32_t md5_rotl_amt(uint32_t x, uint32_t amt)
{
    switch(amt) {
    case 4U: return (uint32_t)((x << 4U) | (x >> 28U));
    case 5U: return (uint32_t)((x << 5U) | (x >> 27U));
    case 6U: return (uint32_t)((x << 6U) | (x >> 26U));
    case 7U: return (uint32_t)((x << 7U) | (x >> 25U));
    case 9U: return (uint32_t)((x << 9U) | (x >> 23U));
    case 10U: return (uint32_t)((x << 10U) | (x >> 22U));
    case 11U: return (uint32_t)((x << 11U) | (x >> 21U));
    case 12U: return (uint32_t)((x << 12U) | (x >> 20U));
    case 14U: return (uint32_t)((x << 14U) | (x >> 18U));
    case 15U: return (uint32_t)((x << 15U) | (x >> 17U));
    case 16U: return (uint32_t)((x << 16U) | (x >> 16U));
    case 17U: return (uint32_t)((x << 17U) | (x >> 15U));
    case 20U: return (uint32_t)((x << 20U) | (x >> 12U));
    case 21U: return (uint32_t)((x << 21U) | (x >> 11U));
    case 22U: return (uint32_t)((x << 22U) | (x >> 10U));
    case 23U: return (uint32_t)((x << 23U) | (x >> 9U));
    default: return x;
    }
}

/**
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if ctx is NULL.
 */
static noxtls_return_t noxtls_md5_round(noxtls_sha_ctx_t * ctx, const uint8_t * input)
{
    /* Tables local to this function (Rule 8.9). */
    static const uint32_t md5_shift[64] =
    {
         7U, 12U, 17U, 22U, 7U, 12U, 17U, 22U, 7U, 12U, 17U, 22U, 7U, 12U, 17U, 22U,
         5U,  9U, 14U, 20U, 5U,  9U, 14U, 20U, 5U,  9U, 14U, 20U, 5U,  9U, 14U, 20U,
         4U, 11U, 16U, 23U, 4U, 11U, 16U, 23U, 4U, 11U, 16U, 23U, 4U, 11U, 16U, 23U,
         6U, 10U, 15U, 21U, 6U, 10U, 15U, 21U, 6U, 10U, 15U, 21U, 6U, 10U, 15U, 21U
    };

    /** Constants for MD5 */
    static const uint32_t md5_k[] =
    {
        0xd76aa478U, 0xe8c7b756U, 0x242070dbU, 0xc1bdceeeU,
        0xf57c0fafU, 0x4787c62aU, 0xa8304613U, 0xfd469501U,
        0x698098d8U, 0x8b44f7afU, 0xffff5bb1U, 0x895cd7beU,
        0x6b901122U, 0xfd987193U, 0xa679438eU, 0x49b40821U,
        0xf61e2562U, 0xc040b340U, 0x265e5a51U, 0xe9b6c7aaU,
        0xd62f105dU, 0x02441453U, 0xd8a1e681U, 0xe7d3fbc8U,
        0x21e1cde6U, 0xc33707d6U, 0xf4d50d87U, 0x455a14edU,
        0xa9e3e905U, 0xfcefa3f8U, 0x676f02d9U, 0x8d2a4c8aU,
        0xfffa3942U, 0x8771f681U, 0x6d9d6122U, 0xfde5380cU,
        0xa4beea44U, 0x4bdecfa9U, 0xf6bb4b60U, 0xbebfbc70U,
        0x289b7ec6U, 0xeaa127faU, 0xd4ef3085U, 0x04881d05U,
        0xd9d4d039U, 0xe6db99e5U, 0x1fa27cf8U, 0xc4ac5665U,
        0xf4292244U, 0x432aff97U, 0xab9423a7U, 0xfc93a039U,
        0x655b59c3U, 0x8f0ccc92U, 0xffeff47dU, 0x85845dd1U,
        0x6fa87e4fU, 0xfe2ce6e0U, 0xa3014314U, 0x4e0811a1U,
        0xf7537e82U, 0xbd3af235U, 0x2ad7d2bbU, 0xeb86d391U    
    };


	noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
	uint32_t t = 0U;
	uint32_t w[MD5_ROUND_COUNT] = {0};

    uint32_t A;
    uint32_t B;
    uint32_t C;
    uint32_t D = 0U;
    
	if (ctx == NULL) {
		return NOXTLS_RETURN_NULL;
	}    
    
    /* Copy the noxtls_message to the first 16 words */    
    for (t = 0U; t < MD5_WORDS_PER_BLOCK; t += 1U) {
        size_t in_off = (size_t)t * (size_t)MD5_WORD_BYTES;
        w[t] = ((uint32_t)input[in_off + 3U] << 24U) | ((uint32_t)input[in_off + 2U] << 16U) | ((uint32_t)input[in_off + 1U] << 8U) | (uint32_t)input[in_off];
    }

    A = ctx->h[0];
    B = ctx->h[1];
    C = ctx->h[2];
    D = ctx->h[3];
    
    if (md5_debug_lvl > 0U) {
        (void)noxtls_debug_printf((const uint8_t *)"A\t\t\tB\t\t\tCc\t\t\tD\t\t\tF\n");
        (void)noxtls_debug_printf((const uint8_t *)"%08x\t%08x\t%08x\t%08x\t\n", A,B,C,D);
    }
    
    for (t = 0U; t < MD5_ROUND_COUNT; t += 1U)
    {
        uint32_t F = 0U;
        uint32_t g = 0U;

        if (t < MD5_WORDS_PER_BLOCK) {
            F = MD5_F(B, C, D);
            g = t;
        }
        else if (t <= 31U) {
            F = MD5_G(B,C,D);
            g = ((5U * t) + 1U) % MD5_WORDS_PER_BLOCK;
        }
        else if (t <= 47U) {
            F = MD5_H(B, C, D);
            g = ((3U * t) + 5U) % MD5_WORDS_PER_BLOCK;
        }
        else {
            /* t in [48..63] */
            F = MD5_I(B,C,D);
            g = (t * 7U) % MD5_WORDS_PER_BLOCK;
        }
        F = (uint32_t)(F + A + md5_k[t] + w[g]);
        A = D;
        D = C;
        C = B;
        B = (uint32_t)(B + md5_rotl_amt(F, md5_shift[t]));
        
        if (md5_debug_lvl > 0U) {
            (void)noxtls_debug_printf((const uint8_t *)"%u\t%u\t%u\t%u\t\n", A,B,C,D);
        }
    }
    
    /* Computer the ith intermediate hash value H(i) */
    ctx->h[0] += A;
    ctx->h[1] += B;
    ctx->h[2] += C;
    ctx->h[3] += D;
    
    return rc;    
}

/**
 * @brief Finalize MD5: pad the noxtls_message, append bit length, and write the digest.
 *
 * @details Call after noxtls_md5_init() and one or more noxtls_md5_update() calls.
 *          hash must hold at least HASH_MD5_OUT_LEN (16) bytes.
 *
 * @param[in,out] ctx MD5 context; must not be NULL.
 * @param[out] hash Output buffer for the 128-bit MD5 digest (16 bytes, little-endian per word).
 *
 * @return NOXTLS_RETURN_SUCCESS when the digest was produced successfully.
 * @return NOXTLS_RETURN_NULL if an internal compression step receives a NULL context.
 * @return NOXTLS_RETURN_FAILED if finalization could not complete (see implementation).
 */
noxtls_return_t noxtls_md5_finish(noxtls_sha_ctx_t * ctx, uint8_t * hash)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    uint32_t len = 0U;
    uint8_t * data = NULL;
    uint32_t total_length = 0U;
    uint32_t i = 0U;
    
    uint8_t temp[MD5_BLOCK_SIZE_BYTES] = {0};

    if ((ctx == NULL) || (hash == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    /* Process any pending data or */
    if (ctx->data_len > 0U)
    {
        len = ctx->data_len;
        data = ctx->data;
        noxtls_secure_zero((temp), sizeof(temp));
        noxtls_copy_u8(temp, sizeof(temp), ctx->data, (size_t)(len));
        total_length = ctx->length + ctx->data_len;
    }
    else
    {
        noxtls_secure_zero((ctx->data), (size_t)(MD5_BLOCK_SIZE_BYTES));
        data = ctx->data;
        noxtls_secure_zero((temp), sizeof(temp));
        total_length = ctx->length;
    }
    
    uint32_t block_size = (uint32_t)(MD5_BLOCK_SIZE_BYTES);
    
    uint32_t space_occupied = (uint32_t)((len % block_size));
    uint32_t space_left = (uint32_t)(block_size - space_occupied);
    
    
    if (len == 0U) {
        space_occupied = 0U;
        space_left = block_size;
    }
        
    if (space_left >= 1U) {
        temp[space_occupied] = MD5_PAD_BYTE;
    }
    
    if (space_left >= (uint32_t)(MD5_LENGTH_FIELD_BYTES + 1U)) {
        uint8_t length_size = (uint8_t)(MD5_LENGTH_FIELD_BYTES); /* Size of length in bytes 8 bytes / 64-bit */
        noxtls_add_padding_length_little(temp, block_size, total_length, length_size);
    }
    
    if (md5_debug_lvl > 0U) {
        (void)noxtls_debug_printf((const uint8_t *)"%d %s \n", __LINE__, __func__);
        for (i = 0U; i < block_size; i += 1U) {
            (void)noxtls_debug_printf((const uint8_t *)"%02x ", temp[i]);
        }
        (void)noxtls_debug_printf((const uint8_t *)"\n");
    }
    
    rc = noxtls_md5_round(ctx, temp);
    
    if (space_left < (uint32_t)(MD5_LENGTH_FIELD_BYTES + 1U))
    {
        noxtls_secure_zero((temp), (size_t)(block_size));
        if (space_left == 0U) {
            /* not previously set */
            data[0] = MD5_PAD_BYTE;
        }
        
        (void)noxtls_add_padding_length_little(temp, block_size, total_length, (uint8_t)MD5_LENGTH_FIELD_BYTES);
            
        if (md5_debug_lvl > 0U) {
            for (i = 0U; i < block_size; i += 1U) {
                (void)noxtls_debug_printf((const uint8_t *)"%02x", temp[i]);
            }
            (void)noxtls_debug_printf((const uint8_t *)"\n");
            (void)noxtls_debug_printf((const uint8_t *)"Process additional block since could not fit padding\n");
        }
        
        rc = noxtls_md5_round(ctx, temp);
        
    }
    
    uint8_t alg_sz = 8U;
    if (ctx->algo == NOXTLS_HASH_MD5) {
        alg_sz = 4;
    }
    
    for (i = 0U; i < (uint32_t)alg_sz; i += 1U)
    {
        size_t out_off = (size_t)i * 4U;
        hash[out_off + 3U] = (uint8_t)((ctx->h[i] & 0xFF000000U) >>24U);
        hash[out_off + 2U] = (uint8_t)((ctx->h[i] & 0x00FF0000U) >>16U);
        hash[out_off + 1U] = (uint8_t)((ctx->h[i] & 0x0000FF00U) >>8U);
        hash[out_off] = (uint8_t)(ctx->h[i] & 0x000000FFU);
    }

    return rc;
}

/**
 * @brief Hash data and compare the result to an expected MD5 digest.
 *
 * @param[in] data Message to hash; must point to at least len bytes when len > 0.
 * @param[in] len Length of data in bytes.
 * @param[in] expected Expected digest; must point to at least HASH_MD5_OUT_LEN (16) bytes.
 *
 * @return NOXTLS_RETURN_SUCCESS if the computed digest equals expected.
 * @return NOXTLS_RETURN_FAILED if the digests differ or hashing did not succeed.
 */
noxtls_return_t noxtls_md5_verify(const uint8_t * data, uint32_t len, const uint8_t * expected)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    uint8_t hash[HASH_MD5_OUT_LEN] = {0};
    noxtls_sha_ctx_t ctx;
    
    (void)noxtls_md5_init(&ctx);
    (void)noxtls_md5_update(&ctx, data, len);
    (void)noxtls_md5_finish(&ctx, hash);
    
    if (md5_debug_lvl > 0U) {
        (void)noxtls_debug_printf((const uint8_t *)"Compare: \n");
        (void)noxtls_print_data(hash, sizeof(hash));
        (void)noxtls_print_data(expected, 16);
    }
    if (noxtls_ct_equal(hash, expected, sizeof(hash)) != 0) {
        rc = NOXTLS_RETURN_SUCCESS;
    }

    return rc;
}

/**
 * @brief Set the MD5 module debug verbosity (internal tracing).
 *
 * @param[in] lvl Debug level; higher values enable more noxtls_debug_printf output.
 *
 * @return None (void).
 */
void noxtls_md5_set_debug(uint8_t lvl)
 {
     md5_debug_lvl = lvl;
 }

#endif /* NOXTLS_FEATURE_MD5 */
 
