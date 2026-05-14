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
* File:    noxtls_md5.c
* Summary: Message Digest Algorithm 5 (MD5)
* Defined in RFC 1321
*
*/

/** @addtogroup noxtls_mdigest */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "string_common.h"
#include "noxtls_common.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_md5.h"

#if NOXTLS_FEATURE_MD5

/* Module Debug Level */
static uint8_t debug_lvl = 0;

/* MD5 Operations */
#define MD5_F(X, Y, Z)     ((X & Y) | (((~X) & Z)))
#define MD5_G(X, Y, Z)     ((X & Z) | ((Y & (~Z))))
#define MD5_H(X, Y, Z)     (X ^ Y ^ Z)
#define MD5_I(X, Y, Z)     (Y ^ (X | (~Z)))

#define MD5_ROTL(X, N)      ((X << N) | (X >> (32 - N)))


noxtls_return_t noxtls_md5_round(noxtls_sha_ctx_t * ctx, const uint8_t * input);

// s specifies the per-round shift amounts
static uint32_t md5_shift[64] =
{
     7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
     5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
     4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
     6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

/** Constants for MD5 */
static uint32_t md5_k[] =
{
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391    
};

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
	if(ctx == NULL) {
		return NOXTLS_RETURN_NULL;
	}
    
    ctx->algo = NOXTLS_HASH_MD5;
    
    memset(ctx->h, 0, sizeof(ctx->h));
        
    ctx->h[0] = 0x67452301;
    ctx->h[1] = 0xefcdab89;
    ctx->h[2] = 0x98badcfe;
    ctx->h[3] = 0x10325476;

    noxtls_debug_printf("ctx->h[0] = %x", ctx->h[0]);   

    memset(&ctx->data, 0, MD5_BLOCK_SIZE_BYTES);
    ctx->data_len = 0;
    ctx->length = 0;
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Feed noxtls_message bytes into the MD5 context (RFC 1321).
 *
 * @param[in,out] ctx MD5 context; must not be NULL.
 * @param[in] input Message bytes; must point to at least len bytes when len > 0.
 * @param[in] len Number of bytes from input to absorb.
 *
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if ctx is NULL.
 * @return NOXTLS_RETURN_INVALID_BLOCK_SIZE if a partial block is already buffered and this call
 *         supplies fewer than MD5_BLOCK_SIZE_BYTES bytes without completing a block (see implementation).
 * @return Any error code propagated from noxtls_md5_round() if compression fails.
 */
noxtls_return_t noxtls_md5_update(noxtls_sha_ctx_t * ctx, uint8_t * input, uint32_t len)
{
	noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

	if(ctx == NULL) {
		return NOXTLS_RETURN_NULL;
	}

    //uint32_t block_count = (len * 8) / MD5_BLOCK_SIZE_BITS;

    if((len * 8 ) < MD5_BLOCK_SIZE_BITS)
    {
        if(ctx->data_len != 0) {
            /* A non 512-bit block already processed, so invalidate */            
            return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
        }

        /* Store for later processing */
        memcpy(& ctx->data[ctx->data_len], input, len);
        ctx->data_len = (uint8_t)len;
    }
    else
    {
        uint32_t total = len;
    	while(total > 0)
        {
            uint32_t to_process;
            if(total > MD5_BLOCK_SIZE_BYTES) {
                to_process = MD5_BLOCK_SIZE_BYTES;
            }
            else {
                /* Store for later processing */
                memset(ctx->data, 0, MD5_BLOCK_SIZE_BYTES);
                memcpy(ctx->data, &input[len - total], total);
                ctx->data_len = (uint8_t)total;
                break;
            }

    		/* Use per-call input offset; ctx->length tracks global bytes across calls. */
    		rc = noxtls_md5_round(ctx, &input[len - total]);
    		if(rc != NOXTLS_RETURN_SUCCESS) {
    			break;
    		}
            ctx->length += MD5_BLOCK_SIZE_BYTES;
            total -= to_process;
    	}
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
noxtls_return_t noxtls_md5_round(noxtls_sha_ctx_t * ctx, const uint8_t * input)
{
	noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
	uint32_t t = 0;
	uint32_t w[MD5_ROUND_COUNT] = {0};

    uint32_t A;
    uint32_t B;
    uint32_t C;
    uint32_t D = 0;
    
	if(ctx == NULL) {
		return NOXTLS_RETURN_NULL;
	}    
    
    /* Copy the noxtls_message to the first 16 words */    
    for(t = 0; t < MD5_WORDS_PER_BLOCK; t++) {
        w[t] = (input[(t * MD5_WORD_BYTES) + 3] << 24) | ((input[(t * MD5_WORD_BYTES) + 2]) << 16) | (input[(t * MD5_WORD_BYTES) + 1] << 8) | input[(t * MD5_WORD_BYTES)];
    }

    A = ctx->h[0];
    B = ctx->h[1];
    C = ctx->h[2];
    D = ctx->h[3];
    
    if(debug_lvl > 0) {
        noxtls_debug_printf("A\t\t\tB\t\t\tCc\t\t\tD\t\t\tF\n");
        noxtls_debug_printf("%08x\t%08x\t%08x\t%08x\t\n", A,B,C,D);
    }
    
    for(t = 0; t < MD5_ROUND_COUNT; t++)
    {
        uint32_t F = 0;
        uint32_t g = 0;

        if(t < MD5_WORDS_PER_BLOCK) {
            F = MD5_F(B, C, D);
            g = t;
        }
        else if(t <= 31) {
            F = MD5_G(B,C,D);
            g = ((5 * t) + 1) % MD5_WORDS_PER_BLOCK;
        }
        else if(t <= 47) {
            F = MD5_H(B, C, D);
            g = ((3 * t) + 5) % MD5_WORDS_PER_BLOCK;
        }
        else {
            /* t in [48..63] */
            F = MD5_I(B,C,D);
            g = (t * 7) % MD5_WORDS_PER_BLOCK;
        }
        F = F + A + md5_k[t] + w[g];
        A = D;
        D = C;
        C = B;
        B = B + MD5_ROTL(F, md5_shift[t]);
        
        if(debug_lvl > 0)
            noxtls_debug_printf("%u\t%u\t%u\t%u\t\n", A,B,C,D);
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

    uint32_t len = 0;
    uint8_t * data = NULL;
    uint32_t total_length = 0;
    int i = 0;
    
    uint8_t temp[MD5_BLOCK_SIZE_BYTES] = {0};
    /* Process any pending data or */
    if(ctx->data_len > 0)
    {
        len = ctx->data_len;
        data = ctx->data;
        memset(temp, 0, sizeof(temp));
        memcpy(temp, ctx->data, len);
        total_length = ctx->length + ctx->data_len;
    }
    else
    {
        //len = 64;
        memset(ctx->data, 0, MD5_BLOCK_SIZE_BYTES);
        data = ctx->data;
        memset(temp, 0, sizeof(temp));
    }
    
    int block_size = MD5_BLOCK_SIZE_BYTES;
    
    int space_occupied = (len % block_size);
    int space_left = block_size - space_occupied;
    
    
    if(len == 0) {
        space_occupied = 0;
        space_left = block_size;
    }
        
    if(space_left >= 1) {
        temp[space_occupied] = MD5_PAD_BYTE;
    }
    
    if(space_left >= (int)(MD5_LENGTH_FIELD_BYTES + 1)) {
        int length_size = MD5_LENGTH_FIELD_BYTES; /* Size of length in bytes 8 bytes / 64-bit */
        noxtls_add_padding_length_little(temp, block_size, total_length, length_size);
    }
    
    if(debug_lvl > 0) {
        noxtls_debug_printf("%d %s \n", __LINE__, __func__);
        for(i = 0; i < block_size; i++) {
            noxtls_debug_printf("%02x ", temp[i]);
        }
        noxtls_debug_printf("\n");
    }
    
    rc = noxtls_md5_round(ctx, temp);
    
    if(space_left < (int)(MD5_LENGTH_FIELD_BYTES + 1))
    {
        memset(temp, 0, block_size);
        if(space_left == 0) {
            /* not previously set */
            data[0] = MD5_PAD_BYTE;
        }
        
        noxtls_add_padding_length_little(temp, block_size, total_length, (uint8_t)MD5_LENGTH_FIELD_BYTES);
            
        if(debug_lvl > 0) {
            for(i = 0; i < block_size; i++) {
                noxtls_debug_printf("%02x", temp[i]);
            }
            noxtls_debug_printf("\n");
            noxtls_debug_printf("Process additional block since could not fit padding\n");
        }
        
        rc = noxtls_md5_round(ctx, temp);
        
    }
    
    uint8_t alg_sz = 8;
    if(ctx->algo == NOXTLS_HASH_MD5) {
        alg_sz = 4;
    }
    
    for(i = 0; i < alg_sz; i++)
    {
        hash[(i * 4) + 3] = (uint8_t)((ctx->h[i] & 0xFF000000) >> 24);
        hash[(i * 4) + 2] = (uint8_t)((ctx->h[i] & 0x00FF0000) >> 16);
        hash[(i * 4) + 1] = (uint8_t)((ctx->h[i] & 0x0000FF00) >> 8);
        hash[i * 4] = (uint8_t)(ctx->h[i] & 0x000000FF);
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
noxtls_return_t noxtls_md5_verify(uint8_t * data, uint32_t len, uint8_t * expected)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    uint8_t hash[HASH_MD5_OUT_LEN] = {0};
    noxtls_sha_ctx_t ctx;
    
    noxtls_md5_init(&ctx);
    noxtls_md5_update(&ctx, data, len);
    noxtls_md5_finish(&ctx, hash);
    
    if(debug_lvl > 0) {
        noxtls_debug_printf("Compare: \n");
        noxtls_print_data(hash, sizeof(hash));
        noxtls_print_data(expected, 16);
    }
    if(memcmp(hash, expected, sizeof(hash)) == 0) {
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
     debug_lvl = lvl;
 }

#endif /* NOXTLS_FEATURE_MD5 */
 
