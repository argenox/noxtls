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
* File:    noxtls_sha1.c
* Summary: Secure Hashing Algorithm SHA-1
* Defined in FIPS
*
*/

/** @addtogroup noxtls_mdigest */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "noxtls_common.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_sha.h"
#include "noxtls_sha1.h"

#if NOXTLS_FEATURE_SHA1

/* Module Debug Level */
static uint8_t debug_lvl = 0;

/* SHA-1 Operations */
#define SHA_CH(X, Y, Z)     ((X & Y) ^ (((~X) & Z)))
#define SHA_PARITY(X,Y,Z)   (X ^ Y ^ Z)
#define SHA_MAJ(X,Y, Z)     ((X & Y) ^ (X & Z) ^ (Y & Z))


#define SHA_ROTR(X, N)      ((X >> N) | (X << (32 - N)))
#define SHA_ROTL(X, N)      ((X << N) | (X >> (32 - N)))


noxtls_return_t noxtls_sha1_round(noxtls_sha_ctx_t * ctx, const uint8_t * input);
noxtls_return_t noxtls_sha1_pad(uint8_t * data, uint32_t zero_pad, uint32_t len);

void noxtls_sha1_set_debug(uint8_t lvl)
{
    debug_lvl = lvl;
}

noxtls_return_t noxtls_sha1_init(noxtls_sha_ctx_t * ctx, noxtls_hash_algos_t algo)
{
	if(ctx == NULL) {
		return NOXTLS_RETURN_NULL;
	}
    
    ctx->algo = algo;
    
    if(ctx->algo == NOXTLS_HASH_SHA1) {

        ctx->h[0] = 0x67452301;
        ctx->h[1] = 0xefcdab89;
        ctx->h[2] = 0x98badcfe;
        ctx->h[3] = 0x10325476;
        ctx->h[4] = 0xc3d2e1f0;        
    }    
    else
    {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }

    memset(&ctx->data, 0, SHA1_BLOCK_SIZE_BYTES);
    ctx->data_len = 0;
    ctx->length = 0;
    
    return NOXTLS_RETURN_SUCCESS;
}

/* Runs on every block of 512 bits */
noxtls_return_t noxtls_sha1_update(noxtls_sha_ctx_t * ctx, const uint8_t * input, uint32_t len)
{
	noxtls_return_t rc;
    uint32_t total = 0;
    uint32_t offset = 0;

	if(ctx == NULL) {
        noxtls_debug_printf("ctx is NULL\n");
		return NOXTLS_RETURN_NULL;
	}

    if(input == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    total = len;
    offset = 0;

    if(ctx->data_len > 0) {
        uint32_t space = SHA1_BLOCK_SIZE_BYTES - ctx->data_len;
        if(total < space) {
            memcpy(&ctx->data[ctx->data_len], input, total);
            ctx->data_len += (uint8_t)total;
            return NOXTLS_RETURN_SUCCESS;
        }

        memcpy(&ctx->data[ctx->data_len], input, space);
        rc = noxtls_sha1_round(ctx, ctx->data);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        ctx->length += SHA1_BLOCK_SIZE_BYTES;
        ctx->data_len = 0;
        offset += space;
        total -= space;
    }

    while(total >= SHA1_BLOCK_SIZE_BYTES) {
        rc = noxtls_sha1_round(ctx, &input[offset]);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        ctx->length += SHA1_BLOCK_SIZE_BYTES;
        offset += SHA1_BLOCK_SIZE_BYTES;
        total -= SHA1_BLOCK_SIZE_BYTES;
    }

    if(total > 0) {
        memcpy(ctx->data, &input[offset], total);
        ctx->data_len = (uint8_t)total;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/* Accepts only 512-bit data input */
noxtls_return_t noxtls_sha1_round(noxtls_sha_ctx_t * ctx, const uint8_t * input)
{
	noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
	uint32_t t = 0;
	uint32_t w[SHA1_ROUND_COUNT] = {0};

    uint32_t a,b,c,d,e = 0;
    
	if(ctx == NULL) {
		return NOXTLS_RETURN_NULL;
	}    
    if(input == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Copy the message to the first 16 words */    
    for(t = 0; t < 16; t++) {
        w[t] = (input[(t*4)] << 24) | (input[(t*4)+ 1] << 16) | (input[(t*4) + 2] << 8) | (input[(t*4)+ 3]);
    }

    for(t = 16; t < SHA1_ROUND_COUNT; t++) {
        w[t] = SHA_ROTL((w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16]), 1);
    }
    
    a = ctx->h[0];
    b = ctx->h[1];
    c = ctx->h[2];
    d = ctx->h[3];
    e = ctx->h[4];
    
    if(debug_lvl > 0)
        noxtls_debug_printf("a\t\t\tb\t\t\tc\t\t\td\t\t\te\n");
    
    for(t = 0; t < SHA1_ROUND_COUNT; t++)
    {
        uint32_t ft = 0;
        uint32_t sha1_k = 0;
        uint32_t T;
        
        if(t <= 19) {
            sha1_k = 0x5A827999;
            ft = SHA_CH(b,c,d);
        }
        else if(t <= 39) {
            sha1_k = 0x6ED9EBA1;
            ft = SHA_PARITY(b,c,d);
        }
        else if(t <= 59) {
            sha1_k = 0x8F1BBCDC;
            ft = SHA_MAJ(b,c,d);
        }
        else {
            /* t in [60..79] */
            sha1_k = 0xCA62C1D6;
            ft = SHA_PARITY(b,c,d);
        }
        
        T = SHA_ROTL(a, 5) + ft + e + sha1_k + w[t];
        e = d;
        d = c;
        c = SHA_ROTL(b, 30);
        b = a;
        a = T;
        
        if(debug_lvl > 0)
            noxtls_debug_printf("%08x\t%08x\t%08x\t%08x\t%08x\t\n", a,b,c,d,e);
    }
    
    /* Computer the ith intermediate hash value H(i) */
    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;    
    
    return rc;    
}

/**
 * @brief Finish SHA-1 operation
 * 
 * @details this function must be called 
 * 
 *
 * @param[in] ctx is the SHA context object
 * @param[in] hash is a pointer to the buffer where the SHA result will be placed
 *
 * @return NOXTLS_RETURN_SUCCESS on success, noxtls_return_t otherwise
 */
noxtls_return_t noxtls_sha1_finish(noxtls_sha_ctx_t * ctx, uint8_t * hash)
{
	noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(ctx == NULL || hash == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    uint32_t len = 0;
    uint32_t zero_padding_first = 0;
    uint32_t total_length = 0;
    uint32_t length_index = SHA1_BLOCK_SIZE_BYTES - SHA1_LENGTH_FIELD_BYTES;
    int i = 0;
    

    /* Process any pending data or */
    if(ctx->data_len > 0)
    {
        len = ctx->data_len;
        total_length = ctx->length + ctx->data_len;
    }
    else
    {
        //len = 64;
        memset(ctx->data, 0, SHA1_BLOCK_SIZE_BYTES);
        total_length = ctx->length;
    }

    //noxtls_debug_printf("\nByte Len: %d\n", len);
    uint32_t space_for_padding = SHA1_BLOCK_SIZE_BITS - ((len << 3) % SHA1_BLOCK_SIZE_BITS);
    //noxtls_debug_printf("Bits needing padding: %d\n", space_for_padding);
    
    
    if(space_for_padding < (SHA1_LENGTH_FIELD_BYTES + 1u) || space_for_padding == SHA1_BLOCK_SIZE_BITS)
    {
        /* Can't fit padding + length in one block; use two blocks */
        zero_padding_first = 0;
        if((len << 3) != SHA1_BLOCK_SIZE_BITS) {
            
            zero_padding_first = space_for_padding - 1;

            // First padding
            //rc = noxtls_sha1_pad(ctx->data, zero_padding_first, len);
            
            ctx->data[len] = SHA1_PAD_BYTE;
            
            rc = noxtls_sha1_round(ctx, ctx->data);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }


        }
        else if((len << 3) == SHA1_BLOCK_SIZE_BITS)
        {
            rc = noxtls_sha1_round(ctx, ctx->data);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
        }
        
        //noxtls_debug_printf("Zero Padding 1st %d\n", zero_padding_first);


        /* Second block: 0x80 at start (if needed), zeros, then 8-byte length at end (bytes 56-63) */
        memset(ctx->data, 0, SHA1_BLOCK_SIZE_BYTES);
        if(zero_padding_first == 0)
            ctx->data[0] = SHA1_PAD_BYTE;
        ctx->data[length_index + 0] = (uint8_t)(((total_length * 8) & 0xFF00000000000000) >> 56);
        ctx->data[length_index + 1] = (uint8_t)(((total_length * 8) & 0x00FF000000000000) >> 48);
        ctx->data[length_index + 2] = (uint8_t)(((total_length * 8) & 0x0000FF0000000000) >> 40);
        ctx->data[length_index + 3] = (uint8_t)(((total_length * 8) & 0x000000FF00000000) >> 32);
        ctx->data[length_index + 4] = (uint8_t)(((total_length * 8) & 0x00000000FF000000) >> 24);
        ctx->data[length_index + 5] = (uint8_t)(((total_length * 8) & 0x0000000000FF0000) >> 16);
        ctx->data[length_index + 6] = (uint8_t)(((total_length * 8) & 0x000000000000FF00) >> 8);
        ctx->data[length_index + 7] = (uint8_t)((total_length * 8) & 0x00000000000000FF);
        rc = noxtls_sha1_round(ctx, ctx->data);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    else
    {
        /* Can fit padding + length in the same block: 0x80 after data, then zeros, then length at end */
        zero_padding_first = space_for_padding;
        {
            uint32_t pad_byte_idx = SHA1_BLOCK_SIZE_BYTES - (zero_padding_first >> 3);
            uint32_t zero_count = length_index - (pad_byte_idx + 1u);
            ctx->data[pad_byte_idx] = SHA1_PAD_BYTE;
            if (zero_count > 0u) {
                memset(ctx->data + pad_byte_idx + 1u, 0, zero_count);
            }
        }
        ctx->data[length_index + 0] = (uint8_t)(((total_length * 8) & 0xFF00000000000000) >> 56);
        ctx->data[length_index + 1] = (uint8_t)(((total_length * 8) & 0x00FF000000000000) >> 48);
        ctx->data[length_index + 2] = (uint8_t)(((total_length * 8) & 0x0000FF0000000000) >> 40);
        ctx->data[length_index + 3] = (uint8_t)(((total_length * 8) & 0x000000FF00000000) >> 32);
        ctx->data[length_index + 4] = (uint8_t)(((total_length * 8) & 0x00000000FF000000) >> 24);
        ctx->data[length_index + 5] = (uint8_t)(((total_length * 8) & 0x0000000000FF0000) >> 16);
        ctx->data[length_index + 6] = (uint8_t)(((total_length * 8) & 0x000000000000FF00) >> 8);
        ctx->data[length_index + 7] = (uint8_t)((total_length * 8) & 0x00000000000000FF);
        
        rc = noxtls_sha1_round(ctx, ctx->data);
        
    }
    
    uint8_t alg_sz = SHA1_LENGTH_FIELD_BYTES;
    if(ctx->algo == NOXTLS_HASH_SHA_224) {
        alg_sz = 6;
    }
    if(ctx->algo == NOXTLS_HASH_SHA1) {
        alg_sz = SHA1_STATE_WORDS;
    }
    for(i = 0; i < alg_sz; i++)
    {
        hash[i * 4]       = (uint8_t)((ctx->h[i] & 0xFF000000) >> 24);
        hash[(i * 4) + 1] = (uint8_t)((ctx->h[i] & 0x00FF0000) >> 16);
        hash[(i * 4) + 2] = (uint8_t)((ctx->h[i] & 0x0000FF00) >> 8);
        hash[(i * 4) + 3] = (uint8_t)(ctx->h[i] & 0x000000FF);
    }


	return rc;
}

/**
 * @brief Takes data and verifies it matches a SHA1 Digest
 * 
 * @details this function must be called 
 * 
 *
 * @param[in] data is the data to hash
 * @param[in] len is the length of the data
 * @param[in] expected is the expected SHA1 digest
 *
 * @return NOXTLS_RETURN_SUCCESS on success, noxtls_return_t otherwise
 */
noxtls_return_t noxtls_sha1_verify(const uint8_t * data, uint32_t len, const uint8_t * expected)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    uint8_t hash[32] = {0};
    noxtls_sha_ctx_t ctx;
    
    rc = noxtls_sha1_init(&ctx, NOXTLS_HASH_SHA1);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("Failed to initialize SHA1 context\n");
        return rc;
    }
    rc = noxtls_sha1_update(&ctx, data, len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("Failed to update SHA1 context\n");
        return rc;
    }
    rc = noxtls_sha1_finish(&ctx, hash);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("Failed to finish SHA1 context\n");
        return rc;
    }
    
    if(memcmp(hash, expected, sizeof(hash)) == 0) {
        rc = NOXTLS_RETURN_SUCCESS;
    }

    return rc;
}

#endif /* NOXTLS_FEATURE_SHA1 */
