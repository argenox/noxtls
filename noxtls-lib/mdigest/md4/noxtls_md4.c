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
* File:    noxtls_md4.c
* Summary: Message Digest Algorithm 4 (MD4)
* Defined in RFC 1320
*
*/

/** @addtogroup noxtls_mdigest */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "string_common.h"
#include "noxtls_common.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_md4.h"

#if NOXTLS_FEATURE_MD4

/* Module Debug Level */
static uint8_t debug_lvl = 0;

/* MD4 Operations */
#define MD4_F(X, Y, Z)     ((X & Y) | ((~X) & Z))
#define MD4_G(X, Y, Z)     ((X & Y) | (X & Z) | (Y & Z))
#define MD4_H(X, Y, Z)     (X ^ Y ^ Z)

#define MD4_ROTL(X, N)      ((X << N) | (X >> (32 - N)))

/* Max bytes per update to avoid misuse (e.g. UINT32_MAX with small buffer). */
#define MD4_MAX_UPDATE_LEN  0x7FFFFFFFu

noxtls_return_t noxtls_md4_round(noxtls_sha_ctx_t * ctx, const uint8_t * input);

/* Shift amounts for MD4 (3 rounds of 16 operations each = 48 total) */
static uint32_t md4_shift[48] =
{
    /* Round 1 */
    3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19,
    /* Round 2 */
    3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13,
    /* Round 3 */
    3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15
};

/**
 * @brief Sets Module Debug level
 *
 *
 * @param[in] lvl is the debug level
 *
 */
void noxtls_md4_set_debug(uint8_t lvl)
{
    debug_lvl = lvl;
}

/**
 * @brief Initialize the MD4 Context
 *
 * @param[in,out] ctx is the context
 *
 * 
 */
noxtls_return_t noxtls_md4_init(noxtls_sha_ctx_t * ctx)
{
	if(ctx == NULL) {
		return NOXTLS_RETURN_NULL;
	}
    
    ctx->algo = NOXTLS_HASH_MD4;
    
    memset(ctx->h, 0, sizeof(ctx->h));
        
    /* MD4 initial hash values */
    ctx->h[0] = 0x67452301;
    ctx->h[1] = 0xefcdab89;
    ctx->h[2] = 0x98badcfe;
    ctx->h[3] = 0x10325476;

    if(debug_lvl > 0) {
        noxtls_debug_printf("ctx->h[0] = %x\n", ctx->h[0]);
    }

    memset(&ctx->data, 0, HASH_MD4_BLOCK_SIZE);
    ctx->data_len = 0;
    ctx->length = 0;
    
    return NOXTLS_RETURN_SUCCESS;
}

/* Runs on every block of 512 bits.
 * Caller must ensure input points to at least len bytes of valid memory.
 * len is rejected if it would cause ctx->length to overflow (uint32_t). */
noxtls_return_t noxtls_md4_update(noxtls_sha_ctx_t * ctx, const uint8_t * input, uint32_t len)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t offset = 0;

	if(ctx == NULL) {
		return NOXTLS_RETURN_NULL;
	}
    if(input == NULL || len == 0) {
        return NOXTLS_RETURN_SUCCESS;
    }
    /* Reject lengths that would overflow total length or are commonly misused (e.g. UINT32_MAX). */
    if(len > (uint32_t)MD4_MAX_UPDATE_LEN || (ctx->length + len < ctx->length)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    /* Fill existing buffer if present */
    if(ctx->data_len > 0) {
        uint32_t to_copy = HASH_MD4_BLOCK_SIZE - ctx->data_len;
        if(to_copy > len) {
            to_copy = len;
        }
        memcpy(ctx->data + ctx->data_len, input, to_copy);
        ctx->data_len += (uint8_t)to_copy; /* Due to 64 subtraction, will always be less than 64 */
        offset += to_copy;
        len -= to_copy;
        if(ctx->data_len == HASH_MD4_BLOCK_SIZE) {
            rc = noxtls_md4_round(ctx, ctx->data);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            ctx->length += HASH_MD4_BLOCK_SIZE;
            ctx->data_len = 0;
        }
    }

    /* Process full blocks directly from input */
    while(len >= HASH_MD4_BLOCK_SIZE) {
        rc = noxtls_md4_round(ctx, input + offset);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        ctx->length += HASH_MD4_BLOCK_SIZE;
        offset += HASH_MD4_BLOCK_SIZE;
        len -= HASH_MD4_BLOCK_SIZE;
    }

    /* Store remainder */
    if(len > 0) {
        memcpy(ctx->data, input + offset, len);
        ctx->data_len = (uint8_t)len;
    }

    return rc;
}

/**
 * @brief Performs an MD4 round
 *
 *
 * @param[in] ctx is the MD4 context
 * @param[in] input is the 512-bit data
 *
 * @return NOXTLS_RETURN_SUCCESS on success, noxtls_return_t otherwise
 */
noxtls_return_t noxtls_md4_round(noxtls_sha_ctx_t * ctx, const uint8_t * input)
{
	noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
	uint32_t t = 0;
	uint32_t w[MD4_WORDS_PER_BLOCK] = {0};

    uint32_t A, B, C, D = 0;
    
	if(ctx == NULL) {
		return NOXTLS_RETURN_NULL;
	}    
    
    /* Copy the message to the first 16 words (little-endian) */
    for(t = 0; t < MD4_WORDS_PER_BLOCK; t++) {
        w[t] = (input[(t * MD4_WORD_BYTES) + 3] << 24) | ((input[(t * MD4_WORD_BYTES) + 2]) << 16) | (input[(t * MD4_WORD_BYTES) + 1] << 8) | input[(t * MD4_WORD_BYTES)];
        if(debug_lvl > 0) {
            noxtls_debug_printf("w[%d] %u  0x%08x\n", t, w[t], w[t]);
        }
    }

    A = ctx->h[0];
    B = ctx->h[1];
    C = ctx->h[2];
    D = ctx->h[3];
    
    if(debug_lvl > 0) {
        noxtls_debug_printf("A\t\t\tB\t\t\tC\t\t\tD\t\t\tF\n");
        noxtls_debug_printf("%08x\t%08x\t%08x\t%08x\t\n", A, B, C, D);
    }
    
    /* Round 1: F function */
    for(t = 0; t < MD4_WORDS_PER_BLOCK; t++)
    {
        uint32_t F = MD4_F(B, C, D);
        F = F + A + w[t];
        A = MD4_ROTL(F, md4_shift[t]);
        
        /* Rotate registers */
        uint32_t temp = D;
        D = C;
        C = B;
        B = A;
        A = temp;
        
        if(debug_lvl > 0) {
            noxtls_debug_printf("%u\t%u\t%u\t%u\t\n", A, B, C, D);
        }
    }
    
    /* Round 2: G function */
    /* Word selection: 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15 */
    const uint32_t round2_words[MD4_WORDS_PER_BLOCK] = {0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15};
    for(t = 0; t < MD4_WORDS_PER_BLOCK; t++)
    {
        uint32_t G = MD4_G(B, C, D);
        G = G + A + w[round2_words[t]] + MD4_ROUND2_CONST;  /* MD4 round 2 constant */
        A = MD4_ROTL(G, md4_shift[16 + t]);
        
        /* Rotate registers */
        uint32_t temp = D;
        D = C;
        C = B;
        B = A;
        A = temp;
        
        if(debug_lvl > 0) {
            noxtls_debug_printf("%u\t%u\t%u\t%u\t\n", A, B, C, D);
        }
    }
    
    /* Round 3: H function */
    /* Word selection: 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15 */
    const uint32_t round3_words[MD4_WORDS_PER_BLOCK] = {0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15};
    for(t = 0; t < MD4_WORDS_PER_BLOCK; t++)
    {
        uint32_t H = MD4_H(B, C, D);
        H = H + A + w[round3_words[t]] + MD4_ROUND3_CONST;  /* MD4 round 3 constant */
        A = MD4_ROTL(H, md4_shift[32 + t]);
        
        /* Rotate registers */
        uint32_t temp = D;
        D = C;
        C = B;
        B = A;
        A = temp;
        
        if(debug_lvl > 0) {
            noxtls_debug_printf("%u\t%u\t%u\t%u\t\n", A, B, C, D);
        }
    }
    
    /* Compute the intermediate hash value H(i) */
    ctx->h[0] += A;
    ctx->h[1] += B;
    ctx->h[2] += C;
    ctx->h[3] += D;
    
    return rc;    
}

/**
 * @brief Finish MD4 operation
 * 
 * @details this function must be called 
 * 
 *
 * @param[in] ctx is the SHA context object
 * @param[in] hash is a pointer to the buffer where the MD4 result will be placed
 *
 * @return NOXTLS_RETURN_SUCCESS on success, noxtls_return_t otherwise
 */
noxtls_return_t noxtls_md4_finish(noxtls_sha_ctx_t * ctx, uint8_t * hash)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint32_t len = 0;
    uint8_t * data = NULL;
    uint32_t total_length = 0;
    int i = 0;
    int space_occupied = 0;
    int space_left = 0;
    uint8_t temp[HASH_MD4_BLOCK_SIZE];

    /* Process any pending data */
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
        memset(ctx->data, 0, HASH_MD4_BLOCK_SIZE);
        data = ctx->data;
        memset(temp, 0, sizeof(temp));
    }

    space_occupied = (len % HASH_MD4_BLOCK_SIZE);
    space_left = HASH_MD4_BLOCK_SIZE - space_occupied;

    if(len == 0) {
        space_occupied = 0;
        space_left = HASH_MD4_BLOCK_SIZE;
    }

    if(space_left >= 1) {
        temp[space_occupied] = MD4_PAD_BYTE;
    }

    if(space_left >= HASH_MD4_LENGTH_LEN + 1) {
        add_padding_length_little(temp, HASH_MD4_BLOCK_SIZE, total_length, HASH_MD4_LENGTH_LEN);
    }

    if(debug_lvl > 0) {
        noxtls_debug_printf("%d %s \n", __LINE__, __func__);
        for(i = 0; i < HASH_MD4_BLOCK_SIZE; i++) {
            noxtls_debug_printf("%02x ", temp[i]);
        }
        noxtls_debug_printf("\n");
    }

    rc = noxtls_md4_round(ctx, temp);

    if(space_left < HASH_MD4_LENGTH_LEN + 1)
    {
        memset(temp, 0, HASH_MD4_BLOCK_SIZE);
        if(space_left == 0) {
            data[0] = MD4_PAD_BYTE;
        }

        add_padding_length_little(temp, HASH_MD4_BLOCK_SIZE, total_length, HASH_MD4_LENGTH_LEN);

        if(debug_lvl > 0) {
            for(i = 0; i < HASH_MD4_BLOCK_SIZE; i++) {
                noxtls_debug_printf("%02x", temp[i]);
            }
            noxtls_debug_printf("\n");
            noxtls_debug_printf("Process additional block since could not fit padding\n");
        }

        rc = noxtls_md4_round(ctx, temp);
    }

    for(i = 0; i < HASH_MD4_STATE_WORDS; i++)
    {
        hash[(i * 4) + 3] = (uint8_t)((ctx->h[i] & 0xFF000000) >> 24);
        hash[(i * 4) + 2] = (uint8_t)((ctx->h[i] & 0x00FF0000) >> 16);
        hash[(i * 4) + 1] = (uint8_t)((ctx->h[i] & 0x0000FF00) >> 8);
        hash[i * 4] = (uint8_t)(ctx->h[i] & 0x000000FF);
    }

    return rc;
}

/**
 * @brief Takes data and verifies it matches a MD4 Digest
 *
 *
 * @param[in] data is the input data
 * @param[in] len is the length of the input data
 * @param[in] expected is the expected MD4 digest
 *
 * @return NOXTLS_RETURN_SUCCESS on success, noxtls_return_t otherwise
 */
noxtls_return_t noxtls_md4_verify(const uint8_t * data, uint32_t len, const uint8_t * expected)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    uint8_t hash[HASH_MD4_OUT_LEN] = {0};
    noxtls_sha_ctx_t ctx;
    
    noxtls_md4_init(&ctx);
    noxtls_md4_update(&ctx, data, len);
    noxtls_md4_finish(&ctx, hash);
    
    if(debug_lvl > 0) {
        noxtls_debug_printf("Compare: \n");
        noxtls_print_data(hash, sizeof(hash));
        noxtls_print_data(expected, HASH_MD4_OUT_LEN);
    }
    if(memcmp(hash, expected, sizeof(hash)) == 0) {
        rc = NOXTLS_RETURN_SUCCESS;
    }

    return rc;
}

#endif /* NOXTLS_FEATURE_MD4 */

