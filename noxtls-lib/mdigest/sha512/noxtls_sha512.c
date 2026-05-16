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
* File:    noxtls_sha512.c
* Summary: NOXTLS SHA512
*
*/

/** @addtogroup noxtls_mdigest */

/* SHA-384, SHA-512, SHA-512/224 and SHA-512/256 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "noxtls_common.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_sha.h"
#include "noxtls_sha512.h"

#if (NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512)

/* Module Debug Level */
static uint8_t debug_lvl = 0;

/* SHA-256 Operations */
#define SHA_CH(X, Y, Z)     (((X) & (Y)) ^ ((~(X)) & (Z)))
#define SHA_MAJ(X,Y, Z)     (((X) & (Y)) ^ ((X) & (Z)) ^ ((Y) & (Z)))
#define SHA_ROTR(X, N)      (((X) >> (N)) | ((X) << (64 - (N))))

#define SHA_SUM_FROM_0(X)   (SHA_ROTR((X), 28)  ^ SHA_ROTR((X), 34) ^ SHA_ROTR((X), 39))
#define SHA_SUM_FROM_1(X)   (SHA_ROTR((X), 14)  ^ SHA_ROTR((X), 18) ^ SHA_ROTR((X), 41))
#define SHA_SIGMA_FROM_0(X) (SHA_ROTR((X), 1)   ^ SHA_ROTR((X), 8)  ^ ((X) >> 7))
#define SHA_SIGMA_FROM_1(X) (SHA_ROTR((X), 19)  ^ SHA_ROTR((X), 61) ^ ((X) >> 6))

noxtls_return_t noxtls_sha512_round(noxtls_sha512_ctx_t * ctx, const uint8_t * input);
noxtls_return_t noxtls_sha512_pad(uint8_t * data, uint32_t zero_pad, uint32_t len);

/* SHA-384 / SHA-512 / SHA-512/224 / SHA-512/256 round constants K[0..79] (FIPS 180-4); count matches SHA512_ROUND_COUNT. */
uint64_t sha512_k[SHA512_ROUND_COUNT] =
{
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694, 
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70, 
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b, 
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

/**
 * @brief Set SHA-512 debug level
 * 
 * @param lvl Debug level
 */
void noxtls_sha512_set_debug(uint8_t lvl)
{
    debug_lvl = lvl;
}

/**
 * @brief Initialize SHA-512
 * 
 * @param ctx SHA-512 context
 * @param algo Algorithm to use
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
noxtls_return_t noxtls_sha512_init(noxtls_sha512_ctx_t * ctx, noxtls_hash_algos_t algo)
{
	if(ctx == NULL) {
		return NOXTLS_RETURN_NULL;
	}
    
    ctx->algo = algo;
    
    if(ctx->algo == NOXTLS_HASH_SHA_512) {
        ctx->h[0] = 0x6a09e667f3bcc908;
        ctx->h[1] = 0xbb67ae8584caa73b;
        ctx->h[2] = 0x3c6ef372fe94f82b;
        ctx->h[3] = 0xa54ff53a5f1d36f1;
        ctx->h[4] = 0x510e527fade682d1;
        ctx->h[5] = 0x9b05688c2b3e6c1f;
        ctx->h[6] = 0x1f83d9abfb41bd6b;
        ctx->h[7] = 0x5be0cd19137e2179;
    } else if(ctx->algo == NOXTLS_HASH_SHA_384) {
        ctx->h[0] = 0xcbbb9d5dc1059ed8;
        ctx->h[1] = 0x629a292a367cd507;
        ctx->h[2] = 0x9159015a3070dd17;
        ctx->h[3] = 0x152fecd8f70e5939;
        ctx->h[4] = 0x67332667ffc00b31;
        ctx->h[5] = 0x8eb44a8768581511;
        ctx->h[6] = 0xdb0c2e0d64f98fa7;
        ctx->h[7] = 0x47b5481dbefa4fa4;
    } else if(ctx->algo == NOXTLS_HASH_SHA_512_224) {
        ctx->h[0] = 0x8c3d37c819544da2;
        ctx->h[1] = 0x73e1996689dcd4d6;
        ctx->h[2] = 0x1dfab7ae32ff9c82;
        ctx->h[3] = 0x679dd514582f9fcf;
        ctx->h[4] = 0x0f6d2b697bd44da8;
        ctx->h[5] = 0x77e36f7304c48942;
        ctx->h[6] = 0x3f9d85a86a1d36c8;
        ctx->h[7] = 0x1112e6ad91d692a1;
    } else if(ctx->algo == NOXTLS_HASH_SHA_512_256) {
        ctx->h[0] = 0x22312194fc2bf72c;
        ctx->h[1] = 0x9f555fa3c84c64c2;
        ctx->h[2] = 0x2393b86b6f53b151;
        ctx->h[3] = 0x963877195940eabd;
        ctx->h[4] = 0x96283ee2a88effe3;
        ctx->h[5] = 0xbe5e1e2553863992;
        ctx->h[6] = 0x2b0199fc2c85b8aa;
        ctx->h[7] = 0x0eb72ddc81c52ca2;
    } else {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }

    memset(&ctx->data, 0, HASH_SHA512_BLOCK_SIZE);
    ctx->data_len = 0;
    ctx->length = 0;
    
    return NOXTLS_RETURN_SUCCESS;
}

/* Runs on every block of 512 bits */
/**
 * @brief Update SHA-512
 * 
 * @param ctx SHA-512 context
 * @param input Data to update
 * @param len Length of data to update
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
noxtls_return_t noxtls_sha512_update(noxtls_sha512_ctx_t * ctx, const uint8_t * input, uint32_t len)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(input == NULL || len == 0) {
        return NOXTLS_RETURN_SUCCESS;
    }

    uint32_t offset = 0;

    /* Fill existing buffer if present */
    if(ctx->data_len > 0) {
        uint32_t to_copy = HASH_SHA512_BLOCK_SIZE - ctx->data_len;
        if(to_copy > len) {
            to_copy = len;
        }
        memcpy(ctx->data + ctx->data_len, input, to_copy);
        ctx->data_len = (uint8_t)(ctx->data_len + to_copy);
        offset += to_copy;
        len -= to_copy;
        if(ctx->data_len == HASH_SHA512_BLOCK_SIZE) {
            noxtls_return_t rc = noxtls_sha512_round(ctx, ctx->data);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            ctx->length += HASH_SHA512_BLOCK_SIZE;
            ctx->data_len = 0;
        }
    }

    /* Process full blocks directly from input */
    while(len >= HASH_SHA512_BLOCK_SIZE) {
        noxtls_return_t rc = noxtls_sha512_round(ctx, input + offset);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        ctx->length += HASH_SHA512_BLOCK_SIZE;
        offset += HASH_SHA512_BLOCK_SIZE;
        len -= HASH_SHA512_BLOCK_SIZE;
    }

    /* Store remainder */
    if(len > 0) {
        memcpy(ctx->data, input + offset, len);
        ctx->data_len = (uint8_t)len;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/* Accepts only 1024-bit data input */
/**
 * @brief SHA-512 round
 * 
 * @param ctx SHA-512 context
 * @param input Data to round
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
noxtls_return_t noxtls_sha512_round(noxtls_sha512_ctx_t * ctx, const uint8_t * input)
{
	noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
	uint32_t t = 0;
	uint64_t w[SHA512_ROUND_COUNT] = {0};

    uint64_t a;
    uint64_t b;
    uint64_t c;
    uint64_t d;
    uint64_t e;
    uint64_t f;
    uint64_t g;
    uint64_t h = 0;
    
	if(ctx == NULL) {
		return NOXTLS_RETURN_NULL;
	}    
    
    /* Copy the noxtls_message to the first 16 words */    
    for(t = 0; t < SHA512_WORDS_PER_BLOCK; t++) {
        size_t in_off = (size_t)t * (size_t)SHA512_WORD_BYTES;
        w[t] =  ((uint64_t)input[in_off] << 56)     |
                ((uint64_t)input[in_off + 1u] << 48) |
                ((uint64_t)input[in_off + 2u] << 40) |
                ((uint64_t)input[in_off + 3u] << 32) |
                ((uint64_t)input[in_off + 4u] << 24) | 
                ((uint64_t)input[in_off + 5u] << 16) | 
                ((uint64_t)input[in_off + 6u] << 8)  | 
                ((uint64_t)input[in_off + 7u]);


    }

    for(t = SHA512_WORDS_PER_BLOCK; t < SHA512_ROUND_COUNT; t++) {
        w[t] = SHA_SIGMA_FROM_1(w[t-2]) + w[t-7] + SHA_SIGMA_FROM_0(w[t - 15]) + w[t-16];
    }
    
    a = ctx->h[0];
    b = ctx->h[1];
    c = ctx->h[2];
    d = ctx->h[3];
    e = ctx->h[4];
    f = ctx->h[5];
    g = ctx->h[6];
    h = ctx->h[7];
    
    for(t = 0; t < SHA512_ROUND_COUNT; t++)
    {
        uint64_t t1 = h + SHA_SUM_FROM_1(e) + SHA_CH(e, f, g) + sha512_k[t] + w[t];
        uint64_t t2 = SHA_SUM_FROM_0(a) + SHA_MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    
    /* Computer the ith internmediate hash value H(i) */
    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
    ctx->h[5] += f;
    ctx->h[6] += g;
    ctx->h[7] += h;
    
    
    return rc;    
}

/**
 * @brief Finish SHA-512 operation
 * 
 * @details this function must be called 
 * 
 *
 * @param[in] ctx is the SHA context object
 * @param[in] hash is a pointer to the buffer where the SHA result will be placed
 *
 * @return NOXTLS_RETURN_SUCCESS on success, noxtls_return_t otherwise
 */
noxtls_return_t noxtls_sha512_finish(noxtls_sha512_ctx_t * ctx, uint8_t * hash)
{
	noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    uint32_t len = 0;
    uint8_t * data = NULL;    
    uint32_t total_length = 0;
    int i = 0;
    
    uint8_t temp[HASH_SHA512_BLOCK_SIZE] = {0};
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
        memset(ctx->data, 0, HASH_SHA512_BLOCK_SIZE);
        data = ctx->data;
        total_length = ctx->length;
    }
    
    uint32_t block_size = HASH_SHA512_BLOCK_SIZE;
    uint8_t length_size = HASH_SHA512_LENGTH_LEN; /* Size of length in bytes 8 bytes / 128-bit */
    
    uint32_t space_occupied = (len % block_size);
    uint32_t space_left = block_size - space_occupied;
    
    
    if(len == 0) {
        space_occupied = 0;
        space_left = block_size;
    }
        
    if(space_left >= 1) {
        temp[space_occupied] = SHA512_PAD_BYTE;
    }
    
    if(space_left >= length_size + 1) {
        noxtls_add_padding_length(temp, block_size, total_length, length_size);
    }

    if(debug_lvl > 0){
        
        for(i = 0; i < block_size; i++) {
            noxtls_debug_printf("%02x ", temp[i]);
        }
        noxtls_debug_printf("\n");
        
        noxtls_debug_printf("Process here the current block\n");
    }
    
    rc = noxtls_sha512_round(ctx, temp);
    
    if(space_left < length_size + 1)
    {
        memset(temp, 0, block_size);
        if(space_left == 0) {
            /* not previously set */
            data[0] = SHA512_PAD_BYTE;
        }
        
        noxtls_add_padding_length(temp, block_size, total_length, length_size);
            
        if(debug_lvl > 0) {
            for(i = 0; i < block_size; i++) {
                noxtls_debug_printf("%02x", temp[i]);
            }
            noxtls_debug_printf("\n");
            noxtls_debug_printf("Process additional block since could not fit padding\n");
        }
        
        rc = noxtls_sha512_round(ctx, temp);
        
    }
    
    uint8_t digest_len = HASH_SHA512_OUT_LEN;
    if(ctx->algo == NOXTLS_HASH_SHA_384) {
        digest_len = 48u;
    } else if(ctx->algo == NOXTLS_HASH_SHA_512_224) {
        digest_len = HASH_SHA512_224_OUT_LEN;
    } else if(ctx->algo == NOXTLS_HASH_SHA_512_256) {
        digest_len = HASH_SHA512_256_OUT_LEN;
    }
    for(i = 0; i < digest_len; i++)
    {
        uint8_t word_idx = (uint8_t)i / SHA512_WORD_BYTES;
        uint8_t byte_shift = (uint8_t)(56u - ((uint8_t)i % SHA512_WORD_BYTES) * 8u);

        if(debug_lvl > 0) {
            noxtls_debug_printf("ctx[%u] = %08llx\n", word_idx, ctx->h[word_idx]);
        }

        hash[i] = (uint8_t)((ctx->h[word_idx] >> byte_shift) & 0xFFu);
    }

	return rc;
}

/**
 * @brief Finish SHA-512 operation
 * 
 * @details this function must be called 
 * 
 *
 * @param[in] data is the HCI controller sink
 * @param[in] zero_pad is the Host Callback
 * @param[in] len is the BT HCI Callback
 *
 * @return NOXTLS_RETURN_SUCCESS on success, noxtls_return_t otherwise
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
noxtls_return_t noxtls_sha512_pad(uint8_t * data, uint32_t zero_pad, uint32_t len)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    (void)data;
    (void)zero_pad;
    (void)len;
    
    

    return rc;
}


/**
 * @brief Verify SHA-512
 * 
 * @param data Data to verify
 * @param len Length of data to verify
 * @param expected Expected hash
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_FAILED if verification fails
 */
noxtls_return_t noxtls_sha512_verify(const uint8_t * data, uint32_t len, const uint8_t * expected)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    uint8_t hash[HASH_SHA512_OUT_LEN] = {0};
    noxtls_sha512_ctx_t ctx;
    
    noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512);
    noxtls_sha512_update(&ctx, data, len);
    noxtls_sha512_finish(&ctx, hash);
    
    if(memcmp(hash, expected, sizeof(hash)) == 0) {
        rc = NOXTLS_RETURN_SUCCESS;
    }

    return rc;
}

#endif /* NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512 */
