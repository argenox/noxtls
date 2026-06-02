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
* File:    noxtls_sha256.c
* Summary: SHA-256 Hash Implementation
* Based on FIPS 180-4
*
*
*****************************************************************************/


/** @addtogroup noxtls_mdigest */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "noxtls_common.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_sha.h"
#include "noxtls_sha256.h"

#if (NOXTLS_FEATURE_SHA224 || NOXTLS_FEATURE_SHA256)

#ifndef NOXTLS_FEATURE_STM32_HW_SHA256_ONLY
#define NOXTLS_FEATURE_STM32_HW_SHA256_ONLY 0
#endif

/* Module Debug Level */
static uint8_t debug_lvl = 0;

/* SHA-256 Operations */
#define SHA_CH(X, Y, Z)     (((X) & (Y)) ^ ((~(X)) & (Z)))
#define SHA_MAJ(X,Y, Z)     (((X) & (Y)) ^ ((X) & (Z)) ^ ((Y) & (Z)))
#define SHA_ROTR(X, N)      (((X) >> (N)) | ((X) << (32 - (N))))
#define SHA_SUM_FROM_0(X)   (SHA_ROTR((X), 2)  ^ SHA_ROTR((X), 13) ^ SHA_ROTR((X), 22))
#define SHA_SUM_FROM_1(X)   (SHA_ROTR((X), 6)  ^ SHA_ROTR((X), 11) ^ SHA_ROTR((X), 25))
#define SHA_SIGMA_FROM_0(X) (SHA_ROTR((X), 7)  ^ SHA_ROTR((X), 18) ^ ((X) >> 3))
#define SHA_SIGMA_FROM_1(X) (SHA_ROTR((X), 17) ^ SHA_ROTR((X), 19) ^ ((X) >> 10))

noxtls_return_t noxtls_sha256_round(noxtls_sha_ctx_t * ctx, const uint8_t * input);
noxtls_return_t noxtls_sha256_pad(uint8_t * data, uint32_t zero_pad, uint32_t len);
noxtls_return_t noxtls_sha256_round_accel_port(noxtls_sha_ctx_t *ctx, const uint8_t *input);
noxtls_return_t noxtls_sha256_blocks_accel_port(noxtls_sha_ctx_t *ctx, const uint8_t *input, uint32_t block_count);

/* SHA-224 / SHA-256 round constants K[0..63] (FIPS 180-4); count matches SHA256_ROUND_COUNT. */
uint32_t sha224_256_k[SHA256_ROUND_COUNT] =
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/**
 * @brief Set the debug level
 * 
 * @param lvl The debug level
 * @return void
 */
void noxtls_sha256_set_debug(uint8_t lvl)
{
    debug_lvl = lvl;
}

/**
 * @brief Initialize SHA-256
 * 
 * @param ctx SHA-256 context
 * @param algo Algorithm to use
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
noxtls_return_t noxtls_sha256_init(noxtls_sha_ctx_t * ctx, noxtls_hash_algos_t algo)
{
	if(ctx == NULL) {
		return NOXTLS_RETURN_NULL;
	}
    
    ctx->algo = algo;
    
    if(ctx->algo == NOXTLS_HASH_SHA_256) {
        ctx->h[0] = 0x6a09e667;
        ctx->h[1] = 0xbb67ae85;
        ctx->h[2] = 0x3c6ef372;
        ctx->h[3] = 0xa54ff53a;
        ctx->h[4] = 0x510e527f;
        ctx->h[5] = 0x9b05688c;
        ctx->h[6] = 0x1f83d9ab;
        ctx->h[7] = 0x5be0cd19;
    }
    else if(ctx->algo == NOXTLS_HASH_SHA_224)
    {
        ctx->h[0] = 0xc1059ed8;
        ctx->h[1] = 0x367cd507;
        ctx->h[2] = 0x3070dd17;
        ctx->h[3] = 0xf70e5939;
        ctx->h[4] = 0xffc00b31;
        ctx->h[5] = 0x68581511;
        ctx->h[6] = 0x64f98fa7;
        ctx->h[7] = 0xbefa4fa4;
    }
    else
    {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }

    memset(&ctx->data, 0, SHA256_BLOCK_SIZE_BYTES);
    ctx->data_len = 0;
    ctx->length = 0;
    
    return NOXTLS_RETURN_SUCCESS;
}

/* Runs on every block of 512 bits */
/** 
 * @brief Update SHA-256
 * 
 * @param ctx SHA-256 context
 * @param input Data to update
 * @param len Length of data to update
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
noxtls_return_t noxtls_sha256_update(noxtls_sha_ctx_t * ctx, const uint8_t * input, uint32_t len)
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
        uint32_t to_copy = SHA256_BLOCK_SIZE_BYTES - ctx->data_len;
        if(to_copy > len) {
            to_copy = len;
        }
        memcpy(ctx->data + ctx->data_len, input, to_copy);
        ctx->data_len = (uint8_t)(ctx->data_len + to_copy);
        offset += to_copy;
        len -= to_copy;
        if(ctx->data_len == SHA256_BLOCK_SIZE_BYTES) {
            noxtls_return_t rc = noxtls_sha256_round(ctx, ctx->data);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            ctx->length += SHA256_BLOCK_SIZE_BYTES;
            ctx->data_len = 0;
        }
    }

    /* Process full blocks directly from input */
    if(len >= SHA256_BLOCK_SIZE_BYTES) {
        uint32_t full_blocks = len / SHA256_BLOCK_SIZE_BYTES;
        uint32_t full_bytes = full_blocks * SHA256_BLOCK_SIZE_BYTES;
        noxtls_return_t rc = noxtls_sha256_blocks_accel_port(ctx, input + offset, full_blocks);

        if(rc == NOXTLS_RETURN_SUCCESS) {
            ctx->length += full_bytes;
            offset += full_bytes;
            len -= full_bytes;
        } else {
#if NOXTLS_FEATURE_STM32_HW_SHA256_ONLY
            return rc;
#else
            while(len >= SHA256_BLOCK_SIZE_BYTES) {
                rc = noxtls_sha256_round(ctx, input + offset);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    return rc;
                }
                ctx->length += SHA256_BLOCK_SIZE_BYTES;
                offset += SHA256_BLOCK_SIZE_BYTES;
                len -= SHA256_BLOCK_SIZE_BYTES;
            }
#endif
        }
    }

    /* Store remainder */
    if(len > 0) {
        memcpy(ctx->data, input + offset, len);
        ctx->data_len = (uint8_t)len;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/* Accepts only 512-bit data input */
/** 
 * @brief SHA-256 round
 * 
 * @param ctx SHA-256 context
 * @param input Data to round
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
noxtls_return_t noxtls_sha256_round(noxtls_sha_ctx_t * ctx, const uint8_t * input)
{
	noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
	uint32_t t = 0;
	uint32_t w[SHA256_ROUND_COUNT] = {0};

    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h = 0;
    
	if(ctx == NULL) {
		return NOXTLS_RETURN_NULL;
	}

    rc = noxtls_sha256_blocks_accel_port(ctx, input, 1U);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha256_round_accel_port(ctx, input);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
#if NOXTLS_FEATURE_STM32_HW_SHA256_ONLY
    return rc;
#endif

    
    
    /* Copy the noxtls_message to the first 16 words */    
    for(t = 0; t < SHA256_WORDS_PER_BLOCK; t++) {
        size_t in_off = (size_t)t * (size_t)SHA256_WORD_BYTES;
        w[t] =
            ((uint32_t)input[in_off] << 24) |
            ((uint32_t)input[in_off + 1U] << 16) |
            ((uint32_t)input[in_off + 2U] << 8) |
            ((uint32_t)input[in_off + 3U]);
    }

    for(t = SHA256_WORDS_PER_BLOCK; t < SHA256_ROUND_COUNT; t++) {
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
    
    for(t = 0; t < SHA256_ROUND_COUNT; t++)
    {
        uint32_t t1 = h + SHA_SUM_FROM_1(e) + SHA_CH(e, f, g) + sha224_256_k[t] + w[t];
        uint32_t t2 = SHA_SUM_FROM_0(a) + SHA_MAJ(a, b, c);
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
    
    
	    return NOXTLS_RETURN_SUCCESS;
}


/**
 * @brief Finish SHA-256 operation
 * 
 * @details this function must be called 
 * 
 *
 * @param[in] ctx is the SHA context object
 * @param[in] hash is a pointer to the buffer where the SHA result will be placed
 *
 * @return NOXTLS_RETURN_SUCCESS on success, noxtls_return_t otherwise
 */
noxtls_return_t noxtls_sha256_finish(noxtls_sha_ctx_t * ctx, uint8_t * hash)
{
	noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(ctx == NULL || hash == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    uint32_t len = 0;
    uint8_t * data = NULL;    
    uint32_t total_length = 0;
    int i = 0;
    
    uint8_t temp[SHA256_BLOCK_SIZE_BYTES] = {0};
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
        memset(ctx->data, 0, SHA256_BLOCK_SIZE_BYTES);
        data = ctx->data;
        total_length = ctx->length;
    }
    
    uint32_t block_size = SHA256_BLOCK_SIZE_BYTES;
    uint8_t length_size = SHA256_LENGTH_FIELD_BYTES; /* Size of length in bytes 8 bytes / 64-bit */
    
    uint32_t space_occupied = (len % block_size);
    uint32_t space_left = block_size - space_occupied;
    
    
    if(len == 0) {
        space_occupied = 0;
        space_left = block_size;
    }
        
    if(space_left >= 1) {
        temp[space_occupied] = SHA256_PAD_BYTE;
    }
    
    if(space_left >= (uint32_t)(SHA256_LENGTH_FIELD_BYTES + 1U)) {
        noxtls_add_padding_length(temp, block_size, total_length, length_size);
    }

    if(debug_lvl > 0){
        
        for(i = 0; i < block_size; i++) {
            noxtls_debug_printf("%02x ", temp[i]);
        }
        noxtls_debug_printf("\n");
        
        noxtls_debug_printf("Process here the current block\n");
    }
    
    rc = noxtls_sha256_round(ctx, temp);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        ctx->length += SHA256_BLOCK_SIZE_BYTES;
    }
    
    if(space_left < (uint32_t)(SHA256_LENGTH_FIELD_BYTES + 1U))
    {
        memset(temp, 0, block_size);
        if(space_left == 0) {
            /* not previously set */
            data[0] = SHA256_PAD_BYTE;
        }
        
        noxtls_add_padding_length(temp, block_size, total_length, length_size);
            
        if(debug_lvl > 0) {
            for(i = 0; i < block_size; i++) {
                noxtls_debug_printf("%02x", temp[i]);
            }
            noxtls_debug_printf("\n");
            noxtls_debug_printf("Process additional block since could not fit padding\n");
        }
        
        rc = noxtls_sha256_round(ctx, temp);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            ctx->length += SHA256_BLOCK_SIZE_BYTES;
        }
        
    }
    
    uint8_t alg_sz = SHA256_STATE_WORDS;
    if(ctx->algo == NOXTLS_HASH_SHA_224) {
        alg_sz = SHA224_STATE_WORDS;
    }
    for(i = 0; i < alg_sz; i++)
    {
        hash[i << 2]       = (uint8_t)((ctx->h[i] & 0xFF000000) >> 24);
        hash[(i << 2) + 1] = (uint8_t)((ctx->h[i] & 0x00FF0000) >> 16);
        hash[(i * 4) + 2] = (uint8_t)((ctx->h[i] & 0x0000FF00) >> 8);
        hash[(i << 2) + 3] = (uint8_t)(ctx->h[i] & 0x000000FF);
    }

	return rc;
}

/**
 * @brief Finish SHA-256 operation
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
noxtls_return_t noxtls_sha256_pad(uint8_t * data, uint32_t zero_pad, uint32_t len)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    (void)data;
    (void)zero_pad;
    (void)len;
    
    

    return rc;
}

/**
 * @brief Verify SHA-256
 * 
 * @param data Data to verify
 * @param len Length of data to verify
 * @param expected Expected hash
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_FAILED if verification fails
 */
noxtls_return_t noxtls_sha256_verify(const uint8_t * data, uint32_t len, const uint8_t * expected)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    uint8_t hash[HASH_SHA256_OUT_LEN] = {0};
    noxtls_sha_ctx_t ctx;
    
    noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256);
    noxtls_sha256_update(&ctx, data, len);
    noxtls_sha256_finish(&ctx, hash);
    
    if(memcmp(hash, expected, sizeof(hash)) == 0) {
        rc = NOXTLS_RETURN_SUCCESS;
    }

    return rc;
}

/**
 * @brief Verify SHA-224
 * 
 * @param data Data to verify
 * @param len Length of data to verify
 * @param expected Expected hash
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_FAILED if verification fails
 */
noxtls_return_t noxtls_sha224_verify(const uint8_t * data, uint32_t len, const uint8_t * expected)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    uint8_t hash[HASH_SHA256_OUT_LEN] = {0};
    noxtls_sha_ctx_t ctx;
    
    noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_224);
    noxtls_sha256_update(&ctx, data, len);
    noxtls_sha256_finish(&ctx, hash);
    
    if(memcmp(hash, expected, HASH_SHA224_OUT_LEN) == 0) {
        rc = NOXTLS_RETURN_SUCCESS;
    }

    return rc;
}

#endif /* NOXTLS_FEATURE_SHA224 || NOXTLS_FEATURE_SHA256 */
