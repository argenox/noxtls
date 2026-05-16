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
* File:    noxtls_chacha20.c
* Summary: ChaCha20 Stream Cipher Implementation
*
* Implementation of ChaCha20 as specified in RFC 7539
*
*/

/** @addtogroup noxtls_encryption */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "common/noxtls_debug_printf.h"
#include "noxtls_chacha20.h"

#if NOXTLS_FEATURE_CHACHA20_POLY1305

#if NOXTLS_CHACHA20_DEBUG
#define NOXTLS_CHACHA20_DEBUG_PRINT(fmt, ...) noxtls_debug_printf("[CHACHA20_DEBUG] " fmt, ##__VA_ARGS__)
#else
#define NOXTLS_CHACHA20_DEBUG_PRINT(fmt, ...) ((void)0)
#endif

/* ChaCha20 Constants */
static const uint32_t NOXTLS_CHACHA20_CONSTANTS[4] = {
    0x61707865,  /* "expa" */
    0x3320646e,  /* "nd 3" */
    0x79622d32,  /* "2-by" */
    0x6b206574   /* "te k" */
};

/**
 * @brief Rotate left (32-bit)
 */
static inline uint32_t chacha20_rotl32(uint32_t x, uint32_t n)
{
    return ((x << n) | (x >> (32 - n)));
}

/**
 * @brief ChaCha20 Quarter Round
 *
 * Performs one quarter round operation on four 32-bit words.
 * This is the core operation of ChaCha20.
 *
 * @param a Pointer to first word
 * @param b Pointer to second word
 * @param c Pointer to third word
 * @param d Pointer to fourth word
 */
static void chacha20_quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    *a += *b; *d ^= *a; *d = chacha20_rotl32(*d, 16);
    *c += *d; *b ^= *c; *b = chacha20_rotl32(*b, 12);
    *a += *b; *d ^= *a; *d = chacha20_rotl32(*d, 8);
    *c += *d; *b ^= *c; *b = chacha20_rotl32(*b, 7);
}

/**
 * @brief Generate one ChaCha20 block (64 bytes)
 *
 * @param state Input state (`NOXTLS_CHACHA20_STATE_WORDS` x 32-bit words)
 * @param output Output keystream block (`NOXTLS_CHACHA20_BLOCK_SIZE` bytes)
 */
static void chacha20_block(const uint32_t state[NOXTLS_CHACHA20_STATE_WORDS], uint8_t output[NOXTLS_CHACHA20_BLOCK_SIZE])
{
    uint32_t working_state[NOXTLS_CHACHA20_STATE_WORDS];
    uint32_t i;
    uint32_t j;
    
    /* Copy state to working state */
    for(i = 0; i < NOXTLS_CHACHA20_STATE_WORDS; i++) {
        working_state[i] = state[i];
    }
    
    /* Perform NOXTLS_CHACHA20_ROUNDS rounds (NOXTLS_CHACHA20_DOUBLE_ROUNDS double rounds) */
    for(i = 0; i < NOXTLS_CHACHA20_DOUBLE_ROUNDS; i++) {
        /* Column rounds */
        chacha20_quarter_round(&working_state[0], &working_state[4], &working_state[8],  &working_state[12]);
        chacha20_quarter_round(&working_state[1], &working_state[5], &working_state[9],  &working_state[13]);
        chacha20_quarter_round(&working_state[2], &working_state[6], &working_state[10], &working_state[14]);
        chacha20_quarter_round(&working_state[3], &working_state[7], &working_state[11], &working_state[15]);
        
        /* Diagonal rounds */
        chacha20_quarter_round(&working_state[0], &working_state[5], &working_state[10], &working_state[15]);
        chacha20_quarter_round(&working_state[1], &working_state[6], &working_state[11], &working_state[12]);
        chacha20_quarter_round(&working_state[2], &working_state[7], &working_state[8],  &working_state[13]);
        chacha20_quarter_round(&working_state[3], &working_state[4], &working_state[9],  &working_state[14]);
    }
    
    /* Add original state to working state */
    for(i = 0; i < NOXTLS_CHACHA20_STATE_WORDS; i++) {
        working_state[i] += state[i];
    }
    
    /* Convert to little-endian bytes */
    for(i = 0; i < NOXTLS_CHACHA20_STATE_WORDS; i++) {
        for(j = 0; j < 4; j++) {
            output[i * 4 + j] = (uint8_t)(working_state[i] >> (j * 8));
        }
    }
}

/**
 * @brief Initialize ChaCha20 context
 */
noxtls_return_t noxtls_chacha20_init(noxtls_chacha20_context_t *ctx, 
                  const uint8_t *key, 
                  const uint8_t *nonce, 
                  uint64_t counter)
{
    if(ctx == NULL || key == NULL || nonce == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Initialize state according to RFC 7539 */
    /* State layout: constants(4) + key(8) + block_counter(1) + nonce(3) = NOXTLS_CHACHA20_STATE_WORDS words */
    
    /* Constants (4 words) */
    ctx->state[0] = NOXTLS_CHACHA20_CONSTANTS[0];
    ctx->state[1] = NOXTLS_CHACHA20_CONSTANTS[1];
    ctx->state[2] = NOXTLS_CHACHA20_CONSTANTS[2];
    ctx->state[3] = NOXTLS_CHACHA20_CONSTANTS[3];
    
    /* Key (8 words = 32 bytes, little-endian) */
    ctx->state[4] = ((uint32_t)key[0]) | ((uint32_t)key[1] << 8) | ((uint32_t)key[2] << 16) | ((uint32_t)key[3] << 24);
    ctx->state[5] = ((uint32_t)key[4]) | ((uint32_t)key[5] << 8) | ((uint32_t)key[6] << 16) | ((uint32_t)key[7] << 24);
    ctx->state[6] = ((uint32_t)key[8]) | ((uint32_t)key[9] << 8) | ((uint32_t)key[10] << 16) | ((uint32_t)key[11] << 24);
    ctx->state[7] = ((uint32_t)key[12]) | ((uint32_t)key[13] << 8) | ((uint32_t)key[14] << 16) | ((uint32_t)key[15] << 24);
    ctx->state[8] = ((uint32_t)key[16]) | ((uint32_t)key[17] << 8) | ((uint32_t)key[18] << 16) | ((uint32_t)key[19] << 24);
    ctx->state[9] = ((uint32_t)key[20]) | ((uint32_t)key[21] << 8) | ((uint32_t)key[22] << 16) | ((uint32_t)key[23] << 24);
    ctx->state[10] = ((uint32_t)key[24]) | ((uint32_t)key[25] << 8) | ((uint32_t)key[26] << 16) | ((uint32_t)key[27] << 24);
    ctx->state[11] = ((uint32_t)key[28]) | ((uint32_t)key[29] << 8) | ((uint32_t)key[30] << 16) | ((uint32_t)key[31] << 24);
    
    /* Block counter (1 word = 32-bit, use low 32 bits of counter parameter) */
    ctx->state[12] = (uint32_t)(counter & 0xFFFFFFFF);
    
    /* Nonce (3 words = 12 bytes, little-endian) */
    ctx->state[13] = ((uint32_t)nonce[0]) | ((uint32_t)nonce[1] << 8) | ((uint32_t)nonce[2] << 16) | ((uint32_t)nonce[3] << 24);
    ctx->state[14] = ((uint32_t)nonce[4]) | ((uint32_t)nonce[5] << 8) | ((uint32_t)nonce[6] << 16) | ((uint32_t)nonce[7] << 24);
    ctx->state[15] = ((uint32_t)nonce[8]) | ((uint32_t)nonce[9] << 8) | ((uint32_t)nonce[10] << 16) | ((uint32_t)nonce[11] << 24);
    
    /* Store key and nonce for potential reuse */
    memcpy(ctx->key, key, NOXTLS_CHACHA20_KEY_SIZE);
    memcpy(ctx->nonce, nonce, NOXTLS_CHACHA20_NONCE_SIZE);
    ctx->counter = counter;
    ctx->keystream_pos = NOXTLS_CHACHA20_BLOCK_SIZE; /* Force generation of first block */
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Generate next keystream block
 */
static void chacha20_generate_keystream(noxtls_chacha20_context_t *ctx)
{
    chacha20_block(ctx->state, ctx->keystream);
    ctx->keystream_pos = 0;
    
    /* Increment counter for next block */
    ctx->state[12]++;
    if(ctx->state[12] == 0) {
        /* Counter overflow - increment high word if we were using 64-bit counter */
        /* For RFC 7539, we only use 32-bit counter, so this shouldn't happen in practice */
        /* But we'll handle it gracefully */
    }
}

/**
 * @brief Encrypt/Decrypt data using ChaCha20
 */
noxtls_return_t noxtls_chacha20_process(noxtls_chacha20_context_t *ctx,
                     const uint8_t *input,
                     uint8_t *output,
                     uint32_t input_len)
{
    uint32_t i;
    
    if(ctx == NULL || input == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    for(i = 0; i < input_len; i++) {
        /* Generate new keystream block if needed */
        if(ctx->keystream_pos >= NOXTLS_CHACHA20_BLOCK_SIZE) {
            chacha20_generate_keystream(ctx);
        }
        
        /* XOR input with keystream */
        output[i] = input[i] ^ ctx->keystream[ctx->keystream_pos];
        ctx->keystream_pos++;
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Encrypt data using ChaCha20 (convenience function)
 */
noxtls_return_t noxtls_chacha20_encrypt(const uint8_t *key,
                     const uint8_t *nonce,
                     uint64_t counter,
                     const uint8_t *input,
                     uint32_t input_len,
                     uint8_t *output)
{
    noxtls_chacha20_context_t ctx = {0};
    
    if(key == NULL || nonce == NULL || input == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    { noxtls_return_t r = noxtls_chacha20_init(&ctx, key, nonce, counter);
    if(r != NOXTLS_RETURN_SUCCESS) return r; }
    
    return noxtls_chacha20_process(&ctx, input, output, input_len);
}

/**
 * @brief Decrypt data using ChaCha20 (convenience function)
 */
noxtls_return_t noxtls_chacha20_decrypt(const uint8_t *key,
                     const uint8_t *nonce,
                     uint64_t counter,
                     const uint8_t *input,
                     uint32_t input_len,
                     uint8_t *output)
{
    /* ChaCha20 encryption and decryption are identical */
    return noxtls_chacha20_encrypt(key, nonce, counter, input, input_len, output);
}

/**
 * @brief Self-test function
 * 
 * Tests against known test vectors from RFC 7539
 */
noxtls_return_t noxtls_chacha20_self_test(void)
{
    /* Test Vector from RFC 7539 Section 2.3.2 */
    const uint8_t test_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    /* RFC 7539/8439 Section 2.3.2: Nonce = 00:00:00:09:00:00:00:4a:00:00:00:00 */
    const uint8_t test_nonce[12] = {
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };
    
    const uint64_t test_counter = 1;
    
    const uint8_t expected_keystream[NOXTLS_CHACHA20_BLOCK_SIZE] = {
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
        0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
        0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
        0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
        0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e
    };
    
    uint8_t keystream[NOXTLS_CHACHA20_BLOCK_SIZE];
    noxtls_chacha20_context_t ctx;
    uint32_t i;
    
    NOXTLS_CHACHA20_DEBUG_PRINT("Running ChaCha20 self-test...\n");
    
    /* Initialize context */
    if(noxtls_chacha20_init(&ctx, test_key, test_nonce, test_counter) != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("ChaCha20 self-test FAILED: Initialization failed\n");
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Generate first keystream block */
    chacha20_generate_keystream(&ctx);
    memcpy(keystream, ctx.keystream, NOXTLS_CHACHA20_BLOCK_SIZE);
    
    /* Compare with expected output */
    for(i = 0; i < NOXTLS_CHACHA20_BLOCK_SIZE; i++) {
        if(keystream[i] != expected_keystream[i]) {
            noxtls_debug_printf("ChaCha20 self-test FAILED: Mismatch at byte %u\n", i);
            noxtls_debug_printf("  Expected: 0x%02x, Got: 0x%02x\n", expected_keystream[i], keystream[i]);
            return NOXTLS_RETURN_FAILED;
        }
    }
    
    NOXTLS_CHACHA20_DEBUG_PRINT("ChaCha20 self-test PASSED\n");
    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_CHACHA20_POLY1305 */
