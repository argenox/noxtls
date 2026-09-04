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
* File:    noxtls_chacha20.c
* Summary: ChaCha20 Stream Cipher Implementation
*
* Implementation of ChaCha20 as specified in RFC 7539
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */

#include <stdint.h>
#include <string.h>
#include "common/noxtls_ct.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_chacha20.h"

#if NOXTLS_FEATURE_CHACHA20_POLY1305

#if NOXTLS_CHACHA20_DEBUG
#define NOXTLS_CHACHA20_DEBUG_PRINT(fmt, ...) noxtls_debug_printf((const uint8_t *)"[CHACHA20_DEBUG] " fmt, ##__VA_ARGS__)
#else
/* Directive: empty debug macro expands to (void)0. */
#define NOXTLS_CHACHA20_DEBUG_PRINT(fmt, ...) ((void)0)
#endif

/**
 * @brief Rotate left (32-bit)
 */
static inline uint32_t chacha20_rotl32(uint32_t x, uint32_t n)
{
    /* Only 7/8/12/16 are used by quarter_round (Rule 12.2). */
    switch(n) {
    case 7U:  return (uint32_t)((x << 7U) | (x >> 25U));
    case 8U:  return (uint32_t)((x << 8U) | (x >> 24U));
    case 12U: return (uint32_t)((x << 12U) | (x >> 20U));
    case 16U: return (uint32_t)((x << 16U) | (x >> 16U));
    default:  return x;
    }
}

/**
 * @brief ChaCha20 Quarter Round (in-place on state words by index)
 */
static void chacha20_quarter_round(uint32_t state[NOXTLS_CHACHA20_STATE_WORDS],
                                   uint32_t ai, uint32_t bi, uint32_t ci, uint32_t di)
{
    state[ai] += state[bi];
    state[di] ^= state[ai];
    state[di] = chacha20_rotl32(state[di], 16U);

    state[ci] += state[di];
    state[bi] ^= state[ci];
    state[bi] = chacha20_rotl32(state[bi], 12U);

    state[ai] += state[bi];
    state[di] ^= state[ai];
    state[di] = chacha20_rotl32(state[di], 8U);

    state[ci] += state[di];
    state[bi] ^= state[ci];
    state[bi] = chacha20_rotl32(state[bi], 7U);
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
    uint32_t i = 0U;

    /* Copy state to working state */
    for (i = 0U; i < (uint32_t)NOXTLS_CHACHA20_STATE_WORDS; i += 1U) {
        working_state[i] = state[i];
    }

    /* Perform NOXTLS_CHACHA20_ROUNDS rounds (NOXTLS_CHACHA20_DOUBLE_ROUNDS double rounds) */
    for (i = 0U; i < (uint32_t)NOXTLS_CHACHA20_DOUBLE_ROUNDS; i += 1U) {
        /* Column rounds */
        chacha20_quarter_round(working_state, 0U, 4U, 8U, 12U);
        chacha20_quarter_round(working_state, 1U, 5U, 9U, 13U);
        chacha20_quarter_round(working_state, 2U, 6U, 10U, 14U);
        chacha20_quarter_round(working_state, 3U, 7U, 11U, 15U);

        /* Diagonal rounds */
        chacha20_quarter_round(working_state, 0U, 5U, 10U, 15U);
        chacha20_quarter_round(working_state, 1U, 6U, 11U, 12U);
        chacha20_quarter_round(working_state, 2U, 7U, 8U, 13U);
        chacha20_quarter_round(working_state, 3U, 4U, 9U, 14U);
    }

    /* Add original state to working state */
    for (i = 0U; i < (uint32_t)NOXTLS_CHACHA20_STATE_WORDS; i += 1U) {
        working_state[i] += state[i];
    }

    /* Convert to little-endian bytes (fixed shifts; Rule 12.2). */
    for (i = 0U; i < (uint32_t)NOXTLS_CHACHA20_STATE_WORDS; i += 1U) {
        uint32_t w = working_state[i];
        output[(i * 4U) + 0U] = (uint8_t)w;
        output[(i * 4U) + 1U] = (uint8_t)(w >> 8U);
        output[(i * 4U) + 2U] = (uint8_t)(w >> 16U);
        output[(i * 4U) + 3U] = (uint8_t)(w >> 24U);
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
    /* ChaCha20 constants (Rule 8.9). */
    /* ChaCha20 Constants */
    static const uint32_t NOXTLS_CHACHA20_CONSTANTS[4] = {
        0x61707865U,  /* "expa" */
        0x3320646eU,  /* "nd 3" */
        0x79622d32U,  /* "2-by" */
        0x6b206574U   /* "te k" */
    };


    if ((ctx == NULL) || (key == NULL) || (nonce == NULL)) {
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
    ctx->state[4] = ((uint32_t)key[0]) | (((uint32_t)key[1]) << 8U) | (((uint32_t)key[2]) << 16U) | (((uint32_t)key[3]) << 24U);
    ctx->state[5] = ((uint32_t)key[4]) | (((uint32_t)key[5]) << 8U) | (((uint32_t)key[6]) << 16U) | (((uint32_t)key[7]) << 24U);
    ctx->state[6] = ((uint32_t)key[8]) | (((uint32_t)key[9]) << 8U) | (((uint32_t)key[10]) << 16U) | (((uint32_t)key[11]) << 24U);
    ctx->state[7] = ((uint32_t)key[12]) | (((uint32_t)key[13]) << 8U) | (((uint32_t)key[14]) << 16U) | (((uint32_t)key[15]) << 24U);
    ctx->state[8] = ((uint32_t)key[16]) | (((uint32_t)key[17]) << 8U) | (((uint32_t)key[18]) << 16U) | (((uint32_t)key[19]) << 24U);
    ctx->state[9] = ((uint32_t)key[20]) | (((uint32_t)key[21]) << 8U) | (((uint32_t)key[22]) << 16U) | (((uint32_t)key[23]) << 24U);
    ctx->state[10] = ((uint32_t)key[24]) | (((uint32_t)key[25]) << 8U) | (((uint32_t)key[26]) << 16U) | (((uint32_t)key[27]) << 24U);
    ctx->state[11] = ((uint32_t)key[28]) | (((uint32_t)key[29]) << 8U) | (((uint32_t)key[30]) << 16U) | (((uint32_t)key[31]) << 24U);

    /* Block counter (1 word = 32-bit, use low 32 bits of counter parameter) */
    ctx->state[12] = (uint32_t)(counter & 0xFFFFFFFFU);

    /* Nonce (3 words = 12 bytes, little-endian) */
    ctx->state[13] = ((uint32_t)nonce[0]) | (((uint32_t)nonce[1]) << 8U) | (((uint32_t)nonce[2]) << 16U) | (((uint32_t)nonce[3]) << 24U);
    ctx->state[14] = ((uint32_t)nonce[4]) | (((uint32_t)nonce[5]) << 8U) | (((uint32_t)nonce[6]) << 16U) | (((uint32_t)nonce[7]) << 24U);
    ctx->state[15] = ((uint32_t)nonce[8]) | (((uint32_t)nonce[9]) << 8U) | (((uint32_t)nonce[10]) << 16U) | (((uint32_t)nonce[11]) << 24U);

    /* Store key and nonce for potential reuse */
    noxtls_copy_u8(ctx->key, sizeof(ctx->key), key, (size_t)NOXTLS_CHACHA20_KEY_SIZE);
    noxtls_copy_u8(ctx->nonce, sizeof(ctx->nonce), nonce, (size_t)NOXTLS_CHACHA20_NONCE_SIZE);
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
    ctx->keystream_pos = 0U;

    /* Increment counter for next block */
    ctx->state[12] += 1U;
    if (ctx->state[12] == 0U) {
        /* Counter overflow - RFC 7539 uses 32-bit counter; rare wrap handled as no-op. */
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
    uint32_t i = 0U;

    if ((ctx == NULL) || (input == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    for (i = 0U; i < input_len; i += 1U) {
        /* Generate new keystream block if needed */
        if (ctx->keystream_pos >= (uint32_t)NOXTLS_CHACHA20_BLOCK_SIZE) {
            chacha20_generate_keystream(ctx);
        }

        /* XOR input with keystream */
        output[i] = (uint8_t)(input[i] ^ ctx->keystream[ctx->keystream_pos]);
        ctx->keystream_pos += 1U;
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
    noxtls_chacha20_context_t ctx;
    noxtls_return_t r = NOXTLS_RETURN_FAILED;

    (void)memset(&ctx, 0, sizeof(ctx));

    if ((key == NULL) || (nonce == NULL) || (input == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    r = noxtls_chacha20_init(&ctx, key, nonce, counter);
    if (r != NOXTLS_RETURN_SUCCESS) {
        return r;
    }

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
        0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU,
        0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U,
        0x18U, 0x19U, 0x1aU, 0x1bU, 0x1cU, 0x1dU, 0x1eU, 0x1fU
    };

    /* RFC 7539/8439 Section 2.3.2: Nonce = 00:00:00:09:00:00:00:4a:00:00:00:00 */
    const uint8_t test_nonce[12] = {
        0x00U, 0x00U, 0x00U, 0x09U, 0x00U, 0x00U, 0x00U, 0x4aU,
        0x00U, 0x00U, 0x00U, 0x00U
    };

    const uint64_t test_counter = 1U;

    const uint8_t expected_keystream[NOXTLS_CHACHA20_BLOCK_SIZE] = {
        0x10U, 0xf1U, 0xe7U, 0xe4U, 0xd1U, 0x3bU, 0x59U, 0x15U,
        0x50U, 0x0fU, 0xddU, 0x1fU, 0xa3U, 0x20U, 0x71U, 0xc4U,
        0xc7U, 0xd1U, 0xf4U, 0xc7U, 0x33U, 0xc0U, 0x68U, 0x03U,
        0x04U, 0x22U, 0xaaU, 0x9aU, 0xc3U, 0xd4U, 0x6cU, 0x4eU,
        0xd2U, 0x82U, 0x64U, 0x46U, 0x07U, 0x9fU, 0xaaU, 0x09U,
        0x14U, 0xc2U, 0xd7U, 0x05U, 0xd9U, 0x8bU, 0x02U, 0xa2U,
        0xb5U, 0x12U, 0x9cU, 0xd1U, 0xdeU, 0x16U, 0x4eU, 0xb9U,
        0xcbU, 0xd0U, 0x83U, 0xe8U, 0xa2U, 0x50U, 0x3cU, 0x4eU
    };

    uint8_t keystream[NOXTLS_CHACHA20_BLOCK_SIZE];
    noxtls_chacha20_context_t ctx;
    uint32_t i = 0U;

    NOXTLS_CHACHA20_DEBUG_PRINT("Running ChaCha20 self-test...\n");

    /* Initialize context */
    if (noxtls_chacha20_init(&ctx, test_key, test_nonce, test_counter) != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_debug_printf((const uint8_t *)"ChaCha20 self-test FAILED: Initialization failed\n");
        return NOXTLS_RETURN_FAILED;
    }

    /* Generate first keystream block */
    chacha20_generate_keystream(&ctx);
    noxtls_copy_u8(keystream, sizeof(keystream), ctx.keystream, (size_t)NOXTLS_CHACHA20_BLOCK_SIZE);

    /* Compare with expected output */
    for (i = 0U; i < (uint32_t)NOXTLS_CHACHA20_BLOCK_SIZE; i += 1U) {
        if (keystream[i] != expected_keystream[i]) {
            (void)noxtls_debug_printf((const uint8_t *)"ChaCha20 self-test FAILED: Mismatch at byte %u\n", i);
            (void)noxtls_debug_printf((const uint8_t *)"  Expected: 0x%02x, Got: 0x%02x\n", expected_keystream[i], keystream[i]);
            return NOXTLS_RETURN_FAILED;
        }
    }

    NOXTLS_CHACHA20_DEBUG_PRINT("ChaCha20 self-test PASSED\n");
    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_CHACHA20_POLY1305 */
