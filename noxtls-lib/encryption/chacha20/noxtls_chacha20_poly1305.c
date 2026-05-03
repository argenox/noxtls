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
* File:    noxtls_chacha20_poly1305.c
* Summary: ChaCha20-Poly1305 Authenticated Encryption Implementation
*
* Implementation of ChaCha20-Poly1305 as specified in RFC 8439
*
*/

/** @addtogroup noxtls_encryption */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "common/noxtls_debug_printf.h"
#include "noxtls_chacha20_poly1305.h"

#if NOXTLS_FEATURE_CHACHA20_POLY1305

#if NOXTLS_CHACHA20_POLY1305_DEBUG
#define CHACHA20_POLY1305_DEBUG_PRINT(fmt, ...) noxtls_debug_printf("[CHACHA20_POLY1305_DEBUG] " fmt, ##__VA_ARGS__)
#else
#define CHACHA20_POLY1305_DEBUG_PRINT(fmt, ...) ((void)0)
#endif

/* Poly1305 modulus: 2^130 - 5 */
#define POLY1305_P ((uint64_t)0x3FFFFFFFFFFFFFFFULL)

static uint32_t poly1305_load_le32(const uint8_t *p)
{
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/**
 * @brief Initialize Poly1305 context
 */
noxtls_return_t poly1305_init(poly1305_context_t *ctx, const uint8_t *key)
{
    if(ctx == NULL || key == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    ctx->r[0] = (poly1305_load_le32(key + 0)) & 0x3ffffff;
    ctx->r[1] = (poly1305_load_le32(key + 3) >> 2) & 0x3ffff03;
    ctx->r[2] = (poly1305_load_le32(key + 6) >> 4) & 0x3ffc0ff;
    ctx->r[3] = (poly1305_load_le32(key + 9) >> 6) & 0x3f03fff;
    ctx->r[4] = (poly1305_load_le32(key + 12) >> 8) & 0x00fffff;

    /* Extract s (pad) from key[16..31] */
    ctx->pad[0] = poly1305_load_le32(key + 16);
    ctx->pad[1] = poly1305_load_le32(key + 20);
    ctx->pad[2] = poly1305_load_le32(key + 24);
    ctx->pad[3] = poly1305_load_le32(key + 28);

    memset(ctx->h, 0, sizeof(ctx->h));
    ctx->buffer_len = 0;
    ctx->finished = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Process a block in Poly1305
 * @param ctx Poly1305 context
 * @param block Block data (at least block_len bytes)
 * @param block_len Number of bytes in block (1-16). For full block adds 2^128; for partial adds 2^(8*block_len).
 */
static void poly1305_blocks(poly1305_context_t *ctx, const uint8_t *block, uint32_t bytes)
{
    const uint32_t hibit = (ctx->finished != NOXTLS_RETURN_SUCCESS) ? 0 : (1U << 24);
    uint32_t r0 = ctx->r[0], r1 = ctx->r[1], r2 = ctx->r[2], r3 = ctx->r[3], r4 = ctx->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2], h3 = ctx->h[3], h4 = ctx->h[4];

    while(bytes >= 16) {
        h0 += (poly1305_load_le32(block + 0)) & 0x3ffffff;
        h1 += (poly1305_load_le32(block + 3) >> 2) & 0x3ffffff;
        h2 += (poly1305_load_le32(block + 6) >> 4) & 0x3ffffff;
        h3 += (poly1305_load_le32(block + 9) >> 6) & 0x3ffffff;
        h4 += (poly1305_load_le32(block + 12) >> 8) | hibit;

        uint64_t d0 = ((uint64_t)h0 * r0) + ((uint64_t)h1 * s4) + ((uint64_t)h2 * s3) + ((uint64_t)h3 * s2) + ((uint64_t)h4 * s1);
        uint64_t d1 = ((uint64_t)h0 * r1) + ((uint64_t)h1 * r0) + ((uint64_t)h2 * s4) + ((uint64_t)h3 * s3) + ((uint64_t)h4 * s2);
        uint64_t d2 = ((uint64_t)h0 * r2) + ((uint64_t)h1 * r1) + ((uint64_t)h2 * r0) + ((uint64_t)h3 * s4) + ((uint64_t)h4 * s3);
        uint64_t d3 = ((uint64_t)h0 * r3) + ((uint64_t)h1 * r2) + ((uint64_t)h2 * r1) + ((uint64_t)h3 * r0) + ((uint64_t)h4 * s4);
        uint64_t d4 = ((uint64_t)h0 * r4) + ((uint64_t)h1 * r3) + ((uint64_t)h2 * r2) + ((uint64_t)h3 * r1) + ((uint64_t)h4 * r0);

        uint32_t c;
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff; d1 += c;
        c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff; d2 += c;
        c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff; d3 += c;
        c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff; d4 += c;
        c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5;
        c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

        block += 16;
        bytes -= 16;
    }

    ctx->h[0] = h0;
    ctx->h[1] = h1;
    ctx->h[2] = h2;
    ctx->h[3] = h3;
    ctx->h[4] = h4;
}

/**
 * @brief Update Poly1305 with data
 */
noxtls_return_t poly1305_update(poly1305_context_t *ctx, const uint8_t *data, uint32_t data_len)
{
    if(ctx == NULL || (data == NULL && data_len > 0)) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(data_len == 0) {
        return NOXTLS_RETURN_SUCCESS;
    }
    
    /* Process any buffered data first */
    if(ctx->buffer_len > 0) {
        uint32_t bytes_to_process = 16 - ctx->buffer_len;
        if(bytes_to_process > data_len) {
            bytes_to_process = data_len;
        }

        memcpy(ctx->buffer + ctx->buffer_len, data, bytes_to_process);
        ctx->buffer_len += bytes_to_process;
        data += bytes_to_process;
        data_len -= bytes_to_process;

        if(ctx->buffer_len < 16) {
            return NOXTLS_RETURN_SUCCESS;
        }

        poly1305_blocks(ctx, ctx->buffer, 16);
        ctx->buffer_len = 0;
    }

    /* Process full blocks */
    if(data_len >= 16) {
        uint32_t block_bytes = data_len & ~0xF;
        poly1305_blocks(ctx, data, block_bytes);
        data += block_bytes;
        data_len -= block_bytes;
    }

    /* Buffer remaining bytes */
    if(data_len > 0) {
        memcpy(ctx->buffer, data, data_len);
        ctx->buffer_len = data_len;
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Finalize Poly1305 and generate tag
 */
noxtls_return_t poly1305_final(poly1305_context_t *ctx, uint8_t *tag)
{
    uint32_t h0, h1, h2, h3, h4;
    uint32_t g0, g1, g2, g3, g4;
    uint32_t c;
    uint32_t i;
    
    if(ctx == NULL || tag == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Process final partial block if any */
    if(ctx->buffer_len > 0) {
        ctx->buffer[ctx->buffer_len] = 1;
        memset(ctx->buffer + ctx->buffer_len + 1, 0, 16 - ctx->buffer_len - 1);
        ctx->finished = 1;
        poly1305_blocks(ctx, ctx->buffer, 16);
    }

    /* Fully carry-propagate h */
    h0 = ctx->h[0];
    h1 = ctx->h[1];
    h2 = ctx->h[2];
    h3 = ctx->h[3];
    h4 = ctx->h[4];

    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    /* Compute h + -p */
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - (1U << 26);

    /* Select h if h < p, or h + -p if h >= p */
    {
        uint32_t mask = (g4 >> 31) - 1;
        g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
        mask = ~mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;
    }

    /* h = h % (2^128) */
    h0 = ((h0) | (h1 << 26)) & 0xFFFFFFFF;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xFFFFFFFF;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xFFFFFFFF;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xFFFFFFFF;

    /* mac = (h + pad) % (2^128) */
    {
        uint64_t f;
        f = (uint64_t)h0 + ctx->pad[0]; h0 = (uint32_t)f;
        f = (uint64_t)h1 + ctx->pad[1] + (f >> 32); h1 = (uint32_t)f;
        f = (uint64_t)h2 + ctx->pad[2] + (f >> 32); h2 = (uint32_t)f;
        f = (uint64_t)h3 + ctx->pad[3] + (f >> 32); h3 = (uint32_t)f;
    }

    for(i = 0; i < 4; i++) {
        tag[i] = (uint8_t)(h0 >> (8 * i));
        tag[i + 4] = (uint8_t)(h1 >> (8 * i));
        tag[i + 8] = (uint8_t)(h2 >> (8 * i));
        tag[i + 12] = (uint8_t)(h3 >> (8 * i));
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Compute Poly1305 MAC (convenience function)
 */
noxtls_return_t poly1305_mac(const uint8_t *key, const uint8_t *data, uint32_t data_len, uint8_t *tag)
{
    poly1305_context_t ctx;
    
    if(key == NULL || (data == NULL && data_len > 0) || tag == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(poly1305_init(&ctx, key) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    
    if(poly1305_update(&ctx, data, data_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    
    return poly1305_final(&ctx, tag);
}

/**
 * @brief Generate Poly1305 key from ChaCha20
 * 
 * Uses ChaCha20 with key and nonce to generate a one-time Poly1305 key
 */
static noxtls_return_t chacha20_poly1305_generate_key(const uint8_t *key, 
                                           const uint8_t *nonce, 
                                           uint8_t *poly_key)
{
    const uint8_t zero_block[64] = {0};
    uint8_t key_block[64] = {0};
    chacha20_context_t ctx;
    
    /* Generate one block of ChaCha20 keystream with counter=0 */
    if(chacha20_init(&ctx, key, nonce, 0) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(chacha20_process(&ctx, zero_block, key_block, 64) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_NULL;
    }

    /* Per RFC 8439, use first 32 bytes as Poly1305 key */
    memcpy(poly_key, key_block, 32);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Encrypt and authenticate data using ChaCha20-Poly1305
 */
noxtls_return_t chacha20_poly1305_encrypt(const uint8_t *key,
                               const uint8_t *nonce,
                               const uint8_t *aad,
                               uint32_t aad_len,
                               const uint8_t *plaintext,
                               uint32_t plaintext_len,
                               uint8_t *ciphertext,
                               uint8_t *tag)
{
    uint8_t poly_key[32];
    poly1305_context_t poly_ctx;
    uint8_t length_block[16];
    
    if(key == NULL || nonce == NULL || tag == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if((plaintext == NULL && plaintext_len > 0) || (ciphertext == NULL && plaintext_len > 0)) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Generate Poly1305 key from ChaCha20 */
    if(chacha20_poly1305_generate_key(key, nonce, poly_key) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Encrypt plaintext using ChaCha20 (counter starts at 1, not 0) */
    if(plaintext_len > 0) {
        if(chacha20_encrypt(key, nonce, 1, plaintext, plaintext_len, ciphertext) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_NULL;
        }
    }
    
    /* Initialize Poly1305 */
    if(poly1305_init(&poly_ctx, poly_key) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Authenticate AAD */
    if(aad_len > 0 && aad != NULL) {
        if(poly1305_update(&poly_ctx, aad, aad_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_NULL;
        }
    }
    /* Pad AAD to 16-byte boundary */
    if((aad_len & 15) != 0) {
        const uint8_t pad[16] = {0};
        uint32_t pad_len = 16 - (aad_len & 15);
        if(poly1305_update(&poly_ctx, pad, pad_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_NULL;
        }
    }
    
    /* Authenticate ciphertext */
    if(plaintext_len > 0) {
        if(poly1305_update(&poly_ctx, ciphertext, plaintext_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_NULL;
        }
    }
    /* Pad ciphertext to 16-byte boundary */
    if((plaintext_len & 15) != NOXTLS_RETURN_SUCCESS) {
        const uint8_t pad[16] = {0};
        uint32_t pad_len = 16 - (plaintext_len & 15);
        if(poly1305_update(&poly_ctx, pad, pad_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_NULL;
        }
    }
    
    /* Authenticate lengths: AAD length (64 bits) + ciphertext length (64 bits) */
    memset(length_block, 0, 16);
    {
        uint64_t aad_len64 = (uint64_t)aad_len;
        uint64_t text_len64 = (uint64_t)plaintext_len;
        for(uint32_t i = 0; i < 8; i++) {
            length_block[i] = (uint8_t)(aad_len64 >> (i * 8));
        }
        for(uint32_t i = 0; i < 8; i++) {
            length_block[i + 8] = (uint8_t)(text_len64 >> (i * 8));
        }
    }
    
    if(poly1305_update(&poly_ctx, length_block, 16) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Generate tag */
    if(poly1305_final(&poly_ctx, tag) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_NULL;
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Decrypt and verify data using ChaCha20-Poly1305
 */
noxtls_return_t chacha20_poly1305_decrypt(const uint8_t *key,
                               const uint8_t *nonce,
                               const uint8_t *aad,
                               uint32_t aad_len,
                               const uint8_t *ciphertext,
                               uint32_t ciphertext_len,
                               const uint8_t *tag,
                               uint8_t *plaintext)
{
    uint8_t poly_key[32];
    poly1305_context_t poly_ctx;
    uint8_t computed_tag[16];
    uint8_t length_block[16];
    int tag_match;
    
    if(key == NULL || nonce == NULL || tag == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if((ciphertext == NULL && ciphertext_len > 0) || (plaintext == NULL && ciphertext_len > 0)) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Generate Poly1305 key from ChaCha20 */
    if(chacha20_poly1305_generate_key(key, nonce, poly_key) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Initialize Poly1305 */
    if(poly1305_init(&poly_ctx, poly_key) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Authenticate AAD */
    if(aad_len > 0 && aad != NULL) {
        if(poly1305_update(&poly_ctx, aad, aad_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_NULL;
        }
    }
    /* Pad AAD to 16-byte boundary */
    if((aad_len & 15) != 0) {
        const uint8_t pad[16] = {0};
        uint32_t pad_len = 16 - (aad_len & 15);
        if(poly1305_update(&poly_ctx, pad, pad_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_NULL;
        }
    }
    
    /* Authenticate ciphertext */
    if(ciphertext_len > 0 && ciphertext != NULL) {
        if(poly1305_update(&poly_ctx, ciphertext, ciphertext_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_NULL;
        }
    }
    /* Pad ciphertext to 16-byte boundary */
    if((ciphertext_len & 15) != 0) {
        const uint8_t pad[16] = {0};
        uint32_t pad_len = 16 - (ciphertext_len & 15);
        if(poly1305_update(&poly_ctx, pad, pad_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_NULL;
        }
    }
    
    /* Authenticate lengths */
    memset(length_block, 0, 16);
    {
        uint64_t aad_len64 = (uint64_t)aad_len;
        uint64_t text_len64 = (uint64_t)ciphertext_len;
        for(uint32_t i = 0; i < 8; i++) {
            length_block[i] = (uint8_t)(aad_len64 >> (i * 8));
        }
        for(uint32_t i = 0; i < 8; i++) {
            length_block[i + 8] = (uint8_t)(text_len64 >> (i * 8));
        }
    }
    
    if(poly1305_update(&poly_ctx, length_block, 16) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Generate tag */
    if(poly1305_final(&poly_ctx, computed_tag) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Verify tag (constant-time comparison) */
    tag_match = 1;
    for(uint32_t i = 0; i < 16; i++) {
        if(computed_tag[i] != tag[i]) {
            tag_match = 0;
        }
    }
    
    if(!tag_match) {
        /* Authentication failed - don't decrypt */
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    /* Decrypt ciphertext using ChaCha20 (counter starts at 1, not 0) */
    if(ciphertext_len > 0) {
        if(chacha20_decrypt(key, nonce, 1, ciphertext, ciphertext_len, plaintext) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_NULL;
        }
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Self-test function
 * 
 * Tests against known test vectors from RFC 8439
 */
noxtls_return_t chacha20_poly1305_self_test(void)
{
    /* Test vectors from RFC 8439 Section 2.8.2 */
    const uint8_t test_key[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    
    const uint8_t test_nonce[12] = {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47
    };
    
    const uint8_t test_aad[12] = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7
    };
    
    const uint8_t test_plaintext[114] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
        0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
        0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
        0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
        0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
        0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
        0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e
    };
    
    const uint8_t expected_ciphertext[114] = {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16
    };
    
    const uint8_t expected_tag[16] = {
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
    };
    
    uint8_t ciphertext[114];
    uint8_t tag[16];
    uint8_t decrypted[114];
    uint32_t i;
    
    CHACHA20_POLY1305_DEBUG_PRINT("Running ChaCha20-Poly1305 self-test...\n");
    
    /* Test encryption */
    if(chacha20_poly1305_encrypt(test_key, test_nonce, test_aad, 12,
                                  test_plaintext, 114, ciphertext, tag) != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("ChaCha20-Poly1305 self-test FAILED: Encryption failed\n");
        return NOXTLS_RETURN_NULL;
    }
    
    /* Verify ciphertext */
    for(i = 0; i < 114; i++) {
        if(ciphertext[i] != expected_ciphertext[i]) {
            noxtls_debug_printf("ChaCha20-Poly1305 self-test FAILED: Ciphertext mismatch at byte %u\n", i);
            noxtls_debug_printf("  Expected: 0x%02x, Got: 0x%02x\n", expected_ciphertext[i], ciphertext[i]);
            return NOXTLS_RETURN_NULL;
        }
    }
    
    /* Verify tag */
    for(i = 0; i < 16; i++) {
        if(tag[i] != expected_tag[i]) {
            noxtls_debug_printf("ChaCha20-Poly1305 self-test FAILED: Tag mismatch at byte %u\n", i);
            noxtls_debug_printf("  Expected: 0x%02x, Got: 0x%02x\n", expected_tag[i], tag[i]);
            return NOXTLS_RETURN_NULL;
        }
    }
    
    /* Test decryption */
    if(chacha20_poly1305_decrypt(test_key, test_nonce, test_aad, 12,
                                  ciphertext, 114, tag, decrypted) != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("ChaCha20-Poly1305 self-test FAILED: Decryption failed\n");
        return NOXTLS_RETURN_NULL;
    }
    
    /* Verify plaintext */
    for(i = 0; i < 114; i++) {
        if(decrypted[i] != test_plaintext[i]) {
            noxtls_debug_printf("ChaCha20-Poly1305 self-test FAILED: Plaintext mismatch at byte %u\n", i);
            return NOXTLS_RETURN_NULL;
        }
    }
    
    CHACHA20_POLY1305_DEBUG_PRINT("ChaCha20-Poly1305 self-test PASSED\n");
    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_CHACHA20_POLY1305 */
