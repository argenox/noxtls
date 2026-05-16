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
* File:    noxtls_rc4.c
* Summary: RC4 Stream Cipher Implementation
*
* RC4: Key-Scheduling Algorithm (KSA) + Pseudo-Random Generation Algorithm (PRGA).
* Key length 1–256 bytes. Security note: RC4 is deprecated; use only for legacy.
*
*/

/** @addtogroup noxtls_encryption */

#include <stdint.h>
#include <string.h>
#include "common/noxtls_debug_printf.h"
#include "noxtls_rc4.h"

#if NOXTLS_FEATURE_RC4

#if NOXTLS_RC4_DEBUG
#define RC4_DEBUG_PRINT(fmt, ...) noxtls_debug_printf("[RC4_DEBUG] " fmt, ##__VA_ARGS__)
#else
#define RC4_DEBUG_PRINT(fmt, ...) ((void)0)
#endif

/**
 * @brief Key-Scheduling Algorithm: initialize S and scramble with key
 */
static void rc4_ksa(noxtls_rc4_context_t *ctx, const uint8_t *key, uint32_t key_len)
{
    uint32_t i;
    uint8_t j = 0;

    for(i = 0; i < 256; i++) {
        ctx->S[i] = (uint8_t)i;
    }
    for(i = 0; i < 256; i++) {
        uint8_t t;
        j = (uint8_t)(j + ctx->S[i] + key[i % key_len]);
        t = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = t;
    }
    ctx->i = 0;
    ctx->j = 0;
}

/**
 * @brief Generate next byte of keystream (PRGA), update state
 */
static uint8_t rc4_prga_byte(noxtls_rc4_context_t *ctx)
{
    uint8_t t;
    ctx->i = (uint8_t)(ctx->i + 1);
    ctx->j = (uint8_t)(ctx->j + ctx->S[ctx->i]);
    t = ctx->S[ctx->i];
    ctx->S[ctx->i] = ctx->S[ctx->j];
    ctx->S[ctx->j] = t;
    return ctx->S[(uint8_t)(ctx->S[ctx->i] + ctx->S[ctx->j])];
}

noxtls_return_t noxtls_rc4_init(noxtls_rc4_context_t *ctx, const uint8_t *key, uint32_t key_len)
{
    if(ctx == NULL || key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(key_len < NOXTLS_RC4_KEY_MIN_BYTES || key_len > NOXTLS_RC4_KEY_MAX_BYTES) {
        return NOXTLS_RETURN_FAILED;
    }
    rc4_ksa(ctx, key, key_len);
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_rc4_process(noxtls_rc4_context_t *ctx,
                              const uint8_t *input,
                              uint8_t *output,
                              uint32_t input_len)
{
    uint32_t n;

    if(ctx == NULL || input == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    for(n = 0; n < input_len; n++) {
        output[n] = input[n] ^ rc4_prga_byte(ctx);
    }
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_rc4_encrypt(const uint8_t *key, uint32_t key_len,
                            const uint8_t *input, uint32_t input_len,
                            uint8_t *output)
{
    noxtls_rc4_context_t ctx;

    if(key == NULL || input == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(noxtls_rc4_init(&ctx, key, key_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    return noxtls_rc4_process(&ctx, input, output, input_len);
}

noxtls_return_t noxtls_rc4_decrypt(const uint8_t *key, uint32_t key_len,
                            const uint8_t *input, uint32_t input_len,
                            uint8_t *output)
{
    /* RC4 encryption and decryption are identical */
    return noxtls_rc4_encrypt(key, key_len, input, input_len, output);
}

/**
 * @brief Self-test using RFC 6229 test vector (40-bit key 0x0102030405, offset 0)
 */
noxtls_return_t noxtls_rc4_self_test(void)
{
    const uint8_t key[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    const uint8_t expected[16] = {
        0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27,
        0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11, 0x18, 0xa8
    };
    uint8_t keystream[16];
    noxtls_rc4_context_t ctx;
    uint32_t i;

    RC4_DEBUG_PRINT("Running RC4 self-test...\n");

    if(noxtls_rc4_init(&ctx, key, (uint32_t)sizeof(key)) != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("RC4 self-test FAILED: init failed\n");
        return NOXTLS_RETURN_FAILED;
    }
    /* First 16 bytes of keystream = encrypt zeros */
    memset(keystream, 0, sizeof(keystream));
    if(noxtls_rc4_process(&ctx, keystream, keystream, 16) != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("RC4 self-test FAILED: process failed\n");
        return NOXTLS_RETURN_FAILED;
    }
    for(i = 0; i < 16; i++) {
        if(keystream[i] != expected[i]) {
            noxtls_debug_printf("RC4 self-test FAILED: byte %u expected 0x%02x got 0x%02x\n",
                               (unsigned)i, expected[i], keystream[i]);
            return NOXTLS_RETURN_FAILED;
        }
    }
    RC4_DEBUG_PRINT("RC4 self-test PASSED\n");
    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_RC4 */
