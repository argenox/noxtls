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
* File:    noxtls_rc4.c
* Summary: RC4 Stream Cipher Implementation
*
* RC4: Key-Scheduling Algorithm (KSA) + Pseudo-Random Generation Algorithm (PRGA).
* Key length 1–256 bytes. Security note: RC4 is deprecated; use only for legacy.
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */

#include <stdint.h>
#include <string.h>
#include "common/noxtls_debug_printf.h"
#include "noxtls_rc4.h"
#include "noxtls_ct.h"

#if NOXTLS_FEATURE_RC4

#if NOXTLS_RC4_DEBUG
/* Directive: debug-only printf wrapper; prefer macro for optional compile-out. */
#define RC4_DEBUG_PRINT(fmt, ...) noxtls_debug_printf((const uint8_t *)"[RC4_DEBUG] " fmt, ##__VA_ARGS__)
#else
#define RC4_DEBUG_PRINT(fmt, ...) ((void)0)
#endif

/**
 * @brief Key-Scheduling Algorithm: initialize S and scramble with key
 */
/* S-box indices are always in 0..255. */
static void rc4_ksa(noxtls_rc4_context_t *ctx, const uint8_t *key, uint32_t key_len)
{
    uint32_t i = 0U;
    uint8_t j = 0U;

    for (i = 0U; i < 256U; i += 1U) {
        ctx->S[i] = (uint8_t)i;
    }
    for (i = 0U; i < 256U; i += 1U) {
        uint8_t t = 0U;
        j = (uint8_t)(j + ctx->S[i] + key[i % key_len]);
        t = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = t;
    }
    ctx->i = 0U;
    ctx->j = 0U;
}

/**
 * @brief Generate next byte of keystream (PRGA), update state
 */
static uint8_t rc4_prga_byte(noxtls_rc4_context_t *ctx)
{
    uint8_t t = 0U;
    ctx->i = (uint8_t)(ctx->i + 1U);
    ctx->j = (uint8_t)(ctx->j + ctx->S[ctx->i]);
    t = ctx->S[ctx->i];
    ctx->S[ctx->i] = ctx->S[ctx->j];
    ctx->S[ctx->j] = t;
    return ctx->S[(uint8_t)(ctx->S[ctx->i] + ctx->S[ctx->j])];
}

/**
 * @brief Initialize RC4 context
 */
noxtls_return_t noxtls_rc4_init(noxtls_rc4_context_t *ctx, const uint8_t *key, uint32_t key_len)
{
    if ((ctx == NULL) || (key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if ((key_len < (uint32_t)NOXTLS_RC4_KEY_MIN_BYTES) || (key_len > (uint32_t)NOXTLS_RC4_KEY_MAX_BYTES)) {
        return NOXTLS_RETURN_FAILED;
    }
    rc4_ksa(ctx, key, key_len);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Encrypt/Decrypt data using RC4
 */
noxtls_return_t noxtls_rc4_process(noxtls_rc4_context_t *ctx,
                              const uint8_t *input,
                              uint8_t *output,
                              uint32_t input_len)
{
    uint32_t n = 0U;

    if ((ctx == NULL) || (input == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    for (n = 0U; n < input_len; n += 1U) {
        output[n] = (uint8_t)(input[n] ^ rc4_prga_byte(ctx));
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Encrypt data using RC4
 */
noxtls_return_t noxtls_rc4_encrypt(const uint8_t *key, uint32_t key_len,
                            const uint8_t *input, uint32_t input_len,
                            uint8_t *output)
{
    noxtls_rc4_context_t ctx;

    if ((key == NULL) || (input == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if (noxtls_rc4_init(&ctx, key, key_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    return noxtls_rc4_process(&ctx, input, output, input_len);
}

/**
 * @brief Decrypt data using RC4
 */
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
    const uint8_t key[] = { 0x01U, 0x02U, 0x03U, 0x04U, 0x05U };
    const uint8_t expected[16] = {
        0xb2U, 0x39U, 0x63U, 0x05U, 0xf0U, 0x3dU, 0xc0U, 0x27U,
        0xccU, 0xc3U, 0x52U, 0x4aU, 0x0aU, 0x11U, 0x18U, 0xa8U
    };
    uint8_t keystream[16];
    noxtls_rc4_context_t ctx;
    uint32_t i = 0U;

    RC4_DEBUG_PRINT("Running RC4 self-test...\n");

    if (noxtls_rc4_init(&ctx, key, (uint32_t)sizeof(key)) != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_debug_printf((const uint8_t *)"RC4 self-test FAILED: init failed\n");
        return NOXTLS_RETURN_FAILED;
    }
    /* First 16 bytes of keystream = encrypt zeros */
    noxtls_secure_zero((keystream), sizeof(keystream));
    if (noxtls_rc4_process(&ctx, keystream, keystream, 16U) != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_debug_printf((const uint8_t *)"RC4 self-test FAILED: process failed\n");
        return NOXTLS_RETURN_FAILED;
    }
    for (i = 0U; i < 16U; i += 1U) {
        if (keystream[i] != expected[i]) {
            (void)noxtls_debug_printf((const uint8_t *)"RC4 self-test FAILED: byte %u expected 0x%02x got 0x%02x\n",
                               (uint32_t)i, expected[i], keystream[i]);
            return NOXTLS_RETURN_FAILED;
        }
    }
    RC4_DEBUG_PRINT("RC4 self-test PASSED\n");
    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_RC4 */
