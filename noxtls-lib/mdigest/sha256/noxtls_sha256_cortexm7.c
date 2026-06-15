/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_sha256_cortexm7.c
* Summary: Cortex-M7 tuned SHA-256 software block compressor.
*
*****************************************************************************/

#include <stdint.h>

#include "noxtls_common.h"
#include "noxtls_sha.h"
#include "noxtls_sha256.h"
#include "noxtls_sha256_backend.h"

#if NOXTLS_FEATURE_SHA256_CORTEXM7 && (defined(__ARM_ARCH_7EM__) || defined(__ARM_ARCH_8M_MAIN__))

#define SHA256_M7_ROTR32(x, n) (((x) >> (n)) | ((x) << (32U - (n))))
#define SHA256_M7_CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_M7_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_M7_BSIG0(x)     (SHA256_M7_ROTR32((x), 2U) ^ SHA256_M7_ROTR32((x), 13U) ^ SHA256_M7_ROTR32((x), 22U))
#define SHA256_M7_BSIG1(x)     (SHA256_M7_ROTR32((x), 6U) ^ SHA256_M7_ROTR32((x), 11U) ^ SHA256_M7_ROTR32((x), 25U))
#define SHA256_M7_SSIG0(x)     (SHA256_M7_ROTR32((x), 7U) ^ SHA256_M7_ROTR32((x), 18U) ^ ((x) >> 3U))
#define SHA256_M7_SSIG1(x)     (SHA256_M7_ROTR32((x), 17U) ^ SHA256_M7_ROTR32((x), 19U) ^ ((x) >> 10U))

static const uint32_t s_sha256_m7_k[SHA256_ROUND_COUNT] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

static uint32_t noxtls_sha256_m7_load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static uint32_t noxtls_sha256_m7_bswap32(uint32_t x)
{
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap32(x);
#else
    return ((x & 0x000000FFU) << 24) |
           ((x & 0x0000FF00U) << 8) |
           ((x & 0x00FF0000U) >> 8) |
           ((x & 0xFF000000U) >> 24);
#endif
}

#define SHA256_M7_ROUND(a, b, c, d, e, f, g, h, wt, kt) do { \
        uint32_t _t1 = (h) + SHA256_M7_BSIG1(e) + SHA256_M7_CH((e), (f), (g)) + (kt) + (wt); \
        uint32_t _t2 = SHA256_M7_BSIG0(a) + SHA256_M7_MAJ((a), (b), (c)); \
        (d) += _t1; \
        (h) = _t1 + _t2; \
    } while(0)

static void noxtls_sha256_m7_compress(noxtls_sha_ctx_t *ctx, const uint8_t *input)
{
    uint32_t w[SHA256_ROUND_COUNT];
    uint32_t a = ctx->h[0];
    uint32_t b = ctx->h[1];
    uint32_t c = ctx->h[2];
    uint32_t d = ctx->h[3];
    uint32_t e = ctx->h[4];
    uint32_t f = ctx->h[5];
    uint32_t g = ctx->h[6];
    uint32_t h = ctx->h[7];
    uint32_t t;

    if((((uintptr_t)input) & 0x03U) == 0U) {
        const uint32_t *input_words = (const uint32_t *)(const void *)input;
        for(t = 0U; t < SHA256_WORDS_PER_BLOCK; ++t) {
            w[t] = noxtls_sha256_m7_bswap32(input_words[t]);
        }
    } else {
        for(t = 0U; t < SHA256_WORDS_PER_BLOCK; ++t) {
            w[t] = noxtls_sha256_m7_load_be32(input + (t * SHA256_WORD_BYTES));
        }
    }

    for(t = SHA256_WORDS_PER_BLOCK; t < SHA256_ROUND_COUNT; ++t) {
        w[t] = SHA256_M7_SSIG1(w[t - 2U]) + w[t - 7U] +
               SHA256_M7_SSIG0(w[t - 15U]) + w[t - 16U];
    }
    for(t = 0U; t < SHA256_ROUND_COUNT; ++t) {
        w[t] += s_sha256_m7_k[t];
    }

    for(t = 0U; t < SHA256_ROUND_COUNT; t += 8U) {
        SHA256_M7_ROUND(a, b, c, d, e, f, g, h, w[t + 0U], 0U);
        SHA256_M7_ROUND(h, a, b, c, d, e, f, g, w[t + 1U], 0U);
        SHA256_M7_ROUND(g, h, a, b, c, d, e, f, w[t + 2U], 0U);
        SHA256_M7_ROUND(f, g, h, a, b, c, d, e, w[t + 3U], 0U);
        SHA256_M7_ROUND(e, f, g, h, a, b, c, d, w[t + 4U], 0U);
        SHA256_M7_ROUND(d, e, f, g, h, a, b, c, w[t + 5U], 0U);
        SHA256_M7_ROUND(c, d, e, f, g, h, a, b, w[t + 6U], 0U);
        SHA256_M7_ROUND(b, c, d, e, f, g, h, a, w[t + 7U], 0U);
    }

    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
    ctx->h[5] += f;
    ctx->h[6] += g;
    ctx->h[7] += h;
}

noxtls_return_t noxtls_sha256_blocks_cortexm7(noxtls_sha_ctx_t *ctx,
                                              const uint8_t *input,
                                              uint32_t block_count)
{
    uint32_t i;

    if(ctx == 0 || input == 0) {
        return NOXTLS_RETURN_NULL;
    }

    for(i = 0U; i < block_count; ++i) {
        noxtls_sha256_m7_compress(ctx, input + (i * SHA256_BLOCK_SIZE_BYTES));
    }

    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_SHA256_CORTEXM7 && Cortex-M */
