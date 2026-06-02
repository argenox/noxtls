/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_stm32_hash_core.c
* Summary: In-house SHA-256 block core used by STM32 hash acceleration hooks.
*****************************************************************************/

#include "vendor/st/common/noxtls_stm32_hash_core.h"

static const uint32_t s_sha256_k[NOXTLS_STM32_SHA256_ROUND_COUNT] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static uint32_t noxtls_load_be32(const uint8_t *src)
{
    return ((uint32_t)src[0] << 24) |
           ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8) |
           ((uint32_t)src[3]);
}

noxtls_return_t noxtls_stm32_hash_core_sha256_round(noxtls_sha_ctx_t *ctx,
                                                     const uint8_t *input)
{
    uint32_t w[NOXTLS_STM32_SHA256_ROUND_COUNT];
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;
    uint32_t t;

    if(ctx == NULL || input == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    for(t = 0u; t < 16u; t++) {
        w[t] = noxtls_load_be32(input + (t * 4u));
    }
    for(t = 16u; t < NOXTLS_STM32_SHA256_ROUND_COUNT; t++) {
        w[t] = NOXTLS_STM32_SHA_SIGMA_FROM_1(w[t - 2u]) + w[t - 7u] +
               NOXTLS_STM32_SHA_SIGMA_FROM_0(w[t - 15u]) + w[t - 16u];
    }

    a = ctx->h[0];
    b = ctx->h[1];
    c = ctx->h[2];
    d = ctx->h[3];
    e = ctx->h[4];
    f = ctx->h[5];
    g = ctx->h[6];
    h = ctx->h[7];

    for(t = 0u; t < NOXTLS_STM32_SHA256_ROUND_COUNT; t++) {
        uint32_t t1 = h + NOXTLS_STM32_SHA_SUM_FROM_1(e) + NOXTLS_STM32_SHA_CH(e, f, g) +
                      s_sha256_k[t] + w[t];
        uint32_t t2 = NOXTLS_STM32_SHA_SUM_FROM_0(a) + NOXTLS_STM32_SHA_MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

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

noxtls_return_t noxtls_stm32_hash_core_sha256_blocks(noxtls_sha_ctx_t *ctx,
                                                      const uint8_t *input,
                                                      uint32_t block_count)
{
    uint32_t i;

    if(ctx == NULL || input == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    for(i = 0u; i < block_count; i++) {
        noxtls_return_t rc = noxtls_stm32_hash_core_sha256_round(ctx, input + (i * 64u));
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}
