/*****************************************************************************
* This file is part of the NoxTLS Library.
*/

﻿#ifndef NOXTLS_MLDSA_FIPS202_GLUE_H
#define NOXTLS_MLDSA_FIPS202_GLUE_H

#include <stddef.h>
#include <stdint.h>

#include "mdigest/sha3/noxtls_sha3.h"

#define SHAKE128_RATE SHA3_SHAKE128_RATE_BYTES
#define SHAKE256_RATE SHA3_SHAKE256_RATE_BYTES

typedef noxtls_sha3_ctx_t noxtls_mld_shake128ctx;
typedef noxtls_sha3_ctx_t noxtls_mld_shake256ctx;

static inline void noxtls_mld_shake128_init(noxtls_mld_shake128ctx *ctx)
{
    (void)noxtls_shake128_init(ctx);
}

static inline void noxtls_mld_shake128_absorb(noxtls_mld_shake128ctx *ctx, const uint8_t *in, size_t inlen)
{
    (void)noxtls_shake128_update(ctx, in, (uint32_t)inlen);
}

static inline void noxtls_mld_shake128_finalize(noxtls_mld_shake128ctx *ctx)
{
    (void)noxtls_shake128_final(ctx);
}

static inline void noxtls_mld_shake128_squeeze(uint8_t *out, size_t outlen, noxtls_mld_shake128ctx *ctx)
{
    (void)noxtls_shake128_squeeze(ctx, out, (uint32_t)outlen);
}

static inline void noxtls_mld_shake128_release(noxtls_mld_shake128ctx *ctx)
{
    (void)ctx;
}

static inline void noxtls_mld_shake256_init(noxtls_mld_shake256ctx *ctx)
{
    (void)noxtls_shake256_init(ctx);
}

static inline void noxtls_mld_shake256_absorb(noxtls_mld_shake256ctx *ctx, const uint8_t *in, size_t inlen)
{
    (void)noxtls_shake256_update(ctx, in, (uint32_t)inlen);
}

static inline void noxtls_mld_shake256_finalize(noxtls_mld_shake256ctx *ctx)
{
    (void)noxtls_shake256_final(ctx);
}

static inline void noxtls_mld_shake256_squeeze(uint8_t *out, size_t outlen, noxtls_mld_shake256ctx *ctx)
{
    (void)noxtls_shake256_squeeze(ctx, out, (uint32_t)outlen);
}

static inline void noxtls_mld_shake256_release(noxtls_mld_shake256ctx *ctx)
{
    (void)ctx;
}

static inline void noxtls_mld_shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    noxtls_sha3_ctx_t ctx;
    if(noxtls_shake256_init(&ctx) != NOXTLS_RETURN_SUCCESS) {
        return;
    }
    if(noxtls_shake256_update(&ctx, in, (uint32_t)inlen) != NOXTLS_RETURN_SUCCESS) {
        return;
    }
    if(noxtls_shake256_final(&ctx) != NOXTLS_RETURN_SUCCESS) {
        return;
    }
    (void)noxtls_shake256_squeeze(&ctx, out, (uint32_t)outlen);
}

#endif


