/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "noxtls_hmac.h"
#include "mdigest/sha1/noxtls_sha1.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha512/noxtls_sha512.h"

static uint32_t noxtls_hmac_hash_block_size(noxtls_hash_algos_t hash_algo)
{
    switch(hash_algo) {
        case NOXTLS_HASH_SHA_256:
        case NOXTLS_HASH_SHA1:
            return 64U;
        case NOXTLS_HASH_SHA_384:
        case NOXTLS_HASH_SHA_512:
            return 128U;
        default:
            return 0U;
    }
}

static uint32_t noxtls_hmac_hash_output_size(noxtls_hash_algos_t hash_algo)
{
    switch(hash_algo) {
        case NOXTLS_HASH_SHA1: return 20U;
        case NOXTLS_HASH_SHA_256: return 32U;
        case NOXTLS_HASH_SHA_384: return 48U;
        case NOXTLS_HASH_SHA_512: return 64U;
        default: return 0U;
    }
}

static noxtls_return_t noxtls_hmac_hash_once(noxtls_hash_algos_t hash_algo,
                                             const uint8_t *data, uint32_t len,
                                             uint8_t *out)
{
    if(hash_algo == NOXTLS_HASH_SHA_256) {
        noxtls_sha_ctx_t ctx;
        if(noxtls_sha256_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if(noxtls_sha256_update(&ctx, (uint8_t *)data, len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        return noxtls_sha256_finish(&ctx, out);
    }
    if(hash_algo == NOXTLS_HASH_SHA_384 || hash_algo == NOXTLS_HASH_SHA_512) {
        noxtls_sha512_ctx_t ctx;
        if(noxtls_sha512_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if(noxtls_sha512_update(&ctx, (uint8_t *)data, len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        return noxtls_sha512_finish(&ctx, out);
    }
    if(hash_algo == NOXTLS_HASH_SHA1) {
        noxtls_sha_ctx_t ctx;
        if(noxtls_sha1_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if(noxtls_sha1_update(&ctx, (uint8_t *)data, len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        return noxtls_sha1_finish(&ctx, out);
    }
    return NOXTLS_RETURN_INVALID_ALGORITHM;
}

noxtls_return_t noxtls_hmac_init(noxtls_hmac_context_t *ctx, noxtls_hash_algos_t hash_algo, const uint8_t *key, uint32_t key_len)
{
    uint32_t block_size;
    uint32_t hash_size;
    uint32_t i;
    uint8_t key_hash[64];

    if(ctx == NULL || key == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    block_size = noxtls_hmac_hash_block_size(hash_algo);
    hash_size = noxtls_hmac_hash_output_size(hash_algo);
    if(block_size == 0U || hash_size == 0U) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->hash_algo = hash_algo;

    if(key_len > block_size) {
        if(noxtls_hmac_hash_once(hash_algo, key, key_len, key_hash) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(ctx->key, key_hash, hash_size);
        ctx->key_len = hash_size;
    } else {
        memcpy(ctx->key, key, key_len);
        ctx->key_len = key_len;
    }

    for(i = 0; i < block_size; i++) {
        uint8_t b = (i < ctx->key_len) ? ctx->key[i] : 0U;
        ctx->i_key_pad[i] = (uint8_t)(b ^ 0x36U);
        ctx->o_key_pad[i] = (uint8_t)(b ^ 0x5CU);
    }

    if(hash_algo == NOXTLS_HASH_SHA_256) {
        noxtls_sha_ctx_t *sha_ctx = (noxtls_sha_ctx_t *)malloc(sizeof(noxtls_sha_ctx_t));
        if(sha_ctx == NULL) return NOXTLS_RETURN_FAILED;
        if(noxtls_sha256_init(sha_ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) {
            free(sha_ctx);
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_sha256_update(sha_ctx, ctx->i_key_pad, block_size);
        ctx->hash_ctx = sha_ctx;
    } else if(hash_algo == NOXTLS_HASH_SHA_384 || hash_algo == NOXTLS_HASH_SHA_512) {
        noxtls_sha512_ctx_t *sha_ctx = (noxtls_sha512_ctx_t *)malloc(sizeof(noxtls_sha512_ctx_t));
        if(sha_ctx == NULL) return NOXTLS_RETURN_FAILED;
        if(noxtls_sha512_init(sha_ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) {
            free(sha_ctx);
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_sha512_update(sha_ctx, ctx->i_key_pad, block_size);
        ctx->hash_ctx = sha_ctx;
    } else {
        noxtls_sha_ctx_t *sha_ctx = (noxtls_sha_ctx_t *)malloc(sizeof(noxtls_sha_ctx_t));
        if(sha_ctx == NULL) return NOXTLS_RETURN_FAILED;
        if(noxtls_sha1_init(sha_ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) {
            free(sha_ctx);
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_sha1_update(sha_ctx, ctx->i_key_pad, block_size);
        ctx->hash_ctx = sha_ctx;
    }

    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_hmac_update(noxtls_hmac_context_t *ctx, const uint8_t *data, uint32_t data_len)
{
    if(ctx == NULL || data == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->hash_ctx == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    if(ctx->hash_algo == NOXTLS_HASH_SHA_256) {
        return noxtls_sha256_update((noxtls_sha_ctx_t *)ctx->hash_ctx, (uint8_t *)data, data_len);
    }
    if(ctx->hash_algo == NOXTLS_HASH_SHA_384 || ctx->hash_algo == NOXTLS_HASH_SHA_512) {
        return noxtls_sha512_update((noxtls_sha512_ctx_t *)ctx->hash_ctx, (uint8_t *)data, data_len);
    }
    if(ctx->hash_algo == NOXTLS_HASH_SHA1) {
        return noxtls_sha1_update((noxtls_sha_ctx_t *)ctx->hash_ctx, (uint8_t *)data, data_len);
    }
    return NOXTLS_RETURN_INVALID_ALGORITHM;
}

noxtls_return_t noxtls_hmac_final(noxtls_hmac_context_t *ctx, uint8_t *mac, uint32_t *mac_len)
{
    uint32_t block_size;
    uint32_t hash_size;
    uint8_t inner_hash[64];
    noxtls_return_t rc;

    if(ctx == NULL || mac == NULL || mac_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->hash_ctx == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    block_size = noxtls_hmac_hash_block_size(ctx->hash_algo);
    hash_size = noxtls_hmac_hash_output_size(ctx->hash_algo);
    if(block_size == 0U || hash_size == 0U) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if(*mac_len < hash_size) {
        *mac_len = hash_size;
        return NOXTLS_RETURN_FAILED;
    }

    if(ctx->hash_algo == NOXTLS_HASH_SHA_256) {
        rc = noxtls_sha256_finish((noxtls_sha_ctx_t *)ctx->hash_ctx, inner_hash);
        free(ctx->hash_ctx);
        ctx->hash_ctx = NULL;
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        {
            noxtls_sha_ctx_t outer;
            noxtls_sha256_init(&outer, ctx->hash_algo);
            noxtls_sha256_update(&outer, ctx->o_key_pad, block_size);
            noxtls_sha256_update(&outer, inner_hash, hash_size);
            rc = noxtls_sha256_finish(&outer, mac);
        }
    } else if(ctx->hash_algo == NOXTLS_HASH_SHA_384 || ctx->hash_algo == NOXTLS_HASH_SHA_512) {
        rc = noxtls_sha512_finish((noxtls_sha512_ctx_t *)ctx->hash_ctx, inner_hash);
        free(ctx->hash_ctx);
        ctx->hash_ctx = NULL;
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        {
            noxtls_sha512_ctx_t outer;
            noxtls_sha512_init(&outer, ctx->hash_algo);
            noxtls_sha512_update(&outer, ctx->o_key_pad, block_size);
            noxtls_sha512_update(&outer, inner_hash, hash_size);
            rc = noxtls_sha512_finish(&outer, mac);
        }
    } else {
        rc = noxtls_sha1_finish((noxtls_sha_ctx_t *)ctx->hash_ctx, inner_hash);
        free(ctx->hash_ctx);
        ctx->hash_ctx = NULL;
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        {
            noxtls_sha_ctx_t outer;
            noxtls_sha1_init(&outer, ctx->hash_algo);
            noxtls_sha1_update(&outer, ctx->o_key_pad, block_size);
            noxtls_sha1_update(&outer, inner_hash, hash_size);
            rc = noxtls_sha1_finish(&outer, mac);
        }
    }

    if(rc == NOXTLS_RETURN_SUCCESS) {
        *mac_len = hash_size;
    }
    return rc;
}

noxtls_return_t noxtls_hmac_free(noxtls_hmac_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->hash_ctx != NULL) {
        free(ctx->hash_ctx);
        ctx->hash_ctx = NULL;
    }
    memset(ctx, 0, sizeof(*ctx));
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_hmac_compute(noxtls_hash_algos_t hash_algo, const uint8_t *key, uint32_t key_len,
                                    const uint8_t *data, uint32_t data_len, uint8_t *mac, uint32_t *mac_len)
{
    noxtls_hmac_context_t ctx;
    noxtls_return_t rc;

    rc = noxtls_hmac_init(&ctx, hash_algo, key, key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(data != NULL && data_len > 0U) {
        rc = noxtls_hmac_update(&ctx, data, data_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_hmac_free(&ctx);
            return rc;
        }
    }
    rc = noxtls_hmac_final(&ctx, mac, mac_len);
    noxtls_hmac_free(&ctx);
    return rc;
}

noxtls_return_t hmac_compute(noxtls_hash_algos_t hash_algo, const uint8_t *key, uint32_t key_len,
                             const uint8_t *data, uint32_t data_len, uint8_t *mac, uint32_t *mac_len)
{
    return noxtls_hmac_compute(hash_algo, key, key_len, data, data_len, mac, mac_len);
}
