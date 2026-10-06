/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*****************************************************************************/

#include <stdint.h>
#include "common/noxtls_memory.h"
#include <string.h>
#include "common/noxtls_memory_compat.h"

#include "noxtls_hmac.h"
#include "mdigest/sha1/noxtls_sha1.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha512/noxtls_sha512.h"
#include "noxtls_ct.h"
#include "mdigest/noxtls_sha.h"

/*
 * Digests usable for HMAC in this build. A digest that is compiled out is
 * rejected at runtime with NOXTLS_RETURN_NOT_SUPPORTED and never referenced.
 */
#define NOXTLS_HMAC_HAVE_SHA1    (NOXTLS_FEATURE_SHA1)
#define NOXTLS_HMAC_HAVE_SHA256  (NOXTLS_FEATURE_SHA256)
#define NOXTLS_HMAC_HAVE_SHA384  (NOXTLS_FEATURE_SHA384)
#define NOXTLS_HMAC_HAVE_SHA512  (NOXTLS_FEATURE_SHA512)
#define NOXTLS_HMAC_HAVE_SHA2_64 (NOXTLS_HMAC_HAVE_SHA384 || NOXTLS_HMAC_HAVE_SHA512)

#if NOXTLS_HMAC_HAVE_SHA256
#if NOXTLS_HMAC_SHA256_SHARED_STATE
/* External serialization is required in this explicitly selected mode.
 * The busy flag rejects overlapping lifetimes; it is not a thread lock. */
static noxtls_sha_ctx_t s_hmac_sha256_shared;
static uint8_t s_hmac_sha256_shared_busy;
#endif

static noxtls_sha_ctx_t *noxtls_hmac_sha256_acquire(void)
{
#if NOXTLS_HMAC_SHA256_SHARED_STATE
    noxtls_sha_ctx_t *result = NULL;
    if(s_hmac_sha256_shared_busy == 0U) {
        s_hmac_sha256_shared_busy = 1U;
        result = &s_hmac_sha256_shared;
    }
    return result;
#else
    return (noxtls_sha_ctx_t *)NOXTLS_MALLOC(sizeof(noxtls_sha_ctx_t));
#endif
}

static void noxtls_hmac_sha256_release(noxtls_sha_ctx_t *ctx)
{
    if(ctx != NULL) {
        noxtls_secure_zero(ctx, sizeof(noxtls_sha_ctx_t));
#if NOXTLS_HMAC_SHA256_SHARED_STATE
        s_hmac_sha256_shared_busy = 0U;
#else
        (void)noxtls_free(ctx);
#endif
    }
}
#endif /* NOXTLS_HMAC_HAVE_SHA256 */

/*
 * Release the streaming hash state of an HMAC context. The state is derived
 * from the key pads, so it is always wiped before it is returned.
 */
static void noxtls_hmac_hash_ctx_release(noxtls_hash_algos_t hash_algo, void *hash_ctx)
{
    if(hash_ctx == NULL) {
        return;
    }
    if(hash_algo == NOXTLS_HASH_SHA_256) {
#if NOXTLS_HMAC_HAVE_SHA256
        noxtls_hmac_sha256_release((noxtls_sha_ctx_t *)hash_ctx);
#endif
    } else if((hash_algo == NOXTLS_HASH_SHA_384) || (hash_algo == NOXTLS_HASH_SHA_512)) {
        noxtls_secure_zero(hash_ctx, sizeof(noxtls_sha512_ctx_t));
        (void)noxtls_free(hash_ctx);
    } else {
        noxtls_secure_zero(hash_ctx, sizeof(noxtls_sha_ctx_t));
        (void)noxtls_free(hash_ctx);
    }
}

/* Wipe every key-derived field of an HMAC context (key, ipad, opad). */
static void noxtls_hmac_wipe_key_material(noxtls_hmac_context_t *ctx)
{
    noxtls_secure_zero(ctx->key, sizeof(ctx->key));
    noxtls_secure_zero(ctx->i_key_pad, sizeof(ctx->i_key_pad));
    noxtls_secure_zero(ctx->o_key_pad, sizeof(ctx->o_key_pad));
    ctx->key_len = 0U;
}

/* Both size helpers return 0 for unknown digests and for digests compiled out of this build. */
static uint32_t noxtls_hmac_hash_block_size(noxtls_hash_algos_t hash_algo)
{
    switch (hash_algo) {
#if NOXTLS_HMAC_HAVE_SHA256
        case NOXTLS_HASH_SHA_256:
            return 64U;
#endif
#if NOXTLS_HMAC_HAVE_SHA1
        case NOXTLS_HASH_SHA1:
            return 64U;
#endif
#if NOXTLS_HMAC_HAVE_SHA384
        case NOXTLS_HASH_SHA_384:
            return 128U;
#endif
#if NOXTLS_HMAC_HAVE_SHA512
        case NOXTLS_HASH_SHA_512:
            return 128U;
#endif
        default:
            return 0U;
    }
}

static uint32_t noxtls_hmac_hash_output_size(noxtls_hash_algos_t hash_algo)
{
    switch (hash_algo) {
#if NOXTLS_HMAC_HAVE_SHA1
        case NOXTLS_HASH_SHA1: return 20U;
#endif
#if NOXTLS_HMAC_HAVE_SHA256
        case NOXTLS_HASH_SHA_256: return 32U;
#endif
#if NOXTLS_HMAC_HAVE_SHA384
        case NOXTLS_HASH_SHA_384: return 48U;
#endif
#if NOXTLS_HMAC_HAVE_SHA512
        case NOXTLS_HASH_SHA_512: return 64U;
#endif
        default: return 0U;
    }
}

/*
 * Status for a digest HMAC cannot use: NOT_SUPPORTED for an HMAC digest that is
 * compiled out of this build, INVALID_ALGORITHM for anything else.
 */
static noxtls_return_t noxtls_hmac_unusable_algorithm(noxtls_hash_algos_t hash_algo)
{
    noxtls_return_t rc = NOXTLS_RETURN_INVALID_ALGORITHM;
    if((hash_algo == NOXTLS_HASH_SHA1) || (hash_algo == NOXTLS_HASH_SHA_256) ||
       (hash_algo == NOXTLS_HASH_SHA_384) || (hash_algo == NOXTLS_HASH_SHA_512)) {
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
    }
    return rc;
}

/*
 * One-shot hash for key shortening.
 */
static noxtls_return_t noxtls_hmac_hash_once(noxtls_hash_algos_t hash_algo,
                                             const uint8_t *data, uint32_t len,
                                             uint8_t *out)
{
#if NOXTLS_HMAC_HAVE_SHA256
    if(hash_algo == NOXTLS_HASH_SHA_256) {
        noxtls_sha_ctx_t *scratch = noxtls_hmac_sha256_acquire();
        noxtls_return_t rc;
        if(scratch == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        rc = noxtls_sha256_init(scratch, hash_algo);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_sha256_update(scratch, data, len);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_sha256_finish(scratch, out);
        }
        noxtls_hmac_sha256_release(scratch);
        return rc;
    }
#endif
#if NOXTLS_HMAC_HAVE_SHA2_64
    if ((hash_algo == NOXTLS_HASH_SHA_384) || (hash_algo == NOXTLS_HASH_SHA_512)) {
        noxtls_sha512_ctx_t ctx;
        noxtls_return_t rc = noxtls_sha512_init(&ctx, hash_algo);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_sha512_update(&ctx, data, len);
        }
        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_sha512_finish(&ctx, out);
        }
        noxtls_secure_zero(&ctx, sizeof(ctx));
        return rc;
    }
#endif
#if NOXTLS_HMAC_HAVE_SHA1
    if (hash_algo == NOXTLS_HASH_SHA1) {
        noxtls_sha_ctx_t ctx;
        noxtls_return_t rc = noxtls_sha1_init(&ctx, hash_algo);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_sha1_update(&ctx, data, len);
        }
        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_sha1_finish(&ctx, out);
        }
        noxtls_secure_zero(&ctx, sizeof(ctx));
        return rc;
    }
#endif
    (void)data;
    (void)len;
    (void)out;
    return noxtls_hmac_unusable_algorithm(hash_algo);
}

/*
 * Streaming HMAC keeps an opaque hash context so the public context stays
 * algorithm-agnostic. SHA-256 can explicitly select one serialized shared slot;
 * otherwise hash state uses the configured allocator.
 */
static noxtls_return_t noxtls_hmac_start_inner(noxtls_hmac_context_t *ctx, uint32_t block_size)
{
#if NOXTLS_HMAC_HAVE_SHA256
    if(ctx->hash_algo == NOXTLS_HASH_SHA_256) {
        noxtls_sha_ctx_t *sha_ctx = noxtls_hmac_sha256_acquire();
        noxtls_return_t rc;
        if(sha_ctx == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        rc = noxtls_sha256_init(sha_ctx, ctx->hash_algo);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_sha256_update(sha_ctx, ctx->i_key_pad, block_size);
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_hmac_sha256_release(sha_ctx);
            return rc;
        }
        ctx->hash_ctx = sha_ctx;
        return NOXTLS_RETURN_SUCCESS;
    }
#endif
#if NOXTLS_HMAC_HAVE_SHA2_64
    if ((ctx->hash_algo == NOXTLS_HASH_SHA_384) || (ctx->hash_algo == NOXTLS_HASH_SHA_512)) {
        noxtls_sha512_ctx_t *sha_ctx = (noxtls_sha512_ctx_t *)NOXTLS_MALLOC(sizeof(noxtls_sha512_ctx_t));
        noxtls_return_t rc;
        if (sha_ctx == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        rc = noxtls_sha512_init(sha_ctx, ctx->hash_algo);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_sha512_update(sha_ctx, ctx->i_key_pad, block_size);
        }
        if (rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_hmac_hash_ctx_release(ctx->hash_algo, sha_ctx);
            return rc;
        }
        ctx->hash_ctx = sha_ctx;
        return NOXTLS_RETURN_SUCCESS;
    }
#endif
#if NOXTLS_HMAC_HAVE_SHA1
    if (ctx->hash_algo == NOXTLS_HASH_SHA1) {
        noxtls_sha_ctx_t *sha_ctx = (noxtls_sha_ctx_t *)NOXTLS_MALLOC(sizeof(noxtls_sha_ctx_t));
        noxtls_return_t rc;
        if (sha_ctx == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        rc = noxtls_sha1_init(sha_ctx, ctx->hash_algo);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_sha1_update(sha_ctx, ctx->i_key_pad, block_size);
        }
        if (rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_hmac_hash_ctx_release(ctx->hash_algo, sha_ctx);
            return rc;
        }
        ctx->hash_ctx = sha_ctx;
        return NOXTLS_RETURN_SUCCESS;
    }
#endif
    (void)block_size;
    return noxtls_hmac_unusable_algorithm(ctx->hash_algo);
}

noxtls_return_t noxtls_hmac_init(noxtls_hmac_context_t *ctx, noxtls_hash_algos_t hash_algo, const uint8_t *key, uint32_t key_len)
{
    uint32_t block_size = 0U;
    uint32_t hash_size = 0U;
    uint32_t i = 0U;
    uint8_t key_hash[64];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if ((ctx == NULL) || (key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    /* Clear first: a context whose init failed is still safe to pass to noxtls_hmac_free(). */
    noxtls_secure_zero((ctx), sizeof(*(ctx)));

    block_size = noxtls_hmac_hash_block_size(hash_algo);
    hash_size = noxtls_hmac_hash_output_size(hash_algo);
    if ((block_size == 0U) || (hash_size == 0U)) {
        return noxtls_hmac_unusable_algorithm(hash_algo);
    }

    ctx->hash_algo = hash_algo;

    if (key_len > block_size) {
        rc = noxtls_hmac_hash_once(hash_algo, key, key_len, key_hash);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_secure_zero(key_hash, sizeof(key_hash));
            return rc;
        }
        noxtls_copy_u8(ctx->key, sizeof(ctx->key), key_hash, (size_t)hash_size);
        noxtls_secure_zero(key_hash, sizeof(key_hash));
        ctx->key_len = hash_size;
    } else {
        noxtls_copy_u8(ctx->key, sizeof(ctx->key), key, (size_t)key_len);
        ctx->key_len = key_len;
    }

    for (i = 0U; i < block_size; i += 1U) {
        uint8_t b = (uint8_t)((i < ctx->key_len) ? ctx->key[i] : 0U);
        ctx->i_key_pad[i] = (uint8_t)(b ^ 0x36U);
        ctx->o_key_pad[i] = (uint8_t)(b ^ 0x5CU);
    }

    rc = noxtls_hmac_start_inner(ctx, block_size);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        /* No usable context: do not leave the key or its pads behind. */
        noxtls_hmac_wipe_key_material(ctx);
    }
    return rc;
}

noxtls_return_t noxtls_hmac_update(noxtls_hmac_context_t *ctx, const uint8_t *data, uint32_t data_len)
{
    if ((ctx == NULL) || (data == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if (ctx->hash_ctx == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

#if NOXTLS_HMAC_HAVE_SHA256
    if (ctx->hash_algo == NOXTLS_HASH_SHA_256) { return noxtls_sha256_update((noxtls_sha_ctx_t *)ctx->hash_ctx, data, data_len); }
#endif
#if NOXTLS_HMAC_HAVE_SHA2_64
    if ((ctx->hash_algo == NOXTLS_HASH_SHA_384) || (ctx->hash_algo == NOXTLS_HASH_SHA_512)) { return noxtls_sha512_update((noxtls_sha512_ctx_t *)ctx->hash_ctx, data, data_len); }
#endif
#if NOXTLS_HMAC_HAVE_SHA1
    if (ctx->hash_algo == NOXTLS_HASH_SHA1) { return noxtls_sha1_update((noxtls_sha_ctx_t *)ctx->hash_ctx, data, data_len); }
#endif
    (void)data_len;
    return noxtls_hmac_unusable_algorithm(ctx->hash_algo);
}

noxtls_return_t noxtls_hmac_final(noxtls_hmac_context_t *ctx, uint8_t *mac, uint32_t *mac_len)
{
    uint32_t block_size = 0U;
    uint32_t hash_size = 0U;
    uint8_t inner_hash[64];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if ((ctx == NULL) || (mac == NULL) || (mac_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if (ctx->hash_ctx == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    block_size = noxtls_hmac_hash_block_size(ctx->hash_algo);
    hash_size = noxtls_hmac_hash_output_size(ctx->hash_algo);
    if ((block_size == 0U) || (hash_size == 0U)) {
        return noxtls_hmac_unusable_algorithm(ctx->hash_algo);
    }
    if (*mac_len < hash_size) {
        *mac_len = hash_size;
        return NOXTLS_RETURN_FAILED;
    }

    /* Only digests enabled in this build get past the size checks above. */
    if (ctx->hash_algo == NOXTLS_HASH_SHA_256) {
#if NOXTLS_HMAC_HAVE_SHA256
        /* Reuse this HMAC's reserved state for the outer hash. */
        noxtls_sha_ctx_t *sha_ctx = (noxtls_sha_ctx_t *)ctx->hash_ctx;
        rc = noxtls_sha256_finish(sha_ctx, inner_hash);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_sha256_init(sha_ctx, ctx->hash_algo);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_sha256_update(sha_ctx, ctx->o_key_pad, block_size);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_sha256_update(sha_ctx, inner_hash, hash_size);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_sha256_finish(sha_ctx, mac);
        }
        noxtls_hmac_sha256_release(sha_ctx);
        ctx->hash_ctx = NULL;
#endif
    } else if((ctx->hash_algo == NOXTLS_HASH_SHA_384) || (ctx->hash_algo == NOXTLS_HASH_SHA_512)) {
#if NOXTLS_HMAC_HAVE_SHA2_64
        rc = noxtls_sha512_finish((noxtls_sha512_ctx_t *)ctx->hash_ctx, inner_hash);
        noxtls_hmac_hash_ctx_release(ctx->hash_algo, ctx->hash_ctx);
        ctx->hash_ctx = NULL;
        if (rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_sha512_ctx_t outer;
            rc = noxtls_sha512_init(&outer, ctx->hash_algo);
            if (rc == NOXTLS_RETURN_SUCCESS) {
                rc = noxtls_sha512_update(&outer, ctx->o_key_pad, block_size);
            }
            if (rc == NOXTLS_RETURN_SUCCESS) {
                rc = noxtls_sha512_update(&outer, inner_hash, hash_size);
            }
            if (rc == NOXTLS_RETURN_SUCCESS) {
                rc = noxtls_sha512_finish(&outer, mac);
            }
            noxtls_secure_zero(&outer, sizeof(outer));
        }
#endif
    } else {
#if NOXTLS_HMAC_HAVE_SHA1
        rc = noxtls_sha1_finish((noxtls_sha_ctx_t *)ctx->hash_ctx, inner_hash);
        noxtls_hmac_hash_ctx_release(ctx->hash_algo, ctx->hash_ctx);
        ctx->hash_ctx = NULL;
        if (rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_sha_ctx_t outer;
            rc = noxtls_sha1_init(&outer, ctx->hash_algo);
            if (rc == NOXTLS_RETURN_SUCCESS) {
                rc = noxtls_sha1_update(&outer, ctx->o_key_pad, block_size);
            }
            if (rc == NOXTLS_RETURN_SUCCESS) {
                rc = noxtls_sha1_update(&outer, inner_hash, hash_size);
            }
            if (rc == NOXTLS_RETURN_SUCCESS) {
                rc = noxtls_sha1_finish(&outer, mac);
            }
            noxtls_secure_zero(&outer, sizeof(outer));
        }
#endif
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        *mac_len = hash_size;
    } else {
        /* Never release a partial or wrong MAC; drop the key material too. */
        noxtls_secure_zero(mac, (size_t)hash_size);
        noxtls_hmac_wipe_key_material(ctx);
    }
    noxtls_secure_zero(inner_hash, sizeof(inner_hash));
    return rc;
}

noxtls_return_t noxtls_hmac_free(noxtls_hmac_context_t *ctx)
{
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->hash_ctx != NULL) {
        noxtls_hmac_hash_ctx_release(ctx->hash_algo, ctx->hash_ctx);
        ctx->hash_ctx = NULL;
    }
    noxtls_secure_zero((ctx), sizeof(*(ctx)));
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_hmac_compute(noxtls_hash_algos_t hash_algo, const uint8_t *key, uint32_t key_len,
                                    const uint8_t *data, uint32_t data_len, uint8_t *mac, uint32_t *mac_len)
{
    noxtls_hmac_context_t ctx;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    rc = noxtls_hmac_init(&ctx, hash_algo, key, key_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if ((data != NULL) && (data_len > 0U)) {
        rc = noxtls_hmac_update(&ctx, data, data_len);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_hmac_free(&ctx);
            return rc;
        }
    }
    rc = noxtls_hmac_final(&ctx, mac, mac_len);
    (void)noxtls_hmac_free(&ctx);
    return rc;
}

noxtls_return_t hmac_compute(noxtls_hash_algos_t hash_algo, const uint8_t *key, uint32_t key_len,
                             const uint8_t *data, uint32_t data_len, uint8_t *mac, uint32_t *mac_len) { return noxtls_hmac_compute(hash_algo, key, key_len, data, data_len, mac, mac_len); }
