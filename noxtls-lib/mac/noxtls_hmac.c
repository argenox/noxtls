/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "noxtls_hmac.h"
#include "mdigest/md5/noxtls_md5.h"
#include "mdigest/sha1/noxtls_sha1.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha512/noxtls_sha512.h"
#include "noxtls_ct.h"
#include "mdigest/noxtls_sha.h"

/*
 * Digests usable for HMAC in this build. A digest that is compiled out is
 * rejected at runtime with NOXTLS_RETURN_NOT_SUPPORTED and never referenced.
 *
 * NOXTLS_HMAC_SHA256_SHARED_STATE is accepted for compatibility but has no
 * effect any more: the context embeds its hash state, so there is neither a
 * per-context heap block nor a shared static slot to select.
 */
#define NOXTLS_HMAC_HAVE_MD5     (NOXTLS_FEATURE_MD5)
#define NOXTLS_HMAC_HAVE_SHA1    (NOXTLS_FEATURE_SHA1)
#define NOXTLS_HMAC_HAVE_SHA256  (NOXTLS_FEATURE_SHA256)
#define NOXTLS_HMAC_HAVE_SHA384  (NOXTLS_FEATURE_SHA384)
#define NOXTLS_HMAC_HAVE_SHA512  (NOXTLS_FEATURE_SHA512)
#define NOXTLS_HMAC_HAVE_SHA2_64 (NOXTLS_HMAC_HAVE_SHA384 || NOXTLS_HMAC_HAVE_SHA512)

/* HMAC context life-cycle (noxtls_hmac_context_t.state). */
#define NOXTLS_HMAC_STATE_UNKEYED  (0U)
#define NOXTLS_HMAC_STATE_ACTIVE   (1U)
#define NOXTLS_HMAC_STATE_FINISHED (2U)

/* Largest digest block (SHA-384/512) and output handled here. */
#if NOXTLS_HMAC_HAVE_SHA2_64
#define NOXTLS_HMAC_MAX_BLOCK (128U)
#else
#define NOXTLS_HMAC_MAX_BLOCK (64U)
#endif

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
#if NOXTLS_HMAC_HAVE_MD5
        case NOXTLS_HASH_MD5:
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
#if NOXTLS_HMAC_HAVE_MD5
        case NOXTLS_HASH_MD5: return 16U;
#endif
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
    if((hash_algo == NOXTLS_HASH_MD5) || (hash_algo == NOXTLS_HASH_SHA1) || (hash_algo == NOXTLS_HASH_SHA_256) ||
       (hash_algo == NOXTLS_HASH_SHA_384) || (hash_algo == NOXTLS_HASH_SHA_512)) {
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
    }
    return rc;
}

/* Thin per-digest dispatch on the embedded hash context (only HMAC digests are linked). */
static noxtls_return_t noxtls_hmac_h_init(noxtls_sha_ctx_t *h, noxtls_hash_algos_t hash_algo)
{
#if NOXTLS_HMAC_HAVE_SHA256
    if (hash_algo == NOXTLS_HASH_SHA_256) {
        return noxtls_sha256_init(h, hash_algo);
    }
#endif
#if NOXTLS_HMAC_HAVE_SHA2_64
    if ((hash_algo == NOXTLS_HASH_SHA_384) || (hash_algo == NOXTLS_HASH_SHA_512)) {
        h->algo = hash_algo;
        return noxtls_sha512_init(&h->u.sha512_ctx, hash_algo);
    }
#endif
#if NOXTLS_HMAC_HAVE_SHA1
    if (hash_algo == NOXTLS_HASH_SHA1) {
        return noxtls_sha1_init(h, hash_algo);
    }
#endif
#if NOXTLS_HMAC_HAVE_MD5
    if (hash_algo == NOXTLS_HASH_MD5) {
        h->algo = hash_algo;
        return noxtls_md5_init(h);
    }
#endif
    (void)h;
    return noxtls_hmac_unusable_algorithm(hash_algo);
}

static noxtls_return_t noxtls_hmac_h_update(noxtls_sha_ctx_t *h, noxtls_hash_algos_t hash_algo,
                                            const uint8_t *data, uint32_t len)
{
#if NOXTLS_HMAC_HAVE_SHA256
    if (hash_algo == NOXTLS_HASH_SHA_256) {
        return noxtls_sha256_update(h, data, len);
    }
#endif
#if NOXTLS_HMAC_HAVE_SHA2_64
    if ((hash_algo == NOXTLS_HASH_SHA_384) || (hash_algo == NOXTLS_HASH_SHA_512)) {
        return noxtls_sha512_update(&h->u.sha512_ctx, data, len);
    }
#endif
#if NOXTLS_HMAC_HAVE_SHA1
    if (hash_algo == NOXTLS_HASH_SHA1) {
        return noxtls_sha1_update(h, data, len);
    }
#endif
#if NOXTLS_HMAC_HAVE_MD5
    if (hash_algo == NOXTLS_HASH_MD5) {
        return noxtls_md5_update(h, data, len);
    }
#endif
    (void)h;
    (void)data;
    (void)len;
    return noxtls_hmac_unusable_algorithm(hash_algo);
}

static noxtls_return_t noxtls_hmac_h_finish(noxtls_sha_ctx_t *h, noxtls_hash_algos_t hash_algo, uint8_t *out)
{
#if NOXTLS_HMAC_HAVE_SHA256
    if (hash_algo == NOXTLS_HASH_SHA_256) {
        return noxtls_sha256_finish(h, out);
    }
#endif
#if NOXTLS_HMAC_HAVE_SHA2_64
    if ((hash_algo == NOXTLS_HASH_SHA_384) || (hash_algo == NOXTLS_HASH_SHA_512)) {
        return noxtls_sha512_finish(&h->u.sha512_ctx, out);
    }
#endif
#if NOXTLS_HMAC_HAVE_SHA1
    if (hash_algo == NOXTLS_HASH_SHA1) {
        return noxtls_sha1_finish(h, out);
    }
#endif
#if NOXTLS_HMAC_HAVE_MD5
    if (hash_algo == NOXTLS_HASH_MD5) {
        return noxtls_md5_finish(h, out);
    }
#endif
    (void)h;
    (void)out;
    return noxtls_hmac_unusable_algorithm(hash_algo);
}

/* Copy the chaining value of the embedded hash after exactly one block. */
static void noxtls_hmac_save_mid(const noxtls_sha_ctx_t *h, noxtls_hash_algos_t hash_algo,
                                 noxtls_hmac_midstate_t *mid)
{
    uint32_t i;
#if NOXTLS_HMAC_HAVE_SHA2_64
    if ((hash_algo == NOXTLS_HASH_SHA_384) || (hash_algo == NOXTLS_HASH_SHA_512)) {
        for (i = 0U; i < NOXTLS_HMAC_MIDSTATE_WORDS; i += 1U) {
            mid->w64[i] = h->u.sha512_ctx.h[i];
        }
        return;
    }
#endif
    (void)hash_algo;
    for (i = 0U; i < NOXTLS_HMAC_MIDSTATE_WORDS; i += 1U) {
        mid->w32[i] = h->u.md32.h[i];
    }
}

/* Start the embedded hash as if one key-pad block had already been absorbed. */
static noxtls_return_t noxtls_hmac_start_from_mid(noxtls_sha_ctx_t *h, noxtls_hash_algos_t hash_algo,
                                                  const noxtls_hmac_midstate_t *mid, uint32_t block_size)
{
    uint32_t i;
    noxtls_return_t rc = noxtls_hmac_h_init(h, hash_algo);

    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
#if NOXTLS_HMAC_HAVE_SHA2_64
    if ((hash_algo == NOXTLS_HASH_SHA_384) || (hash_algo == NOXTLS_HASH_SHA_512)) {
        for (i = 0U; i < NOXTLS_HMAC_MIDSTATE_WORDS; i += 1U) {
            h->u.sha512_ctx.h[i] = mid->w64[i];
        }
        h->u.sha512_ctx.length = block_size;
        return NOXTLS_RETURN_SUCCESS;
    }
#endif
    for (i = 0U; i < NOXTLS_HMAC_MIDSTATE_WORDS; i += 1U) {
        h->u.md32.h[i] = mid->w32[i];
    }
    h->u.md32.length = block_size;
    return NOXTLS_RETURN_SUCCESS;
}

/* Hash one pad block (K' ^ pad, already in blk) from the IV and keep its chaining value. */
static noxtls_return_t noxtls_hmac_pad_mid(noxtls_hmac_context_t *ctx, const uint8_t *blk, uint32_t block_size,
                                           noxtls_hmac_midstate_t *mid)
{
    noxtls_return_t rc = noxtls_hmac_h_init(&ctx->hash, ctx->hash_algo);

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_hmac_h_update(&ctx->hash, ctx->hash_algo, blk, block_size);
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_hmac_save_mid(&ctx->hash, ctx->hash_algo, mid);
    }
    return rc;
}

noxtls_return_t noxtls_hmac_init(noxtls_hmac_context_t *ctx, noxtls_hash_algos_t hash_algo, const uint8_t *key, uint32_t key_len)
{
    uint32_t block_size = 0U;
    uint32_t hash_size = 0U;
    uint32_t i = 0U;
    uint32_t klen = key_len;
    uint8_t blk[NOXTLS_HMAC_MAX_BLOCK];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if ((ctx == NULL) || (key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    /* Clear first: a context whose init failed is still safe to pass to noxtls_hmac_free(). */
    noxtls_secure_zero((ctx), sizeof(*(ctx)));

    block_size = noxtls_hmac_hash_block_size(hash_algo);
    hash_size = noxtls_hmac_hash_output_size(hash_algo);
    if ((block_size == 0U) || (hash_size == 0U) || (block_size > sizeof(blk))) {
        return noxtls_hmac_unusable_algorithm(hash_algo);
    }

    ctx->hash_algo = hash_algo;
    noxtls_secure_zero(blk, sizeof(blk));

    /* K' = H(K) for long keys, else K; zero-padded to the block size. */
    if (klen > block_size) {
        rc = noxtls_hmac_h_init(&ctx->hash, hash_algo);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_hmac_h_update(&ctx->hash, hash_algo, key, klen);
        }
        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_hmac_h_finish(&ctx->hash, hash_algo, blk);
        }
        if (rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_secure_zero(blk, sizeof(blk));
            noxtls_secure_zero(ctx, sizeof(*ctx));
            return rc;
        }
    } else {
        noxtls_copy_u8(blk, sizeof(blk), key, (size_t)klen);
    }

    /* Outer pad first, then inner, so the embedded hash is left running the inner hash. */
    for (i = 0U; i < block_size; i += 1U) {
        blk[i] = (uint8_t)(blk[i] ^ 0x5CU);
    }
    rc = noxtls_hmac_pad_mid(ctx, blk, block_size, &ctx->outer_mid);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        for (i = 0U; i < block_size; i += 1U) {
            blk[i] = (uint8_t)(blk[i] ^ (uint8_t)(0x5CU ^ 0x36U));
        }
        rc = noxtls_hmac_pad_mid(ctx, blk, block_size, &ctx->inner_mid);
    }
    noxtls_secure_zero(blk, sizeof(blk));
    if (rc != NOXTLS_RETURN_SUCCESS) {
        /* No usable context: do not leave key-derived state behind. */
        noxtls_secure_zero(ctx, sizeof(*ctx));
        return rc;
    }
    ctx->state = (uint8_t)NOXTLS_HMAC_STATE_ACTIVE;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_hmac_reset(noxtls_hmac_context_t *ctx)
{
    noxtls_return_t rc;

    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if (ctx->state == (uint8_t)NOXTLS_HMAC_STATE_UNKEYED) {
        return NOXTLS_RETURN_FAILED;
    }
    rc = noxtls_hmac_start_from_mid(&ctx->hash, ctx->hash_algo, &ctx->inner_mid,
                                    noxtls_hmac_hash_block_size(ctx->hash_algo));
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(ctx, sizeof(*ctx));
        return rc;
    }
    ctx->state = (uint8_t)NOXTLS_HMAC_STATE_ACTIVE;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_hmac_update(noxtls_hmac_context_t *ctx, const uint8_t *data, uint32_t data_len)
{
    if ((ctx == NULL) || (data == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if (ctx->state != (uint8_t)NOXTLS_HMAC_STATE_ACTIVE) {
        return NOXTLS_RETURN_FAILED;
    }
    return noxtls_hmac_h_update(&ctx->hash, ctx->hash_algo, data, data_len);
}

noxtls_return_t noxtls_hmac_final(noxtls_hmac_context_t *ctx, uint8_t *mac, uint32_t *mac_len)
{
    uint32_t block_size = 0U;
    uint32_t hash_size = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if ((ctx == NULL) || (mac == NULL) || (mac_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if (ctx->state != (uint8_t)NOXTLS_HMAC_STATE_ACTIVE) {
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

    /* Inner digest goes straight into the caller's buffer: the outer update
     * copies it into the hash block buffer before the outer finish overwrites
     * mac, so no stack copy and no second hash context are needed. */
    rc = noxtls_hmac_h_finish(&ctx->hash, ctx->hash_algo, mac);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_hmac_start_from_mid(&ctx->hash, ctx->hash_algo, &ctx->outer_mid, block_size);
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_hmac_h_update(&ctx->hash, ctx->hash_algo, mac, hash_size);
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_hmac_h_finish(&ctx->hash, ctx->hash_algo, mac);
    }
    noxtls_secure_zero(&ctx->hash, sizeof(ctx->hash));

    if (rc == NOXTLS_RETURN_SUCCESS) {
        *mac_len = hash_size;
        ctx->state = (uint8_t)NOXTLS_HMAC_STATE_FINISHED;
    } else {
        /* Never release a partial or wrong MAC; drop the key material too. */
        noxtls_secure_zero(mac, (size_t)hash_size);
        noxtls_secure_zero(ctx, sizeof(*ctx));
    }
    return rc;
}

noxtls_return_t noxtls_hmac_free(noxtls_hmac_context_t *ctx)
{
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
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
