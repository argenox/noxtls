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
* File:    noxtls_xmss.c
* Summary: XMSS / XMSS^MT (RFC 8391, NIST SP 800-208): parameter sets, key
*          encodings, key generation, streaming verification and stateful
*          signing with fail-closed state persistence.
*
*****************************************************************************/

#include <stdint.h>

#include "noxtls_xmss_internal.h"
#include "common/noxtls_ct.h"
#include "drbg/noxtls_drbg.h"

#if NOXTLS_FEATURE_XMSS

/* ---- parameter sets ----------------------------------------------------- */

typedef struct
{
    uint8_t hash;
    uint8_t n;
    uint8_t h;
    uint8_t d;
} xmss_entry_t;

#define XMSS_E_SHA256 NOXTLS_XMSS_HASH_SHA256
#define XMSS_E_SHA512 NOXTLS_XMSS_HASH_SHA512
#define XMSS_E_SHAKE128 NOXTLS_XMSS_HASH_SHAKE128
#define XMSS_E_SHAKE256 NOXTLS_XMSS_HASH_SHAKE256

/* XMSS, indexed by OID - 1 (RFC 8391 Section 5.3, SP 800-208 Section 5.1 / IANA). */
static const xmss_entry_t g_xmss_sets[21] = {
    { XMSS_E_SHA256, 32U, 10U, 1U }, { XMSS_E_SHA256, 32U, 16U, 1U }, { XMSS_E_SHA256, 32U, 20U, 1U },
    { XMSS_E_SHA512, 64U, 10U, 1U }, { XMSS_E_SHA512, 64U, 16U, 1U }, { XMSS_E_SHA512, 64U, 20U, 1U },
    { XMSS_E_SHAKE128, 32U, 10U, 1U }, { XMSS_E_SHAKE128, 32U, 16U, 1U }, { XMSS_E_SHAKE128, 32U, 20U, 1U },
    { XMSS_E_SHAKE256, 64U, 10U, 1U }, { XMSS_E_SHAKE256, 64U, 16U, 1U }, { XMSS_E_SHAKE256, 64U, 20U, 1U },
    { XMSS_E_SHA256, 24U, 10U, 1U }, { XMSS_E_SHA256, 24U, 16U, 1U }, { XMSS_E_SHA256, 24U, 20U, 1U },
    { XMSS_E_SHAKE256, 32U, 10U, 1U }, { XMSS_E_SHAKE256, 32U, 16U, 1U }, { XMSS_E_SHAKE256, 32U, 20U, 1U },
    { XMSS_E_SHAKE256, 24U, 10U, 1U }, { XMSS_E_SHAKE256, 24U, 16U, 1U }, { XMSS_E_SHAKE256, 24U, 20U, 1U },
};

/* XMSS^MT families of 8 OIDs each: (h, d) = 20/2 20/4 40/2 40/4 40/8 60/3 60/6 60/12. */
static const uint8_t g_xmssmt_hd[8][2] = {
    { 20U, 2U }, { 20U, 4U }, { 40U, 2U }, { 40U, 4U }, { 40U, 8U }, { 60U, 3U }, { 60U, 6U }, { 60U, 12U },
};
static const uint8_t g_xmssmt_family[7][2] = {
    { XMSS_E_SHA256, 32U }, { XMSS_E_SHA512, 64U }, { XMSS_E_SHAKE128, 32U }, { XMSS_E_SHAKE256, 64U },
    { XMSS_E_SHA256, 24U }, { XMSS_E_SHAKE256, 32U }, { XMSS_E_SHAKE256, 24U },
};

static uint8_t xmss_hash_enabled(uint32_t hash, uint32_t n)
{
    if((n == 64U) && (NOXTLS_XMSS_ENABLE_N64 == 0)) {
        return 0U;
    }
    switch(hash) {
        case NOXTLS_XMSS_HASH_SHA256:
            return (NOXTLS_XMSS_ENABLE_SHA2 != 0) ? 1U : 0U;
        case NOXTLS_XMSS_HASH_SHA512:
            return (NOXTLS_XMSS_HAVE_SHA512 != 0) ? 1U : 0U;
        case NOXTLS_XMSS_HASH_SHAKE128:
        case NOXTLS_XMSS_HASH_SHAKE256:
            return (NOXTLS_XMSS_HAVE_SHAKE != 0) ? 1U : 0U;
        default:
            return 0U;
    }
}

const xmss_params_t *xmss_params_get(noxtls_xmss_param_t param, xmss_params_t *out)
{
    xmss_entry_t e;
    uint32_t oid = param & 0xFFFFU;
    uint32_t is_mt = ((param & NOXTLS_XMSS_PARAM_MT_FLAG) != 0U) ? 1U : 0U;
    uint32_t n = 0U;

    if((out == NULL) || ((param & ~(NOXTLS_XMSS_PARAM_MT_FLAG | 0xFFFFU)) != 0U) || (oid == 0U)) {
        return NULL;
    }
    if(is_mt == 0U) {
        if(oid > 21U) {
            return NULL;
        }
        e = g_xmss_sets[oid - 1U];
    } else {
        if(oid > 56U) {
            return NULL;
        }
        e.hash = g_xmssmt_family[(oid - 1U) >> 3U][0];
        e.n = g_xmssmt_family[(oid - 1U) >> 3U][1];
        e.h = g_xmssmt_hd[(oid - 1U) & 7U][0];
        e.d = g_xmssmt_hd[(oid - 1U) & 7U][1];
    }
    if((xmss_hash_enabled(e.hash, e.n) == 0U) || ((uint32_t)e.h > (uint32_t)NOXTLS_XMSS_MAX_HEIGHT)) {
        return NULL;
    }
    n = (uint32_t)e.n;
    out->id = param;
    out->oid = oid;
    out->is_mt = (uint8_t)is_mt;
    out->hash = e.hash;
    out->n = e.n;
    out->pad = (n == 24U) ? 4U : e.n;
    out->h = e.h;
    out->d = e.d;
    out->th = (uint8_t)(e.h / e.d);
    out->len1 = (uint8_t)(2U * n);
    out->len = (uint8_t)((2U * n) + XMSS_LEN2);
    out->idx_bytes = (is_mt != 0U) ? (uint8_t)(((uint32_t)e.h + 7U) / 8U) : 4U;
    out->sig_len = (uint32_t)out->idx_bytes + n + ((uint32_t)e.d * (uint32_t)out->len * n) + ((uint32_t)e.h * n);
    out->pk_len = 4U + (2U * n);
    out->sk_len = 4U + (uint32_t)out->idx_bytes + (4U * n);
    out->sp800_208 = ((((uint32_t)e.hash == NOXTLS_XMSS_HASH_SHA256) || ((uint32_t)e.hash == NOXTLS_XMSS_HASH_SHAKE256)) &&
                      (n != 64U)) ? 1U : 0U;
    return out;
}

/*
 * End of the usable index range of a private key and the value its index
 * field holds once the key is exhausted: 2^h, or 2^h - 1 when 2^h does not fit
 * in the idx_bytes-byte field (XMSS^MT h = 40: ceil(40 / 8) = 5 bytes).  In that
 * case the last one-time key is never used, so that an exhausted key can never
 * be confused with a fresh one (an all-0xff index cannot wrap to 0).
 */
static uint64_t xmss_idx_end(const xmss_params_t *p)
{
    return ((8U * (uint32_t)p->idx_bytes) > (uint32_t)p->h) ? (1ULL << p->h) : ((1ULL << p->h) - 1U);
}

uint32_t noxtls_xmss_public_key_len(noxtls_xmss_param_t param)
{
    xmss_params_t p;

    return (xmss_params_get(param, &p) != NULL) ? p.pk_len : 0U;
}

uint32_t noxtls_xmss_secret_key_len(noxtls_xmss_param_t param)
{
    xmss_params_t p;

    return (xmss_params_get(param, &p) != NULL) ? p.sk_len : 0U;
}

uint32_t noxtls_xmss_signature_len(noxtls_xmss_param_t param)
{
    xmss_params_t p;

    return (xmss_params_get(param, &p) != NULL) ? p.sig_len : 0U;
}

uint64_t noxtls_xmss_max_signatures(noxtls_xmss_param_t param)
{
    xmss_params_t p;

    return (xmss_params_get(param, &p) != NULL) ? xmss_idx_end(&p) : 0U;
}

noxtls_return_t noxtls_xmss_get_param_info(noxtls_xmss_param_t param, noxtls_xmss_param_info_t *info)
{
    xmss_params_t p;

    if(info == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    noxtls_secure_zero(info, sizeof(*info));
    if(xmss_params_get(param, &p) == NULL) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    info->oid = p.oid;
    info->public_key_len = p.pk_len;
    info->secret_key_len = p.sk_len;
    info->signature_len = p.sig_len;
    info->is_mt = p.is_mt;
    info->hash = p.hash;
    info->n = p.n;
    info->w = (uint8_t)XMSS_W;
    info->wots_len = p.len;
    info->height = p.h;
    info->layers = p.d;
    info->tree_height = p.th;
    info->index_len = p.idx_bytes;
    info->sp800_208 = p.sp800_208;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_xmss_param_from_oid(uint32_t oid, uint8_t is_mt, noxtls_xmss_param_t *param)
{
    xmss_params_t p;
    noxtls_xmss_param_t id = 0U;

    if(param == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    *param = NOXTLS_XMSS_NONE;
    if((oid == 0U) || (oid > 0xFFFFU) || (is_mt > 1U)) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    id = (is_mt != 0U) ? (NOXTLS_XMSS_PARAM_MT_FLAG | oid) : oid;
    if(xmss_params_get(id, &p) == NULL) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    *param = id;
    return NOXTLS_RETURN_SUCCESS;
}

/* ---- encodings ----------------------------------------------------------- */

static uint32_t xmss_load_oid(const uint8_t *in)
{
    return (uint32_t)xmss_load_be(in, 4U);
}

/* Secret key field offsets: OID[4] | idx | SK_SEED | SK_PRF | root | PUB_SEED. */
static uint32_t xmss_sk_off_seed(const xmss_params_t *p)
{
    return 4U + (uint32_t)p->idx_bytes;
}

static noxtls_return_t xmss_check_secret_key(const xmss_params_t *p, const uint8_t *sk, uint32_t sk_len, uint64_t *idx)
{
    uint64_t v = 0U;

    if(sk == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(sk_len != p->sk_len) {
        return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }
    if(xmss_load_oid(sk) != p->oid) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    v = xmss_load_be(&sk[4], (uint32_t)p->idx_bytes);
    /* The end marker (see xmss_idx_end) means exhausted; anything larger is malformed. */
    if(v > xmss_idx_end(p)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    *idx = v;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_xmss_public_key_from_secret(noxtls_xmss_param_t param,
                                                   const uint8_t *secret_key,
                                                   uint32_t secret_key_len,
                                                   uint8_t *public_key,
                                                   uint32_t public_key_len)
{
    xmss_params_t ps;
    const xmss_params_t *p = xmss_params_get(param, &ps);
    uint64_t idx = 0U;
    uint32_t off = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if(p == NULL) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    if(public_key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(public_key_len < p->pk_len) {
        return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }
    rc = xmss_check_secret_key(p, secret_key, secret_key_len, &idx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    off = xmss_sk_off_seed(p) + (2U * (uint32_t)p->n);
    xmss_copy(public_key, secret_key, 4U);
    xmss_copy(&public_key[4], &secret_key[off], 2U * (uint32_t)p->n);
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_xmss_secret_key_remaining(noxtls_xmss_param_t param,
                                                 const uint8_t *secret_key,
                                                 uint32_t secret_key_len,
                                                 uint64_t *remaining)
{
    xmss_params_t ps;
    const xmss_params_t *p = xmss_params_get(param, &ps);
    uint64_t idx = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if(remaining == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    *remaining = 0U;
    if(p == NULL) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    rc = xmss_check_secret_key(p, secret_key, secret_key_len, &idx);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        *remaining = xmss_idx_end(p) - idx;
    }
    return rc;
}

/* ---- verification -------------------------------------------------------- */

#define XMSS_VERIFY_HASHING 0x58560001U
#define XMSS_VERIFY_IDLE 0U

/* Recompute the root from a digest and the signature body (after idx || r). */
static noxtls_return_t xmss_root_from_digest(const xmss_hctx_t *hc, uint64_t idx, const uint8_t *digest,
                                             const uint8_t *body, uint8_t *root)
{
    const xmss_params_t *p = hc->p;
    uint32_t th = (uint32_t)p->th;
    uint32_t n = (uint32_t)p->n;
    uint32_t layer_len = ((uint32_t)p->len + th) * n;
    uint64_t mask = (1ULL << th) - 1U;
    uint8_t node[NOXTLS_XMSS_MAX_N];
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    xmss_copy(node, digest, n);
    for(i = 0U; (i < (uint32_t)p->d) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        uint64_t tree = idx >> (th * (i + 1U));
        uint32_t leaf = (uint32_t)((idx >> (th * i)) & mask);

        rc = xmss_root_from_sig(hc, i, tree, leaf, node, &body[i * layer_len], node);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        xmss_copy(root, node, n);
    }
    return rc;
}

noxtls_return_t noxtls_xmss_verify_init(noxtls_xmss_verify_ctx_t *ctx,
                                        noxtls_xmss_param_t param,
                                        const uint8_t *public_key,
                                        uint32_t public_key_len,
                                        const uint8_t *signature,
                                        uint32_t signature_len)
{
    xmss_params_t ps;
    const xmss_params_t *p = NULL;
    uint32_t n = 0U;
    uint64_t idx = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    noxtls_secure_zero(ctx, sizeof(*ctx));
    p = xmss_params_get(param, &ps);
    if(p == NULL) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    if((public_key == NULL) || (signature == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(public_key_len != p->pk_len) {
        return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }
    if(signature_len != p->sig_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(xmss_load_oid(public_key) != p->oid) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    n = (uint32_t)p->n;
    idx = xmss_load_be(signature, (uint32_t)p->idx_bytes);
    if(idx >= (1ULL << p->h)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    ctx->param = param;
    ctx->idx = idx;
    xmss_copy(ctx->root, &public_key[4], n);
    xmss_copy(ctx->pub_seed, &public_key[4U + n], n);
    xmss_copy(ctx->r, &signature[p->idx_bytes], n);
    rc = xmss_hmsg_init(&ctx->hash, p, ctx->r, ctx->root, idx);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        ctx->state = XMSS_VERIFY_HASHING;
    } else {
        noxtls_secure_zero(ctx, sizeof(*ctx));
    }
    return rc;
}

noxtls_return_t noxtls_xmss_verify_update(noxtls_xmss_verify_ctx_t *ctx, const uint8_t *data, uint32_t data_len)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->state != XMSS_VERIFY_HASHING) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
    if(data_len == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }
    if(data == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    rc = xmss_hmsg_update(&ctx->hash, data, data_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(ctx, sizeof(*ctx));
    }
    return rc;
}

noxtls_return_t noxtls_xmss_verify_final(noxtls_xmss_verify_ctx_t *ctx, const uint8_t *signature, uint32_t signature_len)
{
    xmss_params_t ps;
    const xmss_params_t *p = NULL;
    xmss_hctx_t hc;
    uint8_t digest[NOXTLS_XMSS_MAX_N];
    uint32_t n = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->state != XMSS_VERIFY_HASHING) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
    p = xmss_params_get(ctx->param, &ps);
    if(p == NULL) {
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
    } else if(signature == NULL) {
        rc = NOXTLS_RETURN_NULL;
    } else if(signature_len != p->sig_len) {
        rc = NOXTLS_RETURN_BAD_DATA;
    } else if((xmss_load_be(signature, (uint32_t)p->idx_bytes) != ctx->idx) ||
              (noxtls_ct_memcmp(&signature[p->idx_bytes], ctx->r, (size_t)p->n) != 0)) {
        /* final() must see the signature whose header init() parsed. */
        rc = NOXTLS_RETURN_BAD_DATA;
    } else {
        n = (uint32_t)p->n;
        rc = xmss_hmsg_final(&ctx->hash, p, digest);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = xmss_hctx_init(&hc, p, ctx->pub_seed, NULL);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = xmss_root_from_digest(&hc, ctx->idx, digest, &signature[(uint32_t)p->idx_bytes + n], digest);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = (noxtls_ct_memcmp(digest, ctx->root, (size_t)n) == 0) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
        }
        xmss_hctx_wipe(&hc);
    }
    noxtls_secure_zero(digest, sizeof(digest));
    noxtls_secure_zero(ctx, sizeof(*ctx));
    return rc;
}

noxtls_return_t noxtls_xmss_verify(noxtls_xmss_param_t param,
                                   const uint8_t *public_key,
                                   const uint8_t *message,
                                   uint32_t message_len,
                                   const uint8_t *signature,
                                   uint32_t signature_len)
{
    noxtls_xmss_verify_ctx_t ctx;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if((message == NULL) && (message_len != 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    rc = noxtls_xmss_verify_init(&ctx, param, public_key, noxtls_xmss_public_key_len(param), signature, signature_len);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_xmss_verify_update(&ctx, message, message_len);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_xmss_verify_final(&ctx, signature, signature_len);
    }
    noxtls_secure_zero(&ctx, sizeof(ctx));
    return rc;
}

/* ---- key generation and signing --------------------------------------------- */

#if NOXTLS_XMSS_ENABLE_SIGN

noxtls_return_t noxtls_xmss_keygen_from_seed(noxtls_xmss_param_t param,
                                             const uint8_t *seed,
                                             uint32_t seed_len,
                                             uint8_t *public_key,
                                             uint32_t public_key_len,
                                             uint8_t *secret_key,
                                             uint32_t secret_key_len)
{
    xmss_params_t ps;
    const xmss_params_t *p = xmss_params_get(param, &ps);
    xmss_hctx_t hc;
    uint32_t n = 0U;
    uint32_t off = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if(p == NULL) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    if((seed == NULL) || (public_key == NULL) || (secret_key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    n = (uint32_t)p->n;
    if(seed_len != (3U * n)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if((public_key_len < p->pk_len) || (secret_key_len < p->sk_len)) {
        return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }
    /* sk = OID | idx = 0 | SK_SEED | SK_PRF | root | PUB_SEED */
    off = xmss_sk_off_seed(p);
    xmss_store_be(secret_key, 4U, (uint64_t)p->oid);
    xmss_store_be(&secret_key[4], (uint32_t)p->idx_bytes, 0U);
    xmss_copy(&secret_key[off], seed, 2U * n);
    xmss_copy(&secret_key[off + (3U * n)], &seed[2U * n], n);
    rc = xmss_hctx_init(&hc, p, &secret_key[off + (3U * n)], &secret_key[off]);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        /* Root of the single top-layer tree. */
        rc = xmss_tree_pass(&hc, (uint32_t)p->d - 1U, 0U, NULL, &secret_key[off + (2U * n)]);
    }
    xmss_hctx_wipe(&hc);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        xmss_store_be(public_key, 4U, (uint64_t)p->oid);
        xmss_copy(&public_key[4], &secret_key[off + (2U * n)], 2U * n);
    } else {
        noxtls_secure_zero(secret_key, p->sk_len);
        noxtls_secure_zero(public_key, p->pk_len);
    }
    return rc;
}

noxtls_return_t noxtls_xmss_keygen(noxtls_xmss_param_t param,
                                   uint8_t *public_key,
                                   uint32_t public_key_len,
                                   uint8_t *secret_key,
                                   uint32_t secret_key_len)
{
    xmss_params_t ps;
    const xmss_params_t *p = xmss_params_get(param, &ps);
    uint8_t seed[3U * NOXTLS_XMSS_MAX_N];
    drbg_state_t drbg;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if(p == NULL) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    if((public_key == NULL) || (secret_key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if((public_key_len < p->pk_len) || (secret_key_len < p->sk_len)) {
        return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }
    rc = drbg_instantiate(&drbg, DRBG_AES256, NULL, 0U, NULL, 0U, NULL, 0U);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = drbg_generate(&drbg, seed, 3U * (uint32_t)p->n * 8U, NULL, 0U);
    }
    noxtls_secure_zero(&drbg, sizeof(drbg));
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_xmss_keygen_from_seed(param, seed, 3U * (uint32_t)p->n, public_key, public_key_len,
                                          secret_key, secret_key_len);
    }
    noxtls_secure_zero(seed, sizeof(seed));
    return rc;
}

#define XMSS_SIGNER_MAGIC 0x584D5353U /* "XMSS" */

static noxtls_return_t xmss_signer_params(const noxtls_xmss_signer_t *signer, xmss_params_t *ps, const xmss_params_t **p)
{
    if(signer == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if((signer->magic != XMSS_SIGNER_MAGIC) || (signer->secret_key == NULL)) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
    *p = xmss_params_get(signer->param, ps);
    return (*p != NULL) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_xmss_signer_init(noxtls_xmss_signer_t *signer,
                                        noxtls_xmss_param_t param,
                                        uint8_t *secret_key,
                                        uint32_t secret_key_len,
                                        noxtls_xmss_persist_cb_t persist,
                                        void *persist_user,
                                        uint32_t reserve)
{
    xmss_params_t ps;
    const xmss_params_t *p = NULL;
    uint64_t idx = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if(signer == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    noxtls_secure_zero(signer, sizeof(*signer));
    p = xmss_params_get(param, &ps);
    if(p == NULL) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    if(persist == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(reserve == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    rc = xmss_check_secret_key(p, secret_key, secret_key_len, &idx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    signer->param = param;
    signer->secret_key = secret_key;
    signer->secret_key_len = secret_key_len;
    signer->persist = persist;
    signer->persist_user = persist_user;
    signer->reserve = reserve;
    /* Nothing is reserved yet: the stored copy may hold exactly idx. */
    signer->reserved_end = idx;
    signer->magic = XMSS_SIGNER_MAGIC;
    return NOXTLS_RETURN_SUCCESS;
}

uint32_t noxtls_xmss_traversal_state_len(noxtls_xmss_param_t param, uint32_t bds_k)
{
    xmss_params_t ps;
    const xmss_params_t *p = xmss_params_get(param, &ps);

    return (p != NULL) ? xmss_bds_state_len(p, bds_k) : 0U;
}

/* Build the traversal for index idx and check it against the key's root. */
static noxtls_return_t xmss_traversal_build(const xmss_params_t *p, noxtls_xmss_signer_t *signer, uint64_t idx)
{
    xmss_hctx_t hc;
    uint8_t root[NOXTLS_XMSS_MAX_N];
    uint32_t off = xmss_sk_off_seed(p);
    uint32_t n = (uint32_t)p->n;
    const uint8_t *sk = signer->secret_key;
    noxtls_return_t rc = xmss_hctx_init(&hc, p, &sk[off + (3U * n)], &sk[off]);

    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = xmss_bds_init(&hc, signer->traversal, signer->traversal_len, signer->bds_k, idx, root);
    }
    if((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_ct_memcmp(root, &sk[off + (2U * n)], (size_t)n) != 0)) {
        /* SK_SEED / PUB_SEED do not produce the stored root: corrupt key. */
        rc = NOXTLS_RETURN_BAD_DATA;
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(signer->traversal, signer->traversal_len);
    }
    xmss_hctx_wipe(&hc);
    return rc;
}

noxtls_return_t noxtls_xmss_signer_attach_traversal(noxtls_xmss_signer_t *signer,
                                                    uint8_t *state,
                                                    uint32_t state_len,
                                                    uint32_t bds_k)
{
    xmss_params_t ps;
    const xmss_params_t *p = NULL;
    uint64_t idx = 0U;
    uint32_t need = 0U;
    noxtls_return_t rc = xmss_signer_params(signer, &ps, &p);

    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(state == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    need = xmss_bds_state_len(p, bds_k);
    if(need == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(state_len < need) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }
    rc = xmss_check_secret_key(p, signer->secret_key, signer->secret_key_len, &idx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(idx >= xmss_idx_end(p)) {
        return NOXTLS_RETURN_KEY_EXHAUSTED;
    }
    signer->traversal = state;
    signer->traversal_len = need;
    signer->bds_k = bds_k;
    rc = xmss_traversal_build(p, signer, idx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        signer->traversal = NULL;
        signer->traversal_len = 0U;
    }
    return rc;
}

/*
 * Compute the signature for index idx (the index has already been reserved
 * and persisted) into sig.
 */
static noxtls_return_t xmss_sign_index(const xmss_params_t *p, noxtls_xmss_signer_t *signer, uint64_t idx,
                                       const uint8_t *msg, uint32_t msg_len, uint8_t *sig)
{
    const uint8_t *sk = signer->secret_key;
    uint32_t n = (uint32_t)p->n;
    uint32_t th = (uint32_t)p->th;
    uint32_t off_seed = xmss_sk_off_seed(p);
    const uint8_t *sk_seed = &sk[off_seed];
    const uint8_t *sk_prf = &sk[off_seed + n];
    const uint8_t *root = &sk[off_seed + (2U * n)];
    const uint8_t *pub_seed = &sk[off_seed + (3U * n)];
    uint64_t mask = (1ULL << th) - 1U;
    uint8_t digest[NOXTLS_XMSS_MAX_N];
    uint8_t node[NOXTLS_XMSS_MAX_N];
    noxtls_xmss_hash_state_t hs;
    xmss_hctx_t hc;
    uint32_t off = (uint32_t)p->idx_bytes + n;
    uint32_t i = 0U;
    uint8_t use_bds = (signer->traversal != NULL) ? 1U : 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    /* idx || r, r = PRF(SK_PRF, toByte(idx, 32)) */
    xmss_store_be(sig, (uint32_t)p->idx_bytes, idx);
    rc = xmss_prf_idx(p, sk_prf, idx, &sig[p->idx_bytes]);
    /* M' = H_msg(r || root || toByte(idx, n), M) */
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = xmss_hmsg_init(&hs, p, &sig[p->idx_bytes], root, idx);
    }
    if((rc == NOXTLS_RETURN_SUCCESS) && (msg_len != 0U)) {
        rc = xmss_hmsg_update(&hs, msg, msg_len);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = xmss_hmsg_final(&hs, p, digest);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = xmss_hctx_init(&hc, p, pub_seed, sk_seed);
    }
    if((rc == NOXTLS_RETURN_SUCCESS) && (use_bds != 0U)) {
        /* A traversal that does not match the key index (e.g. after a failed
         * signature) is rebuilt; it is only a cache of public nodes. */
        rc = xmss_bds_get(&hc, signer->traversal, 0U, idx, &sig[off + ((uint32_t)p->len * n)], NULL);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            rc = xmss_traversal_build(p, signer, idx);
        }
    }
    xmss_copy(node, digest, n);
    for(i = 0U; (i < (uint32_t)p->d) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        uint64_t tree = idx >> (th * (i + 1U));
        uint32_t leaf = (uint32_t)((idx >> (th * i)) & mask);
        uint8_t *auth = &sig[off + ((uint32_t)p->len * n)];

        rc = xmss_wots_sign(&hc, i, tree, leaf, node, &sig[off]);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            if(use_bds != 0U) {
                rc = xmss_bds_get(&hc, signer->traversal, i, idx, auth, node);
            } else {
                xmss_capture_t cap;

                noxtls_secure_zero(&cap, sizeof(cap));
                cap.s = leaf;
                cap.auth = auth;
                rc = xmss_tree_pass(&hc, i, tree, &cap, node);
            }
        }
        off += ((uint32_t)p->len + th) * n;
    }
    if((rc == NOXTLS_RETURN_SUCCESS) && (use_bds != 0U)) {
        rc = xmss_bds_advance(&hc, signer->traversal, idx);
    }
#if NOXTLS_XMSS_SIGN_SELF_CHECK
    /*
     * Verify before release: a fault in any WOTS+ chain or tree node would
     * otherwise publish a second message under a reused upper-layer one-time
     * key (XMSS^MT) or an invalid signature.
     */
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = xmss_root_from_digest(&hc, idx, digest, &sig[(uint32_t)p->idx_bytes + n], node);
        if((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_ct_memcmp(node, root, (size_t)n) != 0)) {
            rc = NOXTLS_RETURN_FAILED;
        }
    }
#endif
    xmss_hctx_wipe(&hc);
    noxtls_secure_zero(digest, sizeof(digest));
    noxtls_secure_zero(node, sizeof(node));
    return rc;
}

noxtls_return_t noxtls_xmss_sign_stateful(noxtls_xmss_signer_t *signer,
                                          const uint8_t *message,
                                          uint32_t message_len,
                                          uint8_t *signature,
                                          uint32_t *signature_len)
{
    xmss_params_t ps;
    const xmss_params_t *p = NULL;
    uint64_t idx = 0U;
    uint64_t max = 0U;
    uint8_t *sk = NULL;
    noxtls_return_t rc = xmss_signer_params(signer, &ps, &p);

    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if((signature == NULL) || (signature_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(*signature_len < p->sig_len) {
        *signature_len = 0U;
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }
    *signature_len = 0U;
    if((message == NULL) && (message_len != 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    sk = signer->secret_key;
    rc = xmss_check_secret_key(p, sk, signer->secret_key_len, &idx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    max = xmss_idx_end(p);
    if(idx >= max) {
        return NOXTLS_RETURN_KEY_EXHAUSTED;
    }
    noxtls_secure_zero(signature, p->sig_len);

    /* 1. Reserve and persist the index BEFORE any signature material exists. */
    if(idx >= signer->reserved_end) {
        uint64_t end = idx + (uint64_t)signer->reserve;

        if((end > max) || (end < idx)) {
            end = max;
        }
        xmss_store_be(&sk[4], (uint32_t)p->idx_bytes, end);
        rc = signer->persist(signer->persist_user, sk, signer->secret_key_len);
        xmss_store_be(&sk[4], (uint32_t)p->idx_bytes, idx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc; /* fail closed: nothing was signed, the index is not consumed */
        }
        signer->reserved_end = end;
    }
    /* 2. Consume the index in RAM: it is never handed out again. */
    xmss_store_be(&sk[4], (uint32_t)p->idx_bytes, idx + 1U);

    /* 3. Sign (and self-check) with the consumed index. */
    rc = xmss_sign_index(p, signer, idx, message, message_len, signature);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(signature, p->sig_len);
        if(signer->traversal != NULL) {
            signer->traversal[9] = 0U; /* rebuild on next use */
        }
        return rc;
    }

    /* 4. Last one-time key used: wipe the seeds and persist the exhausted key. */
    if((idx + 1U) == max) {
        uint32_t off = xmss_sk_off_seed(p);

        noxtls_secure_zero(&sk[off], 2U * (uint32_t)p->n);
        (void)signer->persist(signer->persist_user, sk, signer->secret_key_len);
        if(signer->traversal != NULL) {
            noxtls_secure_zero(signer->traversal, signer->traversal_len);
        }
    }
    *signature_len = p->sig_len;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_xmss_signer_remaining(const noxtls_xmss_signer_t *signer, uint64_t *remaining)
{
    xmss_params_t ps;
    const xmss_params_t *p = NULL;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if(remaining == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    *remaining = 0U;
    rc = xmss_signer_params(signer, &ps, &p);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_xmss_secret_key_remaining(signer->param, signer->secret_key, signer->secret_key_len, remaining);
    }
    return rc;
}

void noxtls_xmss_signer_free(noxtls_xmss_signer_t *signer)
{
    if(signer == NULL) {
        return;
    }
    if((signer->magic == XMSS_SIGNER_MAGIC) && (signer->traversal != NULL)) {
        noxtls_secure_zero(signer->traversal, signer->traversal_len);
    }
    noxtls_secure_zero(signer, sizeof(*signer));
}

#else /* !NOXTLS_XMSS_ENABLE_SIGN: verification-only build */

noxtls_return_t noxtls_xmss_keygen_from_seed(noxtls_xmss_param_t param, const uint8_t *seed, uint32_t seed_len,
                                             uint8_t *public_key, uint32_t public_key_len,
                                             uint8_t *secret_key, uint32_t secret_key_len)
{
    (void)param;
    (void)seed;
    (void)seed_len;
    (void)public_key;
    (void)public_key_len;
    (void)secret_key;
    (void)secret_key_len;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_xmss_keygen(noxtls_xmss_param_t param, uint8_t *public_key, uint32_t public_key_len,
                                   uint8_t *secret_key, uint32_t secret_key_len)
{
    (void)param;
    (void)public_key;
    (void)public_key_len;
    (void)secret_key;
    (void)secret_key_len;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_xmss_signer_init(noxtls_xmss_signer_t *signer, noxtls_xmss_param_t param,
                                        uint8_t *secret_key, uint32_t secret_key_len,
                                        noxtls_xmss_persist_cb_t persist, void *persist_user, uint32_t reserve)
{
    (void)param;
    (void)secret_key;
    (void)secret_key_len;
    (void)persist;
    (void)persist_user;
    (void)reserve;
    if(signer != NULL) {
        noxtls_secure_zero(signer, sizeof(*signer));
    }
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

uint32_t noxtls_xmss_traversal_state_len(noxtls_xmss_param_t param, uint32_t bds_k)
{
    (void)param;
    (void)bds_k;
    return 0U;
}

noxtls_return_t noxtls_xmss_signer_attach_traversal(noxtls_xmss_signer_t *signer, uint8_t *state,
                                                    uint32_t state_len, uint32_t bds_k)
{
    (void)signer;
    (void)state;
    (void)state_len;
    (void)bds_k;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_xmss_sign_stateful(noxtls_xmss_signer_t *signer, const uint8_t *message, uint32_t message_len,
                                          uint8_t *signature, uint32_t *signature_len)
{
    (void)signer;
    (void)message;
    (void)message_len;
    (void)signature;
    if(signature_len != NULL) {
        *signature_len = 0U;
    }
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_xmss_signer_remaining(const noxtls_xmss_signer_t *signer, uint64_t *remaining)
{
    (void)signer;
    if(remaining != NULL) {
        *remaining = 0U;
    }
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

void noxtls_xmss_signer_free(noxtls_xmss_signer_t *signer)
{
    if(signer != NULL) {
        noxtls_secure_zero(signer, sizeof(*signer));
    }
}

#endif /* NOXTLS_XMSS_ENABLE_SIGN */

noxtls_return_t noxtls_xmss_sign(noxtls_xmss_param_t param,
                                 const uint8_t *secret_key,
                                 const uint8_t *message,
                                 uint32_t message_len,
                                 uint8_t *signature,
                                 uint32_t *signature_len)
{
    (void)param;
    (void)secret_key;
    (void)message;
    (void)message_len;
    (void)signature;
    if(signature_len != NULL) {
        *signature_len = 0U;
    }
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

#endif /* NOXTLS_FEATURE_XMSS */
