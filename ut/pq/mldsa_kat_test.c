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
* File:    mldsa_kat_test.c
* Summary: ML-DSA (FIPS 204) known-answer, round-trip and negative tests.
*
*****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pq_test.h"
#include "pkc/mldsa/noxtls_mldsa.h"
#include "mdigest/sha3/noxtls_sha3.h"
#include "mldsa_kat_vectors.h"

#define MLDSA_NELEMS(a) (sizeof(a) / sizeof((a)[0]))

static uint8_t g_pk[NOXTLS_MLDSA_MAX_PUBLIC_KEY_LEN];
static uint8_t g_sk[NOXTLS_MLDSA_MAX_SECRET_KEY_LEN];
static uint8_t g_sig[NOXTLS_MLDSA_MAX_SIGNATURE_LEN];
static uint8_t g_sig2[NOXTLS_MLDSA_MAX_SIGNATURE_LEN];
static uint8_t g_msg[8192];
static uint8_t g_ctx[256];
static uint8_t g_rnd[32];
static uint32_t g_ws_words[(NOXTLS_MLDSA_MAX_WORKSPACE_LEN / 4U) + 1U];

static const noxtls_mldsa_param_t g_params[3] = { NOXTLS_MLDSA_44, NOXTLS_MLDSA_65, NOXTLS_MLDSA_87 };

static uint32_t hexval(char c)
{
    if((c >= '0') && (c <= '9')) {
        return (uint32_t)(c - '0');
    }
    if((c >= 'A') && (c <= 'F')) {
        return (uint32_t)(c - 'A') + 10U;
    }
    if((c >= 'a') && (c <= 'f')) {
        return (uint32_t)(c - 'a') + 10U;
    }
    return 0U;
}

static uint32_t unhex(uint8_t *out, uint32_t cap, const char *hex)
{
    uint32_t n = 0U;

    while((hex[2U * n] != '\0') && (hex[(2U * n) + 1U] != '\0') && (n < cap)) {
        out[n] = (uint8_t)((hexval(hex[2U * n]) << 4U) | hexval(hex[(2U * n) + 1U]));
        n += 1U;
    }
    return n;
}

static void sha3_256(const uint8_t *in, uint32_t len, uint8_t out[32])
{
    noxtls_sha3_ctx_t ctx;

    (void)noxtls_sha3_256_init(&ctx);
    (void)noxtls_sha3_update(&ctx, in, len);
    (void)noxtls_sha3_finish(&ctx, out);
}

static const char *pname(noxtls_mldsa_param_t p)
{
    return (p == NOXTLS_MLDSA_44) ? "ML-DSA-44" : ((p == NOXTLS_MLDSA_65) ? "ML-DSA-65" : "ML-DSA-87");
}

static void test_sizes(void)
{
    PQ_CHECK(noxtls_mldsa_public_key_len(NOXTLS_MLDSA_44) == 1312U, "pk len 44");
    PQ_CHECK(noxtls_mldsa_secret_key_len(NOXTLS_MLDSA_44) == 2560U, "sk len 44");
    PQ_CHECK(noxtls_mldsa_signature_len(NOXTLS_MLDSA_44) == 2420U, "sig len 44");
    PQ_CHECK(noxtls_mldsa_public_key_len(NOXTLS_MLDSA_65) == 1952U, "pk len 65");
    PQ_CHECK(noxtls_mldsa_secret_key_len(NOXTLS_MLDSA_65) == 4032U, "sk len 65");
    PQ_CHECK(noxtls_mldsa_signature_len(NOXTLS_MLDSA_65) == 3309U, "sig len 65");
    PQ_CHECK(noxtls_mldsa_public_key_len(NOXTLS_MLDSA_87) == 2592U, "pk len 87");
    PQ_CHECK(noxtls_mldsa_secret_key_len(NOXTLS_MLDSA_87) == 4896U, "sk len 87");
    PQ_CHECK(noxtls_mldsa_signature_len(NOXTLS_MLDSA_87) == 4627U, "sig len 87");
    PQ_CHECK(noxtls_mldsa_public_key_len(NOXTLS_MLDSA_NONE) == 0U, "pk len none");
    PQ_CHECK(noxtls_mldsa_signature_len((noxtls_mldsa_param_t)9U) == 0U, "sig len invalid");
    PQ_CHECK(noxtls_mldsa_workspace_len(NOXTLS_MLDSA_44) == 7168U, "ws len 44");
    PQ_CHECK(noxtls_mldsa_workspace_len(NOXTLS_MLDSA_65) == 9216U, "ws len 65");
    PQ_CHECK(noxtls_mldsa_workspace_len(NOXTLS_MLDSA_87) == NOXTLS_MLDSA_MAX_WORKSPACE_LEN, "ws len 87");
    PQ_CHECK(noxtls_mldsa_workspace_len(NOXTLS_MLDSA_NONE) == 0U, "ws len none");
}

static void test_keygen_kat(void)
{
    uint32_t i = 0U;
    uint8_t d[32];

    for(i = 0U; i < MLDSA_NELEMS(g_mldsa_keygen_vecs); i += 1U) {
        const mldsa_keygen_vec_t *v = &g_mldsa_keygen_vecs[i];
        void *ws = ((i & 1U) != 0U) ? (void *)g_ws_words : NULL;
        noxtls_return_t rc = noxtls_mldsa_keygen_ex(v->param, v->seed, g_pk, g_sk, ws,
                                                    (uint32_t)sizeof(g_ws_words));

        PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "keygen_ex KAT");
        sha3_256(g_pk, noxtls_mldsa_public_key_len(v->param), d);
        PQ_CHECK_MEM(d, v->pk_sha3_256, 32U, "keyGen pk digest");
        sha3_256(g_sk, noxtls_mldsa_secret_key_len(v->param), d);
        PQ_CHECK_MEM(d, v->sk_sha3_256, 32U, "keyGen sk digest");
        if(g_pq_test_failures != 0U) {
            printf("    keyGen tcId %lu (%s)\n", (unsigned long)v->tc_id, pname(v->param));
        }
    }
}

static noxtls_return_t sign_vec(noxtls_mldsa_param_t param, uint32_t kind, noxtls_mldsa_prehash_t ph,
                                const uint8_t *sk, const uint8_t *msg, uint32_t msg_len,
                                const uint8_t *ctx, uint32_t ctx_len, const uint8_t *rnd,
                                uint8_t *sig, uint32_t *sig_len, void *ws)
{
    uint32_t wl = (uint32_t)sizeof(g_ws_words);

    if(kind == MLDSA_KAT_EXT_PURE) {
        return noxtls_mldsa_sign_ex(param, sk, msg, msg_len, ctx, ctx_len, rnd, sig, sig_len, ws, wl);
    }
    if(kind == MLDSA_KAT_EXT_PREHASH) {
        return noxtls_mldsa_hash_sign_ex(param, sk, ph, msg, msg_len, ctx, ctx_len, rnd, sig, sig_len, ws, wl);
    }
    return noxtls_mldsa_sign_internal(param, sk, msg, msg_len, (kind == MLDSA_KAT_INT_MU) ? 1U : 0U,
                                      rnd, sig, sig_len, ws, wl);
}

static noxtls_return_t verify_vec(noxtls_mldsa_param_t param, uint32_t kind, noxtls_mldsa_prehash_t ph,
                                  const uint8_t *pk, const uint8_t *msg, uint32_t msg_len,
                                  const uint8_t *ctx, uint32_t ctx_len,
                                  const uint8_t *sig, uint32_t sig_len, void *ws)
{
    uint32_t wl = (uint32_t)sizeof(g_ws_words);

    if(kind == MLDSA_KAT_EXT_PURE) {
        return noxtls_mldsa_verify_ex(param, pk, msg, msg_len, ctx, ctx_len, sig, sig_len, ws, wl);
    }
    if(kind == MLDSA_KAT_EXT_PREHASH) {
        return noxtls_mldsa_hash_verify_ex(param, pk, ph, msg, msg_len, ctx, ctx_len, sig, sig_len, ws, wl);
    }
    return noxtls_mldsa_verify_internal(param, pk, msg, msg_len, (kind == MLDSA_KAT_INT_MU) ? 1U : 0U,
                                        sig, sig_len, ws, wl);
}

static void test_siggen_kat(void)
{
    uint32_t i = 0U;
    uint8_t d[32];

    for(i = 0U; i < MLDSA_NELEMS(g_mldsa_siggen_vecs); i += 1U) {
        const mldsa_siggen_vec_t *v = &g_mldsa_siggen_vecs[i];
        uint32_t sig_len = (uint32_t)sizeof(g_sig);
        uint32_t before = g_pq_test_failures;
        noxtls_return_t rc = NOXTLS_RETURN_FAILED;

        (void)unhex(g_sk, (uint32_t)sizeof(g_sk), v->sk_hex);
        (void)unhex(g_msg, (uint32_t)sizeof(g_msg), v->msg_hex);
        (void)unhex(g_ctx, (uint32_t)sizeof(g_ctx), v->ctx_hex);
        (void)memset(g_rnd, 0, sizeof(g_rnd));
        if(v->rnd_hex != NULL) {
            (void)unhex(g_rnd, (uint32_t)sizeof(g_rnd), v->rnd_hex);
        }
        rc = sign_vec(v->param, v->kind, v->ph, g_sk, g_msg, v->msg_len, g_ctx, v->ctx_len, g_rnd,
                      g_sig, &sig_len, ((i & 1U) != 0U) ? (void *)g_ws_words : NULL);
        PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "sigGen KAT sign");
        PQ_CHECK(sig_len == noxtls_mldsa_signature_len(v->param), "sigGen signature length");
        sha3_256(g_sig, noxtls_mldsa_signature_len(v->param), d);
        PQ_CHECK_MEM(d, v->sig_sha3_256, 32U, "sigGen signature digest");
        if(g_pq_test_failures != before) {
            printf("    sigGen tcId %lu (%s kind %lu)\n", (unsigned long)v->tc_id, pname(v->param),
                   (unsigned long)v->kind);
        }
    }
}

static void test_sigver_kat(void)
{
    uint32_t i = 0U;

    for(i = 0U; i < MLDSA_NELEMS(g_mldsa_sigver_vecs); i += 1U) {
        const mldsa_sigver_vec_t *v = &g_mldsa_sigver_vecs[i];
        uint32_t sig_len = noxtls_mldsa_signature_len(v->param);
        uint32_t before = g_pq_test_failures;
        noxtls_return_t rc = NOXTLS_RETURN_FAILED;

        (void)unhex(g_pk, (uint32_t)sizeof(g_pk), v->pk_hex);
        (void)unhex(g_msg, (uint32_t)sizeof(g_msg), v->msg_hex);
        (void)unhex(g_ctx, (uint32_t)sizeof(g_ctx), v->ctx_hex);
        (void)unhex(g_sig, (uint32_t)sizeof(g_sig), v->sig_hex);
        rc = verify_vec(v->param, v->kind, v->ph, g_pk, g_msg, v->msg_len, g_ctx, v->ctx_len,
                        g_sig, sig_len, ((i & 1U) != 0U) ? (void *)g_ws_words : NULL);
        PQ_CHECK_RC(rc, (v->expect_valid != 0U) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED,
                    "sigVer KAT");
        if(g_pq_test_failures != before) {
            printf("    sigVer tcId %lu (%s kind %lu)\n", (unsigned long)v->tc_id, pname(v->param),
                   (unsigned long)v->kind);
        }
    }
}

/* mu = SHAKE256(tr || 0x00 || len(ctx) || ctx || M, 64), computed independently of the library API. */
static void compute_mu(const uint8_t *sk, const uint8_t *ctx, uint32_t ctx_len,
                       const uint8_t *msg, uint32_t msg_len, uint8_t mu[64])
{
    noxtls_sha3_ctx_t c;
    uint8_t hdr[2];

    hdr[0] = 0U;
    hdr[1] = (uint8_t)ctx_len;
    (void)noxtls_shake256_init(&c);
    (void)noxtls_shake256_update(&c, &sk[64], 64U);
    (void)noxtls_shake256_update(&c, hdr, 2U);
    (void)noxtls_shake256_update(&c, ctx, ctx_len);
    (void)noxtls_shake256_update(&c, msg, msg_len);
    (void)noxtls_shake256_final(&c);
    (void)noxtls_shake256_squeeze(&c, mu, 64U);
}

static const char *mldsa_probe_name(noxtls_mldsa_param_t p, uint32_t op)
{
    static const char *const names[3][3] = {
        { "ML-DSA-44 keygen", "ML-DSA-44 sign", "ML-DSA-44 verify" },
        { "ML-DSA-65 keygen", "ML-DSA-65 sign", "ML-DSA-65 verify" },
        { "ML-DSA-87 keygen", "ML-DSA-87 sign", "ML-DSA-87 verify" }
    };
    uint32_t i = (p == NOXTLS_MLDSA_44) ? 0U : ((p == NOXTLS_MLDSA_65) ? 1U : 2U);
    return names[i][op];
}

static void test_roundtrip_and_negative(noxtls_mldsa_param_t p)
{
    static const uint8_t msg[] = "noxtls ml-dsa round trip message";
    static const uint8_t ctx[] = "ctx-A";
    static const uint8_t ctx_b[] = "ctx-B";
    static uint8_t long_ctx[256];
    uint32_t pk_len = noxtls_mldsa_public_key_len(p);
    uint32_t sk_len = noxtls_mldsa_secret_key_len(p);
    uint32_t sl = noxtls_mldsa_signature_len(p);
    uint32_t sig_len = sl;
    uint32_t sig_len2 = sl;
    uint32_t mlen = (uint32_t)sizeof(msg) - 1U;
    uint32_t clen = (uint32_t)sizeof(ctx) - 1U;
    uint8_t zero_rnd[32];
    uint8_t mu[64];
    uint8_t keep = 0U;
    uint32_t hint_off = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint32_t mark = 0U;

    (void)memset(zero_rnd, 0, sizeof(zero_rnd));
    (void)memset(long_ctx, 0x5A, sizeof(long_ctx));

    /* Public API key generation with a deterministic entropy stream is reproducible. */
    pq_test_rng_seed_label("mldsa-keygen", (uint32_t)p);
    mark = pq_test_probe_begin();
    rc = noxtls_mldsa_keygen(p, g_pk, g_sk);
    pq_test_probe_end(mark, mldsa_probe_name(p, 0U));
    PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "keygen (public API)");
    (void)memcpy(g_sig2, g_pk, pk_len);
    pq_test_rng_seed_label("mldsa-keygen", (uint32_t)p);
    rc = noxtls_mldsa_keygen(p, g_pk, g_sk);
    PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "keygen repeat");
    PQ_CHECK_MEM(g_pk, g_sig2, pk_len, "keygen reproducible under seeded RNG");

    /* Hedged sign / verify through the legacy API (empty context). */
    pq_test_rng_seed_label("mldsa-sign", (uint32_t)p);
    mark = pq_test_probe_begin();
    rc = noxtls_mldsa_sign(p, g_sk, msg, mlen, g_sig, &sig_len);
    pq_test_probe_end(mark, mldsa_probe_name(p, 1U));
    PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "sign (public API)");
    PQ_CHECK(sig_len == sl, "sign length");
    mark = pq_test_probe_begin();
    rc = noxtls_mldsa_verify(p, g_pk, msg, mlen, g_sig, sl);
    pq_test_probe_end(mark, mldsa_probe_name(p, 2U));
    PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "verify");
    PQ_CHECK_RC(noxtls_mldsa_verify_ex(p, g_pk, msg, mlen, NULL, 0U, g_sig, sl, g_ws_words,
                                       (uint32_t)sizeof(g_ws_words)),
                NOXTLS_RETURN_SUCCESS, "verify_ex empty ctx with caller workspace");
    /* Same key, different randomness -> different signature, both valid. */
    pq_test_rng_seed_label("mldsa-sign-2", (uint32_t)p);
    rc = noxtls_mldsa_sign(p, g_sk, msg, mlen, g_sig2, &sig_len2);
    PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "sign #2");
    PQ_CHECK(pq_test_memeq(g_sig, g_sig2, sl) == 0, "hedged signatures differ");
    PQ_CHECK_RC(noxtls_mldsa_verify(p, g_pk, msg, mlen, g_sig2, sl), NOXTLS_RETURN_SUCCESS, "verify #2");

    /* Empty message is allowed. */
    sig_len2 = sl;
    PQ_CHECK_RC(noxtls_mldsa_sign(p, g_sk, NULL, 0U, g_sig2, &sig_len2), NOXTLS_RETURN_SUCCESS, "sign empty");
    PQ_CHECK_RC(noxtls_mldsa_verify(p, g_pk, NULL, 0U, g_sig2, sl), NOXTLS_RETURN_SUCCESS, "verify empty");

    /* Tampering. */
    PQ_CHECK_RC(noxtls_mldsa_verify(p, g_pk, msg, mlen - 1U, g_sig, sl), NOXTLS_RETURN_FAILED, "short msg");
    g_msg[0] = msg[0] ^ 1U;
    (void)memcpy(&g_msg[1], &msg[1], mlen - 1U);
    PQ_CHECK_RC(noxtls_mldsa_verify(p, g_pk, g_msg, mlen, g_sig, sl), NOXTLS_RETURN_FAILED, "tampered msg");
    keep = g_sig[3];
    g_sig[3] ^= 0x10U; /* commitment hash */
    PQ_CHECK_RC(noxtls_mldsa_verify(p, g_pk, msg, mlen, g_sig, sl), NOXTLS_RETURN_FAILED, "tampered c~");
    g_sig[3] = keep;
    keep = g_sig[100];
    g_sig[100] ^= 0x01U; /* z */
    PQ_CHECK_RC(noxtls_mldsa_verify(p, g_pk, msg, mlen, g_sig, sl), NOXTLS_RETURN_FAILED, "tampered z");
    g_sig[100] = keep;
    keep = g_pk[40];
    g_pk[40] ^= 0x04U; /* t1 */
    PQ_CHECK_RC(noxtls_mldsa_verify(p, g_pk, msg, mlen, g_sig, sl), NOXTLS_RETURN_FAILED, "tampered pk t1");
    g_pk[40] = keep;
    keep = g_pk[5];
    g_pk[5] ^= 0x80U; /* rho */
    PQ_CHECK_RC(noxtls_mldsa_verify(p, g_pk, msg, mlen, g_sig, sl), NOXTLS_RETURN_FAILED, "tampered pk rho");
    g_pk[5] = keep;
    PQ_CHECK_RC(noxtls_mldsa_verify(p, g_pk, msg, mlen, g_sig, sl), NOXTLS_RETURN_SUCCESS, "restored");

    /* Hint encoding: last count byte > omega, and non-zero padding. */
    hint_off = sl - 1U; /* last byte = cumulative hint count of row k-1 */
    keep = g_sig[hint_off];
    g_sig[hint_off] = 0xFFU;
    PQ_CHECK_RC(noxtls_mldsa_verify(p, g_pk, msg, mlen, g_sig, sl), NOXTLS_RETURN_FAILED, "hint count > omega");
    g_sig[hint_off] = keep;
    {
        /* hint section starts at sl - (omega + k); total count is the last byte. */
        uint32_t omega_k = (p == NOXTLS_MLDSA_44) ? (80U + 4U) : ((p == NOXTLS_MLDSA_65) ? (55U + 6U) : (75U + 8U));
        uint32_t hstart = sl - omega_k;
        uint32_t total = g_sig[sl - 1U];
        uint32_t omega = omega_k - ((p == NOXTLS_MLDSA_44) ? 4U : ((p == NOXTLS_MLDSA_65) ? 6U : 8U));

        if(total < omega) {
            keep = g_sig[hstart + omega - 1U];
            g_sig[hstart + omega - 1U] = 0x01U; /* padding must be zero */
            PQ_CHECK_RC(noxtls_mldsa_verify(p, g_pk, msg, mlen, g_sig, sl), NOXTLS_RETURN_FAILED,
                        "non-zero hint padding");
            g_sig[hstart + omega - 1U] = keep;
        }
        if(total >= 2U) {
            /* Duplicate position inside one row (rows are cumulative counts). */
            uint8_t a = g_sig[hstart];
            uint8_t b = g_sig[hstart + 1U];
            uint32_t first_row_end = g_sig[hstart + omega];

            if(first_row_end >= 2U) {
                g_sig[hstart + 1U] = a;
                PQ_CHECK_RC(noxtls_mldsa_verify(p, g_pk, msg, mlen, g_sig, sl), NOXTLS_RETURN_FAILED,
                            "unordered hint positions");
                g_sig[hstart + 1U] = b;
            }
        }
        /* Decreasing cumulative count. */
        keep = g_sig[hstart + omega];
        g_sig[hstart + omega] = (uint8_t)(total + 1U);
        PQ_CHECK_RC(noxtls_mldsa_verify(p, g_pk, msg, mlen, g_sig, sl), NOXTLS_RETURN_FAILED,
                    "hint counts not monotonic");
        g_sig[hstart + omega] = keep;
        /* ||z|| out of bound: field value 0 encodes z = gamma1. */
        {
            uint32_t ctl = (p == NOXTLS_MLDSA_44) ? 32U : ((p == NOXTLS_MLDSA_65) ? 48U : 64U);
            uint8_t z0[3];

            (void)memcpy(z0, &g_sig[ctl], 3U);
            g_sig[ctl] = 0U;
            g_sig[ctl + 1U] = 0U;
            g_sig[ctl + 2U] &= 0xF0U;
            PQ_CHECK_RC(noxtls_mldsa_verify(p, g_pk, msg, mlen, g_sig, sl), NOXTLS_RETURN_FAILED,
                        "z coefficient out of range");
            (void)memcpy(&g_sig[ctl], z0, 3U);
        }
    }
    PQ_CHECK_RC(noxtls_mldsa_verify(p, g_pk, msg, mlen, g_sig, sl), NOXTLS_RETURN_SUCCESS, "restored 2");

    /* Lengths and argument validation. */
    PQ_CHECK_RC(noxtls_mldsa_verify(p, g_pk, msg, mlen, g_sig, sl - 1U), NOXTLS_RETURN_INVALID_PARAM, "short sig");
    PQ_CHECK_RC(noxtls_mldsa_verify(p, g_pk, msg, mlen, g_sig, sl + 1U), NOXTLS_RETURN_INVALID_PARAM, "long sig");
    PQ_CHECK_RC(noxtls_mldsa_verify(p, NULL, msg, mlen, g_sig, sl), NOXTLS_RETURN_NULL, "verify NULL pk");
    PQ_CHECK_RC(noxtls_mldsa_verify(p, g_pk, NULL, 4U, g_sig, sl), NOXTLS_RETURN_NULL, "verify NULL msg");
    PQ_CHECK_RC(noxtls_mldsa_verify(NOXTLS_MLDSA_NONE, g_pk, msg, mlen, g_sig, sl),
                NOXTLS_RETURN_INVALID_PARAM, "verify bad param");
    sig_len2 = sl - 1U;
    PQ_CHECK_RC(noxtls_mldsa_sign(p, g_sk, msg, mlen, g_sig2, &sig_len2), NOXTLS_RETURN_INVALID_PARAM,
                "sign buffer too small");
    PQ_CHECK_RC(noxtls_mldsa_sign(p, NULL, msg, mlen, g_sig2, &sig_len2), NOXTLS_RETURN_NULL, "sign NULL sk");
    PQ_CHECK_RC(noxtls_mldsa_sign(p, g_sk, NULL, 1U, g_sig2, &sig_len2), NOXTLS_RETURN_NULL, "sign NULL msg");
    PQ_CHECK_RC(noxtls_mldsa_keygen(p, NULL, g_sk), NOXTLS_RETURN_NULL, "keygen NULL");
    PQ_CHECK_RC(noxtls_mldsa_keygen((noxtls_mldsa_param_t)7U, g_pk, g_sk), NOXTLS_RETURN_INVALID_PARAM,
                "keygen bad param");

    /* Context strings: deterministic signing, wrong / missing context rejected. */
    sig_len = sl;
    rc = noxtls_mldsa_sign_ex(p, g_sk, msg, mlen, ctx, clen, zero_rnd, g_sig, &sig_len, NULL, 0U);
    PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "sign_ex ctx deterministic");
    sig_len2 = sl;
    rc = noxtls_mldsa_sign_ex(p, g_sk, msg, mlen, ctx, clen, zero_rnd, g_sig2, &sig_len2,
                              g_ws_words, (uint32_t)sizeof(g_ws_words));
    PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "sign_ex ctx deterministic (caller ws)");
    PQ_CHECK_MEM(g_sig, g_sig2, sl, "deterministic signing is reproducible");
    PQ_CHECK_RC(noxtls_mldsa_verify_ex(p, g_pk, msg, mlen, ctx, clen, g_sig, sl, NULL, 0U),
                NOXTLS_RETURN_SUCCESS, "verify_ex ctx");
    PQ_CHECK_RC(noxtls_mldsa_verify_ex(p, g_pk, msg, mlen, ctx_b, clen, g_sig, sl, NULL, 0U),
                NOXTLS_RETURN_FAILED, "verify_ex wrong ctx");
    PQ_CHECK_RC(noxtls_mldsa_verify(p, g_pk, msg, mlen, g_sig, sl), NOXTLS_RETURN_FAILED, "verify missing ctx");
    PQ_CHECK_RC(noxtls_mldsa_hash_verify_ex(p, g_pk, NOXTLS_MLDSA_PH_SHA2_256, msg, 32U, ctx, clen, g_sig, sl,
                                            NULL, 0U),
                NOXTLS_RETURN_FAILED, "pure signature does not verify as HashML-DSA");
    PQ_CHECK_RC(noxtls_mldsa_sign_ex(p, g_sk, msg, mlen, long_ctx, 256U, zero_rnd, g_sig2, &sig_len2, NULL, 0U),
                NOXTLS_RETURN_INVALID_PARAM, "ctx > 255");
    PQ_CHECK_RC(noxtls_mldsa_verify_ex(p, g_pk, msg, mlen, NULL, 3U, g_sig, sl, NULL, 0U),
                NOXTLS_RETURN_NULL, "NULL ctx with length");
    sig_len2 = sl;
    PQ_CHECK_RC(noxtls_mldsa_sign_ex(p, g_sk, msg, mlen, long_ctx, 255U, zero_rnd, g_sig2, &sig_len2, NULL, 0U),
                NOXTLS_RETURN_SUCCESS, "ctx = 255");
    PQ_CHECK_RC(noxtls_mldsa_verify_ex(p, g_pk, msg, mlen, long_ctx, 255U, g_sig2, sl, NULL, 0U),
                NOXTLS_RETURN_SUCCESS, "verify ctx = 255");

    /* External mu equals the external interface: Sign_internal(mu) == Sign(M, ctx) for the same rnd. */
    compute_mu(g_sk, ctx, clen, msg, mlen, mu);
    sig_len2 = sl;
    rc = noxtls_mldsa_sign_internal(p, g_sk, mu, 64U, 1U, zero_rnd, g_sig2, &sig_len2, NULL, 0U);
    PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "sign_internal external mu");
    PQ_CHECK_MEM(g_sig2, g_sig, sl, "external-mu signature matches pure ML-DSA signature");
    PQ_CHECK_RC(noxtls_mldsa_verify_internal(p, g_pk, mu, 64U, 1U, g_sig, sl, NULL, 0U),
                NOXTLS_RETURN_SUCCESS, "verify_internal external mu");
    mu[0] ^= 1U;
    PQ_CHECK_RC(noxtls_mldsa_verify_internal(p, g_pk, mu, 64U, 1U, g_sig, sl, NULL, 0U),
                NOXTLS_RETURN_FAILED, "verify_internal wrong mu");
    PQ_CHECK_RC(noxtls_mldsa_verify_internal(p, g_pk, mu, 63U, 1U, g_sig, sl, NULL, 0U),
                NOXTLS_RETURN_INVALID_PARAM, "external mu length");
    PQ_CHECK_RC(noxtls_mldsa_sign_internal(p, g_sk, NULL, 0U, 1U, zero_rnd, g_sig2, &sig_len2, NULL, 0U),
                NOXTLS_RETURN_INVALID_PARAM, "external mu NULL");

    /* HashML-DSA round trip and argument checks. */
    {
        uint8_t digest[64];

        (void)memset(digest, 0xA5, sizeof(digest));
        sig_len2 = sl;
        PQ_CHECK_RC(noxtls_mldsa_hash_sign_ex(p, g_sk, NOXTLS_MLDSA_PH_SHA2_512, digest, 64U, ctx, clen, NULL,
                                              g_sig2, &sig_len2, NULL, 0U),
                    NOXTLS_RETURN_SUCCESS, "hash_sign_ex");
        PQ_CHECK_RC(noxtls_mldsa_hash_verify_ex(p, g_pk, NOXTLS_MLDSA_PH_SHA2_512, digest, 64U, ctx, clen, g_sig2,
                                                sl, NULL, 0U),
                    NOXTLS_RETURN_SUCCESS, "hash_verify_ex");
        PQ_CHECK_RC(noxtls_mldsa_hash_verify_ex(p, g_pk, NOXTLS_MLDSA_PH_SHA3_512, digest, 64U, ctx, clen, g_sig2,
                                                sl, NULL, 0U),
                    NOXTLS_RETURN_FAILED, "hash_verify_ex wrong OID");
        PQ_CHECK_RC(noxtls_mldsa_hash_verify_ex(p, g_pk, NOXTLS_MLDSA_PH_SHA2_512, digest, 32U, ctx, clen, g_sig2,
                                                sl, NULL, 0U),
                    NOXTLS_RETURN_INVALID_PARAM, "hash_verify_ex digest length");
        PQ_CHECK_RC(noxtls_mldsa_hash_sign_ex(p, g_sk, (noxtls_mldsa_prehash_t)99U, digest, 32U, NULL, 0U, NULL,
                                              g_sig2, &sig_len2, NULL, 0U),
                    NOXTLS_RETURN_INVALID_ALGORITHM, "hash_sign_ex unknown ph");
        PQ_CHECK_RC(noxtls_mldsa_hash_sign_ex(p, g_sk, NOXTLS_MLDSA_PH_SHA2_256, NULL, 32U, NULL, 0U, NULL,
                                              g_sig2, &sig_len2, NULL, 0U),
                    NOXTLS_RETURN_NULL, "hash_sign_ex NULL digest");
    }

    /* Workspace validation. */
    sig_len2 = sl;
    PQ_CHECK_RC(noxtls_mldsa_sign_ex(p, g_sk, msg, mlen, NULL, 0U, zero_rnd, g_sig2, &sig_len2, g_ws_words,
                                     noxtls_mldsa_workspace_len(p) - 1U),
                NOXTLS_RETURN_INVALID_BLOCK_SIZE, "small workspace");
    PQ_CHECK_RC(noxtls_mldsa_verify_ex(p, g_pk, msg, mlen, NULL, 0U, g_sig, sl,
                                       (void *)&((uint8_t *)g_ws_words)[1], noxtls_mldsa_workspace_len(p)),
                NOXTLS_RETURN_INVALID_PARAM, "misaligned workspace");
    PQ_CHECK_RC(noxtls_mldsa_keygen_ex(p, zero_rnd, g_pk, g_sk, g_ws_words, 3072U - 4U),
                NOXTLS_RETURN_INVALID_BLOCK_SIZE, "small keygen workspace");

    /* Deprecated hooks are inert. */
    noxtls_mldsa_set_test_seed_sequence(zero_rnd, 32U);
    noxtls_mldsa_set_test_signing_overrides(NULL, 0U, zero_rnd, 32U, 1U);
    (void)sk_len;
}

int noxtls_pq_test_mldsa(void)
{
    uint32_t i = 0U;

    pq_test_begin("ML-DSA (FIPS 204)");
    test_sizes();
    test_keygen_kat();
    test_siggen_kat();
    test_sigver_kat();
    for(i = 0U; i < 3U; i += 1U) {
        test_roundtrip_and_negative(g_params[i]);
    }
    return pq_test_end("ML-DSA (FIPS 204)");
}

NOXTLS_PQ_TEST_MAIN(noxtls_pq_test_mldsa)
