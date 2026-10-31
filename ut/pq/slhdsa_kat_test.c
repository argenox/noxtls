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
* File:    slhdsa_kat_test.c
* Summary: SLH-DSA (FIPS 205) known-answer, negative and round-trip tests
*          against NIST ACVP vectors (ut/pq/vectors/slhdsa_kat_vectors.h).
*
*****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pq_test.h"
#include "noxtls_common.h"
#include "pkc/slhdsa/noxtls_slhdsa.h"
#include "mdigest/sha3/noxtls_sha3.h"
#include "slhdsa_kat_vectors.h"

#define SLHDSA_T_MAX_MSG   (2U + 255U + 4096U)

static uint8_t g_sig[NOXTLS_SLHDSA_MAX_SIGNATURE_LEN + 1U];
/* Round trips run on the 128f sets only. */
#define SLHDSA_T_RT_SIG_LEN 17088U
static uint8_t g_sig2[SLHDSA_T_RT_SIG_LEN];
static uint8_t g_mprime[SLHDSA_T_MAX_MSG];
static uint8_t g_pk[NOXTLS_SLHDSA_MAX_PUBLIC_KEY_LEN];
static uint8_t g_sk[NOXTLS_SLHDSA_MAX_SECRET_KEY_LEN];

typedef struct
{
    noxtls_slhdsa_param_t param;
    uint32_t n;
    uint32_t sig_len;
    uint32_t category;
    uint8_t sha2;
    uint8_t small;
} slhdsa_t_size_t;

static const slhdsa_t_size_t g_sizes[] = {
    { NOXTLS_SLHDSA_SHA2_128S, 16U, 7856U, 1U, 1U, 1U },
    { NOXTLS_SLHDSA_SHA2_128F, 16U, 17088U, 1U, 1U, 0U },
    { NOXTLS_SLHDSA_SHA2_192S, 24U, 16224U, 3U, 1U, 1U },
    { NOXTLS_SLHDSA_SHA2_192F, 24U, 35664U, 3U, 1U, 0U },
    { NOXTLS_SLHDSA_SHA2_256S, 32U, 29792U, 5U, 1U, 1U },
    { NOXTLS_SLHDSA_SHA2_256F, 32U, 49856U, 5U, 1U, 0U },
    { NOXTLS_SLHDSA_SHAKE_128S, 16U, 7856U, 1U, 0U, 1U },
    { NOXTLS_SLHDSA_SHAKE_128F, 16U, 17088U, 1U, 0U, 0U },
    { NOXTLS_SLHDSA_SHAKE_192S, 24U, 16224U, 3U, 0U, 1U },
    { NOXTLS_SLHDSA_SHAKE_192F, 24U, 35664U, 3U, 0U, 0U },
    { NOXTLS_SLHDSA_SHAKE_256S, 32U, 29792U, 5U, 0U, 1U },
    { NOXTLS_SLHDSA_SHAKE_256F, 32U, 49856U, 5U, 0U, 0U },
};

static uint32_t slhdsa_t_n(noxtls_slhdsa_param_t param)
{
    return noxtls_slhdsa_public_key_len(param) / 2U;
}

static void slhdsa_t_sha3_256(const uint8_t *in, uint32_t len, uint8_t out[32])
{
    noxtls_sha3_ctx_t ctx;

    (void)noxtls_sha3_256_init(&ctx);
    (void)noxtls_sha3_update(&ctx, in, len);
    (void)noxtls_sha3_finish(&ctx, out);
}

static uint8_t slhdsa_t_nibble(char c)
{
    if((c >= '0') && (c <= '9')) {
        return (uint8_t)(c - '0');
    }
    if((c >= 'A') && (c <= 'F')) {
        return (uint8_t)(c - 'A' + 10);
    }
    return (uint8_t)(c - 'a' + 10);
}

static void slhdsa_t_unhex(const char *hex, uint8_t *out, uint32_t len)
{
    uint32_t i = 0U;

    for(i = 0U; i < len; i += 1U) {
        out[i] = (uint8_t)((slhdsa_t_nibble(hex[2U * i]) << 4U) | slhdsa_t_nibble(hex[(2U * i) + 1U]));
    }
}

/* Build M' = 0x00 || len(ctx) || ctx || M in g_mprime. */
static uint32_t slhdsa_t_mprime(const uint8_t *msg, uint32_t msg_len, const uint8_t *ctx, uint32_t ctx_len)
{
    if((2U + ctx_len + msg_len) > (uint32_t)sizeof(g_mprime)) {
        PQ_CHECK(0 == 1, "test M' buffer too small");
        return 0U;
    }
    g_mprime[0] = 0x00U;
    g_mprime[1] = (uint8_t)ctx_len;
    if(ctx_len != 0U) {
        (void)memcpy(&g_mprime[2], ctx, ctx_len);
    }
    if(msg_len != 0U) {
        (void)memcpy(&g_mprime[2U + ctx_len], msg, msg_len);
    }
    return 2U + ctx_len + msg_len;
}

static void slhdsa_t_sizes(void)
{
    uint32_t i = 0U;

    for(i = 0U; i < (uint32_t)(sizeof(g_sizes) / sizeof(g_sizes[0])); i += 1U) {
        const slhdsa_t_size_t *s = &g_sizes[i];
        PQ_CHECK(noxtls_slhdsa_public_key_len(s->param) == 2U * s->n, "public key length");
        PQ_CHECK(noxtls_slhdsa_secret_key_len(s->param) == 4U * s->n, "secret key length");
        PQ_CHECK(noxtls_slhdsa_signature_len(s->param) == s->sig_len, "signature length");
        PQ_CHECK(noxtls_slhdsa_security_category(s->param) == s->category, "security category");
        PQ_CHECK(noxtls_slhdsa_is_sha2(s->param) == s->sha2, "hash family");
        PQ_CHECK(noxtls_slhdsa_is_small(s->param) == s->small, "small variant");
    }
    PQ_CHECK(noxtls_slhdsa_public_key_len(NOXTLS_SLHDSA_NONE) == 0U, "invalid param pk len");
    PQ_CHECK(noxtls_slhdsa_signature_len((noxtls_slhdsa_param_t)13U) == 0U, "invalid param sig len");
}

static void slhdsa_t_keygen_kats(void)
{
    uint32_t i = 0U;

    for(i = 0U; i < (uint32_t)(sizeof(g_slhdsa_kat_keygen) / sizeof(g_slhdsa_kat_keygen[0])); i += 1U) {
        const slhdsa_kat_keygen_t *v = &g_slhdsa_kat_keygen[i];
        uint32_t n = slhdsa_t_n(v->param);
        noxtls_return_t rc;

#if defined(NOXTLS_PQ_TEST_QUICK)
        if(noxtls_slhdsa_is_small(v->param) != 0U) {
            continue;
        }
#endif
        rc = noxtls_slhdsa_keygen_from_seed(v->param, v->seeds, &v->seeds[n], &v->seeds[2U * n], g_pk, g_sk);
        PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "keygen_from_seed");
        PQ_CHECK_MEM(g_pk, v->pk, 2U * n, "keyGen KAT pk");
        PQ_CHECK_MEM(g_sk, v->seeds, 3U * n, "keyGen KAT sk seeds");
        PQ_CHECK_MEM(&g_sk[3U * n], &v->pk[n], n, "keyGen KAT sk root");
    }
}

static noxtls_return_t slhdsa_t_verify_vec(uint32_t external, noxtls_slhdsa_param_t param, const uint8_t *pk,
                                           const uint8_t *msg, uint32_t msg_len, const uint8_t *ctx,
                                           uint32_t ctx_len, const uint8_t *sig, uint32_t sig_len)
{
    if(external != 0U) {
        return noxtls_slhdsa_verify_ctx(param, pk, msg, msg_len, ctx, ctx_len, sig, sig_len);
    }
    return noxtls_slhdsa_verify_internal(param, pk, msg, msg_len, sig, sig_len);
}

static void slhdsa_t_siggen_kats(void)
{
    uint32_t i = 0U;

    for(i = 0U; i < (uint32_t)(sizeof(g_slhdsa_kat_siggen) / sizeof(g_slhdsa_kat_siggen[0])); i += 1U) {
        const slhdsa_kat_siggen_t *v = &g_slhdsa_kat_siggen[i];
        uint32_t n = slhdsa_t_n(v->param);
        uint32_t sig_len = sizeof(g_sig);
        uint32_t expect_len = noxtls_slhdsa_signature_len(v->param);
        const uint8_t *pk = &v->sk[2U * n];
        const uint8_t *m = v->msg;
        uint32_t m_len = v->msg_len;
        uint8_t digest[32];
        noxtls_return_t rc;

#if defined(NOXTLS_PQ_TEST_QUICK)
        /* Slow targets: sign only the category-1 (128f) KATs; the larger sets keep sigVer coverage. */
        if(noxtls_slhdsa_security_category(v->param) != 1U) {
            continue;
        }
#endif
        if(v->external != 0U) {
            m_len = slhdsa_t_mprime(v->msg, v->msg_len, v->ctx, v->ctx_len);
            m = g_mprime;
        }
        rc = noxtls_slhdsa_sign_internal(v->param, v->sk, m, m_len, v->addrnd, g_sig, &sig_len);
        PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "sign_internal (sigGen KAT)");
        PQ_CHECK(sig_len == expect_len, "sigGen KAT signature length");
        slhdsa_t_sha3_256(g_sig, expect_len, digest);
        PQ_CHECK_MEM(digest, v->sig_sha3_256, 32U, "sigGen KAT SHA3-256(signature)");

        /* The KAT signature must verify through both interfaces. */
        rc = noxtls_slhdsa_verify_internal(v->param, pk, m, m_len, g_sig, expect_len);
        PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "verify_internal of KAT signature");
        rc = slhdsa_t_verify_vec(v->external, v->param, pk, v->msg, v->msg_len, v->ctx, v->ctx_len,
                                 g_sig, expect_len);
        PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "verify of KAT signature");

        if(v->external != 0U) {
            /* Deterministic external interface through the public API equivalence:
             * the empty-context public verify must reject a non-empty-context signature. */
            if(v->ctx_len != 0U) {
                rc = noxtls_slhdsa_verify(v->param, pk, v->msg, v->msg_len, g_sig, expect_len);
                PQ_CHECK_RC(rc, NOXTLS_RETURN_FAILED, "verify with wrong (empty) context");
            }
        }

        /* Negative: tamper R, FORS, hypertree, message, public key, length. */
        g_sig[0] ^= 0x01U;
        PQ_CHECK_RC(noxtls_slhdsa_verify_internal(v->param, pk, m, m_len, g_sig, expect_len),
                    NOXTLS_RETURN_FAILED, "tampered R rejected");
        g_sig[0] ^= 0x01U;
        g_sig[n + 5U] ^= 0x80U;
        PQ_CHECK_RC(noxtls_slhdsa_verify_internal(v->param, pk, m, m_len, g_sig, expect_len),
                    NOXTLS_RETURN_FAILED, "tampered FORS rejected");
        g_sig[n + 5U] ^= 0x80U;
        g_sig[expect_len - 1U] ^= 0x04U;
        PQ_CHECK_RC(noxtls_slhdsa_verify_internal(v->param, pk, m, m_len, g_sig, expect_len),
                    NOXTLS_RETURN_FAILED, "tampered hypertree rejected");
        g_sig[expect_len - 1U] ^= 0x04U;
        PQ_CHECK_RC(noxtls_slhdsa_verify_internal(v->param, pk, m, m_len - 1U, g_sig, expect_len),
                    NOXTLS_RETURN_FAILED, "truncated message rejected");
        PQ_CHECK_RC(noxtls_slhdsa_verify_internal(v->param, pk, m, m_len, g_sig, expect_len - 1U),
                    NOXTLS_RETURN_FAILED, "short signature rejected");
        PQ_CHECK_RC(noxtls_slhdsa_verify_internal(v->param, pk, m, m_len, g_sig, expect_len + 1U),
                    NOXTLS_RETURN_FAILED, "long signature rejected");
        (void)memcpy(g_pk, pk, 2U * n);
        g_pk[(2U * n) - 1U] ^= 0x01U;
        PQ_CHECK_RC(noxtls_slhdsa_verify_internal(v->param, g_pk, m, m_len, g_sig, expect_len),
                    NOXTLS_RETURN_FAILED, "wrong PK.root rejected");
        g_pk[(2U * n) - 1U] ^= 0x01U;
        g_pk[0] ^= 0x01U;
        PQ_CHECK_RC(noxtls_slhdsa_verify_internal(v->param, g_pk, m, m_len, g_sig, expect_len),
                    NOXTLS_RETURN_FAILED, "wrong PK.seed rejected");
    }
}

static void slhdsa_t_sigver_kats(void)
{
    uint32_t i = 0U;

    for(i = 0U; i < (uint32_t)(sizeof(g_slhdsa_kat_sigver) / sizeof(g_slhdsa_kat_sigver[0])); i += 1U) {
        const slhdsa_kat_sigver_t *v = &g_slhdsa_kat_sigver[i];
        noxtls_return_t rc;

        slhdsa_t_unhex(v->sig_hex, g_sig, v->sig_len);
        rc = slhdsa_t_verify_vec(v->external, v->param, v->pk, v->msg, v->msg_len, v->ctx, v->ctx_len,
                                 g_sig, v->sig_len);
        PQ_CHECK_RC(rc, (v->expect_valid != 0U) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED,
                    "sigVer KAT");
        if(v->expect_valid != 0U) {
            g_sig[v->sig_len / 2U] ^= 0x10U;
            rc = slhdsa_t_verify_vec(v->external, v->param, v->pk, v->msg, v->msg_len, v->ctx, v->ctx_len,
                                     g_sig, v->sig_len);
            PQ_CHECK_RC(rc, NOXTLS_RETURN_FAILED, "sigVer KAT tampered");
        }
    }
}

static void slhdsa_t_roundtrip(noxtls_slhdsa_param_t param)
{
    static const uint8_t msg[] = "NoxTLS SLH-DSA round trip";
    static const uint8_t ctx[] = "ctx";
    uint32_t sig_len = sizeof(g_sig);
    uint32_t sig2_len = sizeof(g_sig2);
    uint32_t expect_len = noxtls_slhdsa_signature_len(param);
    uint32_t small_len = expect_len - 1U;
    uint8_t big_ctx[256];
    uint32_t mark = 0U;
    noxtls_return_t rc;

    if(expect_len > SLHDSA_T_RT_SIG_LEN) {
        PQ_CHECK(0 == 1, "round trip parameter set too large for the test buffers");
        return;
    }

    pq_test_rng_seed_label("slhdsa-roundtrip", param);
    mark = pq_test_probe_begin();
    rc = noxtls_slhdsa_keygen(param, g_pk, g_sk);
    pq_test_probe_end(mark, (param == NOXTLS_SLHDSA_SHA2_128F) ? "SLH-DSA-SHA2-128f keygen" : "SLH-DSA-SHAKE-128f keygen");
    PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "keygen");
    PQ_CHECK_MEM(&g_sk[noxtls_slhdsa_secret_key_len(param) / 2U], g_pk, noxtls_slhdsa_public_key_len(param),
                 "sk embeds pk");

    mark = pq_test_probe_begin();
    rc = noxtls_slhdsa_sign(param, g_sk, msg, (uint32_t)sizeof(msg), g_sig, &sig_len);
    pq_test_probe_end(mark, (param == NOXTLS_SLHDSA_SHA2_128F) ? "SLH-DSA-SHA2-128f sign" : "SLH-DSA-SHAKE-128f sign");
    PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "sign");
    PQ_CHECK(sig_len == expect_len, "sign length");
    mark = pq_test_probe_begin();
    rc = noxtls_slhdsa_verify(param, g_pk, msg, (uint32_t)sizeof(msg), g_sig, sig_len);
    pq_test_probe_end(mark, (param == NOXTLS_SLHDSA_SHA2_128F) ? "SLH-DSA-SHA2-128f verify" : "SLH-DSA-SHAKE-128f verify");
    PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "verify");
    PQ_CHECK_RC(noxtls_slhdsa_verify_ctx(param, g_pk, msg, (uint32_t)sizeof(msg), NULL, 0U, g_sig, sig_len),
                NOXTLS_RETURN_SUCCESS, "verify_ctx(empty)");
    /* Pure interface: M' = 0x00 || 0x00 || M. */
    {
        uint32_t m_len = slhdsa_t_mprime(msg, (uint32_t)sizeof(msg), NULL, 0U);
        PQ_CHECK_RC(noxtls_slhdsa_verify_internal(param, g_pk, g_mprime, m_len, g_sig, sig_len),
                    NOXTLS_RETURN_SUCCESS, "pure sign == internal sign over M'");
        PQ_CHECK_RC(noxtls_slhdsa_verify_internal(param, g_pk, msg, (uint32_t)sizeof(msg), g_sig, sig_len),
                    NOXTLS_RETURN_FAILED, "pure signature is not an internal signature over M");
    }
    PQ_CHECK_RC(noxtls_slhdsa_verify(param, g_pk, msg, (uint32_t)sizeof(msg) - 1U, g_sig, sig_len),
                NOXTLS_RETURN_FAILED, "verify wrong message");

    /* Hedged signing: two signatures differ, both verify. */
    rc = noxtls_slhdsa_sign(param, g_sk, msg, (uint32_t)sizeof(msg), g_sig2, &sig2_len);
    PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "second sign");
    PQ_CHECK(memcmp(g_sig, g_sig2, expect_len) != 0, "hedged signatures differ");
    PQ_CHECK_RC(noxtls_slhdsa_verify(param, g_pk, msg, (uint32_t)sizeof(msg), g_sig2, sig2_len),
                NOXTLS_RETURN_SUCCESS, "verify second signature");

    /* Context strings. */
    sig_len = sizeof(g_sig);
    rc = noxtls_slhdsa_sign_ctx(param, g_sk, msg, (uint32_t)sizeof(msg), ctx, 3U, g_sig, &sig_len);
    PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "sign_ctx");
    PQ_CHECK_RC(noxtls_slhdsa_verify_ctx(param, g_pk, msg, (uint32_t)sizeof(msg), ctx, 3U, g_sig, sig_len),
                NOXTLS_RETURN_SUCCESS, "verify_ctx");
    PQ_CHECK_RC(noxtls_slhdsa_verify_ctx(param, g_pk, msg, (uint32_t)sizeof(msg), ctx, 2U, g_sig, sig_len),
                NOXTLS_RETURN_FAILED, "verify_ctx wrong context");
    PQ_CHECK_RC(noxtls_slhdsa_verify(param, g_pk, msg, (uint32_t)sizeof(msg), g_sig, sig_len),
                NOXTLS_RETURN_FAILED, "verify without context");

    /* Deterministic internal signing is reproducible. */
    sig_len = sizeof(g_sig);
    sig2_len = sizeof(g_sig2);
    PQ_CHECK_RC(noxtls_slhdsa_sign_internal(param, g_sk, msg, 5U, NULL, g_sig, &sig_len),
                NOXTLS_RETURN_SUCCESS, "deterministic sign 1");
    PQ_CHECK_RC(noxtls_slhdsa_sign_internal(param, g_sk, msg, 5U, NULL, g_sig2, &sig2_len),
                NOXTLS_RETURN_SUCCESS, "deterministic sign 2");
    PQ_CHECK_MEM(g_sig, g_sig2, expect_len, "deterministic signatures equal");
    PQ_CHECK_RC(noxtls_slhdsa_sign_internal(param, g_sk, NULL, 0U, NULL, g_sig, &sig_len),
                NOXTLS_RETURN_SUCCESS, "sign empty message");
    PQ_CHECK_RC(noxtls_slhdsa_verify_internal(param, g_pk, NULL, 0U, g_sig, sig_len),
                NOXTLS_RETURN_SUCCESS, "verify empty message");

    /* Argument validation. */
    (void)memset(big_ctx, 0x5A, sizeof(big_ctx));
    sig_len = sizeof(g_sig);
    PQ_CHECK_RC(noxtls_slhdsa_sign_ctx(param, g_sk, msg, 4U, big_ctx, 256U, g_sig, &sig_len),
                NOXTLS_RETURN_INVALID_PARAM, "context longer than 255 rejected");
    PQ_CHECK_RC(noxtls_slhdsa_verify_ctx(param, g_pk, msg, 4U, big_ctx, 256U, g_sig, expect_len),
                NOXTLS_RETURN_INVALID_PARAM, "verify context longer than 255 rejected");
    PQ_CHECK_RC(noxtls_slhdsa_sign(param, g_sk, msg, 4U, g_sig, &small_len),
                NOXTLS_RETURN_INVALID_BLOCK_SIZE, "small signature buffer rejected");
    PQ_CHECK_RC(noxtls_slhdsa_sign(param, NULL, msg, 4U, g_sig, &sig_len), NOXTLS_RETURN_NULL, "NULL sk");
    PQ_CHECK_RC(noxtls_slhdsa_sign(param, g_sk, NULL, 4U, g_sig, &sig_len), NOXTLS_RETURN_NULL, "NULL msg");
    PQ_CHECK_RC(noxtls_slhdsa_sign_ctx(param, g_sk, msg, 4U, NULL, 3U, g_sig, &sig_len),
                NOXTLS_RETURN_NULL, "NULL ctx with length");
    PQ_CHECK_RC(noxtls_slhdsa_verify(param, NULL, msg, 4U, g_sig, expect_len), NOXTLS_RETURN_NULL, "NULL pk");
    PQ_CHECK_RC(noxtls_slhdsa_verify(param, g_pk, msg, 4U, NULL, expect_len), NOXTLS_RETURN_NULL, "NULL sig");
    PQ_CHECK_RC(noxtls_slhdsa_keygen(param, NULL, g_sk), NOXTLS_RETURN_NULL, "keygen NULL pk");
    PQ_CHECK_RC(noxtls_slhdsa_keygen_from_seed(param, NULL, g_sk, g_sk, g_pk, g_sk), NOXTLS_RETURN_NULL,
                "keygen_from_seed NULL seed");
    PQ_CHECK_RC(noxtls_slhdsa_keygen(NOXTLS_SLHDSA_NONE, g_pk, g_sk), NOXTLS_RETURN_INVALID_PARAM,
                "keygen invalid param");
    PQ_CHECK_RC(noxtls_slhdsa_sign(NOXTLS_SLHDSA_NONE, g_sk, msg, 4U, g_sig, &sig_len),
                NOXTLS_RETURN_INVALID_PARAM, "sign invalid param");
    PQ_CHECK_RC(noxtls_slhdsa_verify((noxtls_slhdsa_param_t)99U, g_pk, msg, 4U, g_sig, expect_len),
                NOXTLS_RETURN_INVALID_PARAM, "verify invalid param");
}

int noxtls_pq_test_slhdsa(void)
{
    pq_test_begin("slhdsa");
    slhdsa_t_sizes();
    slhdsa_t_keygen_kats();
    slhdsa_t_siggen_kats();
    slhdsa_t_sigver_kats();
    slhdsa_t_roundtrip(NOXTLS_SLHDSA_SHA2_128F);
    slhdsa_t_roundtrip(NOXTLS_SLHDSA_SHAKE_128F);
    return pq_test_end("slhdsa");
}

NOXTLS_PQ_TEST_MAIN(noxtls_pq_test_slhdsa)
