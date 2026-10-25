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
* File:    xmss_kat_test.c
* Summary: XMSS / XMSS^MT (RFC 8391, SP 800-208) tests: parameter/size
*          contract, known answers from the XMSS reference implementation and
*          an independent Python model (ut/pq/vectors/xmss_kat_vectors.h),
*          verification of complete reference signatures, negative and
*          strict-parsing tests, streaming verification, stateful signing
*          (persist-before-release, reserve-N, fail-closed persistence,
*          exhaustion, XMSS^MT layer rollover) and BDS traversal.
*
*          Work is bounded per vector in SHA-256 leaf computations (keygen plus
*          one stateless signature; a SHAKE leaf counts 5): vectors up to
*          XMSS_T_LIGHT_COST all run, vectors up to XMSS_T_MAX_COST run once
*          per parameter set.  Default host build: all h/d = 5 sets plus one
*          vector of each SHA-256 XMSS h = 10 set; -DXMSS_T_SLOW=1 (ctest label
*          "slow"): everything up to SHA-256 h = 16 / SHAKE h/d = 10; Cortex-M
*          image (NOXTLS_PQ_TEST_QUICK): SHA-256 h/d = 5 sets.
*
*****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#if !defined(NOXTLS_PQ_TEST_ARM)
#include <time.h>
#endif

#include "pq_test.h"
#include "noxtls_common.h"
#include "pkc/xmss/noxtls_xmss.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha3/noxtls_sha3.h"
#include "xmss_kat_vectors.h"

#define XMSS_T_NELEMS(a) ((uint32_t)(sizeof(a) / sizeof((a)[0])))

#if defined(XMSS_T_SLOW) && (XMSS_T_SLOW != 0)
#define XMSS_T_MAX_COST 400000UL
#define XMSS_T_LIGHT_COST 400000UL
#elif defined(NOXTLS_PQ_TEST_QUICK)
#define XMSS_T_MAX_COST 512UL
#define XMSS_T_LIGHT_COST 512UL
#else
#define XMSS_T_MAX_COST 2100UL
#define XMSS_T_LIGHT_COST 1000UL
#endif

static uint8_t g_pk[NOXTLS_XMSS_MAX_PUBLIC_KEY_LEN];
static uint8_t g_sk[NOXTLS_XMSS_MAX_SECRET_KEY_LEN];
#if NOXTLS_XMSS_ENABLE_SIGN
static uint8_t g_pk2[NOXTLS_XMSS_MAX_PUBLIC_KEY_LEN];
static uint8_t g_sk2[NOXTLS_XMSS_MAX_SECRET_KEY_LEN];
#endif
static uint8_t g_seed[3U * NOXTLS_XMSS_MAX_N];
static uint8_t g_msg[256];
static uint8_t g_sig[NOXTLS_XMSS_MAX_SIGNATURE_LEN + 8U];
static uint8_t g_sig2[NOXTLS_XMSS_MAX_SIGNATURE_LEN + 8U];
#if NOXTLS_XMSS_ENABLE_SIGN
/* Traversal state for XMSS h = 10 (k <= 8) and XMSS^MT h/d = 5. */
static uint8_t g_bds[16384];
#endif

/* ---- helpers ------------------------------------------------------------- */

static uint32_t xmss_t_nibble(char c)
{
    if((c >= '0') && (c <= '9')) {
        return (uint32_t)(c - '0');
    }
    if((c >= 'A') && (c <= 'F')) {
        return (uint32_t)(c - 'A') + 10U;
    }
    return (uint32_t)(c - 'a') + 10U;
}

static uint32_t xmss_t_unhex(uint8_t *out, uint32_t cap, const char *hex)
{
    uint32_t n = (uint32_t)(strlen(hex) / 2U);
    uint32_t i = 0U;

    if(n > cap) {
        return 0U;
    }
    for(i = 0U; i < n; i += 1U) {
        out[i] = (uint8_t)((xmss_t_nibble(hex[2U * i]) << 4U) | xmss_t_nibble(hex[(2U * i) + 1U]));
    }
    return n;
}

static void xmss_t_sha256(const uint8_t *in, uint32_t len, uint8_t out[32])
{
    noxtls_sha_ctx_t ctx;

    (void)noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256);
    (void)noxtls_sha256_update(&ctx, in, len);
    (void)noxtls_sha256_finish(&ctx, out);
}

static void xmss_t_shake128_10(const uint8_t *in, uint32_t len, uint8_t out[10])
{
    noxtls_sha3_ctx_t ctx;

    (void)noxtls_shake128_init(&ctx);
    (void)noxtls_shake128_update(&ctx, in, len);
    (void)noxtls_shake128_final(&ctx);
    (void)noxtls_shake128_squeeze(&ctx, out, 10U);
}

static void xmss_t_gen(uint8_t *out, uint32_t len, uint32_t mul, uint32_t add)
{
    uint32_t i = 0U;

    for(i = 0U; i < len; i += 1U) {
        out[i] = (uint8_t)(((i * mul) + add) & 0xFFU);
    }
}

static void xmss_t_msg(uint32_t len)
{
    xmss_t_gen(g_msg, len, 7U, 37U);
}

static int xmss_t_all_zero(const uint8_t *p, uint32_t len)
{
    uint32_t i = 0U;

    for(i = 0U; i < len; i += 1U) {
        if(p[i] != 0U) {
            return 0;
        }
    }
    return 1;
}

static void xmss_t_store_be(uint8_t *out, uint32_t len, uint64_t v)
{
    uint32_t i = len;

    while(i > 0U) {
        i -= 1U;
        out[i] = (uint8_t)(v & 0xFFU);
        v >>= 8U;
    }
}

static uint64_t xmss_t_load_be(const uint8_t *in, uint32_t len)
{
    uint64_t v = 0U;
    uint32_t i = 0U;

    for(i = 0U; i < len; i += 1U) {
        v = (v << 8U) | in[i];
    }
    return v;
}

/* Leaf computations for keygen plus one stateless signature (SHAKE leaves cost ~5 SHA-256 leaves). */
static unsigned long xmss_t_cost(const noxtls_xmss_param_info_t *info)
{
    unsigned long w = ((info->hash == NOXTLS_XMSS_HASH_SHAKE128) || (info->hash == NOXTLS_XMSS_HASH_SHAKE256)) ? 5UL : 1UL;

    return (1UL << info->tree_height) * (1UL + (unsigned long)info->layers) * w;
}

#if !defined(NOXTLS_PQ_TEST_ARM)
static double xmss_t_now(void)
{
    return (double)clock() / (double)CLOCKS_PER_SEC;
}
#define XMSS_T_TIMER_START(t) double t = xmss_t_now()
#define XMSS_T_ELAPSED(t) (xmss_t_now() - (t))
#else
#define XMSS_T_TIMER_START(t) double t = 0.0
#define XMSS_T_ELAPSED(t) ((t) * 0.0)
#endif

/* ---- persistence fixture ----------------------------------------------- */

typedef struct
{
    uint32_t calls;
    uint32_t fail_next;           /* fail this many upcoming calls */
    uint32_t sig_clean_at_call;   /* 1 while every reservation call saw no signature material */
    uint32_t len;
    uint64_t last_idx;
    uint32_t idx_bytes;
    uint8_t image[NOXTLS_XMSS_MAX_SECRET_KEY_LEN];
    const uint8_t *watch;         /* output buffer that must still be empty */
    uint32_t watch_len;
} xmss_t_store_t;

static xmss_t_store_t g_store;

static noxtls_return_t xmss_t_persist(void *user, const uint8_t *sk, uint32_t len)
{
    xmss_t_store_t *s = (xmss_t_store_t *)user;

    s->calls += 1U;
    /* The exhausted-key image (seeds wiped) is persisted after the last signature; every other call
     * reserves indices and must happen before any signature byte exists. */
    if((s->watch != NULL) && (xmss_t_all_zero(s->watch, s->watch_len) == 0) &&
       (xmss_t_all_zero(&sk[4U + s->idx_bytes], 16U) == 0)) {
        s->sig_clean_at_call = 0U;
    }
    if(s->fail_next > 0U) {
        s->fail_next -= 1U;
        return NOXTLS_RETURN_FAILED;
    }
    if(len > (uint32_t)sizeof(s->image)) {
        return NOXTLS_RETURN_FAILED;
    }
    (void)memcpy(s->image, sk, len);
    s->len = len;
    s->last_idx = xmss_t_load_be(&sk[4], s->idx_bytes);
    return NOXTLS_RETURN_SUCCESS;
}

static void xmss_t_store_reset(const noxtls_xmss_param_info_t *info)
{
    (void)memset(&g_store, 0, sizeof(g_store));
    g_store.sig_clean_at_call = 1U;
    g_store.idx_bytes = info->index_len;
    g_store.watch = g_sig;
}

/* Deterministic key from (mul, add) seeds, private-key index set to idx. */
static noxtls_return_t xmss_t_key(noxtls_xmss_param_t param, const noxtls_xmss_param_info_t *info,
                                  uint32_t mul, uint32_t add, uint64_t idx)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    xmss_t_gen(g_seed, 3U * info->n, mul, add);
    rc = noxtls_xmss_keygen_from_seed(param, g_seed, 3U * info->n, g_pk, (uint32_t)sizeof(g_pk),
                                      g_sk, (uint32_t)sizeof(g_sk));
    if(rc == NOXTLS_RETURN_SUCCESS) {
        xmss_t_store_be(&g_sk[4], info->index_len, idx);
    }
    return rc;
}

static noxtls_return_t xmss_t_sign_once(noxtls_xmss_param_t param, const noxtls_xmss_param_info_t *info,
                                        uint32_t msg_len, uint32_t *sig_len)
{
    noxtls_xmss_signer_t signer;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    xmss_t_store_reset(info);
    g_store.watch_len = info->signature_len;
    rc = noxtls_xmss_signer_init(&signer, param, g_sk, info->secret_key_len, xmss_t_persist, &g_store, 1U);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        *sig_len = (uint32_t)sizeof(g_sig);
        rc = noxtls_xmss_sign_stateful(&signer, g_msg, msg_len, g_sig, sig_len);
    }
    noxtls_xmss_signer_free(&signer);
    return rc;
}

/* ---- parameter / size contract ------------------------------------------- */

static void xmss_t_params(void)
{
    uint32_t i = 0U;
    uint32_t enabled = 0U;

    for(i = 0U; i < XMSS_T_NELEMS(g_xmss_params); i += 1U) {
        const xmss_param_row_t *r = &g_xmss_params[i];
        noxtls_xmss_param_info_t info;
        noxtls_xmss_param_t back = NOXTLS_XMSS_NONE;
        noxtls_return_t rc = noxtls_xmss_get_param_info(r->param, &info);

        if(noxtls_xmss_signature_len(r->param) == 0U) {
            /* Compiled out (hash family / n = 64 / max height): every API must refuse it. */
            PQ_CHECK_RC(rc, NOXTLS_RETURN_NOT_SUPPORTED, "disabled set: info");
            PQ_CHECK(noxtls_xmss_public_key_len(r->param) == 0U, "disabled set: pk len");
            PQ_CHECK(noxtls_xmss_max_signatures(r->param) == 0U, "disabled set: max sigs");
            PQ_CHECK_RC(noxtls_xmss_verify(r->param, g_pk, g_msg, 1U, g_sig, r->sig_len),
                        NOXTLS_RETURN_NOT_SUPPORTED, "disabled set: verify");
            continue;
        }
        enabled += 1U;
        PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "param info");
        PQ_CHECK(noxtls_xmss_public_key_len(r->param) == r->pk_len, "public key length");
        PQ_CHECK(noxtls_xmss_secret_key_len(r->param) == r->sk_len, "secret key length");
        PQ_CHECK(noxtls_xmss_signature_len(r->param) == r->sig_len, "signature length");
        PQ_CHECK(r->pk_len <= NOXTLS_XMSS_MAX_PUBLIC_KEY_LEN, "max public key");
        PQ_CHECK(r->sk_len <= NOXTLS_XMSS_MAX_SECRET_KEY_LEN, "max secret key");
        PQ_CHECK(r->sig_len <= NOXTLS_XMSS_MAX_SIGNATURE_LEN, "max signature");
        PQ_CHECK(noxtls_xmss_max_signatures(r->param) ==
                 (((r->is_mt != 0U) && (r->h == 40U)) ? ((1ULL << r->h) - 1U) : (1ULL << r->h)), "max signatures");
        PQ_CHECK((info.n == r->n) && (info.height == r->h) && (info.layers == r->d) &&
                 (info.tree_height == (r->h / r->d)) && (info.w == 16U) && (info.oid == r->oid) &&
                 (info.is_mt == r->is_mt) && (info.sp800_208 == r->sp800_208) &&
                 (info.wots_len == (uint8_t)((2U * r->n) + 3U)), "param info fields");
        PQ_CHECK_RC(noxtls_xmss_param_from_oid(r->oid, r->is_mt, &back), NOXTLS_RETURN_SUCCESS, "param from oid");
        PQ_CHECK(back == r->param, "param from oid value");
    }
    printf("  %lu of %lu parameter sets enabled\n", (unsigned long)enabled, (unsigned long)XMSS_T_NELEMS(g_xmss_params));
    PQ_CHECK(enabled > 0U, "some parameter sets enabled");
    PQ_CHECK(noxtls_xmss_public_key_len(NOXTLS_XMSS_NONE) == 0U, "NONE");
    PQ_CHECK(noxtls_xmss_signature_len((noxtls_xmss_param_t)22U) == 0U, "XMSS OID 22");
    PQ_CHECK(noxtls_xmss_signature_len(NOXTLS_XMSS_PARAM_MT_FLAG | 57U) == 0U, "XMSS^MT OID 57");
    PQ_CHECK(noxtls_xmss_signature_len(NOXTLS_XMSS_PARAM_MT_FLAG) == 0U, "XMSS^MT OID 0");
    PQ_CHECK(noxtls_xmss_signature_len(0x00020001U) == 0U, "unknown flag bits");
    PQ_CHECK(noxtls_xmss_signature_len(0x80000001U) == 0U, "unknown flag bits (2)");
    PQ_CHECK_RC(noxtls_xmss_get_param_info(NOXTLS_XMSS_SHA2_10_256, NULL), NOXTLS_RETURN_NULL, "info NULL");
    PQ_CHECK_RC(noxtls_xmss_param_from_oid(1U, 0U, NULL), NOXTLS_RETURN_NULL, "from oid NULL");
    {
        noxtls_xmss_param_t back = 1U;
        PQ_CHECK_RC(noxtls_xmss_param_from_oid(0U, 0U, &back), NOXTLS_RETURN_NOT_SUPPORTED, "oid 0");
        PQ_CHECK(back == NOXTLS_XMSS_NONE, "oid 0 value");
        PQ_CHECK_RC(noxtls_xmss_param_from_oid(1U, 2U, &back), NOXTLS_RETURN_NOT_SUPPORTED, "is_mt 2");
        PQ_CHECK_RC(noxtls_xmss_param_from_oid(0x10001U, 0U, &back), NOXTLS_RETURN_NOT_SUPPORTED, "oid > 16 bit");
    }
}

/* ---- known answers --------------------------------------------------------- */

static void xmss_t_kats(void)
{
    char label[64];
    uint32_t mark = 0U;
    uint32_t i = 0U;
    uint32_t run = 0U;
    uint32_t skipped = 0U;
    uint8_t d[32];

    for(i = 0U; i < XMSS_T_NELEMS(g_xmss_kats); i += 1U) {
        const xmss_kat_t *v = &g_xmss_kats[i];
        noxtls_xmss_param_info_t info;
        uint32_t sig_len = 0U;
        uint32_t before = g_pq_test_failures;
        uint32_t j = 0U;
        noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

        /* Sets above the light budget run only their test/vectors.c vector (idx 2^(h-1), 1-byte message). */
        if((noxtls_xmss_get_param_info(v->param, &info) != NOXTLS_RETURN_SUCCESS) ||
           (xmss_t_cost(&info) > XMSS_T_MAX_COST) ||
           ((xmss_t_cost(&info) > XMSS_T_LIGHT_COST) && (v->msg_len != 1U))) {
            skipped += 1U;
            continue;
        }
        run += 1U;
        mark = pq_test_probe_begin();
        rc = xmss_t_key(v->param, &info, v->seed_mul, v->seed_add, v->idx);
        if(v->idx == 0U) {
            (void)snprintf(label, sizeof(label), "%s keygen", v->name);
            pq_test_probe_end(mark, label);
        }
        PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "KAT keygen");
        xmss_t_sha256(g_pk, info.public_key_len, d);
        PQ_CHECK_MEM(d, v->pk_sha256, 32U, "KAT public key");
        /* Private key layout: OID | idx | SK_SEED | SK_PRF | root | PUB_SEED. */
        PQ_CHECK_MEM(&g_sk[4U + info.index_len], g_seed, 2U * info.n, "KAT sk seeds");
        PQ_CHECK_MEM(&g_sk[4U + info.index_len + (2U * info.n)], &g_pk[4], 2U * info.n, "KAT sk root/seed");
        xmss_t_msg(v->msg_len);
        mark = pq_test_probe_begin();
        rc = xmss_t_sign_once(v->param, &info, v->msg_len, &sig_len);
        if(v->idx == 0U) {
            (void)snprintf(label, sizeof(label), "%s sign (no traversal)", v->name);
            pq_test_probe_end(mark, label);
        }
        if(v->idx >= noxtls_xmss_max_signatures(v->param)) {
            /* XMSS^MT h = 40: the all-0xff index is the exhausted marker, never a signature. */
            PQ_CHECK_RC(rc, NOXTLS_RETURN_KEY_EXHAUSTED, "KAT index reserved as exhausted marker");
            PQ_CHECK(g_store.calls == 0U, "KAT exhausted marker: no persist");
            continue;
        }
        PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "KAT sign");
        PQ_CHECK(sig_len == info.signature_len, "KAT signature length");
        xmss_t_sha256(g_sig, info.signature_len, d);
        PQ_CHECK_MEM(d, v->sig_sha256, 32U, "KAT signature");
        PQ_CHECK(xmss_t_load_be(g_sig, info.index_len) == v->idx, "KAT signature index");
        PQ_CHECK(g_store.calls == (((v->idx + 1U) == noxtls_xmss_max_signatures(v->param)) ? 2U : 1U),
                 "KAT persist calls");
        PQ_CHECK(g_store.sig_clean_at_call == 1U, "KAT persisted before signature existed");
        PQ_CHECK(g_store.last_idx == (v->idx + 1U), "KAT persisted next index");
        PQ_CHECK(xmss_t_load_be(&g_sk[4], info.index_len) == (v->idx + 1U), "KAT in-RAM index advanced");
        PQ_CHECK_RC(noxtls_xmss_verify(v->param, g_pk, g_msg, v->msg_len, g_sig, info.signature_len),
                    NOXTLS_RETURN_SUCCESS, "KAT verify");
        /* xmss-reference test/vectors.c lines (SHAKE128-80 digests). */
        for(j = 0U; j < XMSS_T_NELEMS(g_xmss_refvec); j += 1U) {
            const xmss_refvec_t *r = &g_xmss_refvec[j];
            uint8_t h10[10];

            if((r->param == v->param) && (v->seed_mul == 1U) && (v->seed_add == 0U) && (v->msg_len == 1U) &&
               (v->idx == (1ULL << (info.height - 1U)))) {
                xmss_t_shake128_10(&g_pk[4], 2U * info.n, h10);
                PQ_CHECK_MEM(h10, r->pk_shake, 10U, "vectors.c public key");
                xmss_t_shake128_10(g_sig, info.signature_len, h10);
                PQ_CHECK_MEM(h10, r->sig_shake, 10U, "vectors.c signature");
            }
        }
        if(g_pq_test_failures != before) {
            printf("    KAT %s idx %llu\n", v->name, (unsigned long long)v->idx);
        }
    }
    printf("  KATs: %lu run, %lu skipped (cost limit %lu leaves or set disabled)\n",
           (unsigned long)run, (unsigned long)skipped, (unsigned long)XMSS_T_MAX_COST);
    PQ_CHECK(run > 0U, "some KATs run");
}

/* ---- complete reference signatures and negative tests ---------------------- */

static void xmss_t_expect_reject(noxtls_xmss_param_t param, const uint8_t *pk, uint32_t msg_len,
                                 const uint8_t *sig, uint32_t sig_len, const char *what)
{
    noxtls_return_t rc = noxtls_xmss_verify(param, pk, g_msg, msg_len, sig, sig_len);

    g_pq_test_checks += 1U;
    if(rc == NOXTLS_RETURN_SUCCESS) {
        pq_test_fail(__FILE__, __LINE__, what);
    }
}

/* An enabled set with the same sizes but another hash function. */
static noxtls_xmss_param_t xmss_t_sibling(noxtls_xmss_param_t param, const noxtls_xmss_param_info_t *info)
{
    uint32_t i = 0U;

    for(i = 0U; i < XMSS_T_NELEMS(g_xmss_params); i += 1U) {
        const xmss_param_row_t *r = &g_xmss_params[i];
        if((r->param != param) && (r->is_mt == info->is_mt) && (r->n == info->n) && (r->h == info->height) &&
           (r->d == info->layers) && (noxtls_xmss_signature_len(r->param) != 0U)) {
            return r->param;
        }
    }
    return NOXTLS_XMSS_NONE;
}

static void xmss_t_full(void)
{
    uint32_t i = 0U;

    for(i = 0U; i < XMSS_T_NELEMS(g_xmss_full); i += 1U) {
        const xmss_fullsig_t *f = &g_xmss_full[i];
        noxtls_xmss_param_info_t info;
        uint32_t pk_len = 0U;
        uint32_t sig_len = 0U;
        uint32_t L = 0U;
        uint32_t off = 0U;
        uint32_t k = 0U;
        uint64_t bad_idx = 0U;
        noxtls_xmss_param_t other = NOXTLS_XMSS_NONE;
        uint32_t mark = 0U;

        if(noxtls_xmss_get_param_info(f->param, &info) != NOXTLS_RETURN_SUCCESS) {
            continue;
        }
        pk_len = xmss_t_unhex(g_pk, (uint32_t)sizeof(g_pk), f->pk);
        sig_len = xmss_t_unhex(g_sig, (uint32_t)sizeof(g_sig), f->sig);
        PQ_CHECK((pk_len == info.public_key_len) && (sig_len == info.signature_len), "full vector sizes");
        xmss_t_msg(33U);
        mark = pq_test_probe_begin();
        PQ_CHECK_RC(noxtls_xmss_verify(f->param, g_pk, g_msg, 33U, g_sig, sig_len), NOXTLS_RETURN_SUCCESS,
                    "reference signature verifies");
        pq_test_probe_end(mark, (info.is_mt != 0U) ? "XMSS^MT verify (20/4)" : "XMSS verify (h=10)");

        /* Message / signature tampering. */
        g_msg[0] ^= 1U;
        PQ_CHECK_RC(noxtls_xmss_verify(f->param, g_pk, g_msg, 33U, g_sig, sig_len), NOXTLS_RETURN_FAILED,
                    "tampered message");
        g_msg[0] ^= 1U;
        PQ_CHECK_RC(noxtls_xmss_verify(f->param, g_pk, g_msg, 32U, g_sig, sig_len), NOXTLS_RETURN_FAILED,
                    "truncated message");
        L = (uint32_t)info.wots_len + info.tree_height;
        /* one byte in: r, first/last WOTS+ chain and first/last auth node of every layer, last byte */
        {
            uint32_t pos[4U + (4U * 12U)];
            uint32_t np = 0U;

            pos[np] = info.index_len;
            np += 1U;
            pos[np] = info.index_len + info.n - 1U;
            np += 1U;
            off = info.index_len + info.n;
            for(k = 0U; k < info.layers; k += 1U) {
                pos[np] = off;
                pos[np + 1U] = off + (((uint32_t)info.wots_len - 1U) * info.n) + 5U;
                pos[np + 2U] = off + ((uint32_t)info.wots_len * info.n);
                pos[np + 3U] = off + ((L - 1U) * info.n) + (info.n - 1U);
                np += 4U;
                off += L * info.n;
            }
            pos[np] = sig_len - 1U;
            np += 1U;
            for(k = 0U; k < np; k += 1U) {
                g_sig[pos[k]] ^= 0x10U;
                xmss_t_expect_reject(f->param, g_pk, 33U, g_sig, sig_len, "tampered signature byte");
                g_sig[pos[k]] ^= 0x10U;
            }
        }
        /* Index: another valid index is a wrong signature; >= 2^h is malformed. */
        g_sig[info.index_len - 1U] ^= 1U;
        PQ_CHECK_RC(noxtls_xmss_verify(f->param, g_pk, g_msg, 33U, g_sig, sig_len), NOXTLS_RETURN_FAILED,
                    "other index");
        g_sig[info.index_len - 1U] ^= 1U;
        (void)memcpy(g_sig2, g_sig, sig_len);
        bad_idx = 1ULL << info.height;
        xmss_t_store_be(g_sig2, info.index_len, bad_idx);
        PQ_CHECK_RC(noxtls_xmss_verify(f->param, g_pk, g_msg, 33U, g_sig2, sig_len), NOXTLS_RETURN_BAD_DATA,
                    "index 2^h rejected");
        xmss_t_store_be(g_sig2, info.index_len, ~0ULL);
        PQ_CHECK_RC(noxtls_xmss_verify(f->param, g_pk, g_msg, 33U, g_sig2, sig_len), NOXTLS_RETURN_BAD_DATA,
                    "index all-ones rejected");
        /* Lengths. */
        PQ_CHECK_RC(noxtls_xmss_verify(f->param, g_pk, g_msg, 33U, g_sig, sig_len - 1U), NOXTLS_RETURN_BAD_DATA,
                    "truncated signature");
        PQ_CHECK_RC(noxtls_xmss_verify(f->param, g_pk, g_msg, 33U, g_sig, sig_len + 1U), NOXTLS_RETURN_BAD_DATA,
                    "overlong signature");
        PQ_CHECK_RC(noxtls_xmss_verify(f->param, g_pk, g_msg, 33U, g_sig, 0U), NOXTLS_RETURN_BAD_DATA,
                    "empty signature");
        /* Public key. */
        g_pk[3] ^= 0x01U;
        PQ_CHECK_RC(noxtls_xmss_verify(f->param, g_pk, g_msg, 33U, g_sig, sig_len), NOXTLS_RETURN_BAD_DATA,
                    "wrong OID in public key");
        g_pk[3] ^= 0x01U;
        g_pk[4] ^= 0x01U;
        PQ_CHECK_RC(noxtls_xmss_verify(f->param, g_pk, g_msg, 33U, g_sig, sig_len), NOXTLS_RETURN_FAILED,
                    "tampered root");
        g_pk[4] ^= 0x01U;
        g_pk[pk_len - 1U] ^= 0x01U;
        PQ_CHECK_RC(noxtls_xmss_verify(f->param, g_pk, g_msg, 33U, g_sig, sig_len), NOXTLS_RETURN_FAILED,
                    "tampered PUB_SEED");
        g_pk[pk_len - 1U] ^= 0x01U;
        /* Same sizes, other hash function: the OID check must catch it. */
        other = xmss_t_sibling(f->param, &info);
        if(other != NOXTLS_XMSS_NONE) {
            PQ_CHECK_RC(noxtls_xmss_verify(other, g_pk, g_msg, 33U, g_sig, sig_len), NOXTLS_RETURN_BAD_DATA,
                        "verified under another parameter set");
        }
        /* XMSS vs XMSS^MT name spaces. */
        PQ_CHECK(noxtls_xmss_verify(f->param ^ NOXTLS_XMSS_PARAM_MT_FLAG, g_pk, g_msg, 33U, g_sig, sig_len) !=
                 NOXTLS_RETURN_SUCCESS, "XMSS / XMSS^MT confusion");
        /* NULL handling. */
        PQ_CHECK_RC(noxtls_xmss_verify(f->param, NULL, g_msg, 33U, g_sig, sig_len), NOXTLS_RETURN_NULL, "NULL pk");
        PQ_CHECK_RC(noxtls_xmss_verify(f->param, g_pk, NULL, 33U, g_sig, sig_len), NOXTLS_RETURN_NULL, "NULL msg");
        PQ_CHECK_RC(noxtls_xmss_verify(f->param, g_pk, g_msg, 33U, NULL, sig_len), NOXTLS_RETURN_NULL, "NULL sig");
        PQ_CHECK_RC(noxtls_xmss_verify(f->param, g_pk, g_msg, 33U, g_sig, sig_len), NOXTLS_RETURN_SUCCESS,
                    "still verifies after negative tests");
    }
}

/* ---- streaming verification -------------------------------------------- */

static void xmss_t_streaming(void)
{
    const xmss_fullsig_t *f = &g_xmss_full[0];
    noxtls_xmss_verify_ctx_t ctx;
    noxtls_xmss_param_info_t info;
    uint32_t pk_len = 0U;
    uint32_t sig_len = 0U;
    uint32_t i = 0U;

    if(noxtls_xmss_get_param_info(f->param, &info) != NOXTLS_RETURN_SUCCESS) {
        return;
    }
    pk_len = xmss_t_unhex(g_pk, (uint32_t)sizeof(g_pk), f->pk);
    sig_len = xmss_t_unhex(g_sig, (uint32_t)sizeof(g_sig), f->sig);
    xmss_t_msg(33U);

    /* Byte-by-byte message. */
    PQ_CHECK_RC(noxtls_xmss_verify_init(&ctx, f->param, g_pk, pk_len, g_sig, sig_len), NOXTLS_RETURN_SUCCESS,
                "stream init");
    for(i = 0U; i < 33U; i += 1U) {
        PQ_CHECK_RC(noxtls_xmss_verify_update(&ctx, &g_msg[i], 1U), NOXTLS_RETURN_SUCCESS, "stream update");
    }
    PQ_CHECK_RC(noxtls_xmss_verify_update(&ctx, NULL, 0U), NOXTLS_RETURN_SUCCESS, "stream empty update");
    PQ_CHECK_RC(noxtls_xmss_verify_final(&ctx, g_sig, sig_len), NOXTLS_RETURN_SUCCESS, "stream final");
    PQ_CHECK_RC(noxtls_xmss_verify_update(&ctx, g_msg, 1U), NOXTLS_RETURN_NOT_INITIALIZED, "update after final");
    PQ_CHECK_RC(noxtls_xmss_verify_final(&ctx, g_sig, sig_len), NOXTLS_RETURN_NOT_INITIALIZED, "final twice");

    /* Uneven chunks. */
    PQ_CHECK_RC(noxtls_xmss_verify_init(&ctx, f->param, g_pk, pk_len, g_sig, sig_len), NOXTLS_RETURN_SUCCESS,
                "stream init 2");
    PQ_CHECK_RC(noxtls_xmss_verify_update(&ctx, g_msg, 7U), NOXTLS_RETURN_SUCCESS, "chunk 1");
    PQ_CHECK_RC(noxtls_xmss_verify_update(&ctx, &g_msg[7], 26U), NOXTLS_RETURN_SUCCESS, "chunk 2");
    PQ_CHECK_RC(noxtls_xmss_verify_final(&ctx, g_sig, sig_len), NOXTLS_RETURN_SUCCESS, "stream final 2");

    /* final() must get the signature whose header init() parsed. */
    (void)memcpy(g_sig2, g_sig, sig_len);
    g_sig2[info.index_len] ^= 1U;
    PQ_CHECK_RC(noxtls_xmss_verify_init(&ctx, f->param, g_pk, pk_len, g_sig, sig_len), NOXTLS_RETURN_SUCCESS,
                "stream init 3");
    PQ_CHECK_RC(noxtls_xmss_verify_update(&ctx, g_msg, 33U), NOXTLS_RETURN_SUCCESS, "stream update 3");
    PQ_CHECK_RC(noxtls_xmss_verify_final(&ctx, g_sig2, sig_len), NOXTLS_RETURN_BAD_DATA, "final with other r");
    PQ_CHECK_RC(noxtls_xmss_verify_init(&ctx, f->param, g_pk, pk_len, g_sig, sig_len), NOXTLS_RETURN_SUCCESS,
                "stream init 4");
    PQ_CHECK_RC(noxtls_xmss_verify_final(&ctx, g_sig, sig_len - 1U), NOXTLS_RETURN_BAD_DATA, "final short sig");

    /* Wrong message in the stream. */
    PQ_CHECK_RC(noxtls_xmss_verify_init(&ctx, f->param, g_pk, pk_len, g_sig, sig_len), NOXTLS_RETURN_SUCCESS,
                "stream init 5");
    PQ_CHECK_RC(noxtls_xmss_verify_update(&ctx, g_msg, 32U), NOXTLS_RETURN_SUCCESS, "stream update 5");
    PQ_CHECK_RC(noxtls_xmss_verify_final(&ctx, g_sig, sig_len), NOXTLS_RETURN_FAILED, "stream short message");

    /* Init errors leave the context unusable. */
    PQ_CHECK_RC(noxtls_xmss_verify_init(&ctx, f->param, g_pk, pk_len - 1U, g_sig, sig_len),
                NOXTLS_RETURN_INVALID_KEY_SIZE, "init short pk");
    PQ_CHECK_RC(noxtls_xmss_verify_update(&ctx, g_msg, 1U), NOXTLS_RETURN_NOT_INITIALIZED, "update after failed init");
    PQ_CHECK_RC(noxtls_xmss_verify_init(NULL, f->param, g_pk, pk_len, g_sig, sig_len), NOXTLS_RETURN_NULL, "init NULL");
    PQ_CHECK_RC(noxtls_xmss_verify_init(&ctx, NOXTLS_XMSS_NONE, g_pk, pk_len, g_sig, sig_len),
                NOXTLS_RETURN_NOT_SUPPORTED, "init NONE");
    PQ_CHECK_RC(noxtls_xmss_verify_update(NULL, g_msg, 1U), NOXTLS_RETURN_NULL, "update NULL");
    PQ_CHECK_RC(noxtls_xmss_verify_final(NULL, g_sig, sig_len), NOXTLS_RETURN_NULL, "final NULL");
    PQ_CHECK_RC(noxtls_xmss_verify_init(&ctx, f->param, g_pk, pk_len, g_sig, sig_len), NOXTLS_RETURN_SUCCESS,
                "stream init 6");
    PQ_CHECK_RC(noxtls_xmss_verify_update(&ctx, NULL, 1U), NOXTLS_RETURN_NULL, "update NULL data");
}

/* ---- round trips, stateful signing and traversal ---------------------- */

#if NOXTLS_XMSS_ENABLE_SIGN

/* Pick the cheapest enabled XMSS and XMSS^MT sets for the state tests. */
static noxtls_xmss_param_t xmss_t_pick(uint8_t mt)
{
    static const noxtls_xmss_param_t xmss[] = {
        NOXTLS_XMSS_SHA2_10_256, NOXTLS_XMSS_SHAKE256_10_256, NOXTLS_XMSS_SHA2_10_192, NOXTLS_XMSS_SHAKE256_10_192,
    };
    static const noxtls_xmss_param_t mtp[] = {
        NOXTLS_XMSSMT_SHA2_20_4_256, NOXTLS_XMSSMT_SHAKE256_20_4_256, NOXTLS_XMSSMT_SHA2_20_4_192,
        NOXTLS_XMSSMT_SHAKE256_20_4_192,
    };
    uint32_t i = 0U;

    for(i = 0U; i < 4U; i += 1U) {
        noxtls_xmss_param_t p = (mt != 0U) ? mtp[i] : xmss[i];
        if(noxtls_xmss_signature_len(p) != 0U) {
            return p;
        }
    }
    return NOXTLS_XMSS_NONE;
}

/* keygen (DRBG) + sign + verify for every enabled set within the cost budget. */
static void xmss_t_roundtrips(void)
{
    uint32_t i = 0U;

    for(i = 0U; i < XMSS_T_NELEMS(g_xmss_params); i += 1U) {
        const xmss_param_row_t *r = &g_xmss_params[i];
        noxtls_xmss_param_info_t info;
        uint32_t sig_len = 0U;
        noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

        /* Sets above the light budget (already covered by their KAT) only for XMSS-SHA2_10_256. */
        if((noxtls_xmss_get_param_info(r->param, &info) != NOXTLS_RETURN_SUCCESS) ||
           (xmss_t_cost(&info) > XMSS_T_MAX_COST) ||
           ((xmss_t_cost(&info) > XMSS_T_LIGHT_COST) && (r->param != NOXTLS_XMSS_SHA2_10_256))) {
            continue;
        }
        pq_test_rng_seed_label("xmss-roundtrip", i);
        {
            XMSS_T_TIMER_START(t0);
            rc = noxtls_xmss_keygen(r->param, g_pk, info.public_key_len, g_sk, info.secret_key_len);
            PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "round trip keygen");
            xmss_t_msg(100U);
            {
                XMSS_T_TIMER_START(t1);
                rc = xmss_t_sign_once(r->param, &info, 100U, &sig_len);
                PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "round trip sign");
                {
                    XMSS_T_TIMER_START(t2);
                    PQ_CHECK_RC(noxtls_xmss_verify(r->param, g_pk, g_msg, 100U, g_sig, sig_len),
                                NOXTLS_RETURN_SUCCESS, "round trip verify");
                    if(info.tree_height >= 10U) {
                        printf("  [time] %-26s keygen %.2fs sign(no BDS) %.2fs verify %.4fs\n", r->name,
                               XMSS_T_ELAPSED(t0) - XMSS_T_ELAPSED(t1), XMSS_T_ELAPSED(t1) - XMSS_T_ELAPSED(t2),
                               XMSS_T_ELAPSED(t2));
                    }
                }
            }
        }
        g_msg[99] ^= 0x80U;
        PQ_CHECK_RC(noxtls_xmss_verify(r->param, g_pk, g_msg, 100U, g_sig, sig_len), NOXTLS_RETURN_FAILED,
                    "round trip tampered message");
        /* Two DRBG key generations differ (light sets only). */
        if(xmss_t_cost(&info) <= XMSS_T_LIGHT_COST) {
            rc = noxtls_xmss_keygen(r->param, g_pk2, info.public_key_len, g_sk2, info.secret_key_len);
            PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "second keygen");
            PQ_CHECK(memcmp(g_pk, g_pk2, info.public_key_len) != 0, "independent keys");
        }
        pq_test_rng_restore();
    }
}

static void xmss_t_keygen_args(void)
{
    noxtls_xmss_param_t p = xmss_t_pick(1U);
    noxtls_xmss_param_info_t info;
    uint64_t rem = 0U;

    if(p == NOXTLS_XMSS_NONE) {
        return;
    }
    (void)noxtls_xmss_get_param_info(p, &info);
    xmss_t_gen(g_seed, 3U * info.n, 1U, 0U);
    PQ_CHECK_RC(noxtls_xmss_keygen_from_seed(p, NULL, 3U * info.n, g_pk, (uint32_t)sizeof(g_pk), g_sk, (uint32_t)sizeof(g_sk)),
                NOXTLS_RETURN_NULL, "keygen NULL seed");
    PQ_CHECK_RC(noxtls_xmss_keygen_from_seed(p, g_seed, 3U * info.n - 1U, g_pk, (uint32_t)sizeof(g_pk), g_sk, (uint32_t)sizeof(g_sk)),
                NOXTLS_RETURN_INVALID_PARAM, "keygen short seed");
    PQ_CHECK_RC(noxtls_xmss_keygen_from_seed(p, g_seed, 3U * info.n, g_pk, info.public_key_len - 1U, g_sk, (uint32_t)sizeof(g_sk)),
                NOXTLS_RETURN_INVALID_KEY_SIZE, "keygen small pk buffer");
    PQ_CHECK_RC(noxtls_xmss_keygen_from_seed(p, g_seed, 3U * info.n, g_pk, (uint32_t)sizeof(g_pk), g_sk, info.secret_key_len - 1U),
                NOXTLS_RETURN_INVALID_KEY_SIZE, "keygen small sk buffer");
    PQ_CHECK_RC(noxtls_xmss_keygen_from_seed(NOXTLS_XMSS_NONE, g_seed, 3U * info.n, g_pk, (uint32_t)sizeof(g_pk), g_sk, (uint32_t)sizeof(g_sk)),
                NOXTLS_RETURN_NOT_SUPPORTED, "keygen NONE");
    PQ_CHECK_RC(noxtls_xmss_keygen(p, NULL, 0U, NULL, 0U), NOXTLS_RETURN_NULL, "keygen NULL");
    PQ_CHECK_RC(noxtls_xmss_keygen_from_seed(p, g_seed, 3U * info.n, g_pk, (uint32_t)sizeof(g_pk), g_sk, (uint32_t)sizeof(g_sk)),
                NOXTLS_RETURN_SUCCESS, "keygen ok");
    PQ_CHECK_RC(noxtls_xmss_public_key_from_secret(p, g_sk, info.secret_key_len, g_pk2, (uint32_t)sizeof(g_pk2)),
                NOXTLS_RETURN_SUCCESS, "pk from sk");
    PQ_CHECK_MEM(g_pk2, g_pk, info.public_key_len, "pk from sk value");
    PQ_CHECK_RC(noxtls_xmss_public_key_from_secret(p, g_sk, info.secret_key_len - 1U, g_pk2, (uint32_t)sizeof(g_pk2)),
                NOXTLS_RETURN_INVALID_KEY_SIZE, "pk from short sk");
    PQ_CHECK_RC(noxtls_xmss_secret_key_remaining(p, g_sk, info.secret_key_len, &rem), NOXTLS_RETURN_SUCCESS,
                "remaining");
    PQ_CHECK(rem == noxtls_xmss_max_signatures(p), "fresh key remaining 2^h");
    g_sk[3] ^= 1U;
    PQ_CHECK_RC(noxtls_xmss_secret_key_remaining(p, g_sk, info.secret_key_len, &rem), NOXTLS_RETURN_BAD_DATA,
                "remaining wrong OID");
    g_sk[3] ^= 1U;
    xmss_t_store_be(&g_sk[4], info.index_len, (1ULL << info.height) + 1U);
    PQ_CHECK_RC(noxtls_xmss_secret_key_remaining(p, g_sk, info.secret_key_len, &rem), NOXTLS_RETURN_BAD_DATA,
                "remaining index > 2^h");
    PQ_CHECK_RC(noxtls_xmss_sign(p, g_sk, g_msg, 1U, g_sig, NULL), NOXTLS_RETURN_NOT_SUPPORTED,
                "legacy const-key sign refused");
}

static void xmss_t_signer_args(void)
{
    noxtls_xmss_param_t p = xmss_t_pick(1U);
    noxtls_xmss_param_info_t info;
    noxtls_xmss_signer_t signer;
    uint32_t sig_len = 0U;
    uint64_t rem = 0U;

    if(p == NOXTLS_XMSS_NONE) {
        return;
    }
    (void)noxtls_xmss_get_param_info(p, &info);
    PQ_CHECK_RC(xmss_t_key(p, &info, 1U, 0U, 0U), NOXTLS_RETURN_SUCCESS, "signer key");
    xmss_t_store_reset(&info);
    PQ_CHECK_RC(noxtls_xmss_signer_init(NULL, p, g_sk, info.secret_key_len, xmss_t_persist, &g_store, 1U),
                NOXTLS_RETURN_NULL, "init NULL signer");
    PQ_CHECK_RC(noxtls_xmss_signer_init(&signer, p, g_sk, info.secret_key_len, NULL, &g_store, 1U),
                NOXTLS_RETURN_NULL, "persist callback mandatory");
    PQ_CHECK_RC(noxtls_xmss_signer_init(&signer, p, g_sk, info.secret_key_len, xmss_t_persist, &g_store, 0U),
                NOXTLS_RETURN_INVALID_PARAM, "reserve 0");
    PQ_CHECK_RC(noxtls_xmss_signer_init(&signer, p, g_sk, info.secret_key_len + 1U, xmss_t_persist, &g_store, 1U),
                NOXTLS_RETURN_INVALID_KEY_SIZE, "sk length");
    PQ_CHECK(noxtls_xmss_signer_init(&signer, p ^ NOXTLS_XMSS_PARAM_MT_FLAG, g_sk, info.secret_key_len,
                                     xmss_t_persist, &g_store, 1U) != NOXTLS_RETURN_SUCCESS,
             "sk for the other name space");
    g_sk[3] ^= 1U;
    PQ_CHECK_RC(noxtls_xmss_signer_init(&signer, p, g_sk, info.secret_key_len, xmss_t_persist, &g_store, 1U),
                NOXTLS_RETURN_BAD_DATA, "sk with wrong OID");
    g_sk[3] ^= 1U;
    xmss_t_store_be(&g_sk[4], info.index_len, (1ULL << info.height) + 1U);
    PQ_CHECK_RC(noxtls_xmss_signer_init(&signer, p, g_sk, info.secret_key_len, xmss_t_persist, &g_store, 1U),
                NOXTLS_RETURN_BAD_DATA, "sk index beyond 2^h");
    xmss_t_store_be(&g_sk[4], info.index_len, 0U);
    sig_len = (uint32_t)sizeof(g_sig);
    PQ_CHECK_RC(noxtls_xmss_sign_stateful(&signer, g_msg, 1U, g_sig, &sig_len), NOXTLS_RETURN_NOT_INITIALIZED,
                "sign with failed init");
    PQ_CHECK_RC(noxtls_xmss_signer_init(&signer, p, g_sk, info.secret_key_len, xmss_t_persist, &g_store, 1U),
                NOXTLS_RETURN_SUCCESS, "init");
    sig_len = info.signature_len - 1U;
    PQ_CHECK_RC(noxtls_xmss_sign_stateful(&signer, g_msg, 1U, g_sig, &sig_len), NOXTLS_RETURN_INVALID_BLOCK_SIZE,
                "small signature buffer");
    PQ_CHECK(g_store.calls == 0U, "no persist for an argument error");
    sig_len = (uint32_t)sizeof(g_sig);
    PQ_CHECK_RC(noxtls_xmss_sign_stateful(&signer, NULL, 1U, g_sig, &sig_len), NOXTLS_RETURN_NULL, "NULL msg");
    PQ_CHECK_RC(noxtls_xmss_sign_stateful(&signer, g_msg, 1U, NULL, &sig_len), NOXTLS_RETURN_NULL, "NULL sig");
    PQ_CHECK_RC(noxtls_xmss_signer_remaining(&signer, &rem), NOXTLS_RETURN_SUCCESS, "remaining");
    PQ_CHECK(rem == noxtls_xmss_max_signatures(p), "remaining before first signature");
    PQ_CHECK(noxtls_xmss_traversal_state_len(p, 2U) == 0U, "k parity (h/d = 5)");
    PQ_CHECK(noxtls_xmss_traversal_state_len(p, 7U) == 0U, "k > h/d");
    PQ_CHECK(noxtls_xmss_traversal_state_len(p, 3U) != 0U, "k = 3");
    PQ_CHECK_RC(noxtls_xmss_signer_attach_traversal(&signer, g_bds, (uint32_t)sizeof(g_bds), 2U), NOXTLS_RETURN_INVALID_PARAM,
                "attach invalid k");
    PQ_CHECK_RC(noxtls_xmss_signer_attach_traversal(&signer, g_bds, noxtls_xmss_traversal_state_len(p, 1U) - 1U, 1U),
                NOXTLS_RETURN_INVALID_BLOCK_SIZE, "attach small buffer");
    PQ_CHECK_RC(noxtls_xmss_signer_attach_traversal(&signer, NULL, (uint32_t)sizeof(g_bds), 1U), NOXTLS_RETURN_NULL,
                "attach NULL");
    noxtls_xmss_signer_free(&signer);
    PQ_CHECK_RC(noxtls_xmss_signer_remaining(&signer, &rem), NOXTLS_RETURN_NOT_INITIALIZED, "remaining after free");
    noxtls_xmss_signer_free(NULL);
}

/* Persist-before-release, fail-closed persistence and reserve-N. */
static void xmss_t_state(void)
{
    noxtls_xmss_param_t p = xmss_t_pick(1U);
    noxtls_xmss_param_info_t info;
    noxtls_xmss_signer_t signer;
    uint32_t sig_len = 0U;
    uint32_t i = 0U;
    uint64_t rem = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if(p == NOXTLS_XMSS_NONE) {
        return;
    }
    (void)noxtls_xmss_get_param_info(p, &info);
    PQ_CHECK_RC(xmss_t_key(p, &info, 5U, 9U, 0U), NOXTLS_RETURN_SUCCESS, "state key");
    xmss_t_store_reset(&info);
    g_store.watch_len = info.signature_len;
    PQ_CHECK_RC(noxtls_xmss_signer_init(&signer, p, g_sk, info.secret_key_len, xmss_t_persist, &g_store, 1U),
                NOXTLS_RETURN_SUCCESS, "state init");
    xmss_t_msg(16U);

    /* Persistence failure: nothing is released and the index is not consumed. */
    g_store.fail_next = 1U;
    (void)memset(g_sig, 0xA5, info.signature_len);
    sig_len = (uint32_t)sizeof(g_sig);
    rc = noxtls_xmss_sign_stateful(&signer, g_msg, 16U, g_sig, &sig_len);
    PQ_CHECK_RC(rc, NOXTLS_RETURN_FAILED, "persist failure fails closed (callback error returned)");
    PQ_CHECK(sig_len == 0U, "no signature length on persist failure");
    PQ_CHECK(xmss_t_all_zero(g_sig, info.signature_len) != 0, "no signature bytes on persist failure");
    PQ_CHECK(xmss_t_load_be(&g_sk[4], info.index_len) == 0U, "index unchanged on persist failure");
    PQ_CHECK(g_store.calls == 1U, "persist attempted once");

    /* Retry succeeds with index 0; then 1, 2, ... each persisted first. */
    for(i = 0U; i < 4U; i += 1U) {
        uint32_t calls = g_store.calls;

        sig_len = (uint32_t)sizeof(g_sig);
        rc = noxtls_xmss_sign_stateful(&signer, g_msg, 16U, g_sig, &sig_len);
        PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "state sign");
        PQ_CHECK(xmss_t_load_be(g_sig, info.index_len) == i, "sequential index");
        PQ_CHECK(g_store.calls == (calls + 1U), "one persist per signature (reserve 1)");
        PQ_CHECK(g_store.last_idx == ((uint64_t)i + 1U), "persisted index = used + 1");
        PQ_CHECK(g_store.sig_clean_at_call == 1U, "persist happened before the signature existed");
        PQ_CHECK_RC(noxtls_xmss_verify(p, g_pk, g_msg, 16U, g_sig, sig_len), NOXTLS_RETURN_SUCCESS, "state verify");
        (void)memset(g_sig, 0, sizeof(g_sig));
    }
    PQ_CHECK_RC(noxtls_xmss_signer_remaining(&signer, &rem), NOXTLS_RETURN_SUCCESS, "remaining");
    PQ_CHECK(rem == (noxtls_xmss_max_signatures(p) - 4U), "remaining after 4 signatures");
    /* The stored image restarts at the next unused index. */
    PQ_CHECK(memcmp(&g_store.image[4U + info.index_len], &g_sk[4U + info.index_len],
                    info.secret_key_len - 4U - info.index_len) == 0, "stored image = key material");
    noxtls_xmss_signer_free(&signer);

    /* Reserve 8: one persist per 8 signatures, stored index runs ahead. */
    xmss_t_store_reset(&info);
    g_store.watch_len = info.signature_len;
    PQ_CHECK_RC(noxtls_xmss_signer_init(&signer, p, g_sk, info.secret_key_len, xmss_t_persist, &g_store, 8U),
                NOXTLS_RETURN_SUCCESS, "reserve init");
    for(i = 0U; i < 10U; i += 1U) {
        sig_len = (uint32_t)sizeof(g_sig);
        rc = noxtls_xmss_sign_stateful(&signer, g_msg, 16U, g_sig, &sig_len);
        PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "reserve sign");
        PQ_CHECK(xmss_t_load_be(g_sig, info.index_len) == (4U + i), "reserve index");
        (void)memset(g_sig, 0, sizeof(g_sig));
    }
    PQ_CHECK(g_store.calls == 2U, "two persist calls for 10 signatures with reserve 8");
    PQ_CHECK(g_store.last_idx == 20U, "stored index = end of the second reservation");
    PQ_CHECK(xmss_t_load_be(&g_sk[4], info.index_len) == 14U, "in-RAM index exact");
    noxtls_xmss_signer_free(&signer);

    /* "Crash": restart from the stored image skips the reserved indices, never reuses them. */
    (void)memcpy(g_sk2, g_store.image, info.secret_key_len);
    xmss_t_store_reset(&info);
    g_store.watch_len = info.signature_len;
    PQ_CHECK_RC(noxtls_xmss_signer_init(&signer, p, g_sk2, info.secret_key_len, xmss_t_persist, &g_store, 1U),
                NOXTLS_RETURN_SUCCESS, "restart init");
    sig_len = (uint32_t)sizeof(g_sig);
    PQ_CHECK_RC(noxtls_xmss_sign_stateful(&signer, g_msg, 16U, g_sig, &sig_len), NOXTLS_RETURN_SUCCESS,
                "restart sign");
    PQ_CHECK(xmss_t_load_be(g_sig, info.index_len) == 20U, "restart uses the first unreserved index");
    PQ_CHECK_RC(noxtls_xmss_verify(p, g_pk, g_msg, 16U, g_sig, sig_len), NOXTLS_RETURN_SUCCESS, "restart verify");
    noxtls_xmss_signer_free(&signer);
}

/* Exhaustion at the end of the key (XMSS and XMSS^MT). */
static void xmss_t_exhaustion(noxtls_xmss_param_t p)
{
    noxtls_xmss_param_info_t info;
    noxtls_xmss_signer_t signer;
    uint32_t sig_len = 0U;
    uint64_t max = 0U;
    uint64_t rem = 0U;
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if((p == NOXTLS_XMSS_NONE) || (noxtls_xmss_get_param_info(p, &info) != NOXTLS_RETURN_SUCCESS)) {
        return;
    }
    if(xmss_t_cost(&info) > XMSS_T_MAX_COST) {
        return;
    }
    max = noxtls_xmss_max_signatures(p);
    PQ_CHECK_RC(xmss_t_key(p, &info, 11U, 3U, max - 2U), NOXTLS_RETURN_SUCCESS, "exhaustion key");
    xmss_t_store_reset(&info);
    g_store.watch_len = info.signature_len;
    PQ_CHECK_RC(noxtls_xmss_signer_init(&signer, p, g_sk, info.secret_key_len, xmss_t_persist, &g_store, 100U),
                NOXTLS_RETURN_SUCCESS, "exhaustion init");
    xmss_t_msg(3U);
    for(i = 0U; i < 2U; i += 1U) {
        sig_len = (uint32_t)sizeof(g_sig);
        rc = noxtls_xmss_sign_stateful(&signer, g_msg, 3U, g_sig, &sig_len);
        PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "sign last indices");
        PQ_CHECK(xmss_t_load_be(g_sig, info.index_len) == (max - 2U + i), "last indices");
        PQ_CHECK_RC(noxtls_xmss_verify(p, g_pk, g_msg, 3U, g_sig, sig_len), NOXTLS_RETURN_SUCCESS,
                    "last-index signature verifies");
    }
    PQ_CHECK(g_store.last_idx == max, "reservation capped at the end marker");
    PQ_CHECK(xmss_t_load_be(&g_sk[4], info.index_len) == max, "in-RAM index = end marker");
    PQ_CHECK(g_store.calls == 2U, "exhausted key persisted again");
    PQ_CHECK(xmss_t_all_zero(&g_store.image[4U + info.index_len], 2U * info.n) != 0, "stored seeds wiped");
    PQ_CHECK(xmss_t_all_zero(&g_sk[4U + info.index_len], 2U * info.n) != 0, "in-RAM seeds wiped");
    PQ_CHECK_RC(noxtls_xmss_signer_remaining(&signer, &rem), NOXTLS_RETURN_SUCCESS, "remaining exhausted");
    PQ_CHECK(rem == 0U, "remaining 0");
    sig_len = (uint32_t)sizeof(g_sig);
    PQ_CHECK_RC(noxtls_xmss_sign_stateful(&signer, g_msg, 3U, g_sig, &sig_len), NOXTLS_RETURN_KEY_EXHAUSTED,
                "exhausted");
    PQ_CHECK(sig_len == 0U, "exhausted: no signature");
    PQ_CHECK(g_store.calls == 2U, "exhausted: no persist");
    PQ_CHECK_RC(noxtls_xmss_signer_attach_traversal(&signer, g_bds, (uint32_t)sizeof(g_bds), (info.tree_height & 1U)),
                NOXTLS_RETURN_KEY_EXHAUSTED, "attach to exhausted key");
    noxtls_xmss_signer_free(&signer);
    /* A restarted exhausted key stays exhausted. */
    PQ_CHECK_RC(noxtls_xmss_signer_init(&signer, p, g_store.image, info.secret_key_len, xmss_t_persist, &g_store, 1U),
                NOXTLS_RETURN_SUCCESS, "init exhausted image");
    sig_len = (uint32_t)sizeof(g_sig);
    PQ_CHECK_RC(noxtls_xmss_sign_stateful(&signer, g_msg, 3U, g_sig, &sig_len), NOXTLS_RETURN_KEY_EXHAUSTED,
                "exhausted image");
    noxtls_xmss_signer_free(&signer);
}

/*
 * BDS traversal: signatures are deterministic, so traversal signatures must be
 * byte-identical to stateless ones; every one is also verified.  Covers
 * attach at index 0 and mid-key, each valid k, and (XMSS^MT) layer-0 and
 * layer-1 tree rollovers.
 */
static void xmss_t_bds_run(noxtls_xmss_param_t p, uint32_t k, uint64_t start, uint32_t count, uint32_t compare_every)
{
    noxtls_xmss_param_info_t info;
    noxtls_xmss_signer_t signer;
    uint32_t sig_len = 0U;
    uint32_t i = 0U;
    uint32_t mark = 0U;
    uint32_t before = g_pq_test_failures;
    uint32_t state_len = noxtls_xmss_traversal_state_len(p, k);
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    (void)noxtls_xmss_get_param_info(p, &info);
    PQ_CHECK((state_len != 0U) && (state_len <= (uint32_t)sizeof(g_bds)), "traversal state fits");
    if((state_len == 0U) || (state_len > (uint32_t)sizeof(g_bds))) {
        return;
    }
    PQ_CHECK_RC(xmss_t_key(p, &info, 7U, 1U, start), NOXTLS_RETURN_SUCCESS, "bds key");
    xmss_t_store_reset(&info);
    PQ_CHECK_RC(noxtls_xmss_signer_init(&signer, p, g_sk, info.secret_key_len, xmss_t_persist, &g_store, 64U),
                NOXTLS_RETURN_SUCCESS, "bds signer");
    mark = pq_test_probe_begin();
    rc = noxtls_xmss_signer_attach_traversal(&signer, g_bds, (uint32_t)sizeof(g_bds), k);
    pq_test_probe_end(mark, "XMSS traversal attach");
    PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "bds attach");
    for(i = 0U; (i < count) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        uint64_t idx = start + i;

        xmss_t_gen(g_msg, 20U, 3U, (uint32_t)idx);
        sig_len = (uint32_t)sizeof(g_sig);
        mark = pq_test_probe_begin();
        rc = noxtls_xmss_sign_stateful(&signer, g_msg, 20U, g_sig, &sig_len);
        if(i == 1U) {
            pq_test_probe_end(mark, "XMSS sign with traversal");
        }
        PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "bds sign");
        PQ_CHECK(xmss_t_load_be(g_sig, info.index_len) == idx, "bds index");
        PQ_CHECK_RC(noxtls_xmss_verify(p, g_pk, g_msg, 20U, g_sig, sig_len), NOXTLS_RETURN_SUCCESS, "bds verify");
        if((compare_every != 0U) && ((i % compare_every) == 0U)) {
            /* Stateless signature of the same index from a copy of the key. */
            uint32_t sl = 0U;
            (void)memcpy(g_sk2, g_sk, info.secret_key_len);
            (void)memcpy(g_sig2, g_sig, sig_len);
            xmss_t_store_be(&g_sk[4], info.index_len, idx);
            rc = xmss_t_sign_once(p, &info, 20U, &sl);
            PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "stateless reference signature");
            PQ_CHECK_MEM(g_sig, g_sig2, sig_len, "traversal signature == stateless signature");
            (void)memcpy(g_sk, g_sk2, info.secret_key_len);
        }
        if(g_pq_test_failures != before) {
            printf("    BDS failure at idx %llu (k=%lu)\n", (unsigned long long)idx, (unsigned long)k);
            break;
        }
    }
    noxtls_xmss_signer_free(&signer);
    PQ_CHECK(xmss_t_all_zero(g_bds, state_len) != 0, "traversal wiped on free");
}

static void xmss_t_bds(void)
{
    noxtls_xmss_param_t px = xmss_t_pick(0U);
    noxtls_xmss_param_t pm = xmss_t_pick(1U);

    if(pm != NOXTLS_XMSS_NONE) {
        /* XMSS^MT h/d = 5: layer-0 rollovers every 32 signatures. */
        xmss_t_bds_run(pm, 1U, 0U, 70U, 23U);
        xmss_t_bds_run(pm, 3U, 25U, 45U, 0U);
        xmss_t_bds_run(pm, 5U, 61U, 10U, 0U);
#if !defined(NOXTLS_PQ_TEST_QUICK)
        /* layer-1 rollover at 1024 and a mid-key attach in the middle of a layer-2 tree */
        xmss_t_bds_run(pm, 1U, 1000U, 60U, 0U);
        xmss_t_bds_run(pm, 3U, (1ULL << 15) - 3U, 6U, 0U);
#endif
    }
#if !defined(NOXTLS_PQ_TEST_QUICK)
    if(px != NOXTLS_XMSS_NONE) {
        xmss_t_bds_run(px, 2U, 0U, 40U, 13U);
        xmss_t_bds_run(px, 4U, 500U, 80U, 0U);
        xmss_t_bds_run(px, 0U, 1000U, 23U, 0U);
        xmss_t_bds_run(px, 8U, 7U, 9U, 0U);
#if defined(XMSS_T_SLOW) && (XMSS_T_SLOW != 0)
        /* the whole key with k = 2 */
        xmss_t_bds_run(px, 2U, 0U, 1024U, 0U);
#endif
    }
#else
    (void)px;
#endif
}

/* A corrupted traversal never releases a bad signature; it is rebuilt. */
static void xmss_t_bds_corrupt(void)
{
    noxtls_xmss_param_t p = xmss_t_pick(1U);
    noxtls_xmss_param_info_t info;
    noxtls_xmss_signer_t signer;
    uint32_t sig_len = 0U;
    uint32_t state_len = 0U;
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if(p == NOXTLS_XMSS_NONE) {
        return;
    }
    (void)noxtls_xmss_get_param_info(p, &info);
    state_len = noxtls_xmss_traversal_state_len(p, 1U);
    PQ_CHECK_RC(xmss_t_key(p, &info, 9U, 9U, 3U), NOXTLS_RETURN_SUCCESS, "corrupt key");
    xmss_t_store_reset(&info);
    PQ_CHECK_RC(noxtls_xmss_signer_init(&signer, p, g_sk, info.secret_key_len, xmss_t_persist, &g_store, 1U),
                NOXTLS_RETURN_SUCCESS, "corrupt signer");
    PQ_CHECK_RC(noxtls_xmss_signer_attach_traversal(&signer, g_bds, state_len, 1U), NOXTLS_RETURN_SUCCESS,
                "corrupt attach");
    xmss_t_msg(8U);
#if NOXTLS_XMSS_SIGN_SELF_CHECK
    /* Flip bytes all over the node area: each signature either verifies or is withheld
     * (without the self check a corrupted traversal would release invalid signatures). */
    for(i = 0U; i < 12U; i += 1U) {
        uint32_t pos = 40U + ((i * 977U) % (state_len - 40U));

        g_bds[pos] ^= 0x5AU;
        sig_len = (uint32_t)sizeof(g_sig);
        rc = noxtls_xmss_sign_stateful(&signer, g_msg, 8U, g_sig, &sig_len);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            PQ_CHECK_RC(noxtls_xmss_verify(p, g_pk, g_msg, 8U, g_sig, sig_len), NOXTLS_RETURN_SUCCESS,
                        "released signature verifies despite corruption");
        } else {
            PQ_CHECK(sig_len == 0U, "withheld signature has no length");
            PQ_CHECK(xmss_t_all_zero(g_sig, info.signature_len) != 0, "withheld signature wiped");
        }
    }
    /* After a failure the traversal is rebuilt: the next signature is good. */
    sig_len = (uint32_t)sizeof(g_sig);
    PQ_CHECK_RC(noxtls_xmss_sign_stateful(&signer, g_msg, 8U, g_sig, &sig_len), NOXTLS_RETURN_SUCCESS,
                "sign after corruption");
    PQ_CHECK_RC(noxtls_xmss_verify(p, g_pk, g_msg, 8U, g_sig, sig_len), NOXTLS_RETURN_SUCCESS,
                "verify after corruption");
#else
    (void)i;
    (void)rc;
#endif
    noxtls_xmss_signer_free(&signer);

    /* A key whose stored root does not match its seeds is refused. */
    PQ_CHECK_RC(xmss_t_key(p, &info, 9U, 9U, 3U), NOXTLS_RETURN_SUCCESS, "bad-root key");
    g_sk[4U + info.index_len + (2U * info.n)] ^= 1U;
    PQ_CHECK_RC(noxtls_xmss_signer_init(&signer, p, g_sk, info.secret_key_len, xmss_t_persist, &g_store, 1U),
                NOXTLS_RETURN_SUCCESS, "bad-root signer");
    PQ_CHECK_RC(noxtls_xmss_signer_attach_traversal(&signer, g_bds, state_len, 1U), NOXTLS_RETURN_BAD_DATA,
                "attach detects wrong root");
    sig_len = (uint32_t)sizeof(g_sig);
#if NOXTLS_XMSS_SIGN_SELF_CHECK
    PQ_CHECK_RC(noxtls_xmss_sign_stateful(&signer, g_msg, 8U, g_sig, &sig_len), NOXTLS_RETURN_FAILED,
                "self-check withholds a signature from a corrupt key");
    PQ_CHECK(xmss_t_all_zero(g_sig, info.signature_len) != 0, "withheld signature wiped (bad root)");
#else
    (void)sig_len;
#endif
    noxtls_xmss_signer_free(&signer);
}

#endif /* NOXTLS_XMSS_ENABLE_SIGN */

#if !defined(NOXTLS_PQ_TEST_ARM)
#define XMSS_T_SECTION(fn) \
    do { double t_ = xmss_t_now(); fn; printf("  [section] %-40s %.1fs\n", #fn, xmss_t_now() - t_); } while(0 == 1)
#else
#define XMSS_T_SECTION(fn) fn
#endif

int noxtls_pq_test_xmss(void)
{
    pq_test_begin("xmss");
    XMSS_T_SECTION(xmss_t_params());
#if NOXTLS_XMSS_ENABLE_SIGN
    XMSS_T_SECTION(xmss_t_kats());
#endif
    XMSS_T_SECTION(xmss_t_full());
    XMSS_T_SECTION(xmss_t_streaming());
#if NOXTLS_XMSS_ENABLE_SIGN
    XMSS_T_SECTION(xmss_t_keygen_args());
    XMSS_T_SECTION(xmss_t_signer_args());
    XMSS_T_SECTION(xmss_t_state());
    XMSS_T_SECTION(xmss_t_exhaustion(xmss_t_pick(0U)));
    XMSS_T_SECTION(xmss_t_exhaustion(xmss_t_pick(1U)));
    /* h = 40: the exhausted marker 2^40 does not fit the 5-byte index (2^40 - 1 signatures). */
    XMSS_T_SECTION(xmss_t_exhaustion(NOXTLS_XMSSMT_SHA2_40_8_256));
    XMSS_T_SECTION(xmss_t_exhaustion(NOXTLS_XMSSMT_SHAKE256_40_8_192));
    XMSS_T_SECTION(xmss_t_bds());
    XMSS_T_SECTION(xmss_t_bds_corrupt());
    XMSS_T_SECTION(xmss_t_roundtrips());
#endif
    return pq_test_end("xmss");
}

NOXTLS_PQ_TEST_MAIN(noxtls_pq_test_xmss)
