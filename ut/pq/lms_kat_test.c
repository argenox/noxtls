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
* File:    lms_kat_test.c
* Summary: LMS / HSS (RFC 8554, SP 800-208) known-answer, negative,
*          round-trip and state-management tests
*          (ut/pq/vectors/lms_kat_vectors.h).
*
*****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pq_test.h"
#include "noxtls_common.h"
#include "pkc/lms/noxtls_lms.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "lms_kat_vectors.h"

#if NOXTLS_FEATURE_LMS_HSS

#if defined(NOXTLS_PQ_TEST_QUICK)
#define LMS_T_QUICK 1
#else
#define LMS_T_QUICK 0
#endif

#define LMS_T_SIG_MAX 20000U
#define LMS_T_WS_WORDS (200000U / 4U)

static uint8_t g_pk[NOXTLS_HSS_MAX_PUBLIC_KEY_LEN + 8U];
static uint8_t g_pk2[NOXTLS_HSS_MAX_PUBLIC_KEY_LEN + 8U];
static uint8_t g_msg[1100];
static uint8_t g_sig[LMS_T_SIG_MAX];
static uint8_t g_sig2[LMS_T_SIG_MAX];
static uint8_t g_sk[NOXTLS_HSS_PRIVATE_KEY_LEN];
static uint8_t g_sk_old[NOXTLS_HSS_PRIVATE_KEY_LEN];
static uint8_t g_seed[32];
static uint8_t g_id[16];
static uint32_t g_ws_words[LMS_T_WS_WORDS];
static uint32_t g_ws2_words[LMS_T_WS_WORDS];
static noxtls_hss_key_t g_key;
static noxtls_hss_key_t g_key2;
static uint8_t g_dig[96][32];

/* ---- persistence stub ("flash") ----------------------------------------- */
static uint8_t g_flash[NOXTLS_HSS_PRIVATE_KEY_LEN];
static uint32_t g_persist_calls = 0U;
static noxtls_return_t g_persist_rc = NOXTLS_RETURN_SUCCESS;
static uint64_t g_persist_last = 0U;
static const uint8_t *g_persist_watch = NULL; /* must still hold the sentinel */
static uint32_t g_persist_watch_bad = 0U;

static uint64_t lms_t_get64(const uint8_t *p)
{
    uint64_t v = 0U;
    uint32_t i = 0U;

    for(i = 0U; i < 8U; i += 1U) {
        v = (v << 8U) | (uint64_t)p[i];
    }
    return v;
}

static noxtls_return_t lms_t_persist(void *user, const uint8_t *sk, uint32_t len)
{
    uint32_t *tag = (uint32_t *)user;

    g_persist_calls += 1U;
    if((tag == NULL) || (*tag != 0x5A5A5A5AU) || (len != NOXTLS_HSS_PRIVATE_KEY_LEN)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if((g_persist_watch != NULL) && (g_persist_watch[0] != 0xEEU || g_persist_watch[100] != 0xEEU)) {
        g_persist_watch_bad += 1U;
    }
    if(g_persist_rc != NOXTLS_RETURN_SUCCESS) {
        return g_persist_rc;
    }
    (void)memcpy(g_flash, sk, len);
    g_persist_last = lms_t_get64(&sk[72]);
    return NOXTLS_RETURN_SUCCESS;
}

static uint32_t g_tag = 0x5A5A5A5AU;

/* ---- helpers -------------------------------------------------------------- */

static uint8_t lms_t_nibble(char c)
{
    if((c >= '0') && (c <= '9')) {
        return (uint8_t)(c - '0');
    }
    if((c >= 'A') && (c <= 'F')) {
        return (uint8_t)(c - 'A' + 10);
    }
    return (uint8_t)(c - 'a' + 10);
}

static void lms_t_unhex(const char *hex, uint8_t *out, uint32_t len)
{
    uint32_t i = 0U;

    for(i = 0U; i < len; i += 1U) {
        out[i] = (uint8_t)((lms_t_nibble(hex[2U * i]) << 4U) | lms_t_nibble(hex[(2U * i) + 1U]));
    }
}

static void lms_t_sha256(const uint8_t *in, uint32_t len, uint8_t out[32])
{
    noxtls_sha_ctx_t ctx;

    (void)noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256);
    (void)noxtls_sha256_update(&ctx, in, len);
    (void)noxtls_sha256_finish(&ctx, out);
}

/* Rewrite the counter of a private key blob (test-only state manipulation). */
static void lms_t_set_counter(uint8_t *sk, uint64_t q)
{
    uint8_t d[32];
    uint32_t i = 0U;

    for(i = 0U; i < 8U; i += 1U) {
        sk[72U + i] = (uint8_t)(q >> (56U - (8U * i)));
    }
    lms_t_sha256(sk, 160U, d);
    (void)memcpy(&sk[160], d, 8U);
}

static uint32_t lms_t_get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24U) | ((uint32_t)p[1] << 16U) | ((uint32_t)p[2] << 8U) | (uint32_t)p[3];
}

static void lms_t_params(noxtls_hss_params_t *p, uint32_t fmt, uint32_t levels, const uint32_t *lms,
                         const uint32_t *ots)
{
    uint32_t i = 0U;

    (void)memset(p, 0, sizeof(*p));
    p->format = fmt;
    p->levels = levels;
    for(i = 0U; i < levels; i += 1U) {
        p->lms_type[i] = lms[i];
        p->ots_type[i] = ots[i];
    }
}

static void lms_t_params1(noxtls_hss_params_t *p, uint32_t fmt, uint32_t levels, uint32_t lms, uint32_t ots)
{
    uint32_t l[NOXTLS_HSS_MAX_LEVELS];
    uint32_t o[NOXTLS_HSS_MAX_LEVELS];
    uint32_t i = 0U;

    for(i = 0U; i < NOXTLS_HSS_MAX_LEVELS; i += 1U) {
        l[i] = lms;
        o[i] = ots;
    }
    lms_t_params(p, fmt, levels, l, o);
}

static uint8_t *lms_t_ws(void)
{
    return (uint8_t *)(void *)g_ws_words;
}

static uint8_t *lms_t_ws2(void)
{
    return (uint8_t *)(void *)g_ws2_words;
}

/* Deterministic test seed / I from a label. */
static void lms_t_seed(const char *label, uint32_t counter)
{
    pq_test_rng_seed_label(label, counter);
    pq_test_rng_bytes(g_seed, (uint32_t)sizeof(g_seed));
    pq_test_rng_bytes(g_id, (uint32_t)sizeof(g_id));
}

static noxtls_return_t lms_t_load(noxtls_hss_key_t *key, const uint8_t *sk, uint8_t *ws, uint32_t s, uint32_t flags)
{
    return noxtls_hss_key_load(key, sk, NOXTLS_HSS_PRIVATE_KEY_LEN, ws, (uint32_t)sizeof(g_ws_words), s, flags,
                               lms_t_persist, &g_tag);
}

/* ---- sizes ---------------------------------------------------------------- */

static void lms_t_sizes(void)
{
    static const uint32_t p32[4] = { 265U, 133U, 67U, 34U };
    static const uint32_t p24[4] = { 200U, 101U, 51U, 26U };
    noxtls_hss_params_t p;
    uint32_t lt = 0U;
    uint32_t ot = 0U;
    uint32_t fam = 0U;
    uint32_t ofam = 0U;
    uint32_t h = 0U;
    uint32_t n = 0U;
    uint32_t pp = 0U;
    uint32_t want = 0U;
    uint32_t got = 0U;

    for(lt = 0x05U; lt <= 0x18U; lt += 1U) {
        fam = (lt - 5U) / 5U;
        h = 5U * (((lt - 5U) % 5U) + 1U);
        for(ot = 0x01U; ot <= 0x10U; ot += 1U) {
            ofam = (ot - 1U) / 4U;
            n = ((ofam & 1U) == 0U) ? 32U : 24U;
            pp = (n == 32U) ? p32[(ot - 1U) % 4U] : p24[(ot - 1U) % 4U];
            want = (ofam == fam) ? (4U + 4U + (n * (pp + 1U)) + 4U + (n * h)) : 0U;
#if !NOXTLS_FEATURE_SHA3
            if(fam >= 2U) {
                want = 0U;
            }
#endif
            got = noxtls_lms_type_signature_len(lt, ot);
            PQ_CHECK(got == want, "LMS signature length table");
            lms_t_params1(&p, NOXTLS_LMS_FORMAT_LMS, 1U, lt, ot);
            PQ_CHECK((noxtls_hss_params_check(&p, 0U) == NOXTLS_RETURN_SUCCESS) == (want != 0U), "params check");
            if(want != 0U) {
                PQ_CHECK(noxtls_hss_public_key_len(&p) == (24U + n), "LMS pk len");
                PQ_CHECK(noxtls_hss_signature_len(&p) == want, "LMS sig len");
                PQ_CHECK(noxtls_hss_max_signatures(&p) == ((uint64_t)1U << h), "LMS max sigs");
                PQ_CHECK(want <= NOXTLS_LMS_MAX_LMS_SIGNATURE_LEN, "max LMS sig len");
                PQ_CHECK(noxtls_hss_workspace_len(&p, 0U) != 0U, "workspace len");
            }
        }
    }
    PQ_CHECK(noxtls_lms_type_signature_len(0x04U, 0x04U) == 0U, "LMS type 4 invalid");
    PQ_CHECK(noxtls_lms_type_signature_len(0x19U, 0x04U) == 0U, "LMS type 0x19 invalid");
    PQ_CHECK(noxtls_lms_type_signature_len(0x05U, 0x00U) == 0U, "OTS type 0 invalid");
    PQ_CHECK(noxtls_lms_type_signature_len(0x05U, 0x11U) == 0U, "OTS type 0x11 invalid");
    /* HSS sizes, levels and signing restrictions. */
    lms_t_params1(&p, NOXTLS_LMS_FORMAT_HSS, 2U, NOXTLS_LMS_TYPE_SHA256_M32_H10, NOXTLS_LMOTS_TYPE_SHA256_N32_W8);
    PQ_CHECK(noxtls_hss_signature_len(&p) == 2964U, "HSS L=2 sig len");
    PQ_CHECK(noxtls_hss_public_key_len(&p) == 60U, "HSS pk len");
    PQ_CHECK(noxtls_hss_max_signatures(&p) == ((uint64_t)1U << 20U), "HSS max sigs");
    p.levels = 0U;
    PQ_CHECK_RC(noxtls_hss_params_check(&p, 0U), NOXTLS_RETURN_INVALID_PARAM, "L=0");
    p.levels = 9U;
    PQ_CHECK_RC(noxtls_hss_params_check(&p, 0U), NOXTLS_RETURN_INVALID_PARAM, "L=9");
    PQ_CHECK(noxtls_hss_signature_len(&p) == 0U, "L=9 sig len");
    PQ_CHECK(noxtls_hss_max_signatures(&p) == 0U, "L=9 max");
    PQ_CHECK(noxtls_hss_workspace_len(&p, 0U) == 0U, "L=9 ws");
    PQ_CHECK_RC(noxtls_hss_params_check(NULL, 0U), NOXTLS_RETURN_NULL, "NULL params");
    lms_t_params1(&p, NOXTLS_LMS_FORMAT_LMS, 2U, NOXTLS_LMS_TYPE_SHA256_M32_H5, NOXTLS_LMOTS_TYPE_SHA256_N32_W8);
    PQ_CHECK_RC(noxtls_hss_params_check(&p, 0U), NOXTLS_RETURN_INVALID_PARAM, "LMS format with L=2");
    p.format = 7U;
    PQ_CHECK_RC(noxtls_hss_params_check(&p, 0U), NOXTLS_RETURN_INVALID_PARAM, "bad format");
    /* 8 x H25 = 200 bits: verifiable, but not a signing key (64-bit counter). */
    lms_t_params1(&p, NOXTLS_LMS_FORMAT_HSS, 8U, NOXTLS_LMS_TYPE_SHA256_M32_H25, NOXTLS_LMOTS_TYPE_SHA256_N32_W8);
    PQ_CHECK_RC(noxtls_hss_params_check(&p, 0U), NOXTLS_RETURN_SUCCESS, "L=8 H25 verifiable");
    PQ_CHECK_RC(noxtls_hss_params_check(&p, 1U), NOXTLS_RETURN_INVALID_PARAM, "L=8 H25 not signable");
    PQ_CHECK(noxtls_hss_max_signatures(&p) == 0U, "L=8 H25 max");
    /* Mixed hash families across levels: verifiable, not signable. */
    p.levels = 2U;
    p.lms_type[1] = NOXTLS_LMS_TYPE_SHA256_M24_H5;
    p.ots_type[1] = NOXTLS_LMOTS_TYPE_SHA256_N24_W8;
    PQ_CHECK_RC(noxtls_hss_params_check(&p, 0U), NOXTLS_RETURN_SUCCESS, "mixed n verifiable");
    PQ_CHECK_RC(noxtls_hss_params_check(&p, 1U), NOXTLS_RETURN_INVALID_PARAM, "mixed n not signable");
    PQ_CHECK(NOXTLS_HSS_PRIVATE_KEY_LEN <= NOXTLS_LMS_MAX_SECRET_KEY_LEN, "private key fits legacy max");
}

/* ---- HSS vectors: verification and negative tests ------------------------ */

static void lms_t_verify_neg(const char *what, uint32_t pk_len, uint32_t msg_len, uint32_t sig_len)
{
    static const uint32_t offs[] = { 0U, 3U, 4U, 7U, 8U, 11U, 12U, 20U, 50U, 200U, 700U };
    noxtls_hss_verify_ctx_t ctx;
    uint32_t i = 0U;
    uint32_t off = 0U;
    uint32_t levels = lms_t_get32(g_pk);

    (void)what;
    PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, msg_len, g_sig, sig_len),
                NOXTLS_RETURN_SUCCESS, what);
    /* streaming in odd chunks */
    PQ_CHECK_RC(noxtls_hss_verify_init(&ctx, NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_sig, sig_len),
                NOXTLS_RETURN_SUCCESS, "stream init");
    for(i = 0U; i < msg_len; i += 7U) {
        PQ_CHECK_RC(noxtls_hss_verify_update(&ctx, &g_msg[i], ((msg_len - i) < 7U) ? (msg_len - i) : 7U),
                    NOXTLS_RETURN_SUCCESS, "stream update");
    }
    PQ_CHECK_RC(noxtls_hss_verify_final(&ctx), NOXTLS_RETURN_SUCCESS, "stream final");
    PQ_CHECK_RC(noxtls_hss_verify_final(&ctx), NOXTLS_RETURN_NOT_INITIALIZED, "final twice");
    PQ_CHECK_RC(noxtls_hss_verify_update(&ctx, g_msg, 1U), NOXTLS_RETURN_NOT_INITIALIZED, "update after final");

    /* every tampered signature byte position class must fail */
    for(i = 0U; i < (uint32_t)(sizeof(offs) / sizeof(offs[0])); i += 1U) {
        off = offs[i];
        g_sig[off] ^= 0x01U;
        PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, msg_len, g_sig, sig_len),
                    NOXTLS_RETURN_FAILED, "tampered signature");
        g_sig[off] ^= 0x01U;
    }
    for(off = sig_len - 1U; off > (sig_len - 40U); off -= 13U) {
        g_sig[off] ^= 0x80U;
        PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, msg_len, g_sig, sig_len),
                    NOXTLS_RETURN_FAILED, "tampered signature tail (path)");
        g_sig[off] ^= 0x80U;
    }
    PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, msg_len, g_sig, sig_len - 1U),
                NOXTLS_RETURN_FAILED, "truncated signature");
    g_sig[sig_len] = 0U;
    PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, msg_len, g_sig, sig_len + 1U),
                NOXTLS_RETURN_FAILED, "extended signature");
    PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, msg_len, g_sig, 3U),
                NOXTLS_RETURN_FAILED, "3-byte signature");
    PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, msg_len, g_sig, 40U),
                NOXTLS_RETURN_FAILED, "40-byte signature");
    if(msg_len > 0U) {
        g_msg[msg_len - 1U] ^= 0x01U;
        PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, msg_len, g_sig, sig_len),
                    NOXTLS_RETURN_FAILED, "tampered message");
        g_msg[msg_len - 1U] ^= 0x01U;
        PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, msg_len - 1U, g_sig, sig_len),
                    NOXTLS_RETURN_FAILED, "shortened message");
    }
    /* public key tampering */
    g_pk[pk_len - 1U] ^= 0x01U;
    PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, msg_len, g_sig, sig_len),
                NOXTLS_RETURN_FAILED, "tampered root");
    g_pk[pk_len - 1U] ^= 0x01U;
    g_pk[12] ^= 0x01U;
    PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, msg_len, g_sig, sig_len),
                NOXTLS_RETURN_FAILED, "tampered I");
    g_pk[12] ^= 0x01U;
    g_pk[3] = (uint8_t)(levels + 1U);
    PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, msg_len, g_sig, sig_len),
                NOXTLS_RETURN_FAILED, "L != Nspk + 1");
    g_pk[3] = 0U;
    PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, msg_len, g_sig, sig_len),
                NOXTLS_RETURN_INVALID_PARAM, "L = 0");
    g_pk[3] = 9U;
    PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, msg_len, g_sig, sig_len),
                NOXTLS_RETURN_INVALID_PARAM, "L = 9");
    g_pk[3] = (uint8_t)levels;
    g_pk[7] ^= 0x03U;
    PQ_CHECK(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, msg_len, g_sig, sig_len) !=
             NOXTLS_RETURN_SUCCESS, "wrong LMS typecode in pk");
    g_pk[7] ^= 0x03U;
    g_pk[11] ^= 0x07U;
    PQ_CHECK(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, msg_len, g_sig, sig_len) !=
             NOXTLS_RETURN_SUCCESS, "wrong OTS typecode in pk");
    g_pk[11] ^= 0x07U;
    PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len - 1U, g_msg, msg_len, g_sig, sig_len),
                NOXTLS_RETURN_INVALID_PARAM, "short pk");
    PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, 3U, g_msg, msg_len, g_sig, sig_len),
                NOXTLS_RETURN_INVALID_PARAM, "3-byte pk");
    PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_LMS, g_pk, pk_len, g_msg, msg_len, g_sig, sig_len),
                NOXTLS_RETURN_INVALID_PARAM, "HSS key as bare LMS");
    PQ_CHECK_RC(noxtls_hss_verify(9U, g_pk, pk_len, g_msg, msg_len, g_sig, sig_len),
                NOXTLS_RETURN_INVALID_PARAM, "bad format");
    PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, NULL, pk_len, g_msg, msg_len, g_sig, sig_len),
                NOXTLS_RETURN_NULL, "NULL pk");
    PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, NULL, msg_len, g_sig, sig_len),
                (msg_len == 0U) ? NOXTLS_RETURN_FAILED : NOXTLS_RETURN_NULL, "NULL msg");
    PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, msg_len, NULL, sig_len),
                NOXTLS_RETURN_NULL, "NULL sig");
    PQ_CHECK_RC(noxtls_hss_verify_init(NULL, NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_sig, sig_len),
                NOXTLS_RETURN_NULL, "NULL ctx");
    PQ_CHECK_RC(noxtls_hss_verify_update(NULL, g_msg, 1U), NOXTLS_RETURN_NULL, "NULL ctx update");
    PQ_CHECK_RC(noxtls_hss_verify_final(NULL), NOXTLS_RETURN_NULL, "NULL ctx final");
    PQ_CHECK_RC(noxtls_hss_verify_init(&ctx, NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_sig, sig_len),
                NOXTLS_RETURN_SUCCESS, "stream init 2");
    PQ_CHECK_RC(noxtls_hss_verify_update(&ctx, NULL, 1U), NOXTLS_RETURN_NULL, "NULL data");
    PQ_CHECK_RC(noxtls_hss_verify_final(&ctx), NOXTLS_RETURN_NOT_INITIALIZED, "final after error");
}

/* q out of range and wrong typecodes inside the (bottom) LMS signature. */
static void lms_t_verify_struct(uint32_t pk_len, uint32_t msg_len, uint32_t sig_len)
{
    uint32_t off = 4U;
    uint32_t i = 0U;
    uint32_t levels = lms_t_get32(g_pk);
    uint32_t lt = lms_t_get32(&g_pk[4]);
    uint32_t ot = lms_t_get32(&g_pk[8]);
    uint32_t len = 0U;
    uint32_t save = 0U;
    uint32_t h = 5U * (((lt - 5U) % 5U) + 1U);

    for(i = 0U; (i + 1U) < levels; i += 1U) {
        len = noxtls_lms_type_signature_len(lt, ot);
        lt = lms_t_get32(&g_sig[off + len]);
        ot = lms_t_get32(&g_sig[off + len + 4U]);
        off += len + 24U + (((((lt - 5U) / 5U) & 1U) == 0U) ? 32U : 24U);
    }
    h = 5U * (((lt - 5U) % 5U) + 1U);
    save = lms_t_get32(&g_sig[off]);
    g_sig[off] = 0U;
    g_sig[off + 1U] = (uint8_t)((1U << h) >> 16U);
    g_sig[off + 2U] = (uint8_t)((1U << h) >> 8U);
    g_sig[off + 3U] = (uint8_t)(1U << h);
    PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, msg_len, g_sig, sig_len),
                NOXTLS_RETURN_FAILED, "q = 2^h");
    g_sig[off] = 0xFFU;
    PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, msg_len, g_sig, sig_len),
                NOXTLS_RETURN_FAILED, "q huge");
    g_sig[off] = (uint8_t)(save >> 24U);
    g_sig[off + 1U] = (uint8_t)(save >> 16U);
    g_sig[off + 2U] = (uint8_t)(save >> 8U);
    g_sig[off + 3U] = (uint8_t)save;
    PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, msg_len, g_sig, sig_len),
                NOXTLS_RETURN_SUCCESS, "restored");
    /* OTS typecode of the bottom signature: a valid other code */
    g_sig[off + 7U] ^= 0x01U;
    PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, msg_len, g_sig, sig_len),
                NOXTLS_RETURN_FAILED, "bottom OTS typecode");
    g_sig[off + 7U] ^= 0x01U;
    /* LMS typecode after the OTS signature */
    len = noxtls_lms_type_signature_len(lt, ot) - (4U + (h * ((((((lt - 5U) / 5U) & 1U) == 0U) ? 32U : 24U))));
    g_sig[off + len - 1U] ^= 0x01U;
    PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, msg_len, g_sig, sig_len),
                NOXTLS_RETURN_FAILED, "bottom LMS typecode");
    g_sig[off + len - 1U] ^= 0x01U;
    PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, msg_len, g_sig, sig_len),
                NOXTLS_RETURN_SUCCESS, "restored 2");
    if(levels > 1U) {
        /* unsupported typecode in the signed lower-level public key */
        len = noxtls_lms_type_signature_len(lms_t_get32(&g_pk[4]), lms_t_get32(&g_pk[8]));
        g_sig[4U + len + 3U] = 0x77U;
        PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, msg_len, g_sig, sig_len),
                    NOXTLS_RETURN_FAILED, "unknown typecode in signed public key");
    }
}

static void lms_t_hss_vectors(void)
{
    uint32_t i = 0U;
    uint32_t mark = 0U;
    const lms_kat_hss_t *v = NULL;

    for(i = 0U; i < (uint32_t)(sizeof(g_lms_kat_hss) / sizeof(g_lms_kat_hss[0])); i += 1U) {
        v = &g_lms_kat_hss[i];
#if !NOXTLS_FEATURE_SHA3
        if((i == 3U) || (i == 4U)) {
            continue; /* SHAKE test cases */
        }
#endif
        lms_t_unhex(v->pk, g_pk, v->pk_len);
        lms_t_unhex(v->msg, g_msg, v->msg_len);
        lms_t_unhex(v->sig, g_sig, v->sig_len);
        mark = pq_test_probe_begin();
        PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, v->pk_len, g_msg, v->msg_len, g_sig, v->sig_len),
                    NOXTLS_RETURN_SUCCESS, v->what);
        pq_test_probe_end(mark, (i == 0U) ? "hss_verify L=2 H5/H5 W8 (RFC 8554 TC1)" :
                                 ((i == 1U) ? "hss_verify L=2 H10 W4/H5 W8 (RFC 8554 TC2)" : "hss_verify L=1"));
        lms_t_verify_neg(v->what, v->pk_len, v->msg_len, v->sig_len);
        lms_t_verify_struct(v->pk_len, v->msg_len, v->sig_len);
    }
}

/* ---- trees from (SEED, I): keygen and signing at a given q -------------- */

static void lms_t_tree_vectors(void)
{
    noxtls_hss_params_t p;
    const lms_kat_tree_t *v = NULL;
    uint32_t i = 0U;
    uint32_t sig_len = 0U;
    uint32_t mark = 0U;

    for(i = 0U; i < (uint32_t)(sizeof(g_lms_kat_tree) / sizeof(g_lms_kat_tree[0])); i += 1U) {
        v = &g_lms_kat_tree[i];
        lms_t_unhex(v->lpk, g_pk2, v->lpk_len);
#if !NOXTLS_FEATURE_SHA3
        if(lms_t_get32(g_pk2) >= NOXTLS_LMS_TYPE_SHAKE_M32_H5) {
            continue;
        }
#endif
#if !defined(NOXTLS_PQ_TEST_SLOW)
        if(v->slow != 0U) {
            continue; /* H20 tree: 2^20 leaves, build with -DNOXTLS_PQ_TEST_SLOW */
        }
#endif
        if((LMS_T_QUICK != 0) && (lms_t_get32(g_pk2) != NOXTLS_LMS_TYPE_SHA256_M32_H5) &&
           (lms_t_get32(g_pk2) != NOXTLS_LMS_TYPE_SHA256_M24_H5)) {
            continue;
        }
        lms_t_unhex(v->seed, g_seed, v->seed_len);
        lms_t_unhex(v->id, g_id, 16U);
        lms_t_unhex(v->lsig, g_sig2, v->lsig_len);
        lms_t_unhex(v->msg, g_msg, v->msg_len);
        lms_t_params1(&p, NOXTLS_LMS_FORMAT_LMS, 1U, lms_t_get32(g_pk2), lms_t_get32(&g_pk2[4]));
        mark = pq_test_probe_begin();
        PQ_CHECK_RC(noxtls_hss_keygen(&p, g_seed, g_id, g_pk, (uint32_t)sizeof(g_pk), g_sk, (uint32_t)sizeof(g_sk)),
                    NOXTLS_RETURN_SUCCESS, "keygen from SEED/I");
        pq_test_probe_end(mark, "lms_keygen (KAT tree)");
        PQ_CHECK_MEM(g_pk, g_pk2, v->lpk_len, v->what);
        /* sign at the vector's q */
        lms_t_set_counter(g_sk, (uint64_t)lms_t_get32(g_sig2));
        PQ_CHECK_RC(lms_t_load(&g_key, g_sk, lms_t_ws(), 0U, 0U), NOXTLS_RETURN_SUCCESS, "load at q");
        PQ_CHECK_RC(noxtls_hss_sign(&g_key, g_msg, v->msg_len, g_sig, (uint32_t)sizeof(g_sig), &sig_len),
                    NOXTLS_RETURN_SUCCESS, "sign at q");
        PQ_CHECK(sig_len == v->lsig_len, "KAT signature length");
        PQ_CHECK_MEM(g_sig, g_sig2, v->lsig_len, "KAT signature (pseudo-random C)");
        noxtls_hss_key_free(&g_key);
        PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_LMS, g_pk2, v->lpk_len, g_msg, v->msg_len, g_sig2,
                                      v->lsig_len), NOXTLS_RETURN_SUCCESS, "verify bare LMS KAT signature");
    }
}

/* ---- ACVP --------------------------------------------------------------- */

static void lms_t_acvp(void)
{
    noxtls_hss_params_t p;
    const lms_kat_keygen_t *k = NULL;
    const lms_kat_sigver_t *v = NULL;
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    for(i = 0U; i < (uint32_t)(sizeof(g_lms_kat_keygen) / sizeof(g_lms_kat_keygen[0])); i += 1U) {
        k = &g_lms_kat_keygen[i];
        if((LMS_T_QUICK != 0) && (i > 0U) && (k->lms_type != NOXTLS_LMS_TYPE_SHA256_M24_H5)) {
            continue;
        }
        lms_t_params1(&p, NOXTLS_LMS_FORMAT_LMS, 1U, k->lms_type, k->ots_type);
        PQ_CHECK_RC(noxtls_hss_keygen(&p, k->seed, k->id, g_pk, (uint32_t)sizeof(g_pk), g_sk, (uint32_t)sizeof(g_sk)),
                    NOXTLS_RETURN_SUCCESS, "ACVP keyGen");
        PQ_CHECK_MEM(g_pk, k->pk, k->pk_len, "ACVP keyGen public key");
    }
    for(i = 0U; i < (uint32_t)(sizeof(g_lms_kat_sigver) / sizeof(g_lms_kat_sigver[0])); i += 1U) {
        v = &g_lms_kat_sigver[i];
        lms_t_unhex(v->pk, g_pk, v->pk_len);
        lms_t_unhex(v->msg, g_msg, v->msg_len);
        lms_t_unhex(v->sig, g_sig, v->sig_len);
        rc = noxtls_hss_verify(NOXTLS_LMS_FORMAT_LMS, g_pk, v->pk_len, g_msg, v->msg_len, g_sig, v->sig_len);
        PQ_CHECK_RC(rc, (v->valid != 0U) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED, v->what);
        if(v->valid != 0U) {
            PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, v->pk_len, g_msg, v->msg_len, g_sig,
                                          v->sig_len), NOXTLS_RETURN_INVALID_PARAM, "bare LMS key as HSS");
        }
    }
}

/* ---- round trips over the parameter sets ---------------------------------- */

static void lms_t_roundtrip(const noxtls_hss_params_t *p, uint32_t s, uint32_t nsig, const char *what)
{
    uint32_t i = 0U;
    uint32_t sig_len = 0U;
    uint32_t pk_len = 0U;
    uint32_t mark = 0U;
    uint64_t max = noxtls_hss_max_signatures(p);

    lms_t_seed(what, s);
    mark = pq_test_probe_begin();
    PQ_CHECK_RC(noxtls_hss_keygen(p, g_seed, g_id, g_pk, (uint32_t)sizeof(g_pk), g_sk, (uint32_t)sizeof(g_sk)),
                NOXTLS_RETURN_SUCCESS, what);
    pq_test_probe_end(mark, "keygen");
    pk_len = noxtls_hss_public_key_len(p);
    PQ_CHECK(noxtls_hss_workspace_len(p, s) <= (uint32_t)sizeof(g_ws_words), "test workspace big enough");
    mark = pq_test_probe_begin();
    PQ_CHECK_RC(lms_t_load(&g_key, g_sk, lms_t_ws(), s, 0U), NOXTLS_RETURN_SUCCESS, "load");
    pq_test_probe_end(mark, "key_load (rebuild)");
    PQ_CHECK(noxtls_hss_key_remaining(&g_key) == max, "remaining = max");
    for(i = 0U; i < nsig; i += 1U) {
        g_msg[0] = (uint8_t)i;
        g_msg[1] = 0xA5U;
        mark = pq_test_probe_begin();
        PQ_CHECK_RC(noxtls_hss_sign(&g_key, g_msg, 2U + i, g_sig, (uint32_t)sizeof(g_sig), &sig_len),
                    NOXTLS_RETURN_SUCCESS, what);
        pq_test_probe_end(mark, "sign");
        PQ_CHECK(sig_len == noxtls_hss_signature_len(p), "signature length");
        mark = pq_test_probe_begin();
        PQ_CHECK_RC(noxtls_hss_verify(p->format, g_pk, pk_len, g_msg, 2U + i, g_sig, sig_len),
                    NOXTLS_RETURN_SUCCESS, "verify round trip");
        pq_test_probe_end(mark, "verify");
        g_msg[1] ^= 0x01U;
        PQ_CHECK_RC(noxtls_hss_verify(p->format, g_pk, pk_len, g_msg, 2U + i, g_sig, sig_len),
                    NOXTLS_RETURN_FAILED, "verify round trip wrong message");
    }
    PQ_CHECK(noxtls_hss_key_remaining(&g_key) == (max - nsig), "remaining decrements");
    noxtls_hss_key_free(&g_key);
}

static void lms_t_roundtrips(void)
{
    static const uint32_t fams[4][2] = {
        { NOXTLS_LMS_TYPE_SHA256_M32_H5, NOXTLS_LMOTS_TYPE_SHA256_N32_W1 },
        { NOXTLS_LMS_TYPE_SHA256_M24_H5, NOXTLS_LMOTS_TYPE_SHA256_N24_W1 },
        { NOXTLS_LMS_TYPE_SHAKE_M32_H5, NOXTLS_LMOTS_TYPE_SHAKE_N32_W1 },
        { NOXTLS_LMS_TYPE_SHAKE_M24_H5, NOXTLS_LMOTS_TYPE_SHAKE_N24_W1 },
    };
    noxtls_hss_params_t p;
    uint32_t lv[NOXTLS_HSS_MAX_LEVELS];
    uint32_t ov[NOXTLS_HSS_MAX_LEVELS];
    uint32_t f = 0U;
    uint32_t w = 0U;
    uint32_t nfam = 4U;

#if !NOXTLS_FEATURE_SHA3
    nfam = 2U;
#endif
    /* every hash family x every Winternitz parameter, H5, bare LMS */
    for(f = 0U; f < nfam; f += 1U) {
        for(w = 0U; w < 4U; w += 1U) {
            if((LMS_T_QUICK != 0) && (w != 2U) && (f != 1U)) {
                continue;
            }
            lms_t_params1(&p, NOXTLS_LMS_FORMAT_LMS, 1U, fams[f][0], fams[f][1] + w);
            lms_t_roundtrip(&p, 0U, 2U, "LMS H5 round trip");
        }
    }
    /* taller trees of every family (cheapest W) */
    for(f = 0U; f < nfam; f += 1U) {
        if((LMS_T_QUICK != 0) && (f != 1U)) {
            continue;
        }
        lms_t_params1(&p, NOXTLS_LMS_FORMAT_HSS, 1U, fams[f][0] + 1U, fams[f][1] + 2U);
        lms_t_roundtrip(&p, 3U, 3U, "HSS L=1 H10 W4 round trip");
    }
#if !LMS_T_QUICK
    lms_t_params1(&p, NOXTLS_LMS_FORMAT_LMS, 1U, NOXTLS_LMS_TYPE_SHA256_M24_H15, NOXTLS_LMOTS_TYPE_SHA256_N24_W1);
    lms_t_roundtrip(&p, 5U, 3U, "LMS H15 W1 round trip");
#endif
    /* HSS: L=2 mixed heights and W, L=3, L=8 */
    lv[0] = NOXTLS_LMS_TYPE_SHA256_M32_H10;
    ov[0] = NOXTLS_LMOTS_TYPE_SHA256_N32_W4;
    lv[1] = NOXTLS_LMS_TYPE_SHA256_M32_H5;
    ov[1] = NOXTLS_LMOTS_TYPE_SHA256_N32_W2;
    lms_t_params(&p, NOXTLS_LMS_FORMAT_HSS, 2U, lv, ov);
    lms_t_roundtrip(&p, 2U, (LMS_T_QUICK != 0) ? 2U : 34U, "HSS L=2 H10W4/H5W2");
#if NOXTLS_FEATURE_SHA3
    lms_t_params1(&p, NOXTLS_LMS_FORMAT_HSS, 3U, NOXTLS_LMS_TYPE_SHAKE_M24_H5, NOXTLS_LMOTS_TYPE_SHAKE_N24_W4);
    lms_t_roundtrip(&p, 1U, (LMS_T_QUICK != 0) ? 2U : 33U, "HSS L=3 SHAKE/192 H5 W4");
#endif
    lms_t_params1(&p, NOXTLS_LMS_FORMAT_HSS, 8U, NOXTLS_LMS_TYPE_SHA256_M24_H5, NOXTLS_LMOTS_TYPE_SHA256_N24_W8);
    lms_t_roundtrip(&p, 0U, 2U, "HSS L=8 H5 W8");
}

/* ---- traversal determinism: different subtree heights, reloads ---------- */

/* Sign nsig messages from counter `start` with sublevel height s; digests to g_dig. */
static void lms_t_sign_run(const uint8_t *sk, uint64_t start, uint32_t s, uint32_t nsig, uint32_t reserve,
                           uint32_t compare)
{
    uint8_t blob[NOXTLS_HSS_PRIVATE_KEY_LEN];
    uint8_t d[32];
    uint32_t i = 0U;
    uint32_t sig_len = 0U;

    (void)memcpy(blob, sk, sizeof(blob));
    lms_t_set_counter(blob, start);
    PQ_CHECK_RC(lms_t_load(&g_key, blob, lms_t_ws(), s, 0U), NOXTLS_RETURN_SUCCESS, "run load");
    PQ_CHECK_RC(noxtls_hss_key_set_reserve(&g_key, reserve), NOXTLS_RETURN_SUCCESS, "set reserve");
    for(i = 0U; i < nsig; i += 1U) {
        g_msg[0] = (uint8_t)i;
        PQ_CHECK_RC(noxtls_hss_sign(&g_key, g_msg, 1U, g_sig, (uint32_t)sizeof(g_sig), &sig_len),
                    NOXTLS_RETURN_SUCCESS, "run sign");
        lms_t_sha256(g_sig, sig_len, d);
        if(compare != 0U) {
            PQ_CHECK_MEM(d, g_dig[i], 32U, "signature independent of traversal parameters");
        } else {
            (void)memcpy(g_dig[i], d, 32U);
        }
    }
    noxtls_hss_key_free(&g_key);
}

static void lms_t_traversal(void)
{
    noxtls_hss_params_t p;
    uint32_t s = 0U;
    uint32_t n = (LMS_T_QUICK != 0) ? 12U : 32U;

    /* single tree H5: full cache (s=5) is the reference, s=1..4 must match */
    lms_t_params1(&p, NOXTLS_LMS_FORMAT_LMS, 1U, NOXTLS_LMS_TYPE_SHA256_M24_H5, NOXTLS_LMOTS_TYPE_SHA256_N24_W1);
    lms_t_seed("traversal-h5", 0U);
    PQ_CHECK_RC(noxtls_hss_keygen(&p, g_seed, g_id, g_pk, (uint32_t)sizeof(g_pk), g_sk, (uint32_t)sizeof(g_sk)),
                NOXTLS_RETURN_SUCCESS, "traversal keygen");
    lms_t_sign_run(g_sk, 0U, 5U, n, 100U, 0U);
    for(s = 1U; s < 5U; s += 1U) {
        lms_t_sign_run(g_sk, 0U, s, n, 1U, 1U);
    }
    /* restart in the middle: reload at q = 13 equals the continuous run */
    {
        uint8_t blob[NOXTLS_HSS_PRIVATE_KEY_LEN];
        uint8_t d[32];
        uint32_t sig_len = 0U;

        (void)memcpy(blob, g_sk, sizeof(blob));
        lms_t_set_counter(blob, 7U);
        PQ_CHECK_RC(lms_t_load(&g_key, blob, lms_t_ws(), 2U, 0U), NOXTLS_RETURN_SUCCESS, "mid load");
        g_msg[0] = 7U;
        PQ_CHECK_RC(noxtls_hss_sign(&g_key, g_msg, 1U, g_sig, (uint32_t)sizeof(g_sig), &sig_len),
                    NOXTLS_RETURN_SUCCESS, "mid sign");
        lms_t_sha256(g_sig, sig_len, d);
        PQ_CHECK_MEM(d, g_dig[7], 32U, "mid-run reload");
        noxtls_hss_key_free(&g_key);
    }
    /* HSS L=2 H5/H5 over two bottom-tree rollovers */
    n = (LMS_T_QUICK != 0) ? 34U : 70U;
    lms_t_params1(&p, NOXTLS_LMS_FORMAT_HSS, 2U, NOXTLS_LMS_TYPE_SHA256_M24_H5, NOXTLS_LMOTS_TYPE_SHA256_N24_W2);
    lms_t_seed("traversal-hss", 0U);
    PQ_CHECK_RC(noxtls_hss_keygen(&p, g_seed, g_id, g_pk, (uint32_t)sizeof(g_pk), g_sk, (uint32_t)sizeof(g_sk)),
                NOXTLS_RETURN_SUCCESS, "traversal hss keygen");
    lms_t_sign_run(g_sk, 0U, 5U, n, 1000U, 0U);
    lms_t_sign_run(g_sk, 0U, 2U, n, 7U, 1U);
    if(LMS_T_QUICK == 0) {
        lms_t_sign_run(g_sk, 0U, 1U, n, 1U, 1U);
    }
}

/* ---- state management ---------------------------------------------------- */

static void lms_t_state(void)
{
    noxtls_hss_params_t p;
    uint32_t sig_len = 0U;
    uint32_t i = 0U;
    uint32_t calls = 0U;
    uint64_t q = 0U;
    uint8_t *ws = lms_t_ws();

    lms_t_params1(&p, NOXTLS_LMS_FORMAT_LMS, 1U, NOXTLS_LMS_TYPE_SHA256_M24_H5, NOXTLS_LMOTS_TYPE_SHA256_N24_W4);
    lms_t_seed("state", 0U);
    PQ_CHECK_RC(noxtls_hss_keygen(&p, g_seed, g_id, g_pk, (uint32_t)sizeof(g_pk), g_sk, (uint32_t)sizeof(g_sk)),
                NOXTLS_RETURN_SUCCESS, "state keygen");
    PQ_CHECK_RC(noxtls_hss_private_key_info(g_sk, (uint32_t)sizeof(g_sk), NULL, &q, NULL), NOXTLS_RETURN_SUCCESS,
                "info");
    PQ_CHECK(q == 0U, "fresh key counter 0");

    /* load argument checks */
    PQ_CHECK_RC(noxtls_hss_key_load(&g_key, g_sk, NOXTLS_HSS_PRIVATE_KEY_LEN, ws, (uint32_t)sizeof(g_ws_words), 0U, 0U,
                                    NULL, NULL), NOXTLS_RETURN_NULL, "load without persistence callback");
    PQ_CHECK_RC(noxtls_hss_key_load(NULL, g_sk, NOXTLS_HSS_PRIVATE_KEY_LEN, ws, 0U, 0U, 0U, lms_t_persist, &g_tag),
                NOXTLS_RETURN_NULL, "load NULL key");
    PQ_CHECK_RC(noxtls_hss_key_load(&g_key, g_sk, NOXTLS_HSS_PRIVATE_KEY_LEN - 1U, ws, (uint32_t)sizeof(g_ws_words),
                                    0U, 0U, lms_t_persist, &g_tag), NOXTLS_RETURN_INVALID_KEY_SIZE, "short blob");
    PQ_CHECK_RC(noxtls_hss_key_load(&g_key, g_sk, NOXTLS_HSS_PRIVATE_KEY_LEN, ws, 64U, 0U, 0U, lms_t_persist, &g_tag),
                NOXTLS_RETURN_NOT_ENOUGH_MEMORY, "short workspace");
    PQ_CHECK_RC(noxtls_hss_key_load(&g_key, g_sk, NOXTLS_HSS_PRIVATE_KEY_LEN, &ws[1], 60000U, 0U, 0U, lms_t_persist,
                                    &g_tag), NOXTLS_RETURN_INVALID_PARAM, "misaligned workspace");
    PQ_CHECK_RC(noxtls_hss_key_load(&g_key, g_sk, NOXTLS_HSS_PRIVATE_KEY_LEN, ws, 60000U, 26U, 0U, lms_t_persist,
                                    &g_tag), NOXTLS_RETURN_INVALID_PARAM, "subtree height 26");
    PQ_CHECK_RC(noxtls_hss_key_load(&g_key, g_sk, NOXTLS_HSS_PRIVATE_KEY_LEN, ws, 60000U, 0U, 0x80U, lms_t_persist,
                                    &g_tag), NOXTLS_RETURN_INVALID_PARAM, "unknown flag");
    (void)memcpy(g_sk_old, g_sk, sizeof(g_sk));
    g_sk_old[100] ^= 0x01U;
    PQ_CHECK_RC(lms_t_load(&g_key, g_sk_old, ws, 0U, 0U), NOXTLS_RETURN_BAD_DATA, "corrupted blob (checksum)");
    (void)memcpy(g_sk_old, g_sk, sizeof(g_sk));
    g_sk_old[130] ^= 0x01U; /* root, with a fixed checksum */
    lms_t_set_counter(g_sk_old, 0U);
    PQ_CHECK_RC(lms_t_load(&g_key, g_sk_old, ws, 0U, 0U), NOXTLS_RETURN_BAD_DATA, "root does not match SEED");
    (void)memcpy(g_sk_old, g_sk, sizeof(g_sk));
    lms_t_set_counter(g_sk_old, 33U);
    PQ_CHECK_RC(lms_t_load(&g_key, g_sk_old, ws, 0U, 0U), NOXTLS_RETURN_BAD_DATA, "counter > max");
    PQ_CHECK_RC(noxtls_hss_private_key_info(g_sk_old, (uint32_t)sizeof(g_sk), NULL, NULL, NULL),
                NOXTLS_RETURN_BAD_DATA, "info counter > max");
    PQ_CHECK(noxtls_hss_key_remaining(&g_key) == 0U, "failed load leaves key unusable");
    PQ_CHECK_RC(noxtls_hss_sign(&g_key, g_msg, 1U, g_sig, (uint32_t)sizeof(g_sig), &sig_len),
                NOXTLS_RETURN_NOT_INITIALIZED, "sign with unloaded key");

    /* persist-before-sign with a sentinel in the output buffer */
    PQ_CHECK_RC(lms_t_load(&g_key, g_sk, ws, 0U, 0U), NOXTLS_RETURN_SUCCESS, "state load");
    g_persist_calls = 0U;
    for(i = 0U; i < 3U; i += 1U) {
        (void)memset(g_sig, 0xEE, 200U);
        g_persist_watch = g_sig;
        g_msg[0] = (uint8_t)i;
        PQ_CHECK_RC(noxtls_hss_sign(&g_key, g_msg, 1U, g_sig, (uint32_t)sizeof(g_sig), &sig_len),
                    NOXTLS_RETURN_SUCCESS, "state sign");
        g_persist_watch = NULL;
        PQ_CHECK(g_persist_calls == (i + 1U), "one persist per signature (reserve 1)");
        PQ_CHECK(g_persist_last == (uint64_t)(i + 1U), "persisted counter = index + 1");
        PQ_CHECK(lms_t_get32(g_sig) == i, "signature uses index i");
    }
    PQ_CHECK(g_persist_watch_bad == 0U, "state persisted before any signature byte was written");

    /* persistence failure: no signature, no state change */
    g_persist_rc = NOXTLS_RETURN_TIMEOUT;
    (void)memset(g_sig, 0xEE, 200U);
    sig_len = 123U;
    PQ_CHECK_RC(noxtls_hss_sign(&g_key, g_msg, 1U, g_sig, (uint32_t)sizeof(g_sig), &sig_len),
                NOXTLS_RETURN_TIMEOUT, "persist failure propagates");
    PQ_CHECK(sig_len == 0U, "no signature length on persist failure");
    PQ_CHECK((g_sig[0] == 0xEEU) && (g_sig[199] == 0xEEU), "output untouched on persist failure");
    PQ_CHECK(noxtls_hss_key_remaining(&g_key) == 29U, "remaining unchanged on persist failure");
    PQ_CHECK_RC(noxtls_hss_key_reserve(&g_key, 4U), NOXTLS_RETURN_TIMEOUT, "explicit reserve failure");
    g_persist_rc = NOXTLS_RETURN_SUCCESS;
    PQ_CHECK_RC(noxtls_hss_sign(&g_key, g_msg, 1U, g_sig, (uint32_t)sizeof(g_sig), &sig_len),
                NOXTLS_RETURN_SUCCESS, "sign after persist recovers");
    PQ_CHECK(lms_t_get32(g_sig) == 3U, "index 3 was not burned by the failed persist");

    /* reservations */
    calls = g_persist_calls;
    PQ_CHECK_RC(noxtls_hss_key_set_reserve(&g_key, 5U), NOXTLS_RETURN_SUCCESS, "set reserve");
    for(i = 0U; i < 10U; i += 1U) {
        PQ_CHECK_RC(noxtls_hss_sign(&g_key, g_msg, 1U, g_sig, (uint32_t)sizeof(g_sig), &sig_len),
                    NOXTLS_RETURN_SUCCESS, "reserved sign");
    }
    PQ_CHECK(g_persist_calls == (calls + 2U), "reserve 5: two persists for ten signatures");
    PQ_CHECK(g_persist_last == 14U, "persisted reservation end");
    PQ_CHECK_RC(noxtls_hss_key_reserve(&g_key, 3U), NOXTLS_RETURN_SUCCESS, "explicit reserve");
    PQ_CHECK(g_persist_last == 17U, "explicit reserve persisted");
    PQ_CHECK_RC(noxtls_hss_key_reserve(&g_key, 0U), NOXTLS_RETURN_INVALID_PARAM, "reserve 0");
    PQ_CHECK_RC(noxtls_hss_key_set_reserve(&g_key, 0U), NOXTLS_RETURN_INVALID_PARAM, "set reserve 0");
    PQ_CHECK(noxtls_hss_key_remaining(&g_key) == 18U, "remaining after 14 signatures");
    {
        uint32_t len = 0U;
        PQ_CHECK_RC(noxtls_hss_key_public_key(&g_key, g_pk2, (uint32_t)sizeof(g_pk2), &len), NOXTLS_RETURN_SUCCESS,
                    "key public key");
        PQ_CHECK((len == 48U) && (memcmp(g_pk2, g_pk, 48U) == 0), "key public key matches keygen");
        PQ_CHECK_RC(noxtls_hss_key_public_key(&g_key, g_pk2, 10U, &len), NOXTLS_RETURN_INVALID_PARAM, "short pk buf");
    }
    PQ_CHECK_RC(noxtls_hss_sign(&g_key, g_msg, 1U, g_sig, 100U, &sig_len), NOXTLS_RETURN_INVALID_PARAM,
                "short signature buffer");
    PQ_CHECK(noxtls_hss_key_remaining(&g_key) == 18U, "short buffer does not consume an index");
    noxtls_hss_key_free(&g_key);

    /* reload from "flash": continues at the persisted counter (skips reserved) */
    PQ_CHECK_RC(lms_t_load(&g_key, g_flash, ws, 0U, 0U), NOXTLS_RETURN_SUCCESS, "reload from flash");
    PQ_CHECK(noxtls_hss_key_remaining(&g_key) == 15U, "reload skips reserved indices");
    PQ_CHECK_RC(noxtls_hss_key_set_reserve(&g_key, 100U), NOXTLS_RETURN_SUCCESS, "reserve beyond end");
    for(i = 17U; i < 32U; i += 1U) {
        PQ_CHECK_RC(noxtls_hss_sign(&g_key, g_msg, 1U, g_sig, (uint32_t)sizeof(g_sig), &sig_len),
                    NOXTLS_RETURN_SUCCESS, "sign to exhaustion");
        PQ_CHECK(lms_t_get32(g_sig) == i, "index after reload");
    }
    PQ_CHECK(g_persist_last == 32U, "reservation clamped to the key size");
    PQ_CHECK(noxtls_hss_key_remaining(&g_key) == 0U, "exhausted");
    PQ_CHECK_RC(noxtls_hss_sign(&g_key, g_msg, 1U, g_sig, (uint32_t)sizeof(g_sig), &sig_len),
                NOXTLS_RETURN_KEY_EXHAUSTED, "exhausted key refuses to sign");
    PQ_CHECK_RC(noxtls_hss_key_reserve(&g_key, 1U), NOXTLS_RETURN_KEY_EXHAUSTED, "exhausted reserve");
    noxtls_hss_key_free(&g_key);
    PQ_CHECK_RC(lms_t_load(&g_key, g_flash, ws, 0U, 0U), NOXTLS_RETURN_SUCCESS, "load exhausted key");
    PQ_CHECK_RC(noxtls_hss_sign(&g_key, g_msg, 1U, g_sig, (uint32_t)sizeof(g_sig), &sig_len),
                NOXTLS_RETURN_KEY_EXHAUSTED, "loaded exhausted key refuses to sign");
    noxtls_hss_key_free(&g_key);
    noxtls_hss_key_free(NULL);
    PQ_CHECK(noxtls_hss_key_remaining(NULL) == 0U, "remaining NULL");
    PQ_CHECK_RC(noxtls_hss_key_reserve(NULL, 1U), NOXTLS_RETURN_NULL, "reserve NULL");
    PQ_CHECK_RC(noxtls_hss_key_set_reserve(NULL, 1U), NOXTLS_RETURN_NULL, "set reserve NULL");
    PQ_CHECK_RC(noxtls_hss_key_reserve(&g_key, 1U), NOXTLS_RETURN_NOT_INITIALIZED, "reserve freed key");
    PQ_CHECK_RC(noxtls_hss_key_set_reserve(&g_key, 1U), NOXTLS_RETURN_NOT_INITIALIZED, "set reserve freed key");
    PQ_CHECK_RC(noxtls_hss_sign(NULL, g_msg, 1U, g_sig, 10U, &sig_len), NOXTLS_RETURN_NULL, "sign NULL");
    PQ_CHECK_RC(noxtls_hss_key_public_key(NULL, g_pk2, 10U, &sig_len), NOXTLS_RETURN_NULL, "pk NULL");
    PQ_CHECK_RC(noxtls_hss_key_public_key(&g_key, g_pk2, 10U, &sig_len), NOXTLS_RETURN_NOT_INITIALIZED, "pk freed");
}

/* HSS lower-tree rollover, workspace reuse, rollback detection, self-check. */
static void lms_t_state_hss(void)
{
    noxtls_hss_params_t p;
    uint32_t sig_len = 0U;
    uint32_t pk_len = 0U;
    uint32_t i = 0U;
    uint8_t *ws = lms_t_ws();
    uint8_t d[32];

    lms_t_params1(&p, NOXTLS_LMS_FORMAT_HSS, 3U, NOXTLS_LMS_TYPE_SHA256_M24_H5, NOXTLS_LMOTS_TYPE_SHA256_N24_W4);
    lms_t_seed("state-hss", 0U);
    PQ_CHECK_RC(noxtls_hss_keygen(&p, g_seed, g_id, g_pk, (uint32_t)sizeof(g_pk), g_sk, (uint32_t)sizeof(g_sk)),
                NOXTLS_RETURN_SUCCESS, "hss keygen");
    pk_len = noxtls_hss_public_key_len(&p);
    /* start just before the level-1 tree rolls over (index 1024 = 1 << 10) */
    lms_t_set_counter(g_sk, 1020U);
    PQ_CHECK_RC(lms_t_load(&g_key, g_sk, ws, 2U, NOXTLS_HSS_KEY_FAULT_HARDENING), NOXTLS_RETURN_SUCCESS,
                "hss load at 1020");
    for(i = 0U; i < 8U; i += 1U) {
        g_msg[0] = (uint8_t)i;
        PQ_CHECK_RC(noxtls_hss_sign(&g_key, g_msg, 1U, g_sig, (uint32_t)sizeof(g_sig), &sig_len),
                    NOXTLS_RETURN_SUCCESS, "hss sign across level-1 rollover");
        PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, 1U, g_sig, sig_len),
                    NOXTLS_RETURN_SUCCESS, "hss verify across rollover");
        PQ_CHECK(lms_t_get32(&g_sig[4]) == ((1020U + i) >> 10U), "level-0 leaf index");
    }
    PQ_CHECK(g_persist_last == 1028U, "hss counter persisted");
    (void)memcpy(g_sk_old, g_flash, sizeof(g_sk_old));     /* counter 1028 */
    for(i = 0U; i < 3U; i += 1U) {
        PQ_CHECK_RC(noxtls_hss_sign(&g_key, g_msg, 1U, g_sig, (uint32_t)sizeof(g_sig), &sig_len),
                    NOXTLS_RETURN_SUCCESS, "hss sign 2");
    }
    lms_t_sha256(g_sig, sig_len, d);                       /* signature at 1030 */
    noxtls_hss_key_free(&g_key);                           /* workspace stays in ws (public data) */

    /* rollback: an older blob with a newer workspace is refused */
    PQ_CHECK_RC(lms_t_load(&g_key, g_sk_old, ws, 2U, NOXTLS_HSS_LOAD_REUSE_WORKSPACE), NOXTLS_RETURN_BAD_DATA,
                "state rollback detected");
    /* reuse: same blob + workspace continues (counter 1031) */
    PQ_CHECK_RC(lms_t_load(&g_key, g_flash, ws, 2U, 0U), NOXTLS_RETURN_SUCCESS, "rebuild after refused load");
    noxtls_hss_key_free(&g_key);
    PQ_CHECK_RC(lms_t_load(&g_key, g_flash, ws, 2U, NOXTLS_HSS_LOAD_REUSE_WORKSPACE), NOXTLS_RETURN_SUCCESS,
                "workspace reuse");
    PQ_CHECK_RC(noxtls_hss_key_reserve(&g_key, 6U), NOXTLS_RETURN_SUCCESS, "reserve 6");
    PQ_CHECK_RC(noxtls_hss_sign(&g_key, g_msg, 1U, g_sig, (uint32_t)sizeof(g_sig), &sig_len),
                NOXTLS_RETURN_SUCCESS, "sign with reused workspace");
    PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, 1U, g_sig, sig_len),
                NOXTLS_RETURN_SUCCESS, "verify with reused workspace");
    noxtls_hss_key_free(&g_key);
    /* reload with reuse after a reservation gap (workspace at 1032, counter 1037) */
    PQ_CHECK(g_persist_last == 1037U, "reservation persisted");
    PQ_CHECK_RC(lms_t_load(&g_key, g_flash, ws, 2U, NOXTLS_HSS_LOAD_REUSE_WORKSPACE), NOXTLS_RETURN_SUCCESS,
                "workspace reuse with gap");
    PQ_CHECK_RC(noxtls_hss_sign(&g_key, g_msg, 1U, g_sig, (uint32_t)sizeof(g_sig), &sig_len),
                NOXTLS_RETURN_SUCCESS, "sign after gap");
    PQ_CHECK(lms_t_get32(&g_sig[4U + noxtls_lms_type_signature_len(p.lms_type[0], p.ots_type[0]) + 48U +
                                noxtls_lms_type_signature_len(p.lms_type[1], p.ots_type[1]) + 48U]) == (1037U & 31U),
             "bottom leaf index after gap");
    lms_t_sha256(g_sig, sig_len, d);
    noxtls_hss_key_free(&g_key);
    /* the same signature from a fresh rebuild at 1037 (separate workspace) */
    (void)memcpy(g_sk_old, g_sk, sizeof(g_sk_old));
    lms_t_set_counter(g_sk_old, 1037U);
    PQ_CHECK_RC(lms_t_load(&g_key2, g_sk_old, lms_t_ws2(), 5U, 0U), NOXTLS_RETURN_SUCCESS, "fresh load 1037");
    PQ_CHECK_RC(noxtls_hss_sign(&g_key2, g_msg, 1U, g_sig2, (uint32_t)sizeof(g_sig2), &sig_len),
                NOXTLS_RETURN_SUCCESS, "fresh sign 1037");
    {
        uint8_t d2[32];
        lms_t_sha256(g_sig2, sig_len, d2);
        PQ_CHECK_MEM(d2, d, 32U, "advanced workspace == rebuilt workspace");
    }
    noxtls_hss_key_free(&g_key2);

    /* self-check: a corrupted stored signed public key is caught, index burned */
    (void)memcpy(g_sk_old, g_sk, sizeof(g_sk_old));
    lms_t_set_counter(g_sk_old, 40U);
    PQ_CHECK_RC(lms_t_load(&g_key, g_sk_old, ws, 5U, 0U), NOXTLS_RETURN_SUCCESS, "load for corruption");
    {
        uint32_t ws_len = noxtls_hss_workspace_len(&p, 5U);
        ws[ws_len - 30U] ^= 0x01U; /* inside signed_pub_key[1] (stored public key) */
        (void)memset(g_sig, 0x11, 64U);
        PQ_CHECK_RC(noxtls_hss_sign(&g_key, g_msg, 1U, g_sig, (uint32_t)sizeof(g_sig), &sig_len),
                    NOXTLS_RETURN_FAILED, "self-check rejects corrupted state");
        PQ_CHECK((sig_len == 0U) && (g_sig[0] == 0U) && (g_sig[63] == 0U), "rejected signature wiped");
        PQ_CHECK_RC(noxtls_hss_sign(&g_key, g_msg, 1U, g_sig, (uint32_t)sizeof(g_sig), &sig_len),
                    NOXTLS_RETURN_SUCCESS, "rebuild after self-check failure");
        PQ_CHECK(lms_t_get32(&g_sig[sig_len - noxtls_lms_type_signature_len(p.lms_type[2], p.ots_type[2])]) == 9U,
                 "failed index 40 burned, signed with 41");
        PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, 1U, g_sig, sig_len),
                    NOXTLS_RETURN_SUCCESS, "signature after rebuild verifies");
    }
    noxtls_hss_key_free(&g_key);
    /* the same corruption without self-check yields an invalid signature (documented) */
    lms_t_set_counter(g_sk_old, 50U);
    PQ_CHECK_RC(lms_t_load(&g_key, g_sk_old, ws, 5U, NOXTLS_HSS_KEY_NO_SELF_VERIFY), NOXTLS_RETURN_SUCCESS,
                "load no self-verify");
    ws[noxtls_hss_workspace_len(&p, 5U) - 30U] ^= 0x01U;
    PQ_CHECK_RC(noxtls_hss_sign(&g_key, g_msg, 1U, g_sig, (uint32_t)sizeof(g_sig), &sig_len),
                NOXTLS_RETURN_SUCCESS, "sign without self-check");
    PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, g_pk, pk_len, g_msg, 1U, g_sig, sig_len),
                NOXTLS_RETURN_FAILED, "corrupted state gives an invalid signature");
    noxtls_hss_key_free(&g_key);

    /* library-allocated workspace */
    PQ_CHECK_RC(noxtls_hss_key_load(&g_key, g_sk, NOXTLS_HSS_PRIVATE_KEY_LEN, NULL, 0U, 0U, 0U, lms_t_persist, &g_tag),
                NOXTLS_RETURN_SUCCESS, "heap workspace");
    PQ_CHECK_RC(noxtls_hss_sign(&g_key, g_msg, 1U, g_sig, (uint32_t)sizeof(g_sig), &sig_len),
                NOXTLS_RETURN_SUCCESS, "sign heap workspace");
    noxtls_hss_key_free(&g_key);
}

/* ---- legacy preset API ---------------------------------------------------- */

static void lms_t_legacy(void)
{
    noxtls_hss_params_t p;
    uint32_t sig_len = 0U;

    PQ_CHECK_RC(noxtls_lms_sign(NOXTLS_LMS_SHA256_M32_H5, g_sk, g_msg, 1U, g_sig, &sig_len),
                NOXTLS_RETURN_NOT_SUPPORTED, "stateless sign fails closed");
    PQ_CHECK_RC(noxtls_lms_keygen(NOXTLS_LMS_SHA256_M32_H5, g_pk, 56U, g_sk, NOXTLS_HSS_PRIVATE_KEY_LEN),
                NOXTLS_RETURN_SUCCESS, "legacy keygen (DRBG)");
    PQ_CHECK_RC(noxtls_lms_keygen(NOXTLS_LMS_SHA256_M32_H5, g_pk, 55U, g_sk, NOXTLS_HSS_PRIVATE_KEY_LEN),
                NOXTLS_RETURN_INVALID_PARAM, "legacy keygen pk len");
    PQ_CHECK_RC(noxtls_lms_keygen(NOXTLS_LMS_NONE, g_pk, 56U, g_sk, NOXTLS_HSS_PRIVATE_KEY_LEN),
                NOXTLS_RETURN_INVALID_PARAM, "legacy keygen bad preset");
    PQ_CHECK_RC(noxtls_lms_keygen(NOXTLS_LMS_SHA256_M32_H5, NULL, 56U, g_sk, NOXTLS_HSS_PRIVATE_KEY_LEN),
                NOXTLS_RETURN_NULL, "legacy keygen NULL");
    PQ_CHECK_RC(lms_t_load(&g_key, g_sk, lms_t_ws(), 0U, 0U), NOXTLS_RETURN_SUCCESS, "legacy load");
    PQ_CHECK_RC(noxtls_hss_sign(&g_key, g_msg, 5U, g_sig, (uint32_t)sizeof(g_sig), &sig_len),
                NOXTLS_RETURN_SUCCESS, "legacy key sign");
    noxtls_hss_key_free(&g_key);
    PQ_CHECK_RC(noxtls_lms_verify(NOXTLS_LMS_SHA256_M32_H5, g_pk, g_msg, 5U, g_sig, sig_len),
                NOXTLS_RETURN_SUCCESS, "legacy verify");
    PQ_CHECK_RC(noxtls_lms_verify(NOXTLS_LMS_SHA256_M32_H5, g_pk, g_msg, 4U, g_sig, sig_len),
                NOXTLS_RETURN_FAILED, "legacy verify wrong message");
    PQ_CHECK_RC(noxtls_lms_verify(NOXTLS_LMS_SHA256_M32_H10, g_pk, g_msg, 5U, g_sig, sig_len),
                NOXTLS_RETURN_INVALID_PARAM, "legacy verify wrong preset");
    PQ_CHECK_RC(noxtls_lms_verify(NOXTLS_LMS_SHA256_M32_H5, g_pk, g_msg, 5U, g_sig, sig_len - 1U),
                NOXTLS_RETURN_FAILED, "legacy verify length");
    PQ_CHECK_RC(noxtls_lms_verify(NOXTLS_LMS_NONE, g_pk, g_msg, 5U, g_sig, sig_len),
                NOXTLS_RETURN_INVALID_PARAM, "legacy verify bad preset");
    PQ_CHECK_RC(noxtls_lms_verify(NOXTLS_LMS_SHA256_M32_H5, NULL, g_msg, 5U, g_sig, sig_len),
                NOXTLS_RETURN_NULL, "legacy verify NULL");
    /* HSS preset: RFC 8554 TC1 is H5/H5, not the H10/H10 preset */
    lms_t_unhex(g_lms_kat_hss[0].pk, g_pk, g_lms_kat_hss[0].pk_len);
    PQ_CHECK_RC(noxtls_lms_verify(NOXTLS_HSS_SHA256_M32_H10_D2, g_pk, g_msg, 5U, g_sig, 2964U),
                NOXTLS_RETURN_INVALID_PARAM, "legacy HSS preset type check");
    PQ_CHECK_RC(noxtls_hss_params_from_preset(NOXTLS_HSS_SHA256_M32_H15_D2, &p), NOXTLS_RETURN_SUCCESS, "preset");
    PQ_CHECK((p.levels == 2U) && (p.lms_type[1] == NOXTLS_LMS_TYPE_SHA256_M32_H15), "preset levels");
    PQ_CHECK_RC(noxtls_hss_params_from_preset(NOXTLS_LMS_SHA256_M32_H5, NULL), NOXTLS_RETURN_NULL, "preset NULL");
    /* HSS preset key (L=2, H10/W8): signatures whose lower level uses other types fail */
    (void)memset(g_pk, 0, sizeof(g_pk));
    g_pk[3] = 2U;
    g_pk[7] = (uint8_t)NOXTLS_LMS_TYPE_SHA256_M32_H10;
    g_pk[11] = (uint8_t)NOXTLS_LMOTS_TYPE_SHA256_N32_W8;
    (void)memset(g_sig, 0, 3000U);
    PQ_CHECK_RC(noxtls_lms_verify(NOXTLS_HSS_SHA256_M32_H10_D2, g_pk, g_msg, 5U, g_sig, 2964U),
                NOXTLS_RETURN_FAILED, "legacy HSS zero signature");
    g_sig[4U + 1452U + 3U] = (uint8_t)NOXTLS_LMS_TYPE_SHA256_M32_H10;
    g_sig[4U + 1452U + 7U] = (uint8_t)NOXTLS_LMOTS_TYPE_SHA256_N32_W8;
    PQ_CHECK_RC(noxtls_lms_verify(NOXTLS_HSS_SHA256_M32_H10_D2, g_pk, g_msg, 5U, g_sig, 2964U),
                NOXTLS_RETURN_FAILED, "legacy HSS invalid signature with preset types");
    lms_t_params1(&p, NOXTLS_LMS_FORMAT_HSS, 2U, NOXTLS_LMS_TYPE_SHA256_M32_H10, NOXTLS_LMOTS_TYPE_SHA256_N32_W8);
    PQ_CHECK_RC(noxtls_hss_keygen(NULL, NULL, NULL, g_pk, 60U, g_sk, NOXTLS_HSS_PRIVATE_KEY_LEN), NOXTLS_RETURN_NULL,
                "keygen NULL");
    PQ_CHECK_RC(noxtls_hss_keygen(&p, NULL, NULL, g_pk, 10U, g_sk, NOXTLS_HSS_PRIVATE_KEY_LEN),
                NOXTLS_RETURN_INVALID_PARAM, "keygen short pk");
    p.levels = 0U;
    PQ_CHECK_RC(noxtls_hss_keygen(&p, NULL, NULL, g_pk, 60U, g_sk, NOXTLS_HSS_PRIVATE_KEY_LEN),
                NOXTLS_RETURN_INVALID_PARAM, "keygen bad params");
    PQ_CHECK(noxtls_lms_public_key_len(NOXTLS_LMS_NONE) == 0U, "legacy pk len invalid");
    PQ_CHECK(noxtls_lms_secret_key_len(NOXTLS_LMS_NONE) == 0U, "legacy sk len invalid");
    PQ_CHECK(noxtls_lms_signature_len(NOXTLS_LMS_NONE) == 0U, "legacy sig len invalid");
    PQ_CHECK_RC(noxtls_hss_private_key_info(NULL, 0U, NULL, NULL, NULL), NOXTLS_RETURN_NULL, "info NULL");
}

int noxtls_pq_test_lms(void)
{
    pq_test_begin("lms (RFC 8554 / SP 800-208 LMS, HSS)");
    lms_t_sizes();
    lms_t_hss_vectors();
    lms_t_tree_vectors();
    lms_t_acvp();
    lms_t_roundtrips();
    lms_t_traversal();
    lms_t_state();
    lms_t_state_hss();
    lms_t_legacy();
    return pq_test_end("lms (RFC 8554 / SP 800-208 LMS, HSS)");
}

#else

int noxtls_pq_test_lms(void)
{
    return 0;
}

#endif /* NOXTLS_FEATURE_LMS_HSS */

NOXTLS_PQ_TEST_MAIN(noxtls_pq_test_lms)
