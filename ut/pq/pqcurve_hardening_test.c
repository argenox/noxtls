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
* File:    pqcurve_hardening_test.c
* Summary: Regression tests for post-quantum input and state hardening:
*          length-checked ML-KEM encaps/decaps, Falcon rejection of a
*          decodable non-NTRU secret key, and the LMS/HSS and XMSS guard
*          against a second sign while a persist callback is running.
*
*****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "pq_test.h"

#if NOXTLS_FEATURE_ML_KEM
#include "pkc/mlkem/noxtls_mlkem.h"
#endif
#if NOXTLS_FEATURE_FALCON
#include "pkc/falcon/noxtls_falcon.h"
#endif
#if NOXTLS_FEATURE_LMS_HSS
#include "pkc/lms/noxtls_lms.h"
#endif
#if NOXTLS_FEATURE_XMSS
#include "pkc/xmss/noxtls_xmss.h"
#endif

/* ---- ML-KEM: explicit-length encaps / decaps ------------------------------ */

#if NOXTLS_FEATURE_ML_KEM
static uint8_t g_kem_pk[NOXTLS_MLKEM_MAX_PUBLIC_KEY_LEN];
static uint8_t g_kem_sk[NOXTLS_MLKEM_MAX_SECRET_KEY_LEN];
static uint8_t g_kem_ct[NOXTLS_MLKEM_MAX_CIPHERTEXT_LEN];

static void hard_t_mlkem(void)
{
    static const noxtls_mlkem_param_t params[3] = { NOXTLS_MLKEM_512, NOXTLS_MLKEM_768, NOXTLS_MLKEM_1024 };
    uint8_t ss_a[NOXTLS_MLKEM_SHARED_SECRET_LEN];
    uint8_t ss_b[NOXTLS_MLKEM_SHARED_SECRET_LEN];
    uint32_t i = 0U;

    pq_test_rng_seed_label("pqcurve-mlkem", 0U);
    for(i = 0U; i < 3U; i += 1U) {
        noxtls_mlkem_param_t p = params[i];
        uint32_t pk_len = noxtls_mlkem_public_key_len(p);
        uint32_t ct_len = noxtls_mlkem_ciphertext_len(p);

        PQ_CHECK_RC(noxtls_mlkem_keygen(p, g_kem_pk, g_kem_sk), NOXTLS_RETURN_SUCCESS, "keygen");
        /* Short peer keys (including lengths inside the rho tail) are rejected. */
        PQ_CHECK_RC(noxtls_mlkem_encaps_ex(p, g_kem_pk, 0U, g_kem_ct, ss_a), NOXTLS_RETURN_BAD_DATA,
                    "encaps_ex empty key");
        PQ_CHECK_RC(noxtls_mlkem_encaps_ex(p, g_kem_pk, 32U, g_kem_ct, ss_a), NOXTLS_RETURN_BAD_DATA,
                    "encaps_ex 32-byte key");
        PQ_CHECK_RC(noxtls_mlkem_encaps_ex(p, g_kem_pk, pk_len - 1U, g_kem_ct, ss_a), NOXTLS_RETURN_BAD_DATA,
                    "encaps_ex key one byte short");
        PQ_CHECK_RC(noxtls_mlkem_encaps_ex(p, g_kem_pk, pk_len - 16U, g_kem_ct, ss_a), NOXTLS_RETURN_BAD_DATA,
                    "encaps_ex key short inside rho");
        PQ_CHECK_RC(noxtls_mlkem_encaps_ex(p, g_kem_pk, pk_len + 1U, g_kem_ct, ss_a), NOXTLS_RETURN_BAD_DATA,
                    "encaps_ex key one byte long");
        PQ_CHECK_RC(noxtls_mlkem_encaps_ex(p, g_kem_pk, pk_len, g_kem_ct, ss_a), NOXTLS_RETURN_SUCCESS,
                    "encaps_ex exact key");
        /* Short ciphertexts are rejected before decapsulation reads them. */
        PQ_CHECK_RC(noxtls_mlkem_decaps_ex(p, g_kem_pk, g_kem_sk, g_kem_ct, 0U, ss_b), NOXTLS_RETURN_BAD_DATA,
                    "decaps_ex empty ct");
        PQ_CHECK_RC(noxtls_mlkem_decaps_ex(p, g_kem_pk, g_kem_sk, g_kem_ct, ct_len - 1U, ss_b),
                    NOXTLS_RETURN_BAD_DATA, "decaps_ex ct one byte short");
        PQ_CHECK_RC(noxtls_mlkem_decaps_ex(p, g_kem_pk, g_kem_sk, g_kem_ct, ct_len + 1U, ss_b),
                    NOXTLS_RETURN_BAD_DATA, "decaps_ex ct one byte long");
        PQ_CHECK_RC(noxtls_mlkem_decaps_ex(p, g_kem_pk, g_kem_sk, g_kem_ct, ct_len, ss_b), NOXTLS_RETURN_SUCCESS,
                    "decaps_ex exact ct");
        PQ_CHECK_MEM(ss_b, ss_a, NOXTLS_MLKEM_SHARED_SECRET_LEN, "encaps_ex/decaps_ex shared secret");
    }
    PQ_CHECK_RC(noxtls_mlkem_encaps_ex(NOXTLS_MLKEM_768, NULL, 1184U, g_kem_ct, ss_a), NOXTLS_RETURN_NULL,
                "encaps_ex NULL key");
    PQ_CHECK_RC(noxtls_mlkem_encaps_ex(NOXTLS_MLKEM_NONE, g_kem_pk, 1184U, g_kem_ct, ss_a),
                NOXTLS_RETURN_INVALID_PARAM, "encaps_ex bad param");
    PQ_CHECK_RC(noxtls_mlkem_decaps_ex(NOXTLS_MLKEM_768, g_kem_pk, g_kem_sk, NULL, 1088U, ss_b), NOXTLS_RETURN_NULL,
                "decaps_ex NULL ct");
    PQ_CHECK_RC(noxtls_mlkem_decaps_ex(NOXTLS_MLKEM_NONE, g_kem_pk, g_kem_sk, g_kem_ct, 1088U, ss_b),
                NOXTLS_RETURN_INVALID_PARAM, "decaps_ex bad param");
    pq_test_rng_restore();
}
#endif

/* ---- Falcon: decodable but non-NTRU secret key ---------------------------- */

#if NOXTLS_FEATURE_FALCON
static uint8_t g_fal_sk[NOXTLS_FALCON_MAX_SECRET_KEY_LEN];
static uint8_t g_fal_sig[NOXTLS_FALCON_MAX_SIGNATURE_LEN];

static void hard_t_falcon(void)
{
    static const uint8_t msg[4] = { 0x01U, 0x02U, 0x03U, 0x04U };
    uint32_t sig_len = (uint32_t)sizeof(g_fal_sig);

    (void)memset(g_fal_sig, 0xA5, sizeof(g_fal_sig));
    /* Header 0x50 | logn, then f = g = F = -1 (all-ones fields): decodes and
     * G = g*F/f = -1 fits, but f*G - g*F = 0 != q (singular Gram matrix).
     * Before the fix SamplerZ looped practically forever on this key. */
    (void)memset(g_fal_sk, 0xFF, sizeof(g_fal_sk));
    g_fal_sk[0] = 0x59U;
    pq_test_rng_seed_label("pqcurve-falcon", 0U);
    PQ_CHECK_RC(noxtls_falcon_sign(NOXTLS_FALCON_512, g_fal_sk, msg, (uint32_t)sizeof(msg), g_fal_sig, &sig_len),
                NOXTLS_RETURN_BAD_DATA, "Falcon-512 all-ones key rejected");
    PQ_CHECK((g_fal_sig[0] == 0U) && (g_fal_sig[1] == 0U), "Falcon-512 output wiped on rejection");
    pq_test_rng_restore();
}
#endif

/* ---- LMS/HSS: sign re-entered from the persist callback ------------------- */

#if NOXTLS_FEATURE_LMS_HSS
#define HARD_T_LMS_WS_WORDS (65536U / 4U)
static uint32_t g_lms_ws[HARD_T_LMS_WS_WORDS];
static uint8_t g_lms_pk[NOXTLS_HSS_MAX_PUBLIC_KEY_LEN];
static uint8_t g_lms_sk[NOXTLS_HSS_PRIVATE_KEY_LEN];
static uint8_t g_lms_sig[4096];
static uint8_t g_lms_sig_inner[4096];
static noxtls_hss_key_t g_lms_key;
static uint32_t g_lms_persist_calls = 0U;
static noxtls_return_t g_lms_inner_sign_rc = NOXTLS_RETURN_SUCCESS;
static noxtls_return_t g_lms_inner_reserve_rc = NOXTLS_RETURN_SUCCESS;
static uint32_t g_lms_inner_sig_len = 1U;

static noxtls_return_t hard_t_lms_persist(void *user, const uint8_t *sk, uint32_t len)
{
    static const uint8_t inner_msg[3] = { 0xAAU, 0xBBU, 0xCCU };

    (void)user;
    (void)sk;
    (void)len;
    g_lms_persist_calls += 1U;
    if(g_lms_persist_calls == 1U) {
        /* Contract violation: sign and reserve on the same key while persisting. */
        g_lms_inner_sign_rc = noxtls_hss_sign(&g_lms_key, inner_msg, (uint32_t)sizeof(inner_msg),
                                              g_lms_sig_inner, (uint32_t)sizeof(g_lms_sig_inner),
                                              &g_lms_inner_sig_len);
        g_lms_inner_reserve_rc = noxtls_hss_key_reserve(&g_lms_key, 4U);
    }
    return NOXTLS_RETURN_SUCCESS;
}

static void hard_t_lms(void)
{
    static const uint8_t msg[3] = { 0x11U, 0x22U, 0x33U };
    noxtls_hss_params_t params;
    uint8_t seed[32];
    uint8_t id[16];
    uint32_t sig_len = 0U;
    uint32_t pk_len = 0U;
    uint64_t before = 0U;

    (void)memset(&params, 0, sizeof(params));
    params.format = NOXTLS_LMS_FORMAT_LMS;
    params.levels = 1U;
    params.lms_type[0] = NOXTLS_LMS_TYPE_SHA256_M32_H5;
    params.ots_type[0] = NOXTLS_LMOTS_TYPE_SHA256_N32_W4;
    pk_len = noxtls_hss_public_key_len(&params);
    pq_test_rng_seed_label("pqcurve-lms", 0U);
    pq_test_rng_bytes(seed, (uint32_t)sizeof(seed));
    pq_test_rng_bytes(id, (uint32_t)sizeof(id));
    PQ_CHECK_RC(noxtls_hss_keygen(&params, seed, id, g_lms_pk, pk_len, g_lms_sk, (uint32_t)sizeof(g_lms_sk)),
                NOXTLS_RETURN_SUCCESS, "LMS keygen");
    PQ_CHECK_RC(noxtls_hss_key_load(&g_lms_key, g_lms_sk, NOXTLS_HSS_PRIVATE_KEY_LEN,
                                    (uint8_t *)(void *)g_lms_ws, (uint32_t)sizeof(g_lms_ws), 0U, 0U,
                                    hard_t_lms_persist, NULL),
                NOXTLS_RETURN_SUCCESS, "LMS key load");
    before = noxtls_hss_key_remaining(&g_lms_key);
    PQ_CHECK_RC(noxtls_hss_sign(&g_lms_key, msg, (uint32_t)sizeof(msg), g_lms_sig, (uint32_t)sizeof(g_lms_sig),
                                &sig_len),
                NOXTLS_RETURN_SUCCESS, "LMS outer sign");
    PQ_CHECK(g_lms_persist_calls == 1U, "LMS persisted once");
    PQ_CHECK_RC(g_lms_inner_sign_rc, NOXTLS_RETURN_FAILED, "LMS sign inside persist refused");
    PQ_CHECK(g_lms_inner_sig_len == 0U, "LMS refused sign reports no signature");
    PQ_CHECK_RC(g_lms_inner_reserve_rc, NOXTLS_RETURN_FAILED, "LMS reserve inside persist refused");
    PQ_CHECK(noxtls_hss_key_remaining(&g_lms_key) == (before - 1U), "LMS exactly one index consumed");
    PQ_CHECK_RC(noxtls_hss_verify(NOXTLS_LMS_FORMAT_LMS, g_lms_pk, pk_len, msg, (uint32_t)sizeof(msg),
                                  g_lms_sig, sig_len),
                NOXTLS_RETURN_SUCCESS, "LMS outer signature verifies");
    /* The guard is released afterwards: a normal second sign works. */
    PQ_CHECK_RC(noxtls_hss_sign(&g_lms_key, msg, (uint32_t)sizeof(msg), g_lms_sig, (uint32_t)sizeof(g_lms_sig),
                                &sig_len),
                NOXTLS_RETURN_SUCCESS, "LMS sign after guard release");
    noxtls_hss_key_free(&g_lms_key);
    pq_test_rng_restore();
}
#endif

/* ---- XMSS: sign re-entered from the persist callback ---------------------- */

#if NOXTLS_FEATURE_XMSS
static uint8_t g_xmss_pk[256];
static uint8_t g_xmss_sk[512];
static uint8_t g_xmss_sig[24000];
static uint8_t g_xmss_sig_inner[24000];
static noxtls_xmss_signer_t g_xmss_signer;
static uint32_t g_xmss_persist_calls = 0U;
static noxtls_return_t g_xmss_inner_rc = NOXTLS_RETURN_SUCCESS;
static uint32_t g_xmss_inner_sig_len = 1U;

static noxtls_return_t hard_t_xmss_persist(void *user, const uint8_t *sk, uint32_t len)
{
    static const uint8_t inner_msg[3] = { 0xAAU, 0xBBU, 0xCCU };

    (void)user;
    (void)sk;
    (void)len;
    g_xmss_persist_calls += 1U;
    if(g_xmss_persist_calls == 1U) {
        g_xmss_inner_sig_len = (uint32_t)sizeof(g_xmss_sig_inner);
        g_xmss_inner_rc = noxtls_xmss_sign_stateful(&g_xmss_signer, inner_msg, (uint32_t)sizeof(inner_msg),
                                                    g_xmss_sig_inner, &g_xmss_inner_sig_len);
    }
    return NOXTLS_RETURN_SUCCESS;
}

static void hard_t_xmss(void)
{
    static const uint8_t msg[3] = { 0x11U, 0x22U, 0x33U };
    const noxtls_xmss_param_t param = NOXTLS_XMSSMT_SHA2_20_4_256;
    noxtls_xmss_param_info_t info;
    uint8_t seed[96];
    uint32_t sig_len = 0U;
    uint64_t rem_before = 0U;
    uint64_t rem_after = 0U;

    PQ_CHECK_RC(noxtls_xmss_get_param_info(param, &info), NOXTLS_RETURN_SUCCESS, "XMSS param info");
    PQ_CHECK((info.secret_key_len <= sizeof(g_xmss_sk)) && (info.public_key_len <= sizeof(g_xmss_pk)) &&
             (info.signature_len <= sizeof(g_xmss_sig)), "XMSS test buffers large enough");
    pq_test_rng_seed_label("pqcurve-xmss", 0U);
    pq_test_rng_bytes(seed, 3U * info.n);
    PQ_CHECK_RC(noxtls_xmss_keygen_from_seed(param, seed, 3U * info.n, g_xmss_pk, (uint32_t)sizeof(g_xmss_pk),
                                             g_xmss_sk, (uint32_t)sizeof(g_xmss_sk)),
                NOXTLS_RETURN_SUCCESS, "XMSS keygen");
    PQ_CHECK_RC(noxtls_xmss_signer_init(&g_xmss_signer, param, g_xmss_sk, info.secret_key_len,
                                        hard_t_xmss_persist, NULL, 1U),
                NOXTLS_RETURN_SUCCESS, "XMSS signer init");
    PQ_CHECK_RC(noxtls_xmss_signer_remaining(&g_xmss_signer, &rem_before), NOXTLS_RETURN_SUCCESS, "remaining");
    sig_len = (uint32_t)sizeof(g_xmss_sig);
    PQ_CHECK_RC(noxtls_xmss_sign_stateful(&g_xmss_signer, msg, (uint32_t)sizeof(msg), g_xmss_sig, &sig_len),
                NOXTLS_RETURN_SUCCESS, "XMSS outer sign");
    PQ_CHECK(g_xmss_persist_calls == 1U, "XMSS persisted once");
    PQ_CHECK_RC(g_xmss_inner_rc, NOXTLS_RETURN_FAILED, "XMSS sign inside persist refused");
    PQ_CHECK(g_xmss_inner_sig_len == 0U, "XMSS refused sign reports no signature");
    PQ_CHECK_RC(noxtls_xmss_signer_remaining(&g_xmss_signer, &rem_after), NOXTLS_RETURN_SUCCESS, "remaining");
    PQ_CHECK(rem_after == (rem_before - 1U), "XMSS exactly one index consumed");
    PQ_CHECK_RC(noxtls_xmss_verify(param, g_xmss_pk, msg, (uint32_t)sizeof(msg),
                                   g_xmss_sig, sig_len),
                NOXTLS_RETURN_SUCCESS, "XMSS outer signature verifies");
    noxtls_xmss_signer_free(&g_xmss_signer);
    pq_test_rng_restore();
}
#endif

int noxtls_pq_test_pqcurve_hardening(void)
{
    pq_test_begin("pqcurve_hardening");
#if NOXTLS_FEATURE_ML_KEM
    hard_t_mlkem();
#endif
#if NOXTLS_FEATURE_FALCON
    hard_t_falcon();
#endif
#if NOXTLS_FEATURE_LMS_HSS
    hard_t_lms();
#endif
#if NOXTLS_FEATURE_XMSS
    hard_t_xmss();
#endif
    return pq_test_end("pqcurve_hardening");
}

NOXTLS_PQ_TEST_MAIN(noxtls_pq_test_pqcurve_hardening)
