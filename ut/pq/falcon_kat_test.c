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
* File:    falcon_kat_test.c
* Summary: Falcon-512/1024 known-answer, negative and round-trip tests.
*
*****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "pq_test.h"
#include "noxtls_config.h"
#include "drbg/noxtls_drbg.h"

/* Largest workspace used by the tests (Falcon-1024 key generation). */
#define FALCON_TEST_WS_BYTES 88072U
#include "pkc/falcon/noxtls_falcon.h"
#include "falcon_kat_vectors.h"

#if NOXTLS_FEATURE_FALCON

#include <math.h>
#include "pkc/falcon/noxtls_falcon_internal.h"

static uint8_t g_sig[NOXTLS_FALCON_MAX_SIGNATURE_LEN];
static uint8_t g_buf[NOXTLS_FALCON_MAX_SECRET_KEY_LEN]; /* >= max signature length */
static uint8_t g_pk[NOXTLS_FALCON_MAX_PUBLIC_KEY_LEN];
static uint8_t g_sk[NOXTLS_FALCON_MAX_SECRET_KEY_LEN];
static uint8_t g_msg[128];
/* Caller-supplied workspace (sized for Falcon-1024 key generation, the largest user). */
static uint64_t g_ws[(FALCON_TEST_WS_BYTES / 8U) + 1U];

/** Verify the official KAT signatures and a set of mutated variants. */
static void falcon_test_kat_verify(noxtls_falcon_param_t param,
                                   const falcon_kat_vector_t *kats,
                                   uint32_t count)
{
    uint32_t pk_len = noxtls_falcon_public_key_len(param);
    uint32_t sig_len = noxtls_falcon_signature_len(param);
    uint32_t i = 0U;

    for(i = 0U; i < count; i += 1U) {
        const falcon_kat_vector_t *v = &kats[i];

        PQ_CHECK_RC(noxtls_falcon_verify(param, v->pk, v->msg, v->msg_len, v->sig, sig_len),
                    NOXTLS_RETURN_SUCCESS, "KAT signature verifies");

        /* Tampered message. */
        (void)memcpy(g_msg, v->msg, v->msg_len);
        g_msg[0] ^= 0x01U;
        PQ_CHECK_RC(noxtls_falcon_verify(param, v->pk, g_msg, v->msg_len, v->sig, sig_len),
                    NOXTLS_RETURN_FAILED, "tampered message rejected");
        /* Truncated message. */
        PQ_CHECK_RC(noxtls_falcon_verify(param, v->pk, v->msg, v->msg_len - 1U, v->sig, sig_len),
                    NOXTLS_RETURN_FAILED, "truncated message rejected");

        /* Tampered salt byte. */
        (void)memcpy(g_buf, v->sig, sig_len);
        g_buf[5] ^= 0x80U;
        PQ_CHECK_RC(noxtls_falcon_verify(param, v->pk, v->msg, v->msg_len, g_buf, sig_len),
                    NOXTLS_RETURN_FAILED, "tampered salt rejected");
        /* Tampered s2 encoding (sign bit of the first coefficient). */
        (void)memcpy(g_buf, v->sig, sig_len);
        g_buf[41] ^= 0x80U;
        PQ_CHECK(noxtls_falcon_verify(param, v->pk, v->msg, v->msg_len, g_buf, sig_len) !=
                 NOXTLS_RETURN_SUCCESS, "tampered s2 rejected");
        /* Wrong header byte. */
        (void)memcpy(g_buf, v->sig, sig_len);
        g_buf[0] ^= 0x01U;
        PQ_CHECK_RC(noxtls_falcon_verify(param, v->pk, v->msg, v->msg_len, g_buf, sig_len),
                    NOXTLS_RETURN_BAD_DATA, "wrong signature header rejected");
        /* Non-zero padding byte. */
        (void)memcpy(g_buf, v->sig, sig_len);
        g_buf[sig_len - 1U] ^= 0x01U;
        PQ_CHECK_RC(noxtls_falcon_verify(param, v->pk, v->msg, v->msg_len, g_buf, sig_len),
                    NOXTLS_RETURN_BAD_DATA, "non-zero padding rejected");
        /* Wrong lengths. */
        PQ_CHECK_RC(noxtls_falcon_verify(param, v->pk, v->msg, v->msg_len, v->sig, sig_len - 1U),
                    NOXTLS_RETURN_BAD_DATA, "short signature rejected");

        /* Tampered public key coefficient. */
        (void)memcpy(g_pk, v->pk, pk_len);
        g_pk[100] ^= 0x04U;
        PQ_CHECK(noxtls_falcon_verify(param, g_pk, v->msg, v->msg_len, v->sig, sig_len) !=
                 NOXTLS_RETURN_SUCCESS, "tampered public key rejected");
        /* Wrong public-key header. */
        (void)memcpy(g_pk, v->pk, pk_len);
        g_pk[0] ^= 0x01U;
        PQ_CHECK_RC(noxtls_falcon_verify(param, g_pk, v->msg, v->msg_len, v->sig, sig_len),
                    NOXTLS_RETURN_BAD_DATA, "wrong public-key header rejected");
        /* Public-key coefficient >= q (first 14-bit value set to 0x3FFF). */
        (void)memcpy(g_pk, v->pk, pk_len);
        g_pk[1] = 0xFFU;
        g_pk[2] |= 0xFCU;
        PQ_CHECK_RC(noxtls_falcon_verify(param, g_pk, v->msg, v->msg_len, v->sig, sig_len),
                    NOXTLS_RETURN_BAD_DATA, "out-of-range public key rejected");
    }

    /* Signature of one vector does not verify under another key. */
    if(count >= 2U) {
        PQ_CHECK_RC(noxtls_falcon_verify(param, kats[1].pk, kats[0].msg, kats[0].msg_len,
                                         kats[0].sig, sig_len),
                    NOXTLS_RETURN_FAILED, "signature under foreign key rejected");
    }
}

/** Sign with the official KAT secret key under a seeded RNG and verify. */
static void falcon_test_kat_sign(noxtls_falcon_param_t param,
                                 const falcon_kat_vector_t *v,
                                 uint32_t rounds)
{
    uint32_t sig_len_max = noxtls_falcon_signature_len(param);
    uint32_t r = 0U;

    for(r = 0U; r < rounds; r += 1U) {
        uint32_t sig_len = (uint32_t)sizeof(g_sig);
        uint32_t msg_len = (r * 37U) % (uint32_t)sizeof(g_msg);
        uint32_t i = 0U;

        for(i = 0U; i < msg_len; i += 1U) {
            g_msg[i] = (uint8_t)(i * 13U + r);
        }
        pq_test_rng_seed_label("falcon-kat-sign", (param << 8U) | r);
        PQ_CHECK_RC(noxtls_falcon_sign(param, v->sk, g_msg, msg_len, g_sig, &sig_len),
                    NOXTLS_RETURN_SUCCESS, "sign with KAT secret key");
        PQ_CHECK(sig_len == sig_len_max, "padded signature length");
        PQ_CHECK_RC(noxtls_falcon_verify(param, v->pk, g_msg, msg_len, g_sig, sig_len),
                    NOXTLS_RETURN_SUCCESS, "own signature verifies under KAT public key");
        g_sig[sig_len / 2U] ^= 0x10U;
        PQ_CHECK(noxtls_falcon_verify(param, v->pk, g_msg, msg_len, g_sig, sig_len) !=
                 NOXTLS_RETURN_SUCCESS, "corrupted own signature rejected");
    }

    /* Argument validation. */
    {
        uint32_t small = sig_len_max - 1U;
        uint32_t sig_len = (uint32_t)sizeof(g_sig);

        PQ_CHECK_RC(noxtls_falcon_sign(param, v->sk, g_msg, 4U, g_sig, &small),
                    NOXTLS_RETURN_INVALID_BLOCK_SIZE, "undersized signature buffer");
        PQ_CHECK_RC(noxtls_falcon_sign(param, NULL, g_msg, 4U, g_sig, &sig_len),
                    NOXTLS_RETURN_NULL, "NULL secret key");
        PQ_CHECK_RC(noxtls_falcon_sign(param, v->sk, NULL, 4U, g_sig, &sig_len),
                    NOXTLS_RETURN_NULL, "NULL message with length");
        PQ_CHECK_RC(noxtls_falcon_sign(NOXTLS_FALCON_NONE, v->sk, g_msg, 4U, g_sig, &sig_len),
                    NOXTLS_RETURN_INVALID_PARAM, "invalid parameter set");
        (void)memcpy(g_buf, v->sk, noxtls_falcon_secret_key_len(param));
        g_buf[0] ^= 0x01U;
        PQ_CHECK_RC(noxtls_falcon_sign(param, g_buf, g_msg, 4U, g_sig, &sig_len),
                    NOXTLS_RETURN_BAD_DATA, "secret key with wrong header");
    }
}

/** Reproduce the official KAT signature from the replayed KAT DRBG outputs. */
static void falcon_test_kat_reproduce(noxtls_falcon_param_t param, const falcon_kat_vector_t *v)
{
    noxtls_falcon_param_spec_t spec;
    uint32_t comp_len = 0U;

    PQ_CHECK_RC(noxtls_falcon_internal_get_param_spec(param, &spec), NOXTLS_RETURN_SUCCESS, "spec");
    PQ_CHECK((uint32_t)sizeof(g_ws) >= noxtls_falcon_internal_sign_ws_len(spec.logn), "ws size");
    PQ_CHECK_RC(noxtls_falcon_internal_sign_seeded(&spec, v->sk, v->msg, v->msg_len, &v->sig[1],
                                                   v->sign_seed, 48U, g_buf, (uint32_t)sizeof(g_buf),
                                                   &comp_len, g_ws),
                NOXTLS_RETURN_SUCCESS, "seeded KAT signing");
    PQ_CHECK(comp_len == v->comp_len, "KAT compressed signature length");
    PQ_CHECK_MEM(g_buf, &v->sig[41], v->comp_len, "KAT signature reproduced bit-exactly");
}

/** Key generation round trips (seeded RNG), signing, verification and negatives. */
static void falcon_test_keygen_roundtrip(noxtls_falcon_param_t param, uint32_t keys, uint32_t use_ws)
{
    uint32_t pk_len = noxtls_falcon_public_key_len(param);
    uint32_t sk_len = noxtls_falcon_secret_key_len(param);
    uint32_t k = 0U;

    for(k = 0U; k < keys; k += 1U) {
        uint32_t sig_len = (uint32_t)sizeof(g_sig);
        uint32_t i = 0U;
        noxtls_return_t rc = NOXTLS_RETURN_FAILED;

        pq_test_rng_seed_label("falcon-keygen", (param << 8U) | k);
        if(use_ws != 0U) {
            rc = noxtls_falcon_keygen_ex(param, g_pk, pk_len, g_sk, sk_len, g_ws, (uint32_t)sizeof(g_ws));
        } else {
            uint32_t mark = pq_test_probe_begin();
            rc = noxtls_falcon_keygen(param, g_pk, pk_len, g_sk, sk_len);
            if(k == 0U) {
                pq_test_probe_end(mark, (param == NOXTLS_FALCON_512) ? "Falcon-512 keygen" : "Falcon-1024 keygen");
            }
        }
        PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "keygen");
        if(rc != NOXTLS_RETURN_SUCCESS) {
            continue;
        }
        PQ_CHECK(g_pk[0] == (uint8_t)((param == NOXTLS_FALCON_512) ? 9U : 10U), "pk header");
        PQ_CHECK(g_sk[0] == (uint8_t)((param == NOXTLS_FALCON_512) ? 0x59U : 0x5AU), "sk header");
        for(i = 0U; i < 57U; i += 1U) {
            g_msg[i] = (uint8_t)(k + i);
        }
        if(use_ws != 0U) {
            rc = noxtls_falcon_sign_ex(param, g_sk, g_msg, 57U, g_sig, &sig_len, g_ws, (uint32_t)sizeof(g_ws));
            PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "sign_ex with fresh key");
            rc = noxtls_falcon_verify_ex(param, g_pk, g_msg, 57U, g_sig, sig_len, g_ws, (uint32_t)sizeof(g_ws));
            PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "verify_ex with fresh key");
        } else {
            uint32_t mark = pq_test_probe_begin();
            rc = noxtls_falcon_sign(param, g_sk, g_msg, 57U, g_sig, &sig_len);
            if(k == 0U) {
                pq_test_probe_end(mark, (param == NOXTLS_FALCON_512) ? "Falcon-512 sign" : "Falcon-1024 sign");
            }
            PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "sign with fresh key");
            mark = pq_test_probe_begin();
            rc = noxtls_falcon_verify(param, g_pk, g_msg, 57U, g_sig, sig_len);
            if(k == 0U) {
                pq_test_probe_end(mark, (param == NOXTLS_FALCON_512) ? "Falcon-512 verify" : "Falcon-1024 verify");
            }
            PQ_CHECK_RC(rc, NOXTLS_RETURN_SUCCESS, "verify with fresh key");
        }
        PQ_CHECK_RC(noxtls_falcon_verify(param, g_pk, g_msg, 56U, g_sig, sig_len),
                    NOXTLS_RETURN_FAILED, "fresh key: modified message rejected");
        g_pk[7] ^= 0x01U;
        PQ_CHECK(noxtls_falcon_verify(param, g_pk, g_msg, 57U, g_sig, sig_len) != NOXTLS_RETURN_SUCCESS,
                 "fresh key: modified public key rejected");
    }
}

static void falcon_test_workspace_api(void)
{
    uint32_t sig_len = (uint32_t)sizeof(g_sig);
    const falcon_kat_vector_t *v = &falcon512_kats[0];

    PQ_CHECK(noxtls_falcon_sign_workspace_len(NOXTLS_FALCON_512) == ((80U * 512U) + 592U), "sign ws len 512");
    PQ_CHECK(noxtls_falcon_sign_workspace_len(NOXTLS_FALCON_1024) == ((80U * 1024U) + 592U), "sign ws len 1024");
    PQ_CHECK(noxtls_falcon_verify_workspace_len(NOXTLS_FALCON_512) == ((6U * 512U) + 8U), "verify ws len 512");
    PQ_CHECK(noxtls_falcon_keygen_workspace_len(NOXTLS_FALCON_1024) <= (uint32_t)sizeof(g_ws), "keygen ws fits");
    PQ_CHECK(noxtls_falcon_keygen_workspace_len(NOXTLS_FALCON_NONE) == 0U, "invalid ws len");
    PQ_CHECK(noxtls_falcon_sign_workspace_len(NOXTLS_FALCON_NONE) == 0U, "invalid sign ws len");
    PQ_CHECK(noxtls_falcon_verify_workspace_len(NOXTLS_FALCON_NONE) == 0U, "invalid verify ws len");
    PQ_CHECK_RC(noxtls_falcon_verify_ex(NOXTLS_FALCON_512, v->pk, v->msg, v->msg_len, v->sig, 666U,
                                        g_ws, noxtls_falcon_verify_workspace_len(NOXTLS_FALCON_512) - 1U),
                NOXTLS_RETURN_INVALID_BLOCK_SIZE, "undersized verify workspace");
    /* Unaligned caller workspace is accepted (aligned internally). */
    PQ_CHECK_RC(noxtls_falcon_verify_ex(NOXTLS_FALCON_512, v->pk, v->msg, v->msg_len, v->sig, 666U,
                                        (uint8_t *)g_ws + 1, noxtls_falcon_verify_workspace_len(NOXTLS_FALCON_512)),
                NOXTLS_RETURN_SUCCESS, "unaligned verify workspace");
    pq_test_rng_seed_label("falcon-ws", 1U);
    PQ_CHECK_RC(noxtls_falcon_sign_ex(NOXTLS_FALCON_512, v->sk, v->msg, v->msg_len, g_sig, &sig_len,
                                      (uint8_t *)g_ws + 3, noxtls_falcon_sign_workspace_len(NOXTLS_FALCON_512)),
                NOXTLS_RETURN_SUCCESS, "unaligned sign workspace");
    PQ_CHECK_RC(noxtls_falcon_verify(NOXTLS_FALCON_512, v->pk, v->msg, v->msg_len, g_sig, sig_len),
                NOXTLS_RETURN_SUCCESS, "signature from caller workspace verifies");
    PQ_CHECK_RC(noxtls_falcon_sign_ex(NOXTLS_FALCON_512, v->sk, v->msg, v->msg_len, g_sig, &sig_len,
                                      g_ws, 100U),
                NOXTLS_RETURN_INVALID_BLOCK_SIZE, "undersized sign workspace");
    PQ_CHECK_RC(noxtls_falcon_keygen_ex(NOXTLS_FALCON_512, g_pk, 897U, g_sk, 1281U, g_ws, 100U),
                NOXTLS_RETURN_INVALID_BLOCK_SIZE, "undersized keygen workspace");
    PQ_CHECK_RC(noxtls_falcon_keygen(NOXTLS_FALCON_512, g_pk, 896U, g_sk, 1281U),
                NOXTLS_RETURN_INVALID_BLOCK_SIZE, "keygen wrong pk length");
    PQ_CHECK_RC(noxtls_falcon_keygen(NOXTLS_FALCON_512, NULL, 897U, g_sk, 1281U),
                NOXTLS_RETURN_NULL, "keygen NULL output");
    PQ_CHECK_RC(noxtls_falcon_keygen(NOXTLS_FALCON_NONE, g_pk, 897U, g_sk, 1281U),
                NOXTLS_RETURN_INVALID_PARAM, "keygen invalid parameter");
    /* Entropy failure is propagated (custom source without callback). */
    pq_test_rng_restore();
    noxtls_drbg_set_entropy_source(NOXTLS_ENTROPY_SOURCE_CUSTOM);
    PQ_CHECK(noxtls_falcon_keygen(NOXTLS_FALCON_512, g_pk, 897U, g_sk, 1281U) != NOXTLS_RETURN_SUCCESS,
             "keygen fails without entropy");
    sig_len = (uint32_t)sizeof(g_sig);
    PQ_CHECK(noxtls_falcon_sign(NOXTLS_FALCON_512, v->sk, v->msg, v->msg_len, g_sig, &sig_len) !=
             NOXTLS_RETURN_SUCCESS, "sign fails without entropy");
    pq_test_rng_restore();
}

static void falcon_test_codec_edges(void)
{
    static int16_t s2[8];
    static int16_t out[8];
    uint32_t used = 0U;
    uint32_t i = 0U;
    uint32_t bad = 0U;

    for(i = 0U; i < 8U; i += 1U) {
        s2[i] = (int16_t)(((i & 1U) != 0U) ? -(int32_t)(i * 255U) : (int32_t)(i * 291U));
    }
    s2[7] = 2047;
    PQ_CHECK_RC(noxtls_falcon_comp_encode(s2, 8U, g_buf, 64U, &used), NOXTLS_RETURN_SUCCESS, "comp encode");
    PQ_CHECK_RC(noxtls_falcon_comp_decode(g_buf, 64U, out, 8U), NOXTLS_RETURN_SUCCESS, "comp decode");
    PQ_CHECK_MEM(out, s2, sizeof(s2), "comp round trip");
    PQ_CHECK_RC(noxtls_falcon_comp_encode(s2, 8U, g_buf, used - 1U, &used), NOXTLS_RETURN_INVALID_BLOCK_SIZE,
                "comp encode overflow");
    s2[3] = 2048;
    PQ_CHECK_RC(noxtls_falcon_comp_encode(s2, 8U, g_buf, 64U, &used), NOXTLS_RETURN_INVALID_PARAM,
                "comp encode out of range");
    /* "-0" (sign bit with zero magnitude) is non-canonical. */
    (void)memset(g_buf, 0, 16U);
    g_buf[0] = 0x80U;
    g_buf[1] = 0x80U;
    PQ_CHECK_RC(noxtls_falcon_comp_decode(g_buf, 16U, out, 1U), NOXTLS_RETURN_BAD_DATA, "comp decode -0");
    /* Unary part longer than 15 zeros. */
    (void)memset(g_buf, 0, 16U);
    g_buf[0] = 0x01U;
    PQ_CHECK_RC(noxtls_falcon_comp_decode(g_buf, 16U, out, 1U), NOXTLS_RETURN_BAD_DATA, "comp decode overlong");
    /* Truncated input. */
    PQ_CHECK_RC(noxtls_falcon_comp_decode(g_buf, 1U, out, 1U), NOXTLS_RETURN_BAD_DATA, "comp decode truncated");

    /* ApproxExp polynomial vs libm. */
    for(i = 0U; i < 64U; i += 1U) {
        double ccs = 0.5 + ((double)i / 160.0);
        double x = ((double)i / 64.0) * 0.6931471805599453;
        double ref = exp(-x) * ccs;
        double got = (double)noxtls_falcon_internal_expm_p63(x, ccs) / 9223372036854775808.0;

        if(fabs(got - ref) > 1e-12) {
            bad += 1U;
        }
    }
    PQ_CHECK(bad == 0U, "ApproxExp accuracy");
}

static void falcon_test_lengths(void)
{
    PQ_CHECK(noxtls_falcon_public_key_len(NOXTLS_FALCON_512) == 897U, "Falcon-512 pk len");
    PQ_CHECK(noxtls_falcon_secret_key_len(NOXTLS_FALCON_512) == 1281U, "Falcon-512 sk len");
    PQ_CHECK(noxtls_falcon_signature_len(NOXTLS_FALCON_512) == 666U, "Falcon-512 sig len");
    PQ_CHECK(noxtls_falcon_public_key_len(NOXTLS_FALCON_1024) == 1793U, "Falcon-1024 pk len");
    PQ_CHECK(noxtls_falcon_secret_key_len(NOXTLS_FALCON_1024) == 2305U, "Falcon-1024 sk len");
    PQ_CHECK(noxtls_falcon_signature_len(NOXTLS_FALCON_1024) == 1280U, "Falcon-1024 sig len");
    PQ_CHECK(noxtls_falcon_public_key_len(NOXTLS_FALCON_NONE) == 0U, "invalid pk len");
    PQ_CHECK(noxtls_falcon_signature_len((noxtls_falcon_param_t)7U) == 0U, "invalid sig len");
    PQ_CHECK_RC(noxtls_falcon_verify(NOXTLS_FALCON_512, NULL, g_msg, 1U, g_sig, 666U),
                NOXTLS_RETURN_NULL, "verify NULL public key");
    PQ_CHECK_RC(noxtls_falcon_verify(NOXTLS_FALCON_NONE, g_pk, g_msg, 1U, g_sig, 666U),
                NOXTLS_RETURN_INVALID_PARAM, "verify invalid parameter");
}

int noxtls_pq_test_falcon(void)
{
    pq_test_begin("falcon");
    falcon_test_lengths();
    falcon_test_kat_verify(NOXTLS_FALCON_512, falcon512_kats,
                           (uint32_t)(sizeof(falcon512_kats) / sizeof(falcon512_kats[0])));
    falcon_test_kat_verify(NOXTLS_FALCON_1024, falcon1024_kats,
                           (uint32_t)(sizeof(falcon1024_kats) / sizeof(falcon1024_kats[0])));
    falcon_test_kat_reproduce(NOXTLS_FALCON_512, &falcon512_kats[0]);
    falcon_test_kat_reproduce(NOXTLS_FALCON_1024, &falcon1024_kats[0]);
#if defined(NOXTLS_PQ_TEST_QUICK)
    /* Reduced round counts for slow targets (Cortex-M binary64 is emulated in software). */
    falcon_test_kat_sign(NOXTLS_FALCON_512, &falcon512_kats[0], 1U);
    falcon_test_kat_sign(NOXTLS_FALCON_1024, &falcon1024_kats[0], 1U);
#else
    falcon_test_kat_sign(NOXTLS_FALCON_512, &falcon512_kats[0], 4U);
    falcon_test_kat_sign(NOXTLS_FALCON_1024, &falcon1024_kats[0], 2U);
#endif
    falcon_test_codec_edges();
    falcon_test_workspace_api();
    falcon_test_keygen_roundtrip(NOXTLS_FALCON_512, 1U, 1U);
#if defined(NOXTLS_PQ_TEST_QUICK)
    falcon_test_keygen_roundtrip(NOXTLS_FALCON_512, 1U, 0U);
    falcon_test_keygen_roundtrip(NOXTLS_FALCON_1024, 1U, 0U);
#else
    falcon_test_keygen_roundtrip(NOXTLS_FALCON_512, 2U, 0U);
    falcon_test_keygen_roundtrip(NOXTLS_FALCON_1024, 1U, 1U);
#endif
    return pq_test_end("falcon");
}

#else

int noxtls_pq_test_falcon(void)
{
    pq_test_begin("falcon (disabled)");
    return pq_test_end("falcon (disabled)");
}

#endif /* NOXTLS_FEATURE_FALCON */

NOXTLS_PQ_TEST_MAIN(noxtls_pq_test_falcon)
