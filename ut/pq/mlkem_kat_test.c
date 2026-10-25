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
* File:    mlkem_kat_test.c
* Summary: ML-KEM-512/768/1024 (FIPS 203) known-answer, implicit-rejection,
*          input-check and round-trip tests.
*
*****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "pq_test.h"
#include "noxtls_common.h"
#include "pkc/mlkem/noxtls_mlkem.h"
#include "mdigest/sha3/noxtls_sha3.h"
#include "mlkem_kat_vectors.h"

#define KAT_COUNT(a) ((uint32_t)(sizeof(a) / sizeof((a)[0])))

static uint8_t g_pk[NOXTLS_MLKEM_MAX_PUBLIC_KEY_LEN];
static uint8_t g_sk[NOXTLS_MLKEM_MAX_SECRET_KEY_LEN];
static uint8_t g_ct[NOXTLS_MLKEM_MAX_CIPHERTEXT_LEN];
static uint8_t g_ct2[NOXTLS_MLKEM_MAX_CIPHERTEXT_LEN];
static uint8_t g_in_key[NOXTLS_MLKEM_MAX_SECRET_KEY_LEN];
static uint8_t g_in_ct[NOXTLS_MLKEM_MAX_CIPHERTEXT_LEN];
static uint8_t g_pk2[NOXTLS_MLKEM_MAX_PUBLIC_KEY_LEN];
static uint8_t g_sk2[NOXTLS_MLKEM_MAX_SECRET_KEY_LEN];

static const noxtls_mlkem_param_t g_params[3] = { NOXTLS_MLKEM_512, NOXTLS_MLKEM_768, NOXTLS_MLKEM_1024 };
static const char *const g_probe_names[3][3] = {
    { "ML-KEM-512 keygen", "ML-KEM-512 encaps", "ML-KEM-512 decaps" },
    { "ML-KEM-768 keygen", "ML-KEM-768 encaps", "ML-KEM-768 decaps" },
    { "ML-KEM-1024 keygen", "ML-KEM-1024 encaps", "ML-KEM-1024 decaps" }
};

static uint32_t hexval(char c)
{
    if((c >= '0') && (c <= '9')) { return (uint32_t)(c - '0'); }
    if((c >= 'a') && (c <= 'f')) { return (uint32_t)(c - 'a') + 10U; }
    if((c >= 'A') && (c <= 'F')) { return (uint32_t)(c - 'A') + 10U; }
    return 0xFFU;
}

/** Decode a hex string; returns the byte count (or 0xFFFFFFFF on error/overflow). */
static uint32_t unhex(const char *hex, uint8_t *out, uint32_t cap)
{
    uint32_t n = 0U;
    while((hex[0] != '\0') && (hex[1] != '\0')) {
        uint32_t hi = hexval(hex[0]);
        uint32_t lo = hexval(hex[1]);
        if((hi > 15U) || (lo > 15U) || (n >= cap)) {
            return 0xFFFFFFFFU;
        }
        out[n] = (uint8_t)((hi << 4U) | lo);
        n += 1U;
        hex = &hex[2];
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

/** Independent J(z || c) = SHAKE256(z || c, 32) for implicit-rejection checks. */
static void kem_j(const uint8_t *z, const uint8_t *c, uint32_t c_len, uint8_t out[32])
{
    noxtls_sha3_ctx_t ctx;
    (void)noxtls_shake256_init(&ctx);
    (void)noxtls_shake256_update(&ctx, z, 32U);
    (void)noxtls_shake256_update(&ctx, c, c_len);
    (void)noxtls_shake256_final(&ctx);
    (void)noxtls_shake256_squeeze(&ctx, out, 32U);
}

static uint32_t mlkem_k(noxtls_mlkem_param_t p)
{
    return (p == NOXTLS_MLKEM_512) ? 2U : ((p == NOXTLS_MLKEM_768) ? 3U : 4U);
}

static void test_sizes(void)
{
    PQ_CHECK(noxtls_mlkem_public_key_len(NOXTLS_MLKEM_512) == 800U, "ML-KEM-512 ek len");
    PQ_CHECK(noxtls_mlkem_secret_key_len(NOXTLS_MLKEM_512) == 1632U, "ML-KEM-512 dk len");
    PQ_CHECK(noxtls_mlkem_ciphertext_len(NOXTLS_MLKEM_512) == 768U, "ML-KEM-512 ct len");
    PQ_CHECK(noxtls_mlkem_public_key_len(NOXTLS_MLKEM_768) == 1184U, "ML-KEM-768 ek len");
    PQ_CHECK(noxtls_mlkem_secret_key_len(NOXTLS_MLKEM_768) == 2400U, "ML-KEM-768 dk len");
    PQ_CHECK(noxtls_mlkem_ciphertext_len(NOXTLS_MLKEM_768) == 1088U, "ML-KEM-768 ct len");
    PQ_CHECK(noxtls_mlkem_public_key_len(NOXTLS_MLKEM_1024) == 1568U, "ML-KEM-1024 ek len");
    PQ_CHECK(noxtls_mlkem_secret_key_len(NOXTLS_MLKEM_1024) == 3168U, "ML-KEM-1024 dk len");
    PQ_CHECK(noxtls_mlkem_ciphertext_len(NOXTLS_MLKEM_1024) == 1568U, "ML-KEM-1024 ct len");
    PQ_CHECK(noxtls_mlkem_public_key_len(NOXTLS_MLKEM_NONE) == 0U, "NONE ek len");
    PQ_CHECK(noxtls_mlkem_secret_key_len((noxtls_mlkem_param_t)9U) == 0U, "bad dk len");
    PQ_CHECK(noxtls_mlkem_ciphertext_len((noxtls_mlkem_param_t)9U) == 0U, "bad ct len");
}

static void test_keygen_kat(void)
{
    uint32_t i = 0U;
    for(i = 0U; i < KAT_COUNT(g_mlkem_kat_keygen); i += 1U) {
        const mlkem_kat_keygen_t *v = &g_mlkem_kat_keygen[i];
        uint8_t d[32];
        uint8_t z[32];
        uint8_t h_ek[32];
        uint8_t h_dk[32];
        uint8_t got[32];

        PQ_CHECK(unhex(v->d, d, 32U) == 32U, "keygen d");
        PQ_CHECK(unhex(v->z, z, 32U) == 32U, "keygen z");
        PQ_CHECK(unhex(v->ek_sha3_256, h_ek, 32U) == 32U, "keygen ek digest");
        PQ_CHECK(unhex(v->dk_sha3_256, h_dk, 32U) == 32U, "keygen dk digest");
        PQ_CHECK_RC(noxtls_mlkem_keygen_derand(v->param, d, z, g_pk, g_sk), NOXTLS_RETURN_SUCCESS, "keygen_derand");
        sha3_256(g_pk, noxtls_mlkem_public_key_len(v->param), got);
        PQ_CHECK_MEM(got, h_ek, 32U, "keyGen KAT ek");
        sha3_256(g_sk, noxtls_mlkem_secret_key_len(v->param), got);
        PQ_CHECK_MEM(got, h_dk, 32U, "keyGen KAT dk");
        PQ_CHECK_RC(noxtls_mlkem_check_public_key(v->param, g_pk), NOXTLS_RETURN_SUCCESS, "generated ek passes check");
        PQ_CHECK_RC(noxtls_mlkem_check_secret_key(v->param, g_sk), NOXTLS_RETURN_SUCCESS, "generated dk passes check");

        /* The legacy test hook must reproduce the same key pair through the randomized API. */
        if(i == 0U) {
            static uint8_t seq[64];
            (void)memcpy(seq, d, 32U);
            (void)memcpy(&seq[32], z, 32U);
            noxtls_mlkem_set_test_random_sequence(seq, sizeof(seq));
            PQ_CHECK_RC(noxtls_mlkem_keygen(v->param, g_pk2, g_sk2), NOXTLS_RETURN_SUCCESS, "keygen via test sequence");
            noxtls_mlkem_set_test_random_sequence(NULL, 0U);
            PQ_CHECK_MEM(g_pk2, g_pk, noxtls_mlkem_public_key_len(v->param), "test-sequence keygen ek");
            PQ_CHECK_MEM(g_sk2, g_sk, noxtls_mlkem_secret_key_len(v->param), "test-sequence keygen dk");
        }
    }
}

static void test_encaps_kat(void)
{
    uint32_t i = 0U;
    for(i = 0U; i < KAT_COUNT(g_mlkem_kat_encaps); i += 1U) {
        const mlkem_kat_encaps_t *v = &g_mlkem_kat_encaps[i];
        uint8_t m[32];
        uint8_t k[32];
        uint8_t h_c[32];
        uint8_t got[32];
        uint8_t ss[32];
        uint32_t ek_len = noxtls_mlkem_public_key_len(v->param);

        PQ_CHECK(unhex(v->ek, g_pk, sizeof(g_pk)) == ek_len, "encaps ek");
        PQ_CHECK(unhex(v->m, m, 32U) == 32U, "encaps m");
        PQ_CHECK(unhex(v->k, k, 32U) == 32U, "encaps k");
        PQ_CHECK(unhex(v->c_sha3_256, h_c, 32U) == 32U, "encaps c digest");
        PQ_CHECK_RC(noxtls_mlkem_encaps_derand(v->param, g_pk, m, g_ct, ss), NOXTLS_RETURN_SUCCESS, "encaps_derand");
        sha3_256(g_ct, noxtls_mlkem_ciphertext_len(v->param), got);
        PQ_CHECK_MEM(got, h_c, 32U, "encaps KAT c");
        PQ_CHECK_MEM(ss, k, 32U, "encaps KAT K");

        if(i == 0U) {
            noxtls_mlkem_set_test_random_sequence(m, 32U);
            PQ_CHECK_RC(noxtls_mlkem_encaps(v->param, g_pk, g_ct2, got), NOXTLS_RETURN_SUCCESS, "encaps via test sequence");
            noxtls_mlkem_set_test_random_sequence(NULL, 0U);
            PQ_CHECK_MEM(g_ct2, g_ct, noxtls_mlkem_ciphertext_len(v->param), "test-sequence encaps c");
            PQ_CHECK_MEM(got, k, 32U, "test-sequence encaps K");
        }
    }
}

static void test_decaps_kat(void)
{
    uint32_t i = 0U;
    uint32_t rejects = 0U;
    for(i = 0U; i < KAT_COUNT(g_mlkem_kat_decaps); i += 1U) {
        const mlkem_kat_decaps_t *v = &g_mlkem_kat_decaps[i];
        uint8_t k[32];
        uint8_t ss[32];
        uint8_t j[32];
        uint32_t kk = mlkem_k(v->param);
        uint32_t ek_len = noxtls_mlkem_public_key_len(v->param);
        uint32_t dk_len = noxtls_mlkem_secret_key_len(v->param);
        uint32_t ct_len = noxtls_mlkem_ciphertext_len(v->param);
        const uint8_t *ek = &g_in_key[kk * 384U];
        const uint8_t *z = &g_in_key[dk_len - 32U];

        PQ_CHECK(unhex(v->dk, g_in_key, sizeof(g_in_key)) == dk_len, "decaps dk");
        PQ_CHECK(unhex(v->c, g_in_ct, sizeof(g_in_ct)) == ct_len, "decaps c");
        PQ_CHECK(unhex(v->k, k, 32U) == 32U, "decaps k");
        PQ_CHECK_RC(noxtls_mlkem_decaps(v->param, ek, g_in_key, g_in_ct, ss), NOXTLS_RETURN_SUCCESS, "decaps");
        PQ_CHECK_MEM(ss, k, 32U, "decaps KAT K");
        kem_j(z, g_in_ct, ct_len, j);
        if(v->implicit_reject != 0U) {
            rejects += 1U;
            PQ_CHECK_MEM(ss, j, 32U, "implicit rejection key equals J(z||c)");
        } else {
            PQ_CHECK(memcmp(ss, j, 32U) != 0, "valid ciphertext does not return J(z||c)");
        }
        (void)ek_len;
    }
    PQ_CHECK(rejects > 0U, "decaps KATs include modified ciphertexts");
}

static void test_key_checks(void)
{
    uint32_t i = 0U;
    uint8_t m[32];
    uint8_t ss[32];

    (void)memset(m, 0x5A, sizeof(m));
    for(i = 0U; i < KAT_COUNT(g_mlkem_kat_ek_check); i += 1U) {
        const mlkem_kat_keycheck_t *v = &g_mlkem_kat_ek_check[i];
        noxtls_return_t expected = (v->valid != 0U) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_BAD_DATA;
        PQ_CHECK(unhex(v->key, g_in_key, sizeof(g_in_key)) == noxtls_mlkem_public_key_len(v->param), "ek check key");
        PQ_CHECK_RC(noxtls_mlkem_check_public_key(v->param, g_in_key), expected, "encapsulationKeyCheck KAT");
        PQ_CHECK_RC(noxtls_mlkem_encaps_derand(v->param, g_in_key, m, g_ct, ss), expected, "encaps applies modulus check");
    }
    for(i = 0U; i < KAT_COUNT(g_mlkem_kat_dk_check); i += 1U) {
        const mlkem_kat_keycheck_t *v = &g_mlkem_kat_dk_check[i];
        noxtls_return_t expected = (v->valid != 0U) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_BAD_DATA;
        uint32_t kk = mlkem_k(v->param);
        PQ_CHECK(unhex(v->key, g_in_key, sizeof(g_in_key)) == noxtls_mlkem_secret_key_len(v->param), "dk check key");
        PQ_CHECK_RC(noxtls_mlkem_check_secret_key(v->param, g_in_key), expected, "decapsulationKeyCheck KAT");
        (void)memset(g_in_ct, 0, sizeof(g_in_ct));
        PQ_CHECK_RC(noxtls_mlkem_decaps(v->param, &g_in_key[kk * 384U], g_in_key, g_in_ct, ss), expected,
                    "decaps applies hash check");
    }
}

static void test_round_trips(void)
{
    uint32_t pi = 0U;
    for(pi = 0U; pi < 3U; pi += 1U) {
        noxtls_mlkem_param_t p = g_params[pi];
        uint32_t ek_len = noxtls_mlkem_public_key_len(p);
        uint32_t dk_len = noxtls_mlkem_secret_key_len(p);
        uint32_t ct_len = noxtls_mlkem_ciphertext_len(p);
        uint32_t trial = 0U;

        for(trial = 0U; trial < 3U; trial += 1U) {
            uint8_t ss_a[32];
            uint8_t ss_b[32];
            uint8_t j[32];
            uint32_t pos = 0U;

            uint32_t mark = 0U;

            pq_test_rng_seed_label("mlkem-roundtrip", (pi * 16U) + trial);
            mark = pq_test_probe_begin();
            PQ_CHECK_RC(noxtls_mlkem_keygen(p, g_pk, g_sk), NOXTLS_RETURN_SUCCESS, "keygen");
            if(trial == 0U) { pq_test_probe_end(mark, g_probe_names[pi][0]); }
            mark = pq_test_probe_begin();
            PQ_CHECK_RC(noxtls_mlkem_encaps(p, g_pk, g_ct, ss_a), NOXTLS_RETURN_SUCCESS, "encaps");
            if(trial == 0U) { pq_test_probe_end(mark, g_probe_names[pi][1]); }
            mark = pq_test_probe_begin();
            PQ_CHECK_RC(noxtls_mlkem_decaps(p, g_pk, g_sk, g_ct, ss_b), NOXTLS_RETURN_SUCCESS, "decaps");
            if(trial == 0U) { pq_test_probe_end(mark, g_probe_names[pi][2]); }
            PQ_CHECK_MEM(ss_b, ss_a, 32U, "round trip shared secret");

            /* Tamper with first, middle (v part) and last ciphertext byte. */
            for(pos = 0U; pos < 3U; pos += 1U) {
                uint32_t idx = (pos == 0U) ? 0U : ((pos == 1U) ? (ct_len - 100U) : (ct_len - 1U));
                (void)memcpy(g_ct2, g_ct, ct_len);
                g_ct2[idx] ^= (uint8_t)(1U << (trial & 7U));
                PQ_CHECK_RC(noxtls_mlkem_decaps(p, g_pk, g_sk, g_ct2, ss_b), NOXTLS_RETURN_SUCCESS, "decaps tampered");
                kem_j(&g_sk[dk_len - 32U], g_ct2, ct_len, j);
                PQ_CHECK_MEM(ss_b, j, 32U, "tampered ciphertext -> J(z||c)");
                PQ_CHECK(memcmp(ss_b, ss_a, 32U) != 0, "tampered ciphertext changes the key");
            }

            /* Wrong public key / corrupted dk hash / wrong z behaviour. */
            (void)memcpy(g_pk2, g_pk, ek_len);
            g_pk2[5] ^= 0x01U;
            PQ_CHECK_RC(noxtls_mlkem_decaps(p, g_pk2, g_sk, g_ct, ss_b), NOXTLS_RETURN_FAILED, "decaps pk mismatch");
            (void)memcpy(g_sk2, g_sk, dk_len);
            g_sk2[dk_len - 40U] ^= 0x80U;   /* inside H(ek) */
            PQ_CHECK_RC(noxtls_mlkem_decaps(p, g_pk, g_sk2, g_ct, ss_b), NOXTLS_RETURN_BAD_DATA, "decaps bad H(ek)");
            (void)memcpy(g_sk2, g_sk, dk_len);
            g_sk2[0] ^= 0x01U;               /* corrupt s^: valid ct now rejected implicitly */
            PQ_CHECK_RC(noxtls_mlkem_decaps(p, g_pk, g_sk2, g_ct, ss_b), NOXTLS_RETURN_SUCCESS, "decaps bad s");
            PQ_CHECK(memcmp(ss_b, ss_a, 32U) != 0, "corrupted s changes the key");

            /* Encapsulation-key modulus check: force a coefficient to 0xFFF. */
            (void)memcpy(g_pk2, g_pk, ek_len);
            g_pk2[0] = 0xFFU;
            g_pk2[1] |= 0x0FU;
            PQ_CHECK_RC(noxtls_mlkem_check_public_key(p, g_pk2), NOXTLS_RETURN_BAD_DATA, "modulus check");
            PQ_CHECK_RC(noxtls_mlkem_encaps(p, g_pk2, g_ct2, ss_b), NOXTLS_RETURN_BAD_DATA, "encaps rejects bad ek");
            /* Coefficient exactly q-1 (0xD00) is still valid. */
            g_pk2[0] = 0x00U;
            g_pk2[1] = (uint8_t)((g_pk2[1] & 0xF0U) | 0x0DU);
            PQ_CHECK_RC(noxtls_mlkem_check_public_key(p, g_pk2), NOXTLS_RETURN_SUCCESS, "q-1 coefficient valid");
            g_pk2[1] = (uint8_t)((g_pk2[1] & 0xF0U) | 0x0DU);
            g_pk2[0] = 0x01U; /* 0xD01 == q */
            PQ_CHECK_RC(noxtls_mlkem_check_public_key(p, g_pk2), NOXTLS_RETURN_BAD_DATA, "q coefficient invalid");
        }
        pq_test_rng_restore();
    }
}

static void test_bad_args(void)
{
    uint8_t buf[32];
    (void)memset(buf, 0, sizeof(buf));
    PQ_CHECK_RC(noxtls_mlkem_keygen(NOXTLS_MLKEM_768, NULL, g_sk), NOXTLS_RETURN_NULL, "keygen NULL pk");
    PQ_CHECK_RC(noxtls_mlkem_keygen(NOXTLS_MLKEM_768, g_pk, NULL), NOXTLS_RETURN_NULL, "keygen NULL sk");
    PQ_CHECK_RC(noxtls_mlkem_keygen(NOXTLS_MLKEM_NONE, g_pk, g_sk), NOXTLS_RETURN_INVALID_PARAM, "keygen bad param");
    PQ_CHECK_RC(noxtls_mlkem_keygen_derand(NOXTLS_MLKEM_768, NULL, buf, g_pk, g_sk), NOXTLS_RETURN_NULL, "derand NULL d");
    PQ_CHECK_RC(noxtls_mlkem_keygen_derand((noxtls_mlkem_param_t)7U, buf, buf, g_pk, g_sk), NOXTLS_RETURN_INVALID_PARAM,
                "derand bad param");
    PQ_CHECK_RC(noxtls_mlkem_encaps(NOXTLS_MLKEM_768, NULL, g_ct, buf), NOXTLS_RETURN_NULL, "encaps NULL pk");
    PQ_CHECK_RC(noxtls_mlkem_encaps(NOXTLS_MLKEM_NONE, g_pk, g_ct, buf), NOXTLS_RETURN_INVALID_PARAM, "encaps bad param");
    PQ_CHECK_RC(noxtls_mlkem_encaps_derand(NOXTLS_MLKEM_768, g_pk, NULL, g_ct, buf), NOXTLS_RETURN_NULL, "encaps_derand NULL m");
    PQ_CHECK_RC(noxtls_mlkem_encaps_derand(NOXTLS_MLKEM_NONE, g_pk, buf, g_ct, buf), NOXTLS_RETURN_INVALID_PARAM,
                "encaps_derand bad param");
    PQ_CHECK_RC(noxtls_mlkem_decaps(NOXTLS_MLKEM_768, g_pk, g_sk, NULL, buf), NOXTLS_RETURN_NULL, "decaps NULL ct");
    PQ_CHECK_RC(noxtls_mlkem_decaps(NOXTLS_MLKEM_NONE, g_pk, g_sk, g_ct, buf), NOXTLS_RETURN_INVALID_PARAM, "decaps bad param");
    PQ_CHECK_RC(noxtls_mlkem_check_public_key(NOXTLS_MLKEM_768, NULL), NOXTLS_RETURN_NULL, "ek check NULL");
    PQ_CHECK_RC(noxtls_mlkem_check_public_key(NOXTLS_MLKEM_NONE, g_pk), NOXTLS_RETURN_INVALID_PARAM, "ek check bad param");
    PQ_CHECK_RC(noxtls_mlkem_check_secret_key(NOXTLS_MLKEM_768, NULL), NOXTLS_RETURN_NULL, "dk check NULL");
    PQ_CHECK_RC(noxtls_mlkem_check_secret_key(NOXTLS_MLKEM_NONE, g_sk), NOXTLS_RETURN_INVALID_PARAM, "dk check bad param");
}

int noxtls_pq_test_mlkem(void)
{
    pq_test_begin("ML-KEM (FIPS 203)");
    test_sizes();
    test_keygen_kat();
    test_encaps_kat();
    test_decaps_kat();
    test_key_checks();
    test_round_trips();
    test_bad_args();
    return pq_test_end("ML-KEM (FIPS 203)");
}

NOXTLS_PQ_TEST_MAIN(noxtls_pq_test_mlkem)
