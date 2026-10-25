/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    crypto_sym_tls_kdf_test.c
* Summary: TLS key-derivation regression tests (public API only).
*
*  - tls12_prf: the widely published SHA-256 (100 bytes), SHA-384 (148 bytes)
*    and SHA-512 (196 bytes) "test label" vectors; every shorter output must be
*    a prefix; a 1000-byte output with a 200-byte secret (longer than the HMAC
*    block) and a 77-byte seed;
*  - tls10_prf (MD5 + SHA-1 split secret) with even (48) and odd (47) secret
*    lengths against a Python model;
*  - TLS 1.3: RFC 8448 section 3 key schedule (early secret, derived, handshake
*    secret, c/s hs traffic, handshake keys/IVs, derived 2, master, server
*    finished key) through noxtls_hkdf_extract, tls13_derive_secret and
*    tls13_hkdf_expand_label; protocol-maximum label (249 bytes after "tls13 ")
*    and context (255 bytes) for SHA-256/SHA-384; over-limit label/context
*    rejected; Derive-Secret over an explicit 300-byte transcript.
* Built twice: CRYPTO_SYM_PART=0 -> crypto_sym_tls_kdf_test, CRYPTO_SYM_PART=1 ->
*   crypto_sym_tls13_label_limits_test (label AND context both at the maximum).
* Expected values: crypto_sym_tls_kdf_vectors.h.
*****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "noxtls_common.h"
#include "mdigest/noxtls_hash.h"
#include "kdf/noxtls_hkdf.h"
#include "tls/noxtls_tls_kdf.h"

#include "crypto_sym_test_util.h"
#include "crypto_sym_tls_kdf_vectors.h"

#ifndef CRYPTO_SYM_PART
#define CRYPTO_SYM_PART 0
#endif

static uint8_t g_out[2048];

static void prf12_vector(const char *what, noxtls_hash_algos_t alg, const char *secret_hex, const char *seed_hex,
                         const char *expect_hex)
{
    static const uint32_t k_prefix[] = { 1U, 31U, 32U, 33U, 47U, 48U, 49U, 64U, 99U };
    uint8_t secret[32];
    uint8_t seed[32];
    uint8_t full[256];
    uint32_t sl = cs_hex(secret_hex, secret, (uint32_t)sizeof(secret));
    uint32_t dl = cs_hex(seed_hex, seed, (uint32_t)sizeof(seed));
    uint32_t n = cs_hex_len(expect_hex);
    uint32_t i;

    cs_section(what);
    (void)memset(g_out, 0xEE, sizeof(g_out));
    CHECK_RC(tls12_prf(secret, sl, (const uint8_t *)"test label", 10U, seed, dl, g_out, n, alg), NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_HEX(what, g_out, n, expect_hex);
    CHECK(g_out[n] == 0xEEU);
    (void)memcpy(full, g_out, n);
    for (i = 0U; i < (uint32_t)(sizeof(k_prefix) / sizeof(k_prefix[0])); i += 1U) {
        (void)memset(g_out, 0xEE, sizeof(g_out));
        CHECK_RC(tls12_prf(secret, sl, (const uint8_t *)"test label", 10U, seed, dl, g_out, k_prefix[i], alg),
                 NOXTLS_RETURN_SUCCESS);
        (void)EXPECT_MEM("PRF prefix", g_out, full, k_prefix[i]);
        CHECK(g_out[k_prefix[i]] == 0xEEU);
    }
}

static void test_tls12_prf(void)
{
    uint8_t secret[200];
    uint8_t seed[77];

#if NOXTLS_FEATURE_SHA256
    prf12_vector("TLS 1.2 PRF SHA-256", NOXTLS_HASH_SHA_256, "9bbe436ba940f017b17652849a71db35",
                 "a0ba9f936cda311827a6f796ffd5198c", k_prf12_sha256);
#endif
#if NOXTLS_FEATURE_SHA384
    prf12_vector("TLS 1.2 PRF SHA-384", NOXTLS_HASH_SHA_384, "b80b733d6ceefcdc71566ea48e5567df",
                 "cd665cf6a8447dd6ff8b27555edb7465", k_prf12_sha384);
#endif
#if NOXTLS_FEATURE_SHA512
    prf12_vector("TLS 1.2 PRF SHA-512", NOXTLS_HASH_SHA_512, "b0323523c1853599584d88568bbb05eb",
                 "d4640e12e4bcdbfb437f03e6ae418ee5", k_prf12_sha512);
#endif
    cs_fill(secret, sizeof(secret), CS_PRF_LONG_SECRET_SEED);
    cs_fill(seed, sizeof(seed), CS_PRF_LONG_SEED_SEED);
#if NOXTLS_FEATURE_SHA256
    cs_section("TLS 1.2 PRF SHA-256 long");
    CHECK_RC(tls12_prf(secret, sizeof(secret), (const uint8_t *)"key expansion", 13U, seed, sizeof(seed), g_out, 1000U,
                       NOXTLS_HASH_SHA_256), NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_HEX("PRF-SHA256 1000 bytes", g_out, 1000U, k_prf12_long_sha256_1000);
#endif
#if NOXTLS_FEATURE_SHA384
    cs_section("TLS 1.2 PRF SHA-384 long");
    CHECK_RC(tls12_prf(secret, sizeof(secret), (const uint8_t *)"key expansion", 13U, seed, sizeof(seed), g_out, 1000U,
                       NOXTLS_HASH_SHA_384), NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_HEX("PRF-SHA384 1000 bytes", g_out, 1000U, k_prf12_long_sha384_1000);
#endif
}

static void test_tls10_prf(void)
{
#if NOXTLS_FEATURE_MD5 && NOXTLS_FEATURE_SHA1
    uint8_t secret[48];
    uint8_t seed[64];

    cs_fill(seed, sizeof(seed), 0x20202020U);
    cs_section("TLS 1.0 PRF secret 48");
    cs_fill(secret, 48U, 0x10101010U + 48U);
    (void)memset(g_out, 0xEE, sizeof(g_out));
    CHECK_RC(tls10_prf(secret, 48U, (const uint8_t *)"master secret", 13U, seed, sizeof(seed), g_out, 104U),
             NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_HEX("tls10_prf 48", g_out, 104U, k_prf10_secret48);
    CHECK(g_out[104] == 0xEEU);
    cs_section("TLS 1.0 PRF secret 47");
    cs_fill(secret, 47U, 0x10101010U + 47U);
    CHECK_RC(tls10_prf(secret, 47U, (const uint8_t *)"master secret", 13U, seed, sizeof(seed), g_out, 104U),
             NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_HEX("tls10_prf 47", g_out, 104U, k_prf10_secret47);
#else
    (void)printf("SKIP tls10_prf: needs MD5 and SHA-1\n");
#endif
}

static void expect_label(const char *what, const uint8_t *secret, const char *label, const uint8_t *ctx, uint32_t ctx_len,
                         uint32_t out_len, const char *expect_hex)
{
    cs_section(what);
    (void)memset(g_out, 0xEE, sizeof(g_out));
    CHECK_RC(tls13_hkdf_expand_label(NOXTLS_HASH_SHA_256, secret, 32U, (const uint8_t *)label, (uint32_t)strlen(label),
                                     ctx, ctx_len, g_out, out_len), NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_HEX(what, g_out, out_len, expect_hex);
    CHECK(g_out[out_len] == 0xEEU);
}

static void test_rfc8448(void)
{
#if NOXTLS_FEATURE_SHA256
    uint8_t zero[32];
    uint8_t early[32];
    uint8_t derived[32];
    uint8_t ecdhe[32];
    uint8_t hs[32];
    uint8_t th[32];
    uint8_t chs[32];
    uint8_t shs[32];
    uint8_t derived2[32];
    uint8_t master[32];
    uint32_t len;

    (void)memset(zero, 0, sizeof(zero));
    cs_section("RFC 8448 early secret");
    len = sizeof(early);
    CHECK_RC(noxtls_hkdf_extract(NOXTLS_HASH_SHA_256, NULL, 0U, zero, 32U, early, &len), NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_HEX("early secret", early, 32U, k_rfc8448_early);

    cs_section("RFC 8448 derived");
    CHECK_RC(tls13_derive_secret(NOXTLS_HASH_SHA_256, early, 32U, (const uint8_t *)"derived", 7U, NULL, 0U, derived, 32U),
             NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_HEX("derived", derived, 32U, k_rfc8448_derived);

    cs_section("RFC 8448 handshake secret");
    (void)cs_hex(k_rfc8448_ecdhe, ecdhe, sizeof(ecdhe));
    len = sizeof(hs);
    CHECK_RC(noxtls_hkdf_extract(NOXTLS_HASH_SHA_256, derived, 32U, ecdhe, 32U, hs, &len), NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_HEX("handshake secret", hs, 32U, k_rfc8448_hs);

    (void)cs_hex(k_rfc8448_th_ch_sh, th, sizeof(th));
    expect_label("RFC 8448 c hs traffic", hs, "c hs traffic", th, 32U, 32U, k_rfc8448_c_hs);
    (void)memcpy(chs, g_out, 32U);
    expect_label("RFC 8448 s hs traffic", hs, "s hs traffic", th, 32U, 32U, k_rfc8448_s_hs);
    (void)memcpy(shs, g_out, 32U);
    expect_label("RFC 8448 server hs key", shs, "key", NULL, 0U, 16U, k_rfc8448_s_hs_key);
    expect_label("RFC 8448 server hs iv", shs, "iv", NULL, 0U, 12U, k_rfc8448_s_hs_iv);
    expect_label("RFC 8448 client hs key", chs, "key", (const uint8_t *)"", 0U, 16U, k_rfc8448_c_hs_key);
    expect_label("RFC 8448 client hs iv", chs, "iv", NULL, 0U, 12U, k_rfc8448_c_hs_iv);
    expect_label("RFC 8448 server finished key", shs, "finished", NULL, 0U, 32U, k_rfc8448_s_finished);

    cs_section("RFC 8448 derived 2 / master");
    CHECK_RC(tls13_derive_secret(NOXTLS_HASH_SHA_256, hs, 32U, (const uint8_t *)"derived", 7U, (const uint8_t *)"", 0U,
                                 derived2, 32U), NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_HEX("derived 2", derived2, 32U, k_rfc8448_derived2);
    len = sizeof(master);
    CHECK_RC(noxtls_hkdf_extract(NOXTLS_HASH_SHA_256, derived2, 32U, zero, 32U, master, &len), NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_HEX("master secret", master, 32U, k_rfc8448_master);
#else
    (void)printf("SKIP RFC 8448: needs SHA-256\n");
#endif
}


/* Label / context near the protocol maximum, over-limit rejection, explicit transcript (part 0). */
static void test_label_limits(void)
{
    static uint8_t label[260];
    static uint8_t context[260];
    static uint8_t transcript[300];
    uint8_t secret[48];
    uint8_t master[32];

    cs_fill(label, 250U, CS_LONG_LABEL_SEED);
    cs_fill(context, 256U, CS_LONG_CONTEXT_SEED);
    cs_fill(transcript, 300U, CS_TRANSCRIPT_SEED);
#if NOXTLS_FEATURE_SHA256
    (void)cs_hex(k_rfc8448_master, master, sizeof(master));
    cs_section("expand_label max label, empty context SHA-256");
    (void)memset(g_out, 0xEE, sizeof(g_out));
    CHECK_RC(tls13_hkdf_expand_label(NOXTLS_HASH_SHA_256, master, 32U, label, 249U, NULL, 0U, g_out, 100U),
             NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_HEX("max label", g_out, 100U, k_label_max_ctx0_sha256_100);
    CHECK(g_out[100] == 0xEEU);
    cs_section("expand_label short label, max context SHA-256");
    (void)memset(g_out, 0xEE, sizeof(g_out));
    CHECK_RC(tls13_hkdf_expand_label(NOXTLS_HASH_SHA_256, master, 32U, (const uint8_t *)"c hs traffic", 12U, context, 255U,
                                     g_out, 100U), NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_HEX("max context", g_out, 100U, k_label_short_ctxmax_sha256_100);
    CHECK(g_out[100] == 0xEEU);
    cs_section("expand_label over-limit label/context rejected");
    /* "tls13 " + 250-byte label = 256 bytes: does not fit the 1-byte length. */
    CHECK(tls13_hkdf_expand_label(NOXTLS_HASH_SHA_256, master, 32U, label, 250U, NULL, 0U, g_out, 100U) !=
          NOXTLS_RETURN_SUCCESS);
    CHECK(tls13_hkdf_expand_label(NOXTLS_HASH_SHA_256, master, 32U, label, 12U, context, 256U, g_out, 100U) !=
          NOXTLS_RETURN_SUCCESS);

    cs_section("derive_secret over explicit transcript SHA-256");
    CHECK_RC(tls13_derive_secret(NOXTLS_HASH_SHA_256, master, 32U, (const uint8_t *)"c ap traffic", 12U, transcript, 300U,
                                 g_out, 32U), NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_HEX("derive_secret transcript", g_out, 32U, k_derive_msgs_sha256);
#endif
#if NOXTLS_FEATURE_SHA384
    cs_fill(secret, 48U, CS_SHA384_SECRET_SEED);
    cs_section("derive_secret SHA-384");
    CHECK_RC(tls13_derive_secret(NOXTLS_HASH_SHA_384, secret, 48U, (const uint8_t *)"s ap traffic", 12U, transcript, 300U,
                                 g_out, 48U), NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_HEX("derive_secret transcript SHA-384", g_out, 48U, k_derive_msgs_sha384);
    CHECK_RC(tls13_derive_secret(NOXTLS_HASH_SHA_384, secret, 48U, (const uint8_t *)"derived", 7U, NULL, 0U, g_out, 48U),
             NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_HEX("derive_secret empty SHA-384", g_out, 48U, k_derive_empty_sha384);
#endif
    (void)secret;
    (void)master;
}

/*
 * Label (249 bytes after "tls13 ") and context (255 bytes) both at the
 * protocol maximum: the HkdfLabel is 2 + 1 + 255 + 1 + 255 = 514 bytes (part 1).
 */
static void test_label_both_max(void)
{
    static uint8_t label[260];
    static uint8_t context[260];
    uint8_t secret[48];
    uint8_t master[32];

    cs_fill(label, 249U, CS_LONG_LABEL_SEED);
    cs_fill(context, 255U, CS_LONG_CONTEXT_SEED);
#if NOXTLS_FEATURE_SHA256
    (void)cs_hex(k_rfc8448_master, master, sizeof(master));
    cs_section("expand_label max label + max context SHA-256");
    (void)memset(g_out, 0xEE, sizeof(g_out));
    CHECK_RC(tls13_hkdf_expand_label(NOXTLS_HASH_SHA_256, master, 32U, label, 249U, context, 255U, g_out, 100U),
             NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_HEX("max label/context", g_out, 100U, k_label_max_sha256_100);
    CHECK(g_out[100] == 0xEEU);
#endif
#if NOXTLS_FEATURE_SHA384
    cs_fill(secret, 48U, CS_SHA384_SECRET_SEED);
    cs_section("expand_label max label + max context SHA-384");
    (void)memset(g_out, 0xEE, sizeof(g_out));
    CHECK_RC(tls13_hkdf_expand_label(NOXTLS_HASH_SHA_384, secret, 48U, label, 249U, context, 255U, g_out, 300U),
             NOXTLS_RETURN_SUCCESS);
    (void)EXPECT_HEX("max label/context SHA-384", g_out, 300U, k_label_max_sha384_300);
    CHECK(g_out[300] == 0xEEU);
#endif
    (void)secret;
    (void)master;
}

typedef struct {
    uint32_t part;
    void (*fn)(void);
} cs_test_entry_t;

/* CRYPTO_SYM_PART 0: crypto_sym_tls_kdf_test, 1: crypto_sym_tls13_label_limits_test. */
static const cs_test_entry_t k_tests[] = {
    { 0U, test_tls12_prf },
    { 0U, test_tls10_prf },
    { 0U, test_rfc8448 },
    { 0U, test_label_limits },
    { 1U, test_label_both_max },
};

int main(void)
{
    uint32_t i;
    for (i = 0U; i < (uint32_t)(sizeof(k_tests) / sizeof(k_tests[0])); i += 1U) {
        if (k_tests[i].part == (uint32_t)CRYPTO_SYM_PART) {
            k_tests[i].fn();
        }
    }
    return cs_finish((CRYPTO_SYM_PART == 0) ? "crypto_sym_tls_kdf_test" : "crypto_sym_tls13_label_limits_test");
}
