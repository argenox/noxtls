/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
* Licensed under the GNU General Public License v2.0 or later,
* or alternatively under a commercial license from Argenox Technologies LLC.
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
* File:    tls12_loopback_test.c
* Summary: End-to-end TLS 1.2 client/server regression tests over an in-memory link
*****************************************************************************/
/** @file tls12_loopback_test.c
 * @brief ECDHE-ECDSA / ECDHE-RSA with GCM, ChaCha20-Poly1305, CCM and CBC suites,
 * ticket resumption, renegotiation_info / HelloRequest handling, mutual TLS,
 * OCSP stapling, max_fragment_length and application-data framing; CertificateVerify hashes
 * that differ from the PRF hash, extended master secret on/off (with resumption) and
 * TLS 1.0/1.1 when built.
 */
#include "lb_fixture.h"

#include <string.h>

#define PAYLOAD_MAX (65536U + 4096U)

static uint8_t s_payload[PAYLOAD_MAX];

static const uint32_t k_sizes[] = {
    1U, 15U, 16U, 17U, 1000U, TLS_MAX_RECORD_SIZE - 1U, TLS_MAX_RECORD_SIZE, TLS_MAX_RECORD_SIZE + 1U,
    65536U + 7U
};

static int data_matrix(lb_pair_t *pair, uint32_t rx_chunk)
{
    uint32_t i;
    LB_RUN(lb_transfer(pair, 1, s_payload, 0U, TLS_MAX_RECORD_SIZE, 64U));
    LB_RUN(lb_transfer(pair, 0, s_payload, 0U, TLS_MAX_RECORD_SIZE, 64U));
    for(i = 0U; i < (uint32_t)(sizeof(k_sizes) / sizeof(k_sizes[0])); i++) {
        uint32_t size = k_sizes[i];
        uint32_t rx = (rx_chunk == 0U) ? size : rx_chunk;
        lb_fill_pattern(s_payload, size, size);
        if(lb_transfer(pair, 1, s_payload, size, TLS_MAX_RECORD_SIZE, rx) != 0) {
            lb_log("client->server size %u rx_chunk %u failed", size, rx);
            return 1;
        }
        lb_fill_pattern(s_payload, size, size + 1U);
        if(lb_transfer(pair, 0, s_payload, size, TLS_MAX_RECORD_SIZE, rx) != 0) {
            lb_log("server->client size %u rx_chunk %u failed", size, rx);
            return 1;
        }
    }
    return 0;
}

static int small_exchange(lb_pair_t *pair)
{
    static const uint8_t c2s[] = "client hello data";
    static const uint8_t s2c[] = "server reply data!";
    LB_RUN(lb_transfer(pair, 1, c2s, sizeof(c2s), TLS_MAX_RECORD_SIZE, sizeof(c2s)));
    LB_RUN(lb_transfer(pair, 0, s2c, sizeof(s2c), TLS_MAX_RECORD_SIZE, sizeof(s2c)));
    return 0;
}

static int run_session(const lb_cfg_t *cfg, uint16_t expect_suite, int matrix)
{
    lb_pair_t pair;
    size_t base;

    LB_RUN(lb_trust_all_roots());
    base = lb_alloc_live_bytes();
    LB_RUN(lb_pair_init(&pair, cfg));
    if(lb_pair_handshake(&pair) != 0) {
        lb_log("handshake failed: client rc=%d server rc=%d", (int)pair.client.last_rc, (int)pair.server.last_rc);
        lb_pair_free(&pair);
        return 1;
    }
    LB_CHECK_EQ(lb_field_state(&pair.client), TLS_STATE_CONNECTED);
    LB_CHECK_EQ(lb_field_state(&pair.server), TLS_STATE_CONNECTED);
    if(expect_suite != 0U) {
        LB_CHECK_EQ(lb_end_cipher_suite(&pair.client), expect_suite);
        LB_CHECK_EQ(lb_end_cipher_suite(&pair.server), expect_suite);
    }
    LB_RUN(small_exchange(&pair));
    if(matrix != 0) {
        LB_RUN(data_matrix(&pair, 0U));
        LB_RUN(data_matrix(&pair, 100U));
    }
    LB_RUN(lb_close_and_observe(&pair, 1));
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "session");
}

static int expect_handshake_failure(const lb_cfg_t *cfg, noxtls_return_t client_rc, noxtls_return_t server_rc)
{
    lb_pair_t pair;
    size_t base = lb_alloc_live_bytes();

    LB_RUN(lb_pair_init(&pair, cfg));
    LB_CHECK(lb_pair_handshake(&pair) != 0);
    LB_CHECK(!((pair.client.done != 0) && (pair.server.done != 0)));
    if(client_rc != NOXTLS_RETURN_SUCCESS) {
        LB_CHECK_EQ(pair.client.last_rc, client_rc);
    }
    if(server_rc != NOXTLS_RETURN_SUCCESS) {
        LB_CHECK_EQ(pair.server.last_rc, server_rc);
    }
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "failed handshake");
}

static int run_suite(lb_auth_t auth, uint16_t suite, int matrix)
{
    lb_cfg_t cfg;
    uint16_t list[1];
    list[0] = suite;
    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    cfg.server_auth = auth;
    if(auth == LB_AUTH_RSA) {
        cfg.sni = "rsa.test";
    }
    cfg.server_suites = list;
    cfg.server_suite_count = 1U;
    return run_session(&cfg, suite, matrix);
}

/* ---- Cipher suites ------------------------------------------------------- */

static int t_ecdsa_aes128gcm(void) { return run_suite(LB_AUTH_ECDSA, TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 1); }
static int t_ecdsa_aes256gcm(void) { return run_suite(LB_AUTH_ECDSA, TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, 1); }
static int t_ecdsa_chacha20(void) { return run_suite(LB_AUTH_ECDSA, TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 1); }
static int t_ecdsa_aes128ccm(void) { return run_suite(LB_AUTH_ECDSA, TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM, 1); }
/* CBC-mode suites are negotiated only with NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES. */
#if NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES
#define LB_LEGACY_SUITE(auth, suite, matrix) run_suite((auth), (suite), (matrix))
#else
#define LB_LEGACY_SUITE(auth, suite, matrix) (LB_SKIP)
#endif
static int t_ecdsa_aes128cbc_sha256(void) { return LB_LEGACY_SUITE(LB_AUTH_ECDSA, TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, 1); }
static int t_ecdsa_aes256cbc_sha384(void) { return LB_LEGACY_SUITE(LB_AUTH_ECDSA, TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, 0); }
static int t_rsa_aes128gcm(void) { return run_suite(LB_AUTH_RSA, TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 1); }
static int t_rsa_aes256gcm(void) { return run_suite(LB_AUTH_RSA, TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384, 0); }
static int t_rsa_chacha20(void) { return run_suite(LB_AUTH_RSA, TLS_CIPHER_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 1); }
static int t_rsa_aes128cbc_sha(void) { return LB_LEGACY_SUITE(LB_AUTH_RSA, TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA, 1); }

static int t_default_negotiation(void)
{
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    return run_session(&cfg, 0U, 0);
}

/* ---- Certificates -------------------------------------------------------- */

static int t_hostname_mismatch(void)
{
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    cfg.sni = "evil.test";
    LB_RUN(lb_trust_ec_root());
    return expect_handshake_failure(&cfg, NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_SUCCESS);
}

static int t_untrusted_ca(void)
{
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    cfg.server_auth = LB_AUTH_ROGUE;
    LB_RUN(lb_trust_ec_root());
    return expect_handshake_failure(&cfg, NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_SUCCESS);
}

static int t_missing_intermediate(void)
{
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    cfg.send_chain = 0;
    LB_RUN(lb_trust_ec_root());
    return expect_handshake_failure(&cfg, NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_SUCCESS);
}

static int t_mtls_ecdsa(void)
{
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    cfg.client_auth = 2;
    cfg.client_cert = LB_AUTH_ECDSA;
    return run_session(&cfg, 0U, 0);
}

static int t_mtls_rsa(void)
{
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    cfg.server_auth = LB_AUTH_RSA;
    cfg.sni = "rsa.test";
    cfg.client_auth = 2;
    cfg.client_cert = LB_AUTH_RSA;
    return run_session(&cfg, 0U, 0);
}

static int t_mtls_peer_certificate(void)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    const uint8_t *der = NULL;
    uint32_t der_len = 0U;
    const void *parsed = NULL;
    size_t base;

    LB_RUN(lb_trust_all_roots());
    base = lb_alloc_live_bytes();
    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    cfg.client_auth = 2;
    cfg.client_cert = LB_AUTH_ECDSA;
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_RUN(lb_pair_handshake(&pair));
    LB_RUN(small_exchange(&pair));
    /* The verified client leaf DER stays available after the handshake. */
    LB_CHECK_OK(noxtls_tls12_get_client_certificate(pair.server.t12, &der, &der_len, NULL));
    LB_CHECK_EQ(der_len, lb_ec_client_cert_len);
    LB_CHECK(memcmp(der, lb_ec_client_cert, der_len) == 0);
#if NOXTLS_TLS_RETAIN_PEER_CERT
    /* Retained: the parsed view is available and borrows the context DER. */
    LB_CHECK_OK(noxtls_tls12_get_client_certificate(pair.server.t12, &der, &der_len, &parsed));
    LB_CHECK(parsed != NULL);
    LB_CHECK(((const x509_certificate_t *)parsed)->raw_data == der);
    LB_CHECK(pair.client.t12->server_cert_parsed != NULL);
#else
    /* Not retained: a clear "not retained" result, the DER is still returned. */
    der = NULL;
    LB_CHECK_EQ(noxtls_tls12_get_client_certificate(pair.server.t12, &der, &der_len, &parsed),
                NOXTLS_RETURN_NOT_SUPPORTED);
    LB_CHECK(parsed == NULL);
    LB_CHECK((der != NULL) && (der_len == lb_ec_client_cert_len));
    LB_CHECK(pair.server.t12->client_cert_parsed == NULL);
    LB_CHECK(pair.client.t12->server_cert_parsed == NULL);
    /* Applications parse the DER on demand without heap. */
    {
        static x509_certificate_t view;
        LB_CHECK_OK(noxtls_x509_certificate_parse_der_nocopy(&view, der, der_len));
        LB_CHECK(noxtls_x509_certificate_san_count(&view, NOXTLS_X509_SAN_ANY) == view.san_dns_count);
        (void)noxtls_x509_certificate_free(&view);
    }
#endif
    LB_RUN(small_exchange(&pair));
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "peer certificate");
}

static int t_mtls_required_missing(void)
{
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    cfg.client_auth = 2;
    LB_RUN(lb_trust_all_roots());
    return expect_handshake_failure(&cfg, NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_CERT_REQUIRED);
}

/* ---- Resumption / renegotiation ------------------------------------------ */

static int t_ticket_resumption(void)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    uint32_t round;
    size_t base;

    LB_RUN(lb_trust_ec_root());
    base = lb_alloc_live_bytes();
    LB_CHECK_EQ(noxtls_tls12_client_session_has_ticket(), 0);
    for(round = 0U; round < 3U; round++) {
        lb_cfg_default(&cfg, LB_PROTO_TLS12);
        LB_RUN(lb_pair_init(&pair, &cfg));
        LB_RUN(lb_pair_handshake(&pair));
        /* First connection: full handshake that issues a ticket; later ones resume it. */
        LB_CHECK_EQ(lb_field_tls12_resumed(pair.client.t12), (round == 0U) ? 0 : 1);
        LB_CHECK_EQ(lb_field_tls12_resumed(pair.server.t12), (round == 0U) ? 0 : 1);
        LB_CHECK_EQ(noxtls_tls12_client_session_has_ticket(), 1);
        LB_RUN(small_exchange(&pair));
        LB_RUN(lb_close_and_observe(&pair, 1));
        lb_pair_free(&pair);
    }
    LB_CHECK(noxtls_tls12_client_session_ticket_len() > 0U);
    return lb_expect_no_leak(base, "ticket resumption");
}

static int t_secure_renegotiation_info(void)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    size_t base;

    LB_RUN(lb_trust_ec_root());
    base = lb_alloc_live_bytes();
    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_RUN(lb_pair_handshake(&pair));
    /* RFC 5746: both ends keep the Finished verify_data for renegotiation_info. */
    LB_CHECK_EQ(lb_field_tls12_reneg_len(pair.client.t12), 12U);
    LB_CHECK_EQ(lb_field_tls12_reneg_len(pair.server.t12), 12U);
    LB_RUN(small_exchange(&pair));
    /* The client declines a server HelloRequest with a warning; data keeps flowing. */
    LB_CHECK_OK(noxtls_tls12_send_hello_request(pair.server.t12));
    (void)lb_end_flush(&pair.server);
    lb_fill_pattern(s_payload, 2000U, 5U);
    LB_RUN(lb_transfer(&pair, 0, s_payload, 2000U, TLS_MAX_RECORD_SIZE, 2000U));
    LB_RUN(lb_transfer(&pair, 1, s_payload, 2000U, TLS_MAX_RECORD_SIZE, 2000U));
    LB_CHECK_EQ(lb_field_state(&pair.client), TLS_STATE_CONNECTED);
    LB_CHECK_EQ(lb_field_state(&pair.server), TLS_STATE_CONNECTED);
    LB_RUN(lb_close_and_observe(&pair, 0));
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "renegotiation");
}

/* ---- Extensions ----------------------------------------------------------- */

static int t_ocsp_stapling(void)
{
    static const uint8_t ocsp[] = { 0x30, 0x03, 0x0A, 0x01, 0x00 };
    lb_pair_t pair;
    lb_cfg_t cfg;
    const uint8_t *got = NULL;
    uint32_t got_len = 0U;
    size_t base;

    LB_RUN(lb_trust_ec_root());
    base = lb_alloc_live_bytes();
    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    LB_RUN(lb_pair_init(&pair, &cfg));
    noxtls_tls12_set_client_request_ocsp_status(pair.client.t12, 1);
    noxtls_tls12_set_server_ocsp_response(pair.server.t12, ocsp, (uint32_t)sizeof(ocsp));
    LB_RUN(lb_pair_handshake(&pair));
    LB_CHECK_OK(noxtls_tls12_get_peer_ocsp_response(pair.client.t12, &got, &got_len));
    LB_CHECK_EQ(got_len, sizeof(ocsp));
    LB_CHECK(memcmp(got, ocsp, sizeof(ocsp)) == 0);
    LB_RUN(small_exchange(&pair));
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "ocsp");
}

static int t_max_fragment_length(void)
{
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    cfg.max_fragment_code = 2U; /* 1024-byte records */
    return run_session(&cfg, 0U, 1);
}

/* ---- Application data framing -------------------------------------------- */

static int t_data_small_reads(void)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    uint32_t i;
    size_t base;

    LB_RUN(lb_trust_ec_root());
    base = lb_alloc_live_bytes();
    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_RUN(lb_pair_handshake(&pair));
    lb_fill_pattern(s_payload, TLS_MAX_RECORD_SIZE, 9U);
    for(i = 1U; i <= 7U; i += 3U) {
        LB_RUN(lb_transfer(&pair, 1, s_payload, 4000U, TLS_MAX_RECORD_SIZE, i));
        LB_RUN(lb_transfer(&pair, 0, s_payload, 4000U, TLS_MAX_RECORD_SIZE, i));
    }
    LB_RUN(lb_transfer(&pair, 0, s_payload, TLS_MAX_RECORD_SIZE, TLS_MAX_RECORD_SIZE, 1000U));
    LB_RUN(lb_transfer(&pair, 1, s_payload, 5000U, 13U, 5000U));
    LB_RUN(lb_close_and_observe(&pair, 0));
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "small reads");
}

static int t_data_interleaved(void)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    uint8_t a[700];
    uint8_t b[900];
    uint8_t buf[1000];
    uint32_t i;
    size_t base;

    LB_RUN(lb_trust_ec_root());
    base = lb_alloc_live_bytes();
    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_RUN(lb_pair_handshake(&pair));
    for(i = 0U; i < 40U; i++) {
        uint32_t la = 1U + ((i * 37U) % sizeof(a));
        uint32_t lbn = 1U + ((i * 53U) % sizeof(b));
        uint32_t len;
        lb_fill_pattern(a, la, i);
        lb_fill_pattern(b, lbn, i + 1000U);
        LB_CHECK_OK(lb_end_send(&pair.client, a, la));
        LB_CHECK_OK(lb_end_send(&pair.server, b, lbn));
        (void)lb_end_flush(&pair.client);
        (void)lb_end_flush(&pair.server);
        len = sizeof(buf);
        LB_CHECK_OK(lb_recv_some(&pair, &pair.server, buf, &len));
        LB_CHECK_EQ(len, la);
        LB_CHECK(memcmp(buf, a, la) == 0);
        len = sizeof(buf);
        LB_CHECK_OK(lb_recv_some(&pair, &pair.client, buf, &len));
        LB_CHECK_EQ(len, lbn);
        LB_CHECK(memcmp(buf, b, lbn) == 0);
    }
    LB_RUN(lb_close_and_observe(&pair, 1));
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "interleaved");
}

static int t_fragmented_transport(void)
{
    static const uint32_t chunks[] = { 1U, 7U, 1400U };
    uint32_t i;
    for(i = 0U; i < 3U; i++) {
        lb_cfg_t cfg;
        lb_cfg_default(&cfg, LB_PROTO_TLS12);
        cfg.max_chunk = chunks[i];
        cfg.block_every = (i == 1U) ? 3U : 0U;
        if(run_session(&cfg, 0U, (i == 2U) ? 1 : 0) != 0) {
            lb_log("fragmented transport max_chunk=%u failed", chunks[i]);
            return 1;
        }
        lb_trust_clear();
    }
    return 0;
}

static int t_alloc_failure_sweep(void)
{
    size_t n;
    size_t base = lb_alloc_live_bytes();
    LB_RUN(lb_trust_ec_root());
    g_lb_quiet = 1;
    for(n = 0U; n < 2000U; n++) {
        lb_pair_t pair;
        lb_cfg_t cfg;
        int hs = 1;
        lb_cfg_default(&cfg, LB_PROTO_TLS12);
        lb_alloc_reset_counters();
        lb_alloc_fail_after(n);
        if(lb_pair_init(&pair, &cfg) == 0) {
            hs = lb_pair_handshake(&pair);
        }
        lb_alloc_fail_after(SIZE_MAX);
        if((hs == 0) && (lb_alloc_failed_calls() == 0U)) {
            g_lb_quiet = 0;
            LB_RUN(small_exchange(&pair));
            lb_pair_free(&pair);
            lb_log("swept %lu allocation points", (unsigned long)n);
            lb_trust_clear();
            return lb_expect_no_leak(base, "alloc sweep");
        }
        lb_pair_free(&pair);
        lb_trust_clear();
        if(lb_alloc_live_bytes() != base) {
            g_lb_quiet = 0;
            lb_log("leak after failing allocation #%lu", (unsigned long)n);
            return lb_expect_no_leak(base, "alloc failure");
        }
        LB_RUN(lb_trust_ec_root());
    }
    return 1;
}

/* ---- Running transcript hashes: CertificateVerify hash != PRF hash, EMS --- */

/*
 * The TLS 1.2 transcript is kept as running hash states only. These cases pin the paths where
 * the CertificateVerify hash differs from the PRF hash (the client keeps both states between
 * ServerHello and CertificateVerify, the server between ClientHello and CertificateVerify), the
 * extended master secret session_hash, and that no transcript state outlives the handshake.
 */
static int run_mtls_cv(lb_proto_t proto, lb_auth_t auth, uint16_t suite, uint16_t expect_cv)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    uint16_t list[1];
    size_t base;

    LB_RUN(lb_trust_all_roots());
    base = lb_alloc_live_bytes();
    lb_cfg_default(&cfg, proto);
    cfg.server_auth = auth;
    if(auth == LB_AUTH_RSA) {
        cfg.sni = "rsa.test";
    }
    list[0] = suite;
    cfg.server_suites = list;
    cfg.server_suite_count = 1U;
    cfg.client_auth = 2;
    cfg.client_cert = auth;
    LB_RUN(lb_pair_init(&pair, &cfg));
    if(lb_pair_handshake(&pair) != 0) {
        lb_log("handshake failed: client rc=%d server rc=%d", (int)pair.client.last_rc, (int)pair.server.last_rc);
        lb_pair_free(&pair);
        return 1;
    }
    LB_CHECK_EQ(lb_end_cipher_suite(&pair.client), suite);
    LB_CHECK_EQ(lb_field_tls12_cv_scheme(pair.client.t12), expect_cv);
    LB_CHECK_EQ(lb_field_tls12_ems(pair.client.t12), 1);
    LB_CHECK_EQ(lb_field_tls12_ems(pair.server.t12), 1);
    LB_CHECK_EQ(lb_field_tls12_transcript_live(pair.client.t12), 0);
    LB_CHECK_EQ(lb_field_tls12_transcript_live(pair.server.t12), 0);
    LB_RUN(small_exchange(&pair));
    LB_RUN(lb_close_and_observe(&pair, 1));
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "mtls cv");
}

/* SHA-384 PRF, ecdsa_secp256r1_sha256 client CertificateVerify. */
static int t_mtls_ecdsa_cv_sha256_prf_sha384(void)
{
    return run_mtls_cv(LB_PROTO_TLS12, LB_AUTH_ECDSA, TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, 0x0403U);
}

/* SHA-384 PRF, rsa_pkcs1_sha256 client CertificateVerify. */
static int t_mtls_rsa_cv_sha256_prf_sha384(void)
{
    return run_mtls_cv(LB_PROTO_TLS12, LB_AUTH_RSA, TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384, 0x0401U);
}

/* CBC SHA-384 suite (MAC-then-encrypt record path) with an ECDSA client certificate
 * (legacy suites build only). */
static int t_mtls_ecdsa_cbc_sha384(void)
{
#if NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES
    return run_mtls_cv(LB_PROTO_TLS12, LB_AUTH_ECDSA, TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, 0x0403U);
#else
    return LB_SKIP;
#endif
}

/* SHA-256 PRF, CertificateVerify hash equal to the PRF hash. */
static int t_mtls_ecdsa_cv_same_hash(void)
{
    return run_mtls_cv(LB_PROTO_TLS12, LB_AUTH_ECDSA, TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0x0403U);
}

/* Client authentication requested, no client certificate: the CV states are dropped. */
static int t_mtls_optional_no_cert(void)
{
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    cfg.client_auth = 1;
    return run_session(&cfg, 0U, 0);
}

static int run_ems(int client_no_ems, int expect_ems)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    size_t base;

    LB_RUN(lb_trust_ec_root());
    base = lb_alloc_live_bytes();
    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    cfg.tls12_client_no_ems = client_no_ems;
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_RUN(lb_pair_handshake(&pair));
    LB_CHECK_EQ(lb_field_tls12_ems(pair.client.t12), expect_ems);
    LB_CHECK_EQ(lb_field_tls12_ems(pair.server.t12), expect_ems);
    LB_CHECK_EQ(lb_field_tls12_transcript_live(pair.client.t12), 0);
    LB_CHECK_EQ(lb_field_tls12_transcript_live(pair.server.t12), 0);
    LB_RUN(small_exchange(&pair));
    LB_RUN(data_matrix(&pair, 0U));
    LB_RUN(lb_close_and_observe(&pair, 1));
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "ems");
}

static int t_ems_on(void) { return run_ems(0, 1); }
static int t_ems_off(void) { return run_ems(1, 0); }

/*
 * RFC 7627 5.3 with tickets: an EMS session resumes with EMS; a session without EMS is not
 * resumed by an EMS-offering client (full handshake); a client that stops offering EMS cannot
 * resume an EMS session (the server aborts).
 */
static int ems_connect(int client_no_ems, int expect_resumed, int expect_ok)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    int hs;

    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    cfg.tls12_client_no_ems = client_no_ems;
    LB_RUN(lb_pair_init(&pair, &cfg));
    hs = lb_pair_handshake(&pair);
    if(expect_ok == 0) {
        LB_CHECK(hs != 0);
        lb_pair_free(&pair);
        return 0;
    }
    LB_CHECK_EQ(hs, 0);
    LB_CHECK_EQ(lb_field_tls12_resumed(pair.client.t12), expect_resumed);
    LB_CHECK_EQ(lb_field_tls12_resumed(pair.server.t12), expect_resumed);
    LB_CHECK_EQ(lb_field_tls12_ems(pair.client.t12), (client_no_ems != 0) ? 0 : 1);
    LB_CHECK_EQ(lb_field_tls12_ems(pair.server.t12), (client_no_ems != 0) ? 0 : 1);
    LB_RUN(small_exchange(&pair));
    LB_RUN(lb_close_and_observe(&pair, 1));
    lb_pair_free(&pair);
    return 0;
}

static int t_ems_resumption(void)
{
    size_t base;

    LB_RUN(lb_trust_ec_root());
    base = lb_alloc_live_bytes();
    LB_RUN(ems_connect(0, 0, 1));   /* full handshake with EMS, ticket issued */
    LB_RUN(ems_connect(0, 1, 1));   /* resumed with EMS */
    LB_RUN(ems_connect(1, 0, 0));   /* EMS session, client without EMS: aborted */
    return lb_expect_no_leak(base, "ems resumption");
}

static int t_ems_resumption_upgrade(void)
{
    size_t base;

    LB_RUN(lb_trust_ec_root());
    base = lb_alloc_live_bytes();
    LB_RUN(ems_connect(1, 0, 1));   /* full handshake without EMS, ticket issued */
    LB_RUN(ems_connect(1, 1, 1));   /* resumed without EMS */
    LB_RUN(ems_connect(0, 0, 1));   /* EMS offered: the non-EMS session is not resumed */
    LB_RUN(ems_connect(0, 1, 1));   /* the new EMS session resumes */
    return lb_expect_no_leak(base, "ems resumption upgrade");
}

/* TLS 1.0 / 1.1 (when built): MD5 || SHA-1 transcript for Finished, RSA key exchange, CBC. */
static int run_legacy_version(uint16_t version)
{
    lb_cfg_t cfg;
    uint16_t list[1];
    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    cfg.tls12_version = version;
    cfg.server_auth = LB_AUTH_RSA;
    cfg.sni = "rsa.test";
    list[0] = TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA;
    cfg.server_suites = list;
    cfg.server_suite_count = 1U;
    return run_session(&cfg, TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA, 1);
}

static int t_tls10_handshake(void)
{
#if NOXTLS_FEATURE_TLS10 && NOXTLS_FEATURE_MD5 && NOXTLS_FEATURE_SHA1
    return run_legacy_version(TLS_VERSION_1_0);
#else
    (void)run_legacy_version;
    return LB_SKIP;
#endif
}

static int t_tls11_handshake(void)
{
#if NOXTLS_FEATURE_TLS11 && NOXTLS_FEATURE_MD5 && NOXTLS_FEATURE_SHA1
    return run_legacy_version(TLS_VERSION_1_1);
#else
    (void)run_legacy_version;
    return LB_SKIP;
#endif
}

/* Allocation failures across a mutual-TLS handshake with two transcript hashes (SHA-384 PRF,
 * SHA-256 CertificateVerify): every failure must be clean and leak-free. */
static int t_alloc_failure_sweep_mtls(void)
{
    static const uint16_t suite = TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
    size_t n;
    size_t base = lb_alloc_live_bytes();
    LB_RUN(lb_trust_all_roots());
    g_lb_quiet = 1;
    for(n = 0U; n < 3000U; n++) {
        lb_pair_t pair;
        lb_cfg_t cfg;
        int hs = 1;
        lb_cfg_default(&cfg, LB_PROTO_TLS12);
        cfg.server_suites = &suite;
        cfg.server_suite_count = 1U;
        cfg.client_auth = 2;
        cfg.client_cert = LB_AUTH_ECDSA;
        lb_alloc_reset_counters();
        lb_alloc_fail_after(n);
        if(lb_pair_init(&pair, &cfg) == 0) {
            hs = lb_pair_handshake(&pair);
        }
        lb_alloc_fail_after(SIZE_MAX);
        if((hs == 0) && (lb_alloc_failed_calls() == 0U)) {
            g_lb_quiet = 0;
            LB_RUN(small_exchange(&pair));
            lb_pair_free(&pair);
            lb_log("swept %lu allocation points", (unsigned long)n);
            lb_trust_clear();
            return lb_expect_no_leak(base, "alloc sweep mtls");
        }
        lb_pair_free(&pair);
        lb_trust_clear();
        if(lb_alloc_live_bytes() != base) {
            g_lb_quiet = 0;
            lb_log("leak after failing allocation #%lu", (unsigned long)n);
            return lb_expect_no_leak(base, "alloc failure mtls");
        }
        LB_RUN(lb_trust_all_roots());
    }
    return 1;
}

/* ---- Legacy policy: CBC / static-RSA / 3DES suites and SHA-1 signatures ---------------
 *
 * Default build: TLS 1.2 offers and negotiates only forward-secret AEAD suites and never offers,
 * signs or accepts a SHA-1 signature. The peer that would need a legacy algorithm is played by
 * the test: it reads what the NoxTLS endpoint sent from the link and writes hand-made handshake
 * records back. With NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES / NOXTLS_TLS12_ENABLE_SHA1_SIGNATURES
 * the same tests check that the legacy behaviour is still available. */

#define LB_REC_ALERT      21U
#define LB_REC_HANDSHAKE  22U
#define LB_HS_CLIENT_HELLO   1U
#define LB_HS_SERVER_HELLO   2U
#define LB_HS_SERVER_KX      12U
#define LB_ALERT_HANDSHAKE_FAILURE 40U
#define LB_ALERT_ILLEGAL_PARAMETER 47U
#define LB_FLIGHT_MAX (64U * 1024U)

static uint8_t s_flight[LB_FLIGHT_MAX];
static uint8_t s_hs[LB_FLIGHT_MAX];

/* The default TLS 1.2 suite offer: ECDHE-ECDSA / ECDHE-RSA / DHE-RSA with AES-GCM,
 * ChaCha20-Poly1305, AES-CCM and AES-CCM_8. */
static const uint16_t k_fs_aead_suites[] = {
    TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_CIPHER_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_CIPHER_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM,
    TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM,
    TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM_8,
    TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM_8,
    TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM,
    TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM,
    TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM_8,
    TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM_8
};

/* CBC-mode, static-RSA key exchange and 3DES suites (none of them may be negotiated by default). */
static const uint16_t k_legacy_suites[] = {
    TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_CIPHER_SUITE_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_CIPHER_SUITE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM,
    TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA,
    TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256,
    TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA
};

static int suite_in(uint16_t suite, const uint16_t *list, size_t count)
{
    size_t i;
    for(i = 0U; i < count; i++) {
        if(list[i] == suite) {
            return 1;
        }
    }
    return 0;
}

static uint32_t rd16(const uint8_t *p) { return ((uint32_t)p[0] << 8U) | (uint32_t)p[1]; }
static uint32_t rd24(const uint8_t *p) { return ((uint32_t)p[0] << 16U) | ((uint32_t)p[1] << 8U) | (uint32_t)p[2]; }
static void wr16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 8U); p[1] = (uint8_t)v; }
static void wr24(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 16U); p[1] = (uint8_t)(v >> 8U); p[2] = (uint8_t)v; }

/** Take everything one endpoint has written to the link (to_client: what the server sent). */
static uint32_t drain_link(lb_pair_t *pair, int to_client)
{
    lb_port_t *reader = (to_client != 0) ? &pair->link->client_port : &pair->link->server_port;
    uint32_t len = 0U;
    for(;;) {
        int32_t n = lb_io_recv(reader, &s_flight[len], LB_FLIGHT_MAX - len);
        if(n <= 0) {
            break;
        }
        len += (uint32_t)n;
    }
    return len;
}

/** Write one TLS record (as the peer of the endpoint that reads it). */
static int inject_record(lb_pair_t *pair, int to_client, uint8_t type, const uint8_t *body, uint32_t len)
{
    lb_port_t *writer = (to_client != 0) ? &pair->link->server_port : &pair->link->client_port;
    uint8_t hdr[5];
    hdr[0] = type;
    hdr[1] = 0x03U;
    hdr[2] = 0x03U;
    wr16(&hdr[3], len);
    LB_CHECK_EQ(lb_io_send(writer, hdr, 5U), 5);
    LB_CHECK_EQ(lb_io_send(writer, body, len), (long)len);
    return 0;
}

/** Description of the first alert record in s_flight[0..len), or -1. */
static int flight_alert(uint32_t len)
{
    uint32_t o = 0U;
    while((o + 5U) <= len) {
        uint32_t rl = rd16(&s_flight[o + 3U]);
        if((s_flight[o] == LB_REC_ALERT) && (rl >= 2U) && ((o + 5U + 2U) <= len)) {
            return (int)s_flight[o + 6U];
        }
        o += 5U + rl;
    }
    return -1;
}

/** Find handshake message @p type in the plaintext handshake records of s_flight[0..len). */
static const uint8_t *flight_handshake(uint32_t len, uint8_t type, uint32_t *body_len)
{
    uint32_t o = 0U;
    uint32_t hs_len = 0U;
    while((o + 5U) <= len) {
        uint32_t rl = rd16(&s_flight[o + 3U]);
        if((o + 5U + rl) > len) {
            break;
        }
        if(s_flight[o] == LB_REC_HANDSHAKE) {
            memcpy(&s_hs[hs_len], &s_flight[o + 5U], rl);
            hs_len += rl;
        } else {
            break; /* ChangeCipherSpec / alert: the rest is not plaintext handshake */
        }
        o += 5U + rl;
    }
    o = 0U;
    while((o + 4U) <= hs_len) {
        uint32_t ml = rd24(&s_hs[o + 1U]);
        if((o + 4U + ml) > hs_len) {
            break;
        }
        if(s_hs[o] == type) {
            *body_len = ml;
            return &s_hs[o + 4U];
        }
        o += 4U + ml;
    }
    return NULL;
}

/** Step an endpoint until it stops making progress; returns the last result. */
static noxtls_return_t step_until_blocked(lb_end_t *end)
{
    noxtls_return_t rc = NOXTLS_RETURN_WANT_READ;
    int i;
    for(i = 0; i < 16; i++) {
        rc = lb_end_step(end);
        if(rc != NOXTLS_RETURN_WANT_WRITE) {
            break;
        }
    }
    return rc;
}

/**
 * Build a TLS 1.2 ClientHello handshake message offering @p suites and, when @p nsig > 0,
 * signature_algorithms @p sigalgs (nsig == 0 omits the extension, RFC 5246 7.4.1.4.1 default).
 */
static uint32_t build_client_hello(uint8_t *out, const uint16_t *suites, uint32_t nsuites,
                                   const uint16_t *sigalgs, uint32_t nsig)
{
    static const uint8_t k_ext_common[] = {
        0x00U, 0x0AU, 0x00U, 0x08U, 0x00U, 0x06U, 0x00U, 0x1DU, 0x00U, 0x17U, 0x00U, 0x18U, /* groups */
        0x00U, 0x0BU, 0x00U, 0x02U, 0x01U, 0x00U,                                           /* point formats */
        0x00U, 0x17U, 0x00U, 0x00U,                                                         /* extended_master_secret */
        0xFFU, 0x01U, 0x00U, 0x01U, 0x00U                                                   /* renegotiation_info */
    };
    uint32_t o = 4U;
    uint32_t ext_start;
    uint32_t i;

    out[0] = LB_HS_CLIENT_HELLO;
    out[o++] = 0x03U;
    out[o++] = 0x03U;
    lb_fill_pattern(&out[o], 32U, 0xC1U);
    o += 32U;
    out[o++] = 0x00U; /* session_id */
    wr16(&out[o], nsuites * 2U);
    o += 2U;
    for(i = 0U; i < nsuites; i++) {
        wr16(&out[o], suites[i]);
        o += 2U;
    }
    out[o++] = 0x01U;
    out[o++] = 0x00U; /* null compression */
    ext_start = o;
    o += 2U;
    memcpy(&out[o], k_ext_common, sizeof(k_ext_common));
    o += (uint32_t)sizeof(k_ext_common);
    if(nsig > 0U) {
        wr16(&out[o], 0x000DU);
        wr16(&out[o + 2U], 2U + (nsig * 2U));
        wr16(&out[o + 4U], nsig * 2U);
        o += 6U;
        for(i = 0U; i < nsig; i++) {
            wr16(&out[o], sigalgs[i]);
            o += 2U;
        }
    }
    wr16(&out[ext_start], o - ext_start - 2U);
    wr24(&out[1], o - 4U);
    return o;
}

/**
 * Send a hand-made ClientHello to a NoxTLS TLS 1.2 server.
 * @p expect_selected 0: the server must refuse with a fatal handshake_failure alert;
 * otherwise it must answer with a ServerHello for that suite (and, if @p expect_skx_scheme is
 * non-zero, a ServerKeyExchange signed with that scheme).
 */
static int server_vs_client_hello(lb_auth_t auth, const uint16_t *allowlist, uint32_t allow_count,
                                  const uint16_t *suites, uint32_t nsuites,
                                  const uint16_t *sigalgs, uint32_t nsig,
                                  uint16_t expect_selected, uint16_t expect_skx_scheme)
{
    static uint8_t ch[1024];
    lb_pair_t pair;
    lb_cfg_t cfg;
    uint32_t ch_len;
    uint32_t len;
    noxtls_return_t rc;
    size_t base = lb_alloc_live_bytes();

    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    cfg.server_auth = auth;
    cfg.server_suites = allowlist;
    cfg.server_suite_count = allow_count;
    LB_RUN(lb_pair_init(&pair, &cfg));
    ch_len = build_client_hello(ch, suites, nsuites, sigalgs, nsig);
    LB_RUN(inject_record(&pair, 0, LB_REC_HANDSHAKE, ch, ch_len));
    rc = step_until_blocked(&pair.server);
    len = drain_link(&pair, 1);
    if(expect_selected == 0U) {
        LB_CHECK(rc != NOXTLS_RETURN_SUCCESS);
        LB_CHECK(rc != NOXTLS_RETURN_WANT_READ);
        LB_CHECK_EQ(flight_alert(len), LB_ALERT_HANDSHAKE_FAILURE);
        LB_CHECK(flight_handshake(len, LB_HS_SERVER_HELLO, &ch_len) == NULL);
    } else {
        const uint8_t *sh;
        uint32_t sh_len = 0U;
        LB_CHECK_EQ(rc, NOXTLS_RETURN_WANT_READ);
        sh = flight_handshake(len, LB_HS_SERVER_HELLO, &sh_len);
        LB_CHECK(sh != NULL);
        LB_CHECK(sh_len >= 38U);
        LB_CHECK_EQ(rd16(&sh[35U + sh[34U]]), expect_selected);
        if(expect_skx_scheme != 0U) {
            uint32_t skx_len = 0U;
            const uint8_t *skx = flight_handshake(len, LB_HS_SERVER_KX, &skx_len);
            LB_CHECK(skx != NULL);
            /* ECParameters: named_curve(3) group(2) || point<1..255> || SignatureAndHashAlgorithm */
            LB_CHECK(skx_len > 6U);
            LB_CHECK_EQ(skx[0], 3U);
            LB_CHECK((uint32_t)(4U + skx[3U] + 2U) <= skx_len);
            LB_CHECK_EQ(rd16(&skx[4U + skx[3U]]), expect_skx_scheme);
        }
    }
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "hand-made ClientHello");
}

/* The NoxTLS TLS 1.2 ClientHello offers no CBC / static-RSA / 3DES suite and no SHA-1 / MD5
 * signature scheme (TLS 1.2 client and the TLS 1.2 part of the unified client's ClientHello). */
static int check_client_hello_offer(lb_proto_t proto)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    const uint8_t *ch;
    uint32_t ch_len = 0U;
    uint32_t len;
    uint32_t o;
    uint32_t n;
    uint32_t i;
    uint32_t aead = 0U;
    uint32_t legacy = 0U;
    uint32_t sha1_sigs = 0U;
    int saw_sigalgs = 0;
    size_t base = lb_alloc_live_bytes();

    lb_cfg_default(&cfg, proto);
    LB_RUN(lb_pair_init(&pair, &cfg));
    (void)step_until_blocked(&pair.client);
    len = drain_link(&pair, 0);
    ch = flight_handshake(len, LB_HS_CLIENT_HELLO, &ch_len);
    LB_CHECK(ch != NULL);
    o = 2U + 32U;
    o += 1U + ch[o];
    n = rd16(&ch[o]);
    o += 2U;
    for(i = 0U; i < n; i += 2U) {
        uint16_t cs = (uint16_t)rd16(&ch[o + i]);
        if(suite_in(cs, k_fs_aead_suites, sizeof(k_fs_aead_suites) / sizeof(k_fs_aead_suites[0])) != 0) {
            aead++;
        } else if((cs >= 0x1300U) && (cs <= 0x13FFU)) {
            /* TLS 1.3 suite (unified ClientHello) */
        } else if((cs == TLS_CIPHER_SUITE_EMPTY_RENEGOTIATION_INFO_SCSV) || (cs == TLS_CIPHER_SUITE_FALLBACK_SCSV)) {
            /* signalling value */
        } else {
            legacy++;
            if(NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES == 0) {
                lb_log("unexpected suite 0x%04X in the ClientHello", (unsigned)cs);
            }
        }
    }
    o += n;
    o += 1U + ch[o];
    if((o + 2U) <= ch_len) {
        uint32_t end = o + 2U + rd16(&ch[o]);
        o += 2U;
        while((o + 4U) <= end) {
            uint32_t et = rd16(&ch[o]);
            uint32_t el = rd16(&ch[o + 2U]);
            if(et == 0x000DU) {
                uint32_t sl = rd16(&ch[o + 4U]);
                saw_sigalgs = 1;
                for(i = 0U; i < sl; i += 2U) {
                    uint32_t hash = ch[o + 6U + i];
                    uint32_t sig = ch[o + 7U + i];
                    if((sig <= 3U) && ((hash == 1U) || (hash == 2U))) {
                        LB_CHECK(hash == 2U); /* MD5 is never offered */
                        sha1_sigs++;
                    }
                }
            }
            o += 4U + el;
        }
    }
    lb_pair_free(&pair);
    LB_CHECK(aead > 0U);
    LB_CHECK(saw_sigalgs != 0);
    if(proto == LB_PROTO_TLS12) {
        /* Every forward-secret AEAD suite of the default list is offered. */
        LB_CHECK_EQ(aead, sizeof(k_fs_aead_suites) / sizeof(k_fs_aead_suites[0]));
        LB_CHECK_EQ(sha1_sigs, (NOXTLS_TLS12_SHA1_SIGNATURES != 0) ? 2U : 0U);
    } else {
        LB_CHECK_EQ(sha1_sigs, 0U); /* the TLS 1.3 signature_algorithms list has no SHA-1 */
    }
    if(NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES != 0) {
        LB_CHECK(legacy > 0U);
    } else {
        LB_CHECK_EQ(legacy, 0U);
    }
    return lb_expect_no_leak(base, "ClientHello offer");
}

static int t_client_hello_no_legacy_offer(void)
{
    LB_RUN(check_client_hello_offer(LB_PROTO_TLS12));
#if NOXTLS_FEATURE_TLS13
    LB_RUN(check_client_hello_offer(LB_PROTO_UNIFIED));
#endif
    return 0;
}

/* A client that offers only CBC / static-RSA / 3DES suites gets handshake_failure, also when
 * the application allowlist names those suites (RSA and ECDSA server keys). */
static int t_server_rejects_legacy_only_client(void)
{
    static const uint16_t sig[] = { 0x0401U, 0x0403U, 0x0804U };
    const uint32_t nl = (uint32_t)(sizeof(k_legacy_suites) / sizeof(k_legacy_suites[0]));
#if NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES
    /* Legacy build: the server's first preferred suite that the client offered is selected. */
    LB_RUN(server_vs_client_hello(LB_AUTH_RSA, NULL, 0U, k_legacy_suites, nl, sig, 3U,
                                  TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM, 0U));
    LB_RUN(server_vs_client_hello(LB_AUTH_ECDSA, NULL, 0U, k_legacy_suites, nl, sig, 3U,
                                  TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, 0U));
    LB_RUN(server_vs_client_hello(LB_AUTH_RSA, &k_legacy_suites[8], 1U, k_legacy_suites, nl, sig, 3U,
                                  TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA, 0U));
#else
    LB_RUN(server_vs_client_hello(LB_AUTH_RSA, NULL, 0U, k_legacy_suites, nl, sig, 3U, 0U, 0U));
    LB_RUN(server_vs_client_hello(LB_AUTH_ECDSA, NULL, 0U, k_legacy_suites, nl, sig, 3U, 0U, 0U));
    /* An application allowlist cannot re-enable them. */
    LB_RUN(server_vs_client_hello(LB_AUTH_RSA, k_legacy_suites, nl, k_legacy_suites, nl, sig, 3U, 0U, 0U));
    LB_RUN(server_vs_client_hello(LB_AUTH_ECDSA, k_legacy_suites, nl, k_legacy_suites, nl, sig, 3U, 0U, 0U));
#endif
    /* Mixed offer, legacy suites first: the forward-secret AEAD suite is chosen by default. */
    {
        static const uint16_t mixed[] = {
            TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA,
            TLS_CIPHER_SUITE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        };
        static const uint16_t allow[] = {
            TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA,
            TLS_CIPHER_SUITE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        };
        LB_RUN(server_vs_client_hello(LB_AUTH_RSA, allow, 3U, mixed, 3U, sig, 3U,
                                      (NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES != 0) ?
                                      TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA :
                                      TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0U));
    }
    return 0;
}

/* signature_algorithms listing only SHA-1 schemes, or no signature_algorithms at all (RFC 5246
 * implicit SHA-1): handshake_failure by default, a SHA-1 ServerKeyExchange with
 * NOXTLS_TLS12_ENABLE_SHA1_SIGNATURES (RSA and ECDSA server keys). */
static int t_server_rejects_sha1_signature_algorithms(void)
{
    static const uint16_t sha1_only[] = { 0x0201U, 0x0203U };
    static const uint16_t rsa_suite[] = { TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256 };
    static const uint16_t ec_suite[] = { TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 };
#if NOXTLS_TLS12_SHA1_SIGNATURES
    LB_RUN(server_vs_client_hello(LB_AUTH_RSA, NULL, 0U, rsa_suite, 1U, sha1_only, 2U, rsa_suite[0], 0x0201U));
    LB_RUN(server_vs_client_hello(LB_AUTH_ECDSA, NULL, 0U, ec_suite, 1U, sha1_only, 2U, ec_suite[0], 0x0203U));
    /* Extension omitted: RSA signs with SHA-1; ECDSA keeps the suite hash (behaviour before
     * the SHA-1 switch existed). */
    LB_RUN(server_vs_client_hello(LB_AUTH_RSA, NULL, 0U, rsa_suite, 1U, NULL, 0U, rsa_suite[0], 0x0201U));
    LB_RUN(server_vs_client_hello(LB_AUTH_ECDSA, NULL, 0U, ec_suite, 1U, NULL, 0U, ec_suite[0], 0x0403U));
#else
    LB_RUN(server_vs_client_hello(LB_AUTH_RSA, NULL, 0U, rsa_suite, 1U, sha1_only, 2U, 0U, 0U));
    LB_RUN(server_vs_client_hello(LB_AUTH_ECDSA, NULL, 0U, ec_suite, 1U, sha1_only, 2U, 0U, 0U));
    LB_RUN(server_vs_client_hello(LB_AUTH_RSA, NULL, 0U, rsa_suite, 1U, NULL, 0U, 0U, 0U));
    LB_RUN(server_vs_client_hello(LB_AUTH_ECDSA, NULL, 0U, ec_suite, 1U, NULL, 0U, 0U, 0U));
#endif
    /* SHA-1 listed first, SHA-256 after it: the server always picks a SHA-256 scheme by default. */
    {
        static const uint16_t mixed[] = { 0x0201U, 0x0203U, 0x0401U, 0x0403U };
        LB_RUN(server_vs_client_hello(LB_AUTH_RSA, NULL, 0U, rsa_suite, 1U, mixed, 4U, rsa_suite[0],
                                      (NOXTLS_TLS12_SHA1_SIGNATURES != 0) ? 0x0201U : 0x0401U));
        LB_RUN(server_vs_client_hello(LB_AUTH_ECDSA, NULL, 0U, ec_suite, 1U, mixed, 4U, ec_suite[0],
                                      (NOXTLS_TLS12_SHA1_SIGNATURES != 0) ? 0x0203U : 0x0403U));
    }
    return 0;
}

/** Build a ServerHello handshake message selecting @p suite (renegotiation_info + EMS acked). */
static uint32_t build_server_hello(uint8_t *out, uint16_t suite)
{
    static const uint8_t k_ext[] = { 0xFFU, 0x01U, 0x00U, 0x01U, 0x00U, 0x00U, 0x17U, 0x00U, 0x00U };
    uint32_t o = 4U;
    out[0] = LB_HS_SERVER_HELLO;
    out[o++] = 0x03U;
    out[o++] = 0x03U;
    lb_fill_pattern(&out[o], 32U, 0x5EU);
    o += 32U;
    out[o++] = 0x00U;
    wr16(&out[o], suite);
    o += 2U;
    out[o++] = 0x00U;
    wr16(&out[o], (uint32_t)sizeof(k_ext));
    o += 2U;
    memcpy(&out[o], k_ext, sizeof(k_ext));
    o += (uint32_t)sizeof(k_ext);
    wr24(&out[1], o - 4U);
    return o;
}

/* A server selecting a suite the client did not offer: illegal_parameter. By default a CBC
 * suite is such a suite; a legacy build uses one no build offers (TLS_RSA_WITH_NULL_SHA256). */
static int t_client_rejects_unoffered_suite(void)
{
    static uint8_t sh[128];
    lb_pair_t pair;
    lb_cfg_t cfg;
    uint32_t len;
    noxtls_return_t rc;
    const uint16_t suite = (NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES != 0) ? 0x003BU :
                           TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA;
    size_t base = lb_alloc_live_bytes();

    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_CHECK_EQ(step_until_blocked(&pair.client), NOXTLS_RETURN_WANT_READ);
    (void)drain_link(&pair, 0);
    len = build_server_hello(sh, suite);
    LB_RUN(inject_record(&pair, 1, LB_REC_HANDSHAKE, sh, len));
    rc = step_until_blocked(&pair.client);
    LB_CHECK_EQ(rc, NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);
    len = drain_link(&pair, 0);
    LB_CHECK_EQ(flight_alert(len), LB_ALERT_ILLEGAL_PARAMETER);
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "unoffered suite");
}

/* TLS 1.3 -> 1.2 downgrade (unified client): the TLS 1.2 ServerHello must select a suite from
 * the TLS 1.3 ClientHello that was sent (DHE_RSA AES-CCM is in the TLS 1.2 offer only). */
static int t_unified_client_rejects_unoffered_tls12_suite(void)
{
#if NOXTLS_FEATURE_TLS13
    static uint8_t sh[128];
    lb_pair_t pair;
    lb_cfg_t cfg;
    uint32_t len;
    noxtls_return_t rc;
    size_t base = lb_alloc_live_bytes();

    lb_cfg_default(&cfg, LB_PROTO_UNIFIED);
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_CHECK_EQ(step_until_blocked(&pair.client), NOXTLS_RETURN_WANT_READ);
    (void)drain_link(&pair, 0);
    len = build_server_hello(sh, TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM);
    LB_RUN(inject_record(&pair, 1, LB_REC_HANDSHAKE, sh, len));
    rc = step_until_blocked(&pair.client);
    LB_CHECK_EQ(rc, NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);
    len = drain_link(&pair, 0);
    LB_CHECK_EQ(flight_alert(len), LB_ALERT_ILLEGAL_PARAMETER);
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "unified unoffered suite");
#else
    return LB_SKIP;
#endif
}

/* P-256 generator, a valid peer point for a hand-made ECDHE ServerKeyExchange. */
static const uint8_t k_p256_g[65] = {
    0x04U,
    0x6BU, 0x17U, 0xD1U, 0xF2U, 0xE1U, 0x2CU, 0x42U, 0x47U, 0xF8U, 0xBCU, 0xE6U, 0xE5U, 0x63U, 0xA4U, 0x40U, 0xF2U,
    0x77U, 0x03U, 0x7DU, 0x81U, 0x2DU, 0xEBU, 0x33U, 0xA0U, 0xF4U, 0xA1U, 0x39U, 0x45U, 0xD8U, 0x98U, 0xC2U, 0x96U,
    0x4FU, 0xE3U, 0x42U, 0xE2U, 0xFEU, 0x1AU, 0x7FU, 0x9BU, 0x8EU, 0xE7U, 0xEBU, 0x4AU, 0x7CU, 0x0FU, 0x9EU, 0x16U,
    0x2BU, 0xCEU, 0x33U, 0x57U, 0x6BU, 0x31U, 0x5EU, 0xCEU, 0xCBU, 0xB6U, 0x40U, 0x68U, 0x37U, 0xBFU, 0x51U, 0xF5U
};

/**
 * Play a TLS 1.2 server whose ServerKeyExchange is signed with @p scheme: valid certificate
 * chain, ECDHE P-256 parameters, dummy signature. The client must abort with illegal_parameter
 * before it verifies the signature, because it did not offer the scheme.
 */
static int client_vs_skx_scheme(lb_auth_t auth, uint16_t suite, uint16_t scheme)
{
    static uint8_t msg[4096];
    lb_pair_t pair;
    lb_cfg_t cfg;
    uint32_t len;
    uint32_t o;
    uint32_t i;
    noxtls_return_t rc;
    const uint8_t *ders[2];
    uint32_t lens[2];
    uint32_t ncerts = 1U;
    size_t base = lb_alloc_live_bytes();

    LB_RUN(lb_trust_all_roots());
    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    if(auth == LB_AUTH_RSA) {
        cfg.sni = "rsa.test";
        ders[0] = lb_rsa_server_cert;
        lens[0] = lb_rsa_server_cert_len;
    } else {
        ders[0] = lb_ec_server_cert;
        lens[0] = lb_ec_server_cert_len;
        ders[1] = lb_ec_int_cert;
        lens[1] = lb_ec_int_cert_len;
        ncerts = 2U;
    }
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_CHECK_EQ(step_until_blocked(&pair.client), NOXTLS_RETURN_WANT_READ);
    (void)drain_link(&pair, 0);
    len = build_server_hello(msg, suite);
    LB_RUN(inject_record(&pair, 1, LB_REC_HANDSHAKE, msg, len));
    /* Certificate */
    o = 7U;
    for(i = 0U; i < ncerts; i++) {
        wr24(&msg[o], lens[i]);
        memcpy(&msg[o + 3U], ders[i], lens[i]);
        o += 3U + lens[i];
    }
    msg[0] = 11U;
    wr24(&msg[1], o - 4U);
    wr24(&msg[4], o - 7U);
    LB_RUN(inject_record(&pair, 1, LB_REC_HANDSHAKE, msg, o));
    /* ServerKeyExchange: named_curve secp256r1, generator point, {scheme, dummy signature} */
    o = 4U;
    msg[o++] = 3U;
    wr16(&msg[o], TLS_NAMED_GROUP_SECP256R1);
    o += 2U;
    msg[o++] = (uint8_t)sizeof(k_p256_g);
    memcpy(&msg[o], k_p256_g, sizeof(k_p256_g));
    o += (uint32_t)sizeof(k_p256_g);
    wr16(&msg[o], scheme);
    len = (auth == LB_AUTH_RSA) ? 256U : 72U;
    wr16(&msg[o + 2U], len);
    o += 4U;
    lb_fill_pattern(&msg[o], len, 0x51U);
    o += len;
    msg[0] = LB_HS_SERVER_KX;
    wr24(&msg[1], o - 4U);
    LB_RUN(inject_record(&pair, 1, LB_REC_HANDSHAKE, msg, o));
    /* ServerHelloDone */
    msg[0] = 14U;
    wr24(&msg[1], 0U);
    LB_RUN(inject_record(&pair, 1, LB_REC_HANDSHAKE, msg, 4U));
    rc = step_until_blocked(&pair.client);
    LB_CHECK_EQ(rc, NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);
    len = drain_link(&pair, 0);
    LB_CHECK_EQ(flight_alert(len), LB_ALERT_ILLEGAL_PARAMETER);
    lb_pair_free(&pair);
    lb_trust_clear();
    return lb_expect_no_leak(base, "ServerKeyExchange scheme");
}

/* ServerKeyExchange signed with SHA-1 (RSA and ECDSA): rejected with illegal_parameter. With
 * SHA-1 signatures enabled those are offered, so MD5 (never offered) takes their place. */
static int t_client_rejects_sha1_server_key_exchange(void)
{
    const int sha1 = (NOXTLS_TLS12_SHA1_SIGNATURES != 0) ? 1 : 0;
    LB_RUN(client_vs_skx_scheme(LB_AUTH_RSA, TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                                (sha1 != 0) ? 0x0101U : 0x0201U));
    LB_RUN(client_vs_skx_scheme(LB_AUTH_ECDSA, TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                                (sha1 != 0) ? 0x0103U : 0x0203U));
    return 0;
}

/* Legacy build: a NoxTLS client and server still complete a static-RSA CBC handshake. */
static int t_legacy_static_rsa_cbc(void)
{
#if NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES
    return run_suite(LB_AUTH_RSA, TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA, 1);
#else
    return LB_SKIP;
#endif
}

static const lb_test_case_t k_cases[] = {
    { "tls12_ecdhe_ecdsa_aes128gcm", t_ecdsa_aes128gcm },
    { "tls12_ecdhe_ecdsa_aes256gcm", t_ecdsa_aes256gcm },
    { "tls12_ecdhe_ecdsa_chacha20", t_ecdsa_chacha20 },
    { "tls12_ecdhe_ecdsa_aes128ccm", t_ecdsa_aes128ccm },
    { "tls12_ecdhe_ecdsa_aes128cbc_sha256", t_ecdsa_aes128cbc_sha256 },
    { "tls12_ecdhe_ecdsa_aes256cbc_sha384", t_ecdsa_aes256cbc_sha384 },
    { "tls12_ecdhe_rsa_aes128gcm", t_rsa_aes128gcm },
    { "tls12_ecdhe_rsa_aes256gcm", t_rsa_aes256gcm },
    { "tls12_ecdhe_rsa_chacha20", t_rsa_chacha20 },
    { "tls12_ecdhe_rsa_aes128cbc_sha", t_rsa_aes128cbc_sha },
    { "tls12_default_negotiation", t_default_negotiation },
    { "tls12_hostname_mismatch", t_hostname_mismatch },
    { "tls12_untrusted_ca", t_untrusted_ca },
    { "tls12_missing_intermediate", t_missing_intermediate },
    { "tls12_mtls_ecdsa", t_mtls_ecdsa },
    { "tls12_mtls_rsa", t_mtls_rsa },
    { "tls12_mtls_peer_certificate", t_mtls_peer_certificate },
    { "tls12_mtls_required_missing", t_mtls_required_missing },
    { "tls12_ticket_resumption", t_ticket_resumption },
    { "tls12_secure_renegotiation_info", t_secure_renegotiation_info },
    { "tls12_ocsp_stapling_handshake", t_ocsp_stapling },
    { "tls12_max_fragment_length", t_max_fragment_length },
    { "tls12_data_small_reads", t_data_small_reads },
    { "tls12_data_interleaved", t_data_interleaved },
    { "tls12_fragmented_transport", t_fragmented_transport },
    { "tls12_alloc_failure_sweep", t_alloc_failure_sweep },
    { "tls12_mtls_ecdsa_cv_sha256_prf_sha384", t_mtls_ecdsa_cv_sha256_prf_sha384 },
    { "tls12_mtls_rsa_cv_sha256_prf_sha384", t_mtls_rsa_cv_sha256_prf_sha384 },
    { "tls12_mtls_ecdsa_cbc_sha384", t_mtls_ecdsa_cbc_sha384 },
    { "tls12_mtls_ecdsa_cv_same_hash", t_mtls_ecdsa_cv_same_hash },
    { "tls12_mtls_optional_no_cert", t_mtls_optional_no_cert },
    { "tls12_ems_on", t_ems_on },
    { "tls12_ems_off", t_ems_off },
    { "tls12_ems_resumption", t_ems_resumption },
    { "tls12_ems_resumption_upgrade", t_ems_resumption_upgrade },
    { "tls10_rsa_cbc_handshake", t_tls10_handshake },
    { "tls11_rsa_cbc_handshake", t_tls11_handshake },
    { "tls12_alloc_failure_sweep_mtls", t_alloc_failure_sweep_mtls },
    { "tls12_client_hello_no_legacy_offer", t_client_hello_no_legacy_offer },
    { "tls12_server_rejects_legacy_only_client", t_server_rejects_legacy_only_client },
    { "tls12_server_rejects_sha1_signature_algorithms", t_server_rejects_sha1_signature_algorithms },
    { "tls12_client_rejects_unoffered_suite", t_client_rejects_unoffered_suite },
    { "tls12_client_rejects_sha1_server_key_exchange", t_client_rejects_sha1_server_key_exchange },
    { "unified_client_rejects_unoffered_tls12_suite", t_unified_client_rejects_unoffered_tls12_suite },
    { "tls12_legacy_static_rsa_cbc", t_legacy_static_rsa_cbc },
};

int main(int argc, char **argv)
{
    return lb_main(argc, argv, "tls12_loopback", k_cases, sizeof(k_cases) / sizeof(k_cases[0]));
}
