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
* File:    tls13_loopback_test.c
* Summary: End-to-end TLS 1.3 client/server regression tests over an in-memory link
*****************************************************************************/
/** @file tls13_loopback_test.c
 * @brief Key exchange groups, cipher suites, server/client authentication,
 * hostname and trust failures, resumption, 0-RTT, KeyUpdate, exporters and
 * application-data framing for TLS 1.3. Run with a test name to run one case.
 */
#include "lb_fixture.h"

#include <string.h>

#define PAYLOAD_MAX (65536U + 4096U)

static uint8_t s_payload[PAYLOAD_MAX];

/* Sizes chosen around AEAD block/tag and record boundaries. */
static const uint32_t k_sizes[] = {
    1U, 15U, 16U, 17U, 1000U, TLS_MAX_RECORD_SIZE - 1U, TLS_MAX_RECORD_SIZE, TLS_MAX_RECORD_SIZE + 1U,
    65536U + 7U
};

/** Exchange every size in both directions; rx_chunk 0 = receive with a buffer of the full size. */
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

/** Handshake with cfg, check the negotiated suite/group, exchange data, close, free, leak-check. */
static int run_session(const lb_cfg_t *cfg, uint16_t expect_suite, uint16_t expect_group, int matrix)
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
    if(expect_group != 0U) {
        LB_CHECK_EQ(lb_field_tls13_group(pair.client.t13), expect_group);
        LB_CHECK_EQ(lb_field_tls13_group(pair.server.t13), expect_group);
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

/** Handshake must fail; both endpoints end in a non-connected state and nothing leaks. */
static int expect_handshake_failure(const lb_cfg_t *cfg, int client_must_fail)
{
    lb_pair_t pair;
    size_t base = lb_alloc_live_bytes();

    LB_RUN(lb_pair_init(&pair, cfg));
    LB_CHECK(lb_pair_handshake(&pair) != 0);
    if(client_must_fail != 0) {
        LB_CHECK(pair.client.done == 0);
        LB_CHECK(pair.client.last_rc != NOXTLS_RETURN_SUCCESS);
    } else {
        LB_CHECK(pair.server.done == 0);
    }
    LB_CHECK(!((pair.client.done != 0) && (pair.server.done != 0)));
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "failed handshake");
}

static void cfg_suite(lb_cfg_t *cfg, const uint16_t *suite)
{
    cfg->server_suites = suite;
    cfg->server_suite_count = 1U;
}

static void cfg_group(lb_cfg_t *cfg, const uint16_t *group)
{
    cfg->client_groups = group;
    cfg->client_group_count = 1U;
}

/* ---- Key exchange and cipher suites ------------------------------------ */

static const uint16_t k_aes128gcm = TLS_CIPHER_SUITE_AES_128_GCM_SHA256;
static const uint16_t k_aes256gcm = TLS_CIPHER_SUITE_AES_256_GCM_SHA384;
static const uint16_t k_chacha = TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256;
static const uint16_t k_aes128ccm = TLS_CIPHER_SUITE_AES_128_CCM_SHA256;
static const uint16_t k_aes128ccm8 = TLS_CIPHER_SUITE_AES_128_CCM_8_SHA256;
static const uint16_t k_x25519 = TLS_NAMED_GROUP_X25519;
static const uint16_t k_p256 = TLS_NAMED_GROUP_SECP256R1;
static const uint16_t k_p384 = TLS_NAMED_GROUP_SECP384R1;

static int t_x25519_aes128gcm(void)
{
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg_suite(&cfg, &k_aes128gcm);
    cfg_group(&cfg, &k_x25519);
    return run_session(&cfg, k_aes128gcm, k_x25519, 1);
}

static int t_p256_aes256gcm(void)
{
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg_suite(&cfg, &k_aes256gcm);
    cfg_group(&cfg, &k_p256);
    return run_session(&cfg, k_aes256gcm, k_p256, 1);
}

static int t_p384_chacha20(void)
{
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg_suite(&cfg, &k_chacha);
    cfg_group(&cfg, &k_p384);
    return run_session(&cfg, k_chacha, k_p384, 1);
}

static int t_prefer_chacha20(void)
{
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg.prefer_chacha20 = 1;
    return run_session(&cfg, 0U, 0U, 0);
}

static int t_aes128ccm(void)
{
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg_suite(&cfg, &k_aes128ccm);
    return run_session(&cfg, k_aes128ccm, 0U, 1);
}

static int t_aes128ccm8(void)
{
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg_suite(&cfg, &k_aes128ccm8);
    return run_session(&cfg, k_aes128ccm8, 0U, 0);
}

/* ---- Server authentication --------------------------------------------- */

static int t_ecdsa_chain(void)
{
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    return run_session(&cfg, 0U, 0U, 0);
}

static int t_rsa_pss_server(void)
{
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg.server_auth = LB_AUTH_RSA;
    cfg.sni = "rsa.test";
    return run_session(&cfg, 0U, 0U, 0);
}

static int t_ed25519_server(void)
{
    lb_cfg_t cfg;
    if(g_lb_have_ed25519 == 0) {
        return LB_SKIP;
    }
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg.server_auth = LB_AUTH_ED25519;
    cfg.sni = "ed.test";
    return run_session(&cfg, 0U, 0U, 0);
}

static int t_missing_intermediate(void)
{
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg.send_chain = 0;
    LB_RUN(lb_trust_ec_root());
    return expect_handshake_failure(&cfg, 1);
}

static int t_hostname_san_and_wildcard(void)
{
    static const char *const names[] = { "server.test", "ALT.test", "foo.wild.test" };
    uint32_t i;
    for(i = 0U; i < 3U; i++) {
        lb_cfg_t cfg;
        lb_cfg_default(&cfg, LB_PROTO_TLS13);
        cfg.sni = names[i];
        if(run_session(&cfg, 0U, 0U, 0) != 0) {
            lb_log("hostname %s rejected", names[i]);
            return 1;
        }
    }
    return 0;
}

static int t_hostname_mismatch(void)
{
    static const char *const names[] = { "evil.test", "wild.test", "a.b.wild.test", "server.test.evil" };
    uint32_t i;
    LB_RUN(lb_trust_ec_root());
    for(i = 0U; i < 4U; i++) {
        lb_cfg_t cfg;
        lb_cfg_default(&cfg, LB_PROTO_TLS13);
        cfg.sni = names[i];
        if(expect_handshake_failure(&cfg, 1) != 0) {
            lb_log("hostname %s unexpectedly accepted", names[i]);
            return 1;
        }
    }
    return 0;
}

static int t_untrusted_ca(void)
{
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg.server_auth = LB_AUTH_ROGUE;
    LB_RUN(lb_trust_ec_root());
    LB_RUN(expect_handshake_failure(&cfg, 1));
    /* A trusted chain with an empty trust store must fail too. */
    lb_trust_clear();
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    return expect_handshake_failure(&cfg, 1);
}

/* ---- Client authentication --------------------------------------------- */

static int t_mtls_ecdsa(void)
{
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg.client_auth = 2;
    cfg.client_cert = LB_AUTH_ECDSA;
    return run_session(&cfg, 0U, 0U, 0);
}

static int t_mtls_rsa_client(void)
{
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg.client_auth = 2;
    cfg.client_cert = LB_AUTH_RSA;
    return run_session(&cfg, 0U, 0U, 0);
}

static int t_mtls_optional_without_cert(void)
{
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg.client_auth = 1;
    return run_session(&cfg, 0U, 0U, 0);
}

static int t_mtls_required_missing(void)
{
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg.client_auth = 2;
    LB_RUN(lb_trust_all_roots());
    return expect_handshake_failure(&cfg, 0);
}

static int t_mtls_untrusted_client(void)
{
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg.client_auth = 2;
    cfg.client_cert = LB_AUTH_RSA;  /* issued by rsa_root, which is not trusted here */
    LB_RUN(lb_trust_ec_root());
    return expect_handshake_failure(&cfg, 0);
}

/* ---- Resumption, 0-RTT, KeyUpdate -------------------------------------- */

/* Resumption needs a NoxTLS server that issues tickets: with no server ticket store
 * (NOXTLS_TLS13_PSK_TICKET_STORE_MAX 0, as in the leader profiles, whose only servers are
 * DTLS 1.3 PSK servers that issue none) the server sends no NewSessionTicket. */
#define LB_SERVER_TICKETS (NOXTLS_TLS13_PSK_TICKET_STORE_MAX > 0U)

/** Full handshake that leaves a resumption ticket in *session. */
static int first_connection(noxtls_tls13_session_t *session, const uint16_t *suite)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    static const uint8_t msg[] = "ticket please";

    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    if(suite != NULL) {
        cfg_suite(&cfg, suite);
    }
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_RUN(lb_pair_handshake(&pair));
    LB_CHECK_EQ(lb_field_tls13_psk_in_use(pair.client.t13), 0);
    /* The client processes NewSessionTicket while reading application data. */
    LB_RUN(lb_transfer(&pair, 0, msg, sizeof(msg), TLS_MAX_RECORD_SIZE, sizeof(msg)));
    LB_CHECK(lb_field_tls13_ticket_stored(pair.client.t13) != 0);
    memset(session, 0, sizeof(*session));
    LB_CHECK_OK(noxtls_tls13_session_export(pair.client.t13, session));
    LB_CHECK(session->ticket_identity_len > 0U);
    LB_RUN(lb_close_and_observe(&pair, 1));
    lb_pair_free(&pair);
    return 0;
}

static int t_resumption_ticket(void)
{
    noxtls_tls13_session_t session;
    lb_pair_t pair;
    lb_cfg_t cfg;
    uint32_t round;
    size_t base = lb_alloc_live_bytes();

#if !LB_SERVER_TICKETS
    return LB_SKIP;
#endif

    LB_RUN(lb_trust_ec_root());
    LB_RUN(first_connection(&session, NULL));
    /* Resume twice: tickets may be reused within their lifetime or replaced by a new one. */
    for(round = 0U; round < 2U; round++) {
        lb_cfg_default(&cfg, LB_PROTO_TLS13);
        cfg.tls13_session = &session;
        LB_RUN(lb_pair_init(&pair, &cfg));
        LB_RUN(lb_pair_handshake(&pair));
        LB_CHECK_EQ(lb_field_tls13_psk_in_use(pair.client.t13), 1);
        LB_CHECK_EQ(lb_field_tls13_psk_in_use(pair.server.t13), 1);
        LB_CHECK_EQ(lb_end_cipher_suite(&pair.client), session.ticket_cipher_suite);
        LB_RUN(small_exchange(&pair));
        if(lb_field_tls13_ticket_stored(pair.client.t13) != 0) {
            LB_CHECK_OK(noxtls_tls13_session_export(pair.client.t13, &session));
        }
        LB_RUN(lb_close_and_observe(&pair, 0));
        lb_pair_free(&pair);
    }
    lb_trust_clear();
    return lb_expect_no_leak(base, "resumption");
}

static int t_resumption_wrong_session(void)
{
    noxtls_tls13_session_t session;
    lb_pair_t pair;
    lb_cfg_t cfg;
    size_t base = lb_alloc_live_bytes();

#if !LB_SERVER_TICKETS
    return LB_SKIP;
#endif

    LB_RUN(lb_trust_ec_root());
    LB_RUN(first_connection(&session, NULL));
    /* A corrupted ticket identity cannot be resumed: the server falls back to a full handshake. */
    session.ticket_identity[0] ^= 0x5AU;
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg.tls13_session = &session;
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_RUN(lb_pair_handshake(&pair));
    LB_CHECK_EQ(lb_field_tls13_psk_in_use(pair.server.t13), 0);
    LB_RUN(small_exchange(&pair));
    lb_pair_free(&pair);
    lb_trust_clear();
    return lb_expect_no_leak(base, "wrong session");
}

static int t_early_data(void)
{
    noxtls_tls13_session_t session;
    lb_pair_t pair;
    lb_cfg_t cfg;
    static const uint8_t early[] = "0-RTT request";
    uint8_t buf[64];
    uint32_t len = sizeof(buf);
    noxtls_return_t rc;
    size_t base = lb_alloc_live_bytes();

#if !LB_SERVER_TICKETS
    return LB_SKIP;
#endif

    LB_RUN(lb_trust_ec_root());
    LB_RUN(first_connection(&session, NULL));
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg.tls13_session = &session;
    LB_RUN(lb_pair_init(&pair, &cfg));
    /* First connect step sends ClientHello and derives early traffic keys. */
    rc = lb_end_step(&pair.client);
    LB_CHECK((rc == NOXTLS_RETURN_WANT_READ) || (rc == NOXTLS_RETURN_WANT_WRITE));
    rc = noxtls_tls13_send_early_data(pair.client.t13, early, sizeof(early));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        lb_log("noxtls_tls13_send_early_data rc=%d: 0-RTT not available", (int)rc);
        lb_pair_free(&pair);
        return 1;
    }
    (void)lb_end_flush(&pair.client);
    pair.client.last_rc = rc;
    LB_RUN(lb_pair_handshake(&pair));
    LB_CHECK_EQ(lb_field_tls13_psk_in_use(pair.server.t13), 1);
    LB_CHECK_EQ(lb_field_tls13_early_accepted(pair.client.t13), 1);
    /* The server delivers the early data as the first application bytes. */
    rc = lb_recv_some(&pair, &pair.server, buf, &len);
    LB_CHECK_OK(rc);
    LB_CHECK_EQ(len, sizeof(early));
    LB_CHECK(memcmp(buf, early, sizeof(early)) == 0);
    LB_RUN(small_exchange(&pair));
    lb_pair_free(&pair);
    lb_trust_clear();
    return lb_expect_no_leak(base, "early data");
}

/* Several 0-RTT records: the server must deliver all of them, in order (it used to keep
 * only the last early-data record). */
static int t_early_data_multi_record(void)
{
    noxtls_tls13_session_t session;
    lb_pair_t pair;
    lb_cfg_t cfg;
    static uint8_t early[3000U];
    static uint8_t got[sizeof(early)];
    static const uint32_t parts[3] = { 17U, 1200U, 3000U - 17U - 1200U };
    uint32_t total = 0U;
    uint32_t off = 0U;
    uint32_t i;
    noxtls_return_t rc;
    size_t base = lb_alloc_live_bytes();

#if !LB_SERVER_TICKETS
    return LB_SKIP;
#endif

    lb_fill_pattern(early, (uint32_t)sizeof(early), 77U);
    LB_RUN(lb_trust_ec_root());
    LB_RUN(first_connection(&session, NULL));
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg.tls13_session = &session;
    LB_RUN(lb_pair_init(&pair, &cfg));
    rc = lb_end_step(&pair.client);
    LB_CHECK((rc == NOXTLS_RETURN_WANT_READ) || (rc == NOXTLS_RETURN_WANT_WRITE));
    /* One record per call: parts above the build's record size go in several calls. */
    for(i = 0U; i < 3U; i++) {
        uint32_t left = parts[i];
        while(left > 0U) {
            uint32_t n = (left < (uint32_t)TLS_MAX_RECORD_SIZE) ? left : (uint32_t)TLS_MAX_RECORD_SIZE;
            LB_CHECK_OK(noxtls_tls13_send_early_data(pair.client.t13, &early[off], n));
            off += n;
            left -= n;
        }
    }
    (void)lb_end_flush(&pair.client);
    pair.client.last_rc = NOXTLS_RETURN_SUCCESS;
    LB_RUN(lb_pair_handshake(&pair));
    LB_CHECK_EQ(lb_field_tls13_psk_in_use(pair.server.t13), 1);
    LB_CHECK_EQ(lb_field_tls13_early_accepted(pair.client.t13), 1);
    /* Read with a small buffer so the delivery crosses record boundaries. */
    while(total < (uint32_t)sizeof(early)) {
        uint8_t chunk[700];
        uint32_t len = sizeof(chunk);
        rc = lb_recv_some(&pair, &pair.server, chunk, &len);
        LB_CHECK_OK(rc);
        LB_CHECK(len > 0U);
        LB_CHECK((total + len) <= (uint32_t)sizeof(early));
        memcpy(&got[total], chunk, len);
        total += len;
    }
    LB_CHECK(memcmp(got, early, sizeof(early)) == 0);
    LB_RUN(small_exchange(&pair));
    lb_pair_free(&pair);
    lb_trust_clear();
    return lb_expect_no_leak(base, "early data multi");
}

static int t_key_update(void)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    uint32_t i;
    size_t base = lb_alloc_live_bytes();

    LB_RUN(lb_trust_ec_root());
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_RUN(lb_pair_handshake(&pair));
    LB_RUN(small_exchange(&pair));
    for(i = 0U; i < 3U; i++) {
        /* Client updates and requests a peer update; data must keep flowing both ways. */
        LB_CHECK_OK(noxtls_tls13_send_key_update(pair.client.t13, 1U));
        (void)lb_end_flush(&pair.client);
        lb_fill_pattern(s_payload, 3000U, i);
        LB_RUN(lb_transfer(&pair, 1, s_payload, 3000U, TLS_MAX_RECORD_SIZE, 3000U));
        LB_RUN(lb_transfer(&pair, 0, s_payload, 3000U, TLS_MAX_RECORD_SIZE, 3000U));
        /* Server-initiated update without request. */
        LB_CHECK_OK(noxtls_tls13_send_key_update(pair.server.t13, 0U));
        (void)lb_end_flush(&pair.server);
        LB_RUN(lb_transfer(&pair, 0, s_payload, 1000U, TLS_MAX_RECORD_SIZE, 1000U));
        LB_RUN(lb_transfer(&pair, 1, s_payload, 1000U, TLS_MAX_RECORD_SIZE, 1000U));
    }
    LB_CHECK(noxtls_tls13_send_key_update(pair.client.t13, 2U) == NOXTLS_RETURN_INVALID_PARAM);
    LB_RUN(lb_close_and_observe(&pair, 1));
    lb_pair_free(&pair);
    lb_trust_clear();
    return lb_expect_no_leak(base, "key update");
}

/* ---- Exporters / channel binding ---------------------------------------- */

/* Peer certificate lifetime (NOXTLS_TLS_RETAIN_PEER_CERT): the parsed peer leaf borrows the
 * context's DER copy and, by default, is released once the handshake no longer needs it. */
static int t_peer_cert_retention(void)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    const uint8_t *der = NULL;
    uint32_t der_len = 0U;
    uint8_t cb_c[64];
    uint8_t cb_s[64];
    uint32_t cb_c_len = sizeof(cb_c);
    uint32_t cb_s_len = sizeof(cb_s);
    size_t base;

    LB_RUN(lb_trust_all_roots());
    base = lb_alloc_live_bytes();
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg.client_auth = 2;
    cfg.client_cert = LB_AUTH_ECDSA;
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_RUN(lb_pair_handshake(&pair));
    LB_RUN(small_exchange(&pair));
    /* The DER copies stay for the connection lifetime. */
    LB_CHECK((pair.client.t13->server_cert_len == lb_ec_server_cert_len) &&
             (memcmp(pair.client.t13->server_cert, lb_ec_server_cert, lb_ec_server_cert_len) == 0));
    LB_CHECK((pair.server.t13->client_cert_len == lb_ec_client_cert_len) &&
             (memcmp(pair.server.t13->client_cert, lb_ec_client_cert, lb_ec_client_cert_len) == 0));
#if NOXTLS_TLS_RETAIN_PEER_CERT
    LB_CHECK(pair.client.t13->server_cert_parsed != NULL);
    LB_CHECK(pair.server.t13->client_cert_parsed != NULL);
    /* Retained views borrow the context DER (one copy per peer certificate). */
    LB_CHECK_OK(noxtls_x509_certificate_get_der((const x509_certificate_t *)pair.client.t13->server_cert_parsed,
                                                &der, &der_len));
    LB_CHECK(der == pair.client.t13->server_cert);
    LB_CHECK_OK(noxtls_x509_certificate_matches_hostname(
        (const x509_certificate_t *)pair.client.t13->server_cert_parsed, (const uint8_t *)"server.test", 0U));
#else
    LB_CHECK(pair.client.t13->server_cert_parsed == NULL);
    LB_CHECK(pair.server.t13->client_cert_parsed == NULL);
    (void)der;
    (void)der_len;
#endif
    /* tls-server-end-point is computed from the DER on both sides and agrees. */
    LB_CHECK_OK(noxtls_tls13_get_channel_binding(pair.client.t13, NOXTLS_TLS_CHANNEL_BINDING_TLS_SERVER_END_POINT,
                                                 cb_c, &cb_c_len));
    LB_CHECK_OK(noxtls_tls13_get_channel_binding(pair.server.t13, NOXTLS_TLS_CHANNEL_BINDING_TLS_SERVER_END_POINT,
                                                 cb_s, &cb_s_len));
    LB_CHECK_EQ(cb_c_len, 32U);
    LB_CHECK((cb_c_len == cb_s_len) && (memcmp(cb_c, cb_s, cb_c_len) == 0));
    LB_RUN(small_exchange(&pair));
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "peer cert retention");
}

static int t_exporter_channel_binding(void)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    static const uint8_t label[] = "EXPORTER-noxtls-test";
    static const uint8_t context[] = { 1U, 2U, 3U };
    uint8_t ek_c[48];
    uint8_t ek_s[48];
    uint8_t cb_c[64];
    uint8_t cb_s[64];
    uint32_t cb_c_len = sizeof(cb_c);
    uint32_t cb_s_len = sizeof(cb_s);
    size_t base = lb_alloc_live_bytes();

    LB_RUN(lb_trust_ec_root());
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_RUN(lb_pair_handshake(&pair));
    LB_RUN(small_exchange(&pair));
    LB_CHECK_OK(noxtls_tls13_export_keying_material(pair.client.t13, label, sizeof(label) - 1U, context,
                                                    sizeof(context), ek_c, sizeof(ek_c)));
    LB_CHECK_OK(noxtls_tls13_export_keying_material(pair.server.t13, label, sizeof(label) - 1U, context,
                                                    sizeof(context), ek_s, sizeof(ek_s)));
    LB_CHECK(memcmp(ek_c, ek_s, sizeof(ek_c)) == 0);
    LB_CHECK_OK(noxtls_tls13_get_channel_binding(pair.client.t13, NOXTLS_TLS_CHANNEL_BINDING_TLS_UNIQUE, cb_c,
                                                 &cb_c_len));
    LB_CHECK_OK(noxtls_tls13_get_channel_binding(pair.server.t13, NOXTLS_TLS_CHANNEL_BINDING_TLS_UNIQUE, cb_s,
                                                 &cb_s_len));
    LB_CHECK_EQ(cb_c_len, cb_s_len);
    LB_CHECK(memcmp(cb_c, cb_s, cb_c_len) == 0);
    /* tls-server-end-point needs the server certificate after the handshake. */
    cb_c_len = sizeof(cb_c);
    cb_s_len = sizeof(cb_s);
    LB_CHECK_OK(noxtls_tls13_get_channel_binding(pair.client.t13, NOXTLS_TLS_CHANNEL_BINDING_TLS_SERVER_END_POINT,
                                                 cb_c, &cb_c_len));
    LB_CHECK_EQ(cb_c_len, 32U);
    if(noxtls_tls13_get_channel_binding(pair.server.t13, NOXTLS_TLS_CHANNEL_BINDING_TLS_SERVER_END_POINT, cb_s,
                                        &cb_s_len) == NOXTLS_RETURN_SUCCESS) {
        LB_CHECK_EQ(cb_c_len, cb_s_len);
        LB_CHECK(memcmp(cb_c, cb_s, cb_c_len) == 0);
    }
    LB_RUN(lb_close_and_observe(&pair, 0));
    lb_pair_free(&pair);
    lb_trust_clear();
    return lb_expect_no_leak(base, "exporter");
}

/* ---- Application-data framing -------------------------------------------- */

static int t_data_small_reads(void)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    uint32_t i;
    size_t base = lb_alloc_live_bytes();

    LB_RUN(lb_trust_ec_root());
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_RUN(lb_pair_handshake(&pair));
    /* Reader buffers far smaller than a record exercise the pending-plaintext path. */
    lb_fill_pattern(s_payload, TLS_MAX_RECORD_SIZE, 9U);
    for(i = 1U; i <= 7U; i += 3U) {
        LB_RUN(lb_transfer(&pair, 1, s_payload, 4000U, TLS_MAX_RECORD_SIZE, i));
        LB_RUN(lb_transfer(&pair, 0, s_payload, 4000U, TLS_MAX_RECORD_SIZE, i));
    }
    LB_RUN(lb_transfer(&pair, 0, s_payload, TLS_MAX_RECORD_SIZE, TLS_MAX_RECORD_SIZE, 1000U));
    /* Many small records read through a large buffer. */
    LB_RUN(lb_transfer(&pair, 1, s_payload, 5000U, 13U, 5000U));
    LB_RUN(lb_close_and_observe(&pair, 0));
    lb_pair_free(&pair);
    lb_trust_clear();
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
    size_t base = lb_alloc_live_bytes();

    LB_RUN(lb_trust_ec_root());
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_RUN(lb_pair_handshake(&pair));
    for(i = 0U; i < 40U; i++) {
        uint32_t la = 1U + ((i * 37U) % sizeof(a));
        uint32_t lbn = 1U + ((i * 53U) % sizeof(b));
        uint32_t len;
        lb_fill_pattern(a, la, i);
        lb_fill_pattern(b, lbn, i + 1000U);
        /* Both sides write before either reads. */
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
    lb_trust_clear();
    return lb_expect_no_leak(base, "interleaved");
}

static int t_fragmented_transport(void)
{
    static const uint32_t chunks[] = { 1U, 7U, 1400U };
    uint32_t i;
    for(i = 0U; i < 3U; i++) {
        lb_cfg_t cfg;
        lb_cfg_default(&cfg, LB_PROTO_TLS13);
        cfg.max_chunk = chunks[i];
        cfg.block_every = (i == 1U) ? 3U : 0U;
        if(run_session(&cfg, 0U, 0U, (i == 2U) ? 1 : 0) != 0) {
            lb_log("fragmented transport max_chunk=%u failed", chunks[i]);
            return 1;
        }
    }
    return 0;
}

static int t_record_size_limit(void)
{
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg.record_size_limit = 512U;
    return run_session(&cfg, 0U, 0U, 1);
}

static int t_server_close(void)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    size_t base = lb_alloc_live_bytes();

    LB_RUN(lb_trust_ec_root());
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_RUN(lb_pair_handshake(&pair));
    LB_RUN(small_exchange(&pair));
    LB_RUN(lb_close_and_observe(&pair, 0));
    lb_pair_free(&pair);
    lb_trust_clear();
    return lb_expect_no_leak(base, "server close");
}

/* ---- Allocation failure robustness -------------------------------------- */

/** Fail the n-th allocation of a full handshake for every n: no crash, no leak, no false success. */
static int t_alloc_failure_sweep(void)
{
    size_t n;
    size_t base = lb_alloc_live_bytes();
    LB_RUN(lb_trust_ec_root());
    g_lb_quiet = 1;
    for(n = 0U; n < 2000U; n++) {
        lb_pair_t pair;
        lb_cfg_t cfg;
        int hs;
        lb_cfg_default(&cfg, LB_PROTO_TLS13);
        lb_alloc_reset_counters();
        lb_alloc_fail_after(n);
        if(lb_pair_init(&pair, &cfg) != 0) {
            lb_alloc_fail_after(SIZE_MAX);
            lb_pair_free(&pair);
            lb_trust_clear();
            LB_CHECK_EQ(lb_alloc_live_bytes(), base);
            LB_RUN(lb_trust_ec_root());
            continue;
        }
        hs = lb_pair_handshake(&pair);
        lb_alloc_fail_after(SIZE_MAX);
        if((hs == 0) && (lb_alloc_failed_calls() == 0U)) {
            /* Every allocation point has been failed once; the clean run succeeded. */
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

static const lb_test_case_t k_cases[] = {
    { "tls13_x25519_aes128gcm", t_x25519_aes128gcm },
    { "tls13_p256_aes256gcm", t_p256_aes256gcm },
    { "tls13_p384_chacha20", t_p384_chacha20 },
    { "tls13_prefer_chacha20", t_prefer_chacha20 },
    { "tls13_aes128ccm", t_aes128ccm },
    { "tls13_aes128ccm8", t_aes128ccm8 },
    { "tls13_ecdsa_chain", t_ecdsa_chain },
    { "tls13_rsa_pss_server", t_rsa_pss_server },
    { "tls13_ed25519_server", t_ed25519_server },
    { "tls13_missing_intermediate", t_missing_intermediate },
    { "tls13_hostname_san_wildcard", t_hostname_san_and_wildcard },
    { "tls13_hostname_mismatch", t_hostname_mismatch },
    { "tls13_untrusted_ca", t_untrusted_ca },
    { "tls13_mtls_ecdsa", t_mtls_ecdsa },
    { "tls13_peer_cert_retention", t_peer_cert_retention },
    { "tls13_mtls_rsa_client", t_mtls_rsa_client },
    { "tls13_mtls_optional_no_cert", t_mtls_optional_without_cert },
    { "tls13_mtls_required_missing", t_mtls_required_missing },
    { "tls13_mtls_untrusted_client", t_mtls_untrusted_client },
    { "tls13_resumption_ticket", t_resumption_ticket },
    { "tls13_resumption_bad_ticket", t_resumption_wrong_session },
    { "tls13_early_data", t_early_data },
    { "tls13_early_data_multi_record", t_early_data_multi_record },
    { "tls13_key_update", t_key_update },
    { "tls13_exporter_channel_binding", t_exporter_channel_binding },
    { "tls13_data_small_reads", t_data_small_reads },
    { "tls13_data_interleaved", t_data_interleaved },
    { "tls13_fragmented_transport", t_fragmented_transport },
    { "tls13_record_size_limit", t_record_size_limit },
    { "tls13_server_close", t_server_close },
    { "tls13_alloc_failure_sweep", t_alloc_failure_sweep },
};

int main(int argc, char **argv)
{
    return lb_main(argc, argv, "tls13_loopback", k_cases, sizeof(k_cases) / sizeof(k_cases[0]));
}
