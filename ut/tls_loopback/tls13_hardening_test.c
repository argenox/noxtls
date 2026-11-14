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
* File:    tls13_hardening_test.c
* Summary: TLS 1.3 / DTLS 1.3 regression tests for peer-input limits, ticket binding,
*          client-certificate trust and context hygiene
*****************************************************************************/
/** @file tls13_hardening_test.c
 * @brief Regression tests for: client chain validation with an empty trust store (TLS 1.3 and
 * TLS 1.2), the RFC 8449 record_size_limit minimum, the post-handshake message bound, ticket
 * binding to the issuing server configuration and suite allowlist, the ticket-store clear APIs,
 * the context wipe at free, the crypto-provider CertificateVerify path, a short ClientHello and
 * unauthenticated DTLS 1.3 datagrams. Run with a test name to run one case.
 */
#include "lb_fixture.h"

#include <string.h>

static int small_exchange(lb_pair_t *pair)
{
    static const uint8_t c2s[] = "client hello data";
    static const uint8_t s2c[] = "server reply data!";
    LB_RUN(lb_transfer(pair, 1, c2s, sizeof(c2s), TLS_MAX_RECORD_SIZE, sizeof(c2s)));
    LB_RUN(lb_transfer(pair, 0, s2c, sizeof(s2c), TLS_MAX_RECORD_SIZE, sizeof(s2c)));
    return 0;
}

/* ---- Client certificate chain validation with an empty global store --------------------- */

static x509_certificate_t s_anchor_ec;
static x509_certificate_t s_anchor_rsa;
static x509_certificate_chain_t s_anchors;

/** Parse both loopback roots into an anchor list that does not use the global trust store. */
static int anchors_init(void)
{
    unsigned prev = lb_alloc_set_owner(LB_OWNER_GLOBAL);
    int rc = 0;

    (void)noxtls_x509_certificate_init(&s_anchor_ec);
    (void)noxtls_x509_certificate_init(&s_anchor_rsa);
    if((noxtls_x509_certificate_chain_init(&s_anchors) != NOXTLS_RETURN_SUCCESS) ||
       (noxtls_x509_certificate_parse_der(&s_anchor_ec, lb_ec_root_cert, lb_ec_root_cert_len) != NOXTLS_RETURN_SUCCESS) ||
       (noxtls_x509_certificate_parse_der(&s_anchor_rsa, lb_rsa_root_cert, lb_rsa_root_cert_len) != NOXTLS_RETURN_SUCCESS) ||
       (noxtls_x509_certificate_chain_add(&s_anchors, &s_anchor_ec) != NOXTLS_RETURN_SUCCESS) ||
       (noxtls_x509_certificate_chain_add(&s_anchors, &s_anchor_rsa) != NOXTLS_RETURN_SUCCESS)) {
        rc = 1;
    }
    (void)lb_alloc_set_owner(prev);
    return rc;
}

static void anchors_free(void)
{
    unsigned prev = lb_alloc_set_owner(LB_OWNER_GLOBAL);
    (void)noxtls_x509_certificate_chain_free(&s_anchors);
    (void)noxtls_x509_certificate_free(&s_anchor_ec);
    (void)noxtls_x509_certificate_free(&s_anchor_rsa);
    (void)lb_alloc_set_owner(prev);
}

static void policy_from_anchors(noxtls_x509_verify_policy_t *policy)
{
    memset(policy, 0, sizeof(*policy));
    policy->trust_anchors = &s_anchors;
    policy->time_mode = NOXTLS_X509_TIME_SYSTEM;
}

/**
 * mode 0: no server-side policy (must fail: empty global store);
 * mode 1: explicit client verify policy (must pass);
 * mode 2: explicit chain-validation opt-out (must pass).
 */
static int tls13_mtls_empty_store_case(int mode)
{
    noxtls_x509_verify_policy_t client_side;
    noxtls_x509_verify_policy_t server_side;
    lb_pair_t pair;
    lb_cfg_t cfg;
    int hs;

    lb_trust_clear();
    policy_from_anchors(&client_side);
    policy_from_anchors(&server_side);
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg.client_auth = 2;
    cfg.client_cert = LB_AUTH_ECDSA;
    LB_RUN(lb_pair_init(&pair, &cfg));
    /* The client verifies the server against its own policy, so only the server's
     * client-certificate decision depends on the (empty) global store. */
    noxtls_tls13_set_server_verify_policy(pair.client.t13, &client_side);
    if(mode == 1) {
        noxtls_tls13_set_client_verify_policy(pair.server.t13, &server_side);
    } else if(mode == 2) {
        noxtls_tls13_set_client_chain_verify_disabled(pair.server.t13, 1);
    } else {
        /* default: global store */
    }
    hs = lb_pair_handshake(&pair);
    if(mode == 0) {
        LB_CHECK(hs != 0);
        LB_CHECK(pair.server.done == 0);
    } else {
        LB_CHECK_EQ(hs, 0);
        LB_RUN(small_exchange(&pair));
    }
    lb_pair_free(&pair);
    return 0;
}

static int t_tls13_mtls_empty_trust_store(void)
{
    size_t base;
    base = lb_alloc_live_bytes();
    LB_RUN(anchors_init());
    LB_RUN(tls13_mtls_empty_store_case(0));
    LB_RUN(tls13_mtls_empty_store_case(1));
    LB_RUN(tls13_mtls_empty_store_case(2));
    anchors_free();
    return lb_expect_no_leak(base, "mtls empty store");
}

#if NOXTLS_FEATURE_TLS12
/* TLS 1.2: without a client verify policy the server checks the client chain against the global
 * store, which here lacks the client's root (the client still verifies the RSA server through it). */
static int t_tls12_mtls_empty_trust_store(void)
{
    noxtls_x509_verify_policy_t server_side;
    lb_pair_t pair;
    lb_cfg_t cfg;
    size_t base;

    base = lb_alloc_live_bytes();
    LB_RUN(anchors_init());
    /* Global store holds only the RSA root: the client accepts the RSA server, but the ECDSA
     * client certificate (issued under the EC root) has no anchor on the server side. */
    {
        const uint8_t *ders[1] = { lb_rsa_root_cert };
        uint32_t lens[1];
        lens[0] = lb_rsa_root_cert_len;
        LB_RUN(lb_trust_set(ders, lens, 1U));
    }
    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    cfg.server_auth = LB_AUTH_RSA;
    cfg.client_auth = 2;
    cfg.client_cert = LB_AUTH_ECDSA;
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_CHECK(lb_pair_handshake(&pair) != 0);
    lb_pair_free(&pair);

    /* An explicit server-side policy with the EC root accepts the same client. */
    policy_from_anchors(&server_side);
    LB_RUN(lb_pair_init(&pair, &cfg));
    noxtls_tls12_set_client_verify_policy(pair.server.t12, &server_side);
    LB_CHECK_EQ(lb_pair_handshake(&pair), 0);
    LB_RUN(small_exchange(&pair));
    lb_pair_free(&pair);
    lb_trust_clear();
    anchors_free();
    return lb_expect_no_leak(base, "tls12 mtls store");
}
#endif

/* ---- RFC 8449 record_size_limit minimum ------------------------------------------------ */

static int t_record_size_limit_minimum(void)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    size_t base;

    base = lb_alloc_live_bytes();
    LB_RUN(lb_trust_ec_root());
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg.record_size_limit = 63U;   /* below the RFC 8449 minimum: illegal_parameter */
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_CHECK(lb_pair_handshake(&pair) != 0);
    LB_CHECK(pair.server.done == 0);
    lb_pair_free(&pair);

    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg.record_size_limit = 64U;   /* the minimum itself is accepted */
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_CHECK_EQ(lb_pair_handshake(&pair), 0);
    LB_RUN(small_exchange(&pair));
    lb_pair_free(&pair);
    lb_trust_clear();
    return lb_expect_no_leak(base, "record_size_limit");
}

/* ---- Post-handshake message bound ------------------------------------------------------- */

static int t_key_update_flood(void)
{
    static const uint8_t msg[] = "after key updates";
    uint8_t buf[64];
    uint32_t len = sizeof(buf);
    lb_pair_t pair;
    lb_cfg_t cfg;
    uint32_t i;
    noxtls_return_t rc;
    size_t base;

    base = lb_alloc_live_bytes();
    LB_RUN(lb_trust_ec_root());
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_CHECK_EQ(lb_pair_handshake(&pair), 0);
    LB_RUN(small_exchange(&pair));
    /* 32 KeyUpdates then data: accepted, and data resets the run. */
    for(i = 0U; i < 32U; i++) {
        LB_CHECK_OK(noxtls_tls13_send_key_update(pair.server.t13, 0U));
    }
    (void)lb_end_flush(&pair.server);
    LB_RUN(lb_transfer(&pair, 0, msg, sizeof(msg), TLS_MAX_RECORD_SIZE, sizeof(msg)));
    /* 33 in a row without application data: the receiver aborts. */
    for(i = 0U; i < 33U; i++) {
        LB_CHECK_OK(noxtls_tls13_send_key_update(pair.server.t13, 0U));
    }
    (void)lb_end_flush(&pair.server);
    rc = lb_recv_some(&pair, &pair.client, buf, &len);
    LB_CHECK(rc != NOXTLS_RETURN_SUCCESS);
    LB_CHECK(lb_field_state(&pair.client) != TLS_STATE_CONNECTED);
    lb_pair_free(&pair);
    lb_trust_clear();
    return lb_expect_no_leak(base, "key update flood");
}

/* ---- Ticket binding, suite allowlist and store clear ------------------------------------ */

/** Full handshake under cfg that leaves a resumption ticket in *session. */
static int ticket_connection(const lb_cfg_t *cfg, noxtls_tls13_session_t *session)
{
    static const uint8_t msg[] = "ticket please";
    lb_pair_t pair;

    LB_RUN(lb_pair_init(&pair, cfg));
    LB_CHECK_EQ(lb_pair_handshake(&pair), 0);
    LB_RUN(lb_transfer(&pair, 0, msg, sizeof(msg), TLS_MAX_RECORD_SIZE, sizeof(msg)));
    LB_CHECK(lb_field_tls13_ticket_stored(pair.client.t13) != 0);
    memset(session, 0, sizeof(*session));
    LB_CHECK_OK(noxtls_tls13_session_export(pair.client.t13, session));
    LB_RUN(lb_close_and_observe(&pair, 1));
    lb_pair_free(&pair);
    return 0;
}

/** Resume with cfg; *psk receives whether the server resumed. The handshake must succeed. */
static int resume_connection(lb_cfg_t *cfg, const noxtls_tls13_session_t *session, int *psk)
{
    lb_pair_t pair;

    cfg->tls13_session = session;
    LB_RUN(lb_pair_init(&pair, cfg));
    LB_CHECK_EQ(lb_pair_handshake(&pair), 0);
    *psk = lb_field_tls13_psk_in_use(pair.server.t13);
    LB_RUN(small_exchange(&pair));
    lb_pair_free(&pair);
    return 0;
}

static int t_ticket_binding(void)
{
    static const uint16_t k_aes128gcm = TLS_CIPHER_SUITE_AES_128_GCM_SHA256;
    static const uint16_t k_aes256gcm = TLS_CIPHER_SUITE_AES_256_GCM_SHA384;
    noxtls_tls13_session_t session;
    lb_cfg_t cfg;
    int psk = 0;
    size_t base;

    base = lb_alloc_live_bytes();
    LB_RUN(lb_trust_all_roots());

    /* Control: the issuing configuration resumes. */
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    LB_RUN(ticket_connection(&cfg, &session));
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    LB_RUN(resume_connection(&cfg, &session, &psk));
    LB_CHECK_EQ(psk, 1);

    /* A server context with another certificate does not resume it. */
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    LB_RUN(ticket_connection(&cfg, &session));
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg.server_auth = LB_AUTH_RSA;
    LB_RUN(resume_connection(&cfg, &session, &psk));
    LB_CHECK_EQ(psk, 0);

    /* A server whose allowlist excludes the ticket's suite does not resume it. */
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg.server_suites = &k_aes128gcm;
    cfg.server_suite_count = 1U;
    LB_RUN(ticket_connection(&cfg, &session));
    LB_CHECK_EQ(session.ticket_cipher_suite, k_aes128gcm);
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg.server_suites = &k_aes256gcm;
    cfg.server_suite_count = 1U;
    LB_RUN(resume_connection(&cfg, &session, &psk));
    LB_CHECK_EQ(psk, 0);

    /* After the store is cleared the ticket is gone. */
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    LB_RUN(ticket_connection(&cfg, &session));
    noxtls_tls13_psk_ticket_store_clear();
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    LB_RUN(resume_connection(&cfg, &session, &psk));
    LB_CHECK_EQ(psk, 0);

    lb_trust_clear();
    return lb_expect_no_leak(base, "ticket binding");
}

#if NOXTLS_FEATURE_TLS12
static int t_tls12_session_stores_clear(void)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    uint32_t round;
    size_t base;

    base = lb_alloc_live_bytes();
    LB_RUN(lb_trust_ec_root());
    for(round = 0U; round < 2U; round++) {
        lb_cfg_default(&cfg, LB_PROTO_TLS12);
        LB_RUN(lb_pair_init(&pair, &cfg));
        LB_CHECK_EQ(lb_pair_handshake(&pair), 0);
        LB_CHECK_EQ(lb_field_tls12_resumed(pair.server.t12), (round == 0U) ? 0 : 1);
        LB_RUN(small_exchange(&pair));
        lb_pair_free(&pair);
    }
    noxtls_tls12_session_stores_clear();
    LB_CHECK_EQ(noxtls_tls12_client_session_has_ticket(), 0);
    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_CHECK_EQ(lb_pair_handshake(&pair), 0);
    LB_CHECK_EQ(lb_field_tls12_resumed(pair.server.t12), 0);
    lb_pair_free(&pair);
    lb_trust_clear();
    return lb_expect_no_leak(base, "tls12 store clear");
}
#endif

/* ---- Context wipe at free ---------------------------------------------------------------- */

static int ctx_all_zero(const tls13_context_t *ctx)
{
    const uint8_t *p = (const uint8_t *)ctx;
    size_t i;
    for(i = 0U; i < sizeof(*ctx); i++) {
        if(p[i] != 0U) {
            lb_log("context byte %lu not wiped", (unsigned long)i);
            return 1;
        }
    }
    return 0;
}

static int t_context_free_wipes(void)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    size_t base;

    base = lb_alloc_live_bytes();
    LB_RUN(lb_trust_ec_root());
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_CHECK_EQ(lb_pair_handshake(&pair), 0);
    LB_RUN(small_exchange(&pair));
    LB_CHECK_OK(noxtls_tls13_context_free(pair.client.t13));
    pair.client.initialized = 0;
    LB_CHECK_OK(noxtls_tls13_context_free(pair.server.t13));
    pair.server.initialized = 0;
    LB_RUN(ctx_all_zero(pair.client.t13));
    LB_RUN(ctx_all_zero(pair.server.t13));
    lb_pair_free(&pair);
    lb_trust_clear();
    return lb_expect_no_leak(base, "context wipe");
}

/* ---- Crypto provider CertificateVerify -------------------------------------------------- */

static uint32_t s_provider_calls;
static int s_provider_fail;

static noxtls_return_t provider_rsa_sign_pss(noxtls_crypto_provider_ctx_t prov_ctx,
                                             noxtls_crypto_key_handle_t key,
                                             const uint8_t *message, uint32_t message_len,
                                             uint8_t *signature, uint32_t *signature_len,
                                             noxtls_crypto_hash_algo_t hash_algo)
{
    (void)prov_ctx;
    s_provider_calls += 1U;
    if(s_provider_fail != 0) {
        return NOXTLS_RETURN_FAILED;
    }
    return noxtls_rsa_sign_pss((const rsa_key_t *)key, message, message_len, signature, signature_len,
                               (noxtls_hash_algos_t)hash_algo);
}

static int provider_case(int fail, int expect_ok)
{
    static noxtls_crypto_provider_ops_t ops;
    static noxtls_crypto_provider_t provider;
    lb_pair_t pair;
    lb_cfg_t cfg;
    int hs;

    memset(&ops, 0, sizeof(ops));
    ops.rsa_sign_pss = provider_rsa_sign_pss;
    provider.ctx = NULL;
    provider.ops = &ops;
    s_provider_calls = 0U;
    s_provider_fail = fail;
    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    cfg.server_auth = LB_AUTH_RSA;
    LB_RUN(lb_pair_init(&pair, &cfg));
    /* The software key stays loaded: it must not be used once a provider key is registered. */
    noxtls_tls13_set_crypto_provider_server(pair.server.t13, &provider, &g_lb_keys.rsa_server);
    hs = lb_pair_handshake(&pair);
    LB_CHECK(s_provider_calls >= 1U);
    if(expect_ok != 0) {
        LB_CHECK_EQ(hs, 0);
        LB_RUN(small_exchange(&pair));
    } else {
        LB_CHECK(hs != 0);
    }
    lb_pair_free(&pair);
    return 0;
}

static int t_provider_certificate_verify(void)
{
    size_t base;
    base = lb_alloc_live_bytes();
    LB_RUN(lb_trust_all_roots());
    LB_RUN(provider_case(0, 1));
    LB_RUN(provider_case(1, 0));   /* no silent fallback to the software key */
    lb_trust_clear();
    return lb_expect_no_leak(base, "provider");
}

/* ---- Short ClientHello ------------------------------------------------------------------ */

/** ClientHello records ending right after the session id (and one byte later). */
static int short_client_hello_case(uint32_t extra)
{
    uint8_t rec[5U + 4U + 2U + 32U + 1U + 1U];
    uint32_t body = 2U + 32U + 1U + extra;
    uint32_t rec_len = 5U + 4U + body;
    lb_pair_t pair;
    lb_cfg_t cfg;
    noxtls_return_t rc = NOXTLS_RETURN_WANT_READ;
    uint32_t steps;

    memset(rec, 0, sizeof(rec));
    rec[0] = TLS_RECORD_HANDSHAKE;
    rec[1] = 0x03U;
    rec[2] = 0x01U;
    rec[3] = (uint8_t)((4U + body) >> 8U);
    rec[4] = (uint8_t)(4U + body);
    rec[5] = TLS_HANDSHAKE_CLIENT_HELLO;
    rec[6] = 0U;
    rec[7] = 0U;
    rec[8] = (uint8_t)body;
    rec[9] = 0x03U;
    rec[10] = 0x03U;
    lb_fill_pattern(&rec[11], 32U, 7U);
    rec[43] = 0U;           /* legacy_session_id length 0 */
    rec[44] = 0x13U;        /* one byte of cipher_suites length when extra == 1 */

    lb_cfg_default(&cfg, LB_PROTO_TLS13);
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_CHECK_EQ(lb_io_send(&pair.link->client_port, rec, rec_len), (int32_t)rec_len);
    for(steps = 0U; (steps < 8U) && ((rc == NOXTLS_RETURN_WANT_READ) || (rc == NOXTLS_RETURN_WANT_WRITE)); steps++) {
        rc = lb_end_step(&pair.server);
    }
    LB_CHECK(rc != NOXTLS_RETURN_SUCCESS);
    LB_CHECK(rc != NOXTLS_RETURN_WANT_READ);
    lb_pair_free(&pair);
    return 0;
}

static int t_short_client_hello(void)
{
    size_t base = lb_alloc_live_bytes();
    LB_RUN(short_client_hello_case(0U));
    LB_RUN(short_client_hello_case(1U));
    return lb_expect_no_leak(base, "short client hello");
}

/* ---- DTLS 1.3: unauthenticated datagrams are discarded --------------------------------- */

#if NOXTLS_FEATURE_DTLS
static int inject_garbage(lb_pair_t *pair, int to_client)
{
    lb_port_t *from = (to_client != 0) ? &pair->link->server_port : &pair->link->client_port;
    /* DTLSPlaintext alert (fatal handshake_failure), epoch 0. */
    static const uint8_t plain_alert[] = {
        TLS_RECORD_ALERT, 0xFEU, 0xFDU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x07U,
        0x00U, 0x02U, 0x02U, 0x28U
    };
    /* DTLSPlaintext ACK claiming a range. */
    static const uint8_t plain_ack[] = {
        TLS_RECORD_ACK, 0xFEU, 0xFDU, 0x00U, 0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x09U,
        0x00U, 0x04U, 0x00U, 0x00U, 0x00U, 0x00U
    };
    /* DTLSPlaintext handshake fragment (NewSessionTicket header). */
    static const uint8_t plain_hs[] = {
        TLS_RECORD_HANDSHAKE, 0xFEU, 0xFDU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x40U,
        0x00U, 0x0CU, 0x04U, 0x00U, 0x00U, 0x10U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
    };
    /* Exactly one record header (13 bytes), no body. */
    static const uint8_t header_only[] = {
        TLS_RECORD_APPLICATION_DATA, 0xFEU, 0xFDU, 0x00U, 0x03U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U, 0x00U,
        0x00U, 0x20U
    };
    /* One-byte datagram. */
    static const uint8_t one_byte[] = { 0x16U };
    /* Unified-header ciphertext (epoch 3, 16-bit seq, length) with garbage body. */
    uint8_t garbage[5U + 40U];

    garbage[0] = 0x2FU;
    garbage[1] = 0x12U;
    garbage[2] = 0x34U;
    garbage[3] = 0x00U;
    garbage[4] = 40U;
    lb_fill_pattern(&garbage[5], 40U, 99U);
    LB_CHECK(lb_io_send(from, plain_alert, sizeof(plain_alert)) > 0);
    LB_CHECK(lb_io_send(from, plain_ack, sizeof(plain_ack)) > 0);
    LB_CHECK(lb_io_send(from, garbage, sizeof(garbage)) > 0);
    LB_CHECK(lb_io_send(from, plain_hs, sizeof(plain_hs)) > 0);
    LB_CHECK(lb_io_send(from, header_only, sizeof(header_only)) > 0);
    LB_CHECK(lb_io_send(from, one_byte, sizeof(one_byte)) > 0);
    return 0;
}

static int t_dtls13_unauthenticated_datagrams(void)
{
    static const uint8_t c2s[] = "client data after garbage";
    static const uint8_t s2c[] = "server data after garbage";
    lb_pair_t pair;
    lb_cfg_t cfg;
    size_t base;

    base = lb_alloc_live_bytes();
    LB_RUN(lb_trust_ec_root());
    lb_cfg_default(&cfg, LB_PROTO_DTLS13);
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_CHECK_EQ(lb_pair_handshake(&pair), 0);
    LB_RUN(small_exchange(&pair));

    LB_RUN(inject_garbage(&pair, 1));
    LB_RUN(lb_transfer(&pair, 0, s2c, sizeof(s2c), TLS_MAX_RECORD_SIZE, sizeof(s2c)));
    LB_CHECK_EQ(lb_field_state(&pair.client), TLS_STATE_CONNECTED);

    LB_RUN(inject_garbage(&pair, 0));
    LB_RUN(lb_transfer(&pair, 1, c2s, sizeof(c2s), TLS_MAX_RECORD_SIZE, sizeof(c2s)));
    LB_CHECK_EQ(lb_field_state(&pair.server), TLS_STATE_CONNECTED);
    LB_CHECK_EQ(lb_field_state(&pair.client), TLS_STATE_CONNECTED);

    lb_pair_free(&pair);
    lb_trust_clear();
    return lb_expect_no_leak(base, "dtls13 garbage");
}
#endif

static const lb_test_case_t k_cases[] = {
    { "tls13_mtls_empty_trust_store", t_tls13_mtls_empty_trust_store },
#if NOXTLS_FEATURE_TLS12
    { "tls12_mtls_empty_trust_store", t_tls12_mtls_empty_trust_store },
    { "tls12_session_stores_clear", t_tls12_session_stores_clear },
#endif
    { "tls13_record_size_limit_minimum", t_record_size_limit_minimum },
    { "tls13_key_update_flood", t_key_update_flood },
    { "tls13_ticket_binding", t_ticket_binding },
    { "tls13_context_free_wipes", t_context_free_wipes },
    { "tls13_provider_certificate_verify", t_provider_certificate_verify },
    { "tls13_short_client_hello", t_short_client_hello },
#if NOXTLS_FEATURE_DTLS
    { "dtls13_unauthenticated_datagrams", t_dtls13_unauthenticated_datagrams },
#endif
};

int main(int argc, char **argv)
{
    return lb_main(argc, argv, "tls13_hardening", k_cases, sizeof(k_cases) / sizeof(k_cases[0]));
}
