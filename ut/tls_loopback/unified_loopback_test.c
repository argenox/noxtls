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
* File:    unified_loopback_test.c
* Summary: End-to-end tests of the version-negotiating noxtls_tls_connection_* API
*****************************************************************************/
/** @file unified_loopback_test.c
 * @brief TLS 1.3 negotiation, client downgrade to a TLS 1.2-only server,
 * fixed-version endpoints, resumption, mutual TLS and record payload limits
 * through the unified connection API.
 */
#include "lb_fixture.h"

#include <stdlib.h>
#include <string.h>

static uint8_t s_payload[65536U + 64U];

static int exchange(lb_pair_t *pair, uint32_t size, uint32_t rx_chunk)
{
    lb_fill_pattern(s_payload, size, size);
    LB_RUN(lb_transfer(pair, 1, s_payload, size, TLS_MAX_RECORD_SIZE, rx_chunk));
    lb_fill_pattern(s_payload, size, size + 7U);
    LB_RUN(lb_transfer(pair, 0, s_payload, size, TLS_MAX_RECORD_SIZE, rx_chunk));
    return 0;
}

/** Handshake with cfg, check version on both sides, exchange data, close and free. */
static int run_unified(const lb_cfg_t *cfg, uint16_t expect_version)
{
    lb_pair_t pair;
    const uint8_t *der = NULL;
    uint32_t der_len = 0U;
    size_t base;

    LB_RUN(lb_trust_all_roots());
    base = lb_alloc_live_bytes();
    LB_RUN(lb_pair_init(&pair, cfg));
    if(cfg->unified_client_version == 0U) {
        LB_CHECK_EQ(noxtls_tls_connection_get_version(pair.client.uni), 0U);
    }
    if(lb_pair_handshake(&pair) != 0) {
        lb_log("handshake failed: client rc=%d server rc=%d", (int)pair.client.last_rc, (int)pair.server.last_rc);
        lb_pair_free(&pair);
        return 1;
    }
    LB_CHECK_EQ(lb_end_version(&pair.client), expect_version);
    LB_CHECK_EQ(lb_end_version(&pair.server), expect_version);
    LB_CHECK(lb_end_cipher_suite(&pair.client) != 0U);
    LB_CHECK_EQ(lb_end_cipher_suite(&pair.client), lb_end_cipher_suite(&pair.server));
    /* The authenticated server leaf stays available to the client after the handshake. */
    LB_CHECK_OK(noxtls_tls_connection_get_peer_certificate(pair.client.uni, &der, &der_len));
    LB_CHECK_EQ(der_len, lb_rsa_server_cert_len);
    LB_CHECK(memcmp(der, lb_rsa_server_cert, der_len) == 0);
    LB_RUN(exchange(&pair, 1U, 64U));
    LB_RUN(exchange(&pair, 5000U, 5000U));
    LB_RUN(exchange(&pair, 65536U, 777U));
    LB_RUN(lb_close_and_observe(&pair, 1));
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "unified session");
}

/**
 * server_version TLS_VERSION_1_2 selects a TLS 1.2-only server built on the
 * noxtls_tls12_* API (see t_server_fixed_version for why not init_version).
 */
static void cfg_unified(lb_cfg_t *cfg, uint16_t client_version, uint16_t server_version)
{
    lb_cfg_default(cfg, LB_PROTO_UNIFIED);
    cfg->server_auth = LB_AUTH_RSA;
    cfg->sni = "rsa.test";
    cfg->unified_client_version = client_version;
    if(server_version == TLS_VERSION_1_2) {
        cfg->server_proto_override = 1;
        cfg->server_proto = LB_PROTO_TLS12;
    } else {
        cfg->unified_server_version = server_version;
    }
}

/*
 * noxtls_tls_connection_init_version(server, TLS_VERSION_1_2) is documented as "only that
 * version is used": accept() must negotiate TLS 1.2 even when the ClientHello offers 1.3.
 */
static int t_server_fixed_version(void)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    uint16_t version;
    size_t base;

    LB_RUN(lb_trust_all_roots());
    base = lb_alloc_live_bytes();
    lb_cfg_default(&cfg, LB_PROTO_UNIFIED);
    cfg.server_auth = LB_AUTH_RSA;
    cfg.sni = "rsa.test";
    cfg.unified_server_version = TLS_VERSION_1_2;
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_RUN(lb_pair_handshake(&pair));
    version = lb_end_version(&pair.server);
    LB_CHECK_EQ(lb_end_version(&pair.client), version);
    LB_RUN(exchange(&pair, 100U, 100U));
    lb_pair_free(&pair);
    LB_RUN(lb_expect_no_leak(base, "fixed version"));
    LB_CHECK_EQ(version, TLS_VERSION_1_2);
    return 0;
}

static int t_tls13_negotiation(void)
{
    lb_cfg_t cfg;
    cfg_unified(&cfg, 0U, 0U);
    return run_unified(&cfg, TLS_VERSION_1_3);
}

static int t_downgrade_to_tls12_server(void)
{
    lb_cfg_t cfg;
    cfg_unified(&cfg, 0U, TLS_VERSION_1_2);
    return run_unified(&cfg, TLS_VERSION_1_2);
}

static int t_tls12_client_auto_server(void)
{
    lb_cfg_t cfg;
    cfg_unified(&cfg, TLS_VERSION_1_2, 0U);
    return run_unified(&cfg, TLS_VERSION_1_2);
}

static int t_tls13_fixed_both(void)
{
    lb_cfg_t cfg;
    cfg_unified(&cfg, TLS_VERSION_1_3, TLS_VERSION_1_3);
    return run_unified(&cfg, TLS_VERSION_1_3);
}

static int t_version_mismatch(void)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    size_t base;

    LB_RUN(lb_trust_all_roots());
    base = lb_alloc_live_bytes();
    /* A TLS 1.3-only client must not complete against a TLS 1.2-only server. */
    cfg_unified(&cfg, TLS_VERSION_1_3, TLS_VERSION_1_2);
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_CHECK(lb_pair_handshake(&pair) != 0);
    LB_CHECK(!((pair.client.done != 0) && (pair.server.done != 0)));
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "version mismatch");
}

static int t_mtls_ecdsa_client(void)
{
    uint32_t i;
    for(i = 0U; i < 2U; i++) {
        lb_cfg_t cfg;
        cfg_unified(&cfg, 0U, (i == 0U) ? 0U : TLS_VERSION_1_2);
        cfg.client_auth = 2;
        cfg.client_cert = LB_AUTH_ECDSA;
        if(run_unified(&cfg, (i == 0U) ? TLS_VERSION_1_3 : TLS_VERSION_1_2) != 0) {
            lb_log("mTLS over %s failed", (i == 0U) ? "TLS 1.3" : "TLS 1.2");
            return 1;
        }
        lb_trust_clear();
    }
    return 0;
}

static int t_tls13_resumption(void)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    noxtls_tls13_session_t session;
    const uint8_t *identity = NULL;
    uint16_t identity_len = 0U;
    size_t base;

    LB_RUN(lb_trust_all_roots());
    base = lb_alloc_live_bytes();
    cfg_unified(&cfg, 0U, 0U);
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_RUN(lb_pair_handshake(&pair));
    LB_CHECK_EQ(noxtls_tls_connection_is_resumed(pair.client.uni), 0);
    LB_RUN(exchange(&pair, 100U, 100U));
    LB_CHECK_OK(noxtls_tls_connection_get_session_identity(pair.client.uni, &identity, &identity_len));
    LB_CHECK(identity_len > 0U);
    LB_CHECK_OK(noxtls_tls13_session_export(lb_field_unified_tls13(pair.client.uni), &session));
    lb_pair_free(&pair);

    cfg_unified(&cfg, 0U, 0U);
    cfg.tls13_session = &session;
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_RUN(lb_pair_handshake(&pair));
    LB_CHECK_EQ(lb_end_version(&pair.client), TLS_VERSION_1_3);
    LB_CHECK(noxtls_tls_connection_is_resumed(pair.client.uni) != 0);
    LB_CHECK(noxtls_tls_connection_is_resumed(pair.server.uni) != 0);
    LB_CHECK_OK(noxtls_tls_connection_get_resumption_identity(pair.server.uni, &identity, &identity_len));
    LB_CHECK_EQ(identity_len, session.ticket_identity_len);
    LB_RUN(exchange(&pair, 3000U, 1000U));
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "unified resumption");
}

static int t_tls12_resumption(void)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    uint32_t round;
    size_t base;

    LB_RUN(lb_trust_all_roots());
    base = lb_alloc_live_bytes();
    for(round = 0U; round < 2U; round++) {
        cfg_unified(&cfg, 0U, TLS_VERSION_1_2);
        LB_RUN(lb_pair_init(&pair, &cfg));
        LB_RUN(lb_pair_handshake(&pair));
        LB_CHECK_EQ(lb_end_version(&pair.client), TLS_VERSION_1_2);
        LB_CHECK_EQ(noxtls_tls_connection_is_resumed(pair.client.uni), (round == 0U) ? 0 : 1);
        LB_CHECK_EQ(lb_field_tls12_resumed(pair.server.t12), (round == 0U) ? 0 : 1);
        LB_RUN(exchange(&pair, 1000U, 1000U));
        LB_RUN(lb_close_and_observe(&pair, 0));
        lb_pair_free(&pair);
    }
    return lb_expect_no_leak(base, "unified tls12 resumption");
}

static int t_maximum_record_payload(void)
{
    uint32_t i;
    for(i = 0U; i < 2U; i++) {
        lb_pair_t pair;
        lb_cfg_t cfg;
        size_t base;
        LB_RUN(lb_trust_all_roots());
        base = lb_alloc_live_bytes();
        cfg_unified(&cfg, 0U, (i == 0U) ? 0U : TLS_VERSION_1_2);
        LB_RUN(lb_pair_init(&pair, &cfg));
        LB_CHECK_OK(noxtls_tls_connection_set_maximum_record_payload(pair.client.uni, 1024U));
        if(pair.server.uni != NULL) {
            LB_CHECK_OK(noxtls_tls_connection_set_maximum_record_payload(pair.server.uni, 1024U));
        }
        LB_CHECK(noxtls_tls_connection_set_maximum_record_payload(pair.client.uni, 1000U) != NOXTLS_RETURN_SUCCESS);
        LB_RUN(lb_pair_handshake(&pair));
        LB_RUN(exchange(&pair, 20000U, 20000U));
        LB_RUN(exchange(&pair, 3000U, 10U));
        lb_pair_free(&pair);
        LB_RUN(lb_expect_no_leak(base, "record payload"));
        lb_trust_clear();
    }
    return 0;
}

static int t_fragmented_transport(void)
{
    lb_cfg_t cfg;
    cfg_unified(&cfg, 0U, TLS_VERSION_1_2);
    cfg.max_chunk = 3U;
    cfg.block_every = 5U;
    LB_RUN(run_unified(&cfg, TLS_VERSION_1_2));
    lb_trust_clear();
    cfg_unified(&cfg, 0U, 0U);
    cfg.max_chunk = 3U;
    cfg.block_every = 5U;
    return run_unified(&cfg, TLS_VERSION_1_3);
}

/*
 * KNOWN ISSUE (reported, TLS stream): noxtls_tls_connection_handshake() is documented
 * to return SUCCESS / WANT_READ / WANT_WRITE and to be called again until SUCCESS. When
 * the final flight cannot be written in one go (slow link), unified_poll_result() turns
 * the version context's SUCCESS into WANT_WRITE; the next call re-enters
 * noxtls_tls13_connect() on a CONNECTED context, which restarts the handshake with a new
 * ClientHello, so the connection never completes. This test drives the API strictly by
 * its contract (no CONNECTED-state workaround) and reports SKIP while the issue exists.
 */
static int t_handshake_reentry_after_want_write(void)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    int hs;
    size_t base;

    LB_RUN(lb_trust_all_roots());
    base = lb_alloc_live_bytes();
    cfg_unified(&cfg, 0U, 0U);
    cfg.max_chunk = 3U;
    g_lb_strict_unified = 1;
    LB_RUN(lb_pair_init(&pair, &cfg));
    hs = lb_pair_handshake(&pair);
    g_lb_strict_unified = 0;
    if(hs == 0) {
        LB_RUN(exchange(&pair, 1000U, 1000U));
    }
    lb_pair_free(&pair);
    LB_RUN(lb_expect_no_leak(base, "re-entry"));
    LB_CHECK_EQ(hs, 0);
    return 0;
}

static const lb_test_case_t k_cases[] = {
    { "unified_tls13_negotiation", t_tls13_negotiation },
    { "unified_downgrade_to_tls12_server", t_downgrade_to_tls12_server },
    { "unified_tls12_client_auto_server", t_tls12_client_auto_server },
    { "unified_tls13_fixed_both", t_tls13_fixed_both },
    { "unified_version_mismatch", t_version_mismatch },
    { "unified_mtls_ecdsa_client", t_mtls_ecdsa_client },
    { "unified_tls13_resumption", t_tls13_resumption },
    { "unified_tls12_resumption", t_tls12_resumption },
    { "unified_maximum_record_payload", t_maximum_record_payload },
    { "unified_fragmented_transport", t_fragmented_transport },
    { "unified_server_fixed_version", t_server_fixed_version },
    { "unified_handshake_reentry_after_want_write", t_handshake_reentry_after_want_write },
};

int main(int argc, char **argv)
{
    return lb_main(argc, argv, "unified_loopback", k_cases, sizeof(k_cases) / sizeof(k_cases[0]));
}
