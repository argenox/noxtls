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
* File:    tls12_audit_test.c
* Summary: TLS 1.2 / DTLS 1.2 regression tests for record, heartbeat, resumption and
*          renegotiation hardening
*****************************************************************************/
/** @file tls12_audit_test.c
 * @brief Relabelled and forged records are fatal, heartbeat-shaped application data is
 * delivered, a failed abbreviated handshake does not keep its session, a renegotiation
 * ClientHello must carry the previous verify_data, key-exchange contexts are wiped,
 * extension lists are bounded, the unified client does not retry TLS 1.2 after a failed
 * TLS 1.3 handshake, and an idle DTLS 1.2 accept returns.
 */
#include "lb_fixture.h"

#include <string.h>

#include "noxtls_tls_key_exchange.h"

#define REC_CCS        20U
#define REC_ALERT      21U
#define REC_HANDSHAKE  22U
#define REC_APP        23U
#define REC_HEARTBEAT  24U

static void wr16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 8U); p[1] = (uint8_t)v; }
static void wr24(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 16U); p[1] = (uint8_t)(v >> 8U); p[2] = (uint8_t)v; }

/** Write one TLS record as the peer of the endpoint that reads it. */
static int inject_record(lb_pair_t *pair, int to_client, uint8_t type, const uint8_t *body, uint32_t len)
{
    lb_port_t *writer = (to_client != 0) ? &pair->link->server_port : &pair->link->client_port;
    uint8_t hdr[5];
    hdr[0] = type;
    hdr[1] = 0x03U;
    hdr[2] = 0x03U;
    wr16(&hdr[3], len);
    LB_CHECK_EQ(lb_io_send(writer, hdr, 5U), 5);
    if(len > 0U) {
        LB_CHECK_EQ(lb_io_send(writer, body, len), (long)len);
    }
    return 0;
}

/** Number of TLS records of @p type queued in one direction (stream mode). */
static uint32_t count_records(const lb_pair_t *pair, int to_client, uint8_t type)
{
    const lb_pipe_t *p = (to_client != 0) ? &pair->link->to_client : &pair->link->to_server;
    uint32_t o = p->rd;
    uint32_t n = 0U;
    while((o + 5U) <= p->wr) {
        uint32_t rl = ((uint32_t)p->data[o + 3U] << 8U) | (uint32_t)p->data[o + 4U];
        if(p->data[o] == type) {
            n++;
        }
        o += 5U + rl;
    }
    return n;
}

/** Type of the first queued record in one direction, or -1. */
static int first_record_type(const lb_pair_t *pair, int to_client)
{
    const lb_pipe_t *p = (to_client != 0) ? &pair->link->to_client : &pair->link->to_server;
    return ((p->rd + 5U) <= p->wr) ? (int)p->data[p->rd] : -1;
}

/** Step an endpoint until it stops making progress; returns the last result. */
static noxtls_return_t step_until_blocked(lb_end_t *end)
{
    noxtls_return_t rc = NOXTLS_RETURN_WANT_READ;
    int i;
    for(i = 0; i < 16; i++) {
        rc = lb_end_step(end);
        (void)lb_end_flush(end);
        if(rc != NOXTLS_RETURN_WANT_WRITE) {
            break;
        }
    }
    return rc;
}

/* The trust store must be installed (lb_trust_ec_root) before the caller's leak baseline. */
static int connected_pair(lb_pair_t *pair, int heartbeat)
{
    static const uint16_t k_gcm[] = { TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 };
    lb_cfg_t cfg;

    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    cfg.server_suites = k_gcm;
    cfg.server_suite_count = 1U;
    LB_RUN(lb_pair_init(pair, &cfg));
    if(heartbeat != 0) {
        noxtls_tls12_set_heartbeat(pair->client.t12, 1);
        noxtls_tls12_set_heartbeat(pair->server.t12, 1);
    }
    LB_RUN(lb_pair_handshake(pair));
    if(heartbeat != 0) {
        LB_CHECK_EQ(pair->server.t12->heartbeat_negotiated, 1U);
        LB_CHECK_EQ(pair->client.t12->heartbeat_negotiated, 1U);
    }
    return 0;
}

/* ---- Heartbeat ------------------------------------------------------------ */

/* An application-data record relabelled as heartbeat must not authenticate (issue 70). */
static int t_heartbeat_relabel_fatal(void)
{
    static const uint8_t k_data[] = { 'B', 'B', 'B', 'B' };
    lb_pair_t pair;
    uint8_t buf[64];
    uint32_t len = (uint32_t)sizeof(buf);
    noxtls_return_t rc;
    size_t base;

    LB_RUN(lb_trust_ec_root());
    base = lb_alloc_live_bytes();
    LB_RUN(connected_pair(&pair, 1));
    LB_CHECK_OK(lb_end_send(&pair.client, k_data, (uint32_t)sizeof(k_data)));
    (void)lb_end_flush(&pair.client);
    LB_CHECK_EQ(first_record_type(&pair, 0), REC_APP);
    pair.link->to_server.data[pair.link->to_server.rd] = (uint8_t)REC_HEARTBEAT;
    rc = lb_end_recv(&pair.server, buf, &len);
    LB_CHECK(rc != NOXTLS_RETURN_SUCCESS);
    LB_CHECK(rc != NOXTLS_RETURN_WANT_READ);
    LB_CHECK_EQ(lb_field_state(&pair.server), TLS_STATE_CLOSED);
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "heartbeat relabel");
}

/* Application data that looks like a heartbeat message is delivered byte for byte (issue 134). */
static int t_heartbeat_shaped_app_data(void)
{
    uint8_t payload[27];
    lb_pair_t pair;
    size_t base;

    payload[0] = 0x01U;
    payload[1] = 0x00U;
    payload[2] = 0x04U;
    memcpy(&payload[3], "ECHO", 4U);
    memset(&payload[7], 'p', 16U);
    memcpy(&payload[23], "TAIL", 4U);
    LB_RUN(lb_trust_ec_root());
    base = lb_alloc_live_bytes();
    LB_RUN(connected_pair(&pair, 1));
    LB_RUN(lb_transfer(&pair, 1, payload, (uint32_t)sizeof(payload), TLS_MAX_RECORD_SIZE, (uint32_t)sizeof(payload)));
    /* Nothing (no heartbeat response) was sent back. */
    LB_CHECK_EQ(lb_link_pending(pair.link, 1), 0U);
    payload[0] = 0x02U;
    LB_RUN(lb_transfer(&pair, 0, payload, (uint32_t)sizeof(payload), TLS_MAX_RECORD_SIZE, (uint32_t)sizeof(payload)));
    LB_RUN(lb_close_and_observe(&pair, 1));
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "heartbeat-shaped data");
}

/* ---- Forged protected records -------------------------------------------- */

static int forged_record_closes(uint8_t type, uint32_t body_len)
{
    uint8_t body[64];
    uint8_t buf[64];
    uint32_t len = (uint32_t)sizeof(buf);
    lb_pair_t pair;
    noxtls_return_t rc;
    size_t base;

    memset(body, 0x41, sizeof(body));
    LB_RUN(lb_trust_ec_root());
    base = lb_alloc_live_bytes();
    LB_RUN(connected_pair(&pair, 0));
    LB_RUN(inject_record(&pair, 0, type, body, body_len));
    rc = lb_end_recv(&pair.server, buf, &len);
    LB_CHECK(rc != NOXTLS_RETURN_SUCCESS);
    LB_CHECK(rc != NOXTLS_RETURN_WANT_READ);
    /* RFC 5246 6.2.3 / 7.2.2: bad_record_mac closes the connection. */
    LB_CHECK_EQ(lb_field_state(&pair.server), TLS_STATE_CLOSED);
    LB_CHECK_EQ(first_record_type(&pair, 1), REC_ALERT);
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "forged record");
}

/* Issue 133: forged handshake and alert records end the connection like application data. */
static int t_forged_handshake_record_closes(void) { return forged_record_closes(REC_HANDSHAKE, 32U); }
/* 26 bytes: explicit nonce (8) + 2-byte alert + GCM tag (16), so it reaches the AEAD. */
static int t_forged_alert_record_closes(void) { return forged_record_closes(REC_ALERT, 26U); }

/* ---- Resumption ------------------------------------------------------------ */

/*
 * Issue 85: session state is committed only after the server Finished verifies. When an
 * abbreviated handshake fails at Finished, neither the NewSessionTicket it carried nor the
 * session it offered is kept, so the next connection takes a full handshake and succeeds.
 */
static int t_failed_resumption_discards_session(void)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    noxtls_return_t rc;
    int i;

    LB_RUN(lb_trust_ec_root());
    LB_CHECK_EQ(noxtls_tls12_client_session_has_ticket(), 0);
    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_RUN(lb_pair_handshake(&pair));
    LB_CHECK_EQ(noxtls_tls12_client_session_has_ticket(), 1);
    LB_RUN(lb_close_and_observe(&pair, 1));
    lb_pair_free(&pair);

    /* Abbreviated handshake whose server Finished is corrupted in transit. */
    LB_RUN(lb_pair_init(&pair, &cfg));
    rc = step_until_blocked(&pair.client);
    LB_CHECK_EQ(rc, NOXTLS_RETURN_WANT_READ);
    rc = step_until_blocked(&pair.server);
    LB_CHECK_EQ(rc, NOXTLS_RETURN_WANT_READ);
    LB_CHECK(pair.link->to_client.wr > pair.link->to_client.rd);
    pair.link->to_client.data[pair.link->to_client.wr - 1U] ^= 0x01U;
    for(i = 0; i < 8; i++) {
        rc = step_until_blocked(&pair.client);
        if(rc != NOXTLS_RETURN_WANT_READ) {
            break;
        }
    }
    LB_CHECK(rc != NOXTLS_RETURN_SUCCESS);
    LB_CHECK(rc != NOXTLS_RETURN_WANT_READ);
    LB_CHECK_EQ(lb_field_tls12_resumed(pair.client.t12), 1);
    LB_CHECK_EQ(noxtls_tls12_client_session_has_ticket(), 0);
    lb_pair_free(&pair);

    /* The next connection is a full handshake and issues a fresh session. */
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_RUN(lb_pair_handshake(&pair));
    LB_CHECK_EQ(lb_field_tls12_resumed(pair.client.t12), 0);
    LB_CHECK_EQ(noxtls_tls12_client_session_has_ticket(), 1);
    LB_RUN(lb_close_and_observe(&pair, 1));
    lb_pair_free(&pair);
    return 0;
}

/* ---- Renegotiation ---------------------------------------------------------- */

/** Build a renegotiation ClientHello whose renegotiation_info carries @p ri (ri_len bytes). */
static uint32_t build_reneg_client_hello(uint8_t *out, const uint8_t *ri, uint32_t ri_len)
{
    static const uint8_t k_ext[] = {
        0x00U, 0x0AU, 0x00U, 0x04U, 0x00U, 0x02U, 0x00U, 0x17U,   /* supported_groups: P-256 */
        0x00U, 0x0BU, 0x00U, 0x02U, 0x01U, 0x00U,                 /* ec_point_formats */
        0x00U, 0x0DU, 0x00U, 0x04U, 0x00U, 0x02U, 0x04U, 0x03U,   /* signature_algorithms */
        0x00U, 0x17U, 0x00U, 0x00U                                /* extended_master_secret */
    };
    uint32_t o = 4U;
    uint32_t ext_start;

    out[0] = 0x01U;
    out[o++] = 0x03U;
    out[o++] = 0x03U;
    lb_fill_pattern(&out[o], 32U, 0x5EU);
    o += 32U;
    out[o++] = 0x00U;
    wr16(&out[o], 2U);
    o += 2U;
    wr16(&out[o], TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    o += 2U;
    out[o++] = 0x01U;
    out[o++] = 0x00U;
    ext_start = o;
    o += 2U;
    memcpy(&out[o], k_ext, sizeof(k_ext));
    o += (uint32_t)sizeof(k_ext);
    wr16(&out[o], 0xFF01U);
    wr16(&out[o + 2U], ri_len);
    o += 4U;
    memcpy(&out[o], ri, ri_len);
    o += ri_len;
    wr16(&out[ext_start], o - ext_start - 2U);
    wr24(&out[1], o - 4U);
    return o;
}

/* Seal @p ch under the client's current keys and deliver it to the server after a HelloRequest. */
static int send_reneg_client_hello(lb_pair_t *pair, const uint8_t *ri, uint32_t ri_len)
{
    uint8_t ch[256];
    uint8_t sealed[512];
    uint32_t sealed_len = (uint32_t)sizeof(sealed);
    uint32_t ch_len = build_reneg_client_hello(ch, ri, ri_len);

    LB_CHECK_OK(noxtls_tls12_send_hello_request(pair->server.t12));
    (void)lb_end_flush(&pair->server);
    /* The HelloRequest is dropped; the "client" answers with a hand-made ClientHello. */
    pair->link->to_client.rd = pair->link->to_client.wr;
    LB_CHECK_OK(noxtls_tls12_encrypt_record(pair->client.t12, REC_HANDSHAKE, ch, ch_len, sealed, &sealed_len));
    LB_RUN(inject_record(pair, 0, REC_HANDSHAKE, sealed, sealed_len));
    return 0;
}

/* Issue 87 (RFC 5746 3.7): a renegotiation ClientHello without the previous verify_data fails. */
static int reneg_bad_signal(const uint8_t *ri, uint32_t ri_len)
{
    lb_pair_t pair;
    uint8_t buf[64];
    uint32_t len = (uint32_t)sizeof(buf);
    noxtls_return_t rc;
    size_t base;

    LB_RUN(lb_trust_ec_root());
    base = lb_alloc_live_bytes();
    LB_RUN(connected_pair(&pair, 0));
    LB_RUN(send_reneg_client_hello(&pair, ri, ri_len));
    rc = lb_end_recv(&pair.server, buf, &len);
    LB_CHECK_EQ(rc, NOXTLS_RETURN_TLS_ERROR);
    LB_CHECK_EQ(lb_field_state(&pair.server), TLS_STATE_CLOSED);
    /* handshake_failure alert, and no ServerHello. */
    LB_CHECK_EQ(first_record_type(&pair, 1), REC_ALERT);
    LB_CHECK_EQ(count_records(&pair, 1, REC_HANDSHAKE), 0U);
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "renegotiation signal");
}

static int t_reneg_requires_verify_data(void)
{
    static const uint8_t k_empty[] = { 0x00U };
    uint8_t wrong[13];
    wrong[0] = 12U;
    memset(&wrong[1], 0xAA, 12U);
    LB_RUN(reneg_bad_signal(k_empty, (uint32_t)sizeof(k_empty)));
    LB_RUN(reneg_bad_signal(wrong, (uint32_t)sizeof(wrong)));
    return 0;
}

/* Control for the test above: the correct verify_data gets a ServerHello. */
static int t_reneg_correct_verify_data_proceeds(void)
{
    lb_pair_t pair;
    uint8_t ri[13];
    uint8_t buf[64];
    uint32_t len = (uint32_t)sizeof(buf);
    size_t base;

    LB_RUN(lb_trust_ec_root());
    base = lb_alloc_live_bytes();
    LB_RUN(connected_pair(&pair, 0));
    ri[0] = 12U;
    memcpy(&ri[1], pair.client.t12->previous_client_verify_data, 12U);
    LB_RUN(send_reneg_client_hello(&pair, ri, (uint32_t)sizeof(ri)));
    (void)lb_end_recv(&pair.server, buf, &len);
    LB_CHECK_EQ(first_record_type(&pair, 1), REC_HANDSHAKE);
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "renegotiation control");
}

/* ---- Key exchange contexts -------------------------------------------------- */

/* Issue 86: freeing a DHE context leaves no key material or shared secret in the struct. */
static int t_dhe_context_free_wipes(void)
{
#if NOXTLS_FEATURE_DH
    tls_dhe_context_t dhe;
    const uint8_t *raw = (const uint8_t *)&dhe;
    size_t i;

    LB_CHECK_OK(noxtls_tls_dhe_context_init(&dhe, TLS_NAMED_GROUP_FFDHE2048));
    memset(dhe.server_private, 0xA5, dhe.p_len);
    memset(dhe.client_private, 0xA5, dhe.p_len);
    memset(dhe.premaster_secret, 0xA5, dhe.p_len);
    dhe.premaster_secret_len = dhe.p_len;
    LB_CHECK_OK(noxtls_tls_dhe_context_free(&dhe));
    for(i = 0U; i < sizeof(dhe); i++) {
        LB_CHECK_EQ(raw[i], 0);
    }
    return 0;
#else
    return LB_SKIP;
#endif
}

/* Issue 174: a zero-length handshake record is rejected, not dereferenced. */
static int t_ecdhe_recv_skx_empty_record(void)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    tls_ecdhe_context_t ecdhe;
    size_t base;

    LB_RUN(lb_trust_ec_root());
    base = lb_alloc_live_bytes();
    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_CHECK_OK(noxtls_tls_ecdhe_context_init(&ecdhe, TLS_NAMED_GROUP_SECP256R1));
    LB_RUN(inject_record(&pair, 1, REC_HANDSHAKE, NULL, 0U));
    LB_CHECK_EQ(noxtls_tls12_ecdhe_recv_server_key_exchange(pair.client.t12, &ecdhe), NOXTLS_RETURN_FAILED);
    (void)noxtls_tls_ecdhe_context_free(&ecdhe);
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "empty SKX");
}

/* ---- Extension list bounds --------------------------------------------------- */

static uint8_t s_ext[4U * 200U + 2U];

static uint32_t build_extensions(uint32_t count)
{
    uint32_t i;
    uint32_t o = 2U;
    for(i = 0U; i < count; i++) {
        wr16(&s_ext[o], 0x1000U + i);
        wr16(&s_ext[o + 2U], 0U);
        o += 4U;
    }
    wr16(s_ext, o - 2U);
    return o;
}

static uint32_t build_key_shares(uint32_t count)
{
    uint32_t i;
    uint32_t o = 2U;
    for(i = 0U; i < count; i++) {
        wr16(&s_ext[o], 0x2000U + i);
        wr16(&s_ext[o + 2U], 0U);
        o += 4U;
    }
    wr16(s_ext, o - 2U);
    return o;
}

/* Issue 167: extension and key_share counts are capped before the pairwise duplicate checks. */
static int t_extension_lists_bounded(void)
{
    tls_extensions_t exts;
    tls_key_share_list_extension_t ks;
    uint32_t len;
    size_t base = lb_alloc_live_bytes();

    len = build_extensions(128U);
    LB_CHECK_OK(noxtls_tls_parse_extensions(s_ext, len, &exts));
    LB_CHECK_EQ(exts.count, 128U);
    (void)noxtls_tls_extensions_free(&exts);
    len = build_extensions(129U);
    LB_CHECK_EQ(noxtls_tls_parse_extensions(s_ext, len, &exts), NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);

    memset(&ks, 0, sizeof(ks));
    len = build_key_shares(64U);
    LB_CHECK_OK(noxtls_tls_parse_extension_key_share(s_ext, len, &ks));
    LB_CHECK_EQ(ks.count, 64U);
    noxtls_free(ks.entries);
    memset(&ks, 0, sizeof(ks));
    len = build_key_shares(65U);
    LB_CHECK_EQ(noxtls_tls_parse_extension_key_share(s_ext, len, &ks), NOXTLS_RETURN_BAD_DATA);
    return lb_expect_no_leak(base, "extension bounds");
}

/* ---- Unified client ----------------------------------------------------------- */

/* Issue 92: a TLS 1.3 handshake ended by a forged alert is not retried as TLS 1.2. */
static int t_unified_no_tls12_retry(void)
{
#if NOXTLS_FEATURE_TLS13
    static const uint8_t k_alert[] = { 0x02U, 0x28U };
    lb_pair_t pair;
    lb_cfg_t cfg;
    noxtls_return_t rc;
    size_t base;

    LB_RUN(lb_trust_ec_root());
    base = lb_alloc_live_bytes();
    lb_cfg_default(&cfg, LB_PROTO_UNIFIED);
    LB_RUN(lb_pair_init(&pair, &cfg));
    /* The forged alert is already waiting when the client sends its first ClientHello. */
    LB_RUN(inject_record(&pair, 1, REC_ALERT, k_alert, (uint32_t)sizeof(k_alert)));
    rc = step_until_blocked(&pair.client);
    LB_CHECK(rc != NOXTLS_RETURN_SUCCESS);
    LB_CHECK(rc != NOXTLS_RETURN_WANT_READ);
    LB_CHECK_EQ(count_records(&pair, 0, REC_HANDSHAKE), 1U);
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "unified no retry");
#else
    return LB_SKIP;
#endif
}

/* ---- DTLS 1.2 ------------------------------------------------------------------ */

/*
 * Issue 107: a blocking DTLS 1.2 accept returns NOXTLS_RETURN_TIMEOUT on an idle transport,
 * and answers each cookie-less ClientHello with exactly one HelloVerifyRequest.
 */
static int t_dtls12_accept_idle_returns(void)
{
#if NOXTLS_FEATURE_DTLS
    lb_pair_t pair;
    lb_cfg_t cfg;
    uint32_t hellos;
    size_t base;

    LB_RUN(lb_trust_ec_root());
    base = lb_alloc_live_bytes();
    lb_cfg_default(&cfg, LB_PROTO_DTLS12);
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_CHECK_EQ(noxtls_tls12_accept(pair.server.t12), NOXTLS_RETURN_TIMEOUT);
    LB_CHECK_EQ(pair.link->to_client.dgram_count, 0U);

    /* Without a time callback the client retransmits its ClientHello and then gives up. */
    pair.client.t12->base.base.time_callback = NULL;
    LB_CHECK_EQ(noxtls_tls12_connect(pair.client.t12), NOXTLS_RETURN_TIMEOUT);
    hellos = pair.link->to_server.dgram_count;
    LB_CHECK(hellos >= 1U);
    LB_CHECK_EQ(noxtls_tls12_accept(pair.server.t12), NOXTLS_RETURN_TIMEOUT);
    LB_CHECK_EQ(pair.link->to_server.dgram_count, 0U);
    LB_CHECK_EQ(pair.link->to_client.dgram_count, hellos);
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "dtls idle accept");
#else
    return LB_SKIP;
#endif
}

static const lb_test_case_t k_cases[] = {
    { "tls12_heartbeat_relabel_fatal", t_heartbeat_relabel_fatal },
    { "tls12_heartbeat_shaped_app_data", t_heartbeat_shaped_app_data },
    { "tls12_forged_handshake_record_closes", t_forged_handshake_record_closes },
    { "tls12_forged_alert_record_closes", t_forged_alert_record_closes },
    { "tls12_failed_resumption_discards_session", t_failed_resumption_discards_session },
    { "tls12_reneg_requires_verify_data", t_reneg_requires_verify_data },
    { "tls12_reneg_correct_verify_data_proceeds", t_reneg_correct_verify_data_proceeds },
    { "tls12_dhe_context_free_wipes", t_dhe_context_free_wipes },
    { "tls12_ecdhe_recv_skx_empty_record", t_ecdhe_recv_skx_empty_record },
    { "tls_extension_lists_bounded", t_extension_lists_bounded },
    { "unified_no_tls12_retry_after_tls13_failure", t_unified_no_tls12_retry },
    { "dtls12_accept_idle_returns", t_dtls12_accept_idle_returns },
};

int main(int argc, char **argv)
{
    return lb_main(argc, argv, "tls12_audit", k_cases, sizeof(k_cases) / sizeof(k_cases[0]));
}
