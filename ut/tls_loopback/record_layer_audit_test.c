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
* File:    record_layer_audit_test.c
* Summary: Record-layer and DTLS retransmission regression tests
*****************************************************************************/
/** @file record_layer_audit_test.c
 * @brief Regression tests for record-layer findings: DTLS replay window updated only after
 * authentication, sequence numbers consumed on failed sends, bounded DTLS retransmission
 * (peer-triggered storm, anti-amplification on retransmissions, no HelloVerifyRequest timer),
 * cookies bound to a peer identity, empty TLS heartbeat records, TLS 1.0 CBC record splitting
 * and MAC-then-encrypt CBC records with every padding length.
 *
 * Some tests read or set context fields directly: the scenarios need state (sequence numbers,
 * replay window, keys) that has no public accessor.
 */
#include "lb_fixture.h"

#include <string.h>

#include "mac/noxtls_hmac.h"
#include "encryption/aes/noxtls_aes.h"

/* ------------------------------------------------------------------------- */
/* Transport wrappers                                                        */
/* ------------------------------------------------------------------------- */

/* Virtual clock for the tests that install their own time callback. */
static uint64_t s_clock_ms = 1000U;
/* Simulated blocking time of an empty receive (a socket timeout). */
static uint64_t s_idle_ms = 0U;
/* Datagrams / bytes handed to the send callbacks. */
static uint32_t s_dgrams = 0U;
static uint64_t s_server_tx_bytes = 0U;
static uint32_t s_server_tx_dgrams = 0U;
static uint32_t s_idle_reads = 0U;
/* Abort limits that end a run that would otherwise not terminate. */
static uint32_t s_dgram_cap = 0U;
static uint32_t s_idle_cap = 0U;
/* Server: drop datagrams that carry a Certificate handshake fragment. */
static int s_drop_certificate = 0;
/* Server: count and discard instead of delivering to the client. */
static int s_server_discard = 0;
/* Next send: 1 emits the datagram and reports failure. */
static int s_fail_next_send = 0;
/* Client receive fails at once (the client stops after its first flight). */
static int s_client_recv_fail = 0;

static uint64_t t_now_ms(void *user)
{
    (void)user;
    return s_clock_ms;
}

static void t_reset_counters(void)
{
    s_clock_ms = 1000U;
    s_idle_ms = 0U;
    s_dgrams = 0U;
    s_server_tx_bytes = 0U;
    s_server_tx_dgrams = 0U;
    s_idle_reads = 0U;
    s_dgram_cap = 0U;
    s_idle_cap = 0U;
    s_drop_certificate = 0;
    s_server_discard = 0;
    s_fail_next_send = 0;
    s_client_recv_fail = 0;
}

static int32_t t_send(void *user, const uint8_t *data, uint32_t len)
{
    lb_port_t *port = (lb_port_t *)user;
    s_dgrams++;
    if(port->is_client == 0) {
        s_server_tx_bytes += len;
        s_server_tx_dgrams++;
        if(s_server_discard != 0) {
            return (int32_t)len;
        }
        if((s_drop_certificate != 0) && (len > (DTLS_RECORD_HEADER_SIZE + 1U)) &&
           (data[0] == TLS_RECORD_HANDSHAKE) && (data[DTLS_RECORD_HEADER_SIZE] == TLS_HANDSHAKE_CERTIFICATE)) {
            return (int32_t)len; /* lost on the path, every time */
        }
    }
    if(s_fail_next_send != 0) {
        /* The datagram leaves the device, but the transport reports an error. */
        s_fail_next_send = 0;
        (void)lb_io_send(user, data, len);
        return -1;
    }
    return lb_io_send(user, data, len);
}

static int32_t t_recv(void *user, uint8_t *data, uint32_t len)
{
    int32_t rc;
    if((s_client_recv_fail != 0) && (((lb_port_t *)user)->is_client != 0)) {
        return -1;
    }
    if((s_dgram_cap != 0U) && (s_dgrams > s_dgram_cap)) {
        return -1; /* harness cap: the exchange did not terminate on its own */
    }
    rc = lb_io_recv(user, data, len);
    if(rc == 0) {
        s_idle_reads++;
        s_clock_ms += s_idle_ms;
        if((s_idle_cap != 0U) && (s_idle_reads > s_idle_cap)) {
            return -1;
        }
    }
    return rc;
}

static int t_wrap_end(lb_pair_t *pair, lb_end_t *end, int is_client)
{
    lb_port_t *port = (is_client != 0) ? &pair->link->client_port : &pair->link->server_port;
    tls_context_t *base = lb_end_base(end);
    LB_CHECK_OK(noxtls_tls_set_io_callbacks(base, t_send, t_recv, port));
    LB_CHECK_OK(noxtls_tls_set_time_callback(base, t_now_ms));
    return 0;
}

static dtls_context_t *t_dtls(lb_end_t *end)
{
    return (end->t12 != NULL) ? &end->t12->base : &end->t13->base;
}

/* ------------------------------------------------------------------------- */
/* DTLS 1.2: replay window updated only after authentication (issue 62)       */
/* ------------------------------------------------------------------------- */

static int dtls12_connected_pair(lb_pair_t *pair)
{
    static const uint16_t suite = TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    lb_cfg_t cfg;
    lb_cfg_default(&cfg, LB_PROTO_DTLS12);
    cfg.server_suites = &suite;
    cfg.server_suite_count = 1U;
    LB_RUN(lb_pair_init(pair, &cfg));
    if(lb_pair_handshake(pair) != 0) {
        lb_log("handshake failed: client rc=%d server rc=%d", (int)pair->client.last_rc, (int)pair->server.last_rc);
        lb_pair_free(pair);
        return 1;
    }
    return 0;
}

static int t_dtls12_forged_seq_window(void)
{
    static const uint8_t msgs[3][4] = { { 'A', 'A', 'A', 'A' }, { 'B', 'B', 'B', 'B' }, { 'C', 'C', 'C', 'C' } };
    uint8_t forged[DTLS_RECORD_HEADER_SIZE + 48U];
    lb_pair_t pair;
    size_t base;
    uint32_t i;
    dtls_context_t *cd;

#if !(NOXTLS_FEATURE_DTLS && NOXTLS_FEATURE_TLS12 && NOXTLS_FEATURE_AES_GCM)
    return LB_SKIP;
#endif
    LB_RUN(lb_trust_ec_root());
    base = lb_alloc_live_bytes();
    LB_RUN(dtls12_connected_pair(&pair));
    cd = t_dtls(&pair.client);
    LB_CHECK_EQ(cd->read_epoch, 1U);

    /* Off-path forgery: handshake record of the current read epoch, sequence 2^48-1, no keys. */
    memset(forged, 0x41, sizeof(forged));
    forged[0] = TLS_RECORD_HANDSHAKE;
    forged[1] = 0xFEU;
    forged[2] = 0xFDU;
    forged[3] = 0x00U;
    forged[4] = 0x01U;
    memset(&forged[5], 0xFF, 6U);
    forged[11] = 0x00U;
    forged[12] = 48U;
    LB_CHECK_EQ(lb_io_send(&pair.link->server_port, forged, (uint32_t)sizeof(forged)), (int32_t)sizeof(forged));
    {
        uint8_t buf[64];
        uint32_t len = sizeof(buf);
        noxtls_return_t rc = noxtls_tls12_recv(pair.client.t12, buf, &len);
        LB_CHECK(rc != NOXTLS_RETURN_SUCCESS); /* forged record does not authenticate */
    }
    /* The unauthenticated sequence number must not have entered the window. */
    LB_CHECK(cd->replay_window.last_seq < 0xFFFFFFFFFFFFULL);
    LB_CHECK_EQ(lb_field_state(&pair.client), TLS_STATE_CONNECTED);

    for(i = 0U; i < 3U; i++) {
        uint8_t buf[64];
        uint32_t len = sizeof(buf);
        LB_CHECK_OK(noxtls_tls12_send(pair.server.t12, msgs[i], 4U));
        LB_CHECK_OK(lb_recv_some(&pair, &pair.client, buf, &len));
        LB_CHECK_EQ(len, 4U);
        LB_CHECK(memcmp(buf, msgs[i], 4U) == 0);
    }
    /* A genuine record still advances the window, and a replay of it is discarded. */
    LB_CHECK(cd->replay_window.last_seq > 0U);
    LB_CHECK(noxtls_dtls_check_replay(cd, cd->replay_window.last_seq) != NOXTLS_RETURN_SUCCESS);
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "dtls12 window");
}

/* ------------------------------------------------------------------------- */
/* DTLS: a failed send consumes the sequence number (issue 115)               */
/* ------------------------------------------------------------------------- */

static int t_dtls_send_failure_burns_seq(lb_proto_t proto)
{
    uint8_t a[64];
    uint8_t b[64];
    lb_pair_t pair;
    lb_cfg_t cfg;
    size_t base;
    dtls_context_t *cd;
    uint64_t seq_before;
    uint8_t buf[128];
    uint32_t len;

    memset(a, 'A', sizeof(a));
    memset(b, 'B', sizeof(b));
    LB_RUN(lb_trust_ec_root());
    base = lb_alloc_live_bytes();
    if(proto == LB_PROTO_DTLS12) {
        LB_RUN(dtls12_connected_pair(&pair));
    } else {
        lb_cfg_default(&cfg, proto);
        LB_RUN(lb_pair_init(&pair, &cfg));
        if(lb_pair_handshake(&pair) != 0) {
            lb_log("handshake failed: client rc=%d server rc=%d", (int)pair.client.last_rc, (int)pair.server.last_rc);
            lb_pair_free(&pair);
            return 1;
        }
    }
    t_reset_counters();
    LB_RUN(t_wrap_end(&pair, &pair.client, 1));
    cd = t_dtls(&pair.client);
    seq_before = cd->write_seq_num;

    s_fail_next_send = 1;
    LB_CHECK(lb_end_send(&pair.client, a, sizeof(a)) != NOXTLS_RETURN_SUCCESS);
    /* The sealed record went out: its sequence number (AEAD nonce) is used up. */
    LB_CHECK_EQ(cd->write_seq_num, seq_before + 1U);
    LB_CHECK_OK(lb_end_send(&pair.client, b, sizeof(b)));
    LB_CHECK_EQ(cd->write_seq_num, seq_before + 2U);

    /* Both records carry distinct nonces: the receiver accepts both, in order. */
    len = sizeof(buf);
    LB_CHECK_OK(lb_recv_some(&pair, &pair.server, buf, &len));
    LB_CHECK_EQ(len, sizeof(a));
    LB_CHECK(memcmp(buf, a, sizeof(a)) == 0);
    len = sizeof(buf);
    LB_CHECK_OK(lb_recv_some(&pair, &pair.server, buf, &len));
    LB_CHECK_EQ(len, sizeof(b));
    LB_CHECK(memcmp(buf, b, sizeof(b)) == 0);
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "dtls send failure");
}

static int t_dtls12_send_failure_burns_seq(void)
{
#if NOXTLS_FEATURE_DTLS && NOXTLS_FEATURE_TLS12 && NOXTLS_FEATURE_AES_GCM
    return t_dtls_send_failure_burns_seq(LB_PROTO_DTLS12);
#else
    return LB_SKIP;
#endif
}

static int t_dtls13_send_failure_burns_seq(void)
{
#if NOXTLS_FEATURE_DTLS && NOXTLS_FEATURE_TLS13
    return t_dtls_send_failure_burns_seq(LB_PROTO_DTLS13);
#else
    return LB_SKIP;
#endif
}

/* ------------------------------------------------------------------------- */
/* DTLS 1.2: persistent loss of one datagram ends the handshake (issue 61)     */
/* ------------------------------------------------------------------------- */

static int t_dtls12_lost_datagram_bounded(void)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    size_t base;

#if !(NOXTLS_FEATURE_DTLS && NOXTLS_FEATURE_TLS12)
    return LB_SKIP;
#endif
    LB_RUN(lb_trust_ec_root());
    base = lb_alloc_live_bytes();
    lb_cfg_default(&cfg, LB_PROTO_DTLS12);
    LB_RUN(lb_pair_init(&pair, &cfg));
    t_reset_counters();
    LB_RUN(t_wrap_end(&pair, &pair.client, 1));
    LB_RUN(t_wrap_end(&pair, &pair.server, 0));
    /* Every Certificate datagram is lost; a socket timeout above the 60 s timer cap means
     * every empty receive reaches the retransmission timer. */
    s_drop_certificate = 1;
    s_idle_ms = 61000U;
    s_dgram_cap = 3000U;

    LB_CHECK(lb_pair_handshake(&pair) != 0);
    lb_log("datagrams=%u client rc=%d server rc=%d", s_dgrams, (int)pair.client.last_rc, (int)pair.server.last_rc);
    /* Both calls returned on their own (not through the harness cap) after a bounded exchange:
     * the server gives up when its retransmission budget is spent and the client fails too. */
    LB_CHECK(s_dgrams <= 200U);
    LB_CHECK(pair.client.last_rc != NOXTLS_RETURN_SUCCESS);
    LB_CHECK_EQ(pair.server.last_rc, NOXTLS_RETURN_TIMEOUT);
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "dtls12 lost datagram");
}

/* ------------------------------------------------------------------------- */
/* DTLS: retransmissions to an unvalidated address are bounded (issue 114)     */
/* ------------------------------------------------------------------------- */

/* Deliver only the client's first flight to the server, then let the server idle. */
static int t_amp_run(lb_proto_t proto, uint32_t polls)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    size_t base;
    dtls_context_t *sd;
    uint32_t received;
    uint32_t i;

    LB_RUN(lb_trust_ec_root());
    base = lb_alloc_live_bytes();
    lb_cfg_default(&cfg, proto);
    LB_RUN(lb_pair_init(&pair, &cfg));
    t_reset_counters();
    LB_RUN(t_wrap_end(&pair, &pair.client, 1));
    LB_RUN(t_wrap_end(&pair, &pair.server, 0));
    s_server_discard = 1; /* the spoofed victim never answers */
    s_idle_ms = 61000U;
    s_idle_cap = polls;

    /* Client: send the ClientHello, then stop (its receive fails). */
    s_client_recv_fail = 1;
    {
        noxtls_return_t rc = (proto == LB_PROTO_DTLS12) ? noxtls_tls12_connect(pair.client.t12)
                                                         : noxtls_tls13_connect(pair.client.t13);
        (void)rc;
    }
    received = lb_link_pending(pair.link, 0);
    LB_CHECK(received > 0U);
    s_idle_reads = 0U;
    sd = t_dtls(&pair.server);
    if(proto == LB_PROTO_DTLS12) {
        /* Blocking accept: returns once the receive callback fails (idle cap). */
        (void)noxtls_tls12_accept(pair.server.t12);
    } else {
        for(i = 0U; i < polls; i++) {
            noxtls_return_t rc = noxtls_tls13_accept(pair.server.t13);
            if((rc != NOXTLS_RETURN_TIMEOUT) && (rc != NOXTLS_RETURN_WANT_READ)) {
                break;
            }
        }
    }
    lb_log("received=%u server sent %llu bytes in %u datagrams, validated=%u", received,
           (unsigned long long)s_server_tx_bytes, s_server_tx_dgrams, (uint32_t)sd->validated);
    LB_CHECK_EQ(sd->validated, 0U);
    LB_CHECK(s_server_tx_dgrams > 0U);
    LB_CHECK(s_server_tx_bytes <= ((uint64_t)received * (uint64_t)sd->anti_amp_factor));
    if(proto == LB_PROTO_DTLS12) {
        /* HelloVerifyRequest is not retransmitted on a timer (RFC 6347 4.2.1). */
        LB_CHECK_EQ(s_server_tx_dgrams, 1U);
    }
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "dtls amplification");
}

static int t_dtls12_hvr_amplification(void)
{
#if NOXTLS_FEATURE_DTLS && NOXTLS_FEATURE_TLS12 && NOXTLS_FEATURE_TLS_SERVER
    return t_amp_run(LB_PROTO_DTLS12, 200U);
#else
    return LB_SKIP;
#endif
}

static int t_dtls13_hrr_amplification(void)
{
#if NOXTLS_FEATURE_DTLS && NOXTLS_FEATURE_TLS13 && NOXTLS_FEATURE_TLS_SERVER
    return t_amp_run(LB_PROTO_DTLS13, 200U);
#else
    return LB_SKIP;
#endif
}

/* ------------------------------------------------------------------------- */
/* DTLS cookie bound to the peer identity (issue 193)                          */
/* ------------------------------------------------------------------------- */

static int t_dtls_cookie_peer_identity(void)
{
    static const uint8_t addr_a[18] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x16, 0x33 };
    static const uint8_t addr_b[18] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0x16, 0x33 };
    static uint8_t too_long[DTLS_PEER_IDENTITY_MAX_LEN + 1U];
    uint8_t client_hello[64];
    uint8_t cookie_a[TLS_COOKIE_MAX_LEN];
    uint8_t cookie_b[TLS_COOKIE_MAX_LEN];
    uint32_t len_a = sizeof(cookie_a);
    uint32_t len_b = sizeof(cookie_b);
    dtls_context_t *ctx;
    size_t base;

#if !NOXTLS_FEATURE_DTLS
    return LB_SKIP;
#endif
    base = lb_alloc_live_bytes();
    ctx = (dtls_context_t *)noxtls_malloc(sizeof(*ctx));
    LB_CHECK(ctx != NULL);
    LB_CHECK_OK(noxtls_dtls_context_init(ctx, TLS_ROLE_SERVER, DTLS_VERSION_1_2));
    lb_fill_pattern(client_hello, sizeof(client_hello), 7U);

    LB_CHECK_EQ(noxtls_dtls_set_peer_identity(ctx, too_long, sizeof(too_long)), NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_EQ(noxtls_dtls_set_peer_identity(ctx, NULL, 4U), NOXTLS_RETURN_NULL);

    /* Cookie issued to A validates only while the datagram comes from A. */
    LB_CHECK_OK(noxtls_dtls_set_peer_identity(ctx, addr_a, sizeof(addr_a)));
    LB_CHECK_OK(noxtls_dtls_generate_cookie(ctx, client_hello, sizeof(client_hello), cookie_a, &len_a));
    LB_CHECK_OK(noxtls_dtls_verify_cookie(ctx, cookie_a, len_a));
    LB_CHECK_OK(noxtls_dtls_set_peer_identity(ctx, addr_b, sizeof(addr_b)));
    LB_CHECK(noxtls_dtls_verify_cookie(ctx, cookie_a, len_a) != NOXTLS_RETURN_SUCCESS);
    LB_CHECK_OK(noxtls_dtls_set_peer_identity(ctx, NULL, 0U));
    LB_CHECK(noxtls_dtls_verify_cookie(ctx, cookie_a, len_a) != NOXTLS_RETURN_SUCCESS);

    /* The identity is mixed into the cookie: same ClientHello, different peer, different cookie. */
    LB_CHECK_OK(noxtls_dtls_set_peer_identity(ctx, addr_b, sizeof(addr_b)));
    LB_CHECK_OK(noxtls_dtls_generate_cookie(ctx, client_hello, sizeof(client_hello), cookie_b, &len_b));
    LB_CHECK_EQ(len_a, len_b);
    LB_CHECK(memcmp(cookie_a, cookie_b, len_a) != 0);
    LB_CHECK_OK(noxtls_dtls_verify_cookie(ctx, cookie_b, len_b));

    /* Without an identity the cookie works as before (one peer per context). */
    LB_CHECK_OK(noxtls_dtls_set_peer_identity(ctx, NULL, 0U));
    len_a = sizeof(cookie_a);
    LB_CHECK_OK(noxtls_dtls_generate_cookie(ctx, client_hello, sizeof(client_hello), cookie_a, &len_a));
    LB_CHECK_OK(noxtls_dtls_verify_cookie(ctx, cookie_a, len_a));

    LB_CHECK_OK(noxtls_dtls_context_free(ctx));
    noxtls_free(ctx);
    return lb_expect_no_leak(base, "cookie identity");
}

/* DTLS 1.2 handshake with a peer identity set on the server: the cookie exchange still works. */
static int t_dtls12_handshake_with_peer_identity(void)
{
    static const uint8_t addr[6] = { 192, 0, 2, 1, 0x16, 0x33 };
    lb_pair_t pair;
    lb_cfg_t cfg;
    size_t base;
    uint8_t buf[16];
    uint32_t len = sizeof(buf);

#if !(NOXTLS_FEATURE_DTLS && NOXTLS_FEATURE_TLS12)
    return LB_SKIP;
#endif
    LB_RUN(lb_trust_ec_root());
    base = lb_alloc_live_bytes();
    lb_cfg_default(&cfg, LB_PROTO_DTLS12);
    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_CHECK_OK(noxtls_dtls_set_peer_identity(&pair.server.t12->base, addr, sizeof(addr)));
    if(lb_pair_handshake(&pair) != 0) {
        lb_log("handshake failed: client rc=%d server rc=%d", (int)pair.client.last_rc, (int)pair.server.last_rc);
        lb_pair_free(&pair);
        return 1;
    }
    LB_CHECK_EQ(pair.server.t12->base.validated, 1U);
    LB_CHECK_OK(noxtls_tls12_send(pair.client.t12, (const uint8_t *)"ping", 4U));
    LB_CHECK_OK(lb_recv_some(&pair, &pair.server, buf, &len));
    LB_CHECK_EQ(len, 4U);
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "dtls12 identity");
}

/* ------------------------------------------------------------------------- */
/* TLS: an empty heartbeat record cannot delete a record (issue 71)            */
/* ------------------------------------------------------------------------- */

/* Byte offset of record @p index in the queued stream, or -1. */
static int32_t t_record_offset(const lb_pipe_t *pipe, uint32_t index, uint32_t *rec_len)
{
    uint32_t off = pipe->rd;
    uint32_t i = 0U;
    while((off + 5U) <= pipe->wr) {
        uint32_t len = ((uint32_t)pipe->data[off + 3U] << 8U) | (uint32_t)pipe->data[off + 4U];
        if(i == index) {
            *rec_len = 5U + len;
            return (int32_t)off;
        }
        off += 5U + len;
        i++;
    }
    return -1;
}

static int t_tls12_empty_heartbeat(void)
{
    static const uint8_t msgs[3][4] = { { 'A', 'A', 'A', 'A' }, { 'B', 'B', 'B', 'B' }, { 'C', 'C', 'C', 'C' } };
    static const uint8_t empty_hb[5] = { TLS_RECORD_HEARTBEAT, 0x03U, 0x03U, 0x00U, 0x00U };
    lb_pair_t pair;
    lb_cfg_t cfg;
    size_t base;
    lb_pipe_t *pipe;
    uint32_t rec_len = 0U;
    int32_t off;
    uint32_t i;
    uint8_t buf[64];
    uint32_t len;
    noxtls_return_t rc;

#if !NOXTLS_FEATURE_TLS12
    return LB_SKIP;
#endif
    LB_RUN(lb_trust_ec_root());
    base = lb_alloc_live_bytes();
    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    LB_RUN(lb_pair_init(&pair, &cfg));
    noxtls_tls12_set_heartbeat(pair.client.t12, 1);
    noxtls_tls12_set_heartbeat(pair.server.t12, 1);
    if(lb_pair_handshake(&pair) != 0) {
        lb_pair_free(&pair);
        return 1;
    }
    if(pair.server.t12->heartbeat_negotiated == 0U) {
        lb_pair_free(&pair);
        (void)lb_expect_no_leak(base, "heartbeat");
        return LB_SKIP; /* heartbeat extension not built */
    }
    for(i = 0U; i < 3U; i++) {
        LB_CHECK_OK(lb_end_send(&pair.client, msgs[i], 4U));
        (void)lb_end_flush(&pair.client);
    }
    /* On-path edit: replace the second protected record with an empty heartbeat record. */
    pipe = &pair.link->to_server;
    off = t_record_offset(pipe, 1U, &rec_len);
    LB_CHECK(off >= 0);
    memcpy(&pipe->data[off], empty_hb, sizeof(empty_hb));
    memmove(&pipe->data[(uint32_t)off + 5U], &pipe->data[(uint32_t)off + rec_len], pipe->wr - ((uint32_t)off + rec_len));
    pipe->wr -= rec_len - 5U;

    len = sizeof(buf);
    LB_CHECK_OK(lb_recv_some(&pair, &pair.server, buf, &len));
    LB_CHECK_EQ(len, 4U);
    LB_CHECK(memcmp(buf, msgs[0], 4U) == 0);
    /* The empty record is rejected and is fatal at once: the deletion is never hidden. */
    len = sizeof(buf);
    rc = lb_end_recv(&pair.server, buf, &len);
    LB_CHECK(rc != NOXTLS_RETURN_SUCCESS);
    LB_CHECK_EQ(pair.server.t12->base.base.state, TLS_STATE_CLOSED);
    /* CCCC is never delivered afterwards. */
    for(i = 0U; i < 4U; i++) {
        len = sizeof(buf);
        rc = lb_end_recv(&pair.server, buf, &len);
        LB_CHECK(!((rc == NOXTLS_RETURN_SUCCESS) && (len == 4U) && (memcmp(buf, msgs[2], 4U) == 0)));
    }
    LB_CHECK(rc != NOXTLS_RETURN_SUCCESS);
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "heartbeat");
}

/* ------------------------------------------------------------------------- */
/* TLS 1.0 CBC: 1/n-1 record splitting in both roles (issue 135)               */
/* ------------------------------------------------------------------------- */

#if NOXTLS_FEATURE_TLS10 && NOXTLS_FEATURE_MD5 && NOXTLS_FEATURE_SHA1
static uint32_t t_count_records(const lb_pipe_t *pipe, uint32_t *first_len)
{
    uint32_t n = 0U;
    uint32_t off = pipe->rd;
    *first_len = 0U;
    while((off + 5U) <= pipe->wr) {
        uint32_t len = ((uint32_t)pipe->data[off + 3U] << 8U) | (uint32_t)pipe->data[off + 4U];
        if(n == 0U) {
            *first_len = len;
        }
        off += 5U + len;
        n++;
    }
    return n;
}
#endif

static int t_tls10_cbc_split(void)
{
#if NOXTLS_FEATURE_TLS10 && NOXTLS_FEATURE_MD5 && NOXTLS_FEATURE_SHA1
    static uint8_t payload[100];
    lb_pair_t pair;
    lb_cfg_t cfg;
    uint16_t list[1];
    size_t base;
    int dir;

    LB_RUN(lb_trust_all_roots());
    base = lb_alloc_live_bytes();
    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    cfg.tls12_version = TLS_VERSION_1_0;
    cfg.server_auth = LB_AUTH_RSA;
    cfg.sni = "rsa.test";
    list[0] = TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA;
    cfg.server_suites = list;
    cfg.server_suite_count = 1U;
    LB_RUN(lb_pair_init(&pair, &cfg));
    if(lb_pair_handshake(&pair) != 0) {
        lb_log("handshake failed: client rc=%d server rc=%d", (int)pair.client.last_rc, (int)pair.server.last_rc);
        lb_pair_free(&pair);
        return 1;
    }
    LB_CHECK_EQ(lb_end_base(&pair.client)->version, TLS_VERSION_1_0);
    LB_CHECK_EQ(lb_end_base(&pair.server)->version, TLS_VERSION_1_0);
    for(dir = 0; dir < 2; dir++) {
        lb_end_t *tx = (dir == 0) ? &pair.client : &pair.server;
        lb_pipe_t *pipe = (dir == 0) ? &pair.link->to_server : &pair.link->to_client;
        uint32_t first_len = 0U;
        uint32_t w;
        for(w = 0U; w < 2U; w++) {
            lb_fill_pattern(payload, sizeof(payload), (uint32_t)(dir * 10) + w);
            LB_CHECK_OK(lb_end_send(tx, payload, sizeof(payload)));
            (void)lb_end_flush(tx);
            /* 1 byte + 20-byte MAC + padding = 32, then the remaining 99 bytes. */
            LB_CHECK_EQ(t_count_records(pipe, &first_len), 2U);
            LB_CHECK_EQ(first_len, 32U);
            {
                static uint8_t rx[sizeof(payload)];
                uint32_t got = 0U;
                lb_end_t *rxe = (dir == 0) ? &pair.server : &pair.client;
                while(got < sizeof(payload)) {
                    uint32_t len = (uint32_t)sizeof(payload) - got;
                    LB_CHECK_OK(lb_recv_some(&pair, rxe, &rx[got], &len));
                    LB_CHECK(len > 0U);
                    got += len;
                }
                LB_CHECK(memcmp(rx, payload, sizeof(payload)) == 0);
            }
        }
    }
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "tls10 split");
#else
    return LB_SKIP;
#endif
}

/* ------------------------------------------------------------------------- */
/* MAC-then-encrypt CBC records with every padding length (issue 172)          */
/* ------------------------------------------------------------------------- */

#if NOXTLS_FEATURE_TLS12 && NOXTLS_FEATURE_AES_CBC
/* Build plaintext || HMAC || padding (pad_len + 1 bytes) and AES-CBC encrypt it behind an IV. */
static int t_build_mte_record(const tls12_context_t *ctx, noxtls_hash_algos_t hash, uint32_t mac_len,
                              noxtls_aes_type_t aes_type, uint64_t seq, const uint8_t *pt, uint32_t pt_len,
                              uint32_t pad_len, uint8_t *out, uint32_t *out_len)
{
    static uint8_t body[TLS_MAX_RECORD_SIZE + 512U];
    uint8_t hdr[13];
    uint8_t iv[16];
    uint32_t mlen = 64U;
    uint32_t body_len = pt_len + mac_len + pad_len + 1U;
    uint32_t i;
    hmac_context_t h;

    if((body_len % 16U) != 0U) {
        return 1;
    }
    for(i = 0U; i < 8U; i++) {
        hdr[i] = (uint8_t)(seq >> (56U - (8U * i)));
    }
    hdr[8] = TLS_RECORD_APPLICATION_DATA;
    hdr[9] = 0x03U;
    hdr[10] = 0x03U;
    hdr[11] = (uint8_t)(pt_len >> 8U);
    hdr[12] = (uint8_t)pt_len;
    memcpy(body, pt, pt_len);
    LB_CHECK_OK(noxtls_hmac_init(&h, hash, ctx->client_write_mac_key, mac_len));
    LB_CHECK_OK(noxtls_hmac_update(&h, hdr, sizeof(hdr)));
    if(pt_len > 0U) {
        LB_CHECK_OK(noxtls_hmac_update(&h, pt, pt_len));
    }
    LB_CHECK_OK(noxtls_hmac_final(&h, &body[pt_len], &mlen));
    (void)noxtls_hmac_free(&h);
    LB_CHECK_EQ(mlen, mac_len);
    memset(&body[pt_len + mac_len], (int)pad_len, pad_len + 1U);
    lb_fill_pattern(iv, sizeof(iv), (uint32_t)seq + 99U);
    memcpy(out, iv, sizeof(iv));
    LB_CHECK_OK(noxtls_aes_encrypt_cbc(ctx->client_write_key, body, body_len, iv, &out[16], aes_type));
    *out_len = 16U + body_len;
    return 0;
}

static int t_mte_suite(uint16_t suite, noxtls_hash_algos_t hash, uint32_t mac_len, uint32_t key_len,
                       noxtls_aes_type_t aes_type)
{
    static uint8_t rec[TLS_MAX_RECORD_SIZE + 1024U];
    static uint8_t pt[300];
    tls12_context_t *ctx;
    uint32_t pt_len;
    uint32_t pad;
    uint32_t checked = 0U;

    ctx = (tls12_context_t *)noxtls_malloc(sizeof(*ctx));
    LB_CHECK(ctx != NULL);
    LB_CHECK_OK(noxtls_tls12_context_init(ctx, TLS_ROLE_SERVER));
    ctx->cipher_suite = suite;
    ctx->use_encrypt_then_mac = 0U;
    lb_fill_pattern(ctx->client_write_key, key_len, 1U);
    lb_fill_pattern(ctx->client_write_iv, 16U, 2U);
    lb_fill_pattern(ctx->client_write_mac_key, mac_len, 3U);
    lb_fill_pattern(pt, sizeof(pt), 4U);

    for(pt_len = 0U; pt_len < 40U; pt_len += 3U) {
        for(pad = 0U; pad < 256U; pad++) {
            uint32_t rec_len = 0U;
            uint32_t off = 0U;
            uint32_t out_len = 0U;
            noxtls_return_t rc;
            if(((pt_len + mac_len + pad + 1U) % 16U) != 0U) {
                continue;
            }
            /* Valid record: opens and yields the plaintext. */
            LB_RUN(t_build_mte_record(ctx, hash, mac_len, aes_type, ctx->client_seq_num, pt, pt_len, pad, rec, &rec_len));
            rc = noxtls_tls12_open_record(ctx, TLS_RECORD_APPLICATION_DATA, rec, rec_len, sizeof(rec), &off, &out_len);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                lb_log("suite 0x%04X pt_len %u pad %u: rc=%d", (uint32_t)suite, pt_len, pad, (int)rc);
                return 1;
            }
            LB_CHECK_EQ(out_len, pt_len);
            LB_CHECK((pt_len == 0U) || (memcmp(&rec[off], pt, pt_len) == 0));

            /* Wrong MAC byte: rejected, sequence number not consumed. */
            LB_RUN(t_build_mte_record(ctx, hash, mac_len, aes_type, ctx->client_seq_num, pt, pt_len, pad, rec, &rec_len));
            {
                /* Flip a bit of the last MAC byte: plaintext block = C[i-1] xor D(C[i]). */
                uint32_t mac_last = 16U + pt_len + mac_len - 1U;
                uint64_t seq_before = ctx->client_seq_num;
                rec[mac_last - 16U] ^= 0x01U;
                rc = noxtls_tls12_open_record(ctx, TLS_RECORD_APPLICATION_DATA, rec, rec_len, sizeof(rec), &off, &out_len);
                LB_CHECK_EQ(rc, NOXTLS_RETURN_BAD_DATA);
                LB_CHECK_EQ(ctx->client_seq_num, seq_before);
            }
            /* Inconsistent padding byte (first padding byte changed): rejected. */
            if(pad > 0U) {
                uint32_t first_pad = 16U + pt_len + mac_len;
                LB_RUN(t_build_mte_record(ctx, hash, mac_len, aes_type, ctx->client_seq_num, pt, pt_len, pad, rec, &rec_len));
                rec[first_pad - 16U] ^= 0x80U;
                rc = noxtls_tls12_open_record(ctx, TLS_RECORD_APPLICATION_DATA, rec, rec_len, sizeof(rec), &off, &out_len);
                LB_CHECK_EQ(rc, NOXTLS_RETURN_BAD_DATA);
            }
            checked++;
        }
    }
    LB_CHECK(checked > 100U);
    /* Shorter than MAC + padding: rejected. */
    {
        uint32_t off = 0U;
        uint32_t out_len = 0U;
        memset(rec, 0, 32U);
        LB_CHECK_EQ(noxtls_tls12_open_record(ctx, TLS_RECORD_APPLICATION_DATA, rec, 32U, sizeof(rec), &off, &out_len),
                    NOXTLS_RETURN_BAD_DATA);
    }
    (void)noxtls_tls12_context_free(ctx);
    noxtls_free(ctx);
    return 0;
}
#endif

static int t_tls12_cbc_mte_padding(void)
{
#if NOXTLS_FEATURE_TLS12 && NOXTLS_FEATURE_AES_CBC
    size_t base = lb_alloc_live_bytes();
#if NOXTLS_FEATURE_SHA1
    LB_RUN(t_mte_suite(TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA, NOXTLS_HASH_SHA1, 20U, 16U, NOXTLS_AES_128_BIT));
#endif
    LB_RUN(t_mte_suite(TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, NOXTLS_HASH_SHA_256, 32U, 16U,
                       NOXTLS_AES_128_BIT));
#if NOXTLS_FEATURE_SHA384
    LB_RUN(t_mte_suite(TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, NOXTLS_HASH_SHA_384, 48U, 32U,
                       NOXTLS_AES_256_BIT));
#endif
    return lb_expect_no_leak(base, "cbc mte");
#else
    return LB_SKIP;
#endif
}

static const lb_test_case_t k_cases[] = {
    { "dtls12_forged_seq_keeps_replay_window", t_dtls12_forged_seq_window },
    { "dtls12_send_failure_consumes_seq", t_dtls12_send_failure_burns_seq },
    { "dtls13_send_failure_consumes_seq", t_dtls13_send_failure_burns_seq },
    { "dtls12_lost_datagram_retransmit_bounded", t_dtls12_lost_datagram_bounded },
    { "dtls12_hvr_retransmit_amplification", t_dtls12_hvr_amplification },
    { "dtls13_hrr_retransmit_amplification", t_dtls13_hrr_amplification },
    { "dtls_cookie_bound_to_peer_identity", t_dtls_cookie_peer_identity },
    { "dtls12_handshake_with_peer_identity", t_dtls12_handshake_with_peer_identity },
    { "tls12_empty_heartbeat_record_rejected", t_tls12_empty_heartbeat },
    { "tls10_cbc_record_split", t_tls10_cbc_split },
    { "tls12_cbc_mte_all_padding_lengths", t_tls12_cbc_mte_padding },
};

int main(int argc, char **argv)
{
    return lb_main(argc, argv, "record_layer_audit", k_cases, sizeof(k_cases) / sizeof(k_cases[0]));
}
