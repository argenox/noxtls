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
* File:    dtls13_single_association_test.c
* Summary: DTLS 1.3 own connection ID, newest record, stateless HelloRetryRequest and
*          handshake-state release
*****************************************************************************/
/** @file dtls13_single_association_test.c
 * @brief Tests of the single-association API of noxtls_tls13.h.
 *
 * A DTLS 1.3 external-PSK client and server run over the in-memory datagram link of
 * ut/tls_loopback. The tests take datagrams off the link to play the part of an
 * application that admits clients itself: it answers the first ClientHello with
 * noxtls_dtls13_stateless_hrr(), checks the second ClientHello's binder with
 * noxtls_dtls13_ch2_binder_check() and hands it to a fresh server context with
 * noxtls_dtls13_accept_after_stateless_hrr().
 *
 * References: RFC 9146 Sections 3 and 6, RFC 9147 Sections 4, 5.1, 5.2, 5.9 and 9,
 * RFC 8446 Sections 4.1.4, 4.2.2, 4.2.8, 4.2.11.2, 4.4.1 and 7.5.
 */
#include "lb_fixture.h"
#include "tls/noxtls_connection_memory.h"
#include "tls/noxtls_tls13_psk.h"
#include "binder_vectors.h"
#include "tls/noxtls_tls_kdf.h"
#include "kdf/noxtls_hkdf.h"
#include "mac/noxtls_hmac.h"

#include <string.h>

/* ---- C library allocator hooks (static memory, GNU ld) ------------------------ */

#if defined(SA_WRAP_HEAP)
void *__real_malloc(size_t size);
void *__real_calloc(size_t nmemb, size_t size);
void *__real_realloc(void *ptr, size_t size);
void __real_free(void *ptr);

static size_t s_heap_calls;

void *__wrap_malloc(size_t size)
{
    s_heap_calls++;
    return __real_malloc(size);
}

void *__wrap_calloc(size_t nmemb, size_t size)
{
    s_heap_calls++;
    return __real_calloc(nmemb, size);
}

void *__wrap_realloc(void *ptr, size_t size)
{
    s_heap_calls++;
    return __real_realloc(ptr, size);
}

void __wrap_free(void *ptr)
{
    if(ptr != NULL) {
        s_heap_calls++;
    }
    __real_free(ptr);
}
#define HEAP_CALLS() s_heap_calls
#else
#define HEAP_CALLS() ((size_t)0U)
#endif

/* ---- Fixture ----------------------------------------------------------------- */

#if NOXTLS_CONFIG_STATIC_MEMORY
/* The node's profile: one DTLS 1.3 PSK block per endpoint. */
static uint64_t s_client_mem[NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_CLIENT, DTLS13_PSK) / 8U];
static uint64_t s_server_mem[NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_SERVER, DTLS13_PSK) / 8U];
#endif

static const uint8_t k_identity[] = "nmx1-management";
static const uint8_t k_psk[32] = {
    0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U, 0x18U, 0x19U, 0x1AU, 0x1BU, 0x1CU, 0x1DU, 0x1EU, 0x1FU,
    0x20U, 0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U, 0x28U, 0x29U, 0x2AU, 0x2BU, 0x2CU, 0x2DU, 0x2EU, 0x2FU
};
static const uint8_t k_cid[2] = { 0x5AU, 0xC3U };
static const uint16_t k_suite = TLS_CIPHER_SUITE_AES_128_GCM_SHA256;
static const uint16_t k_groups_x25519[1] = { TLS_NAMED_GROUP_X25519 };
static const uint16_t k_groups_x25519_p256[2] = { TLS_NAMED_GROUP_X25519, TLS_NAMED_GROUP_SECP256R1 };

#define SA_DGRAM_MAX 2048U

static uint8_t s_ch1[SA_DGRAM_MAX];
static uint32_t s_ch1_len;
static uint8_t s_ch2[SA_DGRAM_MAX];
static uint32_t s_ch2_len;
static uint8_t s_ch1_hash[32];
static uint8_t s_cookie[56];
static uint8_t s_hrr[NOXTLS_DTLS13_STATELESS_HRR_MAX(NOXTLS_DTLS13_STATELESS_COOKIE_MAX)];
static uint32_t s_hrr_len;
static uint8_t s_scratch[NOXTLS_DTLS13_CH2_BINDER_SCRATCH(SA_DGRAM_MAX, NOXTLS_DTLS13_STATELESS_COOKIE_MAX)];
static uint8_t s_buf[4096];

/** Observer record (noxtls_dtls13_set_hrr_observer()). */
typedef struct
{
    lb_link_t *link;
    uint32_t calls;
    uint8_t cookie[NOXTLS_DTLS13_STATELESS_COOKIE_MAX];
    uint16_t len;
    uint32_t to_server_at_call;  /* datagrams queued toward the server when called */
} sa_observer_t;

static sa_observer_t s_obs;

static void sa_observe(void *arg, const uint8_t *cookie, uint16_t len)
{
    sa_observer_t *obs = (sa_observer_t *)arg;
    obs->calls++;
    obs->len = len;
    if((cookie != NULL) && (len <= sizeof(obs->cookie))) {
        memcpy(obs->cookie, cookie, len);
    }
    obs->to_server_at_call = obs->link->to_server.dgram_count;
}

/** A DTLS 1.3 external-PSK pair (PSK-DHE, X25519, AES-128-GCM), not started. */
static int sa_pair_init(lb_pair_t *pair, const uint16_t *groups, uint32_t group_count)
{
    lb_cfg_t cfg;

    lb_cfg_default(&cfg, LB_PROTO_DTLS13);
    cfg.server_auth = LB_AUTH_NONE;
    cfg.send_chain = 0;
    cfg.sni = NULL;
    cfg.server_suites = &k_suite;
    cfg.server_suite_count = 1U;
    cfg.client_groups = groups;
    cfg.client_group_count = group_count;
#if NOXTLS_CONFIG_STATIC_MEMORY
    lb_static_memory_set(s_client_mem, sizeof(s_client_mem), NOXTLS_CONN_PROFILE_DTLS13_PSK,
                         s_server_mem, sizeof(s_server_mem), NOXTLS_CONN_PROFILE_DTLS13_PSK);
#endif
    LB_RUN(lb_pair_init(pair, &cfg));
    LB_CHECK_OK(tls13_set_external_psk(pair->client.t13, k_identity, (uint16_t)(sizeof(k_identity) - 1U),
                                       k_psk, (uint16_t)sizeof(k_psk), TLS13_PSK_KE_MODE_PSK_DHE_KE));
    LB_CHECK_OK(tls13_set_external_psk(pair->server.t13, k_identity, (uint16_t)(sizeof(k_identity) - 1U),
                                       k_psk, (uint16_t)sizeof(k_psk), TLS13_PSK_KE_MODE_PSK_DHE_KE));
#if NOXTLS_TLS_MAX_RECORD_SIZE < DTLS_MAX_FRAGMENT_SIZE
    LB_CHECK_OK(noxtls_dtls_set_mtu(&pair->client.t13->base, (uint16_t)NOXTLS_TLS_MAX_RECORD_SIZE));
    LB_CHECK_OK(noxtls_dtls_set_mtu(&pair->server.t13->base, (uint16_t)NOXTLS_TLS_MAX_RECORD_SIZE));
#endif
    return 0;
}

/** Take the next datagram queued toward the server (to_client 0) or the client (1). */
static uint32_t sa_pop(lb_pair_t *pair, int to_client, uint8_t *buf, uint32_t cap)
{
    lb_port_t *reader = (to_client != 0) ? &pair->link->client_port : &pair->link->server_port;
    int32_t n = lb_io_recv(reader, buf, cap);
    return (n > 0) ? (uint32_t)n : 0U;
}

/** Queue a datagram toward the server (to_client 0) or the client (1). */
static int sa_push(lb_pair_t *pair, int to_client, const uint8_t *buf, uint32_t len)
{
    lb_port_t *writer = (to_client != 0) ? &pair->link->server_port : &pair->link->client_port;
    LB_CHECK_EQ(lb_io_send(writer, buf, len), (long)len);
    return 0;
}

static uint32_t sa_queued(const lb_pair_t *pair, int to_client)
{
    return (to_client != 0) ? pair->link->to_client.dgram_count : pair->link->to_server.dgram_count;
}

/** Exchange data both ways until both sides are idle (final ACKs processed). */
static int sa_exchange(lb_pair_t *pair, uint32_t seed)
{
    lb_fill_pattern(s_buf, 300U, seed);
    LB_RUN(lb_transfer(pair, 1, s_buf, 300U, 300U, 1000U));
    LB_RUN(lb_transfer(pair, 0, s_buf, 300U, 300U, 1000U));
    return 0;
}

/** Client sends its first ClientHello; it is taken off the link into s_ch1. */
static int sa_capture_ch1(lb_pair_t *pair)
{
    pair->client.last_rc = lb_end_step(&pair->client);
    LB_CHECK((pair->client.last_rc == NOXTLS_RETURN_TIMEOUT) || (pair->client.last_rc == NOXTLS_RETURN_WANT_READ));
    LB_CHECK_EQ(sa_queued(pair, 0), 1);
    s_ch1_len = sa_pop(pair, 0, s_ch1, sizeof(s_ch1));
    LB_CHECK(s_ch1_len > 0U);
    LB_CHECK_OK(noxtls_dtls13_client_hello_hash(s_ch1, s_ch1_len, s_ch1_hash));
    /* A cookie laid out as the single-association design does: version, flags, zero,
     * expiry, SHA-256(CH1), tag. Its content is the application's business. */
    memset(s_cookie, 0, sizeof(s_cookie));
    s_cookie[0] = 1U;
    s_cookie[4] = 0x10U;
    memcpy(&s_cookie[8], s_ch1_hash, 32U);
    lb_fill_pattern(&s_cookie[40], 16U, 77U);
    return 0;
}

/** Stateless HelloRetryRequest to the client; the second ClientHello lands in s_ch2. */
static int sa_hrr_and_capture_ch2(lb_pair_t *pair, uint16_t group)
{
    LB_CHECK_OK(noxtls_dtls13_stateless_hrr(s_ch1, s_ch1_len, s_cookie, (uint16_t)sizeof(s_cookie), k_suite, group,
                                            s_hrr, sizeof(s_hrr), &s_hrr_len));
    LB_RUN(sa_push(pair, 1, s_hrr, s_hrr_len));
    pair->client.last_rc = lb_end_step(&pair->client);
    LB_CHECK((pair->client.last_rc == NOXTLS_RETURN_TIMEOUT) || (pair->client.last_rc == NOXTLS_RETURN_WANT_READ));
    LB_CHECK_EQ(sa_queued(pair, 0), 1);
    s_ch2_len = sa_pop(pair, 0, s_ch2, sizeof(s_ch2));
    LB_CHECK(s_ch2_len > 0U);
    return 0;
}

/** Hand CH2 to the fresh server context and finish the handshake. */
static int sa_accept_ch2_and_finish(lb_pair_t *pair, uint16_t group)
{
    noxtls_return_t rc = noxtls_dtls13_accept_after_stateless_hrr(pair->server.t13, s_ch1_hash, k_suite, group,
                                                                  s_ch2, s_ch2_len);
    if((rc != NOXTLS_RETURN_TIMEOUT) && (rc != NOXTLS_RETURN_SUCCESS)) {
        lb_log("accept after stateless HRR: rc %d, step '%s'", (int)rc, (const char *)noxtls_tls13_last_accept_fail_step());
        return 1;
    }
    if(lb_pair_handshake(pair) != 0) {
        lb_log("handshake: client step '%s', server step '%s'", (const char *)noxtls_tls13_last_connect_fail_step(),
               (const char *)noxtls_tls13_last_accept_fail_step());
        return 1;
    }
    LB_CHECK_EQ(lb_field_state(&pair->client), TLS_STATE_CONNECTED);
    LB_CHECK_EQ(lb_field_state(&pair->server), TLS_STATE_CONNECTED);
    LB_CHECK_EQ(pair->client.t13->cipher_suite, k_suite);
    LB_CHECK_EQ(pair->server.t13->cipher_suite, k_suite);
    LB_CHECK_EQ(lb_field_tls13_psk_in_use(pair->server.t13), 1);
    return 0;
}

/** The whole stateless admission: CH1, stateless HRR, binder check, accept of CH2. */
static int sa_stateless_handshake(lb_pair_t *pair, uint16_t group)
{
    LB_RUN(sa_capture_ch1(pair));
    LB_RUN(sa_hrr_and_capture_ch2(pair, group));
    LB_CHECK_OK(noxtls_dtls13_ch2_binder_check(s_ch2, s_ch2_len, s_ch1_hash, k_suite, group,
                                               k_identity, (uint16_t)(sizeof(k_identity) - 1U),
                                               k_psk, (uint16_t)sizeof(k_psk), s_scratch, sizeof(s_scratch)));
    LB_RUN(sa_accept_ch2_and_finish(pair, group));
    return 0;
}

static uint16_t sa_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8U) | (uint16_t)p[1]);
}

/** The frozen ch1_hash rule (NoxMux S0 vectors, group ch1Hash): SHA-256 over msg_type,
 *  length and body, without message_seq and the fragment fields (RFC 9147 5.2). */
static int test_ch1_hash_vector(void)
{
    static const uint8_t hs_header[12] = {
        0x01U, 0x00U, 0x00U, 0x3CU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x3CU
    };
    static const uint8_t expect[32] = {
        0xCEU, 0xF9U, 0x1CU, 0x8CU, 0x71U, 0x8AU, 0x7BU, 0x67U, 0xC8U, 0xD9U, 0x0DU, 0x07U, 0x83U, 0x6DU, 0x0CU, 0x4FU,
        0xFAU, 0x4BU, 0xEFU, 0x92U, 0x5AU, 0x49U, 0xF0U, 0x86U, 0x94U, 0x6BU, 0x62U, 0x74U, 0xBBU, 0xA3U, 0x90U, 0xB3U
    };
    uint8_t dg[13U + 12U + 60U];
    uint8_t hash[32];
    uint32_t i;

    /* DTLSPlaintext: handshake, legacy version, epoch 0, record number 0, length 72. */
    memset(dg, 0, sizeof(dg));
    dg[0] = TLS_RECORD_HANDSHAKE;
    dg[1] = 0xFEU;
    dg[2] = 0xFDU;
    dg[12] = (uint8_t)(12U + 60U);
    memcpy(&dg[13], hs_header, sizeof(hs_header));
    for(i = 0U; i < 60U; i++) {
        dg[25U + i] = (uint8_t)i;
    }
    LB_CHECK_OK(noxtls_dtls13_client_hello_hash(dg, sizeof(dg), hash));
    LB_CHECK(memcmp(hash, expect, sizeof(expect)) == 0);
    /* message_seq and the record number are not hashed. */
    dg[13U + 5U] = 1U;
    dg[10] = 7U;
    LB_CHECK_OK(noxtls_dtls13_client_hello_hash(dg, sizeof(dg), hash));
    LB_CHECK(memcmp(hash, expect, sizeof(expect)) == 0);
    /* The framing is checked: a fragment is refused. */
    dg[13U + 11U] = 0x3BU;
    LB_CHECK_EQ(noxtls_dtls13_client_hello_hash(dg, sizeof(dg), hash), NOXTLS_RETURN_BAD_DATA);
    return 0;
}

/** Wrap a TLS-form handshake message (4-byte header) into an epoch-0 DTLS datagram. */
static uint32_t sa_wrap_datagram(const uint8_t *msg, uint32_t msg_len, uint8_t *out)
{
    const uint32_t body_len = msg_len - 4U;
    memset(out, 0, 25U);
    out[0] = TLS_RECORD_HANDSHAKE;
    out[1] = 0xFEU;
    out[2] = 0xFDU;
    out[11] = (uint8_t)(((body_len + 12U) >> 8U) & 0xFFU);
    out[12] = (uint8_t)((body_len + 12U) & 0xFFU);
    memcpy(&out[13], msg, 4U);                    /* msg_type, length */
    memcpy(&out[22], &msg[1], 3U);                /* fragment_length */
    memcpy(&out[25], &msg[4], body_len);
    return 25U + body_len;
}

/**
 * RFC 9147 5.9: DTLS 1.3 binders use the "dtls13" HKDF label prefix. Compared with
 * gen_binder_vectors.py (Python hmac/hashlib, its key schedule checked against RFC 8448).
 */
static int test_binder_vectors(void)
{
    uint8_t out[32];
    uint8_t dg[512];
    uint32_t dg_len;
    uint32_t hrr_len = 0U;
    uint8_t hash[32];
    const uint32_t off = (uint32_t)sizeof(k_vec_ch1) - 32U;

    /* First ClientHello: "dtls13" binder, and the "tls13 " one for TLS 1.3. */
    LB_CHECK_OK(tls13_psk_compute_external_binder(NOXTLS_HASH_SHA_256, 1U, k_vec_psk, (uint16_t)sizeof(k_vec_psk),
                                                  k_vec_ch1, sizeof(k_vec_ch1), off, 32U, out, NULL, 0U, NULL));
    LB_CHECK(memcmp(out, k_vec_ch1_binder_dtls13, sizeof(out)) == 0);
    /* Compare a copy: MSYS2 GCC 16.1 folds memcmp() of two static const arrays, one at an
     * offset, to a wrong constant (reported with the T2 work). */
    memcpy(out, &k_vec_ch1[off], sizeof(out));
    LB_CHECK(memcmp(out, k_vec_ch1_binder_dtls13, sizeof(out)) == 0);
    LB_CHECK_OK(tls13_psk_compute_external_binder(NOXTLS_HASH_SHA_256, 0U, k_vec_psk, (uint16_t)sizeof(k_vec_psk),
                                                  k_vec_ch1, sizeof(k_vec_ch1), off, 32U, out, NULL, 0U, NULL));
    LB_CHECK(memcmp(out, k_vec_ch1_binder_tls13, sizeof(out)) == 0);
    LB_CHECK(memcmp(out, k_vec_ch1_binder_dtls13, sizeof(out)) != 0);  /* the prefixes differ */

    /* The same first ClientHello as a datagram: its ch1_hash, and the stateless
     * HelloRetryRequest that answers it, byte for byte. */
    dg_len = sa_wrap_datagram(k_vec_ch1, sizeof(k_vec_ch1), dg);
    LB_CHECK_OK(noxtls_dtls13_client_hello_hash(dg, dg_len, hash));
    LB_CHECK(memcmp(hash, k_vec_ch1_hash, sizeof(hash)) == 0);
    LB_CHECK_OK(noxtls_dtls13_stateless_hrr(dg, dg_len, k_vec_cookie, (uint16_t)sizeof(k_vec_cookie),
                                            TLS_CIPHER_SUITE_AES_128_GCM_SHA256, 0U, s_hrr, sizeof(s_hrr), &hrr_len));
    LB_CHECK_EQ(hrr_len, 13U + 8U + sizeof(k_vec_hrr));
    LB_CHECK_EQ(s_hrr[13], k_vec_hrr[0]);
    LB_CHECK(memcmp(&s_hrr[14], &k_vec_hrr[1], 3U) == 0);
    LB_CHECK(memcmp(&s_hrr[25], &k_vec_hrr[4], sizeof(k_vec_hrr) - 4U) == 0);

    /* N4a over message_hash(CH1) || HelloRetryRequest || Truncate(CH2). */
    LB_CHECK_OK(noxtls_dtls13_ch2_binder_check(k_vec_ch2_dtls13, sizeof(k_vec_ch2_dtls13), k_vec_ch1_hash,
                                               TLS_CIPHER_SUITE_AES_128_GCM_SHA256, 0U,
                                               k_vec_identity, (uint16_t)sizeof(k_vec_identity),
                                               k_vec_psk, (uint16_t)sizeof(k_vec_psk), s_scratch, sizeof(s_scratch)));
    LB_CHECK_EQ(noxtls_dtls13_ch2_binder_check(k_vec_ch2_tls13, sizeof(k_vec_ch2_tls13), k_vec_ch1_hash,
                                               TLS_CIPHER_SUITE_AES_128_GCM_SHA256, 0U,
                                               k_vec_identity, (uint16_t)sizeof(k_vec_identity),
                                               k_vec_psk, (uint16_t)sizeof(k_vec_psk), s_scratch, sizeof(s_scratch)),
                NOXTLS_RETURN_AUTH_FAILED);
    return 0;
}

/**
 * The single-association S0 vectors, group binder (NoxADK docs/noxdfu/noxmux-v1-vectors.json,
 * binder_dtls13_k_mgmt and the must-fail binder_tls13_prefix): every step of the external
 * binder (RFC 8446 4.2.11.2) with the NoxTLS primitives of the binder path, "dtls13" labels
 * (RFC 9147 5.9); the "tls13 " prefix gives the must-fail value.
 */
static int test_s0_binder_vector(void)
{
    static const uint8_t psk[32] = {
        0x78U, 0x1CU, 0xF1U, 0xA1U, 0xAFU, 0xCDU, 0x0EU, 0xE9U, 0x3EU, 0x11U, 0xABU, 0x4FU, 0x16U, 0xA4U, 0x72U, 0xA0U,
        0x68U, 0xB4U, 0xC9U, 0xDEU, 0xCDU, 0x08U, 0x7EU, 0x0CU, 0xD1U, 0x22U, 0xBCU, 0x89U, 0x36U, 0x25U, 0xD3U, 0x2EU
    };
    static const uint8_t transcript_hash[32] = {
        0xE1U, 0xA3U, 0x2AU, 0x16U, 0x1DU, 0xDBU, 0xC9U, 0x79U, 0xB5U, 0x21U, 0x43U, 0xCDU, 0x66U, 0xACU, 0xAEU, 0x55U,
        0x1EU, 0xE8U, 0x61U, 0x58U, 0xAAU, 0xF6U, 0x57U, 0x32U, 0xE2U, 0x96U, 0x15U, 0x05U, 0xA8U, 0x60U, 0x2AU, 0x86U
    };
    static const uint8_t expect_early[32] = {
        0xB0U, 0x04U, 0xADU, 0xC2U, 0xF4U, 0xCCU, 0x5AU, 0xA1U, 0x98U, 0x67U, 0xB2U, 0x29U, 0xD2U, 0x9FU, 0x01U, 0x19U,
        0xC0U, 0x8CU, 0xEEU, 0x8AU, 0x98U, 0xAFU, 0x0AU, 0x12U, 0xEAU, 0xC0U, 0x46U, 0x61U, 0x34U, 0x02U, 0x55U, 0xB3U
    };
    static const uint8_t expect_binder_key[32] = {
        0x1EU, 0xDAU, 0x37U, 0xEFU, 0xD5U, 0x5AU, 0x2AU, 0xDBU, 0xC4U, 0xEAU, 0xA1U, 0x7AU, 0xDFU, 0x9DU, 0x83U, 0x3BU,
        0x79U, 0xDCU, 0xA6U, 0x66U, 0x4BU, 0xB4U, 0x8FU, 0x7AU, 0xC8U, 0x05U, 0x3BU, 0x24U, 0x99U, 0x97U, 0x56U, 0x02U
    };
    static const uint8_t expect_finished_key[32] = {
        0x0AU, 0x88U, 0x40U, 0xFCU, 0xB5U, 0xB3U, 0x5BU, 0x7BU, 0xABU, 0x1FU, 0x1EU, 0x62U, 0x1DU, 0x3AU, 0x24U, 0x6CU,
        0x00U, 0x6AU, 0xAAU, 0x02U, 0xF7U, 0x77U, 0x7BU, 0xF3U, 0x3DU, 0x62U, 0x89U, 0x55U, 0x2EU, 0x95U, 0x26U, 0x53U
    };
    static const uint8_t expect_binder[32] = {
        0x62U, 0x0CU, 0x64U, 0x43U, 0xB8U, 0xC0U, 0xA6U, 0x86U, 0xF2U, 0x23U, 0x48U, 0xADU, 0xDDU, 0xB3U, 0x38U, 0x4BU,
        0x40U, 0x1EU, 0x49U, 0x31U, 0xCDU, 0xAEU, 0x88U, 0x43U, 0x32U, 0x6DU, 0x98U, 0x6FU, 0x76U, 0x02U, 0x88U, 0x6FU
    };
    static const uint8_t must_fail_tls13[32] = {
        0xCCU, 0xF9U, 0x0AU, 0x2BU, 0x22U, 0x7BU, 0x6CU, 0x46U, 0xEBU, 0x1AU, 0x94U, 0xCAU, 0x4CU, 0x8AU, 0x05U, 0x86U,
        0xBFU, 0xFBU, 0x1BU, 0x9AU, 0xFBU, 0x31U, 0x5BU, 0xEDU, 0xFCU, 0x2EU, 0x90U, 0xC8U, 0xA3U, 0x11U, 0x59U, 0x90U
    };
    static const uint8_t ext_binder[] = "ext binder";
    static const uint8_t finished[] = "finished";
    uint8_t early[32];
    uint8_t binder_key[32];
    uint8_t finished_key[32];
    uint8_t out[32];
    uint32_t len = sizeof(early);

    LB_CHECK_OK(noxtls_hkdf_extract(NOXTLS_HASH_SHA_256, NULL, 0U, psk, sizeof(psk), early, &len));
    LB_CHECK(memcmp(early, expect_early, sizeof(early)) == 0);
    LB_CHECK_OK(dtls13_derive_secret(NOXTLS_HASH_SHA_256, early, 32U, ext_binder, (uint32_t)(sizeof(ext_binder) - 1U),
                                     NULL, 0U, binder_key, 32U));
    LB_CHECK(memcmp(binder_key, expect_binder_key, sizeof(binder_key)) == 0);
    LB_CHECK_OK(dtls13_hkdf_expand_label(NOXTLS_HASH_SHA_256, binder_key, 32U, finished, (uint32_t)(sizeof(finished) - 1U),
                                         NULL, 0U, finished_key, 32U));
    LB_CHECK(memcmp(finished_key, expect_finished_key, sizeof(finished_key)) == 0);
    len = sizeof(out);
    LB_CHECK_OK(noxtls_hmac_compute(NOXTLS_HASH_SHA_256, finished_key, 32U, transcript_hash, sizeof(transcript_hash),
                                    out, &len));
    LB_CHECK(memcmp(out, expect_binder, sizeof(out)) == 0);
    /* The "tls13 " prefix: the value a DTLS 1.3 server must refuse. */
    LB_CHECK_OK(tls13_derive_secret(NOXTLS_HASH_SHA_256, early, 32U, ext_binder, (uint32_t)(sizeof(ext_binder) - 1U),
                                    NULL, 0U, binder_key, 32U));
    LB_CHECK_OK(tls13_hkdf_expand_label(NOXTLS_HASH_SHA_256, binder_key, 32U, finished, (uint32_t)(sizeof(finished) - 1U),
                                        NULL, 0U, finished_key, 32U));
    len = sizeof(out);
    LB_CHECK_OK(noxtls_hmac_compute(NOXTLS_HASH_SHA_256, finished_key, 32U, transcript_hash, sizeof(transcript_hash),
                                    out, &len));
    LB_CHECK(memcmp(out, must_fail_tls13, sizeof(out)) == 0);
    LB_CHECK(memcmp(out, expect_binder, sizeof(out)) != 0);
    return 0;
}

/**
 * A server takes the first ClientHello of a NoxTLS 72d07e8 peer, whose binder uses the
 * "tls13 " labels (k_vec_ch1_legacy; C:/nxd/n15-legacy-proof/old_binder.c, built against
 * 72d07e8, computes the same binder for it), only with noxtls_dtls13_set_legacy_psk_labels().
 * With the cookie exchange off it answers that ClientHello with its ServerHello.
 */
static int sa_feed_old_peer_client_hello(uint8_t legacy, noxtls_return_t *rc_out)
{
    lb_pair_t pair;
    uint8_t dg[512];
    uint32_t dg_len;

    LB_RUN(sa_pair_init(&pair, k_groups_x25519, 1U));
    LB_CHECK_OK(noxtls_dtls13_set_cookie_exchange(pair.server.t13, 0U));
    LB_CHECK_OK(noxtls_dtls13_set_legacy_psk_labels(pair.server.t13, legacy));
    dg_len = sa_wrap_datagram(k_vec_ch1_legacy, sizeof(k_vec_ch1_legacy), dg);
    LB_RUN(sa_push(&pair, 0, dg, dg_len));
    *rc_out = lb_end_step(&pair.server);
    if((*rc_out == NOXTLS_RETURN_TIMEOUT) || (*rc_out == NOXTLS_RETURN_SUCCESS)) {
        LB_CHECK_EQ(lb_field_tls13_psk_in_use(pair.server.t13), 1);
        LB_CHECK(sa_queued(&pair, 1) >= 1U);                       /* ServerHello flight */
        LB_CHECK_EQ(lb_field_state(&pair.server), TLS_STATE_HANDSHAKING);
    }
    lb_pair_free(&pair);
    return 0;
}

static int test_legacy_labels_old_peer(void)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    LB_RUN(sa_feed_old_peer_client_hello(1U, &rc));
    LB_CHECK(rc == NOXTLS_RETURN_TIMEOUT);                         /* accepted, waits for Finished */
    LB_RUN(sa_feed_old_peer_client_hello(0U, &rc));
    LB_CHECK((rc != NOXTLS_RETURN_TIMEOUT) && (rc != NOXTLS_RETURN_SUCCESS));  /* RFC labels: binder refused */
    return 0;
}

/** Legacy labels on both ends work, a legacy client cannot reach an RFC server, and N4a
 *  stays RFC-only. */
static int test_legacy_labels_handshake(void)
{
    lb_pair_t pair;

    LB_RUN(sa_pair_init(&pair, k_groups_x25519, 1U));
    LB_CHECK_EQ(noxtls_dtls13_set_legacy_psk_labels(NULL, 1U), NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_EQ(noxtls_dtls13_set_legacy_psk_labels(pair.client.t13, 2U), NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_OK(noxtls_dtls13_set_legacy_psk_labels(pair.client.t13, 1U));
    LB_CHECK_OK(noxtls_dtls13_set_legacy_psk_labels(pair.server.t13, 1U));
    LB_RUN(lb_pair_handshake(&pair));
    LB_CHECK_EQ(lb_field_tls13_psk_in_use(pair.server.t13), 1);
    LB_RUN(sa_exchange(&pair, 21U));
    LB_CHECK_EQ(noxtls_dtls13_set_legacy_psk_labels(pair.server.t13, 0U), NOXTLS_RETURN_INVALID_PARAM);
    lb_pair_free(&pair);

    /* A legacy client and an RFC server do not agree on the binder. */
    LB_RUN(sa_pair_init(&pair, k_groups_x25519, 1U));
    LB_CHECK_OK(noxtls_dtls13_set_legacy_psk_labels(pair.client.t13, 1U));
    LB_CHECK(lb_pair_handshake(&pair) != 0);
    LB_CHECK(lb_field_state(&pair.server) != TLS_STATE_CONNECTED);
    lb_pair_free(&pair);

    /* The stateless binder check never takes the legacy labels. */
    LB_RUN(sa_pair_init(&pair, k_groups_x25519, 1U));
    LB_CHECK_OK(noxtls_dtls13_set_legacy_psk_labels(pair.client.t13, 1U));
    LB_RUN(sa_capture_ch1(&pair));
    LB_RUN(sa_hrr_and_capture_ch2(&pair, 0U));
    LB_CHECK_EQ(noxtls_dtls13_ch2_binder_check(s_ch2, s_ch2_len, s_ch1_hash, k_suite, 0U,
                                               k_identity, (uint16_t)(sizeof(k_identity) - 1U),
                                               k_psk, (uint16_t)sizeof(k_psk), s_scratch, sizeof(s_scratch)),
                NOXTLS_RETURN_AUTH_FAILED);
    lb_pair_free(&pair);
    return 0;
}

/* ---- N1: own connection ID ------------------------------------------------------ */

/** RFC 9146 3 / RFC 9147 9.1: the ServerHello carries the server's CID; the client puts
 *  it in every record; the client offered an empty CID, so the server's records have none. */
static int test_cid_own_server(void)
{
    lb_pair_t pair;
    uint32_t n;

    LB_RUN(sa_pair_init(&pair, k_groups_x25519, 1U));
    LB_CHECK_OK(noxtls_dtls13_set_own_connection_id(pair.server.t13, k_cid, (uint8_t)sizeof(k_cid)));
    LB_RUN(lb_pair_handshake(&pair));
    LB_CHECK_EQ(pair.server.t13->own_connection_id_len, sizeof(k_cid));
    LB_CHECK(memcmp(pair.server.t13->own_connection_id, k_cid, sizeof(k_cid)) == 0);
    LB_CHECK_EQ(pair.server.t13->peer_connection_id_len, 0);
    LB_CHECK_EQ(pair.client.t13->peer_connection_id_len, sizeof(k_cid));
    LB_CHECK(memcmp(pair.client.t13->peer_connection_id, k_cid, sizeof(k_cid)) == 0);
    LB_CHECK_EQ(pair.client.t13->own_connection_id_len, 0);
    LB_RUN(sa_exchange(&pair, 1U));

    /* Client to server: unified header with the C bit and the server's CID. */
    LB_CHECK_OK(lb_end_send(&pair.client, (const uint8_t *)"cid", 3U));
    LB_CHECK_EQ(sa_queued(&pair, 0), 1);
    n = sa_pop(&pair, 0, s_buf, sizeof(s_buf));
    LB_CHECK(n > 3U);
    LB_CHECK_EQ(s_buf[0] & 0xE0U, 0x20U);
    LB_CHECK((s_buf[0] & 0x10U) != 0U);
    LB_CHECK(memcmp(&s_buf[1], k_cid, sizeof(k_cid)) == 0);
    LB_RUN(sa_push(&pair, 0, s_buf, n));
    {
        uint8_t rx[16];
        uint32_t len = sizeof(rx);
        LB_CHECK_OK(lb_recv_some(&pair, &pair.server, rx, &len));
        LB_CHECK_EQ(len, 3);
    }
    /* Server to client: no CID (the client offered an empty one). */
    LB_CHECK_OK(lb_end_send(&pair.server, (const uint8_t *)"none", 4U));
    LB_CHECK(sa_queued(&pair, 1) >= 1U);
    n = sa_pop(&pair, 1, s_buf, sizeof(s_buf));
    LB_CHECK(n > 4U);
    LB_CHECK_EQ(s_buf[0] & 0x10U, 0U);
    LB_RUN(sa_push(&pair, 1, s_buf, n));
    {
        uint8_t rx[16];
        uint32_t len = sizeof(rx);
        LB_CHECK_OK(lb_recv_some(&pair, &pair.client, rx, &len));
        LB_CHECK_EQ(len, 4);
    }
    LB_RUN(sa_exchange(&pair, 2U));
    lb_pair_free(&pair);
    return 0;
}

/** RFC 9147 4.5.2: a record whose CID is not this endpoint's is discarded; the association stays. */
static int test_cid_mismatch_dropped(void)
{
    lb_pair_t pair;
    uint8_t good[256];
    uint32_t n;
    uint8_t rx[16];
    uint32_t len;
    noxtls_return_t rc;

    LB_RUN(sa_pair_init(&pair, k_groups_x25519, 1U));
    LB_CHECK_OK(noxtls_dtls13_set_own_connection_id(pair.server.t13, k_cid, (uint8_t)sizeof(k_cid)));
    LB_RUN(lb_pair_handshake(&pair));
    LB_RUN(sa_exchange(&pair, 3U));
    LB_CHECK_OK(lb_end_send(&pair.client, (const uint8_t *)"abc", 3U));
    LB_CHECK_EQ(sa_queued(&pair, 0), 1);
    n = sa_pop(&pair, 0, good, sizeof(good));
    LB_CHECK((n > 3U) && (n <= sizeof(good)));
    memcpy(s_buf, good, n);
    s_buf[2] ^= 0x01U;  /* another CID of the same length */
    LB_RUN(sa_push(&pair, 0, s_buf, n));
    len = sizeof(rx);
    rc = lb_end_recv(&pair.server, rx, &len);
    LB_CHECK((rc != NOXTLS_RETURN_SUCCESS) || (len == 0U));
    LB_CHECK(!noxtls_dtls13_last_record_is_newest(pair.server.t13));
    LB_CHECK_EQ(lb_field_state(&pair.server), TLS_STATE_CONNECTED);
    LB_RUN(sa_push(&pair, 0, good, n));
    len = sizeof(rx);
    LB_CHECK_OK(lb_recv_some(&pair, &pair.server, rx, &len));
    LB_CHECK_EQ(len, 3);
    LB_CHECK(memcmp(rx, "abc", 3U) == 0);
    lb_pair_free(&pair);
    return 0;
}

static int test_cid_api_errors(void)
{
    lb_pair_t pair;
    static const uint8_t long_cid[33] = { 1U };

    LB_RUN(sa_pair_init(&pair, k_groups_x25519, 1U));
    LB_CHECK_EQ(noxtls_dtls13_set_own_connection_id(NULL, k_cid, 2U), NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_EQ(noxtls_dtls13_set_own_connection_id(pair.server.t13, NULL, 2U), NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_EQ(noxtls_dtls13_set_own_connection_id(pair.server.t13, k_cid, 0U), NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_EQ(noxtls_dtls13_set_own_connection_id(pair.server.t13, long_cid, 33U), NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_EQ(noxtls_dtls13_set_own_connection_id(pair.client.t13, k_cid, 2U), NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_OK(noxtls_dtls13_set_own_connection_id(pair.server.t13, long_cid, 32U));
    LB_CHECK_OK(noxtls_dtls13_set_own_connection_id(pair.server.t13, k_cid, 2U));
    LB_RUN(lb_pair_handshake(&pair));
    /* After the handshake started. */
    LB_CHECK_EQ(noxtls_dtls13_set_own_connection_id(pair.server.t13, k_cid, 2U), NOXTLS_RETURN_INVALID_PARAM);
    lb_pair_free(&pair);
    return 0;
}

/* ---- N2: newest record --------------------------------------------------------- */

static int sa_send_capture(lb_pair_t *pair, const char *text, uint8_t *out, uint32_t cap, uint32_t *out_len)
{
    LB_CHECK_OK(lb_end_send(&pair->client, (const uint8_t *)text, (uint32_t)strlen(text)));
    LB_CHECK_EQ(sa_queued(pair, 0), 1);
    *out_len = sa_pop(pair, 0, out, cap);
    LB_CHECK(*out_len > 0U);
    return 0;
}

/** Deliver @p dg to the server and receive; @p expect_data 1 when it must carry @p text. */
static int sa_deliver(lb_pair_t *pair, const uint8_t *dg, uint32_t n, const char *text, int expect_data)
{
    uint8_t rx[64];
    uint32_t len = sizeof(rx);
    noxtls_return_t rc;

    LB_RUN(sa_push(pair, 0, dg, n));
    rc = lb_end_recv(&pair->server, rx, &len);
    if(expect_data != 0) {
        LB_CHECK_OK(rc);
        LB_CHECK_EQ(len, strlen(text));
        LB_CHECK(memcmp(rx, text, len) == 0);
    } else {
        LB_CHECK((rc != NOXTLS_RETURN_SUCCESS) || (len == 0U));
    }
    return 0;
}

/** RFC 9146 6 / RFC 9147 4.5.1: in-order, reordered and duplicate records, and a new epoch. */
static int test_newest_record(void)
{
    lb_pair_t pair;
    static uint8_t a[256];
    static uint8_t b[256];
    static uint8_t c[256];
    static uint8_t d[256];
    uint32_t na = 0U;
    uint32_t nb = 0U;
    uint32_t nc = 0U;
    uint32_t nd = 0U;

    LB_RUN(sa_pair_init(&pair, k_groups_x25519, 1U));
    LB_CHECK_OK(noxtls_dtls13_set_own_connection_id(pair.server.t13, k_cid, (uint8_t)sizeof(k_cid)));
    LB_RUN(lb_pair_handshake(&pair));
    LB_RUN(sa_exchange(&pair, 4U));
    LB_RUN(sa_send_capture(&pair, "one", a, sizeof(a), &na));
    LB_RUN(sa_send_capture(&pair, "two", b, sizeof(b), &nb));
    LB_RUN(sa_send_capture(&pair, "three", c, sizeof(c), &nc));

    LB_RUN(sa_deliver(&pair, a, na, "one", 1));
    LB_CHECK(noxtls_dtls13_last_record_is_newest(pair.server.t13));
    LB_RUN(sa_deliver(&pair, c, nc, "three", 1));          /* skips "two": still newer */
    LB_CHECK(noxtls_dtls13_last_record_is_newest(pair.server.t13));
    LB_RUN(sa_deliver(&pair, b, nb, "two", 1));            /* reordered: authentic, older */
    LB_CHECK(!noxtls_dtls13_last_record_is_newest(pair.server.t13));
    LB_RUN(sa_deliver(&pair, c, nc, "three", 0));          /* duplicate: discarded */
    LB_CHECK(!noxtls_dtls13_last_record_is_newest(pair.server.t13));
    LB_RUN(sa_deliver(&pair, a, na, "one", 0));
    LB_CHECK(!noxtls_dtls13_last_record_is_newest(pair.server.t13));

    /* A KeyUpdate moves the client to the next epoch: its first record is newer than any. */
    LB_CHECK_OK(noxtls_tls13_send_key_update(pair.client.t13, 0U));
    LB_CHECK_EQ(sa_queued(&pair, 0), 1);
    nd = sa_pop(&pair, 0, d, sizeof(d));
    LB_RUN(sa_deliver(&pair, d, nd, "", 0));
    LB_CHECK(noxtls_dtls13_last_record_is_newest(pair.server.t13));
    (void)lb_end_flush(&pair.server);
    LB_RUN(sa_send_capture(&pair, "four", a, sizeof(a), &na));
    LB_RUN(sa_deliver(&pair, a, na, "four", 1));
    LB_CHECK(noxtls_dtls13_last_record_is_newest(pair.server.t13));
    /* A record of the old epoch is no longer accepted. */
    LB_RUN(sa_deliver(&pair, b, nb, "two", 0));
    LB_CHECK(!noxtls_dtls13_last_record_is_newest(pair.server.t13));
    LB_CHECK(!noxtls_dtls13_last_record_is_newest(NULL));
    LB_RUN(sa_exchange(&pair, 5U));
    lb_pair_free(&pair);
    return 0;
}

/* ---- N3, N4: stateless HelloRetryRequest -------------------------------------------- */

/** HelloRetryRequest datagram fields (RFC 9147 4, 5.1, 5.2; RFC 8446 4.1.3, 4.1.4). */
static int sa_check_hrr_fields(uint16_t group)
{
    static const uint8_t hrr_random[4] = { 0xCFU, 0x21U, 0xADU, 0x74U };
    const uint8_t *body = &s_hrr[13U + 12U];
    uint8_t sid_len = s_ch1[13U + 12U + 34U];
    uint32_t off;

    LB_CHECK_EQ(s_hrr[0], TLS_RECORD_HANDSHAKE);
    LB_CHECK_EQ(sa_u16(&s_hrr[1]), 0xFEFDU);
    LB_CHECK_EQ(sa_u16(&s_hrr[3]), 0U);                               /* epoch 0 */
    LB_CHECK(memcmp(&s_hrr[5], &s_ch1[5], 6U) == 0);                 /* CH1's record number */
    LB_CHECK_EQ(sa_u16(&s_hrr[11]) + 13U, s_hrr_len);
    LB_CHECK_EQ(s_hrr[13], TLS_HANDSHAKE_SERVER_HELLO);
    LB_CHECK(memcmp(&s_hrr[17], &s_ch1[17], 2U) == 0);               /* CH1's message_seq */
    LB_CHECK(memcmp(&s_hrr[19], "\x00\x00\x00", 3U) == 0);            /* unfragmented */
    LB_CHECK(memcmp(&s_hrr[14], &s_hrr[22], 3U) == 0);
    LB_CHECK_EQ(sa_u16(body), 0xFEFDU);
    LB_CHECK(memcmp(&body[2], hrr_random, sizeof(hrr_random)) == 0);
    LB_CHECK_EQ(body[34], sid_len);                                   /* legacy_session_id echoed */
    LB_CHECK(memcmp(&body[35], &s_ch1[13U + 12U + 35U], sid_len) == 0);
    off = 35U + sid_len;
    LB_CHECK_EQ(sa_u16(&body[off]), k_suite);
    off += 3U;
    LB_CHECK_EQ(sa_u16(&body[off]) + off + 2U, s_hrr_len - 25U);
    off += 2U;
    LB_CHECK_EQ(sa_u16(&body[off]), TLS_EXTENSION_SUPPORTED_VERSIONS);
    LB_CHECK_EQ(sa_u16(&body[off + 4U]), 0xFEFCU);
    off += 6U;
    if(group != 0U) {
        LB_CHECK_EQ(sa_u16(&body[off]), TLS_EXTENSION_KEY_SHARE);
        LB_CHECK_EQ(sa_u16(&body[off + 4U]), group);
        off += 6U;
    }
    LB_CHECK_EQ(sa_u16(&body[off]), TLS_EXTENSION_COOKIE);
    LB_CHECK_EQ(sa_u16(&body[off + 4U]), sizeof(s_cookie));
    LB_CHECK(memcmp(&body[off + 6U], s_cookie, sizeof(s_cookie)) == 0);
    LB_CHECK_EQ(off + 6U + sizeof(s_cookie) + 25U, s_hrr_len);
    return 0;
}

/** A NoxTLS client completes a handshake through a stateless HelloRetryRequest. */
static int test_stateless_hrr_roundtrip(void)
{
    lb_pair_t pair;
    const uint8_t *id = NULL;
    uint16_t id_len = 0U;
    uint32_t i;

    LB_RUN(sa_pair_init(&pair, k_groups_x25519, 1U));
    LB_RUN(sa_capture_ch1(&pair));
    LB_RUN(sa_hrr_and_capture_ch2(&pair, 0U));
    LB_RUN(sa_check_hrr_fields(0U));
    LB_CHECK_OK(noxtls_dtls13_ch2_binder_check(s_ch2, s_ch2_len, s_ch1_hash, k_suite, 0U,
                                               k_identity, (uint16_t)(sizeof(k_identity) - 1U),
                                               k_psk, (uint16_t)sizeof(k_psk), s_scratch, sizeof(s_scratch)));
    for(i = 0U; i < sizeof(s_scratch); i++) {
        LB_CHECK_EQ(s_scratch[i], 0U);                               /* scratch wiped */
    }
    LB_RUN(sa_accept_ch2_and_finish(&pair, 0U));
    LB_CHECK_EQ(pair.client.t13->received_hrr, 0U);  /* cleared once the ServerHello arrived */
    LB_CHECK_EQ(pair.server.t13->sent_hrr, 1U);
    LB_CHECK_OK(noxtls_tls13_selected_psk_identity(pair.server.t13, &id, &id_len));
    LB_CHECK_EQ(id_len, sizeof(k_identity) - 1U);
    LB_CHECK(memcmp(id, k_identity, id_len) == 0);
    LB_RUN(sa_exchange(&pair, 6U));
    lb_pair_free(&pair);
    return 0;
}

/** Stateless admission with the server's own CID (the single-association node's path). */
static int test_stateless_hrr_cid(void)
{
    lb_pair_t pair;

    LB_RUN(sa_pair_init(&pair, k_groups_x25519, 1U));
    LB_CHECK_OK(noxtls_dtls13_set_own_connection_id(pair.server.t13, k_cid, (uint8_t)sizeof(k_cid)));
    LB_RUN(sa_stateless_handshake(&pair, 0U));
    LB_CHECK_EQ(pair.client.t13->peer_connection_id_len, sizeof(k_cid));
    LB_CHECK(memcmp(pair.client.t13->peer_connection_id, k_cid, sizeof(k_cid)) == 0);
    LB_RUN(sa_exchange(&pair, 7U));
    LB_CHECK_OK(noxtls_tls13_release_handshake_state(pair.server.t13));
    LB_RUN(sa_exchange(&pair, 8U));
    lb_pair_free(&pair);
    return 0;
}

/** RFC 8446 4.2.8 / 4.1.4: a HelloRetryRequest that names a group the client listed
 *  without a share; the second ClientHello carries one share for it. */
static int test_stateless_hrr_group(void)
{
    lb_pair_t pair;

    LB_RUN(sa_pair_init(&pair, k_groups_x25519_p256, 2U));
    LB_RUN(sa_capture_ch1(&pair));
    /* The client sent an X25519 share: naming X25519 again is refused. */
    LB_CHECK_EQ(noxtls_dtls13_stateless_hrr(s_ch1, s_ch1_len, s_cookie, (uint16_t)sizeof(s_cookie), k_suite,
                                            TLS_NAMED_GROUP_X25519, s_hrr, sizeof(s_hrr), &s_hrr_len),
                NOXTLS_RETURN_INVALID_PARAM);
    LB_RUN(sa_hrr_and_capture_ch2(&pair, TLS_NAMED_GROUP_SECP256R1));
    LB_RUN(sa_check_hrr_fields(TLS_NAMED_GROUP_SECP256R1));
    /* The HelloRetryRequest must be rebuilt with the same group. */
    LB_CHECK_EQ(noxtls_dtls13_ch2_binder_check(s_ch2, s_ch2_len, s_ch1_hash, k_suite, 0U,
                                               k_identity, (uint16_t)(sizeof(k_identity) - 1U),
                                               k_psk, (uint16_t)sizeof(k_psk), s_scratch, sizeof(s_scratch)),
                NOXTLS_RETURN_AUTH_FAILED);
    LB_CHECK_EQ(noxtls_dtls13_ch2_binder_check(s_ch2, s_ch2_len, s_ch1_hash, k_suite, TLS_NAMED_GROUP_X25519,
                                               k_identity, (uint16_t)(sizeof(k_identity) - 1U),
                                               k_psk, (uint16_t)sizeof(k_psk), s_scratch, sizeof(s_scratch)),
                NOXTLS_RETURN_BAD_DATA);
    LB_CHECK_OK(noxtls_dtls13_ch2_binder_check(s_ch2, s_ch2_len, s_ch1_hash, k_suite, TLS_NAMED_GROUP_SECP256R1,
                                               k_identity, (uint16_t)(sizeof(k_identity) - 1U),
                                               k_psk, (uint16_t)sizeof(k_psk), s_scratch, sizeof(s_scratch)));
    LB_RUN(sa_accept_ch2_and_finish(&pair, TLS_NAMED_GROUP_SECP256R1));
    LB_CHECK_EQ(lb_field_tls13_group(pair.server.t13), TLS_NAMED_GROUP_SECP256R1);
    LB_RUN(sa_exchange(&pair, 9U));
    lb_pair_free(&pair);
    return 0;
}

static int test_stateless_hrr_errors(void)
{
    lb_pair_t pair;
    uint32_t need = 0U;
    uint32_t out_len = 0U;
    static uint8_t bad[SA_DGRAM_MAX + 1U];
    static uint8_t long_cookie[NOXTLS_DTLS13_STATELESS_COOKIE_MAX + 1U];

    LB_RUN(sa_pair_init(&pair, k_groups_x25519, 1U));
    LB_RUN(sa_capture_ch1(&pair));
    /* Parameters. */
    LB_CHECK_EQ(noxtls_dtls13_stateless_hrr(NULL, s_ch1_len, s_cookie, 56U, k_suite, 0U, s_hrr, sizeof(s_hrr), &out_len),
                NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_EQ(noxtls_dtls13_stateless_hrr(s_ch1, s_ch1_len, s_cookie, 0U, k_suite, 0U, s_hrr, sizeof(s_hrr), &out_len),
                NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_EQ(noxtls_dtls13_stateless_hrr(s_ch1, s_ch1_len, long_cookie, (uint16_t)sizeof(long_cookie), k_suite, 0U,
                                            s_hrr, sizeof(s_hrr), &out_len), NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_EQ(noxtls_dtls13_stateless_hrr(s_ch1, s_ch1_len, s_cookie, 56U, TLS_CIPHER_SUITE_AES_256_GCM_SHA384, 0U,
                                            s_hrr, sizeof(s_hrr), &out_len), NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_EQ(noxtls_dtls13_stateless_hrr(s_ch1, s_ch1_len, s_cookie, 56U, 0x1301U, 0x0017U,
                                            s_hrr, sizeof(s_hrr), &out_len), NOXTLS_RETURN_INVALID_PARAM);  /* P-256 not listed */
    LB_CHECK_EQ(noxtls_dtls13_stateless_hrr(s_ch1, s_ch1_len, s_cookie, 56U, k_suite, 0U, s_hrr, 10U, &need),
                NOXTLS_RETURN_BUFFER_TOO_SMALL);
    LB_CHECK_OK(noxtls_dtls13_stateless_hrr(s_ch1, s_ch1_len, s_cookie, 56U, k_suite, 0U, s_hrr, need, &out_len));
    LB_CHECK_EQ(out_len, need);
    LB_CHECK(need <= NOXTLS_DTLS13_STATELESS_HRR_MAX(56U));
    /* Malformed first ClientHello datagrams (RFC 9147 4, 5.1, 5.2). */
    memcpy(bad, s_ch1, s_ch1_len);
    bad[s_ch1_len] = 0U;
    LB_CHECK_EQ(noxtls_dtls13_stateless_hrr(bad, s_ch1_len + 1U, s_cookie, 56U, k_suite, 0U, s_hrr, sizeof(s_hrr), &out_len),
                NOXTLS_RETURN_BAD_DATA);                              /* bytes after the record */
    LB_CHECK_EQ(noxtls_dtls13_stateless_hrr(bad, s_ch1_len - 1U, s_cookie, 56U, k_suite, 0U, s_hrr, sizeof(s_hrr), &out_len),
                NOXTLS_RETURN_BAD_DATA);                              /* truncated */
    memcpy(bad, s_ch1, s_ch1_len);
    bad[13U + 11U] ^= 0x01U;                                          /* fragment length */
    LB_CHECK_EQ(noxtls_dtls13_stateless_hrr(bad, s_ch1_len, s_cookie, 56U, k_suite, 0U, s_hrr, sizeof(s_hrr), &out_len),
                NOXTLS_RETURN_BAD_DATA);
    memcpy(bad, s_ch1, s_ch1_len);
    bad[3] = 0U;
    bad[4] = 1U;                                                      /* epoch 1 */
    LB_CHECK_EQ(noxtls_dtls13_stateless_hrr(bad, s_ch1_len, s_cookie, 56U, k_suite, 0U, s_hrr, sizeof(s_hrr), &out_len),
                NOXTLS_RETURN_BAD_DATA);
    memcpy(bad, s_ch1, s_ch1_len);
    bad[13] = TLS_HANDSHAKE_SERVER_HELLO;
    LB_CHECK_EQ(noxtls_dtls13_stateless_hrr(bad, s_ch1_len, s_cookie, 56U, k_suite, 0U, s_hrr, sizeof(s_hrr), &out_len),
                NOXTLS_RETURN_BAD_DATA);
    LB_CHECK_EQ(noxtls_dtls13_client_hello_hash(bad, s_ch1_len, s_ch1_hash), NOXTLS_RETURN_BAD_DATA);
    {
        /* ClientHello body fields (RFC 8446 4.1.2; RFC 9147 5.1, 5.3). */
        const uint32_t body = 13U + 12U;
        const uint32_t sid = body + 34U;
        const uint32_t cookie_at = sid + 1U + s_ch1[sid];
        const uint32_t suites_at = cookie_at + 1U;
        const uint32_t comp_at = suites_at + 2U + sa_u16(&s_ch1[suites_at]);
        const uint32_t exts_at = comp_at + 2U;
        memcpy(bad, s_ch1, s_ch1_len);
        bad[1] = 0x03U;                                               /* record version */
        LB_CHECK_EQ(noxtls_dtls13_client_hello_hash(bad, s_ch1_len, s_ch1_hash), NOXTLS_RETURN_BAD_DATA);
        LB_CHECK_EQ(noxtls_dtls13_stateless_hrr(bad, s_ch1_len, s_cookie, 56U, k_suite, 0U, s_hrr, sizeof(s_hrr), &out_len),
                    NOXTLS_RETURN_BAD_DATA);
        memcpy(bad, s_ch1, s_ch1_len);
        bad[body] = 0x03U;                                            /* legacy_version */
        LB_CHECK_EQ(noxtls_dtls13_stateless_hrr(bad, s_ch1_len, s_cookie, 56U, k_suite, 0U, s_hrr, sizeof(s_hrr), &out_len),
                    NOXTLS_RETURN_BAD_DATA);
        memcpy(bad, s_ch1, s_ch1_len);
        bad[sid] = 33U;                                               /* legacy_session_id too long */
        LB_CHECK_EQ(noxtls_dtls13_stateless_hrr(bad, s_ch1_len, s_cookie, 56U, k_suite, 0U, s_hrr, sizeof(s_hrr), &out_len),
                    NOXTLS_RETURN_BAD_DATA);
        memcpy(bad, s_ch1, s_ch1_len);
        bad[cookie_at] = 1U;                                          /* legacy_cookie not empty */
        LB_CHECK_EQ(noxtls_dtls13_stateless_hrr(bad, s_ch1_len, s_cookie, 56U, k_suite, 0U, s_hrr, sizeof(s_hrr), &out_len),
                    NOXTLS_RETURN_BAD_DATA);
        memcpy(bad, s_ch1, s_ch1_len);
        bad[suites_at + 1U] |= 0x01U;                                 /* odd cipher_suites length */
        LB_CHECK_EQ(noxtls_dtls13_stateless_hrr(bad, s_ch1_len, s_cookie, 56U, k_suite, 0U, s_hrr, sizeof(s_hrr), &out_len),
                    NOXTLS_RETURN_BAD_DATA);
        memcpy(bad, s_ch1, s_ch1_len);
        bad[comp_at + 1U] = 1U;                                       /* compression method not null */
        LB_CHECK_EQ(noxtls_dtls13_stateless_hrr(bad, s_ch1_len, s_cookie, 56U, k_suite, 0U, s_hrr, sizeof(s_hrr), &out_len),
                    NOXTLS_RETURN_BAD_DATA);
        memcpy(bad, s_ch1, s_ch1_len);
        bad[exts_at + 2U + 2U] = 0xFFU;                               /* first extension overruns the block */
        LB_CHECK_EQ(noxtls_dtls13_stateless_hrr(bad, s_ch1_len, s_cookie, 56U, k_suite, 0U, s_hrr, sizeof(s_hrr), &out_len),
                    NOXTLS_RETURN_BAD_DATA);
        memcpy(bad, s_ch1, s_ch1_len);
        bad[exts_at + 1U] ^= 0x01U;                                   /* extension block length */
        LB_CHECK_EQ(noxtls_dtls13_stateless_hrr(bad, s_ch1_len, s_cookie, 56U, k_suite, 0U, s_hrr, sizeof(s_hrr), &out_len),
                    NOXTLS_RETURN_BAD_DATA);
        LB_CHECK_EQ(noxtls_dtls13_client_hello_hash(s_ch1, 20U, s_ch1_hash), NOXTLS_RETURN_BAD_DATA);
        LB_CHECK_OK(noxtls_dtls13_client_hello_hash(s_ch1, s_ch1_len, s_ch1_hash));
    }
    LB_CHECK_EQ(noxtls_dtls13_client_hello_hash(NULL, s_ch1_len, s_ch1_hash), NOXTLS_RETURN_INVALID_PARAM);
    lb_pair_free(&pair);
    return 0;
}

/** RFC 8446 4.2.11.2 binder precheck: wrong key, identity, transcript, replayed CH1. */
static int test_binder_check_negative(void)
{
    lb_pair_t pair;
    static const uint8_t other_identity[] = "nmx1-observer";
    uint8_t wrong_psk[32];
    uint8_t wrong_hash[32];
    const uint16_t id_len = (uint16_t)(sizeof(k_identity) - 1U);

    LB_RUN(sa_pair_init(&pair, k_groups_x25519, 1U));
    LB_RUN(sa_capture_ch1(&pair));
    LB_RUN(sa_hrr_and_capture_ch2(&pair, 0U));
    memcpy(wrong_psk, k_psk, sizeof(wrong_psk));
    wrong_psk[0] ^= 0x80U;
    memcpy(wrong_hash, s_ch1_hash, sizeof(wrong_hash));
    wrong_hash[31] ^= 0x01U;
    LB_CHECK_EQ(noxtls_dtls13_ch2_binder_check(s_ch2, s_ch2_len, s_ch1_hash, k_suite, 0U, k_identity, id_len,
                                               wrong_psk, (uint16_t)sizeof(wrong_psk), s_scratch, sizeof(s_scratch)),
                NOXTLS_RETURN_AUTH_FAILED);
    LB_CHECK_EQ(noxtls_dtls13_ch2_binder_check(s_ch2, s_ch2_len, s_ch1_hash, k_suite, 0U, other_identity,
                                               (uint16_t)(sizeof(other_identity) - 1U), k_psk, (uint16_t)sizeof(k_psk),
                                               s_scratch, sizeof(s_scratch)),
                NOXTLS_RETURN_AUTH_FAILED);
    LB_CHECK_EQ(noxtls_dtls13_ch2_binder_check(s_ch2, s_ch2_len, wrong_hash, k_suite, 0U, k_identity, id_len,
                                               k_psk, (uint16_t)sizeof(k_psk), s_scratch, sizeof(s_scratch)),
                NOXTLS_RETURN_AUTH_FAILED);
    /* A replayed first ClientHello has no cookie: it cannot follow a HelloRetryRequest. */
    LB_CHECK_EQ(noxtls_dtls13_ch2_binder_check(s_ch1, s_ch1_len, s_ch1_hash, k_suite, 0U, k_identity, id_len,
                                               k_psk, (uint16_t)sizeof(k_psk), s_scratch, sizeof(s_scratch)),
                NOXTLS_RETURN_BAD_DATA);
    /* A suite the HelloRetryRequest did not select. */
    LB_CHECK_EQ(noxtls_dtls13_ch2_binder_check(s_ch2, s_ch2_len, s_ch1_hash, TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256, 0U,
                                               k_identity, id_len, k_psk, (uint16_t)sizeof(k_psk),
                                               s_scratch, sizeof(s_scratch)) == NOXTLS_RETURN_SUCCESS, 0);
    LB_CHECK_EQ(noxtls_dtls13_ch2_binder_check(s_ch2, s_ch2_len, s_ch1_hash, TLS_CIPHER_SUITE_AES_256_GCM_SHA384, 0U,
                                               k_identity, id_len, k_psk, (uint16_t)sizeof(k_psk),
                                               s_scratch, sizeof(s_scratch)),
                NOXTLS_RETURN_INVALID_PARAM);
    /* A tampered binder (the binders are the last bytes of CH2). */
    s_ch2[s_ch2_len - 1U] ^= 0x01U;
    LB_CHECK_EQ(noxtls_dtls13_ch2_binder_check(s_ch2, s_ch2_len, s_ch1_hash, k_suite, 0U, k_identity, id_len,
                                               k_psk, (uint16_t)sizeof(k_psk), s_scratch, sizeof(s_scratch)),
                NOXTLS_RETURN_AUTH_FAILED);
    s_ch2[s_ch2_len - 1U] ^= 0x01U;
    LB_CHECK_EQ(noxtls_dtls13_ch2_binder_check(s_ch2, s_ch2_len - 1U, s_ch1_hash, k_suite, 0U, k_identity, id_len,
                                               k_psk, (uint16_t)sizeof(k_psk), s_scratch, sizeof(s_scratch)),
                NOXTLS_RETURN_BAD_DATA);
    LB_CHECK_EQ(noxtls_dtls13_ch2_binder_check(s_ch2, s_ch2_len, s_ch1_hash, k_suite, 0U, k_identity, id_len,
                                               k_psk, (uint16_t)sizeof(k_psk), s_scratch, s_ch2_len),
                NOXTLS_RETURN_BUFFER_TOO_SMALL);
    LB_CHECK_EQ(noxtls_dtls13_ch2_binder_check(s_ch2, s_ch2_len, s_ch1_hash, k_suite, 0U, k_identity, 0U,
                                               k_psk, (uint16_t)sizeof(k_psk), s_scratch, sizeof(s_scratch)),
                NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_OK(noxtls_dtls13_ch2_binder_check(s_ch2, s_ch2_len, s_ch1_hash, k_suite, 0U, k_identity, id_len,
                                               k_psk, (uint16_t)sizeof(k_psk), s_scratch,
                                               NOXTLS_DTLS13_CH2_BINDER_SCRATCH(s_ch2_len, sizeof(s_cookie))));
    lb_pair_free(&pair);
    return 0;
}

/** A second ClientHello accepted with the wrong message_hash fails the handshake. */
static int test_accept_wrong_ch1_hash(void)
{
    lb_pair_t pair;
    noxtls_return_t rc;

    LB_RUN(sa_pair_init(&pair, k_groups_x25519, 1U));
    LB_RUN(sa_capture_ch1(&pair));
    LB_RUN(sa_hrr_and_capture_ch2(&pair, 0U));
    LB_CHECK_EQ(noxtls_dtls13_accept_after_stateless_hrr(pair.client.t13, s_ch1_hash, k_suite, 0U, s_ch2, s_ch2_len),
                NOXTLS_RETURN_INVALID_PARAM);                          /* not a server */
    LB_CHECK_EQ(noxtls_dtls13_accept_after_stateless_hrr(pair.server.t13, s_ch1_hash, k_suite, 0U, s_ch1, s_ch1_len),
                NOXTLS_RETURN_BAD_DATA);                               /* no cookie */
    s_ch1_hash[0] ^= 0x01U;
    rc = noxtls_dtls13_accept_after_stateless_hrr(pair.server.t13, s_ch1_hash, k_suite, 0U, s_ch2, s_ch2_len);
    LB_CHECK((rc != NOXTLS_RETURN_SUCCESS) && (rc != NOXTLS_RETURN_TIMEOUT));
    LB_CHECK(lb_field_state(&pair.server) != TLS_STATE_CONNECTED);
    lb_pair_free(&pair);
    return 0;
}

/** RFC 9147 5.1: the client hands the cookie to the observer before it sends CH2. */
static int test_hrr_observer(void)
{
    lb_pair_t pair;

    LB_RUN(sa_pair_init(&pair, k_groups_x25519, 1U));
    LB_CHECK_EQ(noxtls_dtls13_set_hrr_observer(pair.server.t13, sa_observe, &s_obs), NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_EQ(noxtls_dtls13_set_hrr_observer(NULL, sa_observe, &s_obs), NOXTLS_RETURN_INVALID_PARAM);
    memset(&s_obs, 0, sizeof(s_obs));
    s_obs.link = pair.link;
    s_obs.to_server_at_call = 99U;
    LB_CHECK_OK(noxtls_dtls13_set_hrr_observer(pair.client.t13, sa_observe, &s_obs));
    LB_RUN(sa_capture_ch1(&pair));
    LB_CHECK_EQ(s_obs.calls, 0U);
    LB_RUN(sa_hrr_and_capture_ch2(&pair, 0U));
    LB_CHECK_EQ(s_obs.calls, 1U);
    LB_CHECK_EQ(s_obs.len, sizeof(s_cookie));
    LB_CHECK(memcmp(s_obs.cookie, s_cookie, sizeof(s_cookie)) == 0);
    LB_CHECK_EQ(s_obs.to_server_at_call, 0U);                          /* CH2 not sent yet */
    LB_RUN(sa_accept_ch2_and_finish(&pair, 0U));
    LB_CHECK_EQ(s_obs.calls, 1U);
    /* The NoxTLS cookie exchange of an ordinary server reaches the observer too. */
    lb_pair_free(&pair);
    LB_RUN(sa_pair_init(&pair, k_groups_x25519, 1U));
    memset(&s_obs, 0, sizeof(s_obs));
    s_obs.link = pair.link;
    LB_CHECK_OK(noxtls_dtls13_set_hrr_observer(pair.client.t13, sa_observe, &s_obs));
    LB_RUN(lb_pair_handshake(&pair));
    LB_CHECK_EQ(s_obs.calls, 1U);
    LB_CHECK(s_obs.len > 0U);
    LB_CHECK_OK(noxtls_dtls13_set_hrr_observer(pair.client.t13, NULL, NULL));
    lb_pair_free(&pair);
    return 0;
}

/** RFC 9147 5.1: without the cookie exchange the ClientHello is answered with the ServerHello. */
static int test_cookie_exchange_off(void)
{
    lb_pair_t pair;

    LB_RUN(sa_pair_init(&pair, k_groups_x25519, 1U));
    LB_CHECK_EQ(noxtls_dtls13_set_cookie_exchange(pair.client.t13, 0U), NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_EQ(noxtls_dtls13_set_cookie_exchange(pair.server.t13, 2U), NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_OK(noxtls_dtls13_set_cookie_exchange(pair.server.t13, 0U));
    LB_RUN(lb_pair_handshake(&pair));
    LB_CHECK_EQ(lb_field_tls13_hrr(pair.server.t13), 0);
    LB_CHECK_EQ(noxtls_dtls13_set_cookie_exchange(pair.server.t13, 1U), NOXTLS_RETURN_INVALID_PARAM);
    LB_RUN(sa_exchange(&pair, 10U));
    lb_pair_free(&pair);
    /* Default: the NoxTLS cookie exchange runs. */
    LB_RUN(sa_pair_init(&pair, k_groups_x25519, 1U));
    LB_RUN(lb_pair_handshake(&pair));
    LB_CHECK_EQ(lb_field_tls13_hrr(pair.server.t13), 1);
    lb_pair_free(&pair);
    return 0;
}

/* ---- N5: handshake-state release ------------------------------------------------------ */

#if NOXTLS_CONFIG_STATIC_MEMORY
static int sa_check_released(tls13_context_t *ctx)
{
    noxtls_connection_memory_stats_t st;
    LB_CHECK_OK(noxtls_connection_memory_get_stats(ctx, &st));
    LB_CHECK_EQ(st.released, 1U);
    LB_CHECK_EQ(st.dangling_pointers, 0U);
    return 0;
}
#endif

/** RFC 8446 7.5: after the release, recv, send, KeyUpdate and the exporter still work. */
static int test_release_then_traffic(void)
{
    lb_pair_t pair;
    const uint8_t *id = NULL;
    uint16_t id_len = 0U;
    uint8_t ekm_client[32];
    uint8_t ekm_server[32];
    static const uint8_t label[] = "EXPORTER-NoxMux-elevate-v1";
    static const uint8_t context[32] = { 7U };
    int side;

    LB_RUN(sa_pair_init(&pair, k_groups_x25519, 1U));
    LB_CHECK_OK(noxtls_dtls13_set_own_connection_id(pair.server.t13, k_cid, (uint8_t)sizeof(k_cid)));
    LB_RUN(lb_pair_handshake(&pair));
    LB_RUN(sa_exchange(&pair, 11U));
    for(side = 0; side < 2; side++) {
        tls13_context_t *ctx = (side == 0) ? pair.client.t13 : pair.server.t13;
        LB_CHECK_OK(noxtls_tls13_selected_psk_identity(ctx, &id, &id_len));
        LB_CHECK_EQ(id_len, sizeof(k_identity) - 1U);
        LB_CHECK(memcmp(id, k_identity, id_len) == 0);
        LB_CHECK_OK(noxtls_tls13_release_handshake_state(ctx));
        LB_CHECK_OK(noxtls_tls13_release_handshake_state(ctx));        /* idempotent */
        LB_CHECK(ctx->hs == NULL);
        LB_CHECK(ctx->handshake_workspace == NULL);
#if NOXTLS_CONFIG_STATIC_MEMORY
        LB_RUN(sa_check_released(ctx));
#endif
        id = NULL;
        id_len = 0U;
        LB_CHECK_OK(noxtls_tls13_selected_psk_identity(ctx, &id, &id_len));
        LB_CHECK_EQ(id_len, sizeof(k_identity) - 1U);
        LB_CHECK(memcmp(id, k_identity, id_len) == 0);
        LB_CHECK(ctx->exporter_master_secret_len == 32U);
    }
    LB_RUN(sa_exchange(&pair, 12U));
    LB_CHECK_OK(noxtls_tls13_send_key_update(pair.client.t13, 1U));
    LB_RUN(sa_exchange(&pair, 13U));
    LB_CHECK_OK(noxtls_tls13_send_key_update(pair.server.t13, 0U));
    LB_RUN(sa_exchange(&pair, 14U));
    LB_CHECK_OK(noxtls_tls13_export_keying_material(pair.client.t13, label, (uint32_t)(sizeof(label) - 1U),
                                                    context, sizeof(context), ekm_client, sizeof(ekm_client)));
    LB_CHECK_OK(noxtls_tls13_export_keying_material(pair.server.t13, label, (uint32_t)(sizeof(label) - 1U),
                                                    context, sizeof(context), ekm_server, sizeof(ekm_server)));
    LB_CHECK(memcmp(ekm_client, ekm_server, sizeof(ekm_client)) == 0);
    lb_pair_free(&pair);
    return 0;
}

static int test_release_errors(void)
{
    lb_pair_t pair;
    const uint8_t *id = NULL;
    uint16_t id_len = 0U;

    LB_RUN(sa_pair_init(&pair, k_groups_x25519, 1U));
    LB_CHECK_EQ(noxtls_tls13_release_handshake_state(NULL), NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_EQ(noxtls_tls13_release_handshake_state(pair.server.t13), NOXTLS_RETURN_BAD_STATE);
    LB_CHECK_EQ(noxtls_tls13_selected_psk_identity(pair.server.t13, &id, &id_len), NOXTLS_RETURN_BAD_STATE);
    LB_CHECK_EQ(noxtls_tls13_selected_psk_identity(pair.server.t13, NULL, &id_len), NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_EQ(noxtls_tls13_selected_psk_identity(NULL, &id, &id_len), NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK(pair.server.t13->hs != NULL);
    LB_RUN(lb_pair_handshake(&pair));
    LB_RUN(sa_exchange(&pair, 15U));
    LB_CHECK_OK(noxtls_tls13_release_handshake_state(pair.server.t13));
    LB_CHECK_OK(noxtls_tls13_close(pair.server.t13));
    LB_CHECK_EQ(noxtls_tls13_release_handshake_state(pair.server.t13), NOXTLS_RETURN_BAD_STATE);
    lb_pair_free(&pair);
    return 0;
}

/**
 * RFC 9147 5.9: the DTLS 1.3 exporter uses the "dtls13" HKDF label prefix. Compared with
 * gen_exporter_vector.py (Python hmac/hashlib, checked against RFC 8448), not with NoxTLS.
 */
static int test_exporter_vector(void)
{
    static const uint8_t ems[32] = {
        0x40U, 0x41U, 0x42U, 0x43U, 0x44U, 0x45U, 0x46U, 0x47U, 0x48U, 0x49U, 0x4AU, 0x4BU, 0x4CU, 0x4DU, 0x4EU, 0x4FU,
        0x50U, 0x51U, 0x52U, 0x53U, 0x54U, 0x55U, 0x56U, 0x57U, 0x58U, 0x59U, 0x5AU, 0x5BU, 0x5CU, 0x5DU, 0x5EU, 0x5FU
    };
    static const uint8_t label[] = "EXPORTER-NoxMux-elevate-v1";
    static const uint8_t context[32] = {
        0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
        0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x00U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x0FU
    };
    static const uint8_t expect_dtls13[32] = {
        0x24U, 0x57U, 0x91U, 0xB5U, 0x05U, 0x55U, 0xC0U, 0xC5U, 0xB5U, 0x8DU, 0xD8U, 0x38U, 0x5BU, 0x71U, 0x8CU, 0xB7U,
        0x31U, 0xB0U, 0xCBU, 0xF6U, 0x30U, 0x81U, 0xE8U, 0x84U, 0xA8U, 0x35U, 0xD8U, 0x34U, 0xBBU, 0xB4U, 0xA0U, 0x4BU
    };
    static const uint8_t expect_tls13[32] = {
        0x55U, 0x11U, 0x0BU, 0x64U, 0x82U, 0x2CU, 0x53U, 0x7CU, 0x5EU, 0x1FU, 0x16U, 0x14U, 0x24U, 0x73U, 0xD6U, 0xD8U,
        0xD4U, 0x18U, 0x38U, 0xB4U, 0x31U, 0xB8U, 0x0AU, 0xD8U, 0x8BU, 0x0BU, 0xA1U, 0x06U, 0x00U, 0x56U, 0xB4U, 0x0FU
    };
    lb_pair_t pair;
    uint8_t out[32];
    tls13_context_t *ctx;
    uint16_t version;

    LB_RUN(sa_pair_init(&pair, k_groups_x25519, 1U));
    LB_RUN(lb_pair_handshake(&pair));
    LB_RUN(sa_exchange(&pair, 16U));
    LB_CHECK_OK(noxtls_tls13_release_handshake_state(pair.server.t13));
    ctx = pair.server.t13;
    LB_CHECK_EQ(ctx->cipher_suite, TLS_CIPHER_SUITE_AES_128_GCM_SHA256);
    memcpy(ctx->exporter_master_secret, ems, sizeof(ems));
    ctx->exporter_master_secret_len = (uint8_t)sizeof(ems);
    LB_CHECK_OK(noxtls_tls13_export_keying_material(ctx, label, (uint32_t)(sizeof(label) - 1U),
                                                    context, sizeof(context), out, sizeof(out)));
    LB_CHECK(memcmp(out, expect_dtls13, sizeof(out)) == 0);
    /* The same secret on a TLS 1.3 context gives the "tls13 " value. */
    version = ctx->base.base.version;
    ctx->base.base.version = TLS_VERSION_1_3;
    LB_CHECK_OK(noxtls_tls13_export_keying_material(ctx, label, (uint32_t)(sizeof(label) - 1U),
                                                    context, sizeof(context), out, sizeof(out)));
    ctx->base.base.version = version;
    LB_CHECK(memcmp(out, expect_tls13, sizeof(out)) == 0);
    lb_pair_free(&pair);
    return 0;
}

/** The context-free calls allocate nothing (heap or static), and a static-memory
 *  build makes no C library allocator call in the whole stateless handshake. */
static int test_zero_allocation(void)
{
    lb_pair_t pair;
    lb_alloc_stats_t st;
    size_t heap_before;

    LB_RUN(sa_pair_init(&pair, k_groups_x25519, 1U));
    heap_before = HEAP_CALLS();
    LB_RUN(sa_capture_ch1(&pair));
    lb_alloc_reset_counters();
    LB_CHECK_OK(noxtls_dtls13_client_hello_hash(s_ch1, s_ch1_len, s_ch1_hash));
    LB_CHECK_OK(noxtls_dtls13_stateless_hrr(s_ch1, s_ch1_len, s_cookie, (uint16_t)sizeof(s_cookie), k_suite, 0U,
                                            s_hrr, sizeof(s_hrr), &s_hrr_len));
    lb_alloc_get_stats(&st);
    LB_CHECK_EQ(st.alloc_calls, 0U);
    LB_RUN(sa_push(&pair, 1, s_hrr, s_hrr_len));
    pair.client.last_rc = lb_end_step(&pair.client);
    s_ch2_len = sa_pop(&pair, 0, s_ch2, sizeof(s_ch2));
    LB_CHECK(s_ch2_len > 0U);
    lb_alloc_reset_counters();
#if !NOXTLS_CONFIG_STATIC_MEMORY
    lb_alloc_fail_after(0U);  /* any allocation would fail the check */
#endif
    LB_CHECK_OK(noxtls_dtls13_ch2_binder_check(s_ch2, s_ch2_len, s_ch1_hash, k_suite, 0U,
                                               k_identity, (uint16_t)(sizeof(k_identity) - 1U),
                                               k_psk, (uint16_t)sizeof(k_psk), s_scratch, sizeof(s_scratch)));
#if !NOXTLS_CONFIG_STATIC_MEMORY
    lb_alloc_fail_after(SIZE_MAX);
#endif
    lb_alloc_get_stats(&st);
    LB_CHECK_EQ(st.alloc_calls, 0U);
    LB_RUN(sa_accept_ch2_and_finish(&pair, 0U));
    LB_RUN(sa_exchange(&pair, 17U));
    LB_CHECK_OK(noxtls_tls13_release_handshake_state(pair.server.t13));
    LB_RUN(sa_exchange(&pair, 18U));
    LB_CHECK_EQ(HEAP_CALLS(), heap_before);
    lb_pair_free(&pair);
    return 0;
}

static const lb_test_case_t s_cases[] = {
    { "sa_cid_own_server", test_cid_own_server },
    { "sa_cid_mismatch_dropped", test_cid_mismatch_dropped },
    { "sa_cid_api_errors", test_cid_api_errors },
    { "sa_newest_record", test_newest_record },
    { "sa_stateless_hrr_roundtrip", test_stateless_hrr_roundtrip },
    { "sa_stateless_hrr_cid", test_stateless_hrr_cid },
    { "sa_stateless_hrr_group", test_stateless_hrr_group },
    { "sa_stateless_hrr_errors", test_stateless_hrr_errors },
    { "sa_binder_check_negative", test_binder_check_negative },
    { "sa_accept_wrong_ch1_hash", test_accept_wrong_ch1_hash },
    { "sa_hrr_observer", test_hrr_observer },
    { "sa_cookie_exchange_off", test_cookie_exchange_off },
    { "sa_release_then_traffic", test_release_then_traffic },
    { "sa_release_errors", test_release_errors },
    { "sa_exporter_vector", test_exporter_vector },
    { "sa_zero_allocation", test_zero_allocation },
    { "sa_ch1_hash_vector", test_ch1_hash_vector },
    { "sa_binder_vectors", test_binder_vectors },
    { "sa_s0_binder_vector", test_s0_binder_vector },
    { "sa_legacy_labels_old_peer", test_legacy_labels_old_peer },
    { "sa_legacy_labels_handshake", test_legacy_labels_handshake },
};

int main(int argc, char **argv)
{
    return lb_main(argc, argv, "dtls13_single_association_test", s_cases, sizeof(s_cases) / sizeof(s_cases[0]));
}
