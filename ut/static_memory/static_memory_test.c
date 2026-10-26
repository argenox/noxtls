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
* File:    static_memory_test.c
* Summary: NOXTLS_CONFIG_STATIC_MEMORY handshake, release, heap and pool tests
*****************************************************************************/
/** @file static_memory_test.c
 * @brief Static memory regressions (docs/static-memory.md).
 *
 * Every case runs real TLS 1.3 / DTLS 1.3 handshakes between two contexts whose
 * memory is a caller-provided block (noxtls_*_context_init_static), over the
 * in-memory link of ut/tls_loopback. Built with GNU ld, the executable wraps
 * malloc/calloc/realloc/free (-Wl,--wrap=...) and each case asserts that the
 * library made no call to them.
 */
#include "lb_fixture.h"
#include "tls/noxtls_connection_memory.h"

#include <string.h>

/* ---- C library allocator hooks -------------------------------------------- */

#if defined(NOXTLS_STATIC_TEST_WRAP_HEAP)
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
#define HEAP_HOOKED 1
#else
#define HEAP_CALLS() ((size_t)0U)
#define HEAP_HOOKED 0
#endif

/* ---- Caller blocks --------------------------------------------------------- */

#define ST_MAX2(a, b) (((a) > (b)) ? (a) : (b))
#define ST_BLOCK_BYTES \
    ST_MAX2(ST_MAX2(NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_CLIENT, TLS13_CERT), \
                    NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_CLIENT, DTLS13_CERT)), \
            ST_MAX2(NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_CLIENT, TLS13_PSK), \
                    NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_CLIENT, DTLS13_PSK)))

static uint64_t s_client_mem[ST_BLOCK_BYTES / 8U];
static uint64_t s_server_mem[ST_BLOCK_BYTES / 8U];
static uint8_t s_payload[4096];

static const uint8_t k_psk_identity[] = "static-memory-test";
static const uint8_t k_psk_key[] = "0123456789abcdef0123456789abcdef";

/** Measured values of one case, printed by the footprint report. */
typedef struct
{
    size_t hs_peak[2];       /* handshake arena high-water mark [client, server] */
    size_t steady_peak[2];   /* steady arena high-water mark */
} st_measure_t;

static st_measure_t s_measure;

/* The test PKI (RSA-2048 and ECDSA chains) needs certificate copies of about 1 KB. */
#define ST_CERT_PROFILE (NOXTLS_STATIC_CERT_DER_MAX >= 1024U)

/* ---- Helpers --------------------------------------------------------------- */

static int st_psk(lb_pair_t *pair)
{
    static const uint16_t group = TLS_NAMED_GROUP_X25519;
    static const uint16_t suite = TLS_CIPHER_SUITE_AES_128_GCM_SHA256;
    LB_CHECK_OK(tls13_set_external_psk(pair->client.t13, k_psk_identity, sizeof(k_psk_identity) - 1U,
                                       k_psk_key, sizeof(k_psk_key) - 1U, TLS13_PSK_KE_MODE_PSK_DHE_KE));
    LB_CHECK_OK(tls13_set_external_psk(pair->server.t13, k_psk_identity, sizeof(k_psk_identity) - 1U,
                                       k_psk_key, sizeof(k_psk_key) - 1U, TLS13_PSK_KE_MODE_PSK_DHE_KE));
    noxtls_tls13_set_client_supported_groups(pair->client.t13, &group, 1U);
    noxtls_tls13_set_server_cipher_suites(pair->server.t13, &suite, 1U);
    return 0;
}

/** Initialize a pair in the caller blocks. auth LB_AUTH_NONE selects external PSK. */
static int st_pair_init(lb_pair_t *pair, lb_proto_t proto, lb_auth_t auth, lb_auth_t client_cert)
{
    lb_cfg_t cfg;
    uint32_t profile;
    int dtls = (proto == LB_PROTO_DTLS13) ? 1 : 0;

    if(auth == LB_AUTH_NONE) {
        profile = (dtls != 0) ? NOXTLS_CONN_PROFILE_DTLS13_PSK : NOXTLS_CONN_PROFILE_TLS13_PSK;
    } else {
        profile = (dtls != 0) ? NOXTLS_CONN_PROFILE_DTLS13_CERT : NOXTLS_CONN_PROFILE_TLS13_CERT;
        LB_RUN(lb_trust_all_roots());
    }
    lb_cfg_default(&cfg, proto);
    cfg.server_auth = auth;
    cfg.send_chain = (auth == LB_AUTH_ECDSA) ? 1 : 0;
    cfg.client_cert = client_cert;
    cfg.client_auth = (client_cert != LB_AUTH_NONE) ? 2 : 0;
    if(auth == LB_AUTH_NONE) {
        cfg.sni = NULL;
    }
    lb_static_memory_set(s_client_mem, sizeof(s_client_mem), profile, s_server_mem, sizeof(s_server_mem), profile);
    LB_RUN(lb_pair_init(pair, &cfg));
    if(auth == LB_AUTH_NONE) {
        LB_RUN(st_psk(pair));
    }
#if NOXTLS_TLS_MAX_RECORD_SIZE < DTLS_MAX_FRAGMENT_SIZE
    if(dtls != 0) {
        /* As the Thread management endpoints do: datagrams of one record. */
        LB_CHECK_OK(noxtls_dtls_set_mtu(&pair->client.t13->base, (uint16_t)NOXTLS_TLS_MAX_RECORD_SIZE));
        LB_CHECK_OK(noxtls_dtls_set_mtu(&pair->server.t13->base, (uint16_t)NOXTLS_TLS_MAX_RECORD_SIZE));
    }
#endif
    return 0;
}

/** Check one endpoint after the handshake part was released. */
static int st_check_released(lb_end_t *end, int index)
{
    noxtls_connection_memory_stats_t st;
    uint8_t *region = NULL;
    size_t region_len = 0U;
    size_t i;

    LB_CHECK_OK(noxtls_connection_memory_get_stats(end->t13, &st));
    LB_CHECK_EQ(st.released, 1U);
    LB_CHECK_EQ(st.dangling_pointers, 0U);
    LB_CHECK(end->t13->hs == NULL);
    LB_CHECK(st.hs_arena_peak_at_release > 0U);
    LB_CHECK(st.hs_arena_peak_at_release <= st.layout.hs_arena);
    LB_CHECK_OK(noxtls_connection_memory_handshake_region(end->t13, &region, &region_len));
    LB_CHECK_EQ(region_len, st.layout.handshake);
    /* Released handshake storage (secrets, transcript, key shares) is wiped. */
    for(i = 0U; i < region_len; i++) {
        if(region[i] != 0U) {
            lb_log("released handshake byte %lu is not zero", (unsigned long)i);
            return 1;
        }
    }
    if(st.hs_arena_peak_at_release > s_measure.hs_peak[index]) {
        s_measure.hs_peak[index] = st.hs_arena_peak_at_release;
    }
    if(st.steady_arena.peak > s_measure.steady_peak[index]) {
        s_measure.steady_peak[index] = st.steady_arena.peak;
    }
    return 0;
}

/** Steady state: after a drained exchange the steady arena holds nothing. */
static int st_check_steady_idle(const lb_end_t *end)
{
    noxtls_connection_memory_stats_t st;
    LB_CHECK_OK(noxtls_connection_memory_get_stats(end->t13, &st));
    LB_CHECK_EQ(st.steady_arena.live_blocks, 0U);
    LB_CHECK(st.steady_arena.peak <= st.layout.steady_arena);
    return 0;
}

static int st_exchange(lb_pair_t *pair, uint32_t seed)
{
    lb_fill_pattern(s_payload, 1000U, seed);
    LB_RUN(lb_transfer(pair, 1, s_payload, 1000U, 400U, 1000U));
    LB_RUN(lb_transfer(pair, 0, s_payload, 1000U, 400U, 1000U));
    return 0;
}

/** Overwrite the released handshake part as an application reusing it would. */
static int st_reuse_region(lb_end_t *end)
{
    uint8_t *region = NULL;
    size_t region_len = 0U;
    LB_CHECK_OK(noxtls_connection_memory_handshake_region(end->t13, &region, &region_len));
    memset(region, 0xA5, region_len);
    return 0;
}

/**
 * Full scenario: handshake, release checks, data, reuse of the released part,
 * KeyUpdate in both directions, data again, and no C library allocator call.
 */
static int st_scenario(lb_proto_t proto, lb_auth_t auth, lb_auth_t client_cert)
{
    lb_pair_t pair;
    size_t base = lb_alloc_live_bytes();
    size_t heap_before;
    uint32_t i;

    LB_RUN(st_pair_init(&pair, proto, auth, client_cert));
    heap_before = HEAP_CALLS();
    LB_RUN(lb_pair_handshake(&pair));
    /* DTLS: the client releases once its final flight is acknowledged (first exchange). */
    LB_RUN(st_exchange(&pair, 1U));
    LB_RUN(st_check_released(&pair.client, 0));
    LB_RUN(st_check_released(&pair.server, 1));
    LB_RUN(st_check_steady_idle(&pair.client));
    LB_RUN(st_check_steady_idle(&pair.server));
    if(auth != LB_AUTH_NONE) {
        /* The server's leaf certificate stays available (tls-server-end-point). */
        uint8_t cb[64];
        uint32_t cb_len = sizeof(cb);
        LB_CHECK(pair.client.t13->server_cert != NULL);
        LB_CHECK_OK(noxtls_tls13_get_channel_binding(pair.client.t13, NOXTLS_TLS_CHANNEL_BINDING_TLS_SERVER_END_POINT,
                                                     cb, &cb_len));
    }
    LB_RUN(st_reuse_region(&pair.client));
    LB_RUN(st_reuse_region(&pair.server));
    for(i = 0U; i < 2U; i++) {
        LB_CHECK_OK(noxtls_tls13_send_key_update(pair.client.t13, 1U));
        (void)lb_end_flush(&pair.client);
        LB_RUN(st_exchange(&pair, 10U + i));
        LB_CHECK_OK(noxtls_tls13_send_key_update(pair.server.t13, 0U));
        (void)lb_end_flush(&pair.server);
        LB_RUN(st_exchange(&pair, 20U + i));
    }
    LB_RUN(st_check_steady_idle(&pair.client));
    LB_RUN(st_check_steady_idle(&pair.server));
    LB_CHECK_EQ(HEAP_CALLS() - heap_before, 0U);
    if(proto == LB_PROTO_DTLS13) {
        (void)lb_end_close(&pair.client);
    } else {
        LB_RUN(lb_close_and_observe(&pair, 1));
    }
    lb_pair_free(&pair);
    lb_trust_clear();
    /* Freeing a context wipes its whole block. */
    for(i = 0U; i < (uint32_t)(sizeof(s_client_mem) / sizeof(s_client_mem[0])); i++) {
        LB_CHECK((s_client_mem[i] == 0U) && (s_server_mem[i] == 0U));
    }
    return lb_expect_no_leak(base, "static scenario");
}

/* ---- Cases ----------------------------------------------------------------- */

static int t_dtls13_psk(void) { return st_scenario(LB_PROTO_DTLS13, LB_AUTH_NONE, LB_AUTH_NONE); }
static int t_tls13_psk(void) { return st_scenario(LB_PROTO_TLS13, LB_AUTH_NONE, LB_AUTH_NONE); }
static int t_tls13_cert_ecdsa(void) { return st_scenario(LB_PROTO_TLS13, LB_AUTH_ECDSA, LB_AUTH_NONE); }
static int t_tls13_cert_rsa(void) { return st_scenario(LB_PROTO_TLS13, LB_AUTH_RSA, LB_AUTH_NONE); }
static int t_tls13_mtls_rsa_client(void) { return st_scenario(LB_PROTO_TLS13, LB_AUTH_RSA, LB_AUTH_RSA); }
static int t_tls13_mtls_ecdsa_client(void) { return st_scenario(LB_PROTO_TLS13, LB_AUTH_ECDSA, LB_AUTH_ECDSA); }
static int t_dtls13_cert_ecdsa(void)
{
#if NOXTLS_TLS_MAX_RECORD_SIZE < 2048U
    /* DTLS 1.3 certificate flights with small records fail in heap builds as well
     * (dtls13_ecdsa_handshake_data with NOXTLS_TLS_MAX_RECORD_SIZE=512). */
    return LB_SKIP;
#else
    return st_scenario(LB_PROTO_DTLS13, LB_AUTH_ECDSA, LB_AUTH_NONE);
#endif
}

/** The handshake part is not released while a handshake is running and is
 *  refused to the application until then. */
static int t_release_timing(void)
{
    lb_pair_t pair;
    uint8_t *region = NULL;
    size_t region_len = 0U;
    noxtls_connection_memory_stats_t st;
    size_t base = lb_alloc_live_bytes();

    LB_RUN(st_pair_init(&pair, LB_PROTO_DTLS13, LB_AUTH_NONE, LB_AUTH_NONE));
    LB_CHECK_EQ(noxtls_connection_memory_handshake_region(pair.server.t13, &region, &region_len),
                NOXTLS_RETURN_NOT_INITIALIZED);
    LB_CHECK(region == NULL);
    LB_CHECK_OK(noxtls_connection_memory_get_stats(pair.server.t13, &st));
    LB_CHECK_EQ(st.released, 0U);
    LB_CHECK(pair.server.t13->hs != NULL);
    LB_RUN(lb_pair_handshake(&pair));
    /* The server has the client Finished: released. */
    LB_CHECK_OK(noxtls_connection_memory_get_stats(pair.server.t13, &st));
    LB_CHECK_EQ(st.released, 1U);
    LB_RUN(st_exchange(&pair, 3U));
    LB_CHECK_OK(noxtls_connection_memory_get_stats(pair.client.t13, &st));
    LB_CHECK_EQ(st.released, 1U);
    LB_CHECK_EQ(pair.client.t13->base.flight_buffer_len, 0U);
    (void)lb_end_close(&pair.server);
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "release timing");
}

/** A flight buffer the application installs is kept across the release. */
static int t_application_flight_buffer(void)
{
    static uint8_t app_flight[2048];
    lb_pair_t pair;
    size_t base = lb_alloc_live_bytes();

    LB_RUN(st_pair_init(&pair, LB_PROTO_DTLS13, LB_AUTH_NONE, LB_AUTH_NONE));
    LB_CHECK_OK(noxtls_dtls_set_flight_buffer(&pair.server.t13->base, app_flight, sizeof(app_flight)));
    LB_RUN(lb_pair_handshake(&pair));
    LB_RUN(st_exchange(&pair, 4U));
    LB_RUN(st_check_released(&pair.server, 1));
    LB_CHECK(pair.server.t13->base.flight_buffer_storage == app_flight);
    LB_CHECK_OK(noxtls_tls13_send_key_update(pair.server.t13, 1U));
    LB_RUN(st_exchange(&pair, 5U));
    (void)lb_end_close(&pair.server);
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "application flight buffer");
}

/** Every pool returns the same deterministic error when it is full. */
static int t_pool_exhaustion(void)
{
    const uint8_t *ders[NOXTLS_STATIC_TRUST_ANCHORS_MAX + 1U];
    uint32_t lens[NOXTLS_STATIC_TRUST_ANCHORS_MAX + 1U];
    x509_certificate_chain_t chain;
    x509_certificate_t cert;
    noxtls_mem_error_info_t err;
    noxtls_mem_region_stats_t global;
    tls13_context_t extra[NOXTLS_STATIC_CONNECTION_POOL_COUNT + 1U];
    uint8_t big[NOXTLS_STATIC_CERT_DER_MAX + 1U];
    uint32_t i;
    int pass;
    size_t base = lb_alloc_live_bytes();

    for(pass = 0; pass < 2; pass++) {
        /* Trust anchors beyond NOXTLS_STATIC_TRUST_ANCHORS_MAX. */
        for(i = 0U; i <= NOXTLS_STATIC_TRUST_ANCHORS_MAX; i++) {
            ders[i] = lb_ec_root_cert;
            lens[i] = lb_ec_root_cert_len;
        }
        LB_CHECK_EQ(noxtls_x509_trust_store_set_der_nocopy(ders, lens, NOXTLS_STATIC_TRUST_ANCHORS_MAX + 1U),
                    NOXTLS_RETURN_NOT_ENOUGH_MEMORY);
        LB_CHECK_EQ(noxtls_x509_trust_store_has_anchors(), 0);

        /* Chains hold NOXTLS_STATIC_CHAIN_CAPACITY certificates. */
        LB_CHECK_OK(noxtls_x509_certificate_chain_init(&chain));
        for(i = 0U; i < NOXTLS_STATIC_CHAIN_CAPACITY; i++) {
            LB_CHECK_OK(noxtls_x509_certificate_chain_add_der(&chain, lb_ec_root_cert, lb_ec_root_cert_len));
        }
        LB_CHECK(noxtls_x509_certificate_chain_add_der(&chain, lb_ec_root_cert, lb_ec_root_cert_len) !=
                 NOXTLS_RETURN_SUCCESS);
        LB_CHECK_EQ(chain.count, NOXTLS_STATIC_CHAIN_CAPACITY);
        (void)noxtls_x509_certificate_chain_free(&chain);

        /* A certificate copy larger than NOXTLS_STATIC_CERT_DER_MAX. When the profile sets
         * NOXTLS_MAX_CERT_SIZE to the same size (the leader profiles), the certificate is
         * above the build's certificate bound as well, which is checked first. */
        memset(big, 0x30, sizeof(big));
        (void)noxtls_x509_certificate_init(&cert);
        LB_CHECK_EQ(noxtls_x509_certificate_parse_der(&cert, big, (uint32_t)sizeof(big)),
                    (NOXTLS_STATIC_CERT_DER_MAX < NOXTLS_MAX_CERT_SIZE) ? NOXTLS_RETURN_NOT_ENOUGH_MEMORY :
                                                                          NOXTLS_RETURN_CERT_PARSE_FAILED);
        (void)noxtls_x509_certificate_free(&cert);

        /* The global arena (the profile's, with the test harness's share, lb_main):
         * no fallback, the failure names the region. */
        LB_CHECK_OK(noxtls_mem_region_get_stats(noxtls_mem_global_region(), &global));
        LB_CHECK(global.capacity >= NOXTLS_STATIC_GLOBAL_POOL_SIZE);
        noxtls_mem_clear_last_error();
        LB_CHECK(NOXTLS_MALLOC(global.capacity + 1U) == NULL);
        LB_CHECK_OK(noxtls_mem_get_last_error(&err));
        LB_CHECK_EQ(err.reason, NOXTLS_MEM_FAILURE_POOL_EXHAUSTED);
        LB_CHECK((err.region_name != NULL) && (strcmp(err.region_name, "global") == 0));
        LB_CHECK_EQ(err.requested_bytes, global.capacity + 1U);

        /* Library connection pool: NOXTLS_STATIC_CONNECTION_POOL_COUNT blocks. */
        for(i = 0U; i < NOXTLS_STATIC_CONNECTION_POOL_COUNT; i++) {
            LB_CHECK_OK(noxtls_dtls13_context_init(&extra[i], TLS_ROLE_CLIENT));
        }
        LB_CHECK_EQ(noxtls_dtls13_context_init(&extra[i], TLS_ROLE_CLIENT), NOXTLS_RETURN_NOT_ENOUGH_MEMORY);
        for(i = 0U; i < NOXTLS_STATIC_CONNECTION_POOL_COUNT; i++) {
            LB_CHECK_OK(noxtls_tls13_context_free(&extra[i]));
        }

        /* A caller block smaller than the profile needs. */
        LB_CHECK_EQ(noxtls_dtls13_context_init_static(&extra[0], TLS_ROLE_SERVER, NOXTLS_CONN_PROFILE_DTLS13_PSK,
                    s_server_mem, NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_SERVER, DTLS13_PSK) - 8U),
                    NOXTLS_RETURN_INVALID_PARAM);
        LB_CHECK_EQ(noxtls_tls13_context_init_static(&extra[0], TLS_ROLE_SERVER, NOXTLS_CONN_PROFILE_DTLS13_PSK,
                    s_server_mem, sizeof(s_server_mem)), NOXTLS_RETURN_INVALID_PARAM);
    }
    return lb_expect_no_leak(base, "pool exhaustion");
}

/** A received chain deeper than NOXTLS_STATIC_CERT_CHAIN_DEPTH_MAX fails the same way twice. */
static int t_peer_chain_too_deep(void)
{
    static const uint8_t *chain_ders[NOXTLS_STATIC_CERT_CHAIN_DEPTH_MAX];
    static uint32_t chain_lens[NOXTLS_STATIC_CERT_CHAIN_DEPTH_MAX];
    noxtls_return_t first_rc = NOXTLS_RETURN_SUCCESS;
    int pass;
    uint32_t i;
    size_t base = lb_alloc_live_bytes();

    for(i = 0U; i < NOXTLS_STATIC_CERT_CHAIN_DEPTH_MAX; i++) {
        chain_ders[i] = lb_ec_int_cert;
        chain_lens[i] = lb_ec_int_cert_len;
    }
    for(pass = 0; pass < 2; pass++) {
        lb_pair_t pair;
        LB_RUN(st_pair_init(&pair, LB_PROTO_TLS13, LB_AUTH_ECDSA, LB_AUTH_NONE));
        /* Leaf + NOXTLS_STATIC_CERT_CHAIN_DEPTH_MAX intermediates. */
        noxtls_tls13_set_server_certificate_chain(pair.server.t13, chain_ders, chain_lens,
                                                  NOXTLS_STATIC_CERT_CHAIN_DEPTH_MAX);
        LB_CHECK(lb_pair_handshake(&pair) != 0);
        LB_CHECK(pair.client.last_rc != NOXTLS_RETURN_SUCCESS);
        if(pass == 0) {
            first_rc = pair.client.last_rc;
        } else {
            LB_CHECK_EQ(pair.client.last_rc, first_rc);
        }
        lb_pair_free(&pair);
        lb_trust_clear();
    }
    return lb_expect_no_leak(base, "deep chain");
}

static void st_print_profile(const char *name, uint32_t profile, size_t hs_peak, size_t steady_peak)
{
    noxtls_connection_footprint_t fp;
    (void)noxtls_connection_memory_footprint(TLS_ROLE_CLIENT, profile, &fp);
    printf("  %-12s block %6lu  steady %6lu  released %6lu  (hs %5lu, workspace %5lu, flight %5lu, "
           "hs arena %6lu used %6lu; tx %5lu, record ws %5lu, other %5lu, steady arena %5lu used %5lu; "
           "header %lu; context %lu)\n",
           name, (unsigned long)fp.total, (unsigned long)fp.steady, (unsigned long)fp.handshake,
           (unsigned long)fp.hs_state, (unsigned long)fp.handshake_workspace, (unsigned long)fp.flight,
           (unsigned long)fp.hs_arena, (unsigned long)hs_peak, (unsigned long)fp.tx_record,
           (unsigned long)fp.record_workspace, (unsigned long)fp.steady_fixed_other,
           (unsigned long)fp.steady_arena, (unsigned long)steady_peak, (unsigned long)fp.header,
           (unsigned long)fp.context);
}

/** Print every profile's layout with the arena high-water marks measured here. */
static int t_footprint_report(void)
{
    st_measure_t psk_dtls;
    st_measure_t psk_tls;
    st_measure_t cert_tls;

    memset(&s_measure, 0, sizeof(s_measure));
    LB_RUN(st_scenario(LB_PROTO_DTLS13, LB_AUTH_NONE, LB_AUTH_NONE));
    psk_dtls = s_measure;
    memset(&s_measure, 0, sizeof(s_measure));
    LB_RUN(st_scenario(LB_PROTO_TLS13, LB_AUTH_NONE, LB_AUTH_NONE));
    psk_tls = s_measure;
    memset(&s_measure, 0, sizeof(s_measure));
#if ST_CERT_PROFILE
    LB_RUN(st_scenario(LB_PROTO_TLS13, LB_AUTH_RSA, LB_AUTH_RSA));
    LB_RUN(st_scenario(LB_PROTO_TLS13, LB_AUTH_ECDSA, LB_AUTH_ECDSA));
#endif
    cert_tls = s_measure;
    printf("static memory footprint (record %u, handshake workspace %u, cert DER max %u, chain depth %u)\n",
           (unsigned)NOXTLS_TLS_MAX_RECORD_SIZE, (unsigned)TLS_HANDSHAKE_WORKSPACE_SIZE,
           (unsigned)NOXTLS_STATIC_CERT_DER_MAX, (unsigned)NOXTLS_STATIC_CERT_CHAIN_DEPTH_MAX);
    st_print_profile("DTLS13_PSK c", NOXTLS_CONN_PROFILE_DTLS13_PSK, psk_dtls.hs_peak[0], psk_dtls.steady_peak[0]);
    st_print_profile("DTLS13_PSK s", NOXTLS_CONN_PROFILE_DTLS13_PSK, psk_dtls.hs_peak[1], psk_dtls.steady_peak[1]);
    st_print_profile("TLS13_PSK c", NOXTLS_CONN_PROFILE_TLS13_PSK, psk_tls.hs_peak[0], psk_tls.steady_peak[0]);
    st_print_profile("TLS13_PSK s", NOXTLS_CONN_PROFILE_TLS13_PSK, psk_tls.hs_peak[1], psk_tls.steady_peak[1]);
    st_print_profile("TLS13_CERT c", NOXTLS_CONN_PROFILE_TLS13_CERT, cert_tls.hs_peak[0], cert_tls.steady_peak[0]);
    st_print_profile("TLS13_CERT s", NOXTLS_CONN_PROFILE_TLS13_CERT, cert_tls.hs_peak[1], cert_tls.steady_peak[1]);
    printf("  global arena %lu (trust store %lu + extra %lu); sizeof(tls13_hs_state_t) %lu\n",
           (unsigned long)NOXTLS_STATIC_GLOBAL_POOL_SIZE, (unsigned long)NOXTLS_STATIC_TRUST_STORE_BYTES,
           (unsigned long)NOXTLS_STATIC_GLOBAL_EXTRA, (unsigned long)sizeof(tls13_hs_state_t));
    printf("  C library allocator hooked: %s\n", (HEAP_HOOKED != 0) ? "yes (0 calls asserted)" : "no");
    return 0;
}

static const lb_test_case_t k_cases[] = {
    { "static_dtls13_psk", t_dtls13_psk },
    { "static_tls13_psk", t_tls13_psk },
    { "static_tls13_cert_ecdsa", t_tls13_cert_ecdsa },
    { "static_tls13_cert_rsa", t_tls13_cert_rsa },
    { "static_tls13_mtls_rsa_client", t_tls13_mtls_rsa_client },
    { "static_tls13_mtls_ecdsa_client", t_tls13_mtls_ecdsa_client },
    { "static_dtls13_cert_ecdsa", t_dtls13_cert_ecdsa },
    { "static_release_timing", t_release_timing },
    { "static_application_flight_buffer", t_application_flight_buffer },
    { "static_pool_exhaustion", t_pool_exhaustion },
    { "static_peer_chain_too_deep", t_peer_chain_too_deep },
    { "static_footprint_report", t_footprint_report },
};

int main(int argc, char **argv)
{
    return lb_main(argc, argv, "static_memory", k_cases, sizeof(k_cases) / sizeof(k_cases[0]));
}
