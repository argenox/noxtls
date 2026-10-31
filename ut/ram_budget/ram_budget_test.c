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
* File:    ram_budget_test.c
* Summary: Heap / structure-size budget gate for TLS 1.3 and TLS 1.2 connections
*****************************************************************************/
/** @file ram_budget_test.c
 * @brief Runs a full TLS 1.3 and TLS 1.2 handshake plus a 16 KB exchange in each
 * direction over the in-memory loopback link and reports, per endpoint:
 *   - live heap after context init,
 *   - heap peak and allocation count during the handshake,
 *   - live heap after the handshake and after the exchange (steady state),
 *   - heap peak during the exchange,
 * plus the trust-store snapshot and sizeof of the main structures.
 *
 * Heap numbers come from lb_alloc.c (the accounting allocator that replaces
 * noxtls_memory.c in this executable): requested payload bytes, attributed to
 * the endpoint on whose behalf the library was called. "pool" columns add the
 * static-pool block header (32 B) and 8-byte rounding per live block.
 * Host build (64-bit pointers): use the ARM measurement tool for target sizes.
 *
 * Each metric has a budget NOXTLS_RAM_BUDGET_<METRIC> (CMake cache variable of
 * the same name, passed as a compile definition). The test fails only when a
 * measured value exceeds its budget; budget 0 disables that check.
 */
#include "lb_fixture.h"

#include <string.h>

#include "mac/noxtls_hmac.h"
#include "mdigest/noxtls_sha.h"
#include "encryption/aes/noxtls_aes.h"

/* X-macro list of gated metrics: name, CMake/compile-definition suffix. */
#define RAM_METRICS(X) \
    X(SIZEOF_TLS13_CONTEXT) \
    X(SIZEOF_TLS12_CONTEXT) \
    X(SIZEOF_TLS_CONNECTION) \
    X(SIZEOF_X509_CERTIFICATE) \
    X(TRUST_STORE_1_ANCHOR) \
    X(TLS13_CLIENT_INIT_LIVE) \
    X(TLS13_CLIENT_HS_PEAK) \
    X(TLS13_CLIENT_HS_ALLOCS) \
    X(TLS13_CLIENT_STEADY) \
    X(TLS13_CLIENT_DATA_PEAK) \
    X(TLS13_SERVER_INIT_LIVE) \
    X(TLS13_SERVER_HS_PEAK) \
    X(TLS13_SERVER_HS_ALLOCS) \
    X(TLS13_SERVER_STEADY) \
    X(TLS13_SERVER_DATA_PEAK) \
    X(TLS13_TOTAL_POOL_PEAK) \
    X(TLS12_CLIENT_INIT_LIVE) \
    X(TLS12_CLIENT_HS_PEAK) \
    X(TLS12_CLIENT_HS_ALLOCS) \
    X(TLS12_CLIENT_STEADY) \
    X(TLS12_CLIENT_DATA_PEAK) \
    X(TLS12_SERVER_INIT_LIVE) \
    X(TLS12_SERVER_HS_PEAK) \
    X(TLS12_SERVER_HS_ALLOCS) \
    X(TLS12_SERVER_STEADY) \
    X(TLS12_SERVER_DATA_PEAK) \
    X(TLS12_TOTAL_POOL_PEAK) \
    X(TLS12_MTLS_CLIENT_HS_PEAK) \
    X(TLS12_MTLS_SERVER_HS_PEAK)

/* ut/ram_budget/CMakeLists.txt defines every NOXTLS_RAM_BUDGET_<metric> (0 = unchecked). */
#ifndef NOXTLS_RAM_BUDGET_TLS13_CLIENT_HS_PEAK
#error "Build through ut/ram_budget/CMakeLists.txt: it defines the NOXTLS_RAM_BUDGET_* budgets"
#endif

typedef enum
{
#define X_ENUM(name) M_##name,
    RAM_METRICS(X_ENUM)
#undef X_ENUM
    M_COUNT
} metric_id_t;

static const char *const k_metric_names[M_COUNT] = {
#define X_NAME(name) #name,
    RAM_METRICS(X_NAME)
#undef X_NAME
};

static const size_t k_budget[M_COUNT] = {
#define X_BUDGET(name) (size_t)(NOXTLS_RAM_BUDGET_##name),
    RAM_METRICS(X_BUDGET)
#undef X_BUDGET
};

static size_t s_value[M_COUNT];
static int s_have[M_COUNT];

static void put(metric_id_t id, size_t value)
{
    s_value[id] = value;
    s_have[id] = 1;
}

static size_t owner_live(unsigned owner)
{
    lb_alloc_owner_stats_t st;
    lb_alloc_get_owner_stats(owner, &st);
    return st.live_bytes;
}

static size_t owner_peak(unsigned owner)
{
    lb_alloc_owner_stats_t st;
    lb_alloc_get_owner_stats(owner, &st);
    return st.peak_bytes;
}

static size_t owner_allocs(unsigned owner)
{
    lb_alloc_owner_stats_t st;
    lb_alloc_get_owner_stats(owner, &st);
    return st.alloc_calls;
}

static uint8_t s_data[TLS_MAX_RECORD_SIZE]; /* one maximal record */

/** One connection: init, handshake, 16 KB each way; fills the metrics of that protocol. */
static int measure(lb_proto_t proto, metric_id_t first)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    lb_alloc_stats_t total;
    static const uint16_t suite13 = TLS_CIPHER_SUITE_AES_128_GCM_SHA256;
    static const uint16_t suite12 = TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    static const uint16_t group = TLS_NAMED_GROUP_X25519;
    /* Metric order within a protocol block mirrors RAM_METRICS. */
    const metric_id_t c_init = first;
    const metric_id_t c_hs_peak = (metric_id_t)(first + 1);
    const metric_id_t c_hs_allocs = (metric_id_t)(first + 2);
    const metric_id_t c_steady = (metric_id_t)(first + 3);
    const metric_id_t c_data_peak = (metric_id_t)(first + 4);
    const metric_id_t s_init = (metric_id_t)(first + 5);
    const metric_id_t s_hs_peak = (metric_id_t)(first + 6);
    const metric_id_t s_hs_allocs = (metric_id_t)(first + 7);
    const metric_id_t s_steady = (metric_id_t)(first + 8);
    const metric_id_t s_data_peak = (metric_id_t)(first + 9);
    const metric_id_t pool_peak = (metric_id_t)(first + 10);
    size_t c_base;
    size_t s_base;
    size_t c_after_hs;
    size_t s_after_hs;

    lb_cfg_default(&cfg, proto);
    cfg.server_suites = (proto == LB_PROTO_TLS13) ? &suite13 : &suite12;
    cfg.server_suite_count = 1U;
    cfg.client_groups = &group;
    cfg.client_group_count = 1U;

    lb_alloc_reset_peak();
    c_base = owner_live(LB_OWNER_CLIENT);
    s_base = owner_live(LB_OWNER_SERVER);
    LB_RUN(lb_pair_init(&pair, &cfg));
    put(c_init, owner_live(LB_OWNER_CLIENT) - c_base);
    put(s_init, owner_live(LB_OWNER_SERVER) - s_base);

    lb_alloc_reset_peak();
    lb_alloc_reset_counters();
    LB_RUN(lb_pair_handshake(&pair));
    put(c_hs_peak, owner_peak(LB_OWNER_CLIENT) - c_base);
    put(s_hs_peak, owner_peak(LB_OWNER_SERVER) - s_base);
    put(c_hs_allocs, owner_allocs(LB_OWNER_CLIENT));
    put(s_hs_allocs, owner_allocs(LB_OWNER_SERVER));
    c_after_hs = owner_live(LB_OWNER_CLIENT) - c_base;
    s_after_hs = owner_live(LB_OWNER_SERVER) - s_base;

    lb_alloc_reset_peak();
    lb_fill_pattern(s_data, sizeof(s_data), 16U);
    LB_RUN(lb_transfer(&pair, 1, s_data, sizeof(s_data), sizeof(s_data), sizeof(s_data)));
    LB_RUN(lb_transfer(&pair, 0, s_data, sizeof(s_data), sizeof(s_data), sizeof(s_data)));
    put(c_data_peak, owner_peak(LB_OWNER_CLIENT) - c_base);
    put(s_data_peak, owner_peak(LB_OWNER_SERVER) - s_base);
    put(c_steady, owner_live(LB_OWNER_CLIENT) - c_base);
    put(s_steady, owner_live(LB_OWNER_SERVER) - s_base);
    lb_alloc_get_stats(&total);
    put(pool_peak, total.pool_peak_bytes);

    printf("  %s: client live after handshake %lu B, server %lu B\n",
           (proto == LB_PROTO_TLS13) ? "TLS 1.3" : "TLS 1.2", (unsigned long)c_after_hs,
           (unsigned long)s_after_hs);
    LB_RUN(lb_close_and_observe(&pair, 1));
    lb_pair_free(&pair);
    LB_CHECK_EQ(owner_live(LB_OWNER_CLIENT), c_base);
    LB_CHECK_EQ(owner_live(LB_OWNER_SERVER), s_base);
    return 0;
}

/**
 * TLS 1.2 mutual TLS with a SHA-384 PRF suite and an ecdsa_secp256r1_sha256 client
 * CertificateVerify: both ends hold two transcript hash states for part of the handshake.
 */
static int measure_tls12_mtls(void)
{
    lb_pair_t pair;
    lb_cfg_t cfg;
    static const uint16_t suite12 = TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
    size_t c_base;
    size_t s_base;

    lb_cfg_default(&cfg, LB_PROTO_TLS12);
    cfg.server_suites = &suite12;
    cfg.server_suite_count = 1U;
    cfg.client_auth = 2;
    cfg.client_cert = LB_AUTH_ECDSA;

    c_base = owner_live(LB_OWNER_CLIENT);
    s_base = owner_live(LB_OWNER_SERVER);
    LB_RUN(lb_pair_init(&pair, &cfg));
    lb_alloc_reset_peak();
    LB_RUN(lb_pair_handshake(&pair));
    put(M_TLS12_MTLS_CLIENT_HS_PEAK, owner_peak(LB_OWNER_CLIENT) - c_base);
    put(M_TLS12_MTLS_SERVER_HS_PEAK, owner_peak(LB_OWNER_SERVER) - s_base);
    LB_RUN(lb_close_and_observe(&pair, 1));
    lb_pair_free(&pair);
    LB_CHECK_EQ(owner_live(LB_OWNER_CLIENT), c_base);
    LB_CHECK_EQ(owner_live(LB_OWNER_SERVER), s_base);
    return 0;
}

static int report(void)
{
    uint32_t i;
    int over = 0;
    printf("\n%-28s %12s %12s  %s\n", "metric", "measured", "budget", "status");
    printf("%-28s %12s %12s  %s\n", "----------------------------", "------------", "------------", "------");
    for(i = 0U; i < (uint32_t)M_COUNT; i++) {
        const char *status = "ok";
        if(s_have[i] == 0) {
            status = "n/a";
        } else if(k_budget[i] == 0U) {
            status = "unchecked";
        } else if(s_value[i] > k_budget[i]) {
            status = "OVER BUDGET";
            over = 1;
        } else {
            /* within budget */
        }
        printf("%-28s %12lu %12lu  %s\n", k_metric_names[i], (unsigned long)s_value[i],
               (unsigned long)k_budget[i], status);
    }
    printf("\nInformational sizeof (host): tls_context_t=%lu dtls_context_t=%lu tls_ecdhe_context_t=%lu\n",
           (unsigned long)sizeof(tls_context_t), (unsigned long)sizeof(dtls_context_t),
           (unsigned long)sizeof(tls_ecdhe_context_t));
    printf("  x509_certificate_chain_t=%lu noxtls_x509_crl_t=%lu x509_private_key_t=%lu ecc_key_t=%lu rsa_key_t=%lu\n",
           (unsigned long)sizeof(x509_certificate_chain_t), (unsigned long)sizeof(noxtls_x509_crl_t),
           (unsigned long)sizeof(x509_private_key_t), (unsigned long)sizeof(ecc_key_t),
           (unsigned long)sizeof(rsa_key_t));
    printf("  noxtls_sha_ctx_t=%lu noxtls_hmac_context_t=%lu noxtls_aes_context_t=%lu\n",
           (unsigned long)sizeof(noxtls_sha_ctx_t), (unsigned long)sizeof(noxtls_hmac_context_t),
           (unsigned long)sizeof(noxtls_aes_context_t));
    printf("  TLS_MAX_RECORD_SIZE=%u NOXTLS_MAX_CERT_SIZE=%u\n", (unsigned)TLS_MAX_RECORD_SIZE,
           (unsigned)NOXTLS_MAX_CERT_SIZE);
    if(over != 0) {
        fprintf(stderr, "ram_budget: at least one metric exceeds its budget (see table)\n");
        return 1;
    }
    return 0;
}

static int t_ram_budget(void)
{
    size_t g_base;

    put(M_SIZEOF_TLS13_CONTEXT, sizeof(tls13_context_t));
    put(M_SIZEOF_TLS12_CONTEXT, sizeof(tls12_context_t));
    put(M_SIZEOF_TLS_CONNECTION, sizeof(noxtls_tls_connection_t));
    put(M_SIZEOF_X509_CERTIFICATE, sizeof(x509_certificate_t));

    g_base = owner_live(LB_OWNER_GLOBAL);
    LB_RUN(lb_trust_ec_root());
    put(M_TRUST_STORE_1_ANCHOR, owner_live(LB_OWNER_GLOBAL) - g_base);
#if NOXTLS_FEATURE_TLS13
    LB_RUN(measure(LB_PROTO_TLS13, M_TLS13_CLIENT_INIT_LIVE));
#endif
#if NOXTLS_FEATURE_TLS12
    LB_RUN(measure(LB_PROTO_TLS12, M_TLS12_CLIENT_INIT_LIVE));
    lb_trust_clear();
    LB_RUN(lb_trust_all_roots());
    LB_RUN(measure_tls12_mtls());
#endif
    lb_trust_clear();
    return report();
}

static const lb_test_case_t k_cases[] = {
    { "ram_budget", t_ram_budget },
};

int main(int argc, char **argv)
{
    return lb_main(argc, argv, "ram_budget", k_cases, sizeof(k_cases) / sizeof(k_cases[0]));
}
