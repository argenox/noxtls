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
* File:    heap_footprint_test.c
* Summary: Heap-mode reference for the static memory footprint report
*****************************************************************************/
/** @file heap_footprint_test.c
 * @brief Heap high-water mark and steady state of the static-memory scenarios.
 *
 * Heap builds only. Runs the same handshakes as ut/static_memory/static_memory_test.c
 * with the plain context init functions and prints, per endpoint, the heap peak of
 * initialization plus handshake, the heap still held after the handshake and a data
 * exchange, and the caller-owned context size, so that a static-memory build of the
 * same configuration can be compared with it (docs/static-memory.md).
 */
#include "lb_fixture.h"

#include <stdlib.h>
#include <string.h>

static uint8_t s_payload[1000];

/** With LB_TRACE_ALL=1, mark the phase of the allocation trace (audit tooling). */
static void hf_phase(const char *name, const char *phase)
{
    if(getenv("LB_TRACE_ALL") != NULL) {
        fprintf(stderr, "lb_phase %s %s\n", name, phase);
    }
}
static const uint8_t k_psk_identity[] = "static-memory-test";
static const uint8_t k_psk_key[] = "0123456789abcdef0123456789abcdef";

static int hf_run(const char *name, lb_proto_t proto, lb_auth_t auth, lb_auth_t client_cert)
{
    static const uint16_t group = TLS_NAMED_GROUP_X25519;
    static const uint16_t suite = TLS_CIPHER_SUITE_AES_128_GCM_SHA256;
    lb_pair_t pair;
    lb_cfg_t cfg;
    lb_alloc_owner_stats_t peak[2];
    lb_alloc_owner_stats_t steady[2];
    unsigned i;

    if(auth != LB_AUTH_NONE) {
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
    lb_alloc_reset_peak();
    hf_phase(name, "init");
    LB_RUN(lb_pair_init(&pair, &cfg));
    if(auth == LB_AUTH_NONE) {
        LB_CHECK_OK(tls13_set_external_psk(pair.client.t13, k_psk_identity, sizeof(k_psk_identity) - 1U,
                                           k_psk_key, sizeof(k_psk_key) - 1U, TLS13_PSK_KE_MODE_PSK_DHE_KE));
        LB_CHECK_OK(tls13_set_external_psk(pair.server.t13, k_psk_identity, sizeof(k_psk_identity) - 1U,
                                           k_psk_key, sizeof(k_psk_key) - 1U, TLS13_PSK_KE_MODE_PSK_DHE_KE));
        noxtls_tls13_set_client_supported_groups(pair.client.t13, &group, 1U);
        noxtls_tls13_set_server_cipher_suites(pair.server.t13, &suite, 1U);
    }
#if NOXTLS_TLS_MAX_RECORD_SIZE < DTLS_MAX_FRAGMENT_SIZE
    if(proto == LB_PROTO_DTLS13) {
        LB_CHECK_OK(noxtls_dtls_set_mtu(&pair.client.t13->base, (uint16_t)NOXTLS_TLS_MAX_RECORD_SIZE));
        LB_CHECK_OK(noxtls_dtls_set_mtu(&pair.server.t13->base, (uint16_t)NOXTLS_TLS_MAX_RECORD_SIZE));
    }
#endif
    hf_phase(name, "handshake");
    LB_RUN(lb_pair_handshake(&pair));
    hf_phase(name, "connected");
    lb_fill_pattern(s_payload, sizeof(s_payload), 1U);
    LB_RUN(lb_transfer(&pair, 1, s_payload, sizeof(s_payload), 400U, sizeof(s_payload)));
    LB_RUN(lb_transfer(&pair, 0, s_payload, sizeof(s_payload), 400U, sizeof(s_payload)));
    for(i = 0U; i < 2U; i++) {
        lb_alloc_get_owner_stats((i == 0U) ? LB_OWNER_CLIENT : LB_OWNER_SERVER, &peak[i]);
    }
    LB_RUN(lb_transfer(&pair, 1, s_payload, sizeof(s_payload), 400U, sizeof(s_payload)));
    for(i = 0U; i < 2U; i++) {
        lb_alloc_get_owner_stats((i == 0U) ? LB_OWNER_CLIENT : LB_OWNER_SERVER, &steady[i]);
    }
    hf_phase(name, "free");
    printf("  %-18s client heap peak %6lu steady %6lu | server heap peak %6lu steady %6lu | context %lu\n",
           name, (unsigned long)peak[0].peak_bytes, (unsigned long)steady[0].live_bytes,
           (unsigned long)peak[1].peak_bytes, (unsigned long)steady[1].live_bytes,
           (unsigned long)sizeof(tls13_context_t));
    lb_pair_free(&pair);
    lb_trust_clear();
    hf_phase(name, "end");
    return 0;
}

static int t_heap_footprint_report(void)
{
    size_t base = lb_alloc_live_bytes();
    printf("heap footprint (record %u, handshake workspace %u)\n", (unsigned)NOXTLS_TLS_MAX_RECORD_SIZE,
           (unsigned)TLS_HANDSHAKE_WORKSPACE_SIZE);
    LB_RUN(hf_run("DTLS13_PSK", LB_PROTO_DTLS13, LB_AUTH_NONE, LB_AUTH_NONE));
    LB_RUN(hf_run("TLS13_PSK", LB_PROTO_TLS13, LB_AUTH_NONE, LB_AUTH_NONE));
    if(lb_ec_root_cert_len <= (uint32_t)NOXTLS_MAX_CERT_SIZE) {
        LB_RUN(hf_run("TLS13_CERT_ecdsa", LB_PROTO_TLS13, LB_AUTH_ECDSA, LB_AUTH_ECDSA));
        LB_RUN(hf_run("TLS13_CERT_rsa", LB_PROTO_TLS13, LB_AUTH_RSA, LB_AUTH_RSA));
    }
    return lb_expect_no_leak(base, "heap footprint");
}

static const lb_test_case_t k_cases[] = {
    { "heap_footprint_report", t_heap_footprint_report },
};

int main(int argc, char **argv)
{
    return lb_main(argc, argv, "heap_footprint", k_cases, sizeof(k_cases) / sizeof(k_cases[0]));
}
