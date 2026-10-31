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
* File:    dtls_loopback_test.c
* Summary: Certificate-based DTLS 1.2 / DTLS 1.3 handshakes over an in-memory datagram link
*****************************************************************************/
/** @file dtls_loopback_test.c
 * @brief Complements ut/dtls13_recovery (PSK, loss) with ECDSA-certificate
 * handshakes and application data in both directions.
 */
#include "lb_fixture.h"

#include <string.h>

static uint8_t s_payload[16384U];

static int run_dtls_auth(lb_proto_t proto, const uint16_t *suite, int client_auth)
{
    static const uint32_t sizes[] = { 1U, 15U, 16U, 17U, 100U, 1000U };
    lb_pair_t pair;
    lb_cfg_t cfg;
    uint32_t i;
    size_t base;

    LB_RUN((client_auth != 0) ? lb_trust_all_roots() : lb_trust_ec_root());
    base = lb_alloc_live_bytes();
    lb_cfg_default(&cfg, proto);
    if(suite != NULL) {
        cfg.server_suites = suite;
        cfg.server_suite_count = 1U;
    }
    if(client_auth != 0) {
        cfg.client_auth = 2;
        cfg.client_cert = LB_AUTH_ECDSA;
    }
    LB_RUN(lb_pair_init(&pair, &cfg));
    if(lb_pair_handshake(&pair) != 0) {
        lb_log("handshake failed: client rc=%d server rc=%d", (int)pair.client.last_rc, (int)pair.server.last_rc);
        lb_pair_free(&pair);
        return 1;
    }
    if(suite != NULL) {
        LB_CHECK_EQ(lb_end_cipher_suite(&pair.client), *suite);
    }
    for(i = 0U; i < (uint32_t)(sizeof(sizes) / sizeof(sizes[0])); i++) {
        lb_fill_pattern(s_payload, sizes[i], i);
        if(lb_transfer(&pair, 1, s_payload, sizes[i], sizes[i], sizes[i] + 64U) != 0) {
            lb_log("client->server %u bytes failed", sizes[i]);
            return 1;
        }
        lb_fill_pattern(s_payload, sizes[i], i + 100U);
        if(lb_transfer(&pair, 0, s_payload, sizes[i], sizes[i], sizes[i] + 64U) != 0) {
            lb_log("server->client %u bytes failed", sizes[i]);
            return 1;
        }
    }
    lb_pair_free(&pair);
    return lb_expect_no_leak(base, "dtls");
}

static int run_dtls(lb_proto_t proto, const uint16_t *suite)
{
    return run_dtls_auth(proto, suite, 0);
}

static int t_dtls13_ecdsa(void)
{
    return run_dtls(LB_PROTO_DTLS13, NULL);
}

static int t_dtls13_chacha20(void)
{
    static const uint16_t suite = TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256;
    return run_dtls(LB_PROTO_DTLS13, &suite);
}

static int t_dtls12_ecdsa_gcm(void)
{
    static const uint16_t suite = TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    return run_dtls(LB_PROTO_DTLS12, &suite);
}

/* DTLS 1.2 mutual TLS, SHA-384 PRF with an ecdsa_secp256r1_sha256 CertificateVerify: both
 * transcript hashes absorb the reconstructed 12-byte DTLS handshake headers. */
static int t_dtls12_mtls_sha384(void)
{
    static const uint16_t suite = TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
    return run_dtls_auth(LB_PROTO_DTLS12, &suite, 1);
}

static const lb_test_case_t k_cases[] = {
    { "dtls13_ecdsa_handshake_data", t_dtls13_ecdsa },
    { "dtls13_chacha20_handshake_data", t_dtls13_chacha20 },
    { "dtls12_ecdsa_gcm_handshake_data", t_dtls12_ecdsa_gcm },
    { "dtls12_mtls_sha384_handshake_data", t_dtls12_mtls_sha384 },
};

int main(int argc, char **argv)
{
    return lb_main(argc, argv, "dtls_loopback", k_cases, sizeof(k_cases) / sizeof(k_cases[0]));
}
