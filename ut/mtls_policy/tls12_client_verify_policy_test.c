/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Licensed under the GNU General Public License v2.0 or later,
* or alternatively under a commercial license from
* Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
*
* File:    tls12_client_verify_policy_test.c
* Summary: Explicit X.509 verification policy and TLS 1.2 mutual-auth tests
*
*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "noxtls_debug_printf.h"
#include "noxtls_memory.h"
#include "noxtls_tls12.h"
#include "noxtls_x509.h"
#include "mtls_test_pki.h"

#define CHECK(cond) do { if(!(cond)) { fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); return 1; } } while(0)

#define PIPE_CAPACITY      32768U
#define MAX_POLL_ROUNDS    4096U
/* 2026-10-05T00:00:00Z, 2001-06-01T00:00:00Z and 2051-01-01T00:00:00Z. */
#define TIME_NOW           1791158400LL
#define TIME_PAST          991353600LL
#define TIME_FUTURE        2556144000LL

typedef struct
{
    uint8_t data[PIPE_CAPACITY];
    uint32_t len;
} pipe_t;

typedef struct
{
    pipe_t *tx;
    pipe_t *rx;
} endpoint_t;

typedef struct
{
    x509_certificate_t ca;
    x509_certificate_t rogue;
    x509_certificate_t intermediate;
    x509_certificate_chain_t anchors;
    x509_certificate_chain_t rogue_anchors;
    x509_certificate_chain_t empty_anchors;
    x509_certificate_chain_t presented;
    x509_private_key_t server_key_x509;
    x509_private_key_t client_key_x509;
    ecc_key_t server_key;
    ecc_key_t client_key;
} fixture_t;

static pipe_t s_c2s;
static pipe_t s_s2c;
static fixture_t s_fx;

static int32_t pipe_send(void *user_data, const uint8_t *data, uint32_t len)
{
    endpoint_t *ep = (endpoint_t *)user_data;
    uint32_t space = PIPE_CAPACITY - ep->tx->len;
    uint32_t count = (len < space) ? len : space;

    if(count == 0U) {
        return TLS_IO_WOULD_BLOCK;
    }

    memcpy(ep->tx->data + ep->tx->len, data, count);
    ep->tx->len += count;
    return (int32_t)count;
}

static int32_t pipe_recv(void *user_data, uint8_t *data, uint32_t len)
{
    endpoint_t *ep = (endpoint_t *)user_data;
    uint32_t count = (len < ep->rx->len) ? len : ep->rx->len;

    if(count == 0U) {
        return TLS_IO_WOULD_BLOCK;
    }

    memcpy(data, ep->rx->data, count);
    memmove(ep->rx->data, ep->rx->data + count, ep->rx->len - count);
    ep->rx->len -= count;
    return (int32_t)count;
}

static int parse_cert(x509_certificate_t *cert, const uint8_t *der, uint32_t len)
{
    noxtls_x509_certificate_init(cert);
    return noxtls_x509_certificate_parse_der(cert, der, len) == NOXTLS_RETURN_SUCCESS ? 0 : 1;
}

static int load_key(x509_private_key_t *x509_key, ecc_key_t *key, const uint8_t *der, uint32_t len)
{
    noxtls_x509_private_key_init(x509_key);
    if(noxtls_x509_private_key_parse_der(x509_key, der, len) != NOXTLS_RETURN_SUCCESS) {
        return 1;
    }

    return noxtls_x509_private_key_to_ecc_key(x509_key, key) == NOXTLS_RETURN_SUCCESS ? 0 : 1;
}

static int fixture_init(void)
{
    memset(&s_fx, 0, sizeof(s_fx));
    CHECK(parse_cert(&s_fx.ca, mtls_ca_cert, sizeof(mtls_ca_cert)) == 0);
    CHECK(parse_cert(&s_fx.rogue, mtls_rogue_ca_cert, sizeof(mtls_rogue_ca_cert)) == 0);
    CHECK(parse_cert(&s_fx.intermediate, mtls_intermediate_cert, sizeof(mtls_intermediate_cert)) == 0);
    CHECK(noxtls_x509_certificate_chain_init(&s_fx.anchors) == NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_chain_init(&s_fx.rogue_anchors) == NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_chain_init(&s_fx.empty_anchors) == NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_chain_init(&s_fx.presented) == NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_chain_add(&s_fx.anchors, &s_fx.ca) == NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_chain_add(&s_fx.rogue_anchors, &s_fx.rogue) == NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_chain_add(&s_fx.presented, &s_fx.intermediate) == NOXTLS_RETURN_SUCCESS);
    CHECK(load_key(&s_fx.server_key_x509, &s_fx.server_key, mtls_server_key, sizeof(mtls_server_key)) == 0);
    CHECK(load_key(&s_fx.client_key_x509, &s_fx.client_key, mtls_client_key, sizeof(mtls_client_key)) == 0);

    /* The client verifies the server certificate against the global store. */
    CHECK(noxtls_x509_trust_store_set(&s_fx.anchors) == NOXTLS_RETURN_SUCCESS);
    return 0;
}

static void policy_default(noxtls_x509_verify_policy_t *policy, const x509_certificate_chain_t *anchors)
{
    memset(policy, 0, sizeof(*policy));
    policy->trust_anchors = anchors;
    policy->required_eku = X509_EKU_CLIENT_AUTH;
    policy->required_key_usage = X509_KEY_USAGE_DIGITAL_SIGNATURE;
    policy->time_mode = NOXTLS_X509_TIME_EXPLICIT;
    policy->verify_time = TIME_NOW;
}

static noxtls_return_t verify_der(const uint8_t *der, uint32_t len, const x509_certificate_chain_t *presented,
                                  const noxtls_x509_verify_policy_t *policy)
{
    x509_certificate_t leaf;
    noxtls_return_t rc;

    if(parse_cert(&leaf, der, len) != 0) {
        return NOXTLS_RETURN_CERT_PARSE_FAILED;
    }

    rc = noxtls_x509_verify_cert_with_policy(&leaf, presented, policy, NULL);
    noxtls_x509_certificate_free(&leaf);
    return rc;
}

static int test_x509_policy(void)
{
    noxtls_x509_verify_policy_t policy;
    noxtls_x509_verify_flags_t flags = 1U;
    x509_certificate_t leaf;

    policy_default(&policy, &s_fx.anchors);
    CHECK(verify_der(mtls_client_cert, sizeof(mtls_client_cert), &s_fx.presented, &policy) ==
          NOXTLS_RETURN_SUCCESS);
    CHECK(verify_der(mtls_client_direct_cert, sizeof(mtls_client_direct_cert), NULL, &policy) ==
          NOXTLS_RETURN_SUCCESS);

    /* Missing intermediate, wrong anchor, empty anchors. */
    CHECK(verify_der(mtls_client_cert, sizeof(mtls_client_cert), NULL, &policy) ==
          NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
    CHECK(verify_der(mtls_client_rogue_cert, sizeof(mtls_client_rogue_cert), NULL, &policy) ==
          NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
    policy_default(&policy, &s_fx.rogue_anchors);
    CHECK(verify_der(mtls_client_direct_cert, sizeof(mtls_client_direct_cert), NULL, &policy) ==
          NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
    policy_default(&policy, &s_fx.empty_anchors);
    CHECK(verify_der(mtls_client_direct_cert, sizeof(mtls_client_direct_cert), NULL, &policy) ==
          NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
    policy_default(&policy, NULL);
    CHECK(verify_der(mtls_client_direct_cert, sizeof(mtls_client_direct_cert), NULL, &policy) ==
          NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);

    /* Validity windows with an explicit clock. */
    policy_default(&policy, &s_fx.anchors);
    CHECK(verify_der(mtls_client_expired_cert, sizeof(mtls_client_expired_cert), NULL, &policy) ==
          NOXTLS_RETURN_CERT_EXPIRED);
    policy.verify_time = TIME_PAST;
    CHECK(verify_der(mtls_client_expired_cert, sizeof(mtls_client_expired_cert), NULL, &policy) ==
          NOXTLS_RETURN_CERT_NOT_YET_VALID);
    policy.verify_time = TIME_FUTURE;
    CHECK(verify_der(mtls_client_direct_cert, sizeof(mtls_client_direct_cert), NULL, &policy) ==
          NOXTLS_RETURN_CERT_EXPIRED);
    policy.verify_time = -1;
    CHECK(verify_der(mtls_client_direct_cert, sizeof(mtls_client_direct_cert), NULL, &policy) ==
          NOXTLS_RETURN_INVALID_PARAM);
    policy.verify_time = TIME_NOW;
    policy.time_mode = (noxtls_x509_time_mode_t)7;
    CHECK(verify_der(mtls_client_direct_cert, sizeof(mtls_client_direct_cert), NULL, &policy) ==
          NOXTLS_RETURN_INVALID_PARAM);
    policy.time_mode = NOXTLS_X509_TIME_SYSTEM;
    CHECK(verify_der(mtls_client_direct_cert, sizeof(mtls_client_direct_cert), NULL, &policy) ==
          NOXTLS_RETURN_SUCCESS);

    /* Key usage and extended key usage. */
    policy_default(&policy, &s_fx.anchors);
    CHECK(verify_der(mtls_client_key_agreement_cert, sizeof(mtls_client_key_agreement_cert), NULL, &policy) ==
          NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
    policy.required_key_usage = 0U;
    CHECK(verify_der(mtls_client_key_agreement_cert, sizeof(mtls_client_key_agreement_cert), NULL, &policy) ==
          NOXTLS_RETURN_SUCCESS);
    policy.required_eku = X509_EKU_SERVER_AUTH;
    CHECK(verify_der(mtls_client_key_agreement_cert, sizeof(mtls_client_key_agreement_cert), NULL, &policy) ==
          NOXTLS_RETURN_SUCCESS);
    policy.required_eku = 0U;
    CHECK(verify_der(mtls_client_key_agreement_cert, sizeof(mtls_client_key_agreement_cert), NULL, &policy) ==
          NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
    policy_default(&policy, &s_fx.anchors);
    CHECK(verify_der(mtls_client_server_eku_cert, sizeof(mtls_client_server_eku_cert), NULL, &policy) ==
          NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
    policy.required_eku = 0U;
    CHECK(verify_der(mtls_client_server_eku_cert, sizeof(mtls_client_server_eku_cert), NULL, &policy) ==
          NOXTLS_RETURN_SUCCESS);
    policy_default(&policy, &s_fx.anchors);
    CHECK(verify_der(mtls_client_no_ku_cert, sizeof(mtls_client_no_ku_cert), NULL, &policy) ==
          NOXTLS_RETURN_SUCCESS);
    policy.require_key_usage_extension = 1U;
    CHECK(verify_der(mtls_client_no_ku_cert, sizeof(mtls_client_no_ku_cert), NULL, &policy) ==
          NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);

    /* A CA certificate is never accepted as a leaf. */
    policy_default(&policy, &s_fx.anchors);
    CHECK(verify_der(mtls_intermediate_cert, sizeof(mtls_intermediate_cert), NULL, &policy) ==
          NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);

    /* Argument checks. */
    CHECK(parse_cert(&leaf, mtls_client_direct_cert, sizeof(mtls_client_direct_cert)) == 0);
    CHECK(noxtls_x509_verify_cert_with_policy(&leaf, NULL, NULL, &flags) == NOXTLS_RETURN_NULL);
    CHECK(flags == 0U);
    CHECK(noxtls_x509_verify_cert_with_policy(NULL, NULL, &policy, NULL) == NOXTLS_RETURN_NULL);
    CHECK(noxtls_x509_certificate_check_validity_at(&leaf, TIME_NOW) == NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_check_validity_at(NULL, TIME_NOW) == NOXTLS_RETURN_NULL);
    noxtls_x509_certificate_free(&leaf);
    noxtls_x509_certificate_init(&leaf);
    CHECK(noxtls_x509_certificate_check_validity_at(&leaf, TIME_NOW) == NOXTLS_RETURN_FAILED);
    return 0;
}

typedef struct
{
    tls12_context_t server;
    tls12_context_t client;
    endpoint_t server_ep;
    endpoint_t client_ep;
    noxtls_return_t server_rc;
    noxtls_return_t client_rc;
} session_t;

static session_t s_session;

static int session_setup(session_t *session, const uint8_t *client_cert, uint32_t client_cert_len,
                         const noxtls_x509_verify_policy_t *policy)
{
    static const uint16_t suites[] = { TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 };

    memset(session, 0, sizeof(*session));
    memset(&s_c2s, 0, sizeof(s_c2s));
    memset(&s_s2c, 0, sizeof(s_s2c));
    session->server_ep.tx = &s_s2c;
    session->server_ep.rx = &s_c2s;
    session->client_ep.tx = &s_c2s;
    session->client_ep.rx = &s_s2c;
    CHECK(noxtls_tls12_context_init(&session->server, TLS_ROLE_SERVER) == NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_tls12_context_init(&session->client, TLS_ROLE_CLIENT) == NOXTLS_RETURN_SUCCESS);
    session->server.server_cert = (uint8_t *)mtls_server_cert;
    session->server.server_cert_len = (uint32_t)sizeof(mtls_server_cert);
    noxtls_tls12_set_server_private_ecdsa(&session->server, &s_fx.server_key);
    noxtls_tls12_set_server_ecdsa_leaf_certificate(&session->server, mtls_server_cert,
                                                   (uint32_t)sizeof(mtls_server_cert));
    noxtls_tls12_set_server_cipher_suites(&session->server, suites, 1U);
    noxtls_tls12_require_client_auth(&session->server, 1);
    noxtls_tls12_set_client_verify_policy(&session->server, policy);
    CHECK(noxtls_tls_set_io_callbacks(&session->server.base.base, pipe_send, pipe_recv,
                                      &session->server_ep) == NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_tls_set_io_callbacks(&session->client.base.base, pipe_send, pipe_recv,
                                      &session->client_ep) == NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_tls_set_io_mode(&session->server.base.base, TLS_IO_MODE_NON_BLOCKING) == NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_tls_set_io_mode(&session->client.base.base, TLS_IO_MODE_NON_BLOCKING) == NOXTLS_RETURN_SUCCESS);
    if(client_cert != NULL) {
        CHECK(noxtls_tls12_set_client_cert_ecdsa(&session->client, client_cert, client_cert_len,
                                                 &s_fx.client_key) == NOXTLS_RETURN_SUCCESS);
    }

    return 0;
}

static int is_zero(const uint8_t *data, size_t len)
{
    size_t i;
    uint8_t acc = 0U;

    for(i = 0U; i < len; i++) {
        acc |= data[i];
    }

    return acc == 0U;
}

static int is_progress(noxtls_return_t rc)
{
    return (rc == NOXTLS_RETURN_WANT_READ) || (rc == NOXTLS_RETURN_WANT_WRITE);
}

static void session_handshake(session_t *session)
{
    uint32_t round;
    int client_done = 0;
    int server_done = 0;

    session->client_rc = NOXTLS_RETURN_WANT_READ;
    session->server_rc = NOXTLS_RETURN_WANT_READ;
    for(round = 0U; round < MAX_POLL_ROUNDS; round++) {
        if((client_done == 0) && is_progress(session->client_rc)) {
            session->client_rc = noxtls_tls12_connect_poll(&session->client);
            client_done = (session->client_rc == NOXTLS_RETURN_SUCCESS) ? 1 : 0;
        }

        (void)noxtls_tls_flush(&session->client.base.base);
        if((server_done == 0) && is_progress(session->server_rc)) {
            session->server_rc = noxtls_tls12_accept_poll(&session->server);
            server_done = (session->server_rc == NOXTLS_RETURN_SUCCESS) ? 1 : 0;
        }

        (void)noxtls_tls_flush(&session->server.base.base);
        if(((client_done != 0) || !is_progress(session->client_rc)) &&
           ((server_done != 0) || !is_progress(session->server_rc))) {
            break;
        }

        if(!is_progress(session->client_rc) && !is_progress(session->server_rc)) {
            break;
        }
    }
}

static void session_free(session_t *session)
{
    session->server.server_cert = NULL;
    (void)noxtls_tls12_context_free(&session->server);
    (void)noxtls_tls12_context_free(&session->client);
}

static int test_tls12_mutual_auth(void)
{
    noxtls_x509_verify_policy_t policy;
    static const uint8_t ping[] = { 0x0A, 0x02, 'h', 'i' };
    uint8_t buffer[64];
    uint32_t len = sizeof(buffer);
    const uint8_t *der = NULL;
    uint32_t der_len = 0U;
    const void *parsed = NULL;
    uint32_t round;
    noxtls_return_t rc = NOXTLS_RETURN_WANT_READ;

    policy_default(&policy, &s_fx.anchors);
    CHECK(session_setup(&s_session, mtls_client_direct_cert, sizeof(mtls_client_direct_cert), &policy) == 0);
    CHECK(noxtls_tls12_get_client_certificate(&s_session.server, &der, &der_len, &parsed) ==
          NOXTLS_RETURN_FAILED);
    session_handshake(&s_session);
    if((s_session.client_rc != NOXTLS_RETURN_SUCCESS) || (s_session.server_rc != NOXTLS_RETURN_SUCCESS)) {
        fprintf(stderr, "handshake: client_rc=%d server_rc=%d\n", (int)s_session.client_rc,
                (int)s_session.server_rc);
    }

    CHECK(s_session.client_rc == NOXTLS_RETURN_SUCCESS);
    CHECK(s_session.server_rc == NOXTLS_RETURN_SUCCESS);
    CHECK(s_session.server.cipher_suite == TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    CHECK(noxtls_tls12_get_client_certificate(&s_session.server, &der, &der_len, &parsed) ==
          NOXTLS_RETURN_SUCCESS);
    CHECK((der_len == sizeof(mtls_client_direct_cert)) && (memcmp(der, mtls_client_direct_cert, der_len) == 0));
    CHECK(parsed != NULL);
    CHECK(noxtls_tls12_get_client_certificate(&s_session.server, &der, &der_len, NULL) == NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_tls12_get_client_certificate(&s_session.client, &der, &der_len, NULL) == NOXTLS_RETURN_FAILED);
    CHECK(noxtls_tls12_get_client_certificate(NULL, &der, &der_len, NULL) == NOXTLS_RETURN_NULL);
    CHECK(noxtls_tls12_get_client_certificate(&s_session.server, NULL, &der_len, NULL) == NOXTLS_RETURN_NULL);

    CHECK(noxtls_tls12_send(&s_session.client, ping, sizeof(ping)) == NOXTLS_RETURN_SUCCESS);
    (void)noxtls_tls_flush(&s_session.client.base.base);
    for(round = 0U; (round < 8U) && (rc == NOXTLS_RETURN_WANT_READ); round++) {
        len = sizeof(buffer);
        rc = noxtls_tls12_recv(&s_session.server, buffer, &len);
    }

    CHECK(rc == NOXTLS_RETURN_SUCCESS);
    CHECK((len == sizeof(ping)) && (memcmp(buffer, ping, sizeof(ping)) == 0));
    session_free(&s_session);
    CHECK(is_zero(s_session.server.master_secret, sizeof(s_session.server.master_secret)));
    CHECK(is_zero(s_session.server.server_write_key, sizeof(s_session.server.server_write_key)));
    CHECK(is_zero(s_session.client.client_write_key, sizeof(s_session.client.client_write_key)));
    CHECK(is_zero(s_session.client.client_write_iv, sizeof(s_session.client.client_write_iv)));
    CHECK(noxtls_tls12_context_size() == (uint32_t)sizeof(tls12_context_t));

    /* A policy-bound server never resumes: the client must authenticate again. */
    CHECK(session_setup(&s_session, mtls_client_direct_cert, sizeof(mtls_client_direct_cert), &policy) == 0);
    session_handshake(&s_session);
    CHECK((s_session.client_rc == NOXTLS_RETURN_SUCCESS) && (s_session.server_rc == NOXTLS_RETURN_SUCCESS));
    CHECK(s_session.server.session_resume == 0U);
    CHECK(noxtls_tls12_get_client_certificate(&s_session.server, &der, &der_len, NULL) == NOXTLS_RETURN_SUCCESS);
    session_free(&s_session);
    return 0;
}

static int expect_rejected(const uint8_t *cert, uint32_t cert_len, const noxtls_x509_verify_policy_t *policy)
{
    const uint8_t *der = NULL;
    uint32_t der_len = 0U;

    CHECK(session_setup(&s_session, cert, cert_len, policy) == 0);
    session_handshake(&s_session);
    CHECK(s_session.server_rc != NOXTLS_RETURN_SUCCESS);
    CHECK(!is_progress(s_session.server_rc));
    CHECK(s_session.client_rc != NOXTLS_RETURN_SUCCESS);
    CHECK(s_session.server.base.base.state != TLS_STATE_CONNECTED);
    CHECK(noxtls_tls12_get_client_certificate(&s_session.server, &der, &der_len, NULL) == NOXTLS_RETURN_FAILED);
    session_free(&s_session);
    return 0;
}

static int test_tls12_rejections(void)
{
    noxtls_x509_verify_policy_t policy;
    noxtls_x509_verify_policy_t empty_policy;

    policy_default(&policy, &s_fx.anchors);
    CHECK(expect_rejected(NULL, 0U, &policy) == 0);
    CHECK(s_session.server_rc == NOXTLS_RETURN_CERT_REQUIRED);
    CHECK(expect_rejected(mtls_client_rogue_cert, sizeof(mtls_client_rogue_cert), &policy) == 0);
    CHECK(expect_rejected(mtls_client_expired_cert, sizeof(mtls_client_expired_cert), &policy) == 0);
    CHECK(expect_rejected(mtls_client_key_agreement_cert, sizeof(mtls_client_key_agreement_cert), &policy) == 0);
    CHECK(expect_rejected(mtls_client_server_eku_cert, sizeof(mtls_client_server_eku_cert), &policy) == 0);

    /* The explicit policy never falls back to the populated global store. */
    policy_default(&empty_policy, &s_fx.empty_anchors);
    CHECK(noxtls_x509_trust_store_has_anchors() == 1);
    CHECK(expect_rejected(mtls_client_direct_cert, sizeof(mtls_client_direct_cert), &empty_policy) == 0);
    return 0;
}

int main(void)
{
    int rc;

    if(getenv("MTLS_DEBUG") != NULL) {
        noxtls_debug_set_level(2U);
    }

    rc = fixture_init();
    if(rc != 0) {
        return 10 + rc;
    }

    rc = test_x509_policy();
    if(rc != 0) {
        return 20 + rc;
    }

    rc = test_tls12_mutual_auth();
    if(rc != 0) {
        return 30 + rc;
    }

    rc = test_tls12_rejections();
    if(rc != 0) {
        return 40 + rc;
    }

    noxtls_x509_trust_store_clear();
    printf("tls12_client_verify_policy_test: all tests passed\n");
    return 0;
}
