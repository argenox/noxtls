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
* File:    tls13_peer_cert_ut.c
* Summary: PSK client facing a certificate-authenticating TLS 1.3 server
*****************************************************************************/
/** @file tls13_peer_cert_ut.c
 * @brief A PSK client meets a server that ignores its PSK and sends a chain.
 *
 * RFC 8446 (August 2018), Section 4.1.1: a server that does not select an
 * offered PSK authenticates with a certificate (Sections 4.4.2 and 4.4.3).
 * With NOXTLS_TLS13_PEER_CERTIFICATES=0 the client must abort with
 * handshake_failure before reading the Certificate, so no certificate is
 * stored or parsed. With the default profile the client reads and parses the
 * two-certificate chain; the intermediate is borrowed from the message
 * (noxtls_x509_certificate_chain_add_der_nocopy), so no issuer certificate
 * structure is placed on the stack or the heap.
 * @defgroup noxtls_tls13_peer_cert TLS 1.3 peer certificate profile tests
 * @ingroup noxtls_tls13_peer_cert
 */
#include "tls13_peer_cert_fixture.h"
#include "tls/noxtls_tls13_config.h"
#include "tls/noxtls_tls_common.h"
#include "certs/noxtls_x509.h"
#include "common/noxtls_memory.h"
#include "mtls_test_pki.h"
#include "runner.h"
#include "test_assert.h"
#include <string.h>

static peer_cert_pipe_t s_to_server;
static peer_cert_pipe_t s_to_client;
static peer_cert_endpoint_t s_client;
static peer_cert_endpoint_t s_server;
static x509_private_key_t s_server_x509_key;
static ecc_key_t s_server_key;
static uint64_t s_now;
/** External PSK shared by the client and, in the PSK-accepted test, the server. */
static const uint8_t s_psk_identity[] = "peer-cert-test-only";
static const uint8_t s_psk_key[] = "not-a-production-key";

/**
 * @brief Supply a deterministic clock.
 * @internal
 *
 * @param[in] context Unused.
 *
 * @return Virtual milliseconds.
 */
static uint64_t now_ms(void *context)
{
    (void)context;
    return s_now;
}

/**
 * @brief Append bytes to the peer's receive pipe.
 * @internal
 *
 * @param[in] context Sending endpoint.
 * @param[in] data Bytes to send.
 * @param[in] length Byte count.
 *
 * @return Bytes accepted or -1 when the pipe is full.
 */
static int32_t pipe_send(void *context, const uint8_t *data, uint32_t length)
{
    peer_cert_endpoint_t *endpoint = context;
    peer_cert_pipe_t *pipe = endpoint->tx;
    if((length > PEER_CERT_PIPE_BYTES) || (pipe->length > (PEER_CERT_PIPE_BYTES - length))) {
        return -1;
    }

    memcpy(&pipe->bytes[pipe->length], data, length);
    pipe->length += length;
    return (int32_t)length;
}

/**
 * @brief Read bytes from the endpoint's receive pipe without blocking.
 * @internal
 *
 * @param[in] context Receiving endpoint.
 * @param[out] data Caller buffer.
 * @param[in] capacity Buffer capacity.
 *
 * @return Bytes read or TLS_IO_WOULD_BLOCK when empty.
 */
static int32_t pipe_recv(void *context, uint8_t *data, uint32_t capacity)
{
    peer_cert_endpoint_t *endpoint = context;
    peer_cert_pipe_t *pipe = endpoint->rx;
    uint32_t count = (capacity < pipe->length) ? capacity : pipe->length;
    if(count == 0U) {
        return TLS_IO_WOULD_BLOCK;
    }

    memcpy(data, pipe->bytes, count);
    memmove(pipe->bytes, &pipe->bytes[count], pipe->length - count);
    pipe->length -= count;
    return (int32_t)count;
}

/**
 * @brief Initialize one stream endpoint with in-memory pipes.
 * @internal
 *
 * @param[in,out] endpoint Endpoint.
 * @param[in] role Client or server.
 * @param[in] rx Receive pipe.
 * @param[in] tx Transmit pipe.
 *
 * @return Library result.
 */
static noxtls_return_t endpoint_init(peer_cert_endpoint_t *endpoint, tls_role_t role,
                                     peer_cert_pipe_t *rx, peer_cert_pipe_t *tx)
{
    static const uint16_t groups[] = {TLS_NAMED_GROUP_SECP256R1};
    static const uint16_t suites[] = {TLS_CIPHER_SUITE_AES_128_GCM_SHA256};
    noxtls_return_t rc = noxtls_tls13_context_init(&endpoint->tls, role);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    endpoint->rx = rx;
    endpoint->tx = tx;
    endpoint->initialized = true;
    rc = noxtls_tls_set_io_callbacks(&endpoint->tls.base.base, pipe_send, pipe_recv, endpoint);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = noxtls_tls_set_io_mode(&endpoint->tls.base.base, TLS_IO_MODE_NON_BLOCKING);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    noxtls_tls13_set_client_supported_groups(&endpoint->tls, groups,
                                             (uint32_t)(sizeof(groups) / sizeof(groups[0])));
    noxtls_tls13_set_server_cipher_suites(&endpoint->tls, suites,
                                          (uint32_t)(sizeof(suites) / sizeof(suites[0])));
    return noxtls_tls_set_time_callback(&endpoint->tls.base.base, now_ms);
}

/**
 * @brief Build a PSK client and a server holding only a certificate chain.
 * @internal
 *
 * @return Zero when both endpoints are ready.
 */
static int fixture_init(void)
{
    static const uint16_t schemes[] = {TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256};
    static const uint8_t *chain[PEER_CERT_INTERMEDIATES] = {mtls_intermediate_cert};
    static const uint32_t lengths[PEER_CERT_INTERMEDIATES] = {(uint32_t)sizeof(mtls_intermediate_cert)};
    memset(&s_to_server, 0, sizeof(s_to_server));
    memset(&s_to_client, 0, sizeof(s_to_client));
    memset(&s_client, 0, sizeof(s_client));
    memset(&s_server, 0, sizeof(s_server));
    s_now = PEER_CERT_START_MS;
    if((endpoint_init(&s_client, TLS_ROLE_CLIENT, &s_to_client, &s_to_server) != NOXTLS_RETURN_SUCCESS) ||
       (endpoint_init(&s_server, TLS_ROLE_SERVER, &s_to_server, &s_to_client) != NOXTLS_RETURN_SUCCESS)) {
        return 1;
    }

    if(tls13_set_external_psk(&s_client.tls, s_psk_identity, sizeof(s_psk_identity) - 1U, s_psk_key,
                              sizeof(s_psk_key) - 1U, TLS13_PSK_KE_MODE_PSK_DHE_KE) != NOXTLS_RETURN_SUCCESS) {
        return 1;
    }

    noxtls_tls13_set_client_signature_algorithms(&s_client.tls, schemes,
                                                 (uint32_t)(sizeof(schemes) / sizeof(schemes[0])));
    noxtls_x509_private_key_init(&s_server_x509_key);
    if((noxtls_x509_private_key_parse_der(&s_server_x509_key, mtls_server_key,
                                          (uint32_t)sizeof(mtls_server_key)) != NOXTLS_RETURN_SUCCESS) ||
       (noxtls_x509_private_key_to_ecc_key(&s_server_x509_key, &s_server_key) != NOXTLS_RETURN_SUCCESS)) {
        return 1;
    }

    if(noxtls_tls13_add_server_ecdsa_identity(&s_server.tls, mtls_server_cert,
                                              (uint32_t)sizeof(mtls_server_cert), &s_server_key) !=
       NOXTLS_RETURN_SUCCESS) {
        return 1;
    }

    noxtls_tls13_set_server_certificate_chain(&s_server.tls, chain, lengths, PEER_CERT_INTERMEDIATES);
    return 0;
}

/**
 * @brief Release both endpoints.
 * @internal
 */
static void fixture_free(void)
{
    if(s_client.initialized) {
        (void)noxtls_tls13_context_free(&s_client.tls);
    }

    if(s_server.initialized) {
        (void)noxtls_tls13_context_free(&s_server.tls);
    }

    (void)noxtls_x509_private_key_free(&s_server_x509_key);
}

/**
 * @brief Report whether a step result means "still waiting for the peer".
 * @internal
 *
 * @param[in] rc Step result.
 *
 * @return True for WANT_READ, WANT_WRITE or TIMEOUT.
 */
static bool pending(noxtls_return_t rc)
{
    return (rc == NOXTLS_RETURN_WANT_READ) || (rc == NOXTLS_RETURN_WANT_WRITE) ||
           (rc == NOXTLS_RETURN_TIMEOUT);
}

/**
 * @brief Run both state machines until the client reaches a final result.
 * @internal
 *
 * @return Final client result.
 */
static noxtls_return_t run_handshake(void)
{
    noxtls_return_t client_rc = NOXTLS_RETURN_WANT_READ;
    noxtls_return_t server_rc = NOXTLS_RETURN_WANT_READ;
    uint32_t step;
    for(step = 0U; (step < PEER_CERT_MAX_STEPS) && pending(client_rc); ++step) {
        client_rc = noxtls_tls13_connect(&s_client.tls);
        if(pending(server_rc)) {
            server_rc = noxtls_tls13_accept(&s_server.tls);
        }

        s_now += PEER_CERT_STEP_MS;
    }

    return client_rc;
}

/** @brief The server really chose certificate authentication over the PSK.
 * @return Zero on success. */
REGISTER_TEST(tls13_peer_cert_server_selects_certificate)
{
    UTNOX_EQUALS(fixture_init(), 0);
    noxtls_return_t rc = run_handshake();
    UTNOX_EQUALS(s_client.tls.psk_in_use, 0U);
    UTNOX_IS_FALSE(pending(rc));
    fixture_free();
    return 0;
}

/**
 * @brief Run both state machines until both endpoints are connected or one fails.
 * @internal
 *
 * @param[out] client_rc Final client result.
 * @param[out] server_rc Final server result.
 */
static void run_until_both_done(noxtls_return_t *client_rc, noxtls_return_t *server_rc)
{
    uint32_t step;
    *client_rc = NOXTLS_RETURN_WANT_READ;
    *server_rc = NOXTLS_RETURN_WANT_READ;
    for(step = 0U; (step < PEER_CERT_MAX_STEPS) && (pending(*client_rc) || pending(*server_rc)); ++step) {
        if(pending(*client_rc)) {
            *client_rc = noxtls_tls13_connect(&s_client.tls);
        }

        if(pending(*server_rc)) {
            *server_rc = noxtls_tls13_accept(&s_server.tls);
        }

        s_now += PEER_CERT_STEP_MS;
    }
}

/** @brief When the server accepts the PSK, both builds complete the handshake
 * without any certificate on the wire (the only path a PSK-only build keeps).
 * @return Zero on success. */
REGISTER_TEST(tls13_peer_cert_psk_accepted_connects)
{
    noxtls_return_t client_rc;
    noxtls_return_t server_rc;
    UTNOX_EQUALS(fixture_init(), 0);
    UTNOX_EQUALS(tls13_set_external_psk(&s_server.tls, s_psk_identity, sizeof(s_psk_identity) - 1U, s_psk_key,
                                        sizeof(s_psk_key) - 1U, TLS13_PSK_KE_MODE_PSK_DHE_KE),
                 NOXTLS_RETURN_SUCCESS);
    run_until_both_done(&client_rc, &server_rc);
    UTNOX_EQUALS(client_rc, NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(server_rc, NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(s_client.tls.base.base.state, TLS_STATE_CONNECTED);
    UTNOX_EQUALS(s_server.tls.base.base.state, TLS_STATE_CONNECTED);
    UTNOX_EQUALS(s_client.tls.psk_in_use, 1U);
    UTNOX_IS_NULL(s_client.tls.server_cert);
    UTNOX_EQUALS(s_client.tls.server_cert_len, 0U);
    fixture_free();
    return 0;
}

#if !NOXTLS_TLS13_PEER_CERTIFICATES
/** @brief A PSK-only client rejects the certificate handshake before parsing.
 * @return Zero on success. */
REGISTER_TEST(tls13_peer_cert_psk_only_rejects_before_certificate)
{
    UTNOX_EQUALS(fixture_init(), 0);
    UTNOX_EQUALS(run_handshake(), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_IS_NULL(s_client.tls.server_cert);
    UTNOX_EQUALS(s_client.tls.server_cert_len, 0U);
    UTNOX_IS_NULL(s_client.tls.server_cert_parsed);
    UTNOX_EQUALS(s_client.tls.base.base.state, TLS_STATE_CLOSED);
    UTNOX_MEM_EQUAL(noxtls_tls13_last_connect_fail_step(), (const uint8_t *)"psk_not_selected", sizeof("psk_not_selected"));
    fixture_free();
    return 0;
}

/** @brief The PSK-only entry points refuse without touching the context.
 * @return Zero on success. */
REGISTER_TEST(tls13_peer_cert_psk_only_entry_points)
{
    UTNOX_EQUALS(fixture_init(), 0);
    UTNOX_EQUALS(noxtls_tls13_recv_certificate(&s_client.tls), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_tls13_recv_certificate(NULL), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_tls13_recv_certificate_verify(&s_client.tls), NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_tls13_require_client_auth(&s_server.tls, 1);
    UTNOX_EQUALS(s_server.tls.request_client_auth, 0U);
    UTNOX_EQUALS(s_server.tls.require_client_auth, 0U);
    noxtls_tls13_request_client_auth(&s_server.tls, 1);
    UTNOX_EQUALS(s_server.tls.request_client_auth, 0U);
    noxtls_tls13_request_client_auth(NULL, 1);
    noxtls_tls13_require_client_auth(NULL, 1);
    fixture_free();
    return 0;
}
#else
/** @brief The default client reads and parses the two-certificate chain.
 * @return Zero on success. */
REGISTER_TEST(tls13_peer_cert_default_parses_chain)
{
    UTNOX_EQUALS(fixture_init(), 0);
    noxtls_return_t rc = run_handshake();
    UTNOX_NOT_EQUALS(rc, NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_IS_NOT_NULL(s_client.tls.server_cert);
    UTNOX_EQUALS(s_client.tls.server_cert_len, (uint32_t)sizeof(mtls_server_cert));
    fixture_free();
    return 0;
}

/** @brief Client authentication can still be requested and cleared.
 * @return Zero on success. */
REGISTER_TEST(tls13_peer_cert_default_client_auth_flags)
{
    UTNOX_EQUALS(fixture_init(), 0);
    noxtls_tls13_require_client_auth(&s_server.tls, 1);
    UTNOX_EQUALS(s_server.tls.request_client_auth, 1U);
    UTNOX_EQUALS(s_server.tls.require_client_auth, 1U);
    noxtls_tls13_request_client_auth(&s_server.tls, 0);
    UTNOX_EQUALS(s_server.tls.request_client_auth, 0U);
    UTNOX_EQUALS(s_server.tls.require_client_auth, 0U);
    fixture_free();
    return 0;
}
#endif
