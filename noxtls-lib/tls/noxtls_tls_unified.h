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
* File:    noxtls_tls_unified.h
* Summary: Unified TLS API: single connection type for TLS 1.2/1.3
*
*
*****************************************************************************/

#ifndef _NOXTLS_TLS_UNIFIED_H_
#define _NOXTLS_TLS_UNIFIED_H_

#include <stdint.h>

#include "noxtls_common.h"
#include "noxtls_tls_common.h"

#if (NOXTLS_FEATURE_TLS12 || NOXTLS_FEATURE_TLS13)
#include "noxtls_tls12.h"
#include "noxtls_tls13.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if (NOXTLS_FEATURE_TLS12 || NOXTLS_FEATURE_TLS13)

/**
 * Unified TLS connection: one context type for TLS 1.2 or 1.3 with automatic
 * version negotiation. Server uses accept(); client uses connect() (tries 1.3 then 1.2).
 * Only one of u.tls12 or u.tls13 is active per connection.
 */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct noxtls_tls_connection_s
{
    tls_context_t base;            /* I/O and first-record recv for server version detection */
    uint16_t negotiated_version;   /* 0 before handshake; TLS_VERSION_1_2 or TLS_VERSION_1_3 after */
    uint8_t is_tls13;              /* 1 if active context is TLS 1.3 */
    uint8_t fixed_version;         /* 1 if init_version was used (only that version is used) */
    /** 1 if TLS 1.3 may be negotiated on this connection (auto init, or init_version(TLS 1.3)). Used for RFC 8446 TLS 1.2 downgrade random. */
    uint8_t config_offers_tls13;
    /* Config applied when version is chosen (server cert/key; client SNI) */
    const uint8_t *server_cert;
    uint32_t server_cert_len;
    const uint8_t **server_cert_chain;
    const uint32_t *server_cert_chain_len;
    uint32_t server_cert_chain_count;
    void *server_private_rsa;
    const uint16_t *server_cipher_suites;
    uint32_t server_cipher_suites_count;
    const char **server_alpn_protocols;
    uint32_t server_alpn_count;
    const char *server_name;
    uint16_t server_name_len;
    /** Client (RFC 7507): applied to the version context before ClientHello. */
    uint8_t client_send_fallback_scsv;
    /** Server: request a client certificate (CertificateRequest). */
    uint8_t request_client_auth;
    /** Server: require a client certificate (implies request). */
    uint8_t require_client_auth;
    /** Client: optional client certificate for mutual TLS (non-owning DER + key pointers). */
    const uint8_t *client_cert;
    uint32_t client_cert_len;
    void *client_private_rsa;
    void *client_private_ecdsa;
    /** BoGo: force peer certificate verification to fail. */
    uint8_t force_cert_verify_fail;
    /** Optional CRL chain applied to either negotiated protocol version. */
    const noxtls_x509_crl_t *verify_crl;
    /** Requested maximum plaintext record payload; 0 keeps protocol default. */
    uint16_t maximum_record_payload;
    union {
        tls12_context_t tls12;
        tls13_context_t tls13;
    } u;
} noxtls_tls_connection_t;
NOXTLS_MSVC_WARNING_POP

/** Initialize for auto negotiation (client or server). */
noxtls_return_t noxtls_tls_connection_init(noxtls_tls_connection_t *conn, tls_role_t role);

/** Initialize for a fixed TLS version only (TLS_VERSION_1_2 or TLS_VERSION_1_3). */
noxtls_return_t noxtls_tls_connection_init_version(noxtls_tls_connection_t *conn, tls_role_t role, uint16_t version);

/** Free connection and clear struct. */
noxtls_return_t noxtls_tls_connection_free(noxtls_tls_connection_t *conn);

/** Set I/O callbacks and user_data (required before accept/connect). */
noxtls_return_t noxtls_tls_connection_set_io_callbacks(noxtls_tls_connection_t *conn,
                                                       tls_send_callback_t send_cb,
                                                       tls_recv_callback_t recv_cb,
                                                       void *user_data);

/** Set optional time callback (e.g. for DTLS). */
noxtls_return_t noxtls_tls_connection_set_time_callback(noxtls_tls_connection_t *conn, tls_time_callback_t time_cb);

/** Server: set certificate (DER). Applied to chosen context at accept. */
noxtls_return_t noxtls_tls_connection_set_server_cert(noxtls_tls_connection_t *conn, const uint8_t *cert, uint32_t cert_len);
/** Server: set optional intermediate certificate chain (DER). Applied at accept. */
noxtls_return_t noxtls_tls_connection_set_server_cert_chain(noxtls_tls_connection_t *conn,
                                                            const uint8_t **certs,
                                                            const uint32_t *cert_lens,
                                                            uint32_t cert_count);

/** Server: set RSA private key for Server Key Exchange / CertificateVerify. */
noxtls_return_t noxtls_tls_connection_set_server_private_key(noxtls_tls_connection_t *conn, void *rsa_key);
/** Server: set cipher-suite allowlist (wire IDs). */
noxtls_return_t noxtls_tls_connection_set_server_cipher_suites(noxtls_tls_connection_t *conn,
                                                               const uint16_t *suites,
                                                               uint32_t count);
/** Server: set supported ALPN protocol names (non-owning). */
noxtls_return_t noxtls_tls_connection_set_server_alpn_protocols(noxtls_tls_connection_t *conn,
                                                                const char **protocols,
                                                                uint32_t count);

/** Client: set SNI hostname. Applied at connect. */
noxtls_return_t noxtls_tls_connection_set_sni(noxtls_tls_connection_t *conn, const char *name, uint16_t name_len);
noxtls_return_t noxtls_tls_connection_set_client_fallback_scsv(noxtls_tls_connection_t *conn, int enable);

/** Server: request any client certificate (mutual TLS). Call before accept. */
noxtls_return_t noxtls_tls_connection_set_request_client_auth(noxtls_tls_connection_t *conn, int enable);

/** Server: require a client certificate (implies request). Call before accept. */
noxtls_return_t noxtls_tls_connection_set_require_client_auth(noxtls_tls_connection_t *conn, int enable);

/** Client: set RSA client certificate + private key for mutual TLS. Call before connect. */
noxtls_return_t noxtls_tls_connection_set_client_cert_rsa(noxtls_tls_connection_t *conn,
                                                         const uint8_t *cert_der, uint32_t cert_len,
                                                         void *rsa_key);

/** Client: set ECDSA client certificate + private key for mutual TLS. Call before connect. */
noxtls_return_t noxtls_tls_connection_set_client_cert_ecdsa(noxtls_tls_connection_t *conn,
                                                           const uint8_t *cert_der, uint32_t cert_len,
                                                           void *ecc_key);

/** Force peer certificate verification to fail (BoGo -verify-fail with -verify-peer). */
noxtls_return_t noxtls_tls_connection_set_force_cert_verify_fail(noxtls_tls_connection_t *conn, int enable);

/** Apply an application-owned CRL chain to TLS 1.2 and TLS 1.3 verification. */
noxtls_return_t noxtls_tls_connection_set_verify_crl(noxtls_tls_connection_t *conn,
                                                     const noxtls_x509_crl_t *crl);

/**
 * Request a bounded plaintext record payload. TLS 1.2 uses RFC 6066 maximum
 * fragment length and therefore accepts 512, 1024, 2048, or 4096. TLS 1.3
 * uses RFC 8449 record_size_limit. A value of zero restores protocol default.
 */
noxtls_return_t noxtls_tls_connection_set_maximum_record_payload(
    noxtls_tls_connection_t *conn, uint16_t payload_bytes);

/** Server: receive Client Hello, detect version, complete handshake (TLS 1.2 or 1.3). */
noxtls_return_t noxtls_tls_connection_accept(noxtls_tls_connection_t *conn);

/** Client: connect with auto (try 1.3 then 1.2) or fixed version. */
noxtls_return_t noxtls_tls_connection_connect(noxtls_tls_connection_t *conn);

/** Send application data. Call after handshake. */
noxtls_return_t noxtls_tls_connection_send(noxtls_tls_connection_t *conn, const uint8_t *data, uint32_t len);

/** Receive application data. len is in/out: max size in, bytes read out. */
noxtls_return_t noxtls_tls_connection_recv(noxtls_tls_connection_t *conn, uint8_t *buf, uint32_t *len);

/** Send close_notify and transition to closing state. */
noxtls_return_t noxtls_tls_connection_close(noxtls_tls_connection_t *conn);

/** Return negotiated version (TLS_VERSION_1_2, TLS_VERSION_1_3, or 0 if not yet negotiated). */
uint16_t noxtls_tls_connection_get_version(const noxtls_tls_connection_t *conn);

/** Borrow the authenticated peer leaf certificate for the connection lifetime. */
noxtls_return_t noxtls_tls_connection_get_peer_certificate(
    const noxtls_tls_connection_t *conn, const uint8_t **certificate_der,
    uint32_t *certificate_length);

/** Return the negotiated cipher-suite wire identifier, or zero before handshake. */
uint16_t noxtls_tls_connection_get_cipher_suite(const noxtls_tls_connection_t *conn);

#endif /* NOXTLS_FEATURE_TLS12 || NOXTLS_FEATURE_TLS13 */

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_TLS_UNIFIED_H_ */
