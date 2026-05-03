/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
*
* NOTICE:  All information contained herein, source code, binaries and
* derived works is, and remains
* the property of Argenox Technologies and its suppliers,
* if any.  The intellectual and technical concepts contained
* herein are proprietary to Argenox Technologies
* and its suppliers may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Argenox Technologies.
*
* THIS SOFTWARE IS PROVIDED BY ARGENOX "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL ARGENOX TECHNOLOGIES LLC BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
* CONTACT: info@argenox.com
* 
*
* File:    noxtls_tls13.h
* Summary: TLS 1.3 Implementation
*
*/

#ifndef _NOXTLS_TLS13_H_
#define _NOXTLS_TLS13_H_

#include <stdint.h>

#include "noxtls_common.h"
#include "noxtls_tls_common.h"
#include "noxtls_dtls_common.h"
#include "noxtls_crypto_provider.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TLS 1.3 Key Share Entry */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    uint16_t group;         /* Named group */
    uint16_t key_exchange_len; /* Key exchange length */
    uint8_t *key_exchange;  /* Key exchange data */
} tls13_key_share_entry_t;
NOXTLS_MSVC_WARNING_POP

/* TLS 1.3 Context */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct tls13_context_s
{
    dtls_context_t base;            /* Base TLS/DTLS context */
    
    /* Handshake state */
    uint8_t client_random[32];      /* Client random */
    uint8_t server_random[32];      /* Server random */
    uint16_t cipher_suite;          /* Selected cipher suite */
    
    /* Key derivation */
    uint8_t early_secret[64];       /* Early secret (max SHA-384) */
    uint8_t handshake_secret[64];    /* Handshake secret */
    uint8_t master_secret[64];       /* Master secret */
    uint8_t client_handshake_traffic_secret[64];  /* Client handshake traffic secret */
    uint8_t server_handshake_traffic_secret[64];  /* Server handshake traffic secret */
    uint8_t client_application_traffic_secret[64]; /* Client application traffic secret */
    uint8_t server_application_traffic_secret[64]; /* Server application traffic secret */
    
    /* Keys */
    uint8_t client_write_key[32];   /* Client write key */
    uint8_t server_write_key[32];   /* Server write key */
    uint8_t client_write_iv[12];    /* Client write IV */
    uint8_t server_write_iv[12];    /* Server write IV */
    /* RFC 9147 §4.2.3: record number encryption keys (one block = 16 bytes) */
    uint8_t client_sn_key[16];
    uint8_t server_sn_key[16];
    uint8_t client_handshake_sn_key[16];
    uint8_t server_handshake_sn_key[16];
    
    /* Sequence numbers */
    uint64_t client_seq_num;        /* Client sequence number */
    uint64_t server_seq_num;        /* Server sequence number */
    
    /* Certificate */
    uint8_t *server_cert;           /* Server certificate (DER format) */
    uint32_t server_cert_len;       /* Server certificate length */
    void *server_cert_parsed;       /* Parsed X.509 certificate (x509_certificate_t*) */
    
    /* Handshake messages */
    uint8_t *handshake_messages;     /* Accumulated handshake messages */
    uint32_t handshake_messages_len; /* Length of handshake messages */

    /* Pending handshake data from decrypted records */
    uint8_t *handshake_buffer;       /* Decrypted handshake bytes */
    uint32_t handshake_buffer_len;   /* Total bytes in buffer */
    uint32_t handshake_buffer_pos;   /* Read offset in buffer */
    uint8_t handshake_encrypted;     /* Handshake encryption active */
    /** RFC 8446 §5.1: next message extracted from buffer starts at a record boundary (must be true for ClientHello, ServerHello, EndOfEarlyData, Finished, KeyUpdate). */
    uint8_t handshake_next_at_record_boundary;
    
    /* Key shares */
    tls13_key_share_entry_t *client_key_shares;  /* Client key shares */
    uint32_t client_key_shares_count;             /* Number of client key shares */
    tls13_key_share_entry_t *server_key_share;   /* Server key share */
    void *ecdhe_ctx;                               /* ECDHE context (tls_ecdhe_context_t*) */
    
    /* Extensions */
    tls_extensions_t client_extensions;  /* Client Hello extensions */
    tls_extensions_t server_extensions;  /* Server Hello extensions */

    /* Client configuration */
    const char *server_name;             /* SNI hostname (optional) */
    uint16_t server_name_len;            /* SNI hostname length */

    /* Runtime cipher preference: 0 = prefer AES-GCM (default), 1 = prefer ChaCha20-Poly1305 */
    uint8_t prefer_chacha20;

    /** Optional server RSA private key (rsa_key_t*) for CertificateVerify. If set, CertificateVerify is signed with RSA-PSS. */
    void *server_private_rsa;
    /** Optional: crypto provider (PKCS#11/TPM/hardware). When set with server_private_key_handle, server sign uses provider instead of server_private_rsa. */
    const noxtls_crypto_provider_t *crypto_provider;
    /** Provider's handle for server RSA private key. Used when crypto_provider is set for server CertificateVerify. */
    noxtls_crypto_key_handle_t server_private_key_handle;

    /* Client certificate authentication (mutual TLS / mTLS) */
    uint8_t request_client_auth;     /* Server: if set, send CertificateRequest and verify client cert */
    uint8_t client_auth_requested;   /* Client: set when server sent CertificateRequest */
    uint8_t cert_request_context[32];/* Client: context from CertificateRequest (for client Certificate message) */
    uint8_t cert_request_context_len;
    uint8_t *client_cert;            /* Client: cert to send (DER). Server: received client cert (owned). */
    uint32_t client_cert_len;
    void *client_cert_parsed;        /* Server: parsed client X.509 (x509_certificate_t*) for verification */
    void *client_private_rsa;       /* Client: RSA key (rsa_key_t*) for signing CertificateVerify */
    void *client_private_ecdsa;     /* Client: ECC key (ecc_key_t*) for ECDSA CertificateVerify */
    uint8_t client_private_ed25519[32]; /* Client: Ed25519 private key (32-byte seed) for CertificateVerify */
    uint8_t client_cert_use_ed25519;    /* 1 if client_private_ed25519 was set (so use Ed25519 for CertificateVerify) */
    /** Provider's handle for client private key (RSA/ECDSA/Ed25519). Used when crypto_provider is set for client CertificateVerify. */
    noxtls_crypto_key_handle_t client_private_key_handle;

    /* External PSK configuration and negotiated PSK mode */
    uint8_t psk_identity[256];
    uint16_t psk_identity_len;
    uint8_t psk_key[64];
    uint16_t psk_key_len;
    uint8_t psk_configured;
    uint8_t psk_preferred_mode;
    uint8_t psk_in_use;
    uint8_t psk_use_ecdhe;
    uint16_t psk_selected_identity;

    /* Session ticket (resumption) – client stores one ticket from NewSessionTicket */
    uint8_t ticket_identity[32];
    uint16_t ticket_identity_len;
    uint8_t ticket_nonce[32];
    uint8_t ticket_nonce_len;
    uint8_t resumption_psk[64];
    uint8_t resumption_psk_len;
    uint32_t ticket_age_add;
    uint16_t ticket_cipher_suite;
    uint8_t ticket_stored;

    /* One chunk of application data read while waiting for NST at end of connect */
    uint8_t *pending_app_data;
    uint32_t pending_app_data_len;

    /* Client: handshake message pushed back after recv_certificate_request (e.g. server Certificate) */
    uint8_t *pending_handshake_msg;
    uint32_t pending_handshake_len;

    /* TLS 1.3 0-RTT (early data): client can send app data before handshake completes when resuming */
    uint8_t early_data_phase;            /* Client: 1 after sending ClientHello with early_data, until EndOfEarlyData */
    uint8_t early_data_accepted;        /* Client: 1 if server sent early_data in EncryptedExtensions */
    uint8_t client_early_traffic_secret[64];
    uint8_t early_write_key[32];
    uint8_t early_write_iv[12];
    uint64_t early_seq_num;
    uint32_t max_early_data_size;       /* Default 0xFFFFFFFF */
    uint8_t sent_end_of_early_data;
    uint8_t early_data_sent;            /* 1 if tls13_send_early_data was used (so we must send EndOfEarlyData) */
    uint8_t client_offered_early_data;  /* Server: 1 if ClientHello contained early_data extension */
    uint8_t end_of_early_data_seen;     /* Server: 1 after receiving EndOfEarlyData from client */

    /* RFC 9147 Connection ID: CID sent by peer (included in records we send); our CID (expected in records we receive) */
    uint8_t peer_connection_id[32];
    uint8_t peer_connection_id_len;
    uint8_t own_connection_id[32];
    uint8_t own_connection_id_len;

    /* Reusable record workspace: inner plaintext + encrypted (send) or decrypted (recv). One buffer, two regions. */
    uint8_t *record_workspace;
    /* Reusable handshake workspace: build/parse client_hello, certificate, certificate_verify, etc. (one at a time). Size TLS_HANDSHAKE_WORKSPACE_SIZE. */
    uint8_t *handshake_workspace;

    /* RFC 5929 channel binding: first TLS Finished message (verify_data). In TLS 1.3 the first Finished is the server's. */
    uint8_t channel_binding_first_finished[64];
    uint32_t channel_binding_first_finished_len;

    /* RFC 8449 Record Size Limit: max plaintext we may send (peer's limit); max we accept (our advertised limit). 0 = use TLS_MAX_RECORD_SIZE. */
    uint16_t record_size_limit_send;   /* Do not send records larger than this (0 = TLS_MAX_RECORD_SIZE). */
    uint16_t record_size_limit_recv;   /* We advertised this as max we accept; peer must not send larger (0 = use default). */
} tls13_context_t;
NOXTLS_MSVC_WARNING_POP

#define TLS13_PSK_KE_MODE_PSK_KE 0
#define TLS13_PSK_KE_MODE_PSK_DHE_KE 1

/* TLS 1.3 Functions */
noxtls_return_t tls13_context_init(tls13_context_t *ctx, tls_role_t role);
noxtls_return_t dtls13_context_init(tls13_context_t *ctx, tls_role_t role);
noxtls_return_t tls13_context_free(tls13_context_t *ctx);
noxtls_return_t tls13_connect(tls13_context_t *ctx);
noxtls_return_t tls13_accept(tls13_context_t *ctx);
noxtls_return_t tls13_send(tls13_context_t *ctx, const uint8_t *data, uint32_t len);
noxtls_return_t tls13_recv(tls13_context_t *ctx, uint8_t *data, uint32_t *len);
noxtls_return_t tls13_close(tls13_context_t *ctx);

/** Client: send 0-RTT early data (only when resuming and before handshake completes). */
noxtls_return_t tls13_send_early_data(tls13_context_t *ctx, const uint8_t *data, uint32_t len);
void tls13_set_keylog_file(const char *path);

/** Set runtime cipher preference: prefer_chacha20 0 = prefer AES-GCM, 1 = prefer ChaCha20-Poly1305. Call before handshake. */
void tls13_set_prefer_chacha20(tls13_context_t *ctx, int prefer_chacha20);

/** Set server RSA private key (rsa_key_t*) for CertificateVerify. Call before handshake if using server auth with RSA. */
void tls13_set_server_private_rsa(tls13_context_t *ctx, void *rsa_key);
/** Set optional crypto provider and server key handle for server sign (CertificateVerify). Use instead of server_private_rsa when key is in HSM/TPM. */
void tls13_set_crypto_provider_server(tls13_context_t *ctx, const noxtls_crypto_provider_t *provider, noxtls_crypto_key_handle_t server_key_handle);

/** Server: request client certificate (mutual TLS). Call before tls13_accept. */
void tls13_request_client_auth(tls13_context_t *ctx, int request);

/** Client: set client certificate and RSA private key for mutual TLS. Call before tls13_connect. cert in DER; rsa_key is rsa_key_t*. */
noxtls_return_t tls13_set_client_cert(tls13_context_t *ctx, const uint8_t *cert_der, uint32_t cert_len, void *rsa_key);
/** Client: set client certificate and ECDSA private key (ecc_key_t*) for CertificateVerify. Use for ECDSA P-256/P-384 certs. */
noxtls_return_t tls13_set_client_cert_ecdsa(tls13_context_t *ctx, const uint8_t *cert_der, uint32_t cert_len, void *ecc_key);
/** Client: set client certificate and Ed25519 private key (32-byte seed) for CertificateVerify. */
noxtls_return_t tls13_set_client_cert_ed25519(tls13_context_t *ctx, const uint8_t *cert_der, uint32_t cert_len, const uint8_t *private_key_32);

/** Configure external PSK identity/key for TLS 1.3 PSK or ECDHE-PSK handshakes. */
noxtls_return_t tls13_set_external_psk(tls13_context_t *ctx,
                                       const uint8_t *identity, uint16_t identity_len,
                                       const uint8_t *psk_key, uint16_t psk_key_len,
                                       uint8_t preferred_mode);

/** RFC 5929 channel binding types for noxtls_tls13_get_channel_binding. */
#define NOXTLS_TLS_CHANNEL_BINDING_TLS_UNIQUE           1
#define NOXTLS_TLS_CHANNEL_BINDING_TLS_SERVER_END_POINT 2

/**
 * Get TLS channel binding data (RFC 5929). Call after handshake completes.
 * @param ctx TLS 1.3 context.
 * @param binding_type NOXTLS_TLS_CHANNEL_BINDING_TLS_UNIQUE (first Finished verify_data) or NOXTLS_TLS_CHANNEL_BINDING_TLS_SERVER_END_POINT (hash of server cert).
 * @param out Output buffer for binding data.
 * @param out_len On input: buffer size; on success: bytes written (tls-unique: 32 or 48; tls-server-end-point: 32 or 48).
 * @return NOXTLS_RETURN_SUCCESS on success; NOXTLS_RETURN_FAILED if binding not available or invalid type.
 */
noxtls_return_t noxtls_tls13_get_channel_binding(tls13_context_t *ctx, uint32_t binding_type, uint8_t *out, uint32_t *out_len);

/** RFC 8449: Set record size limit we advertise (max plaintext we are willing to receive). 0 = use default (16384). Call before handshake. */
void tls13_set_record_size_limit(tls13_context_t *ctx, uint16_t limit);

/* TLS 1.3 Client Handshake Functions */
noxtls_return_t tls13_send_client_hello(tls13_context_t *ctx);
noxtls_return_t tls13_recv_server_hello(tls13_context_t *ctx);
noxtls_return_t tls13_recv_encrypted_extensions(tls13_context_t *ctx);
noxtls_return_t tls13_recv_certificate_request(tls13_context_t *ctx);
noxtls_return_t tls13_recv_certificate(tls13_context_t *ctx);
noxtls_return_t tls13_recv_certificate_verify(tls13_context_t *ctx);
noxtls_return_t tls13_recv_finished(tls13_context_t *ctx);
noxtls_return_t tls13_send_client_certificate(tls13_context_t *ctx);
noxtls_return_t tls13_send_client_certificate_verify(tls13_context_t *ctx);
noxtls_return_t tls13_send_finished(tls13_context_t *ctx);

/* TLS 1.3 Server Handshake Functions */
noxtls_return_t tls13_send_certificate_request(tls13_context_t *ctx);
noxtls_return_t tls13_recv_client_hello(tls13_context_t *ctx);
noxtls_return_t tls13_send_server_hello(tls13_context_t *ctx);
noxtls_return_t tls13_send_encrypted_extensions(tls13_context_t *ctx);
noxtls_return_t tls13_send_certificate(tls13_context_t *ctx);
noxtls_return_t tls13_send_certificate_verify(tls13_context_t *ctx);
noxtls_return_t tls13_send_finished_server(tls13_context_t *ctx);
noxtls_return_t tls13_recv_finished_client(tls13_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_TLS13_H_ */

