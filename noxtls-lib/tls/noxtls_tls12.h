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
* File:    noxtls_tls12.h
* Summary: TLS 1.2 Implementation
*
*/

#ifndef _NOXTLS_TLS12_H_
#define _NOXTLS_TLS12_H_

#include <stdint.h>

#include "noxtls_common.h"
#include "noxtls_tls_common.h"
#include "noxtls_dtls_common.h"
#include "noxtls_crypto_provider.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TLS 1.2 Context */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct tls12_context_s
{
    dtls_context_t base;            /* Base TLS/DTLS context */
    
    /* Handshake state */
    uint8_t client_random[32];      /* Client random */
    uint8_t server_random[32];      /* Server random */
    uint16_t cipher_suite;          /* Selected cipher suite */
    
    /* Keys */
    uint8_t client_write_key[32];   /* Client write key */
    uint8_t server_write_key[32];   /* Server write key */
    uint8_t client_write_iv[16];     /* Client write IV */
    uint8_t server_write_iv[16];    /* Server write IV */
    uint8_t client_write_mac_key[32]; /* Client write MAC key */
    uint8_t server_write_mac_key[32]; /* Server write MAC key */
    
    /* Sequence numbers */
    uint64_t client_seq_num;        /* Client sequence number */
    uint64_t server_seq_num;        /* Server sequence number */
    
    /* Certificate */
    uint8_t *server_cert;           /* Server certificate (DER format) */
    uint32_t server_cert_len;       /* Server certificate length */
    void *server_cert_parsed;       /* Parsed X.509 certificate (x509_certificate_t*) */

    /** Optional server RSA private key (rsa_key_t*) for Server Key Exchange signature. If set, SKX is signed. */
    void *server_private_rsa;
    /** Optional: crypto provider (PKCS#11/TPM/hardware). When set with server_private_key_handle, server sign uses provider instead of server_private_rsa. */
    const noxtls_crypto_provider_t *crypto_provider;
    /** Provider's handle for server RSA private key. Used when crypto_provider is set for Server Key Exchange / Certificate Verify. */
    noxtls_crypto_key_handle_t server_private_key_handle;

    /* Key exchange */
    uint8_t premaster_secret[66];     /* Premaster secret (RSA 48 bytes, ECDHE up to P-521) */
    uint32_t premaster_secret_len;    /* Premaster secret length */
    uint8_t master_secret[48];        /* Master secret */
    void *ecdhe_ctx;                  /* ECDHE context (tls_ecdhe_context_t*) - for ECDHE key exchange */
    void *dhe_ctx;                     /* DHE context (tls_dhe_context_t*) - for DHE-RSA (FFDHE) key exchange */
    
    /* Handshake messages */
    uint8_t *handshake_messages;     /* Accumulated handshake messages */
    uint32_t handshake_messages_len; /* Length of handshake messages */
    
    /* Extensions */
    tls_extensions_t client_extensions;  /* Client Hello extensions */
    tls_extensions_t server_extensions;   /* Server Hello extensions */

    /* Client configuration */
    const char *server_name;             /* SNI hostname (optional) */
    uint16_t server_name_len;            /* SNI hostname length */

    /* Renegotiation (RFC 5746): verify_data from previous handshake for renegotiation_info extension */
    uint8_t previous_client_verify_data[48];
    uint8_t previous_server_verify_data[48];
    uint8_t previous_verify_data_len;
    uint8_t renegotiation_in_progress;   /* 1 when handling HelloRequest or received ClientHello (server) */

    /* TLS 1.0 implicit IV: last cipher block of previous record (per direction) */
    uint8_t client_last_cipher_block[16];
    uint8_t server_last_cipher_block[16];

    /* Reusable record workspace: encrypted/decrypted/handshake buffer (one at a time). Size TLS_MAX_RECORD_SIZE+256. */
    uint8_t *record_workspace;
    /* Reusable handshake workspace: build/parse client_hello, certificate, server_key_exchange, etc. (one at a time). Size TLS_HANDSHAKE_WORKSPACE_SIZE. */
    uint8_t *handshake_workspace;

    /* RFC 7250 Raw Public Keys (RPK): certificate type negotiation and result */
    uint8_t server_use_rpk;              /* Server: 1 = send SubjectPublicKeyInfo in Certificate (server_cert holds SPKI DER) */
    uint8_t server_certificate_type;     /* Client: negotiated type from ServerHello ext 20; Server: type we chose (e.g. TLS_CERT_TYPE_RAW_PUBLIC_KEY) */
    uint8_t client_certificate_type;     /* Client: negotiated type from ServerHello ext 19 (for client auth); Server: type we request */
    uint8_t server_cert_is_rpk;          /* Client: 1 after recv_certificate when server sent RPK (server_cert = SubjectPublicKeyInfo; verify out-of-band) */
    uint8_t client_accept_server_rpk;    /* Client: 1 = send server_certificate_type ext with RPK in ClientHello */
    uint8_t client_offer_client_rpk;     /* Client: 1 = send client_certificate_type ext with RPK in ClientHello (for client auth) */

    /* RFC 6066 Maximum Fragment Length: 0 = not used; 1=512, 2=1024, 3=2048, 4=4096 (code). Negotiated max plaintext record payload in bytes. */
    uint8_t max_fragment_length_code;    /* Client: requested code (1-4). Server: selected code echoed in ServerHello. */
    uint16_t max_record_payload;         /* Negotiated max record payload (plaintext). 0 = use TLS_MAX_RECORD_SIZE. */
} tls12_context_t;
NOXTLS_MSVC_WARNING_POP

/* TLS 1.2 Functions */
noxtls_return_t tls12_context_init(tls12_context_t *ctx, tls_role_t role);
/** Initialize context for a specific TLS version (e.g. TLS_VERSION_1_0, TLS_VERSION_1_1, TLS_VERSION_1_2). */
noxtls_return_t tls12_context_init_with_version(tls12_context_t *ctx, tls_role_t role, uint16_t version);
noxtls_return_t dtls12_context_init(tls12_context_t *ctx, tls_role_t role);
noxtls_return_t tls12_context_free(tls12_context_t *ctx);
noxtls_return_t tls12_connect(tls12_context_t *ctx);
noxtls_return_t tls12_accept(tls12_context_t *ctx);
noxtls_return_t tls12_compute_master_secret(tls12_context_t *ctx, const uint8_t *premaster_secret, uint32_t premaster_secret_len);  /* Compute master secret from premaster secret */
noxtls_return_t tls12_derive_keys(tls12_context_t *ctx);  /* Derive keys from master secret */
noxtls_return_t tls12_send(tls12_context_t *ctx, const uint8_t *data, uint32_t len);
noxtls_return_t tls12_recv(tls12_context_t *ctx, uint8_t *data, uint32_t *len);
noxtls_return_t tls12_close(tls12_context_t *ctx);

/** Server: send HelloRequest to ask client to renegotiate (RFC 5746). */
noxtls_return_t tls12_send_hello_request(tls12_context_t *ctx);

/* TLS 1.2 Client Handshake Functions */
noxtls_return_t tls12_send_client_hello(tls12_context_t *ctx);
noxtls_return_t tls12_recv_server_hello(tls12_context_t *ctx);
noxtls_return_t tls12_recv_certificate(tls12_context_t *ctx);
noxtls_return_t tls12_recv_server_key_exchange(tls12_context_t *ctx);
noxtls_return_t tls12_recv_server_hello_done(tls12_context_t *ctx);
noxtls_return_t tls12_send_client_key_exchange(tls12_context_t *ctx);
noxtls_return_t tls12_send_change_cipher_spec(tls12_context_t *ctx);
noxtls_return_t tls12_send_finished(tls12_context_t *ctx);
noxtls_return_t tls12_recv_change_cipher_spec(tls12_context_t *ctx);
noxtls_return_t tls12_recv_finished(tls12_context_t *ctx);

/* TLS 1.2 Server Handshake Functions */
noxtls_return_t tls12_recv_client_hello(tls12_context_t *ctx);
noxtls_return_t tls12_send_server_hello(tls12_context_t *ctx);
noxtls_return_t tls12_send_certificate(tls12_context_t *ctx);
noxtls_return_t tls12_send_server_key_exchange(tls12_context_t *ctx);
noxtls_return_t tls12_send_server_hello_done(tls12_context_t *ctx);
noxtls_return_t tls12_recv_client_key_exchange(tls12_context_t *ctx);
noxtls_return_t tls12_recv_change_cipher_spec_client(tls12_context_t *ctx);
noxtls_return_t tls12_recv_finished_client(tls12_context_t *ctx);
noxtls_return_t tls12_send_change_cipher_spec_server(tls12_context_t *ctx);
noxtls_return_t tls12_send_finished_server(tls12_context_t *ctx);

/** Set server RSA private key (rsa_key_t*) for Server Key Exchange signature. Call before handshake if using ECDHE_RSA. */
void tls12_set_server_private_rsa(tls12_context_t *ctx, void *rsa_key);
/** Set optional crypto provider and server key handle for server sign (SKX) and decrypt (Client Key Exchange). Use instead of server_private_rsa when key is in HSM/TPM. */
void tls12_set_crypto_provider_server(tls12_context_t *ctx, const noxtls_crypto_provider_t *provider, noxtls_crypto_key_handle_t server_key_handle);
/** RFC 7250: Server uses Raw Public Key. Set server_cert/server_cert_len to SubjectPublicKeyInfo (DER). Call before handshake. */
void tls12_set_server_use_rpk(tls12_context_t *ctx, int use_rpk);
/** RFC 7250: Client accepts server RPK (sends server_certificate_type extension). Call before connect. */
void tls12_set_client_accept_server_rpk(tls12_context_t *ctx, int accept);
/** RFC 7250: Client can send RPK for client auth (sends client_certificate_type extension). Call before connect. */
void tls12_set_client_offer_client_rpk(tls12_context_t *ctx, int offer);

/** RFC 6066: Set max fragment length (client or server). code: 0 = disabled, 1=512, 2=1024, 3=2048, 4=4096 bytes. Call before handshake. */
void tls12_set_max_fragment_length(tls12_context_t *ctx, uint8_t code);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_TLS12_H_ */

