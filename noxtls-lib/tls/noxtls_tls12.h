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
#include "noxtls_hash.h"
#include "noxtls_tls_common.h"
#include "noxtls_dtls_common.h"
#include "noxtls_crypto_provider.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration to avoid including full X.509 header here. */
typedef struct noxtls_x509_crl noxtls_x509_crl_t;

#define TLS12_SESSION_CACHE_SIZE   16u
#define TLS12_SESSION_SNI_MAX      255u
#define TLS12_TICKET_CACHE_SIZE    32u
#define TLS12_TICKET_MAX_LEN       256u
#define TLS12_TICKET_LIFETIME_HINT 86400u

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
    uint8_t client_write_mac_key[64]; /* Client write MAC key (max: SHA-512/SHA-384 families) */
    uint8_t server_write_mac_key[64]; /* Server write MAC key (max: SHA-512/SHA-384 families) */
    
    /* Sequence numbers */
    uint64_t client_seq_num;        /* Client sequence number */
    uint64_t server_seq_num;        /* Server sequence number */
    
    /* Certificate */
    uint8_t *server_cert;           /* Server certificate (DER format) */
    uint32_t server_cert_len;       /* Server certificate length */
    const uint8_t **server_cert_chain;      /* Optional intermediate certificates (DER, non-owning) */
    const uint32_t *server_cert_chain_len;  /* Lengths for server_cert_chain entries */
    uint32_t server_cert_chain_count;       /* Number of intermediate certs */
    void *server_cert_parsed;       /* Parsed X.509 certificate (x509_certificate_t*) */
    uint8_t *client_cert;           /* Server: received client certificate (DER, leaf only) */
    uint32_t client_cert_len;       /* Server: received client certificate length */
    void *client_cert_parsed;       /* Server: parsed client certificate (x509_certificate_t*) */

    /** Optional server RSA private key (rsa_key_t*) for Server Key Exchange signature. If set, SKX is signed. */
    void *server_private_rsa;
    /** Optional server ECDSA private key (ecc_key_t*) for ECDHE_ECDSA Server Key Exchange signatures. */
    void *server_private_ecdsa;
    /** Optional ECDSA leaf certificate (DER) for TLS 1.2 when \a server_cert is an RSA fallback (ECDSA-primary servers). */
    const uint8_t *server_ecdsa_leaf_cert;
    uint32_t server_ecdsa_leaf_cert_len;
    /** Optional RSASSA-PSS leaf (DER) + key for TLS 1.2 when the client selects rsa_pss_pss_* only (non-owning pointers). */
    const uint8_t *server_rsa_pss_leaf_cert;
    uint32_t server_rsa_pss_leaf_cert_len;
    void *server_private_rsa_pss_leaf;       /**< rsa_key_t* */
    void *server_rsa_pss_leaf_cert_parsed;   /**< x509_certificate_t*; application-owned (not freed by the library). */
    /** Server: populated by \ref noxtls_tls12_prepare_rsa_server_key_exchange_scheme after ClientHello when RSA SKX signing applies. */
    uint8_t tls12_rsa_skx_scheme_prepared;
    uint16_t tls12_rsa_skx_wire_scheme;
    noxtls_hash_algos_t tls12_rsa_skx_sign_hash;
    uint8_t tls12_rsa_skx_sign_use_pss;           /**< 1: \c noxtls_rsa_sign_pss; 0: PKCS#1 v1.5 \c noxtls_rsa_sign */
    uint8_t tls12_rsa_skx_use_pss_leaf_identity;  /**< 1: send \a server_rsa_pss_leaf_cert and sign with \a server_private_rsa_pss_leaf */
    /** Optional server cipher-suite allowlist (wire IDs). If set, server selects only from this list. */
    const uint16_t *server_cipher_suites;
    /** Number of entries in server_cipher_suites. */
    uint32_t server_cipher_suites_count;
    /** Optional server ALPN protocol list (non-owning pointers). */
    const char **server_alpn_protocols;
    /** Number of entries in server_alpn_protocols. */
    uint32_t server_alpn_count;
    /** Negotiated ALPN protocol from last handshake (owned buffer). */
    uint8_t negotiated_alpn[NOXTLS_TLS_ALPN_MAX_PROTOCOL_LEN + 1u];
    /** Length of negotiated_alpn; 0 when ALPN was not negotiated. */
    uint16_t negotiated_alpn_len;
    /** Server-issued session ID for TLS 1.2 resumption. */
    uint8_t server_session_id[TLS_SESSION_ID_MAX_LEN];
    uint8_t server_session_id_len;
    /** 1 when resuming a previously established session. */
    uint8_t session_resume;
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
    uint8_t pending_app_data[TLS_MAX_RECORD_SIZE]; /* Buffered app-data seen during renegotiation handshake */
    uint32_t pending_app_data_len;   /* Length of pending_app_data */
    
    /* Extensions */
    tls_extensions_t client_extensions;  /* Client Hello extensions */
    tls_extensions_t server_extensions;   /* Server Hello extensions */
    /* RFC 6066 status_request (OCSP stapling) */
    uint8_t client_request_ocsp_status;   /* Client: send status_request extension in ClientHello. */
    uint8_t client_offered_ocsp_status;   /* Server: parsed client status_request(ocsp) extension. */
    uint8_t status_request_negotiated;    /* ServerHello carried status_request (client expects CertificateStatus). */
    const uint8_t *server_ocsp_response;  /* Server: configured stapled OCSP response DER (non-owning). */
    uint32_t server_ocsp_response_len;    /* Server stapled OCSP response length. */
    uint8_t *peer_ocsp_response;          /* Client: received stapled OCSP response DER (owned). */
    uint32_t peer_ocsp_response_len;      /* Client received stapled OCSP response length. */

    /* Client configuration */
    const char *server_name;             /* SNI hostname (optional) */
    uint16_t server_name_len;            /* SNI hostname length */
    /** Server (RFC 6066): if non-NULL, ClientHello host_name must match (ASCII, case-insensitive). */
    const char *server_expect_client_sni;
    /** Server: with \a server_expect_client_sni, send fatal unrecognized_name when set; else warning then continue. */
    uint8_t server_expect_sni_fatal;
    const noxtls_x509_crl_t *verify_crl; /* Optional CRL list for server cert verification (non-owning). */

    /* Renegotiation (RFC 5746): verify_data from previous handshake for renegotiation_info extension */
    uint8_t previous_client_verify_data[48];
    uint8_t previous_server_verify_data[48];
    uint8_t previous_verify_data_len;
    uint8_t renegotiation_in_progress;   /* 1 when handling HelloRequest or received ClientHello (server) */
    uint8_t server_renegotiation_requested; /* 1 after server sent HelloRequest; allows next ClientHello renegotiation */
    uint8_t client_secure_renegotiation_offered; /* RFC 5746: ClientHello included SCSV and/or renegotiation_info */
    uint8_t client_encrypt_then_mac_offered;     /* RFC 7366: ClientHello included encrypt_then_mac extension */
    uint8_t use_encrypt_then_mac;                /* RFC 7366 negotiated for current handshake */
    /** RFC 7627: ClientHello included valid (empty) extended_master_secret extension. */
    uint8_t extended_master_secret_offered;
    /** RFC 7627: ServerHello echoed EMS; master secret uses session hash through ServerHelloDone. */
    uint8_t extended_master_secret_negotiated;
    /** Bytes of ctx->handshake_messages through ServerHelloDone (for EMS session hash). */
    uint32_t ems_session_transcript_len;
    /** When session_resume: EMS flag from session/ticket cache entry (for resume policy). */
    uint8_t session_resume_ems;

    /* TLS 1.0 implicit IV: last cipher block of previous record (per direction) */
    uint8_t client_last_cipher_block[16];
    uint8_t server_last_cipher_block[16];

    /* Reusable record workspace: encrypted/decrypted/handshake buffer (one at a time). Size TLS_MAX_RECORD_SIZE+256. */
    uint8_t *record_workspace;
    uint8_t record_workspace_owned;    /* 1 if allocated by context init, 0 if supplied by caller */
    /* Reusable handshake workspace: build/parse client_hello, certificate, server_key_exchange, etc. (one at a time). Size TLS_HANDSHAKE_WORKSPACE_SIZE. */
    uint8_t *handshake_workspace;
    uint8_t handshake_workspace_owned; /* 1 if allocated by context init, 0 if supplied by caller */

    /* RFC 7250 Raw Public Keys (RPK): certificate type negotiation and result */
    uint8_t server_use_rpk;              /* Server: 1 = send SubjectPublicKeyInfo in Certificate (server_cert holds SPKI DER) */
    uint8_t server_certificate_type;     /* Client: negotiated type from ServerHello ext 20; Server: type we chose (e.g. TLS_CERT_TYPE_RAW_PUBLIC_KEY) */
    uint8_t client_certificate_type;     /* Client: negotiated type from ServerHello ext 19 (for client auth); Server: type we request */
    uint8_t server_cert_is_rpk;          /* Client: 1 after recv_certificate when server sent RPK (server_cert = SubjectPublicKeyInfo; verify out-of-band) */
    uint8_t client_accept_server_rpk;    /* Client: 1 = send server_certificate_type ext with RPK in ClientHello */
    uint8_t client_offer_client_rpk;     /* Client: 1 = send client_certificate_type ext with RPK in ClientHello (for client auth) */
    uint8_t request_client_auth;         /* Server: 1 = send CertificateRequest and process client Certificate/CertificateVerify */
    uint16_t client_hello_version;       /* Server: raw ClientHello legacy_version from peer. */
    /** Server: 1 until first application record is sent as 1 byte then remainder (BEAST interop when
     *  ClientHello legacy_version is TLS 1.0 but the connection negotiates TLS 1.2). */
    uint8_t tls12_beast_split_first_appdata;

    /* RFC 8446 §4.1.3: when 1, ServerHello.random last 8 bytes are fixed for TLS-1.3-capable server negotiating TLS 1.2 (unified API sets this). */
    uint8_t rfc8446_tls13_downgrade_sh_random;

    /* RFC 6066 Maximum Fragment Length: 0 = not used; 1=512, 2=1024, 3=2048, 4=4096 (code). Negotiated max plaintext record payload in bytes. */
    uint8_t max_fragment_length_code;    /* Client: requested code (1-4). Server: selected code echoed in ServerHello. */
    uint16_t max_record_payload;         /* Negotiated max record payload (plaintext). 0 = use TLS_MAX_RECORD_SIZE. */

    /* RFC 6520 Heartbeat */
    uint8_t heartbeat_enabled;           /* Runtime toggle; default 0 after init. 1 = advertise/process RFC 6520 heartbeat. */
    uint8_t heartbeat_negotiated;        /* 1 when heartbeat extension is negotiated for current connection. */
    uint8_t heartbeat_peer_mode;         /* Mode received from peer extension (1 or 2). */
    uint8_t client_heartbeat_mode;       /* Server-side: mode offered by client in ClientHello extension. */
} tls12_context_t;
NOXTLS_MSVC_WARNING_POP



typedef struct {
    uint8_t id[TLS_SESSION_ID_MAX_LEN];
    uint8_t id_len;
    uint8_t master_secret[48];
    uint16_t cipher_suite;
    uint8_t alpn[NOXTLS_TLS_ALPN_MAX_PROTOCOL_LEN + 1u];
    uint16_t alpn_len;
    uint16_t sni_len;
    uint8_t sni[255];
    uint8_t extended_master_secret; /* RFC 7627: session established with EMS */
    uint8_t in_use;
} tls12_session_cache_entry_t;

typedef struct {
    uint8_t ticket[TLS12_TICKET_MAX_LEN];
    uint16_t ticket_len;
    uint8_t master_secret[48];
    uint16_t cipher_suite;
    uint8_t alpn[NOXTLS_TLS_ALPN_MAX_PROTOCOL_LEN + 1u];
    uint16_t alpn_len;
    uint16_t sni_len;
    uint8_t sni[255];
    uint8_t extended_master_secret;
    uint32_t issued_at;
    uint32_t lifetime_hint;
    uint8_t in_use;
} tls12_ticket_cache_entry_t;

/* TLS 1.2 Functions */
noxtls_return_t noxtls_tls12_context_init(tls12_context_t *ctx, tls_role_t role);
/** Initialize context for a specific TLS version (e.g. TLS_VERSION_1_0, TLS_VERSION_1_1, TLS_VERSION_1_2). */
noxtls_return_t noxtls_tls12_context_init_with_version(tls12_context_t *ctx, tls_role_t role, uint16_t version);
noxtls_return_t noxtls_dtls12_context_init(tls12_context_t *ctx, tls_role_t role);
noxtls_return_t noxtls_tls12_context_free(tls12_context_t *ctx);
/**
 * Replace internally allocated TLS 1.2 workspaces with caller-provided buffers.
 * Call after context_init and before connect/accept.
 */
noxtls_return_t tls12_set_workspaces(tls12_context_t *ctx,
                                     uint8_t *record_workspace,
                                     uint32_t record_workspace_len,
                                     uint8_t *handshake_workspace,
                                     uint32_t handshake_workspace_len);
noxtls_return_t noxtls_tls12_connect(tls12_context_t *ctx);
/** Client: resume TLS 1.2 after TLS 1.3 ClientHello + TLS 1.2 ServerHello (takes ownership of both buffers on success). */
noxtls_return_t noxtls_tls12_client_resume_from_tls13_downgrade(tls12_context_t *ctx,
                                                                uint8_t *client_hello_transcript,
                                                                uint32_t client_hello_transcript_len,
                                                                uint8_t *server_hello_handshake,
                                                                uint32_t server_hello_handshake_len);
noxtls_return_t noxtls_tls12_accept(tls12_context_t *ctx);
noxtls_return_t tls12_compute_master_secret(tls12_context_t *ctx, const uint8_t *premaster_secret, uint32_t premaster_secret_len);  /* Compute master secret from premaster secret */
noxtls_return_t tls12_derive_keys(tls12_context_t *ctx);  /* Derive keys from master secret */
noxtls_return_t noxtls_tls12_send(tls12_context_t *ctx, const uint8_t *data, uint32_t len);
noxtls_return_t noxtls_tls12_recv(tls12_context_t *ctx, uint8_t *data, uint32_t *len);
noxtls_return_t noxtls_tls12_close(tls12_context_t *ctx);

/** Server: send HelloRequest to ask client to renegotiate (RFC 5746). */
noxtls_return_t noxtls_tls12_send_hello_request(tls12_context_t *ctx);

/* TLS 1.2 Client Handshake Functions */
noxtls_return_t noxtls_tls12_send_client_hello(tls12_context_t *ctx);
noxtls_return_t noxtls_tls12_recv_server_hello(tls12_context_t *ctx);
noxtls_return_t noxtls_tls12_recv_certificate(tls12_context_t *ctx);
noxtls_return_t noxtls_tls12_recv_server_key_exchange(tls12_context_t *ctx);
noxtls_return_t noxtls_tls12_recv_server_hello_done(tls12_context_t *ctx);
noxtls_return_t noxtls_tls12_send_client_key_exchange(tls12_context_t *ctx);
noxtls_return_t noxtls_tls12_send_change_cipher_spec(tls12_context_t *ctx);
noxtls_return_t noxtls_tls12_send_finished(tls12_context_t *ctx);
noxtls_return_t noxtls_tls12_recv_change_cipher_spec(tls12_context_t *ctx);
noxtls_return_t noxtls_tls12_recv_finished(tls12_context_t *ctx);

/* TLS 1.2 Server Handshake Functions */
noxtls_return_t noxtls_tls12_recv_client_hello(tls12_context_t *ctx);
noxtls_return_t noxtls_tls12_send_server_hello(tls12_context_t *ctx);
noxtls_return_t noxtls_tls12_send_certificate(tls12_context_t *ctx);
noxtls_return_t noxtls_tls12_send_server_key_exchange(tls12_context_t *ctx);
noxtls_return_t noxtls_tls12_send_certificate_request(tls12_context_t *ctx);
noxtls_return_t noxtls_tls12_send_server_hello_done(tls12_context_t *ctx);
noxtls_return_t noxtls_tls12_recv_client_key_exchange(tls12_context_t *ctx);
noxtls_return_t noxtls_tls12_recv_change_cipher_spec_client(tls12_context_t *ctx);
noxtls_return_t noxtls_tls12_recv_finished_client(tls12_context_t *ctx);
noxtls_return_t noxtls_tls12_send_change_cipher_spec_server(tls12_context_t *ctx);
noxtls_return_t noxtls_tls12_send_finished_server(tls12_context_t *ctx);

/** Set server RSA private key (rsa_key_t*) for Server Key Exchange signature. Call before handshake if using ECDHE_RSA. */
void noxtls_tls12_set_server_private_rsa(tls12_context_t *ctx, void *rsa_key);
/** Set server ECDSA private key (ecc_key_t*) for ECDHE_ECDSA Server Key Exchange / CertificateVerify. */
void noxtls_tls12_set_server_private_ecdsa(tls12_context_t *ctx, void *ecc_key);
/** Set optional ECDSA leaf certificate (DER) for Certificate when negotiating ECDHE_ECDSA cipher suites. */
void noxtls_tls12_set_server_ecdsa_leaf_certificate(tls12_context_t *ctx, const uint8_t *der, uint32_t der_len);
/** Optional TLS 1.2 RSASSA-PSS leaf + key for rsa_pss_pss_*-only clients (tlsfuzzer); \a parsed_cert is optional, non-owning. */
void noxtls_tls12_set_server_rsa_pss_leaf_material(tls12_context_t *ctx, const uint8_t *der, uint32_t der_len, void *rsa_key, void *parsed_cert);
/** Server: choose RSA SKX signature scheme from ClientHello \c signature_algorithms (RFC 5246 / PSS code points). */
noxtls_return_t noxtls_tls12_prepare_rsa_server_key_exchange_scheme(tls12_context_t *ctx);
/** Set server cipher-suite allowlist (wire IDs). Call before handshake. */
void noxtls_tls12_set_server_cipher_suites(tls12_context_t *ctx, const uint16_t *suites, uint32_t count);
/** Server: set supported ALPN protocol names (non-owning). */
void noxtls_tls12_set_server_alpn_protocols(tls12_context_t *ctx, const char **protocols, uint32_t count);
/** Server (RFC 6066): require ClientHello SNI host_name to match \a ascii_hostname (case-insensitive). NULL disables. */
void noxtls_tls12_set_server_expected_client_sni(tls12_context_t *ctx, const char *ascii_hostname, int mismatch_fatal);
/** Set optional server certificate chain (intermediate certs only, DER). */
void noxtls_tls12_set_server_certificate_chain(tls12_context_t *ctx,
                                               const uint8_t **certs,
                                               const uint32_t *cert_lens,
                                               uint32_t cert_count);
/** Set optional crypto provider and server key handle for server sign (SKX) and decrypt (Client Key Exchange). Use instead of server_private_rsa when key is in HSM/TPM. */
void noxtls_tls12_set_crypto_provider_server(tls12_context_t *ctx, const noxtls_crypto_provider_t *provider, noxtls_crypto_key_handle_t server_key_handle);
/** Set optional CRL chain for certificate revocation checks during peer cert verification. */
void noxtls_tls12_set_verify_crl(tls12_context_t *ctx, const noxtls_x509_crl_t *crl);
/** RFC 7250: Server uses Raw Public Key. Set server_cert/server_cert_len to SubjectPublicKeyInfo (DER). Call before handshake. */
void noxtls_tls12_set_server_use_rpk(tls12_context_t *ctx, int use_rpk);
/** RFC 7250: Client accepts server RPK (sends server_certificate_type extension). Call before connect. */
void noxtls_tls12_set_client_accept_server_rpk(tls12_context_t *ctx, int accept);
/** RFC 7250: Client can send RPK for client auth (sends client_certificate_type extension). Call before connect. */
void noxtls_tls12_set_client_offer_client_rpk(tls12_context_t *ctx, int offer);
/** Server: request client certificate authentication (TLS 1.2 CertificateRequest). Call before accept. */
void noxtls_tls12_request_client_auth(tls12_context_t *ctx, int request);

/** RFC 6066: Set max fragment length (client or server). code: 0 = disabled, 1=512, 2=1024, 3=2048, 4=4096 bytes. Call before handshake. */
void noxtls_tls12_set_max_fragment_length(tls12_context_t *ctx, uint8_t code);
/** RFC 6520: Enable/disable heartbeat extension and record handling (TLS 1.2). */
void noxtls_tls12_set_heartbeat(tls12_context_t *ctx, int enable);
/** RFC 6066 status_request: Client advertises OCSP stapling request (CertificateStatus). */
void noxtls_tls12_set_client_request_ocsp_status(tls12_context_t *ctx, int enable);
/** RFC 6066 status_request: Server configures stapled OCSP response (DER, non-owning). */
void noxtls_tls12_set_server_ocsp_response(tls12_context_t *ctx, const uint8_t *ocsp_der, uint32_t ocsp_len);
/** RFC 6066 status_request: Client retrieves stapled OCSP response received from peer. */
noxtls_return_t noxtls_tls12_get_peer_ocsp_response(const tls12_context_t *ctx,
                                                    const uint8_t **ocsp_der,
                                                    uint32_t *ocsp_len);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_TLS12_H_ */

