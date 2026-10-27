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
* File:    noxtls_tls13.c
* Summary: TLS 1.3 definitions
*
*****************************************************************************/

#ifndef NOXTLS_TLS13_H_
#define NOXTLS_TLS13_H_

#include <stdbool.h>
#include <stdint.h>

#include "noxtls_common.h"
#include "noxtls_tls_common.h"
#include "noxtls_tls_key_exchange.h"
#include "pkc/dh/noxtls_ffdhe_params.h"
#include "noxtls_dtls_common.h"
#include "noxtls_crypto_provider.h"
#include "mdigest/noxtls_sha.h"
#if NOXTLS_FEATURE_ML_KEM
#include "pkc/mlkem/noxtls_mlkem.h"
#else
typedef uint32_t noxtls_mlkem_param_t;
#ifndef NOXTLS_MLKEM_NONE
#define NOXTLS_MLKEM_NONE ((noxtls_mlkem_param_t)0u)
#endif
#ifndef NOXTLS_MLKEM_512
#define NOXTLS_MLKEM_512 ((noxtls_mlkem_param_t)1u)
#endif
#ifndef NOXTLS_MLKEM_768
#define NOXTLS_MLKEM_768 ((noxtls_mlkem_param_t)2u)
#endif
#ifndef NOXTLS_MLKEM_1024
#define NOXTLS_MLKEM_1024 ((noxtls_mlkem_param_t)3u)
#endif
#ifndef NOXTLS_MLKEM_MAX_PUBLIC_KEY_LEN
#define NOXTLS_MLKEM_MAX_PUBLIC_KEY_LEN 1u
#endif
#ifndef NOXTLS_MLKEM_MAX_SECRET_KEY_LEN
#define NOXTLS_MLKEM_MAX_SECRET_KEY_LEN 1u
#endif
#ifndef NOXTLS_MLKEM_SHARED_SECRET_LEN
#define NOXTLS_MLKEM_SHARED_SECRET_LEN 1u
#endif
#endif

#if NOXTLS_FEATURE_ML_DSA
#include "pkc/mldsa/noxtls_mldsa.h"
#endif
#if NOXTLS_FEATURE_SLH_DSA
#include "pkc/slhdsa/noxtls_slhdsa.h"
#endif
#if NOXTLS_FEATURE_FALCON
#include "pkc/falcon/noxtls_falcon.h"
#endif
#include "common/noxtls_pq_param_typedefs.h"

#ifdef __cplusplus
extern "C" {
#endif

struct noxtls_x509_verify_policy;

/*
 * Buffers of the ServerHello builder: the message and its staged key share entry. They are
 * the largest buffers a handshake message builder takes from the handshake arena when a
 * static-memory connection has no workspace slot (NOXTLS_STATIC_HS_WORKSPACE_IN_ARENA).
 * Without ML-KEM and FFDHE the largest key share entry is a P-521 point (4 + 133 bytes) and
 * the largest ServerHello 129 bytes plus that entry (header, version, random, a 32-byte
 * legacy_session_id, suite, compression, supported_versions, key_share, pre_shared_key and a
 * 32-byte connection_id), so such builds use 512 and 256 bytes; others keep
 * TLS_SERVER_HELLO_DEFAULT_SIZE and TLS_KEY_SHARE_ENTRY_MAX_LEN.
 */
#if defined(NOXTLS_STATIC_HS_WORKSPACE_IN_ARENA) && (NOXTLS_STATIC_HS_WORKSPACE_IN_ARENA != 0) && \
    (NOXTLS_FEATURE_ML_KEM == 0) && (NOXTLS_FEATURE_DH == 0)
#ifndef NOXTLS_TLS13_SERVER_HELLO_ALLOC
#define NOXTLS_TLS13_SERVER_HELLO_ALLOC 512U
#endif
#ifndef NOXTLS_TLS13_SERVER_KEY_SHARE_ALLOC
#define NOXTLS_TLS13_SERVER_KEY_SHARE_ALLOC 256U
#endif
#define NOXTLS_TLS13_SERVER_KEY_SHARE_MIN (4U + 133U)
#define NOXTLS_TLS13_SERVER_HELLO_FIXED_MAX 129U
#else
#ifndef NOXTLS_TLS13_SERVER_HELLO_ALLOC
#define NOXTLS_TLS13_SERVER_HELLO_ALLOC TLS_SERVER_HELLO_DEFAULT_SIZE
#endif
#ifndef NOXTLS_TLS13_SERVER_KEY_SHARE_ALLOC
#define NOXTLS_TLS13_SERVER_KEY_SHARE_ALLOC TLS_KEY_SHARE_ENTRY_MAX_LEN
#endif
#endif

/* Max extension entries in one ClientHello extensions block (65535 bytes / 4 bytes min per ext). */
#define TLS13_CLIENTHELLO_EXT_ORDER_MAX 16384u
#define TLS13_RECORD_WORKSPACE_HALF  (TLS_MAX_RECORD_SIZE + 32U)
#define TLS13_INLINE_KEY_SHARE_MAX_LEN 160U
/* RFC 8446 section 4.2.8: the classical client emits one share, at most
 * 4 header bytes + the 133-byte P-521 public point. PQ builds retain the
 * larger vector and encoder capacities used by ML-KEM/hybrid shares. */
#if NOXTLS_FEATURE_ML_KEM
#define TLS13_CLIENT_KEY_SHARE_VECTOR_CAPACITY 4096U
#define TLS13_CLIENT_KEY_SHARE_ENCODED_CAPACITY TLS_KEY_SHARE_ENTRY_MAX_LEN
#else
#define TLS13_CLIENT_KEY_SHARE_VECTOR_CAPACITY TLS13_INLINE_KEY_SHARE_MAX_LEN
#define TLS13_CLIENT_KEY_SHARE_ENCODED_CAPACITY TLS13_INLINE_KEY_SHARE_MAX_LEN
#endif
/* RFC 9147 4.2.3: largest DTLS 1.3 record-number key (AES-256 / ChaCha20 key length). */
#define TLS13_DTLS_SN_KEY_MAX_LEN 32U
/** Largest TLS 1.3 secret / Finished verify_data: the SHA-384 hash length (RFC 8446 B.4). */
#define TLS13_SECRET_MAX 48U

/* RFC 8446 CertificateVerify signature field capacity (scheme-specific; not always SLH-DSA max). */
#define TLS13_CV_STACK_SIGNATURE_MAX  512U

/* RFC 8446 4.4.3 CertificateVerify signed content: 64 x 0x20 || context string || 0x00 || Transcript-Hash. */
#define TLS13_CV_PAD_LEN                     64U
/* Longest context string the builder accepts ("TLS 1.3, server CertificateVerify" is 33 bytes). */
#define TLS13_CV_CONTEXT_STRING_MAX_LEN      64U
/* Largest transcript hash (SHA-512) that can appear in the signed content. */
#define TLS13_CV_TRANSCRIPT_HASH_MAX_LEN     64U
/* Output capacity that always suffices for noxtls_tls13_certificate_verify_build_signed_content(). */
#define NOXTLS_TLS13_CV_SIGNED_CONTENT_MAX_LEN (TLS13_CV_PAD_LEN + 33U + 1U + TLS13_CV_TRANSCRIPT_HASH_MAX_LEN)

#include "certs/noxtls_x509_crl_fwd.h"

/** Running TLS 1.3 transcript hash (RFC 8446 4.4.1) for the suite hash (SHA-256 or SHA-384). */
typedef union
{
    noxtls_sha_ctx_t sha256;
#if NOXTLS_FEATURE_SHA384
    noxtls_sha512_ctx_t sha384;
#endif
} tls13_transcript_hash_ctx_t;

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

typedef struct
{
    uint64_t recv_client_hello_us;
    uint64_t pick_server_identity_us;
    uint64_t select_certificate_sig_scheme_us;
    uint64_t sni_check_us;
    uint64_t send_server_hello_us;
    uint64_t send_server_hello_key_share_gen_us;
    uint64_t send_server_hello_record_send_us;
    uint64_t send_middlebox_compat_ccs_us;
    uint64_t process_client_key_share_us;
    uint64_t process_client_key_share_compute_secret_us;
    uint64_t process_client_key_share_derive_keys_us;
    uint64_t derive_handshake_keys_us;
    uint64_t send_encrypted_extensions_us;
    uint64_t send_certificate_request_us;
    uint64_t send_certificate_us;
    uint64_t send_certificate_verify_us;
    uint64_t send_certificate_verify_build_tosign_us;
    uint64_t send_certificate_verify_sign_us;
    uint64_t send_certificate_verify_der_encode_us;
    uint64_t send_certificate_verify_record_send_us;
    uint64_t send_finished_us;
    uint64_t derive_application_secrets_us;
    uint64_t install_server_application_write_keys_us;
    uint64_t recv_client_certificate_us;
    uint64_t recv_client_certificate_verify_us;
    uint64_t recv_finished_us;
    uint64_t install_client_application_read_keys_us;
    uint64_t send_new_session_ticket_us;
    uint64_t total_us;
} tls13_accept_timing_t;

/**
 * TLS 1.3 handshake-only state, allocated with the context and released (wiped) when a TLS
 * handshake completes (DTLS 1.3 keeps it until the context is freed: retransmitted flights
 * and late epoch-2 records still need the handshake traffic secrets). Holds the transcript,
 * randoms, key schedule secrets, ephemeral key shares, parsed extensions and the
 * handshake-only configuration (external PSK, private signing keys).
 */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
struct tls13_hs_state_s
{
    uint8_t client_random[32];      /* Client random */
    uint8_t server_random[32];      /* Server random */
    uint8_t client_legacy_session_id[TLS_SESSION_ID_MAX_LEN]; /* ClientHello legacy_session_id to echo in ServerHello */
    uint8_t client_legacy_session_id_len;
    uint8_t early_secret[64];       /* Early secret (max SHA-384) */
    uint8_t handshake_secret[64];    /* Handshake secret */
    uint8_t master_secret[64];       /* Master secret */
    uint8_t client_handshake_traffic_secret[64];  /* Client handshake traffic secret */
    uint8_t server_handshake_traffic_secret[64];  /* Server handshake traffic secret */
    uint8_t client_handshake_sn_key[TLS13_DTLS_SN_KEY_MAX_LEN];
    uint8_t server_handshake_sn_key[TLS13_DTLS_SN_KEY_MAX_LEN];
    uint8_t *handshake_messages;     /* Raw transcript (NULL once transcript_hashing is set) */
    uint8_t transcript_hashing;      /* 1: transcript_ctx holds the running hash */
    noxtls_hash_algos_t transcript_algo;
    tls13_transcript_hash_ctx_t transcript_ctx;
    /** Transcript-Hash(ClientHello..server Finished) for the application traffic secrets. */
    uint8_t app_transcript_hash[TLS_MAX_SECRET_LEN];
    uint8_t app_transcript_hash_len;
    /** Client: TLS 1.2 ServerHello handshake fragment when server negotiates TLS 1.2 after a TLS 1.3 ClientHello (owned). */
    uint8_t *client_tls12_downgrade_server_hello;
    uint32_t client_tls12_downgrade_server_hello_len;
    uint8_t awaiting_hrr_client_hello; /* Server sent HRR and expects second ClientHello */
    uint16_t hrr_selected_group;     /* RFC 8446 §4.2.8: NamedGroup selected by the HRR key_share (0 = none) */
    /** RFC 8446 §4.1.4: cipher_suite of a stateless HelloRetryRequest that the ServerHello must repeat (0 = none). */
    uint16_t hrr_cipher_suite;
    /** RFC 8446 §4.1.2: second ClientHello must use the same extension order as the first; wire types in order (TLS server HRR path). */
    uint16_t *hrr_first_clienthello_ext_order;
    uint32_t hrr_first_clienthello_ext_order_count;
    uint8_t peer_compat_ccs_seen;    /* Number of peer compatibility CCS records accepted during handshake */
    tls13_key_share_entry_t *client_key_shares;  /* Client key shares */
    uint32_t client_key_shares_count;             /* Number of client key shares */
    tls13_key_share_entry_t *server_key_share;   /* Server key share */
    void *ecdhe_ctx;                               /* ECDHE context (tls_ecdhe_context_t*) */
    tls13_key_share_entry_t client_key_share_inline; /* Inline client key share storage for X25519/X448/common ECC cases */
    uint8_t client_key_share_inline_buf[TLS13_INLINE_KEY_SHARE_MAX_LEN];
    tls13_key_share_entry_t server_key_share_inline; /* Inline server key share storage for common small groups */
    uint8_t server_key_share_inline_buf[TLS13_INLINE_KEY_SHARE_MAX_LEN];
    tls_ecdhe_context_t ecdhe_ctx_inline;           /* Inline ECDHE context to avoid heap allocation on embedded clients */
    noxtls_mlkem_param_t selected_mlkem_param;
    uint8_t mlkem_client_public_key[NOXTLS_MLKEM_MAX_PUBLIC_KEY_LEN];
    uint32_t mlkem_client_public_key_len;
    uint8_t mlkem_client_secret_key[NOXTLS_MLKEM_MAX_SECRET_KEY_LEN];
    uint32_t mlkem_client_secret_key_len;
    uint8_t mlkem_server_public_key[NOXTLS_MLKEM_MAX_PUBLIC_KEY_LEN];
    uint32_t mlkem_server_public_key_len;
    uint8_t mlkem_server_secret_key[NOXTLS_MLKEM_MAX_SECRET_KEY_LEN];
    uint32_t mlkem_server_secret_key_len;
    uint8_t hybrid_shared_secret[NOXTLS_MLKEM_SHARED_SECRET_LEN + 64U];
    uint32_t hybrid_shared_secret_len;
#if NOXTLS_FEATURE_DH
    uint8_t ffdhe_shared_secret[NOXTLS_FFDHE_MAX_P_BYTES]; /* RFC 7919; max modulus is FFDHE8192 (server) */
    uint32_t ffdhe_shared_secret_len;
#endif
    tls_extensions_t client_extensions;  /* Client Hello extensions */
    tls_extensions_t server_extensions;  /* Server Hello extensions */
    /** Optional server Ed25519 private key seed (32 bytes) for CertificateVerify. */
    uint8_t server_private_ed25519[32];
    /** Optional server Ed448 private key seed (57 bytes) for CertificateVerify. */
    uint8_t server_private_ed448[57];
    /** Optional server ML-DSA private key for CertificateVerify. */
    uint8_t server_private_mldsa[NOXTLS_MLDSA_MAX_SECRET_KEY_LEN];
    uint32_t server_private_mldsa_len;
    noxtls_mldsa_param_t server_private_mldsa_param;
    /** Optional server SLH-DSA private key for CertificateVerify. */
    uint8_t server_private_slhdsa[NOXTLS_SLHDSA_MAX_SECRET_KEY_LEN];
    uint32_t server_private_slhdsa_len;
    noxtls_slhdsa_param_t server_private_slhdsa_param;
    /** Optional server FALCON private key for CertificateVerify. */
    uint8_t server_private_falcon[NOXTLS_FALCON_MAX_SECRET_KEY_LEN];
    uint32_t server_private_falcon_len;
    noxtls_falcon_param_t server_private_falcon_param;
    uint8_t cert_request_context[32];/* Client: context from CertificateRequest (for client Certificate noxtls_message) */
    uint8_t cert_request_context_len;
    uint8_t client_private_ed25519[32]; /* Client: Ed25519 private key (32-byte seed) for CertificateVerify */
    uint8_t client_private_ed448[57];   /* Client: Ed448 private key (57-byte seed) for CertificateVerify */
    uint8_t client_private_mldsa[NOXTLS_MLDSA_MAX_SECRET_KEY_LEN];
    uint32_t client_private_mldsa_len;
    noxtls_mldsa_param_t client_private_mldsa_param;
    uint8_t client_private_slhdsa[NOXTLS_SLHDSA_MAX_SECRET_KEY_LEN];
    uint32_t client_private_slhdsa_len;
    noxtls_slhdsa_param_t client_private_slhdsa_param;
    uint8_t client_private_falcon[NOXTLS_FALCON_MAX_SECRET_KEY_LEN];
    uint32_t client_private_falcon_len;
    noxtls_falcon_param_t client_private_falcon_param;
    uint8_t psk_identity[256];
    uint16_t psk_identity_len;
    uint8_t psk_key[64];
    uint16_t psk_key_len;
    uint8_t *pending_handshake_msg;
    uint32_t pending_handshake_len;
    uint8_t client_early_traffic_secret[64];
    uint8_t early_write_key[32];
    uint8_t early_write_iv[12];
    uint64_t early_seq_num;
};
NOXTLS_MSVC_WARNING_POP
typedef struct tls13_hs_state_s tls13_hs_state_t;

/** Client: callback that receives the cookie of a DTLS 1.3 HelloRetryRequest (noxtls_dtls13_set_hrr_observer()). */
typedef void (*noxtls_dtls13_hrr_observer_fn)(void *arg, const uint8_t *cookie, uint16_t len);

/* TLS 1.3 Context */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
struct tls13_context_s
{
    dtls_context_t base;            /* Base TLS/DTLS context */
    /** Handshake-only state (NULL once a TLS handshake completed). */
    tls13_hs_state_t *hs;
    
    /* Handshake state */
    uint16_t cipher_suite;          /* Selected cipher suite */
    
    /* Key derivation */
    uint8_t client_application_traffic_secret[TLS13_SECRET_MAX]; /* Client application traffic secret */
    uint8_t server_application_traffic_secret[TLS13_SECRET_MAX]; /* Server application traffic secret */
    
    /* Keys */
    uint8_t client_write_key[32];   /* Client write key */
    uint8_t server_write_key[32];   /* Server write key */
    uint8_t client_write_iv[12];    /* Client write IV */
    uint8_t server_write_iv[12];    /* Server write IV */
#if NOXTLS_FEATURE_DTLS
    /* RFC 9147 §4.2.3: record number encryption keys. sn_key is as long as
     * the AEAD key (16 bytes for AES-128, 32 for AES-256 and ChaCha20-Poly1305). */
    uint8_t client_sn_key[TLS13_DTLS_SN_KEY_MAX_LEN];
    uint8_t server_sn_key[TLS13_DTLS_SN_KEY_MAX_LEN];
#endif
    
    /* Sequence numbers */
    uint64_t client_seq_num;        /* Client sequence number */
    uint64_t server_seq_num;        /* Server sequence number */
    
    /* Certificate */
    uint8_t *server_cert;           /* Server certificate (DER); owned on client path */
    uint32_t server_cert_len;       /* Server certificate length */
    const uint8_t **server_cert_chain;      /* Optional intermediate certificates (DER, non-owning) */
    const uint32_t *server_cert_chain_len;  /* Lengths for server_cert_chain entries */
    uint32_t server_cert_chain_count;       /* Number of intermediate certs */
    void *server_cert_parsed;       /* Parsed X.509 view borrowing server_cert (x509_certificate_t*); released after CertificateVerify unless NOXTLS_TLS_RETAIN_PEER_CERT */
    
    /* Handshake transcript (RFC 8446 4.4.1). Raw bytes are kept only until the handshake hash
     * is fixed (ServerHello: HelloRetryRequest message_hash, PSK binders and the TLS 1.2
     * downgrade need them); afterwards only the running hash is kept and the buffer is freed. */
    uint32_t handshake_messages_len; /* Total transcript bytes */
    /** RFC 8446 7.1 exporter_master_secret and resumption_master_secret (0 length: not derived). */
    uint8_t exporter_master_secret[TLS13_SECRET_MAX];
    uint8_t exporter_master_secret_len;
    uint8_t resumption_master_secret[TLS13_SECRET_MAX];
    uint8_t resumption_master_secret_len;

    /* Pending handshake data from decrypted records */
    uint8_t *handshake_buffer;       /* Decrypted handshake bytes */
    uint32_t handshake_buffer_len;   /* Total bytes in buffer */
    uint32_t handshake_buffer_pos;   /* Read offset in buffer */
    uint8_t handshake_encrypted;     /* Handshake encryption active */
    uint8_t sent_hrr;                /* HRR was sent in this handshake */
    uint8_t received_hrr;            /* Client received HRR and must resend ClientHello with preserved random */
    /** RFC 8446 §5.1: next noxtls_message extracted from buffer starts at a record boundary (must be true for ClientHello, ServerHello, EndOfEarlyData, Finished, KeyUpdate). */
    uint8_t handshake_next_at_record_boundary;
    uint8_t client_handshake_step;     /* Resumable client handshake progress for DTLS/TLS retries */
    uint8_t server_handshake_step;     /* Resumable server handshake progress for DTLS/TLS retries */
    
    /* Key shares */
    uint16_t selected_kex_group;                  /* Negotiated key exchange group (classical/PQ/hybrid) */
    uint8_t selected_kex_is_hybrid;
    
    /* Extensions */

    /* Client configuration */
    const uint8_t *server_name;             /* SNI hostname (optional) */
    uint16_t server_name_len;            /* SNI hostname length */
    /** Server (RFC 6066): if non-NULL, ClientHello host_name must match (ASCII, case-insensitive). */
    const uint8_t *server_expect_client_sni;
    /** Server: with \a server_expect_client_sni, send fatal unrecognized_name when set; else warning then continue. */
    uint8_t server_expect_sni_fatal;
    const noxtls_x509_crl_t *verify_crl; /* Optional CRL list for server cert verification (non-owning). */
    /** Client-only, borrowed explicit server trust/time policy; NULL preserves defaults. */
    const struct noxtls_x509_verify_policy *server_verify_policy;

    /* Runtime cipher preference: 0 = prefer AES-GCM (default), 1 = prefer ChaCha20-Poly1305 */
    uint8_t prefer_chacha20;
    /* Optional server cipher-suite allowlist (wire IDs). If set, server selects only from this list. */
    const uint16_t *server_cipher_suites;
    uint32_t server_cipher_suites_count;
    /* Optional client supported_groups override used when building ClientHello. */
    const uint16_t *client_supported_groups;
    uint32_t client_supported_groups_count;
    /* Optional client signature_algorithms override used when building ClientHello. */
    const uint16_t *client_signature_algorithms;
    uint32_t client_signature_algorithms_count;
    /** Optional server ALPN protocol list (non-owning pointers). */
    const uint8_t **server_alpn_protocols;
    uint32_t server_alpn_count;
    /** Negotiated ALPN protocol from last handshake (owned buffer). */
    uint8_t negotiated_alpn[NOXTLS_TLS_ALPN_MAX_PROTOCOL_LEN + 1U];
    uint16_t negotiated_alpn_len;
#if NOXTLS_TLS13_ACCEPT_TIMING
    /** Last server-side TLS 1.3 accept timing breakdown, populated by noxtls_tls13_accept(). */
    tls13_accept_timing_t last_accept_timing;
#endif

    /** Optional server RSA private key (rsa_key_t*) for CertificateVerify. If set, CertificateVerify is signed with RSA-PSS. */
    void *server_private_rsa;
    /** Optional server ECDSA private key (ecc_key_t*) for CertificateVerify. */
    void *server_private_ecdsa;
    /** 1 when server_private_ed25519 is configured. */
    uint8_t server_cert_use_ed25519;
    /** 1 when server_private_ed448 is configured. */
    uint8_t server_cert_use_ed448;
    uint8_t server_cert_use_mldsa;
    uint8_t server_cert_use_slhdsa;
    uint8_t server_cert_use_falcon;
    /**
     * Optional TLS 1.3 server ECDSA identity matrix: multiple leaf certificates + ECC keys.
     * When server_ecdsa_matrix_count > 0, after ClientHello the server picks the first identity
     * that matches the client's signature_algorithms order (see noxtls_tls13_add_server_ecdsa_identity).
     */
#define TLS13_SERVER_ECDSA_MATRIX_MAX 8U
    const uint8_t *server_ecdsa_matrix_certs[8];
    uint32_t server_ecdsa_matrix_cert_lens[8];
    void *server_ecdsa_matrix_keys[8];
    uint32_t server_ecdsa_matrix_count;
    /** Optional: crypto provider (PKCS#11/TPM/hardware). When set with server_private_key_handle, server sign uses provider instead of server_private_rsa. */
    const noxtls_crypto_provider_t *crypto_provider;
    /** Provider's handle for server RSA private key. Used when crypto_provider is set for server CertificateVerify. */
    noxtls_crypto_key_handle_t server_private_key_handle;

    /* Client certificate authentication (mutual TLS / mTLS) */
    uint8_t request_client_auth;     /* Server: if set, send CertificateRequest and verify client cert */
    uint8_t require_client_auth;     /* Server: if set, missing client cert triggers certificate_required alert */
    uint8_t force_cert_verify_fail;  /* BoGo: force peer certificate verification to fail */
    uint8_t client_auth_requested;   /* Client: set when server sent CertificateRequest */
    uint8_t *client_cert;            /* Client: cert to send (DER). Server: received client cert (owned). */
    uint32_t client_cert_len;
    void *client_cert_parsed;        /* Server: parsed client X.509 view borrowing client_cert (x509_certificate_t*); released after CertificateVerify unless NOXTLS_TLS_RETAIN_PEER_CERT */
    void *client_private_rsa;       /* Client: RSA key (rsa_key_t*) for signing CertificateVerify */
    void *client_private_ecdsa;     /* Client: ECC key (ecc_key_t*) for ECDSA CertificateVerify */
    uint8_t client_cert_use_ed25519;    /* 1 if client_private_ed25519 was set (so use Ed25519 for CertificateVerify) */
    uint8_t client_cert_use_ed448;      /* 1 if client_private_ed448 was set (so use Ed448 for CertificateVerify) */
    uint8_t client_cert_use_mldsa;
    uint8_t client_cert_use_slhdsa;
    uint8_t client_cert_use_falcon;
    /** Provider's handle for client private key (RSA/ECDSA/Ed25519). Used when crypto_provider is set for client CertificateVerify. */
    noxtls_crypto_key_handle_t client_private_key_handle;

    /* External PSK configuration and negotiated PSK mode */
    uint8_t psk_configured;
    uint8_t psk_preferred_mode;
    uint8_t psk_in_use;
    uint8_t psk_use_ecdhe;
    uint16_t psk_selected_identity;

    /* Session ticket (resumption) – client stores one ticket from NewSessionTicket */
    uint8_t ticket_identity[32];
    uint16_t ticket_identity_len;
    uint8_t offered_ticket_identity[32];
    uint16_t offered_ticket_identity_len;
    uint8_t ticket_nonce[32];
    uint8_t ticket_nonce_len;
    uint8_t resumption_psk[TLS13_SECRET_MAX];
    uint8_t resumption_psk_len;
    uint32_t ticket_age_add;
    uint16_t ticket_cipher_suite;
    uint8_t ticket_stored;

    /* Decrypted application data not yet returned by noxtls_tls13_recv: the received record
     * buffer itself (decrypted in place) or accumulated 0-RTT data (server). Owned. */
    uint8_t *pending_app_data;
    uint32_t pending_app_data_off;   /* Read offset into pending_app_data */
    uint32_t pending_app_data_len;   /* Unread bytes at pending_app_data_off */
    uint8_t peer_alert_received;      /* Peer sent alert; close without sending response alert */

    /* Client: handshake noxtls_message pushed back after recv_certificate_request (e.g. server Certificate) */

    /* TLS 1.3 0-RTT (early data): client can send app data before handshake completes when resuming */
    uint8_t early_data_phase;            /* Client: 1 after sending ClientHello with early_data, until EndOfEarlyData */
    uint8_t early_data_accepted;        /* Client: 1 if server sent early_data in EncryptedExtensions */
    uint32_t max_early_data_size;       /* Default 0xFFFFFFFF */
    uint8_t sent_end_of_early_data;
    uint8_t early_data_sent;            /* 1 if noxtls_tls13_send_early_data was used */
    uint8_t client_offered_early_data;  /* Server: 1 if ClientHello contained early_data extension */
    uint8_t end_of_early_data_seen;     /* Server: 1 after receiving EndOfEarlyData from client */
    uint8_t end_of_early_data_appended; /* Server: EndOfEarlyData added to the transcript */

#define DTLS13_MAX_CID_POOL 4U
#if NOXTLS_FEATURE_DTLS
    /* RFC 9147 Connection ID: CID sent by peer (included in records we send); our CID (expected in records we receive) */
    uint8_t peer_connection_id[32];
    uint8_t peer_connection_id_len;
    uint8_t own_connection_id[32];
    uint8_t own_connection_id_len;
    uint8_t peer_spare_connection_ids[DTLS13_MAX_CID_POOL][32];
    uint8_t peer_spare_connection_id_lens[DTLS13_MAX_CID_POOL];
    uint8_t peer_spare_connection_id_count;
    uint8_t own_spare_connection_ids[DTLS13_MAX_CID_POOL][32];
    uint8_t own_spare_connection_id_lens[DTLS13_MAX_CID_POOL];
    uint8_t own_spare_connection_id_count;
    uint8_t cid_request_outstanding;
    uint8_t cid_new_outstanding;
    /** 1: the server sends own_connection_id (noxtls_dtls13_set_own_connection_id()) instead of echoing the client's. */
    uint8_t own_connection_id_fixed;
    /** RFC 9146 6: the last ciphertext record consumed by accept/recv, and whether it was the newest. */
    uint8_t last_record_consumed;
    uint8_t last_record_newest;
    uint8_t newest_record_valid;
    uint64_t newest_record_epoch;    /* Full epoch of the newest record accepted so far */
    uint64_t newest_record_seq;      /* Its record number */
    /** Client: noxtls_dtls13_set_hrr_observer() callback and argument. */
    noxtls_dtls13_hrr_observer_fn hrr_observer;
    void *hrr_observer_arg;
    /** Server cookie exchange: 0 = NoxTLS cookie HelloRetryRequest (default), 1 = none
     *  (noxtls_dtls13_set_cookie_exchange()), 2 = the caller verified a stateless cookie. */
    uint8_t dtls_cookie_mode;
    /** 1: PSK binders and resumption secrets use the TLS 1.3 "tls13 " labels, as NoxTLS
     *  did before it followed RFC 9147 Section 5.9 (noxtls_dtls13_set_legacy_psk_labels()). */
    uint8_t dtls_legacy_psk_labels;
#endif

    /* DTLS 1.3 record workspace (inner plaintext + DTLSCiphertext), allocated on first DTLS use.
     * TLS 1.3 protects and opens records in place (record TX buffer / received record). */
    uint8_t *record_workspace;
    uint8_t record_workspace_owned;    /* 1 if allocated by context init, 0 if supplied by caller */
    /* Reusable handshake workspace: build/parse client_hello, certificate, certificate_verify, etc. (one at a time). Size TLS_HANDSHAKE_WORKSPACE_SIZE. */
    uint8_t *handshake_workspace;
    uint8_t handshake_workspace_owned; /* 1 if allocated by context init, 0 if supplied by caller */

    /* RFC 5929 channel binding: first TLS Finished noxtls_message (verify_data). In TLS 1.3 the first Finished is the server's. */
    uint8_t channel_binding_first_finished[TLS13_SECRET_MAX];
    uint32_t channel_binding_first_finished_len;

    /* RFC 8449 Record Size Limit: max plaintext we may send (peer's limit); max we accept (our advertised limit). 0 = use TLS_MAX_RECORD_SIZE. */
    uint16_t record_size_limit_send;   /* Do not send records larger than this (0 = TLS_MAX_RECORD_SIZE). */
    uint16_t record_size_limit_recv;   /* We advertised this as max we accept; peer must not send larger (0 = use default). */
    uint8_t record_size_limit_acked;   /* The peer acknowledged our record_size_limit (RFC 8449). */
    uint8_t record_size_limit_off;     /* Do not negotiate record_size_limit (neither offer nor acknowledge). */
    /** Client (RFC 7507): include TLS_FALLBACK_SCSV in ClientHello cipher suites. */
    uint8_t client_send_fallback_scsv;

    /* Consecutive empty app-data records / warning alerts (BoringSSL-compatible limits). */
    uint8_t empty_record_count;
    uint8_t warning_alert_count;

    /** RFC 8446 4.2.11: identity of the PSK the handshake selected, kept after the
     *  handshake state is released (noxtls_tls13_selected_psk_identity()). */
    uint8_t selected_psk_identity[NOXTLS_TLS13_SELECTED_PSK_IDENTITY_MAX];
    uint16_t selected_psk_identity_len;
    /** 0: none selected, 1: kept, 2: longer than NOXTLS_TLS13_SELECTED_PSK_IDENTITY_MAX. */
    uint8_t selected_psk_identity_state;
};
#ifndef NOXTLS_TLS13_CONTEXT_T_DEFINED
#define NOXTLS_TLS13_CONTEXT_T_DEFINED
typedef struct tls13_context_s tls13_context_t;
#endif

/** Portable client-side state required to resume a TLS 1.3 ticket. */
typedef struct {
    uint8_t ticket_identity[32];
    uint16_t ticket_identity_len;
    uint8_t ticket_nonce[32];
    uint8_t ticket_nonce_len;
    uint8_t resumption_psk[64];
    uint8_t resumption_psk_len;
    uint32_t ticket_age_add;
    uint16_t ticket_cipher_suite;
} noxtls_tls13_session_t;

/** Copy the current client resumption ticket into caller-owned storage. */
noxtls_return_t noxtls_tls13_session_export(
    const tls13_context_t *ctx, noxtls_tls13_session_t *session);

/** Install caller-owned client resumption state before ClientHello is sent. */
noxtls_return_t noxtls_tls13_session_import(
    tls13_context_t *ctx, const noxtls_tls13_session_t *session);
NOXTLS_MSVC_WARNING_POP

/** CertificateVerify handshake message buffer (stack for classical, heap for large PQ sigs). */
typedef struct {
    uint8_t *buf;
    uint32_t cap;
    uint8_t stack_storage[8U + TLS13_CV_STACK_SIGNATURE_MAX];
} tls13_cv_msg_buf_t;

#define TLS13_PSK_KE_MODE_PSK_KE 0
#define TLS13_PSK_KE_MODE_PSK_DHE_KE 1

/* TLS 1.3 Functions */
noxtls_return_t noxtls_tls13_context_init(tls13_context_t *ctx, tls_role_t role);
noxtls_return_t noxtls_dtls13_context_init(tls13_context_t *ctx, tls_role_t role);
noxtls_return_t noxtls_tls13_context_init_with_workspaces(tls13_context_t *ctx,
                                                          tls_role_t role,
                                                          uint8_t *record_workspace,
                                                          uint32_t record_workspace_len,
                                                          uint8_t *handshake_workspace,
                                                          uint32_t handshake_workspace_len);
noxtls_return_t noxtls_dtls13_context_init_with_workspaces(tls13_context_t *ctx,
                                                           tls_role_t role,
                                                           uint8_t *record_workspace,
                                                           uint32_t record_workspace_len,
                                                           uint8_t *handshake_workspace,
                                                           uint32_t handshake_workspace_len);
noxtls_return_t noxtls_tls13_context_free(tls13_context_t *ctx);
/**
 * Replace internally allocated TLS 1.3 workspaces with caller-provided buffers.
 * Call after context_init and before connect/accept.
 */
noxtls_return_t tls13_set_workspaces(tls13_context_t *ctx,
                                     uint8_t *record_workspace,
                                     uint32_t record_workspace_len,
                                     uint8_t *handshake_workspace,
                                     uint32_t handshake_workspace_len);
noxtls_return_t noxtls_tls13_connect(tls13_context_t *ctx);
noxtls_return_t noxtls_tls13_accept(tls13_context_t *ctx);
/** Last accept step that failed (empty if none); for embedded logging after a failed accept. */
const uint8_t *noxtls_tls13_last_accept_fail_step(void);
/** Last connect step that failed (empty if none); for embedded logging after a failed connect. */
const uint8_t *noxtls_tls13_last_connect_fail_step(void);

/** Records of a handshake kept by noxtls_tls13_last_handshake_diag(). */
#define NOXTLS_TLS13_DIAG_RECORDS 16U
/** Certificates of a server Certificate message kept by noxtls_tls13_last_handshake_diag(). */
#define NOXTLS_TLS13_DIAG_CERTS 8U

/**
 * Sizes seen by the last TLS (stream) client handshake, for logs. No record or
 * certificate contents are kept: types, lengths and counts only.
 */
typedef struct
{
    uint16_t records;                                  /**< Records received, the refused one included. */
    uint8_t record_type[NOXTLS_TLS13_DIAG_RECORDS];    /**< Outer content type of the first records. */
    uint16_t record_length[NOXTLS_TLS13_DIAG_RECORDS]; /**< Their TLSCiphertext lengths. */
    uint16_t max_record_length;                        /**< Largest TLSCiphertext length. */
    uint8_t record_refused;                            /**< The last record exceeded the receive ceiling. */
    uint8_t rsl_acknowledged;                          /**< EncryptedExtensions carried record_size_limit. */
    uint16_t rsl_offered;                              /**< record_size_limit sent in ClientHello (0: none). */
    uint16_t rsl_value;                                /**< The server's record_size_limit. */
    uint32_t rx_record_limit;                          /**< TLSCiphertext ceiling in force. */
    uint8_t certificates;                              /**< Entries in the server Certificate. */
    uint16_t certificate_der[NOXTLS_TLS13_DIAG_CERTS]; /**< DER size of the first entries. */
    uint32_t certificate_message;                      /**< Certificate message length, header included. */
    noxtls_return_t result;                            /**< Failing return code, or NOXTLS_RETURN_SUCCESS. */
    uint32_t arena_peak;                               /**< Handshake arena high-water mark (static memory). */
    uint32_t arena_capacity;                           /**< Handshake arena capacity (static memory). */
} noxtls_tls13_handshake_diag_t;

/** Sizes of the last TLS (stream) client handshake; reset when one starts. */
const noxtls_tls13_handshake_diag_t *noxtls_tls13_last_handshake_diag(void);

/**
 * Negotiate RFC 8449 record_size_limit (default) or not. With @p enabled 0 a client
 * does not offer it and a server neither acknowledges nor honours a client's offer,
 * like an implementation without the extension.
 */
void noxtls_tls13_set_record_size_limit_negotiation(tls13_context_t *ctx, uint8_t enabled);

/** 1 when the peer acknowledged this endpoint's record_size_limit (RFC 8449), else 0. */
uint8_t noxtls_tls13_record_size_limit_acknowledged(const tls13_context_t *ctx);
noxtls_return_t noxtls_tls13_send(tls13_context_t *ctx, const uint8_t *data, uint32_t len);
noxtls_return_t noxtls_tls13_recv(tls13_context_t *ctx, uint8_t *data, uint32_t *len);
noxtls_return_t noxtls_tls13_close(tls13_context_t *ctx);
noxtls_return_t noxtls_tls13_send_key_update(tls13_context_t *ctx, uint8_t request_update);
noxtls_return_t noxtls_dtls13_send_request_connection_id(tls13_context_t *ctx, uint8_t num_cids);
noxtls_return_t noxtls_dtls13_send_new_connection_id(tls13_context_t *ctx, const uint8_t *cid, uint8_t cid_len, uint8_t usage);
noxtls_return_t noxtls_dtls13_send_new_connection_ids(tls13_context_t *ctx, uint8_t num_cids, uint8_t usage);
noxtls_return_t noxtls_dtls13_rotate_connection_id(tls13_context_t *ctx);

/** Client: send 0-RTT early data (only when resuming and before handshake completes). */
noxtls_return_t noxtls_tls13_send_early_data(tls13_context_t *ctx, const uint8_t *data, uint32_t len);
void noxtls_tls13_set_keylog_file(const uint8_t *path);

/** Set runtime cipher preference: prefer_chacha20 0 = prefer AES-GCM, 1 = prefer ChaCha20-Poly1305. Call before handshake. */
void noxtls_tls13_set_prefer_chacha20(tls13_context_t *ctx, int prefer_chacha20);
void noxtls_tls13_set_client_fallback_scsv(tls13_context_t *ctx, int enable);
/** Set server cipher-suite allowlist (wire IDs). Call before handshake. */
void noxtls_tls13_set_server_cipher_suites(tls13_context_t *ctx, const uint16_t *suites, uint32_t count);
/** Override the client's supported_groups list used for ClientHello construction. Call before handshake. */
void noxtls_tls13_set_client_supported_groups(tls13_context_t *ctx, const uint16_t *groups, uint32_t count);
/** Override the client's signature_algorithms list used for ClientHello construction. Call before handshake. */
void noxtls_tls13_set_client_signature_algorithms(tls13_context_t *ctx, const uint16_t *algorithms, uint32_t count);
/** Server: set supported ALPN protocol names (non-owning). */
void noxtls_tls13_set_server_alpn_protocols(tls13_context_t *ctx, const uint8_t **protocols, uint32_t count);
/** Server (RFC 6066): require ClientHello SNI host_name to match \a ascii_hostname (case-insensitive). NULL disables. */
void noxtls_tls13_set_server_expected_client_sni(tls13_context_t *ctx, const uint8_t *ascii_hostname, int mismatch_fatal);
/** Set optional server certificate chain (intermediate certs only, DER). */
void noxtls_tls13_set_server_certificate_chain(tls13_context_t *ctx,
                                               const uint8_t **certs,
                                               const uint32_t *cert_lens,
                                               uint32_t cert_count);

/** Set server RSA private key (rsa_key_t*) for CertificateVerify. Call before handshake if using server auth with RSA. */
void noxtls_tls13_set_server_private_rsa(tls13_context_t *ctx, void *rsa_key);
/** Set server ECDSA private key (ecc_key_t*) for CertificateVerify. Call before handshake for ECDSA certs. */
void noxtls_tls13_set_server_private_ecdsa(tls13_context_t *ctx, void *ecc_key);
/** Clear TLS 1.3 server ECDSA identity matrix (does not free keys or certs; app-owned). */
void noxtls_tls13_clear_server_ecdsa_identities(tls13_context_t *ctx);
/**
 * Add one ECDSA server identity (DER leaf cert + ecc_key_t*) for TLS 1.3 matrix selection.
 * Mutually exclusive with noxtls_tls13_set_server_private_rsa / set_server_private_ed25519 / set_server_private_ed448 / set_server_private_mldsa on first add.
 * Call only before noxtls_tls13_accept; max TLS13_SERVER_ECDSA_MATRIX_MAX entries.
 */
noxtls_return_t noxtls_tls13_add_server_ecdsa_identity(tls13_context_t *ctx,
                                                     const uint8_t *cert_der,
                                                     uint32_t cert_len,
                                                     void *ecc_key);
/** Set server Ed25519 private key seed (32 bytes) for CertificateVerify. Call before handshake for Ed25519 certs. */
noxtls_return_t noxtls_tls13_set_server_private_ed25519(tls13_context_t *ctx, const uint8_t *private_key_32);
/** Set server Ed448 private key seed (57 bytes) for CertificateVerify. Call before handshake for Ed448 certs. */
noxtls_return_t noxtls_tls13_set_server_private_ed448(tls13_context_t *ctx, const uint8_t *private_key_57);
#if NOXTLS_FEATURE_ML_DSA
/** Set server ML-DSA private key for CertificateVerify. */
noxtls_return_t noxtls_tls13_set_server_private_mldsa(tls13_context_t *ctx, noxtls_mldsa_param_t param, const uint8_t *private_key);
#endif /* NOXTLS_FEATURE_ML_DSA */
#if NOXTLS_FEATURE_SLH_DSA
/** Set server SLH-DSA private key for CertificateVerify. */
noxtls_return_t noxtls_tls13_set_server_private_slhdsa(tls13_context_t *ctx,
                                                       noxtls_slhdsa_param_t param,
                                                       const uint8_t *private_key);
#endif /* NOXTLS_FEATURE_SLH_DSA */
#if NOXTLS_FEATURE_FALCON
/** Set server FALCON private key for CertificateVerify. */
noxtls_return_t noxtls_tls13_set_server_private_falcon(tls13_context_t *ctx,
                                                       noxtls_falcon_param_t param,
                                                       const uint8_t *private_key);
#endif /* NOXTLS_FEATURE_FALCON */
/** Set optional crypto provider and server key handle for server sign (CertificateVerify). Use instead of server_private_rsa when key is in HSM/TPM. */
void noxtls_tls13_set_crypto_provider_server(tls13_context_t *ctx, const noxtls_crypto_provider_t *provider, noxtls_crypto_key_handle_t server_key_handle);
/** Set optional CRL chain for certificate revocation checks during peer cert verification. */
void noxtls_tls13_set_verify_crl(tls13_context_t *ctx, const noxtls_x509_crl_t *crl);
/** @brief Set a client context's explicit server-certificate policy before connect.
 * @param[in,out] ctx TLS context, or NULL (ignored).
 * @param[in] policy Borrowed until context free; NULL restores global trust/system time.
 * @return None. Server-auth EKU and TLS hostname/CertificateVerify checks remain mandatory.
 * If a context CRL is also configured it is retained; conflicting CRLs are refused. */
void noxtls_tls13_set_server_verify_policy(tls13_context_t *ctx,
    const struct noxtls_x509_verify_policy *policy);

/** Server: request client certificate (mutual TLS). Call before noxtls_tls13_accept. */
void noxtls_tls13_request_client_auth(tls13_context_t *ctx, int request);
/** Server: require client certificate (implies request). Missing cert -> certificate_required alert. */
void noxtls_tls13_require_client_auth(tls13_context_t *ctx, int require);

/** Force peer certificate verification to fail (BoGo -verify-fail). */
void noxtls_tls13_set_force_cert_verify_fail(tls13_context_t *ctx, int enable);

/** Client: set client certificate and RSA private key for mutual TLS. Call before noxtls_tls13_connect. cert in DER; rsa_key is rsa_key_t*. */
noxtls_return_t noxtls_tls13_set_client_cert(tls13_context_t *ctx, const uint8_t *cert_der, uint32_t cert_len, void *rsa_key);
/** Client: set client certificate and ECDSA private key (ecc_key_t*) for CertificateVerify. Use for ECDSA P-256/P-384 certs. */
noxtls_return_t noxtls_tls13_set_client_cert_ecdsa(tls13_context_t *ctx, const uint8_t *cert_der, uint32_t cert_len, void *ecc_key);
/** Client: set client certificate and Ed25519 private key (32-byte seed) for CertificateVerify. */
noxtls_return_t noxtls_tls13_set_client_cert_ed25519(tls13_context_t *ctx, const uint8_t *cert_der, uint32_t cert_len, const uint8_t *private_key_32);
/** Client: set client certificate and Ed448 private key (57-byte seed) for CertificateVerify. Requires NOXTLS_FEATURE_ED448 and SHA3. */
noxtls_return_t noxtls_tls13_set_client_cert_ed448(tls13_context_t *ctx, const uint8_t *cert_der, uint32_t cert_len, const uint8_t *private_key_57);
#if NOXTLS_FEATURE_ML_DSA
/** Client: set client certificate and ML-DSA private key for CertificateVerify. */
noxtls_return_t tls13_set_client_cert_mldsa(tls13_context_t *ctx, const uint8_t *cert_der, uint32_t cert_len,
                                            noxtls_mldsa_param_t param, const uint8_t *private_key);
#endif /* NOXTLS_FEATURE_ML_DSA */
#if NOXTLS_FEATURE_SLH_DSA
/** Client: set client certificate and SLH-DSA private key for CertificateVerify. */
noxtls_return_t tls13_set_client_cert_slhdsa(tls13_context_t *ctx,
                                             const uint8_t *cert_der,
                                             uint32_t cert_len,
                                             noxtls_slhdsa_param_t param,
                                             const uint8_t *private_key);
#endif /* NOXTLS_FEATURE_SLH_DSA */
#if NOXTLS_FEATURE_FALCON
/** Client: set client certificate and FALCON private key for CertificateVerify. */
noxtls_return_t tls13_set_client_cert_falcon(tls13_context_t *ctx,
                                             const uint8_t *cert_der,
                                             uint32_t cert_len,
                                             noxtls_falcon_param_t param,
                                             const uint8_t *private_key);
#endif /* NOXTLS_FEATURE_FALCON */

/** Configure external PSK identity/key for TLS 1.3 PSK or ECDHE-PSK handshakes. */
noxtls_return_t tls13_set_external_psk(tls13_context_t *ctx,
                                       const uint8_t *identity, uint16_t identity_len,
                                       const uint8_t *psk_key, uint16_t psk_key_len,
                                       uint8_t preferred_mode);

/** RFC 5929 channel binding types for noxtls_tls13_get_channel_binding. */
#define NOXTLS_TLS_CHANNEL_BINDING_TLS_UNIQUE           1U
#define NOXTLS_TLS_CHANNEL_BINDING_TLS_SERVER_END_POINT 2U

/**
 * Get TLS channel binding data (RFC 5929). Call after handshake completes.
 * @param ctx TLS 1.3 context.
 * @param binding_type NOXTLS_TLS_CHANNEL_BINDING_TLS_UNIQUE (first Finished verify_data) or NOXTLS_TLS_CHANNEL_BINDING_TLS_SERVER_END_POINT (hash of server cert).
 * @param out Output buffer for binding data.
 * @param out_len On input: buffer size; on success: bytes written (tls-unique: 32 or 48; tls-server-end-point: 32 or 48).
 * @return NOXTLS_RETURN_SUCCESS on success; NOXTLS_RETURN_FAILED if binding not available or invalid type.
 */
noxtls_return_t noxtls_tls13_get_channel_binding(tls13_context_t *ctx, uint32_t binding_type, uint8_t *out, uint32_t *out_len);

/**
 * RFC 8446 Section 7.5 TLS exporter. Call only after the handshake has
 * completed. The label is supplied without the "tls13 " prefix.
 */
noxtls_return_t noxtls_tls13_export_keying_material(
    tls13_context_t *ctx,
    const uint8_t *label, uint32_t label_len,
    const uint8_t *context, uint32_t context_len,
    uint8_t *output, uint32_t output_len);

/** RFC 8449: Set record size limit we advertise (max plaintext we are willing to receive). 0 = use default (16384). Call before handshake. */
void noxtls_tls13_set_record_size_limit(tls13_context_t *ctx, uint16_t limit);

/* ---- Single-association support: DTLS 1.3 connection ID, stateless HelloRetryRequest
 *      and handshake-state release.
 *      Error codes: NOXTLS_RETURN_INVALID_PARAM (bad parameter), NOXTLS_RETURN_BAD_DATA
 *      (malformed input), NOXTLS_RETURN_BUFFER_TOO_SMALL, NOXTLS_RETURN_AUTH_FAILED (binder),
 *      NOXTLS_RETURN_BAD_STATE (connection state). */

/** Largest cookie accepted by noxtls_dtls13_stateless_hrr() and the second-ClientHello calls. */
#define NOXTLS_DTLS13_STATELESS_COOKIE_MAX 255U
/** HelloRetryRequest handshake message without its cookie bytes: header, version, random,
 *  longest legacy_session_id, suite, compression, extensions length and the
 *  supported_versions, key_share and cookie extensions without the cookie. */
#define NOXTLS_DTLS13_HRR_MESSAGE_FIXED_MAX 94U
/** Bytes of a stateless HelloRetryRequest datagram (record and DTLS handshake headers). */
#define NOXTLS_DTLS13_STATELESS_HRR_MAX(cookie_len) \
    (13U + 8U + NOXTLS_DTLS13_HRR_MESSAGE_FIXED_MAX + (uint32_t)(cookie_len))
/** Scratch that noxtls_dtls13_ch2_binder_check() needs for a second ClientHello datagram. */
#define NOXTLS_DTLS13_CH2_BINDER_SCRATCH(ch2_len, cookie_len) \
    ((uint32_t)(ch2_len) + 36U + NOXTLS_DTLS13_HRR_MESSAGE_FIXED_MAX + (uint32_t)(cookie_len))

/**
 * N1. Server: use @p cid as this endpoint's DTLS 1.3 connection ID (RFC 9146 Section 3;
 * RFC 9147 Sections 4 and 9; the extension is carried in ClientHello and ServerHello,
 * RFC 9146 Section 3 and RFC 9147 Section 9.1). Call after context init and before accept.
 * The ServerHello connection_id extension then carries @p cid instead of an echo of the
 * client's value, the CID the client offers (possibly empty) becomes peer_connection_id,
 * and received unified headers with the C bit are parsed with the length of @p cid. When
 * the client does not offer the extension no CID is negotiated (own_connection_id_len
 * becomes 0). A client needs no call: it offers an empty CID and puts the server's CID in
 * every ciphertext record it sends.
 * @return NOXTLS_RETURN_SUCCESS; NOXTLS_RETURN_INVALID_PARAM for a NULL argument, a length
 *         of 0 or above 32, a client or non-DTLS 1.3 context, or once the handshake started.
 */
noxtls_return_t noxtls_dtls13_set_own_connection_id(tls13_context_t *ctx, const uint8_t *cid, uint8_t cid_len);

/**
 * N2. true when the last ciphertext record that the latest noxtls_tls13_accept() or
 * noxtls_tls13_recv() call consumed authenticated and is newer, in epoch and record number,
 * than every record accepted before it (RFC 9146 Section 6; RFC 9147 Sections 4.2.2 and
 * 4.5.1). false when that call consumed no ciphertext record (a replayed or invalid one is
 * not consumed).
 */
bool noxtls_dtls13_last_record_is_newest(const tls13_context_t *ctx);

/**
 * N3a. Build a complete epoch-0 HelloRetryRequest datagram for the ClientHello datagram
 * @p ch1 without any context (RFC 9147 Section 5.1; RFC 8446 Sections 4.1.4 and 4.2.2).
 * The message echoes legacy_session_id, selects @p cipher_suite (a SHA-256 TLS 1.3 suite
 * that CH1 offers), carries a key_share for @p group when it is not 0 (a group CH1 lists in
 * supported_groups without a share, RFC 8446 Section 4.2.8) and the @p cookie extension.
 * The record reuses CH1's record sequence number and the handshake message CH1's
 * message_seq. noxtls_dtls13_ch2_binder_check() and noxtls_dtls13_accept_after_stateless_hrr()
 * rebuild the same message from the second ClientHello with the same @p cipher_suite and
 * @p group.
 * @param[in] ch1 Datagram holding exactly one unfragmented ClientHello record.
 * @param[out] out Datagram; NOXTLS_DTLS13_STATELESS_HRR_MAX(cookie_len) bytes always suffice.
 * @return NOXTLS_RETURN_SUCCESS; NOXTLS_RETURN_INVALID_PARAM for a NULL pointer, an empty or
 *         too long cookie, or a suite or group that CH1 does not allow; NOXTLS_RETURN_BAD_DATA
 *         for a malformed CH1; NOXTLS_RETURN_BUFFER_TOO_SMALL when @p cap is short (*out_len
 *         is then the size needed).
 */
noxtls_return_t noxtls_dtls13_stateless_hrr(const uint8_t *ch1, uint32_t ch1_len,
                                            const uint8_t *cookie, uint16_t cookie_len,
                                            uint16_t cipher_suite, uint16_t group,
                                            uint8_t *out, uint32_t cap, uint32_t *out_len);

/**
 * N3b. Client: call @p fn synchronously with the cookie of every DTLS 1.3 HelloRetryRequest,
 * before the second ClientHello is sent (NULL and 0 when the HelloRetryRequest carries no
 * cookie). @p fn NULL removes the observer.
 * @return NOXTLS_RETURN_SUCCESS; NOXTLS_RETURN_INVALID_PARAM for a NULL @p ctx or a server or
 *         non-DTLS 1.3 context.
 */
noxtls_return_t noxtls_dtls13_set_hrr_observer(tls13_context_t *ctx, noxtls_dtls13_hrr_observer_fn fn, void *arg);

/**
 * SHA-256 over the msg_type, length and body of the ClientHello in a datagram, without
 * message_seq and the fragment fields (the transcript form, RFC 9147 Section 5.2): the value
 * of the synthetic message_hash (RFC 8446 Section 4.4.1) that noxtls_dtls13_ch2_binder_check()
 * and noxtls_dtls13_accept_after_stateless_hrr() take as @p ch1_hash. Only the framing is
 * checked: one epoch-0 record holding one unfragmented ClientHello.
 * @return NOXTLS_RETURN_SUCCESS; NOXTLS_RETURN_INVALID_PARAM; NOXTLS_RETURN_BAD_DATA.
 */
noxtls_return_t noxtls_dtls13_client_hello_hash(const uint8_t *ch, uint32_t ch_len, uint8_t hash[32]);

/**
 * N4a. Verify the external PSK binder of the second ClientHello datagram @p ch2 for
 * @p identity and @p psk over message_hash(CH1) || HelloRetryRequest || Truncate(CH2)
 * (RFC 8446 Sections 4.2.11.2 and 4.4.1). The HelloRetryRequest is rebuilt from CH2
 * (legacy_session_id, cookie) and the @p cipher_suite and @p group that were given to
 * noxtls_dtls13_stateless_hrr(). No context is touched, nothing is allocated, and only
 * @p scratch is written: NOXTLS_DTLS13_CH2_BINDER_SCRATCH(len, cookie length) bytes, wiped
 * before the call returns.
 * @return NOXTLS_RETURN_SUCCESS when the binder verifies; NOXTLS_RETURN_AUTH_FAILED for a
 *         wrong binder or an identity CH2 does not offer; NOXTLS_RETURN_BAD_DATA for a
 *         malformed CH2 (no cookie, or a suite or key_share that contradicts the
 *         HelloRetryRequest); NOXTLS_RETURN_BUFFER_TOO_SMALL; NOXTLS_RETURN_INVALID_PARAM.
 */
noxtls_return_t noxtls_dtls13_ch2_binder_check(const uint8_t *ch2, uint32_t len,
                                               const uint8_t ch1_hash[32],
                                               uint16_t cipher_suite, uint16_t group,
                                               const uint8_t *identity, uint16_t identity_len,
                                               const uint8_t *psk, uint16_t psk_len,
                                               uint8_t *scratch, uint32_t scratch_len);

/**
 * N4b. Server: on a freshly initialized DTLS 1.3 context with its external PSK installed,
 * seed the transcript with message_hash(CH1) and the HelloRetryRequest that
 * noxtls_dtls13_stateless_hrr() built (rebuilt from @p ch2 with @p cipher_suite and
 * @p group), then process the second ClientHello datagram @p ch2 as noxtls_tls13_accept()
 * does. The caller verified the cookie, so the peer counts as validated (RFC 9147 Section
 * 5.1). The ServerHello repeats @p cipher_suite (RFC 8446 Section 4.1.4) and continues the
 * record and message sequence numbers after the HelloRetryRequest. Later calls use
 * noxtls_tls13_accept().
 * @return As noxtls_tls13_accept(); NOXTLS_RETURN_INVALID_PARAM when @p ctx is not a fresh
 *         DTLS 1.3 server context or a parameter is invalid; NOXTLS_RETURN_BAD_DATA for a
 *         malformed @p ch2.
 */
noxtls_return_t noxtls_dtls13_accept_after_stateless_hrr(tls13_context_t *ctx, const uint8_t ch1_hash[32],
                                                         uint16_t cipher_suite, uint16_t group,
                                                         const uint8_t *ch2, uint32_t len);

/**
 * Server: run (@p enabled 1, the default) or skip (0) the NoxTLS DTLS 1.3 cookie exchange
 * (RFC 9147 Section 5.1). With 0, a ClientHello that needs no other HelloRetryRequest is
 * answered with the ServerHello at once; an application that admits clients itself (with
 * noxtls_dtls13_stateless_hrr() when it needs a cookie) uses it. Call before accept.
 * @return NOXTLS_RETURN_SUCCESS; NOXTLS_RETURN_INVALID_PARAM for a NULL, client or
 *         non-DTLS 1.3 context, or once the handshake started.
 */
noxtls_return_t noxtls_dtls13_set_cookie_exchange(tls13_context_t *ctx, uint8_t enabled);

/**
 * DTLS 1.3: derive the PSK binders and the resumption secrets ("ext binder", "res binder",
 * "finished" of the binder key, "res master", "resumption") with the TLS 1.3 label prefix
 * "tls13 " (@p legacy 1), as NoxTLS before RFC 9147 Section 5.9 compliance did, so the
 * context completes PSK handshakes with such peers. 0 (the default) uses the RFC 9147
 * "dtls13" prefix. Every other derivation uses "dtls13" either way.
 * noxtls_dtls13_ch2_binder_check() always uses "dtls13": a server that admits clients with
 * it must leave this setting at 0. Call before the handshake starts (client or server).
 * @return NOXTLS_RETURN_SUCCESS; NOXTLS_RETURN_INVALID_PARAM for a NULL or non-DTLS 1.3
 *         context, a value other than 0 or 1, or once the handshake started.
 */
noxtls_return_t noxtls_dtls13_set_legacy_psk_labels(tls13_context_t *ctx, uint8_t legacy);

/**
 * N5a. After the handshake completed, release the handshake state now: the handshake
 * secrets, transcript, key shares, PSK and handshake workspace are wiped and returned
 * (static memory: the whole handshake part, see noxtls_connection_memory_handshake_region()).
 * The application traffic keys, the selected PSK identity and exporter_master_secret stay,
 * so recv, send, KeyUpdate, ACK and noxtls_tls13_export_keying_material() still work
 * (RFC 8446 Section 7.5). A late epoch-2 record (a retransmitted Finished) is discarded
 * afterwards, except by a static-memory DTLS server, which keeps its epoch-2 read key.
 * Idempotent.
 * @return NOXTLS_RETURN_SUCCESS; NOXTLS_RETURN_INVALID_PARAM for NULL; NOXTLS_RETURN_BAD_STATE
 *         when not connected, or for a DTLS client whose final flight is not yet acknowledged.
 */
noxtls_return_t noxtls_tls13_release_handshake_state(tls13_context_t *ctx);

/**
 * N5b. Identity of the PSK the handshake selected (external PSK identity or ticket identity),
 * valid before and after noxtls_tls13_release_handshake_state() until the context is freed.
 * @return NOXTLS_RETURN_SUCCESS; NOXTLS_RETURN_INVALID_PARAM for NULL; NOXTLS_RETURN_BAD_STATE
 *         when no PSK was selected; NOXTLS_RETURN_BUFFER_TOO_SMALL when the identity was longer
 *         than NOXTLS_TLS13_SELECTED_PSK_IDENTITY_MAX and was not kept.
 */
noxtls_return_t noxtls_tls13_selected_psk_identity(const tls13_context_t *ctx, const uint8_t **id, uint16_t *len);

/* TLS 1.3 Client Handshake Functions */
noxtls_return_t noxtls_tls13_send_client_hello(tls13_context_t *ctx);
noxtls_return_t noxtls_tls13_recv_server_hello(tls13_context_t *ctx);
noxtls_return_t noxtls_tls13_recv_encrypted_extensions(tls13_context_t *ctx);
noxtls_return_t noxtls_tls13_recv_certificate_request(tls13_context_t *ctx);
noxtls_return_t noxtls_tls13_recv_certificate(tls13_context_t *ctx);
noxtls_return_t noxtls_tls13_recv_certificate_verify(tls13_context_t *ctx);
noxtls_return_t noxtls_tls13_recv_finished(tls13_context_t *ctx);
noxtls_return_t noxtls_tls13_send_client_certificate(tls13_context_t *ctx);
noxtls_return_t noxtls_tls13_send_client_certificate_verify(tls13_context_t *ctx);
noxtls_return_t noxtls_tls13_send_finished(tls13_context_t *ctx);

/* TLS 1.3 Server Handshake Functions */
noxtls_return_t noxtls_tls13_send_certificate_request(tls13_context_t *ctx);
noxtls_return_t noxtls_tls13_recv_client_hello(tls13_context_t *ctx);
noxtls_return_t noxtls_tls13_send_server_hello(tls13_context_t *ctx);
noxtls_return_t noxtls_tls13_send_encrypted_extensions(tls13_context_t *ctx);
noxtls_return_t noxtls_tls13_send_certificate(tls13_context_t *ctx);
noxtls_return_t noxtls_tls13_send_certificate_verify(tls13_context_t *ctx);
noxtls_return_t noxtls_tls13_send_finished_server(tls13_context_t *ctx);
noxtls_return_t noxtls_tls13_recv_finished_client(tls13_context_t *ctx);

/**
 * @brief RFC 8446 CertificateVerify Transcript-Hash length for a signature scheme.
 * @param[in] signature_scheme TLS SignatureScheme (e.g. TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256).
 * @param[out] hash_len_out Hash output size in bytes (32, 48, or 64).
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
noxtls_return_t noxtls_tls13_certificate_verify_transcript_hash_length(uint16_t signature_scheme,
                                                                        uint32_t *hash_len_out);

/**
 * @brief Build the TLS 1.3 CertificateVerify signed content (64*0x20 + context + 0x00 + Transcript-Hash).
 * @param[in] handshake_messages Handshake transcript bytes (CertificateVerify excluded).
 * @param[in] handshake_messages_len Length of handshake_messages.
 * @param[in] signature_scheme SignatureScheme used for CertificateVerify.
 * @param[in] role TLS_ROLE_SERVER or TLS_ROLE_CLIENT (selects context string).
 * @param[out] out Output buffer for signed content.
 * @param[in,out] out_len On input: out capacity; on success: bytes written. When the capacity is too
 *                        small nothing is written, *out_len is set to the required length and
 *                        NOXTLS_RETURN_INVALID_PARAM is returned. NOXTLS_TLS13_CV_SIGNED_CONTENT_MAX_LEN
 *                        bytes always suffice.
 * @return NOXTLS_RETURN_SUCCESS on success; NOXTLS_RETURN_NULL on NULL pointers;
 *         NOXTLS_RETURN_INVALID_PARAM on an invalid role or too-small output buffer.
 */
noxtls_return_t noxtls_tls13_certificate_verify_build_signed_content(const uint8_t *handshake_messages,
                                                                     uint32_t handshake_messages_len,
                                                                     uint16_t signature_scheme,
                                                                     tls_role_t role,
                                                                     uint8_t *out,
                                                                     uint32_t *out_len);

/**
 * @brief Build CertificateVerify signed content with an explicit cipher suite hash.
 * @param[in] cipher_suite Negotiated TLS 1.3 cipher suite, or 0 to use SignatureScheme hash only.
 */
noxtls_return_t noxtls_tls13_certificate_verify_build_signed_content_ex(const uint8_t *handshake_messages,
                                                                        uint32_t handshake_messages_len,
                                                                        uint16_t signature_scheme,
                                                                        uint16_t cipher_suite,
                                                                        tls_role_t role,
                                                                        uint8_t *out,
                                                                        uint32_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_TLS13_H_ */
