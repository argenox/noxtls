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
* File:    lb_fixture.h
* Summary: In-memory client/server fixture for end-to-end TLS regression tests
*****************************************************************************/
/** @file lb_fixture.h
 * @brief Shared harness for ut/tls_loopback, ut/x509_parse and ut/ram_budget.
 *
 * Both endpoints run in one process and talk through an in-memory link wired
 * with noxtls_tls_set_io_callbacks() in non-blocking mode. The link can cap
 * the bytes moved per callback (fragmented reads/partial writes) and inject
 * TLS_IO_WOULD_BLOCK, and has a datagram mode for DTLS.
 *
 * Everything here uses public APIs. The few places that must read or write a
 * struct field because no accessor exists are collected in the "struct field
 * access" section of lb_fixture.c (functions prefixed lb_field_) so the
 * streams that change those structs have a single place to update.
 */
#ifndef LB_FIXTURE_H
#define LB_FIXTURE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "noxtls_common.h"
#include "noxtls_memory.h"
#include "noxtls_tls12.h"
#include "noxtls_tls13.h"
#include "noxtls_tls_unified.h"
#include "noxtls_x509.h"
#include "pkc/rsa/noxtls_rsa.h"
#include "pkc/ecc/noxtls_ecc.h"

#include "lb_alloc.h"
#include "loopback_pki.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Test framework                                                            */
/* ------------------------------------------------------------------------- */

/** Result of a test function: 0 pass, LB_SKIP when the feature is unavailable, else fail. */
#define LB_SKIP 77

/** Non-zero suppresses CHECK failure messages (used by allocation-failure sweeps). */
extern int g_lb_quiet;
/** Non-zero disables the unified WANT_WRITE re-entry workaround in lb_pair_handshake(). */
extern int g_lb_strict_unified;

void lb_fail(const char *file, int line, const char *expr);
void lb_fail_rc(const char *file, int line, const char *expr, long actual, long expected);

#define LB_CHECK(cond) do { if(!(cond)) { lb_fail(__FILE__, __LINE__, #cond); return 1; } } while(0)
#define LB_CHECK_EQ(actual, expected) do { long lb_a_ = (long)(actual); long lb_e_ = (long)(expected); \
    if(lb_a_ != lb_e_) { lb_fail_rc(__FILE__, __LINE__, #actual, lb_a_, lb_e_); return 1; } } while(0)
#define LB_CHECK_OK(expr) LB_CHECK_EQ((expr), NOXTLS_RETURN_SUCCESS)
/** Run a sub-step that returns int (0 = success). */
#define LB_RUN(expr) do { if((expr) != 0) { lb_fail(__FILE__, __LINE__, #expr); return 1; } } while(0)

typedef int (*lb_test_fn_t)(void);

typedef struct
{
    const char *name;
    lb_test_fn_t fn;
} lb_test_case_t;

/**
 * Run the selected tests. argv[1] may be a test name (run only that), "--list"
 * (print names) or absent (run all). Installs deterministic entropy, loads the
 * shared keys, and after every test checks that allocator live bytes returned
 * to the pre-test value (any leak fails the test and dumps live blocks).
 */
int lb_main(int argc, char **argv, const char *suite, const lb_test_case_t *cases, size_t count);

/** Print a message prefixed with the current test name. */
void lb_log(const char *fmt, ...);

/** Deterministic pseudo-random bytes for payloads (not for keys). */
void lb_fill_pattern(uint8_t *buf, uint32_t len, uint32_t seed);

/* ------------------------------------------------------------------------- */
/* In-memory link                                                            */
/* ------------------------------------------------------------------------- */

#define LB_PIPE_CAPACITY     (1024U * 1024U)
#define LB_DGRAM_SLOTS       64U
#define LB_DGRAM_MAX         (18U * 1024U)

typedef struct
{
    uint8_t data[LB_PIPE_CAPACITY];
    uint32_t rd;
    uint32_t wr;
    /* Datagram mode: boundaries of queued datagrams (offsets into data). */
    uint32_t dgram_len[LB_DGRAM_SLOTS];
    uint32_t dgram_head;
    uint32_t dgram_count;
    uint64_t total;
} lb_pipe_t;

typedef struct lb_link_s lb_link_t;

typedef struct
{
    lb_link_t *link;
    int is_client;
} lb_port_t;

struct lb_link_s
{
    lb_pipe_t to_server;
    lb_pipe_t to_client;
    lb_port_t client_port;
    lb_port_t server_port;
    uint32_t max_chunk;    /* 0 = unlimited bytes per callback (stream mode) */
    uint32_t block_every;  /* every N-th callback returns TLS_IO_WOULD_BLOCK (0 = never) */
    uint32_t calls;
    int datagram;          /* 1 = DTLS datagram semantics */
};

/** Reset a link. max_chunk/block_every as described above. */
void lb_link_init(lb_link_t *link, uint32_t max_chunk, uint32_t block_every, int datagram);
int32_t lb_io_send(void *user, const uint8_t *data, uint32_t len);
int32_t lb_io_recv(void *user, uint8_t *data, uint32_t len);
uint64_t lb_io_now_ms(void *user);
/** Bytes queued and not yet read in one direction. */
uint32_t lb_link_pending(const lb_link_t *link, int to_client);

/* ------------------------------------------------------------------------- */
/* Shared key material (loaded once by lb_main)                              */
/* ------------------------------------------------------------------------- */

typedef struct
{
    ecc_key_t ec_server;
    ecc_key_t ec_client;
    rsa_key_t rsa_server;
    rsa_key_t rsa_client;
    uint8_t ed_server_seed[32];
    int have_ed25519;
} lb_keys_t;

extern lb_keys_t g_lb_keys;
/** 1 when the Ed25519 test key can be loaded (probed once by lb_main). */
extern int g_lb_have_ed25519;

/** Install the given DER certificates as the global trust store. Returns 0 on success. */
int lb_trust_set(const uint8_t *const *ders, const uint32_t *lens, uint32_t count);
/** Convenience: EC root only / EC root + RSA root. */
int lb_trust_ec_root(void);
int lb_trust_all_roots(void);
void lb_trust_clear(void);

/* ------------------------------------------------------------------------- */
/* Endpoints                                                                 */
/* ------------------------------------------------------------------------- */

typedef enum
{
    LB_PROTO_TLS13 = 0,
    LB_PROTO_TLS12,
    LB_PROTO_UNIFIED,
    LB_PROTO_DTLS13,
    LB_PROTO_DTLS12
} lb_proto_t;

typedef enum
{
    LB_AUTH_ECDSA = 0,   /* ec_server cert (+ ec_int chain when send_chain) */
    LB_AUTH_RSA,         /* rsa_server cert, issued directly by rsa_root */
    LB_AUTH_ED25519,     /* ed_server cert issued by ec_root */
    LB_AUTH_ROGUE,       /* rogue_server cert (untrusted root) with ec_server key */
    LB_AUTH_NONE
} lb_auth_t;

typedef struct
{
    lb_proto_t proto;
    /* Server */
    lb_auth_t server_auth;
    int send_chain;                 /* LB_AUTH_ECDSA: also send ec_int */
    const uint16_t *server_suites;  /* allowlist (wire ids) or NULL */
    uint32_t server_suite_count;
    int client_auth;                /* 0 none, 1 request, 2 require */
    /* Client */
    lb_auth_t client_cert;          /* LB_AUTH_ECDSA (ec_client) / LB_AUTH_RSA (rsa_client) / LB_AUTH_NONE */
    const char *sni;                /* server name for SNI + hostname verification, or NULL */
    const uint16_t *client_groups;  /* TLS 1.3 supported_groups override or NULL */
    uint32_t client_group_count;
    int prefer_chacha20;            /* TLS 1.3 client */
    uint16_t record_size_limit;     /* TLS 1.3: advertised record_size_limit (0 = default) */
    uint8_t max_fragment_code;      /* TLS 1.2: RFC 6066 code (0 = off) */
    uint16_t tls12_version;         /* LB_PROTO_TLS12: 0 = TLS 1.2, else TLS_VERSION_1_0 / TLS_VERSION_1_1 (both ends) */
    int tls12_client_no_ems;        /* TLS 1.2 client: do not offer extended_master_secret */
    const noxtls_tls13_session_t *tls13_session; /* client: resume from this session */
    uint16_t unified_client_version; /* LB_PROTO_UNIFIED: 0 auto, else fixed version */
    uint16_t unified_server_version; /* LB_PROTO_UNIFIED: 0 auto, else fixed version */
    int server_proto_override;      /* 1: the server uses server_proto instead of proto */
    lb_proto_t server_proto;        /* e.g. a raw TLS 1.2 server for a unified client */
    /* Transport */
    uint32_t max_chunk;
    uint32_t block_every;
} lb_cfg_t;

/** Fill a cfg with defaults: given protocol, ECDSA chain auth, SNI "server.test". */
void lb_cfg_default(lb_cfg_t *cfg, lb_proto_t proto);

typedef struct
{
    lb_proto_t proto;
    tls_role_t role;
    tls13_context_t *t13;
    tls12_context_t *t12;
    noxtls_tls_connection_t *uni;
    noxtls_return_t last_rc;
    int done;
    int initialized;
} lb_end_t;

typedef struct
{
    lb_cfg_t cfg;
    lb_link_t *link;
    lb_end_t client;
    lb_end_t server;
} lb_pair_t;

#if NOXTLS_CONFIG_STATIC_MEMORY
/**
 * Static memory: initialize the contexts of the next lb_pair_init() in these caller
 * blocks with noxtls_tls13/dtls13_context_init_static() and the given
 * NOXTLS_CONN_PROFILE_* (NULL keeps the plain init and its library pool block).
 * The setting applies to one pair and is cleared by lb_pair_init().
 */
void lb_static_memory_set(void *client_mem, size_t client_len, uint32_t client_profile,
                          void *server_mem, size_t server_len, uint32_t server_profile);
#endif

/** Create both endpoints according to cfg (link storage is static, one pair at a time). */
int lb_pair_init(lb_pair_t *pair, const lb_cfg_t *cfg);
/** Drive both handshakes until done/failed/stalled. Returns 0 if both succeeded. */
int lb_pair_handshake(lb_pair_t *pair);
/** Free both endpoints (idempotent). */
void lb_pair_free(lb_pair_t *pair);

noxtls_return_t lb_end_step(lb_end_t *end);
noxtls_return_t lb_end_send(lb_end_t *end, const uint8_t *data, uint32_t len);
noxtls_return_t lb_end_recv(lb_end_t *end, uint8_t *buf, uint32_t *len);
noxtls_return_t lb_end_flush(lb_end_t *end);
noxtls_return_t lb_end_close(lb_end_t *end);
uint16_t lb_end_cipher_suite(const lb_end_t *end);
uint16_t lb_end_version(const lb_end_t *end);
tls_context_t *lb_end_base(lb_end_t *end);

/**
 * Send len bytes from tx to rx in tx_chunk-sized send calls (<= TLS_MAX_RECORD_SIZE)
 * and receive them with an rx_chunk-sized buffer; verify byte-exact delivery.
 */
int lb_transfer(lb_pair_t *pair, int client_to_server, const uint8_t *data, uint32_t len,
                uint32_t tx_chunk, uint32_t rx_chunk);
/** One endpoint sends close_notify; the peer must observe the closure. Returns 0 on success. */
int lb_close_and_observe(lb_pair_t *pair, int client_closes);
/** Receive with retries until data or a terminal status. */
noxtls_return_t lb_recv_some(lb_pair_t *pair, lb_end_t *rx, uint8_t *buf, uint32_t *len);

/** Verify allocator live bytes equal baseline (dumps live blocks otherwise). Returns 0 on success. */
int lb_expect_no_leak(size_t baseline, const char *what);

/* ------------------------------------------------------------------------- */
/* Struct field access (no public accessor exists yet)                       */
/* ------------------------------------------------------------------------- */

/** Connection state of an endpoint (tls_context_t::state). */
tls_state_t lb_field_state(lb_end_t *end);
/** TLS 1.3: 1 when the client received a HelloRetryRequest / server sent one. */
int lb_field_tls13_hrr(const tls13_context_t *ctx);
/** TLS 1.3: 1 when the handshake used a PSK (resumption or external). */
int lb_field_tls13_psk_in_use(const tls13_context_t *ctx);
/** TLS 1.3 client: 1 when the server accepted 0-RTT. */
int lb_field_tls13_early_accepted(const tls13_context_t *ctx);
/** TLS 1.3: negotiated key-exchange group. */
uint16_t lb_field_tls13_group(const tls13_context_t *ctx);
/** TLS 1.3 client: 1 when a resumption ticket is stored. */
int lb_field_tls13_ticket_stored(const tls13_context_t *ctx);
/** TLS 1.2: 1 when the handshake was an abbreviated (resumed) one. */
int lb_field_tls12_resumed(const tls12_context_t *ctx);
/** TLS 1.2: renegotiation verify_data length (non-zero after a secure handshake). */
uint32_t lb_field_tls12_reneg_len(const tls12_context_t *ctx);
/** TLS 1.2: 1 when the extended master secret (RFC 7627) was negotiated. */
int lb_field_tls12_ems(const tls12_context_t *ctx);
/** TLS 1.2 client: CertificateVerify scheme chosen from the CertificateRequest (0 = none). */
uint16_t lb_field_tls12_cv_scheme(const tls12_context_t *ctx);
/** TLS 1.2: 1 while handshake transcript hash state is allocated (released at CONNECTED). */
int lb_field_tls12_transcript_live(const tls12_context_t *ctx);
/** Configure a TLS 1.3 / 1.2 server certificate (fields; no setter exists). */
void lb_field_tls13_set_server_cert(tls13_context_t *ctx, const uint8_t *der, uint32_t len);
void lb_field_tls12_set_server_cert(tls12_context_t *ctx, const uint8_t *der, uint32_t len);
/** Configure client SNI / expected hostname (fields; no setter exists). */
void lb_field_tls13_set_sni(tls13_context_t *ctx, const char *name);
void lb_field_tls12_set_sni(tls12_context_t *ctx, const char *name);
/** Raw DER of a parsed certificate (x509_certificate_t::raw_data). */
const uint8_t *lb_field_cert_der(const x509_certificate_t *cert, uint32_t *len);
/** The TLS 1.3 context embedded in a unified connection (noxtls_tls_connection_t::tls13). */
tls13_context_t *lb_field_unified_tls13(noxtls_tls_connection_t *conn);

#ifdef __cplusplus
}
#endif

#endif /* LB_FIXTURE_H */
