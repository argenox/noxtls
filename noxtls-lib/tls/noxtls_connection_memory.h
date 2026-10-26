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
* File:    noxtls_connection_memory.h
* Summary: Build-time sized per-connection memory for TLS 1.3 and DTLS 1.3
*****************************************************************************/
/**
 * @file noxtls_connection_memory.h
 * @brief Per-connection memory for NOXTLS_CONFIG_STATIC_MEMORY builds.
 * @ingroup noxtls_tls
 *
 * One caller-provided block holds everything a TLS 1.3 / DTLS 1.3 connection
 * allocates, carved at fixed offsets when the context is initialized:
 *
 *     [header][steady: TX record | DTLS record workspace | TX queue | ACK ranges |
 *              datagram stash | steady arena][handshake: hs | handshake workspace |
 *              DTLS flight | handshake arena]
 *
 * The steady part is what record protection needs for the connection lifetime.
 * The handshake part holds tls13_hs_state_t, the transcript and handshake buffers,
 * key shares, X.509 parsing and the DTLS flight. It is wiped with
 * noxtls_secure_zero() and released when the handshake is complete: for TLS at
 * the Finished exchange; for a DTLS client when its final flight is acknowledged
 * or its retransmissions are exhausted (RFC 9147, Section 5.8); for a DTLS server
 * when it has the client Finished, keeping only the client epoch-2 read secret
 * (at most 80 bytes, in the steady header) so a retransmitted Finished can be
 * acknowledged again until NOXTLS_STATIC_DTLS13_EPOCH2_RETAIN_MS elapse.
 * After release the application may reuse the handshake part, see
 * noxtls_connection_memory_handshake_region().
 *
 * Every size below is a constant expression of the configuration, so the block
 * can be a static array:
 *
 * @code
 * static uint64_t mem[NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_SERVER, DTLS13_PSK) / 8U];
 * noxtls_dtls13_context_init_static(&ctx, TLS_ROLE_SERVER, NOXTLS_CONN_PROFILE_DTLS13_PSK,
 *                                   mem, sizeof(mem));
 * @endcode
 */
#ifndef NOXTLS_CONNECTION_MEMORY_H_
#define NOXTLS_CONNECTION_MEMORY_H_

#include <stddef.h>
#include <stdint.h>
#include "noxtls_common.h"
#include "noxtls_config.h"
#include "common/noxtls_memory.h"
#include "noxtls_tls_common.h"
#include "noxtls_dtls_common.h"
#include "noxtls_tls13.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Connection profiles: transport and peer authentication. */
#define NOXTLS_CONN_PROFILE_TLS13_PSK   0U  /**< TLS 1.3 external PSK (PSK-DHE). */
#define NOXTLS_CONN_PROFILE_DTLS13_PSK  1U  /**< DTLS 1.3 external PSK (PSK-DHE). */
#define NOXTLS_CONN_PROFILE_TLS13_CERT  2U  /**< TLS 1.3 with X.509 certificates. */
#define NOXTLS_CONN_PROFILE_DTLS13_CERT 3U  /**< DTLS 1.3 with X.509 certificates. */
#define NOXTLS_CONN_PROFILE_COUNT       4U

/** 1 when connection memory is built (static memory with TLS 1.3). */
#if NOXTLS_CONFIG_STATIC_MEMORY && NOXTLS_FEATURE_TLS13
#define NOXTLS_CONN_MEMORY 1
#else
#define NOXTLS_CONN_MEMORY 0
#endif

#if NOXTLS_CONN_MEMORY

/* ------------------------------------------------------------------------- */
/* Configuration (bytes)                                                      */
/* ------------------------------------------------------------------------- */

/** DTLS 1.3: largest flight kept for retransmission (records with 2-byte length
 *  prefixes). A larger flight fails with NOXTLS_RETURN_NOT_ENOUGH_MEMORY. */
#ifndef NOXTLS_STATIC_DTLS_FLIGHT_SIZE
#define NOXTLS_STATIC_DTLS_FLIGHT_SIZE (2U * (NOXTLS_TLS_MAX_RECORD_SIZE + 64U))
#endif
#ifndef NOXTLS_STATIC_DTLS_CERT_FLIGHT_SIZE
#define NOXTLS_STATIC_DTLS_CERT_FLIGHT_SIZE \
    (NOXTLS_STATIC_DTLS_FLIGHT_SIZE + (NOXTLS_STATIC_CERT_CHAIN_DEPTH_MAX * (NOXTLS_STATIC_CERT_DER_MAX + 64U)))
#endif

/** DTLS: ACK ranges this endpoint sends (RFC 9147, Section 7). */
#ifndef NOXTLS_STATIC_DTLS_ACK_RANGES
#define NOXTLS_STATIC_DTLS_ACK_RANGES 8U
#endif

/** TLS: bytes queued when a non-blocking transport accepts part of a record. */
#ifndef NOXTLS_STATIC_TLS_TX_QUEUE_SIZE
#define NOXTLS_STATIC_TLS_TX_QUEUE_SIZE (2U * TLS_RECORD_TX_BUFFER_SIZE)
#endif

/** DTLS 1.3 server: how long the client epoch-2 read secret is kept after the
 *  handshake to acknowledge a retransmitted client Finished (milliseconds). The
 *  default is the retained final ACK window (2 MSL, RFC 9147 Section 5.8). 0 keeps
 *  it until the context is freed. */
#ifndef NOXTLS_STATIC_DTLS13_EPOCH2_RETAIN_MS
#define NOXTLS_STATIC_DTLS13_EPOCH2_RETAIN_MS DTLS_FINAL_ACK_RETENTION_MS
#endif

/** DTLS 1.3: flight storage after release (post-handshake KeyUpdate and connection-ID
 *  messages waiting for an ACK). */
#ifndef NOXTLS_STATIC_DTLS_POST_HS_FLIGHT_SIZE
#define NOXTLS_STATIC_DTLS_POST_HS_FLIGHT_SIZE 256U
#endif

/** Largest post-handshake message accepted after release (NewSessionTicket,
 *  KeyUpdate, DTLS connection-ID messages). */
#ifndef NOXTLS_STATIC_POST_HANDSHAKE_MSG_MAX
#define NOXTLS_STATIC_POST_HANDSHAKE_MSG_MAX 512U
#endif

/** Certificate profiles: keep the peer's leaf certificate (DER) after the handshake, as
 *  heap builds do (tls-server-end-point channel binding, peer inspection). It costs
 *  NOXTLS_STATIC_CERT_DER_MAX steady bytes. 0 releases it with the handshake part. */
#ifndef NOXTLS_STATIC_RETAIN_PEER_CERT_DER
#define NOXTLS_STATIC_RETAIN_PEER_CERT_DER 1
#endif

/*
 * Arena budgets. The handshake arena holds every transient allocation of the
 * handshake: received records, the raw transcript until the hash is fixed, the
 * reassembled handshake message and its copy, parsed extensions, key shares,
 * PSK binder input, X.509 parsing and the public-key arithmetic. The defaults
 * add those terms; ut/static_memory measures every profile against them.
 */
/** Stream: one received record (protected payload, at most
 *  TLS_MAX_PROTECTED_RECORD_FRAGMENT) and the copy passed up. */
#define NOXTLS_STATIC_RX_TRANSIENT_TLS (2U * NOXTLS_MEM_REGION_COST(TLS_MAX_PROTECTED_RECORD_FRAGMENT))
/** DTLS: one datagram buffer (DTLS_MAX_RECORD_DATAGRAM) and the record copied out of it. */
#define NOXTLS_STATIC_RX_TRANSIENT_DTLS \
    (2U * NOXTLS_MEM_REGION_COST(DTLS_MAX_RECORD_DATAGRAM))
/** Largest handshake message, its reassembly bitmap and the copy handed to the parser. */
#define NOXTLS_STATIC_HS_MESSAGE_COST(max_msg) \
    ((2U * NOXTLS_MEM_REGION_COST(max_msg)) + NOXTLS_MEM_REGION_COST(((max_msg) + 7U) / 8U))
/** Raw transcript kept until the handshake hash is fixed (ClientHello, HRR,
 *  second ClientHello, ServerHello) and the PSK binder input. */
#ifndef NOXTLS_STATIC_TRANSCRIPT_BYTES
#define NOXTLS_STATIC_TRANSCRIPT_BYTES (3U * 1024U)
#endif
/** Parsed extension tables, copied key shares, ALPN/SNI copies, HRR cookie. A DTLS
 *  server's cookie exchange keeps the first ClientHello's tables until the end of the
 *  handshake (LIFO arena), so this covers two ClientHellos. */
#ifndef NOXTLS_STATIC_PARSE_BYTES
#define NOXTLS_STATIC_PARSE_BYTES 3072U
#endif
/** Public-key arithmetic for certificate paths (RSA-2048/ECDSA P-256 verify and
 *  sign, chain parsing temporaries). */
#ifndef NOXTLS_STATIC_PKC_SCRATCH_BYTES
#define NOXTLS_STATIC_PKC_SCRATCH_BYTES 8192U
#endif
/** Received chain: the leaf's DER copy and parsed structure, and the chain of
 *  intermediates parsed in borrow mode from the Certificate message (no copies). */
#define NOXTLS_STATIC_PEER_CHAIN_BYTES \
    (NOXTLS_MEM_REGION_COST(NOXTLS_STATIC_CERT_DER_MAX) + NOXTLS_MEM_REGION_COST(NOXTLS_STATIC_X509_CERT_STRUCT_BYTES) + \
     NOXTLS_MEM_REGION_COST(NOXTLS_STATIC_CHAIN_CAPACITY * NOXTLS_STATIC_X509_CERT_STRUCT_BYTES))
/** Largest Certificate message accepted in static mode. */
#define NOXTLS_STATIC_CERT_MSG_MAX \
    (16U + (NOXTLS_STATIC_CERT_CHAIN_DEPTH_MAX * (NOXTLS_STATIC_CERT_DER_MAX + 8U)))

/** Largest PSK-handshake message budgeted (ClientHello with binders and key shares,
 *  ServerHello, EncryptedExtensions, Finished). A larger message fails the handshake
 *  with NOXTLS_RETURN_NOT_ENOUGH_MEMORY; set NOXTLS_TLS_MAX_HANDSHAKE_SIZE to the same
 *  value to refuse it before reassembly. */
#ifndef NOXTLS_STATIC_PSK_MSG_MAX
#define NOXTLS_STATIC_PSK_MSG_MAX 2048U
#endif
#define NOXTLS_STATIC_MAX_(a, b) (((a) > (b)) ? (a) : (b))

/** Handshake terms common to both transports (PSK handshake). */
#define NOXTLS_STATIC_HS_TERMS_PSK \
    (NOXTLS_STATIC_HS_MESSAGE_COST(NOXTLS_STATIC_MAX_(NOXTLS_STATIC_PSK_MSG_MAX, NOXTLS_TLS_MAX_RECORD_SIZE)) + \
     NOXTLS_STATIC_TRANSCRIPT_BYTES + NOXTLS_STATIC_PARSE_BYTES)
/** Additional handshake terms of certificate authentication. */
#define NOXTLS_STATIC_HS_TERMS_CERT \
    (NOXTLS_STATIC_HS_MESSAGE_COST(NOXTLS_STATIC_CERT_MSG_MAX) + NOXTLS_STATIC_PEER_CHAIN_BYTES + \
     NOXTLS_STATIC_PKC_SCRATCH_BYTES)
/** DTLS: a handshake fragment buffer when the configured MTU allows fragments larger
 *  than the record TX buffer (no MTU set: DTLS_MAX_FRAGMENT_SIZE). */
#define NOXTLS_STATIC_DTLS_FRAGMENT_COST \
    ((((uint32_t)DTLS_RECORD_DATA_OFFSET + DTLS_HANDSHAKE_HEADER_SIZE + DTLS_MAX_FRAGMENT_SIZE) > \
      (uint32_t)TLS_RECORD_TX_BUFFER_SIZE) ? \
     NOXTLS_MEM_REGION_COST(DTLS_HANDSHAKE_HEADER_SIZE + DTLS_MAX_FRAGMENT_SIZE) : 0U)

/** Reserve on top of the handshake terms, in percent. The arena returns only trailing
 *  freed blocks (LIFO), so a block freed under a live one stays unusable until the
 *  live one is freed: for example the first ClientHello's tables under the cookie
 *  exchange's transcript state. ut/static_memory and the DTLS loss/reorder suite
 *  run every profile within this reserve. */
#ifndef NOXTLS_STATIC_ARENA_RESERVE_PERCENT
#define NOXTLS_STATIC_ARENA_RESERVE_PERCENT 25U
#endif
#define NOXTLS_STATIC_WITH_RESERVE(n) ((n) + (((n) * NOXTLS_STATIC_ARENA_RESERVE_PERCENT) / 100U))

/** Handshake arenas per profile (each can be overridden). */
#ifndef NOXTLS_STATIC_HS_ARENA_PSK
#define NOXTLS_STATIC_HS_ARENA_PSK NOXTLS_STATIC_WITH_RESERVE(NOXTLS_STATIC_RX_TRANSIENT_TLS + NOXTLS_STATIC_HS_TERMS_PSK)
#endif
#ifndef NOXTLS_STATIC_HS_ARENA_CERT
#define NOXTLS_STATIC_HS_ARENA_CERT \
    NOXTLS_STATIC_WITH_RESERVE(NOXTLS_STATIC_RX_TRANSIENT_TLS + NOXTLS_STATIC_HS_TERMS_PSK + NOXTLS_STATIC_HS_TERMS_CERT)
#endif
#ifndef NOXTLS_STATIC_HS_ARENA_DTLS_PSK
#define NOXTLS_STATIC_HS_ARENA_DTLS_PSK \
    NOXTLS_STATIC_WITH_RESERVE(NOXTLS_STATIC_RX_TRANSIENT_DTLS + NOXTLS_STATIC_DTLS_FRAGMENT_COST + \
                               NOXTLS_STATIC_HS_TERMS_PSK)
#endif
#ifndef NOXTLS_STATIC_HS_ARENA_DTLS_CERT
#define NOXTLS_STATIC_HS_ARENA_DTLS_CERT \
    NOXTLS_STATIC_WITH_RESERVE(NOXTLS_STATIC_RX_TRANSIENT_DTLS + NOXTLS_STATIC_DTLS_FRAGMENT_COST + \
                               NOXTLS_STATIC_HS_TERMS_PSK + NOXTLS_STATIC_HS_TERMS_CERT)
#endif

/** Steady arenas: one received record, its copy, data kept for a short read, and
 *  one post-handshake message with its reassembly. */
#ifndef NOXTLS_STATIC_STEADY_ARENA
#define NOXTLS_STATIC_STEADY_ARENA \
    (NOXTLS_STATIC_RX_TRANSIENT_TLS + NOXTLS_STATIC_HS_MESSAGE_COST(NOXTLS_STATIC_POST_HANDSHAKE_MSG_MAX) + \
     NOXTLS_MEM_REGION_COST(TLS_MAX_RECORD_SIZE))
#endif
#ifndef NOXTLS_STATIC_STEADY_ARENA_DTLS
#define NOXTLS_STATIC_STEADY_ARENA_DTLS \
    (NOXTLS_STATIC_RX_TRANSIENT_DTLS + NOXTLS_STATIC_HS_MESSAGE_COST(NOXTLS_STATIC_POST_HANDSHAKE_MSG_MAX) + \
     NOXTLS_MEM_REGION_COST(TLS_MAX_RECORD_SIZE))
#endif

/** Library-owned connection blocks for the plain init functions
 *  (noxtls_tls13_context_init, noxtls_dtls13_context_init, ...). 0: those return
 *  NOXTLS_RETURN_NOT_SUPPORTED and callers must supply memory. */
#ifndef NOXTLS_STATIC_CONNECTION_POOL_COUNT
#define NOXTLS_STATIC_CONNECTION_POOL_COUNT 0U
#endif
/** Pool blocks carve the certificate profiles (1) or the PSK profiles (0) of the
 *  transport the plain init function selects. */
#ifndef NOXTLS_STATIC_CONNECTION_POOL_CERT
#define NOXTLS_STATIC_CONNECTION_POOL_CERT 1
#endif

/* ------------------------------------------------------------------------- */
/* Connection header (first bytes of the caller block)                        */
/* ------------------------------------------------------------------------- */

/** Largest epoch-2 secret and sn_key kept by a DTLS 1.3 server after release. */
#define NOXTLS_CONN_EPOCH2_SECRET_MAX 48U
#define NOXTLS_CONN_EPOCH2_SN_KEY_MAX 32U

/**
 * Per-connection memory header. It lives at the start of the caller block; only
 * the library writes it. Applications use the accessor functions below.
 */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct noxtls_connection_memory_s
{
    uint32_t magic;
    uint8_t profile;
    uint8_t pool_index;          /**< Pool block index + 1 (0: caller block). */
    uint8_t release_pending;     /**< Handshake completed: release at the end of the call. */
    uint8_t released;            /**< Handshake part wiped and released. */
    uint8_t handshake_external;  /**< The handshake part is a separate caller block (_split init). */
    noxtls_mem_scope_t scope;
    noxtls_mem_region_t steady_fixed;
    noxtls_mem_region_t steady_arena;
    noxtls_mem_region_t hs_fixed;
    noxtls_mem_region_t hs_arena;
    size_t block_size;           /**< Bytes the caller supplied. */
    size_t steady_bytes;         /**< Header + steady part. */
    size_t handshake_bytes;      /**< Handshake part (released region). */
    size_t hs_arena_peak;        /**< Handshake arena high-water mark at release. */
    uint8_t *handshake_base;     /**< First byte of the handshake part. */
    uint8_t *tx_queue;
    uint32_t tx_queue_size;
    uint8_t *rx_stash;
    uint32_t rx_stash_size;
    uint64_t *last_ack_min;
    uint64_t *last_ack_max;
    uint8_t *post_hs_flight;
    uint32_t post_hs_flight_size;
    uint8_t *peer_cert;          /**< Certificate profiles: slot for the peer's leaf DER. */
    uint32_t depth;              /**< Nesting of library calls in this connection's scope. */
    size_t dangling;             /**< Pointers into the handshake part found at release (0). */
    /* DTLS 1.3 server epoch-2 residue (client Finished retransmissions). */
    uint8_t epoch2_secret[NOXTLS_CONN_EPOCH2_SECRET_MAX];
    uint8_t epoch2_sn_key[NOXTLS_CONN_EPOCH2_SN_KEY_MAX];
    uint8_t epoch2_secret_len;
    uint8_t epoch2_valid;
    uint64_t epoch2_expiry_ms;
} noxtls_connection_memory_t;
NOXTLS_MSVC_WARNING_POP

/* ------------------------------------------------------------------------- */
/* Sizes                                                                      */
/* ------------------------------------------------------------------------- */

#define NOXTLS_CONN_A(n) NOXTLS_MEM_REGION_ALIGN_UP(n)
#define NOXTLS_CONN_HEADER_BYTES NOXTLS_CONN_A(sizeof(noxtls_connection_memory_t))

/* Steady fixed slots. */
#define NOXTLS_CONN_TX_BYTES NOXTLS_CONN_A(TLS_RECORD_TX_BUFFER_SIZE)
#define NOXTLS_CONN_DTLS_FIXED_BYTES \
    (NOXTLS_CONN_A(TLS13_RECORD_WORKSPACE_SIZE) + \
     NOXTLS_CONN_A(2U * sizeof(uint64_t) * NOXTLS_STATIC_DTLS_ACK_RANGES) + \
     NOXTLS_CONN_A(2U * sizeof(uint64_t) * DTLS_MAX_ACK_RANGES) + \
     NOXTLS_CONN_A(DTLS_MAX_RECORD_DATAGRAM) + \
     NOXTLS_CONN_A(NOXTLS_STATIC_DTLS_POST_HS_FLIGHT_SIZE))
#define NOXTLS_CONN_TLS_FIXED_BYTES NOXTLS_CONN_A(NOXTLS_STATIC_TLS_TX_QUEUE_SIZE)

/** Steady part (header included) for a profile token (TLS13_PSK, DTLS13_PSK, ...). */
#define NOXTLS_CONN_STEADY_TLS13_PSK \
    (NOXTLS_CONN_HEADER_BYTES + NOXTLS_CONN_TX_BYTES + NOXTLS_CONN_TLS_FIXED_BYTES + \
     NOXTLS_CONN_A(NOXTLS_STATIC_STEADY_ARENA))
#if NOXTLS_STATIC_RETAIN_PEER_CERT_DER
#define NOXTLS_CONN_PEER_CERT_BYTES NOXTLS_CONN_A(NOXTLS_STATIC_CERT_DER_MAX)
#else
#define NOXTLS_CONN_PEER_CERT_BYTES 0U
#endif
#define NOXTLS_CONN_STEADY_TLS13_CERT (NOXTLS_CONN_STEADY_TLS13_PSK + NOXTLS_CONN_PEER_CERT_BYTES)
#define NOXTLS_CONN_STEADY_DTLS13_PSK \
    (NOXTLS_CONN_HEADER_BYTES + NOXTLS_CONN_TX_BYTES + NOXTLS_CONN_DTLS_FIXED_BYTES + \
     NOXTLS_CONN_A(NOXTLS_STATIC_STEADY_ARENA_DTLS))
#define NOXTLS_CONN_STEADY_DTLS13_CERT (NOXTLS_CONN_STEADY_DTLS13_PSK + NOXTLS_CONN_PEER_CERT_BYTES)

/** Handshake part (released after the handshake) for a profile token. */
#define NOXTLS_CONN_HS_COMMON \
    (NOXTLS_CONN_A(sizeof(tls13_hs_state_t)) + NOXTLS_CONN_A(TLS_HANDSHAKE_WORKSPACE_SIZE))
#define NOXTLS_CONN_HANDSHAKE_TLS13_PSK (NOXTLS_CONN_HS_COMMON + NOXTLS_CONN_A(NOXTLS_STATIC_HS_ARENA_PSK))
#define NOXTLS_CONN_HANDSHAKE_TLS13_CERT (NOXTLS_CONN_HS_COMMON + NOXTLS_CONN_A(NOXTLS_STATIC_HS_ARENA_CERT))
#define NOXTLS_CONN_HANDSHAKE_DTLS13_PSK \
    (NOXTLS_CONN_HS_COMMON + NOXTLS_CONN_A(NOXTLS_STATIC_DTLS_FLIGHT_SIZE) + \
     NOXTLS_CONN_A(NOXTLS_STATIC_HS_ARENA_DTLS_PSK))
#define NOXTLS_CONN_HANDSHAKE_DTLS13_CERT \
    (NOXTLS_CONN_HS_COMMON + NOXTLS_CONN_A(NOXTLS_STATIC_DTLS_CERT_FLIGHT_SIZE) + \
     NOXTLS_CONN_A(NOXTLS_STATIC_HS_ARENA_DTLS_CERT))

/* Two-level helpers so that a profile argument that is itself a macro expands first. */
#define NOXTLS_CONN_STEADY_I(profile) NOXTLS_CONN_STEADY_##profile
#define NOXTLS_CONN_HANDSHAKE_I(profile) NOXTLS_CONN_HANDSHAKE_##profile
#define NOXTLS_CONN_STEADY_X(profile) NOXTLS_CONN_STEADY_I(profile)
#define NOXTLS_CONN_HANDSHAKE_X(profile) NOXTLS_CONN_HANDSHAKE_I(profile)

/** Steady-state bytes of a connection after release (header + steady part). The
 *  sizes of this version are the same for both roles. */
#define NOXTLS_CONNECTION_MEMORY_STEADY_SIZE(role, profile) \
    (((role) == TLS_ROLE_SERVER) ? NOXTLS_CONN_STEADY_X(profile) : NOXTLS_CONN_STEADY_X(profile))
/** Bytes released after the handshake. */
#define NOXTLS_CONNECTION_MEMORY_HANDSHAKE_SIZE(role, profile) \
    (((role) == TLS_ROLE_SERVER) ? NOXTLS_CONN_HANDSHAKE_X(profile) : NOXTLS_CONN_HANDSHAKE_X(profile))

/**
 * Bytes a caller block needs for @p role (TLS_ROLE_CLIENT or TLS_ROLE_SERVER) and
 * @p profile (token: TLS13_PSK, DTLS13_PSK, TLS13_CERT, DTLS13_CERT). A constant
 * expression, a multiple of 8; the block must be 8-byte aligned. This version
 * budgets both roles alike; @p role is part of the contract so that a
 * role-specific budget does not change callers.
 */
#define NOXTLS_CONNECTION_MEMORY_SIZE(role, profile) \
    (NOXTLS_CONNECTION_MEMORY_STEADY_SIZE(role, profile) + NOXTLS_CONNECTION_MEMORY_HANDSHAKE_SIZE(role, profile))

/** Peak bytes of one connection: the whole block. */
#define NOXTLS_CONNECTION_MEMORY_PEAK_SIZE(role, profile) NOXTLS_CONNECTION_MEMORY_SIZE(role, profile)

/** Footprint of a profile, all values in bytes. */
typedef struct
{
    size_t total;            /**< Block size (peak). */
    size_t steady;           /**< Kept after the handshake. */
    size_t handshake;        /**< Released after the handshake. */
    size_t hs_state;         /**< sizeof(tls13_hs_state_t). */
    size_t handshake_workspace;
    size_t flight;
    size_t hs_arena;
    size_t tx_record;
    size_t record_workspace;
    size_t steady_fixed_other; /**< TX queue, ACK ranges, datagram stash. */
    size_t steady_arena;
    size_t header;
    size_t context;          /**< sizeof(tls13_context_t), caller-owned and not included above. */
} noxtls_connection_footprint_t;

/** Runtime state of one connection's memory. */
typedef struct
{
    noxtls_connection_footprint_t layout;
    uint8_t released;             /**< 1 after the handshake part was released. */
    noxtls_mem_region_stats_t hs_arena;
    noxtls_mem_region_stats_t steady_arena;
    size_t hs_arena_peak_at_release;
    size_t dangling_pointers;     /**< Context pointers into the released part (always 0). */
} noxtls_connection_memory_stats_t;

/** Runtime query of NOXTLS_CONNECTION_MEMORY_SIZE() (0 for an unknown profile). */
size_t noxtls_connection_memory_size(tls_role_t role, uint32_t profile);
/** Fill @p footprint for @p role / @p profile. */
noxtls_return_t noxtls_connection_memory_footprint(tls_role_t role, uint32_t profile,
                                                   noxtls_connection_footprint_t *footprint);

/**
 * Initialize a TLS 1.3 context whose memory is @p memory (@p memory_len bytes,
 * 8-byte aligned, at least noxtls_connection_memory_size()). The block must stay
 * valid until noxtls_tls13_context_free(), which wipes it.
 */
noxtls_return_t noxtls_tls13_context_init_static(tls13_context_t *ctx, tls_role_t role, uint32_t profile,
                                                 void *memory, size_t memory_len);
/** DTLS 1.3 variant of noxtls_tls13_context_init_static(). */
noxtls_return_t noxtls_dtls13_context_init_static(tls13_context_t *ctx, tls_role_t role, uint32_t profile,
                                                  void *memory, size_t memory_len);

/**
 * Initialize a TLS 1.3 context whose steady part and handshake part are two caller
 * blocks, so that several connections can take turns with one handshake block.
 *
 * - @p steady: at least NOXTLS_CONNECTION_MEMORY_STEADY_SIZE(role, profile) bytes,
 *   8-byte aligned, owned by the context until noxtls_tls13_context_free(), which wipes it.
 * - @p handshake: at least NOXTLS_CONNECTION_MEMORY_HANDSHAKE_SIZE(role, profile) bytes,
 *   8-byte aligned. The context holds it from this call until its handshake part is
 *   released (stats.released, see the release rules) or the context is freed. It is
 *   wiped at the release, after which another context may be initialized with it.
 *
 * Handshakes that share one handshake block are serialized: while a context holds it,
 * an init with the same block (or any overlapping storage still held by a connection)
 * fails with NOXTLS_RETURN_NOT_ENOUGH_MEMORY and changes nothing, so the caller can
 * defer the new connection (a DTLS peer retransmits its ClientHello). Freeing a context
 * that already released the block does not touch it.
 *
 * @return NOXTLS_RETURN_SUCCESS; NOXTLS_RETURN_NULL; NOXTLS_RETURN_INVALID_PARAM for a
 *         wrong profile, a short or misaligned block, or blocks that overlap each other;
 *         NOXTLS_RETURN_NOT_ENOUGH_MEMORY when a block is in use or the region registry
 *         is full (NOXTLS_STATIC_MAX_CONNECTIONS).
 */
noxtls_return_t noxtls_tls13_context_init_static_split(tls13_context_t *ctx, tls_role_t role, uint32_t profile,
                                                       void *steady, size_t steady_len,
                                                       void *handshake, size_t handshake_len);
/** DTLS 1.3 variant of noxtls_tls13_context_init_static_split(). */
noxtls_return_t noxtls_dtls13_context_init_static_split(tls13_context_t *ctx, tls_role_t role, uint32_t profile,
                                                        void *steady, size_t steady_len,
                                                        void *handshake, size_t handshake_len);

/** Copy the memory statistics of a context initialized with static memory. */
noxtls_return_t noxtls_connection_memory_get_stats(const tls13_context_t *ctx,
                                                   noxtls_connection_memory_stats_t *stats);

/**
 * After release, return the handshake part of the block, which the application may
 * use until it frees the context. It is wiped. NOXTLS_RETURN_NOT_INITIALIZED while
 * the handshake still owns it; NOXTLS_RETURN_NOT_ENOUGH_MEMORY (and NULL) for a
 * separate handshake block (_split init) that another connection holds now.
 */
noxtls_return_t noxtls_connection_memory_handshake_region(tls13_context_t *ctx, uint8_t **region, size_t *len);

/* ---- Library internals (used by the TLS modules) ------------------------- */

/** Connection memory bound to a context, or NULL. */
noxtls_connection_memory_t *noxtls_conn_mem_of(const tls_context_t *base);
/** Enter the connection's allocation scope. A context without connection memory (a
 *  freed one, TLS 1.2) enters the global arena's scope, so that nothing it allocates
 *  lands in the connection whose call is running (for example from an I/O callback). */
noxtls_mem_scope_t *noxtls_conn_mem_enter(const tls_context_t *base);
/** Leave the scope; at the outermost level, release the handshake part when due. */
void noxtls_conn_mem_leave(tls13_context_t *ctx, noxtls_mem_scope_t *previous);
/** Leave a scope entered by a record-layer entry point (no tls13_context_t at hand);
 *  the release, when due, happens at the end of the next TLS 1.3 call. */
void noxtls_conn_mem_leave_base(const tls_context_t *base, noxtls_mem_scope_t *previous);
/** Carve a split block pair (noxtls_*_context_init_static_split()). */
noxtls_return_t noxtls_conn_mem_bind_split(tls13_context_t *ctx, uint32_t profile, void *steady, size_t steady_len,
                                           void *handshake, size_t handshake_len);
/** Called by the TLS 1.3 module at handshake completion. */
void noxtls_conn_mem_handshake_done(tls13_context_t *ctx);
/** DTLS 1.3 server after release: epoch-2 read secret and sn_key, or NULL. */
const uint8_t *noxtls_conn_mem_epoch2_secret(const tls13_context_t *ctx, const uint8_t **sn_key);
/** Refuse caller memory that a live connection still uses, before the context is
 *  touched: NOXTLS_RETURN_NOT_ENOUGH_MEMORY when @p memory (the whole block, or the
 *  steady part when @p handshake is not NULL) or @p handshake overlaps a live region. */
noxtls_return_t noxtls_conn_mem_check_unused(uint32_t profile, const void *memory, const void *handshake);
/** Carve @p memory for @p profile and attach it to @p ctx (after its base init). */
noxtls_return_t noxtls_conn_mem_bind(tls13_context_t *ctx, uint32_t profile, void *memory, size_t memory_len,
                                     uint8_t pool_index);
/** Bind a library pool block for the plain init functions, or NOT_SUPPORTED. */
noxtls_return_t noxtls_conn_mem_pool_bind(tls13_context_t *ctx, tls_role_t role, uint8_t is_dtls);
/** Wipe and unregister a connection's memory and return a pool block. */
void noxtls_conn_mem_free(tls13_context_t *ctx, noxtls_connection_memory_t *conn);
/** TLS: transmit queue slot (non-blocking partial writes), or NULL. */
uint8_t *noxtls_conn_mem_tx_queue(const tls_context_t *base, uint32_t *capacity);
/** DTLS: slot for the unread records of the last datagram, or NULL. */
uint8_t *noxtls_conn_mem_rx_stash(const tls_context_t *base, uint32_t *capacity);
/** DTLS: slots for the ranges of the last ACK received (DTLS_MAX_ACK_RANGES each), or NULL. */
uint64_t *noxtls_conn_mem_last_ack_ranges(const tls_context_t *base, uint64_t **max_ranges);

#endif /* NOXTLS_CONN_MEMORY */

/* Record-layer entry points that can allocate for a connection run in its scope. */
#if NOXTLS_CONN_MEMORY
#define NOXTLS_CONN_SCOPE_BEGIN(base) noxtls_mem_scope_t *noxtls_conn_scope_prev = noxtls_conn_mem_enter(base)
#define NOXTLS_CONN_SCOPE_END(base) noxtls_conn_mem_leave_base((base), noxtls_conn_scope_prev)
#else
#define NOXTLS_CONN_SCOPE_BEGIN(base) (void)(base)
#define NOXTLS_CONN_SCOPE_END(base) (void)(base)
#endif

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_CONNECTION_MEMORY_H_ */
