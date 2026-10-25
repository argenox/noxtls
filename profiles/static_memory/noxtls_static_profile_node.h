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
* File:    noxtls_static_profile_node.h
* Summary: Static memory profile: DTLS 1.3 PSK server, one connection
*****************************************************************************/
/**
 * @file noxtls_static_profile_node.h
 * @brief Thread node management endpoint (CC1354): DTLS 1.3 server, external PSK
 *        with X25519 (PSK-DHE), TLS_AES_128_GCM_SHA256, 512-byte records, one
 *        connection at a time.
 *
 * Use: -DNOXTLS_STATIC_MEMORY_PROFILE="profiles/static_memory/noxtls_static_profile_node.h"
 * (CMake: -DNOXTLS_CONFIG_STATIC_MEMORY=ON -DNOXTLS_STATIC_MEMORY_PROFILE=...).
 * The connection block is
 * NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_SERVER, DTLS13_PSK) bytes, passed to
 * noxtls_dtls13_context_init_static(..., NOXTLS_CONN_PROFILE_DTLS13_PSK, ...).
 *
 * Feature selection stays with the build (CMake NOXTLS_CFG_FEATURE_* or Kconfig).
 * Recommended for this role: TLS 1.2 off, RSA off, certificates and
 * NOXTLS_TLS13_PEER_CERTIFICATES off, post-quantum off, ChaCha20 off. Every
 * value below is a default that -D overrides. Measured values: docs/static-memory.md.
 */
#ifndef NOXTLS_STATIC_PROFILE_NODE_H_
#define NOXTLS_STATIC_PROFILE_NODE_H_

#ifndef NOXTLS_CONFIG_STATIC_MEMORY
#define NOXTLS_CONFIG_STATIC_MEMORY 1
#endif

/* Record layer: the Thread management transport carries 512-byte datagrams. */
#ifndef NOXTLS_TLS_MAX_RECORD_SIZE
#define NOXTLS_TLS_MAX_RECORD_SIZE 512U
#endif
#ifndef NOXTLS_TLS_HANDSHAKE_WORKSPACE_SIZE
#define NOXTLS_TLS_HANDSHAKE_WORKSPACE_SIZE 4096U
#endif

/* PSK handshake messages; larger ones are refused before reassembly. */
#ifndef NOXTLS_STATIC_PSK_MSG_MAX
#define NOXTLS_STATIC_PSK_MSG_MAX 1024U
#endif
#ifndef NOXTLS_TLS_MAX_HANDSHAKE_SIZE
#define NOXTLS_TLS_MAX_HANDSHAKE_SIZE 1088U
#endif
#ifndef NOXTLS_DTLS_REASSEMBLY_MAX_BYTES
#define NOXTLS_DTLS_REASSEMBLY_MAX_BYTES (NOXTLS_TLS_MAX_HANDSHAKE_SIZE + (NOXTLS_TLS_MAX_HANDSHAKE_SIZE / 8U))
#endif
#ifndef NOXTLS_STATIC_TRANSCRIPT_BYTES
#define NOXTLS_STATIC_TRANSCRIPT_BYTES 1024U
#endif
/* Extension tables of two ClientHellos: the DTLS server's cookie exchange keeps the
 * first one's storage until the handshake ends (LIFO arena). */
#ifndef NOXTLS_STATIC_PARSE_BYTES
#define NOXTLS_STATIC_PARSE_BYTES 3072U
#endif
#ifndef NOXTLS_STATIC_POST_HANDSHAKE_MSG_MAX
#define NOXTLS_STATIC_POST_HANDSHAKE_MSG_MAX 256U
#endif
#ifndef NOXTLS_STATIC_DTLS_ACK_RANGES
#define NOXTLS_STATIC_DTLS_ACK_RANGES 4U
#endif

/* No certificates: minimal pools (the parser still links in mixed builds). */
#ifndef NOXTLS_STATIC_TRUST_ANCHORS_MAX
#define NOXTLS_STATIC_TRUST_ANCHORS_MAX 1U
#endif
#ifndef NOXTLS_STATIC_CERT_DER_MAX
#define NOXTLS_STATIC_CERT_DER_MAX 512U
#endif
#ifndef NOXTLS_STATIC_CERT_CHAIN_DEPTH_MAX
#define NOXTLS_STATIC_CERT_CHAIN_DEPTH_MAX 1U
#endif
#ifndef NOXTLS_STATIC_GLOBAL_EXTRA
#define NOXTLS_STATIC_GLOBAL_EXTRA 1024U
#endif

/* One management session; process-global server caches off. */
#ifndef NOXTLS_STATIC_MAX_CONNECTIONS
#define NOXTLS_STATIC_MAX_CONNECTIONS 1U
#endif
#ifndef NOXTLS_TLS13_PSK_TICKET_STORE_MAX
#define NOXTLS_TLS13_PSK_TICKET_STORE_MAX 0U
#endif
#ifndef NOXTLS_TLS12_SESSION_CACHE_SIZE
#define NOXTLS_TLS12_SESSION_CACHE_SIZE 0U
#endif
#ifndef NOXTLS_TLS12_TICKET_CACHE_SIZE
#define NOXTLS_TLS12_TICKET_CACHE_SIZE 0U
#endif

#endif /* NOXTLS_STATIC_PROFILE_NODE_H_ */
