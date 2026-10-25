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
* File:    noxtls_static_profile_host_client.h
* Summary: Static memory profile: DTLS 1.3 PSK client (native host helper)
*****************************************************************************/
/**
 * @file noxtls_static_profile_host_client.h
 * @brief Native host management helper: DTLS 1.3 client, external PSK with X25519
 *        (PSK-DHE), TLS_AES_128_GCM_SHA256, talking to the node profile.
 *
 * The record and handshake limits match noxtls_static_profile_node.h so that the
 * helper never sends anything the node refuses. The connection block is
 * NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_CLIENT, DTLS13_PSK) bytes, passed to
 * noxtls_dtls13_context_init_static(..., NOXTLS_CONN_PROFILE_DTLS13_PSK, ...).
 * NOXTLS_STATIC_MAX_CONNECTIONS may be raised for a helper that manages several
 * nodes at once (one block per connection).
 */
#ifndef NOXTLS_STATIC_PROFILE_HOST_CLIENT_H_
#define NOXTLS_STATIC_PROFILE_HOST_CLIENT_H_

#ifndef NOXTLS_CONFIG_STATIC_MEMORY
#define NOXTLS_CONFIG_STATIC_MEMORY 1
#endif
#ifndef NOXTLS_TLS_MAX_RECORD_SIZE
#define NOXTLS_TLS_MAX_RECORD_SIZE 512U
#endif
#ifndef NOXTLS_TLS_HANDSHAKE_WORKSPACE_SIZE
#define NOXTLS_TLS_HANDSHAKE_WORKSPACE_SIZE 4096U
#endif
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
#ifndef NOXTLS_STATIC_MAX_CONNECTIONS
#define NOXTLS_STATIC_MAX_CONNECTIONS 1U
#endif

#endif /* NOXTLS_STATIC_PROFILE_HOST_CLIENT_H_ */
