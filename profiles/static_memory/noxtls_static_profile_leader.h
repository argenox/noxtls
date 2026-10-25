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
* File:    noxtls_static_profile_leader.h
* Summary: Static memory profile: TLS 1.3 certificate client + DTLS 1.3 PSK client
*****************************************************************************/
/**
 * @file noxtls_static_profile_leader.h
 * @brief Wi-Fi leader (CC35x1): one TLS 1.3 client with X.509 certificates (MQTT to
 *        AWS IoT Core, mutual authentication, RSA or ECDSA chains) and one DTLS 1.3
 *        PSK client toward the Thread nodes.
 *
 * Blocks: NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_CLIENT, TLS13_CERT) for MQTT and
 * NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_CLIENT, DTLS13_PSK) for the node channel.
 * The global arena holds the trust store (NOXTLS_STATIC_TRUST_ANCHORS_MAX roots,
 * for example Amazon Root CA 1 and 3) and the device key/certificate the
 * application parses (NOXTLS_STATIC_GLOBAL_EXTRA).
 *
 * AWS IoT Core presents leaf + intermediate (about 1.2 to 1.8 KB each); a chain
 * that also carries the cross-signed root still fits four 2 KB certificates.
 * The record size stays at 512 bytes as in the leader's current configuration;
 * the server must honor record_size_limit (RFC 8449) for that, as it does today.
 */
#ifndef NOXTLS_STATIC_PROFILE_LEADER_H_
#define NOXTLS_STATIC_PROFILE_LEADER_H_

#ifndef NOXTLS_CONFIG_STATIC_MEMORY
#define NOXTLS_CONFIG_STATIC_MEMORY 1
#endif
#ifndef NOXTLS_TLS_MAX_RECORD_SIZE
#define NOXTLS_TLS_MAX_RECORD_SIZE 512U
#endif
#ifndef NOXTLS_TLS_HANDSHAKE_WORKSPACE_SIZE
#define NOXTLS_TLS_HANDSHAKE_WORKSPACE_SIZE 4096U
#endif

/* Certificates: four roots, chains of up to four 2 KB certificates. */
#ifndef NOXTLS_STATIC_TRUST_ANCHORS_MAX
#define NOXTLS_STATIC_TRUST_ANCHORS_MAX 4U
#endif
#ifndef NOXTLS_STATIC_CERT_DER_MAX
#define NOXTLS_STATIC_CERT_DER_MAX 2048U
#endif
#ifndef NOXTLS_STATIC_CERT_CHAIN_DEPTH_MAX
#define NOXTLS_STATIC_CERT_CHAIN_DEPTH_MAX 4U
#endif
#ifndef NOXTLS_TLS_MAX_HANDSHAKE_SIZE
#define NOXTLS_TLS_MAX_HANDSHAKE_SIZE 8448U
#endif
#ifndef NOXTLS_MAX_CERT_SIZE
#define NOXTLS_MAX_CERT_SIZE 2048U
#endif
#ifndef NOXTLS_STATIC_PSK_MSG_MAX
#define NOXTLS_STATIC_PSK_MSG_MAX 1024U
#endif
#ifndef NOXTLS_DTLS_REASSEMBLY_MAX_BYTES
#define NOXTLS_DTLS_REASSEMBLY_MAX_BYTES (NOXTLS_STATIC_PSK_MSG_MAX + 64U + ((NOXTLS_STATIC_PSK_MSG_MAX + 64U) / 8U))
#endif
/* RSA-2048 / P-256 signature verification and RSA-2048 CRT signing. */
#ifndef NOXTLS_STATIC_PKC_SCRATCH_BYTES
#define NOXTLS_STATIC_PKC_SCRATCH_BYTES 8192U
#endif
#ifndef NOXTLS_STATIC_TRANSCRIPT_BYTES
#define NOXTLS_STATIC_TRANSCRIPT_BYTES 2048U
#endif
#ifndef NOXTLS_STATIC_PARSE_BYTES
#define NOXTLS_STATIC_PARSE_BYTES 3072U
#endif
/* NewSessionTicket from the broker may be larger than a KeyUpdate. */
#ifndef NOXTLS_STATIC_POST_HANDSHAKE_MSG_MAX
#define NOXTLS_STATIC_POST_HANDSHAKE_MSG_MAX 2048U
#endif
#ifndef NOXTLS_STATIC_DTLS_ACK_RANGES
#define NOXTLS_STATIC_DTLS_ACK_RANGES 4U
#endif
/* Device RSA-2048 key and certificate parsed by the application. */
#ifndef NOXTLS_STATIC_GLOBAL_EXTRA
#define NOXTLS_STATIC_GLOBAL_EXTRA 8192U
#endif

/* MQTT/TLS and the node DTLS channel. */
#ifndef NOXTLS_STATIC_MAX_CONNECTIONS
#define NOXTLS_STATIC_MAX_CONNECTIONS 2U
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

#endif /* NOXTLS_STATIC_PROFILE_LEADER_H_ */
