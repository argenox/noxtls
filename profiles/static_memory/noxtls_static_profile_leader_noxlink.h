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
* File:    noxtls_static_profile_leader_noxlink.h
* Summary: Static memory profile: leader with the NoxLink DTLS 1.3 PSK server
*****************************************************************************/
/**
 * @file noxtls_static_profile_leader_noxlink.h
 * @brief Wi-Fi leader (CC35x1) holding the NoxLink server associations next to its
 *        node-facing associations and its MQTT connection.
 *
 * Connections (NOXTLS_STATIC_MAX_CONNECTIONS):
 * - one TLS 1.3 certificate client: MQTT to AWS IoT Core (TLS13_CERT block);
 * - three DTLS 1.3 PSK servers: NoxLink `nlk1-fleet` and `nlk1-local`, plus the
 *   association that replaces one of them during a re-handshake (DTLS13_PSK);
 * - four DTLS 1.3 PSK clients: the persistent node associations (DTLS13_PSK).
 *
 * The DTLS 1.3 PSK contexts can use noxtls_dtls13_context_init_static_split(): each has
 * a NOXTLS_CONNECTION_MEMORY_STEADY_SIZE(role, DTLS13_PSK) block, and the contexts whose
 * handshakes the application serializes take turns with one
 * NOXTLS_CONNECTION_MEMORY_HANDSHAKE_SIZE(role, DTLS13_PSK) block.
 *
 * Records: NoxLink carries frames of up to 1,400 bytes in one record per datagram
 * (BACKEND_LEADER_CHANNEL.md C2, C3), so the largest plaintext is 1,400 bytes and the
 * NoxLink contexts advertise record_size_limit 1,401 (the default: the largest
 * plaintext plus the inner content type, RFC 8449 Section 4). The MQTT and node
 * contexts keep their smaller limits with noxtls_tls13_set_record_size_limit() (513
 * for 512-byte records); only their buffers follow the larger size.
 *
 * Everything else is the leader profile (noxtls_static_profile_leader.h).
 */
#ifndef NOXTLS_STATIC_PROFILE_LEADER_NOXLINK_H_
#define NOXTLS_STATIC_PROFILE_LEADER_NOXLINK_H_

#ifndef NOXTLS_TLS_MAX_RECORD_SIZE
#define NOXTLS_TLS_MAX_RECORD_SIZE 1400U
#endif
/* MQTT + 3 NoxLink servers + 4 node clients. */
#ifndef NOXTLS_STATIC_MAX_CONNECTIONS
#define NOXTLS_STATIC_MAX_CONNECTIONS 8U
#endif

/*
 * Budgets set from measured peaks (docs/static-memory.md, profile (iv)). The peaks are
 * the highest of every test under this profile (ut/multi_context mc_leader_*, the 28
 * DTLS 1.3 recovery cases and the record-discard cases in DTLS13_PSK blocks,
 * ut/static_memory), measured on x86-64, whose structures are larger than on the
 * Cortex-M33, plus 25%. Beyond a budget a connection fails with
 * NOXTLS_RETURN_NOT_ENOUGH_MEMORY (mc_leader_budget_limits).
 */
#if (NOXTLS_TLS_MAX_RECORD_SIZE == 1400U)
/* Measured with 1,400-byte records; another record size keeps the derived budgets. */
/* DTLS 1.3 PSK handshake: peak 11,248 (no MTU set: 1.5 KB fragment buffer, loss and
 * reorder cases); NoxLink servers and node clients measure 10,776 at most. */
#ifndef NOXTLS_STATIC_HS_ARENA_DTLS_PSK
#define NOXTLS_STATIC_HS_ARENA_DTLS_PSK 14080U
#endif
/* DTLS 1.3 steady state: peak 2,912 (a 1,429-byte datagram and its 1,399-byte record,
 * also with records read in 100-byte pieces); 25% holds a further post-handshake
 * message of 256 bytes (KeyUpdate, NewConnectionId). DTLS 1.3 servers issue no
 * NewSessionTicket. */
#ifndef NOXTLS_STATIC_STEADY_ARENA_DTLS
#define NOXTLS_STATIC_STEADY_ARENA_DTLS 3648U
#endif
#endif
/* Unchanged: the TLS 1.3 certificate handshake arena (the largest chain the profile
 * accepts, four certificates of 2,040 bytes, measures 54,816 of the 56,856 budgeted on
 * x86-64) and the TLS steady arena (it holds a broker NewSessionTicket of up to
 * NOXTLS_STATIC_POST_HANDSHAKE_MSG_MAX, which no test can send at that size). */
/* The MQTT client verifies the broker with its own anchors (verify policy), so the
 * process trust store holds at most the two roots of a broker's RSA and ECC endpoints. */
#ifndef NOXTLS_STATIC_TRUST_ANCHORS_MAX
#define NOXTLS_STATIC_TRUST_ANCHORS_MAX 2U
#endif
/* The leader's identity: its root parsed with a copy into the verify policy's chain and
 * its P-256 device key, 2,992 bytes with an 859-byte root, 4,181 with a root of
 * NOXTLS_STATIC_CERT_DER_MAX; plus 25%. An RSA-2048 device key needs about 7 KB. */
#ifndef NOXTLS_STATIC_GLOBAL_EXTRA
#define NOXTLS_STATIC_GLOBAL_EXTRA 5376U
#endif

#include "noxtls_static_profile_leader.h"

#endif /* NOXTLS_STATIC_PROFILE_LEADER_NOXLINK_H_ */
