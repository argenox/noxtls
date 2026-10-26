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

#include "noxtls_static_profile_leader.h"

#endif /* NOXTLS_STATIC_PROFILE_LEADER_NOXLINK_H_ */
