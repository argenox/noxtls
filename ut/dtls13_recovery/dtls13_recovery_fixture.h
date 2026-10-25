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
* File:    dtls13_recovery_fixture.h
* Summary: Bounded datagram fixtures for DTLS 1.3 recovery tests
*****************************************************************************/
/** @file dtls13_recovery_fixture.h
 * @brief Test-only transport and loss configuration.
 * @defgroup noxtls_dtls13_recovery DTLS 1.3 recovery tests
 * @ingroup noxtls_dtls13_recovery
 */
#ifndef NOXTLS_DTLS13_RECOVERY_FIXTURE_H
#define NOXTLS_DTLS13_RECOVERY_FIXTURE_H
#include "tls/noxtls_tls13.h"
#include <stdbool.h>

#define RECOVERY_PACKET_BYTES 600U
#define RECOVERY_QUEUE_DEPTH 16U
#define RECOVERY_STEPS 15000U
#define RECOVERY_DROP_SERVER 1U
#define RECOVERY_DROP_FINISHED 2U
#define RECOVERY_DROP_ACK 4U
#define RECOVERY_DROP_ALL 7U
#define RECOVERY_DROP_SERVER_HELLO 8U
#define RECOVERY_REORDER_SERVER_HELLO 16U
#define RECOVERY_FINAL_SERVER_HELLO_SEQ 1U
#define RECOVERY_ENCRYPTED_MASK 0xe0U
#define RECOVERY_ENCRYPTED_HEADER 0x20U
#define RECOVERY_P521_SHARE_BYTES 137U
#define RECOVERY_UNIFIED_HEADER_BYTES 5U
#define RECOVERY_EARLY_CIPHERTEXT_BYTES 17U
#define RECOVERY_MAX_BURSTS 32U
#define RECOVERY_BACKOFF_BASE_MS 500U
#define RECOVERY_BACKOFF_MAX_ATTEMPTS 4U
#define RECOVERY_BACKOFF_WINDOW_MS 16000U
/* RFC 9147 5.8.1 repeated-flight cases: the native helper's default client timer
 * (250 ms doubling) and a 10 ms ClientHello storm. */
#define RECOVERY_CLIENT_RTO_MS 250U
#define RECOVERY_CLIENT_ATTEMPTS 6U
#define RECOVERY_REPEAT_LOST_UNTIL_MS 600U
#define RECOVERY_REPEAT_PROMPT_MS 750U
#define RECOVERY_STORM_PERIOD_MS 10U
#define RECOVERY_STORM_WINDOW_MS 5000U
#define RECOVERY_PING_PONG_WINDOW_MS 40000U
#define RECOVERY_PING_PONG_QUIET_MS 20000U
#define RECOVERY_EARLY_PACKET_BYTES (RECOVERY_UNIFIED_HEADER_BYTES + RECOVERY_EARLY_CIPHERTEXT_BYTES)

/** @brief One complete UDP datagram. */
typedef struct {
    uint8_t bytes[RECOVERY_PACKET_BYTES];
    uint32_t length;
} recovery_packet_t;

/** @brief One context, bounded receive queue and test-owned transport state. */
typedef struct recovery_endpoint_s {
    tls13_context_t tls;
    struct recovery_endpoint_s *peer;
    recovery_packet_t queue[RECOVERY_QUEUE_DEPTH];
    uint32_t head;
    uint32_t count;
    uint32_t drop_mask;
    uint32_t dropped;
    uint32_t encrypted_sends;
    uint64_t previous_sequence;
    bool sequence_seen;
    bool sequence_reused;
    bool finished_forwarded;
    bool initialized;
} recovery_endpoint_t;
#endif
