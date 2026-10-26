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
* File:    dtls13_record_discard_ut.c
* Summary: DTLS 1.3 invalid-record discard, integrity limit and alert reporting
*****************************************************************************/
/** @file dtls13_record_discard_ut.c
 * @brief RFC 9147 (DTLS 1.3, April 2022) Sections 4.5.2 and 4.5.3 and RFC 8446 Section 6
 * alert reporting, exercised with real PSK-DHE handshakes over a test datagram queue.
 * @ingroup noxtls_dtls13_recovery
 */
#include "dtls13_record_discard_fixture.h"
#include "tls/noxtls_tls_common.h"
#include "tls/noxtls_tls13_config.h"
#include "common/noxtls_memory.h"
#include "runner.h"
#include "test_assert.h"
#include <stdio.h>
#include <string.h>

static recovery_endpoint_t s_client;
static recovery_endpoint_t s_server;
static uint64_t s_now;
/* Server encrypted records are lost while set (holds the client after ServerHello). */
static bool s_hold_server_encrypted;
/* Damage the next encrypted server record handed to the transport. */
static bool s_corrupt_next_server_encrypted;
static uint32_t s_corrupted;

/** @brief Supply a deterministic monotonic clock.
 * @internal
 *
 * @param[in] context Unused transport binding.
 *
 * @return Virtual milliseconds.
 */
static uint64_t now_ms(void *context)
{
    (void)context;
    return s_now;
}

/** @brief Report whether a datagram starts with a DTLSCiphertext unified header.
 * @internal
 *
 * @param[in] data Datagram bytes.
 * @param[in] length Datagram length.
 *
 * @return True for a protected record.
 */
static bool is_protected(const uint8_t *data, uint32_t length)
{
    return (length != 0U) && ((data[0] & RECOVERY_ENCRYPTED_MASK) == RECOVERY_ENCRYPTED_HEADER);
}

/** @brief Queue a datagram for the peer, losing or damaging selected server records.
 * @internal
 *
 * @param[in,out] context Sending endpoint.
 * @param[in] data Datagram bytes.
 * @param[in] length Datagram length.
 *
 * @return Datagram length or a transport error.
 */
static int32_t send_packet(void *context, const uint8_t *data, uint32_t length)
{
    recovery_endpoint_t *source = context;
    recovery_endpoint_t *peer = source->peer;
    bool encrypted = is_protected(data, length);

    if((source == &s_server) && encrypted && s_hold_server_encrypted) {
        return (int32_t)length;
    }

    if((length > RECOVERY_PACKET_BYTES) || (peer->count == RECOVERY_QUEUE_DEPTH)) {
        return -1;
    }

    uint32_t index = (peer->head + peer->count) % RECOVERY_QUEUE_DEPTH;
    memcpy(peer->queue[index].bytes, data, length);
    peer->queue[index].length = length;
    ++peer->count;
    if((source == &s_server) && encrypted && s_corrupt_next_server_encrypted) {
        peer->queue[index].bytes[length - 1U] ^= 1U;
        s_corrupt_next_server_encrypted = false;
        ++s_corrupted;
    }

    return (int32_t)length;
}

/** @brief Receive one queued datagram without blocking.
 * @internal
 *
 * @param[in,out] context Receiving endpoint.
 * @param[out] data Caller buffer.
 * @param[in] capacity Buffer size.
 *
 * @return Datagram length, zero if empty, or error for insufficient capacity.
 */
static int32_t receive_packet(void *context, uint8_t *data, uint32_t capacity)
{
    recovery_endpoint_t *endpoint = context;
    if(endpoint->count == 0U) {
        return 0;
    }

    const recovery_packet_t *packet = &endpoint->queue[endpoint->head];
    if(packet->length > capacity) {
        return -1;
    }

    memcpy(data, packet->bytes, packet->length);
    endpoint->head = (endpoint->head + 1U) % RECOVERY_QUEUE_DEPTH;
    --endpoint->count;
    return (int32_t)packet->length;
}

/** @brief Initialize a real external-PSK X25519 AES-128-GCM endpoint.
 * @internal
 *
 * @param[in,out] endpoint Owning test endpoint.
 * @param[in] role Client or server.
 *
 * @return Library initialization result.
 */
static noxtls_return_t initialize(recovery_endpoint_t *endpoint, tls_role_t role)
{
    static const uint8_t identity[] = "discard-test-only";
    static const uint8_t key[] = "not-a-production-key";
    static const uint16_t group = TLS_NAMED_GROUP_X25519;
    static const uint16_t suite = TLS_CIPHER_SUITE_AES_128_GCM_SHA256;
    noxtls_return_t rc = noxtls_dtls13_context_init(&endpoint->tls, role);
    if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }

    endpoint->initialized = true;
    rc = noxtls_tls_set_io_callbacks(&endpoint->tls.base.base, send_packet, receive_packet, endpoint);
    if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }

    rc = noxtls_tls_set_time_callback(&endpoint->tls.base.base, now_ms);
    if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }

    noxtls_tls13_set_client_supported_groups(&endpoint->tls, &group, 1U);
    noxtls_tls13_set_server_cipher_suites(&endpoint->tls, &suite, 1U);
    return tls13_set_external_psk(&endpoint->tls, identity, sizeof(identity) - 1U,
        key, sizeof(key) - 1U, TLS13_PSK_KE_MODE_PSK_DHE_KE);
}

/** @brief Advance one endpoint's handshake or read one record once connected.
 * @internal
 *
 * @param[in,out] endpoint Context to service.
 *
 * @return Library result.
 */
static noxtls_return_t pump(recovery_endpoint_t *endpoint)
{
    if(endpoint->tls.base.base.state == TLS_STATE_CONNECTED) {
        uint8_t buffer[RECOVERY_PACKET_BYTES];
        uint32_t length = sizeof(buffer);
        return noxtls_tls13_recv(&endpoint->tls, buffer, &length);
    }

    return (endpoint == &s_client) ? noxtls_tls13_connect(&endpoint->tls) :
        noxtls_tls13_accept(&endpoint->tls);
}

/** @brief Create a fresh client and server bound to each other.
 * @internal
 *
 * @return Zero on success.
 */
static int start_pair(void)
{
    memset(&s_client, 0, sizeof(s_client));
    memset(&s_server, 0, sizeof(s_server));
    s_client.peer = &s_server;
    s_server.peer = &s_client;
    s_hold_server_encrypted = false;
    s_corrupt_next_server_encrypted = false;
    s_corrupted = 0U;
    s_now = 1U;
    if((initialize(&s_client, TLS_ROLE_CLIENT) != NOXTLS_RETURN_SUCCESS) ||
       (initialize(&s_server, TLS_ROLE_SERVER) != NOXTLS_RETURN_SUCCESS)) { return 1; }

    return 0;
}

/** @brief Run both state machines until the handshake and its final ACK complete.
 * @internal
 *
 * @return Zero once both endpoints are connected with no flight outstanding.
 */
static int complete_handshake(void)
{
    for(uint32_t step = 0U; step < DISCARD_STEPS; ++step) {
        noxtls_return_t client_rc = pump(&s_client);
        noxtls_return_t server_rc = pump(&s_server);
        ++s_now;
        if(((client_rc != NOXTLS_RETURN_SUCCESS) && (client_rc != NOXTLS_RETURN_TIMEOUT)) ||
           ((server_rc != NOXTLS_RETURN_SUCCESS) && (server_rc != NOXTLS_RETURN_TIMEOUT))) { return 1; }

        if((s_client.tls.base.base.state == TLS_STATE_CONNECTED) &&
           (s_server.tls.base.base.state == TLS_STATE_CONNECTED) &&
           (s_client.tls.base.flight_buffer_len == 0U) && (s_client.count == 0U) &&
           (s_server.count == 0U)) { return 0; }
    }

    return 1;
}

/** @brief Release both contexts.
 * @internal
 */
static void release_pair(void)
{
    if(s_client.initialized) { (void)noxtls_tls13_context_free(&s_client.tls); }
    if(s_server.initialized) { (void)noxtls_tls13_context_free(&s_server.tls); }
    s_client.initialized = false;
    s_server.initialized = false;
}

/** @brief Send one application message and require the peer to read it intact.
 * @internal
 *
 * @param[in,out] from Sending endpoint.
 * @param[in,out] to Receiving endpoint.
 *
 * @return Zero on success.
 */
static int exchange(recovery_endpoint_t *from, recovery_endpoint_t *to)
{
    static const uint8_t payload[] = "led=1";
    uint8_t buffer[RECOVERY_PACKET_BYTES];
    uint32_t length = sizeof(buffer);

    if(noxtls_tls13_send(&from->tls, payload, sizeof(payload)) != NOXTLS_RETURN_SUCCESS) { return 1; }

    if((noxtls_tls13_recv(&to->tls, buffer, &length) != NOXTLS_RETURN_SUCCESS) ||
       (length != sizeof(payload)) || (memcmp(buffer, payload, length) != 0)) { return 2; }

    return 0;
}

/** @brief Return the newest datagram queued for an endpoint.
 * @internal
 *
 * @param[in] endpoint Receiving endpoint with at least one queued datagram.
 *
 * @return The datagram.
 */
static recovery_packet_t *newest(recovery_endpoint_t *endpoint)
{
    return &endpoint->queue[(endpoint->head + endpoint->count - 1U) % RECOVERY_QUEUE_DEPTH];
}

/** @brief Damage one queued protected application record.
 * @internal
 *
 * @param[in,out] packet Datagram holding one DTLSCiphertext with a 16-bit sequence number.
 * @param[in] kind Damage to apply.
 */
static void tamper(recovery_packet_t *packet, discard_tamper_t kind)
{
    uint8_t *bytes = packet->bytes;
    uint32_t sequence_bytes = ((bytes[0] & DTLS13_UNIFIED_S_BIT) != 0U) ? DISCARD_SEQUENCE_LONG : DISCARD_SEQUENCE_SHORT;
    uint32_t length_offset = DISCARD_FLAGS_BYTES + sequence_bytes;
    uint32_t header = length_offset + (((bytes[0] & DTLS13_UNIFIED_L_BIT) != 0U) ? DISCARD_LENGTH_BYTES : 0U);

    switch(kind) {
        case DISCARD_TAMPER_TAG:
            bytes[packet->length - 1U] ^= 1U;
            break;
        case DISCARD_TAMPER_SAMPLE:
            bytes[header] ^= 1U;
            break;
        case DISCARD_TAMPER_EPOCH:
            bytes[0] ^= DISCARD_EPOCH_FLIP;
            break;
        case DISCARD_TAMPER_CID:
            bytes[0] |= DTLS13_UNIFIED_CID_BIT;
            break;
        case DISCARD_TAMPER_LENGTH:
            bytes[0] |= DTLS13_UNIFIED_L_BIT;
            bytes[length_offset] = UINT8_MAX;
            break;
        case DISCARD_TAMPER_TRUNCATE:
            --packet->length;
            break;
        case DISCARD_TAMPER_FIXED_BITS:
            bytes[0] ^= DISCARD_FIXED_BITS_FLIP;
            break;
        default:
            bytes[0] = TLS_RECORD_ALERT;
            break;
    }
}

/** @brief Compare two alert reports.
 * @internal
 *
 * @param[in] alert Report read from the library.
 * @param[in] level Expected AlertLevel.
 * @param[in] description Expected AlertDescription.
 *
 * @return True when the report is valid and matches.
 */
static bool alert_is(const noxtls_tls_alert_info_t *alert, uint8_t level, uint8_t description)
{
    return (alert->valid == 1U) && (alert->level == level) && (alert->description == description);
}

/** @brief Deliver one damaged record and require the observable discard behavior.
 * @internal
 *
 * Every invalid record must leave the same trace: the read returns TIMEOUT with no data,
 * the connection stays up, nothing is sent to the peer, no alert is generated and the
 * replay and record-number state is unchanged (RFC 9147 4.5.2).
 *
 * @param[in] kind Damage to apply.
 *
 * @return Zero on success.
 */
static int discard_one(discard_tamper_t kind)
{
    static const uint8_t payload[] = "corrupt";
    uint8_t buffer[RECOVERY_PACKET_BYTES];
    uint32_t length = sizeof(buffer);
    noxtls_tls_alert_info_t alert;
    dtls_context_t *server = &s_server.tls.base;
    const uint32_t slot = DTLS13_EPOCH_APPLICATION & DTLS13_UNIFIED_EPOCH_MASK;

    if(noxtls_tls13_send(&s_client.tls, payload, sizeof(payload)) != NOXTLS_RETURN_SUCCESS) { return 1; }

    tamper(newest(&s_server), kind);
    dtls_replay_window_t window = server->replay_windows[slot];
    uint64_t read_sequence = server->read_seq_num;
    uint64_t highest = server->highest_recv_seq[slot];
    uint32_t client_queued = s_client.count;

    noxtls_return_t rc = noxtls_tls13_recv(&s_server.tls, buffer, &length);
    (void)noxtls_tls_get_last_alert_sent(&server->base, &alert);
    if((rc != NOXTLS_RETURN_TIMEOUT) || (length != 0U) ||
       (server->base.state != TLS_STATE_CONNECTED) || (s_client.count != client_queued) ||
       (alert.valid != 0U) || (server->read_seq_num != read_sequence) ||
       (server->highest_recv_seq[slot] != highest) ||
       (memcmp(&window, &server->replay_windows[slot], sizeof(window)) != 0)) {
        fprintf(stderr, "discard kind %u: rc=%u len=%u state=%u alert=%u\n",
                (unsigned)kind, (unsigned)rc, (unsigned)length, (unsigned)server->base.state,
                (unsigned)alert.valid);
        return 2;
    }

    return exchange(&s_client, &s_server);
}

/** @brief A record that fails AEAD verification mid-session is discarded; data continues.
 * @return Zero on success. */
REGISTER_TEST(dtls13_discard_tampered_record_keeps_session)
{
    noxtls_tls_alert_info_t alert;
    UTNOX_EQUALS(start_pair(), 0);
    UTNOX_EQUALS(complete_handshake(), 0);
    UTNOX_EQUALS(exchange(&s_client, &s_server), 0);
    UTNOX_EQUALS(discard_one(DISCARD_TAMPER_TAG), 0);
    UTNOX_EQUALS(s_server.tls.base.integrity_failures, 1U);
    UTNOX_EQUALS(s_server.tls.base.integrity_failure_epoch, s_server.tls.base.read_connection_epoch);
    UTNOX_EQUALS(exchange(&s_server, &s_client), 0);
    UTNOX_EQUALS(noxtls_tls_get_last_alert_received(&s_client.tls.base.base, &alert), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(alert.valid, 0U);
    release_pair();
    return 0;
}

/** @brief Every kind of invalid record is discarded with the same observable behavior.
 * @return Zero on success. */
REGISTER_TEST(dtls13_discard_invalid_records_uniformly)
{
    UTNOX_EQUALS(start_pair(), 0);
    UTNOX_EQUALS(complete_handshake(), 0);
    for(uint32_t kind = 0U; kind < (uint32_t)DISCARD_TAMPER_COUNT; ++kind) {
        UTNOX_EQUALS(discard_one((discard_tamper_t)kind), 0);
    }

    /* Only deprotection failures count toward the integrity limit (RFC 9147 4.5.3). */
    UTNOX_EQUALS(s_server.tls.base.integrity_failures > 0U, true);
    UTNOX_EQUALS(s_server.tls.base.integrity_failures < (uint64_t)DISCARD_TAMPER_COUNT, true);
    UTNOX_EQUALS(exchange(&s_server, &s_client), 0);
    release_pair();
    return 0;
}

/** @brief Exceeding the AES-128-GCM integrity limit closes with bad_record_mac.
 * @return Zero on success. */
REGISTER_TEST(dtls13_integrity_limit_closes_connection)
{
    static const uint8_t payload[] = "limit";
    uint8_t buffer[RECOVERY_PACKET_BYTES];
    uint32_t length = sizeof(buffer);
    noxtls_tls_alert_info_t alert;
    dtls_context_t *server = &s_server.tls.base;
    UTNOX_EQUALS(start_pair(), 0);
    UTNOX_EQUALS(complete_handshake(), 0);

    /* One below the limit: the failure that reaches the limit is still discarded. */
    server->integrity_failure_epoch = server->read_connection_epoch;
    server->integrity_failures = DISCARD_LIMIT_GCM_CHACHA - 1U;
    UTNOX_EQUALS(discard_one(DISCARD_TAMPER_TAG), 0);
    UTNOX_EQUALS(server->integrity_failures, DISCARD_LIMIT_GCM_CHACHA);

    /* The next failure exceeds it: the connection closes. */
    UTNOX_EQUALS(noxtls_tls13_send(&s_client.tls, payload, sizeof(payload)), NOXTLS_RETURN_SUCCESS);
    tamper(newest(&s_server), DISCARD_TAMPER_TAG);
    UTNOX_EQUALS(noxtls_tls13_recv(&s_server.tls, buffer, &length), NOXTLS_RETURN_TLS_RECORD_AUTH_FAILED);
    UTNOX_EQUALS(server->base.state, TLS_STATE_CLOSED);
    UTNOX_EQUALS(noxtls_tls_get_last_alert_sent(&server->base, &alert), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(alert_is(&alert, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_BAD_RECORD_MAC), true);

    /* The peer reads the protected bad_record_mac (20) alert and reports it. */
    length = sizeof(buffer);
    UTNOX_EQUALS(noxtls_tls13_recv(&s_client.tls, buffer, &length), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(s_client.tls.base.base.state, TLS_STATE_CLOSED);
    UTNOX_EQUALS(noxtls_tls_get_last_alert_received(&s_client.tls.base.base, &alert), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(alert_is(&alert, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_BAD_RECORD_MAC), true);
    release_pair();
    return 0;
}

/** @brief The failure count belongs to one read key and restarts with a new epoch.
 * @return Zero on success. */
REGISTER_TEST(dtls13_integrity_count_per_key)
{
    dtls_context_t *server = &s_server.tls.base;
    UTNOX_EQUALS(start_pair(), 0);
    UTNOX_EQUALS(complete_handshake(), 0);
    server->integrity_failure_epoch = server->read_connection_epoch - 1U;
    server->integrity_failures = DISCARD_LIMIT_GCM_CHACHA;
    UTNOX_EQUALS(discard_one(DISCARD_TAMPER_SAMPLE), 0);
    UTNOX_EQUALS(server->integrity_failures, 1U);
    UTNOX_EQUALS(server->integrity_failure_epoch, server->read_connection_epoch);
    release_pair();
    return 0;
}

/** @brief Integrity limits per AEAD from RFC 9147 4.5.3, including unsupported suites.
 * @return Zero on success. */
REGISTER_TEST(dtls13_integrity_limit_values)
{
#if NOXTLS_FEATURE_AES_GCM
    UTNOX_EQUALS(noxtls_dtls13_integrity_limit(TLS_CIPHER_SUITE_AES_128_GCM_SHA256), DISCARD_LIMIT_GCM_CHACHA);
    UTNOX_EQUALS(noxtls_dtls13_integrity_limit(TLS_CIPHER_SUITE_AES_256_GCM_SHA384), DISCARD_LIMIT_GCM_CHACHA);
#endif
#if NOXTLS_FEATURE_CHACHA20_POLY1305
    UTNOX_EQUALS(noxtls_dtls13_integrity_limit(TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256), DISCARD_LIMIT_GCM_CHACHA);
#endif
#if NOXTLS_FEATURE_AES_CCM
    UTNOX_EQUALS(noxtls_dtls13_integrity_limit(TLS_CIPHER_SUITE_AES_128_CCM_SHA256), DISCARD_LIMIT_CCM);
    UTNOX_EQUALS(noxtls_dtls13_integrity_limit(TLS_CIPHER_SUITE_AES_128_CCM_8_SHA256), DISCARD_LIMIT_CCM_8);
#endif
    UTNOX_EQUALS(noxtls_dtls13_integrity_limit(0U), 0U);
    UTNOX_EQUALS(noxtls_dtls13_integrity_limit(DISCARD_UNKNOWN_SUITE), 0U);
    UTNOX_EQUALS(NOXTLS_DTLS13_INTEGRITY_LIMIT_GCM_CHACHA, DISCARD_LIMIT_GCM_CHACHA);
    return 0;
}

/** @brief A peer's protected close_notify is reported with its level and description.
 * @return Zero on success. */
REGISTER_TEST(dtls13_close_notify_reported)
{
    uint8_t buffer[RECOVERY_PACKET_BYTES];
    uint32_t length = sizeof(buffer);
    noxtls_tls_alert_info_t alert;
    UTNOX_EQUALS(start_pair(), 0);
    UTNOX_EQUALS(complete_handshake(), 0);
    UTNOX_EQUALS(noxtls_tls13_close(&s_client.tls), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(s_server.count, 1U);
    UTNOX_EQUALS(is_protected(newest(&s_server)->bytes, newest(&s_server)->length), true);
    UTNOX_EQUALS(noxtls_tls_get_last_alert_sent(&s_client.tls.base.base, &alert), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(alert_is(&alert, TLS_ALERT_LEVEL_WARNING, TLS_ALERT_CLOSE_NOTIFY), true);
    UTNOX_EQUALS(noxtls_tls13_recv(&s_server.tls, buffer, &length), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(length, 0U);
    UTNOX_EQUALS(s_server.tls.base.base.state, TLS_STATE_CLOSING);
    UTNOX_EQUALS(noxtls_tls_get_last_alert_received(&s_server.tls.base.base, &alert), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(alert_is(&alert, TLS_ALERT_LEVEL_WARNING, TLS_ALERT_CLOSE_NOTIFY), true);
    release_pair();
    return 0;
}

/** @brief An authentic record without a content type is fatal (RFC 8446 5.4) and the
 * peer reads unexpected_message (10).
 * @return Zero on success. */
REGISTER_TEST(dtls13_authentic_invalid_record_fatal)
{
    uint8_t zeros[DISCARD_ZERO_INNER_BYTES] = {0U};
    uint8_t buffer[RECOVERY_PACKET_BYTES];
    uint32_t length = sizeof(buffer);
    noxtls_tls_alert_info_t alert;
    UTNOX_EQUALS(start_pair(), 0);
    UTNOX_EQUALS(complete_handshake(), 0);
    UTNOX_EQUALS(noxtls_tls13_send_dtls13_encrypted_record(&s_server.tls, 0,
        TLS_RECORD_APPLICATION_DATA, zeros, sizeof(zeros), 0), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_tls13_recv(&s_client.tls, buffer, &length), NOXTLS_RETURN_TLS_ERROR);
    UTNOX_EQUALS(s_client.tls.base.base.state, TLS_STATE_CLOSED);
    UTNOX_EQUALS(s_client.tls.base.integrity_failures, 0U);
    UTNOX_EQUALS(noxtls_tls_get_last_alert_sent(&s_client.tls.base.base, &alert), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(alert_is(&alert, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE), true);
    length = sizeof(buffer);
    UTNOX_EQUALS(noxtls_tls13_recv(&s_server.tls, buffer, &length), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(s_server.tls.base.base.state, TLS_STATE_CLOSED);
    UTNOX_EQUALS(noxtls_tls_get_last_alert_received(&s_server.tls.base.base, &alert), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(alert_is(&alert, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE), true);
    release_pair();
    return 0;
}

/** @brief An unprotected alert after the handshake cannot end the association.
 * @return Zero on success. */
REGISTER_TEST(dtls13_unprotected_alert_discarded)
{
    uint8_t buffer[RECOVERY_PACKET_BYTES];
    noxtls_tls_alert_info_t alert;
    UTNOX_EQUALS(start_pair(), 0);
    UTNOX_EQUALS(complete_handshake(), 0);

    /* A DTLSPlaintext fatal handshake_failure in the current epoch, and one in epoch 0. */
    for(uint32_t variant = 0U; variant < 2U; ++variant) {
        recovery_packet_t *packet = &s_server.queue[(s_server.head + s_server.count) % RECOVERY_QUEUE_DEPTH];
        uint16_t epoch = (variant == 0U) ? s_server.tls.base.epoch : 0U;
        memset(packet, 0, sizeof(*packet));
        packet->bytes[DTLS_RECORD_TYPE_OFFSET] = TLS_RECORD_ALERT;
        packet->bytes[DTLS_RECORD_VERSION_OFFSET] = (uint8_t)(DTLS_1_3_LEGACY_RECORD_VERSION >> 8U);
        packet->bytes[DTLS_RECORD_VERSION_OFFSET + 1U] = (uint8_t)DTLS_1_3_LEGACY_RECORD_VERSION;
        packet->bytes[DTLS_RECORD_EPOCH_OFFSET] = (uint8_t)(epoch >> 8U);
        packet->bytes[DTLS_RECORD_EPOCH_OFFSET + 1U] = (uint8_t)epoch;
        packet->bytes[DTLS_RECORD_SEQUENCE_OFFSET + 5U] = DISCARD_PLAINTEXT_SEQUENCE;
        packet->bytes[DTLS_RECORD_LENGTH_OFFSET + 1U] = TLS_ALERT_MESSAGE_LEN;
        packet->bytes[DTLS_RECORD_DATA_OFFSET] = TLS_ALERT_LEVEL_FATAL;
        packet->bytes[DTLS_RECORD_DATA_OFFSET + 1U] = TLS_ALERT_HANDSHAKE_FAILURE;
        packet->length = DTLS_RECORD_HEADER_SIZE + TLS_ALERT_MESSAGE_LEN;
        ++s_server.count;
        uint32_t length = sizeof(buffer);
        UTNOX_EQUALS(noxtls_tls13_recv(&s_server.tls, buffer, &length), NOXTLS_RETURN_TIMEOUT);
        UTNOX_EQUALS(length, 0U);
        UTNOX_EQUALS(s_server.tls.base.base.state, TLS_STATE_CONNECTED);
        UTNOX_EQUALS(s_client.count, 0U);
        UTNOX_EQUALS(noxtls_tls_get_last_alert_received(&s_server.tls.base.base, &alert), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(alert.valid, 0U);
    }

    UTNOX_EQUALS(exchange(&s_client, &s_server), 0);
    release_pair();
    return 0;
}

/** @brief A damaged encrypted handshake record is discarded and retransmission recovers.
 * @return Zero on success. */
REGISTER_TEST(dtls13_handshake_tampered_record_recovers)
{
    noxtls_tls_alert_info_t alert;
    UTNOX_EQUALS(start_pair(), 0);
    s_corrupt_next_server_encrypted = true;
    UTNOX_EQUALS(complete_handshake(), 0);
    UTNOX_EQUALS(s_corrupted, 1U);
    UTNOX_EQUALS(noxtls_tls_get_last_alert_sent(&s_client.tls.base.base, &alert), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(alert.valid, 0U);
    UTNOX_EQUALS(noxtls_tls_get_last_alert_received(&s_server.tls.base.base, &alert), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(alert.valid, 0U);
    UTNOX_EQUALS(exchange(&s_client, &s_server), 0);
    UTNOX_EQUALS(exchange(&s_server, &s_client), 0);
    release_pair();
    return 0;
}

/** @brief Hold the client after ServerHello, then deliver one client handshake-epoch record.
 * @internal
 *
 * @param[in] inner TLSInnerPlaintext the client protects with its handshake keys.
 * @param[in] inner_len Length of @p inner.
 * @param[in] content_type Record content type passed to the record layer.
 * @param[out] server_rc Result of the server's next handshake step.
 *
 * @return Zero on success.
 */
static int inject_client_handshake_record(const uint8_t *inner, uint32_t inner_len, uint8_t content_type,
                                          noxtls_return_t *server_rc)
{
    if(start_pair() != 0) { return 1; }

    s_hold_server_encrypted = true;
    for(uint32_t step = 0U; (step < DISCARD_STEPS) && (s_client.tls.base.epoch != DTLS13_EPOCH_HANDSHAKE); ++step) {
        (void)pump(&s_client);
        (void)pump(&s_server);
        ++s_now;
    }

    if((s_client.tls.base.epoch != DTLS13_EPOCH_HANDSHAKE) ||
       (s_server.tls.base.base.state == TLS_STATE_CONNECTED)) { return 2; }

    s_server.count = 0U;
    if(noxtls_tls13_send_dtls13_encrypted_record(&s_client.tls, 1, content_type, inner, inner_len, 0) !=
       NOXTLS_RETURN_SUCCESS) { return 3; }

    *server_rc = pump(&s_server);
    return 0;
}

/** @brief An authentic handshake-epoch record without a content type ends the handshake
 * with unexpected_message (RFC 8446 5.4).
 * @return Zero on success. */
REGISTER_TEST(dtls13_handshake_authentic_invalid_fatal)
{
    uint8_t zeros[DISCARD_ZERO_INNER_BYTES] = {0U};
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    noxtls_tls_alert_info_t alert;
    UTNOX_EQUALS(inject_client_handshake_record(zeros, sizeof(zeros), TLS_RECORD_HANDSHAKE, &rc), 0);
    UTNOX_EQUALS(rc != NOXTLS_RETURN_SUCCESS, true);
    UTNOX_EQUALS(rc != NOXTLS_RETURN_TIMEOUT, true);
    UTNOX_EQUALS(s_server.tls.base.integrity_failures, 0U);
    UTNOX_EQUALS(noxtls_tls_get_last_alert_sent(&s_server.tls.base.base, &alert), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(alert_is(&alert, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE), true);
    release_pair();
    return 0;
}

/** @brief A protected alert during the handshake ends it and is reported to the server.
 * @return Zero on success. */
REGISTER_TEST(dtls13_handshake_peer_alert_reported)
{
    const uint8_t inner[TLS_ALERT_MESSAGE_LEN + 1U] = {
        TLS_ALERT_LEVEL_FATAL, TLS_ALERT_HANDSHAKE_FAILURE, TLS_RECORD_ALERT };
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    noxtls_tls_alert_info_t alert;
    UTNOX_EQUALS(inject_client_handshake_record(inner, sizeof(inner), TLS_RECORD_ALERT, &rc), 0);
    UTNOX_EQUALS(rc, NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(s_server.tls.base.base.state, TLS_STATE_CLOSED);
    UTNOX_EQUALS(noxtls_tls_get_last_alert_received(&s_server.tls.base.base, &alert), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(alert_is(&alert, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_HANDSHAKE_FAILURE), true);
    UTNOX_EQUALS(noxtls_tls_get_last_alert_sent(&s_server.tls.base.base, &alert), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(alert.valid, 0U);
    release_pair();
    return 0;
}

/** @brief A protected message too short to be an alert is answered with unexpected_message.
 * @return Zero on success. */
REGISTER_TEST(dtls13_handshake_short_alert_fatal)
{
    const uint8_t inner[TLS_ALERT_MESSAGE_LEN] = { TLS_ALERT_LEVEL_FATAL, TLS_RECORD_ALERT };
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    noxtls_tls_alert_info_t alert;
    UTNOX_EQUALS(inject_client_handshake_record(inner, sizeof(inner), TLS_RECORD_ALERT, &rc), 0);
    UTNOX_EQUALS(rc, NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(noxtls_tls_get_last_alert_received(&s_server.tls.base.base, &alert), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(alert.valid, 0U);
    UTNOX_EQUALS(noxtls_tls_get_last_alert_sent(&s_server.tls.base.base, &alert), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(alert_is(&alert, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE), true);
    release_pair();
    return 0;
}

/** @brief Alert accessors reject NULL and report nothing before any alert.
 * @return Zero on success. */
REGISTER_TEST(dtls13_alert_accessors_boundaries)
{
    noxtls_tls_alert_info_t alert;
    tls_context_t *base = NULL;
    UTNOX_EQUALS(start_pair(), 0);
    base = &s_client.tls.base.base;
    UTNOX_EQUALS(noxtls_tls_get_last_alert_received(NULL, &alert), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_tls_get_last_alert_received(base, NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_tls_get_last_alert_sent(NULL, &alert), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_tls_get_last_alert_sent(base, NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_tls_get_last_alert_received(base, &alert), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(alert.valid, 0U);
    UTNOX_EQUALS(noxtls_tls_get_last_alert_sent(base, &alert), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(alert.valid, 0U);
    noxtls_tls_note_alert_received(NULL, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_BAD_RECORD_MAC);
    noxtls_tls_note_alert_sent(NULL, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_BAD_RECORD_MAC);
    noxtls_tls_note_alert_received(base, UINT8_MAX, UINT8_MAX);
    UTNOX_EQUALS(noxtls_tls_get_last_alert_received(base, &alert), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(alert_is(&alert, UINT8_MAX, UINT8_MAX), true);
    noxtls_tls_note_alert_sent(base, TLS_ALERT_LEVEL_WARNING, TLS_ALERT_CLOSE_NOTIFY);
    UTNOX_EQUALS(noxtls_tls_get_last_alert_sent(base, &alert), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(alert_is(&alert, TLS_ALERT_LEVEL_WARNING, TLS_ALERT_CLOSE_NOTIFY), true);
    release_pair();
    return 0;
}

#if defined(_MSC_VER)
/** @brief Register tests where compiler constructor registration is unavailable. */
void utnox_register_tests(void)
{
    register_test(__reg_dtls13_discard_tampered_record_keeps_session.name, __reg_dtls13_discard_tampered_record_keeps_session.func);
    register_test(__reg_dtls13_discard_invalid_records_uniformly.name, __reg_dtls13_discard_invalid_records_uniformly.func);
    register_test(__reg_dtls13_integrity_limit_closes_connection.name, __reg_dtls13_integrity_limit_closes_connection.func);
    register_test(__reg_dtls13_integrity_count_per_key.name, __reg_dtls13_integrity_count_per_key.func);
    register_test(__reg_dtls13_integrity_limit_values.name, __reg_dtls13_integrity_limit_values.func);
    register_test(__reg_dtls13_close_notify_reported.name, __reg_dtls13_close_notify_reported.func);
    register_test(__reg_dtls13_authentic_invalid_record_fatal.name, __reg_dtls13_authentic_invalid_record_fatal.func);
    register_test(__reg_dtls13_unprotected_alert_discarded.name, __reg_dtls13_unprotected_alert_discarded.func);
    register_test(__reg_dtls13_handshake_tampered_record_recovers.name, __reg_dtls13_handshake_tampered_record_recovers.func);
    register_test(__reg_dtls13_handshake_authentic_invalid_fatal.name, __reg_dtls13_handshake_authentic_invalid_fatal.func);
    register_test(__reg_dtls13_handshake_peer_alert_reported.name, __reg_dtls13_handshake_peer_alert_reported.func);
    register_test(__reg_dtls13_handshake_short_alert_fatal.name, __reg_dtls13_handshake_short_alert_fatal.func);
    register_test(__reg_dtls13_alert_accessors_boundaries.name, __reg_dtls13_alert_accessors_boundaries.func);
}
#endif
