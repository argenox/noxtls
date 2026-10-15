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
* File:    dtls13_recovery_ut.c
* Summary: DTLS 1.3 encrypted flight and final ACK recovery regressions
*****************************************************************************/
/** @file dtls13_recovery_ut.c
 * @brief Exercise real PSK-DHE handshakes and AEAD under datagram loss.
 * @ingroup noxtls_dtls13_recovery
 */
#include "dtls13_recovery_fixture.h"
#include "tls/noxtls_tls_key_exchange.h"
#include "common/noxtls_memory.h"
#include "runner.h"
#include "test_assert.h"
#include <string.h>

static recovery_endpoint_t s_client;
static recovery_endpoint_t s_server;
static uint64_t s_now;
static uint32_t s_flood_reads;
#if NOXTLS_FEATURE_ECC
static tls_ecdhe_context_t s_classical_share;
#endif

/** @brief Supply a deterministic monotonic clock, not cryptographic entropy.
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

/** @brief Deliver a datagram or deliberately lose the selected handshake record.
 * @internal
 *
 * @param[in,out] context Sending endpoint.
 * @param[in] data Complete record bytes.
 * @param[in] length Record length.
 *
 * @return Datagram length or a transport error.
 */
static int32_t send_packet(void *context, const uint8_t *data, uint32_t length)
{
    recovery_endpoint_t *source = context;
    recovery_endpoint_t *peer = source->peer;
    uint32_t drop = 0U;
    bool encrypted = length != 0U &&
        (data[0] & RECOVERY_ENCRYPTED_MASK) == RECOVERY_ENCRYPTED_HEADER;
    if(source == &s_server && length > DTLS_RECORD_HEADER_SIZE + DTLS_HANDSHAKE_HEADER_SIZE &&
       data[0] == TLS_RECORD_HANDSHAKE && data[DTLS_RECORD_DATA_OFFSET] == TLS_HANDSHAKE_SERVER_HELLO &&
       data[DTLS_RECORD_DATA_OFFSET + DTLS_HANDSHAKE_MESSAGE_SEQ_OFFSET] == 0U &&
       data[DTLS_RECORD_DATA_OFFSET + DTLS_HANDSHAKE_MESSAGE_SEQ_OFFSET + 1U] == RECOVERY_FINAL_SERVER_HELLO_SEQ) {
        drop = RECOVERY_DROP_SERVER_HELLO;
    } else if(encrypted && source->tls.base.epoch == DTLS13_EPOCH_HANDSHAKE) {
        uint64_t sequence = source->tls.base.write_seq_num;
        if(source->sequence_seen && sequence <= source->previous_sequence) {
            source->sequence_reused = true;
        }

        source->sequence_seen = true;
        source->previous_sequence = sequence;
        ++source->encrypted_sends;
        drop = source == &s_client ? RECOVERY_DROP_FINISHED : RECOVERY_DROP_SERVER;
    } else if(length != 0U && data[0] == TLS_RECORD_ACK &&
              source == &s_server && s_client.finished_forwarded) {
        drop = RECOVERY_DROP_ACK;
    }

    if((drop & source->drop_mask) != 0U && (drop & source->dropped) == 0U) {
        source->dropped |= drop;
        return (int32_t)length;
    }

    if(source == &s_client && encrypted && source->tls.base.epoch == DTLS13_EPOCH_HANDSHAKE) {
        source->finished_forwarded = true;
    }

    if(length > RECOVERY_PACKET_BYTES || peer->count == RECOVERY_QUEUE_DEPTH) {
        return -1;
    }

    uint32_t index = (peer->head + peer->count) % RECOVERY_QUEUE_DEPTH;
    memcpy(peer->queue[index].bytes, data, length);
    peer->queue[index].length = length;
    ++peer->count;
    return (int32_t)length;
}

/** @brief Receive one datagram without blocking or advancing virtual time.
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

    recovery_packet_t *packet = &endpoint->queue[endpoint->head];
    if(packet->length > capacity) {
        return -1;
    }

    memcpy(data, packet->bytes, packet->length);
    endpoint->head = (endpoint->head + 1U) % RECOVERY_QUEUE_DEPTH;
    --endpoint->count;
    return (int32_t)packet->length;
}

/** @brief Initialize a real external-PSK X25519 endpoint.
 * @internal
 *
 * @param[in,out] endpoint Owning test endpoint.
 * @param[in] role Client or server.
 *
 * @return Library initialization result.
 */
static noxtls_return_t initialize(recovery_endpoint_t *endpoint, tls_role_t role)
{
    static const uint8_t identity[] = "recovery-test-only";
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

/** @brief Advance the real state machine, including timers after local connect.
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

    return endpoint == &s_client ? noxtls_tls13_connect(&endpoint->tls) :
        noxtls_tls13_accept(&endpoint->tls);
}

/** @brief Move one encrypted record before the final ServerHello in the test queue.
 * @return None; the injected condition is recorded in the server's observed mask. */
static void reorder_server_hello(void)
{
    for(uint32_t i = 0U; i + 1U < s_client.count; ++i) {
        recovery_packet_t *hello = &s_client.queue[(s_client.head + i) % RECOVERY_QUEUE_DEPTH];
        if(hello->length <= DTLS_RECORD_HEADER_SIZE + DTLS_HANDSHAKE_HEADER_SIZE ||
           hello->bytes[0] != TLS_RECORD_HANDSHAKE ||
           hello->bytes[DTLS_RECORD_DATA_OFFSET] != TLS_HANDSHAKE_SERVER_HELLO ||
           hello->bytes[DTLS_RECORD_DATA_OFFSET + DTLS_HANDSHAKE_MESSAGE_SEQ_OFFSET + 1U] != RECOVERY_FINAL_SERVER_HELLO_SEQ) {
            continue;
        }

        recovery_packet_t *next = &s_client.queue[(s_client.head + i + 1U) % RECOVERY_QUEUE_DEPTH];
        if(next->length != 0U &&
           (next->bytes[0] & RECOVERY_ENCRYPTED_MASK) == RECOVERY_ENCRYPTED_HEADER) {
            recovery_packet_t saved = *hello;
            *hello = *next;
            *next = saved;
            s_server.dropped |= RECOVERY_REORDER_SERVER_HELLO;
            return;
        }
    }
}

/** @brief Complete a lossy handshake and exchange authenticated application data.
 * @internal
 *
 * @param[in] drops Bitmask of records to lose once each.
 *
 * @return Zero on success.
 */
static int round_trip(uint32_t drops)
{
    static const uint8_t payload[] = "led=1";
    uint8_t buffer[RECOVERY_PACKET_BYTES];
    uint32_t length;
    int result = 1;
    noxtls_return_t client_rc = NOXTLS_RETURN_SUCCESS;
    noxtls_return_t server_rc = NOXTLS_RETURN_SUCCESS;
    memset(&s_client, 0, sizeof(s_client));
    memset(&s_server, 0, sizeof(s_server));
    s_client.peer = &s_server;
    s_server.peer = &s_client;
    s_client.drop_mask = drops;
    s_server.drop_mask = drops;
    s_now = 1U;
    if(initialize(&s_client, TLS_ROLE_CLIENT) != NOXTLS_RETURN_SUCCESS ||
       initialize(&s_server, TLS_ROLE_SERVER) != NOXTLS_RETURN_SUCCESS) { goto cleanup; }

    for(uint32_t step = 0U; step < RECOVERY_STEPS; ++step) {
        client_rc = pump(&s_client);
        server_rc = pump(&s_server);
        if((drops & RECOVERY_REORDER_SERVER_HELLO) != 0U &&
           (s_server.dropped & RECOVERY_REORDER_SERVER_HELLO) == 0U) {
            reorder_server_hello();
        }
        ++s_now;
        if((client_rc != NOXTLS_RETURN_SUCCESS && client_rc != NOXTLS_RETURN_TIMEOUT) ||
           (server_rc != NOXTLS_RETURN_SUCCESS && server_rc != NOXTLS_RETURN_TIMEOUT)) { goto cleanup; }

        if(s_client.tls.base.base.state == TLS_STATE_CONNECTED &&
           s_server.tls.base.base.state == TLS_STATE_CONNECTED &&
           s_client.tls.base.flight_buffer_len == 0U) { break; }
    }

    if(s_client.tls.base.base.state != TLS_STATE_CONNECTED ||
       s_server.tls.base.base.state != TLS_STATE_CONNECTED ||
       s_client.tls.base.flight_buffer_len != 0U ||
       s_server.tls.base.flight_buffer_len != 0U ||
       (s_client.dropped | s_server.dropped) != drops ||
       s_client.sequence_reused || s_server.sequence_reused) { goto cleanup; }

    if(drops == 0U) {
        uint32_t pending = s_client.count;
        uint32_t sent = s_server.encrypted_sends;
        s_now += 2000U;
        (void)pump(&s_server);
        if(s_client.count != pending || s_server.encrypted_sends != sent) { goto cleanup; }
    }

    if(noxtls_tls13_send(&s_client.tls, payload, sizeof(payload)) != NOXTLS_RETURN_SUCCESS) { goto cleanup; }

    length = sizeof(buffer);
    if(noxtls_tls13_recv(&s_server.tls, buffer, &length) != NOXTLS_RETURN_SUCCESS ||
       length != sizeof(payload) || memcmp(buffer, payload, length) != 0) { goto cleanup; }

    if(noxtls_tls13_send(&s_server.tls, payload, sizeof(payload)) != NOXTLS_RETURN_SUCCESS) { goto cleanup; }

    length = sizeof(buffer);
    if(noxtls_tls13_recv(&s_client.tls, buffer, &length) != NOXTLS_RETURN_SUCCESS ||
       length != sizeof(payload) || memcmp(buffer, payload, length) != 0) { goto cleanup; }

    result = 0;
cleanup:
    if(result != 0) {
        fprintf(stderr, "DTLS recovery failed: drops=%u observed=%u rc=%d/%d state=%d/%d\n",
            drops, s_client.dropped | s_server.dropped, client_rc, server_rc,
            s_client.tls.base.base.state, s_server.tls.base.base.state);
    }

    if(s_client.initialized) { (void)noxtls_tls13_context_free(&s_client.tls); }
    if(s_server.initialized) { (void)noxtls_tls13_context_free(&s_server.tls); }
    return result;
}

/** @brief Loss-free baseline succeeds with the same protocol and cipher suite.
 * @return Zero on success. */
REGISTER_TEST(dtls13_recovery_baseline)
{
    return round_trip(0U);
}

/** @brief A missing EncryptedExtensions recovers despite a later Finished.
 * @return Zero on success. */
REGISTER_TEST(dtls13_recovery_server_record)
{
    return round_trip(RECOVERY_DROP_SERVER);
}

/** @brief Client Finished retransmits after application write keys are installed.
 * @return Zero on success. */
REGISTER_TEST(dtls13_recovery_client_finished)
{
    return round_trip(RECOVERY_DROP_FINISHED);
}

/** @brief A lost final ACK causes another Finished and ACK, with fresh record numbers.
 * @return Zero on success. */
REGISTER_TEST(dtls13_recovery_final_ack)
{
    return round_trip(RECOVERY_DROP_ACK);
}

/** @brief Both endpoints recover when all three selected packets are lost.
 * @return Zero on success. */
REGISTER_TEST(dtls13_recovery_combined_loss)
{
    return round_trip(RECOVERY_DROP_ALL);
}

/** @brief Early encrypted records must not terminate a client missing ServerHello.
 * @return Zero after retransmission and authenticated bidirectional data. */
REGISTER_TEST(dtls13_recovery_missing_server_hello)
{
    return round_trip(RECOVERY_DROP_SERVER_HELLO);
}

/** @brief Recover a missing ServerHello together with encrypted-flight and ACK loss.
 * @return Zero after retransmission and authenticated bidirectional data. */
REGISTER_TEST(dtls13_recovery_missing_server_hello_and_flight)
{
    return round_trip(RECOVERY_DROP_SERVER_HELLO | RECOVERY_DROP_ALL);
}

/** @brief Deliver encrypted handshake bytes before ServerHello, as observed on hardware.
 * @return Zero after retransmission and authenticated bidirectional data. */
REGISTER_TEST(dtls13_recovery_reordered_server_hello)
{
    return round_trip(RECOVERY_REORDER_SERVER_HELLO);
}

/** @brief Recover reordering together with encrypted-flight and final-ACK loss.
 * @return Zero after retransmission and authenticated bidirectional data. */
REGISTER_TEST(dtls13_recovery_reordered_server_hello_and_loss)
{
    return round_trip(RECOVERY_REORDER_SERVER_HELLO | RECOVERY_DROP_ALL);
}

/** @brief Fill one synthetic protected record; authentication is intentionally unavailable.
 * @param[out] bytes Record storage with at least RECOVERY_EARLY_PACKET_BYTES bytes.
 * @return None. */
static void early_record(uint8_t *bytes)
{
    memset(bytes, 0, RECOVERY_EARLY_PACKET_BYTES);
    bytes[0] = DTLS13_UNIFIED_FIXED_BITS | DTLS13_UNIFIED_S_BIT |
        DTLS13_UNIFIED_L_BIT | DTLS13_EPOCH_HANDSHAKE;
    bytes[RECOVERY_UNIFIED_HEADER_BYTES - 1U] = RECOVERY_EARLY_CIPHERTEXT_BYTES;
}

/** @brief Fill a minimal epoch-zero record for record-layer delivery checks.
 * @param[out] bytes Record storage with at least DTLS_RECORD_HEADER_SIZE + 1 bytes.
 * @return None. */
static void plaintext_record(uint8_t *bytes)
{
    memset(bytes, 0, DTLS_RECORD_HEADER_SIZE + 1U);
    bytes[DTLS_RECORD_TYPE_OFFSET] = TLS_RECORD_HANDSHAKE;
    bytes[DTLS_RECORD_VERSION_OFFSET] = (uint8_t)(DTLS_1_3_LEGACY_RECORD_VERSION >> 8U);
    bytes[DTLS_RECORD_VERSION_OFFSET + 1U] = (uint8_t)DTLS_1_3_LEGACY_RECORD_VERSION;
    bytes[DTLS_RECORD_LENGTH_OFFSET + 1U] = 1U;
    bytes[DTLS_RECORD_DATA_OFFSET] = TLS_HANDSHAKE_SERVER_HELLO;
}

/** @brief Discard ciphertext before keys exist without ACK or replay mutation.
 * @return Zero on success. */
REGISTER_TEST(dtls13_early_ciphertext_preserves_state)
{
    dtls_record_t record;
    memset(&s_client, 0, sizeof(s_client));
    UTNOX_EQUALS(initialize(&s_client, TLS_ROLE_CLIENT), NOXTLS_RETURN_SUCCESS);
    s_client.tls.base.read_seq_num = 17U;
    dtls_replay_window_t replay = s_client.tls.base.replay_window;
    early_record(s_client.queue[0].bytes);
    s_client.queue[0].length = RECOVERY_EARLY_PACKET_BYTES;
    s_client.count = 1U;
    UTNOX_EQUALS(noxtls_dtls_recv_record(&s_client.tls.base, &record), NOXTLS_RETURN_TIMEOUT);
    UTNOX_EQUALS(record.data == NULL, true);
    UTNOX_EQUALS(s_client.tls.base.read_seq_num, 17U);
    UTNOX_EQUALS(s_client.tls.base.read_connection_epoch, 0U);
    UTNOX_EQUALS(s_client.tls.base.ack_pending, 0U);
    UTNOX_EQUALS(s_client.tls.base.flight_buffer_len, 0U);
    UTNOX_EQUALS(memcmp(&replay, &s_client.tls.base.replay_window, sizeof(replay)), 0);
    UTNOX_EQUALS(noxtls_tls13_context_free(&s_client.tls), NOXTLS_RETURN_SUCCESS);
    return 0;
}

/** @brief Keep plaintext that follows discarded ciphertext in the same datagram.
 * @return Zero on success. */
REGISTER_TEST(dtls13_early_ciphertext_coalesced_plaintext)
{
    dtls_record_t record;
    memset(&s_client, 0, sizeof(s_client));
    UTNOX_EQUALS(initialize(&s_client, TLS_ROLE_CLIENT), NOXTLS_RETURN_SUCCESS);
    early_record(s_client.queue[0].bytes);
    plaintext_record(&s_client.queue[0].bytes[RECOVERY_EARLY_PACKET_BYTES]);
    s_client.queue[0].length = RECOVERY_EARLY_PACKET_BYTES + DTLS_RECORD_HEADER_SIZE + 1U;
    s_client.count = 1U;
    UTNOX_EQUALS(noxtls_dtls_recv_record(&s_client.tls.base, &record), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(record.type, TLS_RECORD_HANDSHAKE);
    UTNOX_EQUALS(record.length, 1U);
    UTNOX_EQUALS(record.data[0], TLS_HANDSHAKE_SERVER_HELLO);
    (void)noxtls_free(record.data);
    UTNOX_EQUALS(noxtls_tls13_context_free(&s_client.tls), NOXTLS_RETURN_SUCCESS);
    return 0;
}

/** @brief A malformed early length cannot consume a subsequent datagram.
 * @return Zero on success. */
REGISTER_TEST(dtls13_early_ciphertext_bad_length)
{
    dtls_record_t record;
    memset(&s_client, 0, sizeof(s_client));
    UTNOX_EQUALS(initialize(&s_client, TLS_ROLE_CLIENT), NOXTLS_RETURN_SUCCESS);
    early_record(s_client.queue[0].bytes);
    s_client.queue[0].bytes[RECOVERY_UNIFIED_HEADER_BYTES - 1U] = UINT8_MAX;
    s_client.queue[0].length = RECOVERY_EARLY_PACKET_BYTES;
    plaintext_record(s_client.queue[1].bytes);
    s_client.queue[1].length = DTLS_RECORD_HEADER_SIZE + 1U;
    s_client.count = 2U;
    UTNOX_EQUALS(noxtls_dtls_recv_record(&s_client.tls.base, &record), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(record.type, TLS_RECORD_HANDSHAKE);
    (void)noxtls_free(record.data);
    UTNOX_EQUALS(noxtls_tls13_context_free(&s_client.tls), NOXTLS_RETURN_SUCCESS);
    return 0;
}

/** @brief Once keys are installed, protected records still reach authentication.
 * @return Zero on success. */
REGISTER_TEST(dtls13_ciphertext_after_key_install)
{
    dtls_record_t record;
    memset(&s_client, 0, sizeof(s_client));
    UTNOX_EQUALS(initialize(&s_client, TLS_ROLE_CLIENT), NOXTLS_RETURN_SUCCESS);
    s_client.tls.base.read_connection_epoch = DTLS13_EPOCH_HANDSHAKE;
    early_record(s_client.queue[0].bytes);
    s_client.queue[0].length = RECOVERY_EARLY_PACKET_BYTES;
    s_client.count = 1U;
    UTNOX_EQUALS(noxtls_dtls_recv_record(&s_client.tls.base, &record), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(record.type, s_client.queue[0].bytes[0]);
    UTNOX_EQUALS(record.length, RECOVERY_EARLY_PACKET_BYTES);
    UTNOX_EQUALS(memcmp(record.data, s_client.queue[0].bytes, record.length), 0);
    (void)noxtls_free(record.data);
    UTNOX_EQUALS(noxtls_tls13_context_free(&s_client.tls), NOXTLS_RETURN_SUCCESS);
    return 0;
}

/** @brief Produce an unbounded stream of early ciphertext for the work-limit check.
 * @param[in] context Unused. @param[out] bytes Receive storage.
 * @param[in] capacity Storage capacity.
 * @return One datagram length or a capacity error. */
static int32_t flood_records(void *context, uint8_t *bytes, uint32_t capacity)
{
    (void)context;
    if(capacity < RECOVERY_EARLY_PACKET_BYTES) { return -1; }

    early_record(bytes);
    ++s_flood_reads;
    return RECOVERY_EARLY_PACKET_BYTES;
}

/** @brief Repeated unauthenticated records cannot spin one receive call indefinitely.
 * @return Zero on success. */
REGISTER_TEST(dtls13_early_ciphertext_bounded_work)
{
    dtls_record_t record;
    memset(&s_client, 0, sizeof(s_client));
    UTNOX_EQUALS(initialize(&s_client, TLS_ROLE_CLIENT), NOXTLS_RETURN_SUCCESS);
    s_client.tls.base.base.recv_callback = flood_records;
    s_flood_reads = 0U;
    UTNOX_EQUALS(noxtls_dtls_recv_record(&s_client.tls.base, &record), NOXTLS_RETURN_TIMEOUT);
    UTNOX_EQUALS(s_flood_reads, DTLS12_MAX_RECORDS_PER_READ);
    UTNOX_EQUALS(noxtls_tls13_context_free(&s_client.tls), NOXTLS_RETURN_SUCCESS);
    return 0;
}

/** @brief Reject invalid bindings and oversized entries without modifying the flight.
 * @return Zero on success. */
REGISTER_TEST(dtls13_recovery_buffer_boundaries)
{
    uint8_t inner[8] = {0U};
    uint8_t storage[32];
    memset(&s_client, 0, sizeof(s_client));
    UTNOX_EQUALS(initialize(&s_client, TLS_ROLE_CLIENT), NOXTLS_RETURN_SUCCESS);
    dtls_context_t *base = &s_client.tls.base;
    UTNOX_EQUALS(noxtls_dtls_buffer_handshake(NULL, inner, sizeof(inner)), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_dtls_buffer_handshake(base, NULL, sizeof(inner)), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_dtls_buffer_handshake(base, inner, 0U), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_dtls_buffer_handshake(base, inner, UINT16_MAX), NOXTLS_RETURN_INVALID_PARAM);
    base->base.version = TLS_VERSION_1_3;
    UTNOX_EQUALS(noxtls_dtls_buffer_handshake(base, inner, sizeof(inner)), NOXTLS_RETURN_INVALID_PARAM);
    base->base.version = DTLS_VERSION_1_3;
    UTNOX_EQUALS(noxtls_dtls_set_flight_buffer(base, storage, sizeof(storage)), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_dtls_buffer_handshake(base, inner, sizeof(inner)), NOXTLS_RETURN_SUCCESS);
    uint32_t retained = base->flight_buffer_len;
    UTNOX_EQUALS(retained > sizeof(inner), true);
    UTNOX_EQUALS(noxtls_dtls_buffer_handshake(base, inner, sizeof(inner)), NOXTLS_RETURN_NOT_ENOUGH_MEMORY);
    UTNOX_EQUALS(base->flight_buffer_len, retained);
    base->retransmit_handshake = NULL;
    UTNOX_EQUALS(noxtls_dtls_buffer_handshake(base, inner, sizeof(inner)), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_tls13_context_free(&s_client.tls), NOXTLS_RETURN_SUCCESS);
    return 0;
}

#if NOXTLS_FEATURE_ECC
/** @brief The largest supported classical KeyShareEntry fits the bounded client staging area.
 * @return Zero on success. */
REGISTER_TEST(dtls13_classical_share_capacity)
{
    uint8_t encoded[TLS13_CLIENT_KEY_SHARE_ENCODED_CAPACITY];
    uint32_t length = sizeof(encoded);
    UTNOX_EQUALS(noxtls_tls_ecdhe_context_init(&s_classical_share, TLS_NAMED_GROUP_SECP521R1), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_tls_ecdhe_generate_ephemeral_key(&s_classical_share), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_tls13_key_share_encode(&s_classical_share, encoded, &length), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(length, RECOVERY_P521_SHARE_BYTES);
    UTNOX_EQUALS(length <= TLS13_CLIENT_KEY_SHARE_VECTOR_CAPACITY, true);
    UTNOX_EQUALS(noxtls_tls_ecdhe_context_free(&s_classical_share), NOXTLS_RETURN_SUCCESS);
    return 0;
}
#endif

#if defined(_MSC_VER)
/** @brief Register tests where compiler constructor registration is unavailable. */
void utnox_register_tests(void)
{
    register_test(__reg_dtls13_recovery_baseline.name, __reg_dtls13_recovery_baseline.func);
    register_test(__reg_dtls13_recovery_server_record.name, __reg_dtls13_recovery_server_record.func);
    register_test(__reg_dtls13_recovery_client_finished.name, __reg_dtls13_recovery_client_finished.func);
    register_test(__reg_dtls13_recovery_final_ack.name, __reg_dtls13_recovery_final_ack.func);
    register_test(__reg_dtls13_recovery_combined_loss.name, __reg_dtls13_recovery_combined_loss.func);
    register_test(__reg_dtls13_recovery_missing_server_hello.name, __reg_dtls13_recovery_missing_server_hello.func);
    register_test(__reg_dtls13_recovery_missing_server_hello_and_flight.name, __reg_dtls13_recovery_missing_server_hello_and_flight.func);
    register_test(__reg_dtls13_recovery_reordered_server_hello.name, __reg_dtls13_recovery_reordered_server_hello.func);
    register_test(__reg_dtls13_recovery_reordered_server_hello_and_loss.name, __reg_dtls13_recovery_reordered_server_hello_and_loss.func);
    register_test(__reg_dtls13_early_ciphertext_preserves_state.name, __reg_dtls13_early_ciphertext_preserves_state.func);
    register_test(__reg_dtls13_early_ciphertext_coalesced_plaintext.name, __reg_dtls13_early_ciphertext_coalesced_plaintext.func);
    register_test(__reg_dtls13_early_ciphertext_bad_length.name, __reg_dtls13_early_ciphertext_bad_length.func);
    register_test(__reg_dtls13_ciphertext_after_key_install.name, __reg_dtls13_ciphertext_after_key_install.func);
    register_test(__reg_dtls13_early_ciphertext_bounded_work.name, __reg_dtls13_early_ciphertext_bounded_work.func);
    register_test(__reg_dtls13_recovery_buffer_boundaries.name, __reg_dtls13_recovery_buffer_boundaries.func);
#if NOXTLS_FEATURE_ECC
    register_test(__reg_dtls13_classical_share_capacity.name, __reg_dtls13_classical_share_capacity.func);
#endif
}
#endif
