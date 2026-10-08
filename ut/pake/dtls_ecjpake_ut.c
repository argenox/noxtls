/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Licensed under the GNU General Public License v2.0 or later,
* or alternatively under a commercial license from
* Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
*
* File:    dtls_ecjpake_ut.c
* Summary: In-memory DTLS 1.2 TLS_ECJPAKE_WITH_AES_128_CCM_8 handshake tests
*
*
*****************************************************************************/

/**
 * @file dtls_ecjpake_ut.c
 * @brief DTLS 1.2 EC-JPAKE: full handshake, records, wrong password, tampering, API limits.
 * @ingroup noxtls_tls12_ecjpake
 *
 * Client and server run in one thread over an in-memory datagram transport
 * and are driven with noxtls_tls12_connect_poll() / noxtls_tls12_accept_poll().
 */

#include <stdint.h>
#include <string.h>

#include "noxtls_tls12.h"
#include "noxtls_tls12_ecjpake.h"
#include "noxtls_dtls_common.h"
#include "noxtls_tls12_ecjpake_internal.h"
#include "pake/noxtls_ecjpake.h"
#include "pake/noxtls_ecjpake_internal.h"
#include "runner.h"
#include "test_assert.h"

/** @brief Largest datagram kept by the in-memory transport. */
#define UT_DGRAM_MAX (2048U)
/** @brief Datagrams queued per direction. */
#define UT_QUEUE_DEPTH (32U)
/** @brief Poll iterations before a handshake is declared stuck. */
#define UT_MAX_POLLS (200U)
/** @brief DTLS record header size (RFC 6347 section 4.1). */
#define UT_DTLS_RECORD_HEADER (13U)
/** @brief DTLS handshake header size (RFC 6347 section 4.2.2). */
#define UT_DTLS_HS_HEADER (12U)
/** @brief Offset of the record length in a DTLS record header. */
#define UT_DTLS_RECORD_LEN_OFFSET (11U)
/** @brief Offset of the record epoch in a DTLS record header. */
#define UT_DTLS_RECORD_EPOCH_OFFSET (3U)
/** @brief Handshake record content type. */
#define UT_CT_HANDSHAKE (22U)
/** @brief Alert record content type. */
#define UT_CT_ALERT (21U)
/** @brief Direction index: client to server. */
#define UT_C2S (0U)
/** @brief Direction index: server to client. */
#define UT_S2C (1U)

/** @brief One direction of the in-memory datagram link. */
typedef struct
{
    uint8_t data[UT_QUEUE_DEPTH][UT_DGRAM_MAX];  /**< Datagrams. */
    uint32_t len[UT_QUEUE_DEPTH];                /**< Datagram lengths. */
    uint32_t head;                               /**< Next datagram to read. */
    uint32_t tail;                               /**< Next free slot. */
    uint32_t sent;                               /**< Datagrams ever sent in this direction. */
} ut_link_t;

/** @brief Datagram mutation hook: direction, send index, buffer, length. */
typedef void (*ut_mutate_t)(uint32_t dir, uint32_t index, uint8_t *buf, uint32_t len);

/** @brief Both directions. */
static ut_link_t s_link[2];
/** @brief Active mutation hook (NULL for none). */
static ut_mutate_t s_mutate;
/** @brief Fake clock in milliseconds. */
static uint64_t s_now_ms;
/** @brief Number of alerts seen per direction. */
static uint32_t s_alerts[2];
/** @brief Last alert description per direction (plaintext alerts only). */
static uint8_t s_last_alert[2];
/** @brief When non-zero, drop the next datagram sent server to client. */
static uint32_t s_drop_next_s2c;

/** @brief Client context (large; kept off the stack). */
static tls12_context_t s_client;
/** @brief Server context. */
static tls12_context_t s_server;
/** @brief Direction tags passed as callback user data. */
static uint32_t s_dir_tag[2] = { UT_C2S, UT_S2C };

/**
 * @brief Record alerts carried in a datagram (plaintext epoch 0 only).
 * @internal
 *
 * @param[in] dir Direction.
 * @param[in] buf Datagram.
 * @param[in] len Length.
 */
static void ut_scan_alerts(uint32_t dir, const uint8_t *buf, uint32_t len)
{
    uint32_t off = 0U;

    while ((off + UT_DTLS_RECORD_HEADER) <= len) {
        uint32_t rlen = ((uint32_t)buf[off + UT_DTLS_RECORD_LEN_OFFSET] << 8) |
                        (uint32_t)buf[off + UT_DTLS_RECORD_LEN_OFFSET + 1U];

        if (buf[off] == UT_CT_ALERT) {
            s_alerts[dir]++;
            if ((buf[off + UT_DTLS_RECORD_EPOCH_OFFSET] == 0U) && (buf[off + UT_DTLS_RECORD_EPOCH_OFFSET + 1U] == 0U) &&
                (rlen >= 2U)) {
                s_last_alert[dir] = buf[off + UT_DTLS_RECORD_HEADER + 1U];
            }
        }

        off += UT_DTLS_RECORD_HEADER + rlen;
    }
}

/**
 * @brief Transport send callback.
 * @internal
 *
 * @param[in] dir_tag Direction tag.
 * @param[in] data Datagram.
 * @param[in] len Length.
 *
 * @return len, or -1 when the queue is full.
 */
static int32_t ut_send(const uint32_t *dir_tag, const uint8_t *data, uint32_t len)
{
    uint32_t dir = *dir_tag;
    ut_link_t *link = &s_link[dir];
    uint32_t slot;
    const uint32_t out_len = len;

    if ((len > UT_DGRAM_MAX) || ((link->tail - link->head) >= UT_QUEUE_DEPTH)) {
        return -1;
    }

    slot = link->tail % UT_QUEUE_DEPTH;
    memcpy(link->data[slot], data, len);
    if (s_mutate != NULL) {
        s_mutate(dir, link->sent, link->data[slot], out_len);
    }

    link->sent++;
    ut_scan_alerts(dir, link->data[slot], out_len);
    if ((dir == UT_S2C) && (s_drop_next_s2c != 0U)) {
        s_drop_next_s2c = 0U;
        return (int32_t)len;
    }

    link->len[slot] = out_len;
    link->tail++;
    return (int32_t)len;
}

/**
 * @brief Transport receive callback: one datagram per call, 0 when empty.
 * @internal
 *
 * @param[in] dir_tag Direction tag of the sender (the peer's outbound link).
 * @param[out] data Destination.
 * @param[in] len Capacity.
 *
 * @return Datagram length or 0.
 */
static int32_t ut_recv(const uint32_t *dir_tag, uint8_t *data, uint32_t len)
{
    uint32_t dir = *dir_tag;
    ut_link_t *link = &s_link[dir];
    uint32_t slot;
    uint32_t n;

    if (link->head == link->tail) {
        return 0;
    }

    slot = link->head % UT_QUEUE_DEPTH;
    n = (link->len[slot] < len) ? link->len[slot] : len;
    memcpy(data, link->data[slot], n);
    link->head++;
    return (int32_t)n;
}

/**
 * @brief Fake clock.
 * @internal
 *
 * @param[in] user Unused.
 *
 * @return Current fake time in milliseconds.
 */
static uint64_t ut_time(void *user)
{
    (void)user;
    return s_now_ms;
}

/**
 * @brief Client send: client to server link.
 * @internal
 *
 * @param[in] user Unused.
 * @param[in] data Datagram.
 * @param[in] len Length.
 *
 * @return As ut_send().
 */
static int32_t ut_client_send(void *user, const uint8_t *data, uint32_t len)
{
    (void)user;
    return ut_send(&s_dir_tag[UT_C2S], data, len);
}

/**
 * @brief Client receive: server to client link.
 * @internal
 *
 * @param[in] user Unused.
 * @param[out] data Destination.
 * @param[in] len Capacity.
 *
 * @return As ut_recv().
 */
static int32_t ut_client_recv(void *user, uint8_t *data, uint32_t len)
{
    (void)user;
    return ut_recv(&s_dir_tag[UT_S2C], data, len);
}

/**
 * @brief Server send: server to client link.
 * @internal
 *
 * @param[in] user Unused.
 * @param[in] data Datagram.
 * @param[in] len Length.
 *
 * @return As ut_send().
 */
static int32_t ut_server_send(void *user, const uint8_t *data, uint32_t len)
{
    (void)user;
    return ut_send(&s_dir_tag[UT_S2C], data, len);
}

/**
 * @brief Server receive: client to server link.
 * @internal
 *
 * @param[in] user Unused.
 * @param[out] data Destination.
 * @param[in] len Capacity.
 *
 * @return As ut_recv().
 */
static int32_t ut_server_recv(void *user, uint8_t *data, uint32_t len)
{
    (void)user;
    return ut_recv(&s_dir_tag[UT_C2S], data, len);
}

/**
 * @brief Reset the link, clock and hooks.
 * @internal
 */
static void ut_reset_link(void)
{
    memset(s_link, 0, sizeof(s_link));
    memset(s_alerts, 0, sizeof(s_alerts));
    memset(s_last_alert, 0, sizeof(s_last_alert));
    s_mutate = NULL;
    s_now_ms = 1000U;
    s_drop_next_s2c = 0U;
}

/**
 * @brief Initialize both DTLS 1.2 contexts with the given passwords (NULL for none).
 * @internal
 *
 * @param[in] client_pw Client password or NULL.
 * @param[in] client_len Client password length.
 * @param[in] server_pw Server password or NULL.
 * @param[in] server_len Server password length.
 *
 * @return 0 on success.
 */
static int ut_setup(const uint8_t *client_pw, uint32_t client_len, const uint8_t *server_pw, uint32_t server_len)
{
    ut_reset_link();
    memset(&s_client, 0, sizeof(s_client));
    memset(&s_server, 0, sizeof(s_server));
    if ((noxtls_dtls12_context_init(&s_client, TLS_ROLE_CLIENT) != NOXTLS_RETURN_SUCCESS) ||
        (noxtls_dtls12_context_init(&s_server, TLS_ROLE_SERVER) != NOXTLS_RETURN_SUCCESS)) {
        return 1;
    }

    (void)noxtls_tls_set_io_callbacks(&s_client.base.base, ut_client_send, ut_client_recv, NULL);
    (void)noxtls_tls_set_io_callbacks(&s_server.base.base, ut_server_send, ut_server_recv, NULL);
    (void)noxtls_tls_set_time_callback(&s_client.base.base, ut_time);
    (void)noxtls_tls_set_time_callback(&s_server.base.base, ut_time);
    if ((client_pw != NULL) &&
        (noxtls_tls12_set_ecjpake_password(&s_client, client_pw, client_len) != NOXTLS_RETURN_SUCCESS)) {
        return 2;
    }

    if ((server_pw != NULL) &&
        (noxtls_tls12_set_ecjpake_password(&s_server, server_pw, server_len) != NOXTLS_RETURN_SUCCESS)) {
        return 3;
    }

    return 0;
}

/**
 * @brief Report whether a poll result means "call again".
 * @internal
 *
 * @param[in] rc Poll result.
 *
 * @return 1 for WANT_READ / WANT_WRITE.
 */
static int ut_pending(noxtls_return_t rc)
{
    return ((rc == NOXTLS_RETURN_WANT_READ) || (rc == NOXTLS_RETURN_WANT_WRITE)) ? 1 : 0;
}

/**
 * @brief Drive both sides until each finishes or fails.
 * @internal
 *
 * @param[out] crc Final client result.
 * @param[out] src Final server result.
 */
static void ut_run(noxtls_return_t *crc, noxtls_return_t *src)
{
    uint32_t polls;
    int client_done = 0;
    int server_done = 0;

    *crc = NOXTLS_RETURN_WANT_READ;
    *src = NOXTLS_RETURN_WANT_READ;
    for (polls = 0U; (polls < UT_MAX_POLLS) && ((client_done == 0) || (server_done == 0)); ++polls) {
        if (client_done == 0) {
            *crc = noxtls_tls12_connect_poll(&s_client);
            client_done = (ut_pending(*crc) == 0) ? 1 : 0;
        }

        if (server_done == 0) {
            *src = noxtls_tls12_accept_poll(&s_server);
            server_done = (ut_pending(*src) == 0) ? 1 : 0;
        }

        /* A finished side no longer reads: stop once the other side is stuck. */
        if ((client_done != 0) && (*crc != NOXTLS_RETURN_SUCCESS) && (server_done == 0) &&
            (s_link[UT_C2S].head == s_link[UT_C2S].tail)) {
            server_done = 1;
        }

        if ((server_done != 0) && (*src != NOXTLS_RETURN_SUCCESS) && (client_done == 0) &&
            (s_link[UT_S2C].head == s_link[UT_S2C].tail)) {
            client_done = 1;
        }
    }
}

/**
 * @brief Free both contexts.
 * @internal
 */
static void ut_teardown(void)
{
    (void)noxtls_tls12_context_free(&s_client);
    (void)noxtls_tls12_context_free(&s_server);
    s_mutate = NULL;
}

/** @brief Thread-style PSKc (16 octets). */
static const uint8_t k_pskc[16] = {
    0xC3, 0xF5, 0x93, 0x68, 0x44, 0x5A, 0x1B, 0x61, 0x06, 0xBE, 0x42, 0x0A, 0x70, 0x6D, 0x4C, 0xC9 };
/** @brief Thread-style PSKd (ASCII). */
static const uint8_t k_pskd[6] = { 'J', '0', '1', 'N', 'M', 'E' };

/**
 * @brief Full handshake (with cookie exchange), key block agreement and records both ways.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_dtls_ecjpake_handshake_and_records)
{
    static const uint8_t c_msg[] = "joiner -> commissioner";
    static const uint8_t s_msg[] = "commissioner -> joiner";
    uint8_t kb_c[NOXTLS_TLS12_ECJPAKE_KEY_BLOCK_SIZE];
    uint8_t kb_s[NOXTLS_TLS12_ECJPAKE_KEY_BLOCK_SIZE];
    uint8_t buf[128];
    uint32_t len = 0U;
    noxtls_return_t crc;
    noxtls_return_t src;
    noxtls_return_t rc = NOXTLS_RETURN_WANT_READ;
    uint32_t tries;

    UTNOX_EQUALS(ut_setup(k_pskc, sizeof(k_pskc), k_pskc, sizeof(k_pskc)), 0);
    ut_run(&crc, &src);
    UTNOX_EQUALS(crc, NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(src, NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_tls12_ecjpake_negotiated(&s_client), 1);
    UTNOX_EQUALS(noxtls_tls12_ecjpake_negotiated(&s_server), 1);
    UTNOX_EQUALS(s_client.cipher_suite, TLS_CIPHER_SUITE_ECJPAKE_WITH_AES_128_CCM_8);
    UTNOX_EQUALS(s_alerts[UT_C2S] + s_alerts[UT_S2C], 0U);

    /* Both sides export the same 40-octet key block (Thread KEK input). */
    UTNOX_EQUALS(noxtls_tls12_ecjpake_export_key_block(&s_client, kb_c, sizeof(kb_c), &len), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(len, NOXTLS_TLS12_ECJPAKE_KEY_BLOCK_SIZE);
    UTNOX_EQUALS(noxtls_tls12_ecjpake_export_key_block(&s_server, kb_s, sizeof(kb_s), &len), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(kb_c, kb_s, sizeof(kb_c));

    /* Application data, client to server and back (AES-128-CCM-8 records). */
    UTNOX_EQUALS(noxtls_tls12_send(&s_client, c_msg, (uint32_t)sizeof(c_msg)), NOXTLS_RETURN_SUCCESS);
    for (tries = 0U; (tries < UT_MAX_POLLS) && (rc != NOXTLS_RETURN_SUCCESS); ++tries) {
        len = (uint32_t)sizeof(buf);
        rc = noxtls_tls12_recv(&s_server, buf, &len);
    }

    UTNOX_EQUALS(rc, NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(len, (uint32_t)sizeof(c_msg));
    UTNOX_MEM_EQUAL(buf, c_msg, sizeof(c_msg));
    UTNOX_EQUALS(noxtls_tls12_send(&s_server, s_msg, (uint32_t)sizeof(s_msg)), NOXTLS_RETURN_SUCCESS);
    rc = NOXTLS_RETURN_WANT_READ;
    for (tries = 0U; (tries < UT_MAX_POLLS) && (rc != NOXTLS_RETURN_SUCCESS); ++tries) {
        len = (uint32_t)sizeof(buf);
        rc = noxtls_tls12_recv(&s_client, buf, &len);
    }

    UTNOX_EQUALS(rc, NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(buf, s_msg, sizeof(s_msg));
    ut_teardown();
    return 0;
}

/**
 * @brief Wrong password: every ZKP verifies but Finished fails (handshake failure).
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_dtls_ecjpake_wrong_password)
{
    static const uint8_t wrong[6] = { 'J', '0', '1', 'N', 'M', 'F' };
    noxtls_return_t crc;
    noxtls_return_t src;
    uint8_t kb[NOXTLS_TLS12_ECJPAKE_KEY_BLOCK_SIZE];
    uint32_t len = 0U;

    UTNOX_EQUALS(ut_setup(k_pskd, sizeof(k_pskd), wrong, sizeof(wrong)), 0);
    ut_run(&crc, &src);
    UTNOX_NOT_EQUALS(src, NOXTLS_RETURN_SUCCESS);
    UTNOX_NOT_EQUALS(crc, NOXTLS_RETURN_SUCCESS);
    UTNOX_NOT_EQUALS(s_server.base.base.state, TLS_STATE_CONNECTED);
    UTNOX_EQUALS(noxtls_tls12_ecjpake_export_key_block(&s_server, kb, sizeof(kb), &len),
                 NOXTLS_RETURN_NOT_INITIALIZED);
    ut_teardown();
    return 0;
}

/**
 * @brief Find a plaintext handshake message of a type in a datagram.
 * @internal
 *
 * @param[in] buf Datagram.
 * @param[in] len Length.
 * @param[in] hs_type Handshake type.
 * @param[out] body_off Offset of the message body (after the DTLS handshake header).
 * @param[out] body_len Fragment length.
 *
 * @return 1 when found.
 */
static int ut_find_hs(const uint8_t *buf, uint32_t len, uint8_t hs_type, uint32_t *body_off, uint32_t *body_len)
{
    uint32_t off = 0U;

    while ((off + UT_DTLS_RECORD_HEADER + UT_DTLS_HS_HEADER) <= len) {
        uint32_t rlen = ((uint32_t)buf[off + UT_DTLS_RECORD_LEN_OFFSET] << 8) |
                        (uint32_t)buf[off + UT_DTLS_RECORD_LEN_OFFSET + 1U];

        if ((buf[off] == UT_CT_HANDSHAKE) && (buf[off + UT_DTLS_RECORD_EPOCH_OFFSET + 1U] == 0U) &&
            (buf[off + UT_DTLS_RECORD_HEADER] == hs_type)) {
            *body_off = off + UT_DTLS_RECORD_HEADER + UT_DTLS_HS_HEADER;
            *body_len = rlen - UT_DTLS_HS_HEADER;
            return 1;
        }

        off += UT_DTLS_RECORD_HEADER + rlen;
    }

    return 0;
}

/** @brief Handshake type to tamper with in ut_mutate_last_octet(). */
static uint8_t s_tamper_type;
/** @brief Direction to tamper with. */
static uint32_t s_tamper_dir;
/** @brief Mode: 0 flip the last octet, 1 rename extension 256 to 257, 2 replace group 23 by 24. */
static uint32_t s_tamper_mode;
/** @brief Number of tampering operations performed. */
static uint32_t s_tamper_count;

/**
 * @brief Mutation hook used by the tampering tests.
 * @internal
 *
 * @param[in] dir Direction.
 * @param[in] index Send index in that direction.
 * @param[in,out] buf Datagram.
 * @param[in] len Length.
 */
static void ut_mutate(uint32_t dir, uint32_t index, uint8_t *buf, uint32_t len)
{
    uint32_t body_off = 0U;
    uint32_t body_len = 0U;
    uint32_t i;

    (void)index;
    if ((dir != s_tamper_dir) || (ut_find_hs(buf, len, s_tamper_type, &body_off, &body_len) == 0)) {
        return;
    }

    /* The cookie-less first ClientHello carries no cookie; tamper with the second. */
    if ((s_tamper_type == TLS_HANDSHAKE_CLIENT_HELLO) && (buf[body_off + 2U + 32U + 1U] == 0U)) {
        return;
    }

    if (s_tamper_mode == 0U) {
        buf[body_off + body_len - 1U] ^= 0x01U;
        s_tamper_count++;
    } else if (s_tamper_mode == 1U) {
        uint32_t last = 0U;

        /* ecjpake_key_kp_pair is the last extension: the last type-256 header whose
         * length reaches the end of the body (earlier matches are compression bytes). */
        for (i = body_off; (i + 4U) < (body_off + body_len); ++i) {
            if ((buf[i] == 0x01U) && (buf[i + 1U] == 0x00U) &&
                ((i + 4U + (((uint32_t)buf[i + 2U] << 8) | (uint32_t)buf[i + 3U])) == (body_off + body_len))) {
                last = i;
            }
        }

        if (last != 0U) {
            buf[last + 1U] = 0x01U;
            s_tamper_count++;
        }
    } else {
        for (i = body_off; (i + 8U) < (body_off + body_len); ++i) {
            if ((buf[i] == 0x00U) && (buf[i + 1U] == 0x0AU) && (buf[i + 2U] == 0x00U) && (buf[i + 3U] == 0x04U)) {
                buf[i + 7U] = 0x18U;
                s_tamper_count++;
                break;
            }
        }
    }
}

/**
 * @brief Run a handshake with one tampered handshake message.
 * @internal
 *
 * @param[in] dir Direction to tamper with.
 * @param[in] type Handshake type.
 * @param[in] mode Tamper mode.
 * @param[out] crc Client result.
 * @param[out] src Server result.
 *
 * @return 0 when set up and tampered once or more.
 */
static int ut_tampered_run(uint32_t dir, uint8_t type, uint32_t mode, noxtls_return_t *crc, noxtls_return_t *src)
{
    if (ut_setup(k_pskc, sizeof(k_pskc), k_pskc, sizeof(k_pskc)) != 0) {
        return 1;
    }

    s_tamper_dir = dir;
    s_tamper_type = type;
    s_tamper_mode = mode;
    s_tamper_count = 0U;
    s_mutate = ut_mutate;
    ut_run(crc, src);
    return (s_tamper_count > 0U) ? 0 : 2;
}

/**
 * @brief Tampered ZKPs in ClientHello, ServerHello, ServerKeyExchange and ClientKeyExchange.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_dtls_ecjpake_tampered_messages)
{
    noxtls_return_t crc;
    noxtls_return_t src;

    /* Client round one (last octet is r of the second key): server rejects. */
    UTNOX_EQUALS(ut_tampered_run(UT_C2S, TLS_HANDSHAKE_CLIENT_HELLO, 0U, &crc, &src), 0);
    UTNOX_EQUALS(src, NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);
    UTNOX_EQUALS(s_last_alert[UT_S2C], (uint8_t)TLS_ALERT_ILLEGAL_PARAMETER);
    ut_teardown();

    /* Server round one (ecjpake_key_kp_pair is the last ServerHello extension). */
    UTNOX_EQUALS(ut_tampered_run(UT_S2C, TLS_HANDSHAKE_SERVER_HELLO, 0U, &crc, &src), 0);
    UTNOX_EQUALS(crc, NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);
    UTNOX_EQUALS(s_last_alert[UT_C2S], (uint8_t)TLS_ALERT_ILLEGAL_PARAMETER);
    ut_teardown();

    /* Server round two. */
    UTNOX_EQUALS(ut_tampered_run(UT_S2C, TLS_HANDSHAKE_SERVER_KEY_EXCHANGE, 0U, &crc, &src), 0);
    UTNOX_EQUALS(crc, NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);
    UTNOX_EQUALS(s_last_alert[UT_C2S], (uint8_t)TLS_ALERT_ILLEGAL_PARAMETER);
    ut_teardown();

    /* Client round two. */
    UTNOX_EQUALS(ut_tampered_run(UT_C2S, TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE, 0U, &crc, &src), 0);
    UTNOX_EQUALS(src, NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);
    UTNOX_EQUALS(s_last_alert[UT_S2C], (uint8_t)TLS_ALERT_ILLEGAL_PARAMETER);
    ut_teardown();

    /* Missing ecjpake_key_kp_pair in ClientHello (type renamed to 257). */
    UTNOX_EQUALS(ut_tampered_run(UT_C2S, TLS_HANDSHAKE_CLIENT_HELLO, 1U, &crc, &src), 0);
    UTNOX_EQUALS(src, NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(s_last_alert[UT_S2C], (uint8_t)TLS_ALERT_MISSING_EXTENSION);
    ut_teardown();

    /* Missing ecjpake_key_kp_pair in ServerHello. */
    UTNOX_EQUALS(ut_tampered_run(UT_S2C, TLS_HANDSHAKE_SERVER_HELLO, 1U, &crc, &src), 0);
    UTNOX_EQUALS(crc, NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(s_last_alert[UT_C2S], (uint8_t)TLS_ALERT_MISSING_EXTENSION);
    ut_teardown();

    /* supported_groups without secp256r1. */
    UTNOX_EQUALS(ut_tampered_run(UT_C2S, TLS_HANDSHAKE_CLIENT_HELLO, 2U, &crc, &src), 0);
    UTNOX_EQUALS(src, NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(s_last_alert[UT_S2C], (uint8_t)TLS_ALERT_HANDSHAKE_FAILURE);
    ut_teardown();
    return 0;
}

/**
 * @brief Mode mismatches: only one side configured, and client authentication on the server.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_dtls_ecjpake_mode_mismatch)
{
    noxtls_return_t crc;
    noxtls_return_t src;

    /* EC-JPAKE client, certificate-less non-EC-JPAKE server: no common suite. */
    UTNOX_EQUALS(ut_setup(k_pskc, sizeof(k_pskc), NULL, 0U), 0);
    ut_run(&crc, &src);
    UTNOX_EQUALS(src, NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_NOT_EQUALS(crc, NOXTLS_RETURN_SUCCESS);
    ut_teardown();

    /* Server with client authentication requested cannot run EC-JPAKE. */
    UTNOX_EQUALS(ut_setup(k_pskc, sizeof(k_pskc), k_pskc, sizeof(k_pskc)), 0);
    noxtls_tls12_request_client_auth(&s_server, 1);
    ut_run(&crc, &src);
    UTNOX_EQUALS(src, NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(s_last_alert[UT_S2C], (uint8_t)TLS_ALERT_HANDSHAKE_FAILURE);
    ut_teardown();
    return 0;
}

/**
 * @brief A lost server flight is recovered by DTLS retransmission (RFC 6347 section 4.2.4).
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_dtls_ecjpake_lost_flight_retransmission)
{
    noxtls_return_t crc = NOXTLS_RETURN_WANT_READ;
    noxtls_return_t src = NOXTLS_RETURN_WANT_READ;
    uint32_t polls;

    UTNOX_EQUALS(ut_setup(k_pskd, sizeof(k_pskd), k_pskd, sizeof(k_pskd)), 0);

    /* Client sends ClientHello; server answers HelloVerifyRequest; client resends. */
    crc = noxtls_tls12_connect_poll(&s_client);
    UTNOX_EQUALS(ut_pending(crc), 1);
    src = noxtls_tls12_accept_poll(&s_server);
    UTNOX_EQUALS(ut_pending(src), 1);
    crc = noxtls_tls12_connect_poll(&s_client);
    UTNOX_EQUALS(ut_pending(crc), 1);

    /* Drop the server flight (ServerHello .. ServerHelloDone). */
    s_drop_next_s2c = 1U;
    src = noxtls_tls12_accept_poll(&s_server);
    UTNOX_EQUALS(ut_pending(src), 1);
    crc = noxtls_tls12_connect_poll(&s_client);
    UTNOX_EQUALS(ut_pending(crc), 1);

    /* Let the client retransmission timer expire, then finish normally. */
    for (polls = 0U; (polls < UT_MAX_POLLS) && ((crc != NOXTLS_RETURN_SUCCESS) || (src != NOXTLS_RETURN_SUCCESS));
         ++polls) {
        s_now_ms += 2000U;
        if (crc != NOXTLS_RETURN_SUCCESS) {
            crc = noxtls_tls12_connect_poll(&s_client);
        }

        if (src != NOXTLS_RETURN_SUCCESS) {
            src = noxtls_tls12_accept_poll(&s_server);
        }

        if ((ut_pending(crc) == 0) && (crc != NOXTLS_RETURN_SUCCESS)) {
            break;
        }

        if ((ut_pending(src) == 0) && (src != NOXTLS_RETURN_SUCCESS)) {
            break;
        }
    }

    UTNOX_EQUALS(crc, NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(src, NOXTLS_RETURN_SUCCESS);
    ut_teardown();
    return 0;
}

/**
 * @brief Configuration API arguments, ordering and key-export limits.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_dtls_ecjpake_api_arguments)
{
    uint8_t too_long[NOXTLS_ECJPAKE_PASSWORD_MAX_LEN + 1U];
    uint8_t kb[NOXTLS_TLS12_ECJPAKE_KEY_BLOCK_SIZE];
    uint32_t len = 0U;
    noxtls_return_t crc;
    noxtls_return_t src;

    memset(too_long, 0x31, sizeof(too_long));
    UTNOX_EQUALS(ut_setup(NULL, 0U, NULL, 0U), 0);
    UTNOX_EQUALS(noxtls_tls12_set_ecjpake_password(NULL, k_pskc, sizeof(k_pskc)), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_tls12_set_ecjpake_password(&s_client, NULL, 1U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_tls12_set_ecjpake_password(&s_client, too_long, sizeof(too_long)),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_tls12_ecjpake_negotiated(&s_client), 0);
    UTNOX_EQUALS(noxtls_tls12_ecjpake_negotiated(NULL), 0);

    /* MIN and MAX password lengths are accepted; a second call replaces the password. */
    UTNOX_EQUALS(noxtls_tls12_set_ecjpake_password(&s_client, too_long, 1U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_tls12_set_ecjpake_password(&s_client, too_long, sizeof(too_long) - 1U),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_tls12_set_ecjpake_password(&s_server, too_long, sizeof(too_long) - 1U),
                 NOXTLS_RETURN_SUCCESS);

    /* Key export before the handshake, and argument checks. */
    UTNOX_EQUALS(noxtls_tls12_ecjpake_export_key_block(NULL, kb, sizeof(kb), &len), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_tls12_ecjpake_export_key_block(&s_client, NULL, sizeof(kb), &len), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_tls12_ecjpake_export_key_block(&s_client, kb, sizeof(kb), NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_tls12_ecjpake_export_key_block(&s_client, kb, sizeof(kb), &len),
                 NOXTLS_RETURN_NOT_INITIALIZED);

    /* Handshake with MAX-length passwords, then the post-handshake checks. */
    ut_run(&crc, &src);
    UTNOX_EQUALS(crc, NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(src, NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_tls12_ecjpake_export_key_block(&s_client, kb, sizeof(kb) - 1U, &len),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_tls12_set_ecjpake_password(&s_client, k_pskc, sizeof(k_pskc)), NOXTLS_RETURN_FAILED);
    ut_teardown();

    /* A non-EC-JPAKE DTLS 1.2 context still refuses the polled API. */
    UTNOX_EQUALS(ut_setup(NULL, 0U, NULL, 0U), 0);
    UTNOX_EQUALS(noxtls_tls12_connect_poll(&s_client), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_tls12_accept_poll(&s_server), NOXTLS_RETURN_NOT_SUPPORTED);
    ut_teardown();
    return 0;
}


/** @brief Draws allowed before the injected random source fails. */
static uint32_t s_rng_budget;
/** @brief Injected generator state (xorshift32; test only). */
static uint32_t s_rng_state = 0x12345678U;

/**
 * @brief Injected EC-JPAKE random source that fails once its budget is spent.
 * @internal
 *
 * @param[in] user Unused.
 * @param[out] out Destination.
 * @param[in] len Length.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_NOT_ENOUGH_ENTROPY.
 */
static noxtls_return_t ut_budget_random(void *user, uint8_t *out, uint32_t len)
{
    uint32_t index;

    (void)user;
    if (s_rng_budget == 0U) {
        return NOXTLS_RETURN_NOT_ENOUGH_ENTROPY;
    }

    s_rng_budget--;
    for (index = 0U; index < len; ++index) {
        s_rng_state ^= s_rng_state << 13;
        s_rng_state ^= s_rng_state >> 17;
        s_rng_state ^= s_rng_state << 5;
        out[index] = (uint8_t)s_rng_state;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Random failures while building the ClientHello and the ServerHello.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_dtls_ecjpake_random_failures)
{
    noxtls_return_t crc;
    noxtls_return_t src;

    /* No draws at all: the client cannot build its round one. */
    UTNOX_EQUALS(ut_setup(k_pskc, sizeof(k_pskc), k_pskc, sizeof(k_pskc)), 0);
    s_rng_budget = 0U;
    noxtls_ecjpake_set_random_source(ut_budget_random, NULL);
    crc = noxtls_tls12_connect_poll(&s_client);
    UTNOX_EQUALS(crc, NOXTLS_RETURN_NOT_ENOUGH_ENTROPY);
    ut_teardown();

    /* Client round one uses four draws (x1, v1, x2, v2); the server round one then fails. */
    UTNOX_EQUALS(ut_setup(k_pskc, sizeof(k_pskc), k_pskc, sizeof(k_pskc)), 0);
    s_rng_budget = 4U;
    ut_run(&crc, &src);
    UTNOX_EQUALS(src, NOXTLS_RETURN_NOT_ENOUGH_ENTROPY);
    UTNOX_NOT_EQUALS(crc, NOXTLS_RETURN_SUCCESS);
    noxtls_ecjpake_set_random_source(NULL, NULL);
    ut_teardown();
    return 0;
}

/**
 * @brief Internal hooks: inactive context, NULL buffers, short buffers and alert mapping.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_dtls_ecjpake_internal_hooks)
{
    uint8_t buf[NOXTLS_TLS12_ECJPAKE_CLIENT_HELLO_EXT_MAX_SIZE];
    uint32_t len = 0U;

    UTNOX_EQUALS(ut_setup(NULL, 0U, NULL, 0U), 0);
    UTNOX_EQUALS(tls12_ecjpake_active(NULL), 0);
    UTNOX_EQUALS(tls12_ecjpake_active(&s_client), 0);
    UTNOX_EQUALS(tls12_ecjpake_write_client_hello_extensions(&s_client, buf, sizeof(buf), &len), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(tls12_ecjpake_client_read_server_hello_extension(&s_client, buf, 1U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(tls12_ecjpake_client_read_server_key_exchange(&s_client, buf, 1U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(tls12_ecjpake_client_write_key_exchange(&s_client, buf, sizeof(buf), &len), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(tls12_ecjpake_server_process_client_hello(&s_server), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(tls12_ecjpake_write_server_hello_extension(&s_server, buf, sizeof(buf), &len), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(tls12_ecjpake_server_write_key_exchange(&s_server, buf, sizeof(buf), &len), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(tls12_ecjpake_server_read_client_key_exchange(&s_server, buf, 1U), NOXTLS_RETURN_NULL);
    tls12_ecjpake_release(NULL);
    tls12_ecjpake_release(&s_client);

    /* Active context with NULL or short buffers. */
    UTNOX_EQUALS(noxtls_tls12_set_ecjpake_password(&s_client, k_pskd, sizeof(k_pskd)), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_tls12_set_ecjpake_password(&s_server, k_pskd, sizeof(k_pskd)), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(tls12_ecjpake_write_client_hello_extensions(&s_client, NULL, sizeof(buf), &len), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(tls12_ecjpake_write_client_hello_extensions(&s_client, buf, sizeof(buf), NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(tls12_ecjpake_write_client_hello_extensions(&s_client, buf, sizeof(buf) - 1U, &len),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(tls12_ecjpake_client_read_server_hello_extension(&s_client, NULL, 1U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(tls12_ecjpake_client_read_server_key_exchange(&s_client, NULL, 1U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(tls12_ecjpake_client_write_key_exchange(&s_client, NULL, sizeof(buf), &len), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(tls12_ecjpake_client_write_key_exchange(&s_client, buf, sizeof(buf), NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(tls12_ecjpake_write_server_hello_extension(&s_server, NULL, sizeof(buf), &len), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(tls12_ecjpake_write_server_hello_extension(&s_server, buf, sizeof(buf), NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(tls12_ecjpake_write_server_hello_extension(&s_server, buf, NOXTLS_TLS12_ECJPAKE_EXT_HEADER_SIZE - 1U,
                                                            &len), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(tls12_ecjpake_server_write_key_exchange(&s_server, NULL, sizeof(buf), &len), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(tls12_ecjpake_server_write_key_exchange(&s_server, buf, sizeof(buf), NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(tls12_ecjpake_server_read_client_key_exchange(&s_server, NULL, 1U), NOXTLS_RETURN_NULL);

    /* Alert mapping (draft section 6). */
    UTNOX_EQUALS(tls12_ecjpake_alert_for(NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR), (uint8_t)TLS_ALERT_DECODE_ERROR);
    UTNOX_EQUALS(tls12_ecjpake_alert_for(NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER),
                 (uint8_t)TLS_ALERT_ILLEGAL_PARAMETER);
    UTNOX_EQUALS(tls12_ecjpake_alert_for(NOXTLS_RETURN_NOT_SUPPORTED), (uint8_t)TLS_ALERT_HANDSHAKE_FAILURE);
    UTNOX_EQUALS(tls12_ecjpake_alert_for(NOXTLS_RETURN_FAILED), (uint8_t)TLS_ALERT_INTERNAL_ERROR);
    ut_teardown();
    return 0;
}

#if defined(_WIN32)
#include <windows.h>
/** @brief Lock protecting the link for the blocking-API test. */
static CRITICAL_SECTION s_lock;
#define UT_LOCK() EnterCriticalSection(&s_lock)
#define UT_UNLOCK() LeaveCriticalSection(&s_lock)
#define UT_SLEEP_MS(ms) Sleep(ms)
#else
#include <pthread.h>
#include <unistd.h>
/** @brief Lock protecting the link for the blocking-API test. */
static pthread_mutex_t s_lock = PTHREAD_MUTEX_INITIALIZER;
#define UT_LOCK() (void)pthread_mutex_lock(&s_lock)
#define UT_UNLOCK() (void)pthread_mutex_unlock(&s_lock)
#define UT_SLEEP_MS(ms) (void)usleep((ms) * 1000U)
#endif

/** @brief Blocking receive deadline in 1 ms steps. */
#define UT_BLOCKING_WAIT_MS (20000U)

/**
 * @brief Locked send for the threaded test.
 * @internal
 *
 * @param[in] dir Direction.
 * @param[in] data Datagram.
 * @param[in] len Length.
 *
 * @return As ut_send().
 */
static int32_t ut_locked_send(uint32_t dir, const uint8_t *data, uint32_t len)
{
    int32_t rc;

    UT_LOCK();
    rc = ut_send(&s_dir_tag[dir], data, len);
    UT_UNLOCK();
    return rc;
}

/**
 * @brief Blocking receive: waits until a datagram arrives or the deadline passes.
 * @internal
 *
 * @param[in] dir Direction to read.
 * @param[out] data Destination.
 * @param[in] len Capacity.
 *
 * @return Datagram length, or 0 at the deadline.
 */
static int32_t ut_blocking_recv(uint32_t dir, uint8_t *data, uint32_t len)
{
    uint32_t waited;
    int32_t rc = 0;

    for (waited = 0U; (waited < UT_BLOCKING_WAIT_MS) && (rc == 0); ++waited) {
        UT_LOCK();
        rc = ut_recv(&s_dir_tag[dir], data, len);
        UT_UNLOCK();
        if (rc == 0) {
            UT_SLEEP_MS(1U);
        }
    }

    return rc;
}

/**
 * @brief Blocking client send.
 * @internal
 *
 * @param[in] user Unused.
 * @param[in] data Datagram.
 * @param[in] len Length.
 *
 * @return As ut_send().
 */
static int32_t ut_bc_send(void *user, const uint8_t *data, uint32_t len)
{
    (void)user;
    return ut_locked_send(UT_C2S, data, len);
}

/**
 * @brief Blocking client receive.
 * @internal
 *
 * @param[in] user Unused.
 * @param[out] data Destination.
 * @param[in] len Capacity.
 *
 * @return As ut_blocking_recv().
 */
static int32_t ut_bc_recv(void *user, uint8_t *data, uint32_t len)
{
    (void)user;
    return ut_blocking_recv(UT_S2C, data, len);
}

/**
 * @brief Blocking server send.
 * @internal
 *
 * @param[in] user Unused.
 * @param[in] data Datagram.
 * @param[in] len Length.
 *
 * @return As ut_send().
 */
static int32_t ut_bs_send(void *user, const uint8_t *data, uint32_t len)
{
    (void)user;
    return ut_locked_send(UT_S2C, data, len);
}

/**
 * @brief Blocking server receive.
 * @internal
 *
 * @param[in] user Unused.
 * @param[out] data Destination.
 * @param[in] len Capacity.
 *
 * @return As ut_blocking_recv().
 */
static int32_t ut_bs_recv(void *user, uint8_t *data, uint32_t len)
{
    (void)user;
    return ut_blocking_recv(UT_C2S, data, len);
}

/** @brief Result of the server thread. */
static volatile noxtls_return_t s_server_thread_rc;

#if defined(_WIN32)
/**
 * @brief Server thread: blocking accept.
 * @internal
 *
 * @param[in] arg Unused.
 *
 * @return 0.
 */
static DWORD WINAPI ut_server_thread(LPVOID arg)
{
    (void)arg;
    s_server_thread_rc = noxtls_tls12_accept(&s_server);
    return 0U;
}
#else
/**
 * @brief Server thread: blocking accept.
 * @internal
 *
 * @param[in] arg Unused.
 *
 * @return NULL.
 */
static void *ut_server_thread(void *arg)
{
    (void)arg;
    s_server_thread_rc = noxtls_tls12_accept(&s_server);
    return NULL;
}
#endif

/**
 * @brief Run blocking noxtls_tls12_connect() against a threaded noxtls_tls12_accept().
 * @internal
 *
 * @param[out] crc Client result.
 *
 * @return 0 when the thread ran.
 */
static int ut_blocking_run(noxtls_return_t *crc)
{
#if defined(_WIN32)
    HANDLE thread;

    InitializeCriticalSection(&s_lock);
    thread = CreateThread(NULL, 0U, ut_server_thread, NULL, 0U, NULL);
    if (thread == NULL) {
        DeleteCriticalSection(&s_lock);
        return 1;
    }

    *crc = noxtls_tls12_connect(&s_client);
    (void)WaitForSingleObject(thread, INFINITE);
    (void)CloseHandle(thread);
    DeleteCriticalSection(&s_lock);
#else
    pthread_t thread;

    if (pthread_create(&thread, NULL, ut_server_thread, NULL) != 0) {
        return 1;
    }

    *crc = noxtls_tls12_connect(&s_client);
    (void)pthread_join(thread, NULL);
#endif
    return 0;
}

/**
 * @brief Blocking connect / accept over a threaded transport (success and tampered CKE).
 *
 * @return 0 on success.
 */
REGISTER_TEST_TIMEOUT(test_dtls_ecjpake_blocking_api, 120000000U)
{
    noxtls_return_t crc = NOXTLS_RETURN_FAILED;

    UTNOX_EQUALS(ut_setup(k_pskd, sizeof(k_pskd), k_pskd, sizeof(k_pskd)), 0);
    (void)noxtls_tls_set_io_callbacks(&s_client.base.base, ut_bc_send, ut_bc_recv, NULL);
    (void)noxtls_tls_set_io_callbacks(&s_server.base.base, ut_bs_send, ut_bs_recv, NULL);
    UTNOX_EQUALS(ut_blocking_run(&crc), 0);
    UTNOX_EQUALS(crc, NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(s_server_thread_rc, NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_tls12_ecjpake_negotiated(&s_client), 1);
    ut_teardown();

    /* Tampered ClientKeyExchange: blocking accept reports illegal_parameter. */
    UTNOX_EQUALS(ut_setup(k_pskd, sizeof(k_pskd), k_pskd, sizeof(k_pskd)), 0);
    (void)noxtls_tls_set_io_callbacks(&s_client.base.base, ut_bc_send, ut_bc_recv, NULL);
    (void)noxtls_tls_set_io_callbacks(&s_server.base.base, ut_bs_send, ut_bs_recv, NULL);
    s_tamper_dir = UT_C2S;
    s_tamper_type = TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE;
    s_tamper_mode = 0U;
    s_tamper_count = 0U;
    s_mutate = ut_mutate;
    UTNOX_EQUALS(ut_blocking_run(&crc), 0);
    UTNOX_EQUALS(s_server_thread_rc, NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);
    UTNOX_NOT_EQUALS(crc, NOXTLS_RETURN_SUCCESS);
    ut_teardown();
    return 0;
}

#if defined(_MSC_VER) && !defined(__cplusplus)
/**
 * @brief Register the tests when REGISTER_TEST cannot use constructors (MSVC-ABI C builds).
 */
void utnox_register_tests(void)
{
    register_test(__reg_test_dtls_ecjpake_handshake_and_records.name,
                  __reg_test_dtls_ecjpake_handshake_and_records.func);
    register_test(__reg_test_dtls_ecjpake_wrong_password.name, __reg_test_dtls_ecjpake_wrong_password.func);
    register_test(__reg_test_dtls_ecjpake_tampered_messages.name, __reg_test_dtls_ecjpake_tampered_messages.func);
    register_test(__reg_test_dtls_ecjpake_mode_mismatch.name, __reg_test_dtls_ecjpake_mode_mismatch.func);
    register_test(__reg_test_dtls_ecjpake_lost_flight_retransmission.name,
                  __reg_test_dtls_ecjpake_lost_flight_retransmission.func);
    register_test(__reg_test_dtls_ecjpake_api_arguments.name, __reg_test_dtls_ecjpake_api_arguments.func);
    register_test(__reg_test_dtls_ecjpake_random_failures.name, __reg_test_dtls_ecjpake_random_failures.func);
    register_test(__reg_test_dtls_ecjpake_internal_hooks.name, __reg_test_dtls_ecjpake_internal_hooks.func);
    register_test_ex(__reg_test_dtls_ecjpake_blocking_api.name, __reg_test_dtls_ecjpake_blocking_api.func,
                     __reg_test_dtls_ecjpake_blocking_api.max_time_us);
}
#endif
