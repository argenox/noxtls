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
* File:    noxtls_tls_common.c
* Summary: TLS Common Implementation
*
*
*****************************************************************************/

#include <stdint.h>
#include <string.h>
#include "common/noxtls_memory.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_tls_common.h"

static const uint8_t s_u8txt_noxtls_tls_common_865[] = { (uint8_t)'w', (uint8_t)'a', (uint8_t)'r', (uint8_t)'n', (uint8_t)'i', (uint8_t)'n', (uint8_t)'g', 0 };
static const uint8_t s_u8txt_noxtls_tls_common_867[] = { (uint8_t)'f', (uint8_t)'a', (uint8_t)'t', (uint8_t)'a', (uint8_t)'l', 0 };
static const uint8_t s_u8txt_noxtls_tls_common_869[] = { (uint8_t)'u', (uint8_t)'n', (uint8_t)'k', (uint8_t)'n', (uint8_t)'o', (uint8_t)'w', (uint8_t)'n', 0 };

#if NOXTLS_FEATURE_DTLS
#include "noxtls_dtls_common.h"
#endif
#include "noxtls_tls_noxsight.h"
#include "certs/noxtls_x509.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/noxtls_hash.h"

/* Optional TLS record hex dump to a file (stdio); off by default for MISRA 21.6. */
#ifndef NOXTLS_TLS_RECORD_DUMP
#define NOXTLS_TLS_RECORD_DUMP 0
#endif
#if NOXTLS_TLS_RECORD_DUMP
#include <stdio.h>
#include "noxtls_ct.h"
static FILE *tls_record_dump_fp = NULL;

static FILE *noxtls_tls_dump_fopen(const uint8_t *filename, const uint8_t *mode)
{
#ifdef _MSC_VER
    FILE *fp = NULL;
    if (fopen_s(&fp, filename, mode) != 0) {
        return NULL;
    }
    return fp;
#else
    return fopen(filename, mode);
#endif
}
#endif

/**
 * @brief Return whether a wire version constant denotes DTLS (1.0, 1.2, or 1.3).
 * @param[in] version Record-layer version from `tls_context_t.version`.
 * @return 1 if DTLS; 0 for TLS versions.
 */
#if NOXTLS_FEATURE_DTLS
static uint8_t tls_is_dtls_version(uint16_t version)
{
    if ((version == (uint16_t)DTLS_VERSION_1_0)
        || (version == (uint16_t)DTLS_VERSION_1_2)
        || (version == (uint16_t)DTLS_VERSION_1_3)) {
        return 1U;
    }
    return 0U;
}
#endif

/**
 * @brief Enable hex dumping of TLS records sent/received to a file (debugging).
 * @param[in] path Append-only log file path, or NULL/empty to disable dumping.
 */
void noxtls_tls_set_record_dump_file(const uint8_t *path)
{
#if !NOXTLS_TLS_RECORD_DUMP
    (void)path;
#else
    if (tls_record_dump_fp != NULL) {
        (void)fclose(tls_record_dump_fp);
        tls_record_dump_fp = NULL;
    }
    if ((path == NULL) || (*path == 0U)) {
        return;
    }
    tls_record_dump_fp = noxtls_tls_dump_fopen(path, "a");
#endif
}

/**
 * @brief Append one record dump line when record dumping is enabled.
 * @param[in] direction Label such as "SEND" or "RECV".
 * @param[in] data        Record bytes (header or payload).
 * @param[in] len         Length of @p data.
 */
static void tls_dump_record(const uint8_t *direction, const uint8_t *data, uint32_t len)
{
#if !NOXTLS_TLS_RECORD_DUMP
    (void)direction;
    (void)data;
    (void)len;
#else
    uint32_t i = 0U;
    if ((tls_record_dump_fp == NULL) || (direction == NULL) || (data == NULL)) {
        return;
    }
    (void)fprintf(tls_record_dump_fp, "%s %lu ", direction, (unsigned long)len);
    for (i = 0U; i < len; i += 1U) {
        (void)fprintf(tls_record_dump_fp, "%02X", data[i]);
    }
    (void)fprintf(tls_record_dump_fp, "\n");
#endif
}

/**
 * @brief Initialize a base TLS or DTLS transport context.
 * @param[in,out] ctx      Context structure to zero and initialize.
 * @param[in] role         `TLS_ROLE_CLIENT` or `TLS_ROLE_SERVER`.
 * @param[in] version      Protocol version (`TLS_VERSION_*` or `DTLS_VERSION_*`).
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` if @p ctx is NULL.
 */
noxtls_return_t noxtls_tls_context_init(tls_context_t *ctx, tls_role_t role, uint16_t version) /* NOLINT(bugprone-easily-swappable-parameters) */
{
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    noxtls_secure_zero((ctx), sizeof(tls_context_t));
    ctx->role = role;
    ctx->version = version;
    ctx->state = TLS_STATE_INIT;
    ctx->io_mode = TLS_IO_MODE_BLOCKING;
    ctx->time_callback = NULL;
    ctx->pending_client_hello = NULL;
    ctx->pending_client_hello_len = 0U;
    ctx->io_tx_queue_limit = NOXTLS_TLS_IO_TX_QUEUE_LIMIT;
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Release pending handshake buffers and zero a TLS context.
 * @param[in,out] ctx Context to free; safe to call with NULL.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` if @p ctx is NULL.
 */
noxtls_return_t noxtls_tls_context_free(tls_context_t *ctx)
{
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if (ctx->pending_client_hello != NULL) {
        (void)noxtls_free(ctx->pending_client_hello);
        ctx->pending_client_hello = NULL;
        ctx->pending_client_hello_len = 0U;
    }
    if (ctx->pending_server_hello != NULL) {
        (void)noxtls_free(ctx->pending_server_hello);
        ctx->pending_server_hello = NULL;
        ctx->pending_server_hello_len = 0U;
    }
    if (ctx->io_tx_pending != NULL) {
        (void)noxtls_free(ctx->io_tx_pending);
        ctx->io_tx_pending = NULL;
    }
    if (ctx->io_rx_payload != NULL) {
        (void)noxtls_free(ctx->io_rx_payload);
        ctx->io_rx_payload = NULL;
    }

    noxtls_secure_zero((ctx), sizeof(tls_context_t));

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Register send/receive callbacks for record-layer I/O.
 * @param[in,out] ctx       TLS context.
 * @param[in] send_cb       Callback to transmit bytes (must send full buffer or return error).
 * @param[in] recv_cb       Callback to receive bytes.
 * @param[in] user_data     Opaque pointer passed to both callbacks.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` if @p ctx is NULL.
 */
noxtls_return_t noxtls_tls_set_io_callbacks(tls_context_t *ctx, 
                                        tls_send_callback_t send_cb, 
                                        tls_recv_callback_t recv_cb, 
                                        void *user_data)
{
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    ctx->send_callback = send_cb;
    ctx->recv_callback = recv_cb;
    ctx->user_data = user_data;
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Register a millisecond time source (used by DTLS timers and timeouts).
 * @param[in,out] ctx      TLS context.
 * @param[in] time_cb      Callback returning current time in milliseconds, or NULL to clear.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` if @p ctx is NULL.
 */
noxtls_return_t noxtls_tls_set_time_callback(tls_context_t *ctx, tls_time_callback_t time_cb)
{
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    ctx->time_callback = time_cb;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_tls_set_io_mode(tls_context_t *ctx, tls_io_mode_t mode)
{
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if ((mode != TLS_IO_MODE_BLOCKING) && (mode != TLS_IO_MODE_NON_BLOCKING)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    ctx->io_mode = mode;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_tls_set_io_tx_queue_limit(tls_context_t *ctx, uint32_t limit)
{
    uint32_t pending = 0U;
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    pending = ctx->io_tx_pending_len - ctx->io_tx_pending_offset;
    if ((limit < pending) || (limit < (5U + TLS_MAX_PROTECTED_RECORD_FRAGMENT))) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    ctx->io_tx_queue_limit = limit;
    return NOXTLS_RETURN_SUCCESS;
}

int noxtls_tls_has_pending_output(const tls_context_t *ctx)
{
    return ((ctx != NULL) && (ctx->io_tx_pending_len > ctx->io_tx_pending_offset)) ? 1 : 0;
}

noxtls_return_t noxtls_tls_flush(tls_context_t *ctx)
{
    int32_t sent = 0;
    uint32_t remaining = 0U;

    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if (noxtls_tls_has_pending_output(ctx) == 0) {
        return NOXTLS_RETURN_SUCCESS;
    }
    if (ctx->send_callback == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    remaining = ctx->io_tx_pending_len - ctx->io_tx_pending_offset;
    sent = ctx->send_callback(ctx->user_data,
                              &ctx->io_tx_pending[ctx->io_tx_pending_offset],
                              remaining);
    if ((sent == TLS_IO_WOULD_BLOCK) || (sent == 0)) {
        return NOXTLS_RETURN_WANT_WRITE;
    }
    if ((sent < 0) || ((uint32_t)sent > remaining)) {
        return NOXTLS_RETURN_FAILED;
    }
    ctx->io_tx_pending_offset += (uint32_t)sent;
    if (ctx->io_tx_pending_offset == ctx->io_tx_pending_len) {
        (void)noxtls_free(ctx->io_tx_pending);
        ctx->io_tx_pending = NULL;
        ctx->io_tx_pending_len = 0U;
        ctx->io_tx_pending_offset = 0U;
        return NOXTLS_RETURN_SUCCESS;
    }
    return NOXTLS_RETURN_WANT_WRITE;
}

static noxtls_return_t tls_queue_pending_output(tls_context_t *ctx,
                                                 const uint8_t *data,
                                                 uint32_t len)
{
    uint32_t pending = 0U;
    uint8_t *next = NULL;

    if (len == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }
    pending = ctx->io_tx_pending_len - ctx->io_tx_pending_offset;
    if ((len > ctx->io_tx_queue_limit) || (pending > (ctx->io_tx_queue_limit - len))) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    next = (uint8_t *)noxtls_malloc(pending + len);
    if (next == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    if (pending > 0U) {
        noxtls_copy_u8(next, (size_t)pending, &ctx->io_tx_pending[ctx->io_tx_pending_offset], (size_t)pending);
    }
    noxtls_copy_u8(&next[pending], (size_t)len, data, (size_t)len);
    if (ctx->io_tx_pending != NULL) {
        (void)noxtls_free(ctx->io_tx_pending);
    }
    ctx->io_tx_pending = next;
    ctx->io_tx_pending_len = pending + len;
    ctx->io_tx_pending_offset = 0U;
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t tls_nonblocking_send_record(tls_context_t *ctx,
                                                    const uint8_t *record,
                                                    uint32_t record_len)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    int32_t sent = 0;

    rc = noxtls_tls_flush(ctx);
    if ((rc != NOXTLS_RETURN_SUCCESS) && (rc != NOXTLS_RETURN_WANT_WRITE)) {
        return rc;
    }
    if (noxtls_tls_has_pending_output(ctx) != 0) { return tls_queue_pending_output(ctx, record, record_len); }

    sent = ctx->send_callback(ctx->user_data, record, record_len);
    if ((sent == TLS_IO_WOULD_BLOCK) || (sent == 0)) { return tls_queue_pending_output(ctx, record, record_len); }
    if ((sent < 0) || ((uint32_t)sent > record_len)) {
        return NOXTLS_RETURN_FAILED;
    }
    if ((uint32_t)sent < record_len) { return tls_queue_pending_output(ctx, &record[sent], record_len - (uint32_t)sent); }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Send one TLS or DTLS record via the configured send callback.
 *
 * Builds a five-byte record header, copies @p data as the fragment, and invokes
 * `send_callback`. For DTLS, handshake messages may be fragmented automatically.
 *
 * @param[in,out] ctx   TLS context with `send_callback` set.
 * @param[in] type      Record content type (`TLS_RECORD_*`).
 * @param[in] data      Record fragment bytes.
 * @param[in] len       Length of @p data (max `TLS_MAX_PROTECTED_RECORD_FRAGMENT`).
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` if @p ctx or @p data is NULL;
 *         `NOXTLS_RETURN_FAILED` if no callback or partial send; `NOXTLS_RETURN_INVALID_PARAM` if @p len is too large.
 */
noxtls_return_t noxtls_tls_send_record(tls_context_t *ctx, uint8_t type, const uint8_t *data, uint32_t len)
{
    uint8_t *record = NULL;
    int32_t sent = 0;
    
    if ((ctx == NULL) || (data == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    if (ctx->send_callback == NULL) {
        return NOXTLS_RETURN_FAILED;  /* No send callback set */
    }
    
    if (len > TLS_MAX_PROTECTED_RECORD_FRAGMENT) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

#if NOXTLS_FEATURE_DTLS
    if (tls_is_dtls_version(ctx->version) != 0U) {
        dtls_context_t *dctx = (dtls_context_t *)(void *)ctx;
        if (type == TLS_RECORD_HANDSHAKE) {
            uint32_t msg_len = 0U;
            if (len < 4U) {
                noxtls_return_t rc = noxtls_dtls_send_record(dctx, type, data, len);
                if (rc == NOXTLS_RETURN_SUCCESS) {
                    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_RECORD, NOXSIGHT_SEVERITY_TRACE,
                                    NOXTLS_EVT_RECORD_TX, type, len);
                }
                return rc;
            }
            msg_len = ((uint32_t)data[1] <<16U) | ((uint32_t)data[2] <<8U) | (uint16_t)data[3];
            if((((msg_len + 4U) == len) &&
               (data[0] >= TLS_HANDSHAKE_CLIENT_HELLO) &&
               (data[0] <= TLS_HANDSHAKE_FINISHED))) {
                noxtls_return_t rc = dtls_send_handshake_fragment(dctx, data[0], &data[4], msg_len,
                                                                 dctx->send_message_seq);
                if (rc == NOXTLS_RETURN_SUCCESS) {
                    dctx->send_message_seq += 1U;
                    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_RECORD, NOXSIGHT_SEVERITY_TRACE,
                                    NOXTLS_EVT_RECORD_TX, type, len);
                }
                return rc;
            }
            {
                noxtls_return_t rc = noxtls_dtls_send_record(dctx, type, data, len);
                if (rc == NOXTLS_RETURN_SUCCESS) {
                    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_RECORD, NOXSIGHT_SEVERITY_TRACE,
                                    NOXTLS_EVT_RECORD_TX, type, len);
                }
                return rc;
            }
        }
        {
            noxtls_return_t rc = noxtls_dtls_send_record(dctx, type, data, len);
            if (rc == NOXTLS_RETURN_SUCCESS) {
                NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_RECORD, NOXSIGHT_SEVERITY_TRACE,
                                NOXTLS_EVT_RECORD_TX, type, len);
            }
            return rc;
        }
    }
#endif /* NOXTLS_FEATURE_DTLS */
    
    record = ctx->record_send_buf;
    if (record == NULL) {
        record = (uint8_t*)noxtls_malloc(5U + TLS_MAX_PROTECTED_RECORD_FRAGMENT);
        if (record == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    
    /* Build TLS record header */
    tls_record_header_t header;
    header.type = type;
    header.version[0] = (uint8_t)((((uint32_t)ctx->version) >> 8U) & 0xFFU);
    header.version[1] = (uint8_t)(ctx->version & 0xFFU);
    header.length[0] = (uint8_t)((((uint32_t)len) >>8U) & 0xFFU);
    header.length[1] = (uint8_t)(len & 0xFFU);
    record[0U] = header.type;
    record[1U] = header.version[0U];
    record[2U] = header.version[1U];
    record[3U] = header.length[0U];
    record[4U] = header.length[1U];
    
    /* Copy record data */
    if (len > 0U) {
        noxtls_copy_u8(&record[5], (size_t)len, data, (size_t)len);
    }

    if ((type == TLS_RECORD_HANDSHAKE) && (len >= 4U) && (data[0] == TLS_HANDSHAKE_CLIENT_HELLO)) {
        noxtls_sha_ctx_t sha_ctx;
        uint8_t digest[32];
        (void)noxtls_sha256_init(&sha_ctx, NOXTLS_HASH_SHA_256);
        (void)noxtls_sha256_update(&sha_ctx, data, len);
        if (noxtls_sha256_finish(&sha_ctx, digest) == NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_debug_printf((const uint8_t *)"[TLS13_DEBUG] sent_client_hello_sha256=");
            for (uint32_t i = 0U; i < 32U; i += 1U) {
                (void)noxtls_debug_printf((const uint8_t *)"%02X", digest[i]);
            }
            (void)noxtls_debug_printf((const uint8_t *)"\n");
        }
        (void)noxtls_debug_printf((const uint8_t *)"[TLS13_DEBUG] sent_client_hello head=%02X%02X%02X%02X tail=%02X%02X%02X%02X\n",
                              data[0], data[1], data[2], data[3],
                              data[len - 4U], data[len - 3U], data[len - 2U], data[len - 1U]);
    }
    
    tls_dump_record(NULL, record, 5U + len);

    /* Send via callback. Nonblocking streams atomically accept the record into
     * the bounded context queue, even when the carrier only writes a prefix. */
    if (ctx->io_mode == TLS_IO_MODE_NON_BLOCKING) {
        noxtls_return_t rc = tls_nonblocking_send_record(ctx, record, 5U + len);
        if (record != ctx->record_send_buf) {
            (void)noxtls_free(record);
        }
        if (rc != NOXTLS_RETURN_SUCCESS) {
            NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_IO, NOXSIGHT_SEVERITY_ERROR,
                            NOXTLS_EVT_INTERNAL_ERROR, (uint32_t)type, (uint32_t)rc);
            return rc;
        }
        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_RECORD, NOXSIGHT_SEVERITY_TRACE,
                        NOXTLS_EVT_RECORD_TX, type, len);
        return NOXTLS_RETURN_SUCCESS;
    }

    sent = ctx->send_callback(ctx->user_data, record, 5U + len);
    if ((sent < 0) || ((uint32_t)sent != (5U + len))) {
        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_IO, NOXSIGHT_SEVERITY_ERROR,
                        NOXTLS_EVT_INTERNAL_ERROR, (uint32_t)type, (uint32_t)sent);
        if (record != ctx->record_send_buf) {
            (void)noxtls_free(record);
        }
        return NOXTLS_RETURN_FAILED;
    }
    if (record != ctx->record_send_buf) {
        (void)noxtls_free(record);
    }

    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_RECORD, NOXSIGHT_SEVERITY_TRACE,
                    NOXTLS_EVT_RECORD_TX, type, len);
    
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t tls_nonblocking_read(tls_context_t *ctx,
                                            uint8_t *data,
                                            uint32_t *offset,
                                            uint32_t total)
{
    while (*offset < total) {
        uint32_t remaining = (uint32_t)(total - *offset);
        int32_t received = ctx->recv_callback(ctx->user_data, &data[*offset], remaining);
        if ((received == TLS_IO_WOULD_BLOCK) || (received == 0)) {
            return NOXTLS_RETURN_WANT_READ;
        }
        if ((received < 0) || ((uint32_t)received > remaining)) {
            return NOXTLS_RETURN_FAILED;
        }
        *offset += (uint32_t)received;
    }
    return NOXTLS_RETURN_SUCCESS;
}

static void tls_nonblocking_reset_rx(tls_context_t *ctx)
{
    ctx->io_rx_header_len = 0U;
    ctx->io_rx_payload = NULL;
    ctx->io_rx_payload_len = 0U;
    ctx->io_rx_payload_offset = 0U;
}

static noxtls_return_t tls_nonblocking_recv_record(tls_context_t *ctx,
                                                    tls_record_t *record)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint16_t length = 0U;
    uint8_t type = 0U;
    uint16_t version = 0U;
    uint8_t *payload = NULL;

    rc = tls_nonblocking_read(ctx, ctx->io_rx_header, &ctx->io_rx_header_len, 5U);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    type = ctx->io_rx_header[0];
    version = (uint16_t)(((uint16_t)ctx->io_rx_header[1U] <<8U) |
                         (uint16_t)ctx->io_rx_header[2U]);
    length = (uint16_t)(((uint16_t)ctx->io_rx_header[3U] <<8U) |
                        (uint16_t)ctx->io_rx_header[4U]);

#if NOXTLS_TLS_MAX_WIRE_RECORD_LENGTH < 65535U
    if (length > TLS_MAX_WIRE_RECORD_LENGTH) {
        ctx->io_rx_header_len = 0U;
        return NOXTLS_RETURN_INVALID_PARAM;
    }
#endif
    if (length > TLS_MAX_PROTECTED_RECORD_FRAGMENT) {
        ctx->io_rx_header_len = 0U;
        return NOXTLS_RETURN_RECORD_OVERFLOW;
    }

    if ((ctx->io_rx_payload == NULL) && (length > 0U)) {
        ctx->io_rx_payload = (uint8_t *)noxtls_malloc(length);
        if (ctx->io_rx_payload == NULL) {
            ctx->io_rx_header_len = 0U;
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        ctx->io_rx_payload_len = length;
    }
    if (length > 0U) {
        rc = tls_nonblocking_read(ctx, ctx->io_rx_payload,
                                  &ctx->io_rx_payload_offset, length);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    payload = ctx->io_rx_payload;
    tls_nonblocking_reset_rx(ctx);

    noxtls_secure_zero((record), sizeof(*(record)));
    record->type = type;
    record->version = version;
    if ((type != TLS_RECORD_CHANGE_CIPHER_SPEC) &&
       (type != TLS_RECORD_ALERT) &&
       (type != TLS_RECORD_HANDSHAKE) &&
       (type != TLS_RECORD_APPLICATION_DATA) &&
       (type != TLS_RECORD_HEARTBEAT)) {
        if (payload != NULL) {
            (void)noxtls_free(payload);
        }
        return NOXTLS_RETURN_SUCCESS;
    }
    record->length = length;
    record->data = payload;

    tls_dump_record(NULL, ctx->io_rx_header, 5U);
    if ((payload != NULL) && (length > 0U)) {
        tls_dump_record(NULL, payload, length);
    }
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_RECORD, NOXSIGHT_SEVERITY_TRACE,
                    NOXTLS_EVT_RECORD_RX, record->type, record->length);
    if ((record->type == TLS_RECORD_ALERT) && (record->length >= 2U) && (record->data != NULL)) {
        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_ALERT, NOXSIGHT_SEVERITY_WARN,
                        NOXTLS_EVT_ALERT_RECV, record->data[0], record->data[1]);
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Receive one TLS or DTLS record via the configured receive callback.
 *
 * For TLS, reads a five-byte header then the fragment. For DTLS, delegates to the DTLS
 * record layer and reassembles handshake fragments when needed. The caller must `free`
 * `record->data` when non-NULL.
 *
 * @param[in,out] ctx     TLS context with `recv_callback` set.
 * @param[out] record     On success, populated record (type, version, length, allocated data).
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers;
 *         `NOXTLS_RETURN_FAILED` on I/O short read or missing callback;
 *         `NOXTLS_RETURN_INVALID_PARAM` if wire length exceeds `TLS_MAX_WIRE_RECORD_LENGTH`.
 */
noxtls_return_t noxtls_tls_recv_record(tls_context_t *ctx, tls_record_t *record)
{
    uint8_t header[5];
    tls_record_header_t parsed_header;
    int32_t received = 0;
    uint16_t length = 0U;
    
    if ((ctx == NULL) || (record == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    if (ctx->recv_callback == NULL) {
        return NOXTLS_RETURN_FAILED;  /* No receive callback set */
    }
    
    noxtls_secure_zero((record), sizeof(tls_record_t));

#if NOXTLS_FEATURE_DTLS
    if (tls_is_dtls_version(ctx->version) != 0U) {
        dtls_context_t *dctx = (dtls_context_t *)(void *)ctx;

        for (;;) {
            dtls_record_t drec;
            noxtls_return_t rc = noxtls_dtls_recv_record(dctx, &drec);
            if (rc != NOXTLS_RETURN_SUCCESS) {
                (void)noxtls_debug_printf((const uint8_t *)"[TLS13_DEBUG] tls_recv_record(dtls): dtls_recv_record rc=%d\n", rc);
                return rc;
            }
            (void)noxtls_debug_printf((const uint8_t *)"[TLS13_DEBUG] tls_recv_record(dtls): drec.type=0x%02X len=%u version=0x%04X epoch=%u\n",
                                drec.type, drec.length, drec.version, drec.epoch);

            if (drec.type != TLS_RECORD_HANDSHAKE) {
                record->type = drec.type;
                record->version = drec.version;
                record->length = drec.length;
                record->data = drec.data;
                NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_RECORD, NOXSIGHT_SEVERITY_TRACE,
                                NOXTLS_EVT_RECORD_RX, record->type, record->length);
                if ((record->type == TLS_RECORD_ALERT) && (record->length >= 2U) && (record->data != NULL)) {
                    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_ALERT, NOXSIGHT_SEVERITY_WARN,
                                    NOXTLS_EVT_ALERT_RECV, record->data[0], record->data[1]);
                }
                return NOXTLS_RETURN_SUCCESS;
            }

            if (drec.length < DTLS_HANDSHAKE_HEADER_SIZE) {
                if (drec.data != NULL) {
                    (void)noxtls_free(drec.data);
                }
                return NOXTLS_RETURN_FAILED;
            }

            dtls_handshake_fragment_t fragment;
            uint8_t *complete_msg = NULL;
            uint32_t complete_len = 0U;
            uint32_t fragment_len = 0U;
            int valid_fragment = 1;

            fragment.msg_type = drec.data[DTLS_HANDSHAKE_TYPE_OFFSET];
            {
                uint32_t b0 = (uint32_t)drec.data[DTLS_HANDSHAKE_LENGTH_OFFSET];
                uint32_t b1 = (uint32_t)drec.data[DTLS_HANDSHAKE_LENGTH_OFFSET + 1U];
                uint32_t b2 = (uint32_t)drec.data[DTLS_HANDSHAKE_LENGTH_OFFSET + 2U];
                b0 <<= 16U;
                b1 <<= 8U;
                fragment.length = b0 | b1 | b2;
            }
            {
                uint16_t s0 = (uint16_t)drec.data[DTLS_HANDSHAKE_MESSAGE_SEQ_OFFSET];
                uint16_t s1 = (uint16_t)drec.data[DTLS_HANDSHAKE_MESSAGE_SEQ_OFFSET + 1U];
                s0 = (uint16_t)(s0 << 8U);
                fragment.message_seq = (uint16_t)(s0 | s1);
            }
            {
                uint32_t b0 = (uint32_t)drec.data[DTLS_HANDSHAKE_FRAGMENT_OFFSET];
                uint32_t b1 = (uint32_t)drec.data[DTLS_HANDSHAKE_FRAGMENT_OFFSET + 1U];
                uint32_t b2 = (uint32_t)drec.data[DTLS_HANDSHAKE_FRAGMENT_OFFSET + 2U];
                b0 <<= 16U;
                b1 <<= 8U;
                fragment.fragment_offset = b0 | b1 | b2;
            }
            {
                uint32_t b0 = (uint32_t)drec.data[DTLS_HANDSHAKE_FRAGMENT_LEN_OFFSET];
                uint32_t b1 = (uint32_t)drec.data[DTLS_HANDSHAKE_FRAGMENT_LEN_OFFSET + 1U];
                uint32_t b2 = (uint32_t)drec.data[DTLS_HANDSHAKE_FRAGMENT_LEN_OFFSET + 2U];
                b0 <<= 16U;
                b1 <<= 8U;
                fragment.fragment_length = b0 | b1 | b2;
            }
            fragment_len = fragment.fragment_length;
            if ((fragment.msg_type < TLS_HANDSHAKE_CLIENT_HELLO) ||
               (fragment.msg_type > TLS_HANDSHAKE_FINISHED)) {
                valid_fragment = 0;
            }
            if ((fragment.length == 0U) ||
               (fragment.fragment_length > fragment.length) ||
               ((fragment.fragment_offset + fragment.fragment_length) > fragment.length)) {
                valid_fragment = 0;
            }
            if ((fragment_len > ((uint32_t)drec.length - DTLS_HANDSHAKE_HEADER_SIZE)) ||
               (((DTLS_HANDSHAKE_HEADER_SIZE + fragment_len) != (uint32_t)drec.length))) {
                valid_fragment = 0;
            }
            if (valid_fragment == 0) {
                /* SECURITY (NX-11): a malformed handshake fragment must not be handed to
                 * the caller as a successfully received record. Drop it and report it. */
                (void)noxtls_free(drec.data);
                dctx->flight_buffer_len = 0U;
                return NOXTLS_RETURN_BAD_DATA;
            }
            fragment.data = &drec.data[DTLS_HANDSHAKE_BODY_OFFSET];

            rc = noxtls_dtls_reassemble_handshake(dctx, &fragment, &complete_msg, &complete_len);
            (void)noxtls_free(drec.data);
            if (rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            if (complete_msg == NULL) {
                continue;
            }

            record->type = TLS_RECORD_HANDSHAKE;
            record->version = ctx->version;
            record->length = complete_len + 4U;
            record->data = (uint8_t*)noxtls_malloc((size_t)record->length);
            if (record->data == NULL) {
                (void)noxtls_free(complete_msg);
                return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
            }
            record->data[0] = fragment.msg_type;
            record->data[1] = (uint8_t)((((uint32_t)complete_len) >>16U) & 0xFFU);
            record->data[2] = (uint8_t)((((uint32_t)complete_len) >>8U) & 0xFFU);
            record->data[3] = (uint8_t)(complete_len & 0xFFU);
            noxtls_copy_u8(&record->data[4], (size_t)complete_len, complete_msg, (size_t)complete_len);
            (void)noxtls_free(complete_msg);

            dctx->flight_buffer_len = 0U;
            NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_RECORD, NOXSIGHT_SEVERITY_TRACE,
                            NOXTLS_EVT_RECORD_RX, record->type, record->length);
            return NOXTLS_RETURN_SUCCESS;
        }
    }
#endif /* NOXTLS_FEATURE_DTLS */

    if (ctx->io_mode == TLS_IO_MODE_NON_BLOCKING) { return tls_nonblocking_recv_record(ctx, record); }
    
    /* Receive record header (5 bytes) */
    (void)noxtls_debug_printf((const uint8_t *)"[TLS_DEBUG] tls_recv_record: Attempting to read 5-byte header...\n");
    received = ctx->recv_callback(ctx->user_data, header, 5);
    (void)noxtls_debug_printf((const uint8_t *)"[TLS_DEBUG] tls_recv_record: Received %d bytes for header\n", received);
    if (received < 5) {
        (void)noxtls_debug_printf((const uint8_t *)"[TLS_DEBUG] tls_recv_record: Failed to receive full header (got %d/5 bytes)\n", received);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Parse record header */
    parsed_header.type = header[0U];
    parsed_header.version[0U] = header[1U];
    parsed_header.version[1U] = header[2U];
    parsed_header.length[0U] = header[3U];
    parsed_header.length[1U] = header[4U];
    record->type = parsed_header.type;
    {
        uint16_t v0 = (uint16_t)parsed_header.version[0U];
        uint16_t v1 = (uint16_t)parsed_header.version[1U];
        v0 = (uint16_t)(v0 << 8U);
        record->version = (uint16_t)(v0 | v1);
    }
    {
        uint16_t l0 = (uint16_t)parsed_header.length[0U];
        uint16_t l1 = (uint16_t)parsed_header.length[1U];
        l0 = (uint16_t)(l0 << 8U);
        length = (uint16_t)(l0 | l1);
    }
    (void)noxtls_debug_printf((const uint8_t *)"[TLS_DEBUG] tls_recv_record: Header parsed - type=%u, version=0x%04x, length=%u\n", 
                          record->type, record->version, length);
    
#if NOXTLS_TLS_MAX_WIRE_RECORD_LENGTH < 65535U
    if (length > TLS_MAX_WIRE_RECORD_LENGTH) {
        (void)noxtls_debug_printf((const uint8_t *)"[TLS_DEBUG] tls_recv_record: Record length %u exceeds max wire %u\n", length, TLS_MAX_WIRE_RECORD_LENGTH);
        return NOXTLS_RETURN_INVALID_PARAM;
    }
#endif
    /* Absolute ciphertext ceiling (RFC 5246 TLSCiphertext / RFC 8446 encrypted). */
    if (length > TLS_MAX_PROTECTED_RECORD_FRAGMENT) {
        (void)noxtls_debug_printf((const uint8_t *)"[TLS_DEBUG] tls_recv_record: Record length %u exceeds protected max %u\n",
                            length, (uint32_t)TLS_MAX_PROTECTED_RECORD_FRAGMENT);
        /* Drain so the stream stays aligned; caller sends record_overflow. */
        uint8_t *drain = (uint8_t*)noxtls_malloc(length);
        if (drain != NULL) {
            (void)ctx->recv_callback(ctx->user_data, drain, length);
            (void)noxtls_free(drain);
        }
        return NOXTLS_RETURN_RECORD_OVERFLOW;
    }

    if ((record->type != TLS_RECORD_CHANGE_CIPHER_SPEC) &&
       (record->type != TLS_RECORD_ALERT) &&
       (record->type != TLS_RECORD_HANDSHAKE) &&
       (record->type != TLS_RECORD_APPLICATION_DATA) &&
       (record->type != TLS_RECORD_HEARTBEAT)) {
        (void)noxtls_debug_printf((const uint8_t *)"[TLS_DEBUG] tls_recv_record: Invalid record type %u (draining %u bytes)\n",
                            (uint32_t)record->type, (uint32_t)length);
        /* Read full payload so the byte stream stays aligned; upper layer sends fatal unexpected_message. */
        if (length > 0U) {
            uint8_t *drain = (uint8_t*)noxtls_malloc(length);
            if (drain == NULL) {
                return NOXTLS_RETURN_FAILED;
            }
            received = ctx->recv_callback(ctx->user_data, drain, length);
            (void)noxtls_free(drain);
            if ((received < 0) || ((uint32_t)received != length)) {
                return NOXTLS_RETURN_FAILED;
            }
        }
        /* Payload consumed; report unsupported type to handshake layer (fatal unexpected_message). */
        noxtls_secure_zero((record), sizeof(tls_record_t));
        record->type = parsed_header.type;
        record->version = (uint16_t)(((uint16_t)parsed_header.version[0] << 8U) | (uint16_t)parsed_header.version[1]);
        record->length = 0U;
        record->data = NULL;
        return NOXTLS_RETURN_SUCCESS;
    }
    
    /* Allocate and receive record data */
    if (length > 0U) {
        (void)noxtls_debug_printf((const uint8_t *)"[TLS_DEBUG] tls_recv_record: Allocating %u bytes for record data...\n", length);
        record->data = (uint8_t*)noxtls_malloc(length);
        if (record->data == NULL) {
            (void)noxtls_debug_printf((const uint8_t *)"[TLS_DEBUG] tls_recv_record: Memory allocation failed\n");
            return NOXTLS_RETURN_FAILED;
        }
        
        (void)noxtls_debug_printf((const uint8_t *)"[TLS_DEBUG] tls_recv_record: Attempting to read %u bytes of record data...\n", length);
        received = ctx->recv_callback(ctx->user_data, record->data, length);
        (void)noxtls_debug_printf((const uint8_t *)"[TLS_DEBUG] tls_recv_record: Received %d bytes of record data\n", received);
        if ((received < 0) || ((uint32_t)received != length)) {
            (void)noxtls_debug_printf((const uint8_t *)"[TLS_DEBUG] tls_recv_record: Failed to receive full record data (got %d/%u bytes)\n", received, length);
            (void)noxtls_free(record->data);
            record->data = NULL;
            return NOXTLS_RETURN_FAILED;
        }
        (void)noxtls_debug_printf((const uint8_t *)"[TLS_DEBUG] tls_recv_record: Successfully received complete record (%u bytes)\n", length);
        if ((record->type == TLS_RECORD_ALERT) && (length >= 2U)) {
            uint8_t alert_level = (uint8_t)(record->data[0U]);
            uint8_t alert_desc = (uint8_t)(record->data[1U]);
            const uint8_t *level_str = NULL;
            if (alert_level == 1U) {
                level_str = s_u8txt_noxtls_tls_common_865;
            } else if (alert_level == 2U) {
                level_str = s_u8txt_noxtls_tls_common_867;
            } else {
                level_str = s_u8txt_noxtls_tls_common_869;
            }
            const uint8_t *desc_str = (const uint8_t[]){ (uint8_t)'u', (uint8_t)'n', (uint8_t)'k', (uint8_t)'n', (uint8_t)'o', (uint8_t)'w', (uint8_t)'n', 0 };
            switch (alert_desc) {
                case 0: desc_str = (const uint8_t[]){ (uint8_t)'c', (uint8_t)'l', (uint8_t)'o', (uint8_t)'s', (uint8_t)'e', (uint8_t)'_', (uint8_t)'n', (uint8_t)'o', (uint8_t)'t', (uint8_t)'i', (uint8_t)'f', (uint8_t)'y', 0 }; break;
                case 10: desc_str = (const uint8_t[]){ (uint8_t)'u', (uint8_t)'n', (uint8_t)'e', (uint8_t)'x', (uint8_t)'p', (uint8_t)'e', (uint8_t)'c', (uint8_t)'t', (uint8_t)'e', (uint8_t)'d', (uint8_t)'_', (uint8_t)'m', (uint8_t)'e', (uint8_t)'s', (uint8_t)'s', (uint8_t)'a', (uint8_t)'g', (uint8_t)'e', 0 }; break;
                case 20: desc_str = (const uint8_t[]){ (uint8_t)'b', (uint8_t)'a', (uint8_t)'d', (uint8_t)'_', (uint8_t)'r', (uint8_t)'e', (uint8_t)'c', (uint8_t)'o', (uint8_t)'r', (uint8_t)'d', (uint8_t)'_', (uint8_t)'m', (uint8_t)'a', (uint8_t)'c', 0 }; break;
                case 21: desc_str = (const uint8_t[]){ (uint8_t)'d', (uint8_t)'e', (uint8_t)'c', (uint8_t)'r', (uint8_t)'y', (uint8_t)'p', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', (uint8_t)'_', (uint8_t)'f', (uint8_t)'a', (uint8_t)'i', (uint8_t)'l', (uint8_t)'e', (uint8_t)'d', 0 }; break;
                case 22: desc_str = (const uint8_t[]){ (uint8_t)'r', (uint8_t)'e', (uint8_t)'c', (uint8_t)'o', (uint8_t)'r', (uint8_t)'d', (uint8_t)'_', (uint8_t)'o', (uint8_t)'v', (uint8_t)'e', (uint8_t)'r', (uint8_t)'f', (uint8_t)'l', (uint8_t)'o', (uint8_t)'w', 0 }; break;
                case 40: desc_str = (const uint8_t[]){ (uint8_t)'h', (uint8_t)'a', (uint8_t)'n', (uint8_t)'d', (uint8_t)'s', (uint8_t)'h', (uint8_t)'a', (uint8_t)'k', (uint8_t)'e', (uint8_t)'_', (uint8_t)'f', (uint8_t)'a', (uint8_t)'i', (uint8_t)'l', (uint8_t)'u', (uint8_t)'r', (uint8_t)'e', 0 }; break;
                case 42: desc_str = (const uint8_t[]){ (uint8_t)'b', (uint8_t)'a', (uint8_t)'d', (uint8_t)'_', (uint8_t)'c', (uint8_t)'e', (uint8_t)'r', (uint8_t)'t', (uint8_t)'i', (uint8_t)'f', (uint8_t)'i', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'e', 0 }; break;
                case 43: desc_str = (const uint8_t[]){ (uint8_t)'u', (uint8_t)'n', (uint8_t)'s', (uint8_t)'u', (uint8_t)'p', (uint8_t)'p', (uint8_t)'o', (uint8_t)'r', (uint8_t)'t', (uint8_t)'e', (uint8_t)'d', (uint8_t)'_', (uint8_t)'c', (uint8_t)'e', (uint8_t)'r', (uint8_t)'t', (uint8_t)'i', (uint8_t)'f', (uint8_t)'i', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'e', 0 }; break;
                case 44: desc_str = (const uint8_t[]){ (uint8_t)'c', (uint8_t)'e', (uint8_t)'r', (uint8_t)'t', (uint8_t)'i', (uint8_t)'f', (uint8_t)'i', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'e', (uint8_t)'_', (uint8_t)'r', (uint8_t)'e', (uint8_t)'v', (uint8_t)'o', (uint8_t)'k', (uint8_t)'e', (uint8_t)'d', 0 }; break;
                case 45: desc_str = (const uint8_t[]){ (uint8_t)'c', (uint8_t)'e', (uint8_t)'r', (uint8_t)'t', (uint8_t)'i', (uint8_t)'f', (uint8_t)'i', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'e', (uint8_t)'_', (uint8_t)'e', (uint8_t)'x', (uint8_t)'p', (uint8_t)'i', (uint8_t)'r', (uint8_t)'e', (uint8_t)'d', 0 }; break;
                case 46: desc_str = (const uint8_t[]){ (uint8_t)'c', (uint8_t)'e', (uint8_t)'r', (uint8_t)'t', (uint8_t)'i', (uint8_t)'f', (uint8_t)'i', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'e', (uint8_t)'_', (uint8_t)'u', (uint8_t)'n', (uint8_t)'k', (uint8_t)'n', (uint8_t)'o', (uint8_t)'w', (uint8_t)'n', 0 }; break;
                case 47: desc_str = (const uint8_t[]){ (uint8_t)'i', (uint8_t)'l', (uint8_t)'l', (uint8_t)'e', (uint8_t)'g', (uint8_t)'a', (uint8_t)'l', (uint8_t)'_', (uint8_t)'p', (uint8_t)'a', (uint8_t)'r', (uint8_t)'a', (uint8_t)'m', (uint8_t)'e', (uint8_t)'t', (uint8_t)'e', (uint8_t)'r', 0 }; break;
                case 48: desc_str = (const uint8_t[]){ (uint8_t)'u', (uint8_t)'n', (uint8_t)'k', (uint8_t)'n', (uint8_t)'o', (uint8_t)'w', (uint8_t)'n', (uint8_t)'_', (uint8_t)'c', (uint8_t)'a', 0 }; break;
                case 49: desc_str = (const uint8_t[]){ (uint8_t)'a', (uint8_t)'c', (uint8_t)'c', (uint8_t)'e', (uint8_t)'s', (uint8_t)'s', (uint8_t)'_', (uint8_t)'d', (uint8_t)'e', (uint8_t)'n', (uint8_t)'i', (uint8_t)'e', (uint8_t)'d', 0 }; break;
                case 50: desc_str = (const uint8_t[]){ (uint8_t)'d', (uint8_t)'e', (uint8_t)'c', (uint8_t)'o', (uint8_t)'d', (uint8_t)'e', (uint8_t)'_', (uint8_t)'e', (uint8_t)'r', (uint8_t)'r', (uint8_t)'o', (uint8_t)'r', 0 }; break;
                case 51: desc_str = (const uint8_t[]){ (uint8_t)'d', (uint8_t)'e', (uint8_t)'c', (uint8_t)'r', (uint8_t)'y', (uint8_t)'p', (uint8_t)'t', (uint8_t)'_', (uint8_t)'e', (uint8_t)'r', (uint8_t)'r', (uint8_t)'o', (uint8_t)'r', 0 }; break;
                case 52: desc_str = (const uint8_t[]){ (uint8_t)'t', (uint8_t)'o', (uint8_t)'o', (uint8_t)'_', (uint8_t)'m', (uint8_t)'a', (uint8_t)'n', (uint8_t)'y', (uint8_t)'_', (uint8_t)'c', (uint8_t)'i', (uint8_t)'d', (uint8_t)'s', (uint8_t)'_', (uint8_t)'r', (uint8_t)'e', (uint8_t)'q', (uint8_t)'u', (uint8_t)'e', (uint8_t)'s', (uint8_t)'t', (uint8_t)'e', (uint8_t)'d', 0 }; break;
                case 70: desc_str = (const uint8_t[]){ (uint8_t)'p', (uint8_t)'r', (uint8_t)'o', (uint8_t)'t', (uint8_t)'o', (uint8_t)'c', (uint8_t)'o', (uint8_t)'l', (uint8_t)'_', (uint8_t)'v', (uint8_t)'e', (uint8_t)'r', (uint8_t)'s', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', 0 }; break;
                case 71: desc_str = (const uint8_t[]){ (uint8_t)'i', (uint8_t)'n', (uint8_t)'s', (uint8_t)'u', (uint8_t)'f', (uint8_t)'f', (uint8_t)'i', (uint8_t)'c', (uint8_t)'i', (uint8_t)'e', (uint8_t)'n', (uint8_t)'t', (uint8_t)'_', (uint8_t)'s', (uint8_t)'e', (uint8_t)'c', (uint8_t)'u', (uint8_t)'r', (uint8_t)'i', (uint8_t)'t', (uint8_t)'y', 0 }; break;
                case 80: desc_str = (const uint8_t[]){ (uint8_t)'i', (uint8_t)'n', (uint8_t)'t', (uint8_t)'e', (uint8_t)'r', (uint8_t)'n', (uint8_t)'a', (uint8_t)'l', (uint8_t)'_', (uint8_t)'e', (uint8_t)'r', (uint8_t)'r', (uint8_t)'o', (uint8_t)'r', 0 }; break;
                case 86: desc_str = (const uint8_t[]){ (uint8_t)'i', (uint8_t)'n', (uint8_t)'a', (uint8_t)'p', (uint8_t)'p', (uint8_t)'r', (uint8_t)'o', (uint8_t)'p', (uint8_t)'r', (uint8_t)'i', (uint8_t)'a', (uint8_t)'t', (uint8_t)'e', (uint8_t)'_', (uint8_t)'f', (uint8_t)'a', (uint8_t)'l', (uint8_t)'l', (uint8_t)'b', (uint8_t)'a', (uint8_t)'c', (uint8_t)'k', 0 }; break;
                case 90: desc_str = (const uint8_t[]){ (uint8_t)'u', (uint8_t)'s', (uint8_t)'e', (uint8_t)'r', (uint8_t)'_', (uint8_t)'c', (uint8_t)'a', (uint8_t)'n', (uint8_t)'c', (uint8_t)'e', (uint8_t)'l', (uint8_t)'e', (uint8_t)'d', 0 }; break;
                case 109: desc_str = (const uint8_t[]){ (uint8_t)'m', (uint8_t)'i', (uint8_t)'s', (uint8_t)'s', (uint8_t)'i', (uint8_t)'n', (uint8_t)'g', (uint8_t)'_', (uint8_t)'e', (uint8_t)'x', (uint8_t)'t', (uint8_t)'e', (uint8_t)'n', (uint8_t)'s', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', 0 }; break;
                case 110: desc_str = (const uint8_t[]){ (uint8_t)'u', (uint8_t)'n', (uint8_t)'s', (uint8_t)'u', (uint8_t)'p', (uint8_t)'p', (uint8_t)'o', (uint8_t)'r', (uint8_t)'t', (uint8_t)'e', (uint8_t)'d', (uint8_t)'_', (uint8_t)'e', (uint8_t)'x', (uint8_t)'t', (uint8_t)'e', (uint8_t)'n', (uint8_t)'s', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', 0 }; break;
                case 112: desc_str = (const uint8_t[]){ (uint8_t)'u', (uint8_t)'n', (uint8_t)'r', (uint8_t)'e', (uint8_t)'c', (uint8_t)'o', (uint8_t)'g', (uint8_t)'n', (uint8_t)'i', (uint8_t)'z', (uint8_t)'e', (uint8_t)'d', (uint8_t)'_', (uint8_t)'n', (uint8_t)'a', (uint8_t)'m', (uint8_t)'e', 0 }; break;
                case 120: desc_str = (const uint8_t[]){ (uint8_t)'n', (uint8_t)'o', (uint8_t)'_', (uint8_t)'a', (uint8_t)'p', (uint8_t)'p', (uint8_t)'l', (uint8_t)'i', (uint8_t)'c', (uint8_t)'a', (uint8_t)'t', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', (uint8_t)'_', (uint8_t)'p', (uint8_t)'r', (uint8_t)'o', (uint8_t)'t', (uint8_t)'o', (uint8_t)'c', (uint8_t)'o', (uint8_t)'l', 0 }; break;
                default: desc_str = (const uint8_t[]){ (uint8_t)'u', (uint8_t)'n', (uint8_t)'k', (uint8_t)'n', (uint8_t)'o', (uint8_t)'w', (uint8_t)'n', 0 }; break;
            }
            (void)noxtls_debug_printf((const uint8_t *)"[TLS_DEBUG] tls_recv_record: Alert level=%u (%s) desc=%u (%s)\n",
                                  alert_level, level_str, alert_desc, desc_str);
        }
    }

    {
        uint8_t dump_buf[5];
        dump_buf[0] = record->type;
        dump_buf[1] = (uint8_t)((((uint32_t)record->version) >> 8U) & 0xFFU);
        dump_buf[2] = (uint8_t)(record->version & 0xFFU);
dump_buf[3] = (uint8_t)((((uint32_t)(length) >>8U)) & 0xFFU);
        dump_buf[4] = (uint8_t)(length & 0xFFU);
tls_dump_record(NULL, dump_buf, 5);
        if ((record->data != NULL) && (length > 0U)) {
            tls_dump_record(NULL, record->data, length);
        }
    }
    
    record->length = length;
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_RECORD, NOXSIGHT_SEVERITY_TRACE,
                    NOXTLS_EVT_RECORD_RX, record->type, record->length);
    if ((record->type == TLS_RECORD_ALERT) && (record->length >= 2U) && (record->data != NULL)) {
        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_ALERT, NOXSIGHT_SEVERITY_WARN,
                        NOXTLS_EVT_ALERT_RECV, record->data[0], record->data[1]);
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Send a TLS alert record (two-byte alert body).
 * @param[in,out] ctx          TLS context.
 * @param[in] level            `TLS_ALERT_LEVEL_WARNING` or `TLS_ALERT_LEVEL_FATAL`.
 * @param[in] description      Alert description code (e.g. `TLS_ALERT_CLOSE_NOTIFY`).
 * @return `NOXTLS_RETURN_SUCCESS` on success; error from `noxtls_tls_send_record` otherwise.
 */
noxtls_return_t noxtls_tls_send_alert(tls_context_t *ctx, uint8_t level, uint8_t description) /* NOLINT(bugprone-easily-swappable-parameters) */
{
    uint8_t alert[2];
    
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    alert[0] = level;
    alert[1] = description;
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_ALERT, NOXSIGHT_SEVERITY_WARN,
                    NOXTLS_EVT_ALERT_SENT, level, description);
    
    return noxtls_tls_send_record(ctx, TLS_RECORD_ALERT, alert, 2);
}

/**
 * @brief Receive ClientHello and detect the highest supported TLS version.
 *
 * Reads the first handshake flight and inspects the supported_versions extension (type 43)
 * and legacy version field to choose among TLS 1.0–1.3 (and related downgrade paths).
 *
 * @param[in,out] base_ctx           Base TLS context with I/O callbacks configured.
 * @param[out] detected_version      On success, chosen `TLS_VERSION_*` constant.
 * @param[out] client_hello_data     On success, allocated ClientHello bytes; caller must `free`.
 * @param[out] client_hello_len      On success, length of `*client_hello_data`.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid pointers;
 *         I/O or parse errors otherwise; `NOXTLS_RETURN_BAD_DATA` if version cannot be determined.
 */
noxtls_return_t noxtls_tls_detect_version(tls_context_t *base_ctx, uint16_t *detected_version, 
                                     uint8_t **client_hello_data, uint32_t *client_hello_len)
{
    tls_record_t record;
    tls_record_t next_record;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint32_t offset = 0U;
    uint32_t client_hello_total_len = 0U;
    uint32_t assembled_len = 0U;
    uint16_t version = 0U;
    uint8_t session_id_len = 0U;
    uint16_t cipher_suites_len = 0U;
    uint8_t compression_methods_len = 0U;
    uint8_t has_supported_versions_ext = 0U;
    uint8_t has_tls13 = 0U;
    uint8_t has_tls12 = 0U;
    uint8_t resumed_reassembly = 0U;
    
    if ((base_ctx == NULL) || (detected_version == NULL) ||
       (client_hello_data == NULL) || (client_hello_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    if (base_ctx->recv_callback == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    *client_hello_data = NULL;
    *client_hello_len = 0U;
    *detected_version = TLS_VERSION_1_2;  /* Default to TLS 1.2 */
    
    /* Receive Client Hello record, or resume handshake-message reassembly. */
    noxtls_secure_zero(&record, sizeof(record));
    if ((base_ctx->io_mode == TLS_IO_MODE_NON_BLOCKING) &&
       (base_ctx->pending_client_hello != NULL)) {
        record.type = TLS_RECORD_HANDSHAKE;
        record.data = base_ctx->pending_client_hello;
        record.length = base_ctx->pending_client_hello_len;
        base_ctx->pending_client_hello = NULL;
        base_ctx->pending_client_hello_len = 0U;
        resumed_reassembly = 1U;
    } else {
        /* MISRA 15.7: final else path */
        rc = noxtls_tls_recv_record(base_ctx, &record);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    if ((record.length > 0U) && (record.data == NULL)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    /* ClientHello is always TLSPlaintext; reject fragments above 2^14 (RFC 5246). */
    if ((resumed_reassembly == 0U) && (record.length > TLS_MAX_RECORD_SIZE)) {
        (void)noxtls_free(record.data);
        return NOXTLS_RETURN_RECORD_OVERFLOW;
    }
    
    if (record.type != TLS_RECORD_HANDSHAKE) {
        (void)noxtls_free(record.data);
        return NOXTLS_RETURN_TLS_ERROR;
    }
    if (record.length < 1U) {
        (void)noxtls_free(record.data);
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    if (record.data[0] != TLS_HANDSHAKE_CLIENT_HELLO) {
        (void)noxtls_free(record.data);
        return NOXTLS_RETURN_TLS_ERROR;
    }

    assembled_len = record.length;
    /* Handshake length needs 4 bytes; ClientHello may be split with a tiny first record (tlsfuzzer). */
    while (assembled_len < 4U) {
        uint8_t *new_buf = NULL;
        rc = noxtls_tls_recv_record(base_ctx, &next_record);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            if ((base_ctx->io_mode == TLS_IO_MODE_NON_BLOCKING) &&
               ((rc == NOXTLS_RETURN_WANT_READ) || (rc == NOXTLS_RETURN_WANT_WRITE))) {
                base_ctx->pending_client_hello = record.data;
                base_ctx->pending_client_hello_len = assembled_len;
                return rc;
            }
            (void)noxtls_free(record.data);
            return rc;
        }
        if ((next_record.length > 0U) && (next_record.data == NULL)) {
            (void)noxtls_free(record.data);
            return NOXTLS_RETURN_BAD_DATA;
        }
        if (next_record.length > TLS_MAX_RECORD_SIZE) {
            (void)noxtls_free(next_record.data);
            (void)noxtls_free(record.data);
            return NOXTLS_RETURN_RECORD_OVERFLOW;
        }
        if (next_record.type != TLS_RECORD_HANDSHAKE) {
            if (next_record.data != NULL) {
                (void)noxtls_free(next_record.data);
            }
            (void)noxtls_free(record.data);
            return NOXTLS_RETURN_TLS_ERROR;
        }
        if (next_record.length > (UINT32_MAX - assembled_len)) {
            if (next_record.data != NULL) {
                (void)noxtls_free(next_record.data);
            }
            (void)noxtls_free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        new_buf = (uint8_t*)noxtls_realloc(record.data, assembled_len + next_record.length);
        if (new_buf == NULL) {
            if (next_record.data != NULL) {
                (void)noxtls_free(next_record.data);
            }
            (void)noxtls_free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        record.data = new_buf;
        if ((next_record.length > 0U) && (next_record.data != NULL)) {
            noxtls_copy_u8(&record.data[assembled_len], (size_t)next_record.length, next_record.data, (size_t)next_record.length);
        }
        assembled_len += next_record.length;
        if (next_record.data != NULL) {
            (void)noxtls_free(next_record.data);
        }
    }

    client_hello_total_len = 4U + (((uint32_t)record.data[1] <<16U) |
                                   ((uint32_t)record.data[2] <<8U) |
                                   (uint32_t)record.data[3]);
    if ((client_hello_total_len > TLS_MAX_CLIENT_HELLO_BYTES) || (client_hello_total_len < 38U)) {
        (void)noxtls_free(record.data);
        return NOXTLS_RETURN_BAD_DATA;
    }
    while (assembled_len < client_hello_total_len) {
        uint8_t *new_buf = NULL;
        rc = noxtls_tls_recv_record(base_ctx, &next_record);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            if ((base_ctx->io_mode == TLS_IO_MODE_NON_BLOCKING) &&
               ((rc == NOXTLS_RETURN_WANT_READ) || (rc == NOXTLS_RETURN_WANT_WRITE))) {
                base_ctx->pending_client_hello = record.data;
                base_ctx->pending_client_hello_len = assembled_len;
                return rc;
            }
            (void)noxtls_free(record.data);
            return rc;
        }
        if ((next_record.length > 0U) && (next_record.data == NULL)) {
            (void)noxtls_free(record.data);
            return NOXTLS_RETURN_BAD_DATA;
        }
        if (next_record.length > TLS_MAX_RECORD_SIZE) {
            if (next_record.data != NULL) {
                (void)noxtls_free(next_record.data);
            }
            (void)noxtls_free(record.data);
            return NOXTLS_RETURN_RECORD_OVERFLOW;
        }
        if (next_record.type != TLS_RECORD_HANDSHAKE) {
            if (next_record.data != NULL) { (void)noxtls_free(next_record.data); }
            (void)noxtls_free(record.data);
            return NOXTLS_RETURN_TLS_ERROR;
        }
        new_buf = (uint8_t*)noxtls_realloc(record.data, assembled_len + next_record.length);
        if (new_buf == NULL) {
            if (next_record.data != NULL) { (void)noxtls_free(next_record.data); }
            (void)noxtls_free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        record.data = new_buf;
        if ((next_record.length > 0U) && (next_record.data != NULL)) {
            noxtls_copy_u8(&record.data[assembled_len], (size_t)next_record.length, next_record.data, (size_t)next_record.length);
        }
        assembled_len += next_record.length;
        if (next_record.data != NULL) { (void)noxtls_free(next_record.data); }
    }

    if ((assembled_len != client_hello_total_len) || (assembled_len < 38U)) {
        (void)noxtls_free(record.data);
        return NOXTLS_RETURN_BAD_DATA;
    }
    /* A fragmented ClientHello can legitimately exceed a single record payload. */
    record.length = assembled_len;
    
    /* Store Client Hello data for later use */
    *client_hello_data = record.data;
    *client_hello_len = assembled_len;
    
    offset = 4U;  /* Skip handshake header */
    
    /* Legacy version */
    version = ((uint16_t)record.data[offset] << 8U) | (uint16_t)record.data[offset + 1U];
    offset += 2U;
    
    /* Client Random (32 bytes) */
    offset += 32U;
    
    /* Session ID length */
    if ((offset + 1U) > record.length) {
        (void)noxtls_free(*client_hello_data);
        *client_hello_data = NULL;
        *client_hello_len = 0U;
        return NOXTLS_RETURN_BAD_DATA;
    }
    session_id_len = record.data[offset];
    offset += 1U;
    if(((offset + session_id_len) > record.length)) {
        (void)noxtls_free(*client_hello_data);
        *client_hello_data = NULL;
        *client_hello_len = 0U;
        return NOXTLS_RETURN_BAD_DATA;
    }
    offset += session_id_len;
    
    /* Cipher suites length */
    if ((offset + 2U) > record.length) {
        (void)noxtls_free(*client_hello_data);
        *client_hello_data = NULL;
        *client_hello_len = 0U;
        return NOXTLS_RETURN_BAD_DATA;
    }
    cipher_suites_len = ((uint16_t)record.data[offset] << 8U) | (uint16_t)record.data[offset + 1U];
    offset += 2U;
    if ((cipher_suites_len == 0U) ||
       (((cipher_suites_len & 1U) != 0U)) ||
       ((offset + cipher_suites_len) > record.length)) {
        (void)noxtls_free(*client_hello_data);
        *client_hello_data = NULL;
        *client_hello_len = 0U;
        return NOXTLS_RETURN_BAD_DATA;
    }
    offset += cipher_suites_len;
    
    /* Compression methods length */
    if ((offset + 1U) > record.length) {
        (void)noxtls_free(*client_hello_data);
        *client_hello_data = NULL;
        *client_hello_len = 0U;
        return NOXTLS_RETURN_BAD_DATA;
    }
    compression_methods_len = record.data[offset];
    offset += 1U;
    if ((compression_methods_len == 0U) || ((offset + compression_methods_len) > record.length)) {
        (void)noxtls_free(*client_hello_data);
        *client_hello_data = NULL;
        *client_hello_len = 0U;
        return NOXTLS_RETURN_BAD_DATA;
    }
    {
        uint32_t ci = 0U;
        uint8_t have_null = 0U;
        for (ci = 0U; ci < (uint32_t)compression_methods_len; ci += 1U) {
            if (record.data[offset + ci] == 0U) {
                have_null = 1U;
                break;
            }
        }
        if (have_null == 0U) {
            (void)noxtls_free(*client_hello_data);
            *client_hello_data = NULL;
            *client_hello_len = 0U;
            return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
        }
    }
    offset += compression_methods_len;
    
    /*
     * No extension block: honor ClientHello.legacy_version. Do not upgrade
     * TLS 1.0/1.1 hellos to TLS 1.2 — that invents a higher offer than the
     * client made and breaks protocol_version rejection when 1.0/1.1 are off.
     */
    if (offset >= record.length) {
        if (version >= TLS_VERSION_1_2) {
            *detected_version = TLS_VERSION_1_2;
        } else if (version == TLS_VERSION_1_1) {
            *detected_version = TLS_VERSION_1_1;
        } else if (version == TLS_VERSION_1_0) {
            *detected_version = TLS_VERSION_1_0;
        } else if ((version == 0x0300U) || (version == 0x0000U)) {
            /* SSLv3 / bogus (0,0): protocol_version (not decode_error). */
            (void)noxtls_free(*client_hello_data);
            *client_hello_data = NULL;
            *client_hello_len = 0U;
            return NOXTLS_RETURN_NOT_SUPPORTED;
        } else {
            /* MISRA 15.7: final else path */
            (void)noxtls_free(*client_hello_data);
            *client_hello_data = NULL;
            *client_hello_len = 0U;
            return NOXTLS_RETURN_BAD_DATA;
        }
        return NOXTLS_RETURN_SUCCESS;
    }
    
    /* Check if extensions are present */
    {
        uint32_t extensions_end = 0U;
        if ((offset + 2U) > record.length) {
            (void)noxtls_free(*client_hello_data);
            *client_hello_data = NULL;
            *client_hello_len = 0U;
            return NOXTLS_RETURN_BAD_DATA;
        }
        uint16_t extensions_len = (uint16_t)(((uint16_t)record.data[offset] << 8U) | (uint16_t)record.data[offset + 1U]);
        offset += 2U;
        uint32_t extensions_start = (uint32_t)(offset);
        if (extensions_len > (record.length - offset)) {
            (void)noxtls_free(*client_hello_data);
            *client_hello_data = NULL;
            *client_hello_len = 0U;
            return NOXTLS_RETURN_BAD_DATA;
        }
        extensions_end = extensions_start + extensions_len;
        
        /* Parse extensions to find Supported Versions (type 43) */
        while ((offset < extensions_end) && ((offset + 4U) <= extensions_end) && ((offset + 4U) <= record.length)) {
            uint16_t ext_type = (uint16_t)(((uint16_t)record.data[offset] << 8U) | (uint16_t)record.data[offset + 1U]);
            offset += 2U;
            uint16_t ext_len = (uint16_t)(((uint16_t)record.data[offset] << 8U) | (uint16_t)record.data[offset + 1U]);
            offset += 2U;
            if (ext_len > (extensions_end - offset)) {
                (void)noxtls_free(*client_hello_data);
                *client_hello_data = NULL;
                *client_hello_len = 0U;
                return NOXTLS_RETURN_BAD_DATA;
            }
            uint32_t ext_data_end = (uint32_t)(offset + ext_len);
            
            if (ext_type == TLS_EXTENSION_SUPPORTED_VERSIONS) {
                /* RFC 8446: server must select from client's supported_versions list. */
                has_supported_versions_ext = 1U;
                if ((ext_len >= 3U) && (offset < ext_data_end)) {
                    uint8_t versions_len = (uint8_t)(record.data[offset]);
                    uint32_t ver_offset = (uint32_t)(offset + 1U);
                    uint32_t versions_end = (uint32_t)(ver_offset + versions_len);
                    if (((versions_len >= 2U) &&
                       ((versions_len % 2U) == 0U) &&
                       (versions_len <= (ext_len - 1U)) &&
                       (versions_end <= ext_data_end))) {
                        while ((ver_offset + 1U) < versions_end) {
                            uint16_t supported_version = (uint16_t)(((uint16_t)record.data[ver_offset] << 8U) | (uint16_t)record.data[ver_offset + 1U]);
                            if (supported_version == TLS_VERSION_1_3) {
                                has_tls13 = 1U;
                            } else if (supported_version == TLS_VERSION_1_2) {
                                has_tls12 = 1U;
                            }
                             else {
                                 /* MISRA 15.7: no remaining alternative */
                             }
                            ver_offset += 2U;
                        }
                    }
                }
                offset = ext_data_end;
                break;  /* Found the extension, no need to continue */
            }
            /* Skip this extension */
            offset += ext_len;
        }
        if (extensions_end != record.length) {
            (void)noxtls_free(*client_hello_data);
            *client_hello_data = NULL;
            *client_hello_len = 0U;
            return NOXTLS_RETURN_BAD_DATA;
        }
        if ((has_supported_versions_ext == 0U) && (offset != extensions_end)) {
            (void)noxtls_free(*client_hello_data);
            *client_hello_data = NULL;
            *client_hello_len = 0U;
            return NOXTLS_RETURN_BAD_DATA;
        }
    }
    
    /* Determine version */
    if (has_supported_versions_ext != 0U) {
        if (has_tls13 != 0U) {
            *detected_version = TLS_VERSION_1_3;
        } else if (has_tls12 != 0U) {
            *detected_version = TLS_VERSION_1_2;
        } else if ((version == TLS_VERSION_1_1) || (version == TLS_VERSION_1_0)) {
            /* Client sent supported_versions but without TLS 1.2/1.3 entries we recognize (e.g. draft-only);
             * fall back to legacy ClientHello.version for TLS 1.0/1.1 interop (tlsfuzzer EMS TLSv1.1). */
            *detected_version = version;
        } else {
            /* supported_versions present but no overlap with server policy. */
            (void)noxtls_free(*client_hello_data);
            *client_hello_data = NULL;
            *client_hello_len = 0U;
            return NOXTLS_RETURN_NOT_SUPPORTED;
        }
    } else if (version >= TLS_VERSION_1_2) {
        *detected_version = TLS_VERSION_1_2;
    } else if (version == TLS_VERSION_1_1) {
        *detected_version = TLS_VERSION_1_1;
    } else if (version == TLS_VERSION_1_0) {
        *detected_version = TLS_VERSION_1_0;
    } else if ((version == 0x0300U) || (version == 0x0000U)) {
        /* SSLv3 / bogus (0,0): protocol_version (not decode_error). */
        (void)noxtls_free(*client_hello_data);
        *client_hello_data = NULL;
        *client_hello_len = 0U;
        return NOXTLS_RETURN_NOT_SUPPORTED;
    } else {
        /* MISRA 15.7: final else path */
        (void)noxtls_free(*client_hello_data);
        *client_hello_data = NULL;
        *client_hello_len = 0U;
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Test whether ClientHello lists a version in the supported_versions extension (RFC 8446).
 * @param[in] client_hello      Full handshake message (type + 3-byte length + ClientHello body).
 * @param[in] client_hello_len  Length of @p client_hello.
 * @param[in] version           Wire version to search for (e.g. `TLS_VERSION_1_3`).
 * @return 1 if @p version appears in extension 43; 0 if absent, malformed, or not listed.
 */
int noxtls_tls_client_hello_supported_versions_has(const uint8_t *client_hello,
                                                 uint32_t client_hello_len,
                                                 uint16_t version)
{
    uint32_t offset = 0U;
    uint8_t session_id_len = 0U;
    uint16_t cipher_suites_len = 0U;
    uint8_t compression_methods_len = 0U;

    if ((client_hello == NULL) || (client_hello_len < 38U)) {
        return 0;
    }
    if (client_hello[0] != TLS_HANDSHAKE_CLIENT_HELLO) {
        return 0;
    }

    offset = 4U;
    offset += 2U; /* legacy version */

    offset += 32U; /* random */

    if ((offset + 1U) > client_hello_len) {
        return 0;
    }
    session_id_len = client_hello[offset];
    offset += 1U;
    if ((offset + (uint32_t)session_id_len) > client_hello_len) {
        return 0;
    }
    offset += (uint32_t)session_id_len;

    if ((offset + 2U) > client_hello_len) {
        return 0;
    }
    cipher_suites_len = (uint16_t)(((uint16_t)client_hello[offset] <<8U) | (uint16_t)client_hello[offset + 1U]);
    offset += 2U;
    if ((offset + (uint32_t)cipher_suites_len) > client_hello_len) {
        return 0;
    }
    offset += (uint32_t)cipher_suites_len;

    if ((offset + 1U) > client_hello_len) {
        return 0;
    }
    compression_methods_len = client_hello[offset];
    offset += 1U;
    if ((offset + (uint32_t)compression_methods_len) > client_hello_len) {
        return 0;
    }
    offset += (uint32_t)compression_methods_len;

    if ((offset + 2U) > client_hello_len) {
        return 0;
    }
    {
        uint16_t extensions_len = (uint16_t)(((uint16_t)client_hello[offset] <<8U) | (uint16_t)client_hello[offset + 1U]);
        uint32_t extensions_end = 0U;
        offset += 2U;
        if ((uint32_t)extensions_len > (client_hello_len - offset)) {
            return 0;
        }
        extensions_end = offset + (uint32_t)extensions_len;

        while (((offset + 4U) <= extensions_end) && ((offset + 4U) <= client_hello_len)) {
            uint16_t ext_type = (uint16_t)(((uint16_t)client_hello[offset] <<8U) | (uint16_t)client_hello[offset + 1U]);
            offset += 2U;
            uint16_t ext_len = (uint16_t)(((uint16_t)client_hello[offset] <<8U) | (uint16_t)client_hello[offset + 1U]);
            offset += 2U;
            if ((uint32_t)ext_len > (extensions_end - offset)) {
                return 0;
            }
            if (ext_type == TLS_EXTENSION_SUPPORTED_VERSIONS) {
                uint32_t ext_data_end = (uint32_t)(offset + (uint32_t)ext_len);
                if ((ext_len >= 3U) && (offset < ext_data_end)) {
                    uint8_t versions_len = (uint8_t)(client_hello[offset]);
                    uint32_t ver_offset = (uint32_t)(offset + 1U);
                    uint32_t versions_end = (uint32_t)(ver_offset + (uint32_t)versions_len);
                    if (((versions_len >= 2U) &&
                       ((versions_len % 2U) == 0U) &&
                       (versions_len <= (ext_len - 1U)) &&
                       (versions_end <= ext_data_end))) {
                        while ((ver_offset + 1U) < versions_end) {
                            uint16_t supported_version = (uint16_t)(((uint16_t)client_hello[ver_offset] <<8U) |
                                                                    (uint16_t)client_hello[ver_offset + 1U]);
                            if (supported_version == version) {
                                return 1;
                            }
                            ver_offset += 2U;
                        }
                    }
                }
                return 0;
            }
            offset += (uint32_t)ext_len;
        }
    }

    return 0;
}

/**
 * @brief Verify a certificate signature using its issuer's public key (TLS wrapper).
 *
 * Thin wrapper around `noxtls_x509_certificate_verify_signature` for handshake code.
 *
 * @param[in] cert    Certificate to verify (`x509_certificate_t*`).
 * @param[in] issuer  Issuer certificate with the signing public key (`x509_certificate_t*`).
 * @return `NOXTLS_RETURN_SUCCESS` if the signature is valid; `NOXTLS_RETURN_NULL` or
 *         X.509 verification error codes otherwise.
 */
noxtls_return_t noxtls_tls_verify_certificate_signature(const void *cert, const void *issuer)
{
    if ((cert == NULL) || (issuer == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    /* Call the X.509 certificate verification function */
    return noxtls_x509_certificate_verify_signature((const x509_certificate_t*)cert,
                                                    (const x509_certificate_t*)issuer);
}
