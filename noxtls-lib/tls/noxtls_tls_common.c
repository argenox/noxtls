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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_tls_common.h"
#if NOXTLS_FEATURE_DTLS
#include "noxtls_dtls_common.h"
#endif
#include "noxtls_tls_noxsight.h"
#include "certs/noxtls_x509.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/noxtls_hash.h"

static FILE *tls_record_dump_fp = NULL;

/**
 * @brief Return whether a wire version constant denotes DTLS (1.0, 1.2, or 1.3).
 * @param[in] version Record-layer version from `tls_context_t.version`.
 * @return 1 if DTLS; 0 for TLS versions.
 */
#if NOXTLS_FEATURE_DTLS
static int tls_is_dtls_version(uint16_t version)
{
    return (version == DTLS_VERSION_1_0 ||
            version == DTLS_VERSION_1_2 ||
            version == DTLS_VERSION_1_3);
}
#endif
/**
 * @brief Open a file.
 *
 * @param[in] filename The filename value.
 * @param[in] mode The mode value.
 * @return The file pointer.
 */
static FILE *noxtls_fopen(const char *filename, const char *mode)
{
#ifdef _MSC_VER
    FILE *fp = NULL;
    if(fopen_s(&fp, filename, mode) != 0) {
        return NULL;
    }
    return fp;
#else
    return fopen(filename, mode);
#endif
}

/**
 * @brief Enable hex dumping of TLS records sent/received to a file (debugging).
 * @param[in] path Append-only log file path, or NULL/empty to disable dumping.
 */
void noxtls_tls_set_record_dump_file(const char *path)
{
    if(tls_record_dump_fp != NULL) {
        fclose(tls_record_dump_fp);
        tls_record_dump_fp = NULL;
    }
    if(path == NULL || *path == '\0') {
        return;
    }
    tls_record_dump_fp = noxtls_fopen(path, "a");
}

/**
 * @brief Append one record dump line when record dumping is enabled.
 * @param[in] direction Label such as "SEND" or "RECV".
 * @param[in] data        Record bytes (header or payload).
 * @param[in] len         Length of @p data.
 */
static void tls_dump_record(const char *direction, const uint8_t *data, uint32_t len)
{
    if(tls_record_dump_fp == NULL || direction == NULL || data == NULL) {
        return;
    }
    fprintf(tls_record_dump_fp, "%s %lu ", direction, (unsigned long)len);
    for(uint32_t i = 0; i < len; i++) {
        fprintf(tls_record_dump_fp, "%02X", data[i]);
    }
    fprintf(tls_record_dump_fp, "\n");
    fflush(tls_record_dump_fp);
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
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    memset(ctx, 0, sizeof(tls_context_t));
    ctx->role = role;
    ctx->version = version;
    ctx->state = TLS_STATE_INIT;
    ctx->io_mode = TLS_IO_MODE_BLOCKING;
    ctx->time_callback = NULL;
    ctx->pending_client_hello = NULL;
    ctx->pending_client_hello_len = 0;
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Release pending handshake buffers and zero a TLS context.
 * @param[in,out] ctx Context to free; safe to call with NULL.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` if @p ctx is NULL.
 */
noxtls_return_t noxtls_tls_context_free(tls_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(ctx->pending_client_hello != NULL) {
        free(ctx->pending_client_hello);
        ctx->pending_client_hello = NULL;
        ctx->pending_client_hello_len = 0;
    }
    if(ctx->pending_server_hello != NULL) {
        free(ctx->pending_server_hello);
        ctx->pending_server_hello = NULL;
        ctx->pending_server_hello_len = 0;
    }

    memset(ctx, 0, sizeof(tls_context_t));

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
    if(ctx == NULL) {
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
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    ctx->time_callback = time_cb;
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
    int32_t sent;
    
    if(ctx == NULL || data == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->send_callback == NULL) {
        return NOXTLS_RETURN_FAILED;  /* No send callback set */
    }
    
    if(len > TLS_MAX_PROTECTED_RECORD_FRAGMENT) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

#if NOXTLS_FEATURE_DTLS
    if(tls_is_dtls_version(ctx->version)) {
        dtls_context_t *dctx = (dtls_context_t*)ctx;
        if(type == TLS_RECORD_HANDSHAKE) {
            uint32_t msg_len;
            if(len < 4) {
                noxtls_return_t rc = noxtls_dtls_send_record(dctx, type, data, len);
                if(rc == NOXTLS_RETURN_SUCCESS) {
                    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_RECORD, NOXSIGHT_SEVERITY_TRACE,
                                    NOXTLS_EVT_RECORD_TX, type, len);
                }
                return rc;
            }
            msg_len = ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
            if(msg_len + 4U == len &&
               data[0] >= TLS_HANDSHAKE_CLIENT_HELLO &&
               data[0] <= TLS_HANDSHAKE_FINISHED) {
                noxtls_return_t rc = dtls_send_handshake_fragment(dctx, data[0],
                                                                 data + 4, msg_len,
                                                                 dctx->send_message_seq);
                if(rc == NOXTLS_RETURN_SUCCESS) {
                    dctx->send_message_seq++;
                    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_RECORD, NOXSIGHT_SEVERITY_TRACE,
                                    NOXTLS_EVT_RECORD_TX, type, len);
                }
                return rc;
            }
            {
                noxtls_return_t rc = noxtls_dtls_send_record(dctx, type, data, len);
                if(rc == NOXTLS_RETURN_SUCCESS) {
                    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_RECORD, NOXSIGHT_SEVERITY_TRACE,
                                    NOXTLS_EVT_RECORD_TX, type, len);
                }
                return rc;
            }
        }
        {
            noxtls_return_t rc = noxtls_dtls_send_record(dctx, type, data, len);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_RECORD, NOXSIGHT_SEVERITY_TRACE,
                                NOXTLS_EVT_RECORD_TX, type, len);
            }
            return rc;
        }
    }
#endif /* NOXTLS_FEATURE_DTLS */
    
    record = ctx->record_send_buf;
    if(record == NULL) {
        record = (uint8_t*)noxtls_malloc(5U + TLS_MAX_PROTECTED_RECORD_FRAGMENT);
        if(record == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    
    /* Build TLS record header */
    tls_record_header_t header;
    header.type = type;
    header.version[0] = (uint8_t)((ctx->version >> 8) & 0xFF);
    header.version[1] = (uint8_t)(ctx->version & 0xFF);
    header.length[0] = (uint8_t)((len >> 8) & 0xFF);
    header.length[1] = (uint8_t)(len & 0xFF);
    memcpy(record, &header, sizeof(header));
    
    /* Copy record data */
    if(len > 0) {
        memcpy(record + 5, data, len);
    }

    if(type == TLS_RECORD_HANDSHAKE && len >= 4 && data[0] == TLS_HANDSHAKE_CLIENT_HELLO) {
        noxtls_sha_ctx_t sha_ctx;
        uint8_t digest[32];
        noxtls_sha256_init(&sha_ctx, NOXTLS_HASH_SHA_256);
        noxtls_sha256_update(&sha_ctx, (uint8_t*)data, len);
        if(noxtls_sha256_finish(&sha_ctx, digest) == NOXTLS_RETURN_SUCCESS) {
            noxtls_debug_printf("[TLS13_DEBUG] sent_client_hello_sha256=");
            for(uint32_t i = 0; i < 32; i++) {
                noxtls_debug_printf("%02X", digest[i]);
            }
            noxtls_debug_printf("\n");
        }
        noxtls_debug_printf("[TLS13_DEBUG] sent_client_hello head=%02X%02X%02X%02X tail=%02X%02X%02X%02X\n",
                              data[0], data[1], data[2], data[3],
                              data[len - 4], data[len - 3], data[len - 2], data[len - 1]);
    }
    
    tls_dump_record("SEND", record, 5 + len);

    /* Send via callback */
    sent = ctx->send_callback(ctx->user_data, record, 5 + len);
    if(sent < 0 || (uint32_t)sent != (5 + len)) {
        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_IO, NOXSIGHT_SEVERITY_ERROR,
                        NOXTLS_EVT_INTERNAL_ERROR, (uint32_t)type, (uint32_t)sent);
        if(record != ctx->record_send_buf) {
            noxtls_free(record);
        }
        return NOXTLS_RETURN_FAILED;
    }
    if(record != ctx->record_send_buf) {
        noxtls_free(record);
    }

    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_RECORD, NOXSIGHT_SEVERITY_TRACE,
                    NOXTLS_EVT_RECORD_TX, type, len);
    
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
    int32_t received;
    uint16_t length;
    
    if(ctx == NULL || record == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->recv_callback == NULL) {
        return NOXTLS_RETURN_FAILED;  /* No receive callback set */
    }
    
    memset(record, 0, sizeof(tls_record_t));

#if NOXTLS_FEATURE_DTLS
    if(tls_is_dtls_version(ctx->version)) {
        dtls_context_t *dctx = (dtls_context_t*)ctx;

        while(1) {
            dtls_record_t drec;
            noxtls_return_t rc = noxtls_dtls_recv_record(dctx, &drec);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }

            if(drec.type != TLS_RECORD_HANDSHAKE) {
                record->type = drec.type;
                record->version = drec.version;
                record->length = drec.length;
                record->data = drec.data;
                NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_RECORD, NOXSIGHT_SEVERITY_TRACE,
                                NOXTLS_EVT_RECORD_RX, record->type, record->length);
                if(record->type == TLS_RECORD_ALERT && record->length >= 2 && record->data != NULL) {
                    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_ALERT, NOXSIGHT_SEVERITY_WARN,
                                    NOXTLS_EVT_ALERT_RECV, record->data[0], record->data[1]);
                }
                return NOXTLS_RETURN_SUCCESS;
            }

            if(drec.length < DTLS_HANDSHAKE_HEADER_SIZE) {
                if(drec.data) {
                    noxtls_free(drec.data);
                }
                return NOXTLS_RETURN_FAILED;
            }

            dtls_handshake_fragment_t fragment;
            uint8_t *complete_msg = NULL;
            uint32_t complete_len = 0;
            uint32_t fragment_len;
            int valid_fragment = 1;

            fragment.msg_type = drec.data[DTLS_HANDSHAKE_TYPE_OFFSET];
            fragment.length = (uint32_t)((drec.data[DTLS_HANDSHAKE_LENGTH_OFFSET] << 16) |
                                         (drec.data[DTLS_HANDSHAKE_LENGTH_OFFSET + 1] << 8) |
                                         drec.data[DTLS_HANDSHAKE_LENGTH_OFFSET + 2]);
            fragment.message_seq = (uint16_t)((drec.data[DTLS_HANDSHAKE_MESSAGE_SEQ_OFFSET] << 8) |
                                              drec.data[DTLS_HANDSHAKE_MESSAGE_SEQ_OFFSET + 1]);
            fragment.fragment_offset = (uint32_t)((drec.data[DTLS_HANDSHAKE_FRAGMENT_OFFSET] << 16) |
                                                  (drec.data[DTLS_HANDSHAKE_FRAGMENT_OFFSET + 1] << 8) |
                                                  drec.data[DTLS_HANDSHAKE_FRAGMENT_OFFSET + 2]);
            fragment.fragment_length = (uint32_t)((drec.data[DTLS_HANDSHAKE_FRAGMENT_LEN_OFFSET] << 16) |
                                                  (drec.data[DTLS_HANDSHAKE_FRAGMENT_LEN_OFFSET + 1] << 8) |
                                                  drec.data[DTLS_HANDSHAKE_FRAGMENT_LEN_OFFSET + 2]);
            fragment_len = fragment.fragment_length;
            if(fragment.msg_type < TLS_HANDSHAKE_CLIENT_HELLO ||
               fragment.msg_type > TLS_HANDSHAKE_FINISHED) {
                valid_fragment = 0;
            }
            if(fragment.length == 0 ||
               fragment.fragment_length > fragment.length ||
               fragment.fragment_offset + fragment.fragment_length > fragment.length) {
                valid_fragment = 0;
            }
            if(fragment_len > ((uint32_t)drec.length - DTLS_HANDSHAKE_HEADER_SIZE) ||
               (DTLS_HANDSHAKE_HEADER_SIZE + fragment_len) != (uint32_t)drec.length) {
                valid_fragment = 0;
            }
            if(!valid_fragment) {
                record->type = drec.type;
                record->version = drec.version;
                record->length = drec.length;
                record->data = drec.data;
                dctx->flight_buffer_len = 0;
                return NOXTLS_RETURN_SUCCESS;
            }
            fragment.data = drec.data + DTLS_HANDSHAKE_BODY_OFFSET;

            rc = noxtls_dtls_reassemble_handshake(dctx, &fragment, &complete_msg, &complete_len);
            noxtls_free(drec.data);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            if(complete_msg == NULL) {
                continue;
            }

            record->type = TLS_RECORD_HANDSHAKE;
            record->version = ctx->version;
            record->length = complete_len + 4U;
            record->data = (uint8_t*)noxtls_malloc((size_t)record->length);
            if(record->data == NULL) {
                noxtls_free(complete_msg);
                return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
            }
            record->data[0] = fragment.msg_type;
            record->data[1] = (uint8_t)((complete_len >> 16) & 0xFF);
            record->data[2] = (uint8_t)((complete_len >> 8) & 0xFF);
            record->data[3] = (uint8_t)(complete_len & 0xFF);
            memcpy(record->data + 4, complete_msg, complete_len);
            noxtls_free(complete_msg);

            dctx->flight_buffer_len = 0;
            NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_RECORD, NOXSIGHT_SEVERITY_TRACE,
                            NOXTLS_EVT_RECORD_RX, record->type, record->length);
            return NOXTLS_RETURN_SUCCESS;
        }
    }
#endif /* NOXTLS_FEATURE_DTLS */
    
    /* Receive record header (5 bytes) */
    noxtls_debug_printf("[TLS_DEBUG] tls_recv_record: Attempting to read 5-byte header...\n");
    received = ctx->recv_callback(ctx->user_data, header, 5);
    noxtls_debug_printf("[TLS_DEBUG] tls_recv_record: Received %d bytes for header\n", received);
    if(received < 5) {
        noxtls_debug_printf("[TLS_DEBUG] tls_recv_record: Failed to receive full header (got %d/5 bytes)\n", received);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Parse record header */
    memcpy(&parsed_header, header, sizeof(parsed_header));
    record->type = parsed_header.type;
    record->version = (uint16_t)((parsed_header.version[0] << 8) | parsed_header.version[1]);
    length = (uint16_t)((parsed_header.length[0] << 8) | parsed_header.length[1]);
    noxtls_debug_printf("[TLS_DEBUG] tls_recv_record: Header parsed - type=%u, version=0x%04x, length=%u\n", 
                          record->type, record->version, length);
    
#if NOXTLS_TLS_MAX_WIRE_RECORD_LENGTH < 65535U
    if(length > TLS_MAX_WIRE_RECORD_LENGTH) {
        noxtls_debug_printf("[TLS_DEBUG] tls_recv_record: Record length %u exceeds max wire %u\n", length, TLS_MAX_WIRE_RECORD_LENGTH);
        return NOXTLS_RETURN_INVALID_PARAM;
    }
#endif

    if(record->type != TLS_RECORD_CHANGE_CIPHER_SPEC &&
       record->type != TLS_RECORD_ALERT &&
       record->type != TLS_RECORD_HANDSHAKE &&
       record->type != TLS_RECORD_APPLICATION_DATA &&
       record->type != TLS_RECORD_HEARTBEAT) {
        noxtls_debug_printf("[TLS_DEBUG] tls_recv_record: Invalid record type %u (draining %u bytes)\n",
                            (unsigned)record->type, (unsigned)length);
        /* Read full payload so the byte stream stays aligned; upper layer sends fatal unexpected_message. */
        if(length > 0) {
            uint8_t *drain = (uint8_t*)noxtls_malloc(length);
            if(drain == NULL) {
                return NOXTLS_RETURN_FAILED;
            }
            received = ctx->recv_callback(ctx->user_data, drain, length);
            noxtls_free(drain);
            if(received < 0 || (uint32_t)received != length) {
                return NOXTLS_RETURN_FAILED;
            }
        }
        /* Payload consumed; report unsupported type to handshake layer (fatal unexpected_message). */
        memset(record, 0, sizeof(tls_record_t));
        record->type = parsed_header.type;
        record->version = (uint16_t)((parsed_header.version[0] << 8) | parsed_header.version[1]);
        record->length = 0;
        record->data = NULL;
        return NOXTLS_RETURN_SUCCESS;
    }
    
    /* Allocate and receive record data */
    if(length > 0) {
        noxtls_debug_printf("[TLS_DEBUG] tls_recv_record: Allocating %u bytes for record data...\n", length);
        record->data = (uint8_t*)noxtls_malloc(length);
        if(record->data == NULL) {
            noxtls_debug_printf("[TLS_DEBUG] tls_recv_record: Memory allocation failed\n");
            return NOXTLS_RETURN_FAILED;
        }
        
        noxtls_debug_printf("[TLS_DEBUG] tls_recv_record: Attempting to read %u bytes of record data...\n", length);
        received = ctx->recv_callback(ctx->user_data, record->data, length);
        noxtls_debug_printf("[TLS_DEBUG] tls_recv_record: Received %d bytes of record data\n", received);
        if(received < 0 || (uint32_t)received != length) {
            noxtls_debug_printf("[TLS_DEBUG] tls_recv_record: Failed to receive full record data (got %d/%u bytes)\n", received, length);
            noxtls_free(record->data);
            record->data = NULL;
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_debug_printf("[TLS_DEBUG] tls_recv_record: Successfully received complete record (%u bytes)\n", length);
        if(record->type == TLS_RECORD_ALERT && length >= 2) {
            uint8_t alert_level = record->data[0];
            uint8_t alert_desc = record->data[1];
            const char *level_str = (alert_level == 1) ? "warning" :
                                    (alert_level == 2) ? "fatal" : "unknown";
            const char *desc_str = "unknown";
            switch(alert_desc) {
                case 0: desc_str = "close_notify"; break;
                case 10: desc_str = "unexpected_message"; break;
                case 20: desc_str = "bad_record_mac"; break;
                case 21: desc_str = "decryption_failed"; break;
                case 22: desc_str = "record_overflow"; break;
                case 40: desc_str = "handshake_failure"; break;
                case 42: desc_str = "bad_certificate"; break;
                case 43: desc_str = "unsupported_certificate"; break;
                case 44: desc_str = "certificate_revoked"; break;
                case 45: desc_str = "certificate_expired"; break;
                case 46: desc_str = "certificate_unknown"; break;
                case 47: desc_str = "illegal_parameter"; break;
                case 48: desc_str = "unknown_ca"; break;
                case 49: desc_str = "access_denied"; break;
                case 50: desc_str = "decode_error"; break;
                case 51: desc_str = "decrypt_error"; break;
                case 52: desc_str = "too_many_cids_requested"; break;
                case 70: desc_str = "protocol_version"; break;
                case 71: desc_str = "insufficient_security"; break;
                case 80: desc_str = "internal_error"; break;
                case 86: desc_str = "inappropriate_fallback"; break;
                case 90: desc_str = "user_canceled"; break;
                case 109: desc_str = "missing_extension"; break;
                case 110: desc_str = "unsupported_extension"; break;
                case 112: desc_str = "unrecognized_name"; break;
                case 120: desc_str = "no_application_protocol"; break;
                default: break;
            }
            noxtls_debug_printf("[TLS_DEBUG] tls_recv_record: Alert level=%u (%s) desc=%u (%s)\n",
                                  alert_level, level_str, alert_desc, desc_str);
        }
    }

    {
        uint8_t dump_buf[5];
        dump_buf[0] = record->type;
        dump_buf[1] = (record->version >> 8) & 0xFF;
        dump_buf[2] = record->version & 0xFF;
        dump_buf[3] = (length >> 8) & 0xFF;
        dump_buf[4] = length & 0xFF;
        tls_dump_record("RECV", dump_buf, 5);
        if(record->data && length > 0) {
            tls_dump_record("RECV", record->data, length);
        }
    }
    
    record->length = length;
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_RECORD, NOXSIGHT_SEVERITY_TRACE,
                    NOXTLS_EVT_RECORD_RX, record->type, record->length);
    if(record->type == TLS_RECORD_ALERT && record->length >= 2 && record->data != NULL) {
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
    
    if(ctx == NULL) {
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
    noxtls_return_t rc;
    uint32_t offset;
    uint32_t client_hello_total_len;
    uint32_t assembled_len;
    uint16_t version;
    uint8_t session_id_len;
    uint16_t cipher_suites_len;
    uint8_t compression_methods_len;
    uint8_t has_supported_versions_ext = 0;
    uint8_t has_tls13 = 0;
    uint8_t has_tls12 = 0;
    
    if(base_ctx == NULL || detected_version == NULL || 
       client_hello_data == NULL || client_hello_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(base_ctx->recv_callback == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    *client_hello_data = NULL;
    *client_hello_len = 0;
    *detected_version = TLS_VERSION_1_2;  /* Default to TLS 1.2 */
    
    /* Receive Client Hello record */
    rc = noxtls_tls_recv_record(base_ctx, &record);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(record.length > 0 && record.data == NULL) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    if(record.type != TLS_RECORD_HANDSHAKE) {
        noxtls_free(record.data);
        return NOXTLS_RETURN_TLS_ERROR;
    }
    if(record.length < 1U) {
        noxtls_free(record.data);
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    if(record.data[0] != TLS_HANDSHAKE_CLIENT_HELLO) {
        noxtls_free(record.data);
        return NOXTLS_RETURN_TLS_ERROR;
    }

    assembled_len = (uint32_t)record.length;
    /* Handshake length needs 4 bytes; ClientHello may be split with a tiny first record (tlsfuzzer). */
    while(assembled_len < 4U) {
        uint8_t *new_buf;
        rc = noxtls_tls_recv_record(base_ctx, &next_record);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_free(record.data);
            return rc;
        }
        if(next_record.length > 0U && next_record.data == NULL) {
            noxtls_free(record.data);
            return NOXTLS_RETURN_BAD_DATA;
        }
        if(next_record.type != TLS_RECORD_HANDSHAKE) {
            if(next_record.data) {
                noxtls_free(next_record.data);
            }
            noxtls_free(record.data);
            return NOXTLS_RETURN_TLS_ERROR;
        }
        if(next_record.length > UINT32_MAX - assembled_len) {
            if(next_record.data) {
                noxtls_free(next_record.data);
            }
            noxtls_free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        new_buf = (uint8_t*)noxtls_realloc(record.data, assembled_len + (uint32_t)next_record.length);
        if(new_buf == NULL) {
            if(next_record.data) {
                noxtls_free(next_record.data);
            }
            noxtls_free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        record.data = new_buf;
        if(next_record.length > 0U && next_record.data != NULL) {
            memcpy(record.data + assembled_len, next_record.data, next_record.length);
        }
        assembled_len += (uint32_t)next_record.length;
        if(next_record.data) {
            noxtls_free(next_record.data);
        }
    }

    client_hello_total_len = 4U + (((uint32_t)record.data[1] << 16) |
                                   ((uint32_t)record.data[2] << 8) |
                                   (uint32_t)record.data[3]);
    if(client_hello_total_len > TLS_MAX_CLIENT_HELLO_BYTES || client_hello_total_len < 38U) {
        noxtls_free(record.data);
        return NOXTLS_RETURN_BAD_DATA;
    }
    while(assembled_len < client_hello_total_len) {
        uint8_t *new_buf;
        rc = noxtls_tls_recv_record(base_ctx, &next_record);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_free(record.data);
            return rc;
        }
        if(next_record.length > 0 && next_record.data == NULL) {
            noxtls_free(record.data);
            return NOXTLS_RETURN_BAD_DATA;
        }
        if(next_record.type != TLS_RECORD_HANDSHAKE) {
            if(next_record.data) noxtls_free(next_record.data);
            noxtls_free(record.data);
            return NOXTLS_RETURN_TLS_ERROR;
        }
        new_buf = (uint8_t*)noxtls_realloc(record.data, assembled_len + (uint32_t)next_record.length);
        if(new_buf == NULL) {
            if(next_record.data) noxtls_free(next_record.data);
            noxtls_free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        record.data = new_buf;
        if(next_record.length > 0 && next_record.data != NULL) {
            memcpy(record.data + assembled_len, next_record.data, next_record.length);
        }
        assembled_len += (uint32_t)next_record.length;
        if(next_record.data) noxtls_free(next_record.data);
    }

    if(assembled_len != client_hello_total_len || assembled_len < 38U) {
        noxtls_free(record.data);
        return NOXTLS_RETURN_BAD_DATA;
    }
    /* A fragmented ClientHello can legitimately exceed a single record payload. */
    record.length = assembled_len;
    
    /* Store Client Hello data for later use */
    *client_hello_data = record.data;
    *client_hello_len = assembled_len;
    
    offset = 4;  /* Skip handshake header */
    
    /* Legacy version */
    version = (record.data[offset] << 8) | record.data[offset + 1];
    offset += 2;
    
    /* Client Random (32 bytes) */
    offset += 32;
    
    /* Session ID length */
    if(offset + 1 > record.length) {
        noxtls_free(*client_hello_data);
        *client_hello_data = NULL;
        *client_hello_len = 0;
        return NOXTLS_RETURN_BAD_DATA;
    }
    session_id_len = record.data[offset++];
    if(offset + session_id_len > record.length) {
        noxtls_free(*client_hello_data);
        *client_hello_data = NULL;
        *client_hello_len = 0;
        return NOXTLS_RETURN_BAD_DATA;
    }
    offset += session_id_len;
    
    /* Cipher suites length */
    if(offset + 2 > record.length) {
        noxtls_free(*client_hello_data);
        *client_hello_data = NULL;
        *client_hello_len = 0;
        return NOXTLS_RETURN_BAD_DATA;
    }
    cipher_suites_len = (record.data[offset] << 8) | record.data[offset + 1];
    offset += 2;
    if(cipher_suites_len == 0U ||
       (cipher_suites_len & 1U) != 0U ||
       offset + cipher_suites_len > record.length) {
        noxtls_free(*client_hello_data);
        *client_hello_data = NULL;
        *client_hello_len = 0;
        return NOXTLS_RETURN_BAD_DATA;
    }
    offset += cipher_suites_len;
    
    /* Compression methods length */
    if(offset + 1 > record.length) {
        noxtls_free(*client_hello_data);
        *client_hello_data = NULL;
        *client_hello_len = 0;
        return NOXTLS_RETURN_BAD_DATA;
    }
    compression_methods_len = record.data[offset++];
    if(compression_methods_len == 0U || offset + compression_methods_len > record.length) {
        noxtls_free(*client_hello_data);
        *client_hello_data = NULL;
        *client_hello_len = 0;
        return NOXTLS_RETURN_BAD_DATA;
    }
    {
        uint32_t ci;
        int have_null = 0;
        for(ci = 0; ci < (uint32_t)compression_methods_len; ci++) {
            if(record.data[offset + ci] == 0U) {
                have_null = 1;
                break;
            }
        }
        if(!have_null) {
            noxtls_free(*client_hello_data);
            *client_hello_data = NULL;
            *client_hello_len = 0;
            return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
        }
    }
    offset += compression_methods_len;
    
    /* No extension block: low legacy ClientHello versions are treated as TLS 1.2
     * (common for compatibility probes and tlsfuzzer downgrade checks). */
    if(offset >= record.length) {
        if(version == TLS_VERSION_1_0 || version == TLS_VERSION_1_1) {
            *detected_version = TLS_VERSION_1_2;
        } else if(version >= TLS_VERSION_1_2) {
            *detected_version = TLS_VERSION_1_2;
        } else {
            noxtls_free(*client_hello_data);
            *client_hello_data = NULL;
            *client_hello_len = 0;
            return NOXTLS_RETURN_BAD_DATA;
        }
        return NOXTLS_RETURN_SUCCESS;
    }
    
    /* Check if extensions are present */
    {
        uint32_t extensions_end;
        if(offset + 2 > record.length) {
            noxtls_free(*client_hello_data);
            *client_hello_data = NULL;
            *client_hello_len = 0;
            return NOXTLS_RETURN_BAD_DATA;
        }
        uint16_t extensions_len = (record.data[offset] << 8) | record.data[offset + 1];
        offset += 2;
        uint32_t extensions_start = offset;
        if(extensions_len > record.length - offset) {
            noxtls_free(*client_hello_data);
            *client_hello_data = NULL;
            *client_hello_len = 0;
            return NOXTLS_RETURN_BAD_DATA;
        }
        extensions_end = extensions_start + extensions_len;
        
        /* Parse extensions to find Supported Versions (type 43) */
        while(offset < extensions_end && offset + 4 <= extensions_end && offset + 4 <= record.length) {
            uint16_t ext_type = (record.data[offset] << 8) | record.data[offset + 1];
            offset += 2;
            uint16_t ext_len = (record.data[offset] << 8) | record.data[offset + 1];
            offset += 2;
            if(ext_len > extensions_end - offset) {
                noxtls_free(*client_hello_data);
                *client_hello_data = NULL;
                *client_hello_len = 0;
                return NOXTLS_RETURN_BAD_DATA;
            }
            uint32_t ext_data_end = offset + ext_len;
            
            if(ext_type == TLS_EXTENSION_SUPPORTED_VERSIONS) {
                /* RFC 8446: server must select from client's supported_versions list. */
                has_supported_versions_ext = 1;
                if(ext_len >= 3 && offset < ext_data_end) {
                    uint8_t versions_len = record.data[offset];
                    uint32_t ver_offset = offset + 1;
                    uint32_t versions_end = ver_offset + versions_len;
                    if(versions_len >= 2 &&
                       (versions_len % 2) == 0 &&
                       versions_len <= ext_len - 1 &&
                       versions_end <= ext_data_end) {
                        while(ver_offset + 1 < versions_end) {
                            uint16_t supported_version = (record.data[ver_offset] << 8) | record.data[ver_offset + 1];
                            if(supported_version == TLS_VERSION_1_3) {
                                has_tls13 = 1;
                            } else if(supported_version == TLS_VERSION_1_2) {
                                has_tls12 = 1;
                            }
                            ver_offset += 2;
                        }
                    }
                }
                offset = ext_data_end;
                break;  /* Found the extension, no need to continue */
            } else {
                /* Skip this extension */
                offset += ext_len;
            }
        }
        if(extensions_end != record.length) {
            noxtls_free(*client_hello_data);
            *client_hello_data = NULL;
            *client_hello_len = 0;
            return NOXTLS_RETURN_BAD_DATA;
        }
        if(!has_supported_versions_ext && offset != extensions_end) {
            noxtls_free(*client_hello_data);
            *client_hello_data = NULL;
            *client_hello_len = 0;
            return NOXTLS_RETURN_BAD_DATA;
        }
    }
    
    /* Determine version */
    if(has_supported_versions_ext) {
        if(has_tls13) {
            *detected_version = TLS_VERSION_1_3;
        } else if(has_tls12) {
            *detected_version = TLS_VERSION_1_2;
        } else if(version == TLS_VERSION_1_1 || version == TLS_VERSION_1_0) {
            /* Client sent supported_versions but without TLS 1.2/1.3 entries we recognize (e.g. draft-only);
             * fall back to legacy ClientHello.version for TLS 1.0/1.1 interop (tlsfuzzer EMS TLSv1.1). */
            *detected_version = version;
        } else {
            /* supported_versions present but no overlap with server policy. */
            noxtls_free(*client_hello_data);
            *client_hello_data = NULL;
            *client_hello_len = 0;
            return NOXTLS_RETURN_NOT_SUPPORTED;
        }
    } else if(version >= TLS_VERSION_1_2) {
        *detected_version = TLS_VERSION_1_2;
    } else if(version == TLS_VERSION_1_1) {
        *detected_version = TLS_VERSION_1_1;
    } else if(version == TLS_VERSION_1_0) {
        *detected_version = TLS_VERSION_1_0;
    } else {
        noxtls_free(*client_hello_data);
        *client_hello_data = NULL;
        *client_hello_len = 0;
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
    uint32_t offset;
    uint8_t session_id_len;
    uint16_t cipher_suites_len;
    uint8_t compression_methods_len;

    if(client_hello == NULL || client_hello_len < 38U) {
        return 0;
    }
    if(client_hello[0] != TLS_HANDSHAKE_CLIENT_HELLO) {
        return 0;
    }

    offset = 4U;
    offset += 2U; /* legacy version */

    offset += 32U; /* random */

    if(offset + 1U > client_hello_len) {
        return 0;
    }
    session_id_len = client_hello[offset++];
    if(offset + (uint32_t)session_id_len > client_hello_len) {
        return 0;
    }
    offset += (uint32_t)session_id_len;

    if(offset + 2U > client_hello_len) {
        return 0;
    }
    cipher_suites_len = (uint16_t)(((uint16_t)client_hello[offset] << 8) | (uint16_t)client_hello[offset + 1]);
    offset += 2U;
    if(offset + (uint32_t)cipher_suites_len > client_hello_len) {
        return 0;
    }
    offset += (uint32_t)cipher_suites_len;

    if(offset + 1U > client_hello_len) {
        return 0;
    }
    compression_methods_len = client_hello[offset++];
    if(offset + (uint32_t)compression_methods_len > client_hello_len) {
        return 0;
    }
    offset += (uint32_t)compression_methods_len;

    if(offset + 2U > client_hello_len) {
        return 0;
    }
    {
        uint16_t extensions_len = (uint16_t)(((uint16_t)client_hello[offset] << 8) | (uint16_t)client_hello[offset + 1]);
        uint32_t extensions_end;
        offset += 2U;
        if((uint32_t)extensions_len > client_hello_len - offset) {
            return 0;
        }
        extensions_end = offset + (uint32_t)extensions_len;

        while(offset + 4U <= extensions_end && offset + 4U <= client_hello_len) {
            uint16_t ext_type = (uint16_t)(((uint16_t)client_hello[offset] << 8) | (uint16_t)client_hello[offset + 1]);
            offset += 2U;
            uint16_t ext_len = (uint16_t)(((uint16_t)client_hello[offset] << 8) | (uint16_t)client_hello[offset + 1]);
            offset += 2U;
            if((uint32_t)ext_len > extensions_end - offset) {
                return 0;
            }
            if(ext_type == TLS_EXTENSION_SUPPORTED_VERSIONS) {
                uint32_t ext_data_end = offset + (uint32_t)ext_len;
                if(ext_len >= 3U && offset < ext_data_end) {
                    uint8_t versions_len = client_hello[offset];
                    uint32_t ver_offset = offset + 1U;
                    uint32_t versions_end = ver_offset + (uint32_t)versions_len;
                    if(versions_len >= 2U &&
                       (versions_len % 2U) == 0U &&
                       versions_len <= ext_len - 1U &&
                       versions_end <= ext_data_end) {
                        while(ver_offset + 1U < versions_end) {
                            uint16_t supported_version = (uint16_t)(((uint16_t)client_hello[ver_offset] << 8) |
                                                                    (uint16_t)client_hello[ver_offset + 1]);
                            if(supported_version == version) {
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
noxtls_return_t noxtls_tls_verify_certificate_signature(void *cert, void *issuer)
{
    if(cert == NULL || issuer == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Call the X.509 certificate verification function */
    return noxtls_x509_certificate_verify_signature((x509_certificate_t*)cert, (x509_certificate_t*)issuer);
}
