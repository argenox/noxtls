/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
*
* NOTICE:  All information contained herein, source code, binaries and
* derived works is, and remains
* the property of Argenox Technologies and its suppliers,
* if any.  The intellectual and technical concepts contained
* herein are proprietary to Argenox Technologies
* and its suppliers may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Argenox Technologies.
*
* THIS SOFTWARE IS PROVIDED BY ARGENOX "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL ARGENOX TECHNOLOGIES LLC BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
* CONTACT: info@argenox.com
* 
*
* File:    noxtls_tls_common.c
* Summary: TLS Common Implementation
*
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_tls_common.h"
#include "noxtls_dtls_common.h"
#include "noxtls_tls_noxsight.h"
#include "certs/noxtls_x509.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/noxtls_hash.h"

static FILE *tls_record_dump_fp = NULL;

static int tls_is_dtls_version(uint16_t version)
{
    return (version == DTLS_VERSION_1_0 ||
            version == DTLS_VERSION_1_2 ||
            version == DTLS_VERSION_1_3);
}

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
 * @brief Initialize TLS context
 */
noxtls_return_t noxtls_tls_context_init(tls_context_t *ctx, tls_role_t role, uint16_t version)
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
 * @brief Free TLS context
 */
noxtls_return_t noxtls_tls_context_free(tls_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    memset(ctx, 0, sizeof(tls_context_t));
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Set I/O callback functions
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

noxtls_return_t noxtls_tls_set_time_callback(tls_context_t *ctx, tls_time_callback_t time_cb)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    ctx->time_callback = time_cb;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Send TLS record
 * 
 * This function uses the send_callback to transmit data over the network.
 * Applications must provide the send_callback implementation.
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
    
    if(len > TLS_MAX_RECORD_SIZE) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if(tls_is_dtls_version(ctx->version)) {
        dtls_context_t *dctx = (dtls_context_t*)ctx;
        if(type == TLS_RECORD_HANDSHAKE) {
            uint32_t msg_len;
            if(len < 4) {
                noxtls_return_t rc = dtls_send_record(dctx, type, data, len);
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
                noxtls_return_t rc = dtls_send_record(dctx, type, data, len);
                if(rc == NOXTLS_RETURN_SUCCESS) {
                    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_RECORD, NOXSIGHT_SEVERITY_TRACE,
                                    NOXTLS_EVT_RECORD_TX, type, len);
                }
                return rc;
            }
        }
        {
            noxtls_return_t rc = dtls_send_record(dctx, type, data, len);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_RECORD, NOXSIGHT_SEVERITY_TRACE,
                                NOXTLS_EVT_RECORD_TX, type, len);
            }
            return rc;
        }
    }
    
    record = ctx->record_send_buf;
    if(record == NULL) {
        record = (uint8_t*)noxtls_malloc(5 + TLS_MAX_RECORD_SIZE);
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
 * @brief Receive TLS record
 * 
 * This function uses the recv_callback to receive data from the network.
 * Applications must provide the recv_callback implementation.
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

    if(tls_is_dtls_version(ctx->version)) {
        dtls_context_t *dctx = (dtls_context_t*)ctx;
        noxtls_return_t rc;

        while(1) {
            dtls_record_t drec;
            rc = dtls_recv_record(dctx, &drec);
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
            fragment.fragment_seq = (uint16_t)((drec.data[DTLS_HANDSHAKE_FRAGMENT_SEQ_OFFSET] << 8) |
                                               drec.data[DTLS_HANDSHAKE_FRAGMENT_SEQ_OFFSET + 1]);
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

            rc = dtls_reassemble_handshake(dctx, &fragment, &complete_msg, &complete_len);
            noxtls_free(drec.data);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            if(complete_msg == NULL) {
                continue;
            }

            record->type = TLS_RECORD_HANDSHAKE;
            record->version = ctx->version;
            record->length = (uint16_t)(complete_len + 4U);
            record->data = (uint8_t*)noxtls_malloc(record->length);
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
    
    if(length > TLS_MAX_RECORD_SIZE) {
        noxtls_debug_printf("[TLS_DEBUG] tls_recv_record: Record length %u exceeds max %u\n", length, TLS_MAX_RECORD_SIZE);
        return NOXTLS_RETURN_INVALID_PARAM;
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
 * @brief Send TLS alert
 */
noxtls_return_t noxtls_tls_send_alert(tls_context_t *ctx, uint8_t level, uint8_t description)
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
 * @brief Detect TLS version from Client Hello
 * 
 * This function receives the Client Hello and determines whether the client
 * is requesting TLS 1.2 or TLS 1.3 by checking:
 * 1. The "Supported Versions" extension (type 43) - if present and contains TLS 1.3, it's TLS 1.3
 * 2. The legacy version field - if TLS 1.2 or higher, default to TLS 1.2
 * 
 * @param base_ctx Base TLS context with I/O callbacks set
 * @param detected_version Output: Detected TLS version (TLS_VERSION_1_2 or TLS_VERSION_1_3)
 * @param client_hello_data Output: Pointer to Client Hello data (caller must free)
 * @param client_hello_len Output: Length of Client Hello data
 * @return NOXTLS_RETURN_SUCCESS on success, error code on failure
 */
noxtls_return_t noxtls_tls_detect_version(tls_context_t *base_ctx, uint16_t *detected_version, 
                                     uint8_t **client_hello_data, uint32_t *client_hello_len)
{
    tls_record_t record;
    noxtls_return_t rc;
    uint32_t offset;
    uint16_t version;
    uint8_t session_id_len;
    uint16_t cipher_suites_len;
    uint8_t compression_methods_len;
    uint8_t has_tls13 = 0;
    
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
        return NOXTLS_RETURN_FAILED;
    }
    
    if(record.type != TLS_RECORD_HANDSHAKE || record.length < 38) {
        noxtls_free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    if(record.data[0] != TLS_HANDSHAKE_CLIENT_HELLO) {
        noxtls_free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Store Client Hello data for later use */
    *client_hello_data = record.data;
    *client_hello_len = record.length;
    
    offset = 4;  /* Skip handshake header */
    if(offset + 2 > record.length) {
        noxtls_free(*client_hello_data);
        *client_hello_data = NULL;
        *client_hello_len = 0;
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Legacy version */
    version = (record.data[offset] << 8) | record.data[offset + 1];
    offset += 2;
    
    /* Check legacy version for TLS 1.0 or TLS 1.1 */
    if(version == TLS_VERSION_1_0) {
        *detected_version = TLS_VERSION_1_0;
        return NOXTLS_RETURN_SUCCESS;  /* TLS 1.0 doesn't support extensions */
    } else if(version == TLS_VERSION_1_1) {
        *detected_version = TLS_VERSION_1_1;
        return NOXTLS_RETURN_SUCCESS;  /* TLS 1.1 doesn't support extensions */
    }
    
    /* Client Random (32 bytes) */
    if(offset + 32 > record.length) {
        noxtls_free(*client_hello_data);
        *client_hello_data = NULL;
        *client_hello_len = 0;
        return NOXTLS_RETURN_FAILED;
    }
    offset += 32;
    
    /* Session ID length */
    if(offset + 1 > record.length) {
        noxtls_free(*client_hello_data);
        *client_hello_data = NULL;
        *client_hello_len = 0;
        return NOXTLS_RETURN_FAILED;
    }
    session_id_len = record.data[offset++];
    if(offset + session_id_len > record.length) {
        noxtls_free(*client_hello_data);
        *client_hello_data = NULL;
        *client_hello_len = 0;
        return NOXTLS_RETURN_FAILED;
    }
    offset += session_id_len;
    
    /* Cipher suites length */
    if(offset + 2 > record.length) {
        noxtls_free(*client_hello_data);
        *client_hello_data = NULL;
        *client_hello_len = 0;
        return NOXTLS_RETURN_FAILED;
    }
    cipher_suites_len = (record.data[offset] << 8) | record.data[offset + 1];
    offset += 2;
    if(offset + cipher_suites_len > record.length) {
        noxtls_free(*client_hello_data);
        *client_hello_data = NULL;
        *client_hello_len = 0;
        return NOXTLS_RETURN_FAILED;
    }
    offset += cipher_suites_len;
    
    /* Compression methods length */
    if(offset + 1 > record.length) {
        noxtls_free(*client_hello_data);
        *client_hello_data = NULL;
        *client_hello_len = 0;
        return NOXTLS_RETURN_FAILED;
    }
    compression_methods_len = record.data[offset++];
    if(offset + compression_methods_len > record.length) {
        noxtls_free(*client_hello_data);
        *client_hello_data = NULL;
        *client_hello_len = 0;
        return NOXTLS_RETURN_FAILED;
    }
    offset += compression_methods_len;
    
    /* Check if extensions are present */
    if(offset < record.length) {
        uint32_t extensions_end;
        uint32_t ext_data_end;
        if(offset + 2 > record.length) {
            noxtls_free(*client_hello_data);
            *client_hello_data = NULL;
            *client_hello_len = 0;
            return NOXTLS_RETURN_FAILED;
        }
        uint16_t extensions_len = (record.data[offset] << 8) | record.data[offset + 1];
        offset += 2;
        uint32_t extensions_start = offset;
        if(extensions_len > record.length - offset) {
            noxtls_free(*client_hello_data);
            *client_hello_data = NULL;
            *client_hello_len = 0;
            return NOXTLS_RETURN_FAILED;
        }
        extensions_end = extensions_start + extensions_len;
        
        /* Parse extensions to find Supported Versions (type 43) */
        while(offset < extensions_end && offset + 4 <= extensions_end && offset + 4 <= record.length) {
            uint16_t ext_type = (record.data[offset] << 8) | record.data[offset + 1];
            offset += 2;
            uint16_t ext_len = (record.data[offset] << 8) | record.data[offset + 1];
            offset += 2;
            if(ext_len > extensions_end - offset) {
                break;
            }
            ext_data_end = offset + ext_len;
            
            if(ext_type == TLS_EXTENSION_SUPPORTED_VERSIONS) {
                /* Supported Versions extension found - check if TLS 1.3 is supported */
                /* Format: length (1 byte) + list of versions (2 bytes each) */
                if(ext_len >= 3 && offset < ext_data_end) {
                    uint8_t versions_len = record.data[offset++];
                    if(versions_len >= 2 && versions_len <= ext_len - 1 &&
                       versions_len <= ext_data_end - offset) {
                        /* Check each version in the list */
                        uint8_t i;
                        for(i = 0; i + 1 < versions_len && offset + 1 < ext_data_end; i += 2) {
                            uint16_t supported_version = (record.data[offset] << 8) | record.data[offset + 1];
                            if(supported_version == TLS_VERSION_1_3) {
                                has_tls13 = 1;
                                break;
                            }
                            offset += 2;
                        }
                    }
                }
                break;  /* Found the extension, no need to continue */
            } else {
                /* Skip this extension */
                offset += ext_len;
            }
        }
    }
    
    /* Determine version */
    if(has_tls13) {
        *detected_version = TLS_VERSION_1_3;
    } else if(version >= TLS_VERSION_1_2) {
        *detected_version = TLS_VERSION_1_2;
    } else {
        /* Unsupported version */
        noxtls_free(*client_hello_data);
        *client_hello_data = NULL;
        *client_hello_len = 0;
        return NOXTLS_RETURN_FAILED;
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS Certificate Signature Verification Wrapper
 * 
 * This is a wrapper around x509_certificate_verify_signature for use in TLS.
 * It verifies that a certificate's signature is valid using the issuer's public key.
 * 
 * @param cert Certificate to verify (x509_certificate_t*)
 * @param issuer Issuer certificate containing the public key (x509_certificate_t*)
 * @return NOXTLS_RETURN_SUCCESS if signature is valid, error code otherwise
 */
noxtls_return_t noxtls_tls_verify_certificate_signature(void *cert, void *issuer)
{
    if(cert == NULL || issuer == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Call the X.509 certificate verification function */
    return noxtls_x509_certificate_verify_signature((x509_certificate_t*)cert, (x509_certificate_t*)issuer);
}

