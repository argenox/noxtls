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
* File:    noxtls_tls13.c
* Summary: TLS 1.3 Implementation
*
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "common/noxtls_debug_printf.h"
#include "common/noxtls_ct.h"
#include "noxtls_tls13.h"
#include "noxtls_tls13_psk.h"
#include "drbg/noxtls_drbg.h"
#include "certs/noxtls_x509.h"
#include "noxtls_tls_kdf.h"
#include "noxtls_tls_key_exchange.h"
#include "noxtls_tls_common.h"
#include "noxtls_tls_noxsight.h"
#include "pkc/rsa/noxtls_rsa.h"
#include "pkc/ecdsa/noxtls_ecdsa.h"
#include "pkc/ecc/noxtls_ecc.h"
#include "pkc/ed25519/noxtls_ed25519.h"
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
#include "pkc/ed448/noxtls_ed448.h"
#endif
#include "mdigest/noxtls_hash.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha512/noxtls_sha512.h"

/* Forward declarations for local helpers used before definition */
static noxtls_return_t tls13_hash_messages(noxtls_hash_algos_t hash_algo,
                                           const uint8_t *messages,
                                           uint32_t messages_len,
                                           uint8_t *out_hash,
                                           uint32_t *out_hash_len);
static noxtls_return_t tls13_send_encrypted_handshake(tls13_context_t *ctx,
                                                      const uint8_t *msg,
                                                      uint32_t msg_len);
static noxtls_return_t tls13_derive_handshake_keys(tls13_context_t *ctx,
                                                   const uint8_t *shared_secret,
                                                   uint32_t shared_secret_len);
static void tls13_write_uint16(uint8_t *buf, uint16_t value)
{
    buf[0] = (uint8_t)((value >> 8) & 0xFF);
    buf[1] = (uint8_t)(value & 0xFF);
}

static void tls13_write_uint48(uint8_t *buf, uint64_t value)
{
    buf[0] = (uint8_t)((value >> 40) & 0xFF);
    buf[1] = (uint8_t)((value >> 32) & 0xFF);
    buf[2] = (uint8_t)((value >> 24) & 0xFF);
    buf[3] = (uint8_t)((value >> 16) & 0xFF);
    buf[4] = (uint8_t)((value >> 8) & 0xFF);
    buf[5] = (uint8_t)(value & 0xFF);
}

static uint16_t tls13_read_uint16(const uint8_t *buf)
{
    return (uint16_t)((buf[0] << 8) | buf[1]);
}

static uint64_t tls13_read_uint48(const uint8_t *buf)
{
    return ((uint64_t)buf[0] << 40) |
           ((uint64_t)buf[1] << 32) |
           ((uint64_t)buf[2] << 24) |
           ((uint64_t)buf[3] << 16) |
           ((uint64_t)buf[4] << 8) |
           (uint64_t)buf[5];
}

static void tls13_dtls_ack_range_add(dtls_context_t *ctx, uint16_t epoch, uint64_t seq)
{
    if(ctx == NULL) {
        return;
    }

    if(ctx->ack_ranges_min == NULL || ctx->ack_ranges_max == NULL || ctx->ack_range_capacity == 0) {
        uint8_t limit = ctx->ack_range_limit == 0 ? DTLS_MAX_ACK_RANGES : ctx->ack_range_limit;
        ctx->ack_range_capacity = limit < 4 ? limit : 4;
        ctx->ack_ranges_min = (uint64_t*)noxtls_malloc(sizeof(uint64_t) * ctx->ack_range_capacity);
        ctx->ack_ranges_max = (uint64_t*)noxtls_malloc(sizeof(uint64_t) * ctx->ack_range_capacity);
        if(ctx->ack_ranges_min == NULL || ctx->ack_ranges_max == NULL) {
            if(ctx->ack_ranges_min != NULL) {
                noxtls_free(ctx->ack_ranges_min);
            }
            if(ctx->ack_ranges_max != NULL) {
                noxtls_free(ctx->ack_ranges_max);
            }
            ctx->ack_ranges_min = NULL;
            ctx->ack_ranges_max = NULL;
            ctx->ack_range_capacity = 0;
            ctx->ack_range_count = 0;
            ctx->ack_range_valid = 0;
            return;
        }
    }

    if(!ctx->ack_pending || !ctx->ack_range_valid || (uint16_t)ctx->ack_epoch != epoch ||
       ctx->ack_range_count == 0) {
        ctx->ack_epoch = epoch;
        ctx->ack_ranges_min[0] = seq;
        ctx->ack_ranges_max[0] = seq;
        ctx->ack_range_count = 1;
        ctx->ack_range_valid = 1;
    } else {
        uint8_t merged = 0;
        for(uint8_t i = 0; i < ctx->ack_range_count; i++) {
            uint64_t minv = ctx->ack_ranges_min[i];
            uint64_t maxv = ctx->ack_ranges_max[i];
            if(seq + 1 >= minv && seq <= maxv + 1) {
                if(seq < minv) {
                    ctx->ack_ranges_min[i] = seq;
                }
                if(seq > maxv) {
                    ctx->ack_ranges_max[i] = seq;
                }
                merged = 1;
                break;
            }
        }
        if(!merged) {
            if(ctx->ack_range_count >= ctx->ack_range_capacity) {
                uint8_t limit = ctx->ack_range_limit == 0 ? DTLS_MAX_ACK_RANGES : ctx->ack_range_limit;
                if(ctx->ack_range_capacity >= limit) {
                    for(uint8_t k = 0; k + 1 < ctx->ack_range_count; k++) {
                        ctx->ack_ranges_min[k] = ctx->ack_ranges_min[k + 1];
                        ctx->ack_ranges_max[k] = ctx->ack_ranges_max[k + 1];
                    }
                    if(ctx->ack_range_count > 0) {
                        ctx->ack_range_count--;
                    }
                } else {
                    uint8_t new_capacity = (uint8_t)(ctx->ack_range_capacity << 1);
                    if(new_capacity > limit) {
                        new_capacity = limit;
                    }
                    {
                        uint64_t *new_min = (uint64_t*)noxtls_realloc(ctx->ack_ranges_min,
                                                                     sizeof(uint64_t) * new_capacity);
                        uint64_t *new_max = (uint64_t*)noxtls_realloc(ctx->ack_ranges_max,
                                                                     sizeof(uint64_t) * new_capacity);
                        if(new_min == NULL || new_max == NULL) {
                            if(new_min != NULL) {
                                noxtls_free(new_min);
                            }
                            if(new_max != NULL) {
                                noxtls_free(new_max);
                            }
                            return;
                        }
                        ctx->ack_ranges_min = new_min;
                        ctx->ack_ranges_max = new_max;
                        ctx->ack_range_capacity = new_capacity;
                    }
                }
            }
            if(ctx->ack_range_count < ctx->ack_range_capacity) {
                uint8_t idx = ctx->ack_range_count;
                ctx->ack_ranges_min[idx] = seq;
                ctx->ack_ranges_max[idx] = seq;
                ctx->ack_range_count++;
                merged = 1;
                (void)merged;
            } else {
                return;
            }
        }

        for(uint8_t i = 0; i < ctx->ack_range_count; i++) {
            for(uint8_t j = i + 1; j < ctx->ack_range_count; ) {
                uint64_t imin = ctx->ack_ranges_min[i];
                uint64_t imax = ctx->ack_ranges_max[i];
                uint64_t jmin = ctx->ack_ranges_min[j];
                uint64_t jmax = ctx->ack_ranges_max[j];
                if(jmin <= imax + 1 && jmax + 1 >= imin) {
                    if(jmin < imin) {
                        ctx->ack_ranges_min[i] = jmin;
                    }
                    if(jmax > imax) {
                        ctx->ack_ranges_max[i] = jmax;
                    }
                    for(uint8_t k = j; k + 1 < ctx->ack_range_count; k++) {
                        ctx->ack_ranges_min[k] = ctx->ack_ranges_min[k + 1];
                        ctx->ack_ranges_max[k] = ctx->ack_ranges_max[k + 1];
                    }
                    ctx->ack_range_count--;
                } else {
                    j++;
                }
            }
        }
    }

    ctx->ack_range_min = ctx->ack_ranges_min[0];
    ctx->ack_range_max = ctx->ack_ranges_max[0];
    for(uint8_t i = 1; i < ctx->ack_range_count; i++) {
        if(ctx->ack_ranges_min[i] < ctx->ack_range_min) {
            ctx->ack_range_min = ctx->ack_ranges_min[i];
        }
        if(ctx->ack_ranges_max[i] > ctx->ack_range_max) {
            ctx->ack_range_max = ctx->ack_ranges_max[i];
        }
    }
    ctx->ack_seq = ctx->ack_range_max;
}

static int tls13_is_dtls(const tls13_context_t *ctx)
{
    return (ctx != NULL && ctx->base.base.version == DTLS_VERSION_1_3);
}

static int tls13_client_has_key_share(const tls13_context_t *ctx, uint16_t group)
{
    if(ctx == NULL) {
        return 0;
    }
    for(uint32_t i = 0; i < ctx->client_key_shares_count; i++) {
        if(ctx->client_key_shares[i].group == group) {
            return 1;
        }
    }
    return 0;
}

static noxtls_return_t tls13_send_hello_retry_request_dtls(tls13_context_t *ctx,
                                                           const uint8_t *cookie,
                                                           uint16_t cookie_len,
                                                           uint16_t selected_group,
                                                           uint8_t *hrr_out,
                                                           uint32_t *hrr_out_len)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    uint8_t *hrr = ctx->handshake_workspace;
    if(hrr == NULL) {
        hrr = (uint8_t*)noxtls_malloc(TLS_HELLO_RETRY_REQUEST_MAX_SIZE);
        if(hrr == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    uint32_t offset = 0;
    static const uint8_t hrr_random[TLS_RANDOM_SIZE] = {
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
    };

    hrr[offset++] = TLS_HANDSHAKE_SERVER_HELLO;
    hrr[offset++] = 0x00;
    hrr[offset++] = 0x00;
    hrr[offset++] = 0x00;
    hrr[offset++] = (DTLS_VERSION_1_2 >> 8) & 0xFF;
    hrr[offset++] = DTLS_VERSION_1_2 & 0xFF;
    memcpy(hrr + offset, hrr_random, sizeof(hrr_random));
    offset += sizeof(hrr_random);
    hrr[offset++] = 0x00; /* legacy session id */
    hrr[offset++] = (ctx->cipher_suite >> 8) & 0xFF;
    hrr[offset++] = ctx->cipher_suite & 0xFF;
    hrr[offset++] = 0x00; /* legacy compression */

    /* Extensions length placeholder */
    uint32_t ext_start = offset;
    hrr[offset++] = 0x00;
    hrr[offset++] = 0x00;

    /* Supported Versions extension */
    hrr[offset++] = (TLS_EXTENSION_SUPPORTED_VERSIONS >> 8) & 0xFF;
    hrr[offset++] = TLS_EXTENSION_SUPPORTED_VERSIONS & 0xFF;
    hrr[offset++] = 0x00;
    hrr[offset++] = 0x02;
    hrr[offset++] = (TLS_VERSION_1_3 >> 8) & 0xFF;
    hrr[offset++] = TLS_VERSION_1_3 & 0xFF;

    if(selected_group != 0) {
        hrr[offset++] = (TLS_EXTENSION_KEY_SHARE >> 8) & 0xFF;
        hrr[offset++] = TLS_EXTENSION_KEY_SHARE & 0xFF;
        hrr[offset++] = 0x00;
        hrr[offset++] = 0x02;
        hrr[offset++] = (selected_group >> 8) & 0xFF;
        hrr[offset++] = selected_group & 0xFF;
    }

    /* Cookie extension */
    if(cookie != NULL && cookie_len > 0) {
        hrr[offset++] = (TLS_EXTENSION_COOKIE >> 8) & 0xFF;
        hrr[offset++] = TLS_EXTENSION_COOKIE & 0xFF;
        hrr[offset++] = (cookie_len >> 8) & 0xFF;
        hrr[offset++] = cookie_len & 0xFF;
        memcpy(hrr + offset, cookie, cookie_len);
        offset += cookie_len;
    }

    uint32_t ext_len = offset - ext_start - 2;
    hrr[ext_start] = (uint8_t)((ext_len >> 8) & 0xFF);
    hrr[ext_start + 1] = (uint8_t)(ext_len & 0xFF);

    uint32_t hs_len = offset - 4;
    hrr[1] = (uint8_t)((hs_len >> 16) & 0xFF);
    hrr[2] = (uint8_t)((hs_len >> 8) & 0xFF);
    hrr[3] = (uint8_t)(hs_len & 0xFF);

    if(hrr_out != NULL && hrr_out_len != NULL) {
        if(*hrr_out_len < offset) {
            if(hrr != ctx->handshake_workspace) NOXTLS_SECURE_FREE(hrr, 256);
            else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            *hrr_out_len = offset;
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(hrr_out, hrr, offset);
        *hrr_out_len = offset;
    }

    noxtls_return_t rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, hrr, offset);
    if(hrr != ctx->handshake_workspace) NOXTLS_SECURE_FREE(hrr, 256);
    else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
    return rc;
}

static noxtls_return_t tls13_reset_transcript_for_hrr(tls13_context_t *ctx,
                                                      noxtls_hash_algos_t hash_algo,
                                                      uint32_t hash_len)
{
    uint8_t hash[TLS_MAX_SECRET_LEN];
    uint32_t out_len = sizeof(hash);
    uint8_t *msg;
    uint32_t msg_len;
    noxtls_return_t rc;

    if(ctx == NULL || ctx->handshake_messages_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    rc = tls13_hash_messages(hash_algo, ctx->handshake_messages, ctx->handshake_messages_len,
                             hash, &out_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(out_len != hash_len) {
        return NOXTLS_RETURN_FAILED;
    }

    msg_len = 4 + out_len;
    msg = (uint8_t*)malloc(msg_len);
    if(msg == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    msg[0] = TLS_HANDSHAKE_MESSAGE_HASH;
    msg[1] = (uint8_t)((out_len >> 16) & 0xFF);
    msg[2] = (uint8_t)((out_len >> 8) & 0xFF);
    msg[3] = (uint8_t)(out_len & 0xFF);
    memcpy(msg + 4, hash, out_len);

    if(ctx->handshake_messages) {
        free(ctx->handshake_messages);
    }
    ctx->handshake_messages = msg;
    ctx->handshake_messages_len = msg_len;

    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t tls13_send_handshake_message(tls13_context_t *ctx, const uint8_t *msg, uint32_t msg_len)
{
    if(ctx == NULL || msg == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->handshake_encrypted) {
        return tls13_send_encrypted_handshake(ctx, msg, msg_len);
    }
    return noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, msg, msg_len);
}

static int tls13_is_ack_message(const uint8_t *msg, uint32_t len)
{
    if(msg == NULL || len == 0) {
        return 0;
    }
    return (msg[0] == TLS_HANDSHAKE_ACK);
}

static void tls13_dtls_handle_ack(tls13_context_t *ctx, const uint8_t *msg, uint32_t len)
{
    uint32_t body_len;
    uint32_t offset = 4;
    uint16_t epoch;
    uint16_t range_count;
    uint64_t min_seq = UINT64_MAX;
    uint64_t max_seq = 0;

    if(ctx == NULL || msg == NULL || len < 8 || msg[0] != TLS_HANDSHAKE_ACK) {
        return;
    }

    body_len = ((uint32_t)msg[1] << 16) | ((uint32_t)msg[2] << 8) | msg[3];
    if(len < body_len + 4) {
        return;
    }

    epoch = tls13_read_uint16(msg + offset);
    offset += 2;
    range_count = tls13_read_uint16(msg + offset);
    offset += 2;
    if(range_count == 0) {
        return;
    }

    for(uint16_t i = 0; i < range_count; i++) {
        uint64_t start;
        uint64_t end;
        if(offset + 12 > len) {
            return;
        }
        start = tls13_read_uint48(msg + offset);
        offset += 6;
        end = tls13_read_uint48(msg + offset);
        offset += 6;
        if(start > end) {
            uint64_t tmp = start;
            start = end;
            end = tmp;
        }
        if(start < min_seq) {
            min_seq = start;
        }
        if(end > max_seq) {
            max_seq = end;
        }
    }

    if(offset + 2 > len) {
        return;
    }

    ctx->base.last_ack_epoch = epoch;
    ctx->base.last_ack_seq = max_seq;
    ctx->base.last_ack_range_min = min_seq;
    ctx->base.last_ack_range_max = max_seq;
    if(ctx->base.flight_has_range &&
       ctx->base.flight_epoch == epoch &&
       min_seq <= ctx->base.flight_min_seq &&
       max_seq >= ctx->base.flight_max_seq) {
        ctx->base.flight_buffer_len = 0;
        ctx->base.flight_has_range = 0;
    }
}

static noxtls_return_t tls13_process_client_key_share_internal(tls13_context_t *ctx)
{
    const tls13_key_share_entry_t *share;
    tls_ecdhe_context_t *ecdhe_ctx;
    ecc_point_t peer_public_key;
    noxtls_return_t rc;

    if(ctx == NULL || ctx->client_key_shares_count == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    share = &ctx->client_key_shares[0];
    ecdhe_ctx = (tls_ecdhe_context_t*)ctx->ecdhe_ctx;
    if(ecdhe_ctx == NULL || ecdhe_ctx->named_group != share->group) {
        if(ecdhe_ctx != NULL) {
            tls_ecdhe_context_free(ecdhe_ctx);
            free(ecdhe_ctx);
        }
        ecdhe_ctx = (tls_ecdhe_context_t*)malloc(sizeof(tls_ecdhe_context_t));
        if(ecdhe_ctx == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        if(tls_ecdhe_context_init(ecdhe_ctx, share->group) != NOXTLS_RETURN_SUCCESS ||
           tls_ecdhe_generate_ephemeral_key(ecdhe_ctx) != NOXTLS_RETURN_SUCCESS) {
            tls_ecdhe_context_free(ecdhe_ctx);
            free(ecdhe_ctx);
            return NOXTLS_RETURN_FAILED;
        }
        ctx->ecdhe_ctx = ecdhe_ctx;
    }

    rc = tls_decode_ecc_point_uncompressed(share->key_exchange, share->key_exchange_len,
                                           &peer_public_key, ecdhe_ctx->curve_type);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tls_ecdhe_compute_shared_secret(ecdhe_ctx, &peer_public_key);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(ecdhe_ctx->shared_secret == NULL || ecdhe_ctx->shared_secret_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    return tls13_derive_handshake_keys(ctx, ecdhe_ctx->shared_secret, ecdhe_ctx->shared_secret_len);
}

static char tls13_keylog_path[512] = {0};

void tls13_set_keylog_file(const char *path)
{
    if(path == NULL || *path == '\0') {
        tls13_keylog_path[0] = '\0';
        return;
    }
    {
        size_t path_len = strlen(path);
        size_t copy_len = path_len < (sizeof(tls13_keylog_path) - 1)
            ? path_len
            : (sizeof(tls13_keylog_path) - 1);
        memcpy(tls13_keylog_path, path, copy_len);
        tls13_keylog_path[copy_len] = '\0';
    }
}

static void tls13_keylog_write(const char *label, const uint8_t *client_random,
                               const uint8_t *secret, uint32_t secret_len)
{
    const char *path = tls13_keylog_path[0] ? tls13_keylog_path : getenv("SSLKEYLOGFILE");
    if(path == NULL || client_random == NULL || secret == NULL) {
        return;
    }

    FILE *fp = fopen(path, "a");
    if(fp == NULL) {
        return;
    }

    fprintf(fp, "%s ", label);
    for(uint32_t i = 0; i < 32; i++) {
        fprintf(fp, "%02X", client_random[i]);
    }
    fprintf(fp, " ");
    for(uint32_t i = 0; i < secret_len; i++) {
        fprintf(fp, "%02X", secret[i]);
    }
    fprintf(fp, "\n");
    fclose(fp);
}

static noxtls_return_t tls13_append_handshake_message(tls13_context_t *ctx, const uint8_t *data, uint32_t len)
{
    if(ctx == NULL || data == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(len >= 4) {
        uint32_t hs_len = ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
        noxtls_debug_printf("[TLS13_DEBUG] append_handshake: type=0x%02X hs_len=%u total_len=%u\n",
                              data[0], hs_len, len);
    } else {
        noxtls_debug_printf("[TLS13_DEBUG] append_handshake: len=%u\n", len);
    }

    if(len > UINT32_MAX - ctx->handshake_messages_len) {
        return NOXTLS_RETURN_FAILED;
    }
    uint32_t new_len = ctx->handshake_messages_len + len;
    uint8_t *new_buffer = (uint8_t*)realloc(ctx->handshake_messages, new_len);
    if(new_buffer == NULL && len > 0) {
        return NOXTLS_RETURN_FAILED;
    }

    ctx->handshake_messages = new_buffer;
    memcpy(ctx->handshake_messages + ctx->handshake_messages_len, data, len);
    ctx->handshake_messages_len = new_len;
    noxtls_debug_printf("[TLS13_DEBUG] handshake_messages_len=%u\n", ctx->handshake_messages_len);
    if(ctx->handshake_messages_len >= 16) {
        uint8_t *buf = ctx->handshake_messages;
        uint32_t total = ctx->handshake_messages_len;
        noxtls_debug_printf("[TLS13_DEBUG] transcript head: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                              buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
        noxtls_debug_printf("[TLS13_DEBUG] transcript tail: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                              buf[total - 8], buf[total - 7], buf[total - 6], buf[total - 5],
                              buf[total - 4], buf[total - 3], buf[total - 2], buf[total - 1]);
    }

    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t dtls13_context_init(tls13_context_t *ctx, tls_role_t role)
{
    noxtls_return_t rc = tls13_context_init(ctx, role);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    ctx->base.base.version = DTLS_VERSION_1_3;
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t tls13_get_cipher_params(uint16_t cipher_suite,
                                                 noxtls_hash_algos_t *hash_algo,
                                                 uint32_t *hash_len,
                                                 uint32_t *key_len)
{
    if(hash_algo == NULL || hash_len == NULL || key_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    switch(cipher_suite) {
        case TLS_CIPHER_SUITE_AES_128_GCM_SHA256:
        case TLS_CIPHER_SUITE_AES_128_CCM_SHA256:
        case TLS_CIPHER_SUITE_AES_128_CCM_8_SHA256:
            *hash_algo = NOXTLS_HASH_SHA_256;
            *hash_len = 32;
            *key_len = 16;
            return NOXTLS_RETURN_SUCCESS;
        case TLS_CIPHER_SUITE_AES_256_GCM_SHA384:
            *hash_algo = NOXTLS_HASH_SHA_384;
            *hash_len = 48;
            *key_len = 32;
            return NOXTLS_RETURN_SUCCESS;
        case TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256:
            *hash_algo = NOXTLS_HASH_SHA_256;
            *hash_len = 32;
            *key_len = 32;
            return NOXTLS_RETURN_SUCCESS;
        default:
            return NOXTLS_RETURN_INVALID_PARAM;
    }
}

static noxtls_return_t tls13_hash_messages(noxtls_hash_algos_t hash_algo,
                                             const uint8_t *messages, uint32_t messages_len,
                                             uint8_t *hash, uint32_t *hash_len)
{
    if(hash == NULL || hash_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(hash_algo == NOXTLS_HASH_SHA_256) {
        noxtls_sha_ctx_t sha_ctx;
        noxtls_sha256_init(&sha_ctx, hash_algo);
        if(messages != NULL && messages_len > 0) {
            noxtls_sha256_update(&sha_ctx, (uint8_t*)messages, messages_len);
        }
        *hash_len = 32;
        return noxtls_sha256_finish(&sha_ctx, hash);
    }

    if(hash_algo == NOXTLS_HASH_SHA_384) {
        noxtls_sha512_ctx_t sha_ctx;
        noxtls_sha512_init(&sha_ctx, hash_algo);
        if(messages != NULL && messages_len > 0) {
            noxtls_sha512_update(&sha_ctx, (uint8_t*)messages, messages_len);
        }
        *hash_len = 48;
        return noxtls_sha512_finish(&sha_ctx, hash);
    }

    return NOXTLS_RETURN_INVALID_ALGORITHM;
}

/**
 * Derive 0-RTT (early data) keys on client after sending ClientHello with early_data.
 * Uses ticket_cipher_suite and resumption_psk; transcript is only ClientHello.
 */
static noxtls_return_t tls13_derive_early_data_keys(tls13_context_t *ctx)
{
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint32_t key_len;
    uint32_t prk_len;
    uint8_t early_secret_buf[64];
    noxtls_return_t rc;

    if(ctx == NULL || !ctx->ticket_stored || ctx->resumption_psk_len == 0 ||
       ctx->handshake_messages == NULL || ctx->handshake_messages_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    rc = tls13_get_cipher_params(ctx->ticket_cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    prk_len = hash_len;
    rc = hkdf_extract(hash_algo, NULL, 0, ctx->resumption_psk, (uint32_t)ctx->resumption_psk_len,
                      early_secret_buf, &prk_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    /* client_early_traffic_secret = Derive-Secret(early_secret, "c e traffic", Hash(ClientHello)) */
    rc = tls13_derive_secret(hash_algo, early_secret_buf, hash_len,
                             (const uint8_t*)"c e traffic", 12,
                             ctx->handshake_messages, ctx->handshake_messages_len,
                             ctx->client_early_traffic_secret, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = tls13_hkdf_expand_label(hash_algo, ctx->client_early_traffic_secret, hash_len,
                                 (const uint8_t*)"key", 3, NULL, 0,
                                 ctx->early_write_key, key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tls13_hkdf_expand_label(hash_algo, ctx->client_early_traffic_secret, hash_len,
                                 (const uint8_t*)"iv", 2, NULL, 0,
                                 ctx->early_write_iv, 12);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    ctx->early_seq_num = 0;
    ctx->early_data_phase = 1;
    noxtls_debug_printf("[TLS13_DEBUG] 0-RTT keys derived (ticket_cipher=0x%04X)\n", ctx->ticket_cipher_suite);
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t tls13_derive_handshake_keys(tls13_context_t *ctx, const uint8_t *shared_secret, uint32_t shared_secret_len)
{
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint32_t key_len;
    uint32_t prk_len;
    uint8_t derived_secret[64];
    const uint8_t zero_ikm[64] = {0};
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_KEYSCHED, NOXSIGHT_SEVERITY_DEBUG,
                    NOXTLS_EVT_KEY_SCHEDULE_STAGE, 1u, ctx->cipher_suite);
    noxtls_debug_printf("[TLS13_DEBUG] derive_handshake_keys: cipher=0x%04X hash=%u key_len=%u\n",
                          ctx->cipher_suite, (unsigned)hash_algo, key_len);
    {
        uint8_t transcript_hash[64];
        uint32_t transcript_len = sizeof(transcript_hash);
        if(tls13_hash_messages(hash_algo, ctx->handshake_messages, ctx->handshake_messages_len,
                               transcript_hash, &transcript_len) == NOXTLS_RETURN_SUCCESS) {
            noxtls_debug_printf("[TLS13_DEBUG] transcript hash[0..3]=%02X%02X%02X%02X len=%u hs_len=%u\n",
                                  transcript_hash[0], transcript_hash[1], transcript_hash[2], transcript_hash[3],
                                  transcript_len, ctx->handshake_messages_len);
            noxtls_debug_printf("[TLS13_DEBUG] transcript_hash=");
            for(uint32_t i = 0; i < transcript_len; i++) {
                noxtls_debug_printf("%02X", transcript_hash[i]);
            }
            noxtls_debug_printf("\n");
        }
    }

    if(shared_secret != NULL && shared_secret_len > 0) {
        noxtls_debug_printf("[TLS13_DEBUG] derive_handshake_keys: shared[0..3]=%02X%02X%02X%02X len=%u\n",
                              shared_secret[0], shared_secret[1], shared_secret[2], shared_secret[3], shared_secret_len);
        noxtls_debug_printf("[TLS13_DEBUG] shared_secret=");
        for(uint32_t i = 0; i < shared_secret_len; i++) {
            noxtls_debug_printf("%02X", shared_secret[i]);
        }
        noxtls_debug_printf("\n");
    } else {
        noxtls_debug_printf("[TLS13_DEBUG] derive_handshake_keys: no ecdhe shared secret (PSK-only path)\n");
    }

    prk_len = hash_len;
    if(ctx->psk_in_use && ctx->psk_key_len > 0) {
        rc = hkdf_extract(hash_algo, NULL, 0, ctx->psk_key, ctx->psk_key_len, ctx->early_secret, &prk_len);
    } else {
        rc = hkdf_extract(hash_algo, NULL, 0, zero_ikm, hash_len, ctx->early_secret, &prk_len);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_KEYSCHED, NOXSIGHT_SEVERITY_DEBUG,
                    NOXTLS_EVT_KEY_SCHEDULE_STAGE, 2u, hash_len);
    noxtls_debug_printf("[TLS13_DEBUG] early_secret[0..3]=%02X%02X%02X%02X\n",
                          ctx->early_secret[0], ctx->early_secret[1], ctx->early_secret[2], ctx->early_secret[3]);

    /* Server: derive 0-RTT read keys when client offered early_data (context is Hash(ClientHello) only) */
    if(ctx->base.base.role == TLS_ROLE_SERVER && ctx->client_offered_early_data &&
       ctx->handshake_messages != NULL && ctx->handshake_messages_len >= 4) {
        uint32_t ch_len = 4u + ((uint32_t)ctx->handshake_messages[1] << 16) + ((uint32_t)ctx->handshake_messages[2] << 8) + ctx->handshake_messages[3];
        if(ch_len > ctx->handshake_messages_len) {
            ch_len = ctx->handshake_messages_len;
        }
        rc = tls13_derive_secret(hash_algo, ctx->early_secret, hash_len,
                                 (const uint8_t*)"c e traffic", 12,
                                 ctx->handshake_messages, ch_len,
                                 ctx->client_early_traffic_secret, hash_len);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = tls13_hkdf_expand_label(hash_algo, ctx->client_early_traffic_secret, hash_len,
                                         (const uint8_t*)"key", 3, NULL, 0,
                                         ctx->early_write_key, key_len);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                rc = tls13_hkdf_expand_label(hash_algo, ctx->client_early_traffic_secret, hash_len,
                                             (const uint8_t*)"iv", 2, NULL, 0,
                                             ctx->early_write_iv, 12);
            }
            if(rc == NOXTLS_RETURN_SUCCESS) {
                ctx->early_seq_num = 0;
                noxtls_debug_printf("[TLS13_DEBUG] server 0-RTT read keys derived\n");
            }
        }
    }

    rc = tls13_derive_secret(hash_algo, ctx->early_secret, hash_len,
                             (const uint8_t*)"derived", 7, NULL, 0,
                             derived_secret, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    noxtls_debug_printf("[TLS13_DEBUG] derived_secret[0..3]=%02X%02X%02X%02X\n",
                          derived_secret[0], derived_secret[1], derived_secret[2], derived_secret[3]);

    prk_len = hash_len;
    if(shared_secret != NULL && shared_secret_len > 0) {
        rc = hkdf_extract(hash_algo, derived_secret, hash_len, shared_secret, shared_secret_len,
                          ctx->handshake_secret, &prk_len);
    } else {
        rc = hkdf_extract(hash_algo, derived_secret, hash_len, zero_ikm, hash_len,
                          ctx->handshake_secret, &prk_len);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    noxtls_debug_printf("[TLS13_DEBUG] handshake_secret[0..3]=%02X%02X%02X%02X\n",
                          ctx->handshake_secret[0], ctx->handshake_secret[1], ctx->handshake_secret[2], ctx->handshake_secret[3]);

    rc = tls13_derive_secret(hash_algo, ctx->handshake_secret, hash_len,
                             (const uint8_t*)"c hs traffic", 12,
                             ctx->handshake_messages, ctx->handshake_messages_len,
                             ctx->client_handshake_traffic_secret, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    noxtls_debug_printf("[TLS13_DEBUG] c_hs_secret[0..3]=%02X%02X%02X%02X\n",
                          ctx->client_handshake_traffic_secret[0], ctx->client_handshake_traffic_secret[1],
                          ctx->client_handshake_traffic_secret[2], ctx->client_handshake_traffic_secret[3]);

    rc = tls13_derive_secret(hash_algo, ctx->handshake_secret, hash_len,
                             (const uint8_t*)"s hs traffic", 12,
                             ctx->handshake_messages, ctx->handshake_messages_len,
                             ctx->server_handshake_traffic_secret, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    noxtls_debug_printf("[TLS13_DEBUG] s_hs_secret[0..3]=%02X%02X%02X%02X\n",
                          ctx->server_handshake_traffic_secret[0], ctx->server_handshake_traffic_secret[1],
                          ctx->server_handshake_traffic_secret[2], ctx->server_handshake_traffic_secret[3]);
    noxtls_debug_printf("[TLS13_DEBUG] s_hs_secret=");
    for(uint32_t i = 0; i < hash_len; i++) {
        noxtls_debug_printf("%02X", ctx->server_handshake_traffic_secret[i]);
    }
    noxtls_debug_printf("\n");
    noxtls_debug_printf("[TLS13_KEYLOG] CLIENT_HANDSHAKE_TRAFFIC_SECRET ");
    for(uint32_t i = 0; i < 32; i++) {
        noxtls_debug_printf("%02X", ctx->client_random[i]);
    }
    noxtls_debug_printf(" ");
    for(uint32_t i = 0; i < hash_len; i++) {
        noxtls_debug_printf("%02X", ctx->client_handshake_traffic_secret[i]);
    }
    noxtls_debug_printf("\n");
    noxtls_debug_printf("[TLS13_KEYLOG] SERVER_HANDSHAKE_TRAFFIC_SECRET ");
    for(uint32_t i = 0; i < 32; i++) {
        noxtls_debug_printf("%02X", ctx->client_random[i]);
    }
    noxtls_debug_printf(" ");
    for(uint32_t i = 0; i < hash_len; i++) {
        noxtls_debug_printf("%02X", ctx->server_handshake_traffic_secret[i]);
    }
    noxtls_debug_printf("\n");
    tls13_keylog_write("CLIENT_HANDSHAKE_TRAFFIC_SECRET", ctx->client_random,
                       ctx->client_handshake_traffic_secret, hash_len);
    tls13_keylog_write("SERVER_HANDSHAKE_TRAFFIC_SECRET", ctx->client_random,
                       ctx->server_handshake_traffic_secret, hash_len);

    rc = tls13_hkdf_expand_label(hash_algo, ctx->client_handshake_traffic_secret, hash_len,
                                 (const uint8_t*)"key", 3, NULL, 0,
                                 ctx->client_write_key, key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = tls13_hkdf_expand_label(hash_algo, ctx->client_handshake_traffic_secret, hash_len,
                                 (const uint8_t*)"iv", 2, NULL, 0,
                                 ctx->client_write_iv, 12);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = tls13_hkdf_expand_label(hash_algo, ctx->server_handshake_traffic_secret, hash_len,
                                 (const uint8_t*)"key", 3, NULL, 0,
                                 ctx->server_write_key, key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = tls13_hkdf_expand_label(hash_algo, ctx->server_handshake_traffic_secret, hash_len,
                                 (const uint8_t*)"iv", 2, NULL, 0,
                                 ctx->server_write_iv, 12);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    /* RFC 9147 §4.2.3: record number encryption keys for DTLS 1.3 handshake */
    rc = tls13_hkdf_expand_label(hash_algo, ctx->client_handshake_traffic_secret, hash_len,
                                 (const uint8_t*)"sn", 2, NULL, 0,
                                 ctx->client_handshake_sn_key, DTLS13_RECORD_NUMBER_ENC_LEN);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tls13_hkdf_expand_label(hash_algo, ctx->server_handshake_traffic_secret, hash_len,
                                 (const uint8_t*)"sn", 2, NULL, 0,
                                 ctx->server_handshake_sn_key, DTLS13_RECORD_NUMBER_ENC_LEN);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    ctx->client_seq_num = 0;
    ctx->server_seq_num = 0;

    noxtls_debug_printf("[TLS13_DEBUG] hs keys: ckey[0..3]=%02X%02X%02X%02X civ[0..3]=%02X%02X%02X%02X "
                          "skey[0..3]=%02X%02X%02X%02X siv[0..3]=%02X%02X%02X%02X\n",
                          ctx->client_write_key[0], ctx->client_write_key[1], ctx->client_write_key[2], ctx->client_write_key[3],
                          ctx->client_write_iv[0], ctx->client_write_iv[1], ctx->client_write_iv[2], ctx->client_write_iv[3],
                          ctx->server_write_key[0], ctx->server_write_key[1], ctx->server_write_key[2], ctx->server_write_key[3],
                          ctx->server_write_iv[0], ctx->server_write_iv[1], ctx->server_write_iv[2], ctx->server_write_iv[3]);
    noxtls_debug_printf("[TLS13_DEBUG] hs server_key=");
    for(uint32_t i = 0; i < key_len; i++) {
        noxtls_debug_printf("%02X", ctx->server_write_key[i]);
    }
    noxtls_debug_printf("\n");
    noxtls_debug_printf("[TLS13_DEBUG] hs server_iv=");
    for(uint32_t i = 0; i < 12; i++) {
        noxtls_debug_printf("%02X", ctx->server_write_iv[i]);
    }
    noxtls_debug_printf("\n");

    ctx->handshake_encrypted = 1;
    if(tls13_is_dtls(ctx)) {
        ctx->base.epoch = DTLS_EPOCH_ENCRYPTED;
        ctx->base.write_seq_num = 0;
        ctx->base.read_seq_num = 0;
        ctx->base.replay_window.window_bitmap = 0;
        ctx->base.replay_window.last_seq = 0;
    }
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_KEYSCHED, NOXSIGHT_SEVERITY_DEBUG,
                    NOXTLS_EVT_KEY_SCHEDULE_STAGE, 3u, key_len);

    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t tls13_derive_application_secrets(tls13_context_t *ctx)
{
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint32_t key_len;
    uint32_t prk_len;
    uint8_t derived_secret[64];
    const uint8_t zero_ikm[64] = {0};
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_KEYSCHED, NOXSIGHT_SEVERITY_DEBUG,
                    NOXTLS_EVT_KEY_SCHEDULE_STAGE, 4u, ctx->cipher_suite);

    rc = tls13_derive_secret(hash_algo, ctx->handshake_secret, hash_len,
                             (const uint8_t*)"derived", 7, NULL, 0,
                             derived_secret, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    prk_len = hash_len;
    rc = hkdf_extract(hash_algo, derived_secret, hash_len, zero_ikm, hash_len,
                      ctx->master_secret, &prk_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = tls13_derive_secret(hash_algo, ctx->master_secret, hash_len,
                             (const uint8_t*)"c ap traffic", 12,
                             ctx->handshake_messages, ctx->handshake_messages_len,
                             ctx->client_application_traffic_secret, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = tls13_derive_secret(hash_algo, ctx->master_secret, hash_len,
                             (const uint8_t*)"s ap traffic", 12,
                             ctx->handshake_messages, ctx->handshake_messages_len,
                             ctx->server_application_traffic_secret, hash_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t tls13_install_application_keys(tls13_context_t *ctx)
{
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint32_t key_len;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_KEYSCHED, NOXSIGHT_SEVERITY_DEBUG,
                    NOXTLS_EVT_KEY_SCHEDULE_STAGE, 5u, key_len);

    rc = tls13_hkdf_expand_label(hash_algo, ctx->client_application_traffic_secret, hash_len,
                                 (const uint8_t*)"key", 3, NULL, 0,
                                 ctx->client_write_key, key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = tls13_hkdf_expand_label(hash_algo, ctx->client_application_traffic_secret, hash_len,
                                 (const uint8_t*)"iv", 2, NULL, 0,
                                 ctx->client_write_iv, 12);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = tls13_hkdf_expand_label(hash_algo, ctx->server_application_traffic_secret, hash_len,
                                 (const uint8_t*)"key", 3, NULL, 0,
                                 ctx->server_write_key, key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = tls13_hkdf_expand_label(hash_algo, ctx->server_application_traffic_secret, hash_len,
                                 (const uint8_t*)"iv", 2, NULL, 0,
                                 ctx->server_write_iv, 12);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    /* RFC 9147 §4.2.3: record number encryption keys for DTLS 1.3 application data */
    rc = tls13_hkdf_expand_label(hash_algo, ctx->client_application_traffic_secret, hash_len,
                                 (const uint8_t*)"sn", 2, NULL, 0,
                                 ctx->client_sn_key, DTLS13_RECORD_NUMBER_ENC_LEN);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tls13_hkdf_expand_label(hash_algo, ctx->server_application_traffic_secret, hash_len,
                                 (const uint8_t*)"sn", 2, NULL, 0,
                                 ctx->server_sn_key, DTLS13_RECORD_NUMBER_ENC_LEN);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    ctx->client_seq_num = 0;
    ctx->server_seq_num = 0;
    if(tls13_is_dtls(ctx)) {
        ctx->base.epoch = DTLS_EPOCH_APPLICATION;
        ctx->base.write_seq_num = 0;
        ctx->base.read_seq_num = 0;
        ctx->base.replay_window.window_bitmap = 0;
        ctx->base.replay_window.last_seq = 0;
    }

    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t tls13_build_inner_plaintext(const uint8_t *content, uint32_t content_len,
                                                     uint8_t content_type,
                                                     uint8_t *output, uint32_t *output_len)
{
    if(output == NULL || output_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(*output_len < content_len + 1) {
        *output_len = content_len + 1;
        return NOXTLS_RETURN_FAILED;
    }
    if(content != NULL && content_len > 0) {
        memcpy(output, content, content_len);
    }
    output[content_len] = content_type;
    *output_len = content_len + 1;
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t tls13_extract_inner_plaintext(const uint8_t *plaintext, uint32_t *plaintext_len, uint8_t *content_type)
{
    if(plaintext == NULL || plaintext_len == NULL || content_type == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    uint32_t len = *plaintext_len;
    while(len > 0 && plaintext[len - 1] == 0) {
        len--;
    }
    if(len == 0) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    *content_type = plaintext[len - 1];
    *plaintext_len = len - 1;
    return NOXTLS_RETURN_SUCCESS;
}

static void tls13_handshake_buffer_reset(tls13_context_t *ctx)
{
    if(ctx == NULL) {
        return;
    }
    if(ctx->handshake_buffer) {
        free(ctx->handshake_buffer);
        ctx->handshake_buffer = NULL;
    }
    ctx->handshake_buffer_len = 0;
    ctx->handshake_buffer_pos = 0;
    ctx->handshake_next_at_record_boundary = 0;
}

static noxtls_return_t tls13_handshake_buffer_append(tls13_context_t *ctx, const uint8_t *data, uint32_t len)
{
    if(ctx == NULL || (data == NULL && len > 0)) {
        return NOXTLS_RETURN_NULL;
    }
    if(len == 0) {
        return NOXTLS_RETURN_SUCCESS;
    }
    if(ctx->handshake_buffer_len < ctx->handshake_buffer_pos) {
        return NOXTLS_RETURN_FAILED;
    }
    uint32_t remaining = ctx->handshake_buffer_len - ctx->handshake_buffer_pos;
    if(len > UINT32_MAX - remaining) {
        return NOXTLS_RETURN_FAILED;
    }
    uint32_t new_len = remaining + len;
    uint8_t *new_buffer = (uint8_t*)realloc(ctx->handshake_buffer, new_len);
    if(new_buffer == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    /* Compact to front if we've consumed data */
    if(remaining > 0 && ctx->handshake_buffer_pos > 0) {
        memmove(new_buffer, new_buffer + ctx->handshake_buffer_pos, remaining);
    }
    memcpy(new_buffer + remaining, data, len);
    ctx->handshake_buffer = new_buffer;
    ctx->handshake_buffer_len = new_len;
    ctx->handshake_buffer_pos = 0;
    /* Track whether the next handshake message starts at a new record boundary.
     * If we had no buffered remainder, this append begins a fresh record payload.
     * If we had remainder, this append is a continuation (cross-record fragment). */
    ctx->handshake_next_at_record_boundary = (remaining == 0) ? 1 : 0;
    return NOXTLS_RETURN_SUCCESS;
}

/* RFC 8446 §5.1: these handshake types must not span a key change; they must be at a record boundary. */
static int tls13_handshake_type_requires_record_boundary(uint8_t msg_type)
{
    return (msg_type == TLS_HANDSHAKE_CLIENT_HELLO ||
            msg_type == TLS_HANDSHAKE_SERVER_HELLO ||
            msg_type == TLS_HANDSHAKE_END_OF_EARLY_DATA ||
            msg_type == TLS_HANDSHAKE_FINISHED ||
            msg_type == TLS_HANDSHAKE_KEY_UPDATE);
}

static noxtls_return_t tls13_handshake_buffer_get(tls13_context_t *ctx, uint8_t **out_msg, uint32_t *out_len)
{
    if(ctx == NULL || out_msg == NULL || out_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    uint32_t available = ctx->handshake_buffer_len - ctx->handshake_buffer_pos;
    if(available < 4) {
        return NOXTLS_RETURN_FAILED;
    }
    const uint8_t *buf = ctx->handshake_buffer + ctx->handshake_buffer_pos;
    uint32_t hs_len = ((uint32_t)buf[1] << 16) | ((uint32_t)buf[2] << 8) | buf[3];
    uint32_t total_len = hs_len + 4;
    if(available < total_len) {
        return NOXTLS_RETURN_FAILED;
    }
    /* RFC 8446 §5.1: reject messages that must be at record boundary but were received fragmented. */
    if(tls13_handshake_type_requires_record_boundary(buf[0]) && !ctx->handshake_next_at_record_boundary) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    uint8_t *msg = (uint8_t*)malloc(total_len);
    if(msg == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(msg, buf, total_len);
    ctx->handshake_buffer_pos += total_len;
    ctx->handshake_next_at_record_boundary = 0;  /* Next message in buffer (if any) does not start at boundary */
    if(ctx->handshake_buffer_pos >= ctx->handshake_buffer_len) {
        tls13_handshake_buffer_reset(ctx);
    }
    *out_msg = msg;
    *out_len = total_len;
    return NOXTLS_RETURN_SUCCESS;
}

#define TLS13_RECORD_WORKSPACE_HALF  (TLS_MAX_RECORD_SIZE + 32)

static noxtls_return_t tls13_send_encrypted_handshake(tls13_context_t *ctx, const uint8_t *msg, uint32_t msg_len)
{
    uint32_t inner_len = TLS13_RECORD_WORKSPACE_HALF;
    uint32_t encrypted_len = TLS13_RECORD_WORKSPACE_HALF;
    uint8_t *inner = ctx->record_workspace;
    uint8_t *encrypted = ctx->record_workspace + TLS13_RECORD_WORKSPACE_HALF;
    noxtls_return_t rc;

    if(ctx == NULL || msg == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = tls13_build_inner_plaintext(msg, msg_len, TLS_RECORD_HANDSHAKE, inner, &inner_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(tls13_is_dtls(ctx)) {
        return noxtls_tls13_send_dtls13_encrypted_record(ctx, 1, TLS_RECORD_HANDSHAKE, inner, inner_len, 1);
    }

    rc = noxtls_tls13_encrypt_record(ctx, TLS_RECORD_APPLICATION_DATA, inner, inner_len, encrypted, &encrypted_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_APPLICATION_DATA, encrypted, encrypted_len);
}

/* RFC 8446 4.6.1: send NewSessionTicket (standard NST + appended resumption_psk for client storage) */
static noxtls_return_t tls13_send_new_session_ticket(tls13_context_t *ctx)
{
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint8_t ticket_nonce[TLS13_PSK_TICKET_NONCE_MAX];
    uint8_t ticket_id[TLS13_PSK_TICKET_ID_LEN];
    uint8_t resumption_psk[64];
    uint32_t ticket_age_add;
    uint8_t *msg;
    uint32_t msg_len;
    uint32_t payload_len;
    drbg_state_t drbg_state;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, NULL);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(drbg_instantiate(&drbg_state, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(drbg_generate(&drbg_state, ticket_nonce, 16 * 8u, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(drbg_generate(&drbg_state, ticket_id, sizeof(ticket_id) * 8u, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(drbg_generate(&drbg_state, (uint8_t*)&ticket_age_add, sizeof(ticket_age_add) * 8u, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    rc = tls13_psk_derive_resumption_psk(hash_algo, (uint32_t)hash_len, ctx->master_secret,
                                         ticket_nonce, 16, resumption_psk);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tls13_psk_ticket_store_add(ticket_id, TLS13_PSK_TICKET_ID_LEN, resumption_psk, (uint8_t)hash_len,
                                    ticket_nonce, 16, ticket_age_add, ctx->cipher_suite);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        memset(resumption_psk, 0, sizeof(resumption_psk));
        return rc;
    }

    /* NST payload: lifetime(4) | age_add(4) | nonce_len(1) | nonce(16) | ticket_len(2) | ticket(16) | resumption_psk(hash_len) */
    payload_len = 4 + 4 + 1 + 16 + 2 + 16 + (uint32_t)hash_len;
    msg_len = 4 + payload_len;
    msg = (uint8_t*)malloc(msg_len);
    if(msg == NULL) {
        memset(resumption_psk, 0, sizeof(resumption_psk));
        return NOXTLS_RETURN_FAILED;
    }
    msg[0] = TLS_HANDSHAKE_NEW_SESSION_TICKET;
    msg[1] = (uint8_t)(payload_len >> 16);
    msg[2] = (uint8_t)(payload_len >> 8);
    msg[3] = (uint8_t)payload_len;
    /* ticket_lifetime: 86400 seconds (1 day) */
    msg[4] = 0;
    msg[5] = 0;
    msg[6] = (uint8_t)(86400 >> 8);
    msg[7] = (uint8_t)86400;
    msg[8] = (uint8_t)(ticket_age_add >> 24);
    msg[9] = (uint8_t)(ticket_age_add >> 16);
    msg[10] = (uint8_t)(ticket_age_add >> 8);
    msg[11] = (uint8_t)ticket_age_add;
    msg[12] = 16;
    memcpy(msg + 13, ticket_nonce, 16);
    msg[29] = 0;
    msg[30] = 16;
    memcpy(msg + 31, ticket_id, 16);
    memcpy(msg + 47, resumption_psk, (size_t)hash_len);
    memset(resumption_psk, 0, sizeof(resumption_psk));

    rc = tls13_send_encrypted_handshake(ctx, msg, msg_len);
    memset(msg + 47, 0, (size_t)hash_len);
    free(msg);
    return rc;
}

/* Client: optionally receive one record after connect; if NST, parse and store ticket; if app data, buffer for tls13_recv */
static void tls13_try_recv_nst(tls13_context_t *ctx)
{
    tls_record_t record;
    noxtls_return_t rc;
    uint32_t decrypted_len = TLS13_RECORD_WORKSPACE_HALF;
    uint8_t *decrypted = ctx->record_workspace;  /* Reuse first half of workspace */
    uint8_t content_type = 0;
    uint32_t hash_len;
    const uint8_t *payload;
    uint32_t payload_len;
    uint32_t off;
    uint8_t nonce_len;
    uint16_t ticket_len;

    if(ctx == NULL || ctx->base.base.role != TLS_ROLE_CLIENT) {
        return;
    }
    if(ctx->record_workspace == NULL) {
        return;
    }
    memset(&record, 0, sizeof(record));
    rc = noxtls_tls_recv_record(&ctx->base.base, &record);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        if(record.data) free(record.data);
        return;
    }
    if(record.length > 0 && record.data == NULL) {
        return;
    }
    if(record.type != TLS_RECORD_APPLICATION_DATA) {
        if(record.data) free(record.data);
        return;
    }
    rc = noxtls_tls13_decrypt_record(ctx, record.data, record.length, decrypted, &decrypted_len);
    if(record.data) free(record.data);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return;
    }
    rc = tls13_extract_inner_plaintext(decrypted, &decrypted_len, &content_type);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return;
    }
    if(content_type == TLS_RECORD_APPLICATION_DATA) {
        if(decrypted_len > 0) {
            ctx->pending_app_data = (uint8_t*)malloc(decrypted_len);
            if(ctx->pending_app_data != NULL) {
                memcpy(ctx->pending_app_data, decrypted, decrypted_len);
                ctx->pending_app_data_len = decrypted_len;
            }
        }
        return;
    }
    if(content_type != TLS_RECORD_HANDSHAKE || decrypted_len < 4) {
        return;
    }
    if(decrypted[0] != TLS_HANDSHAKE_NEW_SESSION_TICKET) {
        return;
    }
    payload_len = ((uint32_t)decrypted[1] << 16) | ((uint32_t)decrypted[2] << 8) | decrypted[3];
    payload = decrypted + 4;
    if(payload_len < 11 || (uint32_t)4 + payload_len > decrypted_len) {
        return;
    }
    rc = tls13_get_cipher_params(ctx->cipher_suite, NULL, &hash_len, NULL);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return;
    }
    off = 9;
    nonce_len = payload[8];
    if(nonce_len > 32 || off + nonce_len + 2 > payload_len) {
        return;
    }
    off += nonce_len;
    ticket_len = ((uint16_t)payload[off] << 8) | payload[off + 1];
    off += 2;
    if(ticket_len > 32 || off + ticket_len + (uint32_t)hash_len > payload_len) {
        return;
    }
    ctx->ticket_age_add = ((uint32_t)payload[4] << 24) | ((uint32_t)payload[5] << 16) |
                         ((uint32_t)payload[6] << 8) | payload[7];
    memcpy(ctx->ticket_nonce, payload + 9, (size_t)nonce_len);
    ctx->ticket_nonce_len = nonce_len;
    memcpy(ctx->ticket_identity, payload + 9 + nonce_len + 2, (size_t)ticket_len);
    ctx->ticket_identity_len = ticket_len;
    memcpy(ctx->resumption_psk, payload + off + ticket_len, (size_t)hash_len);
    ctx->resumption_psk_len = (uint8_t)hash_len;
    ctx->ticket_cipher_suite = ctx->cipher_suite;
    ctx->ticket_stored = 1;
}

/**
 * Receive one TLS 1.3 handshake message (RFC 8446).
 * - Coalescing: multiple handshake messages in one record are buffered; we return one message per call.
 * - Fragmentation: one message spanning multiple records is reassembled by appending until we have 4 + length bytes.
 * - Order: callers (recv_encrypted_extensions, recv_certificate_request, etc.) enforce required message order by type.
 */
static noxtls_return_t tls13_recv_handshake_message(tls13_context_t *ctx, uint8_t **out_msg, uint32_t *out_len)
{
    tls_record_t record;
    noxtls_return_t rc;
    uint8_t content_type = 0;

    if(ctx == NULL || out_msg == NULL || out_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(ctx->pending_handshake_msg != NULL && ctx->pending_handshake_len > 0) {
        *out_msg = ctx->pending_handshake_msg;
        *out_len = ctx->pending_handshake_len;
        ctx->pending_handshake_msg = NULL;
        ctx->pending_handshake_len = 0;
        return NOXTLS_RETURN_SUCCESS;
    }

    /* Try to satisfy from buffered data first */
    while(1) {
        rc = tls13_handshake_buffer_get(ctx, out_msg, out_len);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            if(tls13_is_ack_message(*out_msg, *out_len)) {
                tls13_dtls_handle_ack(ctx, *out_msg, *out_len);
                free(*out_msg);
                *out_msg = NULL;
                *out_len = 0;
                continue;
            }
            return rc;
        }
        break;
    }

    while(1) {
        rc = noxtls_tls_recv_record(&ctx->base.base, &record);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if(record.length > 0 && record.data == NULL) {
            return NOXTLS_RETURN_FAILED;
        }

        if(record.type == TLS_RECORD_CHANGE_CIPHER_SPEC) {
            if(record.data) free(record.data);
            /* TLS 1.3 middlebox compatibility CCS, ignore */
            continue;
        }

        /* RFC 9147: ACK can be received as record content type 26 in DTLS 1.3 */
        if(record.type == TLS_RECORD_ACK && tls13_is_dtls(ctx)) {
            if(record.length > 0 && record.data != NULL) {
                tls13_dtls_handle_ack(ctx, record.data, record.length);
            }
            if(record.data) free(record.data);
            continue;
        }

        /* RFC 9147: DTLSCiphertext (unified header, first byte 0x20-0x3F); support multiple records per datagram */
        if(tls13_is_dtls(ctx) && record.type >= 0x20 && record.type <= 0x3F) {
            uint32_t offset = 0;
            uint32_t total_len = (uint32_t)record.length;
            while(offset < total_len) {
                uint32_t rec_size = noxtls_tls13_dtls13_record_size(record.data + offset, total_len - offset,
                                                                     ctx->own_connection_id_len);
                if(rec_size == 0) {
                    if(record.data) free(record.data);
                    return NOXTLS_RETURN_BAD_DATA;
                }
                {
                    uint8_t inner_type;
                    uint32_t inner_len = rec_size;
                    uint8_t *inner_buf = (uint8_t*)malloc(inner_len);
                    if(inner_buf == NULL) {
                        if(record.data) free(record.data);
                        return NOXTLS_RETURN_FAILED;
                    }
                    rc = noxtls_tls13_decrypt_dtls13_record(ctx, record.data + offset, rec_size,
                                                            &inner_type, inner_buf, &inner_len);
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        free(inner_buf);
                        if(record.data) free(record.data);
                        return rc;
                    }
                    if(inner_type == TLS_RECORD_HANDSHAKE) {
                        rc = tls13_handshake_buffer_append(ctx, inner_buf, inner_len);
                        free(inner_buf);
                        if(rc != NOXTLS_RETURN_SUCCESS) {
                            if(record.data) free(record.data);
                            return rc;
                        }
                        rc = tls13_handshake_buffer_get(ctx, out_msg, out_len);
                        if(rc == NOXTLS_RETURN_SUCCESS) {
                            if(tls13_is_ack_message(*out_msg, *out_len)) {
                                tls13_dtls_handle_ack(ctx, *out_msg, *out_len);
                                free(*out_msg);
                                *out_msg = NULL;
                                *out_len = 0;
                                offset += rec_size;
                                continue;
                            }
                            if(record.data) free(record.data);
                            return rc;
                        }
                    } else if(inner_type == TLS_RECORD_APPLICATION_DATA) {
                        if(record.data) free(record.data);
                        *out_msg = inner_buf;
                        *out_len = inner_len;
                        return NOXTLS_RETURN_SUCCESS;
                    } else {
                        free(inner_buf);
                    }
                }
                offset += rec_size;
            }
            if(record.data) free(record.data);
            continue;
        }

        if(record.type == TLS_RECORD_HANDSHAKE && tls13_is_dtls(ctx)) {
            dtls_context_t *dctx = &ctx->base;
            if(record.length > 0 && record.data[0] == TLS_HANDSHAKE_ACK) {
                dctx->ack_pending = 0;
                dctx->ack_range_valid = 0;
                dctx->ack_range_count = 0;
            } else if(dctx->ack_pending) {
                if(dctx->ack_range_valid && dctx->ack_range_count > 0) {
                    uint32_t body_len = 2 + 2 + (12u * dctx->ack_range_count) + 2;
                    uint32_t total_len = body_len + 4;
                    uint8_t *ack_msg = (uint8_t*)malloc(total_len);
                    uint32_t offset = 0;
                    if(ack_msg == NULL) {
                        if(record.data) free(record.data);
                        return NOXTLS_RETURN_FAILED;
                    }
                    ack_msg[offset++] = TLS_HANDSHAKE_ACK;
                    ack_msg[offset++] = (uint8_t)((body_len >> 16) & 0xFF);
                    ack_msg[offset++] = (uint8_t)((body_len >> 8) & 0xFF);
                    ack_msg[offset++] = (uint8_t)(body_len & 0xFF);
                    tls13_write_uint16(ack_msg + offset, (uint16_t)dctx->ack_epoch);
                    offset += 2;
                    tls13_write_uint16(ack_msg + offset, dctx->ack_range_count);
                    offset += 2;
                    for(uint8_t i = 0; i < dctx->ack_range_count; i++) {
                        tls13_write_uint48(ack_msg + offset, dctx->ack_ranges_min[i]);
                        offset += 6;
                        tls13_write_uint48(ack_msg + offset, dctx->ack_ranges_max[i]);
                        offset += 6;
                    }
                    ack_msg[offset++] = 0x00;
                    ack_msg[offset++] = 0x00;
                    /* RFC 9147: ACK sent as record content type 26 in DTLS 1.3; handshake (22) otherwise */
                    {
                        uint8_t rec_type = tls13_is_dtls(ctx) ? TLS_RECORD_ACK : TLS_RECORD_HANDSHAKE;
                        if(noxtls_tls_send_record(&ctx->base.base, rec_type, ack_msg, offset) == NOXTLS_RETURN_SUCCESS) {
                            dctx->ack_pending = 0;
                            dctx->ack_range_valid = 0;
                            dctx->ack_range_count = 0;
                        }
                    }
                    free(ack_msg);
                }
            }
        }

        if(record.type == TLS_RECORD_HANDSHAKE) {
            /* Append and return a single handshake message */
            rc = tls13_handshake_buffer_append(ctx, record.data, record.length);
            if(record.data) free(record.data);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            rc = tls13_handshake_buffer_get(ctx, out_msg, out_len);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                if(tls13_is_ack_message(*out_msg, *out_len)) {
                    tls13_dtls_handle_ack(ctx, *out_msg, *out_len);
                    free(*out_msg);
                    *out_msg = NULL;
                    *out_len = 0;
                    continue;
                }
                return rc;
            }
            continue;
        }

        if(record.type == TLS_RECORD_APPLICATION_DATA) {
            uint8_t *decrypted = (uint8_t*)malloc(record.length);
            uint32_t decrypted_len = record.length;
            if(decrypted == NULL) {
                if(record.data) free(record.data);
                return NOXTLS_RETURN_FAILED;
            }
            rc = noxtls_tls13_decrypt_record(ctx, record.data, record.length, decrypted, &decrypted_len);
            /* Server: if handshake decrypt failed, try 0-RTT (early) decrypt */
            if(rc != NOXTLS_RETURN_SUCCESS && ctx->base.base.role == TLS_ROLE_SERVER &&
               ctx->client_offered_early_data && !ctx->end_of_early_data_seen) {
                decrypted_len = record.length;
                rc = noxtls_tls13_decrypt_record_early(ctx, ctx->cipher_suite, record.data, record.length,
                                                      decrypted, &decrypted_len);
            }
            if(record.data) free(record.data);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_debug_printf("[TLS13_DEBUG] recv_handshake: decrypt rc=%d len=%u\n", rc, decrypted_len);
                free(decrypted);
                return rc;
            }
            rc = tls13_extract_inner_plaintext(decrypted, &decrypted_len, &content_type);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                free(decrypted);
                return NOXTLS_RETURN_FAILED;
            }
            /* Server: 0-RTT application data can be delivered or buffered */
            if(content_type == TLS_RECORD_APPLICATION_DATA && ctx->base.base.role == TLS_ROLE_SERVER) {
                if(decrypted_len > 0) {
                    if(ctx->pending_app_data) free(ctx->pending_app_data);
                    ctx->pending_app_data = (uint8_t*)malloc(decrypted_len);
                    if(ctx->pending_app_data) {
                        memcpy(ctx->pending_app_data, decrypted, decrypted_len);
                        ctx->pending_app_data_len = decrypted_len;
                    }
                }
                free(decrypted);
                continue;
            }
            if(content_type != TLS_RECORD_HANDSHAKE) {
                noxtls_debug_printf("[TLS13_DEBUG] recv_handshake: inner type=%u len=%u\n", content_type, decrypted_len);
                free(decrypted);
                return NOXTLS_RETURN_FAILED;
            }
            /* EndOfEarlyData is handshake type 5 */
            if(decrypted_len >= 1 && decrypted[0] == TLS_HANDSHAKE_END_OF_EARLY_DATA) {
                ctx->end_of_early_data_seen = 1;
            }
            if(tls13_is_dtls(ctx)) {
                dtls_context_t *dctx = &ctx->base;
                tls13_dtls_ack_range_add(dctx, (uint16_t)dctx->epoch, dctx->read_seq_num);
                dctx->ack_pending = 1;
            }
            rc = tls13_handshake_buffer_append(ctx, decrypted, decrypted_len);
            free(decrypted);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            rc = tls13_handshake_buffer_get(ctx, out_msg, out_len);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                if(tls13_is_ack_message(*out_msg, *out_len)) {
                    tls13_dtls_handle_ack(ctx, *out_msg, *out_len);
                    free(*out_msg);
                    *out_msg = NULL;
                    *out_len = 0;
                    continue;
                }
                return rc;
            }
            continue;
        }

        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
}

/**
 * @brief Initialize TLS 1.3 context
 */
noxtls_return_t tls13_context_init(tls13_context_t *ctx, tls_role_t role)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* TLS 1.3 uses 0x0303 in the record layer */
    if(dtls_context_init(&ctx->base, role, TLS_VERSION_1_2) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    
    memset(ctx->client_random, 0, sizeof(ctx->client_random));
    memset(ctx->server_random, 0, sizeof(ctx->server_random));
    ctx->cipher_suite = 0;
    memset(ctx->early_secret, 0, sizeof(ctx->early_secret));
    memset(ctx->handshake_secret, 0, sizeof(ctx->handshake_secret));
    memset(ctx->master_secret, 0, sizeof(ctx->master_secret));
    ctx->client_seq_num = 0;
    ctx->server_seq_num = 0;
    ctx->server_cert = NULL;
    ctx->server_cert_len = 0;
    ctx->server_cert_parsed = NULL;
    ctx->handshake_messages = NULL;
    ctx->handshake_messages_len = 0;
    ctx->handshake_buffer = NULL;
    ctx->handshake_buffer_len = 0;
    ctx->handshake_buffer_pos = 0;
    ctx->handshake_encrypted = 0;
    ctx->handshake_next_at_record_boundary = 0;
    ctx->client_key_shares = NULL;
    ctx->client_key_shares_count = 0;
    ctx->server_key_share = NULL;
    ctx->ecdhe_ctx = NULL;
    ctx->server_name = NULL;
    ctx->server_name_len = 0;
    ctx->server_private_rsa = NULL;
    ctx->crypto_provider = NULL;
    ctx->server_private_key_handle = NULL;
    ctx->request_client_auth = 0;
    ctx->client_auth_requested = 0;
    ctx->cert_request_context_len = 0;
    ctx->client_cert = NULL;
    ctx->client_cert_len = 0;
    ctx->client_cert_parsed = NULL;
    ctx->client_private_rsa = NULL;
    ctx->client_private_ecdsa = NULL;
    memset(ctx->client_private_ed25519, 0, sizeof(ctx->client_private_ed25519));
    ctx->client_cert_use_ed25519 = 0;
    memset(ctx->client_private_ed448, 0, sizeof(ctx->client_private_ed448));
    ctx->client_cert_use_ed448 = 0;
    ctx->client_private_key_handle = NULL;
    ctx->prefer_chacha20 = 0;
    memset(ctx->psk_identity, 0, sizeof(ctx->psk_identity));
    ctx->psk_identity_len = 0;
    memset(ctx->psk_key, 0, sizeof(ctx->psk_key));
    ctx->psk_key_len = 0;
    ctx->psk_configured = 0;
    ctx->psk_preferred_mode = TLS13_PSK_KE_MODE_PSK_DHE_KE;
    ctx->psk_in_use = 0;
    ctx->psk_use_ecdhe = 0;
    ctx->psk_selected_identity = 0;

    ctx->ticket_identity_len = 0;
    ctx->ticket_nonce_len = 0;
    ctx->resumption_psk_len = 0;
    ctx->ticket_age_add = 0;
    ctx->ticket_cipher_suite = 0;
    ctx->ticket_stored = 0;
    ctx->pending_app_data = NULL;
    ctx->pending_app_data_len = 0;
    ctx->pending_handshake_msg = NULL;
    ctx->pending_handshake_len = 0;
    memset(ctx->ticket_identity, 0, sizeof(ctx->ticket_identity));
    memset(ctx->ticket_nonce, 0, sizeof(ctx->ticket_nonce));
    memset(ctx->resumption_psk, 0, sizeof(ctx->resumption_psk));
    ctx->early_data_phase = 0;
    ctx->early_data_accepted = 0;
    ctx->sent_end_of_early_data = 0;
    ctx->early_data_sent = 0;
    ctx->client_offered_early_data = 0;
    ctx->end_of_early_data_seen = 0;
    ctx->max_early_data_size = 0xFFFFFFFFu;
    ctx->peer_connection_id_len = 0;
    ctx->own_connection_id_len = 0;
    ctx->early_seq_num = 0;
    ctx->record_workspace = NULL;
    ctx->handshake_workspace = NULL;

    /* Reusable record workspace: 2 * (TLS_MAX_RECORD_SIZE + 32) for inner + encrypted (or decrypted) */
    {
        size_t ws_size = (size_t)(TLS_MAX_RECORD_SIZE + 32) * 2;
        ctx->record_workspace = (uint8_t*)noxtls_malloc(ws_size);
        if(ctx->record_workspace == NULL) {
            dtls_context_free(&ctx->base);
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        ctx->handshake_workspace = (uint8_t*)noxtls_malloc(TLS_HANDSHAKE_WORKSPACE_SIZE);
        if(ctx->handshake_workspace == NULL) {
            noxtls_free(ctx->record_workspace);
            ctx->record_workspace = NULL;
            dtls_context_free(&ctx->base);
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }

    /* Zero extensions so tls13_context_free can safely call noxtls_tls_extensions_free */
    memset(&ctx->client_extensions, 0, sizeof(ctx->client_extensions));
    memset(&ctx->server_extensions, 0, sizeof(ctx->server_extensions));

    ctx->record_size_limit_send = 0;
    ctx->record_size_limit_recv = 0;

    return NOXTLS_RETURN_SUCCESS;
}

void tls13_set_record_size_limit(tls13_context_t *ctx, uint16_t limit)
{
    if(ctx != NULL) {
        ctx->record_size_limit_recv = limit;
    }
}

/**
 * @brief Set server RSA private key (rsa_key_t*) for CertificateVerify
 */
void tls13_set_server_private_rsa(tls13_context_t *ctx, void *rsa_key)
{
    if(ctx != NULL) {
        ctx->server_private_rsa = rsa_key;
    }
}

void tls13_request_client_auth(tls13_context_t *ctx, int request)
{
    if(ctx != NULL) {
        ctx->request_client_auth = request ? 1 : 0;
    }
}

noxtls_return_t tls13_set_client_cert(tls13_context_t *ctx, const uint8_t *cert_der, uint32_t cert_len, void *rsa_key)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(cert_der == NULL || cert_len == 0 || rsa_key == NULL) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ctx->client_cert) {
        free(ctx->client_cert);
        ctx->client_cert = NULL;
    }
    ctx->client_cert = (uint8_t*)malloc(cert_len);
    if(ctx->client_cert == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(ctx->client_cert, cert_der, cert_len);
    ctx->client_cert_len = cert_len;
    ctx->client_private_rsa = rsa_key;
    ctx->client_private_ecdsa = NULL;
    ctx->client_cert_use_ed25519 = 0;
    memset(ctx->client_private_ed25519, 0, sizeof(ctx->client_private_ed25519));
    memset(ctx->client_private_ed448, 0, sizeof(ctx->client_private_ed448));
    ctx->client_cert_use_ed448 = 0;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t tls13_set_client_cert_ecdsa(tls13_context_t *ctx, const uint8_t *cert_der, uint32_t cert_len, void *ecc_key)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(cert_der == NULL || cert_len == 0 || ecc_key == NULL) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ctx->client_cert) {
        free(ctx->client_cert);
        ctx->client_cert = NULL;
    }
    ctx->client_cert = (uint8_t*)malloc(cert_len);
    if(ctx->client_cert == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(ctx->client_cert, cert_der, cert_len);
    ctx->client_cert_len = cert_len;
    ctx->client_private_rsa = NULL;
    ctx->client_private_ecdsa = ecc_key;
    ctx->client_cert_use_ed25519 = 0;
    memset(ctx->client_private_ed25519, 0, sizeof(ctx->client_private_ed25519));
    memset(ctx->client_private_ed448, 0, sizeof(ctx->client_private_ed448));
    ctx->client_cert_use_ed448 = 0;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t tls13_set_client_cert_ed25519(tls13_context_t *ctx, const uint8_t *cert_der, uint32_t cert_len, const uint8_t *private_key_32)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(cert_der == NULL || cert_len == 0 || private_key_32 == NULL) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ctx->client_cert) {
        free(ctx->client_cert);
        ctx->client_cert = NULL;
    }
    ctx->client_cert = (uint8_t*)malloc(cert_len);
    if(ctx->client_cert == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(ctx->client_cert, cert_der, cert_len);
    ctx->client_cert_len = cert_len;
    ctx->client_private_rsa = NULL;
    ctx->client_private_ecdsa = NULL;
    memcpy(ctx->client_private_ed25519, private_key_32, 32);
    ctx->client_cert_use_ed25519 = 1;
    memset(ctx->client_private_ed448, 0, sizeof(ctx->client_private_ed448));
    ctx->client_cert_use_ed448 = 0;
    return NOXTLS_RETURN_SUCCESS;
}

#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
noxtls_return_t tls13_set_client_cert_ed448(tls13_context_t *ctx, const uint8_t *cert_der, uint32_t cert_len, const uint8_t *private_key_57)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(cert_der == NULL || cert_len == 0 || private_key_57 == NULL) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ctx->client_cert) {
        free(ctx->client_cert);
        ctx->client_cert = NULL;
    }
    ctx->client_cert = (uint8_t*)malloc(cert_len);
    if(ctx->client_cert == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(ctx->client_cert, cert_der, cert_len);
    ctx->client_cert_len = cert_len;
    ctx->client_private_rsa = NULL;
    ctx->client_private_ecdsa = NULL;
    ctx->client_cert_use_ed25519 = 0;
    memset(ctx->client_private_ed25519, 0, sizeof(ctx->client_private_ed25519));
    memcpy(ctx->client_private_ed448, private_key_57, 57);
    ctx->client_cert_use_ed448 = 1;
    return NOXTLS_RETURN_SUCCESS;
}
#else
noxtls_return_t tls13_set_client_cert_ed448(tls13_context_t *ctx, const uint8_t *cert_der, uint32_t cert_len, const uint8_t *private_key_57)
{
    (void)ctx;
    (void)cert_der;
    (void)cert_len;
    (void)private_key_57;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}
#endif

noxtls_return_t tls13_set_external_psk(tls13_context_t *ctx,
                                       const uint8_t *identity, uint16_t identity_len,
                                       const uint8_t *psk_key, uint16_t psk_key_len,
                                       uint8_t preferred_mode)
{
    if(ctx == NULL || identity == NULL || psk_key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(identity_len == 0 || identity_len > sizeof(ctx->psk_identity) ||
       psk_key_len == 0 || psk_key_len > sizeof(ctx->psk_key)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(preferred_mode != TLS13_PSK_KE_MODE_PSK_KE &&
       preferred_mode != TLS13_PSK_KE_MODE_PSK_DHE_KE) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    memset(ctx->psk_identity, 0, sizeof(ctx->psk_identity));
    memcpy(ctx->psk_identity, identity, identity_len);
    ctx->psk_identity_len = identity_len;
    memset(ctx->psk_key, 0, sizeof(ctx->psk_key));
    memcpy(ctx->psk_key, psk_key, psk_key_len);
    ctx->psk_key_len = psk_key_len;
    ctx->psk_configured = 1;
    ctx->psk_preferred_mode = preferred_mode;
    ctx->psk_in_use = 0;
    ctx->psk_use_ecdhe = 0;
    ctx->psk_selected_identity = 0;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Free TLS 1.3 context
 */
noxtls_return_t tls13_context_free(tls13_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->server_cert) {
        free(ctx->server_cert);
        ctx->server_cert = NULL;
    }
    
    if(ctx->server_cert_parsed) {
        noxtls_x509_certificate_free((x509_certificate_t*)ctx->server_cert_parsed);
        free(ctx->server_cert_parsed);
        ctx->server_cert_parsed = NULL;
    }
    if(ctx->client_cert) {
        free(ctx->client_cert);
        ctx->client_cert = NULL;
    }
    ctx->client_cert_len = 0;
    ctx->client_private_rsa = NULL;
    ctx->client_private_ecdsa = NULL;
    memset(ctx->client_private_ed25519, 0, sizeof(ctx->client_private_ed25519));
    ctx->client_cert_use_ed25519 = 0;
    memset(ctx->client_private_ed448, 0, sizeof(ctx->client_private_ed448));
    ctx->client_cert_use_ed448 = 0;
    if(ctx->client_cert_parsed) {
        noxtls_x509_certificate_free((x509_certificate_t*)ctx->client_cert_parsed);
        free(ctx->client_cert_parsed);
        ctx->client_cert_parsed = NULL;
    }
    if(ctx->pending_handshake_msg) {
        free(ctx->pending_handshake_msg);
        ctx->pending_handshake_msg = NULL;
    }
    ctx->pending_handshake_len = 0;
    
    if(ctx->handshake_messages) {
        free(ctx->handshake_messages);
        ctx->handshake_messages = NULL;
    }
    if(ctx->handshake_buffer) {
        free(ctx->handshake_buffer);
        ctx->handshake_buffer = NULL;
    }
    ctx->handshake_buffer_len = 0;
    ctx->handshake_buffer_pos = 0;
    ctx->handshake_next_at_record_boundary = 0;
    if(ctx->record_workspace) {
        noxtls_free(ctx->record_workspace);
        ctx->record_workspace = NULL;
    }
    if(ctx->handshake_workspace) {
        memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        noxtls_free(ctx->handshake_workspace);
        ctx->handshake_workspace = NULL;
    }

    if(ctx->client_key_shares) {
        for(uint32_t i = 0; i < ctx->client_key_shares_count; i++) {
            if(ctx->client_key_shares[i].key_exchange) {
                free(ctx->client_key_shares[i].key_exchange);
            }
        }
        free(ctx->client_key_shares);
        ctx->client_key_shares = NULL;
    }
    
    if(ctx->server_key_share) {
        if(ctx->server_key_share->key_exchange) {
            free(ctx->server_key_share->key_exchange);
        }
        free(ctx->server_key_share);
        ctx->server_key_share = NULL;
    }

    if(ctx->ecdhe_ctx) {
        tls_ecdhe_context_free((tls_ecdhe_context_t*)ctx->ecdhe_ctx);
        free(ctx->ecdhe_ctx);
        ctx->ecdhe_ctx = NULL;
    }
    
    /* Free extensions */
    noxtls_tls_extensions_free(&ctx->client_extensions);
    noxtls_tls_extensions_free(&ctx->server_extensions);

    memset(ctx->psk_key, 0, sizeof(ctx->psk_key));
    ctx->psk_key_len = 0;
    ctx->psk_configured = 0;
    ctx->psk_in_use = 0;
    ctx->psk_use_ecdhe = 0;

    if(ctx->pending_app_data) {
        free(ctx->pending_app_data);
        ctx->pending_app_data = NULL;
    }
    ctx->pending_app_data_len = 0;
    memset(ctx->ticket_identity, 0, sizeof(ctx->ticket_identity));
    memset(ctx->ticket_nonce, 0, sizeof(ctx->ticket_nonce));
    memset(ctx->resumption_psk, 0, sizeof(ctx->resumption_psk));
    ctx->ticket_stored = 0;

    dtls_context_free(&ctx->base);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.3 Client: Send Client Hello
 */
noxtls_return_t tls13_send_client_hello(tls13_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    uint8_t *client_hello = ctx->handshake_workspace;
    if(client_hello == NULL) {
        client_hello = (uint8_t*)noxtls_malloc(TLS_CLIENT_HELLO_DEFAULT_SIZE);
        if(client_hello == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    uint8_t *key_share_entry = (ctx->handshake_workspace != NULL) ? (ctx->handshake_workspace + 1024) : (client_hello + 1024);
    uint32_t key_share_entry_len = TLS_KEY_SHARE_ENTRY_MAX_LEN;
    uint32_t offset = 0;
    drbg_state_t drbg_state;
    uint16_t cipher_suites[] = {
        TLS_CIPHER_SUITE_AES_128_GCM_SHA256,
        TLS_CIPHER_SUITE_AES_128_CCM_SHA256,
        TLS_CIPHER_SUITE_AES_128_CCM_8_SHA256,
        TLS_CIPHER_SUITE_AES_256_GCM_SHA384,
        TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256
        /* Note: ARIA GCM suites for TLS 1.3 would need to be defined if supported */
    };
    uint16_t supported_groups[] = {
        TLS_NAMED_GROUP_SECP256R1,
        TLS_NAMED_GROUP_SECP384R1
    };
    uint16_t signature_algorithms[] = {
        TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256,
        TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256,
        TLS_SIGSCHEME_ED25519,
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
        TLS_SIGSCHEME_ED448,
#endif
        0x0401, /* rsa_pkcs1_sha256 */
        TLS_SIGSCHEME_ECDSA_SECP384R1_SHA384,
        0x0805  /* rsa_pss_rsae_sha384 */
    };
    tls_ecdhe_context_t *ecdhe_ctx = NULL;
    int offer_psk = 0;
    int offer_resumption = 0;
    int offer_external_psk = 0;
    int include_key_share = 1;
    noxtls_hash_algos_t psk_hash_algo = NOXTLS_HASH_SHA_256;
    uint32_t psk_hash_len = 0;
    uint32_t psk_key_len = 0;
    uint32_t resumption_binder_offset = 0;
    uint32_t external_binder_offset = 0;
    uint16_t psk_binder_len = 0;
    
    ctx->psk_in_use = 0;
    ctx->psk_use_ecdhe = 0;
    ctx->psk_selected_identity = 0;
    offer_resumption = (ctx->ticket_stored && ctx->ticket_identity_len > 0 && ctx->resumption_psk_len > 0);
    offer_external_psk = (ctx->psk_configured && ctx->psk_identity_len > 0 && ctx->psk_key_len > 0);
    offer_psk = offer_resumption || offer_external_psk;
    if(offer_psk) {
        uint16_t cs = offer_resumption ? ctx->ticket_cipher_suite : cipher_suites[0];
        if(tls13_get_cipher_params(cs, &psk_hash_algo, &psk_hash_len, &psk_key_len) != NOXTLS_RETURN_SUCCESS) {
            if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
    }
    include_key_share = (!offer_psk || ctx->psk_preferred_mode == TLS13_PSK_KE_MODE_PSK_DHE_KE);
    
    /* Generate client random */
    if(drbg_instantiate(&drbg_state, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    if(drbg_generate(&drbg_state, ctx->client_random, sizeof(ctx->client_random) * 8u, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_debug_printf("[TLS13_DEBUG] client_random=");
    for(uint32_t i = 0; i < 32; i++) {
        noxtls_debug_printf("%02X", ctx->client_random[i]);
    }
    noxtls_debug_printf("\n");
    
    /* Build Client Hello message */
    client_hello[offset++] = TLS_HANDSHAKE_CLIENT_HELLO;
    client_hello[offset++] = 0x00;  /* Length (3 bytes) - placeholder */
    client_hello[offset++] = 0x00;
    client_hello[offset++] = 0x00;
    
    /* Legacy version (for compatibility) */
    if(tls13_is_dtls(ctx)) {
        client_hello[offset++] = (DTLS_VERSION_1_2 >> 8) & 0xFF;
        client_hello[offset++] = DTLS_VERSION_1_2 & 0xFF;
    } else {
        client_hello[offset++] = 0x03;
        client_hello[offset++] = 0x03;
    }
    
    /* Random (32 bytes) */
    memcpy(client_hello + offset, ctx->client_random, TLS_RANDOM_SIZE);
    offset += TLS_RANDOM_SIZE;
    
    /* Legacy session ID length (1 byte) */
    uint8_t session_id[TLS_SESSION_ID_MAX_LEN];
    if(drbg_generate(&drbg_state, session_id, sizeof(session_id) * 8u, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    client_hello[offset++] = (uint8_t)sizeof(session_id);
    memcpy(client_hello + offset, session_id, sizeof(session_id));
    offset += sizeof(session_id);
    
    /* Cipher suites length (2 bytes) */
    uint16_t cipher_suites_len = sizeof(cipher_suites);
    client_hello[offset++] = (cipher_suites_len >> 8) & 0xFF;
    client_hello[offset++] = cipher_suites_len & 0xFF;
    
    /* Cipher suites (network byte order) */
    for(uint32_t i = 0; i < sizeof(cipher_suites) / sizeof(cipher_suites[0]); i++) {
        client_hello[offset++] = (cipher_suites[i] >> 8) & 0xFF;
        client_hello[offset++] = cipher_suites[i] & 0xFF;
    }
    
    /* Legacy compression methods length (1 byte) */
    client_hello[offset++] = 0x01;
    client_hello[offset++] = 0x00;  /* NULL compression */
    
    /* Extensions length (2 bytes) - placeholder */
    uint32_t extensions_start = offset;
    client_hello[offset++] = 0x00;
    client_hello[offset++] = 0x00;
    
    /* Ensure ECDHE context and key share only when ECDHE is offered */
    if(include_key_share) {
        if(ctx->ecdhe_ctx == NULL) {
            ecdhe_ctx = (tls_ecdhe_context_t*)malloc(sizeof(tls_ecdhe_context_t));
            if(ecdhe_ctx == NULL) {
                if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                return NOXTLS_RETURN_FAILED;
            }
            if(tls_ecdhe_context_init(ecdhe_ctx, TLS_NAMED_GROUP_SECP256R1) != NOXTLS_RETURN_SUCCESS) {
                free(ecdhe_ctx);
                if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                return NOXTLS_RETURN_FAILED;
            }
            if(tls_ecdhe_generate_ephemeral_key(ecdhe_ctx) != NOXTLS_RETURN_SUCCESS) {
                tls_ecdhe_context_free(ecdhe_ctx);
                free(ecdhe_ctx);
                if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                return NOXTLS_RETURN_FAILED;
            }
            ctx->ecdhe_ctx = ecdhe_ctx;
        } else {
            ecdhe_ctx = (tls_ecdhe_context_t*)ctx->ecdhe_ctx;
        }

        if(tls13_key_share_encode(ecdhe_ctx, key_share_entry, &key_share_entry_len) != NOXTLS_RETURN_SUCCESS) {
            if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
        if(key_share_entry_len >= 8) {
            noxtls_debug_printf("[TLS13_DEBUG] client_key_share: group=0x%04X key[0..3]=%02X%02X%02X%02X\n",
                                  ecdhe_ctx->named_group,
                                  key_share_entry[4], key_share_entry[5], key_share_entry[6], key_share_entry[7]);
        }
    }

    if(ctx->client_key_shares) {
        for(uint32_t i = 0; i < ctx->client_key_shares_count; i++) {
            if(ctx->client_key_shares[i].key_exchange) {
                free(ctx->client_key_shares[i].key_exchange);
            }
        }
        free(ctx->client_key_shares);
        ctx->client_key_shares = NULL;
        ctx->client_key_shares_count = 0;
    }
    if(include_key_share) {
        ctx->client_key_shares = (tls13_key_share_entry_t*)malloc(sizeof(tls13_key_share_entry_t));
        if(ctx->client_key_shares == NULL) {
            if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
        ctx->client_key_shares_count = 1;
        ctx->client_key_shares[0].group = ecdhe_ctx->named_group;
        ctx->client_key_shares[0].key_exchange_len = (uint16_t)(key_share_entry_len - 4);
        ctx->client_key_shares[0].key_exchange = (uint8_t*)malloc(ctx->client_key_shares[0].key_exchange_len);
        if(ctx->client_key_shares[0].key_exchange == NULL) {
            free(ctx->client_key_shares);
            ctx->client_key_shares = NULL;
            if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(ctx->client_key_shares[0].key_exchange, key_share_entry + 4, ctx->client_key_shares[0].key_exchange_len);
    }
    
    /* Server Name (SNI) */
    if(ctx->server_name != NULL && ctx->server_name_len > 0) {
        uint32_t ext_start = offset;
        uint32_t sni_list_len = 1 + 2 + ctx->server_name_len;
        uint32_t sni_ext_len = 2 + sni_list_len;
        client_hello[offset++] = (TLS_EXTENSION_SERVER_NAME >> 8) & 0xFF;
        client_hello[offset++] = TLS_EXTENSION_SERVER_NAME & 0xFF;
        client_hello[offset++] = (sni_ext_len >> 8) & 0xFF;
        client_hello[offset++] = sni_ext_len & 0xFF;
        client_hello[offset++] = (sni_list_len >> 8) & 0xFF;
        client_hello[offset++] = sni_list_len & 0xFF;
        client_hello[offset++] = 0x00; /* host_name */
        client_hello[offset++] = (ctx->server_name_len >> 8) & 0xFF;
        client_hello[offset++] = ctx->server_name_len & 0xFF;
        memcpy(client_hello + offset, ctx->server_name, ctx->server_name_len);
        offset += ctx->server_name_len;
        (void)ext_start;
    }

    /* Supported Versions */
    client_hello[offset++] = (TLS_EXTENSION_SUPPORTED_VERSIONS >> 8) & 0xFF;
    client_hello[offset++] = TLS_EXTENSION_SUPPORTED_VERSIONS & 0xFF;
    client_hello[offset++] = 0x00;
    client_hello[offset++] = 0x05;
    client_hello[offset++] = 0x04;
    client_hello[offset++] = 0x03;
    client_hello[offset++] = 0x04;
    client_hello[offset++] = 0x03;
    client_hello[offset++] = 0x03;

    /* Supported Groups */
    client_hello[offset++] = (TLS_EXTENSION_SUPPORTED_GROUPS >> 8) & 0xFF;
    client_hello[offset++] = TLS_EXTENSION_SUPPORTED_GROUPS & 0xFF;
    uint16_t groups_len = sizeof(supported_groups);
    client_hello[offset++] = (uint8_t)((groups_len + 2) >> 8);
    client_hello[offset++] = (uint8_t)((groups_len + 2) & 0xFF);
    client_hello[offset++] = (groups_len >> 8) & 0xFF;
    client_hello[offset++] = groups_len & 0xFF;
    for(uint32_t i = 0; i < sizeof(supported_groups) / sizeof(supported_groups[0]); i++) {
        client_hello[offset++] = (supported_groups[i] >> 8) & 0xFF;
        client_hello[offset++] = supported_groups[i] & 0xFF;
    }

    /* Signature Algorithms */
    client_hello[offset++] = (TLS_EXTENSION_SIGNATURE_ALGORITHMS >> 8) & 0xFF;
    client_hello[offset++] = TLS_EXTENSION_SIGNATURE_ALGORITHMS & 0xFF;
    uint16_t sig_len = sizeof(signature_algorithms);
    client_hello[offset++] = (uint8_t)((sig_len + 2) >> 8);
    client_hello[offset++] = (uint8_t)((sig_len + 2) & 0xFF);
    client_hello[offset++] = (sig_len >> 8) & 0xFF;
    client_hello[offset++] = sig_len & 0xFF;
    for(uint32_t i = 0; i < sizeof(signature_algorithms) / sizeof(signature_algorithms[0]); i++) {
        client_hello[offset++] = (signature_algorithms[i] >> 8) & 0xFF;
        client_hello[offset++] = signature_algorithms[i] & 0xFF;
    }

    /* RFC 8449 Record Size Limit: max plaintext we are willing to receive */
    if(ctx->record_size_limit_recv > 0) {
        uint16_t rsl = ctx->record_size_limit_recv;
        client_hello[offset++] = (TLS_EXTENSION_RECORD_SIZE_LIMIT >> 8) & 0xFF;
        client_hello[offset++] = TLS_EXTENSION_RECORD_SIZE_LIMIT & 0xFF;
        client_hello[offset++] = 0x00;
        client_hello[offset++] = 0x02;
        client_hello[offset++] = (rsl >> 8) & 0xFF;
        client_hello[offset++] = rsl & 0xFF;
    }

    /* Key Share (required for normal TLS 1.3 and ECDHE-PSK) */
    if(include_key_share) {
        uint16_t key_share_list_len = (uint16_t)key_share_entry_len;
        uint16_t key_share_ext_len = (uint16_t)(key_share_entry_len + 2);
        client_hello[offset++] = (TLS_EXTENSION_KEY_SHARE >> 8) & 0xFF;
        client_hello[offset++] = TLS_EXTENSION_KEY_SHARE & 0xFF;
        client_hello[offset++] = (key_share_ext_len >> 8) & 0xFF;
        client_hello[offset++] = key_share_ext_len & 0xFF;
        client_hello[offset++] = (key_share_list_len >> 8) & 0xFF;
        client_hello[offset++] = key_share_list_len & 0xFF;
        memcpy(client_hello + offset, key_share_entry, key_share_entry_len);
        offset += key_share_entry_len;
    }

    /* Cookie (DTLS 1.3 HelloRetryRequest) */
    if(tls13_is_dtls(ctx) && ctx->base.cookie_len > 0) {
        uint16_t cookie_ext_len = (uint16_t)ctx->base.cookie_len;
        client_hello[offset++] = (TLS_EXTENSION_COOKIE >> 8) & 0xFF;
        client_hello[offset++] = TLS_EXTENSION_COOKIE & 0xFF;
        client_hello[offset++] = (cookie_ext_len >> 8) & 0xFF;
        client_hello[offset++] = cookie_ext_len & 0xFF;
        memcpy(client_hello + offset, ctx->base.cookie, ctx->base.cookie_len);
        offset += ctx->base.cookie_len;
    }

    /* Connection ID (RFC 9146/9147): DTLS 1.3 only; zero-length = prepared but no CID requested */
    if(tls13_is_dtls(ctx)) {
        client_hello[offset++] = (TLS_EXTENSION_CONNECTION_ID >> 8) & 0xFF;
        client_hello[offset++] = TLS_EXTENSION_CONNECTION_ID & 0xFF;
        client_hello[offset++] = 0x00;
        client_hello[offset++] = 0x01;  /* extension data length */
        client_hello[offset++] = 0x00;  /* ConnectionId: zero-length cid */
    }

    if(offer_psk) {
        uint8_t modes_len = include_key_share ? 2 : 1;
        client_hello[offset++] = (TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES >> 8) & 0xFF;
        client_hello[offset++] = TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES & 0xFF;
        client_hello[offset++] = 0x00;
        client_hello[offset++] = (uint8_t)(1 + modes_len);
        client_hello[offset++] = modes_len;
        if(include_key_share) {
            client_hello[offset++] = TLS13_PSK_KE_MODE_PSK_DHE_KE;
            client_hello[offset++] = TLS13_PSK_KE_MODE_PSK_KE;
        } else {
            client_hello[offset++] = TLS13_PSK_KE_MODE_PSK_KE;
        }

        /* early_data (RFC 8446 4.2.10): offer 0-RTT when resuming */
        if(offer_resumption) {
            client_hello[offset++] = (TLS_EXTENSION_EARLY_DATA >> 8) & 0xFF;
            client_hello[offset++] = TLS_EXTENSION_EARLY_DATA & 0xFF;
            client_hello[offset++] = 0x00;
            client_hello[offset++] = 0x00;
        }

        /* pre_shared_key must be the last ClientHello extension */
        client_hello[offset++] = (TLS_EXTENSION_PRE_SHARED_KEY >> 8) & 0xFF;
        client_hello[offset++] = TLS_EXTENSION_PRE_SHARED_KEY & 0xFF;
        {
            uint32_t psk_ext_len_pos = offset;
            uint32_t psk_ext_start;
            uint16_t psk_identities_len = 0;
            uint16_t psk_binders_len;
            uint32_t identities_start;

            client_hello[offset++] = 0x00;
            client_hello[offset++] = 0x00;
            psk_ext_start = offset;

            identities_start = offset + 2;
            if(offer_resumption) {
                psk_identities_len += (uint16_t)(2 + ctx->ticket_identity_len + 4);
            }
            if(offer_external_psk) {
                psk_identities_len += (uint16_t)(2 + ctx->psk_identity_len + 4);
            }
            client_hello[offset++] = (uint8_t)(psk_identities_len >> 8);
            client_hello[offset++] = (uint8_t)(psk_identities_len & 0xFF);

            if(offer_resumption) {
                client_hello[offset++] = (uint8_t)(ctx->ticket_identity_len >> 8);
                client_hello[offset++] = (uint8_t)(ctx->ticket_identity_len & 0xFF);
                memcpy(client_hello + offset, ctx->ticket_identity, ctx->ticket_identity_len);
                offset += ctx->ticket_identity_len;
                client_hello[offset++] = 0x00;
                client_hello[offset++] = 0x00;
                client_hello[offset++] = 0x00;
                client_hello[offset++] = 0x00;
            }
            if(offer_external_psk) {
                client_hello[offset++] = (uint8_t)(ctx->psk_identity_len >> 8);
                client_hello[offset++] = (uint8_t)(ctx->psk_identity_len & 0xFF);
                memcpy(client_hello + offset, ctx->psk_identity, ctx->psk_identity_len);
                offset += ctx->psk_identity_len;
                client_hello[offset++] = 0x00;
                client_hello[offset++] = 0x00;
                client_hello[offset++] = 0x00;
                client_hello[offset++] = 0x00;
            }

            psk_binder_len = (uint16_t)psk_hash_len;
            psk_binders_len = (uint16_t)((offer_resumption ? (1u + psk_binder_len) : 0) + (offer_external_psk ? (1u + psk_binder_len) : 0));
            client_hello[offset++] = (uint8_t)(psk_binders_len >> 8);
            client_hello[offset++] = (uint8_t)(psk_binders_len & 0xFF);
            if(offer_resumption) {
                client_hello[offset++] = (uint8_t)psk_binder_len;
                resumption_binder_offset = offset;
                memset(client_hello + offset, 0, psk_binder_len);
                offset += psk_binder_len;
            }
            if(offer_external_psk) {
                client_hello[offset++] = (uint8_t)psk_binder_len;
                external_binder_offset = offset;
                memset(client_hello + offset, 0, psk_binder_len);
                offset += psk_binder_len;
            }

            {
                uint16_t psk_ext_len = (uint16_t)(offset - psk_ext_start);
                client_hello[psk_ext_len_pos] = (uint8_t)(psk_ext_len >> 8);
                client_hello[psk_ext_len_pos + 1] = (uint8_t)(psk_ext_len & 0xFF);
            }
            (void)identities_start;
        }
    }

    /* Update extensions length */
    uint32_t extensions_len32 = offset - extensions_start - 2;
    if(extensions_len32 > UINT16_MAX) {
        if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    uint16_t extensions_len = (uint16_t)extensions_len32;
    client_hello[extensions_start] = (extensions_len >> 8) & 0xFF;
    client_hello[extensions_start + 1] = extensions_len & 0xFF;
    
    /* Update handshake message length */
    uint32_t handshake_len = offset - 4;
    client_hello[1] = (handshake_len >> 16) & 0xFF;
    client_hello[2] = (handshake_len >> 8) & 0xFF;
    client_hello[3] = handshake_len & 0xFF;
    if(offer_psk && psk_binder_len > 0) {
        uint8_t binder[64];
        noxtls_return_t psk_rc;
        if(offer_resumption && resumption_binder_offset > 0) {
            psk_rc = tls13_psk_compute_resumption_binder(psk_hash_algo,
                                                         ctx->resumption_psk, ctx->resumption_psk_len,
                                                         ctx->ticket_nonce, ctx->ticket_nonce_len,
                                                         client_hello, offset,
                                                         resumption_binder_offset, psk_binder_len,
                                                         binder);
            if(psk_rc != NOXTLS_RETURN_SUCCESS) {
                if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                return psk_rc;
            }
            memcpy(client_hello + resumption_binder_offset, binder, psk_binder_len);
        }
        if(offer_external_psk && external_binder_offset > 0) {
            psk_rc = tls13_psk_compute_external_binder(psk_hash_algo,
                                                       ctx->psk_key, ctx->psk_key_len,
                                                       client_hello, offset,
                                                       external_binder_offset, psk_binder_len,
                                                       binder);
            if(psk_rc != NOXTLS_RETURN_SUCCESS) {
                if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                return psk_rc;
            }
            memcpy(client_hello + external_binder_offset, binder, psk_binder_len);
        }
    }
    noxtls_debug_printf("[TLS13_DEBUG] client_hello: len=%u\n", handshake_len + 4);
    
    /* Append to handshake transcript */
    tls13_append_handshake_message(ctx, client_hello, offset);

    noxtls_debug_printf("[TLS13_DEBUG] client_hello hex:\n");
    for(uint32_t i = 0; i < offset; i++) {
        noxtls_debug_printf("%02X", client_hello[i]);
        if(((i + 1) & 31) == 0) {
            noxtls_debug_printf("\n");
        }
    }
    if(offset % 32 != 0) {
        noxtls_debug_printf("\n");
    }

    /* Send via record layer */
    {
        noxtls_return_t send_rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, client_hello, offset);
        if(client_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(client_hello, 1024 + 256); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        if(send_rc == NOXTLS_RETURN_SUCCESS) {
            NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_HANDSHAKE, NOXSIGHT_SEVERITY_INFO,
                            NOXTLS_EVT_CLIENT_HELLO_SENT, offset, 0u);
        } else {
            NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_IO, NOXSIGHT_SEVERITY_ERROR,
                            NOXTLS_EVT_INTERNAL_ERROR, NOXTLS_EVT_CLIENT_HELLO_SENT, send_rc);
        }
        return send_rc;
    }
}

/**
 * @brief TLS 1.3 Client: Receive Server Hello
 */
noxtls_return_t tls13_recv_server_hello(tls13_context_t *ctx)
{
    tls_record_t record;
    noxtls_return_t rc;
    int is_hrr = 0;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    rc = noxtls_tls_recv_record(&ctx->base.base, &record);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_IO, NOXSIGHT_SEVERITY_ERROR,
                        NOXTLS_EVT_INTERNAL_ERROR, NOXTLS_EVT_SERVER_HELLO_RECV, rc);
        return rc;
    }
    if(record.length > 0 && record.data == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: record type=%u len=%u\n", record.type, record.length);
    if(record.type != TLS_RECORD_HANDSHAKE || record.length < 42) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: hs_type=0x%02X\n", record.data[0]);
    if(record.data[0] != TLS_HANDSHAKE_SERVER_HELLO) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    if(record.length >= 4) {
        uint32_t hs_len = ((uint32_t)record.data[1] << 16) | ((uint32_t)record.data[2] << 8) | record.data[3];
        noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: hs_len=%u\n", hs_len);
    }
    noxtls_debug_printf("[TLS13_DEBUG] server_hello hex:\n");
    for(uint32_t i = 0; i < record.length; i++) {
        noxtls_debug_printf("%02X", record.data[i]);
        if(((i + 1) & 31) == 0) {
            noxtls_debug_printf("\n");
        }
    }
    if((record.length & 31) != 0) {
        noxtls_debug_printf("\n");
    }

    /* Parse Server Hello */
    uint32_t offset = 4; /* Skip handshake header */
    if(offset + 2 + TLS_RANDOM_SIZE + 1 > record.length) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    offset += 2; /* legacy_version */
    memcpy(ctx->server_random, record.data + offset, TLS_RANDOM_SIZE);
    noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: server_random[0..3]=%02X%02X%02X%02X\n",
                          ctx->server_random[0], ctx->server_random[1], ctx->server_random[2], ctx->server_random[3]);
    {
        static const uint8_t hrr_random[TLS_RANDOM_SIZE] = {
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
            0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
            0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
        };
        if(memcmp(ctx->server_random, hrr_random, sizeof(hrr_random)) == 0) {
            noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: detected HelloRetryRequest (HRR)\n");
            if(tls13_is_dtls(ctx)) {
                is_hrr = 1;
            }
        }
    }
    offset += TLS_RANDOM_SIZE;

    uint8_t session_id_len = record.data[offset++];
    if(offset + session_id_len + 2 + 1 + 2 > record.length) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    offset += session_id_len;

    ctx->cipher_suite = (record.data[offset] << 8) | record.data[offset + 1];
    noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: cipher_suite=0x%04X\n", ctx->cipher_suite);
    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_HANDSHAKE, NOXSIGHT_SEVERITY_INFO,
                    NOXTLS_EVT_SERVER_HELLO_RECV, ctx->cipher_suite, record.length);
    offset += 2;

    offset += 1; /* legacy compression method */

    if(offset + 2 > record.length) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }

    /* Parse extensions */
    noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: extensions_len=%u\n", (unsigned)(record.length - offset));
    if(noxtls_tls_parse_extensions(record.data + offset, record.length - offset, &ctx->server_extensions) != NOXTLS_RETURN_SUCCESS) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    if(is_hrr) {
        noxtls_hash_algos_t hash_algo;
        uint32_t hash_len;
        uint32_t key_len;
        tls_extension_t *ext = NULL;
        tls_extension_t *ext_keyshare = NULL;
        if(tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len) != NOXTLS_RETURN_SUCCESS) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        if(noxtls_tls_find_extension(&ctx->server_extensions, TLS_EXTENSION_COOKIE, &ext) == NOXTLS_RETURN_SUCCESS) {
            if(ext != NULL && ext->length <= sizeof(ctx->base.cookie)) {
                memcpy(ctx->base.cookie, ext->data, ext->length);
                ctx->base.cookie_len = ext->length;
            }
        }
        if(noxtls_tls_find_extension(&ctx->server_extensions, TLS_EXTENSION_KEY_SHARE, &ext_keyshare) == NOXTLS_RETURN_SUCCESS) {
            if(ext_keyshare != NULL && ext_keyshare->length >= 2) {
                uint16_t group = (ext_keyshare->data[0] << 8) | ext_keyshare->data[1];
                tls_ecdhe_context_t *ecdhe_ctx = (tls_ecdhe_context_t*)ctx->ecdhe_ctx;
                if(ecdhe_ctx == NULL || ecdhe_ctx->named_group != group) {
                    if(ecdhe_ctx) {
                        tls_ecdhe_context_free(ecdhe_ctx);
                        free(ecdhe_ctx);
                    }
                    ecdhe_ctx = (tls_ecdhe_context_t*)malloc(sizeof(tls_ecdhe_context_t));
                    if(ecdhe_ctx == NULL) {
                        if(record.data) free(record.data);
                        return NOXTLS_RETURN_FAILED;
                    }
                    if(tls_ecdhe_context_init(ecdhe_ctx, group) != NOXTLS_RETURN_SUCCESS ||
                       tls_ecdhe_generate_ephemeral_key(ecdhe_ctx) != NOXTLS_RETURN_SUCCESS) {
                        tls_ecdhe_context_free(ecdhe_ctx);
                        free(ecdhe_ctx);
                        if(record.data) free(record.data);
                        return NOXTLS_RETURN_FAILED;
                    }
                    ctx->ecdhe_ctx = ecdhe_ctx;
                }
            }
        }
        if(tls13_reset_transcript_for_hrr(ctx, hash_algo, hash_len) != NOXTLS_RETURN_SUCCESS) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        tls13_append_handshake_message(ctx, record.data, record.length);
        if(record.data) free(record.data);
        rc = tls13_send_client_hello(ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        return tls13_recv_server_hello(ctx);
    }
    
    /* Append to transcript */
    tls13_append_handshake_message(ctx, record.data, record.length);

    tls_extension_t *ext = NULL;
    if(noxtls_tls_find_extension(&ctx->server_extensions, TLS_EXTENSION_SUPPORTED_VERSIONS, &ext) == NOXTLS_RETURN_SUCCESS) {
        if(ext == NULL || ext->length != 2 || ext->data == NULL) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
        uint16_t negotiated = (ext->data[0] << 8) | ext->data[1];
        noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: supported_versions=0x%04X\n", negotiated);
        if(negotiated != TLS_VERSION_1_3) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
    } else {
        noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: supported_versions not found\n");
    }

    /* Connection ID (RFC 9147): store server's CID for use in record header when sending */
    {
        tls_extension_t *ext_cid = NULL;
        if(tls13_is_dtls(ctx) &&
           noxtls_tls_find_extension(&ctx->server_extensions, TLS_EXTENSION_CONNECTION_ID, &ext_cid) == NOXTLS_RETURN_SUCCESS &&
           ext_cid != NULL && ext_cid->length >= 1 && ext_cid->data != NULL) {
            uint8_t cid_len = ext_cid->data[0];
            if(cid_len > 0 && cid_len <= 32 && ext_cid->length >= 1u + cid_len) {
                ctx->peer_connection_id_len = cid_len;
                memcpy(ctx->peer_connection_id, ext_cid->data + 1, cid_len);
            }
        }
    }

    {
        int have_key_share = 0;
        int server_selected_psk = 0;
        uint16_t selected_identity = 0;
        const uint8_t *shared_secret = NULL;
        uint32_t shared_secret_len = 0;

        if(noxtls_tls_find_extension(&ctx->server_extensions, TLS_EXTENSION_PRE_SHARED_KEY, &ext) == NOXTLS_RETURN_SUCCESS) {
            if(ext == NULL || ext->data == NULL || ext->length != 2) {
                if(record.data) free(record.data);
                return NOXTLS_RETURN_FAILED;
            }
            selected_identity = tls13_read_uint16(ext->data);
            if(!ctx->psk_configured || selected_identity != 0) {
                if(record.data) free(record.data);
                return NOXTLS_RETURN_FAILED;
            }
            server_selected_psk = 1;
            ctx->psk_in_use = 1;
            ctx->psk_selected_identity = selected_identity;
        }

        if(noxtls_tls_find_extension(&ctx->server_extensions, TLS_EXTENSION_KEY_SHARE, &ext) == NOXTLS_RETURN_SUCCESS) {
            uint16_t group;
            uint16_t key_len;
            have_key_share = 1;
            if(ext == NULL || ext->length < 4 || ext->data == NULL) {
                if(record.data) free(record.data);
                return NOXTLS_RETURN_FAILED;
            }
            group = (uint16_t)((ext->data[0] << 8) | ext->data[1]);
            key_len = (uint16_t)((ext->data[2] << 8) | ext->data[3]);
            noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: key_share group=0x%04X len=%u\n", group, key_len);
            if(ext->length >= 8) {
                noxtls_debug_printf("[TLS13_DEBUG] server_key_share: key[0..3]=%02X%02X%02X%02X\n",
                                      ext->data[4], ext->data[5], ext->data[6], ext->data[7]);
            }
            if(4 + key_len > ext->length) {
                if(record.data) free(record.data);
                return NOXTLS_RETURN_FAILED;
            }
            if(ctx->server_key_share) {
                if(ctx->server_key_share->key_exchange) {
                    free(ctx->server_key_share->key_exchange);
                }
                free(ctx->server_key_share);
                ctx->server_key_share = NULL;
            }
            ctx->server_key_share = (tls13_key_share_entry_t*)malloc(sizeof(tls13_key_share_entry_t));
            if(ctx->server_key_share == NULL) {
                if(record.data) free(record.data);
                return NOXTLS_RETURN_FAILED;
            }
            ctx->server_key_share->group = group;
            ctx->server_key_share->key_exchange_len = key_len;
            ctx->server_key_share->key_exchange = (uint8_t*)malloc(key_len);
            if(ctx->server_key_share->key_exchange == NULL) {
                if(record.data) free(record.data);
                return NOXTLS_RETURN_FAILED;
            }
            memcpy(ctx->server_key_share->key_exchange, ext->data + 4, key_len);
        }

        if(record.data) free(record.data);

        if(have_key_share) {
            tls_ecdhe_context_t *ecdhe_ctx;
            if(ctx->ecdhe_ctx == NULL) {
                return NOXTLS_RETURN_FAILED;
            }
            ecdhe_ctx = (tls_ecdhe_context_t*)ctx->ecdhe_ctx;
            rc = tls13_process_server_key_share(ctx, ecdhe_ctx);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: process_key_share rc=%d\n", rc);
                return rc;
            }
            if(ecdhe_ctx->shared_secret == NULL || ecdhe_ctx->shared_secret_len == 0) {
                return NOXTLS_RETURN_FAILED;
            }
            shared_secret = ecdhe_ctx->shared_secret;
            shared_secret_len = ecdhe_ctx->shared_secret_len;
            ctx->psk_use_ecdhe = server_selected_psk ? 1 : 0;
        } else if(server_selected_psk) {
            ctx->psk_use_ecdhe = 0;
        } else {
            noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: neither key_share nor psk selected\n");
            return NOXTLS_RETURN_FAILED;
        }

        rc = tls13_derive_handshake_keys(ctx, shared_secret, shared_secret_len);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("[TLS13_DEBUG] recv_server_hello: derive_handshake_keys rc=%d\n", rc);
    }
    return rc;
}

/**
 * @brief TLS 1.3 Client: Receive Encrypted Extensions
 */
noxtls_return_t tls13_recv_encrypted_extensions(tls13_context_t *ctx)
{
    uint8_t *msg = NULL;
    uint32_t msg_len = 0;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = tls13_recv_handshake_message(ctx, &msg, &msg_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(msg_len < 4 || msg[0] != TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }

    /* Append to transcript */
    tls13_append_handshake_message(ctx, msg, msg_len);

    /* Parse encrypted extensions (extensions length at offset 4, then extension data) */
    if(msg_len >= 6) {
        uint32_t ext_len = ((uint32_t)msg[4] << 8) | msg[5];
        if(ext_len > 0 && 6u + ext_len <= msg_len) {
            noxtls_tls_parse_extensions(msg + 6, ext_len, &ctx->server_extensions);
            /* If server sent early_data extension, 0-RTT was accepted */
            {
                tls_extension_t *ext_early = NULL;
                if(noxtls_tls_find_extension(&ctx->server_extensions, TLS_EXTENSION_EARLY_DATA, &ext_early) == NOXTLS_RETURN_SUCCESS &&
                   ext_early != NULL) {
                    ctx->early_data_accepted = 1;
                    if(ext_early->length >= 4 && ext_early->data != NULL) {
                        ctx->max_early_data_size = ((uint32_t)ext_early->data[0] << 24) | ((uint32_t)ext_early->data[1] << 16) |
                                                   ((uint32_t)ext_early->data[2] << 8) | ext_early->data[3];
                    }
                }
            }
            /* RFC 8449: record_size_limit = max plaintext we may send to server */
            {
                tls_extension_t *ext_rsl = NULL;
                if(noxtls_tls_find_extension(&ctx->server_extensions, TLS_EXTENSION_RECORD_SIZE_LIMIT, &ext_rsl) == NOXTLS_RETURN_SUCCESS &&
                   ext_rsl != NULL && ext_rsl->data != NULL && ext_rsl->length >= 2) {
                    ctx->record_size_limit_send = (uint16_t)((ext_rsl->data[0] << 8) | ext_rsl->data[1]);
                }
            }
        }
    }

    free(msg);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.3 Client: Receive CertificateRequest or leave next message (server Certificate) in pending.
 * Call after EncryptedExtensions. If server sent CertificateRequest, parses it and sets client_auth_requested.
 * If next message is server Certificate, stores it in pending for tls13_recv_certificate.
 */
noxtls_return_t tls13_recv_certificate_request(tls13_context_t *ctx)
{
    uint8_t *msg = NULL;
    uint32_t msg_len = 0;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->pending_handshake_msg) {
        free(ctx->pending_handshake_msg);
        ctx->pending_handshake_msg = NULL;
        ctx->pending_handshake_len = 0;
    }
    ctx->client_auth_requested = 0;
    ctx->cert_request_context_len = 0;

    rc = tls13_recv_handshake_message(ctx, &msg, &msg_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(msg_len < 4) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }

    if(msg[0] == TLS_HANDSHAKE_CERTIFICATE_REQUEST) {
        /* Parse CertificateRequest: certificate_request_context<0..255>, Extension extensions<2..2^16-1> */
        uint32_t off = 4;
        if(off + 1 > msg_len) {
            free(msg);
            return NOXTLS_RETURN_FAILED;
        }
        uint8_t ctx_len = msg[off++];
        if(ctx_len > sizeof(ctx->cert_request_context)) {
            ctx_len = sizeof(ctx->cert_request_context);
        }
        if(off + ctx_len + 2 > msg_len) {
            free(msg);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(ctx->cert_request_context, msg + off, ctx_len);
        ctx->cert_request_context_len = ctx_len;
        off += ctx_len + 2; /* skip extensions length */
        tls13_append_handshake_message(ctx, msg, msg_len);
        ctx->client_auth_requested = 1;
        free(msg);
        return NOXTLS_RETURN_SUCCESS;
    }

    if(msg[0] == TLS_HANDSHAKE_CERTIFICATE) {
        /* Server did not send CertificateRequest; next message is server Certificate. Push back for recv_certificate. */
        ctx->pending_handshake_msg = msg;
        ctx->pending_handshake_len = msg_len;
        return NOXTLS_RETURN_SUCCESS;
    }

    if(msg[0] == TLS_HANDSHAKE_FINISHED) {
        /* PSK-only handshake without client auth: after EncryptedExtensions, server can send Finished directly. */
        ctx->pending_handshake_msg = msg;
        ctx->pending_handshake_len = msg_len;
        return NOXTLS_RETURN_SUCCESS;
    }

    free(msg);
    return NOXTLS_RETURN_FAILED;
}

/**
 * @brief TLS 1.3 Client: Receive Certificate
 */
noxtls_return_t tls13_recv_certificate(tls13_context_t *ctx)
{
    uint8_t *msg = NULL;
    uint32_t msg_len = 0;
    uint32_t cert_list_len;
    uint32_t cert_len;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(ctx->pending_handshake_msg != NULL) {
        msg = ctx->pending_handshake_msg;
        msg_len = ctx->pending_handshake_len;
        ctx->pending_handshake_msg = NULL;
        ctx->pending_handshake_len = 0;
    } else {
        rc = tls13_recv_handshake_message(ctx, &msg, &msg_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    if(msg_len < 8 || msg[0] != TLS_HANDSHAKE_CERTIFICATE) {
        free(msg);
        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                        NOXTLS_EVT_CERT_PARSE_FAIL, msg_len, 0u);
        return NOXTLS_RETURN_FAILED;
    }

    /* Append to transcript */
    tls13_append_handshake_message(ctx, msg, msg_len);

    /* Parse Certificate message (TLS 1.3 format); need at least 4 bytes handshake header + 1 byte cert_request_context_len */
    uint32_t offset = 4;
    if(msg_len < 5u || offset >= msg_len) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }
    uint8_t cert_request_context_len = msg[offset++];
    if(offset + cert_request_context_len + 3 > msg_len) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }
    offset += cert_request_context_len;

    cert_list_len = (msg[offset] << 16) | (msg[offset + 1] << 8) | msg[offset + 2];
    offset += 3;
    if(cert_list_len < 3 || offset + cert_list_len > msg_len) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }

    cert_len = (msg[offset] << 16) | (msg[offset + 1] << 8) | msg[offset + 2];
    offset += 3;
    if(cert_len == 0 || offset + cert_len > msg_len) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }

    if(ctx->server_cert) {
        free(ctx->server_cert);
    }
    ctx->server_cert = (uint8_t*)malloc(cert_len);
    if(ctx->server_cert == NULL) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(ctx->server_cert, msg + offset, cert_len);
    ctx->server_cert_len = cert_len;

    if(ctx->server_cert_parsed) {
        noxtls_x509_certificate_free((x509_certificate_t*)ctx->server_cert_parsed);
        free(ctx->server_cert_parsed);
        ctx->server_cert_parsed = NULL;
    }

    x509_certificate_t *parsed_cert = (x509_certificate_t*)malloc(sizeof(x509_certificate_t));
    if(parsed_cert) {
        noxtls_x509_certificate_init(parsed_cert);
        noxtls_return_t parse_rc = noxtls_x509_certificate_parse_der(parsed_cert, ctx->server_cert, ctx->server_cert_len);
        if(parse_rc == NOXTLS_RETURN_SUCCESS) {
            ctx->server_cert_parsed = parsed_cert;
        } else {
            NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                            NOXTLS_EVT_CERT_PARSE_FAIL, ctx->server_cert_len, 1u);
            noxtls_x509_certificate_free(parsed_cert);
            free(parsed_cert);
            free(msg);
            return parse_rc;
        }
    }

    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_INFO,
                    NOXTLS_EVT_CERTIFICATE_RECV, ctx->server_cert_len, 0u);
    free(msg);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.3 Client: Receive Certificate Verify
 */
noxtls_return_t tls13_recv_certificate_verify(tls13_context_t *ctx)
{
    uint8_t *msg = NULL;
    uint32_t msg_len = 0;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = tls13_recv_handshake_message(ctx, &msg, &msg_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_IO, NOXSIGHT_SEVERITY_ERROR,
                        NOXTLS_EVT_INTERNAL_ERROR, NOXTLS_EVT_VERIFY_SIG_FAIL, rc);
        return rc;
    }

    if(msg_len < 4 || msg[0] != TLS_HANDSHAKE_CERTIFICATE_VERIFY) {
        free(msg);
        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                        NOXTLS_EVT_VERIFY_SIG_FAIL, 1u, msg_len);
        return NOXTLS_RETURN_FAILED;
    }

    /* Verify Certificate Verify signature before appending (signature is over transcript excluding this message) */
    if(msg_len >= 8 && ctx->server_cert_parsed != NULL) {
        uint16_t sig_scheme = (msg[4] << 8) | msg[5];
        uint16_t sig_len = (msg[6] << 8) | msg[7];
        if(8u + sig_len > msg_len) {
            free(msg);
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_hash_algos_t hash_algo;
        uint32_t hash_len;
        uint32_t key_len;
        rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            free(msg);
            return rc;
        }
        uint8_t transcript_hash[64];
        uint32_t transcript_len = sizeof(transcript_hash);
        rc = tls13_hash_messages(hash_algo, ctx->handshake_messages, ctx->handshake_messages_len,
                                 transcript_hash, &transcript_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            free(msg);
            return rc;
        }
        /* Signed content per RFC 8446: 64*0x20 + "TLS 1.3, server CertificateVerify" + 0x00 + Hash */
        static const char ctx_str[] = "TLS 1.3, server CertificateVerify";
        uint8_t to_verify[64 + sizeof(ctx_str) + 1 + 64];
        uint32_t to_verify_len = 0;
        memset(to_verify, 0x20, 64);
        to_verify_len = 64;
        memcpy(to_verify + to_verify_len, ctx_str, sizeof(ctx_str));
        to_verify_len += sizeof(ctx_str);
        to_verify[to_verify_len++] = 0x00;
        memcpy(to_verify + to_verify_len, transcript_hash, transcript_len);
        to_verify_len += transcript_len;

        {
            x509_certificate_t *cert = (x509_certificate_t *)ctx->server_cert_parsed;
            if(cert->rsa_modulus != NULL && cert->rsa_exponent != NULL && sig_scheme == TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256) {
                /* rsa_pss_rsae_sha256 */
                uint32_t key_bytes = cert->rsa_modulus_len;
                rsa_key_size_t key_size = (key_bytes == 128) ? RSA_1024_BIT : (key_bytes == 256) ? RSA_2048_BIT :
                                          (key_bytes == 384) ? RSA_3072_BIT : (key_bytes == 512) ? RSA_4096_BIT : RSA_1024_BIT;
                if(key_bytes != 128 && key_bytes != 256 && key_bytes != 384 && key_bytes != 512) {
                    free(msg);
                    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                                    NOXTLS_EVT_VERIFY_SIG_FAIL, 2u, key_bytes);
                    return NOXTLS_RETURN_FAILED;
                }
                rsa_key_t rsa_key;
                rc = noxtls_rsa_key_init(&rsa_key, key_size);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    free(msg);
                    return rc;
                }
                memcpy(rsa_key.n, cert->rsa_modulus, cert->rsa_modulus_len);
                memcpy(rsa_key.e, cert->rsa_exponent, cert->rsa_exponent_len);
                rc = noxtls_rsa_verify_pss(&rsa_key, to_verify, to_verify_len, msg + 8, sig_len, NOXTLS_HASH_SHA_256);
                noxtls_rsa_key_free(&rsa_key);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    free(msg);
                    NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                                    NOXTLS_EVT_VERIFY_SIG_FAIL, 3u, rc);
                    return NOXTLS_RETURN_FAILED;
                }
            } else {
                free(msg);
                NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                                NOXTLS_EVT_VERIFY_SIG_FAIL, 4u, sig_scheme);
                return NOXTLS_RETURN_FAILED;
            }
        }
        /* Client: verify server cert is valid for the requested hostname (SAN or CN) */
        if(ctx->server_name != NULL && ctx->server_name_len > 0) {
            rc = noxtls_x509_certificate_matches_hostname((x509_certificate_t*)ctx->server_cert_parsed,
                (const char*)ctx->server_name, ctx->server_name_len);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                free(msg);
                NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_X509, NOXSIGHT_SEVERITY_ERROR,
                                NOXTLS_EVT_CERT_VERIFY_FAIL, rc, 2u);
                return NOXTLS_RETURN_FAILED;
            }
        }
    }

    /* Append to transcript after verification */
    tls13_append_handshake_message(ctx, msg, msg_len);

    free(msg);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.3 Client: Receive Finished
 */
noxtls_return_t tls13_recv_finished(tls13_context_t *ctx)
{
    uint8_t *msg = NULL;
    uint32_t msg_len = 0;
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint32_t key_len;
    uint8_t transcript_hash[64];
    uint32_t transcript_len = sizeof(transcript_hash);
    uint8_t finished_key[64];
    uint32_t finished_key_len;
    uint8_t verify_data[64];
    uint32_t verify_len;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = tls13_recv_handshake_message(ctx, &msg, &msg_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(msg_len < 4 || msg[0] != TLS_HANDSHAKE_FINISHED) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }

    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(msg);
        return rc;
    }

    rc = tls13_hash_messages(hash_algo, ctx->handshake_messages, ctx->handshake_messages_len,
                             transcript_hash, &transcript_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(msg);
        return rc;
    }

    finished_key_len = hash_len;
    rc = tls13_hkdf_expand_label(hash_algo, ctx->server_handshake_traffic_secret, hash_len,
                                 (const uint8_t*)"finished", 8, NULL, 0,
                                 finished_key, finished_key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(msg);
        return rc;
    }

    verify_len = hash_len;
    rc = hmac_compute(hash_algo, finished_key, hash_len, transcript_hash, transcript_len,
                      verify_data, &verify_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(msg);
        return rc;
    }

    if(msg_len < 4 + verify_len || noxtls_secret_memcmp(msg + 4, verify_data, verify_len) != 0) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }

    /* RFC 5929: store first Finished verify_data for tls-unique channel binding (TLS 1.3: server sends first) */
    if(ctx->channel_binding_first_finished_len == 0 && verify_len <= sizeof(ctx->channel_binding_first_finished)) {
        memcpy(ctx->channel_binding_first_finished, msg + 4, verify_len);
        ctx->channel_binding_first_finished_len = verify_len;
    }

    /* Append server Finished to transcript */
    tls13_append_handshake_message(ctx, msg, msg_len);

    free(msg);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.3 Client: Send empty Certificate (RFC 8446: MUST send Certificate when requested, may be empty)
 */
static noxtls_return_t tls13_send_client_certificate_empty(tls13_context_t *ctx)
{
    uint8_t certificate[64];
    uint32_t offset = 0;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_CLIENT) {
        return NOXTLS_RETURN_FAILED;
    }
    certificate[offset++] = TLS_HANDSHAKE_CERTIFICATE;
    certificate[offset++] = 0x00;
    certificate[offset++] = 0x00;
    certificate[offset++] = 0x00;
    certificate[offset++] = ctx->cert_request_context_len;
    if(ctx->cert_request_context_len > 0) {
        if(offset + ctx->cert_request_context_len > sizeof(certificate)) {
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(certificate + offset, ctx->cert_request_context, ctx->cert_request_context_len);
        offset += ctx->cert_request_context_len;
    }
    certificate[offset++] = 0x00;
    certificate[offset++] = 0x00;
    certificate[offset++] = 0x00;
    uint32_t handshake_len = offset - 4;
    certificate[1] = (handshake_len >> 16) & 0xFF;
    certificate[2] = (handshake_len >> 8) & 0xFF;
    certificate[3] = handshake_len & 0xFF;
    {
        noxtls_return_t rc = tls13_send_encrypted_handshake(ctx, certificate, offset);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    tls13_append_handshake_message(ctx, certificate, offset);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.3 Client: Send Certificate (client identity for mutual TLS)
 */
noxtls_return_t tls13_send_client_certificate(tls13_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_CLIENT || ctx->client_cert == NULL || ctx->client_cert_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }
    uint8_t *certificate = ctx->handshake_workspace;
    if(certificate == NULL) {
        certificate = (uint8_t*)noxtls_malloc(TLS_HANDSHAKE_WORKSPACE_SIZE);
        if(certificate == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    uint32_t offset = 0;

    certificate[offset++] = TLS_HANDSHAKE_CERTIFICATE;
    certificate[offset++] = 0x00;
    certificate[offset++] = 0x00;
    certificate[offset++] = 0x00;
    certificate[offset++] = ctx->cert_request_context_len;
    if(ctx->cert_request_context_len > 0) {
        memcpy(certificate + offset, ctx->cert_request_context, ctx->cert_request_context_len);
        offset += ctx->cert_request_context_len;
    }
    uint32_t cert_list_len = ctx->client_cert_len + 3;
    certificate[offset++] = (cert_list_len >> 16) & 0xFF;
    certificate[offset++] = (cert_list_len >> 8) & 0xFF;
    certificate[offset++] = cert_list_len & 0xFF;
    certificate[offset++] = (ctx->client_cert_len >> 16) & 0xFF;
    certificate[offset++] = (ctx->client_cert_len >> 8) & 0xFF;
    certificate[offset++] = ctx->client_cert_len & 0xFF;
    if(offset + ctx->client_cert_len > TLS_HANDSHAKE_WORKSPACE_SIZE) {
        if(certificate != ctx->handshake_workspace) NOXTLS_SECURE_FREE(certificate, TLS_HANDSHAKE_WORKSPACE_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(certificate + offset, ctx->client_cert, ctx->client_cert_len);
    offset += ctx->client_cert_len;
    certificate[offset++] = 0x00;
    certificate[offset++] = 0x00;

    uint32_t handshake_len = offset - 4;
    certificate[1] = (handshake_len >> 16) & 0xFF;
    certificate[2] = (handshake_len >> 8) & 0xFF;
    certificate[3] = handshake_len & 0xFF;

    noxtls_return_t rc = tls13_send_encrypted_handshake(ctx, certificate, offset);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        if(certificate != ctx->handshake_workspace) NOXTLS_SECURE_FREE(certificate, TLS_HANDSHAKE_WORKSPACE_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return rc;
    }
    tls13_append_handshake_message(ctx, certificate, offset);
    if(certificate != ctx->handshake_workspace) NOXTLS_SECURE_FREE(certificate, TLS_HANDSHAKE_WORKSPACE_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
    return NOXTLS_RETURN_SUCCESS;
}

/* Encode ECDSA signature (r, s) to DER for TLS CertificateVerify. Returns bytes written or 0 on error. */
static uint32_t tls13_ecdsa_signature_to_der(const ecdsa_signature_t *sig, uint8_t *der, uint32_t der_max)
{
    uint32_t size = sig->size;
    const uint8_t *r = sig->r;
    const uint8_t *s = sig->s;
    uint8_t r_buf[ECC_MAX_KEY_SIZE + 1];
    uint8_t s_buf[ECC_MAX_KEY_SIZE + 1];
    uint32_t r_len, s_len;
    uint32_t r_off = 0, s_off = 0;
    uint32_t pos = 2;

    if(der == NULL || der_max < 10 || size > ECC_MAX_KEY_SIZE) {
        return 0;
    }
    while(r_off < size && r[r_off] == 0) {
        r_off++;
    }
    if(r_off == size) {
        r_buf[0] = 0x00;
        r_len = 1;
    } else {
        r_len = size - r_off;
        if(r[r_off] >= 0x80) {
            r_buf[0] = 0x00;
            memcpy(r_buf + 1, r + r_off, r_len);
            r_len++;
        } else {
            memcpy(r_buf, r + r_off, r_len);
        }
    }
    while(s_off < size && s[s_off] == 0) {
        s_off++;
    }
    if(s_off == size) {
        s_buf[0] = 0x00;
        s_len = 1;
    } else {
        s_len = size - s_off;
        if(s[s_off] >= 0x80) {
            s_buf[0] = 0x00;
            memcpy(s_buf + 1, s + s_off, s_len);
            s_len++;
        } else {
            memcpy(s_buf, s + s_off, s_len);
        }
    }
    if(der_max < 2 + 2 + r_len + 2 + s_len) {
        return 0;
    }
    der[pos++] = 0x02;
    der[pos++] = (uint8_t)r_len;
    memcpy(der + pos, r_buf, r_len);
    pos += r_len;
    der[pos++] = 0x02;
    der[pos++] = (uint8_t)s_len;
    memcpy(der + pos, s_buf, s_len);
    pos += s_len;
    der[0] = 0x30;
    der[1] = (uint8_t)(pos - 2);
    return pos;
}

/**
 * @brief TLS 1.3 Client: Send Certificate Verify (signature over handshake transcript)
 * Supports RSA-PSS (0x0804), ECDSA P-256/SHA256 (0x0403), ECDSA P-384/SHA384 (0x0503), Ed25519 (0x0807), Ed448 (0x0808).
 */
noxtls_return_t tls13_send_client_certificate_verify(tls13_context_t *ctx)
{
    uint8_t certificate_verify[8 + 512];
    uint32_t offset = 0;
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint32_t key_len;
    uint8_t transcript_hash[64];
    uint32_t transcript_len = sizeof(transcript_hash);
    static const char ctx_str[] = "TLS 1.3, client CertificateVerify";
    uint8_t to_sign[64 + sizeof(ctx_str) + 1 + 64];
    uint32_t to_sign_len;
    noxtls_return_t rc;
    uint16_t sig_scheme = TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256;
    uint32_t signature_len = 0;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_CLIENT) {
        return NOXTLS_RETURN_FAILED;
    }
    if(ctx->client_private_rsa == NULL && ctx->client_private_ecdsa == NULL && !ctx->client_cert_use_ed25519
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
        && !ctx->client_cert_use_ed448
#endif
        ) {
        return NOXTLS_RETURN_FAILED;
    }
    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tls13_hash_messages(hash_algo, ctx->handshake_messages, ctx->handshake_messages_len,
                             transcript_hash, &transcript_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    memset(to_sign, 0x20, 64);
    to_sign_len = 64;
    memcpy(to_sign + to_sign_len, ctx_str, sizeof(ctx_str));
    to_sign_len += sizeof(ctx_str);
    to_sign[to_sign_len++] = 0x00;
    memcpy(to_sign + to_sign_len, transcript_hash, transcript_len);
    to_sign_len += transcript_len;

    certificate_verify[offset++] = TLS_HANDSHAKE_CERTIFICATE_VERIFY;
    certificate_verify[offset++] = 0x00;
    certificate_verify[offset++] = 0x00;
    certificate_verify[offset++] = 0x00;
    offset += 4;

    if(ctx->client_private_rsa != NULL) {
        sig_scheme = TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256;
        signature_len = sizeof(certificate_verify) - 8;
        rc = noxtls_rsa_sign_pss((const rsa_key_t *)ctx->client_private_rsa, to_sign, to_sign_len,
                                 certificate_verify + 8, &signature_len, NOXTLS_HASH_SHA_256);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    } else if(ctx->client_private_ecdsa != NULL) {
        ecc_key_t *eckey = (ecc_key_t *)ctx->client_private_ecdsa;
        uint32_t coord_size = eckey->curve != NULL ? eckey->curve->size : 32;
        if(coord_size == 32) {
            sig_scheme = TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256;
            hash_algo = NOXTLS_HASH_SHA_256;
        } else if(coord_size == 48) {
            sig_scheme = TLS_SIGSCHEME_ECDSA_SECP384R1_SHA384;
            hash_algo = NOXTLS_HASH_SHA_384;
        } else {
            return NOXTLS_RETURN_INVALID_ALGORITHM;
        }
        transcript_len = sizeof(transcript_hash);
        rc = tls13_hash_messages(hash_algo, ctx->handshake_messages, ctx->handshake_messages_len,
                                 transcript_hash, &transcript_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        to_sign_len = 64 + sizeof(ctx_str) + 1 + transcript_len;
        memcpy(to_sign + 64 + sizeof(ctx_str) + 1, transcript_hash, transcript_len);
        {
            ecdsa_signature_t sig;
            uint32_t der_len;
            rc = noxtls_ecdsa_signature_init(&sig, coord_size);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            rc = noxtls_ecdsa_sign(eckey, to_sign, to_sign_len, &sig, hash_algo);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_ecdsa_signature_free(&sig);
                return rc;
            }
            der_len = tls13_ecdsa_signature_to_der(&sig, certificate_verify + 8, (uint32_t)(sizeof(certificate_verify) - 8));
            noxtls_ecdsa_signature_free(&sig);
            if(der_len == 0) {
                return NOXTLS_RETURN_FAILED;
            }
            signature_len = der_len;
        }
    } else if(ctx->client_cert_use_ed25519) {
        sig_scheme = TLS_SIGSCHEME_ED25519;
        rc = noxtls_ed25519_sign(ctx->client_private_ed25519, to_sign, to_sign_len, certificate_verify + 8);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        signature_len = 64;
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
    } else if(ctx->client_cert_use_ed448) {
        sig_scheme = TLS_SIGSCHEME_ED448;
        rc = noxtls_ed448_sign(ctx->client_private_ed448, to_sign, to_sign_len, certificate_verify + 8);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        signature_len = 114;
#endif
    } else {
        return NOXTLS_RETURN_FAILED;
    }

    certificate_verify[4] = (uint8_t)(sig_scheme >> 8);
    certificate_verify[5] = (uint8_t)sig_scheme;
    certificate_verify[6] = (uint8_t)(signature_len >> 8);
    certificate_verify[7] = (uint8_t)signature_len;
    offset = 8 + signature_len;
    uint32_t handshake_len = offset - 4;
    certificate_verify[1] = (handshake_len >> 16) & 0xFF;
    certificate_verify[2] = (handshake_len >> 8) & 0xFF;
    certificate_verify[3] = handshake_len & 0xFF;

    rc = tls13_send_encrypted_handshake(ctx, certificate_verify, offset);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    tls13_append_handshake_message(ctx, certificate_verify, offset);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.3 Client: Send Finished
 */
noxtls_return_t tls13_send_finished(tls13_context_t *ctx)
{
    uint8_t finished[80];
    uint32_t offset = 0;
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint32_t key_len;
    uint8_t transcript_hash[64];
    uint32_t transcript_len = sizeof(transcript_hash);
    uint8_t finished_key[64];
    uint32_t finished_key_len;
    uint8_t verify_data[64];
    uint32_t verify_len;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = tls13_hash_messages(hash_algo, ctx->handshake_messages, ctx->handshake_messages_len,
                             transcript_hash, &transcript_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    finished_key_len = hash_len;
    rc = tls13_hkdf_expand_label(hash_algo, ctx->client_handshake_traffic_secret, hash_len,
                                 (const uint8_t*)"finished", 8, NULL, 0,
                                 finished_key, finished_key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    verify_len = hash_len;
    rc = hmac_compute(hash_algo, finished_key, hash_len, transcript_hash, transcript_len,
                      verify_data, &verify_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    /* Build Finished message */
    finished[offset++] = TLS_HANDSHAKE_FINISHED;
    finished[offset++] = 0x00;
    finished[offset++] = 0x00;
    finished[offset++] = (uint8_t)verify_len;
    memcpy(finished + offset, verify_data, verify_len);
    offset += verify_len;

    rc = tls13_send_encrypted_handshake(ctx, finished, offset);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    /* Append client Finished to transcript */
    tls13_append_handshake_message(ctx, finished, offset);

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Get TLS channel binding data (RFC 5929). Call after handshake completes.
 */
noxtls_return_t noxtls_tls13_get_channel_binding(tls13_context_t *ctx, uint32_t binding_type, uint8_t *out, uint32_t *out_len)
{
    if(ctx == NULL || out == NULL || out_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(binding_type == NOXTLS_TLS_CHANNEL_BINDING_TLS_UNIQUE) {
        if(ctx->channel_binding_first_finished_len == 0) {
            return NOXTLS_RETURN_FAILED;
        }
        if(*out_len < ctx->channel_binding_first_finished_len) {
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(out, ctx->channel_binding_first_finished, ctx->channel_binding_first_finished_len);
        *out_len = ctx->channel_binding_first_finished_len;
        return NOXTLS_RETURN_SUCCESS;
    }

    if(binding_type == NOXTLS_TLS_CHANNEL_BINDING_TLS_SERVER_END_POINT) {
        if(ctx->server_cert == NULL || ctx->server_cert_len == 0 || ctx->server_cert_parsed == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_hash_algos_t hash_algo;
        if(noxtls_x509_get_channel_binding_hash_algo((const x509_certificate_t*)ctx->server_cert_parsed, &hash_algo) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        uint32_t hash_size = (hash_algo == NOXTLS_HASH_SHA_384 || hash_algo == NOXTLS_HASH_SHA_512) ? 48u : 32u;
        if(hash_algo == NOXTLS_HASH_SHA_512) {
            hash_size = 64u;
        }
        if(*out_len < hash_size) {
            return NOXTLS_RETURN_FAILED;
        }
        if(hash_algo == NOXTLS_HASH_SHA_256 || hash_algo == NOXTLS_HASH_SHA_224) {
            noxtls_sha_ctx_t sha_ctx;
            if(noxtls_sha256_init(&sha_ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_FAILED;
            }
            noxtls_sha256_update(&sha_ctx, (uint8_t *)ctx->server_cert, ctx->server_cert_len);
            if(noxtls_sha256_finish(&sha_ctx, out) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_FAILED;
            }
            *out_len = 32u;
            return NOXTLS_RETURN_SUCCESS;
        }
        if(hash_algo == NOXTLS_HASH_SHA_384 || hash_algo == NOXTLS_HASH_SHA_512) {
            noxtls_sha512_ctx_t sha_ctx;
            if(noxtls_sha512_init(&sha_ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_FAILED;
            }
            noxtls_sha512_update(&sha_ctx, ctx->server_cert, ctx->server_cert_len);
            if(noxtls_sha512_finish(&sha_ctx, out) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_FAILED;
            }
            *out_len = (hash_algo == NOXTLS_HASH_SHA_384) ? 48u : 64u;
            return NOXTLS_RETURN_SUCCESS;
        }
        return NOXTLS_RETURN_FAILED;
    }

    return NOXTLS_RETURN_FAILED;
}

/**
 * @brief TLS 1.3 Client: Connect
 */
noxtls_return_t tls13_connect(tls13_context_t *ctx)
{
    noxtls_return_t rc;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.role != TLS_ROLE_CLIENT) {
        return NOXTLS_RETURN_FAILED;
    }
    
    ctx->base.base.state = TLS_STATE_HANDSHAKING;
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_START);
    
    noxtls_debug_printf("[TLS13_DEBUG] tls13_connect: send_client_hello...\n");
    /* Send Client Hello */
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_SEND_CH);
    rc = tls13_send_client_hello(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("[TLS13_DEBUG] tls13_send_client_hello rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_SEND_CH, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_SEND_CH, rc);
    /* Derive 0-RTT keys if we offered resumption (and early_data); allows send_early_data before ServerHello */
    if(ctx->ticket_stored && ctx->resumption_psk_len > 0) {
        rc = tls13_derive_early_data_keys(ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_debug_printf("[TLS13_DEBUG] tls13_derive_early_data_keys rc=%d\n", rc);
            /* non-fatal: continue without 0-RTT */
            ctx->early_data_phase = 0;
        }
    }

    /* Receive Server Hello */
    noxtls_debug_printf("[TLS13_DEBUG] tls13_connect: recv_server_hello...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_RECV_SH);
    rc = tls13_recv_server_hello(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("[TLS13_DEBUG] tls13_recv_server_hello rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_SH, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_SH, rc);
    
    /* Receive Encrypted Extensions */
    noxtls_debug_printf("[TLS13_DEBUG] tls13_connect: recv_encrypted_extensions...\n");
    rc = tls13_recv_encrypted_extensions(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("[TLS13_DEBUG] tls13_recv_encrypted_extensions rc=%d\n", rc);
        return rc;
    }
    /* Optional CertificateRequest (mutual TLS); if present, next message is server Certificate */
    noxtls_debug_printf("[TLS13_DEBUG] tls13_connect: recv_certificate_request...\n");
    rc = tls13_recv_certificate_request(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("[TLS13_DEBUG] tls13_recv_certificate_request rc=%d\n", rc);
        return rc;
    }
    
    if(!ctx->psk_in_use) {
        /* Receive Certificate */
        noxtls_debug_printf("[TLS13_DEBUG] tls13_connect: recv_certificate...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_VERIFY_CERT);
        rc = tls13_recv_certificate(ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_debug_printf("[TLS13_DEBUG] tls13_recv_certificate rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_VERIFY_CERT, rc);
            return rc;
        }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_VERIFY_CERT, rc);
        
        /* Receive Certificate Verify */
        noxtls_debug_printf("[TLS13_DEBUG] tls13_connect: recv_certificate_verify...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_RECV_CERT_VERIFY);
        rc = tls13_recv_certificate_verify(ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_debug_printf("[TLS13_DEBUG] tls13_recv_certificate_verify rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_CERT_VERIFY, rc);
            return rc;
        }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_CERT_VERIFY, rc);
    }
    
    /* Receive Finished */
    noxtls_debug_printf("[TLS13_DEBUG] tls13_connect: recv_finished...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_RECV_FINISHED);
    rc = tls13_recv_finished(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("[TLS13_DEBUG] tls13_recv_finished rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_FINISHED, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_RECV_FINISHED, rc);

    /* Derive application traffic secrets (uses transcript incl. server Finished) */
    noxtls_debug_printf("[TLS13_DEBUG] tls13_connect: derive_application_secrets...\n");
    rc = tls13_derive_application_secrets(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("[TLS13_DEBUG] tls13_derive_application_secrets rc=%d\n", rc);
        return rc;
    }
    /* If server requested client auth: send Certificate (with or without cert), then optionally CertificateVerify */
    if(ctx->client_auth_requested) {
        if(ctx->client_cert != NULL && ctx->client_cert_len > 0 &&
           (ctx->client_private_rsa != NULL || ctx->client_private_ecdsa != NULL || ctx->client_cert_use_ed25519
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
            || ctx->client_cert_use_ed448
#endif
            )) {
            noxtls_debug_printf("[TLS13_DEBUG] tls13_connect: send_client_certificate...\n");
            rc = tls13_send_client_certificate(ctx);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_debug_printf("[TLS13_DEBUG] tls13_send_client_certificate rc=%d\n", rc);
                return rc;
            }
            noxtls_debug_printf("[TLS13_DEBUG] tls13_connect: send_client_certificate_verify...\n");
            rc = tls13_send_client_certificate_verify(ctx);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_debug_printf("[TLS13_DEBUG] tls13_send_client_certificate_verify rc=%d\n", rc);
                return rc;
            }
        } else {
            noxtls_debug_printf("[TLS13_DEBUG] tls13_connect: send_client_certificate (empty)...\n");
            rc = tls13_send_client_certificate_empty(ctx);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_debug_printf("[TLS13_DEBUG] tls13_send_client_certificate_empty rc=%d\n", rc);
                return rc;
            }
        }
    }
    /* If we sent 0-RTT data, send EndOfEarlyData (encrypted with handshake keys) before Finished */
    if(ctx->early_data_sent && !ctx->sent_end_of_early_data) {
        uint8_t eoed[4];
        eoed[0] = TLS_HANDSHAKE_END_OF_EARLY_DATA;
        eoed[1] = 0;
        eoed[2] = 0;
        eoed[3] = 0;
        rc = tls13_append_handshake_message(ctx, eoed, 4);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        noxtls_debug_printf("[TLS13_DEBUG] tls13_connect: send EndOfEarlyData...\n");
        rc = tls13_send_encrypted_handshake(ctx, eoed, 4);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_debug_printf("[TLS13_DEBUG] tls13_send EndOfEarlyData rc=%d\n", rc);
            return rc;
        }
        ctx->sent_end_of_early_data = 1;
    }
    /* Send Finished */
    noxtls_debug_printf("[TLS13_DEBUG] tls13_connect: send_finished...\n");
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_SEND_FINISHED);
    rc = tls13_send_finished(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("[TLS13_DEBUG] tls13_send_finished rc=%d\n", rc);
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_SEND_FINISHED, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_SEND_FINISHED, rc);

    /* Install application keys after sending client Finished */
    noxtls_debug_printf("[TLS13_DEBUG] tls13_connect: install_application_keys...\n");
    rc = tls13_install_application_keys(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_debug_printf("[TLS13_DEBUG] tls13_install_application_keys rc=%d\n", rc);
        return rc;
    }

    ctx->base.base.state = TLS_STATE_CONNECTED;
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_CONNECTED);
    dtls_mark_validated(&ctx->base);

    /* Optionally receive NewSessionTicket if server sends it.
     * In client-auth flows tests don't rely on NST, and waiting here can stall on peer failure. */
    if(!ctx->client_auth_requested) {
        tls13_try_recv_nst(ctx);
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.3 Server: Receive Client Hello
 */
noxtls_return_t tls13_recv_client_hello(tls13_context_t *ctx)
{
    tls_record_t record;
    uint32_t offset;
    uint16_t version;
    uint8_t session_id_len;
    uint16_t cipher_suites_len;
    uint8_t compression_methods_len;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Check if we have a pending Client Hello from version negotiation */
    if(ctx->base.base.pending_client_hello != NULL && ctx->base.base.pending_client_hello_len > 0) {
        record.type = TLS_RECORD_HANDSHAKE;
        record.version = TLS_VERSION_1_3;  /* Legacy version for TLS 1.3 */
        (void)record.version;
        if(ctx->base.base.pending_client_hello_len > UINT16_MAX) {
            return NOXTLS_RETURN_FAILED;
        }
        record.length = (uint16_t)ctx->base.base.pending_client_hello_len;
        record.data = (uint8_t*)malloc(record.length);
        if(record.length > 0 && record.data == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(record.data, ctx->base.base.pending_client_hello, record.length);
    } else {
        noxtls_return_t rc = noxtls_tls_recv_record(&ctx->base.base, &record);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if(record.length > 0 && record.data == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    
    if(record.type != TLS_RECORD_HANDSHAKE || record.length < 38) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    if(record.data[0] != TLS_HANDSHAKE_CLIENT_HELLO) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }

    /* Append ClientHello to transcript (server side) */
    tls13_append_handshake_message(ctx, record.data, record.length);
    
    offset = 4;  /* Skip handshake header */
    
    /* Version */
    version = (record.data[offset] << 8) | record.data[offset + 1];
    (void)version;
    offset += 2;
    
    /* Client Random (32 bytes) */
    memcpy(ctx->client_random, record.data + offset, TLS_RANDOM_SIZE);
    offset += TLS_RANDOM_SIZE;
    
    /* Session ID length */
    session_id_len = record.data[offset++];
    offset += session_id_len;  /* Skip session ID */
    
    /* Cipher suites length */
    cipher_suites_len = (record.data[offset] << 8) | record.data[offset + 1];
    offset += 2;
    
    /* Parse and select first supported cipher suite from client's list */
    {
        static const uint16_t supported[] = {
            TLS_CIPHER_SUITE_AES_128_GCM_SHA256,
            TLS_CIPHER_SUITE_AES_128_CCM_SHA256,
            TLS_CIPHER_SUITE_AES_128_CCM_8_SHA256,
            TLS_CIPHER_SUITE_AES_256_GCM_SHA384,
            TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256
        };
        uint32_t num_supported = sizeof(supported) / sizeof(supported[0]);
        ctx->cipher_suite = 0;
        for(uint32_t i = 0; i + 2 <= cipher_suites_len; i += 2) {
            uint16_t candidate = (record.data[offset + i] << 8) | record.data[offset + i + 1];
            for(uint32_t j = 0; j < num_supported; j++) {
                if(candidate == supported[j]) {
                    ctx->cipher_suite = candidate;
                    break;
                }
            }
            if(ctx->cipher_suite != 0) break;
        }
        if(ctx->cipher_suite == 0) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }
    }
    offset += cipher_suites_len;
    
    /* Compression methods length */
    compression_methods_len = record.data[offset++];
    offset += compression_methods_len;
    
    /* Parse extensions (especially key_share extension) */
    if(offset < record.length) {
        uint32_t extensions_len = record.length - offset;
        if(extensions_len >= 2) {
            noxtls_return_t rc = noxtls_tls_parse_extensions(record.data + offset, extensions_len, &ctx->client_extensions);
            if(rc == NOXTLS_RETURN_SUCCESS && ctx->client_extensions.key_share != NULL) {
                /* Extract client key shares for key exchange */
                if(ctx->client_key_shares) {
                    for(uint32_t i = 0; i < ctx->client_key_shares_count; i++) {
                        if(ctx->client_key_shares[i].key_exchange) {
                            free(ctx->client_key_shares[i].key_exchange);
                        }
                    }
                    free(ctx->client_key_shares);
                }
                ctx->client_key_shares_count = ctx->client_extensions.key_share->count;
                if(ctx->client_key_shares_count > 0) {
                    ctx->client_key_shares = (tls13_key_share_entry_t*)malloc(ctx->client_key_shares_count * sizeof(tls13_key_share_entry_t));
                    if(ctx->client_key_shares) {
                        for(uint32_t i = 0; i < ctx->client_key_shares_count; i++) {
                            ctx->client_key_shares[i].group = ctx->client_extensions.key_share->entries[i].group;
                            ctx->client_key_shares[i].key_exchange_len = ctx->client_extensions.key_share->entries[i].key_exchange_len;
                            if(ctx->client_key_shares[i].key_exchange_len > 0) {
                                ctx->client_key_shares[i].key_exchange = (uint8_t*)malloc(ctx->client_key_shares[i].key_exchange_len);
                                if(ctx->client_key_shares[i].key_exchange) {
                                    memcpy(ctx->client_key_shares[i].key_exchange,
                                           ctx->client_extensions.key_share->entries[i].key_exchange,
                                           ctx->client_key_shares[i].key_exchange_len);
                                }
                            } else {
                                ctx->client_key_shares[i].key_exchange = NULL;
                            }
                        }
                    }
                }
            }
        }
    }

    ctx->client_offered_early_data = 0;
    {
        tls_extension_t *ext_early = NULL;
        if(noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_EARLY_DATA, &ext_early) == NOXTLS_RETURN_SUCCESS && ext_early != NULL) {
            ctx->client_offered_early_data = 1;
        }
    }

    /* RFC 8449: client's record_size_limit = max plaintext we may send to client */
    {
        tls_extension_t *ext_rsl = NULL;
        if(noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_RECORD_SIZE_LIMIT, &ext_rsl) == NOXTLS_RETURN_SUCCESS &&
           ext_rsl != NULL && ext_rsl->data != NULL && ext_rsl->length >= 2) {
            ctx->record_size_limit_send = (uint16_t)((ext_rsl->data[0] << 8) | ext_rsl->data[1]);
        }
    }

    ctx->psk_in_use = 0;
    ctx->psk_use_ecdhe = 0;
    ctx->psk_selected_identity = 0;
    {
        tls_extension_t *ext_psk = NULL;
        tls_extension_t *ext_modes = NULL;
        int have_psk = (noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_PRE_SHARED_KEY, &ext_psk) == NOXTLS_RETURN_SUCCESS);
        int have_modes = (noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES, &ext_modes) == NOXTLS_RETURN_SUCCESS);
        if(have_psk && have_modes && ext_psk != NULL && ext_psk->data != NULL && ext_modes != NULL && ext_modes->data != NULL) {
            uint16_t identity_index = 0;
            uint8_t identity_buf[256];
            uint16_t id_len;
            uint32_t binder_offset = 0;
            uint16_t binder_loc_len = 0;
            uint16_t selected_identity = 0;
            noxtls_return_t rc_psk = NOXTLS_RETURN_SUCCESS;

            for(identity_index = 0; ; identity_index++) {
                id_len = sizeof(identity_buf);
                rc_psk = tls13_psk_find_clienthello_binder(record.data, record.length,
                                                           identity_index,
                                                           &binder_offset, &binder_loc_len, &selected_identity,
                                                           identity_buf, &id_len);
                if(rc_psk != NOXTLS_RETURN_SUCCESS) {
                    break;
                }
                /* Try session ticket (resumption) first: identity is 16-byte ticket_id */
                if(id_len == TLS13_PSK_TICKET_ID_LEN) {
                    const void *entry = tls13_psk_ticket_store_lookup(identity_buf, (uint32_t)id_len);
                    if(entry != NULL) {
                        noxtls_hash_algos_t hash_algo;
                        uint32_t hash_len;
                        uint8_t expected_binder[64];
                        noxtls_return_t rc_binder;
                        uint8_t entry_psk[64];
                        uint8_t entry_psk_len;
                        uint8_t entry_nonce[TLS13_PSK_TICKET_NONCE_MAX];
                        uint8_t entry_nonce_len;

                        if(tls13_get_cipher_params(tls13_psk_ticket_store_entry_cipher_suite(entry), &hash_algo, &hash_len, NULL) != NOXTLS_RETURN_SUCCESS) {
                            continue;
                        }
                        if(binder_loc_len != hash_len) {
                            continue;
                        }
                        if(tls13_psk_ticket_store_entry_psk(entry, entry_psk, (uint8_t)sizeof(entry_psk), &entry_psk_len,
                                                            entry_nonce, (uint8_t)sizeof(entry_nonce), &entry_nonce_len) != NOXTLS_RETURN_SUCCESS) {
                            continue;
                        }
                        rc_binder = tls13_psk_compute_resumption_binder(hash_algo,
                                                                        entry_psk, entry_psk_len,
                                                                        entry_nonce, entry_nonce_len,
                                                                        record.data, record.length,
                                                                        binder_offset, binder_loc_len,
                                                                        expected_binder);
                        if(rc_binder != NOXTLS_RETURN_SUCCESS) {
                            continue;
                        }
                        if(noxtls_secret_memcmp(record.data + binder_offset, expected_binder, binder_loc_len) != 0) {
                            continue;
                        }
                        ctx->cipher_suite = tls13_psk_ticket_store_entry_cipher_suite(entry);
                        memcpy(ctx->psk_key, entry_psk, entry_psk_len);
                        ctx->psk_key_len = entry_psk_len;
                        ctx->psk_selected_identity = identity_index;
                        ctx->psk_in_use = 1;
                        if(ctx->client_key_shares_count > 0 &&
                           tls13_psk_mode_offered(ext_modes->data, ext_modes->length, TLS13_PSK_KE_MODE_PSK_DHE_KE)) {
                            ctx->psk_use_ecdhe = 1;
                        } else if(tls13_psk_mode_offered(ext_modes->data, ext_modes->length, TLS13_PSK_KE_MODE_PSK_KE)) {
                            ctx->psk_use_ecdhe = 0;
                        } else {
                            ctx->psk_use_ecdhe = 1;
                        }
                        break;
                    }
                }
                /* Try external PSK */
                if(ctx->psk_configured && id_len == ctx->psk_identity_len &&
                   memcmp(identity_buf, ctx->psk_identity, id_len) == 0) {
                    noxtls_hash_algos_t hash_algo;
                    uint32_t hash_len;
                    uint32_t key_len;
                    uint8_t expected_binder[64];

                    if(tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len) != NOXTLS_RETURN_SUCCESS) {
                        continue;
                    }
                    if(binder_loc_len != hash_len) {
                        continue;
                    }
                    if(tls13_psk_compute_external_binder(hash_algo,
                                                          ctx->psk_key, ctx->psk_key_len,
                                                          record.data, record.length,
                                                          binder_offset, binder_loc_len,
                                                          expected_binder) != NOXTLS_RETURN_SUCCESS) {
                        continue;
                    }
                    if(noxtls_secret_memcmp(record.data + binder_offset, expected_binder, binder_loc_len) != 0) {
                        continue;
                    }
                    if(ctx->psk_preferred_mode == TLS13_PSK_KE_MODE_PSK_DHE_KE &&
                       tls13_psk_mode_offered(ext_modes->data, ext_modes->length, TLS13_PSK_KE_MODE_PSK_DHE_KE) &&
                       ctx->client_key_shares_count > 0) {
                        ctx->psk_use_ecdhe = 1;
                    } else if(tls13_psk_mode_offered(ext_modes->data, ext_modes->length, TLS13_PSK_KE_MODE_PSK_KE)) {
                        ctx->psk_use_ecdhe = 0;
                    } else if(tls13_psk_mode_offered(ext_modes->data, ext_modes->length, TLS13_PSK_KE_MODE_PSK_DHE_KE) &&
                              ctx->client_key_shares_count > 0) {
                        ctx->psk_use_ecdhe = 1;
                    } else {
                        continue;
                    }
                    ctx->psk_in_use = 1;
                    ctx->psk_selected_identity = identity_index;
                    break;
                }
            }
        }
    }

    if(tls13_is_dtls(ctx)) {
        tls_extension_t *ext = NULL;
        int cookie_valid = 0;
        uint8_t hrr_msg[256];
        uint32_t hrr_len = sizeof(hrr_msg);
        uint8_t cookie[32];
        uint32_t cookie_len = sizeof(cookie);
        noxtls_hash_algos_t hash_algo;
        uint32_t hash_len;
        uint32_t key_len;
        uint16_t selected_group = TLS_NAMED_GROUP_SECP256R1;
        int has_key_share = 0;
        int need_key_share = 1;

        if(ctx->client_extensions.supported_groups != NULL &&
           ctx->client_extensions.supported_groups->count > 0) {
            selected_group = ctx->client_extensions.supported_groups->groups[0];
        }
        if(ctx->psk_in_use && !ctx->psk_use_ecdhe) {
            need_key_share = 0;
        }
        has_key_share = tls13_client_has_key_share(ctx, selected_group);

        if(noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_COOKIE, &ext) == NOXTLS_RETURN_SUCCESS) {
            if(ext != NULL && ext->length <= sizeof(ctx->base.cookie) &&
               dtls_verify_cookie(&ctx->base, ext->data, ext->length) == NOXTLS_RETURN_SUCCESS) {
                memcpy(ctx->base.cookie, ext->data, ext->length);
                ctx->base.cookie_len = ext->length;
                cookie_valid = 1;
                dtls_mark_validated(&ctx->base);
            }
        }

        if(tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len) != NOXTLS_RETURN_SUCCESS) {
            if(record.data) free(record.data);
            return NOXTLS_RETURN_FAILED;
        }

        if(!cookie_valid) {
            if(dtls_generate_cookie(&ctx->base, record.data, record.length, cookie, &cookie_len) != NOXTLS_RETURN_SUCCESS) {
                if(record.data) free(record.data);
                return NOXTLS_RETURN_FAILED;
            }
        } else {
            memcpy(cookie, ctx->base.cookie, ctx->base.cookie_len);
            cookie_len = ctx->base.cookie_len;
        }

        if(!cookie_valid || (need_key_share && !has_key_share)) {
            if(has_key_share || !need_key_share) {
                selected_group = 0;
            }
            if(tls13_reset_transcript_for_hrr(ctx, hash_algo, hash_len) != NOXTLS_RETURN_SUCCESS) {
                if(record.data) free(record.data);
                return NOXTLS_RETURN_FAILED;
            }
            if(tls13_send_hello_retry_request_dtls(ctx, cookie, (uint16_t)cookie_len,
                                                   selected_group, hrr_msg, &hrr_len) != NOXTLS_RETURN_SUCCESS) {
                if(record.data) free(record.data);
                return NOXTLS_RETURN_FAILED;
            }
            tls13_append_handshake_message(ctx, hrr_msg, hrr_len);
            if(record.data) free(record.data);
            return NOXTLS_RETURN_TIMEOUT;
        }
    }
    
    if(record.data) free(record.data);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.3 Server: Send Server Hello
 */
noxtls_return_t tls13_send_server_hello(tls13_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    uint8_t *server_hello = ctx->handshake_workspace;
    if(server_hello == NULL) {
        server_hello = (uint8_t*)noxtls_malloc(TLS_SERVER_HELLO_DEFAULT_SIZE);
        if(server_hello == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    uint32_t offset = 0;
    drbg_state_t drbg_state;
    
    /* Generate server random */
    if(drbg_instantiate(&drbg_state, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    if(drbg_generate(&drbg_state, ctx->server_random, sizeof(ctx->server_random) * 8u, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Build Server Hello message */
    server_hello[offset++] = TLS_HANDSHAKE_SERVER_HELLO;
    server_hello[offset++] = 0x00;  /* Length (3 bytes) - placeholder */
    server_hello[offset++] = 0x00;
    server_hello[offset++] = 0x00;
    
    /* Version */
    if(tls13_is_dtls(ctx)) {
        server_hello[offset++] = (DTLS_VERSION_1_2 >> 8) & 0xFF;
        server_hello[offset++] = DTLS_VERSION_1_2 & 0xFF;
    } else {
        server_hello[offset++] = (TLS_VERSION_1_3 >> 8) & 0xFF;
        server_hello[offset++] = TLS_VERSION_1_3 & 0xFF;
    }
    
    /* Random (32 bytes) */
    memcpy(server_hello + offset, ctx->server_random, TLS_RANDOM_SIZE);
    offset += TLS_RANDOM_SIZE;
    
    /* Session ID length (1 byte) */
    server_hello[offset++] = 0x00;  /* No session ID in TLS 1.3 */
    
    /* Cipher suite (2 bytes) */
    server_hello[offset++] = (ctx->cipher_suite >> 8) & 0xFF;
    server_hello[offset++] = ctx->cipher_suite & 0xFF;
    
    /* Compression method (1 byte) */
    server_hello[offset++] = 0x00;  /* NULL compression */

    /* Extensions length (2 bytes) placeholder */
    uint32_t extensions_start = offset;
    server_hello[offset++] = 0x00;
    server_hello[offset++] = 0x00;

    /* Supported Versions */
    server_hello[offset++] = (TLS_EXTENSION_SUPPORTED_VERSIONS >> 8) & 0xFF;
    server_hello[offset++] = TLS_EXTENSION_SUPPORTED_VERSIONS & 0xFF;
    server_hello[offset++] = 0x00;
    server_hello[offset++] = 0x02;
    server_hello[offset++] = (TLS_VERSION_1_3 >> 8) & 0xFF;
    server_hello[offset++] = TLS_VERSION_1_3 & 0xFF;

    if(!ctx->psk_in_use || ctx->psk_use_ecdhe) {
        /* Key Share for non-PSK and ECDHE-PSK */
        tls_ecdhe_context_t *ecdhe_ctx = (tls_ecdhe_context_t*)ctx->ecdhe_ctx;
        uint16_t selected_group = TLS_NAMED_GROUP_SECP256R1;
        uint8_t *key_share_entry = (ctx->handshake_workspace != NULL) ? (ctx->handshake_workspace + TLS_SERVER_HELLO_DEFAULT_SIZE) : (uint8_t*)noxtls_malloc(TLS_KEY_SHARE_ENTRY_MAX_LEN);
        uint32_t key_share_entry_len = TLS_KEY_SHARE_ENTRY_MAX_LEN;
        if(key_share_entry == NULL) {
            if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }

        if(ctx->client_key_shares_count > 0) {
            selected_group = ctx->client_key_shares[0].group;
        }
        if(ecdhe_ctx == NULL || ecdhe_ctx->named_group != selected_group) {
            if(ecdhe_ctx != NULL) {
                tls_ecdhe_context_free(ecdhe_ctx);
                free(ecdhe_ctx);
            }
            ecdhe_ctx = (tls_ecdhe_context_t*)malloc(sizeof(tls_ecdhe_context_t));
            if(ecdhe_ctx == NULL) {
                if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(key_share_entry, TLS_KEY_SHARE_ENTRY_MAX_LEN);
                if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                return NOXTLS_RETURN_FAILED;
            }
            if(tls_ecdhe_context_init(ecdhe_ctx, selected_group) != NOXTLS_RETURN_SUCCESS ||
               tls_ecdhe_generate_ephemeral_key(ecdhe_ctx) != NOXTLS_RETURN_SUCCESS) {
                tls_ecdhe_context_free(ecdhe_ctx);
                free(ecdhe_ctx);
                if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(key_share_entry, TLS_KEY_SHARE_ENTRY_MAX_LEN);
                if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
                return NOXTLS_RETURN_FAILED;
            }
            ctx->ecdhe_ctx = ecdhe_ctx;
        }

        if(tls13_key_share_encode(ecdhe_ctx, key_share_entry, &key_share_entry_len) != NOXTLS_RETURN_SUCCESS) {
            if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(key_share_entry, TLS_KEY_SHARE_ENTRY_MAX_LEN);
            if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return NOXTLS_RETURN_FAILED;
        }

        server_hello[offset++] = (TLS_EXTENSION_KEY_SHARE >> 8) & 0xFF;
        server_hello[offset++] = TLS_EXTENSION_KEY_SHARE & 0xFF;
        server_hello[offset++] = (key_share_entry_len >> 8) & 0xFF;
        server_hello[offset++] = key_share_entry_len & 0xFF;
        memcpy(server_hello + offset, key_share_entry, key_share_entry_len);
        offset += key_share_entry_len;
        if(ctx->handshake_workspace == NULL) NOXTLS_SECURE_FREE(key_share_entry, TLS_KEY_SHARE_ENTRY_MAX_LEN);
    }

    if(ctx->psk_in_use) {
        server_hello[offset++] = (TLS_EXTENSION_PRE_SHARED_KEY >> 8) & 0xFF;
        server_hello[offset++] = TLS_EXTENSION_PRE_SHARED_KEY & 0xFF;
        server_hello[offset++] = 0x00;
        server_hello[offset++] = 0x02;
        server_hello[offset++] = (uint8_t)(ctx->psk_selected_identity >> 8);
        server_hello[offset++] = (uint8_t)(ctx->psk_selected_identity & 0xFF);
    }

    /* Connection ID (RFC 9146/9147): DTLS 1.3 only; echo client's CID if present (store for record header) */
    {
        tls_extension_t *ext_cid = NULL;
        if(tls13_is_dtls(ctx) &&
           noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_CONNECTION_ID, &ext_cid) == NOXTLS_RETURN_SUCCESS &&
           ext_cid != NULL && ext_cid->length >= 1) {
            uint8_t cid_len = ext_cid->data[0];
            if(cid_len > 0 && cid_len <= 32 && ext_cid->length >= 1u + cid_len) {
                ctx->peer_connection_id_len = cid_len;
                memcpy(ctx->peer_connection_id, ext_cid->data + 1, cid_len);
                ctx->own_connection_id_len = cid_len;
                memcpy(ctx->own_connection_id, ctx->peer_connection_id, cid_len);  /* echo for simplicity */
            }
            server_hello[offset++] = (TLS_EXTENSION_CONNECTION_ID >> 8) & 0xFF;
            server_hello[offset++] = TLS_EXTENSION_CONNECTION_ID & 0xFF;
            server_hello[offset++] = 0x00;
            server_hello[offset++] = (uint8_t)(1 + ctx->peer_connection_id_len);
            server_hello[offset++] = ctx->peer_connection_id_len;
            if(ctx->peer_connection_id_len > 0) {
                memcpy(server_hello + offset, ctx->peer_connection_id, ctx->peer_connection_id_len);
                offset += ctx->peer_connection_id_len;
            }
        } else if(tls13_is_dtls(ctx) &&
                  noxtls_tls_find_extension(&ctx->client_extensions, TLS_EXTENSION_CONNECTION_ID, &ext_cid) == NOXTLS_RETURN_SUCCESS) {
            server_hello[offset++] = (TLS_EXTENSION_CONNECTION_ID >> 8) & 0xFF;
            server_hello[offset++] = TLS_EXTENSION_CONNECTION_ID & 0xFF;
            server_hello[offset++] = 0x00;
            server_hello[offset++] = 0x01;
            server_hello[offset++] = 0x00;  /* zero-length CID */
        }
    }

    /* Update extensions length */
    uint32_t extensions_len32 = offset - extensions_start - 2;
    if(extensions_len32 > UINT16_MAX) {
        return NOXTLS_RETURN_FAILED;
    }
    uint16_t extensions_len = (uint16_t)extensions_len32;
    server_hello[extensions_start] = (extensions_len >> 8) & 0xFF;
    server_hello[extensions_start + 1] = extensions_len & 0xFF;
    
    /* Update handshake message length */
    uint32_t handshake_len = offset - 4;
    server_hello[1] = (handshake_len >> 16) & 0xFF;
    server_hello[2] = (handshake_len >> 8) & 0xFF;
    server_hello[3] = handshake_len & 0xFF;
    
    /* Append to transcript before deriving keys; server derives after this returns. */
    tls13_append_handshake_message(ctx, server_hello, offset);
    
    /* Send via record layer */
    noxtls_return_t rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_HANDSHAKE, server_hello, offset);
    if(server_hello != ctx->handshake_workspace) NOXTLS_SECURE_FREE(server_hello, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
    return rc;
}

/**
 * @brief TLS 1.3 Server: Send Encrypted Extensions
 */
noxtls_return_t tls13_send_encrypted_extensions(tls13_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    uint8_t *encrypted_extensions = ctx->handshake_workspace;
    if(encrypted_extensions == NULL) {
        encrypted_extensions = (uint8_t*)noxtls_malloc(512);
        if(encrypted_extensions == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    uint32_t offset = 0;
    uint32_t ext_len;
    
    /* Build Encrypted Extensions message */
    encrypted_extensions[offset++] = TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS;
    encrypted_extensions[offset++] = 0x00;  /* Length (3 bytes) - placeholder */
    encrypted_extensions[offset++] = 0x00;
    encrypted_extensions[offset++] = 0x00;
    
    /* Extensions: early_data (0-RTT), RFC 8449 record_size_limit */
    ext_len = 0;
    if(ctx->psk_in_use && ctx->client_offered_early_data) {
        ext_len += 8;  /* type(2) + length(2) + max_early_data_size(4) */
    }
    /* RFC 8449: record_size_limit = max plaintext we are willing to receive from client */
    {
        (void)((ctx->record_size_limit_recv > 0) ? ctx->record_size_limit_recv : (uint16_t)TLS_MAX_RECORD_SIZE);
        ext_len += 6;  /* type(2) + length(2) + limit(2) */
    }
    encrypted_extensions[offset++] = (ext_len >> 8) & 0xFF;
    encrypted_extensions[offset++] = ext_len & 0xFF;
    if(ctx->psk_in_use && ctx->client_offered_early_data) {
        encrypted_extensions[offset++] = (TLS_EXTENSION_EARLY_DATA >> 8) & 0xFF;
        encrypted_extensions[offset++] = TLS_EXTENSION_EARLY_DATA & 0xFF;
        encrypted_extensions[offset++] = 0x00;
        encrypted_extensions[offset++] = 0x04;
        encrypted_extensions[offset++] = 0xFF;
        encrypted_extensions[offset++] = 0xFF;
        encrypted_extensions[offset++] = 0xFF;
        encrypted_extensions[offset++] = 0xFF;
    }
    {
        uint16_t rsl = (ctx->record_size_limit_recv > 0) ? ctx->record_size_limit_recv : (uint16_t)TLS_MAX_RECORD_SIZE;
        encrypted_extensions[offset++] = (TLS_EXTENSION_RECORD_SIZE_LIMIT >> 8) & 0xFF;
        encrypted_extensions[offset++] = TLS_EXTENSION_RECORD_SIZE_LIMIT & 0xFF;
        encrypted_extensions[offset++] = 0x00;
        encrypted_extensions[offset++] = 0x02;
        encrypted_extensions[offset++] = (rsl >> 8) & 0xFF;
        encrypted_extensions[offset++] = rsl & 0xFF;
    }
    
    /* Update handshake message length */
    uint32_t handshake_len = offset - 4;
    encrypted_extensions[1] = (handshake_len >> 16) & 0xFF;
    encrypted_extensions[2] = (handshake_len >> 8) & 0xFF;
    encrypted_extensions[3] = handshake_len & 0xFF;
    
    {
        noxtls_return_t rc = tls13_send_handshake_message(ctx, encrypted_extensions, offset);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(encrypted_extensions != ctx->handshake_workspace) NOXTLS_SECURE_FREE(encrypted_extensions, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return rc;
        }
    }
    tls13_append_handshake_message(ctx, encrypted_extensions, offset);
    if(encrypted_extensions != ctx->handshake_workspace) NOXTLS_SECURE_FREE(encrypted_extensions, TLS_SERVER_HELLO_DEFAULT_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.3 Server: Send CertificateRequest (request client cert for mutual TLS)
 */
noxtls_return_t tls13_send_certificate_request(tls13_context_t *ctx)
{
    uint8_t cert_req[32];
    uint32_t offset = 0;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    /* RFC 8446 4.3.2: certificate_request_context (1 byte len + bytes), extensions (2 byte len + bytes). Minimal: context_len=0, extensions_len=0. */
    cert_req[offset++] = TLS_HANDSHAKE_CERTIFICATE_REQUEST;
    cert_req[offset++] = 0x00;
    cert_req[offset++] = 0x00;
    cert_req[offset++] = 3;
    cert_req[offset++] = 0x00;  /* certificate_request_context length 0 */
    cert_req[offset++] = 0x00;  /* extensions length */
    cert_req[offset++] = 0x00;
    {
        noxtls_return_t rc = tls13_send_handshake_message(ctx, cert_req, offset);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    tls13_append_handshake_message(ctx, cert_req, offset);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.3 Server: Send Certificate
 */
noxtls_return_t tls13_send_certificate(tls13_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    if(ctx->server_cert == NULL || ctx->server_cert_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }
    uint8_t *certificate = ctx->handshake_workspace;
    if(certificate == NULL) {
        certificate = (uint8_t*)noxtls_malloc(TLS_HANDSHAKE_WORKSPACE_SIZE);
        if(certificate == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    uint32_t offset = 0;
    
    /* Build Certificate message */
    certificate[offset++] = TLS_HANDSHAKE_CERTIFICATE;
    certificate[offset++] = 0x00;  /* Length (3 bytes) - placeholder */
    certificate[offset++] = 0x00;
    certificate[offset++] = 0x00;
    
    /* Certificate request context (1 byte) - empty for server */
    certificate[offset++] = 0x00;
    
    /* Certificate list length (3 bytes) */
    uint32_t cert_list_len = ctx->server_cert_len + 3;  /* +3 for certificate entry length field */
    certificate[offset++] = (cert_list_len >> 16) & 0xFF;
    certificate[offset++] = (cert_list_len >> 8) & 0xFF;
    certificate[offset++] = cert_list_len & 0xFF;
    
    /* Certificate entry length (3 bytes) */
    certificate[offset++] = (ctx->server_cert_len >> 16) & 0xFF;
    certificate[offset++] = (ctx->server_cert_len >> 8) & 0xFF;
    certificate[offset++] = ctx->server_cert_len & 0xFF;
    
    /* Certificate data */
    if(offset + ctx->server_cert_len > TLS_HANDSHAKE_WORKSPACE_SIZE) {
        if(certificate != ctx->handshake_workspace) NOXTLS_SECURE_FREE(certificate, TLS_HANDSHAKE_WORKSPACE_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(certificate + offset, ctx->server_cert, ctx->server_cert_len);
    offset += ctx->server_cert_len;
    
    /* Extensions length (2 bytes) - no extensions */
    certificate[offset++] = 0x00;
    certificate[offset++] = 0x00;
    
    /* Update handshake message length */
    uint32_t handshake_len = offset - 4;
    certificate[1] = (handshake_len >> 16) & 0xFF;
    certificate[2] = (handshake_len >> 8) & 0xFF;
    certificate[3] = handshake_len & 0xFF;
    
    {
        noxtls_return_t rc = tls13_send_handshake_message(ctx, certificate, offset);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(certificate != ctx->handshake_workspace) NOXTLS_SECURE_FREE(certificate, TLS_HANDSHAKE_WORKSPACE_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
            return rc;
        }
    }
    tls13_append_handshake_message(ctx, certificate, offset);
    if(certificate != ctx->handshake_workspace) NOXTLS_SECURE_FREE(certificate, TLS_HANDSHAKE_WORKSPACE_SIZE); else if(ctx->handshake_workspace != NULL) memset(ctx->handshake_workspace, 0, TLS_HANDSHAKE_WORKSPACE_SIZE);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.3 Server: Send Certificate Verify
 */
noxtls_return_t tls13_send_certificate_verify(tls13_context_t *ctx)
{
    uint8_t certificate_verify[8 + 512];  /* header 8 + max RSA signature */
    uint32_t offset = 0;
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint32_t key_len;
    uint8_t transcript_hash[64];
    uint32_t transcript_len = sizeof(transcript_hash);
    static const char ctx_str[] = "TLS 1.3, server CertificateVerify";
    uint8_t to_sign[64 + sizeof(ctx_str) + 1 + 64];
    uint32_t to_sign_len;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    if(ctx->server_private_rsa == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = tls13_hash_messages(hash_algo, ctx->handshake_messages, ctx->handshake_messages_len,
                             transcript_hash, &transcript_len);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    memset(to_sign, 0x20, 64);
    to_sign_len = 64;
    memcpy(to_sign + to_sign_len, ctx_str, sizeof(ctx_str));
    to_sign_len += sizeof(ctx_str);
    to_sign[to_sign_len++] = 0x00;
    memcpy(to_sign + to_sign_len, transcript_hash, transcript_len);
    to_sign_len += transcript_len;

    certificate_verify[offset++] = TLS_HANDSHAKE_CERTIFICATE_VERIFY;
    certificate_verify[offset++] = 0x00;
    certificate_verify[offset++] = 0x00;
    certificate_verify[offset++] = 0x00;
    /* Signature algorithm: rsa_pss_rsae_sha256 (0x0804) */
    certificate_verify[offset++] = 0x08;
    certificate_verify[offset++] = 0x04;
    uint32_t signature_len = (uint32_t)(sizeof(certificate_verify) - 8);
    rc = noxtls_rsa_sign_pss((const rsa_key_t *)ctx->server_private_rsa, to_sign, to_sign_len,
                             certificate_verify + 8, &signature_len, NOXTLS_HASH_SHA_256);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    certificate_verify[offset++] = (signature_len >> 8) & 0xFF;
    certificate_verify[offset++] = signature_len & 0xFF;
    offset += signature_len;
    uint32_t handshake_len = offset - 4;
    certificate_verify[1] = (handshake_len >> 16) & 0xFF;
    certificate_verify[2] = (handshake_len >> 8) & 0xFF;
    certificate_verify[3] = handshake_len & 0xFF;
    {
        noxtls_return_t rc = tls13_send_handshake_message(ctx, certificate_verify, offset);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    tls13_append_handshake_message(ctx, certificate_verify, offset);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.3 Server: Send Finished
 */
noxtls_return_t tls13_send_finished_server(tls13_context_t *ctx)
{
    uint8_t finished[64];
    uint32_t offset = 0;
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint32_t key_len;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    {
        uint8_t transcript_hash[64];
        uint32_t transcript_len = sizeof(transcript_hash);
        uint8_t finished_key[64];
        uint32_t verify_len;
        rc = tls13_hash_messages(hash_algo, ctx->handshake_messages, ctx->handshake_messages_len,
                                 transcript_hash, &transcript_len);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        rc = tls13_hkdf_expand_label(hash_algo, ctx->server_handshake_traffic_secret, hash_len,
                                    (const uint8_t *)"finished", 8, NULL, 0,
                                    finished_key, hash_len);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        verify_len = hash_len;
        rc = hmac_compute(hash_algo, finished_key, hash_len, transcript_hash, transcript_len,
                          finished + 4, &verify_len);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        finished[offset++] = TLS_HANDSHAKE_FINISHED;
        finished[offset++] = 0x00;
        finished[offset++] = 0x00;
        finished[offset++] = (uint8_t)verify_len;
        offset += verify_len;
        /* RFC 5929: store first Finished verify_data for tls-unique (TLS 1.3 server sends first) */
        if(ctx->channel_binding_first_finished_len == 0 && verify_len <= sizeof(ctx->channel_binding_first_finished)) {
            memcpy(ctx->channel_binding_first_finished, finished + 4, verify_len);
            ctx->channel_binding_first_finished_len = verify_len;
        }
    }
    {
        noxtls_return_t rc = tls13_send_handshake_message(ctx, finished, offset);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    /* Server Finished is included in transcript after sending. */
    tls13_append_handshake_message(ctx, finished, offset);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.3 Server: Receive client Certificate (called when request_client_auth was set)
 */
noxtls_return_t tls13_recv_client_certificate(tls13_context_t *ctx)
{
    uint8_t *msg = NULL;
    uint32_t msg_len = 0;
    uint32_t offset;
    uint8_t ctx_len;
    uint32_t cert_list_len;
    uint32_t cert_len;
    noxtls_return_t rc;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    rc = tls13_recv_handshake_message(ctx, &msg, &msg_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(msg_len < 4 || msg[0] != TLS_HANDSHAKE_CERTIFICATE) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }
    tls13_append_handshake_message(ctx, msg, msg_len);
    offset = 4;
    if(offset + 1 > msg_len) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }
    ctx_len = msg[offset++];
    if(offset + ctx_len + 3 > msg_len) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }
    offset += ctx_len;
    cert_list_len = (msg[offset] << 16) | (msg[offset + 1] << 8) | msg[offset + 2];
    offset += 3;
    if(cert_list_len == 0) {
        free(msg);
        return NOXTLS_RETURN_SUCCESS;  /* Client sent no certificate */
    }
    if(cert_list_len < 3 || offset + cert_list_len > msg_len) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }
    cert_len = (msg[offset] << 16) | (msg[offset + 1] << 8) | msg[offset + 2];
    offset += 3;
    if(cert_len == 0 || offset + cert_len > msg_len) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }
    if(ctx->client_cert) {
        free(ctx->client_cert);
        ctx->client_cert = NULL;
    }
    ctx->client_cert = (uint8_t*)malloc(cert_len);
    if(ctx->client_cert == NULL) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(ctx->client_cert, msg + offset, cert_len);
    ctx->client_cert_len = cert_len;
    if(ctx->client_cert_parsed) {
        noxtls_x509_certificate_free((x509_certificate_t*)ctx->client_cert_parsed);
        free(ctx->client_cert_parsed);
        ctx->client_cert_parsed = NULL;
    }
    {
        x509_certificate_t *parsed = (x509_certificate_t*)malloc(sizeof(x509_certificate_t));
        if(parsed) {
            noxtls_x509_certificate_init(parsed);
            if(noxtls_x509_certificate_parse_der(parsed, ctx->client_cert, ctx->client_cert_len) == NOXTLS_RETURN_SUCCESS) {
                ctx->client_cert_parsed = parsed;
            } else {
                noxtls_x509_certificate_free(parsed);
                free(parsed);
            }
        }
    }
    free(msg);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.3 Server: Receive and verify client CertificateVerify
 */
noxtls_return_t tls13_recv_client_certificate_verify(tls13_context_t *ctx)
{
    uint8_t *msg = NULL;
    uint32_t msg_len = 0;
    noxtls_hash_algos_t hash_algo;
    uint32_t hash_len;
    uint32_t key_len;
    uint8_t transcript_hash[64];
    uint32_t transcript_len = sizeof(transcript_hash);
    uint8_t to_verify[64 + 32 + 1 + 64];
    uint32_t to_verify_len;
    noxtls_return_t rc;
    static const char ctx_str[] = "TLS 1.3, client CertificateVerify";

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_SERVER || ctx->client_cert_parsed == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    rc = tls13_recv_handshake_message(ctx, &msg, &msg_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(msg_len < 8 || msg[0] != TLS_HANDSHAKE_CERTIFICATE_VERIFY) {
        free(msg);
        return NOXTLS_RETURN_FAILED;
    }
    rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(msg);
        return rc;
    }
    rc = tls13_hash_messages(hash_algo, ctx->handshake_messages, ctx->handshake_messages_len,
                             transcript_hash, &transcript_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(msg);
        return rc;
    }
    memset(to_verify, 0x20, 64);
    to_verify_len = 64;
    memcpy(to_verify + to_verify_len, ctx_str, sizeof(ctx_str));
    to_verify_len += sizeof(ctx_str);
    to_verify[to_verify_len++] = 0x00;
    memcpy(to_verify + to_verify_len, transcript_hash, transcript_len);
    to_verify_len += transcript_len;

    {
        uint16_t sig_scheme = (msg[4] << 8) | msg[5];
        uint16_t sig_len = (msg[6] << 8) | msg[7];
        if(8u + sig_len > msg_len) {
            free(msg);
            return NOXTLS_RETURN_FAILED;
        }
        x509_certificate_t *cert = (x509_certificate_t *)ctx->client_cert_parsed;

        if(sig_scheme == TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256) {
            if(cert->rsa_modulus == NULL || cert->rsa_exponent == NULL) {
                free(msg);
                return NOXTLS_RETURN_FAILED;
            }
            {
                uint32_t key_bytes = cert->rsa_modulus_len;
                rsa_key_t rsa_key;
                if(key_bytes != 128 && key_bytes != 256 && key_bytes != 384 && key_bytes != 512) {
                    free(msg);
                    return NOXTLS_RETURN_FAILED;
                }
                rc = noxtls_rsa_key_init(&rsa_key, (key_bytes == 128) ? RSA_1024_BIT : (key_bytes == 256) ? RSA_2048_BIT :
                                         (key_bytes == 384) ? RSA_3072_BIT : RSA_4096_BIT);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    free(msg);
                    return rc;
                }
                memcpy(rsa_key.n, cert->rsa_modulus, cert->rsa_modulus_len);
                memcpy(rsa_key.e, cert->rsa_exponent, cert->rsa_exponent_len);
                rc = noxtls_rsa_verify_pss(&rsa_key, to_verify, to_verify_len, msg + 8, sig_len, NOXTLS_HASH_SHA_256);
                noxtls_rsa_key_free(&rsa_key);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    free(msg);
                    return NOXTLS_RETURN_FAILED;
                }
            }
        } else if(sig_scheme == TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256 || sig_scheme == TLS_SIGSCHEME_ECDSA_SECP384R1_SHA384) {
            if(cert->ecc_public_key == NULL || cert->ecc_public_key_len == 0) {
                free(msg);
                return NOXTLS_RETURN_FAILED;
            }
            {
                void *pubkey = NULL;
                uint32_t key_type = 0;
                ecc_key_t *ecc_key;
                ecdsa_signature_t ecdsa_sig;
                uint32_t coord_size = (sig_scheme == TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256) ? 32u : 48u;
                noxtls_hash_algos_t verify_hash = (sig_scheme == TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256) ? NOXTLS_HASH_SHA_256 : NOXTLS_HASH_SHA_384;

                transcript_len = sizeof(transcript_hash);
                rc = tls13_hash_messages(verify_hash, ctx->handshake_messages, ctx->handshake_messages_len,
                                         transcript_hash, &transcript_len);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    free(msg);
                    return NOXTLS_RETURN_FAILED;
                }
                memset(to_verify, 0x20, 64);
                to_verify_len = 64;
                memcpy(to_verify + to_verify_len, ctx_str, sizeof(ctx_str));
                to_verify_len += sizeof(ctx_str);
                to_verify[to_verify_len++] = 0x00;
                memcpy(to_verify + to_verify_len, transcript_hash, transcript_len);
                to_verify_len += transcript_len;

                rc = noxtls_x509_certificate_get_public_key(cert, &pubkey, &key_type);
                if(rc != NOXTLS_RETURN_SUCCESS || pubkey == NULL || key_type != 2) {
                    if(pubkey) free(pubkey);
                    free(msg);
                    return NOXTLS_RETURN_FAILED;
                }
                ecc_key = (ecc_key_t *)pubkey;
                if(ecc_key->curve == NULL || ecc_key->curve->size != coord_size) {
                    noxtls_ecc_key_free(ecc_key);
                    free(ecc_key);
                    free(msg);
                    return NOXTLS_RETURN_FAILED;
                }
                rc = noxtls_ecdsa_signature_init(&ecdsa_sig, coord_size);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    noxtls_ecc_key_free(ecc_key);
                    free(ecc_key);
                    free(msg);
                    return NOXTLS_RETURN_FAILED;
                }
                rc = noxtls_ecdsa_signature_parse_der(msg + 8, (uint32_t)sig_len, &ecdsa_sig, coord_size);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    noxtls_ecdsa_signature_free(&ecdsa_sig);
                    noxtls_ecc_key_free(ecc_key);
                    free(ecc_key);
                    free(msg);
                    return NOXTLS_RETURN_FAILED;
                }
                rc = noxtls_ecdsa_verify(ecc_key, to_verify, to_verify_len, &ecdsa_sig, verify_hash);
                noxtls_ecdsa_signature_free(&ecdsa_sig);
                noxtls_ecc_key_free(ecc_key);
                free(ecc_key);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    free(msg);
                    return NOXTLS_RETURN_FAILED;
                }
            }
        } else if(sig_scheme == TLS_SIGSCHEME_ED25519) {
            if(!cert->has_ed25519 || sig_len != 64) {
                free(msg);
                return NOXTLS_RETURN_FAILED;
            }
            rc = noxtls_ed25519_verify(cert->ed25519_public_key, to_verify, to_verify_len, msg + 8);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                free(msg);
                return NOXTLS_RETURN_FAILED;
            }
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
        } else if(sig_scheme == TLS_SIGSCHEME_ED448) {
            if(!cert->has_ed448 || sig_len != 114) {
                free(msg);
                return NOXTLS_RETURN_FAILED;
            }
            rc = noxtls_ed448_verify(cert->ed448_public_key, to_verify, to_verify_len, msg + 8);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                free(msg);
                return NOXTLS_RETURN_FAILED;
            }
#endif
        } else {
            free(msg);
            return NOXTLS_RETURN_FAILED;
        }
    }
    tls13_append_handshake_message(ctx, msg, msg_len);
    free(msg);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.3 Server: Receive Finished from Client
 */
noxtls_return_t tls13_recv_finished_client(tls13_context_t *ctx)
{
    uint8_t *msg = NULL;
    uint32_t msg_len = 0;
    noxtls_return_t rc;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    
    rc = tls13_recv_handshake_message(ctx, &msg, &msg_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(msg_len < 4 || msg[0] != TLS_HANDSHAKE_FINISHED) {
        if(msg) free(msg);
        return NOXTLS_RETURN_FAILED;
    }
    {
        noxtls_hash_algos_t hash_algo;
        uint32_t hash_len;
        uint32_t key_len;
        uint8_t transcript_hash[64];
        uint32_t transcript_len = sizeof(transcript_hash);
        uint8_t finished_key[64];
        uint8_t verify_data[64];
        uint32_t verify_len;
        rc = tls13_get_cipher_params(ctx->cipher_suite, &hash_algo, &hash_len, &key_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            free(msg);
            return rc;
        }
        rc = tls13_hash_messages(hash_algo, ctx->handshake_messages, ctx->handshake_messages_len,
                                transcript_hash, &transcript_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            free(msg);
            return rc;
        }
        rc = tls13_hkdf_expand_label(hash_algo, ctx->client_handshake_traffic_secret, hash_len,
                                     (const uint8_t *)"finished", 8, NULL, 0,
                                     finished_key, hash_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            free(msg);
            return rc;
        }
        verify_len = hash_len;
        rc = hmac_compute(hash_algo, finished_key, hash_len, transcript_hash, transcript_len,
                         verify_data, &verify_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            free(msg);
            return rc;
        }
        if(msg_len != 4u + verify_len || noxtls_secret_memcmp(msg + 4, verify_data, verify_len) != 0) {
            free(msg);
            return NOXTLS_RETURN_FAILED;
        }
    }
    tls13_append_handshake_message(ctx, msg, msg_len);
    free(msg);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.3 Server: Accept connection
 */
noxtls_return_t tls13_accept(tls13_context_t *ctx)
{
    noxtls_return_t rc;
    
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.role != TLS_ROLE_SERVER) {
        return NOXTLS_RETURN_FAILED;
    }
    
    ctx->base.base.state = TLS_STATE_HANDSHAKING;
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_START);
    
    /* Receive Client Hello */
    do {
        NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_ACCEPT_RECV_CH);
        rc = tls13_recv_client_hello(ctx);
        if(rc == NOXTLS_RETURN_TIMEOUT && tls13_is_dtls(ctx)) {
            continue;
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_RECV_CH, rc);
            return rc;
        }
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_RECV_CH, rc);
        break;
    } while(1);
    
    /* Send Server Hello */
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_ACCEPT_SEND_SH);
    rc = tls13_send_server_hello(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_SH, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_SH, rc);
    
    if(!ctx->psk_in_use || ctx->psk_use_ecdhe) {
        rc = tls13_process_client_key_share_internal(ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    } else {
        rc = tls13_derive_handshake_keys(ctx, NULL, 0);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    
    /* Send Encrypted Extensions */
    rc = tls13_send_encrypted_extensions(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(ctx->request_client_auth) {
        rc = tls13_send_certificate_request(ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    if(!ctx->psk_in_use) {
        /* Send Certificate */
        rc = tls13_send_certificate(ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        
        /* Send Certificate Verify */
        rc = tls13_send_certificate_verify(ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    
    /* Send Finished */
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_ACCEPT_SEND_FINISHED);
    rc = tls13_send_finished_server(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_FINISHED, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_SEND_FINISHED, rc);
    if(ctx->request_client_auth) {
        rc = tls13_recv_client_certificate(ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if(ctx->client_cert != NULL && ctx->client_cert_len > 0) {
            rc = tls13_recv_client_certificate_verify(ctx);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
        }
    }
    /* Receive Finished */
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_ACCEPT_RECV_FINISHED);
    rc = tls13_recv_finished_client(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_RECV_FINISHED, rc);
        return rc;
    }
    NOXTLS_STATE_EXIT(ctx, NOXTLS_STATE_ACCEPT_RECV_FINISHED, rc);
    
    rc = tls13_derive_application_secrets(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = tls13_install_application_keys(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = tls13_send_new_session_ticket(ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        /* NST is optional post-handshake data; handshake is already complete. */
        noxtls_debug_printf("[TLS13_DEBUG] tls13_accept: send_new_session_ticket failed rc=%d (ignored)\n", rc);
    }
    
    ctx->base.base.state = TLS_STATE_CONNECTED;
    NOXTLS_STATE_ENTER(ctx, NOXTLS_STATE_CONNECTED);
    dtls_mark_validated(&ctx->base);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.3 Client: Send 0-RTT early data (when resuming, before handshake completes).
 * Encrypts with early_write_key/iv and sends as APPLICATION_DATA. Call only after ClientHello, before EndOfEarlyData.
 */
noxtls_return_t tls13_send_early_data(tls13_context_t *ctx, const uint8_t *data, uint32_t len)
{
    uint32_t inner_len = TLS13_RECORD_WORKSPACE_HALF;
    uint32_t encrypted_len = TLS13_RECORD_WORKSPACE_HALF;
    uint8_t *inner = ctx->record_workspace;
    uint8_t *encrypted_record = ctx->record_workspace + TLS13_RECORD_WORKSPACE_HALF;
    noxtls_return_t rc;

    if(ctx == NULL || data == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->base.base.role != TLS_ROLE_CLIENT || !ctx->early_data_phase || ctx->sent_end_of_early_data) {
        return NOXTLS_RETURN_FAILED;
    }
    if(len == 0 || len > TLS_MAX_RECORD_SIZE) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ctx->record_workspace == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    /* Optional: enforce max_early_data_size if server sent it (after EE we'd know; for now we allow) */

    rc = tls13_build_inner_plaintext(data, len, TLS_RECORD_APPLICATION_DATA, inner, &inner_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_tls13_encrypt_record_early(ctx, ctx->ticket_cipher_suite, TLS_RECORD_APPLICATION_DATA,
                                           inner, inner_len, encrypted_record, &encrypted_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_APPLICATION_DATA, encrypted_record, encrypted_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    ctx->early_data_sent = 1;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.3: Send application data
 */
noxtls_return_t tls13_send(tls13_context_t *ctx, const uint8_t *data, uint32_t len)
{
    uint32_t inner_len = TLS13_RECORD_WORKSPACE_HALF;
    uint32_t encrypted_len = TLS13_RECORD_WORKSPACE_HALF;  /* Extra space for tag */
    uint8_t *inner = ctx->record_workspace;
    uint8_t *encrypted_record = ctx->record_workspace + TLS13_RECORD_WORKSPACE_HALF;
    noxtls_return_t rc;
    uint32_t max_payload = (ctx->record_size_limit_send > 0) ? ctx->record_size_limit_send : (uint32_t)TLS_MAX_RECORD_SIZE;

    if(ctx == NULL || data == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(ctx->base.base.state != TLS_STATE_CONNECTED) {
        return NOXTLS_RETURN_FAILED;
    }

    if(len > TLS_MAX_RECORD_SIZE) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if(ctx->record_workspace == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    /* RFC 8449: send in chunks not exceeding record_size_limit_send */
    uint32_t sent = 0;
    while(sent < len) {
        uint32_t chunk = len - sent;
        if(chunk > max_payload) {
            chunk = max_payload;
        }
        inner_len = TLS13_RECORD_WORKSPACE_HALF;
        rc = tls13_build_inner_plaintext(data + sent, chunk, TLS_RECORD_APPLICATION_DATA, inner, &inner_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }

        if(tls13_is_dtls(ctx)) {
            rc = noxtls_tls13_send_dtls13_encrypted_record(ctx, 0, TLS_RECORD_APPLICATION_DATA, inner, inner_len, 1);
        } else {
            encrypted_len = TLS13_RECORD_WORKSPACE_HALF;
            rc = noxtls_tls13_encrypt_record(ctx, TLS_RECORD_APPLICATION_DATA, inner, inner_len,
                                      encrypted_record, &encrypted_len);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                rc = noxtls_tls_send_record(&ctx->base.base, TLS_RECORD_APPLICATION_DATA, encrypted_record, encrypted_len);
            }
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        sent += chunk;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.3: Receive application data
 */
noxtls_return_t tls13_recv(tls13_context_t *ctx, uint8_t *data, uint32_t *len)
{
    tls_record_t record;
    noxtls_return_t rc;
    uint8_t content_type = 0;
    
    if(ctx == NULL || data == NULL || len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->base.base.state != TLS_STATE_CONNECTED) {
        return NOXTLS_RETURN_FAILED;
    }

    if(ctx->pending_app_data != NULL && ctx->pending_app_data_len > 0) {
        uint32_t copy_len = ctx->pending_app_data_len;
        if(*len < copy_len) {
            copy_len = *len;
        }
        memcpy(data, ctx->pending_app_data, copy_len);
        *len = copy_len;
        free(ctx->pending_app_data);
        ctx->pending_app_data = NULL;
        ctx->pending_app_data_len = 0;
        return NOXTLS_RETURN_SUCCESS;
    }
    
    rc = noxtls_tls_recv_record(&ctx->base.base, &record);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(record.length > 0 && record.data == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    if(record.type != TLS_RECORD_APPLICATION_DATA) {
        if(record.data) free(record.data);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Decrypt application data using AEAD */
    rc = noxtls_tls13_decrypt_record(ctx, record.data, record.length, data, len);
    if(record.data) free(record.data);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_NS_EVENT(ctx, NOXTLS_NS_MOD_CRYPTO, NOXSIGHT_SEVERITY_ERROR,
                        NOXTLS_EVT_DECRYPT_FAIL, rc, record.length);
        return rc;
    }

    rc = tls13_extract_inner_plaintext(data, len, &content_type);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(content_type != TLS_RECORD_APPLICATION_DATA) {
        return NOXTLS_RETURN_FAILED;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.3: Close connection
 */
noxtls_return_t tls13_close(tls13_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Send close_notify alert */
    noxtls_tls_send_alert(&ctx->base.base, TLS_ALERT_LEVEL_WARNING, TLS_ALERT_CLOSE_NOTIFY);
    
    ctx->base.base.state = TLS_STATE_CLOSED;
    
    return NOXTLS_RETURN_SUCCESS;
}

