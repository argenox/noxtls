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
* File:    noxtls_dtls_common.c
* Summary: DTLS Common Implementation
*
*/

#include <stdint.h>
#include <string.h>
#include "common/noxtls_memory.h"
#include "noxtls_dtls_common.h"
#include "noxtls_tls_common.h"
#include "mdigest/sha256/noxtls_sha256.h"

static void dtls_flight_clear(dtls_context_t *ctx)
{
    if(ctx == NULL) {
        return;
    }

    ctx->flight_buffer_len = 0;
}

static void dtls_reassembly_slot_clear(dtls_reassembly_slot_t *slot)
{
    if(slot == NULL) {
        return;
    }
    if(slot->buffer != NULL) {
        noxtls_free(slot->buffer);
    }
    if(slot->received != NULL) {
        noxtls_free(slot->received);
    }
    memset(slot, 0, sizeof(*slot));
}

static void dtls_reassembly_queue_clear(dtls_context_t *ctx)
{
    if(ctx == NULL) {
        return;
    }
    for(uint32_t i = 0; i < DTLS_REASSEMBLY_QUEUE_SIZE; i++) {
        dtls_reassembly_slot_clear(&ctx->reassembly_queue[i]);
    }
}

static dtls_reassembly_slot_t *dtls_reassembly_slot_find(dtls_context_t *ctx, uint16_t message_seq)
{
    if(ctx == NULL) {
        return NULL;
    }
    for(uint32_t i = 0; i < DTLS_REASSEMBLY_QUEUE_SIZE; i++) {
        if(ctx->reassembly_queue[i].active && ctx->reassembly_queue[i].message_seq == message_seq) {
            return &ctx->reassembly_queue[i];
        }
    }
    return NULL;
}

static dtls_reassembly_slot_t *dtls_reassembly_slot_alloc(dtls_context_t *ctx)
{
    dtls_reassembly_slot_t *oldest = NULL;
    if(ctx == NULL) {
        return NULL;
    }
    for(uint32_t i = 0; i < DTLS_REASSEMBLY_QUEUE_SIZE; i++) {
        if(!ctx->reassembly_queue[i].active) {
            return &ctx->reassembly_queue[i];
        }
        if(oldest == NULL || ctx->reassembly_queue[i].message_seq < oldest->message_seq) {
            oldest = &ctx->reassembly_queue[i];
        }
    }
    if(oldest != NULL) {
        dtls_reassembly_slot_clear(oldest);
    }
    return oldest;
}

static noxtls_return_t dtls_reassembly_slot_store(dtls_reassembly_slot_t *slot,
                                                   const dtls_handshake_fragment_t *fragment)
{
    if(slot == NULL || fragment == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(fragment->length > DTLS_MAX_HANDSHAKE_SIZE ||
       fragment->fragment_offset + fragment->fragment_length > fragment->length) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(fragment->fragment_length > 0u && fragment->data == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(!slot->active || slot->message_seq != fragment->message_seq || slot->length != fragment->length) {
        dtls_reassembly_slot_clear(slot);
        slot->buffer = (uint8_t*)noxtls_malloc(fragment->length == 0u ? 1u : fragment->length);
        slot->received = (uint8_t*)noxtls_malloc(fragment->length == 0u ? 1u : fragment->length);
        if(slot->buffer == NULL || slot->received == NULL) {
            dtls_reassembly_slot_clear(slot);
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        memset(slot->buffer, 0, fragment->length == 0u ? 1u : fragment->length);
        memset(slot->received, 0, fragment->length == 0u ? 1u : fragment->length);
        slot->active = 1;
        slot->msg_type = fragment->msg_type;
        slot->message_seq = fragment->message_seq;
        slot->length = fragment->length;
        slot->capacity = fragment->length;
        slot->received_len = fragment->length;
        slot->received_count = 0;
    }
    if(slot->msg_type != fragment->msg_type || slot->length != fragment->length) {
        return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
    }
    for(uint32_t i = 0; i < fragment->fragment_length; i++) {
        uint32_t idx = fragment->fragment_offset + i;
        if(slot->received[idx] != 0u) {
            if(slot->buffer[idx] != fragment->data[i]) {
                return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
            }
        } else {
            slot->buffer[idx] = fragment->data[i];
            slot->received[idx] = 1u;
            slot->received_count++;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t dtls_reassembly_slot_take_complete(dtls_context_t *ctx,
                                                           uint8_t **complete_msg,
                                                           uint32_t *complete_len)
{
    dtls_reassembly_slot_t *slot;
    if(ctx == NULL || complete_msg == NULL || complete_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    slot = dtls_reassembly_slot_find(ctx, ctx->expected_message_seq);
    if(slot == NULL || slot->received_count != slot->length) {
        return NOXTLS_RETURN_TIMEOUT;
    }
    *complete_msg = (uint8_t*)noxtls_malloc(slot->length == 0u ? 1u : slot->length);
    if(*complete_msg == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    if(slot->length > 0u) {
        memcpy(*complete_msg, slot->buffer, slot->length);
    }
    *complete_len = slot->length;
    ctx->expected_message_seq++;
    dtls_reassembly_slot_clear(slot);
    return NOXTLS_RETURN_SUCCESS;
}

static void dtls_ack_range_add(dtls_context_t *ctx, uint16_t epoch, /* NOLINT(bugprone-easily-swappable-parameters): ACK tuple is (epoch,sequence). */
                               uint64_t seq)
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
                        size_t new_bytes = sizeof(uint64_t) * new_capacity;
                        size_t copy_bytes = sizeof(uint64_t) * ctx->ack_range_count;
                        uint64_t *new_min = (uint64_t*)noxtls_malloc(new_bytes);
                        uint64_t *new_max = (uint64_t*)noxtls_malloc(new_bytes);
                        if(new_min == NULL || new_max == NULL) {
                            if(new_min != NULL) noxtls_free(new_min);
                            if(new_max != NULL) noxtls_free(new_max);
                            return;
                        }
                        memcpy(new_min, ctx->ack_ranges_min, copy_bytes);
                        memcpy(new_max, ctx->ack_ranges_max, copy_bytes);
                        noxtls_free(ctx->ack_ranges_min);
                        noxtls_free(ctx->ack_ranges_max);
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

static int dtls_record_acked_by_last_ack(const dtls_context_t *ctx, uint16_t epoch, uint64_t seq);
static int dtls_parse_record_epoch_seq(const uint8_t *record, uint16_t record_len,
                                       uint16_t *epoch, uint64_t *seq);

static noxtls_return_t dtls_flight_append(dtls_context_t *ctx, const uint8_t *record, uint32_t record_len)
{
    uint32_t needed;
    uint8_t *new_buf;

    if(ctx == NULL || record == NULL || record_len == 0) {
        return NOXTLS_RETURN_NULL;
    }

    if(record_len > UINT32_MAX - ctx->flight_buffer_len - 2u) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    needed = ctx->flight_buffer_len + 2u + record_len;
    if(needed > ctx->flight_buffer_capacity) {
        uint32_t new_capacity = ctx->flight_buffer_capacity == 0 ? 1024 : ctx->flight_buffer_capacity << 1;
        while(new_capacity < needed) {
            if(new_capacity > UINT32_MAX / 2u) {
                new_capacity = needed;
                break;
            }
            new_capacity *= 2u;
        }
        new_buf = (uint8_t*)noxtls_realloc(ctx->flight_buffer, new_capacity);
        if(new_buf == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        ctx->flight_buffer = new_buf;
        ctx->flight_buffer_capacity = new_capacity;
    }

    ctx->flight_buffer[ctx->flight_buffer_len] = (uint8_t)((record_len >> 8) & 0xFF);
    ctx->flight_buffer[ctx->flight_buffer_len + 1] = (uint8_t)(record_len & 0xFF);
    memcpy(ctx->flight_buffer + ctx->flight_buffer_len + 2, record, record_len);
    ctx->flight_buffer_len += 2 + record_len;

    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t dtls_flight_retransmit(dtls_context_t *ctx)
{
    uint32_t offset = 0;
    uint32_t sent_records = 0;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(ctx->flight_buffer_len == 0 || ctx->base.send_callback == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    if(ctx->flight_has_range &&
       ctx->last_ack_epoch == ctx->flight_epoch &&
       ctx->last_ack_range_min <= ctx->flight_min_seq &&
       ctx->last_ack_range_max >= ctx->flight_max_seq) {
        return NOXTLS_RETURN_SUCCESS;
    }

    while(offset + 2 <= ctx->flight_buffer_len && sent_records < DTLS_RETRANSMIT_RECORD_BURST) {
        uint16_t rec_len = (uint16_t)((ctx->flight_buffer[offset] << 8) |
                                      ctx->flight_buffer[offset + 1]);
        uint32_t rec_offset = offset + 2;
        uint16_t rec_epoch = 0;
        uint64_t rec_seq = 0;
        if(rec_offset + rec_len > ctx->flight_buffer_len) {
            return NOXTLS_RETURN_FAILED;
        }

        if(!dtls_parse_record_epoch_seq(ctx->flight_buffer + rec_offset, rec_len, &rec_epoch, &rec_seq) ||
           !dtls_record_acked_by_last_ack(ctx, rec_epoch, rec_seq)) {
            if(ctx->base.send_callback(ctx->base.user_data,
                                       ctx->flight_buffer + rec_offset,
                                       rec_len) < 0) {
                return NOXTLS_RETURN_FAILED;
            }
            sent_records++;
        }

        offset = rec_offset + rec_len;
    }

    if(ctx->base.time_callback != NULL && sent_records > 0u) {
        ctx->last_flight_sent_ms = ctx->base.time_callback(ctx->base.user_data);
    }

    return NOXTLS_RETURN_SUCCESS;
}

static void dtls_write_uint16(uint8_t *buf, uint16_t value)
{
    buf[0] = (uint8_t)((value >> 8) & 0xFF);
    buf[1] = (uint8_t)(value & 0xFF);
}

static uint32_t dtls_compute_max_fragment_for_version(uint16_t mtu, uint16_t version)
{
    uint32_t usable;
    uint32_t record_overhead = DTLS_RECORD_HEADER_SIZE;
    if(version == DTLS_VERSION_1_3) {
        record_overhead = DTLS13_UNIFIED_HEADER_WITH_LEN + DTLS13_RECORD_NUMBER_ENC_LEN;
    }
    if(mtu <= record_overhead + DTLS_HANDSHAKE_HEADER_SIZE) {
        return DTLS_MIN_FRAGMENT_SIZE;
    }
    usable = (uint32_t)mtu - record_overhead - DTLS_HANDSHAKE_HEADER_SIZE;
    if(usable > DTLS_MAX_FRAGMENT_SIZE) {
        usable = DTLS_MAX_FRAGMENT_SIZE;
    }
    if(usable < DTLS_MIN_FRAGMENT_SIZE) {
        usable = DTLS_MIN_FRAGMENT_SIZE;
    }
    return usable;
}


static void dtls_write_uint24(uint8_t *buf, uint32_t value)
{
    buf[0] = (uint8_t)((value >> 16) & 0xFF);
    buf[1] = (uint8_t)((value >> 8) & 0xFF);
    buf[2] = (uint8_t)(value & 0xFF);
}

static void dtls_write_uint48(uint8_t *buf, uint64_t value)
{
    buf[0] = (uint8_t)((value >> 40) & 0xFF);
    buf[1] = (uint8_t)((value >> 32) & 0xFF);
    buf[2] = (uint8_t)((value >> 24) & 0xFF);
    buf[3] = (uint8_t)((value >> 16) & 0xFF);
    buf[4] = (uint8_t)((value >> 8) & 0xFF);
    buf[5] = (uint8_t)(value & 0xFF);
}

static uint16_t dtls_read_uint16(const uint8_t *buf)
{
    return (uint16_t)((buf[0] << 8) | buf[1]);
}

static uint32_t dtls_read_uint24(const uint8_t *buf)
{
    return (uint32_t)((buf[0] << 16) | (buf[1] << 8) | buf[2]);
}

static uint64_t dtls_read_uint48(const uint8_t *buf)
{
    return ((uint64_t)buf[0] << 40) |
           ((uint64_t)buf[1] << 32) |
           ((uint64_t)buf[2] << 24) |
           ((uint64_t)buf[3] << 16) |
           ((uint64_t)buf[4] << 8) |
           (uint64_t)buf[5];
}

static int dtls_record_acked_by_last_ack(const dtls_context_t *ctx, uint16_t epoch, uint64_t seq)
{
    if(ctx == NULL || ctx->last_ack_epoch != epoch) {
        return 0;
    }
    if(ctx->last_ack_ranges_min != NULL && ctx->last_ack_ranges_max != NULL && ctx->last_ack_range_count > 0u) {
        for(uint8_t i = 0; i < ctx->last_ack_range_count; i++) {
            if(seq >= ctx->last_ack_ranges_min[i] && seq <= ctx->last_ack_ranges_max[i]) {
                return 1;
            }
        }
        return 0;
    }
    return (seq >= ctx->last_ack_range_min && seq <= ctx->last_ack_range_max);
}

static int dtls_parse_record_epoch_seq(const uint8_t *record, uint16_t record_len,
                                       uint16_t *epoch, uint64_t *seq)
{
    if(record == NULL || epoch == NULL || seq == NULL || record_len < DTLS_RECORD_HEADER_SIZE) {
        return 0;
    }
    if((record[0] & 0xE0u) == DTLS13_UNIFIED_FIXED_BITS) {
        *epoch = (uint16_t)(record[0] & DTLS13_UNIFIED_EPOCH_MASK);
        *seq = 0;
        return 1;
    }
    *epoch = dtls_read_uint16(record + DTLS_RECORD_EPOCH_OFFSET);
    *seq = dtls_read_uint48(record + DTLS_RECORD_SEQUENCE_OFFSET);
    return 1;
}

noxtls_return_t noxtls_dtls_context_init(dtls_context_t *ctx, tls_role_t role, uint16_t version)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    memset(ctx, 0, sizeof(dtls_context_t));
    if(noxtls_tls_context_init(&ctx->base, role, version) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    ctx->epoch = DTLS_EPOCH_UNENCRYPTED;
    ctx->read_seq_num = 0;
    ctx->write_seq_num = 0;
    ctx->send_message_seq = 0;
    ctx->mtu = DTLS_MAX_FRAGMENT_SIZE;
    ctx->max_fragment = dtls_compute_max_fragment_for_version(ctx->mtu, version);
    ctx->anti_amp_factor = 3;
    ctx->replay_window.window_bitmap = 0;
    ctx->replay_window.last_seq = 0;
    for(uint32_t i = 0; i < 4u; i++) {
        ctx->replay_windows[i].window_bitmap = 0;
        ctx->replay_windows[i].last_seq = 0;
        ctx->highest_recv_seq[i] = 0;
        ctx->highest_recv_seq_valid[i] = 0;
    }
    ctx->connection_epoch = 0;
    ctx->read_connection_epoch = 0;
    ctx->handshake_buffer = NULL;
    ctx->handshake_buffer_len = 0;
    ctx->handshake_buffer_capacity = 0;
    ctx->expected_message_seq = 0;
    ctx->expected_fragment_offset = 0;
    ctx->handshake_received = NULL;
    ctx->handshake_received_len = 0;
    ctx->handshake_received_count = 0;
    for(uint32_t i = 0; i < DTLS_REASSEMBLY_QUEUE_SIZE; i++) {
        memset(&ctx->reassembly_queue[i], 0, sizeof(ctx->reassembly_queue[i]));
    }
    ctx->flight_buffer = NULL;
    ctx->flight_buffer_len = 0;
    ctx->flight_buffer_capacity = 0;
    ctx->retransmit_max_attempts = 4;
    ctx->bytes_received = 0;
    ctx->bytes_sent = 0;
    ctx->validated = 0;
    ctx->ack_epoch = 0;
    ctx->ack_seq = 0;
    ctx->ack_pending = 0;
    ctx->ack_range_min = 0;
    ctx->ack_range_max = 0;
    ctx->ack_range_valid = 0;
    ctx->ack_range_count = 0;
    ctx->ack_range_capacity = 0;
    ctx->ack_range_limit = DTLS_MAX_ACK_RANGES;
    ctx->ack_ranges_min = NULL;
    ctx->ack_ranges_max = NULL;
    ctx->last_ack_epoch = 0;
    ctx->last_ack_seq = 0;
    ctx->last_ack_range_min = 0;
    ctx->last_ack_range_max = 0;
    ctx->last_ack_ranges_min = NULL;
    ctx->last_ack_ranges_max = NULL;
    ctx->last_ack_range_count = 0;
    ctx->flight_epoch = 0;
    ctx->flight_min_seq = 0;
    ctx->flight_max_seq = 0;
    ctx->flight_has_range = 0;
    ctx->retransmit_timeout_ms = 1000;
    ctx->retransmit_base_timeout_ms = 1000;
    ctx->retransmit_backoff_ms = 2000;
    ctx->smoothed_rtt_ms = 0;
    ctx->rttvar_ms = 0;
    ctx->rtt_estimator_valid = 0;
    ctx->last_flight_sent_ms = 0;
    ctx->final_ack_active = 0;
    ctx->final_ack_until_ms = 0;
    ctx->final_ack_len = 0;
    ctx->cookie_len = 0;

        ctx->base.record_send_buf = (uint8_t*)noxtls_malloc(5u + TLS_MAX_PROTECTED_RECORD_FRAGMENT);
    if(ctx->base.record_send_buf == NULL) {
        noxtls_tls_context_free(&ctx->base);
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_dtls_context_free(dtls_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(ctx->handshake_buffer != NULL) {
        noxtls_free(ctx->handshake_buffer);
        ctx->handshake_buffer = NULL;
    }
    if(ctx->handshake_received != NULL) {
        noxtls_free(ctx->handshake_received);
        ctx->handshake_received = NULL;
    }
    dtls_reassembly_queue_clear(ctx);
    if(ctx->flight_buffer != NULL) {
        noxtls_free(ctx->flight_buffer);
        ctx->flight_buffer = NULL;
    }
    if(ctx->ack_ranges_min != NULL) {
        noxtls_free(ctx->ack_ranges_min);
        ctx->ack_ranges_min = NULL;
    }
    if(ctx->ack_ranges_max != NULL) {
        noxtls_free(ctx->ack_ranges_max);
        ctx->ack_ranges_max = NULL;
    }
    if(ctx->last_ack_ranges_min != NULL) {
        noxtls_free(ctx->last_ack_ranges_min);
        ctx->last_ack_ranges_min = NULL;
    }
    if(ctx->last_ack_ranges_max != NULL) {
        noxtls_free(ctx->last_ack_ranges_max);
        ctx->last_ack_ranges_max = NULL;
    }
    if(ctx->base.record_send_buf != NULL) {
        noxtls_free(ctx->base.record_send_buf);
        ctx->base.record_send_buf = NULL;
    }

    noxtls_tls_context_free(&ctx->base);
    memset(ctx, 0, sizeof(dtls_context_t));

    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_dtls_set_mtu(dtls_context_t *ctx, uint16_t mtu)
{
    if(ctx == NULL || mtu == 0) {
        return NOXTLS_RETURN_NULL;
    }
    ctx->mtu = mtu;
    ctx->max_fragment = dtls_compute_max_fragment_for_version(mtu, ctx->base.version);
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t dtls_set_retransmit(dtls_context_t *ctx, uint32_t timeout_ms,
                                    uint32_t backoff_ms, uint32_t max_attempts)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(timeout_ms == 0 || backoff_ms == 0 || max_attempts == 0) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    ctx->retransmit_timeout_ms = timeout_ms;
    ctx->retransmit_base_timeout_ms = timeout_ms;
    ctx->smoothed_rtt_ms = 0;
    ctx->rttvar_ms = 0;
    ctx->rtt_estimator_valid = 0;
    ctx->retransmit_backoff_ms = backoff_ms;
    ctx->retransmit_max_attempts = max_attempts;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_dtls_set_anti_amplification_limit(dtls_context_t *ctx, uint8_t factor)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    ctx->anti_amp_factor = factor;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_dtls_set_ack_range_limit(dtls_context_t *ctx, uint8_t max_ranges)
{
    if(ctx == NULL || max_ranges == 0) {
        return NOXTLS_RETURN_NULL;
    }
    if(max_ranges > DTLS_MAX_ACK_RANGES) {
        max_ranges = DTLS_MAX_ACK_RANGES;
    }
    ctx->ack_range_limit = max_ranges;
    if(ctx->ack_range_capacity > max_ranges) {
        if(ctx->ack_ranges_min != NULL && ctx->ack_ranges_max != NULL) {
            size_t new_bytes = sizeof(uint64_t) * max_ranges;
            uint8_t keep_count = ctx->ack_range_count > max_ranges ? max_ranges : ctx->ack_range_count;
            size_t copy_bytes = sizeof(uint64_t) * keep_count;
            uint64_t *new_min = (uint64_t*)noxtls_malloc(new_bytes);
            uint64_t *new_max = (uint64_t*)noxtls_malloc(new_bytes);
            if(new_min != NULL && new_max != NULL) {
                memcpy(new_min, ctx->ack_ranges_min, copy_bytes);
                memcpy(new_max, ctx->ack_ranges_max, copy_bytes);
                noxtls_free(ctx->ack_ranges_min);
                noxtls_free(ctx->ack_ranges_max);
                ctx->ack_ranges_min = new_min;
                ctx->ack_ranges_max = new_max;
                ctx->ack_range_capacity = max_ranges;
                if(ctx->ack_range_count > max_ranges) {
                    ctx->ack_range_count = max_ranges;
                }
            } else {
                if(new_min != NULL) noxtls_free(new_min);
                if(new_max != NULL) noxtls_free(new_max);
            }
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_dtls_send_record(dtls_context_t *ctx, uint8_t type, const uint8_t *data, uint32_t len)
{
    uint8_t *record = NULL;
    uint32_t record_len;
    int32_t sent;

    if(ctx == NULL || (data == NULL && len > 0)) {
        return NOXTLS_RETURN_NULL;
    }
    if(len > DTLS_MAX_HANDSHAKE_SIZE) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if(ctx->base.send_callback == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    if(len > TLS_MAX_RECORD_SIZE) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    record_len = DTLS_RECORD_HEADER_SIZE + len;
    if(ctx->base.role == TLS_ROLE_SERVER && !ctx->validated && ctx->anti_amp_factor > 0) {
        if(ctx->bytes_received == 0) {
            return NOXTLS_RETURN_TIMEOUT;
        }
        if(ctx->bytes_sent + record_len > ctx->bytes_received * (uint64_t)ctx->anti_amp_factor) {
            return NOXTLS_RETURN_TIMEOUT;
        }
    }
    record = (uint8_t*)noxtls_malloc(record_len);
    if(record == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    record[DTLS_RECORD_TYPE_OFFSET] = type;
    /* RFC 9147: DTLS 1.3 uses legacy_record_version 0xFEFD in record header (0xFEFF allowed for initial ClientHello only) */
    if(ctx->base.version == DTLS_VERSION_1_3) {
        dtls_write_uint16(record + DTLS_RECORD_VERSION_OFFSET, DTLS_1_3_LEGACY_RECORD_VERSION);
    } else {
        dtls_write_uint16(record + DTLS_RECORD_VERSION_OFFSET, ctx->base.version);
    }
    dtls_write_uint16(record + DTLS_RECORD_EPOCH_OFFSET, ctx->epoch);
    dtls_write_uint48(record + DTLS_RECORD_SEQUENCE_OFFSET, ctx->write_seq_num);
    dtls_write_uint16(record + DTLS_RECORD_LENGTH_OFFSET, (uint16_t)len);

    if(len > 0) {
        memcpy(record + DTLS_RECORD_DATA_OFFSET, data, len);
    }

    if(type == TLS_RECORD_HANDSHAKE) {
        uint64_t seq = ctx->write_seq_num;
        if(!ctx->flight_has_range) {
            ctx->flight_epoch = ctx->epoch;
            ctx->flight_min_seq = seq;
            ctx->flight_max_seq = seq;
            ctx->flight_has_range = 1;
        } else {
            if(seq < ctx->flight_min_seq) {
                ctx->flight_min_seq = seq;
            }
            if(seq > ctx->flight_max_seq) {
                ctx->flight_max_seq = seq;
            }
        }
        if(dtls_flight_append(ctx, record, record_len) != NOXTLS_RETURN_SUCCESS) {
            noxtls_free(record);
            return NOXTLS_RETURN_FAILED;
        }
    }

    sent = ctx->base.send_callback(ctx->base.user_data, record, record_len);
    noxtls_free(record);
    if(sent < 0 || (uint32_t)sent != record_len) {
        return NOXTLS_RETURN_FAILED;
    }

    ctx->bytes_sent += record_len;
    ctx->write_seq_num++;
    if(type == TLS_RECORD_HANDSHAKE && ctx->base.time_callback != NULL) {
        ctx->last_flight_sent_ms = ctx->base.time_callback(ctx->base.user_data);
    }
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_dtls_recv_record(dtls_context_t *ctx, dtls_record_t *record)
{
    uint8_t *packet = NULL;
    int32_t received;
    uint32_t packet_capacity = DTLS_RECORD_HEADER_SIZE + TLS_MAX_RECORD_SIZE;
    uint16_t length;
    uint32_t payload_offset = DTLS_RECORD_DATA_OFFSET;
    noxtls_return_t rc;
    uint32_t attempts = 0;

    if(ctx == NULL || record == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(ctx->base.recv_callback == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    memset(record, 0, sizeof(dtls_record_t));

    packet = (uint8_t*)noxtls_malloc(packet_capacity);
    if(packet == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    while(1) {
        received = ctx->base.recv_callback(ctx->base.user_data, packet, packet_capacity);
        if(received == 0) {
            if(ctx->flight_buffer_len > 0 && attempts < ctx->retransmit_max_attempts) {
                if(ctx->base.time_callback != NULL) {
                    uint64_t now = ctx->base.time_callback(ctx->base.user_data);
                    if(ctx->last_flight_sent_ms == 0) {
                        ctx->last_flight_sent_ms = now;
                    }
                    if(now - ctx->last_flight_sent_ms < ctx->retransmit_timeout_ms) {
                        noxtls_free(packet);
                        return NOXTLS_RETURN_TIMEOUT;
                    }
                }
                dtls_flight_retransmit(ctx);
                attempts++;
                /* RFC 9147 5.8: timer value SHOULD be backed off after each retransmission. */
                ctx->retransmit_timeout_ms =
                    (uint32_t)(((uint64_t)ctx->retransmit_timeout_ms * ctx->retransmit_backoff_ms) / 1000u);
                if(ctx->retransmit_timeout_ms == 0u) {
                    ctx->retransmit_timeout_ms = 1u;
                }
                if(ctx->retransmit_timeout_ms > 60000) {
                    ctx->retransmit_timeout_ms = 60000;  /* cap at 60 seconds */
                }
                continue;
            }
            noxtls_free(packet);
            return NOXTLS_RETURN_TIMEOUT;
        }
        if(received < (int32_t)DTLS_RECORD_HEADER_SIZE) {
            noxtls_free(packet);
            return NOXTLS_RETURN_FAILED;
        }
        break;
    }
    if(received > 0) {
        ctx->retransmit_timeout_ms = ctx->retransmit_base_timeout_ms == 0u ? 1000u : ctx->retransmit_base_timeout_ms;
    }

    ctx->bytes_received += (uint64_t)received;

    /* RFC 9147: DTLSCiphertext has first byte in 0x20-0x3F (unified header); pass to TLS 1.3 for decrypt */
    if(ctx->base.version == DTLS_VERSION_1_3 && received >= 4 && (packet[0] & 0xE0) == 0x20) {
        record->type = packet[0];
        record->version = DTLS_VERSION_1_3;
        record->epoch = packet[0] & 0x03;
        record->sequence_number = 0;
        record->length = (uint16_t)(uint32_t)received;
        record->data = (uint8_t*)noxtls_malloc((uint32_t)received);
        if(record->data == NULL) {
            noxtls_free(packet);
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        memcpy(record->data, packet, (uint32_t)received);
        noxtls_free(packet);
        return NOXTLS_RETURN_SUCCESS;
    }

    record->type = packet[DTLS_RECORD_TYPE_OFFSET];
    record->version = dtls_read_uint16(packet + DTLS_RECORD_VERSION_OFFSET);
    /* RFC 9147: DTLS 1.3 sends 0xFEFD (or 0xFEFF for initial ClientHello); normalize so upper layer sees DTLS_VERSION_1_3 */
    if(ctx->base.version == DTLS_VERSION_1_3 &&
       (record->version == DTLS_1_3_LEGACY_RECORD_VERSION || record->version == 0xFEFF)) {
        record->version = DTLS_VERSION_1_3;
    }
    record->epoch = dtls_read_uint16(packet + DTLS_RECORD_EPOCH_OFFSET);
    record->sequence_number = dtls_read_uint48(packet + DTLS_RECORD_SEQUENCE_OFFSET);
    length = dtls_read_uint16(packet + DTLS_RECORD_LENGTH_OFFSET);
    ctx->read_seq_num = record->sequence_number;

    if(record->epoch != ctx->epoch) {
        noxtls_free(packet);
        return NOXTLS_RETURN_TIMEOUT;
    }

    if(length > TLS_MAX_RECORD_SIZE) {
        noxtls_free(packet);
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if(received < (int32_t)(payload_offset + length)) {
        if(received == (int32_t)DTLS_RECORD_HEADER_SIZE) {
            int32_t extra = ctx->base.recv_callback(ctx->base.user_data,
                                                    packet + payload_offset,
                                                    length);
            if(extra < 0 || (uint16_t)extra != length) {
                noxtls_free(packet);
                return NOXTLS_RETURN_FAILED;
            }
        } else {
            noxtls_free(packet);
            return NOXTLS_RETURN_FAILED;
        }
    }

    rc = noxtls_dtls_check_replay(ctx, record->sequence_number);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_free(packet);
        return rc;
    }

    record->length = length;
    if(length > 0) {
        record->data = (uint8_t*)noxtls_malloc(length);
        if(record->data == NULL) {
            noxtls_free(packet);
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        memcpy(record->data, packet + payload_offset, length);
    }

    noxtls_dtls_update_replay_window(ctx, record->sequence_number);
    if(record->type == TLS_RECORD_HANDSHAKE) {
        dtls_flight_clear(ctx);
        ctx->flight_has_range = 0;
        if(record->length > 0 && record->data[DTLS_HANDSHAKE_TYPE_OFFSET] == TLS_HANDSHAKE_ACK) {
            ctx->ack_pending = 0;
            ctx->ack_range_valid = 0;
            ctx->ack_range_count = 0;
        } else {
            dtls_ack_range_add(ctx, record->epoch, record->sequence_number);
            ctx->ack_pending = 1;
        }
    }

    noxtls_free(packet);
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t dtls_send_handshake_fragment(dtls_context_t *ctx,
                                             uint8_t msg_type,
                                             const uint8_t *data,
                                             uint32_t len, /* NOLINT(bugprone-easily-swappable-parameters): DTLS fragment fields keep RFC header ordering. */
                                             uint16_t message_seq)
{
    uint32_t offset = 0;
    uint32_t max_fragment = DTLS_MAX_FRAGMENT_SIZE;
    uint32_t buffer_len;
    uint8_t *buffer = NULL;

    if(ctx == NULL || (data == NULL && len > 0)) {
        return NOXTLS_RETURN_NULL;
    }

    if(ctx->max_fragment > 0) {
        max_fragment = ctx->max_fragment;
    }
    if(max_fragment < DTLS_MIN_FRAGMENT_SIZE) {
        max_fragment = DTLS_MIN_FRAGMENT_SIZE;
    }
    buffer_len = DTLS_HANDSHAKE_HEADER_SIZE + max_fragment;
    buffer = (uint8_t*)noxtls_malloc(buffer_len);
    if(buffer == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    while(offset < len) {
        noxtls_return_t rc;
        uint32_t fragment_len = len - offset;
        if(fragment_len > max_fragment) {
            fragment_len = max_fragment;
        }

        buffer[DTLS_HANDSHAKE_TYPE_OFFSET] = msg_type;
        dtls_write_uint24(buffer + DTLS_HANDSHAKE_LENGTH_OFFSET, len);
        dtls_write_uint16(buffer + DTLS_HANDSHAKE_MESSAGE_SEQ_OFFSET, message_seq);
        dtls_write_uint24(buffer + DTLS_HANDSHAKE_FRAGMENT_OFFSET, offset);
        dtls_write_uint24(buffer + DTLS_HANDSHAKE_FRAGMENT_LEN_OFFSET, fragment_len);

        if(fragment_len > 0) {
            memcpy(buffer + DTLS_HANDSHAKE_BODY_OFFSET, data + offset, fragment_len);
        }

        rc = noxtls_dtls_send_record(ctx, TLS_RECORD_HANDSHAKE, buffer,
                              DTLS_HANDSHAKE_HEADER_SIZE + fragment_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_free(buffer);
            return rc;
        }

        offset += fragment_len;
    }

    noxtls_free(buffer);
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_dtls_recv_handshake_fragment(dtls_context_t *ctx, dtls_handshake_fragment_t *fragment)
{
    dtls_record_t record;
    noxtls_return_t rc;
    uint32_t fragment_len;

    if(ctx == NULL || fragment == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    memset(fragment, 0, sizeof(dtls_handshake_fragment_t));

    rc = noxtls_dtls_recv_record(ctx, &record);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(record.type != TLS_RECORD_HANDSHAKE || record.length < DTLS_HANDSHAKE_HEADER_SIZE) {
        if(record.data) {
            noxtls_free(record.data);
        }
        return NOXTLS_RETURN_FAILED;
    }

    fragment->msg_type = record.data[DTLS_HANDSHAKE_TYPE_OFFSET];
    fragment->length = dtls_read_uint24(record.data + DTLS_HANDSHAKE_LENGTH_OFFSET);
    fragment->message_seq = dtls_read_uint16(record.data + DTLS_HANDSHAKE_MESSAGE_SEQ_OFFSET);
    fragment->fragment_offset = dtls_read_uint24(record.data + DTLS_HANDSHAKE_FRAGMENT_OFFSET);
    fragment->fragment_length = dtls_read_uint24(record.data + DTLS_HANDSHAKE_FRAGMENT_LEN_OFFSET);

    if(fragment->length > DTLS_MAX_HANDSHAKE_SIZE) {
        noxtls_free(record.data);
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    fragment_len = fragment->fragment_length;
    if(fragment_len > ((uint32_t)record.length - DTLS_HANDSHAKE_HEADER_SIZE)) {
        noxtls_free(record.data);
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if(fragment_len > 0) {
        fragment->data = (uint8_t*)noxtls_malloc(fragment_len);
        if(fragment->data == NULL) {
            noxtls_free(record.data);
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        memcpy(fragment->data, record.data + DTLS_HANDSHAKE_BODY_OFFSET, fragment_len);
    }

    noxtls_free(record.data);
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_dtls_reassemble_handshake(dtls_context_t *ctx,
                                          dtls_handshake_fragment_t *fragment,
                                          uint8_t **complete_msg,
                                          uint32_t *complete_len)
{
    uint32_t total_len;
    noxtls_return_t rc;

    if(ctx == NULL || fragment == NULL || complete_msg == NULL || complete_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    *complete_msg = NULL;
    *complete_len = 0;

    rc = dtls_reassembly_slot_take_complete(ctx, complete_msg, complete_len);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    total_len = fragment->length;
    if(total_len > DTLS_MAX_HANDSHAKE_SIZE) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(fragment->fragment_offset + fragment->fragment_length > total_len) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(fragment->fragment_length > 0u && fragment->data == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(fragment->message_seq < ctx->expected_message_seq) {
        return NOXTLS_RETURN_TIMEOUT;
    }

    if(fragment->message_seq > ctx->expected_message_seq) {
        dtls_reassembly_slot_t *slot = dtls_reassembly_slot_find(ctx, fragment->message_seq);
        if(slot == NULL) {
            slot = dtls_reassembly_slot_alloc(ctx);
        }
        return dtls_reassembly_slot_store(slot, fragment);
    }

    if(fragment->fragment_offset == 0 && fragment->fragment_length == total_len) {
        *complete_msg = (uint8_t*)noxtls_malloc(total_len == 0u ? 1u : total_len);
        if(*complete_msg == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        if(total_len > 0U) {
            memcpy(*complete_msg, fragment->data, total_len);
        }
        *complete_len = total_len;
        ctx->expected_message_seq++;
        return NOXTLS_RETURN_SUCCESS;
    }

    if(ctx->handshake_buffer == NULL || ctx->handshake_buffer_len != total_len) {
        uint32_t alloc_len = (total_len == 0u) ? 1u : total_len;
        ctx->expected_fragment_offset = 0;
        ctx->handshake_buffer_len = total_len;
        if(ctx->handshake_buffer == NULL || ctx->handshake_buffer_capacity < alloc_len) {
            uint8_t *new_buf = (uint8_t*)noxtls_realloc(ctx->handshake_buffer, alloc_len);
            if(new_buf == NULL) {
                return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
            }
            ctx->handshake_buffer = new_buf;
            ctx->handshake_buffer_capacity = alloc_len;
        }
        if(ctx->handshake_received == NULL || ctx->handshake_received_len < alloc_len) {
            uint8_t *new_map = (uint8_t*)noxtls_realloc(ctx->handshake_received, alloc_len);
            if(new_map == NULL) {
                return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
            }
            ctx->handshake_received = new_map;
            ctx->handshake_received_len = alloc_len;
        }
        memset(ctx->handshake_buffer, 0, alloc_len);
        memset(ctx->handshake_received, 0, alloc_len);
        ctx->handshake_received_count = 0;
    }

    if(fragment->fragment_length > 0) {
        for(uint32_t i = 0; i < fragment->fragment_length; i++) {
            uint32_t idx = fragment->fragment_offset + i;
            if(ctx->handshake_received[idx] != 0u) {
                if(ctx->handshake_buffer[idx] != fragment->data[i]) {
                    return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
                }
            } else {
                ctx->handshake_buffer[idx] = fragment->data[i];
                ctx->handshake_received[idx] = 1u;
                ctx->handshake_received_count++;
            }
        }
    }

    if(ctx->handshake_received_count == total_len) {
        *complete_msg = (uint8_t*)noxtls_malloc(total_len == 0u ? 1u : total_len);
        if(*complete_msg == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        if(total_len > 0u) {
            memcpy(*complete_msg, ctx->handshake_buffer, total_len);
        }
        *complete_len = total_len;
        ctx->handshake_received_count = 0;
        ctx->expected_message_seq++;
    }

    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_dtls_check_replay(dtls_context_t *ctx, uint64_t sequence_number)
{
    uint64_t last_seq;
    uint64_t diff;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    last_seq = ctx->replay_window.last_seq;
    if(sequence_number > last_seq) {
        return NOXTLS_RETURN_SUCCESS;
    }

    diff = last_seq - sequence_number;
    if(diff >= DTLS_REPLAY_WINDOW_SIZE) {
        return NOXTLS_RETURN_FAILED;
    }

    if((ctx->replay_window.window_bitmap >> diff) & 0x1U) {
        return NOXTLS_RETURN_FAILED;
    }

    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_dtls_update_replay_window(dtls_context_t *ctx, uint64_t sequence_number)
{
    uint64_t last_seq;
    uint64_t diff;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    last_seq = ctx->replay_window.last_seq;
    if(sequence_number > last_seq) {
        diff = sequence_number - last_seq;
        if(diff >= DTLS_REPLAY_WINDOW_SIZE) {
            ctx->replay_window.window_bitmap = 1;
        } else {
            ctx->replay_window.window_bitmap <<= diff;
            ctx->replay_window.window_bitmap |= 1;
        }
        ctx->replay_window.last_seq = sequence_number;
        return NOXTLS_RETURN_SUCCESS;
    }

    diff = last_seq - sequence_number;
    if(diff < DTLS_REPLAY_WINDOW_SIZE) {
        ctx->replay_window.window_bitmap |= (uint64_t)1 << diff;
    }

    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_dtls_generate_cookie(dtls_context_t *ctx,
                                     const uint8_t *client_hello,
                                     uint32_t client_hello_len,
                                     uint8_t *cookie,
                                     uint32_t *cookie_len)
{
    uint8_t digest[HASH_SHA256_OUT_LEN];
    noxtls_sha_ctx_t sha_ctx;

    if(ctx == NULL || client_hello == NULL || cookie == NULL || cookie_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(*cookie_len < HASH_SHA256_OUT_LEN) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if(noxtls_sha256_init(&sha_ctx, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_sha256_update(&sha_ctx, (uint8_t*)client_hello, client_hello_len);
    if(noxtls_sha256_finish(&sha_ctx, digest) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    memcpy(cookie, digest, HASH_SHA256_OUT_LEN);
    memcpy(ctx->cookie, digest, HASH_SHA256_OUT_LEN);
    ctx->cookie_len = HASH_SHA256_OUT_LEN;
    *cookie_len = HASH_SHA256_OUT_LEN;

    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_dtls_verify_cookie(const dtls_context_t *ctx,
                                   const uint8_t *cookie,
                                   uint32_t cookie_len)
{
    if(ctx == NULL || cookie == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(cookie_len != ctx->cookie_len || ctx->cookie_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    if(memcmp(cookie, ctx->cookie, cookie_len) != 0) {
        return NOXTLS_RETURN_FAILED;
    }

    return NOXTLS_RETURN_SUCCESS;
}

void noxtls_dtls_mark_validated(dtls_context_t *ctx)
{
    if(ctx == NULL) {
        return;
    }
    ctx->validated = 1;
}
