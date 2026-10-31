/* Copyright (c) 2026 Argenox Technologies LLC.
 * SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial */
/**
 * @file dtls_reassembly_ut.c
 * @brief DTLS handshake reassembly: out-of-order and overlapping fragments, future-message
 *        queue and the NOXTLS_DTLS_REASSEMBLY_MAX_BYTES budget.
 * @ingroup noxtls_dtls13_recovery
 */
#include <stdint.h>
#include <string.h>

#include "noxtls_config.h"
#include "common/noxtls_memory.h"
#include "tls/noxtls_dtls_common.h"
#include "runner.h"
#include "test_assert.h"

#define REASM_MSG_LEN 3000U

static uint8_t g_msg[REASM_MSG_LEN];

/** @brief Fill the reference message with a position-dependent pattern. */
static void reasm_fill(uint8_t seed)
{
    for(uint32_t i = 0U; i < REASM_MSG_LEN; ++i) {
        g_msg[i] = (uint8_t)((i * 31U) + seed);
    }
}

/**
 * @brief Feed one fragment [off, off+len) of a message of total length total.
 *
 * @return The reassembly return code; *out receives a completed message (caller frees).
 */
static noxtls_return_t reasm_feed(dtls_context_t *ctx, const uint8_t *msg, uint16_t seq,
                                  uint32_t total, uint32_t off, uint32_t len,
                                  uint8_t **out, uint32_t *out_len)
{
    dtls_handshake_fragment_t frag;

    memset(&frag, 0, sizeof(frag));
    frag.msg_type = 11U;
    frag.length = total;
    frag.message_seq = seq;
    frag.fragment_offset = off;
    frag.fragment_length = len;
    frag.data = (uint8_t *)&msg[off];
    return noxtls_dtls_reassemble_handshake(ctx, &frag, out, out_len);
}

/**
 * @brief Out-of-order, overlapping and duplicate fragments reassemble to the original bytes;
 *        a conflicting overlap is rejected.
 *
 * @return Zero on success.
 */
REGISTER_TEST(dtls_reassembly_out_of_order_bitmap)
{
    dtls_context_t ctx;
    uint8_t *out = NULL;
    uint32_t out_len = 0U;
    uint8_t bad[16];

    reasm_fill(7U);
    UTNOX_EQUALS(noxtls_dtls_context_init(&ctx, TLS_ROLE_CLIENT, DTLS_VERSION_1_2), NOXTLS_RETURN_SUCCESS);

    /* Unaligned pieces (bit boundaries), out of order, overlapping. */
    UTNOX_EQUALS(reasm_feed(&ctx, g_msg, 0U, REASM_MSG_LEN, 1001U, 999U, &out, &out_len), NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_NULL(out);
    UTNOX_EQUALS(reasm_feed(&ctx, g_msg, 0U, REASM_MSG_LEN, 3U, 1005U, &out, &out_len), NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_NULL(out);
    UTNOX_EQUALS(reasm_feed(&ctx, g_msg, 0U, REASM_MSG_LEN, 3U, 1005U, &out, &out_len), NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_NULL(out);
    UTNOX_EQUALS(reasm_feed(&ctx, g_msg, 0U, REASM_MSG_LEN, 1995U, 1005U, &out, &out_len), NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_NULL(out);

    /* A conflicting retransmission of received bytes is rejected. */
    memcpy(bad, &g_msg[10], sizeof(bad));
    bad[5] ^= 0xFFU;
    {
        dtls_handshake_fragment_t frag;
        memset(&frag, 0, sizeof(frag));
        frag.msg_type = 11U;
        frag.length = REASM_MSG_LEN;
        frag.message_seq = 0U;
        frag.fragment_offset = 10U;
        frag.fragment_length = (uint32_t)sizeof(bad);
        frag.data = bad;
        UTNOX_EQUALS(noxtls_dtls_reassemble_handshake(&ctx, &frag, &out, &out_len),
                     NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);
        UTNOX_IS_NULL(out);
    }

    /* The last missing bytes [0, 3) complete the message. */
    UTNOX_EQUALS(reasm_feed(&ctx, g_msg, 0U, REASM_MSG_LEN, 0U, 3U, &out, &out_len), NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_NOT_NULL(out);
    UTNOX_EQUALS(out_len, REASM_MSG_LEN);
    UTNOX_MEM_EQUAL(out, g_msg, REASM_MSG_LEN);
    noxtls_free(out);
    out = NULL;
    /* Bitmap: 1 bit per byte. */
    UTNOX_EQUALS(ctx.handshake_received_len, (REASM_MSG_LEN + 7U) / 8U);

    /* A future message (seq 2) is queued, then delivered after seq 1. */
    reasm_fill(9U);
    UTNOX_EQUALS(reasm_feed(&ctx, g_msg, 2U, REASM_MSG_LEN, 0U, 1500U, &out, &out_len), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(reasm_feed(&ctx, g_msg, 2U, REASM_MSG_LEN, 1500U, 1500U, &out, &out_len), NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_NULL(out);
    UTNOX_EQUALS(reasm_feed(&ctx, g_msg, 1U, 100U, 0U, 100U, &out, &out_len), NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_NOT_NULL(out);
    UTNOX_EQUALS(out_len, 100U);
    noxtls_free(out);
    out = NULL;
    {
        dtls_handshake_fragment_t frag;
        memset(&frag, 0, sizeof(frag));
        frag.msg_type = 11U;
        frag.length = 10U;
        frag.message_seq = 3U;
        frag.fragment_offset = 0U;
        frag.fragment_length = 10U;
        frag.data = g_msg;
        /* The queued seq 2 is returned first. */
        UTNOX_EQUALS(noxtls_dtls_reassemble_handshake(&ctx, &frag, &out, &out_len), NOXTLS_RETURN_SUCCESS);
        UTNOX_IS_NOT_NULL(out);
        UTNOX_EQUALS(out_len, REASM_MSG_LEN);
        UTNOX_MEM_EQUAL(out, g_msg, REASM_MSG_LEN);
        noxtls_free(out);
        out = NULL;
    }

    UTNOX_EQUALS(noxtls_dtls_context_free(&ctx), NOXTLS_RETURN_SUCCESS);
    return 0;
}

/**
 * @brief Future messages beyond NOXTLS_DTLS_REASSEMBLY_MAX_BYTES are dropped; the in-progress
 *        message evicts queued future messages to fit.
 *
 * @return Zero on success.
 */
REGISTER_TEST(dtls_reassembly_budget)
{
    dtls_context_t ctx;
    uint8_t *out = NULL;
    uint32_t out_len = 0U;
    /* Each queued future message claims about 40% of the budget. */
    uint32_t big = ((uint32_t)NOXTLS_DTLS_REASSEMBLY_MAX_BYTES / 5U) * 2U;
    uint32_t active = 0U;

    if(big > (uint32_t)NOXTLS_TLS_MAX_HANDSHAKE_SIZE) {
        big = (uint32_t)NOXTLS_TLS_MAX_HANDSHAKE_SIZE;
    }
    reasm_fill(3U);
    UTNOX_EQUALS(noxtls_dtls_context_init(&ctx, TLS_ROLE_SERVER, DTLS_VERSION_1_2), NOXTLS_RETURN_SUCCESS);

    /* Three partial future messages: only two fit in the budget, the third is dropped. */
    for(uint16_t seq = 1U; seq <= 3U; ++seq) {
        UTNOX_EQUALS(reasm_feed(&ctx, g_msg, seq, big, 0U, 16U, &out, &out_len), NOXTLS_RETURN_SUCCESS);
        UTNOX_IS_NULL(out);
    }
    for(uint32_t i = 0U; i < DTLS_REASSEMBLY_QUEUE_SIZE; ++i) {
        active += ctx.reassembly_queue[i].active;
    }
    if(big == ((uint32_t)NOXTLS_DTLS_REASSEMBLY_MAX_BYTES / 5U) * 2U) {
        UTNOX_EQUALS(active, 2U);
    }

    /* The in-progress message (seq 0) of the same size evicts the highest queued seq. */
    UTNOX_EQUALS(reasm_feed(&ctx, g_msg, 0U, big, 0U, 16U, &out, &out_len), NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_NULL(out);
    UTNOX_IS_TRUE(((uint64_t)ctx.handshake_buffer_capacity + ctx.handshake_received_len) <=
                  (uint64_t)NOXTLS_DTLS_REASSEMBLY_MAX_BYTES);
    {
        uint64_t held = (uint64_t)ctx.handshake_buffer_capacity + ctx.handshake_received_len;
        for(uint32_t i = 0U; i < DTLS_REASSEMBLY_QUEUE_SIZE; ++i) {
            if(ctx.reassembly_queue[i].active != 0U) {
                held += ctx.reassembly_queue[i].capacity + ((ctx.reassembly_queue[i].capacity + 7U) / 8U);
            }
        }
        UTNOX_IS_TRUE(held <= (uint64_t)NOXTLS_DTLS_REASSEMBLY_MAX_BYTES);
    }

    UTNOX_EQUALS(noxtls_dtls_context_free(&ctx), NOXTLS_RETURN_SUCCESS);
    return 0;
}

#if defined(_MSC_VER)
/** @brief Register the reassembly tests on MSVC. */
void utnox_register_tests(void)
{
    register_test(__reg_dtls_reassembly_out_of_order_bitmap.name,
                  __reg_dtls_reassembly_out_of_order_bitmap.func);
    register_test(__reg_dtls_reassembly_budget.name,
                  __reg_dtls_reassembly_budget.func);
}
#endif
