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
* File:    noxtls_connection_memory.c
* Summary: Build-time sized per-connection memory for TLS 1.3 and DTLS 1.3
*****************************************************************************/
/**
 * @file noxtls_connection_memory.c
 * @brief Layout, scope and release of per-connection static memory.
 * @ingroup noxtls_tls
 */
#include "noxtls_connection_memory.h"

#if NOXTLS_CONN_MEMORY

#include "common/noxtls_ct.h"

#define NOXTLS_CONN_MAGIC 0x4E58434DUL /* "NXCM" */

NOXTLS_STATIC_ASSERT((NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_CLIENT, DTLS13_PSK) % 8U) == 0U, conn_size_aligned);
NOXTLS_STATIC_ASSERT(NOXTLS_STATIC_MAX_REGIONS >= (1U + (4U * NOXTLS_STATIC_MAX_CONNECTIONS)), conn_region_registry);
NOXTLS_STATIC_ASSERT(NOXTLS_STATIC_HS_ARENA_PSK <= 0xFFFFFFFFUL, conn_arena_offsets_fit);
NOXTLS_STATIC_ASSERT(NOXTLS_STATIC_DTLS_ACK_RANGES <= DTLS_MAX_ACK_RANGES, conn_ack_ranges);
NOXTLS_STATIC_ASSERT(NOXTLS_STATIC_DTLS_ACK_RANGES > 0U, conn_ack_ranges_nonzero);
NOXTLS_STATIC_ASSERT(NOXTLS_TLS_MAX_HANDSHAKE_SIZE >= NOXTLS_STATIC_CERT_MSG_MAX, conn_handshake_limit_covers_chain);
NOXTLS_STATIC_ASSERT(NOXTLS_STATIC_CERT_DER_MAX <= NOXTLS_MAX_CERT_SIZE, conn_cert_der_limit);
NOXTLS_STATIC_ASSERT(NOXTLS_CONN_EPOCH2_SN_KEY_MAX >= TLS13_DTLS_SN_KEY_MAX_LEN, conn_epoch2_sn_key);
NOXTLS_STATIC_ASSERT(NOXTLS_STATIC_DTLS_FLIGHT_SIZE <= 0xFFFFFFFFUL, conn_flight_fits);
/* The hello builders write into the handshake workspace; a smaller workspace makes them
 * allocate 4 KB from the handshake arena, which the budgets do not include. */
NOXTLS_STATIC_ASSERT(TLS_HANDSHAKE_WORKSPACE_SIZE >= TLS_CLIENT_HELLO_DEFAULT_SIZE, conn_workspace_client_hello);
NOXTLS_STATIC_ASSERT(TLS_HANDSHAKE_WORKSPACE_SIZE >= (TLS_SERVER_HELLO_DEFAULT_SIZE + TLS_KEY_SHARE_ENTRY_MAX_LEN),
                     conn_workspace_server_hello);

#if NOXTLS_STATIC_CONNECTION_POOL_COUNT > 0U
#if NOXTLS_STATIC_CONNECTION_POOL_CERT
#define NOXTLS_CONN_POOL_BLOCK_A NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_CLIENT, TLS13_CERT)
#define NOXTLS_CONN_POOL_BLOCK_B NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_CLIENT, DTLS13_CERT)
#else
#define NOXTLS_CONN_POOL_BLOCK_A NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_CLIENT, TLS13_PSK)
#define NOXTLS_CONN_POOL_BLOCK_B NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_CLIENT, DTLS13_PSK)
#endif
#define NOXTLS_CONN_POOL_BLOCK \
    ((NOXTLS_CONN_POOL_BLOCK_A > NOXTLS_CONN_POOL_BLOCK_B) ? NOXTLS_CONN_POOL_BLOCK_A : NOXTLS_CONN_POOL_BLOCK_B)
NOXTLS_STATIC_ASSERT(NOXTLS_STATIC_CONNECTION_POOL_COUNT <= NOXTLS_STATIC_MAX_CONNECTIONS, conn_pool_count);
/* Library-owned connection blocks: uint64_t elements give them 8-byte alignment. */
static uint64_t s_conn_pool[NOXTLS_STATIC_CONNECTION_POOL_COUNT][NOXTLS_CONN_POOL_BLOCK / 8U];
static uint8_t s_conn_pool_used[NOXTLS_STATIC_CONNECTION_POOL_COUNT];
#endif

/**
 * @brief Compute the layout of one profile.
 * @param[in] profile NOXTLS_CONN_PROFILE_*.
 * @param[out] fp Footprint.
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_INVALID_PARAM for an unknown profile.
 */
static noxtls_return_t conn_layout(uint32_t profile, noxtls_connection_footprint_t *fp)
{
    uint8_t is_dtls;
    uint8_t is_cert;

    if(profile >= NOXTLS_CONN_PROFILE_COUNT) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    is_dtls = (uint8_t)(profile & 1U);
    is_cert = (uint8_t)((profile >= NOXTLS_CONN_PROFILE_TLS13_CERT) ? 1U : 0U);
    noxtls_secure_zero(fp, sizeof(*fp));
    fp->header = NOXTLS_CONN_HEADER_BYTES;
    fp->tx_record = NOXTLS_CONN_TX_BYTES;
    if(is_dtls != 0U) {
        fp->record_workspace = NOXTLS_CONN_A(TLS13_RECORD_WORKSPACE_SIZE);
        fp->steady_fixed_other = NOXTLS_CONN_DTLS_FIXED_BYTES - fp->record_workspace;
        fp->flight = (is_cert != 0U) ? NOXTLS_CONN_A(NOXTLS_STATIC_DTLS_CERT_FLIGHT_SIZE) :
                                       NOXTLS_CONN_A(NOXTLS_STATIC_DTLS_FLIGHT_SIZE);
    } else {
        fp->steady_fixed_other = NOXTLS_CONN_TLS_FIXED_BYTES;
    }
    if(is_cert != 0U) {
        fp->steady_fixed_other += NOXTLS_CONN_PEER_CERT_BYTES;
    }
    fp->steady_arena = (is_dtls != 0U) ? NOXTLS_CONN_A(NOXTLS_STATIC_STEADY_ARENA_DTLS) :
                                         NOXTLS_CONN_A(NOXTLS_STATIC_STEADY_ARENA);
    fp->hs_state = NOXTLS_CONN_A(sizeof(tls13_hs_state_t));
    fp->handshake_workspace = NOXTLS_CONN_A(TLS_HANDSHAKE_WORKSPACE_SIZE);
    if(is_dtls != 0U) {
        fp->hs_arena = (is_cert != 0U) ? NOXTLS_CONN_A(NOXTLS_STATIC_HS_ARENA_DTLS_CERT) :
                                         NOXTLS_CONN_A(NOXTLS_STATIC_HS_ARENA_DTLS_PSK);
    } else {
        fp->hs_arena = (is_cert != 0U) ? NOXTLS_CONN_A(NOXTLS_STATIC_HS_ARENA_CERT) :
                                         NOXTLS_CONN_A(NOXTLS_STATIC_HS_ARENA_PSK);
    }
    fp->steady = fp->header + fp->tx_record + fp->record_workspace + fp->steady_fixed_other + fp->steady_arena;
    fp->handshake = fp->hs_state + fp->handshake_workspace + fp->flight + fp->hs_arena;
    fp->total = fp->steady + fp->handshake;
    fp->context = sizeof(tls13_context_t);
    return NOXTLS_RETURN_SUCCESS;
}

size_t noxtls_connection_memory_size(tls_role_t role, uint32_t profile)
{
    noxtls_connection_footprint_t fp;

    (void)role;
    if(conn_layout(profile, &fp) != NOXTLS_RETURN_SUCCESS) {
        return 0U;
    }
    return fp.total;
}

noxtls_return_t noxtls_connection_memory_footprint(tls_role_t role, uint32_t profile,
                                                   noxtls_connection_footprint_t *footprint)
{
    (void)role;
    if(footprint == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    return conn_layout(profile, footprint);
}

noxtls_connection_memory_t *noxtls_conn_mem_of(const tls_context_t *base)
{
    noxtls_connection_memory_t *conn;

    if(base == NULL) {
        return NULL;
    }
    conn = (noxtls_connection_memory_t *)base->static_mem;
    if((conn == NULL) || (conn->magic != NOXTLS_CONN_MAGIC)) {
        return NULL;
    }
    return conn;
}

/**
 * @brief Carve @p memory for @p profile and register its regions.
 * @return The header, or NULL with @p rc set.
 */
static noxtls_connection_memory_t *conn_carve(uint32_t profile, void *memory, size_t memory_len,
                                              noxtls_return_t *rc)
{
    noxtls_connection_footprint_t fp;
    noxtls_connection_memory_t *conn = (noxtls_connection_memory_t *)memory;
    uint8_t *base = (uint8_t *)memory;
    size_t steady_fixed;
    size_t hs_fixed;

    *rc = conn_layout(profile, &fp);
    if(*rc != NOXTLS_RETURN_SUCCESS) {
        return NULL;
    }
    if(memory == NULL) {
        *rc = NOXTLS_RETURN_NULL;
        return NULL;
    }
    if((((uintptr_t)memory % NOXTLS_MEM_REGION_ALIGN) != 0U) || (memory_len < fp.total)) {
        *rc = NOXTLS_RETURN_INVALID_PARAM;
        return NULL;
    }
    noxtls_secure_zero(memory, fp.total);
    steady_fixed = fp.tx_record + fp.record_workspace + fp.steady_fixed_other;
    hs_fixed = fp.hs_state + fp.handshake_workspace + fp.flight;
    conn->magic = NOXTLS_CONN_MAGIC;
    conn->profile = (uint8_t)profile;
    conn->block_size = memory_len;
    conn->steady_bytes = fp.steady;
    conn->handshake_bytes = fp.handshake;
    conn->handshake_base = &base[fp.steady];
    *rc = noxtls_mem_region_init(&conn->steady_fixed, &base[fp.header], steady_fixed,
                                 NOXTLS_MEM_REGION_FIXED, "connection steady slots");
    if(*rc == NOXTLS_RETURN_SUCCESS) {
        *rc = noxtls_mem_region_init(&conn->steady_arena, &base[fp.header + steady_fixed], fp.steady_arena,
                                     NOXTLS_MEM_REGION_ARENA, "connection steady arena");
    }
    if(*rc == NOXTLS_RETURN_SUCCESS) {
        *rc = noxtls_mem_region_init(&conn->hs_fixed, conn->handshake_base, hs_fixed,
                                     NOXTLS_MEM_REGION_FIXED, "connection handshake slots");
    }
    if(*rc == NOXTLS_RETURN_SUCCESS) {
        *rc = noxtls_mem_region_init(&conn->hs_arena, &conn->handshake_base[hs_fixed], fp.hs_arena,
                                     NOXTLS_MEM_REGION_ARENA, "connection handshake arena");
    }
    if(*rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_mem_region_deinit(&conn->steady_fixed);
        noxtls_mem_region_deinit(&conn->steady_arena);
        noxtls_mem_region_deinit(&conn->hs_fixed);
        noxtls_mem_region_deinit(&conn->hs_arena);
        noxtls_secure_zero(conn, sizeof(*conn));
        return NULL;
    }
    conn->scope.current = &conn->hs_arena;
    return conn;
}

/**
 * @brief Point the context's buffers at the carved slots.
 *
 * Called by tls13_context_init_internal() right after the record-layer base is
 * initialized, before anything is allocated.
 */
static void conn_attach(tls13_context_t *ctx, noxtls_connection_memory_t *conn, uint8_t is_dtls)
{
    noxtls_connection_footprint_t fp;
    uint8_t *steady = conn->steady_fixed.base;
    uint8_t *hs = conn->hs_fixed.base;

    (void)conn_layout(conn->profile, &fp);
    ctx->base.base.static_mem = conn;
    ctx->base.base.record_send_buf = steady;
    steady = &steady[fp.tx_record];
    ctx->hs = (tls13_hs_state_t *)(void *)hs;
    hs = &hs[fp.hs_state];
    ctx->handshake_workspace = hs;
    ctx->handshake_workspace_owned = 0U;
    hs = &hs[fp.handshake_workspace];
#if NOXTLS_FEATURE_DTLS
    if(is_dtls != 0U) {
        ctx->record_workspace = steady;
        ctx->record_workspace_owned = 0U;
        steady = &steady[fp.record_workspace];
        ctx->base.ack_ranges_min = (uint64_t *)(void *)steady;
        ctx->base.ack_ranges_max = &ctx->base.ack_ranges_min[NOXTLS_STATIC_DTLS_ACK_RANGES];
        ctx->base.ack_range_capacity = (uint8_t)NOXTLS_STATIC_DTLS_ACK_RANGES;
        ctx->base.ack_range_limit = (uint8_t)NOXTLS_STATIC_DTLS_ACK_RANGES;
        steady = &steady[NOXTLS_CONN_A(2U * sizeof(uint64_t) * NOXTLS_STATIC_DTLS_ACK_RANGES)];
        conn->last_ack_min = (uint64_t *)(void *)steady;
        conn->last_ack_max = &conn->last_ack_min[DTLS_MAX_ACK_RANGES];
        steady = &steady[NOXTLS_CONN_A(2U * sizeof(uint64_t) * DTLS_MAX_ACK_RANGES)];
        conn->rx_stash = steady;
        conn->rx_stash_size = (uint32_t)(DTLS_RECORD_HEADER_SIZE + TLS_MAX_RECORD_SIZE);
        steady = &steady[NOXTLS_CONN_A(DTLS_RECORD_HEADER_SIZE + TLS_MAX_RECORD_SIZE)];
        conn->post_hs_flight = steady;
        conn->post_hs_flight_size = (uint32_t)NOXTLS_STATIC_DTLS_POST_HS_FLIGHT_SIZE;
        steady = &steady[NOXTLS_CONN_A(NOXTLS_STATIC_DTLS_POST_HS_FLIGHT_SIZE)];
        ctx->base.flight_buffer_storage = hs;
        ctx->base.flight_buffer_storage_capacity = (uint32_t)fp.flight;
        ctx->base.flight_buffer = hs;
        ctx->base.flight_buffer_capacity = (uint32_t)fp.flight;
    } else
#endif
    {
        (void)is_dtls;
        conn->tx_queue = steady;
        conn->tx_queue_size = (uint32_t)NOXTLS_STATIC_TLS_TX_QUEUE_SIZE;
        ctx->base.base.io_tx_queue_limit = (uint32_t)NOXTLS_STATIC_TLS_TX_QUEUE_SIZE;
        steady = &steady[NOXTLS_CONN_TLS_FIXED_BYTES];
    }
    if((conn->profile >= NOXTLS_CONN_PROFILE_TLS13_CERT) && (NOXTLS_CONN_PEER_CERT_BYTES != 0U)) {
        conn->peer_cert = steady;
    }
}

noxtls_return_t noxtls_conn_mem_bind(tls13_context_t *ctx, uint32_t profile, void *memory, size_t memory_len,
                                     uint8_t pool_index)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    noxtls_connection_memory_t *conn = conn_carve(profile, memory, memory_len, &rc);

    if(conn == NULL) {
        return rc;
    }
    conn->pool_index = pool_index;
    conn_attach(ctx, conn, (uint8_t)(profile & 1U));
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_conn_mem_pool_bind(tls13_context_t *ctx, tls_role_t role, uint8_t is_dtls)
{
#if NOXTLS_STATIC_CONNECTION_POOL_COUNT > 0U
    uint32_t i;
#if NOXTLS_STATIC_CONNECTION_POOL_CERT
    uint32_t profile = (is_dtls != 0U) ? NOXTLS_CONN_PROFILE_DTLS13_CERT : NOXTLS_CONN_PROFILE_TLS13_CERT;
#else
    uint32_t profile = (is_dtls != 0U) ? NOXTLS_CONN_PROFILE_DTLS13_PSK : NOXTLS_CONN_PROFILE_TLS13_PSK;
#endif

    (void)role;
    for(i = 0U; i < (uint32_t)NOXTLS_STATIC_CONNECTION_POOL_COUNT; ++i) {
        if(s_conn_pool_used[i] == 0U) {
            noxtls_return_t rc = noxtls_conn_mem_bind(ctx, profile, s_conn_pool[i], sizeof(s_conn_pool[i]),
                                                      (uint8_t)(i + 1U));
            if(rc == NOXTLS_RETURN_SUCCESS) {
                s_conn_pool_used[i] = 1U;
            }
            return rc;
        }
    }
    return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
#else
    (void)ctx;
    (void)role;
    (void)is_dtls;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

noxtls_mem_scope_t *noxtls_conn_mem_enter(const tls_context_t *base)
{
    noxtls_connection_memory_t *conn = noxtls_conn_mem_of(base);
    noxtls_mem_scope_t *previous;

    if(conn == NULL) {
        /* No connection memory (or a freed one): keep the caller's scope. */
        previous = noxtls_mem_scope_enter(NULL);
        noxtls_mem_scope_exit(previous);
        return previous;
    }
    conn->depth += 1U;
    return noxtls_mem_scope_enter(&conn->scope);
}

/**
 * @brief Copy one buffer that lives in the handshake part into the steady arena.
 * @param[in,out] ptr Buffer pointer; replaced by the copy or set to NULL.
 * @param[in] len Bytes to keep.
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_NOT_ENOUGH_MEMORY (buffer dropped).
 */
static noxtls_return_t conn_migrate(noxtls_connection_memory_t *conn, uint8_t **ptr, uint32_t len)
{
    uint8_t *copy;

    if((*ptr == NULL) || ((noxtls_mem_region_contains(&conn->hs_arena, *ptr) == 0) &&
                          (noxtls_mem_region_contains(&conn->hs_fixed, *ptr) == 0))) {
        return NOXTLS_RETURN_SUCCESS;
    }
    if(len == 0U) {
        *ptr = NULL;
        return NOXTLS_RETURN_SUCCESS;
    }
    copy = (uint8_t *)NOXTLS_MALLOC(len);
    if(copy == NULL) {
        *ptr = NULL;
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    noxtls_copy_u8(copy, (size_t)len, *ptr, (size_t)len);
    *ptr = copy;
    return NOXTLS_RETURN_SUCCESS;
}

/** @brief 1 when @p ptr points into the handshake part of @p conn. */
static int conn_in_handshake_part(const noxtls_connection_memory_t *conn, const void *ptr)
{
    uintptr_t at = (uintptr_t)ptr;
    uintptr_t start = (uintptr_t)conn->handshake_base;

    return ((ptr != NULL) && (at >= start) && ((at - start) < conn->handshake_bytes)) ? 1 : 0;
}

/** @brief Drop a pointer into the handshake part (the storage is about to be wiped). */
static void conn_drop(const noxtls_connection_memory_t *conn, uint8_t **ptr)
{
    if(conn_in_handshake_part(conn, *ptr) != 0) {
        *ptr = NULL;
    }
}

/**
 * @brief Count pointer-sized words of the context that point into the handshake part.
 *
 * A safety net run at every release: every field that could refer to handshake
 * storage is migrated or cleared first, so the count is zero. Tests assert it.
 */
static size_t conn_scan_dangling(const noxtls_connection_memory_t *conn, const tls13_context_t *ctx)
{
    const uint8_t *bytes = (const uint8_t *)(const void *)ctx;
    size_t count = 0U;
    size_t off;

    for(off = 0U; (off + sizeof(uintptr_t)) <= sizeof(*ctx); off += sizeof(void *)) {
        uintptr_t value;
        noxtls_copy_u8((uint8_t *)(void *)&value, sizeof(value), &bytes[off], sizeof(value));
        if(conn_in_handshake_part(conn, (const void *)value) != 0) {
            count += 1U;
        }
    }
    return count;
}

/** @brief DTLS 1.3 server: keep the client epoch-2 read secret for Finished retransmissions. */
static void conn_keep_epoch2(noxtls_connection_memory_t *conn, tls13_context_t *ctx)
{
#if NOXTLS_FEATURE_DTLS
    uint8_t secret_len = (uint8_t)((ctx->cipher_suite == TLS_CIPHER_SUITE_AES_256_GCM_SHA384) ? 48U : 32U);

    if((ctx->base.base.version != DTLS_VERSION_1_3) || (ctx->base.base.role != TLS_ROLE_SERVER) ||
       (ctx->hs == NULL)) {
        return;
    }
    noxtls_copy_u8(conn->epoch2_secret, sizeof(conn->epoch2_secret), ctx->hs->client_handshake_traffic_secret,
                   (size_t)secret_len);
    noxtls_copy_u8(conn->epoch2_sn_key, sizeof(conn->epoch2_sn_key), ctx->hs->client_handshake_sn_key,
                   (size_t)TLS13_DTLS_SN_KEY_MAX_LEN);
    conn->epoch2_secret_len = secret_len;
    conn->epoch2_valid = 1U;
    conn->epoch2_expiry_ms = 0U;
    if((NOXTLS_STATIC_DTLS13_EPOCH2_RETAIN_MS != 0U) && (ctx->base.base.time_callback != NULL)) {
        conn->epoch2_expiry_ms = ctx->base.base.time_callback(ctx->base.base.user_data) +
                                 (uint64_t)NOXTLS_STATIC_DTLS13_EPOCH2_RETAIN_MS;
    }
#else
    (void)conn;
    (void)ctx;
#endif
}

static void conn_wipe_epoch2(noxtls_connection_memory_t *conn)
{
    noxtls_secure_zero(conn->epoch2_secret, sizeof(conn->epoch2_secret));
    noxtls_secure_zero(conn->epoch2_sn_key, sizeof(conn->epoch2_sn_key));
    conn->epoch2_secret_len = 0U;
    conn->epoch2_valid = 0U;
    conn->epoch2_expiry_ms = 0U;
}

/**
 * @brief Release the handshake part: keep what the steady state needs, wipe the rest.
 *
 * Runs at the end of the outermost library call, so no stack frame holds a
 * pointer into the handshake part.
 */
static void conn_release(noxtls_connection_memory_t *conn, tls13_context_t *ctx)
{
    noxtls_mem_region_stats_t arena;

    (void)noxtls_mem_region_get_stats(&conn->hs_arena, &arena);
    conn->hs_arena_peak = arena.peak;
    conn_keep_epoch2(conn, ctx);
    /* From here on allocations go to the steady arena. */
    conn->scope.current = &conn->steady_arena;

    /* Data that is still owed to the application or to the next parse. */
    if((ctx->handshake_buffer != NULL) && (ctx->handshake_buffer_len > ctx->handshake_buffer_pos) &&
       (conn_in_handshake_part(conn, ctx->handshake_buffer) != 0)) {
        uint8_t *rest = &ctx->handshake_buffer[ctx->handshake_buffer_pos];
        uint32_t rest_len = ctx->handshake_buffer_len - ctx->handshake_buffer_pos;
        ctx->handshake_buffer = rest;
        if(conn_migrate(conn, &ctx->handshake_buffer, rest_len) == NOXTLS_RETURN_SUCCESS) {
            ctx->handshake_buffer_len = rest_len;
        } else {
            ctx->handshake_buffer_len = 0U;
        }
        ctx->handshake_buffer_pos = 0U;
    } else if(conn_in_handshake_part(conn, ctx->handshake_buffer) != 0) {
        ctx->handshake_buffer = NULL;
        ctx->handshake_buffer_len = 0U;
        ctx->handshake_buffer_pos = 0U;
    } else {
        /* Already in the steady part, or none. */
    }
    if((ctx->pending_app_data != NULL) && (conn_in_handshake_part(conn, ctx->pending_app_data) != 0)) {
        uint8_t *rest = &ctx->pending_app_data[ctx->pending_app_data_off];
        ctx->pending_app_data = rest;
        if(conn_migrate(conn, &ctx->pending_app_data, ctx->pending_app_data_len) != NOXTLS_RETURN_SUCCESS) {
            ctx->pending_app_data_len = 0U;
        }
        ctx->pending_app_data_off = 0U;
    }
    if(conn_in_handshake_part(conn, ctx->base.base.io_rx_payload) != 0) {
        if(conn_migrate(conn, &ctx->base.base.io_rx_payload, ctx->base.base.io_rx_payload_len) !=
           NOXTLS_RETURN_SUCCESS) {
            ctx->base.base.io_rx_payload_len = 0U;
            ctx->base.base.io_rx_payload_offset = 0U;
            ctx->base.base.io_rx_header_len = 0U;
        }
    }

    /* Handshake-only references. */
    conn_drop(conn, &ctx->base.base.pending_client_hello);
    if(ctx->base.base.pending_client_hello == NULL) {
        ctx->base.base.pending_client_hello_len = 0U;
    }
    conn_drop(conn, &ctx->base.base.pending_server_hello);
    if(ctx->base.base.pending_server_hello == NULL) {
        ctx->base.base.pending_server_hello_len = 0U;
    }
    if((ctx->base.base.role == TLS_ROLE_CLIENT) && (conn->peer_cert != NULL) &&
       (conn_in_handshake_part(conn, ctx->server_cert) != 0) && (ctx->server_cert_len <= NOXTLS_STATIC_CERT_DER_MAX)) {
        /* Keep the server's leaf certificate, as heap builds do. */
        noxtls_copy_u8(conn->peer_cert, (size_t)NOXTLS_STATIC_CERT_DER_MAX, ctx->server_cert, (size_t)ctx->server_cert_len);
        ctx->server_cert = conn->peer_cert;
    }
    if((ctx->base.base.role == TLS_ROLE_SERVER) && (conn->peer_cert != NULL) &&
       (conn_in_handshake_part(conn, ctx->client_cert) != 0) && (ctx->client_cert_len <= NOXTLS_STATIC_CERT_DER_MAX)) {
        /* Keep the client's certificate (mutual authentication). */
        noxtls_copy_u8(conn->peer_cert, (size_t)NOXTLS_STATIC_CERT_DER_MAX, ctx->client_cert, (size_t)ctx->client_cert_len);
        ctx->client_cert = conn->peer_cert;
    }
    if(conn_in_handshake_part(conn, ctx->server_cert) != 0) {
        ctx->server_cert = NULL;
        ctx->server_cert_len = 0U;
    }
    if(conn_in_handshake_part(conn, ctx->server_cert_parsed) != 0) {
        ctx->server_cert_parsed = NULL;
    }
    if(conn_in_handshake_part(conn, ctx->client_cert) != 0) {
        ctx->client_cert = NULL;
        ctx->client_cert_len = 0U;
    }
    if(conn_in_handshake_part(conn, ctx->client_cert_parsed) != 0) {
        ctx->client_cert_parsed = NULL;
    }
    ctx->hs = NULL;
    ctx->handshake_workspace = NULL;
    ctx->handshake_workspace_owned = 0U;
#if NOXTLS_FEATURE_DTLS
    if(ctx->base.base.version == DTLS_VERSION_1_3) {
        uint32_t i;
        if(conn_in_handshake_part(conn, ctx->base.flight_buffer) != 0) {
            ctx->base.flight_buffer = NULL;
            ctx->base.flight_buffer_len = 0U;
            ctx->base.flight_buffer_capacity = 0U;
        }
        /* Post-handshake flights (KeyUpdate, connection IDs) use a steady slot. */
        ctx->base.flight_buffer_storage = conn->post_hs_flight;
        ctx->base.flight_buffer_storage_capacity = conn->post_hs_flight_size;
        if(ctx->base.flight_buffer == NULL) {
            ctx->base.flight_buffer = conn->post_hs_flight;
            ctx->base.flight_buffer_capacity = conn->post_hs_flight_size;
            ctx->base.flight_buffer_len = 0U;
        }
        conn_drop(conn, &ctx->base.hrr_cookie);
        if(ctx->base.hrr_cookie == NULL) {
            ctx->base.hrr_cookie_len = 0U;
        }
        if(conn_in_handshake_part(conn, ctx->base.handshake_buffer) != 0) {
            ctx->base.handshake_buffer = NULL;
            ctx->base.handshake_buffer_len = 0U;
            ctx->base.handshake_buffer_capacity = 0U;
            ctx->base.expected_fragment_offset = 0U;
        }
        if(conn_in_handshake_part(conn, ctx->base.handshake_received) != 0) {
            ctx->base.handshake_received = NULL;
            ctx->base.handshake_received_len = 0U;
            ctx->base.handshake_received_count = 0U;
        }
        for(i = 0U; i < (uint32_t)DTLS_REASSEMBLY_QUEUE_SIZE; ++i) {
            dtls_reassembly_slot_t *slot = &ctx->base.reassembly_queue[i];
            if((conn_in_handshake_part(conn, slot->buffer) != 0) || (conn_in_handshake_part(conn, slot->received) != 0)) {
                /* An unfinished future message: the peer retransmits it. */
                noxtls_secure_zero(slot, sizeof(*slot));
            }
        }
        conn_drop(conn, &ctx->base.rx_datagram);
        if(ctx->base.rx_datagram == NULL) {
            ctx->base.rx_datagram_len = 0U;
        }
    }
#endif
    conn->dangling = conn_scan_dangling(conn, ctx);
    noxtls_mem_region_release(&conn->hs_fixed);
    noxtls_mem_region_release(&conn->hs_arena);
    conn->release_pending = 0U;
    conn->released = 1U;
}

/** @brief 1 when the handshake part may be released now. */
static int conn_release_due(const noxtls_connection_memory_t *conn, const tls13_context_t *ctx)
{
    if((conn->release_pending == 0U) || (conn->released != 0U)) {
        return 0;
    }
    if(ctx->base.base.state != TLS_STATE_CONNECTED) {
        return 0;
    }
#if NOXTLS_FEATURE_DTLS
    if((ctx->base.base.version == DTLS_VERSION_1_3) && (ctx->base.base.role == TLS_ROLE_CLIENT) &&
       (ctx->base.flight_buffer_len != 0U) && (ctx->base.retransmit_exhausted == 0U)) {
        /* RFC 9147 Section 5.8: the final flight may still be retransmitted. */
        return 0;
    }
#endif
    return 1;
}

void noxtls_conn_mem_leave(tls13_context_t *ctx, noxtls_mem_scope_t *previous)
{
    noxtls_connection_memory_t *conn = (ctx != NULL) ? noxtls_conn_mem_of(&ctx->base.base) : NULL;

    if(conn != NULL) {
        if(conn->depth > 0U) {
            conn->depth -= 1U;
        }
        if(conn->depth == 0U) {
            if(conn_release_due(conn, ctx) != 0) {
                conn_release(conn, ctx);
            }
            if((conn->epoch2_valid != 0U) && (conn->epoch2_expiry_ms != 0U) &&
               (ctx->base.base.time_callback != NULL) &&
               (ctx->base.base.time_callback(ctx->base.base.user_data) > conn->epoch2_expiry_ms)) {
                conn_wipe_epoch2(conn);
            }
        }
    }
    noxtls_mem_scope_exit(previous);
}

void noxtls_conn_mem_handshake_done(tls13_context_t *ctx)
{
    noxtls_connection_memory_t *conn = (ctx != NULL) ? noxtls_conn_mem_of(&ctx->base.base) : NULL;

    if(conn != NULL) {
        conn->release_pending = 1U;
    }
}

const uint8_t *noxtls_conn_mem_epoch2_secret(const tls13_context_t *ctx, const uint8_t **sn_key)
{
    noxtls_connection_memory_t *conn = (ctx != NULL) ? noxtls_conn_mem_of(&ctx->base.base) : NULL;

    if((conn == NULL) || (conn->epoch2_valid == 0U)) {
        return NULL;
    }
    if(sn_key != NULL) {
        *sn_key = conn->epoch2_sn_key;
    }
    return conn->epoch2_secret;
}

void noxtls_conn_mem_free(tls13_context_t *ctx, noxtls_connection_memory_t *conn)
{
    uint8_t pool_index;

    (void)ctx;
    if(conn == NULL) {
        return;
    }
    pool_index = conn->pool_index;
    noxtls_mem_region_deinit(&conn->steady_fixed);
    noxtls_mem_region_deinit(&conn->steady_arena);
    noxtls_mem_region_deinit(&conn->hs_fixed);
    noxtls_mem_region_deinit(&conn->hs_arena);
    conn_wipe_epoch2(conn);
    noxtls_secure_zero(conn, sizeof(*conn));
#if NOXTLS_STATIC_CONNECTION_POOL_COUNT > 0U
    if((pool_index != 0U) && (pool_index <= (uint8_t)NOXTLS_STATIC_CONNECTION_POOL_COUNT)) {
        s_conn_pool_used[pool_index - 1U] = 0U;
    }
#else
    (void)pool_index;
#endif
}

noxtls_return_t noxtls_connection_memory_get_stats(const tls13_context_t *ctx,
                                                   noxtls_connection_memory_stats_t *stats)
{
    const noxtls_connection_memory_t *conn;

    if((ctx == NULL) || (stats == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    conn = noxtls_conn_mem_of(&ctx->base.base);
    if(conn == NULL) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
    noxtls_secure_zero(stats, sizeof(*stats));
    (void)conn_layout(conn->profile, &stats->layout);
    stats->released = conn->released;
    (void)noxtls_mem_region_get_stats(&conn->hs_arena, &stats->hs_arena);
    (void)noxtls_mem_region_get_stats(&conn->steady_arena, &stats->steady_arena);
    stats->hs_arena_peak_at_release = conn->hs_arena_peak;
    stats->dangling_pointers = conn->dangling;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_connection_memory_handshake_region(tls13_context_t *ctx, uint8_t **region, size_t *len)
{
    noxtls_connection_memory_t *conn;

    if((ctx == NULL) || (region == NULL) || (len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    conn = noxtls_conn_mem_of(&ctx->base.base);
    if(conn == NULL) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
    if(conn->released == 0U) {
        *region = NULL;
        *len = 0U;
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
    *region = conn->handshake_base;
    *len = conn->handshake_bytes;
    return NOXTLS_RETURN_SUCCESS;
}

/* ---- DTLS / TLS record-layer slots ---------------------------------------- */

uint8_t *noxtls_conn_mem_tx_queue(const tls_context_t *base, uint32_t *capacity)
{
    noxtls_connection_memory_t *conn = noxtls_conn_mem_of(base);

    if((conn == NULL) || (conn->tx_queue == NULL)) {
        return NULL;
    }
    *capacity = conn->tx_queue_size;
    return conn->tx_queue;
}

uint8_t *noxtls_conn_mem_rx_stash(const tls_context_t *base, uint32_t *capacity)
{
    noxtls_connection_memory_t *conn = noxtls_conn_mem_of(base);

    if((conn == NULL) || (conn->rx_stash == NULL)) {
        return NULL;
    }
    *capacity = conn->rx_stash_size;
    return conn->rx_stash;
}

uint64_t *noxtls_conn_mem_last_ack_ranges(const tls_context_t *base, uint64_t **max_ranges)
{
    noxtls_connection_memory_t *conn = noxtls_conn_mem_of(base);

    if((conn == NULL) || (conn->last_ack_min == NULL)) {
        return NULL;
    }
    *max_ranges = conn->last_ack_max;
    return conn->last_ack_min;
}

#endif /* NOXTLS_CONN_MEMORY */
