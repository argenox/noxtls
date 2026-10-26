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
* File:    multi_context_test.c
* Summary: Several TLS 1.3 / DTLS 1.3 PSK connections in one process
*****************************************************************************/
/** @file multi_context_test.c
 * @brief Concurrent server and client contexts (docs/static-memory.md, "Several
 *        connections").
 *
 * One process holds several associations at once, as a leader does (NoxLink server
 * associations next to its node-facing client associations and its MQTT stream) and
 * as a host helper does (many PSK client associations). Each association is a client
 * and a server context joined by its own in-memory link; every association has its own
 * PSK identity and key. The same cases run in the heap and the static memory
 * configurations; static builds also check every connection's own memory (release
 * per context, arenas, regions) and, with GNU ld, that the C library allocator is
 * never called.
 *
 * Handshakes are driven by a round-robin owner loop: each turn calls one endpoint's
 * connect/accept once, as an event-driven owner task does when a datagram arrives or
 * a deadline expires. Nothing waits.
 */
#include "lb_fixture.h"
#include "leader_pki.h"
#include "tls/noxtls_connection_memory.h"

#include <string.h>

/* ---- C library allocator hooks (static builds, GNU ld) -------------------- */

#if defined(MC_WRAP_HEAP)
void *__real_malloc(size_t size);
void *__real_calloc(size_t nmemb, size_t size);
void *__real_realloc(void *ptr, size_t size);
void __real_free(void *ptr);

static size_t s_heap_calls;

void *__wrap_malloc(size_t size)
{
    s_heap_calls++;
    return __real_malloc(size);
}

void *__wrap_calloc(size_t nmemb, size_t size)
{
    s_heap_calls++;
    return __real_calloc(nmemb, size);
}

void *__wrap_realloc(void *ptr, size_t size)
{
    s_heap_calls++;
    return __real_realloc(ptr, size);
}

void __wrap_free(void *ptr)
{
    if(ptr != NULL) {
        s_heap_calls++;
    }
    __real_free(ptr);
}
#define MC_HEAP_CALLS() s_heap_calls
#else
#define MC_HEAP_CALLS() ((size_t)0U)
#endif

/* ---- In-memory links ------------------------------------------------------ */

#define MC_ASSOC_MAX   8U
#define MC_SLOTS       32U
#define MC_DGRAM_MAX   2048U
#define MC_STREAM_CAP  65536U
/** NoxLink records: record_size_limit 1,400 (BACKEND_LEADER_CHANNEL.md C2). */
#define MC_RSL         1400U
#define MC_MTU         1500U
/* Associations that can be live at once: both ends of an association are contexts of
 * this process, so a static build holds NOXTLS_STATIC_MAX_CONNECTIONS / 2 of them
 * (4 with the leader profile's 8 connections, which counts only the leader's side). */
#if NOXTLS_CONFIG_STATIC_MEMORY
#define MC_FIT ((((uint32_t)NOXTLS_STATIC_MAX_CONNECTIONS / 2U) < MC_ASSOC_MAX) ? \
                ((uint32_t)NOXTLS_STATIC_MAX_CONNECTIONS / 2U) : MC_ASSOC_MAX)
#else
#define MC_FIT MC_ASSOC_MAX
#endif

typedef struct
{
    uint8_t data[MC_SLOTS][MC_DGRAM_MAX];
    uint32_t len[MC_SLOTS];
    uint32_t head;
    uint32_t count;
    uint32_t drop_next;   /* datagrams to drop when sent */
    uint32_t dup_next;    /* datagrams to queue twice */
    uint32_t datagrams;   /* datagrams handed to the link (dropped ones included) */
    uint8_t stream[MC_STREAM_CAP];
    uint32_t rd;
    uint32_t wr;
} mc_queue_t;

typedef struct mc_link_s mc_link_t;

typedef struct
{
    mc_link_t *link;
    int is_client;
} mc_port_t;

typedef void (*mc_hook_t)(void *arg);

struct mc_link_s
{
    mc_queue_t to_server;
    mc_queue_t to_client;
    mc_port_t cport;
    mc_port_t sport;
    int datagram;
    mc_hook_t server_send_hook;   /* called once from the server's send callback */
    void *hook_arg;
};

static uint64_t s_now_ms = 1000U;

static uint64_t mc_now(void *user)
{
    (void)user;
    return s_now_ms;
}

static int32_t mc_send(void *user, const uint8_t *data, uint32_t len)
{
    mc_port_t *port = (mc_port_t *)user;
    mc_link_t *link = port->link;
    mc_queue_t *q = (port->is_client != 0) ? &link->to_server : &link->to_client;
    uint32_t copies = 1U;
    uint32_t i;

    if((port->is_client == 0) && (link->server_send_hook != NULL)) {
        mc_hook_t hook = link->server_send_hook;
        link->server_send_hook = NULL;
        hook(link->hook_arg);
    }
    if(link->datagram == 0) {
        if((MC_STREAM_CAP - q->wr) < len) {
            /* Move the unread bytes to the front (long-running connections). */
            uint32_t unread = q->wr - q->rd;
            memmove(q->stream, &q->stream[q->rd], unread);
            q->rd = 0U;
            q->wr = unread;
            if((MC_STREAM_CAP - q->wr) < len) {
                return TLS_IO_WOULD_BLOCK;
            }
        }
        memcpy(&q->stream[q->wr], data, len);
        q->wr += len;
        return (int32_t)len;
    }
    q->datagrams++;
    if(len > MC_DGRAM_MAX) {
        return -1;
    }
    if(q->drop_next > 0U) {
        q->drop_next--;
        return (int32_t)len;
    }
    if(q->dup_next > 0U) {
        q->dup_next--;
        copies = 2U;
    }
    for(i = 0U; i < copies; i++) {
        uint32_t slot;
        if(q->count >= MC_SLOTS) {
            return -1;
        }
        slot = (q->head + q->count) % MC_SLOTS;
        memcpy(q->data[slot], data, len);
        q->len[slot] = len;
        q->count++;
    }
    return (int32_t)len;
}

static int32_t mc_recv(void *user, uint8_t *data, uint32_t len)
{
    mc_port_t *port = (mc_port_t *)user;
    mc_link_t *link = port->link;
    mc_queue_t *q = (port->is_client != 0) ? &link->to_client : &link->to_server;
    uint32_t n;

    if(link->datagram == 0) {
        n = q->wr - q->rd;
        if(n == 0U) {
            return TLS_IO_WOULD_BLOCK;
        }
        if(n > len) {
            n = len;
        }
        memcpy(data, &q->stream[q->rd], n);
        q->rd += n;
        return (int32_t)n;
    }
    if(q->count == 0U) {
        return 0;
    }
    n = q->len[q->head];
    if(n > len) {
        return -1;
    }
    memcpy(data, q->data[q->head], n);
    q->head = (q->head + 1U) % MC_SLOTS;
    q->count--;
    return (int32_t)n;
}

/* ---- Associations ---------------------------------------------------------- */

typedef struct
{
    tls13_context_t ctx;
    int is_client;
    int dtls;
    int initialized;
    int done;
    noxtls_return_t last_rc;
} mc_end_t;

typedef struct
{
    mc_link_t link;
    mc_end_t c;
    mc_end_t s;
    uint8_t identity[16];
    uint16_t identity_len;
    uint8_t key[32];
} mc_assoc_t;

static mc_assoc_t s_assoc[MC_ASSOC_MAX];
static uint8_t s_buf[8192];
static uint8_t s_rx[8192];

#if NOXTLS_CONN_MEMORY
#define MC_MAX2(a, b) (((a) > (b)) ? (a) : (b))
#define MC_BLOCK_BYTES \
    MC_MAX2(NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_CLIENT, DTLS13_PSK), \
            NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_CLIENT, TLS13_PSK))
#define MC_STEADY_BYTES NOXTLS_CONNECTION_MEMORY_STEADY_SIZE(TLS_ROLE_SERVER, DTLS13_PSK)
#define MC_HS_BYTES NOXTLS_CONNECTION_MEMORY_HANDSHAKE_SIZE(TLS_ROLE_SERVER, DTLS13_PSK)
/* One block per context: [association][0 client, 1 server]. */
static uint64_t s_blocks[MC_ASSOC_MAX][2][MC_BLOCK_BYTES / 8U];
/* Split blocks: steady parts of three server contexts and one shared handshake block. */
static uint64_t s_steady[3][MC_STEADY_BYTES / 8U];
static uint64_t s_shared_hs[MC_HS_BYTES / 8U];
#endif

/** Build the identity and key of association @p i (distinct for every association). */
static void mc_assoc_keys(mc_assoc_t *a, uint32_t i)
{
    static const char *const names[MC_ASSOC_MAX] = {
        "nlk1-fleet", "nlk1-local", "nmx1-dist-0", "nmx1-dist-1",
        "nmx1-dist-2", "nmx1-dist-3", "helper-6", "helper-7"
    };
    a->identity_len = (uint16_t)strlen(names[i]);
    memcpy(a->identity, names[i], a->identity_len);
    lb_fill_pattern(a->key, sizeof(a->key), 0xA000U + i);
}

/** Initialize one endpoint, in its own block (static) or on the heap. */
static int mc_end_init(mc_end_t *e, int is_client, int dtls, void *mem, size_t mem_len)
{
    tls_role_t role = (is_client != 0) ? TLS_ROLE_CLIENT : TLS_ROLE_SERVER;
    noxtls_return_t rc;

#if NOXTLS_CONN_MEMORY
    if(mem != NULL) {
        rc = (dtls != 0) ?
            noxtls_dtls13_context_init_static(&e->ctx, role, NOXTLS_CONN_PROFILE_DTLS13_PSK, mem, mem_len) :
            noxtls_tls13_context_init_static(&e->ctx, role, NOXTLS_CONN_PROFILE_TLS13_PSK, mem, mem_len);
    } else
#else
    (void)mem;
    (void)mem_len;
#endif
    {
        rc = (dtls != 0) ? noxtls_dtls13_context_init(&e->ctx, role) : noxtls_tls13_context_init(&e->ctx, role);
    }
    LB_CHECK_OK(rc);
    e->is_client = is_client;
    e->dtls = dtls;
    e->initialized = 1;
    e->done = 0;
    e->last_rc = NOXTLS_RETURN_WANT_READ;
    return 0;
}

/** Configure an initialized endpoint: I/O, time, MTU, record size limit and its PSK. */
static int mc_end_config(mc_assoc_t *a, mc_end_t *e)
{
    static const uint16_t group = TLS_NAMED_GROUP_X25519;
    static const uint16_t suite = TLS_CIPHER_SUITE_AES_128_GCM_SHA256;
    mc_port_t *port = (e->is_client != 0) ? &a->link.cport : &a->link.sport;

    LB_CHECK_OK(noxtls_tls_set_io_callbacks(&e->ctx.base.base, mc_send, mc_recv, port));
    if(e->dtls != 0) {
        LB_CHECK_OK(noxtls_tls_set_time_callback(&e->ctx.base.base, mc_now));
        LB_CHECK_OK(noxtls_dtls_set_mtu(&e->ctx.base, (uint16_t)MC_MTU));
        noxtls_tls13_set_record_size_limit(&e->ctx, (uint16_t)MC_RSL);
    } else {
        LB_CHECK_OK(noxtls_tls_set_io_mode(&e->ctx.base.base, TLS_IO_MODE_NON_BLOCKING));
    }
    LB_CHECK_OK(tls13_set_external_psk(&e->ctx, a->identity, a->identity_len, a->key, sizeof(a->key),
                                       TLS13_PSK_KE_MODE_PSK_DHE_KE));
    if(e->is_client != 0) {
        noxtls_tls13_set_client_supported_groups(&e->ctx, &group, 1U);
    } else {
        noxtls_tls13_set_server_cipher_suites(&e->ctx, &suite, 1U);
    }
    return 0;
}

/** Create association @p i (link, keys, both endpoints). @p use_blocks selects static blocks. */
static int mc_assoc_open(uint32_t i, int dtls, int use_blocks)
{
    mc_assoc_t *a = &s_assoc[i];
    void *cmem = NULL;
    void *smem = NULL;
    size_t mem_len = 0U;

    memset(a, 0, sizeof(*a));
    a->link.datagram = dtls;
    a->link.cport.link = &a->link;
    a->link.cport.is_client = 1;
    a->link.sport.link = &a->link;
    a->link.sport.is_client = 0;
    mc_assoc_keys(a, i);
#if NOXTLS_CONN_MEMORY
    if(use_blocks != 0) {
        cmem = s_blocks[i][0];
        smem = s_blocks[i][1];
        mem_len = sizeof(s_blocks[i][0]);
    }
#else
    (void)use_blocks;
#endif
    LB_RUN(mc_end_init(&a->c, 1, dtls, cmem, mem_len));
    LB_RUN(mc_end_config(a, &a->c));
    LB_RUN(mc_end_init(&a->s, 0, dtls, smem, mem_len));
    LB_RUN(mc_end_config(a, &a->s));
    return 0;
}

static void mc_end_free(mc_end_t *e)
{
    if(e->initialized != 0) {
        (void)noxtls_tls13_context_free(&e->ctx);
        e->initialized = 0;
    }
}

static void mc_assoc_free(uint32_t i)
{
    mc_end_free(&s_assoc[i].c);
    mc_end_free(&s_assoc[i].s);
}

static int mc_is_progress(noxtls_return_t rc)
{
    return ((rc == NOXTLS_RETURN_WANT_READ) || (rc == NOXTLS_RETURN_WANT_WRITE) || (rc == NOXTLS_RETURN_TIMEOUT)) ? 1 : 0;
}

/** One owner turn for an endpoint: one connect/accept call while its handshake runs. */
static void mc_step(mc_end_t *e)
{
    if((e->initialized == 0) || (e->done != 0) || (mc_is_progress(e->last_rc) == 0)) {
        return;
    }
    e->last_rc = (e->is_client != 0) ? noxtls_tls13_connect(&e->ctx) : noxtls_tls13_accept(&e->ctx);
    if(e->last_rc == NOXTLS_RETURN_SUCCESS) {
        e->done = 1;
    }
    if(e->dtls == 0) {
        (void)noxtls_tls_flush(&e->ctx.base.base);
    }
}

static int mc_assoc_done(const mc_assoc_t *a)
{
    return ((a->c.done != 0) && (a->s.done != 0)) ? 1 : 0;
}

/**
 * Drive the handshakes of @p order[0..n) round-robin until all complete. Each round
 * gives every endpoint one turn; @p reverse_odd reverses the order on odd rounds, and
 * association order[late] starts only after @p late_rounds rounds.
 */
static int mc_drive(const uint32_t *order, uint32_t n, int reverse_odd, uint32_t late, uint32_t late_rounds)
{
    uint32_t round;
    uint32_t k;

    for(round = 0U; round < 4000U; round++) {
        int all = 1;
        for(k = 0U; k < n; k++) {
            uint32_t idx = ((reverse_odd != 0) && ((round & 1U) != 0U)) ? (n - 1U - k) : k;
            mc_assoc_t *a = &s_assoc[order[idx]];
            if((idx == late) && (round < late_rounds)) {
                all = 0;
                continue;
            }
            mc_step(&a->c);
            mc_step(&a->s);
            if(mc_assoc_done(a) == 0) {
                all = 0;
            }
        }
        for(k = 0U; k < n; k++) {
            const mc_assoc_t *a = &s_assoc[order[k]];
            if(((a->c.done == 0) && (mc_is_progress(a->c.last_rc) == 0)) ||
               ((a->s.done == 0) && (mc_is_progress(a->s.last_rc) == 0))) {
                lb_log("association %u failed: client rc=%d server rc=%d", (unsigned)order[k],
                       (int)a->c.last_rc, (int)a->s.last_rc);
                return 1;
            }
        }
        if(all != 0) {
            return 0;
        }
        s_now_ms += 25U;
    }
    lb_log("handshakes did not complete");
    return 1;
}

/** Receive exactly @p len bytes on @p e (turns of the owner loop, no waiting). */
static int mc_recv_exact(mc_end_t *e, uint8_t *out, uint32_t len)
{
    uint32_t got = 0U;
    uint32_t turns;

    for(turns = 0U; (turns < 200U) && (got < len); turns++) {
        uint32_t n = len - got;
        noxtls_return_t rc = noxtls_tls13_recv(&e->ctx, &out[got], &n);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            got += n;
        } else if(mc_is_progress(rc) == 0) {
            lb_log("recv failed rc=%d", (int)rc);
            return 1;
        } else {
            s_now_ms += 5U;
        }
    }
    LB_CHECK_EQ(got, len);
    return 0;
}

/** Send @p len pattern bytes from one endpoint of association @p i and check delivery. */
static int mc_exchange(uint32_t i, int from_client, uint32_t len, uint32_t seed)
{
    mc_assoc_t *a = &s_assoc[i];
    mc_end_t *tx = (from_client != 0) ? &a->c : &a->s;
    mc_end_t *rx = (from_client != 0) ? &a->s : &a->c;

    lb_fill_pattern(s_buf, len, seed);
    LB_CHECK_OK(noxtls_tls13_send(&tx->ctx, s_buf, len));
    if(tx->dtls == 0) {
        (void)noxtls_tls_flush(&tx->ctx.base.base);
    }
    memset(s_rx, 0, len);
    LB_RUN(mc_recv_exact(rx, s_rx, len));
    LB_CHECK(memcmp(s_rx, s_buf, len) == 0);
    return 0;
}

/** Data in both directions on every association, interleaved across associations. */
static int mc_exchange_all(const uint32_t *order, uint32_t n, uint32_t seed)
{
    uint32_t k;
    for(k = 0U; k < n; k++) {
        LB_RUN(mc_exchange(order[k], 1, 300U + (17U * k), seed + order[k]));
    }
    for(k = n; k > 0U; k--) {
        LB_RUN(mc_exchange(order[k - 1U], 0, 500U + (11U * k), seed + 100U + order[k - 1U]));
    }
    return 0;
}

#if NOXTLS_CONN_MEMORY
static int mc_released(const mc_end_t *e)
{
    noxtls_connection_memory_stats_t st;
    if(noxtls_connection_memory_get_stats(&e->ctx, &st) != NOXTLS_RETURN_SUCCESS) {
        return -1;
    }
    return (int)st.released;
}

/** A released endpoint: hs gone, part wiped, no pointer into it, steady arena idle. */
static int mc_check_released(const mc_end_t *e)
{
    noxtls_connection_memory_stats_t st;
    LB_CHECK_OK(noxtls_connection_memory_get_stats(&e->ctx, &st));
    LB_CHECK_EQ(st.released, 1U);
    LB_CHECK_EQ(st.dangling_pointers, 0U);
    LB_CHECK(e->ctx.hs == NULL);
    LB_CHECK_EQ(st.steady_arena.live_blocks, 0U);
    return 0;
}
#endif

/* ---- Cases ----------------------------------------------------------------- */

/**
 * Two DTLS 1.3 PSK server associations (NoxLink fleet and local), two node-facing
 * DTLS 1.3 PSK associations and one TLS 1.3 PSK stream association, all live at once.
 * With room for four associations only (MC_FIT), the second node association is left
 * out.
 */
static int t_concurrent_server_client(void)
{
    static const uint32_t all[5] = { 0U, 1U, 2U, 3U, 4U };
    static const uint32_t fit4[4] = { 0U, 1U, 2U, 4U };
    const uint32_t *order = (MC_FIT >= 5U) ? all : fit4;
    uint32_t n = (MC_FIT >= 5U) ? 5U : 4U;
    size_t base = lb_alloc_live_bytes();
    size_t heap_before;
    uint32_t k;

    if(MC_FIT < 4U) {
        return LB_SKIP;
    }
    for(k = 0U; k < n; k++) {
        LB_RUN(mc_assoc_open(order[k], (order[k] < 4U) ? 1 : 0, 1));
    }
    heap_before = MC_HEAP_CALLS();
    LB_RUN(mc_drive(order, n, 0, 0U, 0U));
    LB_RUN(mc_exchange_all(order, n, 1U));
    /* KeyUpdate on every association, interleaved, then data again. */
    for(k = 0U; k < n; k++) {
        LB_CHECK_OK(noxtls_tls13_send_key_update(&s_assoc[order[k]].s.ctx, 1U));
        if(order[k] == 4U) {
            (void)noxtls_tls_flush(&s_assoc[order[k]].s.ctx.base.base);
        }
    }
    LB_RUN(mc_exchange_all(order, n, 50U));
    /* A full NoxLink frame budget in one record on the fleet association. */
    LB_RUN(mc_exchange(0U, 0, MC_RSL - 1U, 77U));
#if NOXTLS_CONN_MEMORY
    for(k = 0U; k < n; k++) {
        LB_RUN(mc_check_released(&s_assoc[order[k]].c));
        LB_RUN(mc_check_released(&s_assoc[order[k]].s));
    }
#endif
    LB_CHECK_EQ(MC_HEAP_CALLS() - heap_before, 0U);
    for(k = 0U; k < n; k++) {
        (void)noxtls_tls13_close(&s_assoc[order[k]].c.ctx);
        mc_assoc_free(order[k]);
    }
    return lb_expect_no_leak(base, "concurrent server and client");
}

/**
 * A server only accepts its own identity: a client offering the fleet identity to the
 * local server fails, and the established fleet association is not disturbed.
 */
static int t_cross_identity_refused(void)
{
    static const uint32_t fleet[1] = { 0U };
    size_t base = lb_alloc_live_bytes();
    mc_assoc_t *rogue = &s_assoc[1];
    uint32_t round;

    LB_RUN(mc_assoc_open(0U, 1, 1));
    LB_RUN(mc_drive(fleet, 1U, 0, 0U, 0U));
    /* Association 1: its client is given association 0's identity and key. */
    LB_RUN(mc_assoc_open(1U, 1, 1));
    LB_CHECK_OK(tls13_set_external_psk(&rogue->c.ctx, s_assoc[0].identity, s_assoc[0].identity_len,
                                       s_assoc[0].key, sizeof(s_assoc[0].key), TLS13_PSK_KE_MODE_PSK_DHE_KE));
    for(round = 0U; round < 200U; round++) {
        mc_step(&rogue->c);
        mc_step(&rogue->s);
        if((mc_is_progress(rogue->s.last_rc) == 0) || (mc_is_progress(rogue->c.last_rc) == 0)) {
            break;
        }
        s_now_ms += 25U;
    }
    LB_CHECK(rogue->s.done == 0);
    LB_CHECK(rogue->c.done == 0);
    /* The fleet association still carries data in both directions. */
    LB_RUN(mc_exchange(0U, 1, 700U, 3U));
    LB_RUN(mc_exchange(0U, 0, 900U, 4U));
    mc_assoc_free(1U);
    LB_RUN(mc_exchange(0U, 1, 64U, 5U));
    (void)noxtls_tls13_close(&s_assoc[0].c.ctx);
    mc_assoc_free(0U);
    return lb_expect_no_leak(base, "cross identity");
}

/**
 * Four DTLS 1.3 associations handshake one flight per turn, in an order that reverses
 * every round, with one association starting late, one losing its first server flight
 * (recovered by the retransmission timer) and one receiving its ClientHello twice
 * (the repeated-flight answer, RFC 9147 Section 5.8.1).
 */
static int t_interleaved_handshakes(void)
{
    static const uint32_t order[4] = { 3U, 0U, 2U, 1U };
    size_t base = lb_alloc_live_bytes();
    uint32_t i;

    for(i = 0U; i < 4U; i++) {
        LB_RUN(mc_assoc_open(i, 1, 1));
    }
    s_assoc[1].link.to_client.drop_next = 1U;
    s_assoc[3].link.to_server.dup_next = 1U;
    LB_RUN(mc_drive(order, 4U, 1, 2U, 6U));
    LB_CHECK(s_assoc[1].link.to_client.datagrams > 1U);
    LB_RUN(mc_exchange_all(order, 4U, 9U));
#if NOXTLS_CONN_MEMORY
    for(i = 0U; i < 4U; i++) {
        LB_RUN(mc_check_released(&s_assoc[i].c));
        LB_RUN(mc_check_released(&s_assoc[i].s));
    }
#endif
    for(i = 0U; i < 4U; i++) {
        (void)noxtls_tls13_close(&s_assoc[i].s.ctx);
        mc_assoc_free(i);
    }
    return lb_expect_no_leak(base, "interleaved handshakes");
}

/**
 * The release after the handshake applies to each context alone: one association
 * completes and releases while another is in the middle of its handshake, whose state
 * and memory stay intact; then the second completes while the first carries data.
 */
static int t_release_per_context(void)
{
    static const uint32_t first[2] = { 0U, 2U };   /* DTLS 0, TLS 2 */
    static const uint32_t second[2] = { 1U, 3U };  /* DTLS 1, TLS 3 */
    size_t base = lb_alloc_live_bytes();
    uint32_t i;
#if NOXTLS_CONN_MEMORY
    noxtls_connection_memory_stats_t before[2];
    noxtls_connection_memory_stats_t after;
#endif

    LB_RUN(mc_assoc_open(0U, 1, 1));
    LB_RUN(mc_assoc_open(1U, 1, 1));
    LB_RUN(mc_assoc_open(2U, 0, 1));
    LB_RUN(mc_assoc_open(3U, 0, 1));
    /* Second pair: client hello sent and processed by the server; the server's flight
     * is queued for the client, which has not read it yet. */
    for(i = 0U; i < 2U; i++) {
        mc_assoc_t *a = &s_assoc[second[i]];
        mc_step(&a->c);
        mc_step(&a->s);
        LB_CHECK((a->c.done == 0) && (a->s.done == 0));
        LB_CHECK(a->c.ctx.hs != NULL);
        LB_CHECK(a->s.ctx.hs != NULL);
#if NOXTLS_CONN_MEMORY
        LB_CHECK_OK(noxtls_connection_memory_get_stats(&a->s.ctx, &before[i]));
        LB_CHECK_EQ(before[i].released, 0U);
        LB_CHECK(before[i].hs_arena.live_blocks > 0U);
#endif
    }
    /* First pair: complete, exchange data (the DTLS client releases on the ACK). */
    LB_RUN(mc_drive(first, 2U, 0, 0U, 0U));
    LB_RUN(mc_exchange_all(first, 2U, 21U));
    for(i = 0U; i < 2U; i++) {
        mc_assoc_t *done = &s_assoc[first[i]];
        mc_assoc_t *busy = &s_assoc[second[i]];
#if NOXTLS_CONN_MEMORY
        LB_RUN(mc_check_released(&done->c));
        LB_RUN(mc_check_released(&done->s));
        LB_CHECK_EQ(mc_released(&busy->c), 0);
        LB_CHECK_OK(noxtls_connection_memory_get_stats(&busy->s.ctx, &after));
        LB_CHECK_EQ(after.released, 0U);
        LB_CHECK_EQ(after.hs_arena.live_blocks, before[i].hs_arena.live_blocks);
        LB_CHECK_EQ(after.hs_arena.used, before[i].hs_arena.used);
        LB_CHECK_EQ(after.hs_arena.allocations, before[i].hs_arena.allocations);
#else
        /* Heap TLS 1.3 frees its handshake state at CONNECTED (DTLS keeps it). */
        if(done->c.dtls == 0) {
            LB_CHECK(done->c.ctx.hs == NULL);
            LB_CHECK(done->s.ctx.hs == NULL);
        }
#endif
        LB_CHECK(busy->c.ctx.hs != NULL);
        LB_CHECK(busy->s.ctx.hs != NULL);
    }
    /* Second pair completes; the first pair keeps working throughout. */
    LB_RUN(mc_drive(second, 2U, 0, 0U, 0U));
    LB_RUN(mc_exchange_all(second, 2U, 31U));
    LB_RUN(mc_exchange_all(first, 2U, 41U));
#if NOXTLS_CONN_MEMORY
    for(i = 0U; i < 4U; i++) {
        LB_RUN(mc_check_released(&s_assoc[i].c));
        LB_RUN(mc_check_released(&s_assoc[i].s));
    }
#else
    LB_CHECK(s_assoc[3].c.ctx.hs == NULL);
    LB_CHECK(s_assoc[3].s.ctx.hs == NULL);
#endif
    for(i = 0U; i < 4U; i++) {
        (void)noxtls_tls13_close(&s_assoc[i].c.ctx);
        mc_assoc_free(i);
    }
    return lb_expect_no_leak(base, "release per context");
}

#if NOXTLS_CONN_MEMORY
/** Initialize a DTLS 1.3 PSK server of association @p i in a steady block and @p hs. */
static noxtls_return_t mc_split_server(uint32_t i, uint32_t steady, void *hs, size_t hs_len)
{
    mc_assoc_t *a = &s_assoc[i];
    noxtls_return_t rc = noxtls_dtls13_context_init_static_split(&a->s.ctx, TLS_ROLE_SERVER,
                                                                 NOXTLS_CONN_PROFILE_DTLS13_PSK,
                                                                 s_steady[steady], sizeof(s_steady[steady]), hs, hs_len);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        a->s.is_client = 0;
        a->s.dtls = 1;
        a->s.initialized = 1;
        a->s.done = 0;
        a->s.last_rc = NOXTLS_RETURN_WANT_READ;
        if(mc_end_config(a, &a->s) != 0) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    return rc;
}

/** Association @p i with a heap-free client block and no server yet. */
static int mc_open_client_only(uint32_t i)
{
    mc_assoc_t *a = &s_assoc[i];
    memset(a, 0, sizeof(*a));
    a->link.datagram = 1;
    a->link.cport.link = &a->link;
    a->link.cport.is_client = 1;
    a->link.sport.link = &a->link;
    a->link.sport.is_client = 0;
    mc_assoc_keys(a, i);
    LB_RUN(mc_end_init(&a->c, 1, 1, s_blocks[i][0], sizeof(s_blocks[i][0])));
    LB_RUN(mc_end_config(a, &a->c));
    return 0;
}

static int mc_all_zero(const uint64_t *p, size_t words)
{
    size_t k;
    for(k = 0U; k < words; k++) {
        if(p[k] != 0U) {
            return 0;
        }
    }
    return 1;
}
#endif

/**
 * Two NoxLink server associations take turns with one handshake block
 * (noxtls_dtls13_context_init_static_split): the second server can start its
 * handshake only after the first released the block; freeing a context that already
 * released the block does not disturb the handshake that holds it; a replacement
 * association (a Fleet deploy re-handshake) reuses a freed steady block.
 */
static int t_shared_handshake_region(void)
{
#if !NOXTLS_CONN_MEMORY
    return LB_SKIP;
#else
    static const uint32_t a0[1] = { 0U };
    static const uint32_t a1[1] = { 1U };
    static const uint32_t a2[1] = { 2U };
    size_t base = lb_alloc_live_bytes();
    uint8_t *region = NULL;
    size_t region_len = 0U;
    size_t heap_before = MC_HEAP_CALLS();
    noxtls_connection_footprint_t fp;
    uint32_t i;

    LB_CHECK_OK(noxtls_connection_memory_footprint(TLS_ROLE_SERVER, NOXTLS_CONN_PROFILE_DTLS13_PSK, &fp));
    LB_CHECK_EQ(sizeof(s_steady[0]), fp.steady);
    LB_CHECK_EQ(sizeof(s_shared_hs), fp.handshake);

    /* Parameter errors leave nothing behind. */
    LB_RUN(mc_open_client_only(0U));
    LB_CHECK_EQ(noxtls_dtls13_context_init_static_split(&s_assoc[0].s.ctx, TLS_ROLE_SERVER,
                NOXTLS_CONN_PROFILE_DTLS13_PSK, s_steady[0], sizeof(s_steady[0]), s_shared_hs,
                sizeof(s_shared_hs) - 8U), NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_EQ(noxtls_dtls13_context_init_static_split(&s_assoc[0].s.ctx, TLS_ROLE_SERVER,
                NOXTLS_CONN_PROFILE_DTLS13_PSK, s_steady[0], sizeof(s_steady[0]) - 8U, s_shared_hs,
                sizeof(s_shared_hs)), NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_EQ(noxtls_dtls13_context_init_static_split(&s_assoc[0].s.ctx, TLS_ROLE_SERVER,
                NOXTLS_CONN_PROFILE_DTLS13_PSK, s_steady[0], sizeof(s_steady[0]),
                (uint8_t *)(void *)s_shared_hs + 4, sizeof(s_shared_hs) - 8U), NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_EQ(noxtls_dtls13_context_init_static_split(&s_assoc[0].s.ctx, TLS_ROLE_SERVER,
                NOXTLS_CONN_PROFILE_TLS13_PSK, s_steady[0], sizeof(s_steady[0]), s_shared_hs,
                sizeof(s_shared_hs)), NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_EQ(noxtls_dtls13_context_init_static_split(&s_assoc[0].s.ctx, TLS_ROLE_SERVER,
                NOXTLS_CONN_PROFILE_DTLS13_PSK, s_steady[0], sizeof(s_steady[0]), NULL, 0U), NOXTLS_RETURN_NULL);
    /* The client's block is in use: neither part may overlap it. */
    LB_CHECK_EQ(noxtls_dtls13_context_init_static_split(&s_assoc[0].s.ctx, TLS_ROLE_SERVER,
                NOXTLS_CONN_PROFILE_DTLS13_PSK, s_steady[0], sizeof(s_steady[0]), s_blocks[0][0],
                sizeof(s_blocks[0][0])), NOXTLS_RETURN_NOT_ENOUGH_MEMORY);

    /* Server 0 takes the handshake block. */
    LB_CHECK_OK(mc_split_server(0U, 0U, s_shared_hs, sizeof(s_shared_hs)));
    LB_RUN(mc_open_client_only(1U));
    memset(s_steady[1], 0x5A, sizeof(s_steady[1]));
    LB_CHECK_EQ(mc_split_server(1U, 1U, s_shared_hs, sizeof(s_shared_hs)), NOXTLS_RETURN_NOT_ENOUGH_MEMORY);
    /* The refused init wrote nothing. */
    LB_CHECK(((const uint8_t *)(const void *)s_steady[1])[0] == 0x5AU);
    LB_CHECK(((const uint8_t *)(const void *)s_steady[1])[sizeof(s_steady[1]) - 1U] == 0x5AU);
    LB_CHECK_EQ(noxtls_connection_memory_handshake_region(&s_assoc[0].s.ctx, &region, &region_len),
                NOXTLS_RETURN_NOT_INITIALIZED);

    LB_RUN(mc_drive(a0, 1U, 0, 0U, 0U));
    LB_CHECK_EQ(mc_released(&s_assoc[0].s), 1);
    LB_CHECK_OK(noxtls_connection_memory_handshake_region(&s_assoc[0].s.ctx, &region, &region_len));
    LB_CHECK(region == (uint8_t *)(void *)s_shared_hs);
    LB_CHECK_EQ(region_len, fp.handshake);
    LB_CHECK(mc_all_zero(s_shared_hs, sizeof(s_shared_hs) / 8U) != 0);

    /* Server 1 now takes it; server 0 can no longer lend it out. */
    LB_CHECK_OK(mc_split_server(1U, 1U, s_shared_hs, sizeof(s_shared_hs)));
    LB_CHECK_EQ(noxtls_connection_memory_handshake_region(&s_assoc[0].s.ctx, &region, &region_len),
                NOXTLS_RETURN_NOT_ENOUGH_MEMORY);
    LB_CHECK(region == NULL);
    /* Server 1 is mid-handshake (it processed the ClientHello) when server 0 goes. */
    mc_step(&s_assoc[1].c);
    mc_step(&s_assoc[1].s);
    LB_CHECK(s_assoc[1].s.ctx.hs != NULL);
    LB_RUN(mc_exchange(0U, 1, 600U, 61U));
    LB_RUN(mc_exchange(0U, 0, 800U, 62U));
    (void)noxtls_tls13_close(&s_assoc[0].c.ctx);
    mc_assoc_free(0U);
    LB_CHECK(mc_all_zero(s_steady[0], sizeof(s_steady[0]) / 8U) != 0);
    LB_CHECK(mc_all_zero(s_shared_hs, sizeof(s_shared_hs) / 8U) == 0);
    LB_RUN(mc_drive(a1, 1U, 0, 0U, 0U));
    LB_RUN(mc_exchange(1U, 1, 1000U, 63U));
    LB_RUN(mc_exchange(1U, 0, MC_RSL - 1U, 64U));
    LB_RUN(mc_check_released(&s_assoc[1].c));
    LB_RUN(mc_check_released(&s_assoc[1].s));

    /* Replacement association in the freed steady block 0, through the same block. */
    LB_RUN(mc_open_client_only(2U));
    LB_CHECK_OK(mc_split_server(2U, 0U, s_shared_hs, sizeof(s_shared_hs)));
    LB_RUN(mc_drive(a2, 1U, 0, 0U, 0U));
    for(i = 0U; i < 2U; i++) {
        LB_CHECK_OK(noxtls_tls13_send_key_update(&s_assoc[1U + i].s.ctx, 1U));
        LB_RUN(mc_exchange(1U + i, 1, 400U, 70U + i));
        LB_RUN(mc_exchange(1U + i, 0, 450U, 80U + i));
        LB_RUN(mc_check_released(&s_assoc[1U + i].s));
    }
    LB_CHECK_EQ(MC_HEAP_CALLS() - heap_before, 0U);
    printf("shared handshake block: steady %lu + handshake %lu per DTLS13_PSK server; "
           "2 associations %lu separate, %lu shared\n",
           (unsigned long)fp.steady, (unsigned long)fp.handshake,
           (unsigned long)(2U * fp.total), (unsigned long)((2U * fp.steady) + fp.handshake));
    for(i = 1U; i < 3U; i++) {
        (void)noxtls_tls13_close(&s_assoc[i].c.ctx);
        mc_assoc_free(i);
    }
    LB_CHECK(mc_all_zero(s_steady[0], sizeof(s_steady[0]) / 8U) != 0);
    LB_CHECK(mc_all_zero(s_steady[1], sizeof(s_steady[1]) / 8U) != 0);
    LB_CHECK(mc_all_zero(s_shared_hs, sizeof(s_shared_hs) / 8U) != 0);
    return lb_expect_no_leak(base, "shared handshake region");
#endif
}

/* ---- Calls on one connection from inside another's call ------------------- */

typedef struct
{
    mc_end_t *other;          /* a client of another association */
    noxtls_return_t send_rc;
    noxtls_return_t record_rc;
    noxtls_return_t flush_rc;
    noxtls_return_t trust_rc;
    size_t global_blocks;     /* global arena blocks right after the trust store set */
    int ran;
} mc_nested_t;

static void mc_nested_hook(void *arg)
{
    mc_nested_t *n = (mc_nested_t *)arg;
    static const uint8_t data[3] = { 'n', 'e', 's' };
    static const uint8_t inner[4] = { 't', 'e', 'd', TLS_RECORD_APPLICATION_DATA };
    const uint8_t *ders[1];
    uint32_t lens[1];

    n->ran = 1;
    n->send_rc = noxtls_tls13_send(&n->other->ctx, data, sizeof(data));
    /* A record-layer entry point, as the host helper uses for its close alerts. */
    n->record_rc = noxtls_tls13_send_dtls13_encrypted_record(&n->other->ctx, 0, TLS_RECORD_APPLICATION_DATA,
                                                            inner, sizeof(inner), 1);
    n->flush_rc = noxtls_tls_flush(&n->other->ctx.base.base);
    ders[0] = lb_ec_root_cert;
    lens[0] = lb_ec_root_cert_len;
    n->trust_rc = noxtls_x509_trust_store_set_der_nocopy(ders, lens, 1U);
#if NOXTLS_CONN_MEMORY
    {
        noxtls_mem_region_stats_t g;
        (void)noxtls_mem_region_get_stats(noxtls_mem_global_region(), &g);
        n->global_blocks = g.live_blocks;
    }
#endif
}

/**
 * The owner drives connection B from inside connection A's send callback (as a leader
 * publishes a NoxLink datagram through its MQTT connection). B's allocations stay in
 * B's memory, the trust store goes to the global arena, and A's memory sees exactly
 * what A's own send needs.
 */
static int t_foreign_scope_isolation(void)
{
    static const uint32_t order[2] = { 0U, 1U };
    mc_nested_t nested;
    size_t base = lb_alloc_live_bytes();
#if NOXTLS_CONN_MEMORY
    noxtls_connection_memory_stats_t a0;
    noxtls_connection_memory_stats_t a1;
    noxtls_connection_memory_stats_t b0;
    noxtls_connection_memory_stats_t b1;
    noxtls_mem_region_stats_t g0;
    size_t own_send;
#endif

    LB_RUN(mc_assoc_open(0U, 1, 1));
    LB_RUN(mc_assoc_open(1U, 1, 1));
    LB_RUN(mc_drive(order, 2U, 0, 0U, 0U));
    LB_RUN(mc_exchange_all(order, 2U, 90U));
#if NOXTLS_CONN_MEMORY
    /* What one 200-byte send costs server A on its own. */
    LB_CHECK_OK(noxtls_connection_memory_get_stats(&s_assoc[0].s.ctx, &a0));
    LB_RUN(mc_exchange(0U, 0, 200U, 91U));
    LB_CHECK_OK(noxtls_connection_memory_get_stats(&s_assoc[0].s.ctx, &a1));
    own_send = a1.steady_arena.allocations - a0.steady_arena.allocations;
    LB_CHECK_OK(noxtls_connection_memory_get_stats(&s_assoc[0].s.ctx, &a0));
    LB_CHECK_OK(noxtls_connection_memory_get_stats(&s_assoc[1].c.ctx, &b0));
    (void)noxtls_mem_region_get_stats(noxtls_mem_global_region(), &g0);
#endif
    memset(&nested, 0, sizeof(nested));
    nested.other = &s_assoc[1].c;
    s_assoc[0].link.server_send_hook = mc_nested_hook;
    s_assoc[0].link.hook_arg = &nested;
    LB_RUN(mc_exchange(0U, 0, 200U, 92U));
    LB_CHECK(nested.ran != 0);
    LB_CHECK_OK(nested.send_rc);
    LB_CHECK_OK(nested.record_rc);
    LB_CHECK_OK(nested.flush_rc);
    LB_CHECK_OK(nested.trust_rc);
    LB_CHECK(noxtls_x509_trust_store_has_anchors() != 0);
#if NOXTLS_CONN_MEMORY
    LB_CHECK_OK(noxtls_connection_memory_get_stats(&s_assoc[0].s.ctx, &a1));
    LB_CHECK_OK(noxtls_connection_memory_get_stats(&s_assoc[1].c.ctx, &b1));
    LB_CHECK_EQ(a1.steady_arena.allocations - a0.steady_arena.allocations, own_send);
    LB_CHECK_EQ(a1.steady_arena.live_blocks, 0U);
    LB_CHECK(b1.steady_arena.allocations > b0.steady_arena.allocations);
    LB_CHECK(nested.global_blocks > g0.live_blocks);
#endif
    /* B's peer receives both nested records in order. */
    LB_RUN(mc_recv_exact(&s_assoc[1].s, s_rx, 6U));
    LB_CHECK(memcmp(s_rx, "nested", 6U) == 0);
    noxtls_x509_trust_store_clear();
    LB_RUN(mc_exchange_all(order, 2U, 93U));
    (void)noxtls_tls13_close(&s_assoc[0].c.ctx);
    (void)noxtls_tls13_close(&s_assoc[1].c.ctx);
    mc_assoc_free(0U);
    mc_assoc_free(1U);
    return lb_expect_no_leak(base, "foreign scope");
}

/**
 * A host helper holding many PSK client associations: eight associations handshake
 * interleaved, all carry data, then associations close one by one (the others keep
 * working after each close) and new associations reuse the freed slots while the rest
 * are live. With room for fewer than eight associations (MC_FIT), four run: two close,
 * one reopens.
 */
static int t_many_psk_clients(void)
{
    static const uint32_t all8[8] = { 7U, 1U, 5U, 3U, 0U, 6U, 2U, 4U };
    static const uint32_t close8[4] = { 2U, 5U, 0U, 7U };
    static const uint32_t reopen8[2] = { 5U, 2U };
    static const uint32_t all4[4] = { 7U, 1U, 5U, 3U };
    static const uint32_t close4[2] = { 5U, 7U };
    static const uint32_t reopen4[1] = { 5U };
    const int full = (MC_FIT >= 8U) ? 1 : 0;
    const uint32_t *all = (full != 0) ? all8 : all4;
    const uint32_t *close_order = (full != 0) ? close8 : close4;
    const uint32_t *reopened = (full != 0) ? reopen8 : reopen4;
    uint32_t n = (full != 0) ? 8U : 4U;
    uint32_t n_close = n / 2U;
    uint32_t n_reopen = n / 4U;
    size_t base = lb_alloc_live_bytes();
    uint32_t i;
    uint32_t k;

    if(MC_FIT < 4U) {
        return LB_SKIP;
    }
    for(k = 0U; k < n; k++) {
        LB_RUN(mc_assoc_open(all[k], 1, 1));
    }
    LB_RUN(mc_drive(all, n, 1, n / 2U, 3U));
    LB_RUN(mc_exchange_all(all, n, 200U));
    for(k = 0U; k < n_close; k++) {
        uint32_t gone = close_order[k];
        (void)noxtls_tls13_close(&s_assoc[gone].c.ctx);
        mc_assoc_free(gone);
        for(i = 0U; i < MC_ASSOC_MAX; i++) {
            if(s_assoc[i].c.initialized != 0) {
                LB_RUN(mc_exchange(i, 1, 120U + i, 300U + (k * 10U) + i));
            }
        }
    }
    /* Reopen closed slots (new handshakes next to the live associations). */
    for(k = 0U; k < n_reopen; k++) {
        LB_RUN(mc_assoc_open(reopened[k], 1, 1));
    }
    LB_RUN(mc_drive(reopened, n_reopen, 1, 0U, 0U));
    for(i = 0U; i < MC_ASSOC_MAX; i++) {
        if(s_assoc[i].c.initialized != 0) {
            LB_RUN(mc_exchange(i, 0, 256U, 400U + i));
#if NOXTLS_CONN_MEMORY
            LB_RUN(mc_check_released(&s_assoc[i].c));
#endif
        }
    }
    for(i = 0U; i < MC_ASSOC_MAX; i++) {
        if(s_assoc[i].c.initialized != 0) {
            (void)noxtls_tls13_close(&s_assoc[i].c.ctx);
        }
        mc_assoc_free(i);
    }
    return lb_expect_no_leak(base, "many PSK clients");
}

/**
 * A 1,400-byte NoxLink frame and record_size_limit (RFC 8449 Section 4: the limit counts
 * the inner content type, so a record carries at most limit - 1 bytes): with the limit
 * 1,400 the frame needs two records (two datagrams, two MQTT publishes); with 1,401 it
 * is one record in one datagram, which the receiver accepts at the largest record size.
 */
static int t_noxlink_frame_records(void)
{
    static const uint32_t one[1] = { 0U };
    static const uint16_t limits[2] = { 1400U, 1401U };
    static const uint32_t expected[2] = { 2U, 1U };
    size_t base = lb_alloc_live_bytes();
    uint32_t k;

    if(TLS_MAX_RECORD_SIZE < 1400U) {
        return LB_SKIP;
    }
    for(k = 0U; k < 2U; k++) {
        uint32_t before;
        LB_RUN(mc_assoc_open(0U, 1, 1));
        noxtls_tls13_set_record_size_limit(&s_assoc[0].c.ctx, limits[k]);
        noxtls_tls13_set_record_size_limit(&s_assoc[0].s.ctx, limits[k]);
        LB_RUN(mc_drive(one, 1U, 0, 0U, 0U));
        LB_RUN(mc_exchange(0U, 1, 16U, 500U + k));   /* the client's final ACK is settled */
        before = s_assoc[0].link.to_client.datagrams;
        LB_RUN(mc_exchange(0U, 0, 1400U, 510U + k));
        LB_CHECK_EQ(s_assoc[0].link.to_client.datagrams - before, expected[k]);
        (void)noxtls_tls13_close(&s_assoc[0].c.ctx);
        mc_assoc_free(0U);
    }
    return lb_expect_no_leak(base, "NoxLink frame records");
}

/* ---- Leader use cases (docs/static-memory.md, profile (iv)) ---------------- */

/*
 * The leader's connections, by association slot: NoxLink fleet and local servers and
 * the replacement server of a re-handshake (DTLS 1.3 PSK, lazy split contexts on one
 * handshake block), node-facing DTLS 1.3 PSK clients, and the MQTT connection (TLS 1.3
 * client with certificates and mutual authentication). In each association the
 * leader's context is the server (NoxLink) or the client (nodes, MQTT); the other end
 * stands for the peer.
 */
#define MC_L_FLEET 0U
#define MC_L_LOCAL 1U
#define MC_L_REPL  2U
#define MC_L_NODE0 3U
#define MC_L_NODES 4U
#define MC_L_MQTT  7U
/** The leader limits the broker's records to 512 bytes (RFC 8449). */
#define MC_MQTT_RSL 513U
/** A NoxLink frame of 1,400 bytes in one MQTT publish, split into broker records. */
#define MC_MQTT_FRAME 1400U
/** Broker chains: ECDSA (leaf + intermediate), RSA (leaf + intermediate + cross-signed
 *  root), RSA after an intermediate rotation (four certificates, the profile's limit). */
#define MC_CHAIN_ECDSA 0
#define MC_CHAIN_RSA   1
#define MC_CHAIN_RSA4  2
/** Four RSA certificates of 2,036 to 2,040 bytes: the largest chain the profile accepts. */
#define MC_CHAIN_RSA_MAX 3

#if NOXTLS_CONN_MEMORY
#define MC_CERT_BYTES \
    MC_MAX2(NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_CLIENT, TLS13_CERT), \
            NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_SERVER, TLS13_CERT))
/* [0] the leader's MQTT client, [1] the broker. */
static uint64_t s_cert_blocks[2][MC_CERT_BYTES / 8U];
#endif

/** Broker and device keys, and what they cost the global arena. */
typedef struct
{
    int rsa;
    int kind;
    uint16_t rsl;
    uint32_t chain_count;
    const uint8_t *leaf;
    uint32_t leaf_len;
    rsa_key_t device_rsa;
    rsa_key_t broker_rsa;
    ecc_key_t device_ec;
    ecc_key_t broker_ec;
    int loaded;
    const uint8_t *chain[3];
    uint32_t chain_lens[3];
    size_t device_key_global;
    size_t identity_global;
    /* The leader's anchors for its connection's verify policy (fleet_mqtt.c). */
    x509_certificate_t roots[2];
    x509_certificate_chain_t anchors;
    noxtls_x509_verify_policy_t policy;
    size_t trust_store_global;
} mc_broker_t;

static mc_broker_t s_broker;

#if NOXTLS_CONN_MEMORY
/** Highest arena use seen per leader context kind (printed by the cases). */
typedef struct
{
    size_t hs_peak;
    size_t hs_budget;
    size_t steady_peak;
    size_t steady_budget;
    size_t block;
} mc_usage_t;
#endif

static size_t mc_global_used(void)
{
#if NOXTLS_CONN_MEMORY
    noxtls_mem_region_stats_t g;
    if(noxtls_mem_region_get_stats(noxtls_mem_global_region(), &g) != NOXTLS_RETURN_SUCCESS) {
        return 0U;
    }
    return g.live_bytes;
#else
    return lb_alloc_live_bytes();
#endif
}

static int mc_load_rsa(rsa_key_t *key, const uint8_t *der, uint32_t len)
{
    x509_private_key_t pk;
    (void)noxtls_x509_private_key_init(&pk);
    LB_CHECK_OK(noxtls_x509_private_key_parse_der(&pk, der, len));
    LB_CHECK_OK(noxtls_x509_private_key_to_rsa_key(&pk, key));
    (void)noxtls_x509_private_key_free(&pk);
    return 0;
}

static int mc_load_ecc(ecc_key_t *key, const uint8_t *der, uint32_t len)
{
    x509_private_key_t pk;
    (void)noxtls_x509_private_key_init(&pk);
    LB_CHECK_OK(noxtls_x509_private_key_parse_der(&pk, der, len));
    LB_CHECK_OK(noxtls_x509_private_key_to_ecc_key(&pk, key));
    (void)noxtls_x509_private_key_free(&pk);
    return 0;
}

/**
 * The leader's anchors (Test Root CA 1 and 3) for its MQTT connection's verify policy,
 * as fleet_mqtt.c sets them (parsed copies in a chain, not the process trust store),
 * the broker's device CA in the process trust store, and the device and broker keys,
 * all in the global arena as an application loads them at start-up.
 */
static int mc_broker_load(int kind)
{
    int rsa = (kind != MC_CHAIN_ECDSA) ? 1 : 0;
    static const uint8_t *const device_ca[1] = { lp_device_ca_cert };
    const uint32_t device_ca_len[1] = { lp_device_ca_cert_len };
    size_t before;

    memset(&s_broker, 0, sizeof(s_broker));
    s_broker.rsa = rsa;
    s_broker.kind = kind;
    s_broker.rsl = (uint16_t)MC_MQTT_RSL;
    before = mc_global_used();
    (void)noxtls_x509_certificate_init(&s_broker.roots[0]);
    (void)noxtls_x509_certificate_init(&s_broker.roots[1]);
    (void)noxtls_x509_certificate_chain_init(&s_broker.anchors);
    LB_CHECK_OK(noxtls_x509_certificate_parse_der(&s_broker.roots[0], lp_root1_cert, lp_root1_cert_len));
    LB_CHECK_OK(noxtls_x509_certificate_parse_der(&s_broker.roots[1], lp_root3_cert, lp_root3_cert_len));
    LB_CHECK_OK(noxtls_x509_certificate_chain_add(&s_broker.anchors, &s_broker.roots[0]));
    LB_CHECK_OK(noxtls_x509_certificate_chain_add(&s_broker.anchors, &s_broker.roots[1]));
    s_broker.policy.trust_anchors = &s_broker.anchors;
    s_broker.policy.required_eku = X509_EKU_SERVER_AUTH;
    s_broker.policy.time_mode = NOXTLS_X509_TIME_SYSTEM;
    LB_CHECK_OK(noxtls_x509_trust_store_set_der_nocopy(device_ca, device_ca_len, 1U));
    s_broker.trust_store_global = mc_global_used() - before;
    before = mc_global_used();
    if(rsa != 0) {
        LB_RUN(mc_load_rsa(&s_broker.device_rsa, lp_device_rsa_key, lp_device_rsa_key_len));
    } else {
        LB_RUN(mc_load_ecc(&s_broker.device_ec, lp_device_ec_key, lp_device_ec_key_len));
    }
    s_broker.device_key_global = mc_global_used() - before;
    if(rsa != 0) {
        LB_RUN(mc_load_rsa(&s_broker.broker_rsa, lp_rsa_leaf_key, lp_rsa_leaf_key_len));
    }
    if(kind == MC_CHAIN_RSA) {
        /* Leaf + intermediate + Test Root CA 1 cross-signed by an untrusted legacy root. */
        s_broker.leaf = lp_rsa_leaf_cert;
        s_broker.leaf_len = lp_rsa_leaf_cert_len;
        s_broker.chain[0] = lp_rsa_int_cert;
        s_broker.chain_lens[0] = lp_rsa_int_cert_len;
        s_broker.chain[1] = lp_root1_cross_cert;
        s_broker.chain_lens[1] = lp_root1_cross_cert_len;
        s_broker.chain_count = 2U;
    } else if(kind == MC_CHAIN_RSA4) {
        /* After a rotation: leaf + new intermediate + bridge CA + cross-signed root. */
        s_broker.leaf = lp_rsa_leaf4_cert;
        s_broker.leaf_len = lp_rsa_leaf4_cert_len;
        s_broker.chain[0] = lp_rsa_int2_cert;
        s_broker.chain_lens[0] = lp_rsa_int2_cert_len;
        s_broker.chain[1] = lp_rsa_bridge_cert;
        s_broker.chain_lens[1] = lp_rsa_bridge_cert_len;
        s_broker.chain[2] = lp_root1_cross_cert;
        s_broker.chain_lens[2] = lp_root1_cross_cert_len;
        s_broker.chain_count = 3U;
    } else if(kind == MC_CHAIN_RSA_MAX) {
        s_broker.leaf = lp_max_leaf_cert;
        s_broker.leaf_len = lp_max_leaf_cert_len;
        s_broker.chain[0] = lp_max_int_cert;
        s_broker.chain_lens[0] = lp_max_int_cert_len;
        s_broker.chain[1] = lp_max_bridge_cert;
        s_broker.chain_lens[1] = lp_max_bridge_cert_len;
        s_broker.chain[2] = lp_max_cross_cert;
        s_broker.chain_lens[2] = lp_max_cross_cert_len;
        s_broker.chain_count = 3U;
    } else {
        LB_RUN(mc_load_ecc(&s_broker.broker_ec, lp_ec_leaf_key, lp_ec_leaf_key_len));
        s_broker.leaf = lp_ec_leaf_cert;
        s_broker.leaf_len = lp_ec_leaf_cert_len;
        s_broker.chain[0] = lp_ec_int_cert;
        s_broker.chain_lens[0] = lp_ec_int_cert_len;
        s_broker.chain_count = 1U;
    }
    s_broker.loaded = 1;
    return 0;
}

static void mc_broker_unload(void)
{
    if(s_broker.loaded != 0) {
        if(s_broker.rsa != 0) {
            (void)noxtls_rsa_key_free(&s_broker.device_rsa);
            (void)noxtls_rsa_key_free(&s_broker.broker_rsa);
        } else {
            (void)noxtls_ecc_key_free(&s_broker.device_ec);
            (void)noxtls_ecc_key_free(&s_broker.broker_ec);
        }
        (void)noxtls_x509_certificate_chain_free(&s_broker.anchors);
        (void)noxtls_x509_certificate_free(&s_broker.roots[0]);
        (void)noxtls_x509_certificate_free(&s_broker.roots[1]);
        s_broker.loaded = 0;
    }
    noxtls_x509_trust_store_clear();
}

static void mc_end_ready(mc_end_t *e, int is_client, int dtls)
{
    e->is_client = is_client;
    e->dtls = dtls;
    e->initialized = 1;
    e->done = 0;
    e->last_rc = NOXTLS_RETURN_WANT_READ;
}

static void mc_link_reset(mc_assoc_t *a, int datagram)
{
    memset(a, 0, sizeof(*a));
    a->link.datagram = datagram;
    a->link.cport.link = &a->link;
    a->link.cport.is_client = 1;
    a->link.sport.link = &a->link;
    a->link.sport.is_client = 0;
}

/**
 * The MQTT association: the leader's TLS 1.3 client (SNI, record_size_limit, the
 * device certificate) and the broker, which presents its chain and requires a client
 * certificate.
 */
static int mc_mqtt_open(void)
{
    mc_assoc_t *a = &s_assoc[MC_L_MQTT];
    tls13_context_t *c = &a->c.ctx;
    tls13_context_t *s = &a->s.ctx;

    mc_link_reset(a, 0);
#if NOXTLS_CONN_MEMORY
    LB_CHECK_OK(noxtls_tls13_context_init_static(c, TLS_ROLE_CLIENT, NOXTLS_CONN_PROFILE_TLS13_CERT,
                                                 s_cert_blocks[0], sizeof(s_cert_blocks[0])));
    mc_end_ready(&a->c, 1, 0);
    LB_CHECK_OK(noxtls_tls13_context_init_static(s, TLS_ROLE_SERVER, NOXTLS_CONN_PROFILE_TLS13_CERT,
                                                 s_cert_blocks[1], sizeof(s_cert_blocks[1])));
#else
    LB_CHECK_OK(noxtls_tls13_context_init(c, TLS_ROLE_CLIENT));
    mc_end_ready(&a->c, 1, 0);
    LB_CHECK_OK(noxtls_tls13_context_init(s, TLS_ROLE_SERVER));
#endif
    mc_end_ready(&a->s, 0, 0);
    LB_CHECK_OK(noxtls_tls_set_io_callbacks(&c->base.base, mc_send, mc_recv, &a->link.cport));
    LB_CHECK_OK(noxtls_tls_set_io_callbacks(&s->base.base, mc_send, mc_recv, &a->link.sport));
    LB_CHECK_OK(noxtls_tls_set_io_mode(&c->base.base, TLS_IO_MODE_NON_BLOCKING));
    LB_CHECK_OK(noxtls_tls_set_io_mode(&s->base.base, TLS_IO_MODE_NON_BLOCKING));

    lb_field_tls13_set_sni(c, LP_BROKER_HOST);
    noxtls_tls13_set_server_verify_policy(c, &s_broker.policy);
    noxtls_tls13_set_record_size_limit(c, s_broker.rsl);
    lb_field_tls13_set_server_cert(s, s_broker.leaf, s_broker.leaf_len);
    noxtls_tls13_set_server_certificate_chain(s, s_broker.chain, s_broker.chain_lens, s_broker.chain_count);
    if(s_broker.rsa != 0) {
        LB_CHECK_OK(noxtls_tls13_set_client_cert(c, lp_device_rsa_cert, lp_device_rsa_cert_len, &s_broker.device_rsa));
        noxtls_tls13_set_server_private_rsa(s, &s_broker.broker_rsa);
    } else {
        LB_CHECK_OK(noxtls_tls13_set_client_cert_ecdsa(c, lp_device_ec_cert, lp_device_ec_cert_len,
                                                       &s_broker.device_ec));
        noxtls_tls13_set_server_private_ecdsa(s, &s_broker.broker_ec);
    }
    noxtls_tls13_require_client_auth(s, 1);
    return 0;
}

/** TLS records queued toward the leader's MQTT client: count, and the largest. */
static void mc_mqtt_records(uint32_t *count, uint32_t *largest)
{
    const mc_queue_t *q = &s_assoc[MC_L_MQTT].link.to_client;
    uint32_t off = q->rd;

    *count = 0U;
    *largest = 0U;
    while((off + 5U) <= q->wr) {
        uint32_t len = ((uint32_t)q->stream[off + 3U] << 8) | (uint32_t)q->stream[off + 4U];
        *count += 1U;
        if(len > *largest) {
            *largest = len;
        }
        off += 5U + len;
    }
}

#if NOXTLS_CONN_MEMORY
static void mc_usage_note(mc_usage_t *u, const mc_end_t *e)
{
    noxtls_connection_memory_stats_t st;
    if(noxtls_connection_memory_get_stats(&e->ctx, &st) == NOXTLS_RETURN_SUCCESS) {
        if(st.hs_arena_peak_at_release > u->hs_peak) {
            u->hs_peak = st.hs_arena_peak_at_release;
        }
        if(st.steady_arena.peak > u->steady_peak) {
            u->steady_peak = st.steady_arena.peak;
        }
        u->hs_budget = st.layout.hs_arena;
        u->steady_budget = st.layout.steady_arena;
        u->block = st.layout.total;
    }
}

static void mc_usage_print(const char *what, const mc_usage_t *u)
{
    printf("%s: block %lu, handshake arena peak %lu of %lu, steady arena peak %lu of %lu\n", what,
           (unsigned long)u->block, (unsigned long)u->hs_peak, (unsigned long)u->hs_budget,
           (unsigned long)u->steady_peak, (unsigned long)u->steady_budget);
}
#endif

/**
 * Long-running KeyUpdate on association @p i: @p rounds updates, alternately requested by
 * each end, each followed by data both ways (@p len bytes). The steady arena is idle
 * after every exchange and its high-water mark stops growing after the first rounds.
 */
static int mc_key_update_run(uint32_t i, uint32_t rounds, uint32_t len)
{
    mc_assoc_t *a = &s_assoc[i];
    uint32_t r;
#if NOXTLS_CONN_MEMORY
    noxtls_connection_memory_stats_t st;
    size_t early_peak[2] = { 0U, 0U };
#endif

    for(r = 0U; r < rounds; r++) {
        mc_end_t *from = ((r & 1U) == 0U) ? &a->c : &a->s;
        LB_CHECK_OK(noxtls_tls13_send_key_update(&from->ctx, 1U));
        if(from->dtls == 0) {
            (void)noxtls_tls_flush(&from->ctx.base.base);
        }
        LB_RUN(mc_exchange(i, 1, len, 1000U + r));
        LB_RUN(mc_exchange(i, 0, len, 2000U + r));
#if NOXTLS_CONN_MEMORY
        LB_CHECK_OK(noxtls_connection_memory_get_stats(&a->c.ctx, &st));
        LB_CHECK_EQ(st.steady_arena.live_blocks, 0U);
        if(r == 7U) {
            early_peak[0] = st.steady_arena.peak;
        }
        if((r > 7U) && (st.steady_arena.peak != early_peak[0])) {
            lb_log("association %u: client steady peak grew to %lu at round %u", (unsigned)i,
                   (unsigned long)st.steady_arena.peak, (unsigned)r);
            return 1;
        }
        LB_CHECK_OK(noxtls_connection_memory_get_stats(&a->s.ctx, &st));
        LB_CHECK_EQ(st.steady_arena.live_blocks, 0U);
        if(r == 7U) {
            early_peak[1] = st.steady_arena.peak;
        }
        if((r > 7U) && (st.steady_arena.peak != early_peak[1])) {
            lb_log("association %u: server steady peak grew to %lu at round %u", (unsigned)i,
                   (unsigned long)st.steady_arena.peak, (unsigned)r);
            return 1;
        }
#endif
    }
    return 0;
}

/**
 * The leader's identity as its MQTT client loads it at start-up (fleet_mqtt.c: the
 * gateway root parsed with a copy into a trust chain for the per-connection verify
 * policy, the P-256 device key parsed and converted), all in the global arena.
 * @return The global arena bytes the identity holds, in @p used.
 */
static int mc_identity_global(size_t *used)
{
    x509_certificate_t root;
    x509_certificate_chain_t trust;
    x509_private_key_t pk;
    ecc_key_t key;
    size_t before = mc_global_used();

    memset(&key, 0, sizeof(key));
    (void)noxtls_x509_certificate_init(&root);
    (void)noxtls_x509_certificate_chain_init(&trust);
    (void)noxtls_x509_private_key_init(&pk);
    LB_CHECK_OK(noxtls_x509_certificate_parse_der(&root, lp_root1_cert, lp_root1_cert_len));
    LB_CHECK_OK(noxtls_x509_certificate_chain_add(&trust, &root));
    LB_CHECK_OK(noxtls_x509_private_key_parse_der(&pk, lp_device_ec_key, lp_device_ec_key_len));
    LB_CHECK_OK(noxtls_x509_private_key_to_ecc_key(&pk, &key));
    *used = mc_global_used() - before;
    (void)noxtls_ecc_key_free(&key);
    (void)noxtls_x509_private_key_free(&pk);
    (void)noxtls_x509_certificate_chain_free(&trust);
    (void)noxtls_x509_certificate_free(&root);
    LB_CHECK_EQ(mc_global_used(), before);
    return 0;
}

/**
 * MQTT to the broker with the broker's chain: handshake (chain verification through the
 * intermediates, the cross-signed root ignored, hostname by wildcard SAN, mutual
 * authentication with the device key), release after the handshake (peer leaf DER kept
 * for channel binding), broker records within the client's record_size_limit
 * (@p rsl: 513, or TLS_MAX_RECORD_SIZE as fleet_mqtt.c sets it), 1,400-byte publishes
 * both ways, and 256 KeyUpdates with data.
 */
static int mc_leader_mqtt(int kind, uint16_t rsl, const char *what)
{
    static const uint32_t mqtt[1] = { MC_L_MQTT };
    mc_assoc_t *a = &s_assoc[MC_L_MQTT];
    size_t base = lb_alloc_live_bytes();
    size_t heap_before;
    uint32_t records = 0U;
    uint32_t largest = 0U;
    uint32_t content = (uint32_t)rsl - 1U;
    uint8_t cb[64];
    uint32_t cb_len = sizeof(cb);
#if NOXTLS_CONN_MEMORY
    mc_usage_t client_use;
    mc_usage_t broker_use;
    memset(&client_use, 0, sizeof(client_use));
    memset(&broker_use, 0, sizeof(broker_use));
#endif

    LB_RUN(mc_broker_load(kind));
    LB_RUN(mc_identity_global(&s_broker.identity_global));
    s_broker.rsl = rsl;
    LB_RUN(mc_mqtt_open());
    heap_before = MC_HEAP_CALLS();
    LB_RUN(mc_drive(mqtt, 1U, 0, 0U, 0U));
    LB_CHECK_EQ(a->c.ctx.base.base.state, TLS_STATE_CONNECTED);
    LB_CHECK_EQ(a->s.ctx.base.base.state, TLS_STATE_CONNECTED);
    /* The broker's leaf stays available (tls-server-end-point channel binding). */
    LB_CHECK(a->c.ctx.server_cert != NULL);
    LB_CHECK_EQ(a->c.ctx.server_cert_len, s_broker.leaf_len);
    LB_CHECK_OK(noxtls_tls13_get_channel_binding(&a->c.ctx, NOXTLS_TLS_CHANNEL_BINDING_TLS_SERVER_END_POINT,
                                                 cb, &cb_len));
#if NOXTLS_CONN_MEMORY
    LB_RUN(mc_check_released(&a->c));
    mc_usage_note(&client_use, &a->c);
    mc_usage_note(&broker_use, &a->s);
#endif

    /* A NoxLink frame published to the leader: broker records within the limit. */
    lb_fill_pattern(s_buf, MC_MQTT_FRAME, 41U);
    LB_CHECK_OK(noxtls_tls13_send(&a->s.ctx, s_buf, MC_MQTT_FRAME));
    (void)noxtls_tls_flush(&a->s.ctx.base.base);
    mc_mqtt_records(&records, &largest);
    LB_CHECK(records >= ((MC_MQTT_FRAME + content - 1U) / content));
    LB_CHECK(largest <= ((uint32_t)rsl + 16U));   /* inner plaintext + AEAD tag */
    LB_RUN(mc_recv_exact(&a->c, s_rx, MC_MQTT_FRAME));
    LB_CHECK(memcmp(s_rx, s_buf, MC_MQTT_FRAME) == 0);
    LB_RUN(mc_exchange(MC_L_MQTT, 1, MC_MQTT_FRAME, 42U));
    LB_RUN(mc_key_update_run(MC_L_MQTT, 256U, MC_MQTT_FRAME));
#if NOXTLS_CONN_MEMORY
    mc_usage_note(&client_use, &a->c);
    mc_usage_note(&broker_use, &a->s);
    LB_RUN(mc_check_released(&a->c));
    mc_usage_print(what, &client_use);
    mc_usage_print("  broker (test peer)", &broker_use);
    printf("anchors (2 roots, verify policy) and device CA: %lu, device key: %lu, leader identity (root copy, chain, P-256 key): "
           "%lu bytes of global arena\n", (unsigned long)s_broker.trust_store_global,
           (unsigned long)s_broker.device_key_global, (unsigned long)s_broker.identity_global);
    LB_CHECK(s_broker.device_key_global <= (size_t)NOXTLS_STATIC_GLOBAL_EXTRA);
    LB_CHECK(s_broker.identity_global <= (size_t)NOXTLS_STATIC_GLOBAL_EXTRA);
#endif
    LB_CHECK_EQ(MC_HEAP_CALLS() - heap_before, 0U);
    (void)noxtls_tls13_close(&a->c.ctx);
    (void)noxtls_tls_flush(&a->c.ctx.base.base);
    mc_assoc_free(MC_L_MQTT);
#if NOXTLS_CONN_MEMORY
    LB_CHECK(mc_all_zero(s_cert_blocks[0], sizeof(s_cert_blocks[0]) / 8U) != 0);
#endif
    mc_broker_unload();
    return lb_expect_no_leak(base, "leader MQTT");
}

static int t_leader_mqtt_rsa(void)
{
    return mc_leader_mqtt(MC_CHAIN_RSA, (uint16_t)MC_MQTT_RSL,
                          "MQTT client, RSA-2048 chain (3 certificates), mutual TLS, record_size_limit 513");
}

static int t_leader_mqtt_ecdsa(void)
{
    return mc_leader_mqtt(MC_CHAIN_ECDSA, (uint16_t)TLS_MAX_RECORD_SIZE,
                          "MQTT client, ECDSA P-256 chain (2 certificates), mutual TLS, full records");
}

static int t_leader_mqtt_rsa_max_chain(void)
{
    return mc_leader_mqtt(MC_CHAIN_RSA_MAX, (uint16_t)TLS_MAX_RECORD_SIZE,
                          "MQTT client, RSA-2048 chain (4 x 2,040-byte certificates), mutual TLS, full records");
}

static int t_leader_mqtt_rsa_rotated(void)
{
    return mc_leader_mqtt(MC_CHAIN_RSA4, (uint16_t)TLS_MAX_RECORD_SIZE,
                          "MQTT client, RSA-2048 chain (4 certificates), mutual TLS, full records");
}

/* ---- NoxLink servers created when their first datagram arrives -------------- */

/** Association @p i as a client using association @p keys's identity and key. */
static int mc_open_client_as(uint32_t i, uint32_t keys)
{
    mc_assoc_t *a = &s_assoc[i];
#if NOXTLS_CONN_MEMORY
    void *mem = s_blocks[i][0];
    size_t mem_len = sizeof(s_blocks[i][0]);
#else
    void *mem = NULL;
    size_t mem_len = 0U;
#endif
    mc_link_reset(a, 1);
    mc_assoc_keys(a, keys);
    LB_RUN(mc_end_init(&a->c, 1, 1, mem, mem_len));
    LB_RUN(mc_end_config(a, &a->c));
    return 0;
}

/** The leader's server context of association @p i: steady block @p steady, shared handshake block. */
static noxtls_return_t mc_lazy_server_init(uint32_t i, uint32_t steady)
{
#if NOXTLS_CONN_MEMORY
    return mc_split_server(i, steady, s_shared_hs, sizeof(s_shared_hs));
#else
    mc_assoc_t *a = &s_assoc[i];
    (void)steady;
    if((mc_end_init(&a->s, 0, 1, NULL, 0U) != 0) || (mc_end_config(a, &a->s) != 0)) {
        return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
#endif
}

/**
 * The leader's turn for a NoxLink association: with no server context yet, a queued
 * datagram creates one; while another server holds the handshake block the init is
 * refused and the datagram dropped (the peer retransmits its ClientHello).
 */
static int mc_lazy_server_turn(uint32_t i, uint32_t steady, uint32_t *refused)
{
    mc_assoc_t *a = &s_assoc[i];
    mc_queue_t *q = &a->link.to_server;

    if(a->s.initialized == 0) {
        noxtls_return_t rc;
        if(q->count == 0U) {
            return 0;
        }
        rc = mc_lazy_server_init(i, steady);
        if(rc == NOXTLS_RETURN_NOT_ENOUGH_MEMORY) {
            q->head = (q->head + 1U) % MC_SLOTS;
            q->count--;
            *refused += 1U;
            return 0;
        }
        LB_CHECK_OK(rc);
    }
    mc_step(&a->s);
    return 0;
}

typedef struct
{
    uint32_t nox[3];        /* NoxLink associations being opened */
    uint32_t nox_steady[3]; /* their steady blocks */
    uint32_t n_nox;
    uint32_t nodes[MC_L_NODES];
    uint32_t n_nodes;
    int mqtt;
    uint32_t refused;
} mc_leader_plan_t;

static int mc_end_failed(const mc_end_t *e)
{
    return ((e->initialized != 0) && (e->done == 0) && (mc_is_progress(e->last_rc) == 0)) ? 1 : 0;
}

/** The owner loop of the leader: one turn per endpoint per round, until all are connected. */
static int mc_leader_drive(mc_leader_plan_t *p)
{
    uint32_t round;
    uint32_t k;

    for(round = 0U; round < 8000U; round++) {
        int all = 1;
        for(k = 0U; k < p->n_nox; k++) {
            mc_assoc_t *a = &s_assoc[p->nox[k]];
            mc_step(&a->c);
            LB_RUN(mc_lazy_server_turn(p->nox[k], p->nox_steady[k], &p->refused));
            all &= mc_assoc_done(a);
            if((mc_end_failed(&a->c) != 0) || (mc_end_failed(&a->s) != 0)) {
                lb_log("NoxLink association %u failed: client rc=%d server rc=%d", (unsigned)p->nox[k],
                       (int)a->c.last_rc, (int)a->s.last_rc);
                return 1;
            }
        }
        for(k = 0U; k < p->n_nodes; k++) {
            mc_assoc_t *a = &s_assoc[p->nodes[k]];
            mc_step(&a->c);
            mc_step(&a->s);
            all &= mc_assoc_done(a);
            if((mc_end_failed(&a->c) != 0) || (mc_end_failed(&a->s) != 0)) {
                lb_log("node association %u failed: client rc=%d server rc=%d", (unsigned)p->nodes[k],
                       (int)a->c.last_rc, (int)a->s.last_rc);
                return 1;
            }
        }
        if(p->mqtt != 0) {
            mc_assoc_t *a = &s_assoc[MC_L_MQTT];
            mc_step(&a->c);
            mc_step(&a->s);
            all &= mc_assoc_done(a);
            if((mc_end_failed(&a->c) != 0) || (mc_end_failed(&a->s) != 0)) {
                lb_log("MQTT association failed: client rc=%d server rc=%d", (int)a->c.last_rc, (int)a->s.last_rc);
                return 1;
            }
        }
        if(all != 0) {
            return 0;
        }
        s_now_ms += 25U;
    }
    lb_log("leader handshakes did not complete");
    return 1;
}

/** Turns of the owner loop on association @p i alone (reads on both ends), no data. */
static int mc_idle_turns(uint32_t i, uint32_t turns, uint32_t step_ms)
{
    uint32_t t;
    for(t = 0U; t < turns; t++) {
        uint32_t n = (uint32_t)sizeof(s_rx);
        s_now_ms += step_ms;
        LB_CHECK_EQ(noxtls_tls13_recv(&s_assoc[i].c.ctx, s_rx, &n), NOXTLS_RETURN_TIMEOUT);
        n = (uint32_t)sizeof(s_rx);
        LB_CHECK_EQ(noxtls_tls13_recv(&s_assoc[i].s.ctx, s_rx, &n), NOXTLS_RETURN_TIMEOUT);
    }
    return 0;
}

/**
 * The leader's whole set of connections: the NoxLink fleet and local servers, created
 * when their peers' ClientHellos arrive and taking turns with one handshake block
 * (refused ClientHellos are dropped and retransmitted), next to concurrent node
 * associations (one losing the node's first flight, one with a duplicated ClientHello)
 * and, when the build holds both ends of eight associations, the MQTT connection.
 * Then a re-handshake of the fleet peer: the replacement server takes the handshake
 * block while the old fleet association carries data; the ACK of the replacement
 * client's Finished is lost, the block passes to another re-handshake (local) and is
 * wiped, and the replacement server, already released, still answers the retransmitted
 * Finished (its epoch-2 read key is kept in its steady part). Every association then
 * carries 1,399-byte NoxLink frames and runs KeyUpdates (600 on the fleet association).
 */
static int t_leader_topology(void)
{
    mc_leader_plan_t plan;
    size_t base = lb_alloc_live_bytes();
    size_t heap_before;
    uint32_t k;
    uint32_t n_live;
    uint32_t n_nodes;
    uint32_t before_tx;
    uint32_t live[MC_ASSOC_MAX];
#if NOXTLS_CONN_MEMORY
    mc_usage_t server_use;
    mc_usage_t node_use;
    memset(&server_use, 0, sizeof(server_use));
    memset(&node_use, 0, sizeof(node_use));
#endif

    /* Three NoxLink servers, one node association at least. */
    if(MC_FIT < 4U) {
        return LB_SKIP;
    }
    memset(&plan, 0, sizeof(plan));
    plan.mqtt = (MC_FIT >= 8U) ? 1 : 0;
    plan.n_nodes = MC_FIT - 3U - ((plan.mqtt != 0) ? 1U : 0U);
    if(plan.n_nodes > MC_L_NODES) {
        plan.n_nodes = MC_L_NODES;
    }
    n_nodes = plan.n_nodes;
    if(plan.mqtt != 0) {
        LB_RUN(mc_broker_load(0));
        LB_RUN(mc_mqtt_open());
    }
    heap_before = MC_HEAP_CALLS();

    /* Phase 1: fleet and local peers start at once; the nodes connect concurrently. */
    LB_RUN(mc_open_client_as(MC_L_FLEET, MC_L_FLEET));
    LB_RUN(mc_open_client_as(MC_L_LOCAL, MC_L_LOCAL));
    plan.nox[0] = MC_L_FLEET;
    plan.nox_steady[0] = 0U;
    plan.nox[1] = MC_L_LOCAL;
    plan.nox_steady[1] = 1U;
    plan.n_nox = 2U;
    for(k = 0U; k < plan.n_nodes; k++) {
        plan.nodes[k] = MC_L_NODE0 + k;
        LB_RUN(mc_assoc_open(MC_L_NODE0 + k, 1, 1));
    }
    s_assoc[MC_L_NODE0].link.to_client.drop_next = 1U;
    if(plan.n_nodes > 1U) {
        s_assoc[MC_L_NODE0 + 1U].link.to_server.dup_next = 1U;
    }
    LB_RUN(mc_leader_drive(&plan));
#if NOXTLS_CONN_MEMORY
    /* The second server could only start once the first had released the block. */
    LB_CHECK(plan.refused > 0U);
#endif
    LB_CHECK(s_assoc[MC_L_NODE0].link.to_client.datagrams > 1U);
    for(k = 0U; k < plan.n_nodes; k++) {
        LB_RUN(mc_exchange(plan.nodes[k], 1, 300U + k, 10U + k));
        LB_RUN(mc_exchange(plan.nodes[k], 0, 500U + k, 20U + k));
#if NOXTLS_CONN_MEMORY
        LB_RUN(mc_check_released(&s_assoc[plan.nodes[k]].c));
        mc_usage_note(&node_use, &s_assoc[plan.nodes[k]].c);
#endif
    }
    LB_RUN(mc_exchange(MC_L_FLEET, 0, MC_RSL - 1U, 30U));
    LB_RUN(mc_exchange(MC_L_LOCAL, 1, MC_RSL - 1U, 31U));
    if(plan.mqtt != 0) {
        LB_RUN(mc_exchange(MC_L_MQTT, 1, MC_MQTT_FRAME, 32U));
        LB_RUN(mc_exchange(MC_L_MQTT, 0, MC_MQTT_FRAME, 33U));
    }

    /* Phase 2: the fleet peer re-handshakes; the old fleet association keeps working. */
    LB_RUN(mc_open_client_as(MC_L_REPL, MC_L_FLEET));
    plan.nox[0] = MC_L_REPL;
    plan.nox_steady[0] = 2U;
    plan.n_nox = 1U;
    plan.n_nodes = 0U;
    plan.mqtt = 0;
    for(k = 0U; k < 3U; k++) {
        mc_step(&s_assoc[MC_L_REPL].c);
        LB_RUN(mc_lazy_server_turn(MC_L_REPL, 2U, &plan.refused));
        LB_RUN(mc_exchange(MC_L_FLEET, 0, 700U + k, 40U + k));
    }
    LB_RUN(mc_leader_drive(&plan));
    /* The ACK of the replacement client's Finished is lost. */
    s_assoc[MC_L_REPL].link.to_client.count = 0U;
    s_assoc[MC_L_REPL].link.to_client.head = 0U;
#if NOXTLS_CONN_MEMORY
    LB_CHECK_EQ(mc_released(&s_assoc[MC_L_REPL].s), 1);
    LB_CHECK_EQ(mc_released(&s_assoc[MC_L_REPL].c), 0);
#endif
    /* The old fleet association goes; its steady block hosts a re-handshake of local. */
    (void)noxtls_tls13_close(&s_assoc[MC_L_FLEET].s.ctx);
    mc_assoc_free(MC_L_FLEET);
#if NOXTLS_CONN_MEMORY
    LB_CHECK(mc_all_zero(s_steady[0], sizeof(s_steady[0]) / 8U) != 0);
#endif
    LB_RUN(mc_open_client_as(MC_L_FLEET, MC_L_LOCAL));
    plan.nox[0] = MC_L_FLEET;
    plan.nox_steady[0] = 0U;
    LB_RUN(mc_leader_drive(&plan));
#if NOXTLS_CONN_MEMORY
    LB_RUN(mc_check_released(&s_assoc[MC_L_FLEET].s));
    LB_CHECK(mc_all_zero(s_shared_hs, sizeof(s_shared_hs) / 8U) != 0);
#endif
    /* The replacement client retransmits its Finished; the released server ACKs it. */
    before_tx = s_assoc[MC_L_REPL].link.to_server.datagrams;
    LB_RUN(mc_idle_turns(MC_L_REPL, 40U, 250U));
    LB_CHECK(s_assoc[MC_L_REPL].link.to_server.datagrams > before_tx);
#if NOXTLS_CONN_MEMORY
    LB_CHECK_EQ(mc_released(&s_assoc[MC_L_REPL].c), 1);
#endif

    /* Phase 3: data and KeyUpdates on every live association. */
    n_live = 0U;
    live[n_live++] = MC_L_REPL;
    live[n_live++] = MC_L_LOCAL;
    live[n_live++] = MC_L_FLEET;   /* now the local re-handshake */
    for(k = 0U; k < n_nodes; k++) {
        live[n_live++] = MC_L_NODE0 + k;
    }
    if(MC_FIT >= 8U) {
        live[n_live++] = MC_L_MQTT;
    }
    for(k = 0U; k < n_live; k++) {
        uint32_t len = (live[k] == MC_L_MQTT) ? 512U : (MC_RSL - 1U);
        LB_RUN(mc_key_update_run(live[k], 24U, len));
    }
    LB_RUN(mc_key_update_run(MC_L_REPL, 600U, 64U));
#if NOXTLS_CONN_MEMORY
    for(k = 0U; k < n_live; k++) {
        mc_assoc_t *a = &s_assoc[live[k]];
        LB_RUN(mc_check_released(&a->c));
        LB_RUN(mc_check_released(&a->s));
        if(live[k] < MC_L_NODE0) {
            mc_usage_note(&server_use, &a->s);
        } else if(live[k] != MC_L_MQTT) {
            mc_usage_note(&node_use, &a->c);
        } else {
            /* the MQTT client is measured by mc_leader_mqtt_* */
        }
    }
    mc_usage_print("NoxLink DTLS 1.3 PSK server (split, shared handshake block)", &server_use);
    mc_usage_print("node DTLS 1.3 PSK client", &node_use);
    printf("leader connections live at once: %u (MQTT %s), refused ClientHellos while the block was held: %u\n",
           (unsigned)n_live, (MC_FIT >= 8U) ? "included" : "not included: 8 connections hold both ends of 4",
           (unsigned)plan.refused);
#endif
    LB_CHECK_EQ(MC_HEAP_CALLS() - heap_before, 0U);
    for(k = 0U; k < MC_ASSOC_MAX; k++) {
        if(s_assoc[k].c.initialized != 0) {
            (void)noxtls_tls13_close(&s_assoc[k].c.ctx);
        }
        mc_assoc_free(k);
    }
#if NOXTLS_CONN_MEMORY
    for(k = 0U; k < 3U; k++) {
        LB_CHECK(mc_all_zero(s_steady[k], sizeof(s_steady[k]) / 8U) != 0);
    }
    LB_CHECK(mc_all_zero(s_shared_hs, sizeof(s_shared_hs) / 8U) != 0);
#endif
    if(MC_FIT >= 8U) {
        mc_broker_unload();
    }
    return lb_expect_no_leak(base, "leader topology");
}

/* ---- Leader budgets: peaks and exhaustion ---------------------------------- */

#if NOXTLS_CONN_MEMORY
#define MC_GUARD_WORDS 8U
#define MC_GUARD 0xC3A5C3A5C3A5C3A5ULL
/* One DTLS 1.3 PSK block with guard words on both sides. */
static uint64_t s_guarded[MC_GUARD_WORDS + (MC_BLOCK_BYTES / 8U) + MC_GUARD_WORDS];

static void mc_guard_set(void)
{
    uint32_t k;
    for(k = 0U; k < MC_GUARD_WORDS; k++) {
        s_guarded[k] = MC_GUARD;
        s_guarded[MC_GUARD_WORDS + (MC_BLOCK_BYTES / 8U) + k] = MC_GUARD;
    }
}

static int mc_guard_intact(void)
{
    uint32_t k;
    for(k = 0U; k < MC_GUARD_WORDS; k++) {
        LB_CHECK(s_guarded[k] == MC_GUARD);
        LB_CHECK(s_guarded[MC_GUARD_WORDS + (MC_BLOCK_BYTES / 8U) + k] == MC_GUARD);
    }
    return 0;
}

/**
 * Take all but @p leave bytes of the arena that @p e allocates from now (the handshake
 * arena before the release, the steady arena after it). Returns the filler, which the
 * caller frees with mc_unfill() while the context lives.
 */
static void *mc_fill(mc_end_t *e, size_t leave)
{
    noxtls_connection_memory_stats_t st;
    noxtls_mem_scope_t *prev;
    const noxtls_mem_region_stats_t *r;
    void *p = NULL;
    size_t free_bytes;

    if(noxtls_connection_memory_get_stats(&e->ctx, &st) != NOXTLS_RETURN_SUCCESS) {
        return NULL;
    }
    r = (st.released != 0U) ? &st.steady_arena : &st.hs_arena;
    free_bytes = r->capacity - r->used;
    if(free_bytes <= (leave + 32U)) {
        return NULL;
    }
    prev = noxtls_conn_mem_enter(&e->ctx.base.base);
    p = NOXTLS_MALLOC(free_bytes - leave - 16U);
    noxtls_conn_mem_leave(&e->ctx, prev);
    return p;
}

static void mc_unfill(mc_end_t *e, void *p)
{
    noxtls_mem_scope_t *prev = noxtls_conn_mem_enter(&e->ctx.base.base);
    noxtls_free(p);
    noxtls_conn_mem_leave(&e->ctx, prev);
}

/** The node association of the budget cases: its client in the guarded block. */
static int mc_open_guarded(uint32_t i)
{
    mc_assoc_t *a = &s_assoc[i];
    mc_guard_set();
    mc_link_reset(a, 1);
    mc_assoc_keys(a, i);
    LB_RUN(mc_end_init(&a->c, 1, 1, &s_guarded[MC_GUARD_WORDS], MC_BLOCK_BYTES));
    LB_RUN(mc_end_config(a, &a->c));
    LB_RUN(mc_end_init(&a->s, 0, 1, s_blocks[i][1], sizeof(s_blocks[i][1])));
    LB_RUN(mc_end_config(a, &a->s));
    return 0;
}

/** Drive one association until it completes or one end fails (no waiting: owner turns). */
static void mc_drive_until_end(uint32_t i)
{
    mc_assoc_t *a = &s_assoc[i];
    uint32_t round;
    for(round = 0U; round < 2000U; round++) {
        mc_step(&a->c);
        mc_step(&a->s);
        if((mc_assoc_done(a) != 0) || (mc_end_failed(&a->c) != 0) || (mc_end_failed(&a->s) != 0)) {
            return;
        }
        s_now_ms += 25U;
    }
}
#endif

/**
 * Every leader connection type at its peak and beyond its budget:
 * - a node client reads three 1,399-byte records in 100-byte pieces (each record's rest
 *   is held across calls while the next datagrams wait), the steady arena's worst use;
 * - a node client whose handshake arena is taken but for 4 KB fails its handshake with
 *   NOXTLS_RETURN_NOT_ENOUGH_MEMORY, the same way twice, the region named in the last
 *   error, nothing written outside its block, and its block wiped by the free;
 * - the same client after its release, with its steady arena taken but for 256 bytes,
 *   refuses a 1,399-byte record with NOXTLS_RETURN_NOT_ENOUGH_MEMORY, nothing outside
 *   its block changed;
 * - the MQTT client with its handshake arena taken but for 12 KB fails the RSA chain's
 *   handshake with NOXTLS_RETURN_NOT_ENOUGH_MEMORY.
 * The handshake peaks of the NoxLink servers, the node clients and the MQTT client are
 * those of mc_leader_topology, dtls13_recovery_ut and mc_leader_mqtt_rsa_max_chain.
 */
static int t_leader_budget_limits(void)
{
#if !NOXTLS_CONN_MEMORY
    return LB_SKIP;
#else
    static const uint32_t node[1] = { MC_L_NODE0 };
    mc_assoc_t *a = &s_assoc[MC_L_NODE0];
    noxtls_connection_memory_stats_t st;
    noxtls_mem_error_info_t err;
    noxtls_return_t first_rc = NOXTLS_RETURN_SUCCESS;
    size_t base = lb_alloc_live_bytes();
    void *fill;
    uint32_t got;
    uint32_t pass;
    uint32_t k;

    /* Short reads of full records: the steady arena's peak. */
    LB_RUN(mc_open_guarded(MC_L_NODE0));
    LB_RUN(mc_drive(node, 1U, 0, 0U, 0U));
    LB_RUN(mc_exchange(MC_L_NODE0, 1, 16U, 600U));
    for(k = 0U; k < 3U; k++) {
        lb_fill_pattern(&s_buf[k * (MC_RSL - 1U)], MC_RSL - 1U, 610U + k);
        LB_CHECK_OK(noxtls_tls13_send(&a->s.ctx, &s_buf[k * (MC_RSL - 1U)], MC_RSL - 1U));
    }
    got = 0U;
    for(k = 0U; (k < 400U) && (got < (3U * (MC_RSL - 1U))); k++) {
        uint32_t n = 100U;
        noxtls_return_t rc = noxtls_tls13_recv(&a->c.ctx, &s_rx[got], &n);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            got += n;
        } else {
            LB_CHECK(mc_is_progress(rc) != 0);
        }
    }
    LB_CHECK_EQ(got, 3U * (MC_RSL - 1U));
    LB_CHECK(memcmp(s_rx, s_buf, got) == 0);
    LB_CHECK_OK(noxtls_connection_memory_get_stats(&a->c.ctx, &st));
    printf("node client, three 1,399-byte records read in 100-byte pieces: steady arena peak %lu of %lu\n",
           (unsigned long)st.steady_arena.peak, (unsigned long)st.layout.steady_arena);
    LB_CHECK(st.steady_arena.peak <= st.layout.steady_arena);

    /* Steady arena taken but for 256 bytes: a full record is refused, nothing else moves. */
    fill = mc_fill(&a->c, 256U);
    LB_CHECK(fill != NULL);
    lb_fill_pattern(s_buf, MC_RSL - 1U, 620U);
    LB_CHECK_OK(noxtls_tls13_send(&a->s.ctx, s_buf, MC_RSL - 1U));
    {
        uint32_t n = (uint32_t)sizeof(s_rx);
        noxtls_mem_clear_last_error();
        LB_CHECK_EQ(noxtls_tls13_recv(&a->c.ctx, s_rx, &n), NOXTLS_RETURN_NOT_ENOUGH_MEMORY);
        LB_CHECK_OK(noxtls_mem_get_last_error(&err));
        LB_CHECK_EQ(err.reason, NOXTLS_MEM_FAILURE_POOL_EXHAUSTED);
        LB_CHECK(err.region_name != NULL);
    }
    LB_RUN(mc_guard_intact());
    mc_unfill(&a->c, fill);
    mc_assoc_free(MC_L_NODE0);
    LB_RUN(mc_guard_intact());
    LB_CHECK(mc_all_zero(&s_guarded[MC_GUARD_WORDS], MC_BLOCK_BYTES / 8U) != 0);

    /* Handshake arena taken but for 4 KB: the handshake fails the same way twice. */
    for(pass = 0U; pass < 2U; pass++) {
        LB_RUN(mc_open_guarded(MC_L_NODE0));
        fill = mc_fill(&a->c, 4096U);
        LB_CHECK(fill != NULL);
        noxtls_mem_clear_last_error();
        mc_drive_until_end(MC_L_NODE0);
        LB_CHECK(a->c.done == 0);
        LB_CHECK_EQ(a->c.last_rc, NOXTLS_RETURN_NOT_ENOUGH_MEMORY);
        LB_CHECK_OK(noxtls_mem_get_last_error(&err));
        LB_CHECK_EQ(err.reason, NOXTLS_MEM_FAILURE_POOL_EXHAUSTED);
        LB_CHECK(err.region_name != NULL);
        if(pass == 0U) {
            first_rc = a->c.last_rc;
        } else {
            LB_CHECK_EQ(a->c.last_rc, first_rc);
        }
        LB_RUN(mc_guard_intact());
        mc_unfill(&a->c, fill);
        mc_assoc_free(MC_L_NODE0);
        LB_RUN(mc_guard_intact());
        LB_CHECK(mc_all_zero(&s_guarded[MC_GUARD_WORDS], MC_BLOCK_BYTES / 8U) != 0);
    }

    /* MQTT client: handshake arena taken but for 12 KB, the RSA chain does not fit. */
    LB_RUN(mc_broker_load(MC_CHAIN_RSA));
    LB_RUN(mc_mqtt_open());
    fill = mc_fill(&s_assoc[MC_L_MQTT].c, 12U * 1024U);
    LB_CHECK(fill != NULL);
    noxtls_mem_clear_last_error();
    mc_drive_until_end(MC_L_MQTT);
    LB_CHECK(s_assoc[MC_L_MQTT].c.done == 0);
    LB_CHECK_OK(noxtls_mem_get_last_error(&err));
    LB_CHECK_EQ(err.reason, NOXTLS_MEM_FAILURE_POOL_EXHAUSTED);
    LB_CHECK(err.region_name != NULL);
    LB_CHECK_EQ(s_assoc[MC_L_MQTT].c.last_rc, NOXTLS_RETURN_NOT_ENOUGH_MEMORY);
    mc_unfill(&s_assoc[MC_L_MQTT].c, fill);
    mc_assoc_free(MC_L_MQTT);
    LB_CHECK(mc_all_zero(s_cert_blocks[0], sizeof(s_cert_blocks[0]) / 8U) != 0);
    mc_broker_unload();
    return lb_expect_no_leak(base, "leader budget limits");
#endif
}

static const lb_test_case_t k_cases[] = {
    { "mc_concurrent_server_client", t_concurrent_server_client },
    { "mc_cross_identity_refused", t_cross_identity_refused },
    { "mc_interleaved_handshakes", t_interleaved_handshakes },
    { "mc_release_per_context", t_release_per_context },
    { "mc_shared_handshake_region", t_shared_handshake_region },
    { "mc_foreign_scope_isolation", t_foreign_scope_isolation },
    { "mc_many_psk_clients", t_many_psk_clients },
    { "mc_noxlink_frame_records", t_noxlink_frame_records },
    { "mc_leader_mqtt_rsa", t_leader_mqtt_rsa },
    { "mc_leader_mqtt_ecdsa", t_leader_mqtt_ecdsa },
    { "mc_leader_mqtt_rsa_rotated", t_leader_mqtt_rsa_rotated },
    { "mc_leader_mqtt_rsa_max_chain", t_leader_mqtt_rsa_max_chain },
    { "mc_leader_topology", t_leader_topology },
    { "mc_leader_budget_limits", t_leader_budget_limits },
};

int main(int argc, char **argv)
{
    return lb_main(argc, argv, "multi_context", k_cases, sizeof(k_cases) / sizeof(k_cases[0]));
}
