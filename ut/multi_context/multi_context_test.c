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
            if(q->rd == q->wr) {
                q->rd = 0U;
                q->wr = 0U;
            }
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
static uint8_t s_buf[4096];
static uint8_t s_rx[4096];

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
 */
static int t_concurrent_server_client(void)
{
    static const uint32_t order[5] = { 0U, 1U, 2U, 3U, 4U };
    size_t base = lb_alloc_live_bytes();
    size_t heap_before;
    uint32_t i;

    for(i = 0U; i < 5U; i++) {
        LB_RUN(mc_assoc_open(i, (i < 4U) ? 1 : 0, 1));
    }
    heap_before = MC_HEAP_CALLS();
    LB_RUN(mc_drive(order, 5U, 0, 0U, 0U));
    LB_RUN(mc_exchange_all(order, 5U, 1U));
    /* KeyUpdate on every association, interleaved, then data again. */
    for(i = 0U; i < 5U; i++) {
        LB_CHECK_OK(noxtls_tls13_send_key_update(&s_assoc[i].s.ctx, 1U));
        if(i == 4U) {
            (void)noxtls_tls_flush(&s_assoc[i].s.ctx.base.base);
        }
    }
    LB_RUN(mc_exchange_all(order, 5U, 50U));
    /* A full NoxLink frame budget in one record on the fleet association. */
    LB_RUN(mc_exchange(0U, 0, MC_RSL - 1U, 77U));
#if NOXTLS_CONN_MEMORY
    for(i = 0U; i < 5U; i++) {
        LB_RUN(mc_check_released(&s_assoc[i].c));
        LB_RUN(mc_check_released(&s_assoc[i].s));
    }
#endif
    LB_CHECK_EQ(MC_HEAP_CALLS() - heap_before, 0U);
    for(i = 0U; i < 5U; i++) {
        (void)noxtls_tls13_close(&s_assoc[i].c.ctx);
        mc_assoc_free(i);
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
 * are live.
 */
static int t_many_psk_clients(void)
{
    static const uint32_t all[MC_ASSOC_MAX] = { 7U, 1U, 5U, 3U, 0U, 6U, 2U, 4U };
    static const uint32_t close_order[4] = { 2U, 5U, 0U, 7U };
    size_t base = lb_alloc_live_bytes();
    uint32_t i;
    uint32_t k;

    for(i = 0U; i < MC_ASSOC_MAX; i++) {
        LB_RUN(mc_assoc_open(i, 1, 1));
    }
    LB_RUN(mc_drive(all, MC_ASSOC_MAX, 1, 4U, 3U));
    LB_RUN(mc_exchange_all(all, MC_ASSOC_MAX, 200U));
    for(k = 0U; k < 4U; k++) {
        uint32_t gone = close_order[k];
        (void)noxtls_tls13_close(&s_assoc[gone].c.ctx);
        mc_assoc_free(gone);
        for(i = 0U; i < MC_ASSOC_MAX; i++) {
            if(s_assoc[i].c.initialized != 0) {
                LB_RUN(mc_exchange(i, 1, 120U + i, 300U + (k * 10U) + i));
            }
        }
    }
    /* Reopen the closed slots (new handshakes next to the live associations). */
    LB_RUN(mc_assoc_open(2U, 1, 1));
    LB_RUN(mc_assoc_open(5U, 1, 1));
    {
        static const uint32_t reopened[2] = { 5U, 2U };
        LB_RUN(mc_drive(reopened, 2U, 1, 0U, 0U));
    }
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

static const lb_test_case_t k_cases[] = {
    { "mc_concurrent_server_client", t_concurrent_server_client },
    { "mc_cross_identity_refused", t_cross_identity_refused },
    { "mc_interleaved_handshakes", t_interleaved_handshakes },
    { "mc_release_per_context", t_release_per_context },
    { "mc_shared_handshake_region", t_shared_handshake_region },
    { "mc_foreign_scope_isolation", t_foreign_scope_isolation },
    { "mc_many_psk_clients", t_many_psk_clients },
    { "mc_noxlink_frame_records", t_noxlink_frame_records },
};

int main(int argc, char **argv)
{
    return lb_main(argc, argv, "multi_context", k_cases, sizeof(k_cases) / sizeof(k_cases[0]));
}
