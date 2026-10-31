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
* File:    lb_fixture.c
* Summary: In-memory client/server fixture for end-to-end TLS regression tests
*****************************************************************************/
/** @file lb_fixture.c
 * @brief See lb_fixture.h.
 */
#include "lb_fixture.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "noxtls_debug_printf.h"
#include "drbg/noxtls_drbg.h"

#if defined(_WIN32)
#include <windows.h>
#else
#include <pthread.h>
#endif

/* ------------------------------------------------------------------------- */
/* Framework                                                                 */
/* ------------------------------------------------------------------------- */

static const char *s_current_test = "";
static uint64_t s_entropy_state = 0x4E6F78544C53ULL; /* "NoxTLS" */
static uint64_t s_now_ms = 1U;

lb_keys_t g_lb_keys;
int g_lb_have_ed25519;
static int s_keys_loaded;

int g_lb_quiet;

void lb_fail(const char *file, int line, const char *expr)
{
    if(g_lb_quiet != 0) {
        return;
    }
    fprintf(stderr, "[%s] %s:%d: CHECK failed: %s\n", s_current_test, file, line, expr);
}

void lb_fail_rc(const char *file, int line, const char *expr, long actual, long expected)
{
    if(g_lb_quiet != 0) {
        return;
    }
    fprintf(stderr, "[%s] %s:%d: CHECK failed: %s == %ld (expected %ld)\n", s_current_test, file, line,
            expr, actual, expected);
}

void lb_log(const char *fmt, ...)
{
    va_list ap;
    printf("[%s] ", s_current_test);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}

static uint64_t lb_splitmix(uint64_t *state)
{
    uint64_t z;
    *state += 0x9E3779B97F4A7C15ULL;
    z = *state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* Deterministic "entropy" so handshakes are reproducible run to run. Test-only. */
static noxtls_return_t lb_entropy(uint8_t *out, uint32_t len)
{
    uint32_t i;
    for(i = 0U; i < len; i++) {
        if((i % 8U) == 0U) {
            (void)lb_splitmix(&s_entropy_state);
        }
        out[i] = (uint8_t)(s_entropy_state >> ((i % 8U) * 8U));
    }
    return NOXTLS_RETURN_SUCCESS;
}

void lb_fill_pattern(uint8_t *buf, uint32_t len, uint32_t seed)
{
    uint64_t state = 0x1234567ULL + seed;
    uint32_t i;
    for(i = 0U; i < len; i++) {
        if((i % 8U) == 0U) {
            (void)lb_splitmix(&state);
        }
        buf[i] = (uint8_t)(state >> ((i % 8U) * 8U));
    }
}

static int lb_load_ecc(ecc_key_t *key, const uint8_t *der, uint32_t len)
{
    x509_private_key_t pk;
    int rc = 1;
    (void)noxtls_x509_private_key_init(&pk);
    if((noxtls_x509_private_key_parse_der(&pk, der, len) == NOXTLS_RETURN_SUCCESS) &&
       (noxtls_x509_private_key_to_ecc_key(&pk, key) == NOXTLS_RETURN_SUCCESS)) {
        rc = 0;
    }
    (void)noxtls_x509_private_key_free(&pk);
    return rc;
}

static int lb_load_rsa(rsa_key_t *key, const uint8_t *der, uint32_t len)
{
    x509_private_key_t pk;
    int rc = 1;
    (void)noxtls_x509_private_key_init(&pk);
    if((noxtls_x509_private_key_parse_der(&pk, der, len) == NOXTLS_RETURN_SUCCESS) &&
       (noxtls_x509_private_key_to_rsa_key(&pk, key) == NOXTLS_RETURN_SUCCESS)) {
        rc = 0;
    }
    (void)noxtls_x509_private_key_free(&pk);
    return rc;
}

static int lb_load_ed25519(uint8_t seed[32], const uint8_t *der, uint32_t len)
{
    x509_private_key_t pk;
    const uint8_t *raw;
    uint32_t raw_len = 0U;
    int rc = 1;
    (void)noxtls_x509_private_key_init(&pk);
    if(noxtls_x509_private_key_parse_der(&pk, der, len) == NOXTLS_RETURN_SUCCESS) {
        raw = noxtls_x509_private_key_get_eddsa_seed(&pk, &raw_len);
        if((raw != NULL) && (raw_len == 32U)) {
            memcpy(seed, raw, 32U);
            rc = 0;
        }
    }
    (void)noxtls_x509_private_key_free(&pk);
    return rc;
}

static void lb_keys_free(void);

static int lb_keys_load(void)
{
    memset(&g_lb_keys, 0, sizeof(g_lb_keys));
    s_keys_loaded = 1;
    if(lb_load_ecc(&g_lb_keys.ec_server, lb_ec_server_key, lb_ec_server_key_len) != 0) {
        fprintf(stderr, "cannot load ec_server key\n");
        return 1;
    }
    if(lb_load_ecc(&g_lb_keys.ec_client, lb_ec_client_key, lb_ec_client_key_len) != 0) {
        fprintf(stderr, "cannot load ec_client key\n");
        return 1;
    }
    if(lb_load_rsa(&g_lb_keys.rsa_server, lb_rsa_server_key, lb_rsa_server_key_len) != 0) {
        fprintf(stderr, "cannot load rsa_server key\n");
        return 1;
    }
    if(lb_load_rsa(&g_lb_keys.rsa_client, lb_rsa_client_key, lb_rsa_client_key_len) != 0) {
        fprintf(stderr, "cannot load rsa_client key\n");
        return 1;
    }
    g_lb_keys.have_ed25519 = (lb_load_ed25519(g_lb_keys.ed_server_seed, lb_ed_server_key,
                                              lb_ed_server_key_len) == 0) ? 1 : 0;
    return 0;
}

static void lb_keys_free(void)
{
    if(s_keys_loaded == 0) {
        return;
    }
    s_keys_loaded = 0;
    (void)noxtls_ecc_key_free(&g_lb_keys.ec_server);
    (void)noxtls_ecc_key_free(&g_lb_keys.ec_client);
    (void)noxtls_rsa_key_free(&g_lb_keys.rsa_server);
    (void)noxtls_rsa_key_free(&g_lb_keys.rsa_client);
    noxtls_secure_zero(&g_lb_keys, sizeof(g_lb_keys));
}

int lb_expect_no_leak(size_t baseline, const char *what)
{
    if(lb_alloc_live_bytes() != baseline) {
        fprintf(stderr, "[%s] LEAK after %s: live=%lu baseline=%lu (blocks=%lu)\n", s_current_test, what,
                (unsigned long)lb_alloc_live_bytes(), (unsigned long)baseline,
                (unsigned long)lb_alloc_live_blocks());
        (void)lb_alloc_dump_live();
        return 1;
    }
    return 0;
}

int lb_main(int argc, char **argv, const char *suite, const lb_test_case_t *cases, size_t count)
{
    size_t i;
    size_t run = 0U;
    size_t failed = 0U;
    size_t skipped = 0U;
    const char *only = NULL;
    size_t baseline_total;

    if(getenv("LB_DEBUG") != NULL) {
        noxtls_debug_set_level((unsigned char)atoi(getenv("LB_DEBUG")));
    }
    if((argc > 1) && (strcmp(argv[1], "--list") == 0)) {
        for(i = 0U; i < count; i++) {
            printf("%s\n", cases[i].name);
        }
        return 0;
    }
    if(argc > 1) {
        only = argv[1];
    }

    noxtls_drbg_set_entropy_callback(lb_entropy);
    noxtls_drbg_set_entropy_source(NOXTLS_ENTROPY_SOURCE_CUSTOM);
    baseline_total = lb_alloc_live_bytes();
    lb_alloc_reset_counters();
    /* Probe the key material once (keys are loaded per pair, see lb_pair_init). */
    if(lb_keys_load() != 0) {
        return 2;
    }
    g_lb_have_ed25519 = g_lb_keys.have_ed25519;
    lb_keys_free();
    {
        lb_alloc_stats_t st;
        lb_alloc_get_stats(&st);
        if(st.alloc_calls == 0U) {
            /* The library must allocate through lb_alloc.c; otherwise leak checks are meaningless. */
            fprintf(stderr, "%s: library allocations do not reach lb_alloc.c (link order?)\n", suite);
            return 2;
        }
    }
    if(lb_alloc_live_bytes() != baseline_total) {
        fprintf(stderr, "%s: key load/free leaks %lu bytes\n", suite,
                (unsigned long)(lb_alloc_live_bytes() - baseline_total));
        (void)lb_alloc_dump_live();
        return 2;
    }

    for(i = 0U; i < count; i++) {
        size_t baseline;
        int rc;
        if((only != NULL) && (strcmp(only, cases[i].name) != 0)) {
            continue;
        }
        run++;
        s_current_test = cases[i].name;
        baseline = lb_alloc_live_bytes();
        if(getenv("LB_DUMP") != NULL) {
            fprintf(stderr, "live blocks before %s:\n", cases[i].name);
            (void)lb_alloc_dump_live();
        }
        rc = cases[i].fn();
        g_lb_quiet = 0;
        g_lb_strict_unified = 0;
        lb_alloc_fail_after(SIZE_MAX);
        lb_trust_clear();
        if((rc == 0) || (rc == LB_SKIP)) {
            if(lb_expect_no_leak(baseline, "test") != 0) {
                rc = 1;
            }
        }
        if(rc == LB_SKIP) {
            skipped++;
            printf("[%s] SKIP\n", cases[i].name);
        } else if(rc != 0) {
            failed++;
            printf("[%s] FAIL (%d)\n", cases[i].name, rc);
        } else {
            printf("[%s] PASS\n", cases[i].name);
        }
        fflush(stdout);
    }
    s_current_test = suite;
    lb_trust_clear();
    if((only == NULL) && (lb_alloc_live_bytes() != baseline_total)) {
        fprintf(stderr, "%s: %lu bytes still allocated at exit\n", suite, (unsigned long)lb_alloc_live_bytes());
        (void)lb_alloc_dump_live();
        failed++;
    }
    if(run == 0U) {
        fprintf(stderr, "%s: no test named '%s'\n", suite, (only != NULL) ? only : "");
        return 3;
    }
    printf("%s: %lu run, %lu failed, %lu skipped\n", suite, (unsigned long)run, (unsigned long)failed,
           (unsigned long)skipped);
    if(failed != 0U) {
        return 1;
    }
    if((only != NULL) && (skipped == run)) {
        return LB_SKIP;
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Cooperative threads                                                       */
/*                                                                           */
/* DTLS 1.2 certificate handshakes only have blocking entry points. Each     */
/* endpoint then runs on its own thread, but a baton guarantees that exactly */
/* one of them executes at a time: an endpoint that finds no datagram hands  */
/* the baton to its peer. Execution therefore stays deterministic and the    */
/* (non-thread-safe) library and allocator are never entered concurrently.   */
/* ------------------------------------------------------------------------- */

typedef struct
{
    lb_end_t *end;
    int id;
    int finished;
    noxtls_return_t rc;
} lb_coop_t;

static lb_coop_t s_coop[2];
static int s_coop_active;
static int s_coop_turn;

#if defined(_WIN32)
static SRWLOCK s_coop_lock = SRWLOCK_INIT;
static CONDITION_VARIABLE s_coop_cv = CONDITION_VARIABLE_INIT;
#define LB_COOP_LOCK() AcquireSRWLockExclusive(&s_coop_lock)
#define LB_COOP_UNLOCK() ReleaseSRWLockExclusive(&s_coop_lock)
#define LB_COOP_WAIT() (void)SleepConditionVariableSRW(&s_coop_cv, &s_coop_lock, INFINITE, 0)
#define LB_COOP_WAKE() WakeAllConditionVariable(&s_coop_cv)
#else
static pthread_mutex_t s_coop_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t s_coop_cv = PTHREAD_COND_INITIALIZER;
#define LB_COOP_LOCK() (void)pthread_mutex_lock(&s_coop_lock)
#define LB_COOP_UNLOCK() (void)pthread_mutex_unlock(&s_coop_lock)
#define LB_COOP_WAIT() (void)pthread_cond_wait(&s_coop_cv, &s_coop_lock)
#define LB_COOP_WAKE() (void)pthread_cond_broadcast(&s_coop_cv)
#endif

static void lb_coop_yield(int me)
{
    LB_COOP_LOCK();
    /* Virtual time advances on every idle receive so retransmission timers fire. */
    s_now_ms += 50U;
    if(s_coop[1 - me].finished == 0) {
        s_coop_turn = 1 - me;
        LB_COOP_WAKE();
        while(s_coop_turn != me) {
            LB_COOP_WAIT();
        }
    }
    LB_COOP_UNLOCK();
}

#if defined(_WIN32)
static DWORD WINAPI lb_coop_thread(LPVOID arg)
#else
static void *lb_coop_thread(void *arg)
#endif
{
    lb_coop_t *self = (lb_coop_t *)arg;
    LB_COOP_LOCK();
    while(s_coop_turn != self->id) {
        LB_COOP_WAIT();
    }
    LB_COOP_UNLOCK();
    self->rc = lb_end_step(self->end);
    LB_COOP_LOCK();
    self->finished = 1;
    s_coop_turn = 1 - self->id;
    LB_COOP_WAKE();
    LB_COOP_UNLOCK();
#if defined(_WIN32)
    return 0;
#else
    return NULL;
#endif
}

/** Run blocking client and server handshakes on cooperative threads. */
static int lb_pair_handshake_coop(lb_pair_t *pair)
{
    int i;
    memset(s_coop, 0, sizeof(s_coop));
    s_coop[0].end = &pair->client;
    s_coop[0].id = 0;
    s_coop[1].end = &pair->server;
    s_coop[1].id = 1;
    s_coop_turn = 0;
    s_coop_active = 1;
    {
#if defined(_WIN32)
        HANDLE threads[2];
        for(i = 0; i < 2; i++) {
            threads[i] = CreateThread(NULL, 1024U * 1024U, lb_coop_thread, &s_coop[i], 0, NULL);
            if(threads[i] == NULL) {
                s_coop_active = 0;
                return 1;
            }
        }
        (void)WaitForMultipleObjects(2U, threads, TRUE, INFINITE);
        (void)CloseHandle(threads[0]);
        (void)CloseHandle(threads[1]);
#else
        pthread_t threads[2];
        for(i = 0; i < 2; i++) {
            if(pthread_create(&threads[i], NULL, lb_coop_thread, &s_coop[i]) != 0) {
                s_coop_active = 0;
                return 1;
            }
        }
        (void)pthread_join(threads[0], NULL);
        (void)pthread_join(threads[1], NULL);
#endif
    }
    s_coop_active = 0;
    pair->client.last_rc = s_coop[0].rc;
    pair->server.last_rc = s_coop[1].rc;
    pair->client.done = (s_coop[0].rc == NOXTLS_RETURN_SUCCESS) ? 1 : 0;
    pair->server.done = (s_coop[1].rc == NOXTLS_RETURN_SUCCESS) ? 1 : 0;
    return ((pair->client.done != 0) && (pair->server.done != 0)) ? 0 : 1;
}

/* ------------------------------------------------------------------------- */
/* Link                                                                      */
/* ------------------------------------------------------------------------- */

static void lb_pipe_reset(lb_pipe_t *pipe)
{
    pipe->rd = 0U;
    pipe->wr = 0U;
    pipe->dgram_head = 0U;
    pipe->dgram_count = 0U;
    pipe->total = 0U;
}

void lb_link_init(lb_link_t *link, uint32_t max_chunk, uint32_t block_every, int datagram)
{
    lb_pipe_reset(&link->to_server);
    lb_pipe_reset(&link->to_client);
    link->client_port.link = link;
    link->client_port.is_client = 1;
    link->server_port.link = link;
    link->server_port.is_client = 0;
    link->max_chunk = max_chunk;
    link->block_every = block_every;
    link->calls = 0U;
    link->datagram = datagram;
}

uint32_t lb_link_pending(const lb_link_t *link, int to_client)
{
    const lb_pipe_t *pipe = (to_client != 0) ? &link->to_client : &link->to_server;
    return pipe->wr - pipe->rd;
}

static int lb_link_block(lb_link_t *link)
{
    link->calls++;
    return ((link->block_every != 0U) && ((link->calls % link->block_every) == 0U)) ? 1 : 0;
}

static void lb_pipe_compact(lb_pipe_t *pipe)
{
    if(pipe->rd == pipe->wr) {
        pipe->rd = 0U;
        pipe->wr = 0U;
    } else if(pipe->rd > (LB_PIPE_CAPACITY / 2U)) {
        memmove(pipe->data, &pipe->data[pipe->rd], pipe->wr - pipe->rd);
        pipe->wr -= pipe->rd;
        pipe->rd = 0U;
    } else {
        /* keep */
    }
}

int32_t lb_io_send(void *user, const uint8_t *data, uint32_t len)
{
    lb_port_t *port = (lb_port_t *)user;
    lb_link_t *link = port->link;
    lb_pipe_t *pipe = (port->is_client != 0) ? &link->to_server : &link->to_client;
    uint32_t count = len;

    if(link->datagram != 0) {
        uint32_t slot;
        lb_pipe_compact(pipe);
        if((len > LB_DGRAM_MAX) || (pipe->dgram_count >= LB_DGRAM_SLOTS) ||
           ((LB_PIPE_CAPACITY - pipe->wr) < len)) {
            return -1;
        }
        slot = (pipe->dgram_head + pipe->dgram_count) % LB_DGRAM_SLOTS;
        memcpy(&pipe->data[pipe->wr], data, len);
        pipe->wr += len;
        pipe->dgram_len[slot] = len;
        pipe->dgram_count++;
        pipe->total += len;
        return (int32_t)len;
    }
    if(lb_link_block(link) != 0) {
        return TLS_IO_WOULD_BLOCK;
    }
    if((link->max_chunk != 0U) && (count > link->max_chunk)) {
        count = link->max_chunk;
    }
    lb_pipe_compact(pipe);
    if((LB_PIPE_CAPACITY - pipe->wr) < count) {
        count = LB_PIPE_CAPACITY - pipe->wr;
    }
    if(count == 0U) {
        return TLS_IO_WOULD_BLOCK;
    }
    memcpy(&pipe->data[pipe->wr], data, count);
    pipe->wr += count;
    pipe->total += count;
    return (int32_t)count;
}

int32_t lb_io_recv(void *user, uint8_t *data, uint32_t len)
{
    lb_port_t *port = (lb_port_t *)user;
    lb_link_t *link = port->link;
    lb_pipe_t *pipe = (port->is_client != 0) ? &link->to_client : &link->to_server;
    uint32_t avail = pipe->wr - pipe->rd;
    uint32_t count = len;

    if(link->datagram != 0) {
        uint32_t dlen;
        if((pipe->dgram_count == 0U) && (s_coop_active != 0)) {
            /* Blocking-only handshake running on a cooperative thread: let the peer run. */
            lb_coop_yield((port->is_client != 0) ? 0 : 1);
        }
        if(pipe->dgram_count == 0U) {
            return 0;
        }
        dlen = pipe->dgram_len[pipe->dgram_head];
        if(dlen > len) {
            return -1;
        }
        memcpy(data, &pipe->data[pipe->rd], dlen);
        pipe->rd += dlen;
        pipe->dgram_head = (pipe->dgram_head + 1U) % LB_DGRAM_SLOTS;
        pipe->dgram_count--;
        return (int32_t)dlen;
    }
    if(avail == 0U) {
        return TLS_IO_WOULD_BLOCK;
    }
    if(lb_link_block(link) != 0) {
        return TLS_IO_WOULD_BLOCK;
    }
    if((link->max_chunk != 0U) && (count > link->max_chunk)) {
        count = link->max_chunk;
    }
    if(count > avail) {
        count = avail;
    }
    memcpy(data, &pipe->data[pipe->rd], count);
    pipe->rd += count;
    return (int32_t)count;
}

uint64_t lb_io_now_ms(void *user)
{
    (void)user;
    return s_now_ms;
}

/* ------------------------------------------------------------------------- */
/* Trust store                                                               */
/* ------------------------------------------------------------------------- */

static x509_certificate_t s_trust_tmp;

int lb_trust_set(const uint8_t *const *ders, const uint32_t *lens, uint32_t count)
{
    x509_certificate_chain_t chain;
    uint32_t i;
    int rc = 0;
    unsigned prev = lb_alloc_set_owner(LB_OWNER_GLOBAL);

    if(noxtls_x509_certificate_chain_init(&chain) != NOXTLS_RETURN_SUCCESS) {
        return 1;
    }
    for(i = 0U; (i < count) && (rc == 0); i++) {
        (void)noxtls_x509_certificate_init(&s_trust_tmp);
        if(noxtls_x509_certificate_parse_der(&s_trust_tmp, ders[i], lens[i]) != NOXTLS_RETURN_SUCCESS) {
            rc = 1;
        } else if(noxtls_x509_certificate_chain_add(&chain, &s_trust_tmp) != NOXTLS_RETURN_SUCCESS) {
            rc = 1;
        } else {
            /* added */
        }
        (void)noxtls_x509_certificate_free(&s_trust_tmp);
    }
    if((rc == 0) && (noxtls_x509_trust_store_set(&chain) != NOXTLS_RETURN_SUCCESS)) {
        rc = 1;
    }
    (void)noxtls_x509_certificate_chain_free(&chain);
    (void)lb_alloc_set_owner(prev);
    return rc;
}

int lb_trust_ec_root(void)
{
    const uint8_t *ders[1] = { lb_ec_root_cert };
    const uint32_t lens[1] = { lb_ec_root_cert_len };
    return lb_trust_set(ders, lens, 1U);
}

int lb_trust_all_roots(void)
{
    const uint8_t *ders[2] = { lb_ec_root_cert, lb_rsa_root_cert };
    uint32_t lens[2];
    lens[0] = lb_ec_root_cert_len;
    lens[1] = lb_rsa_root_cert_len;
    return lb_trust_set(ders, lens, 2U);
}

void lb_trust_clear(void)
{
    noxtls_x509_trust_store_clear();
}

/* ------------------------------------------------------------------------- */
/* Struct field access (no public accessor exists yet)                       */
/* Update these when the TLS / CERT streams change the structures.           */
/* ------------------------------------------------------------------------- */

tls_state_t lb_field_state(lb_end_t *end)
{
    return lb_end_base(end)->state;
}

int lb_field_tls13_hrr(const tls13_context_t *ctx)
{
    return ((ctx->received_hrr != 0U) || (ctx->sent_hrr != 0U)) ? 1 : 0;
}

int lb_field_tls13_psk_in_use(const tls13_context_t *ctx)
{
    return (ctx->psk_in_use != 0U) ? 1 : 0;
}

int lb_field_tls13_early_accepted(const tls13_context_t *ctx)
{
    return (ctx->early_data_accepted != 0U) ? 1 : 0;
}

uint16_t lb_field_tls13_group(const tls13_context_t *ctx)
{
    return ctx->selected_kex_group;
}

int lb_field_tls13_ticket_stored(const tls13_context_t *ctx)
{
    return (ctx->ticket_stored != 0U) ? 1 : 0;
}

int lb_field_tls12_resumed(const tls12_context_t *ctx)
{
    return (ctx->session_resume != 0U) ? 1 : 0;
}

uint32_t lb_field_tls12_reneg_len(const tls12_context_t *ctx)
{
    return ctx->previous_verify_data_len;
}

int lb_field_tls12_ems(const tls12_context_t *ctx)
{
    return (ctx->extended_master_secret_negotiated != 0U) ? 1 : 0;
}

uint16_t lb_field_tls12_cv_scheme(const tls12_context_t *ctx)
{
    return ctx->client_cv_scheme;
}

int lb_field_tls12_transcript_live(const tls12_context_t *ctx)
{
    return (ctx->transcript != NULL) ? 1 : 0;
}

void lb_field_tls13_set_server_cert(tls13_context_t *ctx, const uint8_t *der, uint32_t len)
{
    ctx->server_cert = (uint8_t *)(uintptr_t)der;
    ctx->server_cert_len = len;
}

void lb_field_tls12_set_server_cert(tls12_context_t *ctx, const uint8_t *der, uint32_t len)
{
    ctx->server_cert = (uint8_t *)(uintptr_t)der;
    ctx->server_cert_len = len;
}

void lb_field_tls13_set_sni(tls13_context_t *ctx, const char *name)
{
    ctx->server_name = (const uint8_t *)name;
    ctx->server_name_len = (uint16_t)((name != NULL) ? strlen(name) : 0U);
}

void lb_field_tls12_set_sni(tls12_context_t *ctx, const char *name)
{
    ctx->server_name = (const uint8_t *)name;
    ctx->server_name_len = (uint16_t)((name != NULL) ? strlen(name) : 0U);
}

tls13_context_t *lb_field_unified_tls13(noxtls_tls_connection_t *conn)
{
    return &conn->ver.tls13;
}

const uint8_t *lb_field_cert_der(const x509_certificate_t *cert, uint32_t *len)
{
    const uint8_t *der = NULL;
    *len = 0U;
    (void)noxtls_x509_certificate_get_der(cert, &der, len);
    return der;
}

/* ------------------------------------------------------------------------- */
/* Endpoints                                                                 */
/* ------------------------------------------------------------------------- */

static lb_link_t s_link;
static tls13_context_t s_t13[2];
static tls12_context_t s_t12[2];
static noxtls_tls_connection_t s_uni[2];
static const uint8_t *s_chain_ders[1];
static uint32_t s_chain_lens[1];

void lb_cfg_default(lb_cfg_t *cfg, lb_proto_t proto)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->proto = proto;
    cfg->server_auth = LB_AUTH_ECDSA;
    cfg->send_chain = 1;
    cfg->client_cert = LB_AUTH_NONE;
    cfg->sni = "server.test";
}

tls_context_t *lb_end_base(lb_end_t *end)
{
    switch(end->proto) {
        case LB_PROTO_TLS13:
        case LB_PROTO_DTLS13:
            return &end->t13->base.base;
        case LB_PROTO_TLS12:
        case LB_PROTO_DTLS12:
            return &end->t12->base.base;
        case LB_PROTO_UNIFIED:
        default:
            if(end->uni->negotiated_version == 0U) {
                return &end->uni->base;
            }
            return (end->uni->is_tls13 != 0U) ? &end->uni->ver.tls13.base.base : &end->uni->ver.tls12.base.base;
    }
}

static void lb_server_cert_material(lb_auth_t auth, const uint8_t **der, uint32_t *len)
{
    switch(auth) {
        case LB_AUTH_RSA:
            *der = lb_rsa_server_cert;
            *len = lb_rsa_server_cert_len;
            break;
        case LB_AUTH_ED25519:
            *der = lb_ed_server_cert;
            *len = lb_ed_server_cert_len;
            break;
        case LB_AUTH_ROGUE:
            *der = lb_rogue_server_cert;
            *len = lb_rogue_server_cert_len;
            break;
        case LB_AUTH_ECDSA:
        default:
            *der = lb_ec_server_cert;
            *len = lb_ec_server_cert_len;
            break;
    }
}

static int lb_setup_tls13(lb_pair_t *pair, lb_end_t *end, int is_client)
{
    const lb_cfg_t *cfg = &pair->cfg;
    tls13_context_t *ctx = &s_t13[is_client ? 0 : 1];
    tls_role_t role = is_client ? TLS_ROLE_CLIENT : TLS_ROLE_SERVER;
    lb_port_t *port = is_client ? &pair->link->client_port : &pair->link->server_port;
    noxtls_return_t rc;

    end->t13 = ctx;
    rc = (end->proto == LB_PROTO_DTLS13) ? noxtls_dtls13_context_init(ctx, role) :
                                            noxtls_tls13_context_init(ctx, role);
    LB_CHECK_OK(rc);
    end->initialized = 1;
    LB_CHECK_OK(noxtls_tls_set_io_callbacks(&ctx->base.base, lb_io_send, lb_io_recv, port));
    if(end->proto == LB_PROTO_DTLS13) {
        LB_CHECK_OK(noxtls_tls_set_time_callback(&ctx->base.base, lb_io_now_ms));
    } else {
        LB_CHECK_OK(noxtls_tls_set_io_mode(&ctx->base.base, TLS_IO_MODE_NON_BLOCKING));
    }
    if(is_client) {
        if(cfg->sni != NULL) {
            lb_field_tls13_set_sni(ctx, cfg->sni);
        }
        if((cfg->client_groups != NULL) && (cfg->client_group_count > 0U)) {
            noxtls_tls13_set_client_supported_groups(ctx, cfg->client_groups, cfg->client_group_count);
        }
        if(cfg->prefer_chacha20 != 0) {
            noxtls_tls13_set_prefer_chacha20(ctx, 1);
        }
        if(cfg->record_size_limit != 0U) {
            noxtls_tls13_set_record_size_limit(ctx, cfg->record_size_limit);
        }
        if(cfg->client_cert == LB_AUTH_ECDSA) {
            LB_CHECK_OK(noxtls_tls13_set_client_cert_ecdsa(ctx, lb_ec_client_cert, lb_ec_client_cert_len,
                                                           &g_lb_keys.ec_client));
        } else if(cfg->client_cert == LB_AUTH_RSA) {
            LB_CHECK_OK(noxtls_tls13_set_client_cert(ctx, lb_rsa_client_cert, lb_rsa_client_cert_len,
                                                     &g_lb_keys.rsa_client));
        } else {
            /* no client certificate */
        }
        if(cfg->tls13_session != NULL) {
            LB_CHECK_OK(noxtls_tls13_session_import(ctx, cfg->tls13_session));
        }
    } else {
        const uint8_t *der = NULL;
        uint32_t len = 0U;
        lb_server_cert_material(cfg->server_auth, &der, &len);
        if(cfg->server_auth != LB_AUTH_NONE) {
            lb_field_tls13_set_server_cert(ctx, der, len);
        }
        if((cfg->server_auth == LB_AUTH_ECDSA) && (cfg->send_chain != 0)) {
            s_chain_ders[0] = lb_ec_int_cert;
            s_chain_lens[0] = lb_ec_int_cert_len;
            noxtls_tls13_set_server_certificate_chain(ctx, s_chain_ders, s_chain_lens, 1U);
        }
        if((cfg->server_auth == LB_AUTH_ECDSA) || (cfg->server_auth == LB_AUTH_ROGUE)) {
            noxtls_tls13_set_server_private_ecdsa(ctx, &g_lb_keys.ec_server);
        } else if(cfg->server_auth == LB_AUTH_RSA) {
            noxtls_tls13_set_server_private_rsa(ctx, &g_lb_keys.rsa_server);
        } else if(cfg->server_auth == LB_AUTH_ED25519) {
            LB_CHECK_OK(noxtls_tls13_set_server_private_ed25519(ctx, g_lb_keys.ed_server_seed));
        } else {
            /* PSK-only server */
        }
        if((cfg->server_suites != NULL) && (cfg->server_suite_count > 0U)) {
            noxtls_tls13_set_server_cipher_suites(ctx, cfg->server_suites, cfg->server_suite_count);
        }
        if(cfg->client_auth == 2) {
            noxtls_tls13_require_client_auth(ctx, 1);
        } else if(cfg->client_auth == 1) {
            noxtls_tls13_request_client_auth(ctx, 1);
        } else {
            /* no client auth */
        }
    }
    return 0;
}

static int lb_setup_tls12(lb_pair_t *pair, lb_end_t *end, int is_client)
{
    const lb_cfg_t *cfg = &pair->cfg;
    tls12_context_t *ctx = &s_t12[is_client ? 0 : 1];
    tls_role_t role = is_client ? TLS_ROLE_CLIENT : TLS_ROLE_SERVER;
    lb_port_t *port = is_client ? &pair->link->client_port : &pair->link->server_port;
    noxtls_return_t rc;

    end->t12 = ctx;
    if(end->proto == LB_PROTO_DTLS12) {
        rc = noxtls_dtls12_context_init(ctx, role);
    } else if(cfg->tls12_version != 0U) {
        rc = noxtls_tls12_context_init_with_version(ctx, role, cfg->tls12_version);
    } else {
        rc = noxtls_tls12_context_init(ctx, role);
    }
    LB_CHECK_OK(rc);
    end->initialized = 1;
    LB_CHECK_OK(noxtls_tls_set_io_callbacks(&ctx->base.base, lb_io_send, lb_io_recv, port));
    if(end->proto == LB_PROTO_DTLS12) {
        LB_CHECK_OK(noxtls_tls_set_time_callback(&ctx->base.base, lb_io_now_ms));
    } else {
        LB_CHECK_OK(noxtls_tls_set_io_mode(&ctx->base.base, TLS_IO_MODE_NON_BLOCKING));
    }
    if(cfg->max_fragment_code != 0U) {
        noxtls_tls12_set_max_fragment_length(ctx, cfg->max_fragment_code);
    }
    if(is_client) {
        if(cfg->sni != NULL) {
            lb_field_tls12_set_sni(ctx, cfg->sni);
        }
        if(cfg->tls12_client_no_ems != 0) {
            noxtls_tls12_set_client_extended_master_secret(ctx, 0);
        }
        if(cfg->client_cert == LB_AUTH_ECDSA) {
            LB_CHECK_OK(noxtls_tls12_set_client_cert_ecdsa(ctx, lb_ec_client_cert, lb_ec_client_cert_len,
                                                           &g_lb_keys.ec_client));
        } else if(cfg->client_cert == LB_AUTH_RSA) {
            LB_CHECK_OK(noxtls_tls12_set_client_cert_rsa(ctx, lb_rsa_client_cert, lb_rsa_client_cert_len,
                                                         &g_lb_keys.rsa_client));
        } else {
            /* no client certificate */
        }
    } else {
        const uint8_t *der = NULL;
        uint32_t len = 0U;
        lb_server_cert_material(cfg->server_auth, &der, &len);
        lb_field_tls12_set_server_cert(ctx, der, len);
        if((cfg->server_auth == LB_AUTH_ECDSA) && (cfg->send_chain != 0)) {
            s_chain_ders[0] = lb_ec_int_cert;
            s_chain_lens[0] = lb_ec_int_cert_len;
            noxtls_tls12_set_server_certificate_chain(ctx, s_chain_ders, s_chain_lens, 1U);
        }
        if((cfg->server_auth == LB_AUTH_ECDSA) || (cfg->server_auth == LB_AUTH_ROGUE)) {
            noxtls_tls12_set_server_private_ecdsa(ctx, &g_lb_keys.ec_server);
            noxtls_tls12_set_server_ecdsa_leaf_certificate(ctx, der, len);
        } else if(cfg->server_auth == LB_AUTH_RSA) {
            noxtls_tls12_set_server_private_rsa(ctx, &g_lb_keys.rsa_server);
        } else {
            /* unsupported for TLS 1.2 in this fixture */
        }
        if((cfg->server_suites != NULL) && (cfg->server_suite_count > 0U)) {
            noxtls_tls12_set_server_cipher_suites(ctx, cfg->server_suites, cfg->server_suite_count);
        }
        if(cfg->client_auth == 2) {
            noxtls_tls12_require_client_auth(ctx, 1);
        } else if(cfg->client_auth == 1) {
            noxtls_tls12_request_client_auth(ctx, 1);
        } else {
            /* no client auth */
        }
    }
    return 0;
}

static int lb_setup_unified(lb_pair_t *pair, lb_end_t *end, int is_client)
{
    const lb_cfg_t *cfg = &pair->cfg;
    noxtls_tls_connection_t *conn = &s_uni[is_client ? 0 : 1];
    tls_role_t role = is_client ? TLS_ROLE_CLIENT : TLS_ROLE_SERVER;
    lb_port_t *port = is_client ? &pair->link->client_port : &pair->link->server_port;
    uint16_t version = is_client ? cfg->unified_client_version : cfg->unified_server_version;

    end->uni = conn;
    if(version != 0U) {
        LB_CHECK_OK(noxtls_tls_connection_init_version(conn, role, version));
    } else {
        LB_CHECK_OK(noxtls_tls_connection_init(conn, role));
    }
    end->initialized = 1;
    LB_CHECK_OK(noxtls_tls_connection_set_io_callbacks(conn, lb_io_send, lb_io_recv, port));
    LB_CHECK_OK(noxtls_tls_connection_set_io_mode(conn, TLS_IO_MODE_NON_BLOCKING));
    if(is_client) {
        if(cfg->sni != NULL) {
            LB_CHECK_OK(noxtls_tls_connection_set_sni(conn, (const uint8_t *)cfg->sni, (uint16_t)strlen(cfg->sni)));
        }
        if(cfg->client_cert == LB_AUTH_ECDSA) {
            LB_CHECK_OK(noxtls_tls_connection_set_client_cert_ecdsa(conn, lb_ec_client_cert, lb_ec_client_cert_len,
                                                                    &g_lb_keys.ec_client));
        } else if(cfg->client_cert == LB_AUTH_RSA) {
            LB_CHECK_OK(noxtls_tls_connection_set_client_cert_rsa(conn, lb_rsa_client_cert, lb_rsa_client_cert_len,
                                                                  &g_lb_keys.rsa_client));
        } else {
            /* no client certificate */
        }
        if(cfg->tls13_session != NULL) {
            LB_CHECK_OK(noxtls_tls_connection_set_tls13_session(conn, cfg->tls13_session));
        }
    } else {
        /* The unified API carries an RSA server identity only. */
        LB_CHECK_OK(noxtls_tls_connection_set_server_cert(conn, (uint8_t *)(uintptr_t)lb_rsa_server_cert,
                                                          lb_rsa_server_cert_len));
        LB_CHECK_OK(noxtls_tls_connection_set_server_private_key(conn, &g_lb_keys.rsa_server));
        if((cfg->server_suites != NULL) && (cfg->server_suite_count > 0U)) {
            LB_CHECK_OK(noxtls_tls_connection_set_server_cipher_suites(conn, cfg->server_suites,
                                                                       cfg->server_suite_count));
        }
        if(cfg->client_auth == 2) {
            LB_CHECK_OK(noxtls_tls_connection_set_require_client_auth(conn, 1));
        } else if(cfg->client_auth == 1) {
            LB_CHECK_OK(noxtls_tls_connection_set_request_client_auth(conn, 1));
        } else {
            /* no client auth */
        }
    }
    return 0;
}

static int lb_setup_end(lb_pair_t *pair, lb_end_t *end, int is_client);
static void lb_end_free(lb_end_t *end);

static int lb_setup_end_raw(lb_pair_t *pair, lb_end_t *end, int is_client)
{
    switch(end->proto) {
        case LB_PROTO_TLS13:
        case LB_PROTO_DTLS13:
            return lb_setup_tls13(pair, end, is_client);
        case LB_PROTO_TLS12:
        case LB_PROTO_DTLS12:
            return lb_setup_tls12(pair, end, is_client);
        case LB_PROTO_UNIFIED:
        default:
            return lb_setup_unified(pair, end, is_client);
    }
}

int lb_pair_init(lb_pair_t *pair, const lb_cfg_t *cfg)
{
    int datagram = ((cfg->proto == LB_PROTO_DTLS13) || (cfg->proto == LB_PROTO_DTLS12)) ? 1 : 0;

    memset(pair, 0, sizeof(*pair));
    pair->cfg = *cfg;
    pair->link = &s_link;
    lb_link_init(pair->link, cfg->max_chunk, cfg->block_every, datagram);
    s_now_ms = 1U;
    pair->client.proto = cfg->proto;
    pair->client.role = TLS_ROLE_CLIENT;
    pair->server.proto = (cfg->server_proto_override != 0) ? cfg->server_proto : cfg->proto;
    pair->server.role = TLS_ROLE_SERVER;
    /* Keys live exactly as long as the pair, so library-global ECC precompute caches
     * owned by their curves are released by lb_pair_free() as well. */
    if(lb_keys_load() != 0) {
        lb_keys_free();
        return 1;
    }
    LB_RUN(lb_setup_end(pair, &pair->client, 1));
    LB_RUN(lb_setup_end(pair, &pair->server, 0));
    return 0;
}

static void lb_end_free_raw(lb_end_t *end)
{
    if(end->initialized == 0) {
        return;
    }
    switch(end->proto) {
        case LB_PROTO_TLS13:
        case LB_PROTO_DTLS13:
            (void)noxtls_tls13_context_free(end->t13);
            break;
        case LB_PROTO_TLS12:
        case LB_PROTO_DTLS12:
            if(end->role == TLS_ROLE_SERVER) {
                /* Server-role server_cert points at test-owned DER; the library does not free it. */
            }
            (void)noxtls_tls12_context_free(end->t12);
            break;
        case LB_PROTO_UNIFIED:
        default:
            (void)noxtls_tls_connection_free(end->uni);
            break;
    }
    end->initialized = 0;
}

void lb_pair_free(lb_pair_t *pair)
{
    lb_end_free(&pair->client);
    lb_end_free(&pair->server);
    lb_keys_free();
}

static int lb_is_progress(lb_proto_t proto, noxtls_return_t rc)
{
    if((rc == NOXTLS_RETURN_WANT_READ) || (rc == NOXTLS_RETURN_WANT_WRITE)) {
        return 1;
    }
    if(((proto == LB_PROTO_DTLS13) || (proto == LB_PROTO_DTLS12)) && (rc == NOXTLS_RETURN_TIMEOUT)) {
        return 1;
    }
    return 0;
}

static noxtls_return_t lb_end_step_raw(lb_end_t *end)
{
    switch(end->proto) {
        case LB_PROTO_TLS13:
        case LB_PROTO_DTLS13:
            return (end->role == TLS_ROLE_CLIENT) ? noxtls_tls13_connect(end->t13) : noxtls_tls13_accept(end->t13);
        case LB_PROTO_TLS12:
            return (end->role == TLS_ROLE_CLIENT) ? noxtls_tls12_connect_poll(end->t12) :
                                                    noxtls_tls12_accept_poll(end->t12);
        case LB_PROTO_DTLS12:
            /* Certificate DTLS 1.2 has no caller-polled entry point (connect_poll/accept_poll
             * return NOT_SUPPORTED outside EC-JPAKE): run blocking on cooperative threads. */
            return (end->role == TLS_ROLE_CLIENT) ? noxtls_tls12_connect(end->t12) : noxtls_tls12_accept(end->t12);
        case LB_PROTO_UNIFIED:
        default:
            return noxtls_tls_connection_handshake(end->uni);
    }
}

static noxtls_return_t lb_end_flush_raw(lb_end_t *end)
{
    if(end->proto == LB_PROTO_UNIFIED) {
        return noxtls_tls_connection_flush(end->uni);
    }
    if((end->proto == LB_PROTO_DTLS13) || (end->proto == LB_PROTO_DTLS12)) {
        return NOXTLS_RETURN_SUCCESS;
    }
    return noxtls_tls_flush(lb_end_base(end));
}

static noxtls_return_t lb_end_send_raw(lb_end_t *end, const uint8_t *data, uint32_t len)
{
    switch(end->proto) {
        case LB_PROTO_TLS13:
        case LB_PROTO_DTLS13:
            return noxtls_tls13_send(end->t13, data, len);
        case LB_PROTO_TLS12:
        case LB_PROTO_DTLS12:
            return noxtls_tls12_send(end->t12, data, len);
        case LB_PROTO_UNIFIED:
        default:
            return noxtls_tls_connection_send(end->uni, data, len);
    }
}

static noxtls_return_t lb_end_recv_raw(lb_end_t *end, uint8_t *buf, uint32_t *len)
{
    switch(end->proto) {
        case LB_PROTO_TLS13:
        case LB_PROTO_DTLS13:
            return noxtls_tls13_recv(end->t13, buf, len);
        case LB_PROTO_TLS12:
        case LB_PROTO_DTLS12:
            return noxtls_tls12_recv(end->t12, buf, len);
        case LB_PROTO_UNIFIED:
        default:
            return noxtls_tls_connection_recv(end->uni, buf, len);
    }
}

static noxtls_return_t lb_end_close_raw(lb_end_t *end)
{
    switch(end->proto) {
        case LB_PROTO_TLS13:
        case LB_PROTO_DTLS13:
            return noxtls_tls13_close(end->t13);
        case LB_PROTO_TLS12:
        case LB_PROTO_DTLS12:
            return noxtls_tls12_close(end->t12);
        case LB_PROTO_UNIFIED:
        default:
            return noxtls_tls_connection_close(end->uni);
    }
}

/* ---- Allocation-owner attribution: every library call made on behalf of an
 *      endpoint charges its allocations to that endpoint (see ut/ram_budget). */

static unsigned lb_owner_of(const lb_end_t *end)
{
    return (end->role == TLS_ROLE_CLIENT) ? LB_OWNER_CLIENT : LB_OWNER_SERVER;
}

static int lb_setup_end(lb_pair_t *pair, lb_end_t *end, int is_client)
{
    unsigned prev = lb_alloc_set_owner(lb_owner_of(end));
    int rc = lb_setup_end_raw(pair, end, is_client);
    (void)lb_alloc_set_owner(prev);
    return rc;
}

static void lb_end_free(lb_end_t *end)
{
    unsigned prev = lb_alloc_set_owner(lb_owner_of(end));
    lb_end_free_raw(end);
    (void)lb_alloc_set_owner(prev);
}

noxtls_return_t lb_end_step(lb_end_t *end)
{
    unsigned prev = lb_alloc_set_owner(lb_owner_of(end));
    noxtls_return_t rc = lb_end_step_raw(end);
    (void)lb_alloc_set_owner(prev);
    return rc;
}

noxtls_return_t lb_end_flush(lb_end_t *end)
{
    unsigned prev = lb_alloc_set_owner(lb_owner_of(end));
    noxtls_return_t rc = lb_end_flush_raw(end);
    (void)lb_alloc_set_owner(prev);
    return rc;
}

noxtls_return_t lb_end_send(lb_end_t *end, const uint8_t *data, uint32_t len)
{
    unsigned prev = lb_alloc_set_owner(lb_owner_of(end));
    noxtls_return_t rc = lb_end_send_raw(end, data, len);
    (void)lb_alloc_set_owner(prev);
    return rc;
}

noxtls_return_t lb_end_recv(lb_end_t *end, uint8_t *buf, uint32_t *len)
{
    unsigned prev = lb_alloc_set_owner(lb_owner_of(end));
    noxtls_return_t rc = lb_end_recv_raw(end, buf, len);
    (void)lb_alloc_set_owner(prev);
    return rc;
}

noxtls_return_t lb_end_close(lb_end_t *end)
{
    unsigned prev = lb_alloc_set_owner(lb_owner_of(end));
    noxtls_return_t rc = lb_end_close_raw(end);
    (void)lb_alloc_set_owner(prev);
    return rc;
}

uint16_t lb_end_cipher_suite(const lb_end_t *end)
{
    switch(end->proto) {
        case LB_PROTO_TLS13:
        case LB_PROTO_DTLS13:
            return end->t13->cipher_suite;
        case LB_PROTO_TLS12:
        case LB_PROTO_DTLS12:
            return end->t12->cipher_suite;
        case LB_PROTO_UNIFIED:
        default:
            return noxtls_tls_connection_get_cipher_suite(end->uni);
    }
}

uint16_t lb_end_version(const lb_end_t *end)
{
    if(end->proto == LB_PROTO_UNIFIED) {
        return noxtls_tls_connection_get_version(end->uni);
    }
    return ((end->proto == LB_PROTO_TLS13) || (end->proto == LB_PROTO_DTLS13)) ? TLS_VERSION_1_3 : TLS_VERSION_1_2;
}

static uint64_t lb_link_total(const lb_link_t *link)
{
    return link->to_client.total + link->to_server.total;
}

int g_lb_strict_unified;

static void lb_step_once(lb_end_t *end)
{
    end->last_rc = lb_end_step(end);
    end->done = (end->last_rc == NOXTLS_RETURN_SUCCESS) ? 1 : 0;
    /* noxtls_tls_connection_handshake() may be called again after WANT_WRITE: once the
     * version context is CONNECTED it only flushes (no workaround needed any more). */
}

int lb_pair_handshake(lb_pair_t *pair)
{
    uint32_t round;
    uint32_t idle = 0U;
    lb_end_t *c = &pair->client;
    lb_end_t *s = &pair->server;
    int is_dgram = pair->link->datagram;

    if((c->proto == LB_PROTO_DTLS12) && (s->proto == LB_PROTO_DTLS12)) {
        return lb_pair_handshake_coop(pair);
    }
    c->last_rc = NOXTLS_RETURN_WANT_READ;
    s->last_rc = NOXTLS_RETURN_WANT_READ;
    c->done = 0;
    s->done = 0;
    /* Stalls are caught by the idle counter below; the round cap is only a
     * backstop. 1-byte transport chunks with post-quantum key shares need
     * well over 4000 rounds. */
    for(round = 0U; round < 200000U; round++) {
        uint64_t before = lb_link_total(pair->link);
        uint32_t pend_before = lb_link_pending(pair->link, 1) + lb_link_pending(pair->link, 0);
        if((c->done == 0) && lb_is_progress(c->proto, c->last_rc)) {
            lb_step_once(c);
        }
        (void)lb_end_flush(c);
        if((s->done == 0) && lb_is_progress(s->proto, s->last_rc)) {
            lb_step_once(s);
        }
        (void)lb_end_flush(s);
        if(is_dgram != 0) {
            s_now_ms += 20U;
        }
        if((c->done != 0) && (s->done != 0)) {
            return 0;
        }
        if(!lb_is_progress(c->proto, c->last_rc) && (c->done == 0) &&
           !lb_is_progress(s->proto, s->last_rc) && (s->done == 0)) {
            break;
        }
        if((lb_link_total(pair->link) == before) &&
           ((lb_link_pending(pair->link, 1) + lb_link_pending(pair->link, 0)) == pend_before)) {
            idle++;
            if(idle > ((is_dgram != 0) ? 400U : 8U)) {
                break;
            }
        } else {
            idle = 0U;
        }
    }
    if((c->done != 0) && (s->done != 0)) {
        return 0;
    }
    if(getenv("LB_VERBOSE") != NULL) {
        lb_log("handshake incomplete: client rc=%d done=%d, server rc=%d done=%d (rounds=%u)", (int)c->last_rc,
               c->done, (int)s->last_rc, s->done, round);
    }
    return 1;
}

noxtls_return_t lb_recv_some(lb_pair_t *pair, lb_end_t *rx, uint8_t *buf, uint32_t *len)
{
    uint32_t cap = *len;
    uint32_t tries;
    noxtls_return_t rc = NOXTLS_RETURN_WANT_READ;
    lb_end_t *tx = (rx == &pair->client) ? &pair->server : &pair->client;

    for(tries = 0U; tries < 64U; tries++) {
        *len = cap;
        rc = lb_end_recv(rx, buf, len);
        if((rc == NOXTLS_RETURN_SUCCESS) && (*len > 0U)) {
            return rc;
        }
        if(!lb_is_progress(rx->proto, rc) && (rc != NOXTLS_RETURN_SUCCESS)) {
            return rc;
        }
        (void)lb_end_flush(tx);
        (void)lb_end_flush(rx);
        if(pair->link->datagram != 0) {
            s_now_ms += 20U;
        }
    }
    *len = 0U;
    return rc;
}

static uint8_t s_rx_buf[256U * 1024U];

int lb_transfer(lb_pair_t *pair, int client_to_server, const uint8_t *data, uint32_t len,
                uint32_t tx_chunk, uint32_t rx_chunk)
{
    lb_end_t *tx = (client_to_server != 0) ? &pair->client : &pair->server;
    lb_end_t *rx = (client_to_server != 0) ? &pair->server : &pair->client;
    uint32_t sent = 0U;
    uint32_t received = 0U;
    uint32_t stalls = 0U;

    LB_CHECK(len <= sizeof(s_rx_buf));
    LB_CHECK((tx_chunk > 0U) && (tx_chunk <= TLS_MAX_RECORD_SIZE));
    LB_CHECK(rx_chunk > 0U);
    if(len == 0U) {
        uint32_t got = sizeof(s_rx_buf);
        noxtls_return_t rc;
        LB_CHECK_OK(lb_end_send(tx, data, 0U));
        (void)lb_end_flush(tx);
        rc = lb_end_recv(rx, s_rx_buf, &got);
        /* Nothing was written, so the receiver must not produce data. */
        LB_CHECK((rc != NOXTLS_RETURN_SUCCESS) || (got == 0U));
        LB_CHECK(lb_is_progress(rx->proto, rc) || (rc == NOXTLS_RETURN_SUCCESS));
        return 0;
    }
    while(received < len) {
        if(sent < len) {
            uint32_t chunk = len - sent;
            noxtls_return_t rc;
            if(chunk > tx_chunk) {
                chunk = tx_chunk;
            }
            rc = lb_end_send(tx, &data[sent], chunk);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                lb_log("send of %u bytes at offset %u failed rc=%d", chunk, sent, (int)rc);
                return 1;
            }
            sent += chunk;
        }
        (void)lb_end_flush(tx);
        {
            uint32_t want = len - received;
            uint32_t got;
            noxtls_return_t rc;
            if(want > rx_chunk) {
                want = rx_chunk;
            }
            got = want;
            rc = lb_end_recv(rx, &s_rx_buf[received], &got);
            if((rc == NOXTLS_RETURN_SUCCESS) && (got > 0U)) {
                LB_CHECK(got <= want);
                received += got;
                stalls = 0U;
            } else if(lb_is_progress(rx->proto, rc) || (rc == NOXTLS_RETURN_SUCCESS)) {
                if(sent == len) {
                    stalls++;
                    /* Slow links (1-3 bytes per callback) need many polls per record. */
                    LB_CHECK(stalls < (4096U + (len * 4U)));
                }
            } else {
                lb_log("recv failed rc=%d after %u/%u bytes", (int)rc, received, len);
                return 1;
            }
        }
    }
    LB_CHECK_EQ(received, len);
    LB_CHECK(memcmp(s_rx_buf, data, len) == 0);
    /* No stray bytes may remain for the receiver (blocking DTLS 1.2 recv would wait instead). */
    if(rx->proto != LB_PROTO_DTLS12) {
        uint32_t extra = 16U;
        noxtls_return_t rc = lb_end_recv(rx, s_rx_buf, &extra);
        LB_CHECK((rc != NOXTLS_RETURN_SUCCESS) || (extra == 0U));
    }
    return 0;
}

int lb_close_and_observe(lb_pair_t *pair, int client_closes)
{
    lb_end_t *closer = (client_closes != 0) ? &pair->client : &pair->server;
    lb_end_t *peer = (client_closes != 0) ? &pair->server : &pair->client;
    uint8_t buf[64];
    uint32_t len = sizeof(buf);
    noxtls_return_t rc;
    uint32_t tries;

    LB_CHECK_OK(lb_end_close(closer));
    (void)lb_end_flush(closer);
    rc = NOXTLS_RETURN_WANT_READ;
    for(tries = 0U; (tries < 1024U) && lb_is_progress(peer->proto, rc); tries++) {
        len = sizeof(buf);
        rc = lb_end_recv(peer, buf, &len);
        (void)lb_end_flush(closer);
    }
    /* close_notify carries no data: recv must report the end of the stream, not bytes. */
    LB_CHECK(!((rc == NOXTLS_RETURN_SUCCESS) && (len > 0U)));
    LB_CHECK(!lb_is_progress(peer->proto, rc));
    {
        tls_state_t st = lb_field_state(peer);
        LB_CHECK((st == TLS_STATE_CLOSED) || (st == TLS_STATE_CLOSING));
    }
    /* Further sends on the closed side must fail. */
    LB_CHECK(lb_end_send(closer, buf, 1U) != NOXTLS_RETURN_SUCCESS);
    return 0;
}
