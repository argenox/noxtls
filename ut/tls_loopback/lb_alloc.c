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
* File:    lb_alloc.c
* Summary: Accounting/checking allocator used by the loopback, X.509 and RAM tests
*****************************************************************************/
/** @file lb_alloc.c
 * @brief Drop-in, test-only definition of the noxtls_memory.c symbol set.
 * See lb_alloc.h. Not thread-safe (the tests are single-threaded).
 */
#ifndef NOXTLS_TEST_ALLOCATOR_FAULT_INJECTION
#define NOXTLS_TEST_ALLOCATOR_FAULT_INJECTION 1
#endif

#include "noxtls_config.h"

#if NOXTLS_CONFIG_STATIC_MEMORY
/*
 * Static memory builds: the library's own region allocator is the allocator under
 * test. It is compiled into the test executable (with the fault-injection hooks)
 * and lb_alloc.h reports its accounting: live bytes of every registered arena,
 * allocation counts, injected failures. Owners are not tracked.
 */
#include "lb_alloc.h"
#include <stdio.h>
#include "../../noxtls-lib/common/noxtls_memory.c"

static unsigned s_lb_owner = LB_OWNER_FIXTURE;
static size_t s_lb_count_base;
static size_t s_lb_peak_base;

static size_t lb_static_live_blocks(void)
{
    size_t i;
    size_t blocks = 0U;
    for(i = 0U; i < (size_t)NOXTLS_STATIC_MAX_REGIONS; i++) {
        if((g_noxtls_regions[i] != NULL) && (g_noxtls_regions[i]->kind == NOXTLS_MEM_REGION_ARENA)) {
            blocks += g_noxtls_regions[i]->live_blocks;
        }
    }
    return blocks;
}

unsigned lb_alloc_set_owner(unsigned owner)
{
    unsigned previous = s_lb_owner;
    s_lb_owner = (owner < LB_OWNER_MAX) ? owner : LB_OWNER_FIXTURE;
    return previous;
}

void lb_alloc_get_owner_stats(unsigned owner, lb_alloc_owner_stats_t *stats)
{
    (void)owner;
    if(stats != NULL) {
        memset(stats, 0, sizeof(*stats));
    }
}

void lb_alloc_get_stats(lb_alloc_stats_t *stats)
{
    noxtls_mem_test_stats_t test;
    if(stats == NULL) {
        return;
    }
    noxtls_mem_test_get_stats(&test);
    memset(stats, 0, sizeof(*stats));
    stats->live_bytes = noxtls_mem_static_live_bytes();
    stats->live_blocks = lb_static_live_blocks();
    stats->peak_bytes = (stats->live_bytes > s_lb_peak_base) ? stats->live_bytes : s_lb_peak_base;
    stats->alloc_calls = noxtls_mem_static_allocation_count() - s_lb_count_base;
    stats->alloc_bytes = test.successful_bytes;
    stats->largest_block = test.largest_request;
}

void lb_alloc_reset_peak(void)
{
    s_lb_peak_base = noxtls_mem_static_live_bytes();
}

void lb_alloc_reset_counters(void)
{
    s_lb_count_base = noxtls_mem_static_allocation_count();
    noxtls_mem_test_stats_reset();
}

size_t lb_alloc_live_bytes(void)
{
    return noxtls_mem_static_live_bytes();
}

size_t lb_alloc_live_blocks(void)
{
    return lb_static_live_blocks();
}

size_t lb_alloc_dump_live(void)
{
    size_t i;
    for(i = 0U; i < (size_t)NOXTLS_STATIC_MAX_REGIONS; i++) {
        const noxtls_mem_region_t *r = g_noxtls_regions[i];
        if((r != NULL) && (r->kind == NOXTLS_MEM_REGION_ARENA) && (r->live_blocks != 0U)) {
            fprintf(stderr, "  live region %s: %lu bytes in %lu blocks\n", r->name,
                    (unsigned long)r->live_bytes, (unsigned long)r->live_blocks);
        }
    }
    return lb_static_live_blocks();
}

void lb_alloc_fail_after(size_t allocations_before_failure)
{
    if(allocations_before_failure == SIZE_MAX) {
        noxtls_mem_test_fail_reset();
    } else {
        noxtls_mem_test_fail_after(allocations_before_failure);
    }
}

size_t lb_alloc_failed_calls(void)
{
    noxtls_mem_test_stats_t test;
    noxtls_mem_test_get_stats(&test);
    return test.failed_allocations;
}

#else /* !NOXTLS_CONFIG_STATIC_MEMORY */

#include "lb_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "noxtls_memory.h"
#include "noxtls_memory_test.h"

#define LB_HEAD_MAGIC   0x4C42484DU   /* "LBHM" */
#define LB_FREED_MAGIC  0x4C424644U   /* "LBFD" */
#define LB_TAIL_BYTES   16U
#define LB_TAIL_FILL    0xA5U
#define LB_ALLOC_FILL   0xCDU
#define LB_FREE_FILL    0xDDU
/* Header modelled on the static pool's mem_block_header_t plus alignment. */
#define LB_POOL_HEADER  32U

typedef struct lb_block
{
    struct lb_block *prev;
    struct lb_block *next;
    size_t size;
    size_t seq;
    const char *file;
    const char *function;
    uint32_t line;
    uint32_t magic;
    uint32_t pad;
    uint32_t reserved;
} lb_block_t;

/* Payload follows the header; keep it 16-byte aligned. */
#define LB_HEADER_SIZE ((sizeof(lb_block_t) + 15U) & ~(size_t)15U)

static lb_block_t *s_head;
static lb_alloc_stats_t s_stats;
static size_t s_pool_live;
static size_t s_seq;
static size_t s_fail_after = SIZE_MAX;
static size_t s_failed_calls;
static noxtls_mem_error_info_t s_last_error;
static int s_last_error_valid;
static noxtls_mem_test_stats_t s_test_stats;
#define LB_QUARANTINE 512U
static lb_block_t *s_quarantine[LB_QUARANTINE];
static size_t s_quarantine_pos;
static unsigned s_owner = LB_OWNER_FIXTURE;
static lb_alloc_owner_stats_t s_owner_stats[LB_OWNER_MAX];

static void lb_die(const char *what, const lb_block_t *block)
{
    fprintf(stderr, "lb_alloc: FATAL %s (block size=%lu seq=%lu)\n", what,
            (unsigned long)((block != NULL) ? block->size : 0U),
            (unsigned long)((block != NULL) ? block->seq : 0U));
    fflush(stderr);
    abort();
}

static uint8_t *lb_payload(lb_block_t *block)
{
    return (uint8_t *)block + LB_HEADER_SIZE;
}

static lb_block_t *lb_block_of(void *ptr)
{
    return (lb_block_t *)(void *)((uint8_t *)ptr - LB_HEADER_SIZE);
}

static size_t lb_pool_cost(size_t size)
{
    return ((size + 7U) & ~(size_t)7U) + LB_POOL_HEADER;
}

static void lb_check_tail(lb_block_t *block)
{
    const uint8_t *tail = lb_payload(block) + block->size;
    uint32_t i;
    for(i = 0U; i < LB_TAIL_BYTES; i++) {
        if(tail[i] != LB_TAIL_FILL) {
            lb_die("heap buffer overrun detected on free (tail canary damaged)", block);
        }
    }
}

static void lb_record_failure(noxtls_mem_operation_t op, size_t size, const char *file, uint32_t line,
                              const char *function)
{
    memset(&s_last_error, 0, sizeof(s_last_error));
    s_last_error.operation = op;
    s_last_error.reason = NOXTLS_MEM_FAILURE_INJECTED;
    s_last_error.allocator_mode = NOXTLS_MEM_ALLOCATOR_MODE_SYSTEM;
    s_last_error.source_line = line;
    s_last_error.requested_bytes = size;
    s_last_error.largest_available_block = NOXTLS_MEM_SIZE_UNKNOWN;
    s_last_error.minimum_additional_bytes = NOXTLS_MEM_SIZE_UNKNOWN;
    s_last_error.pool_capacity = NOXTLS_MEM_SIZE_UNKNOWN;
    s_last_error.pool_used = s_stats.live_bytes;
    s_last_error.source_file = file;
    s_last_error.source_function = function;
    s_last_error_valid = 1;
}

static int lb_should_fail(void)
{
    if(s_fail_after == SIZE_MAX) {
        return 0;
    }
    if(s_fail_after == 0U) {
        s_failed_calls++;
        return 1;
    }
    s_fail_after--;
    return 0;
}

static size_t s_trace_seq = SIZE_MAX;
static int s_trace_init;
static int s_trace_all;

/* LB_TRACE_ALL=1: print every allocation and free with its source location (audits). */
static void lb_trace_all(char what, const lb_block_t *block)
{
    if((s_trace_all != 0) && (block != NULL)) {
        const char *file = (block->file != NULL) ? block->file : "?";
        const char *slash = strrchr(file, '/');
        const char *bslash = strrchr(file, '\\');
        if((bslash != NULL) && ((slash == NULL) || (bslash > slash))) {
            slash = bslash;
        }
        fprintf(stderr, "lb_trace %c %lu %lu %s:%u %s owner=%u\n", what, (unsigned long)block->seq,
                (unsigned long)block->size, (slash != NULL) ? slash + 1 : file, (unsigned)block->line,
                (block->function != NULL) ? block->function : "?", (unsigned)block->pad);
    }
}

/* LB_TRACE_SEQ=<n>: report the caller addresses that allocate and free allocation #n. */
static void lb_trace(const char *what, const lb_block_t *block, void *caller)
{
    if(s_trace_init == 0) {
        const char *env = getenv("LB_TRACE_SEQ");
        const char *all = getenv("LB_TRACE_ALL");
        s_trace_init = 1;
        s_trace_all = (all != NULL) && (all[0] == '1');
        if(env != NULL) {
            s_trace_seq = (size_t)strtoul(env, NULL, 10);
        }
    }
    if((block != NULL) && (block->seq == s_trace_seq)) {
#if defined(_WIN32)
        /* Report the caller as an image-relative address (map with llvm-nm / addr2line). */
        extern char __ImageBase;
        fprintf(stderr, "lb_alloc: %s of allocation #%lu (%lu bytes) from image+0x%lx\n", what,
                (unsigned long)block->seq, (unsigned long)block->size,
                (unsigned long)((uintptr_t)caller - (uintptr_t)&__ImageBase));
#else
        fprintf(stderr, "lb_alloc: %s of allocation #%lu (%lu bytes) from %p\n", what,
                (unsigned long)block->seq, (unsigned long)block->size, caller);
#endif
    }
}

static void *lb_alloc(size_t size, noxtls_mem_operation_t op, const char *file, uint32_t line,
                      const char *function)
{
    lb_block_t *block;

    if(size == 0U) {
        return NULL;
    }
    s_test_stats.allocation_attempts++;
    s_test_stats.requested_bytes += size;
    if(size > s_test_stats.largest_request) {
        s_test_stats.largest_request = size;
    }
    if((size > (SIZE_MAX / 2U)) || (lb_should_fail() != 0)) {
        s_test_stats.failed_allocations++;
        lb_record_failure(op, size, file, line, function);
        return NULL;
    }
    block = (lb_block_t *)malloc(LB_HEADER_SIZE + size + LB_TAIL_BYTES);
    if(block == NULL) {
        s_test_stats.failed_allocations++;
        lb_record_failure(op, size, file, line, function);
        return NULL;
    }
    block->size = size;
    block->seq = ++s_seq;
    block->file = file;
    block->function = function;
    block->line = line;
    block->magic = LB_HEAD_MAGIC;
    block->pad = s_owner;
    {
        lb_alloc_owner_stats_t *o = &s_owner_stats[s_owner];
        o->live_bytes += size;
        o->live_blocks++;
        o->alloc_calls++;
        if(o->live_bytes > o->peak_bytes) {
            o->peak_bytes = o->live_bytes;
        }
    }
    block->prev = NULL;
    block->next = s_head;
    if(s_head != NULL) {
        s_head->prev = block;
    }
    s_head = block;
    memset(lb_payload(block), LB_ALLOC_FILL, size);
    memset(lb_payload(block) + size, LB_TAIL_FILL, LB_TAIL_BYTES);

    s_test_stats.successful_allocations++;
    s_test_stats.successful_bytes += size;
    s_stats.alloc_calls++;
    s_stats.alloc_bytes += size;
    if(size > s_stats.largest_block) {
        s_stats.largest_block = size;
    }
    s_stats.live_bytes += size;
    s_stats.live_blocks++;
    s_pool_live += lb_pool_cost(size);
    if(s_stats.live_bytes > s_stats.peak_bytes) {
        s_stats.peak_bytes = s_stats.live_bytes;
    }
    if(s_stats.live_blocks > s_stats.peak_blocks) {
        s_stats.peak_blocks = s_stats.live_blocks;
    }
    if(s_pool_live > s_stats.pool_peak_bytes) {
        s_stats.pool_peak_bytes = s_pool_live;
    }
    return lb_payload(block);
}

static lb_block_t *lb_validate(void *ptr)
{
    lb_block_t *block = lb_block_of(ptr);
    if(block->magic == LB_FREED_MAGIC) {
        lb_die("double free", block);
    }
    if(block->magic != LB_HEAD_MAGIC) {
        lb_die("free of a pointer not returned by noxtls_malloc (or header underrun)", NULL);
    }
    lb_check_tail(block);
    return block;
}

static void lb_trace_all(char what, const lb_block_t *block);

static void lb_release(lb_block_t *block)
{
    lb_trace_all('-', block);
    if(block->prev != NULL) {
        block->prev->next = block->next;
    } else {
        s_head = block->next;
    }
    if(block->next != NULL) {
        block->next->prev = block->prev;
    }
    s_stats.live_bytes -= block->size;
    s_stats.live_blocks--;
    s_owner_stats[block->pad % LB_OWNER_MAX].live_bytes -= block->size;
    s_owner_stats[block->pad % LB_OWNER_MAX].live_blocks--;
    s_pool_live -= lb_pool_cost(block->size);
    s_stats.free_calls++;
    memset(lb_payload(block), LB_FREE_FILL, block->size);
    block->magic = LB_FREED_MAGIC;
    /* Quarantine recently freed blocks so a double free still sees LB_FREED_MAGIC. */
    if(s_quarantine[s_quarantine_pos] != NULL) {
        free(s_quarantine[s_quarantine_pos]);
    }
    s_quarantine[s_quarantine_pos] = block;
    s_quarantine_pos = (s_quarantine_pos + 1U) % LB_QUARANTINE;
}

static void *lb_traced(void *ptr, void *caller)
{
    if(ptr != NULL) {
        lb_trace("allocation", lb_block_of(ptr), caller);
        lb_trace_all('+', lb_block_of(ptr));
    }
    return ptr;
}

void *noxtls_malloc_at(size_t size, const char *file, uint32_t line, const char *function)
{
    return lb_traced(lb_alloc(size, NOXTLS_MEM_OPERATION_MALLOC, file, line, function),
                     __builtin_return_address(0));
}

void *noxtls_malloc(size_t size)
{
    return lb_traced(lb_alloc(size, NOXTLS_MEM_OPERATION_MALLOC, NULL, 0U, NULL), __builtin_return_address(0));
}

void noxtls_free(void *ptr)
{
    if(ptr != NULL) {
        lb_block_t *block = lb_validate(ptr);
        lb_trace("free", block, __builtin_return_address(0));
        lb_release(block);
    }
}

static void *lb_calloc_impl(size_t nmemb, size_t size, const char *file, uint32_t line, const char *function)
{
    void *ptr;
    if((nmemb != 0U) && (size > (SIZE_MAX / nmemb))) {
        return NULL;
    }
    ptr = lb_alloc(nmemb * size, NOXTLS_MEM_OPERATION_CALLOC, file, line, function);
    if(ptr != NULL) {
        memset(ptr, 0, nmemb * size);
    }
    return ptr;
}

void *noxtls_calloc_at(size_t nmemb, size_t size, const char *file, uint32_t line, const char *function)
{
    return lb_traced(lb_calloc_impl(nmemb, size, file, line, function), __builtin_return_address(0));
}

void *noxtls_calloc(size_t nmemb, size_t size)
{
    return lb_traced(lb_calloc_impl(nmemb, size, NULL, 0U, NULL), __builtin_return_address(0));
}

static void *lb_realloc_impl(void *ptr, size_t size, const char *file, uint32_t line, const char *function)
{
    lb_block_t *old_block;
    void *fresh;

    if(ptr == NULL) {
        return lb_alloc(size, NOXTLS_MEM_OPERATION_REALLOC, file, line, function);
    }
    old_block = lb_validate(ptr);
    if(size == 0U) {
        lb_release(old_block);
        return NULL;
    }
    fresh = lb_alloc(size, NOXTLS_MEM_OPERATION_REALLOC, file, line, function);
    if(fresh == NULL) {
        return NULL;
    }
    memcpy(fresh, ptr, (old_block->size < size) ? old_block->size : size);
    lb_release(old_block);
    return fresh;
}

void *noxtls_realloc_at(void *ptr, size_t size, const char *file, uint32_t line, const char *function)
{
    return lb_traced(lb_realloc_impl(ptr, size, file, line, function), __builtin_return_address(0));
}

void *noxtls_realloc(void *ptr, size_t size)
{
    return lb_traced(lb_realloc_impl(ptr, size, NULL, 0U, NULL), __builtin_return_address(0));
}

noxtls_return_t noxtls_mem_get_last_error(noxtls_mem_error_info_t *info)
{
    if(info == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(s_last_error_valid == 0) {
        memset(info, 0, sizeof(*info));
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
    *info = s_last_error;
    return NOXTLS_RETURN_SUCCESS;
}

void noxtls_mem_clear_last_error(void)
{
    memset(&s_last_error, 0, sizeof(s_last_error));
    s_last_error_valid = 0;
}

noxtls_return_t noxtls_mem_init(uint8_t *buffer, size_t buffer_size)
{
    (void)buffer;
    (void)buffer_size;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_mem_cleanup(void)
{
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_mem_get_stats(size_t *total_allocated, size_t *total_used, size_t *max_used)
{
    if(total_allocated != NULL) {
        *total_allocated = s_stats.alloc_bytes;
    }
    if(total_used != NULL) {
        *total_used = s_stats.live_bytes;
    }
    if(max_used != NULL) {
        *max_used = s_stats.peak_bytes;
    }
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_mem_get_bucket_stats(noxtls_mem_bucket_stats_t *stats)
{
    if(stats == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    memset(stats, 0, sizeof(*stats));
    stats->allocator_mode = NOXTLS_MEM_ALLOCATOR_MODE_SYSTEM;
    return NOXTLS_RETURN_FAILED;
}

/* noxtls_memory_test.h hooks. */
void noxtls_mem_test_fail_after(size_t allocations_before_failure)
{
    s_fail_after = allocations_before_failure;
}

void noxtls_mem_test_fail_reset(void)
{
    s_fail_after = SIZE_MAX;
}

void noxtls_mem_test_stats_reset(void)
{
    memset(&s_test_stats, 0, sizeof(s_test_stats));
}

void noxtls_mem_test_get_stats(noxtls_mem_test_stats_t *stats)
{
    if(stats != NULL) {
        *stats = s_test_stats;
    }
}

/* lb_alloc.h API. */
void lb_alloc_get_stats(lb_alloc_stats_t *stats)
{
    if(stats != NULL) {
        *stats = s_stats;
    }
}

void lb_alloc_reset_peak(void)
{
    unsigned i;
    s_stats.peak_bytes = s_stats.live_bytes;
    s_stats.peak_blocks = s_stats.live_blocks;
    s_stats.pool_peak_bytes = s_pool_live;
    for(i = 0U; i < LB_OWNER_MAX; i++) {
        s_owner_stats[i].peak_bytes = s_owner_stats[i].live_bytes;
    }
}

unsigned lb_alloc_set_owner(unsigned owner)
{
    unsigned previous = s_owner;
    s_owner = (owner < LB_OWNER_MAX) ? owner : LB_OWNER_FIXTURE;
    return previous;
}

void lb_alloc_get_owner_stats(unsigned owner, lb_alloc_owner_stats_t *stats)
{
    if((stats != NULL) && (owner < LB_OWNER_MAX)) {
        *stats = s_owner_stats[owner];
    }
}

void lb_alloc_reset_counters(void)
{
    unsigned i;
    for(i = 0U; i < LB_OWNER_MAX; i++) {
        s_owner_stats[i].alloc_calls = 0U;
    }
    s_stats.alloc_calls = 0U;
    s_stats.alloc_bytes = 0U;
    s_stats.free_calls = 0U;
    s_stats.largest_block = 0U;
    s_failed_calls = 0U;
}

size_t lb_alloc_live_bytes(void)
{
    return s_stats.live_bytes;
}

size_t lb_alloc_live_blocks(void)
{
    return s_stats.live_blocks;
}

size_t lb_alloc_dump_live(void)
{
    size_t count = 0U;
    const lb_block_t *block;
    for(block = s_head; block != NULL; block = block->next) {
        if(count < 64U) {
            fprintf(stderr, "  live block: %lu bytes (allocation #%lu)\n", (unsigned long)block->size,
                    (unsigned long)block->seq);
        }
        count++;
    }
    return count;
}

void lb_alloc_fail_after(size_t allocations_before_failure)
{
    s_fail_after = allocations_before_failure;
}

size_t lb_alloc_failed_calls(void)
{
    return s_failed_calls;
}

#endif /* NOXTLS_CONFIG_STATIC_MEMORY */
