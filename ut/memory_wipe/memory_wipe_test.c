/*
 * SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
 *
 * Regression coverage for allocator memory hygiene (audit issues 166, 169).
 *
 * Static builds: noxtls_free must clear the whole payload of bucket and
 * fallback blocks, noxtls_realloc must not leave the old payload behind when
 * it moves a block, and noxtls_mem_cleanup must clear the pool. The pool is
 * caller-supplied, so the test can scan it for a marker after each step.
 *
 * Host builds: the freed memory cannot be inspected safely, so the test checks
 * that noxtls_realloc keeps the payload intact on grow and shrink.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "noxtls_memory.h"

#define MARKER 0xA5U

static int failures = 0;

static void expect(int condition, const char *message)
{
    if(!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        failures += 1;
    }
}

#if NOXTLS_USE_STATIC_BUFFERS
static uint8_t pool[192U * 1024U];

/* Longest run of MARKER bytes anywhere in the pool. */
static size_t marker_run(void)
{
    size_t i;
    size_t run = 0U;
    size_t best = 0U;

    for(i = 0U; i < sizeof(pool); i += 1U) {
        if(pool[i] == MARKER) {
            run += 1U;
            if(run > best) {
                best = run;
            }
        } else {
            run = 0U;
        }
    }
    return best;
}

static void test_free_clears(size_t size)
{
    uint8_t *p = (uint8_t *)noxtls_malloc(size);

    expect(p != NULL, "malloc");
    if(p == NULL) {
        return;
    }
    memset(p, MARKER, size);
    expect(marker_run() >= size, "marker present before free");
    noxtls_free(p);
    expect(marker_run() < 4U, "free clears the payload");
}

static void test_realloc_move_clears(size_t from, size_t to)
{
    uint8_t *p = (uint8_t *)noxtls_malloc(from);
    uint8_t *q;
    size_t i;
    int intact = 1;

    expect(p != NULL, "malloc before realloc");
    if(p == NULL) {
        return;
    }
    memset(p, MARKER, from);
    q = (uint8_t *)noxtls_realloc(p, to);
    expect(q != NULL, "realloc grow");
    if(q == NULL) {
        noxtls_free(p);
        return;
    }
    for(i = 0U; i < from; i += 1U) {
        if(q[i] != MARKER) {
            intact = 0;
        }
    }
    expect(intact, "realloc keeps the payload");
    /* Only the copy in the new block may hold the marker. */
    memset(q, 0, from);
    expect(marker_run() < 4U, "realloc move leaves no copy in the old block");
    noxtls_free(q);
}

static void test_cleanup_clears(void)
{
    uint8_t *a = (uint8_t *)noxtls_malloc(48U);
    uint8_t *b = (uint8_t *)noxtls_malloc(20000U);

    expect((a != NULL) && (b != NULL), "malloc before cleanup");
    if(a != NULL) {
        memset(a, MARKER, 48U);
    }
    if(b != NULL) {
        memset(b, MARKER, 20000U);
    }
    expect(noxtls_mem_cleanup() == NOXTLS_RETURN_SUCCESS, "cleanup");
    expect(marker_run() == 0U, "cleanup clears blocks still allocated");
}
#endif

int main(void)
{
#if NOXTLS_USE_STATIC_BUFFERS
    memset(pool, 0, sizeof(pool));
    expect(noxtls_mem_init(pool, sizeof(pool)) == NOXTLS_RETURN_SUCCESS, "mem_init");
    test_free_clears(24U);
    test_free_clears(1000U);
    test_free_clears(20000U);
    test_realloc_move_clears(40U, 900U);
    test_realloc_move_clears(3000U, 30000U);
    test_cleanup_clears();
#else
    uint8_t *p = (uint8_t *)noxtls_malloc(64U);
    uint8_t *q;
    size_t i;
    int intact = 1;

    expect(p != NULL, "malloc");
    if(p != NULL) {
        for(i = 0U; i < 64U; i += 1U) {
            p[i] = (uint8_t)i;
        }
        q = (uint8_t *)noxtls_realloc(p, 4096U);
        expect(q != NULL, "realloc grow");
        if(q != NULL) {
            for(i = 0U; i < 64U; i += 1U) {
                if(q[i] != (uint8_t)i) {
                    intact = 0;
                }
            }
            p = (uint8_t *)noxtls_realloc(q, 16U);
            expect(p != NULL, "realloc shrink");
            if(p != NULL) {
                for(i = 0U; i < 16U; i += 1U) {
                    if(p[i] != (uint8_t)i) {
                        intact = 0;
                    }
                }
                noxtls_free(p);
            } else {
                noxtls_free(q);
            }
        }
        expect(intact, "realloc keeps the payload");
    }
    expect(noxtls_realloc(NULL, 0U) == NULL, "realloc(NULL, 0)");
#endif
    if(failures == 0) {
        printf("memory_wipe_test: PASS\n");
    }
    return (failures == 0) ? 0 : 1;
}
