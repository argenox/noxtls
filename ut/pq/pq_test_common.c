/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Licensed under the GNU General Public License v2.0 or later,
* or alternatively under a commercial license from
* Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
*
* File:    pq_test_common.c
* Summary: Shared harness for the post-quantum known-answer tests.
*
*****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pq_test.h"
#include "noxtls_config.h"
#include "drbg/noxtls_drbg.h"
#include "mdigest/sha3/noxtls_sha3.h"

uint32_t g_pq_test_failures = 0U;
uint32_t g_pq_test_checks = 0U;

static noxtls_sha3_ctx_t g_pq_rng;
static uint8_t g_pq_rng_ready = 0U;

void pq_test_begin(const char *suite)
{
    g_pq_test_failures = 0U;
    g_pq_test_checks = 0U;
    printf("[pq] %s: start\n", suite);
}

int pq_test_end(const char *suite)
{
    pq_test_rng_restore();
    printf("[pq] %s: %lu checks, %lu failures -> %s\n",
           suite,
           (unsigned long)g_pq_test_checks,
           (unsigned long)g_pq_test_failures,
           (g_pq_test_failures == 0U) ? "PASS" : "FAIL");
    return (int)g_pq_test_failures;
}

void pq_test_fail(const char *file, int line, const char *what)
{
    g_pq_test_failures += 1U;
    printf("  FAIL %s:%d: %s\n", file, line, what);
}

void pq_test_fail_rc(const char *file, int line, const char *what, int got, int expected)
{
    g_pq_test_failures += 1U;
    printf("  FAIL %s:%d: %s (rc=%d, expected %d)\n", file, line, what, got, expected);
}

static void pq_test_dump(const char *label, const uint8_t *p, uint32_t len)
{
    uint32_t i = 0U;
    uint32_t n = (len > 32U) ? 32U : len;

    printf("    %s:", label);
    for(i = 0U; i < n; i += 1U) {
        printf("%02x", (unsigned)p[i]);
    }
    printf("%s\n", (len > n) ? "..." : "");
}

void pq_test_fail_mem(const char *file, int line, const char *what,
                      const uint8_t *got, const uint8_t *expected, uint32_t len)
{
    uint32_t first = 0U;

    g_pq_test_failures += 1U;
    while((first < len) && (got[first] == expected[first])) {
        first += 1U;
    }
    printf("  FAIL %s:%d: %s (len=%lu, first diff at %lu)\n",
           file, line, what, (unsigned long)len, (unsigned long)first);
    pq_test_dump("got     ", &got[first], len - first);
    pq_test_dump("expected", &expected[first], len - first);
}

int pq_test_memeq(const void *a, const void *b, uint32_t len)
{
    if(len == 0U) {
        return 1;
    }
    if((a == NULL) || (b == NULL)) {
        return 0;
    }
    return (memcmp(a, b, (size_t)len) == 0) ? 1 : 0;
}

void pq_test_rng_bytes(uint8_t *out, uint32_t len)
{
    if(g_pq_rng_ready == 0U) {
        pq_test_rng_seed_label("pq-test-default", 0U);
    }
    (void)noxtls_shake256_squeeze(&g_pq_rng, out, len);
}

static noxtls_return_t pq_test_entropy_cb(uint8_t *out, uint32_t len)
{
    if(out == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    pq_test_rng_bytes(out, len);
    return NOXTLS_RETURN_SUCCESS;
}

void pq_test_rng_seed(const uint8_t *seed, uint32_t seed_len)
{
    static const uint8_t domain[] = "noxtls-pq-test-rng";

    (void)noxtls_shake256_init(&g_pq_rng);
    (void)noxtls_shake256_update(&g_pq_rng, domain, (uint32_t)(sizeof(domain) - 1U));
    (void)noxtls_shake256_update(&g_pq_rng, seed, seed_len);
    (void)noxtls_shake256_final(&g_pq_rng);
    g_pq_rng_ready = 1U;
    noxtls_drbg_set_entropy_callback(pq_test_entropy_cb);
    noxtls_drbg_set_entropy_source(NOXTLS_ENTROPY_SOURCE_CUSTOM);
}

void pq_test_rng_seed_label(const char *label, uint32_t counter)
{
    uint8_t buf[68];
    uint32_t n = 0U;

    while((label[n] != '\0') && (n < 64U)) {
        buf[n] = (uint8_t)label[n];
        n += 1U;
    }
    buf[n] = (uint8_t)(counter >> 24U);
    buf[n + 1U] = (uint8_t)(counter >> 16U);
    buf[n + 2U] = (uint8_t)(counter >> 8U);
    buf[n + 3U] = (uint8_t)counter;
    pq_test_rng_seed(buf, n + 4U);
}

void pq_test_rng_restore(void)
{
    noxtls_drbg_set_entropy_callback(NULL);
    noxtls_drbg_set_entropy_source(NOXTLS_ENTROPY_SOURCE_AUTO);
    g_pq_rng_ready = 0U;
}

#if defined(NOXTLS_PQ_TEST_ARM)
uint32_t pq_arm_probe_begin(void);
void pq_arm_probe_end(uint32_t mark, uint32_t *stack_bytes, uint32_t *heap_bytes);
#endif

uint32_t pq_test_probe_begin(void)
{
#if defined(NOXTLS_PQ_TEST_ARM)
    return pq_arm_probe_begin();
#else
    return 0U;
#endif
}

void pq_test_probe_end(uint32_t mark, const char *label)
{
#if defined(NOXTLS_PQ_TEST_ARM)
    uint32_t stack_bytes = 0U;
    uint32_t heap_bytes = 0U;

    pq_arm_probe_end(mark, &stack_bytes, &heap_bytes);
    printf("[probe] %s stack=%lu heap=%lu\n", label, (unsigned long)stack_bytes, (unsigned long)heap_bytes);
#else
    (void)mark;
    (void)label;
#endif
}
