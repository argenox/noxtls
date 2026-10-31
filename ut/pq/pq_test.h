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
* File:    pq_test.h
* Summary: Minimal freestanding-friendly harness shared by the post-quantum
*          known-answer tests (host ctest executables and the Cortex-M
*          semihosting image).
*
*****************************************************************************/

#ifndef NOXTLS_PQ_TEST_H_
#define NOXTLS_PQ_TEST_H_

#include <stdint.h>
#include <stdio.h>

#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Every PQ test translation unit provides one entry point
 *     int noxtls_pq_test_<alg>(void);   returns the number of failed checks
 * and main() via NOXTLS_PQ_TEST_MAIN(fn).  The same source is built as a
 * host ctest executable and as a Cortex-M semihosting ELF (ut/pq/arm, with
 * NOXTLS_PQ_TEST_ARM and NOXTLS_PQ_TEST_QUICK defined).
 *
 * Tests must not put large buffers on the stack (the Cortex-M image runs
 * with a small main stack); use file-scope static storage instead.
 */

/** Number of failed checks since the last pq_test_begin(). */
extern uint32_t g_pq_test_failures;
/** Number of executed checks since the last pq_test_begin(). */
extern uint32_t g_pq_test_checks;

void pq_test_begin(const char *suite);
int pq_test_end(const char *suite);

void pq_test_fail(const char *file, int line, const char *what);
void pq_test_fail_rc(const char *file, int line, const char *what, int got, int expected);
void pq_test_fail_mem(const char *file, int line, const char *what,
                      const uint8_t *got, const uint8_t *expected, uint32_t len);

#define PQ_CHECK(cond, what) \
    do { g_pq_test_checks += 1U; if(!(cond)) { pq_test_fail(__FILE__, __LINE__, (what)); } } while(0 == 1)

#define PQ_CHECK_RC(rc, expected, what) \
    do { int pq_rc_ = (int)(rc); int pq_exp_ = (int)(expected); g_pq_test_checks += 1U; \
         if(pq_rc_ != pq_exp_) { pq_test_fail_rc(__FILE__, __LINE__, (what), pq_rc_, pq_exp_); } } while(0 == 1)

#define PQ_CHECK_MEM(got, expected, len, what) \
    do { g_pq_test_checks += 1U; \
         if(pq_test_memeq((got), (expected), (uint32_t)(len)) == 0) { \
             pq_test_fail_mem(__FILE__, __LINE__, (what), (const uint8_t *)(got), \
                              (const uint8_t *)(expected), (uint32_t)(len)); } } while(0 == 1)

/** @return 1 when equal, 0 otherwise (non-constant-time; tests only). */
int pq_test_memeq(const void *a, const void *b, uint32_t len);

/**
 * Install a deterministic entropy source (SHAKE256(seed) stream) as the
 * library's custom entropy callback.  All DRBG instantiations and direct
 * noxtls_drbg_get_entropy() users then consume reproducible bytes.
 */
void pq_test_rng_seed(const uint8_t *seed, uint32_t seed_len);
/** Seed the deterministic stream from a short label plus a counter. */
void pq_test_rng_seed_label(const char *label, uint32_t counter);
/** Restore the default (AUTO) entropy source. */
void pq_test_rng_restore(void);
/** Draw bytes from the deterministic stream (for test-side randomness). */
void pq_test_rng_bytes(uint8_t *out, uint32_t len);

/**
 * Per-operation resource probes.  On the Cortex-M semihosting image
 * (NOXTLS_PQ_TEST_ARM) pq_test_probe_begin() paints the unused stack and
 * restarts the live-heap peak; pq_test_probe_end() prints
 * "[probe] <label> stack=<bytes> heap=<bytes>" for the calls made in between
 * (stack depth below the caller's frame, peak live heap bytes requested).
 * On the host both are no-ops.
 */
uint32_t pq_test_probe_begin(void);
void pq_test_probe_end(uint32_t mark, const char *label);

#define NOXTLS_PQ_TEST_MAIN(fn) \
    int main(void) { return ((fn)() == 0) ? 0 : 1; }

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_PQ_TEST_H_ */
