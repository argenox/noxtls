/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* NoxTLS-Commercial
*
* Test-only controls for deterministic allocator failure injection.
*****************************************************************************/

#ifndef _NOXTLS_MEMORY_TEST_H_
#define _NOXTLS_MEMORY_TEST_H_

#include <stddef.h>

#if !defined(NOXTLS_TEST_ALLOCATOR_FAULT_INJECTION)
#error "noxtls_memory_test.h is available only in allocator fault-injection test builds"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    size_t allocation_attempts;
    size_t successful_allocations;
    size_t failed_allocations;
    size_t requested_bytes;
    size_t successful_bytes;
    size_t largest_request;
} noxtls_mem_test_stats_t;

/** Fail every non-zero allocation after this many allocation attempts. */
void noxtls_mem_test_fail_after(size_t allocations_before_failure);

/** Disable deterministic allocation failures. */
void noxtls_mem_test_fail_reset(void);

/** Reset allocation counters without changing the configured failure point. */
void noxtls_mem_test_stats_reset(void);

/** Copy allocation counters collected since the last statistics reset. */
void noxtls_mem_test_get_stats(noxtls_mem_test_stats_t *stats);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_MEMORY_TEST_H_ */
