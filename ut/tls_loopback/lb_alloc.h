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
* File:    lb_alloc.h
* Summary: Accounting/checking allocator used by the loopback, X.509 and RAM tests
*****************************************************************************/
/** @file lb_alloc.h
 * @brief Test-only replacement for noxtls-lib/common/noxtls_memory.c.
 *
 * lb_alloc.c defines every symbol of noxtls_memory.c (noxtls_malloc/free/...,
 * noxtls_mem_* and the noxtls_memory_test.h fault-injection hooks). Linking it
 * into a test executable makes the linker skip the archive member of
 * libnoxtls_common, so every library allocation goes through it. It keeps
 * exact live/peak accounting (requested payload bytes), detects invalid or
 * double frees and heap overruns (tail canary checked on free), and poisons
 * freed memory. Any corruption aborts the process with a diagnostic.
 */
#ifndef LB_ALLOC_H
#define LB_ALLOC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Snapshot of allocator accounting. Byte counts are requested payload bytes. */
typedef struct
{
    size_t live_bytes;        /**< Bytes currently allocated. */
    size_t live_blocks;       /**< Blocks currently allocated. */
    size_t peak_bytes;        /**< High-water mark of live_bytes since the last peak reset. */
    size_t peak_blocks;       /**< High-water mark of live_blocks since the last peak reset. */
    size_t pool_peak_bytes;   /**< Peak of sum(align8(size) + 32-byte header): estimate of a first-fit static pool. */
    size_t alloc_calls;       /**< Successful allocations (malloc/calloc/realloc) since the last counter reset. */
    size_t alloc_bytes;       /**< Bytes requested by those allocations. */
    size_t free_calls;        /**< Non-NULL frees since the last counter reset. */
    size_t largest_block;     /**< Largest single allocation since the last counter reset. */
} lb_alloc_stats_t;

/**
 * Allocation owners: every block is attributed to the owner that was current when it
 * was allocated (the fixture switches owner around client / server library calls).
 */
#define LB_OWNER_CLIENT  0U
#define LB_OWNER_SERVER  1U
#define LB_OWNER_FIXTURE 2U   /* test code, keys (default) */
#define LB_OWNER_GLOBAL  3U   /* library-global state such as the trust store */
#define LB_OWNER_MAX     4U

typedef struct
{
    size_t live_bytes;
    size_t peak_bytes;     /* since the last lb_alloc_reset_peak() */
    size_t alloc_calls;    /* since the last lb_alloc_reset_counters() */
    size_t live_blocks;
} lb_alloc_owner_stats_t;

/** Select the owner of subsequent allocations; returns the previous owner. */
unsigned lb_alloc_set_owner(unsigned owner);
/** Copy one owner's statistics. */
void lb_alloc_get_owner_stats(unsigned owner, lb_alloc_owner_stats_t *stats);

/** Copy current statistics. */
void lb_alloc_get_stats(lb_alloc_stats_t *stats);
/** Restart peak tracking from the current live values. */
void lb_alloc_reset_peak(void);
/** Zero the call counters (alloc_calls, alloc_bytes, free_calls, largest_block). */
void lb_alloc_reset_counters(void);
/** Bytes currently allocated. */
size_t lb_alloc_live_bytes(void);
/** Blocks currently allocated. */
size_t lb_alloc_live_blocks(void);
/** Print every live block (size and allocation sequence number) to stderr; returns count. */
size_t lb_alloc_dump_live(void);
/** Make the n-th next allocation (0 = the very next one) and all following ones fail; SIZE_MAX disables. */
void lb_alloc_fail_after(size_t allocations_before_failure);
/** Number of allocations refused by lb_alloc_fail_after since the last counter reset. */
size_t lb_alloc_failed_calls(void);

#ifdef __cplusplus
}
#endif

#endif /* LB_ALLOC_H */
