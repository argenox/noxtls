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
* File:    noxtls_memory.h
* Summary: NoxTLS Memory Management
*
*****************************************************************************/

/**
 * @defgroup noxtls_common Common Utilities
 * @brief Memory, string helpers, debug printf, and platform compatibility.
 * @addtogroup noxtls
 */
/** @{ */

#ifndef _NOXTLS_MEMORY_H_
#define _NOXTLS_MEMORY_H_

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "noxtls_common.h"
#include "noxtls_config.h"
#include "noxtls_ct.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Static Buffer Allocator Implementation */

/* Memory alignment for allocator blocks */
#ifndef NOXTLS_MEM_ALIGNMENT
#define NOXTLS_MEM_ALIGNMENT (8U)
#endif

#ifndef NOXTLS_STATIC_ALLOCATOR_MODE_LEGACY
#define NOXTLS_STATIC_ALLOCATOR_MODE_LEGACY 0
#endif
#ifndef NOXTLS_STATIC_ALLOCATOR_MODE_BUCKETS
#define NOXTLS_STATIC_ALLOCATOR_MODE_BUCKETS 1
#endif
#ifndef NOXTLS_STATIC_ALLOCATOR_MODE_HYBRID
#define NOXTLS_STATIC_ALLOCATOR_MODE_HYBRID 2
#endif

#ifndef NOXTLS_STATIC_ALLOCATOR_MODE
#define NOXTLS_STATIC_ALLOCATOR_MODE NOXTLS_STATIC_ALLOCATOR_MODE_HYBRID
#endif

#ifndef NOXTLS_MEM_BUCKET_ALIGNMENT
#define NOXTLS_MEM_BUCKET_ALIGNMENT NOXTLS_MEM_ALIGNMENT
#endif

#ifndef NOXTLS_MEM_BUCKET_COUNT
#define NOXTLS_MEM_BUCKET_COUNT 9U
#endif

#ifndef NOXTLS_MEM_BUCKET_SIZES
#define NOXTLS_MEM_BUCKET_SIZES 32U, 64U, 128U, 256U, 512U, 1024U, 2048U, 4096U, 8192U
#endif

#ifndef NOXTLS_MEM_BUCKET_COUNTS
#define NOXTLS_MEM_BUCKET_COUNTS 16U, 16U, 12U, 10U, 8U, 6U, 4U, 2U, 1U
#endif

#ifndef NOXTLS_MEM_BUCKET_MAX
#define NOXTLS_MEM_BUCKET_MAX 16U
#endif

/* Memory block header */
typedef struct mem_block_header
{
    size_t size;                    /* Size of the block (excluding header) */
    struct mem_block_header *next;   /* Next block in free list */
    uint8_t allocated;               /* 1 if allocated, 0 if free */
    uint8_t kind;                    /* Internal allocator region kind */
    uint16_t bucket_index;           /* Internal bucket index, if any */
    uint32_t magic;                  /* Internal pointer validation marker */
} mem_block_header_t;

typedef struct
{
    size_t block_size;
    size_t total_blocks;
    size_t free_blocks;
    size_t used_blocks;
} noxtls_mem_bucket_stat_t;

typedef struct
{
    uint32_t allocator_mode;
    size_t bucket_count;
    size_t fallback_size;
    size_t fallback_used;
    size_t fallback_max_used;
    noxtls_mem_bucket_stat_t buckets[NOXTLS_MEM_BUCKET_MAX];
} noxtls_mem_bucket_stats_t;

/* Memory pool structure */
typedef struct
{
    uint8_t *buffer;                 /* The static buffer */
    size_t buffer_size;              /* Total size of buffer */
    uint8_t internal_buffer;         /* 1 if we allocated the buffer internally */
    mem_block_header_t *free_list;   /* Free block list */
    size_t total_allocated;          /* Total bytes allocated */
    size_t total_used;               /* Total bytes currently in use */
    size_t max_used;                 /* Maximum bytes used at peak */
    uint32_t allocator_mode;         /* Static allocator mode */
    size_t bucket_count;             /* Number of configured bucket classes */
    size_t bucket_sizes[NOXTLS_MEM_BUCKET_MAX];
    size_t bucket_total[NOXTLS_MEM_BUCKET_MAX];
    size_t bucket_free[NOXTLS_MEM_BUCKET_MAX];
    mem_block_header_t *bucket_free_list[NOXTLS_MEM_BUCKET_MAX];
    uint8_t *fallback_start;
    size_t fallback_size;
    size_t fallback_used;
    size_t fallback_max_used;
} mem_pool_t;

/** Zero buffer then free; use for buffers that may hold keys or other sensitive data to avoid leakage. (ptr may be NULL.) */
#define NOXTLS_SECURE_FREE(ptr, size) do { if((ptr) != NULL) { noxtls_secure_zero((void*)(ptr), (size)); noxtls_free(ptr); } } while(0)

/* Memory Allocation Functions */
/* These functions replace malloc, free, calloc, realloc throughout the library */

/**
 * @brief Allocate memory
 * 
 * @param size Number of bytes to allocate
 * @return Pointer to allocated memory, or NULL on failure
 */
void *noxtls_malloc(size_t size);

/**
 * @brief Free allocated memory
 * 
 * @param ptr Pointer to memory to free (can be NULL)
 */
void noxtls_free(void *ptr);

/**
 * @brief Allocate and zero-initialize memory
 * 
 * @param nmemb Number of elements
 * @param size Size of each element
 * @return Pointer to allocated memory, or NULL on failure
 */
void *noxtls_calloc(size_t nmemb, size_t size);

/**
 * @brief Reallocate memory
 * 
 * @param ptr Pointer to previously allocated memory (can be NULL)
 * @param size New size in bytes
 * @return Pointer to reallocated memory, or NULL on failure
 */
void *noxtls_realloc(void *ptr, size_t size);

/* Static Buffer Management Functions */

/**
 * @brief Initialize static buffer memory allocator
 * 
 * @param buffer Pre-allocated buffer to use (can be NULL to use internal allocation)
 * @param buffer_size Size of the buffer in bytes
 * @return NOXTLS_RETURN_SUCCESS on success, error code on failure
 * 
 * Note: If buffer is NULL, an internal buffer of size buffer_size will be allocated.
 *       If buffer_size is 0, NOXTLS_STATIC_BUFFER_SIZE will be used.
 */
noxtls_return_t noxtls_mem_init(uint8_t *buffer, size_t buffer_size);

/**
 * @brief Cleanup static buffer memory allocator
 * 
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t noxtls_mem_cleanup(void);

/**
 * @brief Get memory usage statistics
 * 
 * @param total_allocated Output: Total bytes allocated
 * @param total_used Output: Total bytes currently in use
 * @param max_used Output: Maximum bytes used at peak
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t noxtls_mem_get_stats(size_t *total_allocated, size_t *total_used, size_t *max_used);

noxtls_return_t noxtls_mem_get_bucket_stats(noxtls_mem_bucket_stats_t *stats);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _NOXTLS_MEMORY_H_ */


