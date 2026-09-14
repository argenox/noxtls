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
* File:    noxtls_memory.c
* Summary: NoxTLS Memory Management Implementation
*
*****************************************************************************/

/** @addtogroup noxtls_common */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "noxtls_memory.h"

/* This is diagnostic metadata only.  It deliberately retains no allocation
 * pointer or payload, so it is safe to consume from a constrained target's
 * status channel after a cryptographic allocation failure. */
static noxtls_mem_failure_t g_noxtls_mem_last_failure;
static uint32_t g_noxtls_mem_failure_sequence;

static void noxtls_mem_record_failure(noxtls_mem_operation_t operation,
                                      noxtls_mem_failure_reason_t reason,
                                      size_t requested_size,
                                      size_t element_count,
                                      size_t element_size,
                                      const char *file, uint32_t line)
{
    g_noxtls_mem_failure_sequence++;
    if(g_noxtls_mem_failure_sequence == 0U) {
        g_noxtls_mem_failure_sequence = 1U;
    }
    g_noxtls_mem_last_failure.sequence = g_noxtls_mem_failure_sequence;
    g_noxtls_mem_last_failure.operation = operation;
    g_noxtls_mem_last_failure.reason = reason;
    g_noxtls_mem_last_failure.requested_size = requested_size;
    g_noxtls_mem_last_failure.element_count = element_count;
    g_noxtls_mem_last_failure.element_size = element_size;
    g_noxtls_mem_last_failure.file = file;
    g_noxtls_mem_last_failure.line = line;
}

noxtls_return_t noxtls_mem_get_last_failure(noxtls_mem_failure_t *failure)
{
    if(failure == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    *failure = g_noxtls_mem_last_failure;
    return failure->reason == NOXTLS_MEM_FAILURE_NONE ?
        NOXTLS_RETURN_FAILED : NOXTLS_RETURN_SUCCESS;
}

void noxtls_mem_clear_last_failure(void)
{
    memset(&g_noxtls_mem_last_failure, 0, sizeof(g_noxtls_mem_last_failure));
}

#if NOXTLS_USE_STATIC_BUFFERS

/* Only include stdlib.h for internal buffer allocation when needed */
#include <stdlib.h>

static mem_pool_t g_mem_pool = {0};
static int g_mem_initialized = 0;

#define NOXTLS_MEM_BLOCK_MAGIC 0x4E584D45UL
#define NOXTLS_MEM_KIND_FALLBACK 1U
#define NOXTLS_MEM_KIND_BUCKET 2U

#if NOXTLS_STATIC_ALLOCATOR_MODE != NOXTLS_STATIC_ALLOCATOR_MODE_LEGACY && \
    NOXTLS_STATIC_ALLOCATOR_MODE != NOXTLS_STATIC_ALLOCATOR_MODE_BUCKETS && \
    NOXTLS_STATIC_ALLOCATOR_MODE != NOXTLS_STATIC_ALLOCATOR_MODE_HYBRID
#error "Invalid NOXTLS_STATIC_ALLOCATOR_MODE"
#endif

#define ALIGN_SIZE_WITH(s, a) (((s) + ((a) - 1U)) & ~((a) - 1U))
#define ALIGN_SIZE(s) ALIGN_SIZE_WITH((s), NOXTLS_MEM_ALIGNMENT)

static uintptr_t noxtls_align_up_uintptr(uintptr_t value, size_t alignment)
{
    uintptr_t mask = (uintptr_t)alignment - 1U;
    return (value + mask) & ~mask;
}

static uint8_t *noxtls_align_header_for_payload(const uint8_t *cursor, size_t alignment)
{
    uintptr_t payload = noxtls_align_up_uintptr((uintptr_t)cursor + sizeof(mem_block_header_t), alignment);
    return (uint8_t *)(payload - sizeof(mem_block_header_t));
}

#if NOXTLS_STATIC_ALLOCATOR_MODE != NOXTLS_STATIC_ALLOCATOR_MODE_BUCKETS
static noxtls_return_t noxtls_mem_init_fallback(uint8_t *start, size_t size)
{
    mem_block_header_t *header;
    uint8_t *aligned_start;
    size_t skipped;

    aligned_start = noxtls_align_header_for_payload(start, NOXTLS_MEM_ALIGNMENT);
    if(aligned_start < start || aligned_start >= start + size) {
        return NOXTLS_RETURN_FAILED;
    }
    skipped = (size_t)(aligned_start - start);
    if(size <= skipped + sizeof(mem_block_header_t)) {
        return NOXTLS_RETURN_FAILED;
    }

    g_mem_pool.fallback_start = aligned_start;
    g_mem_pool.fallback_size = size - skipped;
    g_mem_pool.fallback_used = 0U;
    g_mem_pool.fallback_max_used = 0U;

    header = (mem_block_header_t *)aligned_start;
    header->size = g_mem_pool.fallback_size - sizeof(mem_block_header_t);
    header->next = NULL;
    header->allocated = 0U;
    header->kind = NOXTLS_MEM_KIND_FALLBACK;
    header->bucket_index = 0xFFFFU;
    header->magic = NOXTLS_MEM_BLOCK_MAGIC;
    g_mem_pool.free_list = header;

    return NOXTLS_RETURN_SUCCESS;
}

static void *noxtls_mem_alloc_fallback(size_t aligned_size)
{
    mem_block_header_t *current;
    mem_block_header_t *prev;
    mem_block_header_t *new_block;
    size_t block_size;

    if(g_mem_pool.free_list == NULL) {
        return NULL;
    }
    if(aligned_size > SIZE_MAX - sizeof(mem_block_header_t)) {
        return NULL;
    }
    block_size = aligned_size + sizeof(mem_block_header_t);

    prev = NULL;
    current = g_mem_pool.free_list;
    while(current != NULL) {
        if(!current->allocated && current->magic == NOXTLS_MEM_BLOCK_MAGIC && current->size >= aligned_size) {
            if(current->size >= block_size + sizeof(mem_block_header_t) + NOXTLS_MEM_ALIGNMENT) {
                new_block = (mem_block_header_t *)((uint8_t *)current + block_size);
                new_block->size = current->size - block_size;
                new_block->next = current->next;
                new_block->allocated = 0U;
                new_block->kind = NOXTLS_MEM_KIND_FALLBACK;
                new_block->bucket_index = 0xFFFFU;
                new_block->magic = NOXTLS_MEM_BLOCK_MAGIC;

                if(prev == NULL) {
                    g_mem_pool.free_list = new_block;
                } else {
                    prev->next = new_block;
                }
                current->size = aligned_size;
            } else {
                if(prev == NULL) {
                    g_mem_pool.free_list = current->next;
                } else {
                    prev->next = current->next;
                }
            }

            current->allocated = 1U;
            current->next = NULL;
            current->kind = NOXTLS_MEM_KIND_FALLBACK;
            current->magic = NOXTLS_MEM_BLOCK_MAGIC;

            g_mem_pool.total_allocated += current->size;
            g_mem_pool.total_used += current->size;
            g_mem_pool.fallback_used += current->size;
            if(g_mem_pool.total_used > g_mem_pool.max_used) {
                g_mem_pool.max_used = g_mem_pool.total_used;
            }
            if(g_mem_pool.fallback_used > g_mem_pool.fallback_max_used) {
                g_mem_pool.fallback_max_used = g_mem_pool.fallback_used;
            }

            return (uint8_t *)current + sizeof(mem_block_header_t);
        }

        prev = current;
        current = current->next;
    }

    return NULL;
}

static void noxtls_mem_coalesce_fallback(void)
{
    mem_block_header_t *current = g_mem_pool.free_list;
    mem_block_header_t *next;
    uint8_t *current_end;

    while(current != NULL && current->next != NULL) {
        next = current->next;
        current_end = (uint8_t *)current + sizeof(mem_block_header_t) + current->size;
        if(current_end == (uint8_t *)next && next->magic == NOXTLS_MEM_BLOCK_MAGIC &&
           next->allocated == 0U && next->kind == NOXTLS_MEM_KIND_FALLBACK) {
            current->size += sizeof(mem_block_header_t) + next->size;
            current->next = next->next;
            memset(next, 0, sizeof(*next));
        } else {
            current = current->next;
        }
    }
}

static void noxtls_mem_free_fallback(mem_block_header_t *header)
{
    mem_block_header_t *current;
    mem_block_header_t *prev;

    if(g_mem_pool.fallback_used >= header->size) {
        g_mem_pool.fallback_used -= header->size;
    } else {
        g_mem_pool.fallback_used = 0U;
    }

    header->allocated = 0U;
    prev = NULL;
    current = g_mem_pool.free_list;
    while(current != NULL && (uintptr_t)current < (uintptr_t)header) {
        prev = current;
        current = current->next;
    }

    header->next = current;
    if(prev == NULL) {
        g_mem_pool.free_list = header;
    } else {
        prev->next = header;
    }

    noxtls_mem_coalesce_fallback();
}
#endif

#if NOXTLS_STATIC_ALLOCATOR_MODE != NOXTLS_STATIC_ALLOCATOR_MODE_LEGACY
static void *noxtls_mem_alloc_bucket(size_t aligned_size)
{
    size_t i;
    mem_block_header_t *header;

    for(i = 0U; i < g_mem_pool.bucket_count; ++i) {
        if(g_mem_pool.bucket_sizes[i] >= aligned_size && g_mem_pool.bucket_free_list[i] != NULL) {
            header = g_mem_pool.bucket_free_list[i];
            g_mem_pool.bucket_free_list[i] = header->next;
            header->next = NULL;
            header->allocated = 1U;
            header->kind = NOXTLS_MEM_KIND_BUCKET;
            header->bucket_index = (uint16_t)i;
            header->magic = NOXTLS_MEM_BLOCK_MAGIC;
            g_mem_pool.bucket_free[i]--;

            g_mem_pool.total_allocated += header->size;
            g_mem_pool.total_used += header->size;
            if(g_mem_pool.total_used > g_mem_pool.max_used) {
                g_mem_pool.max_used = g_mem_pool.total_used;
            }

            return (uint8_t *)header + sizeof(mem_block_header_t);
        }
    }

    return NULL;
}

static noxtls_return_t noxtls_mem_init_buckets(uint8_t **cursor, uint8_t *end)
{
    static const size_t bucket_sizes_cfg[NOXTLS_MEM_BUCKET_COUNT] = { NOXTLS_MEM_BUCKET_SIZES };
    static const size_t bucket_counts_cfg[NOXTLS_MEM_BUCKET_COUNT] = { NOXTLS_MEM_BUCKET_COUNTS };
    size_t i;
    size_t j;
    uint8_t *p;
    mem_block_header_t *header;

    if(NOXTLS_MEM_BUCKET_COUNT > NOXTLS_MEM_BUCKET_MAX) {
        return NOXTLS_RETURN_FAILED;
    }

    g_mem_pool.bucket_count = NOXTLS_MEM_BUCKET_COUNT;
    for(i = 0U; i < NOXTLS_MEM_BUCKET_COUNT; ++i) {
        if(bucket_sizes_cfg[i] == 0U || bucket_counts_cfg[i] == 0U) {
            return NOXTLS_RETURN_FAILED;
        }
        g_mem_pool.bucket_sizes[i] = ALIGN_SIZE_WITH(bucket_sizes_cfg[i], NOXTLS_MEM_BUCKET_ALIGNMENT);
        g_mem_pool.bucket_total[i] = bucket_counts_cfg[i];
        g_mem_pool.bucket_free[i] = bucket_counts_cfg[i];
        g_mem_pool.bucket_free_list[i] = NULL;

        for(j = 0U; j < bucket_counts_cfg[i]; ++j) {
            p = noxtls_align_header_for_payload(*cursor, NOXTLS_MEM_BUCKET_ALIGNMENT);
            if(p < *cursor || p > end || (size_t)(end - p) < sizeof(mem_block_header_t) + g_mem_pool.bucket_sizes[i]) {
                return NOXTLS_RETURN_FAILED;
            }

            header = (mem_block_header_t *)p;
            header->size = g_mem_pool.bucket_sizes[i];
            header->allocated = 0U;
            header->kind = NOXTLS_MEM_KIND_BUCKET;
            header->bucket_index = (uint16_t)i;
            header->magic = NOXTLS_MEM_BLOCK_MAGIC;
            header->next = g_mem_pool.bucket_free_list[i];
            g_mem_pool.bucket_free_list[i] = header;

            *cursor = p + sizeof(mem_block_header_t) + g_mem_pool.bucket_sizes[i];
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}
#endif

static int noxtls_mem_header_valid(const mem_block_header_t *header)
{
    const uint8_t *h = (const uint8_t *)header;

    if(!g_mem_initialized || g_mem_pool.buffer == NULL || header == NULL) {
        return 0;
    }
    if(h < g_mem_pool.buffer || h >= g_mem_pool.buffer + g_mem_pool.buffer_size) {
        return 0;
    }
    if(header->magic != NOXTLS_MEM_BLOCK_MAGIC || header->allocated == 0U) {
        return 0;
    }
    return 1;
}

/**
 * @brief Initialize the static-buffer memory pool.
 * @param[in] buffer Caller-supplied pool storage, or NULL to allocate an internal buffer with `malloc`.
 * @param[in] buffer_size Size of @p buffer in bytes; if 0, uses `NOXTLS_STATIC_BUFFER_SIZE`.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_FAILED` if already initialized, size too small, or allocation failed.
 */
noxtls_return_t noxtls_mem_init(uint8_t *buffer, size_t buffer_size)
{
    uint8_t *cursor;
    uint8_t *end;
    
    if(g_mem_initialized) {
        return NOXTLS_RETURN_FAILED; /* Already initialized */
    }
    
    if(buffer_size == 0) {
        buffer_size = NOXTLS_STATIC_BUFFER_SIZE;
    }
    if(buffer_size <= sizeof(mem_block_header_t)) {
        return NOXTLS_RETURN_FAILED;
    }
    
    if(buffer == NULL) {
        /* Allocate internal buffer using system malloc */
        /* Note: This is the only place we use system malloc when static buffers are enabled */
        g_mem_pool.buffer = (uint8_t*)malloc(buffer_size);
        if(g_mem_pool.buffer == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        g_mem_pool.internal_buffer = 1;
    } else {
        g_mem_pool.buffer = buffer;
        g_mem_pool.internal_buffer = 0;
    }
    
    g_mem_pool.buffer_size = buffer_size;
    g_mem_pool.total_allocated = 0;
    g_mem_pool.total_used = 0;
    g_mem_pool.max_used = 0;
    g_mem_pool.allocator_mode = NOXTLS_STATIC_ALLOCATOR_MODE;

    cursor = g_mem_pool.buffer;
    end = g_mem_pool.buffer + g_mem_pool.buffer_size;

#if NOXTLS_STATIC_ALLOCATOR_MODE == NOXTLS_STATIC_ALLOCATOR_MODE_LEGACY
    if(noxtls_mem_init_fallback(cursor, (size_t)(end - cursor)) != NOXTLS_RETURN_SUCCESS) {
        if(g_mem_pool.internal_buffer && g_mem_pool.buffer != NULL) {
            free(g_mem_pool.buffer);
        }
        memset(&g_mem_pool, 0, sizeof(mem_pool_t));
        return NOXTLS_RETURN_FAILED;
    }
#elif NOXTLS_STATIC_ALLOCATOR_MODE == NOXTLS_STATIC_ALLOCATOR_MODE_BUCKETS
    if(noxtls_mem_init_buckets(&cursor, end) != NOXTLS_RETURN_SUCCESS) {
        if(g_mem_pool.internal_buffer && g_mem_pool.buffer != NULL) {
            free(g_mem_pool.buffer);
        }
        memset(&g_mem_pool, 0, sizeof(mem_pool_t));
        return NOXTLS_RETURN_FAILED;
    }
#else
    if(noxtls_mem_init_buckets(&cursor, end) != NOXTLS_RETURN_SUCCESS ||
       noxtls_mem_init_fallback(cursor, (size_t)(end - cursor)) != NOXTLS_RETURN_SUCCESS) {
        if(g_mem_pool.internal_buffer && g_mem_pool.buffer != NULL) {
            free(g_mem_pool.buffer);
        }
        memset(&g_mem_pool, 0, sizeof(mem_pool_t));
        return NOXTLS_RETURN_FAILED;
    }
#endif

    g_mem_initialized = 1;
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Releases the static-buffer pool and resets allocator state.
 * @return `NOXTLS_RETURN_SUCCESS` after shutdown; `NOXTLS_RETURN_FAILED` if the pool was not initialized.
 */
noxtls_return_t noxtls_mem_cleanup(void)
{
    if(!g_mem_initialized) {
        return NOXTLS_RETURN_FAILED;
    }
    
    if(g_mem_pool.internal_buffer && g_mem_pool.buffer != NULL) {
        free(g_mem_pool.buffer);
        g_mem_pool.buffer = NULL;
    }
    
    memset(&g_mem_pool, 0, sizeof(mem_pool_t));
    g_mem_initialized = 0;
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Allocate @p size bytes from the static-buffer pool (lazy `noxtls_mem_init` on first use).
 * @param[in] size Requested payload size in bytes (must be non-zero for a non-NULL result).
 * @return Pointer to usable memory, or NULL if uninitialized, zero size, overflow, or no block fits.
 */
void *noxtls_malloc_at(size_t size, const char *file, uint32_t line)
{
    size_t aligned_size;
#if NOXTLS_STATIC_ALLOCATOR_MODE == NOXTLS_STATIC_ALLOCATOR_MODE_HYBRID
    void *ptr;
#endif
    
    if(!g_mem_initialized) {
        /* Auto-initialize if not already done */
        if(noxtls_mem_init(NULL, 0) != NOXTLS_RETURN_SUCCESS) {
            noxtls_mem_record_failure(NOXTLS_MEM_OPERATION_MALLOC,
                                      NOXTLS_MEM_FAILURE_POOL_INIT, size, 1U,
                                      size, file, line);
            return NULL;
        }
    }
    
    if(size == 0) {
        noxtls_mem_record_failure(NOXTLS_MEM_OPERATION_MALLOC,
                                  NOXTLS_MEM_FAILURE_INVALID_REQUEST, size,
                                  1U, size, file, line);
        return NULL;
    }
    if(size > SIZE_MAX - (NOXTLS_MEM_ALIGNMENT - 1)) {
        noxtls_mem_record_failure(NOXTLS_MEM_OPERATION_MALLOC,
                                  NOXTLS_MEM_FAILURE_SIZE_OVERFLOW, size,
                                  1U, size, file, line);
        return NULL;
    }
    aligned_size = ALIGN_SIZE(size);

#if NOXTLS_STATIC_ALLOCATOR_MODE == NOXTLS_STATIC_ALLOCATOR_MODE_LEGACY
    {
        void *ptr = noxtls_mem_alloc_fallback(aligned_size);
        if(ptr == NULL) {
            noxtls_mem_record_failure(NOXTLS_MEM_OPERATION_MALLOC,
                                      NOXTLS_MEM_FAILURE_FALLBACK_EXHAUSTED,
                                      size, 1U, size, file, line);
        }
        return ptr;
    }
#elif NOXTLS_STATIC_ALLOCATOR_MODE == NOXTLS_STATIC_ALLOCATOR_MODE_BUCKETS
    {
        void *ptr = noxtls_mem_alloc_bucket(aligned_size);
        if(ptr == NULL) {
            noxtls_mem_record_failure(NOXTLS_MEM_OPERATION_MALLOC,
                                      NOXTLS_MEM_FAILURE_BUCKET_EXHAUSTED,
                                      size, 1U, size, file, line);
        }
        return ptr;
    }
#else
    ptr = noxtls_mem_alloc_bucket(aligned_size);
    if(ptr != NULL) {
        return ptr;
    }
    ptr = noxtls_mem_alloc_fallback(aligned_size);
    if(ptr == NULL) {
        noxtls_mem_record_failure(NOXTLS_MEM_OPERATION_MALLOC,
                                  NOXTLS_MEM_FAILURE_FALLBACK_EXHAUSTED,
                                  size, 1U, size, file, line);
    }
    return ptr;
#endif
}

void *noxtls_malloc(size_t size)
{
    return noxtls_malloc_at(size, NULL, 0U);
}

/**
 * @brief Returns a static-pool allocation to the free list.
 * @param[in,out] ptr Pointer from @ref noxtls_malloc, @ref noxtls_calloc, or @ref noxtls_realloc; no-op if NULL or invalid.
 * @return None.
 */
void noxtls_free(void *ptr)
{
    mem_block_header_t *header;
    size_t bucket_index;
    
    if(ptr == NULL || !g_mem_initialized) {
        return;
    }
    
    header = (mem_block_header_t*)((uint8_t*)ptr - sizeof(mem_block_header_t));

    if(!noxtls_mem_header_valid(header)) {
        return;
    }
    
    if(header->kind == NOXTLS_MEM_KIND_BUCKET) {
        bucket_index = header->bucket_index;
        if(bucket_index >= g_mem_pool.bucket_count) {
            return;
        }
        if(g_mem_pool.total_used >= header->size) {
            g_mem_pool.total_used -= header->size;
        } else {
            g_mem_pool.total_used = 0U;
        }
        header->allocated = 0U;
        header->next = g_mem_pool.bucket_free_list[bucket_index];
        g_mem_pool.bucket_free_list[bucket_index] = header;
        g_mem_pool.bucket_free[bucket_index]++;
        return;
    }

#if NOXTLS_STATIC_ALLOCATOR_MODE != NOXTLS_STATIC_ALLOCATOR_MODE_BUCKETS
    if(header->kind == NOXTLS_MEM_KIND_FALLBACK) {
        if(g_mem_pool.total_used >= header->size) {
            g_mem_pool.total_used -= header->size;
        } else {
            g_mem_pool.total_used = 0U;
        }
        noxtls_mem_free_fallback(header);
    }
#endif
}

/**
 * @brief Allocates `nmemb * size` bytes from the static pool and zero-fills the payload.
 * @param[in] nmemb Number of elements.
 * @param[in] size Size of each element in bytes.
 * @return Pointer to zeroed memory, or NULL on overflow or allocation failure.
 */
void *noxtls_calloc_at(size_t nmemb, size_t size, const char *file,
                       uint32_t line)
{
    void *ptr;
    size_t total_size;

    if(nmemb != 0 && size > SIZE_MAX / nmemb) {
        noxtls_mem_record_failure(NOXTLS_MEM_OPERATION_CALLOC,
                                  NOXTLS_MEM_FAILURE_SIZE_OVERFLOW, 0U,
                                  nmemb, size, file, line);
        return NULL;
    }
    total_size = nmemb * size;
    ptr = noxtls_malloc_at(total_size, file, line);
    if(ptr == NULL) {
        if(g_noxtls_mem_last_failure.reason != NOXTLS_MEM_FAILURE_NONE) {
            g_noxtls_mem_last_failure.operation = NOXTLS_MEM_OPERATION_CALLOC;
            g_noxtls_mem_last_failure.requested_size = total_size;
            g_noxtls_mem_last_failure.element_count = nmemb;
            g_noxtls_mem_last_failure.element_size = size;
        }
        return NULL;
    }
    
    if(ptr != NULL) {
        memset(ptr, 0, total_size);
    }
    
    return ptr;
}

void *noxtls_calloc(size_t nmemb, size_t size)
{
    return noxtls_calloc_at(nmemb, size, NULL, 0U);
}

/**
 * @brief Resizes a static-pool block; copies to a new block if @p size exceeds the current payload.
 * @param[in,out] ptr Existing allocation, or NULL to behave as @ref noxtls_malloc.
 * @param[in]     size New requested payload size; zero frees @p ptr and returns NULL.
 * @return Pointer to usable memory (may equal @p ptr when shrinking or in-place), or NULL on failure.
 */
void *noxtls_realloc_at(void *ptr, size_t size, const char *file,
                        uint32_t line)
{
    const mem_block_header_t *header;
    void *new_ptr;
    size_t old_size;
    
    if(ptr == NULL) {
        new_ptr = noxtls_malloc_at(size, file, line);
        if(new_ptr == NULL && g_noxtls_mem_last_failure.reason != NOXTLS_MEM_FAILURE_NONE) {
            g_noxtls_mem_last_failure.operation = NOXTLS_MEM_OPERATION_REALLOC;
        }
        return new_ptr;
    }
    
    if(size == 0) {
        noxtls_free(ptr);
        return NULL;
    }
    
    if(!g_mem_initialized || g_mem_pool.buffer == NULL) {
        noxtls_mem_record_failure(NOXTLS_MEM_OPERATION_REALLOC,
                                  NOXTLS_MEM_FAILURE_INVALID_REQUEST, size,
                                  1U, size, file, line);
        return NULL;
    }
    header = (const mem_block_header_t*)((const uint8_t*)ptr - sizeof(mem_block_header_t));
    if(!noxtls_mem_header_valid(header) || header->size > g_mem_pool.buffer_size) {
        noxtls_mem_record_failure(NOXTLS_MEM_OPERATION_REALLOC,
                                  NOXTLS_MEM_FAILURE_INVALID_REQUEST, size,
                                  1U, size, file, line);
        return NULL;
    }
    old_size = header->size;
    
    /* If new size fits in existing block, just return same pointer */
    if(size <= old_size) {
        return ptr;
    }
    
    /* Allocate new block */
    new_ptr = noxtls_malloc_at(size, file, line);
    if(new_ptr == NULL) {
        if(g_noxtls_mem_last_failure.reason != NOXTLS_MEM_FAILURE_NONE) {
            g_noxtls_mem_last_failure.operation = NOXTLS_MEM_OPERATION_REALLOC;
        }
        return NULL;
    }
    
    /* Copy old data */
    memcpy(new_ptr, ptr, old_size);
    
    /* Free old block */
    noxtls_free(ptr);
    
    return new_ptr;
}

void *noxtls_realloc(void *ptr, size_t size)
{
    return noxtls_realloc_at(ptr, size, NULL, 0U);
}

/**
 * @brief Copies cumulative static-pool statistics (pass NULL for any output not needed).
 * @param[out] total_allocated Lifetime sum of bytes returned from successful allocations, or NULL to skip.
 * @param[out] total_used Bytes currently allocated and not freed, or NULL to skip.
 * @param[out] max_used High-water mark of in-use bytes, or NULL to skip.
 * @return `NOXTLS_RETURN_SUCCESS` if the pool is initialized; `NOXTLS_RETURN_FAILED` otherwise.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
noxtls_return_t noxtls_mem_get_stats(size_t *total_allocated, size_t *total_used, size_t *max_used)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    if(!g_mem_initialized) {
        return NOXTLS_RETURN_FAILED;
    }
    
    if(total_allocated != NULL) {
        *total_allocated = g_mem_pool.total_allocated;
    }
    if(total_used != NULL) {
        *total_used = g_mem_pool.total_used;
    }
    if(max_used != NULL) {
        *max_used = g_mem_pool.max_used;
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_mem_get_bucket_stats(noxtls_mem_bucket_stats_t *stats)
{
    size_t i;

    if(!g_mem_initialized || stats == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    memset(stats, 0, sizeof(*stats));
    stats->allocator_mode = g_mem_pool.allocator_mode;
    stats->bucket_count = g_mem_pool.bucket_count;
    stats->fallback_size = g_mem_pool.fallback_size;
    stats->fallback_used = g_mem_pool.fallback_used;
    stats->fallback_max_used = g_mem_pool.fallback_max_used;

    for(i = 0U; i < g_mem_pool.bucket_count && i < NOXTLS_MEM_BUCKET_MAX; ++i) {
        stats->buckets[i].block_size = g_mem_pool.bucket_sizes[i];
        stats->buckets[i].total_blocks = g_mem_pool.bucket_total[i];
        stats->buckets[i].free_blocks = g_mem_pool.bucket_free[i];
        stats->buckets[i].used_blocks = g_mem_pool.bucket_total[i] - g_mem_pool.bucket_free[i];
    }

    return NOXTLS_RETURN_SUCCESS;
}

#else /* NOXTLS_USE_STATIC_BUFFERS == 0 */

/* System malloc/free implementation */

#include <stdlib.h>

/**
 * @brief Allocates @p size bytes using the host C library `malloc`.
 * @param[in] size Number of bytes; zero yields NULL.
 * @return Pointer from `malloc`, or NULL on failure or zero size.
 */
void *noxtls_malloc_at(size_t size, const char *file, uint32_t line)
{
    if(size == 0) {
        noxtls_mem_record_failure(NOXTLS_MEM_OPERATION_MALLOC,
                                  NOXTLS_MEM_FAILURE_INVALID_REQUEST, size,
                                  1U, size, file, line);
        return NULL;
    }
    {
        void *ptr = malloc(size);
        if(ptr == NULL) {
            noxtls_mem_record_failure(NOXTLS_MEM_OPERATION_MALLOC,
                                      NOXTLS_MEM_FAILURE_SYSTEM_ALLOC, size,
                                      1U, size, file, line);
        }
        return ptr;
    }
}

void *noxtls_malloc(size_t size)
{
    return noxtls_malloc_at(size, NULL, 0U);
}

/**
 * @brief Frees memory with the host `free`.
 * @param[in,out] ptr Pointer from @ref noxtls_malloc or compatible; NULL is ignored.
 * @return None.
 */
void noxtls_free(void *ptr)
{
    free(ptr);
}

/**
 * @brief Allocates `nmemb * size` bytes with `calloc` (zeroed).
 * @param[in] nmemb Number of elements.
 * @param[in] size Element size in bytes.
 * @return Pointer from `calloc`, or NULL on failure or zero total size.
 */
void *noxtls_calloc_at(size_t nmemb, size_t size, const char *file,
                       uint32_t line)
{
    void *ptr;

    if(nmemb != 0U && size > SIZE_MAX / nmemb) {
        noxtls_mem_record_failure(NOXTLS_MEM_OPERATION_CALLOC,
                                  NOXTLS_MEM_FAILURE_SIZE_OVERFLOW, 0U,
                                  nmemb, size, file, line);
        return NULL;
    }
    ptr = calloc(nmemb, size);
    if(ptr == NULL) {
        noxtls_mem_record_failure(NOXTLS_MEM_OPERATION_CALLOC,
                                  NOXTLS_MEM_FAILURE_SYSTEM_ALLOC,
                                  nmemb * size, nmemb, size, file, line);
    }
    return ptr;
}

void *noxtls_calloc(size_t nmemb, size_t size)
{
    return noxtls_calloc_at(nmemb, size, NULL, 0U);
}

/**
 * @brief Resizes or frees using the host `realloc` / `free`.
 * @param[in,out] ptr Existing block or NULL for a fresh allocation.
 * @param[in]     size New size; zero frees @p ptr and returns NULL.
 * @return Pointer from `realloc`, or NULL per C library rules.
 */
void *noxtls_realloc_at(void *ptr, size_t size, const char *file,
                        uint32_t line)
{
    if(size == 0) {
        free(ptr);
        return NULL;
    }
    ptr = realloc(ptr, size);
    if(ptr == NULL) {
        noxtls_mem_record_failure(NOXTLS_MEM_OPERATION_REALLOC,
                                  NOXTLS_MEM_FAILURE_SYSTEM_ALLOC, size,
                                  1U, size, file, line);
    }
    return ptr;
}

void *noxtls_realloc(void *ptr, size_t size)
{
    return noxtls_realloc_at(ptr, size, NULL, 0U);
}

/**
 * @brief Compatibility hook when static buffers are disabled; arguments are ignored.
 * @param[in] buffer Unused.
 * @param[in] buffer_size Unused.
 * @return Always `NOXTLS_RETURN_SUCCESS`.
 */
noxtls_return_t noxtls_mem_init(uint8_t *buffer, size_t buffer_size)
{
    (void)buffer;
    (void)buffer_size;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Compatibility hook when static buffers are disabled; no pool state is held.
 * @return Always `NOXTLS_RETURN_SUCCESS`.
 */
noxtls_return_t noxtls_mem_cleanup(void)
{
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Statistics are not tracked when the build uses system malloc.
 * @param[out] total_allocated Unused.
 * @param[out] total_used Unused.
 * @param[out] max_used Unused.
 * @return Always `NOXTLS_RETURN_FAILED`.
 */
noxtls_return_t noxtls_mem_get_stats(size_t *total_allocated, /* NOLINT(bugprone-easily-swappable-parameters): output triplet follows API contract */
                                     size_t *total_used, size_t *max_used)
{
    (void)total_allocated;
    (void)total_used;
    (void)max_used;
    return NOXTLS_RETURN_FAILED;
}

noxtls_return_t noxtls_mem_get_bucket_stats(noxtls_mem_bucket_stats_t *stats)
{
    (void)stats;
    return NOXTLS_RETURN_FAILED;
}

#endif /* NOXTLS_USE_STATIC_BUFFERS */

