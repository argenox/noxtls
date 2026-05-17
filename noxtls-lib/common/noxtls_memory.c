/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
*
* NOTICE:  All information contained herein, source code, binaries and
* derived works is, and remains
* the property of Argenox Technologies and its suppliers,
* if any.  The intellectual and technical concepts contained
* herein are proprietary to Argenox Technologies
* and its suppliers may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Argenox Technologies.
*
* THIS SOFTWARE IS PROVIDED BY ARGENOX "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL ARGENOX TECHNOLOGIES LLC BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
* CONTACT: info@argenox.com
* 
*
* File:    noxtls_memory.c
* Summary: NOXTLS Memory Management Implementation
*
*/

/** @addtogroup noxtls_common */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "noxtls_memory.h"

#if NOXTLS_USE_STATIC_BUFFERS

/* Only include stdlib.h for internal buffer allocation when needed */
#include <stdlib.h>



static mem_pool_t g_mem_pool = {0};
static int g_mem_initialized = 0;

/* Alignment for memory blocks */
#define ALIGN_SIZE(s) (((s) + (NOXTLS_MEM_ALIGNMENT - 1)) & ~(NOXTLS_MEM_ALIGNMENT - 1))

/**
 * @brief Initialize the static-buffer memory pool.
 * @param[in] buffer Caller-supplied pool storage, or NULL to allocate an internal buffer with `malloc`.
 * @param[in] buffer_size Size of @p buffer in bytes; if 0, uses `NOXTLS_STATIC_BUFFER_SIZE`.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_FAILED` if already initialized, size too small, or allocation failed.
 */
noxtls_return_t noxtls_mem_init(uint8_t *buffer, size_t buffer_size)
{
    mem_block_header_t *header;
    
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
    
    /* Initialize first free block covering entire buffer */
    header = (mem_block_header_t*)g_mem_pool.buffer;
    header->size = buffer_size - sizeof(mem_block_header_t);
    header->next = NULL;
    header->allocated = 0;
    
    g_mem_pool.free_list = header;
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
void *noxtls_malloc(size_t size)
{
    mem_block_header_t *current;
    mem_block_header_t *prev;
    mem_block_header_t *new_block;
    size_t aligned_size;
    size_t block_size;
    
    if(!g_mem_initialized) {
        /* Auto-initialize if not already done */
        if(noxtls_mem_init(NULL, 0) != NOXTLS_RETURN_SUCCESS) {
            return NULL;
        }
    }
    
    if(size == 0) {
        return NULL;
    }
    if(size > SIZE_MAX - (NOXTLS_MEM_ALIGNMENT - 1)) {
        return NULL;
    }
    aligned_size = ALIGN_SIZE(size);
    if(aligned_size > SIZE_MAX - sizeof(mem_block_header_t)) {
        return NULL;
    }
    block_size = aligned_size + sizeof(mem_block_header_t);
    
    /* Find a free block large enough */
    prev = NULL;
    current = g_mem_pool.free_list;
    
    while(current != NULL) {
        if(!current->allocated && current->size >= aligned_size) {
            /* Found a suitable block */
            if(current->size >= block_size + sizeof(mem_block_header_t) + NOXTLS_MEM_ALIGNMENT) {
                /* Split the block */
                new_block = (mem_block_header_t*)((uint8_t*)current + block_size);
                new_block->size = current->size - block_size;
                new_block->next = current->next;
                new_block->allocated = 0;
                
                if(prev == NULL) {
                    g_mem_pool.free_list = new_block;
                } else {
                    prev->next = new_block;
                }
                
                current->size = aligned_size;
            } else {
                /* Use entire block */
                if(prev == NULL) {
                    g_mem_pool.free_list = current->next;
                } else {
                    prev->next = current->next;
                }
            }
            
            current->allocated = 1;
            current->next = NULL;
            
            g_mem_pool.total_allocated += current->size;
            g_mem_pool.total_used += current->size;
            if(g_mem_pool.total_used > g_mem_pool.max_used) {
                g_mem_pool.max_used = g_mem_pool.total_used;
            }
            
            return (uint8_t*)current + sizeof(mem_block_header_t);
        }
        
        prev = current;
        current = current->next;
    }
    
    /* No suitable block found */
    return NULL;
}

/**
 * @brief Returns a static-pool allocation to the free list.
 * @param[in,out] ptr Pointer from @ref noxtls_malloc, @ref noxtls_calloc, or @ref noxtls_realloc; no-op if NULL or invalid.
 * @return None.
 */
void noxtls_free(void *ptr)
{
    mem_block_header_t *header;
    
    if(ptr == NULL || !g_mem_initialized) {
        return;
    }
    
    header = (mem_block_header_t*)((uint8_t*)ptr - sizeof(mem_block_header_t));
    
    /* Validate pointer is within our buffer */
    if((uint8_t*)header < g_mem_pool.buffer || 
       (uint8_t*)header >= g_mem_pool.buffer + g_mem_pool.buffer_size) {
        return; /* Invalid pointer */
    }
    
    if(!header->allocated) {
        return; /* Already freed */
    }
    
    /* Update statistics */
    g_mem_pool.total_used -= header->size;
    
    /* Mark as free */
    header->allocated = 0;
    
    /* Coalesce with adjacent free blocks */
    /* For simplicity, we'll just add to free list and coalesce on next allocation */
    header->next = g_mem_pool.free_list;
    g_mem_pool.free_list = header;
}

/**
 * @brief Allocates `nmemb * size` bytes from the static pool and zero-fills the payload.
 * @param[in] nmemb Number of elements.
 * @param[in] size Size of each element in bytes.
 * @return Pointer to zeroed memory, or NULL on overflow or allocation failure.
 */
void *noxtls_calloc(size_t nmemb, size_t size)
{
    void *ptr;
    size_t total_size;

    if(nmemb != 0 && size > SIZE_MAX / nmemb) {
        return NULL;
    }
    total_size = nmemb * size;
    ptr = noxtls_malloc(total_size);
    
    if(ptr != NULL) {
        memset(ptr, 0, total_size);
    }
    
    return ptr;
}

/**
 * @brief Resizes a static-pool block; copies to a new block if @p size exceeds the current payload.
 * @param[in,out] ptr Existing allocation, or NULL to behave as @ref noxtls_malloc.
 * @param[in]     size New requested payload size; zero frees @p ptr and returns NULL.
 * @return Pointer to usable memory (may equal @p ptr when shrinking or in-place), or NULL on failure.
 */
void *noxtls_realloc(void *ptr, size_t size)
{
    const mem_block_header_t *header;
    void *new_ptr;
    size_t old_size;
    
    if(ptr == NULL) {
        return noxtls_malloc(size);
    }
    
    if(size == 0) {
        noxtls_free(ptr);
        return NULL;
    }
    
    if(!g_mem_initialized || g_mem_pool.buffer == NULL) {
        return NULL;
    }
    header = (const mem_block_header_t*)((const uint8_t*)ptr - sizeof(mem_block_header_t));
    if((const uint8_t*)header < g_mem_pool.buffer ||
       (const uint8_t*)header >= g_mem_pool.buffer + g_mem_pool.buffer_size) {
        return NULL;
    }
    if(!header->allocated || header->size > g_mem_pool.buffer_size) {
        return NULL;
    }
    old_size = header->size;
    
    /* If new size fits in existing block, just return same pointer */
    if(size <= old_size) {
        return ptr;
    }
    
    /* Allocate new block */
    new_ptr = noxtls_malloc(size);
    if(new_ptr == NULL) {
        return NULL;
    }
    
    /* Copy old data */
    memcpy(new_ptr, ptr, old_size);
    
    /* Free old block */
    noxtls_free(ptr);
    
    return new_ptr;
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

#else /* NOXTLS_USE_STATIC_BUFFERS == 0 */

/* System malloc/free implementation */

#include <stdlib.h>

/**
 * @brief Allocates @p size bytes using the host C library `malloc`.
 * @param[in] size Number of bytes; zero yields NULL.
 * @return Pointer from `malloc`, or NULL on failure or zero size.
 */
void *noxtls_malloc(size_t size)
{
    if(size == 0) {
        return NULL;
    }
    return malloc(size);
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
void *noxtls_calloc(size_t nmemb, size_t size)
{
    return calloc(nmemb, size);
}

/**
 * @brief Resizes or frees using the host `realloc` / `free`.
 * @param[in,out] ptr Existing block or NULL for a fresh allocation.
 * @param[in]     size New size; zero frees @p ptr and returns NULL.
 * @return Pointer from `realloc`, or NULL per C library rules.
 */
void *noxtls_realloc(void *ptr, size_t size)
{
    if(size == 0) {
        free(ptr);
        return NULL;
    }
    return realloc(ptr, size);
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

#endif /* NOXTLS_USE_STATIC_BUFFERS */

