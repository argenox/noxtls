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
* This file is part of the NoxTLS Library.
*
* File:    noxtls_memory.h
* Summary: NOXTLS Memory Management
*
* This module provides memory allocation functions that can use either
* system malloc/free or a static buffer pool, depending on configuration.
*
*/

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

/* Memory block header */
typedef struct mem_block_header
{
    size_t size;                    /* Size of the block (excluding header) */
    struct mem_block_header *next;   /* Next block in free list */
    uint8_t allocated;               /* 1 if allocated, 0 if free */
} mem_block_header_t;

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
} mem_pool_t;

/** Zero buffer then free; use for buffers that may hold keys or other sensitive data to avoid leakage. (ptr may be NULL.) */
#define NOXTLS_SECURE_FREE(ptr, size) do { if((ptr) != NULL) { noxtls_secure_zero((void*)(ptr), (size)); noxtls_free(ptr); } } while(0)

/* Memory alignment for allocator blocks */
#define NOXTLS_MEM_ALIGNMENT (8u)

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

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _NOXTLS_MEMORY_H_ */


