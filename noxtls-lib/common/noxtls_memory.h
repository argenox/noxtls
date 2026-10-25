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

#ifndef NOXTLS_MEMORY_H_
#define NOXTLS_MEMORY_H_

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

/** Value reported by diagnostics when the system allocator is in use. */
#define NOXTLS_MEM_ALLOCATOR_MODE_SYSTEM 3U

/** Size value used when the platform cannot report an amount. */
#define NOXTLS_MEM_SIZE_UNKNOWN SIZE_MAX

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

/** Allocation operation associated with the last memory failure. */
typedef enum
{
    NOXTLS_MEM_OPERATION_NONE = 0,
    NOXTLS_MEM_OPERATION_MALLOC,
    NOXTLS_MEM_OPERATION_CALLOC,
    NOXTLS_MEM_OPERATION_REALLOC,
    NOXTLS_MEM_OPERATION_INITIALIZE
} noxtls_mem_operation_t;

/** Cause recorded for the last failed allocation. */
typedef enum
{
    NOXTLS_MEM_FAILURE_NONE = 0,
    NOXTLS_MEM_FAILURE_POOL_EXHAUSTED,
    NOXTLS_MEM_FAILURE_SYSTEM_ALLOCATOR,
    NOXTLS_MEM_FAILURE_SIZE_OVERFLOW,
    NOXTLS_MEM_FAILURE_INITIALIZATION,
    NOXTLS_MEM_FAILURE_INJECTED
} noxtls_mem_failure_reason_t;

/**
 * Diagnostic details for the most recent failed allocation.
 *
 * `largest_available_block` and `minimum_additional_bytes` describe payload
 * capacity, not allocator metadata. They are `NOXTLS_MEM_SIZE_UNKNOWN` when
 * the host system allocator cannot supply that information. Source strings
 * point at static compiler-generated storage and must not be freed. The
 * record is module-wide; applications using the allocator concurrently must
 * serialize access if they need to associate a diagnostic with one thread.
 */
typedef struct
{
    noxtls_mem_operation_t operation;
    noxtls_mem_failure_reason_t reason;
    uint32_t allocator_mode;
    uint32_t source_line;
    size_t requested_bytes;
    size_t largest_available_block;
    size_t minimum_additional_bytes;
    size_t pool_capacity;
    size_t pool_used;
    const char *source_file;
    const char *source_function;
    /** Static memory: name of the region that could not satisfy the request (NULL otherwise). */
    const char *region_name;
} noxtls_mem_error_info_t;

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

/**
 * Zero buffer then free; use for buffers that may hold keys or other sensitive data to
 * avoid leakage. (ptr may be NULL.) SECURITY (NX-10): the caller pointer is nulled after
 * free so a freed secret pointer cannot be reused (use-after-free / double-free).
 * @p ptr must be an lvalue.
 */
/* Dir 4.9: statement-expression style free+null requires a macro (lvalue assignment). */
#define NOXTLS_SECURE_FREE(ptr, size) do { if((ptr) != NULL) { noxtls_secure_zero((void*)(ptr), (size)); noxtls_free(ptr); (ptr) = NULL; } } while (0 == 1)

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

/** Location-aware allocation entry points used by the public macros below. */
void *noxtls_malloc_at(size_t size, const char *file, uint32_t line, const char *function);
void *noxtls_calloc_at(size_t nmemb, size_t size, const char *file, uint32_t line, const char *function);
void *noxtls_realloc_at(void *ptr, size_t size, const char *file, uint32_t line, const char *function);

/**
 * Copy the most recent allocation failure diagnostic.
 *
 * @return NOXTLS_RETURN_SUCCESS when a failure is available,
 *         NOXTLS_RETURN_NOT_INITIALIZED when none has been recorded, or
 *         NOXTLS_RETURN_NULL when @p info is NULL.
 */
noxtls_return_t noxtls_mem_get_last_error(noxtls_mem_error_info_t *info);

/** Clear the module-wide saved allocation failure diagnostic. */
void noxtls_mem_clear_last_error(void);

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

#if NOXTLS_CONFIG_STATIC_MEMORY
#if NOXTLS_USE_STATIC_BUFFERS
#error "NOXTLS_CONFIG_STATIC_MEMORY and NOXTLS_USE_STATIC_BUFFERS are mutually exclusive"
#endif

/*
 * Static memory (NOXTLS_CONFIG_STATIC_MEMORY=1)
 *
 * Every library allocation is served by a region: a byte array whose size is fixed
 * at build time. An arena region is a bump allocator with LIFO reclamation: a block
 * is carved at the top, a freed block is wiped, and freed blocks at the top return to
 * the free space. A fixed region holds slots that the library places explicitly
 * (record buffers, handshake state); noxtls_free() on a slot pointer does nothing.
 * Allocation uses the region of the active scope (a connection, while one of its API
 * calls runs) or, outside any scope, the global arena (trust store, keys and other
 * process-wide state). An arena that cannot hold a request returns NULL and records
 * NOXTLS_MEM_FAILURE_POOL_EXHAUSTED with the region name. Nothing falls back to
 * another region or to the C library.
 */

/** Region kinds. */
#define NOXTLS_MEM_REGION_ARENA 1U
#define NOXTLS_MEM_REGION_FIXED 2U

/** Bytes of bookkeeping in front of each arena block. */
#define NOXTLS_MEM_REGION_BLOCK_HEADER 16U
/** Arena block payload alignment. */
#define NOXTLS_MEM_REGION_ALIGN 8U
/** Round a byte count up to the region alignment. */
#define NOXTLS_MEM_REGION_ALIGN_UP(n) \
    (((size_t)(n) + ((size_t)NOXTLS_MEM_REGION_ALIGN - 1U)) & ~((size_t)NOXTLS_MEM_REGION_ALIGN - 1U))
/** Arena bytes that one request of @p n payload bytes consumes. */
#define NOXTLS_MEM_REGION_COST(n) (NOXTLS_MEM_REGION_ALIGN_UP(n) + (size_t)NOXTLS_MEM_REGION_BLOCK_HEADER)

/** Connections that can hold static memory at once (caller blocks and pool blocks). */
#ifndef NOXTLS_STATIC_MAX_CONNECTIONS
#define NOXTLS_STATIC_MAX_CONNECTIONS 4U
#endif

/** Regions registered at once: the global arena plus four per connection. */
#ifndef NOXTLS_STATIC_MAX_REGIONS
#define NOXTLS_STATIC_MAX_REGIONS (1U + (4U * NOXTLS_STATIC_MAX_CONNECTIONS))
#endif

/** Certificate pools. Trust anchors installed with noxtls_x509_trust_store_set*(). */
#ifndef NOXTLS_STATIC_TRUST_ANCHORS_MAX
#define NOXTLS_STATIC_TRUST_ANCHORS_MAX 4U
#endif
/** Largest DER certificate accepted anywhere (trust anchor, peer chain, own chain).
 *  Larger certificates are refused with NOXTLS_RETURN_NOT_ENOUGH_MEMORY before any
 *  storage is used. */
#ifndef NOXTLS_STATIC_CERT_DER_MAX
#define NOXTLS_STATIC_CERT_DER_MAX 2048U
#endif
/** Most certificates in a received Certificate message (leaf plus intermediates). */
#ifndef NOXTLS_STATIC_CERT_CHAIN_DEPTH_MAX
#define NOXTLS_STATIC_CERT_CHAIN_DEPTH_MAX 4U
#endif
/** Bytes reserved per parsed certificate structure (checked against
 *  sizeof(x509_certificate_t) at build time). */
#ifndef NOXTLS_STATIC_X509_CERT_STRUCT_BYTES
#define NOXTLS_STATIC_X509_CERT_STRUCT_BYTES 512U
#endif
/** Global arena bytes beyond the trust store: keys and certificates the application
 *  parses outside a connection (for example its client key and certificate). */
#ifndef NOXTLS_STATIC_GLOBAL_EXTRA
#define NOXTLS_STATIC_GLOBAL_EXTRA 4096U
#endif

/** Certificates one chain holds (received chain or trust store). A static-memory chain
 *  allocates this capacity once; one more certificate fails with
 *  NOXTLS_RETURN_NOT_ENOUGH_MEMORY. */
#define NOXTLS_STATIC_CHAIN_CAPACITY \
    ((NOXTLS_STATIC_CERT_CHAIN_DEPTH_MAX > NOXTLS_STATIC_TRUST_ANCHORS_MAX) ? \
     NOXTLS_STATIC_CERT_CHAIN_DEPTH_MAX : NOXTLS_STATIC_TRUST_ANCHORS_MAX)

/** Trust store: the application's chain and the store's copy coexist while
 *  noxtls_x509_trust_store_set() runs (each anchor: DER copy + parsed structure). */
#define NOXTLS_STATIC_TRUST_STORE_BYTES \
    ((2U * ((NOXTLS_STATIC_TRUST_ANCHORS_MAX * NOXTLS_MEM_REGION_COST(NOXTLS_STATIC_CERT_DER_MAX)) + \
            NOXTLS_MEM_REGION_COST(NOXTLS_STATIC_CHAIN_CAPACITY * NOXTLS_STATIC_X509_CERT_STRUCT_BYTES))) + \
     NOXTLS_MEM_REGION_COST(NOXTLS_STATIC_X509_CERT_STRUCT_BYTES))

/** Process-wide arena used outside connection scopes. noxtls_mem_init() may replace
 *  it with a caller buffer while it is empty. */
#ifndef NOXTLS_STATIC_GLOBAL_POOL_SIZE
#define NOXTLS_STATIC_GLOBAL_POOL_SIZE (NOXTLS_STATIC_TRUST_STORE_BYTES + NOXTLS_STATIC_GLOBAL_EXTRA)
#endif

/** Storage class of the active-scope pointer. Empty: one scope for the process, so
 *  NoxTLS calls on different connections must be serialized. Define it as the
 *  compiler's thread-local keyword (_Thread_local, __thread) to give each thread its
 *  own scope. */
#ifndef NOXTLS_STATIC_MEMORY_THREAD_LOCAL
#define NOXTLS_STATIC_MEMORY_THREAD_LOCAL
#endif

/** Compile-time assertion (C99): a false condition gives a negative array size. */
#define NOXTLS_STATIC_ASSERT(cond, name) typedef char noxtls_static_assert_##name[(cond) ? 1 : -1]

/** One region. Fields are read by the statistics API; callers treat it as opaque. */
typedef struct noxtls_mem_region_s
{
    uint8_t *base;          /**< First byte (8-byte aligned). */
    size_t capacity;        /**< Bytes in the region. */
    size_t top;             /**< Arena: first unused byte offset. */
    size_t last;            /**< Arena: offset of the top block header + 1 (0: empty). */
    size_t live_bytes;      /**< Arena: payload bytes allocated. */
    size_t live_blocks;     /**< Arena: blocks allocated. */
    size_t peak;            /**< Arena: high-water mark of top (headers included). */
    size_t allocations;     /**< Arena: successful allocations since initialization. */
    const char *name;       /**< Diagnostic name. */
    uint8_t kind;           /**< NOXTLS_MEM_REGION_ARENA or NOXTLS_MEM_REGION_FIXED. */
    uint8_t registered;     /**< 1 while in the registry. */
    uint8_t released;       /**< 1 after noxtls_mem_region_release(). */
    uint8_t reserved;
} noxtls_mem_region_t;

/** Allocation scope: allocations made while it is active use @c current. */
typedef struct noxtls_mem_scope_s
{
    noxtls_mem_region_t *current;
} noxtls_mem_scope_t;

/** Statistics of one region. */
typedef struct
{
    size_t capacity;
    size_t used;            /**< Arena: bytes between base and top (headers included). */
    size_t peak;            /**< Arena: high-water mark of used. */
    size_t live_bytes;
    size_t live_blocks;
    size_t allocations;
} noxtls_mem_region_stats_t;

/**
 * Prepare and register a region over @p base, which is wiped. @p base must be aligned
 * to NOXTLS_MEM_REGION_ALIGN.
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM, or
 *         NOXTLS_RETURN_NOT_ENOUGH_MEMORY when NOXTLS_STATIC_MAX_REGIONS are registered.
 */
noxtls_return_t noxtls_mem_region_init(noxtls_mem_region_t *region, uint8_t *base, size_t capacity,
                                       uint8_t kind, const char *name);
/** Wipe the whole region with noxtls_secure_zero() and mark it released. Frees of
 *  pointers into it become no-ops and an arena no longer allocates. */
void noxtls_mem_region_release(noxtls_mem_region_t *region);
/** Wipe the region and remove it from the registry. */
void noxtls_mem_region_deinit(noxtls_mem_region_t *region);
/** Copy a region's counters. */
noxtls_return_t noxtls_mem_region_get_stats(const noxtls_mem_region_t *region,
                                            noxtls_mem_region_stats_t *stats);
/** 1 when @p ptr lies inside @p region. */
int noxtls_mem_region_contains(const noxtls_mem_region_t *region, const void *ptr);

/** Make @p scope active; returns the previously active scope (NULL: global arena). */
noxtls_mem_scope_t *noxtls_mem_scope_enter(noxtls_mem_scope_t *scope);
/** Restore the scope returned by noxtls_mem_scope_enter(). */
void noxtls_mem_scope_exit(noxtls_mem_scope_t *previous);

/** The global arena used outside any scope. */
noxtls_mem_region_t *noxtls_mem_global_region(void);
/** Payload bytes live in every registered arena (leak checks). */
size_t noxtls_mem_static_live_bytes(void);
/** Successful arena allocations since start-up, all regions. */
size_t noxtls_mem_static_allocation_count(void);
#endif /* NOXTLS_CONFIG_STATIC_MEMORY */

#if !defined(NOXTLS_MEMORY_IMPLEMENTATION) && !defined(NOXTLS_DISABLE_MEMORY_LOCATION_TRACKING)
#if defined(_MSC_VER)
#define NOXTLS_MEM_CALLER_FUNCTION __FUNCTION__
#else
#define NOXTLS_MEM_CALLER_FUNCTION __func__
#endif
#define NOXTLS_MALLOC(size) \
    noxtls_malloc_at((size), __FILE__, (uint32_t)__LINE__, NOXTLS_MEM_CALLER_FUNCTION)
#define NOXTLS_CALLOC(nmemb, size) \
    noxtls_calloc_at((nmemb), (size), __FILE__, (uint32_t)__LINE__, NOXTLS_MEM_CALLER_FUNCTION)
#define NOXTLS_REALLOC(ptr, size) \
    noxtls_realloc_at((ptr), (size), __FILE__, (uint32_t)__LINE__, NOXTLS_MEM_CALLER_FUNCTION)
#else
#define NOXTLS_MALLOC(size) noxtls_malloc(size)
#define NOXTLS_CALLOC(nmemb, size) noxtls_calloc(nmemb, size)
#define NOXTLS_REALLOC(ptr, size) noxtls_realloc(ptr, size)
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* NOXTLS_MEMORY_H_ */

