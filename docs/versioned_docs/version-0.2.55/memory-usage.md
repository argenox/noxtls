---
sidebar_position: 7
title: Memory Usage
description: "NoxTLS documentation: Memory Usage."
---

# Memory Usage

This guide describes how to configure and use the NoxTLS memory management system: system allocator vs. static buffer pool, bucket pools, configuration, and examples.

## Overview

The NoxTLS library provides a configurable memory management system that can use either:

- **System malloc/free** (default) — Standard system memory allocation
- **Static buffer pool** — Pre-allocated buffer managed by the library

When static buffers are enabled, the pool can use one of three allocator strategies:

| Mode | `NOXTLS_STATIC_ALLOCATOR_MODE` | Behavior |
|------|--------------------------------|----------|
| **HYBRID** (default) | `NOXTLS_STATIC_ALLOCATOR_MODE_HYBRID` | Fixed-size **bucket pools** for common allocation sizes; remaining buffer space is a **fallback** first-fit pool for larger or overflow allocations |
| **BUCKETS** | `NOXTLS_STATIC_ALLOCATOR_MODE_BUCKETS` | Bucket pools only; allocations that do not fit any bucket class fail |
| **LEGACY** | `NOXTLS_STATIC_ALLOCATOR_MODE_LEGACY` | Original single first-fit pool over the entire buffer (no buckets) |

Bucket allocation is **O(1)** and avoids fragmentation for the size classes you configure. HYBRID is recommended for embedded TLS workloads where most allocations are small but occasional larger handshake buffers are still needed.

## Configuration

Edit `noxtls_config.h` to enable static buffers and tune the allocator:

```c
#define NOXTLS_USE_STATIC_BUFFERS 1
#define NOXTLS_STATIC_BUFFER_SIZE (64 * 1024)  /* 64KB default */

/* Default: try buckets first, then fallback pool */
#define NOXTLS_STATIC_ALLOCATOR_MODE NOXTLS_STATIC_ALLOCATOR_MODE_HYBRID
```

### Bucket pool settings

Bucket classes are defined at compile time. Each class has a block size and a block count. At `noxtls_mem_init()`, the library lays out fixed blocks for every class from the start of your pool buffer; in HYBRID mode, any bytes left after bucket layout become the fallback pool.

Default configuration (from `noxtls_config.h`):

```c
#define NOXTLS_MEM_BUCKET_COUNT 9U
#define NOXTLS_MEM_BUCKET_SIZES  32U, 64U, 128U, 256U, 512U, 1024U, 2048U, 4096U, 8192U
#define NOXTLS_MEM_BUCKET_COUNTS 16U, 16U, 12U, 10U, 8U, 6U, 4U, 2U, 1U
#define NOXTLS_MEM_BUCKET_ALIGNMENT 8U
```

**Sizing a pool buffer:** ensure `NOXTLS_STATIC_BUFFER_SIZE` (or the buffer you pass to `noxtls_mem_init()`) is large enough for:

1. Every bucket block: `(sizeof(header) + aligned_block_size) × count` for each class
2. In HYBRID or LEGACY mode, additional space for the fallback first-fit allocator (including alignment padding)

If the buffer is too small, `noxtls_mem_init()` returns `NOXTLS_RETURN_FAILED`. Increase `NOXTLS_STATIC_BUFFER_SIZE` or reduce `NOXTLS_MEM_BUCKET_COUNTS` / `NOXTLS_MEM_BUCKET_COUNT` for tighter RAM budgets.

**Choosing a mode:**

- Use **HYBRID** when you want predictable small allocations plus occasional large TLS records or certificate buffers.
- Use **BUCKETS** when you want hard upper bounds on allocation size and can size every class explicitly (no fallback).
- Use **LEGACY** only when you need backward-compatible behavior identical to pre-0.2.55 static pools.

## Usage with Static Buffers

### Option 1: Provide Your Own Buffer

Supply a pre-allocated buffer to the library. All internal allocations then use this buffer instead of system malloc.

```c
#include "noxtls_memory.h"

uint8_t my_buffer[64 * 1024];  /* 64KB static buffer */

int main(void) {
    /* Initialize with your buffer */
    noxtls_return_t rc = noxtls_mem_init(my_buffer, sizeof(my_buffer));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        /* Handle error */
        return -1;
    }
    
    /* Use library functions - all malloc/free calls will use your buffer */
    /* ... your code ... */
    
    /* Cleanup when done */
    noxtls_mem_cleanup();
    
    return 0;
}
```

### Option 2: Let Library Allocate Buffer

Pass `NULL` as the buffer and a size; the library allocates the pool internally (via system malloc). Useful when you want a fixed cap on NoxTLS heap usage without managing the buffer yourself.

```c
#include "noxtls_memory.h"

int main(void) {
    /* Initialize with NULL - library will allocate buffer internally */
    noxtls_return_t rc = noxtls_mem_init(NULL, 128 * 1024);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        /* Handle error */
        return -1;
    }
    
    /* Use library functions */
    /* ... your code ... */
    
    /* Cleanup - will free internally allocated buffer */
    noxtls_mem_cleanup();
    
    return 0;
}
```

## Memory Statistics

You can query memory usage statistics at runtime (static-buffer mode):

```c
#include "noxtls_memory.h"
#include <stdio.h>

size_t total_allocated, total_used, max_used;
if(noxtls_mem_get_stats(&total_allocated, &total_used, &max_used) == NOXTLS_RETURN_SUCCESS) {
    printf("Total allocated: %zu bytes\n", total_allocated);
    printf("Currently used: %zu bytes\n", total_used);
    printf("Peak usage: %zu bytes\n", max_used);
}
```

### Bucket pool statistics

When bucket pools are enabled (BUCKETS or HYBRID), use `noxtls_mem_get_bucket_stats()` to inspect per-class utilization and fallback usage:

```c
#include "noxtls_memory.h"
#include <stdio.h>

noxtls_mem_bucket_stats_t stats;
if(noxtls_mem_get_bucket_stats(&stats) == NOXTLS_RETURN_SUCCESS) {
    size_t i;
    printf("Allocator mode: %u\n", (unsigned)stats.allocator_mode);
    printf("Fallback used: %zu / peak %zu (pool size %zu)\n",
           stats.fallback_used, stats.fallback_max_used, stats.fallback_size);
    for(i = 0; i < stats.bucket_count; ++i) {
        const noxtls_mem_bucket_stat_t *b = &stats.buckets[i];
        printf("Bucket %zu: size=%zu total=%zu used=%zu free=%zu\n",
               i, b->block_size, b->total_blocks, b->used_blocks, b->free_blocks);
    }
}
```

Use these counters during bring-up to tune `NOXTLS_MEM_BUCKET_SIZES` and `NOXTLS_MEM_BUCKET_COUNTS`. If the fallback pool shows sustained high usage in HYBRID mode, add blocks to the matching bucket class or increase the overall buffer size.

## Notes

- When `NOXTLS_USE_STATIC_BUFFERS` is **0** (default), all allocation functions use system malloc/free.
- When `NOXTLS_USE_STATIC_BUFFERS` is **1**, all library malloc/free calls are routed to the static buffer allocator.
- In static-buffer mode, if `noxtls_mem_init()` is not called explicitly, the allocator lazily initializes on first allocation using `noxtls_mem_init(NULL, 0)` and `NOXTLS_STATIC_BUFFER_SIZE`.
- Bucket frees return blocks to their class free list; fallback frees use coalescing first-fit logic (LEGACY and HYBRID fallback only).
- The compatibility header (`noxtls_memory_compat.h`) automatically replaces malloc/free with `noxtls_malloc` / `noxtls_free` in library code.
- Application code can still use standard malloc/free if needed.
