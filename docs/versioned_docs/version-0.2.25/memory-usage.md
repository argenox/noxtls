---
sidebar_position: 7
title: Memory Usage
description: "NoxTLS documentation: Memory Usage."
---

# Memory Usage

This guide describes how to configure and use the NoxTLS memory management system: system allocator vs. static buffer pool, configuration, and examples.

## Overview

The NoxTLS library provides a configurable memory management system that can use either:

- **System malloc/free** (default) — Standard system memory allocation
- **Static buffer pool** — Pre-allocated buffer managed by the library

## Configuration

Edit `noxtls_config.h` to enable static buffers:

```c
#define NOXTLS_USE_STATIC_BUFFERS 1
#define NOXTLS_STATIC_BUFFER_SIZE (64 * 1024)  /* 64KB default */
```

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

## Notes

- When `NOXTLS_USE_STATIC_BUFFERS` is **0** (default), all allocation functions use system malloc/free.
- When `NOXTLS_USE_STATIC_BUFFERS` is **1**, all library malloc/free calls are routed to the static buffer allocator.
- In static-buffer mode, if `noxtls_mem_init()` is not called explicitly, the allocator lazily initializes on first allocation using `noxtls_mem_init(NULL, 0)` and `NOXTLS_STATIC_BUFFER_SIZE`.
- The compatibility header (`NOXTLS_memory_compat.h`) automatically replaces malloc/free with `noxtls_malloc` / `noxtls_free` in library code.
- Application code can still use standard malloc/free if needed.
