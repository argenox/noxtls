# NOXTLS Memory Management Usage

## Overview

The NOXTLS library provides a configurable memory management system that can use either:
- **System malloc/free** (default) - Standard system memory allocation
- **Static buffer pool** - Pre-allocated buffer managed by the library

## Configuration

Edit `noxtls_config.h` to enable static buffers:

```c
#define NOXTLS_USE_STATIC_BUFFERS 1
#define NOXTLS_STATIC_BUFFER_SIZE (64 * 1024)  /* 64KB default */
```

## Usage with Static Buffers

### Option 1: Provide Your Own Buffer

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

You can query memory usage statistics (static-buffer mode):

```c
size_t total_allocated;
size_t total_used;
size_t max_used;

if(noxtls_mem_get_stats(&total_allocated, &total_used, &max_used) == NOXTLS_RETURN_SUCCESS) {
    printf("Total allocated: %zu bytes\n", total_allocated);
    printf("Currently used: %zu bytes\n", total_used);
    printf("Peak usage: %zu bytes\n", max_used);
}
```

## Last Allocation Failure

When an operation reports `NOXTLS_RETURN_NOT_ENOUGH_MEMORY`, the last allocator
failure can be inspected without enabling test instrumentation:

```c
noxtls_mem_error_info_t error;

if(noxtls_mem_get_last_error(&error) == NOXTLS_RETURN_SUCCESS) {
    printf("OOM at %s:%u (%s): requested=%zu, additional=%zu\n",
           error.source_file != NULL ? error.source_file : "<unknown>",
           (unsigned)error.source_line,
           error.source_function != NULL ? error.source_function : "<unknown>",
           error.requested_bytes,
           error.minimum_additional_bytes);
}
```

The saved record persists until another allocation fails or
`noxtls_mem_clear_last_error()` is called. Static pools report the minimum
additional contiguous payload capacity. System allocators use
`NOXTLS_MEM_SIZE_UNKNOWN` for capacity values the host cannot determine. The
record is module-wide, so concurrent users should serialize access when they need
per-thread attribution.

## P-256 embedded-memory options

Enable `NOXTLS_ECC_P256_FLASH_PRECOMPUTE` to replace the 6528-byte heap-backed
P-256 generator table with a compact 2048-byte read-only table placed in
flash/ROM by the linker. Enable `NOXTLS_ECC_P256_LOW_RAM_VERIFY` as well to
replace the 13056-byte ECDSA verification joint table with a compact 512-byte
runtime public-key table. The low-RAM verification option requires the flash
precompute option and trades some verification speed for substantially lower
peak and retained heap use.

## Notes

- When `NOXTLS_USE_STATIC_BUFFERS` is 0 (default), all functions use system malloc/free
- When `NOXTLS_USE_STATIC_BUFFERS` is 1, all library malloc/free calls are routed to the static buffer allocator
- In static-buffer mode, if `noxtls_mem_init()` is not called explicitly, allocator init occurs lazily on first allocation with `noxtls_mem_init(NULL, 0)`.
- The compatibility header (`NOXTLS_memory_compat.h`) automatically replaces malloc/free with noxtls_malloc/noxtls_free in library code
- Application code can still use standard malloc/free if needed


