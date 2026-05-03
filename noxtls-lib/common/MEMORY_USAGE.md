# NOXTLS Memory Management Usage

## Overview

The NOXTLS library provides a configurable memory management system that can use either:
- **System malloc/free** (default) - Standard system memory allocation
- **Static buffer pool** - Pre-allocated buffer managed by the library

## Configuration

Edit `NOXTLS_config.h` to enable static buffers:

```c
#define NOXTLS_USE_STATIC_BUFFERS 1
#define NOXTLS_STATIC_BUFFER_SIZE (128 * 1024)  /* 128KB default */
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

You can query memory usage statistics:

```c
size_t total_allocated, total_used, max_used;
noxtls_mem_get_stats(&total_allocated, &total_used, &max_used);
printf("Total allocated: %zu bytes\n", total_allocated);
printf("Currently used: %zu bytes\n", total_used);
printf("Peak usage: %zu bytes\n", max_used);
```

## Notes

- When `NOXTLS_USE_STATIC_BUFFERS` is 0 (default), all functions use system malloc/free
- When `NOXTLS_USE_STATIC_BUFFERS` is 1, all library malloc/free calls are routed to the static buffer allocator
- The compatibility header (`NOXTLS_memory_compat.h`) automatically replaces malloc/free with noxtls_malloc/noxtls_free in library code
- Application code can still use standard malloc/free if needed


