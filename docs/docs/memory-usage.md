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

For devices that must not use a heap at all, `NOXTLS_CONFIG_STATIC_MEMORY` sizes
every byte at build time instead: per-connection blocks supplied by the caller,
handshake storage released after the handshake, and fixed certificate pools. See
[Static Memory](./static-memory.md).

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
- Use **LEGACY** only when you need backward-compatible behavior identical to pre-0.2.56 static pools.

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

## Last Allocation Failure

Use `NOXTLS_MALLOC`, `NOXTLS_CALLOC`, and `NOXTLS_REALLOC` at call sites to
capture source file, function, and line. These macros have distinct names from
the exported allocation functions, as required by the MISRA identifier rules.
The lowercase `noxtls_malloc`, `noxtls_calloc`, and `noxtls_realloc` functions
remain available with their existing ABI and record failures without a source
location. Defining `NOXTLS_DISABLE_MEMORY_LOCATION_TRACKING` makes the uppercase
macros call those functions directly.

After an API returns `NOXTLS_RETURN_NOT_ENOUGH_MEMORY`, query the allocator's
most recent failure:

```c
#include "noxtls_memory.h"
#include <stdio.h>

noxtls_mem_error_info_t error;

if(noxtls_mem_get_last_error(&error) == NOXTLS_RETURN_SUCCESS) {
    printf("allocation failed at %s:%u in %s\n",
           error.source_file != NULL ? error.source_file : "<unknown>",
           (unsigned)error.source_line,
           error.source_function != NULL ? error.source_function : "<unknown>");
    printf("requested=%zu, largest-block=%zu, additional=%zu\n",
           error.requested_bytes,
           error.largest_available_block,
           error.minimum_additional_bytes);
}
```

The record persists across successful allocations so cleanup cannot erase the
evidence. Call `noxtls_mem_clear_last_error()` before an operation when you want
to distinguish a new failure from an older one. The static allocator reports an
exact contiguous-payload shortfall. A system allocator may report
`NOXTLS_MEM_SIZE_UNKNOWN` because the host does not expose remaining heap capacity.
The record is module-wide; concurrent callers must serialize diagnostic access if
they need to associate a failure with a particular thread.

## Embedded Heap Profiles

The unit-test build includes four algorithm profile executables with fixed static
heap pools of 32, 64, 128, and 256 KiB. Run them with the normal all-tests script,
or select only the profiles:

```powershell
.\run_tests_all.ps1 -Filter "embedded_memory"
```

Every enabled hash, block/stream cipher variant, AEAD/MAC, DRBG, finite-field DH,
RSA size, DSA size, modern curve, and supported ECC curve is exercised with a
fresh pool. Output reports context-state bytes, allocator peak/live bytes,
allocation count, cumulative requested bytes, and largest single request. A real
pool exhaustion reports the allocation location and exact contiguous-payload
shortfall from `noxtls_mem_get_last_error()`.

Every configured Weierstrass ECC curve performs scalar multiplication. The curve
profiles also include a full P-256 workflow (two public-key derivations,
bidirectional ECDH, and ECDSA/SHA-256 sign/verify), X25519 and X448 key-agreement
round trips, and Ed25519 and Ed448 public-key/sign/verify round trips. These
operations run without injected failures, so any OOM result is caused by the
selected embedded heap limit.

These profiles use the LEGACY first-fit allocator so the entire stated pool is
available to the algorithm; allocator-policy behavior is covered separately by
the LEGACY, BUCKETS, HYBRID, and system allocator tests. The pool limit covers
NoxTLS heap allocations. `state=` reports explicit context storage separately;
compiler stack-frame usage is not included in the heap cap.

### P-256 flash and low-RAM modes

The P-256 generator table lives in flash and ECDSA verification uses the
low-RAM path by default:

```cmake
-DNOXTLS_ECC_P256_FLASH_PRECOMPUTE=ON      # default
-DNOXTLS_ECC_P256_LOW_RAM_VERIFY=ON        # default (requires the flash table)
-DNOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE=OFF   # default
```

`NOXTLS_ECC_P256_FLASH_PRECOMPUTE` stores a 2048-byte constant affine generator
comb table in flash. `NOXTLS_ECC_P256_LOW_RAM_VERIFY` computes the generator side
from that table and builds only a small compact table for the runtime public key,
released after each operation. All precompute tables store affine X||Y entries
(64 bytes per P-256 point) with constant-time selection.

Measured heap peaks (host, default configuration): P-256 ECDSA verify 2,056 bytes
(was 20,056), an ECDHE key kept alive while two certificates are verified 2,792
bytes (was 30,184), and 32 bytes held per P-256 key (was 6,864). Host timing for
sign, verify and ECDH is equal or faster than the previous cache-based defaults.
`NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE=1` keeps a per-curve cache for workloads that
sign repeatedly with one long-lived key.

## RAM tuning reference

The defaults below favour embedded targets. Profile presets
(`NOXTLS_PROFILE_*`) only supply values that are not already defined, so any
setting can be adjusted on top of a profile with `-D`.

| Setting | Default | Effect |
|---|---|---|
| `NOXTLS_FEATURE_TLS_CLIENT` / `NOXTLS_FEATURE_TLS_SERVER` | 1 / 1 | Compile out the unused TLS role, including the server caches. |
| `NOXTLS_TLS12_SESSION_CACHE_SIZE` | 16 | TLS 1.2 server session-ID cache entries (0 compiles it out). |
| `NOXTLS_TLS12_TICKET_CACHE_SIZE` / `NOXTLS_TLS12_TICKET_MAX_LEN` | 32 / 256 | TLS 1.2 server ticket cache entries and ticket length. |
| `NOXTLS_TLS13_PSK_TICKET_STORE_MAX` | 64 | TLS 1.3 server ticket store entries (0..64). |
| `NOXTLS_TLS_MAX_RECORD_SIZE` | 16384 | Record payload limit; sizes the single lazily allocated transmit buffer. |
| `NOXTLS_TLS13_SERVER_MAX_EARLY_DATA` | 16384 | 0-RTT data a TLS 1.3 server buffers. |
| `NOXTLS_DTLS_REASSEMBLY_MAX_BYTES` | 2 x `NOXTLS_TLS_MAX_HANDSHAKE_SIZE` | Total DTLS handshake reassembly memory a peer can pin. |
| `NOXTLS_TLS_RETAIN_PEER_CERT` | 0 | Keep the parsed peer certificate after the handshake (the DER is always kept). |
| `NOXTLS_X509_FAIL_INFO` | 1 | Detailed certificate failure strings (556 bytes of static RAM when on). |
| `NOXTLS_X509_CHAIN_INITIAL_CAPACITY` | 1 | Linear growth step for certificate chains (chains allocate lazily). |
| `NOXTLS_ECC_ENABLE_<curve>` | 1 | Per-curve switches; `ECC_MAX_KEY_SIZE` follows the largest enabled curve (P-256 only: 32 bytes, halving every ECC point and table). |
| `NOXTLS_PKC_SHARED_DRBG` | 1 | One CTR-DRBG instance for all public-key modules (serialize PKC randomness across threads). |
| `NOXTLS_BN_MONT_WINDOW_BITS` | 4 | Window width of the private-key Montgomery exponentiation (1..6). |
| `NOXTLS_AES_ROM_TABLES` | 1 | AES T-tables in flash (4 KB); 0 builds them in RAM at first use. |
| `NOXTLS_AES_COMPACT_TABLES` | 0 | Keep one 1 KB T-table and derive the others by rotation. |
| `NOXTLS_GCM_TABLE_BITS` | 4 | 0 selects a table-free, constant-time GHASH. |
| `NOXTLS_AES_CTX_RAW_KEY` | 1 | 0 drops the raw key copy from AES contexts in software-only builds. |
| `NOXTLS_ED25519_READONLY_COMB` | 1 | Ed25519 base tables as constant data in flash (9.6 KB moved out of RAM). |
| `NOXTLS_FEATURE_KEYLOG` | 0 | SSLKEYLOGFILE support (debug builds only). |

`NOXTLS_PROFILE_MINIMAL_TLS_CLIENT` selects TLS 1.2/1.3 client-only with
ECDHE (X25519, P-256), ECDSA P-256 server authentication, AES-GCM and SHA-256,
no stdio and no certificate failure strings. Enable RSA, SHA-384 or more curves
with `-D` when the servers you connect to need them.

Measured on the host (`ut/ram_budget`, default configuration, 16 KB records), a
TLS 1.3 client uses about 33 KB of heap at the handshake peak and about 17 KB
after the handshake, of which about 16.5 KB is the record transmit buffer; with
`NOXTLS_TLS_MAX_RECORD_SIZE=4096` the steady state is about 4.7 KB. The
connection object is 2,816 bytes on Cortex-M4 (1,488 bytes in the minimal
client profile).

## Notes

- When `NOXTLS_USE_STATIC_BUFFERS` is **0** (default), all allocation functions use system malloc/free.
- When `NOXTLS_USE_STATIC_BUFFERS` is **1**, all library malloc/free calls are routed to the static buffer allocator.
- In static-buffer mode, if `noxtls_mem_init()` is not called explicitly, the allocator lazily initializes on first allocation using `noxtls_mem_init(NULL, 0)` and `NOXTLS_STATIC_BUFFER_SIZE`.
- Bucket frees return blocks to their class free list; fallback frees use coalescing first-fit logic (LEGACY and HYBRID fallback only).
- Library code calls the NoxTLS allocator explicitly (`NOXTLS_MALLOC`, `NOXTLS_CALLOC`, `NOXTLS_REALLOC`, `noxtls_free()`). Since 0.3.0, `noxtls_memory_compat.h` no longer `#define`s `malloc`/`free`/`calloc`/`realloc` (MISRA C:2025 Rule 21.2). Raw allocator calls are allowed only in `noxtls_memory.c` and `noxtls_memory_stdlib.c`, which `scripts/check_allocator_policy.py` (CTest `allocator_policy_check`) enforces. See [MISRA C:2025](./misra-c.md#allocator-routing-no-raw-allocator-calls).
- With `NOXTLS_USE_STATIC_BUFFERS=1`, the allocator translation unit does not include `<stdlib.h>`, so static-pool builds never reference `malloc`/`free`.
- Application code can still use standard malloc/free if needed.

### Concurrent crypto scratch storage

HMAC contexts embed their hash state and the precomputed key-pad chaining values, so HMAC never allocates and independent streaming contexts may be interleaved; contexts are wiped on final or free. `NOXTLS_HMAC_SHA256_SHARED_STATE` is deprecated and has no effect.

ECC inversion and the P-256 bignum inversion fast path use private, bounded scratch arrays. With ARM GNU 16.1, Cortex-M4 and `-O2`, the measured function frames were 512 and 232 bytes respectively; callers and callees require additional stack. Check the complete call-chain budget on each embedded target. These changes do not make the shared static allocator or module-wide diagnostics thread-safe; applications using those facilities concurrently must provide synchronization.

For externally serialized builds, the ECC scratch can be shared (default `OFF`):

```sh
-DNOXTLS_ECC_SHARED_SCRATCH=ON
```

The equivalent preprocessor setting is `NOXTLS_ECC_SHARED_SCRATCH=1`; it is also exposed by the generated ESP-IDF and Zephyr configuration.

The ECC option moves the inversion scratch to fixed storage, reducing stack use. All access to the affected ECC and P-256 bignum inversion paths must be externally serialized, including interrupt callers. Shared mode does not support reentrant calls. Keep private mode for concurrent handshakes unless the integration supplies suitable serialization at the crypto-operation boundaries.
