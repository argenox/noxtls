---
sidebar_position: 5
title: Porting Guide
description: "NoxTLS documentation: Porting Guide."
---

# Porting Guide

Having ported many libraries to a variety of platforms, we know that getting a library working quickly and reliably in your own platform is one of the most important things. 

We designed NoxTLS to be easy to port to a variety of platforms, especially embedded devices.

This guide will help you bring up NoxTLS to a new platform or integrate it with your build system and runtime environment.

## Overview

NoxTLS is written in C99 and uses a small set of abstractions for memory, I/O, and optional platform hooks. Porting typically involves:

- **Build integration**: CMake or your own build (Makefile, Meson, etc.)
- **Platform APIs**: Replace or configure memory allocator, entropy source, and (for TLS) socket/network layer
- **Configuration**: Enable or disable features via macros or config headers to control the space utilization

## Build integration

### CMake

The library provides a top-level `CMakeLists.txt`. To use NoxTLS as a subdirectory or fetched dependency:

```cmake
add_subdirectory(noxtls)
target_link_libraries(your_app noxtls)
```

Or with FetchContent:

```cmake
include(FetchContent)
FetchContent_Declare(noxtls
  GIT_REPOSITORY https://github.com/your-org/noxtls.git
  GIT_TAG        v1.0.0
)
FetchContent_MakeAvailable(noxtls)
target_link_libraries(your_app noxtls)
```

### Custom builds

- Add all sources under `noxtls-lib/` (and optionally `utility/`) to your build.
- Define the same macros and include paths your CMake build would use (see Configuration Guide).
- Exclude optional modules (e.g. TLS, PKC) by not compiling their sources if not needed.

## Platform abstractions

### Memory

All library allocations go through the NoxTLS allocator (`noxtls_malloc()` / `noxtls_calloc()` / `noxtls_realloc()` / `noxtls_free()`, called through the `NOXTLS_MALLOC`-style macros). By default it forwards to the C library `malloc`/`free`. To use a fixed pool instead, set `NOXTLS_USE_STATIC_BUFFERS=1` and call `noxtls_mem_init()`. See [Memory usage](./memory-usage.md).

Since 0.3.0 the library no longer remaps `malloc`/`free` with `#define` wrappers (MISRA C:2025 Rule 21.2), and `scripts/check_allocator_policy.py` rejects raw allocator calls outside the allocator implementation. Port code that relied on the old remap should call `noxtls_malloc()`/`noxtls_free()` explicitly. See [MISRA C:2025](./misra-c.md).

### Entropy and random

Cryptographic operations that need randomness (key generation, nonces, etc.) depend on a secure random source. The library may call a platform abstraction (e.g. `noxtls_rand_bytes` or similar). Implement this with your OS or hardware RNG (e.g. `/dev/urandom`, CSPRNG, or HWRNG).

### Threads and the shared random generator

NoxTLS has no built-in mutexes. Per-connection objects (TLS contexts, keys, PAKE contexts) need no locking as long as each one is used by one thread at a time, but one piece of state is process-global: the PKC CTR-DRBG behind ECDSA nonces, EC / X25519 / X448 / Ed25519 / Ed448 key generation and RSA blinding (`NOXTLS_PKC_SHARED_DRBG=1`, the default). Two handshakes that draw from it at the same moment can otherwise receive the same output, or output from a state that is still being seeded on first use; a repeated ECDSA nonce reveals the signing key.

If handshakes or public-key operations run on more than one thread or RTOS task, install a lock once at start-up, before any of those threads run:

```c
#include "drbg/noxtls_drbg.h"

static pthread_mutex_t s_drbg_mutex = PTHREAD_MUTEX_INITIALIZER;
static void drbg_lock(void *user)   { (void)pthread_mutex_lock((pthread_mutex_t *)user); }
static void drbg_unlock(void *user) { (void)pthread_mutex_unlock((pthread_mutex_t *)user); }

noxtls_drbg_set_lock_callbacks(drbg_lock, drbg_unlock, &s_drbg_mutex);
```

- The lock covers first-use instantiation, reseeding and every generate request; a new DRBG state is seeded privately and published only when complete.
- The same lock also serialises the process-global TLS 1.3 server ticket store (add, lookup, remove and `noxtls_tls13_psk_ticket_store_clear()`), so a resuming handshake cannot read a ticket while another thread rewrites it. The TLS 1.2 session caches are not covered; serialize TLS 1.2 server handshakes that use session resumption.
- The lock does not need to be recursive: the library never takes it twice on one thread. Your entropy callback runs while it is held and must not call back into the PKC layer.
- FreeRTOS (`xSemaphoreTake`/`xSemaphoreGive` on a mutex) and Zephyr (`k_mutex_lock`/`k_mutex_unlock`) wrap the same way. `noxtls_drbg_set_lock_callbacks(NULL, NULL, NULL)` removes the lock.
- Without a lock (the default, unchanged behaviour) the application must serialize all handshakes and PKC operations that can draw random bits, as before.
- EC-JPAKE draws from a per-call DRBG seeded from the entropy source, and ML-KEM, ML-DSA and FFDHE use per-call DRBGs too, so none of them needs the lock. Other shared modes that remain caller-serialized are listed in [Memory usage](./memory-usage.md) (`NOXTLS_ECC_SHARED_SCRATCH`, `NOXTLS_HMAC_SHA256_SHARED_STATE`, the opt-in global ECC precompute caches).

### TLS / networking

For TLS and DTLS, the library needs:

- A way to send and receive encrypted data (often over sockets).
- Optional callbacks for certificate verification, PSK, or ALPN.

Porting usually means implementing the TLS transport layer (sockets or equivalent) and wiring the library’s send/receive and callback interfaces to your stack.

## Testing on the new platform

- Run the project’s test suite (e.g. unit tests and any integration tests) on the target.
- If you use a simulator or emulator, run the same tests there before moving to real hardware.

## Zephyr RTOS

NoxTLS ships as a [Zephyr west module](https://docs.zephyrproject.org/latest/develop/modules.html). Add the repository to your manifest at `modules/crypto/noxtls`, enable `CONFIG_NOXTLS=y` in your application, and link with `target_link_libraries(app PRIVATE noxtls)`.

Integration files live under `ports/zephyr/`; the required `zephyr/module.yml` at the NoxTLS repository root points the Zephyr build system at that port. Entropy is wired to Zephyr’s CSRNG via `sys_csrand_get()` when `CONFIG_NOXTLS_USE_ZEPHYR_ENTROPY` is enabled.

See **ports/zephyr/README.md** in the NoxTLS repository for the west manifest snippet, sample application, and Twister tests.

## ESP-IDF

NoxTLS ships as an ESP-IDF component under `ports/esp-idf/`. Add the directory to `EXTRA_COMPONENT_DIRS` in your application `CMakeLists.txt`, enable `CONFIG_NOXTLS=y` in `sdkconfig`, and depend on the component with `REQUIRES esp-idf` from your app components.

Entropy is wired to the ESP hardware RNG via `esp_fill_random()` when `CONFIG_NOXTLS_USE_ESP_ENTROPY` is enabled.

See **ports/esp-idf/README.md** in the NoxTLS repository for `EXTRA_COMPONENT_DIRS` setup, the TLS client example, and Kconfig / RAM tuning.

## Next steps

- See the **Configuration Guide** for build options, feature macros, and optional components.
- See **Getting Started** for a minimal build and **Crypto API** for the public API.
