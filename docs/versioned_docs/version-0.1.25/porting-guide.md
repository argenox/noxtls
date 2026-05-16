---
sidebar_position: 5
title: "Porting Guide"
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

By default, NoxTLS uses `malloc` / `free` / `realloc`. To override:

- Provide your own implementations (e.g. linked before the library, or via `#define` wrappers) so that the symbols resolve to your allocator.
- Or use the configuration layer (if available) to point the library at custom allocator function pointers.

### Entropy and random

Cryptographic operations that need randomness (key generation, nonces, etc.) depend on a secure random source. The library may call a platform abstraction (e.g. `noxtls_rand_bytes` or similar). Implement this with your OS or hardware RNG (e.g. `/dev/urandom`, CSPRNG, or HWRNG).

### TLS / networking

For TLS and DTLS, the library needs:

- A way to send and receive encrypted data (often over sockets).
- Optional callbacks for certificate verification, PSK, or ALPN.

Porting usually means implementing the TLS transport layer (sockets or equivalent) and wiring the library’s send/receive and callback interfaces to your stack.

## Testing on the new platform

- Run the project’s test suite (e.g. unit tests and any integration tests) on the target.
- If you use a simulator or emulator, run the same tests there before moving to real hardware.

## Next steps

- See the **Configuration Guide** for build options, feature macros, and optional components.
- See **Getting Started** for a minimal build and **Crypto API** for the public API.
