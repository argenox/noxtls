---
sidebar_position: 7
title: Port NoxTLS to Your Platform
description: Integrate NoxTLS on Zephyr, custom RTOS, or bare-metal with CMake, memory, entropy, and I/O hooks.
keywords:
  - porting
  - zephyr
  - embedded
  - platform
---

# Port NoxTLS to Your Platform

NoxTLS is **C99** and designed to port to embedded targets, desktop hosts, and RTOS environments. This page is a practical checklist; the [Porting Guide](../porting-guide) has additional detail.

## Porting checklist

| Step | What to do |
|------|------------|
| 1. Build integration | CMake subdirectory, or compile `noxtls-lib/` sources in your IDE/Makefile |
| 2. Configuration | Pick a [profile](../configuration-guide); disable unused algorithms |
| 3. Memory | Route allocations to your heap or static pools |
| 4. Entropy | Provide a CSPRNG (`/dev/urandom`, hardware TRNG, RTOS service) |
| 5. Time (optional) | RTC for certificate validity; or test-only time bypass |
| 6. Transport | TCP for TLS, UDP for DTLS — send/recv callbacks |
| 7. Test | Run unit tests on host; target smoke tests on device |

## CMake integration (recommended)

```cmake
add_subdirectory(path/to/noxtls)
target_link_libraries(your_app PRIVATE noxtls_tls noxtls_pkc noxtls_common)
# Link only the targets your app needs — see noxtls/CMakeLists.txt
```

For library-only firmware:

```bash
cmake -S noxtls -B build \
  -D BUILD_APPLICATIONS=OFF \
  -D BUILD_TESTS=OFF \
  -D NOXTLS_PROFILE=minimal_tls_client
```

## Zephyr RTOS

Typical pattern:

1. Add NoxTLS as a west module or `add_subdirectory` from your app CMake.
2. Set `NOXTLS_OMIT_UT_SOURCES ON` so unit-test sources are excluded.
3. Link against `zephyr_interface` / NoxTLS targets so ABI matches the kernel build.
4. Implement socket or offloaded networking that feeds TLS/DTLS record read/write.
5. Map entropy to the Zephyr random API or hardware driver.

See Zephyr-specific notes in [Porting Guide](../porting-guide) and [Getting Started](../getting-started).

## Memory

Default allocation uses `malloc` / `free`. Options:

- Wrap standard library allocators at link time
- Use static buffers for TLS contexts where possible ([Memory usage](../memory-usage))
- Enable bounded allocator patterns for safety-critical firmware (see library memory APIs in [Common](../api/common))

## Entropy and DRBG

Key generation, DTLS cookies, and nonces require unpredictable bytes. Wire the platform hook used by the DRBG seed path (see [DRBG](../api/drbg) and port-specific notes under `noxtls/ports/`).

Never ship with a stub RNG that returns predictable values.

## TLS and DTLS I/O

The stack is **transport-agnostic**:

- **TLS:** read/write encrypted records on a connected TCP stream
- **DTLS:** datagram-oriented send/receive with MTU awareness

Start from host samples (`https_client`, `https_server`), then replace socket calls with your driver. [Run DTLS on Embedded Devices](./dtls-embedded) covers UDP-specific tuning.

## Hardware acceleration (optional)

| Platform | Option |
|----------|--------|
| x86/x64 | `NOXTLS_CFG_FEATURE_AES_ACCEL_NI=ON` |
| Apple Silicon | `NOXTLS_CFG_FEATURE_AES_ACCEL_APPLE=ON` |
| STM32 / ESP | Vendor files under `noxtls/ports/` and `vendor/` |

Acceleration is selected at build time; see [Configuration Guide](../configuration-guide).

## Feature trimming

Use `NOXTLS_PROFILE=crypto_only` if you only need algorithms without TLS. Use `minimal_tls_client` for TLS client + modern crypto without server-heavy legacy suites.

Preprocessor flags mirror CMake options — see `noxtls_config.h` and [Build config API](../api/build_config).

## Validate on the target

1. Build a minimal app that runs AES-SHA self-tests or known-answer tests from your CI vectors.
2. Run TLS client against a known public server (or your staging HTTPS endpoint).
3. Run DTLS PSK against OpenSSL on a host (commands in [DTLS PSK demo](../applications/app_dtls_psk_demo)).
4. Stress-test MTU and packet loss on your radio link.

## Get help from reference material

| Resource | Topic |
|----------|--------|
| [Architecture](../architecture) | Module layout |
| [Configuration Guide](../configuration-guide) | Flags and profiles |
| [Security](../security) | Hardening expectations |
| [Porting Guide](../porting-guide) | Extended porting narrative |
| [Start Here — Quickstart](./quickstart) | Host build sanity |

## Next steps

You should now have a path from host build → TLS or DTLS app → certificates → target port. Keep the [Crypto API](../api) and [TLS component](../tls) guides open as you implement production features.
