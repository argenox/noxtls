---
sidebar_position: 3
title: Host Computer
description: Build and run NoxTLS sample applications on Linux, macOS, or Windows.
keywords:
  - host
  - desktop
  - cmake
  - demo
  - linux
  - windows
---

# Host Computer Demo

The fastest way to explore NoxTLS is on a **host computer** (Linux, macOS, or Windows) using CMake and the bundled reference applications. No board or RTOS is required.

## Prerequisites

- CMake 3.10 or newer
- C99 compiler (GCC, Clang, or MSVC)
- Network access (only for `https_client` and similar samples)

See [Getting Started](../getting-started) and [BUILDING.md](https://github.com/argenox/noxtls/blob/main/noxtls/BUILDING.md) for platform-specific toolchain notes.

## Build the library and apps

From the `noxtls` directory (top-level `CMakeLists.txt`):

```bash
cmake -S . -B build -D BUILD_TESTS=OFF
cmake --build build --config Release
```

Binaries are written under `binary/` at the repository root (or `binary-arm64/` / `binary-x86_64/` on macOS when targeting one architecture). `BUILD_APPLICATIONS` is **ON** by default.

On macOS, build both Apple Silicon and Intel application binaries:

```bash
cmake -S . -B build -D BUILD_TESTS=OFF -D NOXTLS_BUILD_MACOS_APPLICATION_SLICES=ON
cmake --build build --target noxtls_macos_application_slices
```

## Recommended smoke tests

### DTLS PSK (no network)

In-process handshake exercise for DTLS 1.2 and 1.3:

```bash
./binary/dtls_psk_demo
./binary/dtls_psk_demo 1.3
```

Details: [DTLS PSK demo](../applications/app_dtls_psk_demo).

### HTTPS client (network)

```bash
./binary/https_client https://example.com/ 443 tls13
```

Optional TLS version: `tls12`, `tls13`, or `auto`. See [HTTPS client](../applications/app_https_client).

### HTTPS server (local)

Generate a self-signed cert, then:

```bash
./binary/https_server 8443 --cert server.crt --key server.key
./binary/https_client https://127.0.0.1:8443 tls13
```

See [Build Your First HTTPS Server](../start-here/https-server).

### Certificate utilities

```bash
./binary/cert info -i path/to/cert.pem
./binary/cert verify -i chain.pem
```

## Optional: unit tests on host

Enable tests when validating a port or configuration change:

```bash
cmake -S . -B build -D BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build
```

The separate **UTNox** harness in the repository root (`utnox/`) can drive on-target tests over UART/SPI; host builds use the same NoxTLS sources.

## Host-only acceleration

On x86/x64 and Apple Silicon you can enable hardware AES paths for throughput experiments:

| Host | CMake option |
|------|----------------|
| x86/x64 with AES-NI | `NOXTLS_CFG_FEATURE_AES_ACCEL_NI=ON` |
| Apple arm64 | `NOXTLS_CFG_FEATURE_AES_ACCEL_APPLE=ON` |

See [Configuration Guide](../configuration-guide).

## What to do next

| Goal | Guide |
|------|--------|
| Guided tutorials | [Start Here](../start-here/what-is-noxtls) |
| TLS integration | [TLS component](../tls) |
| Embedded UDP | [ESP32](./esp32) or [STM32](./stm32/stm32f413zh) |
