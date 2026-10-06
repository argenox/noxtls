---
sidebar_position: 2
title: 5 Minute Quickstart
description: Build NoxTLS and run sample TLS/HTTPS applications in a few minutes.
keywords:
  - quickstart
  - cmake
  - build
  - tutorial
---

# 5 Minute Quickstart

This guide gets the NoxTLS library and sample applications built on a desktop host. It assumes CMake and a C compiler are already installed.

## 1. Clone and configure

From the `noxtls` repository root (the directory that contains the top-level `CMakeLists.txt`):

```bash
cmake -S . -B build -D BUILD_TESTS=OFF
```

`BUILD_APPLICATIONS` is **ON** by default, so sample programs are included in the build.

## 2. Build

```bash
cmake --build build --config Release
```

On Linux/macOS you can add `-j` for parallel compilation. Application binaries are written under `binary/` at the repository root.

## 3. Run a smoke test

**DTLS PSK demo** (in-process, no network setup):

```bash
./binary/dtls_psk_demo
./binary/dtls_psk_demo 1.3
```

**HTTPS client** (requires network access to the target host):

```bash
./binary/https_client https://example.com/ 443 tls13
```

**Certificate utility** (uses built-in or local test material):

```bash
./binary/cert info -i path/to/cert.pem
```

## 4. Optional: enable post-quantum features

Rebuild with ML-KEM and ML-DSA if you need PQC APIs or TLS 1.3 PQ groups:

```bash
cmake -S . -B build -D BUILD_TESTS=OFF \
  -D NOXTLS_CFG_FEATURE_ML_KEM=ON \
  -D NOXTLS_CFG_FEATURE_ML_DSA=ON
cmake --build build --config Release
```

See [Configuration Guide](../configuration-guide) for profiles and other feature gates.

## Troubleshooting

| Issue | What to try |
|-------|-------------|
| CMake too old | Require CMake 3.10+ (`cmake --version`) |
| MSVC link errors on apps | Build from **x64 Native Tools** prompt; see [BUILDING.md](https://github.com/argenox/noxtls/blob/main/noxtls/BUILDING.md) |
| `https_client` certificate errors | Use a public HTTPS site with a well-known CA, or supply your own trust store in your integration |
| Missing `binary/` output | Confirm `BUILD_APPLICATIONS=ON` and check the build log for app target names |

## Where to go next

| Goal | Guide |
|------|--------|
| TLS client integration | [Build Your First TLS Client](./tls-client) |
| HTTPS server | [Build Your First HTTPS Server](./https-server) |
| DTLS on UDP / embedded | [Run DTLS on Embedded Devices](./dtls-embedded) |
| Certs and PKI | [Configure Certificates](./configure-certificates) |
| Zephyr or custom OS | [Port NoxTLS to Your Platform](./port-to-platform) |

For full build matrices (Linux packages, MSVC, library-only builds), see [BUILDING.md](https://github.com/argenox/noxtls/blob/main/noxtls/BUILDING.md) and [Getting Started](../getting-started).
