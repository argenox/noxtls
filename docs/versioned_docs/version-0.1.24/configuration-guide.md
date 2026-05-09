---
sidebar_position: 6
title: "Configuration Guide"
---

# Configuration Guide

This guide describes how to configure NoxTLS for your build and target: feature selection, macros, and optional components.

## Overview

NoxTLS can be tailored to reduce code size and dependencies by enabling only the algorithms and features you need. Configuration is typically done via:

- **CMake options** when using the provided CMake build
- **Preprocessor macros** when integrating with a custom build

## CMake options

When building with CMake, you can turn features on or off. Common options (names may vary; check the top-level `CMakeLists.txt` for the exact list):

| Option | Description | Default |
|--------|-------------|---------|
| Build type | `Release`, `Debug`, `MinSizeRel` | Depends on generator |
| Tests | Enable unit tests / test apps | Off or On |
| Examples / applications | Build sample applications | Off or On |
| Profile | `NOXTLS_PROFILE` (`default`, `minimal_tls_client`, `tls_server_pki`, `crypto_only`, `fips_like_profile`) | `default` |
| Side-channel profile | `NOXTLS_SIDECHANNEL_PROFILE` (`performance`, `balanced`, `constant_time_strict`) | `balanced` |

Run from the build directory:

```bash
cmake -B build -DOPTION_NAME=ON
cmake --build build
```

Or use `ccmake build` / `cmake -L` to list cached variables.

Example:

```bash
cmake -S noxtls -B noxtls/build -DNOXTLS_PROFILE=crypto_only -DBUILD_APPLICATIONS=OFF
cmake --build noxtls/build
```

Strict timing-hardening example:

```bash
cmake -S noxtls -B noxtls/build -DNOXTLS_SIDECHANNEL_PROFILE=constant_time_strict -DBUILD_APPLICATIONS=OFF
cmake --build noxtls/build
```

## Preprocessor macros

For custom builds or fine-grained control, the codebase may use macros such as:

- **Feature toggles**: Enable/disable TLS, DTLS, specific ciphers (e.g. AES-GCM, ChaCha20), or public-key crypto.
- **Sizes and limits**: Max certificate size, TLS record size, or buffer limits.
- **Platform**: Custom allocator, logging, or debug output (e.g. `NOXTLS_DEBUG`, `NOXTLS_AES_DEBUG`).

Check the source and any `noxtls_config.h` or similar header in the repository for the exact macro names and recommended values.

## Optional components

- **Encryption**: AES, ARIA, Camellia, ChaCha20 — include only the source files for the algorithms you use.
- **Message digests**: SHA-1, SHA-256, SHA-512, SHA-3, MD5, etc. — same approach; link only what you need.
- **Public key crypto**: RSA, ECC, ECDSA, ECDH — optional; omit if you only need symmetric crypto and hashes.
- **TLS / DTLS**: Omit TLS-related sources and dependencies if you use NoxTLS only for crypto primitives.
- **X.509 / certificates**: Optional; required only if you verify or parse certificates.

Reducing enabled features and algorithms reduces footprint and attack surface.

## Configuration header (optional)

Some projects use a single configuration header (e.g. `noxtls_config.h`) that the build system generates or that you maintain. In that header you can:

- Define or undef feature macros.
- Set default buffer sizes or limits.
- Redirect allocation or logging to your platform.

Include this header first (e.g. via a global `-include` or as the first include in a common internal header) so all compilation units see the same configuration.

The library now uses:

- `noxtls_config.h` for feature/profile selection
- `noxtls_check_config.h` for dependency validation (`#error` on invalid combinations)

### Built-in profiles

- `minimal_tls_client`: TLS client-focused footprint (no legacy hashes, no RSA cert generation)
- `tls_server_pki`: full TLS server PKI baseline
- `crypto_only`: crypto primitives only (TLS/X.509 disabled)
- `fips_like_profile`: conservative modern set (legacy primitives disabled)

### Side-channel profiles

- `performance`: preserves legacy comparison behavior (fastest, least hardened)
- `balanced`: constant-time secret comparison baseline for protocol verification paths
- `constant_time_strict`: balanced plus strict hardening guards for higher-assurance builds

## Next steps

- See the **Porting Guide** for bringing NoxTLS to a new platform.
- See **Getting Started** for a minimal build and **Crypto API** for the public API.
