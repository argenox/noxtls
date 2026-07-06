---
sidebar_position: 6
title: Configuration Guide
description: "NoxTLS documentation: Configuration Guide."
---

# Configuration Guide

This guide describes how to configure NoxTLS for your build and target, including profile selection, feature gates, and post-quantum options.

## Overview

NoxTLS can be tailored to reduce code size and dependencies by enabling only required algorithms and protocol features. Configuration is typically done via:

- **CMake options** when using the provided CMake build
- **Preprocessor macros** when integrating with a custom build

## CMake options

When building with CMake, common knobs include:

| Option | Description | Default |
|--------|-------------|---------|
| `BUILD_APPLICATIONS` | Build sample/demo applications | `ON` |
| `NOXTLS_BUILD_MACOS_APPLICATION_SLICES` | macOS only: build apps for `arm64` and `x86_64` via target `noxtls_macos_application_slices` | `OFF` |
| `NOXTLS_APPLICATIONS_BINARY_DIR` | Output directory for application executables (defaults to `binary/` or `binary-<arch>/` on macOS) | `binary/` |
| `BUILD_TESTS` | Build unit/integration tests | `OFF` |
| `NOXTLS_PROFILE` | Preset feature profile (`default`, `minimal_tls_client`, `tls_server_pki`, `crypto_only`, `fips_like_profile`) | `default` |
| `NOXTLS_SIDECHANNEL_PROFILE` | Side-channel hardening profile (`performance`, `balanced`, `constant_time_strict`) | `balanced` |
| `NOXTLS_CFG_TLS12_ENABLE_LEGACY_CIPHER_SUITES` | Enable legacy TLS 1.2 CBC/RSA key-exchange suites | `OFF` |
| `NOXTLS_CFG_FEATURE_ML_KEM` | Enable ML-KEM API and TLS PQ KEM paths | `OFF` |
| `NOXTLS_CFG_FEATURE_ML_DSA` | Enable ML-DSA API and TLS/X.509 PQ signatures | `OFF` |
| `NOXTLS_CFG_FEATURE_AES_ACCEL_NI` | Enable AES-NI block backend on x86/x64 targets | `OFF` |
| `NOXTLS_CFG_FEATURE_AES_ACCEL_APPLE` | Enable ARMv8 AES block backend on Apple Silicon targets | `OFF` |

Run from the build directory:

```bash
cmake -B build -DOPTION_NAME=ON
cmake --build build
```

Or use `ccmake build` / `cmake -L` to inspect cached variables.

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

AES hardware acceleration examples (build-targeted selection):

```bash
# x86/x64 build with AES-NI backend
cmake -S noxtls -B noxtls/build-aesni \
  -DNOXTLS_CFG_FEATURE_AES_ACCEL_NI=ON \
  -DNOXTLS_CFG_FEATURE_AES_ACCEL_APPLE=OFF
cmake --build noxtls/build-aesni

# Apple Silicon build with ARMv8 AES backend
cmake -S noxtls -B noxtls/build-apple-aes \
  -DNOXTLS_CFG_FEATURE_AES_ACCEL_NI=OFF \
  -DNOXTLS_CFG_FEATURE_AES_ACCEL_APPLE=ON
cmake --build noxtls/build-apple-aes
```

macOS application binaries for both Apple Silicon and Intel:

```bash
cmake -S noxtls -B noxtls/build -DNOXTLS_BUILD_MACOS_APPLICATION_SLICES=ON
cmake --build noxtls/build --target noxtls_macos_application_slices
# binary-arm64/ and binary-x86_64/
```

## Feature-gate model

`noxtls` uses CMake-side config flags (for example `NOXTLS_CFG_FEATURE_*`) that map to compile-time feature macros (`NOXTLS_FEATURE_*`).

Examples:

- `NOXTLS_CFG_FEATURE_TLS` -> `NOXTLS_FEATURE_TLS`
- `NOXTLS_CFG_FEATURE_CERT` -> `NOXTLS_FEATURE_CERT`
- `NOXTLS_CFG_FEATURE_PKC` -> `NOXTLS_FEATURE_PKC`
- `NOXTLS_CFG_FEATURE_ML_KEM` -> `NOXTLS_FEATURE_ML_KEM`
- `NOXTLS_CFG_FEATURE_ML_DSA` -> `NOXTLS_FEATURE_ML_DSA`
- `NOXTLS_CFG_FEATURE_AES_ACCEL_NI` -> `NOXTLS_FEATURE_AES_ACCEL_NI`
- `NOXTLS_CFG_FEATURE_AES_ACCEL_APPLE` -> `NOXTLS_FEATURE_AES_ACCEL_APPLE`

Use [Build Configuration Checks](/docs/api/build_config) for dependency rules enforced by `noxtls_check_config.h`.

## Optional components

- **Encryption**: AES, ARIA, Camellia, ChaCha20 — include only the source files for the algorithms you use.
- **Message digests**: SHA-1, SHA-256, SHA-512, SHA-3, MD5, etc. — same approach; link only what you need.
- **Public key crypto**: RSA, ECC, ECDSA, ECDH, X25519/X448, EdDSA, ML-KEM, ML-DSA.
- **TLS / DTLS**: Omit TLS-related sources and dependencies if you use NoxTLS only for crypto primitives.
- **X.509 / certificates**: Optional; required only if you verify or parse certificates.

Reducing enabled features and algorithms reduces footprint and attack surface.

## TLS 1.2 secure defaults and legacy compatibility

NoxTLS ships with a secure-by-default TLS 1.2 cipher-suite policy:

- Legacy CBC-mode and RSA key-exchange TLS 1.2 suites are disabled by default.
- Default TLS 1.2 negotiation prefers modern AEAD suites.

If you must interoperate with older endpoints, explicitly opt in to legacy suites:

```bash
cmake -S noxtls -B noxtls/build-legacy \
  -DNOXTLS_CFG_TLS12_ENABLE_LEGACY_CIPHER_SUITES=ON
cmake --build noxtls/build-legacy
```

For custom/non-CMake builds, set `NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES=1` in `noxtls_config.h` (or via compiler define).

Use this only when compatibility requirements justify the additional risk surface.

## Configuration header (optional)

Some projects use a single configuration header (e.g. `noxtls_config.h`) that the build system generates or that you maintain. In that header you can:

- Define or undef feature macros.
- Set default buffer sizes or limits.
- Redirect allocation or logging to your platform.

Include this header first (e.g. via a global `-include` or as the first include in a common internal header) so all compilation units see the same configuration.

The library uses:

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

#### Side-channel profile details

| Profile | Intended use | Security posture | Performance impact |
| --- | --- | --- | --- |
| `performance` | Lab/dev benchmarks, compatibility/perf investigations | Lowest hardening; timing behavior may leak more information | Lowest overhead |
| `balanced` | General production default | Constant-time secret comparisons in core verification/tag-check paths | Moderate overhead |
| `constant_time_strict` | High-assurance or hostile/shared compute environments | Strongest hardening profile; strict constant-time expectations | Highest overhead |

Configuration examples:

```bash
# Fastest profile (not recommended for exposed production deployments)
cmake -S noxtls -B noxtls/build-perf \
  -DNOXTLS_SIDECHANNEL_PROFILE=performance

# Recommended baseline for most deployments
cmake -S noxtls -B noxtls/build-balanced \
  -DNOXTLS_SIDECHANNEL_PROFILE=balanced

# Strongest hardening profile
cmake -S noxtls -B noxtls/build-ct-strict \
  -DNOXTLS_SIDECHANNEL_PROFILE=constant_time_strict
```

`noxtls_check_config.h` enforces profile constraints at compile time. For example:

- `NOXTLS_SIDECHANNEL_PROFILE_PERFORMANCE` requires `NOXTLS_CT_COMPARE=0`
- `NOXTLS_SIDECHANNEL_PROFILE_CONSTANT_TIME_STRICT` requires `NOXTLS_CT_COMPARE=1`

If these constraints are violated, the build fails with `#error` so invalid combinations do not ship.

## Post-quantum configuration

Enable PQC support:

```bash
cmake -S noxtls -B noxtls/build-pqc \
  -DNOXTLS_CFG_FEATURE_ML_KEM=ON \
  -DNOXTLS_CFG_FEATURE_ML_DSA=ON
cmake --build noxtls/build-pqc
```

Optional strict vector-conformance mode:

```bash
cmake -S noxtls -B noxtls/build-pqc-strict \
  -DBUILD_TESTS=ON \
  -DBUILD_APPLICATIONS=OFF \
  -DNOXTLS_CFG_FEATURE_ML_KEM=ON \
  -DNOXTLS_CFG_FEATURE_ML_DSA=ON \
  -DNOXTLS_CFG_PQC_STRICT_OFFICIAL_VECTORS=ON
```

PQC references:

- [ML-KEM API](/docs/api/mlkem)
- [ML-DSA API](/docs/api/mldsa)
- [TLS 1.3 PQC](/docs/api/tls13_pqc)

## Next steps

- See the **Porting Guide** for bringing NoxTLS to a new platform.
- See **Getting Started** for a minimal build and **Crypto API** for the public API.
