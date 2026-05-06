---
sidebar_position: 3
title: "Build Configuration Checks"
---

# Build Configuration Checks

Compile-time feature validation from `noxtls_check_config.h`.

## Purpose

`noxtls_check_config.h` enforces consistency between feature flags set by build profiles (for example `NOXTLS_FEATURE_TLS`, `NOXTLS_FEATURE_PKC`, `NOXTLS_FEATURE_AES_GCM`) and stops invalid combinations at compile time using `#error`.

## What It Validates

- Feature toggles are boolean (`0` or `1`)
- Core dependencies (for example TLS requires certs, PKC, encryption, hash, DRBG)
- Algorithm dependencies (for example AES mode/key-size flags require AES core)
- PKC dependencies (`ECDSA` and `ECDH` require `ECC`; `X25519`/`X448`/`ED25519` require PKC)
- Profile constraints (for example crypto-only profile disables TLS/certs)

## How To Use

- Set feature flags through CMake options/profile selection.
- Include `noxtls_check_config.h` in builds to fail fast on invalid combinations.
- Resolve any `#error` output by enabling required dependencies or disabling incompatible features.

