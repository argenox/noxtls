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
- PQC dependencies (`ML_KEM` and `ML_DSA` require PKC)
- Ed448 dependency (`ED448` requires SHA-3 and PKC)
- Profile constraints (for example crypto-only profile disables TLS/certs)

## PQC-related checks

`noxtls_check_config.h` enforces:

- `NOXTLS_FEATURE_ML_KEM` must be `0` or `1`
- `NOXTLS_FEATURE_ML_DSA` must be `0` or `1`
- `NOXTLS_FEATURE_ML_KEM` requires `NOXTLS_FEATURE_PKC`
- `NOXTLS_FEATURE_ML_DSA` requires `NOXTLS_FEATURE_PKC`

In CMake these are controlled by:

- `NOXTLS_CFG_FEATURE_ML_KEM`
- `NOXTLS_CFG_FEATURE_ML_DSA`
- Optional strict vector conformance path: `NOXTLS_CFG_PQC_STRICT_OFFICIAL_VECTORS`

## How To Use

- Set feature flags through CMake options/profile selection.
- Include `noxtls_check_config.h` in builds to fail fast on invalid combinations.
- Resolve any `#error` output by enabling required dependencies or disabling incompatible features.

