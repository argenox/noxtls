---
sidebar_position: 8
title: Release Notes
---

# Release Notes

This page describes changes, fixes, and known issues for **NoxTLS 0.2.55**.

For source and binary artifacts, see [Releases on GitHub](https://github.com/argenox/noxtls/releases).

Use the **version dropdown** in the navbar to view docs (and release notes) for other versions.

---

## 0.2.55

**Release date:** 6/15/2026

### Changes

- Project version updated to 0.2.55 in CMake and noxtls_version.h.
- Static buffer pool bucket allocator: LEGACY, BUCKETS, and HYBRID modes (default HYBRID) with configurable size classes via NOXTLS_MEM_BUCKET_*.
- noxtls_mem_get_bucket_stats() reports per-bucket block utilization and fallback pool usage.
- ECC curve enum values renamed with NOXTLS_ECC_* prefix (e.g. NOXTLS_ECC_SECP256R1).
- nRF52 AES hardware acceleration with hw-only fallback mode; STM32 and Cortex-M7 crypto path optimizations.
- Embedded firmware size benchmark tooling (toolchains and scripts).
- HMAC/HKDF split from the TLS stack; Ed25519 decoupled from bignum.

### Fixed / Resolved

- crypto_only profile keeps PKC enabled.
- LMS/HSS and XMSS certificate verification paths.
- AES-CMAC calculation and AES internal header extern "C" linkage for C++ consumers.
- DTLS embedded PSK-only handshakes and related DTLS fixes.
- Security hardening across crypto and parser paths.

### Known issues / Open

- DTLS 1.3 interop hardening continues against external test suites.