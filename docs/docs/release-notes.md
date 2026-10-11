---
sidebar_position: 8
title: Release Notes
---

# Release Notes

This page describes changes, fixes, and known issues for **NoxTLS 0.3.5**.

For source and binary artifacts, see [Releases on GitHub](https://github.com/argenox/noxtls/releases).

Use the **version dropdown** in the navbar to view docs (and release notes) for other versions.

---

## 0.3.5

**Release date:** TBD

### Changes

- Patch release on top of 0.3.4 that adds two opt-in features; builds that do not enable them keep their behavior, configuration defaults and wire format.
- **EC-JPAKE** (`NOXTLS_CFG_FEATURE_ECJPAKE`, default OFF): EC J-PAKE over P-256 (RFC 8236 section 3) with SHA-256 Schnorr NIZK proofs (RFC 8235 section 3) in the TLS form of draft-cragie-tls-ecjpake-01. API in `noxtls-lib/pake/noxtls_ecjpake.h`.
- **DTLS 1.2 EC-JPAKE suite** (`NOXTLS_CFG_FEATURE_DTLS_ECJPAKE`, default OFF): `TLS_ECJPAKE_WITH_AES_128_CCM_8` (0xC0FF) with the `ecjpake_key_kp_pair` extension (256), the EC-JPAKE ServerKeyExchange / ClientKeyExchange and AES-128-CCM-8 records, as used by Thread MeshCoP commissioning. New API: `noxtls_tls12_set_ecjpake_password()`, `noxtls_tls12_ecjpake_negotiated()`, `noxtls_tls12_ecjpake_export_key_block()`. `noxtls_tls12_connect_poll()` / `noxtls_tls12_accept_poll()` also drive DTLS 1.2 for EC-JPAKE contexts.
- Zephyr and ESP-IDF Kconfig expose both switches.

### Known issues / Open

- The known issues listed for 0.3.0 still apply.
- No public known-answer vectors exist for the complete EC-JPAKE TLS exchange; interoperability with other Thread implementations has not yet been tested on hardware.

---

## 0.3.4

**Release date:** TBD

### Changes

- Patch release on top of 0.3.3. Build fix only; no API, ABI, configuration, or wire-format changes, and no change to generated code. 0.3.4 is a drop-in replacement for 0.3.3.

### Fixed / Resolved

- **Cortex-M7 and STM32 accelerated builds failed with `'NULL' undeclared`.** `noxtls_sha256_cortexm7.c`, `noxtls_stm32_hash_core.c` and `noxtls_aes_accel_stm32_port.c` used `NULL` and `size_t` without including `<stddef.h>`. They used to get the definitions indirectly through `<stdio.h>` in other NoxTLS headers, which the 0.3.0 MISRA cleanup removed, so every build that compiles the Cortex-M7 SHA-256 core or the STM32 hash/AES ports failed (for example STM32F767 and STM32H7 targets). Each file now includes `<stddef.h>` itself.

### Known issues / Open

- The known issues listed for 0.3.0 still apply.