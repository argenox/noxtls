---
sidebar_position: 8
title: Release Notes
---

# Release Notes

This page describes changes, fixes, and known issues for **NoxTLS 0.3.4**.

For source and binary artifacts, see [Releases on GitHub](https://github.com/argenox/noxtls/releases).

Use the **version dropdown** in the navbar to view docs (and release notes) for other versions.

---

## 0.3.4

**Release date:** TBD

### Changes

- Patch release on top of 0.3.3. Build fix only; no API, ABI, configuration, or wire-format changes, and no change to generated code. 0.3.4 is a drop-in replacement for 0.3.3.

### Fixed / Resolved

- **Cortex-M7 and STM32 accelerated builds failed with `'NULL' undeclared`.** `noxtls_sha256_cortexm7.c`, `noxtls_stm32_hash_core.c` and `noxtls_aes_accel_stm32_port.c` used `NULL` and `size_t` without including `<stddef.h>`. They used to get the definitions indirectly through `<stdio.h>` in other NoxTLS headers, which the 0.3.0 MISRA cleanup removed, so every build that compiles the Cortex-M7 SHA-256 core or the STM32 hash/AES ports failed (for example STM32F767 and STM32H7 targets). Each file now includes `<stddef.h>` itself.

### Known issues / Open

- The known issues listed for 0.3.0 still apply.