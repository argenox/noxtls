---
sidebar_position: 8
title: Release Notes
---

# Release Notes

This page describes changes, fixes, and known issues for **NoxTLS 0.3.3**.

For source and binary artifacts, see [Releases on GitHub](https://github.com/argenox/noxtls/releases).

Use the **version dropdown** in the navbar to view docs (and release notes) for other versions.

---

## 0.3.3

**Release date:** 10/6/2026

### Changes

- Patch release on top of 0.3.2. CC13xx hardware-acceleration changes only; no API signature, ABI, or wire-format changes. Builds that do not enable a CC13xx accelerator port are unaffected.
- **Per-engine CC13xx accelerator switches.** `NOXTLS_CFG_FEATURE_CC13XX_AES_ACCEL` and `NOXTLS_CFG_FEATURE_CC13XX_P256_ACCEL` select the AES and P-256 callback ports separately. `NOXTLS_CFG_FEATURE_CC13XX_HW_ACCEL` remains an umbrella that enables both, so existing configurations behave as before. See [CC13xx hardware accelerator](./cc13xx-accelerator.md).
- **New `noxtls_cc13xx_aes_blocks()`.** Runs a batch of AES blocks while holding the AES engine, used by the CTR DRBG.
- **Behavior change for direct binding callers.** A request that finds its engine busy now returns `NOXTLS_RETURN_NOT_SUPPORTED` (fall back to software) instead of `NOXTLS_RETURN_NOT_INITIALIZED`. Callers that use the AES and ECC APIs are unaffected. See [Upgrading from 0.3.2](./cc13xx-accelerator.md#upgrading-from-032).

### Fixed / Resolved

- **CC13xx AES failed during a P-256 multiply.** The AES engine and the PKA shared one busy flag, and the busy check ran before the missing-callback fallback, so an AES block requested while a yielding P-256 multiply was in progress failed with `NOXTLS_RETURN_NOT_INITIALIZED` instead of falling back to software, even when no AES callback was bound. Each engine now has its own guard, and a busy or unbound engine falls back to software. Severity: Medium (availability); not a memory-safety issue.
- **CC13xx busy flag race.** The guard was a plain flag checked and then set, so two tasks or a task and an interrupt could both enter the binding. The per-engine guards now use atomic test-and-set.
- **CTR DRBG batch interrupted between blocks.** Another task could take the AES engine between blocks of a DRBG batch and fail it partway. The batch now holds the engine for its duration.

### Known issues / Open

- The known issues listed for 0.3.0 still apply.