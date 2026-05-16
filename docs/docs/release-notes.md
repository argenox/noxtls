---
sidebar_position: 8
title: Release Notes
description: "NoxTLS documentation: Release Notes."
---

# Release Notes

This page describes changes, fixes, and known issues for **NoxTLS 0.2.4**.

For source and binary artifacts, see [Releases on GitHub](https://github.com/argenox/noxtls/releases).

Use the **version dropdown** in the navbar to view docs (and release notes) for other versions.

---

## 0.2.4

**Release date:** TBD

### Changes

- Project version updated to 0.2.4 in CMake and `noxtls_version.h`.
- `noxtls` CLI expanded with digest, encryption/decryption, PKC/key, and X.509 certificate operations.
- SHA and digest utilities now expose enabled algorithms with compact help output, including SHA-3, SHA-512/224, SHA-512/256, RIPEMD-160, BLAKE2, and feature-gated MD4.
- Certificate conversion now supports explicit input and output formats with `-I der|pem` and `-O der|pem`.

### Fixed / Resolved

- RIPEMD-160 output corrected to match known vectors.
- SHA-512/224 and SHA-512/256 initialization/output handling completed.

### Known issues / Open

- DTLS 1.3 interop hardening continues against external test suites.
