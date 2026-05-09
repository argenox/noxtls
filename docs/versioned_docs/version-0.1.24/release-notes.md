---
sidebar_position: 8
title: Release Notes
---

# Release Notes

This page describes changes, fixes, and known issues for **NoxTLS 0.1.24**.

For source and binary artifacts, see [Releases on GitHub](https://github.com/argenox/noxtls/releases).

Use the **version dropdown** in the navbar to view docs (and release notes) for other versions.

---

## 0.1.24

**Release date:** TBD

### Changes

- Memory-safety hardening across TLS, DTLS, allocator, ASN.1, and helper paths: added overflow/underflow guards, parser boundary checks, and safer resize/copy patterns.
- Hex conversion APIs and callsites hardened: checked conversion paths enforced in applications, `noxtls_hex_string_to_bytes` widened to size_t capacity, and legacy unbounded conversion API removed from public surface.
- Documentation and tests updated: versioned docs 0.1.24 snapshot, release-notes generation refresh, and new `string_common_test` coverage for success/error and large-input conversion paths.

### Fixed / Resolved

- (None recorded.)

### Known issues / Open

- (None recorded.)