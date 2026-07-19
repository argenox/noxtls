---
sidebar_position: 8
title: Release Notes
---

# Release Notes

This page describes changes, fixes, and known issues for **NoxTLS 0.2.61**.

For source and binary artifacts, see [Releases on GitHub](https://github.com/argenox/noxtls/releases).

Use the **version dropdown** in the navbar to view docs (and release notes) for other versions.

---

## 0.2.61

**Release date:** 7/18/2026

### Changes

- Project version updated to 0.2.61 in CMake and noxtls_version.h.
- CMake install/export support for the full SDK (static libraries, headers, CLIs, NoxTLSConfig.cmake, pkg-config).
- Homebrew tap packaging via argenox/homebrew-noxtls; release archives built with cmake --install.
- Short generic CLI names install as noxtls-* to avoid PATH collisions.

### Fixed / Resolved

- (None recorded.)

### Known issues / Open

- DTLS 1.3 interop hardening continues against external test suites.
