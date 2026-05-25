---
sidebar_position: 8
title: Release Notes
---

# Release Notes

This page describes changes, fixes, and known issues for **NoxTLS 0.2.53**.

For source and binary artifacts, see [Releases on GitHub](https://github.com/argenox/noxtls/releases).

Use the **version dropdown** in the navbar to view docs (and release notes) for other versions.

---

## 0.2.53

**Release date:** TBD

### Changes

- Project version updated to 0.2.53 in CMake and noxtls_version.h.

### Fixed / Resolved

- ESP-IDF standalone examples: snapshot main/noxtls_config.h into the component generated config directory (ESP-IDF 5.x cross-component include rules).

### Known issues / Open

- DTLS 1.3 interop hardening continues against external test suites.