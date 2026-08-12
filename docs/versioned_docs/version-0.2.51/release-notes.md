---
sidebar_position: 8
title: Release Notes
---

# Release Notes

This page describes changes, fixes, and known issues for **NoxTLS 0.2.51**.

For source and binary artifacts, see [Releases on GitHub](https://github.com/argenox/noxtls/releases).

Use the **version dropdown** in the navbar to view docs (and release notes) for other versions.

---

## 0.2.51

**Release date:** TBD

### Changes

- Project version updated to 0.2.51 in CMake and noxtls_version.h.
- ESP Component Registry package (argenox/noxtls) now bundles the full library under lib_root/ inside the component.
- ESP-IDF examples support in-repo development and standalone builds via Component Manager (^0.2.51).
- Release workflow ships noxtls-esp32-applications zip with standalone example projects.

### Fixed / Resolved

- Registry component 0.2.50 was incomplete (wrapper only); standalone examples failed with missing utility/ directory.
- ESP-IDF component NOXTLS_PROJECT_ROOT resolution for managed_components installs.

### Known issues / Open

- DTLS 1.3 interop hardening continues against external test suites.