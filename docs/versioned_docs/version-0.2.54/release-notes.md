---
sidebar_position: 8
title: Release Notes
---

# Release Notes

This page describes changes, fixes, and known issues for **NoxTLS 0.2.54**.

For source and binary artifacts, see [Releases on GitHub](https://github.com/argenox/noxtls/releases).

Use the **version dropdown** in the navbar to view docs (and release notes) for other versions.

---

## 0.2.54

**Release date:** 5/25/2026

### Changes

- Project version updated to 0.2.54 in CMake and noxtls_version.h.
- ESP-IDF port supports both IDF 5.x and 6.x (newlib vs esp_libc, HAL include paths, mbedTLS header locations).
- GitHub CI builds https_server example for seven WiFi-capable ESP targets (S2, S3, C2, C3, C6, C5, C61) with espressif/idf:v6.0.1.
- ESP-IDF example build script renamed to build_esp_idf_examples.sh.
- ESP-IDF component manifest (idf_component.yml) extended for C2, C5, and C61 targets.

### Fixed / Resolved

- In-tree ESP-IDF example detection: corrected port path resolution in noxtls_example_project.cmake.
- ESP32-C6 (RISC-V): -Wstringop-overflow in noxtls_bn_mod_inv via safer noxtls_bn_copy.
- IDF 6: TLS wire-length check guarded when max record length is 65535; AES GCM port and ALPN qualifier fixes.

### Known issues / Open

- DTLS 1.3 interop hardening continues against external test suites.