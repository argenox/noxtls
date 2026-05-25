---
sidebar_position: 8
title: Release Notes
---

# Release Notes

This page describes changes, fixes, and known issues for **NoxTLS 0.2.52**.

For source and binary artifacts, see [Releases on GitHub](https://github.com/argenox/noxtls/releases).

Use the **version dropdown** in the navbar to view docs (and release notes) for other versions.

---

## 0.2.52

**Release date:** TBD

### Changes

- Project version updated to 0.2.52 in CMake and noxtls_version.h.

### Fixed / Resolved

- ESP-IDF standalone examples: snapshot `main/noxtls_config.h` into the component generated config dir so ESP-IDF 5.x does not require a circular `main` ↔ `argenox__noxtls` component dependency.

### Known issues / Open

- DTLS 1.3 interop hardening continues against external test suites.

---

## 0.2.51

**Release date:** TBD

### Changes

- Project version updated to 0.2.51 in CMake and noxtls_version.h.
- ESP Component Registry package (`argenox/noxtls`) now bundles the full library (`noxtls-lib/`, `utility/`, root CMake) under `lib_root/` inside the component.
- ESP-IDF examples support in-repo development (`ports/esp-idf`) and standalone builds via Component Manager (`^0.2.51`).
- Release workflow ships `noxtls-esp32-applications-<version>.zip` with standalone example projects.

### Fixed / Resolved

- Registry component 0.2.50 was incomplete (wrapper only); standalone examples failed with missing `utility/` directory.
- ESP-IDF component `NOXTLS_PROJECT_ROOT` resolution for `managed_components/argenox__noxtls` installs.

### Known issues / Open

- DTLS 1.3 interop hardening continues against external test suites.

---

## 0.2.50

**Release date:** TBD

### Changes

- Project version updated to 0.2.50 in CMake and noxtls_version.h.
- noxtls CLI expanded with digest, encryption/decryption, PKC/key, and X.509 certificate operations.
- SHA and digest utilities now expose enabled algorithms with compact help output, including SHA-3, SHA-512/224, SHA-512/256, RIPEMD-160, BLAKE2, and feature-gated MD4.
- Certificate conversion now supports explicit input and output formats with -I der|pem and -O der|pem.

### Fixed / Resolved

- RIPEMD-160 output corrected to match known vectors.
- SHA-512/224 and SHA-512/256 initialization/output handling completed.

### Known issues / Open

- DTLS 1.3 interop hardening continues against external test suites.