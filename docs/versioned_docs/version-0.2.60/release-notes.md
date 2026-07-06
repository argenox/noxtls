---
sidebar_position: 8
title: Release Notes
---

# Release Notes

This page describes changes, fixes, and known issues for **NoxTLS 0.2.60**.

For source and binary artifacts, see [Releases on GitHub](https://github.com/argenox/noxtls/releases).

Use the **version dropdown** in the navbar to view docs (and release notes) for other versions.

---

## 0.2.60

**Release date:** 7/5/2026

### Changes

- Project version updated to 0.2.60 in CMake and noxtls_version.h.
- TLS 1.3 key schedule: Derive-Secret with empty messages now uses Hash("") per RFC 8446, restoring OpenSSL and other RFC-compliant peer interop.
- TLS vulnerability hardening across record parsing, handshake validation, and configurable feature guards.
- Malformed TLS 1.3 CertificateVerify messages are rejected.

### Fixed / Resolved

- TLS 1.3 server handshakes failed at encrypted Finished with OpenSSL/curl clients due to incorrect HKDF context for the "derived" label.
- TLS 1.2 CBC record tests updated for Encrypt-then-MAC enforcement.

### Known issues / Open

- DTLS 1.3 interop hardening continues against external test suites.
