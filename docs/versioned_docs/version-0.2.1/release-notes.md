---
sidebar_position: 8
title: Release Notes
---

# Release Notes

This page describes changes, fixes, and known issues for **NoxTLS 0.2.1**.

For source and binary artifacts, see [Releases on GitHub](https://github.com/argenox/noxtls/releases).

Use the **version dropdown** in the navbar to view docs (and release notes) for other versions.

---

## 0.2.1

**Release date:** TBD

### Changes

- TLS component guide rewritten with feature matrices for TLS 1.2, TLS 1.3, DTLS 1.2, and DTLS 1.3 (RFC 9147).
- New DTLS 1.3 RFC 9147 conformance page: unified header, CID, ACK/retransmit, dtls13 key schedule, and regression matrix.
- Introduction and release notes updated for default TLS/DTLS build profile, tlsfuzzer interop, and OCSP stapling (TLS 1.2).

### Fixed / Resolved

- (None recorded.)

### Known issues / Open

- DTLS 1.3 interop hardening still in progress for CID rotation and lossy retransmit scenarios.
- Several TLS extensions remain constants-only (SCT, certificate compression, delegated credentials).