---
sidebar_position: 8
title: Release Notes
---

# Release Notes

This page describes changes, fixes, and known issues for **NoxTLS 0.3.2**.

For source and binary artifacts, see [Releases on GitHub](https://github.com/argenox/noxtls/releases).

Use the **version dropdown** in the navbar to view docs (and release notes) for other versions.

---

## 0.3.2

**Release date:** TBD

### Changes

- Patch release on top of 0.3.0. No API, ABI, configuration, or wire-format changes; 0.3.2 is a drop-in replacement for 0.3.0. See the 0.3.0 notes below for the MISRA C:2025 conversion, security fixes, and upgrade notes from 0.2.x.

### Fixed / Resolved

- **TLS 1.3 handshake records that continue a message.** RFC 8446 section 5.1 allows a handshake message to span records, but the record layer read the first byte of every decrypted handshake record as a message type. When a peer split a message such as Certificate or Finished and the continuation record started with 0x18 (KeyUpdate), the handshake was aborted with unexpected_message; with 0x05 (EndOfEarlyData) a client aborted and a server recorded EndOfEarlyData too early, which could end the 0-RTT phase. The failure depended on certificate or Finished bytes, so it appeared as an intermittent handshake failure of about 1 in 128 for each affected split. The KeyUpdate and EndOfEarlyData checks now apply only to records that start a new handshake message. DTLS is not affected. Severity: Medium (handshake availability); not a memory-safety issue.

### Known issues / Open

- The known issues listed for 0.3.0 still apply, except the TLS 1.3 fragmented-handshake issue fixed in this release.