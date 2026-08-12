---
sidebar_position: 8
title: Release Notes
---

# Release Notes

This page describes changes, security impact, operational impact, and known limitations for **NoxTLS 0.2.70**.

For source and binary artifacts, see [Releases on GitHub](https://github.com/argenox/noxtls/releases).

Use the **version dropdown** in the navbar to view docs (and release notes) for other versions.

---

## 0.2.70

**Release date:** 2026-08-12  
**Release type:** Feature + hardening release (security-sensitive TLS/DTLS behavior changes)

## Executive Summary

NoxTLS 0.2.70 focuses on TLS/DTLS robustness and security posture improvements while adding targeted functionality for OEM/security integrations:

- Multiple TLS 1.2 / TLS 1.3 parser and state-machine hardening updates.
- Better interop with strict peers and fuzz-style negative cases (BoGo, tlsfuzzer, OpenSSL/curl compatibility paths).
- New TLS 1.3 exporter API for EAP-TLS style keying material derivation.
- New streaming AES-CMAC API.
- New NOXV AES acceleration backend.
- SDK packaging/install improvements (CMake package export, pkg-config, Homebrew packaging flow).

## Security Impact

### What Improved

- **Handshake validation hardening:** tighter checks in TLS 1.2 and TLS 1.3 certificate/record/handshake flows reduce malformed-message acceptance risk.
- **Record-layer boundary hardening:** stricter ciphertext/fragment sizing and alert behavior lower parser ambiguity and reduce downgrade/interoperability edge-case exposure.
- **State-machine hardening:** improved version negotiation, alert handling, and session/cipher binding behavior reduce protocol state confusion risk.
- **CertificateVerify robustness:** malformed or inconsistent `CertificateVerify` processing paths were hardened.

### Default-Risk Posture Change

- Overall default posture is **more strict** for malformed or ambiguous traffic.
- Deployments that relied on non-compliant peer behavior may observe earlier handshake failure (by design).

### Breaking-Behavior Notes (Security-Driven)

- Some previously tolerated malformed handshakes/records now fail fast with explicit alerts.
- TLS 1.2 CBC and legacy edge flows are more strictly validated.

## Protocol and Crypto Changes

### TLS / DTLS Hardening and Interop

- Hardened TLS handshake selection and alert behavior for tlsfuzzer/BoGo interop paths.
- Hardened TLS 1.2 ECDHE verify handling and certificate verify edge conditions.
- Raised TLS 1.2 ciphertext ceiling handling with explicit `record_overflow` behavior.
- Hardened fragmentation, resume cipher binding, and related handshake integrity checks.
- Improved handling of legacy ClientHello version behaviors and `close_notify` response patterns.
- Additional TLS vulnerability hardening landed from `fix/tls_0_2_54` payload.

### TLS 1.3 Exporter

- Added `noxtls_tls13_export_keying_material(...)` (RFC 8446 section 7.5 exporter model).
- Enables controlled derivation of keying material for upper-layer integrations (for example EAP-TLS ecosystems).

### AES-CMAC API

- Added streaming AES-CMAC init/update/final API for incremental MAC computation use-cases.

### Hardware Acceleration

- Added NOXV AES acceleration backend and integration wiring.

## Build, Packaging, and Distribution

- Added install/export support for SDK-style consumption:
  - CMake package config (`NoxTLSConfig.cmake` flow)
  - install rules for headers/libs/tools
  - pkg-config metadata (`noxtls.pc`)
- Added/updated Homebrew release automation and formula bump workflow hardening.
- Updated docs and metadata around packaged SDK consumption and versioned docs publication.

## Operational Impact for Integrators

### Recommended Validation After Upgrade

- Re-run TLS interop matrix against your target clients/servers (especially strict TLS 1.2/TLS 1.3 peers).
- Re-test certificate validation and CertificateVerify edge paths if you have custom cert handling.
- Re-test any OEM wrapper code that touches:
  - TLS record parsing assumptions
  - downgrade/version fallback behavior
  - alert routing/telemetry logic
- For EAP-TLS or key-export consumers, validate exporter label/context conventions and key length assumptions.

### Performance/Footprint Expectations

- Hardware AES performance can improve on NOXV-enabled targets.
- Validation hardening may slightly increase negative-path processing checks.
- Packaging changes do not alter runtime semantics, but they do change install/integration mechanics.

## Known Limitations / Open Items

- DTLS 1.3 interop hardening remains an active area (ongoing external-suite alignment work).
- If your deployment depends on permissive handling of malformed peer messages, update peer conformance or adapt policy.

## Upgrade and Migration Notes

- Treat this as a security-sensitive upgrade: stage in pre-prod first.
- If pinning API surface, include new TLS 1.3 exporter and CMAC streaming symbols in compatibility checks.
- If consuming via package managers/build-system exports, verify install paths and package-discovery logic in CI.

## Complete Change Inventory (since v0.2.60)

Non-merge commits included in the 0.2.70 RC line:

1. `76eca80` - fix: harden TLS vulnerability paths
2. `208b56e` - feat(noxv): add AES accelerator backend
3. `ff2dfcc` - docs(release): publish docusaurus docs version 0.2.70
4. `cef2a44` - feat(cmac): add streaming init/update/final API
5. `3b09eff` - fix: Green BoGo handshake paths for client auth and version negotiation
6. `c3bda78` - fix: Harden TLS 1.2 ECDHE verify and BoGo interop paths
7. `2e76fff` - fix: Raise TLS 1.2 ciphertext ceiling and emit record_overflow alerts
8. `4122afd` - fix: Harden fragmentation, resume cipher binding, and ECDSA DER for tlsfuzzer
9. `49e58b8` - fix: Harden TLS handshake selection and alerts for tlsfuzzer interop
10. `4c44b41` - Add TLS 1.3 exporter for EAP-TLS key material
11. `c493d68` - ci: harden homebrew formula bump string rewrites
12. `67e6ae1` - Add CMake install/export and Homebrew tap packaging for 0.2.61
13. `2243033` - fix: Harden TLS handshake alerts and interop HTTP buffering for tlsfuzzer
14. `05dfb6c` - fix: Honor legacy ClientHello versions and reply to close_notify
15. `984e59d` - Fix https_server multi-connection interop and harden TLS 1.2 CertificateVerify
16. `9458dd0` - fix: Fixes several downgrade failures found
17. `807d19e` - feat: adds Interop mode to allow for testing

## Integrity and Disclosure Notes

- This release includes security hardening but does not currently publish CVE IDs in this note set.
- For coordinated vulnerability reporting, use the security reporting process documented in the project docs.
