---
sidebar_position: 8
title: Release Notes
---

# Release Notes

This page describes changes, security impact, operational impact, and known limitations for **NoxTLS 0.2.71**.

For source and binary artifacts, see [Releases on GitHub](https://github.com/argenox/noxtls/releases).

Use the **version dropdown** in the navbar to view docs (and release notes) for other versions.

---

## 0.2.71

**Release date:** 2026-08-27
**Release type:** Feature + hardening release (caller-polled TLS, resumption, and diagnostic API additions)

## Executive Summary

NoxTLS 0.2.71 adds APIs that make TLS integration more controllable in event-driven and embedded applications, while preserving the strict protocol behavior introduced in 0.2.70:

- Caller-polled, nonblocking TLS record I/O and resumable TLS 1.2 handshakes.
- TLS 1.3 session export/import for caller-owned resumption storage.
- Unified TLS controls for CRLs, bounded plaintext record payloads, handshake progression, and connection inspection.
- Detailed, non-secret ECDH/ECDHE failure provenance for field diagnostics.
- Streaming and split-message Ed25519 verification APIs.
- Build fixes for strict compilers, duplicate CMAC implementation removal, and CMake-controlled Ed448 enablement.

## Security Impact

### What Improved

- **Bounded nonblocking output:** encrypted output accepted by the record layer is queued only up to `NOXTLS_TLS_IO_TX_QUEUE_LIMIT` (256 KiB by default). This prevents an indefinitely blocked transport from causing unbounded queued output.
- **Explicit I/O progress states:** callers can distinguish an incomplete read (`NOXTLS_RETURN_WANT_READ`) from pending encrypted output (`NOXTLS_RETURN_WANT_WRITE`) and resume without re-encrypting application data.
- **Mutual-auth policy:** TLS 1.2 servers can require a non-empty client certificate instead of accepting an empty Certificate message after requesting client authentication.
- **Diagnostic safety:** ECDH diagnostics expose only the failing control-flow stage and internal status—not private scalars, points, or shared-secret bytes.
- **CRL and record-size policy:** the unified API can apply a CRL chain consistently and request bounded record payloads using the protocol-appropriate extension.

### Default-Risk Posture Change

- Blocking I/O remains the default. Caller-polled behavior is opt-in through `TLS_IO_MODE_NON_BLOCKING`.
- The default nonblocking transmit-queue limit is finite. Applications that need a different bounded limit must configure it explicitly.
- Existing permissive client-auth behavior remains available when the server requests, but does not require, a client certificate.

### Compatibility Notes

- The new APIs are additive; existing blocking `connect()`, `accept()`, `send()`, and `recv()` integrations keep their established behavior.
- A nonblocking transport callback must return `TLS_IO_WOULD_BLOCK` when it cannot make progress. Applications must treat `NOXTLS_RETURN_WANT_READ` and `NOXTLS_RETURN_WANT_WRITE` as resumable, not terminal, results.
- TLS 1.3 session export objects contain resumption PSK material. Store them as sensitive data, bind them to the intended peer policy, and erase them when no longer needed.

## Protocol and Crypto Changes

### Caller-Polled TLS and Resumption

- Added caller-polled record transport support, including partial-record reassembly, partial-write retention, explicit flushing, and an encrypted-output queue limit.
- Added `noxtls_tls12_connect_poll()` and `noxtls_tls12_accept_poll()` for resumable TLS 1.2 handshakes.
- Added `noxtls_tls13_session_export()` and `noxtls_tls13_session_import()` so client resumption state can be stored outside the connection context and installed before ClientHello.
- Added unified handshake progression with `noxtls_tls_connection_handshake()` plus output flushing and pending-output inspection.

### Unified TLS Security and Observability

- Added unified setters for CRL verification, maximum plaintext record payload, I/O mode, transmit-queue limit, and imported TLS 1.3 session state.
- Added accessors for the authenticated peer leaf certificate, negotiated cipher suite, resumption status, issued session identity, and resumption identity.
- Added TLS 1.2 required-client-auth policy support.

### ECDH Diagnostics

- Added `noxtls_ecdh_compute_shared_secret_ex()` and `noxtls_ecdh_diagnostic_t` for optional, non-secret failure provenance.
- TLS ECDHE now propagates specific ECDH return codes and retains the most recent diagnostic in `tls_ecdhe_context_t`.

### Ed25519 Streaming Verification

- Added `noxtls_ed25519_verify_stream_init()`, `noxtls_ed25519_verify_stream_update()`, and `noxtls_ed25519_verify_stream_final()` for verification without staging a complete message in memory.
- Added `noxtls_ed25519_verify_split()` for a two-segment message.
- Corrected the streaming-finalization implementation to use the existing non-failing point helpers correctly on strict C compilers.

## Build and Configuration

- Removed a duplicate AES-CMAC streaming implementation that could cause strict-build conflicts.
- Resolved strict-build merge regressions in the TLS implementation.
- `NOXTLS_FEATURE_ED448` now honors a compiler/CMake definition instead of unconditionally redefining the default in `noxtls_config.h`.

## Operational Impact for Integrators

### Recommended Validation After Upgrade

- Exercise the nonblocking path with fragmented receives, short writes, and writable-notification retries; call `flush()` after `WANT_WRITE`.
- Validate session-cache protection and peer-policy binding before persisting TLS 1.3 resumption data.
- Test required-client-auth behavior with both populated and empty client Certificate messages.
- If ECDHE diagnostics are logged, ensure telemetry records only the documented enum/status fields and not application-owned key material.

### Performance/Footprint Expectations

- Caller-polled I/O retains incomplete records and encrypted output in the connection context. Size the queue limit according to the memory budget and transport backpressure policy.
- Streaming Ed25519 verification reduces the need to hold a complete signed message in a contiguous application buffer.

## Known Limitations / Open Items

- DTLS 1.3 interop hardening remains an active area (ongoing external-suite alignment work).
- Caller-polled support is for stream TLS. DTLS retains its datagram and retransmission model.
- Resumption-state persistence is application-managed; NoxTLS does not provide durable storage, anti-rollback storage, or cross-process cache synchronization.

## Upgrade and Migration Notes

- Stage event-driven integrations first, then enable `TLS_IO_MODE_NON_BLOCKING` and migrate loops to the `WANT_READ`/`WANT_WRITE` contract.
- Keep using blocking APIs if the transport already blocks reliably; no migration is required.
- Include the new TLS, ECDH, and Ed25519 public symbols in ABI/API compatibility checks.

## Complete Change Inventory (since v0.2.70)

Non-merge commits included in the 0.2.71 line:

1. `a9576bb` - feat: extend unified TLS security controls
2. `ea804ec` - Harden caller-polled TLS record I/O
3. `2bbe9f0` - tls: add polled TLS 1.2 and resumable sessions
4. `652935b` - Expose detailed ECDH failure results
5. `d369bd2` - fix(tls): propagate ECDHE failure diagnostics
6. `56d5966` - fix(cmac): remove duplicate streaming implementation
7. `7e78243` - fix(tls): resolve strict-build merge regressions
8. `d33beda` - feat(ed25519): add streaming verification API
9. `90e266e` - fix(ed25519): compile streaming verification

## Integrity and Disclosure Notes

- This release includes security hardening but does not currently publish CVE IDs in this note set.
- For coordinated vulnerability reporting, use the security reporting process documented in the project docs.
