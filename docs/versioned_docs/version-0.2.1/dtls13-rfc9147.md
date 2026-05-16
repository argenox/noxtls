---
sidebar_position: 8
title: "DTLS 1.3 (RFC 9147)"
---

# DTLS 1.3 RFC 9147 conformance

This page summarizes NoxTLS DTLS 1.3 alignment with [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147). For API usage, see [TLS component](/docs/tls) and [DTLS API](/docs/api/dtls).

## Implemented

| RFC section | Topic | Status |
|-------------|-------|--------|
| 5.9 | HKDF `dtls13` label prefix | Done |
| 5.3 | ClientHello (`legacy_session_id`, `legacy_cookie`) | Done |
| 4.2, 4.2.3 | Unified header (CID, S/L bits, length) | Done |
| 4.2.2 | Record number reconstruction for AEAD | Done |
| 4.5.1 | Replay window per epoch | Done |
| 4.2.1 | Benign plaintext epoch mismatch handling | Done |
| 4.2.3 | Short-AEAD-tag padding (e.g. CCM_8) | Done |
| 5.2, 5.5 | Handshake reassembly and overlap checks | Done |
| 5.8.3 | ACK-aware retransmit (skip ACKed records) | Done |
| 4.3, 4.4 | MTU-aware handshake fragmentation | Done |
| 5.8.2, 9 | Connection ID request/response and rotation APIs | Done |
| 5.8.1 | Final-flight ACK retention and resend | Done |
| 5.8.1 | RTT-based retransmission timer | Done |
| 4.2.2, 4.5.3 | KeyUpdate read/write epoch tracking | Done |

## Interop hardening (in progress)

- Connection ID rotation under asymmetric third-party peers.
- Duplicate final-flight and lossy-timer scenarios under packet loss.
- KeyUpdate stress across epoch wrap.

## Suggested regression matrix

After changing DTLS 1.3 code:

1. `cmake --build build && ctest --test-dir build --output-on-failure`
2. Manual OpenSSL 3 `s_client` / `s_server` with `-dtls1_3` where available

## Migration

DTLS 1.3 key schedule and ClientHello layout changed for RFC 9147. Older NoxTLS DTLS 1.3 peers are not interoperable with current builds without upgrading both ends.
