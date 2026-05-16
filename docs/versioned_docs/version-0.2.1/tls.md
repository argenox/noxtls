---
sidebar_position: 7
title: "TLS component"
description: NoxTLS TLS 1.2/1.3 and DTLS 1.2/1.3 — protocol features, extensions, configuration, and API entry points.
keywords:
  - noxtls
  - tls 1.3
  - dtls
  - embedded tls
  - cipher suites
  - handshake
---

# TLS component

The NoxTLS TLS component implements **Transport Layer Security (TLS)** and **Datagram TLS (DTLS)** for secure client and server connections over callback-based I/O (sockets, custom transports, or test harnesses).

**Default build profile:** TLS **1.2** and **1.3**, plus DTLS **1.2** and **1.3**. TLS 1.0 and 1.1 remain available when enabled in `noxtls_config.h` (`NOXTLS_FEATURE_TLS10`, `NOXTLS_FEATURE_TLS11`).

## Protocol overview

| Protocol | Wire versions | Default build | Primary APIs |
|----------|---------------|---------------|--------------|
| TLS 1.2 | `0x0303` | On | [tls12](./api/tls12), [unified](./api/tls_unified) |
| TLS 1.3 | `0x0304` | On | [tls13](./api/tls13), [unified](./api/tls_unified) |
| TLS 1.0 / 1.1 | `0x0301` / `0x0302` | Off | [tls10](./api/tls10), [tls11](./api/tls11) |
| DTLS 1.2 | `0xFEFD` | On | [dtls12](./api/dtls12) via `noxtls_dtls12_context_init` |
| DTLS 1.3 | `0xFEFC` | On | [dtls13](./api/dtls13) via `noxtls_dtls13_context_init` |

## TLS 1.3 features

| Area | Support |
|------|---------|
| Full handshake (1-RTT) | Client and server |
| HelloRetryRequest | Supported |
| KeyUpdate | Send and receive |
| Session resumption | NewSessionTicket, PSK binder, external PSK |
| 0-RTT early data | Client and server paths (some edge cases still under test) |
| PSK modes | `psk_ke`, `psk_dhe_ke` (ECDHE-PSK) |
| Client authentication (mTLS) | RSA, ECDSA, Ed25519, Ed448, ML-DSA (feature-gated) |
| ALPN | Offer, select, and verify |
| SNI | Client send and server validation |
| Record Size Limit (RFC 8449) | Negotiation and send chunking |
| Channel bindings (RFC 5929) | `tls-unique` style export API |
| Signature algorithms | RSA-PSS, ECDSA (P-256/P-384/P-521), Ed25519 |
| Named groups | X25519, X448, FFDHE (RFC 7919), optional ML-KEM / hybrids |

## TLS 1.2 features

| Area | Support |
|------|---------|
| Cipher suites | ECDHE-RSA, ECDHE-ECDSA, DHE-RSA, RSA key transport, AES-GCM, AES-CBC, AES-CCM, ChaCha20-Poly1305, ARIA |
| Secure renegotiation (RFC 5746) | `renegotiation_info` and fallback SCSV handling |
| Encrypt-then-MAC (RFC 7366) | Negotiated and applied on record layer |
| Extended Master Secret (RFC 7627) | Offer, negotiation, session/ticket binding |
| Session tickets (RFC 5077) | ServerHello echo, NewSessionTicket, cache hooks |
| Maximum fragment length (RFC 6066) | `noxtls_tls12_set_max_fragment_length` |
| SNI, ALPN | Same extension framework as TLS 1.3 stack |
| Raw public keys (RFC 7250) | Certificate type negotiation |
| OCSP stapling (RFC 6066) | Client `status_request`, server CertificateStatus send/receive |
| Heartbeat (RFC 6520) | Extension and record handling (conformance still improving) |

## DTLS 1.2 features (RFC 6347)

| Area | Support |
|------|---------|
| Record layer | 13-byte header, epoch and 48-bit sequence |
| Handshake | Fragmentation and reassembly |
| Loss recovery | Retransmission timer, flight buffers |
| DoS mitigation | HelloVerifyRequest cookie (generate/verify) |
| Replay protection | Sliding window per epoch |
| Configuration | [noxtls_dtls_set_mtu](./api/dtls#noxtls_dtls_set_mtu), [dtls_set_retransmit](./api/dtls#dtls_set_retransmit), anti-amplification limit |

Initialize with [noxtls_dtls12_context_init](./api/dtls12#noxtls_dtls12_context_init), then use the same [noxtls_tls12_connect](./api/tls12#noxtls_tls12_connect) / [noxtls_tls12_accept](./api/tls12#noxtls_tls12_accept) and send/recv APIs as for TLS over TCP.

## DTLS 1.3 features (RFC 9147)

DTLS 1.3 shares the TLS 1.3 handshake and cipher suites but uses a datagram record layer. NoxTLS implements the following (see also the [DTLS 1.3 guide](./dtls13)):

| Area | Support |
|------|---------|
| Key schedule | HKDF labels use the `dtls13` prefix (not `tls13`) |
| ClientHello | Empty `legacy_session_id`, zero-length `legacy_cookie` in first flight |
| Unified record header | Connection ID bit, sequence number length bit, optional length field |
| Record number protection | Truncated on wire, reconstructed before AEAD |
| Replay detection | Per low epoch; benign epoch mismatch discarded |
| Handshake reassembly | Overlap checks, bounded future-message queue |
| ACK records | Parse ACK ranges; retransmit skips acknowledged records |
| Retransmission | RTT-based timer when ACKs available; final-flight ACK retention (2 MSL window) |
| Connection ID | RequestConnectionId / NewConnectionId APIs, spare CID pool, rotation hooks |
| KeyUpdate | Independent read/write epoch tracking across epoch wrap |
| Short tags | CCM_8 suites padded before AEAD when tag length &lt; 16 bytes |
| MTU-aware fragmentation | Handshake fragment size accounts for unified header overhead |

Initialize with [noxtls_dtls13_context_init](./api/dtls13#noxtls_dtls13_context_init). Configure the shared DTLS base via [DTLS API](./api/dtls) (MTU, retransmit, ACK range limit).

:::caution Interoperability note
DTLS 1.3 wire format and key derivation changed to align with RFC 9147. Peers built before this alignment are not interoperable with RFC 9147-conformant builds.
:::

## Extensions and security properties (summary)

| RFC | Feature | TLS 1.2 | TLS 1.3 | DTLS |
|-----|---------|---------|---------|------|
| 5746 | Secure renegotiation | Yes | N/A | N/A |
| 6066 | SNI | Yes | Yes | Yes |
| 6066 | Max fragment length | Yes | — | — |
| 6066 | OCSP stapling | Yes | Partial / planned | — |
| 7366 | Encrypt-then-MAC | Yes | N/A | N/A |
| 7627 | Extended Master Secret | Yes | N/A | N/A |
| 5077 | Session tickets | Yes | Yes | Yes (TLS 1.3 path) |
| 7301 | ALPN | Yes | Yes | Yes |
| 8449 | Record size limit | — | Yes | Yes |
| 9146 / 9147 | Connection ID | — | — | DTLS 1.3 |
| 6520 | Heartbeat | Partial | — | — |
| 7250 | Raw public keys | Yes | — | — |

Extension constants exist for SCT, certificate compression, delegated credentials, and token binding; dedicated handling is not yet complete. See the [TLS RFC feature analysis](https://github.com/argenox/noxtls/blob/main/tls-rfc-feature-implementation-analysis.md) in the repository for a full matrix.

## Post-quantum TLS (experimental)

When `NOXTLS_FEATURE_ML_KEM` and `NOXTLS_FEATURE_ML_DSA` are enabled:

- TLS 1.3 key shares: ML-KEM-768 / ML-KEM-1024 and X25519+ML-KEM hybrids (private-use code points).
- TLS 1.3 signatures: ML-DSA-65 / ML-DSA-87 and RSA+ML-DSA composites.

See [Quantum crypto](./quantum-crypto), [TLS 1.3 PQC](./api/tls13_pqc), [ML-KEM](./api/mlkem), and [ML-DSA](./api/mldsa).

## Architecture

- **Base context** ([tls_context_t](./api/tls#tls_context_t)) holds role (client/server), version, I/O callbacks, and shared record state.
- **Version-specific contexts** extend the base: [tls12_context_t](./api/tls12), [tls13_context_t](./api/tls13).
- **I/O is callback-based:** implement [noxtls_tls_set_io_callbacks](./api/tls#noxtls_tls_set_io_callbacks) so the stack can read/write records on your transport.
- **Server version negotiation:** [noxtls_tls_detect_version](./api/tls#noxtls_tls_detect_version) or [noxtls_tls_connection_accept](./api/tls_unified#noxtls_tls_connection_accept) on the unified connection type.

## Typical usage

### TLS client (TLS 1.2 or 1.3)

1. [noxtls_tls12_context_init](./api/tls12#noxtls_tls12_context_init) or [noxtls_tls13_context_init](./api/tls13#noxtls_tls13_context_init).
2. [noxtls_tls_set_io_callbacks](./api/tls#noxtls_tls_set_io_callbacks).
3. Optional SNI on `ctx->server_name` / `server_name_len`.
4. Optional client cert: [noxtls_tls13_set_client_cert](./api/tls13#noxtls_tls13_set_client_cert) (or ECDSA / Ed25519 / ML-DSA variants).
5. [noxtls_tls12_connect](./api/tls12#noxtls_tls12_connect) or [noxtls_tls13_connect](./api/tls13#noxtls_tls13_connect).
6. [noxtls_tls12_send](./api/tls12#noxtls_tls12_send) / [noxtls_tls12_recv](./api/tls12#noxtls_tls12_recv) or TLS 1.3 equivalents.
7. [noxtls_tls12_close](./api/tls12#noxtls_tls12_close) and context free.

### TLS server

1. Initialize context, set I/O, load DER certificate and private key (RSA via [noxtls_tls12_set_server_private_rsa](./api/tls12#noxtls_tls12_set_server_private_rsa) or [noxtls_tls13_set_server_private_rsa](./api/tls13#noxtls_tls13_set_server_private_rsa); ECDSA via `noxtls_tls*_set_server_private_ecdsa`).
2. [noxtls_tls12_accept](./api/tls12#noxtls_tls12_accept) or [noxtls_tls13_accept](./api/tls13#noxtls_tls13_accept).

### Unified API (TLS 1.2 + 1.3 auto-negotiation)

Use [noxtls_tls_connection_t](./api/tls_unified#noxtls_tls_connection_t) for one handle per TCP connection:

- Server: [noxtls_tls_connection_init](./api/tls_unified#noxtls_tls_connection_init), set cert/key, [noxtls_tls_connection_accept](./api/tls_unified#noxtls_tls_connection_accept).
- Client: init, SNI, [noxtls_tls_connection_connect](./api/tls_unified#noxtls_tls_connection_connect) (TLS 1.3 first, then 1.2).
- Data: [noxtls_tls_connection_send](./api/tls_unified#noxtls_tls_connection_send) / [noxtls_tls_connection_recv](./api/tls_unified#noxtls_tls_connection_recv).

### DTLS client or server

1. [noxtls_dtls12_context_init](./api/dtls12#noxtls_dtls12_context_init) or [noxtls_dtls13_context_init](./api/dtls13#noxtls_dtls13_context_init).
2. [noxtls_dtls_set_mtu](./api/dtls#noxtls_dtls_set_mtu) and [dtls_set_retransmit](./api/dtls#dtls_set_retransmit) on `ctx->base` (DTLS base inside the TLS context).
3. [noxtls_tls13_connect](./api/tls13#noxtls_tls13_connect) / [noxtls_tls13_accept](./api/tls13#noxtls_tls13_accept) (or TLS 1.2 equivalents for DTLS 1.2).
4. Application data via [noxtls_tls13_send](./api/tls13#noxtls_tls13_send) / [noxtls_tls13_recv](./api/tls13#noxtls_tls13_recv).

## Interoperability testing

| Harness | Purpose |
|---------|---------|
| tlsfuzzer | Scripted negative and edge-case tests — see `tlsfuzzer-script-status.md` in the repo |

## Configuration

- **Certificates:** DER in context; chain verification via [certs API](./api/certs). Enable `NOXTLS_FEATURE_CERT` and required PKC algorithms.
- **Cipher preference:** [noxtls_tls13_set_prefer_chacha20](./api/tls13#noxtls_tls13_set_prefer_chacha20).
- **PSK (TLS 1.3):** [noxtls_tls13_set_external_psk](./api/tls13#noxtls_tls13_set_external_psk).
- **Buffer sizes:** `NOXTLS_TLS_MAX_RECORD_SIZE` and `NOXTLS_TLS_MAX_HANDSHAKE_SIZE` in [configuration guide](./configuration-guide).
- **PQC:** `NOXTLS_CFG_FEATURE_ML_KEM`, `NOXTLS_CFG_FEATURE_ML_DSA`.

## API reference

- **[TLS API (common)](./api/tls)** — Base context, I/O, alerts, version detection.
- **[TLS API (unified)](./api/tls_unified)** — Single connection, auto TLS 1.2/1.3.
- **[TLS 1.2 API](./api/tls12)** — TLS 1.2 context and stream transport APIs.
- **[TLS 1.3 API](./api/tls13)** — TLS 1.3 context and stream transport APIs.
- **[DTLS API](./api/dtls)** — MTU, retransmit, cookies, replay, ACK helpers.
- **[DTLS 1.2 API](./api/dtls12)** — DTLS 1.2 initialization and datagram usage.
- **[DTLS 1.3 API](./api/dtls13)** — DTLS 1.3 initialization and datagram usage.
- **[DTLS 1.3 guide](./dtls13)** — DTLS 1.3 features and transport model.

## Sample applications

- [HTTPS client](./applications/app_https_client) and [HTTPS server](./applications/app_https_server) — TLS over TCP.
- [TLS test](./applications/app_tls_test) — Demos and tests.
- [DTLS PSK demo](./applications/app_dtls_psk_demo) and [DTLS PSK test](./applications/app_dtls_psk_test) — DTLS with PSK-oriented examples.
