---
sidebar_position: 1
description: Introduction to NoxTLS — embedded TLS 1.2/1.3, DTLS, cryptography, and X.509 for resource-constrained C systems.
keywords:
  - noxtls
  - embedded tls
  - dtls
  - c cryptography
  - introduction
---

# Introduction

NoxTLS is a C cryptography and TLS/DTLS library for embedded and systems software. It is designed for low-footprint integration while still providing broad algorithm and protocol coverage.

## Features

- **Encryption**: AES, ARIA, Camellia, ChaCha20/Poly1305
- **Message digests**: SHA-1, SHA-256, SHA-512, SHA-3, MD4, MD5, RIPEMD-160, BLAKE2
- **Public key crypto**: RSA, DSA, ECC, ECDSA, ECDH, X25519, X448, Ed25519, Ed448
- **Post-quantum crypto**: ML-KEM and ML-DSA (feature-gated)
- **TLS / DTLS**: TLS 1.2 and 1.3, DTLS 1.2 and 1.3 (default build); optional TLS 1.0/1.1 — see [TLS component](./tls)
- **X.509 / certificates**: Parsing, verification, and TLS integration

## TLS and DTLS at a glance

| Layer | What NoxTLS provides |
|-------|----------------------|
| **TLS 1.3** | 1-RTT handshake, resumption, 0-RTT, PSK, mTLS, ALPN, record size limit |
| **TLS 1.2** | ECDHE/DHE suites, secure renegotiation, ETM, EMS, session tickets, OCSP stapling |
| **DTLS 1.2** | Datagram records, cookies, retransmission, replay protection |
| **DTLS 1.3** | RFC 9147 unified header, CID, ACK flights, `dtls13` key schedule — [feature guide](./dtls13) |

For protocol details, extension tables, and sample code paths, start with the [TLS component](./tls) guide.

## Supported elliptic curves

NoxTLS supports the following curves for ECDH, ECDSA, and TLS key exchange:

| Curve | OID / name | Use |
|-------|------------|-----|
| **NIST P-256** | secp256r1, prime256v1 | ECDSA, ECDH, TLS (e.g. ECDHE with AES-128) |
| **NIST P-384** | secp384r1 | ECDSA, ECDH, TLS (e.g. ECDHE with AES-256) |
| **NIST P-521** | secp521r1 | ECDSA, ECDH |
| **Curve25519** | X25519 | Key agreement (ECDH), TLS 1.3 key share |
| **Ed25519** | Ed25519 (RFC 8032) | Digital signatures, X.509 subject public keys |

- **Weierstrass (NIST)**: P-256, P-384, and P-521 are used for ECDSA signing/verification and ECDH key agreement, and for TLS 1.2/1.3 ECDHE cipher suites.
- **X25519**: Montgomery curve used for key agreement; supported in TLS key exchange.
- **Ed25519**: Twisted Edwards curve used for signatures; supported for X.509 and general signing.

## Build modes

NoxTLS can be built in two ways:

1. **Standalone (host)** – For unit tests, protocol interop, and desktop tooling. Build from the repository with CMake.
2. **With Zephyr (embedded)** – Add the library to your Zephyr application via `add_subdirectory` and link to the noxtls targets.

See [Getting Started](/docs/getting-started) for build instructions, [TLS component](/docs/tls) for TLS/DTLS usage, and [Crypto API](/docs/api) for the C API.

For post-quantum details, see [Quantum crypto](/docs/quantum-crypto), [ML-KEM](/docs/api/mlkem), [ML-DSA](/docs/api/mldsa), and [TLS 1.3 PQC](/docs/api/tls13_pqc).
