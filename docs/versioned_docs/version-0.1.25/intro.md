---
sidebar_position: 1
---

# Introduction

NoxTLS is a C cryptography and TLS/DTLS library for embedded and systems software. It is designed for low-footprint integration while still providing broad algorithm and protocol coverage.

## Features

- **Encryption**: AES, ARIA, Camellia, ChaCha20/Poly1305
- **Message digests**: SHA-1, SHA-256, SHA-512, SHA-3, MD4, MD5, RIPEMD-160, BLAKE2
- **Public key crypto**: RSA, DSA, ECC, ECDSA, ECDH, X25519, X448, Ed25519, Ed448
- **Post-quantum crypto**: ML-KEM and ML-DSA (feature-gated)
- **TLS**: TLS 1.0–1.3 and DTLS support — see [TLS component](/docs/tls) for usage and [TLS API](/docs/api/tls) for the API
- **X.509 / certificates**: Parsing and verification

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

1. **Standalone (host)** – For unit tests and desktop tooling. Build from the repository with CMake.
2. **With Zephyr (embedded)** – Add the library to your Zephyr application via `add_subdirectory` and link to the noxtls targets.

See [Getting Started](/docs/getting-started) for build instructions, [TLS component](/docs/tls) for TLS/DTLS usage, and [Crypto API](/docs/api) for the C API.

For post-quantum details, see [ML-KEM](/docs/api/mlkem), [ML-DSA](/docs/api/mldsa), and [TLS 1.3 PQC](/docs/api/tls13_pqc).
