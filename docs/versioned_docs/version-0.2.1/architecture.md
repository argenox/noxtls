---
sidebar_position: 3
---

# Architecture

## Layout

The NoxTLS codebase is organized into:

- **noxtls-lib/** – Core library
  - **common** – Memory, debug, and shared utilities
  - **mdigest** – Hash algorithms (SHA, MD5, SHA-3, BLAKE2, etc.)
  - **encryption** – Symmetric ciphers (AES, ARIA, Camellia, ChaCha20)
  - **certs** – X.509 and certificate handling
  - **pkc** – Public key cryptography (RSA, DSA, ECC, ECDSA, ECDH)
  - **drbg** – Deterministic random bit generator
  - **tls** – TLS/DTLS protocol implementation; see [TLS component](/docs/tls) and [TLS API](/docs/api/tls)
- **utility/** – Helper code (e.g. Base64, file I/O) used by apps and tests
- **applications/** – Example and test applications (not part of the library API)

## Design

- **C99** – No external runtime beyond the C standard library where needed.
- **Modular** – Configurable profiles enable
- **Embedded-friendly** – No heavy dependencies; suitable for constrained environments

For the C API of each module, see the [Crypto API](/docs/api).
