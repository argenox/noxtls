---
sidebar_position: 0
title: Crypto API
---

# Crypto API

The NoxTLS C API is organized by module. Each page is generated from Doxygen documentation in the source.

- **[Common](/docs/api/common)** – Memory, debug, and shared utilities
- **[Version macros](/docs/api/version)** – Compile-time version constants
- **[Build configuration checks](/docs/api/build_config)** – Compile-time feature dependency checks
- **[Encryption](/docs/api/encryption)** – AES, ARIA, Camellia, ChaCha20
- **[DRBG](/docs/api/drbg)** – AES-CTR deterministic random bit generation
- **[Message digest](/docs/api/mdigest)** – SHA, MD5, SHA-3, BLAKE2, etc.
- **[Public key crypto](/docs/api/pkc)** – RSA, ECC/DSA/DH, X25519/X448, EdDSA, and PQC
- **[ML-KEM](/docs/api/mlkem)** – Post-quantum key encapsulation (FIPS 203)
- **[ML-DSA](/docs/api/mldsa)** – Post-quantum signatures (FIPS 204)
- **[TLS 1.3 PQC](/docs/api/tls13_pqc)** – PQ and hybrid key exchange/signature integration
- **[Certificates](/docs/api/certs)** – X.509 and certificate handling
- **[Utility](/docs/api/utility)** – Base64, file I/O

## Documentation pattern

Each API page should include:

- Purpose
- Enablement flags and dependencies
- Key APIs and types
- Typical usage flow
- Security and compatibility notes

## Generation pipeline

Docs are generated from Doxygen comments. In CI, the deploy workflow runs Doxygen (XML) then `scripts/doxygen-xml-to-md.js` to convert XML to Markdown for API and applications pages, including [return codes](/docs/api/return_codes).

When updating source comments (`@brief`, `@param`, `@return`, enum docs), refresh locally:

```bash
doxygen Doxyfile
node scripts/doxygen-xml-to-md.js build/doxygen/xml docs/docs/api
```
