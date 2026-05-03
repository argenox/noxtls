---
sidebar_position: 0
title: Crypto API
---

# Crypto API

The NoxTLS C API is organized by module. Each page is generated from Doxygen documentation in the source.

- **[Common](/docs/api/common)** – Memory, debug, and shared utilities
- **[Encryption](/docs/api/encryption)** – AES, ARIA, Camellia, ChaCha20
- **[Message digest](/docs/api/mdigest)** – SHA, MD5, SHA-3, BLAKE2, etc.
- **[Public key crypto](/docs/api/pkc)** – RSA, ECC, ECDSA, ECDH
- **[Certificates](/docs/api/certs)** – X.509 and certificate handling
- **[Utility](/docs/api/utility)** – Base64, file I/O

**Pipeline:** Docs are generated automatically from Doxygen. In CI, the deploy workflow runs Doxygen (XML only), then `scripts/doxygen-xml-to-md.js` converts XML → Markdown for the API, applications, and [return codes](/docs/return-codes). When you update source comments (e.g. `@brief`, `@param`, `@return`, or enum `/**< ... */`), re-run Doxygen and the script to refresh the site. Local: `doxygen Doxyfile` then `node scripts/doxygen-xml-to-md.js build/doxygen/xml docs/docs/api`.
