<div align="center">
  <img src="docs/static/img/noxtls-logo-50.webp" alt="NoxTLS" width="200" />
</div>

# NoxTLS

**A fast, lightweight TLS crypto library designed for embedded and constrained systems.**  
Built for deterministic performance, clean APIs, and modern cryptography.


[![Build](https://github.com/argenox/noxtls/actions/workflows/build-applications.yml/badge.svg)](https://github.com/argenox/noxtls/actions/workflows/build-applications.yml)
[![Static Analysis](https://github.com/argenox/noxtls/actions/workflows/static-analysis.yml/badge.svg)](https://github.com/argenox/noxtls/actions/workflows/static-analysis.yml)
[![CodeQL](https://github.com/argenox/noxtls/actions/workflows/codeql.yml/badge.svg)](https://github.com/argenox/noxtls/actions/workflows/codeql.yml)



**Website:** https://argenox.com  
**Issues:** https://github.com/argenox/noxtls/issues  



## Why NoxTLS?

NoxTLS is built specifically for engineers building secure firmware and embedded devices.

- ⚡ **Small footprint** — optimized for microcontrollers  
- 🧠 **Predictable performance** — deterministic crypto operations  
- 🔒 **Security-first design** — constant-time primitives where required  
- 🔐 **Secure defaults** — legacy TLS 1.2 CBC/RSA suites are opt-in  
- 🧩 **Easy integration** — clean C APIs and configurable build  
- 🛠️ **Portable** — Cortex-M, embedded Linux, desktop, and [Zephyr RTOS](ports/zephyr/README.md)  


## Features

- Full TLS 1.2/1.3 Support and DTLS Pre-Shared Key
- ECC (P-256, P-384, P-521) ECDH and ECDSA
- AES-GCM AEAD
- Standard Message Digests - MD4, MD5, SHA-1, SHA-2, SHA-3 hashing
- HMAC
- Deterministic random bit generator (DRBG)
- X.509 parsing helpers
- Experimental Post-Quantum TLS 1.3 primitives:
  - ML-KEM-512/768/1024
  - ML-DSA-44/65/87
  - Pure PQ and X25519+ML-KEM hybrid keyshare negotiation
  - KAT-style and fuzz-smoke CI coverage for PQC paths
- Configurable footprint
- Embedded-friendly architecture


## Project Status

- ✅ In early Alpha - Currently being improved in various ways
- ✅ Actively developed  
- 🧪 Continuous integration enabled  
- 🔍 Security review planned  


## Documentation

The [NoxTLS documentation](https://docs.noxtls.com) is built with Docusaurus. Use the **version dropdown** in the navbar to switch between the latest (Next) and older releases (e.g. 0.1.6). When you cut a new release, snapshot the docs for that version—see [docs/VERSIONING.md](docs/VERSIONING.md).

Post-quantum rollout and interop status are tracked in [PQC_STATUS.md](PQC_STATUS.md).


## Getting Started

### Clone

```bash
git clone https://github.com/argenox/noxtls.git
cd noxtls
