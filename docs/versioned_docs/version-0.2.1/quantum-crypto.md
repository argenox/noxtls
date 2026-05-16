---
sidebar_position: 5
title: Quantum Crypto
---

# Quantum Crypto

This page summarizes post-quantum cryptography (PQC) in `noxtls`, why it matters, and how the current implementation is intended to be used.

## Why quantum crypto matters

Large-scale quantum computers are expected to weaken widely used public-key schemes such as RSA and ECC. Even before practical quantum attacks are available, there is a "harvest now, decrypt later" risk for data that must remain confidential for many years.

For this reason, modern TLS and PKI deployments are starting staged migration to PQC-capable algorithms.

## Current noxtls PQC scope

`noxtls` currently includes:

- **ML-KEM** (FIPS 203) for key encapsulation
- **ML-DSA** (FIPS 204) for signatures
- **TLS 1.3 integration** for:
  - pure ML-KEM keyshare groups
  - hybrid X25519 + ML-KEM groups
  - ML-DSA and RSA-ML-DSA signature scheme paths
- **X.509 integration** for ML-DSA signature verification paths

See API references:

- [ML-KEM API](/docs/next/api/mlkem)
- [ML-DSA API](/docs/next/api/mldsa)
- [TLS 1.3 PQC](/docs/next/api/tls13_pqc)
- [Certificates API](/docs/api/certs)

## Migration approach

Recommended adoption model:

1. **Start with hybrid TLS key exchange** where compatibility is required.
2. **Enable PQC in controlled environments** and validate interop and performance.
3. **Keep cryptographic agility** in configuration and certificate pipelines.
4. **Track standards evolution** and be ready to update private-use IDs/profiles as final assignments and ecosystem support mature.

## Build and feature gates

Enable PQC features with:

```bash
cmake -S . -B build \
  -DNOXTLS_CFG_FEATURE_ML_KEM=ON \
  -DNOXTLS_CFG_FEATURE_ML_DSA=ON
```

Related docs:

- [Configuration Guide](/docs/configuration-guide)
- [Build Configuration Checks](/docs/api/build_config)
- [`PQC_STATUS.md`](https://github.com/argenox/noxtls/blob/main/noxtls/PQC_STATUS.md)

## Security notes

- Treat PQC deployment as an evolving interoperability program, not a one-time switch.
- Use strict testing/conformance profiles in CI for PQ-enabled builds.
- Continue applying classical TLS and PKI best practices (certificate validation, key protection, secure defaults) while rolling out PQC.
