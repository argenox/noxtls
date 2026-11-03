---
sidebar_position: 5
title: Post Quantum Crypto (PQC)
description: "NoxTLS documentation: Post Quantum Crypto."
---

# Post Quantum Crypto

As the world is using public-key schemes like RSA and ECC, these can be broken using Shor's algorithm on Quantum Computers.

Quantum Computers are still not here, but for data that has to stay safe for decades, 

Large-scale quantum computers are expected to weaken widely used public-key schemes such as RSA and ECC. Even before practical quantum attacks are available, there is a "harvest now, decrypt later" risk for data that must remain confidential for many years.

For this reason, modern TLS and PKI deployments are starting staged migration to PQC-capable algorithms.

## Current noxtls PQC scope

`noxtls` currently includes:

- **ML-KEM** (FIPS 203) for key encapsulation
- **ML-DSA** (FIPS 204) for signatures
- **SLH-DSA** (FIPS 205) for stateless hash-based signatures
- **TLS 1.3 integration** for:
  - pure ML-KEM keyshare groups
  - hybrid X25519 + ML-KEM groups
  - ML-DSA and RSA-ML-DSA signature scheme paths
- **X.509 integration** for ML-DSA signature verification paths

SLH-DSA is exposed as a disabled-by-default FIPS 205 feature. SHA2-family and SHAKE-family core
keygen/sign/verify paths are implemented, and TLS/X.509 dispatch is wired behind the feature gate.
Official vector validation and interoperability coverage remain in progress.

See API references:

- [ML-KEM API](/docs/api/mlkem)
- [ML-DSA API](/docs/api/mldsa)
- [SLH-DSA API](/docs/api/slhdsa)
- [TLS 1.3 PQC](/docs/api/tls13_pqc)
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
  -DNOXTLS_CFG_FEATURE_ML_DSA=ON \
  -DNOXTLS_CFG_FEATURE_SLH_DSA=ON
```

Related docs:

- [Configuration Guide](/docs/configuration-guide)
- [Build Configuration Checks](/docs/api/build_config)
- [`PQC_STATUS.md`](https://github.com/argenox/noxtls/blob/main/noxtls/PQC_STATUS.md)

## Security notes

- Treat PQC deployment as an evolving interoperability program, not a one-time switch.
- Use strict testing/conformance profiles in CI for PQ-enabled builds.
- Continue applying classical TLS and PKI best practices (certificate validation, key protection, secure defaults) while rolling out PQC.
- Falcon signing uses IEEE-754 binary64 arithmetic over the secret key. On cores without a double-precision FPU (for example Cortex-M0, M3, M4 and M33, or RV32 without the D extension), the compiler runtime emulates it, and its instruction count depends on operand values, so signing time can leak key information to a local timing or power observer. Falcon verification is integer-only and unaffected. Define `NOXTLS_FALCON_REQUIRE_HW_DOUBLE=1` to make such a build fail at compile time; prefer ML-DSA or SLH-DSA for signing on those cores.
- Falcon signing rejects a secret key that decodes but does not satisfy the NTRU equation `f*G - g*F = q` with `NOXTLS_RETURN_BAD_DATA`, instead of looping in the sampler.
- ML-KEM: use `noxtls_mlkem_encaps_ex()` and `noxtls_mlkem_decaps_ex()` for keys and ciphertexts received from a peer. They take the received length and reject a value of the wrong size instead of reading past it.
- LMS/HSS and XMSS: a sign or reserve call made while another sign on the same key is still in progress (for example from inside the persistence callback) returns `NOXTLS_RETURN_FAILED` and does not touch the key. This guard is a flag, not a lock; serialize signing across threads.
