---
sidebar_position: 25
title: "Public key crypto"
---

# Public key crypto

Public key cryptography is split into:

- **[ECC (Elliptic curve crypto)](/docs/api/ecc)** — Curves, points, keys, ECDH, ECDSA, and bignum helpers.
- **[RSA](/docs/api/rsa)** — Key generation, encryption, decryption, and signatures.
- **[DSA](/docs/api/dsa)** — Digital Signature Algorithm (FIPS 186-4): domain parameters, key generation, signing, and verification.
- **[Diffie-Hellman (FFDHE)](/docs/api/dh)** — Finite-field DH group parameters, key generation, shared secret.
- **[X25519](/docs/api/x25519)** — Curve25519 key agreement.
- **[X448](/docs/api/x448)** — Curve448 key agreement.
- **[Ed25519](/docs/api/ed25519)** — EdDSA signatures over Curve25519.
- **[Ed448](/docs/api/ed448)** — EdDSA signatures over Curve448.
- **[ML-KEM](/docs/api/mlkem)** — Post-quantum key encapsulation (FIPS 203).
- **[ML-DSA](/docs/api/mldsa)** — Post-quantum signatures (FIPS 204).

## Enablement flags

Key build flags:

- `NOXTLS_CFG_FEATURE_PKC` (base PKC)
- `NOXTLS_CFG_FEATURE_RSA`, `NOXTLS_CFG_FEATURE_ECC`, `NOXTLS_CFG_FEATURE_DSA`, `NOXTLS_CFG_FEATURE_DH`
- `NOXTLS_CFG_FEATURE_X25519`, `NOXTLS_CFG_FEATURE_X448`
- `NOXTLS_CFG_FEATURE_ED25519`, `NOXTLS_CFG_FEATURE_ED448`
- `NOXTLS_CFG_FEATURE_ML_KEM`, `NOXTLS_CFG_FEATURE_ML_DSA`

Dependency checks are enforced by [Build Configuration Checks](/docs/api/build_config).
