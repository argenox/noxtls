---
sidebar_position: 27
title: "ML-DSA"
---

# ML-DSA

ML-DSA (NIST FIPS 204) digital signature API. Header: `pkc/mldsa/noxtls_mldsa.h`.

## Purpose

Use ML-DSA for post-quantum signatures in standalone PKC workflows and TLS 1.3 CertificateVerify paths.

## Enablement

- Build flag: `-DNOXTLS_CFG_FEATURE_ML_DSA=ON`
- Dependency: `NOXTLS_FEATURE_PKC` must be enabled (validated by `noxtls_check_config.h`)

## Parameters and sizes

| Parameter | Public key | Secret key | Signature |
| --- | ---: | ---: | ---: |
| `NOXTLS_MLDSA_44` | 1312 | 2560 | 2420 |
| `NOXTLS_MLDSA_65` | 1952 | 4032 | 3309 |
| `NOXTLS_MLDSA_87` | 2592 | 4896 | 4627 |

Maximum compile-time contracts:

- `NOXTLS_MLDSA_MAX_PUBLIC_KEY_LEN` = `2592`
- `NOXTLS_MLDSA_MAX_SECRET_KEY_LEN` = `4896`
- `NOXTLS_MLDSA_MAX_SIGNATURE_LEN` = `4627`
- `NOXTLS_MLDSA_SEED_LEN` = `32`
- `NOXTLS_MLDSA_RND_LEN` = `32`
- `NOXTLS_MLDSA_MAX_CONTEXT_LEN` = `255`

## Key APIs

### `noxtls_mldsa_public_key_len`

```c
uint32_t noxtls_mldsa_public_key_len(noxtls_mldsa_param_t param);
```

Return the exact public-key length for a parameter set.

### `noxtls_mldsa_secret_key_len`

```c
uint32_t noxtls_mldsa_secret_key_len(noxtls_mldsa_param_t param);
```

Return the exact secret-key length for a parameter set.

### `noxtls_mldsa_signature_len`

```c
uint32_t noxtls_mldsa_signature_len(noxtls_mldsa_param_t param);
```

Return the exact signature length for a parameter set.

### `noxtls_mldsa_keygen`

```c
noxtls_return_t noxtls_mldsa_keygen(noxtls_mldsa_param_t param,
                                    uint8_t *public_key,
                                    uint8_t *secret_key);
```

Generate ML-DSA keypair.

### `noxtls_mldsa_sign`

```c
noxtls_return_t noxtls_mldsa_sign(noxtls_mldsa_param_t param,
                                  const uint8_t *secret_key,
                                  const uint8_t *message,
                                  uint32_t message_len,
                                  uint8_t *signature,
                                  uint32_t *signature_len);
```

Sign message bytes. `signature_len` is in/out (input capacity, output actual size).

### `noxtls_mldsa_verify`

```c
noxtls_return_t noxtls_mldsa_verify(noxtls_mldsa_param_t param,
                                    const uint8_t *public_key,
                                    const uint8_t *message,
                                    uint32_t message_len,
                                    const uint8_t *signature,
                                    uint32_t signature_len);
```

Verify an ML-DSA signature.

### Test/vector hooks

```c
void noxtls_mldsa_set_test_seed_sequence(const uint8_t *bytes, uint32_t byte_len);
void noxtls_mldsa_set_test_signing_overrides(const uint8_t *pre,
                                             uint32_t pre_len,
                                             const uint8_t *rnd,
                                             uint32_t rnd_len,
                                             uint8_t externalmu);
```

Deterministic hooks used by test and vector-conformance harnesses.

## Typical flow

1. Select `NOXTLS_MLDSA_44`, `65`, or `87`.
2. Query sizes using `noxtls_mldsa_*_len`.
3. Allocate key/signature buffers.
4. Call `noxtls_mldsa_keygen`.
5. Sign with `noxtls_mldsa_sign`.
6. Verify with `noxtls_mldsa_verify`.

## TLS and X.509 integration

- TLS 1.3 CertificateVerify support and signature scheme IDs: [TLS 1.3 PQC](/docs/next/api/tls13_pqc)
- X.509 parse/verify handling for ML-DSA OIDs: [Certificates](/docs/api/certs)

## Security notes

- ML-DSA signature IDs currently use private-use code points for prototyping and may change when standardized IDs are available.
- Always validate `signature_len` against `noxtls_mldsa_signature_len(param)`.
- Treat private keys and transient randomness/seed buffers as sensitive material.
