---
sidebar_position: 28
title: SLH-DSA
description: "NoxTLS SLH-DSA (FIPS 205) API for stateless hash-based post-quantum signatures."
keywords:
  - noxtls
  - slh-dsa
  - fips 205
  - post-quantum signatures
---

# SLH-DSA

SLH-DSA (NIST FIPS 205) stateless hash-based digital signature API.
Header: `pkc/slhdsa/noxtls_slhdsa.h`.

## Purpose

Use SLH-DSA for post-quantum signatures where the large signature sizes are acceptable and
stateless hash-based signatures are required.

## Enablement

- Build flag: `-DNOXTLS_CFG_FEATURE_SLH_DSA=ON`
- Dependency: `NOXTLS_FEATURE_PKC` must be enabled (validated by `noxtls_check_config.h`)
- Status: SHA2-family and SHAKE-family keygen/sign/verify are implemented for the FIPS 205
  parameter sets, with TLS 1.3 and X.509 dispatch wired behind the feature gate. Official vector
  validation and interoperability coverage are still in progress.

## Parameters and sizes

| Parameter | Public key | Secret key | Signature | Category |
| --- | ---: | ---: | ---: | ---: |
| `NOXTLS_SLHDSA_SHA2_128S` | 32 | 64 | 7856 | 1 |
| `NOXTLS_SLHDSA_SHA2_128F` | 32 | 64 | 17088 | 1 |
| `NOXTLS_SLHDSA_SHA2_192S` | 48 | 96 | 16224 | 3 |
| `NOXTLS_SLHDSA_SHA2_192F` | 48 | 96 | 35664 | 3 |
| `NOXTLS_SLHDSA_SHA2_256S` | 64 | 128 | 29792 | 5 |
| `NOXTLS_SLHDSA_SHA2_256F` | 64 | 128 | 49856 | 5 |
| `NOXTLS_SLHDSA_SHAKE_128S` | 32 | 64 | 7856 | 1 |
| `NOXTLS_SLHDSA_SHAKE_128F` | 32 | 64 | 17088 | 1 |
| `NOXTLS_SLHDSA_SHAKE_192S` | 48 | 96 | 16224 | 3 |
| `NOXTLS_SLHDSA_SHAKE_192F` | 48 | 96 | 35664 | 3 |
| `NOXTLS_SLHDSA_SHAKE_256S` | 64 | 128 | 29792 | 5 |
| `NOXTLS_SLHDSA_SHAKE_256F` | 64 | 128 | 49856 | 5 |

Maximum compile-time contracts:

- `NOXTLS_SLHDSA_MAX_PUBLIC_KEY_LEN` = `64`
- `NOXTLS_SLHDSA_MAX_SECRET_KEY_LEN` = `128`
- `NOXTLS_SLHDSA_MAX_SIGNATURE_LEN` = `49856`
- `NOXTLS_SLHDSA_MAX_CONTEXT_LEN` = `255`

## Key APIs

```c
uint32_t noxtls_slhdsa_public_key_len(noxtls_slhdsa_param_t param);
uint32_t noxtls_slhdsa_secret_key_len(noxtls_slhdsa_param_t param);
uint32_t noxtls_slhdsa_signature_len(noxtls_slhdsa_param_t param);
uint32_t noxtls_slhdsa_security_category(noxtls_slhdsa_param_t param);
uint8_t noxtls_slhdsa_is_sha2(noxtls_slhdsa_param_t param);
uint8_t noxtls_slhdsa_is_small(noxtls_slhdsa_param_t param);
```

Return exact FIPS 205 size and parameter metadata.

```c
noxtls_return_t noxtls_slhdsa_keygen(noxtls_slhdsa_param_t param,
                                     uint8_t *public_key,
                                     uint8_t *secret_key);
noxtls_return_t noxtls_slhdsa_sign(noxtls_slhdsa_param_t param,
                                   const uint8_t *secret_key,
                                   const uint8_t *message,
                                   uint32_t message_len,
                                   uint8_t *signature,
                                   uint32_t *signature_len);
noxtls_return_t noxtls_slhdsa_verify(noxtls_slhdsa_param_t param,
                                     const uint8_t *public_key,
                                     const uint8_t *message,
                                     uint32_t message_len,
                                     const uint8_t *signature,
                                     uint32_t signature_len);
```

## Security and compatibility notes

The current SLH-DSA backend has internal round-trip/tamper tests for SHAKE-128s, SHAKE-128f,
SHA2-128s, SHA2-128f, and SHA2-192s.
Do not claim FIPS validation or production conformance until official FIPS 205 vectors pass.

SLH-DSA signatures are much larger than ML-DSA signatures. The largest FIPS 205 signature is
49,856 bytes, so TLS and X.509 callers must size certificate, handshake, and signature buffers
accordingly before enabling production use.
