---
sidebar_position: 17
title: TLS 1.3 PQC
description: "NoxTLS TLS 1.3 post-quantum integration: ML-KEM groups, hybrids, and ML-DSA signature schemes."
keywords:
  - noxtls
  - tls 1.3 pqc
  - hybrid key exchange
---

# TLS 1.3 PQC

Post-quantum TLS 1.3 integration guide for `noxtls`. This page documents named groups, signature schemes, and setup APIs used when ML-KEM / ML-DSA are enabled.

## Enablement

Required build flags:

- `-DNOXTLS_CFG_FEATURE_ML_KEM=ON`
- `-DNOXTLS_CFG_FEATURE_ML_DSA=ON`
- `-DNOXTLS_CFG_FEATURE_SLH_DSA=ON` for FIPS 205 SLH-DSA size contracts and signature-scheme IDs

Related dependencies:

- `NOXTLS_FEATURE_PKC` must be enabled.
- Hybrid groups (`X25519+ML-KEM`) require `NOXTLS_FEATURE_X25519`.

## Named groups (key exchange)

Defined in `noxtls_tls_common.h`:

- `TLS_NAMED_GROUP_MLKEM512` (`0xFE30`)
- `TLS_NAMED_GROUP_MLKEM768` (`0xFE31`)
- `TLS_NAMED_GROUP_MLKEM1024` (`0xFE32`)
- `TLS_NAMED_GROUP_X25519_MLKEM512` (`0xFE40`)
- `TLS_NAMED_GROUP_X25519_MLKEM768` (`0xFE41`)
- `TLS_NAMED_GROUP_X25519_MLKEM1024` (`0xFE42`)

Pure ML-KEM groups provide PQ KEM-only key exchange; hybrid groups combine X25519 and ML-KEM key material.

## Signature schemes

Defined in `noxtls_tls_common.h`:

- `TLS_SIGSCHEME_MLDSA44` (`0xFEA0`)
- `TLS_SIGSCHEME_MLDSA65` (`0xFEA1`)
- `TLS_SIGSCHEME_MLDSA87` (`0xFEA2`)
- `TLS_SIGSCHEME_RSA_PSS_SHA256_MLDSA44` (`0xFEB0`)
- `TLS_SIGSCHEME_RSA_PSS_SHA256_MLDSA65` (`0xFEB1`)
- `TLS_SIGSCHEME_RSA_PSS_SHA384_MLDSA87` (`0xFEB2`)
- `TLS_SIGSCHEME_SLHDSA_SHA2_128S` (`0xFEC0`) through `TLS_SIGSCHEME_SLHDSA_SHAKE_256F` (`0xFECB`)

These IDs are currently private-use values for prototyping/interoperability while standards-track assignments finalize.

SLH-DSA CertificateVerify dispatch is wired for the private-use signature schemes. Production use
still needs official vector validation and interoperability coverage because the largest signatures
stress certificate, handshake, and signature buffer paths more than existing ML-DSA paths.

## API setup

The TLS 1.3 context (`tls13_context_t`) carries ML-KEM and ML-DSA state when features are enabled.

### Server: configure ML-DSA private key

```c
noxtls_return_t noxtls_tls13_set_server_private_mldsa(tls13_context_t *ctx,
                                                noxtls_mldsa_param_t param,
                                                const uint8_t *private_key);
```

Use before `noxtls_tls13_accept()` when server CertificateVerify should use ML-DSA.

### Client (mTLS): configure ML-DSA client cert/private key

```c
noxtls_return_t tls13_set_client_cert_mldsa(tls13_context_t *ctx,
                                            const uint8_t *cert_der,
                                            uint32_t cert_len,
                                            noxtls_mldsa_param_t param,
                                            const uint8_t *private_key);
```

Use before `noxtls_tls13_connect()` for mutual TLS with ML-DSA client authentication.

SLH-DSA uses parallel setup calls with `noxtls_slhdsa_param_t`:

```c
noxtls_return_t noxtls_tls13_set_server_private_slhdsa(tls13_context_t *ctx,
                                                       noxtls_slhdsa_param_t param,
                                                       const uint8_t *private_key);
noxtls_return_t tls13_set_client_cert_slhdsa(tls13_context_t *ctx,
                                             const uint8_t *cert_der,
                                             uint32_t cert_len,
                                             noxtls_slhdsa_param_t param,
                                             const uint8_t *private_key);
```

## Behavior overview

1. Client advertises supported groups and signature schemes.
2. Negotiation selects classical, pure PQ, or hybrid group.
3. For hybrid groups, both components contribute to shared-secret derivation.
4. CertificateVerify uses selected scheme (including ML-DSA variants when configured).

## Interop and testing

- Enable PQC flags in build configuration.
- Run unit and conformance tests from PQ-enabled test builds (`ctest --output-on-failure`).
- Use strict-vector mode as needed: `-DNOXTLS_CFG_PQC_STRICT_OFFICIAL_VECTORS=ON`.

See also:

- [ML-KEM](/docs/api/mlkem)
- [ML-DSA](/docs/api/mldsa)
- [TLS 1.3 API](/docs/api/tls13)
- [Build Configuration Checks](/docs/api/build_config)
