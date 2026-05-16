---
sidebar_position: 26
title: "ML-KEM"
---

# ML-KEM

ML-KEM (NIST FIPS 203) key encapsulation mechanism API. Header: `pkc/mlkem/noxtls_mlkem.h`.

## Purpose

Use ML-KEM to establish a 32-byte shared secret between peers using encapsulation/decapsulation. In `noxtls`, this is also used by TLS 1.3 post-quantum and hybrid keyshare paths.

## Enablement

- Build flag: `-DNOXTLS_CFG_FEATURE_ML_KEM=ON`
- Dependency: `NOXTLS_FEATURE_PKC` must be enabled (validated by `noxtls_check_config.h`)

## Parameters and sizes

| Parameter | Public key | Secret key | Ciphertext | Shared secret |
| --- | ---: | ---: | ---: | ---: |
| `NOXTLS_MLKEM_512` | 800 | 1632 | 768 | 32 |
| `NOXTLS_MLKEM_768` | 1184 | 2400 | 1088 | 32 |
| `NOXTLS_MLKEM_1024` | 1568 | 3168 | 1568 | 32 |

Maximum compile-time contracts:

- `NOXTLS_MLKEM_MAX_PUBLIC_KEY_LEN` = `1568`
- `NOXTLS_MLKEM_MAX_SECRET_KEY_LEN` = `3168`
- `NOXTLS_MLKEM_MAX_CIPHERTEXT_LEN` = `1568`
- `NOXTLS_MLKEM_SHARED_SECRET_LEN` = `32`

## Key APIs

### `noxtls_mlkem_public_key_len`

```c
uint32_t noxtls_mlkem_public_key_len(noxtls_mlkem_param_t param);
```

Return the exact public-key length for a parameter set.

### `noxtls_mlkem_secret_key_len`

```c
uint32_t noxtls_mlkem_secret_key_len(noxtls_mlkem_param_t param);
```

Return the exact secret-key length for a parameter set.

### `noxtls_mlkem_ciphertext_len`

```c
uint32_t noxtls_mlkem_ciphertext_len(noxtls_mlkem_param_t param);
```

Return the exact ciphertext length for a parameter set.

### `noxtls_mlkem_keygen`

```c
noxtls_return_t noxtls_mlkem_keygen(noxtls_mlkem_param_t param,
                                    uint8_t *public_key,
                                    uint8_t *secret_key);
```

Generate keypair for `param`.

### `noxtls_mlkem_encaps`

```c
noxtls_return_t noxtls_mlkem_encaps(noxtls_mlkem_param_t param,
                                    const uint8_t *public_key,
                                    uint8_t *ciphertext,
                                    uint8_t *shared_secret_32);
```

Encapsulate to peer public key. Produces ciphertext and 32-byte shared secret.

### `noxtls_mlkem_decaps`

```c
noxtls_return_t noxtls_mlkem_decaps(noxtls_mlkem_param_t param,
                                    const uint8_t *public_key,
                                    const uint8_t *secret_key,
                                    const uint8_t *ciphertext,
                                    uint8_t *shared_secret_32);
```

Decapsulate ciphertext with local secret key and recover the 32-byte shared secret.

### `noxtls_mlkem_set_test_random_sequence`

```c
void noxtls_mlkem_set_test_random_sequence(const uint8_t *bytes, uint32_t byte_len);
```

Test-only deterministic random hook used for reproducible vectors and conformance harnesses.

## Typical flow

1. Choose parameter (`NOXTLS_MLKEM_512`, `768`, or `1024`).
2. Query lengths with `noxtls_mlkem_*_len`.
3. Allocate buffers.
4. Call `noxtls_mlkem_keygen`.
5. Sender calls `noxtls_mlkem_encaps`; receiver calls `noxtls_mlkem_decaps`.
6. Use `shared_secret_32` as KDF input for session keys.

## TLS integration

For TLS 1.3 integration details (pure ML-KEM groups and X25519+ML-KEM hybrid groups), see [TLS 1.3 PQC](/docs/next/api/tls13_pqc).

## Security notes

- ML-KEM group and signature IDs currently use private-use code points for prototyping and may change when IANA assignments finalize.
- Keep ML-KEM secret keys in protected storage and clear temporary buffers after use.
- Use authenticated key schedule construction (for TLS this is handled by the protocol implementation).
