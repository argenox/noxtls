---
sidebar_position: 24
title: Key derivation (HKDF, PBKDF2)
description: "NoxTLS key derivation C API reference: HKDF (RFC 5869) and PBKDF2-HMAC (RFC 8018) for embedded TLS, Matter PASE, and password-based keys."
keywords:
  - noxtls
  - pbkdf2
  - rfc 8018
  - hkdf
  - rfc 5869
  - key derivation
---

# Key derivation (HKDF, PBKDF2)

The `noxtls_kdf` library (`noxtls-lib/kdf`) provides two key-derivation functions:

- **HKDF** (RFC 5869), declared in `noxtls_hkdf.h`. TLS 1.3 uses it internally.
- **PBKDF2** (RFC 8018 section 5.2), declared in `noxtls_pbkdf.h`. New public API in 0.3.0.

Both are built on the NoxTLS HMAC module (`noxtls_mac`).

## Enablement

| CMake knob | `noxtls_config.h` macro | Default | Requires |
|---|---|---|---|
| `NOXTLS_CFG_FEATURE_HKDF` | `NOXTLS_FEATURE_HKDF` | Follows `NOXTLS_CFG_FEATURE_HMAC` | HMAC |
| `NOXTLS_CFG_FEATURE_PBKDF2` | `NOXTLS_FEATURE_PBKDF2` | OFF | HMAC |

When PBKDF2 is enabled, X.509 PBES2 private-key decryption (`noxtls_x509_private_key_parse_*_with_password()`) uses `noxtls_pbkdf2_hmac()`. When it is disabled, PBES2 keeps its private PBKDF2-HMAC-SHA1 implementation, so reduced builds behave as before. [Matter PASE](../spake2p.md) requires PBKDF2.

## PBKDF2

### Constants

| Macro | Value | Meaning |
|---|---|---|
| `NOXTLS_PBKDF2_MIN_ITERATIONS` | `1U` | Smallest accepted iteration count *c* |
| `NOXTLS_PBKDF2_BLOCK_INDEX_SIZE` | `4U` | Size of the big-endian block index INT(i) |
| `NOXTLS_PBKDF2_MAX_PRF_SIZE` | `64U` | Largest supported HMAC output (SHA-512) |

### `noxtls_pbkdf2_hmac`

```c
noxtls_return_t noxtls_pbkdf2_hmac(noxtls_hash_algos_t hash_algo,
                                   const uint8_t *password, uint32_t password_len,
                                   const uint8_t *salt, uint32_t salt_len,
                                   uint32_t iterations,
                                   uint8_t *dk, uint32_t dk_len);
```

Derives `dk_len` bytes, computed as `DK = T_1 || T_2 || ...` with `T_i = U_1 ^ ... ^ U_c`, `U_1 = PRF(P, S || INT(i))` and `U_j = PRF(P, U_{j-1})`.

**Parameters:**

- `hash_algo`: the HMAC hash. One of `NOXTLS_HASH_SHA1`, `NOXTLS_HASH_SHA_256`, `NOXTLS_HASH_SHA_384`, or `NOXTLS_HASH_SHA_512`.
- `password`, `password_len`: the password P. May be `NULL` only when the length is 0.
- `salt`, `salt_len`: the salt S. May be `NULL` only when the length is 0.
- `iterations`: the iteration count *c*. Must be at least `NOXTLS_PBKDF2_MIN_ITERATIONS`.
- `dk`, `dk_len`: the output buffer and its length. `dk_len` must be non-zero. **The buffer is erased on failure.**

**Returns:** a [noxtls_return_t](./return_codes):

- `NOXTLS_RETURN_SUCCESS` on success.
- `NOXTLS_RETURN_NULL` if a required pointer is NULL.
- `NOXTLS_RETURN_INVALID_ALGORITHM` for an unsupported hash.
- `NOXTLS_RETURN_INVALID_PARAM` if the iteration count or the output length is zero.
- `NOXTLS_RETURN_FAILED` if the HMAC primitive fails.

All intermediate PRF blocks are erased before the function returns.

### `noxtls_pbkdf2_self_test`

```c
noxtls_return_t noxtls_pbkdf2_self_test(void);
```

Runs the PBKDF2-HMAC-SHA1 known-answer tests from RFC 6070 section 2 (c = 1, 2). Returns `NOXTLS_RETURN_SUCCESS` when all vectors match.

### Example

```c
#include "kdf/noxtls_pbkdf.h"

uint8_t key[32];
noxtls_return_t rc = noxtls_pbkdf2_hmac(NOXTLS_HASH_SHA_256,
                                        password, password_len,
                                        salt, salt_len,
                                        100000U,
                                        key, (uint32_t)sizeof(key));
if (rc != NOXTLS_RETURN_SUCCESS) {
    /* key[] has already been erased */
}
/* ... use key ... */
noxtls_secure_zero(key, sizeof(key));
```

### Compatibility header

`noxtls_pbkdf2.h` only includes `noxtls_pbkdf.h`, so existing `#include "noxtls_pbkdf2.h"` lines keep working.

## HKDF

```c
noxtls_return_t noxtls_hkdf_extract(noxtls_hash_algos_t hash_algo,
                                    const uint8_t *salt, uint32_t salt_len,
                                    const uint8_t *ikm, uint32_t ikm_len,
                                    uint8_t *prk, uint32_t *prk_len);

noxtls_return_t noxtls_hkdf_expand(noxtls_hash_algos_t hash_algo,
                                   const uint8_t *prk, uint32_t prk_len,
                                   const uint8_t *info, uint32_t info_len,
                                   uint8_t *okm, uint32_t okm_len);
```

These implement RFC 5869 Extract and Expand. `hkdf_extract()` and `hkdf_expand()` remain as backward-compatible aliases.

## Security notes

- Choose the iteration count and salt for your threat model. RFC 8018 accepts any *c* ≥ 1, but low counts give weak protection for human-chosen passwords.
- HMAC-SHA256 state is private per context by default, so PBKDF2 may run alongside other HMAC computations. If you build with `NOXTLS_HMAC_SHA256_SHARED_STATE=1`, a single shared SHA-256 slot is used: do not call PBKDF2-HMAC-SHA256 while another HMAC-SHA256 context is live, and serialize all access. See [Memory usage](../memory-usage.md#concurrent-crypto-scratch-storage).
