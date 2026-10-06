---
sidebar_position: 10
title: AES Key Wrap
description: "NoxTLS AES Key Wrap (RFC 3394) C API reference: wrap and unwrap key material with an AES key-encryption key."
keywords:
  - noxtls
  - aes key wrap
  - rfc 3394
  - kek
  - eapol
---

# AES Key Wrap (RFC 3394)

AES Key Wrap protects key material, such as session keys or group keys, under an AES **key-encryption key (KEK)**. It uses the RFC 3394 section 2.2 algorithm with the default initial value `A6A6A6A6A6A6A6A6`. Key-transport protocols use it, including IEEE 802.11 EAPOL-Key Key Data encryption.

Header: `encryption/aes/noxtls_aes_keywrap.h`. New in 0.3.0.

## Enablement

Key wrap is built on single-block AES-ECB. It is compiled whenever **AES-ECB** is enabled (`NOXTLS_CFG_FEATURE_AES_ECB`). There is no separate knob.

## Constants

| Macro | Value | Meaning |
|---|---|---|
| `NOXTLS_AES_KW_SEMIBLOCK` | `8U` | Key-wrap semiblock size (64 bits) |

## API

### `noxtls_aes_key_wrap`

```c
noxtls_return_t noxtls_aes_key_wrap(const uint8_t *kek, noxtls_aes_type_t type,
                                    const uint8_t *plain, uint32_t plain_len,
                                    uint8_t *wrapped);
```

Wraps key data (RFC 3394 section 2.2.1).

**Parameters:**

- `kek`: the key-encryption key, 16, 24, or 32 bytes to match `type`.
- `type`: the AES key size of `kek`: `NOXTLS_AES_128_BIT`, `NOXTLS_AES_192_BIT`, or `NOXTLS_AES_256_BIT` (see [AES (shared)](./aes_shared.md#noxtls_aes_type_t)).
- `plain`, `plain_len`: the key data to wrap. The length must be a multiple of 8 and at least 16.
- `wrapped`: the output buffer, `plain_len + 8` bytes.

**Returns:** `NOXTLS_RETURN_SUCCESS`, `NOXTLS_RETURN_NULL`, or `NOXTLS_RETURN_INVALID_PARAM` for an invalid length.

### `noxtls_aes_key_unwrap`

```c
noxtls_return_t noxtls_aes_key_unwrap(const uint8_t *kek, noxtls_aes_type_t type,
                                      const uint8_t *wrapped, uint32_t wrapped_len,
                                      uint8_t *plain);
```

Unwraps key data and verifies the integrity check value (RFC 3394 section 2.2.2). The check is constant-time.

**Parameters:**

- `kek`, `type`: as for wrapping.
- `wrapped`, `wrapped_len`: the wrapped data. The length must be a multiple of 8 and at least 24.
- `plain`: the output buffer, `wrapped_len - 8` bytes. **It is cleared on failure.**

**Returns:** `NOXTLS_RETURN_SUCCESS`, `NOXTLS_RETURN_NULL`, `NOXTLS_RETURN_INVALID_PARAM` for an invalid length, or `NOXTLS_RETURN_FAILED` when the integrity check fails.

### `noxtls_aes_keywrap_self_test`

```c
noxtls_return_t noxtls_aes_keywrap_self_test(void);
```

Runs the RFC 3394 section 4.1 known-answer test (128-bit KEK, 128-bit key data). Returns `NOXTLS_RETURN_SUCCESS` when both wrap and unwrap match.

## Example

```c
#include "encryption/aes/noxtls_aes_keywrap.h"

uint8_t wrapped[16 + NOXTLS_AES_KW_SEMIBLOCK];
uint8_t unwrapped[16];

if (noxtls_aes_key_wrap(kek, NOXTLS_AES_128_BIT, key, 16U, wrapped) == NOXTLS_RETURN_SUCCESS &&
    noxtls_aes_key_unwrap(kek, NOXTLS_AES_128_BIT, wrapped, (uint32_t)sizeof(wrapped), unwrapped)
        == NOXTLS_RETURN_SUCCESS) {
    /* unwrapped[] == key[] */
}
noxtls_secure_zero(unwrapped, sizeof(unwrapped));
```

## Security notes

- Treat a `NOXTLS_RETURN_FAILED` from unwrap as tampering or a wrong KEK. Don't use the output buffer, which has already been cleared.
- RFC 3394 accepts only key data that is a multiple of 64 bits. Inputs that need padding (RFC 5649) are not supported.
