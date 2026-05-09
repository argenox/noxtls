---
sidebar_position: 12
title: "ARIA - ECB"
---

# ARIA - ECB

ARIA in ECB (Electronic Codebook) mode: each 16-byte block is encrypted or decrypted independently. No IV is used. Same security caveats as [AES - ECB](/docs/api/aes_ecb)—use only for single-block or deterministic single-block use cases; never for bulk data.

For mode-specific guidance, see [AES - ECB](/docs/api/aes_ecb). IV may be NULL.

## API

### `aria_encrypt_ecb`

```c
noxtls_return_t aria_encrypt_ecb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t* iv, uint8_t* output, aria_type_t type);
```

Encrypts data in ARIA ECB mode. IV is not used; may be NULL.

**Parameters:** `key` — encryption key; `data` — plaintext; `data_len` — length (multiple of 16); `iv` — unused (NULL); `output` — ciphertext buffer; `type` — `ARIA_128_BIT`, `ARIA_192_BIT`, or `ARIA_256_BIT`.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).

### `aria_decrypt_ecb`

```c
noxtls_return_t aria_decrypt_ecb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t* iv, uint8_t* output, aria_type_t type);
```

Decrypts data in ARIA ECB mode. IV is not used; may be NULL.

**Parameters:** `key` — decryption key; `data` — ciphertext; `data_len` — length (multiple of 16); `iv` — unused (NULL); `output` — plaintext buffer; `type` — ARIA key type.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).
