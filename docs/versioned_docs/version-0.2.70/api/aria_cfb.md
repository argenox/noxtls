---
sidebar_position: 15
title: ARIA - CFB
description: "NoxTLS ARIA - CFB C API reference for embedded TLS, DTLS, and cryptography."
---

# ARIA - CFB

ARIA in CFB (Cipher Feedback) mode: the IV or previous ciphertext block is encrypted to form a keystream, which is XORed with the plaintext. Same semantics as [AES CFB](/docs/api/aes_cfb). IV must be unique per encryption.

## API

### `noxtls_aria_encrypt_cfb`

```c
noxtls_return_t noxtls_aria_encrypt_cfb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t* iv, uint8_t* output, noxtls_aria_type_t type);
```

Encrypts data in ARIA CFB mode.

**Parameters:** `key` — encryption key; `data` — plaintext; `data_len` — length; `iv` — 16-byte IV (unique per encryption); `output` — ciphertext buffer; `type` — ARIA key type.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).

### `noxtls_aria_decrypt_cfb`

```c
noxtls_return_t noxtls_aria_decrypt_cfb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t* iv, uint8_t* output, noxtls_aria_type_t type);
```

Decrypts data in ARIA CFB mode. Use the same IV that was used for encryption.

**Parameters:** `key` — decryption key; `data` — ciphertext; `data_len` — length; `iv` — 16-byte IV used for this ciphertext; `output` — plaintext buffer; `type` — ARIA key type.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).
