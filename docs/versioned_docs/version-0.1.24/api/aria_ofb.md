---
sidebar_position: 16
title: "ARIA - OFB"
---

# ARIA - OFB

ARIA in OFB (Output Feedback) mode: the IV or previous keystream block is encrypted to produce the next keystream block, which is XORed with the plaintext. Same semantics as [AES OFB](/docs/api/aes_ofb). IV must be unique per encryption.

## API

### `aria_encrypt_ofb`

```c
noxtls_return_t aria_encrypt_ofb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t* iv, uint8_t* output, aria_type_t type);
```

Encrypts data in ARIA OFB mode.

**Parameters:** `key` — encryption key; `data` — plaintext; `data_len` — length; `iv` — 16-byte IV (unique per encryption); `output` — ciphertext buffer; `type` — ARIA key type.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).

### `aria_decrypt_ofb`

```c
noxtls_return_t aria_decrypt_ofb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t* iv, uint8_t* output, aria_type_t type);
```

Decrypts data in ARIA OFB mode (same keystream as encrypt). Use the same IV that was used for encryption.

**Parameters:** `key` — decryption key; `data` — ciphertext; `data_len` — length; `iv` — 16-byte IV used for this ciphertext; `output` — plaintext buffer; `type` — ARIA key type.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).
