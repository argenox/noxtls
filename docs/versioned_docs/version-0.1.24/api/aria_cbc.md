---
sidebar_position: 13
title: "ARIA - CBC"
---

# ARIA - CBC

ARIA in CBC (Cipher Block Chaining) mode: each plaintext block is XORed with the previous ciphertext (or IV for the first block), then encrypted. Same semantics and IV rules as [AES CBC](/docs/api/aes_cbc)—**use a unique IV per encryption** (e.g. new IV per packet or message).

## API

### `aria_encrypt_cbc`

```c
noxtls_return_t aria_encrypt_cbc(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t* iv, uint8_t* output, aria_type_t type);
```

Encrypts data in ARIA CBC mode. IV must be 16 bytes and unique per encryption.

**Parameters:** `key` — encryption key; `data` — plaintext; `data_len` — length (multiple of 16); `iv` — 16-byte IV (unique per encryption); `output` — ciphertext buffer; `type` — ARIA key type.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).

### `aria_decrypt_cbc`

```c
noxtls_return_t aria_decrypt_cbc(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t* iv, uint8_t* output, aria_type_t type);
```

Decrypts data in ARIA CBC mode. Use the same IV that was used for encryption.

**Parameters:** `key` — decryption key; `data` — ciphertext; `data_len` — length (multiple of 16); `iv` — 16-byte IV used for this ciphertext; `output` — plaintext buffer; `type` — ARIA key type.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).
