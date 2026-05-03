---
sidebar_position: 14
title: "ARIA - CTR"
---

# ARIA - CTR

ARIA in CTR (Counter) mode: a counter block is encrypted to produce a keystream, which is XORed with the plaintext. Same semantics as [AES CTR](/docs/api/aes_ctr). The IV/nonce must be **unique per encryption** (no reuse with the same key).

## API

### `aria_encrypt_ctr`

```c
noxtls_return_t aria_encrypt_ctr(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t* iv, uint8_t* output, aria_type_t type);
```

Encrypts data in ARIA CTR mode. IV is the initial counter (16 bytes); must be unique per encryption.

**Parameters:** `key` — encryption key; `data` — plaintext; `data_len` — length; `iv` — 16-byte initial counter/nonce (unique per encryption); `output` — ciphertext buffer; `type` — ARIA key type.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).

### `aria_decrypt_ctr`

```c
noxtls_return_t aria_decrypt_ctr(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t* iv, uint8_t* output, aria_type_t type);
```

Decrypts data in ARIA CTR mode (same keystream as encrypt; XOR with ciphertext). Use the same IV that was used for encryption.

**Parameters:** `key` — decryption key; `data` — ciphertext; `data_len` — length; `iv` — 16-byte initial counter used for this ciphertext; `output` — plaintext buffer; `type` — ARIA key type.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).
