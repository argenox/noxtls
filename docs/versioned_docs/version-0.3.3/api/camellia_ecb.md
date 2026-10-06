---
sidebar_position: 18
title: Camellia - ECB
description: "NoxTLS Camellia - ECB C API reference for embedded TLS, DTLS, and cryptography."
---

# Camellia - ECB

Camellia in ECB (Electronic Codebook) mode: each 16-byte block is encrypted or decrypted independently. No IV is used. Same security caveats as [AES - ECB](/docs/api/aes_ecb)—use only for single-block or deterministic single-block use cases; never for bulk data.

## API

### `noxtls_camellia_encrypt_ecb`

```c
noxtls_return_t noxtls_camellia_encrypt_ecb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t* iv, uint8_t* output, noxtls_camellia_type_t type);
```

Encrypts data in Camellia ECB mode. IV is not used; may be NULL.

**Parameters:** `key` — encryption key; `data` — plaintext; `data_len` — length (multiple of 16); `iv` — unused (NULL); `output` — ciphertext buffer; `type` — `NOXTLS_CAMELLIA_128_BIT`, `NOXTLS_CAMELLIA_192_BIT`, or `NOXTLS_CAMELLIA_256_BIT`.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).

### `noxtls_camellia_decrypt_ecb`

```c
noxtls_return_t noxtls_camellia_decrypt_ecb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t* iv, uint8_t* output, noxtls_camellia_type_t type);
```

Decrypts data in Camellia ECB mode. IV is not used; may be NULL.

**Parameters:** `key` — decryption key; `data` — ciphertext; `data_len` — length (multiple of 16); `iv` — unused (NULL); `output` — plaintext buffer; `type` — Camellia key type.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).
