---
sidebar_position: 3
title: AES - ECB
description: "NoxTLS AES - ECB C API reference for embedded TLS, DTLS, and cryptography."
---

# AES - ECB

AES ECB (Electronic Codebook) is the simplest mode of operation for the AES block cipher. In ECB mode, the data to be encrypted is divided into 16-byte (128-bit) blocks. Each block is independently encrypted using the same key, meaning the same plaintext block will always produce the same ciphertext block.

**How it works:**  
- Each plaintext block is encrypted separately and independently.  
- No Initialization Vector (IV) is used.  
- Encryption and decryption of each block can be done in parallel.

**Security Implications:**  
ECB mode should generally be avoided except for very specific use cases. Because identical plaintext blocks are encrypted into identical ciphertext blocks, patterns in the plaintext remain visible in the ciphertext. This makes ECB mode vulnerable to pattern analysis and information leakage—not suitable for encrypting structured or sensitive data.

**Recommended Use Cases:**  
- Encrypting exactly one block of data (e.g., encrypting keys for key wrapping).
- Situations where deterministic encryption is required for a single block.
- Debugging or testing cryptographic implementations.

**Never use ECB** for encrypting more than one block of structured or sensitive data, files, or disk sectors, as it provides no semantic security.


### When to use

- **Single-block encryption** where you need to encrypt exactly one 16-byte block (e.g. key wrapping, some legacy protocols).
- **Deterministic encryption** where the same plaintext must always produce the same ciphertext (e.g. searchable encryption with careful design).
- **Testing or debugging** of block-cipher behavior only.

### What to be careful of

- **Do not use for bulk data or multiple blocks.** ECB encrypts each block independently, so identical plaintext blocks produce identical ciphertext blocks. This leaks structure and patterns (e.g. repeated headers, blank areas in images).
- **No authentication.** ECB provides confidentiality only; it does not detect tampering or forgery.
- **No IV.** There is no randomization; same key + same plaintext always yields same ciphertext.

### Practical deployment

- Prefer **AES-GCM**, **AES-CCM**, or **ChaCha20-Poly1305** for general-purpose encryption (authenticated, no pattern leakage).
- If you must use ECB (e.g. compatibility), use it only for a single block or with a higher-level scheme (e.g. NIST key wrapping) that defines safe usage.
- Never use ECB for file or disk encryption, or for any data longer than one block without a standardized construction.

## API

### `noxtls_aes_encrypt_ecb`

```c
noxtls_return_t noxtls_aes_encrypt_ecb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t* iv, uint8_t* output, noxtls_aes_type_t type);
```

Encrypts data in ECB mode. Each 16-byte block is encrypted independently. No IV is used; `iv` may be NULL.

**Parameters:**

- `key` — pointer to the encryption key (16, 24, or 32 bytes for AES-128, AES-192, AES-256)
- `data` — pointer to the plaintext to be encrypted
- `data_len` — length of the plaintext in bytes (must be a multiple of 16)
- `iv` — not used in ECB; may be NULL
- `output` — output buffer where the ciphertext will be written
- `type` — AES variant: `NOXTLS_AES_128_BIT`, `NOXTLS_AES_192_BIT`, or `NOXTLS_AES_256_BIT`

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success

### `noxtls_aes_decrypt_ecb`

```c
noxtls_return_t noxtls_aes_decrypt_ecb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t* iv, uint8_t* output, noxtls_aes_type_t type);
```

Decrypts data in ECB mode. Each 16-byte block is decrypted independently. No IV is used; `iv` may be NULL.

**Parameters:**

- `key` — pointer to the decryption key (16, 24, or 32 bytes for AES-128, AES-192, AES-256)
- `data` — pointer to the ciphertext to be decrypted
- `data_len` — length of the ciphertext in bytes (must be a multiple of 16)
- `iv` — not used in ECB; may be NULL
- `output` — output buffer where the plaintext will be written
- `type` — AES variant: `NOXTLS_AES_128_BIT`, `NOXTLS_AES_192_BIT`, or `NOXTLS_AES_256_BIT`

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).

