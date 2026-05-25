---
sidebar_position: 4
title: AES CBC
description: "NoxTLS AES CBC C API reference for embedded TLS, DTLS, and cryptography."
---

# AES CBC

AES CBC (Cipher Block Chaining) is a mode of operation for the AES block cipher in which each plaintext block is XORed with the previous ciphertext block (or the IV for the first block) before being encrypted. This chaining removes the obvious pattern leakage of ECB: identical plaintext blocks no longer produce identical ciphertext blocks when the IV or prior ciphertext differs.

**How it works:**  
- The first block is XORed with a 16-byte Initialization Vector (IV), then encrypted.  
- Each subsequent block is XORed with the previous ciphertext block, then encrypted.  
- Decryption reverses the process: decrypt a block, then XOR with the previous ciphertext (or IV) to recover plaintext.  
- Plaintext must be padded to a multiple of 16 bytes (e.g. PKCS#7).

**Security implications:**  
CBC provides confidentiality and hides block-level patterns when the IV is unique per encryption. It does **not** provide integrity or authentication; ciphertext can be modified (e.g. bit-flipping) without detection. Reusing the same (key, IV) for different messages can leak information. Padding must be validated in constant time to avoid padding-oracle attacks.

**Recommended use cases:**  
- Bulk encryption where an IV can be chosen uniquely per message or session (e.g. TLS 1.2 record layer, legacy file encryption).  
- Situations where CBC is mandated by protocol or interoperability, and authentication is added separately (e.g. Encrypt-then-MAC).

**Avoid** using CBC without a MAC or other integrity mechanism; prefer AES-GCM or AES-CCM for new designs when possible.

### When to use

- **Bulk encryption** where you need confidentiality and can use an IV per message or per session (e.g. TLS 1.2 record layer, legacy file encryption).
- **Sequential or single-shot processing** where you encrypt/decrypt in one go and can provide a random or counter-based IV.

### What to be careful of

- **IV must be unique per encryption.** Reusing the same (key, IV) with different plaintexts can leak information. Use a cryptographically random IV (e.g. 16 bytes from a secure RNG) or a counter/sector ID when the construction allows it.
- **No built-in authentication.** CBC does not detect tampering. Prefer an AEAD (e.g. AES-GCM, AES-CCM) or use Encrypt-then-MAC with a strong MAC (e.g. HMAC-SHA256) and verify before decrypting.
- **Padding.** Plaintext length must be a multiple of 16 bytes. Use a well-defined padding scheme (e.g. PKCS#7) and validate padding securely on decrypt to avoid padding-oracle attacks.
- **Decryption order.** Implementations often decrypt in order; ensure you do not use decrypted data before verifying a MAC if you add one.

### Practical deployment

- Prefer **AES-GCM** or **AES-CCM** for new designs so you get authentication and avoid padding and many IV pitfalls.
- If you must use CBC: (1) generate a random IV for each encryption and prepend or transmit it; (2) use **Encrypt-then-MAC** (encrypt, then MAC ciphertext + IV, verify MAC before decrypting); (3) use constant-time padding validation.
- Do not use a zero or fixed IV; do not use a counter as IV unless the protocol explicitly defines it (e.g. TLS 1.2 record IV derivation).

## API

### `noxtls_aes_encrypt_cbc`

```c
noxtls_return_t noxtls_aes_encrypt_cbc(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, noxtls_aes_type_t type);
```

Encrypts data in CBC mode: each plaintext block is XORed with the previous ciphertext (or the IV for the first block), then encrypted.

**IV uniqueness (critical):** The IV must be **unique for every encryption** — i.e. for every call to `noxtls_aes_encrypt_cbc` that produces a separate ciphertext. In practice: **use a new IV for every packet or every message**. Do not reuse the same (key, IV) pair for two different plaintexts; reuse can leak information. Typically you generate 16 random bytes per encryption (e.g. from a secure RNG) and send the IV with the ciphertext (e.g. prepended to the packet) so the decrypt side can use it. If NULL is passed, a zero IV is used — acceptable only for a single encryption or when a protocol explicitly defines otherwise; do not use zero IV for multiple packets.

**Parameters:**

- `key` — pointer to the encryption key
- `data` — pointer to the plaintext to be encrypted
- `data_len` — length of the plaintext in bytes (must be a multiple of 16)
- `iv` — 16-byte Initialization Vector. Must be unique per encryption (new IV per packet/message). If NULL, zero IV is used (see above).
- `output` — output buffer where the ciphertext will be placed
- `type` — AES variant: `NOXTLS_AES_128_BIT`, `NOXTLS_AES_192_BIT`, or `NOXTLS_AES_256_BIT`

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).

### `noxtls_aes_decrypt_cbc`

```c
noxtls_return_t noxtls_aes_decrypt_cbc(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t* iv, uint8_t* output, noxtls_aes_type_t type);
```

Decrypts data in CBC mode: each ciphertext block is decrypted, then XORed with the previous ciphertext block (or IV for the first block) to recover the plaintext.

**IV per decryption:** Use the **same IV that was used for that encryption**. For packet or message protocols, the IV is typically sent with the ciphertext (e.g. the first 16 bytes of the packet); pass that same 16-byte value as `iv` for this call. Each call to `noxtls_aes_decrypt_cbc` corresponds to one encrypted message or packet, so you pass the IV that was used for that specific encryption. If the encryptor used a zero IV (NULL), pass NULL here.

**Parameters:**

- `key` — pointer to the decryption key
- `data` — pointer to the ciphertext to be decrypted
- `data_len` — length of the ciphertext in bytes (must be a multiple of 16)
- `iv` — 16-byte Initialization Vector that was used when this ciphertext was encrypted (e.g. the IV from the same packet). If NULL, zero IV is assumed.
- `output` — output buffer where the plaintext will be placed
- `type` — AES variant: `NOXTLS_AES_128_BIT`, `NOXTLS_AES_192_BIT`, or `NOXTLS_AES_256_BIT`

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).

