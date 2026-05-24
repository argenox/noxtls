---
sidebar_position: 6
title: AES CFB
description: "NoxTLS AES CFB C API reference for embedded TLS, DTLS, and cryptography."
---

# AES CFB

AES CFB (Cipher Feedback) is a mode in which the previous ciphertext block (or the IV for the first block) is encrypted to produce a keystream, which is XORed with the plaintext. The result becomes the next ciphertext block and the input to the next encryption. No padding is required for the plaintext; partial blocks are supported (CFB can be used with a smaller feedback size, e.g. CFB-8). Decryption is sequential—you cannot skip to an arbitrary block without processing previous blocks.

**How it works:**  
- The IV (or a previous ciphertext block) is encrypted with the block cipher to produce a keystream block.  
- The keystream is XORed with the plaintext to produce ciphertext.  
- That ciphertext block is then used as the next “feedback” input for the following block.  
- Decryption uses the same structure: encrypt the incoming ciphertext block, XOR with ciphertext to get plaintext.

**Security implications:**  
CFB provides confidentiality and removes block-level pattern leakage when the IV is unique. It does **not** provide authentication; ciphertext can be modified. Reusing (key, IV) for two messages can leak information. Use an AEAD or Encrypt-then-MAC if integrity is required. Error propagation depends on the CFB variant (e.g. CFB-128 vs CFB-8).

**Recommended use cases:**  
- Legacy or protocol compatibility when CFB is mandated.  
- Streaming encryption with arbitrary-length data when a feedback-style mode is required and CTR is not available.

**Prefer** AES-GCM, AES-CTR (with MAC), or ChaCha20-Poly1305 for new designs; use CFB mainly for interoperability.

### When to use

- **Streaming encryption** with arbitrary-length data when you need a mode that uses the block cipher in a feedback style (e.g. legacy compatibility, some protocols).
- **Situations where CTR is not available** but you need non-padded encryption.

### What to be careful of

- **IV must be unique.** As with CTR, reusing (key, IV) with different plaintexts can leak information. Use a random or otherwise unique IV per encryption.
- **No authentication.** CFB does not detect tampering. Use an AEAD or Encrypt-then-MAC if you need integrity.
- **Sequential.** Decryption is sequential; you cannot skip to an arbitrary block without processing previous blocks. For random access, CTR is usually preferred.
- **Error propagation.** In some variants, a bit error in ciphertext can affect subsequent blocks; implementors should be aware of the variant in use.

### Practical deployment

- For new designs, prefer **AES-GCM**, **AES-CTR** (with a MAC), or **ChaCha20-Poly1305**. Use CFB mainly for interoperability with existing systems.
- If you use CFB: (1) generate a random 16-byte IV per encryption; (2) add authentication (e.g. Encrypt-then-MAC) and verify before decrypting; (3) document whether you use CFB-1, CFB-8, or CFB-128 and stick to it.

## API

### `noxtls_aes_encrypt_cfb`

```c
noxtls_return_t noxtls_aes_encrypt_cfb(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, noxtls_aes_type_t type);
```

AES Encrypt in CFB Mode  Cipher Feedback mode: The previous ciphertext block (or IV for first block) is encrypted to produce a keystream, which is XORed with the plaintext. Supports arbitrary-length data.

**Parameters:**

- `key` — is a pointer to the encryption key
- `data` — is a pointer to the plaintext to be encrypted
- `data_len` — is the length of the plaintext in bytes
- `iv` — is the Initialization Vector (16 bytes). Required.
- `output` — is the output buffer where the encrypted plaintext will be placed
- `type` — is the AES variant, 128, 192, 256

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).

