---
sidebar_position: 5
title: "AES CTR"
---

# AES CTR

AES CTR (Counter mode) turns the block cipher into a stream cipher: a counter block (typically built from a nonce and an incrementing value) is encrypted to produce a keystream block, which is XORed with the plaintext. No padding is required—plaintext can be any length. Encryption and decryption are the same operation, and blocks can be processed in parallel or in random order.

**How it works:**  
- A 16-byte counter block is formed (e.g. nonce in the high bytes, counter in the low bytes).  
- Each counter value is encrypted to produce 16 bytes of keystream, which are XORed with the next 16 bytes of plaintext.  
- The counter is incremented for each block; it must never repeat for the same key.  
- Decryption is identical: same keystream XOR with ciphertext.

**Security implications:**  
CTR provides confidentiality and hides patterns, but **nonce/IV must never repeat** under the same key. Reusing (key, nonce) lets an attacker XOR two ciphertexts and recover plaintext. CTR does **not** provide authentication; use an AEAD (e.g. AES-GCM) or Encrypt-then-MAC. Prevent counter overflow (e.g. do not encrypt more than 2^32 blocks per nonce if the counter is 32 bits).

**Recommended use cases:**  
- Streaming or arbitrary-length data without padding (e.g. disk encryption, protocols that need random access).  
- When you need parallel or random-access decryption and will add authentication separately.

**Prefer** AES-GCM or ChaCha20-Poly1305 for most applications; use raw CTR only when you need its structure and combine it with a MAC.

### When to use

- **Streaming or arbitrary-length data** where you need confidentiality without padding (e.g. disk encryption, some protocols).
- **Parallel or random access:** CTR mode allows encrypting/decrypting any block without processing previous blocks, which can help performance and random-access scenarios.

### What to be careful of

- **Nonce/IV must never repeat.** Reusing the same (key, nonce/IV) for two messages is catastrophic: an attacker can XOR the two ciphertexts and recover plaintext. Use a unique nonce per encryption (e.g. counter, or random with enough bits that collision is negligible).
- **No authentication.** CTR does not detect tampering. Flipping bits in ciphertext flips the same bits in plaintext. Always use an AEAD (e.g. AES-GCM) or a separate MAC (Encrypt-then-MAC) for authenticated encryption.
- **Counter overflow.** The IV/nonce is typically 16 bytes; the top bytes are often used as a block counter. Ensure the counter never wraps for a single key (do not encrypt more than 2^32 blocks per key/nonce if the counter is 32 bits).

### Practical deployment

- Prefer **AES-GCM** or **ChaCha20-Poly1305** for most use cases; they provide authentication and avoid nonce-reuse pitfalls in a single API.
- If using raw CTR: (1) use a 96- or 128-bit nonce and a counter that never repeats; (2) combine with a MAC (e.g. Encrypt-then-MAC with HMAC-SHA256) and verify before decrypting; (3) enforce a maximum message length per (key, nonce) to prevent counter wrap.
- Good for disk or storage encryption where the “sector index” is the nonce and each sector is encrypted once.

## API

### `noxtls_aes_encrypt_ctr`

```c
noxtls_return_t noxtls_aes_encrypt_ctr(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, noxtls_aes_type_t type);
```

AES Encrypt in CTR Mode  Counter Mode: A counter is encrypted to produce a keystream, which is XORed with the plaintext. Supports arbitrary-length data.

**Parameters:**

- `key` — is a pointer to the encryption key
- `data` — is a pointer to the plaintext to be encrypted
- `data_len` — is the length of the plaintext in bytes
- `iv` — is the Initialization Vector (16 bytes) used as the initial counter. Required.
- `output` — is the output buffer where the encrypted plaintext will be placed
- `type` — is the AES variant, 128, 192, 256

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).

