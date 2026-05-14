---
sidebar_position: 14
title: "ChaCha20-Poly1305"
---

# ChaCha20-Poly1305

ChaCha20-Poly1305 is an **authenticated encryption with associated data (AEAD)** that combines the ChaCha20 stream cipher with the Poly1305 one-time authenticator. It provides both confidentiality and integrity in one primitive. It uses a 256-bit key, a 96-bit (12-byte) nonce, and produces a 128-bit (16-byte) tag. Optional associated data (AAD) can be authenticated but not encrypted. ChaCha20-Poly1305 is fast in software and is used in TLS 1.3, Signal, and many modern protocols; it is a good default when AES hardware (e.g. AES-NI) is not available or when constant-time software is preferred.

**How it works:**  
- A one-time Poly1305 key is derived by encrypting a fixed block with ChaCha20 under the same key and nonce (counter 0).  
- ChaCha20 encrypts the plaintext (counter starting at 1), producing ciphertext.  
- Poly1305 is computed over the AAD (padded), ciphertext (padded), and their lengths, using the derived key; the result is the tag.  
- Decryption: verify the tag in constant time, then decrypt with ChaCha20.

**Security implications:**  
**Nonce must never repeat** under the same key—reuse can allow forgery and plaintext recovery. Verify the tag in **constant time** before using decrypted data; do not leak information on failure. Use AAD for any metadata that must be bound to the ciphertext. Rotate keys and limit the number of encryptions per key per standard guidance (e.g. 2^32 messages with 96-bit random nonces).

**Recommended use cases:**  
- Default AEAD when AES-GCM is not desirable (no AES-NI, or preference for constant-time software).  
- TLS 1.3, Signal, and other protocols that specify ChaCha20-Poly1305 (RFC 8439).

**Prefer** ChaCha20-Poly1305 over raw ChaCha20 plus a separate MAC; ensure nonce, tag placement, and AAD match the protocol (e.g. RFC 8439).

### When to use

- **Authenticated encryption (AEAD)** for most new designs, especially when AES hardware is not available or you want to avoid timing side channels. ChaCha20-Poly1305 is fast in software and is used in TLS 1.3, Signal, and many modern protocols.
- **When you need a single primitive** that provides both confidentiality and integrity with a 256-bit key, 12-byte nonce, and 16-byte tag.

### What to be careful of

- **Nonce must never repeat.** Reusing (key, nonce) for two different messages can allow forgery and plaintext recovery. Use a counter or random 12-byte nonce; if random, limit the number of encryptions per key so collision probability is negligible.
- **Tag verification.** Always verify the tag in constant time before using decrypted data. On failure, do not leak any information (e.g. do not distinguish “decrypt failed” from “tag mismatch” to external callers).
- **AAD.** Use additional authenticated data (AAD) for any context that must be bound to the ciphertext (e.g. protocol headers, length). AAD is not encrypted but is authenticated.

### Practical deployment

- **Default choice** for AEAD when AES-GCM is not desirable (e.g. no AES-NI, or preference for constant-time software). Use a 256-bit key, 12-byte nonce, and 16-byte tag.
- **Key and nonce management:** Rotate keys before reaching the recommended message limit per key (e.g. 2^32 messages with 96-bit random nonces). Never reuse a nonce under the same key.
- **Interoperability:** ChaCha20-Poly1305 is standardized in RFC 8439; ensure nonce, tag placement, and AAD match the protocol or standard you are implementing.

## Types

### noxtls_poly1305_context_t

Opaque context for incremental Poly1305 MAC computation. Used by [poly1305_init](#poly1305_init), [poly1305_update](#poly1305_update), [poly1305_final](#poly1305_final). Allocate and pass to [poly1305_init](#poly1305_init); do not access fields directly.

## API

### `poly1305_init`

```c
noxtls_return_t poly1305_init(noxtls_poly1305_context_t *ctx, const uint8_t *key);
```

Initialize Poly1305 context

**Parameters:**

- `ctx` — [noxtls_poly1305_context_t](#noxtls_poly1305_context_t) to initialize
- `key` — MAC key (32 bytes)

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success

### `poly1305_update`

```c
noxtls_return_t poly1305_update(noxtls_poly1305_context_t *ctx, const uint8_t *data, uint32_t data_len);
```

Update Poly1305 with data

**Parameters:**

- `ctx` — [noxtls_poly1305_context_t](#noxtls_poly1305_context_t) (from [poly1305_init](#poly1305_init))
- `data` — Data to authenticate
- `data_len` — Length of data in bytes

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success

### `poly1305_final`

```c
noxtls_return_t poly1305_final(noxtls_poly1305_context_t *ctx, uint8_t *tag);
```

Finalize Poly1305 and generate tag

**Parameters:**

- `ctx` — [noxtls_poly1305_context_t](#noxtls_poly1305_context_t) (from [poly1305_init](#poly1305_init), after [poly1305_update](#poly1305_update))
- `tag` — Output tag (16 bytes)

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success

### `poly1305_mac`

```c
noxtls_return_t poly1305_mac(const uint8_t *key, const uint8_t *data, uint32_t data_len, uint8_t *tag);
```

Compute Poly1305 MAC (convenience function)

**Parameters:**

- `key` — MAC key (32 bytes)
- `data` — Data to authenticate
- `data_len` — Length of data in bytes
- `tag` — Output tag (16 bytes)

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success

### `noxtls_chacha20_poly1305_encrypt`

```c
noxtls_return_t noxtls_chacha20_poly1305_encrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad, uint32_t aad_len, const uint8_t *plaintext, uint32_t plaintext_len, uint8_t *ciphertext, uint8_t *tag);
```

Encrypt and authenticate data using ChaCha20-Poly1305

**Parameters:**

- `key` — Encryption key (32 bytes)
- `nonce` — Nonce (12 bytes)
- `aad` — Additional authenticated data (can be NULL if aad_len is 0)
- `aad_len` — Length of AAD in bytes
- `plaintext` — Plaintext to encrypt (can be NULL if plaintext_len is 0)
- `plaintext_len` — Length of plaintext in bytes
- `ciphertext` — Output buffer for ciphertext (must be at least plaintext_len bytes)
- `tag` — Output buffer for authentication tag (must be at least 16 bytes)

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success

### `noxtls_chacha20_poly1305_decrypt`

```c
noxtls_return_t noxtls_chacha20_poly1305_decrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad, uint32_t aad_len, const uint8_t *ciphertext, uint32_t ciphertext_len, const uint8_t *tag, uint8_t *plaintext);
```

Decrypt and verify data using ChaCha20-Poly1305

**Parameters:**

- `key` — Encryption key (32 bytes)
- `nonce` — Nonce (12 bytes)
- `aad` — Additional authenticated data (can be NULL if aad_len is 0)
- `aad_len` — Length of AAD in bytes
- `ciphertext` — Ciphertext to decrypt (can be NULL if ciphertext_len is 0)
- `ciphertext_len` — Length of ciphertext in bytes
- `tag` — Authentication tag to verify (16 bytes)
- `plaintext` — Output buffer for plaintext (must be at least ciphertext_len bytes)

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success (authentication verified), [NOXTLS_RETURN_BAD_DATA](/docs/api/return_codes) on authentication failure

### `chacha20_poly1305_self_test`

```c
noxtls_return_t chacha20_poly1305_self_test(void);
```

Self-test function

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success (all tests passed)

