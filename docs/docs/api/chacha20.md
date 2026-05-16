---
sidebar_position: 15
title: ChaCha20
description: "NoxTLS ChaCha20 C API reference for embedded TLS, DTLS, and cryptography."
---

# ChaCha20

ChaCha20 is a **stream cipher** designed for high speed in software. It takes a 256-bit key, a 96-bit (12-byte) nonce, and a 64-bit block counter, and produces a keystream that is XORed with the plaintext. No padding is required; plaintext can be any length. Encryption and decryption are the same operation. ChaCha20 is often faster than AES in software when AES hardware (e.g. AES-NI) is not available and is used as the core of ChaCha20-Poly1305 (AEAD).

**How it works:**  
- A 512-bit state is built from constants, the key, nonce, and counter; it is updated by a series of quarter-round operations.  
- Each state update produces 64 bytes of keystream.  
- The keystream is XORed with the plaintext (or ciphertext for decryption).  
- The counter is incremented for each 64-byte block; it must not wrap for a single (key, nonce) within the message.

**Security implications:**  
ChaCha20 provides **confidentiality only**; it does not detect tampering. **Nonce must never repeat** under the same key—reuse allows an attacker to recover plaintext. Use **ChaCha20-Poly1305** when you need authenticated encryption. Limit the amount of data per (key, nonce) to stay within the 64-bit counter (e.g. at most 2^64 bytes per nonce).

**Recommended use cases:**  
- Building a custom AEAD or protocol that adds a MAC separately.  
- Software-heavy or constrained environments where AES acceleration is unavailable and only confidentiality is needed (with a separate MAC).

**Prefer** ChaCha20-Poly1305 for most use cases so you get authentication in one API; use raw ChaCha20 only when you need only the stream cipher and will add integrity separately.

### When to use

- **Stream cipher encryption** when you need confidentiality for arbitrary-length data without padding (e.g. custom protocols, compatibility with ChaCha20-based designs).
- **Software-heavy or constrained environments** where AES hardware acceleration is not available; ChaCha20 is typically fast in software.
- **When you need a PRNG-like keystream** that can be generated from (key, nonce, counter) and XORed with plaintext.

### What to be careful of

- **Nonce must never repeat.** Reusing (key, nonce) for two messages allows an attacker to recover plaintext. Use a 12-byte nonce (96 bits) and ensure uniqueness (e.g. counter or random with limited use per key).
- **No authentication.** ChaCha20 alone does not detect tampering. For authenticated encryption, use **ChaCha20-Poly1305** (AEAD) instead.
- **Counter.** The counter is 64-bit; do not encrypt more than 2^64 bytes per (key, nonce). For very long streams, segment with different nonces.

### Practical deployment

- Prefer **ChaCha20-Poly1305** for most use cases so you get authentication in one API. Use raw ChaCha20 only when you are building a custom AEAD or need only confidentiality and will add a MAC separately.
- If using raw ChaCha20: (1) use a unique 12-byte nonce per encryption; (2) combine with a MAC (e.g. Encrypt-then-MAC with Poly1305 or HMAC-SHA256) and verify before decrypting; (3) limit the amount of data per (key, nonce) to stay within counter limits.

## Types

### noxtls_chacha20_context_t

Opaque context for incremental ChaCha20 encryption/decryption. Used by [noxtls_chacha20_init](#noxtls_chacha20_init) and [noxtls_chacha20_process](#noxtls_chacha20_process). Allocate and pass to [noxtls_chacha20_init](#noxtls_chacha20_init); do not access fields directly.

## API

### `noxtls_chacha20_init`

```c
noxtls_return_t noxtls_chacha20_init(noxtls_chacha20_context_t *ctx, const uint8_t *key, const uint8_t *nonce, uint64_t counter);
```

Initialize ChaCha20 context

**Parameters:**

- `ctx` — [noxtls_chacha20_context_t](#noxtls_chacha20_context_t) to initialize
- `key` — Encryption key (32 bytes)
- `nonce` — Nonce (12 bytes)
- `counter` — Initial counter value (default: 0)

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) on failure

### `noxtls_chacha20_process`

```c
noxtls_return_t noxtls_chacha20_process(noxtls_chacha20_context_t *ctx, const uint8_t *input, uint8_t *output, uint32_t input_len);
```

Encrypt/Decrypt data using ChaCha20  ChaCha20 is a stream cipher, so encryption and decryption are identical operations (XOR with keystream).

**Parameters:**

- `ctx` — [noxtls_chacha20_context_t](#noxtls_chacha20_context_t) (from [noxtls_chacha20_init](#noxtls_chacha20_init))
- `input` — Input data (plaintext for encryption, ciphertext for decryption)
- `output` — Output buffer (must be at least input_len bytes)
- `input_len` — Length of input data in bytes

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success

### `noxtls_chacha20_encrypt`

```c
noxtls_return_t noxtls_chacha20_encrypt(const uint8_t *key, const uint8_t *nonce, uint64_t counter, const uint8_t *input, uint32_t input_len, uint8_t *output);
```

Encrypt data using ChaCha20 (convenience function)

**Parameters:**

- `key` — Encryption key (32 bytes)
- `nonce` — Nonce (12 bytes)
- `counter` — Initial counter value (default: 0)
- `input` — Plaintext data
- `input_len` — Length of plaintext in bytes
- `output` — Output buffer for ciphertext (must be at least input_len bytes)

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).

### `noxtls_chacha20_decrypt`

```c
noxtls_return_t noxtls_chacha20_decrypt(const uint8_t *key, const uint8_t *nonce, uint64_t counter, const uint8_t *input, uint32_t input_len, uint8_t *output);
```

Decrypt data using ChaCha20 (convenience function)

**Parameters:**

- `key` — Encryption key (32 bytes)
- `nonce` — Nonce (12 bytes)
- `counter` — Initial counter value (default: 0)
- `input` — Ciphertext data
- `input_len` — Length of ciphertext in bytes
- `output` — Output buffer for plaintext (must be at least input_len bytes)

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success

### `noxtls_chacha20_self_test`

```c
noxtls_return_t noxtls_chacha20_self_test(void);
```

Self-test function

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success (all tests passed)

