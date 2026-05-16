---
sidebar_position: 16
title: RC4
description: "NoxTLS RC4 C API reference for embedded TLS, DTLS, and cryptography."
---

# RC4

::::::warning

RC4 is **cryptographically weak** and **should not be used** for new applications or any security-sensitive use. It has known biases in its keystream that allow practical attacks (e.g. plaintext recovery, key recovery in some settings). Major standards and protocols (including TLS) have deprecated or removed RC4. This implementation is provided **only for legacy compatibility** with existing systems or data. Do not use RC4 for new designs or where security is critical.

**Recommended alternatives:** [ChaCha20](/docs/api/chacha20), [ChaCha20-Poly1305](/docs/api/chacha20_poly1305), or [AES-GCM](/docs/api/aes_gcm) for confidentiality and authenticated encryption.

:::

RC4 (Rivest Cipher 4) is a **stream cipher** that accepts a key of 1–256 bytes and produces a keystream that is XORed with the plaintext. Encryption and decryption are the same operation. No nonce or IV is defined in the original algorithm; some protocols prepend an IV to the key. RC4 is **deprecated**; use the alternatives above for any new or security-sensitive work.

### When RC4 might appear

- Legacy protocols or file formats that historically used RC4.
- Interoperability with very old systems that cannot be upgraded.
- **Do not use** for TLS, new protocols, or any application where strong confidentiality is required.

## Types

### noxtls_rc4_context_t

Opaque context for incremental RC4 encryption/decryption. Used by [noxtls_rc4_init](#noxtls_rc4_init) and [noxtls_rc4_process](#noxtls_rc4_process). Allocate and pass to [noxtls_rc4_init](#noxtls_rc4_init); do not access fields directly.

## API

### `noxtls_rc4_init`

```c
noxtls_return_t noxtls_rc4_init(noxtls_rc4_context_t *ctx, const uint8_t *key, uint32_t key_len);
```

Initialize RC4 context with the given key.

**Parameters:**

- `ctx` — [noxtls_rc4_context_t](#noxtls_rc4_context_t) to initialize
- `key` — Key bytes (1–256 bytes)
- `key_len` — Key length in bytes (1–256)

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) or [NOXTLS_RETURN_FAILED](/docs/api/return_codes) on invalid arguments

### `noxtls_rc4_process`

```c
noxtls_return_t noxtls_rc4_process(noxtls_rc4_context_t *ctx, const uint8_t *input, uint8_t *output, uint32_t input_len);
```

Encrypt or decrypt data using RC4. As a stream cipher, encryption and decryption are identical (XOR with keystream).

**Parameters:**

- `ctx` — [noxtls_rc4_context_t](#noxtls_rc4_context_t) (from [noxtls_rc4_init](#noxtls_rc4_init))
- `input` — Input data (plaintext or ciphertext)
- `output` — Output buffer (must be at least input_len bytes)
- `input_len` — Length of input in bytes

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success

### `noxtls_rc4_encrypt`

```c
noxtls_return_t noxtls_rc4_encrypt(const uint8_t *key, uint32_t key_len, const uint8_t *input, uint32_t input_len, uint8_t *output);
```

Encrypt data using RC4 (convenience function).

**Parameters:**

- `key` — Key bytes
- `key_len` — Key length (1–256)
- `input` — Plaintext
- `input_len` — Length of plaintext
- `output` — Output buffer for ciphertext (at least input_len bytes)

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success

### `noxtls_rc4_decrypt`

```c
noxtls_return_t noxtls_rc4_decrypt(const uint8_t *key, uint32_t key_len, const uint8_t *input, uint32_t input_len, uint8_t *output);
```

Decrypt data using RC4 (convenience function). Identical to encryption for this stream cipher.

**Parameters:**

- `key` — Key bytes
- `key_len` — Key length (1–256)
- `input` — Ciphertext
- `input_len` — Length of ciphertext
- `output` — Output buffer for plaintext (at least input_len bytes)

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success

### `noxtls_rc4_self_test`

```c
noxtls_return_t noxtls_rc4_self_test(void);
```

Self-test using RFC 6229 test vector (40-bit key).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) if all tests pass
