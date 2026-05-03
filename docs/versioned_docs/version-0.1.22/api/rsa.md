---
sidebar_position: 27
title: "RSA"
---

# RSA

RSA key generation, encryption, decryption, and signatures.

## Types

### rsa_key_t

RSA key pair (public and private components). Initialized with [noxtls_rsa_key_init](#noxtls_rsa_key_init), generated with [noxtls_rsa_key_generate](#noxtls_rsa_key_generate), freed with [noxtls_rsa_key_free](#noxtls_rsa_key_free).

### rsa_key_size_t

RSA key size (e.g. 2048, 4096 bits). Used when initializing or generating an [rsa_key_t](#rsa_key_t).

## API

### `noxtls_rsa_key_init`

```c
noxtls_return_t noxtls_rsa_key_init(rsa_key_t *key, rsa_key_size_t key_size);
```

Initialize RSA key structure. `key` is [rsa_key_t](#rsa_key_t); `key_size` is [rsa_key_size_t](#rsa_key_size_t).

### `noxtls_rsa_key_generate`

```c
noxtls_return_t noxtls_rsa_key_generate(rsa_key_t *key, rsa_key_size_t key_size);
```

Generate RSA key pair. `key` is [rsa_key_t](#rsa_key_t); `key_size` is [rsa_key_size_t](#rsa_key_size_t).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_rsa_key_free`

```c
noxtls_return_t noxtls_rsa_key_free(rsa_key_t *key);
```

Free RSA key structure. `key` is [rsa_key_t](#rsa_key_t).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_rsa_encrypt`

```c
noxtls_return_t noxtls_rsa_encrypt(const rsa_key_t *key, const uint8_t *plaintext, uint32_t plaintext_len, uint8_t *ciphertext, uint32_t *ciphertext_len);
```

RSA Encryption. `key` is [rsa_key_t](#rsa_key_t).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_rsa_decrypt`

```c
noxtls_return_t noxtls_rsa_decrypt(const rsa_key_t *key, const uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *plaintext, uint32_t *plaintext_len);
```

RSA Decryption. `key` is [rsa_key_t](#rsa_key_t).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_rsa_decrypt_crt_only`

```c
noxtls_return_t noxtls_rsa_decrypt_crt_only(const rsa_key_t *key, const uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *plaintext, uint32_t *plaintext_len);
```

RSA decrypt using CRT path only (for unit testing).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_rsa_sign`

```c
noxtls_return_t noxtls_rsa_sign(const rsa_key_t *key, const uint8_t *message, uint32_t message_len, uint8_t *signature, uint32_t *signature_len, noxtls_hash_algos_t hash_algo);
```

RSA Signature Generation. `key` is [rsa_key_t](#rsa_key_t); `hash_algo` is [noxtls_hash_algos_t](/docs/api/hash#noxtls_hash_algos_t).

### `noxtls_rsa_verify`

```c
noxtls_return_t noxtls_rsa_verify(const rsa_key_t *key, const uint8_t *message, uint32_t message_len, const uint8_t *signature, uint32_t signature_len, noxtls_hash_algos_t hash_algo);
```

RSA Signature Verification. `key` is [rsa_key_t](#rsa_key_t); `hash_algo` is [noxtls_hash_algos_t](/docs/api/hash#noxtls_hash_algos_t).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.
