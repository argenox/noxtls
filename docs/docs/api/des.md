---
sidebar_position: 24
title: "DES / 3DES"
---

# DES / 3DES

DES and 3DES are legacy block ciphers with 8-byte block size. 3DES (EDE) is stronger than single DES but still legacy and slower than modern ciphers.

- **DES**: 56-bit effective key (not recommended for new systems).
- **3DES (2-key/3-key)**: 112-bit or 168-bit effective key, still considered legacy.

Use these only for interoperability with existing protocols or systems. Prefer AES or ChaCha20-Poly1305 for new designs.

## API

### `noxtls_des_encrypt_block`

```c
noxtls_return_t noxtls_des_encrypt_block(const uint8_t *key, const uint8_t *data, uint8_t *output);
```

Encrypt a single 8-byte block with DES.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).

### `noxtls_des_decrypt_block`

```c
noxtls_return_t noxtls_des_decrypt_block(const uint8_t *key, const uint8_t *data, uint8_t *output);
```

Decrypt a single 8-byte block with DES.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).

### `noxtls_des3_encrypt_block`

```c
noxtls_return_t noxtls_des3_encrypt_block(const uint8_t *key, uint32_t key_len, const uint8_t *data, uint8_t *output);
```

Encrypt a single 8-byte block with 3DES (EDE). `key_len` is 16 (2-key) or 24 (3-key).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).

### `noxtls_des3_decrypt_block`

```c
noxtls_return_t noxtls_des3_decrypt_block(const uint8_t *key, uint32_t key_len, const uint8_t *data, uint8_t *output);
```

Decrypt a single 8-byte block with 3DES (DED). `key_len` is 16 (2-key) or 24 (3-key).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).

### `noxtls_des_encrypt_cbc`

```c
noxtls_return_t noxtls_des_encrypt_cbc(const uint8_t *key, const uint8_t *data, uint32_t data_len, const uint8_t *iv, uint8_t *output);
```

DES CBC encryption. `data_len` must be a multiple of 8. `iv` is 8 bytes.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).

### `noxtls_des_decrypt_cbc`

```c
noxtls_return_t noxtls_des_decrypt_cbc(const uint8_t *key, const uint8_t *data, uint32_t data_len, const uint8_t *iv, uint8_t *output);
```

DES CBC decryption. `data_len` must be a multiple of 8. `iv` is 8 bytes.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).

### `des3_encrypt_cbc`

```c
noxtls_return_t des3_encrypt_cbc(const uint8_t *key, uint32_t key_len, const uint8_t *data, uint32_t data_len, const uint8_t *iv, uint8_t *output);
```

3DES CBC encryption. `key_len` is 16 or 24. `data_len` must be multiple of 8. `iv` is 8 bytes.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).

### `des3_decrypt_cbc`

```c
noxtls_return_t des3_decrypt_cbc(const uint8_t *key, uint32_t key_len, const uint8_t *data, uint32_t data_len, const uint8_t *iv, uint8_t *output);
```

3DES CBC decryption. `key_len` is 16 or 24. `data_len` must be multiple of 8. `iv` is 8 bytes.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).

### `noxtls_des_self_test`

```c
noxtls_return_t noxtls_des_self_test(void);
```

Run DES/3DES known-answer self-tests.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) if tests pass; otherwise [NOXTLS_RETURN_FAILED](/docs/api/return_codes).

