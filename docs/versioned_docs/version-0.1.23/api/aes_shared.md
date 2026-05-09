---
sidebar_position: 11
title: "AES (shared)"
---

# AES (shared)

Shared AES types and generic entry points.

For mode-specific APIs and guidance, use the pages for each mode: [AES - ECB](/docs/api/aes_ecb), [AES CBC](/docs/api/aes_cbc), [AES CTR](/docs/api/aes_ctr), [AES CFB](/docs/api/aes_cfb), [AES OFB](/docs/api/aes_ofb), [AES GCM](/docs/api/aes_gcm), [AES CCM](/docs/api/aes_ccm), [AES XTS](/docs/api/aes_xts).

## Streaming API

AES now supports incremental processing with a context object for scenarios where plaintext/ciphertext arrives in chunks.

- Use `aes_init()` once with key/IV/mode/direction.
- Call `aes_update()` any number of times as data arrives.
- Call `aes_final()` once at the end to flush any buffered data.

Supported streaming modes:

- `AES_ECB`, `AES_CBC`, `AES_CTR`, `AES_CFB`, `AES_OFB`

Notes:

- `AES_CTR`, `AES_CFB`, and `AES_OFB` behave as stream modes: `aes_final()` emits no extra bytes.
- `AES_ECB` and `AES_CBC` buffer partial blocks; on encrypt, `aes_final()` emits one final block if needed.
- `AES_GCM` and `AES_XTS` are currently one-shot APIs in this library (use their dedicated functions).

## Types

### aes_context_t

Opaque context for incremental AES encryption/decryption. Used by [aes_init](#aes_init), [aes_update](#aes_update), [aes_final](#aes_final). Allocate and pass to [aes_init](#aes_init); do not access fields directly.

### aes_type_t

AES key size: `AES_128_BIT`, `AES_192_BIT`, or `AES_256_BIT`. Determines key length (16, 24, or 32 bytes).

### aes_mode_t

AES mode of operation: `AES_ECB`, `AES_CBC`, `AES_CTR`, `AES_CFB`, or `AES_OFB` for streaming; `AES_GCM` and `AES_XTS` are one-shot only.

### aes_operation_t

Direction: `AES_OP_ENCRYPT` or `AES_OP_DECRYPT`.

## API

### `aes_init`

```c
noxtls_return_t aes_init(aes_context_t *ctx,
             const uint8_t *key,
             const uint8_t *iv,
             aes_type_t type,
             aes_mode_t mode,
             aes_operation_t op);
```

Initialize AES streaming context.

**Parameters:**

- `ctx` — [aes_context_t](#aes_context_t) to initialize
- `key` — AES key (size depends on `type`)
- `iv` — IV/nonce (required for CTR/CFB/OFB, optional for CBC, unused for ECB)
- `type` — [aes_type_t](#aes_type_t): key size (AES_128_BIT, AES_192_BIT, AES_256_BIT)
- `mode` — [aes_mode_t](#aes_mode_t): AES_ECB, AES_CBC, AES_CTR, AES_CFB, or AES_OFB
- `op` — [aes_operation_t](#aes_operation_t): AES_OP_ENCRYPT or AES_OP_DECRYPT

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; [NOXTLS_RETURN_NULL](/docs/api/return_codes) if ctx or key is NULL; [NOXTLS_RETURN_INVALID_KEY_SIZE](/docs/api/return_codes), [NOXTLS_RETURN_INVALID_PARAM](/docs/api/return_codes), [NOXTLS_RETURN_NOT_SUPPORTED](/docs/api/return_codes), or [NOXTLS_RETURN_INVALID_MODE](/docs/api/return_codes) on error.

### `aes_update`

```c
noxtls_return_t aes_update(aes_context_t *ctx,
               const uint8_t *input,
               uint32_t input_len,
               uint8_t *output,
               uint32_t *output_len);
```

Process the next chunk.

**Parameters:**

- `ctx` — [aes_context_t](#aes_context_t) (from [aes_init](#aes_init))
- `input` — input chunk
- `input_len` — input length
- `output` — output buffer
- `output_len` — bytes produced in this call

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `aes_final`

```c
noxtls_return_t aes_final(aes_context_t *ctx,
              uint8_t *output,
              uint32_t *output_len);
```

Finalize streaming operation and flush buffered data.

**Parameters:**

- `ctx` — [aes_context_t](#aes_context_t) (from [aes_init](#aes_init))
- `output` — output buffer for any final bytes
- `output_len` — bytes produced in finalization

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; [NOXTLS_RETURN_NULL](/docs/api/return_codes), [NOXTLS_RETURN_NOT_INITIALIZED](/docs/api/return_codes), [NOXTLS_RETURN_INVALID_BLOCK_SIZE](/docs/api/return_codes), or [NOXTLS_RETURN_INVALID_MODE](/docs/api/return_codes) on error.
