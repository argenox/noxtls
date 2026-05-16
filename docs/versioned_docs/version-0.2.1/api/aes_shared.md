---
sidebar_position: 11
title: "AES (shared)"
---

# AES (shared)

Shared AES types and generic entry points.

For mode-specific APIs and guidance, use the pages for each mode: [AES - ECB](/docs/api/aes_ecb), [AES CBC](/docs/api/aes_cbc), [AES CTR](/docs/api/aes_ctr), [AES CFB](/docs/api/aes_cfb), [AES OFB](/docs/api/aes_ofb), [AES GCM](/docs/api/aes_gcm), [AES CCM](/docs/api/aes_ccm), [AES XTS](/docs/api/aes_xts).

## Streaming API

AES now supports incremental processing with a context object for scenarios where plaintext/ciphertext arrives in chunks.

- Use `noxtls_aes_init()` once with key/IV/mode/direction.
- Call `noxtls_aes_update()` any number of times as data arrives.
- Call `noxtls_aes_final()` once at the end to flush any buffered data.

Supported streaming modes:

- `NOXTLS_AES_ECB`, `NOXTLS_AES_CBC`, `NOXTLS_AES_CTR`, `NOXTLS_AES_CFB`, `NOXTLS_AES_OFB`

Notes:

- `NOXTLS_AES_CTR`, `NOXTLS_AES_CFB`, and `NOXTLS_AES_OFB` behave as stream modes: `noxtls_aes_final()` emits no extra bytes.
- `NOXTLS_AES_ECB` and `NOXTLS_AES_CBC` buffer partial blocks; on encrypt, `noxtls_aes_final()` emits one final block if needed.
- `NOXTLS_AES_GCM` and `NOXTLS_AES_XTS` are currently one-shot APIs in this library (use their dedicated functions).

## Types

### noxtls_aes_context_t

Opaque context for incremental AES encryption/decryption. Used by [noxtls_aes_init](#noxtls_aes_init), [noxtls_aes_update](#noxtls_aes_update), [noxtls_aes_final](#noxtls_aes_final). Allocate and pass to [noxtls_aes_init](#noxtls_aes_init); do not access fields directly.

### noxtls_aes_type_t

AES key size: `NOXTLS_AES_128_BIT`, `NOXTLS_AES_192_BIT`, or `NOXTLS_AES_256_BIT`. Determines key length (16, 24, or 32 bytes).

### noxtls_aes_mode_t

AES mode of operation: `NOXTLS_AES_ECB`, `NOXTLS_AES_CBC`, `NOXTLS_AES_CTR`, `NOXTLS_AES_CFB`, or `NOXTLS_AES_OFB` for streaming; `NOXTLS_AES_GCM` and `NOXTLS_AES_XTS` are one-shot only.

### noxtls_aes_operation_t

Direction: `NOXTLS_AES_OP_ENCRYPT` or `NOXTLS_AES_OP_DECRYPT`.

## API

### `noxtls_aes_init`

```c
noxtls_return_t noxtls_aes_init(noxtls_aes_context_t *ctx,
             const uint8_t *key,
             const uint8_t *iv,
             noxtls_aes_type_t type,
             noxtls_aes_mode_t mode,
             noxtls_aes_operation_t op);
```

Initialize AES streaming context.

**Parameters:**

- `ctx` — [noxtls_aes_context_t](#noxtls_aes_context_t) to initialize
- `key` — AES key (size depends on `type`)
- `iv` — IV/nonce (required for CTR/CFB/OFB, optional for CBC, unused for ECB)
- `type` — [noxtls_aes_type_t](#noxtls_aes_type_t): key size (NOXTLS_AES_128_BIT, NOXTLS_AES_192_BIT, NOXTLS_AES_256_BIT)
- `mode` — [noxtls_aes_mode_t](#noxtls_aes_mode_t): NOXTLS_AES_ECB, NOXTLS_AES_CBC, NOXTLS_AES_CTR, NOXTLS_AES_CFB, or NOXTLS_AES_OFB
- `op` — [noxtls_aes_operation_t](#noxtls_aes_operation_t): NOXTLS_AES_OP_ENCRYPT or NOXTLS_AES_OP_DECRYPT

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; [NOXTLS_RETURN_NULL](/docs/api/return_codes) if ctx or key is NULL; [NOXTLS_RETURN_INVALID_KEY_SIZE](/docs/api/return_codes), [NOXTLS_RETURN_INVALID_PARAM](/docs/api/return_codes), [NOXTLS_RETURN_NOT_SUPPORTED](/docs/api/return_codes), or [NOXTLS_RETURN_INVALID_MODE](/docs/api/return_codes) on error.

### `noxtls_aes_update`

```c
noxtls_return_t noxtls_aes_update(noxtls_aes_context_t *ctx,
               const uint8_t *input,
               uint32_t input_len,
               uint8_t *output,
               uint32_t *output_len);
```

Process the next chunk.

**Parameters:**

- `ctx` — [noxtls_aes_context_t](#noxtls_aes_context_t) (from [noxtls_aes_init](#noxtls_aes_init))
- `input` — input chunk
- `input_len` — input length
- `output` — output buffer
- `output_len` — bytes produced in this call

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_aes_final`

```c
noxtls_return_t noxtls_aes_final(noxtls_aes_context_t *ctx,
              uint8_t *output,
              uint32_t *output_len);
```

Finalize streaming operation and flush buffered data.

**Parameters:**

- `ctx` — [noxtls_aes_context_t](#noxtls_aes_context_t) (from [noxtls_aes_init](#noxtls_aes_init))
- `output` — output buffer for any final bytes
- `output_len` — bytes produced in finalization

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; [NOXTLS_RETURN_NULL](/docs/api/return_codes), [NOXTLS_RETURN_NOT_INITIALIZED](/docs/api/return_codes), [NOXTLS_RETURN_INVALID_BLOCK_SIZE](/docs/api/return_codes), or [NOXTLS_RETURN_INVALID_MODE](/docs/api/return_codes) on error.
