---
sidebar_position: 17
title: "ARIA (shared)"
---

# ARIA (shared)

ARIA is a **128-bit block cipher** with 128-, 192-, and 256-bit key sizes, standardized in South Korea. Use it in a **mode of operation** for multi-block data; key and IV rules match [AES](/docs/api/aes_cbc) in the same mode.

**Prefer AES** unless ARIA is required by protocol or region. When using ARIA, apply the same mode and IV practices as for AES.

For mode-specific APIs and guidance, use the pages for each mode:

- [**ARIA - ECB**](/docs/api/aria_ecb)
- [**ARIA - CBC**](/docs/api/aria_cbc)
- [**ARIA - CTR**](/docs/api/aria_ctr)
- [**ARIA - CFB**](/docs/api/aria_cfb)
- [**ARIA - OFB**](/docs/api/aria_ofb)

## Streaming API

ARIA supports incremental processing with a context API:

- `noxtls_aria_init()` — configure key, IV, mode, and direction
- `noxtls_aria_update()` — process one or more chunks
- `noxtls_aria_final()` — flush buffered state

Supported streaming modes: `NOXTLS_ARIA_ECB`, `NOXTLS_ARIA_CBC`, `NOXTLS_ARIA_CTR`, `NOXTLS_ARIA_CFB`, `NOXTLS_ARIA_OFB`.

## Types

### noxtls_aria_context_t

Opaque context for incremental ARIA encryption/decryption. Used by [noxtls_aria_init](#noxtls_aria_init), [noxtls_aria_update](#noxtls_aria_update), [noxtls_aria_final](#noxtls_aria_final). Allocate and pass to [noxtls_aria_init](#noxtls_aria_init); do not access fields directly.

### noxtls_aria_type_t

ARIA key size: 128-, 192-, or 256-bit. Determines key length (16, 24, or 32 bytes).

### noxtls_aria_mode_t

ARIA mode: `NOXTLS_ARIA_ECB`, `NOXTLS_ARIA_CBC`, `NOXTLS_ARIA_CTR`, `NOXTLS_ARIA_CFB`, or `NOXTLS_ARIA_OFB`.

### noxtls_aria_operation_t

Direction: encrypt or decrypt.

## API (generic and streaming)

### `noxtls_aria_encrypt_data`

```c
noxtls_return_t noxtls_aria_encrypt_data(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t* iv, uint8_t* output, noxtls_aria_type_t type, noxtls_aria_mode_t mode);
```

One-shot encrypt; `mode` ([noxtls_aria_mode_t](#noxtls_aria_mode_t)) selects ECB, CBC, CTR, CFB, or OFB. See the mode pages for IV requirements. `type` is [noxtls_aria_type_t](#noxtls_aria_type_t).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_INVALID_MODE](/docs/api/return_codes) for unsupported mode.

### `noxtls_aria_decrypt_data`

```c
noxtls_return_t noxtls_aria_decrypt_data(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t* iv, uint8_t* output, noxtls_aria_type_t type, noxtls_aria_mode_t mode);
```

One-shot decrypt. Use the same IV that was used for encryption. `type` is [noxtls_aria_type_t](#noxtls_aria_type_t), `mode` is [noxtls_aria_mode_t](#noxtls_aria_mode_t).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_aria_self_test`

```c
noxtls_return_t noxtls_aria_self_test(void);
```

Built-in self-test.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_aria_init`

```c
noxtls_return_t noxtls_aria_init(noxtls_aria_context_t *ctx, const uint8_t *key, const uint8_t *iv, noxtls_aria_type_t type, noxtls_aria_mode_t mode, noxtls_aria_operation_t op);
```

Initialize ARIA streaming context. `ctx` is an [noxtls_aria_context_t](#noxtls_aria_context_t); `type` is [noxtls_aria_type_t](#noxtls_aria_type_t); `mode` is [noxtls_aria_mode_t](#noxtls_aria_mode_t); `op` is [noxtls_aria_operation_t](#noxtls_aria_operation_t).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; [NOXTLS_RETURN_NULL](/docs/api/return_codes), [NOXTLS_RETURN_INVALID_KEY_SIZE](/docs/api/return_codes), [NOXTLS_RETURN_INVALID_PARAM](/docs/api/return_codes), or [NOXTLS_RETURN_INVALID_MODE](/docs/api/return_codes) on error.

### `noxtls_aria_update`

```c
noxtls_return_t noxtls_aria_update(noxtls_aria_context_t *ctx, const uint8_t *input, uint32_t input_len, uint8_t *output, uint32_t *output_len);
```

Process the next chunk. `ctx` is an [noxtls_aria_context_t](#noxtls_aria_context_t) from [noxtls_aria_init](#noxtls_aria_init).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_aria_final`

```c
noxtls_return_t noxtls_aria_final(noxtls_aria_context_t *ctx, uint8_t *output, uint32_t *output_len);
```

Finalize streaming operation and flush buffered data. `ctx` is an [noxtls_aria_context_t](#noxtls_aria_context_t) from [noxtls_aria_init](#noxtls_aria_init).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.
