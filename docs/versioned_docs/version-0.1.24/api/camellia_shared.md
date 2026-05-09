---
sidebar_position: 24
title: "Camellia (shared)"
---

# Camellia (shared)

Camellia is a **128-bit block cipher** with 128-, 192-, and 256-bit key sizes (NTT/Mitsubishi, ISO/IEC, NESSIE, CRYPTREC). Use it in a **mode of operation** for multi-block data; key and IV rules match [AES](/docs/api/aes_cbc) in the same mode.

**Prefer AES** unless Camellia is required by protocol or deployment. When using Camellia, apply the same mode and IV practices as for AES.

For mode-specific APIs and guidance, use the pages for each mode:

- [**Camellia - ECB**](/docs/api/camellia_ecb)
- [**Camellia - CBC**](/docs/api/camellia_cbc)
- [**Camellia - CTR**](/docs/api/camellia_ctr)
- [**Camellia - CFB**](/docs/api/camellia_cfb)
- [**Camellia - OFB**](/docs/api/camellia_ofb)

## Streaming API

Camellia supports incremental processing with a context API:

- `camellia_init()` — configure key, IV, mode, and direction
- `camellia_update()` — process one or more chunks
- `camellia_final()` — flush buffered state

Supported streaming modes: `CAMELLIA_ECB`, `CAMELLIA_CBC`, `CAMELLIA_CTR`, `CAMELLIA_CFB`, `CAMELLIA_OFB`.

## Types

### camellia_context_t

Opaque context for incremental Camellia encryption/decryption. Used by [camellia_init](#camellia_init), [camellia_update](#camellia_update), [camellia_final](#camellia_final). Allocate and pass to [camellia_init](#camellia_init); do not access fields directly.

### camellia_type_t

Camellia key size: 128-, 192-, or 256-bit. Determines key length (16, 24, or 32 bytes).

### camellia_mode_t

Camellia mode: `CAMELLIA_ECB`, `CAMELLIA_CBC`, `CAMELLIA_CTR`, `CAMELLIA_CFB`, or `CAMELLIA_OFB`.

### camellia_operation_t

Direction: encrypt or decrypt.

## API (generic and streaming)

### `camellia_encrypt_data`

```c
noxtls_return_t camellia_encrypt_data(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t* iv, uint8_t* output, camellia_type_t type, camellia_mode_t mode);
```

One-shot encrypt; `mode` ([camellia_mode_t](#camellia_mode_t)) selects ECB, CBC, CTR, CFB, or OFB. See the mode pages for IV requirements. `type` is [camellia_type_t](#camellia_type_t).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `camellia_decrypt_data`

```c
noxtls_return_t camellia_decrypt_data(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t* iv, uint8_t* output, camellia_type_t type, camellia_mode_t mode);
```

One-shot decrypt. Use the same IV that was used for encryption. `type` is [camellia_type_t](#camellia_type_t), `mode` is [camellia_mode_t](#camellia_mode_t).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `camellia_self_test`

```c
noxtls_return_t camellia_self_test(void);
```

Built-in self-test (RFC 3713 Appendix A vectors).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `camellia_init`

```c
noxtls_return_t camellia_init(camellia_context_t *ctx, const uint8_t *key, const uint8_t *iv, camellia_type_t type, camellia_mode_t mode, camellia_operation_t op);
```

Initialize Camellia streaming context. `ctx` is a [camellia_context_t](#camellia_context_t); `type` is [camellia_type_t](#camellia_type_t); `mode` is [camellia_mode_t](#camellia_mode_t); `op` is [camellia_operation_t](#camellia_operation_t).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `camellia_update`

```c
noxtls_return_t camellia_update(camellia_context_t *ctx, const uint8_t *input, uint32_t input_len, uint8_t *output, uint32_t *output_len);
```

Process the next chunk. `ctx` is a [camellia_context_t](#camellia_context_t) from [camellia_init](#camellia_init).

### `camellia_final`

```c
noxtls_return_t camellia_final(camellia_context_t *ctx, uint8_t *output, uint32_t *output_len);
```

Finalize streaming operation and flush buffered data. `ctx` is a [camellia_context_t](#camellia_context_t) from [camellia_init](#camellia_init).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.
