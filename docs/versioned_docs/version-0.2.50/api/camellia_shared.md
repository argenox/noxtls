---
sidebar_position: 24
title: Camellia (shared)
description: "NoxTLS Camellia (shared) C API reference for embedded TLS, DTLS, and cryptography."
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

- `noxtls_camellia_init()` — configure key, IV, mode, and direction
- `noxtls_camellia_update()` — process one or more chunks
- `noxtls_camellia_final()` — flush buffered state

Supported streaming modes: `NOXTLS_CAMELLIA_ECB`, `NOXTLS_CAMELLIA_CBC`, `NOXTLS_CAMELLIA_CTR`, `NOXTLS_CAMELLIA_CFB`, `NOXTLS_CAMELLIA_OFB`.

## Types

### noxtls_camellia_context_t

Opaque context for incremental Camellia encryption/decryption. Used by [noxtls_camellia_init](#noxtls_camellia_init), [noxtls_camellia_update](#noxtls_camellia_update), [noxtls_camellia_final](#noxtls_camellia_final). Allocate and pass to [noxtls_camellia_init](#noxtls_camellia_init); do not access fields directly.

### noxtls_camellia_type_t

Camellia key size: 128-, 192-, or 256-bit. Determines key length (16, 24, or 32 bytes).

### noxtls_camellia_mode_t

Camellia mode: `NOXTLS_CAMELLIA_ECB`, `NOXTLS_CAMELLIA_CBC`, `NOXTLS_CAMELLIA_CTR`, `NOXTLS_CAMELLIA_CFB`, or `NOXTLS_CAMELLIA_OFB`.

### noxtls_camellia_operation_t

Direction: encrypt or decrypt.

## API (generic and streaming)

### `noxtls_camellia_encrypt_data`

```c
noxtls_return_t noxtls_camellia_encrypt_data(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t* iv, uint8_t* output, noxtls_camellia_type_t type, noxtls_camellia_mode_t mode);
```

One-shot encrypt; `mode` ([noxtls_camellia_mode_t](#noxtls_camellia_mode_t)) selects ECB, CBC, CTR, CFB, or OFB. See the mode pages for IV requirements. `type` is [noxtls_camellia_type_t](#noxtls_camellia_type_t).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_camellia_decrypt_data`

```c
noxtls_return_t noxtls_camellia_decrypt_data(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t* iv, uint8_t* output, noxtls_camellia_type_t type, noxtls_camellia_mode_t mode);
```

One-shot decrypt. Use the same IV that was used for encryption. `type` is [noxtls_camellia_type_t](#noxtls_camellia_type_t), `mode` is [noxtls_camellia_mode_t](#noxtls_camellia_mode_t).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_camellia_self_test`

```c
noxtls_return_t noxtls_camellia_self_test(void);
```

Built-in self-test (RFC 3713 Appendix A vectors).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_camellia_init`

```c
noxtls_return_t noxtls_camellia_init(noxtls_camellia_context_t *ctx, const uint8_t *key, const uint8_t *iv, noxtls_camellia_type_t type, noxtls_camellia_mode_t mode, noxtls_camellia_operation_t op);
```

Initialize Camellia streaming context. `ctx` is a [noxtls_camellia_context_t](#noxtls_camellia_context_t); `type` is [noxtls_camellia_type_t](#noxtls_camellia_type_t); `mode` is [noxtls_camellia_mode_t](#noxtls_camellia_mode_t); `op` is [noxtls_camellia_operation_t](#noxtls_camellia_operation_t).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_camellia_update`

```c
noxtls_return_t noxtls_camellia_update(noxtls_camellia_context_t *ctx, const uint8_t *input, uint32_t input_len, uint8_t *output, uint32_t *output_len);
```

Process the next chunk. `ctx` is a [noxtls_camellia_context_t](#noxtls_camellia_context_t) from [noxtls_camellia_init](#noxtls_camellia_init).

### `noxtls_camellia_final`

```c
noxtls_return_t noxtls_camellia_final(noxtls_camellia_context_t *ctx, uint8_t *output, uint32_t *output_len);
```

Finalize streaming operation and flush buffered data. `ctx` is a [noxtls_camellia_context_t](#noxtls_camellia_context_t) from [noxtls_camellia_init](#noxtls_camellia_init).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.
