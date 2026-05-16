---
sidebar_position: 25
title: "Common hash API"
---

# Common hash API

## Types

### noxtls_sha_ctx_t

Opaque context for incremental SHA/MD4/MD5 hashing. Used by [noxtls_sha_init](#noxtls_sha_init), [noxtls_sha_update](#noxtls_sha_update), [noxtls_sha_finish](#noxtls_sha_finish), and by MD4, MD5, SHA-1, SHA-256, RIPEMD-160 APIs. Allocate and pass to init; do not access fields directly.

### noxtls_hash_algos_t

Enumeration of supported hash algorithms (e.g. SHA-224, SHA-256, SHA-384, SHA-512). Used when initializing a [noxtls_sha_ctx_t](#noxtls_sha_ctx_t) for the common SHA API.

## API

### `noxtls_add_padding_length`

```c
void noxtls_add_padding_length(uint8_t * data, uint32_t block_size, uint64_t length, uint8_t length_size);
```

Adds padding length to the data

**Parameters:**

- `data` — is the data to
- `block_size` — is the block size being processed in bytes
- `length` — is the length of the data in bytes
- `length_size` — is the size of length in bytes

### `noxtls_add_padding_length_little`

```c
void noxtls_add_padding_length_little(uint8_t * data, uint32_t block_size, uint64_t length, uint8_t length_size);
```

Adds padding length to the data

**Parameters:**

- `data` — is the data to
- `block_size` — is the block size being processed in bytes
- `length` — is the length of the data in bytes
- `length_size` — is the size of length in bytes

### `noxtls_sha_init`

```c
noxtls_return_t noxtls_sha_init(noxtls_sha_ctx_t * ctx, noxtls_hash_algos_t algo);
```

Initialize SHA

**Parameters:**

- `ctx` — [noxtls_sha_ctx_t](#noxtls_sha_ctx_t) to initialize
- `algo` — [noxtls_hash_algos_t](#noxtls_hash_algos_t) (e.g. SHA-224, SHA-256, SHA-384, SHA-512)

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) if ctx is NULL

### `noxtls_sha_update`

```c
noxtls_return_t noxtls_sha_update(noxtls_sha_ctx_t * ctx, uint8_t * data, uint32_t len);
```

Update SHA

**Parameters:**

- `ctx` — [noxtls_sha_ctx_t](#noxtls_sha_ctx_t) (from [noxtls_sha_init](#noxtls_sha_init))
- `data` — Data to update
- `len` — Length of data to update

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) if ctx is NULL

### `noxtls_sha_finish`

```c
noxtls_return_t noxtls_sha_finish(noxtls_sha_ctx_t * ctx, uint8_t * hash);
```

Finish SHA

**Parameters:**

- `ctx` — [noxtls_sha_ctx_t](#noxtls_sha_ctx_t) (from [noxtls_sha_init](#noxtls_sha_init))
- `hash` — Output buffer for the digest

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) if ctx is NULL

