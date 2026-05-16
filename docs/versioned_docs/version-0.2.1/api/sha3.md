---
sidebar_position: 22
title: "SHA-3"
---

# SHA-3

## Types

### `noxtls_sha3_ctx_t`

SHA-3 context state used by the init, update, and finish APIs.

## API

### `noxtls_sha3_224_init`

```c
noxtls_return_t noxtls_sha3_224_init(noxtls_sha3_ctx_t * ctx);
```

Initialize SHA3-224

**Parameters:**

- `ctx` — [noxtls_sha3_ctx_t](#noxtls_sha3_ctx_t) to initialize

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) if ctx is NULL

### `noxtls_sha3_256_init`

```c
noxtls_return_t noxtls_sha3_256_init(noxtls_sha3_ctx_t * ctx);
```

Initialize SHA3-256

**Parameters:**

- `ctx` — [noxtls_sha3_ctx_t](#noxtls_sha3_ctx_t) to initialize

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) if ctx is NULL

### `noxtls_sha3_384_init`

```c
noxtls_return_t noxtls_sha3_384_init(noxtls_sha3_ctx_t * ctx);
```

Initialize SHA3-384

**Parameters:**

- `ctx` — [noxtls_sha3_ctx_t](#noxtls_sha3_ctx_t) to initialize

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) if ctx is NULL

### `noxtls_sha3_512_init`

```c
noxtls_return_t noxtls_sha3_512_init(noxtls_sha3_ctx_t * ctx);
```

Initialize SHA3-512

**Parameters:**

- `ctx` — [noxtls_sha3_ctx_t](#noxtls_sha3_ctx_t) to initialize

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) if ctx is NULL

### `noxtls_sha3_update`

```c
noxtls_return_t noxtls_sha3_update(noxtls_sha3_ctx_t * ctx, const uint8_t * data, uint32_t len);
```

Update SHA-3 with new data

**Parameters:**

- `ctx` — [noxtls_sha3_ctx_t](#noxtls_sha3_ctx_t) (from one of the init functions)
- `data` — Data to update SHA-3 with
- `len` — Length of data to update SHA-3 with

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) if ctx is NULL, [NOXTLS_RETURN_FAILED](/docs/api/return_codes) if SHA-3 is finalized

### `noxtls_sha3_finish`

```c
noxtls_return_t noxtls_sha3_finish(noxtls_sha3_ctx_t * ctx, uint8_t * hash);
```

Finalize SHA-3 and produce hash

**Parameters:**

- `ctx` — [noxtls_sha3_ctx_t](#noxtls_sha3_ctx_t) (from one of the init functions)
- `hash` — Output buffer for the digest (28/32/48/64 bytes for 224/256/384/512)

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) if ctx is NULL, [NOXTLS_RETURN_FAILED](/docs/api/return_codes) if SHA-3 is finalized

### `noxtls_sha3_verify`

```c
noxtls_return_t noxtls_sha3_verify(uint8_t * data, uint32_t len, uint8_t * expected, noxtls_hash_algos_t algo);
```

Verify data against expected SHA-3 hash

**Parameters:**

- `data` — Data to verify
- `len` — Length of data to verify
- `expected` — Expected hash
- `algo` — [noxtls_hash_algos_t](/docs/api/hash#noxtls_hash_algos_t) (NOXTLS_SHA3_224, SHA3_256, SHA3_384, or SHA3_512)

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_FAILED](/docs/api/return_codes) if verification fails

### `noxtls_sha3_set_debug`

```c
void noxtls_sha3_set_debug(uint8_t lvl);
```

Sets Module Debug level

**Parameters:**

- `lvl` — Debug level

