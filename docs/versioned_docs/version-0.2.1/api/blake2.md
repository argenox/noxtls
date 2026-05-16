---
sidebar_position: 23
title: "BLAKE2"
---

# BLAKE2

## Types

### noxtls_blake2_ctx_t

Opaque context for incremental BLAKE2s or BLAKE2b hashing. Used by [noxtls_blake2s_256_init](#noxtls_blake2s_256_init) / [noxtls_blake2b_512_init](#noxtls_blake2b_512_init), [noxtls_blake2_update](#noxtls_blake2_update), [noxtls_blake2_finish](#noxtls_blake2_finish). Allocate and pass to the appropriate init; do not access fields directly.

## API

### `noxtls_blake2s_256_init`

```c
noxtls_return_t noxtls_blake2s_256_init(noxtls_blake2_ctx_t * ctx);
```

Initialize BLAKE2s for a 256-bit (32-byte) digest (RFC 7693).

**Parameters:**

- `ctx` — [noxtls_blake2_ctx_t](#noxtls_blake2_ctx_t) to initialize; must not be NULL

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) if ctx is NULL.

### `noxtls_blake2b_512_init`

```c
noxtls_return_t noxtls_blake2b_512_init(noxtls_blake2_ctx_t * ctx);
```

Initialize BLAKE2b for a 512-bit (64-byte) digest (RFC 7693).

**Parameters:**

- `ctx` — [noxtls_blake2_ctx_t](#noxtls_blake2_ctx_t) to initialize; must not be NULL

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) if ctx is NULL.

### `noxtls_blake2_update`

```c
noxtls_return_t noxtls_blake2_update(noxtls_blake2_ctx_t * ctx, const uint8_t * data, uint32_t len);
```

Feed data into the BLAKE2 (BLAKE2s or BLAKE2b) hash.

**Parameters:**

- `ctx` — [noxtls_blake2_ctx_t](#noxtls_blake2_ctx_t) (from [noxtls_blake2s_256_init](#noxtls_blake2s_256_init) or [noxtls_blake2b_512_init](#noxtls_blake2b_512_init))
- `data` — Input data; may be NULL only if len is 0
- `len` — Number of bytes to hash.

**Returns:** NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL or data is NULL with len non-zero.

### `noxtls_blake2_finish`

```c
noxtls_return_t noxtls_blake2_finish(noxtls_blake2_ctx_t * ctx, uint8_t * hash);
```

Finalize BLAKE2 and write the digest.

**Parameters:**

- `ctx` — [noxtls_blake2_ctx_t](#noxtls_blake2_ctx_t) (from [noxtls_blake2s_256_init](#noxtls_blake2s_256_init) or [noxtls_blake2b_512_init](#noxtls_blake2b_512_init))
- `hash` — Output buffer; must hold at least 32 bytes for BLAKE2s-256 or 64 bytes for BLAKE2b-512

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) if ctx or hash is NULL.

