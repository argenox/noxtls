---
sidebar_position: 24
title: RIPEMD-160
description: "NoxTLS RIPEMD-160 C API reference for embedded TLS, DTLS, and cryptography."
---

# RIPEMD-160

## API

### `noxtls_ripemd160_init`

```c
noxtls_return_t noxtls_ripemd160_init(noxtls_sha_ctx_t * ctx);
```

Initialize RIPEMD-160 hashing (ISO/IEC 10118-3).

**Parameters:**

- `ctx` — [noxtls_sha_ctx_t](/docs/api/hash#noxtls_sha_ctx_t) to initialize for RIPEMD-160; must not be NULL

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) if ctx is NULL.

### `noxtls_ripemd160_update`

```c
noxtls_return_t noxtls_ripemd160_update(noxtls_sha_ctx_t * ctx, uint8_t * data, uint32_t len);
```

Feed data into the RIPEMD-160 hash.

**Parameters:**

- `ctx` — [noxtls_sha_ctx_t](/docs/api/hash#noxtls_sha_ctx_t) (from [noxtls_ripemd160_init](#noxtls_ripemd160_init))
- `data` — Input data; may be NULL only if len is 0
- `len` — Number of bytes to hash.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) if ctx is NULL or data is NULL with len non-zero.

### `noxtls_ripemd160_finish`

```c
noxtls_return_t noxtls_ripemd160_finish(noxtls_sha_ctx_t * ctx, uint8_t * hash);
```

Finalize RIPEMD-160 and write the 20-byte digest.

**Parameters:**

- `ctx` — [noxtls_sha_ctx_t](/docs/api/hash#noxtls_sha_ctx_t) (from [noxtls_ripemd160_init](#noxtls_ripemd160_init))
- `hash` — Output buffer; must hold at least 20 bytes (HASH_RIPEMD160_OUT_LEN)

**Returns:** NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx or hash is NULL.

### `noxtls_ripemd160_verify`

```c
noxtls_return_t noxtls_ripemd160_verify(uint8_t * data, uint32_t len, uint8_t * expected);
```

Compute RIPEMD-160 of data and compare to expected digest.

**Parameters:**

- `data` — Input data to hash; may be NULL only if len is 0.
- `len` — Number of bytes to hash.
- `expected` — Expected 20-byte RIPEMD-160 digest for comparison.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) if digest matches, [NOXTLS_RETURN_FAILED](/docs/api/return_codes) otherwise or on error.

