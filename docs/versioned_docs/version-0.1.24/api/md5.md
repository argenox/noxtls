---
sidebar_position: 18
title: "MD5"
---

# MD5

::::::warning

MD5 is no longer recommended due to serious cryptographic weaknesses. It is vulnerable to practical collision and preimage attacks, making it unsuitable for security-sensitive tasks such as digital signatures, certificate validation, or password hashing. MD5 should only be used for legacy compatibility purposes and never for new designs or where security is a concern.

:::

## API

### `noxtls_md5_init`

```c
noxtls_return_t noxtls_md5_init(noxtls_sha_ctx_t * ctx);
```

Initialize the MD5 Context

**Parameters:**

- `ctx` — [noxtls_sha_ctx_t](/docs/api/hash#noxtls_sha_ctx_t) to initialize for MD5

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_md5_round`

```c
noxtls_return_t noxtls_md5_round(noxtls_sha_ctx_t * ctx, const uint8_t * input);
```

Performs an MD5 round

**Parameters:**

- `ctx` — [noxtls_sha_ctx_t](/docs/api/hash#noxtls_sha_ctx_t) (from [noxtls_md5_init](#noxtls_md5_init))
- `input` — 512-bit (64-byte) block to process

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, or another error code otherwise

### `noxtls_md5_finish`

```c
noxtls_return_t noxtls_md5_finish(noxtls_sha_ctx_t * ctx, uint8_t * hash);
```

Finish MD5 operation

**Parameters:**

- `ctx` — [noxtls_sha_ctx_t](/docs/api/hash#noxtls_sha_ctx_t) (from [noxtls_md5_init](#noxtls_md5_init))
- `hash` — Output buffer for the 16-byte MD5 digest

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, or another error code otherwise

### `noxtls_md5_verify`

```c
noxtls_return_t noxtls_md5_verify(uint8_t * data, uint32_t len, uint8_t * expected);
```

Takes data and verifies it matches a MD5 Digest

**Parameters:**

- `data` — is the input data
- `len` — is the length of the input data
- `expected` — is the expected MD5 digest

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, or another error code otherwise

### `noxtls_md5_set_debug`

```c
void noxtls_md5_set_debug(uint8_t lvl);
```

Sets Module Debug level

**Parameters:**

- `lvl` — is the debug level

