---
sidebar_position: 17
title: "MD4"
---

# MD4

:::warning

MD4 is long broken and should not be used. It is included for backwards compatibility with legacy systems

:::


MD4 is a 128-bit cryptographic hash (RFC 1320). It is **cryptographically broken** and should not be used for security-sensitive applications; prefer SHA-256, SHA-3, or BLAKE2. This module is provided for compatibility with legacy systems only.

##What is MD4?

MD4 is a cryptographic hash function designed by Ron Rivest in 1990. It produces a 128-bit (16-byte) hash value from input data of arbitrary length.

**Design Goals:**
- Very fast in software
- Simple to implement
- Suitable for 32-bit processors

**How MD4 Works:**
- Processes input in 512-bit message blocks
- Uses 3 rounds of nonlinear functions
- Operates on 32-bit words with addition, rotation, and XOR operations

MD4 was one of the earliest widely-adopted hash functions and influenced later designs such as MD5 and the SHA-1 family.

MD4 is now considered **cryptographically obsolete** and should not be used as it has trivial collision attacks.
It is included in the NoxTLS to maintain compatibility with protocls which may still use it.

You should instead use SHA-256 / SHA-384 or better

## API

### `noxtls_md4_set_debug`

```c
void noxtls_md4_set_debug(uint8_t lvl);
```

Sets Module Debug level

**Parameters:**

- `lvl` — is the debug level

### `noxtls_md4_init`

```c
noxtls_return_t noxtls_md4_init(noxtls_sha_ctx_t * ctx);
```

Initialize the MD4 Context

**Parameters:**

- `ctx` — [noxtls_sha_ctx_t](/docs/api/hash#noxtls_sha_ctx_t) to initialize for MD4

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_md4_round`

```c
noxtls_return_t noxtls_md4_round(noxtls_sha_ctx_t * ctx, const uint8_t * input);
```

Performs an MD4 round

**Parameters:**

- `ctx` — [noxtls_sha_ctx_t](/docs/api/hash#noxtls_sha_ctx_t) (from [noxtls_md4_init](#noxtls_md4_init))
- `input` — 512-bit (64-byte) block to process

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, or another error code otherwise

### `noxtls_md4_finish`

```c
noxtls_return_t noxtls_md4_finish(noxtls_sha_ctx_t * ctx, uint8_t * hash);
```

Finish MD4 operation

**Parameters:**

- `ctx` — [noxtls_sha_ctx_t](/docs/api/hash#noxtls_sha_ctx_t) (from [noxtls_md4_init](#noxtls_md4_init))
- `hash` — Output buffer for the 16-byte MD4 digest

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, or another error code otherwise

### `noxtls_md4_verify`

```c
noxtls_return_t noxtls_md4_verify(const uint8_t * data, uint32_t len, const uint8_t * expected);
```

Takes data and verifies it matches a MD4 Digest

**Parameters:**

- `data` — is the input data
- `len` — is the length of the input data
- `expected` — is the expected MD4 digest

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, or another error code otherwise

