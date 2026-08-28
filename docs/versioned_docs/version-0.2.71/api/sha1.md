---
sidebar_position: 19
title: SHA-1
description: "NoxTLS SHA-1 C API reference for embedded TLS, DTLS, and cryptography."
---

# SHA-1

::::::warning

SHA-1 is no longer recommended due to significant cryptographic weaknesses. It is vulnerable to practical collision and chosen-prefix attacks, allowing attackers to create different inputs with the same hash. This makes SHA-1 unsuitable for security-sensitive applications such as digital signatures, TLS certificates, or password storage. SHA-1 should only be used for legacy compatibility and never for new designs or where security is critical.

Recommended alternatives: [SHA-256](./sha256) or [SHA-3](./sha3)


:::

## API

### `noxtls_sha1_finish`

```c
noxtls_return_t noxtls_sha1_finish(noxtls_sha_ctx_t * ctx, uint8_t * hash);
```

Finish SHA-1 operation

**Parameters:**

- `ctx` — [noxtls_sha_ctx_t](/docs/api/hash#noxtls_sha_ctx_t) (initialized for SHA-1)
- `hash` — Output buffer for the 20-byte SHA-1 digest

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, or another error code otherwise

### `noxtls_sha1_verify`

```c
noxtls_return_t noxtls_sha1_verify(const uint8_t * data, uint32_t len, const uint8_t * expected);
```

Takes data and verifies it matches a SHA1 Digest

**Parameters:**

- `data` — is the data to hash
- `len` — is the length of the data
- `expected` — is the expected SHA1 digest

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, or another error code otherwise

