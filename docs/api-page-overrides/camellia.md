### When to use

- **Standards compliance** when the protocol or deployment requires Camellia (e.g. TLS Camellia cipher suites, Japanese/European use). Camellia is a 128-bit block cipher with 128-, 192-, and 256-bit keys, with security and structure similar to AES.

### What to be careful of

- **Use a mode, not raw blocks.** Camellia is a block cipher; use it in a secure mode (CBC, CTR, GCM if available) with proper IV/nonce and authentication.
- **Key and IV management** follow the same rules as for AES in the chosen mode (unique IV, no nonce reuse, etc.).

### Practical deployment

- Prefer **AES** for new designs unless Camellia is explicitly required. When Camellia is required, apply the same mode and key/IV practices as for AES (see [AES CBC](/docs/api/aes_cbc), [AES GCM](/docs/api/aes_gcm), etc.).
