### When to use

- **Standards compliance** when the protocol or region requires ARIA (e.g. South Korean government, some industry standards). ARIA is a block cipher similar to AES in structure and key sizes (128, 192, 256 bits).

### What to be careful of

- **Use a mode, not raw blocks.** ARIA is a block cipher; use it in a secure mode (e.g. CBC, CTR, GCM if available) with proper IV/nonce and authentication. Do not use raw block encryption for multi-block data.
- **Key and IV management** follow the same rules as for AES in the chosen mode (unique IV per encryption, no nonce reuse in CTR/GCM, etc.).

### Practical deployment

- Prefer **AES** for new designs unless ARIA is explicitly required. When ARIA is required, use the same mode and key/IV practices as you would for AES (see [AES CBC](/docs/api/aes_cbc), [AES GCM](/docs/api/aes_gcm), etc.).
