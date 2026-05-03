### When to use

- **Single-block encryption** where you need to encrypt exactly one 16-byte block (e.g. key wrapping, some legacy protocols).
- **Deterministic encryption** where the same plaintext must always produce the same ciphertext (e.g. searchable encryption with careful design).
- **Testing or debugging** of block-cipher behavior only.

### What to be careful of

- **Do not use for bulk data or multiple blocks.** ECB encrypts each block independently, so identical plaintext blocks produce identical ciphertext blocks. This leaks structure and patterns (e.g. repeated headers, blank areas in images).
- **No authentication.** ECB provides confidentiality only; it does not detect tampering or forgery.
- **No IV.** There is no randomization; same key + same plaintext always yields same ciphertext.

### Practical deployment

- Prefer **AES-GCM**, **AES-CCM**, or **ChaCha20-Poly1305** for general-purpose encryption (authenticated, no pattern leakage).
- If you must use ECB (e.g. compatibility), use it only for a single block or with a higher-level scheme (e.g. NIST key wrapping) that defines safe usage.
- Never use ECB for file or disk encryption, or for any data longer than one block without a standardized construction.
