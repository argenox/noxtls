### When to use

- **Streaming or arbitrary-length data** where you need confidentiality without padding (e.g. disk encryption, some protocols).
- **Parallel or random access:** CTR mode allows encrypting/decrypting any block without processing previous blocks, which can help performance and random-access scenarios.

### What to be careful of

- **Nonce/IV must never repeat.** Reusing the same (key, nonce/IV) for two messages is catastrophic: an attacker can XOR the two ciphertexts and recover plaintext. Use a unique nonce per encryption (e.g. counter, or random with enough bits that collision is negligible).
- **No authentication.** CTR does not detect tampering. Flipping bits in ciphertext flips the same bits in plaintext. Always use an AEAD (e.g. AES-GCM) or a separate MAC (Encrypt-then-MAC) for authenticated encryption.
- **Counter overflow.** The IV/nonce is typically 16 bytes; the top bytes are often used as a block counter. Ensure the counter never wraps for a single key (do not encrypt more than 2^32 blocks per key/nonce if the counter is 32 bits).

### Practical deployment

- Prefer **AES-GCM** or **ChaCha20-Poly1305** for most use cases; they provide authentication and avoid nonce-reuse pitfalls in a single API.
- If using raw CTR: (1) use a 96- or 128-bit nonce and a counter that never repeats; (2) combine with a MAC (e.g. Encrypt-then-MAC with HMAC-SHA256) and verify before decrypting; (3) enforce a maximum message length per (key, nonce) to prevent counter wrap.
- Good for disk or storage encryption where the “sector index” is the nonce and each sector is encrypted once.
