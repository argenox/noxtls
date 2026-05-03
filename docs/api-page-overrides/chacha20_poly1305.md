### When to use

- **Authenticated encryption (AEAD)** for most new designs, especially when AES hardware is not available or you want to avoid timing side channels. ChaCha20-Poly1305 is fast in software and is used in TLS 1.3, Signal, and many modern protocols.
- **When you need a single primitive** that provides both confidentiality and integrity with a 256-bit key, 12-byte nonce, and 16-byte tag.

### What to be careful of

- **Nonce must never repeat.** Reusing (key, nonce) for two different messages can allow forgery and plaintext recovery. Use a counter or random 12-byte nonce; if random, limit the number of encryptions per key so collision probability is negligible.
- **Tag verification.** Always verify the tag in constant time before using decrypted data. On failure, do not leak any information (e.g. do not distinguish “decrypt failed” from “tag mismatch” to external callers).
- **AAD.** Use additional authenticated data (AAD) for any context that must be bound to the ciphertext (e.g. protocol headers, length). AAD is not encrypted but is authenticated.

### Practical deployment

- **Default choice** for AEAD when AES-GCM is not desirable (e.g. no AES-NI, or preference for constant-time software). Use a 256-bit key, 12-byte nonce, and 16-byte tag.
- **Key and nonce management:** Rotate keys before reaching the recommended message limit per key (e.g. 2^32 messages with 96-bit random nonces). Never reuse a nonce under the same key.
- **Interoperability:** ChaCha20-Poly1305 is standardized in RFC 8439; ensure nonce, tag placement, and AAD match the protocol or standard you are implementing.
