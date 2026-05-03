### When to use

- **Stream cipher encryption** when you need confidentiality for arbitrary-length data without padding (e.g. custom protocols, compatibility with ChaCha20-based designs).
- **Software-heavy or constrained environments** where AES hardware acceleration is not available; ChaCha20 is typically fast in software.
- **When you need a PRNG-like keystream** that can be generated from (key, nonce, counter) and XORed with plaintext.

### What to be careful of

- **Nonce must never repeat.** Reusing (key, nonce) for two messages allows an attacker to recover plaintext. Use a 12-byte nonce (96 bits) and ensure uniqueness (e.g. counter or random with limited use per key).
- **No authentication.** ChaCha20 alone does not detect tampering. For authenticated encryption, use **ChaCha20-Poly1305** (AEAD) instead.
- **Counter.** The counter is 64-bit; do not encrypt more than 2^64 bytes per (key, nonce). For very long streams, segment with different nonces.

### Practical deployment

- Prefer **ChaCha20-Poly1305** for most use cases so you get authentication in one API. Use raw ChaCha20 only when you are building a custom AEAD or need only confidentiality and will add a MAC separately.
- If using raw ChaCha20: (1) use a unique 12-byte nonce per encryption; (2) combine with a MAC (e.g. Encrypt-then-MAC with Poly1305 or HMAC-SHA256) and verify before decrypting; (3) limit the amount of data per (key, nonce) to stay within counter limits.
