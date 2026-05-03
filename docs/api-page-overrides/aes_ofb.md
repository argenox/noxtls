### When to use

- **Streaming encryption** where you need a feedback-based mode (e.g. legacy or protocol compatibility). OFB turns the block cipher into a keystream generator; the keystream is then XORed with the plaintext.

### What to be careful of

- **IV must be unique.** Reusing (key, IV) for two messages allows an attacker to recover plaintext by XORing ciphertexts. Use a unique IV per encryption.
- **No authentication.** OFB does not detect tampering. Add an AEAD or Encrypt-then-MAC if integrity matters.
- **Sequential.** Keystream is generated sequentially; no random access. Prefer CTR if you need random access or simpler semantics.
- **Rarely preferred.** CTR is more common and often better supported; use OFB only when required by a spec or legacy system.

### Practical deployment

- Prefer **AES-GCM**, **AES-CTR** (with MAC), or **ChaCha20-Poly1305** for new designs. Use OFB only for compatibility.
- If you use OFB: (1) use a unique 16-byte IV per encryption; (2) add authentication (Encrypt-then-MAC) and verify before decrypting; (3) document the mode clearly for maintainers.
