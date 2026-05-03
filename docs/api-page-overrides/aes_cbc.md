### When to use

- **Bulk encryption** where you need confidentiality and can use an IV per message or per session (e.g. TLS 1.2 record layer, legacy file encryption).
- **Sequential or single-shot processing** where you encrypt/decrypt in one go and can provide a random or counter-based IV.

### What to be careful of

- **IV must be unique per encryption.** Reusing the same (key, IV) with different plaintexts can leak information. Use a cryptographically random IV (e.g. 16 bytes from a secure RNG) or a counter/sector ID when the construction allows it.
- **No built-in authentication.** CBC does not detect tampering. Prefer an AEAD (e.g. AES-GCM, AES-CCM) or use Encrypt-then-MAC with a strong MAC (e.g. HMAC-SHA256) and verify before decrypting.
- **Padding.** Plaintext length must be a multiple of 16 bytes. Use a well-defined padding scheme (e.g. PKCS#7) and validate padding securely on decrypt to avoid padding-oracle attacks.
- **Decryption order.** Implementations often decrypt in order; ensure you do not use decrypted data before verifying a MAC if you add one.

### Practical deployment

- Prefer **AES-GCM** or **AES-CCM** for new designs so you get authentication and avoid padding and many IV pitfalls.
- If you must use CBC: (1) generate a random IV for each encryption and prepend or transmit it; (2) use **Encrypt-then-MAC** (encrypt, then MAC ciphertext + IV, verify MAC before decrypting); (3) use constant-time padding validation.
- Do not use a zero or fixed IV; do not use a counter as IV unless the protocol explicitly defines it (e.g. TLS 1.2 record IV derivation).
