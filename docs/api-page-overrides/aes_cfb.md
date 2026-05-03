### When to use

- **Streaming encryption** with arbitrary-length data when you need a mode that uses the block cipher in a feedback style (e.g. legacy compatibility, some protocols).
- **Situations where CTR is not available** but you need non-padded encryption.

### What to be careful of

- **IV must be unique.** As with CTR, reusing (key, IV) with different plaintexts can leak information. Use a random or otherwise unique IV per encryption.
- **No authentication.** CFB does not detect tampering. Use an AEAD or Encrypt-then-MAC if you need integrity.
- **Sequential.** Decryption is sequential; you cannot skip to an arbitrary block without processing previous blocks. For random access, CTR is usually preferred.
- **Error propagation.** In some variants, a bit error in ciphertext can affect subsequent blocks; implementors should be aware of the variant in use.

### Practical deployment

- For new designs, prefer **AES-GCM**, **AES-CTR** (with a MAC), or **ChaCha20-Poly1305**. Use CFB mainly for interoperability with existing systems.
- If you use CFB: (1) generate a random 16-byte IV per encryption; (2) add authentication (e.g. Encrypt-then-MAC) and verify before decrypting; (3) document whether you use CFB-1, CFB-8, or CFB-128 and stick to it.
