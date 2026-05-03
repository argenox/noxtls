### When to use

- **Authenticated encryption (AEAD)** for most new applications: TLS 1.3, IPsec, storage encryption, APIs. AES-GCM provides both confidentiality and integrity in one primitive.
- **When you need nonce-based encryption** with a 96-bit nonce (12 bytes) and optional associated data (AAD), e.g. for headers or context that must be authenticated but not encrypted.

### What to be careful of

- **Nonce must never repeat.** Reusing the same (key, nonce) for two different messages can allow an attacker to recover the authentication key and forge ciphertexts. Use a counter or random 96-bit nonce; if random, ensure collision probability is negligible (e.g. limit number of encryptions per key).
- **Tag verification.** Always verify the tag in constant time before using decrypted data. If verification fails, do not expose any part of the plaintext or error details that could aid an attacker.
- **AAD.** Use AAD for any metadata that must be bound to the ciphertext (e.g. length, protocol version). AAD is not encrypted but is authenticated.

### Practical deployment

- **Default choice** for new symmetric encryption when AES is available: use a 256-bit key, 12-byte random or counter-based nonce, and 16-byte tag; include any context in AAD.
- **Key and nonce management:** Rotate keys before reaching the recommended encryption limit (e.g. 2^32 messages per key with 96-bit random nonces, or follow NIST/standard guidance). Never reuse a nonce under the same key.
- **Hardware support:** On platforms with AES-NI and CLMUL, GCM is fast. On very constrained or non-AES-NI systems, ChaCha20-Poly1305 can be a simpler or faster alternative.
