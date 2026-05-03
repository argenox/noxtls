### When to use

- **Authenticated encryption (AEAD)** in constrained or embedded environments (e.g. IEEE 802.11, Zigbee, CoAP). AES-CCM is widely required by standards and is suitable when GCM is not available or when CCM’s structure is preferred.
- **When you need flexible nonce and tag lengths:** CCM supports nonce lengths from 7 to 13 bytes and tag lengths 4, 6, 8, 10, 12, 14, or 16 bytes, which can help match protocol or size constraints.

### What to be careful of

- **Nonce must be unique per encryption.** As with GCM, reusing (key, nonce) is catastrophic. Use a counter or unique value per message.
- **Tag verification.** Verify the tag in constant time before releasing decrypted data. Reject and do not leak information on failure.
- **Message length.** CCM imposes a maximum plaintext length that depends on the nonce length (L = 15 - nonce_len). Ensure your plaintext length is within the limit (e.g. with 12-byte nonce, L=3, max ~2^24 bytes).
- **Slower than GCM.** CCM is sequential and typically slower than GCM on platforms with AES-NI; use it where required by spec or when GCM is not an option.

### Practical deployment

- Use **fixed nonce and tag lengths** for your protocol (e.g. 12-byte nonce, 16-byte tag) and document them. Avoid changing lengths at runtime.
- **Key and nonce:** Never reuse a nonce; rotate keys according to your security policy and standard recommendations.
- Prefer **AES-GCM** for new general-purpose designs when hardware acceleration is available; choose **AES-CCM** when the standard or environment requires it (e.g. IoT, wireless).
