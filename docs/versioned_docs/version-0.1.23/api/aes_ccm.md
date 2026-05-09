---
sidebar_position: 9
title: "AES CCM"
---

# AES CCM

AES CCM (Counter with CBC-MAC) is an authenticated encryption (AEAD) mode that combines CTR-mode encryption with a CBC-MAC over the plaintext (and optional associated data). It provides both confidentiality and integrity. CCM supports flexible nonce lengths (7–13 bytes) and tag lengths (4, 6, 8, 10, 12, 14, or 16 bytes), and imposes a maximum plaintext length that depends on the nonce length (L = 15 − nonce_len, so max length 2^(8L) − 1 bytes). No padding is applied to the plaintext for encryption.

**How it works:**  
- The authentication tag is computed first: a CBC-MAC over a formatted header (flags, nonce, length), optional AAD, and the plaintext.  
- Encryption is then performed in CTR mode using the same key and a counter derived from the nonce.  
- The tag is appended (or transmitted with) the ciphertext; the decryptor verifies the tag in constant time before releasing plaintext.

**Security implications:**  
CCM provides confidentiality and authenticity. **Nonce uniqueness is critical:** reusing (key, nonce) is catastrophic. Verify the tag in constant time and do not leak information on failure. Respect the maximum plaintext length for the chosen nonce length (e.g. with a 12-byte nonce, L=3, max about 2^24 bytes). CCM is typically slower than GCM on platforms with AES-NI because it is more sequential.

**Recommended use cases:**  
- AEAD in constrained or embedded environments (e.g. IEEE 802.11, Zigbee, CoAP) where CCM is required by standard.  
- When you need flexible nonce and tag sizes to match protocol or size constraints.

**Prefer** AES-GCM for new general-purpose designs when hardware acceleration is available; choose **AES-CCM** when the standard or environment requires it.

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

## API

### `aes_ccm_encrypt`

```c
noxtls_return_t aes_ccm_encrypt(const uint8_t *key, aes_type_t type, const uint8_t *nonce, uint32_t nonce_len, const uint8_t *aad, uint32_t aad_len, const uint8_t *plaintext, uint32_t plaintext_len, uint8_t *ciphertext, uint8_t *tag, uint32_t tag_len);
```

AES-CCM encrypt (authenticated encryption).

**Parameters:**

- `key` — AES key
- `type` — AES key size (AES_128_BIT, AES_192_BIT, AES_256_BIT)
- `nonce` — Nonce (7..13 bytes; length must match L = 15 - nonce_len, L in 2..8)
- `nonce_len` — Nonce length in bytes (7, 8, 9, 10, 11, 12, or 13)
- `aad` — Optional associated data (may be NULL if aad_len == 0)
- `aad_len` — Length of AAD in bytes
- `plaintext` — Plaintext to encrypt
- `plaintext_len` — Length of plaintext (max 2^(8 L)-1 bytes for L = 15 - nonce_len)
- `ciphertext` — Output ciphertext (same length as plaintext)
- `tag` — Authentication tag (4, 6, 8, 10, 12, 14, or 16 bytes)
- `tag_len` — Tag length in bytes

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).

### `aes_ccm_decrypt`

```c
noxtls_return_t aes_ccm_decrypt(const uint8_t *key, aes_type_t type, const uint8_t *nonce, uint32_t nonce_len, const uint8_t *aad, uint32_t aad_len, const uint8_t *ciphertext, uint32_t ciphertext_len, const uint8_t *tag, uint32_t tag_len, uint8_t *plaintext);
```

AES-CCM decrypt (verify tag and decrypt).

**Parameters:**

- `key` — AES key
- `type` — AES key size
- `nonce` — Nonce (same length as used in encrypt)
- `nonce_len` — Nonce length in bytes
- `aad` — Optional associated data (may be NULL if aad_len == 0)
- `aad_len` — Length of AAD in bytes
- `ciphertext` — Ciphertext to decrypt
- `ciphertext_len` — Length of ciphertext
- `tag` — Expected authentication tag
- `tag_len` — Tag length in bytes
- `plaintext` — Output plaintext (same length as ciphertext)

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success (tag verified); otherwise a specific [return code](/docs/api/return_codes).

