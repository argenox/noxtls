---
sidebar_position: 10
title: "AES XTS"
---

# AES XTS

AES XTS (XEX-based Tweaked CodeBook with ciphertext Stealing) is a mode designed for **disk or sector-based encryption** (e.g. full-disk encryption, IEEE 1619). Each logical unit (e.g. sector) is encrypted with a **tweak**—typically the sector index—so that the same plaintext in different sectors produces different ciphertext. XTS uses two AES keys (often derived by splitting one key); the tweak is combined with the encryption output in a way that prevents reusing the same effective key across sectors. The last partial block uses ciphertext stealing, so no padding is needed.

**How it works:**  
- The 16-byte tweak (e.g. sector number) is encrypted with one key to form a mask.  
- Each block of the sector is encrypted in XEX style: XOR with the mask, encrypt with the other key, XOR with the mask again (mask updated per block via multiplication in a finite field).  
- For a final partial block, ciphertext stealing is used so the ciphertext length equals the plaintext length.

**Security implications:**  
XTS provides **confidentiality only**; it does not provide integrity or authentication. The **tweak must be unique per logical sector**—reusing the same tweak for two different sectors can leak information. Use only for sectorized storage; do not use XTS for general-purpose message encryption. For full-disk encryption, consider an integrity layer if the threat model requires it.

**Recommended use cases:**  
- Full-disk or sector-based encryption where each sector has a unique index.  
- Standards-compliant storage encryption (e.g. IEEE 1619) when the application matches the sector/tweak model.

**Do not** use XTS for general-purpose message or transport encryption; use AEAD modes (e.g. AES-GCM, ChaCha20-Poly1305) instead.

### When to use

- **Disk or sector-based encryption** (e.g. full-disk encryption, encrypted storage). XTS-AES is designed so that each “sector” (or unit) is encrypted with a tweak (e.g. sector index) so that the same plaintext in different sectors produces different ciphertext.
- **When you have a natural sector or block index** that can be used as the tweak and will not repeat for the same logical unit.

### What to be careful of

- **Tweak must be unique per logical sector.** Typically the tweak is the sector number or (sector number, offset). Reusing the same tweak for two different sectors can leak information. Do not use XTS for non-sectorized data without a clear, unique tweak per unit.
- **Two keys.** XTS uses two AES keys (often derived from one key by splitting). This implementation takes a single key and splits it; ensure key length is 2× the AES key size (e.g. 256 bits for AES-128 XTS, 512 bits for AES-256 XTS).
- **No authentication.** XTS provides confidentiality only. For full-disk encryption, consider an integrity layer (e.g. dm-integrity, or higher-level authenticated storage) if the threat model requires it.
- **Sector size.** Typically 16 bytes (one block) or 512 bytes; the last incomplete block uses ciphertext stealing. Match your sector size to the standard or platform expectation.

### Practical deployment

- Use **only for disk/sector encryption** or standardized storage encryption (e.g. IEEE 1619). Do not use XTS for general-purpose message encryption.
- **Tweak format:** Use the sector index (or equivalent) as the 16-byte tweak; do not reuse tweaks. Document how the tweak is formed (endianness, padding).
- **Key management:** Protect the XTS key as you would any master storage key; consider hardware protection or key derivation from a higher-level secret.

## API

### `noxtls_aes_encrypt_xts`

```c
noxtls_return_t noxtls_aes_encrypt_xts(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, noxtls_aes_type_t type);
```

AES Encrypt in XTS Mode  XEX-based Tweaked CodeBook mode with ciphertext Stealing (XTS-AES). Used for disk encryption. Requires two keys (or key split in half). The IV parameter is used as the tweak value (typically sector number).

**Parameters:**

- `key` — is a pointer to the encryption key (full key, will be split)
- `data` — is a pointer to the plaintext to be encrypted
- `data_len` — is the length of the plaintext in bytes
- `iv` — is the tweak value (16 bytes). Typically represents sector number.
- `output` — is the output buffer where the encrypted plaintext will be placed
- `type` — is the AES variant, 128, 192, 256

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; otherwise a specific [return code](/docs/api/return_codes).

