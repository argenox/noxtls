---
sidebar_position: 10
title: AES XTS
description: "NoxTLS AES XTS C API reference for embedded TLS, DTLS, and cryptography."
---

# AES XTS

AES XTS (XEX-based Tweaked CodeBook with ciphertext Stealing) is a mode designed for **disk or sector-based encryption** (e.g. full-disk encryption, IEEE 1619). Each logical unit (e.g. sector) is encrypted with a **tweak**—typically the sector index—so that the same plaintext in different sectors produces different ciphertext. XTS uses two AES keys of the same size: Key1 encrypts the data and Key2 encrypts the tweak. The last partial block uses ciphertext stealing, so no padding is needed.

NoxTLS implements XTS-AES as specified in IEEE Std 1619-2007 and NIST SP 800-38E, and its output matches the IEEE 1619 test vectors and OpenSSL. Header: `encryption/aes/noxtls_aes.h`. Enable with `NOXTLS_CFG_FEATURE_AES_XTS` (CMake, default ON), which defines `NOXTLS_FEATURE_AES_XTS`.

**How it works:**  
- The 16-byte tweak (the data unit sequence number, little-endian as in IEEE 1619) is encrypted with Key2 to form a mask.  
- Each block of the data unit is encrypted in XEX style with Key1: XOR with the mask, encrypt, XOR with the mask again. The mask is multiplied by α in GF(2^128) for each block.  
- For a final partial block, ciphertext stealing (IEEE 1619-2007 sections 5.3.2 and 5.4.2) is used so the ciphertext length equals the plaintext length.

**Security implications:**  
XTS provides **confidentiality only**; it does not provide integrity or authentication. The **tweak must be unique per logical sector**—reusing the same tweak for two different sectors can leak information. Use only for sectorized storage; do not use XTS for general-purpose message encryption. For full-disk encryption, consider an integrity layer if the threat model requires it.

**Recommended use cases:**  
- Full-disk or sector-based encryption where each sector has a unique index.  
- Standards-compliant storage encryption (e.g. IEEE 1619) when the application matches the sector/tweak model.

**Do not** use XTS for general-purpose message or transport encryption; use AEAD modes (e.g. AES-GCM, ChaCha20-Poly1305) instead.

:::warning Changed in 0.3.0: not compatible with earlier NoxTLS XTS output

Before 0.3.0, the XTS tweak update and ciphertext stealing did not follow IEEE 1619: every block after the first was encrypted under the wrong tweak, a final partial block could not be decrypted, and inputs shorter than 16 bytes were padded and truncated. There was also no decrypt function. **Data encrypted with earlier NoxTLS XTS code is not compatible with 0.3.0 and must be re-encrypted** from its plaintext. Only data units of exactly 16 bytes produce the same ciphertext as before.

:::

### When to use

- **Disk or sector-based encryption** (e.g. full-disk encryption, encrypted storage). XTS-AES is designed so that each “sector” (or unit) is encrypted with a tweak (e.g. sector index) so that the same plaintext in different sectors produces different ciphertext.
- **When you have a natural sector or block index** that can be used as the tweak and will not repeat for the same logical unit.

### What to be careful of

- **Tweak must be unique per logical sector.** Typically the tweak is the sector number or (sector number, offset). Reusing the same tweak for two different sectors can leak information. Do not use XTS for non-sectorized data without a clear, unique tweak per unit.
- **Two keys.** XTS uses two AES keys of the same size: a data key (Key1) and a tweak key (Key2). Use `noxtls_aes_xts_encrypt()` and `noxtls_aes_xts_decrypt()` and pass two different keys; NIST SP 800-38E requires Key1 ≠ Key2. Each key is one AES key of the size selected by `type` (16 bytes for AES-128, 32 bytes for AES-256). The single-key functions `noxtls_aes_encrypt_xts()` and `noxtls_aes_decrypt_xts()` read exactly one AES key and use it as both Key1 and Key2. They do **not** split a double-length key into "data key || tweak key". They are kept for compatibility and do not meet SP 800-38E.
- **Minimum length.** A data unit must be at least one block (16 bytes). Shorter inputs return `NOXTLS_RETURN_INVALID_BLOCK_SIZE`. IEEE 1619 limits a data unit to 2^20 blocks.
- **No authentication.** XTS provides confidentiality only. For full-disk encryption, consider an integrity layer (e.g. dm-integrity, or higher-level authenticated storage) if the threat model requires it.
- **Sector size.** Typically 512 or 4096 bytes. Lengths that are not a multiple of 16 use ciphertext stealing. Match your sector size to the standard or platform expectation.

### Practical deployment

- Use **only for disk/sector encryption** or standardized storage encryption (e.g. IEEE 1619). Do not use XTS for general-purpose message encryption.
- **Tweak format:** Use the sector index (or equivalent) as the 16-byte tweak, encoded little-endian as in IEEE 1619; do not reuse tweaks.
- **Key management:** Protect both XTS keys as you would any master storage key; consider hardware protection or key derivation from a higher-level secret. Derive or generate Key1 and Key2 independently.

## API

All four functions share one implementation. Input and output may be the same buffer (in-place operation). Temporary values are erased, and the output is zeroed if the block cipher fails.

**Return codes (all four functions):**

- [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.
- [NOXTLS_RETURN_NULL](/docs/api/return_codes) when a key, `data`, or `output` is NULL.
- [NOXTLS_RETURN_INVALID_PARAM](/docs/api/return_codes) when the tweak is NULL.
- [NOXTLS_RETURN_INVALID_BLOCK_SIZE](/docs/api/return_codes) when `data_len` is less than 16.
- [NOXTLS_RETURN_INVALID_KEY_SIZE](/docs/api/return_codes) for an unknown `type`, or [NOXTLS_RETURN_NOT_SUPPORTED](/docs/api/return_codes) for a key size disabled in the build.
- Any error returned by the AES block cipher or a hardware accelerator; the output is zeroed.

### `noxtls_aes_xts_encrypt`

```c
noxtls_return_t noxtls_aes_xts_encrypt(const uint8_t *data_key,
                                       const uint8_t *tweak_key,
                                       const uint8_t *data,
                                       uint32_t data_len,
                                       const uint8_t *tweak,
                                       uint8_t *output,
                                       noxtls_aes_type_t type);
```

New in 0.3.0. Encrypt one data unit with XTS-AES (IEEE Std 1619-2007, NIST SP 800-38E), using separate data and tweak keys.

**Parameters:**

- `data_key` — Key1, which encrypts the data: one AES key of the size selected by `type`
- `tweak_key` — Key2, which encrypts the tweak: one AES key of the same size. NIST SP 800-38E requires `data_key` ≠ `tweak_key`.
- `data` — plaintext
- `data_len` — length of the plaintext in bytes; at least 16 (`NOXTLS_AES_BLOCK_LENGTH`)
- `tweak` — 16-byte tweak (data unit sequence number, little-endian as in IEEE 1619)
- `output` — buffer of `data_len` bytes that receives the ciphertext; may be the same buffer as `data`
- `type` — AES key size: `NOXTLS_AES_128_BIT`, `NOXTLS_AES_192_BIT`, or `NOXTLS_AES_256_BIT`

**Returns:** [noxtls_return_t](/docs/api/return_codes): see the return codes above.

### `noxtls_aes_xts_decrypt`

```c
noxtls_return_t noxtls_aes_xts_decrypt(const uint8_t *data_key,
                                       const uint8_t *tweak_key,
                                       const uint8_t *data,
                                       uint32_t data_len,
                                       const uint8_t *tweak,
                                       uint8_t *output,
                                       noxtls_aes_type_t type);
```

New in 0.3.0. Inverse of `noxtls_aes_xts_encrypt()`. The parameters and return codes are the same, with `data` holding the ciphertext and `output` receiving the plaintext. Pass the same `data_key`, `tweak_key`, and `tweak` that were used to encrypt.

### `noxtls_aes_encrypt_xts`

```c
noxtls_return_t noxtls_aes_encrypt_xts(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, noxtls_aes_type_t type);
```

Encrypt with XTS-AES using one key as both Key1 and Key2. Equivalent to `noxtls_aes_xts_encrypt(key, key, data, data_len, iv, output, type)`. Kept for compatibility: NIST SP 800-38E requires distinct data and tweak keys, so new code should use `noxtls_aes_xts_encrypt()`.

**Parameters:**

- `key` — one AES key of the size selected by `type`, used to encrypt both the data and the tweak (not a double-length key)
- `data` — plaintext
- `data_len` — length of the plaintext in bytes; at least 16
- `iv` — 16-byte tweak (data unit sequence number, little-endian as in IEEE 1619)
- `output` — buffer of `data_len` bytes that receives the ciphertext; may be the same buffer as `data`
- `type` — AES key size: `NOXTLS_AES_128_BIT`, `NOXTLS_AES_192_BIT`, or `NOXTLS_AES_256_BIT`

**Returns:** [noxtls_return_t](/docs/api/return_codes): see the return codes above.

### `noxtls_aes_decrypt_xts`

```c
noxtls_return_t noxtls_aes_decrypt_xts(const uint8_t* key, const uint8_t* data, uint32_t data_len, const uint8_t * iv, uint8_t* output, noxtls_aes_type_t type);
```

New in 0.3.0. Inverse of `noxtls_aes_encrypt_xts()`; equivalent to `noxtls_aes_xts_decrypt(key, key, data, data_len, iv, output, type)`. The parameters and return codes are the same, with `data` holding the ciphertext and `output` receiving the plaintext.

### Example

```c
#include "encryption/aes/noxtls_aes.h"

/* Encrypt one 512-byte sector in place with AES-256-XTS. Decrypt with noxtls_aes_xts_decrypt(). */
noxtls_return_t encrypt_sector(const uint8_t data_key[32], const uint8_t tweak_key[32],
                               uint64_t sector, uint8_t buf[512])
{
    uint8_t tweak[16] = {0};
    for (uint32_t i = 0U; i < 8U; i++) {
        tweak[i] = (uint8_t)(sector >> (8U * i)); /* little-endian sector number */
    }
    return noxtls_aes_xts_encrypt(data_key, tweak_key, buf, 512U, tweak, buf, NOXTLS_AES_256_BIT);
}
```
