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

