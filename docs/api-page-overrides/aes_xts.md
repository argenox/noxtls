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
