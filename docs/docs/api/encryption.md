---
sidebar_position: 2
title: Encryption
description: "NoxTLS Encryption C API reference for embedded TLS, DTLS, and cryptography."
---

# Encryption

Block and stream ciphers by mode: AES (ECB, CBC, CTR, CFB, OFB, GCM, CCM, XTS), ARIA, Camellia, DES/3DES, ChaCha20, ChaCha20-Poly1305, RC4 (legacy; not recommended).

## AES hardware acceleration

NoxTLS supports build-targeted AES block acceleration while keeping API compatibility:

- `NOXTLS_CFG_FEATURE_AES_ACCEL_NI=ON` enables AES-NI backend for x86/x64 targets.
- `NOXTLS_CFG_FEATURE_AES_ACCEL_APPLE=ON` enables ARMv8 AES backend for Apple Silicon targets.
- Unsupported targets or disabled flags automatically use the software AES backend.

Acceleration is wired at AES block level and is reused by existing AES modes and TLS AES call paths.

## Streaming / incremental processing

If your application receives data in chunks, use context-based APIs:

- AES: `noxtls_aes_init()` / `noxtls_aes_update()` / `noxtls_aes_final()`
- ARIA: `noxtls_aria_init()` / `noxtls_aria_update()` / `noxtls_aria_final()`
- Camellia: `noxtls_camellia_init()` / `noxtls_camellia_update()` / `noxtls_camellia_final()`
- ChaCha20 already supports streaming with `noxtls_chacha20_init()` / `noxtls_chacha20_process()`
- RC4 supports streaming with `noxtls_rc4_init()` / `noxtls_rc4_process()` (legacy only; RC4 is weak and should not be used for new designs)
- Poly1305 already supports incremental MAC with `noxtls_poly1305_init()` / `noxtls_poly1305_update()` / `noxtls_poly1305_final()`

## Pages

### AES (grouped)

- [**AES**](/docs/api/aes) — Overview and links to all AES modes
- [**AES - ECB**](/docs/api/aes_ecb) — API for AES ECB
- [**AES - CBC**](/docs/api/aes_cbc) — API for AES CBC
- [**AES - CTR**](/docs/api/aes_ctr) — API for AES CTR
- [**AES - CFB**](/docs/api/aes_cfb) — API for AES CFB
- [**AES - OFB**](/docs/api/aes_ofb) — API for AES OFB
- [**AES - GCM**](/docs/api/aes_gcm) — API for AES GCM
- [**AES - CCM**](/docs/api/aes_ccm) — API for AES CCM
- [**AES - XTS**](/docs/api/aes_xts) — API for AES XTS
- [**AES (shared)**](/docs/api/aes_shared) — Shared types and streaming API

### ARIA

- [**ARIA - ECB**](/docs/api/aria_ecb) — API for ARIA ECB
- [**ARIA - CBC**](/docs/api/aria_cbc) — API for ARIA CBC
- [**ARIA - CTR**](/docs/api/aria_ctr) — API for ARIA CTR
- [**ARIA - CFB**](/docs/api/aria_cfb) — API for ARIA CFB
- [**ARIA - OFB**](/docs/api/aria_ofb) — API for ARIA OFB
- [**ARIA (shared)**](/docs/api/aria) — API for ARIA (shared)

### Camellia (grouped)

- [**Camellia**](/docs/api/camellia) — Overview and links to all Camellia modes
- [**Camellia - ECB**](/docs/api/camellia_ecb) — API for Camellia ECB
- [**Camellia - CBC**](/docs/api/camellia_cbc) — API for Camellia CBC
- [**Camellia - CTR**](/docs/api/camellia_ctr) — API for Camellia CTR
- [**Camellia - CFB**](/docs/api/camellia_cfb) — API for Camellia CFB
- [**Camellia - OFB**](/docs/api/camellia_ofb) — API for Camellia OFB
- [**Camellia (shared)**](/docs/api/camellia_shared) — Shared types and streaming API

### Other

- [**DES / 3DES**](/docs/api/des) — API for DES and 3DES
- [**ChaCha20-Poly1305**](/docs/api/chacha20_poly1305) — API for ChaCha20-Poly1305
- [**ChaCha20**](/docs/api/chacha20) — API for ChaCha20
- [**RC4**](/docs/api/rc4) — API for RC4 (legacy only; weak, do not use for new designs)
