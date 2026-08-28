---
sidebar_position: 9
title: EdDSA
description: "NoxTLS documentation: EdDSA."
---

# EdDSA in NoxTLS

This library implements **Ed25519** and **Ed448** (RFC 8032) with **PureEdDSA**, **Ed25519ctx / Ed448ctx**, and **Ed25519ph / Ed448ph** variants where applicable. Ed448 requires SHA-3 (SHAKE256) support (`NOXTLS_FEATURE_SHA3`).

## C APIs

- **Ed25519**: `noxtls-lib/pkc/ed25519/noxtls_ed25519.h` — `noxtls_ed25519_sign` / `verify`, `noxtls_ed25519ctx_*`, `noxtls_ed25519ph_*`, key generation and public-key derivation.
- **Ed448**: `noxtls-lib/pkc/ed448/noxtls_ed448.h` — same pattern for pure, ctx, and ph.

## X.509 and PKCS#8 (RFC 8410)

- Parsed certificates may expose **Ed25519** / **Ed448** subject public keys (`noxtls_x509.h`).
- **PKCS#8** private keys with algorithm **id-Ed25519** / **id-Ed448** and raw seed in the `PrivateKey` OCTET STRING are parsed into `x509_private_key_t` with `key_type` `X509_PRIVATE_KEY_ED25519` or `X509_PRIVATE_KEY_ED448`.
- **`noxtls_x509_private_key_get_eddsa_seed`** returns the 32- or 57-byte seed when the key is Ed25519/Ed448.
- **`noxtls_x509_private_key_sign_data`** accepts PEM/DER for those keys and writes a **raw** signature (64 bytes Ed25519, 114 bytes Ed448) suitable for RFC 8410 certificate `signature` BIT STRINGs. **PureEdDSA** is used; `hash_algo` is ignored for Ed keys.

## Applications

- **certgen**: `gened25519` / `gened448` emit PKCS#8 + SPKI; `req -new -x509` can sign self-signed certificates with ECC, Ed25519, or Ed448 keys when `NOXTLS_HAVE_CERT_WRITE` is enabled.
- **pkc**: `sign` / `verify` / `genkey` for `ed25519`, `ed25519ctx`, `ed25519ph`, `ed448`, `ed448ctx`, `ed448ph` — use **`-K`** (private key PEM) for sign, **`-P`** (hex public key) for verify, **`-C`** (hex context) for `*ctx` algorithms.

## TLS 1.3

Client certificate verify paths support Ed25519 and Ed448 signature schemes when the corresponding features are enabled; see `noxtls_tls13.h` and the **tls_test** application documentation.
