---
sidebar_position: 8
title: Release Notes
---

# Release Notes

This page describes changes, fixes, and known issues for **NoxTLS 0.1.23**.

For source and binary artifacts, see [Releases on GitHub](https://github.com/argenox/noxtls/releases).

Use the **version dropdown** in the navbar to view docs (and release notes) for other versions.

---

## 0.1.23

**Release date:** TBD

### Changes

- Ed25519 / Ed448: RFC 8032 pure, ctx, and ph APIs; X.509 RFC 8410 PKCS#8 parse and raw certificate signing via noxtls_x509_private_key_sign_data; certgen req -new -x509 for Ed25519/Ed448 keys.
- PKC CLI: EdDSA algorithms (ed25519, ed25519ctx, ed25519ph, ed448, ed448ctx, ed448ph) with -K / -P / -C; in-tree build links X.509 for PEM key load.
- Documentation: docs/eddsa page, PKC and certgen README updates; versioned docs 0.1.23.

### Fixed / Resolved

- (None recorded.)

### Known issues / Open

- (None recorded.)