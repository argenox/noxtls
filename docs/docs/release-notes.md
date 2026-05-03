---
sidebar_position: 8
title: Release Notes
---

# Release Notes

This page describes changes, fixes, and known issues for **NoxTLS 0.1.22** (current release).

For source and binary artifacts, see [Releases on GitHub](https://github.com/argenox/noxtls/releases).

Use the **version dropdown** in the navbar to view docs (and release notes) for other versions.

---

## 0.1.22

**Release date:** TBD

### Changes

- **RFC 6066 Maximum Fragment Length (MFL):** Full support for TLS 1.2 / DTLS 1.2. Client can request smaller max record payload (512, 1024, 2048, 4096 bytes) via `tls12_set_max_fragment_length()`; server echoes the extension; application data is sent in chunks respecting the negotiated limit.
- **RFC 8449 Record Size Limit (RSL):** Full support for TLS 1.3. Client sends `record_size_limit` in Client Hello; server sends it in Encrypted Extensions; `tls13_set_record_size_limit()` configures the limit; application data is sent in chunks per the negotiated limit.
- **RC4:** Optional RC4 stream cipher (RFC 4345) added for legacy compatibility. Documented as weak; prefer ChaCha20 or AES-GCM. Config: `NOXTLS_FEATURE_RC4`; API: `noxtls_rc4.h` (e.g. `rc4_self_test`, `rc4_encrypt` / `rc4_decrypt`).
- **Raw Public Keys (RFC 7250):** TLS 1.2/DTLS 1.2 support for server and client certificate type extensions; server can send SubjectPublicKeyInfo in Certificate; client accepts RPK and verifies out-of-band. APIs: `tls12_set_server_use_rpk()`, `tls12_set_client_accept_server_rpk()`, `tls12_set_client_offer_client_rpk()`.
- **Unit tests:** Added `ut/encryption/test_rc4.c` (self-test, roundtrip, incremental) and RPK setter tests in `ut/tls/test_tls_ut.c` (`tls12_rpk_setters_client`, `tls12_rpk_setters_server`).
- **Documentation:** Versioned docs for 0.1.22; FEATURE_CHECKLIST updated for MFL, RSL, RC4, RPK; API docs for RC4 and certs (RPK).

### Fixed / Resolved

- **Build (certs):** Removed invalid `#include "encryption/aes/noxtls_aes_cbc.h"` from `noxtls_x509.c` (header does not exist; CBC API is declared in `noxtls_aes.h`).
- **Build (MSVC):** Removed duplicate definition of `oid_equal()` in `noxtls_x509.c` (C2084).

### Known issues / Open

- (None recorded.)
