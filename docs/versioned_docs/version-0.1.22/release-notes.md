---
sidebar_position: 8
title: Release Notes
---

# Release Notes

This page describes changes, fixes, and known issues for **NoxTLS 0.1.22**.

For source and binary artifacts, see [Releases on GitHub](https://github.com/argenox/noxtls/releases).

Use the **version dropdown** in the navbar to view docs (and release notes) for other versions.

---

## 0.1.22

**Release date:** TBD

### Changes

- RFC 6066 Maximum Fragment Length: full TLS 1.2/DTLS 1.2 support; tls12_set_max_fragment_length(); application data sent in chunks.
- RFC 8449 Record Size Limit: full TLS 1.3 support; tls13_set_record_size_limit(); Client Hello and Encrypted Extensions; application data sent in chunks.
- RC4 stream cipher (legacy); NOXTLS_FEATURE_RC4; noxtls_rc4.h.
- Raw Public Keys (RFC 7250): TLS 1.2/DTLS 1.2 server/client certificate type extensions; tls12_set_server_use_rpk, tls12_set_client_accept_server_rpk, tls12_set_client_offer_client_rpk.
- Unit tests: test_rc4.c; tls12_rpk_setters_client, tls12_rpk_setters_server.
- Documentation: versioned docs for 0.1.22; FEATURE_CHECKLIST and API docs updated.

### Fixed / Resolved

- Removed invalid noxtls_aes_cbc.h include from noxtls_x509.c.
- Removed duplicate oid_equal() in noxtls_x509.c (MSVC C2084).

### Known issues / Open

- (None recorded.)