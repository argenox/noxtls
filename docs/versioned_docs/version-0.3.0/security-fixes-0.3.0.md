---
title: Security Fixes in 0.3.0
description: "Security issues fixed in NoxTLS 0.3.0: severity, affected APIs and configurations, impact, and required actions."
---

# Security fixes in NoxTLS 0.3.0

This page describes the security issues fixed in NoxTLS 0.3.0. Use it to decide whether a product built on an earlier release is affected and whether you need to change your code when you upgrade. The full list of changes is in the [Release Notes](./release-notes.md).

No CVE identifiers have been assigned to these issues. To report a suspected vulnerability, see [Security Reporting](./security-reporting.md).

## How to read this page

**Severity.** *Critical* and *High* mean a wrong cryptographic result, a signature or trust bypass, or a memory-safety error. Ratings describe the defect itself; the practical risk to a product depends on which features it enables and where its inputs come from.

**Origin** states which releases are affected:

- **Present in 0.2.x**: verified to be present in releases before 0.3.0.
- **0.3.0 development only**: introduced while 0.3.0 was being developed and fixed before release. No 0.2.x release contains it.
- **Origin not determined**: not yet traced to the release that introduced it. If you use the affected feature in an earlier release, treat that release as potentially affected.

## Summary

| Severity | Issue | Origin | Action when upgrading |
| --- | --- | --- | --- |
| Critical | [RSA PKCS#1 v1.5 signature forgery](#rsa-pkcs1-v15-signature-forgery) | Present in 0.2.x | None (stricter verification) |
| Critical | [X.509 trust-anchor impersonation](#x509-trust-anchor-impersonation) | Origin not determined | None |
| High | [ASN.1 DER validation disabled in non-debug builds](#asn1-der-validation-disabled-in-non-debug-builds) | 0.3.0 development only | None |
| High | [`noxtls_sha1_verify()` accepted any digest](#sha-1-verify-accepted-any-digest) | Present in 0.2.x | Check callers' results |
| High | [ARIA invalid key type corrupts the stack](#aria-invalid-key-type-corrupts-the-stack) | Origin not determined | Handle new error codes |
| High | [Camellia one-shot modes read and write out of bounds](#camellia-one-shot-modes-read-and-write-out-of-bounds) | Origin not determined | Handle new error codes |
| High | [PKCS#8 private-key parse stack overflow](#pkcs8-private-key-parse-stack-overflow) | Origin not determined | None |
| High | [ECDSA signing nonce exposed in a public global](#ecdsa-signing-nonce-exposed-in-a-public-global) | Development line after 0.2.70 | **Remove references to the symbol** |
| High | [TLS 1.2 client-authentication bypass through session resumption](#tls-12-client-authentication-bypass-through-session-resumption) | Origin not determined | **Expect full handshakes** |
| High | [TLS 1.2 Finished accepted without record protection](#tls-12-finished-accepted-without-record-protection) | Origin not determined | None |

## Critical

### RSA PKCS#1 v1.5 signature forgery

- **Severity:** Critical.
- **Affected:** `noxtls_rsa_verify()` with PKCS#1 v1.5 padding, and everything built on it: verification of RSA-signed X.509 certificates and chains, and TLS 1.2 verification of RSA PKCS#1 v1.5 signatures in ServerKeyExchange and CertificateVerify. All configurations with RSA enabled.
- **Origin:** Present in 0.2.x (present since the RSA code was first added).
- **Impact:** Verification looked for the `00 01` marker, treated any later zero byte as the separator, and compared only the trailing hash bytes. Neither the `0xFF` padding string nor the DigestInfo was checked, so a block of the form `00 01 00 <arbitrary bytes> H(m)` verified. This is the signature forgery described by Bleichenbacher in 2006. Against an RSA public key with exponent e = 3, an attacker can construct a signature that verifies for a message of their choice without the private key. That could make a forged certificate verify under a CA key with e = 3, or forge a TLS 1.2 handshake signature for a peer key with e = 3. This technique is not known to be practical against the common exponent e = 65537, but verification was still incorrect for every key.
- **Fix:** Verification now follows RFC 8017 section 8.2.2. It rejects a signature value that is not less than the modulus, rebuilds the expected encoding `00 01 FF..FF 00 || DigestInfo || H(m)`, and compares the whole block in constant time. The only alternative form accepted is a DigestInfo with the NULL parameters omitted (RFC 8017 section 9.2, note 1). Signing uses the same encoder and enforces the minimum of eight padding bytes.
- **Action:** Upgrade. No API changes. Signatures with non-standard encodings that were accepted before are now rejected.

### X.509 trust-anchor impersonation

- **Severity:** Critical.
- **Affected:** X.509 chain verification against trust anchors, through both the global trust store and `noxtls_x509_verify_cert_with_policy()`, and therefore TLS server and client certificate verification.
- **Origin:** Origin not determined.
- **Impact:** A certificate was identified by its subject name and serial number (or subject name and public key). An attacker could create a CA certificate that copied a trusted root's subject and serial number but carried the attacker's own key. Chain verification treated that certificate as the trust anchor, so certificates the attacker issued under it were accepted. In TLS, this lets an attacker who can present such a chain authenticate as any identity that the trust anchor is trusted for.
- **Fix:** A certificate is treated as a trust anchor only when its TBSCertificate and signature are byte-identical to the anchor's. Issuer lookup returns only a candidate whose public key verifies the certificate's signature, and the path ends only at a trust anchor whose key verifies the last certificate.
- **Action:** Upgrade. No API changes.

## High

### ASN.1 DER validation disabled in non-debug builds

- **Severity:** High.
- **Affected:** `noxtls_parse_der()` in builds without `NOXTLS_ASN1_DEBUG`, which is the normal configuration.
- **Origin:** 0.3.0 development only. The regression came from the MISRA C rework. No 0.2.x release is affected.
- **Impact:** The function returned success for any input, so truncated or malformed DER (for example `30 84 00 00 00`) was reported as valid. Code that relied on it to reject malformed DER before further processing lost that check.
- **Fix:** The TLV walk, with its length and truncation checks, runs in every build. Only the diagnostic pretty-printing still depends on `NOXTLS_ASN1_DEBUG`.
- **Action:** None for 0.2.x users. Update any build made from pre-release 0.3.0 sources.

### SHA-1 verify accepted any digest

- **Severity:** High.
- **Affected:** `noxtls_sha1_verify()`.
- **Origin:** Present in 0.2.x.
- **Impact:** The function returned `NOXTLS_RETURN_SUCCESS` even when the computed digest did not match the expected one, so an integrity check built on it accepted any data. It also compared 32 bytes against the 20-byte expected digest, reading past the caller's buffer.
- **Fix:** The function compares exactly 20 bytes, returns `NOXTLS_RETURN_FAILED` on a mismatch and `NOXTLS_RETURN_NULL` when `expected` is NULL, and erases its working buffer.
- **Action:** Upgrade. If a product on 0.2.x used `noxtls_sha1_verify()` to check integrity, those checks were not effective.

### ARIA invalid key type corrupts the stack

- **Severity:** High.
- **Affected:** ARIA key setup (`noxtls_aria_set_encrypt_key()`, `noxtls_aria_set_decrypt_key()`) and the ARIA one-shot and streaming modes when called with an unsupported key type.
- **Origin:** Origin not determined.
- **Impact:** An unsupported key type left the round count uninitialized while key setup still returned success. Decryption key setup then indexed a stack array with that value, corrupting stack memory. The issue is reachable only when an application passes an unvalidated key type to the ARIA API.
- **Fix:** Key types are validated before use (`NOXTLS_RETURN_INVALID_KEY_SIZE`), the block functions refuse an invalid round count, and CTR and CFB report key-setup errors. One-shot decryption rejects lengths that are not a multiple of the block size, and encryption and ECB reject lengths that would overflow.
- **Action:** Calls with an invalid key type or length now fail. Check the return codes.

### Camellia one-shot modes read and write out of bounds

- **Severity:** High.
- **Affected:** The Camellia one-shot mode functions (ECB, CBC, CTR, CFB, and OFB, encrypt and decrypt).
- **Origin:** Origin not determined.
- **Impact:** These functions did not check for NULL pointers, the key type, or the data length. An invalid key type returned success. ECB with a length that is not a multiple of 16 read and wrote past the caller's buffers, and CBC decryption read past the input. If the length comes from untrusted input, such as a received ciphertext, this is an out-of-bounds read and write.
- **Fix:** All ten entry points share one argument check: NULL pointers return `NOXTLS_RETURN_NULL`, and an invalid key type returns `NOXTLS_RETURN_INVALID_KEY_SIZE`. ECB and CBC decryption return `NOXTLS_RETURN_INVALID_BLOCK_SIZE` for lengths that are not a multiple of 16, and block-level errors are returned to the caller.
- **Action:** Calls with invalid arguments now fail instead of returning success. Check the return codes.

### PKCS#8 private-key parse stack overflow

- **Severity:** High.
- **Affected:** Parsing PKCS#8 private keys with `noxtls_x509_private_key_parse_der()`, `noxtls_x509_private_key_parse_pem()`, and their `_with_password` variants.
- **Origin:** Origin not determined.
- **Impact:** The version INTEGER was copied into a one-byte stack buffer using the size of the whole structure as the limit. A malformed key with a long version field overflowed the stack buffer. This matters wherever keys are parsed from a source that is not fully trusted.
- **Fix:** The version field must be exactly one byte. The other fixed-size ASN.1 reads in the parser were audited and already pass the correct limit.
- **Action:** Upgrade. No API changes.

### ECDSA signing nonce exposed in a public global

- **Severity:** High.
- **Affected:** Every ECDSA signature produced by `noxtls_ecdsa_sign()`, on all curves, in builds that contain the exported variable `noxtls_ecdsa_sign_last_nonce`.
- **Origin:** Introduced in September 2026 on the development line after 0.2.70, as an on-target diagnostic. The tagged 0.2.70 release and earlier releases do not contain it.
- **Impact:** The library kept a copy of the secret per-signature nonce k of each signature in a public global variable. Anyone who can read that variable and the matching signature can compute the ECDSA private key. Possible routes include a memory-disclosure bug, a debug interface, or other code linked into the same image.
- **Fix:** The variable has been removed from the library and its header.
- **Action:** **Required if your code references `noxtls_ecdsa_sign_last_nonce`:** it no longer compiles or links, and there is no replacement. If devices ran an affected build and their memory could have been read by an untrusted party, consider rotating the ECDSA keys those devices used.

### TLS 1.2 client-authentication bypass through session resumption

- **Severity:** High.
- **Affected:** TLS 1.2 servers that call `noxtls_tls12_require_client_auth()` or `noxtls_tls12_request_client_auth()` with session-ID or session-ticket resumption available. Servers that set an explicit policy with `noxtls_tls12_set_client_verify_policy()` already declined resumption and were not affected.
- **Origin:** Origin not determined.
- **Impact:** The TLS 1.2 session cache is shared by the whole process, and the server's resumption check looked only for an explicit client-verification policy. A client that obtained a session on a connection without client authentication, for example from another server context in the same process, could resume that session on a server that requires client certificates. It then completed the handshake without presenting or proving possession of a certificate.
- **Fix:** A server that requests or requires client certificates never resumes a session, so every connection authenticates the client. Session-cache entries are also bound to a SHA-256 hash of the issuing server's certificates, the negotiated protocol version, and the certificate type, so a session issued under one server configuration is not resumed under another.
- **Action:** **Behaviour change.** Every connection to such a server is a full handshake, so plan for the extra CPU time and latency on constrained servers. Clients that offer a session simply fall back to a full handshake, as the protocol allows.

### TLS 1.2 Finished accepted without record protection

- **Severity:** High.
- **Affected:** TLS 1.2 client and server handshakes.
- **Origin:** Origin not determined.
- **Impact:** Both sides accepted the peer's Finished message in a plaintext record instead of requiring it to be protected under the newly negotiated keys (RFC 5246 section 7.4.9), and each side sent its own Finished unprotected when its traffic keys were all zero. The Finished verify_data was still checked. However, the handshake no longer confirmed that the peer held the negotiated record keys, and a Finished message could be sent in clear text.
- **Fix:** Both plaintext paths were removed. A Finished record must decrypt and authenticate under the new keys, and Finished is always sent protected. A memory leak on the rejected plaintext path was removed with it.
- **Action:** Upgrade. No API changes.

## Related hardening

These fixes in 0.3.0 are not rated as security issues above, but are relevant to security reviews. See the [Release Notes](./release-notes.md) for the complete list.

- `noxtls_tls12_context_free()` erases secrets, traffic keys, and buffered plaintext that it previously left in the context.
- TLS 1.2 message builders no longer overrun a handshake workspace smaller than their fixed layouts.
- Hardware accelerator errors are no longer silently replaced by a software result, and partial outputs are erased.
- ChaCha20-Poly1305 compares tags in constant time and rejects a NULL AAD pointer with a non-zero length.
- Duplicate TLS extensions are rejected, and the TLS 1.3 client rejects malformed EncryptedExtensions and ServerHello extensions.
- `noxtls_dh_shared_secret()` rejects over-long peer values with non-zero leading bytes.
