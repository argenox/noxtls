---
title: Security Fixes in 0.3.0
description: "Security issues fixed in NoxTLS 0.3.0: severity, affected APIs and configurations, impact, and required actions."
---

# Security fixes in NoxTLS 0.3.0

This page describes the security issues fixed in NoxTLS 0.3.0. Use it to decide whether a product built on an earlier release is affected and whether you need to change your code when you upgrade. The full list of changes is in the [Release Notes](./release-notes.md).

NoxTLS 0.3.0 fixes 26 security issues: two rated Critical, fourteen High, seven Medium, and three Low. Fourteen of them (four High and all of the Medium and Low issues) were found by a final round of fuzz testing, code review, and interoperability testing before release.

No CVE identifiers have been assigned to these issues. To report a suspected vulnerability, see [Security Reporting](./security-reporting.md).

## How to read this page

**Severity.** *Critical* and *High* mean a wrong cryptographic result, a signature or trust bypass, or a memory-safety error. *Medium* means a weakness in a less common path or one that needs more conditions to exploit, such as a memory leak a peer can trigger repeatedly. *Low* means a validation gap with limited practical impact. Ratings describe the defect itself; the practical risk to a product depends on which features it enables and where its inputs come from.

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
| High | [TLS 1.3 accepted records reflected back to their sender](#tls-13-accepted-records-reflected-back-to-their-sender) | Origin not determined | None |
| High | [TLS 1.3 CertificateVerify signed-content buffer overflow](#tls-13-certificateverify-signed-content-buffer-overflow) | Origin not determined | **Check buffer sizes and return codes** |
| High | [DTLS 1.3 record length not checked against the datagram](#dtls-13-record-length-not-checked-against-the-datagram) | Origin not determined | None |
| High | [TLS 1.3 handshake buffer over-read](#tls-13-handshake-buffer-over-read) | Origin not determined | None |
| High | [Certificate and CSR PEM writers ignored the buffer size](#certificate-and-csr-pem-writers-ignored-the-buffer-size) | Origin not determined | **Check buffer sizes and return codes** |
| High | [TLS 1.2 server accepted loosely encoded RSA client signatures](#tls-12-server-accepted-loosely-encoded-rsa-client-signatures) | Origin not determined | None (stricter verification) |
| Medium | [TLS 1.3 HelloRetryRequest memory leak](#tls-13-helloretryrequest-memory-leak) | Origin not determined | None |
| Medium | [TLS 1.2 context free leaked partial handshake state](#tls-12-context-free-leaked-partial-handshake-state) | Origin not determined | None |
| Medium | [Global trust store leaked every replaced copy](#global-trust-store-leaked-every-replaced-copy) | Origin not determined | **Do not replace the store during verification** |
| Medium | [SAN DNS name with an embedded NUL matched its prefix](#san-dns-name-with-an-embedded-nul-matched-its-prefix) | Origin not determined | None |
| Medium | [Hostname fallback read CN from other subject attributes](#hostname-fallback-read-cn-from-other-subject-attributes) | Origin not determined | None for parsed certificates |
| Medium | [EC private-key import accepted out-of-range scalars](#ec-private-key-import-accepted-out-of-range-scalars) | Origin not determined | Handle new error codes |
| Medium | [RSA-PSS verification and RSA decryption accepted out-of-range values](#rsa-pss-verification-and-rsa-decryption-accepted-out-of-range-values) | Origin not determined | None |
| Low | [TLS 1.2 CBC padding oracle through the record-overflow error](#tls-12-cbc-padding-oracle-through-the-record-overflow-error) | Origin not determined | Prefer AEAD cipher suites |
| Low | [RSA-PSS ignored the leftmost encoded-message bits](#rsa-pss-ignored-the-leftmost-encoded-message-bits) | Origin not determined | None |
| Low | [Ed25519 accepted a non-canonical negative-zero point](#ed25519-accepted-a-non-canonical-negative-zero-point) | Origin not determined | None |

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

### TLS 1.3 accepted records reflected back to their sender

- **Severity:** High.
- **Affected:** TLS 1.3 and DTLS 1.3 record decryption (`noxtls_tls13_decrypt_record()`) with AES-GCM, AES-CCM, and ChaCha20-Poly1305 cipher suites, on clients and servers.
- **Origin:** Origin not determined.
- **Impact:** When a received record failed to decrypt under the peer's traffic key, the library tried again with the endpoint's own write key and sequence number, and on success advanced its own write sequence number. RFC 8446 section 5.2 requires such a record to be rejected. An attacker on the network path could therefore send an endpoint's own records back to it, and the endpoint accepted them as data from its peer. Protected records that one side sent, such as application data, could be delivered back to that same side as if the other side had sent them.
- **Fix:** The retry with the endpoint's own key was removed for all three AEAD modes. A record that fails authentication now zeroes the output and returns `NOXTLS_RETURN_BAD_DATA` (bad_record_mac) without moving any sequence number or replay window. Nothing in the library depended on the retry.
- **Action:** Upgrade. No API changes.

### TLS 1.3 CertificateVerify signed-content buffer overflow

- **Severity:** High.
- **Affected:** The public functions `noxtls_tls13_certificate_verify_build_signed_content()` and `noxtls_tls13_certificate_verify_build_signed_content_ex()`, and the internal TLS 1.3 code that builds and checks CertificateVerify messages.
- **Origin:** Origin not determined.
- **Impact:** These functions build the content that a TLS 1.3 CertificateVerify signs: 64 bytes of padding, a context string, a zero byte, and the transcript hash, up to 162 bytes in total. They did not read the buffer capacity passed in `*out_len`, so an application that passed a smaller buffer had memory past the end of that buffer overwritten. Inside the library, the buffer the server uses to check a client's CertificateVerify was one byte shorter than this maximum.
- **Fix:** The functions compute the required length first. When the buffer is too small they write nothing, set `*out_len` to the required length, and return `NOXTLS_RETURN_INVALID_PARAM`; context strings longer than 64 bytes are rejected. The new constant `NOXTLS_TLS13_CV_SIGNED_CONTENT_MAX_LEN` (162 bytes) is always large enough. Internal callers now pass their buffer sizes, and the server's buffer was corrected. A review of the other TLS 1.3 functions that write to caller buffers also changed `noxtls_tls13_get_channel_binding()`, which now reports the required length when the buffer is too small and returns 28 bytes (not 32) for a SHA-224-signed server certificate, and `noxtls_tls13_export_keying_material()`, which now rejects output longer than 255 times the hash length and labels longer than 249 bytes.
- **Action:** **API behaviour change.** If you call either function, set `*out_len` to the real buffer size before the call, size the buffer with `NOXTLS_TLS13_CV_SIGNED_CONTENT_MAX_LEN`, and check for `NOXTLS_RETURN_INVALID_PARAM`. Applications that do not call these functions directly need no changes.

### DTLS 1.3 record length not checked against the datagram

- **Severity:** High.
- **Affected:** DTLS 1.3 clients and servers: record parsing in `noxtls_tls13_dtls13_record_size()` and `noxtls_tls13_decrypt_dtls13_record()`, reached for every received datagram.
- **Origin:** Origin not determined.
- **Impact:** For a record header with a length field, the record size was taken from the 16-bit length without checking it against the bytes left in the datagram. Record decryption then read up to 64 KB past the end of the received datagram. Any peer could trigger this before authentication with a single datagram. The record still fails authentication, so no data is delivered to the application, but the over-read can fault on targets with memory protection and reads unrelated memory on targets without it.
- **Fix:** A record whose header and length are larger than the rest of the datagram is malformed and the datagram is dropped with `NOXTLS_RETURN_BAD_DATA`. Records too short for the 16-byte record-number mask sample (RFC 9147 section 4.2.3) are also rejected.
- **Action:** Upgrade. No API changes.

### TLS 1.3 handshake buffer over-read

- **Severity:** High.
- **Affected:** TLS 1.3 and DTLS 1.3 clients, while receiving the encrypted server handshake flight.
- **Origin:** Origin not determined.
- **Impact:** The buffer that collects decrypted handshake messages was resized to the new size before its unread bytes were moved to the front. When one record completed several messages and began another, and the next record was shorter than the part already consumed, the buffer shrank and the move read past the end of the new allocation. A server, or an attacker in the network path, could trigger this before the server was authenticated. Without memory checking it corrupted or stalled the handshake.
- **Fix:** The unread bytes are moved to the front of the current buffer before it is resized, so a shrink only drops consumed bytes. The buffer also stays consistent if the reallocation fails.
- **Action:** Upgrade. No API changes.

### Certificate and CSR PEM writers ignored the buffer size

- **Severity:** High.
- **Affected:** `noxtls_x509_certificate_write_pem()` and `noxtls_x509_csr_create_pem()` in builds with certificate writing (`NOXTLS_HAVE_CERT_WRITE`).
- **Origin:** Origin not determined.
- **Impact:** Both functions take an `out_max` capacity but passed the caller's buffer to DER-to-PEM converters that have no capacity parameter and write the whole PEM text and a NUL terminator. Any `out_max` smaller than the PEM text was a buffer overflow. `noxtls_x509_certificate_write_pem()` also made a temporary heap copy of `NOXTLS_MAX_CERT_SIZE` (16 to 64 KB) bytes.
- **Fix:** One bounded encoder computes the exact PEM size before writing and returns `NOXTLS_RETURN_FAILED` without touching the buffer when the text and its NUL do not fit. It is public as `noxtls_certificate_der_to_pem_ex()` and `noxtls_csr_der_to_pem_ex()`. `noxtls_x509_certificate_write_pem()` now encodes directly from the parsed certificate, with no heap copy. A review of the other certificate writers added explicit bounds for offset checks that could wrap, for the validity-time scratch buffer, and for the self-signed certificate workspace when `NOXTLS_MAX_CERT_SIZE` is reduced.
- **Action:** **API behaviour change.** Size `out_max` for the full PEM text plus its NUL terminator and check for `NOXTLS_RETURN_FAILED`. The legacy `noxtls_certificate_der_to_pem()` and `noxtls_csr_der_to_pem()` keep their signatures and still require the caller to size the buffer; use the `_ex` variants in new code. See [Certificates](./api/certs.md).

### TLS 1.2 server accepted loosely encoded RSA client signatures

- **Severity:** High.
- **Affected:** TLS 1.2 servers that request or require client certificates, when the client signs CertificateVerify with an RSA PKCS#1 v1.5 key.
- **Origin:** Origin not determined.
- **Impact:** The server's CertificateVerify check did not reject a signature value not less than the modulus, ignored the result of the modular exponentiation, and searched the decrypted block for a padding-and-DigestInfo pattern anywhere in it instead of comparing the whole block. A value of s + n verified like s, and blocks that only contained the expected digest were accepted. This is the same class of lenient check as the [RSA PKCS#1 v1.5 signature forgery](#rsa-pkcs1-v15-signature-forgery) above, which makes forged client signatures possible against keys with a small public exponent such as e = 3.
- **Fix:** The check follows RFC 8017 section 8.2.2: it rejects s >= n, checks the exponentiation result, builds the expected encoding `00 01 FF..FF 00 || T`, and compares the whole block in constant time. The CertificateVerify decision depends on this exact check alone.
- **Action:** Upgrade. No API changes. Clients that send non-standard encodings are now rejected.

## Medium

### TLS 1.3 HelloRetryRequest memory leak

- **Severity:** Medium.
- **Affected:** TLS 1.3 clients that receive a HelloRetryRequest, and every DTLS 1.3 client, because the DTLS 1.3 cookie exchange uses a HelloRetryRequest.
- **Origin:** Origin not determined.
- **Impact:** The extension list parsed from the HelloRetryRequest was overwritten without being freed when the ServerHello arrived, leaking about 300 bytes per handshake. A server can force a HelloRetryRequest on every connection, and on a fixed embedded memory pool the leak eventually exhausts memory.
- **Fix:** The previous extension list is freed before the next one is parsed.
- **Action:** Upgrade. No API changes.

### TLS 1.2 context free leaked partial handshake state

- **Severity:** Medium.
- **Affected:** TLS 1.2 and DTLS 1.2 clients and servers: `noxtls_tls12_context_free()`.
- **Origin:** Origin not determined.
- **Impact:** Freeing a context did not release a partly received handshake message or a record buffered by the client state machine, and taking a buffered record left the reassembly buffer behind. A peer that sends the first fragment of a handshake message and disconnects leaks memory on every connection. Context initialization also left the reassembly pointer uninitialized.
- **Fix:** Context free releases both buffers, taking a buffered record frees the stale reassembly buffer, and initialization sets both fields to empty.
- **Action:** Upgrade. No API changes.

### Global trust store leaked every replaced copy

- **Severity:** Medium.
- **Affected:** `noxtls_x509_trust_store_set()` and `noxtls_x509_trust_store_clear()`.
- **Origin:** Origin not determined.
- **Impact:** `noxtls_x509_trust_store_set()` stores a deep copy of the trust anchors, but both functions only dropped the pointer to the previous copy. Each reconfiguration leaked several KB per anchor, which exhausts a fixed embedded memory pool when trust anchors are updated in the field.
- **Fix:** The store owns exactly one copy. Replacing or clearing it frees the previous copy before a new one is allocated, and an allocation failure leaves the store empty (fail closed). Verification reads the store only for the duration of a call, and TLS contexts do not keep a pointer to it.
- **Action:** **Threading requirement.** The library has no internal locking, so do not call `noxtls_x509_trust_store_set()` or `noxtls_x509_trust_store_clear()` while another thread verifies a certificate against the global store or runs a TLS handshake that does. Configure the store at start-up, serialize updates with your own lock, or pass anchors per call with `noxtls_x509_verify_cert_with_policy()`.

### SAN DNS name with an embedded NUL matched its prefix

- **Severity:** Medium.
- **Affected:** Hostname verification with `noxtls_x509_certificate_matches_hostname()`, including TLS client server-name checks.
- **Origin:** Origin not determined.
- **Impact:** SAN dNSName values were copied into C strings, so a name such as `victim.example\0.evil.example` was stored, and matched, as `victim.example`. A certificate authority that checks only the full name could be led to issue a certificate that impersonates the prefix.
- **Fix:** A dNSName that contains a NUL byte is stored as an empty entry that never matches. It still counts as a SAN, so the subject-CN fallback stays disabled (RFC 6125 section 6.4.4).
- **Action:** Upgrade. No API changes.

### Hostname fallback read CN from other subject attributes

- **Severity:** Medium.
- **Affected:** `noxtls_x509_certificate_matches_hostname()` for certificates without a SAN DNS name, including TLS client server-name checks.
- **Origin:** Origin not determined.
- **Impact:** Without a SAN, the hostname was compared with the first `CN=` text in the formatted subject string. An attribute whose value contained `CN=`, such as an organization name `CN=victim.example`, therefore acted as the common name.
- **Fix:** The fallback walks the DER subject and compares the hostname only with commonName attributes, including those in multi-valued RDNs. A value is used only if it is a PrintableString, UTF8String, IA5String, or TeletexString, contains no NUL, and is shorter than 256 bytes.
- **Action:** None for certificates from the parser. Code that builds an `x509_certificate_t` by hand must fill in the DER subject, not only the `subject_dn` text, for the CN fallback to match.

### EC private-key import accepted out-of-range scalars

- **Severity:** Medium.
- **Affected:** `noxtls_x509_private_key_to_ecc_key()`, and signing with `noxtls_x509_private_key_sign_data()`, for SEC1 and PKCS#8 EC private keys.
- **Origin:** Origin not determined.
- **Impact:** The private scalar d was not range-checked. A key with d = 0 corresponds to the point at infinity, and a key with d not less than the group order n produces signatures that do not verify under the stated public key. Both were accepted and used for signing.
- **Fix:** The scalar must be in the range [1, n - 1], checked in constant time against the curve order. Out-of-range keys return `NOXTLS_RETURN_BAD_DATA`.
- **Action:** Keys with an invalid scalar now fail to load. Check the return codes.

### RSA-PSS verification and RSA decryption accepted out-of-range values

- **Severity:** Medium.
- **Affected:** `noxtls_rsa_verify_pss()`, and the RSA decryption functions `noxtls_rsa_decrypt()` and `noxtls_rsa_decrypt_crt_only()`.
- **Origin:** Origin not determined.
- **Impact:** PSS verification reduced the signature modulo n before checking it, so s + n (and s + 2n while it fits) verified like s. This makes signatures malleable: a second, different byte string verifies for the same message. RSA decryption likewise decrypted c + n to the same plaintext as c instead of rejecting it, against RFC 8017 section 5.1.2.
- **Fix:** PSS verification rejects a signature not less than n before exponentiation, and both decryption paths reject a ciphertext not less than n before any private-key work. PKCS#1 v1.5 verification already had this check.
- **Action:** Upgrade. No API changes.

## Low

### TLS 1.2 CBC padding oracle through the record-overflow error

- **Severity:** Low.
- **Affected:** TLS 1.2 and DTLS 1.2 connections that negotiate a CBC cipher suite (MAC-then-encrypt).
- **Origin:** Origin not determined.
- **Impact:** The record_overflow check ran before the padding and MAC checks, on a plaintext length derived from the unauthenticated padding byte. Two forged records of the same length that differed only in their decrypted padding byte returned different errors, `NOXTLS_RETURN_RECORD_OVERFLOW` or `NOXTLS_RETURN_BAD_DATA`, which is a padding oracle. The padding scan also branched on the padding byte.
- **Fix:** Padding, length, and MAC failures all return `NOXTLS_RETURN_BAD_DATA` (bad_record_mac), and `NOXTLS_RETURN_RECORD_OVERFLOW` is returned only for a record that authenticated. The padding check always scans the same number of bytes without branching on the padding.
- **Action:** Upgrade, and prefer AEAD cipher suites (AES-GCM, AES-CCM, or ChaCha20-Poly1305). The MAC is still computed over a length that depends on the padding, so a Lucky13-style timing difference remains; see the [Release Notes](./release-notes.md) known issues.

### RSA-PSS ignored the leftmost encoded-message bits

- **Severity:** Low.
- **Affected:** `noxtls_rsa_sign_pss()` and `noxtls_rsa_verify_pss()`, and the RSA-PSS signature schemes in TLS and X.509 that use them.
- **Origin:** Origin not determined.
- **Impact:** Verification cleared the leftmost bit of the encoded message and then tested the bit it had just cleared, so a signature with that bit set was accepted, against RFC 8017 section 9.1.2. Signing and verification also assumed a modulus length that is a multiple of 8 bits. For moduli of 8k - 1 bits, such as 2047-bit keys, about half of NoxTLS's signatures failed verification elsewhere and about half of valid signatures from other implementations were rejected; for 8k + 1 bits, signing failed.
- **Fix:** emBits and emLen are derived from the modulus. The encoder clears the required leftmost bits, and the verifier rejects any set bit outside the mask instead of clearing it. Mask-generation failures are checked.
- **Action:** Upgrade. No API changes. RSA-PSS now interoperates with OpenSSL for every modulus size.

### Ed25519 accepted a non-canonical negative-zero point

- **Severity:** Low.
- **Affected:** `noxtls_ed25519_verify()`, its ctx and ph variants, and Ed25519 streaming verification.
- **Origin:** Origin not determined.
- **Impact:** RFC 8032 section 5.1.3 requires point decoding to fail when x = 0 and the sign bit is set. The decoder accepted that encoding, so the identity point and the point of order 2 each had two accepted encodings, and the identity public key `01 00..00 80` verified the identity signature for every message. Exploiting this requires the attacker to choose the public key.
- **Fix:** Decoding fails when x is zero and the sign bit is set.
- **Action:** Upgrade. No API changes.

## Related hardening

These fixes in 0.3.0 are not rated as security issues above, but are relevant to security reviews. See the [Release Notes](./release-notes.md) for the complete list.

- `noxtls_tls12_context_free()` erases secrets, traffic keys, and buffered plaintext that it previously left in the context.
- TLS 1.2 message builders no longer overrun a handshake workspace smaller than their fixed layouts.
- Hardware accelerator errors are no longer silently replaced by a software result, and partial outputs are erased.
- ChaCha20-Poly1305 compares tags in constant time and rejects a NULL AAD pointer with a non-zero length.
- Duplicate TLS extensions are rejected, and the TLS 1.3 client rejects malformed EncryptedExtensions and ServerHello extensions.
- `noxtls_dh_shared_secret()` rejects over-long peer values with non-zero leading bytes.
- Bignum, DSA, RSA, ECC, digest, HMAC, HKDF, and PBKDF2 functions no longer report success after an internal failure such as an allocation or accelerator error. Before these fixes, memory pressure could make DSA signing return an invalid signature, and ECC key generation return the point at infinity as a public key, with success.
- `noxtls_ecc_point_validate_public()` rejects the point at infinity and coordinates that are not less than p, so ECDH and ECDSA reject such peer keys.
- The X.509 parser checks every cursor advance against the bytes remaining, and rejects malformed BOOLEAN values that could previously move it past the end of an extension.
- A failed allocation during DTLS handshake reassembly, or while a DTLS 1.3 server stores the client's key shares, no longer leads to a NULL pointer dereference.
- `noxtls_ecc_key_free()` no longer writes past a private-key buffer smaller than 66 bytes.
- SHA-3 and SHAKE no longer access the Keccak state through misaligned 64-bit pointers, which faulted on strict-alignment cores (Cortex-M0/M0+ and many RISC-V and Xtensa cores) and gave wrong digests on big-endian targets. MD4 no longer relies on an undefined signed shift.
- P-521 field arithmetic no longer uses generic bignum division. A single P-521 ECDSA verification took 0.4 to 1 s at -O2 on a host machine, so a peer presenting P-521 certificates or key shares could exhaust the CPU of a small core.
- Ed448 rejects reserved bits, non-canonical points, and S values not less than the group order, and its scalar multiplication no longer branches on secret bits. The earlier Ed448 code did not compile when enabled.
- AES-XTS follows IEEE 1619; earlier output was wrong after the first block and could not be fully decrypted. See the [Release Notes](./release-notes.md) for the compatibility impact.
- A basicConstraints pathLenConstraint above 255 is no longer truncated to 8 bits when a certificate is written, which silently changed the constraint the caller asked for. The parser rejects a negative pathLenConstraint instead of reading it as absent, which lifted the constraint.
- With an explicit verification time, `noxtls_x509_verify_cert_with_policy()` checks CRL freshness against that time instead of the system clock.
- DTLS 1.2 and DTLS 1.3 record handling was brought in line with RFC 6347 and RFC 9147, including the epoch in the DTLS 1.2 MAC and AEAD sequence number and silent discarding of replayed and wrong-epoch records.
