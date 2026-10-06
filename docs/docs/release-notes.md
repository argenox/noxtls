---
sidebar_position: 8
title: Release Notes
---

# Release Notes

This page describes changes, fixes, and known issues for **NoxTLS 0.3.0**.

For source and binary artifacts, see [Releases on GitHub](https://github.com/argenox/noxtls/releases).

Use the **version dropdown** in the navbar to view docs (and release notes) for other versions.

---

## 0.3.0

**Release date:** TBD

### Changes

- **MISRA C:2025.** NoxTLS 0.3.0 is the first release built against MISRA C:2025. Mandatory and Required findings were fixed in the code, with no suppressions or blanket exemptions. Every recorded library scan shows 0 Mandatory findings. The latest recorded integration scan (96 translation units) lists 24 Required findings with draft technical dispositions awaiting project sign-off. Advisory findings are not claimed, and NoxTLS is not certified under any functional-safety standard. See [MISRA C:2025](./misra-c.md).
- **Security fixes.** 0.3.0 fixes twelve security issues: two rated Critical and ten rated High. Each one is described in [Security fixes in 0.3.0](./security-fixes-0.3.0.md), including the affected APIs and configurations, what an attacker could do, what changed, and whether you need to act. No CVE identifiers have been assigned. In summary:
  - **Critical:** RSA PKCS#1 v1.5 signature verification accepted forged signatures (practical against RSA keys with public exponent 3). Affects X.509 certificate verification and TLS 1.2 signature checks. Present in 0.2.x.
  - **Critical:** X.509 chain verification accepted a CA certificate that copied a trust anchor's subject and serial number, so certificates issued under an attacker's key could be trusted.
  - **High:** `noxtls_parse_der()` accepted malformed DER in non-debug builds. Introduced during 0.3.0 development; not in any 0.2.x release.
  - **High:** `noxtls_sha1_verify()` returned success when the digest did not match. Present in 0.2.x.
  - **High:** ARIA key setup with an unsupported key type corrupted the stack, and the Camellia one-shot modes read and wrote past caller buffers for invalid lengths.
  - **High:** parsing a malformed PKCS#8 private key could overflow a stack buffer.
  - **High:** a diagnostic global, `noxtls_ecdsa_sign_last_nonce`, kept a copy of every ECDSA signing nonce, from which the private key can be computed. The symbol has been removed: **remove any reference to it.**
  - **High:** a TLS 1.2 server that requires client certificates could be bypassed through session resumption. Such servers **no longer resume sessions**.
  - **High:** TLS 1.2 accepted a Finished message sent outside record protection.
  - **High:** TLS 1.3 and DTLS 1.3 accepted an endpoint's own records when an attacker reflected them back to it. A record that fails authentication is now always rejected with bad_record_mac.
  - **High:** `noxtls_tls13_certificate_verify_build_signed_content()` and its `_ex` variant ignored the caller's buffer size and could write past the buffer. They now return `NOXTLS_RETURN_INVALID_PARAM` and report the required length when the buffer is too small: **check buffer sizes and return codes.**
- **MISRA API conventions.** Public text parameters and structure fields (hostnames, SNI, ALPN, file paths, passwords, DN and time strings, debug formats) are now `uint8_t` instead of `char`, so cast string literals at call sites. `noxtls_return_t` and most public enums (`noxtls_hash_algos_t`, `noxtls_aes_type_t`, `ecc_curve_t`, `rsa_key_size_t`, the PQC parameter sets and more) are now `uint32_t` typedefs; their numeric values are unchanged. New helpers in `noxtls_ct.h`: bounded `noxtls_copy_u8()`, `noxtls_move_u8()`, and `noxtls_fill_u8()`, plus `noxtls_u8_strlen()`, `noxtls_u8_strcmp()`, and `noxtls_u8_strncmp()`.
- **Allocator policy.** Library code allocates only through `NOXTLS_MALLOC`, `NOXTLS_CALLOC`, and `NOXTLS_REALLOC`, and releases through `noxtls_free()`. `scripts/check_allocator_policy.py` (CTest `allocator_policy_check`) rejects raw allocator calls outside the allocator implementation. `noxtls_memory_compat.h` no longer redefines `malloc`/`free`/`calloc`/`realloc`, because MISRA Rule 21.2 forbids redefining standard-library names.
- **Host stdio is optional.** Set `NOXTLS_HAVE_FILE_IO=0` (default 1; also available in the ESP-IDF and Zephyr Kconfig) to build without stdio file helpers. File-load APIs then return `NOXTLS_RETURN_FAILED`. `noxtls_debug_printf()` is now a no-op unless you configure CMake with `-DNOXTLS_DEBUG_PRINTF_STDIO=ON`.
- SHA-256 HMAC state and ECC inversion scratch are now private per context or per call by default. `NOXTLS_HMAC_SHA256_SHARED_STATE` and `NOXTLS_ECC_SHARED_SCRATCH` (both default OFF) switch to fixed shared storage for externally serialized builds. See [Memory usage](./memory-usage.md#concurrent-crypto-scratch-storage).
- **SPAKE2+** (P256-SHA256-HKDF-SHA256-HMAC-SHA256) with two per-context profiles: RFC 9383 (default) and the Matter draft-bar-cfrg-spake2plus-01 key schedule. Added **Matter PASE** helpers for passcode validation, w0/w1 and verifier generation, the PASE context hash, and session-key derivation. Both are off by default (`NOXTLS_CFG_FEATURE_SPAKE2P`, `NOXTLS_CFG_FEATURE_SPAKE2P_MATTER`, `NOXTLS_CFG_FEATURE_MATTER_PASE`). See [SPAKE2+ and Matter PASE](./spake2p.md) and the [SPAKE2+ API](./api/spake2p.md).
- **PBKDF2 (RFC 8018)** public API: `noxtls_pbkdf2_hmac()` over HMAC-SHA1, SHA-256, SHA-384, or SHA-512, with `noxtls_pbkdf2_self_test()` (RFC 6070 vectors). It erases the output on failure. When enabled, X.509 PBES2 private-key decryption uses it. Enable with `NOXTLS_CFG_FEATURE_PBKDF2` (default OFF). See [Key derivation API](./api/kdf.md).
- **AES key wrap (RFC 3394)**: `noxtls_aes_key_wrap()`, `noxtls_aes_key_unwrap()` (constant-time integrity check, output cleared on failure), and `noxtls_aes_keywrap_self_test()`. Built together with AES-ECB. See [AES key wrap](./api/aes_keywrap.md).
- **X.509 explicit verification policy.** `noxtls_x509_verify_cert_with_policy()` verifies a leaf and the intermediates it presents against caller-supplied trust anchors, required Key Usage (all-of), EKU, an optional CRL, and a system or explicit clock, without using the global trust store. It fails closed when the policy has no anchors. `noxtls_x509_certificate_check_validity_at()` checks validity at a caller-supplied time.
- **Strict raw X.509 extension lookup** (`noxtls_x509_ext.h`). Iterate extensions or find one by OID with strict DER checks, rejecting duplicate extensions per RFC 5280 section 4.2. `noxtls_x509_oid_is_under_arc()` checks private-enterprise arcs (for example Thread TCAT).
- **TLS 1.2 per-context client-certificate policy for servers.** `noxtls_tls12_set_client_verify_policy()` verifies client certificates only against the policy. Session-ID and ticket resumption are declined while a policy is set, so every connection re-authenticates. `noxtls_tls12_get_client_certificate()` returns the accepted client leaf. `noxtls_tls12_context_size()` detects `noxtls_config.h` mismatches between the library and the application.
- **Hardware acceleration ports** (all default OFF):
  - TI CC13xx AES and P-256 callback ports (`NOXTLS_CFG_FEATURE_CC13XX_HW_ACCEL`).
  - nRF54L CRACEN backend for nRF54LM20/nRF54L15 (`NOXTLS_CFG_FEATURE_NRF54_HW_ACCEL`): AES ECB/CBC/CTR/GCM/CCM, SHA-224/256/384/512, TRNG entropy, P-256 point multiply, ECDSA P-256 verify, and Ed25519 verify.
  - NoxV AES, SHA-256, and P-256 accelerator ports (`NOXTLS_CFG_FEATURE_NOXV_HW_ACCEL`).
- Optional precomputed ROM AES encryption tables (`NOXTLS_AES_ROM_TABLES`) for Nordic PTS builds.
- Static libraries are compiled with function and data sections on GNU and Clang, so firmware linkers can drop unused cryptographic routines.
- Also included from the upstream 0.2.72 line (not covered by the 0.2.71 notes):
  - configurable low-memory P-256 paths
  - allocation-failure diagnostics (`noxtls_mem_get_last_error()`)
  - Nordic P-256 hardware backends, including a direct CC310 backend
  - STM32U5 AES-IP and STM32F4 CRYP AES-GCM hardware paths
  - a faster portable GHASH
  - Ed25519 performance work
  - Ed448 streaming verification
- **Upgrading from 0.2.x:** see [Upgrading from 0.2.x](./misra-c.md#upgrading-from-02x) for the type, allocator, debug-output, and file-I/O changes, and **Behaviour changes and upgrade notes** under Fixed / Resolved below for changes introduced by this release's fixes.

### Fixed / Resolved

- **Security.** The twelve security fixes are summarized under Changes above and described in [Security fixes in 0.3.0](./security-fixes-0.3.0.md).
- **Message digests, HMAC, and key derivation:**
  - RIPEMD-160 produced a wrong digest for every input. This was a regression introduced during 0.3.0 development and is not present in 0.2.x releases. Its bit counter is now 64-bit (it previously overflowed at 512 MiB of input).
  - MD4 produced a wrong digest for non-empty messages whose length is a multiple of 64 bytes.
  - BLAKE2s and BLAKE2b produced wrong digests for inputs of one block or more; the implementation now follows RFC 7693, including the full 64-bit BLAKE2b counter.
  - MD5 streaming updates mishandled a buffered partial block and rejected a second short update.
  - All digests now match the reference vectors for both one-shot and chunked input.
  - A failed compression step (for example an accelerator error) could still return success with a wrong digest: SHA-224/256, SHA-384/512, and MD5 let the final padding block's status overwrite an earlier failure, and RIPEMD-160 ignored compression results. Digests now stop at the first failure and erase the output and the context, and the verify helpers never report a match after a hashing error. SHA-3 rejects NULL data with a non-zero length.
  - HMAC with SHA-1, SHA-384, or SHA-512 ignored the status of some inner and outer hash steps and could return success with a wrong MAC. Every status now propagates, and the MAC output, key pads, and hash state are erased on failure. HKDF expand and the PBKDF2 PRF return the underlying error and erase their outputs.
- **Symmetric ciphers and AEAD:**
  - ARIA one-shot CBC encryption did not chain the zero-padded final partial block; it now matches AES-CBC. ARIA decryption rejects lengths that are not a multiple of the block size, and CTR and CFB report key-setup errors.
  - ChaCha20-Poly1305 rejects `aad == NULL` with a non-zero `aad_len`, compares the tag in constant time, and erases the computed tag.
  - AES-CCM: removed an undefined shift for the maximum length-field size (L = 8).
  - nRF52: an AES-ECB operation preempted by an interrupt-side AES call could return a wrong block. The ECB transaction now runs with interrupts masked.
- **Bignum, DSA, RSA, and Diffie-Hellman:**
  - `noxtls_bn_mod_inv()` returned a wrong value with success for even moduli and when no inverse exists (for example 7^-1 mod 8 returned 2). It now computes correct inverses for odd and even moduli and returns `NOXTLS_RETURN_FAILED` with a zeroed result when the modulus is 1 or less or no inverse exists. The P-256 path is unchanged.
  - `noxtls_dh_generate_key()` could loop forever when the top byte of p was below 0x80. Private values are now drawn by bounded rejection sampling in [2, p - 2], and degenerate p or g values fail cleanly.
  - `noxtls_dh_shared_secret()` used the wrong end of an over-long peer value. A longer peer value is now accepted only when its extra leading bytes are zero.
  - FFDHE ephemeral keys applied the RFC 7919 exponent-length mask to the least significant byte instead of the most significant byte.
  - DH erases DRBG state and private buffers after use and zeroes outputs on failure.
  - `noxtls_bn_mod()` returned success with a zeroed result when an internal allocation failed. Allocation failures now return `NOXTLS_RETURN_NOT_ENOUGH_MEMORY`, every bignum error propagates with the result zeroed, and modular exponentiation reports memory and reduction errors instead of switching to its fallback path. Hardware bignum hooks fall back to software only on `NOXTLS_RETURN_NOT_SUPPORTED` or `NOXTLS_RETURN_FAILED`.
  - DSA key generation, signing, and verification ignored bignum errors. Under memory pressure, signing could return success with an invalid s, and key generation could return x = 1, y = g. Every result is now checked, only r = 0, s = 0, or a non-invertible k is retried, and outputs and secrets are erased on failure.
  - RSA: Miller-Rabin treated a failed exponentiation as "probably prime". Key generation, encryption, CRT decryption, and the blinded private-key operation now check every step and erase outputs on failure.
  - `noxtls_bn_mod_inv()` validates its lengths before writing to the result buffer. It previously zeroed the buffer before rejecting an oversized modulus length.
- **ECC, ECDSA, EdDSA, X25519, and X448:**
  - secp224k1: the 225-bit group order was truncated, so no ECDSA signature verified and generated keys were reduced incorrectly. All other curve constants were re-checked against SEC 2 and RFC 5639. Because r and s remain 28 bytes, a secp224k1 signature with s of 2^224 or more (probability about 2^-111) is retried when signing and rejected when verifying.
  - Point multiply-and-add failed when one point was a small multiple of the other (seen on secp256k1 and brainpoolP256r1), and P-256 gave a wrong result when one operand was the point at infinity. ECDSA verification now rejects an identity result.
  - `noxtls_ecdsa_sign()` returned success with r = 0 when its retries ran out. It now fails, zeroes the signature, and erases the nonce and its inverse.
  - nRF54 CRACEN: P-256 results are double-checked with an independent blinding factor, and the portable implementation is used if the two results disagree.
  - Under memory pressure, ECC point operations continued after a failed field operation: secp256k1 point multiplication could return success with a wrong point, and key generation could return the point at infinity as a public key. Field and point operations now return the first failure and zero their output. `noxtls_ecc_point_validate_public()` rejects the point at infinity and coordinates that are not less than p, and key generation redraws a zero private key, validates the public key, and erases both on failure. ECDSA, ECDH, X448, and Ed25519 propagate these errors in the same way.
  - After a single DRBG failure, ECC, ECDSA, X25519, X448, Ed25519, Ed448, and RSA key generation and signing failed for the rest of the process, because the internal generator stayed marked as initialized after its state was erased. A DRBG failure now uninstantiates the generator, and the next call re-instantiates it from entropy.
  - `noxtls_ecc_key_free()` erased a fixed 66 bytes of the private-key buffer even when the key's curve had been detached, overrunning a smaller buffer. It now erases the allocated length recorded in the new `d_size` field.
- **X.509 certificates and private keys:**
  - Encrypted PKCS#8 private keys could never be decrypted. Decryption now follows RFC 5958 and PBES2 (RFC 8018): PBKDF2 with the PRF named in the key, optional keyLength, AES-128/192/256-CBC with the IV from the parameters, and a padding check.
  - Ed25519 and Ed448 keys whose first byte was 0x04 (or 0x30) were parsed as EC (or RSA) keys. The key type now follows the algorithm OID, and Ed25519/Ed448 certificate signatures are verified.
  - Authority and Subject Key Identifiers never matched. Issuer lookup now prefers key-identifier matches, falls back to name matching, and always requires a valid signature.
  - SEC1 EC private keys kept no public key and were reported as PKCS#8. They now keep the embedded public key and are reported as SEC1, and a stored public key that does not match the private key is rejected.
  - Certificate generation issued a certificate without its extensions when extension encoding failed. It now fails instead.
  - A malformed BOOLEAN in a certificate extension could move the parser past the end of the extension. A BOOLEAN must now be one byte with the value 0x00 or 0xFF, a malformed critical flag or basicConstraints cA value is rejected with `NOXTLS_RETURN_BAD_DATA`, and every cursor advance is checked against the bytes remaining.
  - PKCS#1 private-key parsing returned success with missing key components after an allocation failure. Certificate, PKCS#1, PKCS#8, SEC1, encrypted PKCS#8, PEM, and file loading now erase and free partial results and return `NOXTLS_RETURN_NOT_ENOUGH_MEMORY`, and the DER parse dispatchers stop trying other formats after an allocation failure.
  - `noxtls_x509_parse_time()` returned success without writing or terminating the output when `output_size` was less than 20. It now returns `NOXTLS_RETURN_INVALID_PARAM` with an empty string and always NUL-terminates its output. This was found by fuzzing.
- **TLS 1.2:**
  - The client's signature_algorithms extension carried uninitialized bytes, so servers that require an ECDSA scheme rejected the handshake. This was a regression introduced during 0.3.0 development and is not present in 0.2.x releases.
  - The client could not verify DHE-RSA ServerKeyExchange signatures from servers with standard certificates. One verifier now handles DHE and ECDHE, uses the signature scheme the server actually signed with, and requires that scheme to be one the client offered. The ClientHello now also offers rsa_pkcs1_sha512, ecdsa_secp521r1_sha512, and rsa_pss_rsae_sha256/384/512, which the client already verified.
  - `noxtls_tls10_connect()` and `noxtls_tls11_connect()` rejected the TLS 1.0/1.1 ServerHello they had negotiated. The client now accepts exactly the version it offered.
  - The server rejected every X448 ClientKeyExchange; it now accepts X448 and rejects an all-zero shared secret.
  - The client rejected DHE-RSA AES-CCM suites it had offered; it now accepts exactly the suites it offered.
  - A DHE generator g in its minimal encoding was rejected; g is now checked numerically.
  - Trailing bytes after Certificate or ClientKeyExchange are rejected unless they form the next handshake message, and the RSA CertificateVerify length check (which compared bytes to bits) now works.
  - Zero-length records could not be sent with AEAD cipher suites.
  - `noxtls_tls12_context_free()` now erases the premaster and master secrets, traffic keys, IVs, MAC keys, Finished data, and buffered application plaintext held in the context.
  - With a handshake workspace smaller than the fixed message layouts (for example `NOXTLS_TLS_HANDSHAKE_WORKSPACE_SIZE` = 2048), message builders overran the heap block. They now use a dedicated allocation instead.
- **TLS 1.3, DTLS, and the unified connection API:**
  - The TLS 1.3 client could crash after a HelloRetryRequest that selected a group other than X25519.
  - The TLS 1.3 client always sent an X25519 key share. It now offers a share for the first configured (EC)DHE group and, after a HelloRetryRequest, exactly one share for the group the server selected, which must be a group the client offered. The server now rejects a second ClientHello that does not carry exactly one share for the group its HelloRetryRequest selected.
  - Post-handshake messages (NewSessionTicket, KeyUpdate) and alerts are processed from an internal buffer, independent of the size of the buffer passed to the read call. A post-handshake message larger than that buffer previously closed the connection.
  - A TLS 1.3 server could select only the last PSK identity offered; selecting any other identity failed. Any offered identity can now be selected, and the identities and binders are fully validated (one binder of at least 32 bytes per identity).
  - The TLS 1.3 client ignored parse errors in EncryptedExtensions. EncryptedExtensions and ServerHello extensions are now validated: a duplicate extension aborts with illegal_parameter and a malformed list with decode_error.
  - 0-RTT: when early data was offered with a PSK, the server now adds the client's EndOfEarlyData to the handshake transcript instead of failing the handshake.
  - DTLS 1.3 post-handshake messages (KeyUpdate, NewSessionTicket, NewConnectionId, RequestConnectionId) were sent under the handshake keys and parsed with TLS framing, so a KeyUpdate ended the connection. They now use the current application keys and DTLS handshake framing, and are acknowledged with ACK records.
  - DTLS 1.3 connection IDs longer than one byte could not be received. The full negotiated length (up to 255 bytes) is now supported.
  - DTLS: a lost first ClientHello was never retransmitted, because epoch 0, sequence 0 was treated as acknowledged before any ACK arrived.
  - DTLS 1.3: a retransmission timeout while waiting for the encrypted server flight aborted the handshake. The client now retransmits and keeps waiting, and the server answers a retransmitted first ClientHello with its HelloRetryRequest again.
  - DTLS 1.2: zero-length handshake messages such as ServerHelloDone were neither sent nor accepted, so DTLS 1.2 handshakes could not complete. They are now sent and accepted as a single empty fragment (RFC 6347 section 4.2.3).
  - DTLS 1.3 record-number protection used a 16-byte key for every cipher suite, but AES-256-GCM and ChaCha20-Poly1305 need a 32-byte key (RFC 9147 section 4.2.3), so the record-number mask was computed with the wrong key and read past the stored key. The key now has the AEAD key length.
  - DTLS 1.3 fatal alerts sent after the handshake were protected with the handshake epoch's record-number key, so peers could not read them. They now use the current epoch's keys. After three KeyUpdates (epoch 6, which shares its 2-bit header value with the handshake epoch), the receiver also chose the handshake key; it now selects the key from the full epoch.
  - DTLS: an allocation failure while reassembling a fragmented handshake message led to a NULL pointer dereference on the next fragment. Reassembly state is now committed only after its buffers are allocated and is reset after each message is delivered, which also fixes reassembly of a following message of the same length. An unfragmented retransmission discards partial state.
  - DTLS 1.3 server: an allocation failure while storing the client's key shares left a non-zero share count with no array, which the server then dereferenced. Key shares are now published only after the allocation succeeds. Lengths are also cleared after failed allocations of pending application data and certificates.
  - Unified API: a client using `noxtls_tls_connection_connect()` with automatic version selection on a non-blocking (caller-polled) transport returned `NOXTLS_RETURN_NEGOTIATED_TLS12` instead of continuing with TLS 1.2. It now downgrades to TLS 1.2 as a blocking client does. A client restricted to TLS 1.3 sends a protocol_version alert when the server selects TLS 1.2.
  - `noxtls_tls13_get_channel_binding()` returned 32 bytes for tls-server-end-point with a SHA-224-signed server certificate; it now returns the 28-byte SHA-224 hash, and reports the required length when the buffer is too small. `noxtls_tls13_export_keying_material()` rejects output longer than 255 times the hash length and labels longer than 249 bytes with `NOXTLS_RETURN_INVALID_PARAM`.
- **Platform ports and build:**
  - Ed25519 on Cortex-M: the packed-assembly field glue gave wrong results, and software verification failed the RFC 8032 vectors. The conversion is fixed and the packed assembly is now **opt-in** (`NOXTLS_ED25519_FE_USE_PACKED_ASM`). The portable path, now the default for all Cortex-M builds, measured faster: 113 ms vs 260 ms per verification on nRF54LM20 at 128 MHz.
  - MISRA reference helpers (`noxtls_misra_refs.h`) now compile with MSVC and other non-GNU compilers, and `getopt_win.h` includes `<stdint.h>`.
- **Behaviour changes and upgrade notes.** These fixes change behaviour that integrators may notice:
  - **Hardware accelerator errors are no longer hidden.** Software fallback now happens only when the accelerator returns `NOXTLS_RETURN_NOT_SUPPORTED`. Any other accelerator error or timeout is returned to the caller, and partial outputs are erased first. This applies to the AES modes, CMAC, CCM, GCM, XTS, the DRBG, and ECC point multiplication. A port that wants software fallback must return `NOXTLS_RETURN_NOT_SUPPORTED`.
  - **Removed `noxtls_ecdsa_sign_last_nonce`.** Code that references it no longer compiles or links. There is no replacement.
  - **TLS 1.2 servers that request or require client certificates do not resume sessions.** Every connection to such a server runs a full handshake, so expect the cost of a full handshake per connection. Cached sessions are also bound to the issuing server's certificates, protocol version, and certificate type, so a session issued under one server configuration is not resumed under another.
  - **Strict PKCS#1 v1.5 signature verification.** Signatures are checked by re-encoding the full block. The only non-canonical form accepted is a DigestInfo without the NULL parameters (RFC 8017 section 9.2, note 1).
  - **TLS 1.2 client declines renegotiation.** A HelloRequest is answered with a protected no_renegotiation warning alert, and a malformed HelloRequest is a decode_error.
  - **Duplicate TLS extensions are rejected** with illegal_parameter (TLS 1.2 and TLS 1.3). The TLS 1.3 client also aborts on malformed EncryptedExtensions or ServerHello extensions.
  - **TLS 1.2 client accepts only what it offered:** the protocol version, the cipher suite, and the ServerKeyExchange signature scheme must each be one the client offered.
  - **TLS 1.3 key share follows the configuration.** The client's first key share is for its first configured (EC)DHE group instead of always X25519, which can change whether a server sends a HelloRetryRequest.
  - **Encrypted PKCS#8 keys now decrypt.** `noxtls_x509_private_key_parse_der_with_password()` and `noxtls_x509_private_key_parse_pem_with_password()` decrypt standard PBES2 keys. A PRF other than hmacWithSHA1 (for example hmacWithSHA256) requires `NOXTLS_CFG_FEATURE_PBKDF2`; otherwise it returns `NOXTLS_RETURN_INVALID_ALGORITHM`. hmacWithSHA224 is not supported.
  - **SEC1 keys are reported as SEC1.** `EC PRIVATE KEY` keys report `X509_PRIVATE_KEY_FORMAT_SEC1` instead of PKCS#8, only SEC1 version 1 is accepted, and a stored public key that does not match the private key is rejected.
  - **ECC curve parameters gain `n_size`** (length of the group order in bytes; 0 means the coordinate size) and `noxtls_ecc_curve_order_size()`. Code that builds its own curve parameters, or assumes the order is as long as a coordinate, should use them.
  - **Stricter argument checks.** ARIA and Camellia return `NOXTLS_RETURN_INVALID_KEY_SIZE` for an unsupported key type, Camellia ECB and CBC decryption return `NOXTLS_RETURN_INVALID_BLOCK_SIZE` for lengths that are not a multiple of 16, and NULL arguments return `NOXTLS_RETURN_NULL`. These calls previously returned success.
  - **Failures that used to report success now fail:** `noxtls_sha1_verify()` on a mismatch, `noxtls_bn_mod_inv()` when no inverse exists, `noxtls_ecdsa_sign()` when its retries run out, DH key generation with degenerate parameters, and certificate generation when an extension cannot be encoded (including unknown EKU bits and over-long SAN lists).
  - **CertificateVerify signed-content builders check the buffer size.** `noxtls_tls13_certificate_verify_build_signed_content()` and `noxtls_tls13_certificate_verify_build_signed_content_ex()` read the capacity from `*out_len`. When it is too small they write nothing, set `*out_len` to the required length, and return `NOXTLS_RETURN_INVALID_PARAM`. The new `NOXTLS_TLS13_CV_SIGNED_CONTENT_MAX_LEN` (162 bytes) always suffices. Check the return code and make sure `*out_len` holds the buffer size on input.
  - **Channel binding and exporter limits.** `noxtls_tls13_get_channel_binding()` sets `*out_len` to the required length when the buffer is too small (it still returns `NOXTLS_RETURN_FAILED`), and tls-server-end-point returns 28 bytes for a SHA-224-signed server certificate. `noxtls_tls13_export_keying_material()` returns `NOXTLS_RETURN_INVALID_PARAM` for output longer than 255 times the hash length or a label longer than 249 bytes.
  - **Non-blocking automatic clients downgrade to TLS 1.2 transparently.** `noxtls_tls_connection_connect()` on a caller-polled transport no longer returns `NOXTLS_RETURN_NEGOTIATED_TLS12`. Keep calling it while it returns `NOXTLS_RETURN_WANT_READ` or `NOXTLS_RETURN_WANT_WRITE`, as for TLS 1.3. Remove any code that handled `NOXTLS_RETURN_NEGOTIATED_TLS12` by restarting the connection as TLS 1.2.
  - **DTLS 1.3 record-number keys follow the AEAD key length** (RFC 9147). Earlier builds derived a 16-byte key for every suite, so DTLS 1.3 with TLS_AES_256_GCM_SHA384 or TLS_CHACHA20_POLY1305_SHA256 did not interoperate with other implementations. These suites now interoperate with RFC 9147 peers but not with earlier NoxTLS builds, so upgrade both ends of such links together. AES-128 suites are not affected.
  - **`ecc_key_t` gains `d_size`**, the allocated length of the private key. `noxtls_ecc_key_init()` sets it and `noxtls_ecc_key_free()` uses it to erase the key. It occupies existing padding, so the structure size is unchanged. Code that fills in an `ecc_key_t` without `noxtls_ecc_key_init()` should set it: a `d_size` of 0 means the private key is not erased when the key is freed.
  - **Stricter ECC public-key validation.** `noxtls_ecc_point_validate_public()` rejects the point at infinity and coordinates greater than or equal to p, so ECDH and ECDSA reject such peer keys.
  - **DRBG failures are recoverable.** After a DRBG failure in ECC, ECDSA, X25519, X448, Ed25519, Ed448, or RSA, the failing call returns its error and the next call re-instantiates the generator from entropy, instead of every later call failing.
  - **Internal failures are reported instead of producing a wrong result.** Under memory pressure, or after a hash or accelerator failure, the bignum, DSA, RSA, ECC, digest, HMAC, HKDF, PBKDF2, and X.509 parsing functions now return an error (allocation failures return `NOXTLS_RETURN_NOT_ENOUGH_MEMORY`) and erase their outputs. `noxtls_x509_parse_time()` returns `NOXTLS_RETURN_INVALID_PARAM` for an output buffer smaller than 20 bytes, and malformed BOOLEAN values in certificate extensions are rejected.
  - **Ed25519 packed Cortex-M assembly is opt-in.** Define `NOXTLS_ED25519_FE_USE_PACKED_ASM` to use it; the portable path is the default.
  - **PBKDF2 is off by default** (`NOXTLS_CFG_FEATURE_PBKDF2`). The public header is `kdf/noxtls_pbkdf.h`; `kdf/noxtls_pbkdf2.h` remains as a compatibility header that includes it.
  - **Configure the X.509 trust store at start-up**, not per connection: clearing the store keeps earlier snapshots alive because other threads may still be reading them.
- **Testing.** The unit-test suite grew from 1,382 to 2,409 test cases, including regression tests for the fixes above and failure-injection tests that fail each allocation, hash step, or DRBG call in turn across bignum, DSA, RSA, ECC, X.509, digest, HMAC, and TLS 1.3/DTLS 1.3 handshake paths. Library line coverage rose from about 49% to about 95%, function coverage from about 64% to about 99%, and branch coverage from about 33% to about 86%. These figures were measured on the GCC host build and do not include code that runs only on target hardware (hardware accelerator ports, Cortex-M assembly) or features compiled out of the test build.

### Known issues / Open

- This repository has no MISRA C:2025 scan result for the final merged 0.3.0 tree. Modules merged on the release branch after the recorded scans have no separate MISRA result: SPAKE2+/Matter PASE, the raw X.509 extension walker, and the CC13xx, nRF54 CRACEN, and NoxV ports.
- The 24 Required MISRA findings reported by the integration scan have draft technical dispositions that still need project sign-off. Advisory findings are not addressed in this release.
- nRF54 CRACEN P-256 hardware validation remains open.
- SPAKE2+ point addition uses the generic NoxTLS helpers, which are not constant-time. Scalar multiplications go through `noxtls_ecc_point_multiply()`.
- DTLS 1.3 interop hardening continues against external test suites.
- TLS 1.2 DHE: the client requires the server's DHE group to match the cipher suite's default group, so a server that selects a different group (for example OpenSSL choosing ffdhe2048 for an AES-256 DHE suite) is refused. This is an interoperability gap, not a security issue; ECDHE suites are not affected.
- `noxtls_bn_mod_inv()` runs in variable time outside the P-256 path, as in earlier releases, so DSA computes the inverse of its secret per-signature nonce in variable time.
- ARIA one-shot CBC zero-pads a partial final block, while the ARIA streaming API and the one-shot ECB function use PKCS#7 padding. For input that is not a multiple of 16 bytes the results differ, so use the same API on both sides or pass whole blocks.
- The TLS 1.2 client session cache is shared by every client context in the process, so separate client connections in one process may resume each other's sessions.
- Some sample applications do not build with GCC 14 or later.
- The ML-KEM, ML-DSA, and SLH-DSA helpers do not uninstantiate their per-call DRBG, so its state remains on the stack after use.
- The TLS 1.3 transcript hash supports only SHA-256 and SHA-384. Building CertificateVerify signed content for a SHA-512 signature scheme without a cipher suite (`noxtls_tls13_certificate_verify_build_signed_content()`, or the `_ex` variant with `cipher_suite` 0) returns `NOXTLS_RETURN_INVALID_ALGORITHM`.
- secp224k1 private keys are stored in 28 bytes while the group order is 29 bytes, so an imported private key in [2^224, n - 1] (about 2^-111 of the key space) cannot be represented. Generated keys are not affected.
- Memory headroom on embedded targets: with the 32 KiB embedded memory pool, a P-256 key with ECDH and ECDSA peaks at 26,928 bytes, and ECDSA verification uses about 132 bytes more stack than before the 0.3.0 ECC fixes. Check heap and stack headroom on memory-constrained Cortex-M targets.