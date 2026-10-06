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
- **Upgrading from 0.2.x:** see [Upgrading from 0.2.x](./misra-c.md#upgrading-from-02x) for the type, allocator, debug-output, and file-I/O changes.

### Fixed / Resolved

- Hardware accelerator failures are no longer hidden. Software fallback now happens only when the accelerator reports the operation as not supported. Real accelerator errors and timeouts are returned to the caller, and partial outputs are erased first. This applies to the AES modes, CMAC, CCM, GCM, XTS, the DRBG, and ECC point multiplication.
- TLS 1.2: `noxtls_tls12_context_free()` now erases the premaster and master secrets, traffic keys, IVs, MAC keys, Finished data, and buffered application plaintext held in the context.
- TLS 1.2: with a handshake workspace smaller than the fixed message layouts (for example `NOXTLS_TLS_HANDSHAKE_WORKSPACE_SIZE` = 2048), message builders overran the heap block. They now use a dedicated allocation instead.
- Ed25519 on Cortex-M: the packed-assembly field glue gave wrong results, and software verification failed the RFC 8032 vectors. The conversion is fixed and the packed assembly is now **opt-in** (`NOXTLS_ED25519_FE_USE_PACKED_ASM`). The portable path, now the default for all Cortex-M builds, measured faster: 113 ms vs 260 ms per verification on nRF54LM20 at 128 MHz.
- nRF52: an AES-ECB operation preempted by an interrupt-side AES call could return a wrong block. The ECB transaction now runs with interrupts masked.
- nRF54 CRACEN: P-256 results are double-checked with an independent blinding factor, and the portable implementation is used if the two results disagree.
- AES-CCM: removed an undefined shift for the maximum length-field size (L = 8).
- MISRA reference helpers (`noxtls_misra_refs.h`) now compile with MSVC and other non-GNU compilers, and `getopt_win.h` includes `<stdint.h>`.

### Known issues / Open

- This repository has no MISRA C:2025 scan result for the final merged 0.3.0 tree. Modules merged on the release branch after the recorded scans have no separate MISRA result: SPAKE2+/Matter PASE, the raw X.509 extension walker, and the CC13xx, nRF54 CRACEN, and NoxV ports.
- The 24 Required MISRA findings reported by the integration scan have draft technical dispositions that still need project sign-off. Advisory findings are not addressed in this release.
- nRF54 CRACEN P-256 hardware validation remains open.
- SPAKE2+ point addition uses the generic NoxTLS helpers, which are not constant-time. Scalar multiplications go through `noxtls_ecc_point_multiply()`.
- DTLS 1.3 interop hardening continues against external test suites.