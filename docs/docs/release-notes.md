---
sidebar_position: 8
title: Release Notes
---

# Release Notes

This page describes changes, fixes, and known issues for **NoxTLS 0.3.8**.

For source and binary artifacts, see [Releases on GitHub](https://github.com/argenox/noxtls/releases).

Use the **version dropdown** in the navbar to view docs (and release notes) for other versions.

---

## 0.3.8

**Release date:** TBD

### Changes

- Patch release on top of 0.3.7 for native library section granularity. GNU and Clang C/C++ builds use private function/data section flags on supported platforms; applications control final linker garbage collection.
- No API, ABI, protocol or optimization-level changes. Apple and MSVC-compatible builds keep their existing compiler options.

### Fixed / Resolved

- Certificate, utility, SHA-3, PAKE and optional nRF54 libraries now receive section flags alongside the core libraries. Direct subdirectory builds no longer depend on the root target list.

### Known issues / Open

- Earlier release limitations still apply. Applications must enable linker garbage collection to discard unused sections.

---

## 0.3.7

**Release date:** TBD

### Changes

- Patch release on top of 0.3.6 combining shared Zephyr integration, cooperative crypto service hooks and embedded DTLS/DFU support. Rebuild the library and callers together with the same configuration.
- Zephyr consumers share one NoxTLS configuration and CPU ABI across archives. Kernel monotonic time is used without a Newlib _times shim.
- Software P-256 arithmetic calls the cooperative ECC service hook between bounded operations, including field inversion. The default hook does nothing; ports can provide their task-aware implementation.
- NoxV CCM acceleration is opt-in and checks engine ownership, input limits and completion. Platforms can use NoxV AES/SHA without enabling P-256 acceleration.
- Embedded profiles can select the TLS 1.3 ticket-store capacity. Optional CC13xx SHA-512 block callbacks support SHA-384, SHA-512, SHA-512/224 and SHA-512/256 under the existing AES/SHA guard.

### Fixed / Resolved

- DTLS 1.3 discards duplicate or stale records without failing the connection or delivering their plaintext. Fresh records following a duplicate in the same datagram are preserved; duplicate-discard loops remain bounded.
- Zephyr and ESP-IDF configuration generation handles initializer lists and enum constants without exposing them as scalar Kconfig settings.
- Mocked NoxV ECC, SHA-256 and CCM regression tests use explicit test I/O bindings and consistent accelerator profiles on GCC and MSVC.

### Known issues / Open

- Earlier release limitations still apply except where explicitly fixed above. DTLS 1.2 EC-JPAKE interoperability remains unqualified.
- The combined revision passes local crypto/DTLS tests, shared and secure-feature Zephyr QEMU tests, and CC1354/CC35x1 application builds. Hardware was not reflashed for this consolidation.

---

## 0.3.6

**Release date:** TBD

### Changes

- Patch update to 0.3.5 for DTLS 1.3 recovery, embedded memory use and optional CC13xx accelerator bindings. Rebuild the library and callers together: the DTLS context gains one callback pointer for encrypted-flight retransmission.
- Optional CC13xx CCM, SHA-224/256 and X25519 callbacks complement AES/GCM/P-256. AES and PKA engines bind independently, with software fallback for unbound or busy engines before admission. No vendor SDK driver dependency or new fixed record buffer is added.

### Fixed / Resolved

- DTLS 1.3 clients aborted when an encrypted handshake record arrived before final ServerHello. Undecryptable pre-key records are now discarded without acknowledging them or changing replay state, allowing retransmission to recover. Existing trailing-record handling and the bounded receive loop are preserved.
- DTLS 1.3 encrypted handshake flights were not retained for retransmission. Lost server records, client Finished or final ACK could leave a half-open session and cause Secure CoAP timeouts. Flights now retransmit with fresh record sequence numbers; verified client Finished releases the completed server flight.
- The TLS 1.3 key-share parser allocated 512 descriptors for a single X25519 share. It now validates the vector and allocates only the actual entry count.
- Classical-only ClientHello staging used large post-quantum-sized stack arrays, causing a measured embedded task stack overflow. Classical builds now use bounded 160-byte staging; ML-KEM builds retain their existing capacities.
- TLS-only builds with DTLS disabled now retain the compile guards needed by the recovery code.

### Known issues / Open

- Earlier release limitations still apply except where explicitly fixed above. DTLS 1.2 EC-JPAKE interoperability remains unqualified.
- Recovery is covered by native loss/reordering tests and bounded CC1354/CC35x1 Secure CoAP hardware runs. These tests do not qualify every cipher suite or long-duration operation.

---

## 0.3.5

**Release date:** TBD

### Changes

- Patch release on top of 0.3.4 that adds two opt-in features; builds that do not enable them keep their behavior, configuration defaults and wire format.
- **EC-JPAKE** (`NOXTLS_CFG_FEATURE_ECJPAKE`, default OFF): EC J-PAKE over P-256 (RFC 8236 section 3) with SHA-256 Schnorr NIZK proofs (RFC 8235 section 3) in the TLS form of draft-cragie-tls-ecjpake-01. API in `noxtls-lib/pake/noxtls_ecjpake.h`.
- **DTLS 1.2 EC-JPAKE suite** (`NOXTLS_CFG_FEATURE_DTLS_ECJPAKE`, default OFF): `TLS_ECJPAKE_WITH_AES_128_CCM_8` (0xC0FF) with the `ecjpake_key_kp_pair` extension (256), the EC-JPAKE ServerKeyExchange / ClientKeyExchange and AES-128-CCM-8 records, as used by Thread MeshCoP commissioning. New API: `noxtls_tls12_set_ecjpake_password()`, `noxtls_tls12_ecjpake_negotiated()`, `noxtls_tls12_ecjpake_export_key_block()`. `noxtls_tls12_connect_poll()` / `noxtls_tls12_accept_poll()` also drive DTLS 1.2 for EC-JPAKE contexts.
- Zephyr and ESP-IDF Kconfig expose both switches.

### Known issues / Open

- The known issues listed for 0.3.0 still apply.
- No public known-answer vectors exist for the complete EC-JPAKE TLS exchange; interoperability with other Thread implementations has not yet been tested on hardware.

---

## 0.3.4

**Release date:** TBD

### Changes

- Patch release on top of 0.3.3. Build fix only; no API, ABI, configuration, or wire-format changes, and no change to generated code. 0.3.4 is a drop-in replacement for 0.3.3.

### Fixed / Resolved

- **Cortex-M7 and STM32 accelerated builds failed with `'NULL' undeclared`.** `noxtls_sha256_cortexm7.c`, `noxtls_stm32_hash_core.c` and `noxtls_aes_accel_stm32_port.c` used `NULL` and `size_t` without including `<stddef.h>`. They used to get the definitions indirectly through `<stdio.h>` in other NoxTLS headers, which the 0.3.0 MISRA cleanup removed, so every build that compiles the Cortex-M7 SHA-256 core or the STM32 hash/AES ports failed (for example STM32F767 and STM32H7 targets). Each file now includes `<stddef.h>` itself.

### Known issues / Open

- The known issues listed for 0.3.0 still apply.