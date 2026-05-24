/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
* 
*
* File:    noxtls_config.h
* Summary: NoxTLS Configuration Header
*
* This header file defines configuration options that control which modules
* and features are enabled in the NoxTLS library. These can be overridden
* by defining them before including this header, or via compiler defines.
*
*/

#ifndef _NOXTLS_CONFIG_H_
#define _NOXTLS_CONFIG_H_

/* ============================================================================
 * Application-local configuration for: aes
 * Workload: AES file encrypt/decrypt
 * ============================================================================
 *
 * This file is a SELF-CONTAINED copy of the NoxTLS configuration. Per project
 * policy, application code MUST NOT include the top-level noxtls_config.h --
 * each application owns its own configuration so it can be tuned and built
 * independently. The library libraries (.lib / .a) are still produced from
 * the top-level config; this file controls what application translation
 * units see when they include "noxtls_config.h".
 *
 * To customize this app, edit values below directly; do NOT add a
 * `#include "../../noxtls_config.h"` line.
 */

/* Size of the application-private static workspace (bump arena) declared in
 * the app's main translation unit. Replaces heap allocations for the app's
 * own working buffers. Sized per app for its worst-case workload. */
#ifndef NOXTLS_APP_STATIC_BUFFER_SIZE
#define NOXTLS_APP_STATIC_BUFFER_SIZE (64U * 1024U)
#endif

/* ============================================================================
 * Profile selection
 * ============================================================================
 *
 * Select one profile by defining one of:
 *   NOXTLS_PROFILE_MINIMAL_TLS_CLIENT
 *   NOXTLS_PROFILE_TLS_SERVER_PKI
 *   NOXTLS_PROFILE_CRYPTO_ONLY
 *   NOXTLS_PROFILE_FIPS_LIKE
 *   NOXTLS_PROFILE_UT_ALL_FEATURES
 *
 * If none is defined, the build uses per-feature defaults below.
 */

#if (defined(NOXTLS_PROFILE_MINIMAL_TLS_CLIENT) + \
     defined(NOXTLS_PROFILE_TLS_SERVER_PKI) + \
     defined(NOXTLS_PROFILE_CRYPTO_ONLY) + \
     defined(NOXTLS_PROFILE_FIPS_LIKE) + \
     defined(NOXTLS_PROFILE_UT_ALL_FEATURES)) > 1
#error "Only one NOXTLS_PROFILE_* may be defined at a time."
#endif

/* Side-channel profile selection
 *
 * Select one side-channel profile by defining one of:
 *   NOXTLS_SIDECHANNEL_PROFILE_PERFORMANCE
 *   NOXTLS_SIDECHANNEL_PROFILE_BALANCED
 *   NOXTLS_SIDECHANNEL_PROFILE_CONSTANT_TIME_STRICT
 *
 * If none is defined, BALANCED is selected by default.
 */
#if (defined(NOXTLS_SIDECHANNEL_PROFILE_PERFORMANCE) + \
     defined(NOXTLS_SIDECHANNEL_PROFILE_BALANCED) + \
     defined(NOXTLS_SIDECHANNEL_PROFILE_CONSTANT_TIME_STRICT)) > 1
#error "Only one NOXTLS_SIDECHANNEL_PROFILE_* may be defined at a time."
#endif

#if !defined(NOXTLS_SIDECHANNEL_PROFILE_PERFORMANCE) && \
    !defined(NOXTLS_SIDECHANNEL_PROFILE_BALANCED) && \
    !defined(NOXTLS_SIDECHANNEL_PROFILE_CONSTANT_TIME_STRICT)
#define NOXTLS_SIDECHANNEL_PROFILE_BALANCED 1
#endif

/* Enable constant-time secret compare in balanced/strict profiles. */
#ifndef NOXTLS_CT_COMPARE
#if defined(NOXTLS_SIDECHANNEL_PROFILE_PERFORMANCE)
#define NOXTLS_CT_COMPARE 0
#else
#define NOXTLS_CT_COMPARE 1
#endif
#endif

/* ============================================================================
 * Feature Configuration (defaults)
 * ============================================================================
 */

/* Core modules */
/* Enables hash framework and hash algorithm implementations.
 * Prereq: none.
 * Required by: certificates and TLS stacks.
 */
#define NOXTLS_FEATURE_HASH 1

/* Enables symmetric encryption module family (AES/ARIA/Camellia/ChaCha/DES).
 * Prereq: none.
 * Required by: DRBG and TLS record protection.
 */
#define NOXTLS_FEATURE_ENCRYPTION 1

/* Enables deterministic random bit generator (CTR-DRBG implementation).
 * Prereq: NOXTLS_FEATURE_ENCRYPTION=1 and NOXTLS_FEATURE_AES=1.
 */
#define NOXTLS_FEATURE_DRBG 1

/* Enables public-key cryptography module family (RSA/ECC/curve algorithms).
 * Prereq: none.
 * Required by: certificates and most TLS key exchange/signature flows.
 */
#define NOXTLS_FEATURE_PKC 1

/* Enables X.509 certificate parsing/verification/generation support.
 * Prereq: NOXTLS_FEATURE_HASH=1 and NOXTLS_FEATURE_PKC=1.
 * Required by: certificate-authenticated TLS.
 */
#define NOXTLS_FEATURE_CERT 1

/* Hostname verification policy for certificate matching.
 * When 1, SAN/CN entries with left-most wildcard ("*.example.com") are accepted.
 * When 0, only exact SAN/CN DNS matches are accepted.
 * Runtime may override this default through noxtls_x509_set_hostname_wildcard_matching().
 */
#ifndef NOXTLS_X509_HOSTNAME_ALLOW_WILDCARD
#define NOXTLS_X509_HOSTNAME_ALLOW_WILDCARD 1
#endif

/* Enables TLS protocol implementation.
 * Prereq: NOXTLS_FEATURE_HASH=1, NOXTLS_FEATURE_ENCRYPTION=1,
 *         NOXTLS_FEATURE_DRBG=1, NOXTLS_FEATURE_PKC=1, NOXTLS_FEATURE_CERT=1.
 */
#define NOXTLS_FEATURE_TLS 1

/* Hash primitives */
/* Enables MD4 hashing algorithm.
 * Prereq: NOXTLS_FEATURE_HASH=1.
 * Security note: legacy algorithm; generally disable for modern deployments.
 */
#ifndef NOXTLS_FEATURE_MD4
#define NOXTLS_FEATURE_MD4 0
#endif

/* Enables MD5 hashing algorithm.
 * Prereq: NOXTLS_FEATURE_HASH=1.
 * Security note: legacy algorithm; generally disable for modern deployments.
 */
#define NOXTLS_FEATURE_MD5 1

/* Enables SHA-1 hashing algorithm.
 * Prereq: NOXTLS_FEATURE_HASH=1.
 * Security note: legacy algorithm; generally disable for modern deployments.
 */
#define NOXTLS_FEATURE_SHA1 1

/* Enables SHA-224 hashing algorithm (same implementation as SHA-256).
 * Prereq: NOXTLS_FEATURE_HASH=1.
 * Build: sha256.c is compiled when NOXTLS_FEATURE_SHA224 or NOXTLS_FEATURE_SHA256 is 1.
 */
#define NOXTLS_FEATURE_SHA224 1

/* Enables SHA-256 hashing algorithm.
 * Prereq: NOXTLS_FEATURE_HASH=1.
 * Required by: TLS and certificate verification flows.
 * Build: sha256.c is compiled when NOXTLS_FEATURE_SHA224 or NOXTLS_FEATURE_SHA256 is 1.
 */
#define NOXTLS_FEATURE_SHA256 1

/* Enables SHA-384 hashing algorithm (same implementation as SHA-512).
 * Prereq: NOXTLS_FEATURE_HASH=1.
 * Build: sha512.c is compiled when NOXTLS_FEATURE_SHA384 or NOXTLS_FEATURE_SHA512 is 1.
 */
#define NOXTLS_FEATURE_SHA384 1

/* Enables SHA-512 and truncated variants (SHA-512/224, SHA-512/256).
 * Prereq: NOXTLS_FEATURE_HASH=1.
 * Build: sha512.c is compiled when NOXTLS_FEATURE_SHA384 or NOXTLS_FEATURE_SHA512 is 1.
 */
#define NOXTLS_FEATURE_SHA512 1

/* Enables SHA-3 hashing algorithms.
 * Prereq: NOXTLS_FEATURE_HASH=1.
 */
#define NOXTLS_FEATURE_SHA3 1

/* Enables RIPEMD-160 hashing algorithm.
 * Prereq: NOXTLS_FEATURE_HASH=1.
 */
#define NOXTLS_FEATURE_RIPEMD160 1

/* Enables BLAKE2 hash family.
 * Prereq: NOXTLS_FEATURE_HASH=1.
 */
#define NOXTLS_FEATURE_BLAKE2 1

/* Symmetric primitives */
/* Enables AES cipher family.
 * Prereq: NOXTLS_FEATURE_ENCRYPTION=1.
 * Constraint: at least one NOXTLS_FEATURE_AES_* mode and one NOXTLS_FEATURE_AES_* key size must be enabled.
 */
#define NOXTLS_FEATURE_AES 1

/* Enables AES-128 key schedule/path.
 * Prereq: NOXTLS_FEATURE_AES=1.
 */
#define NOXTLS_FEATURE_AES_128 1

/* Enables AES-192 key schedule/path.
 * Prereq: NOXTLS_FEATURE_AES=1.
 */
#define NOXTLS_FEATURE_AES_192 1

/* Enables AES-256 key schedule/path.
 * Prereq: NOXTLS_FEATURE_AES=1.
 */
#define NOXTLS_FEATURE_AES_256 1

/* Enables AES-ECB mode.
 * Prereq: NOXTLS_FEATURE_AES=1.
 * Security note: ECB is usually not suitable for bulk data confidentiality.
 */
#define NOXTLS_FEATURE_AES_ECB 1

/* Enables AES-CBC mode.
 * Prereq: NOXTLS_FEATURE_AES=1.
 */
#define NOXTLS_FEATURE_AES_CBC 1

/* Enables AES-CTR mode.
 * Prereq: NOXTLS_FEATURE_AES=1.
 */
#define NOXTLS_FEATURE_AES_CTR 1

/* Enables AES-CFB mode.
 * Prereq: NOXTLS_FEATURE_AES=1.
 */
#define NOXTLS_FEATURE_AES_CFB 1

/* Enables AES-OFB mode.
 * Prereq: NOXTLS_FEATURE_AES=1.
 */
#define NOXTLS_FEATURE_AES_OFB 1

/* Enables AES-XTS mode.
 * Prereq: NOXTLS_FEATURE_AES=1.
 * Typical use case: storage encryption.
 */
#define NOXTLS_FEATURE_AES_XTS 1

/* Enables AES-GCM AEAD mode.
 * Prereq: NOXTLS_FEATURE_AES=1.
 * Required by: TLS if ChaCha20-Poly1305 is disabled.
 */
#define NOXTLS_FEATURE_AES_GCM 1

/* Enables AES-CCM AEAD mode.
 * Prereq: NOXTLS_FEATURE_AES=1.
 */
#define NOXTLS_FEATURE_AES_CCM 1

/* Enables AES-CMAC (RFC 4493) for message authentication (e.g. BLE Signed Write).
 * Prereq: NOXTLS_FEATURE_AES=1.
 */
#define NOXTLS_FEATURE_AES_CMAC 1

/* Enables AES-NI accelerated AES block path on x86/x64 builds that compile with AES intrinsics.
 * Prereq: NOXTLS_FEATURE_AES=1.
 * Build knob: NOXTLS_CFG_FEATURE_AES_ACCEL_NI.
 */
#ifndef NOXTLS_FEATURE_AES_ACCEL_NI
#define NOXTLS_FEATURE_AES_ACCEL_NI 0
#endif

/* Enables Apple Silicon ARMv8 AES accelerated block path on arm64 Apple builds.
 * Prereq: NOXTLS_FEATURE_AES=1.
 * Build knob: NOXTLS_CFG_FEATURE_AES_ACCEL_APPLE.
 */
#ifndef NOXTLS_FEATURE_AES_ACCEL_APPLE
#define NOXTLS_FEATURE_AES_ACCEL_APPLE 0
#endif

/* Enables ARIA cipher family.
 * Prereq: NOXTLS_FEATURE_ENCRYPTION=1.
 */
#define NOXTLS_FEATURE_ARIA 1

/* Enables Camellia cipher family.
 * Prereq: NOXTLS_FEATURE_ENCRYPTION=1.
 */
#define NOXTLS_FEATURE_CAMELLIA 1

/* Enables ChaCha20-Poly1305 AEAD.
 * Prereq: NOXTLS_FEATURE_ENCRYPTION=1.
 * Alternative TLS AEAD when AES-GCM is disabled or less preferred.
 */
#define NOXTLS_FEATURE_CHACHA20_POLY1305 1

/* Enables DES/3DES-related implementation units.
 * Prereq: NOXTLS_FEATURE_ENCRYPTION=1.
 * Security note: legacy; generally disable for modern deployments.
 */
#define NOXTLS_FEATURE_DES 1

/* Enables RC4 stream cipher.
 * Prereq: NOXTLS_FEATURE_ENCRYPTION=1.
 * Security note: RC4 is deprecated and weak; use only for legacy compatibility.
 */
#define NOXTLS_FEATURE_RC4 1

/* PKC primitives */
/* Enables RSA (and bignum backend used by RSA paths).
 * Prereq: NOXTLS_FEATURE_PKC=1.
 */
#define NOXTLS_FEATURE_RSA 1

/* Enables ECC core (short Weierstrass curve arithmetic).
 * Prereq: NOXTLS_FEATURE_PKC=1.
 * Required by: ECDSA and ECDH.
 */
#define NOXTLS_FEATURE_ECC 1

/* Enables ECDSA signatures.
 * Prereq: NOXTLS_FEATURE_PKC=1 and NOXTLS_FEATURE_ECC=1.
 */
#define NOXTLS_FEATURE_ECDSA 1

/* Enables ECDH key agreement.
 * Prereq: NOXTLS_FEATURE_PKC=1 and NOXTLS_FEATURE_ECC=1.
 */
#define NOXTLS_FEATURE_ECDH 1

/* Enables finite-field Diffie-Hellman (FFDHE) support.
 * Prereq: NOXTLS_FEATURE_PKC=1.
 */
#define NOXTLS_FEATURE_DH 1

/* Enables X25519 key agreement.
 * Prereq: NOXTLS_FEATURE_PKC=1.
 */
#define NOXTLS_FEATURE_X25519 1

/* Enables X448 key agreement.
 * Prereq: NOXTLS_FEATURE_PKC=1.
 */
#define NOXTLS_FEATURE_X448 1

/* Enables Ed25519 signatures.
 * Prereq: NOXTLS_FEATURE_PKC=1.
 */
#define NOXTLS_FEATURE_ED25519 1

/* Enables Ed448 signatures (RFC 8032). Requires NOXTLS_FEATURE_SHA3=1 for SHAKE256.
 * Prereq: NOXTLS_FEATURE_PKC=1. Default OFF; set NOXTLS_CFG_FEATURE_ED448=ON in CMake to enable.
 */
#define NOXTLS_FEATURE_ED448 0

/* Enables DSA (Digital Signature Algorithm) per FIPS 186-4.
 * Prereq: NOXTLS_FEATURE_PKC=1 (and bignum via RSA or DSA).
 */
#define NOXTLS_FEATURE_DSA 1
/* Enables ML-KEM (FIPS 203) KEM APIs and TLS PQ keyshare support. */
#ifndef NOXTLS_FEATURE_ML_KEM
#define NOXTLS_FEATURE_ML_KEM 0
#endif
/* Enables ML-DSA (FIPS 204) signature APIs and TLS PQ signature support. */
#ifndef NOXTLS_FEATURE_ML_DSA
#define NOXTLS_FEATURE_ML_DSA 0
#endif
/* Enables SLH-DSA (FIPS 205) signature APIs and TLS/X.509 PQ signature support. */
#ifndef NOXTLS_FEATURE_SLH_DSA
#define NOXTLS_FEATURE_SLH_DSA 0
#endif

/* TLS/cert granularity */
/* Enables TLS 1.0 protocol implementation.
 * Prereq: NOXTLS_FEATURE_TLS=1.
 * Security note: legacy protocol; disabled by default.
 */
#ifndef NOXTLS_FEATURE_TLS10
#define NOXTLS_FEATURE_TLS10 0
#endif

/* Enables TLS 1.1 protocol implementation.
 * Prereq: NOXTLS_FEATURE_TLS=1.
 * Security note: legacy protocol; disabled by default.
 */
#ifndef NOXTLS_FEATURE_TLS11
#define NOXTLS_FEATURE_TLS11 0
#endif

/* Enables TLS 1.2 protocol implementation.
 * Prereq: NOXTLS_FEATURE_TLS=1.
 */
#define NOXTLS_FEATURE_TLS12 1

/* Enables TLS 1.3 protocol implementation.
 * Prereq: NOXTLS_FEATURE_TLS=1.
 */
#define NOXTLS_FEATURE_TLS13 1

/*
 * TLS 1.3 (RFC 8446): RSA PKCS#1 v1.5 CertificateVerify schemes (e.g. rsa_pkcs1_sha256,
 * wire 0x0401) are deprecated for TLS 1.3 handshake signatures. NoxTLS does not implement
 * signing those for CertificateVerify; keep 0. When 0, client offers consisting only of
 * such schemes fail algorithm selection (fatal handshake_failure). Do not set to 1 without
 * a reviewed implementation and test plan.
 */
#ifndef NOXTLS_CFG_TLS13_ALLOW_RSA_PKCS1_CERTVERIFY
#define NOXTLS_CFG_TLS13_ALLOW_RSA_PKCS1_CERTVERIFY 0
#endif

/* Enables DTLS support.
 * Prereq: NOXTLS_FEATURE_TLS=1.
 */
#define NOXTLS_FEATURE_DTLS 1

/* Enables legacy TLS 1.2 cipher suites (CBC-mode and RSA key exchange suites).
 * Security note: keep disabled for oracle/timing hardening unless strict
 * backwards compatibility is required.
 */
#ifndef NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES
#define NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES 0
#endif

/* Enables X.509 certificate writing/generation helpers.
 * Prereq: NOXTLS_FEATURE_CERT=1 and NOXTLS_FEATURE_PKC=1.
 *
 * Default: ON. Required by the certgen application (req -new -x509) and by any
 * embedded code path that needs to mint X.509 certificates at runtime. Disable
 * explicitly to shave a few KB of flash on parse-only deployments.
 */
#ifndef NOXTLS_HAVE_CERT_WRITE
#define NOXTLS_HAVE_CERT_WRITE 1
#endif

/* ============================================================================
 * Profile presets (override defaults above)
 * ============================================================================
 * Notes:
 * - Definitions in these blocks only override default values.
 * - For behavior, prerequisites, and security notes, refer to the feature
 *   documentation above at the primary NOXTLS_FEATURE_* definitions.
 */

#if defined(NOXTLS_PROFILE_MINIMAL_TLS_CLIENT)
#undef NOXTLS_FEATURE_HASH
#define NOXTLS_FEATURE_HASH 1
#undef NOXTLS_FEATURE_ENCRYPTION
#define NOXTLS_FEATURE_ENCRYPTION 1
#undef NOXTLS_FEATURE_DRBG
#define NOXTLS_FEATURE_DRBG 1
#undef NOXTLS_FEATURE_PKC
#define NOXTLS_FEATURE_PKC 1
#undef NOXTLS_FEATURE_CERT
#define NOXTLS_FEATURE_CERT 1
#undef NOXTLS_FEATURE_TLS
#define NOXTLS_FEATURE_TLS 1

#undef NOXTLS_FEATURE_TLS10
#define NOXTLS_FEATURE_TLS10 0
#undef NOXTLS_FEATURE_TLS11
#define NOXTLS_FEATURE_TLS11 0
#undef NOXTLS_FEATURE_MD4
#define NOXTLS_FEATURE_MD4 0
#undef NOXTLS_FEATURE_MD5
#define NOXTLS_FEATURE_MD5 0
#undef NOXTLS_FEATURE_SHA1
#define NOXTLS_FEATURE_SHA1 0
#undef NOXTLS_FEATURE_SHA224
#define NOXTLS_FEATURE_SHA224 1
#undef NOXTLS_FEATURE_SHA256
#define NOXTLS_FEATURE_SHA256 1
#undef NOXTLS_FEATURE_SHA384
#define NOXTLS_FEATURE_SHA384 0
#undef NOXTLS_FEATURE_SHA512
#define NOXTLS_FEATURE_SHA512 0
#undef NOXTLS_FEATURE_SHA3
#define NOXTLS_FEATURE_SHA3 0
#undef NOXTLS_FEATURE_RIPEMD160
#define NOXTLS_FEATURE_RIPEMD160 0
#undef NOXTLS_FEATURE_BLAKE2
#define NOXTLS_FEATURE_BLAKE2 0

#undef NOXTLS_FEATURE_AES
#define NOXTLS_FEATURE_AES 1
#undef NOXTLS_FEATURE_AES_128
#define NOXTLS_FEATURE_AES_128 1
#undef NOXTLS_FEATURE_AES_192
#define NOXTLS_FEATURE_AES_192 1
#undef NOXTLS_FEATURE_AES_256
#define NOXTLS_FEATURE_AES_256 1
#undef NOXTLS_FEATURE_AES_ECB
#define NOXTLS_FEATURE_AES_ECB 1
#undef NOXTLS_FEATURE_AES_CBC
#define NOXTLS_FEATURE_AES_CBC 1
#undef NOXTLS_FEATURE_AES_CTR
#define NOXTLS_FEATURE_AES_CTR 1
#undef NOXTLS_FEATURE_AES_CFB
#define NOXTLS_FEATURE_AES_CFB 1
#undef NOXTLS_FEATURE_AES_OFB
#define NOXTLS_FEATURE_AES_OFB 1
#undef NOXTLS_FEATURE_AES_XTS
#define NOXTLS_FEATURE_AES_XTS 0
#undef NOXTLS_FEATURE_AES_GCM
#define NOXTLS_FEATURE_AES_GCM 1
#undef NOXTLS_FEATURE_AES_CCM
#define NOXTLS_FEATURE_AES_CCM 0
#undef NOXTLS_FEATURE_AES_CMAC
#define NOXTLS_FEATURE_AES_CMAC 0
#undef NOXTLS_FEATURE_ARIA
#define NOXTLS_FEATURE_ARIA 0
#undef NOXTLS_FEATURE_CAMELLIA
#define NOXTLS_FEATURE_CAMELLIA 0
#undef NOXTLS_FEATURE_CHACHA20_POLY1305
#define NOXTLS_FEATURE_CHACHA20_POLY1305 0
#undef NOXTLS_FEATURE_DES
#define NOXTLS_FEATURE_DES 0
#undef NOXTLS_FEATURE_RC4
#define NOXTLS_FEATURE_RC4 0

#undef NOXTLS_FEATURE_RSA
#define NOXTLS_FEATURE_RSA 0
#undef NOXTLS_FEATURE_ECC
#define NOXTLS_FEATURE_ECC 1
#undef NOXTLS_FEATURE_ECDSA
#define NOXTLS_FEATURE_ECDSA 0
#undef NOXTLS_FEATURE_ECDH
#define NOXTLS_FEATURE_ECDH 1
#undef NOXTLS_FEATURE_DH
#define NOXTLS_FEATURE_DH 0
#undef NOXTLS_FEATURE_X25519
#define NOXTLS_FEATURE_X25519 1
#undef NOXTLS_FEATURE_X448
#define NOXTLS_FEATURE_X448 1
#undef NOXTLS_FEATURE_ED25519
#define NOXTLS_FEATURE_ED25519 0
#undef NOXTLS_FEATURE_DSA
#define NOXTLS_FEATURE_DSA 0
#undef NOXTLS_FEATURE_ML_KEM
#define NOXTLS_FEATURE_ML_KEM 0
#undef NOXTLS_FEATURE_ML_DSA
#define NOXTLS_FEATURE_ML_DSA 0
#undef NOXTLS_FEATURE_SLH_DSA
#define NOXTLS_FEATURE_SLH_DSA 0

#undef NOXTLS_FEATURE_TLS12
#define NOXTLS_FEATURE_TLS12 1
#undef NOXTLS_FEATURE_TLS13
#define NOXTLS_FEATURE_TLS13 1
#undef NOXTLS_FEATURE_DTLS
#define NOXTLS_FEATURE_DTLS 0
#undef NOXTLS_HAVE_CERT_WRITE
#define NOXTLS_HAVE_CERT_WRITE 0
#endif

#if defined(NOXTLS_PROFILE_TLS_SERVER_PKI)
#undef NOXTLS_FEATURE_HASH
#define NOXTLS_FEATURE_HASH 1
#undef NOXTLS_FEATURE_ENCRYPTION
#define NOXTLS_FEATURE_ENCRYPTION 1
#undef NOXTLS_FEATURE_DRBG
#define NOXTLS_FEATURE_DRBG 1
#undef NOXTLS_FEATURE_PKC
#define NOXTLS_FEATURE_PKC 1
#undef NOXTLS_FEATURE_CERT
#define NOXTLS_FEATURE_CERT 1
#undef NOXTLS_FEATURE_TLS
#define NOXTLS_FEATURE_TLS 1

#undef NOXTLS_FEATURE_TLS10
#define NOXTLS_FEATURE_TLS10 0
#undef NOXTLS_FEATURE_TLS11
#define NOXTLS_FEATURE_TLS11 0
#undef NOXTLS_FEATURE_MD4
#define NOXTLS_FEATURE_MD4 0
#undef NOXTLS_FEATURE_MD5
#define NOXTLS_FEATURE_MD5 0
#undef NOXTLS_FEATURE_SHA1
#define NOXTLS_FEATURE_SHA1 0
#undef NOXTLS_FEATURE_SHA224
#define NOXTLS_FEATURE_SHA224 1
#undef NOXTLS_FEATURE_SHA256
#define NOXTLS_FEATURE_SHA256 1
#undef NOXTLS_FEATURE_SHA384
#define NOXTLS_FEATURE_SHA384 1
#undef NOXTLS_FEATURE_SHA512
#define NOXTLS_FEATURE_SHA512 1
#undef NOXTLS_FEATURE_SHA3
#define NOXTLS_FEATURE_SHA3 0
#undef NOXTLS_FEATURE_RIPEMD160
#define NOXTLS_FEATURE_RIPEMD160 0
#undef NOXTLS_FEATURE_BLAKE2
#define NOXTLS_FEATURE_BLAKE2 0

#undef NOXTLS_FEATURE_AES
#define NOXTLS_FEATURE_AES 1
#undef NOXTLS_FEATURE_AES_128
#define NOXTLS_FEATURE_AES_128 1
#undef NOXTLS_FEATURE_AES_192
#define NOXTLS_FEATURE_AES_192 1
#undef NOXTLS_FEATURE_AES_256
#define NOXTLS_FEATURE_AES_256 1
#undef NOXTLS_FEATURE_AES_ECB
#define NOXTLS_FEATURE_AES_ECB 1
#undef NOXTLS_FEATURE_AES_CBC
#define NOXTLS_FEATURE_AES_CBC 1
#undef NOXTLS_FEATURE_AES_CTR
#define NOXTLS_FEATURE_AES_CTR 1
#undef NOXTLS_FEATURE_AES_CFB
#define NOXTLS_FEATURE_AES_CFB 1
#undef NOXTLS_FEATURE_AES_OFB
#define NOXTLS_FEATURE_AES_OFB 1
#undef NOXTLS_FEATURE_AES_XTS
#define NOXTLS_FEATURE_AES_XTS 0
#undef NOXTLS_FEATURE_AES_GCM
#define NOXTLS_FEATURE_AES_GCM 1
#undef NOXTLS_FEATURE_AES_CCM
#define NOXTLS_FEATURE_AES_CCM 0
#undef NOXTLS_FEATURE_ARIA
#define NOXTLS_FEATURE_ARIA 0
#undef NOXTLS_FEATURE_CAMELLIA
#define NOXTLS_FEATURE_CAMELLIA 0
#undef NOXTLS_FEATURE_CHACHA20_POLY1305
#define NOXTLS_FEATURE_CHACHA20_POLY1305 1
#undef NOXTLS_FEATURE_DES
#define NOXTLS_FEATURE_DES 0
#undef NOXTLS_FEATURE_RC4
#define NOXTLS_FEATURE_RC4 0

#undef NOXTLS_FEATURE_RSA
#define NOXTLS_FEATURE_RSA 1
#undef NOXTLS_FEATURE_ECC
#define NOXTLS_FEATURE_ECC 1
#undef NOXTLS_FEATURE_ECDSA
#define NOXTLS_FEATURE_ECDSA 1
#undef NOXTLS_FEATURE_ECDH
#define NOXTLS_FEATURE_ECDH 1
#undef NOXTLS_FEATURE_DH
#define NOXTLS_FEATURE_DH 0
#undef NOXTLS_FEATURE_X25519
#define NOXTLS_FEATURE_X25519 1
#undef NOXTLS_FEATURE_X448
#define NOXTLS_FEATURE_X448 1
#undef NOXTLS_FEATURE_ED25519
#define NOXTLS_FEATURE_ED25519 1
#undef NOXTLS_FEATURE_ED448
#define NOXTLS_FEATURE_ED448 0
#undef NOXTLS_FEATURE_DSA
#define NOXTLS_FEATURE_DSA 1
#undef NOXTLS_FEATURE_ML_KEM
#define NOXTLS_FEATURE_ML_KEM 0
#undef NOXTLS_FEATURE_ML_DSA
#define NOXTLS_FEATURE_ML_DSA 0
#undef NOXTLS_FEATURE_SLH_DSA
#define NOXTLS_FEATURE_SLH_DSA 0

#undef NOXTLS_FEATURE_TLS12
#define NOXTLS_FEATURE_TLS12 1
#undef NOXTLS_FEATURE_TLS13
#define NOXTLS_FEATURE_TLS13 1
#undef NOXTLS_FEATURE_DTLS
#define NOXTLS_FEATURE_DTLS 1
#undef NOXTLS_HAVE_CERT_WRITE
#define NOXTLS_HAVE_CERT_WRITE 1
#endif

#if defined(NOXTLS_PROFILE_CRYPTO_ONLY)
#undef NOXTLS_FEATURE_HASH
#define NOXTLS_FEATURE_HASH 1
#undef NOXTLS_FEATURE_ENCRYPTION
#define NOXTLS_FEATURE_ENCRYPTION 1
#undef NOXTLS_FEATURE_DRBG
#define NOXTLS_FEATURE_DRBG 1
#undef NOXTLS_FEATURE_PKC
#define NOXTLS_FEATURE_PKC 1
#undef NOXTLS_FEATURE_CERT
#define NOXTLS_FEATURE_CERT 0
#undef NOXTLS_FEATURE_TLS
#define NOXTLS_FEATURE_TLS 0

#undef NOXTLS_FEATURE_TLS10
#define NOXTLS_FEATURE_TLS10 0
#undef NOXTLS_FEATURE_TLS11
#define NOXTLS_FEATURE_TLS11 0
#undef NOXTLS_FEATURE_MD4
#define NOXTLS_FEATURE_MD4 0
#undef NOXTLS_FEATURE_TLS12
#define NOXTLS_FEATURE_TLS12 0
#undef NOXTLS_FEATURE_TLS13
#define NOXTLS_FEATURE_TLS13 0
#undef NOXTLS_FEATURE_DTLS
#define NOXTLS_FEATURE_DTLS 0
#undef NOXTLS_HAVE_CERT_WRITE
#define NOXTLS_HAVE_CERT_WRITE 0
#undef NOXTLS_FEATURE_AES_XTS
#define NOXTLS_FEATURE_AES_XTS 0
#undef NOXTLS_FEATURE_ML_KEM
#define NOXTLS_FEATURE_ML_KEM 0
#undef NOXTLS_FEATURE_ML_DSA
#define NOXTLS_FEATURE_ML_DSA 0
#undef NOXTLS_FEATURE_SLH_DSA
#define NOXTLS_FEATURE_SLH_DSA 0
#endif

#if defined(NOXTLS_PROFILE_FIPS_LIKE)
#undef NOXTLS_FEATURE_HASH
#define NOXTLS_FEATURE_HASH 1
#undef NOXTLS_FEATURE_ENCRYPTION
#define NOXTLS_FEATURE_ENCRYPTION 1
#undef NOXTLS_FEATURE_DRBG
#define NOXTLS_FEATURE_DRBG 1
#undef NOXTLS_FEATURE_PKC
#define NOXTLS_FEATURE_PKC 1
#undef NOXTLS_FEATURE_CERT
#define NOXTLS_FEATURE_CERT 1
#undef NOXTLS_FEATURE_TLS
#define NOXTLS_FEATURE_TLS 1

#undef NOXTLS_FEATURE_TLS10
#define NOXTLS_FEATURE_TLS10 0
#undef NOXTLS_FEATURE_TLS11
#define NOXTLS_FEATURE_TLS11 0
#undef NOXTLS_FEATURE_MD4
#define NOXTLS_FEATURE_MD4 0
#undef NOXTLS_FEATURE_MD5
#define NOXTLS_FEATURE_MD5 0
#undef NOXTLS_FEATURE_SHA1
#define NOXTLS_FEATURE_SHA1 0
#undef NOXTLS_FEATURE_SHA224
#define NOXTLS_FEATURE_SHA224 1
#undef NOXTLS_FEATURE_SHA256
#define NOXTLS_FEATURE_SHA256 1
#undef NOXTLS_FEATURE_SHA384
#define NOXTLS_FEATURE_SHA384 1
#undef NOXTLS_FEATURE_SHA512
#define NOXTLS_FEATURE_SHA512 1
#undef NOXTLS_FEATURE_SHA3
#define NOXTLS_FEATURE_SHA3 0
#undef NOXTLS_FEATURE_RIPEMD160
#define NOXTLS_FEATURE_RIPEMD160 0
#undef NOXTLS_FEATURE_BLAKE2
#define NOXTLS_FEATURE_BLAKE2 0

#undef NOXTLS_FEATURE_AES
#define NOXTLS_FEATURE_AES 1
#undef NOXTLS_FEATURE_AES_128
#define NOXTLS_FEATURE_AES_128 1
#undef NOXTLS_FEATURE_AES_192
#define NOXTLS_FEATURE_AES_192 1
#undef NOXTLS_FEATURE_AES_256
#define NOXTLS_FEATURE_AES_256 1
#undef NOXTLS_FEATURE_AES_ECB
#define NOXTLS_FEATURE_AES_ECB 1
#undef NOXTLS_FEATURE_AES_CBC
#define NOXTLS_FEATURE_AES_CBC 1
#undef NOXTLS_FEATURE_AES_CTR
#define NOXTLS_FEATURE_AES_CTR 1
#undef NOXTLS_FEATURE_AES_CFB
#define NOXTLS_FEATURE_AES_CFB 1
#undef NOXTLS_FEATURE_AES_OFB
#define NOXTLS_FEATURE_AES_OFB 1
#undef NOXTLS_FEATURE_AES_XTS
#define NOXTLS_FEATURE_AES_XTS 0
#undef NOXTLS_FEATURE_AES_GCM
#define NOXTLS_FEATURE_AES_GCM 1
#undef NOXTLS_FEATURE_AES_CCM
#define NOXTLS_FEATURE_AES_CCM 0
#undef NOXTLS_FEATURE_AES_CMAC
#define NOXTLS_FEATURE_AES_CMAC 0
#undef NOXTLS_FEATURE_ARIA
#define NOXTLS_FEATURE_ARIA 0
#undef NOXTLS_FEATURE_CAMELLIA
#define NOXTLS_FEATURE_CAMELLIA 0
#undef NOXTLS_FEATURE_CHACHA20_POLY1305
#define NOXTLS_FEATURE_CHACHA20_POLY1305 0
#undef NOXTLS_FEATURE_DES
#define NOXTLS_FEATURE_DES 0
#undef NOXTLS_FEATURE_RC4
#define NOXTLS_FEATURE_RC4 0

#undef NOXTLS_FEATURE_RSA
#define NOXTLS_FEATURE_RSA 1
#undef NOXTLS_FEATURE_ECC
#define NOXTLS_FEATURE_ECC 1
#undef NOXTLS_FEATURE_ECDSA
#define NOXTLS_FEATURE_ECDSA 1
#undef NOXTLS_FEATURE_ECDH
#define NOXTLS_FEATURE_ECDH 1
#undef NOXTLS_FEATURE_DH
#define NOXTLS_FEATURE_DH 0
#undef NOXTLS_FEATURE_X25519
#define NOXTLS_FEATURE_X25519 0
#undef NOXTLS_FEATURE_X448
#define NOXTLS_FEATURE_X448 0
#undef NOXTLS_FEATURE_ED25519
#define NOXTLS_FEATURE_ED25519 0
#undef NOXTLS_FEATURE_DSA
#define NOXTLS_FEATURE_DSA 1
#undef NOXTLS_FEATURE_ML_KEM
#define NOXTLS_FEATURE_ML_KEM 0
#undef NOXTLS_FEATURE_ML_DSA
#define NOXTLS_FEATURE_ML_DSA 0
#undef NOXTLS_FEATURE_SLH_DSA
#define NOXTLS_FEATURE_SLH_DSA 0

#undef NOXTLS_FEATURE_TLS12
#define NOXTLS_FEATURE_TLS12 1
#undef NOXTLS_FEATURE_TLS13
#define NOXTLS_FEATURE_TLS13 1
#undef NOXTLS_FEATURE_DTLS
#define NOXTLS_FEATURE_DTLS 0
#undef NOXTLS_HAVE_CERT_WRITE
#define NOXTLS_HAVE_CERT_WRITE 0
#endif

#if defined(NOXTLS_PROFILE_UT_ALL_FEATURES)
#undef NOXTLS_FEATURE_HASH
#define NOXTLS_FEATURE_HASH 1
#undef NOXTLS_FEATURE_ENCRYPTION
#define NOXTLS_FEATURE_ENCRYPTION 1
#undef NOXTLS_FEATURE_DRBG
#define NOXTLS_FEATURE_DRBG 1
#undef NOXTLS_FEATURE_PKC
#define NOXTLS_FEATURE_PKC 1
#undef NOXTLS_FEATURE_CERT
#define NOXTLS_FEATURE_CERT 1
#undef NOXTLS_FEATURE_TLS
#define NOXTLS_FEATURE_TLS 1

#undef NOXTLS_FEATURE_MD4
#define NOXTLS_FEATURE_MD4 1
#undef NOXTLS_FEATURE_MD5
#define NOXTLS_FEATURE_MD5 1
#undef NOXTLS_FEATURE_SHA1
#define NOXTLS_FEATURE_SHA1 1
#undef NOXTLS_FEATURE_SHA224
#define NOXTLS_FEATURE_SHA224 1
#undef NOXTLS_FEATURE_SHA256
#define NOXTLS_FEATURE_SHA256 1
#undef NOXTLS_FEATURE_SHA384
#define NOXTLS_FEATURE_SHA384 1
#undef NOXTLS_FEATURE_SHA512
#define NOXTLS_FEATURE_SHA512 1
#undef NOXTLS_FEATURE_SHA3
#define NOXTLS_FEATURE_SHA3 1
#undef NOXTLS_FEATURE_RIPEMD160
#define NOXTLS_FEATURE_RIPEMD160 1
#undef NOXTLS_FEATURE_BLAKE2
#define NOXTLS_FEATURE_BLAKE2 1

#undef NOXTLS_FEATURE_AES
#define NOXTLS_FEATURE_AES 1
#undef NOXTLS_FEATURE_AES_128
#define NOXTLS_FEATURE_AES_128 1
#undef NOXTLS_FEATURE_AES_192
#define NOXTLS_FEATURE_AES_192 1
#undef NOXTLS_FEATURE_AES_256
#define NOXTLS_FEATURE_AES_256 1
#undef NOXTLS_FEATURE_AES_ECB
#define NOXTLS_FEATURE_AES_ECB 1
#undef NOXTLS_FEATURE_AES_CBC
#define NOXTLS_FEATURE_AES_CBC 1
#undef NOXTLS_FEATURE_AES_CTR
#define NOXTLS_FEATURE_AES_CTR 1
#undef NOXTLS_FEATURE_AES_CFB
#define NOXTLS_FEATURE_AES_CFB 1
#undef NOXTLS_FEATURE_AES_OFB
#define NOXTLS_FEATURE_AES_OFB 1
#undef NOXTLS_FEATURE_AES_XTS
#define NOXTLS_FEATURE_AES_XTS 1
#undef NOXTLS_FEATURE_AES_GCM
#define NOXTLS_FEATURE_AES_GCM 1
#undef NOXTLS_FEATURE_AES_CCM
#define NOXTLS_FEATURE_AES_CCM 1
#undef NOXTLS_FEATURE_AES_CMAC
#define NOXTLS_FEATURE_AES_CMAC 1
#undef NOXTLS_FEATURE_ARIA
#define NOXTLS_FEATURE_ARIA 1
#undef NOXTLS_FEATURE_CAMELLIA
#define NOXTLS_FEATURE_CAMELLIA 1
#undef NOXTLS_FEATURE_CHACHA20_POLY1305
#define NOXTLS_FEATURE_CHACHA20_POLY1305 1
#undef NOXTLS_FEATURE_DES
#define NOXTLS_FEATURE_DES 1
#undef NOXTLS_FEATURE_RC4
#define NOXTLS_FEATURE_RC4 1

#undef NOXTLS_FEATURE_RSA
#define NOXTLS_FEATURE_RSA 1
#undef NOXTLS_FEATURE_ECC
#define NOXTLS_FEATURE_ECC 1
#undef NOXTLS_FEATURE_ECDSA
#define NOXTLS_FEATURE_ECDSA 1
#undef NOXTLS_FEATURE_ECDH
#define NOXTLS_FEATURE_ECDH 1
#undef NOXTLS_FEATURE_DH
#define NOXTLS_FEATURE_DH 1
#undef NOXTLS_FEATURE_X25519
#define NOXTLS_FEATURE_X25519 1
#undef NOXTLS_FEATURE_X448
#define NOXTLS_FEATURE_X448 1
#undef NOXTLS_FEATURE_ED25519
#define NOXTLS_FEATURE_ED25519 1
#undef NOXTLS_FEATURE_ED448
#define NOXTLS_FEATURE_ED448 0
#undef NOXTLS_FEATURE_DSA
#define NOXTLS_FEATURE_DSA 1
#undef NOXTLS_FEATURE_ML_KEM
#define NOXTLS_FEATURE_ML_KEM 0
#undef NOXTLS_FEATURE_ML_DSA
#define NOXTLS_FEATURE_ML_DSA 0
#undef NOXTLS_FEATURE_SLH_DSA
#define NOXTLS_FEATURE_SLH_DSA 0

#undef NOXTLS_FEATURE_TLS10
#define NOXTLS_FEATURE_TLS10 1
#undef NOXTLS_FEATURE_TLS11
#define NOXTLS_FEATURE_TLS11 1
#undef NOXTLS_FEATURE_TLS12
#define NOXTLS_FEATURE_TLS12 1
#undef NOXTLS_FEATURE_TLS13
#define NOXTLS_FEATURE_TLS13 1
#undef NOXTLS_FEATURE_DTLS
#define NOXTLS_FEATURE_DTLS 1
#undef NOXTLS_HAVE_CERT_WRITE
#define NOXTLS_HAVE_CERT_WRITE 1
#undef NOXTLS_HAVE_TIME
#define NOXTLS_HAVE_TIME 0
#endif

/* NOXTLS_HAVE_TIME
 * 
 * Define this to 1 if the system has time support (time.h, time(), etc.)
 * Define this to 0 if the system does not have time support (e.g. embedded
 * systems without an RTC or time source).
 * 
 * When disabled:
 * - Certificate validity (notBefore/notAfter) checking is skipped in
 *   noxtls_x509_certificate_check_validity() and in chain verification.
 * - Other functions that require time will return appropriate error codes.
 * 
 * For embedded builds without time, add -DNOXTLS_HAVE_TIME=0 (or #define
 * before including noxtls headers).
 * 
 * Default: 1 (enabled) - assumes standard systems have time support
 */
#if defined(NOXTLS_PROFILE_UT_ALL_FEATURES)
#define NOXTLS_HAVE_TIME 0
#else
#define NOXTLS_HAVE_TIME 1
#endif

/* ============================================================================
 * Memory Management Configuration
 * ============================================================================
 */

/* NOXTLS_USE_STATIC_BUFFERS
 * 
 * Define this to 1 to use static buffer allocation instead of system malloc.
 * When enabled, all memory allocations will use a pre-allocated static buffer
 * pool managed by the library's internal memory allocator.
 * 
 * When disabled (default), the library uses standard system malloc/free.
 * 
 * Default: 0 (disabled) - uses system malloc/free
 * 
 * Recommended: Call noxtls_mem_init() early with a caller-supplied buffer
 *              for deterministic RAM usage.
 *
 * Behavior without explicit init: The allocator lazily initializes on first
 * allocation by calling noxtls_mem_init(NULL, 0), which uses
 * NOXTLS_STATIC_BUFFER_SIZE for the pool size.
 */
#ifndef NOXTLS_USE_STATIC_BUFFERS
#define NOXTLS_USE_STATIC_BUFFERS 0
#endif

/* NOXTLS_STATIC_BUFFER_SIZE
 * 
 * Default size for static buffer pool (in bytes) when NOXTLS_USE_STATIC_BUFFERS is enabled.
 * This is only used if noxtls_mem_init() is called without a buffer (uses internal allocation).
 * 
 * Default: 64KB (65536 bytes)
 */
#ifndef NOXTLS_STATIC_BUFFER_SIZE
#define NOXTLS_STATIC_BUFFER_SIZE (64 * 1024)
#endif

/* ============================================================================
 * TLS size limits (stack / buffer sizing)
 * ============================================================================
 *
 * Reduce these in noxtls_config.h (or via compiler -D) to lower RAM/stack
 * usage on embedded systems.
 *
 * Relationship to certificate size:
 * - The Certificate handshake message carries the full certificate chain
 *   (each cert is length-prefixed). Its size is the sum of all certificate
 *   DER lengths plus a few bytes of list framing.
 * - Each TLS record carries at most TLS_MAX_RECORD_SIZE bytes of payload.
 *   The largest single handshake message (including Certificate) must fit
 *   within one record. Set NOXTLS_TLS_MAX_RECORD_SIZE to at least the size
 *   of your largest expected Certificate message. If the chain is larger
 *   than the record limit, the handshake will fail.
 *
 * When reducing below the TLS default (16384): both peers must agree on
 * smaller fragments (e.g. max_fragment_length extension) or the
 * connection may fail.
 */

/** Maximum TLS record payload size (bytes). TLS default 16384.
 *  Must be >= size of largest handshake message (usually the Certificate
 *  message). This value drives large stack buffers in record send/recv;
 *  reduce it for constrained stack. Ensure peer supports smaller fragment
 *  size if below 16384. */
#ifndef NOXTLS_TLS_MAX_RECORD_SIZE
#define NOXTLS_TLS_MAX_RECORD_SIZE 16384
#endif

/** Maximum TLS record-layer fragment length from the 2-byte length field (encrypted payload).
 *  RFC 5246 plaintext is at most 2^14 bytes; ciphertext is larger. Interop tests (e.g. tlsfuzzer
 *  SetMaxRecordSize) may send fragments up to 2^16-1. Must be >= NOXTLS_TLS_MAX_RECORD_SIZE. */
#ifndef NOXTLS_TLS_MAX_WIRE_RECORD_LENGTH
#define NOXTLS_TLS_MAX_WIRE_RECORD_LENGTH 65535
#endif

/** Maximum handshake message size (bytes). Used only as a bounds check:
 *  handshake messages that claim a length above this are rejected. No buffer
 *  of this size is allocatedâ€”DTLS reassembly allocates only the actual
 *  message length (from the wire). So this can be set to a small value
 *  (e.g. 16384 or 8192) on embedded without reserving 64KB. It must be
 *  >= the largest handshake message you need (typically Certificate =
 *  chain size). Default 65536 for compatibility; set to NOXTLS_TLS_MAX_RECORD_SIZE
 *  or your max cert chain size to avoid accepting oversized messages. */
#ifndef NOXTLS_TLS_MAX_HANDSHAKE_SIZE
#define NOXTLS_TLS_MAX_HANDSHAKE_SIZE 65536
#endif

/** Maximum single certificate size in bytes accepted by X.509 parse APIs.
 *  Default: 16384.
 */
#ifndef NOXTLS_MAX_CERT_SIZE
#if NOXTLS_FEATURE_SLH_DSA
/* SLH-DSA signatures are large (up to ~50 KB). Allow 64 KB certs by default
 * when SLH-DSA is enabled so the cert+TBS+signature comfortably fits. */
#define NOXTLS_MAX_CERT_SIZE 65536
#elif NOXTLS_FEATURE_ML_DSA
/* ML-DSA-87 signatures are ~4.6 KB; combined with public-key (~2.6 KB) and TBS
 * fields, 32 KB headroom is plenty. */
#define NOXTLS_MAX_CERT_SIZE 32768
#else
#define NOXTLS_MAX_CERT_SIZE 16384
#endif
#endif

/** Maximum certificate-chain traversal depth for trust verification.
 *  Used by X.509 trust-chain walking to cap issuer hops and prevent
 *  unbounded loops in malformed or adversarial chains.
 *  Default: 16.
 */
#ifndef NOXTLS_MAX_CERT_CHAIN_DEPTH
#define NOXTLS_MAX_CERT_CHAIN_DEPTH 16
#endif

/* ============================================================================
 * RSA Key Generation Configuration
 * ============================================================================
 */

/* NOXTLS_RSA_MAX_PRIME_ATTEMPTS
 * 
 * Maximum number of attempts to generate a prime number before giving up.
 * 
 * With aggressive filtering (wheel + large small-prime table), the search
 * space is reduced but candidate density can still vary significantly.
 * Use a higher limit to avoid spurious failures on unlucky sequences.
 * 
 * Default: 50000 attempts
 */
#define NOXTLS_RSA_MAX_PRIME_ATTEMPTS 50000

/* NOXTLS_RSA_MILLER_RABIN_ITERATIONS_SMALL
 * 
 * Number of Miller-Rabin test iterations for "small" primes (<= 512 bits).
 * 
 * Security: 2 iterations gives error probability of ~2^-40 (very secure)
 * 
 * Default: 2 iterations
 */
#define NOXTLS_RSA_MILLER_RABIN_ITERATIONS_SMALL 2

/* NOXTLS_RSA_MILLER_RABIN_ITERATIONS_LARGE
 * 
 * Number of Miller-Rabin test iterations for "large" primes (> 512 bits).
 * 
 * Security: 3 iterations gives error probability of ~2^-60 (extremely secure)
 * 
 * Default: 3 iterations
 */
#define NOXTLS_RSA_MILLER_RABIN_ITERATIONS_LARGE 3

/* NOXTLS_RSA_MILLER_RABIN_SMALL_THRESHOLD_BITS
 * 
 * Prime size threshold (in bits) for determining "small" vs "large" primes.
 * Primes <= this size use NOXTLS_RSA_MILLER_RABIN_ITERATIONS_SMALL.
 * Primes > this size use NOXTLS_RSA_MILLER_RABIN_ITERATIONS_LARGE.
 * 
 * Default: 512 bits
 */
#define NOXTLS_RSA_MILLER_RABIN_SMALL_THRESHOLD_BITS 512

/* NOXTLS_RSA_ENABLE_QUICK_DIVISIBILITY_TEST
 * 
 * Enable/disable quick divisibility test before expensive Miller-Rabin test.
 * When enabled, candidates are first tested for divisibility by small primes
 * (3, 5, 7, 11, 13, 17, 19, 23, 29, 31) to quickly filter out composites.
 * 
 * This significantly speeds up prime generation by avoiding expensive
 * Miller-Rabin tests on obviously composite numbers.
 * 
 * Default: 1 (enabled)
 */
#define NOXTLS_RSA_ENABLE_QUICK_DIVISIBILITY_TEST 1

/* NOXTLS_RSA_DEBUG_PROGRESS_INTERVAL
 * 
 * Interval (in attempts) for printing progress messages during prime generation.
 * Set to 0 to disable progress messages.
 * 
 * Default: 100 (print every 100 attempts)
 */
#define NOXTLS_RSA_DEBUG_PROGRESS_INTERVAL 100

/* NOXTLS_RSA_DEBUG_PRIMALITY_CHECK_INTERVAL
 * 
 * Interval (in attempts) for printing messages when checking primality
 * (after quick divisibility test passes).
 * Set to 0 to disable these messages.
 * 
 * Default: 50 (print every 50 attempts)
 */
#define NOXTLS_RSA_DEBUG_PRIMALITY_CHECK_INTERVAL 50

/* NOXTLS_RSA_DEBUG_REJECTED_CANDIDATE_INTERVAL
 * 
 * Interval (in attempts) for printing debug info about rejected candidates.
 * Only prints for the first 500 attempts to avoid spam.
 * Set to 0 to disable rejected candidate debug output.
 * 
 * Default: 100 (print every 100 attempts, up to 500 attempts)
 */
#define NOXTLS_RSA_DEBUG_REJECTED_CANDIDATE_INTERVAL 100

/* NOXTLS_RSA_DEBUG_REJECTED_CANDIDATE_MAX_ATTEMPTS
 * 
 * Maximum number of attempts for which to print rejected candidate debug info.
 * After this many attempts, rejected candidate debug output is disabled.
 * 
 * Default: 500 attempts
 */
#define NOXTLS_RSA_DEBUG_REJECTED_CANDIDATE_MAX_ATTEMPTS 500

/* ============================================================================
 * ECC Point Multiplication Configuration
 * ============================================================================
 */

/* NOXTLS_ECC_POINT_MUL_WINDOW_SIZE
 *
 * Log2 of the precomputation table size for windowed scalar multiplication.
 * Table has 2^W Jacobian points; larger W = fewer point ops, more RAM.
 * Uses 4 for P-256 (good tradeoff). Use 0 to disable windowing (Montgomery ladder only).
 *
 * Default: 4 (table of 16 points)
 */
#define NOXTLS_ECC_POINT_MUL_WINDOW_SIZE 4

/* NOXTLS_ECC_FIXED_POINT_OPTIM
 *
 * When 1, cache precomputed multiples of the curve generator G and reuse for
 * repeated k*G (ECDSA sign, key gen, ECDHE). Speeds up fixed-base multiplications.
 *
 * Default: 1 (enabled)
 */
#define NOXTLS_ECC_FIXED_POINT_OPTIM 1

/* ============================================================================
 * Observability integration
 * ============================================================================
 */

/* Optional NoxSight integration for structured TLS diagnostics.
 * Default is disabled so existing builds are unchanged unless explicitly enabled.
 */
#ifndef NOXTLS_CFG_ENABLE_NOXSIGHT
#define NOXTLS_CFG_ENABLE_NOXSIGHT 0
#endif

#endif /* _NOXTLS_CONFIG_H_ */
