/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Licensed under the GNU General Public License v2.0 or later,
* or alternatively under a commercial license from
* Argenox Technologies LLC.
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
*
*****************************************************************************/

#ifndef NOXTLS_CONFIG_H_
#define NOXTLS_CONFIG_H_

/* ============================================================================
 * Application-local configuration for: https_server
 * Workload: HTTPS server (TLS 1.2 / 1.3)
 * ============================================================================
 *
 * This file is a SELF-CONTAINED copy of the NoxTLS configuration. Per project
 * policy, application code MUST NOT include the top-level noxtls_config.h --
 * each application owns its own configuration so it can be tuned and built
 * independently. The library libraries (.lib / .a) are still produced from
 * the top-level config; this file controls what application translation
 * units see when they include "noxtls_config.h".
 *
 * Everything after this block is generated from the top-level
 * noxtls_config.h by tools/app_config_sync/sync_app_configs.py (ctest
 * app_config_sync_check fails when a copy is stale). The library archives
 * are built from the top-level config, so settings that change structure
 * layouts (features, size limits, table modes) must match it exactly.
 * Put app-only tuning in this block; do NOT edit the generated part and
 * do NOT add a `#include "../../noxtls_config.h"` line.
 */

/* Size of the application-private static workspace (bump arena) declared in
 * the app's main translation unit. Replaces heap allocations for the app's
 * own working buffers. Sized per app for its worst-case workload. */
#ifndef NOXTLS_APP_STATIC_BUFFER_SIZE
#define NOXTLS_APP_STATIC_BUFFER_SIZE (256u * 1024U)
#endif

/* NOXTLS_STATIC_MEMORY_PROFILE
 *
 * Optional header (quoted path, for example
 * -DNOXTLS_STATIC_MEMORY_PROFILE="profiles/static_memory/noxtls_static_profile_node.h")
 * included before every other setting. The static-memory profiles under
 * profiles/static_memory/ set feature switches and size limits for one device
 * role; every value they define can still be overridden with -D.
 */
#ifdef NOXTLS_STATIC_MEMORY_PROFILE
#include NOXTLS_STATIC_MEMORY_PROFILE
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
 * Profile presets (applied before the per-feature defaults below)
 * ============================================================================
 * Notes:
 * - A profile only supplies values for settings that are not already defined.
 *   A -D compiler option or a #define placed before this header always wins,
 *   so a profile can be used as a base and adjusted per setting (for example
 *   -DNOXTLS_PROFILE_MINIMAL_TLS_CLIENT -DNOXTLS_FEATURE_RSA=1).
 * - CMake builds pass every NOXTLS_FEATURE_* explicitly (from the NOXTLS_CFG_*
 *   options and the NOXTLS_PROFILE tables in CMakeLists.txt), so for those
 *   settings the CMake values are the effective ones.
 * - For behavior, prerequisites, and security notes, refer to the feature
 *   documentation above at the primary NOXTLS_FEATURE_* definitions.
 */

#if defined(NOXTLS_PROFILE_MINIMAL_TLS_CLIENT)
#ifndef NOXTLS_FEATURE_HASH
#define NOXTLS_FEATURE_HASH 1
#endif
#ifndef NOXTLS_FEATURE_HMAC
#define NOXTLS_FEATURE_HMAC 1
#endif
#ifndef NOXTLS_FEATURE_HKDF
#define NOXTLS_FEATURE_HKDF 1
#endif
#ifndef NOXTLS_FEATURE_ENCRYPTION
#define NOXTLS_FEATURE_ENCRYPTION 1
#endif
#ifndef NOXTLS_FEATURE_DRBG
#define NOXTLS_FEATURE_DRBG 1
#endif
#ifndef NOXTLS_FEATURE_PKC
#define NOXTLS_FEATURE_PKC 1
#endif
#ifndef NOXTLS_FEATURE_CERT
#define NOXTLS_FEATURE_CERT 1
#endif
#ifndef NOXTLS_FEATURE_TLS
#define NOXTLS_FEATURE_TLS 1
#endif

#ifndef NOXTLS_FEATURE_TLS10
#define NOXTLS_FEATURE_TLS10 0
#endif
#ifndef NOXTLS_FEATURE_TLS11
#define NOXTLS_FEATURE_TLS11 0
#endif
#ifndef NOXTLS_FEATURE_MD4
#define NOXTLS_FEATURE_MD4 0
#endif
#ifndef NOXTLS_FEATURE_MD5
#define NOXTLS_FEATURE_MD5 0
#endif
#ifndef NOXTLS_FEATURE_SHA1
#define NOXTLS_FEATURE_SHA1 0
#endif
#ifndef NOXTLS_FEATURE_SHA224
#define NOXTLS_FEATURE_SHA224 1
#endif
#ifndef NOXTLS_FEATURE_SHA256
#define NOXTLS_FEATURE_SHA256 1
#endif
#ifndef NOXTLS_FEATURE_SHA384
#define NOXTLS_FEATURE_SHA384 0
#endif
#ifndef NOXTLS_FEATURE_SHA512
#define NOXTLS_FEATURE_SHA512 0
#endif
#ifndef NOXTLS_FEATURE_SHA3
#define NOXTLS_FEATURE_SHA3 0
#endif
#ifndef NOXTLS_FEATURE_RIPEMD160
#define NOXTLS_FEATURE_RIPEMD160 0
#endif
#ifndef NOXTLS_FEATURE_BLAKE2
#define NOXTLS_FEATURE_BLAKE2 0
#endif

#ifndef NOXTLS_FEATURE_AES
#define NOXTLS_FEATURE_AES 1
#endif
#ifndef NOXTLS_FEATURE_AES_128
#define NOXTLS_FEATURE_AES_128 1
#endif
#ifndef NOXTLS_FEATURE_AES_192
#define NOXTLS_FEATURE_AES_192 1
#endif
#ifndef NOXTLS_FEATURE_AES_256
#define NOXTLS_FEATURE_AES_256 1
#endif
#ifndef NOXTLS_FEATURE_AES_ECB
#define NOXTLS_FEATURE_AES_ECB 1
#endif
#ifndef NOXTLS_FEATURE_AES_CBC
#define NOXTLS_FEATURE_AES_CBC 1
#endif
#ifndef NOXTLS_FEATURE_AES_CTR
#define NOXTLS_FEATURE_AES_CTR 1
#endif
#ifndef NOXTLS_FEATURE_AES_CFB
#define NOXTLS_FEATURE_AES_CFB 1
#endif
#ifndef NOXTLS_FEATURE_AES_OFB
#define NOXTLS_FEATURE_AES_OFB 1
#endif
#ifndef NOXTLS_FEATURE_AES_XTS
#define NOXTLS_FEATURE_AES_XTS 0
#endif
#ifndef NOXTLS_FEATURE_AES_GCM
#define NOXTLS_FEATURE_AES_GCM 1
#endif
#ifndef NOXTLS_FEATURE_AES_CCM
#define NOXTLS_FEATURE_AES_CCM 0
#endif
#ifndef NOXTLS_FEATURE_AES_CMAC
#define NOXTLS_FEATURE_AES_CMAC 0
#endif
#ifndef NOXTLS_FEATURE_ARIA
#define NOXTLS_FEATURE_ARIA 0
#endif
#ifndef NOXTLS_FEATURE_CAMELLIA
#define NOXTLS_FEATURE_CAMELLIA 0
#endif
#ifndef NOXTLS_FEATURE_CHACHA20_POLY1305
#define NOXTLS_FEATURE_CHACHA20_POLY1305 0
#endif
#ifndef NOXTLS_FEATURE_DES
#define NOXTLS_FEATURE_DES 0
#endif
#ifndef NOXTLS_FEATURE_RC4
#define NOXTLS_FEATURE_RC4 0
#endif

#ifndef NOXTLS_FEATURE_RSA
#define NOXTLS_FEATURE_RSA 0
#endif
#ifndef NOXTLS_FEATURE_ECC
#define NOXTLS_FEATURE_ECC 1
#endif
#ifndef NOXTLS_FEATURE_ECDSA
#define NOXTLS_FEATURE_ECDSA 1
#endif
#ifndef NOXTLS_FEATURE_ECDH
#define NOXTLS_FEATURE_ECDH 1
#endif
#ifndef NOXTLS_FEATURE_DH
#define NOXTLS_FEATURE_DH 0
#endif
#ifndef NOXTLS_FEATURE_X25519
#define NOXTLS_FEATURE_X25519 1
#endif
#ifndef NOXTLS_FEATURE_X448
#define NOXTLS_FEATURE_X448 0
#endif
#ifndef NOXTLS_FEATURE_ED25519
#define NOXTLS_FEATURE_ED25519 0
#endif
#ifndef NOXTLS_FEATURE_ED448
#define NOXTLS_FEATURE_ED448 0
#endif
#ifndef NOXTLS_FEATURE_DSA
#define NOXTLS_FEATURE_DSA 0
#endif
#ifndef NOXTLS_FEATURE_ML_KEM
#define NOXTLS_FEATURE_ML_KEM 0
#endif
#ifndef NOXTLS_FEATURE_ML_DSA
#define NOXTLS_FEATURE_ML_DSA 0
#endif
#ifndef NOXTLS_FEATURE_SLH_DSA
#define NOXTLS_FEATURE_SLH_DSA 0
#endif
#ifndef NOXTLS_FEATURE_FALCON
#define NOXTLS_FEATURE_FALCON 0
#endif
#ifndef NOXTLS_FEATURE_LMS_HSS
#define NOXTLS_FEATURE_LMS_HSS 0
#endif
#ifndef NOXTLS_FEATURE_XMSS
#define NOXTLS_FEATURE_XMSS 0
#endif

#ifndef NOXTLS_FEATURE_TLS12
#define NOXTLS_FEATURE_TLS12 1
#endif
#ifndef NOXTLS_FEATURE_TLS13
#define NOXTLS_FEATURE_TLS13 1
#endif
#ifndef NOXTLS_FEATURE_DTLS
#define NOXTLS_FEATURE_DTLS 0
#endif
#ifndef NOXTLS_HAVE_CERT_WRITE
#define NOXTLS_HAVE_CERT_WRITE 0
#endif

/* Minimal client: ECDSA P-256 server authentication only (enable more curves,
 * RSA or SHA-384 with -D for chains that need them), client role only, no
 * stdio and no detailed certificate failure strings. */
#ifndef NOXTLS_FEATURE_TLS_SERVER
#define NOXTLS_FEATURE_TLS_SERVER 0
#endif
#ifndef NOXTLS_HAVE_FILE_IO
#define NOXTLS_HAVE_FILE_IO 0
#endif
#ifndef NOXTLS_X509_FAIL_INFO
#define NOXTLS_X509_FAIL_INFO 0
#endif
#ifndef NOXTLS_ECC_ENABLE_SECP192R1
#define NOXTLS_ECC_ENABLE_SECP192R1 0
#endif
#ifndef NOXTLS_ECC_ENABLE_SECP224R1
#define NOXTLS_ECC_ENABLE_SECP224R1 0
#endif
#ifndef NOXTLS_ECC_ENABLE_SECP384R1
#define NOXTLS_ECC_ENABLE_SECP384R1 0
#endif
#ifndef NOXTLS_ECC_ENABLE_SECP521R1
#define NOXTLS_ECC_ENABLE_SECP521R1 0
#endif
#ifndef NOXTLS_ECC_ENABLE_SECP192K1
#define NOXTLS_ECC_ENABLE_SECP192K1 0
#endif
#ifndef NOXTLS_ECC_ENABLE_SECP224K1
#define NOXTLS_ECC_ENABLE_SECP224K1 0
#endif
#ifndef NOXTLS_ECC_ENABLE_SECP256K1
#define NOXTLS_ECC_ENABLE_SECP256K1 0
#endif
#ifndef NOXTLS_ECC_ENABLE_BP256R1
#define NOXTLS_ECC_ENABLE_BP256R1 0
#endif
#ifndef NOXTLS_ECC_ENABLE_BP384R1
#define NOXTLS_ECC_ENABLE_BP384R1 0
#endif
#ifndef NOXTLS_ECC_ENABLE_BP512R1
#define NOXTLS_ECC_ENABLE_BP512R1 0
#endif
#endif

#if defined(NOXTLS_PROFILE_TLS_SERVER_PKI)
#ifndef NOXTLS_FEATURE_HASH
#define NOXTLS_FEATURE_HASH 1
#endif
#ifndef NOXTLS_FEATURE_HMAC
#define NOXTLS_FEATURE_HMAC 1
#endif
#ifndef NOXTLS_FEATURE_HKDF
#define NOXTLS_FEATURE_HKDF 1
#endif
#ifndef NOXTLS_FEATURE_ENCRYPTION
#define NOXTLS_FEATURE_ENCRYPTION 1
#endif
#ifndef NOXTLS_FEATURE_DRBG
#define NOXTLS_FEATURE_DRBG 1
#endif
#ifndef NOXTLS_FEATURE_PKC
#define NOXTLS_FEATURE_PKC 1
#endif
#ifndef NOXTLS_FEATURE_CERT
#define NOXTLS_FEATURE_CERT 1
#endif
#ifndef NOXTLS_FEATURE_TLS
#define NOXTLS_FEATURE_TLS 1
#endif

#ifndef NOXTLS_FEATURE_TLS10
#define NOXTLS_FEATURE_TLS10 0
#endif
#ifndef NOXTLS_FEATURE_TLS11
#define NOXTLS_FEATURE_TLS11 0
#endif
#ifndef NOXTLS_FEATURE_MD4
#define NOXTLS_FEATURE_MD4 0
#endif
#ifndef NOXTLS_FEATURE_MD5
#define NOXTLS_FEATURE_MD5 0
#endif
#ifndef NOXTLS_FEATURE_SHA1
#define NOXTLS_FEATURE_SHA1 0
#endif
#ifndef NOXTLS_FEATURE_SHA224
#define NOXTLS_FEATURE_SHA224 1
#endif
#ifndef NOXTLS_FEATURE_SHA256
#define NOXTLS_FEATURE_SHA256 1
#endif
#ifndef NOXTLS_FEATURE_SHA384
#define NOXTLS_FEATURE_SHA384 1
#endif
#ifndef NOXTLS_FEATURE_SHA512
#define NOXTLS_FEATURE_SHA512 1
#endif
#ifndef NOXTLS_FEATURE_SHA3
#define NOXTLS_FEATURE_SHA3 0
#endif
#ifndef NOXTLS_FEATURE_RIPEMD160
#define NOXTLS_FEATURE_RIPEMD160 0
#endif
#ifndef NOXTLS_FEATURE_BLAKE2
#define NOXTLS_FEATURE_BLAKE2 0
#endif

#ifndef NOXTLS_FEATURE_AES
#define NOXTLS_FEATURE_AES 1
#endif
#ifndef NOXTLS_FEATURE_AES_128
#define NOXTLS_FEATURE_AES_128 1
#endif
#ifndef NOXTLS_FEATURE_AES_192
#define NOXTLS_FEATURE_AES_192 1
#endif
#ifndef NOXTLS_FEATURE_AES_256
#define NOXTLS_FEATURE_AES_256 1
#endif
#ifndef NOXTLS_FEATURE_AES_ECB
#define NOXTLS_FEATURE_AES_ECB 1
#endif
#ifndef NOXTLS_FEATURE_AES_CBC
#define NOXTLS_FEATURE_AES_CBC 1
#endif
#ifndef NOXTLS_FEATURE_AES_CTR
#define NOXTLS_FEATURE_AES_CTR 1
#endif
#ifndef NOXTLS_FEATURE_AES_CFB
#define NOXTLS_FEATURE_AES_CFB 1
#endif
#ifndef NOXTLS_FEATURE_AES_OFB
#define NOXTLS_FEATURE_AES_OFB 1
#endif
#ifndef NOXTLS_FEATURE_AES_XTS
#define NOXTLS_FEATURE_AES_XTS 0
#endif
#ifndef NOXTLS_FEATURE_AES_GCM
#define NOXTLS_FEATURE_AES_GCM 1
#endif
#ifndef NOXTLS_FEATURE_AES_CCM
#define NOXTLS_FEATURE_AES_CCM 0
#endif
#ifndef NOXTLS_FEATURE_ARIA
#define NOXTLS_FEATURE_ARIA 0
#endif
#ifndef NOXTLS_FEATURE_CAMELLIA
#define NOXTLS_FEATURE_CAMELLIA 0
#endif
#ifndef NOXTLS_FEATURE_CHACHA20_POLY1305
#define NOXTLS_FEATURE_CHACHA20_POLY1305 1
#endif
#ifndef NOXTLS_FEATURE_DES
#define NOXTLS_FEATURE_DES 0
#endif
#ifndef NOXTLS_FEATURE_RC4
#define NOXTLS_FEATURE_RC4 0
#endif

#ifndef NOXTLS_FEATURE_RSA
#define NOXTLS_FEATURE_RSA 1
#endif
#ifndef NOXTLS_FEATURE_ECC
#define NOXTLS_FEATURE_ECC 1
#endif
#ifndef NOXTLS_FEATURE_ECDSA
#define NOXTLS_FEATURE_ECDSA 1
#endif
#ifndef NOXTLS_FEATURE_ECDH
#define NOXTLS_FEATURE_ECDH 1
#endif
#ifndef NOXTLS_FEATURE_DH
#define NOXTLS_FEATURE_DH 0
#endif
#ifndef NOXTLS_FEATURE_X25519
#define NOXTLS_FEATURE_X25519 1
#endif
#ifndef NOXTLS_FEATURE_X448
#define NOXTLS_FEATURE_X448 1
#endif
#ifndef NOXTLS_FEATURE_ED25519
#define NOXTLS_FEATURE_ED25519 1
#endif
#ifndef NOXTLS_FEATURE_ED448
#define NOXTLS_FEATURE_ED448 0
#endif
#ifndef NOXTLS_FEATURE_DSA
#define NOXTLS_FEATURE_DSA 1
#endif
#ifndef NOXTLS_FEATURE_ML_KEM
#define NOXTLS_FEATURE_ML_KEM 0
#endif
#ifndef NOXTLS_FEATURE_ML_DSA
#define NOXTLS_FEATURE_ML_DSA 0
#endif
#ifndef NOXTLS_FEATURE_SLH_DSA
#define NOXTLS_FEATURE_SLH_DSA 0
#endif
#ifndef NOXTLS_FEATURE_FALCON
#define NOXTLS_FEATURE_FALCON 0
#endif
#ifndef NOXTLS_FEATURE_LMS_HSS
#define NOXTLS_FEATURE_LMS_HSS 0
#endif
#ifndef NOXTLS_FEATURE_XMSS
#define NOXTLS_FEATURE_XMSS 0
#endif

#ifndef NOXTLS_FEATURE_TLS12
#define NOXTLS_FEATURE_TLS12 1
#endif
#ifndef NOXTLS_FEATURE_TLS13
#define NOXTLS_FEATURE_TLS13 1
#endif
#ifndef NOXTLS_FEATURE_DTLS
#define NOXTLS_FEATURE_DTLS 1
#endif
#ifndef NOXTLS_HAVE_CERT_WRITE
#define NOXTLS_HAVE_CERT_WRITE 1
#endif
#endif

#if defined(NOXTLS_PROFILE_CRYPTO_ONLY)
#ifndef NOXTLS_FEATURE_HASH
#define NOXTLS_FEATURE_HASH 1
#endif
#ifndef NOXTLS_FEATURE_HMAC
#define NOXTLS_FEATURE_HMAC 1
#endif
#ifndef NOXTLS_FEATURE_HKDF
#define NOXTLS_FEATURE_HKDF 1
#endif
#ifndef NOXTLS_FEATURE_ENCRYPTION
#define NOXTLS_FEATURE_ENCRYPTION 1
#endif
#ifndef NOXTLS_FEATURE_DRBG
#define NOXTLS_FEATURE_DRBG 1
#endif
#ifndef NOXTLS_FEATURE_PKC
#define NOXTLS_FEATURE_PKC 1
#endif
#ifndef NOXTLS_FEATURE_CERT
#define NOXTLS_FEATURE_CERT 0
#endif
#ifndef NOXTLS_FEATURE_TLS
#define NOXTLS_FEATURE_TLS 0
#endif

#ifndef NOXTLS_FEATURE_FALCON
#define NOXTLS_FEATURE_FALCON 0
#endif
#ifndef NOXTLS_FEATURE_LMS_HSS
#define NOXTLS_FEATURE_LMS_HSS 0
#endif
#ifndef NOXTLS_FEATURE_XMSS
#define NOXTLS_FEATURE_XMSS 0
#endif

#ifndef NOXTLS_FEATURE_TLS10
#define NOXTLS_FEATURE_TLS10 0
#endif
#ifndef NOXTLS_FEATURE_TLS11
#define NOXTLS_FEATURE_TLS11 0
#endif
#ifndef NOXTLS_FEATURE_MD4
#define NOXTLS_FEATURE_MD4 0
#endif
#ifndef NOXTLS_FEATURE_TLS12
#define NOXTLS_FEATURE_TLS12 0
#endif
#ifndef NOXTLS_FEATURE_TLS13
#define NOXTLS_FEATURE_TLS13 0
#endif
#ifndef NOXTLS_FEATURE_DTLS
#define NOXTLS_FEATURE_DTLS 0
#endif
#ifndef NOXTLS_HAVE_CERT_WRITE
#define NOXTLS_HAVE_CERT_WRITE 0
#endif
#ifndef NOXTLS_FEATURE_AES_XTS
#define NOXTLS_FEATURE_AES_XTS 0
#endif
#ifndef NOXTLS_FEATURE_ML_KEM
#define NOXTLS_FEATURE_ML_KEM 0
#endif
#ifndef NOXTLS_FEATURE_ML_DSA
#define NOXTLS_FEATURE_ML_DSA 0
#endif
#ifndef NOXTLS_FEATURE_SLH_DSA
#define NOXTLS_FEATURE_SLH_DSA 0
#endif
#endif

#if defined(NOXTLS_PROFILE_FIPS_LIKE)
#ifndef NOXTLS_FEATURE_HASH
#define NOXTLS_FEATURE_HASH 1
#endif
#ifndef NOXTLS_FEATURE_HMAC
#define NOXTLS_FEATURE_HMAC 1
#endif
#ifndef NOXTLS_FEATURE_HKDF
#define NOXTLS_FEATURE_HKDF 1
#endif
#ifndef NOXTLS_FEATURE_ENCRYPTION
#define NOXTLS_FEATURE_ENCRYPTION 1
#endif
#ifndef NOXTLS_FEATURE_DRBG
#define NOXTLS_FEATURE_DRBG 1
#endif
#ifndef NOXTLS_FEATURE_PKC
#define NOXTLS_FEATURE_PKC 1
#endif
#ifndef NOXTLS_FEATURE_CERT
#define NOXTLS_FEATURE_CERT 1
#endif
#ifndef NOXTLS_FEATURE_TLS
#define NOXTLS_FEATURE_TLS 1
#endif

#ifndef NOXTLS_FEATURE_TLS10
#define NOXTLS_FEATURE_TLS10 0
#endif
#ifndef NOXTLS_FEATURE_TLS11
#define NOXTLS_FEATURE_TLS11 0
#endif
#ifndef NOXTLS_FEATURE_MD4
#define NOXTLS_FEATURE_MD4 0
#endif
#ifndef NOXTLS_FEATURE_MD5
#define NOXTLS_FEATURE_MD5 0
#endif
#ifndef NOXTLS_FEATURE_SHA1
#define NOXTLS_FEATURE_SHA1 0
#endif
#ifndef NOXTLS_FEATURE_SHA224
#define NOXTLS_FEATURE_SHA224 1
#endif
#ifndef NOXTLS_FEATURE_SHA256
#define NOXTLS_FEATURE_SHA256 1
#endif
#ifndef NOXTLS_FEATURE_SHA384
#define NOXTLS_FEATURE_SHA384 1
#endif
#ifndef NOXTLS_FEATURE_SHA512
#define NOXTLS_FEATURE_SHA512 1
#endif
#ifndef NOXTLS_FEATURE_SHA3
#define NOXTLS_FEATURE_SHA3 0
#endif
#ifndef NOXTLS_FEATURE_RIPEMD160
#define NOXTLS_FEATURE_RIPEMD160 0
#endif
#ifndef NOXTLS_FEATURE_BLAKE2
#define NOXTLS_FEATURE_BLAKE2 0
#endif

#ifndef NOXTLS_FEATURE_AES
#define NOXTLS_FEATURE_AES 1
#endif
#ifndef NOXTLS_FEATURE_AES_128
#define NOXTLS_FEATURE_AES_128 1
#endif
#ifndef NOXTLS_FEATURE_AES_192
#define NOXTLS_FEATURE_AES_192 1
#endif
#ifndef NOXTLS_FEATURE_AES_256
#define NOXTLS_FEATURE_AES_256 1
#endif
#ifndef NOXTLS_FEATURE_AES_ECB
#define NOXTLS_FEATURE_AES_ECB 1
#endif
#ifndef NOXTLS_FEATURE_AES_CBC
#define NOXTLS_FEATURE_AES_CBC 1
#endif
#ifndef NOXTLS_FEATURE_AES_CTR
#define NOXTLS_FEATURE_AES_CTR 1
#endif
#ifndef NOXTLS_FEATURE_AES_CFB
#define NOXTLS_FEATURE_AES_CFB 1
#endif
#ifndef NOXTLS_FEATURE_AES_OFB
#define NOXTLS_FEATURE_AES_OFB 1
#endif
#ifndef NOXTLS_FEATURE_AES_XTS
#define NOXTLS_FEATURE_AES_XTS 0
#endif
#ifndef NOXTLS_FEATURE_AES_GCM
#define NOXTLS_FEATURE_AES_GCM 1
#endif
#ifndef NOXTLS_FEATURE_AES_CCM
#define NOXTLS_FEATURE_AES_CCM 0
#endif
#ifndef NOXTLS_FEATURE_AES_CMAC
#define NOXTLS_FEATURE_AES_CMAC 0
#endif
#ifndef NOXTLS_FEATURE_ARIA
#define NOXTLS_FEATURE_ARIA 0
#endif
#ifndef NOXTLS_FEATURE_CAMELLIA
#define NOXTLS_FEATURE_CAMELLIA 0
#endif
#ifndef NOXTLS_FEATURE_CHACHA20_POLY1305
#define NOXTLS_FEATURE_CHACHA20_POLY1305 0
#endif
#ifndef NOXTLS_FEATURE_DES
#define NOXTLS_FEATURE_DES 0
#endif
#ifndef NOXTLS_FEATURE_RC4
#define NOXTLS_FEATURE_RC4 0
#endif

#ifndef NOXTLS_FEATURE_RSA
#define NOXTLS_FEATURE_RSA 1
#endif
#ifndef NOXTLS_FEATURE_ECC
#define NOXTLS_FEATURE_ECC 1
#endif
#ifndef NOXTLS_FEATURE_ECDSA
#define NOXTLS_FEATURE_ECDSA 1
#endif
#ifndef NOXTLS_FEATURE_ECDH
#define NOXTLS_FEATURE_ECDH 1
#endif
#ifndef NOXTLS_FEATURE_DH
#define NOXTLS_FEATURE_DH 0
#endif
#ifndef NOXTLS_FEATURE_X25519
#define NOXTLS_FEATURE_X25519 0
#endif
#ifndef NOXTLS_FEATURE_X448
#define NOXTLS_FEATURE_X448 0
#endif
#ifndef NOXTLS_FEATURE_ED25519
#define NOXTLS_FEATURE_ED25519 0
#endif
#ifndef NOXTLS_FEATURE_ED448
#define NOXTLS_FEATURE_ED448 0
#endif
#ifndef NOXTLS_FEATURE_DSA
#define NOXTLS_FEATURE_DSA 1
#endif
#ifndef NOXTLS_FEATURE_ML_KEM
#define NOXTLS_FEATURE_ML_KEM 0
#endif
#ifndef NOXTLS_FEATURE_ML_DSA
#define NOXTLS_FEATURE_ML_DSA 0
#endif
#ifndef NOXTLS_FEATURE_SLH_DSA
#define NOXTLS_FEATURE_SLH_DSA 0
#endif
#ifndef NOXTLS_FEATURE_FALCON
#define NOXTLS_FEATURE_FALCON 0
#endif
#ifndef NOXTLS_FEATURE_LMS_HSS
#define NOXTLS_FEATURE_LMS_HSS 0
#endif
#ifndef NOXTLS_FEATURE_XMSS
#define NOXTLS_FEATURE_XMSS 0
#endif

#ifndef NOXTLS_FEATURE_TLS12
#define NOXTLS_FEATURE_TLS12 1
#endif
#ifndef NOXTLS_FEATURE_TLS13
#define NOXTLS_FEATURE_TLS13 1
#endif
#ifndef NOXTLS_FEATURE_DTLS
#define NOXTLS_FEATURE_DTLS 0
#endif
#ifndef NOXTLS_HAVE_CERT_WRITE
#define NOXTLS_HAVE_CERT_WRITE 0
#endif
#endif

#if defined(NOXTLS_PROFILE_UT_ALL_FEATURES)
#ifndef NOXTLS_FEATURE_HASH
#define NOXTLS_FEATURE_HASH 1
#endif
#ifndef NOXTLS_FEATURE_HMAC
#define NOXTLS_FEATURE_HMAC 1
#endif
#ifndef NOXTLS_FEATURE_HKDF
#define NOXTLS_FEATURE_HKDF 1
#endif
#ifndef NOXTLS_FEATURE_ENCRYPTION
#define NOXTLS_FEATURE_ENCRYPTION 1
#endif
#ifndef NOXTLS_FEATURE_DRBG
#define NOXTLS_FEATURE_DRBG 1
#endif
#ifndef NOXTLS_FEATURE_PKC
#define NOXTLS_FEATURE_PKC 1
#endif
#ifndef NOXTLS_FEATURE_CERT
#define NOXTLS_FEATURE_CERT 1
#endif
#ifndef NOXTLS_FEATURE_TLS
#define NOXTLS_FEATURE_TLS 1
#endif

#ifndef NOXTLS_FEATURE_MD4
#define NOXTLS_FEATURE_MD4 1
#endif
#ifndef NOXTLS_FEATURE_MD5
#define NOXTLS_FEATURE_MD5 1
#endif
#ifndef NOXTLS_FEATURE_SHA1
#define NOXTLS_FEATURE_SHA1 1
#endif
#ifndef NOXTLS_FEATURE_SHA224
#define NOXTLS_FEATURE_SHA224 1
#endif
#ifndef NOXTLS_FEATURE_SHA256
#define NOXTLS_FEATURE_SHA256 1
#endif
#ifndef NOXTLS_FEATURE_SHA384
#define NOXTLS_FEATURE_SHA384 1
#endif
#ifndef NOXTLS_FEATURE_SHA512
#define NOXTLS_FEATURE_SHA512 1
#endif
#ifndef NOXTLS_FEATURE_SHA3
#define NOXTLS_FEATURE_SHA3 1
#endif
#ifndef NOXTLS_FEATURE_RIPEMD160
#define NOXTLS_FEATURE_RIPEMD160 1
#endif
#ifndef NOXTLS_FEATURE_BLAKE2
#define NOXTLS_FEATURE_BLAKE2 1
#endif

#ifndef NOXTLS_FEATURE_AES
#define NOXTLS_FEATURE_AES 1
#endif
#ifndef NOXTLS_FEATURE_AES_128
#define NOXTLS_FEATURE_AES_128 1
#endif
#ifndef NOXTLS_FEATURE_AES_192
#define NOXTLS_FEATURE_AES_192 1
#endif
#ifndef NOXTLS_FEATURE_AES_256
#define NOXTLS_FEATURE_AES_256 1
#endif
#ifndef NOXTLS_FEATURE_AES_ECB
#define NOXTLS_FEATURE_AES_ECB 1
#endif
#ifndef NOXTLS_FEATURE_AES_CBC
#define NOXTLS_FEATURE_AES_CBC 1
#endif
#ifndef NOXTLS_FEATURE_AES_CTR
#define NOXTLS_FEATURE_AES_CTR 1
#endif
#ifndef NOXTLS_FEATURE_AES_CFB
#define NOXTLS_FEATURE_AES_CFB 1
#endif
#ifndef NOXTLS_FEATURE_AES_OFB
#define NOXTLS_FEATURE_AES_OFB 1
#endif
#ifndef NOXTLS_FEATURE_AES_XTS
#define NOXTLS_FEATURE_AES_XTS 1
#endif
#ifndef NOXTLS_FEATURE_AES_GCM
#define NOXTLS_FEATURE_AES_GCM 1
#endif
#ifndef NOXTLS_FEATURE_AES_CCM
#define NOXTLS_FEATURE_AES_CCM 1
#endif
#ifndef NOXTLS_FEATURE_AES_CMAC
#define NOXTLS_FEATURE_AES_CMAC 1
#endif
#ifndef NOXTLS_FEATURE_ARIA
#define NOXTLS_FEATURE_ARIA 1
#endif
#ifndef NOXTLS_FEATURE_CAMELLIA
#define NOXTLS_FEATURE_CAMELLIA 1
#endif
#ifndef NOXTLS_FEATURE_CHACHA20_POLY1305
#define NOXTLS_FEATURE_CHACHA20_POLY1305 1
#endif
#ifndef NOXTLS_FEATURE_DES
#define NOXTLS_FEATURE_DES 1
#endif
#ifndef NOXTLS_FEATURE_RC4
#define NOXTLS_FEATURE_RC4 1
#endif

#ifndef NOXTLS_FEATURE_RSA
#define NOXTLS_FEATURE_RSA 1
#endif
#ifndef NOXTLS_FEATURE_ECC
#define NOXTLS_FEATURE_ECC 1
#endif
#ifndef NOXTLS_FEATURE_ECDSA
#define NOXTLS_FEATURE_ECDSA 1
#endif
#ifndef NOXTLS_FEATURE_ECDH
#define NOXTLS_FEATURE_ECDH 1
#endif
#ifndef NOXTLS_FEATURE_DH
#define NOXTLS_FEATURE_DH 1
#endif
#ifndef NOXTLS_FEATURE_X25519
#define NOXTLS_FEATURE_X25519 1
#endif
#ifndef NOXTLS_FEATURE_X448
#define NOXTLS_FEATURE_X448 1
#endif
#ifndef NOXTLS_FEATURE_ED25519
#define NOXTLS_FEATURE_ED25519 1
#endif
#ifndef NOXTLS_FEATURE_ED448
#define NOXTLS_FEATURE_ED448 1
#endif
#ifndef NOXTLS_FEATURE_DSA
#define NOXTLS_FEATURE_DSA 1
#endif
#ifndef NOXTLS_FEATURE_ML_KEM
#define NOXTLS_FEATURE_ML_KEM 0
#endif
#ifndef NOXTLS_FEATURE_ML_DSA
#define NOXTLS_FEATURE_ML_DSA 0
#endif
#ifndef NOXTLS_FEATURE_SLH_DSA
#define NOXTLS_FEATURE_SLH_DSA 0
#endif

#ifndef NOXTLS_FEATURE_TLS10
#define NOXTLS_FEATURE_TLS10 1
#endif
#ifndef NOXTLS_FEATURE_TLS11
#define NOXTLS_FEATURE_TLS11 1
#endif
#ifndef NOXTLS_FEATURE_TLS12
#define NOXTLS_FEATURE_TLS12 1
#endif
#ifndef NOXTLS_FEATURE_TLS13
#define NOXTLS_FEATURE_TLS13 1
#endif
#ifndef NOXTLS_FEATURE_DTLS
#define NOXTLS_FEATURE_DTLS 1
#endif
#ifndef NOXTLS_HAVE_CERT_WRITE
#define NOXTLS_HAVE_CERT_WRITE 1
#endif
#ifndef NOXTLS_HAVE_TIME
#define NOXTLS_HAVE_TIME 0
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
#ifndef NOXTLS_FEATURE_HASH
#define NOXTLS_FEATURE_HASH 1
#endif

/* Enables generic HMAC primitive.
 * Prereq: NOXTLS_FEATURE_HASH=1.
 * Required by: HKDF and TLS transcript/finished MACs.
 */
#ifndef NOXTLS_FEATURE_HMAC
#define NOXTLS_FEATURE_HMAC 1
#endif

/* Enables generic HKDF (RFC 5869) primitive.
 * Prereq: NOXTLS_FEATURE_HMAC=1.
 * Required by: TLS 1.3 key schedule.
 */
#ifndef NOXTLS_FEATURE_HKDF
#define NOXTLS_FEATURE_HKDF 1
#endif

/* Enables PBKDF2 (RFC 8018 section 5.2) password-based key derivation over HMAC.
 * Prereq: NOXTLS_FEATURE_HMAC=1.
 * Required by: NOXTLS_FEATURE_MATTER_PASE (Matter passcode verifier).
 * Also used by: PKCS#8 PBES2 key decryption (falls back to a private
 * PBKDF2-HMAC-SHA1 when disabled) and IEEE 802.11 PSK-to-PMK mapping.
 * Build knob: NOXTLS_CFG_FEATURE_PBKDF2. Default OFF.
 */
#ifndef NOXTLS_FEATURE_PBKDF2
#define NOXTLS_FEATURE_PBKDF2 0
#endif

/* Enables symmetric encryption module family (AES/ARIA/Camellia/ChaCha/DES).
 * Prereq: none.
 * Required by: DRBG and TLS record protection.
 */
#ifndef NOXTLS_FEATURE_ENCRYPTION
#define NOXTLS_FEATURE_ENCRYPTION 1
#endif

/* Enables deterministic random bit generator (CTR-DRBG implementation).
 * Prereq: NOXTLS_FEATURE_ENCRYPTION=1 and NOXTLS_FEATURE_AES=1.
 */
#ifndef NOXTLS_FEATURE_DRBG
#define NOXTLS_FEATURE_DRBG 1
#endif

/* Enables public-key cryptography module family (RSA/ECC/curve algorithms).
 * Prereq: none.
 * Required by: certificates and most TLS key exchange/signature flows.
 */
#ifndef NOXTLS_FEATURE_PKC
#define NOXTLS_FEATURE_PKC 1
#endif

/* Enables X.509 certificate parsing/verification/generation support.
 * Prereq: NOXTLS_FEATURE_HASH=1 and NOXTLS_FEATURE_PKC=1.
 * Required by: certificate-authenticated TLS.
 */
#ifndef NOXTLS_FEATURE_CERT
#define NOXTLS_FEATURE_CERT 1
#endif

/* Hostname verification policy for certificate matching.
 * When 1, SAN/CN entries with left-most wildcard ("*.example.com") are accepted.
 * When 0, only exact SAN/CN DNS matches are accepted.
 * Runtime may override this default through noxtls_x509_set_hostname_wildcard_matching().
 */
#ifndef NOXTLS_X509_HOSTNAME_ALLOW_WILDCARD
#define NOXTLS_X509_HOSTNAME_ALLOW_WILDCARD 1
#endif

/* Detailed certificate failure information (noxtls_cert_verify_failure_get()).
 * When 1, the last failure keeps the subject DN, expected hostname and validity
 * strings (one static noxtls_cert_verify_failure_info_t, 556 bytes on Cortex-M4).
 * When 0, only return_code, cert_index and populated are kept (12 bytes of .bss);
 * the text fields read back empty. Size-constrained profiles may set 0.
 */
#ifndef NOXTLS_X509_FAIL_INFO
#define NOXTLS_X509_FAIL_INFO 1
#endif

/* Enables TLS protocol implementation.
 * Prereq: NOXTLS_FEATURE_HASH=1, NOXTLS_FEATURE_ENCRYPTION=1,
 *         NOXTLS_FEATURE_DRBG=1, NOXTLS_FEATURE_PKC=1, NOXTLS_FEATURE_CERT=1.
 */
#ifndef NOXTLS_FEATURE_TLS
#define NOXTLS_FEATURE_TLS 1
#endif

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
#ifndef NOXTLS_FEATURE_MD5
#define NOXTLS_FEATURE_MD5 1
#endif

/* Enables SHA-1 hashing algorithm.
 * Prereq: NOXTLS_FEATURE_HASH=1.
 * Security note: legacy algorithm; generally disable for modern deployments.
 */
#ifndef NOXTLS_FEATURE_SHA1
#define NOXTLS_FEATURE_SHA1 1
#endif

/* Enables SHA-224 hashing algorithm (same implementation as SHA-256).
 * Prereq: NOXTLS_FEATURE_HASH=1.
 * Build: sha256.c is compiled when NOXTLS_FEATURE_SHA224 or NOXTLS_FEATURE_SHA256 is 1.
 */
#ifndef NOXTLS_FEATURE_SHA224
#define NOXTLS_FEATURE_SHA224 1
#endif

/* Enables SHA-256 hashing algorithm.
 * Prereq: NOXTLS_FEATURE_HASH=1.
 * Required by: TLS and certificate verification flows.
 * Build: sha256.c is compiled when NOXTLS_FEATURE_SHA224 or NOXTLS_FEATURE_SHA256 is 1.
 */
#ifndef NOXTLS_FEATURE_SHA256
#define NOXTLS_FEATURE_SHA256 1
#endif

/* Enables the Cortex-M7 tuned software SHA-256 block compressor.
 * This is CPU-only and does not use STM32 HASH/CRYP peripherals.
 */
#ifndef NOXTLS_FEATURE_SHA256_CORTEXM7
#define NOXTLS_FEATURE_SHA256_CORTEXM7 0
#endif

/* Enables the 8-round unrolled portable C SHA-256 compressor path. */
#ifndef NOXTLS_SHA256_UNROLL_8
#define NOXTLS_SHA256_UNROLL_8 1
#endif

/* Enables SHA-384 hashing algorithm (same implementation as SHA-512).
 * Prereq: NOXTLS_FEATURE_HASH=1.
 * Build: sha512.c is compiled when NOXTLS_FEATURE_SHA384 or NOXTLS_FEATURE_SHA512 is 1.
 */
#ifndef NOXTLS_FEATURE_SHA384
#define NOXTLS_FEATURE_SHA384 1
#endif

/* Enables SHA-512 and truncated variants (SHA-512/224, SHA-512/256).
 * Prereq: NOXTLS_FEATURE_HASH=1.
 * Build: sha512.c is compiled when NOXTLS_FEATURE_SHA384 or NOXTLS_FEATURE_SHA512 is 1.
 */
#ifndef NOXTLS_FEATURE_SHA512
#define NOXTLS_FEATURE_SHA512 1
#endif

/* Enables SHA-3 hashing algorithms.
 * Prereq: NOXTLS_FEATURE_HASH=1.
 */
#ifndef NOXTLS_FEATURE_SHA3
#define NOXTLS_FEATURE_SHA3 1
#endif

/* Enables RIPEMD-160 hashing algorithm.
 * Prereq: NOXTLS_FEATURE_HASH=1.
 */
#ifndef NOXTLS_FEATURE_RIPEMD160
#define NOXTLS_FEATURE_RIPEMD160 1
#endif

/* Enables BLAKE2 hash family.
 * Prereq: NOXTLS_FEATURE_HASH=1.
 */
#ifndef NOXTLS_FEATURE_BLAKE2
#define NOXTLS_FEATURE_BLAKE2 1
#endif

/* Symmetric primitives */
/* Enables AES cipher family.
 * Prereq: NOXTLS_FEATURE_ENCRYPTION=1.
 * Constraint: at least one NOXTLS_FEATURE_AES_* mode and one NOXTLS_FEATURE_AES_* key size must be enabled.
 */
#ifndef NOXTLS_FEATURE_AES
#define NOXTLS_FEATURE_AES 1
#endif

/* Enables AES-128 key schedule/path.
 * Prereq: NOXTLS_FEATURE_AES=1.
 */
#ifndef NOXTLS_FEATURE_AES_128
#define NOXTLS_FEATURE_AES_128 1
#endif

/* Enables AES-192 key schedule/path.
 * Prereq: NOXTLS_FEATURE_AES=1.
 */
#ifndef NOXTLS_FEATURE_AES_192
#define NOXTLS_FEATURE_AES_192 1
#endif

/* Enables AES-256 key schedule/path.
 * Prereq: NOXTLS_FEATURE_AES=1.
 */
#ifndef NOXTLS_FEATURE_AES_256
#define NOXTLS_FEATURE_AES_256 1
#endif

/* Enables AES-ECB mode.
 * Prereq: NOXTLS_FEATURE_AES=1.
 * Security note: ECB is usually not suitable for bulk data confidentiality.
 */
#ifndef NOXTLS_FEATURE_AES_ECB
#define NOXTLS_FEATURE_AES_ECB 1
#endif

/* Enables AES-CBC mode.
 * Prereq: NOXTLS_FEATURE_AES=1.
 */
#ifndef NOXTLS_FEATURE_AES_CBC
#define NOXTLS_FEATURE_AES_CBC 1
#endif

/* Enables AES-CTR mode.
 * Prereq: NOXTLS_FEATURE_AES=1.
 */
#ifndef NOXTLS_FEATURE_AES_CTR
#define NOXTLS_FEATURE_AES_CTR 1
#endif

/* Enables AES-CFB mode.
 * Prereq: NOXTLS_FEATURE_AES=1.
 */
#ifndef NOXTLS_FEATURE_AES_CFB
#define NOXTLS_FEATURE_AES_CFB 1
#endif

/* Enables AES-OFB mode.
 * Prereq: NOXTLS_FEATURE_AES=1.
 */
#ifndef NOXTLS_FEATURE_AES_OFB
#define NOXTLS_FEATURE_AES_OFB 1
#endif

/* Enables AES-XTS mode.
 * Prereq: NOXTLS_FEATURE_AES=1.
 * Typical use case: storage encryption.
 */
#ifndef NOXTLS_FEATURE_AES_XTS
#define NOXTLS_FEATURE_AES_XTS 1
#endif

/* Enables AES-GCM AEAD mode.
 * Prereq: NOXTLS_FEATURE_AES=1.
 * Required by: TLS if ChaCha20-Poly1305 is disabled.
 */
#ifndef NOXTLS_FEATURE_AES_GCM
#define NOXTLS_FEATURE_AES_GCM 1
#endif

/* Software GHASH multiplier for AES-GCM.
 * 4 (default): Shoup 4-bit table, 256 B built on the stack per GCM call and
 *              wiped on return (no static cache; reentrant).
 * 0: constant-time bit-serial multiply, no table (16 B key, ~8x slower GHASH);
 *    for the smallest stacks or when table-lookup timing is a concern.
 * Prereq: NOXTLS_FEATURE_AES_GCM=1.
 */
#ifndef NOXTLS_GCM_TABLE_BITS
#define NOXTLS_GCM_TABLE_BITS 4
#endif

/* Enables AES-CCM AEAD mode.
 * Prereq: NOXTLS_FEATURE_AES=1.
 */
#ifndef NOXTLS_FEATURE_AES_CCM
#define NOXTLS_FEATURE_AES_CCM 1
#endif

/* Enables AES-CMAC (RFC 4493) for message authentication (e.g. BLE Signed Write).
 * Prereq: NOXTLS_FEATURE_AES=1.
 */
#ifndef NOXTLS_FEATURE_AES_CMAC
#define NOXTLS_FEATURE_AES_CMAC 1
#endif

/* Placement of the software AES encryption T-tables (Te0..Te3).
 * 1 (default): const tables in flash/ROM (+4 KB .rodata, 0 B RAM, no runtime init).
 * 0: tables built in RAM on first use (4 KB .bss + 1 B flag, ~4 KB less flash).
 * Use 0 only on parts where flash is scarcer than RAM or flash wait states make
 * table lookups slow. See also NOXTLS_AES_COMPACT_TABLES.
 * Prereq: NOXTLS_FEATURE_AES=1 (software AES path).
 */
#ifndef NOXTLS_AES_ROM_TABLES
#define NOXTLS_AES_ROM_TABLES 1
#endif

/* Keep a copy of the raw AES key in noxtls_aes_context_t (32 B per context).
 * Needed by block backends that take key bytes: platform accelerator ports
 * (including ports linked in through the noxtls_aes_accel_port_* hooks),
 * AES-NI and ARMv8 Apple. Builds that use only the software AES core may set
 * 0 to save 32 B in every AES context (and in GCM/CCM/XTS/CTR... call frames);
 * the port hooks are then not consulted for context-based operations.
 * Prereq: NOXTLS_FEATURE_AES=1.
 */
#ifndef NOXTLS_AES_CTX_RAW_KEY
#define NOXTLS_AES_CTX_RAW_KEY 1
#endif

/* Compact software AES encryption tables: keep only Te0 (1 KB) and derive
 * Te1..Te3 by 8/16/24-bit rotations at lookup time. Cuts the table footprint
 * from 4 KB to 1 KB (flash with NOXTLS_AES_ROM_TABLES=1, RAM otherwise) at a
 * small per-round cost (three extra rotates per column).
 * Prereq: NOXTLS_FEATURE_AES=1.
 */
#ifndef NOXTLS_AES_COMPACT_TABLES
#define NOXTLS_AES_COMPACT_TABLES 0
#endif

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

/* Bounded NoxV CCM: AES-128, nonce 13, AAD 1, MIC 4, payload 0..16.
 * Explicit opt-in; larger/different requests retain the generic CCM path. */
#ifndef NOXTLS_FEATURE_NOXV_CCM_ACCEL
#define NOXTLS_FEATURE_NOXV_CCM_ACCEL 0
#endif

/* Enables nRF52 ECB peripheral accelerated AES-128 block encrypt path.
 * Prereq: NOXTLS_FEATURE_AES=1.
 * Build knob: NOXTLS_CFG_FEATURE_NRF52_HW_ACCEL.
 */
#ifndef NOXTLS_FEATURE_NRF52_HW_ACCEL
#define NOXTLS_FEATURE_NRF52_HW_ACCEL 0
#endif

/* Umbrella for the original injected CC13xx accelerator callbacks: when 1, enables
 * both NOXTLS_FEATURE_CC13XX_AES_ACCEL and NOXTLS_FEATURE_CC13XX_P256_ACCEL.
 * No vendor SDK or OS dependency. Disabled by default.
 * Build knob: NOXTLS_CFG_FEATURE_CC13XX_HW_ACCEL.
 */
#ifndef NOXTLS_FEATURE_CC13XX_HW_ACCEL
#define NOXTLS_FEATURE_CC13XX_HW_ACCEL 0
#endif

/* Injected CC13xx AES engine callback port (AES block and bounded batch); a busy or
 * unbound engine falls back to software AES. Also enabled by NOXTLS_FEATURE_CC13XX_HW_ACCEL.
 * Prereq: NOXTLS_FEATURE_AES=1.
 * Build knob: NOXTLS_CFG_FEATURE_CC13XX_AES_ACCEL.
 */
#ifndef NOXTLS_FEATURE_CC13XX_AES_ACCEL
#define NOXTLS_FEATURE_CC13XX_AES_ACCEL 0
#endif

/* Injected CC13xx PKA callback port for secp256r1 point multiplication; a busy or
 * unbound PKA falls back to software ECC. Also enabled by NOXTLS_FEATURE_CC13XX_HW_ACCEL.
 * Prereq: NOXTLS_FEATURE_ECC=1.
 * Build knob: NOXTLS_CFG_FEATURE_CC13XX_P256_ACCEL.
 */
/** @brief Optional in-house CC13xx X25519 callback; disabled by default. */
#ifndef NOXTLS_FEATURE_CC13XX_X25519_ACCEL
#define NOXTLS_FEATURE_CC13XX_X25519_ACCEL 0
#endif

#ifndef NOXTLS_FEATURE_CC13XX_P256_ACCEL
#define NOXTLS_FEATURE_CC13XX_P256_ACCEL 0
#endif

/* When enabled, require nRF52 hardware AES support and disable software AES fallback.
 * Prereq: NOXTLS_FEATURE_NRF52_HW_ACCEL=1.
 * Build knob: NOXTLS_CFG_FEATURE_NRF52_HW_AES_ONLY.
 */
#ifndef NOXTLS_FEATURE_NRF52_HW_AES_ONLY
#define NOXTLS_FEATURE_NRF52_HW_AES_ONLY 0
#endif

/* Enables the nRF54L (nRF54LM20 / nRF54L15) CRACEN backend: AES block, ECB/CBC/CTR, GCM and CCM,
 * SHA-224/256/384/512, TRNG entropy for the DRBG, P-256 point multiply, ECDSA P-256 and Ed25519 verify,
 * with software fallback (noxtls-lib/vendor/nordic/nrf54x).
 * Prereq: NOXTLS_FEATURE_AES=1.
 * Build knob: NOXTLS_CFG_FEATURE_NRF54_HW_ACCEL.
 */
#ifndef NOXTLS_FEATURE_NRF54_HW_ACCEL
#define NOXTLS_FEATURE_NRF54_HW_ACCEL 0
#endif

/* Enables ARIA cipher family.
 * Prereq: NOXTLS_FEATURE_ENCRYPTION=1.
 */
#ifndef NOXTLS_FEATURE_ARIA
#define NOXTLS_FEATURE_ARIA 1
#endif

/* Enables Camellia cipher family.
 * Prereq: NOXTLS_FEATURE_ENCRYPTION=1.
 */
#ifndef NOXTLS_FEATURE_CAMELLIA
#define NOXTLS_FEATURE_CAMELLIA 1
#endif

/* Enables ChaCha20-Poly1305 AEAD.
 * Prereq: NOXTLS_FEATURE_ENCRYPTION=1.
 * Alternative TLS AEAD when AES-GCM is disabled or less preferred.
 */
#ifndef NOXTLS_FEATURE_CHACHA20_POLY1305
#define NOXTLS_FEATURE_CHACHA20_POLY1305 1
#endif

/* Enables DES/3DES-related implementation units.
 * Prereq: NOXTLS_FEATURE_ENCRYPTION=1.
 * Security note: legacy; generally disable for modern deployments.
 */
#ifndef NOXTLS_FEATURE_DES
#define NOXTLS_FEATURE_DES 1
#endif

/* Enables RC4 stream cipher.
 * Prereq: NOXTLS_FEATURE_ENCRYPTION=1.
 * Security note: RC4 is deprecated and weak; use only for legacy compatibility.
 */
#ifndef NOXTLS_FEATURE_RC4
#define NOXTLS_FEATURE_RC4 1
#endif

/* PKC primitives */
/* Enables RSA (and bignum backend used by RSA paths).
 * Prereq: NOXTLS_FEATURE_PKC=1.
 */
#ifndef NOXTLS_FEATURE_RSA
#define NOXTLS_FEATURE_RSA 1
#endif

/* Enables ECC core (short Weierstrass curve arithmetic).
 * Prereq: NOXTLS_FEATURE_PKC=1.
 * Required by: ECDSA and ECDH.
 */
#ifndef NOXTLS_FEATURE_ECC
#define NOXTLS_FEATURE_ECC 1
#endif

/* Enables ECDSA signatures.
 * Prereq: NOXTLS_FEATURE_PKC=1 and NOXTLS_FEATURE_ECC=1.
 */
#ifndef NOXTLS_FEATURE_ECDSA
#define NOXTLS_FEATURE_ECDSA 1
#endif

/* Enables ECDH key agreement.
 * Prereq: NOXTLS_FEATURE_PKC=1 and NOXTLS_FEATURE_ECC=1.
 */
#ifndef NOXTLS_FEATURE_ECDH
#define NOXTLS_FEATURE_ECDH 1
#endif

/* Enables finite-field Diffie-Hellman (FFDHE) support.
 * Prereq: NOXTLS_FEATURE_PKC=1.
 */
#ifndef NOXTLS_FEATURE_DH
#define NOXTLS_FEATURE_DH 1
#endif

/* Enables X25519 key agreement.
 * Prereq: NOXTLS_FEATURE_PKC=1.
 */
#ifndef NOXTLS_FEATURE_X25519
#define NOXTLS_FEATURE_X25519 1
#endif

/* Enables X448 key agreement.
 * Prereq: NOXTLS_FEATURE_PKC=1.
 */
#ifndef NOXTLS_FEATURE_X448
#define NOXTLS_FEATURE_X448 1
#endif

/* Enables Ed25519 signatures.
 * Prereq: NOXTLS_FEATURE_PKC=1.
 */
#ifndef NOXTLS_FEATURE_ED25519
#define NOXTLS_FEATURE_ED25519 1
#endif

/* Enables Ed448 signatures (RFC 8032). Requires NOXTLS_FEATURE_SHA3=1 for SHAKE256.
 * Prereq: NOXTLS_FEATURE_PKC=1. Default OFF; set NOXTLS_CFG_FEATURE_ED448=ON in CMake to enable.
 */
#ifndef NOXTLS_FEATURE_ED448
#define NOXTLS_FEATURE_ED448 0
#endif

/* Enables DSA (Digital Signature Algorithm) per FIPS 186-4.
 * Prereq: NOXTLS_FEATURE_PKC=1 (and bignum via RSA or DSA).
 */
#ifndef NOXTLS_FEATURE_DSA
#define NOXTLS_FEATURE_DSA 1
#endif
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
/* Enables FALCON signature APIs (NIST PQC finalist). */
#ifndef NOXTLS_FEATURE_FALCON
#define NOXTLS_FEATURE_FALCON 0
#endif
/* Enables LMS/HSS hash-based signature APIs (RFC 8554). */
#ifndef NOXTLS_FEATURE_LMS_HSS
#define NOXTLS_FEATURE_LMS_HSS 0
#endif
/* Enables XMSS/XMSS^MT hash-based signature APIs (RFC 8391). */
#ifndef NOXTLS_FEATURE_XMSS
#define NOXTLS_FEATURE_XMSS 0
#endif
/** XMSS/XMSS^MT: SHA-256 parameter sets (RFC 8391 n = 32 and SP 800-208 SHA-256/192).
 *  Default: 1. */
#ifndef NOXTLS_XMSS_ENABLE_SHA2
#define NOXTLS_XMSS_ENABLE_SHA2 1
#endif
/** XMSS/XMSS^MT: SHAKE parameter sets (SP 800-208 SHAKE256/256 and SHAKE256/192, RFC 8391
 *  SHAKE128 n = 32). Effective only with NOXTLS_FEATURE_SHA3. Default: 1. */
#ifndef NOXTLS_XMSS_ENABLE_SHAKE
#define NOXTLS_XMSS_ENABLE_SHAKE 1
#endif
/** XMSS/XMSS^MT: RFC 8391 n = 64 sets (SHA2_*_512 only with NOXTLS_FEATURE_SHA512, SHAKE_*_512).
 *  Not SP 800-208 approved; doubles node buffers (verify stack, traversal state).
 *  Default: 0. */
#ifndef NOXTLS_XMSS_ENABLE_N64
#define NOXTLS_XMSS_ENABLE_N64 0
#endif
/** XMSS/XMSS^MT: largest total tree height h accepted (10..60); sets above it are refused and
 *  NOXTLS_XMSS_MAX_SIGNATURE_LEN shrinks (h <= 20: 9251 bytes). Default: 60. */
#ifndef NOXTLS_XMSS_MAX_HEIGHT
#define NOXTLS_XMSS_MAX_HEIGHT 60
#endif
/** XMSS/XMSS^MT: key generation and stateful signing. 0 builds a verification-only module
 *  (firmware verifiers). Default: 1. */
#ifndef NOXTLS_XMSS_ENABLE_SIGN
#define NOXTLS_XMSS_ENABLE_SIGN 1
#endif
/** XMSS/XMSS^MT: verify every signature before it is released (fault countermeasure for
 *  reused XMSS^MT upper-layer one-time keys; about one verification per signature).
 *  Default: 1. */
#ifndef NOXTLS_XMSS_SIGN_SELF_CHECK
#define NOXTLS_XMSS_SIGN_SELF_CHECK 1
#endif

/* Enables SPAKE2+ augmented PAKE over P-256 with SHA-256, HKDF-SHA256 and HMAC-SHA256.
 * Prereq: NOXTLS_FEATURE_PKC=1 and NOXTLS_FEATURE_ECC=1 and NOXTLS_FEATURE_SHA256=1 and NOXTLS_FEATURE_HMAC=1 and NOXTLS_FEATURE_HKDF=1 and NOXTLS_FEATURE_DRBG=1.
 * Constraint: at least one of NOXTLS_FEATURE_SPAKE2P_RFC9383 / NOXTLS_FEATURE_SPAKE2P_MATTER.
 * Build knob: NOXTLS_CFG_FEATURE_SPAKE2P. Default OFF.
 */
#ifndef NOXTLS_FEATURE_SPAKE2P
#define NOXTLS_FEATURE_SPAKE2P 0
#endif

/* Includes the standard RFC 9383 SPAKE2+ key schedule (NOXTLS_SPAKE2P_PROFILE_RFC9383).
 * Effective only when NOXTLS_FEATURE_SPAKE2P=1; this is the default profile.
 * Build knob: NOXTLS_CFG_FEATURE_SPAKE2P_RFC9383. Default ON.
 */
#ifndef NOXTLS_FEATURE_SPAKE2P_RFC9383
#define NOXTLS_FEATURE_SPAKE2P_RFC9383 1
#endif

/* Includes the draft-bar-cfrg-spake2plus-01 key schedule used by Matter PASE
 * (NOXTLS_SPAKE2P_PROFILE_MATTER). Not RFC 9383; for Matter interoperability only.
 * Effective only when NOXTLS_FEATURE_SPAKE2P=1.
 * Build knob: NOXTLS_CFG_FEATURE_SPAKE2P_MATTER. Default OFF.
 */
#ifndef NOXTLS_FEATURE_SPAKE2P_MATTER
#define NOXTLS_FEATURE_SPAKE2P_MATTER 0
#endif

/* Enables Matter PASE cryptographic helpers (passcode verifier, PASE context, session keys).
 * Prereq: NOXTLS_FEATURE_SPAKE2P=1 and NOXTLS_FEATURE_SPAKE2P_MATTER=1 and NOXTLS_FEATURE_PBKDF2=1.
 * Build knob: NOXTLS_CFG_FEATURE_MATTER_PASE. Default OFF.
 */
#ifndef NOXTLS_FEATURE_MATTER_PASE
#define NOXTLS_FEATURE_MATTER_PASE 0
#endif

/* Enables EC-JPAKE over P-256 with SHA-256 Schnorr NIZK proofs (RFC 8236 section 3,
 * RFC 8235 section 3, draft-cragie-tls-ecjpake-01 section 8).
 * Prereq: NOXTLS_FEATURE_PKC=1 and NOXTLS_FEATURE_ECC=1 and NOXTLS_FEATURE_SHA256=1 and NOXTLS_FEATURE_DRBG=1.
 * Build knob: NOXTLS_CFG_FEATURE_ECJPAKE. Default OFF.
 */
#ifndef NOXTLS_FEATURE_ECJPAKE
#define NOXTLS_FEATURE_ECJPAKE 0
#endif

/* Enables TLS_ECJPAKE_WITH_AES_128_CCM_8 (0xC0FF) and the ecjpake_key_kp_pair extension (256)
 * in the TLS 1.2 / DTLS 1.2 engine (draft-cragie-tls-ecjpake-01; Thread MeshCoP commissioning).
 * Prereq: NOXTLS_FEATURE_ECJPAKE=1 and NOXTLS_FEATURE_TLS=1 and NOXTLS_FEATURE_TLS12=1 and
 * NOXTLS_FEATURE_DTLS=1 and NOXTLS_FEATURE_AES_CCM=1.
 * Build knob: NOXTLS_CFG_FEATURE_DTLS_ECJPAKE. Default OFF.
 */
#ifndef NOXTLS_FEATURE_DTLS_ECJPAKE
#define NOXTLS_FEATURE_DTLS_ECJPAKE 0
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
#ifndef NOXTLS_FEATURE_TLS12
#define NOXTLS_FEATURE_TLS12 1
#endif

/* Enables TLS 1.3 protocol implementation.
 * Prereq: NOXTLS_FEATURE_TLS=1.
 */
#ifndef NOXTLS_FEATURE_TLS13
#define NOXTLS_FEATURE_TLS13 1
#endif

/* TLS roles built into the library. A client-only build (NOXTLS_FEATURE_TLS_SERVER=0) drops
 * the server handshakes, the server session/ticket caches and server-only context fields;
 * a server-only build (NOXTLS_FEATURE_TLS_CLIENT=0) drops the client handshakes and the
 * client session store. At least one must be 1. Default: both 1.
 */
#ifndef NOXTLS_FEATURE_TLS_CLIENT
#define NOXTLS_FEATURE_TLS_CLIENT 1
#endif
#ifndef NOXTLS_FEATURE_TLS_SERVER
#define NOXTLS_FEATURE_TLS_SERVER 1
#endif

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

/*
 * TLS 1.3 / DTLS 1.3 certificate-based peer authentication.
 * 1 (default): full RFC 8446 Section 4.4.2 Certificate and 4.4.3 CertificateVerify
 * receive paths. 0: PSK-only profile. A client aborts with handshake_failure when the
 * server did not select its PSK (before any Certificate is read), a server never sends
 * CertificateRequest, and the peer Certificate/CertificateVerify receivers are not
 * built. Set 0 only when every TLS 1.3 context authenticates with an external PSK.
 * Also settable with the CMake option NOXTLS_TLS13_PEER_CERTIFICATES=OFF.
 */
#ifndef NOXTLS_TLS13_PEER_CERTIFICATES
#define NOXTLS_TLS13_PEER_CERTIFICATES 1
#endif

/*
 * Prefer secp256r1 over X25519 in TLS 1.3 group ordering.
 * Default keeps the standard X25519-first preference. Platforms where
 * X25519 is materially slower than P-256 can set this to 1.
 */
#ifndef NOXTLS_CFG_TLS13_PREFER_SECP256R1_OVER_X25519
#define NOXTLS_CFG_TLS13_PREFER_SECP256R1_OVER_X25519 0
#endif

/* Enables DTLS support.
 * Prereq: NOXTLS_FEATURE_TLS=1.
 * When built via CMake/Kconfig, NOXTLS_FEATURE_DTLS is set on the command line; do not override here.
 */
#ifndef NOXTLS_FEATURE_DTLS
#define NOXTLS_FEATURE_DTLS 1
#endif

/* Enables legacy TLS 1.2 / DTLS 1.2 cipher suites: every CBC-mode suite (AES-CBC, ARIA-CBC
 * and 3DES; 3DES additionally needs NOXTLS_FEATURE_DES=1) and every static-RSA key exchange
 * suite (TLS_RSA_WITH_*, including the AES-GCM and AES-CCM ones). When 0, TLS 1.2
 * offers and negotiates only forward-secret AEAD suites (ECDHE-ECDSA, ECDHE-RSA, DHE-RSA with
 * AES-GCM, ChaCha20-Poly1305, AES-CCM, AES-CCM_8). TLS 1.0 / 1.1 connections
 * (NOXTLS_FEATURE_TLS10 / NOXTLS_FEATURE_TLS11) always use their CBC suites.
 * Security note: CBC suites need careful padding-oracle / timing handling and static RSA has
 * no forward secrecy; keep disabled unless strict backwards compatibility is required.
 */
#ifndef NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES
#define NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES 0
#endif

/* Enables SHA-1 signatures in TLS 1.2 / DTLS 1.2 handshakes (rsa_pkcs1_sha1 0x0201,
 * ecdsa_sha1 0x0203): the client offers them in signature_algorithms and accepts them in
 * ServerKeyExchange, and the server signs ServerKeyExchange with SHA-1 when the client asks
 * for it or omits signature_algorithms (RFC 5246 7.4.1.4.1 implicit SHA-1 default). When 0, a
 * server facing a client without signature_algorithms fails with handshake_failure.
 * MD5 signatures are never negotiated. TLS 1.0 / 1.1 use their fixed MD5 / SHA-1 signatures.
 * Prereq: NOXTLS_FEATURE_SHA1=1 (no effect without it).
 * Security note: SHA-1 signatures are deprecated (RFC 9155); keep disabled unless a peer
 * cannot sign with SHA-256 or better.
 */
#ifndef NOXTLS_TLS12_ENABLE_SHA1_SIGNATURES
#define NOXTLS_TLS12_ENABLE_SHA1_SIGNATURES 0
#endif

/* Enables the NSS key log (SSLKEYLOGFILE format) writer for TLS 1.3 traffic secrets
 * (noxtls_tls13_set_keylog_file() / SSLKEYLOGFILE environment variable).
 * Prereq: NOXTLS_HAVE_FILE_IO=1.
 * Security note: writes handshake secrets to a file; debugging aid only. When 0 the
 * setter is a no-op and no getenv/fopen code or path buffer is linked.
 */
#ifndef NOXTLS_FEATURE_KEYLOG
#define NOXTLS_FEATURE_KEYLOG 0
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
#ifndef NOXTLS_HAVE_TIME
#if defined(NOXTLS_PROFILE_UT_ALL_FEATURES)
#define NOXTLS_HAVE_TIME 0
#else
#define NOXTLS_HAVE_TIME 1
#endif
#endif

/* NOXTLS_HAVE_FILE_IO
 *
 * Define to 1 when stdio file helpers (fopen/fread/load_file) are available.
 * Define to 0 for embedded/MISRA scan profiles that must not pull in stdio.
 *
 * File-load APIs return NOXTLS_RETURN_FAILED when disabled.
 */
#ifndef NOXTLS_HAVE_FILE_IO
#define NOXTLS_HAVE_FILE_IO 1
#endif

/* ============================================================================
 * Memory Management Configuration
 * ============================================================================
 */

/* NOXTLS_HMAC_SHA256_SHARED_STATE
 * Deprecated, no effect (kept so existing configurations still build).
 * noxtls_hmac_context_t now embeds its hash state and the precomputed
 * key-pad chaining values, so HMAC never allocates and never uses a shared
 * static slot; independent live contexts are always permitted.
 */
#ifndef NOXTLS_HMAC_SHA256_SHARED_STATE
#define NOXTLS_HMAC_SHA256_SHARED_STATE 0
#endif

/* NOXTLS_ECC_SHARED_SCRATCH
 * Move ECC inversion and the P-256 bignum inversion fast-path scratch from
 * the call stack to fixed shared storage. Callers MUST serialize operations
 * that use this scratch, including interrupts; this mode is not reentrant.
 * Default: 0 (private per-call scratch).
 */
#ifndef NOXTLS_ECC_SHARED_SCRATCH
#define NOXTLS_ECC_SHARED_SCRATCH 0
#endif

/* NOXTLS_PKC_SHARED_DRBG
 * When 1, ECC key generation, ECDSA nonces, RSA (keygen, padding, blinding),
 * X25519/X448 and Ed25519/Ed448 key generation draw from ONE internal
 * CTR-DRBG state instead of seven per-module static drbg_state_t (saves
 * about 6 x sizeof(drbg_state_t) of .bss). The state is reseeded every
 * NOXTLS_PKC_RNG_RESEED_INTERVAL requests; a generate that invalidates the
 * state (AES failure) fails that call and the next call re-instantiates from
 * fresh entropy. The state is not locked: callers
 * that generate PKC randomness from several threads must serialize those
 * calls (with 0, only calls into the same module need serializing).
 * Default: 1 (shared state).
 */
#ifndef NOXTLS_PKC_SHARED_DRBG
#define NOXTLS_PKC_SHARED_DRBG 1
#endif

/* NOXTLS_PKC_RNG_RESEED_INTERVAL
 * Number of generate requests after which the long-lived PKC CTR-DRBG (see
 * NOXTLS_PKC_SHARED_DRBG) reseeds from the entropy source before the next
 * request, so that a compromise of its state exposes at most that many future
 * outputs. 0 = reseed only at the SP 800-90A limit (DRBG_RESEED_INTERVAL,
 * 2^48 requests). Each reseed reads security-strength bits (32 bytes for
 * AES-256) from the entropy source. If the reseed cannot get entropy the
 * request fails and the next request retries.
 * Default: 1024.
 */
#ifndef NOXTLS_PKC_RNG_RESEED_INTERVAL
#define NOXTLS_PKC_RNG_RESEED_INTERVAL 1024
#endif

/* NOXTLS_CONFIG_STATIC_MEMORY
 *
 * 1: every byte NoxTLS uses is sized at build time and nothing reaches malloc()
 * or a general-purpose heap. NOXTLS_MALLOC/CALLOC/REALLOC resolve to a region
 * allocator over storage that is either supplied by the caller per connection
 * (noxtls_tls13_context_init_static / noxtls_dtls13_context_init_static) or
 * reserved statically by the library (global pool, connection pool). A full
 * region returns a deterministic NOXTLS_RETURN_NOT_ENOUGH_MEMORY; there is no
 * fallback. Handshake-only storage is wiped and released when the handshake
 * completes. Sizing macros and profiles: noxtls-lib/common/noxtls_static_memory.h
 * and docs/static-memory.md. Mutually exclusive with NOXTLS_USE_STATIC_BUFFERS.
 *
 * Default: 0 (allocation through noxtls_malloc() and the system allocator).
 */
#ifndef NOXTLS_CONFIG_STATIC_MEMORY
#define NOXTLS_CONFIG_STATIC_MEMORY 0
#endif

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

/* NOXTLS_STATIC_ALLOCATOR_MODE
 * Selects the allocator used when NOXTLS_USE_STATIC_BUFFERS is enabled.
 * LEGACY preserves the original first-fit fallback allocator.
 * BUCKETS uses only fixed-size bucket pools.
 * HYBRID uses bucket pools first and a fallback pool for oversized or exhausted bucket allocations.
 */
#ifndef NOXTLS_STATIC_ALLOCATOR_MODE_LEGACY
#define NOXTLS_STATIC_ALLOCATOR_MODE_LEGACY 0
#endif
#ifndef NOXTLS_STATIC_ALLOCATOR_MODE_BUCKETS
#define NOXTLS_STATIC_ALLOCATOR_MODE_BUCKETS 1
#endif
#ifndef NOXTLS_STATIC_ALLOCATOR_MODE_HYBRID
#define NOXTLS_STATIC_ALLOCATOR_MODE_HYBRID 2
#endif
#ifndef NOXTLS_STATIC_ALLOCATOR_MODE
#define NOXTLS_STATIC_ALLOCATOR_MODE NOXTLS_STATIC_ALLOCATOR_MODE_HYBRID
#endif

#ifndef NOXTLS_MEM_BUCKET_COUNT
#define NOXTLS_MEM_BUCKET_COUNT 9U
#endif

#ifndef NOXTLS_MEM_BUCKET_SIZES
#define NOXTLS_MEM_BUCKET_SIZES 32U, 64U, 128U, 256U, 512U, 1024U, 2048U, 4096U, 8192U
#endif

#ifndef NOXTLS_MEM_BUCKET_COUNTS
#define NOXTLS_MEM_BUCKET_COUNTS 16U, 16U, 12U, 10U, 8U, 6U, 4U, 2U, 1U
#endif

#ifndef NOXTLS_MEM_BUCKET_ALIGNMENT
#define NOXTLS_MEM_BUCKET_ALIGNMENT 8U
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
#define NOXTLS_TLS_MAX_RECORD_SIZE 16384U
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
#define NOXTLS_TLS_MAX_HANDSHAKE_SIZE 65536U
#endif

/** DTLS: most bytes held for handshake reassembly per connection (the in-progress message
 *  plus the out-of-order future messages, buffers and received bitmaps). A future message that
 *  does not fit is dropped (the peer retransmits it); the in-progress message evicts future
 *  messages first and is rejected (NOT_ENOUGH_MEMORY) if it still does not fit. Must be
 *  >= NOXTLS_TLS_MAX_HANDSHAKE_SIZE plus 1/8 of it for the bitmap to accept every message.
 *  Default: 2 * NOXTLS_TLS_MAX_HANDSHAKE_SIZE. */
#ifndef NOXTLS_DTLS_REASSEMBLY_MAX_BYTES
#define NOXTLS_DTLS_REASSEMBLY_MAX_BYTES (2U * NOXTLS_TLS_MAX_HANDSHAKE_SIZE)
#endif

/** TLS 1.3 server: most 0-RTT (early data) plaintext bytes buffered for the application
 *  before the handshake completes; more is rejected with unexpected_message
 *  (RFC 8446 4.2.10). Default: 16384. */
#ifndef NOXTLS_TLS13_SERVER_MAX_EARLY_DATA
#define NOXTLS_TLS13_SERVER_MAX_EARLY_DATA 16384U
#endif

/** TLS 1.2 server: entries of the process-global session-ID resumption cache (about 150 B
 *  each, server role only). 0 compiles the cache out (no session-ID resumption).
 *  Default: 16. */
#ifndef NOXTLS_TLS12_SESSION_CACHE_SIZE
#define NOXTLS_TLS12_SESSION_CACHE_SIZE 16U
#endif

/** TLS 1.2 server: entries of the process-global session-ticket cache (about 210 B each,
 *  server role only). 0 compiles the cache out: the server neither accepts nor issues
 *  RFC 5077 tickets. Default: 32. */
#ifndef NOXTLS_TLS12_TICKET_CACHE_SIZE
#define NOXTLS_TLS12_TICKET_CACHE_SIZE 32U
#endif

/** TLS 1.2 client: largest NewSessionTicket ticket stored for resumption (larger tickets
 *  are ignored, the next connection does a full handshake). Default: 256. */
#ifndef NOXTLS_TLS12_TICKET_MAX_LEN
#define NOXTLS_TLS12_TICKET_MAX_LEN 256U
#endif

/** TLS 1.3 server: entries of the process-global resumption ticket store (about 120 B
 *  each, server role only), 0..64. 0 compiles the store out: no NewSessionTicket is sent
 *  and resumption PSKs are not accepted. Default: 64. */
#ifndef NOXTLS_TLS13_PSK_TICKET_STORE_MAX
#define NOXTLS_TLS13_PSK_TICKET_STORE_MAX 64U
#endif

/** TLS 1.3 server diagnostics: record a per-step timing breakdown of every accept in
 *  tls13_context_t::last_accept_timing (232 bytes per context, monotonic clock reads).
 *  Default: 0 (field and clock reads compiled out). */
#ifndef NOXTLS_TLS13_ACCEPT_TIMING
#define NOXTLS_TLS13_ACCEPT_TIMING 0
#endif

/** Maximum single certificate size in bytes accepted by X.509 parse APIs.
 *  Default: 16384.
 */
#ifndef NOXTLS_MAX_CERT_SIZE
#if NOXTLS_FEATURE_SLH_DSA
/* SLH-DSA signatures are large (up to ~50 KB). Allow 64 KB certs by default
 * when SLH-DSA is enabled so the cert+TBS+signature comfortably fits. */
#define NOXTLS_MAX_CERT_SIZE 65536U
#elif NOXTLS_FEATURE_ML_DSA
/* ML-DSA-87 signatures are ~4.6 KB; combined with public-key (~2.6 KB) and TBS
 * fields, 32 KB headroom is plenty. */
#define NOXTLS_MAX_CERT_SIZE 32768U
#else
#define NOXTLS_MAX_CERT_SIZE 16384U
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

/** Certificate slots added per chain growth step. A chain allocates nothing at
 * init; the first add allocates this many slots and later adds grow the slot
 * array linearly by the same step (each slot is sizeof(x509_certificate_t),
 * ~152 bytes on Cortex-M4; certificate DER is allocated separately). Use
 * noxtls_x509_certificate_chain_reserve() for a known count. This does not
 * limit verification depth.
 */
#ifndef NOXTLS_X509_CHAIN_INITIAL_CAPACITY
#define NOXTLS_X509_CHAIN_INITIAL_CAPACITY 1U
#endif

/** Keep the parsed peer certificate (x509_certificate_t) for the whole connection.
 *  0 (default): the parsed view of the peer leaf is released as soon as the
 *    handshake no longer needs it (TLS 1.3 client: after CertificateVerify and the
 *    hostname check; TLS 1.2 client: after ClientKeyExchange; TLS 1.2/1.3 server:
 *    after the client CertificateVerify). The peer DER stays available
 *    (noxtls_tls_connection_get_peer_certificate(), tls-server-end-point channel
 *    binding); noxtls_tls12_get_client_certificate() returns
 *    NOXTLS_RETURN_NOT_SUPPORTED (DER still returned) when the parsed certificate
 *    is requested - parse the DER with noxtls_x509_certificate_parse_der_nocopy().
 *  1: retain the parsed certificate until the context is freed (previous behaviour).
 */
#ifndef NOXTLS_TLS_RETAIN_PEER_CERT
#define NOXTLS_TLS_RETAIN_PEER_CERT 0
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
#ifndef NOXTLS_RSA_MAX_PRIME_ATTEMPTS
#define NOXTLS_RSA_MAX_PRIME_ATTEMPTS 50000U
#endif

/* NOXTLS_RSA_MILLER_RABIN_ITERATIONS_SMALL
 * 
 * Number of Miller-Rabin test iterations for "small" primes (<= 512 bits).
 * 
 * Security: 2 iterations gives error probability of ~2^-40 (very secure)
 * 
 * Default: 2 iterations
 */
#ifndef NOXTLS_RSA_MILLER_RABIN_ITERATIONS_SMALL
#define NOXTLS_RSA_MILLER_RABIN_ITERATIONS_SMALL 2U
#endif

/* NOXTLS_RSA_MILLER_RABIN_ITERATIONS_LARGE
 * 
 * Number of Miller-Rabin test iterations for "large" primes (> 512 bits).
 * 
 * Security: 3 iterations gives error probability of ~2^-60 (extremely secure)
 * 
 * Default: 3 iterations
 */
#ifndef NOXTLS_RSA_MILLER_RABIN_ITERATIONS_LARGE
#define NOXTLS_RSA_MILLER_RABIN_ITERATIONS_LARGE 3U
#endif

/* NOXTLS_RSA_MILLER_RABIN_SMALL_THRESHOLD_BITS
 * 
 * Prime size threshold (in bits) for determining "small" vs "large" primes.
 * Primes <= this size use NOXTLS_RSA_MILLER_RABIN_ITERATIONS_SMALL.
 * Primes > this size use NOXTLS_RSA_MILLER_RABIN_ITERATIONS_LARGE.
 * 
 * Default: 512 bits
 */
#ifndef NOXTLS_RSA_MILLER_RABIN_SMALL_THRESHOLD_BITS
#define NOXTLS_RSA_MILLER_RABIN_SMALL_THRESHOLD_BITS 512U
#endif

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
#ifndef NOXTLS_RSA_ENABLE_QUICK_DIVISIBILITY_TEST
#define NOXTLS_RSA_ENABLE_QUICK_DIVISIBILITY_TEST 1
#endif

/* NOXTLS_RSA_DEBUG_PROGRESS_INTERVAL
 * 
 * Interval (in attempts) for printing progress messages during prime generation.
 * Set to 0 to disable progress messages.
 * 
 * Default: 100 (print every 100 attempts)
 */
#ifndef NOXTLS_RSA_DEBUG_PROGRESS_INTERVAL
#define NOXTLS_RSA_DEBUG_PROGRESS_INTERVAL 100U
#endif

/* NOXTLS_RSA_DEBUG_PRIMALITY_CHECK_INTERVAL
 * 
 * Interval (in attempts) for printing messages when checking primality
 * (after quick divisibility test passes).
 * Set to 0 to disable these messages.
 * 
 * Default: 50 (print every 50 attempts)
 */
#ifndef NOXTLS_RSA_DEBUG_PRIMALITY_CHECK_INTERVAL
#define NOXTLS_RSA_DEBUG_PRIMALITY_CHECK_INTERVAL 50U
#endif

/* NOXTLS_RSA_DEBUG_REJECTED_CANDIDATE_INTERVAL
 * 
 * Interval (in attempts) for printing debug info about rejected candidates.
 * Only prints for the first 500 attempts to avoid spam.
 * Set to 0 to disable rejected candidate debug output.
 * 
 * Default: 100 (print every 100 attempts, up to 500 attempts)
 */
#ifndef NOXTLS_RSA_DEBUG_REJECTED_CANDIDATE_INTERVAL
#define NOXTLS_RSA_DEBUG_REJECTED_CANDIDATE_INTERVAL 100U
#endif

/* NOXTLS_RSA_DEBUG_REJECTED_CANDIDATE_MAX_ATTEMPTS
 * 
 * Maximum number of attempts for which to print rejected candidate debug info.
 * After this many attempts, rejected candidate debug output is disabled.
 * 
 * Default: 500 attempts
 */
#ifndef NOXTLS_RSA_DEBUG_REJECTED_CANDIDATE_MAX_ATTEMPTS
#define NOXTLS_RSA_DEBUG_REJECTED_CANDIDATE_MAX_ATTEMPTS 500U
#endif

/* NOXTLS_BN_MONT_WINDOW_BITS
 *
 * Window width W (bits) of the constant-time Montgomery exponentiation used for
 * secret exponents (RSA private key / CRT halves, DH, DSA signing). Its table
 * holds 2^W residues of the modulus size: 2^W * 128 B for an RSA-2048 CRT half,
 * 2^W * 256 B for DH-2048 or non-CRT RSA-2048. Smaller W saves RAM, larger W
 * saves multiplications (1024-bit exponent: W=2 +19%, W=3 +6%, W=5 -3% vs W=4).
 * Public exponents (RSA e) use a table-free path and are not affected.
 * Range: 1..6.
 *
 * Default: 4 (16-entry table)
 */
#ifndef NOXTLS_BN_MONT_WINDOW_BITS
#define NOXTLS_BN_MONT_WINDOW_BITS 4U
#endif

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
#ifndef NOXTLS_ECC_POINT_MUL_WINDOW_SIZE
#define NOXTLS_ECC_POINT_MUL_WINDOW_SIZE 4
#endif

/* NOXTLS_ECC_FIXED_POINT_OPTIM
 *
 * When 1, cache precomputed multiples of the curve generator G and reuse for
 * repeated k*G (ECDSA sign, key gen, ECDHE). Speeds up fixed-base multiplications.
 *
 * Default: 1 (enabled)
 */
#ifndef NOXTLS_ECC_FIXED_POINT_OPTIM
#define NOXTLS_ECC_FIXED_POINT_OPTIM 1
#endif

/* NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE
 *
 * When 1, keep a process-global precompute table for repeated fixed-base ECC
 * scalar multiplication (generator G of curves without a read-only table) and
 * the last P-256 joint verification table, keyed by curve id. This speeds up
 * repeated operations at the cost of retained heap.
 *
 * Tradeoffs:
 * - Retains allocator-backed tables (1-4 KB per curve) after first use.
 * - Shared mutable cache state is not internally locked; multi-threaded users
 *   must serialize ECC use externally.
 *
 * Default: 0 (no retained tables; P-256 uses NOXTLS_ECC_P256_FLASH_PRECOMPUTE)
 */
#ifndef NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE
#define NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE 0
#endif

/* NOXTLS_ECC_P256_FLASH_PRECOMPUTE
 *
 * When 1, use a compact, compile-time P-256 generator comb table from
 * read-only storage instead of building the fixed-base table on the heap.
 * Embedded linkers normally place the const table in flash/ROM. This adds
 * approximately 2 KiB of read-only data, removes the per-operation table
 * build and its heap, and is as fast as or faster than the heap table.
 *
 * Default: 1 (read-only generator table)
 */
#ifndef NOXTLS_ECC_P256_FLASH_PRECOMPUTE
#define NOXTLS_ECC_P256_FLASH_PRECOMPUTE 1
#endif

/* NOXTLS_ECC_P256_LOW_RAM_VERIFY
 *
 * When 1, P-256 two-scalar multiplication with G as one point uses the
 * flash generator table plus a compact 8-entry runtime table for the public
 * point instead of the 64-entry joint verification table. Requires
 * NOXTLS_ECC_P256_FLASH_PRECOMPUTE.
 *
 * Default: NOXTLS_ECC_P256_FLASH_PRECOMPUTE (1: low-RAM verification, measured
 * as fast as the joint table)
 */
#ifndef NOXTLS_ECC_P256_LOW_RAM_VERIFY
#define NOXTLS_ECC_P256_LOW_RAM_VERIFY NOXTLS_ECC_P256_FLASH_PRECOMPUTE
#endif

/* NOXTLS_ECC_ENABLE_<curve>
 *
 * Per-curve enables for the short Weierstrass curves (ECC, ECDSA, ECDH).
 * A disabled curve is rejected by noxtls_ecc_curve_init()/noxtls_ecc_key_init()
 * (NOXTLS_RETURN_FAILED) and its constants are not linked. ECC_MAX_KEY_SIZE,
 * the coordinate array size of ecc_point_t / ecc_jpoint_t / ecdsa_signature_t,
 * is derived from the largest enabled curve: 66 with P-521, 64 with
 * brainpoolP512r1, 48 with P-384/brainpoolP384r1, 32 for 256-bit curves only.
 * A P-256-only build (all others 0) shrinks ecc_point_t 136 -> 68 bytes and
 * the ECC stack/heap accordingly. All translation units must see the same
 * values (set them here or with -D for the whole build).
 *
 * Default: 1 for every curve (unchanged curve support)
 */
#ifndef NOXTLS_ECC_ENABLE_SECP192R1
#define NOXTLS_ECC_ENABLE_SECP192R1 1
#endif
#ifndef NOXTLS_ECC_ENABLE_SECP224R1
#define NOXTLS_ECC_ENABLE_SECP224R1 1
#endif
#ifndef NOXTLS_ECC_ENABLE_SECP256R1
#define NOXTLS_ECC_ENABLE_SECP256R1 1
#endif
#ifndef NOXTLS_ECC_ENABLE_SECP384R1
#define NOXTLS_ECC_ENABLE_SECP384R1 1
#endif
#ifndef NOXTLS_ECC_ENABLE_SECP521R1
#define NOXTLS_ECC_ENABLE_SECP521R1 1
#endif
#ifndef NOXTLS_ECC_ENABLE_BP256R1
#define NOXTLS_ECC_ENABLE_BP256R1 1
#endif
#ifndef NOXTLS_ECC_ENABLE_BP384R1
#define NOXTLS_ECC_ENABLE_BP384R1 1
#endif
#ifndef NOXTLS_ECC_ENABLE_BP512R1
#define NOXTLS_ECC_ENABLE_BP512R1 1
#endif
#ifndef NOXTLS_ECC_ENABLE_SECP192K1
#define NOXTLS_ECC_ENABLE_SECP192K1 1
#endif
#ifndef NOXTLS_ECC_ENABLE_SECP224K1
#define NOXTLS_ECC_ENABLE_SECP224K1 1
#endif
#ifndef NOXTLS_ECC_ENABLE_SECP256K1
#define NOXTLS_ECC_ENABLE_SECP256K1 1
#endif

/* NOXTLS_ECC_STATUS_WORDS
 *
 * When 1, ECC key generation/initialization and ECDSA signing record their last
 * return code and stage in the volatile PTS status words
 * (noxtls_ecc_keygen_last_*, noxtls_ecc_keyinit_last_*, noxtls_ecdsa_sign_last_*;
 * control flow only, never key material). 0 removes the words (36 bytes of
 * RAM); code that reads them must then not be built.
 *
 * Default: 1 (status words kept for existing integrations)
 */
#ifndef NOXTLS_ECC_STATUS_WORDS
#define NOXTLS_ECC_STATUS_WORDS 1
#endif

/* NOXTLS_ECDSA_SIGN_SELF_VERIFY
 *
 * When 1, ECDSA signing immediately verifies the produced signature before
 * returning it. This hardens signing against local fault/glitch attacks but
 * materially reduces signing throughput.
 *
 * Default: 0 (disabled)
 */
#ifndef NOXTLS_ECDSA_SIGN_SELF_VERIFY
#define NOXTLS_ECDSA_SIGN_SELF_VERIFY 0
#endif

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

#endif /* NOXTLS_CONFIG_H_ */
