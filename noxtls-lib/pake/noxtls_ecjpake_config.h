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
* File:    noxtls_ecjpake_config.h
* Summary: EC-JPAKE sizes, protocol constants and tunable limits
*
*
*****************************************************************************/

/**
 * @file noxtls_ecjpake_config.h
 * @brief Fixed sizes, identities and tunable limits for EC-JPAKE over P-256 / SHA-256.
 * @ingroup noxtls_ecjpake
 *
 * Protocol constants come from:
 * - RFC 8236 "J-PAKE: Password-Authenticated Key Exchange by Juggling"
 *   (September 2017) section 3 (J-PAKE over Elliptic Curve).
 * - RFC 8235 "Schnorr Non-interactive Zero-Knowledge Proof" (September 2017)
 *   section 3 (Schnorr NIZK proof over Elliptic Curve).
 * - draft-cragie-tls-ecjpake-01 "Elliptic Curve J-PAKE Cipher Suites for
 *   Transport Layer Security (TLS)" (June 2016) sections 3, 7 and 8.
 *
 * Values marked "tunable" may be overridden by the application before this
 * header is included; everything else is fixed by the specifications.
 */

#ifndef _NOXTLS_ECJPAKE_CONFIG_H_
#define _NOXTLS_ECJPAKE_CONFIG_H_

/** @brief P-256 scalar / field element size in bytes (SEC 2 v2.0 section 2.4.2). */
#define NOXTLS_ECJPAKE_SCALAR_SIZE (32U)

/** @brief Uncompressed SEC 1 point size: 0x04 || X || Y (SEC 1 v2.0 section 2.3.3). */
#define NOXTLS_ECJPAKE_POINT_SIZE (65U)

/** @brief SEC 1 uncompressed point prefix octet (SEC 1 v2.0 section 2.3.3). */
#define NOXTLS_ECJPAKE_POINT_PREFIX_UNCOMPRESSED (0x04U)

/** @brief SHA-256 output size used for the ZKP challenge and the premaster secret. */
#define NOXTLS_ECJPAKE_HASH_SIZE (32U)

/**
 * @brief Size of the 4-octet length prefix put before every Schnorr ZKP hash input
 * (draft-cragie-tls-ecjpake-01 section 8.2; RFC 8235 section 2.3 recommendation).
 */
#define NOXTLS_ECJPAKE_HASH_LENGTH_PREFIX_SIZE (4U)

/** @brief Size of the TLS opaque<1..2^8-1> length octet before ECPoint and r (RFC 4492 section 5.4). */
#define NOXTLS_ECJPAKE_TLS_LENGTH_OCTET_SIZE (1U)

/** @brief Smallest encoded ZKP r: one octet (draft-cragie-tls-ecjpake-01 section 7.1.2, r<1..2^8-1>). */
#define NOXTLS_ECJPAKE_ZKP_R_MIN_SIZE (1U)

/** @brief Largest accepted ZKP r: a P-256 scalar (r is reduced modulo n, RFC 8235 section 3.2). */
#define NOXTLS_ECJPAKE_ZKP_R_MAX_SIZE (NOXTLS_ECJPAKE_SCALAR_SIZE)

/**
 * @brief Largest encoded ECJPAKEKeyKP: ECPoint X || ECPoint V || r
 * (draft-cragie-tls-ecjpake-01 sections 7.1.1 and 7.1.2).
 */
#define NOXTLS_ECJPAKE_KEY_KP_MAX_SIZE ((2U * (NOXTLS_ECJPAKE_TLS_LENGTH_OCTET_SIZE + NOXTLS_ECJPAKE_POINT_SIZE)) + \
                                        NOXTLS_ECJPAKE_TLS_LENGTH_OCTET_SIZE + NOXTLS_ECJPAKE_ZKP_R_MAX_SIZE)

/** @brief Smallest encoded ECJPAKEKeyKP (r of one octet). */
#define NOXTLS_ECJPAKE_KEY_KP_MIN_SIZE ((2U * (NOXTLS_ECJPAKE_TLS_LENGTH_OCTET_SIZE + NOXTLS_ECJPAKE_POINT_SIZE)) + \
                                        NOXTLS_ECJPAKE_TLS_LENGTH_OCTET_SIZE + NOXTLS_ECJPAKE_ZKP_R_MIN_SIZE)

/** @brief Number of ECJPAKEKeyKP entries in a round-one ECJPAKEKeyKPPairList (section 7.2.2). */
#define NOXTLS_ECJPAKE_ROUND_ONE_KEY_COUNT (2U)

/**
 * @brief Largest round-one message (ecjpake_key_kp_pair extension body). The
 * optional identity field is elided, as Thread does (draft section 7.2.2 and section 3).
 */
#define NOXTLS_ECJPAKE_ROUND_ONE_MAX_SIZE (NOXTLS_ECJPAKE_ROUND_ONE_KEY_COUNT * NOXTLS_ECJPAKE_KEY_KP_MAX_SIZE)

/** @brief Smallest round-one message. */
#define NOXTLS_ECJPAKE_ROUND_ONE_MIN_SIZE (NOXTLS_ECJPAKE_ROUND_ONE_KEY_COUNT * NOXTLS_ECJPAKE_KEY_KP_MIN_SIZE)

/** @brief ECParameters for a named curve: curve_type(1) || NamedCurve(2) (RFC 4492 section 5.4). */
#define NOXTLS_ECJPAKE_EC_PARAMETERS_SIZE (3U)

/** @brief ECCurveType named_curve (RFC 4492 section 5.4). */
#define NOXTLS_ECJPAKE_EC_CURVE_TYPE_NAMED_CURVE (3U)

/** @brief NamedCurve secp256r1 (RFC 4492 section 5.1.1; RFC 8422 section 5.1.1). */
#define NOXTLS_ECJPAKE_NAMED_CURVE_SECP256R1 (23U)

/** @brief Largest round-two message: ServerECJPAKEParams (draft section 7.3). */
#define NOXTLS_ECJPAKE_ROUND_TWO_MAX_SIZE (NOXTLS_ECJPAKE_EC_PARAMETERS_SIZE + NOXTLS_ECJPAKE_KEY_KP_MAX_SIZE)

/** @brief Premaster secret size: SHA-256 of the X coordinate of K (draft section 8.7). */
#define NOXTLS_ECJPAKE_PREMASTER_SIZE (NOXTLS_ECJPAKE_HASH_SIZE)

/** @brief Client identity used in the ZKP hash: "client" (draft-cragie-tls-ecjpake-01 section 8.1). */
#define NOXTLS_ECJPAKE_ID_CLIENT "client"

/** @brief Server identity used in the ZKP hash: "server" (draft-cragie-tls-ecjpake-01 section 8.1). */
#define NOXTLS_ECJPAKE_ID_SERVER "server"

/** @brief Length of either identity string without a terminator (draft section 8.1). */
#define NOXTLS_ECJPAKE_ID_LEN (6U)

/**
 * @brief Random bytes drawn per secret scalar before reduction modulo n: 256 + 64
 * bits, so the modulo bias is below 2^-64 (FIPS 186-5 Appendix A.2.1 method).
 */
#define NOXTLS_ECJPAKE_RANDOM_SEED_SIZE (NOXTLS_ECJPAKE_SCALAR_SIZE + 8U)

/** @brief Smallest accepted password length in octets (s must be non-zero, draft section 8.3). */
#define NOXTLS_ECJPAKE_PASSWORD_MIN_LEN (1U)

#ifndef NOXTLS_ECJPAKE_PASSWORD_MAX_LEN
/**
 * @brief Largest accepted password length in octets (tunable). Thread PSKd is at most
 * 32 characters and PSKc is 16 octets; 64 leaves room for other uses.
 */
#define NOXTLS_ECJPAKE_PASSWORD_MAX_LEN (64U)
#endif

#ifndef NOXTLS_ECJPAKE_MAX_RANDOM_RETRIES
/**
 * @brief Attempts to draw a usable random scalar or nonce before giving up (tunable).
 * A retry is needed only with probability about 2^-256 per draw.
 */
#define NOXTLS_ECJPAKE_MAX_RANDOM_RETRIES (8U)
#endif

#endif /* _NOXTLS_ECJPAKE_CONFIG_H_ */
