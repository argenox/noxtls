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
* File:    noxtls_common.h
* Summary: NoxTLS Common Definitions
*
*
*****************************************************************************/

/**
 * @defgroup noxtls Library
 * @brief NoxTLS cryptographic and TLS library components.
 */

/**
 * @defgroup return_codes Return codes (noxtls_return_t)
 * @brief API return codes. Most NoxTLS functions return noxtls_return_t; check for 
 *        NOXTLS_RETURN_SUCCESS or handle specific errors.
 *
 * Always check the return value of functions that return noxtls_return_t. For verification-style
 * functions (e.g. noxtls_ripemd160_verify), NOXTLS_RETURN_SUCCESS means the check passed and
 * NOXTLS_RETURN_FAILED means it did not. The type and constants are defined in this header;
 * see the Common API for related utilities.
 * @{
 */

#ifndef NOXTLS_COMMON_H_
#define NOXTLS_COMMON_H_

#include <noxtls_config.h>
#include "noxtls_check_config.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MSVC warning control helpers */
#ifdef _MSC_VER
#define NOXTLS_MSVC_WARNING_PUSH __pragma(warning(push))
#define NOXTLS_MSVC_WARNING_POP __pragma(warning(pop))
#define NOXTLS_MSVC_DISABLE_PADDING __pragma(warning(disable: 4820))
#else
#define NOXTLS_MSVC_WARNING_PUSH
#define NOXTLS_MSVC_WARNING_POP
#define NOXTLS_MSVC_DISABLE_PADDING
#endif

#if defined(__GNUC__) || defined(__clang__)
#define NOXTLS_UNUSED_ATTR __attribute__((unused))
#else
#define NOXTLS_UNUSED_ATTR
#endif

/* Cross-compiler packed struct helpers */
#if defined(_MSC_VER)
#define NOXTLS_PACK_BEGIN __pragma(pack(push, 1))
#define NOXTLS_PACK_END __pragma(pack(pop))
#define NOXTLS_PACKED
#elif defined(__GNUC__) || defined(__clang__)
#define NOXTLS_PACK_BEGIN
#define NOXTLS_PACK_END
#define NOXTLS_PACKED __attribute__((packed))
#else
#define NOXTLS_PACK_BEGIN
#define NOXTLS_PACK_END
#define NOXTLS_PACKED
#endif

/** @addtogroup return_codes */
/**
 * Return type for NoxTLS API functions.
 *
 * Implemented as an unsigned integer (not a C enum) so return constants have
 * the same essential type as the API return type (MISRA C:2025 Rule 10.3).
 * Numeric values match the historical enum order.
 */
typedef uint32_t noxtls_return_t;

#define NOXTLS_RETURN_SUCCESS                         ((noxtls_return_t)0U)  /**< Operation completed successfully. */
#define NOXTLS_RETURN_FAILED                          ((noxtls_return_t)1U)  /**< General failure. */
#define NOXTLS_RETURN_NULL                            ((noxtls_return_t)2U)  /**< A required pointer argument was NULL. */
#define NOXTLS_RETURN_INVALID_PARAM                   ((noxtls_return_t)3U)  /**< An argument was invalid. */
#define NOXTLS_RETURN_INVALID_BLOCK_SIZE              ((noxtls_return_t)4U)  /**< Block or buffer size invalid. */
#define NOXTLS_RETURN_INVALID_KEY_SIZE                ((noxtls_return_t)5U)  /**< Key size invalid. */
#define NOXTLS_RETURN_INVALID_MODE                    ((noxtls_return_t)6U)  /**< Cipher mode invalid or unsupported. */
#define NOXTLS_RETURN_INVALID_ALGORITHM               ((noxtls_return_t)7U)  /**< Algorithm not supported or invalid. */
#define NOXTLS_RETURN_BAD_DATA                        ((noxtls_return_t)8U)  /**< Input data was malformed or invalid. */
#define NOXTLS_RETURN_TIMEOUT                         ((noxtls_return_t)9U)  /**< Operation timed out. */
#define NOXTLS_RETURN_NOT_SUPPORTED                   ((noxtls_return_t)10U) /**< Feature or option not supported. */
#define NOXTLS_RETURN_NOT_INITIALIZED                 ((noxtls_return_t)11U) /**< Context or module not initialized. */
#define NOXTLS_RETURN_NOT_ENOUGH_MEMORY               ((noxtls_return_t)12U) /**< Memory allocation failed. */
#define NOXTLS_RETURN_NOT_ENOUGH_ENTROPY              ((noxtls_return_t)13U) /**< Insufficient entropy. */
#define NOXTLS_RETURN_CERT_PARSE_FAILED               ((noxtls_return_t)14U) /**< Certificate parsing failed. */
#define NOXTLS_RETURN_CERT_VERIFY_FAILED              ((noxtls_return_t)15U) /**< Certificate verification failed. */
#define NOXTLS_RETURN_TLS_ERROR                       ((noxtls_return_t)16U) /**< TLS/protocol error. */
#define NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED    ((noxtls_return_t)17U) /**< Certificate signature verification failed. */
#define NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH   ((noxtls_return_t)18U) /**< Hostname does not match certificate. */
#define NOXTLS_RETURN_CERT_EXPIRED                    ((noxtls_return_t)19U) /**< Certificate has expired. */
#define NOXTLS_RETURN_CERT_NOT_YET_VALID              ((noxtls_return_t)20U) /**< Certificate not yet valid. */
#define NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED        ((noxtls_return_t)21U) /**< Certificate chain verification failed. */
#define NOXTLS_RETURN_CERT_REVOKED                    ((noxtls_return_t)22U) /**< Certificate appears on CRL. */
#define NOXTLS_RETURN_CRL_PARSE_FAILED                ((noxtls_return_t)23U) /**< CRL parsing failed. */
#define NOXTLS_RETURN_CRL_VERIFY_FAILED               ((noxtls_return_t)24U) /**< CRL signature verification failed. */
#define NOXTLS_RETURN_CRL_EXPIRED                     ((noxtls_return_t)25U) /**< CRL validity window not acceptable. */
#define NOXTLS_RETURN_TLS_WEAK_DHE_PARAMS             ((noxtls_return_t)26U) /**< Weak/unsupported DHE parameters. */
#define NOXTLS_RETURN_RECORD_OVERFLOW                 ((noxtls_return_t)27U) /**< TLS record plaintext exceeds maximum. */
#define NOXTLS_RETURN_CERT_REQUIRED                   ((noxtls_return_t)28U) /**< Client certificate was required but missing. */
#define NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR          ((noxtls_return_t)29U) /**< Malformed handshake (decode_error). */
#define NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER     ((noxtls_return_t)30U) /**< Invalid handshake field (illegal_parameter). */
#define NOXTLS_RETURN_TLS_RECORD_AUTH_FAILED          ((noxtls_return_t)31U) /**< AEAD record open failed (bad_record_mac). */
#define NOXTLS_RETURN_TLS_FINISHED_VERIFY_FAILED      ((noxtls_return_t)32U) /**< Finished verify_data mismatch. */
#define NOXTLS_RETURN_NEGOTIATED_TLS12                ((noxtls_return_t)33U) /**< Downgrade path: continue as TLS 1.2. */
#define NOXTLS_RETURN_WANT_READ                       ((noxtls_return_t)34U) /**< Nonblocking: need more input bytes. */
#define NOXTLS_RETURN_WANT_WRITE                      ((noxtls_return_t)35U) /**< Nonblocking: encrypted output pending. */
#define NOXTLS_RETURN_ECDH_PRIVATE_KEY_INVALID        ((noxtls_return_t)36U) /**< ECDH private-key context invalid. */
#define NOXTLS_RETURN_ECDH_OUTPUT_TOO_SMALL           ((noxtls_return_t)37U) /**< ECDH output buffer too small. */
#define NOXTLS_RETURN_ECDH_PEER_PUBLIC_KEY_INVALID    ((noxtls_return_t)38U) /**< ECDH peer public key invalid. */
#define NOXTLS_RETURN_ECDH_SCALAR_MULTIPLY_FAILED     ((noxtls_return_t)39U) /**< ECDH scalar multiplication failed. */
#define NOXTLS_RETURN_ECDH_SHARED_POINT_INFINITY      ((noxtls_return_t)40U) /**< ECDH result was the point at infinity. */

/** @} */

#ifdef __cplusplus
}
#endif

#endif
