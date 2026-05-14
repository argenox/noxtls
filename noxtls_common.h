/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
* 
*
* File:    noxtls_common.h
* Summary: NOXTLS Common Definitions
*
*/

/**
 * @defgroup noxtls Library
 * @brief NoxTLS cryptographic and TLS library components.
 */

/**
 * @defgroup return_codes Return codes (noxtls_return_t)
 * @brief API return codes. Most NoxTLS functions return noxtls_return_t; check for NOXTLS_RETURN_SUCCESS or handle specific errors.
 *
 * Always check the return value of functions that return noxtls_return_t. For verification-style
 * functions (e.g. noxtls_ripemd160_verify), NOXTLS_RETURN_SUCCESS means the check passed and
 * NOXTLS_RETURN_FAILED means it did not. The type and constants are defined in this header;
 * see the Common API for related utilities.
 * @{
 */

#ifndef _NOXTLS_COMMON_H_
#define _NOXTLS_COMMON_H_

#include "noxtls_config.h"
#include "noxtls_check_config.h"

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
/** Return type for NoxTLS API functions. */
typedef enum
{
	NOXTLS_RETURN_SUCCESS,           /**< Operation completed successfully (value 0). */
	NOXTLS_RETURN_FAILED,            /**< General failure (e.g. verification failed, crypto operation failed). */
	NOXTLS_RETURN_NULL,              /**< A required pointer argument was NULL. */
	NOXTLS_RETURN_INVALID_PARAM,     /**< An argument was invalid (e.g. out of range, inconsistent). */
	NOXTLS_RETURN_INVALID_BLOCK_SIZE,/**< Block or buffer size invalid for the operation. */
	NOXTLS_RETURN_INVALID_KEY_SIZE,  /**< Key size invalid for the algorithm or mode. */
	NOXTLS_RETURN_INVALID_MODE,      /**< Cipher mode invalid or not supported for this operation. */
	NOXTLS_RETURN_INVALID_ALGORITHM, /**< Requested algorithm not supported or invalid in this context. */
	NOXTLS_RETURN_BAD_DATA,          /**< Input data was malformed or invalid. */
	NOXTLS_RETURN_TIMEOUT,           /**< Operation timed out. */
	NOXTLS_RETURN_NOT_SUPPORTED,     /**< Requested feature or option is not supported. */
	NOXTLS_RETURN_NOT_INITIALIZED,   /**< Context or module was not initialized. */
	NOXTLS_RETURN_NOT_ENOUGH_MEMORY, /**< Memory allocation failed. */
	NOXTLS_RETURN_NOT_ENOUGH_ENTROPY,/**< Insufficient entropy for random or key-generation. */
	NOXTLS_RETURN_CERT_PARSE_FAILED,         /**< Certificate parsing failed (malformed DER or invalid structure). */
	NOXTLS_RETURN_CERT_VERIFY_FAILED,        /**< Certificate verification failed (generic). */
	NOXTLS_RETURN_TLS_ERROR,                 /**< TLS/protocol error (handshake, record, or unexpected message). */
	NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED,/**< Certificate signature verification failed (invalid or issuer key missing). */
	NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH,/**< Hostname does not match certificate SAN or subject CN. */
	NOXTLS_RETURN_CERT_EXPIRED,              /**< Certificate has expired (current time > notAfter). */
	NOXTLS_RETURN_CERT_NOT_YET_VALID,        /**< Certificate not yet valid (current time < notBefore). */
	NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED,  /**< Certificate chain verification failed (signature or validity of a link). */
	NOXTLS_RETURN_CERT_REVOKED,              /**< Certificate serial appears on the provided CRL (revoked). */
	NOXTLS_RETURN_CRL_PARSE_FAILED,         /**< CRL DER/PEM parsing failed (malformed structure). */
	NOXTLS_RETURN_CRL_VERIFY_FAILED,        /**< CRL signature verification failed against issuer. */
	NOXTLS_RETURN_CRL_EXPIRED,              /**< CRL nextUpdate (or validity window) is not acceptable (e.g. stale CRL). */
	NOXTLS_RETURN_TLS_WEAK_DHE_PARAMS       /**< TLS DHE ServerKeyExchange parameters are weak/unsupported (e.g. very small finite-field DH). */
} noxtls_return_t;

/** @} */

#ifdef __cplusplus
}
#endif

#endif
