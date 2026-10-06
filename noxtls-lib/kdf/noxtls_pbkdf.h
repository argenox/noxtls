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
* File:    noxtls_pbkdf.h
* Summary: PBKDF2 password-based key derivation (RFC 8018 section 5.2)
*
*
*****************************************************************************/

/**
 * @file noxtls_pbkdf.h
 * @brief PBKDF2 with an HMAC pseudorandom function (RFC 8018 section 5.2).
 * @ingroup noxtls_kdf
 *
 * Specification: RFC 8018 (PKCS #5 v2.1), section 5.2 "PBKDF2".
 * The PRF is HMAC (RFC 2104) over SHA-1, SHA-256, SHA-384 or SHA-512 as
 * provided by noxtls_hmac. PBKDF2-HMAC-SHA256 is the variant used by
 * Matter PASE (Matter Core specification section 3.9, Crypto_PBKDF).
 */

/**
 * @defgroup noxtls_kdf Key Derivation Functions
 * @brief HKDF (RFC 5869) and PBKDF2 (RFC 8018) key derivation.
 */

#ifndef _NOXTLS_PBKDF_H_
#define _NOXTLS_PBKDF_H_

#include <stdint.h>

#include "noxtls_common.h"
#include "mdigest/noxtls_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Minimum iteration count c accepted by RFC 8018 section 5.2 (c is a positive integer). */
#define NOXTLS_PBKDF2_MIN_ITERATIONS (1U)

/** @brief Size in bytes of the big-endian block index INT(i) appended to the salt (RFC 8018 section 5.2 step 3). */
#define NOXTLS_PBKDF2_BLOCK_INDEX_SIZE (4U)

/** @brief Largest supported HMAC output (SHA-512) used to size internal U/T blocks. */
#define NOXTLS_PBKDF2_MAX_PRF_SIZE (64U)

/**
 * @brief Derive key material with PBKDF2 (RFC 8018 section 5.2).
 *
 * DK = T_1 || T_2 || ... || T_l, where T_i = U_1 ^ U_2 ^ ... ^ U_c,
 * U_1 = PRF(P, S || INT(i)) and U_j = PRF(P, U_{j-1}).
 *
 * The HMAC module keeps a single SHA-256 inner context, so this function
 * must not be called while another HMAC-SHA256 context is active.
 * All intermediate PRF blocks are erased before returning.
 *
 * @param[in] hash_algo HMAC hash: NOXTLS_HASH_SHA1, NOXTLS_HASH_SHA_256, NOXTLS_HASH_SHA_384 or NOXTLS_HASH_SHA_512.
 * @param[in] password Password P (may be NULL only when password_len is 0).
 * @param[in] password_len Length of P in bytes.
 * @param[in] salt Salt S (may be NULL only when salt_len is 0).
 * @param[in] salt_len Length of S in bytes.
 * @param[in] iterations Iteration count c (must be at least NOXTLS_PBKDF2_MIN_ITERATIONS).
 * @param[out] dk Derived key output buffer of dk_len bytes; erased on failure.
 * @param[in] dk_len Requested derived key length in bytes (must be non-zero).
 *
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL for a NULL
 *         required pointer, NOXTLS_RETURN_INVALID_ALGORITHM for an
 *         unsupported hash, NOXTLS_RETURN_NOT_SUPPORTED for a hash compiled
 *         out of this build, NOXTLS_RETURN_INVALID_PARAM for a zero
 *         iteration count or zero output length, or NOXTLS_RETURN_FAILED if
 *         the HMAC primitive fails.
 */
noxtls_return_t noxtls_pbkdf2_hmac(noxtls_hash_algos_t hash_algo,
                                   const uint8_t *password, uint32_t password_len,
                                   const uint8_t *salt, uint32_t salt_len,
                                   uint32_t iterations,
                                   uint8_t *dk, uint32_t dk_len);

/**
 * @brief Run PBKDF2-HMAC-SHA1 known-answer tests (RFC 6070 section 2, c = 1, 2).
 *
 * Builds without SHA-1 run the same two cases with PBKDF2-HMAC-SHA256.
 *
 * @return NOXTLS_RETURN_SUCCESS when all vectors match,
 *         NOXTLS_RETURN_NOT_SUPPORTED when neither SHA-1 nor SHA-256 is
 *         compiled in, else NOXTLS_RETURN_FAILED.
 */
noxtls_return_t noxtls_pbkdf2_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_PBKDF_H_ */
