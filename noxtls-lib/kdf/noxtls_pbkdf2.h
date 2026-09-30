/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*****************************************************************************/

/**
 * @file noxtls_pbkdf2.h
 * @brief PBKDF2 password-based key derivation (RFC 8018 §5.2) over HMAC.
 * @ingroup noxtls_kdf
 *
 * Used by PKCS#8 EncryptedPrivateKeyInfo decryption (PBES2) and by
 * IEEE 802.11 WPA2-Personal PSK-to-PMK mapping (802.11-2020 §J.4).
 */

#ifndef NOXTLS_PBKDF2_H
#define NOXTLS_PBKDF2_H

#include <stdint.h>

#include "noxtls_common.h"
#include "mdigest/noxtls_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Derive key material with PBKDF2 (RFC 8018 §5.2).
 *
 * @param [in] hash_algo PRF hash for HMAC (SHA-1, SHA-256, SHA-384, SHA-512).
 * @param [in] password Password octets.
 * @param [in] password_len Password length (0 allowed).
 * @param [in] salt Salt octets.
 * @param [in] salt_len Salt length.
 * @param [in] iterations Iteration count c (must be >= 1).
 * @param [out] out Derived key output.
 * @param [in] out_len Derived key length dkLen (must be >= 1).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL for NULL arguments,
 *         NOXTLS_RETURN_INVALID_PARAM for a zero count/length, or
 *         NOXTLS_RETURN_INVALID_ALGORITHM for an unsupported hash.
 */
noxtls_return_t noxtls_pbkdf2_hmac(noxtls_hash_algos_t hash_algo,
                                   const uint8_t *password, uint32_t password_len,
                                   const uint8_t *salt, uint32_t salt_len,
                                   uint32_t iterations,
                                   uint8_t *out, uint32_t out_len);

/**
 * @brief Run PBKDF2-HMAC-SHA1 known-answer tests (RFC 6070 §2, c = 1, 2).
 *
 * @return NOXTLS_RETURN_SUCCESS when all vectors match, else
 *         NOXTLS_RETURN_FAILED.
 */
noxtls_return_t noxtls_pbkdf2_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_PBKDF2_H */
