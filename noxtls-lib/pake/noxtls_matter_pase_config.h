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
* File:    noxtls_matter_pase_config.h
* Summary: Matter PASE cryptographic constants
*
*
*****************************************************************************/

/**
 * @file noxtls_matter_pase_config.h
 * @brief Matter PASE constants (Matter Core specification 1.x sections 3.9, 3.10, 4.14.1 and 5.1.7).
 * @ingroup noxtls_matter_pase
 */

#ifndef _NOXTLS_MATTER_PASE_CONFIG_H_
#define _NOXTLS_MATTER_PASE_CONFIG_H_

#include "noxtls_spake2p_config.h"

/** @brief CRYPTO_PBKDF_ITERATIONS_MIN (Matter Core section 3.9). */
#define NOXTLS_MATTER_PASE_PBKDF_ITERATIONS_MIN (1000U)

/** @brief CRYPTO_PBKDF_ITERATIONS_MAX (Matter Core section 3.9). */
#define NOXTLS_MATTER_PASE_PBKDF_ITERATIONS_MAX (100000U)

/** @brief Minimum PBKDF salt length in bytes (Matter Core section 4.14.1). */
#define NOXTLS_MATTER_PASE_SALT_MIN_SIZE (16U)

/** @brief Maximum PBKDF salt length in bytes (Matter Core section 4.14.1). */
#define NOXTLS_MATTER_PASE_SALT_MAX_SIZE (32U)

/** @brief Size of the little-endian passcode encoding fed to PBKDF2 (Matter Core section 3.10). */
#define NOXTLS_MATTER_PASE_PASSCODE_ENCODED_SIZE (4U)

/** @brief Largest valid setup passcode (Matter Core section 5.1.7.1: 00000001 to 99999998). */
#define NOXTLS_MATTER_PASE_PASSCODE_MAX (99999998UL)

/** @brief Serialized verifier w0 || L size (Matter Core section 3.10, Crypto_PAKEValues_Responder). */
#define NOXTLS_MATTER_PASE_VERIFIER_SIZE (NOXTLS_SPAKE2P_SCALAR_SIZE + NOXTLS_SPAKE2P_POINT_SIZE)

/** @brief PASE context hash size: SHA-256 (Matter Core section 4.14.1.2). */
#define NOXTLS_MATTER_PASE_CONTEXT_SIZE (NOXTLS_SPAKE2P_HASH_SIZE)

/** @brief PASE context prefix (Matter Core section 4.14.1.2). */
#define NOXTLS_MATTER_PASE_CONTEXT_PREFIX "CHIP PAKE V1 Commissioning"

/** @brief Session key derivation info label SEKeys_Info (Matter Core section 4.14.1.3). */
#define NOXTLS_MATTER_PASE_SESSION_KEYS_INFO "SessionKeys"

/** @brief CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES: size of I2RKey, R2IKey and AttestationChallenge. */
#define NOXTLS_MATTER_PASE_SESSION_KEY_SIZE (16U)

/** @brief AttestationChallenge size (equal to CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES). */
#define NOXTLS_MATTER_PASE_ATTESTATION_CHALLENGE_SIZE (16U)

/** @brief Number of 16-byte outputs from the SessionKeys KDF: I2RKey, R2IKey, AttestationChallenge. */
#define NOXTLS_MATTER_PASE_SESSION_KEY_COUNT (3U)

#endif /* _NOXTLS_MATTER_PASE_CONFIG_H_ */
