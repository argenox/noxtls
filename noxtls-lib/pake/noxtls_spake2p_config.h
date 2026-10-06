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
* File:    noxtls_spake2p_config.h
* Summary: SPAKE2+ sizes and protocol constants
*
*
*****************************************************************************/

/**
 * @file noxtls_spake2p_config.h
 * @brief Fixed sizes and labels for SPAKE2+ (P-256, SHA-256, HKDF-SHA256, HMAC-SHA256).
 * @ingroup noxtls_spake2p
 *
 * Values come from RFC 9383 (SPAKE2+, May 2023) sections 3.2-3.4 and 4 for
 * the ciphersuite P256-SHA256-HKDF-SHA256-HMAC-SHA256, and from
 * draft-bar-cfrg-spake2plus-01 section 3 for the Matter profile (Matter Core
 * specification 1.x section 3.10). These are protocol constants, not tuning
 * parameters; they are collected here so no magic values appear in the code.
 */

#ifndef _NOXTLS_SPAKE2P_CONFIG_H_
#define _NOXTLS_SPAKE2P_CONFIG_H_

/** @brief P-256 field element / scalar size in bytes (SEC 2 v2.0 section 2.4.2). */
#define NOXTLS_SPAKE2P_SCALAR_SIZE (32U)

/** @brief Uncompressed SEC 1 point size (0x04 || X || Y) used for shares, M, N, Z, V and L. */
#define NOXTLS_SPAKE2P_POINT_SIZE (65U)

/** @brief SEC 1 uncompressed point prefix octet. */
#define NOXTLS_SPAKE2P_POINT_PREFIX_UNCOMPRESSED (0x04U)

/** @brief SHA-256 output size; RFC 9383 Hash() and the transcript digest. */
#define NOXTLS_SPAKE2P_HASH_SIZE (32U)

/** @brief HMAC-SHA256 output size; confirmation MAC length for both profiles. */
#define NOXTLS_SPAKE2P_CONFIRMATION_SIZE (32U)

/**
 * @brief Size of each of w0s and w1s for P-256: ceil(log2(p)/8) + k/8 with k = 64 (RFC 9383 section 3.2).
 * Matter uses the same value (CRYPTO_W_SIZE_BYTES = CRYPTO_GROUP_SIZE_BYTES + 8).
 */
#define NOXTLS_SPAKE2P_WS_HALF_SIZE (40U)

/** @brief Total registration KDF output w0s || w1s. */
#define NOXTLS_SPAKE2P_WS_SIZE (NOXTLS_SPAKE2P_WS_HALF_SIZE * 2U)

/** @brief Width of each transcript length prefix: 8-byte little-endian (RFC 9383 section 3.3). */
#define NOXTLS_SPAKE2P_TT_LENGTH_PREFIX_SIZE (8U)

/** @brief RFC 9383 section 3.4: size of each of K_confirmP and K_confirmV (HMAC-SHA256 key, Nh). */
#define NOXTLS_SPAKE2P_RFC9383_CONFIRM_KEY_SIZE (32U)

/** @brief RFC 9383 section 3.4: size of K_shared. */
#define NOXTLS_SPAKE2P_RFC9383_SHARED_KEY_SIZE (32U)

/** @brief draft-bar-cfrg-spake2plus-01 section 3.4: Ka and Ke are the two halves of Hash(TT). */
#define NOXTLS_SPAKE2P_MATTER_KA_SIZE (NOXTLS_SPAKE2P_HASH_SIZE / 2U)

/** @brief draft-01 / Matter: size of Ke, the shared secret handed to the session layer. */
#define NOXTLS_SPAKE2P_MATTER_SHARED_KEY_SIZE (NOXTLS_SPAKE2P_HASH_SIZE / 2U)

/** @brief draft-01 / Matter: size of each of KcA and KcB (half of the 32-byte KDF output). */
#define NOXTLS_SPAKE2P_MATTER_CONFIRM_KEY_SIZE (16U)

/** @brief Largest confirmation key size across profiles (sizes context storage). */
#define NOXTLS_SPAKE2P_MAX_CONFIRM_KEY_SIZE (NOXTLS_SPAKE2P_RFC9383_CONFIRM_KEY_SIZE)

/** @brief Largest shared key size across profiles (sizes context storage). */
#define NOXTLS_SPAKE2P_MAX_SHARED_KEY_SIZE (NOXTLS_SPAKE2P_RFC9383_SHARED_KEY_SIZE)

/** @brief KDF info label for confirmation keys (RFC 9383 section 3.4; draft-01 section 3.4). */
#define NOXTLS_SPAKE2P_LABEL_CONFIRMATION_KEYS "ConfirmationKeys"

/** @brief KDF info label for the RFC 9383 shared key (RFC 9383 section 3.4). */
#define NOXTLS_SPAKE2P_LABEL_SHARED_KEY "SharedKey"

#endif /* _NOXTLS_SPAKE2P_CONFIG_H_ */
