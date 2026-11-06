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
* File:    noxtls_efr32_se_ops.h
* Summary: Secure Engine operations of the EFR32xG2x backend: TRNG, SHA-2, ECC
*
*****************************************************************************/

/**
 * @file noxtls_efr32_se_ops.h
 * @brief TRNG, SHA-256 / SHA-512 block compression, ECDH point multiplication and
 *        ECDSA on the EFR32xG2x Secure Engine (HSE).
 * @ingroup noxtls_efr32
 *
 * Every operation takes the mailbox with a bounded retry
 * (noxtls_efr32_se_acquire()). Inputs and outputs are staged through module
 * buffers because the SE accesses host memory by DMA. A busy, disabled or hung
 * mailbox, or a command the SE does not implement, returns
 * NOXTLS_RETURN_NOT_SUPPORTED so the caller continues in software. SHA-384 /
 * SHA-512 and P-384 need the Vault-High feature set (EFR32MG26B5xx).
 */
#ifndef NOXTLS_EFR32_SE_OPS_H
#define NOXTLS_EFR32_SE_OPS_H

#include <stdint.h>

#include "noxtls_efr32_semailbox.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Hash selector: SHA-256 compression (SHA-224 shares it), 64-byte blocks, 32-byte state. */
#define NOXTLS_EFR32_SE_HASH_SHA256     0U
/** @brief Hash selector: SHA-512 compression (SHA-384 shares it), 128-byte blocks, 64-byte state. */
#define NOXTLS_EFR32_SE_HASH_SHA512     1U
/** @brief SHA-256 state bytes. */
#define NOXTLS_EFR32_SE_STATE_256       32U
/** @brief SHA-512 state bytes. */
#define NOXTLS_EFR32_SE_STATE_512       64U
/** @brief SHA-256 block bytes. */
#define NOXTLS_EFR32_SE_BLOCK_256       64U
/** @brief SHA-512 block bytes. */
#define NOXTLS_EFR32_SE_BLOCK_512       128U
/** @brief Coordinate bytes of NIST P-256. */
#define NOXTLS_EFR32_SE_P256_BYTES      32U
/** @brief Coordinate bytes of NIST P-384. */
#define NOXTLS_EFR32_SE_P384_BYTES      48U
/** @brief Largest supported coordinate. */
#define NOXTLS_EFR32_SE_COORD_MAX       NOXTLS_EFR32_SE_P384_BYTES

/**
 * @brief Fill a buffer from the SE true random number generator.
 *
 * @param[out] buf Destination.
 * @param[in]  len Bytes (0 returns success).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_NOT_SUPPORTED
 *         (mailbox unavailable), NOXTLS_RETURN_FAILED or NOXTLS_RETURN_TIMEOUT.
 *         On failure the buffer is zeroed.
 */
noxtls_return_t noxtls_efr32_se_trng_fill(uint8_t *buf, uint32_t len);

/**
 * @brief Compress whole message blocks into a SHA-2 chaining value (FIPS 180-4 §6.2.2 / §6.4.2).
 *
 * @param[in]     alg         NOXTLS_EFR32_SE_HASH_SHA256 or NOXTLS_EFR32_SE_HASH_SHA512.
 * @param[in,out] state       Chaining value in FIPS 180-4 byte order (big-endian words), 32 or 64 bytes.
 * @param[in]     data        Message blocks (flash or SRAM).
 * @param[in]     block_count Blocks (0 returns success).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM,
 *         NOXTLS_RETURN_NOT_SUPPORTED (nothing changed: mailbox unavailable, data
 *         unreachable, algorithm not implemented), NOXTLS_RETURN_FAILED or
 *         NOXTLS_RETURN_TIMEOUT. The state is unchanged unless the result is success.
 */
noxtls_return_t noxtls_efr32_se_hash_blocks(uint32_t alg, uint8_t *state, const uint8_t *data, uint32_t block_count);

/**
 * @brief Elliptic-curve point multiplication R = k * P on NIST P-256 / P-384 (SEC 1 §3.3.1 ECDH primitive).
 *
 * @param[in]  size   Coordinate bytes (32 or 48).
 * @param[in]  scalar k, big-endian.
 * @param[in]  px     x of P, big-endian.
 * @param[in]  py     y of P, big-endian.
 * @param[out] rx     x of R.
 * @param[out] ry     y of R.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM,
 *         NOXTLS_RETURN_NOT_SUPPORTED, NOXTLS_RETURN_FAILED or NOXTLS_RETURN_TIMEOUT.
 *         The outputs are zeroed on failure.
 */
noxtls_return_t noxtls_efr32_se_ecc_mul(uint32_t size, const uint8_t *scalar, const uint8_t *px, const uint8_t *py,
                                        uint8_t *rx, uint8_t *ry);

/**
 * @brief ECDSA signature of a digest on P-256 / P-384 (FIPS 186-5 §6.4.1; the SE draws the nonce).
 *
 * @param[in]  size Coordinate bytes (32 or 48); the digest has the same length.
 * @param[in]  d    Private key, big-endian.
 * @param[in]  hash Digest (already reduced to the order length).
 * @param[out] r    r, big-endian.
 * @param[out] s    s, big-endian.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM,
 *         NOXTLS_RETURN_NOT_SUPPORTED, NOXTLS_RETURN_FAILED or NOXTLS_RETURN_TIMEOUT.
 */
noxtls_return_t noxtls_efr32_se_ecdsa_sign(uint32_t size, const uint8_t *d, const uint8_t *hash, uint8_t *r, uint8_t *s);

/**
 * @brief ECDSA verification of a digest on P-256 / P-384 (FIPS 186-5 §6.4.2).
 *
 * @param[in] size Coordinate bytes (32 or 48); the digest has the same length.
 * @param[in] qx   Public key x, big-endian.
 * @param[in] qy   Public key y, big-endian.
 * @param[in] hash Digest.
 * @param[in] r    r, big-endian.
 * @param[in] s    s, big-endian.
 *
 * @return NOXTLS_RETURN_SUCCESS (valid), NOXTLS_RETURN_BAD_DATA (the signature is invalid),
 *         NOXTLS_RETURN_NULL, NOXTLS_RETURN_NOT_SUPPORTED (use software), NOXTLS_RETURN_FAILED
 *         or NOXTLS_RETURN_TIMEOUT.
 */
noxtls_return_t noxtls_efr32_se_ecdsa_verify(uint32_t size, const uint8_t *qx, const uint8_t *qy, const uint8_t *hash,
                                             const uint8_t *r, const uint8_t *s);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_EFR32_SE_OPS_H */
