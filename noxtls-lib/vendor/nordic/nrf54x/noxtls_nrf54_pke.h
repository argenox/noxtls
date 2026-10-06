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
* File:    noxtls_nrf54_pke.h
* Summary: CRACEN BA414EP: ECDSA P-256 verify, Ed25519 verify, P-256 point multiply
*
*****************************************************************************/

/**
 * @file noxtls_nrf54_pke.h
 * @brief Public-key operations on the CRACEN BA414EP engine.
 * @ingroup noxtls_nrf54
 *
 * - ECDSA verification on NIST P-256 (FIPS 186-5 §6.4.2; curve SP 800-186 §3.2.1.3),
 *   operands big-endian;
 * - Ed25519 verification (RFC 8032 §5.1.7), operands little-endian: the caller
 *   supplies k = SHA-512(R || A || M); the engine decodes A and R from their
 *   y-coordinates and x-parity and checks [S]B = R + [k]A;
 * - P-256 point multiplication with scalar blinding and randomised projective
 *   coordinates (key generation and ECDH).
 * The engine uses its built-in P-256 and Edwards25519 parameters. On the
 * nRF54L15 the microcode is loaded into the PKE code RAM before the first
 * command (and again if the engine reports a microcode error); the nRF54LM20
 * runs it from ROM. Operand memory is wiped after every command: by the
 * clear-memory command on CRACEN Lite, by word writes on the nRF54L15.
 */

#ifndef NOXTLS_NRF54_PKE_H
#define NOXTLS_NRF54_PKE_H

#include <stdint.h>

#include "noxtls_nrf54_cracen.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Bytes of a P-256 / Ed25519 field element or scalar. */
#define NOXTLS_NRF54_PKE_OPERAND_BYTES  32U
/** Bytes of the Ed25519 verification digest k (SHA-512 output). */
#define NOXTLS_NRF54_PKE_ED25519_K_BYTES 64U

/** PKE counters (diagnostics). */
typedef struct {
    uint32_t commands;      /**< Commands completed (any status). */
    uint32_t rejects;       /**< Verifications rejected by the engine. */
    uint32_t errors;        /**< Commands that failed for another reason (fallback to software). */
    uint32_t ucode_loads;   /**< Microcode loads (nRF54L15). */
    uint32_t last_status;   /**< STATUS of the last command. */
} noxtls_nrf54_pke_stats_t;

/**
 * @brief ECDSA P-256 signature verification.
 *
 * @param[in] qx Public key x (32 bytes, big-endian).
 * @param[in] qy Public key y.
 * @param[in] h  Hash, truncated / reduced to 32 bytes (FIPS 186-5 §6.4.2 step 3).
 * @param[in] r  Signature r.
 * @param[in] s  Signature s.
 *
 * @return NOXTLS_RETURN_SUCCESS (valid), NOXTLS_RETURN_FAILED (rejected),
 *         NOXTLS_RETURN_NULL or NOXTLS_RETURN_NOT_SUPPORTED (engine unavailable
 *         or error: verify in software).
 */
noxtls_return_t noxtls_nrf54_pke_ecdsa_p256_verify(const uint8_t *qx, const uint8_t *qy, const uint8_t *h,
                                                   const uint8_t *r, const uint8_t *s);

/**
 * @brief Ed25519 signature verification from the digest k.
 *
 * @param[in] pub Public key A (32 bytes, RFC 8032 encoding).
 * @param[in] sig Signature R || S (64 bytes).
 * @param[in] k   SHA-512(dom || R || A || M) (64 bytes, little-endian integer).
 *
 * @return As noxtls_nrf54_pke_ecdsa_p256_verify().
 */
noxtls_return_t noxtls_nrf54_pke_ed25519_verify(const uint8_t *pub, const uint8_t *sig, const uint8_t *k);

/**
 * @brief P-256 point multiplication R = k * P with blinding.
 *
 * @param[in]  k     Scalar (32 bytes, big-endian, 1 <= k < n).
 * @param[in]  px    Point x.
 * @param[in]  py    Point y.
 * @param[in]  blind 8 random bytes (blinding factor; adjusted to the engine rules).
 * @param[out] rx    Result x.
 * @param[out] ry    Result y.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL or NOXTLS_RETURN_NOT_SUPPORTED
 *         (engine unavailable or error: multiply in software; outputs wiped).
 */
noxtls_return_t noxtls_nrf54_pke_p256_mul(const uint8_t *k, const uint8_t *px, const uint8_t *py,
                                          const uint8_t *blind, uint8_t *rx, uint8_t *ry);

/**
 * @brief PKE counters.
 *
 * @return Counters (never NULL).
 */
const noxtls_nrf54_pke_stats_t *noxtls_nrf54_pke_stats(void);

/**
 * @brief Forget that the microcode is loaded (next command reloads it; tests and power loss).
 */
void noxtls_nrf54_pke_invalidate_ucode(void);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_NRF54_PKE_H */
