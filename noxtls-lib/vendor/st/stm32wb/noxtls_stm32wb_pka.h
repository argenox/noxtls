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
* File:    noxtls_stm32wb_pka.h
* Summary: STM32WB5x public key accelerator driver (P-256 ECC, ECDSA, modexp)
*
*****************************************************************************/

/**
 * @file noxtls_stm32wb_pka.h
 * @brief PKA register-level driver of the STM32WB5x.
 * @ingroup noxtls_stm32wb
 *
 * Specification: RM0434 Rev 13, PKA chapter (operating modes, PKA RAM
 * operand layout, end-of-operation / RAM error / address error flags, and the
 * "ECC scalar multiplication", "ECDSA signature", "ECDSA verification",
 * "point on elliptic curve check" and "modular exponentiation" operations).
 * Operand encoding follows stm32wbxx_hal_pka: big-endian byte strings are
 * stored as little-endian 32-bit words, each operand is followed by a zero
 * word, and bit lengths are written ahead of the operands.
 *
 * Scope: NIST P-256 (SP 800-186) for ECC / ECDSA; modular exponentiation for
 * any odd modulus of 8..392 bytes. Operations take the PKA semaphore
 * (NOXTLS_STM32WB_CONFIG_HSEM_ID_PKA) and wipe the PKA RAM afterwards because
 * it held private operands.
 *
 * Return convention:
 *  - NOXTLS_RETURN_SUCCESS: result valid.
 *  - NOXTLS_RETURN_NOT_SUPPORTED: nothing was started or the result must not
 *    be used (unsupported parameters, PKA or semaphore busy); software must
 *    compute the operation.
 *  - NOXTLS_RETURN_FAILED: hardware error / timeout / operation error
 *    (outputs are wiped); software may retry or fall back.
 *  - NOXTLS_RETURN_BAD_DATA: definitive negative answer (invalid signature, point not on curve).
 */

#ifndef NOXTLS_STM32WB_PKA_H
#define NOXTLS_STM32WB_PKA_H

#include <stdint.h>

#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Bytes of a P-256 field element, scalar or hash. */
#define NOXTLS_STM32WB_P256_BYTES       32U

/** PKA counters. */
typedef struct {
    uint32_t operations;    /**< Operations completed in hardware. */
    uint32_t declined;      /**< Requests refused before start. */
    uint32_t hw_errors;     /**< Hardware errors / timeouts / operation errors. */
    uint32_t check_failures;/**< Results rejected by the point check. */
} noxtls_stm32wb_pka_stats_t;

/**
 * @brief Whether four curve parameter strings are the NIST P-256 domain.
 *
 * @param[in] p Field prime (32 bytes big-endian).
 * @param[in] a Coefficient a (32 bytes, equal to p - 3).
 * @param[in] b Coefficient b (32 bytes).
 * @param[in] n Group order (32 bytes).
 *
 * @return Non-zero for P-256, 0 otherwise (or when a pointer is NULL).
 */
uint32_t noxtls_stm32wb_pka_is_p256(const uint8_t *p, const uint8_t *a, const uint8_t *b, const uint8_t *n);

/**
 * @brief P-256 scalar multiplication R = k * P.
 *
 * With NOXTLS_STM32WB_CONFIG_PKA_CHECK_RESULT the result is verified with the
 * point-check operation; the point at infinity is reported as NOT_SUPPORTED.
 *
 * @param[in]  k  Scalar (32 bytes, non-zero).
 * @param[in]  px Point X (32 bytes).
 * @param[in]  py Point Y (32 bytes).
 * @param[out] rx Result X (32 bytes).
 * @param[out] ry Result Y (32 bytes).
 *
 * @return See the return convention in the file header.
 */
noxtls_return_t noxtls_stm32wb_pka_p256_mul(const uint8_t *k, const uint8_t *px, const uint8_t *py,
                                            uint8_t *rx, uint8_t *ry);

/**
 * @brief P-256 point-on-curve check (RM0434 "point on elliptic curve check").
 *
 * @param[in] x Point X (32 bytes).
 * @param[in] y Point Y (32 bytes).
 *
 * @return SUCCESS when the point is on the curve, BAD_DATA when it is not,
 *         otherwise as in the file header.
 */
noxtls_return_t noxtls_stm32wb_pka_p256_check(const uint8_t *x, const uint8_t *y);

/**
 * @brief P-256 ECDSA signature generation with a caller-supplied nonce (SP 800-186 / FIPS 186-5 6.4.1).
 *
 * The caller must draw @p k from a DRBG in [1, n-1]. A hardware operation
 * error (r = 0 or s = 0) is reported as FAILED so the caller may retry with
 * a fresh nonce.
 *
 * @param[in]  d Private key (32 bytes).
 * @param[in]  k Nonce (32 bytes).
 * @param[in]  e Message hash reduced to a scalar (32 bytes).
 * @param[out] r Signature r (32 bytes).
 * @param[out] s Signature s (32 bytes).
 *
 * @return See the return convention in the file header.
 */
noxtls_return_t noxtls_stm32wb_pka_p256_sign(const uint8_t *d, const uint8_t *k, const uint8_t *e,
                                             uint8_t *r, uint8_t *s);

/**
 * @brief P-256 ECDSA signature verification (FIPS 186-5 6.4.2).
 *
 * The public key is first checked with the point-check operation; a key off
 * the curve is reported as NOT_SUPPORTED so software decides.
 *
 * @param[in] qx Public key X (32 bytes).
 * @param[in] qy Public key Y (32 bytes).
 * @param[in] e  Message hash reduced to a scalar (32 bytes).
 * @param[in] r  Signature r (32 bytes).
 * @param[in] s  Signature s (32 bytes).
 *
 * @return SUCCESS for a valid signature, BAD_DATA for an invalid one,
 *         otherwise as in the file header.
 */
noxtls_return_t noxtls_stm32wb_pka_p256_verify(const uint8_t *qx, const uint8_t *qy, const uint8_t *e,
                                               const uint8_t *r, const uint8_t *s);

/**
 * @brief Modular exponentiation out = base ^ exp mod mod (all big-endian).
 *
 * Requires an odd modulus (Montgomery based) of 8..392 bytes and base < mod;
 * anything else is NOT_SUPPORTED.
 *
 * @param[out] out     Result (@p mod_len bytes).
 * @param[in]  base    Base (@p mod_len bytes).
 * @param[in]  exp     Exponent.
 * @param[in]  exp_len Exponent bytes (1..392).
 * @param[in]  mod     Modulus (@p mod_len bytes).
 * @param[in]  mod_len Modulus bytes.
 *
 * @return See the return convention in the file header.
 */
noxtls_return_t noxtls_stm32wb_pka_modexp(uint8_t *out, const uint8_t *base, const uint8_t *exp, uint32_t exp_len,
                                          const uint8_t *mod, uint32_t mod_len);

/**
 * @brief PKA counters.
 *
 * @return Pointer to the (static) counters.
 */
const noxtls_stm32wb_pka_stats_t *noxtls_stm32wb_pka_stats(void);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_STM32WB_PKA_H */
