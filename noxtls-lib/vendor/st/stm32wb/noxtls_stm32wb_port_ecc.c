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
* File:    noxtls_stm32wb_port_ecc.c
* Summary: NoxTLS ECC point multiply and ECDSA ports served by the STM32WB5x PKA
*
*****************************************************************************/

/**
 * @file noxtls_stm32wb_port_ecc.c
 * @brief P-256 point multiplication, ECDSA signature and verification ports.
 * @ingroup noxtls_stm32wb
 *
 * ECDH is served through the point-multiplication port: NoxTLS ECDH computes
 * d * Q with noxtls_ecc_point_multiply(), which calls
 * noxtls_ecc_point_multiply_accel_port().
 *
 * Fallback policy (NoxTLS only falls back on NOXTLS_RETURN_NOT_SUPPORTED for
 * point multiplication): a curve other than P-256, a busy PKA or semaphore,
 * a hardware error or a rejected result all return NOT_SUPPORTED. The PKA
 * writes only its own RAM, so the caller's buffers are intact and the
 * portable implementation recomputes. A hardware rejection of an ECDSA
 * signature is final (NOXTLS_RETURN_FAILED).
 *
 * ECDSA signing draws the nonce k from the NoxTLS ECDSA DRBG slot (NIST
 * SP 800-90A) and rejects k >= n; the PKA signs with it (FIPS 186-5 6.4.1).
 */

#include <stddef.h>

#include "common/noxtls_ct.h"
#include "pkc/ecc/noxtls_ecc.h"
#include "pkc/ecc/noxtls_ecc_accel_port.h"
#include "pkc/ecdsa/noxtls_ecdsa_accel_port.h"
#include "pkc/noxtls_pkc_rng.h"
#include "noxtls_stm32wb_config.h"
#include "noxtls_stm32wb_pka.h"

/** @brief Bits requested from the DRBG for a P-256 nonce. */
#define NOXTLS_STM32WB_PORT_P256_BITS   256U

/** Point-multiply telemetry (NoxTLS noxtls_ecc_accel_* interface). */
typedef struct {
    uint32_t operations;    /**< Accelerated multiplications. */
    uint32_t fallbacks;     /**< Requests continued in software. */
    int32_t last_rc;        /**< Result of the last attempt. */
    uint32_t last_stage;    /**< Last stage reached (1 validated, 2 hardware done). */
    uint8_t ready;          /**< Non-zero after a successful multiplication. */
} noxtls_stm32wb_port_ecc_t;

/** @brief Stage: request validated. */
#define NOXTLS_STM32WB_PORT_STAGE_VALID 1U
/** @brief Stage: hardware finished. */
#define NOXTLS_STM32WB_PORT_STAGE_DONE  2U

/** Telemetry. */
static noxtls_stm32wb_port_ecc_t s_noxtls_stm32wb_port_ecc = { 0U, 0U, (int32_t)NOXTLS_RETURN_NOT_SUPPORTED, 0U, 0U };

/** NIST P-256 group order n (the driver holds its own copy; this one bounds the nonce), big-endian. */
static const uint8_t s_noxtls_stm32wb_port_n[NOXTLS_STM32WB_P256_BYTES] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xBCU, 0xE6U, 0xFAU, 0xADU, 0xA7U, 0x17U, 0x9EU, 0x84U, 0xF3U, 0xB9U, 0xCAU, 0xC2U, 0xFCU, 0x63U, 0x25U, 0x51U
};

/**
 * @brief Whether curve parameters are NIST P-256.
 * @internal
 *
 * @param[in] curve Curve.
 *
 * @return Non-zero for P-256.
 */
static uint32_t noxtls_stm32wb_port_is_p256(const ecc_curve_params_t *curve)
{
    uint32_t is = 0U;

    if ((curve != NULL) && (curve->size == NOXTLS_STM32WB_P256_BYTES)) {
        is = noxtls_stm32wb_pka_is_p256(curve->p, curve->a, curve->b, curve->n);
    }
    return is;
}

int noxtls_ecc_accel_is_ready(void)
{
    return (s_noxtls_stm32wb_port_ecc.ready != 0U) ? 1 : 0;
}

uint32_t noxtls_ecc_accel_operation_count(void)
{
    return s_noxtls_stm32wb_port_ecc.operations;
}

uint32_t noxtls_ecc_accel_fallback_count(void)
{
    return s_noxtls_stm32wb_port_ecc.fallbacks;
}

void noxtls_ecc_accel_note_fallback(void)
{
    s_noxtls_stm32wb_port_ecc.fallbacks++;
}

int32_t noxtls_ecc_accel_last_rc(void)
{
    return s_noxtls_stm32wb_port_ecc.last_rc;
}

uint32_t noxtls_ecc_accel_last_status(void)
{
    return noxtls_stm32wb_pka_stats()->hw_errors;
}

uint32_t noxtls_ecc_accel_last_stage(void)
{
    return s_noxtls_stm32wb_port_ecc.last_stage;
}

int noxtls_ecc_accel_input_echo_ok(void)
{
    /* Operands are written with aligned word stores only; no echo check is needed. */
    return 1;
}

noxtls_return_t noxtls_ecc_point_multiply_accel_port(ecc_point_t *result,
                                                      const uint8_t *scalar,
                                                      const ecc_point_t *point,
                                                      const ecc_curve_params_t *curve)
{
    noxtls_stm32wb_port_ecc_t *st = &s_noxtls_stm32wb_port_ecc;
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;

    if ((result != NULL) && (scalar != NULL) && (point != NULL) && (noxtls_stm32wb_port_is_p256(curve) != 0U) &&
        (point->size == NOXTLS_STM32WB_P256_BYTES)) {
        st->last_stage = NOXTLS_STM32WB_PORT_STAGE_VALID;
        if (noxtls_stm32wb_pka_p256_mul(scalar, point->x, point->y, result->x, result->y) == NOXTLS_RETURN_SUCCESS) {
            result->size = NOXTLS_STM32WB_P256_BYTES;
            st->operations++;
            st->ready = 1U;
            st->last_stage = NOXTLS_STM32WB_PORT_STAGE_DONE;
            rc = NOXTLS_RETURN_SUCCESS;
        }
        st->last_rc = (int32_t)rc;
    }
    return rc;
}

/**
 * @brief Whether a big-endian 32-byte value is non-zero and below the group order.
 * @internal
 *
 * @param[in] k Value.
 *
 * @return Non-zero when 1 <= k < n.
 */
static uint32_t noxtls_stm32wb_port_nonce_ok(const uint8_t *k)
{
    uint32_t i = 0U;
    uint32_t nonzero = 0U;
    uint32_t below = 0U;

    while ((i < NOXTLS_STM32WB_P256_BYTES) && (k[i] == s_noxtls_stm32wb_port_n[i])) {
        i++;
    }
    if ((i < NOXTLS_STM32WB_P256_BYTES) && (k[i] < s_noxtls_stm32wb_port_n[i])) {
        below = 1U;
    }
    for (i = 0U; i < NOXTLS_STM32WB_P256_BYTES; i++) {
        if (k[i] != 0U) {
            nonzero = 1U;
        }
    }
    return (below != 0U) ? nonzero : 0U;
}

noxtls_return_t noxtls_ecdsa_sign_accel_port(const ecc_key_t *key,
                                             const uint8_t *hash,
                                             uint32_t hash_len,
                                             ecdsa_signature_t *signature)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    uint8_t k[NOXTLS_STM32WB_P256_BYTES];
    uint32_t attempt;
    uint32_t active = 1U;
    noxtls_return_t hw;

    if ((key != NULL) && (key->d != NULL) && (hash != NULL) && (signature != NULL) &&
        (hash_len == NOXTLS_STM32WB_P256_BYTES) && (noxtls_stm32wb_port_is_p256(key->curve) != 0U)) {
        for (attempt = 0U; (attempt < NOXTLS_STM32WB_CONFIG_ECDSA_SIGN_ATTEMPTS) && (active != 0U); attempt++) {
            if (noxtls_pkc_rng_generate(NOXTLS_PKC_RNG_SLOT_ECDSA, k, NOXTLS_STM32WB_PORT_P256_BITS) !=
                NOXTLS_RETURN_SUCCESS) {
                active = 0U;
            } else if (noxtls_stm32wb_port_nonce_ok(k) != 0U) {
                hw = noxtls_stm32wb_pka_p256_sign(key->d, k, hash, signature->r, signature->s);
                if (hw == NOXTLS_RETURN_SUCCESS) {
                    signature->size = NOXTLS_STM32WB_P256_BYTES;
                    rc = NOXTLS_RETURN_SUCCESS;
                    active = 0U;
                } else if (hw != NOXTLS_RETURN_FAILED) {
                    /* PKA or semaphore busy: software signs. */
                    active = 0U;
                } else {
                    /* Operation error: retry with a fresh nonce. */
                }
            } else {
                /* Nonce outside [1, n-1]: draw another. */
            }
        }
    }
    noxtls_secure_zero(k, sizeof(k));
    return rc;
}

noxtls_return_t noxtls_ecdsa_verify_accel_port(const ecc_key_t *key,
                                               const uint8_t *hash,
                                               uint32_t hash_len,
                                               const ecdsa_signature_t *signature)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    noxtls_return_t hw;

    if ((key != NULL) && (hash != NULL) && (signature != NULL) && (hash_len == NOXTLS_STM32WB_P256_BYTES) &&
        (noxtls_stm32wb_port_is_p256(key->curve) != 0U)) {
        hw = noxtls_stm32wb_pka_p256_verify(key->Q.x, key->Q.y, hash, signature->r, signature->s);
        if (hw == NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_SUCCESS;
        } else if (hw == NOXTLS_RETURN_BAD_DATA) {
            /* The hardware rejected the signature: final. */
            rc = NOXTLS_RETURN_FAILED;
        } else {
            /* Busy, off-curve key or hardware error: software decides. */
        }
    }
    return rc;
}
