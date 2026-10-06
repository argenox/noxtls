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
* File:    noxtls_nrf54_port_ecc.c
* Summary: NoxTLS ECC / ECDSA accelerator ports on the nRF54L CRACEN BA414EP
*
*****************************************************************************/

/**
 * @file noxtls_nrf54_port_ecc.c
 * @brief ECC point multiplication and ECDSA verification ports served by the CRACEN BA414EP.
 * @ingroup noxtls_nrf54
 *
 * P-256 point multiplication (key generation, ECDH): the engine runs with
 * scalar blinding and randomised projective coordinates; with
 * NOXTLS_NRF54_CONFIG_PTMUL_DOUBLE_CHECK the multiplication is repeated under
 * an independent blinding factor and accepted only when both results agree
 * (a successful status does not authenticate the arithmetic; a transient
 * fault could otherwise publish a valid-looking wrong point). Disagreement
 * returns NOT_SUPPORTED and the portable NoxTLS path recomputes.
 *
 * ECDSA P-256 verification: a hardware rejection is final (FAILED); any
 * other hardware error falls back to software. Ed25519 verification is in
 * noxtls_nrf54_port_ed25519.c.
 */

#include <stddef.h>
#include <string.h>

#include "noxtls_ecc.h"
#include "noxtls_ecdsa_accel_port.h"
#include "drbg/noxtls_drbg.h"
#include "noxtls_nrf54_pke.h"

/** @brief Bytes of a P-256 coordinate. */
#define NOXTLS_NRF54_PORT_P256_BYTES    32U

/** NIST P-256 prime p (SP 800-186 §3.2.1.3), big-endian. */
static const uint8_t s_noxtls_nrf54_p256_p[NOXTLS_NRF54_PORT_P256_BYTES] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU
};

/** Point-multiply port telemetry (NoxTLS noxtls_ecc_accel_* interface). */
typedef struct {
    uint32_t operations;   /**< Accelerated multiplications. */
    uint32_t fallbacks;    /**< Requests continued in software. */
    uint32_t mismatches;   /**< Double-check disagreements. */
    int32_t last_rc;       /**< Result of the last attempt. */
    uint32_t last_stage;   /**< Last stage reached (1 entropy, 2 first run, 3 second run, 4 done). */
    uint8_t ready;         /**< Non-zero after a successful multiplication. */
} noxtls_nrf54_port_ecc_t;

/** Telemetry. */
static noxtls_nrf54_port_ecc_t s_noxtls_nrf54_port_ecc = { 0U, 0U, 0U, (int32_t)NOXTLS_RETURN_NOT_SUPPORTED, 0U, 0U };

/** @brief Stage: blinding entropy. */
#define NOXTLS_NRF54_PORT_STAGE_ENTROPY 1U
/** @brief Stage: first multiplication. */
#define NOXTLS_NRF54_PORT_STAGE_FIRST   2U
/** @brief Stage: check multiplication. */
#define NOXTLS_NRF54_PORT_STAGE_CHECK   3U
/** @brief Stage: accepted. */
#define NOXTLS_NRF54_PORT_STAGE_DONE    4U

/**
 * @brief Whether curve parameters are NIST P-256.
 * @internal
 *
 * @param[in] curve Curve.
 *
 * @return 1 for P-256.
 */
static uint8_t noxtls_nrf54_port_is_p256(const ecc_curve_params_t *curve)
{
    return ((curve != NULL) && (curve->size == NOXTLS_NRF54_PORT_P256_BYTES) && (curve->p != NULL) &&
            (memcmp(curve->p, s_noxtls_nrf54_p256_p, sizeof(s_noxtls_nrf54_p256_p)) == 0)) ? 1U : 0U;
}

int noxtls_ecc_accel_is_ready(void)
{
    return (s_noxtls_nrf54_port_ecc.ready != 0U) ? 1 : 0;
}

uint32_t noxtls_ecc_accel_operation_count(void)
{
    return s_noxtls_nrf54_port_ecc.operations;
}

uint32_t noxtls_ecc_accel_fallback_count(void)
{
    return s_noxtls_nrf54_port_ecc.fallbacks;
}

void noxtls_ecc_accel_note_fallback(void)
{
    s_noxtls_nrf54_port_ecc.fallbacks++;
}

int32_t noxtls_ecc_accel_last_rc(void)
{
    return s_noxtls_nrf54_port_ecc.last_rc;
}

uint32_t noxtls_ecc_accel_last_status(void)
{
    return noxtls_nrf54_pke_stats()->last_status;
}

uint32_t noxtls_ecc_accel_last_stage(void)
{
    return s_noxtls_nrf54_port_ecc.last_stage;
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
    noxtls_nrf54_port_ecc_t *st = &s_noxtls_nrf54_port_ecc;
    uint8_t blind[2U * NOXTLS_NRF54_PK_BLIND_BYTES];
    uint8_t check_x[NOXTLS_NRF54_PORT_P256_BYTES];
    uint8_t check_y[NOXTLS_NRF54_PORT_P256_BYTES];
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;

    if ((result == NULL) || (scalar == NULL) || (point == NULL) || (noxtls_nrf54_port_is_p256(curve) == 0U) ||
        (point->size != NOXTLS_NRF54_PORT_P256_BYTES) || (noxtls_nrf54_cracen_is_enabled() == 0U)) {
        /* Not for this engine. */
    } else {
        st->last_stage = NOXTLS_NRF54_PORT_STAGE_ENTROPY;
        if (noxtls_drbg_get_entropy(blind, (uint32_t)sizeof(blind)) == NOXTLS_RETURN_SUCCESS) {
            st->last_stage = NOXTLS_NRF54_PORT_STAGE_FIRST;
            rc = noxtls_nrf54_pke_p256_mul(scalar, point->x, point->y, blind, result->x, result->y);
        }
#if (NOXTLS_NRF54_CONFIG_PTMUL_DOUBLE_CHECK != 0)
        if (rc == NOXTLS_RETURN_SUCCESS) {
            st->last_stage = NOXTLS_NRF54_PORT_STAGE_CHECK;
            rc = noxtls_nrf54_pke_p256_mul(scalar, point->x, point->y, &blind[NOXTLS_NRF54_PK_BLIND_BYTES], check_x,
                                           check_y);
            if ((rc == NOXTLS_RETURN_SUCCESS) &&
                ((memcmp(check_x, result->x, sizeof(check_x)) != 0) ||
                 (memcmp(check_y, result->y, sizeof(check_y)) != 0))) {
                st->mismatches++;
                rc = NOXTLS_RETURN_NOT_SUPPORTED;
            }
        }
#endif
        if (rc == NOXTLS_RETURN_SUCCESS) {
            result->size = NOXTLS_NRF54_PORT_P256_BYTES;
            st->operations++;
            st->ready = 1U;
            st->last_stage = NOXTLS_NRF54_PORT_STAGE_DONE;
        } else {
            noxtls_nrf54_wipe(result->x, NOXTLS_NRF54_PORT_P256_BYTES);
            noxtls_nrf54_wipe(result->y, NOXTLS_NRF54_PORT_P256_BYTES);
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
        }
        st->last_rc = (int32_t)rc;
    }
    noxtls_nrf54_wipe(blind, (uint32_t)sizeof(blind));
    noxtls_nrf54_wipe(check_x, (uint32_t)sizeof(check_x));
    noxtls_nrf54_wipe(check_y, (uint32_t)sizeof(check_y));
    return rc;
}

noxtls_return_t noxtls_ecdsa_sign_accel_port(const ecc_key_t *key,
                                             const uint8_t *hash,
                                             uint32_t hash_len,
                                             ecdsa_signature_t *signature)
{
    /* Signing stays in software (NoxTLS deterministic nonce handling). */
    (void)key;
    (void)hash;
    (void)hash_len;
    (void)signature;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_ecdsa_verify_accel_port(const ecc_key_t *key,
                                               const uint8_t *hash,
                                               uint32_t hash_len,
                                               const ecdsa_signature_t *signature)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;

    if ((key != NULL) && (hash != NULL) && (signature != NULL) && (hash_len == NOXTLS_NRF54_PORT_P256_BYTES) &&
        (noxtls_nrf54_port_is_p256(key->curve) != 0U)) {
        rc = noxtls_nrf54_pke_ecdsa_p256_verify(key->Q.x, key->Q.y, hash, signature->r, signature->s);
        if ((rc != NOXTLS_RETURN_SUCCESS) && (rc != NOXTLS_RETURN_FAILED)) {
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
        }
    }
    return rc;
}
