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
* File:    noxtls_esp32s31_port_ecc.c
* Summary: NoxTLS ECC / ECDSA accelerator ports on the ESP32-S31 ECC and ECDSA engines
*
*****************************************************************************/

/**
 * @file noxtls_esp32s31_port_ecc.c
 * @brief P-192 / P-256 / P-384 point multiplication, ECDSA verify and ECDSA sign.
 *
 * Point multiplication and verification run on the ECC / ECDSA engines through
 * nox-driver-lib (esp32s31_pka.h). Signing uses the ECDSA engine with the caller's
 * private key and a hardware-derived deterministic nonce (RFC 6979 style), or the
 * on-chip TRNG nonce when NOXTLS_ESP32S31_ECDSA_RANDOMIZED is non-zero (that needs
 * the entropy source of the RNG driver to be running). Other curves return
 * NOXTLS_RETURN_NOT_SUPPORTED so software computes them.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "noxtls_ecc.h"
#include "noxtls_ecdsa.h"
#include "esp32s31_pka.h"

#ifndef NOXTLS_ESP32S31_ECDSA_RANDOMIZED
/** @brief Non-zero selects TRNG nonces for signing instead of the engine's deterministic nonce. */
#define NOXTLS_ESP32S31_ECDSA_RANDOMIZED 0
#endif

/** @brief Largest coordinate size handled. */
#define NOXTLS_ESP32S31_ECC_MAX 48U

/** @brief Telemetry (control flow only, no secret material). */
typedef struct
{
    uint32_t operations;
    uint32_t fallbacks;
    int32_t last_rc;
    uint8_t ready;
} noxtls_esp32s31_ecc_stats_t;

static noxtls_esp32s31_ecc_stats_t s_noxtls_esp32s31_ecc;
static uint8_t s_noxtls_esp32s31_pka_ready;

int noxtls_ecc_accel_is_ready(void)
{
    return (s_noxtls_esp32s31_ecc.ready != 0U) ? 1 : 0;
}

uint32_t noxtls_ecc_accel_operation_count(void)
{
    return s_noxtls_esp32s31_ecc.operations;
}

uint32_t noxtls_ecc_accel_fallback_count(void)
{
    return s_noxtls_esp32s31_ecc.fallbacks;
}

void noxtls_ecc_accel_note_fallback(void)
{
    s_noxtls_esp32s31_ecc.fallbacks++;
}

int32_t noxtls_ecc_accel_last_rc(void)
{
    return s_noxtls_esp32s31_ecc.last_rc;
}

uint32_t noxtls_ecc_accel_last_status(void)
{
    return 0U;
}

uint32_t noxtls_ecc_accel_last_stage(void)
{
    return 0U;
}

int noxtls_ecc_accel_input_echo_ok(void)
{
    return 1;
}

/**
 * @brief Enable the engines on first use.
 * @internal
 *
 * @return Non-zero when the engines are usable.
 */
static uint8_t noxtls_esp32s31_pka_prepare(void)
{
    if (s_noxtls_esp32s31_pka_ready == 0U) {
        if (esp32s31_pka_init() == NOXDRV_SUCCESS) {
            s_noxtls_esp32s31_pka_ready = 1U;
        }
    }
    return s_noxtls_esp32s31_pka_ready;
}

/**
 * @brief Engine curve of NoxTLS curve parameters.
 * @internal
 *
 * @param[in]  curve Library curve parameters (curve_tag is the library curve id + 1).
 * @param[out] out   Engine curve.
 *
 * @return 1 when the engine supports the curve.
 */
static uint8_t noxtls_esp32s31_curve(const ecc_curve_params_t *curve, esp32s31_ecc_curve_t *out)
{
    uint8_t ok = 0U;

    if ((curve != NULL) && (curve->curve_tag != 0U)) {
        ecc_curve_t id = (ecc_curve_t)(curve->curve_tag - 1U);

        if (id == NOXTLS_ECC_SECP192R1) {
            *out = ESP32S31_ECC_P192;
            ok = 1U;
        } else if (id == NOXTLS_ECC_SECP256R1) {
            *out = ESP32S31_ECC_P256;
            ok = 1U;
        } else if (id == NOXTLS_ECC_SECP384R1) {
            *out = ESP32S31_ECC_P384;
            ok = 1U;
        } else {
            /* Not served. */
        }
        if ((ok != 0U) && (curve->size != esp32s31_ecc_curve_bytes(*out))) {
            ok = 0U;
        }
    }
    return ok;
}

/**
 * @brief Digest as an ECDSA z value of the curve size (left-pad or leftmost-bits truncate).
 * @internal
 *
 * @param[in]  hash     Digest.
 * @param[in]  hash_len Digest bytes.
 * @param[in]  size     Curve bytes.
 * @param[out] z        size bytes.
 */
static void noxtls_esp32s31_fit_digest(const uint8_t *hash, uint32_t hash_len, uint32_t size, uint8_t *z)
{
    (void)memset(z, 0, size);
    if (hash_len >= size) {
        (void)memcpy(z, hash, size);
    } else {
        (void)memcpy(&z[size - hash_len], hash, hash_len);
    }
}

noxtls_return_t noxtls_ecc_point_multiply_accel_port(ecc_point_t *result, const uint8_t *scalar,
                                                      const ecc_point_t *point, const ecc_curve_params_t *curve)
{
    noxtls_esp32s31_ecc_stats_t *st = &s_noxtls_esp32s31_ecc;
    esp32s31_ecc_curve_t ec = ESP32S31_ECC_P256;
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;

    if ((result != NULL) && (scalar != NULL) && (point != NULL) && (noxtls_esp32s31_curve(curve, &ec) != 0U) &&
        (point->size == esp32s31_ecc_curve_bytes(ec)) && (noxtls_esp32s31_pka_prepare() != 0U)) {
        if (esp32s31_ecc_point_mul(ec, scalar, point->x, point->y, result->x, result->y, true) == NOXDRV_SUCCESS) {
            result->size = point->size;
            st->operations++;
            st->ready = 1U;
            rc = NOXTLS_RETURN_SUCCESS;
        } else {
            (void)memset(result->x, 0, esp32s31_ecc_curve_bytes(ec));
            (void)memset(result->y, 0, esp32s31_ecc_curve_bytes(ec));
        }
        st->last_rc = (int32_t)rc;
    }
    return rc;
}

noxtls_return_t noxtls_ecdsa_sign_accel_port(const ecc_key_t *key, const uint8_t *hash, uint32_t hash_len,
                                             ecdsa_signature_t *signature)
{
    esp32s31_ecc_curve_t ec = ESP32S31_ECC_P256;
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    uint8_t z[NOXTLS_ESP32S31_ECC_MAX];

    if ((key != NULL) && (key->d != NULL) && (hash != NULL) && (hash_len != 0U) && (signature != NULL) &&
        (noxtls_esp32s31_curve(key->curve, &ec) != 0U) && (noxtls_esp32s31_pka_prepare() != 0U)) {
        uint32_t size = esp32s31_ecc_curve_bytes(ec);

        noxtls_esp32s31_fit_digest(hash, hash_len, size, z);
        if (esp32s31_ecdsa_sign(ec, key->d, z, signature->r, signature->s,
                                (NOXTLS_ESP32S31_ECDSA_RANDOMIZED == 0) ? true : false) == NOXDRV_SUCCESS) {
            signature->size = size;
            rc = NOXTLS_RETURN_SUCCESS;
        }
        (void)memset(z, 0, sizeof(z));
    }
    return rc;
}

noxtls_return_t noxtls_ecdsa_verify_accel_port(const ecc_key_t *key, const uint8_t *hash, uint32_t hash_len,
                                               const ecdsa_signature_t *signature)
{
    esp32s31_ecc_curve_t ec = ESP32S31_ECC_P256;
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    uint8_t z[NOXTLS_ESP32S31_ECC_MAX];

    if ((key != NULL) && (hash != NULL) && (hash_len != 0U) && (signature != NULL) &&
        (noxtls_esp32s31_curve(key->curve, &ec) != 0U) && (noxtls_esp32s31_pka_prepare() != 0U)) {
        noxdrv_ret_t r;

        noxtls_esp32s31_fit_digest(hash, hash_len, esp32s31_ecc_curve_bytes(ec), z);
        r = esp32s31_ecdsa_verify(ec, z, signature->r, signature->s, key->Q.x, key->Q.y);
        if (r == NOXDRV_SUCCESS) {
            rc = NOXTLS_RETURN_SUCCESS;
        } else if (r == NOXDRV_ERROR_FAILURE) {
            rc = NOXTLS_RETURN_FAILED;
        } else {
            /* Engine problem: let software verify. */
        }
    }
    return rc;
}
