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
* File:    noxtls_ecc_accel_cc13xx_port.c
* Summary: Validated CC13xx secp256r1 callback accelerator port
*
*
*****************************************************************************/

/** @file noxtls_ecc_accel_cc13xx_port.c
 * @brief Fixed-domain validation and checked accelerator result adoption.
 * @ingroup noxtls_cc13xx_ecc
 * SEC 2 v2.0 section 2.4.2 fixes the domain; SEC 1 v2.0 section 3.2.2
 * requires finite, bounded, on-curve public points. Cofactor is one for P-256.
 */
#include "noxtls_ecc_accel_cc13xx_port.h"
#include "common/noxtls_cc13xx_crypto.h"
#include "common/noxtls_ct.h"
#include <string.h>
#include <limits.h>
#if NOXTLS_CC13XX_P256_ACCEL_ENABLED
#include "noxtls_ecc_accel_cc13xx_config.h"
#endif

static uint32_t s_operations;
static uint32_t s_fallbacks;
static noxtls_return_t s_last_rc = (noxtls_return_t)NOXTLS_RETURN_NOT_SUPPORTED;

/** @brief Report only actual bound callback availability.
 *
 * @return One for an enabled P-256 callback, zero otherwise. */
int noxtls_ecc_accel_is_ready(void)
{
#if NOXTLS_CC13XX_P256_ACCEL_ENABLED
    return noxtls_cc13xx_crypto_has_p256() ? 1 : 0;
#else
    return 0;
#endif
}

/** @brief Query saturating successful validated operation count.
 *
 * @return Number of accepted finite accelerator outputs. */
uint32_t noxtls_ecc_accel_operation_count(void)
{
    return s_operations;
}

/** @brief Query saturating software fallback count.
 *
 * @return Actual caller-noted software fallbacks. */
uint32_t noxtls_ecc_accel_fallback_count(void)
{
    return s_fallbacks;
}

/** @brief Record one existing dispatcher fallback without wraparound.
 *
 * @return None. */
void noxtls_ecc_accel_note_fallback(void)
{
    if (s_fallbacks != UINT32_MAX) {
        ++s_fallbacks;
    }
}

/** @brief Query last scalar result code without any key or point bytes.
 *
 * @return Last actual port result. */
int32_t noxtls_ecc_accel_last_rc(void)
{
    return (int32_t)s_last_rc;
}

/** @brief No device status register is exposed by this callback interface.
 *
 * @return Zero, explicitly unavailable. */
uint32_t noxtls_ecc_accel_last_status(void)
{
    return 0U;
}

/** @brief No device execution stage is exposed by this callback interface.
 *
 * @return Zero, explicitly unavailable. */
uint32_t noxtls_ecc_accel_last_stage(void)
{
    return 0U;
}

/** @brief No hardware operand echo proof is exposed by this interface.
 *
 * @return Zero, explicitly unavailable. */
int noxtls_ecc_accel_input_echo_ok(void)
{
    return 0;
}

/** @brief Clear failed output and publish only a bounded return code.
 * @internal
 *
 * @param[out] result Owned output, possibly NULL.
 * @param[in] rc Actual error to propagate.
 *
 * @return Unmodified failure result. */
static noxtls_return_t reject(ecc_point_t *result, noxtls_return_t rc)
{
    if (result != NULL) {
        noxtls_secure_zero(result, sizeof(*result));
    }

    s_last_rc = rc;
    return rc;
}

#if NOXTLS_CC13XX_P256_ACCEL_ENABLED
/** @brief Compare fixed-width big-endian values in a constant iteration count.
 * @internal
 *
 * @param[in] left First complete 32-byte value.
 * @param[in] right Second complete 32-byte value.
 *
 * @return True only when left is strictly less than right. */
static bool less(const uint8_t *left, const uint8_t *right)
{
    uint32_t index = NOXTLS_CC13XX_ECC_BYTES;
    uint32_t borrow = 0U;
    while (index != 0U) {
        --index;
        borrow = ((uint32_t)left[index] - (uint32_t)right[index] - borrow) >>
            NOXTLS_CC13XX_ECC_BORROW_SHIFT;
    }

    return borrow != 0U;
}

/** @brief Test zero without data-dependent iteration count.
 * @internal
 *
 * @param[in] bytes Complete 32-byte scalar or coordinate.
 *
 * @return True only for zero. */
static bool zero(const uint8_t *bytes)
{
    uint32_t index;
    uint32_t combined = 0U;
    for (index = 0U; index < NOXTLS_CC13XX_ECC_BYTES; ++index) {
        combined |= bytes[index];
    }

    return combined == 0U;
}

/** @brief Require every public domain parameter, including generator/order.
 * @internal
 *
 * @param[in] curve Required non-NULL domain storage.
 *
 * @return True only for the exact SEC 2 v2.0 section 2.4.2 domain. */
static bool exact_domain(const ecc_curve_params_t *curve)
{
    return curve->size == NOXTLS_CC13XX_ECC_BYTES &&
        curve->G.size == NOXTLS_CC13XX_ECC_BYTES &&
        noxtls_ct_equal(curve->p, s_cc13xx_p256_prime, NOXTLS_CC13XX_ECC_BYTES) &&
        noxtls_ct_equal(curve->a, s_cc13xx_p256_a, NOXTLS_CC13XX_ECC_BYTES) &&
        noxtls_ct_equal(curve->b, s_cc13xx_p256_b, NOXTLS_CC13XX_ECC_BYTES) &&
        noxtls_ct_equal(curve->n, s_cc13xx_p256_order, NOXTLS_CC13XX_ECC_BYTES) &&
        noxtls_ct_equal(curve->G.x, s_cc13xx_p256_gx, NOXTLS_CC13XX_ECC_BYTES) &&
        noxtls_ct_equal(curve->G.y, s_cc13xx_p256_gy, NOXTLS_CC13XX_ECC_BYTES);
}

/** @brief Validate finite canonical field encodings and actual curve equation.
 * @internal
 *
 * @param[in] point Exact fixed-width public coordinates.
 * @param[in] curve Previously validated domain.
 *
 * @return True for a finite point in the cofactor-one P-256 group. */
static bool valid_point(const ecc_point_t *point, const ecc_curve_params_t *curve)
{
    return point->size == NOXTLS_CC13XX_ECC_BYTES &&
        !(zero(point->x) && zero(point->y)) &&
        less(point->x, curve->p) && less(point->y, curve->p) &&
        noxtls_ecc_point_validate_public(point, curve) == NOXTLS_RETURN_SUCCESS;
}
#endif

/** @brief Adopt only checked finite output from an exact-domain callback.
 *
 * @param[out] result Caller-owned output, erased on failure.
 * @param[in] scalar Exact 32-byte big-endian scalar in [1,n-1].
 * @param[in] point Finite canonical secp256r1 input point.
 * @param[in] curve Complete SEC 2 v2.0 section 2.4.2 domain.
 *
 * @return Actual callback status, or explicit input/output validation error.
 */
noxtls_return_t noxtls_ecc_point_multiply_accel_port(ecc_point_t *result,
    const uint8_t *scalar, const ecc_point_t *point, const ecc_curve_params_t *curve)
{
#if NOXTLS_CC13XX_P256_ACCEL_ENABLED
    ecc_point_t candidate = {{0U}, {0U}, NOXTLS_CC13XX_ECC_BYTES};
    noxtls_return_t rc;
    if (result == NULL || scalar == NULL || point == NULL || curve == NULL) {
        return reject(result, (noxtls_return_t)NOXTLS_RETURN_NULL);
    }

    if (curve->p == NULL || curve->a == NULL || curve->b == NULL || curve->n == NULL) {
        return reject(result, (noxtls_return_t)NOXTLS_RETURN_INVALID_PARAM);
    }

    if (!exact_domain(curve)) {
        return reject(result, (noxtls_return_t)NOXTLS_RETURN_NOT_SUPPORTED);
    }

    if (zero(scalar) || !less(scalar, curve->n)) {
        return reject(result, (noxtls_return_t)NOXTLS_RETURN_INVALID_PARAM);
    }

    if (!valid_point(point, curve)) {
        return reject(result, (noxtls_return_t)NOXTLS_RETURN_BAD_DATA);
    }

    rc = noxtls_cc13xx_p256_multiply(scalar, point->x, point->y,
        candidate.x, candidate.y);
    if (rc == NOXTLS_RETURN_SUCCESS && !valid_point(&candidate, curve)) {
        rc = (noxtls_return_t)NOXTLS_RETURN_BAD_DATA;
    }

    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(&candidate, sizeof(candidate));
        return reject(result, rc);
    }

    *result = candidate;
    noxtls_secure_zero(&candidate, sizeof(candidate));
    if (s_operations != UINT32_MAX) {
        ++s_operations;
    }

    s_last_rc = (noxtls_return_t)NOXTLS_RETURN_SUCCESS;
    return (noxtls_return_t)NOXTLS_RETURN_SUCCESS;
#else
    (void)scalar;
    (void)point;
    (void)curve;
    return reject(result, (noxtls_return_t)NOXTLS_RETURN_NOT_SUPPORTED);
#endif
}
