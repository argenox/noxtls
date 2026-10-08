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
* File:    noxtls_ecjpake_group.c
* Summary: EC-JPAKE P-256 point validation, multiplication and addition
*
*
*****************************************************************************/

/**
 * @file noxtls_ecjpake_group.c
 * @brief P-256 point helpers for EC-JPAKE on top of the NoxTLS ECC module.
 * @ingroup noxtls_ecjpake
 *
 * Points travel as 65-octet uncompressed SEC 1 encodings (SEC 1 v2.0
 * section 2.3.3). The identity, which has no SEC 1 uncompressed encoding,
 * is represented internally by all-zero coordinates, as in the NoxTLS ECC
 * module. Received points are validated per SEC 1 v2.0 section 3.2.2.1 and
 * RFC 8235 section 3.2 (valid point, not the identity; cofactor 1). Every
 * scalar multiplication calls noxtls_ecc_point_multiply(), which dispatches
 * to a bound platform accelerator port.
 */

#include <stdint.h>

#include "noxtls_ecjpake_internal.h"
#include "pkc/ecc/noxtls_ecc.h"
#include "common/noxtls_ct.h"

/** @brief Offset of the X coordinate in an uncompressed encoding. */
#define NOXTLS_ECJPAKE_X_OFFSET (1U)
/** @brief Offset of the Y coordinate in an uncompressed encoding. */
#define NOXTLS_ECJPAKE_Y_OFFSET (1U + NOXTLS_ECJPAKE_SCALAR_SIZE)
/** @brief Most significant bit index of a 32-bit word. */
#define NOXTLS_ECJPAKE_WORD_MSB (31U)

/**
 * @brief Decode an uncompressed encoding into an ecc_point_t (no validation).
 * @internal
 *
 * @param[in] encoded 65-octet encoding.
 * @param[out] point Destination point.
 */
static void noxtls_ecjpake_decode(const uint8_t encoded[NOXTLS_ECJPAKE_POINT_SIZE], ecc_point_t *point)
{
    (void)noxtls_ecc_point_init(point, NOXTLS_ECJPAKE_SCALAR_SIZE);
    noxtls_copy_u8(point->x, NOXTLS_ECJPAKE_SCALAR_SIZE, &encoded[NOXTLS_ECJPAKE_X_OFFSET], NOXTLS_ECJPAKE_SCALAR_SIZE);
    noxtls_copy_u8(point->y, NOXTLS_ECJPAKE_SCALAR_SIZE, &encoded[NOXTLS_ECJPAKE_Y_OFFSET], NOXTLS_ECJPAKE_SCALAR_SIZE);
}

/**
 * @brief Encode an ecc_point_t as uncompressed SEC 1; the identity keeps all-zero coordinates.
 * @internal
 *
 * @param[in] point Source point.
 * @param[out] encoded 65-octet encoding.
 */
static void noxtls_ecjpake_encode(const ecc_point_t *point, uint8_t encoded[NOXTLS_ECJPAKE_POINT_SIZE])
{
    encoded[0] = NOXTLS_ECJPAKE_POINT_PREFIX_UNCOMPRESSED;
    noxtls_copy_u8(&encoded[NOXTLS_ECJPAKE_X_OFFSET], NOXTLS_ECJPAKE_SCALAR_SIZE, point->x, NOXTLS_ECJPAKE_SCALAR_SIZE);
    noxtls_copy_u8(&encoded[NOXTLS_ECJPAKE_Y_OFFSET], NOXTLS_ECJPAKE_SCALAR_SIZE, point->y, NOXTLS_ECJPAKE_SCALAR_SIZE);
}

uint32_t noxtls_ecjpake_point_is_identity(const uint8_t point[NOXTLS_ECJPAKE_POINT_SIZE])
{
    uint32_t acc = 0U;
    uint32_t index;

    for (index = NOXTLS_ECJPAKE_X_OFFSET; index < NOXTLS_ECJPAKE_POINT_SIZE; ++index) {
        acc |= (uint32_t)point[index];
    }

    return ((acc - 1U) >> NOXTLS_ECJPAKE_WORD_MSB) & 1U;
}

noxtls_return_t noxtls_ecjpake_point_validate(const uint8_t point[NOXTLS_ECJPAKE_POINT_SIZE])
{
    ecc_curve_params_t curve;
    ecc_point_t decoded;
    noxtls_return_t rc;

    if (point == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    /* SEC 1 v2.0 section 2.3.4: only the uncompressed form is negotiated (draft section 3). */
    if (point[0] != NOXTLS_ECJPAKE_POINT_PREFIX_UNCOMPRESSED) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    rc = noxtls_ecc_curve_init(&curve, NOXTLS_ECC_SECP256R1);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    noxtls_ecjpake_decode(point, &decoded);

    /* Rejects the identity, coordinates >= p and points off the curve
     * (SEC 1 v2.0 section 3.2.2.1; cofactor 1, so no subgroup check). */
    if (noxtls_ecc_point_validate_public(&decoded, &curve) != NOXTLS_RETURN_SUCCESS) {
        rc = NOXTLS_RETURN_BAD_DATA;
    }

    (void)noxtls_ecc_curve_free(&curve);
    return rc;
}

noxtls_return_t noxtls_ecjpake_point_mul(const uint8_t scalar[NOXTLS_ECJPAKE_SCALAR_SIZE],
                                         const uint8_t *point,
                                         uint8_t out[NOXTLS_ECJPAKE_POINT_SIZE])
{
    ecc_curve_params_t curve;
    ecc_point_t base;
    ecc_point_t result;
    noxtls_return_t rc;

    if ((scalar == NULL) || (out == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero(out, NOXTLS_ECJPAKE_POINT_SIZE);
    rc = noxtls_ecc_curve_init(&curve, NOXTLS_ECC_SECP256R1);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if (point == NULL) {
        base = curve.G;
    } else {
        noxtls_ecjpake_decode(point, &base);
    }

    (void)noxtls_ecc_point_init(&result, NOXTLS_ECJPAKE_SCALAR_SIZE);
    rc = noxtls_ecc_point_multiply(&result, scalar, &base, &curve);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_ecjpake_encode(&result, out);
    }

    noxtls_secure_zero(&result, sizeof(result));
    (void)noxtls_ecc_curve_free(&curve);
    return rc;
}

/**
 * @brief Replace y with p - y (point negation), constant time.
 * @internal
 *
 * @param[in,out] y 32-octet big-endian coordinate.
 * @param[in] prime 32-octet big-endian field prime p.
 */
static void noxtls_ecjpake_negate_y(uint8_t y[NOXTLS_ECJPAKE_SCALAR_SIZE],
                                    const uint8_t prime[NOXTLS_ECJPAKE_SCALAR_SIZE])
{
    uint32_t borrow = 0U;
    uint32_t index = NOXTLS_ECJPAKE_SCALAR_SIZE;

    while (index > 0U) {
        uint32_t diff;

        --index;
        diff = (uint32_t)prime[index] - (uint32_t)y[index] - borrow;
        y[index] = (uint8_t)diff;
        borrow = (diff >> NOXTLS_ECJPAKE_WORD_MSB) & 1U;
    }
}

noxtls_return_t noxtls_ecjpake_point_add(const uint8_t a[NOXTLS_ECJPAKE_POINT_SIZE],
                                         const uint8_t b[NOXTLS_ECJPAKE_POINT_SIZE],
                                         uint32_t subtract,
                                         uint8_t out[NOXTLS_ECJPAKE_POINT_SIZE])
{
    ecc_curve_params_t curve;
    ecc_point_t a_point;
    ecc_point_t b_point;
    ecc_point_t result;
    noxtls_return_t rc;

    if ((a == NULL) || (b == NULL) || (out == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_ecc_curve_init(&curve, NOXTLS_ECC_SECP256R1);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(out, NOXTLS_ECJPAKE_POINT_SIZE);
        return rc;
    }

    noxtls_ecjpake_decode(a, &a_point);
    noxtls_ecjpake_decode(b, &b_point);
    if ((subtract != 0U) && (noxtls_ecjpake_point_is_identity(b) == 0U)) {
        /* -(x, y) = (x, p - y); y != 0 for every finite P-256 point (odd prime order). */
        noxtls_ecjpake_negate_y(b_point.y, curve.p);
    }

    (void)noxtls_ecc_point_init(&result, NOXTLS_ECJPAKE_SCALAR_SIZE);
    rc = noxtls_ecc_point_add(&result, &a_point, &b_point, &curve);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_ecjpake_encode(&result, out);
    } else {
        noxtls_secure_zero(out, NOXTLS_ECJPAKE_POINT_SIZE);
    }

    noxtls_secure_zero(&a_point, sizeof(a_point));
    noxtls_secure_zero(&b_point, sizeof(b_point));
    noxtls_secure_zero(&result, sizeof(result));
    (void)noxtls_ecc_curve_free(&curve);
    return rc;
}
