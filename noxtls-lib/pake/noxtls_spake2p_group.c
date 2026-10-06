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
* File:    noxtls_spake2p_group.c
* Summary: SPAKE2+ P-256 group operations shared by all profiles
*
*
*****************************************************************************/

/**
 * @file noxtls_spake2p_group.c
 * @brief SPAKE2+ P-256 group math: M/N, scalar checks, shares, Z and V.
 * @ingroup noxtls_spake2p
 *
 * RFC 9383 section 3.2 (registration), section 3.3 (shares, Z, V) and
 * section 4 (P-256 M and N). draft-bar-cfrg-spake2plus-01 uses the same
 * points and group operations, so this file is profile independent.
 * Every scalar multiplication calls noxtls_ecc_point_multiply(), which
 * dispatches to the platform accelerator port when one is bound.
 */

#include <stdint.h>
#include <string.h>

#include "noxtls_spake2p_internal.h"
#include "pkc/ecc/noxtls_ecc.h"
#include "common/noxtls_ct.h"

/** @brief Number of 32-bit limbs in a P-256 scalar. */
#define NOXTLS_SPAKE2P_LIMBS (8U)
/** @brief Limb count with one extra limb for the carry bit during reduction. */
#define NOXTLS_SPAKE2P_LIMBS_EXT (NOXTLS_SPAKE2P_LIMBS + 1U)
/** @brief Bytes per 32-bit limb. */
#define NOXTLS_SPAKE2P_LIMB_BYTES (4U)
/** @brief Bits per byte. */
#define NOXTLS_SPAKE2P_BITS_PER_BYTE (8U)
/** @brief Bits per limb. */
#define NOXTLS_SPAKE2P_LIMB_BITS (32U)
/** @brief Most significant bit index of a limb. */
#define NOXTLS_SPAKE2P_LIMB_MSB (31U)
/** @brief Offset of the X coordinate in an uncompressed encoding. */
#define NOXTLS_SPAKE2P_X_OFFSET (1U)
/** @brief Offset of the Y coordinate in an uncompressed encoding. */
#define NOXTLS_SPAKE2P_Y_OFFSET (1U + NOXTLS_SPAKE2P_SCALAR_SIZE)

/** @brief P-256 group order n (SEC 2 v2.0 section 2.4.2), big-endian. */
static const uint8_t s_p256_order[NOXTLS_SPAKE2P_SCALAR_SIZE] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x00U,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xBCU, 0xE6U, 0xFAU, 0xADU, 0xA7U, 0x17U, 0x9EU, 0x84U,
    0xF3U, 0xB9U, 0xCAU, 0xC2U, 0xFCU, 0x63U, 0x25U, 0x51U
};

/** @brief P-256 field prime p (SEC 2 v2.0 section 2.4.2), big-endian. */
static const uint8_t s_p256_prime[NOXTLS_SPAKE2P_SCALAR_SIZE] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x01U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU
};

/**
 * @brief RFC 9383 section 4 P-256 M (compressed form
 * 02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f), uncompressed.
 */
static const uint8_t s_p256_M[NOXTLS_SPAKE2P_POINT_SIZE] = {
    0x04U,
    0x88U, 0x6EU, 0x2FU, 0x97U, 0xACU, 0xE4U, 0x6EU, 0x55U,
    0xBAU, 0x9DU, 0xD7U, 0x24U, 0x25U, 0x79U, 0xF2U, 0x99U,
    0x3BU, 0x64U, 0xE1U, 0x6EU, 0xF3U, 0xDCU, 0xABU, 0x95U,
    0xAFU, 0xD4U, 0x97U, 0x33U, 0x3DU, 0x8FU, 0xA1U, 0x2FU,
    0x5FU, 0xF3U, 0x55U, 0x16U, 0x3EU, 0x43U, 0xCEU, 0x22U,
    0x4EU, 0x0BU, 0x0EU, 0x65U, 0xFFU, 0x02U, 0xACU, 0x8EU,
    0x5CU, 0x7BU, 0xE0U, 0x94U, 0x19U, 0xC7U, 0x85U, 0xE0U,
    0xCAU, 0x54U, 0x7DU, 0x55U, 0xA1U, 0x2EU, 0x2DU, 0x20U
};

/**
 * @brief RFC 9383 section 4 P-256 N (compressed form
 * 03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49), uncompressed.
 */
static const uint8_t s_p256_N[NOXTLS_SPAKE2P_POINT_SIZE] = {
    0x04U,
    0xD8U, 0xBBU, 0xD6U, 0xC6U, 0x39U, 0xC6U, 0x29U, 0x37U,
    0xB0U, 0x4DU, 0x99U, 0x7FU, 0x38U, 0xC3U, 0x77U, 0x07U,
    0x19U, 0xC6U, 0x29U, 0xD7U, 0x01U, 0x4DU, 0x49U, 0xA2U,
    0x4BU, 0x4FU, 0x98U, 0xBAU, 0xA1U, 0x29U, 0x2BU, 0x49U,
    0x07U, 0xD6U, 0x0AU, 0xA6U, 0xBFU, 0xADU, 0xE4U, 0x50U,
    0x08U, 0xA6U, 0x36U, 0x33U, 0x7FU, 0x51U, 0x68U, 0xC6U,
    0x4DU, 0x9BU, 0xD3U, 0x60U, 0x34U, 0x80U, 0x8CU, 0xD5U,
    0x64U, 0x49U, 0x0BU, 0x1EU, 0x65U, 0x6EU, 0xDBU, 0xE7U
};

const uint8_t *noxtls_spake2p_p256_M(void)
{
    return s_p256_M;
}

const uint8_t *noxtls_spake2p_p256_N(void)
{
    return s_p256_N;
}

/**
 * @brief Load a 32-byte big-endian value into little-endian 32-bit limbs.
 * @internal
 *
 * @param[out] limbs Destination limbs (NOXTLS_SPAKE2P_LIMBS entries).
 * @param[in] bytes Big-endian source.
 */
static void noxtls_spake2p_load_limbs(uint32_t limbs[NOXTLS_SPAKE2P_LIMBS],
                                      const uint8_t bytes[NOXTLS_SPAKE2P_SCALAR_SIZE])
{
    uint32_t limb;

    for (limb = 0U; limb < NOXTLS_SPAKE2P_LIMBS; ++limb) {
        uint32_t base = NOXTLS_SPAKE2P_SCALAR_SIZE - ((limb + 1U) * NOXTLS_SPAKE2P_LIMB_BYTES);
        limbs[limb] = ((uint32_t)bytes[base] << 24) |
                      ((uint32_t)bytes[base + 1U] << 16) |
                      ((uint32_t)bytes[base + 2U] << 8) |
                      (uint32_t)bytes[base + 3U];
    }
}

/**
 * @brief Store little-endian limbs as a 32-byte big-endian value.
 * @internal
 *
 * @param[out] bytes Big-endian destination.
 * @param[in] limbs Source limbs (NOXTLS_SPAKE2P_LIMBS entries).
 */
static void noxtls_spake2p_store_limbs(uint8_t bytes[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                       const uint32_t limbs[NOXTLS_SPAKE2P_LIMBS])
{
    uint32_t limb;

    for (limb = 0U; limb < NOXTLS_SPAKE2P_LIMBS; ++limb) {
        uint32_t base = NOXTLS_SPAKE2P_SCALAR_SIZE - ((limb + 1U) * NOXTLS_SPAKE2P_LIMB_BYTES);
        bytes[base] = (uint8_t)(limbs[limb] >> 24);
        bytes[base + 1U] = (uint8_t)(limbs[limb] >> 16);
        bytes[base + 2U] = (uint8_t)(limbs[limb] >> 8);
        bytes[base + 3U] = (uint8_t)limbs[limb];
    }
}

/**
 * @brief Constant-time a < b for 32-byte big-endian values.
 * @internal
 *
 * @param[in] a First value.
 * @param[in] b Second value.
 *
 * @return 1 when a < b, 0 otherwise (no data-dependent branches).
 */
static uint32_t noxtls_spake2p_ct_less(const uint8_t a[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                       const uint8_t b[NOXTLS_SPAKE2P_SCALAR_SIZE])
{
    uint32_t borrow = 0U;
    uint32_t index = NOXTLS_SPAKE2P_SCALAR_SIZE;

    while (index > 0U) {
        --index;
        borrow = (((uint32_t)a[index] - (uint32_t)b[index] - borrow) >> NOXTLS_SPAKE2P_LIMB_MSB) & 1U;
    }

    return borrow;
}

/**
 * @brief Constant-time test for an all-zero byte string.
 * @internal
 *
 * @param[in] bytes Input.
 * @param[in] len Length.
 *
 * @return 1 when all bytes are zero, 0 otherwise.
 */
static uint32_t noxtls_spake2p_ct_is_zero(const uint8_t *bytes, uint32_t len)
{
    uint32_t acc = 0U;
    uint32_t index;

    for (index = 0U; index < len; ++index) {
        acc |= bytes[index];
    }

    return ((acc - 1U) >> NOXTLS_SPAKE2P_LIMB_MSB) & 1U;
}

int noxtls_spake2p_group_scalar_is_valid(const uint8_t scalar[NOXTLS_SPAKE2P_SCALAR_SIZE])
{
    uint32_t below_n;
    uint32_t zero;

    if (scalar == NULL) {
        return 0;
    }

    below_n = noxtls_spake2p_ct_less(scalar, s_p256_order);
    zero = noxtls_spake2p_ct_is_zero(scalar, NOXTLS_SPAKE2P_SCALAR_SIZE);
    return (int)(below_n & (zero ^ 1U));
}

noxtls_return_t noxtls_spake2p_group_reduce_mod_n(const uint8_t *in, uint32_t in_len,
                                                  uint8_t out[NOXTLS_SPAKE2P_SCALAR_SIZE])
{
    uint32_t n_limbs[NOXTLS_SPAKE2P_LIMBS_EXT];
    uint32_t r[NOXTLS_SPAKE2P_LIMBS_EXT];
    uint32_t t[NOXTLS_SPAKE2P_LIMBS_EXT];
    uint32_t byte_index;

    if ((in == NULL) || (out == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    memset(r, 0, sizeof(r));
    memset(t, 0, sizeof(t));
    noxtls_spake2p_load_limbs(n_limbs, s_p256_order);
    n_limbs[NOXTLS_SPAKE2P_LIMBS] = 0U;

    /* Left-to-right binary reduction: r = 2r + bit; if r >= n then r -= n.
     * The invariant r < n keeps 2r + 1 < 2^257, so one extra limb suffices.
     * The loop count depends only on in_len, never on the secret value. */
    for (byte_index = 0U; byte_index < in_len; ++byte_index) {
        uint32_t bit_index;

        for (bit_index = NOXTLS_SPAKE2P_BITS_PER_BYTE; bit_index > 0U; --bit_index) {
            uint32_t carry = ((uint32_t)in[byte_index] >> (bit_index - 1U)) & 1U;
            uint32_t borrow = 0U;
            uint32_t keep_mask;
            uint32_t limb;

            for (limb = 0U; limb < NOXTLS_SPAKE2P_LIMBS_EXT; ++limb) {
                uint32_t next_carry = r[limb] >> NOXTLS_SPAKE2P_LIMB_MSB;
                r[limb] = (r[limb] << 1) | carry;
                carry = next_carry;
            }

            for (limb = 0U; limb < NOXTLS_SPAKE2P_LIMBS_EXT; ++limb) {
                uint64_t diff = (uint64_t)r[limb] - (uint64_t)n_limbs[limb] - (uint64_t)borrow;
                t[limb] = (uint32_t)diff;
                borrow = (uint32_t)(diff >> NOXTLS_SPAKE2P_LIMB_BITS) & 1U;
            }

            /* borrow == 0 means r >= n: select t. */
            keep_mask = (uint32_t)0U - borrow;
            for (limb = 0U; limb < NOXTLS_SPAKE2P_LIMBS_EXT; ++limb) {
                r[limb] = (r[limb] & keep_mask) | (t[limb] & ~keep_mask);
            }
        }
    }

    noxtls_spake2p_store_limbs(out, r);
    noxtls_secure_zero(r, sizeof(r));
    noxtls_secure_zero(t, sizeof(t));
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Decode an uncompressed encoding into an ecc_point_t without validation.
 * @internal
 *
 * @param[in] encoded 65-byte encoding.
 * @param[out] point Destination point.
 */
static void noxtls_spake2p_decode(const uint8_t encoded[NOXTLS_SPAKE2P_POINT_SIZE], ecc_point_t *point)
{
    (void)noxtls_ecc_point_init(point, NOXTLS_SPAKE2P_SCALAR_SIZE);
    memcpy(point->x, &encoded[NOXTLS_SPAKE2P_X_OFFSET], NOXTLS_SPAKE2P_SCALAR_SIZE);
    memcpy(point->y, &encoded[NOXTLS_SPAKE2P_Y_OFFSET], NOXTLS_SPAKE2P_SCALAR_SIZE);
}

/**
 * @brief Encode an ecc_point_t as uncompressed SEC 1.
 * @internal
 *
 * @param[in] point Source point.
 * @param[out] encoded 65-byte encoding.
 */
static void noxtls_spake2p_encode(const ecc_point_t *point, uint8_t encoded[NOXTLS_SPAKE2P_POINT_SIZE])
{
    encoded[0] = NOXTLS_SPAKE2P_POINT_PREFIX_UNCOMPRESSED;
    memcpy(&encoded[NOXTLS_SPAKE2P_X_OFFSET], point->x, NOXTLS_SPAKE2P_SCALAR_SIZE);
    memcpy(&encoded[NOXTLS_SPAKE2P_Y_OFFSET], point->y, NOXTLS_SPAKE2P_SCALAR_SIZE);
}

/**
 * @brief Return 1 when the point is the identity (encoded as all-zero coordinates by NoxTLS).
 * @internal
 *
 * @param[in] point Point.
 *
 * @return 1 for the identity, 0 otherwise.
 */
static uint32_t noxtls_spake2p_is_identity(const ecc_point_t *point)
{
    return noxtls_spake2p_ct_is_zero(point->x, NOXTLS_SPAKE2P_SCALAR_SIZE) &
           noxtls_spake2p_ct_is_zero(point->y, NOXTLS_SPAKE2P_SCALAR_SIZE);
}

/**
 * @brief Validate a decoded point against the curve: canonical, on curve, not identity.
 * @internal
 *
 * @param[in] encoded Original encoding (for the prefix check).
 * @param[in] point Decoded point.
 * @param[in] curve P-256 parameters.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_BAD_DATA.
 */
static noxtls_return_t noxtls_spake2p_check_point(const uint8_t encoded[NOXTLS_SPAKE2P_POINT_SIZE],
                                                  const ecc_point_t *point,
                                                  const ecc_curve_params_t *curve)
{
    if (encoded[0] != NOXTLS_SPAKE2P_POINT_PREFIX_UNCOMPRESSED) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    /* SEC 1 v2.0 section 3.2.2.1: coordinates must be field elements (< p). */
    if ((noxtls_spake2p_ct_less(point->x, s_p256_prime) == 0U) ||
        (noxtls_spake2p_ct_less(point->y, s_p256_prime) == 0U)) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    /* Rejects the identity and points off the curve (cofactor h = 1, so no subgroup check). */
    if (noxtls_ecc_point_validate_public(point, curve) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_spake2p_group_validate_point(const uint8_t point[NOXTLS_SPAKE2P_POINT_SIZE])
{
    ecc_curve_params_t curve;
    ecc_point_t decoded;
    noxtls_return_t rc;

    if (point == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_ecc_curve_init(&curve, NOXTLS_ECC_SECP256R1);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    noxtls_spake2p_decode(point, &decoded);
    rc = noxtls_spake2p_check_point(point, &decoded, &curve);
    (void)noxtls_ecc_curve_free(&curve);
    return rc;
}

noxtls_return_t noxtls_spake2p_group_mul_base(const uint8_t scalar[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                              uint8_t out[NOXTLS_SPAKE2P_POINT_SIZE])
{
    ecc_curve_params_t curve;
    ecc_point_t result;
    noxtls_return_t rc;

    if ((scalar == NULL) || (out == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero(out, NOXTLS_SPAKE2P_POINT_SIZE);
    if (noxtls_spake2p_group_scalar_is_valid(scalar) == 0) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    rc = noxtls_ecc_curve_init(&curve, NOXTLS_ECC_SECP256R1);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    (void)noxtls_ecc_point_init(&result, NOXTLS_SPAKE2P_SCALAR_SIZE);
    rc = noxtls_ecc_point_multiply(&result, scalar, &curve.G, &curve);
    if ((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_spake2p_is_identity(&result) != 0U)) {
        rc = NOXTLS_RETURN_FAILED;
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_spake2p_encode(&result, out);
    }

    noxtls_secure_zero(&result, sizeof(result));
    (void)noxtls_ecc_curve_free(&curve);
    return rc;
}

/**
 * @brief Replace y with p - y (point negation), constant time.
 * @internal
 *
 * @param[in,out] y 32-byte big-endian coordinate in [1, p-1].
 */
static void noxtls_spake2p_negate_y(uint8_t y[NOXTLS_SPAKE2P_SCALAR_SIZE])
{
    uint32_t borrow = 0U;
    uint32_t index = NOXTLS_SPAKE2P_SCALAR_SIZE;

    while (index > 0U) {
        uint32_t diff;

        --index;
        diff = (uint32_t)s_p256_prime[index] - (uint32_t)y[index] - borrow;
        y[index] = (uint8_t)diff;
        borrow = (diff >> NOXTLS_SPAKE2P_LIMB_MSB) & 1U;
    }
}

/**
 * @brief Compute out = a + w0*Q, or out = a - w0*Q, for a public point Q (M or N).
 * @internal
 *
 * @param[in] a Encoded first operand (already validated or locally computed).
 * @param[in] w0 Big-endian w0 in [1, n-1].
 * @param[in] q Encoded M or N.
 * @param[in] subtract Non-zero to subtract w0*Q.
 * @param[out] out Result point (identity reported via return code).
 * @param[in] curve P-256 parameters.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_BAD_DATA if the result is the identity,
 *         or an ECC error.
 */
static noxtls_return_t noxtls_spake2p_add_w0_q(const uint8_t a[NOXTLS_SPAKE2P_POINT_SIZE],
                                               const uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                               const uint8_t q[NOXTLS_SPAKE2P_POINT_SIZE],
                                               int subtract,
                                               ecc_point_t *out,
                                               const ecc_curve_params_t *curve)
{
    ecc_point_t a_point;
    ecc_point_t q_point;
    ecc_point_t w0q;
    noxtls_return_t rc;

    noxtls_spake2p_decode(a, &a_point);
    noxtls_spake2p_decode(q, &q_point);
    (void)noxtls_ecc_point_init(&w0q, NOXTLS_SPAKE2P_SCALAR_SIZE);
    (void)noxtls_ecc_point_init(out, NOXTLS_SPAKE2P_SCALAR_SIZE);

    rc = noxtls_ecc_point_multiply(&w0q, w0, &q_point, curve);
    if ((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_spake2p_is_identity(&w0q) != 0U)) {
        rc = NOXTLS_RETURN_FAILED;
    }

    if ((rc == NOXTLS_RETURN_SUCCESS) && (subtract != 0)) {
        /* -(x, y) = (x, p - y); y != 0 for every finite P-256 point (odd prime order). */
        noxtls_spake2p_negate_y(w0q.y);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecc_point_add(out, &a_point, &w0q, curve);
    }

    if ((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_spake2p_is_identity(out) != 0U)) {
        rc = NOXTLS_RETURN_BAD_DATA;
    }

    noxtls_secure_zero(&w0q, sizeof(w0q));
    noxtls_secure_zero(&a_point, sizeof(a_point));
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(out, sizeof(*out));
    }

    return rc;
}

noxtls_return_t noxtls_spake2p_group_compute_share(noxtls_spake2p_role_t role,
                                                   const uint8_t base_part[NOXTLS_SPAKE2P_POINT_SIZE],
                                                   const uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                                   uint8_t share[NOXTLS_SPAKE2P_POINT_SIZE])
{
    ecc_curve_params_t curve;
    ecc_point_t result;
    const uint8_t *q = (role == NOXTLS_SPAKE2P_ROLE_PROVER) ? s_p256_M : s_p256_N;
    noxtls_return_t rc;

    if ((base_part == NULL) || (w0 == NULL) || (share == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero(share, NOXTLS_SPAKE2P_POINT_SIZE);
    rc = noxtls_ecc_curve_init(&curve, NOXTLS_ECC_SECP256R1);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    /* RFC 9383 section 3.3: X = x*G + w0*M (prover), Y = y*G + w0*N (verifier). */
    rc = noxtls_spake2p_add_w0_q(base_part, w0, q, 0, &result, &curve);
    if (rc == NOXTLS_RETURN_BAD_DATA) {
        /* An identity share means x = -w0*m (mod n): reject and let the caller retry. */
        rc = NOXTLS_RETURN_FAILED;
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_spake2p_encode(&result, share);
    }

    noxtls_secure_zero(&result, sizeof(result));
    (void)noxtls_ecc_curve_free(&curve);
    return rc;
}

noxtls_return_t noxtls_spake2p_group_compute_zv(const noxtls_spake2p_ctx_t *ctx,
                                                const uint8_t peer_share[NOXTLS_SPAKE2P_POINT_SIZE],
                                                uint8_t Z[NOXTLS_SPAKE2P_POINT_SIZE],
                                                uint8_t V[NOXTLS_SPAKE2P_POINT_SIZE])
{
    ecc_curve_params_t curve;
    ecc_point_t peer;
    ecc_point_t t_point;
    ecc_point_t z_point;
    ecc_point_t v_point;
    ecc_point_t l_point;
    const uint8_t *q;
    noxtls_return_t rc;

    if ((ctx == NULL) || (peer_share == NULL) || (Z == NULL) || (V == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero(Z, NOXTLS_SPAKE2P_POINT_SIZE);
    noxtls_secure_zero(V, NOXTLS_SPAKE2P_POINT_SIZE);
    rc = noxtls_ecc_curve_init(&curve, NOXTLS_ECC_SECP256R1);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    (void)noxtls_ecc_point_init(&z_point, NOXTLS_SPAKE2P_SCALAR_SIZE);
    (void)noxtls_ecc_point_init(&v_point, NOXTLS_SPAKE2P_SCALAR_SIZE);
    (void)noxtls_ecc_point_init(&t_point, NOXTLS_SPAKE2P_SCALAR_SIZE);
    noxtls_spake2p_decode(peer_share, &peer);
    rc = noxtls_spake2p_check_point(peer_share, &peer, &curve);

    /* RFC 9383 section 3.3: prover T = Y - w0*N; verifier T = X - w0*M. */
    q = (ctx->role == NOXTLS_SPAKE2P_ROLE_PROVER) ? s_p256_N : s_p256_M;
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_spake2p_add_w0_q(peer_share, ctx->w0, q, 1, &t_point, &curve);
    }

    /* Z = h*x*T (prover) or h*y*T (verifier), h = 1 for P-256. */
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecc_point_multiply(&z_point, ctx->ephemeral, &t_point, &curve);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        if (ctx->role == NOXTLS_SPAKE2P_ROLE_PROVER) {
            /* V = h*w1*T. */
            rc = noxtls_ecc_point_multiply(&v_point, ctx->w1, &t_point, &curve);
        } else {
            /* V = h*y*L. */
            noxtls_spake2p_decode(ctx->L, &l_point);
            rc = noxtls_ecc_point_multiply(&v_point, ctx->ephemeral, &l_point, &curve);
            noxtls_secure_zero(&l_point, sizeof(l_point));
        }
    }

    if ((rc == NOXTLS_RETURN_SUCCESS) &&
        ((noxtls_spake2p_is_identity(&z_point) | noxtls_spake2p_is_identity(&v_point)) != 0U)) {
        rc = NOXTLS_RETURN_BAD_DATA;
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_spake2p_encode(&z_point, Z);
        noxtls_spake2p_encode(&v_point, V);
    }

    noxtls_secure_zero(&t_point, sizeof(t_point));
    noxtls_secure_zero(&z_point, sizeof(z_point));
    noxtls_secure_zero(&v_point, sizeof(v_point));
    (void)noxtls_ecc_curve_free(&curve);
    return rc;
}
