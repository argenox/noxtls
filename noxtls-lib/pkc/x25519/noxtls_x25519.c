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
* File:    noxtls_x25519.c
* Summary: X25519 key agreement (Curve25519, RFC 7748)
*
*
*****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "drbg/noxtls_drbg.h"
#include "noxtls_common.h"
#include "noxtls_x25519.h"

/*
 * Keep the X25519 backend portable across the embedded targets we actually
 * support. A 5x51 backend built around 128-bit intermediates is attractive on
 * host CPUs, but it is not a valid optimization direction for our 32-bit
 * embedded platforms.
 */
#define NOXTLS_X25519_USE_FE51 0

#if NOXTLS_X25519_USE_FE51

#define X25519_FE_LIMBS 5U
#define X25519_FE51_MASK UINT64_C(0x7FFFFFFFFFFFF)

typedef struct {
    uint64_t v[X25519_FE_LIMBS];
} fe25519_t;

typedef unsigned __int128 fe25519_u128_t;

/**
 * @brief The p limbs.
 *
 * @param[in] X25519_FE_LIMBS The X25519_FE_LIMBS value.
 * @param[in] X25519_FE51_MASK The X25519_FE51_MASK value.
 * @return The p limbs.
 */
static const uint64_t x25519_p_limbs[X25519_FE_LIMBS] = {
    X25519_FE51_MASK - 18U,
    X25519_FE51_MASK,
    X25519_FE51_MASK,
    X25519_FE51_MASK,
    X25519_FE51_MASK
};

/**
 * @brief Load 64 bits from a little-endian source.
 *
 * @param[in] src The source value.
 * @return The loaded value.
 */
static uint64_t load64_le(const uint8_t *src)
{
    uint64_t value = 0U;
    uint32_t i;

    for(i = 0U; i < 8U; i++) {
        value |= ((uint64_t)src[i]) << (8U * i);
    }
    return value;
}

/**
 * @brief Store 64 bits to a little-endian destination.
 *
 * @param[out] dst The destination value.
 * @param[in] value The value to store.
 */
static void store64_le(uint8_t *dst, uint64_t value)
{
    uint32_t i;

    for(i = 0U; i < 8U; i++) {
        dst[i] = (uint8_t)(value >> (8U * i));
    }
}

/**
 * @brief Carry the fe25519_t.
 *
 * @param[in] a The a value.
 */
static void fe25519_carry(fe25519_t *a)
{
    uint64_t carry;

    carry = a->v[0] >> 51;
    a->v[0] &= X25519_FE51_MASK;
    a->v[1] += carry;
    carry = a->v[1] >> 51;
    a->v[1] &= X25519_FE51_MASK;
    a->v[2] += carry;
    carry = a->v[2] >> 51;
    a->v[2] &= X25519_FE51_MASK;
    a->v[3] += carry;
    carry = a->v[3] >> 51;
    a->v[3] &= X25519_FE51_MASK;
    a->v[4] += carry;
    carry = a->v[4] >> 51;
    a->v[4] &= X25519_FE51_MASK;
    a->v[0] += carry * 19U;
    carry = a->v[0] >> 51;
    a->v[0] &= X25519_FE51_MASK;
    a->v[1] += carry;
}

/**
 * @brief Check if the fe25519_t is greater than or equal to p.
 *
 * @param[in] a The a value.
 * @return 1 if the fe25519_t is greater than or equal to p, 0 otherwise.
 */
static int fe25519_ge_p(const fe25519_t *a)
{
    int i;

    for(i = (int)X25519_FE_LIMBS - 1; i >= 0; i--) {
        if(a->v[i] > x25519_p_limbs[i]) {
            return 1;
        }
        if(a->v[i] < x25519_p_limbs[i]) {
            return 0;
        }
    }
    return 1;
}

/**
 * @brief Subtract p from the fe25519_t.
 *
 * @param[in] a The a value.
 */
static void fe25519_sub_p(fe25519_t *a)
{
    uint32_t i;
    uint64_t borrow = 0U;

    for(i = 0U; i < X25519_FE_LIMBS; i++) {
        uint64_t bi = x25519_p_limbs[i] + borrow;
        if(a->v[i] < bi) {
            a->v[i] = (a->v[i] + (X25519_FE51_MASK + 1U)) - bi;
            borrow = 1U;
        } else {
            a->v[i] -= bi;
            borrow = 0U;
        }
    }
}

/**
 * @brief Normalize the fe25519_t.
 *
 * @param[in] a The a value.
 */
static void fe25519_normalize(fe25519_t *a)
{
    fe25519_carry(a);
    fe25519_carry(a);
    if(fe25519_ge_p(a)) {
        fe25519_sub_p(a);
    }
}

/**
 * @brief Copy the fe25519_t.
 *
 * @param[out] dst The destination value.
 * @param[in] src The source value.
 */
static void fe25519_copy(fe25519_t *dst, const fe25519_t *src)
{
    memcpy(dst, src, sizeof(*dst));
}

/**
 * @brief Zero the fe25519_t.
 *
 * @param[in] a The a value.
 */
static void fe25519_zero(fe25519_t *a)
{
    memset(a, 0, sizeof(*a));
}

/**
 * @brief One the fe25519_t.
 *
 * @param[in] a The a value.
 */
static void fe25519_one(fe25519_t *a)
{
    fe25519_zero(a);
    a->v[0] = 1U;
}

/**
 * @brief From little-endian to fe25519_t.
 *
 * @param[out] out The output value.
 * @param[in] in The input value.
 */
static void fe25519_from_le(fe25519_t *out, const uint8_t in[32])
{
    uint64_t x0 = load64_le(in);
    uint64_t x1 = load64_le(in + 8U);
    uint64_t x2 = load64_le(in + 16U);
    uint64_t x3 = load64_le(in + 24U);

    out->v[0] = x0 & X25519_FE51_MASK;
    out->v[1] = ((x0 >> 51) | (x1 << 13)) & X25519_FE51_MASK;
    out->v[2] = ((x1 >> 38) | (x2 << 26)) & X25519_FE51_MASK;
    out->v[3] = ((x2 >> 25) | (x3 << 39)) & X25519_FE51_MASK;
    out->v[4] = (x3 >> 12) & X25519_FE51_MASK;
    fe25519_normalize(out);
}

/**
 * @brief To little-endian from fe25519_t.
 *
 * @param[out] out The output value.
 * @param[in] in The input value.
 */
static void fe25519_to_le(uint8_t out[32], const fe25519_t *in)
{
    fe25519_t t;
    uint64_t x0;
    uint64_t x1;
    uint64_t x2;
    uint64_t x3;

    fe25519_copy(&t, in);
    fe25519_normalize(&t);

    x0 = t.v[0] | (t.v[1] << 51);
    x1 = (t.v[1] >> 13) | (t.v[2] << 38);
    x2 = (t.v[2] >> 26) | (t.v[3] << 25);
    x3 = (t.v[3] >> 39) | (t.v[4] << 12);

    store64_le(out, x0);
    store64_le(out + 8U, x1);
    store64_le(out + 16U, x2);
    store64_le(out + 24U, x3);
    out[31] &= (uint8_t)NOXTLS_X25519_RESULT_HIGH_CLEAR;
}

/**
 * @brief Conditional swap the fe25519_t.
 *
 * @param[in] swap The swap value.
 * @param[in] a The a value.
 * @param[in] b The b value.
 */
static void fe25519_cswap(uint8_t swap, fe25519_t *a, fe25519_t *b)
{
    uint64_t mask = (uint64_t)(0U - (uint64_t)(swap & 1U));
    uint32_t i;

    for(i = 0U; i < X25519_FE_LIMBS; i++) {
        uint64_t d = mask & (a->v[i] ^ b->v[i]);
        a->v[i] ^= d;
        b->v[i] ^= d;
    }
}

/**
 * @brief Add the fe25519_t.
 *
 * @param[out] out The output value.
 * @param[in] a The a value.
 * @param[in] b The b value.
 */
static void fe25519_add(fe25519_t *out, const fe25519_t *a, const fe25519_t *b)
{
    out->v[0] = a->v[0] + b->v[0];
    out->v[1] = a->v[1] + b->v[1];
    out->v[2] = a->v[2] + b->v[2];
    out->v[3] = a->v[3] + b->v[3];
    out->v[4] = a->v[4] + b->v[4];
    fe25519_carry(out);
}

/**
 * @brief Subtract the fe25519_t.
 *
 * @param[out] out The output value.
 * @param[in] a The a value.
 * @param[in] b The b value.
 */
static void fe25519_sub(fe25519_t *out, const fe25519_t *a, const fe25519_t *b)
{
    out->v[0] = a->v[0] + ((x25519_p_limbs[0]) << 2) - b->v[0];
    out->v[1] = a->v[1] + ((x25519_p_limbs[1]) << 2) - b->v[1];
    out->v[2] = a->v[2] + ((x25519_p_limbs[2]) << 2) - b->v[2];
    out->v[3] = a->v[3] + ((x25519_p_limbs[3]) << 2) - b->v[3];
    out->v[4] = a->v[4] + ((x25519_p_limbs[4]) << 2) - b->v[4];
    fe25519_carry(out);
}

/**
 * @brief Multiply the fe25519_t.
 *
 * @param[out] out The output value.
 * @param[in] a The a value.
 * @param[in] b The b value.
 */
static void fe25519_mul(fe25519_t *out, const fe25519_t *a, const fe25519_t *b)
{
    const uint64_t f0 = a->v[0];
    const uint64_t f1 = a->v[1];
    const uint64_t f2 = a->v[2];
    const uint64_t f3 = a->v[3];
    const uint64_t f4 = a->v[4];
    const uint64_t g0 = b->v[0];
    const uint64_t g1 = b->v[1];
    const uint64_t g2 = b->v[2];
    const uint64_t g3 = b->v[3];
    const uint64_t g4 = b->v[4];
    const uint64_t g1_19 = g1 * 19U;
    const uint64_t g2_19 = g2 * 19U;
    const uint64_t g3_19 = g3 * 19U;
    const uint64_t g4_19 = g4 * 19U;
    fe25519_u128_t h0 = ((fe25519_u128_t)f0 * g0) + ((fe25519_u128_t)f1 * g4_19) + ((fe25519_u128_t)f2 * g3_19) + ((fe25519_u128_t)f3 * g2_19) + ((fe25519_u128_t)f4 * g1_19);
    fe25519_u128_t h1 = ((fe25519_u128_t)f0 * g1) + ((fe25519_u128_t)f1 * g0) + ((fe25519_u128_t)f2 * g4_19) + ((fe25519_u128_t)f3 * g3_19) + ((fe25519_u128_t)f4 * g2_19);
    fe25519_u128_t h2 = ((fe25519_u128_t)f0 * g2) + ((fe25519_u128_t)f1 * g1) + ((fe25519_u128_t)f2 * g0) + ((fe25519_u128_t)f3 * g4_19) + ((fe25519_u128_t)f4 * g3_19);
    fe25519_u128_t h3 = ((fe25519_u128_t)f0 * g3) + ((fe25519_u128_t)f1 * g2) + ((fe25519_u128_t)f2 * g1) + ((fe25519_u128_t)f3 * g0) + ((fe25519_u128_t)f4 * g4_19);
    fe25519_u128_t h4 = ((fe25519_u128_t)f0 * g4) + ((fe25519_u128_t)f1 * g3) + ((fe25519_u128_t)f2 * g2) + ((fe25519_u128_t)f3 * g1) + ((fe25519_u128_t)f4 * g0);
    uint64_t carry;

    carry = (uint64_t)(h0 >> 51);
    h1 += carry;
    out->v[0] = (uint64_t)h0 & X25519_FE51_MASK;
    carry = (uint64_t)(h1 >> 51);
    h2 += carry;
    out->v[1] = (uint64_t)h1 & X25519_FE51_MASK;
    carry = (uint64_t)(h2 >> 51);
    h3 += carry;
    out->v[2] = (uint64_t)h2 & X25519_FE51_MASK;
    carry = (uint64_t)(h3 >> 51);
    h4 += carry;
    out->v[3] = (uint64_t)h3 & X25519_FE51_MASK;
    carry = (uint64_t)(h4 >> 51);
    out->v[4] = (uint64_t)h4 & X25519_FE51_MASK;
    out->v[0] += carry * 19U;
    fe25519_carry(out);
}

/**
 * @brief Square the fe25519_t.
 *
 * @param[out] out The output value.
 * @param[in] a The a value.
 */
static void fe25519_sq(fe25519_t *out, const fe25519_t *a)
{
    const uint64_t f0 = a->v[0];
    const uint64_t f1 = a->v[1];
    const uint64_t f2 = a->v[2];
    const uint64_t f3 = a->v[3];
    const uint64_t f4 = a->v[4];
    const uint64_t f0_2 = f0 * 2U;
    const uint64_t f1_2 = f1 * 2U;
    const uint64_t f2_2 = f2 * 2U;
    const uint64_t f3_2 = f3 * 2U;
    const uint64_t f1_38 = f1 * 38U;
    const uint64_t f2_38 = f2 * 38U;
    const uint64_t f3_38 = f3 * 38U;
    const uint64_t f4_19 = f4 * 19U;
    const uint64_t f4_38 = f4 * 38U;
    fe25519_u128_t h0 = ((fe25519_u128_t)f0 * f0) + ((fe25519_u128_t)f1_38 * f4) + ((fe25519_u128_t)f2_38 * f3);
    fe25519_u128_t h1 = ((fe25519_u128_t)f0_2 * f1) + ((fe25519_u128_t)f2_38 * f4) + ((fe25519_u128_t)f3 * (f3 * 19U));
    fe25519_u128_t h2 = ((fe25519_u128_t)f0_2 * f2) + ((fe25519_u128_t)f1 * f1) + ((fe25519_u128_t)f3_38 * f4);
    fe25519_u128_t h3 = ((fe25519_u128_t)f0_2 * f3) + ((fe25519_u128_t)f1_2 * f2) + ((fe25519_u128_t)f4_19 * f4);
    fe25519_u128_t h4 = ((fe25519_u128_t)f0_2 * f4) + ((fe25519_u128_t)f1_2 * f3) + ((fe25519_u128_t)f2 * f2);
    uint64_t carry;

    (void)f2_2;
    (void)f3_2;
    (void)f4_38;

    carry = (uint64_t)(h0 >> 51);
    h1 += carry;
    out->v[0] = (uint64_t)h0 & X25519_FE51_MASK;
    carry = (uint64_t)(h1 >> 51);
    h2 += carry;
    out->v[1] = (uint64_t)h1 & X25519_FE51_MASK;
    carry = (uint64_t)(h2 >> 51);
    h3 += carry;
    out->v[2] = (uint64_t)h2 & X25519_FE51_MASK;
    carry = (uint64_t)(h3 >> 51);
    h4 += carry;
    out->v[3] = (uint64_t)h3 & X25519_FE51_MASK;
    carry = (uint64_t)(h4 >> 51);
    out->v[4] = (uint64_t)h4 & X25519_FE51_MASK;
    out->v[0] += carry * 19U;
    fe25519_carry(out);
}

/**
 * @brief Multiply the fe25519_t by a small constant.
 *
 * @param[out] out The output value.
 * @param[in] a The a value.
 * @param[in] c The c value.
 */
static void fe25519_mul_small(fe25519_t *out, const fe25519_t *a, uint32_t c)
{
    fe25519_u128_t h0 = (fe25519_u128_t)a->v[0] * c;
    fe25519_u128_t h1 = (fe25519_u128_t)a->v[1] * c;
    fe25519_u128_t h2 = (fe25519_u128_t)a->v[2] * c;
    fe25519_u128_t h3 = (fe25519_u128_t)a->v[3] * c;
    fe25519_u128_t h4 = (fe25519_u128_t)a->v[4] * c;
    uint64_t carry;

    carry = (uint64_t)(h0 >> 51);
    h1 += carry;
    out->v[0] = (uint64_t)h0 & X25519_FE51_MASK;
    carry = (uint64_t)(h1 >> 51);
    h2 += carry;
    out->v[1] = (uint64_t)h1 & X25519_FE51_MASK;
    carry = (uint64_t)(h2 >> 51);
    h3 += carry;
    out->v[2] = (uint64_t)h2 & X25519_FE51_MASK;
    carry = (uint64_t)(h3 >> 51);
    h4 += carry;
    out->v[3] = (uint64_t)h3 & X25519_FE51_MASK;
    carry = (uint64_t)(h4 >> 51);
    out->v[4] = (uint64_t)h4 & X25519_FE51_MASK;
    out->v[0] += carry * 19U;
    fe25519_carry(out);
}

/**
 * @brief Square the fe25519_t times.
 *
 * @param[out] out The output value.
 * @param[in] z The z value.
 * @param[in] count The count value.
 */
static void fe25519_sq_times(fe25519_t *out, const fe25519_t *z, uint32_t count)
{
    uint32_t i;

    fe25519_copy(out, z);
    for(i = 0U; i < count; i++) {
        fe25519_sq(out, out);
    }
}

/**
 * @brief Inverse the fe25519_t.
 *
 * @param[out] out The output value.
 * @param[in] z The z value.
 */
static void fe25519_inv(fe25519_t *out, const fe25519_t *z)
{
    fe25519_t z2;
    fe25519_t z9;
    fe25519_t z11;
    fe25519_t z2_5_0;
    fe25519_t z2_10_0;
    fe25519_t z2_20_0;
    fe25519_t z2_50_0;
    fe25519_t z2_100_0;
    fe25519_t t0;
    fe25519_t t1;

    fe25519_sq(&z2, z);
    fe25519_sq(&t0, &z2);
    fe25519_sq(&t0, &t0);
    fe25519_mul(&z9, &t0, z);
    fe25519_mul(&z11, &z9, &z2);
    fe25519_sq(&t0, &z11);
    fe25519_mul(&z2_5_0, &t0, &z9);

    fe25519_sq_times(&t0, &z2_5_0, 5U);
    fe25519_mul(&z2_10_0, &t0, &z2_5_0);

    fe25519_sq_times(&t0, &z2_10_0, 10U);
    fe25519_mul(&z2_20_0, &t0, &z2_10_0);

    fe25519_sq_times(&t0, &z2_20_0, 20U);
    fe25519_mul(&t0, &t0, &z2_20_0);

    fe25519_sq_times(&t0, &t0, 10U);
    fe25519_mul(&z2_50_0, &t0, &z2_10_0);

    fe25519_sq_times(&t0, &z2_50_0, 50U);
    fe25519_mul(&z2_100_0, &t0, &z2_50_0);

    fe25519_sq_times(&t1, &z2_100_0, 100u);
    fe25519_mul(&t1, &t1, &z2_100_0);

    fe25519_sq_times(&t1, &t1, 50U);
    fe25519_mul(&t1, &t1, &z2_50_0);

    fe25519_sq_times(&t1, &t1, 5U);
    fe25519_mul(out, &t1, &z11);
}

/**
 * @brief Scalar multiply the fe25519_t.
 *
 * @param[in] k The k value.
 * @param[in] u The u value.
 * @param[out] result The result value.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the input or output is NULL, or another NOXTLS_RETURN_t on failure.
 */
static noxtls_return_t x25519_scalar_mult(const uint8_t k[NOXTLS_X25519_KEY_SIZE],
                                          const uint8_t u[NOXTLS_X25519_KEY_SIZE],
                                          uint8_t result[NOXTLS_X25519_KEY_SIZE])
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint8_t k_clamped[NOXTLS_X25519_KEY_SIZE];
    uint8_t u_masked[NOXTLS_X25519_KEY_SIZE];
    fe25519_t x1;
    fe25519_t x2;
    fe25519_t z2;
    fe25519_t x3;
    fe25519_t z3;
    fe25519_t a;
    fe25519_t aa;
    fe25519_t b;
    fe25519_t bb;
    fe25519_t e;
    fe25519_t c;
    fe25519_t d;
    fe25519_t da;
    fe25519_t cb;
    fe25519_t t0;
    fe25519_t t1;
    fe25519_t inv;
    uint8_t swap = 0U;
    int t;

    memcpy(k_clamped, k, NOXTLS_X25519_KEY_SIZE);
    memcpy(u_masked, u, NOXTLS_X25519_KEY_SIZE);
    k_clamped[0] &= (uint8_t)NOXTLS_X25519_CLAMP_BYTE0_MASK;
    k_clamped[31] &= (uint8_t)NOXTLS_X25519_CLAMP_BYTE31_AND;
    k_clamped[31] |= (uint8_t)NOXTLS_X25519_CLAMP_BYTE31_OR;
    u_masked[31] &= (uint8_t)NOXTLS_X25519_U_COORD_HIGH_CLEAR;

    fe25519_from_le(&x1, u_masked);
    fe25519_one(&x2);
    fe25519_zero(&z2);
    fe25519_copy(&x3, &x1);
    fe25519_one(&z3);

    for(t = (int)NOXTLS_X25519_SCALAR_LOOP_TOP; t >= 0; t--) {
        uint8_t k_t = (uint8_t)((k_clamped[t >> 3] >> (t & 7)) & 1U);
        swap ^= k_t;
        fe25519_cswap(swap, &x2, &x3);
        fe25519_cswap(swap, &z2, &z3);
        swap = k_t;

        fe25519_add(&a, &x2, &z2);
        fe25519_sq(&aa, &a);
        fe25519_sub(&b, &x2, &z2);
        fe25519_sq(&bb, &b);
        fe25519_sub(&e, &aa, &bb);
        fe25519_add(&c, &x3, &z3);
        fe25519_sub(&d, &x3, &z3);
        fe25519_mul(&da, &d, &a);
        fe25519_mul(&cb, &c, &b);
        fe25519_add(&t0, &da, &cb);
        fe25519_sub(&t1, &da, &cb);
        fe25519_sq(&x3, &t0);
        fe25519_sq(&t0, &t1);
        fe25519_mul(&z3, &x1, &t0);
        fe25519_mul(&x2, &aa, &bb);
        fe25519_mul_small(&t0, &e, 121665u);
        fe25519_add(&t0, &aa, &t0);
        fe25519_mul(&z2, &e, &t0);
    }

    fe25519_cswap(swap, &x2, &x3);
    fe25519_cswap(swap, &z2, &z3);

    fe25519_inv(&inv, &z2);
    fe25519_mul(&x2, &x2, &inv);
    fe25519_to_le(result, &x2);
    return NOXTLS_RETURN_SUCCESS;
}

#else

#define X25519_FE_LIMBS 10U

typedef struct {
    int32_t v[X25519_FE_LIMBS];
} fe25519_t;

/**
 * @brief Load 32 bits from a little-endian source.
 *
 * @param[in] src The source value.
 * @return The loaded value.
 */
static uint32_t load32_le(const uint8_t *src)
{
    return ((uint32_t)src[0]) |
           ((uint32_t)src[1] << 8) |
           ((uint32_t)src[2] << 16) |
           ((uint32_t)src[3] << 24);
}

/**
 * @brief Load 24 bits from a little-endian source.
 *
 * @param[in] src The source value.
 * @return The loaded value.
 */
static uint32_t load24_le(const uint8_t *src)
{
    return ((uint32_t)src[0]) |
           ((uint32_t)src[1] << 8) |
           ((uint32_t)src[2] << 16);
}

/**
 * @brief Copy the fe25519_t.
 *
 * @param[out] dst The destination value.
 * @param[in] src The source value.
 */
static void fe25519_copy(fe25519_t *dst, const fe25519_t *src)
{
    memcpy(dst, src, sizeof(*dst));
}

/**
 * @brief Zero the fe25519_t.
 *
 * @param[in] a The a value.
 */
static void fe25519_zero(fe25519_t *a)
{
    memset(a, 0, sizeof(*a));
}

/**
 * @brief One the fe25519_t.
 *
 * @param[in] a The a value.
 */
static void fe25519_one(fe25519_t *a)
{
    fe25519_zero(a);
    a->v[0] = 1;
}

/**
 * @brief From little-endian to fe25519_t.
 *
 * @param[out] out The output value.
 * @param[in] in The input value.
 */
static void fe25519_from_le(fe25519_t *out, const uint8_t in[32])
{
    int64_t h0 = (int64_t)load32_le(in);
    int64_t h1 = (int64_t)load24_le(in + 4U) << 6;
    int64_t h2 = (int64_t)load24_le(in + 7U) << 5;
    int64_t h3 = (int64_t)load24_le(in + 10U) << 3;
    int64_t h4 = (int64_t)load24_le(in + 13U) << 2;
    int64_t h5 = (int64_t)load32_le(in + 16U);
    int64_t h6 = (int64_t)load24_le(in + 20U) << 7;
    int64_t h7 = (int64_t)load24_le(in + 23U) << 5;
    int64_t h8 = (int64_t)load24_le(in + 26U) << 4;
    int64_t h9 = (int64_t)(load24_le(in + 29U) & 0x7FFFFFu) << 2;
    int64_t carry;

    carry = (h9 + (((int64_t)1) << 24)) >> 25;
    h0 += carry * 19;
    h9 -= carry << 25;
    carry = (h1 + (((int64_t)1) << 24)) >> 25;
    h2 += carry;
    h1 -= carry << 25;
    carry = (h3 + (((int64_t)1) << 24)) >> 25;
    h4 += carry;
    h3 -= carry << 25;
    carry = (h5 + (((int64_t)1) << 24)) >> 25;
    h6 += carry;
    h5 -= carry << 25;
    carry = (h7 + (((int64_t)1) << 24)) >> 25;
    h8 += carry;
    h7 -= carry << 25;

    carry = (h0 + (((int64_t)1) << 25)) >> 26;
    h1 += carry;
    h0 -= carry << 26;
    carry = (h2 + (((int64_t)1) << 25)) >> 26;
    h3 += carry;
    h2 -= carry << 26;
    carry = (h4 + (((int64_t)1) << 25)) >> 26;
    h5 += carry;
    h4 -= carry << 26;
    carry = (h6 + (((int64_t)1) << 25)) >> 26;
    h7 += carry;
    h6 -= carry << 26;
    carry = (h8 + (((int64_t)1) << 25)) >> 26;
    h9 += carry;
    h8 -= carry << 26;

    out->v[0] = (int32_t)h0;
    out->v[1] = (int32_t)h1;
    out->v[2] = (int32_t)h2;
    out->v[3] = (int32_t)h3;
    out->v[4] = (int32_t)h4;
    out->v[5] = (int32_t)h5;
    out->v[6] = (int32_t)h6;
    out->v[7] = (int32_t)h7;
    out->v[8] = (int32_t)h8;
    out->v[9] = (int32_t)h9;
}

/**
 * @brief To little-endian from fe25519_t.
 *
 * @param[out] out The output value.
 * @param[in] in The input value.
 */
static void fe25519_to_le(uint8_t out[32], const fe25519_t *in)
{
    int64_t h0 = in->v[0];
    int64_t h1 = in->v[1];
    int64_t h2 = in->v[2];
    int64_t h3 = in->v[3];
    int64_t h4 = in->v[4];
    int64_t h5 = in->v[5];
    int64_t h6 = in->v[6];
    int64_t h7 = in->v[7];
    int64_t h8 = in->v[8];
    int64_t h9 = in->v[9];
    int64_t q;
    int64_t carry;

    q = (19 * h9 + (((int64_t)1) << 24)) >> 25;
    q = (h0 + q) >> 26;
    q = (h1 + q) >> 25;
    q = (h2 + q) >> 26;
    q = (h3 + q) >> 25;
    q = (h4 + q) >> 26;
    q = (h5 + q) >> 25;
    q = (h6 + q) >> 26;
    q = (h7 + q) >> 25;
    q = (h8 + q) >> 26;
    q = (h9 + q) >> 25;

    h0 += 19 * q;

    carry = h0 >> 26;
    h1 += carry;
    h0 -= carry << 26;
    carry = h1 >> 25;
    h2 += carry;
    h1 -= carry << 25;
    carry = h2 >> 26;
    h3 += carry;
    h2 -= carry << 26;
    carry = h3 >> 25;
    h4 += carry;
    h3 -= carry << 25;
    carry = h4 >> 26;
    h5 += carry;
    h4 -= carry << 26;
    carry = h5 >> 25;
    h6 += carry;
    h5 -= carry << 25;
    carry = h6 >> 26;
    h7 += carry;
    h6 -= carry << 26;
    carry = h7 >> 25;
    h8 += carry;
    h7 -= carry << 25;
    carry = h8 >> 26;
    h9 += carry;
    h8 -= carry << 26;
    carry = h9 >> 25;
    h9 -= carry << 25;

    out[0] = (uint8_t)(h0 >> 0);
    out[1] = (uint8_t)(h0 >> 8);
    out[2] = (uint8_t)(h0 >> 16);
    out[3] = (uint8_t)((h0 >> 24) | (h1 << 2));
    out[4] = (uint8_t)(h1 >> 6);
    out[5] = (uint8_t)(h1 >> 14);
    out[6] = (uint8_t)((h1 >> 22) | (h2 << 3));
    out[7] = (uint8_t)(h2 >> 5);
    out[8] = (uint8_t)(h2 >> 13);
    out[9] = (uint8_t)((h2 >> 21) | (h3 << 5));
    out[10] = (uint8_t)(h3 >> 3);
    out[11] = (uint8_t)(h3 >> 11);
    out[12] = (uint8_t)((h3 >> 19) | (h4 << 6));
    out[13] = (uint8_t)(h4 >> 2);
    out[14] = (uint8_t)(h4 >> 10);
    out[15] = (uint8_t)(h4 >> 18);
    out[16] = (uint8_t)(h5 >> 0);
    out[17] = (uint8_t)(h5 >> 8);
    out[18] = (uint8_t)(h5 >> 16);
    out[19] = (uint8_t)((h5 >> 24) | (h6 << 1));
    out[20] = (uint8_t)(h6 >> 7);
    out[21] = (uint8_t)(h6 >> 15);
    out[22] = (uint8_t)((h6 >> 23) | (h7 << 3));
    out[23] = (uint8_t)(h7 >> 5);
    out[24] = (uint8_t)(h7 >> 13);
    out[25] = (uint8_t)((h7 >> 21) | (h8 << 4));
    out[26] = (uint8_t)(h8 >> 4);
    out[27] = (uint8_t)(h8 >> 12);
    out[28] = (uint8_t)((h8 >> 20) | (h9 << 6));
    out[29] = (uint8_t)(h9 >> 2);
    out[30] = (uint8_t)(h9 >> 10);
    out[31] = (uint8_t)(h9 >> 18);
    out[31] &= (uint8_t)NOXTLS_X25519_RESULT_HIGH_CLEAR;
}

/**
 * @brief Conditional swap the fe25519_t.
 *
 * @param[in] swap The swap value.
 * @param[in] a The a value.
 * @param[in] b The b value.
 */
static void fe25519_cswap(uint8_t swap, fe25519_t *a, fe25519_t *b)
{
    uint32_t mask = (uint32_t)(0U - (uint32_t)(swap & 1U));
    uint32_t i;

    for(i = 0U; i < X25519_FE_LIMBS; i++) {
        uint32_t ai = (uint32_t)a->v[i];
        uint32_t bi = (uint32_t)b->v[i];
        uint32_t d = mask & (ai ^ bi);
        a->v[i] = (int32_t)(ai ^ d);
        b->v[i] = (int32_t)(bi ^ d);
    }
}

/**
 * @brief Add the fe25519_t.
 *
 * @param[out] out The output value.
 * @param[in] a The a value.
 * @param[in] b The b value.
 */
static void fe25519_add(fe25519_t *out, const fe25519_t *a, const fe25519_t *b)
{
    uint32_t i;

    for(i = 0U; i < X25519_FE_LIMBS; i++) {
        out->v[i] = a->v[i] + b->v[i];
    }
}

/**
 * @brief Subtract the fe25519_t.
 *
 * @param[out] out The output value.
 * @param[in] a The a value.
 * @param[in] b The b value.
 */
static void fe25519_sub(fe25519_t *out, const fe25519_t *a, const fe25519_t *b)
{
    uint32_t i;

    for(i = 0U; i < X25519_FE_LIMBS; i++) {
        out->v[i] = a->v[i] - b->v[i];
    }
}

/**
 * @brief Multiply the fe25519_t.
 *
 * @param[out] out The output value.
 * @param[in] a The a value.
 * @param[in] b The b value.
 */
static void fe25519_mul(fe25519_t *out, const fe25519_t *a, const fe25519_t *b)
{
    const int64_t f0 = a->v[0];
    const int64_t f1 = a->v[1];
    const int64_t f2 = a->v[2];
    const int64_t f3 = a->v[3];
    const int64_t f4 = a->v[4];
    const int64_t f5 = a->v[5];
    const int64_t f6 = a->v[6];
    const int64_t f7 = a->v[7];
    const int64_t f8 = a->v[8];
    const int64_t f9 = a->v[9];
    const int64_t g0 = b->v[0];
    const int64_t g1 = b->v[1];
    const int64_t g2 = b->v[2];
    const int64_t g3 = b->v[3];
    const int64_t g4 = b->v[4];
    const int64_t g5 = b->v[5];
    const int64_t g6 = b->v[6];
    const int64_t g7 = b->v[7];
    const int64_t g8 = b->v[8];
    const int64_t g9 = b->v[9];
    const int64_t g1_19 = 19 * g1;
    const int64_t g2_19 = 19 * g2;
    const int64_t g3_19 = 19 * g3;
    const int64_t g4_19 = 19 * g4;
    const int64_t g5_19 = 19 * g5;
    const int64_t g6_19 = 19 * g6;
    const int64_t g7_19 = 19 * g7;
    const int64_t g8_19 = 19 * g8;
    const int64_t g9_19 = 19 * g9;
    const int64_t f1_2 = 2 * f1;
    const int64_t f3_2 = 2 * f3;
    const int64_t f5_2 = 2 * f5;
    const int64_t f7_2 = 2 * f7;
    const int64_t f9_2 = 2 * f9;
    int64_t h0 = f0 * g0 + f1_2 * g9_19 + f2 * g8_19 + f3_2 * g7_19 + f4 * g6_19 + f5_2 * g5_19 + f6 * g4_19 + f7_2 * g3_19 + f8 * g2_19 + f9_2 * g1_19;
    int64_t h1 = f0 * g1 + f1 * g0 + f2 * g9_19 + f3 * g8_19 + f4 * g7_19 + f5 * g6_19 + f6 * g5_19 + f7 * g4_19 + f8 * g3_19 + f9 * g2_19;
    int64_t h2 = f0 * g2 + f1_2 * g1 + f2 * g0 + f3_2 * g9_19 + f4 * g8_19 + f5_2 * g7_19 + f6 * g6_19 + f7_2 * g5_19 + f8 * g4_19 + f9_2 * g3_19;
    int64_t h3 = f0 * g3 + f1 * g2 + f2 * g1 + f3 * g0 + f4 * g9_19 + f5 * g8_19 + f6 * g7_19 + f7 * g6_19 + f8 * g5_19 + f9 * g4_19;
    int64_t h4 = f0 * g4 + f1_2 * g3 + f2 * g2 + f3_2 * g1 + f4 * g0 + f5_2 * g9_19 + f6 * g8_19 + f7_2 * g7_19 + f8 * g6_19 + f9_2 * g5_19;
    int64_t h5 = f0 * g5 + f1 * g4 + f2 * g3 + f3 * g2 + f4 * g1 + f5 * g0 + f6 * g9_19 + f7 * g8_19 + f8 * g7_19 + f9 * g6_19;
    int64_t h6 = f0 * g6 + f1_2 * g5 + f2 * g4 + f3_2 * g3 + f4 * g2 + f5_2 * g1 + f6 * g0 + f7_2 * g9_19 + f8 * g8_19 + f9_2 * g7_19;
    int64_t h7 = f0 * g7 + f1 * g6 + f2 * g5 + f3 * g4 + f4 * g3 + f5 * g2 + f6 * g1 + f7 * g0 + f8 * g9_19 + f9 * g8_19;
    int64_t h8 = f0 * g8 + f1_2 * g7 + f2 * g6 + f3_2 * g5 + f4 * g4 + f5_2 * g3 + f6 * g2 + f7_2 * g1 + f8 * g0 + f9_2 * g9_19;
    int64_t h9 = f0 * g9 + f1 * g8 + f2 * g7 + f3 * g6 + f4 * g5 + f5 * g4 + f6 * g3 + f7 * g2 + f8 * g1 + f9 * g0;
    int64_t carry;

    carry = (h0 + (((int64_t)1) << 25)) >> 26;
    h1 += carry;
    h0 -= carry << 26;
    carry = (h4 + (((int64_t)1) << 25)) >> 26;
    h5 += carry;
    h4 -= carry << 26;

    carry = (h1 + (((int64_t)1) << 24)) >> 25;
    h2 += carry;
    h1 -= carry << 25;
    carry = (h5 + (((int64_t)1) << 24)) >> 25;
    h6 += carry;
    h5 -= carry << 25;

    carry = (h2 + (((int64_t)1) << 25)) >> 26;
    h3 += carry;
    h2 -= carry << 26;
    carry = (h6 + (((int64_t)1) << 25)) >> 26;
    h7 += carry;
    h6 -= carry << 26;

    carry = (h3 + (((int64_t)1) << 24)) >> 25;
    h4 += carry;
    h3 -= carry << 25;
    carry = (h7 + (((int64_t)1) << 24)) >> 25;
    h8 += carry;
    h7 -= carry << 25;

    carry = (h4 + (((int64_t)1) << 25)) >> 26;
    h5 += carry;
    h4 -= carry << 26;
    carry = (h8 + (((int64_t)1) << 25)) >> 26;
    h9 += carry;
    h8 -= carry << 26;

    carry = (h9 + (((int64_t)1) << 24)) >> 25;
    h0 += carry * 19;
    h9 -= carry << 25;
    carry = (h0 + (((int64_t)1) << 25)) >> 26;
    h1 += carry;
    h0 -= carry << 26;

    out->v[0] = (int32_t)h0;
    out->v[1] = (int32_t)h1;
    out->v[2] = (int32_t)h2;
    out->v[3] = (int32_t)h3;
    out->v[4] = (int32_t)h4;
    out->v[5] = (int32_t)h5;
    out->v[6] = (int32_t)h6;
    out->v[7] = (int32_t)h7;
    out->v[8] = (int32_t)h8;
    out->v[9] = (int32_t)h9;
}

/**
 * @brief Square the fe25519_t.
 *
 * @param[out] out The output value.
 * @param[in] a The a value.
 */
static void fe25519_sq(fe25519_t *out, const fe25519_t *a)
{
    fe25519_mul(out, a, a);
}

/**
 * @brief Multiply the fe25519_t by a small constant.
 *
 * @param[out] out The output value.
 * @param[in] a The a value.
 * @param[in] c The c value.
 */
static void fe25519_mul_small(fe25519_t *out, const fe25519_t *a, uint32_t c)
{
    int64_t h0 = (int64_t)a->v[0] * (int64_t)c;
    int64_t h1 = (int64_t)a->v[1] * (int64_t)c;
    int64_t h2 = (int64_t)a->v[2] * (int64_t)c;
    int64_t h3 = (int64_t)a->v[3] * (int64_t)c;
    int64_t h4 = (int64_t)a->v[4] * (int64_t)c;
    int64_t h5 = (int64_t)a->v[5] * (int64_t)c;
    int64_t h6 = (int64_t)a->v[6] * (int64_t)c;
    int64_t h7 = (int64_t)a->v[7] * (int64_t)c;
    int64_t h8 = (int64_t)a->v[8] * (int64_t)c;
    int64_t h9 = (int64_t)a->v[9] * (int64_t)c;
    int64_t carry;

    carry = (h0 + (((int64_t)1) << 25)) >> 26;
    h1 += carry;
    h0 -= carry << 26;
    carry = (h4 + (((int64_t)1) << 25)) >> 26;
    h5 += carry;
    h4 -= carry << 26;

    carry = (h1 + (((int64_t)1) << 24)) >> 25;
    h2 += carry;
    h1 -= carry << 25;
    carry = (h5 + (((int64_t)1) << 24)) >> 25;
    h6 += carry;
    h5 -= carry << 25;

    carry = (h2 + (((int64_t)1) << 25)) >> 26;
    h3 += carry;
    h2 -= carry << 26;
    carry = (h6 + (((int64_t)1) << 25)) >> 26;
    h7 += carry;
    h6 -= carry << 26;

    carry = (h3 + (((int64_t)1) << 24)) >> 25;
    h4 += carry;
    h3 -= carry << 25;
    carry = (h7 + (((int64_t)1) << 24)) >> 25;
    h8 += carry;
    h7 -= carry << 25;

    carry = (h4 + (((int64_t)1) << 25)) >> 26;
    h5 += carry;
    h4 -= carry << 26;
    carry = (h8 + (((int64_t)1) << 25)) >> 26;
    h9 += carry;
    h8 -= carry << 26;

    carry = (h9 + (((int64_t)1) << 24)) >> 25;
    h0 += carry * 19;
    h9 -= carry << 25;
    carry = (h0 + (((int64_t)1) << 25)) >> 26;
    h1 += carry;
    h0 -= carry << 26;

    out->v[0] = (int32_t)h0;
    out->v[1] = (int32_t)h1;
    out->v[2] = (int32_t)h2;
    out->v[3] = (int32_t)h3;
    out->v[4] = (int32_t)h4;
    out->v[5] = (int32_t)h5;
    out->v[6] = (int32_t)h6;
    out->v[7] = (int32_t)h7;
    out->v[8] = (int32_t)h8;
    out->v[9] = (int32_t)h9;
}

/**
 * @brief Square the fe25519_t times.
 *
 * @param[out] out The output value.
 * @param[in] z The z value.
 * @param[in] count The count value.
 */
static void fe25519_sq_times(fe25519_t *out, const fe25519_t *z, uint32_t count)
{
    uint32_t i;

    fe25519_copy(out, z);
    for(i = 0U; i < count; i++) {
        fe25519_sq(out, out);
    }
}

/**
 * @brief Inverse the fe25519_t.
 *
 * @param[out] out The output value.
 * @param[in] z The z value.
 */
static void fe25519_inv(fe25519_t *out, const fe25519_t *z)
{
    fe25519_t z2;
    fe25519_t z9;
    fe25519_t z11;
    fe25519_t z2_5_0;
    fe25519_t z2_10_0;
    fe25519_t z2_20_0;
    fe25519_t z2_50_0;
    fe25519_t z2_100_0;
    fe25519_t t0;
    fe25519_t t1;

    fe25519_sq(&z2, z);
    fe25519_sq(&t0, &z2);
    fe25519_sq(&t0, &t0);
    fe25519_mul(&z9, &t0, z);
    fe25519_mul(&z11, &z9, &z2);
    fe25519_sq(&t0, &z11);
    fe25519_mul(&z2_5_0, &t0, &z9);

    fe25519_sq_times(&t0, &z2_5_0, 5U);
    fe25519_mul(&z2_10_0, &t0, &z2_5_0);

    fe25519_sq_times(&t0, &z2_10_0, 10U);
    fe25519_mul(&z2_20_0, &t0, &z2_10_0);

    fe25519_sq_times(&t0, &z2_20_0, 20U);
    fe25519_mul(&t0, &t0, &z2_20_0);

    fe25519_sq_times(&t0, &t0, 10U);
    fe25519_mul(&z2_50_0, &t0, &z2_10_0);

    fe25519_sq_times(&t0, &z2_50_0, 50U);
    fe25519_mul(&z2_100_0, &t0, &z2_50_0);

    fe25519_sq_times(&t1, &z2_100_0, 100u);
    fe25519_mul(&t1, &t1, &z2_100_0);

    fe25519_sq_times(&t1, &t1, 50U);
    fe25519_mul(&t1, &t1, &z2_50_0);

    fe25519_sq_times(&t1, &t1, 5U);
    fe25519_mul(out, &t1, &z11);
}

/**
 * @brief Scalar multiplication for X25519
 * 
 * @param k The k value
 * @param u The u value
 * @param result The result value
 * @return The return value
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t x25519_scalar_mult(const uint8_t k[NOXTLS_X25519_KEY_SIZE],
                                          const uint8_t u[NOXTLS_X25519_KEY_SIZE],
                                          uint8_t result[NOXTLS_X25519_KEY_SIZE])
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint8_t k_clamped[NOXTLS_X25519_KEY_SIZE];
    uint8_t u_masked[NOXTLS_X25519_KEY_SIZE];
    fe25519_t x1;
    fe25519_t x2;
    fe25519_t z2;
    fe25519_t x3;
    fe25519_t z3;
    fe25519_t a;
    fe25519_t aa;
    fe25519_t b;
    fe25519_t bb;
    fe25519_t e;
    fe25519_t c;
    fe25519_t d;
    fe25519_t da;
    fe25519_t cb;
    fe25519_t t0;
    fe25519_t t1;
    fe25519_t inv;
    uint8_t swap = 0U;
    int t;

    memcpy(k_clamped, k, NOXTLS_X25519_KEY_SIZE);
    memcpy(u_masked, u, NOXTLS_X25519_KEY_SIZE);
    k_clamped[0] &= (uint8_t)NOXTLS_X25519_CLAMP_BYTE0_MASK;
    k_clamped[31] &= (uint8_t)NOXTLS_X25519_CLAMP_BYTE31_AND;
    k_clamped[31] |= (uint8_t)NOXTLS_X25519_CLAMP_BYTE31_OR;
    u_masked[31] &= (uint8_t)NOXTLS_X25519_U_COORD_HIGH_CLEAR;

    fe25519_from_le(&x1, u_masked);
    fe25519_one(&x2);
    fe25519_zero(&z2);
    fe25519_copy(&x3, &x1);
    fe25519_one(&z3);

    for(t = (int)NOXTLS_X25519_SCALAR_LOOP_TOP; t >= 0; t--) {
        uint8_t k_t = (uint8_t)((k_clamped[t >> 3] >> (t & 7)) & 1U);
        swap ^= k_t;
        fe25519_cswap(swap, &x2, &x3);
        fe25519_cswap(swap, &z2, &z3);
        swap = k_t;

        fe25519_add(&a, &x2, &z2);
        fe25519_sq(&aa, &a);
        fe25519_sub(&b, &x2, &z2);
        fe25519_sq(&bb, &b);
        fe25519_sub(&e, &aa, &bb);
        fe25519_add(&c, &x3, &z3);
        fe25519_sub(&d, &x3, &z3);
        fe25519_mul(&da, &d, &a);
        fe25519_mul(&cb, &c, &b);
        fe25519_add(&t0, &da, &cb);
        fe25519_sub(&t1, &da, &cb);
        fe25519_sq(&x3, &t0);
        fe25519_sq(&t0, &t1);
        fe25519_mul(&z3, &x1, &t0);
        fe25519_mul(&x2, &aa, &bb);
        fe25519_mul_small(&t0, &e, 121665u);
        fe25519_add(&t0, &aa, &t0);
        fe25519_mul(&z2, &e, &t0);
    }

    fe25519_cswap(swap, &x2, &x3);
    fe25519_cswap(swap, &z2, &z3);

    fe25519_inv(&inv, &z2);
    fe25519_mul(&x2, &x2, &inv);
    fe25519_to_le(result, &x2);
    return NOXTLS_RETURN_SUCCESS;
}

#endif

/**
 * @brief Applies RFC 7748 clamping to a 32-byte X25519 scalar in place.
 * @param[in,out] k Little-endian scalar (`NOXTLS_X25519_KEY_SIZE` bytes); no-op if NULL.
 * @return None.
 */
void noxtls_x25519_clamp_scalar(uint8_t k[NOXTLS_X25519_KEY_SIZE])
{
    if(k == NULL) {
        return;
    }
    k[0] &= (uint8_t)NOXTLS_X25519_CLAMP_BYTE0_MASK;
    k[NOXTLS_X25519_FE_BYTES - 1U] &= (uint8_t)NOXTLS_X25519_CLAMP_BYTE31_AND;
    k[NOXTLS_X25519_FE_BYTES - 1U] |= (uint8_t)NOXTLS_X25519_CLAMP_BYTE31_OR;
}

/**
 * @brief Derives the X25519 public key from a private key (RFC 7748, base u = 9).
 * @param[in]  private_key 32-byte little-endian private key.
 * @param[out] public_key 32-byte little-endian public u-coordinate.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_x25519_public_key(const uint8_t private_key[NOXTLS_X25519_KEY_SIZE],
                                         uint8_t public_key[NOXTLS_X25519_KEY_SIZE])
{
    static const uint8_t base_point[NOXTLS_X25519_KEY_SIZE] = {
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    if(private_key == NULL || public_key == NULL) return NOXTLS_RETURN_NULL;
    return x25519_scalar_mult(private_key, base_point, public_key);
}

/**
 * @brief Computes X25519 shared secret from own private key and peer public key (RFC 7748).
 * @param[in]  private_key 32-byte little-endian private key.
 * @param[in]  peer_public_key 32-byte little-endian peer public u-coordinate.
 * @param[out] shared_secret 32-byte little-endian shared secret output.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_x25519_shared_secret(const uint8_t private_key[NOXTLS_X25519_KEY_SIZE],
                                            const uint8_t peer_public_key[NOXTLS_X25519_KEY_SIZE],
                                            uint8_t shared_secret[NOXTLS_X25519_KEY_SIZE])
{
    if(private_key == NULL || peer_public_key == NULL || shared_secret == NULL) return NOXTLS_RETURN_NULL;
    return x25519_scalar_mult(private_key, peer_public_key, shared_secret);
}

/**
 * @brief Generates a random X25519 key pair using the library DRBG (RFC 7748).
 * @param[out] private_key 32-byte little-endian private key (clamped internally).
 * @param[out] public_key 32-byte little-endian public key.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_x25519_generate_key(uint8_t private_key[NOXTLS_X25519_KEY_SIZE],
                                           uint8_t public_key[NOXTLS_X25519_KEY_SIZE])
{
    static drbg_state_t drbg_state;
    static int drbg_initialized = 0;
    noxtls_return_t rc;

    if(private_key == NULL || public_key == NULL) return NOXTLS_RETURN_NULL;

    if(!drbg_initialized) {
        uint8_t seed[NOXTLS_X25519_DRBG_ENTROPY_SEED_BYTES];
        rc = noxtls_drbg_get_entropy(seed, sizeof(seed));
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        rc = drbg_instantiate(&drbg_state, DRBG_AES256, seed, sizeof(seed), NULL, 0, NULL, 0);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        drbg_initialized = 1;
    }

    rc = drbg_generate(&drbg_state, private_key, NOXTLS_X25519_DRBG_SEED_BITS, NULL, 0);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;

    noxtls_x25519_clamp_scalar(private_key);
    return noxtls_x25519_public_key(private_key, public_key);
}
