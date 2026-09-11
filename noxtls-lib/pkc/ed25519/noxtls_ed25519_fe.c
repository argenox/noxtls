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
* File:    noxtls_ed25519_fe.c
* Summary: Native GF(2^255-19) field arithmetic for Ed25519
*
*
*****************************************************************************/

/**
 * @file noxtls_ed25519_fe.c
 * @brief Native limb field-element operations for Ed25519 (RFC 8032).
 * @ingroup noxtls_ed25519
 */

#include <string.h>

#include "noxtls_ed25519_fe.h"

/**
 * @brief Swap endianness of a 32-byte field element (LE <-> BE).
 * @internal
 *
 * @param[out] dst Destination bytes.
 * @param[in] src Source bytes.
 */
static void fe25519_swap_endian32(uint8_t dst[NOXTLS_ED25519_FE25519_BYTES],
                                  const uint8_t src[NOXTLS_ED25519_FE25519_BYTES])
{
    uint32_t i;
    for(i = 0U; i < NOXTLS_ED25519_FE25519_BYTES; i++) {
        dst[i] = src[NOXTLS_ED25519_FE25519_BYTES - 1U - i];
    }
}

static uint32_t fe25519_load32_le(const uint8_t *src)
{
    return ((uint32_t)src[0]) |
           ((uint32_t)src[1] << 8) |
           ((uint32_t)src[2] << 16) |
           ((uint32_t)src[3] << 24);
}

/**
 * @brief Load 24 bits from a little-endian source.
 */
static uint32_t fe25519_load24_le(const uint8_t *src)
{
    return ((uint32_t)src[0]) |
           ((uint32_t)src[1] << 8) |
           ((uint32_t)src[2] << 16);
}

void fe25519_native_copy(fe25519_native_t *dst, const fe25519_native_t *src)
{
    memcpy(dst, src, sizeof(*dst));
}

void fe25519_native_zero(fe25519_native_t *a)
{
    memset(a, 0, sizeof(*a));
}

void fe25519_native_from_le(fe25519_native_t *out, const uint8_t in[NOXTLS_ED25519_FE25519_BYTES])
{
    int64_t h0 = (int64_t)fe25519_load32_le(in);
    int64_t h1 = (int64_t)fe25519_load24_le(in + 4U) << 6;
    int64_t h2 = (int64_t)fe25519_load24_le(in + 7U) << 5;
    int64_t h3 = (int64_t)fe25519_load24_le(in + 10U) << 3;
    int64_t h4 = (int64_t)fe25519_load24_le(in + 13U) << 2;
    int64_t h5 = (int64_t)fe25519_load32_le(in + 16U);
    int64_t h6 = (int64_t)fe25519_load24_le(in + 20U) << 7;
    int64_t h7 = (int64_t)fe25519_load24_le(in + 23U) << 5;
    int64_t h8 = (int64_t)fe25519_load24_le(in + 26U) << 4;
    int64_t h9 = (int64_t)(fe25519_load24_le(in + 29U) & 0x7FFFFFU) << 2;
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

void fe25519_native_to_le(uint8_t out[NOXTLS_ED25519_FE25519_BYTES], const fe25519_native_t *in)
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

    q = ((19 * h9) + (((int64_t)1) << 24)) >> 25;
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
}

void fe25519_native_add(fe25519_native_t *out, const fe25519_native_t *a, const fe25519_native_t *b)
{
    uint32_t i;
    for(i = 0; i < 10U; i++) {
        out->v[i] = a->v[i] + b->v[i];
    }
}

void fe25519_native_sub(fe25519_native_t *out, const fe25519_native_t *a, const fe25519_native_t *b)
{
    uint32_t i;
    for(i = 0; i < 10U; i++) {
        out->v[i] = a->v[i] - b->v[i];
    }
}

void fe25519_native_mul(fe25519_native_t *out, const fe25519_native_t *a, const fe25519_native_t *b)
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
    int64_t h0 = (f0 * g0) + (f1_2 * g9_19) + (f2 * g8_19) + (f3_2 * g7_19) + (f4 * g6_19) + (f5_2 * g5_19) + (f6 * g4_19) + (f7_2 * g3_19) + (f8 * g2_19) + (f9_2 * g1_19);
    int64_t h1 = (f0 * g1) + (f1 * g0) + (f2 * g9_19) + (f3 * g8_19) + (f4 * g7_19) + (f5 * g6_19) + (f6 * g5_19) + (f7 * g4_19) + (f8 * g3_19) + (f9 * g2_19);
    int64_t h2 = (f0 * g2) + (f1_2 * g1) + (f2 * g0) + (f3_2 * g9_19) + (f4 * g8_19) + (f5_2 * g7_19) + (f6 * g6_19) + (f7_2 * g5_19) + (f8 * g4_19) + (f9_2 * g3_19);
    int64_t h3 = (f0 * g3) + (f1 * g2) + (f2 * g1) + (f3 * g0) + (f4 * g9_19) + (f5 * g8_19) + (f6 * g7_19) + (f7 * g6_19) + (f8 * g5_19) + (f9 * g4_19);
    int64_t h4 = (f0 * g4) + (f1_2 * g3) + (f2 * g2) + (f3_2 * g1) + (f4 * g0) + (f5_2 * g9_19) + (f6 * g8_19) + (f7_2 * g7_19) + (f8 * g6_19) + (f9_2 * g5_19);
    int64_t h5 = (f0 * g5) + (f1 * g4) + (f2 * g3) + (f3 * g2) + (f4 * g1) + (f5 * g0) + (f6 * g9_19) + (f7 * g8_19) + (f8 * g7_19) + (f9 * g6_19);
    int64_t h6 = (f0 * g6) + (f1_2 * g5) + (f2 * g4) + (f3_2 * g3) + (f4 * g2) + (f5_2 * g1) + (f6 * g0) + (f7_2 * g9_19) + (f8 * g8_19) + (f9_2 * g7_19);
    int64_t h7 = (f0 * g7) + (f1 * g6) + (f2 * g5) + (f3 * g4) + (f4 * g3) + (f5 * g2) + (f6 * g1) + (f7 * g0) + (f8 * g9_19) + (f9 * g8_19);
    int64_t h8 = (f0 * g8) + (f1_2 * g7) + (f2 * g6) + (f3_2 * g5) + (f4 * g4) + (f5_2 * g3) + (f6 * g2) + (f7_2 * g1) + (f8 * g0) + (f9_2 * g9_19);
    int64_t h9 = (f0 * g9) + (f1 * g8) + (f2 * g7) + (f3 * g6) + (f4 * g5) + (f5 * g4) + (f6 * g3) + (f7 * g2) + (f8 * g1) + (f9 * g0);
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

void fe25519_native_sq(fe25519_native_t *out, const fe25519_native_t *a)
{
    fe25519_native_mul(out, a, a);
}

static void fe25519_native_sq_times(fe25519_native_t *out, const fe25519_native_t *z, uint32_t count)
{
    uint32_t i;
    fe25519_native_copy(out, z);
    for(i = 0; i < count; i++) {
        fe25519_native_sq(out, out);
    }
}

void fe25519_native_inv(fe25519_native_t *out, const fe25519_native_t *z)
{
    fe25519_native_t z2;
    fe25519_native_t z9;
    fe25519_native_t z11;
    fe25519_native_t z2_5_0;
    fe25519_native_t z2_10_0;
    fe25519_native_t z2_20_0;
    fe25519_native_t z2_50_0;
    fe25519_native_t z2_100_0;
    fe25519_native_t t0;
    fe25519_native_t t1;

    fe25519_native_sq(&z2, z);
    fe25519_native_sq(&t0, &z2);
    fe25519_native_sq(&t0, &t0);
    fe25519_native_mul(&z9, &t0, z);
    fe25519_native_mul(&z11, &z9, &z2);
    fe25519_native_sq(&t0, &z11);
    fe25519_native_mul(&z2_5_0, &t0, &z9);

    fe25519_native_sq_times(&t0, &z2_5_0, 5U);
    fe25519_native_mul(&z2_10_0, &t0, &z2_5_0);

    fe25519_native_sq_times(&t0, &z2_10_0, 10U);
    fe25519_native_mul(&z2_20_0, &t0, &z2_10_0);

    fe25519_native_sq_times(&t0, &z2_20_0, 20U);
    fe25519_native_mul(&t0, &t0, &z2_20_0);

    fe25519_native_sq_times(&t0, &t0, 10U);
    fe25519_native_mul(&z2_50_0, &t0, &z2_10_0);

    fe25519_native_sq_times(&t0, &z2_50_0, 50U);
    fe25519_native_mul(&z2_100_0, &t0, &z2_50_0);

    fe25519_native_sq_times(&t1, &z2_100_0, 100U);
    fe25519_native_mul(&t1, &t1, &z2_100_0);

    fe25519_native_sq_times(&t1, &t1, 50U);
    fe25519_native_mul(&t1, &t1, &z2_50_0);

    fe25519_native_sq_times(&t1, &t1, 5U);
    fe25519_native_mul(out, &t1, &z11);
}

void fe25519_native_from_be(fe25519_native_t *out, const uint8_t be[NOXTLS_ED25519_FE25519_BYTES])
{
    uint8_t le[NOXTLS_ED25519_FE25519_BYTES];
    fe25519_swap_endian32(le, be);
    fe25519_native_from_le(out, le);
}

void fe25519_native_to_be(uint8_t be[NOXTLS_ED25519_FE25519_BYTES], const fe25519_native_t *in)
{
    uint8_t le[NOXTLS_ED25519_FE25519_BYTES];
    fe25519_native_to_le(le, in);
    fe25519_swap_endian32(be, le);
}


/**
 * @brief Set a native field element to one.
 *
 * @param[out] a Element to set.
 */
void fe25519_native_one(fe25519_native_t *a)
{
    fe25519_native_zero(a);
    a->v[0] = 1;
}

/**
 * @brief Field negation: out = -a.
 *
 * @param[out] out Negated value.
 * @param[in] a Input.
 */
void fe25519_native_neg(fe25519_native_t *out, const fe25519_native_t *a)
{
    uint32_t i;
    for(i = 0U; i < NOXTLS_ED25519_FE_LIMBS; i++) {
        out->v[i] = -a->v[i];
    }
}

/**
 * @brief Compute out = z^((p-5)/8) via ref10-style addition chain (RFC 8032 §5.1.3).
 *
 * @param[out] out Power.
 * @param[in] z Input.
 */
void fe25519_native_pow22523(fe25519_native_t *out, const fe25519_native_t *z)
{
    fe25519_native_t t0;
    fe25519_native_t t1;
    fe25519_native_t t2;
    uint32_t i;

    /* Addition chain from SUPERCOP/ref10 fe_pow22523. */
    fe25519_native_sq(&t0, z);
    fe25519_native_sq(&t1, &t0);
    fe25519_native_sq(&t1, &t1);
    fe25519_native_mul(&t1, z, &t1);
    fe25519_native_mul(&t0, &t0, &t1);
    fe25519_native_sq(&t0, &t0);
    fe25519_native_mul(&t0, &t1, &t0);
    fe25519_native_sq(&t1, &t0);
    for(i = 1U; i < 5U; i++) {
        fe25519_native_sq(&t1, &t1);
    }
    fe25519_native_mul(&t0, &t1, &t0);
    fe25519_native_sq(&t1, &t0);
    for(i = 1U; i < 10U; i++) {
        fe25519_native_sq(&t1, &t1);
    }
    fe25519_native_mul(&t1, &t1, &t0);
    fe25519_native_sq(&t2, &t1);
    for(i = 1U; i < 20U; i++) {
        fe25519_native_sq(&t2, &t2);
    }
    fe25519_native_mul(&t1, &t2, &t1);
    fe25519_native_sq(&t1, &t1);
    for(i = 1U; i < 10U; i++) {
        fe25519_native_sq(&t1, &t1);
    }
    fe25519_native_mul(&t0, &t1, &t0);
    fe25519_native_sq(&t1, &t0);
    for(i = 1U; i < 50U; i++) {
        fe25519_native_sq(&t1, &t1);
    }
    fe25519_native_mul(&t1, &t1, &t0);
    fe25519_native_sq(&t2, &t1);
    for(i = 1U; i < 100U; i++) {
        fe25519_native_sq(&t2, &t2);
    }
    fe25519_native_mul(&t1, &t2, &t1);
    fe25519_native_sq(&t1, &t1);
    for(i = 1U; i < 50U; i++) {
        fe25519_native_sq(&t1, &t1);
    }
    fe25519_native_mul(&t0, &t1, &t0);
    fe25519_native_sq(&t0, &t0);
    fe25519_native_sq(&t0, &t0);
    fe25519_native_mul(out, &t0, z);
}

/**
 * @brief Constant-time conditional move: if b != 0 then f = g.
 *
 * @param[in,out] f Destination (unchanged when @p b is 0).
 * @param[in] g Source.
 * @param[in] b Selector bit (0 or 1).
 */
void fe25519_native_cmov(fe25519_native_t *f, const fe25519_native_t *g, unsigned int b)
{
    uint32_t i;
    int32_t mask = -(int32_t)(b & 1U);
    for(i = 0U; i < NOXTLS_ED25519_FE_LIMBS; i++) {
        f->v[i] ^= mask & (f->v[i] ^ g->v[i]);
    }
}

/**
 * @brief Return the least significant bit of the canonical representative.
 *
 * @param[in] f Field element.
 *
 * @return 0 or 1.
 */
unsigned int fe25519_native_isnegative(const fe25519_native_t *f)
{
    uint8_t s[NOXTLS_ED25519_FE25519_BYTES];
    fe25519_native_to_le(s, f);
    return (unsigned int)(s[0] & 1U);
}

/**
 * @brief Constant-time zero test after canonicalization.
 *
 * @param[in] f Field element.
 *
 * @return 1 if zero, else 0.
 */
unsigned int fe25519_native_iszero(const fe25519_native_t *f)
{
    uint8_t s[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t acc = 0U;
    uint32_t i;
    fe25519_native_to_le(s, f);
    for(i = 0U; i < NOXTLS_ED25519_FE25519_BYTES; i++) {
        acc |= s[i];
    }
    return (unsigned int)(((uint32_t)acc - 1U) >> 31);
}

/**
 * @brief Compare two field elements for equality after canonicalization.
 *
 * @param[in] a First element.
 * @param[in] b Second element.
 *
 * @return 1 if equal, else 0.
 */
unsigned int fe25519_native_equal(const fe25519_native_t *a, const fe25519_native_t *b)
{
    uint8_t sa[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t sb[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t acc = 0U;
    uint32_t i;
    fe25519_native_to_le(sa, a);
    fe25519_native_to_le(sb, b);
    for(i = 0U; i < NOXTLS_ED25519_FE25519_BYTES; i++) {
        acc |= (uint8_t)(sa[i] ^ sb[i]);
    }
    return (unsigned int)(((uint32_t)acc - 1U) >> 31);
}
