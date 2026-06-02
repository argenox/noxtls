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
* File:    noxtls_ed25519.c
* Summary: Ed25519 digital signatures (RFC 8032)
*
*
*****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "common/noxtls_ct.h"
#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "drbg/noxtls_drbg.h"
#include "mdigest/sha512/noxtls_sha512.h"
#include "noxtls_common.h"
#include "noxtls_ed25519.h"

/* p = 2^255 - 19 (same as Curve25519), big-endian */
static const uint8_t ed25519_p[NOXTLS_ED25519_FE25519_BYTES] = {
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xED
};

/* L = order of base point = 2^252 + 27742317777372353535851937790883648493, big-endian */
static const uint8_t ed25519_L[NOXTLS_ED25519_FE25519_BYTES] = {
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xDE, 0xF9, 0xDE, 0xA2, 0xF7, 0x9C, 0xD6,
    0x58, 0x12, 0x63, 0x1A, 0x5C, 0xF5, 0xD3, 0xED
};

/* d = -121665/121666 mod p (twisted Edwards curve), big-endian */
static const uint8_t ed25519_d[NOXTLS_ED25519_FE25519_BYTES] = {
    0x52, 0x03, 0x6C, 0xEE, 0x2B, 0x6F, 0xFE, 0x73,
    0x8C, 0xC7, 0x40, 0x79, 0x77, 0x79, 0xE8, 0x98,
    0x00, 0x70, 0x0A, 0x4D, 0x41, 0x41, 0xD8, 0xAB,
    0x75, 0xEB, 0x4D, 0xCA, 0x13, 0x59, 0x78, 0xA3
};

/* Base point B encoding (32 bytes LE) per RFC 8032: y with LSB(x) in high bit of last octet */
static const uint8_t ed25519_B_encoded[NOXTLS_ED25519_FE25519_BYTES] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
};

/* Base point affine coordinates in big-endian (reserved for future use). */
static const uint8_t ed25519_B_x_be[NOXTLS_ED25519_FE25519_BYTES] NOXTLS_UNUSED_ATTR = {
    0x21, 0x69, 0x36, 0xD3, 0xCD, 0x6E, 0x53, 0xFE,
    0xC0, 0xA4, 0xE2, 0x31, 0xFD, 0xD6, 0xDC, 0x5C,
    0x69, 0x2C, 0xC7, 0x60, 0x95, 0x25, 0xA7, 0xB2,
    0xC9, 0x56, 0x2D, 0x60, 0x8F, 0x25, 0xD5, 0x1A
};
static const uint8_t ed25519_B_y_be[NOXTLS_ED25519_FE25519_BYTES] NOXTLS_UNUSED_ATTR = {
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x58
};

/**
 * @brief Converts a 255-bit field element from little-endian to big-endian field helpers.
 * @param[out] be Big-endian output (`NOXTLS_ED25519_FE25519_BYTES` bytes).
 * @param[in]  le Little-endian input (`NOXTLS_ED25519_FE25519_BYTES` bytes).
 * @return None.
 */
static void le32_to_be32(uint8_t be[NOXTLS_ED25519_FE25519_BYTES], const uint8_t le[NOXTLS_ED25519_FE25519_BYTES])
{
    for(int i = 0; i < (int)NOXTLS_ED25519_FE25519_BYTES; i++) be[i] = le[(int)NOXTLS_ED25519_FE25519_BYTES - 1 - i];
}

/**
 * @brief Converts a 255-bit field element from big-endian to little-endian wire encoding.
 * @param[out] le Little-endian output (`NOXTLS_ED25519_FE25519_BYTES` bytes).
 * @param[in]  be Big-endian input (`NOXTLS_ED25519_FE25519_BYTES` bytes).
 * @return None.
 */
static void be32_to_le32(uint8_t le[NOXTLS_ED25519_FE25519_BYTES], const uint8_t be[NOXTLS_ED25519_FE25519_BYTES])
{
    for(int i = 0; i < (int)NOXTLS_ED25519_FE25519_BYTES; i++) le[i] = be[(int)NOXTLS_ED25519_FE25519_BYTES - 1 - i];
}

static int ed25519_cmp_be(const uint8_t *a, const uint8_t *b, uint32_t len)
{
    for(uint32_t i = 0; i < len; i++) {
        if(a[i] != b[i]) {
            return (a[i] > b[i]) ? 1 : -1;
        }
    }
    return 0;
}

/**
 * @brief Load 32 bits from a little-endian source.
 */
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

typedef struct {
    int32_t v[10];
} fe25519_native_t;

static void fe25519_native_copy(fe25519_native_t *dst, const fe25519_native_t *src)
{
    memcpy(dst, src, sizeof(*dst));
}

static void fe25519_native_zero(fe25519_native_t *a)
{
    memset(a, 0, sizeof(*a));
}

static void fe25519_native_from_le(fe25519_native_t *out, const uint8_t in[32])
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
    int64_t h9 = (int64_t)(fe25519_load24_le(in + 29U) & 0x7FFFFFu) << 2;
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

static void fe25519_native_to_le(uint8_t out[32], const fe25519_native_t *in)
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
}

static void fe25519_native_add(fe25519_native_t *out, const fe25519_native_t *a, const fe25519_native_t *b)
{
    uint32_t i;
    for(i = 0; i < 10U; i++) {
        out->v[i] = a->v[i] + b->v[i];
    }
}

static void fe25519_native_sub(fe25519_native_t *out, const fe25519_native_t *a, const fe25519_native_t *b)
{
    uint32_t i;
    for(i = 0; i < 10U; i++) {
        out->v[i] = a->v[i] - b->v[i];
    }
}

static void fe25519_native_mul(fe25519_native_t *out, const fe25519_native_t *a, const fe25519_native_t *b)
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

static void fe25519_native_sq(fe25519_native_t *out, const fe25519_native_t *a)
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

static void fe25519_native_inv(fe25519_native_t *out, const fe25519_native_t *z)
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

static void fe25519_native_from_be(fe25519_native_t *out, const uint8_t be[NOXTLS_ED25519_FE25519_BYTES])
{
    uint8_t le[NOXTLS_ED25519_FE25519_BYTES];
    be32_to_le32(le, be);
    fe25519_native_from_le(out, le);
}

static void fe25519_native_to_be(uint8_t be[NOXTLS_ED25519_FE25519_BYTES], const fe25519_native_t *in)
{
    uint8_t le[NOXTLS_ED25519_FE25519_BYTES];
    fe25519_native_to_le(le, in);
    le32_to_be32(be, le);
}

static noxtls_return_t ed25519_sub_be(uint8_t *r, const uint8_t *a, const uint8_t *b, uint32_t len)
{
    int32_t borrow = 0;

    if(r == NULL || a == NULL || b == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    for(int32_t i = (int32_t)len - 1; i >= 0; i--) {
        int32_t v = (int32_t)a[i] - (int32_t)b[i] - borrow;
        if(v < 0) {
            v += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        r[i] = (uint8_t)v;
    }

    return (borrow == 0) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
}

static void ed25519_set_zero(uint8_t *a, uint32_t len)
{
    if(a == NULL) {
        return;
    }
    memset(a, 0, len);
}

static void ed25519_set_one_be32(uint8_t a[NOXTLS_ED25519_FE25519_BYTES])
{
    if(a == NULL) {
        return;
    }
    memset(a, 0, NOXTLS_ED25519_FE25519_BYTES);
    a[NOXTLS_ED25519_FE25519_BYTES - 1U] = 1U;
}

static noxtls_return_t ed25519_mod_reduce_be(const uint8_t *input,
                                             uint32_t input_len,
                                             const uint8_t mod[NOXTLS_ED25519_FE25519_BYTES],
                                             uint8_t out[NOXTLS_ED25519_FE25519_BYTES])
{
    uint8_t rem[33];
    uint8_t mod33[33];
    uint8_t tmp[33];

    if(input == NULL || mod == NULL || out == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    memset(rem, 0, sizeof(rem));
    memset(mod33, 0, sizeof(mod33));
    memcpy(&mod33[1], mod, NOXTLS_ED25519_FE25519_BYTES);

    for(uint32_t i = 0; i < input_len; i++) {
        memmove(rem, rem + 1, sizeof(rem) - 1U);
        rem[sizeof(rem) - 1U] = input[i];
        while(ed25519_cmp_be(rem, mod33, sizeof(rem)) >= 0) {
            if(ed25519_sub_be(tmp, rem, mod33, sizeof(rem)) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_FAILED;
            }
            memcpy(rem, tmp, sizeof(rem));
        }
    }

    memcpy(out, &rem[1], NOXTLS_ED25519_FE25519_BYTES);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Debug helper: prints a 32-byte value as hex to stderr (development builds).
 * @param[in] label NUL-terminated label printed before the hex digits.
 * @param[in] v     32-byte buffer to dump.
 * @return None.
 */
#ifndef NDEBUG
static void ed25519_dbg_hex32(const char *label, const uint8_t v[NOXTLS_ED25519_FE25519_BYTES])
{
    fprintf(stderr, "%s=", label);
    for(int i = 0; i < (int)NOXTLS_ED25519_FE25519_BYTES; i++) {
        fprintf(stderr, "%02x", v[i]);
    }
    fprintf(stderr, "\n");
}
#endif

/**
 * @brief Debug helper: prints a 64-byte value as hex to stderr (development builds).
 * @param[in] label NUL-terminated label printed before the hex digits.
 * @param[in] v     64-byte buffer to dump.
 * @return None.
 */
#ifndef NDEBUG
static void ed25519_dbg_hex64(const char *label, const uint8_t v[NOXTLS_ED25519_SHA512_DIGEST_BYTES])
{
    fprintf(stderr, "%s=", label);
    for(int i = 0; i < (int)NOXTLS_ED25519_SHA512_DIGEST_BYTES; i++) {
        fprintf(stderr, "%02x", v[i]);
    }
    fprintf(stderr, "\n");
}
#endif

/**
 * @brief Field addition in GF(p), p = 2^255 - 19; operands and result are 32-byte big-endian.
 * @param[out] r Sum (a + b) mod p.
 * @param[in]  a First operand (`NOXTLS_ED25519_FE25519_BYTES` bytes).
 * @param[in]  b Second operand (`NOXTLS_ED25519_FE25519_BYTES` bytes).
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
static noxtls_return_t fe25519_add(uint8_t r[NOXTLS_ED25519_FE25519_BYTES], const uint8_t a[NOXTLS_ED25519_FE25519_BYTES], const uint8_t b[NOXTLS_ED25519_FE25519_BYTES])
{
    fe25519_native_t x;
    fe25519_native_t y;
    fe25519_native_t z;
    fe25519_native_from_be(&x, a);
    fe25519_native_from_be(&y, b);
    fe25519_native_add(&z, &x, &y);
    fe25519_native_to_be(r, &z);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Field subtraction in GF(p): r = (a - b) mod p.
 * @param[out] r Difference mod p.
 * @param[in]  a Minuend (`NOXTLS_ED25519_FE25519_BYTES` bytes).
 * @param[in]  b Subtrahend (`NOXTLS_ED25519_FE25519_BYTES` bytes).
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
static noxtls_return_t fe25519_sub(uint8_t r[NOXTLS_ED25519_FE25519_BYTES], const uint8_t a[NOXTLS_ED25519_FE25519_BYTES], const uint8_t b[NOXTLS_ED25519_FE25519_BYTES])
{
    fe25519_native_t x;
    fe25519_native_t y;
    fe25519_native_t z;
    fe25519_native_from_be(&x, a);
    fe25519_native_from_be(&y, b);
    fe25519_native_sub(&z, &x, &y);
    fe25519_native_to_be(r, &z);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Field multiplication in GF(p): r = (a * b) mod p.
 * @param[out] r Product mod p.
 * @param[in]  a First factor (`NOXTLS_ED25519_FE25519_BYTES` bytes).
 * @param[in]  b Second factor (`NOXTLS_ED25519_FE25519_BYTES` bytes).
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
static noxtls_return_t fe25519_mul(uint8_t r[NOXTLS_ED25519_FE25519_BYTES], const uint8_t a[NOXTLS_ED25519_FE25519_BYTES], const uint8_t b[NOXTLS_ED25519_FE25519_BYTES])
{
    fe25519_native_t x;
    fe25519_native_t y;
    fe25519_native_t z;
    fe25519_native_from_be(&x, a);
    fe25519_native_from_be(&y, b);
    fe25519_native_mul(&z, &x, &y);
    fe25519_native_to_be(r, &z);
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t fe25519_pow(uint8_t r[NOXTLS_ED25519_FE25519_BYTES],
                                   const uint8_t a[NOXTLS_ED25519_FE25519_BYTES],
                                   const uint8_t exp_be[NOXTLS_ED25519_FE25519_BYTES])
{
    uint8_t result[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t base[NOXTLS_ED25519_FE25519_BYTES];

    ed25519_set_one_be32(result);
    memcpy(base, a, NOXTLS_ED25519_FE25519_BYTES);

    for(uint32_t i = 0; i < NOXTLS_ED25519_FE25519_BYTES; i++) {
        uint8_t bits = exp_be[i];
        for(uint32_t bit = 0; bit < 8U; bit++) {
            if(fe25519_mul(result, result, result) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_FAILED;
            }
            if((bits & 0x80U) != 0U) {
                if(fe25519_mul(result, result, base) != NOXTLS_RETURN_SUCCESS) {
                    return NOXTLS_RETURN_FAILED;
                }
            }
            bits <<= 1U;
        }
    }

    memcpy(r, result, NOXTLS_ED25519_FE25519_BYTES);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Multiplicative inverse in GF(p): r = a^(-1) mod p (Fermat's little theorem).
 * @param[out] r Inverse of @p a mod p.
 * @param[in]  a Non-zero field element (`NOXTLS_ED25519_FE25519_BYTES` bytes).
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
static noxtls_return_t fe25519_inv(uint8_t r[NOXTLS_ED25519_FE25519_BYTES], const uint8_t a[NOXTLS_ED25519_FE25519_BYTES])
{
    fe25519_native_t x;
    fe25519_native_t z;
    fe25519_native_from_be(&x, a);
    fe25519_native_inv(&z, &x);
    fe25519_native_to_be(r, &z);
    return NOXTLS_RETURN_SUCCESS;
}

/* 2^((p-1)/4) mod p for p = 2^255-19 (for sqrt when x^2 = -a) */
static const uint8_t ed25519_sqrt_minus1[NOXTLS_ED25519_FE25519_BYTES] = {
    0x2b, 0x83, 0x24, 0x80, 0x4f, 0xc1, 0xdf, 0x0b,
    0x2b, 0x4d, 0x00, 0x99, 0x3d, 0xfb, 0xd7, 0xa7,
    0x2f, 0x43, 0x18, 0x06, 0xad, 0x2f, 0xe4, 0x78,
    0xc4, 0xee, 0x1b, 0x27, 0x4a, 0x0e, 0xa0, 0xb0
};

/**
 * @brief Square root in GF(p) when it exists (p = 5 mod 8 method per RFC 8032).
 * @param[out] r A root such that r^2 ≡ a (mod p) when successful.
 * @param[in]  a Field element (`NOXTLS_ED25519_FE25519_BYTES` bytes).
 * @return `NOXTLS_RETURN_SUCCESS` if a square root was found, or another `noxtls_return_t` on failure.
 */
NOXTLS_UNUSED_ATTR
static noxtls_return_t fe25519_sqrt(uint8_t r[NOXTLS_ED25519_FE25519_BYTES], const uint8_t a[NOXTLS_ED25519_FE25519_BYTES])
{
    uint8_t p38[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t x[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t x2[NOXTLS_ED25519_FE25519_BYTES];
    /* (p+3)/8 = 2^252 - 2 in BE */
    memset(p38, 0xFF, NOXTLS_ED25519_FE25519_BYTES);
    p38[0] = 0x0F;
    p38[NOXTLS_ED25519_FE25519_BYTES - 1U] = 0xFE;
    if(fe25519_pow(x, a, p38) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_mul(x2, x, x) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(ed25519_cmp_be(x2, a, NOXTLS_ED25519_FE25519_BYTES) == 0) { memcpy(r, x, NOXTLS_ED25519_FE25519_BYTES); return NOXTLS_RETURN_SUCCESS; }
    /* x^2 = -a: then x * 2^((p-1)/4) is a square root of a */
    fe25519_mul(x2, x, (const uint8_t *)ed25519_sqrt_minus1);
    memcpy(r, x2, NOXTLS_ED25519_FE25519_BYTES);
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t ge25519_decode(ge25519_pt_t *p, const uint8_t enc[NOXTLS_ED25519_FE25519_BYTES]);

/**
 * @brief Loads the RFC 8032 base point B into extended homogeneous coordinates.
 * @param[out] p Destination point; undefined on failure.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
static noxtls_return_t ge25519_set_basepoint(ge25519_pt_t *p)
{
    if(p == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    /* Canonical RFC8032 basepoint encoding -> point. */
    return ge25519_decode(p, ed25519_B_encoded);
}

/**
 * @brief Sets an extended point to the neutral element (identity) of the curve group.
 * @param[out] p Point to zero.
 * @return None.
 */
static void ge25519_pt_zero(ge25519_pt_t *p)
{
    ed25519_set_zero(p->X, NOXTLS_ED25519_FE25519_BYTES);
    ed25519_set_one_be32(p->Y);
    ed25519_set_one_be32(p->Z);
    ed25519_set_zero(p->T, NOXTLS_ED25519_FE25519_BYTES);
}

/**
 * @brief Extended homogeneous point addition (RFC 8032 §5.1.4, a = -1).
 * @param[out] r Sum p + q in extended coordinates.
 * @param[in]  p First summand.
 * @param[in]  q Second summand.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
static noxtls_return_t ge25519_add(ge25519_pt_t *r, const ge25519_pt_t *p, const ge25519_pt_t *q)
{
    uint8_t A[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t B[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t C[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t D[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t E[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t F[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t G[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t H[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t t0[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t t1[NOXTLS_ED25519_FE25519_BYTES];

    if(fe25519_sub(t0, p->Y, p->X) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_sub(t1, q->Y, q->X) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_mul(A, t0, t1) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    if(fe25519_add(t0, p->Y, p->X) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_add(t1, q->Y, q->X) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_mul(B, t0, t1) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    if(fe25519_mul(C, p->T, q->T) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_mul(C, C, ed25519_d) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_add(C, C, C) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    if(fe25519_mul(D, p->Z, q->Z) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_add(D, D, D) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    if(fe25519_sub(E, B, A) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_sub(F, D, C) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_add(G, D, C) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_add(H, B, A) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    if(fe25519_mul(r->X, E, F) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_mul(r->Y, G, H) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_mul(r->T, E, H) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_mul(r->Z, F, G) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Point doubling via addition with self (RFC 8032 extended coordinates).
 * @param[out] r Double of @p p.
 * @param[in]  p Input point.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
static noxtls_return_t ge25519_dbl(ge25519_pt_t *r, const ge25519_pt_t *p)
{
    uint8_t A[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t B[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t C[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t D[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t E[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t F[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t G[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t H[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t t0[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t zero[NOXTLS_ED25519_FE25519_BYTES];

    ed25519_set_zero(zero, sizeof(zero));

    if(fe25519_mul(A, p->X, p->X) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_mul(B, p->Y, p->Y) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_mul(C, p->Z, p->Z) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_add(C, C, C) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_sub(D, zero, A) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    if(fe25519_add(t0, p->X, p->Y) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_mul(E, t0, t0) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_sub(E, E, A) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_sub(E, E, B) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    if(fe25519_add(G, D, B) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_sub(F, G, C) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_sub(H, D, B) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    if(fe25519_mul(r->X, E, F) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_mul(r->Y, G, H) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_mul(r->T, E, H) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe25519_mul(r->Z, F, G) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Scalar multiplication: R = s * P (double-and-add, scalar in little-endian).
 * @param[out] R Result point.
 * @param[in]  s_le Scalar clamped to subgroup order, `NOXTLS_ED25519_FE25519_BYTES` little-endian bytes.
 * @param[in]  P Base point on the curve.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
static noxtls_return_t ge25519_scalar_mult(ge25519_pt_t *R, const uint8_t s_le[NOXTLS_ED25519_FE25519_BYTES], const ge25519_pt_t *P)
{
    ge25519_pt_t N;
    ge25519_pt_t T;
    ge25519_pt_zero(R);
    memcpy(&N, P, sizeof(ge25519_pt_t));

    /* LSB-first double-and-add over little-endian scalar. */
    for(int i = 0; i < (int)NOXTLS_ED25519_SCALAR_MULT_BITS; i++) {
        int bit = (s_le[i >> 3] >> (i & 7)) & 1;
        if(bit) {
            memcpy(&T, R, sizeof(ge25519_pt_t));
            if(ge25519_add(R, &T, &N) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_FAILED;
            }
        }
        memcpy(&T, &N, sizeof(ge25519_pt_t));
        if(ge25519_dbl(&N, &T) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Decodes a 32-byte compressed Edwards-y encoding into an extended point.
 * @param[out] p Decoded point in homogeneous coordinates.
 * @param[in]  enc Compressed encoding (`NOXTLS_ED25519_FE25519_BYTES` bytes, little-endian wire order).
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` if encoding is invalid.
 */
static noxtls_return_t ge25519_decode(ge25519_pt_t *p, const uint8_t enc[NOXTLS_ED25519_FE25519_BYTES])
{
    noxtls_return_t rc;
    uint8_t y_le[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t y_be[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t u[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t v[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t vx2[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t u_val[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t x[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t uv7[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t p58_exp[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t p58_buf[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t x_cand[NOXTLS_ED25519_FE25519_BYTES];
    memcpy(y_le, enc, NOXTLS_ED25519_FE25519_BYTES);
    y_le[NOXTLS_ED25519_FE25519_BYTES - 1U] &= NOXTLS_ED25519_COMPRESSED_Y_SIGN_MASK;
    le32_to_be32(y_be, y_le);
    if(ed25519_cmp_be(y_be, ed25519_p, NOXTLS_ED25519_FE25519_BYTES) >= 0) return NOXTLS_RETURN_FAILED;
    /* u = y^2 - 1, v = d*y^2 + 1 */
    rc = fe25519_mul(u, y_be, y_be);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    ed25519_set_one_be32(u_val);
    rc = fe25519_sub(u, u, u_val);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = fe25519_mul(v, y_be, y_be);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = fe25519_mul(v, v, (const uint8_t *)ed25519_d);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = fe25519_add(v, v, u_val);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    /* x^2 = u/v => x = (u/v)^((p+3)/8). Use x = u * v^3 * (u*v^7)^((p-5)/8) */
    rc = fe25519_mul(uv7, u, v);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = fe25519_mul(uv7, uv7, v);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = fe25519_mul(uv7, uv7, v);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = fe25519_mul(uv7, uv7, v);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = fe25519_mul(uv7, uv7, v);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = fe25519_mul(uv7, uv7, v);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = fe25519_mul(uv7, uv7, v);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    /* (p-5)/8 = 2^252 - 3 in BE */
    memset(p58_exp, 0xFF, NOXTLS_ED25519_FE25519_BYTES);
    p58_exp[0] = 0x0F;
    p58_exp[NOXTLS_ED25519_FE25519_BYTES - 1U] = 0xFD;
    if(fe25519_pow(p58_buf, uv7, p58_exp) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    rc = fe25519_mul(x_cand, u, v);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = fe25519_mul(x_cand, x_cand, v);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = fe25519_mul(x_cand, x_cand, v);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = fe25519_mul(x_cand, x_cand, p58_buf);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = fe25519_mul(vx2, v, x_cand);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = fe25519_mul(vx2, vx2, x_cand);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    if(ed25519_cmp_be(vx2, u, NOXTLS_ED25519_FE25519_BYTES) == 0) {
        memcpy(x, x_cand, NOXTLS_ED25519_FE25519_BYTES);
    } else {
        rc = fe25519_sub(u_val, ed25519_p, u);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        if(ed25519_cmp_be(vx2, u_val, NOXTLS_ED25519_FE25519_BYTES) != 0) return NOXTLS_RETURN_FAILED;
        rc = fe25519_mul(x, x_cand, (const uint8_t *)ed25519_sqrt_minus1);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    }
    if((enc[NOXTLS_ED25519_FE25519_BYTES - 1U] >> 7) != (x[NOXTLS_ED25519_FE25519_BYTES - 1U] & 1)) {
        rc = fe25519_sub(x, ed25519_p, x);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    }
    ed25519_set_one_be32(p->Z);
    memcpy(p->X, x, NOXTLS_ED25519_FE25519_BYTES);
    memcpy(p->Y, y_be, NOXTLS_ED25519_FE25519_BYTES);
    rc = fe25519_mul(p->T, p->X, p->Y);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Encodes an affine-equivalent extended point to 32-byte compressed form (RFC 8032).
 * @param[out] enc Compressed public encoding (`NOXTLS_ED25519_FE25519_BYTES` bytes).
 * @param[in]  p Point in extended coordinates.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
static noxtls_return_t ge25519_encode(uint8_t enc[NOXTLS_ED25519_FE25519_BYTES], const ge25519_pt_t *p)
{
    noxtls_return_t rc;
    uint8_t zinv[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t x[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t y[NOXTLS_ED25519_FE25519_BYTES];
    if(fe25519_inv(zinv, p->Z) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    rc = fe25519_mul(x, p->X, zinv);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = fe25519_mul(y, p->Y, zinv);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    be32_to_le32(enc, y);
    enc[NOXTLS_ED25519_FE25519_BYTES - 1U] |= (x[NOXTLS_ED25519_FE25519_BYTES - 1U] & 1) << 7;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Point negation in extended coordinates (maps (x,y) to (-x,y)).
 * @param[out] r Negated point.
 * @param[in]  p Input point.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
NOXTLS_UNUSED_ATTR
static noxtls_return_t ge25519_neg(ge25519_pt_t *r, const ge25519_pt_t *p)
{
    if(fe25519_sub(r->X, (const uint8_t *)ed25519_p, p->X) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    memcpy(r->Y, p->Y, NOXTLS_ED25519_FE25519_BYTES);
    memcpy(r->Z, p->Z, NOXTLS_ED25519_FE25519_BYTES);
    if(fe25519_sub(r->T, (const uint8_t *)ed25519_p, p->T) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Reduces a 512-bit little-endian integer modulo the curve subgroup order L.
 * @param[out] out_le 32-byte little-endian residue.
 * @param[in]  in_le 64-byte little-endian input (typically SHA-512 output).
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
static noxtls_return_t sc25519_reduce_mod_l(uint8_t out_le[NOXTLS_ED25519_FE25519_BYTES], const uint8_t in_le[NOXTLS_ED25519_SHA512_DIGEST_BYTES])
{
    uint8_t in_be[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
    uint8_t out_be[NOXTLS_ED25519_FE25519_BYTES];
    for(int i = 0; i < (int)NOXTLS_ED25519_SHA512_DIGEST_BYTES; i++) in_be[i] = in_le[(int)NOXTLS_ED25519_SHA512_DIGEST_BYTES - 1 - i];
    if(ed25519_mod_reduce_be(in_be, NOXTLS_ED25519_BN_PRODUCT_BYTES, ed25519_L, out_be) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    be32_to_le32(out_le, out_be);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Multiplies two 32-byte little-endian integers into a 64-byte little-endian product.
 * @param[out] out_le Product buffer (`NOXTLS_ED25519_SHA512_DIGEST_BYTES` bytes).
 * @param[in]  a_le First factor (`NOXTLS_ED25519_FE25519_BYTES` bytes).
 * @param[in]  b_le Second factor (`NOXTLS_ED25519_FE25519_BYTES` bytes).
 * @return None.
 */
static void sc25519_mul_le(uint8_t out_le[NOXTLS_ED25519_SHA512_DIGEST_BYTES], const uint8_t a_le[NOXTLS_ED25519_FE25519_BYTES], const uint8_t b_le[NOXTLS_ED25519_FE25519_BYTES])
{
    memset(out_le, 0, NOXTLS_ED25519_BN_PRODUCT_BYTES);
    for(int i = 0; i < (int)NOXTLS_ED25519_FE25519_BYTES; i++) {
        uint32_t carry = 0;
        for(int j = 0; j < (int)NOXTLS_ED25519_FE25519_BYTES; j++) {
            uint32_t idx = (uint32_t)i + (uint32_t)j;
            uint32_t t = (uint32_t)out_le[idx] + (uint32_t)a_le[i] * (uint32_t)b_le[j] + carry;
            out_le[idx] = (uint8_t)(t & 0xFFu);
            carry = t >> 8;
        }
        uint32_t idx = (uint32_t)i + (uint32_t)NOXTLS_ED25519_FE25519_BYTES;
        while(carry != 0 && idx < (uint32_t)NOXTLS_ED25519_SHA512_DIGEST_BYTES) {
            uint32_t t = (uint32_t)out_le[idx] + carry;
            out_le[idx] = (uint8_t)(t & 0xFFu);
            carry = t >> 8;
            idx++;
        }
    }
}

/**
 * @brief Adds two 32-byte little-endian integers, producing a 33-byte significant little-endian sum in @p out_le.
 * @param[out] out_le Output buffer (low `NOXTLS_ED25519_FE25519_BYTES + 1` bytes used).
 * @param[in]  a_le First summand (`NOXTLS_ED25519_FE25519_BYTES` bytes).
 * @param[in]  b_le Second summand (`NOXTLS_ED25519_FE25519_BYTES` bytes).
 * @return None.
 */
static void sc25519_add_le_32_to_64(uint8_t out_le[NOXTLS_ED25519_SHA512_DIGEST_BYTES], const uint8_t a_le[NOXTLS_ED25519_FE25519_BYTES], const uint8_t b_le[NOXTLS_ED25519_FE25519_BYTES])
{
    memset(out_le, 0, NOXTLS_ED25519_BN_PRODUCT_BYTES);
    uint32_t carry = 0;
    for(int i = 0; i < (int)NOXTLS_ED25519_FE25519_BYTES; i++) {
        uint32_t t = (uint32_t)a_le[i] + (uint32_t)b_le[i] + carry;
        out_le[i] = (uint8_t)(t & 0xFFu);
        carry = t >> 8;
    }
    out_le[NOXTLS_ED25519_FE25519_BYTES] = (uint8_t)carry;
}

/* RFC 8032 dom2 prefix (32 bytes, no NUL); avoids MSVC C4295 on char[32] = "..." */
static const uint8_t ed25519_dom2_literal[NOXTLS_ED25519_DOM2_LITERAL_BYTES] = {
    'S', 'i', 'g', 'E', 'd', '2', '5', '5', '1', '9', ' ', 'n', 'o', ' ', 'E', 'd',
    '2', '5', '5', '1', '9', ' ', 'c', 'o', 'l', 'l', 'i', 's', 'i', 'o', 'n', 's'
};

/**
 * @brief Core Ed25519 signing: pure, ctx, or prehash variant controlled by @p phflag and @p ctx_str.
 * @param[in]  private_key 32-byte seed/private key material.
 * @param[in]  noxtls_message Message bytes (or prehash input when @p phflag is prehash).
 * @param[in]  message_len Length of @p noxtls_message.
 * @param[out] signature 64-byte signature (`R || S` wire encoding).
 * @param[in]  phflag `NOXTLS_ED25519_PH_FLAG_PURE` or `NOXTLS_ED25519_PH_FLAG_PREHASH`.
 * @param[in]  ctx_str Optional context string (Ed25519ctx); may be NULL when @p ctx_len is 0.
 * @param[in]  ctx_len Context length; must be 0 for prehash variant.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on validation or crypto failure.
 */
static noxtls_return_t ed25519_sign_internal(const uint8_t private_key[NOXTLS_ED25519_FE25519_BYTES],
                                             const uint8_t *noxtls_message,
                                             uint32_t message_len,
                                             uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE],
                                             uint8_t phflag,
                                             const uint8_t *ctx_str,
                                             uint32_t ctx_len)
{
    uint8_t h[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
    uint8_t prefix[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t s_le[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t r_in[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
    uint8_t r_le[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t k_in[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
    uint8_t k_le[NOXTLS_ED25519_FE25519_BYTES];
    ge25519_pt_t B;
    ge25519_pt_t R;
    noxtls_sha512_ctx_t ctx;
    uint8_t public_key[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t dom_buf[NOXTLS_ED25519_DOM2_BUFFER_BYTES];
    uint32_t dom_len = 0;
    uint8_t ph_digest[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
    const uint8_t *m_body = noxtls_message;
    uint32_t m_len = message_len;

    if(private_key == NULL || signature == NULL) return NOXTLS_RETURN_NULL;
    if(noxtls_message == NULL && message_len != 0) return NOXTLS_RETURN_NULL;
    if(phflag > NOXTLS_ED25519_PH_FLAG_PREHASH) return NOXTLS_RETURN_INVALID_PARAM;
    if(phflag == NOXTLS_ED25519_PH_FLAG_PREHASH && ctx_len != 0) return NOXTLS_RETURN_INVALID_PARAM;
    if(ctx_len > NOXTLS_ED25519_CONTEXT_MAX) return NOXTLS_RETURN_INVALID_PARAM;
    if(ctx_len > 0 && ctx_str == NULL) return NOXTLS_RETURN_NULL;

    if(phflag != NOXTLS_ED25519_PH_FLAG_PURE || ctx_len > 0) {
        memcpy(dom_buf, ed25519_dom2_literal, NOXTLS_ED25519_DOM2_LITERAL_BYTES);
        dom_buf[NOXTLS_ED25519_DOM2_PHFLAG_OCTET_INDEX] = phflag;
        dom_buf[NOXTLS_ED25519_DOM2_CTX_LEN_OCTET_INDEX] = (uint8_t)ctx_len;
        if(ctx_len > 0) {
            memcpy(dom_buf + NOXTLS_ED25519_DOM2_CTX_START_OCTET_INDEX, ctx_str, ctx_len);
        }
        dom_len = NOXTLS_ED25519_DOM2_PREFIX_BYTES + ctx_len;
    }

    if(phflag == NOXTLS_ED25519_PH_FLAG_PREHASH) {
        if(noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if(message_len != 0U && noxtls_sha512_update(&ctx, noxtls_message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if(noxtls_sha512_finish(&ctx, ph_digest) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        m_body = ph_digest;
        m_len = NOXTLS_ED25519_SHA512_DIGEST_BYTES;
    }

    if(noxtls_ed25519_public_key(private_key, public_key) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
    if(noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_INVALID_ALGORITHM;
    if(noxtls_sha512_update(&ctx, private_key, NOXTLS_ED25519_FE25519_BYTES) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_INVALID_ALGORITHM;
    if(noxtls_sha512_finish(&ctx, h) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_INVALID_ALGORITHM;
    h[0] &= NOXTLS_ED25519_SCALAR_CLAMP_BYTE0_MASK;
    h[NOXTLS_ED25519_FE25519_BYTES - 1U] &= NOXTLS_ED25519_SCALAR_CLAMP_BYTE31_AND;
    h[NOXTLS_ED25519_FE25519_BYTES - 1U] |= NOXTLS_ED25519_SCALAR_CLAMP_BYTE31_OR;
    memcpy(prefix, h + NOXTLS_ED25519_FE25519_BYTES, NOXTLS_ED25519_FE25519_BYTES);
    memcpy(s_le, h, NOXTLS_ED25519_FE25519_BYTES);

    if(noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_BAD_DATA;
    if(dom_len != 0U && noxtls_sha512_update(&ctx, dom_buf, dom_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_BAD_DATA;
    if(noxtls_sha512_update(&ctx, prefix, NOXTLS_ED25519_FE25519_BYTES) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_BAD_DATA;
    if(m_len != 0U && noxtls_sha512_update(&ctx, m_body, m_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_BAD_DATA;
    if(noxtls_sha512_finish(&ctx, r_in) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_BAD_DATA;
    if(sc25519_reduce_mod_l(r_le, r_in) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_TIMEOUT;
    if(ge25519_set_basepoint(&B) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_NOT_SUPPORTED;
    if(ge25519_scalar_mult(&R, r_le, &B) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_NOT_SUPPORTED;
    if(ge25519_encode(signature, &R) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_NOT_SUPPORTED;

    if(noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    if(dom_len != 0U && noxtls_sha512_update(&ctx, dom_buf, dom_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    if(noxtls_sha512_update(&ctx, signature, NOXTLS_ED25519_FE25519_BYTES) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    if(noxtls_sha512_update(&ctx, public_key, NOXTLS_ED25519_FE25519_BYTES) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    if(m_len != 0U && noxtls_sha512_update(&ctx, m_body, m_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    if(noxtls_sha512_finish(&ctx, k_in) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    if(sc25519_reduce_mod_l(k_le, k_in) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;

    {
        uint8_t ks_le64[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
        uint8_t ks_le32[NOXTLS_ED25519_FE25519_BYTES];
        uint8_t sum_le64[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
        uint8_t S_le[NOXTLS_ED25519_FE25519_BYTES];
        sc25519_mul_le(ks_le64, k_le, s_le);
        if(sc25519_reduce_mod_l(ks_le32, ks_le64) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        sc25519_add_le_32_to_64(sum_le64, r_le, ks_le32);
        if(sc25519_reduce_mod_l(S_le, sum_le64) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_NOT_ENOUGH_ENTROPY;
        memcpy(signature + NOXTLS_ED25519_FE25519_BYTES, S_le, NOXTLS_ED25519_FE25519_BYTES);
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Core Ed25519 verification with the same dom2 / prehash rules as `ed25519_sign_internal`.
 * @param[in] public_key 32-byte public key encoding.
 * @param[in] noxtls_message Message bytes (or prehash input when @p phflag is prehash).
 * @param[in] message_len Length of @p noxtls_message.
 * @param[in] signature 64-byte signature to verify.
 * @param[in] phflag `NOXTLS_ED25519_PH_FLAG_PURE` or `NOXTLS_ED25519_PH_FLAG_PREHASH`.
 * @param[in] ctx_str Optional context string; may be NULL when @p ctx_len is 0.
 * @param[in] ctx_len Context length; must be 0 for prehash variant.
 * @return `NOXTLS_RETURN_SUCCESS` if the signature is valid, otherwise an error `noxtls_return_t`.
 */
static noxtls_return_t ed25519_verify_internal(const uint8_t public_key[NOXTLS_ED25519_FE25519_BYTES],
                                                const uint8_t *noxtls_message,
                                                uint32_t message_len,
                                                const uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE],
                                                uint8_t phflag,
                                                const uint8_t *ctx_str,
                                                uint32_t ctx_len)
{
    uint8_t k_in[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
    uint8_t k_le[NOXTLS_ED25519_FE25519_BYTES];
    ge25519_pt_t A;
    ge25519_pt_t R;
    ge25519_pt_t R_plus_kA;
    ge25519_pt_t kA;
    ge25519_pt_t sB;
    noxtls_sha512_ctx_t ctx;
    uint8_t dom_buf[NOXTLS_ED25519_DOM2_BUFFER_BYTES];
    uint32_t dom_len = 0;
    uint8_t ph_digest[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
    const uint8_t *m_body = noxtls_message;
    uint32_t m_len = message_len;

    if(public_key == NULL || signature == NULL) return NOXTLS_RETURN_NULL;
    if(noxtls_message == NULL && message_len != 0) return NOXTLS_RETURN_NULL;
    if(phflag > NOXTLS_ED25519_PH_FLAG_PREHASH) return NOXTLS_RETURN_INVALID_PARAM;
    if(phflag == NOXTLS_ED25519_PH_FLAG_PREHASH && ctx_len != 0) return NOXTLS_RETURN_INVALID_PARAM;
    if(ctx_len > NOXTLS_ED25519_CONTEXT_MAX) return NOXTLS_RETURN_INVALID_PARAM;
    if(ctx_len > 0 && ctx_str == NULL) return NOXTLS_RETURN_NULL;

    if(phflag != NOXTLS_ED25519_PH_FLAG_PURE || ctx_len > 0) {
        memcpy(dom_buf, ed25519_dom2_literal, NOXTLS_ED25519_DOM2_LITERAL_BYTES);
        dom_buf[NOXTLS_ED25519_DOM2_PHFLAG_OCTET_INDEX] = phflag;
        dom_buf[NOXTLS_ED25519_DOM2_CTX_LEN_OCTET_INDEX] = (uint8_t)ctx_len;
        if(ctx_len > 0) {
            memcpy(dom_buf + NOXTLS_ED25519_DOM2_CTX_START_OCTET_INDEX, ctx_str, ctx_len);
        }
        dom_len = NOXTLS_ED25519_DOM2_PREFIX_BYTES + ctx_len;
    }

    if(phflag == NOXTLS_ED25519_PH_FLAG_PREHASH) {
        if(noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if(message_len != 0U && noxtls_sha512_update(&ctx, noxtls_message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if(noxtls_sha512_finish(&ctx, ph_digest) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        m_body = ph_digest;
        m_len = NOXTLS_ED25519_SHA512_DIGEST_BYTES;
    }

    if(ge25519_decode(&A, public_key) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(ge25519_decode(&R, signature) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    {
        uint8_t S_be[NOXTLS_ED25519_FE25519_BYTES];
        uint8_t S_le[NOXTLS_ED25519_FE25519_BYTES];
        memcpy(S_le, signature + NOXTLS_ED25519_FE25519_BYTES, NOXTLS_ED25519_FE25519_BYTES);
        le32_to_be32(S_be, S_le);
        if(ed25519_cmp_be(S_be, ed25519_L, NOXTLS_ED25519_FE25519_BYTES) >= 0) return NOXTLS_RETURN_FAILED;
    }

    if(noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(dom_len != 0U && noxtls_sha512_update(&ctx, dom_buf, dom_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(noxtls_sha512_update(&ctx, signature, NOXTLS_ED25519_FE25519_BYTES) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(noxtls_sha512_update(&ctx, public_key, NOXTLS_ED25519_FE25519_BYTES) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(m_len != 0U && noxtls_sha512_update(&ctx, m_body, m_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(noxtls_sha512_finish(&ctx, k_in) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(sc25519_reduce_mod_l(k_le, k_in) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    if(ge25519_scalar_mult(&kA, k_le, &A) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(ge25519_add(&R_plus_kA, &R, &kA) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(ge25519_set_basepoint(&R) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    {
        uint8_t S_le[NOXTLS_ED25519_FE25519_BYTES];
        memcpy(S_le, signature + NOXTLS_ED25519_FE25519_BYTES, NOXTLS_ED25519_FE25519_BYTES);
        if(ge25519_scalar_mult(&sB, S_le, &R) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    }
    {
        uint8_t enc1[NOXTLS_ED25519_FE25519_BYTES];
        uint8_t enc2[NOXTLS_ED25519_FE25519_BYTES];
        if(ge25519_encode(enc1, &R_plus_kA) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if(ge25519_encode(enc2, &sB) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if(noxtls_secret_memcmp(enc1, enc2, NOXTLS_ED25519_FE25519_BYTES) != 0) {
            uint8_t cofactor_le[NOXTLS_ED25519_FE25519_BYTES] = {0};
            ge25519_pt_t lhs8;
            ge25519_pt_t rhs8;
            uint8_t enc_lhs8[NOXTLS_ED25519_FE25519_BYTES];
            uint8_t enc_rhs8[NOXTLS_ED25519_FE25519_BYTES];
            cofactor_le[0] = NOXTLS_ED25519_SUBGROUP_COFACTOR;
            if(ge25519_scalar_mult(&lhs8, cofactor_le, &sB) == NOXTLS_RETURN_SUCCESS &&
                ge25519_scalar_mult(&rhs8, cofactor_le, &R_plus_kA) == NOXTLS_RETURN_SUCCESS &&
                ge25519_encode(enc_lhs8, &lhs8) == NOXTLS_RETURN_SUCCESS &&
                ge25519_encode(enc_rhs8, &rhs8) == NOXTLS_RETURN_SUCCESS &&
                noxtls_secret_memcmp(enc_lhs8, enc_rhs8, NOXTLS_ED25519_FE25519_BYTES) == 0) {
                return NOXTLS_RETURN_SUCCESS;
            }
            return NOXTLS_RETURN_FAILED;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Derives the Ed25519 public key from a 32-byte private key seed (RFC 8032).
 * @param[in]  private_key 32-byte private key / seed.
 * @param[out] public_key 32-byte compressed public key encoding.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_ed25519_public_key(const uint8_t private_key[NOXTLS_ED25519_FE25519_BYTES], uint8_t public_key[NOXTLS_ED25519_FE25519_BYTES])
{
    uint8_t h[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
    uint8_t s_le[NOXTLS_ED25519_FE25519_BYTES];
    ge25519_pt_t B;
    ge25519_pt_t A;
    noxtls_sha512_ctx_t ctx;

    if(private_key == NULL || public_key == NULL) return NOXTLS_RETURN_NULL;
    if(noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(noxtls_sha512_update(&ctx, private_key, NOXTLS_ED25519_FE25519_BYTES) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(noxtls_sha512_finish(&ctx, h) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    h[0] &= NOXTLS_ED25519_SCALAR_CLAMP_BYTE0_MASK;
    h[NOXTLS_ED25519_FE25519_BYTES - 1U] &= NOXTLS_ED25519_SCALAR_CLAMP_BYTE31_AND;
    h[NOXTLS_ED25519_FE25519_BYTES - 1U] |= NOXTLS_ED25519_SCALAR_CLAMP_BYTE31_OR;
    memcpy(s_le, h, NOXTLS_ED25519_FE25519_BYTES);
    if(ge25519_set_basepoint(&B) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(ge25519_scalar_mult(&A, s_le, &B) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return ge25519_encode(public_key, &A);
}

/**
 * @brief Signs a noxtls_message with Ed25519 (pure variant, no context, no prehash).
 * @param[in]  private_key 32-byte private key.
 * @param[in]  noxtls_message Message to sign.
 * @param[in]  message_len Length of @p noxtls_message in bytes.
 * @param[out] signature 64-byte signature output.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_ed25519_sign(const uint8_t private_key[NOXTLS_ED25519_FE25519_BYTES],
                                     const uint8_t *noxtls_message,
                                     uint32_t message_len,
                                     uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE])
{
    return ed25519_sign_internal(private_key, noxtls_message, message_len, signature, NOXTLS_ED25519_PH_FLAG_PURE, NULL, 0);
}

/**
 * @brief Verifies an Ed25519 signature (pure variant).
 * @param[in] public_key 32-byte public key encoding.
 * @param[in] noxtls_message Message that was signed.
 * @param[in] message_len Length of @p noxtls_message in bytes.
 * @param[in] signature 64-byte signature.
 * @return `NOXTLS_RETURN_SUCCESS` if valid, otherwise an error `noxtls_return_t`.
 */
noxtls_return_t noxtls_ed25519_verify(const uint8_t public_key[NOXTLS_ED25519_FE25519_BYTES],
                                      const uint8_t *noxtls_message,
                                      uint32_t message_len,
                                      const uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE])
{
    return ed25519_verify_internal(public_key, noxtls_message, message_len, signature, NOXTLS_ED25519_PH_FLAG_PURE, NULL, 0);
}

/**
 * @brief Signs a noxtls_message with Ed25519ctx (RFC 8032 context string, not prehashed).
 * @param[in]  private_key 32-byte private key.
 * @param[in]  noxtls_message Message to sign.
 * @param[in]  message_len Length of @p noxtls_message in bytes.
 * @param[in]  context Context string (length at most `NOXTLS_ED25519_CONTEXT_MAX`).
 * @param[in]  context_len Length of @p context in bytes.
 * @param[out] signature 64-byte signature output.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_ed25519ctx_sign(const uint8_t private_key[NOXTLS_ED25519_FE25519_BYTES],
                                       const uint8_t *context,
                                       uint32_t context_len,
                                       const uint8_t *noxtls_message,
                                       uint32_t message_len,
                                       uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE])
{
    if(context == NULL && context_len != 0) return NOXTLS_RETURN_NULL;
    if(context_len < 1U || context_len > NOXTLS_ED25519_CONTEXT_MAX) return NOXTLS_RETURN_INVALID_PARAM;
    return ed25519_sign_internal(private_key, noxtls_message, message_len, signature, NOXTLS_ED25519_PH_FLAG_PURE, context, context_len);
}

/**
 * @brief Verifies an Ed25519ctx signature.
 * @param[in] public_key 32-byte public key encoding.
 * @param[in] noxtls_message Message that was signed.
 * @param[in] message_len Length of @p noxtls_message in bytes.
 * @param[in] context Context string used when signing.
 * @param[in] context_len Length of @p context in bytes.
 * @param[in] signature 64-byte signature.
 * @return `NOXTLS_RETURN_SUCCESS` if valid, otherwise an error `noxtls_return_t`.
 */
noxtls_return_t noxtls_ed25519ctx_verify(const uint8_t public_key[NOXTLS_ED25519_FE25519_BYTES],
                                         const uint8_t *context,
                                         uint32_t context_len,
                                         const uint8_t *noxtls_message,
                                         uint32_t message_len,
                                         const uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE])
{
    if(context == NULL && context_len != 0) return NOXTLS_RETURN_NULL;
    if(context_len < 1U || context_len > NOXTLS_ED25519_CONTEXT_MAX) return NOXTLS_RETURN_INVALID_PARAM;
    return ed25519_verify_internal(public_key, noxtls_message, message_len, signature, NOXTLS_ED25519_PH_FLAG_PURE, context, context_len);
}

/**
 * @brief Signs with Ed25519ph: @p noxtls_message is hashed with SHA-512 first, then signed.
 * @param[in]  private_key 32-byte private key.
 * @param[in]  noxtls_message Input to SHA-512 (typically the raw noxtls_message bytes).
 * @param[in]  message_len Length of @p noxtls_message in bytes.
 * @param[out] signature 64-byte signature output.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_ed25519ph_sign(const uint8_t private_key[NOXTLS_ED25519_FE25519_BYTES],
                                      const uint8_t *noxtls_message,
                                      uint32_t message_len,
                                      uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE])
{
    return ed25519_sign_internal(private_key, noxtls_message, message_len, signature, NOXTLS_ED25519_PH_FLAG_PREHASH, NULL, 0);
}

/**
 * @brief Verifies an Ed25519ph signature (SHA-512 prehash of @p noxtls_message).
 * @param[in] public_key 32-byte public key encoding.
 * @param[in] noxtls_message Same prehash input that was signed.
 * @param[in] message_len Length of @p noxtls_message in bytes.
 * @param[in] signature 64-byte signature.
 * @return `NOXTLS_RETURN_SUCCESS` if valid, otherwise an error `noxtls_return_t`.
 */
noxtls_return_t noxtls_ed25519ph_verify(const uint8_t public_key[NOXTLS_ED25519_FE25519_BYTES],
                                        const uint8_t *noxtls_message,
                                        uint32_t message_len,
                                        const uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE])
{
    return ed25519_verify_internal(public_key, noxtls_message, message_len, signature, NOXTLS_ED25519_PH_FLAG_PREHASH, NULL, 0);
}

/**
 * @brief Generates a random Ed25519 key pair using the library DRBG.
 * @param[out] private_key 32-byte random private key / seed.
 * @param[out] public_key 32-byte derived public key encoding.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_ed25519_generate_key(uint8_t private_key[NOXTLS_ED25519_FE25519_BYTES], uint8_t public_key[NOXTLS_ED25519_FE25519_BYTES])
{
    static drbg_state_t drbg_state;
    static int drbg_initialized = 0;
    noxtls_return_t rc;

    if(private_key == NULL || public_key == NULL) return NOXTLS_RETURN_NULL;
    if(!drbg_initialized) {
        rc = drbg_instantiate(&drbg_state, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        drbg_initialized = 1;
    }
    rc = drbg_generate(&drbg_state, private_key, NOXTLS_ED25519_DRBG_SEED_BITS, NULL, 0);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    return noxtls_ed25519_public_key(private_key, public_key);
}
