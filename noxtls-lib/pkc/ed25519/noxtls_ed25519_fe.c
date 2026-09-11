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

#include "noxtls_ed25519_config.h"
#include "noxtls_ed25519_fe.h"

/*
 * On Cortex-M4/M7 with NOXTLS_ED25519_FE_USE_HAASE_ASM, mul/sq/sq2 live in
 * noxtls_ed25519_fe_arm.c (Haase CC0 packed UMAAL). Otherwise this file owns
 * the portable 10-limb SMULL path.
 */
#if (defined(__ARM_ARCH_7EM__) || defined(__ARM_ARCH_8M_MAIN__)) && \
    !defined(NOXTLS_ED25519_FE_USE_HAASE_ASM)
#define FE25519_HOT __attribute__((optimize("O3")))
#else
#define FE25519_HOT
#endif

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

/**
 * @brief Reduce limb a0 to 26 bits; carry into a1 (ref10 / wolfSSL TO_26).
 * @internal
 */
#define FE25519_TO_26(a0, a1, c) \
    do { \
        (c) = ((a0) + ((int64_t)1 << 25)) >> 26; \
        (a1) += (c); \
        (a0) -= (c) << 26; \
    } while(0)

/**
 * @brief Reduce limb a0 to 25 bits; carry into a1 (ref10 / wolfSSL TO_25).
 * @internal
 */
#define FE25519_TO_25(a0, a1, c) \
    do { \
        (c) = ((a0) + ((int64_t)1 << 24)) >> 25; \
        (a1) += (c); \
        (a0) -= (c) << 25; \
    } while(0)

/**
 * @brief Reduce limb a0 to 25 bits; carry * 19 into a1 (mod p).
 * @internal
 */
#define FE25519_TO_25_RED(a0, a1, c) \
    do { \
        (c) = ((a0) + ((int64_t)1 << 24)) >> 25; \
        (a1) += (c) * 19; \
        (a0) -= (c) << 25; \
    } while(0)

#if !((defined(__ARM_ARCH_7EM__) || defined(__ARM_ARCH_8M_MAIN__)) && \
      defined(NOXTLS_ED25519_FE_USE_HAASE_ASM))
FE25519_HOT void fe25519_native_mul(fe25519_native_t *out, const fe25519_native_t *a, const fe25519_native_t *b)
{
    /* ref10 / wolfSSL fe_mul: keep limbs int32 so f*(int64_t)g is SMULL on Cortex-M4. */
    const int32_t f0 = a->v[0];
    const int32_t f1 = a->v[1];
    const int32_t f2 = a->v[2];
    const int32_t f3 = a->v[3];
    const int32_t f4 = a->v[4];
    const int32_t f5 = a->v[5];
    const int32_t f6 = a->v[6];
    const int32_t f7 = a->v[7];
    const int32_t f8 = a->v[8];
    const int32_t f9 = a->v[9];
    const int32_t g0 = b->v[0];
    const int32_t g1 = b->v[1];
    const int32_t g2 = b->v[2];
    const int32_t g3 = b->v[3];
    const int32_t g4 = b->v[4];
    const int32_t g5 = b->v[5];
    const int32_t g6 = b->v[6];
    const int32_t g7 = b->v[7];
    const int32_t g8 = b->v[8];
    const int32_t g9 = b->v[9];
    const int32_t g1_19 = 19 * g1;
    const int32_t g2_19 = 19 * g2;
    const int32_t g3_19 = 19 * g3;
    const int32_t g4_19 = 19 * g4;
    const int32_t g5_19 = 19 * g5;
    const int32_t g6_19 = 19 * g6;
    const int32_t g7_19 = 19 * g7;
    const int32_t g8_19 = 19 * g8;
    const int32_t g9_19 = 19 * g9;
    const int32_t f1_2 = 2 * f1;
    const int32_t f3_2 = 2 * f3;
    const int32_t f5_2 = 2 * f5;
    const int32_t f7_2 = 2 * f7;
    const int32_t f9_2 = 2 * f9;
    const int64_t f0g0 = f0 * (int64_t)g0;
    const int64_t f0g1 = f0 * (int64_t)g1;
    const int64_t f0g2 = f0 * (int64_t)g2;
    const int64_t f0g3 = f0 * (int64_t)g3;
    const int64_t f0g4 = f0 * (int64_t)g4;
    const int64_t f0g5 = f0 * (int64_t)g5;
    const int64_t f0g6 = f0 * (int64_t)g6;
    const int64_t f0g7 = f0 * (int64_t)g7;
    const int64_t f0g8 = f0 * (int64_t)g8;
    const int64_t f0g9 = f0 * (int64_t)g9;
    const int64_t f1g0 = f1 * (int64_t)g0;
    const int64_t f1g1_2 = f1_2 * (int64_t)g1;
    const int64_t f1g2 = f1 * (int64_t)g2;
    const int64_t f1g3_2 = f1_2 * (int64_t)g3;
    const int64_t f1g4 = f1 * (int64_t)g4;
    const int64_t f1g5_2 = f1_2 * (int64_t)g5;
    const int64_t f1g6 = f1 * (int64_t)g6;
    const int64_t f1g7_2 = f1_2 * (int64_t)g7;
    const int64_t f1g8 = f1 * (int64_t)g8;
    const int64_t f1g9_38 = f1_2 * (int64_t)g9_19;
    const int64_t f2g0 = f2 * (int64_t)g0;
    const int64_t f2g1 = f2 * (int64_t)g1;
    const int64_t f2g2 = f2 * (int64_t)g2;
    const int64_t f2g3 = f2 * (int64_t)g3;
    const int64_t f2g4 = f2 * (int64_t)g4;
    const int64_t f2g5 = f2 * (int64_t)g5;
    const int64_t f2g6 = f2 * (int64_t)g6;
    const int64_t f2g7 = f2 * (int64_t)g7;
    const int64_t f2g8_19 = f2 * (int64_t)g8_19;
    const int64_t f2g9_19 = f2 * (int64_t)g9_19;
    const int64_t f3g0 = f3 * (int64_t)g0;
    const int64_t f3g1_2 = f3_2 * (int64_t)g1;
    const int64_t f3g2 = f3 * (int64_t)g2;
    const int64_t f3g3_2 = f3_2 * (int64_t)g3;
    const int64_t f3g4 = f3 * (int64_t)g4;
    const int64_t f3g5_2 = f3_2 * (int64_t)g5;
    const int64_t f3g6 = f3 * (int64_t)g6;
    const int64_t f3g7_38 = f3_2 * (int64_t)g7_19;
    const int64_t f3g8_19 = f3 * (int64_t)g8_19;
    const int64_t f3g9_38 = f3_2 * (int64_t)g9_19;
    const int64_t f4g0 = f4 * (int64_t)g0;
    const int64_t f4g1 = f4 * (int64_t)g1;
    const int64_t f4g2 = f4 * (int64_t)g2;
    const int64_t f4g3 = f4 * (int64_t)g3;
    const int64_t f4g4 = f4 * (int64_t)g4;
    const int64_t f4g5 = f4 * (int64_t)g5;
    const int64_t f4g6_19 = f4 * (int64_t)g6_19;
    const int64_t f4g7_19 = f4 * (int64_t)g7_19;
    const int64_t f4g8_19 = f4 * (int64_t)g8_19;
    const int64_t f4g9_19 = f4 * (int64_t)g9_19;
    const int64_t f5g0 = f5 * (int64_t)g0;
    const int64_t f5g1_2 = f5_2 * (int64_t)g1;
    const int64_t f5g2 = f5 * (int64_t)g2;
    const int64_t f5g3_2 = f5_2 * (int64_t)g3;
    const int64_t f5g4 = f5 * (int64_t)g4;
    const int64_t f5g5_38 = f5_2 * (int64_t)g5_19;
    const int64_t f5g6_19 = f5 * (int64_t)g6_19;
    const int64_t f5g7_38 = f5_2 * (int64_t)g7_19;
    const int64_t f5g8_19 = f5 * (int64_t)g8_19;
    const int64_t f5g9_38 = f5_2 * (int64_t)g9_19;
    const int64_t f6g0 = f6 * (int64_t)g0;
    const int64_t f6g1 = f6 * (int64_t)g1;
    const int64_t f6g2 = f6 * (int64_t)g2;
    const int64_t f6g3 = f6 * (int64_t)g3;
    const int64_t f6g4_19 = f6 * (int64_t)g4_19;
    const int64_t f6g5_19 = f6 * (int64_t)g5_19;
    const int64_t f6g6_19 = f6 * (int64_t)g6_19;
    const int64_t f6g7_19 = f6 * (int64_t)g7_19;
    const int64_t f6g8_19 = f6 * (int64_t)g8_19;
    const int64_t f6g9_19 = f6 * (int64_t)g9_19;
    const int64_t f7g0 = f7 * (int64_t)g0;
    const int64_t f7g1_2 = f7_2 * (int64_t)g1;
    const int64_t f7g2 = f7 * (int64_t)g2;
    const int64_t f7g3_38 = f7_2 * (int64_t)g3_19;
    const int64_t f7g4_19 = f7 * (int64_t)g4_19;
    const int64_t f7g5_38 = f7_2 * (int64_t)g5_19;
    const int64_t f7g6_19 = f7 * (int64_t)g6_19;
    const int64_t f7g7_38 = f7_2 * (int64_t)g7_19;
    const int64_t f7g8_19 = f7 * (int64_t)g8_19;
    const int64_t f7g9_38 = f7_2 * (int64_t)g9_19;
    const int64_t f8g0 = f8 * (int64_t)g0;
    const int64_t f8g1 = f8 * (int64_t)g1;
    const int64_t f8g2_19 = f8 * (int64_t)g2_19;
    const int64_t f8g3_19 = f8 * (int64_t)g3_19;
    const int64_t f8g4_19 = f8 * (int64_t)g4_19;
    const int64_t f8g5_19 = f8 * (int64_t)g5_19;
    const int64_t f8g6_19 = f8 * (int64_t)g6_19;
    const int64_t f8g7_19 = f8 * (int64_t)g7_19;
    const int64_t f8g8_19 = f8 * (int64_t)g8_19;
    const int64_t f8g9_19 = f8 * (int64_t)g9_19;
    const int64_t f9g0 = f9 * (int64_t)g0;
    const int64_t f9g1_38 = f9_2 * (int64_t)g1_19;
    const int64_t f9g2_19 = f9 * (int64_t)g2_19;
    const int64_t f9g3_38 = f9_2 * (int64_t)g3_19;
    const int64_t f9g4_19 = f9 * (int64_t)g4_19;
    const int64_t f9g5_38 = f9_2 * (int64_t)g5_19;
    const int64_t f9g6_19 = f9 * (int64_t)g6_19;
    const int64_t f9g7_38 = f9_2 * (int64_t)g7_19;
    const int64_t f9g8_19 = f9 * (int64_t)g8_19;
    const int64_t f9g9_38 = f9_2 * (int64_t)g9_19;
    int64_t h0 = f0g0 + f1g9_38 + f2g8_19 + f3g7_38 + f4g6_19 + f5g5_38 + f6g4_19 + f7g3_38 + f8g2_19 + f9g1_38;
    int64_t h1 = f0g1 + f1g0 + f2g9_19 + f3g8_19 + f4g7_19 + f5g6_19 + f6g5_19 + f7g4_19 + f8g3_19 + f9g2_19;
    int64_t h2 = f0g2 + f1g1_2 + f2g0 + f3g9_38 + f4g8_19 + f5g7_38 + f6g6_19 + f7g5_38 + f8g4_19 + f9g3_38;
    int64_t h3 = f0g3 + f1g2 + f2g1 + f3g0 + f4g9_19 + f5g8_19 + f6g7_19 + f7g6_19 + f8g5_19 + f9g4_19;
    int64_t h4 = f0g4 + f1g3_2 + f2g2 + f3g1_2 + f4g0 + f5g9_38 + f6g8_19 + f7g7_38 + f8g6_19 + f9g5_38;
    int64_t h5 = f0g5 + f1g4 + f2g3 + f3g2 + f4g1 + f5g0 + f6g9_19 + f7g8_19 + f8g7_19 + f9g6_19;
    int64_t h6 = f0g6 + f1g5_2 + f2g4 + f3g3_2 + f4g2 + f5g1_2 + f6g0 + f7g9_38 + f8g8_19 + f9g7_38;
    int64_t h7 = f0g7 + f1g6 + f2g5 + f3g4 + f4g3 + f5g2 + f6g1 + f7g0 + f8g9_19 + f9g8_19;
    int64_t h8 = f0g8 + f1g7_2 + f2g6 + f3g5_2 + f4g4 + f5g3_2 + f6g2 + f7g1_2 + f8g0 + f9g9_38;
    int64_t h9 = f0g9 + f1g8 + f2g7 + f3g6 + f4g5 + f5g4 + f6g3 + f7g2 + f8g1 + f9g0;
    int64_t carry;

    FE25519_TO_26(h0, h1, carry);
    FE25519_TO_26(h4, h5, carry);
    FE25519_TO_25(h1, h2, carry);
    FE25519_TO_25(h5, h6, carry);
    FE25519_TO_26(h2, h3, carry);
    FE25519_TO_26(h6, h7, carry);
    FE25519_TO_25(h3, h4, carry);
    FE25519_TO_25(h7, h8, carry);
    FE25519_TO_26(h4, h5, carry);
    FE25519_TO_26(h8, h9, carry);
    FE25519_TO_25_RED(h9, h0, carry);
    FE25519_TO_26(h0, h1, carry);

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

FE25519_HOT void fe25519_native_sq(fe25519_native_t *out, const fe25519_native_t *a)
{
    /* Dedicated ref10 / wolfSSL fe_sq (fewer products than mul(a,a)). */
    const int32_t f0 = a->v[0];
    const int32_t f1 = a->v[1];
    const int32_t f2 = a->v[2];
    const int32_t f3 = a->v[3];
    const int32_t f4 = a->v[4];
    const int32_t f5 = a->v[5];
    const int32_t f6 = a->v[6];
    const int32_t f7 = a->v[7];
    const int32_t f8 = a->v[8];
    const int32_t f9 = a->v[9];
    const int32_t f0_2 = 2 * f0;
    const int32_t f1_2 = 2 * f1;
    const int32_t f2_2 = 2 * f2;
    const int32_t f3_2 = 2 * f3;
    const int32_t f4_2 = 2 * f4;
    const int32_t f5_2 = 2 * f5;
    const int32_t f6_2 = 2 * f6;
    const int32_t f7_2 = 2 * f7;
    const int32_t f5_38 = 38 * f5;
    const int32_t f6_19 = 19 * f6;
    const int32_t f7_38 = 38 * f7;
    const int32_t f8_19 = 19 * f8;
    const int32_t f9_38 = 38 * f9;
    const int64_t f0f0 = f0 * (int64_t)f0;
    const int64_t f0f1_2 = f0_2 * (int64_t)f1;
    const int64_t f0f2_2 = f0_2 * (int64_t)f2;
    const int64_t f0f3_2 = f0_2 * (int64_t)f3;
    const int64_t f0f4_2 = f0_2 * (int64_t)f4;
    const int64_t f0f5_2 = f0_2 * (int64_t)f5;
    const int64_t f0f6_2 = f0_2 * (int64_t)f6;
    const int64_t f0f7_2 = f0_2 * (int64_t)f7;
    const int64_t f0f8_2 = f0_2 * (int64_t)f8;
    const int64_t f0f9_2 = f0_2 * (int64_t)f9;
    const int64_t f1f1_2 = f1_2 * (int64_t)f1;
    const int64_t f1f2_2 = f1_2 * (int64_t)f2;
    const int64_t f1f3_4 = f1_2 * (int64_t)f3_2;
    const int64_t f1f4_2 = f1_2 * (int64_t)f4;
    const int64_t f1f5_4 = f1_2 * (int64_t)f5_2;
    const int64_t f1f6_2 = f1_2 * (int64_t)f6;
    const int64_t f1f7_4 = f1_2 * (int64_t)f7_2;
    const int64_t f1f8_2 = f1_2 * (int64_t)f8;
    const int64_t f1f9_76 = f1_2 * (int64_t)f9_38;
    const int64_t f2f2 = f2 * (int64_t)f2;
    const int64_t f2f3_2 = f2_2 * (int64_t)f3;
    const int64_t f2f4_2 = f2_2 * (int64_t)f4;
    const int64_t f2f5_2 = f2_2 * (int64_t)f5;
    const int64_t f2f6_2 = f2_2 * (int64_t)f6;
    const int64_t f2f7_2 = f2_2 * (int64_t)f7;
    const int64_t f2f8_38 = f2_2 * (int64_t)f8_19;
    const int64_t f2f9_38 = f2 * (int64_t)f9_38;
    const int64_t f3f3_2 = f3_2 * (int64_t)f3;
    const int64_t f3f4_2 = f3_2 * (int64_t)f4;
    const int64_t f3f5_4 = f3_2 * (int64_t)f5_2;
    const int64_t f3f6_2 = f3_2 * (int64_t)f6;
    const int64_t f3f7_76 = f3_2 * (int64_t)f7_38;
    const int64_t f3f8_38 = f3_2 * (int64_t)f8_19;
    const int64_t f3f9_76 = f3_2 * (int64_t)f9_38;
    const int64_t f4f4 = f4 * (int64_t)f4;
    const int64_t f4f5_2 = f4_2 * (int64_t)f5;
    const int64_t f4f6_38 = f4_2 * (int64_t)f6_19;
    const int64_t f4f7_38 = f4 * (int64_t)f7_38;
    const int64_t f4f8_38 = f4_2 * (int64_t)f8_19;
    const int64_t f4f9_38 = f4 * (int64_t)f9_38;
    const int64_t f5f5_38 = f5 * (int64_t)f5_38;
    const int64_t f5f6_38 = f5_2 * (int64_t)f6_19;
    const int64_t f5f7_76 = f5_2 * (int64_t)f7_38;
    const int64_t f5f8_38 = f5_2 * (int64_t)f8_19;
    const int64_t f5f9_76 = f5_2 * (int64_t)f9_38;
    const int64_t f6f6_19 = f6 * (int64_t)f6_19;
    const int64_t f6f7_38 = f6 * (int64_t)f7_38;
    const int64_t f6f8_38 = f6_2 * (int64_t)f8_19;
    const int64_t f6f9_38 = f6 * (int64_t)f9_38;
    const int64_t f7f7_38 = f7 * (int64_t)f7_38;
    const int64_t f7f8_38 = f7_2 * (int64_t)f8_19;
    const int64_t f7f9_76 = f7_2 * (int64_t)f9_38;
    const int64_t f8f8_19 = f8 * (int64_t)f8_19;
    const int64_t f8f9_38 = f8 * (int64_t)f9_38;
    const int64_t f9f9_38 = f9 * (int64_t)f9_38;
    int64_t h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
    int64_t h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
    int64_t h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
    int64_t h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
    int64_t h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
    int64_t h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
    int64_t h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
    int64_t h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
    int64_t h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
    int64_t h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;
    int64_t carry;

    FE25519_TO_26(h0, h1, carry);
    FE25519_TO_26(h4, h5, carry);
    FE25519_TO_25(h1, h2, carry);
    FE25519_TO_25(h5, h6, carry);
    FE25519_TO_26(h2, h3, carry);
    FE25519_TO_26(h6, h7, carry);
    FE25519_TO_25(h3, h4, carry);
    FE25519_TO_25(h7, h8, carry);
    FE25519_TO_26(h4, h5, carry);
    FE25519_TO_26(h8, h9, carry);
    FE25519_TO_25_RED(h9, h0, carry);
    FE25519_TO_26(h0, h1, carry);

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

FE25519_HOT void fe25519_native_sq2(fe25519_native_t *out, const fe25519_native_t *a)
{
    /* ref10 / wolfSSL fe_sq2: square then double before carry (2*a^2). */
    const int32_t f0 = a->v[0];
    const int32_t f1 = a->v[1];
    const int32_t f2 = a->v[2];
    const int32_t f3 = a->v[3];
    const int32_t f4 = a->v[4];
    const int32_t f5 = a->v[5];
    const int32_t f6 = a->v[6];
    const int32_t f7 = a->v[7];
    const int32_t f8 = a->v[8];
    const int32_t f9 = a->v[9];
    const int32_t f0_2 = 2 * f0;
    const int32_t f1_2 = 2 * f1;
    const int32_t f2_2 = 2 * f2;
    const int32_t f3_2 = 2 * f3;
    const int32_t f4_2 = 2 * f4;
    const int32_t f5_2 = 2 * f5;
    const int32_t f6_2 = 2 * f6;
    const int32_t f7_2 = 2 * f7;
    const int32_t f5_38 = 38 * f5;
    const int32_t f6_19 = 19 * f6;
    const int32_t f7_38 = 38 * f7;
    const int32_t f8_19 = 19 * f8;
    const int32_t f9_38 = 38 * f9;
    const int64_t f0f0 = f0 * (int64_t)f0;
    const int64_t f0f1_2 = f0_2 * (int64_t)f1;
    const int64_t f0f2_2 = f0_2 * (int64_t)f2;
    const int64_t f0f3_2 = f0_2 * (int64_t)f3;
    const int64_t f0f4_2 = f0_2 * (int64_t)f4;
    const int64_t f0f5_2 = f0_2 * (int64_t)f5;
    const int64_t f0f6_2 = f0_2 * (int64_t)f6;
    const int64_t f0f7_2 = f0_2 * (int64_t)f7;
    const int64_t f0f8_2 = f0_2 * (int64_t)f8;
    const int64_t f0f9_2 = f0_2 * (int64_t)f9;
    const int64_t f1f1_2 = f1_2 * (int64_t)f1;
    const int64_t f1f2_2 = f1_2 * (int64_t)f2;
    const int64_t f1f3_4 = f1_2 * (int64_t)f3_2;
    const int64_t f1f4_2 = f1_2 * (int64_t)f4;
    const int64_t f1f5_4 = f1_2 * (int64_t)f5_2;
    const int64_t f1f6_2 = f1_2 * (int64_t)f6;
    const int64_t f1f7_4 = f1_2 * (int64_t)f7_2;
    const int64_t f1f8_2 = f1_2 * (int64_t)f8;
    const int64_t f1f9_76 = f1_2 * (int64_t)f9_38;
    const int64_t f2f2 = f2 * (int64_t)f2;
    const int64_t f2f3_2 = f2_2 * (int64_t)f3;
    const int64_t f2f4_2 = f2_2 * (int64_t)f4;
    const int64_t f2f5_2 = f2_2 * (int64_t)f5;
    const int64_t f2f6_2 = f2_2 * (int64_t)f6;
    const int64_t f2f7_2 = f2_2 * (int64_t)f7;
    const int64_t f2f8_38 = f2_2 * (int64_t)f8_19;
    const int64_t f2f9_38 = f2 * (int64_t)f9_38;
    const int64_t f3f3_2 = f3_2 * (int64_t)f3;
    const int64_t f3f4_2 = f3_2 * (int64_t)f4;
    const int64_t f3f5_4 = f3_2 * (int64_t)f5_2;
    const int64_t f3f6_2 = f3_2 * (int64_t)f6;
    const int64_t f3f7_76 = f3_2 * (int64_t)f7_38;
    const int64_t f3f8_38 = f3_2 * (int64_t)f8_19;
    const int64_t f3f9_76 = f3_2 * (int64_t)f9_38;
    const int64_t f4f4 = f4 * (int64_t)f4;
    const int64_t f4f5_2 = f4_2 * (int64_t)f5;
    const int64_t f4f6_38 = f4_2 * (int64_t)f6_19;
    const int64_t f4f7_38 = f4 * (int64_t)f7_38;
    const int64_t f4f8_38 = f4_2 * (int64_t)f8_19;
    const int64_t f4f9_38 = f4 * (int64_t)f9_38;
    const int64_t f5f5_38 = f5 * (int64_t)f5_38;
    const int64_t f5f6_38 = f5_2 * (int64_t)f6_19;
    const int64_t f5f7_76 = f5_2 * (int64_t)f7_38;
    const int64_t f5f8_38 = f5_2 * (int64_t)f8_19;
    const int64_t f5f9_76 = f5_2 * (int64_t)f9_38;
    const int64_t f6f6_19 = f6 * (int64_t)f6_19;
    const int64_t f6f7_38 = f6 * (int64_t)f7_38;
    const int64_t f6f8_38 = f6_2 * (int64_t)f8_19;
    const int64_t f6f9_38 = f6 * (int64_t)f9_38;
    const int64_t f7f7_38 = f7 * (int64_t)f7_38;
    const int64_t f7f8_38 = f7_2 * (int64_t)f8_19;
    const int64_t f7f9_76 = f7_2 * (int64_t)f9_38;
    const int64_t f8f8_19 = f8 * (int64_t)f8_19;
    const int64_t f8f9_38 = f8 * (int64_t)f9_38;
    const int64_t f9f9_38 = f9 * (int64_t)f9_38;
    int64_t h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
    int64_t h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
    int64_t h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
    int64_t h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
    int64_t h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
    int64_t h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
    int64_t h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
    int64_t h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
    int64_t h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
    int64_t h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;
    int64_t carry;

    h0 += h0;
    h1 += h1;
    h2 += h2;
    h3 += h3;
    h4 += h4;
    h5 += h5;
    h6 += h6;
    h7 += h7;
    h8 += h8;
    h9 += h9;

    FE25519_TO_26(h0, h1, carry);
    FE25519_TO_26(h4, h5, carry);
    FE25519_TO_25(h1, h2, carry);
    FE25519_TO_25(h5, h6, carry);
    FE25519_TO_26(h2, h3, carry);
    FE25519_TO_26(h6, h7, carry);
    FE25519_TO_25(h3, h4, carry);
    FE25519_TO_25(h7, h8, carry);
    FE25519_TO_26(h4, h5, carry);
    FE25519_TO_26(h8, h9, carry);
    FE25519_TO_25_RED(h9, h0, carry);
    FE25519_TO_26(h0, h1, carry);

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
#endif /* !HAASE_ASM — mul/sq/sq2 provided by noxtls_ed25519_fe_arm.c */

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
