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
* File:    noxtls_ed25519_sc.c
* Summary: Ed25519 scalar arithmetic mod L (RFC 8032 / SUPERCOP ref10)
*
*
*****************************************************************************/

/**
 * @file noxtls_ed25519_sc.c
 * @brief Constant-time scalar reduction and muladd modulo L for Ed25519.
 * @ingroup noxtls_ed25519
 *
 * Ported from SUPERCOP crypto_sign/ed25519/ref10 (`sc_reduce`, `sc_muladd`).
 * Order L = 2^252 + 27742317777372353535851937790883648493 (RFC 8032).
 * Wire format at API edges remains little-endian (RFC 8032).
 */

#include "common/noxtls_ct.h"
#include <stdint.h>
#include <string.h>

#include "noxtls_ed25519_sc.h"

/** Mask for a 21-bit scalar limb (ref10 radix 2^21). */
#define NOXTLS_ED25519_SC_LIMB_MASK 2097151ULL

/** Carry bias for interleaved 21-bit carries: 2^20. */
#define NOXTLS_ED25519_SC_CARRY_BIAS INT64_C(1048576)

/** Limb shift for radix-2^21 packing. */
#define NOXTLS_ED25519_SC_LIMB_BITS 21

/* Floor division by 2^21 without implementation-defined signed shifts.
 * The unsigned conversion is defined modulo 2^64; both converted terms fit
 * int64_t. The arithmetic is branch-free for secret scalar values. */
static int64_t sc25519_asr21(int64_t value)
{
    uint64_t bits = (uint64_t)value;
    uint64_t magnitude = bits >> 21U;
    uint64_t correction = (bits >> 63U) << 43U;
    return (int64_t)magnitude - (int64_t)correction;
}

/**
 * @brief Load 3 little-endian bytes as an unsigned 64-bit integer.
 * @internal
 *
 * @param[in] in Input bytes.
 *
 * @return Loaded value.
 */
static uint64_t sc25519_load_3(const uint8_t *in)
{
    uint64_t result;
    result = (uint64_t)in[0];
    result |= ((uint64_t)in[1]) << 8;
    result |= ((uint64_t)in[2]) << 16;
    return result;
}

/**
 * @brief Load 4 little-endian bytes as an unsigned 64-bit integer.
 * @internal
 *
 * @param[in] in Input bytes.
 *
 * @return Loaded value.
 */
static uint64_t sc25519_load_4(const uint8_t *in)
{
    uint64_t result;
    result = (uint64_t)in[0];
    result |= ((uint64_t)in[1]) << 8;
    result |= ((uint64_t)in[2]) << 16;
    result |= ((uint64_t)in[3]) << 24;
    return result;
}

/**
 * @brief In-place reduce a 64-byte little-endian integer modulo L (ref10 sc_reduce).
 * @internal
 *
 * RFC 8032 / SUPERCOP ref10: L = 2^252 + 27742317777372353535851937790883648493.
 * Overwrites the first 32 bytes of @p s with the reduced scalar.
 *
 * @param[in,out] s 64-byte little-endian buffer.
 */
static void sc25519_reduce_inplace(uint8_t *s)
{
  uint64_t s0_u = NOXTLS_ED25519_SC_LIMB_MASK & sc25519_load_3(s);
  int64_t s0 = (int64_t)s0_u;
  uint64_t s1_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&s[2]) >> 5);
  int64_t s1 = (int64_t)s1_u;
  uint64_t s2_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_3(&s[5]) >> 2);
  int64_t s2 = (int64_t)s2_u;
  uint64_t s3_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&s[7]) >> 7);
  int64_t s3 = (int64_t)s3_u;
  uint64_t s4_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&s[10]) >> 4);
  int64_t s4 = (int64_t)s4_u;
  uint64_t s5_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_3(&s[13]) >> 1);
  int64_t s5 = (int64_t)s5_u;
  uint64_t s6_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&s[15]) >> 6);
  int64_t s6 = (int64_t)s6_u;
  uint64_t s7_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_3(&s[18]) >> 3);
  int64_t s7 = (int64_t)s7_u;
  uint64_t s8_u = NOXTLS_ED25519_SC_LIMB_MASK & sc25519_load_3(&s[21]);
  int64_t s8 = (int64_t)s8_u;
  uint64_t s9_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&s[23]) >> 5);
  int64_t s9 = (int64_t)s9_u;
  uint64_t s10_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_3(&s[26]) >> 2);
  int64_t s10 = (int64_t)s10_u;
  uint64_t s11_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&s[28]) >> 7);
  int64_t s11 = (int64_t)s11_u;
  uint64_t s12_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&s[31]) >> 4);
  int64_t s12 = (int64_t)s12_u;
  uint64_t s13_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_3(&s[34]) >> 1);
  int64_t s13 = (int64_t)s13_u;
  uint64_t s14_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&s[36]) >> 6);
  int64_t s14 = (int64_t)s14_u;
  uint64_t s15_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_3(&s[39]) >> 3);
  int64_t s15 = (int64_t)s15_u;
  uint64_t s16_u = NOXTLS_ED25519_SC_LIMB_MASK & sc25519_load_3(&s[42]);
  int64_t s16 = (int64_t)s16_u;
  uint64_t s17_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&s[44]) >> 5);
  int64_t s17 = (int64_t)s17_u;
  uint64_t s18_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_3(&s[47]) >> 2);
  int64_t s18 = (int64_t)s18_u;
  uint64_t s19_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&s[49]) >> 7);
  int64_t s19 = (int64_t)s19_u;
  uint64_t s20_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&s[52]) >> 4);
  int64_t s20 = (int64_t)s20_u;
  uint64_t s21_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_3(&s[55]) >> 1);
  int64_t s21 = (int64_t)s21_u;
  uint64_t s22_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&s[57]) >> 6);
  int64_t s22 = (int64_t)s22_u;
  uint64_t s23_u = (sc25519_load_4(&s[60]) >> 3);
  int64_t s23 = (int64_t)s23_u;
  int64_t carry0;
  int64_t carry1;
  int64_t carry2;
  int64_t carry3;
  int64_t carry4;
  int64_t carry5;
  int64_t carry6;
  int64_t carry7;
  int64_t carry8;
  int64_t carry9;
  int64_t carry10;
  int64_t carry11;
  int64_t carry12;
  int64_t carry13;
  int64_t carry14;
  int64_t carry15;
  int64_t carry16;

  s11 += s23 * 666643;
  s12 += s23 * 470296;
  s13 += s23 * 654183;
  s14 -= s23 * 997805;
  s15 += s23 * 136657;
  s16 -= s23 * 683901;

  s10 += s22 * 666643;
  s11 += s22 * 470296;
  s12 += s22 * 654183;
  s13 -= s22 * 997805;
  s14 += s22 * 136657;
  s15 -= s22 * 683901;

  s9 += s21 * 666643;
  s10 += s21 * 470296;
  s11 += s21 * 654183;
  s12 -= s21 * 997805;
  s13 += s21 * 136657;
  s14 -= s21 * 683901;

  s8 += s20 * 666643;
  s9 += s20 * 470296;
  s10 += s20 * 654183;
  s11 -= s20 * 997805;
  s12 += s20 * 136657;
  s13 -= s20 * 683901;

  s7 += s19 * 666643;
  s8 += s19 * 470296;
  s9 += s19 * 654183;
  s10 -= s19 * 997805;
  s11 += s19 * 136657;
  s12 -= s19 * 683901;

  s6 += s18 * 666643;
  s7 += s18 * 470296;
  s8 += s18 * 654183;
  s9 -= s18 * 997805;
  s10 += s18 * 136657;
  s11 -= s18 * 683901;

  carry6 = sc25519_asr21((s6 + NOXTLS_ED25519_SC_CARRY_BIAS)); s7 += carry6; s6 -= carry6 * INT64_C(2097152);
  carry8 = sc25519_asr21((s8 + NOXTLS_ED25519_SC_CARRY_BIAS)); s9 += carry8; s8 -= carry8 * INT64_C(2097152);
  carry10 = sc25519_asr21((s10 + NOXTLS_ED25519_SC_CARRY_BIAS)); s11 += carry10; s10 -= carry10 * INT64_C(2097152);
  carry12 = sc25519_asr21((s12 + NOXTLS_ED25519_SC_CARRY_BIAS)); s13 += carry12; s12 -= carry12 * INT64_C(2097152);
  carry14 = sc25519_asr21((s14 + NOXTLS_ED25519_SC_CARRY_BIAS)); s15 += carry14; s14 -= carry14 * INT64_C(2097152);
  carry16 = sc25519_asr21((s16 + NOXTLS_ED25519_SC_CARRY_BIAS)); s17 += carry16; s16 -= carry16 * INT64_C(2097152);

  carry7 = sc25519_asr21((s7 + NOXTLS_ED25519_SC_CARRY_BIAS)); s8 += carry7; s7 -= carry7 * INT64_C(2097152);
  carry9 = sc25519_asr21((s9 + NOXTLS_ED25519_SC_CARRY_BIAS)); s10 += carry9; s9 -= carry9 * INT64_C(2097152);
  carry11 = sc25519_asr21((s11 + NOXTLS_ED25519_SC_CARRY_BIAS)); s12 += carry11; s11 -= carry11 * INT64_C(2097152);
  carry13 = sc25519_asr21((s13 + NOXTLS_ED25519_SC_CARRY_BIAS)); s14 += carry13; s13 -= carry13 * INT64_C(2097152);
  carry15 = sc25519_asr21((s15 + NOXTLS_ED25519_SC_CARRY_BIAS)); s16 += carry15; s15 -= carry15 * INT64_C(2097152);

  s5 += s17 * 666643;
  s6 += s17 * 470296;
  s7 += s17 * 654183;
  s8 -= s17 * 997805;
  s9 += s17 * 136657;
  s10 -= s17 * 683901;

  s4 += s16 * 666643;
  s5 += s16 * 470296;
  s6 += s16 * 654183;
  s7 -= s16 * 997805;
  s8 += s16 * 136657;
  s9 -= s16 * 683901;

  s3 += s15 * 666643;
  s4 += s15 * 470296;
  s5 += s15 * 654183;
  s6 -= s15 * 997805;
  s7 += s15 * 136657;
  s8 -= s15 * 683901;

  s2 += s14 * 666643;
  s3 += s14 * 470296;
  s4 += s14 * 654183;
  s5 -= s14 * 997805;
  s6 += s14 * 136657;
  s7 -= s14 * 683901;

  s1 += s13 * 666643;
  s2 += s13 * 470296;
  s3 += s13 * 654183;
  s4 -= s13 * 997805;
  s5 += s13 * 136657;
  s6 -= s13 * 683901;

  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;
  s12 = 0;

  carry0 = sc25519_asr21((s0 + NOXTLS_ED25519_SC_CARRY_BIAS)); s1 += carry0; s0 -= carry0 * INT64_C(2097152);
  carry2 = sc25519_asr21((s2 + NOXTLS_ED25519_SC_CARRY_BIAS)); s3 += carry2; s2 -= carry2 * INT64_C(2097152);
  carry4 = sc25519_asr21((s4 + NOXTLS_ED25519_SC_CARRY_BIAS)); s5 += carry4; s4 -= carry4 * INT64_C(2097152);
  carry6 = sc25519_asr21((s6 + NOXTLS_ED25519_SC_CARRY_BIAS)); s7 += carry6; s6 -= carry6 * INT64_C(2097152);
  carry8 = sc25519_asr21((s8 + NOXTLS_ED25519_SC_CARRY_BIAS)); s9 += carry8; s8 -= carry8 * INT64_C(2097152);
  carry10 = sc25519_asr21((s10 + NOXTLS_ED25519_SC_CARRY_BIAS)); s11 += carry10; s10 -= carry10 * INT64_C(2097152);

  carry1 = sc25519_asr21((s1 + NOXTLS_ED25519_SC_CARRY_BIAS)); s2 += carry1; s1 -= carry1 * INT64_C(2097152);
  carry3 = sc25519_asr21((s3 + NOXTLS_ED25519_SC_CARRY_BIAS)); s4 += carry3; s3 -= carry3 * INT64_C(2097152);
  carry5 = sc25519_asr21((s5 + NOXTLS_ED25519_SC_CARRY_BIAS)); s6 += carry5; s5 -= carry5 * INT64_C(2097152);
  carry7 = sc25519_asr21((s7 + NOXTLS_ED25519_SC_CARRY_BIAS)); s8 += carry7; s7 -= carry7 * INT64_C(2097152);
  carry9 = sc25519_asr21((s9 + NOXTLS_ED25519_SC_CARRY_BIAS)); s10 += carry9; s9 -= carry9 * INT64_C(2097152);
  carry11 = sc25519_asr21((s11 + NOXTLS_ED25519_SC_CARRY_BIAS)); s12 += carry11; s11 -= carry11 * INT64_C(2097152);

  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;
  s12 = 0;

  carry0 = sc25519_asr21(s0); s1 += carry0; s0 -= carry0 * INT64_C(2097152);
  carry1 = sc25519_asr21(s1); s2 += carry1; s1 -= carry1 * INT64_C(2097152);
  carry2 = sc25519_asr21(s2); s3 += carry2; s2 -= carry2 * INT64_C(2097152);
  carry3 = sc25519_asr21(s3); s4 += carry3; s3 -= carry3 * INT64_C(2097152);
  carry4 = sc25519_asr21(s4); s5 += carry4; s4 -= carry4 * INT64_C(2097152);
  carry5 = sc25519_asr21(s5); s6 += carry5; s5 -= carry5 * INT64_C(2097152);
  carry6 = sc25519_asr21(s6); s7 += carry6; s6 -= carry6 * INT64_C(2097152);
  carry7 = sc25519_asr21(s7); s8 += carry7; s7 -= carry7 * INT64_C(2097152);
  carry8 = sc25519_asr21(s8); s9 += carry8; s8 -= carry8 * INT64_C(2097152);
  carry9 = sc25519_asr21(s9); s10 += carry9; s9 -= carry9 * INT64_C(2097152);
  carry10 = sc25519_asr21(s10); s11 += carry10; s10 -= carry10 * INT64_C(2097152);
  carry11 = sc25519_asr21(s11); s12 += carry11; s11 -= carry11 * INT64_C(2097152);

  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;

  carry0 = sc25519_asr21(s0); s1 += carry0; s0 -= carry0 * INT64_C(2097152);
  carry1 = sc25519_asr21(s1); s2 += carry1; s1 -= carry1 * INT64_C(2097152);
  carry2 = sc25519_asr21(s2); s3 += carry2; s2 -= carry2 * INT64_C(2097152);
  carry3 = sc25519_asr21(s3); s4 += carry3; s3 -= carry3 * INT64_C(2097152);
  carry4 = sc25519_asr21(s4); s5 += carry4; s4 -= carry4 * INT64_C(2097152);
  carry5 = sc25519_asr21(s5); s6 += carry5; s5 -= carry5 * INT64_C(2097152);
  carry6 = sc25519_asr21(s6); s7 += carry6; s6 -= carry6 * INT64_C(2097152);
  carry7 = sc25519_asr21(s7); s8 += carry7; s7 -= carry7 * INT64_C(2097152);
  carry8 = sc25519_asr21(s8); s9 += carry8; s8 -= carry8 * INT64_C(2097152);
  carry9 = sc25519_asr21(s9); s10 += carry9; s9 -= carry9 * INT64_C(2097152);
  carry10 = sc25519_asr21(s10); s11 += carry10; s10 -= carry10 * INT64_C(2097152);

  s[0] = (uint8_t)(((uint64_t)s0) >> 0);
  s[1] = (uint8_t)(((uint64_t)s0) >> 8);
  s[2] = (uint8_t)((((uint64_t)s0) >> 16) | (((uint64_t)s1) << 5));
  s[3] = (uint8_t)(((uint64_t)s1) >> 3);
  s[4] = (uint8_t)(((uint64_t)s1) >> 11);
  s[5] = (uint8_t)((((uint64_t)s1) >> 19) | (((uint64_t)s2) << 2));
  s[6] = (uint8_t)(((uint64_t)s2) >> 6);
  s[7] = (uint8_t)((((uint64_t)s2) >> 14) | (((uint64_t)s3) << 7));
  s[8] = (uint8_t)(((uint64_t)s3) >> 1);
  s[9] = (uint8_t)(((uint64_t)s3) >> 9);
  s[10] = (uint8_t)((((uint64_t)s3) >> 17) | (((uint64_t)s4) << 4));
  s[11] = (uint8_t)(((uint64_t)s4) >> 4);
  s[12] = (uint8_t)(((uint64_t)s4) >> 12);
  s[13] = (uint8_t)((((uint64_t)s4) >> 20) | (((uint64_t)s5) << 1));
  s[14] = (uint8_t)(((uint64_t)s5) >> 7);
  s[15] = (uint8_t)((((uint64_t)s5) >> 15) | (((uint64_t)s6) << 6));
  s[16] = (uint8_t)(((uint64_t)s6) >> 2);
  s[17] = (uint8_t)(((uint64_t)s6) >> 10);
  s[18] = (uint8_t)((((uint64_t)s6) >> 18) | (((uint64_t)s7) << 3));
  s[19] = (uint8_t)(((uint64_t)s7) >> 5);
  s[20] = (uint8_t)(((uint64_t)s7) >> 13);
  s[21] = (uint8_t)(((uint64_t)s8) >> 0);
  s[22] = (uint8_t)(((uint64_t)s8) >> 8);
  s[23] = (uint8_t)((((uint64_t)s8) >> 16) | (((uint64_t)s9) << 5));
  s[24] = (uint8_t)(((uint64_t)s9) >> 3);
  s[25] = (uint8_t)(((uint64_t)s9) >> 11);
  s[26] = (uint8_t)((((uint64_t)s9) >> 19) | (((uint64_t)s10) << 2));
  s[27] = (uint8_t)(((uint64_t)s10) >> 6);
  s[28] = (uint8_t)((((uint64_t)s10) >> 14) | (((uint64_t)s11) << 7));
  s[29] = (uint8_t)(((uint64_t)s11) >> 1);
  s[30] = (uint8_t)(((uint64_t)s11) >> 9);
  s[31] = (uint8_t)(((uint64_t)s11) >> 17);
}

/**
 * @brief Compute s = (a*b + c) mod L (ref10 sc_muladd).
 * @internal
 *
 * RFC 8032 §5.1.6: S = (r + k*s) mod L.
 *
 * @param[out] s Output 32-byte little-endian scalar.
 * @param[in] a First factor (32-byte LE).
 * @param[in] b Second factor (32-byte LE).
 * @param[in] c Addend (32-byte LE).
 */
static void sc25519_muladd_inplace(uint8_t *s, const uint8_t *a, const uint8_t *b, const uint8_t *c)
{
  uint64_t a0_u = NOXTLS_ED25519_SC_LIMB_MASK & sc25519_load_3(a);
  int64_t a0 = (int64_t)a0_u;
  uint64_t a1_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&a[2]) >> 5);
  int64_t a1 = (int64_t)a1_u;
  uint64_t a2_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_3(&a[5]) >> 2);
  int64_t a2 = (int64_t)a2_u;
  uint64_t a3_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&a[7]) >> 7);
  int64_t a3 = (int64_t)a3_u;
  uint64_t a4_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&a[10]) >> 4);
  int64_t a4 = (int64_t)a4_u;
  uint64_t a5_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_3(&a[13]) >> 1);
  int64_t a5 = (int64_t)a5_u;
  uint64_t a6_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&a[15]) >> 6);
  int64_t a6 = (int64_t)a6_u;
  uint64_t a7_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_3(&a[18]) >> 3);
  int64_t a7 = (int64_t)a7_u;
  uint64_t a8_u = NOXTLS_ED25519_SC_LIMB_MASK & sc25519_load_3(&a[21]);
  int64_t a8 = (int64_t)a8_u;
  uint64_t a9_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&a[23]) >> 5);
  int64_t a9 = (int64_t)a9_u;
  uint64_t a10_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_3(&a[26]) >> 2);
  int64_t a10 = (int64_t)a10_u;
  uint64_t a11_u = (sc25519_load_4(&a[28]) >> 7);
  int64_t a11 = (int64_t)a11_u;
  uint64_t b0_u = NOXTLS_ED25519_SC_LIMB_MASK & sc25519_load_3(b);
  int64_t b0 = (int64_t)b0_u;
  uint64_t b1_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&b[2]) >> 5);
  int64_t b1 = (int64_t)b1_u;
  uint64_t b2_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_3(&b[5]) >> 2);
  int64_t b2 = (int64_t)b2_u;
  uint64_t b3_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&b[7]) >> 7);
  int64_t b3 = (int64_t)b3_u;
  uint64_t b4_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&b[10]) >> 4);
  int64_t b4 = (int64_t)b4_u;
  uint64_t b5_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_3(&b[13]) >> 1);
  int64_t b5 = (int64_t)b5_u;
  uint64_t b6_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&b[15]) >> 6);
  int64_t b6 = (int64_t)b6_u;
  uint64_t b7_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_3(&b[18]) >> 3);
  int64_t b7 = (int64_t)b7_u;
  uint64_t b8_u = NOXTLS_ED25519_SC_LIMB_MASK & sc25519_load_3(&b[21]);
  int64_t b8 = (int64_t)b8_u;
  uint64_t b9_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&b[23]) >> 5);
  int64_t b9 = (int64_t)b9_u;
  uint64_t b10_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_3(&b[26]) >> 2);
  int64_t b10 = (int64_t)b10_u;
  uint64_t b11_u = (sc25519_load_4(&b[28]) >> 7);
  int64_t b11 = (int64_t)b11_u;
  uint64_t c0_u = NOXTLS_ED25519_SC_LIMB_MASK & sc25519_load_3(c);
  int64_t c0 = (int64_t)c0_u;
  uint64_t c1_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&c[2]) >> 5);
  int64_t c1 = (int64_t)c1_u;
  uint64_t c2_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_3(&c[5]) >> 2);
  int64_t c2 = (int64_t)c2_u;
  uint64_t c3_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&c[7]) >> 7);
  int64_t c3 = (int64_t)c3_u;
  uint64_t c4_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&c[10]) >> 4);
  int64_t c4 = (int64_t)c4_u;
  uint64_t c5_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_3(&c[13]) >> 1);
  int64_t c5 = (int64_t)c5_u;
  uint64_t c6_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&c[15]) >> 6);
  int64_t c6 = (int64_t)c6_u;
  uint64_t c7_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_3(&c[18]) >> 3);
  int64_t c7 = (int64_t)c7_u;
  uint64_t c8_u = NOXTLS_ED25519_SC_LIMB_MASK & sc25519_load_3(&c[21]);
  int64_t c8 = (int64_t)c8_u;
  uint64_t c9_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_4(&c[23]) >> 5);
  int64_t c9 = (int64_t)c9_u;
  uint64_t c10_u = NOXTLS_ED25519_SC_LIMB_MASK & (sc25519_load_3(&c[26]) >> 2);
  int64_t c10 = (int64_t)c10_u;
  uint64_t c11_u = (sc25519_load_4(&c[28]) >> 7);
  int64_t c11 = (int64_t)c11_u;
  int64_t s0;
  int64_t s1;
  int64_t s2;
  int64_t s3;
  int64_t s4;
  int64_t s5;
  int64_t s6;
  int64_t s7;
  int64_t s8;
  int64_t s9;
  int64_t s10;
  int64_t s11;
  int64_t s12;
  int64_t s13;
  int64_t s14;
  int64_t s15;
  int64_t s16;
  int64_t s17;
  int64_t s18;
  int64_t s19;
  int64_t s20;
  int64_t s21;
  int64_t s22;
  int64_t s23;
  int64_t carry0;
  int64_t carry1;
  int64_t carry2;
  int64_t carry3;
  int64_t carry4;
  int64_t carry5;
  int64_t carry6;
  int64_t carry7;
  int64_t carry8;
  int64_t carry9;
  int64_t carry10;
  int64_t carry11;
  int64_t carry12;
  int64_t carry13;
  int64_t carry14;
  int64_t carry15;
  int64_t carry16;
  int64_t carry17;
  int64_t carry18;
  int64_t carry19;
  int64_t carry20;
  int64_t carry21;
  int64_t carry22;

  s0 = c0 + (a0*b0);
  s1 = c1 + (a0*b1) + (a1*b0);
  s2 = c2 + (a0*b2) + (a1*b1) + (a2*b0);
  s3 = c3 + (a0*b3) + (a1*b2) + (a2*b1) + (a3*b0);
  s4 = c4 + (a0*b4) + (a1*b3) + (a2*b2) + (a3*b1) + (a4*b0);
  s5 = c5 + (a0*b5) + (a1*b4) + (a2*b3) + (a3*b2) + (a4*b1) + (a5*b0);
  s6 = c6 + (a0*b6) + (a1*b5) + (a2*b4) + (a3*b3) + (a4*b2) + (a5*b1) + (a6*b0);
  s7 = c7 + (a0*b7) + (a1*b6) + (a2*b5) + (a3*b4) + (a4*b3) + (a5*b2) + (a6*b1) + (a7*b0);
  s8 = c8 + (a0*b8) + (a1*b7) + (a2*b6) + (a3*b5) + (a4*b4) + (a5*b3) + (a6*b2) + (a7*b1) + (a8*b0);
  s9 = c9 + (a0*b9) + (a1*b8) + (a2*b7) + (a3*b6) + (a4*b5) + (a5*b4) + (a6*b3) + (a7*b2) + (a8*b1) + (a9*b0);
  s10 = c10 + (a0*b10) + (a1*b9) + (a2*b8) + (a3*b7) + (a4*b6) + (a5*b5) + (a6*b4) + (a7*b3) + (a8*b2) + (a9*b1) + (a10*b0);
  s11 = c11 + (a0*b11) + (a1*b10) + (a2*b9) + (a3*b8) + (a4*b7) + (a5*b6) + (a6*b5) + (a7*b4) + (a8*b3) + (a9*b2) + (a10*b1) + (a11*b0);
  s12 = (a1*b11) + (a2*b10) + (a3*b9) + (a4*b8) + (a5*b7) + (a6*b6) + (a7*b5) + (a8*b4) + (a9*b3) + (a10*b2) + (a11*b1);
  s13 = (a2*b11) + (a3*b10) + (a4*b9) + (a5*b8) + (a6*b7) + (a7*b6) + (a8*b5) + (a9*b4) + (a10*b3) + (a11*b2);
  s14 = (a3*b11) + (a4*b10) + (a5*b9) + (a6*b8) + (a7*b7) + (a8*b6) + (a9*b5) + (a10*b4) + (a11*b3);
  s15 = (a4*b11) + (a5*b10) + (a6*b9) + (a7*b8) + (a8*b7) + (a9*b6) + (a10*b5) + (a11*b4);
  s16 = (a5*b11) + (a6*b10) + (a7*b9) + (a8*b8) + (a9*b7) + (a10*b6) + (a11*b5);
  s17 = (a6*b11) + (a7*b10) + (a8*b9) + (a9*b8) + (a10*b7) + (a11*b6);
  s18 = (a7*b11) + (a8*b10) + (a9*b9) + (a10*b8) + (a11*b7);
  s19 = (a8*b11) + (a9*b10) + (a10*b9) + (a11*b8);
  s20 = (a9*b11) + (a10*b10) + (a11*b9);
  s21 = (a10*b11) + (a11*b10);
  s22 = (a11*b11);
  s23 = 0;

  carry0 = sc25519_asr21((s0 + NOXTLS_ED25519_SC_CARRY_BIAS)); s1 += carry0; s0 -= carry0 * INT64_C(2097152);
  carry2 = sc25519_asr21((s2 + NOXTLS_ED25519_SC_CARRY_BIAS)); s3 += carry2; s2 -= carry2 * INT64_C(2097152);
  carry4 = sc25519_asr21((s4 + NOXTLS_ED25519_SC_CARRY_BIAS)); s5 += carry4; s4 -= carry4 * INT64_C(2097152);
  carry6 = sc25519_asr21((s6 + NOXTLS_ED25519_SC_CARRY_BIAS)); s7 += carry6; s6 -= carry6 * INT64_C(2097152);
  carry8 = sc25519_asr21((s8 + NOXTLS_ED25519_SC_CARRY_BIAS)); s9 += carry8; s8 -= carry8 * INT64_C(2097152);
  carry10 = sc25519_asr21((s10 + NOXTLS_ED25519_SC_CARRY_BIAS)); s11 += carry10; s10 -= carry10 * INT64_C(2097152);
  carry12 = sc25519_asr21((s12 + NOXTLS_ED25519_SC_CARRY_BIAS)); s13 += carry12; s12 -= carry12 * INT64_C(2097152);
  carry14 = sc25519_asr21((s14 + NOXTLS_ED25519_SC_CARRY_BIAS)); s15 += carry14; s14 -= carry14 * INT64_C(2097152);
  carry16 = sc25519_asr21((s16 + NOXTLS_ED25519_SC_CARRY_BIAS)); s17 += carry16; s16 -= carry16 * INT64_C(2097152);
  carry18 = sc25519_asr21((s18 + NOXTLS_ED25519_SC_CARRY_BIAS)); s19 += carry18; s18 -= carry18 * INT64_C(2097152);
  carry20 = sc25519_asr21((s20 + NOXTLS_ED25519_SC_CARRY_BIAS)); s21 += carry20; s20 -= carry20 * INT64_C(2097152);
  carry22 = sc25519_asr21((s22 + NOXTLS_ED25519_SC_CARRY_BIAS)); s23 += carry22; s22 -= carry22 * INT64_C(2097152);

  carry1 = sc25519_asr21((s1 + NOXTLS_ED25519_SC_CARRY_BIAS)); s2 += carry1; s1 -= carry1 * INT64_C(2097152);
  carry3 = sc25519_asr21((s3 + NOXTLS_ED25519_SC_CARRY_BIAS)); s4 += carry3; s3 -= carry3 * INT64_C(2097152);
  carry5 = sc25519_asr21((s5 + NOXTLS_ED25519_SC_CARRY_BIAS)); s6 += carry5; s5 -= carry5 * INT64_C(2097152);
  carry7 = sc25519_asr21((s7 + NOXTLS_ED25519_SC_CARRY_BIAS)); s8 += carry7; s7 -= carry7 * INT64_C(2097152);
  carry9 = sc25519_asr21((s9 + NOXTLS_ED25519_SC_CARRY_BIAS)); s10 += carry9; s9 -= carry9 * INT64_C(2097152);
  carry11 = sc25519_asr21((s11 + NOXTLS_ED25519_SC_CARRY_BIAS)); s12 += carry11; s11 -= carry11 * INT64_C(2097152);
  carry13 = sc25519_asr21((s13 + NOXTLS_ED25519_SC_CARRY_BIAS)); s14 += carry13; s13 -= carry13 * INT64_C(2097152);
  carry15 = sc25519_asr21((s15 + NOXTLS_ED25519_SC_CARRY_BIAS)); s16 += carry15; s15 -= carry15 * INT64_C(2097152);
  carry17 = sc25519_asr21((s17 + NOXTLS_ED25519_SC_CARRY_BIAS)); s18 += carry17; s17 -= carry17 * INT64_C(2097152);
  carry19 = sc25519_asr21((s19 + NOXTLS_ED25519_SC_CARRY_BIAS)); s20 += carry19; s19 -= carry19 * INT64_C(2097152);
  carry21 = sc25519_asr21((s21 + NOXTLS_ED25519_SC_CARRY_BIAS)); s22 += carry21; s21 -= carry21 * INT64_C(2097152);

  s11 += s23 * 666643;
  s12 += s23 * 470296;
  s13 += s23 * 654183;
  s14 -= s23 * 997805;
  s15 += s23 * 136657;
  s16 -= s23 * 683901;

  s10 += s22 * 666643;
  s11 += s22 * 470296;
  s12 += s22 * 654183;
  s13 -= s22 * 997805;
  s14 += s22 * 136657;
  s15 -= s22 * 683901;

  s9 += s21 * 666643;
  s10 += s21 * 470296;
  s11 += s21 * 654183;
  s12 -= s21 * 997805;
  s13 += s21 * 136657;
  s14 -= s21 * 683901;

  s8 += s20 * 666643;
  s9 += s20 * 470296;
  s10 += s20 * 654183;
  s11 -= s20 * 997805;
  s12 += s20 * 136657;
  s13 -= s20 * 683901;

  s7 += s19 * 666643;
  s8 += s19 * 470296;
  s9 += s19 * 654183;
  s10 -= s19 * 997805;
  s11 += s19 * 136657;
  s12 -= s19 * 683901;

  s6 += s18 * 666643;
  s7 += s18 * 470296;
  s8 += s18 * 654183;
  s9 -= s18 * 997805;
  s10 += s18 * 136657;
  s11 -= s18 * 683901;

  carry6 = sc25519_asr21((s6 + NOXTLS_ED25519_SC_CARRY_BIAS)); s7 += carry6; s6 -= carry6 * INT64_C(2097152);
  carry8 = sc25519_asr21((s8 + NOXTLS_ED25519_SC_CARRY_BIAS)); s9 += carry8; s8 -= carry8 * INT64_C(2097152);
  carry10 = sc25519_asr21((s10 + NOXTLS_ED25519_SC_CARRY_BIAS)); s11 += carry10; s10 -= carry10 * INT64_C(2097152);
  carry12 = sc25519_asr21((s12 + NOXTLS_ED25519_SC_CARRY_BIAS)); s13 += carry12; s12 -= carry12 * INT64_C(2097152);
  carry14 = sc25519_asr21((s14 + NOXTLS_ED25519_SC_CARRY_BIAS)); s15 += carry14; s14 -= carry14 * INT64_C(2097152);
  carry16 = sc25519_asr21((s16 + NOXTLS_ED25519_SC_CARRY_BIAS)); s17 += carry16; s16 -= carry16 * INT64_C(2097152);

  carry7 = sc25519_asr21((s7 + NOXTLS_ED25519_SC_CARRY_BIAS)); s8 += carry7; s7 -= carry7 * INT64_C(2097152);
  carry9 = sc25519_asr21((s9 + NOXTLS_ED25519_SC_CARRY_BIAS)); s10 += carry9; s9 -= carry9 * INT64_C(2097152);
  carry11 = sc25519_asr21((s11 + NOXTLS_ED25519_SC_CARRY_BIAS)); s12 += carry11; s11 -= carry11 * INT64_C(2097152);
  carry13 = sc25519_asr21((s13 + NOXTLS_ED25519_SC_CARRY_BIAS)); s14 += carry13; s13 -= carry13 * INT64_C(2097152);
  carry15 = sc25519_asr21((s15 + NOXTLS_ED25519_SC_CARRY_BIAS)); s16 += carry15; s15 -= carry15 * INT64_C(2097152);

  s5 += s17 * 666643;
  s6 += s17 * 470296;
  s7 += s17 * 654183;
  s8 -= s17 * 997805;
  s9 += s17 * 136657;
  s10 -= s17 * 683901;

  s4 += s16 * 666643;
  s5 += s16 * 470296;
  s6 += s16 * 654183;
  s7 -= s16 * 997805;
  s8 += s16 * 136657;
  s9 -= s16 * 683901;

  s3 += s15 * 666643;
  s4 += s15 * 470296;
  s5 += s15 * 654183;
  s6 -= s15 * 997805;
  s7 += s15 * 136657;
  s8 -= s15 * 683901;

  s2 += s14 * 666643;
  s3 += s14 * 470296;
  s4 += s14 * 654183;
  s5 -= s14 * 997805;
  s6 += s14 * 136657;
  s7 -= s14 * 683901;

  s1 += s13 * 666643;
  s2 += s13 * 470296;
  s3 += s13 * 654183;
  s4 -= s13 * 997805;
  s5 += s13 * 136657;
  s6 -= s13 * 683901;

  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;
  s12 = 0;

  carry0 = sc25519_asr21((s0 + NOXTLS_ED25519_SC_CARRY_BIAS)); s1 += carry0; s0 -= carry0 * INT64_C(2097152);
  carry2 = sc25519_asr21((s2 + NOXTLS_ED25519_SC_CARRY_BIAS)); s3 += carry2; s2 -= carry2 * INT64_C(2097152);
  carry4 = sc25519_asr21((s4 + NOXTLS_ED25519_SC_CARRY_BIAS)); s5 += carry4; s4 -= carry4 * INT64_C(2097152);
  carry6 = sc25519_asr21((s6 + NOXTLS_ED25519_SC_CARRY_BIAS)); s7 += carry6; s6 -= carry6 * INT64_C(2097152);
  carry8 = sc25519_asr21((s8 + NOXTLS_ED25519_SC_CARRY_BIAS)); s9 += carry8; s8 -= carry8 * INT64_C(2097152);
  carry10 = sc25519_asr21((s10 + NOXTLS_ED25519_SC_CARRY_BIAS)); s11 += carry10; s10 -= carry10 * INT64_C(2097152);

  carry1 = sc25519_asr21((s1 + NOXTLS_ED25519_SC_CARRY_BIAS)); s2 += carry1; s1 -= carry1 * INT64_C(2097152);
  carry3 = sc25519_asr21((s3 + NOXTLS_ED25519_SC_CARRY_BIAS)); s4 += carry3; s3 -= carry3 * INT64_C(2097152);
  carry5 = sc25519_asr21((s5 + NOXTLS_ED25519_SC_CARRY_BIAS)); s6 += carry5; s5 -= carry5 * INT64_C(2097152);
  carry7 = sc25519_asr21((s7 + NOXTLS_ED25519_SC_CARRY_BIAS)); s8 += carry7; s7 -= carry7 * INT64_C(2097152);
  carry9 = sc25519_asr21((s9 + NOXTLS_ED25519_SC_CARRY_BIAS)); s10 += carry9; s9 -= carry9 * INT64_C(2097152);
  carry11 = sc25519_asr21((s11 + NOXTLS_ED25519_SC_CARRY_BIAS)); s12 += carry11; s11 -= carry11 * INT64_C(2097152);

  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;
  s12 = 0;

  carry0 = sc25519_asr21(s0); s1 += carry0; s0 -= carry0 * INT64_C(2097152);
  carry1 = sc25519_asr21(s1); s2 += carry1; s1 -= carry1 * INT64_C(2097152);
  carry2 = sc25519_asr21(s2); s3 += carry2; s2 -= carry2 * INT64_C(2097152);
  carry3 = sc25519_asr21(s3); s4 += carry3; s3 -= carry3 * INT64_C(2097152);
  carry4 = sc25519_asr21(s4); s5 += carry4; s4 -= carry4 * INT64_C(2097152);
  carry5 = sc25519_asr21(s5); s6 += carry5; s5 -= carry5 * INT64_C(2097152);
  carry6 = sc25519_asr21(s6); s7 += carry6; s6 -= carry6 * INT64_C(2097152);
  carry7 = sc25519_asr21(s7); s8 += carry7; s7 -= carry7 * INT64_C(2097152);
  carry8 = sc25519_asr21(s8); s9 += carry8; s8 -= carry8 * INT64_C(2097152);
  carry9 = sc25519_asr21(s9); s10 += carry9; s9 -= carry9 * INT64_C(2097152);
  carry10 = sc25519_asr21(s10); s11 += carry10; s10 -= carry10 * INT64_C(2097152);
  carry11 = sc25519_asr21(s11); s12 += carry11; s11 -= carry11 * INT64_C(2097152);

  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;

  carry0 = sc25519_asr21(s0); s1 += carry0; s0 -= carry0 * INT64_C(2097152);
  carry1 = sc25519_asr21(s1); s2 += carry1; s1 -= carry1 * INT64_C(2097152);
  carry2 = sc25519_asr21(s2); s3 += carry2; s2 -= carry2 * INT64_C(2097152);
  carry3 = sc25519_asr21(s3); s4 += carry3; s3 -= carry3 * INT64_C(2097152);
  carry4 = sc25519_asr21(s4); s5 += carry4; s4 -= carry4 * INT64_C(2097152);
  carry5 = sc25519_asr21(s5); s6 += carry5; s5 -= carry5 * INT64_C(2097152);
  carry6 = sc25519_asr21(s6); s7 += carry6; s6 -= carry6 * INT64_C(2097152);
  carry7 = sc25519_asr21(s7); s8 += carry7; s7 -= carry7 * INT64_C(2097152);
  carry8 = sc25519_asr21(s8); s9 += carry8; s8 -= carry8 * INT64_C(2097152);
  carry9 = sc25519_asr21(s9); s10 += carry9; s9 -= carry9 * INT64_C(2097152);
  carry10 = sc25519_asr21(s10); s11 += carry10; s10 -= carry10 * INT64_C(2097152);

  s[0] = (uint8_t)(((uint64_t)s0) >> 0);
  s[1] = (uint8_t)(((uint64_t)s0) >> 8);
  s[2] = (uint8_t)((((uint64_t)s0) >> 16) | (((uint64_t)s1) << 5));
  s[3] = (uint8_t)(((uint64_t)s1) >> 3);
  s[4] = (uint8_t)(((uint64_t)s1) >> 11);
  s[5] = (uint8_t)((((uint64_t)s1) >> 19) | (((uint64_t)s2) << 2));
  s[6] = (uint8_t)(((uint64_t)s2) >> 6);
  s[7] = (uint8_t)((((uint64_t)s2) >> 14) | (((uint64_t)s3) << 7));
  s[8] = (uint8_t)(((uint64_t)s3) >> 1);
  s[9] = (uint8_t)(((uint64_t)s3) >> 9);
  s[10] = (uint8_t)((((uint64_t)s3) >> 17) | (((uint64_t)s4) << 4));
  s[11] = (uint8_t)(((uint64_t)s4) >> 4);
  s[12] = (uint8_t)(((uint64_t)s4) >> 12);
  s[13] = (uint8_t)((((uint64_t)s4) >> 20) | (((uint64_t)s5) << 1));
  s[14] = (uint8_t)(((uint64_t)s5) >> 7);
  s[15] = (uint8_t)((((uint64_t)s5) >> 15) | (((uint64_t)s6) << 6));
  s[16] = (uint8_t)(((uint64_t)s6) >> 2);
  s[17] = (uint8_t)(((uint64_t)s6) >> 10);
  s[18] = (uint8_t)((((uint64_t)s6) >> 18) | (((uint64_t)s7) << 3));
  s[19] = (uint8_t)(((uint64_t)s7) >> 5);
  s[20] = (uint8_t)(((uint64_t)s7) >> 13);
  s[21] = (uint8_t)(((uint64_t)s8) >> 0);
  s[22] = (uint8_t)(((uint64_t)s8) >> 8);
  s[23] = (uint8_t)((((uint64_t)s8) >> 16) | (((uint64_t)s9) << 5));
  s[24] = (uint8_t)(((uint64_t)s9) >> 3);
  s[25] = (uint8_t)(((uint64_t)s9) >> 11);
  s[26] = (uint8_t)((((uint64_t)s9) >> 19) | (((uint64_t)s10) << 2));
  s[27] = (uint8_t)(((uint64_t)s10) >> 6);
  s[28] = (uint8_t)((((uint64_t)s10) >> 14) | (((uint64_t)s11) << 7));
  s[29] = (uint8_t)(((uint64_t)s11) >> 1);
  s[30] = (uint8_t)(((uint64_t)s11) >> 9);
  s[31] = (uint8_t)(((uint64_t)s11) >> 17);
}

/**
 * @brief Reduce a 64-byte little-endian integer modulo L into 32 LE bytes.
 *
 * @param[out] out_le Reduced 32-byte little-endian scalar.
 * @param[in] in_le 64-byte little-endian input (e.g. SHA-512 digest).
 */
void sc25519_reduce(uint8_t *out_le,
                    const uint8_t *in_le)
{
    uint8_t tmp[NOXTLS_ED25519_SHA512_DIGEST_BYTES];

    noxtls_copy_u8((uint8_t *)(void *)(tmp), (size_t)(NOXTLS_ED25519_SHA512_DIGEST_BYTES), (const uint8_t *)(const void *)(in_le), (size_t)(NOXTLS_ED25519_SHA512_DIGEST_BYTES));
    sc25519_reduce_inplace(tmp);
    noxtls_copy_u8((uint8_t *)(void *)(out_le), (size_t)(NOXTLS_ED25519_FE25519_BYTES), (const uint8_t *)(const void *)(tmp), (size_t)(NOXTLS_ED25519_FE25519_BYTES));
}

/**
 * @brief Compute out = (a*b + c) mod L in little-endian wire format.
 *
 * @param[out] out_le Resulting 32-byte little-endian scalar.
 * @param[in] a_le First factor.
 * @param[in] b_le Second factor.
 * @param[in] c_le Addend.
 */
void sc25519_muladd(uint8_t *out_le,
                    const uint8_t *a_le,
                    const uint8_t *b_le,
                    const uint8_t *c_le)
{
    sc25519_muladd_inplace(out_le, a_le, b_le, c_le);
}
