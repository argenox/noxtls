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
* File:    noxtls_ed25519_fe_arm.c
* Summary: Packed 8×uint32 FE helpers; Cortex-M4/M7 uses Haase CC0 asm mul/sqr
*
* On ARMv7E-M / ARMv8-M Mainline, field mul/sq route through Björn Haase's
* packed UMAAL assembly (CC0-1.0) after a fast limb→u32 pack (carry + bit
* pack, no full canonical reduction). Portable schoolbook remains for host
* tests and non-ARM targets.
*
*****************************************************************************/

/**
 * @file noxtls_ed25519_fe_arm.c
 * @brief Packed 8×uint32 field multiply/square for Ed25519 (ARM + portable).
 * @ingroup noxtls_ed25519
 */

#include <string.h>

#include "noxtls_ed25519_config.h"
#include "noxtls_ed25519_fe_arm.h"

/** Clear bit 255 when packing/unpacking 8×uint32 field elements. */
#define FE25519_U32_BIT255_MASK 0x7FFFFFFFu
/** Reduction constant: 2^256 ≡ 38 (mod 2^255-19). */
#define FE25519_U32_RED_38      38u
/** Reduction constant: 2^255 ≡ 19 (mod 2^255-19). */
#define FE25519_U32_RED_19      19u

/**
 * @brief Store one little-endian uint32 into four bytes.
 * @internal
 */
static void fe25519_store32_le(uint8_t *dst, uint32_t v)
{
    dst[0] = (uint8_t)v;
    dst[1] = (uint8_t)(v >> 8);
    dst[2] = (uint8_t)(v >> 16);
    dst[3] = (uint8_t)(v >> 24);
}

/**
 * @brief Load one little-endian uint32 from four bytes.
 * @internal
 */
static uint32_t fe25519_arm_load32_le(const uint8_t *src)
{
    return ((uint32_t)src[0]) |
           ((uint32_t)src[1] << 8) |
           ((uint32_t)src[2] << 16) |
           ((uint32_t)src[3] << 24);
}

/**
 * @brief Carry-reduce limbs then pack to 32 LE bytes (no canonical q step).
 * @internal
 *
 * Same final carry schedule as fe_mul / fe_tobytes after the q fold — enough
 * for a weakly reduced 255-bit encoding suitable as Haase asm input.
 */
static void fe25519_limbs_pack_le_fast(uint8_t out[NOXTLS_ED25519_FE25519_BYTES],
                                       const fe25519_native_t *in)
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

void fe25519_limbs_to_u32(uint32_t out[8], const fe25519_native_t *in)
{
    uint8_t le[NOXTLS_ED25519_FE25519_BYTES];
    uint32_t i;

    fe25519_limbs_pack_le_fast(le, in);
    for(i = 0U; i < 8U; i++) {
        out[i] = fe25519_arm_load32_le(le + (4U * i));
    }
    out[7] &= FE25519_U32_BIT255_MASK;
}

void fe25519_u32_to_limbs(fe25519_native_t *out, const uint32_t in[8])
{
    uint8_t le[NOXTLS_ED25519_FE25519_BYTES];
    uint32_t tmp[8];
    uint32_t i;

    memcpy(tmp, in, sizeof(tmp));
    tmp[7] &= FE25519_U32_BIT255_MASK;
    for(i = 0U; i < 8U; i++) {
        fe25519_store32_le(le + (4U * i), tmp[i]);
    }
    fe25519_native_from_le(out, le);
}

/**
 * @brief Weak-reduce a 512-bit product into 8 limbs with bit 255 clear.
 * @internal
 */
static void fe25519_u32_reduce_512(uint32_t out[8], const uint32_t t[16])
{
    uint64_t c;
    uint32_t i;
    uint32_t r[8];
    uint32_t msb;

    c = 0U;
    for(i = 0U; i < 8U; i++) {
        c += (uint64_t)t[i] + ((uint64_t)FE25519_U32_RED_38 * (uint64_t)t[i + 8U]);
        r[i] = (uint32_t)c;
        c >>= 32;
    }
    c *= (uint64_t)FE25519_U32_RED_38;
    for(i = 0U; i < 8U; i++) {
        c += (uint64_t)r[i];
        r[i] = (uint32_t)c;
        c >>= 32;
    }
    if(c != 0U) {
        c *= (uint64_t)FE25519_U32_RED_38;
        for(i = 0U; i < 8U; i++) {
            c += (uint64_t)r[i];
            r[i] = (uint32_t)c;
            c >>= 32;
        }
    }

    msb = r[7] >> 31;
    r[7] &= FE25519_U32_BIT255_MASK;
    c = (uint64_t)msb * (uint64_t)FE25519_U32_RED_19;
    for(i = 0U; i < 8U; i++) {
        c += (uint64_t)r[i];
        out[i] = (uint32_t)c;
        c >>= 32;
    }
    if((out[7] & 0x80000000u) != 0U) {
        msb = out[7] >> 31;
        out[7] &= FE25519_U32_BIT255_MASK;
        c = (uint64_t)msb * (uint64_t)FE25519_U32_RED_19;
        for(i = 0U; i < 8U; i++) {
            c += (uint64_t)out[i];
            out[i] = (uint32_t)c;
            c >>= 32;
        }
    }
}

/**
 * @brief Portable schoolbook 8×8 → 16 limb multiply (uint64 accumulators).
 * @internal
 */
static void fe25519_u32_mul_schoolbook(uint32_t t[16],
                                       const uint32_t a[8],
                                       const uint32_t b[8])
{
    uint64_t acc;
    uint32_t i;
    uint32_t j;

    for(i = 0U; i < 16U; i++) {
        t[i] = 0U;
    }
    for(i = 0U; i < 8U; i++) {
        acc = 0U;
        for(j = 0U; j < 8U; j++) {
            acc += (uint64_t)t[i + j] + ((uint64_t)a[i] * (uint64_t)b[j]);
            t[i + j] = (uint32_t)acc;
            acc >>= 32;
        }
        t[i + 8U] = (uint32_t)acc;
    }
}

void fe25519_u32_mul(uint32_t out[8], const uint32_t a[8], const uint32_t b[8])
{
    uint32_t t[16];
    uint32_t aa[8];
    uint32_t bb[8];

    memcpy(aa, a, sizeof(aa));
    memcpy(bb, b, sizeof(bb));
    fe25519_u32_mul_schoolbook(t, aa, bb);
    fe25519_u32_reduce_512(out, t);
}

void fe25519_u32_sqr(uint32_t out[8], const uint32_t a[8])
{
    uint32_t t[16];
    uint32_t aa[8];

    memcpy(aa, a, sizeof(aa));
    fe25519_u32_mul_schoolbook(t, aa, aa);
    fe25519_u32_reduce_512(out, t);
}

#if (defined(__ARM_ARCH_7EM__) || defined(__ARM_ARCH_8M_MAIN__)) && \
    defined(NOXTLS_ED25519_FE_USE_HAASE_ASM)

/* Björn Haase CC0 Cortex-M4 packed mul/sqr (see asm/noxtls_fe25519_*_armv7em.S). */
void fe25519_mul_asm(uint32_t out[8], const uint32_t a[8], const uint32_t b[8]);
void fe25519_square_asm(uint32_t out[8], const uint32_t a[8]);

/**
 * @brief Double a packed field element with weak reduction (bit 255 clear).
 * @internal
 */
static void fe25519_u32_dbl_reduce(uint32_t x[8])
{
    uint64_t c = 0U;
    uint32_t i;
    uint32_t msb;

    for(i = 0U; i < 8U; i++) {
        c += ((uint64_t)x[i]) << 1;
        x[i] = (uint32_t)c;
        c >>= 32;
    }
    if(c != 0U) {
        c *= (uint64_t)FE25519_U32_RED_38;
        for(i = 0U; i < 8U; i++) {
            c += (uint64_t)x[i];
            x[i] = (uint32_t)c;
            c >>= 32;
        }
    }
    msb = x[7] >> 31;
    x[7] &= FE25519_U32_BIT255_MASK;
    c = (uint64_t)msb * (uint64_t)FE25519_U32_RED_19;
    for(i = 0U; i < 8U; i++) {
        c += (uint64_t)x[i];
        x[i] = (uint32_t)c;
        c >>= 32;
    }
}

void fe25519_native_mul(fe25519_native_t *out,
                        const fe25519_native_t *a,
                        const fe25519_native_t *b)
{
    uint32_t aa[8];
    uint32_t bb[8];
    uint32_t rr[8];

    fe25519_limbs_to_u32(aa, a);
    fe25519_limbs_to_u32(bb, b);
    fe25519_mul_asm(rr, aa, bb);
    fe25519_u32_to_limbs(out, rr);
}

void fe25519_native_sq(fe25519_native_t *out, const fe25519_native_t *a)
{
    uint32_t aa[8];
    uint32_t rr[8];

    fe25519_limbs_to_u32(aa, a);
    fe25519_square_asm(rr, aa);
    fe25519_u32_to_limbs(out, rr);
}

void fe25519_native_sq2(fe25519_native_t *out, const fe25519_native_t *a)
{
    uint32_t aa[8];
    uint32_t rr[8];

    fe25519_limbs_to_u32(aa, a);
    fe25519_square_asm(rr, aa);
    fe25519_u32_dbl_reduce(rr);
    fe25519_u32_to_limbs(out, rr);
}

#endif /* ARM + NOXTLS_ED25519_FE_USE_HAASE_ASM */
