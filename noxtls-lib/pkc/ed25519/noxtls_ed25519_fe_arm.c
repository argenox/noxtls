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
* Summary: Packed 8×uint32 FE helpers; Cortex-M4/M7 packed UMAAL asm mul/sqr
*
* On ARMv7E-M / ARMv8-M Mainline, field mul/sq route through public-domain
* packed UMAAL assembly after canonical limb-to-u32 packing. Portable schoolbook remains for host tests
* and non-ARM targets.
*
*****************************************************************************/

/**
 * @file noxtls_ed25519_fe_arm.c
 * @brief Packed 8×uint32 field multiply/square for Ed25519 (ARM + portable).
 * @ingroup noxtls_ed25519
 */

#include "common/noxtls_ct.h"
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
 * @brief Fold bit 255 of a 256-bit value into the low words (2^255 = 19 mod p).
 * @internal
 *
 * Two passes: the first can carry back into bit 255 only when the value was
 * within 19 of 2^256; the second then leaves bit 255 clear.
 *
 * @param[in,out] x Eight little-endian words.
 */
static void fe25519_u32_fold255(uint32_t x[8])
{
    uint32_t pass;
    uint32_t i;

    for(pass = 0U; pass < 2U; pass++) {
        uint64_t c = (uint64_t)(x[7] >> 31) * (uint64_t)FE25519_U32_RED_19;

        x[7] &= FE25519_U32_BIT255_MASK;
        for(i = 0U; i < 8U; i++) {
            c += (uint64_t)x[i];
            x[i] = (uint32_t)c;
            c >>= 32;
        }
    }
}

void fe25519_limbs_to_u32(uint32_t *out, const fe25519_native_t *in)
{
    uint8_t le[NOXTLS_ED25519_FE25519_BYTES];
    uint32_t i;

    /* Canonical encoding (< p, bit 255 clear). The limbs carry signed values
     * after add / sub, so a pack without the full carry and q step can emit
     * wrong bytes. */
    fe25519_native_to_le(le, in);
    for(i = 0U; i < 8U; i++) {
        out[i] = fe25519_arm_load32_le(&le[4U * i]);
    }
}

void fe25519_u32_to_limbs(fe25519_native_t *out, const uint32_t *in)
{
    uint8_t le[NOXTLS_ED25519_FE25519_BYTES];
    uint32_t tmp[8];
    uint32_t i;

    noxtls_copy_u8((uint8_t *)(void *)(tmp), (size_t)(sizeof(tmp)), (const uint8_t *)(const void *)(in), (size_t)(sizeof(tmp)));
    /* The packed asm returns a value below 2^256, not 2^255: fold bit 255
     * (2^255 = 19 mod p) instead of dropping it. */
    fe25519_u32_fold255(tmp);
    for(i = 0U; i < 8U; i++) {
        fe25519_store32_le(&le[4U * i], tmp[i]);
    }
    fe25519_native_from_le(out, le);
}

/**
 * @brief Weak-reduce a 512-bit product into 8 limbs with bit 255 clear.
 * @internal
 */
static void fe25519_u32_reduce_512(uint32_t *out, const uint32_t *t)
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
static void fe25519_u32_mul_schoolbook(uint32_t *t,
                                       const uint32_t *a,
                                       const uint32_t *b)
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

void fe25519_u32_mul(uint32_t *out, const uint32_t *a, const uint32_t *b)
{
    uint32_t t[16];
    uint32_t aa[8];
    uint32_t bb[8];

    noxtls_copy_u8((uint8_t *)(void *)(aa), (size_t)(sizeof(aa)), (const uint8_t *)(const void *)(a), (size_t)(sizeof(aa)));
    noxtls_copy_u8((uint8_t *)(void *)(bb), (size_t)(sizeof(bb)), (const uint8_t *)(const void *)(b), (size_t)(sizeof(bb)));
    fe25519_u32_mul_schoolbook(t, aa, bb);
    fe25519_u32_reduce_512(out, t);
}

void fe25519_u32_sqr(uint32_t *out, const uint32_t *a)
{
    uint32_t t[16];
    uint32_t aa[8];

    noxtls_copy_u8((uint8_t *)(void *)(aa), (size_t)(sizeof(aa)), (const uint8_t *)(const void *)(a), (size_t)(sizeof(aa)));
    fe25519_u32_mul_schoolbook(t, aa, aa);
    fe25519_u32_reduce_512(out, t);
}

#if (defined(__ARM_ARCH_7EM__) || defined(__ARM_ARCH_8M_MAIN__)) && \
    defined(NOXTLS_ED25519_FE_USE_PACKED_ASM)

/* Public-domain Cortex-M4 packed mul/sqr (see asm/noxtls_fe25519_*_armv7em.S). */
void fe25519_mul_asm(uint32_t *out, const uint32_t *a, const uint32_t *b);
void fe25519_square_asm(uint32_t *out, const uint32_t *a);

/**
 * @brief Double a packed field element with weak reduction (bit 255 clear).
 * @internal
 */
static void fe25519_u32_dbl_reduce(uint32_t *x)
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

#endif /* ARM + NOXTLS_ED25519_FE_USE_PACKED_ASM */
