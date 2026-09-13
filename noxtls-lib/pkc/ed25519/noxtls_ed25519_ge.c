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
* File:    noxtls_ed25519_ge.c
* Summary: Ed25519 group arithmetic with native field limbs (RFC 8032)
*
*
*****************************************************************************/

/**
 * @file noxtls_ed25519_ge.c
 * @brief Extended Edwards group ops, ref10 fixed-base, sliding double-scalar (RFC 8032).
 * @ingroup noxtls_ed25519
 */

#include <string.h>

#include "common/noxtls_memory.h"
#include "noxtls_ed25519_ge.h"

/* p = 2^255 - 19, big-endian (RFC 8032). */
static const uint8_t ed25519_p[NOXTLS_ED25519_FE25519_BYTES] = {
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xED
};

/* d = -121665/121666 mod p (twisted Edwards), big-endian (RFC 8032). */
static const uint8_t ed25519_d[NOXTLS_ED25519_FE25519_BYTES] = {
    0x52, 0x03, 0x6C, 0xEE, 0x2B, 0x6F, 0xFE, 0x73,
    0x8C, 0xC7, 0x40, 0x79, 0x77, 0x79, 0xE8, 0x98,
    0x00, 0x70, 0x0A, 0x4D, 0x41, 0x41, 0xD8, 0xAB,
    0x75, 0xEB, 0x4D, 0xCA, 0x13, 0x59, 0x78, 0xA3
};

/* sqrt(-1) mod p for the RFC 8032 §5.1.3 twist case, big-endian. */
static const uint8_t ed25519_sqrt_minus1[NOXTLS_ED25519_FE25519_BYTES] = {
    0x2b, 0x83, 0x24, 0x80, 0x4f, 0xc1, 0xdf, 0x0b,
    0x2b, 0x4d, 0x00, 0x99, 0x3d, 0xfb, 0xd7, 0xa7,
    0x2f, 0x43, 0x18, 0x06, 0xad, 0x2f, 0xe4, 0x78,
    0xc4, 0xee, 0x1b, 0x27, 0x4a, 0x0e, 0xa0, 0xb0
};

/* Base point B encoding (32 bytes LE) per RFC 8032. */
static const uint8_t ed25519_B_encoded[NOXTLS_ED25519_FE25519_BYTES] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
};

/** Completed (p1p1) intermediate: X:Y:Z:T before conversion to extended. */
typedef struct
{
    fe25519_native_t X;
    fe25519_native_t Y;
    fe25519_native_t Z;
    fe25519_native_t T;
} ge25519_p1p1_t;

/** Projective (p2) point: (X:Y:Z) with x=X/Z, y=Y/Z (ref10 ge_p2). */
typedef struct
{
    fe25519_native_t X;
    fe25519_native_t Y;
    fe25519_native_t Z;
} ge25519_p2_t;

static void ge25519_p2_dbl_p1p1(ge25519_p1p1_t *r, const ge25519_p2_t *p);
static void ge25519_p1p1_to_p2(ge25519_p2_t *r, const ge25519_p1p1_t *p);
void ge25519_scalarmult_base_n(ge25519_n_t *R, const uint8_t s_le[NOXTLS_ED25519_FE25519_BYTES]);

/** Duif precomputed (affine-like): y+x, y-x, 2d*x*y (SUPERCOP/ref10 ge_precomp). */
typedef struct
{
    fe25519_native_t yplusx;
    fe25519_native_t yminusx;
    fe25519_native_t xy2d;
} ge25519_precomp_t;

/** Cached extended for variable-base add (ref10 ge_cached). */
typedef struct
{
    fe25519_native_t YplusX;
    fe25519_native_t YminusX;
    fe25519_native_t Z;
    fe25519_native_t T2d;
} ge25519_cached_t;

static fe25519_native_t g_ed25519_d;
static fe25519_native_t g_ed25519_d2;
static fe25519_native_t g_ed25519_sqrtm1;
static int g_ed25519_curve_ready;

#if defined(NOXTLS_ED25519_DUMP_BASE)
/* Mutable tables filled then dumped by host tool (NOXTLS_ED25519_DUMP_BASE). */
static ge25519_precomp_t g_base_bi[NOXTLS_ED25519_BASE_POS_COUNT][NOXTLS_ED25519_BASE_ODD_COUNT];
static int g_base_bi_ready;
static ge25519_precomp_t g_base_odd[NOXTLS_ED25519_SLIDE_ODD_COUNT];
static int g_base_odd_ready;
static ge25519_precomp_t g_base_comb[NOXTLS_ED25519_COMB_BLOCKS][NOXTLS_ED25519_COMB_POINTS];
static int g_base_comb_ready;
#elif defined(NOXTLS_ED25519_SMALL_BASE)
static ge25519_n_t g_base_table_small[NOXTLS_ED25519_SCALAR_TABLE_ENTRIES];
static int g_base_table_small_ready;
static ge25519_precomp_t g_base_odd[NOXTLS_ED25519_SLIDE_ODD_COUNT];
static int g_base_odd_ready;
#else
/* Comb + verify odd-B tables: lazy BSS (flash dump can replace later). */
static ge25519_precomp_t g_base_comb[NOXTLS_ED25519_COMB_BLOCKS][NOXTLS_ED25519_COMB_POINTS];
static int g_base_comb_ready;
static ge25519_precomp_t g_base_odd[NOXTLS_ED25519_SLIDE_ODD_COUNT];
static int g_base_odd_ready;
#endif

/**
 * @brief Compare two big-endian byte strings.
 * @internal
 *
 * @param[in] a First buffer.
 * @param[in] b Second buffer.
 * @param[in] len Length in bytes.
 *
 * @return Negative, zero, or positive as for memcmp-style ordering.
 */
static int ed25519_cmp_be(const uint8_t *a, const uint8_t *b, uint32_t len)
{
    uint32_t i;
    for(i = 0U; i < len; i++) {
        if(a[i] != b[i]) {
            return (a[i] > b[i]) ? 1 : -1;
        }
    }
    return 0;
}

/**
 * @brief Lazy-init curve constants d, 2d, and sqrt(-1) in native form.
 * @internal
 */
static void ed25519_curve_constants_init(void)
{
    if(g_ed25519_curve_ready != 0) {
        return;
    }
    fe25519_native_from_be(&g_ed25519_d, ed25519_d);
    fe25519_native_add(&g_ed25519_d2, &g_ed25519_d, &g_ed25519_d);
    fe25519_native_from_be(&g_ed25519_sqrtm1, ed25519_sqrt_minus1);
    g_ed25519_curve_ready = 1;
}

/**
 * @brief Constant-time equality of unsigned indices (0 or 1 result).
 * @internal
 *
 * @param[in] x First index.
 * @param[in] y Second index.
 *
 * @return 1 if equal, else 0.
 */
static unsigned int ge25519_ct_eq_u32(uint32_t x, uint32_t y)
{
    uint32_t d = x ^ y;
    return (unsigned int)(((uint32_t)(d - 1U) & (uint32_t)(~d)) >> 31);
}

/**
 * @brief Constant-time equality of signed chars treated as bytes.
 * @internal
 *
 * @param[in] b First value.
 * @param[in] c Second value.
 *
 * @return 1 if equal, else 0.
 */
static unsigned int ge25519_ct_equal_u8(uint8_t b, uint8_t c)
{
    return ge25519_ct_eq_u32((uint32_t)b, (uint32_t)c);
}

/**
 * @brief Constant-time conditional move of a native group element.
 * @internal
 *
 * @param[in,out] t Destination.
 * @param[in] u Source.
 * @param[in] b Selector (0 or 1).
 */
static void ge25519_n_cmov(ge25519_n_t *t, const ge25519_n_t *u, unsigned int b)
{
    fe25519_native_cmov(&t->X, &u->X, b);
    fe25519_native_cmov(&t->Y, &u->Y, b);
    fe25519_native_cmov(&t->Z, &u->Z, b);
    fe25519_native_cmov(&t->T, &u->T, b);
}

/**
 * @brief Constant-time conditional move of a precomp element.
 * @internal
 *
 * @param[in,out] t Destination.
 * @param[in] u Source.
 * @param[in] b Selector (0 or 1).
 */
static void ge25519_precomp_cmov(ge25519_precomp_t *t,
                                 const ge25519_precomp_t *u,
                                 unsigned int b)
{
    fe25519_native_cmov(&t->yplusx, &u->yplusx, b);
    fe25519_native_cmov(&t->yminusx, &u->yminusx, b);
    fe25519_native_cmov(&t->xy2d, &u->xy2d, b);
}

/**
 * @brief Set precomp to identity (y+x=1, y-x=1, 2dxy=0).
 * @internal
 *
 * @param[out] t Precomp to clear.
 */
static void ge25519_precomp_0(ge25519_precomp_t *t)
{
    fe25519_native_one(&t->yplusx);
    fe25519_native_one(&t->yminusx);
    fe25519_native_zero(&t->xy2d);
}

/**
 * @brief Convert extended Z=1 point to Duif precomp (ref10).
 * @internal
 *
 * @param[out] t Precomp (y+x, y-x, 2dxy).
 * @param[in] p Extended point with Z preferably 1 (affine).
 */
static void ge25519_n_to_precomp(ge25519_precomp_t *t, const ge25519_n_t *p)
{
    fe25519_native_t x;
    fe25519_native_t y;
    fe25519_native_t xy;

    ed25519_curve_constants_init();
    /* Assume projective with usable X,Y (caller uses Z=1 multiples of B). */
    fe25519_native_copy(&x, &p->X);
    fe25519_native_copy(&y, &p->Y);
    fe25519_native_add(&t->yplusx, &y, &x);
    fe25519_native_sub(&t->yminusx, &y, &x);
    fe25519_native_mul(&xy, &x, &y);
    fe25519_native_mul(&t->xy2d, &xy, &g_ed25519_d2);
}

/**
 * @brief Convert extended to cached form for ge_add/ge_sub.
 * @internal
 *
 * @param[out] r Cached point.
 * @param[in] p Extended point.
 */
static void ge25519_n_to_cached(ge25519_cached_t *r, const ge25519_n_t *p)
{
    ed25519_curve_constants_init();
    fe25519_native_add(&r->YplusX, &p->Y, &p->X);
    fe25519_native_sub(&r->YminusX, &p->Y, &p->X);
    fe25519_native_copy(&r->Z, &p->Z);
    fe25519_native_mul(&r->T2d, &p->T, &g_ed25519_d2);
}

/**
 * @brief Convert p1p1 to extended p3 (ref10 ge_p1p1_to_p3).
 * @internal
 *
 * @param[out] r Extended point.
 * @param[in] p Completed intermediate.
 */
static void ge25519_p1p1_to_n(ge25519_n_t *r, const ge25519_p1p1_t *p)
{
    fe25519_native_mul(&r->X, &p->X, &p->T);
    fe25519_native_mul(&r->Y, &p->Y, &p->Z);
    fe25519_native_mul(&r->Z, &p->Z, &p->T);
    fe25519_native_mul(&r->T, &p->X, &p->Y);
}

/**
 * @brief Convert p1p1 to projective p2 (ref10 ge_p1p1_to_p2).
 * @internal
 *
 * @param[out] r Projective point.
 * @param[in] p Completed intermediate.
 */
static void ge25519_p1p1_to_p2(ge25519_p2_t *r, const ge25519_p1p1_t *p)
{
    fe25519_native_mul(&r->X, &p->X, &p->T);
    fe25519_native_mul(&r->Y, &p->Y, &p->Z);
    fe25519_native_mul(&r->Z, &p->Z, &p->T);
}

/**
 * @brief Set projective point to the identity.
 * @internal
 *
 * @param[out] h Point to clear.
 */
static void ge25519_p2_0(ge25519_p2_t *h)
{
    fe25519_native_zero(&h->X);
    fe25519_native_one(&h->Y);
    fe25519_native_one(&h->Z);
}

/**
 * @brief Double a projective point into p1p1 (ref10 ge_p2_dbl).
 * @internal
 *
 * Uses @ref fe25519_native_sq and @ref fe25519_native_sq2. Extended T is unused.
 *
 * @param[out] r Completed double.
 * @param[in] p Projective input (X:Y:Z).
 */
static void ge25519_p2_dbl_p1p1(ge25519_p1p1_t *r, const ge25519_p2_t *p)
{
    fe25519_native_t t0;

    fe25519_native_sq(&r->X, &p->X);
    fe25519_native_sq(&r->Z, &p->Y);
    fe25519_native_sq2(&r->T, &p->Z);
    fe25519_native_add(&r->Y, &p->X, &p->Y);
    fe25519_native_sq(&t0, &r->Y);
    fe25519_native_add(&r->Y, &r->Z, &r->X);
    fe25519_native_sub(&r->Z, &r->Z, &r->X);
    fe25519_native_sub(&r->X, &t0, &r->Y);
    fe25519_native_sub(&r->T, &r->T, &r->Z);
}

/**
 * @brief Mixed addition: extended + precomp -> p1p1 (ref10 ge_madd).
 * @internal
 *
 * @param[out] r Completed sum.
 * @param[in] p Extended point.
 * @param[in] q Precomputed Duif point.
 */
static void ge25519_madd(ge25519_p1p1_t *r,
                         const ge25519_n_t *p,
                         const ge25519_precomp_t *q)
{
    fe25519_native_t t0;
    fe25519_native_t A;
    fe25519_native_t B;

    fe25519_native_add(&A, &p->Y, &p->X);
    fe25519_native_sub(&B, &p->Y, &p->X);
    fe25519_native_mul(&r->Z, &A, &q->yplusx);
    fe25519_native_mul(&r->Y, &B, &q->yminusx);
    fe25519_native_mul(&r->T, &q->xy2d, &p->T);
    fe25519_native_add(&t0, &p->Z, &p->Z);
    fe25519_native_sub(&r->X, &r->Z, &r->Y);
    fe25519_native_add(&r->Y, &r->Z, &r->Y);
    fe25519_native_add(&r->Z, &t0, &r->T);
    fe25519_native_sub(&r->T, &t0, &r->T);
}

/**
 * @brief Mixed subtraction: extended - precomp -> p1p1 (ref10 ge_msub).
 * @internal
 *
 * @param[out] r Completed difference.
 * @param[in] p Extended point.
 * @param[in] q Precomputed Duif point.
 */
static void ge25519_msub(ge25519_p1p1_t *r,
                         const ge25519_n_t *p,
                         const ge25519_precomp_t *q)
{
    fe25519_native_t t0;
    fe25519_native_t A;
    fe25519_native_t B;

    fe25519_native_add(&A, &p->Y, &p->X);
    fe25519_native_sub(&B, &p->Y, &p->X);
    fe25519_native_mul(&r->Z, &A, &q->yminusx);
    fe25519_native_mul(&r->Y, &B, &q->yplusx);
    fe25519_native_mul(&r->T, &q->xy2d, &p->T);
    fe25519_native_add(&t0, &p->Z, &p->Z);
    fe25519_native_sub(&r->X, &r->Z, &r->Y);
    fe25519_native_add(&r->Y, &r->Z, &r->Y);
    fe25519_native_sub(&r->Z, &t0, &r->T);
    fe25519_native_add(&r->T, &t0, &r->T);
}

/**
 * @brief Addition: extended + cached -> p1p1 (ref10 ge_add).
 * @internal
 *
 * @param[out] r Completed sum.
 * @param[in] p Extended point.
 * @param[in] q Cached point.
 */
static void ge25519_add_cached(ge25519_p1p1_t *r,
                               const ge25519_n_t *p,
                               const ge25519_cached_t *q)
{
    fe25519_native_t t0;
    fe25519_native_t A;
    fe25519_native_t B;

    fe25519_native_add(&A, &p->Y, &p->X);
    fe25519_native_sub(&B, &p->Y, &p->X);
    fe25519_native_mul(&r->Z, &A, &q->YplusX);
    fe25519_native_mul(&r->Y, &B, &q->YminusX);
    fe25519_native_mul(&r->T, &q->T2d, &p->T);
    fe25519_native_mul(&r->X, &p->Z, &q->Z);
    fe25519_native_add(&t0, &r->X, &r->X);
    fe25519_native_sub(&r->X, &r->Z, &r->Y);
    fe25519_native_add(&r->Y, &r->Z, &r->Y);
    fe25519_native_add(&r->Z, &t0, &r->T);
    fe25519_native_sub(&r->T, &t0, &r->T);
}

/**
 * @brief Subtraction: extended - cached -> p1p1 (ref10 ge_sub).
 * @internal
 *
 * @param[out] r Completed difference.
 * @param[in] p Extended point.
 * @param[in] q Cached point.
 */
static void ge25519_sub_cached(ge25519_p1p1_t *r,
                               const ge25519_n_t *p,
                               const ge25519_cached_t *q)
{
    fe25519_native_t t0;
    fe25519_native_t A;
    fe25519_native_t B;

    fe25519_native_add(&A, &p->Y, &p->X);
    fe25519_native_sub(&B, &p->Y, &p->X);
    fe25519_native_mul(&r->Z, &A, &q->YminusX);
    fe25519_native_mul(&r->Y, &B, &q->YplusX);
    fe25519_native_mul(&r->T, &q->T2d, &p->T);
    fe25519_native_mul(&r->X, &p->Z, &q->Z);
    fe25519_native_add(&t0, &r->X, &r->X);
    fe25519_native_sub(&r->X, &r->Z, &r->Y);
    fe25519_native_add(&r->Y, &r->Z, &r->Y);
    fe25519_native_sub(&r->Z, &t0, &r->T);
    fe25519_native_add(&r->T, &t0, &r->T);
}

/**
 * @brief Double extended point into p1p1 (ref10 ge_p3_dbl via ge_p2_dbl).
 * @internal
 *
 * Ignores extended T; matches wolfSSL/ref10 ge_p2_dbl using
 * @ref fe25519_native_sq / @ref fe25519_native_sq2.
 *
 * @param[out] r Completed double.
 * @param[in] p Extended input.
 */
static void ge25519_n_dbl_p1p1(ge25519_p1p1_t *r, const ge25519_n_t *p)
{
    ge25519_p2_t q;

    fe25519_native_copy(&q.X, &p->X);
    fe25519_native_copy(&q.Y, &p->Y);
    fe25519_native_copy(&q.Z, &p->Z);
    ge25519_p2_dbl_p1p1(r, &q);
}

void ge25519_n_from_pt(ge25519_n_t *out, const ge25519_pt_t *in)
{
    fe25519_native_from_be(&out->X, in->X);
    fe25519_native_from_be(&out->Y, in->Y);
    fe25519_native_from_be(&out->Z, in->Z);
    fe25519_native_from_be(&out->T, in->T);
}

void ge25519_n_to_pt(ge25519_pt_t *out, const ge25519_n_t *in)
{
    fe25519_native_to_be(out->X, &in->X);
    fe25519_native_to_be(out->Y, &in->Y);
    fe25519_native_to_be(out->Z, &in->Z);
    fe25519_native_to_be(out->T, &in->T);
}

void ge25519_n_zero(ge25519_n_t *p)
{
    fe25519_native_zero(&p->X);
    fe25519_native_one(&p->Y);
    fe25519_native_one(&p->Z);
    fe25519_native_zero(&p->T);
}

void ge25519_n_neg(ge25519_n_t *r, const ge25519_n_t *p)
{
    fe25519_native_neg(&r->X, &p->X);
    fe25519_native_copy(&r->Y, &p->Y);
    fe25519_native_copy(&r->Z, &p->Z);
    fe25519_native_neg(&r->T, &p->T);
}

void ge25519_n_add(ge25519_n_t *r, const ge25519_n_t *p, const ge25519_n_t *q)
{
    fe25519_native_t A;
    fe25519_native_t B;
    fe25519_native_t C;
    fe25519_native_t D;
    fe25519_native_t E;
    fe25519_native_t F;
    fe25519_native_t G;
    fe25519_native_t H;
    fe25519_native_t t0;
    fe25519_native_t t1;

    ed25519_curve_constants_init();

    fe25519_native_sub(&t0, &p->Y, &p->X);
    fe25519_native_sub(&t1, &q->Y, &q->X);
    fe25519_native_mul(&A, &t0, &t1);

    fe25519_native_add(&t0, &p->Y, &p->X);
    fe25519_native_add(&t1, &q->Y, &q->X);
    fe25519_native_mul(&B, &t0, &t1);

    fe25519_native_mul(&C, &p->T, &q->T);
    fe25519_native_mul(&C, &C, &g_ed25519_d2);

    fe25519_native_mul(&D, &p->Z, &q->Z);
    fe25519_native_add(&D, &D, &D);

    fe25519_native_sub(&E, &B, &A);
    fe25519_native_sub(&F, &D, &C);
    fe25519_native_add(&G, &D, &C);
    fe25519_native_add(&H, &B, &A);

    fe25519_native_mul(&r->X, &E, &F);
    fe25519_native_mul(&r->Y, &G, &H);
    fe25519_native_mul(&r->T, &E, &H);
    fe25519_native_mul(&r->Z, &F, &G);
}

void ge25519_n_dbl(ge25519_n_t *r, const ge25519_n_t *p)
{
    ge25519_p1p1_t t;
    ge25519_n_dbl_p1p1(&t, p);
    ge25519_p1p1_to_n(r, &t);
}

/**
 * @brief Constant-time table lookup for unsigned window digit.
 * @internal
 */
static void ge25519_n_select(ge25519_n_t *u,
                             const ge25519_n_t table[NOXTLS_ED25519_SCALAR_TABLE_ENTRIES],
                             uint32_t digit)
{
    uint32_t i;
    ge25519_n_zero(u);
    for(i = 0U; i < NOXTLS_ED25519_SCALAR_TABLE_ENTRIES; i++) {
        ge25519_n_cmov(u, &table[i], ge25519_ct_eq_u32(i, digit));
    }
}

/**
 * @brief Extract an unsigned window digit from a little-endian scalar.
 * @internal
 */
static uint32_t ge25519_scalar_window_digit(const uint8_t s_le[NOXTLS_ED25519_FE25519_BYTES],
                                           uint32_t window_index)
{
    uint32_t bit_offset = window_index * NOXTLS_ED25519_SCALAR_WINDOW_BITS;
    uint32_t byte_index = bit_offset / 8U;
    uint32_t bit_in_byte = bit_offset % 8U;
    uint32_t value = (uint32_t)s_le[byte_index] >> bit_in_byte;
    if((bit_in_byte + NOXTLS_ED25519_SCALAR_WINDOW_BITS) > 8U) {
        value |= (uint32_t)s_le[byte_index + 1U] << (8U - bit_in_byte);
    }
    return value & (uint32_t)NOXTLS_ED25519_SCALAR_WINDOW_MASK;
}

/**
 * @brief Build unsigned multiples {0P, P, 2P, ..., (RADIX-1)P}.
 * @internal
 */
static void ge25519_n_precompute_table(ge25519_n_t table[NOXTLS_ED25519_SCALAR_TABLE_ENTRIES],
                                       const ge25519_n_t *p)
{
    uint32_t i;
    ge25519_n_zero(&table[0]);
    table[1] = *p;
    for(i = 2U; i < NOXTLS_ED25519_SCALAR_TABLE_ENTRIES; i++) {
        ge25519_n_add(&table[i], &table[i - 1U], p);
    }
}

/**
 * @brief Windowed radix-16 scalar multiplication over native points.
 * @internal
 */
static void ge25519_n_scalarmult_windowed(ge25519_n_t *r,
                                         const uint8_t s_le[NOXTLS_ED25519_FE25519_BYTES],
                                         const ge25519_n_t table[NOXTLS_ED25519_SCALAR_TABLE_ENTRIES])
{
    ge25519_n_t t;
    ge25519_n_t selected;
    int32_t w;
    uint32_t d;

    ge25519_n_zero(r);
    for(w = (int32_t)NOXTLS_ED25519_SCALAR_WINDOW_COUNT - 1; w >= 0; w--) {
        for(d = 0U; d < NOXTLS_ED25519_SCALAR_WINDOW_BITS; d++) {
            ge25519_n_dbl(&t, r);
            *r = t;
        }
        ge25519_n_select(&selected, table, ge25519_scalar_window_digit(s_le, (uint32_t)w));
        ge25519_n_add(&t, r, &selected);
        *r = t;
    }
}

/**
 * @brief Convert little-endian scalar to signed radix-16 digits in [-8,8] (ref10).
 * @internal
 *
 * @param[out] e 64 signed digits.
 * @param[in] a_le Little-endian scalar.
 */
#if defined(NOXTLS_ED25519_DUMP_BASE)
static void ge25519_to_signed_radix16(int8_t e[NOXTLS_ED25519_BASE_DIGIT_COUNT],
                                      const uint8_t a_le[NOXTLS_ED25519_FE25519_BYTES])
{
    int32_t i;
    int8_t carry;

    for(i = 0; i < 32; i++) {
        e[2 * i + 0] = (int8_t)(a_le[i] & 15U);
        e[2 * i + 1] = (int8_t)((a_le[i] >> 4) & 15U);
    }
    carry = 0;
    for(i = 0; i < 63; i++) {
        e[i] = (int8_t)(e[i] + carry);
        carry = (int8_t)((e[i] + 8) >> 4);
        e[i] = (int8_t)(e[i] - (carry << 4));
    }
    e[63] = (int8_t)(e[63] + carry);
}

/**
 * @brief Constant-time select of Bi[pos][|b|-1] with conditional negation (ref10).
 * @internal
 *
 * @param[out] t Selected precomp (identity if b==0).
 * @param[in] table Eight odd multiples for one 16^i position.
 * @param[in] b Signed digit in [-8,8].
 */
static void ge25519_base_select(ge25519_precomp_t *t,
                                const ge25519_precomp_t table[NOXTLS_ED25519_BASE_ODD_COUNT],
                                int8_t b)
{
    ge25519_precomp_t minust;
    uint8_t bnegative;
    uint8_t babs;
    uint32_t j;

    /* bnegative = 1 if b < 0 (ref10 negative()). */
    bnegative = (uint8_t)((uint8_t)b >> 7);
    babs = (uint8_t)(b - (((int8_t)((-bnegative) & b)) << 1));

    ge25519_precomp_0(t);
    for(j = 0U; j < NOXTLS_ED25519_BASE_ODD_COUNT; j++) {
        ge25519_precomp_cmov(t, &table[j], ge25519_ct_equal_u8(babs, (uint8_t)(j + 1U)));
    }

    fe25519_native_copy(&minust.yplusx, &t->yminusx);
    fe25519_native_copy(&minust.yminusx, &t->yplusx);
    fe25519_native_neg(&minust.xy2d, &t->xy2d);
    ge25519_precomp_cmov(t, &minust, (unsigned int)bnegative);
}
#endif /* NOXTLS_ED25519_DUMP_BASE */

/**
 * @brief Affine-normalize extended point (Z := 1) for precomp table build.
 * @internal
 *
 * @param[in,out] p Point to project to Z=1.
 */
/* Always available for table builders (comb / odd-B / dump). */
static void ge25519_n_to_affine(ge25519_n_t *p)
{
    fe25519_native_t zinv;
    fe25519_native_inv(&zinv, &p->Z);
    fe25519_native_mul(&p->X, &p->X, &zinv);
    fe25519_native_mul(&p->Y, &p->Y, &zinv);
    fe25519_native_one(&p->Z);
    fe25519_native_mul(&p->T, &p->X, &p->Y);
}

/**
 * @brief Lazy-init odd multiples of B used by sliding-window verify.
 * @internal
 *
 * Builds A,3A,...,(2*SLIDE_ODD_COUNT-1)A as Duif precomp.
 *
 * @return Success or failure.
 */
static noxtls_return_t ge25519_base_odd_init(void)
{
    ge25519_pt_t B_pt;
    ge25519_n_t B;
    ge25519_n_t B2;
    ge25519_n_t odd;
    uint32_t j;

    if(g_base_odd_ready != 0) {
        return NOXTLS_RETURN_SUCCESS;
    }
    if(ge25519_decode(&B_pt, ed25519_B_encoded) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    ge25519_n_from_pt(&B, &B_pt);
    ge25519_n_to_affine(&B);
    ge25519_n_dbl(&B2, &B);
    ge25519_n_to_affine(&B2);

    odd = B;
    for(j = 0U; j < NOXTLS_ED25519_SLIDE_ODD_COUNT; j++) {
        ge25519_n_to_affine(&odd);
        ge25519_n_to_precomp(&g_base_odd[j], &odd);
        if(j + 1U < NOXTLS_ED25519_SLIDE_ODD_COUNT) {
            ge25519_n_add(&odd, &odd, &B2);
        }
    }
    g_base_odd_ready = 1;
    return NOXTLS_RETURN_SUCCESS;
}

#if defined(NOXTLS_ED25519_DUMP_BASE)
/**
 * @brief Fill mutable Bi[32][8] for dump-tool / host regeneration.
 * @internal
 *
 * Bi[i][j] = (j+1) * 256^i * B as Duif precomp (SUPERCOP/ref10).
 *
 * @return Success or failure.
 */
static noxtls_return_t ge25519_base_bi_init(void)
{
    ge25519_pt_t B_pt;
    ge25519_n_t cur;
    ge25519_n_t multiple;
    uint32_t i;
    uint32_t j;
    uint32_t k;

    if(g_base_bi_ready != 0) {
        return NOXTLS_RETURN_SUCCESS;
    }
    if(ge25519_decode(&B_pt, ed25519_B_encoded) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    ge25519_n_from_pt(&cur, &B_pt);

    for(i = 0U; i < NOXTLS_ED25519_BASE_POS_COUNT; i++) {
        ge25519_n_to_affine(&cur);
        multiple = cur;
        for(j = 0U; j < NOXTLS_ED25519_BASE_ODD_COUNT; j++) {
            ge25519_n_to_affine(&multiple);
            ge25519_n_to_precomp(&g_base_bi[i][j], &multiple);
            if(j + 1U < NOXTLS_ED25519_BASE_ODD_COUNT) {
                ge25519_n_add(&multiple, &multiple, &cur);
            }
        }

        if(i + 1U < NOXTLS_ED25519_BASE_POS_COUNT) {
            for(k = 0U; k < NOXTLS_ED25519_BASE_POS_DBL_COUNT; k++) {
                ge25519_n_dbl(&cur, &cur);
            }
        }
    }

    g_base_bi_ready = 1;
    return NOXTLS_RETURN_SUCCESS;
}
#endif /* NOXTLS_ED25519_DUMP_BASE */

#if !defined(NOXTLS_ED25519_SMALL_BASE)
/** Ed25519 group order L as little-endian 32-bit limbs (for signed-digit recode). */
static const uint32_t g_ed25519_L_le[8] = {
    0x5CF5D3EDu, 0x5812631Au, 0xA2F79CD6u, 0x14DEF9DEu,
    0x00000000u, 0x00000000u, 0x00000000u, 0x10000000u
};

/**
 * @brief Read bit @p pos from a little-endian limb array.
 * @internal
 */
#if (NOXTLS_ED25519_COMB_TEETH * NOXTLS_ED25519_COMB_SPACING) != 32U
static unsigned int ge25519_limb_bit(const uint32_t *n, unsigned int pos)
{
    return (n[pos >> 5] >> (pos & 31U)) & 1U;
}
#endif

/**
 * @brief Recode scalar to signed binary digits of length COMB_RANGE.
 * @internal
 *
 * @param[out] n Nine LE limbs (supports RANGE up to 288).
 * @param[in] s_le Little-endian 32-byte scalar.
 */
static void ge25519_to_signed_digits_comb(uint32_t n[9],
                                          const uint8_t s_le[NOXTLS_ED25519_FE25519_BYTES])
{
    uint32_t i;
    uint32_t cond;
    uint32_t mask;
    uint64_t carry;
    uint32_t c;
    uint32_t next;

    for(i = 0U; i < 8U; i++) {
        n[i] = (uint32_t)s_le[4U * i] |
               ((uint32_t)s_le[4U * i + 1U] << 8) |
               ((uint32_t)s_le[4U * i + 2U] << 16) |
               ((uint32_t)s_le[4U * i + 3U] << 24);
    }
    n[8] = 0U;

    cond = (~n[0]) & 1U;
    mask = 0U - cond;
    carry = 0U;
    for(i = 0U; i < 8U; i++) {
        carry += (uint64_t)n[i] + (uint64_t)(g_ed25519_L_le[i] & mask);
        n[i] = (uint32_t)carry;
        carry >>= 32;
    }
    n[8] = (uint32_t)carry;

#if NOXTLS_ED25519_COMB_RANGE > 256U
    n[8] += 1U << (NOXTLS_ED25519_COMB_RANGE - 256U);
    c = 0U;
    /* Arithmetic right-shift across 9 limbs (RANGE padding in n[8]). */
    i = 9U;
#else
    c = 1U;
    /* Arithmetic right-shift across 8 limbs with high carry-in 1. */
    i = 8U;
#endif
    while(i > 0U) {
        i--;
        next = n[i];
        n[i] = (c << 31) | (next >> 1);
        c = next;
    }
}

/**
 * @brief Bit-permute for 32-bit comb packing (gather teeth within a limb).
 * @internal
 */
#if (NOXTLS_ED25519_COMB_TEETH * NOXTLS_ED25519_COMB_SPACING) == 32U
static uint32_t ge25519_shuffle2(uint32_t x)
{
    uint32_t t;
    t = ((x >> 7) ^ x) & 0x00AA00AAu;
    x = (x ^ t) ^ (t << 7);
    t = ((x >> 14) ^ x) & 0x0000CCCCu;
    x = (x ^ t) ^ (t << 14);
    t = ((x >> 4) ^ x) & 0x00F000F0u;
    x = (x ^ t) ^ (t << 4);
    t = ((x >> 8) ^ x) & 0x0000FF00u;
    x = (x ^ t) ^ (t << 8);
    return x;
}

/**
 * @brief Group signed digits into comb teeth within each 32-bit block limb.
 * @internal
 */
static void ge25519_group_comb_bits(uint32_t n[8])
{
    uint32_t i;
    for(i = 0U; i < 8U; i++) {
        n[i] = ge25519_shuffle2(n[i]);
    }
}
#endif /* TEETH*SPACING == 32 */

/**
 * @brief Constant-time select comb table entry by absolute index.
 * @internal
 */
static void ge25519_comb_select(ge25519_precomp_t *t,
                                const ge25519_precomp_t table[NOXTLS_ED25519_COMB_POINTS],
                                unsigned int abs_index)
{
    uint32_t j;

    ge25519_precomp_0(t);
    for(j = 0U; j < NOXTLS_ED25519_COMB_POINTS; j++) {
        ge25519_precomp_cmov(t, &table[j],
                             ge25519_ct_equal_u8((uint8_t)abs_index, (uint8_t)j));
    }
}

/**
 * @brief Build Hamburg signed multi-comb tables for base point B.
 * @internal
 *
 * Builds Duif precomp entries for each comb block from tooth powers of B
 * (Mike Hamburg, ePrint 2012/309).
 *
 * @return Success or failure.
 */
static noxtls_return_t ge25519_comb_init(void)
{
    ge25519_pt_t B_pt;
    ge25519_n_t p;
    ge25519_n_t tooth_powers[NOXTLS_ED25519_COMB_TEETH];
    ge25519_n_t points[NOXTLS_ED25519_COMB_POINTS];
    ge25519_n_t sum;
    ge25519_n_t u;
    uint32_t block;
    uint32_t tooth;
    uint32_t spacing;
    uint32_t size;
    uint32_t j;
    uint32_t idx;

    if(g_base_comb_ready != 0) {
        return NOXTLS_RETURN_SUCCESS;
    }

    if(ge25519_decode(&B_pt, ed25519_B_encoded) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    ge25519_n_from_pt(&p, &B_pt);

    for(block = 0U; block < NOXTLS_ED25519_COMB_BLOCKS; block++) {
        for(tooth = 0U; tooth < NOXTLS_ED25519_COMB_TEETH; tooth++) {
            if(tooth == 0U) {
                sum = p;
            } else {
                u = p;
                ge25519_n_add(&sum, &sum, &u);
            }

            ge25519_n_dbl(&p, &p);
            tooth_powers[tooth] = p;

            if((block + tooth) !=
               (NOXTLS_ED25519_COMB_BLOCKS + NOXTLS_ED25519_COMB_TEETH - 2U)) {
                for(spacing = 1U; spacing < NOXTLS_ED25519_COMB_SPACING; spacing++) {
                    ge25519_n_dbl(&p, &p);
                }
            }
        }

        ge25519_n_neg(&sum, &sum);
        points[0] = sum;

        idx = 1U;
        for(tooth = 0U; tooth < (NOXTLS_ED25519_COMB_TEETH - 1U); tooth++) {
            size = 1U << tooth;
            for(j = 0U; j < size; j++, idx++) {
                ge25519_n_add(&points[idx], &points[idx - size], &tooth_powers[tooth]);
            }
        }

        for(j = 0U; j < NOXTLS_ED25519_COMB_POINTS; j++) {
            ge25519_n_to_affine(&points[j]);
            ge25519_n_to_precomp(&g_base_comb[block][j], &points[j]);
        }
    }

    g_base_comb_ready = 1;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Fixed-base R = s*B using Hamburg signed multi-comb (ePrint 2012/309).
 * @internal
 *
 * Supports (8,4,8) with per-limb tooth shuffle, or general (B,T,S) via bit extract.
 * Sign is applied to the Duif precomp (swap y±x, negate 2dxy).
 *
 * @param[out] r Extended result.
 * @param[in] s_le Little-endian scalar.
 */
static void ge25519_n_scalarmult_base_comb(ge25519_n_t *r,
                                           const uint8_t s_le[NOXTLS_ED25519_FE25519_BYTES])
{
    uint32_t n[9];
    ge25519_precomp_t t;
    ge25519_precomp_t tneg;
    ge25519_p1p1_t p1;
    uint32_t block;
    unsigned int sign;
    unsigned int abs_index;

    ge25519_to_signed_digits_comb(n, s_le);
#if (NOXTLS_ED25519_COMB_TEETH * NOXTLS_ED25519_COMB_SPACING) == 32U
    {
        int32_t c_off;
        uint32_t w;

        ge25519_group_comb_bits(n);
        ge25519_n_zero(r);

        c_off = (int32_t)((NOXTLS_ED25519_COMB_SPACING - 1U) * NOXTLS_ED25519_COMB_TEETH);
        for(;;) {
            for(block = 0U; block < NOXTLS_ED25519_COMB_BLOCKS; block++) {
                w = n[block] >> (uint32_t)c_off;
                sign = (w >> (NOXTLS_ED25519_COMB_TEETH - 1U)) & 1U;
                abs_index = (w ^ (0U - sign)) & NOXTLS_ED25519_COMB_MASK;

                ge25519_comb_select(&t, g_base_comb[block], abs_index);
                fe25519_native_copy(&tneg.yplusx, &t.yminusx);
                fe25519_native_copy(&tneg.yminusx, &t.yplusx);
                fe25519_native_neg(&tneg.xy2d, &t.xy2d);
                ge25519_precomp_cmov(&t, &tneg, sign);

                ge25519_madd(&p1, r, &t);
                ge25519_p1p1_to_n(r, &p1);
            }

            c_off -= (int32_t)NOXTLS_ED25519_COMB_TEETH;
            if(c_off < 0) {
                break;
            }
            ge25519_n_dbl(r, r);
        }
    }
#else
    {
        int32_t spacing;
        uint32_t tooth;
        unsigned int teeth;
        unsigned int pos;

        ge25519_n_zero(r);
        for(spacing = (int32_t)NOXTLS_ED25519_COMB_SPACING - 1; spacing >= 0; spacing--) {
            for(block = 0U; block < NOXTLS_ED25519_COMB_BLOCKS; block++) {
                teeth = 0U;
                for(tooth = 0U; tooth < NOXTLS_ED25519_COMB_TEETH; tooth++) {
                    pos = (block * NOXTLS_ED25519_COMB_TEETH * NOXTLS_ED25519_COMB_SPACING) +
                          (tooth * NOXTLS_ED25519_COMB_SPACING) + (uint32_t)spacing;
                    teeth |= ge25519_limb_bit(n, pos) << tooth;
                }
                sign = (teeth >> (NOXTLS_ED25519_COMB_TEETH - 1U)) & 1U;
                abs_index = (teeth ^ (0U - sign)) & NOXTLS_ED25519_COMB_MASK;

                ge25519_comb_select(&t, g_base_comb[block], abs_index);
                fe25519_native_copy(&tneg.yplusx, &t.yminusx);
                fe25519_native_copy(&tneg.yminusx, &t.yplusx);
                fe25519_native_neg(&tneg.xy2d, &t.xy2d);
                ge25519_precomp_cmov(&t, &tneg, sign);

                ge25519_madd(&p1, r, &t);
                ge25519_p1p1_to_n(r, &p1);
            }
            if(spacing > 0) {
                ge25519_n_dbl(r, r);
            }
        }
    }
#endif
}
#endif /* !SMALL_BASE */

#if defined(NOXTLS_ED25519_SMALL_BASE)
static noxtls_return_t ge25519_base_table_small_init(void)
{
    ge25519_pt_t B_pt;
    ge25519_n_t B_n;

    if(g_base_table_small_ready != 0) {
        return NOXTLS_RETURN_SUCCESS;
    }
    if(ge25519_decode(&B_pt, ed25519_B_encoded) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    ge25519_n_from_pt(&B_n, &B_pt);
    ge25519_n_precompute_table(g_base_table_small, &B_n);
    g_base_table_small_ready = 1;
    return NOXTLS_RETURN_SUCCESS;
}
#endif /* NOXTLS_ED25519_SMALL_BASE */

/**
 * @brief Build ref10 slide digits in [-15,15] (variable-time, for verify).
 * @internal
 *
 * @param[out] r 256 signed slide digits.
 * @param[in] a Little-endian scalar.
 */
static void ge25519_slide(int8_t r[NOXTLS_ED25519_SCALAR_BIT_LENGTH],
                          const uint8_t a[NOXTLS_ED25519_FE25519_BYTES])
{
    int32_t i;
    int32_t b;
    int32_t k;

    for(i = 0; i < (int32_t)NOXTLS_ED25519_SCALAR_BIT_LENGTH; i++) {
        r[i] = (int8_t)(1 & (a[i >> 3] >> (i & 7)));
    }

    for(i = 0; i < (int32_t)NOXTLS_ED25519_SCALAR_BIT_LENGTH; i++) {
        if(r[i] == 0) {
            continue;
        }
        for(b = 1; b <= 6 && (i + b) < (int32_t)NOXTLS_ED25519_SCALAR_BIT_LENGTH; b++) {
            if(r[i + b] == 0) {
                continue;
            }
            if(r[i] + (r[i + b] << b) <= NOXTLS_ED25519_SLIDE_MAX_ABS) {
                r[i] = (int8_t)(r[i] + (r[i + b] << b));
                r[i + b] = 0;
            } else if(r[i] - (r[i + b] << b) >= -NOXTLS_ED25519_SLIDE_MAX_ABS) {
                r[i] = (int8_t)(r[i] - (r[i + b] << b));
                for(k = i + b; k < (int32_t)NOXTLS_ED25519_SCALAR_BIT_LENGTH; k++) {
                    if(r[k] == 0) {
                        r[k] = 1;
                        break;
                    }
                    r[k] = 0;
                }
            } else {
                break;
            }
        }
    }
}

void ge25519_scalar_mult(ge25519_pt_t *R,
                         const uint8_t s_le[NOXTLS_ED25519_FE25519_BYTES],
                         const ge25519_pt_t *P)
{
    ge25519_n_t p_n;
    ge25519_n_t r_n;
    ge25519_n_t *table;
    const size_t table_bytes =
        (size_t)NOXTLS_ED25519_SCALAR_TABLE_ENTRIES * sizeof(ge25519_n_t);

    table = (ge25519_n_t *)noxtls_malloc(table_bytes);
    if(table == NULL) {
        ge25519_n_zero(&r_n);
        ge25519_n_to_pt(R, &r_n);
        return;
    }

    ge25519_n_from_pt(&p_n, P);
    ge25519_n_precompute_table(table, &p_n);
    ge25519_n_scalarmult_windowed(&r_n, s_le, table);
    ge25519_n_to_pt(R, &r_n);
    NOXTLS_SECURE_FREE(table, table_bytes);
}

void ge25519_scalarmult_base(ge25519_pt_t *R,
                             const uint8_t s_le[NOXTLS_ED25519_FE25519_BYTES])
{
    ge25519_n_t r_n;

    ge25519_scalarmult_base_n(&r_n, s_le);
    ge25519_n_to_pt(R, &r_n);
}

/**
 * @brief Native double-scalar: R = [a]P + [b]B (ref10 ge_double_scalarmult_vartime).
 *
 * Uses a projective (p2) accumulator with p2_dbl + p1p1_to_p2 on the hot path.
 * Result X:Y:Z are projective; T is set to X*Y (valid once Z=1 after encode path).
 *
 * @param[out] R Native result (projective X,Y,Z sufficient for encode).
 * @param[in] a_le Little-endian scalar for @p P.
 * @param[in] P Native variable base.
 * @param[in] b_le Little-endian scalar for base point B.
 */
void ge25519_double_scalarmult_n(ge25519_n_t *R,
                                        const uint8_t a_le[NOXTLS_ED25519_FE25519_BYTES],
                                        const ge25519_n_t *P,
                                        const uint8_t b_le[NOXTLS_ED25519_FE25519_BYTES])
{
    int8_t aslide[NOXTLS_ED25519_SCALAR_BIT_LENGTH];
    int8_t bslide[NOXTLS_ED25519_SCALAR_BIT_LENGTH];
    ge25519_cached_t Ai[NOXTLS_ED25519_SLIDE_ODD_COUNT];
    ge25519_n_t A2;
    ge25519_n_t u;
    ge25519_n_t odd;
    ge25519_p2_t r;
    ge25519_p1p1_t t;
    int32_t i;
    uint32_t j;

    if(ge25519_base_odd_init() != NOXTLS_RETURN_SUCCESS) {
        ge25519_n_zero(R);
        return;
    }

    ge25519_slide(aslide, a_le);
    ge25519_slide(bslide, b_le);

    ge25519_n_to_cached(&Ai[0], P);
    ge25519_n_dbl(&A2, P);
    odd = *P;
    for(j = 1U; j < NOXTLS_ED25519_SLIDE_ODD_COUNT; j++) {
        ge25519_add_cached(&t, &A2, &Ai[j - 1U]);
        ge25519_p1p1_to_n(&odd, &t);
        ge25519_n_to_cached(&Ai[j], &odd);
    }

    ge25519_p2_0(&r);

    for(i = (int32_t)NOXTLS_ED25519_SCALAR_BIT_LENGTH - 1; i >= 0; i--) {
        if((aslide[i] != 0) || (bslide[i] != 0)) {
            break;
        }
    }

    for(; i >= 0; i--) {
        ge25519_p2_dbl_p1p1(&t, &r);

        if(aslide[i] > 0) {
            ge25519_p1p1_to_n(&u, &t);
            ge25519_add_cached(&t, &u, &Ai[aslide[i] / 2]);
        } else if(aslide[i] < 0) {
            ge25519_p1p1_to_n(&u, &t);
            ge25519_sub_cached(&t, &u, &Ai[(-aslide[i]) / 2]);
        }

        if(bslide[i] > 0) {
            ge25519_p1p1_to_n(&u, &t);
            ge25519_madd(&t, &u, &g_base_odd[bslide[i] / 2]);
        } else if(bslide[i] < 0) {
            ge25519_p1p1_to_n(&u, &t);
            ge25519_msub(&t, &u, &g_base_odd[(-bslide[i]) / 2]);
        }

        ge25519_p1p1_to_p2(&r, &t);
    }

    /* Projective result; T=X*Y is unused by encode_n (uses X/Z, Y/Z only). */
    fe25519_native_copy(&R->X, &r.X);
    fe25519_native_copy(&R->Y, &r.Y);
    fe25519_native_copy(&R->Z, &r.Z);
    fe25519_native_mul(&R->T, &r.X, &r.Y);
}

void ge25519_double_scalarmult(ge25519_pt_t *R,
                               const uint8_t a_le[NOXTLS_ED25519_FE25519_BYTES],
                               const ge25519_pt_t *P,
                               const uint8_t b_le[NOXTLS_ED25519_FE25519_BYTES])
{
    ge25519_n_t P_n;
    ge25519_n_t r_n;
    fe25519_native_t zinv;

    ge25519_n_from_pt(&P_n, P);
    ge25519_double_scalarmult_n(&r_n, a_le, &P_n, b_le);
    /* Affine for BE ABI so T = XY/Z holds. */
    fe25519_native_inv(&zinv, &r_n.Z);
    fe25519_native_mul(&r_n.X, &r_n.X, &zinv);
    fe25519_native_mul(&r_n.Y, &r_n.Y, &zinv);
    fe25519_native_one(&r_n.Z);
    fe25519_native_mul(&r_n.T, &r_n.X, &r_n.Y);
    ge25519_n_to_pt(R, &r_n);
}

noxtls_return_t ge25519_decode_n(ge25519_n_t *p, const uint8_t enc[NOXTLS_ED25519_FE25519_BYTES])
{
    /* RFC 8032 §5.1.3: recover x from compressed y and sign bit. */
    uint8_t y_le[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t y_be[NOXTLS_ED25519_FE25519_BYTES];
    fe25519_native_t y;
    fe25519_native_t y2;
    fe25519_native_t u;
    fe25519_native_t v;
    fe25519_native_t v3;
    fe25519_native_t v7;
    fe25519_native_t uv7;
    fe25519_native_t x;
    fe25519_native_t x2;
    fe25519_native_t vx2;
    fe25519_native_t one;
    fe25519_native_t d;
    fe25519_native_t neg_u;
    unsigned int sign;

    if(p == NULL || enc == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    ed25519_curve_constants_init();
    fe25519_native_one(&one);
    fe25519_native_from_be(&d, ed25519_d);

    memcpy(y_le, enc, NOXTLS_ED25519_FE25519_BYTES);
    sign = (unsigned int)(y_le[NOXTLS_ED25519_FE25519_BYTES - 1U] >> 7);
    y_le[NOXTLS_ED25519_FE25519_BYTES - 1U] &= NOXTLS_ED25519_COMPRESSED_Y_SIGN_MASK;

    {
        uint32_t i;
        for(i = 0U; i < NOXTLS_ED25519_FE25519_BYTES; i++) {
            y_be[i] = y_le[NOXTLS_ED25519_FE25519_BYTES - 1U - i];
        }
    }
    if(ed25519_cmp_be(y_be, ed25519_p, NOXTLS_ED25519_FE25519_BYTES) >= 0) {
        return NOXTLS_RETURN_FAILED;
    }

    fe25519_native_from_le(&y, y_le);
    fe25519_native_sq(&y2, &y);
    fe25519_native_sub(&u, &y2, &one);
    fe25519_native_mul(&v, &y2, &d);
    fe25519_native_add(&v, &v, &one);

    fe25519_native_sq(&v3, &v);
    fe25519_native_mul(&v3, &v3, &v);
    fe25519_native_sq(&v7, &v3);
    fe25519_native_mul(&v7, &v7, &v);
    fe25519_native_mul(&uv7, &u, &v7);
    fe25519_native_pow22523(&x, &uv7);
    fe25519_native_mul(&x, &x, &u);
    fe25519_native_mul(&x, &x, &v3);

    fe25519_native_sq(&x2, &x);
    fe25519_native_mul(&vx2, &v, &x2);
    if(fe25519_native_equal(&vx2, &u) == 0U) {
        fe25519_native_neg(&neg_u, &u);
        if(fe25519_native_equal(&vx2, &neg_u) == 0U) {
            return NOXTLS_RETURN_FAILED;
        }
        fe25519_native_mul(&x, &x, &g_ed25519_sqrtm1);
    }

    if(fe25519_native_isnegative(&x) != sign) {
        fe25519_native_neg(&x, &x);
    }

    fe25519_native_copy(&p->X, &x);
    fe25519_native_copy(&p->Y, &y);
    fe25519_native_one(&p->Z);
    fe25519_native_mul(&p->T, &p->X, &p->Y);
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t ge25519_decode(ge25519_pt_t *p, const uint8_t enc[NOXTLS_ED25519_FE25519_BYTES])
{
    ge25519_n_t pn;
    noxtls_return_t rc;

    if(p == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    rc = ge25519_decode_n(&pn, enc);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    ge25519_n_to_pt(p, &pn);
    return NOXTLS_RETURN_SUCCESS;
}

void ge25519_encode_n(uint8_t enc[NOXTLS_ED25519_FE25519_BYTES], const ge25519_n_t *p)
{
    /* RFC 8032 §5.1.2: compress (x,y) with sign(x) in high bit of y encoding. */
    fe25519_native_t zinv;
    fe25519_native_t x;
    fe25519_native_t y;

    fe25519_native_inv(&zinv, &p->Z);
    fe25519_native_mul(&x, &p->X, &zinv);
    fe25519_native_mul(&y, &p->Y, &zinv);
    fe25519_native_to_le(enc, &y);
    enc[NOXTLS_ED25519_FE25519_BYTES - 1U] |=
        (uint8_t)(fe25519_native_isnegative(&x) << 7);
}

void ge25519_encode(uint8_t enc[NOXTLS_ED25519_FE25519_BYTES], const ge25519_pt_t *p)
{
    ge25519_n_t pn;

    ge25519_n_from_pt(&pn, p);
    ge25519_encode_n(enc, &pn);
}

void ge25519_scalarmult_base_n(ge25519_n_t *R,
                               const uint8_t s_le[NOXTLS_ED25519_FE25519_BYTES])
{
#if defined(NOXTLS_ED25519_SMALL_BASE)
    if(ge25519_base_table_small_init() != NOXTLS_RETURN_SUCCESS) {
        ge25519_n_zero(R);
        return;
    }
    ge25519_n_scalarmult_windowed(R, s_le, g_base_table_small);
#else
    if(ge25519_comb_init() != NOXTLS_RETURN_SUCCESS) {
        ge25519_n_zero(R);
        return;
    }
    ge25519_n_scalarmult_base_comb(R, s_le);
#endif
}

#if defined(NOXTLS_ED25519_DUMP_BASE)
#include <stdio.h>

/**
 * @brief Host-only helper: print one field element as a C initializer.
 * @internal
 */
static void ge25519_dump_fe(FILE *out, const fe25519_native_t *f)
{
    uint32_t i;
    fputc('{', out);
    for(i = 0U; i < NOXTLS_ED25519_FE_LIMBS; i++) {
        if(i != 0U) {
            fputc(',', out);
        }
        fprintf(out, "%d", (int)f->v[i]);
    }
    fputc('}', out);
}

/**
 * @brief Host-only helper: print one Duif precomp as a C initializer.
 * @internal
 */
static void ge25519_dump_precomp(FILE *out, const ge25519_precomp_t *p)
{
    fputs("    {\n      ", out);
    ge25519_dump_fe(out, &p->yplusx);
    fputs(",\n      ", out);
    ge25519_dump_fe(out, &p->yminusx);
    fputs(",\n      ", out);
    ge25519_dump_fe(out, &p->xy2d);
    fputs("\n    }", out);
}

/**
 * @brief Emit flash-resident Bi[32][8] and odd-B tables to stdout.
 * @return 0 on success.
 */
int main(void)
{
    uint32_t i;
    uint32_t j;

#ifndef NOXTLS_ED25519_SMALL_BASE
    if(ge25519_base_bi_init() != NOXTLS_RETURN_SUCCESS) {
        return 1;
    }
#endif
    if(ge25519_base_odd_init() != NOXTLS_RETURN_SUCCESS) {
        return 1;
    }

    fputs("/* Generated by NOXTLS_ED25519_DUMP_BASE - Bi[i][j]=(j+1)*256^i*B */\n", stdout);
#ifndef NOXTLS_ED25519_SMALL_BASE
    fputs("static const ge25519_precomp_t g_base_bi"
          "[NOXTLS_ED25519_BASE_POS_COUNT][NOXTLS_ED25519_BASE_ODD_COUNT] = {\n",
          stdout);
    for(i = 0U; i < NOXTLS_ED25519_BASE_POS_COUNT; i++) {
        fputs("  {\n", stdout);
        for(j = 0U; j < NOXTLS_ED25519_BASE_ODD_COUNT; j++) {
            ge25519_dump_precomp(stdout, &g_base_bi[i][j]);
            fputs((j + 1U < NOXTLS_ED25519_BASE_ODD_COUNT) ? ",\n" : "\n", stdout);
        }
        fputs((i + 1U < NOXTLS_ED25519_BASE_POS_COUNT) ? "  },\n" : "  }\n", stdout);
    }
    fputs("};\n\n", stdout);
#endif
    fputs("static const ge25519_precomp_t g_base_odd"
          "[NOXTLS_ED25519_SLIDE_ODD_COUNT] = {\n",
          stdout);
    for(j = 0U; j < NOXTLS_ED25519_SLIDE_ODD_COUNT; j++) {
        ge25519_dump_precomp(stdout, &g_base_odd[j]);
        fputs((j + 1U < NOXTLS_ED25519_SLIDE_ODD_COUNT) ? ",\n" : "\n", stdout);
    }
    fputs("};\n", stdout);
    return 0;
}
#endif /* NOXTLS_ED25519_DUMP_BASE */
