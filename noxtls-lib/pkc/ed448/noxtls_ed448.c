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
* File:    noxtls_ed448.c
* Summary: Ed448 digital signatures (RFC 8032)
*
* Field arithmetic: GF(p), p = 2^448 - 2^224 - 1, 16 little-endian limbs of
* 28 bits (portable 32x32->64 multiplies, no data-dependent branches).
* Group: untwisted Edwards curve x^2 + y^2 = 1 + d*x^2*y^2, d = -39081, in
* projective (X:Y:Z) coordinates with the complete RFC 8032 5.2.4 formulas.
* Scalars modulo the group order L use the bignum module.
*
*****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "common/noxtls_ct.h"
#include "common/noxtls_memory.h"
#include "drbg/noxtls_drbg.h"
#include "noxtls_common.h"
#include "noxtls_ed448.h"
#include "pkc/rsa/noxtls_bignum.h"

#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3

#include "mdigest/sha3/noxtls_sha3.h"
#include "noxtls_ct.h"

/* ------------------------------------------------------------------------- */
/* Field GF(p), p = 2^448 - 2^224 - 1                                         */
/* ------------------------------------------------------------------------- */

#define ED448_FE_LIMBS       16U
#define ED448_FE_LIMB_BITS   28U
#define ED448_FE_LIMB_MASK   0x0FFFFFFFU
/** Limb index holding weight 2^224 (2^448 == 2^224 + 1 mod p). */
#define ED448_FE_MID_LIMB    8U
/** Number of product limbs (2 * 16) used by the multiplier. */
#define ED448_FE_WIDE_LIMBS  32U

/** Field element: value = sum v[i] * 2^(28 i). Limbs are < 2^28 + 16 after every operation. */
typedef struct {
    uint32_t v[ED448_FE_LIMBS];
} fe448_t;

/* p in limbs. */
static const fe448_t fe448_p = { {
    0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU,
    0x0FFFFFFEU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU
} };

/* d = -39081 mod p. */
static const fe448_t fe448_d = { {
    0x0FFF6756U, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU,
    0x0FFFFFFEU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU
} };

/* Base point B (RFC 8032 5.2): affine x and y. */
static const fe448_t fe448_base_x = { {
    0x070CC05EU, 0x026A82BCU, 0x00938E26U, 0x080E18B0U, 0x0511433BU, 0x0F72AB66U, 0x0412AE1AU, 0x0A3D3A46U,
    0x0A6DE324U, 0x00F1767EU, 0x04657047U, 0x036DA9E1U, 0x05A622BFU, 0x0ED221D1U, 0x066BED0DU, 0x04F1970CU
} };
static const fe448_t fe448_base_y = { {
    0x0230FA14U, 0x008795BFU, 0x07C8AD98U, 0x0132C4EDU, 0x09C4FDBDU, 0x01CE67C3U, 0x073AD3FFU, 0x005A0C2DU,
    0x07789C1EU, 0x0A398408U, 0x0A73736CU, 0x0C7624BEU, 0x003756C9U, 0x02488762U, 0x016EB6BCU, 0x0693F467U
} };

/* p - 2 (Fermat inversion exponent), big-endian. */
static const uint8_t ed448_exp_p_minus_2[NOXTLS_ED448_FE448_BYTES] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFEU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFDU
};

/* (p - 3) / 4 (square-root exponent, RFC 8032 5.2.3), big-endian. */
static const uint8_t ed448_exp_p_minus_3_div_4[NOXTLS_ED448_FE448_BYTES] = {
    0x3FU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xBFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU
};

/* Order L of the prime-order subgroup: 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885, big-endian. */
static const uint8_t ed448_L[NOXTLS_ED448_FE448_BYTES] = {
    0x3FU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0x7CU, 0xCAU, 0x23U, 0xE9U, 0xC4U, 0x4EU, 0xDBU, 0x49U, 0xAEU, 0xD6U, 0x36U, 0x90U, 0x21U, 0x6CU,
    0xC2U, 0x72U, 0x8DU, 0xC5U, 0x8FU, 0x55U, 0x23U, 0x78U, 0xC2U, 0x92U, 0xABU, 0x58U, 0x44U, 0xF3U
};

/**
 * @brief Weak reduction: fold carries so every limb is < 2^28 + 16 (value unchanged mod p).
 * @param[in,out] a Field element.
 */
static void fe448_weak_reduce(fe448_t *a)
{
    uint32_t i;
    uint32_t top = a->v[ED448_FE_LIMBS - 1U] >> ED448_FE_LIMB_BITS;

    a->v[ED448_FE_MID_LIMB] += top;
    for(i = ED448_FE_LIMBS - 1U; i > 0U; i -= 1U) {
        a->v[i] = (a->v[i] & ED448_FE_LIMB_MASK) + (a->v[i - 1U] >> ED448_FE_LIMB_BITS);
    }
    a->v[0] = (a->v[0] & ED448_FE_LIMB_MASK) + top;
}

/**
 * @brief Strong reduction to the canonical representative in [0, p) with limbs < 2^28.
 * @param[in,out] a Field element.
 */
static void fe448_strong_reduce(fe448_t *a)
{
    uint32_t i;
    uint32_t borrow = 0U;
    uint32_t carry = 0U;
    uint32_t mask;

    /* After two weak reductions the value is < 2^448 + 2^425 < 2p: one conditional subtraction. */
    fe448_weak_reduce(a);
    fe448_weak_reduce(a);
    for(i = 0U; i < ED448_FE_LIMBS; i += 1U) {
        /* a->v[i] - p[i] - borrow lies in [-2^28, 17]: bias by 2^28 to stay unsigned. */
        uint32_t t = (a->v[i] + 0x10000000U) - fe448_p.v[i] - borrow;
        a->v[i] = t & ED448_FE_LIMB_MASK;
        borrow = 1U - (t >> ED448_FE_LIMB_BITS);
    }
    /* borrow == 1: the subtraction went negative, add p back. */
    mask = 0U - borrow;
    for(i = 0U; i < ED448_FE_LIMBS; i += 1U) {
        uint32_t t = a->v[i] + (fe448_p.v[i] & mask) + carry;
        a->v[i] = t & ED448_FE_LIMB_MASK;
        carry = t >> ED448_FE_LIMB_BITS;
    }
}

/** @brief r = 0. */
static void fe448_zero(fe448_t *r)
{
    uint32_t i;
    for(i = 0U; i < ED448_FE_LIMBS; i += 1U) {
        r->v[i] = 0U;
    }
}

/** @brief r = 1. */
static void fe448_one(fe448_t *r)
{
    fe448_zero(r);
    r->v[0] = 1U;
}

/** @brief r = a + b mod p. */
static void fe448_add(fe448_t *r, const fe448_t *a, const fe448_t *b)
{
    uint32_t i;
    for(i = 0U; i < ED448_FE_LIMBS; i += 1U) {
        r->v[i] = a->v[i] + b->v[i];
    }
    fe448_weak_reduce(r);
}

/** @brief r = a - b mod p (computed as a + 2p - b so limbs never go negative). */
static void fe448_sub(fe448_t *r, const fe448_t *a, const fe448_t *b)
{
    uint32_t i;
    for(i = 0U; i < ED448_FE_LIMBS; i += 1U) {
        r->v[i] = (a->v[i] + (2U * fe448_p.v[i])) - b->v[i];
    }
    fe448_weak_reduce(r);
}

/** @brief r = a * b mod p (schoolbook 16x16 limbs, Solinas folding 2^448 = 2^224 + 1). */
static void fe448_mul(fe448_t *r, const fe448_t *a, const fe448_t *b)
{
    uint64_t c[ED448_FE_WIDE_LIMBS];
    uint32_t i;
    uint32_t j;

    for(i = 0U; i < ED448_FE_WIDE_LIMBS; i += 1U) {
        c[i] = 0U;
    }
    /* Inputs have limbs < 2^28 + 16: every column sum is < 2^61. */
    for(i = 0U; i < ED448_FE_LIMBS; i += 1U) {
        for(j = 0U; j < ED448_FE_LIMBS; j += 1U) {
            c[i + j] += (uint64_t)a->v[i] * (uint64_t)b->v[j];
        }
    }
    /* Normalise the 32 columns to 28-bit digits. */
    for(i = 0U; i < (ED448_FE_WIDE_LIMBS - 1U); i += 1U) {
        c[i + 1U] += c[i] >> ED448_FE_LIMB_BITS;
        c[i] &= (uint64_t)ED448_FE_LIMB_MASK;
    }
    /* Fold weights >= 2^448 from the top: 2^(28k) = 2^(28(k-16)) + 2^(28(k-8)). */
    for(i = ED448_FE_WIDE_LIMBS - 1U; i >= ED448_FE_LIMBS; i -= 1U) {
        c[i - ED448_FE_LIMBS] += c[i];
        c[i - ED448_FE_MID_LIMB] += c[i];
        c[i] = 0U;
    }
    /* All columns are now < 2^31: carry into 28-bit limbs, folding the final carry. */
    {
        uint64_t carry = 0U;
        for(i = 0U; i < ED448_FE_LIMBS; i += 1U) {
            uint64_t t = c[i] + carry;
            r->v[i] = (uint32_t)(t & (uint64_t)ED448_FE_LIMB_MASK);
            carry = t >> ED448_FE_LIMB_BITS;
        }
        r->v[0] += (uint32_t)carry;
        r->v[ED448_FE_MID_LIMB] += (uint32_t)carry;
    }
    fe448_weak_reduce(r);
}

/** @brief r = a^2 mod p. */
static void fe448_sqr(fe448_t *r, const fe448_t *a)
{
    fe448_mul(r, a, a);
}

/**
 * @brief r = a^e mod p for a public exponent (left-to-right square and multiply).
 * @param[out] r      Result.
 * @param[in]  a      Base.
 * @param[in]  exp_be Exponent, NOXTLS_ED448_FE448_BYTES big-endian bytes (public value).
 */
static void fe448_pow(fe448_t *r, const fe448_t *a, const uint8_t exp_be[NOXTLS_ED448_FE448_BYTES])
{
    fe448_t acc;
    fe448_t base;
    uint32_t i;

    base = *a;
    fe448_one(&acc);
    for(i = 0U; i < (NOXTLS_ED448_FE448_BYTES * 8U); i += 1U) {
        uint32_t bit = ((uint32_t)exp_be[i >> 3U] >> (7U - (i & 7U))) & 1U;
        fe448_sqr(&acc, &acc);
        if(bit != 0U) {
            fe448_mul(&acc, &acc, &base);
        }
    }
    *r = acc;
}

/** @brief r = a^-1 mod p (Fermat; 0 maps to 0). */
static void fe448_inv(fe448_t *r, const fe448_t *a)
{
    fe448_pow(r, a, ed448_exp_p_minus_2);
}

/** @brief Canonical 56-byte little-endian encoding of a. */
static void fe448_to_bytes(uint8_t out[NOXTLS_ED448_FE448_BYTES], const fe448_t *a)
{
    fe448_t t = *a;
    uint32_t i;
    uint32_t pos = 0U;
    uint64_t acc = 0U;
    uint32_t acc_bits = 0U;

    fe448_strong_reduce(&t);
    for(i = 0U; i < ED448_FE_LIMBS; i += 1U) {
        acc |= (uint64_t)t.v[i] << acc_bits;
        acc_bits += ED448_FE_LIMB_BITS;
        while(acc_bits >= 8U) {
            out[pos] = (uint8_t)(acc & 0xFFU);
            pos += 1U;
            acc >>= 8U;
            acc_bits -= 8U;
        }
    }
}

/** @brief Load a 56-byte little-endian value (any value < 2^448; not reduced). */
static void fe448_from_bytes(fe448_t *r, const uint8_t in[NOXTLS_ED448_FE448_BYTES])
{
    uint32_t i;
    uint32_t pos = 0U;
    uint64_t acc = 0U;
    uint32_t acc_bits = 0U;

    for(i = 0U; i < ED448_FE_LIMBS; i += 1U) {
        while(acc_bits < ED448_FE_LIMB_BITS) {
            acc |= (uint64_t)in[pos] << acc_bits;
            pos += 1U;
            acc_bits += 8U;
        }
        r->v[i] = (uint32_t)(acc & (uint64_t)ED448_FE_LIMB_MASK);
        acc >>= ED448_FE_LIMB_BITS;
        acc_bits -= ED448_FE_LIMB_BITS;
    }
}

/** @brief 1 if a == b mod p, else 0 (constant time). */
static uint32_t fe448_equal(const fe448_t *a, const fe448_t *b)
{
    uint8_t ea[NOXTLS_ED448_FE448_BYTES];
    uint8_t eb[NOXTLS_ED448_FE448_BYTES];
    uint32_t diff = 0U;
    uint32_t i;

    fe448_to_bytes(ea, a);
    fe448_to_bytes(eb, b);
    for(i = 0U; i < NOXTLS_ED448_FE448_BYTES; i += 1U) {
        diff |= (uint32_t)ea[i] ^ (uint32_t)eb[i];
    }
    return (uint32_t)(((diff - 1U) >> 31U) & 1U);
}

/** @brief 1 if a == 0 mod p, else 0. */
static uint32_t fe448_is_zero(const fe448_t *a)
{
    fe448_t z;
    fe448_zero(&z);
    return fe448_equal(a, &z);
}

/** @brief Least significant bit of the canonical value ("sign" of x, RFC 8032). */
static uint32_t fe448_lsb(const fe448_t *a)
{
    fe448_t t = *a;
    fe448_strong_reduce(&t);
    return t.v[0] & 1U;
}

/** @brief r = cond ? a : r, constant time (cond is 0 or 1). */
static void fe448_cmov(fe448_t *r, const fe448_t *a, uint32_t cond)
{
    uint32_t mask = 0U - (cond & 1U);
    uint32_t i;
    for(i = 0U; i < ED448_FE_LIMBS; i += 1U) {
        r->v[i] ^= mask & (r->v[i] ^ a->v[i]);
    }
}

/* ------------------------------------------------------------------------- */
/* Group: projective (X:Y:Z), x = X/Z, y = Y/Z                                */
/* ------------------------------------------------------------------------- */

/** @internal Projective point on Ed448. */
typedef struct {
    fe448_t X;
    fe448_t Y;
    fe448_t Z;
} ge448_pt_t;

/** @brief p = neutral element (0, 1). */
static void ge448_identity(ge448_pt_t *p)
{
    fe448_zero(&p->X);
    fe448_one(&p->Y);
    fe448_one(&p->Z);
}

/** @brief p = base point B. */
static void ge448_base(ge448_pt_t *p)
{
    p->X = fe448_base_x;
    p->Y = fe448_base_y;
    fe448_one(&p->Z);
}

/**
 * @brief r = p + q (RFC 8032 5.2.4; complete for Ed448, so valid for p == q and the identity).
 */
static void ge448_add(ge448_pt_t *r, const ge448_pt_t *p, const ge448_pt_t *q)
{
    fe448_t A;
    fe448_t B;
    fe448_t C;
    fe448_t D;
    fe448_t E;
    fe448_t F;
    fe448_t G;
    fe448_t H;
    fe448_t t;

    fe448_mul(&A, &p->Z, &q->Z);       /* A = Z1*Z2 */
    fe448_sqr(&B, &A);                 /* B = A^2 */
    fe448_mul(&C, &p->X, &q->X);       /* C = X1*X2 */
    fe448_mul(&D, &p->Y, &q->Y);       /* D = Y1*Y2 */
    fe448_mul(&E, &C, &D);
    fe448_mul(&E, &E, &fe448_d);       /* E = d*C*D */
    fe448_sub(&F, &B, &E);             /* F = B - E */
    fe448_add(&G, &B, &E);             /* G = B + E */
    fe448_add(&H, &p->X, &p->Y);
    fe448_add(&t, &q->X, &q->Y);
    fe448_mul(&H, &H, &t);             /* H = (X1+Y1)*(X2+Y2) */
    fe448_sub(&H, &H, &C);
    fe448_sub(&H, &H, &D);             /* H - C - D */
    fe448_mul(&t, &A, &F);
    fe448_mul(&r->X, &t, &H);          /* X3 = A*F*(H-C-D) */
    fe448_sub(&t, &D, &C);
    fe448_mul(&t, &t, &G);
    fe448_mul(&r->Y, &t, &A);          /* Y3 = A*G*(D-C) */
    fe448_mul(&r->Z, &F, &G);          /* Z3 = F*G */
}

/** @brief r = 2p (RFC 8032 5.2.4 doubling). */
static void ge448_dbl(ge448_pt_t *r, const ge448_pt_t *p)
{
    fe448_t B;
    fe448_t C;
    fe448_t D;
    fe448_t E;
    fe448_t H;
    fe448_t J;
    fe448_t t;

    fe448_add(&t, &p->X, &p->Y);
    fe448_sqr(&B, &t);                 /* B = (X1+Y1)^2 */
    fe448_sqr(&C, &p->X);              /* C = X1^2 */
    fe448_sqr(&D, &p->Y);              /* D = Y1^2 */
    fe448_add(&E, &C, &D);             /* E = C + D */
    fe448_sqr(&H, &p->Z);              /* H = Z1^2 */
    fe448_add(&t, &H, &H);
    fe448_sub(&J, &E, &t);             /* J = E - 2H */
    fe448_sub(&t, &B, &E);
    fe448_mul(&r->X, &t, &J);          /* X3 = (B-E)*J */
    fe448_sub(&t, &C, &D);
    fe448_mul(&r->Y, &E, &t);          /* Y3 = E*(C-D) */
    fe448_mul(&r->Z, &E, &J);          /* Z3 = E*J */
}

/** @brief r = cond ? p : r (constant time). */
static void ge448_cmov(ge448_pt_t *r, const ge448_pt_t *p, uint32_t cond)
{
    fe448_cmov(&r->X, &p->X, cond);
    fe448_cmov(&r->Y, &p->Y, cond);
    fe448_cmov(&r->Z, &p->Z, cond);
}

/**
 * @brief r = [s]P, constant time (double-and-always-add over all 456 scalar bits).
 * @param[out] r    Result.
 * @param[in]  s_le Scalar, NOXTLS_ED448_PRIVATE_KEY_SIZE (57) little-endian bytes.
 * @param[in]  P    Point.
 */
static void ge448_scalar_mult(ge448_pt_t *r, const uint8_t s_le[NOXTLS_ED448_PRIVATE_KEY_SIZE], const ge448_pt_t *P)
{
    ge448_pt_t acc;
    ge448_pt_t sum;
    uint32_t i;

    ge448_identity(&acc);
    for(i = NOXTLS_ED448_PRIVATE_KEY_SIZE * 8U; i > 0U; i -= 1U) {
        uint32_t bit_index = i - 1U;
        uint32_t bit = ((uint32_t)s_le[bit_index >> 3U] >> (bit_index & 7U)) & 1U;
        ge448_dbl(&acc, &acc);
        ge448_add(&sum, &acc, P);
        ge448_cmov(&acc, &sum, bit);
    }
    *r = acc;
    noxtls_secure_zero(&acc, sizeof(acc));
    noxtls_secure_zero(&sum, sizeof(sum));
}

/**
 * @brief Decode a 57-byte point encoding (RFC 8032 5.2.3).
 *
 * Rejects: non-zero reserved bits of the last octet, y >= p, no square root for x,
 * and x = 0 with the sign bit set.
 *
 * @return NOXTLS_RETURN_SUCCESS, or NOXTLS_RETURN_FAILED for an invalid encoding.
 */
static noxtls_return_t ge448_decode(ge448_pt_t *p, const uint8_t enc[NOXTLS_ED448_PUBLIC_KEY_SIZE])
{
    uint8_t canon[NOXTLS_ED448_FE448_BYTES];
    fe448_t y;
    fe448_t y2;
    fe448_t u;
    fe448_t v;
    fe448_t x;
    fe448_t t;
    fe448_t one;
    uint32_t x0;

    /* Bit 455 is x_0; bits 448..454 belong to y and must be zero since y < p < 2^448. */
    if((enc[NOXTLS_ED448_PUBLIC_KEY_SIZE - 1U] & NOXTLS_ED448_COMPRESSED_Y_SIGN_MASK) != 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    x0 = (uint32_t)enc[NOXTLS_ED448_PUBLIC_KEY_SIZE - 1U] >> 7U;

    /* y must be canonical (y < p): the re-encoding must match the input octets. */
    fe448_from_bytes(&y, enc);
    fe448_to_bytes(canon, &y);
    if(noxtls_secret_memcmp(canon, enc, (size_t)NOXTLS_ED448_FE448_BYTES) != 0) {
        return NOXTLS_RETURN_FAILED;
    }

    /* x^2 = (y^2 - 1) / (d y^2 - 1) = u / v. */
    fe448_one(&one);
    fe448_sqr(&y2, &y);
    fe448_sub(&u, &y2, &one);
    fe448_mul(&v, &y2, &fe448_d);
    fe448_sub(&v, &v, &one);

    /* x = u^3 v (u^5 v^3)^((p-3)/4) */
    fe448_sqr(&t, &u);
    fe448_mul(&x, &t, &u);              /* u^3 */
    fe448_mul(&x, &x, &v);              /* u^3 v */
    fe448_mul(&t, &t, &x);              /* u^5 v */
    fe448_sqr(&y2, &v);
    fe448_mul(&t, &t, &y2);             /* u^5 v^3 */
    fe448_pow(&t, &t, ed448_exp_p_minus_3_div_4);
    fe448_mul(&x, &x, &t);

    /* v x^2 must equal u, otherwise there is no square root. */
    fe448_sqr(&t, &x);
    fe448_mul(&t, &t, &v);
    if(fe448_equal(&t, &u) == 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    /* x = 0 with x_0 = 1 is not a valid encoding. */
    if((fe448_is_zero(&x) != 0U) && (x0 != 0U)) {
        return NOXTLS_RETURN_FAILED;
    }
    if(fe448_lsb(&x) != x0) {
        fe448_t zero;
        fe448_zero(&zero);
        fe448_sub(&x, &zero, &x);
    }
    p->X = x;
    p->Y = y;
    fe448_one(&p->Z);
    return NOXTLS_RETURN_SUCCESS;
}

/** @brief Encode a point to 57 bytes (RFC 8032 5.2.2). */
static void ge448_encode(uint8_t enc[NOXTLS_ED448_PUBLIC_KEY_SIZE], const ge448_pt_t *p)
{
    fe448_t zinv;
    fe448_t x;
    fe448_t y;

    fe448_inv(&zinv, &p->Z);
    fe448_mul(&x, &p->X, &zinv);
    fe448_mul(&y, &p->Y, &zinv);
    fe448_to_bytes(enc, &y);
    enc[NOXTLS_ED448_PUBLIC_KEY_SIZE - 1U] = (uint8_t)(fe448_lsb(&x) << 7U);
}

/** @brief 1 if p and q are the same point (projective comparison), else 0. */
static uint32_t ge448_equal(const ge448_pt_t *p, const ge448_pt_t *q)
{
    fe448_t l;
    fe448_t r;
    uint32_t eq;

    fe448_mul(&l, &p->X, &q->Z);
    fe448_mul(&r, &q->X, &p->Z);
    eq = fe448_equal(&l, &r);
    fe448_mul(&l, &p->Y, &q->Z);
    fe448_mul(&r, &q->Y, &p->Z);
    eq &= fe448_equal(&l, &r);
    return eq;
}

/* ------------------------------------------------------------------------- */
/* Scalars modulo L                                                           */
/* ------------------------------------------------------------------------- */

/**
 * @brief Reduce a 114-byte little-endian integer modulo L into a 57-byte little-endian scalar.
 * @return NOXTLS_RETURN_SUCCESS on success, or an error from the bignum module.
 */
static noxtls_return_t sc448_reduce_mod_l(uint8_t out_le[NOXTLS_ED448_PRIVATE_KEY_SIZE], const uint8_t in_le[NOXTLS_ED448_SHAKE_WIDE_BYTES])
{
    uint8_t in_be[NOXTLS_ED448_SHAKE_WIDE_BYTES];
    uint8_t out_be[NOXTLS_ED448_FE448_BYTES];
    noxtls_return_t rc;
    uint32_t i;

    for(i = 0U; i < NOXTLS_ED448_SHAKE_WIDE_BYTES; i += 1U) {
        in_be[i] = in_le[NOXTLS_ED448_SHAKE_WIDE_BYTES - 1U - i];
    }
    rc = noxtls_bn_mod(out_be, in_be, NOXTLS_ED448_SHAKE_WIDE_BYTES, ed448_L, NOXTLS_ED448_FE448_BYTES);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        for(i = 0U; i < NOXTLS_ED448_FE448_BYTES; i += 1U) {
            out_le[i] = out_be[NOXTLS_ED448_FE448_BYTES - 1U - i];
        }
        out_le[NOXTLS_ED448_FE448_BYTES] = 0U;
    }
    noxtls_secure_zero(in_be, sizeof(in_be));
    noxtls_secure_zero(out_be, sizeof(out_be));
    return rc;
}

/**
 * @brief out = (a * b + c) mod L; all operands 57-byte little-endian (byte schoolbook, no
 *        data-dependent branches).
 */
static noxtls_return_t sc448_muladd(uint8_t out_le[NOXTLS_ED448_PRIVATE_KEY_SIZE],
    const uint8_t a_le[NOXTLS_ED448_PRIVATE_KEY_SIZE],
    const uint8_t b_le[NOXTLS_ED448_PRIVATE_KEY_SIZE],
    const uint8_t c_le[NOXTLS_ED448_PRIVATE_KEY_SIZE])
{
    uint8_t wide[NOXTLS_ED448_SHAKE_WIDE_BYTES];
    uint32_t i;
    uint32_t j;
    uint32_t carry;
    noxtls_return_t rc;

    for(i = 0U; i < NOXTLS_ED448_SHAKE_WIDE_BYTES; i += 1U) {
        wide[i] = 0U;
    }
    for(i = 0U; i < NOXTLS_ED448_PRIVATE_KEY_SIZE; i += 1U) {
        carry = 0U;
        for(j = 0U; j < NOXTLS_ED448_PRIVATE_KEY_SIZE; j += 1U) {
            uint32_t t = (uint32_t)wide[i + j] + ((uint32_t)a_le[i] * (uint32_t)b_le[j]) + carry;
            wide[i + j] = (uint8_t)(t & 0xFFU);
            carry = t >> 8U;
        }
        wide[i + NOXTLS_ED448_PRIVATE_KEY_SIZE] = (uint8_t)carry;
    }
    carry = 0U;
    for(i = 0U; i < NOXTLS_ED448_SHAKE_WIDE_BYTES; i += 1U) {
        uint32_t add = (i < NOXTLS_ED448_PRIVATE_KEY_SIZE) ? (uint32_t)c_le[i] : 0U;
        uint32_t t = (uint32_t)wide[i] + add + carry;
        wide[i] = (uint8_t)(t & 0xFFU);
        carry = t >> 8U;
    }
    /* a, b < 2^448 and c < 2^456 (callers pass reduced scalars): no carry out of 114 bytes. */
    rc = sc448_reduce_mod_l(out_le, wide);
    noxtls_secure_zero(wide, sizeof(wide));
    return rc;
}

/* ------------------------------------------------------------------------- */
/* Hashing helpers                                                            */
/* ------------------------------------------------------------------------- */

/**
 * @brief Build dom4(phflag, context) (RFC 8032 5.2): "SigEd448" || phflag || len(C) || C.
 * @return Total length written: NOXTLS_ED448_DOM4_PREFIX_BYTES + ctx_len.
 */
static uint32_t ed448_dom4_build(uint8_t out[NOXTLS_ED448_DOM4_BUFFER_BYTES], uint8_t phflag,
    const uint8_t *ctx, uint32_t ctx_len)
{
    static const uint8_t sig8[NOXTLS_ED448_DOM4_LITERAL_BYTES] = { 'S','i','g','E','d','4','4','8' };
    noxtls_copy_u8(out, (size_t)NOXTLS_ED448_DOM4_BUFFER_BYTES, sig8, (size_t)NOXTLS_ED448_DOM4_LITERAL_BYTES);
    out[NOXTLS_ED448_DOM4_LITERAL_BYTES] = phflag;
    out[NOXTLS_ED448_DOM4_LITERAL_BYTES + 1U] = (uint8_t)ctx_len;
    if((ctx_len != 0U) && (ctx != NULL)) {
        noxtls_copy_u8(&out[NOXTLS_ED448_DOM4_PREFIX_BYTES],
                       (size_t)(NOXTLS_ED448_DOM4_BUFFER_BYTES - NOXTLS_ED448_DOM4_PREFIX_BYTES),
                       ctx, (size_t)ctx_len);
    }
    return NOXTLS_ED448_DOM4_PREFIX_BYTES + ctx_len;
}

/**
 * @brief SHAKE256(parts[0] || ... || parts[n-1], 114).
 * @return NOXTLS_RETURN_SUCCESS on success, or an error from SHAKE256.
 */
static noxtls_return_t ed448_shake256_chain(uint8_t out[NOXTLS_ED448_SHAKE_WIDE_BYTES], uint32_t n,
    const uint8_t * const *parts, const uint32_t *lens)
{
    noxtls_sha3_ctx_t ctx;
    noxtls_return_t rc;
    uint32_t i;

    rc = noxtls_shake256_init(&ctx);
    for(i = 0U; (i < n) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        if((lens[i] != 0U) && (parts[i] != NULL)) {
            rc = noxtls_shake256_update(&ctx, parts[i], lens[i]);
        }
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_final(&ctx);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_squeeze(&ctx, out, NOXTLS_ED448_SHAKE_WIDE_BYTES);
    }
    noxtls_secure_zero(&ctx, sizeof(ctx));
    return (rc == NOXTLS_RETURN_SUCCESS) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
}

/**
 * @brief Expand the private key and derive the clamped secret scalar (RFC 8032 5.2.5).
 *
 * h = SHAKE256(sk, 114); s = h[0..56] with the two low bits of h[0] cleared, the top bit of
 * h[55] set and h[56] cleared; prefix = h[57..113].
 *
 * @param[out] s_le   57-byte little-endian secret scalar.
 * @param[out] prefix 57-byte nonce prefix (may be NULL).
 * @param[in]  sk     57-byte private key.
 */
static noxtls_return_t ed448_expand_secret(uint8_t s_le[NOXTLS_ED448_PRIVATE_KEY_SIZE],
    uint8_t *prefix, const uint8_t sk[NOXTLS_ED448_PRIVATE_KEY_SIZE])
{
    uint8_t h[NOXTLS_ED448_SHAKE_WIDE_BYTES];
    const uint8_t *parts[1];
    uint32_t lens[1];
    noxtls_return_t rc;

    parts[0] = sk;
    lens[0] = NOXTLS_ED448_PRIVATE_KEY_SIZE;
    rc = ed448_shake256_chain(h, 1U, parts, lens);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_copy_u8(s_le, (size_t)NOXTLS_ED448_PRIVATE_KEY_SIZE, h, (size_t)NOXTLS_ED448_PRIVATE_KEY_SIZE);
        s_le[0] &= (uint8_t)NOXTLS_ED448_SCALAR_CLAMP_BYTE0_MASK;
        s_le[NOXTLS_ED448_FE448_BYTES - 1U] &= (uint8_t)NOXTLS_ED448_SCALAR_CLAMP_BYTE55_AND;
        s_le[NOXTLS_ED448_FE448_BYTES - 1U] |= (uint8_t)NOXTLS_ED448_SCALAR_CLAMP_BYTE55_OR;
        s_le[NOXTLS_ED448_PRIVATE_KEY_SIZE - 1U] = 0U;
        if(prefix != NULL) {
            noxtls_copy_u8(prefix, (size_t)NOXTLS_ED448_PRIVATE_KEY_SIZE, &h[NOXTLS_ED448_PRIVATE_KEY_SIZE],
                           (size_t)NOXTLS_ED448_PRIVATE_KEY_SIZE);
        }
    }
    noxtls_secure_zero(h, sizeof(h));
    return rc;
}

/**
 * @brief Ed448ph message representative: SHAKE256(M, 64) (RFC 8032 5.2).
 */
static noxtls_return_t ed448_ph64(const uint8_t *msg, uint32_t msg_len, uint8_t digest[NOXTLS_ED448_PH_DIGEST_BYTES])
{
    noxtls_sha3_ctx_t ctx;
    noxtls_return_t rc;

    rc = noxtls_shake256_init(&ctx);
    if((rc == NOXTLS_RETURN_SUCCESS) && (msg_len != 0U) && (msg != NULL)) {
        rc = noxtls_shake256_update(&ctx, msg, msg_len);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_final(&ctx);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_squeeze(&ctx, digest, NOXTLS_ED448_PH_DIGEST_BYTES);
    }
    return (rc == NOXTLS_RETURN_SUCCESS) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
}

/**
 * @internal
 * @brief Validate the phflag/context combination shared by sign and verify.
 */
static noxtls_return_t ed448_check_mode(uint8_t phflag, const uint8_t *ctx, uint32_t ctx_len)
{
    if(phflag > NOXTLS_ED448_PH_FLAG_PREHASH) {
        return NOXTLS_RETURN_FAILED;
    }
    if(phflag == NOXTLS_ED448_PH_FLAG_PREHASH) {
        if((ctx_len != 0U) || (ctx != NULL)) {
            return NOXTLS_RETURN_FAILED;
        }
    } else if(ctx_len != 0U) {
        if((ctx == NULL) || (ctx_len > (uint32_t)NOXTLS_ED448_CONTEXT_MAX)) {
            return NOXTLS_RETURN_FAILED;
        }
    } else {
        /* Pure Ed448: dom4(0, "") */
    }
    return NOXTLS_RETURN_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* Sign / verify                                                              */
/* ------------------------------------------------------------------------- */

/**
 * @internal
 * @brief Shared Ed448 / Ed448ctx / Ed448ph signing (RFC 8032 5.2.6).
 *
 * @param[in] private_key 57-byte private key.
 * @param[in] noxtls_message Message (for Ed448ph the full message; it is prehashed here).
 * @param[in] message_len Length of @p noxtls_message.
 * @param[out] signature 114-byte signature R || S.
 * @param[in] phflag NOXTLS_ED448_PH_FLAG_PURE or NOXTLS_ED448_PH_FLAG_PREHASH.
 * @param[in] ctx Context string (NULL when ctx_len is 0).
 * @param[in] ctx_len Context length (0..NOXTLS_ED448_CONTEXT_MAX; 0 for Ed448ph).
 *
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL on invalid pointers,
 *         NOXTLS_RETURN_FAILED on inconsistent parameters or a failed crypto step.
 */
static noxtls_return_t ed448_sign_internal(const uint8_t private_key[NOXTLS_ED448_PRIVATE_KEY_SIZE],
    const uint8_t *noxtls_message, uint32_t message_len, uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE],
    uint8_t phflag, const uint8_t *ctx, uint32_t ctx_len)
{
    uint8_t s_le[NOXTLS_ED448_PRIVATE_KEY_SIZE];
    uint8_t prefix[NOXTLS_ED448_PRIVATE_KEY_SIZE];
    uint8_t wide[NOXTLS_ED448_SHAKE_WIDE_BYTES];
    uint8_t r_le[NOXTLS_ED448_PRIVATE_KEY_SIZE];
    uint8_t k_le[NOXTLS_ED448_PRIVATE_KEY_SIZE];
    uint8_t S_le[NOXTLS_ED448_PRIVATE_KEY_SIZE];
    uint8_t public_key[NOXTLS_ED448_PUBLIC_KEY_SIZE];
    uint8_t dom[NOXTLS_ED448_DOM4_BUFFER_BYTES];
    uint8_t ph_buf[NOXTLS_ED448_PH_DIGEST_BYTES];
    const uint8_t *parts[4];
    uint32_t lens[4];
    uint32_t dom_len;
    const uint8_t *m_body = NULL;
    uint32_t m_len = 0U;
    ge448_pt_t B;
    ge448_pt_t P;
    noxtls_return_t rc;

    if((private_key == NULL) || (signature == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if((noxtls_message == NULL) && (message_len != 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    rc = ed448_check_mode(phflag, ctx, ctx_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    dom_len = ed448_dom4_build(dom, phflag, ctx, ctx_len);

    if(phflag == NOXTLS_ED448_PH_FLAG_PREHASH) {
        rc = ed448_ph64(noxtls_message, message_len, ph_buf);
        m_body = ph_buf;
        m_len = NOXTLS_ED448_PH_DIGEST_BYTES;
    } else {
        m_body = noxtls_message;
        m_len = message_len;
    }

    /* s, prefix and A = [s]B */
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = ed448_expand_secret(s_le, prefix, private_key);
    }
    ge448_base(&B);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        ge448_scalar_mult(&P, s_le, &B);
        ge448_encode(public_key, &P);
    }

    /* r = SHAKE256(dom4(F, C) || prefix || PH(M), 114) mod L; R = [r]B */
    if(rc == NOXTLS_RETURN_SUCCESS) {
        parts[0] = dom;
        lens[0] = dom_len;
        parts[1] = prefix;
        lens[1] = NOXTLS_ED448_PRIVATE_KEY_SIZE;
        parts[2] = m_body;
        lens[2] = m_len;
        rc = ed448_shake256_chain(wide, 3U, parts, lens);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = sc448_reduce_mod_l(r_le, wide);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        ge448_scalar_mult(&P, r_le, &B);
        ge448_encode(signature, &P);
    }

    /* k = SHAKE256(dom4(F, C) || R || A || PH(M), 114) mod L; S = (r + k*s) mod L */
    if(rc == NOXTLS_RETURN_SUCCESS) {
        parts[0] = dom;
        lens[0] = dom_len;
        parts[1] = signature;
        lens[1] = NOXTLS_ED448_PUBLIC_KEY_SIZE;
        parts[2] = public_key;
        lens[2] = NOXTLS_ED448_PUBLIC_KEY_SIZE;
        parts[3] = m_body;
        lens[3] = m_len;
        rc = ed448_shake256_chain(wide, 4U, parts, lens);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = sc448_reduce_mod_l(k_le, wide);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = sc448_muladd(S_le, k_le, s_le, r_le);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_copy_u8(&signature[NOXTLS_ED448_PUBLIC_KEY_SIZE], (size_t)NOXTLS_ED448_PRIVATE_KEY_SIZE,
                       S_le, (size_t)NOXTLS_ED448_PRIVATE_KEY_SIZE);
    } else {
        noxtls_secure_zero(signature, (size_t)NOXTLS_ED448_SIGNATURE_SIZE);
        rc = NOXTLS_RETURN_FAILED;
    }

    noxtls_secure_zero(s_le, sizeof(s_le));
    noxtls_secure_zero(prefix, sizeof(prefix));
    noxtls_secure_zero(wide, sizeof(wide));
    noxtls_secure_zero(r_le, sizeof(r_le));
    noxtls_secure_zero(&P, sizeof(P));
    return rc;
}

/**
 * @internal
 * @brief Verification core (RFC 8032 5.2.7) once k = SHAKE256(dom4 || R || A || PH(M)) is known.
 *
 * Decodes A and R (rejecting invalid encodings), rejects S >= L (including any non-zero top
 * octet) and checks the cofactored equation [4][S]B == [4]R + [4][k]A.
 */
static noxtls_return_t ed448_verify_finalize(const uint8_t public_key[NOXTLS_ED448_PUBLIC_KEY_SIZE],
                                             const uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE],
                                             const uint8_t k_in[NOXTLS_ED448_SHAKE_WIDE_BYTES])
{
    ge448_pt_t A;
    ge448_pt_t R;
    ge448_pt_t B;
    ge448_pt_t sB;
    ge448_pt_t kA;
    uint8_t k_le[NOXTLS_ED448_PRIVATE_KEY_SIZE];
    uint8_t S_be[NOXTLS_ED448_FE448_BYTES];
    const uint8_t *S_le = &signature[NOXTLS_ED448_PUBLIC_KEY_SIZE];
    uint32_t i;

    if((public_key == NULL) || (signature == NULL) || (k_in == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    /* S is 57 octets: the last one must be zero and the value must be < L. */
    if(S_le[NOXTLS_ED448_PRIVATE_KEY_SIZE - 1U] != 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    for(i = 0U; i < NOXTLS_ED448_FE448_BYTES; i += 1U) {
        S_be[i] = S_le[NOXTLS_ED448_FE448_BYTES - 1U - i];
    }
    if(noxtls_bn_cmp(S_be, ed448_L, NOXTLS_ED448_FE448_BYTES) >= 0) {
        return NOXTLS_RETURN_FAILED;
    }
    if(ge448_decode(&A, public_key) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(ge448_decode(&R, signature) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(sc448_reduce_mod_l(k_le, k_in) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    ge448_base(&B);
    ge448_scalar_mult(&sB, S_le, &B);
    ge448_scalar_mult(&kA, k_le, &A);
    ge448_add(&R, &R, &kA);
    /* Multiply both sides by the cofactor 4. */
    ge448_dbl(&sB, &sB);
    ge448_dbl(&sB, &sB);
    ge448_dbl(&R, &R);
    ge448_dbl(&R, &R);
    return (ge448_equal(&sB, &R) != 0U) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
}

/**
 * @internal
 * @brief Shared Ed448 / Ed448ctx / Ed448ph verification (RFC 8032 5.2.7).
 *
 * @return NOXTLS_RETURN_SUCCESS if the signature is valid, NOXTLS_RETURN_NULL on invalid
 *         pointers, NOXTLS_RETURN_FAILED otherwise.
 */
static noxtls_return_t ed448_verify_internal(const uint8_t public_key[NOXTLS_ED448_PUBLIC_KEY_SIZE],
    const uint8_t *noxtls_message, uint32_t message_len, const uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE],
    uint8_t phflag, const uint8_t *ctx, uint32_t ctx_len)
{
    uint8_t dom[NOXTLS_ED448_DOM4_BUFFER_BYTES];
    uint8_t k_in[NOXTLS_ED448_SHAKE_WIDE_BYTES];
    uint8_t ph_buf[NOXTLS_ED448_PH_DIGEST_BYTES];
    const uint8_t *parts[4];
    uint32_t lens[4];
    uint32_t dom_len;
    const uint8_t *m_body = NULL;
    uint32_t m_len = 0U;
    noxtls_return_t rc;

    if((public_key == NULL) || (signature == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if((noxtls_message == NULL) && (message_len != 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    rc = ed448_check_mode(phflag, ctx, ctx_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    dom_len = ed448_dom4_build(dom, phflag, ctx, ctx_len);

    if(phflag == NOXTLS_ED448_PH_FLAG_PREHASH) {
        if(ed448_ph64(noxtls_message, message_len, ph_buf) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        m_body = ph_buf;
        m_len = NOXTLS_ED448_PH_DIGEST_BYTES;
    } else {
        m_body = noxtls_message;
        m_len = message_len;
    }

    parts[0] = dom;
    lens[0] = dom_len;
    parts[1] = signature;
    lens[1] = NOXTLS_ED448_PUBLIC_KEY_SIZE;
    parts[2] = public_key;
    lens[2] = NOXTLS_ED448_PUBLIC_KEY_SIZE;
    parts[3] = m_body;
    lens[3] = m_len;
    if(ed448_shake256_chain(k_in, 4U, parts, lens) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    return ed448_verify_finalize(public_key, signature, k_in);
}

noxtls_return_t noxtls_ed448_verify_stream_init(noxtls_ed448_verify_stream_ctx_t *ctx,
                                                const uint8_t public_key[NOXTLS_ED448_PUBLIC_KEY_SIZE],
                                                const uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE])
{
    uint8_t dom[NOXTLS_ED448_DOM4_BUFFER_BYTES];
    uint32_t dom_len;
    noxtls_return_t rc;

    if((ctx == NULL) || (public_key == NULL) || (signature == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero(ctx, sizeof(*ctx));
    noxtls_copy_u8(ctx->public_key, sizeof(ctx->public_key), public_key, (size_t)NOXTLS_ED448_PUBLIC_KEY_SIZE);
    noxtls_copy_u8(ctx->signature, sizeof(ctx->signature), signature, (size_t)NOXTLS_ED448_SIGNATURE_SIZE);

    /* Pure Ed448: k = SHAKE256(dom4(0, "") || R || A || M, 114). */
    dom_len = ed448_dom4_build(dom, NOXTLS_ED448_PH_FLAG_PURE, NULL, 0U);
    rc = noxtls_shake256_init(&ctx->shake_ctx);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_update(&ctx->shake_ctx, dom, dom_len);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_update(&ctx->shake_ctx, signature, NOXTLS_ED448_PUBLIC_KEY_SIZE);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_update(&ctx->shake_ctx, public_key, NOXTLS_ED448_PUBLIC_KEY_SIZE);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    ctx->initialized = 1U;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_ed448_verify_stream_update(noxtls_ed448_verify_stream_ctx_t *ctx,
                                                  const uint8_t *message_part,
                                                  uint32_t message_part_len)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->initialized == 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    if((message_part == NULL) && (message_part_len != 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    if(message_part_len == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }
    return noxtls_shake256_update(&ctx->shake_ctx, message_part, message_part_len);
}

noxtls_return_t noxtls_ed448_verify_stream_final(noxtls_ed448_verify_stream_ctx_t *ctx)
{
    uint8_t k_in[NOXTLS_ED448_SHAKE_WIDE_BYTES];

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->initialized == 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    ctx->initialized = 0U;
    if(noxtls_shake256_final(&ctx->shake_ctx) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(noxtls_shake256_squeeze(&ctx->shake_ctx, k_in, NOXTLS_ED448_SHAKE_WIDE_BYTES) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    return ed448_verify_finalize(ctx->public_key, ctx->signature, k_in);
}

/**
 * @brief Derive the Ed448 public key (57-byte encoding) from a 57-byte private key (RFC 8032 5.2.5).
 * @param[in] private_key 57-byte secret.
 * @param[out] public_key 57-byte compressed public key.
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if @p private_key or @p public_key is NULL.
 * @return NOXTLS_RETURN_FAILED if hashing fails.
 */
noxtls_return_t noxtls_ed448_public_key(const uint8_t private_key[NOXTLS_ED448_PRIVATE_KEY_SIZE], uint8_t public_key[NOXTLS_ED448_PUBLIC_KEY_SIZE])
{
    uint8_t s_le[NOXTLS_ED448_PRIVATE_KEY_SIZE];
    ge448_pt_t B;
    ge448_pt_t A;
    noxtls_return_t rc;

    if((private_key == NULL) || (public_key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    rc = ed448_expand_secret(s_le, NULL, private_key);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        ge448_base(&B);
        ge448_scalar_mult(&A, s_le, &B);
        ge448_encode(public_key, &A);
    } else {
        rc = NOXTLS_RETURN_FAILED;
    }
    noxtls_secure_zero(s_le, sizeof(s_le));
    noxtls_secure_zero(&A, sizeof(A));
    return rc;
}

/**
 * @brief Sign a noxtls_message with Ed448 (PureEdDSA, no context string; RFC 8032).
 * @param[in] private_key 57-byte private seed.
 * @param[in] noxtls_message Message bytes (NULL allowed only if @p message_len is 0).
 * @param[in] message_len Length of @p noxtls_message in bytes.
 * @param[out] signature 114-byte signature (R || S).
 * @return NOXTLS_RETURN_SUCCESS on success, or an error from the internal signing path.
 */
noxtls_return_t noxtls_ed448_sign(const uint8_t private_key[NOXTLS_ED448_PRIVATE_KEY_SIZE], const uint8_t *noxtls_message, uint32_t message_len, uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE]) { return ed448_sign_internal(private_key, noxtls_message, message_len, signature, NOXTLS_ED448_PH_FLAG_PURE, NULL, 0U); }

/**
 * @brief Verify an Ed448 signature (pure mode; RFC 8032).
 * @param[in] public_key 57-byte public key encoding.
 * @param[in] noxtls_message Message that was signed.
 * @param[in] message_len Length of @p noxtls_message in bytes.
 * @param[in] signature 114-byte signature (R || S).
 * @return NOXTLS_RETURN_SUCCESS if the signature is valid.
 * @return NOXTLS_RETURN_NULL on invalid pointer combination.
 * @return NOXTLS_RETURN_FAILED if verification fails.
 */
noxtls_return_t noxtls_ed448_verify(const uint8_t public_key[NOXTLS_ED448_PUBLIC_KEY_SIZE], const uint8_t *noxtls_message, uint32_t message_len, const uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE]) { return ed448_verify_internal(public_key, noxtls_message, message_len, signature, NOXTLS_ED448_PH_FLAG_PURE, NULL, 0U); }

/**
 * @brief Sign with Ed448ctx (non-empty context string; RFC 8032).
 * @param[in] private_key 57-byte private seed.
 * @param[in] context Context bytes (length must be 1..NOXTLS_ED448_CONTEXT_MAX).
 * @param[in] context_len Length of @p context.
 * @param[in] noxtls_message Message to sign.
 * @param[in] message_len Length of @p noxtls_message in bytes.
 * @param[out] signature 114-byte signature.
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if @p context is NULL while @p context_len is non-zero.
 * @return NOXTLS_RETURN_FAILED if @p context_len is out of range or signing fails.
 */
noxtls_return_t noxtls_ed448ctx_sign(const uint8_t private_key[NOXTLS_ED448_PRIVATE_KEY_SIZE],
    const uint8_t *context, uint32_t context_len,
    const uint8_t *noxtls_message, uint32_t message_len, uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE])
{
    if((context == NULL) && (context_len != 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    if((context_len < 1U) || (context_len > (uint32_t)NOXTLS_ED448_CONTEXT_MAX)) {
        return NOXTLS_RETURN_FAILED;
    }
    return ed448_sign_internal(private_key, noxtls_message, message_len, signature, NOXTLS_ED448_PH_FLAG_PURE, context, context_len);
}

/**
 * @brief Verify an Ed448ctx signature (RFC 8032).
 * @param[in] public_key 57-byte public key encoding.
 * @param[in] context Same context string used when signing.
 * @param[in] context_len Length of @p context (1..NOXTLS_ED448_CONTEXT_MAX).
 * @param[in] noxtls_message Message that was signed.
 * @param[in] message_len Length of @p noxtls_message in bytes.
 * @param[in] signature 114-byte signature.
 * @return NOXTLS_RETURN_SUCCESS if the signature is valid.
 * @return NOXTLS_RETURN_NULL if @p context is NULL while @p context_len is non-zero.
 * @return NOXTLS_RETURN_FAILED if @p context_len is out of range or verification fails.
 */
noxtls_return_t noxtls_ed448ctx_verify(const uint8_t public_key[NOXTLS_ED448_PUBLIC_KEY_SIZE],
    const uint8_t *context, uint32_t context_len,
    const uint8_t *noxtls_message, uint32_t message_len, const uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE])
{
    if((context == NULL) && (context_len != 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    if((context_len < 1U) || (context_len > (uint32_t)NOXTLS_ED448_CONTEXT_MAX)) {
        return NOXTLS_RETURN_FAILED;
    }
    return ed448_verify_internal(public_key, noxtls_message, message_len, signature, NOXTLS_ED448_PH_FLAG_PURE, context, context_len);
}

/**
 * @brief Sign with Ed448ph: noxtls_message representative is SHAKE256(M, 64) (RFC 8032).
 * @param[in] private_key 57-byte private seed.
 * @param[in] noxtls_message Message to prehash.
 * @param[in] message_len Length of @p noxtls_message in bytes.
 * @param[out] signature 114-byte signature.
 * @return NOXTLS_RETURN_SUCCESS on success, or an error from the internal signing path.
 */
noxtls_return_t noxtls_ed448ph_sign(const uint8_t private_key[NOXTLS_ED448_PRIVATE_KEY_SIZE],
    const uint8_t *noxtls_message, uint32_t message_len, uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE]) { return ed448_sign_internal(private_key, noxtls_message, message_len, signature, NOXTLS_ED448_PH_FLAG_PREHASH, NULL, 0U); }

/**
 * @brief Verify an Ed448ph signature (RFC 8032).
 * @param[in] public_key 57-byte public key encoding.
 * @param[in] noxtls_message Same noxtls_message input as for signing (full noxtls_message, not only the 64-byte digest).
 * @param[in] message_len Length of @p noxtls_message in bytes.
 * @param[in] signature 114-byte signature.
 * @return NOXTLS_RETURN_SUCCESS if the signature is valid.
 * @return NOXTLS_RETURN_NULL or NOXTLS_RETURN_FAILED on failure (see internal verify path).
 */
noxtls_return_t noxtls_ed448ph_verify(const uint8_t public_key[NOXTLS_ED448_PUBLIC_KEY_SIZE],
    const uint8_t *noxtls_message, uint32_t message_len, const uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE]) { return ed448_verify_internal(public_key, noxtls_message, message_len, signature, NOXTLS_ED448_PH_FLAG_PREHASH, NULL, 0U); }

/**
 * @brief Generate a random Ed448 key pair using the library DRBG (RFC 8032).
 * @param[out] private_key 57-byte random seed.
 * @param[out] public_key 57-byte derived public key.
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if an output pointer is NULL.
 * @return Other error codes from DRBG instantiation or generation.
 */
noxtls_return_t noxtls_ed448_generate_key(uint8_t private_key[NOXTLS_ED448_PRIVATE_KEY_SIZE], uint8_t public_key[NOXTLS_ED448_PUBLIC_KEY_SIZE])
{
    static drbg_state_t drbg_state;
    static int drbg_initialized = 0;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    if((private_key == NULL) || (public_key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if (drbg_initialized == 0) {
        rc = drbg_instantiate(&drbg_state, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_drbg_uninstantiate(&drbg_state);
            return rc;
        }
        drbg_initialized = 1;
    }
    rc = drbg_generate(&drbg_state, private_key, NOXTLS_ED448_DRBG_SEED_BITS, NULL, 0);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        /* Fail closed for this call and drop the instance: a failed generate
         * may have wiped the state, so the next call re-instantiates from
         * fresh entropy instead of failing forever. */
        (void)noxtls_drbg_uninstantiate(&drbg_state);
        drbg_initialized = 0;
        noxtls_secure_zero(private_key, (size_t)NOXTLS_ED448_PRIVATE_KEY_SIZE);
        return rc;
    }
    rc = noxtls_ed448_public_key(private_key, public_key);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(private_key, (size_t)NOXTLS_ED448_PRIVATE_KEY_SIZE);
    }
    return rc;
}

#endif /* NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3 */
