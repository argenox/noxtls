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
* File:    noxtls_x448.c
* Summary: X448 key agreement (Curve448, RFC 7748)
*
*
*****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "common/noxtls_memory.h"
#include "noxtls_common.h"
#include "noxtls_x448.h"
#include "pkc/noxtls_pkc_rng.h"
#include "common/noxtls_ct.h"

#if NOXTLS_FEATURE_X448



/* ------------------------------------------------------------------------- */
/* Field GF(p), p = 2^448 - 2^224 - 1: 16 little-endian limbs of 28 bits      */
/* (same representation and arithmetic as noxtls_ed448.c). All operations   */
/* run in constant time: no secret-dependent branches or memory indexing.   */
/* ------------------------------------------------------------------------- */

#define X448_FE_LIMBS       16U
#define X448_FE_LIMB_BITS   28U
#define X448_FE_LIMB_MASK   0x0FFFFFFFU
/** Limb index holding weight 2^224 (2^448 == 2^224 + 1 mod p). */
#define X448_FE_MID_LIMB    8U
/** Number of product columns (2 * 16) used by the multiplier. */
#define X448_FE_WIDE_LIMBS  32U
/** RFC 7748 a24 = (156326 - 2) / 4 for the X448 ladder. */
#define X448_A24            39081U

/** Field element: value = sum v[i] * 2^(28 i). Limbs are < 2^28 + 16 after every operation. */
typedef struct {
    uint32_t v[X448_FE_LIMBS];
} fe448_t;

/* p in limbs. */
static const fe448_t x448_fe_p = { {
    0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU,
    0x0FFFFFFEU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU, 0x0FFFFFFFU
} };

/* Keep the inversion out of line so its temporaries never share the ladder frame. */
#if defined(__GNUC__) || defined(__clang__)
#define X448_NOINLINE __attribute__((noinline))
#else
#define X448_NOINLINE
#endif

/**
 * @brief Weak reduction: fold carries so every limb is < 2^28 + 16 (value unchanged mod p).
 * @param[in,out] a Field element.
 */
static void fe448_weak_reduce(fe448_t *a)
{
    uint32_t i;
    uint32_t top = a->v[X448_FE_LIMBS - 1U] >> X448_FE_LIMB_BITS;

    a->v[X448_FE_MID_LIMB] += top;
    for(i = X448_FE_LIMBS - 1U; i > 0U; i -= 1U) {
        a->v[i] = (a->v[i] & X448_FE_LIMB_MASK) + (a->v[i - 1U] >> X448_FE_LIMB_BITS);
    }
    a->v[0] = (a->v[0] & X448_FE_LIMB_MASK) + top;
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
    for(i = 0U; i < X448_FE_LIMBS; i += 1U) {
        /* a->v[i] - p[i] - borrow lies in [-2^28, 17]: bias by 2^28 to stay unsigned. */
        uint32_t t = (a->v[i] + 0x10000000U) - x448_fe_p.v[i] - borrow;
        a->v[i] = t & X448_FE_LIMB_MASK;
        borrow = 1U - (t >> X448_FE_LIMB_BITS);
    }
    /* borrow == 1: the subtraction went negative, add p back (masked, no branch). */
    mask = 0U - borrow;
    for(i = 0U; i < X448_FE_LIMBS; i += 1U) {
        uint32_t t = a->v[i] + (x448_fe_p.v[i] & mask) + carry;
        a->v[i] = t & X448_FE_LIMB_MASK;
        carry = t >> X448_FE_LIMB_BITS;
    }
}

/** @brief r = 0. */
static void fe448_zero(fe448_t *r)
{
    uint32_t i;
    for(i = 0U; i < X448_FE_LIMBS; i += 1U) {
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
    for(i = 0U; i < X448_FE_LIMBS; i += 1U) {
        r->v[i] = a->v[i] + b->v[i];
    }
    fe448_weak_reduce(r);
}

/** @brief r = a - b mod p (computed as a + 2p - b so limbs never go negative). */
static void fe448_sub(fe448_t *r, const fe448_t *a, const fe448_t *b)
{
    uint32_t i;
    for(i = 0U; i < X448_FE_LIMBS; i += 1U) {
        r->v[i] = (a->v[i] + (2U * x448_fe_p.v[i])) - b->v[i];
    }
    fe448_weak_reduce(r);
}

/** @brief r = a * b mod p (schoolbook 16x16 limbs, Solinas folding 2^448 = 2^224 + 1). */
static void fe448_mul(fe448_t *r, const fe448_t *a, const fe448_t *b)
{
    uint64_t c[X448_FE_WIDE_LIMBS];
    uint32_t i;
    uint32_t j;

    for(i = 0U; i < X448_FE_WIDE_LIMBS; i += 1U) {
        c[i] = 0U;
    }
    /* Inputs have limbs < 2^28 + 16: every column sum is < 2^61. */
    for(i = 0U; i < X448_FE_LIMBS; i += 1U) {
        for(j = 0U; j < X448_FE_LIMBS; j += 1U) {
            c[i + j] += (uint64_t)a->v[i] * (uint64_t)b->v[j];
        }
    }
    /* Normalise the 32 columns to 28-bit digits. */
    for(i = 0U; i < (X448_FE_WIDE_LIMBS - 1U); i += 1U) {
        c[i + 1U] += c[i] >> X448_FE_LIMB_BITS;
        c[i] &= (uint64_t)X448_FE_LIMB_MASK;
    }
    /* Fold weights >= 2^448 from the top: 2^(28k) = 2^(28(k-16)) + 2^(28(k-8)). */
    for(i = X448_FE_WIDE_LIMBS - 1U; i >= X448_FE_LIMBS; i -= 1U) {
        c[i - X448_FE_LIMBS] += c[i];
        c[i - X448_FE_MID_LIMB] += c[i];
        c[i] = 0U;
    }
    /* All columns are now < 2^31: carry into 28-bit limbs, folding the final carry. */
    {
        uint64_t carry = 0U;
        for(i = 0U; i < X448_FE_LIMBS; i += 1U) {
            uint64_t t = c[i] + carry;
            r->v[i] = (uint32_t)(t & (uint64_t)X448_FE_LIMB_MASK);
            carry = t >> X448_FE_LIMB_BITS;
        }
        r->v[0] += (uint32_t)carry;
        r->v[X448_FE_MID_LIMB] += (uint32_t)carry;
    }
    fe448_weak_reduce(r);
}

/** @brief r = a^2 mod p. */
static void fe448_sqr(fe448_t *r, const fe448_t *a)
{
    fe448_mul(r, a, a);
}

/** @brief r = a * c mod p for a small constant c < 2^17 (RFC 7748 a24). */
static void fe448_mul_small(fe448_t *r, const fe448_t *a, uint32_t c)
{
    uint64_t carry = 0U;
    uint32_t i;

    /* Limbs < 2^28 + 16 times c < 2^17: every product plus carry is < 2^46. */
    for(i = 0U; i < X448_FE_LIMBS; i += 1U) {
        uint64_t t = ((uint64_t)a->v[i] * (uint64_t)c) + carry;
        r->v[i] = (uint32_t)(t & (uint64_t)X448_FE_LIMB_MASK);
        carry = t >> X448_FE_LIMB_BITS;
    }
    /* carry < 2^18 has weight 2^448 = 2^224 + 1. */
    r->v[0] += (uint32_t)carry;
    r->v[X448_FE_MID_LIMB] += (uint32_t)carry;
    fe448_weak_reduce(r);
}

/** @brief r = a^(2^n) mod p (n >= 1 squarings). */
static void fe448_sqr_n(fe448_t *r, const fe448_t *a, uint32_t n)
{
    uint32_t i;
    fe448_sqr(r, a);
    for(i = 1U; i < n; i += 1U) {
        fe448_sqr(r, r);
    }
}

/**
 * @brief r = a^(p-2) = a^-1 mod p (Fermat; 0 maps to 0).
 *
 * Fixed addition chain (453 squarings, 13 multiplications) for
 * p - 2 = 2^448 - 2^224 - 3 = ((2^223-1) * 2^223 + 2^222 - 1) * 4 + 1,
 * with x_k = a^(2^k - 1). The exponent is public; the sequence of operations
 * does not depend on @p a. Temporaries are wiped (secret ladder state).
 */
static X448_NOINLINE void fe448_inv(fe448_t *r, const fe448_t *a)
{
    fe448_t t1;
    fe448_t t2;
    fe448_t t3;

    fe448_sqr(&t1, a);
    fe448_mul(&t1, &t1, a);          /* x2 */
    fe448_sqr(&t1, &t1);
    fe448_mul(&t1, &t1, a);          /* x3 */
    fe448_sqr_n(&t2, &t1, 3U);
    fe448_mul(&t2, &t2, &t1);        /* x6 */
    fe448_sqr_n(&t1, &t2, 6U);
    fe448_mul(&t1, &t1, &t2);        /* x12 */
    fe448_sqr_n(&t3, &t1, 12U);
    fe448_mul(&t3, &t3, &t1);        /* x24 */
    fe448_sqr_n(&t1, &t3, 6U);
    fe448_mul(&t1, &t1, &t2);        /* x30 */
    fe448_sqr_n(&t2, &t3, 24U);
    fe448_mul(&t2, &t2, &t3);        /* x48 */
    fe448_sqr_n(&t3, &t2, 48U);
    fe448_mul(&t3, &t3, &t2);        /* x96 */
    fe448_sqr_n(&t2, &t3, 96U);
    fe448_mul(&t2, &t2, &t3);        /* x192 */
    fe448_sqr_n(&t2, &t2, 30U);
    fe448_mul(&t2, &t2, &t1);        /* x222 */
    fe448_sqr(&t1, &t2);
    fe448_mul(&t1, &t1, a);          /* x223 */
    fe448_sqr_n(&t1, &t1, 223U);
    fe448_mul(&t1, &t1, &t2);        /* a^(2^446 - 2^222 - 1) */
    fe448_sqr_n(&t1, &t1, 2U);
    fe448_mul(r, &t1, a);            /* a^(2^448 - 2^224 - 3) */

    noxtls_secure_zero(&t1, sizeof(t1));
    noxtls_secure_zero(&t2, sizeof(t2));
    noxtls_secure_zero(&t3, sizeof(t3));
}

/** @brief Canonical 56-byte little-endian encoding of a. */
static void fe448_to_bytes(uint8_t out[NOXTLS_X448_FE_BYTES], const fe448_t *a)
{
    fe448_t t = *a;
    uint32_t i;
    uint32_t pos = 0U;
    uint64_t acc = 0U;
    uint32_t acc_bits = 0U;

    fe448_strong_reduce(&t);
    for(i = 0U; i < X448_FE_LIMBS; i += 1U) {
        acc |= (uint64_t)t.v[i] << acc_bits;
        acc_bits += X448_FE_LIMB_BITS;
        while(acc_bits >= 8U) {
            out[pos] = (uint8_t)(acc & 0xFFU);
            pos += 1U;
            acc >>= 8U;
            acc_bits -= 8U;
        }
    }
    noxtls_secure_zero(&t, sizeof(t));
}

/** @brief Load a 56-byte little-endian value (any value < 2^448; reduced lazily). */
static void fe448_from_bytes(fe448_t *r, const uint8_t in[NOXTLS_X448_FE_BYTES])
{
    uint32_t i;
    uint32_t pos = 0U;
    uint64_t acc = 0U;
    uint32_t acc_bits = 0U;

    for(i = 0U; i < X448_FE_LIMBS; i += 1U) {
        while(acc_bits < X448_FE_LIMB_BITS) {
            acc |= (uint64_t)in[pos] << acc_bits;
            pos += 1U;
            acc_bits += 8U;
        }
        r->v[i] = (uint32_t)(acc & (uint64_t)X448_FE_LIMB_MASK);
        acc >>= X448_FE_LIMB_BITS;
        acc_bits -= X448_FE_LIMB_BITS;
    }
}

/**
 * @brief Constant-time conditional swap of two field elements (Montgomery ladder).
 * @param[in]     swap When 1, swap @p a and @p b; when 0, leave them unchanged.
 * @param[in,out] a First element.
 * @param[in,out] b Second element.
 */
static void fe448_cswap(uint32_t swap, fe448_t *a, fe448_t *b)
{
    uint32_t mask = 0U - (swap & 1U);
    uint32_t i;
    for(i = 0U; i < X448_FE_LIMBS; i += 1U) {
        uint32_t d = mask & (a->v[i] ^ b->v[i]);
        a->v[i] ^= d;
        b->v[i] ^= d;
    }
}

/**
 * @brief X448 scalar multiplication (RFC 7748 section 5 Montgomery ladder).
 *
 * Dedicated constant-time GF(2^448 - 2^224 - 1) arithmetic on the stack (no
 * heap, no bignum). Same ladder formulas as RFC 7748 with a24 = 39081.
 *
 * @param k Little-endian scalar (`NOXTLS_X448_KEY_SIZE` bytes, clamped here).
 * @param u Little-endian u-coordinate of input point.
 * @param result Little-endian u-coordinate of k*P.
 * @return `NOXTLS_RETURN_SUCCESS`.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t x448_scalar_mult_core(const uint8_t *k,
                                             const uint8_t *u,
                                             uint8_t *result)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    static const uint8_t x448_s_bit8[8] = {
        0x01U, 0x02U, 0x04U, 0x08U, 0x10U, 0x20U, 0x40U, 0x80U
    };
    uint8_t k_clamped[NOXTLS_X448_KEY_SIZE];
    fe448_t x1;
    fe448_t x2;
    fe448_t z2;
    fe448_t x3;
    fe448_t z3;
    fe448_t ta;
    fe448_t tb;
    fe448_t tc;
    fe448_t td;
    uint32_t swap = 0U;
    int32_t t;

    noxtls_copy_u8(k_clamped, sizeof(k_clamped), k, NOXTLS_X448_KEY_SIZE);
    k_clamped[0] &= (uint8_t)NOXTLS_X448_CLAMP_BYTE0_MASK;
    k_clamped[NOXTLS_X448_FE_BYTES - 1U] |= (uint8_t)NOXTLS_X448_CLAMP_HIGH_OR;

    fe448_from_bytes(&x1, u);
    fe448_one(&x2);
    fe448_zero(&z2);
    x3 = x1;
    fe448_one(&z3);

    for(t = (int32_t)NOXTLS_X448_SCALAR_LOOP_TOP; t >= 0; t -= 1) {
        const uint32_t bit = (uint32_t)t;
        const uint32_t k_t = ((k_clamped[bit >> 3U] & x448_s_bit8[bit & 7U]) != 0U) ? 1U : 0U;
        swap ^= k_t;
        fe448_cswap(swap, &x2, &x3);
        fe448_cswap(swap, &z2, &z3);
        swap = k_t;

        /*
         * A = x2+z2, B = x2-z2, C = x3+z3, D = x3-z3, DA = D*A, CB = C*B,
         * AA = A^2 (x2), BB = B^2 (z2), x3 = (DA+CB)^2, z3 = x1*(DA-CB)^2,
         * E = AA-BB, x2 = AA*BB, z2 = E*(AA + a24*E).
         */
        fe448_add(&ta, &x2, &z2);
        fe448_sub(&tb, &x2, &z2);
        fe448_add(&tc, &x3, &z3);
        fe448_sub(&td, &x3, &z3);
        fe448_sqr(&x2, &ta);
        fe448_sqr(&z2, &tb);
        fe448_mul(&td, &td, &ta);
        fe448_mul(&tc, &tc, &tb);
        fe448_add(&ta, &td, &tc);
        fe448_sub(&tb, &td, &tc);
        fe448_sqr(&x3, &ta);
        fe448_sqr(&ta, &tb);
        fe448_mul(&z3, &x1, &ta);
        fe448_sub(&tc, &x2, &z2);
        fe448_mul_small(&ta, &tc, X448_A24);
        fe448_add(&ta, &x2, &ta);
        fe448_mul(&x2, &x2, &z2);
        fe448_mul(&z2, &tc, &ta);
    }

    fe448_cswap(swap, &x2, &x3);
    fe448_cswap(swap, &z2, &z3);

    fe448_inv(&ta, &z2);
    fe448_mul(&x2, &x2, &ta);
    fe448_to_bytes(result, &x2);

    /* Wipe the scalar and the secret-dependent ladder state. */
    noxtls_secure_zero(k_clamped, sizeof(k_clamped));
    noxtls_secure_zero(&x2, sizeof(x2));
    noxtls_secure_zero(&z2, sizeof(z2));
    noxtls_secure_zero(&x3, sizeof(x3));
    noxtls_secure_zero(&z3, sizeof(z3));
    noxtls_secure_zero(&ta, sizeof(ta));
    noxtls_secure_zero(&tb, sizeof(tb));
    noxtls_secure_zero(&tc, sizeof(tc));
    noxtls_secure_zero(&td, sizeof(td));
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief X448 scalar multiplication with a fail-closed output.
 * @param k Little-endian scalar (`NOXTLS_X448_KEY_SIZE` bytes).
 * @param u Little-endian u-coordinate of input point.
 * @param result Little-endian u-coordinate of k*P; wiped if the ladder ever
 *        reports a failure, so a stale or partial value is never left behind
 *        next to an error.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t x448_scalar_mult(const uint8_t *k,
                                        const uint8_t *u,
                                        uint8_t *result)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    noxtls_return_t rc = x448_scalar_mult_core(k, u, result);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(result, (size_t)NOXTLS_X448_KEY_SIZE);
    }
    return rc;
}

/**
 * @brief Applies RFC 7748 clamping to a 56-byte X448 scalar in place.
 * @param[in,out] k Little-endian scalar (`NOXTLS_X448_KEY_SIZE` bytes); no-op if NULL.
 * @return None.
 */
void noxtls_x448_clamp_scalar(uint8_t *k)
{
    if (k == NULL) {
        return;
    }
    k[0] &= (uint8_t)NOXTLS_X448_CLAMP_BYTE0_MASK;
    k[NOXTLS_X448_FE_BYTES - 1U] |= (uint8_t)NOXTLS_X448_CLAMP_HIGH_OR;
}

/**
 * @brief Derives the X448 public key from a private key (RFC 7748, base u = 5).
 * @param[in]  private_key 56-byte little-endian private key.
 * @param[out] public_key 56-byte little-endian public u-coordinate.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_x448_public_key(const uint8_t *private_key,
                                       uint8_t *public_key)
{
    static const uint8_t base_point[NOXTLS_X448_KEY_SIZE] = {
        0x05U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
    };
    if ((private_key == NULL) || (public_key == NULL)) { return NOXTLS_RETURN_NULL; }
    return x448_scalar_mult(private_key, base_point, public_key);
}

/**
 * @brief Computes X448 shared secret from own private key and peer public key (RFC 7748).
 * @param[in]  private_key 56-byte little-endian private key.
 * @param[in]  peer_public_key 56-byte little-endian peer public u-coordinate.
 * @param[out] shared_secret 56-byte little-endian shared secret output.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_x448_shared_secret(const uint8_t *private_key,
                                         const uint8_t *peer_public_key,
                                         uint8_t *shared_secret)
{
    if ((private_key == NULL) || (peer_public_key == NULL) || (shared_secret == NULL)) { return NOXTLS_RETURN_NULL; }
    return x448_scalar_mult(private_key, peer_public_key, shared_secret);
}

/**
 * @brief Generates a random X448 key pair using the library DRBG (RFC 7748).
 * @param[out] private_key 56-byte little-endian private key (clamped internally).
 * @param[out] public_key 56-byte little-endian public key.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_x448_generate_key(uint8_t *private_key,
                                         uint8_t *public_key)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if ((private_key == NULL) || (public_key == NULL)) { return NOXTLS_RETURN_NULL; }

    /* Shared PKC CTR-DRBG (instantiated from noxtls_drbg_get_entropy() on first
     * use; a failed generate fails this call closed, wipes the output and drops
     * the instance so the next call re-instantiates from fresh entropy). */
    rc = noxtls_pkc_rng_generate(NOXTLS_PKC_RNG_SLOT_X448, private_key, NOXTLS_X448_DRBG_SEED_BITS);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    (void)noxtls_x448_clamp_scalar(private_key);
    rc = noxtls_x448_public_key(private_key, public_key);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(private_key, (size_t)NOXTLS_X448_KEY_SIZE);
    }
    return rc;
}

#endif /* NOXTLS_FEATURE_X448 */
