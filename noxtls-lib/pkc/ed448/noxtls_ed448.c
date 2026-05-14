/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_ed448.c
* Summary: Ed448 digital signatures (RFC 8032)
*
*/

#include <stdint.h>
#include <string.h>

#include "common/noxtls_ct.h"
#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "drbg/noxtls_drbg.h"
#include "noxtls_common.h"
#include "noxtls_ed448.h"
#include "pkc/rsa/noxtls_bignum.h"

#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3

#include "mdigest/sha3/noxtls_sha3.h"

/* p = 2^448 - 2^224 - 1 (same as Curve448), big-endian */
static const uint8_t ed448_p[NOXTLS_ED448_FE448_BYTES] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/* d = -39081 for curve x^2+y^2 = 1 + d*x^2*y^2. Stored as p + (-39081) in BE. */
static const uint8_t ed448_d[NOXTLS_ED448_FE448_BYTES] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x6F, 0x67, 0x97
};

/* Order L of the prime-order subgroup (446-bit prime), big-endian. */
static const uint8_t ed448_L[NOXTLS_ED448_FE448_BYTES] = {
    0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7C, 0xCA, 0x23, 0xE9,
    0x63, 0xC4, 0x4C, 0x17, 0x32, 0x6E, 0x42, 0x84, 0xC5, 0xBB, 0x9D, 0xAE, 0x90, 0xE9,
    0x36, 0x53, 0xBF, 0x6D, 0x5C, 0xC8, 0x4C, 0x1D, 0x1A, 0x8A, 0x6D, 0x1E, 0xAD, 0x93
};

/**
 * @brief Convert a 448-bit field element from little-endian to big-endian (56 bytes).
 * @param[out] be Big-endian output.
 * @param[in] le Little-endian input.
 */
static void le56_to_be56(uint8_t be[NOXTLS_ED448_FE448_BYTES], const uint8_t le[NOXTLS_ED448_FE448_BYTES])
{
    int i;
    for(i = 0; i < NOXTLS_ED448_FE448_BYTES; i++)
        be[i] = le[NOXTLS_ED448_FE448_BYTES - 1 - i];
}

/**
 * @brief Convert a 448-bit field element from big-endian to little-endian (56 bytes).
 * @param[out] le Little-endian output.
 * @param[in] be Big-endian input.
 */
static void be56_to_le56(uint8_t le[NOXTLS_ED448_FE448_BYTES], const uint8_t be[NOXTLS_ED448_FE448_BYTES])
{
    int i;
    for(i = 0; i < NOXTLS_ED448_FE448_BYTES; i++)
        le[i] = be[NOXTLS_ED448_FE448_BYTES - 1 - i];
}

/**
 * @brief Field addition: r = (a + b) mod p for Ed448 prime p (RFC 8032).
 * @param[out] r Sum in [0, p).
 * @param[in] a Operand (56-byte big-endian).
 * @param[in] b Operand (56-byte big-endian).
 * @return NOXTLS_RETURN_SUCCESS on success, or an error from bignum operations.
 */
static noxtls_return_t fe448_add(uint8_t r[NOXTLS_ED448_FE448_BYTES], const uint8_t a[NOXTLS_ED448_FE448_BYTES], const uint8_t b[NOXTLS_ED448_FE448_BYTES])
{
    uint8_t sum[NOXTLS_ED448_BN_PRODUCT_BYTES];
    memset(sum, 0, sizeof(sum));
    if(noxtls_bn_add(sum + NOXTLS_ED448_FE448_BYTES, a, b, NOXTLS_ED448_FE448_BYTES) != NOXTLS_RETURN_SUCCESS)
        return NOXTLS_RETURN_FAILED;
    return noxtls_bn_mod(r, sum, sizeof(sum), ed448_p, NOXTLS_ED448_FE448_BYTES);
}

/**
 * @brief Field subtraction: r = (a - b) mod p.
 * @param[out] r Difference in [0, p).
 * @param[in] a Minuend.
 * @param[in] b Subtrahend.
 * @return NOXTLS_RETURN_SUCCESS on success, or an error from bignum operations.
 */
static noxtls_return_t fe448_sub(uint8_t r[NOXTLS_ED448_FE448_BYTES], const uint8_t a[NOXTLS_ED448_FE448_BYTES], const uint8_t b[NOXTLS_ED448_FE448_BYTES])
{
    uint8_t diff[NOXTLS_ED448_FE448_BYTES];
    if(noxtls_bn_sub(diff, a, b, NOXTLS_ED448_FE448_BYTES) != NOXTLS_RETURN_SUCCESS)
        return NOXTLS_RETURN_FAILED;
    if(noxtls_bn_cmp(a, b, NOXTLS_ED448_FE448_BYTES) < 0) {
        if(noxtls_bn_add(diff, diff, ed448_p, NOXTLS_ED448_FE448_BYTES) != NOXTLS_RETURN_SUCCESS)
            return NOXTLS_RETURN_FAILED;
    }
    if(noxtls_bn_cmp(diff, ed448_p, NOXTLS_ED448_FE448_BYTES) >= 0)
        return noxtls_bn_mod(r, diff, NOXTLS_ED448_FE448_BYTES, ed448_p, NOXTLS_ED448_FE448_BYTES);
    memcpy(r, diff, NOXTLS_ED448_FE448_BYTES);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Field multiplication: r = (a * b) mod p.
 * @param[out] r Product in [0, p).
 * @param[in] a Operand.
 * @param[in] b Operand.
 * @return NOXTLS_RETURN_SUCCESS on success, or an error from bignum operations.
 */
static noxtls_return_t fe448_mul(uint8_t r[NOXTLS_ED448_FE448_BYTES], const uint8_t a[NOXTLS_ED448_FE448_BYTES], const uint8_t b[NOXTLS_ED448_FE448_BYTES])
{
    uint8_t product[NOXTLS_ED448_BN_PRODUCT_BYTES];
    if(noxtls_bn_mul(product, a, NOXTLS_ED448_FE448_BYTES, b, NOXTLS_ED448_FE448_BYTES) != NOXTLS_RETURN_SUCCESS)
        return NOXTLS_RETURN_FAILED;
    return noxtls_bn_mod(r, product, sizeof(product), ed448_p, NOXTLS_ED448_FE448_BYTES);
}

/**
 * @brief Field inverse: r = a^(p-2) mod p (Fermat) for non-zero a.
 * @param[out] r Multiplicative inverse.
 * @param[in] a Non-zero field element.
 * @return NOXTLS_RETURN_SUCCESS on success, or an error from bignum operations.
 */
static noxtls_return_t fe448_inv(uint8_t r[NOXTLS_ED448_FE448_BYTES], const uint8_t a[NOXTLS_ED448_FE448_BYTES])
{
    uint8_t p_minus_2[NOXTLS_ED448_FE448_BYTES];
    uint8_t two[NOXTLS_ED448_FE448_BYTES];
    memcpy(p_minus_2, ed448_p, NOXTLS_ED448_FE448_BYTES);
    memset(two, 0, NOXTLS_ED448_FE448_BYTES);
    two[NOXTLS_ED448_FE448_BYTES - 1] = 2;
    if(noxtls_bn_sub(p_minus_2, p_minus_2, two, NOXTLS_ED448_FE448_BYTES) != NOXTLS_RETURN_SUCCESS)
        return NOXTLS_RETURN_FAILED;
    return noxtls_bn_mod_exp(r, a, p_minus_2, NOXTLS_ED448_FE448_BYTES, ed448_p, NOXTLS_ED448_FE448_BYTES);
}

/** @internal Extended coordinates (X:Y:Z:T) for Ed448 twisted Edwards curve (RFC 8032). */
typedef struct {
    uint8_t X[NOXTLS_ED448_FE448_BYTES];
    uint8_t Y[NOXTLS_ED448_FE448_BYTES];
    uint8_t Z[NOXTLS_ED448_FE448_BYTES];
    uint8_t T[NOXTLS_ED448_FE448_BYTES];
} ge448_pt_t;

/** @internal Forward declaration; see definition for parameters and return value. */
static noxtls_return_t ge448_decode(ge448_pt_t *p, const uint8_t enc[NOXTLS_ED448_PUBLIC_KEY_SIZE]);
/** @internal Forward declaration; see definition for parameters and return value. */
static noxtls_return_t ge448_encode(uint8_t enc[NOXTLS_ED448_PUBLIC_KEY_SIZE], const ge448_pt_t *p);

/**
 * @brief Set point to the identity (neutral element) in extended coordinates.
 * @param[out] p Point cleared to identity.
 */
static void ge448_pt_zero(ge448_pt_t *p)
{
    noxtls_bn_zero(p->X, NOXTLS_ED448_FE448_BYTES);
    noxtls_bn_one(p->Y, NOXTLS_ED448_FE448_BYTES);
    noxtls_bn_one(p->Z, NOXTLS_ED448_FE448_BYTES);
    noxtls_bn_zero(p->T, NOXTLS_ED448_FE448_BYTES);
}

/**
 * @brief Add two curve points in extended coordinates (RFC 8032 / Edwards addition).
 * @param[out] r p + q.
 * @param[in] p First summand.
 * @param[in] q Second summand.
 * @return NOXTLS_RETURN_SUCCESS on success, or an error from field arithmetic.
 */
static noxtls_return_t ge448_add(ge448_pt_t *r, const ge448_pt_t *p, const ge448_pt_t *q)
{
    uint8_t A[NOXTLS_ED448_FE448_BYTES];
    uint8_t B[NOXTLS_ED448_FE448_BYTES];
    uint8_t C[NOXTLS_ED448_FE448_BYTES];
    uint8_t D[NOXTLS_ED448_FE448_BYTES];
    uint8_t E[NOXTLS_ED448_FE448_BYTES];
    uint8_t F[NOXTLS_ED448_FE448_BYTES];
    uint8_t G[NOXTLS_ED448_FE448_BYTES];
    uint8_t H[NOXTLS_ED448_FE448_BYTES];
    uint8_t y1mx1[NOXTLS_ED448_FE448_BYTES];
    uint8_t y2mx2[NOXTLS_ED448_FE448_BYTES];
    uint8_t y1px1[NOXTLS_ED448_FE448_BYTES];
    uint8_t y2px2[NOXTLS_ED448_FE448_BYTES];
    uint8_t z1_inv[NOXTLS_ED448_FE448_BYTES];
    uint8_t z2_inv[NOXTLS_ED448_FE448_BYTES];
    uint8_t x1[NOXTLS_ED448_FE448_BYTES];
    uint8_t y1[NOXTLS_ED448_FE448_BYTES];
    uint8_t x2[NOXTLS_ED448_FE448_BYTES];
    uint8_t y2[NOXTLS_ED448_FE448_BYTES];
    uint8_t two[NOXTLS_ED448_FE448_BYTES];
    memset(two, 0, NOXTLS_ED448_FE448_BYTES);
    two[NOXTLS_ED448_FE448_BYTES - 1] = 2;

    if(fe448_inv(z1_inv, p->Z) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_inv(z2_inv, q->Z) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_mul(x1, p->X, z1_inv) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_mul(y1, p->Y, z1_inv) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_mul(x2, q->X, z2_inv) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_mul(y2, q->Y, z2_inv) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    if(fe448_sub(y1mx1, y1, x1) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_sub(y2mx2, y2, x2) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_add(y1px1, y1, x1) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_add(y2px2, y2, x2) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_mul(A, y1mx1, y2mx2) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_mul(B, y1px1, y2px2) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_mul(C, p->T, q->T) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_mul(C, C, ed448_d) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_mul(C, C, two) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_mul(D, p->Z, q->Z) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_mul(D, D, two) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_sub(E, B, A) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_sub(F, D, C) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_add(G, D, C) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_add(H, B, A) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_mul(r->X, E, F) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_mul(r->Y, G, H) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_mul(r->T, E, H) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_mul(r->Z, F, G) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Double a curve point: r = 2p.
 * @param[out] r 2p.
 * @param[in] p Input point.
 * @return NOXTLS_RETURN_SUCCESS on success, or an error from field arithmetic.
 */
static noxtls_return_t ge448_dbl(ge448_pt_t *r, const ge448_pt_t *p)
{
    return ge448_add(r, p, p);
}

/**
 * @brief Scalar multiplication R = s*P using binary little-endian scan of s (448 bits).
 * @param[out] R Result point.
 * @param[in] s_le Scalar in 56-byte little-endian form (as produced by this implementation).
 * @param[in] P Base point.
 * @return NOXTLS_RETURN_SUCCESS on success, or an error from point operations.
 */
static noxtls_return_t ge448_scalar_mult(ge448_pt_t *R, const uint8_t s_le[NOXTLS_ED448_FE448_BYTES], const ge448_pt_t *P)
{
    ge448_pt_t N;
    ge448_pt_t T;
    ge448_pt_zero(R);
    memcpy(&N, P, sizeof(ge448_pt_t));
    int i;
    int bit;
    for(i = 0; i < (int)NOXTLS_ED448_SCALAR_MULT_BITS; i++) {
        bit = (s_le[i >> 3] >> (i & 7)) & 1;
        if(bit) {
            memcpy(&T, R, sizeof(ge448_pt_t));
            if(ge448_add(R, &T, &N) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        }
        memcpy(&T, &N, sizeof(ge448_pt_t));
        if(ge448_dbl(&N, &T) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Decode a 57-byte compressed Edwards y-coordinate encoding to extended coordinates.
 * @param[out] p Decoded point.
 * @param[in] enc RFC 8032 public key / encoded point (56 bytes y + sign bit of x).
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_FAILED if encoding is invalid.
 */
static noxtls_return_t ge448_decode(ge448_pt_t *p, const uint8_t enc[NOXTLS_ED448_PUBLIC_KEY_SIZE])
{
    uint8_t y_le[NOXTLS_ED448_PUBLIC_KEY_SIZE];
    uint8_t y_be[NOXTLS_ED448_FE448_BYTES];
    uint8_t u[NOXTLS_ED448_FE448_BYTES];
    uint8_t v[NOXTLS_ED448_FE448_BYTES];
    uint8_t x2[NOXTLS_ED448_FE448_BYTES];
    uint8_t x[NOXTLS_ED448_FE448_BYTES];
    uint8_t one[NOXTLS_ED448_FE448_BYTES];
    uint8_t v_inv[NOXTLS_ED448_FE448_BYTES];
    uint8_t p34[NOXTLS_ED448_FE448_BYTES]; /* (p+3)/4 for sqrt */
    int i;
    memset(y_le, 0, NOXTLS_ED448_PUBLIC_KEY_SIZE);
    memcpy(y_le, enc, NOXTLS_ED448_FE448_BYTES);
    y_le[NOXTLS_ED448_PUBLIC_KEY_SIZE - 1] &= 0x7Fu;
    le56_to_be56(y_be, y_le);
    if(noxtls_bn_cmp(y_be, ed448_p, NOXTLS_ED448_FE448_BYTES) >= 0) return NOXTLS_RETURN_FAILED;
    noxtls_bn_one(one, NOXTLS_ED448_FE448_BYTES);
    /* u = y^2 - 1, v = d*y^2 + 1 */
    if(fe448_mul(u, y_be, y_be) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_sub(u, u, one) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_mul(v, y_be, y_be) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_mul(v, v, ed448_d) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_add(v, v, one) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_inv(v_inv, v) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_mul(x2, u, v_inv) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    /* p ≡ 3 (mod 4): x = x2^((p+3)/4) */
    memcpy(p34, ed448_p, NOXTLS_ED448_FE448_BYTES);
    for(i = NOXTLS_ED448_FE448_BYTES - 1; i >= 0 && p34[i] == 0; i--) {}
    if(i >= 0) {
        p34[NOXTLS_ED448_FE448_BYTES - 1] += 3;
        for(i = NOXTLS_ED448_FE448_BYTES - 1; i > 0 && p34[i] < 3; i--) { p34[i] += 256; p34[i-1]--; }
    }
    if(noxtls_bn_mod_exp(x, x2, p34, NOXTLS_ED448_FE448_BYTES, ed448_p, NOXTLS_ED448_FE448_BYTES) != NOXTLS_RETURN_SUCCESS)
        return NOXTLS_RETURN_FAILED;
    if((enc[NOXTLS_ED448_PUBLIC_KEY_SIZE - 1] >> 7) != (x[NOXTLS_ED448_FE448_BYTES - 1] & 1)) {
        if(fe448_sub(x, ed448_p, x) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    }
    noxtls_bn_one(p->Z, NOXTLS_ED448_FE448_BYTES);
    memcpy(p->X, x, NOXTLS_ED448_FE448_BYTES);
    memcpy(p->Y, y_be, NOXTLS_ED448_FE448_BYTES);
    if(fe448_mul(p->T, p->X, p->Y) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Encode an affine-equivalent point to the 57-byte wire format (compressed y + x parity).
 * @param[out] enc 57-byte output buffer.
 * @param[in] p Point in extended coordinates.
 * @return NOXTLS_RETURN_SUCCESS on success, or an error from field arithmetic.
 */
static noxtls_return_t ge448_encode(uint8_t enc[NOXTLS_ED448_PUBLIC_KEY_SIZE], const ge448_pt_t *p)
{
    uint8_t zinv[NOXTLS_ED448_FE448_BYTES];
    uint8_t x[NOXTLS_ED448_FE448_BYTES];
    uint8_t y[NOXTLS_ED448_FE448_BYTES];
    if(fe448_inv(zinv, p->Z) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_mul(x, p->X, zinv) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_mul(y, p->Y, zinv) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    be56_to_le56(enc, y);
    enc[NOXTLS_ED448_PUBLIC_KEY_SIZE - 1] |= (x[NOXTLS_ED448_FE448_BYTES - 1] & 1) << 7;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Initialize @p p to the Ed448 base point B (RFC 8032, y = 19).
 * @param[out] p Base point in extended coordinates.
 * @return NOXTLS_RETURN_SUCCESS on success, or an error from field arithmetic.
 */
static noxtls_return_t ge448_set_basepoint(ge448_pt_t *p)
{
    /* y = 19. u = 1-361 = -360, v = 1+d*361. We need x^2 = u/v, x = sqrt(u/v). */
    uint8_t y_be[NOXTLS_ED448_FE448_BYTES];
    uint8_t u[NOXTLS_ED448_FE448_BYTES];
    uint8_t v[NOXTLS_ED448_FE448_BYTES];
    uint8_t v_inv[NOXTLS_ED448_FE448_BYTES];
    uint8_t x2[NOXTLS_ED448_FE448_BYTES];
    uint8_t x[NOXTLS_ED448_FE448_BYTES];
    uint8_t p34[NOXTLS_ED448_FE448_BYTES];
    uint8_t neg360[NOXTLS_ED448_FE448_BYTES];
    uint8_t d361[NOXTLS_ED448_FE448_BYTES];
    int i;
    memset(y_be, 0, NOXTLS_ED448_FE448_BYTES);
    y_be[NOXTLS_ED448_FE448_BYTES - 1] = 19;
    noxtls_bn_zero(neg360, NOXTLS_ED448_FE448_BYTES);
    if(noxtls_bn_sub(neg360, ed448_p, neg360) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    /* neg360 = 360 in BE: 0..0 0x01 0x68 */
    memset(neg360, 0, NOXTLS_ED448_FE448_BYTES);
    neg360[NOXTLS_ED448_FE448_BYTES - 2] = 1;
    neg360[NOXTLS_ED448_FE448_BYTES - 1] = 0x68; /* 360 = 0x168 */
    if(noxtls_bn_sub(u, ed448_p, neg360) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED; /* u = p - 360 */
    if(fe448_mul(d361, ed448_d, y_be) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_mul(d361, d361, y_be) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED; /* d*361 */
    noxtls_bn_one(v, NOXTLS_ED448_FE448_BYTES);
    if(fe448_add(v, v, d361) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_inv(v_inv, v) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_mul(x2, u, v_inv) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    memcpy(p34, ed448_p, NOXTLS_ED448_FE448_BYTES);
    p34[NOXTLS_ED448_FE448_BYTES - 1] += 3;
    for(i = NOXTLS_ED448_FE448_BYTES - 1; i > 0 && p34[i] < 3; i--) { p34[i] += 256; p34[i-1]--; }
    if(noxtls_bn_mod_exp(x, x2, p34, NOXTLS_ED448_FE448_BYTES, ed448_p, NOXTLS_ED448_FE448_BYTES) != NOXTLS_RETURN_SUCCESS)
        return NOXTLS_RETURN_FAILED;
    noxtls_bn_one(p->Z, NOXTLS_ED448_FE448_BYTES);
    memcpy(p->X, x, NOXTLS_ED448_FE448_BYTES);
    memcpy(p->Y, y_be, NOXTLS_ED448_FE448_BYTES);
    if(fe448_mul(p->T, p->X, p->Y) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Reduce a 114-byte little-endian integer modulo subgroup order L; store 57-byte LE scalar.
 * @param[out] out_le 57-byte little-endian scalar (low 56 bytes + zero high byte).
 * @param[in] in_le 114-byte SHAKE256-wide little-endian input.
 * @return NOXTLS_RETURN_SUCCESS on success, or an error from bignum mod.
 */
static noxtls_return_t sc448_reduce_mod_l(uint8_t out_le[NOXTLS_ED448_PUBLIC_KEY_SIZE], const uint8_t in_le[NOXTLS_ED448_SHAKE_WIDE_BYTES])
{
    uint8_t in_be[NOXTLS_ED448_SHAKE_WIDE_BYTES];
    uint8_t out_be[NOXTLS_ED448_FE448_BYTES];
    int i;
    for(i = 0; i < (int)NOXTLS_ED448_SHAKE_WIDE_BYTES; i++) {
        in_be[i] = in_le[NOXTLS_ED448_SHAKE_WIDE_BYTES - 1 - i];
    }
    if(noxtls_bn_mod(out_be, in_be, NOXTLS_ED448_SHAKE_WIDE_BYTES, ed448_L, NOXTLS_ED448_FE448_BYTES) != NOXTLS_RETURN_SUCCESS)
        return NOXTLS_RETURN_FAILED;
    be56_to_le56(out_le, out_be);
    out_le[NOXTLS_ED448_FE448_BYTES] = 0;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Build dom4(phflag, context) prefix for Ed448 hashing (RFC 8032).
 * @param[out] out Buffer of at least NOXTLS_ED448_DOM4_BUFFER_BYTES.
 * @param[in] phflag NOXTLS_ED448_PH_FLAG_PURE or NOXTLS_ED448_PH_FLAG_PREHASH.
 * @param[in] ctx Context bytes (may be NULL if ctx_len is 0).
 * @param[in] ctx_len Context length in bytes (0 for pure without ctx, or 1..NOXTLS_ED448_CONTEXT_MAX for Ed448ctx).
 * @return Total length written: NOXTLS_ED448_DOM4_PREFIX_BYTES + ctx_len.
 */
static uint32_t ed448_dom4_build(uint8_t out[NOXTLS_ED448_DOM4_BUFFER_BYTES], uint8_t phflag,
    const uint8_t *ctx, uint32_t ctx_len)
{
    static const uint8_t sig8[NOXTLS_ED448_DOM4_LITERAL_BYTES] = { 'S','i','g','E','d','4','4','8' };
    memcpy(out, sig8, NOXTLS_ED448_DOM4_LITERAL_BYTES);
    out[NOXTLS_ED448_DOM4_LITERAL_BYTES] = phflag;
    out[NOXTLS_ED448_DOM4_LITERAL_BYTES + 1U] = (uint8_t)ctx_len;
    if(ctx_len != 0u && ctx != NULL)
        memcpy(out + NOXTLS_ED448_DOM4_PREFIX_BYTES, ctx, ctx_len);
    return NOXTLS_ED448_DOM4_PREFIX_BYTES + ctx_len;
}

/**
 * @brief Absorb @p n noxtls_message parts into SHAKE256 and squeeze 114 octets (RFC 8032 wide scalar hash).
 * @param[out] out 114-byte SHAKE256 output.
 * @param[in] n Number of (pointer, length) pairs.
 * @param[in] parts Array of @p n input pointers (NULL allowed if corresponding length is 0).
 * @param[in] lens Length of each part in bytes.
 * @return NOXTLS_RETURN_SUCCESS on success, or an error from SHAKE256.
 */
static noxtls_return_t ed448_shake256_chain(uint8_t out[NOXTLS_ED448_SHAKE_WIDE_BYTES], unsigned n,
    const uint8_t **parts, const uint32_t *lens)
{
    noxtls_sha3_ctx_t ctx;
    unsigned i;
    if(noxtls_shake256_init(&ctx) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    for(i = 0; i < n; i++) {
        if(lens[i] != 0u && parts[i] != NULL) {
            if(noxtls_shake256_update(&ctx, parts[i], lens[i]) != NOXTLS_RETURN_SUCCESS)
                return NOXTLS_RETURN_FAILED;
        }
    }
    if(noxtls_shake256_final(&ctx) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return noxtls_shake256_squeeze(&ctx, out, NOXTLS_ED448_SHAKE_WIDE_BYTES);
}

/**
 * @brief Derive expanded secret material from 57-byte seed: SHAKE256(dom4(pure) || sk) (RFC 8032).
 * @param[out] out 114-byte wide output (first half used as scalar, second as prefix for signing).
 * @param[in] sk57 57-byte private seed.
 * @return NOXTLS_RETURN_SUCCESS on success, or an error from SHAKE256.
 */
static noxtls_return_t ed448_hash_secret(uint8_t out[NOXTLS_ED448_SHAKE_WIDE_BYTES], const uint8_t *sk57)
{
    uint8_t dom[NOXTLS_ED448_DOM4_PREFIX_BYTES];
    const uint8_t *parts[2];
    uint32_t lens[2];
    (void)ed448_dom4_build(dom, NOXTLS_ED448_PH_FLAG_PURE, NULL, 0);
    parts[0] = dom;
    lens[0] = NOXTLS_ED448_DOM4_PREFIX_BYTES;
    parts[1] = sk57;
    lens[1] = NOXTLS_ED448_PRIVATE_KEY_SIZE;
    return ed448_shake256_chain(out, 2, parts, lens);
}

/**
 * @brief Ed448ph noxtls_message representative: first 64 bytes of SHAKE256(M) (RFC 8032).
 * @param[in] msg Message bytes (NULL allowed if msg_len is 0).
 * @param[in] msg_len Length of @p msg.
 * @param[out] digest 64-byte prehash output.
 * @return NOXTLS_RETURN_SUCCESS on success, or an error from SHAKE256.
 */
static noxtls_return_t ed448_ph64(const uint8_t *msg, uint32_t msg_len, uint8_t digest[NOXTLS_ED448_PH_DIGEST_BYTES])
{
    noxtls_sha3_ctx_t ctx;
    if(noxtls_shake256_init(&ctx) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(msg_len != 0u && msg != NULL) {
        if(noxtls_shake256_update(&ctx, msg, msg_len) != NOXTLS_RETURN_SUCCESS)
            return NOXTLS_RETURN_FAILED;
    }
    if(noxtls_shake256_final(&ctx) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return noxtls_shake256_squeeze(&ctx, digest, NOXTLS_ED448_PH_DIGEST_BYTES);
}

/**
 * @internal
 * @brief Shared Ed448 / Ed448ctx / Ed448ph signing (RFC 8032) with dom4 and optional context or prehash.
 *
 * @param[in] private_key 57-byte seed.
 * @param[in] noxtls_message Message bytes for pure/ctx modes; for Ed448ph, full noxtls_message passed to SHAKE256 prehash.
 * @param[in] message_len Length of @p noxtls_message.
 * @param[out] signature 114-byte signature R||S.
 * @param[in] phflag NOXTLS_ED448_PH_FLAG_PURE (with optional ctx) or NOXTLS_ED448_PH_FLAG_PREHASH (Ed448ph; ctx must be empty).
 * @param[in] ctx Context string for Ed448ctx when ctx_len is non-zero; NULL if unused.
 * @param[in] ctx_len Context length (0 for pure or ph; 1..NOXTLS_ED448_CONTEXT_MAX for ctx mode).
 *
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL on invalid pointer combination for noxtls_message/context.
 * @return NOXTLS_RETURN_FAILED if flags/context are inconsistent or a crypto step fails.
 */
static noxtls_return_t ed448_sign_internal(const uint8_t private_key[NOXTLS_ED448_PRIVATE_KEY_SIZE],
    const uint8_t *noxtls_message, uint32_t message_len, uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE],
    uint8_t phflag, const uint8_t *ctx, uint32_t ctx_len)
{
    uint8_t h[NOXTLS_ED448_SHAKE_WIDE_BYTES];
    uint8_t prefix[NOXTLS_ED448_PRIVATE_KEY_SIZE];
    uint8_t s_le[NOXTLS_ED448_PUBLIC_KEY_SIZE];
    uint8_t r_in[NOXTLS_ED448_SHAKE_WIDE_BYTES];
    uint8_t r_le[NOXTLS_ED448_PUBLIC_KEY_SIZE];
    uint8_t k_in[NOXTLS_ED448_SHAKE_WIDE_BYTES];
    uint8_t k_le[NOXTLS_ED448_PUBLIC_KEY_SIZE];
    uint8_t dom[NOXTLS_ED448_DOM4_BUFFER_BYTES];
    uint32_t dom_len;
    ge448_pt_t B;
    ge448_pt_t R;
    uint8_t public_key[NOXTLS_ED448_PUBLIC_KEY_SIZE];
    uint8_t S_le[NOXTLS_ED448_PUBLIC_KEY_SIZE];
    uint8_t ks_le[NOXTLS_ED448_PUBLIC_KEY_SIZE];
    uint8_t rs_le64[NOXTLS_ED448_SHAKE_WIDE_BYTES];
    uint8_t sum_le[NOXTLS_ED448_SHAKE_WIDE_BYTES];
    uint8_t ph_buf[NOXTLS_ED448_PH_DIGEST_BYTES];
    const uint8_t *m_body;
    uint32_t m_len;
    uint32_t i;

    if(private_key == NULL || signature == NULL) return NOXTLS_RETURN_NULL;
    if(noxtls_message == NULL && message_len != 0u) return NOXTLS_RETURN_NULL;
    if(phflag > NOXTLS_ED448_PH_FLAG_PREHASH) return NOXTLS_RETURN_FAILED;
    if(phflag == NOXTLS_ED448_PH_FLAG_PREHASH) {
        if(ctx_len != 0u || ctx != NULL) return NOXTLS_RETURN_FAILED;
    } else if(ctx_len != 0u) {
        if(ctx == NULL || ctx_len < 1u || ctx_len > (uint32_t)NOXTLS_ED448_CONTEXT_MAX)
            return NOXTLS_RETURN_FAILED;
    }

    dom_len = ed448_dom4_build(dom, phflag, ctx, ctx_len);

    if(phflag == NOXTLS_ED448_PH_FLAG_PREHASH) {
        if(ed448_ph64(noxtls_message, message_len, ph_buf) != NOXTLS_RETURN_SUCCESS)
            return NOXTLS_RETURN_FAILED;
        m_body = ph_buf;
        m_len = NOXTLS_ED448_PH_DIGEST_BYTES;
    } else {
        m_body = noxtls_message;
        m_len = message_len;
    }

    if(ed448_hash_secret(h, private_key) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    h[0] &= (uint8_t)NOXTLS_ED448_SCALAR_CLAMP_BYTE0_MASK;
    h[55] &= (uint8_t)NOXTLS_ED448_SCALAR_CLAMP_BYTE55_AND;
    h[55] |= (uint8_t)NOXTLS_ED448_SCALAR_CLAMP_BYTE55_OR;
    memcpy(prefix, h + NOXTLS_ED448_FE448_BYTES, NOXTLS_ED448_PRIVATE_KEY_SIZE);
    memcpy(s_le, h, NOXTLS_ED448_FE448_BYTES);
    s_le[NOXTLS_ED448_PUBLIC_KEY_SIZE - 1U] = 0;
    if(noxtls_ed448_public_key(private_key, public_key) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    {
        const uint8_t *parts_r[3];
        uint32_t lens_r[3];
        parts_r[0] = dom;
        lens_r[0] = dom_len;
        parts_r[1] = prefix;
        lens_r[1] = NOXTLS_ED448_PRIVATE_KEY_SIZE;
        parts_r[2] = m_body;
        lens_r[2] = m_len;
        if(ed448_shake256_chain(r_in, 3, parts_r, lens_r) != NOXTLS_RETURN_SUCCESS)
            return NOXTLS_RETURN_FAILED;
    }
    if(sc448_reduce_mod_l(r_le, r_in) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(ge448_set_basepoint(&B) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(ge448_scalar_mult(&R, r_le, &B) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(ge448_encode(signature, &R) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    {
        const uint8_t *parts_k[4];
        uint32_t lens_k[4];
        parts_k[0] = dom;
        lens_k[0] = dom_len;
        parts_k[1] = signature;
        lens_k[1] = NOXTLS_ED448_PUBLIC_KEY_SIZE;
        parts_k[2] = public_key;
        lens_k[2] = NOXTLS_ED448_PUBLIC_KEY_SIZE;
        parts_k[3] = m_body;
        lens_k[3] = m_len;
        if(ed448_shake256_chain(k_in, 4, parts_k, lens_k) != NOXTLS_RETURN_SUCCESS)
            return NOXTLS_RETURN_FAILED;
    }
    if(sc448_reduce_mod_l(k_le, k_in) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    memset(rs_le64, 0, NOXTLS_ED448_SHAKE_WIDE_BYTES);
    for(i = 0; i < (int)NOXTLS_ED448_PUBLIC_KEY_SIZE; i++) {
        uint32_t j;
        uint32_t carry = 0;
        for(j = 0; j < (int)NOXTLS_ED448_PUBLIC_KEY_SIZE; j++) {
            uint32_t t = (uint32_t)rs_le64[i + j] + (uint32_t)k_le[i] * (uint32_t)s_le[j] + carry;
            rs_le64[i + j] = (uint8_t)(t & 0xFFu);
            carry = t >> 8;
        }
        for(j = (int)NOXTLS_ED448_PUBLIC_KEY_SIZE; j < (int)NOXTLS_ED448_SHAKE_WIDE_BYTES - i && carry != 0u; j++) {
            uint32_t t = (uint32_t)rs_le64[i + j] + carry;
            rs_le64[i + j] = (uint8_t)(t & 0xFFu);
            carry = t >> 8;
        }
    }
    if(sc448_reduce_mod_l(ks_le, rs_le64) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    memset(sum_le, 0, NOXTLS_ED448_SHAKE_WIDE_BYTES);
    {
        uint32_t carry = 0;
        for(i = 0; i < (int)NOXTLS_ED448_PUBLIC_KEY_SIZE; i++) {
            uint32_t t = (uint32_t)r_le[i] + (uint32_t)ks_le[i] + carry;
            sum_le[i] = (uint8_t)(t & 0xFFu);
            carry = t >> 8;
        }
        if(carry != 0u) {
            sum_le[NOXTLS_ED448_PUBLIC_KEY_SIZE] = (uint8_t)carry;
        }
    }
    if(sc448_reduce_mod_l(S_le, sum_le) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    memcpy(signature + NOXTLS_ED448_PUBLIC_KEY_SIZE, S_le, NOXTLS_ED448_PUBLIC_KEY_SIZE);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @internal
 * @brief Shared Ed448 / Ed448ctx / Ed448ph verification (RFC 8032) with cofactor check.
 *
 * @param[in] public_key 57-byte public key encoding.
 * @param[in] noxtls_message Message or prehash input consistent with signing mode.
 * @param[in] message_len Length of @p noxtls_message.
 * @param[in] signature 114-byte signature R||S.
 * @param[in] phflag Pure, ctx, or prehash mode flag (same semantics as ed448_sign_internal()).
 * @param[in] ctx Context used when signing (Ed448ctx); NULL if unused.
 * @param[in] ctx_len Context length.
 *
 * @return NOXTLS_RETURN_SUCCESS if the signature is valid.
 * @return NOXTLS_RETURN_NULL on invalid pointer combination.
 * @return NOXTLS_RETURN_FAILED if parameters are inconsistent, decoding fails, or verification fails.
 */
static noxtls_return_t ed448_verify_internal(const uint8_t public_key[NOXTLS_ED448_PUBLIC_KEY_SIZE],
    const uint8_t *noxtls_message, uint32_t message_len, const uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE],
    uint8_t phflag, const uint8_t *ctx, uint32_t ctx_len)
{
    ge448_pt_t A;
    ge448_pt_t R;
    ge448_pt_t R_plus_kA;
    ge448_pt_t kA;
    ge448_pt_t sB;
    uint8_t dom[NOXTLS_ED448_DOM4_BUFFER_BYTES];
    uint32_t dom_len;
    uint8_t k_in[NOXTLS_ED448_SHAKE_WIDE_BYTES];
    uint8_t k_le[NOXTLS_ED448_PUBLIC_KEY_SIZE];
    uint8_t S_be[NOXTLS_ED448_FE448_BYTES];
    uint8_t S_le[NOXTLS_ED448_PUBLIC_KEY_SIZE];
    noxtls_sha3_ctx_t ctx_shake;
    uint8_t four[NOXTLS_ED448_PUBLIC_KEY_SIZE];
    uint8_t ph_buf[NOXTLS_ED448_PH_DIGEST_BYTES];
    const uint8_t *m_body;
    uint32_t m_len;

    if(public_key == NULL || signature == NULL) return NOXTLS_RETURN_NULL;
    if(noxtls_message == NULL && message_len != 0u) return NOXTLS_RETURN_NULL;
    if(phflag > NOXTLS_ED448_PH_FLAG_PREHASH) return NOXTLS_RETURN_FAILED;
    if(phflag == NOXTLS_ED448_PH_FLAG_PREHASH) {
        if(ctx_len != 0u || ctx != NULL) return NOXTLS_RETURN_FAILED;
    } else if(ctx_len != 0u) {
        if(ctx == NULL || ctx_len < 1u || ctx_len > (uint32_t)NOXTLS_ED448_CONTEXT_MAX)
            return NOXTLS_RETURN_FAILED;
    }

    dom_len = ed448_dom4_build(dom, phflag, ctx, ctx_len);

    if(phflag == NOXTLS_ED448_PH_FLAG_PREHASH) {
        if(ed448_ph64(noxtls_message, message_len, ph_buf) != NOXTLS_RETURN_SUCCESS)
            return NOXTLS_RETURN_FAILED;
        m_body = ph_buf;
        m_len = NOXTLS_ED448_PH_DIGEST_BYTES;
    } else {
        m_body = noxtls_message;
        m_len = message_len;
    }

    if(ge448_decode(&A, public_key) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(ge448_decode(&R, signature) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    memcpy(S_le, signature + NOXTLS_ED448_PUBLIC_KEY_SIZE, NOXTLS_ED448_PUBLIC_KEY_SIZE);
    le56_to_be56(S_be, S_le);
    if(noxtls_bn_cmp(S_be, ed448_L, NOXTLS_ED448_FE448_BYTES) >= 0) return NOXTLS_RETURN_FAILED;

    if(noxtls_shake256_init(&ctx_shake) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(noxtls_shake256_update(&ctx_shake, dom, dom_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(noxtls_shake256_update(&ctx_shake, signature, NOXTLS_ED448_PUBLIC_KEY_SIZE) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(noxtls_shake256_update(&ctx_shake, public_key, NOXTLS_ED448_PUBLIC_KEY_SIZE) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(m_len != 0u && m_body != NULL) {
        if(noxtls_shake256_update(&ctx_shake, m_body, m_len) != NOXTLS_RETURN_SUCCESS)
            return NOXTLS_RETURN_FAILED;
    }
    if(noxtls_shake256_final(&ctx_shake) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(noxtls_shake256_squeeze(&ctx_shake, k_in, NOXTLS_ED448_SHAKE_WIDE_BYTES) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    if(sc448_reduce_mod_l(k_le, k_in) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(ge448_scalar_mult(&kA, k_le, &A) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(ge448_add(&R_plus_kA, &R, &kA) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(ge448_set_basepoint(&R) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(ge448_scalar_mult(&sB, S_le, &R) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    memset(four, 0, NOXTLS_ED448_PUBLIC_KEY_SIZE);
    four[0] = NOXTLS_ED448_VERIFY_COFACTOR;
    {
        ge448_pt_t lhs;
        ge448_pt_t rhs;
        uint8_t enc_l[NOXTLS_ED448_PUBLIC_KEY_SIZE];
        uint8_t enc_r[NOXTLS_ED448_PUBLIC_KEY_SIZE];
        if(ge448_scalar_mult(&lhs, four, &sB) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if(ge448_scalar_mult(&rhs, four, &R_plus_kA) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if(ge448_encode(enc_l, &lhs) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if(ge448_encode(enc_r, &rhs) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if(noxtls_secret_memcmp(enc_l, enc_r, NOXTLS_ED448_PUBLIC_KEY_SIZE) != 0) return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Derive the Ed448 public key (57-byte encoding) from a 57-byte private seed (RFC 8032).
 * @param[in] private_key 57-byte secret seed.
 * @param[out] public_key 57-byte compressed public key.
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if @p private_key or @p public_key is NULL.
 * @return NOXTLS_RETURN_FAILED if hashing or curve operations fail.
 */
noxtls_return_t noxtls_ed448_public_key(const uint8_t private_key[NOXTLS_ED448_PRIVATE_KEY_SIZE], uint8_t public_key[NOXTLS_ED448_PUBLIC_KEY_SIZE])
{
    uint8_t h[NOXTLS_ED448_SHAKE_WIDE_BYTES];
    uint8_t s_le[NOXTLS_ED448_PUBLIC_KEY_SIZE];
    ge448_pt_t B;
    ge448_pt_t A;
    if(private_key == NULL || public_key == NULL) return NOXTLS_RETURN_NULL;
    if(ed448_hash_secret(h, private_key) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    h[0] &= (uint8_t)NOXTLS_ED448_SCALAR_CLAMP_BYTE0_MASK;
    h[55] &= (uint8_t)NOXTLS_ED448_SCALAR_CLAMP_BYTE55_AND;
    h[55] |= (uint8_t)NOXTLS_ED448_SCALAR_CLAMP_BYTE55_OR;
    memcpy(s_le, h, NOXTLS_ED448_FE448_BYTES);
    s_le[NOXTLS_ED448_PUBLIC_KEY_SIZE - 1U] = 0;
    if(ge448_set_basepoint(&B) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(ge448_scalar_mult(&A, s_le, &B) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return ge448_encode(public_key, &A);
}

/**
 * @brief Sign a noxtls_message with Ed448 (PureEdDSA, no context string; RFC 8032).
 * @param[in] private_key 57-byte private seed.
 * @param[in] noxtls_message Message bytes (NULL allowed only if @p message_len is 0).
 * @param[in] message_len Length of @p noxtls_message in bytes.
 * @param[out] signature 114-byte signature (R || S).
 * @return NOXTLS_RETURN_SUCCESS on success, or an error from the internal signing path.
 */
noxtls_return_t noxtls_ed448_sign(const uint8_t private_key[NOXTLS_ED448_PRIVATE_KEY_SIZE], const uint8_t *noxtls_message, uint32_t message_len, uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE])
{
    return ed448_sign_internal(private_key, noxtls_message, message_len, signature, NOXTLS_ED448_PH_FLAG_PURE, NULL, 0);
}

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
noxtls_return_t noxtls_ed448_verify(const uint8_t public_key[NOXTLS_ED448_PUBLIC_KEY_SIZE], const uint8_t *noxtls_message, uint32_t message_len, const uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE])
{
    return ed448_verify_internal(public_key, noxtls_message, message_len, signature, NOXTLS_ED448_PH_FLAG_PURE, NULL, 0);
}

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
    if(context == NULL && context_len != 0u) return NOXTLS_RETURN_NULL;
    if(context_len < 1u || context_len > (uint32_t)NOXTLS_ED448_CONTEXT_MAX)
        return NOXTLS_RETURN_FAILED;
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
    if(context == NULL && context_len != 0u) return NOXTLS_RETURN_NULL;
    if(context_len < 1u || context_len > (uint32_t)NOXTLS_ED448_CONTEXT_MAX)
        return NOXTLS_RETURN_FAILED;
    return ed448_verify_internal(public_key, noxtls_message, message_len, signature, NOXTLS_ED448_PH_FLAG_PURE, context, context_len);
}

/**
 * @brief Sign with Ed448ph: noxtls_message representative is first 64 bytes of SHAKE256(M) (RFC 8032).
 * @param[in] private_key 57-byte private seed.
 * @param[in] noxtls_message Message to prehash.
 * @param[in] message_len Length of @p noxtls_message in bytes.
 * @param[out] signature 114-byte signature.
 * @return NOXTLS_RETURN_SUCCESS on success, or an error from the internal signing path.
 */
noxtls_return_t noxtls_ed448ph_sign(const uint8_t private_key[NOXTLS_ED448_PRIVATE_KEY_SIZE],
    const uint8_t *noxtls_message, uint32_t message_len, uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE])
{
    return ed448_sign_internal(private_key, noxtls_message, message_len, signature, NOXTLS_ED448_PH_FLAG_PREHASH, NULL, 0);
}

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
    const uint8_t *noxtls_message, uint32_t message_len, const uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE])
{
    return ed448_verify_internal(public_key, noxtls_message, message_len, signature, NOXTLS_ED448_PH_FLAG_PREHASH, NULL, 0);
}

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
    noxtls_return_t rc;
    if(private_key == NULL || public_key == NULL) return NOXTLS_RETURN_NULL;
    if(!drbg_initialized) {
        rc = drbg_instantiate(&drbg_state, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        drbg_initialized = 1;
    }
    rc = drbg_generate(&drbg_state, private_key, NOXTLS_ED448_DRBG_SEED_BITS, NULL, 0);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    return noxtls_ed448_public_key(private_key, public_key);
}

#else /* !NOXTLS_FEATURE_ED448 || !NOXTLS_FEATURE_SHA3 */

/**
 * @brief Stubs when Ed448 or SHA-3 is disabled at build time: all noxtls_ed448_* entry points return NOXTLS_RETURN_NOT_SUPPORTED.
 */

noxtls_return_t noxtls_ed448_generate_key(uint8_t private_key[NOXTLS_ED448_PRIVATE_KEY_SIZE], uint8_t public_key[NOXTLS_ED448_PUBLIC_KEY_SIZE])
{
    (void)private_key;
    (void)public_key;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_ed448_public_key(const uint8_t private_key[NOXTLS_ED448_PRIVATE_KEY_SIZE], uint8_t public_key[NOXTLS_ED448_PUBLIC_KEY_SIZE])
{
    (void)private_key;
    (void)public_key;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_ed448_sign(const uint8_t private_key[NOXTLS_ED448_PRIVATE_KEY_SIZE], const uint8_t *noxtls_message, uint32_t message_len, uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE])
{
    (void)private_key;
    (void)noxtls_message;
    (void)message_len;
    (void)signature;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_ed448_verify(const uint8_t public_key[NOXTLS_ED448_PUBLIC_KEY_SIZE], const uint8_t *noxtls_message, uint32_t message_len, const uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE])
{
    (void)public_key;
    (void)noxtls_message;
    (void)message_len;
    (void)signature;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_ed448ctx_sign(const uint8_t private_key[NOXTLS_ED448_PRIVATE_KEY_SIZE],
    const uint8_t *context, uint32_t context_len,
    const uint8_t *noxtls_message, uint32_t message_len, uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE])
{
    (void)private_key;
    (void)context;
    (void)context_len;
    (void)noxtls_message;
    (void)message_len;
    (void)signature;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_ed448ctx_verify(const uint8_t public_key[NOXTLS_ED448_PUBLIC_KEY_SIZE],
    const uint8_t *context, uint32_t context_len,
    const uint8_t *noxtls_message, uint32_t message_len, const uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE])
{
    (void)public_key;
    (void)context;
    (void)context_len;
    (void)noxtls_message;
    (void)message_len;
    (void)signature;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_ed448ph_sign(const uint8_t private_key[NOXTLS_ED448_PRIVATE_KEY_SIZE],
    const uint8_t *noxtls_message, uint32_t message_len, uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE])
{
    (void)private_key;
    (void)noxtls_message;
    (void)message_len;
    (void)signature;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_ed448ph_verify(const uint8_t public_key[NOXTLS_ED448_PUBLIC_KEY_SIZE],
    const uint8_t *noxtls_message, uint32_t message_len, const uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE])
{
    (void)public_key;
    (void)noxtls_message;
    (void)message_len;
    (void)signature;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

#endif /* NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3 */
