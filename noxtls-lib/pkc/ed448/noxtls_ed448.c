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

#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "common/noxtls_ct.h"
#include "noxtls_common.h"
#include "noxtls_ed448.h"
#include "pkc/rsa/noxtls_bignum.h"
#include "drbg/noxtls_drbg.h"

#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3

#include "mdigest/sha3/noxtls_sha3.h"

#define ED448_FIELD_SIZE 56
#define ED448_ENCODED_SIZE 57

/* p = 2^448 - 2^224 - 1 (same as Curve448), big-endian */
static const uint8_t ed448_p[ED448_FIELD_SIZE] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/* d = -39081 for curve x^2+y^2 = 1 + d*x^2*y^2. Stored as p + (-39081) in BE. */
static const uint8_t ed448_d[ED448_FIELD_SIZE] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x6F, 0x67, 0x97
};

/* Order L of the prime-order subgroup (446-bit prime), big-endian. */
static const uint8_t ed448_L[ED448_FIELD_SIZE] = {
    0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7C, 0xCA, 0x23, 0xE9,
    0x63, 0xC4, 0x4C, 0x17, 0x32, 0x6E, 0x42, 0x84, 0xC5, 0xBB, 0x9D, 0xAE, 0x90, 0xE9,
    0x36, 0x53, 0xBF, 0x6D, 0x5C, 0xC8, 0x4C, 0x1D, 0x1A, 0x8A, 0x6D, 0x1E, 0xAD, 0x93
};

static void le56_to_be56(uint8_t be[ED448_FIELD_SIZE], const uint8_t le[ED448_FIELD_SIZE])
{
    int i;
    for (i = 0; i < ED448_FIELD_SIZE; i++)
        be[i] = le[ED448_FIELD_SIZE - 1 - i];
}

static void be56_to_le56(uint8_t le[ED448_FIELD_SIZE], const uint8_t be[ED448_FIELD_SIZE])
{
    int i;
    for (i = 0; i < ED448_FIELD_SIZE; i++)
        le[i] = be[ED448_FIELD_SIZE - 1 - i];
}

static noxtls_return_t fe448_add(uint8_t r[ED448_FIELD_SIZE], const uint8_t a[ED448_FIELD_SIZE], const uint8_t b[ED448_FIELD_SIZE])
{
    uint8_t sum[112];
    memset(sum, 0, sizeof(sum));
    if (noxtls_bn_add(sum + ED448_FIELD_SIZE, a, b, ED448_FIELD_SIZE) != NOXTLS_RETURN_SUCCESS)
        return NOXTLS_RETURN_FAILED;
    return noxtls_bn_mod(r, sum, sizeof(sum), ed448_p, ED448_FIELD_SIZE);
}

static noxtls_return_t fe448_sub(uint8_t r[ED448_FIELD_SIZE], const uint8_t a[ED448_FIELD_SIZE], const uint8_t b[ED448_FIELD_SIZE])
{
    uint8_t diff[ED448_FIELD_SIZE];
    if (noxtls_bn_sub(diff, a, b, ED448_FIELD_SIZE) != NOXTLS_RETURN_SUCCESS)
        return NOXTLS_RETURN_FAILED;
    if (noxtls_bn_cmp(a, b, ED448_FIELD_SIZE) < 0) {
        if (noxtls_bn_add(diff, diff, ed448_p, ED448_FIELD_SIZE) != NOXTLS_RETURN_SUCCESS)
            return NOXTLS_RETURN_FAILED;
    }
    if (noxtls_bn_cmp(diff, ed448_p, ED448_FIELD_SIZE) >= 0)
        return noxtls_bn_mod(r, diff, ED448_FIELD_SIZE, ed448_p, ED448_FIELD_SIZE);
    memcpy(r, diff, ED448_FIELD_SIZE);
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t fe448_mul(uint8_t r[ED448_FIELD_SIZE], const uint8_t a[ED448_FIELD_SIZE], const uint8_t b[ED448_FIELD_SIZE])
{
    uint8_t product[112];
    if (noxtls_bn_mul(product, a, ED448_FIELD_SIZE, b, ED448_FIELD_SIZE) != NOXTLS_RETURN_SUCCESS)
        return NOXTLS_RETURN_FAILED;
    return noxtls_bn_mod(r, product, sizeof(product), ed448_p, ED448_FIELD_SIZE);
}

static noxtls_return_t fe448_inv(uint8_t r[ED448_FIELD_SIZE], const uint8_t a[ED448_FIELD_SIZE])
{
    uint8_t p_minus_2[ED448_FIELD_SIZE], two[ED448_FIELD_SIZE];
    memcpy(p_minus_2, ed448_p, ED448_FIELD_SIZE);
    memset(two, 0, ED448_FIELD_SIZE);
    two[ED448_FIELD_SIZE - 1] = 2;
    if (noxtls_bn_sub(p_minus_2, p_minus_2, two, ED448_FIELD_SIZE) != NOXTLS_RETURN_SUCCESS)
        return NOXTLS_RETURN_FAILED;
    return noxtls_bn_mod_exp(r, a, p_minus_2, ED448_FIELD_SIZE, ed448_p, ED448_FIELD_SIZE);
}

typedef struct { uint8_t X[ED448_FIELD_SIZE], Y[ED448_FIELD_SIZE], Z[ED448_FIELD_SIZE], T[ED448_FIELD_SIZE]; } ge448_pt_t;

static noxtls_return_t ge448_decode(ge448_pt_t *p, const uint8_t enc[ED448_ENCODED_SIZE]);
static noxtls_return_t ge448_encode(uint8_t enc[ED448_ENCODED_SIZE], const ge448_pt_t *p);

static void ge448_pt_zero(ge448_pt_t *p)
{
    noxtls_bn_zero(p->X, ED448_FIELD_SIZE);
    noxtls_bn_one(p->Y, ED448_FIELD_SIZE);
    noxtls_bn_one(p->Z, ED448_FIELD_SIZE);
    noxtls_bn_zero(p->T, ED448_FIELD_SIZE);
}

/* Point add for a=1: x^2+y^2 = 1+d*x^2*y^2. Formulas from RFC 8032 / Edwards-revisited. */
static noxtls_return_t ge448_add(ge448_pt_t *r, const ge448_pt_t *p, const ge448_pt_t *q)
{
    uint8_t A[ED448_FIELD_SIZE], B[ED448_FIELD_SIZE], C[ED448_FIELD_SIZE], D[ED448_FIELD_SIZE];
    uint8_t E[ED448_FIELD_SIZE], F[ED448_FIELD_SIZE], G[ED448_FIELD_SIZE], H[ED448_FIELD_SIZE];
    uint8_t y1mx1[ED448_FIELD_SIZE], y2mx2[ED448_FIELD_SIZE], y1px1[ED448_FIELD_SIZE], y2px2[ED448_FIELD_SIZE];
    uint8_t z1_inv[ED448_FIELD_SIZE], z2_inv[ED448_FIELD_SIZE];
    uint8_t x1[ED448_FIELD_SIZE], y1[ED448_FIELD_SIZE], x2[ED448_FIELD_SIZE], y2[ED448_FIELD_SIZE];
    uint8_t two[ED448_FIELD_SIZE];
    memset(two, 0, ED448_FIELD_SIZE);
    two[ED448_FIELD_SIZE - 1] = 2;

    if (fe448_inv(z1_inv, p->Z) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_inv(z2_inv, q->Z) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_mul(x1, p->X, z1_inv) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_mul(y1, p->Y, z1_inv) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_mul(x2, q->X, z2_inv) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_mul(y2, q->Y, z2_inv) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    if (fe448_sub(y1mx1, y1, x1) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_sub(y2mx2, y2, x2) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_add(y1px1, y1, x1) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_add(y2px2, y2, x2) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_mul(A, y1mx1, y2mx2) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_mul(B, y1px1, y2px2) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_mul(C, p->T, q->T) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_mul(C, C, ed448_d) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_mul(C, C, two) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_mul(D, p->Z, q->Z) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_mul(D, D, two) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_sub(E, B, A) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_sub(F, D, C) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_add(G, D, C) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_add(H, B, A) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_mul(r->X, E, F) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_mul(r->Y, G, H) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_mul(r->T, E, H) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_mul(r->Z, F, G) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t ge448_dbl(ge448_pt_t *r, const ge448_pt_t *p)
{
    return ge448_add(r, p, p);
}

static noxtls_return_t ge448_scalar_mult(ge448_pt_t *R, const uint8_t s_le[ED448_FIELD_SIZE], const ge448_pt_t *P)
{
    ge448_pt_t N, T;
    ge448_pt_zero(R);
    memcpy(&N, P, sizeof(ge448_pt_t));
    int i, bit;
    for (i = 0; i < 448; i++) {
        bit = (s_le[i >> 3] >> (i & 7)) & 1;
        if (bit) {
            memcpy(&T, R, sizeof(ge448_pt_t));
            if (ge448_add(R, &T, &N) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        }
        memcpy(&T, &N, sizeof(ge448_pt_t));
        if (ge448_dbl(&N, &T) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/* Decode 57-byte encoding to point. */
static noxtls_return_t ge448_decode(ge448_pt_t *p, const uint8_t enc[ED448_ENCODED_SIZE])
{
    uint8_t y_le[ED448_ENCODED_SIZE], y_be[ED448_FIELD_SIZE];
    uint8_t u[ED448_FIELD_SIZE], v[ED448_FIELD_SIZE], x2[ED448_FIELD_SIZE], x[ED448_FIELD_SIZE];
    uint8_t one[ED448_FIELD_SIZE], v_inv[ED448_FIELD_SIZE];
    uint8_t p34[ED448_FIELD_SIZE]; /* (p+3)/4 for sqrt */
    int i;
    memset(y_le, 0, ED448_ENCODED_SIZE);
    memcpy(y_le, enc, ED448_FIELD_SIZE);
    y_le[ED448_ENCODED_SIZE - 1] &= 0x7Fu;
    le56_to_be56(y_be, y_le);
    if (noxtls_bn_cmp(y_be, ed448_p, ED448_FIELD_SIZE) >= 0) return NOXTLS_RETURN_FAILED;
    noxtls_bn_one(one, ED448_FIELD_SIZE);
    /* u = y^2 - 1, v = d*y^2 + 1 */
    if (fe448_mul(u, y_be, y_be) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_sub(u, u, one) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_mul(v, y_be, y_be) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_mul(v, v, ed448_d) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_add(v, v, one) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_inv(v_inv, v) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_mul(x2, u, v_inv) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    /* p ≡ 3 (mod 4): x = x2^((p+3)/4) */
    memcpy(p34, ed448_p, ED448_FIELD_SIZE);
    for (i = ED448_FIELD_SIZE - 1; i >= 0 && p34[i] == 0; i--) {}
    if (i >= 0) {
        p34[ED448_FIELD_SIZE - 1] += 3;
        for (i = ED448_FIELD_SIZE - 1; i > 0 && p34[i] < 3; i--) { p34[i] += 256; p34[i-1]--; }
    }
    if (noxtls_bn_mod_exp(x, x2, p34, ED448_FIELD_SIZE, ed448_p, ED448_FIELD_SIZE) != NOXTLS_RETURN_SUCCESS)
        return NOXTLS_RETURN_FAILED;
    if ((enc[ED448_ENCODED_SIZE - 1] >> 7) != (x[ED448_FIELD_SIZE - 1] & 1)) {
        if (fe448_sub(x, ed448_p, x) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    }
    noxtls_bn_one(p->Z, ED448_FIELD_SIZE);
    memcpy(p->X, x, ED448_FIELD_SIZE);
    memcpy(p->Y, y_be, ED448_FIELD_SIZE);
    if (fe448_mul(p->T, p->X, p->Y) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t ge448_encode(uint8_t enc[ED448_ENCODED_SIZE], const ge448_pt_t *p)
{
    uint8_t zinv[ED448_FIELD_SIZE], x[ED448_FIELD_SIZE], y[ED448_FIELD_SIZE];
    if (fe448_inv(zinv, p->Z) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_mul(x, p->X, zinv) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_mul(y, p->Y, zinv) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    be56_to_le56(enc, y);
    enc[ED448_ENCODED_SIZE - 1] |= (x[ED448_FIELD_SIZE - 1] & 1) << 7;
    return NOXTLS_RETURN_SUCCESS;
}

/* Base point: (x, 19) with x^2 = (1-361)/(1+d*361). Computed once. */
static noxtls_return_t ge448_set_basepoint(ge448_pt_t *p)
{
    /* y = 19. u = 1-361 = -360, v = 1+d*361. We need x^2 = u/v, x = sqrt(u/v). */
    uint8_t y_be[ED448_FIELD_SIZE], u[ED448_FIELD_SIZE], v[ED448_FIELD_SIZE], v_inv[ED448_FIELD_SIZE];
    uint8_t x2[ED448_FIELD_SIZE], x[ED448_FIELD_SIZE], p34[ED448_FIELD_SIZE];
    uint8_t neg360[ED448_FIELD_SIZE], d361[ED448_FIELD_SIZE];
    int i;
    memset(y_be, 0, ED448_FIELD_SIZE);
    y_be[ED448_FIELD_SIZE - 1] = 19;
    noxtls_bn_zero(neg360, ED448_FIELD_SIZE);
    if (noxtls_bn_sub(neg360, ed448_p, neg360) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    /* neg360 = 360 in BE: 0..0 0x01 0x68 */
    memset(neg360, 0, ED448_FIELD_SIZE);
    neg360[ED448_FIELD_SIZE - 2] = 1;
    neg360[ED448_FIELD_SIZE - 1] = 0x68; /* 360 = 0x168 */
    if (noxtls_bn_sub(u, ed448_p, neg360) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED; /* u = p - 360 */
    if (fe448_mul(d361, ed448_d, y_be) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_mul(d361, d361, y_be) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED; /* d*361 */
    noxtls_bn_one(v, ED448_FIELD_SIZE);
    if (fe448_add(v, v, d361) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_inv(v_inv, v) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe448_mul(x2, u, v_inv) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    memcpy(p34, ed448_p, ED448_FIELD_SIZE);
    p34[ED448_FIELD_SIZE - 1] += 3;
    for (i = ED448_FIELD_SIZE - 1; i > 0 && p34[i] < 3; i--) { p34[i] += 256; p34[i-1]--; }
    if (noxtls_bn_mod_exp(x, x2, p34, ED448_FIELD_SIZE, ed448_p, ED448_FIELD_SIZE) != NOXTLS_RETURN_SUCCESS)
        return NOXTLS_RETURN_FAILED;
    noxtls_bn_one(p->Z, ED448_FIELD_SIZE);
    memcpy(p->X, x, ED448_FIELD_SIZE);
    memcpy(p->Y, y_be, ED448_FIELD_SIZE);
    if (fe448_mul(p->T, p->X, p->Y) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return NOXTLS_RETURN_SUCCESS;
}

/* Reduce 114-byte LE integer mod L, output 57-byte LE (high 57 bytes of 114). */
static noxtls_return_t sc448_reduce_mod_l(uint8_t out_le[ED448_ENCODED_SIZE], const uint8_t in_le[114])
{
    uint8_t in_be[114], out_be[ED448_FIELD_SIZE];
    int i;
    for (i = 0; i < 114; i++) in_be[i] = in_le[113 - i];
    if (noxtls_bn_mod(out_be, in_be, 114, ed448_L, ED448_FIELD_SIZE) != NOXTLS_RETURN_SUCCESS)
        return NOXTLS_RETURN_FAILED;
    be56_to_le56(out_le, out_be);
    out_le[56] = 0;
    return NOXTLS_RETURN_SUCCESS;
}

/* dom4(phflag, ctx): "SigEd448" (8) || phflag (1) || ctx_len (1) || ctx (ctx_len) */
static uint32_t ed448_dom4_build(uint8_t out[10 + NOXTLS_ED448_CONTEXT_MAX], uint8_t phflag,
    const uint8_t *ctx, uint32_t ctx_len)
{
    static const uint8_t sig8[8] = { 'S','i','g','E','d','4','4','8' };
    memcpy(out, sig8, 8);
    out[8] = phflag;
    out[9] = (uint8_t)ctx_len;
    if (ctx_len != 0u && ctx != NULL)
        memcpy(out + 10, ctx, ctx_len);
    return 10u + ctx_len;
}

static noxtls_return_t ed448_shake256_chain(uint8_t out[114], unsigned n,
    const uint8_t **parts, const uint32_t *lens)
{
    noxtls_sha3_ctx_t ctx;
    unsigned i;
    if (noxtls_shake256_init(&ctx) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    for (i = 0; i < n; i++) {
        if (lens[i] != 0u && parts[i] != NULL) {
            if (noxtls_shake256_update(&ctx, parts[i], lens[i]) != NOXTLS_RETURN_SUCCESS)
                return NOXTLS_RETURN_FAILED;
        }
    }
    if (noxtls_shake256_final(&ctx) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return noxtls_shake256_squeeze(&ctx, out, 114);
}

/* H(dom_pure || sk57): first 114 octets of SHAKE256 — key derivation (pure dom only). */
static noxtls_return_t ed448_hash_secret(uint8_t out[114], const uint8_t *sk57)
{
    uint8_t dom[10];
    const uint8_t *parts[2];
    uint32_t lens[2];
    (void)ed448_dom4_build(dom, 0, NULL, 0);
    parts[0] = dom;
    lens[0] = 10;
    parts[1] = sk57;
    lens[1] = 57;
    return ed448_shake256_chain(out, 2, parts, lens);
}

/** PH(M): first 64 bytes of SHAKE256(M) per RFC 8032 Ed448ph. */
static noxtls_return_t ed448_ph64(const uint8_t *msg, uint32_t msg_len, uint8_t digest[64])
{
    noxtls_sha3_ctx_t ctx;
    if (noxtls_shake256_init(&ctx) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (msg_len != 0u && msg != NULL) {
        if (noxtls_shake256_update(&ctx, msg, msg_len) != NOXTLS_RETURN_SUCCESS)
            return NOXTLS_RETURN_FAILED;
    }
    if (noxtls_shake256_final(&ctx) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return noxtls_shake256_squeeze(&ctx, digest, 64);
}

static noxtls_return_t ed448_sign_internal(const uint8_t private_key[57],
    const uint8_t *message, uint32_t message_len, uint8_t signature[114],
    uint8_t phflag, const uint8_t *ctx, uint32_t ctx_len)
{
    uint8_t h[114], prefix[57], s_le[ED448_ENCODED_SIZE];
    uint8_t r_in[114], r_le[ED448_ENCODED_SIZE], k_in[114], k_le[ED448_ENCODED_SIZE];
    uint8_t dom[10 + NOXTLS_ED448_CONTEXT_MAX];
    uint32_t dom_len;
    ge448_pt_t B, R;
    uint8_t public_key[57];
    uint8_t S_le[ED448_ENCODED_SIZE], ks_le[ED448_ENCODED_SIZE];
    uint8_t rs_le64[114], sum_le[114];
    uint8_t ph_buf[64];
    const uint8_t *m_body;
    uint32_t m_len;
    uint32_t i;

    if (private_key == NULL || signature == NULL) return NOXTLS_RETURN_NULL;
    if (message == NULL && message_len != 0u) return NOXTLS_RETURN_NULL;
    if (phflag > 1u) return NOXTLS_RETURN_FAILED;
    if (phflag != 0u) {
        if (ctx_len != 0u || ctx != NULL) return NOXTLS_RETURN_FAILED;
    } else if (ctx_len != 0u) {
        if (ctx == NULL || ctx_len < 1u || ctx_len > (uint32_t)NOXTLS_ED448_CONTEXT_MAX)
            return NOXTLS_RETURN_FAILED;
    }

    dom_len = ed448_dom4_build(dom, phflag, ctx, ctx_len);

    if (phflag != 0u) {
        if (ed448_ph64(message, message_len, ph_buf) != NOXTLS_RETURN_SUCCESS)
            return NOXTLS_RETURN_FAILED;
        m_body = ph_buf;
        m_len = 64;
    } else {
        m_body = message;
        m_len = message_len;
    }

    if (ed448_hash_secret(h, private_key) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    h[0] &= (uint8_t)0xFC;
    h[55] &= (uint8_t)0x7F;
    h[55] |= (uint8_t)0x40;
    memcpy(prefix, h + ED448_FIELD_SIZE, 57);
    memcpy(s_le, h, ED448_FIELD_SIZE);
    s_le[56] = 0;
    if (noxtls_ed448_public_key(private_key, public_key) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    {
        const uint8_t *parts_r[3];
        uint32_t lens_r[3];
        parts_r[0] = dom;
        lens_r[0] = dom_len;
        parts_r[1] = prefix;
        lens_r[1] = 57;
        parts_r[2] = m_body;
        lens_r[2] = m_len;
        if (ed448_shake256_chain(r_in, 3, parts_r, lens_r) != NOXTLS_RETURN_SUCCESS)
            return NOXTLS_RETURN_FAILED;
    }
    if (sc448_reduce_mod_l(r_le, r_in) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (ge448_set_basepoint(&B) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (ge448_scalar_mult(&R, r_le, &B) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (ge448_encode(signature, &R) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    {
        const uint8_t *parts_k[4];
        uint32_t lens_k[4];
        parts_k[0] = dom;
        lens_k[0] = dom_len;
        parts_k[1] = signature;
        lens_k[1] = 57;
        parts_k[2] = public_key;
        lens_k[2] = 57;
        parts_k[3] = m_body;
        lens_k[3] = m_len;
        if (ed448_shake256_chain(k_in, 4, parts_k, lens_k) != NOXTLS_RETURN_SUCCESS)
            return NOXTLS_RETURN_FAILED;
    }
    if (sc448_reduce_mod_l(k_le, k_in) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    memset(rs_le64, 0, 114);
    for (i = 0; i < 57; i++) {
        uint32_t j, carry = 0;
        for (j = 0; j < 57; j++) {
            uint32_t t = (uint32_t)rs_le64[i + j] + (uint32_t)k_le[i] * (uint32_t)s_le[j] + carry;
            rs_le64[i + j] = (uint8_t)(t & 0xFFu);
            carry = t >> 8;
        }
        for (j = 57; j < 114 - i && carry != 0u; j++) {
            uint32_t t = (uint32_t)rs_le64[i + j] + carry;
            rs_le64[i + j] = (uint8_t)(t & 0xFFu);
            carry = t >> 8;
        }
    }
    if (sc448_reduce_mod_l(ks_le, rs_le64) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    memset(sum_le, 0, 114);
    {
        uint32_t carry = 0;
        for (i = 0; i < 57; i++) {
            uint32_t t = (uint32_t)r_le[i] + (uint32_t)ks_le[i] + carry;
            sum_le[i] = (uint8_t)(t & 0xFFu);
            carry = t >> 8;
        }
        if (carry != 0u) sum_le[57] = (uint8_t)carry;
    }
    if (sc448_reduce_mod_l(S_le, sum_le) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    memcpy(signature + 57, S_le, 57);
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t ed448_verify_internal(const uint8_t public_key[57],
    const uint8_t *message, uint32_t message_len, const uint8_t signature[114],
    uint8_t phflag, const uint8_t *ctx, uint32_t ctx_len)
{
    ge448_pt_t A, R, R_plus_kA, kA, sB;
    uint8_t dom[10 + NOXTLS_ED448_CONTEXT_MAX];
    uint32_t dom_len;
    uint8_t k_in[114], k_le[ED448_ENCODED_SIZE];
    uint8_t S_be[ED448_FIELD_SIZE], S_le[ED448_ENCODED_SIZE];
    noxtls_sha3_ctx_t ctx_shake;
    uint8_t four[ED448_ENCODED_SIZE];
    uint8_t ph_buf[64];
    const uint8_t *m_body;
    uint32_t m_len;

    if (public_key == NULL || signature == NULL) return NOXTLS_RETURN_NULL;
    if (message == NULL && message_len != 0u) return NOXTLS_RETURN_NULL;
    if (phflag > 1u) return NOXTLS_RETURN_FAILED;
    if (phflag != 0u) {
        if (ctx_len != 0u || ctx != NULL) return NOXTLS_RETURN_FAILED;
    } else if (ctx_len != 0u) {
        if (ctx == NULL || ctx_len < 1u || ctx_len > (uint32_t)NOXTLS_ED448_CONTEXT_MAX)
            return NOXTLS_RETURN_FAILED;
    }

    dom_len = ed448_dom4_build(dom, phflag, ctx, ctx_len);

    if (phflag != 0u) {
        if (ed448_ph64(message, message_len, ph_buf) != NOXTLS_RETURN_SUCCESS)
            return NOXTLS_RETURN_FAILED;
        m_body = ph_buf;
        m_len = 64;
    } else {
        m_body = message;
        m_len = message_len;
    }

    if (ge448_decode(&A, public_key) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (ge448_decode(&R, signature) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    memcpy(S_le, signature + 57, 57);
    le56_to_be56(S_be, S_le);
    if (noxtls_bn_cmp(S_be, ed448_L, ED448_FIELD_SIZE) >= 0) return NOXTLS_RETURN_FAILED;

    if (noxtls_shake256_init(&ctx_shake) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (noxtls_shake256_update(&ctx_shake, dom, dom_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (noxtls_shake256_update(&ctx_shake, signature, 57) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (noxtls_shake256_update(&ctx_shake, public_key, 57) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (m_len != 0u && m_body != NULL) {
        if (noxtls_shake256_update(&ctx_shake, m_body, m_len) != NOXTLS_RETURN_SUCCESS)
            return NOXTLS_RETURN_FAILED;
    }
    if (noxtls_shake256_final(&ctx_shake) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (noxtls_shake256_squeeze(&ctx_shake, k_in, 114) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    if (sc448_reduce_mod_l(k_le, k_in) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (ge448_scalar_mult(&kA, k_le, &A) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (ge448_add(&R_plus_kA, &R, &kA) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (ge448_set_basepoint(&R) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (ge448_scalar_mult(&sB, S_le, &R) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    memset(four, 0, ED448_ENCODED_SIZE);
    four[0] = 4;
    {
        ge448_pt_t lhs, rhs;
        uint8_t enc_l[57], enc_r[57];
        if (ge448_scalar_mult(&lhs, four, &sB) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (ge448_scalar_mult(&rhs, four, &R_plus_kA) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (ge448_encode(enc_l, &lhs) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (ge448_encode(enc_r, &rhs) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (noxtls_secret_memcmp(enc_l, enc_r, 57) != 0) return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_ed448_public_key(const uint8_t private_key[57], uint8_t public_key[57])
{
    uint8_t h[114], s_le[ED448_ENCODED_SIZE];
    ge448_pt_t B, A;
    if (private_key == NULL || public_key == NULL) return NOXTLS_RETURN_NULL;
    if (ed448_hash_secret(h, private_key) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    h[0] &= (uint8_t)0xFC;
    h[55] &= (uint8_t)0x7F;
    h[55] |= (uint8_t)0x40;
    memcpy(s_le, h, ED448_FIELD_SIZE);
    s_le[56] = 0;
    if (ge448_set_basepoint(&B) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (ge448_scalar_mult(&A, s_le, &B) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return ge448_encode(public_key, &A);
}

noxtls_return_t noxtls_ed448_sign(const uint8_t private_key[57], const uint8_t *message, uint32_t message_len, uint8_t signature[114])
{
    return ed448_sign_internal(private_key, message, message_len, signature, 0, NULL, 0);
}

noxtls_return_t noxtls_ed448_verify(const uint8_t public_key[57], const uint8_t *message, uint32_t message_len, const uint8_t signature[114])
{
    return ed448_verify_internal(public_key, message, message_len, signature, 0, NULL, 0);
}

noxtls_return_t noxtls_ed448ctx_sign(const uint8_t private_key[57],
    const uint8_t *context, uint32_t context_len,
    const uint8_t *message, uint32_t message_len, uint8_t signature[114])
{
    if (context == NULL && context_len != 0u) return NOXTLS_RETURN_NULL;
    if (context_len < 1u || context_len > (uint32_t)NOXTLS_ED448_CONTEXT_MAX)
        return NOXTLS_RETURN_FAILED;
    return ed448_sign_internal(private_key, message, message_len, signature, 0, context, context_len);
}

noxtls_return_t noxtls_ed448ctx_verify(const uint8_t public_key[57],
    const uint8_t *context, uint32_t context_len,
    const uint8_t *message, uint32_t message_len, const uint8_t signature[114])
{
    if (context == NULL && context_len != 0u) return NOXTLS_RETURN_NULL;
    if (context_len < 1u || context_len > (uint32_t)NOXTLS_ED448_CONTEXT_MAX)
        return NOXTLS_RETURN_FAILED;
    return ed448_verify_internal(public_key, message, message_len, signature, 0, context, context_len);
}

noxtls_return_t noxtls_ed448ph_sign(const uint8_t private_key[57],
    const uint8_t *message, uint32_t message_len, uint8_t signature[114])
{
    return ed448_sign_internal(private_key, message, message_len, signature, 1, NULL, 0);
}

noxtls_return_t noxtls_ed448ph_verify(const uint8_t public_key[57],
    const uint8_t *message, uint32_t message_len, const uint8_t signature[114])
{
    return ed448_verify_internal(public_key, message, message_len, signature, 1, NULL, 0);
}

noxtls_return_t noxtls_ed448_generate_key(uint8_t private_key[57], uint8_t public_key[57])
{
    static drbg_state_t drbg_state;
    static int drbg_initialized = 0;
    noxtls_return_t rc;
    if (private_key == NULL || public_key == NULL) return NOXTLS_RETURN_NULL;
    if (!drbg_initialized) {
        rc = drbg_instantiate(&drbg_state, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0);
        if (rc != NOXTLS_RETURN_SUCCESS) return rc;
        drbg_initialized = 1;
    }
    rc = drbg_generate(&drbg_state, private_key, 456, NULL, 0);
    if (rc != NOXTLS_RETURN_SUCCESS) return rc;
    return noxtls_ed448_public_key(private_key, public_key);
}

#else /* !NOXTLS_FEATURE_ED448 || !NOXTLS_FEATURE_SHA3 */

noxtls_return_t noxtls_ed448_generate_key(uint8_t private_key[57], uint8_t public_key[57])
{
    (void)private_key;
    (void)public_key;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_ed448_public_key(const uint8_t private_key[57], uint8_t public_key[57])
{
    (void)private_key;
    (void)public_key;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_ed448_sign(const uint8_t private_key[57], const uint8_t *message, uint32_t message_len, uint8_t signature[114])
{
    (void)private_key;
    (void)message;
    (void)message_len;
    (void)signature;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_ed448_verify(const uint8_t public_key[57], const uint8_t *message, uint32_t message_len, const uint8_t signature[114])
{
    (void)public_key;
    (void)message;
    (void)message_len;
    (void)signature;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_ed448ctx_sign(const uint8_t private_key[57],
    const uint8_t *context, uint32_t context_len,
    const uint8_t *message, uint32_t message_len, uint8_t signature[114])
{
    (void)private_key;
    (void)context;
    (void)context_len;
    (void)message;
    (void)message_len;
    (void)signature;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_ed448ctx_verify(const uint8_t public_key[57],
    const uint8_t *context, uint32_t context_len,
    const uint8_t *message, uint32_t message_len, const uint8_t signature[114])
{
    (void)public_key;
    (void)context;
    (void)context_len;
    (void)message;
    (void)message_len;
    (void)signature;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_ed448ph_sign(const uint8_t private_key[57],
    const uint8_t *message, uint32_t message_len, uint8_t signature[114])
{
    (void)private_key;
    (void)message;
    (void)message_len;
    (void)signature;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_ed448ph_verify(const uint8_t public_key[57],
    const uint8_t *message, uint32_t message_len, const uint8_t signature[114])
{
    (void)public_key;
    (void)message;
    (void)message_len;
    (void)signature;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

#endif /* NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3 */
