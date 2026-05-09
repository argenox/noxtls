/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
*
* File:    noxtls_ed25519.c
* Summary: Ed25519 digital signatures (RFC 8032)
*
*/

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "noxtls_ed25519.h"
#include "noxtls_common.h"
#include "drbg/noxtls_drbg.h"
#include "pkc/rsa/noxtls_bignum.h"
#include "mdigest/sha512/noxtls_sha512.h"

#define ED25519_SIZE 32

/* p = 2^255 - 19 (same as Curve25519), big-endian */
static const uint8_t ed25519_p[ED25519_SIZE] = {
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xED
};

/* L = order of base point = 2^252 + 27742317777372353535851937790883648493, big-endian */
static const uint8_t ed25519_L[ED25519_SIZE] = {
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xDE, 0xF9, 0xDE, 0xA2, 0xF7, 0x9C, 0xD6,
    0x58, 0x12, 0x63, 0x1A, 0x5C, 0xF5, 0xD3, 0xED
};

/* d = -121665/121666 mod p (twisted Edwards curve), big-endian */
static const uint8_t ed25519_d[ED25519_SIZE] = {
    0x52, 0x03, 0x6C, 0xEE, 0x2B, 0x6F, 0xFE, 0x73,
    0x8C, 0xC7, 0x40, 0x79, 0x77, 0x79, 0xE8, 0x98,
    0x00, 0x70, 0x0A, 0x4D, 0x41, 0x41, 0xD8, 0xAB,
    0x75, 0xEB, 0x4D, 0xCA, 0x13, 0x59, 0x78, 0xA3
};

/* Base point B encoding (32 bytes LE) per RFC 8032: y with LSB(x) in high bit of last octet */
static const uint8_t ed25519_B_encoded[ED25519_SIZE] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
};

/* Base point affine coordinates in big-endian (reserved for future use). */
static const uint8_t ed25519_B_x_be[ED25519_SIZE] NOXTLS_UNUSED_ATTR = {
    0x21, 0x69, 0x36, 0xD3, 0xCD, 0x6E, 0x53, 0xFE,
    0xC0, 0xA4, 0xE2, 0x31, 0xFD, 0xD6, 0xDC, 0x5C,
    0x69, 0x2C, 0xC7, 0x60, 0x95, 0x25, 0xA7, 0xB2,
    0xC9, 0x56, 0x2D, 0x60, 0x8F, 0x25, 0xD5, 0x1A
};
static const uint8_t ed25519_B_y_be[ED25519_SIZE] NOXTLS_UNUSED_ATTR = {
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x58
};

static void le32_to_be32(uint8_t be[32], const uint8_t le[32])
{
    for (int i = 0; i < 32; i++) be[i] = le[31 - i];
}

static void be32_to_le32(uint8_t le[32], const uint8_t be[32])
{
    for (int i = 0; i < 32; i++) le[i] = be[31 - i];
}

static void ed25519_dbg_hex32(const char *label, const uint8_t v[32])
{
    fprintf(stderr, "%s=", label);
    for (int i = 0; i < 32; i++) {
        fprintf(stderr, "%02x", v[i]);
    }
    fprintf(stderr, "\n");
}

NOXTLS_UNUSED_ATTR
static void ed25519_dbg_hex64(const char *label, const uint8_t v[64])
{
    fprintf(stderr, "%s=", label);
    for (int i = 0; i < 64; i++) {
        fprintf(stderr, "%02x", v[i]);
    }
    fprintf(stderr, "\n");
}

/* Field GF(p): add, sub, mul, inv (operands and result 32-byte big-endian).
 * Implemented with generic bignum (noxtls_bn_*). For faster Ed25519, use
 * radix-2^51 limbs and projective add/dbl without affine conversion. */
static noxtls_return_t fe25519_add(uint8_t r[32], const uint8_t a[32], const uint8_t b[32])
{
    /* Preserve carry explicitly: build a 33-byte sum in the low half of a 64-byte BE buffer. */
    uint8_t sum[64];
    uint16_t carry = 0;
    memset(sum, 0, sizeof(sum));
    for (int i = 31; i >= 0; i--) {
        uint16_t v = (uint16_t)a[i] + (uint16_t)b[i] + carry;
        sum[32 + i] = (uint8_t)(v & 0xFFu);
        carry = (uint16_t)(v >> 8);
    }
    sum[31] = (uint8_t)carry;
    return noxtls_bn_mod(r, sum, 64, ed25519_p, 32);
}

static noxtls_return_t fe25519_sub(uint8_t r[32], const uint8_t a[32], const uint8_t b[32])
{
    int cmp = noxtls_bn_cmp(a, b, 32);
    if (cmp >= 0) {
        if (noxtls_bn_sub(r, a, b, 32) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        return NOXTLS_RETURN_SUCCESS;
    }

    /* r = a - b mod p = p - (b - a), with 0 < (b-a) < p */
    uint8_t diff[32];
    if (noxtls_bn_sub(diff, b, a, 32) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (noxtls_bn_sub(r, ed25519_p, diff, 32) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t fe25519_mul(uint8_t r[32], const uint8_t a[32], const uint8_t b[32])
{
    uint8_t product[64];
    if (noxtls_bn_mul(product, a, 32, b, 32) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return noxtls_bn_mod(r, product, 64, ed25519_p, 32);
}

/* Field inverse: r = a^(-1) mod p. Use extended GCD (faster than a^(p-2) for 255-bit p). */
static noxtls_return_t fe25519_inv(uint8_t r[32], const uint8_t a[32])
{
    return noxtls_bn_mod_inv(r, a, 32, (const uint8_t *)ed25519_p, 32);
}

/* 2^((p-1)/4) mod p for p = 2^255-19 (for sqrt when x^2 = -a) */
static const uint8_t ed25519_sqrt_minus1[32] = {
    0x2b, 0x83, 0x24, 0x80, 0x4f, 0xc1, 0xdf, 0x0b,
    0x2b, 0x4d, 0x00, 0x99, 0x3d, 0xfb, 0xd7, 0xa7,
    0x2f, 0x43, 0x18, 0x06, 0xad, 0x2f, 0xe4, 0x78,
    0xc4, 0xee, 0x1b, 0x27, 0x4a, 0x0e, 0xa0, 0xb0
};

/* Square root: return x such that x^2 = a (mod p). p = 5 (mod 8): x = a^((p+3)/8). */
NOXTLS_UNUSED_ATTR
static noxtls_return_t fe25519_sqrt(uint8_t r[32], const uint8_t a[32])
{
    uint8_t p38[32], x[32], x2[32];
    /* (p+3)/8 = 2^252 - 2 in BE */
    memset(p38, 0xFF, 32);
    p38[0] = 0x0F;
    p38[31] = 0xFE;
    if (noxtls_bn_mod_exp(x, a, p38, 32, ed25519_p, 32) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (noxtls_bn_mul(x2, x, 32, x, 32) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (noxtls_bn_mod(x2, x2, 64, ed25519_p, 32) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (noxtls_bn_cmp(x2, a, 32) == 0) { memcpy(r, x, 32); return NOXTLS_RETURN_SUCCESS; }
    /* x^2 = -a: then x * 2^((p-1)/4) is a square root of a */
    fe25519_mul(x2, x, (const uint8_t *)ed25519_sqrt_minus1);
    if (noxtls_bn_mod(r, x2, 64, ed25519_p, 32) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return NOXTLS_RETURN_SUCCESS;
}

/* Extended homogeneous point (X, Y, Z, T) with T = X*Y/Z. All 32-byte BE. */
typedef struct { uint8_t X[32], Y[32], Z[32], T[32]; } ge25519_pt_t;

/* Forward declaration */
static noxtls_return_t ge25519_decode(ge25519_pt_t *p, const uint8_t enc[32]);

static noxtls_return_t ge25519_set_basepoint(ge25519_pt_t *p)
{
    if(p == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    /* Canonical RFC8032 basepoint encoding -> point. */
    return ge25519_decode(p, ed25519_B_encoded);
}

static void ge25519_pt_zero(ge25519_pt_t *p)
{
    noxtls_bn_zero(p->X, 32);
    noxtls_bn_one(p->Y, 32);
    noxtls_bn_one(p->Z, 32);
    noxtls_bn_zero(p->T, 32);
}

/* Point add: (X3,Y3,Z3,T3) = (X1,Y1,Z1,T1) + (X2,Y2,Z2,T2) per RFC 8032 5.1.4 (a=-1). */
static noxtls_return_t ge25519_add(ge25519_pt_t *r, const ge25519_pt_t *p, const ge25519_pt_t *q)
{
    uint8_t z1_inv[32], z2_inv[32];
    uint8_t x1[32], y1[32], x2[32], y2[32];
    uint8_t x1y2[32], y1x2[32], y1y2[32], x1x2[32];
    uint8_t t[32], x_num[32], y_num[32], x_den[32], y_den[32];
    uint8_t x_den_inv[32], y_den_inv[32], one[32] = {0};

    one[31] = 1;
    if (fe25519_inv(z1_inv, p->Z) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe25519_inv(z2_inv, q->Z) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe25519_mul(x1, p->X, z1_inv) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe25519_mul(y1, p->Y, z1_inv) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe25519_mul(x2, q->X, z2_inv) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe25519_mul(y2, q->Y, z2_inv) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    if (fe25519_mul(x1y2, x1, y2) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe25519_mul(y1x2, y1, x2) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe25519_mul(y1y2, y1, y2) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe25519_mul(x1x2, x1, x2) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    if (fe25519_add(x_num, x1y2, y1x2) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe25519_add(y_num, y1y2, x1x2) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    if (fe25519_mul(t, x1x2, y1y2) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe25519_mul(t, t, ed25519_d) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    if (fe25519_add(x_den, one, t) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe25519_sub(y_den, one, t) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe25519_inv(x_den_inv, x_den) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe25519_inv(y_den_inv, y_den) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    if (fe25519_mul(r->X, x_num, x_den_inv) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (fe25519_mul(r->Y, y_num, y_den_inv) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    noxtls_bn_one(r->Z, 32);
    if (fe25519_mul(r->T, r->X, r->Y) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return NOXTLS_RETURN_SUCCESS;
}

/* Point double: (X3,Y3,Z3,T3) = 2*(X1,Y1,Z1,T1) per RFC 8032 5.1.4. */
static noxtls_return_t ge25519_dbl(ge25519_pt_t *r, const ge25519_pt_t *p)
{
    return ge25519_add(r, p, p);
}

/* Scalar multiplication: R = s * P, s in LE 32-byte. */
static noxtls_return_t ge25519_scalar_mult(ge25519_pt_t *R, const uint8_t s_le[32], const ge25519_pt_t *P)
{
    ge25519_pt_t N, T;
    ge25519_pt_zero(R);
    memcpy(&N, P, sizeof(ge25519_pt_t));

    /* LSB-first double-and-add over little-endian scalar. */
    for (int i = 0; i < 256; i++) {
        int bit = (s_le[i >> 3] >> (i & 7)) & 1;
        if (bit) {
            memcpy(&T, R, sizeof(ge25519_pt_t));
            if (ge25519_add(R, &T, &N) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_FAILED;
            }
        }
        memcpy(&T, &N, sizeof(ge25519_pt_t));
        if (ge25519_dbl(&N, &T) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/* Decode 32-byte LE encoding to extended point. */
static noxtls_return_t ge25519_decode(ge25519_pt_t *p, const uint8_t enc[32])
{
    uint8_t y_le[32], y_be[32], u[32], v[32], vx2[32], u_val[32];
    uint8_t x[32], uv7[32], p58_exp[32], p58_buf[32], x_cand[32];
    memcpy(y_le, enc, 32);
    y_le[31] &= 0x7F;
    le32_to_be32(y_be, y_le);
    if (noxtls_bn_cmp(y_be, ed25519_p, 32) >= 0) return NOXTLS_RETURN_FAILED;
    /* u = y^2 - 1, v = d*y^2 + 1 */
    fe25519_mul(u, y_be, y_be);
    noxtls_bn_one(u_val, 32);
    fe25519_sub(u, u, u_val);
    fe25519_mul(v, y_be, y_be);
    fe25519_mul(v, v, (const uint8_t *)ed25519_d);
    fe25519_add(v, v, u_val);
    /* x^2 = u/v => x = (u/v)^((p+3)/8). Use x = u * v^3 * (u*v^7)^((p-5)/8) */
    fe25519_mul(uv7, u, v);
    fe25519_mul(uv7, uv7, v);
    fe25519_mul(uv7, uv7, v);
    fe25519_mul(uv7, uv7, v);
    fe25519_mul(uv7, uv7, v);
    fe25519_mul(uv7, uv7, v);
    fe25519_mul(uv7, uv7, v);
    /* (p-5)/8 = 2^252 - 3 in BE */
    memset(p58_exp, 0xFF, 32);
    p58_exp[0] = 0x0F;
    p58_exp[31] = 0xFD;
    if (noxtls_bn_mod_exp(p58_buf, uv7, p58_exp, 32, ed25519_p, 32) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    fe25519_mul(x_cand, u, v);
    fe25519_mul(x_cand, x_cand, v);
    fe25519_mul(x_cand, x_cand, v);
    fe25519_mul(x_cand, x_cand, p58_buf);
    fe25519_mul(vx2, v, x_cand);
    fe25519_mul(vx2, vx2, x_cand);
    if (noxtls_bn_cmp(vx2, u, 32) == 0) {
        memcpy(x, x_cand, 32);
    } else {
        fe25519_sub(u_val, ed25519_p, u);
        if (noxtls_bn_cmp(vx2, u_val, 32) != 0) return NOXTLS_RETURN_FAILED;
        fe25519_mul(x, x_cand, (const uint8_t *)ed25519_sqrt_minus1);
        if (noxtls_bn_mod(x, x, 32, ed25519_p, 32) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    }
    if ((enc[31] >> 7) != (x[31] & 1)) {
        fe25519_sub(x, ed25519_p, x);
    }
    noxtls_bn_one(p->Z, 32);
    memcpy(p->X, x, 32);
    memcpy(p->Y, y_be, 32);
    fe25519_mul(p->T, p->X, p->Y);
    return NOXTLS_RETURN_SUCCESS;
}

/* Encode point to 32 bytes LE: y with LSB(x) in high bit of last octet. */
static noxtls_return_t ge25519_encode(uint8_t enc[32], const ge25519_pt_t *p)
{
    uint8_t zinv[32], x[32], y[32];
    if (fe25519_inv(zinv, p->Z) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    fe25519_mul(x, p->X, zinv);
    fe25519_mul(y, p->Y, zinv);
    be32_to_le32(enc, y);
    enc[31] |= (x[31] & 1) << 7;
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t ge25519_neg(ge25519_pt_t *r, const ge25519_pt_t *p)
{
    if (fe25519_sub(r->X, (const uint8_t *)ed25519_p, p->X) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    memcpy(r->Y, p->Y, 32);
    memcpy(r->Z, p->Z, 32);
    if (fe25519_sub(r->T, (const uint8_t *)ed25519_p, p->T) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return NOXTLS_RETURN_SUCCESS;
}

/* Reduce 64-byte LE integer mod L, output 32-byte LE. */
static noxtls_return_t sc25519_reduce_mod_l(uint8_t out_le[32], const uint8_t in_le[64])
{
    uint8_t in_be[64], out_be[32];
    for (int i = 0; i < 64; i++) in_be[i] = in_le[63 - i];
    if (noxtls_bn_mod(out_be, in_be, 64, ed25519_L, 32) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    be32_to_le32(out_le, out_be);
    return NOXTLS_RETURN_SUCCESS;
}

/* 32x32 -> 64 little-endian schoolbook multiply. */
static void sc25519_mul_le(uint8_t out_le[64], const uint8_t a_le[32], const uint8_t b_le[32])
{
    memset(out_le, 0, 64);
    for (int i = 0; i < 32; i++) {
        uint32_t carry = 0;
        for (int j = 0; j < 32; j++) {
            uint32_t idx = (uint32_t)i + (uint32_t)j;
            uint32_t t = (uint32_t)out_le[idx] + (uint32_t)a_le[i] * (uint32_t)b_le[j] + carry;
            out_le[idx] = (uint8_t)(t & 0xFFu);
            carry = t >> 8;
        }
        uint32_t idx = (uint32_t)i + 32u;
        while (carry != 0 && idx < 64u) {
            uint32_t t = (uint32_t)out_le[idx] + carry;
            out_le[idx] = (uint8_t)(t & 0xFFu);
            carry = t >> 8;
            idx++;
        }
    }
}

/* 32-byte LE add into 64-byte LE accumulator: out = a + b. */
static void sc25519_add_le_32_to_64(uint8_t out_le[64], const uint8_t a_le[32], const uint8_t b_le[32])
{
    memset(out_le, 0, 64);
    uint32_t carry = 0;
    for (int i = 0; i < 32; i++) {
        uint32_t t = (uint32_t)a_le[i] + (uint32_t)b_le[i] + carry;
        out_le[i] = (uint8_t)(t & 0xFFu);
        carry = t >> 8;
    }
    out_le[32] = (uint8_t)carry;
}

/* RFC 8032 dom2(phflag, ctx) for Ed25519ctx / Ed25519ph (pure Ed25519 uses empty dom2). */
static const char ed25519_dom2_literal[32] = "SigEd25519 no Ed25519 collisions";

static noxtls_return_t ed25519_sign_internal(const uint8_t private_key[32],
                                             const uint8_t *message,
                                             uint32_t message_len,
                                             uint8_t signature[64],
                                             uint8_t phflag,
                                             const uint8_t *ctx_str,
                                             uint32_t ctx_len)
{
    uint8_t h[64], prefix[32], s_le[32];
    uint8_t r_in[64], r_le[32], k_in[64], k_le[32];
    ge25519_pt_t B, R;
    noxtls_sha512_ctx_t ctx;
    uint8_t public_key[32];
    uint8_t dom_buf[32 + 1 + 1 + 255];
    uint32_t dom_len = 0;
    uint8_t ph_digest[64];
    const uint8_t *m_body = message;
    uint32_t m_len = message_len;

    if (private_key == NULL || signature == NULL) return NOXTLS_RETURN_NULL;
    if (message == NULL && message_len != 0) return NOXTLS_RETURN_NULL;
    if (phflag > 1) return NOXTLS_RETURN_INVALID_PARAM;
    if (phflag != 0 && ctx_len != 0) return NOXTLS_RETURN_INVALID_PARAM;
    if (ctx_len > NOXTLS_ED25519_CONTEXT_MAX) return NOXTLS_RETURN_INVALID_PARAM;
    if (ctx_len > 0 && ctx_str == NULL) return NOXTLS_RETURN_NULL;

    if (phflag != 0 || ctx_len > 0) {
        memcpy(dom_buf, ed25519_dom2_literal, 32);
        dom_buf[32] = phflag;
        dom_buf[33] = (uint8_t)ctx_len;
        if (ctx_len > 0) {
            memcpy(dom_buf + 34, ctx_str, ctx_len);
        }
        dom_len = 34u + ctx_len;
    }

    if (phflag != 0) {
        if (noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (message_len != 0u && noxtls_sha512_update(&ctx, message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (noxtls_sha512_finish(&ctx, ph_digest) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        m_body = ph_digest;
        m_len = 64u;
    }

    if (noxtls_ed25519_public_key(private_key, public_key) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
    if (noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_INVALID_ALGORITHM;
    if (noxtls_sha512_update(&ctx, private_key, 32) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_INVALID_ALGORITHM;
    if (noxtls_sha512_finish(&ctx, h) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_INVALID_ALGORITHM;
    h[0] &= 0xF8;
    h[31] &= 0x7F;
    h[31] |= 0x40;
    memcpy(prefix, h + 32, 32);
    memcpy(s_le, h, 32);

    if (noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_BAD_DATA;
    if (dom_len != 0u && noxtls_sha512_update(&ctx, dom_buf, dom_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_BAD_DATA;
    if (noxtls_sha512_update(&ctx, prefix, 32) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_BAD_DATA;
    if (m_len != 0u && noxtls_sha512_update(&ctx, m_body, m_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_BAD_DATA;
    if (noxtls_sha512_finish(&ctx, r_in) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_BAD_DATA;
    if (sc25519_reduce_mod_l(r_le, r_in) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_TIMEOUT;
    if (ge25519_set_basepoint(&B) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_NOT_SUPPORTED;
    if (ge25519_scalar_mult(&R, r_le, &B) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_NOT_SUPPORTED;
    if (ge25519_encode(signature, &R) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_NOT_SUPPORTED;

    if (noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    if (dom_len != 0u && noxtls_sha512_update(&ctx, dom_buf, dom_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    if (noxtls_sha512_update(&ctx, signature, 32) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    if (noxtls_sha512_update(&ctx, public_key, 32) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    if (m_len != 0u && noxtls_sha512_update(&ctx, m_body, m_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    if (noxtls_sha512_finish(&ctx, k_in) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    if (sc25519_reduce_mod_l(k_le, k_in) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;

    {
        uint8_t ks_le64[64], ks_le32[32], sum_le64[64], S_le[32];
        sc25519_mul_le(ks_le64, k_le, s_le);
        if (sc25519_reduce_mod_l(ks_le32, ks_le64) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        sc25519_add_le_32_to_64(sum_le64, r_le, ks_le32);
        if (sc25519_reduce_mod_l(S_le, sum_le64) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_NOT_ENOUGH_ENTROPY;
        memcpy(signature + 32, S_le, 32);
    }
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t ed25519_verify_internal(const uint8_t public_key[32],
                                                const uint8_t *message,
                                                uint32_t message_len,
                                                const uint8_t signature[64],
                                                uint8_t phflag,
                                                const uint8_t *ctx_str,
                                                uint32_t ctx_len)
{
    uint8_t k_in[64], k_le[32];
    ge25519_pt_t A, R, R_plus_kA, kA, sB;
    noxtls_sha512_ctx_t ctx;
    uint8_t dom_buf[32 + 1 + 1 + 255];
    uint32_t dom_len = 0;
    uint8_t ph_digest[64];
    const uint8_t *m_body = message;
    uint32_t m_len = message_len;

    if (public_key == NULL || signature == NULL) return NOXTLS_RETURN_NULL;
    if (message == NULL && message_len != 0) return NOXTLS_RETURN_NULL;
    if (phflag > 1) return NOXTLS_RETURN_INVALID_PARAM;
    if (phflag != 0 && ctx_len != 0) return NOXTLS_RETURN_INVALID_PARAM;
    if (ctx_len > NOXTLS_ED25519_CONTEXT_MAX) return NOXTLS_RETURN_INVALID_PARAM;
    if (ctx_len > 0 && ctx_str == NULL) return NOXTLS_RETURN_NULL;

    if (phflag != 0 || ctx_len > 0) {
        memcpy(dom_buf, ed25519_dom2_literal, 32);
        dom_buf[32] = phflag;
        dom_buf[33] = (uint8_t)ctx_len;
        if (ctx_len > 0) {
            memcpy(dom_buf + 34, ctx_str, ctx_len);
        }
        dom_len = 34u + ctx_len;
    }

    if (phflag != 0) {
        if (noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (message_len != 0u && noxtls_sha512_update(&ctx, message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (noxtls_sha512_finish(&ctx, ph_digest) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        m_body = ph_digest;
        m_len = 64u;
    }

    if (ge25519_decode(&A, public_key) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (ge25519_decode(&R, signature) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    {
        uint8_t S_be[32], S_le[32];
        memcpy(S_le, signature + 32, 32);
        le32_to_be32(S_be, S_le);
        if (noxtls_bn_cmp(S_be, ed25519_L, 32) >= 0) return NOXTLS_RETURN_FAILED;
    }

    if (noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (dom_len != 0u && noxtls_sha512_update(&ctx, dom_buf, dom_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (noxtls_sha512_update(&ctx, signature, 32) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (noxtls_sha512_update(&ctx, public_key, 32) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (m_len != 0u && noxtls_sha512_update(&ctx, m_body, m_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (noxtls_sha512_finish(&ctx, k_in) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (sc25519_reduce_mod_l(k_le, k_in) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    if (ge25519_scalar_mult(&kA, k_le, &A) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (ge25519_add(&R_plus_kA, &R, &kA) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (ge25519_set_basepoint(&R) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    {
        uint8_t S_le[32];
        memcpy(S_le, signature + 32, 32);
        if (ge25519_scalar_mult(&sB, S_le, &R) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    }
    {
        uint8_t enc1[32], enc2[32];
        if (ge25519_encode(enc1, &R_plus_kA) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (ge25519_encode(enc2, &sB) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (memcmp(enc1, enc2, 32) != 0) {
            uint8_t cofactor_le[32] = {0};
            ge25519_pt_t lhs8, rhs8;
            uint8_t enc_lhs8[32], enc_rhs8[32];
            cofactor_le[0] = 8;
            if (ge25519_scalar_mult(&lhs8, cofactor_le, &sB) == NOXTLS_RETURN_SUCCESS &&
                ge25519_scalar_mult(&rhs8, cofactor_le, &R_plus_kA) == NOXTLS_RETURN_SUCCESS &&
                ge25519_encode(enc_lhs8, &lhs8) == NOXTLS_RETURN_SUCCESS &&
                ge25519_encode(enc_rhs8, &rhs8) == NOXTLS_RETURN_SUCCESS &&
                memcmp(enc_lhs8, enc_rhs8, 32) == 0) {
                return NOXTLS_RETURN_SUCCESS;
            }
            return NOXTLS_RETURN_FAILED;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_ed25519_public_key(const uint8_t private_key[32], uint8_t public_key[32])
{
    uint8_t h[64], s_le[32];
    ge25519_pt_t B, A;
    noxtls_sha512_ctx_t ctx;

    if (private_key == NULL || public_key == NULL) return NOXTLS_RETURN_NULL;
    if (noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (noxtls_sha512_update(&ctx, private_key, 32) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (noxtls_sha512_finish(&ctx, h) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    h[0] &= 0xF8;
    h[31] &= 0x7F;
    h[31] |= 0x40;
    memcpy(s_le, h, 32);
    if (ge25519_set_basepoint(&B) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (ge25519_scalar_mult(&A, s_le, &B) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return ge25519_encode(public_key, &A);
}

noxtls_return_t noxtls_ed25519_sign(const uint8_t private_key[32],
                                     const uint8_t *message,
                                     uint32_t message_len,
                                     uint8_t signature[64])
{
    return ed25519_sign_internal(private_key, message, message_len, signature, 0, NULL, 0);
}

noxtls_return_t noxtls_ed25519_verify(const uint8_t public_key[32],
                                      const uint8_t *message,
                                      uint32_t message_len,
                                      const uint8_t signature[64])
{
    return ed25519_verify_internal(public_key, message, message_len, signature, 0, NULL, 0);
}

noxtls_return_t noxtls_ed25519ctx_sign(const uint8_t private_key[32],
                                       const uint8_t *context,
                                       uint32_t context_len,
                                       const uint8_t *message,
                                       uint32_t message_len,
                                       uint8_t signature[64])
{
    if (context == NULL && context_len != 0) return NOXTLS_RETURN_NULL;
    if (context_len < 1u || context_len > NOXTLS_ED25519_CONTEXT_MAX) return NOXTLS_RETURN_INVALID_PARAM;
    return ed25519_sign_internal(private_key, message, message_len, signature, 0, context, context_len);
}

noxtls_return_t noxtls_ed25519ctx_verify(const uint8_t public_key[32],
                                         const uint8_t *context,
                                         uint32_t context_len,
                                         const uint8_t *message,
                                         uint32_t message_len,
                                         const uint8_t signature[64])
{
    if (context == NULL && context_len != 0) return NOXTLS_RETURN_NULL;
    if (context_len < 1u || context_len > NOXTLS_ED25519_CONTEXT_MAX) return NOXTLS_RETURN_INVALID_PARAM;
    return ed25519_verify_internal(public_key, message, message_len, signature, 0, context, context_len);
}

noxtls_return_t noxtls_ed25519ph_sign(const uint8_t private_key[32],
                                      const uint8_t *message,
                                      uint32_t message_len,
                                      uint8_t signature[64])
{
    return ed25519_sign_internal(private_key, message, message_len, signature, 1, NULL, 0);
}

noxtls_return_t noxtls_ed25519ph_verify(const uint8_t public_key[32],
                                        const uint8_t *message,
                                        uint32_t message_len,
                                        const uint8_t signature[64])
{
    return ed25519_verify_internal(public_key, message, message_len, signature, 1, NULL, 0);
}

noxtls_return_t noxtls_ed25519_generate_key(uint8_t private_key[32], uint8_t public_key[32])
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
    rc = drbg_generate(&drbg_state, private_key, 256, NULL, 0);
    if (rc != NOXTLS_RETURN_SUCCESS) return rc;
    return noxtls_ed25519_public_key(private_key, public_key);
}
