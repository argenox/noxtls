/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
*
* File:    noxtls_x25519.c
* Summary: X25519 key agreement (Curve25519, RFC 7748)
*
*/

#include <stdint.h>
#include <string.h>
#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "noxtls_x25519.h"
#include "noxtls_common.h"
#include "drbg/noxtls_drbg.h"
#include "pkc/rsa/noxtls_bignum.h"

#define X25519_SIZE  32

/* Curve25519 prime p = 2^255 - 19 (big-endian for bignum) */
static const uint8_t x25519_p[X25519_SIZE] = {
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xED
};

/* a24 = (A-2)/4 = (486662-2)/4 = 121665 = 0x1DB41 (for Montgomery ladder) */
static const uint8_t x25519_a24_be[X25519_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xDB, 0x41
};

static void le32_to_be32(uint8_t be[32], const uint8_t le[32])
{
    for (int i = 0; i < 32; i++) {
        be[i] = le[31 - i];
    }
}

static void be32_to_le32(uint8_t le[32], const uint8_t be[32])
{
    for (int i = 0; i < 32; i++) {
        le[i] = be[31 - i];
    }
}

/* Constant-time conditional swap: if swap != 0, swap (a,b); else leave as is. */
static void cswap(uint8_t swap, uint8_t a[32], uint8_t b[32])
{
    uint8_t dummy;
    uint32_t mask = (uint32_t)(0 - (swap & 1));
    for (int i = 0; i < 32; i++) {
        dummy = (uint8_t)(mask & (a[i] ^ b[i]));
        a[i] ^= dummy;
        b[i] ^= dummy;
    }
}

/* Field op: result = (a + b) mod p. a, b, result in BE 32-byte. */
static noxtls_return_t fe25519_add_be(uint8_t result[32], const uint8_t a[32], const uint8_t b[32])
{
    uint8_t sum[64];
    memset(sum, 0, 64);
    if (noxtls_bn_add(sum + 32, a, b, 32) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return noxtls_bn_mod(result, sum, 64, x25519_p, 32);
}

/* Field op: result = (a - b) mod p. */
static noxtls_return_t fe25519_sub_be(uint8_t result[32], const uint8_t a[32], const uint8_t b[32])
{
    uint8_t diff[32];
    if (noxtls_bn_sub(diff, a, b, 32) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if (noxtls_bn_cmp(a, b, 32) < 0) {
        if (noxtls_bn_add(diff, diff, x25519_p, 32) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    }
    if (noxtls_bn_cmp(diff, x25519_p, 32) >= 0) {
        return noxtls_bn_mod(result, diff, 32, x25519_p, 32);
    }
    memcpy(result, diff, 32);
    return NOXTLS_RETURN_SUCCESS;
}

/* Field op: result = (a * b) mod p. */
static noxtls_return_t fe25519_mul_be(uint8_t result[32], const uint8_t a[32], const uint8_t b[32])
{
    uint8_t product[64];
    if (noxtls_bn_mul(product, a, 32, b, 32) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return noxtls_bn_mod(result, product, 64, x25519_p, 32);
}

/* result = a^(-1) mod p via Fermat: a^(p-2) mod p. */
static noxtls_return_t fe25519_inv_be(uint8_t result[32], const uint8_t a[32])
{
    uint8_t p_minus_2[32];
    memcpy(p_minus_2, x25519_p, 32);
    uint8_t two[32] = {0};
    two[31] = 2;
    if (noxtls_bn_sub(p_minus_2, p_minus_2, two, 32) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return noxtls_bn_mod_exp(result, a, p_minus_2, 32, x25519_p, 32);
}

/**
 * X25519 scalar multiplication (RFC 7748).
 * k, u, result are 32-byte little-endian.
 * result = u-coordinate of k*P where P has u-coordinate u.
 */
static noxtls_return_t x25519_scalar_mult(const uint8_t k[32], const uint8_t u[32], uint8_t result[32])
{
    uint8_t k_clamped[32];
    uint8_t k_be[32], u_be[32];
    uint8_t x_1[32], x_2[32], z_2[32], x_3[32], z_3[32];
    uint8_t A[32], AA[32], B[32], BB[32], E[32], C[32], D[32], DA[32], CB[32];
    uint8_t DA_plus_CB[32], DA_minus_CB[32], t1[32], t2[32];
    uint8_t z_2_inv[32];

    /* RFC 7748: decode scalar (clamp) before use so ladder sees 255-bit decoded scalar */
    memcpy(k_clamped, k, 32);
    k_clamped[0] &= 248;
    k_clamped[31] &= 127;
    k_clamped[31] |= 64;

    le32_to_be32(k_be, k_clamped);
    le32_to_be32(u_be, u);

    /* Mask high bit of u (RFC 7748: "final byte" = high byte in LE = u_be[0] in BE) */
    u_be[0] &= 0x7F;

    memcpy(x_1, u_be, 32);
    noxtls_bn_one(x_2, 32);
    noxtls_bn_zero(z_2, 32);
    memcpy(x_3, u_be, 32);
    noxtls_bn_one(z_3, 32);

    /* RFC 7748: "For t = bits-1 down to 0" with bits=255 for X25519 */
    for (int t = 254; t >= 0; t--) {
        uint8_t k_t = (uint8_t)((k_be[31 - (t >> 3)] >> (t & 7)) & 1);
        cswap(k_t, x_2, x_3);
        cswap(k_t, z_2, z_3);

        fe25519_add_be(A, x_2, z_2);
        fe25519_mul_be(AA, A, A);
        fe25519_sub_be(B, x_2, z_2);
        fe25519_mul_be(BB, B, B);
        fe25519_sub_be(E, AA, BB);
        fe25519_add_be(C, x_3, z_3);
        fe25519_sub_be(D, x_3, z_3);
        fe25519_mul_be(DA, D, A);
        fe25519_mul_be(CB, C, B);
        fe25519_add_be(DA_plus_CB, DA, CB);
        fe25519_sub_be(DA_minus_CB, DA, CB);
        fe25519_mul_be(x_3, DA_plus_CB, DA_plus_CB);
        fe25519_mul_be(t1, DA_minus_CB, DA_minus_CB);
        fe25519_mul_be(z_3, x_1, t1);
        fe25519_mul_be(x_2, AA, BB);
        fe25519_mul_be(t2, x25519_a24_be, E);
        fe25519_add_be(t1, AA, t2);
        fe25519_mul_be(z_2, E, t1);

        cswap(k_t, x_2, x_3);
        cswap(k_t, z_2, z_3);
    }

    fe25519_inv_be(z_2_inv, z_2);
    fe25519_mul_be(x_2, x_2, z_2_inv);
    be32_to_le32(result, x_2);
    result[31] &= 0x7F;
    return NOXTLS_RETURN_SUCCESS;
}

void noxtls_x25519_clamp_scalar(uint8_t k[32])
{
    if (k == NULL) return;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
}

noxtls_return_t noxtls_x25519_public_key(const uint8_t private_key[32], uint8_t public_key[32])
{
    static const uint8_t base_point[32] = { 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    if (private_key == NULL || public_key == NULL) return NOXTLS_RETURN_NULL;
    return x25519_scalar_mult(private_key, base_point, public_key);
}

noxtls_return_t noxtls_x25519_shared_secret(const uint8_t private_key[32],
                                            const uint8_t peer_public_key[32],
                                            uint8_t shared_secret[32])
{
    if (private_key == NULL || peer_public_key == NULL || shared_secret == NULL) return NOXTLS_RETURN_NULL;
    return x25519_scalar_mult(private_key, peer_public_key, shared_secret);
}

noxtls_return_t noxtls_x25519_generate_key(uint8_t private_key[32], uint8_t public_key[32])
{
    static drbg_state_t drbg_state;
    static int drbg_initialized = 0;
    noxtls_return_t rc;

    if (private_key == NULL || public_key == NULL) return NOXTLS_RETURN_NULL;

    if (!drbg_initialized) {
        uint8_t seed[48];
        rc = drbg_get_entropy(seed, sizeof(seed));
        if (rc != NOXTLS_RETURN_SUCCESS) return rc;
        rc = drbg_instantiate(&drbg_state, DRBG_AES256, seed, sizeof(seed), NULL, 0, NULL, 0);
        if (rc != NOXTLS_RETURN_SUCCESS) return rc;
        drbg_initialized = 1;
    }

    rc = drbg_generate(&drbg_state, private_key, 256, NULL, 0);
    if (rc != NOXTLS_RETURN_SUCCESS) return rc;

    noxtls_x25519_clamp_scalar(private_key);
    return noxtls_x25519_public_key(private_key, public_key);
}
