/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_x448.c
* Summary: X448 key agreement (Curve448, RFC 7748)
*
*/

#include <stdint.h>
#include <string.h>

#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "drbg/noxtls_drbg.h"
#include "noxtls_common.h"
#include "noxtls_x448.h"
#include "pkc/rsa/noxtls_bignum.h"

#define X448_SIZE 56

/* Curve448 prime p = 2^448 - 2^224 - 1 (big-endian). */
static const uint8_t x448_p[X448_SIZE] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/* a24 = (A-2)/4 = (156326-2)/4 = 39081 = 0x98A9 (big-endian). */
static const uint8_t x448_a24_be[X448_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x98, 0xA9
};

static void le56_to_be56(uint8_t be[X448_SIZE], const uint8_t le[X448_SIZE])
{
    int i;
    for(i = 0; i < X448_SIZE; i++) {
        be[i] = le[X448_SIZE - 1 - i];
    }
}

static void be56_to_le56(uint8_t le[X448_SIZE], const uint8_t be[X448_SIZE])
{
    int i;
    for(i = 0; i < X448_SIZE; i++) {
        le[i] = be[X448_SIZE - 1 - i];
    }
}

/* Constant-time conditional swap. */
static void cswap56(uint8_t swap, uint8_t a[X448_SIZE], uint8_t b[X448_SIZE])
{
    uint8_t dummy;
    uint32_t mask = (uint32_t)(0 - (swap & 1));
    int i;
    for(i = 0; i < X448_SIZE; i++) {
        dummy = (uint8_t)(mask & (a[i] ^ b[i]));
        a[i] ^= dummy;
        b[i] ^= dummy;
    }
}

static noxtls_return_t fe448_add_be(uint8_t result[X448_SIZE], const uint8_t a[X448_SIZE], const uint8_t b[X448_SIZE])
{
    uint8_t sum[112];
    memset(sum, 0, sizeof(sum));
    if(noxtls_bn_add(sum + X448_SIZE, a, b, X448_SIZE) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return noxtls_bn_mod(result, sum, sizeof(sum), x448_p, X448_SIZE);
}

static noxtls_return_t fe448_sub_be(uint8_t result[X448_SIZE], const uint8_t a[X448_SIZE], const uint8_t b[X448_SIZE])
{
    uint8_t diff[X448_SIZE];
    if(noxtls_bn_sub(diff, a, b, X448_SIZE) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(noxtls_bn_cmp(a, b, X448_SIZE) < 0) {
        if(noxtls_bn_add(diff, diff, x448_p, X448_SIZE) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    }
    if(noxtls_bn_cmp(diff, x448_p, X448_SIZE) >= 0) {
        return noxtls_bn_mod(result, diff, X448_SIZE, x448_p, X448_SIZE);
    }
    memcpy(result, diff, X448_SIZE);
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t fe448_mul_be(uint8_t result[X448_SIZE], const uint8_t a[X448_SIZE], const uint8_t b[X448_SIZE])
{
    uint8_t product[112];
    if(noxtls_bn_mul(product, a, X448_SIZE, b, X448_SIZE) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return noxtls_bn_mod(result, product, sizeof(product), x448_p, X448_SIZE);
}

/* result = a^(-1) mod p using Fermat: a^(p-2) mod p. */
static noxtls_return_t fe448_inv_be(uint8_t result[X448_SIZE], const uint8_t a[X448_SIZE])
{
    uint8_t p_minus_2[X448_SIZE];
    uint8_t two[X448_SIZE];

    memcpy(p_minus_2, x448_p, X448_SIZE);
    memset(two, 0, X448_SIZE);
    two[X448_SIZE - 1] = 2;
    if(noxtls_bn_sub(p_minus_2, p_minus_2, two, X448_SIZE) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    return noxtls_bn_mod_exp(result, a, p_minus_2, X448_SIZE, x448_p, X448_SIZE);
}

/* X448 scalar multiplication (RFC 7748): k, u, result are 56-byte little-endian. */
static noxtls_return_t x448_scalar_mult(const uint8_t k[56], const uint8_t u[56], uint8_t result[56])
{
    uint8_t k_clamped[X448_SIZE];
    uint8_t k_be[X448_SIZE], u_be[X448_SIZE];
    uint8_t x_1[X448_SIZE], x_2[X448_SIZE], z_2[X448_SIZE], x_3[X448_SIZE], z_3[X448_SIZE];
    uint8_t A[X448_SIZE], AA[X448_SIZE], B[X448_SIZE], BB[X448_SIZE], E[X448_SIZE], C[X448_SIZE], D[X448_SIZE];
    uint8_t DA[X448_SIZE], CB[X448_SIZE], DA_plus_CB[X448_SIZE], DA_minus_CB[X448_SIZE];
    uint8_t t1[X448_SIZE], t2[X448_SIZE], z_2_inv[X448_SIZE];
    int t;

    memcpy(k_clamped, k, X448_SIZE);
    k_clamped[0] &= 252;
    k_clamped[55] |= 128;

    le56_to_be56(k_be, k_clamped);
    le56_to_be56(u_be, u);

    memcpy(x_1, u_be, X448_SIZE);
    noxtls_bn_one(x_2, X448_SIZE);
    noxtls_bn_zero(z_2, X448_SIZE);
    memcpy(x_3, u_be, X448_SIZE);
    noxtls_bn_one(z_3, X448_SIZE);

    for(t = 447; t >= 0; t--) {
        uint8_t k_t = (uint8_t)((k_be[55 - (t >> 3)] >> (t & 7)) & 1);
        cswap56(k_t, x_2, x_3);
        cswap56(k_t, z_2, z_3);

        fe448_add_be(A, x_2, z_2);
        fe448_mul_be(AA, A, A);
        fe448_sub_be(B, x_2, z_2);
        fe448_mul_be(BB, B, B);
        fe448_sub_be(E, AA, BB);
        fe448_add_be(C, x_3, z_3);
        fe448_sub_be(D, x_3, z_3);
        fe448_mul_be(DA, D, A);
        fe448_mul_be(CB, C, B);
        fe448_add_be(DA_plus_CB, DA, CB);
        fe448_sub_be(DA_minus_CB, DA, CB);
        fe448_mul_be(x_3, DA_plus_CB, DA_plus_CB);
        fe448_mul_be(t1, DA_minus_CB, DA_minus_CB);
        fe448_mul_be(z_3, x_1, t1);
        fe448_mul_be(x_2, AA, BB);
        fe448_mul_be(t2, x448_a24_be, E);
        fe448_add_be(t1, AA, t2);
        fe448_mul_be(z_2, E, t1);

        cswap56(k_t, x_2, x_3);
        cswap56(k_t, z_2, z_3);
    }

    if(fe448_inv_be(z_2_inv, z_2) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(fe448_mul_be(x_2, x_2, z_2_inv) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    be56_to_le56(result, x_2);
    return NOXTLS_RETURN_SUCCESS;
}

void noxtls_x448_clamp_scalar(uint8_t k[56])
{
    if(k == NULL) return;
    k[0] &= 252;
    k[55] |= 128;
}

noxtls_return_t noxtls_x448_public_key(const uint8_t private_key[56], uint8_t public_key[56])
{
    static const uint8_t base_point[X448_SIZE] = {
        0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    if(private_key == NULL || public_key == NULL) return NOXTLS_RETURN_NULL;
    return x448_scalar_mult(private_key, base_point, public_key);
}

noxtls_return_t noxtls_x448_shared_secret(const uint8_t private_key[56],
                                          const uint8_t peer_public_key[56],
                                          uint8_t shared_secret[56])
{
    if(private_key == NULL || peer_public_key == NULL || shared_secret == NULL) return NOXTLS_RETURN_NULL;
    return x448_scalar_mult(private_key, peer_public_key, shared_secret);
}

noxtls_return_t noxtls_x448_generate_key(uint8_t private_key[56], uint8_t public_key[56])
{
    static drbg_state_t drbg_state;
    static int drbg_initialized = 0;
    noxtls_return_t rc;

    if(private_key == NULL || public_key == NULL) return NOXTLS_RETURN_NULL;

    if(!drbg_initialized) {
        uint8_t seed[48];
        rc = drbg_get_entropy(seed, sizeof(seed));
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        rc = drbg_instantiate(&drbg_state, DRBG_AES256, seed, sizeof(seed), NULL, 0, NULL, 0);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        drbg_initialized = 1;
    }

    rc = drbg_generate(&drbg_state, private_key, 448, NULL, 0);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;

    noxtls_x448_clamp_scalar(private_key);
    return noxtls_x448_public_key(private_key, public_key);
}
