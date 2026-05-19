/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
*
* This file is part of the NoxTLS Library.
*
* File:    noxtls_x25519.c
* Summary: X25519 key agreement (Curve25519, RFC 7748)
*
*/

#include <stdint.h>
#include <string.h>

#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "drbg/noxtls_drbg.h"
#include "noxtls_common.h"
#include "noxtls_x25519.h"
#include "pkc/rsa/noxtls_bignum.h"

/* Curve25519 prime p = 2^255 - 19 (big-endian for bignum) */
static const uint8_t x25519_p[NOXTLS_X25519_FE_BYTES] = {
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xED
};

/* a24 = (A-2)/4 = (486662-2)/4 = 121665 = 0x1DB41 (for Montgomery ladder) */
static const uint8_t x25519_a24_be[NOXTLS_X25519_FE_BYTES] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xDB, 0x41
};

/**
 * @brief Converts a 255-bit field element from little-endian wire order to big-endian for bignum.
 * @param[out] be Big-endian output (`NOXTLS_X25519_FE_BYTES` bytes).
 * @param[in]  le Little-endian input (`NOXTLS_X25519_FE_BYTES` bytes).
 * @return None.
 */
static void le32_to_be32(uint8_t be[NOXTLS_X25519_FE_BYTES], const uint8_t le[NOXTLS_X25519_FE_BYTES])
{
    int i;
    for(i = 0; i < (int)NOXTLS_X25519_FE_BYTES; i++) {
        be[i] = le[(int)NOXTLS_X25519_FE_BYTES - 1 - i];
    }
}

/**
 * @brief Converts a 255-bit field element from big-endian to little-endian wire order.
 * @param[out] le Little-endian output (`NOXTLS_X25519_FE_BYTES` bytes).
 * @param[in]  be Big-endian input (`NOXTLS_X25519_FE_BYTES` bytes).
 * @return None.
 */
static void be32_to_le32(uint8_t le[NOXTLS_X25519_FE_BYTES], const uint8_t be[NOXTLS_X25519_FE_BYTES])
{
    int i;
    for(i = 0; i < (int)NOXTLS_X25519_FE_BYTES; i++) {
        le[i] = be[(int)NOXTLS_X25519_FE_BYTES - 1 - i];
    }
}

/**
 * @brief Constant-time conditional swap of two field buffers (Montgomery ladder).
 * @param[in]     swap When LSB is set, swap @p a and @p b; otherwise leave unchanged.
 * @param[in,out] a First buffer (`NOXTLS_X25519_FE_BYTES` bytes).
 * @param[in,out] b Second buffer (`NOXTLS_X25519_FE_BYTES` bytes).
 * @return None.
 */
static void cswap(uint8_t swap, uint8_t a[NOXTLS_X25519_FE_BYTES], uint8_t b[NOXTLS_X25519_FE_BYTES])
{
    uint32_t mask = (uint32_t)(0 - (swap & 1));
    int i;
    for(i = 0; i < (int)NOXTLS_X25519_FE_BYTES; i++) {
        uint8_t dummy = (uint8_t)(mask & (a[i] ^ b[i]));
        a[i] ^= dummy;
        b[i] ^= dummy;
    }
}

/**
 * @brief Field addition in GF(p), p = Curve25519 prime; operands and result are big-endian.
 * @param[out] result Sum (a + b) mod p (`NOXTLS_X25519_FE_BYTES` bytes).
 * @param[in]  a First operand (`NOXTLS_X25519_FE_BYTES` bytes).
 * @param[in]  b Second operand (`NOXTLS_X25519_FE_BYTES` bytes).
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
static noxtls_return_t fe25519_add_be(uint8_t result[NOXTLS_X25519_FE_BYTES],
                                      const uint8_t a[NOXTLS_X25519_FE_BYTES],
                                      const uint8_t b[NOXTLS_X25519_FE_BYTES])
{
    uint8_t sum[NOXTLS_X25519_BN_SUM_BYTES];
    memset(sum, 0, sizeof(sum));
    if(noxtls_bn_add(sum + NOXTLS_X25519_FE_BYTES, a, b, NOXTLS_X25519_FE_BYTES) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    return noxtls_bn_mod(result, sum, NOXTLS_X25519_BN_PRODUCT_BYTES, x25519_p, NOXTLS_X25519_FE_BYTES);
}

/**
 * @brief Field subtraction in GF(p): result = (a - b) mod p (big-endian limbs).
 * @param[out] result Difference mod p (`NOXTLS_X25519_FE_BYTES` bytes).
 * @param[in]  a Minuend (`NOXTLS_X25519_FE_BYTES` bytes).
 * @param[in]  b Subtrahend (`NOXTLS_X25519_FE_BYTES` bytes).
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
static noxtls_return_t fe25519_sub_be(uint8_t result[NOXTLS_X25519_FE_BYTES],
                                      const uint8_t a[NOXTLS_X25519_FE_BYTES],
                                      const uint8_t b[NOXTLS_X25519_FE_BYTES])
{
    uint8_t diff[NOXTLS_X25519_FE_BYTES];
    if(noxtls_bn_sub(diff, a, b, NOXTLS_X25519_FE_BYTES) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(noxtls_bn_cmp(a, b, NOXTLS_X25519_FE_BYTES) < 0) {
        if(noxtls_bn_add(diff, diff, x25519_p, NOXTLS_X25519_FE_BYTES) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    if(noxtls_bn_cmp(diff, x25519_p, NOXTLS_X25519_FE_BYTES) >= 0) {
        return noxtls_bn_mod(result, diff, NOXTLS_X25519_FE_BYTES, x25519_p, NOXTLS_X25519_FE_BYTES);
    }
    memcpy(result, diff, NOXTLS_X25519_FE_BYTES);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Field multiplication in GF(p): result = (a * b) mod p (big-endian limbs).
 * @param[out] result Product mod p (`NOXTLS_X25519_FE_BYTES` bytes).
 * @param[in]  a First factor (`NOXTLS_X25519_FE_BYTES` bytes).
 * @param[in]  b Second factor (`NOXTLS_X25519_FE_BYTES` bytes).
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
static noxtls_return_t fe25519_mul_be(uint8_t result[NOXTLS_X25519_FE_BYTES],
                                      const uint8_t a[NOXTLS_X25519_FE_BYTES],
                                      const uint8_t b[NOXTLS_X25519_FE_BYTES])
{
    uint8_t product[NOXTLS_X25519_BN_PRODUCT_BYTES];
    if(noxtls_bn_mul(product, a, NOXTLS_X25519_FE_BYTES, b, NOXTLS_X25519_FE_BYTES) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    return noxtls_bn_mod(result, product, NOXTLS_X25519_BN_PRODUCT_BYTES, x25519_p, NOXTLS_X25519_FE_BYTES);
}

/**
 * @brief Multiplicative inverse in GF(p) via Fermat: result = a^(p-2) mod p (big-endian).
 * @param[out] result Inverse of @p a mod p (`NOXTLS_X25519_FE_BYTES` bytes).
 * @param[in]  a Non-zero field element (`NOXTLS_X25519_FE_BYTES` bytes).
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
static noxtls_return_t fe25519_inv_be(uint8_t result[NOXTLS_X25519_FE_BYTES], const uint8_t a[NOXTLS_X25519_FE_BYTES])
{
    uint8_t p_minus_2[NOXTLS_X25519_FE_BYTES];
    uint8_t two[NOXTLS_X25519_FE_BYTES];

    memcpy(p_minus_2, x25519_p, NOXTLS_X25519_FE_BYTES);
    memset(two, 0, NOXTLS_X25519_FE_BYTES);
    two[NOXTLS_X25519_FE_BYTES - 1U] = 2;
    if(noxtls_bn_sub(p_minus_2, p_minus_2, two, NOXTLS_X25519_FE_BYTES) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    return noxtls_bn_mod_exp(result, a, p_minus_2, NOXTLS_X25519_FE_BYTES, x25519_p, NOXTLS_X25519_FE_BYTES);
}

/**
 * @brief X25519 scalar multiplication (RFC 7748, Montgomery ladder).
 * @param[in]  k Little-endian scalar (`NOXTLS_X25519_KEY_SIZE` bytes).
 * @param[in]  u Little-endian u-coordinate of input point.
 * @param[out] result Little-endian u-coordinate of k*P.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t x25519_scalar_mult(const uint8_t k[NOXTLS_X25519_KEY_SIZE],
                                          const uint8_t u[NOXTLS_X25519_KEY_SIZE],
                                          uint8_t result[NOXTLS_X25519_KEY_SIZE])
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint8_t k_clamped[NOXTLS_X25519_KEY_SIZE];
    uint8_t k_be[NOXTLS_X25519_FE_BYTES];
    uint8_t u_be[NOXTLS_X25519_FE_BYTES];
    uint8_t x_1[NOXTLS_X25519_FE_BYTES];
    uint8_t x_2[NOXTLS_X25519_FE_BYTES];
    uint8_t z_2[NOXTLS_X25519_FE_BYTES];
    uint8_t x_3[NOXTLS_X25519_FE_BYTES];
    uint8_t z_3[NOXTLS_X25519_FE_BYTES];
    uint8_t A[NOXTLS_X25519_FE_BYTES];
    uint8_t AA[NOXTLS_X25519_FE_BYTES];
    uint8_t B[NOXTLS_X25519_FE_BYTES];
    uint8_t BB[NOXTLS_X25519_FE_BYTES];
    uint8_t E[NOXTLS_X25519_FE_BYTES];
    uint8_t C[NOXTLS_X25519_FE_BYTES];
    uint8_t D[NOXTLS_X25519_FE_BYTES];
    uint8_t DA[NOXTLS_X25519_FE_BYTES];
    uint8_t CB[NOXTLS_X25519_FE_BYTES];
    uint8_t DA_plus_CB[NOXTLS_X25519_FE_BYTES];
    uint8_t DA_minus_CB[NOXTLS_X25519_FE_BYTES];
    uint8_t t1[NOXTLS_X25519_FE_BYTES];
    uint8_t t2[NOXTLS_X25519_FE_BYTES];
    uint8_t z_2_inv[NOXTLS_X25519_FE_BYTES];
    int t;

    memcpy(k_clamped, k, NOXTLS_X25519_KEY_SIZE);
    k_clamped[0] &= (uint8_t)NOXTLS_X25519_CLAMP_BYTE0_MASK;
    k_clamped[NOXTLS_X25519_FE_BYTES - 1U] &= (uint8_t)NOXTLS_X25519_CLAMP_BYTE31_AND;
    k_clamped[NOXTLS_X25519_FE_BYTES - 1U] |= (uint8_t)NOXTLS_X25519_CLAMP_BYTE31_OR;

    le32_to_be32(k_be, k_clamped);
    le32_to_be32(u_be, u);

    u_be[0] &= (uint8_t)NOXTLS_X25519_U_COORD_HIGH_CLEAR;

    memcpy(x_1, u_be, NOXTLS_X25519_FE_BYTES);
    noxtls_bn_one(x_2, NOXTLS_X25519_FE_BYTES);
    noxtls_bn_zero(z_2, NOXTLS_X25519_FE_BYTES);
    memcpy(x_3, u_be, NOXTLS_X25519_FE_BYTES);
    noxtls_bn_one(z_3, NOXTLS_X25519_FE_BYTES);

    for(t = (int)NOXTLS_X25519_SCALAR_LOOP_TOP; t >= 0; t--) {
        uint8_t k_t = (uint8_t)((k_be[(int)NOXTLS_X25519_FE_BYTES - 1 - (t >> 3)] >> (t & 7)) & 1);
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
    result[NOXTLS_X25519_FE_BYTES - 1U] &= (uint8_t)NOXTLS_X25519_RESULT_HIGH_CLEAR;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Applies RFC 7748 clamping to a 32-byte X25519 scalar in place.
 * @param[in,out] k Little-endian scalar (`NOXTLS_X25519_KEY_SIZE` bytes); no-op if NULL.
 * @return None.
 */
void noxtls_x25519_clamp_scalar(uint8_t k[NOXTLS_X25519_KEY_SIZE])
{
    if(k == NULL) {
        return;
    }
    k[0] &= (uint8_t)NOXTLS_X25519_CLAMP_BYTE0_MASK;
    k[NOXTLS_X25519_FE_BYTES - 1U] &= (uint8_t)NOXTLS_X25519_CLAMP_BYTE31_AND;
    k[NOXTLS_X25519_FE_BYTES - 1U] |= (uint8_t)NOXTLS_X25519_CLAMP_BYTE31_OR;
}

/**
 * @brief Derives the X25519 public key from a private key (RFC 7748, base u = 9).
 * @param[in]  private_key 32-byte little-endian private key.
 * @param[out] public_key 32-byte little-endian public u-coordinate.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_x25519_public_key(const uint8_t private_key[NOXTLS_X25519_KEY_SIZE],
                                         uint8_t public_key[NOXTLS_X25519_KEY_SIZE])
{
    static const uint8_t base_point[NOXTLS_X25519_KEY_SIZE] = {
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    if(private_key == NULL || public_key == NULL) return NOXTLS_RETURN_NULL;
    return x25519_scalar_mult(private_key, base_point, public_key);
}

/**
 * @brief Computes X25519 shared secret from own private key and peer public key (RFC 7748).
 * @param[in]  private_key 32-byte little-endian private key.
 * @param[in]  peer_public_key 32-byte little-endian peer public u-coordinate.
 * @param[out] shared_secret 32-byte little-endian shared secret output.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_x25519_shared_secret(const uint8_t private_key[NOXTLS_X25519_KEY_SIZE],
                                            const uint8_t peer_public_key[NOXTLS_X25519_KEY_SIZE],
                                            uint8_t shared_secret[NOXTLS_X25519_KEY_SIZE])
{
    if(private_key == NULL || peer_public_key == NULL || shared_secret == NULL) return NOXTLS_RETURN_NULL;
    return x25519_scalar_mult(private_key, peer_public_key, shared_secret);
}

/**
 * @brief Generates a random X25519 key pair using the library DRBG (RFC 7748).
 * @param[out] private_key 32-byte little-endian private key (clamped internally).
 * @param[out] public_key 32-byte little-endian public key.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_x25519_generate_key(uint8_t private_key[NOXTLS_X25519_KEY_SIZE],
                                           uint8_t public_key[NOXTLS_X25519_KEY_SIZE])
{
    static drbg_state_t drbg_state;
    static int drbg_initialized = 0;
    noxtls_return_t rc;

    if(private_key == NULL || public_key == NULL) return NOXTLS_RETURN_NULL;

    if(!drbg_initialized) {
        uint8_t seed[NOXTLS_X25519_DRBG_ENTROPY_SEED_BYTES];
        rc = noxtls_drbg_get_entropy(seed, sizeof(seed));
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        rc = drbg_instantiate(&drbg_state, DRBG_AES256, seed, sizeof(seed), NULL, 0, NULL, 0);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        drbg_initialized = 1;
    }

    rc = drbg_generate(&drbg_state, private_key, NOXTLS_X25519_DRBG_SEED_BITS, NULL, 0);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;

    noxtls_x25519_clamp_scalar(private_key);
    return noxtls_x25519_public_key(private_key, public_key);
}
