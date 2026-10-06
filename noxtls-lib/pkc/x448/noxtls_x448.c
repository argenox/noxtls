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
#include "drbg/noxtls_drbg.h"
#include "noxtls_common.h"
#include "noxtls_x448.h"
#include "pkc/rsa/noxtls_bignum.h"
#include "common/noxtls_ct.h"



/* Curve448 prime p = 2^448 - 2^224 - 1 (big-endian). */
static const uint8_t x448_p[NOXTLS_X448_FE_BYTES] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFEU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU
};

/**
 * @brief Converts a 448-bit field element from little-endian wire order to big-endian for bignum.
 * @param[out] be Big-endian output (`NOXTLS_X448_FE_BYTES` bytes).
 * @param[in]  le Little-endian input (`NOXTLS_X448_FE_BYTES` bytes).
 * @return None.
 */
/* Fixed-size field element endian convert. */
static void le56_to_be56(uint8_t *be, const uint8_t *le)
{
    uint32_t i = 0U;
    const uint32_t n = (uint32_t)NOXTLS_X448_FE_BYTES;
    for (i = 0U; i < n; i += 1U) {
        be[i] = le[(n - 1U) - i];
    }
}

/**
 * @brief Converts a 448-bit field element from big-endian to little-endian wire order.
 * @param[out] le Little-endian output (`NOXTLS_X448_FE_BYTES` bytes).
 * @param[in]  be Big-endian input (`NOXTLS_X448_FE_BYTES` bytes).
 * @return None.
 */
static void be56_to_le56(uint8_t *le, const uint8_t *be)
{
    uint32_t i = 0U;
    const uint32_t n = (uint32_t)NOXTLS_X448_FE_BYTES;
    for (i = 0U; i < n; i += 1U) {
        le[i] = be[(n - 1U) - i];
    }
}

/**
 * @brief Constant-time conditional swap of two field buffers (Montgomery ladder).
 * @param[in]     swap When LSB is set, swap @p a and @p b; otherwise leave unchanged.
 * @param[in,out] a First buffer (`NOXTLS_X448_FE_BYTES` bytes).
 * @param[in,out] b Second buffer (`NOXTLS_X448_FE_BYTES` bytes).
 * @return None.
 */
static void cswap56(uint8_t swap, uint8_t *a, uint8_t *b)
{
    uint32_t swap_u = (uint32_t)swap;
    uint32_t swap_bit = swap_u & 1U;
    uint32_t mask = 0U - swap_bit;
    uint32_t i = 0U;
    const uint32_t n = (uint32_t)NOXTLS_X448_FE_BYTES;
    for (i = 0U; i < n; i += 1U) {
        uint32_t ai = (uint32_t)a[i];
        uint32_t bi = (uint32_t)b[i];
        uint32_t xored = ai ^ bi;
        uint32_t d = mask & xored;
        uint8_t dummy = (uint8_t)d;
        a[i] ^= dummy;
        b[i] ^= dummy;
    }
}

/**
 * @brief Field addition in GF(p), p = Curve448 prime; operands and result are big-endian.
 * @param[out] result Sum (a + b) mod p (`NOXTLS_X448_FE_BYTES` bytes).
 * @param[in]  a First operand (`NOXTLS_X448_FE_BYTES` bytes).
 * @param[in]  b Second operand (`NOXTLS_X448_FE_BYTES` bytes).
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
static noxtls_return_t fe448_add_be(uint8_t *result,
                                      const uint8_t *a,
                                      const uint8_t *b)
{
    uint8_t sum[NOXTLS_X448_BN_SUM_BYTES];
    uint8_t low[NOXTLS_X448_FE_BYTES];
    noxtls_secure_zero((sum), sizeof(sum));
    if (noxtls_bn_add(low, a, b, NOXTLS_X448_FE_BYTES) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_copy_u8(&sum[NOXTLS_X448_FE_BYTES], (size_t)NOXTLS_X448_FE_BYTES, low, (size_t)NOXTLS_X448_FE_BYTES);
    /*
     * noxtls_bn_add() returns only the low limb and drops the carry-out.
     * For 448-bit field addition we must preserve that carry into bit 448
     * before modular reduction.
     */
    if (noxtls_bn_cmp(low, a, NOXTLS_X448_FE_BYTES) < 0) {
        sum[NOXTLS_X448_FE_BYTES - 1U] = 1U;
    }
    return noxtls_bn_mod(result, sum, NOXTLS_X448_BN_PRODUCT_BYTES, x448_p, NOXTLS_X448_FE_BYTES);
}

/**
 * @brief Field subtraction in GF(p): r = (a - b) mod p (big-endian limbs).
 * @param[out] result Difference mod p (`NOXTLS_X448_FE_BYTES` bytes).
 * @param[in]  a Minuend (`NOXTLS_X448_FE_BYTES` bytes).
 * @param[in]  b Subtrahend (`NOXTLS_X448_FE_BYTES` bytes).
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
static noxtls_return_t fe448_sub_be(uint8_t *result,
                                     const uint8_t *a,
                                     const uint8_t *b)
{
    uint8_t diff[NOXTLS_X448_FE_BYTES];
    if (noxtls_bn_sub(diff, a, b, NOXTLS_X448_FE_BYTES) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if (noxtls_bn_cmp(a, b, NOXTLS_X448_FE_BYTES) < 0) {
        if (noxtls_bn_add(diff, diff, x448_p, NOXTLS_X448_FE_BYTES) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    if (noxtls_bn_cmp(diff, x448_p, NOXTLS_X448_FE_BYTES) >= 0) { return noxtls_bn_mod(result, diff, NOXTLS_X448_FE_BYTES, x448_p, NOXTLS_X448_FE_BYTES); }
    noxtls_copy_u8(result, (size_t)NOXTLS_X448_FE_BYTES, diff, (size_t)NOXTLS_X448_FE_BYTES);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Field multiplication in GF(p): r = (a * b) mod p (big-endian limbs).
 * @param[out] result Product mod p (`NOXTLS_X448_FE_BYTES` bytes).
 * @param[in]  a First factor (`NOXTLS_X448_FE_BYTES` bytes).
 * @param[in]  b Second factor (`NOXTLS_X448_FE_BYTES` bytes).
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
static noxtls_return_t fe448_mul_be(uint8_t *result,
                                    const uint8_t *a,
                                    const uint8_t *b)
{
    uint8_t product[NOXTLS_X448_BN_PRODUCT_BYTES];
    noxtls_return_t rc = noxtls_bn_mul(product, a, NOXTLS_X448_FE_BYTES,
                                       b, NOXTLS_X448_FE_BYTES);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return noxtls_bn_mod(result, product, NOXTLS_X448_BN_PRODUCT_BYTES, x448_p, NOXTLS_X448_FE_BYTES);
}

/**
 * @brief Multiplicative inverse in GF(p) via Fermat: r = a^(p-2) mod p (big-endian).
 * @param[out] result Inverse of @p a mod p (`NOXTLS_X448_FE_BYTES` bytes).
 * @param[in]  a Non-zero field element (`NOXTLS_X448_FE_BYTES` bytes).
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
static noxtls_return_t fe448_inv_be(uint8_t *result, const uint8_t *a)
{
    uint8_t p_minus_2[NOXTLS_X448_FE_BYTES];
    uint8_t two[NOXTLS_X448_FE_BYTES];

    noxtls_copy_u8(p_minus_2, sizeof(p_minus_2), x448_p, (size_t)NOXTLS_X448_FE_BYTES);
    noxtls_secure_zero((two), (size_t)(NOXTLS_X448_FE_BYTES));
    two[NOXTLS_X448_FE_BYTES - 1U] = 2U;
    if (noxtls_bn_sub(p_minus_2, p_minus_2, two, NOXTLS_X448_FE_BYTES) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    return noxtls_bn_mod_exp(result, a, p_minus_2, NOXTLS_X448_FE_BYTES, x448_p, NOXTLS_X448_FE_BYTES);
}

/**
 * @brief X448 scalar multiplication (RFC 7748).
 * @param k Little-endian scalar (`NOXTLS_X448_KEY_SIZE` bytes).
 * @param u Little-endian u-coordinate of input point.
 * @param result Little-endian u-coordinate of k*P.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
/* Montgomery ladder: intermediate field-op RCs historically unchecked for CT; accept 17.7. */
static noxtls_return_t x448_scalar_mult_core(const uint8_t *k,
                                             const uint8_t *u,
                                             uint8_t *result)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    static const uint8_t x448_s_bit8[8] = {
    0x01U, 0x02U, 0x04U, 0x08U, 0x10U, 0x20U, 0x40U, 0x80U
};

    /* X448 a24 (Rule 8.9). */
    /* a24 = (A-2)/4 = (156326-2)/4 = 39081 = 0x98A9U (big-endian). */
    static const uint8_t x448_a24_be[NOXTLS_X448_FE_BYTES] = {
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x98U, 0xA9U
    };


    uint8_t k_clamped[NOXTLS_X448_KEY_SIZE];
    uint8_t k_be[NOXTLS_X448_FE_BYTES];
    uint8_t u_be[NOXTLS_X448_FE_BYTES];
    uint8_t x_1[NOXTLS_X448_FE_BYTES];
    uint8_t x_2[NOXTLS_X448_FE_BYTES];
    uint8_t z_2[NOXTLS_X448_FE_BYTES];
    uint8_t x_3[NOXTLS_X448_FE_BYTES];
    uint8_t z_3[NOXTLS_X448_FE_BYTES];
    uint8_t A[NOXTLS_X448_FE_BYTES];
    uint8_t AA[NOXTLS_X448_FE_BYTES];
    uint8_t B[NOXTLS_X448_FE_BYTES];
    uint8_t BB[NOXTLS_X448_FE_BYTES];
    uint8_t E[NOXTLS_X448_FE_BYTES];
    uint8_t C[NOXTLS_X448_FE_BYTES];
    uint8_t D[NOXTLS_X448_FE_BYTES];
    uint8_t DA[NOXTLS_X448_FE_BYTES];
    uint8_t CB[NOXTLS_X448_FE_BYTES];
    uint8_t DA_plus_CB[NOXTLS_X448_FE_BYTES];
    uint8_t DA_minus_CB[NOXTLS_X448_FE_BYTES];
    uint8_t t1[NOXTLS_X448_FE_BYTES];
    uint8_t t2[NOXTLS_X448_FE_BYTES];
    uint8_t z_2_inv[NOXTLS_X448_FE_BYTES];
    noxtls_return_t rc;
    int32_t t = 0;

#define X448_TRY(operation) do { \
        rc = (operation); \
        if(rc != NOXTLS_RETURN_SUCCESS) { return rc; } \
    } while(0 == 1)

    noxtls_copy_u8(k_clamped, sizeof(k_clamped), k, NOXTLS_X448_KEY_SIZE);
    k_clamped[0] &= (uint8_t)NOXTLS_X448_CLAMP_BYTE0_MASK;
    k_clamped[NOXTLS_X448_FE_BYTES - 1U] |= (uint8_t)NOXTLS_X448_CLAMP_HIGH_OR;

    le56_to_be56(k_be, k_clamped);
    le56_to_be56(u_be, u);

    noxtls_copy_u8(x_1, sizeof(x_1), u_be, (size_t)NOXTLS_X448_FE_BYTES);
    (void)noxtls_bn_one(x_2, NOXTLS_X448_FE_BYTES);
    (void)noxtls_bn_zero(z_2, NOXTLS_X448_FE_BYTES);
    noxtls_copy_u8(x_3, sizeof(x_3), u_be, (size_t)NOXTLS_X448_FE_BYTES);
    (void)noxtls_bn_one(z_3, NOXTLS_X448_FE_BYTES);

    for (t = (int32_t)NOXTLS_X448_SCALAR_LOOP_TOP; t >= 0; t -= 1) {
        /* Bit extract from BE scalar: index/shift within fixed FE bytes. */
        const uint32_t bit = (uint32_t)t;
        const uint32_t byte_ix = ((uint32_t)NOXTLS_X448_FE_BYTES - 1U) - (bit >> 3U);
        uint8_t k_t = ((k_be[byte_ix] & x448_s_bit8[bit & 7U]) != 0U) ? 1U : 0U;
        cswap56(k_t, x_2, x_3);
        cswap56(k_t, z_2, z_3);

        X448_TRY(fe448_add_be(A, x_2, z_2));
        X448_TRY(fe448_mul_be(AA, A, A));
        X448_TRY(fe448_sub_be(B, x_2, z_2));
        X448_TRY(fe448_mul_be(BB, B, B));
        X448_TRY(fe448_sub_be(E, AA, BB));
        X448_TRY(fe448_add_be(C, x_3, z_3));
        X448_TRY(fe448_sub_be(D, x_3, z_3));
        X448_TRY(fe448_mul_be(DA, D, A));
        X448_TRY(fe448_mul_be(CB, C, B));
        X448_TRY(fe448_add_be(DA_plus_CB, DA, CB));
        X448_TRY(fe448_sub_be(DA_minus_CB, DA, CB));
        X448_TRY(fe448_mul_be(x_3, DA_plus_CB, DA_plus_CB));
        X448_TRY(fe448_mul_be(t1, DA_minus_CB, DA_minus_CB));
        X448_TRY(fe448_mul_be(z_3, x_1, t1));
        X448_TRY(fe448_mul_be(x_2, AA, BB));
        X448_TRY(fe448_mul_be(t2, x448_a24_be, E));
        X448_TRY(fe448_add_be(t1, AA, t2));
        X448_TRY(fe448_mul_be(z_2, E, t1));

        cswap56(k_t, x_2, x_3);
        cswap56(k_t, z_2, z_3);
    }

    X448_TRY(fe448_inv_be(z_2_inv, z_2));
    X448_TRY(fe448_mul_be(x_2, x_2, z_2_inv));
    be56_to_le56(result, x_2);
#undef X448_TRY
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief X448 scalar multiplication with a fail-closed output.
 * @param k Little-endian scalar (`NOXTLS_X448_KEY_SIZE` bytes).
 * @param u Little-endian u-coordinate of input point.
 * @param result Little-endian u-coordinate of k*P; wiped when the ladder fails
 *        (e.g. a bignum allocation failure), so a stale or partial value is
 *        never left behind next to an error.
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
    static drbg_state_t drbg_state;
    static uint8_t drbg_initialized = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if ((private_key == NULL) || (public_key == NULL)) { return NOXTLS_RETURN_NULL; }

    if (drbg_initialized == 0U) {
        uint8_t seed[NOXTLS_X448_DRBG_ENTROPY_SEED_BYTES];
        rc = noxtls_drbg_get_entropy(seed, sizeof(seed));
        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = drbg_instantiate(&drbg_state, DRBG_AES256, seed, sizeof(seed), NULL, 0, NULL, 0);
        }
        noxtls_secure_zero(seed, sizeof(seed));
        if (rc != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_drbg_uninstantiate(&drbg_state);
            return rc;
        }
        drbg_initialized = 1U;
    }

    rc = drbg_generate(&drbg_state, private_key, NOXTLS_X448_DRBG_SEED_BITS, NULL, 0);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        /* Fail closed for this call and drop the instance: a failed generate
         * may have wiped the state, so the next call re-instantiates from
         * fresh entropy instead of failing forever. */
        (void)noxtls_drbg_uninstantiate(&drbg_state);
        drbg_initialized = 0U;
        noxtls_secure_zero(private_key, (size_t)NOXTLS_X448_KEY_SIZE);
        return rc;
    }

    (void)noxtls_x448_clamp_scalar(private_key);
    rc = noxtls_x448_public_key(private_key, public_key);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(private_key, (size_t)NOXTLS_X448_KEY_SIZE);
    }
    return rc;
}
