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
* File:    noxtls_mldsa_ntt.c
* Summary: ML-DSA NTT helpers over Z_q with q = 8380417.
*
*
*****************************************************************************/

#include <stdint.h>
#include <stddef.h>

#include "noxtls_mldsa_internal.h"

typedef struct
{
    uint8_t initialized;
    int32_t root;
    int32_t inv_root;
    int32_t inv_n;
} noxtls_mldsa_ntt_ctx_t;

static noxtls_mldsa_ntt_ctx_t g_ntt_ctx = {0U, 0, 0, 0};

/**
 * @brief Add two integers modulo q.
 *
 * @param[in] a The a value.
 * @param[in] b The b value.
 * @return The return value.
 */
static int32_t mod_add_q(int32_t a, int32_t b)
{
    int32_t r = a + b;
    if(r >= NOXTLS_MLDSA_Q) {
        r -= NOXTLS_MLDSA_Q;
    }
    return r;
}

/**
 * @brief Subtract two integers modulo q.
 *
 * @param[in] a The a value.
 * @param[in] b The b value.
 * @return The return value.
 */
static int32_t mod_sub_q(int32_t a, int32_t b)
{
    int32_t r = a - b;
    if(r < 0) {
        r += NOXTLS_MLDSA_Q;
    }
    return r;
}

/**
 * @brief Multiply two integers modulo q.
 *
 * @param[in] a The a value.
 * @param[in] b The b value.
 * @return The return value.
 */
static int32_t mod_mul_q(int32_t a, int32_t b)
{
    int64_t p = (int64_t)a * (int64_t)b;
    return (int32_t)(p % NOXTLS_MLDSA_Q);
}

/**
 * @brief Raise an integer to a power modulo q.
 *
 * @param[in] base The base value.
 * @param[in] exp The exp value.
 * @return The return value.
 */
static int32_t mod_pow_q(int32_t base, int32_t exp)
{
    int32_t r = 1;
    int32_t b = noxtls_mldsa_coeff_normalize(base);
    int32_t e = exp;

    while(e > 0) {
        if((e & 1) != 0) {
            r = mod_mul_q(r, b);
        }
        b = mod_mul_q(b, b);
        e >>= 1;
    }
    return r;
}

/**
 * @brief Inverse an integer modulo q.
 *
 * @param[in] x The x value.
 * @return The return value.
 */
static int32_t mod_inv_q(int32_t x)
{
    return mod_pow_q(x, NOXTLS_MLDSA_Q - 2);
}

/**
 * @brief Reverse the bits of an 8-bit integer.
 *
 * @param[in] x The x value.
 * @return The return value.
 */
static uint32_t bit_reverse_u8(uint32_t x)
{
    uint32_t r = 0U;
    uint32_t i;
    for(i = 0U; i < 8U; ++i) {
        r = (r << 1U) | (x & 1U);
        x >>= 1U;
    }
    return r;
}

/**
 * @brief Initialize the NTT context.
 *
 * @return The return value.
 */
static int ntt_init_once(void)
{
    int32_t cand;
    int32_t root = 0;

    if(g_ntt_ctx.initialized != 0U) {
        return 0;
    }

    /* Find a primitive 256-th root of unity modulo q. */
    for(cand = 2; cand < NOXTLS_MLDSA_Q; ++cand) {
        if(mod_pow_q(cand, NOXTLS_MLDSA_N) == 1 &&
           mod_pow_q(cand, NOXTLS_MLDSA_N / 2) != 1) {
            root = cand;
            break;
        }
    }
    if(root == 0) {
        return -1;
    }

    g_ntt_ctx.root = root;
    g_ntt_ctx.inv_root = mod_inv_q(root);
    g_ntt_ctx.inv_n = mod_inv_q(NOXTLS_MLDSA_N);
    g_ntt_ctx.initialized = 1U;
    return 0;
}

/**
 * @brief Bit-reverse permute a polynomial.
 *
 * @param[in] p The p value.
 */
static void bit_reverse_permute(noxtls_mldsa_poly_t *p)
{
    uint32_t i;

    for(i = 0U; i < NOXTLS_MLDSA_N; ++i) {
        uint32_t j = bit_reverse_u8(i);
        if(j > i) {
            int32_t tmp = p->coeff[i];
            p->coeff[i] = p->coeff[j];
            p->coeff[j] = tmp;
        }
    }
}

/**
 * @brief Core NTT operation.
 *
 * @param[in] p The p value.
 * @param[in] omega The omega value.
 */
static void ntt_core(noxtls_mldsa_poly_t *p, int32_t omega)
{
    uint32_t m;

    bit_reverse_permute(p);

    for(m = 2U; m <= NOXTLS_MLDSA_N; m <<= 1U) {
        uint32_t half = m >> 1U;
        int32_t wm = mod_pow_q(omega, (int32_t)(NOXTLS_MLDSA_N / m));
        uint32_t k;

        for(k = 0U; k < NOXTLS_MLDSA_N; k += m) {
            int32_t w = 1;
            uint32_t j;
            for(j = 0U; j < half; ++j) {
                int32_t t = mod_mul_q(w, p->coeff[k + j + half]);
                int32_t u = p->coeff[k + j];
                p->coeff[k + j] = mod_add_q(u, t);
                p->coeff[k + j + half] = mod_sub_q(u, t);
                w = mod_mul_q(w, wm);
            }
        }
    }
}

/**
 * @brief Perform the NTT on a polynomial.
 *
 * @param[in] p The p value.
 */
void noxtls_mldsa_poly_ntt(noxtls_mldsa_poly_t *p)
{
    if(p == NULL) {
        return;
    }
    if(ntt_init_once() != 0) {
        return;
    }
    noxtls_mldsa_poly_reduce(p);
    ntt_core(p, g_ntt_ctx.root);
}

/**
 * @brief Perform the inverse NTT and convert to Montgomery domain.
 *
 * @param[in] p The p value.
 */
void noxtls_mldsa_poly_invntt_to_mont(noxtls_mldsa_poly_t *p)
{
    uint32_t i;

    if(p == NULL) {
        return;
    }
    if(ntt_init_once() != 0) {
        return;
    }

    noxtls_mldsa_poly_reduce(p);
    ntt_core(p, g_ntt_ctx.inv_root);
    for(i = 0U; i < NOXTLS_MLDSA_N; ++i) {
        p->coeff[i] = mod_mul_q(p->coeff[i], g_ntt_ctx.inv_n);
    }
}

/**
 * @brief Perform a pointwise Montgomery multiplication.
 *
 * @param[out] r The r value.
 * @param[in] a The a value.
 * @param[in] b The b value.
 */
void noxtls_mldsa_poly_pointwise_montgomery(noxtls_mldsa_poly_t *r,
                                            const noxtls_mldsa_poly_t *a,
                                            const noxtls_mldsa_poly_t *b)
{
    uint32_t i;

    if(r == NULL || a == NULL || b == NULL) {
        return;
    }

    for(i = 0U; i < NOXTLS_MLDSA_N; ++i) {
        r->coeff[i] = mod_mul_q(noxtls_mldsa_coeff_normalize(a->coeff[i]),
                                noxtls_mldsa_coeff_normalize(b->coeff[i]));
    }
}

