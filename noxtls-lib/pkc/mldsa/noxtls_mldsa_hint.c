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
* File:    noxtls_mldsa_hint.c
* Summary: ML-DSA decomposition and hint primitives.
*
*
*****************************************************************************/

#include <stdint.h>
#include <stddef.h>

#include "noxtls_mldsa_internal.h"

/**
 * @brief Absolute value of an integer.
 *
 * @param[in] x The x value.
 * @return The return value.
 */
static int32_t mldsa_abs_i32(int32_t x)
{
    return (x < 0) ? -x : x;
}

/**
 * @brief Center modulo q.
 *
 * @param[in] x The x value.
 * @return The return value.
 */
static int32_t mldsa_center_mod_q(int32_t x)
{
    int32_t r = noxtls_mldsa_coeff_normalize(x);
    if(r > (NOXTLS_MLDSA_Q / 2)) {
        r -= NOXTLS_MLDSA_Q;
    }
    return r;
}

/**
 * @brief W1 modulus.
 *
 * @param[in] gamma2 The gamma2 value.
 * @return The return value.
 */
static int32_t mldsa_w1_modulus(int32_t gamma2)
{
    int32_t two_gamma = gamma2 * 2;
    if(two_gamma <= 0) {
        return 0;
    }
    return (NOXTLS_MLDSA_Q + (two_gamma - 1)) / two_gamma;
}

/**
 * @brief Modular centered integer.
 *
 * @param[in] x The x value.
 * @param[in] mod The mod value.
 * @return The return value.
 */
static int32_t mldsa_mod_centered_int(int32_t x, int32_t mod)
{
    int32_t r;

    if(mod <= 0) {
        return x;
    }
    r = x % mod;
    if(r < 0) {
        r += mod;
    }
    return r;
}

/**
 * @brief Decompose a polynomial.
 *
 * @param[in] w The w value.
 * @param[in] gamma2 The gamma2 value.
 * @param[out] w1 The w1 value.
 * @param[out] w0 The w0 value.
 * @return The return value.
 */
noxtls_return_t noxtls_mldsa_decompose_poly(const noxtls_mldsa_poly_t *w,
                                            int32_t gamma2,
                                            noxtls_mldsa_poly_t *w1,
                                            noxtls_mldsa_poly_t *w0)
{
    int32_t two_gamma;
    int32_t a1_mod;
    uint32_t i;

    if(w == NULL || w1 == NULL || w0 == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(gamma2 <= 0) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    two_gamma = gamma2 * 2;
    a1_mod = mldsa_w1_modulus(gamma2);
    if(a1_mod <= 0) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    for(i = 0U; i < NOXTLS_MLDSA_N; ++i) {
        int32_t a = mldsa_center_mod_q(w->coeff[i]);
        int32_t a1 = a / two_gamma;
        int32_t a0 = a - (a1 * two_gamma);

        if(a0 > gamma2) {
            a0 -= two_gamma;
            a1 += 1;
        } else if(a0 <= -gamma2) {
            a0 += two_gamma;
            a1 -= 1;
        }

        w1->coeff[i] = mldsa_mod_centered_int(a1, a1_mod);
        w0->coeff[i] = a0;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Make a hint polynomial.
 *
 * @param[in] w0 The w0 value.
 * @param[in] gamma2 The gamma2 value.
 * @param[out] h The h value.
 * @param[out] weight The weight value.
 * @return The return value.
 */
noxtls_return_t noxtls_mldsa_make_hint_poly(const noxtls_mldsa_poly_t *w0,
                                            int32_t gamma2,
                                            noxtls_mldsa_poly_t *h,
                                            uint32_t *weight)
{
    uint32_t i;
    uint32_t local_weight = 0U;
    int32_t threshold;

    if(w0 == NULL || h == NULL || weight == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(gamma2 <= 0) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    threshold = gamma2 / 2;
    for(i = 0U; i < NOXTLS_MLDSA_N; ++i) {
        if(mldsa_abs_i32(w0->coeff[i]) > threshold) {
            h->coeff[i] = 1;
            local_weight++;
        } else {
            h->coeff[i] = 0;
        }
    }

    *weight = local_weight;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Use a hint polynomial.
 *
 * @param[in] w The w value.
 * @param[in] h The h value.
 * @param[in] gamma2 The gamma2 value.
 * @param[out] w1_adj The w1_adj value.
 * @return The return value.
 */
noxtls_return_t noxtls_mldsa_use_hint_poly(const noxtls_mldsa_poly_t *w,
                                           const noxtls_mldsa_poly_t *h,
                                           int32_t gamma2,
                                           noxtls_mldsa_poly_t *w1_adj)
{
    noxtls_mldsa_poly_t w1;
    noxtls_mldsa_poly_t w0;
    int32_t mod;
    noxtls_return_t rc;
    uint32_t i;

    if(w == NULL || h == NULL || w1_adj == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(gamma2 <= 0) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    rc = noxtls_mldsa_decompose_poly(w, gamma2, &w1, &w0);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    mod = mldsa_w1_modulus(gamma2);
    if(mod <= 0) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    for(i = 0U; i < NOXTLS_MLDSA_N; ++i) {
        int32_t hint = h->coeff[i];
        int32_t out = w1.coeff[i];

        if(hint != 0 && hint != 1) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        if(hint == 1) {
            out += (w0.coeff[i] >= 0) ? 1 : -1;
        }
        out %= mod;
        if(out < 0) {
            out += mod;
        }
        w1_adj->coeff[i] = out;
    }

    return NOXTLS_RETURN_SUCCESS;
}
