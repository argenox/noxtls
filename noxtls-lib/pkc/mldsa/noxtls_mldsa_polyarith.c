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
* File:    noxtls_mldsa_polyarith.c
* Summary: ML-DSA polynomial arithmetic helpers (add, sub, reduce, norm check).
*
*
*****************************************************************************/

#include <stdint.h>
#include <stddef.h>

#include "noxtls_mldsa_internal.h"

#if NOXTLS_FEATURE_ML_DSA

/**
 * @brief Set all coefficients to zero.
 * @param[out] p Polynomial.
 */
void noxtls_mldsa_poly_zero(noxtls_mldsa_poly_t *p)
{
    uint32_t i = 0U;

    for(i = 0U; i < NOXTLS_MLDSA_N; i += 1U) {
        p->coeff[i] = 0;
    }
}

/**
 * @brief r += a (no reduction).
 * @param[in,out] r Accumulator.
 * @param[in] a Addend.
 */
void noxtls_mldsa_poly_add(noxtls_mldsa_poly_t *r, const noxtls_mldsa_poly_t *a)
{
    uint32_t i = 0U;

    for(i = 0U; i < NOXTLS_MLDSA_N; i += 1U) {
        r->coeff[i] += a->coeff[i];
    }
}

/**
 * @brief r -= a (no reduction).
 * @param[in,out] r Minuend / result.
 * @param[in] a Subtrahend.
 */
void noxtls_mldsa_poly_sub(noxtls_mldsa_poly_t *r, const noxtls_mldsa_poly_t *a)
{
    uint32_t i = 0U;

    for(i = 0U; i < NOXTLS_MLDSA_N; i += 1U) {
        r->coeff[i] -= a->coeff[i];
    }
}

/**
 * @brief Apply noxtls_mldsa_reduce32 to every coefficient.
 * @param[in,out] p Polynomial.
 */
void noxtls_mldsa_poly_reduce(noxtls_mldsa_poly_t *p)
{
    uint32_t i = 0U;

    for(i = 0U; i < NOXTLS_MLDSA_N; i += 1U) {
        p->coeff[i] = noxtls_mldsa_reduce32(p->coeff[i]);
    }
}

/**
 * @brief Map every coefficient from (-q, q) to [0, q).
 * @param[in,out] p Polynomial.
 */
void noxtls_mldsa_poly_caddq(noxtls_mldsa_poly_t *p)
{
    uint32_t i = 0U;

    for(i = 0U; i < NOXTLS_MLDSA_N; i += 1U) {
        p->coeff[i] = noxtls_mldsa_caddq(p->coeff[i]);
    }
}

/**
 * @brief Multiply every coefficient by 2^d (t1 * 2^d).
 * @param[in,out] p Polynomial with coefficients < 2^10.
 */
void noxtls_mldsa_poly_shiftl(noxtls_mldsa_poly_t *p)
{
    uint32_t i = 0U;

    for(i = 0U; i < NOXTLS_MLDSA_N; i += 1U) {
        p->coeff[i] = (int32_t)((uint32_t)p->coeff[i] << NOXTLS_MLDSA_D);
    }
}

/**
 * @brief Infinity-norm check of a reduced polynomial.
 *
 * Leaks only which coefficient violates the bound (independent of secret data
 * for the rejection-sampled quantities), never the sign of the centred value.
 *
 * @param[in] p Polynomial with coefficients in [-6283008, 6283008].
 * @param[in] bound Exclusive bound B <= (q-1)/8.
 * @return 0 if all |coeff| < bound, 1 otherwise.
 */
uint32_t noxtls_mldsa_poly_chknorm(const noxtls_mldsa_poly_t *p, int32_t bound)
{
    uint32_t i = 0U;

    if(bound > ((NOXTLS_MLDSA_Q - 1) / 8)) {
        return 1U;
    }
    for(i = 0U; i < NOXTLS_MLDSA_N; i += 1U) {
        int32_t t = p->coeff[i] >> 31U;

        t = p->coeff[i] - (t & (2 * p->coeff[i]));
        if(t >= bound) {
            return 1U;
        }
    }
    return 0U;
}

#endif /* NOXTLS_FEATURE_ML_DSA */
