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
* File:    noxtls_mldsa_internal.c
* Summary: ML-DSA parameter definitions and basic arithmetic.
*
*
*****************************************************************************/

#include <stdint.h>
#include <stddef.h>

#include "noxtls_mldsa_internal.h"

static const noxtls_mldsa_param_spec_t g_mldsa_specs[] = {
    { NOXTLS_MLDSA_44, 1312U, 2560U, 2420U, 4U, 4U, 2U, 80U, 39U, 78U, 131072, 95232 },
    { NOXTLS_MLDSA_65, 1952U, 4032U, 3309U, 6U, 5U, 4U, 55U, 49U, 196U, 524288, 261888 },
    { NOXTLS_MLDSA_87, 2592U, 4896U, 4627U, 8U, 7U, 2U, 75U, 60U, 120U, 524288, 261888 }
};

/**
 * @brief Get the parameter specification.
 *
 * @param[in] param The param value.
 * @param[out] spec The spec value.
 * @return The return value.
 */
noxtls_return_t noxtls_mldsa_internal_get_param_spec(noxtls_mldsa_param_t param,
                                                     noxtls_mldsa_param_spec_t *spec)
{
    size_t i;

    if(spec == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    for(i = 0U; i < (sizeof(g_mldsa_specs)) / (sizeof(g_mldsa_specs[0])); i += 1U) {
        if(g_mldsa_specs[i].param == param) {
            *spec = g_mldsa_specs[i];
            return NOXTLS_RETURN_SUCCESS;
        }
    }

    return NOXTLS_RETURN_INVALID_PARAM;
}

/**
 * @brief Normalize a coefficient.
 *
 * @param[in] a The a value.
 * @return The return value.
 */
int32_t noxtls_mldsa_coeff_normalize(int32_t a)
{
    int32_t r = a % NOXTLS_MLDSA_Q;
    if(r < 0) {
        r += NOXTLS_MLDSA_Q;
    }
    return r;
}

/**
 * @brief Zero a polynomial.
 *
 * @param[in] p The p value.
 */
void noxtls_mldsa_poly_zero(noxtls_mldsa_poly_t *p)
{
    size_t i;

    if(p == NULL) {
        return;
    }

    for(i = 0U; i < NOXTLS_MLDSA_N; i += 1U) {
        p->coeff[i] = 0U;
    }
}

/**
 * @brief Add two polynomials.
 *
 * @param[out] r The r value.
 * @param[in] a The a value.
 * @param[in] b The b value.
 */
void noxtls_mldsa_poly_add(noxtls_mldsa_poly_t *r,
                           const noxtls_mldsa_poly_t *a,
                           const noxtls_mldsa_poly_t *b)
{
    size_t i;

    if(r == NULL || a == NULL || b == NULL) {
        return;
    }

    for(i = 0U; i < NOXTLS_MLDSA_N; i += 1U) {
        r->coeff[i] = a->coeff[i] + b->coeff[i];
    }
}

/**
 * @brief Subtract two polynomials.
 *
 * @param[out] r The r value.
 * @param[in] a The a value.
 * @param[in] b The b value.
 */
void noxtls_mldsa_poly_sub(noxtls_mldsa_poly_t *r,
                           const noxtls_mldsa_poly_t *a,
                           const noxtls_mldsa_poly_t *b)
{
    size_t i;

    if(r == NULL || a == NULL || b == NULL) {
        return;
    }

    for(i = 0U; i < NOXTLS_MLDSA_N; i += 1U) {
        r->coeff[i] = a->coeff[i] - b->coeff[i];
    }
}

/**
 * @brief Reduce a polynomial.
 *
 * @param[in] p The p value.
 */
void noxtls_mldsa_poly_reduce(noxtls_mldsa_poly_t *p)
{
    size_t i;

    if(p == NULL) {
        return;
    }

    for(i = 0U; i < NOXTLS_MLDSA_N; i += 1U) {
        p->coeff[i] = noxtls_mldsa_coeff_normalize(p->coeff[i]);
    }
}
