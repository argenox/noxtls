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
* Summary: ML-DSA polynomial arithmetic helpers.
*
*
*****************************************************************************/

#include <stdint.h>
#include <stddef.h>

#include "noxtls_mldsa_internal.h"

/**
 * @brief Multiply a polynomial by a challenge polynomial.
 *
 * @param[in] a The a value.
 * @param[in] c The c value.
 * @param[out] r The r value.
 * @return The return value.
 */
noxtls_return_t noxtls_mldsa_poly_mul_challenge(const noxtls_mldsa_poly_t *a,
                                                const noxtls_mldsa_poly_t *c,
                                                noxtls_mldsa_poly_t *r)
{
    int64_t acc[NOXTLS_MLDSA_N];
    uint32_t i;
    uint32_t j;

    if(a == NULL || c == NULL || r == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    for(i = 0U; i < NOXTLS_MLDSA_N; ++i) {
        acc[i] = 0;
    }

    for(j = 0U; j < NOXTLS_MLDSA_N; ++j) {
        int32_t cj = c->coeff[j];
        if(cj == 0) {
            continue;
        }
        if(cj != 1 && cj != -1) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        for(i = 0U; i < NOXTLS_MLDSA_N; ++i) {
            uint32_t pos = i + j;
            int64_t term = (int64_t)a->coeff[i] * (int64_t)cj;
            if(pos >= NOXTLS_MLDSA_N) {
                pos -= NOXTLS_MLDSA_N;
                term = -term;
            }
            acc[pos] += term;
        }
    }

    for(i = 0U; i < NOXTLS_MLDSA_N; ++i) {
        r->coeff[i] = (int32_t)acc[i];
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Make the Z polynomial.
 *
 * @param[in] param The param value.
 * @param[in] y The y value.
 * @param[in] c The c value.
 * @param[in] s1 The s1 value.
 * @param[out] z The z value.
 * @return The return value.
 */
noxtls_return_t noxtls_mldsa_make_z(noxtls_mldsa_param_t param,
                                    const noxtls_mldsa_polyvecl_t *y,
                                    const noxtls_mldsa_poly_t *c,
                                    const noxtls_mldsa_polyvecl_t *s1,
                                    noxtls_mldsa_polyvecl_t *z)
{
    noxtls_mldsa_param_spec_t spec;
    noxtls_mldsa_poly_t cs1;
    noxtls_return_t rc;
    uint32_t i;
    uint32_t j;

    if(y == NULL || c == NULL || s1 == NULL || z == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_mldsa_internal_get_param_spec(param, &spec);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(j = 0U; j < spec.l; ++j) {
        rc = noxtls_mldsa_poly_mul_challenge(&s1->v[j], c, &cs1);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        for(i = 0U; i < NOXTLS_MLDSA_N; ++i) {
            z->v[j].coeff[i] = y->v[j].coeff[i] + cs1.coeff[i];
        }
    }

    for(j = spec.l; j < NOXTLS_MLDSA_L_MAX; ++j) {
        noxtls_mldsa_poly_zero(&z->v[j]);
    }

    return NOXTLS_RETURN_SUCCESS;
}
