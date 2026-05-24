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
* File:    noxtls_mldsa_polyvec.c
* Summary: ML-DSA vector and matrix helpers.
*
*
*****************************************************************************/

#include <string.h>

#include "noxtls_mldsa_internal.h"

/**
 * @brief Sample a polynomial vector eta.
 *
 * @param[in] param The param value.
 * @param[in] seed The seed value.
 * @param[in] nonce_base The nonce base value.
 * @param[out] out The out value.
 * @return The return value.
 */
noxtls_return_t noxtls_mldsa_sample_polyvecl_eta(noxtls_mldsa_param_t param,
                                                  const uint8_t seed[NOXTLS_MLDSA_INTERNAL_SEED_BYTES],
                                                  uint16_t nonce_base,
                                                  noxtls_mldsa_polyvecl_t *out)
{
    noxtls_mldsa_param_spec_t spec;
    noxtls_return_t rc;
    uint8_t j;

    if(seed == NULL || out == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_mldsa_internal_get_param_spec(param, &spec);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(j = 0U; j < spec.l; ++j) {
        rc = noxtls_mldsa_sample_small_eta(param, seed, (uint16_t)(nonce_base + j), &out->v[j]);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Expand a matrix row.
 *
 * @param[in] param The param value.
 * @param[in] rho The rho value.
 * @param[in] row_index The row index value.
 * @param[out] row_out The row out value.
 * @return The return value.
 */
noxtls_return_t noxtls_mldsa_expand_matrix_row(noxtls_mldsa_param_t param,
                                                const uint8_t rho[NOXTLS_MLDSA_INTERNAL_SEED_BYTES],
                                                uint8_t row_index,
                                                noxtls_mldsa_polyvecl_t *row_out)
{
    noxtls_mldsa_param_spec_t spec;
    noxtls_return_t rc;
    uint8_t j;

    if(rho == NULL || row_out == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_mldsa_internal_get_param_spec(param, &spec);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(row_index >= spec.k) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    for(j = 0U; j < spec.l; ++j) {
        uint16_t nonce = (uint16_t)(((uint16_t)row_index << 8U) | (uint16_t)j);
        rc = noxtls_mldsa_sample_uniform_q(param, rho, nonce, &row_out->v[j]);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Multiply a matrix by a vector.
 *
 * @param[in] param The param value.
 * @param[in] rho The rho value.
 * @param[in] s1 The s1 value.
 * @param[out] t_out The t out value.
 * @return The return value.
 */
noxtls_return_t noxtls_mldsa_matrix_vector_mul(noxtls_mldsa_param_t param,
                                                const uint8_t rho[NOXTLS_MLDSA_INTERNAL_SEED_BYTES],
                                                const noxtls_mldsa_polyvecl_t *s1,
                                                noxtls_mldsa_polyveck_t *t_out)
{
    noxtls_mldsa_param_spec_t spec;
    noxtls_return_t rc;
    uint8_t row;

    if(rho == NULL || s1 == NULL || t_out == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_mldsa_internal_get_param_spec(param, &spec);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(row = 0U; row < spec.k; ++row) {
        noxtls_mldsa_polyvecl_t arow;
        noxtls_mldsa_poly_t acc;
        uint8_t j;

        rc = noxtls_mldsa_expand_matrix_row(param, rho, row, &arow);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }

        noxtls_mldsa_poly_zero(&acc);
        for(j = 0U; j < spec.l; ++j) {
            noxtls_mldsa_poly_t a = arow.v[j];
            noxtls_mldsa_poly_t b = s1->v[j];
            noxtls_mldsa_poly_t p;

            noxtls_mldsa_poly_ntt(&a);
            noxtls_mldsa_poly_ntt(&b);
            noxtls_mldsa_poly_pointwise_montgomery(&p, &a, &b);
            noxtls_mldsa_poly_invntt_to_mont(&p);
            noxtls_mldsa_poly_add(&acc, &acc, &p);
        }
        noxtls_mldsa_poly_reduce(&acc);
        t_out->v[row] = acc;
    }

    for(row = spec.k; row < NOXTLS_MLDSA_K_MAX; ++row) {
        noxtls_mldsa_poly_zero(&t_out->v[row]);
    }

    return NOXTLS_RETURN_SUCCESS;
}

