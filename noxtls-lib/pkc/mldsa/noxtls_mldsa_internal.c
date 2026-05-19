/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
*
* File:    noxtls_mldsa_internal.c
* Summary: ML-DSA parameter definitions and basic arithmetic.
*/

#include <stddef.h>

#include "noxtls_mldsa_internal.h"

static const noxtls_mldsa_param_spec_t g_mldsa_specs[] = {
    { NOXTLS_MLDSA_44, 1312u, 2560u, 2420u, 4u, 4u, 2u, 80u, 39u, 78u, 131072, 95232 },
    { NOXTLS_MLDSA_65, 1952u, 4032u, 3309u, 6u, 5u, 4u, 55u, 49u, 196u, 524288, 261888 },
    { NOXTLS_MLDSA_87, 2592u, 4896u, 4627u, 8u, 7u, 2u, 75u, 60u, 120u, 524288, 261888 }
};

noxtls_return_t noxtls_mldsa_internal_get_param_spec(noxtls_mldsa_param_t param,
                                                     noxtls_mldsa_param_spec_t *spec)
{
    size_t i;

    if(spec == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    for(i = 0u; i < (sizeof(g_mldsa_specs) / sizeof(g_mldsa_specs[0])); ++i) {
        if(g_mldsa_specs[i].param == param) {
            *spec = g_mldsa_specs[i];
            return NOXTLS_RETURN_SUCCESS;
        }
    }

    return NOXTLS_RETURN_INVALID_PARAM;
}

int32_t noxtls_mldsa_coeff_normalize(int32_t a)
{
    int32_t r = a % NOXTLS_MLDSA_Q;
    if(r < 0) {
        r += NOXTLS_MLDSA_Q;
    }
    return r;
}

void noxtls_mldsa_poly_zero(noxtls_mldsa_poly_t *p)
{
    size_t i;

    if(p == NULL) {
        return;
    }

    for(i = 0u; i < NOXTLS_MLDSA_N; ++i) {
        p->coeff[i] = 0;
    }
}

void noxtls_mldsa_poly_add(noxtls_mldsa_poly_t *r,
                           const noxtls_mldsa_poly_t *a,
                           const noxtls_mldsa_poly_t *b)
{
    size_t i;

    if(r == NULL || a == NULL || b == NULL) {
        return;
    }

    for(i = 0u; i < NOXTLS_MLDSA_N; ++i) {
        r->coeff[i] = a->coeff[i] + b->coeff[i];
    }
}

void noxtls_mldsa_poly_sub(noxtls_mldsa_poly_t *r,
                           const noxtls_mldsa_poly_t *a,
                           const noxtls_mldsa_poly_t *b)
{
    size_t i;

    if(r == NULL || a == NULL || b == NULL) {
        return;
    }

    for(i = 0u; i < NOXTLS_MLDSA_N; ++i) {
        r->coeff[i] = a->coeff[i] - b->coeff[i];
    }
}

void noxtls_mldsa_poly_reduce(noxtls_mldsa_poly_t *p)
{
    size_t i;

    if(p == NULL) {
        return;
    }

    for(i = 0u; i < NOXTLS_MLDSA_N; ++i) {
        p->coeff[i] = noxtls_mldsa_coeff_normalize(p->coeff[i]);
    }
}
