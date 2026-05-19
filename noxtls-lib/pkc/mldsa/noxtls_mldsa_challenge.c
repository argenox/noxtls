/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
*
* File:    noxtls_mldsa_challenge.c
* Summary: ML-DSA challenge polynomial generation.
*/

#include <string.h>

#include "noxtls_mldsa_internal.h"

noxtls_return_t noxtls_mldsa_make_challenge(noxtls_mldsa_param_t param,
                                            const uint8_t *mu,
                                            uint32_t mu_len,
                                            noxtls_mldsa_poly_t *c)
{
    noxtls_mldsa_param_spec_t spec;
    noxtls_return_t rc;
    uint8_t stream[512];
    uint16_t stream_nonce = 0u;
    uint32_t off = 0u;
    uint16_t picked = 0u;

    if(mu == NULL || c == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_mldsa_internal_get_param_spec(param, &spec);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    noxtls_mldsa_poly_zero(c);

    while(picked < spec.tau) {
        uint8_t pos_byte;
        uint8_t sign_byte;
        uint16_t pos;
        int32_t coeff;

        if((off + 2u) > (uint32_t)sizeof(stream)) {
            off = 0u;
        }
        if(off == 0u) {
            rc = noxtls_mldsa_expand_xof(mu, mu_len, 0xD0u, stream_nonce, stream, (uint32_t)sizeof(stream));
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            stream_nonce++;
        }

        pos_byte = stream[off++];
        sign_byte = stream[off++];
        pos = (uint16_t)(pos_byte % NOXTLS_MLDSA_N);
        coeff = (sign_byte & 1u) ? -1 : 1;

        if(c->coeff[pos] == 0) {
            c->coeff[pos] = coeff;
            picked++;
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

