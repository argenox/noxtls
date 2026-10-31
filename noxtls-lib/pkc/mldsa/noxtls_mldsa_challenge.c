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
* File:    noxtls_mldsa_challenge.c
* Summary: ML-DSA SampleInBall (FIPS 204 Alg. 29).
*
*
*****************************************************************************/

#include <stdint.h>
#include <stddef.h>

#include "noxtls_mldsa_internal.h"

#if NOXTLS_FEATURE_ML_DSA

#include "noxtls_ct.h"

/**
 * @brief SampleInBall: derive the challenge c with tau coefficients in {-1, +1}
 *        from the full commitment hash c~ (lambda/4 bytes).
 *
 * @param[in] spec Parameter set (tau, ctilde length).
 * @param[out] c Output challenge polynomial.
 * @param[in] ctilde Commitment hash.
 * @return NOXTLS_RETURN_SUCCESS or a SHAKE error.
 */
noxtls_return_t noxtls_mldsa_poly_challenge(const noxtls_mldsa_param_spec_t *spec,
                                            noxtls_mldsa_poly_t *c,
                                            const uint8_t *ctilde)
{
    noxtls_sha3_ctx_t ctx;
    uint8_t buf[8] = { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U };
    uint64_t signs = 0U;
    uint32_t i = 0U;
    noxtls_return_t rc = noxtls_shake256_init(&ctx);

    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_update(&ctx, ctilde, spec->ctilde_len);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_final(&ctx);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_squeeze(&ctx, buf, 8U);
    }
    for(i = 0U; i < 8U; i += 1U) {
        signs |= (uint64_t)buf[i] << (8U * i);
    }
    noxtls_mldsa_poly_zero(c);
    for(i = NOXTLS_MLDSA_N - spec->tau; (rc == NOXTLS_RETURN_SUCCESS) && (i < NOXTLS_MLDSA_N); i += 1U) {
        uint32_t j = 0xFFFFU;

        while((rc == NOXTLS_RETURN_SUCCESS) && (j > i)) {
            uint8_t b = 0U;

            rc = noxtls_shake256_squeeze(&ctx, &b, 1U);
            j = (uint32_t)b;
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            c->coeff[i] = c->coeff[j];
            c->coeff[j] = 1 - (2 * (int32_t)(uint32_t)(signs & 1U));
            signs >>= 1U;
        }
    }
    noxtls_secure_zero(&ctx, sizeof(ctx));
    return rc;
}

#endif /* NOXTLS_FEATURE_ML_DSA */
