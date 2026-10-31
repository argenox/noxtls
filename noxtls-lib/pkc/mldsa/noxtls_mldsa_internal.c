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
* Summary: ML-DSA parameter sets (FIPS 204 Tables 1-2), SHAKE256 helper and
*          secret-key layout offsets.
*
*
*****************************************************************************/

#include <stdint.h>
#include <stddef.h>

#include "noxtls_mldsa_internal.h"

#if NOXTLS_FEATURE_ML_DSA

#include "noxtls_ct.h"

/**
 * @brief Resolve an ML-DSA parameter identifier to its FIPS 204 constants.
 *
 * @param[in] param ML-DSA parameter set identifier.
 * @param[out] spec Output parameter specification.
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL or NOXTLS_RETURN_INVALID_PARAM.
 */
noxtls_return_t noxtls_mldsa_internal_get_param_spec(noxtls_mldsa_param_t param,
                                                     noxtls_mldsa_param_spec_t *spec)
{
    if(spec == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    noxtls_secure_zero(spec, sizeof(*spec));
    spec->param = param;
    if(param == NOXTLS_MLDSA_44) {
        spec->k = 4U;
        spec->l = 4U;
        spec->eta = 2U;
        spec->tau = 39U;
        spec->beta = 78;
        spec->gamma1 = (int32_t)1 << 17;
        spec->gamma2 = (NOXTLS_MLDSA_Q - 1) / 88;
        spec->omega = 80U;
        spec->ctilde_len = 32U;
    } else if(param == NOXTLS_MLDSA_65) {
        spec->k = 6U;
        spec->l = 5U;
        spec->eta = 4U;
        spec->tau = 49U;
        spec->beta = 196;
        spec->gamma1 = (int32_t)1 << 19;
        spec->gamma2 = (NOXTLS_MLDSA_Q - 1) / 32;
        spec->omega = 55U;
        spec->ctilde_len = 48U;
    } else if(param == NOXTLS_MLDSA_87) {
        spec->k = 8U;
        spec->l = 7U;
        spec->eta = 2U;
        spec->tau = 60U;
        spec->beta = 120;
        spec->gamma1 = (int32_t)1 << 19;
        spec->gamma2 = (NOXTLS_MLDSA_Q - 1) / 32;
        spec->omega = 75U;
        spec->ctilde_len = 64U;
    } else {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    spec->eta_bits = (spec->eta == 2U) ? 3U : 4U;
    spec->poly_eta_bytes = (NOXTLS_MLDSA_N * spec->eta_bits) / 8U;
    spec->gamma1_bits = (spec->gamma1 == ((int32_t)1 << 17)) ? 18U : 20U;
    spec->poly_z_bytes = (NOXTLS_MLDSA_N * spec->gamma1_bits) / 8U;
    spec->w1_bits = (spec->gamma2 == ((NOXTLS_MLDSA_Q - 1) / 88)) ? 6U : 4U;
    spec->poly_w1_bytes = (NOXTLS_MLDSA_N * spec->w1_bits) / 8U;
    spec->public_key_len = NOXTLS_MLDSA_SEEDBYTES + (spec->k * NOXTLS_MLDSA_POLYT1_BYTES);
    spec->secret_key_len = (2U * NOXTLS_MLDSA_SEEDBYTES) + NOXTLS_MLDSA_TRBYTES +
                           ((spec->l + spec->k) * spec->poly_eta_bytes) +
                           (spec->k * NOXTLS_MLDSA_POLYT0_BYTES);
    spec->signature_len = spec->ctilde_len + (spec->l * spec->poly_z_bytes) +
                          spec->omega + spec->k;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief One-shot SHAKE256 over the concatenation in1 || in2.
 *
 * @param[out] out Output buffer.
 * @param[in] out_len Number of bytes to squeeze.
 * @param[in] in1 First input (may be NULL when in1_len is 0).
 * @param[in] in1_len Length of in1.
 * @param[in] in2 Second input (may be NULL when in2_len is 0).
 * @param[in] in2_len Length of in2.
 * @return NOXTLS_RETURN_SUCCESS or the SHAKE error code.
 */
noxtls_return_t noxtls_mldsa_shake256(uint8_t *out, uint32_t out_len,
                                      const uint8_t *in1, uint32_t in1_len,
                                      const uint8_t *in2, uint32_t in2_len)
{
    noxtls_sha3_ctx_t ctx;
    noxtls_return_t rc = noxtls_shake256_init(&ctx);

    if((rc == NOXTLS_RETURN_SUCCESS) && (in1_len > 0U)) {
        rc = noxtls_shake256_update(&ctx, in1, in1_len);
    }
    if((rc == NOXTLS_RETURN_SUCCESS) && (in2_len > 0U)) {
        rc = noxtls_shake256_update(&ctx, in2, in2_len);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_final(&ctx);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_squeeze(&ctx, out, out_len);
    }
    noxtls_secure_zero(&ctx, sizeof(ctx));
    return rc;
}

/**
 * @brief Byte offset of s1[j] inside an encoded secret key.
 * @param[in] spec Parameter set.
 * @param[in] j Polynomial index (0..l-1).
 * @return Offset in bytes.
 */
uint32_t noxtls_mldsa_sk_s1_offset(const noxtls_mldsa_param_spec_t *spec, uint32_t j)
{
    return (2U * NOXTLS_MLDSA_SEEDBYTES) + NOXTLS_MLDSA_TRBYTES + (j * spec->poly_eta_bytes);
}

/**
 * @brief Byte offset of s2[i] inside an encoded secret key.
 * @param[in] spec Parameter set.
 * @param[in] i Polynomial index (0..k-1).
 * @return Offset in bytes.
 */
uint32_t noxtls_mldsa_sk_s2_offset(const noxtls_mldsa_param_spec_t *spec, uint32_t i)
{
    return noxtls_mldsa_sk_s1_offset(spec, spec->l) + (i * spec->poly_eta_bytes);
}

/**
 * @brief Byte offset of t0[i] inside an encoded secret key.
 * @param[in] spec Parameter set.
 * @param[in] i Polynomial index (0..k-1).
 * @return Offset in bytes.
 */
uint32_t noxtls_mldsa_sk_t0_offset(const noxtls_mldsa_param_spec_t *spec, uint32_t i)
{
    return noxtls_mldsa_sk_s2_offset(spec, spec->k) + (i * NOXTLS_MLDSA_POLYT0_BYTES);
}

#endif /* NOXTLS_FEATURE_ML_DSA */
