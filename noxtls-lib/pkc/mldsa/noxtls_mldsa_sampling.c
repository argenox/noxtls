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
* File:    noxtls_mldsa_sampling.c
* Summary: ML-DSA samplers: RejNTTPoly (ExpandA entry), RejBoundedPoly
*          (ExpandS entry) and ExpandMask entry (FIPS 204 Alg. 30-34).
*
*
*****************************************************************************/

#include <stdint.h>
#include <stddef.h>

#include "noxtls_mldsa_internal.h"

#if NOXTLS_FEATURE_ML_DSA

#include "noxtls_ct.h"

/** SHAKE128 rate in bytes. */
#define MLDSA_SHAKE128_RATE 168U
/** SHAKE256 rate in bytes. */
#define MLDSA_SHAKE256_RATE 136U
/** Chunk used when streaming ExpandMask output. */
#define MLDSA_MASK_CHUNK 64U

/**
 * @brief Sample A[row][col] = RejNTTPoly(rho || col || row) (already NTT domain).
 *
 * @param[out] a Output polynomial, coefficients in [0, q).
 * @param[in] rho Public seed.
 * @param[in] row Row index r.
 * @param[in] col Column index s.
 * @return NOXTLS_RETURN_SUCCESS or a SHAKE error.
 */
noxtls_return_t noxtls_mldsa_poly_uniform(noxtls_mldsa_poly_t *a,
                                          const uint8_t rho[NOXTLS_MLDSA_SEEDBYTES],
                                          uint32_t row, uint32_t col)
{
    noxtls_sha3_ctx_t ctx;
    uint8_t buf[MLDSA_SHAKE128_RATE];
    uint8_t idx[2];
    uint32_t ctr = 0U;
    noxtls_return_t rc = noxtls_shake128_init(&ctx);

    idx[0] = (uint8_t)col;
    idx[1] = (uint8_t)row;
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake128_update(&ctx, rho, NOXTLS_MLDSA_SEEDBYTES);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake128_update(&ctx, idx, 2U);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake128_final(&ctx);
    }
    while((rc == NOXTLS_RETURN_SUCCESS) && (ctr < NOXTLS_MLDSA_N)) {
        uint32_t pos = 0U;

        rc = noxtls_shake128_squeeze(&ctx, buf, MLDSA_SHAKE128_RATE);
        while((rc == NOXTLS_RETURN_SUCCESS) && (ctr < NOXTLS_MLDSA_N) &&
              ((pos + 3U) <= MLDSA_SHAKE128_RATE)) {
            uint32_t t = (uint32_t)buf[pos] |
                         ((uint32_t)buf[pos + 1U] << 8U) |
                         (((uint32_t)buf[pos + 2U] & 0x7FU) << 16U);

            pos += 3U;
            if(t < (uint32_t)NOXTLS_MLDSA_Q) {
                a->coeff[ctr] = (int32_t)t;
                ctr += 1U;
            }
        }
    }
    noxtls_secure_zero(&ctx, sizeof(ctx));
    return rc;
}

/**
 * @brief Sample a polynomial with coefficients in [-eta, eta]:
 *        RejBoundedPoly(rho' || IntegerToBytes(nonce, 2)).
 *
 * @param[in] spec Parameter set (selects eta).
 * @param[out] a Output polynomial.
 * @param[in] rhoprime 64-byte private seed.
 * @param[in] nonce Polynomial index (r for s1, l + r for s2).
 * @return NOXTLS_RETURN_SUCCESS or a SHAKE error.
 */
noxtls_return_t noxtls_mldsa_poly_uniform_eta(const noxtls_mldsa_param_spec_t *spec,
                                              noxtls_mldsa_poly_t *a,
                                              const uint8_t rhoprime[NOXTLS_MLDSA_CRHBYTES],
                                              uint32_t nonce)
{
    noxtls_sha3_ctx_t ctx;
    uint8_t buf[MLDSA_SHAKE256_RATE];
    uint8_t idx[2];
    uint32_t ctr = 0U;
    noxtls_return_t rc = noxtls_shake256_init(&ctx);

    idx[0] = (uint8_t)(nonce & 0xFFU);
    idx[1] = (uint8_t)((nonce >> 8U) & 0xFFU);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_update(&ctx, rhoprime, NOXTLS_MLDSA_CRHBYTES);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_update(&ctx, idx, 2U);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_final(&ctx);
    }
    while((rc == NOXTLS_RETURN_SUCCESS) && (ctr < NOXTLS_MLDSA_N)) {
        uint32_t pos = 0U;

        rc = noxtls_shake256_squeeze(&ctx, buf, MLDSA_SHAKE256_RATE);
        while((rc == NOXTLS_RETURN_SUCCESS) && (ctr < NOXTLS_MLDSA_N) && (pos < MLDSA_SHAKE256_RATE)) {
            uint32_t half[2];
            uint32_t h = 0U;

            half[0] = (uint32_t)buf[pos] & 0x0FU;
            half[1] = (uint32_t)buf[pos] >> 4U;
            pos += 1U;
            for(h = 0U; (h < 2U) && (ctr < NOXTLS_MLDSA_N); h += 1U) {
                uint32_t t = half[h];

                if(spec->eta == 2U) {
                    if(t < 15U) {
                        t = t - (((205U * t) >> 10U) * 5U); /* t mod 5 */
                        a->coeff[ctr] = 2 - (int32_t)t;
                        ctr += 1U;
                    }
                } else {
                    if(t < 9U) {
                        a->coeff[ctr] = 4 - (int32_t)t;
                        ctr += 1U;
                    }
                }
            }
        }
    }
    noxtls_secure_zero(buf, sizeof(buf));
    noxtls_secure_zero(&ctx, sizeof(ctx));
    return rc;
}

/**
 * @brief ExpandMask entry: y = BitUnpack(H(rho'' || IntegerToBytes(nonce, 2)), gamma1 - 1, gamma1).
 *
 * @param[in] spec Parameter set (selects gamma1).
 * @param[out] a Output polynomial with coefficients in [-gamma1 + 1, gamma1].
 * @param[in] rhoprime 64-byte seed rho''.
 * @param[in] nonce kappa + r.
 * @return NOXTLS_RETURN_SUCCESS or a SHAKE error.
 */
noxtls_return_t noxtls_mldsa_poly_uniform_gamma1(const noxtls_mldsa_param_spec_t *spec,
                                                 noxtls_mldsa_poly_t *a,
                                                 const uint8_t rhoprime[NOXTLS_MLDSA_CRHBYTES],
                                                 uint32_t nonce)
{
    noxtls_sha3_ctx_t ctx;
    uint8_t buf[MLDSA_MASK_CHUNK];
    uint8_t idx[2];
    uint32_t remaining = spec->poly_z_bytes;
    uint32_t avail = 0U;
    uint32_t pos = 0U;
    uint32_t acc = 0U;
    uint32_t nbits = 0U;
    uint32_t bits = spec->gamma1_bits;
    uint32_t mask = (1U << bits) - 1U;
    uint32_t i = 0U;
    noxtls_return_t rc = noxtls_shake256_init(&ctx);

    idx[0] = (uint8_t)(nonce & 0xFFU);
    idx[1] = (uint8_t)((nonce >> 8U) & 0xFFU);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_update(&ctx, rhoprime, NOXTLS_MLDSA_CRHBYTES);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_update(&ctx, idx, 2U);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_final(&ctx);
    }
    for(i = 0U; (rc == NOXTLS_RETURN_SUCCESS) && (i < NOXTLS_MLDSA_N); i += 1U) {
        while((rc == NOXTLS_RETURN_SUCCESS) && (nbits < bits)) {
            if(pos == avail) {
                avail = (remaining < MLDSA_MASK_CHUNK) ? remaining : MLDSA_MASK_CHUNK;
                remaining -= avail;
                pos = 0U;
                rc = noxtls_shake256_squeeze(&ctx, buf, avail);
            }
            if(rc == NOXTLS_RETURN_SUCCESS) {
                acc |= (uint32_t)buf[pos] << nbits;
                pos += 1U;
                nbits += 8U;
            }
        }
        a->coeff[i] = spec->gamma1 - (int32_t)(acc & mask);
        acc >>= bits;
        nbits -= bits;
    }
    noxtls_secure_zero(buf, sizeof(buf));
    noxtls_secure_zero(&ctx, sizeof(ctx));
    return rc;
}

#endif /* NOXTLS_FEATURE_ML_DSA */
