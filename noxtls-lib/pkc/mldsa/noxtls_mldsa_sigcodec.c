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
* File:    noxtls_mldsa_sigcodec.c
* Summary: ML-DSA signature component codecs: z (BitPack gamma1), w1Encode and
*          hint (HintBitPack/HintBitUnpack validation), FIPS 204 Alg. 20-28.
*
*
*****************************************************************************/

#include <stdint.h>
#include <stddef.h>

#include "noxtls_mldsa_internal.h"

#if NOXTLS_FEATURE_ML_DSA

/**
 * @brief Encode z (BitPack(z, gamma1 - 1, gamma1)).
 * @param[in] spec Parameter set.
 * @param[out] out Output (spec->poly_z_bytes).
 * @param[in] p Polynomial with coefficients in (-gamma1, gamma1].
 */
void noxtls_mldsa_polyz_pack(const noxtls_mldsa_param_spec_t *spec,
                             uint8_t *out, const noxtls_mldsa_poly_t *p)
{
    noxtls_mldsa_bitpack(out, p, spec->gamma1_bits, spec->gamma1, 1U);
}

/**
 * @brief Decode z (BitUnpack(z, gamma1 - 1, gamma1)).
 * @param[in] spec Parameter set.
 * @param[out] p Output polynomial.
 * @param[in] in Encoded polynomial (spec->poly_z_bytes).
 */
void noxtls_mldsa_polyz_unpack(const noxtls_mldsa_param_spec_t *spec,
                               noxtls_mldsa_poly_t *p, const uint8_t *in)
{
    noxtls_mldsa_bitunpack(p, in, spec->gamma1_bits, spec->gamma1, 1U);
}

/**
 * @brief w1Encode of one polynomial: HighBits(w) (hints == NULL) or
 *        UseHint(h, w) using the sorted hint positions hints[hint_start..hint_end).
 *
 * @param[in] spec Parameter set.
 * @param[out] out Output (spec->poly_w1_bytes).
 * @param[in] w Polynomial with coefficients in [0, q).
 * @param[in] hints Hint position bytes, or NULL.
 * @param[in] hint_start First hint index for this polynomial.
 * @param[in] hint_end One past the last hint index for this polynomial.
 */
void noxtls_mldsa_polyw1_pack(const noxtls_mldsa_param_spec_t *spec,
                              uint8_t *out, const noxtls_mldsa_poly_t *w,
                              const uint8_t *hints, uint32_t hint_start, uint32_t hint_end)
{
    uint32_t acc = 0U;
    uint32_t nbits = 0U;
    uint32_t o = 0U;
    uint32_t i = 0U;
    uint32_t pos = hint_start;

    for(i = 0U; i < NOXTLS_MLDSA_N; i += 1U) {
        int32_t a0 = 0;
        int32_t a1 = 0;

        if(hints == NULL) {
            a1 = noxtls_mldsa_decompose(w->coeff[i], spec->gamma2, &a0);
        } else {
            uint32_t h = 0U;

            if((pos < hint_end) && ((uint32_t)hints[pos] == i)) {
                h = 1U;
                pos += 1U;
            }
            a1 = noxtls_mldsa_use_hint(w->coeff[i], h, spec->gamma2);
        }
        acc |= (uint32_t)a1 << nbits;
        nbits += spec->w1_bits;
        while(nbits >= 8U) {
            out[o] = (uint8_t)(acc & 0xFFU);
            o += 1U;
            acc >>= 8U;
            nbits -= 8U;
        }
    }
}

/**
 * @brief Validate the hint section of a signature (HintBitUnpack error checks).
 *
 * Rejects decreasing/duplicate positions within a polynomial, cumulative counts
 * that decrease or exceed omega, and non-zero padding (strong unforgeability).
 *
 * @param[in] spec Parameter set.
 * @param[in] h Hint section (omega + k bytes).
 * @return NOXTLS_RETURN_SUCCESS if well-formed, NOXTLS_RETURN_FAILED otherwise.
 */
noxtls_return_t noxtls_mldsa_hint_validate(const noxtls_mldsa_param_spec_t *spec,
                                           const uint8_t *h)
{
    uint32_t index = 0U;
    uint32_t i = 0U;
    uint32_t j = 0U;

    for(i = 0U; i < spec->k; i += 1U) {
        uint32_t end = (uint32_t)h[spec->omega + i];

        if((end < index) || (end > spec->omega)) {
            return NOXTLS_RETURN_FAILED;
        }
        for(j = index; j < end; j += 1U) {
            if((j > index) && (h[j] <= h[j - 1U])) {
                return NOXTLS_RETURN_FAILED;
            }
        }
        index = end;
    }
    for(j = index; j < spec->omega; j += 1U) {
        if(h[j] != 0U) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_ML_DSA */
