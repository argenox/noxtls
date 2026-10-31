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
* File:    noxtls_mldsa_packing.c
* Summary: ML-DSA SimpleBitPack / BitPack and their inverses (FIPS 204
*          Alg. 16-19), LSB-first, branch-free on coefficient values.
*
*
*****************************************************************************/

#include <stdint.h>
#include <stddef.h>

#include "noxtls_mldsa_internal.h"

#if NOXTLS_FEATURE_ML_DSA

/**
 * @brief Pack 256 coefficients as `bits`-bit little-endian fields.
 *
 * Each field holds (base - coeff) when subtract != 0 (BitPack with b = base),
 * otherwise coeff (SimpleBitPack).
 *
 * @param[out] out Output, 32 * bits bytes.
 * @param[in] p Polynomial.
 * @param[in] bits Field width (<= 24).
 * @param[in] base Offset b used in subtract mode.
 * @param[in] subtract Selects BitPack (non-zero) or SimpleBitPack (zero).
 */
void noxtls_mldsa_bitpack(uint8_t *out, const noxtls_mldsa_poly_t *p,
                          uint32_t bits, int32_t base, uint32_t subtract)
{
    uint32_t acc = 0U;
    uint32_t nbits = 0U;
    uint32_t o = 0U;
    uint32_t i = 0U;
    uint32_t mask = (1U << bits) - 1U;

    for(i = 0U; i < NOXTLS_MLDSA_N; i += 1U) {
        int32_t v = (subtract != 0U) ? (base - p->coeff[i]) : p->coeff[i];

        acc |= ((uint32_t)v & mask) << nbits;
        nbits += bits;
        while(nbits >= 8U) {
            out[o] = (uint8_t)(acc & 0xFFU);
            o += 1U;
            acc >>= 8U;
            nbits -= 8U;
        }
    }
}

/**
 * @brief Inverse of noxtls_mldsa_bitpack.
 *
 * @param[out] p Output polynomial; coeff = base - field (subtract) or field.
 * @param[in] in Input, 32 * bits bytes.
 * @param[in] bits Field width (<= 24).
 * @param[in] base Offset b used in subtract mode.
 * @param[in] subtract Selects BitUnpack (non-zero) or SimpleBitUnpack (zero).
 */
void noxtls_mldsa_bitunpack(noxtls_mldsa_poly_t *p, const uint8_t *in,
                            uint32_t bits, int32_t base, uint32_t subtract)
{
    uint32_t acc = 0U;
    uint32_t nbits = 0U;
    uint32_t o = 0U;
    uint32_t i = 0U;
    uint32_t mask = (1U << bits) - 1U;

    for(i = 0U; i < NOXTLS_MLDSA_N; i += 1U) {
        uint32_t v = 0U;

        while(nbits < bits) {
            acc |= (uint32_t)in[o] << nbits;
            o += 1U;
            nbits += 8U;
        }
        v = acc & mask;
        acc >>= bits;
        nbits -= bits;
        p->coeff[i] = (subtract != 0U) ? (base - (int32_t)v) : (int32_t)v;
    }
}

/**
 * @brief Decode an s1/s2 polynomial (BitUnpack with a = b = eta).
 * @param[in] spec Parameter set.
 * @param[out] p Output polynomial.
 * @param[in] in Encoded polynomial (spec->poly_eta_bytes).
 */
void noxtls_mldsa_polyeta_unpack(const noxtls_mldsa_param_spec_t *spec,
                                 noxtls_mldsa_poly_t *p, const uint8_t *in)
{
    noxtls_mldsa_bitunpack(p, in, spec->eta_bits, (int32_t)spec->eta, 1U);
}

/**
 * @brief Encode an s1/s2 polynomial (BitPack with a = b = eta).
 * @param[in] spec Parameter set.
 * @param[out] out Output (spec->poly_eta_bytes).
 * @param[in] p Polynomial with coefficients in [-eta, eta].
 */
void noxtls_mldsa_polyeta_pack(const noxtls_mldsa_param_spec_t *spec,
                               uint8_t *out, const noxtls_mldsa_poly_t *p)
{
    noxtls_mldsa_bitpack(out, p, spec->eta_bits, (int32_t)spec->eta, 1U);
}

#endif /* NOXTLS_FEATURE_ML_DSA */
