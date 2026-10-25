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
* File:    noxtls_mldsa_hint.c
* Summary: ML-DSA Power2Round, Decompose, MakeHint and UseHint
*          (FIPS 204 Alg. 35-40), constant-time arithmetic forms.
*
*
*****************************************************************************/

#include <stdint.h>
#include <stddef.h>

#include "noxtls_mldsa_internal.h"

#if NOXTLS_FEATURE_ML_DSA

/**
 * @brief Power2Round: a = a1 * 2^d + a0 with -2^(d-1) < a0 <= 2^(d-1).
 * @param[in] a Standard representative in [0, q).
 * @param[out] a0 Low part.
 * @return High part a1.
 */
int32_t noxtls_mldsa_power2round(int32_t a, int32_t *a0)
{
    int32_t a1 = (a + ((int32_t)1 << (NOXTLS_MLDSA_D - 1U)) - 1) >> NOXTLS_MLDSA_D;

    *a0 = a - (int32_t)((uint32_t)a1 << NOXTLS_MLDSA_D);
    return a1;
}

/**
 * @brief Decompose: a = a1 * 2 * gamma2 + a0 with -gamma2 < a0 <= gamma2, except
 *        a1 = 0, a0 = a - q when a - a0 = q - 1.
 * @param[in] a Standard representative in [0, q).
 * @param[in] gamma2 (q-1)/88 or (q-1)/32.
 * @param[out] a0 Low part.
 * @return High part a1.
 */
int32_t noxtls_mldsa_decompose(int32_t a, int32_t gamma2, int32_t *a0)
{
    int32_t a1 = (a + 127) >> 7U;

    if(gamma2 == ((NOXTLS_MLDSA_Q - 1) / 32)) {
        a1 = ((a1 * 1025) + ((int32_t)1 << 21)) >> 22U;
        a1 &= 15;
    } else {
        a1 = ((a1 * 11275) + ((int32_t)1 << 23)) >> 24U;
        a1 ^= ((43 - a1) >> 31U) & a1;
    }
    *a0 = a - (a1 * 2 * gamma2);
    *a0 -= ((((NOXTLS_MLDSA_Q - 1) / 2) - *a0) >> 31U) & NOXTLS_MLDSA_Q;
    return a1;
}

/**
 * @brief MakeHint: 1 when adding the (negated) low part changes the high bits.
 * @param[in] a0 Low part (w0 - cs2 + ct0).
 * @param[in] a1 High part of w.
 * @param[in] gamma2 Rounding parameter.
 * @return Hint bit.
 */
uint32_t noxtls_mldsa_make_hint(int32_t a0, int32_t a1, int32_t gamma2)
{
    if((a0 > gamma2) || (a0 < -gamma2) || ((a0 == -gamma2) && (a1 != 0))) {
        return 1U;
    }
    return 0U;
}

/**
 * @brief UseHint: recover the corrected high bits.
 * @param[in] a Standard representative in [0, q).
 * @param[in] hint Hint bit.
 * @param[in] gamma2 Rounding parameter.
 * @return Corrected high bits.
 */
int32_t noxtls_mldsa_use_hint(int32_t a, uint32_t hint, int32_t gamma2)
{
    int32_t a0 = 0;
    int32_t a1 = noxtls_mldsa_decompose(a, gamma2, &a0);

    if(hint == 0U) {
        return a1;
    }
    if(gamma2 == ((NOXTLS_MLDSA_Q - 1) / 32)) {
        if(a0 > 0) {
            return (a1 + 1) & 15;
        }
        return (a1 - 1) & 15;
    }
    if(a0 > 0) {
        return (a1 == 43) ? 0 : (a1 + 1);
    }
    return (a1 == 0) ? 43 : (a1 - 1);
}

#endif /* NOXTLS_FEATURE_ML_DSA */
