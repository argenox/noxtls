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
* Summary: Streaming matrix-vector helper: the public matrix A is never stored,
*          each entry is regenerated from rho when it is consumed.
*
*
*****************************************************************************/

#include <stdint.h>
#include <stddef.h>

#include "noxtls_mldsa_internal.h"

#if NOXTLS_FEATURE_ML_DSA

/**
 * @brief acc += A[row][col] o vhat (NTT domain, Montgomery product).
 *
 * @param[in,out] acc Accumulator polynomial.
 * @param[out] a_tmp Scratch polynomial receiving A[row][col].
 * @param[in] rho Public seed.
 * @param[in] row Matrix row.
 * @param[in] col Matrix column.
 * @param[in] vhat NTT-domain vector element for column col.
 * @return NOXTLS_RETURN_SUCCESS or a sampling error.
 */
noxtls_return_t noxtls_mldsa_matrix_acc(noxtls_mldsa_poly_t *acc,
                                        noxtls_mldsa_poly_t *a_tmp,
                                        const uint8_t rho[NOXTLS_MLDSA_SEEDBYTES],
                                        uint32_t row, uint32_t col,
                                        const noxtls_mldsa_poly_t *vhat)
{
    noxtls_return_t rc = noxtls_mldsa_poly_uniform(a_tmp, rho, row, col);

    if(rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_mldsa_poly_pointwise_acc_montgomery(acc, a_tmp, vhat);
    }
    return rc;
}

#endif /* NOXTLS_FEATURE_ML_DSA */
