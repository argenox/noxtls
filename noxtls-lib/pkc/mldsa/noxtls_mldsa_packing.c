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
* Summary: ML-DSA packing helpers for internal seed/state layout.
*
*
*****************************************************************************/

#include <stdint.h>
#include <stddef.h>

#include "noxtls_mldsa_internal.h"

/**
 * @brief Pack the seeds.
 *
 * @param[in] out The out value.
 * @param[in] out_len The out length value.
 * @param[in] rho The rho value.
 * @param[in] k The k value.
 * @param[in] tr The tr value.
 * @return The return value.
 */
noxtls_return_t noxtls_mldsa_pack_seeds(uint8_t *out,
                                        uint32_t out_len,
                                        const uint8_t rho[NOXTLS_MLDSA_INTERNAL_SEED_BYTES],
                                        const uint8_t k[NOXTLS_MLDSA_INTERNAL_SEED_BYTES],
                                        const uint8_t tr[NOXTLS_MLDSA_INTERNAL_SEED_BYTES])
{
    const uint32_t need = 3U * NOXTLS_MLDSA_INTERNAL_SEED_BYTES;

    if(out == NULL || rho == NULL || k == NULL || tr == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(out_len < need) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    memcpy(out, rho, NOXTLS_MLDSA_INTERNAL_SEED_BYTES);
    memcpy(out + NOXTLS_MLDSA_INTERNAL_SEED_BYTES, k, NOXTLS_MLDSA_INTERNAL_SEED_BYTES);
    memcpy(out + (2U * NOXTLS_MLDSA_INTERNAL_SEED_BYTES), tr, NOXTLS_MLDSA_INTERNAL_SEED_BYTES);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Unpack the seeds.
 *
 * @param[in] in The in value.
 * @param[in] in_len The in length value.
 * @param[out] rho The rho value.
 * @param[out] k The k value.
 * @param[out] tr The tr value.
 * @return The return value.
 */
noxtls_return_t noxtls_mldsa_unpack_seeds(const uint8_t *in,
                                          uint32_t in_len,
                                          uint8_t rho[NOXTLS_MLDSA_INTERNAL_SEED_BYTES],
                                          uint8_t k[NOXTLS_MLDSA_INTERNAL_SEED_BYTES],
                                          uint8_t tr[NOXTLS_MLDSA_INTERNAL_SEED_BYTES])
{
    const uint32_t need = 3U * NOXTLS_MLDSA_INTERNAL_SEED_BYTES;

    if(in == NULL || rho == NULL || k == NULL || tr == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(in_len < need) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    memcpy(rho, in, NOXTLS_MLDSA_INTERNAL_SEED_BYTES);
    memcpy(k, in + NOXTLS_MLDSA_INTERNAL_SEED_BYTES, NOXTLS_MLDSA_INTERNAL_SEED_BYTES);
    memcpy(tr, in + (2U * NOXTLS_MLDSA_INTERNAL_SEED_BYTES), NOXTLS_MLDSA_INTERNAL_SEED_BYTES);
    return NOXTLS_RETURN_SUCCESS;
}

