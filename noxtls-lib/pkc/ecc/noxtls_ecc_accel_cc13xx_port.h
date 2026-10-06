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
* File:    noxtls_ecc_accel_cc13xx_port.h
* Summary: CC13xx secp256r1 accelerator port interface
*
*
*****************************************************************************/

/**
 * @file noxtls_ecc_accel_cc13xx_port.h
 * @brief Validated OS-independent CC13xx point multiplication binding.
 * @defgroup noxtls_cc13xx_ecc CC13xx secp256r1 acceleration
 * @brief Original NoxTLS port over application-owned synchronous callbacks.
 * @{
 */
#ifndef NOXTLS_ECC_ACCEL_CC13XX_PORT_H
#define NOXTLS_ECC_ACCEL_CC13XX_PORT_H
#include "noxtls_ecc.h"

/** @brief Validate exact secp256r1 inputs and the returned finite public point.
 *
 * @param[out] result Caller-owned output, cleared on failure.
 * @param[in] scalar Exactly 32 big-endian bytes, in the interval [1,n-1].
 * @param[in] point Finite on-curve input with 32-byte coordinates less than p.
 * @param[in] curve Exact SEC 2 v2.0 section 2.4.2 secp256r1 domain parameters.
 *
 * @return Actual callback status; NOT_SUPPORTED for disabled/missing backend
 * or another curve; NULL/INVALID_PARAM/BAD_DATA for malformed input/output.
 * @note Caller-serialized ownership includes the complete surrounding ECC
 * operation. No private scalar or point data is retained in diagnostics.
 */
noxtls_return_t noxtls_ecc_point_multiply_accel_port(ecc_point_t *result,
    const uint8_t *scalar, const ecc_point_t *point, const ecc_curve_params_t *curve);
#endif
/** @} */
