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
* File:    noxtls_ecc_accel_port.c
* Summary: Platform ECC acceleration hook (default software fallback)
*
*
*****************************************************************************/

#include <stdint.h>

#include "noxtls_ecc.h"
#include "noxtls_common.h"

/**
 * @brief Multiply the point by the scalar using the acceleration port
 *
 * @param[out] result The result of the point multiplication
 * @param[in] scalar The scalar to multiply the point by
 * @param[in] point The point to multiply
 * @param[in] curve The curve to multiply the point by
 * @return The return code
 */
noxtls_return_t noxtls_ecc_point_multiply_accel_port(ecc_point_t *result,
                                                      const uint8_t *scalar,
                                                      const ecc_point_t *point,
                                                      const ecc_curve_params_t *curve)
{
    (void)result;
    (void)scalar;
    (void)point;
    (void)curve;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}
