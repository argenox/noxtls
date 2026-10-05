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
* File:    noxtls_nrf54_port_drbg.c
* Summary: NoxTLS hardware entropy port on the nRF54L CRACEN TRNG
*
*****************************************************************************/

/**
 * @file noxtls_nrf54_port_drbg.c
 * @brief noxtls_drbg_entropy_accel_port(): entropy input of the NoxTLS CTR-DRBG
 *        (NIST SP 800-90A §8.6.3) from the CRACEN TRNG.
 * @ingroup noxtls_nrf54
 */

#include "drbg/noxtls_drbg.h"
#include "noxtls_nrf54_rng.h"

noxtls_return_t noxtls_drbg_entropy_accel_port(uint8_t *entropy_buffer, uint32_t entropy_len)
{
    return (noxtls_nrf54_rng_fill(entropy_buffer, entropy_len) == NOXTLS_RETURN_SUCCESS) ? NOXTLS_RETURN_SUCCESS :
           NOXTLS_RETURN_NOT_SUPPORTED;
}
