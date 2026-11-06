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
* File:    noxtls_atecc608_port_drbg.c
* Summary: noxtls_drbg_entropy_accel_port(): chip RNG as DRBG entropy
*
*****************************************************************************/

/**
 * @file noxtls_atecc608_port_drbg.c
 * @brief Entropy input of the NoxTLS CTR-DRBG from the ATECC608 random number generator.
 *
 * Used by NOXTLS_ENTROPY_SOURCE_AUTO before the operating system sources when NOXTLS_FEATURE_ATECC608_ENTROPY is
 * set. The DRBG stays on top: the chip output only seeds it (NIST SP 800-90A), it is never used raw.
 */
#include "common/noxtls_accel_port.h"

#if NOXTLS_FEATURE_ATECC608_ENTROPY

#include "drbg/noxtls_drbg.h"
#include "noxtls_atecc608.h"

static const noxtls_atecc608_backend_t *g_entropy_backend;

void noxtls_atecc608_set_entropy_backend(const noxtls_atecc608_backend_t *backend)
{
    g_entropy_backend = backend;
}

noxtls_return_t noxtls_drbg_entropy_accel_port(uint8_t *entropy_buffer, uint32_t entropy_len)
{
    if ((entropy_buffer == NULL) || (entropy_len == 0U)) {
        return NOXTLS_RETURN_NULL;
    }

    if ((g_entropy_backend == NULL) || (g_entropy_backend->random == NULL)) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    return (g_entropy_backend->random(g_entropy_backend->device, entropy_buffer, entropy_len) == 0) ? NOXTLS_RETURN_SUCCESS
                                                                                                        : NOXTLS_RETURN_FAILED;
}

#endif
