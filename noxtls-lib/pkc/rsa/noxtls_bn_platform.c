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
* File:    noxtls_bn_platform.c
* Summary: Platform bignum hook registration and dispatch.
*
*
*****************************************************************************/

#include <stddef.h>

#include "noxtls_bn_platform.h"

static const noxtls_bn_platform_ops_t *s_bn_platform_ops;

/**
 * @brief Register the BN platform operations
 * 
 * @param ops The BN platform operations
 * @return void
 */
void noxtls_bn_platform_register(const noxtls_bn_platform_ops_t *ops)
{
    s_bn_platform_ops = ops;
}

/**
 * @brief Try the BN platform modular reduction hook
 */
noxtls_return_t noxtls_bn_platform_try_mod(uint8_t *out,
                                           const uint8_t *dividend,
                                           uint32_t dividend_len,
                                           const uint8_t *modulus,
                                           uint32_t modulus_len)
{
    if ((s_bn_platform_ops == NULL) || (s_bn_platform_ops->mod == NULL)) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    return s_bn_platform_ops->mod(out, dividend, dividend_len, modulus, modulus_len);
}

/**
 * @brief Try the BN platform modular exponentiation hook
 */
noxtls_return_t noxtls_bn_platform_try_mod_exp(uint8_t *out,
                                               const uint8_t *base,
                                               const uint8_t *exponent,
                                               uint32_t exponent_len,
                                               const uint8_t *modulus,
                                               uint32_t modulus_len)
{
    if ((s_bn_platform_ops == NULL) || (s_bn_platform_ops->mod_exp == NULL)) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    return s_bn_platform_ops->mod_exp(out, base, exponent, exponent_len, modulus, modulus_len);
}
