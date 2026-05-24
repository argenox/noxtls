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
 * @brief Try the BN platform operations
 * 
 * @param result The result
 * @param a The a value
 * @param a_len The length of the a value
 * @param mod The mod value
 * @param mod_len The length of the mod value
 * @return The return value
 */
noxtls_return_t noxtls_bn_platform_try_mod(uint8_t *result,
                                           const uint8_t *a,
                                           uint32_t a_len,
                                           const uint8_t *mod,
                                           uint32_t mod_len)
{
    if(s_bn_platform_ops == NULL || s_bn_platform_ops->mod == NULL) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    return s_bn_platform_ops->mod(result, a, a_len, mod, mod_len);
}

/**
 * @brief Try the BN platform operations
 * 
 * @param result The result
 * @param base The base value
 * @param exp The exp value
 * @param exp_len The length of the exp value
 * @param mod The mod value
 * @param mod_len The length of the mod value
 * @return The return value
 */
noxtls_return_t noxtls_bn_platform_try_mod_exp(uint8_t *result,
                                               const uint8_t *base,
                                               const uint8_t *exp,
                                               uint32_t exp_len,
                                               const uint8_t *mod,
                                               uint32_t mod_len)
{
    if(s_bn_platform_ops == NULL || s_bn_platform_ops->mod_exp == NULL) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    return s_bn_platform_ops->mod_exp(result, base, exp, exp_len, mod, mod_len);
}
