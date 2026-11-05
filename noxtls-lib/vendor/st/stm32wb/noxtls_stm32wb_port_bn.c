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
* File:    noxtls_stm32wb_port_bn.c
* Summary: NoxTLS big-number modular exponentiation platform hook on the STM32WB5x PKA
*
*****************************************************************************/

/**
 * @file noxtls_stm32wb_port_bn.c
 * @brief Registers the PKA modular exponentiation with noxtls_bn_platform.
 * @ingroup noxtls_stm32wb
 *
 * The big-number layer routes RSA, DH and DSA exponentiations through the
 * registered platform hook before its portable Montgomery code. The hook is
 * installed at run time with noxtls_stm32wb_bn_register(); until then (or
 * when the PKA declines a request) the portable code runs.
 */

#include <stddef.h>

#include "noxtls_stm32wb_accel.h"
#include "noxtls_stm32wb_pka.h"
#include "pkc/rsa/noxtls_bn_platform.h"

/**
 * @brief Platform modular exponentiation hook.
 * @internal
 *
 * @param[out] out      Result.
 * @param[in]  base     Base.
 * @param[in]  exponent Exponent.
 * @param[in]  exp_len  Exponent bytes.
 * @param[in]  modulus  Modulus.
 * @param[in]  mod_len  Modulus bytes.
 *
 * @return NOXTLS_RETURN_SUCCESS, or NOXTLS_RETURN_NOT_SUPPORTED so the portable code runs.
 */
static noxtls_return_t noxtls_stm32wb_bn_mod_exp(uint8_t *out, const uint8_t *base, const uint8_t *exponent,
                                                 uint32_t exp_len, const uint8_t *modulus, uint32_t mod_len)
{
    return (noxtls_stm32wb_pka_modexp(out, base, exponent, exp_len, modulus, mod_len) == NOXTLS_RETURN_SUCCESS) ?
           NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_NOT_SUPPORTED;
}

/** Hook table: only the modular exponentiation is accelerated. */
static const noxtls_bn_platform_ops_t s_noxtls_stm32wb_bn_ops = {
    NULL,
    &noxtls_stm32wb_bn_mod_exp
};

void noxtls_stm32wb_bn_register(void)
{
    noxtls_bn_platform_register(&s_noxtls_stm32wb_bn_ops);
}
