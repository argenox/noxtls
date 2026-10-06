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
* File:    noxtls_bn_platform.h
* Summary: Optional platform hooks for big-integer modular arithmetic.
*
*
*****************************************************************************/

#ifndef NOXTLS_BN_PLATFORM_H
#define NOXTLS_BN_PLATFORM_H

#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Platform-provided modular reduction: out = dividend mod modulus (big-endian byte arrays).
 * Return NOXTLS_RETURN_NOT_SUPPORTED to use the portable C implementation.
 */
typedef noxtls_return_t (*noxtls_bn_platform_mod_fn)(
    uint8_t *bn_mod_out,
    const uint8_t *bn_mod_dividend,
    uint32_t bn_mod_dividend_len,
    const uint8_t *bn_mod_modulus,
    uint32_t bn_mod_modulus_len);

/**
 * Platform-provided modular exponentiation: out = base^exponent mod modulus.
 */
typedef noxtls_return_t (*noxtls_bn_platform_mod_exp_fn)(
    uint8_t *bn_mod_exp_out,
    const uint8_t *bn_mod_exp_base,
    const uint8_t *bn_mod_exp_exponent,
    uint32_t bn_mod_exp_exponent_len,
    const uint8_t *bn_mod_exp_modulus,
    uint32_t bn_mod_exp_modulus_len);

typedef struct {
    noxtls_bn_platform_mod_fn     mod;
    noxtls_bn_platform_mod_exp_fn  mod_exp;
} noxtls_bn_platform_ops_t;

/** Register hooks (NULL clears). Only one provider at a time. */
void noxtls_bn_platform_register(const noxtls_bn_platform_ops_t *ops);

/** Dispatch helpers used from noxtls_bignum.c */
noxtls_return_t noxtls_bn_platform_try_mod(uint8_t *out,
                                           const uint8_t *dividend,
                                           uint32_t dividend_len,
                                           const uint8_t *modulus,
                                           uint32_t modulus_len);

noxtls_return_t noxtls_bn_platform_try_mod_exp(uint8_t *out,
                                               const uint8_t *base,
                                               const uint8_t *exponent,
                                               uint32_t exponent_len,
                                               const uint8_t *modulus,
                                               uint32_t modulus_len);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_BN_PLATFORM_H */
