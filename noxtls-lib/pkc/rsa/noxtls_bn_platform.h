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

#ifndef _NOXTLS_BN_PLATFORM_H_
#define _NOXTLS_BN_PLATFORM_H_

#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Platform-provided modular reduction: result = a mod mod (big-endian byte arrays).
 * Return NOXTLS_RETURN_NOT_SUPPORTED to use the portable C implementation.
 */
typedef noxtls_return_t (*noxtls_bn_platform_mod_fn)(
    uint8_t *result,
    const uint8_t *a,
    uint32_t a_len,
    const uint8_t *mod,
    uint32_t mod_len);

/**
 * Platform-provided modular exponentiation: result = base^exp mod mod.
 */
typedef noxtls_return_t (*noxtls_bn_platform_mod_exp_fn)(
    uint8_t *result,
    const uint8_t *base,
    const uint8_t *exp,
    uint32_t exp_len,
    const uint8_t *mod,
    uint32_t mod_len);

typedef struct {
    noxtls_bn_platform_mod_fn     mod;
    noxtls_bn_platform_mod_exp_fn  mod_exp;
} noxtls_bn_platform_ops_t;

/** Register hooks (NULL clears). Only one provider at a time. */
void noxtls_bn_platform_register(const noxtls_bn_platform_ops_t *ops);

/** Dispatch helpers used from noxtls_bignum.c */
noxtls_return_t noxtls_bn_platform_try_mod(uint8_t *result,
                                           const uint8_t *a,
                                           uint32_t a_len,
                                           const uint8_t *mod,
                                           uint32_t mod_len);

noxtls_return_t noxtls_bn_platform_try_mod_exp(uint8_t *result,
                                               const uint8_t *base,
                                               const uint8_t *exp,
                                               uint32_t exp_len,
                                               const uint8_t *mod,
                                               uint32_t mod_len);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_BN_PLATFORM_H_ */
