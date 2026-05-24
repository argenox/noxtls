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
* File:    noxtls_slhdsa.h
* Summary: SLH-DSA (NIST FIPS 205) API and parameter contracts definition
*
*
*****************************************************************************/

#ifndef _NOXTLS_SLHDSA_H_
#define _NOXTLS_SLHDSA_H_

#include <stdint.h>

#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    NOXTLS_SLHDSA_NONE = 0,
    NOXTLS_SLHDSA_SHA2_128S = 1,
    NOXTLS_SLHDSA_SHA2_128F = 2,
    NOXTLS_SLHDSA_SHA2_192S = 3,
    NOXTLS_SLHDSA_SHA2_192F = 4,
    NOXTLS_SLHDSA_SHA2_256S = 5,
    NOXTLS_SLHDSA_SHA2_256F = 6,
    NOXTLS_SLHDSA_SHAKE_128S = 7,
    NOXTLS_SLHDSA_SHAKE_128F = 8,
    NOXTLS_SLHDSA_SHAKE_192S = 9,
    NOXTLS_SLHDSA_SHAKE_192F = 10,
    NOXTLS_SLHDSA_SHAKE_256S = 11,
    NOXTLS_SLHDSA_SHAKE_256F = 12
} noxtls_slhdsa_param_t;

#define NOXTLS_SLHDSA_MAX_PUBLIC_KEY_LEN 64U
#define NOXTLS_SLHDSA_MAX_SECRET_KEY_LEN 128U
#define NOXTLS_SLHDSA_MAX_SIGNATURE_LEN 49856u
#define NOXTLS_SLHDSA_MAX_CONTEXT_LEN 255u

typedef struct
{
    uint32_t public_key_len;
    uint32_t secret_key_len;
    uint32_t signature_len;
    uint32_t security_category;
    uint8_t hash_family_sha2;
    uint8_t small_variant;
} slhdsa_sizes_t;

uint32_t noxtls_slhdsa_public_key_len(noxtls_slhdsa_param_t param);
uint32_t noxtls_slhdsa_secret_key_len(noxtls_slhdsa_param_t param);
uint32_t noxtls_slhdsa_signature_len(noxtls_slhdsa_param_t param);
uint32_t noxtls_slhdsa_security_category(noxtls_slhdsa_param_t param);
uint8_t noxtls_slhdsa_is_sha2(noxtls_slhdsa_param_t param);
uint8_t noxtls_slhdsa_is_small(noxtls_slhdsa_param_t param);

noxtls_return_t noxtls_slhdsa_keygen(noxtls_slhdsa_param_t param,
                                     uint8_t *public_key,
                                     uint8_t *secret_key);
noxtls_return_t noxtls_slhdsa_sign(noxtls_slhdsa_param_t param,
                                   const uint8_t *secret_key,
                                   const uint8_t *noxtls_message,
                                   uint32_t message_len,
                                   uint8_t *signature,
                                   uint32_t *signature_len);
noxtls_return_t noxtls_slhdsa_verify(noxtls_slhdsa_param_t param,
                                     const uint8_t *public_key,
                                     const uint8_t *noxtls_message,
                                     uint32_t message_len,
                                     const uint8_t *signature,
                                     uint32_t signature_len);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_SLHDSA_H_ */
