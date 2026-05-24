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
* File:    noxtls_mldsa.h
* Summary: ML-DSA (NIST FIPS 204) API surface.
*
*
*****************************************************************************/

#ifndef _NOXTLS_MLDSA_H_
#define _NOXTLS_MLDSA_H_

#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    NOXTLS_MLDSA_NONE = 0,
    NOXTLS_MLDSA_44 = 1,
    NOXTLS_MLDSA_65 = 2,
    NOXTLS_MLDSA_87 = 3
} noxtls_mldsa_param_t;

#define NOXTLS_MLDSA_MAX_PUBLIC_KEY_LEN 2592u
#define NOXTLS_MLDSA_MAX_SECRET_KEY_LEN 4896u
#define NOXTLS_MLDSA_MAX_SIGNATURE_LEN 4627u
#define NOXTLS_MLDSA_SEED_LEN 32U
#define NOXTLS_MLDSA_RND_LEN 32U
#define NOXTLS_MLDSA_MAX_CONTEXT_LEN 255u
#define NOXTLS_MLDSA_PURE_PRE_LEN (2U + NOXTLS_MLDSA_MAX_CONTEXT_LEN)
#define NOXTLS_MLDSA_TEST_OVERRIDE_PRE_LEN (3U + NOXTLS_MLDSA_MAX_CONTEXT_LEN)

typedef struct
{
    uint32_t public_key_len;
    uint32_t secret_key_len;
    uint32_t signature_len;
} mldsa_sizes_t;

uint32_t noxtls_mldsa_public_key_len(noxtls_mldsa_param_t param);
uint32_t noxtls_mldsa_secret_key_len(noxtls_mldsa_param_t param);
uint32_t noxtls_mldsa_signature_len(noxtls_mldsa_param_t param);
void noxtls_mldsa_set_test_seed_sequence(const uint8_t *bytes, uint32_t byte_len);
void noxtls_mldsa_set_test_signing_overrides(const uint8_t *pre,
                                             uint32_t pre_len,
                                             const uint8_t *rnd,
                                             uint32_t rnd_len,
                                             uint8_t externalmu);

noxtls_return_t noxtls_mldsa_keygen(noxtls_mldsa_param_t param,
                                    uint8_t *public_key,
                                    uint8_t *secret_key);
noxtls_return_t noxtls_mldsa_sign(noxtls_mldsa_param_t param,
                                  const uint8_t *secret_key,
                                  const uint8_t *noxtls_message,
                                  uint32_t message_len,
                                  uint8_t *signature,
                                  uint32_t *signature_len);
noxtls_return_t noxtls_mldsa_verify(noxtls_mldsa_param_t param,
                                    const uint8_t *public_key,
                                    const uint8_t *noxtls_message,
                                    uint32_t message_len,
                                    const uint8_t *signature,
                                    uint32_t signature_len);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_MLDSA_H_ */
