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
* File:    noxtls_lms.h
* Summary: LMS/HSS API surface (scaffold).
*
*****************************************************************************/

#ifndef _NOXTLS_LMS_H_
#define _NOXTLS_LMS_H_

#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    NOXTLS_LMS_NONE = 0,
    NOXTLS_LMS_SHA256_M32_H5 = 1,
    NOXTLS_LMS_SHA256_M32_H10 = 2,
    NOXTLS_LMS_SHA256_M32_H15 = 3,
    NOXTLS_HSS_SHA256_M32_H10_D2 = 4,
    NOXTLS_HSS_SHA256_M32_H15_D2 = 5
} noxtls_lms_param_t;

#define NOXTLS_LMS_MAX_PUBLIC_KEY_LEN  64U
#define NOXTLS_LMS_MAX_SECRET_KEY_LEN  256u
#define NOXTLS_LMS_MAX_SIGNATURE_LEN   8192u

uint32_t noxtls_lms_public_key_len(noxtls_lms_param_t param);
uint32_t noxtls_lms_secret_key_len(noxtls_lms_param_t param);
uint32_t noxtls_lms_signature_len(noxtls_lms_param_t param);

noxtls_return_t noxtls_lms_keygen(noxtls_lms_param_t param,
                                  uint8_t *public_key,
                                  uint32_t public_key_len,
                                  uint8_t *secret_key,
                                  uint32_t secret_key_len);

noxtls_return_t noxtls_lms_sign(noxtls_lms_param_t param,
                                const uint8_t *secret_key,
                                const uint8_t *message,
                                uint32_t message_len,
                                uint8_t *signature,
                                uint32_t *signature_len);

noxtls_return_t noxtls_lms_verify(noxtls_lms_param_t param,
                                  const uint8_t *public_key,
                                  const uint8_t *message,
                                  uint32_t message_len,
                                  const uint8_t *signature,
                                  uint32_t signature_len);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_LMS_H_ */

