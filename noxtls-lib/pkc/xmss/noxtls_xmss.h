/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_xmss.h
* Summary: XMSS/XMSS^MT API surface (scaffold).
*****************************************************************************/

#ifndef NOXTLS_XMSS_H_
#define NOXTLS_XMSS_H_

#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t noxtls_xmss_param_t;
#define NOXTLS_XMSS_NONE              ((noxtls_xmss_param_t)0U)
#define NOXTLS_XMSS_SHA2_10_256       ((noxtls_xmss_param_t)1U)
#define NOXTLS_XMSS_SHA2_16_256       ((noxtls_xmss_param_t)2U)
#define NOXTLS_XMSSMT_SHA2_20_2_256   ((noxtls_xmss_param_t)3U)
#define NOXTLS_XMSSMT_SHA2_20_4_256   ((noxtls_xmss_param_t)4U)

#define NOXTLS_XMSS_MAX_PUBLIC_KEY_LEN  128U
#define NOXTLS_XMSS_MAX_SECRET_KEY_LEN  256u
#define NOXTLS_XMSS_MAX_SIGNATURE_LEN   8192u

uint32_t noxtls_xmss_public_key_len(noxtls_xmss_param_t param);
uint32_t noxtls_xmss_secret_key_len(noxtls_xmss_param_t param);
uint32_t noxtls_xmss_signature_len(noxtls_xmss_param_t param);

noxtls_return_t noxtls_xmss_keygen(noxtls_xmss_param_t param,
                                   uint8_t *public_key,
                                   uint32_t public_key_len,
                                   uint8_t *secret_key,
                                   uint32_t secret_key_len);

noxtls_return_t noxtls_xmss_sign(noxtls_xmss_param_t param,
                                 const uint8_t *secret_key,
                                 const uint8_t *message,
                                 uint32_t message_len,
                                 uint8_t *signature,
                                 uint32_t *signature_len);

noxtls_return_t noxtls_xmss_verify(noxtls_xmss_param_t param,
                                   const uint8_t *public_key,
                                   const uint8_t *message,
                                   uint32_t message_len,
                                   const uint8_t *signature,
                                   uint32_t signature_len);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_XMSS_H_ */

