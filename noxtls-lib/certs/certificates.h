/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
*
* File:    noxtls_certificates.h
* Summary: NoxTLS Certificate Definitions
*
*/

/** @addtogroup noxtls_certs */
/** @{ */

#ifndef _NOXTLS_CERTIFICATES_H_
#define _NOXTLS_CERTIFICATES_H_

#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CERT_BEGIN_STR    "-----BEGIN CERTIFICATE-----"
#define CERT_END_STR      "-----END CERTIFICATE-----"

#define CERT_PUB_KEY_STR  "-----BEGIN PUBLIC KEY-----"
#define CERT_PUB_KEY_END  "-----END PUBLIC KEY-----"

#define CERT_PRIV_KEY_STR "-----BEGIN PRIVATE KEY-----"
#define CERT_PRIV_KEY_END "-----END PRIVATE KEY-----"

#define CERT_REQ_BEGIN_STR "-----BEGIN CERTIFICATE REQUEST-----"
#define CERT_REQ_END_STR   "-----END CERTIFICATE REQUEST-----"

#define PEM_MAX_LINE_LEN        64
#define PEM_MAX_LINE_LEN_B64    48




noxtls_return_t noxtls_certificate_der_to_pem(uint8_t * data, uint32_t length, uint8_t * output, uint32_t * out_len);
noxtls_return_t noxtls_certificate_pem_to_der(uint8_t * data, uint32_t length, uint8_t * output, uint32_t * out_len);
noxtls_return_t noxtls_csr_der_to_pem(uint8_t *data, uint32_t length, uint8_t *output, uint32_t *out_len);

#ifdef __cplusplus
}
#endif

#endif
