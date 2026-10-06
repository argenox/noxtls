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

#ifndef NOXTLS_CERTIFICATES_H_
#define NOXTLS_CERTIFICATES_H_

#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif



/* Private-key PEM banners used by certgen / tooling. */

/* CSR PEM banners used by certgen / tooling. */


#define PEM_MAX_LINE_LEN_B64    48U

noxtls_return_t noxtls_certificate_der_to_pem(const uint8_t * data, uint32_t length, uint8_t * output, uint32_t * out_len);
noxtls_return_t noxtls_certificate_pem_to_der(const uint8_t * data, uint32_t length, uint8_t * output, uint32_t * out_len);
noxtls_return_t noxtls_csr_der_to_pem(const uint8_t *data, uint32_t length, uint8_t *output, uint32_t *out_len);

#ifdef __cplusplus
}
#endif

#endif
