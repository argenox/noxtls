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

/**
 * DER -> PEM ("CERTIFICATE" banners). @p out_max is the capacity of @p output including the NUL
 * terminator; when the PEM text plus NUL does not fit, NOXTLS_RETURN_FAILED is returned and
 * @p output is not written. *out_len receives the PEM length without the NUL.
 */
noxtls_return_t noxtls_certificate_der_to_pem_ex(const uint8_t *data, uint32_t length, uint8_t *output,
                                                 uint32_t out_max, uint32_t *out_len);
/** DER -> PEM ("CERTIFICATE REQUEST" banners); same contract as noxtls_certificate_der_to_pem_ex(). */
noxtls_return_t noxtls_csr_der_to_pem_ex(const uint8_t *data, uint32_t length, uint8_t *output,
                                         uint32_t out_max, uint32_t *out_len);
/**
 * Capacity (PEM text plus NUL) that noxtls_certificate_der_to_pem_ex() needs for @p length DER
 * bytes; 0 when @p length is 0 or too large. PEM is not a fixed multiple of the DER size: short
 * inputs need more than twice their length because of the banners.
 */
uint32_t noxtls_certificate_pem_buffer_size(uint32_t length);
/**
 * Legacy unbounded forms (deprecated): @p output must hold the complete PEM text plus NUL
 * (noxtls_certificate_pem_buffer_size(length) bytes for certificates). Prefer the _ex variants,
 * which enforce the capacity.
 */
noxtls_return_t noxtls_certificate_der_to_pem(const uint8_t * data, uint32_t length, uint8_t * output, uint32_t * out_len);
noxtls_return_t noxtls_csr_der_to_pem(const uint8_t *data, uint32_t length, uint8_t *output, uint32_t *out_len);
/** PEM -> DER. @p output must hold at least @p length bytes (decoded DER is always shorter). */
noxtls_return_t noxtls_certificate_pem_to_der(const uint8_t * data, uint32_t length, uint8_t * output, uint32_t * out_len);

#ifdef __cplusplus
}
#endif

#endif
