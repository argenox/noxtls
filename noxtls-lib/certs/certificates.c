/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
*
* File:    certificates.c
* Summary: Certificates
*
*/

/** @addtogroup noxtls_certs */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <stddef.h>

#include "noxtls_common.h"
#include "certificates.h"
#include "base64.h"
#include "oids.h"


/**
 * @brief Converts DER certificate to PEM
 *
 * @param[in] data is a pointer to the DER data to convert
 * @param[in] length is the length of the DER data
 * @param[out] output is a pointer to a buffer to place the PEM data
 * @param[out] out_len is the length of data placed in output
 *
 * @note this function requires output have sufficient length to hold the
 *       data
 *
 * @return @see noxtls_return_t
 */
noxtls_return_t noxtls_certificate_der_to_pem(uint8_t * data, uint32_t length, uint8_t * output, uint32_t * out_len)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint8_t * ptr;
    int result;

    do
    {
        if(data == NULL || length == 0 || output == NULL || out_len == NULL) {
            rc = NOXTLS_RETURN_INVALID_PARAM;
            break;
        }

        ptr = output;

        memcpy(ptr, CERT_BEGIN_STR, strlen(CERT_BEGIN_STR));
        ptr += strlen(CERT_BEGIN_STR);
        *ptr++ = '\n';


        uint32_t write_len;
        while(length > 0)
        {
            const uint8_t *in_ptr = data;
            if(length > PEM_MAX_LINE_LEN_B64)
                write_len = PEM_MAX_LINE_LEN_B64;
            else
                write_len = length;

            result = noxtls_base64_encode(in_ptr, write_len, (char *)ptr);
            ptr += result;

            data += write_len;

            /* Add EOL */
            *ptr = '\n';
            ptr++;

            length -= write_len;
        }


        memcpy(ptr, CERT_END_STR, strlen(CERT_END_STR));
        ptr += strlen(CERT_END_STR);
        *ptr = '\0';

        {
            ptrdiff_t written = ptr - output;
            if(written < 0 || (unsigned long)written > UINT32_MAX) {
                rc = NOXTLS_RETURN_FAILED;
                break;
            }
            *out_len = (uint32_t)written;
        }
        rc = NOXTLS_RETURN_SUCCESS;

    } while(0);

    return rc;
}

/**
 * @brief Converts DER Certificate Signing Request (PKCS#10) to PEM.
 */
noxtls_return_t noxtls_csr_der_to_pem(uint8_t *data, uint32_t length, uint8_t *output, uint32_t *out_len)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    int result;

    do {
        if(data == NULL || length == 0 || output == NULL || out_len == NULL) {
            rc = NOXTLS_RETURN_INVALID_PARAM;
            break;
        }

        uint8_t *ptr = output;
        memcpy(ptr, CERT_REQ_BEGIN_STR, strlen(CERT_REQ_BEGIN_STR));
        ptr += strlen(CERT_REQ_BEGIN_STR);
        *ptr++ = '\n';

        while(length > 0) {
            const uint8_t *ptr_data = data;
            uint32_t write_len = (length > PEM_MAX_LINE_LEN_B64) ? PEM_MAX_LINE_LEN_B64 : length;
            result = noxtls_base64_encode(ptr_data, write_len, (char *)ptr);
            ptr += result;
            data += write_len;
            *ptr++ = '\n';
            length -= write_len;
        }
        
        memcpy(ptr, CERT_REQ_END_STR, strlen(CERT_REQ_END_STR));
        ptr += strlen(CERT_REQ_END_STR);
        *ptr = '\0';
        *out_len = (uint32_t)(ptr - output);
        rc = NOXTLS_RETURN_SUCCESS;

    } while(0);
    return rc;
}

/**
 * @brief Converts PEM certificate to DER
 *
 * @param[in] data is a pointer to the data to convert
 * @param[in] length is the length of the PEM data
 * @param[out] output is a pointer to a buffer to place the DER data
 * @param[out] out_len is the length of data placed in output
 *
 * @note this function requires output have sufficient length to hold the
 *       data
 *
 * @return @see noxtls_return_t
 */
noxtls_return_t noxtls_certificate_pem_to_der(uint8_t * data, uint32_t length, uint8_t * output, uint32_t * out_len)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    size_t begin_len = strlen(CERT_BEGIN_STR);
    size_t end_len = strlen(CERT_END_STR);

    do
    {
        if(data == NULL || length == 0 || output == NULL || out_len == NULL) {
            rc = NOXTLS_RETURN_INVALID_PARAM;
            break;
        }

        while(length > 0u) {
            unsigned char uc;

            uc = data[length - 1u];
            if(uc == (unsigned char)'\r' || uc == (unsigned char)'\n' || uc == (unsigned char)'\t' ||
               uc == (unsigned char)' ') {
                length--;
                continue;
            }
            break;
        }
        if(length == 0u) {
            rc = NOXTLS_RETURN_BAD_DATA;
            break;
        }

        if(begin_len > UINT32_MAX || end_len > UINT32_MAX) {
            rc = NOXTLS_RETURN_BAD_DATA;
            break;
        }
        if(length < (uint32_t)begin_len || length < (uint32_t)end_len) {
            rc = NOXTLS_RETURN_BAD_DATA;
            break;
        }
        if(length < (uint32_t)(begin_len + end_len)) {
            rc = NOXTLS_RETURN_BAD_DATA;
            break;
        }

        /* Ensure certificate contains start string */
        if(memcmp(data, CERT_BEGIN_STR, begin_len) != 0) {
            rc = NOXTLS_RETURN_BAD_DATA;
            break;
        }

        if(memcmp((void *)(data + length - end_len), CERT_END_STR, end_len) != 0) {
            rc = NOXTLS_RETURN_BAD_DATA;
            break;
        }

        {
            int dec;

            {
                uint32_t b64_len = length - (uint32_t)begin_len - (uint32_t)end_len;

                dec = noxtls_base64_decode((char *)&data[begin_len], b64_len, output);
            }
            if(dec <= 0) {
                rc = NOXTLS_RETURN_BAD_DATA;
                break;
            }
            *out_len = (uint32_t)dec;
        }

        rc = NOXTLS_RETURN_SUCCESS;

    } while(0);

    return rc;
}
