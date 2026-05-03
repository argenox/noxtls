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
    uint8_t * in_ptr;
    int result;

    do
    {
        if(data == NULL || length == 0 || output == NULL || out_len == NULL) {
            rc = NOXTLS_RETURN_INVALID_PARAM;
            break;
        }

        ptr = output;
        in_ptr = data;

        memcpy(ptr, CERT_BEGIN_STR, strlen(CERT_BEGIN_STR));
        ptr += strlen(CERT_BEGIN_STR);
        *ptr++ = '\n';


        uint32_t write_len;
        while(length > 0)
        {
            if(length > PEM_MAX_LINE_LEN_B64)
                write_len = PEM_MAX_LINE_LEN_B64;
            else
                write_len = length;

            result = noxtls_base64_encode(in_ptr, write_len, (char *)ptr);
            ptr += result;

            in_ptr += write_len;

            /* Add EOL */
            *ptr = '\n';
            ptr++;

            length -= write_len;
        }


        memcpy(ptr, CERT_END_STR, strlen(CERT_END_STR));
        ptr += strlen(CERT_END_STR);

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
    uint8_t *ptr;
    uint8_t *in_ptr = data;
    int result;

    do {
        if (data == NULL || length == 0 || output == NULL || out_len == NULL) {
            rc = NOXTLS_RETURN_INVALID_PARAM;
            break;
        }
        ptr = output;
        memcpy(ptr, CERT_REQ_BEGIN_STR, strlen(CERT_REQ_BEGIN_STR));
        ptr += strlen(CERT_REQ_BEGIN_STR);
        *ptr++ = '\n';

        while (length > 0) {
            uint32_t write_len = (length > PEM_MAX_LINE_LEN_B64) ? PEM_MAX_LINE_LEN_B64 : length;
            result = noxtls_base64_encode(in_ptr, write_len, (char *)ptr);
            ptr += result;
            in_ptr += write_len;
            *ptr++ = '\n';
            length -= write_len;
        }
        memcpy(ptr, CERT_REQ_END_STR, strlen(CERT_REQ_END_STR));
        ptr += strlen(CERT_REQ_END_STR);
        *out_len = (uint32_t)(ptr - output);
        rc = NOXTLS_RETURN_SUCCESS;
    } while (0);
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

    do
    {
        if(data == NULL || length == 0 || output == NULL || out_len == NULL) {
            rc = NOXTLS_RETURN_INVALID_PARAM;
            break;
        }

        /* Ensure certificate contains start string */
        if(memcmp(data, CERT_BEGIN_STR, strlen(CERT_BEGIN_STR)) != 0) {
            rc = NOXTLS_RETURN_BAD_DATA;
            break;
        }

        /* Ensure certificate contains start string */
        printf("data: %s\n", data);
        printf("End:  %s\n", (data + length - strlen(CERT_END_STR)));
        printf("Comp: %s\n", CERT_END_STR);

        printf("start: %x  %c\n", (data + length - strlen(CERT_END_STR))[0], (data + length - strlen(CERT_END_STR))[0]);

        if(memcmp((void *)(data + length - strlen(CERT_END_STR)), CERT_END_STR, strlen(CERT_END_STR)) != 0) {
            rc = NOXTLS_RETURN_BAD_DATA;
            printf("No End string\n");
            break;
        }

        printf("Here %d\n", __LINE__);

        {
            size_t begin_len = strlen(CERT_BEGIN_STR);
            size_t end_len = strlen(CERT_END_STR);
            if(begin_len + end_len > length) {
                rc = NOXTLS_RETURN_BAD_DATA;
                break;
            }
            if(begin_len > UINT32_MAX || end_len > UINT32_MAX) {
                rc = NOXTLS_RETURN_BAD_DATA;
                break;
            }
            printf("Here %d\n", __LINE__);
            {
                uint32_t len = length - (uint32_t)begin_len - (uint32_t)end_len;
                *out_len = (uint32_t)noxtls_base64_decode((char *)&data[begin_len], len, output);
            }
        }

        rc = NOXTLS_RETURN_SUCCESS;

    } while(0);

    return rc;
}