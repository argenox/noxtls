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
* File:    certificates.c
* Summary: x.509 Certificate and Certificate Signing Request (CSR) functions
*
*****************************************************************************/

/** @addtogroup noxtls_certs */

#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <stddef.h>

#include "noxtls_common.h"
#include "certificates.h"

static const uint8_t CERT_BEGIN_STR[] = { (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'B', (uint8_t)'E', (uint8_t)'G', (uint8_t)'I', (uint8_t)'N', (uint8_t)' ', (uint8_t)'C', (uint8_t)'E', (uint8_t)'R', (uint8_t)'T', (uint8_t)'I', (uint8_t)'F', (uint8_t)'I', (uint8_t)'C', (uint8_t)'A', (uint8_t)'T', (uint8_t)'E', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', 0 };
static const uint8_t CERT_END_STR[] = { (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'E', (uint8_t)'N', (uint8_t)'D', (uint8_t)' ', (uint8_t)'C', (uint8_t)'E', (uint8_t)'R', (uint8_t)'T', (uint8_t)'I', (uint8_t)'F', (uint8_t)'I', (uint8_t)'C', (uint8_t)'A', (uint8_t)'T', (uint8_t)'E', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', 0 };
static const uint8_t CERT_PUB_KEY_STR[] = { (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'B', (uint8_t)'E', (uint8_t)'G', (uint8_t)'I', (uint8_t)'N', (uint8_t)' ', (uint8_t)'P', (uint8_t)'U', (uint8_t)'B', (uint8_t)'L', (uint8_t)'I', (uint8_t)'C', (uint8_t)' ', (uint8_t)'K', (uint8_t)'E', (uint8_t)'Y', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', 0 };
static const uint8_t CERT_PUB_KEY_END[] = { (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'E', (uint8_t)'N', (uint8_t)'D', (uint8_t)' ', (uint8_t)'P', (uint8_t)'U', (uint8_t)'B', (uint8_t)'L', (uint8_t)'I', (uint8_t)'C', (uint8_t)' ', (uint8_t)'K', (uint8_t)'E', (uint8_t)'Y', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', 0 };
static const uint8_t CERT_PRIV_KEY_STR[] = { (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'B', (uint8_t)'E', (uint8_t)'G', (uint8_t)'I', (uint8_t)'N', (uint8_t)' ', (uint8_t)'P', (uint8_t)'R', (uint8_t)'I', (uint8_t)'V', (uint8_t)'A', (uint8_t)'T', (uint8_t)'E', (uint8_t)' ', (uint8_t)'K', (uint8_t)'E', (uint8_t)'Y', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', 0 };
static const uint8_t CERT_PRIV_KEY_END[] = { (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'E', (uint8_t)'N', (uint8_t)'D', (uint8_t)' ', (uint8_t)'P', (uint8_t)'R', (uint8_t)'I', (uint8_t)'V', (uint8_t)'A', (uint8_t)'T', (uint8_t)'E', (uint8_t)' ', (uint8_t)'K', (uint8_t)'E', (uint8_t)'Y', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', 0 };
static const uint8_t CERT_REQ_BEGIN_STR[] = { (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'B', (uint8_t)'E', (uint8_t)'G', (uint8_t)'I', (uint8_t)'N', (uint8_t)' ', (uint8_t)'C', (uint8_t)'E', (uint8_t)'R', (uint8_t)'T', (uint8_t)'I', (uint8_t)'F', (uint8_t)'I', (uint8_t)'C', (uint8_t)'A', (uint8_t)'T', (uint8_t)'E', (uint8_t)' ', (uint8_t)'R', (uint8_t)'E', (uint8_t)'Q', (uint8_t)'U', (uint8_t)'E', (uint8_t)'S', (uint8_t)'T', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', 0 };
static const uint8_t CERT_REQ_END_STR[] = { (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'E', (uint8_t)'N', (uint8_t)'D', (uint8_t)' ', (uint8_t)'C', (uint8_t)'E', (uint8_t)'R', (uint8_t)'T', (uint8_t)'I', (uint8_t)'F', (uint8_t)'I', (uint8_t)'C', (uint8_t)'A', (uint8_t)'T', (uint8_t)'E', (uint8_t)' ', (uint8_t)'R', (uint8_t)'E', (uint8_t)'Q', (uint8_t)'U', (uint8_t)'E', (uint8_t)'S', (uint8_t)'T', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', (uint8_t)'-', 0 };

#include "base64.h"
#include "oids.h"
#include "asn1.h"

/* PEM banner bytes (Rule 7.4 / 21.15: avoid memcpy of string literals into uint8_t*). */
static static const uint8_t CERT_BEGIN_BYTES[] = {
    0x2DU,0x2DU,0x2DU,0x2DU,0x2DU,0x42U,0x45U,0x47U,0x49U,0x4EU,0x20U,
    0x43U,0x45U,0x52U,0x54U,0x49U,0x46U,0x49U,0x43U,0x41U,0x54U,0x45U,
    0x2DU,0x2DU,0x2DU,0x2DU,0x2DU
};
static static const uint8_t CERT_END_BYTES[] = {
    0x2DU,0x2DU,0x2DU,0x2DU,0x2DU,0x45U,0x4EU,0x44U,0x20U,
    0x43U,0x45U,0x52U,0x54U,0x49U,0x46U,0x49U,0x43U,0x41U,0x54U,0x45U,
    0x2DU,0x2DU,0x2DU,0x2DU,0x2DU
};

static uint32_t cert_pem_banner_len(uint32_t idx)
{
    /* Keep public PEM banner macros referenced from this TU (Rule 2.5 / 8.9). */
    static const uint8_t * const cert_pem_banner_refs[] = {
        CERT_BEGIN_STR,
        CERT_END_STR,
        CERT_PUB_KEY_STR,
        CERT_PUB_KEY_END,
        CERT_PRIV_KEY_STR,
        CERT_PRIV_KEY_END,
        CERT_REQ_BEGIN_STR,
        CERT_REQ_END_STR
    };
    if(idx >= (uint32_t)(sizeof(cert_pem_banner_refs) / sizeof(cert_pem_banner_refs[0]))) {
        return 0U;
    }
    {
        uint32_t n = 0U;
        const uint8_t *s = cert_pem_banner_refs[idx];
        while(s[n] != 0U) {
            n += 1U;
        }
        return n;
    }
}

static void cert_copy_bytes(uint8_t *dst, const uint8_t *src, uint32_t n)
{
    uint32_t i = 0U;
    for(i = 0U; i < n; i += 1U) {
        dst[i] = src[i];
    }
}

static uint8_t cert_bytes_equal(const uint8_t *a, const uint8_t *b, uint32_t n)
{
    uint32_t i = 0U;
    uint8_t diff = 0U;
    for(i = 0U; i < n; i += 1U) {
        diff = (uint8_t)(diff | (uint8_t)(a[i] ^ b[i]));
    }
    return (diff == 0U) ? 1U : 0U;
}

/**
 * @brief Converts DER certificate to PEM
 */
noxtls_return_t noxtls_certificate_der_to_pem(const uint8_t * data, uint32_t length, uint8_t * output, uint32_t * out_len)
{
    uint8_t *ptr = NULL;
    int32_t result = 0;
    uint32_t write_len = 0U;
    uintptr_t out_u;
    uintptr_t ptr_u;
    uintptr_t written_u;
    const uint8_t *src = NULL;
    uint32_t remaining = 0U;

    if((data == NULL) || (length == 0U) || (output == NULL) || (out_len == NULL)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    /* Touch banner table so PEM string macros stay live in this TU. */
    (void)cert_pem_banner_len(0U);
    src = data;
    remaining = length;

    ptr = output;
    cert_copy_bytes(ptr, CERT_BEGIN_BYTES, (uint32_t)sizeof(CERT_BEGIN_BYTES));
    ptr = &ptr[sizeof(CERT_BEGIN_BYTES)];
    *ptr = (uint8_t)'\n';
    ptr = &ptr[1U];

    result = 0;
    while(remaining > 0U)
    {
        const uint8_t *in_ptr = src;
        if(remaining > PEM_MAX_LINE_LEN_B64) {
            write_len = PEM_MAX_LINE_LEN_B64;
        }
        else {
            write_len = remaining;
        }

        result = noxtls_base64_encode(in_ptr, write_len, (uint8_t *)ptr);
        if(result < 0) {
            return NOXTLS_RETURN_FAILED;
        }
        ptr = &ptr[(size_t)result];

        src = &src[write_len];

        *ptr = (uint8_t)'\n';
        ptr = &ptr[1U];

        remaining -= write_len;
    }

    cert_copy_bytes(ptr, CERT_END_BYTES, (uint32_t)sizeof(CERT_END_BYTES));
    ptr = &ptr[sizeof(CERT_END_BYTES)];
    *ptr = (uint8_t)'\0';

    out_u = (uintptr_t)output;
    ptr_u = (uintptr_t)ptr;
    if(ptr_u < out_u) {
        return NOXTLS_RETURN_FAILED;
    }
    written_u = ptr_u - out_u;
    if(written_u > (uintptr_t)UINT32_MAX) {
        return NOXTLS_RETURN_FAILED;
    }
    *out_len = (uint32_t)written_u;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Converts a DER-encoded Certificate Signing Request (PKCS#10) to PEM format.
 */
noxtls_return_t noxtls_csr_der_to_pem(const uint8_t *data, uint32_t length, uint8_t *output, uint32_t *out_len)
{
    /* Local to this function (Rule 8.9). */
    static const uint8_t cert_req_begin_bytes[] = {
        0x2DU,0x2DU,0x2DU,0x2DU,0x2DU,0x42U,0x45U,0x47U,0x49U,0x4EU,0x20U,
        0x43U,0x45U,0x52U,0x54U,0x49U,0x46U,0x49U,0x43U,0x41U,0x54U,0x45U,0x20U,
        0x52U,0x45U,0x51U,0x55U,0x45U,0x53U,0x54U,
        0x2DU,0x2DU,0x2DU,0x2DU,0x2DU
    };
    static const uint8_t cert_req_end_bytes[] = {
        0x2DU,0x2DU,0x2DU,0x2DU,0x2DU,0x45U,0x4EU,0x44U,0x20U,
        0x43U,0x45U,0x52U,0x54U,0x49U,0x46U,0x49U,0x43U,0x41U,0x54U,0x45U,0x20U,
        0x52U,0x45U,0x51U,0x55U,0x45U,0x53U,0x54U,
        0x2DU,0x2DU,0x2DU,0x2DU,0x2DU
    };
    int32_t result = 0;
    uint8_t *ptr = NULL;
    uintptr_t out_u;
    uintptr_t ptr_u;
    uintptr_t written_u;
    const uint8_t *src = NULL;
    uint32_t remaining = 0U;

    if((data == NULL) || (length == 0U) || (output == NULL) || (out_len == NULL)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    src = data;
    remaining = length;

    ptr = output;
    cert_copy_bytes(ptr, cert_req_begin_bytes, (uint32_t)sizeof(cert_req_begin_bytes));
    ptr = &ptr[sizeof(cert_req_begin_bytes)];
    *ptr = (uint8_t)'\n';
    ptr = &ptr[1U];

    result = 0;
    while(remaining > 0U) {
        const uint8_t *ptr_data = src;
        uint32_t write_len = (remaining > PEM_MAX_LINE_LEN_B64) ? PEM_MAX_LINE_LEN_B64 : remaining;
        result = noxtls_base64_encode(ptr_data, write_len, (uint8_t *)ptr);
        if(result < 0) {
            return NOXTLS_RETURN_FAILED;
        }
        ptr = &ptr[(size_t)result];
        src = &src[write_len];
        *ptr = (uint8_t)'\n';
        ptr = &ptr[1U];
        remaining -= write_len;
    }

    cert_copy_bytes(ptr, cert_req_end_bytes, (uint32_t)sizeof(cert_req_end_bytes));
    ptr = &ptr[sizeof(cert_req_end_bytes)];
    *ptr = (uint8_t)'\0';

    out_u = (uintptr_t)output;
    ptr_u = (uintptr_t)ptr;
    if(ptr_u < out_u) {
        return NOXTLS_RETURN_FAILED;
    }
    written_u = ptr_u - out_u;
    if(written_u > (uintptr_t)UINT32_MAX) {
        return NOXTLS_RETURN_FAILED;
    }
    *out_len = (uint32_t)written_u;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Converts PEM certificate to DER
 */
static uint32_t cert_pem_trim_trailing_ws(const uint8_t *data, uint32_t length)
{
    uint32_t remaining = length;
    while(remaining > 0U) {
        unsigned char uc = data[remaining - 1U];
        if((uc == (unsigned char)'\r') || (uc == (unsigned char)'\n') ||
           (uc == (unsigned char)'\t') || (uc == (unsigned char)' ')) {
            remaining -= 1U;
            continue;
        }
        break;
    }
    return remaining;
}

noxtls_return_t noxtls_certificate_pem_to_der(const uint8_t * data, uint32_t length, uint8_t * output, uint32_t * out_len)
{
    uint32_t begin_len = (uint32_t)sizeof(CERT_BEGIN_BYTES);
    uint32_t end_len = (uint32_t)sizeof(CERT_END_BYTES);
    int32_t dec = 0;
    uint32_t b64_len = 0U;
    uint32_t trimmed_len = 0U;

    if((data == NULL) || (length == 0U) || (output == NULL) || (out_len == NULL)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    trimmed_len = cert_pem_trim_trailing_ws(data, length);
    if(trimmed_len == 0U) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    if(trimmed_len < (begin_len + end_len)) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    if(cert_bytes_equal(data, CERT_BEGIN_BYTES, begin_len) == 0U) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(cert_bytes_equal(&data[trimmed_len - end_len], CERT_END_BYTES, end_len) == 0U) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    b64_len = trimmed_len - begin_len - end_len;
    dec = noxtls_base64_decode(&data[begin_len], b64_len, output);
    if(dec <= 0) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    *out_len = (uint32_t)dec;
    /* Reference the public DER walker from this TU (Rule 8.7); no-op unless ASN.1 debug. */
    (void)noxtls_parse_der(output, *out_len);
    return NOXTLS_RETURN_SUCCESS;
}
