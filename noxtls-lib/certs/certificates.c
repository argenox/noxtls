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
static const uint8_t CERT_BEGIN_BYTES[] = {
    0x2DU,0x2DU,0x2DU,0x2DU,0x2DU,0x42U,0x45U,0x47U,0x49U,0x4EU,0x20U,
    0x43U,0x45U,0x52U,0x54U,0x49U,0x46U,0x49U,0x43U,0x41U,0x54U,0x45U,
    0x2DU,0x2DU,0x2DU,0x2DU,0x2DU
};
static const uint8_t CERT_END_BYTES[] = {
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

/** Base64 characters plus '\n' emitted for one full PEM line of PEM_MAX_LINE_LEN_B64 DER bytes. */
#define CERT_PEM_FULL_LINE_OUT  (((PEM_MAX_LINE_LEN_B64 / BASE64_ENCODE_BLOCK_BYTES) * BASE64_ENCODE_OUTPUT_BYTES) + 1U)

/**
 * @brief PEM text length (without the NUL) produced for @p length DER bytes.
 *
 * Layout: BEGIN banner, '\n', base64 body wrapped at PEM_MAX_LINE_LEN_B64 input bytes per line
 * (each line ends with '\n'), END banner.
 *
 * @return Length in bytes, or 0 when the result would not fit in uint32_t.
 */
static uint32_t cert_pem_text_len(uint32_t length, uint32_t begin_len, uint32_t end_len)
{
    uint32_t full_lines = length / PEM_MAX_LINE_LEN_B64;
    uint32_t rem = length % PEM_MAX_LINE_LEN_B64;
    uint32_t total = begin_len + 1U + end_len;

    /* PEM is ~1.36x the DER size: bounding the input keeps every product below 2^32. */
    if(length > (UINT32_MAX / 2U)) {
        return 0U;
    }
    total += full_lines * CERT_PEM_FULL_LINE_OUT;
    if(rem != 0U) {
        total += (((rem + (BASE64_ENCODE_BLOCK_BYTES - 1U)) / BASE64_ENCODE_BLOCK_BYTES) * BASE64_ENCODE_OUTPUT_BYTES) + 1U;
    }
    return total;
}

/**
 * @brief Shared DER -> PEM writer that never writes past @p out_max.
 *
 * The full output size (PEM text plus NUL terminator) is computed before the first byte is
 * written, so a too-small buffer is rejected without being touched.
 *
 * @param[in]  begin      BEGIN banner bytes.
 * @param[in]  begin_len  Length of @p begin.
 * @param[in]  end        END banner bytes.
 * @param[in]  end_len    Length of @p end.
 * @param[in]  data       DER input.
 * @param[in]  length     Length of @p data (> 0).
 * @param[out] output     Output buffer (NUL-terminated on success).
 * @param[in]  out_max    Capacity of @p output in bytes, including room for the NUL.
 * @param[out] out_len    PEM length written, not counting the NUL.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_INVALID_PARAM for NULL/empty input, or
 *         NOXTLS_RETURN_FAILED when @p out_max is too small (nothing is written).
 */
static noxtls_return_t cert_der_to_pem_bounded(const uint8_t *begin, uint32_t begin_len,
                                               const uint8_t *end, uint32_t end_len,
                                               const uint8_t *data, uint32_t length,
                                               uint8_t *output, uint32_t out_max, uint32_t *out_len)
{
    uint32_t text_len = 0U;
    uint32_t pos = 0U;
    uint32_t remaining = 0U;
    const uint8_t *src = NULL;

    if((data == NULL) || (length == 0U) || (output == NULL) || (out_len == NULL)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    text_len = cert_pem_text_len(length, begin_len, end_len);
    if((text_len == 0U) || (text_len >= out_max)) {
        return NOXTLS_RETURN_FAILED;
    }

    cert_copy_bytes(output, begin, begin_len);
    pos = begin_len;
    output[pos] = (uint8_t)'\n';
    pos += 1U;

    src = data;
    remaining = length;
    while(remaining > 0U) {
        uint32_t write_len = (remaining > PEM_MAX_LINE_LEN_B64) ? PEM_MAX_LINE_LEN_B64 : remaining;
        int32_t result = noxtls_base64_encode(src, write_len, &output[pos]);
        if(result < 0) {
            return NOXTLS_RETURN_FAILED;
        }
        pos += (uint32_t)result;
        output[pos] = (uint8_t)'\n';
        pos += 1U;
        src = &src[write_len];
        remaining -= write_len;
    }

    cert_copy_bytes(&output[pos], end, end_len);
    pos += end_len;
    if(pos != text_len) {
        /* Cannot happen: the size computation mirrors the loop above. */
        return NOXTLS_RETURN_FAILED;
    }
    output[pos] = (uint8_t)'\0';
    *out_len = pos;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Converts a DER certificate to PEM, bounded by the output capacity.
 *
 * @param[in]  data     DER certificate.
 * @param[in]  length   Length of @p data.
 * @param[out] output   Output buffer; receives NUL-terminated PEM text.
 * @param[in]  out_max  Capacity of @p output, including the NUL terminator.
 * @param[out] out_len  PEM length, not counting the NUL.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_INVALID_PARAM, or NOXTLS_RETURN_FAILED when
 *         @p out_max is too small (the buffer is left untouched).
 */
noxtls_return_t noxtls_certificate_der_to_pem_ex(const uint8_t *data, uint32_t length, uint8_t *output,
                                                 uint32_t out_max, uint32_t *out_len)
{
    /* Touch banner table so PEM string macros stay live in this TU. */
    (void)cert_pem_banner_len(0U);
    return cert_der_to_pem_bounded(CERT_BEGIN_BYTES, (uint32_t)sizeof(CERT_BEGIN_BYTES),
                                   CERT_END_BYTES, (uint32_t)sizeof(CERT_END_BYTES),
                                   data, length, output, out_max, out_len);
}

/**
 * @brief Converts DER certificate to PEM (legacy, unbounded).
 *
 * @warning @p output must hold the whole PEM text plus a NUL terminator; this function cannot
 *          check it. Use noxtls_certificate_der_to_pem_ex() to pass the buffer capacity.
 */
noxtls_return_t noxtls_certificate_der_to_pem(const uint8_t * data, uint32_t length, uint8_t * output, uint32_t * out_len)
{
    return noxtls_certificate_der_to_pem_ex(data, length, output, UINT32_MAX, out_len);
}

/**
 * @brief Converts a DER PKCS#10 request to PEM, bounded by the output capacity.
 *
 * Same contract as noxtls_certificate_der_to_pem_ex() with CERTIFICATE REQUEST banners.
 */
noxtls_return_t noxtls_csr_der_to_pem_ex(const uint8_t *data, uint32_t length, uint8_t *output,
                                         uint32_t out_max, uint32_t *out_len)
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
    return cert_der_to_pem_bounded(cert_req_begin_bytes, (uint32_t)sizeof(cert_req_begin_bytes),
                                   cert_req_end_bytes, (uint32_t)sizeof(cert_req_end_bytes),
                                   data, length, output, out_max, out_len);
}

/**
 * @brief Converts a DER-encoded Certificate Signing Request (PKCS#10) to PEM format (legacy, unbounded).
 *
 * @warning @p output must hold the whole PEM text plus a NUL terminator; this function cannot
 *          check it. Use noxtls_csr_der_to_pem_ex() to pass the buffer capacity.
 */
noxtls_return_t noxtls_csr_der_to_pem(const uint8_t *data, uint32_t length, uint8_t *output, uint32_t *out_len)
{
    return noxtls_csr_der_to_pem_ex(data, length, output, UINT32_MAX, out_len);
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
