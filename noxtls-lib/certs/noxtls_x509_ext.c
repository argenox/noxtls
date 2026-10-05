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
* File:    noxtls_x509_ext.c
* Summary: Strict raw X.509 v3 extension lookup by OID
*
*****************************************************************************/

/**
 * @file noxtls_x509_ext.c
 * @brief Strict DER walker that exposes raw X.509 v3 extensions by OID.
 * @ingroup noxtls_x509_ext
 *
 * RFC 5280 Section 4.1/4.2 structure, ITU-T X.690 (08/2015) DER rules.
 */

#include <string.h>

#include "noxtls_x509_ext.h"

/** Mask selecting the long-form flag of a DER length octet (X.690 8.1.3.5). */
#define X509_EXT_LENGTH_LONG_FORM    0x80U
/** Mask selecting the count of long-form length octets (X.690 8.1.3.5). */
#define X509_EXT_LENGTH_COUNT_MASK   0x7FU
/** Smallest length that needs the long form under DER (X.690 10.1). */
#define X509_EXT_LENGTH_SHORT_LIMIT  0x80U
/** Continuation bit of a base-128 OID sub-identifier octet (X.690 8.19.2). */
#define X509_EXT_OID_CONTINUATION    0x80U
/** Minimum TLV size: one tag octet and one length octet. */
#define X509_EXT_TLV_HEADER_MIN      2U

/**
 * @brief Read one DER TLV with the expected tag and a minimal definite length.
 * @internal
 *
 * @param[in,out] pos Cursor; advanced past the TLV on success.
 * @param[in] end End of the enclosing value.
 * @param[in] expected_tag Required identifier octet.
 * @param[out] value Start of the content octets.
 * @param[out] value_len Content length.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_BAD_DATA.
 */
static noxtls_return_t x509_ext_read_tlv(const uint8_t **pos,
                                         const uint8_t *end,
                                         uint8_t expected_tag,
                                         const uint8_t **value,
                                         uint32_t *value_len)
{
    const uint8_t *p = *pos;
    uint32_t remaining;
    uint32_t length;
    uint8_t first;

    if((p > end) || ((uint32_t)(end - p) < X509_EXT_TLV_HEADER_MIN) || (p[0] != expected_tag)) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    first = p[1];
    p += X509_EXT_TLV_HEADER_MIN;
    remaining = (uint32_t)(end - p);
    if((first & X509_EXT_LENGTH_LONG_FORM) == 0U) {
        length = first;
    } else {
        uint32_t count = (uint32_t)(first & X509_EXT_LENGTH_COUNT_MASK);
        uint32_t i;

        /* X.690 10.1: indefinite form is forbidden in DER. */
        if((count == 0U) || (count > NOXTLS_X509_EXT_MAX_LENGTH_OCTETS) || (count > remaining)) {
            return NOXTLS_RETURN_BAD_DATA;
        }

        /* X.690 10.1: the length must use the minimum number of octets. */
        if(p[0] == 0U) {
            return NOXTLS_RETURN_BAD_DATA;
        }

        length = 0U;
        for(i = 0U; i < count; i++) {
            length = (length << 8) | (uint32_t)p[i];
        }

        if(length < X509_EXT_LENGTH_SHORT_LIMIT) {
            return NOXTLS_RETURN_BAD_DATA;
        }

        p += count;
        remaining -= count;
    }

    if(length > remaining) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    *value = p;
    *value_len = length;
    *pos = p + length;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Validate OID content octets (X.690 Section 8.19).
 * @internal
 *
 * @param[in] oid OID content octets.
 * @param[in] oid_len Length of @p oid.
 *
 * @return 1 when every sub-identifier is minimally encoded and terminated, else 0.
 */
static int x509_ext_oid_is_valid(const uint8_t *oid, uint32_t oid_len)
{
    uint32_t i;
    int at_start = 1;

    if((oid == NULL) || (oid_len == 0U) ||
       ((oid[oid_len - 1U] & X509_EXT_OID_CONTINUATION) != 0U)) {
        return 0;
    }

    for(i = 0U; i < oid_len; i++) {
        /* X.690 8.19.2: a sub-identifier must not start with 0x80. */
        if((at_start != 0) && (oid[i] == X509_EXT_OID_CONTINUATION)) {
            return 0;
        }

        at_start = ((oid[i] & X509_EXT_OID_CONTINUATION) == 0U) ? 1 : 0;
    }

    return 1;
}

noxtls_return_t noxtls_x509_extension_iter_init_der(noxtls_x509_extension_iter_t *iter,
                                                    const uint8_t *extensions_der,
                                                    uint32_t extensions_len)
{
    const uint8_t *pos;
    const uint8_t *end;
    const uint8_t *contents = NULL;
    uint32_t contents_len = 0U;
    noxtls_return_t rc;

    if(iter == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    iter->next = NULL;
    iter->end = NULL;
    if(extensions_len == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }

    if(extensions_der == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    pos = extensions_der;
    end = extensions_der + extensions_len;
    rc = x509_ext_read_tlv(&pos, end, NOXTLS_X509_EXT_TAG_SEQUENCE, &contents, &contents_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    /* The [3] EXPLICIT wrapper holds exactly one SEQUENCE; RFC 5280 4.1 requires SIZE (1..MAX). */
    if((pos != end) || (contents_len == 0U)) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    iter->next = contents;
    iter->end = contents + contents_len;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_x509_extension_iter_init(noxtls_x509_extension_iter_t *iter,
                                                const x509_certificate_t *cert)
{
    if((iter == NULL) || (cert == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    iter->next = NULL;
    iter->end = NULL;
    if(cert->parsed == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    if(cert->extensions == NULL) {
        return NOXTLS_RETURN_SUCCESS;
    }

    return noxtls_x509_extension_iter_init_der(iter, cert->extensions, cert->extensions_len);
}

noxtls_return_t noxtls_x509_extension_iter_next(noxtls_x509_extension_iter_t *iter,
                                                noxtls_x509_extension_t *ext,
                                                int *has_ext)
{
    const uint8_t *start;
    const uint8_t *pos;
    const uint8_t *body = NULL;
    const uint8_t *body_end;
    uint32_t body_len = 0U;
    const uint8_t *field = NULL;
    uint32_t field_len = 0U;
    noxtls_x509_extension_t decoded;
    noxtls_return_t rc;

    if((iter == NULL) || (ext == NULL) || (has_ext == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    *has_ext = 0;
    if((iter->next == NULL) || (iter->next >= iter->end)) {
        return NOXTLS_RETURN_SUCCESS;
    }

    memset(&decoded, 0, sizeof(decoded));
    start = iter->next;
    pos = start;
    rc = x509_ext_read_tlv(&pos, iter->end, NOXTLS_X509_EXT_TAG_SEQUENCE, &body, &body_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        iter->next = iter->end;
        return rc;
    }

    body_end = body + body_len;
    rc = x509_ext_read_tlv(&body, body_end, NOXTLS_X509_EXT_TAG_OID, &field, &field_len);
    if((rc != NOXTLS_RETURN_SUCCESS) || (x509_ext_oid_is_valid(field, field_len) == 0)) {
        iter->next = iter->end;
        return NOXTLS_RETURN_BAD_DATA;
    }

    decoded.oid = field;
    decoded.oid_len = field_len;
    if((body < body_end) && (body[0] == NOXTLS_X509_EXT_TAG_BOOLEAN)) {
        rc = x509_ext_read_tlv(&body, body_end, NOXTLS_X509_EXT_TAG_BOOLEAN, &field, &field_len);
        if((rc != NOXTLS_RETURN_SUCCESS) || (field_len != 1U) ||
           ((field[0] != NOXTLS_X509_EXT_DER_TRUE) && (field[0] != NOXTLS_X509_EXT_DER_FALSE))) {
            iter->next = iter->end;
            return NOXTLS_RETURN_BAD_DATA;
        }

        decoded.critical = (field[0] == NOXTLS_X509_EXT_DER_TRUE) ? 1U : 0U;
    }

    rc = x509_ext_read_tlv(&body, body_end, NOXTLS_X509_EXT_TAG_OCTET_STRING, &field, &field_len);
    if((rc != NOXTLS_RETURN_SUCCESS) || (body != body_end)) {
        iter->next = iter->end;
        return NOXTLS_RETURN_BAD_DATA;
    }

    decoded.value = field;
    decoded.value_len = field_len;
    decoded.der = start;
    decoded.der_len = (uint32_t)(pos - start);
    iter->next = pos;
    *ext = decoded;
    *has_ext = 1;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_x509_extensions_find_der(const uint8_t *extensions_der,
                                                uint32_t extensions_len,
                                                const uint8_t *oid,
                                                uint32_t oid_len,
                                                noxtls_x509_extension_t *ext,
                                                int *found)
{
    noxtls_x509_extension_iter_t iter;
    noxtls_x509_extension_t current;
    noxtls_x509_extension_t match;
    int has_ext = 0;
    int matched = 0;
    noxtls_return_t rc;

    if((oid == NULL) || (ext == NULL) || (found == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    *found = 0;
    if(oid_len == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    memset(&match, 0, sizeof(match));
    rc = noxtls_x509_extension_iter_init_der(&iter, extensions_der, extensions_len);
    while(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_x509_extension_iter_next(&iter, &current, &has_ext);
        if((rc != NOXTLS_RETURN_SUCCESS) || (has_ext == 0)) {
            break;
        }

        if((current.oid_len == oid_len) && (memcmp(current.oid, oid, oid_len) == 0)) {
            if(matched != 0) {
                /* RFC 5280 4.2: at most one instance of a particular extension. */
                return NOXTLS_RETURN_BAD_DATA;
            }

            match = current;
            matched = 1;
        }
    }

    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(matched != 0) {
        *ext = match;
        *found = 1;
    }

    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_x509_certificate_find_extension(const x509_certificate_t *cert,
                                                       const uint8_t *oid,
                                                       uint32_t oid_len,
                                                       noxtls_x509_extension_t *ext,
                                                       int *found)
{
    if((cert == NULL) || (found == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    *found = 0;
    if(cert->parsed == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    return noxtls_x509_extensions_find_der(cert->extensions,
                                           (cert->extensions != NULL) ? cert->extensions_len : 0U,
                                           oid, oid_len, ext, found);
}

int noxtls_x509_oid_is_under_arc(const uint8_t *oid,
                                 uint32_t oid_len,
                                 const uint8_t *arc,
                                 uint32_t arc_len)
{
    if((oid == NULL) || (arc == NULL) || (arc_len == 0U) || (oid_len <= arc_len) ||
       ((arc[arc_len - 1U] & X509_EXT_OID_CONTINUATION) != 0U)) {
        return 0;
    }

    return (memcmp(oid, arc, arc_len) == 0) ? 1 : 0;
}
