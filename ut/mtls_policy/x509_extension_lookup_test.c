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
* File:    x509_extension_lookup_test.c
* Summary: Positive and negative tests for raw X.509 extension lookup
*
*****************************************************************************/

#include <stdio.h>
#include <string.h>

#include "noxtls_x509.h"
#include "noxtls_x509_ext.h"
#include "mtls_test_pki.h"

#define CHECK(cond) do { if(!(cond)) { fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); return 1; } } while(0)

/* 1.3.6.1.4.1.44970 and selected attributes (content octets). */
static const uint8_t k_arc[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDF, 0x2A };
static const uint8_t k_oid_auth[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDF, 0x2A, 0x03 };
static const uint8_t k_oid_domain[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDF, 0x2A, 0x01 };
static const uint8_t k_oid_absent[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDF, 0x2A, 0x04 };
static const uint8_t k_auth_value[] = { 0x04, 0x05, 0x21, 0x01, 0x01, 0x01, 0x01 };

static int find_in(const uint8_t *der, uint32_t len, noxtls_return_t expected, int expected_found)
{
    noxtls_x509_extension_t ext;
    int found = -1;
    noxtls_return_t rc = noxtls_x509_extensions_find_der(der, len, k_oid_auth, sizeof(k_oid_auth),
                                                         &ext, &found);
    CHECK(rc == expected);
    CHECK(found == expected_found);
    return 0;
}

static int test_certificate_lookup(void)
{
    x509_certificate_t cert;
    noxtls_x509_extension_t ext;
    noxtls_x509_extension_iter_t iter;
    int found = 0;
    int has = 0;
    uint32_t count = 0U;
    uint32_t under_arc = 0U;

    noxtls_x509_certificate_init(&cert);
    CHECK(noxtls_x509_certificate_find_extension(&cert, k_oid_auth, sizeof(k_oid_auth), &ext, &found) ==
          NOXTLS_RETURN_FAILED);
    CHECK(noxtls_x509_extension_iter_init(&iter, &cert) == NOXTLS_RETURN_FAILED);
    CHECK(noxtls_x509_certificate_parse_der(&cert, mtls_client_cert, sizeof(mtls_client_cert)) ==
          NOXTLS_RETURN_SUCCESS);

    CHECK(noxtls_x509_certificate_find_extension(&cert, k_oid_auth, sizeof(k_oid_auth), &ext, &found) ==
          NOXTLS_RETURN_SUCCESS);
    CHECK(found == 1);
    CHECK(ext.critical == 0U);
    CHECK(ext.value_len == sizeof(k_auth_value));
    CHECK(memcmp(ext.value, k_auth_value, sizeof(k_auth_value)) == 0);
    CHECK(ext.der[0] == NOXTLS_X509_EXT_TAG_SEQUENCE);
    CHECK(ext.oid_len == sizeof(k_oid_auth));
    CHECK(ext.der + ext.der_len == ext.value + ext.value_len);

    CHECK(noxtls_x509_certificate_find_extension(&cert, k_oid_domain, sizeof(k_oid_domain), &ext, &found) ==
          NOXTLS_RETURN_SUCCESS);
    CHECK(found == 1);
    CHECK(ext.value_len == 15U);
    CHECK(memcmp(ext.value + 2, "DefaultDomain", 13U) == 0);

    CHECK(noxtls_x509_certificate_find_extension(&cert, k_oid_absent, sizeof(k_oid_absent), &ext, &found) ==
          NOXTLS_RETURN_SUCCESS);
    CHECK(found == 0);
    CHECK(noxtls_x509_certificate_find_extension(&cert, k_oid_auth, 0U, &ext, &found) ==
          NOXTLS_RETURN_INVALID_PARAM);
    CHECK(noxtls_x509_certificate_find_extension(NULL, k_oid_auth, sizeof(k_oid_auth), &ext, &found) ==
          NOXTLS_RETURN_NULL);
    CHECK(noxtls_x509_certificate_find_extension(&cert, k_oid_auth, sizeof(k_oid_auth), &ext, NULL) ==
          NOXTLS_RETURN_NULL);
    CHECK(noxtls_x509_certificate_find_extension(&cert, NULL, sizeof(k_oid_auth), &ext, &found) ==
          NOXTLS_RETURN_NULL);

    CHECK(noxtls_x509_extension_iter_init(&iter, &cert) == NOXTLS_RETURN_SUCCESS);
    for(;;) {
        CHECK(noxtls_x509_extension_iter_next(&iter, &ext, &has) == NOXTLS_RETURN_SUCCESS);
        if(has == 0) {
            break;
        }

        count++;
        if(noxtls_x509_oid_is_under_arc(ext.oid, ext.oid_len, k_arc, sizeof(k_arc)) != 0) {
            under_arc++;
        }
    }

    /* BasicConstraints, KeyUsage, EKU, SKI, domain attribute, authorization attribute. */
    CHECK(count == 6U);
    CHECK(under_arc == 2U);
    CHECK(noxtls_x509_extension_iter_next(&iter, &ext, &has) == NOXTLS_RETURN_SUCCESS);
    CHECK(has == 0);
    CHECK(noxtls_x509_extension_iter_next(NULL, &ext, &has) == NOXTLS_RETURN_NULL);
    CHECK(noxtls_x509_extension_iter_next(&iter, NULL, &has) == NOXTLS_RETURN_NULL);
    CHECK(noxtls_x509_extension_iter_next(&iter, &ext, NULL) == NOXTLS_RETURN_NULL);
    CHECK(noxtls_x509_extension_iter_init(NULL, &cert) == NOXTLS_RETURN_NULL);
    CHECK(noxtls_x509_extension_iter_init(&iter, NULL) == NOXTLS_RETURN_NULL);
    noxtls_x509_certificate_free(&cert);

    /* A parsed certificate with no extensions yields an empty iterator. */
    noxtls_x509_certificate_init(&cert);
    cert.parsed = 1;
    CHECK(noxtls_x509_extension_iter_init(&iter, &cert) == NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_extension_iter_next(&iter, &ext, &has) == NOXTLS_RETURN_SUCCESS);
    CHECK(has == 0);
    CHECK(noxtls_x509_certificate_find_extension(&cert, k_oid_auth, sizeof(k_oid_auth), &ext, &found) ==
          NOXTLS_RETURN_SUCCESS);
    CHECK(found == 0);
    return 0;
}

static int test_oid_arc(void)
{
    static const uint8_t open_arc[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82 };
    static const uint8_t other[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDF, 0x2B, 0x03 };

    CHECK(noxtls_x509_oid_is_under_arc(k_oid_auth, sizeof(k_oid_auth), k_arc, sizeof(k_arc)) == 1);
    CHECK(noxtls_x509_oid_is_under_arc(k_arc, sizeof(k_arc), k_arc, sizeof(k_arc)) == 0);
    CHECK(noxtls_x509_oid_is_under_arc(other, sizeof(other), k_arc, sizeof(k_arc)) == 0);
    CHECK(noxtls_x509_oid_is_under_arc(k_oid_auth, sizeof(k_oid_auth), open_arc, sizeof(open_arc)) == 0);
    CHECK(noxtls_x509_oid_is_under_arc(NULL, 9U, k_arc, sizeof(k_arc)) == 0);
    CHECK(noxtls_x509_oid_is_under_arc(k_oid_auth, sizeof(k_oid_auth), NULL, 1U) == 0);
    CHECK(noxtls_x509_oid_is_under_arc(k_oid_auth, sizeof(k_oid_auth), k_arc, 0U) == 0);
    return 0;
}

static int test_handcrafted_der(void)
{
    /* SEQUENCE { Extension { OID .3, OCTET STRING { 05 } } } */
    static const uint8_t ok[] = {
        0x30, 0x10, 0x30, 0x0E, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDF, 0x2A, 0x03,
        0x04, 0x01, 0x05
    };
    static const uint8_t critical_true[] = {
        0x30, 0x13, 0x30, 0x11, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDF, 0x2A, 0x03,
        0x01, 0x01, 0xFF, 0x04, 0x01, 0x05
    };
    static const uint8_t critical_false[] = {
        0x30, 0x13, 0x30, 0x11, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDF, 0x2A, 0x03,
        0x01, 0x01, 0x00, 0x04, 0x01, 0x05
    };
    static const uint8_t critical_ber_true[] = {
        0x30, 0x13, 0x30, 0x11, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDF, 0x2A, 0x03,
        0x01, 0x01, 0x01, 0x04, 0x01, 0x05
    };
    static const uint8_t critical_long_bool[] = {
        0x30, 0x14, 0x30, 0x12, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDF, 0x2A, 0x03,
        0x01, 0x02, 0xFF, 0xFF, 0x04, 0x01, 0x05
    };
    static const uint8_t duplicate[] = {
        0x30, 0x20,
        0x30, 0x0E, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDF, 0x2A, 0x03, 0x04, 0x01, 0x05,
        0x30, 0x0E, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDF, 0x2A, 0x03, 0x04, 0x01, 0x06
    };
    static const uint8_t indefinite[] = { 0x30, 0x80, 0x00, 0x00 };
    static const uint8_t non_minimal[] = {
        0x30, 0x81, 0x10, 0x30, 0x0E, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDF, 0x2A,
        0x03, 0x04, 0x01, 0x05
    };
    static const uint8_t leading_zero[] = { 0x30, 0x82, 0x00, 0x90 };
    static const uint8_t too_many_octets[] = { 0x30, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00 };
    static const uint8_t truncated_length[] = { 0x30, 0x82, 0x01 };
    static const uint8_t overlong[] = { 0x30, 0x20, 0x30, 0x00 };
    static const uint8_t trailing_outer[] = {
        0x30, 0x10, 0x30, 0x0E, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDF, 0x2A, 0x03,
        0x04, 0x01, 0x05, 0x00
    };
    static const uint8_t trailing_inner[] = {
        0x30, 0x12, 0x30, 0x10, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDF, 0x2A, 0x03,
        0x04, 0x01, 0x05, 0x05, 0x00
    };
    static const uint8_t missing_value[] = {
        0x30, 0x0D, 0x30, 0x0B, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDF, 0x2A, 0x03
    };
    static const uint8_t bad_oid[] = {
        0x30, 0x10, 0x30, 0x0E, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x80, 0xDF, 0x2A, 0x03,
        0x04, 0x01, 0x05
    };
    static const uint8_t unterminated_oid[] = {
        0x30, 0x10, 0x30, 0x0E, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDF, 0x2A, 0x83,
        0x04, 0x01, 0x05
    };
    static const uint8_t empty_oid[] = { 0x30, 0x07, 0x30, 0x05, 0x06, 0x00, 0x04, 0x01, 0x05 };
    static const uint8_t empty_list[] = { 0x30, 0x00 };
    static const uint8_t wrong_outer_tag[] = { 0x31, 0x00 };
    static const uint8_t not_sequence_entry[] = { 0x30, 0x03, 0x04, 0x01, 0x05 };
    uint8_t long_form[3U + 2U + 11U + 3U + 200U];
    noxtls_x509_extension_t ext;
    noxtls_x509_extension_iter_t iter;
    int found = 0;
    int has = 0;
    uint32_t pos = 0U;

    CHECK(find_in(ok, sizeof(ok), NOXTLS_RETURN_SUCCESS, 1) == 0);
    CHECK(noxtls_x509_extensions_find_der(critical_true, sizeof(critical_true), k_oid_auth,
                                          sizeof(k_oid_auth), &ext, &found) == NOXTLS_RETURN_SUCCESS);
    CHECK((found == 1) && (ext.critical == 1U) && (ext.value_len == 1U) && (ext.value[0] == 0x05U));
    CHECK(noxtls_x509_extensions_find_der(critical_false, sizeof(critical_false), k_oid_auth,
                                          sizeof(k_oid_auth), &ext, &found) == NOXTLS_RETURN_SUCCESS);
    CHECK((found == 1) && (ext.critical == 0U));
    CHECK(find_in(critical_ber_true, sizeof(critical_ber_true), NOXTLS_RETURN_BAD_DATA, 0) == 0);
    CHECK(find_in(critical_long_bool, sizeof(critical_long_bool), NOXTLS_RETURN_BAD_DATA, 0) == 0);
    CHECK(find_in(duplicate, sizeof(duplicate), NOXTLS_RETURN_BAD_DATA, 0) == 0);
    CHECK(find_in(indefinite, sizeof(indefinite), NOXTLS_RETURN_BAD_DATA, 0) == 0);
    CHECK(find_in(non_minimal, sizeof(non_minimal), NOXTLS_RETURN_BAD_DATA, 0) == 0);
    CHECK(find_in(leading_zero, sizeof(leading_zero), NOXTLS_RETURN_BAD_DATA, 0) == 0);
    CHECK(find_in(too_many_octets, sizeof(too_many_octets), NOXTLS_RETURN_BAD_DATA, 0) == 0);
    CHECK(find_in(truncated_length, sizeof(truncated_length), NOXTLS_RETURN_BAD_DATA, 0) == 0);
    CHECK(find_in(overlong, sizeof(overlong), NOXTLS_RETURN_BAD_DATA, 0) == 0);
    CHECK(find_in(trailing_outer, sizeof(trailing_outer), NOXTLS_RETURN_BAD_DATA, 0) == 0);
    CHECK(find_in(trailing_inner, sizeof(trailing_inner), NOXTLS_RETURN_BAD_DATA, 0) == 0);
    CHECK(find_in(missing_value, sizeof(missing_value), NOXTLS_RETURN_BAD_DATA, 0) == 0);
    CHECK(find_in(bad_oid, sizeof(bad_oid), NOXTLS_RETURN_BAD_DATA, 0) == 0);
    CHECK(find_in(unterminated_oid, sizeof(unterminated_oid), NOXTLS_RETURN_BAD_DATA, 0) == 0);
    CHECK(find_in(empty_oid, sizeof(empty_oid), NOXTLS_RETURN_BAD_DATA, 0) == 0);
    CHECK(find_in(empty_list, sizeof(empty_list), NOXTLS_RETURN_BAD_DATA, 0) == 0);
    CHECK(find_in(wrong_outer_tag, sizeof(wrong_outer_tag), NOXTLS_RETURN_BAD_DATA, 0) == 0);
    CHECK(find_in(not_sequence_entry, sizeof(not_sequence_entry), NOXTLS_RETURN_BAD_DATA, 0) == 0);
    CHECK(find_in(ok, 1U, NOXTLS_RETURN_BAD_DATA, 0) == 0);
    CHECK(find_in(NULL, 0U, NOXTLS_RETURN_SUCCESS, 0) == 0);
    CHECK(find_in(NULL, 4U, NOXTLS_RETURN_NULL, 0) == 0);

    /* A failed iterator stays at the end and reports no further entries. */
    CHECK(noxtls_x509_extension_iter_init_der(&iter, trailing_inner, sizeof(trailing_inner)) ==
          NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_extension_iter_next(&iter, &ext, &has) == NOXTLS_RETURN_BAD_DATA);
    CHECK(noxtls_x509_extension_iter_next(&iter, &ext, &has) == NOXTLS_RETURN_SUCCESS);
    CHECK(has == 0);
    CHECK(noxtls_x509_extension_iter_init_der(NULL, ok, sizeof(ok)) == NOXTLS_RETURN_NULL);

    /* Valid long-form lengths (0x81 and 0x82) are accepted. */
    long_form[pos++] = 0x30;
    long_form[pos++] = 0x81;
    long_form[pos++] = (uint8_t)(2U + 11U + 3U + 200U - 3U - 1U + 1U);
    long_form[pos++] = 0x30;
    long_form[pos++] = 0x81;
    long_form[pos++] = (uint8_t)(11U + 3U + 200U - 3U - 1U);
    long_form[pos++] = 0x06;
    long_form[pos++] = 0x09;
    memcpy(&long_form[pos], k_oid_auth, sizeof(k_oid_auth));
    pos += sizeof(k_oid_auth);
    long_form[pos++] = 0x04;
    long_form[pos++] = 0x81;
    long_form[pos++] = 200U - 3U - 2U;
    memset(&long_form[pos], 0xA5, 200U - 3U - 2U);
    pos += 200U - 3U - 2U;
    long_form[2] = (uint8_t)(pos - 3U);
    long_form[5] = (uint8_t)(pos - 6U);
    CHECK(noxtls_x509_extensions_find_der(long_form, pos, k_oid_auth, sizeof(k_oid_auth), &ext,
                                          &found) == NOXTLS_RETURN_SUCCESS);
    CHECK((found == 1) && (ext.value_len == 195U) && (ext.value[194] == 0xA5U));
    return 0;
}

int main(void)
{
    int rc = test_certificate_lookup();
    if(rc != 0) {
        return 10 + rc;
    }

    rc = test_oid_arc();
    if(rc != 0) {
        return 20 + rc;
    }

    rc = test_handcrafted_der();
    if(rc != 0) {
        return 30 + rc;
    }

    printf("x509_extension_lookup_test: all tests passed\n");
    return 0;
}
