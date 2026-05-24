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
* File:    asn1.h
* Summary: ASN1 DER parser and encoder definitions
*
*****************************************************************************/

/** @addtogroup noxtls_certs */
/** @{ */

#ifndef _NOXTLS_ASN1_H
#define _NOXTLS_ASN1_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ASN1_TAG_EOC               0x00
#define ASN1_TAG_BOOLEAN           0x01
#define ASN1_TAG_INTEGER           0x02
#define ASN1_TAG_BITSTRING         0x03
#define ASN1_TAG_OCTET_STR         0x04
#define ASN1_TAG_NULL              0x05
#define ASN1_TAG_OBJ_IDENT         0x06
#define ASN1_TAG_OBJECT            0x07
#define ASN1_TAG_EXTERNAL	       0x08
#define ASN1_TAG_REAL_FLOAT	       0x09
#define ASN1_TAG_ENUMERATED	       0x0A
#define ASN1_TAG_EMBEDDED          0x0B
#define ASN1_TAG_UTF8STRING        0x0C
#define ASN1_TAG_RELATIVE_OID      0x0D
#define ASN1_TAG_TIME              0x0E
#define ASN1_TAG_SEQUENCE          0x10
#define ASN1_TAG_SET               0x11
#define ASN1_TAG_IA5STRING         0x16
#define ASN1_TAG_PRINTABLESTRING   0x13
#define ASN1_TAG_BMPSTRING         0x1E

/* DER encoding: constructed SEQUENCE tag (0x30 = constructed | tag 16) */
#define ASN1_DER_TAG_SEQUENCE      0x30

#define GET_TAG_CLASS(X)      (((((1U << 7) | (1U << 6)) & (X))) >> 6)
#define GET_TAG_PRIM_CONST(X) ((((1U << 5) & (X))) >> 5)
#define GET_TAG_NUM(X)        ((X) & 0x1Fu)

#define GET_LENGTH(X)         ((X) & 0x7Fu)

#define ASN1_CLASS_TYPE_UNIVERSAL     0
#define ASN1_CLASS_TYPE_APPLICATION   1
#define ASN1_CLASS_TYPE_CONTEXT       2
#define ASN1_CLASS_TYPE_PRIVATE       3

#define ASN1_TAG_TYPE_PRIMITIVE       0
#define ASN1_TAG_TYPE_CONSTRUCTED     1

uint32_t noxtls_parse_der(uint8_t * data, uint32_t len);

/* ASN.1 DER encode API (for keys, certificates, etc.) */

/** Encode length in DER format into out. Returns bytes written (1 or 2-5), or 0 if length too large. */
uint32_t noxtls_asn1_put_length(uint8_t *out, uint32_t len);

/** Encode INTEGER from big-endian buffer. Skips leading zeros, adds 0x00 if high bit set.
 *  Returns bytes written, or 0 on error (buffer too small). */
uint32_t noxtls_asn1_put_integer(uint8_t *out, uint32_t out_max, const uint8_t *value, uint32_t value_len);

/** Encode SEQUENCE: write 0x30 + length + contents.
 *  Returns total bytes written, or 0 on error. */
uint32_t noxtls_asn1_put_sequence(uint8_t *out, uint32_t out_max, const uint8_t *contents, uint32_t contents_len);

/** Encode OBJECT IDENTIFIER from raw DER-encoded OID bytes.
 *  Returns bytes written, or 0 on error. */
uint32_t noxtls_asn1_put_oid_raw(uint8_t *out, uint32_t out_max, const uint8_t *oid, uint32_t oid_len);

/** Encode BIT STRING: tag 0x03, unused bits 0, then data.
 *  Returns bytes written, or 0 on error. */
uint32_t noxtls_asn1_put_bit_string(uint8_t *out, uint32_t out_max, const uint8_t *data, uint32_t data_len);

/** Encode UTCTime (0x17): time_str must be "YYMMDDHHMMSSZ" (13 bytes).
 *  Returns bytes written, or 0 on error. */
uint32_t noxtls_asn1_put_utc_time(uint8_t *out, uint32_t out_max, const char *time_str);

/** Encode context-specific EXPLICIT tag [tag_no]: 0x80|0x20|tag_no, length, contents.
 *  Returns bytes written, or 0 on error. */
uint32_t noxtls_asn1_put_explicit(uint8_t *out, uint32_t out_max, uint8_t tag_no, const uint8_t *contents, uint32_t contents_len);

/** Encode OCTET STRING (0x04): raw bytes.
 *  Returns bytes written, or 0 on error. */
uint32_t noxtls_asn1_put_octet_string(uint8_t *out, uint32_t out_max, const uint8_t *data, uint32_t data_len);

/** Encode SET (0x31): same as SEQUENCE but tag 0x31.
 *  Returns bytes written, or 0 on error. */
uint32_t noxtls_asn1_put_set(uint8_t *out, uint32_t out_max, const uint8_t *contents, uint32_t contents_len);

/** Encode PrintableString (0x13): str is NUL-terminated.
 *  Returns bytes written, or 0 on error. */
uint32_t noxtls_asn1_put_printable_string(uint8_t *out, uint32_t out_max, const char *str);

/** Encode IA5String (0x16): str is NUL-terminated.
 *  Returns bytes written, or 0 on error. */
uint32_t noxtls_asn1_put_ia5_string(uint8_t *out, uint32_t out_max, const char *str);

#ifdef __cplusplus
}
#endif

#endif
