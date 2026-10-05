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
* File:    noxtls_x509_ext.h
* Summary: Strict raw X.509 v3 extension lookup by OID
*
*****************************************************************************/

/**
 * @file noxtls_x509_ext.h
 * @brief Strict DER walker that exposes raw X.509 v3 extensions by OID.
 * @ingroup noxtls_x509_ext
 *
 * The X.509 parser in noxtls_x509.c decodes the well-known extensions into
 * fields of x509_certificate_t and keeps the raw Extensions DER. This module
 * walks that raw DER so applications can read private or protocol-specific
 * extensions (for example the Thread TCAT attributes under
 * 1.3.6.1.4.1.44970) without installing the global unknown-extension
 * callback.
 *
 * Encoding follows RFC 5280 Section 4.1 and 4.2 (Extension ::= SEQUENCE {
 * extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT FALSE, extnValue OCTET
 * STRING }) and the DER rules of ITU-T X.690 (08/2015) Section 8.1.3 and
 * 10.1. Duplicate extensions are rejected per RFC 5280 Section 4.2.
 */

/**
 * @defgroup noxtls_x509_ext NoxTLS X.509 extension lookup
 * @brief Raw X.509 v3 extension iteration and OID lookup.
 */

#ifndef _NOXTLS_X509_EXT_H_
#define _NOXTLS_X509_EXT_H_

#include <stdint.h>

#include "noxtls_common.h"
#include "noxtls_x509.h"

#ifdef __cplusplus
extern "C" {
#endif

/** DER universal tag for SEQUENCE (constructed). */
#define NOXTLS_X509_EXT_TAG_SEQUENCE      0x30U
/** DER universal tag for OBJECT IDENTIFIER. */
#define NOXTLS_X509_EXT_TAG_OID           0x06U
/** DER universal tag for BOOLEAN. */
#define NOXTLS_X509_EXT_TAG_BOOLEAN       0x01U
/** DER universal tag for OCTET STRING. */
#define NOXTLS_X509_EXT_TAG_OCTET_STRING  0x04U
/** DER encoding of BOOLEAN TRUE (X.690 Section 11.1). */
#define NOXTLS_X509_EXT_DER_TRUE          0xFFU
/** DER encoding of BOOLEAN FALSE (X.690 Section 11.1). */
#define NOXTLS_X509_EXT_DER_FALSE         0x00U
/** Maximum number of long-form DER length octets accepted (lengths below 2^32). */
#define NOXTLS_X509_EXT_MAX_LENGTH_OCTETS 4U

/** One raw X.509 v3 extension; all pointers alias the source DER. */
typedef struct
{
    const uint8_t *der;        /**< Complete Extension SEQUENCE TLV. */
    uint32_t der_len;          /**< Length of @ref der in bytes. */
    const uint8_t *oid;        /**< extnID OID content octets (no tag or length). */
    uint32_t oid_len;          /**< Length of @ref oid in bytes. */
    const uint8_t *value;      /**< extnValue OCTET STRING content octets. */
    uint32_t value_len;        /**< Length of @ref value in bytes. */
    uint8_t critical;          /**< 1 when the critical flag is TRUE, else 0. */
} noxtls_x509_extension_t;

/** Iterator over a SEQUENCE OF Extension; never owns memory. */
typedef struct
{
    const uint8_t *next;       /**< Next unread Extension TLV. */
    const uint8_t *end;        /**< End of the Extensions SEQUENCE contents. */
} noxtls_x509_extension_iter_t;

/**
 * @brief Start iterating a raw Extensions DER value (SEQUENCE OF Extension).
 *
 * @param[out] iter Iterator to initialize.
 * @param[in] extensions_der Extensions SEQUENCE TLV, or NULL when @p extensions_len is 0.
 * @param[in] extensions_len Length of @p extensions_der; 0 yields an empty iterator.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, or NOXTLS_RETURN_BAD_DATA when
 *         the outer SEQUENCE is malformed or has trailing bytes.
 */
noxtls_return_t noxtls_x509_extension_iter_init_der(noxtls_x509_extension_iter_t *iter,
                                                    const uint8_t *extensions_der,
                                                    uint32_t extensions_len);

/**
 * @brief Start iterating the extensions of a parsed certificate.
 *
 * @param[out] iter Iterator to initialize.
 * @param[in] cert Parsed certificate; a certificate without extensions yields an empty iterator.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_FAILED when the
 *         certificate is not parsed, or NOXTLS_RETURN_BAD_DATA for malformed DER.
 */
noxtls_return_t noxtls_x509_extension_iter_init(noxtls_x509_extension_iter_t *iter,
                                                const x509_certificate_t *cert);

/**
 * @brief Decode the next extension with strict DER checks.
 *
 * @param[in,out] iter Iterator state; left at the end after an error.
 * @param[out] ext Decoded extension (valid only when @p has_ext is 1).
 * @param[out] has_ext Set to 1 when @p ext was filled, 0 at the end of the list.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, or NOXTLS_RETURN_BAD_DATA.
 */
noxtls_return_t noxtls_x509_extension_iter_next(noxtls_x509_extension_iter_t *iter,
                                                noxtls_x509_extension_t *ext,
                                                int *has_ext);

/**
 * @brief Find one extension by exact OID in a raw Extensions DER value.
 *
 * The whole list is validated, and a second instance of the same OID is
 * rejected (RFC 5280 Section 4.2).
 *
 * @param[in] extensions_der Extensions SEQUENCE TLV, or NULL when @p extensions_len is 0.
 * @param[in] extensions_len Length of @p extensions_der.
 * @param[in] oid OID content octets to match.
 * @param[in] oid_len Length of @p oid (must be non-zero).
 * @param[out] ext Matching extension (valid only when @p found is 1).
 * @param[out] found Set to 1 when the extension is present, 0 otherwise.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM,
 *         or NOXTLS_RETURN_BAD_DATA for malformed DER or duplicates.
 */
noxtls_return_t noxtls_x509_extensions_find_der(const uint8_t *extensions_der,
                                                uint32_t extensions_len,
                                                const uint8_t *oid,
                                                uint32_t oid_len,
                                                noxtls_x509_extension_t *ext,
                                                int *found);

/**
 * @brief Find one extension by exact OID in a parsed certificate.
 *
 * @param[in] cert Parsed certificate.
 * @param[in] oid OID content octets to match.
 * @param[in] oid_len Length of @p oid (must be non-zero).
 * @param[out] ext Matching extension; pointers alias @p cert storage.
 * @param[out] found Set to 1 when the extension is present, 0 otherwise.
 *
 * @return As noxtls_x509_extensions_find_der(), plus NOXTLS_RETURN_FAILED for an
 *         unparsed certificate.
 */
noxtls_return_t noxtls_x509_certificate_find_extension(const x509_certificate_t *cert,
                                                       const uint8_t *oid,
                                                       uint32_t oid_len,
                                                       noxtls_x509_extension_t *ext,
                                                       int *found);

/**
 * @brief Test whether an OID lies strictly below an arc.
 *
 * Both values are OID content octets. The arc must end on a sub-identifier
 * boundary (last octet below 0x80) so byte prefix matching is exact.
 *
 * @param[in] oid OID content octets.
 * @param[in] oid_len Length of @p oid.
 * @param[in] arc Arc content octets.
 * @param[in] arc_len Length of @p arc.
 *
 * @return 1 when @p oid has @p arc as a proper prefix, else 0.
 */
int noxtls_x509_oid_is_under_arc(const uint8_t *oid,
                                 uint32_t oid_len,
                                 const uint8_t *arc,
                                 uint32_t arc_len);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_X509_EXT_H_ */
