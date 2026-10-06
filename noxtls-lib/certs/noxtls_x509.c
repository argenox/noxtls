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
* File:    noxtls_x509.c
* Summary: X.509 Certificate Parsing and Validation Implementation
*
*****************************************************************************/

/** @addtogroup noxtls_certs */

#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stddef.h>

static const uint8_t s_u8txt_noxtls_x509_3160[] = { (uint8_t)'C', (uint8_t)'N', 0 };
static const uint8_t s_u8txt_noxtls_x509_3165[] = { (uint8_t)'O', 0 };
static const uint8_t s_u8txt_noxtls_x509_3170[] = { (uint8_t)'O', (uint8_t)'U', 0 };
static const uint8_t s_u8txt_noxtls_x509_3175[] = { (uint8_t)'C', 0 };
static const uint8_t s_u8txt_noxtls_x509_3180[] = { (uint8_t)'S', (uint8_t)'T', 0 };
static const uint8_t s_u8txt_noxtls_x509_3185[] = { (uint8_t)'L', 0 };
static const uint8_t s_u8txt_noxtls_x509_3192[] = { (uint8_t)'E', 0 };
static const uint8_t s_u8txt_noxtls_x509_3290[] = { (uint8_t)'O', (uint8_t)'I', (uint8_t)'D', 0 };


#include "noxtls_config.h"
#if NOXTLS_HAVE_FILE_IO
#include <stdio.h>
#endif
#include "common/noxtls_memory.h"
#include "common/noxtls_ct.h"
#include "common/noxtls_memory_compat.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_x509.h"
#if NOXTLS_FEATURE_PBKDF2
#include "kdf/noxtls_pbkdf.h"
#endif
#include "certificates.h"
#include "asn1.h"

#include "utility/base64.h"
#include "pkc/rsa/noxtls_rsa.h"
#include "pkc/ecdsa/noxtls_ecdsa.h"
#include "pkc/ecc/noxtls_ecc.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha512/noxtls_sha512.h"
#include "mdigest/noxtls_hash.h"

#if NOXTLS_FEATURE_ED25519
#include "pkc/ed25519/noxtls_ed25519.h"
#endif
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
#include "pkc/ed448/noxtls_ed448.h"
#endif
#if NOXTLS_FEATURE_ML_DSA
#include "pkc/mldsa/noxtls_mldsa.h"
#endif
#if NOXTLS_FEATURE_SLH_DSA
#include "pkc/slhdsa/noxtls_slhdsa.h"
#endif
#if NOXTLS_FEATURE_FALCON
#include "pkc/falcon/noxtls_falcon.h"
#endif
#if NOXTLS_FEATURE_AES_CBC
#include "mdigest/sha1/noxtls_sha1.h"
#include "encryption/aes/noxtls_aes.h"
#endif

#if NOXTLS_HAVE_TIME
#include "common/noxtls_time.h"
#endif

/**
 * @brief Bytes remaining between cursor and one-past-end (same object).
 */
static size_t x509_bytes_remaining(const uint8_t *ptr, const uint8_t *end)
{
    uintptr_t start_addr;
    uintptr_t end_addr;
    if((ptr == NULL) || (end == NULL)) {
        return 0U;
    }
    start_addr = (uintptr_t)ptr;
    end_addr = (uintptr_t)end;
    if(start_addr > end_addr) {
        return 0U;
    }
    return (size_t)(end_addr - start_addr);
}


static noxtls_x509_unknown_ext_cb_t noxtls_x509_unknown_ext_cb;
static void *noxtls_x509_unknown_ext_user_ctx;

#if NOXTLS_FEATURE_FALCON
static int x509_oid_is_falcon(const uint8_t *o, uint32_t l);
#endif

static noxtls_return_t noxtls_x509_validate_ecc_public_key_bytes(const uint8_t *pubkey,
                                                                 uint32_t pubkey_len,
                                                                 const uint8_t *curve_oid,
                                                                 uint32_t curve_oid_len);
static int s_x509_hostname_wildcard_matching =
#if NOXTLS_X509_HOSTNAME_ALLOW_WILDCARD
    1
#else
    0
#endif
;

/**
 * @brief Open a file (host builds with NOXTLS_HAVE_FILE_IO only).
 */
#if NOXTLS_HAVE_FILE_IO
static FILE *noxtls_x509_fopen(const uint8_t *filename, const uint8_t *mode)
{
#ifdef _MSC_VER
    FILE *fp = NULL;
    if(fopen_s(&fp, filename, mode) != 0U) {
        return NULL;
    }
    return fp;
#else
    return fopen(filename, mode);
#endif
}
#endif

/* Certificate debug logging disabled (was CERT_DEBUG / CERT_DEBUG_PRINT). */
#define CERT_DEBUG_PRINT(...) ((void)0)

/* Last certificate verification failure detail (single global; not thread-safe). */
static noxtls_cert_verify_failure_info_t s_cert_fail_info;
/*
 * Global trust anchors for TLS certificate verification.
 *
 * Ownership: the store owns exactly one heap snapshot (a deep copy made by
 * noxtls_x509_trust_store_set()). Verification reads the pointer once per
 * noxtls_x509_verify_*_cert_trust*() call and never keeps it after returning;
 * TLS contexts do not cache it. noxtls_x509_trust_store_set()/_clear() free the
 * previous snapshot, so they must not run concurrently with a verification that
 * uses the global store (the library has no internal locking; serialize like any
 * other global configuration call).
 */
static x509_certificate_chain_t *s_x509_trust_anchors;
static int s_x509_trust_anchors_initialized;


/**
 * @brief Clones a trust store.
 *
 * This function clones a trust store by creating a new trust store and adding the certificates from the original trust store.
 *
 * @param[in] trust_anchors The trust store to clone.
 * @return The cloned trust store.
 */
static x509_certificate_chain_t *x509_trust_store_clone(const x509_certificate_chain_t *trust_anchors)
{
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    x509_certificate_chain_t *snapshot;

    if((trust_anchors == NULL) || (trust_anchors->count == 0U)) {
        return NULL;
    }

    snapshot = (x509_certificate_chain_t *)NOXTLS_CALLOC(1, sizeof(x509_certificate_chain_t));
    if(snapshot == NULL) {
        return NULL;
    }
    rc = noxtls_x509_certificate_chain_init(snapshot);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_free(snapshot);
        return NULL;
    }

    for(i = 0U; i < trust_anchors->count; i += 1U) {
        rc = noxtls_x509_certificate_chain_add(snapshot, &trust_anchors->certs[i]);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_x509_certificate_chain_free(snapshot);
            (void)noxtls_free(snapshot);
            return NULL;
        }
    }

    return snapshot;
}


static void x509_copy_bytes_to_chars(uint8_t *dst, const uint8_t *src, uint32_t len)
{
    uint32_t i = 0U;
    for(i = 0U; i < len; i += 1U) {
        dst[i] = (uint8_t)src[i];
    }
}

/**
 * @brief Return 1 when @p len bytes at @p src contain a NUL octet, 0 otherwise.
 *
 * Names are stored and compared as C strings: a value with an embedded NUL would be
 * silently truncated to its prefix ("victim.example<NUL>.evil.example" -> "victim.example").
 */
static int x509_bytes_have_nul(const uint8_t *src, uint32_t len)
{
    uint32_t i = 0U;
    for(i = 0U; i < len; i += 1U) {
        if(src[i] == 0U) {
            return 1;
        }
    }
    return 0;
}


/* NOLINTNEXTLINE(bugprone-easily-swappable-parameters): captures fixed failure payload fields (hostname length/index). */
/**
 * @brief Sets the certificate verification failure information.
 *
 * This function sets the certificate verification failure information by clearing the
 * s_cert_fail_info structure and setting the return code, certificate index, and populated flag.
 *
 * @param[in] return_code The return code of the certificate verification failure.
 * @param[in] cert The certificate that failed verification.
 * @param[in] expected_hostname The expected hostname of the certificate.
 * @param[in] expected_hostname_len The length of the expected hostname.
 * @param[in] cert_index The index of the certificate in the chain.
 */
static void cert_fail_copy_bytes(uint8_t *dst, uint32_t dst_max, const uint8_t *src)
{
    uint32_t n = 0U;

    if((dst == NULL) || (dst_max == 0U) || (src == NULL)) {
        return;
    }
    while((n < (dst_max - 1U)) && (src[n] != 0U)) {
        dst[n] = (uint8_t)src[n];
        n += 1U;
    }
    dst[n] = 0U;
}

static void cert_fail_copy_cstr(uint8_t *dst, uint32_t dst_max, const uint8_t *src, uint32_t src_len)
{
    uint32_t n = 0U;

    if((dst == NULL) || (dst_max == 0U) || (src == NULL)) {
        return;
    }
    while((n < (dst_max - 1U)) && ((src_len == 0U) || (n < src_len)) && (src[n] != 0U)) {
        dst[n] = src[n];
        n += 1U;
    }
    dst[n] = 0U;
}

static void cert_fail_set(noxtls_return_t return_code, const x509_certificate_t *cert, const uint8_t *expected_hostname, uint32_t expected_hostname_len, uint32_t cert_index)
{
    noxtls_secure_zero((&s_cert_fail_info), sizeof(s_cert_fail_info));
    s_cert_fail_info.return_code = return_code;
    s_cert_fail_info.cert_index = cert_index;
    s_cert_fail_info.populated = 1;

    if(cert != NULL) {
        if(cert->not_before[0] != 0U) {
            cert_fail_copy_bytes(s_cert_fail_info.not_before, NOXTLS_CERT_FAIL_TIME_MAX, cert->not_before);
        }
        if(cert->not_after[0] != 0U) {
            cert_fail_copy_bytes(s_cert_fail_info.not_after, NOXTLS_CERT_FAIL_TIME_MAX, cert->not_after);
        }
        if(cert->subject_dn[0] != 0U) {
            cert_fail_copy_cstr(s_cert_fail_info.subject_dn, NOXTLS_CERT_FAIL_DN_HOSTNAME_MAX, cert->subject_dn, 0U);
        }
    }

    if(expected_hostname != NULL) {
        cert_fail_copy_cstr(s_cert_fail_info.expected_hostname, NOXTLS_CERT_FAIL_DN_HOSTNAME_MAX,
                            expected_hostname, expected_hostname_len);
    }
}

/**
 * @brief Clears the certificate verification failure information.
 *
 * This function clears the certificate verification failure information by setting the
 * s_cert_fail_info structure to zero.
 */
void noxtls_cert_verify_failure_clear(void)
{
    noxtls_secure_zero((&s_cert_fail_info), sizeof(s_cert_fail_info));
}

/**
 * @brief Gets the certificate verification failure information.
 *
 * This function gets the certificate verification failure information by copying the
 * s_cert_fail_info structure to the output parameter.
 *
 * @param[out] out The output parameter to receive the certificate verification failure information.
 */
void noxtls_cert_verify_failure_get(noxtls_cert_verify_failure_info_t *out)
{
    if(out != NULL) {
        noxtls_copy_u8((uint8_t *)(void *)(out), sizeof(noxtls_cert_verify_failure_info_t), (const uint8_t *)(const void *)(&s_cert_fail_info), sizeof(noxtls_cert_verify_failure_info_t));
    }
}

/* ASN.1 Helper Functions */

/**
 * @brief Gets the length of an ASN.1 encoded value.
 *
 * This function gets the length of an ASN.1 encoded value by parsing the length field.
 *
 * @param[in] data The pointer to the ASN.1 encoded value.
 * @param[in] end The pointer to the end of the ASN.1 encoded value.
 * @return The length of the ASN.1 encoded value.
 */
static uint32_t asn1_get_length(const uint8_t **data, const uint8_t *end)
{
    const uint8_t *ptr = *data;
    uint32_t length = 0U;

    if((uintptr_t)ptr >= (uintptr_t)end) {
        return 0U;
    }

    if((*ptr & 0x80U) != 0U) {
        /* Long form */
        uint8_t len_bytes = (uint8_t)(*ptr & 0x7FU);
        ptr = &ptr[1];

        if((len_bytes == 0U) || (len_bytes > 4U) || (x509_bytes_remaining(ptr, end) < (size_t)len_bytes)) {
            return 0U;
        }

        uint32_t i = 0U;
        for(i = 0U; i < len_bytes; i += 1U) {
            length = (length << 8U) | (uint32_t)(*ptr);
            ptr = &ptr[1];
        }
    } else {
        /* Short form */
        length = (uint32_t)(*ptr) & 0x7FU;
        ptr = &ptr[1];
    }

    *data = ptr;
    return length;
}

/**
 * @brief Gets the tag of an ASN.1 encoded value.
 *
 * This function gets the tag of an ASN.1 encoded value by parsing the tag field.
 *
 * @param[in] data The pointer to the ASN.1 encoded value.
 * @param[in] end The pointer to the end of the ASN.1 encoded value.
 * @param[in] expected_tag The expected tag of the ASN.1 encoded value.
 * @return The tag of the ASN.1 encoded value.
 */
static noxtls_return_t asn1_get_tag(const uint8_t **data, const uint8_t *end, uint8_t expected_tag)
{
    if((uintptr_t)(*data) >= (uintptr_t)end) {
        return NOXTLS_RETURN_FAILED;
    }

    uint8_t tag = (uint8_t)(**data);
    (*data)++;

    if(tag != expected_tag) {
        return NOXTLS_RETURN_FAILED;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Gets the OID of an ASN.1 encoded value.
 *
 * This function gets the OID of an ASN.1 encoded value by parsing the OID field.
 *
 * @param[in] data The pointer to the ASN.1 encoded value.
 * @param[in] end The pointer to the end of the ASN.1 encoded value.
 * @param[out] oid The pointer to the buffer to receive the OID.
 * @param[out] oid_len The length of the OID.
 * @return The return code of the function.
 */
static noxtls_return_t asn1_get_oid(const uint8_t **data, const uint8_t *end, uint8_t *oid_out, uint32_t *oid_out_len)
{
    uint32_t len = 0U;

    if(asn1_get_tag(data, end, 0x06U) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    len = asn1_get_length(data, end);
    if((len == 0U) || (len > 32U) || (x509_bytes_remaining(*data, end) < (size_t)len)) {
        return NOXTLS_RETURN_FAILED;
    }

    if((oid_out != NULL) && (oid_out_len != NULL)) {
        noxtls_copy_u8((uint8_t *)(void *)(oid_out), (size_t)len, (const uint8_t *)(const void *)(*data), (size_t)len);
        *oid_out_len = len;
    }
    *data = &(*data)[len];

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Gets the integer of an ASN.1 encoded value.
 *
 * This function gets the integer of an ASN.1 encoded value by parsing the integer field.
 *
 * @param[in] data The pointer to the ASN.1 encoded value.
 * @param[in] end The pointer to the end of the ASN.1 encoded value.
 * @param[out] integer The pointer to the buffer to receive the integer.
 * @param[out] integer_len The length of the integer.
 * @return The return code of the function.
 */
static noxtls_return_t asn1_get_integer(const uint8_t **data, const uint8_t *end, uint8_t *integer, uint32_t *integer_len)
{
    uint32_t len = 0U;

    if(asn1_get_tag(data, end, 0x02U) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    len = asn1_get_length(data, end);

    if((len == 0U) || (x509_bytes_remaining(*data, end) < (size_t)len)) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Check buffer size only if buffer is provided */
    if((integer != NULL) && (integer_len != NULL)) {
        if(len > *integer_len) {
            *integer_len = len;
            *data = &(*data)[len];  /* Skip the data */
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_copy_u8((uint8_t *)(void *)(integer), (size_t)len, (const uint8_t *)(const void *)(*data), (size_t)len);
        *integer_len = len;
    } else if(integer_len != NULL) {
        *integer_len = len;
    }
     else {
         /* MISRA 15.7: no remaining alternative */
     }

    *data = &(*data)[len];

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Gets the sequence of an ASN.1 encoded value.
 *
 * This function gets the sequence of an ASN.1 encoded value by parsing the sequence field.
 *
 * @param[in] data The pointer to the ASN.1 encoded value.
 * @param[in] end The pointer to the end of the ASN.1 encoded value.
 * @param[out] seq_data The pointer to the buffer to receive the sequence.
 * @param[out] seq_len The length of the sequence.
 * @return The return code of the function.
 */
static noxtls_return_t asn1_get_sequence(const uint8_t **data, const uint8_t *end, const uint8_t **seq_data, uint32_t *seq_len)
{
    if(asn1_get_tag(data, end, 0x30U) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    *seq_len = asn1_get_length(data, end);

    /* Zero-length SEQUENCE is valid (e.g. empty X.509 subject DN: 30 00). */
    if(x509_bytes_remaining(*data, end) < (size_t)(*seq_len)) {
        return NOXTLS_RETURN_FAILED;
    }

    *seq_data = *data;
    *data = &(*data)[*seq_len];

    return NOXTLS_RETURN_SUCCESS;
}

/* Get OCTET STRING (tag 0x04); *out_data points into original buffer, *out_len set. */


/**
 * @brief Gets the octet string of an ASN.1 encoded value.
 *
 * This function gets the octet string of an ASN.1 encoded value by parsing the octet string field.
 *
 * @param[in] data The pointer to the ASN.1 encoded value.
 * @param[in] end The pointer to the end of the ASN.1 encoded value.
 * @param[out] out_data The pointer to the buffer to receive the octet string.
 * @param[out] out_len The length of the octet string.
 * @return The return code of the function.
 */
static noxtls_return_t asn1_get_octet_string(const uint8_t **data, const uint8_t *end, const uint8_t **out_data, uint32_t *out_len)
{
    if(asn1_get_tag(data, end, 0x04U) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    *out_len = asn1_get_length(data, end);
    if(x509_bytes_remaining(*data, end) < (size_t)(*out_len)) {
        return NOXTLS_RETURN_FAILED;
    }

    *out_data = *data;
    *data = &(*data)[*out_len];
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Gets the boolean of an ASN.1 encoded value.
 *
 * This function gets the boolean of an ASN.1 encoded value by parsing the boolean field.
 * DER (X.690 Section 11.1) requires a one-octet value that is 0x00 (FALSE) or 0xFF (TRUE);
 * any other length or value is rejected. On failure *data is left unchanged, so a caller
 * can never resume scanning from inside (or past the end of) a malformed element.
 *
 * @param[in] data The pointer to the ASN.1 encoded value.
 * @param[in] end The pointer to the end of the ASN.1 encoded value.
 * @param[out] out_value The pointer to the buffer to receive the boolean.
 * @return NOXTLS_RETURN_SUCCESS, or NOXTLS_RETURN_BAD_DATA for a malformed BOOLEAN.
 */
static noxtls_return_t asn1_get_boolean(const uint8_t **data, const uint8_t *end, int *out_value)
{
    const uint8_t *cur = *data;
    uint32_t len = 0U;
    uint8_t value = 0U;

    if(asn1_get_tag(&cur, end, 0x01U) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(x509_bytes_remaining(cur, end) < 2U) {
        return NOXTLS_RETURN_BAD_DATA;  /* need the length octet and the value octet */
    }
    len = asn1_get_length(&cur, end);
    if((len != 1U) || (x509_bytes_remaining(cur, end) < 1U)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    value = cur[0];
    if((value != 0x00U) && (value != 0xFFU)) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    *out_value = (value != 0U) ? 1 : 0;
    *data = &cur[1];
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Reads a TLV header (tag already consumed) and checks the content fits before @p end.
 *
 * Unlike forming &ptr[len] and comparing it with @p end, this never creates a pointer outside
 * the buffer. On failure *data is left unchanged.
 *
 * @param[in,out] data Cursor positioned at the length octet(s); advanced to the content on success.
 * @param[in] end One past the last readable byte.
 * @param[out] out_len Content length.
 * @return NOXTLS_RETURN_SUCCESS when the whole content is inside the buffer, NOXTLS_RETURN_FAILED otherwise.
 */
static noxtls_return_t asn1_get_bounded_length(const uint8_t **data, const uint8_t *end, uint32_t *out_len)
{
    const uint8_t *cur = *data;
    uint32_t len = 0U;

    if(x509_bytes_remaining(cur, end) == 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    len = asn1_get_length(&cur, end);
    if((uintptr_t)cur == (uintptr_t)(*data)) {
        /* asn1_get_length() does not advance on an indefinite, oversize or truncated long form. */
        return NOXTLS_RETURN_FAILED;
    }
    if(x509_bytes_remaining(cur, end) < (size_t)len) {
        return NOXTLS_RETURN_FAILED;
    }
    *data = cur;
    *out_len = len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Check if two OIDs are equal
 * 
 * @param[in] a The first OID.
 * @param[in] a_len The length of the first OID.
 * @param[in] b The second OID.
 * @param[in] b_len The length of the second OID.
 * @return 1 if the OIDs are equal, 0 otherwise.
 */
static int oid_equal(const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len)
{
    int equal = 0;
    if(a_len == b_len) {
        equal = (noxtls_ct_memcmp(a, b, (size_t)a_len) == 0) ? 1 : 0;
    }
    return equal;
}

#if NOXTLS_FEATURE_AES_CBC
/* OIDs for EncryptedPrivateKeyInfo (RFC 5208) and PBES2/PBKDF2 (RFC 8018). DER-encoded. */

#define SHA1_OUT_LEN 20U
#define NOXTLS_AES_BLOCK_LEN 16
#endif
#if NOXTLS_FEATURE_SLH_DSA
/**
 * @brief Map a FIPS 205 SLH-DSA OID to the public API parameter set.
 *
 * @param[in] oid DER-encoded object identifier bytes.
 * @param[in] oid_len OID length.
 * @param[out] param Output parameter set.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t noxtls_x509_slhdsa_param_from_oid(const uint8_t *oid,
                                                         uint32_t oid_len,
                                                         noxtls_slhdsa_param_t *param)
{
    static const uint8_t oid_prefix[] = {0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x03U};
    uint8_t last = 0U;

    if((oid == NULL) || (param == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if((size_t)(oid_len) != (sizeof(oid_prefix) + 1U)) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if(noxtls_ct_memcmp(oid, oid_prefix, sizeof(oid_prefix)) != 0) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    last = oid[sizeof(oid_prefix)];
    if((last < 0x14U) || (last > 0x1FU)) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    *param = (noxtls_slhdsa_param_t)((uint32_t)NOXTLS_SLHDSA_SHA2_128S + (uint32_t)(last - 0x14U));
    return NOXTLS_RETURN_SUCCESS;
}
#endif

#if NOXTLS_FEATURE_AES_CBC
#if !NOXTLS_FEATURE_PBKDF2
/* Builds without NOXTLS_FEATURE_HMAC keep a private PBKDF2-HMAC-SHA1. */
/**
 * @brief Computes the HMAC-SHA1 of a message.
 *
 * This function computes the HMAC-SHA1 of a message using the SHA-1 hash algorithm.
 * key_len can be any size; block size 64.
 *
 * @param[in] key The key to use for the HMAC.
 * @param[in] key_len The length of the key.
 * @param[in] msg The message to compute the HMAC-SHA1 of.
 * @param[in] msg_len The length of the message.
 * @param[out] mac The buffer to receive the HMAC-SHA1.
 *
 * @return The return code of the function.
 */
static noxtls_return_t hmac_sha1(const uint8_t *key, uint32_t key_len,
                                  const uint8_t *msg, uint32_t msg_len,
                                  uint8_t *mac)
{
    noxtls_sha_ctx_t ctx;
    uint8_t ipad[64];
    uint8_t opad[64];
    uint8_t tmp[SHA1_OUT_LEN];
    uint32_t i = 0U;
    const uint8_t *key_ptr = key;
    uint32_t key_bytes = key_len;

    if((key_ptr == NULL) || (msg == NULL) || (mac == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    {
        size_t fill_i = 0U;
        for(fill_i = 0U; fill_i < 64U; fill_i += 1U) {
            ipad[fill_i] = 0x36U;
            opad[fill_i] = 0x5CU;
        }
    }

    if(key_bytes > 64U) {
        if(noxtls_sha1_init(&ctx, NOXTLS_HASH_SHA1) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
        if(noxtls_sha1_update(&ctx, key_ptr, key_bytes) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
        if(noxtls_sha1_finish(&ctx, tmp) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
        key_ptr = tmp;
        key_bytes = SHA1_OUT_LEN;
    }

    for(i = 0U; i < key_bytes; i += 1U) {
        ipad[i] ^= key_ptr[i];
        opad[i] ^= key_ptr[i];
    }

    if(noxtls_sha1_init(&ctx, NOXTLS_HASH_SHA1) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_sha1_update(&ctx, ipad, 64) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_sha1_update(&ctx, msg, msg_len) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_sha1_finish(&ctx, mac) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_sha1_init(&ctx, NOXTLS_HASH_SHA1) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_sha1_update(&ctx, opad, 64) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_sha1_update(&ctx, mac, SHA1_OUT_LEN) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_sha1_finish(&ctx, mac) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    return NOXTLS_RETURN_SUCCESS;
}



/**
 * @brief Derives the key using PBKDF2-HMAC-SHA1.
 *
 * This function derives the key using PBKDF2-HMAC-SHA1.
 * This function is used to derive the key using PBKDF2-HMAC-SHA1.
 *
 * @param[in] password The password to use for the derivation.
 * @param[in] password_len The length of the password.
 * @param[in] salt The salt to use for the derivation.
 * @param[in] salt_len The length of the salt.
 * @param[in] params The parameters for the derivation.
 * @param[out] out The buffer to receive the derived key.
 *
 * @return The return code of the function.
 */
static noxtls_return_t pbkdf2_hmac_sha1(const uint8_t *password, uint32_t password_len,
                                         const uint8_t *salt, const pbkdf2_sha1_params_t *params, uint8_t *out)
{
    uint8_t u[SHA1_OUT_LEN];
    uint8_t t[SHA1_OUT_LEN];
    uint8_t *block_input = NULL;
    uint32_t j = 0U;
    uint32_t k = 0U;
    uint32_t blocks = 0U;
    uint32_t block_index = 0U;

    if((password == NULL) || (salt == NULL) || (params == NULL) || (out == NULL) || (params->iterations == 0U)) {
        return NOXTLS_RETURN_NULL;
    }

    if(params->salt_len > (0xFFFFU - 4U)) { return NOXTLS_RETURN_FAILED; }
    block_input = (uint8_t*)NOXTLS_MALLOC(params->salt_len + 4U);
    if(block_input == NULL) { return NOXTLS_RETURN_NOT_ENOUGH_MEMORY; }
    noxtls_copy_u8((uint8_t *)(void *)(block_input), (size_t)params->salt_len, (const uint8_t *)(const void *)(salt), (size_t)params->salt_len);
    blocks = (params->key_len + SHA1_OUT_LEN - 1U) / SHA1_OUT_LEN;

    for(block_index = 1U; block_index <= blocks; block_index += 1U) {
        block_input[params->salt_len + 0U] = (uint8_t)(block_index >> 24U);
        block_input[params->salt_len + 1U] = (uint8_t)(block_index >> 16U);
        block_input[params->salt_len + 2U] = (uint8_t)(block_index >> 8U);
        block_input[params->salt_len + 3U] = (uint8_t)block_index;

        if(hmac_sha1(password, password_len, block_input, params->salt_len + 4U, u) != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_free(block_input);
            return NOXTLS_RETURN_FAILED;
        }

        for(k = 0U; k < SHA1_OUT_LEN; k += 1U) {
            t[k] = u[k];
        }

        for(j = 1U; j < params->iterations; j += 1U) {
            if(hmac_sha1(password, password_len, u, SHA1_OUT_LEN, u) != NOXTLS_RETURN_SUCCESS) {
                (void)noxtls_free(block_input);
                return NOXTLS_RETURN_FAILED;
            }
            for(k = 0U; k < SHA1_OUT_LEN; k += 1U) { t[k] ^= u[k]; }
        }

        {
            uint32_t copy_len = (uint32_t)(((block_index * SHA1_OUT_LEN) <= params->key_len)
                                    ? SHA1_OUT_LEN
                                    : (params->key_len - ((block_index - 1U) * SHA1_OUT_LEN)));
            noxtls_copy_u8((uint8_t *)(void *)(&out[((size_t)(block_index - 1U) * SHA1_OUT_LEN)]), (size_t)copy_len, (const uint8_t *)(const void *)(t), (size_t)copy_len);
        }
    }
    (void)noxtls_free(block_input);
    return NOXTLS_RETURN_SUCCESS;
}
#endif /* !NOXTLS_FEATURE_PBKDF2 */

/**
 * @brief PBES2 key derivation: PBKDF2 with the PRF selected by PBKDF2-params (RFC 8018 5.2, A.2).
 * @internal
 *
 * @param[in] prf_hash HMAC hash named by the prf AlgorithmIdentifier (default SHA-1).
 * @param[in] password Password bytes.
 * @param[in] password_len Password length.
 * @param[in] salt Salt bytes.
 * @param[in] salt_len Salt length.
 * @param[in] iterations Iteration count.
 * @param[out] out Derived key buffer of @p out_len bytes.
 * @param[in] out_len Derived key length.
 *
 * @return NOXTLS_RETURN_SUCCESS, or an error when the PRF is unsupported or derivation fails.
 */
static noxtls_return_t x509_pbes2_kdf(noxtls_hash_algos_t prf_hash,
                                      const uint8_t *password, uint32_t password_len,
                                      const uint8_t *salt, uint32_t salt_len, uint32_t iterations,
                                      uint8_t *out, uint32_t out_len)
{
#if NOXTLS_FEATURE_PBKDF2
    return noxtls_pbkdf2_hmac(prf_hash, password, password_len, salt, salt_len, iterations, out, out_len);
#else
    pbkdf2_sha1_params_t params;

    if(prf_hash != NOXTLS_HASH_SHA1) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    params.salt_len = salt_len;
    params.iterations = iterations;
    params.key_len = out_len;
    return pbkdf2_hmac_sha1(password, password_len, salt, &params, out);
#endif
}
#endif

/**
 * @brief Sets the unknown extension callback.
 *
 * This function sets the unknown extension callback.
 *
 * @param[in] cb The callback to set.
 * @param[in] user_ctx The user context to pass to the callback.
 */
void noxtls_x509_set_unknown_extension_callback(noxtls_x509_unknown_ext_cb_t cb, void *ext_user_ctx)
{
    noxtls_x509_unknown_ext_cb = cb;
    noxtls_x509_unknown_ext_user_ctx = ext_user_ctx;
}

/**
 * @brief Enable or disable wildcard hostname matching at runtime.
 *
 * @param enabled 1 to allow wildcard DNS matching, 0 to require exact DNS match.
 */
void noxtls_x509_set_hostname_wildcard_matching(int enabled)
{
    s_x509_hostname_wildcard_matching = (enabled != 0) ? 1 : 0;
}

/**
 * @brief Get current wildcard hostname matching runtime state.
 *
 * @return 1 when wildcard DNS matching is enabled, 0 otherwise.
 */
int noxtls_x509_get_hostname_wildcard_matching(void)
{
    return s_x509_hostname_wildcard_matching;
}

/**
 * Parse cert->extensions (SEQUENCE OF Extension) and fill SAN, Key Usage, EKU, Basic Constraints, AKI, SKI, etc.
 * Unknown critical extensions cause parse failure unless handled by noxtls_x509_set_unknown_extension_callback.
 *
 * @param[in] cert The certificate to parse the extensions from.
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_parse_extensions(x509_certificate_t *cert)
{
    /* Extension OIDs local to this function (Rule 8.9). */
    /* RFC 5280 id-ce extension OIDs (DER) */
    /* id-ce-subjectAltName = 2.5.29.17 */
    static const uint8_t x509p_oid_subject_alt_name[] = { 0x55U, 0x1DU, 0x11U };
    /* id-ce-keyUsage = 2.5.29.15 */
    static const uint8_t x509p_oid_key_usage[] = { 0x55U, 0x1DU, 0x0FU };
    /* id-ce-basicConstraints = 2.5.29.19 */
    static const uint8_t x509p_oid_basic_constraints[] = { 0x55U, 0x1DU, 0x13U };
    /* id-ce-extKeyUsage = 2.5.29.37 */
    static const uint8_t x509p_oid_ext_key_usage[] = { 0x55U, 0x1DU, 0x25U };
    /* id-ce-authorityKeyIdentifier = 2.5.29.35 */
    static const uint8_t x509p_oid_authority_key_id[] = { 0x55U, 0x1DU, 0x23U };
    /* id-ce-subjectKeyIdentifier = 2.5.29.14 */
    static const uint8_t x509p_oid_subject_key_id[] = { 0x55U, 0x1DU, 0x0EU };
    /* id-ce-certificatePolicies = 2.5.29.32 */
    static const uint8_t x509p_oid_certificate_policies[] = { 0x55U, 0x1DU, 0x20U };
    /* id-ce-cRLDistributionPoints = 2.5.29.31 */
    static const uint8_t x509p_oid_crl_distribution_points[] = { 0x55U, 0x1DU, 0x1FU };
    /* id-ce-nameConstraints = 2.5.29.30 */
    static const uint8_t x509p_oid_name_constraints[] = { 0x55U, 0x1DU, 0x1EU };
    /* id-ce-policyConstraints = 2.5.29.36 */
    static const uint8_t x509p_oid_policy_constraints[] = { 0x55U, 0x1DU, 0x24U };
    /* id-ce-inhibitAnyPolicy = 2.5.29.54 */
    static const uint8_t x509p_oid_inhibit_any_policy[] = { 0x55U, 0x1DU, 0x36U };
    /* id-kp OIDs (Extended Key Usage): 1.3.6.1.5.5.7.3.x */
    static const uint8_t x509p_oid_kp_server_auth[] = { 0x2BU, 0x06U, 0x01U, 0x05U, 0x05U, 0x07U, 0x03U, 0x01U };
    static const uint8_t x509p_oid_kp_client_auth[] = { 0x2BU, 0x06U, 0x01U, 0x05U, 0x05U, 0x07U, 0x03U, 0x02U };
    static const uint8_t x509p_oid_kp_code_signing[] = { 0x2BU, 0x06U, 0x01U, 0x05U, 0x05U, 0x07U, 0x03U, 0x03U };
    static const uint8_t x509p_oid_kp_email_protection[] = { 0x2BU, 0x06U, 0x01U, 0x05U, 0x05U, 0x07U, 0x03U, 0x04U };
    static const uint8_t x509p_oid_kp_time_stamping[] = { 0x2BU, 0x06U, 0x01U, 0x05U, 0x05U, 0x07U, 0x03U, 0x08U };
    static const uint8_t x509p_oid_kp_ocsp_signing[] = { 0x2BU, 0x06U, 0x01U, 0x05U, 0x05U, 0x07U, 0x03U, 0x09U };
    /* anyExtendedKeyUsage 2.5.29.37.0 */
    static const uint8_t x509p_oid_any_eku[] = { 0x55U, 0x1DU, 0x25U, 0x00U };

    const uint8_t *ext_ptr = NULL;
    const uint8_t *ext_end = NULL;
    const uint8_t *seq_data = NULL;
    uint32_t seq_len = 0U;

    if((cert == NULL) || (cert->extensions == NULL) || (cert->extensions_len < 2U)) {
        return NOXTLS_RETURN_SUCCESS;
    }
    cert->san_dns_count = 0U;
    cert->san_email_count = 0U;
    cert->san_uri_count = 0U;
    cert->san_ip_count = 0U;
    cert->key_usage_bits = 0U;
    cert->ext_key_usage_bits = 0U;
    cert->basic_constraints_ca = -1;
    cert->basic_constraints_path_len = X509_BC_PATH_LEN_ABSENT;
    cert->authority_key_id_len = 0U;
    cert->subject_key_id_len = 0U;
    ext_ptr = cert->extensions;
    ext_end = &cert->extensions[cert->extensions_len];

    if(asn1_get_sequence(&ext_ptr, ext_end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_SUCCESS;
    }

    {
        const uint8_t *list_ptr = seq_data;
        const uint8_t *list_end = &seq_data[seq_len];
        while((uintptr_t)list_ptr < (uintptr_t)list_end) {
            const uint8_t *ext_seq = NULL;
            uint32_t ext_seq_len = 0U;
            uint8_t oid_buf[32];
            uint32_t ext_oid_len = 0U;
            int ext_critical = 0;
            const uint8_t *val_data = NULL;
            uint32_t val_len = 0U;

            if(asn1_get_sequence(&list_ptr, list_end, &ext_seq, &ext_seq_len) != NOXTLS_RETURN_SUCCESS) {
                break;
            }
            {
                const uint8_t *eptr = ext_seq;
                const uint8_t *eend = &ext_seq[ext_seq_len];
                if(asn1_get_oid(&eptr, eend, oid_buf, &ext_oid_len) != NOXTLS_RETURN_SUCCESS) {
                    list_ptr = &ext_seq[ext_seq_len];
                    continue;
                }
                {
                    uint8_t eptr_done = 0U;
                    while(((uintptr_t)eptr < (uintptr_t)eend) && (eptr_done == 0U)) {
                        if(*eptr == 0x01U) {
                            /* critical BOOLEAN: DER requires length 1 and value 0x00/0xFF. A malformed
                             * BOOLEAN rejects the certificate; the cursor is never moved past eend. */
                            if(asn1_get_boolean(&eptr, eend, &ext_critical) != NOXTLS_RETURN_SUCCESS) {
                                return NOXTLS_RETURN_BAD_DATA;
                            }
                        } else if(*eptr == 0x04U) {
                            if(asn1_get_octet_string(&eptr, eend, &val_data, &val_len) != NOXTLS_RETURN_SUCCESS) {
                                val_data = NULL;
                                val_len = 0U;
                            }
                            eptr_done = 1U;
                        } else {
                            eptr_done = 1U;
                        }
                    }
                }
            }
            if((val_data == NULL) || (val_len == 0U)) {
                list_ptr = &ext_seq[ext_seq_len];
                continue;
            }

            if(oid_equal(oid_buf, ext_oid_len, x509p_oid_subject_alt_name, sizeof(x509p_oid_subject_alt_name)) != 0) {
                /* SubjectAltName: GeneralNames; dNSName [2]=0x82, rfc822Name [1]=0x81, uniformResourceIdentifier [6]=0x86, iPAddress [7]=0x87 */
                const uint8_t *san_ptr = val_data;
                const uint8_t *san_end = &val_data[val_len];
                const uint8_t *san_seq = NULL;
                uint32_t san_seq_len = 0U;
                if(asn1_get_sequence(&san_ptr, san_end, &san_seq, &san_seq_len) == NOXTLS_RETURN_SUCCESS) {
                    const uint8_t *gn_ptr = san_seq;
                    const uint8_t *gn_end = &san_seq[san_seq_len];
                    {
                        uint8_t gn_done = 0U;
                        while(((uintptr_t)gn_ptr < (uintptr_t)gn_end) && (gn_done == 0U)) {
                            if(*gn_ptr == 0x82U) {
                                gn_ptr = &gn_ptr[1];
                                { uint32_t dlen = (uint32_t)(asn1_get_length(&gn_ptr, gn_end));
                                if(dlen > (uint32_t)((uintptr_t)gn_end - (uintptr_t)gn_ptr)) { gn_done = 1U; }
                                else {
                                    if((cert->san_dns_count < X509_SAN_DNS_MAX) && (dlen > 0U) && (dlen < X509_SAN_DNS_LEN)) {
                                        if(x509_bytes_have_nul(gn_ptr, dlen) == 0) {
                                            x509_copy_bytes_to_chars(cert->san_dns_names[cert->san_dns_count], gn_ptr, dlen);
                                            cert->san_dns_names[cert->san_dns_count][dlen] = 0U;
                                        } else {
                                            /* SECURITY: a dNSName with an embedded NUL cannot be stored as a
                                             * C string without turning "victim.example<NUL>.evil.example"
                                             * into "victim.example". Keep it as an empty entry: it never
                                             * matches a hostname and the SAN still counts as present, so the
                                             * subject CN fallback stays disabled (RFC 6125 Section 6.4.4). */
                                            cert->san_dns_names[cert->san_dns_count][0] = 0U;
                                        }
                                        cert->san_dns_count += 1U;
                                    }
                                    gn_ptr = &gn_ptr[dlen];
                                } }
                            } else if(*gn_ptr == 0x81U) {
                                gn_ptr = &gn_ptr[1];
                                { uint32_t elen = (uint32_t)(asn1_get_length(&gn_ptr, gn_end));
                                if(elen > (uint32_t)((uintptr_t)gn_end - (uintptr_t)gn_ptr)) { gn_done = 1U; }
                                else {
                                    if((cert->san_email_count < X509_SAN_EMAIL_MAX) && (elen > 0U) && (elen < X509_SAN_EMAIL_LEN)) {
                                        x509_copy_bytes_to_chars(cert->san_emails[cert->san_email_count], gn_ptr, elen);
                                        cert->san_emails[cert->san_email_count][elen] = 0U;
                                        cert->san_email_count += 1U;
                                    }
                                    gn_ptr = &gn_ptr[elen];
                                } }
                            } else if(*gn_ptr == 0x86U) {
                                gn_ptr = &gn_ptr[1];
                                { uint32_t ulen = (uint32_t)(asn1_get_length(&gn_ptr, gn_end));
                                if(ulen > (uint32_t)((uintptr_t)gn_end - (uintptr_t)gn_ptr)) { gn_done = 1U; }
                                else {
                                    if((cert->san_uri_count < X509_SAN_URI_MAX) && (ulen > 0U) && (ulen < X509_SAN_URI_LEN)) {
                                        x509_copy_bytes_to_chars(cert->san_uris[cert->san_uri_count], gn_ptr, ulen);
                                        cert->san_uris[cert->san_uri_count][ulen] = 0U;
                                        cert->san_uri_count += 1U;
                                    }
                                    gn_ptr = &gn_ptr[ulen];
                                } }
                            } else if(*gn_ptr == 0x87U) {
                                gn_ptr = &gn_ptr[1];
                                { uint32_t iplen = (uint32_t)(asn1_get_length(&gn_ptr, gn_end));
                                if(iplen > (uint32_t)((uintptr_t)gn_end - (uintptr_t)gn_ptr)) { gn_done = 1U; }
                                else {
                                    if((cert->san_ip_count < X509_SAN_IP_MAX) && ((iplen == 4U) || (iplen == 16U))) {
                                        cert->san_ip_len[cert->san_ip_count] = (uint8_t)iplen;
                                        noxtls_copy_u8((uint8_t *)(void *)(cert->san_ips[cert->san_ip_count]), (size_t)iplen, (const uint8_t *)(const void *)(gn_ptr), (size_t)iplen);
                                        cert->san_ip_count += 1U;
                                    }
                                    gn_ptr = &gn_ptr[iplen];
                                } }
                            } else {
                                uint32_t skip = 0U;
                                gn_ptr = &gn_ptr[1];
                                /* Bound-check before advancing: never form a pointer past gn_end. */
                                if(asn1_get_bounded_length(&gn_ptr, gn_end, &skip) == NOXTLS_RETURN_SUCCESS) {
                                    gn_ptr = &gn_ptr[skip];
                                } else {
                                    gn_done = 1U;
                                }
                            }
                        }
                    }
                }
            } else if(oid_equal(oid_buf, ext_oid_len, x509p_oid_key_usage, sizeof(x509p_oid_key_usage)) != 0) {
                const uint8_t *ku_ptr = val_data;
                const uint8_t *ku_end = &val_data[val_len];
                if(asn1_get_tag(&ku_ptr, ku_end, 0x03U) == NOXTLS_RETURN_SUCCESS) {
                    uint32_t bs_len = (uint32_t)(asn1_get_length(&ku_ptr, ku_end));
                    if((bs_len >= 1U) && (x509_bytes_remaining(ku_ptr, ku_end) >= (size_t)bs_len)) {
                        uint32_t unused = (uint32_t)ku_ptr[0] & 0x7U;
                        const uint8_t *bits_data = &ku_ptr[1];
                        uint32_t bits_bytes = (uint32_t)(bs_len - 1U);
                        uint32_t num_bits = (uint32_t)(bits_bytes * 8U);
                        uint16_t bits = 0U;
                        uint32_t i = 0U;
                        if((unused <= 7U) && (num_bits >= unused)) {
                            num_bits -= unused;
                        }
                        {
                            static const uint16_t ku_bit16[9] = {
                                0x0001U, 0x0002U, 0x0004U, 0x0008U, 0x0010U, 0x0020U, 0x0040U, 0x0080U, 0x0100U
                            };
                            static const uint8_t ku_msb8[8] = {
                                0x80U, 0x40U, 0x20U, 0x10U, 0x08U, 0x04U, 0x02U, 0x01U
                            };
                            for(i = 0U; (i < num_bits) && (i < 9U); i += 1U) {
                                uint32_t byte_off = (uint32_t)(i >> 3U);
                                uint32_t bit_off = (uint32_t)(i & 7U);
                                if((byte_off < bits_bytes) &&
                                   ((bits_data[byte_off] & ku_msb8[bit_off]) != 0U)) {
                                    bits = (uint16_t)(bits | ku_bit16[i]);
                                }
                            }
                        }
                        cert->key_usage_bits = bits;
                    }
                }
            } else if(oid_equal(oid_buf, ext_oid_len, x509p_oid_basic_constraints, sizeof(x509p_oid_basic_constraints)) != 0) {
                const uint8_t *bc_ptr = val_data;
                const uint8_t *bc_end = &val_data[val_len];
                const uint8_t *bc_seq = NULL;
                uint32_t bc_seq_len = 0U;
                if(asn1_get_sequence(&bc_ptr, bc_end, &bc_seq, &bc_seq_len) == NOXTLS_RETURN_SUCCESS) {
                    const uint8_t *p = bc_seq;
                    const uint8_t *pe = &bc_seq[bc_seq_len];
                    cert->basic_constraints_ca = 0;
                    {
                        uint8_t pe_done = 0U;
                        while(((uintptr_t)p < (uintptr_t)pe) && (pe_done == 0U)) {
                            if(*p == 0x01U) {
                                int ca_val = 0;
                                /* cA BOOLEAN: a malformed BOOLEAN rejects the certificate (DER: length 1, 0x00/0xFF). */
                                if(asn1_get_boolean(&p, pe, &ca_val) != NOXTLS_RETURN_SUCCESS) {
                                    return NOXTLS_RETURN_BAD_DATA;
                                }
                                cert->basic_constraints_ca = (ca_val != 0) ? 1 : 0;
                            } else if(*p == 0x02U) {
                                uint8_t path_buf[4];
                                uint32_t path_buf_len = (uint32_t)sizeof(path_buf);
                                if((asn1_get_integer(&p, pe, path_buf, &path_buf_len) == NOXTLS_RETURN_SUCCESS) && (path_buf_len > 0U) && (path_buf_len <= 4U)) {
                                    uint32_t path_len = 0U;
                                    if((path_buf[0] & 0x80U) != 0U) {
                                        /* pathLenConstraint is INTEGER (0..MAX) (RFC 5280 4.2.1.9): a negative
                                         * value would otherwise read back as X509_BC_PATH_LEN_ABSENT (-1) or a
                                         * huge depth and silently lift the constraint. */
                                        return NOXTLS_RETURN_BAD_DATA;
                                    }
                                    uint32_t j = 0U;
                                    for(j = 0U; j < path_buf_len; j += 1U) { path_len = (path_len << 8U) | (uint32_t)(path_buf[j]); }
                                    cert->basic_constraints_path_len = (int)path_len;
                                } else {
                                    pe_done = 1U;  /* do not resume scanning from inside a malformed INTEGER */
                                }
                            } else {
                                uint32_t L = 0U;
                                p = &p[1];
                                if(asn1_get_bounded_length(&p, pe, &L) == NOXTLS_RETURN_SUCCESS) {
                                    p = &p[L];
                                } else {
                                    pe_done = 1U;
                                }
                            }
                        }
                    }
                }
            } else if(oid_equal(oid_buf, ext_oid_len, x509p_oid_ext_key_usage, sizeof(x509p_oid_ext_key_usage)) != 0) {
                const uint8_t *eku_ptr = val_data;
                const uint8_t *eku_end = &val_data[val_len];
                const uint8_t *eku_seq = NULL;
                uint32_t eku_seq_len = 0U;
                if(asn1_get_sequence(&eku_ptr, eku_end, &eku_seq, &eku_seq_len) == NOXTLS_RETURN_SUCCESS) {
                    const uint8_t *q = eku_seq;
                    const uint8_t *qe = &eku_seq[eku_seq_len];
                    while((uintptr_t)q < (uintptr_t)qe) {
                        uint8_t ko[32];
                        uint32_t ko_len = 0U;
                        if(asn1_get_oid(&q, qe, ko, &ko_len) == NOXTLS_RETURN_SUCCESS) {
                            if(oid_equal(ko, ko_len, x509p_oid_kp_server_auth, sizeof(x509p_oid_kp_server_auth)) != 0) { cert->ext_key_usage_bits |= X509_EKU_SERVER_AUTH; }
                            else if(oid_equal(ko, ko_len, x509p_oid_kp_client_auth, sizeof(x509p_oid_kp_client_auth)) != 0) { cert->ext_key_usage_bits |= X509_EKU_CLIENT_AUTH; }
                            else if(oid_equal(ko, ko_len, x509p_oid_kp_code_signing, sizeof(x509p_oid_kp_code_signing)) != 0) { cert->ext_key_usage_bits |= X509_EKU_CODE_SIGNING; }
                            else if(oid_equal(ko, ko_len, x509p_oid_kp_email_protection, sizeof(x509p_oid_kp_email_protection)) != 0) { cert->ext_key_usage_bits |= X509_EKU_EMAIL_PROTECTION; }
                            else if(oid_equal(
                            ko, ko_len, x509p_oid_kp_time_stamping, sizeof(x509p_oid_kp_time_stamping)) != 0) { cert->ext_key_usage_bits |= X509_EKU_TIME_STAMPING; }
                            else if(oid_equal(ko, ko_len, x509p_oid_kp_ocsp_signing, sizeof(x509p_oid_kp_ocsp_signing)) != 0) { cert->ext_key_usage_bits |= X509_EKU_OCSP_SIGNING; }
                            else if(oid_equal(ko, ko_len, x509p_oid_any_eku, sizeof(x509p_oid_any_eku)) != 0) { cert->ext_key_usage_bits |= X509_EKU_ANY; }
                            else {
                                /* MISRA 15.7: no remaining alternative */
                            }
                        } else { break; }
                    /* MISRA 15.7: final else path */
                    }
                }
            } else if(oid_equal(oid_buf, ext_oid_len, x509p_oid_authority_key_id, sizeof(x509p_oid_authority_key_id)) != 0) {
                const uint8_t *aki_ptr = val_data;
                const uint8_t *aki_end = &val_data[val_len];
                const uint8_t *aki_seq = NULL;
                uint32_t aki_seq_len = 0U;
                if(asn1_get_sequence(&aki_ptr, aki_end, &aki_seq, &aki_seq_len) == NOXTLS_RETURN_SUCCESS) {
                    /* AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT OCTET STRING OPTIONAL, ... }:
                     * the [0] primitive tag (0x80) carries the key identifier bytes directly. */
                    const uint8_t *r = aki_seq;
                    const uint8_t *re = &aki_seq[aki_seq_len];
                    if(((uintptr_t)r < (uintptr_t)re) && (*r == 0x80U)) {
                        uint32_t kid_len = 0U;
                        r = &r[1];
                        kid_len = (uint32_t)(asn1_get_length(&r, re));
                        if((kid_len > 0U) && (kid_len <= X509_KEY_ID_MAX_LEN) &&
                           (x509_bytes_remaining(r, re) >= (size_t)kid_len)) {
                            cert->authority_key_id_len = (uint8_t)kid_len;
                            noxtls_copy_u8((uint8_t *)(void *)(cert->authority_key_id), (size_t)kid_len, (const uint8_t *)(const void *)(r), (size_t)kid_len);
                        }
                    }
                }
            } else if(oid_equal(oid_buf, ext_oid_len, x509p_oid_subject_key_id, sizeof(x509p_oid_subject_key_id)) != 0) {
                /* extnValue holds the DER SubjectKeyIdentifier (an OCTET STRING); store only its contents. */
                const uint8_t *ski_ptr = val_data;
                const uint8_t *ski_data = NULL;
                uint32_t ski_len = 0U;
                if((asn1_get_octet_string(&ski_ptr, &val_data[val_len], &ski_data, &ski_len) == NOXTLS_RETURN_SUCCESS) &&
                   (ski_len > 0U) && (ski_len <= X509_KEY_ID_MAX_LEN)) {
                    cert->subject_key_id_len = (uint8_t)ski_len;
                    noxtls_copy_u8((uint8_t *)(void *)(cert->subject_key_id), (size_t)ski_len, (const uint8_t *)(const void *)(ski_data), (size_t)ski_len);
                }
            } else if((oid_equal(oid_buf, ext_oid_len, x509p_oid_certificate_policies, sizeof(x509p_oid_certificate_policies)) != 0) || (oid_equal(oid_buf, ext_oid_len, x509p_oid_crl_distribution_points, sizeof(x509p_oid_crl_distribution_points)) != 0) || (oid_equal(oid_buf, ext_oid_len, x509p_oid_name_constraints, sizeof(x509p_oid_name_constraints)) != 0) || (oid_equal(oid_buf, ext_oid_len, x509p_oid_policy_constraints, sizeof(x509p_oid_policy_constraints)) != 0) || (oid_equal(oid_buf, ext_oid_len, x509p_oid_inhibit_any_policy, sizeof(x509p_oid_inhibit_any_policy)) != 0)) {
                /*
                 * These extensions are recognized, but their policy semantics are not
                 * enforced here. Critical instances must fail closed.
                 */
                if(ext_critical != 0) {
                    return NOXTLS_RETURN_BAD_DATA;
                }
            } else {
                /* Unknown or custom OID */
                if(ext_critical != 0) {
                    if(noxtls_x509_unknown_ext_cb != NULL) {
                        if(noxtls_x509_unknown_ext_cb(oid_buf, ext_oid_len, val_data, val_len, 1, noxtls_x509_unknown_ext_user_ctx) != NOXTLS_RETURN_SUCCESS) {
                            return NOXTLS_RETURN_BAD_DATA;
                        }
                    } else {
                        /* MISRA 15.7: final else path */
                        return NOXTLS_RETURN_BAD_DATA;
                    }
                } else {
                    if(noxtls_x509_unknown_ext_cb != NULL) {
                        (void)noxtls_x509_unknown_ext_cb(oid_buf, ext_oid_len, val_data, val_len, 0, noxtls_x509_unknown_ext_user_ctx);
                    }
                }
            }
            list_ptr = &ext_seq[ext_seq_len];
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Compares two strings case-insensitively for DNS (ASCII); hostname_len = length of hostname (no null required).
 *
 * This function compares two strings case-insensitively for DNS (ASCII); hostname_len = length of hostname (no null required).
 *
 * @param[in] hostname The hostname to compare.
 * @param[in] hostname_len The length of the hostname.
 * @param[in] dns_name The DNS name to compare.
 *
 * @return The return code of the function.
 */
static int noxtls_x509_dns_name_equal(const uint8_t *hostname, uint32_t hostname_len, const uint8_t *dns_name)
{
    uint32_t i = 0U;
    uint32_t dns_name_len = 0U;
    if(dns_name == NULL) {
        return 0;
    }

    while(dns_name[dns_name_len] != 0U) {
        dns_name_len += 1U;
    }

    if((s_x509_hostname_wildcard_matching != 0) &&
       (dns_name_len > X509_HOSTNAME_WILDCARD_PREFIX_LEN) &&
       (dns_name[0] == (uint8_t)0x2AU) &&
       (dns_name[1] == (uint8_t)0x2EU)) {
        uint32_t first_dot_index = 0U;
        uint32_t suffix_len = 0U;
        int has_first_dot = 0;
        int has_second_wildcard = 0;
        uint32_t j = X509_HOSTNAME_WILDCARD_PREFIX_LEN;
        while(j < dns_name_len) {
            if(dns_name[j] == (uint8_t)'*') {
                has_second_wildcard = 1;
                break;
            }
            j += 1U;
        }
        if(has_second_wildcard != 0) {
            return 0;
        }

        /* SECURITY (NX-18): the wildcard must not span a whole registry-level domain.
         * Require at least two labels after "*." (e.g. "*.example.com"), rejecting
         * certificates such as "*.com" that would match every second-level name. */
        {
            uint32_t dot_count = 0U;
            uint32_t k = 0U;
            for(k = 1U; k < dns_name_len; k += 1U) {
                if(dns_name[k] == (uint8_t)'.') {
                    dot_count += 1U;
                }
            }
            if(dot_count < 2U) {
                return 0;
            }
        }

        {
            uint8_t dot_scan_done = 0U;
            while((first_dot_index < hostname_len) && (dot_scan_done == 0U)) {
                if(hostname[first_dot_index] == (uint8_t)'.') {
                    has_first_dot = 1;
                    dot_scan_done = 1U;
                } else if(hostname[first_dot_index] == 0U) {
                    dot_scan_done = 1U;
                } else {
                    first_dot_index += 1U;
                }
            }
        }

        if((has_first_dot == 0) || (first_dot_index == 0U)) {
            return 0;
        }

        suffix_len = hostname_len - first_dot_index;
        if(suffix_len != (dns_name_len - 1U)) {
            return 0;
        }

        i = 0U;
        while(i < suffix_len) {
            unsigned char a = (uint8_t)hostname[first_dot_index + i];
            unsigned char b = (uint8_t)dns_name[1U + i];
            if((a >= (uint8_t)'A') && (a <= (uint8_t)'Z')) { a = (uint8_t)(a + 32U); }
            if((b >= (uint8_t)'A') && (b <= (uint8_t)'Z')) { b = (uint8_t)(b + 32U); }
            if(a != b) {
                return 0;
            }
            i += 1U;
        }
        return 1;
    }

    while((i < hostname_len) && (hostname[i] != 0U) && (dns_name[i] != 0U)) {
        unsigned char a = (uint8_t)hostname[i];
        unsigned char b = (uint8_t)dns_name[i];
        if((a >= (uint8_t)'A') && (a <= (uint8_t)'Z')) { a = (uint8_t)(a + 32U); }
        if((b >= (uint8_t)'A') && (b <= (uint8_t)'Z')) { b = (uint8_t)(b + 32U); }
        if(a != b) { return 0; }
        i += 1U;
    }

    if(i != hostname_len) {
        return 0;
    }
    return (dns_name[i] == 0U) ? 1 : 0;
}


/**
 * @brief Return 1 when an AttributeValue tag is a string type usable as a DNS name.
 *
 * PrintableString, UTF8String, IA5String and TeletexString carry one octet per ASCII
 * character; BMPString/UniversalString (multi-octet) are never compared as host names.
 */
static int x509_cn_value_tag_ok(uint8_t tag)
{
    return ((tag == 0x13U) || (tag == 0x0CU) || (tag == 0x16U) || (tag == 0x14U)) ? 1 : 0;
}

/**
 * @brief Match @p hostname against the subject commonName attributes (OID 2.5.4.3).
 *
 * Walks the DER RDNSequence kept in cert->subject (every AttributeTypeAndValue of every RDN,
 * including multi-valued RDNs) instead of searching the formatted subject_dn text, where an
 * attribute such as O="CN=victim.example" would otherwise be taken for a CN. CN values that
 * are not a single-octet string type, contain a NUL, or do not fit @p cn_buf are ignored;
 * leading/trailing spaces of a value are not compared.
 *
 * @param[in] cert          Parsed certificate.
 * @param[in] hostname      Expected hostname.
 * @param[in] host_len      Length of @p hostname.
 * @param[in] cn_buf        Scratch buffer for one NUL-terminated CN value.
 * @param[in] cn_buf_size   Size of @p cn_buf.
 *
 * @return 1 when a commonName attribute matches, 0 otherwise.
 */
static int x509_subject_cn_matches(const x509_certificate_t *cert, const uint8_t *hostname, uint32_t host_len,
                                   uint8_t *cn_buf, uint32_t cn_buf_size)
{
    static const uint8_t x509_oid_common_name[] = { 0x55U, 0x04U, 0x03U };
    const uint8_t *dn_ptr = cert->subject;
    const uint8_t *dn_end = NULL;
    int matched = 0;

    if((cert->subject_len == 0U) || (cert->subject_len > (uint32_t)sizeof(cert->subject)) || (cn_buf_size < 2U)) {
        return 0;
    }
    dn_end = &cert->subject[cert->subject_len];

    while(((uintptr_t)dn_ptr < (uintptr_t)dn_end) && (matched == 0)) {
        const uint8_t *set_ptr = NULL;
        const uint8_t *set_end = NULL;
        uint32_t set_len = 0U;

        /* RelativeDistinguishedName ::= SET OF AttributeTypeAndValue */
        if((asn1_get_tag(&dn_ptr, dn_end, 0x31U) != NOXTLS_RETURN_SUCCESS) ||
           (asn1_get_bounded_length(&dn_ptr, dn_end, &set_len) != NOXTLS_RETURN_SUCCESS)) {
            break;
        }
        set_ptr = dn_ptr;
        set_end = &dn_ptr[set_len];
        dn_ptr = set_end;

        while(((uintptr_t)set_ptr < (uintptr_t)set_end) && (matched == 0)) {
            const uint8_t *atv = NULL;
            const uint8_t *atv_end = NULL;
            uint32_t atv_len = 0U;
            uint8_t attr_oid[32];
            uint32_t attr_oid_len = 0U;
            uint8_t value_tag = 0U;
            uint32_t value_len = 0U;

            if(asn1_get_sequence(&set_ptr, set_end, &atv, &atv_len) != NOXTLS_RETURN_SUCCESS) {
                break;
            }
            atv_end = &atv[atv_len];
            if((asn1_get_oid(&atv, atv_end, attr_oid, &attr_oid_len) != NOXTLS_RETURN_SUCCESS) ||
               (oid_equal(attr_oid, attr_oid_len, x509_oid_common_name, (uint32_t)sizeof(x509_oid_common_name)) == 0) ||
               (x509_bytes_remaining(atv, atv_end) < 2U)) {
                continue;
            }
            value_tag = atv[0];
            atv = &atv[1];
            if((x509_cn_value_tag_ok(value_tag) == 0) ||
               (asn1_get_bounded_length(&atv, atv_end, &value_len) != NOXTLS_RETURN_SUCCESS) ||
               (value_len == 0U) || (value_len >= cn_buf_size) || (x509_bytes_have_nul(atv, value_len) != 0)) {
                continue;
            }
            /* Surrounding spaces are not part of a host name (legacy CN values sometimes carry them). */
            while((value_len > 0U) && (atv[0] == (uint8_t)' ')) {
                atv = &atv[1];
                value_len -= 1U;
            }
            while((value_len > 0U) && (atv[value_len - 1U] == (uint8_t)' ')) {
                value_len -= 1U;
            }
            if(value_len == 0U) {
                continue;
            }
            x509_copy_bytes_to_chars(cn_buf, atv, value_len);
            cn_buf[value_len] = 0U;
            if(noxtls_x509_dns_name_equal(hostname, host_len, cn_buf) != 0) {
                matched = 1;
            }
        }
    }
    return matched;
}

/**
 * @brief Check whether the certificate is valid for the given hostname (RFC 6125 style).
 * Prefer SAN dNSName; if none, fall back to the subject commonName attribute(s) of the DER subject
 * Name (never the formatted subject_dn text). Comparison is case-insensitive for DNS.
 *
 * @param cert Parsed certificate (must have been parsed so subject_dn and optionally san_dns_* are set).
 * @param hostname Expected hostname (need not be null-terminated).
 * @param hostname_len Length of hostname.
 *
 * @return NOXTLS_RETURN_SUCCESS if hostname matches a SAN dNSName or subject CN; NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH otherwise; NOXTLS_RETURN_NULL if cert or hostname is NULL.
 */
noxtls_return_t noxtls_x509_certificate_matches_hostname(const x509_certificate_t *cert, const uint8_t *hostname, uint32_t hostname_len)
{
    uint8_t *cn_buf = NULL;
    const uint32_t cn_buf_size = 256U;
    uint32_t host_len = hostname_len;

    if((cert == NULL) || (hostname == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if(host_len == 0U) {
        while((host_len < 256U) && (hostname[host_len] != 0U)) { host_len += 1U; }
    }

    if(host_len == 0U) {
        cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH, cert, hostname, 0, 0);
        return NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH;
    }

    /* Prefer SAN dNSName */
    if(cert->san_dns_count > 0U) {
        uint8_t i = 0U;
        for(i = 0U; i < cert->san_dns_count; i += 1U) {
            if(noxtls_x509_dns_name_equal(hostname, host_len, cert->san_dns_names[i]) != 0) {
                return NOXTLS_RETURN_SUCCESS;
            }
        }
        cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH, cert, hostname, host_len, 0);
        return NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH;
    }

    /* Fallback: subject CN */
    cn_buf = (uint8_t *)NOXTLS_MALLOC(cn_buf_size);
    if(cn_buf == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    if(x509_subject_cn_matches(cert, hostname, host_len, cn_buf, cn_buf_size) != 0) {
        (void)noxtls_free(cn_buf);
        return NOXTLS_RETURN_SUCCESS;
    }

    (void)noxtls_free(cn_buf);
    cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH, cert, hostname, hostname_len, 0);
    return NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH;
}

/**
 * @brief Initialize X.509 certificate structure
 *
 * This function initializes the X.509 certificate structure.
 *
 * @param[in] cert The certificate to initialize.
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_certificate_init(x509_certificate_t *cert)
{
    if(cert == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero((cert), sizeof(x509_certificate_t));
    cert->parsed = 0;

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Free X.509 certificate structure
 *
 * This function frees the X.509 certificate structure.
 *
 * @param[in] cert The certificate to free.
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_certificate_free(x509_certificate_t *cert)
{
    if(cert == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(cert->rsa_modulus != NULL) {
        (void)noxtls_free(cert->rsa_modulus);
        cert->rsa_modulus = NULL;
    }

    if(cert->rsa_exponent != NULL) {
        (void)noxtls_free(cert->rsa_exponent);
        cert->rsa_exponent = NULL;
    }

    if(cert->ecc_public_key != NULL) {
        (void)noxtls_free(cert->ecc_public_key);
        cert->ecc_public_key = NULL;
    }

    if(cert->extensions != NULL) {
        (void)noxtls_free(cert->extensions);
        cert->extensions = NULL;
    }

    if(cert->signature != NULL) {
        (void)noxtls_free(cert->signature);
        cert->signature = NULL;
    }

    if(cert->raw_data != NULL) {
        (void)noxtls_free(cert->raw_data);
        cert->raw_data = NULL;
    }

    if(cert->tbs_certificate != NULL) {
        (void)noxtls_free(cert->tbs_certificate);
        cert->tbs_certificate = NULL;
    }

    noxtls_secure_zero((cert), sizeof(x509_certificate_t));

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Parse X.509 certificate from DER format
 *
 * This function parses an X.509 certificate from a DER encoded buffer.
 *
 * @param[in] cert The certificate to parse.
 * @param[in] data The DER encoded buffer to parse.
 * @param[in] len The length of the DER encoded buffer.
 * @return The return code of the function.
 */
static noxtls_return_t x509_certificate_parse_der_body(x509_certificate_t *cert, const uint8_t *data, uint32_t len)
{
    /* EdDSA algorithm OIDs local to this function (Rule 8.9). */
    static const uint8_t s_oid_ed25519[] = { 0x2BU, 0x65U, 0x70U };
    static const uint8_t s_oid_ed448[] = { 0x2BU, 0x65U, 0x71U };
    /* id-ecPublicKey 1.2.840.10045.2.1 (RFC 5480). */
    static const uint8_t s_oid_ec_public_key[] = { 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x02U, 0x01U };
    /* rsaEncryption 1.2.840.113549.1.1.1 and id-RSASSA-PSS 1.2.840.113549.1.1.10 (RFC 3279, RFC 4055). */
    static const uint8_t s_oid_rsa_encryption[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x01U, 0x01U };
    static const uint8_t s_oid_rsassa_pss[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x01U, 0x0AU };

    const uint8_t *ptr = data;
    const uint8_t *end = &data[len];
    const uint8_t *tbs_cert = NULL;
    uint32_t tbs_cert_len = 0U;
    const uint8_t *seq_data = NULL;
    uint32_t seq_len = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

        if(asn1_get_sequence(&ptr, end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            return rc;
        }

        const uint8_t *cert_end = &seq_data[seq_len];
        ptr = seq_data;

        {
            const uint8_t *tbs_seq_start = ptr;
            if(asn1_get_sequence(&ptr, cert_end, &tbs_cert, &tbs_cert_len) != NOXTLS_RETURN_SUCCESS) {
                rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
                return rc;
            }

            /* Signature is computed over full DER TBSCertificate (&tag[length+value]), not value only. */
            cert->tbs_certificate_len = (uint32_t)((uintptr_t)ptr - (uintptr_t)tbs_seq_start);
            cert->tbs_certificate = (uint8_t*)NOXTLS_MALLOC(cert->tbs_certificate_len);
            if(cert->tbs_certificate == NULL) {
                rc = NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
                return rc;
            }
            noxtls_copy_u8((uint8_t *)(void *)(cert->tbs_certificate), (size_t)cert->tbs_certificate_len, (const uint8_t *)(const void *)(tbs_seq_start), (size_t)cert->tbs_certificate_len);
        }

    const uint8_t *tbs_end = &tbs_cert[tbs_cert_len];
    const uint8_t *tbs_ptr = tbs_cert;

    /* Parse version (optional, v1 certificates don't have it) */
    if(((uintptr_t)tbs_ptr < (uintptr_t)tbs_end) && ((*tbs_ptr & 0xE0U) == 0xA0U) && ((*tbs_ptr & 0x1FU) == 0x00U)) {
        /* Context-specific tag [0] EXPLICIT for version. A wrapper whose length is malformed or runs
         * past the TBSCertificate is rejected: there is no in-bounds place to resume parsing from. */
        uint32_t version_wrapper_len = 0U;
        tbs_ptr = &tbs_ptr[1];
        if((asn1_get_bounded_length(&tbs_ptr, tbs_end, &version_wrapper_len) != NOXTLS_RETURN_SUCCESS) ||
           (version_wrapper_len == 0U)) {
            return NOXTLS_RETURN_CERT_PARSE_FAILED;
        }
        {
            const uint8_t *version_end = &tbs_ptr[version_wrapper_len];
            uint32_t ver_len = 0U;
            if((asn1_get_tag(&tbs_ptr, version_end, 0x02U) == NOXTLS_RETURN_SUCCESS) &&
               (asn1_get_bounded_length(&tbs_ptr, version_end, &ver_len) == NOXTLS_RETURN_SUCCESS) &&
               (ver_len > 0U)) {
                cert->version = tbs_ptr[ver_len - 1U];
            }
            /* A malformed inner INTEGER leaves the version unset; resume at the (bounded) wrapper end. */
            tbs_ptr = version_end;
        }
    } else {
        cert->version = 0U;  /* v1 */
    }

        cert->serial_number_len = X509_MAX_SERIAL_SIZE;
        if(asn1_get_integer(&tbs_ptr, tbs_end, cert->serial_number, &cert->serial_number_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            return rc;
        }

        if(asn1_get_sequence(&tbs_ptr, tbs_end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            return rc;
        }
        const uint8_t *alg_end = &seq_data[seq_len];
        const uint8_t *alg_ptr = seq_data;

        if(asn1_get_oid(&alg_ptr, alg_end, cert->signature_algorithm_oid, &cert->signature_algorithm_oid_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            return rc;
        }

    if((uintptr_t)alg_ptr < (uintptr_t)alg_end) {
        alg_ptr = alg_end;
    }

        if(asn1_get_sequence(&tbs_ptr, tbs_end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            return rc;
        }
        if(seq_len > X509_MAX_ISSUER_SIZE) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            return rc;
        }
    noxtls_copy_u8((uint8_t *)(void *)(cert->issuer), (size_t)seq_len, (const uint8_t *)(const void *)(seq_data), (size_t)seq_len);
    cert->issuer_len = seq_len;
    (void)noxtls_x509_parse_distinguished_name(seq_data, seq_len, cert->issuer_dn, sizeof(cert->issuer_dn));

        if(asn1_get_sequence(&tbs_ptr, tbs_end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            return rc;
        }
    if(seq_len >= 13U) {
        const uint8_t *validity_ptr = seq_data;
        const uint8_t *validity_end = &seq_data[seq_len];
        /* Parse notBefore */
        if(((uintptr_t)validity_ptr < (uintptr_t)validity_end) && ((*validity_ptr == 0x17U) || (*validity_ptr == 0x18U))) {
            validity_ptr = &validity_ptr[1];  /* Skip tag */
            uint32_t time_len = (uint32_t)(asn1_get_length(&validity_ptr, validity_end));
            if((time_len > 0U) && (x509_bytes_remaining(validity_ptr, validity_end) >= (size_t)time_len)) {
                /* Clear the buffer first */
                noxtls_secure_zero((cert->not_before), (size_t)15);
                /* Copy up to 15 bytes; null-terminate */
                uint32_t copy_len = (uint32_t)((time_len > 15U) ? 15U : time_len);
                noxtls_copy_u8((uint8_t *)(void *)(cert->not_before), (size_t)copy_len, (const uint8_t *)(const void *)(validity_ptr), (size_t)copy_len);
                cert->not_before[14] = 0;
                validity_ptr = &validity_ptr[time_len];
            }
        }

        /* Parse notAfter */
        if(((uintptr_t)validity_ptr < (uintptr_t)validity_end) && ((*validity_ptr == 0x17U) || (*validity_ptr == 0x18U))) {
            validity_ptr = &validity_ptr[1];  /* Skip tag */
            uint32_t time_len = (uint32_t)(asn1_get_length(&validity_ptr, validity_end));
            if((time_len > 0U) && (x509_bytes_remaining(validity_ptr, validity_end) >= (size_t)time_len)) {
                /* Clear the buffer first */
                noxtls_secure_zero((cert->not_after), (size_t)15);
                /* Copy up to 15 bytes (e.g. YYYYMMDDHHMMSSZ or YYYYMMDDHHMMSS.); null-terminate */
                uint32_t copy_len = (uint32_t)((time_len > 15U) ? 15U : time_len);
                noxtls_copy_u8((uint8_t *)(void *)(cert->not_after), (size_t)copy_len, (const uint8_t *)(const void *)(validity_ptr), (size_t)copy_len);
                cert->not_after[14] = 0;
            }
        }
    }

        if(asn1_get_sequence(&tbs_ptr, tbs_end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            return rc;
        }
        if(seq_len > X509_MAX_SUBJECT_SIZE) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            return rc;
        }
    noxtls_copy_u8((uint8_t *)(void *)(cert->subject), (size_t)seq_len, (const uint8_t *)(const void *)(seq_data), (size_t)seq_len);
    cert->subject_len = seq_len;
    (void)noxtls_x509_parse_distinguished_name(seq_data, seq_len, cert->subject_dn, sizeof(cert->subject_dn));

        if(asn1_get_sequence(&tbs_ptr, tbs_end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            return rc;
        }
    const uint8_t *spki_end = &seq_data[seq_len];
    const uint8_t *spki_ptr = seq_data;

        const uint8_t *spki_alg_data = NULL;
        uint32_t spki_alg_len = 0U;
        if(asn1_get_sequence(&spki_ptr, spki_end, &spki_alg_data, &spki_alg_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            return rc;
        }
        const uint8_t *spki_alg_end = &spki_alg_data[spki_alg_len];
        const uint8_t *spki_alg_ptr = spki_alg_data;

        if(asn1_get_oid(&spki_alg_ptr, spki_alg_end, cert->public_key_algorithm_oid, &cert->public_key_algorithm_oid_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            return rc;
        }

    /* id-ecPublicKey parameters: namedCurve OID (RFC 5480 2.1.1). Other forms leave the curve unset. */
    if((oid_equal(cert->public_key_algorithm_oid, cert->public_key_algorithm_oid_len,
                  s_oid_ec_public_key, (uint32_t)sizeof(s_oid_ec_public_key)) != 0) &&
       ((uintptr_t)spki_alg_ptr < (uintptr_t)spki_alg_end) && (*spki_alg_ptr == 0x06U)) {
        const uint8_t *curve_ptr = spki_alg_ptr;
        if(asn1_get_oid(&curve_ptr, spki_alg_end, cert->ecc_curve_oid, &cert->ecc_curve_oid_len) != NOXTLS_RETURN_SUCCESS) {
            cert->ecc_curve_oid_len = 0U;
        }
    }
    if(((uintptr_t)spki_alg_ptr < (uintptr_t)spki_alg_end)) {
        spki_alg_ptr = spki_alg_end;
    }

        if(asn1_get_tag(&spki_ptr, spki_end, 0x03U) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            return rc;
        }
    uint32_t public_key_len = (uint32_t)(asn1_get_length(&spki_ptr, spki_end));
    if((public_key_len > 0U) && (x509_bytes_remaining(spki_ptr, spki_end) >= (size_t)public_key_len)) {
        /* Skip unused bits byte */
        spki_ptr = &spki_ptr[1];
        public_key_len -= 1U;

        if(public_key_len <= X509_MAX_PUBLIC_KEY_SIZE) {
            const uint8_t *pkalg = cert->public_key_algorithm_oid;
            uint32_t pkalg_len = cert->public_key_algorithm_oid_len;

            noxtls_copy_u8((uint8_t *)(void *)(cert->public_key), (size_t)public_key_len, (const uint8_t *)(const void *)(spki_ptr), (size_t)public_key_len);
            cert->public_key_len = public_key_len;

            /* Dispatch on the SubjectPublicKeyInfo algorithm OID, never on the key's first byte. */
            if((oid_equal(pkalg, pkalg_len, s_oid_rsa_encryption, (uint32_t)sizeof(s_oid_rsa_encryption)) != 0) ||
               (oid_equal(pkalg, pkalg_len, s_oid_rsassa_pss, (uint32_t)sizeof(s_oid_rsassa_pss)) != 0)) {
                const uint8_t *pk_ptr = spki_ptr;
                const uint8_t *pk_end = &spki_ptr[public_key_len];
                if(asn1_get_sequence(&pk_ptr, pk_end, &seq_data, &seq_len) == NOXTLS_RETURN_SUCCESS) {
                /* RSA public key: SEQUENCE { modulus INTEGER, exponent INTEGER } */
                const uint8_t *rsa_seq_end = &seq_data[seq_len];
                const uint8_t *rsa_seq_ptr = seq_data;
                const uint8_t *mod_start = rsa_seq_ptr;
                uint32_t mod_len = 0U;
                if(asn1_get_integer(&rsa_seq_ptr, rsa_seq_end, NULL, &mod_len) == NOXTLS_RETURN_SUCCESS) {
                    uint32_t mod_len2 = mod_len;
                    cert->rsa_modulus = (uint8_t*)NOXTLS_MALLOC(mod_len);
                    if(cert->rsa_modulus == NULL) {
                        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
                    }
                    cert->rsa_modulus_len = mod_len;
                    rsa_seq_ptr = mod_start;
                    if(asn1_get_integer(&rsa_seq_ptr, rsa_seq_end, cert->rsa_modulus, &mod_len2) != NOXTLS_RETURN_SUCCESS) {
                        (void)noxtls_free(cert->rsa_modulus);
                        cert->rsa_modulus = NULL;
                        cert->rsa_modulus_len = 0U;
                    }
                }
                const uint8_t *exp_start = rsa_seq_ptr;
                uint32_t exp_len = 0U;
                if(asn1_get_integer(&rsa_seq_ptr, rsa_seq_end, NULL, &exp_len) == NOXTLS_RETURN_SUCCESS) {
                    uint32_t exp_len2 = exp_len;
                    cert->rsa_exponent = (uint8_t*)NOXTLS_MALLOC(exp_len);
                    if(cert->rsa_exponent == NULL) {
                        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
                    }
                    cert->rsa_exponent_len = exp_len;
                    rsa_seq_ptr = exp_start;
                    if(asn1_get_integer(&rsa_seq_ptr, rsa_seq_end, cert->rsa_exponent, &exp_len2) != NOXTLS_RETURN_SUCCESS) {
                        (void)noxtls_free(cert->rsa_exponent);
                        cert->rsa_exponent = NULL;
                        cert->rsa_exponent_len = 0U;
                    }
                }
                }
            } else if(oid_equal(pkalg, pkalg_len, s_oid_ec_public_key, (uint32_t)sizeof(s_oid_ec_public_key)) != 0) {
                if((public_key_len > 0U) && (spki_ptr[0] == 0x04U)) {
                    /* ECC public key: uncompressed point 0x04 || x || y. */
                    rc = noxtls_x509_validate_ecc_public_key_bytes(spki_ptr,
                                                                   public_key_len,
                                                                   cert->ecc_curve_oid,
                                                                   cert->ecc_curve_oid_len);
                    if(rc == NOXTLS_RETURN_NOT_ENOUGH_MEMORY) {
                        return rc;
                    }
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        CERT_DEBUG_PRINT("x509_certificate_parse_der: invalid ECC public key\n");
                        return NOXTLS_RETURN_BAD_DATA;
                    }
                    cert->ecc_public_key = (uint8_t*)NOXTLS_MALLOC(public_key_len);
                    if(cert->ecc_public_key == NULL) {
                        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
                    }
                    cert->ecc_public_key_len = public_key_len;
                    noxtls_copy_u8((uint8_t *)(void *)(cert->ecc_public_key), (size_t)public_key_len, (const uint8_t *)(const void *)(spki_ptr), (size_t)public_key_len);
                }
            } else if(oid_equal(pkalg, pkalg_len, s_oid_ed25519, (uint32_t)sizeof(s_oid_ed25519)) != 0) {
                if(public_key_len == 32U) {
                    /* Ed25519 public key (OID 1.3.101.112 id-Ed25519): 32-byte raw key */
                    cert->has_ed25519 = 1U;
                    noxtls_copy_u8((uint8_t *)(void *)(cert->ed25519_public_key), (size_t)32, (const uint8_t *)(const void *)(spki_ptr), (size_t)32);
                }
            } else if(oid_equal(pkalg, pkalg_len, s_oid_ed448, (uint32_t)sizeof(s_oid_ed448)) != 0) {
                if(public_key_len == 57U) {
                    /* Ed448 public key (OID 1.3.101.113 id-Ed448): 57-byte raw key (RFC 8410) */
                    cert->has_ed448 = 1U;
                    noxtls_copy_u8((uint8_t *)(void *)(cert->ed448_public_key), (size_t)57, (const uint8_t *)(const void *)(spki_ptr), (size_t)57);
                }
            } else {
                /* MISRA 15.7: other algorithms (PQC below, X25519/X448, unknown) */
            }
#if NOXTLS_FEATURE_ML_DSA
            if((cert->has_ed25519 == 0U) && (cert->has_ed448 == 0U)) {
                uint32_t mldsa_pk_len_44 = noxtls_mldsa_public_key_len(NOXTLS_MLDSA_44);
                uint32_t mldsa_pk_len_65 = noxtls_mldsa_public_key_len(NOXTLS_MLDSA_65);
                uint32_t mldsa_pk_len_87 = noxtls_mldsa_public_key_len(NOXTLS_MLDSA_87);
                int mldsa_len_ok = 0;
                if(public_key_len == mldsa_pk_len_44) {
                    mldsa_len_ok = 1;
                } else if(public_key_len == mldsa_pk_len_65) {
                    mldsa_len_ok = 1;
                } else if(public_key_len == mldsa_pk_len_87) {
                    mldsa_len_ok = 1;
                }
                 else {
                     /* MISRA 15.7: no remaining alternative */
                 }
                if((mldsa_len_ok != 0) &&
                   (cert->public_key_algorithm_oid_len >= 7U) &&
                   (cert->public_key_algorithm_oid[0] == 0x60U) &&
                   (cert->public_key_algorithm_oid[1] == 0x86U) &&
                   (cert->public_key_algorithm_oid[2] == 0x48U) &&
                   (cert->public_key_algorithm_oid[3] == 0x01U) &&
                   (cert->public_key_algorithm_oid[4] == 0x65U)) {
                    cert->has_mldsa = 1U;
                    cert->mldsa_public_key_len = public_key_len;
                    if(public_key_len == mldsa_pk_len_44) {
                        cert->mldsa_param = NOXTLS_MLDSA_44;
                    } else if(public_key_len == mldsa_pk_len_65) {
                        cert->mldsa_param = NOXTLS_MLDSA_65;
                    } else {
                        cert->mldsa_param = NOXTLS_MLDSA_87;
                    }
                    noxtls_copy_u8((uint8_t *)(void *)(cert->mldsa_public_key), (size_t)public_key_len, (const uint8_t *)(const void *)(spki_ptr), (size_t)public_key_len);
                }
            }
#endif
#if NOXTLS_FEATURE_SLH_DSA
            if((cert->has_ed25519 == 0U) && (cert->has_ed448 == 0U) && (cert->has_mldsa == 0U)) {
                noxtls_slhdsa_param_t slhdsa_param = NOXTLS_SLHDSA_NONE;
                uint32_t slhdsa_pk_len = 0U;
                if(noxtls_x509_slhdsa_param_from_oid(cert->public_key_algorithm_oid,
                                                     cert->public_key_algorithm_oid_len,
                                                     &slhdsa_param) == NOXTLS_RETURN_SUCCESS) {
                    slhdsa_pk_len = noxtls_slhdsa_public_key_len(slhdsa_param);
                    if(public_key_len == slhdsa_pk_len) {
                        cert->has_slhdsa = 1U;
                        cert->slhdsa_public_key_len = public_key_len;
                        cert->slhdsa_param = slhdsa_param;
                        noxtls_copy_u8((uint8_t *)(void *)(cert->slhdsa_public_key), (size_t)public_key_len, (const uint8_t *)(const void *)(spki_ptr), (size_t)public_key_len);
                    }
                }
            }
#endif
#if NOXTLS_FEATURE_FALCON
            if((cert->has_mldsa == 0U) && (cert->has_slhdsa == 0U)) {
                int falcon_param = x509_oid_is_falcon(cert->public_key_algorithm_oid,
                                                      cert->public_key_algorithm_oid_len);
                if(falcon_param != 0) {
                    uint32_t falcon_pk_len = noxtls_falcon_public_key_len((noxtls_falcon_param_t)falcon_param);
                    if(public_key_len == falcon_pk_len) {
                        cert->has_falcon = 1U;
                        cert->falcon_param = (noxtls_falcon_param_t)falcon_param;
                        cert->falcon_public_key_len = public_key_len;
                        noxtls_copy_u8((uint8_t *)(void *)(cert->falcon_public_key), (size_t)public_key_len, (const uint8_t *)(const void *)(spki_ptr), (size_t)public_key_len);
                    }
                }
            }
#endif
        }
    }

    if((cert->version >= 2U) && ((uintptr_t)tbs_ptr < (uintptr_t)tbs_end)) {
        if(((*tbs_ptr & 0xE0U) == 0xA0U) && ((*tbs_ptr & 0x1FU) == 0x03U)) {
            tbs_ptr = &tbs_ptr[1];
            uint32_t ext_len = (uint32_t)(asn1_get_length(&tbs_ptr, tbs_end));
            if((ext_len > 0U) && (x509_bytes_remaining(tbs_ptr, tbs_end) >= (size_t)ext_len)) {
                noxtls_return_t ext_rc = NOXTLS_RETURN_FAILED;
                cert->extensions = (uint8_t*)NOXTLS_MALLOC(ext_len);
                if(cert->extensions == NULL) {
                    /* Never report success for a certificate whose extensions were not checked. */
                    return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
                }
                noxtls_copy_u8((uint8_t *)(void *)(cert->extensions), (size_t)ext_len, (const uint8_t *)(const void *)(tbs_ptr), (size_t)ext_len);
                cert->extensions_len = ext_len;
                tbs_ptr = &tbs_ptr[ext_len];
                ext_rc = noxtls_x509_parse_extensions(cert);
                if(ext_rc != NOXTLS_RETURN_SUCCESS) {
                    rc = (ext_rc == NOXTLS_RETURN_FAILED) ? NOXTLS_RETURN_CERT_PARSE_FAILED : ext_rc;
                    return rc;
                }
            }
        }
    }

        const uint8_t *sig_alg_data = NULL;
        uint32_t sig_alg_len = 0U;
        if(asn1_get_sequence(&ptr, cert_end, &sig_alg_data, &sig_alg_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            return rc;
        }
    const uint8_t *sig_alg_end = &sig_alg_data[sig_alg_len];
    const uint8_t *sig_alg_ptr = sig_alg_data;

    (void)asn1_get_oid(&sig_alg_ptr, sig_alg_end, cert->signature_algorithm_oid, &cert->signature_algorithm_oid_len);

        if(asn1_get_tag(&ptr, cert_end, 0x03U) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            return rc;
        }
        uint32_t sig_len = (uint32_t)(asn1_get_length(&ptr, cert_end));
        if((sig_len > 0U) && (x509_bytes_remaining(ptr, cert_end) >= (size_t)sig_len)) {
            ptr = &ptr[1];  /* Skip unused bits */
            sig_len -= 1U;
            if(sig_len > 0U) {
                cert->signature = (uint8_t*)NOXTLS_MALLOC(sig_len);
                if(cert->signature == NULL) {
                    return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
                }
                noxtls_copy_u8((uint8_t *)(void *)(cert->signature), (size_t)sig_len, (const uint8_t *)(const void *)(ptr), (size_t)sig_len);
                cert->signature_len = sig_len;
            }
        }

        cert->parsed = 1;

    return rc;
}

noxtls_return_t noxtls_x509_certificate_parse_der(x509_certificate_t *cert, const uint8_t *data, uint32_t len)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if((cert == NULL) || (data == NULL) || (len == 0U)) {
        return NOXTLS_RETURN_NULL;
    }

    (void)noxtls_x509_certificate_free(cert);

    cert->raw_data = (uint8_t*)NOXTLS_MALLOC(len);
    if(cert->raw_data == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    noxtls_copy_u8((uint8_t *)(void *)(cert->raw_data), (size_t)len, (const uint8_t *)(const void *)(data), (size_t)len);
    cert->raw_data_len = len;

    rc = x509_certificate_parse_der_body(cert, data, len);

    if(rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_x509_certificate_free(cert);
    }

    return rc;
}

/**
 * @brief Parse X.509 certificate from PEM format
 *
 * This function parses an X.509 certificate from a PEM encoded buffer.
 *
 * @param[in] cert The certificate to parse.
 * @param[in] data The PEM encoded buffer to parse.
 * @param[in] len The length of the PEM encoded buffer.
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_certificate_parse_pem(x509_certificate_t *cert, const uint8_t *data, uint32_t len)
{
    uint8_t *der_data = NULL;
    uint32_t der_len = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((cert == NULL) || (data == NULL) || (len == 0U)) {
        return NOXTLS_RETURN_NULL;
    }

    /* Allocate buffer for DER data */
    der_data = (uint8_t*)NOXTLS_MALLOC(len);
    if(der_data == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    /* Convert PEM to DER */
    rc = noxtls_certificate_pem_to_der(data, len, der_data, &der_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_free(der_data);
        return rc;
    }

    /* Parse DER */
    rc = noxtls_x509_certificate_parse_der(cert, der_data, der_len);

    (void)noxtls_free(der_data);

    return rc;
}

/**
 * @brief Load X.509 certificate from file
 *
 * This function loads an X.509 certificate from a file.
 *
 * @param[in] cert The certificate to load.
 * @param[in] filename The name of the file to load the certificate from.
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_certificate_load_file(x509_certificate_t *cert, const uint8_t *filename)
{
#if !NOXTLS_HAVE_FILE_IO
    if((cert == NULL) || (filename == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    (void)cert;
    (void)filename;
    return NOXTLS_RETURN_FAILED;
#else
    FILE *fp;
    uint8_t *data = NULL;
    uint32_t len = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((cert == NULL) || (filename == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    fp = noxtls_x509_fopen(filename, "rb");
    if(fp == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Get file size */
    errno = 0;
    if(fseek(fp, 0, SEEK_END) != 0) {
        (void)fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }
    {
        long ftell_len = 0;
        errno = 0;
        ftell_len = ftell(fp);
        if(errno != 0) {
            (void)fclose(fp);
            return NOXTLS_RETURN_FAILED;
        }
        if(ftell_len < 0) {
            (void)fclose(fp);
            return NOXTLS_RETURN_FAILED;
        }
        len = (uint32_t)ftell_len;
    }
    errno = 0;
    if(fseek(fp, 0, SEEK_SET) != 0) {
        (void)fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }

    if((len == 0U) || (len > X509_MAX_CERT_SIZE)) {
        (void)fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }

    data = (uint8_t*)NOXTLS_MALLOC(len);
    if(data == NULL) {
        (void)fclose(fp);
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    if(fread(data, 1, len, fp) != len) {
        (void)noxtls_free(data);
        (void)fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }

    (void)fclose(fp);

    /* Try DER first, then PEM */
    rc = noxtls_x509_certificate_parse_der(cert, data, len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        /* If DER parsing failed, try PEM */
        noxtls_return_t pem_rc = noxtls_x509_certificate_parse_pem(cert, data, len);
        if(pem_rc == NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_SUCCESS;
        } else {
            /* Both failed - return the DER error as it's more specific */
            rc = NOXTLS_RETURN_BAD_DATA;
        }
    }

    (void)noxtls_free(data);

    return rc;
#endif
}

/**
 * @brief Map signature algorithm OID to hash algorithm and signature type
 *
 * @param oid Signature algorithm OID
 * @param oid_len OID length
 * @param hash_algo Output hash algorithm
 * @param is_rsa Output: 1 if RSA, 0 if ECDSA, 2 if ML-DSA, 3 if SLH-DSA
 *
 * @return NOXTLS_RETURN_SUCCESS on success
 */
static noxtls_return_t noxtls_x509_map_signature_algorithm(const uint8_t *sig_oid, uint32_t sig_oid_len,
                                                      noxtls_hash_algos_t *hash_algo, int *is_rsa)
{
    /* Common signature algorithm OIDs */
    /* sha256WithRSAEncryption: 1.2.840.113549.1.1.11 */
    const uint8_t oid_sha256_rsa[] = {0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x01U, 0x0BU};

    /* sha384WithRSAEncryption: 1.2.840.113549.1.1.12 */
    const uint8_t oid_sha384_rsa[] = {0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x01U, 0x0CU};

    /* sha512WithRSAEncryption: 1.2.840.113549.1.1.13 */
    const uint8_t oid_sha512_rsa[] = {0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x01U, 0x0DU};

    /* ecdsa-with-SHA256: 1.2.840.10045.4.3.2 */
    const uint8_t oid_ecdsa_sha256[] = {0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x04U, 0x03U, 0x02U};

    /* ecdsa-with-SHA384: 1.2.840.10045.4.3.3 */
    const uint8_t oid_ecdsa_sha384[] = {0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x04U, 0x03U, 0x03U};

    /* ecdsa-with-SHA512: 1.2.840.10045.4.3.4 */
    const uint8_t oid_ecdsa_sha512[] = {0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x04U, 0x03U, 0x04U};

    /* ml-dsa-44 / 65 / 87 (private-use parser mapping for PQ cert experiments) */
    const uint8_t oid_mldsa44[] = {0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x03U, 0x11U};
    const uint8_t oid_mldsa65[] = {0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x03U, 0x12U};
    const uint8_t oid_mldsa87[] = {0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x03U, 0x13U};

    if((sig_oid == NULL) || (hash_algo == NULL) || (is_rsa == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if((size_t)(sig_oid_len) == sizeof(oid_sha256_rsa)) {
        if(noxtls_ct_memcmp(sig_oid, oid_sha256_rsa, (size_t)sig_oid_len) == 0) {
            *hash_algo = NOXTLS_HASH_SHA_256;
            *is_rsa = 1;
            return NOXTLS_RETURN_SUCCESS;
        }
    }
    if((size_t)(sig_oid_len) == sizeof(oid_sha384_rsa)) {
        if(noxtls_ct_memcmp(sig_oid, oid_sha384_rsa, (size_t)sig_oid_len) == 0) {
            *hash_algo = NOXTLS_HASH_SHA_384;
            *is_rsa = 1;
            return NOXTLS_RETURN_SUCCESS;
        }
    }
    if((size_t)(sig_oid_len) == sizeof(oid_sha512_rsa)) {
        if(noxtls_ct_memcmp(sig_oid, oid_sha512_rsa, (size_t)sig_oid_len) == 0) {
            *hash_algo = NOXTLS_HASH_SHA_512;
            *is_rsa = 1;
            return NOXTLS_RETURN_SUCCESS;
        }
    }
    if((size_t)(sig_oid_len) == sizeof(oid_ecdsa_sha256)) {
        if(noxtls_ct_memcmp(sig_oid, oid_ecdsa_sha256, (size_t)sig_oid_len) == 0) {
            *hash_algo = NOXTLS_HASH_SHA_256;
            *is_rsa = 0;
            return NOXTLS_RETURN_SUCCESS;
        }
    }
    if((size_t)(sig_oid_len) == sizeof(oid_ecdsa_sha384)) {
        if(noxtls_ct_memcmp(sig_oid, oid_ecdsa_sha384, (size_t)sig_oid_len) == 0) {
            *hash_algo = NOXTLS_HASH_SHA_384;
            *is_rsa = 0;
            return NOXTLS_RETURN_SUCCESS;
        }
    }
    if((size_t)(sig_oid_len) == sizeof(oid_ecdsa_sha512)) {
        if(noxtls_ct_memcmp(sig_oid, oid_ecdsa_sha512, (size_t)sig_oid_len) == 0) {
            *hash_algo = NOXTLS_HASH_SHA_512;
            *is_rsa = 0;
            return NOXTLS_RETURN_SUCCESS;
        }
    }

    {
        int mldsa_match = 0;
        if((size_t)(sig_oid_len) == sizeof(oid_mldsa44)) {
            if(noxtls_ct_memcmp(sig_oid, oid_mldsa44, (size_t)sig_oid_len) == 0) {
                mldsa_match = 1;
            }
        }
        if(mldsa_match == 0) {
            if((size_t)(sig_oid_len) == sizeof(oid_mldsa65)) {
                if(noxtls_ct_memcmp(sig_oid, oid_mldsa65, (size_t)sig_oid_len) == 0) {
                    mldsa_match = 1;
                }
            }
        }
        if(mldsa_match == 0) {
            if((size_t)(sig_oid_len) == sizeof(oid_mldsa87)) {
                if(noxtls_ct_memcmp(sig_oid, oid_mldsa87, (size_t)sig_oid_len) == 0) {
                    mldsa_match = 1;
                }
            }
        }
        if(mldsa_match != 0) {
            *hash_algo = NOXTLS_HASH_SHA_512;
            *is_rsa = 2;
            return NOXTLS_RETURN_SUCCESS;
        }
    }
#if NOXTLS_FEATURE_SLH_DSA
    {
        noxtls_slhdsa_param_t slhdsa_param = NOXTLS_SLHDSA_NONE;
        if(noxtls_x509_slhdsa_param_from_oid(sig_oid, sig_oid_len, &slhdsa_param) == NOXTLS_RETURN_SUCCESS) {
            *hash_algo = NOXTLS_HASH_SHA_512;
            *is_rsa = 3;
            return NOXTLS_RETURN_SUCCESS;
        }
    }
#endif
#if NOXTLS_FEATURE_FALCON
    const uint8_t oid_falcon512[] = {0x2BU, 0xCEU, 0x0FU, 0x03U, 0x06U};
    const uint8_t oid_falcon1024[] = {0x2BU, 0xCEU, 0x0FU, 0x03U, 0x07U};

    {
        int falcon_oid_match = 0;
        if((size_t)(sig_oid_len) == sizeof(oid_falcon512)) {
            falcon_oid_match = (noxtls_ct_memcmp(sig_oid, oid_falcon512, (size_t)sig_oid_len) == 0) ? 1 : 0;
        }
        if(falcon_oid_match == 0) {
            if((size_t)(sig_oid_len) == sizeof(oid_falcon1024)) {
                falcon_oid_match = (noxtls_ct_memcmp(sig_oid, oid_falcon1024, (size_t)sig_oid_len) == 0) ? 1 : 0;
            }
        }
        if(falcon_oid_match != 0) {
            *hash_algo = NOXTLS_HASH_SHA_512;
            *is_rsa = 4;
            return NOXTLS_RETURN_SUCCESS;
        }
    }
#endif

    return NOXTLS_RETURN_INVALID_ALGORITHM;
}

/**
 * @brief RFC 5929 tls-server-end-point: return hash algorithm for hashing the server certificate.
 *
 * This function returns the hash algorithm for hashing the server certificate.
 * RFC 5929 tls-server-end-point: return hash algorithm for hashing the server certificate.
 * If cert's signatureAlgorithm uses MD5 or SHA-1, use SHA-256; else use the cert's hash.
 *
 * @param[in] cert The certificate to get the channel binding hash algorithm for.
 * @param[out] hash_algo The hash algorithm to use for the channel binding.
 *
 * @return The return code of the function.
 *  
 * @param[in] cert The certificate to get the channel binding hash algorithm for.
 * @param[out] hash_algo The hash algorithm to use for the channel binding.
 *
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_get_channel_binding_hash_algo(const x509_certificate_t *cert, noxtls_hash_algos_t *hash_algo)
{
    noxtls_hash_algos_t mapped = NOXTLS_HASH_SHA_256;
    int is_rsa = 0;

    if((cert == NULL) || (hash_algo == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    /* RFC 5929 §4.1: if signature uses MD5 or SHA-1, use SHA-256 */
    /* md5WithRSAEncryption 1.2.840.113549.1.1.4 */
    static const uint8_t oid_md5_rsa[] = {0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x01U, 0x04U};

    /* sha1WithRSAEncryption 1.2.840.113549.1.1.5 */
    static const uint8_t oid_sha1_rsa[] = {0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x01U, 0x05U};

    /* ecdsa-with-SHA1 1.2.840.10045.4.1 */
    static const uint8_t oid_ecdsa_sha1[] = {0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x04U, 0x01U};

    {
        int oid_match = 0;
        if((size_t)(cert->signature_algorithm_oid_len) == sizeof(oid_md5_rsa)) {
            oid_match = (noxtls_ct_memcmp(cert->signature_algorithm_oid, oid_md5_rsa, sizeof(oid_md5_rsa)) == 0) ? 1 : 0;
        }
        if(oid_match != 0) {
            *hash_algo = NOXTLS_HASH_SHA_256;
            return NOXTLS_RETURN_SUCCESS;
        }
    }
    {
        int oid_match = 0;
        if((size_t)(cert->signature_algorithm_oid_len) == sizeof(oid_sha1_rsa)) {
            oid_match = (noxtls_ct_memcmp(cert->signature_algorithm_oid, oid_sha1_rsa, sizeof(oid_sha1_rsa)) == 0) ? 1 : 0;
        }
        if(oid_match != 0) {
            *hash_algo = NOXTLS_HASH_SHA_256;
            return NOXTLS_RETURN_SUCCESS;
        }
    }
    {
        int oid_match = 0;
        if((size_t)(cert->signature_algorithm_oid_len) == sizeof(oid_ecdsa_sha1)) {
            oid_match = (noxtls_ct_memcmp(cert->signature_algorithm_oid, oid_ecdsa_sha1, sizeof(oid_ecdsa_sha1)) == 0) ? 1 : 0;
        }
        if(oid_match != 0) {
            *hash_algo = NOXTLS_HASH_SHA_256;
            return NOXTLS_RETURN_SUCCESS;
        }
    }
    if(noxtls_x509_map_signature_algorithm(cert->signature_algorithm_oid, cert->signature_algorithm_oid_len, &mapped, &is_rsa) == NOXTLS_RETURN_SUCCESS) {
        *hash_algo = mapped;
        return NOXTLS_RETURN_SUCCESS;
    }
    *hash_algo = NOXTLS_HASH_SHA_256;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Map curve OID to ecc_curve_t (for noxtls_x509 API)
 *
 * This function maps a curve OID to an ecc_curve_t.
 *
 * @param[in] oid The OID to map.
 * @param[in] oid_len The length of the OID.
 * @param[out] curve_type The curve type to map to.
 * @return The return code of the function.
 */
static noxtls_return_t noxtls_x509_ecc_curve_from_oid(const uint8_t *curve_oid, uint32_t curve_oid_len, ecc_curve_t *curve_type)
{
    /* Curve OIDs local to this function (Rule 8.9). */
    /* ECC curve OIDs (DER) for noxtls_x509 helpers */
    static const uint8_t noxtls_x509_oid_secp192r1[] = {0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x03U, 0x01U, 0x01U};
    static const uint8_t noxtls_x509_oid_secp224r1[] = {0x2BU, 0x81U, 0x04U, 0x00U, 0x21U};
    static const uint8_t noxtls_x509_oid_secp256r1[] = {0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x03U, 0x01U, 0x07U};
    static const uint8_t noxtls_x509_oid_secp384r1[] = {0x2BU, 0x81U, 0x04U, 0x00U, 0x22U};
    static const uint8_t noxtls_x509_oid_secp521r1[] = {0x2BU, 0x81U, 0x04U, 0x00U, 0x23U};
    static const uint8_t noxtls_x509_oid_bp256r1[] = {0x2BU, 0x24U, 0x03U, 0x03U, 0x02U, 0x08U, 0x01U, 0x01U, 0x07U};
    static const uint8_t noxtls_x509_oid_bp384r1[] = {0x2BU, 0x24U, 0x03U, 0x03U, 0x02U, 0x08U, 0x01U, 0x01U, 0x0BU};
    static const uint8_t noxtls_x509_oid_bp512r1[] = {0x2BU, 0x24U, 0x03U, 0x03U, 0x02U, 0x08U, 0x01U, 0x01U, 0x0DU};
    static const uint8_t noxtls_x509_oid_secp192k1[] = {0x2BU, 0x81U, 0x04U, 0x00U, 0x1FU};
    static const uint8_t noxtls_x509_oid_secp224k1[] = {0x2BU, 0x81U, 0x04U, 0x00U, 0x20U};
    static const uint8_t noxtls_x509_oid_secp256k1[] = {0x2BU, 0x81U, 0x04U, 0x00U, 0x0AU};

    static const struct {
        const uint8_t *curve_oid;
        uint32_t curve_oid_len;
        ecc_curve_t curve;
    } map[] = {
        { noxtls_x509_oid_secp192r1, (uint32_t)sizeof(noxtls_x509_oid_secp192r1), NOXTLS_ECC_SECP192R1 },
        { noxtls_x509_oid_secp224r1, (uint32_t)sizeof(noxtls_x509_oid_secp224r1), NOXTLS_ECC_SECP224R1 },
        { noxtls_x509_oid_secp256r1, (uint32_t)sizeof(noxtls_x509_oid_secp256r1), NOXTLS_ECC_SECP256R1 },
        { noxtls_x509_oid_secp384r1, (uint32_t)sizeof(noxtls_x509_oid_secp384r1), NOXTLS_ECC_SECP384R1 },
        { noxtls_x509_oid_secp521r1, (uint32_t)sizeof(noxtls_x509_oid_secp521r1), NOXTLS_ECC_SECP521R1 },
        { noxtls_x509_oid_bp256r1, (uint32_t)sizeof(noxtls_x509_oid_bp256r1), NOXTLS_ECC_BP256R1 },
        { noxtls_x509_oid_bp384r1, (uint32_t)sizeof(noxtls_x509_oid_bp384r1), NOXTLS_ECC_BP384R1 },
        { noxtls_x509_oid_bp512r1, (uint32_t)sizeof(noxtls_x509_oid_bp512r1), NOXTLS_ECC_BP512R1 },
        { noxtls_x509_oid_secp192k1, (uint32_t)sizeof(noxtls_x509_oid_secp192k1), NOXTLS_ECC_SECP192K1 },
        { noxtls_x509_oid_secp224k1, (uint32_t)sizeof(noxtls_x509_oid_secp224k1), NOXTLS_ECC_SECP224K1 },
        { noxtls_x509_oid_secp256k1, (uint32_t)sizeof(noxtls_x509_oid_secp256k1), NOXTLS_ECC_SECP256K1 },
    };
    uint32_t i = 0U;

    if((curve_oid == NULL) || (curve_type == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(curve_oid_len == 0U) {
        *curve_type = NOXTLS_ECC_SECP256R1; /* default */
        return NOXTLS_RETURN_SUCCESS;
    }
    for(i = 0U; i < (uint32_t)(sizeof(map) / sizeof(map[0])); i += 1U) {
        {
            int oid_map_match = 0;
            if(curve_oid_len == map[i].curve_oid_len) {
                oid_map_match = (noxtls_ct_memcmp(curve_oid, map[i].curve_oid, (size_t)curve_oid_len) == 0) ? 1 : 0;
            }
            if(oid_map_match != 0) {
                *curve_type = map[i].curve;
                return NOXTLS_RETURN_SUCCESS;
            }
        }
    }
    return NOXTLS_RETURN_INVALID_ALGORITHM;
}

/**
 * @brief Infer ecc_curve_t from public key length (uncompressed 0x04 || X || Y)
 *
 * This function infers the ecc_curve_t from the public key length.
 *
 * @param[in] pubkey_len The length of the public key.
 * @param[out] curve_type The curve type to infer.
 * @return The return code of the function.
 */
static noxtls_return_t noxtls_x509_ecc_curve_from_pubkey_len(uint32_t pubkey_len, ecc_curve_t *curve_type)
{
    if(curve_type == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(pubkey_len == 49U) {   /* 0x04U || 24-byte X || 24-byte Y */
        *curve_type = NOXTLS_ECC_SECP192R1;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(pubkey_len == 57U) {   /* 0x04U || 28-byte X || 28-byte Y */
        *curve_type = NOXTLS_ECC_SECP224R1;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(pubkey_len == 65U) {
        *curve_type = NOXTLS_ECC_SECP256R1;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(pubkey_len == 97U) {
        *curve_type = NOXTLS_ECC_SECP384R1;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(pubkey_len == 129U) {  /* 0x04U || 64-byte X || 64-byte Y */
        *curve_type = NOXTLS_ECC_BP512R1;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(pubkey_len == 133U) {
        *curve_type = NOXTLS_ECC_SECP521R1;
        return NOXTLS_RETURN_SUCCESS;
    }
    return NOXTLS_RETURN_INVALID_PARAM;
}

/**
 * @brief Validate ECC public key bytes
 *
 * This function validates the ECC public key bytes.
 *
 * @param[in] pubkey The public key to validate.
 * @param[in] pubkey_len The length of the public key.
 * @param[in] curve_oid The OID of the curve.
 * @param[in] curve_oid_len The length of the OID of the curve.
 *
 * @return The return code of the function.
 */
static noxtls_return_t noxtls_x509_validate_ecc_public_key_bytes(const uint8_t *pubkey,
                                                                 uint32_t pubkey_len,
                                                                 const uint8_t *curve_oid,
                                                                 uint32_t curve_oid_len)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    ecc_curve_t curve_type = NOXTLS_ECC_SECP256R1;
    ecc_curve_params_t curve;
    ecc_point_t point;
    uint32_t coord_size = 0U;

    if((pubkey == NULL) || (pubkey_len == 0U)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if(curve_oid_len > 0U) {
        rc = noxtls_x509_ecc_curve_from_oid(curve_oid, curve_oid_len, &curve_type);
    } else {
        /* MISRA 15.7: final else path */
        rc = noxtls_x509_ecc_curve_from_pubkey_len(pubkey_len, &curve_type);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = noxtls_ecc_curve_init(&curve, curve_type);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    coord_size = curve.size;
    if((pubkey[0] != 0x04U) || (pubkey_len != (1U + (2U * coord_size)))) {
        (void)noxtls_ecc_curve_free(&curve);
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    noxtls_secure_zero((&point), sizeof(point));
    point.size = coord_size;
    noxtls_copy_u8((uint8_t *)(void *)(point.x), (size_t)coord_size, (const uint8_t *)(const void *)(&pubkey[1]), (size_t)coord_size);
    noxtls_copy_u8((uint8_t *)(void *)(point.y), (size_t)coord_size, (const uint8_t *)(const void *)(&pubkey[1U + coord_size]), (size_t)coord_size);

    rc = noxtls_ecc_point_validate_public(&point, &curve);
    (void)noxtls_ecc_curve_free(&curve);

    if(rc == NOXTLS_RETURN_NOT_ENOUGH_MEMORY) {
        return rc;  /* resource failure, not a malformed key */
    }
    return (rc == NOXTLS_RETURN_SUCCESS) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_INVALID_PARAM;
}

/**
 * @brief Verify certificate signature
 *
 * This function verifies the signature of a certificate.
 *
 * @param[in] cert The certificate to verify the signature of.
 * @param[in] issuer The issuer of the certificate.
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_certificate_verify_signature(const x509_certificate_t *cert, const x509_certificate_t *issuer)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    noxtls_hash_algos_t hash_algo = NOXTLS_HASH_SHA_256;
    int is_rsa = 0;
    uint8_t hash[64];  /* Max hash size (SHA-512) */

    if((cert == NULL) || (issuer == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if((cert->parsed == 0) || (issuer->parsed == 0)) {
        CERT_DEBUG_PRINT("x509_certificate_verify_signature: certificate not parsed\n");
        cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED, cert, NULL, 0, 0);
        return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
    }

    if((cert->tbs_certificate == NULL) || (cert->tbs_certificate_len == 0U)) {
        CERT_DEBUG_PRINT("x509_certificate_verify_signature: TBSCertificate not available\n");
        cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED, cert, NULL, 0, 0);
        return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
    }

    if((cert->signature == NULL) || (cert->signature_len == 0U)) {
        CERT_DEBUG_PRINT("x509_certificate_verify_signature: signature not available\n");
        cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED, cert, NULL, 0, 0);
        return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
    }

#if NOXTLS_FEATURE_ED25519 || (NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3)
    {
        /* PureEdDSA over the DER TBSCertificate (RFC 8410 Section 6). */
        static const uint8_t oid_sig_ed25519[] = { 0x2BU, 0x65U, 0x70U };
        static const uint8_t oid_sig_ed448[] = { 0x2BU, 0x65U, 0x71U };
        int eddsa = 0;

        if(oid_equal(cert->signature_algorithm_oid, cert->signature_algorithm_oid_len,
                     oid_sig_ed25519, (uint32_t)sizeof(oid_sig_ed25519)) != 0) {
            eddsa = 1;
        } else if(oid_equal(cert->signature_algorithm_oid, cert->signature_algorithm_oid_len,
                            oid_sig_ed448, (uint32_t)sizeof(oid_sig_ed448)) != 0) {
            eddsa = 2;
        } else {
            /* MISRA 15.7: not an EdDSA signature */
        }
#if NOXTLS_FEATURE_ED25519
        if(eddsa == 1) {
            if((issuer->has_ed25519 == 0U) || (cert->signature_len != NOXTLS_ED25519_SIGNATURE_SIZE)) {
                cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED, cert, NULL, 0, 0);
                return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
            }
            rc = noxtls_ed25519_verify(issuer->ed25519_public_key, cert->tbs_certificate,
                                       cert->tbs_certificate_len, cert->signature);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED, cert, NULL, 0, 0);
                return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
            }
            return NOXTLS_RETURN_SUCCESS;
        }
#endif
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
        if(eddsa == 2) {
            if((issuer->has_ed448 == 0U) || (cert->signature_len != NOXTLS_ED448_SIGNATURE_SIZE)) {
                cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED, cert, NULL, 0, 0);
                return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
            }
            rc = noxtls_ed448_verify(issuer->ed448_public_key, cert->tbs_certificate,
                                     cert->tbs_certificate_len, cert->signature);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED, cert, NULL, 0, 0);
                return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
            }
            return NOXTLS_RETURN_SUCCESS;
        }
#endif
        if(eddsa != 0) {
            return NOXTLS_RETURN_INVALID_ALGORITHM;
        }
    }
#endif

    /* Map signature algorithm OID to hash algorithm and signature type */
    rc = noxtls_x509_map_signature_algorithm(cert->signature_algorithm_oid, cert->signature_algorithm_oid_len,
                                     &hash_algo, &is_rsa);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        CERT_DEBUG_PRINT("x509_certificate_verify_signature: unsupported signature algorithm\n");
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }

    /* Hash the TBSCertificate */
    if(hash_algo == NOXTLS_HASH_SHA_256) {
        noxtls_sha_ctx_t sha_ctx;
        (void)noxtls_sha256_init(&sha_ctx, hash_algo);
        (void)noxtls_sha256_update(&sha_ctx, cert->tbs_certificate, cert->tbs_certificate_len);
        rc = noxtls_sha256_finish(&sha_ctx, hash);
    } else if(hash_algo == NOXTLS_HASH_SHA_384) {
        noxtls_sha512_ctx_t sha_ctx;
        (void)noxtls_sha512_init(&sha_ctx, hash_algo);
        (void)noxtls_sha512_update(&sha_ctx, cert->tbs_certificate, cert->tbs_certificate_len);
        rc = noxtls_sha512_finish(&sha_ctx, hash);
    } else if(hash_algo == NOXTLS_HASH_SHA_512) {
        noxtls_sha512_ctx_t sha_ctx;
        (void)noxtls_sha512_init(&sha_ctx, hash_algo);
        (void)noxtls_sha512_update(&sha_ctx, cert->tbs_certificate, cert->tbs_certificate_len);
        rc = noxtls_sha512_finish(&sha_ctx, hash);
    } else {
        /* MISRA 15.7: final else path */
        CERT_DEBUG_PRINT("x509_certificate_verify_signature: unsupported hash algorithm\n");
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }

    if(rc != NOXTLS_RETURN_SUCCESS) {
        CERT_DEBUG_PRINT("x509_certificate_verify_signature: failed to hash TBSCertificate\n");
        return rc;
    }

    /* Verify signature using issuer's public key */
    if(is_rsa == 1) {
        /* RSA signature verification */
        if((issuer->rsa_modulus == NULL) || (issuer->rsa_exponent == NULL)) {
            CERT_DEBUG_PRINT("x509_certificate_verify_signature: issuer RSA public key not available\n");
            cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED, cert, NULL, 0, 0);
            return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
        }

        /* Determine RSA key size from normalized modulus length (skip ASN.1 INTEGER sign-padding 0x00). */
        const uint8_t *mod_ptr = issuer->rsa_modulus;
        uint32_t mod_len = (uint32_t)(issuer->rsa_modulus_len);
        const uint8_t *exp_ptr = issuer->rsa_exponent;
        uint32_t exp_len = (uint32_t)(issuer->rsa_exponent_len);
        uint32_t key_bytes = 0U;
        rsa_key_size_t key_size = RSA_2048_BIT;
        while((mod_len > 0U) && (mod_ptr[0] == 0U)) {
            mod_ptr = &mod_ptr[1];
            mod_len -= 1U;
        }
        while((exp_len > 0U) && (exp_ptr[0] == 0U)) {
            exp_ptr = &exp_ptr[1];
            exp_len -= 1U;
        }
        key_bytes = mod_len;
        if(key_bytes == X509_RSA_MODULUS_BYTES_1024) {
            key_size = RSA_1024_BIT;
        } else if(key_bytes == X509_RSA_MODULUS_BYTES_2048) {
            key_size = RSA_2048_BIT;
        } else if(key_bytes == X509_RSA_MODULUS_BYTES_3072) {
            key_size = RSA_3072_BIT;
        } else if(key_bytes == X509_RSA_MODULUS_BYTES_4096) {
            key_size = RSA_4096_BIT;
        } else {
            /* MISRA 15.7: final else path */
            CERT_DEBUG_PRINT("x509_certificate_verify_signature: unsupported RSA key size\n");
            return NOXTLS_RETURN_INVALID_PARAM;
        }

        rsa_key_t rsa_key;
        rc = noxtls_rsa_key_init(&rsa_key, key_size);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }

        if((mod_len == 0U) || (exp_len == 0U) || (mod_len > rsa_key.key_bytes) || (exp_len > rsa_key.key_bytes)) {
            (void)noxtls_rsa_key_free(&rsa_key);
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        noxtls_copy_u8((uint8_t *)(void *)(&rsa_key.n[rsa_key.key_bytes - mod_len]), (size_t)mod_len, (const uint8_t *)(const void *)(mod_ptr), (size_t)mod_len);
        noxtls_copy_u8((uint8_t *)(void *)(&rsa_key.e[(rsa_key.key_bytes - exp_len)]), (size_t)exp_len, (const uint8_t *)(const void *)(exp_ptr), (size_t)exp_len);

        /* noxtls_rsa_verify hashes the message internally (PKCS#1 v1.5 DigestInfo check). */
        rc = noxtls_rsa_verify(&rsa_key,
                               cert->tbs_certificate,
                               cert->tbs_certificate_len,
                               cert->signature,
                               cert->signature_len,
                               hash_algo);
        (void)noxtls_rsa_key_free(&rsa_key);

        CERT_DEBUG_PRINT("x509_certificate_verify_signature: RSA signature verification %s\n",
                         (rc == NOXTLS_RETURN_SUCCESS) ? "SUCCESS" : "FAILED");

        if(rc != NOXTLS_RETURN_SUCCESS) {
            cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED, cert, NULL, 0, 0);
            return ((rc == NOXTLS_RETURN_FAILED) ? NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED : rc);
        }
        return NOXTLS_RETURN_SUCCESS;
    }
    if(is_rsa == 2) {
#if NOXTLS_FEATURE_ML_DSA
        uint32_t hash_len = 0U;
        if((issuer->has_mldsa == 0U) || (issuer->mldsa_public_key_len == 0U) || (issuer->mldsa_param == 0U)) {
            cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED, cert, NULL, 0, 0);
            return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
        }
        if(hash_algo == NOXTLS_HASH_SHA_256) {
            hash_len = 32U;
        } else if(hash_algo == NOXTLS_HASH_SHA_384) {
            hash_len = 48U;
        } else if(hash_algo == NOXTLS_HASH_SHA_512) {
            hash_len = 64U;
        } else {
            /* MISRA 15.7: final else path */
            return NOXTLS_RETURN_INVALID_ALGORITHM;
        }
        rc = noxtls_mldsa_verify(issuer->mldsa_param,
                                 issuer->mldsa_public_key,
                                 hash, hash_len,
                                 cert->signature, cert->signature_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED, cert, NULL, 0, 0);
            return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
        }
        return NOXTLS_RETURN_SUCCESS;
#else
        return NOXTLS_RETURN_INVALID_ALGORITHM;
#endif
    }
    if(is_rsa == 3) {
#if NOXTLS_FEATURE_SLH_DSA
        noxtls_slhdsa_param_t sig_param = NOXTLS_SLHDSA_NONE;

        if(noxtls_x509_slhdsa_param_from_oid(cert->signature_algorithm_oid,
                                             cert->signature_algorithm_oid_len,
                                             &sig_param) != NOXTLS_RETURN_SUCCESS ||
           (issuer->has_slhdsa == 0U) ||
           issuer->slhdsa_public_key_len == 0U ||
           issuer->slhdsa_param != sig_param) {
            cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED, cert, NULL, 0, 0);
            return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
        }
        rc = noxtls_slhdsa_verify(sig_param,
                                  issuer->slhdsa_public_key,
                                  cert->tbs_certificate,
                                  cert->tbs_certificate_len,
                                  cert->signature,
                                  cert->signature_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED, cert, NULL, 0, 0);
            return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
        }
        return NOXTLS_RETURN_SUCCESS;
#else
        return NOXTLS_RETURN_INVALID_ALGORITHM;
#endif
    }
    if(is_rsa == 4) {
#if NOXTLS_FEATURE_FALCON
        int falcon_param = x509_oid_is_falcon(cert->signature_algorithm_oid, cert->signature_algorithm_oid_len);
        if(falcon_param == 0 ||
           (issuer->has_falcon == 0U) ||
           issuer->falcon_public_key_len == 0U ||
           issuer->falcon_param != (noxtls_falcon_param_t)falcon_param) {
            cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED, cert, NULL, 0, 0);
            return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
        }
        rc = noxtls_falcon_verify((noxtls_falcon_param_t)falcon_param,
                                  issuer->falcon_public_key,
                                  cert->tbs_certificate,
                                  cert->tbs_certificate_len,
                                  cert->signature,
                                  cert->signature_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED, cert, NULL, 0, 0);
            return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
        }
        return NOXTLS_RETURN_SUCCESS;
#else
        return NOXTLS_RETURN_INVALID_ALGORITHM;
#endif
    }
    {
        /* ECDSA signature verification */
        if((issuer->ecc_public_key == NULL) || (issuer->ecc_public_key_len == 0U)) {
            CERT_DEBUG_PRINT("x509_certificate_verify_signature: issuer ECC public key not available\n");
            cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED, cert, NULL, 0, 0);
            return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
        }

        /* Determine curve from issuer's public key */
        ecc_curve_t curve_type = NOXTLS_ECC_SECP256R1;
        if(issuer->ecc_curve_oid_len > 0U) {
            if(noxtls_x509_ecc_curve_from_oid(issuer->ecc_curve_oid, issuer->ecc_curve_oid_len, &curve_type) != NOXTLS_RETURN_SUCCESS) {
                CERT_DEBUG_PRINT("x509_certificate_verify_signature: unsupported ECC curve\n");
                return NOXTLS_RETURN_INVALID_ALGORITHM;
            }
        } else {
            /* MISRA 15.7: final else path */
            if(noxtls_x509_ecc_curve_from_pubkey_len(issuer->ecc_public_key_len, &curve_type) != NOXTLS_RETURN_SUCCESS) {
                CERT_DEBUG_PRINT("x509_certificate_verify_signature: cannot determine ECC curve\n");
                return NOXTLS_RETURN_INVALID_ALGORITHM;
            }
        }

        ecc_key_t ecc_key;
        rc = noxtls_ecc_key_init(&ecc_key, curve_type);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }

        /* Decode ECC public key point (uncompressed format: 0x04 || X || Y) */
        if(issuer->ecc_public_key[0] != 0x04U) {
            CERT_DEBUG_PRINT("x509_certificate_verify_signature: unsupported ECC point format\n");
            (void)noxtls_ecc_key_free(&ecc_key);
            return NOXTLS_RETURN_INVALID_PARAM;
        }

        uint32_t coord_size = (uint32_t)(ecc_key.curve->size);
        if(issuer->ecc_public_key_len != (1U + (2U * coord_size))) {
            CERT_DEBUG_PRINT("x509_certificate_verify_signature: invalid ECC public key length\n");
            (void)noxtls_ecc_key_free(&ecc_key);
            return NOXTLS_RETURN_INVALID_PARAM;
        }

        noxtls_copy_u8((uint8_t *)(void *)(ecc_key.Q.x), (size_t)coord_size, (const uint8_t *)(const void *)(&issuer->ecc_public_key[1]), (size_t)coord_size);
        noxtls_copy_u8((uint8_t *)(void *)(ecc_key.Q.y), (size_t)coord_size, (const uint8_t *)(const void *)(&issuer->ecc_public_key[1U + coord_size]), (size_t)coord_size);
        ecc_key.Q.size = coord_size;
        if(noxtls_ecc_point_validate_public(&ecc_key.Q, ecc_key.curve) != NOXTLS_RETURN_SUCCESS) {
            CERT_DEBUG_PRINT("x509_certificate_verify_signature: invalid issuer ECC public key\n");
            (void)noxtls_ecc_key_free(&ecc_key);
            return NOXTLS_RETURN_INVALID_PARAM;
        }

        /* Parse ECDSA signature (DER-encoded) */
        /* ECDSA signature in X.509 is DER-encoded SEQUENCE of two INTEGERs (r, s) */
        const uint8_t *sig_ptr = cert->signature;
        const uint8_t *sig_end = &cert->signature[cert->signature_len];
        const uint8_t *seq_data = NULL;
        uint32_t seq_len = 0U;

        CERT_DEBUG_PRINT("x509_certificate_verify_signature: signature_len=%u first_byte=0x%02x (expect 0x30 SEQUENCE)\n",
            (uint32_t)cert->signature_len, cert->signature_len > 0U ? cert->signature[0] : 0);
        if(asn1_get_tag(&sig_ptr, sig_end, 0x30U) != NOXTLS_RETURN_SUCCESS) {  /* SEQUENCE tag = 0x30U */
            CERT_DEBUG_PRINT("x509_certificate_verify_signature: invalid ECDSA signature format (not SEQUENCE 0x30)\n");
            (void)noxtls_ecc_key_free(&ecc_key);
            return NOXTLS_RETURN_BAD_DATA;
        }

        seq_len = asn1_get_length(&sig_ptr, sig_end);
        if((seq_len == 0U) || (x509_bytes_remaining(sig_ptr, sig_end) < (size_t)seq_len)) {
            CERT_DEBUG_PRINT("x509_certificate_verify_signature: invalid ECDSA signature length\n");
            (void)noxtls_ecc_key_free(&ecc_key);
            return NOXTLS_RETURN_BAD_DATA;
        }

        seq_data = sig_ptr;
        const uint8_t *seq_end = &seq_data[seq_len];
        /* Parse r */
        uint8_t r[ECC_MAX_KEY_SIZE];
        uint32_t r_len = ECC_MAX_KEY_SIZE;
        if(asn1_get_integer(&sig_ptr, seq_end, r, &r_len) != NOXTLS_RETURN_SUCCESS) {
            CERT_DEBUG_PRINT("x509_certificate_verify_signature: failed to parse ECDSA r\n");
            (void)noxtls_ecc_key_free(&ecc_key);
            return NOXTLS_RETURN_BAD_DATA;
        }

        /* Parse s */
        uint8_t s[ECC_MAX_KEY_SIZE];
        uint32_t s_len = ECC_MAX_KEY_SIZE;
        if(asn1_get_integer(&sig_ptr, seq_end, s, &s_len) != NOXTLS_RETURN_SUCCESS) {
            CERT_DEBUG_PRINT("x509_certificate_verify_signature: failed to parse ECDSA s\n");
            (void)noxtls_ecc_key_free(&ecc_key);
            return NOXTLS_RETURN_BAD_DATA;
        }

        /* Create ECDSA signature structure */
        ecdsa_signature_t ecdsa_sig;
        ecdsa_sig.size = coord_size;
        noxtls_secure_zero((ecdsa_sig.r), (size_t)ECC_MAX_KEY_SIZE);
        noxtls_secure_zero((ecdsa_sig.s), (size_t)ECC_MAX_KEY_SIZE);

        /* Copy r and s, handling leading zeros */
        if(r_len <= coord_size) {
            noxtls_copy_u8((uint8_t *)(void *)(&ecdsa_sig.r[coord_size - r_len]), (size_t)r_len, (const uint8_t *)(const void *)(r), (size_t)r_len);
        } else {
            /* Skip leading zero padding if r is longer than expected. */
            uint32_t skip = (uint32_t)(r_len - coord_size);
            uint32_t i = 0U;
            for(i = 0U; i < skip; i += 1U) {
                if(r[i] != 0U) {
                    /* r is too large (non-zero overflow prefix). */
                    (void)noxtls_ecc_key_free(&ecc_key);
                    return NOXTLS_RETURN_BAD_DATA;
                }
            }
            noxtls_copy_u8((uint8_t *)(void *)(ecdsa_sig.r), (size_t)coord_size, (const uint8_t *)(const void *)(&r[skip]), (size_t)coord_size);
        }

        if(s_len <= coord_size) {
            noxtls_copy_u8((uint8_t *)(void *)(&ecdsa_sig.s[coord_size - s_len]), (size_t)s_len, (const uint8_t *)(const void *)(s), (size_t)s_len);
        } else {
            uint32_t skip = (uint32_t)(s_len - coord_size);
            uint32_t i = 0U;
            for(i = 0U; i < skip; i += 1U) {
                if(s[i] != 0U) {
                    (void)noxtls_ecc_key_free(&ecc_key);
                    return NOXTLS_RETURN_BAD_DATA;
                }
            }
            noxtls_copy_u8((uint8_t *)(void *)(ecdsa_sig.s), (size_t)coord_size, (const uint8_t *)(const void *)(&s[skip]), (size_t)coord_size);
        }

        /* noxtls_ecdsa_verify hashes its input internally; pass raw TBSCertificate bytes (DER). */
        rc = noxtls_ecdsa_verify(&ecc_key, cert->tbs_certificate, cert->tbs_certificate_len, &ecdsa_sig, hash_algo);
        (void)noxtls_ecc_key_free(&ecc_key);

        CERT_DEBUG_PRINT("x509_certificate_verify_signature: ECDSA signature verification %s\n",
                         (rc == NOXTLS_RETURN_SUCCESS) ? "SUCCESS" : "FAILED");

        if(rc != NOXTLS_RETURN_SUCCESS) {
            cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED, cert, NULL, 0, 0);
            return ((rc == NOXTLS_RETURN_FAILED) ? NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED : rc);
        }
        return NOXTLS_RETURN_SUCCESS;
    }
}

#if NOXTLS_HAVE_TIME
/**
 * @brief Decode two-digit UTC year (YY) to full year.
 *
 * This function decodes a two-digit UTC year (YY) to a full year.
 *
 * @param[in] time_data The time data to decode.
 * @return The full year.
 */
static int32_t x509_asn1_utc_year(const uint8_t *time_data)
{
    uint32_t year_u = (((uint32_t)time_data[0] - (uint32_t)'0') * 10U) + ((uint32_t)time_data[1] - (uint32_t)'0');
    int32_t year = (int32_t)year_u;
    return (year < 50) ? (year + 2000) : (year + 1900);
}

/**
 * @brief Load month..second from UTCTime digit layout (indices 2..11).
 *
 * This function loads the month, day, hour, minute, and second from the UTCTime digit layout (indices 2..11).
 *
 * @param[in] time_data The time data to load the month, day, hour, minute, and second from.
 * @param[out] month The month to load.
 * @param[out] day The day to load.
 * @param[out] hour The hour to load
 * @param[out] minute The minute to load
 * @param[out] second The second to load
 * @return void
 */
/* NOLINTNEXTLINE(bugprone-easily-swappable-parameters): grouped out-params are positional date-time components. */
static void x509_asn1_utc_load_mdhm(const uint8_t *time_data, int32_t *month, int32_t *day, int32_t *hour, int32_t *minute, int32_t *second)
{
    {
        uint32_t month_u = (((uint32_t)time_data[2] - (uint32_t)'0') * 10U)
            + ((uint32_t)time_data[3] - (uint32_t)'0');
        *month = (int32_t)month_u;
    }
    {
        uint32_t day_u = (((uint32_t)time_data[4] - (uint32_t)'0') * 10U)
            + ((uint32_t)time_data[5] - (uint32_t)'0');
        *day = (int32_t)day_u;
    }
    {
        uint32_t hour_u = (((uint32_t)time_data[6] - (uint32_t)'0') * 10U)
            + ((uint32_t)time_data[7] - (uint32_t)'0');
        *hour = (int32_t)hour_u;
    }
    {
        uint32_t minute_u = (((uint32_t)time_data[8] - (uint32_t)'0') * 10U)
            + ((uint32_t)time_data[9] - (uint32_t)'0');
        *minute = (int32_t)minute_u;
    }
    {
        uint32_t second_u = (((uint32_t)time_data[10] - (uint32_t)'0') * 10U)
            + ((uint32_t)time_data[11] - (uint32_t)'0');
        *second = (int32_t)second_u;
    }
}

/**
 * @brief Decode four-digit GeneralizedTime year (YYYY).
 *
 * This function decodes a four-digit GeneralizedTime year (YYYY).
 *
 * @param[in] time_data The time data to decode.
 * @return The full year.
 */
static int32_t x509_asn1_gt_year(const uint8_t *time_data)
{
    uint32_t year_u =
        (((uint32_t)time_data[0] - (uint32_t)'0') * 1000U)
        + (((uint32_t)time_data[1] - (uint32_t)'0') * 100U)
        + (((uint32_t)time_data[2] - (uint32_t)'0') * 10U)
        + ((uint32_t)time_data[3] - (uint32_t)'0');
    return (int32_t)year_u;
}

/**
 * @brief Load month..second from GeneralizedTime digit layout (indices 4..13).
 *
 * This function loads the month, day, hour, minute, and second from the GeneralizedTime digit layout (indices 4..13).
 *
 * @param[in] time_data The time data to load the month, day, hour, minute, and second from.
 * @param[out] month The month to load.
 * @param[out] day The day to load.
 * @param[out] hour The hour to load
 * @param[out] minute The minute to load
 * @param[out] second The second to load
 * @return void
 */
/* NOLINTNEXTLINE(bugprone-easily-swappable-parameters): grouped out-params are positional date-time components. */
static void x509_asn1_gt_load_mdhm(const uint8_t *time_data, int32_t *month, int32_t *day, int32_t *hour, int32_t *minute, int32_t *second)
{
    {
        uint32_t month_u = (((uint32_t)time_data[4] - (uint32_t)'0') * 10U)
            + ((uint32_t)time_data[5] - (uint32_t)'0');
        *month = (int32_t)month_u;
    }
    {
        uint32_t day_u = (((uint32_t)time_data[6] - (uint32_t)'0') * 10U)
            + ((uint32_t)time_data[7] - (uint32_t)'0');
        *day = (int32_t)day_u;
    }
    {
        uint32_t hour_u = (((uint32_t)time_data[8] - (uint32_t)'0') * 10U)
            + ((uint32_t)time_data[9] - (uint32_t)'0');
        *hour = (int32_t)hour_u;
    }
    {
        uint32_t minute_u = (((uint32_t)time_data[10] - (uint32_t)'0') * 10U)
            + ((uint32_t)time_data[11] - (uint32_t)'0');
        *minute = (int32_t)minute_u;
    }
    {
        uint32_t second_u = (((uint32_t)time_data[12] - (uint32_t)'0') * 10U)
            + ((uint32_t)time_data[13] - (uint32_t)'0');
        *second = (int32_t)second_u;
    }
}

/**
 * @brief Convert ASN.1 time to noxtls_unix_time_t (Unix timestamp)
 *
 * @param time_data ASN.1 time data (UTCTime or GeneralizedTime)
 * @param time_len Length of time data
 * @param time_out Output noxtls_unix_time_t value
 * @return NOXTLS_RETURN_SUCCESS on success, error code otherwise
 */
static noxtls_return_t noxtls_x509_asn1_noxtls_unix_time_to_timet(const uint8_t *time_data, uint32_t time_len, noxtls_unix_time_t *time_out)
{
    if((time_data == NULL) || (time_len == 0U) || (time_out == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    /* Check if time data is valid ASCII; allow '.' or ',' for fractional seconds (GeneralizedTime) */
    uint32_t i = 0U;
    {
        uint8_t time_scan_done = 0U;
        for(i = 0U; (i < time_len) && (time_scan_done == 0U); i += 1U) {
            if(((uint8_t)time_data[i] < (uint8_t)'0') || ((uint8_t)time_data[i] > (uint8_t)'9')) {
                if((i == (time_len - 1U)) && (((uint8_t)time_data[i] == (uint8_t)'Z') || ((uint8_t)time_data[i] == (uint8_t)'+') || ((uint8_t)time_data[i] == (uint8_t)'-'))) {
                    /* Valid timezone indicator at end */
                    time_scan_done = 1U;
                } else if((i < (time_len - 1U)) && (((uint8_t)time_data[i] == (uint8_t)'+') || ((uint8_t)time_data[i] == (uint8_t)'-'))) {
                    /* Timezone offset */
                    time_scan_done = 1U;
                } else if((((uint8_t)time_data[i] == (uint8_t)'.') || ((uint8_t)time_data[i] == (uint8_t)',')) && (i == 14U)) {
                    /* GeneralizedTime may have fractional seconds */
                    time_scan_done = 1U;
                } else {
                    /* MISRA 15.7: final else path */
                    return NOXTLS_RETURN_BAD_DATA;
                }
            }
        }
    }

    int32_t year = 0;
    int32_t month = 0;
    int32_t day = 0;
    int32_t hour = 0;
    int32_t minute = 0;
    int32_t second = 0;

    /* Parse UTCTime formats: YYMMDDHHMMSSZ or YYMMDDHHMMSS+/-HHMM */
    if(((time_len == 13U) && ((uint8_t)time_data[12] == (uint8_t)'Z')) ||
       ((time_len == 17U) && (((uint8_t)time_data[12] == (uint8_t)'+') || ((uint8_t)time_data[12] == (uint8_t)'-')))) {
        year = x509_asn1_utc_year(time_data);
        x509_asn1_utc_load_mdhm(time_data, &month, &day, &hour, &minute, &second);
        /* For timezone offset encodings, we currently ignore the +/-HHMM suffix and assume UTC. */
    }
    /* Parse GeneralizedTime formats:
     *  - YYYYMMDDHHMMSSZ
     *  - YYYYMMDDHHMMSS
     *  - YYYYMMDDHHMMSS.0Z (or comma separator)
     *  - YYYYMMDDHHMMSS+/-HHMM
     */
    else if(((time_len == 15U) && ((uint8_t)time_data[14] == (uint8_t)'Z')) ||
            (time_len == 14U) ||
            ((time_len == 15U) && (((uint8_t)time_data[14] == (uint8_t)'.') || ((uint8_t)time_data[14] == (uint8_t)','))) ||
            ((time_len == 19U) && (((uint8_t)time_data[14] == (uint8_t)'+') || ((uint8_t)time_data[14] == (uint8_t)'-')))) {
        year = x509_asn1_gt_year(time_data);
        x509_asn1_gt_load_mdhm(time_data, &month, &day, &hour, &minute, &second);
        /* For timezone offset encodings, we currently ignore the +/-HHMM suffix and assume UTC. */
    } else {
        /* MISRA 15.7: final else path */
        return NOXTLS_RETURN_BAD_DATA;
    }

    /* Validate parsed values */
    if((month < 1) || (month > 12) || (day < 1) || (day > 31) ||
       (hour > 23) || (minute > 59) || (second > 59)) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    /* Calculate Unix timestamp (UTC) manually for portability */
    /* Algorithm based on standard Unix epoch calculation */

    /* Days per month (non-leap year) */
    static const int32_t days_per_month[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    /* Calculate days since epoch (1970-01-01 00:00:00 UTC) */
    int64_t days = 0;
    int y = 0;

    /* Add days for all years since 1970 */
    for(y = 1970; y < year; y++) {
        days += 365;
        /* Add leap day if it's a leap year */
        if(((((y % 4) == 0) && ((y % 100) != 0)) || ((y % 400) == 0))) {
            days += 1;
        }
    }

    /* Add days for all months in current year before current month */
    for(y = 1; y < month; y++) {
        days += days_per_month[y - 1];
        /* Add leap day for February in leap years */
        if((y == 2) && ((((year % 4) == 0) && ((year % 100) != 0)) || ((year % 400) == 0))) {
            days += 1;
        }
    }

    /* Add days for current month (day - 1, since day 1 is day 0) */
    days += (int64_t)day;
    days -= 1;

    /* Convert days to seconds and add time of day */
    int64_t seconds = days * 86400LL;  /* 86400 seconds per day */
    seconds += hour * 3600LL;
    seconds += minute * 60LL;
    seconds += second;

    /* Check for overflow/underflow (noxtls_unix_time_t is typically 32-bit or 64-bit) */
    if((seconds < 0) || (seconds > (int64_t)INT32_MAX)) {
        /* For 64-bit noxtls_unix_time_t, we can handle larger values, but check reasonable bounds */
#ifdef _MSC_VER
#ifdef _USE_32BIT_TIME_T
        if(seconds > INT32_MAX) {
            return NOXTLS_RETURN_FAILED;
        }
#endif
#else
        {
            /* Runtime-sized check keeps the failure path reachable on 64-bit hosts (Rule 2.1). */
            size_t time_width = sizeof(noxtls_unix_time_t);
            if((time_width == 4U) && (seconds > INT32_MAX)) {
                return NOXTLS_RETURN_FAILED;
            }
        }
#endif
    }

    *time_out = (noxtls_unix_time_t)seconds;

    return NOXTLS_RETURN_SUCCESS;
}
#endif /* NOXTLS_HAVE_TIME */

/**
 * @brief Check certificate validity (not expired)
 *
 * This function checks the validity of a certificate.
 *
 * @param[in] cert The certificate to check the validity of.
 * @return The return code of the function.
 */
#if NOXTLS_HAVE_TIME
static noxtls_return_t x509_check_time_bound(const x509_certificate_t *cert,
                                              const uint8_t *asn1_time,
                                              noxtls_unix_time_t current_time,
                                              int is_not_before,
                                              noxtls_unix_time_t *out_bound)
{
    uint32_t time_len = 0U;
    noxtls_unix_time_t bound = 0;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(out_bound != NULL) {
        *out_bound = 0;
    }
    if(asn1_time[0] == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }
    while((time_len < 15U) && (asn1_time[time_len] != 0U)) {
        time_len += 1U;
    }
    if(time_len == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }

    rc = noxtls_x509_asn1_noxtls_unix_time_to_timet(asn1_time, time_len, &bound);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        CERT_DEBUG_PRINT("x509_certificate_check_validity: failed to parse validity time\n");
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(out_bound != NULL) {
        *out_bound = bound;
    }

    if(is_not_before != 0) {
        if(current_time < bound) {
            CERT_DEBUG_PRINT("x509_certificate_check_validity: certificate not yet valid\n");
            cert_fail_set(NOXTLS_RETURN_CERT_NOT_YET_VALID, cert, NULL, 0, 0);
            return NOXTLS_RETURN_CERT_NOT_YET_VALID;
        }
    } else if(current_time > bound) {
        CERT_DEBUG_PRINT("x509_certificate_check_validity: certificate expired\n");
        cert_fail_set(NOXTLS_RETURN_CERT_EXPIRED, cert, NULL, 0, 0);
        return NOXTLS_RETURN_CERT_EXPIRED;
    }
     else {
         /* MISRA 15.7: no remaining alternative */
     }

    return NOXTLS_RETURN_SUCCESS;
}
#endif /* NOXTLS_HAVE_TIME */

#if NOXTLS_HAVE_TIME
/**
 * @brief Check notBefore/notAfter of a parsed certificate against a given time.
 * @internal
 *
 * @param[in] cert Parsed certificate.
 * @param[in] current_time Reference time.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_CERT_EXPIRED, NOXTLS_RETURN_CERT_NOT_YET_VALID
 *         or NOXTLS_RETURN_BAD_DATA.
 */
static noxtls_return_t x509_check_validity_window(const x509_certificate_t *cert, noxtls_unix_time_t current_time)
{
    noxtls_unix_time_t not_before_time = 0;
    noxtls_unix_time_t not_after_time = 0;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    rc = x509_check_time_bound(cert, cert->not_before, current_time, 1, &not_before_time);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = x509_check_time_bound(cert, cert->not_after, current_time, 0, &not_after_time);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if((not_before_time > 0) && (not_after_time > 0) && (not_before_time > not_after_time)) {
        CERT_DEBUG_PRINT("x509_certificate_check_validity: invalid validity period (not_before > not_after)\n");
        return NOXTLS_RETURN_BAD_DATA;
    }

    CERT_DEBUG_PRINT("x509_certificate_check_validity: certificate is valid\n");
    return NOXTLS_RETURN_SUCCESS;
}
#endif /* NOXTLS_HAVE_TIME */

noxtls_return_t noxtls_x509_certificate_check_validity(const x509_certificate_t *cert)
{
    if(cert == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(cert->parsed == 0) {
        return NOXTLS_RETURN_FAILED;
    }

#if NOXTLS_HAVE_TIME
    {
        noxtls_unix_time_t current_time = noxtls_time_unix_seconds();

        if(current_time == (noxtls_unix_time_t)-1) {
            CERT_DEBUG_PRINT("x509_certificate_check_validity: failed to get current time\n");
            return NOXTLS_RETURN_FAILED;
        }

        return x509_check_validity_window(cert, current_time);
    }
#else
    CERT_DEBUG_PRINT("x509_certificate_check_validity: time support not available, skipping time-based validation\n");
    return NOXTLS_RETURN_SUCCESS;
#endif /* NOXTLS_HAVE_TIME */
}

/**
 * @brief Check certificate validity at an explicit time.
 *
 * @param[in] cert Parsed certificate.
 * @param[in] now Seconds since the Unix epoch.
 *
 * @return NOXTLS_RETURN_SUCCESS, a CERT_* validity code, NOXTLS_RETURN_INVALID_PARAM when
 *         @p now is negative, or NOXTLS_RETURN_NOT_SUPPORTED without NOXTLS_HAVE_TIME.
 */
noxtls_return_t noxtls_x509_certificate_check_validity_at(const x509_certificate_t *cert, int64_t now)
{
    if(cert == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(!cert->parsed) {
        return NOXTLS_RETURN_FAILED;
    }

#if NOXTLS_HAVE_TIME
    {
        noxtls_unix_time_t reference = (noxtls_unix_time_t)now;

        if(now < 0) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }

        return x509_check_validity_window(cert, reference);
    }
#else
    (void)now;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif /* NOXTLS_HAVE_TIME */
}

/**
 * @brief Get public key from certificate (noxtls_ namespace)
 *
 * For ECC: *key is set to an allocated ecc_key_t* (caller must noxtls_ecc_key_free then free).
 * key_type: 1 = RSA, 2 = ECC.
 *
 * @param[in] cert The certificate to get the public key from.
 * @param[out] key The public key.
 * @param[out] key_type The type of the public key.
 *
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_certificate_get_public_key(const x509_certificate_t *cert, void **key, uint32_t *key_type)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    ecc_curve_t curve_type = NOXTLS_ECC_SECP256R1;
    ecc_key_t *ecc_key = NULL;
    uint32_t coord_size = 0U;

    if((cert == NULL) || (key == NULL) || (key_type == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    *key = NULL;
    *key_type = 0;

    if(cert->parsed == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    /* ECC public key from certificate */
    if((cert->ecc_public_key == NULL) || (cert->ecc_public_key_len == 0U)) {
        /* RSA not implemented here */
        return NOXTLS_RETURN_SUCCESS;
    }

    if(cert->ecc_curve_oid_len > 0U) {
        rc = noxtls_x509_ecc_curve_from_oid(cert->ecc_curve_oid, cert->ecc_curve_oid_len, &curve_type);
    } else {
        rc = noxtls_x509_ecc_curve_from_pubkey_len(cert->ecc_public_key_len, &curve_type);
    }

    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    ecc_key = (ecc_key_t *)NOXTLS_CALLOC(1, sizeof(ecc_key_t));
    if(ecc_key == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    rc = noxtls_ecc_key_init(ecc_key, curve_type);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_free(ecc_key);
        return rc;
    }

    coord_size = ecc_key->curve->size;
    if((cert->ecc_public_key[0] != 0x04U) || (cert->ecc_public_key_len != (1U + (2U * coord_size)))) {
        (void)noxtls_ecc_key_free(ecc_key);
        (void)noxtls_free(ecc_key);
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    noxtls_copy_u8((uint8_t *)(void *)(ecc_key->Q.x), (size_t)coord_size, (const uint8_t *)(const void *)(&cert->ecc_public_key[1]), (size_t)coord_size);
    noxtls_copy_u8((uint8_t *)(void *)(ecc_key->Q.y), (size_t)coord_size, (const uint8_t *)(const void *)(&cert->ecc_public_key[1U + coord_size]), (size_t)coord_size);
    ecc_key->Q.size = coord_size;
    if(noxtls_ecc_point_validate_public(&ecc_key->Q, ecc_key->curve) != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_ecc_key_free(ecc_key);
        (void)noxtls_free(ecc_key);
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    *key = ecc_key;
    *key_type = 2; /* ECC */
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Get public key from certificate (legacy wrapper)
 *
 * This function gets the public key from a certificate.
 *
 * @param[in] cert The certificate to get the public key from.
 * @param[out] key The public key.
 * @param[out] key_type The type of the public key.
 * @return The return code of the function.
 */
noxtls_return_t x509_certificate_get_public_key(const x509_certificate_t *cert, void **key, uint32_t *key_type)
{
    return noxtls_x509_certificate_get_public_key(cert, key, key_type);
}

/**
 * @brief Parse Distinguished Name
 * Helper function to get attribute name from OID
 * This function parses a Distinguished Name from a buffer.
 *
 * @param[in] dn_data The buffer to parse the Distinguished Name from.
 * @param[in] dn_len The length of the buffer.
 * @param[out] output The buffer to store the Distinguished Name.
 * @param[in] output_size The size of the buffer to store the Distinguished Name.
 * @return The return code of the function.
 */

static const uint8_t * noxtls_x509_get_attr_name_from_oid(const uint8_t *attr_oid, uint32_t attr_oid_len)
{
    /* Common OIDs for DN attributes */
    /* CN = 2.5.4.3 */
    if((attr_oid_len == 3U) && (attr_oid[0] == 0x55U) && (attr_oid[1] == 0x04U) && (attr_oid[2] == 0x03U)) {
        return s_u8txt_noxtls_x509_3160;
    }

    /* O = 2.5.4.10 */
    if((attr_oid_len == 3U) && (attr_oid[0] == 0x55U) && (attr_oid[1] == 0x04U) && (attr_oid[2] == 0x0AU)) {
        return s_u8txt_noxtls_x509_3165;
    }

    /* OU = 2.5.4.11 */
    if((attr_oid_len == 3U) && (attr_oid[0] == 0x55U) && (attr_oid[1] == 0x04U) && (attr_oid[2] == 0x0BU)) {
        return s_u8txt_noxtls_x509_3170;
    }

    /* C = 2.5.4.6 */
    if((attr_oid_len == 3U) && (attr_oid[0] == 0x55U) && (attr_oid[1] == 0x04U) && (attr_oid[2] == 0x06U)) {
        return s_u8txt_noxtls_x509_3175;
    }

    /* ST = 2.5.4.8 */
    if((attr_oid_len == 3U) && (attr_oid[0] == 0x55U) && (attr_oid[1] == 0x04U) && (attr_oid[2] == 0x08U)) {
        return s_u8txt_noxtls_x509_3180;
    }

    /* L = 2.5.4.7 */
    if((attr_oid_len == 3U) && (attr_oid[0] == 0x55U) && (attr_oid[1] == 0x04U) && (attr_oid[2] == 0x07U)) {
        return s_u8txt_noxtls_x509_3185;
    }

    /* E = 1.2.840.113549.1.9.1 (emailAddress) */
    if((attr_oid_len == 9U) && (attr_oid[0] == 0x2AU) && (attr_oid[1] == 0x86U) && (attr_oid[2] == 0x48U) &&
       (attr_oid[3] == 0x86U) && (attr_oid[4] == 0xF7U) && (attr_oid[5] == 0x0DU) && (attr_oid[6] == 0x01U) &&
       (attr_oid[7] == 0x09U) && (attr_oid[8] == 0x01U)) {
        return s_u8txt_noxtls_x509_3192;
    }
    return NULL;
}

/**     
 * @brief Parse Distinguished Name
 *
 * This function parses a Distinguished Name from a buffer.
 *
 * @param[in] dn_data The buffer to parse the Distinguished Name from.
 * @param[in] dn_len The length of the buffer.
 * @param[out] output The buffer to store the Distinguished Name.
 * @param[in] output_size The size of the buffer to store the Distinguished Name.
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_parse_distinguished_name(const uint8_t *dn_data, uint32_t dn_len, uint8_t *output, uint32_t output_size)
{
    uint32_t output_pos = 0U;
    int first = 1;

    if((output == NULL) || (output_size == 0U) || (dn_data == NULL) || (dn_len == 0U)) {
        if((output != NULL) && (output_size > 0U)) {
            output[0] = 0U;
        }
        return NOXTLS_RETURN_NULL;
    }

    output[0] = 0U;

    /* DN is a SEQUENCE OF RelativeDistinguishedName */
    /* The dn_data already points to the SEQUENCE content, so we don't need to parse it again */
    const uint8_t *dn_end = &dn_data[dn_len];
    const uint8_t *dn_ptr = dn_data;

    /* Iterate through RDN sequence */
    {
    uint8_t dn_done = 0U;
    while((((uintptr_t)dn_ptr < (uintptr_t)dn_end)) && (dn_done == 0U)) {
        const uint8_t *rdn_data = NULL;
        uint32_t rdn_len = 0U;

        /* Try SET first (RDN is a SET, tag 0x31); loop guarantees ((uintptr_t)dn_ptr < (uintptr_t)dn_end) */
        if(*dn_ptr == 0x31U) {
            dn_ptr = &dn_ptr[1];  /* Skip SET tag */
            rdn_len = asn1_get_length(&dn_ptr, dn_end);
            if((rdn_len > 0U) && (x509_bytes_remaining(dn_ptr, dn_end) >= (size_t)rdn_len)) {
                rdn_data = dn_ptr;
                dn_ptr = &dn_ptr[rdn_len];
            } else {
                dn_done = 1U;  /* Invalid SET */
            }
        } else if(*dn_ptr == 0x30U) {
            if(asn1_get_sequence(&dn_ptr, dn_end, &rdn_data, &rdn_len) != NOXTLS_RETURN_SUCCESS) {
                dn_done = 1U;  /* End of DN or invalid */
            }
        } else {
            dn_done = 1U;  /* Unexpected tag */
        }
        if(dn_done != 0U) {
            continue;
        }

        const uint8_t *rdn_end = &rdn_data[rdn_len];
        const uint8_t *rdn_ptr = rdn_data;

        /* If RDN is a SET (e.g. Name = SEQUENCE(SET(SEQUENCE(...)))), unwrap to get the AttributeTypeAndValue SEQUENCE */
        if((rdn_len >= 1U) && (*rdn_data == 0x31U)) {
            const uint8_t *set_ptr = &rdn_data[1];
            uint32_t set_content_len = (uint32_t)(asn1_get_length(&set_ptr, rdn_end));
            if((set_content_len == 0U) || (x509_bytes_remaining(set_ptr, rdn_end) < (size_t)set_content_len)) {
                continue;
            }
            rdn_ptr = set_ptr;
            rdn_end = &set_ptr[set_content_len];
        }

        /* Parse AttributeTypeAndValue: SEQUENCE { type OID, value ANY } */
        const uint8_t *attr_data = NULL;
        uint32_t attr_len = 0U;

        if(asn1_get_sequence(&rdn_ptr, rdn_end, &attr_data, &attr_len) != NOXTLS_RETURN_SUCCESS) {
            continue;  /* Skip invalid attribute */
        }

        const uint8_t *attr_end = &attr_data[attr_len];
        const uint8_t *attr_ptr = attr_data;

        /* Parse OID (attribute type) */
        uint8_t dn_oid[32];
        uint32_t dn_oid_len = (uint32_t)sizeof(dn_oid);
        if(asn1_get_oid(&attr_ptr, attr_end, dn_oid, &dn_oid_len) != NOXTLS_RETURN_SUCCESS) {
            continue;  /* Skip if no OID */
        }

        /* Get attribute name */
        const uint8_t *attr_name = noxtls_x509_get_attr_name_from_oid(dn_oid, dn_oid_len);
        if(attr_name == NULL) {
            attr_name = s_u8txt_noxtls_x509_3290;  /* Unknown attribute */
        }

        /* Parse value (can be various types, but usually a string) */
        if(((uintptr_t)attr_ptr < (uintptr_t)attr_end)) {
            attr_ptr = &attr_ptr[1];  /* Skip value tag */
            uint32_t attr_value_len = (uint32_t)(asn1_get_length(&attr_ptr, attr_end));

            if((attr_value_len > 0U) && (x509_bytes_remaining(attr_ptr, attr_end) >= (size_t)attr_value_len) &&
               (output_pos < (output_size - 1U))) {

                /* Format: "attr=value, " */
                if((first == 0) && (output_pos < (output_size - 2U))) {
                    output[output_pos] = (uint8_t)',';
                    output_pos += 1U;
                    output[output_pos] = (uint8_t)' ';
                    output_pos += 1U;
                }
                first = 0;

                /* Add attribute name */
                size_t name_len = noxtls_u8_strlen(attr_name);
                size_t remaining = (size_t)((output_pos < output_size) ? (size_t)(output_size - output_pos) : 0U);
                if((remaining > 1U) && ((name_len + 1U) < remaining)) {
                    noxtls_copy_u8((uint8_t *)(void *)(&output[output_pos]), (size_t)name_len, (const uint8_t *)(const void *)(attr_name), (size_t)name_len);
                    output_pos += (uint32_t)name_len;
                    output[output_pos] = (uint8_t)'=';
                    output_pos += 1U;
                }

                /* Add value (limit to printable characters and reasonable length) */
                uint32_t i = 0U;
                uint32_t room = (output_size - output_pos) - 1U;
                uint32_t max_value_len = (room < attr_value_len) ? room : attr_value_len;

                for(i = 0U; (i < max_value_len) && (output_pos < (output_size - 1U)); i += 1U) {
                    uint8_t c = attr_ptr[i];
                    if(((uint8_t)c >= (uint8_t)32) && ((uint8_t)c < (uint8_t)127)) {  /* Printable ASCII */
                        output[output_pos] = (uint8_t)c;
                        output_pos += 1U;
                    } else {
                        output[output_pos] = (uint8_t)'?';
                        output_pos += 1U;
                    }
                }
            }
        }
    }
    }

    output[output_pos] = 0U;

    if(output_pos == 0U) {
        static const uint8_t empty_dn[] = "(empty DN)";
        uint32_t k = 0U;
        while((empty_dn[k] != 0U) && (k + 1U < output_size)) {
            output[k] = empty_dn[k];
            k += 1U;
        }
        output[k] = 0U;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Parse ASN.1 time
 *
 * This function parses an ASN.1 time from a buffer.
 *
 * @param[in] time_data The buffer to parse the ASN.1 time from.
 * @param[in] time_len The length of the buffer.
 * @param[out] output The buffer to store the ASN.1 time.
 * @param[in] output_size The size of the buffer to store the ASN.1 time.
 * @return The return code of the function.
 */
/** Size of "YYYY-MM-DD HH:MM:SS" plus the NUL terminator. */
#define X509_FORMATTED_TIME_SIZE 20U

static noxtls_return_t x509_format_utctime(uint8_t *output, uint32_t output_size, int year, const uint8_t *time_str)
{
    uint8_t ydigits[4];

    if((output == NULL) || (output_size == 0U) || (time_str == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    output[0] = 0U;
    if(output_size < X509_FORMATTED_TIME_SIZE) {
        return NOXTLS_RETURN_INVALID_PARAM;  /* caller buffer cannot hold the formatted time */
    }
    if((year < 0) || (year > 9999)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    {
        uint32_t yu = (uint32_t)year;
        uint32_t d;
        d = yu % 10U; yu = yu / 10U; d = d + 0x30U; ydigits[3] = (uint8_t)d;
        d = yu % 10U; yu = yu / 10U; d = d + 0x30U; ydigits[2] = (uint8_t)d;
        d = yu % 10U; yu = yu / 10U; d = d + 0x30U; ydigits[1] = (uint8_t)d;
        d = yu % 10U; d = d + 0x30U; ydigits[0] = (uint8_t)d;
    }

    output[0] = ydigits[0];
    output[1] = ydigits[1];
    output[2] = ydigits[2];
    output[3] = ydigits[3];
    output[4] = (uint8_t)'-';
    output[5] = time_str[2];
    output[6] = time_str[3];
    output[7] = (uint8_t)'-';
    output[8] = time_str[4];
    output[9] = time_str[5];
    output[10] = (uint8_t)' ';
    output[11] = time_str[6];
    output[12] = time_str[7];
    output[13] = (uint8_t)':';
    output[14] = time_str[8];
    output[15] = time_str[9];
    output[16] = (uint8_t)':';
    output[17] = time_str[10];
    output[18] = time_str[11];
    output[19] = 0U;
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t x509_format_generalized_time(uint8_t *output, uint32_t output_size, const uint8_t *time_str)
{
    if((output == NULL) || (output_size == 0U) || (time_str == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    output[0] = 0U;
    if(output_size < X509_FORMATTED_TIME_SIZE) {
        return NOXTLS_RETURN_INVALID_PARAM;  /* caller buffer cannot hold the formatted time */
    }
    output[0] = time_str[0];
    output[1] = time_str[1];
    output[2] = time_str[2];
    output[3] = time_str[3];
    output[4] = (uint8_t)'-';
    output[5] = time_str[4];
    output[6] = time_str[5];
    output[7] = (uint8_t)'-';
    output[8] = time_str[6];
    output[9] = time_str[7];
    output[10] = (uint8_t)' ';
    output[11] = time_str[8];
    output[12] = time_str[9];
    output[13] = (uint8_t)':';
    output[14] = time_str[10];
    output[15] = time_str[11];
    output[16] = (uint8_t)':';
    output[17] = time_str[12];
    output[18] = time_str[13];
    output[19] = 0U;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_x509_parse_time(const uint8_t *time_data, uint32_t time_len, uint8_t *output, uint32_t output_size)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if((output == NULL) || (output_size == 0U) || (time_data == NULL) || (time_len == 0U)) {
        if((output != NULL) && (output_size > 0U)) {
            output[0] = 0U;
        }
        return NOXTLS_RETURN_NULL;
    }

    /* UTCTime format: YYMMDDHHMMSSZ (13 bytes) or YYMMDDHHMMSS+/-HHMM (17 bytes) */
    /* GeneralizedTime format: YYYYMMDDHHMMSSZ (15 bytes) or YYYYMMDDHHMMSS+/-HHMM (19 bytes) */

    /* First, copy the raw time string to a buffer for processing */
    uint8_t time_str[20] = {0};
    uint32_t i = 0U;
    for(i = 0U; (i < time_len) && (i < (sizeof(time_str) - 1U)); i += 1U) {
        uint8_t c = time_data[i];
        if(((uint8_t)c >= (uint8_t)32) && ((uint8_t)c < (uint8_t)127)) {  /* Printable ASCII */
            time_str[i] = (uint8_t)c;
        } else {
            time_str[i] = (uint8_t)'?';
        }
    }
    time_str[i] = 0U;

    /* Format: YYMMDDHHMMSSZ -> YYYY-MM-DD HH:MM:SS */
    if((time_len == 13U) && (time_str[12] == (uint8_t)'Z')) {
        /* UTCTime: convert YY to YYYY */
        int year = ((int)time_str[0] - 0x30) * 10 + ((int)time_str[1] - 0x30);
        if(year < 50) {
            year += 2000;  /* 00-49 = 2000-2049 */
        } else {
            year += 1900;  /* 50-99 = 1950-1999 */
        }

        /* Format: YYYY-MM-DD HH:MM:SS */
        rc = x509_format_utctime(output, output_size, year, time_str);
    } else if((time_len == 15U) && (time_str[14] == (uint8_t)'Z')) {
        /* GeneralizedTime: YYYYMMDDHHMMSSZ */
        rc = x509_format_generalized_time(output, output_size, time_str);
    } else {
        /* Invalid or unsupported time format - just show raw */
        size_t time_str_len = (size_t)i;
        size_t copy_len = (size_t)((time_str_len > (output_size - 1U)) ? (size_t)(output_size - 1U) : time_str_len);
        noxtls_copy_u8((uint8_t *)(void *)(output), (size_t)copy_len, (const uint8_t *)(const void *)(time_str), (size_t)copy_len);
        output[copy_len] = 0U;
    }

    if(rc != NOXTLS_RETURN_SUCCESS) {
        output[0] = 0U;  /* never leave a partial or unterminated string behind on error */
    }
    return rc;
}

/**
 * @brief Initialize certificate chain
 *
 * This function initializes a certificate chain.
 *
 * @param[in] chain The certificate chain to initialize.
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_certificate_chain_init(x509_certificate_chain_t *chain)
{
    if(chain == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero((chain), sizeof(x509_certificate_chain_t));
    chain->capacity = 8;
    chain->certs = (x509_certificate_t*)NOXTLS_CALLOC(chain->capacity, sizeof(x509_certificate_t));
    if(chain->certs == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Free certificate chain
 *
 * This function frees a certificate chain.
 *
 * @param[in] chain The certificate chain to free.
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_certificate_chain_free(x509_certificate_chain_t *chain)
{
    if(chain == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(chain->certs != NULL) {
        uint32_t i = 0U;
        for(i = 0U; i < chain->count; i += 1U) {
            (void)noxtls_x509_certificate_free(&chain->certs[i]);
        }
        (void)noxtls_free(chain->certs);
        chain->certs = NULL;
    }

    noxtls_secure_zero((chain), sizeof(x509_certificate_chain_t));

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Add certificate to chain
 *
 * This function adds a certificate to a certificate chain.
 *
 * @param[in] chain The certificate chain to add the certificate to.
 * @param[in] cert The certificate to add to the chain.
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_certificate_chain_add(x509_certificate_chain_t *chain, const x509_certificate_t *cert)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    x509_certificate_t *dst = NULL;

    if((chain == NULL) || (cert == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if(chain->count >= chain->capacity) {
        /* Expand capacity */
        if((chain->capacity == 0U) || (chain->capacity > (UINT32_MAX / 2U))) {
            return NOXTLS_RETURN_FAILED;
        }
        uint32_t new_capacity = (uint32_t)(chain->capacity * 2U);
        if(new_capacity > (UINT32_MAX / (uint32_t)sizeof(x509_certificate_t))) {
            return NOXTLS_RETURN_FAILED;
        }
        x509_certificate_t *new_certs = (x509_certificate_t*)NOXTLS_REALLOC(chain->certs, (size_t)new_capacity * sizeof(x509_certificate_t));
        if(new_certs == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        chain->certs = new_certs;
        chain->capacity = new_capacity;
    }

    dst = &chain->certs[chain->count];
    (void)noxtls_x509_certificate_init(dst);

    /* Allow adding an init-only cert (no raw_data) for empty slot / unit tests. */
    if((cert->raw_data == NULL) || (cert->raw_data_len == 0U)) {
        chain->count += 1U;
        return NOXTLS_RETURN_SUCCESS;
    }

    /* Deep-copy by reparsing source DER to avoid shared pointer ownership/double-free. */
    rc = noxtls_x509_certificate_parse_der(dst, cert->raw_data, cert->raw_data_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_x509_certificate_free(dst);
        return rc;
    }

    chain->count += 1U;

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Verify certificate chain
 *
 * This function verifies a certificate chain.
 *
 * @param[in] chain The certificate chain to verify.
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_certificate_chain_verify(const x509_certificate_chain_t *chain)
{
    uint32_t i = 0U;

    if(chain == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(chain->count == 0U) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Verify each certificate is signed by the next one */
    for(i = 0U; i < (chain->count - 1U); i += 1U) {
        noxtls_return_t rc = noxtls_x509_certificate_verify_signature(&chain->certs[i], &chain->certs[i + 1U]);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            s_cert_fail_info.cert_index = i;
            s_cert_fail_info.return_code = NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED;
            return NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED;
        }

        rc = noxtls_x509_certificate_check_validity(&chain->certs[i]);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            s_cert_fail_info.cert_index = i;
            return rc;  /* CERT_EXPIRED or CERT_NOT_YET_VALID already set by check_validity */
        }
    }

    /* Check validity of last certificate (root CA) */
    {
        noxtls_return_t rc = noxtls_x509_certificate_check_validity(&chain->certs[chain->count - 1U]);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            s_cert_fail_info.cert_index = chain->count - 1U;
            return rc;
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}
/**
 * @brief Compare two Distinguished Names
 *
 * This function compares two Distinguished Names.
 *
 * @param[in] lhs The left-hand side Distinguished Name.
 * @param[in] lhs_len The length of the left-hand side Distinguished Name.
 * @param[in] rhs The right-hand side Distinguished Name.
 * @param[in] rhs_len The length of the right-hand side Distinguished Name.
 *
 * @return The return code of the function.
 */
static int x509_dn_equal(const uint8_t *lhs, uint32_t lhs_len, const uint8_t *rhs, uint32_t rhs_len)
{
    if((lhs == NULL) || (rhs == NULL)) {
        return 0;
    }
    if(lhs_len != rhs_len) {
        return 0;
    }
    if(lhs_len == 0U) {
        return 1;
    }
    return (noxtls_ct_memcmp(lhs, rhs, (size_t)lhs_len) == 0) ? 1 : 0;
}

/**
 * @brief Check whether two parsed certificates are the same certificate.
 * @internal
 *
 * Identity is decided by the full DER TBSCertificate plus the signature value, never by
 * subject, serial number or public key alone: an attacker can copy any of those fields
 * into a certificate signed with their own key.
 *
 * @param[in] lhs The left-hand side certificate.
 * @param[in] rhs The right-hand side certificate.
 *
 * @return 1 when both certificates are byte-identical, 0 otherwise.
 */
static int x509_cert_identical(const x509_certificate_t *lhs, const x509_certificate_t *rhs)
{
    int same = 0;

    if((lhs == NULL) || (rhs == NULL)) {
        return 0;
    }
    if(lhs == rhs) {
        return 1;
    }
    if((lhs->tbs_certificate == NULL) || (rhs->tbs_certificate == NULL) ||
       (lhs->tbs_certificate_len == 0U) ||
       (lhs->tbs_certificate_len != rhs->tbs_certificate_len) ||
       (lhs->signature_len != rhs->signature_len)) {
        return 0;
    }
    if(noxtls_ct_memcmp(lhs->tbs_certificate, rhs->tbs_certificate, (size_t)lhs->tbs_certificate_len) == 0) {
        if(lhs->signature_len == 0U) {
            same = 1;
        } else if((lhs->signature != NULL) && (rhs->signature != NULL) &&
                  (noxtls_ct_memcmp(lhs->signature, rhs->signature, (size_t)lhs->signature_len) == 0)) {
            same = 1;
        } else {
            /* MISRA 15.7: signatures differ */
        }
    }
    return same;
}

/**
 * @brief Check issuer policy
 *
 * This function checks the policy of an issuer.
 *
 * @param[in] issuer The issuer to check the policy of.
 * @param[in] path_depth_below The path depth below the issuer.
 *
 * @return The return code of the function.
 */
static noxtls_return_t x509_issuer_policy_check(const x509_certificate_t *issuer, uint32_t path_depth_below)
{
    if(issuer == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(issuer->basic_constraints_ca != 1) {
        cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED, issuer, NULL, 0, path_depth_below + 1U);
        return NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED;
    }
    if((issuer->key_usage_bits != 0U) &&
       ((issuer->key_usage_bits & X509_KEY_USAGE_KEY_CERT_SIGN) == 0U)) {
        cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED, issuer, NULL, 0, path_depth_below + 1U);
        return NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED;
    }
    if((issuer->basic_constraints_path_len != X509_BC_PATH_LEN_ABSENT) &&
       (path_depth_below > (uint32_t)issuer->basic_constraints_path_len)) {
        cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED, issuer, NULL, 0, path_depth_below + 1U);
        return NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Check leaf policy
 *
 * This function checks the policy of a leaf certificate.
 *
 * @param[in] leaf The leaf certificate to check the policy of.
 * @param[in] required_eku The required Extended Key Usage.
 * @return The return code of the function.
 *
 */
static noxtls_return_t x509_leaf_policy_check(const x509_certificate_t *leaf, uint32_t required_eku)
{
    uint32_t required_key_usage = X509_KEY_USAGE_DIGITAL_SIGNATURE;

    if(leaf == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(leaf->basic_constraints_ca == 1) {
        cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED, leaf, NULL, 0, 0);
        return NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED;
    }
    if((leaf->ext_key_usage_bits != 0U) &&
       ((leaf->ext_key_usage_bits & (required_eku | X509_EKU_ANY)) == 0U)) {
        cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED, leaf, NULL, 0, 0);
        return NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED;
    }
    if(required_eku == X509_EKU_SERVER_AUTH) {
        required_key_usage = X509_KEY_USAGE_DIGITAL_SIGNATURE |
                             X509_KEY_USAGE_KEY_ENCIPHERMENT |
                             X509_KEY_USAGE_KEY_AGREEMENT;
    } else if(required_eku == X509_EKU_CLIENT_AUTH) {
        required_key_usage = X509_KEY_USAGE_DIGITAL_SIGNATURE |
                             X509_KEY_USAGE_KEY_AGREEMENT;
    }
     else {
         /* MISRA 15.7: no remaining alternative */
     }
    if((leaf->key_usage_bits != 0U) &&
       ((leaf->key_usage_bits & required_key_usage) == 0U)) {
        cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED, leaf, NULL, 0, 0);
        return NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Check whether a candidate's subject name matches a certificate's issuer name.
 * @internal
 *
 * Name matching only selects candidates; it never establishes trust on its own.
 *
 * @param[in] subject_cert Certificate whose issuer is being looked up.
 * @param[in] candidate Candidate issuer certificate.
 *
 * @return 1 when the names match, 0 otherwise.
 */
static int x509_issuer_name_matches(const x509_certificate_t *subject_cert, const x509_certificate_t *candidate)
{
    int dn_match = x509_dn_equal(subject_cert->issuer, subject_cert->issuer_len,
                                 candidate->subject, candidate->subject_len);

    if((dn_match == 0) && (subject_cert->issuer_dn[0] != 0U) && (candidate->subject_dn[0] != 0U)) {
        dn_match = (noxtls_u8_strcmp(subject_cert->issuer_dn, candidate->subject_dn) == 0) ? 1 : 0;
    }
    return dn_match;
}

/**
 * @brief Check AuthorityKeyIdentifier / SubjectKeyIdentifier consistency (RFC 5280 4.2.1.1, 4.2.1.2).
 * @internal
 *
 * @param[in] subject_cert Certificate whose issuer is being looked up.
 * @param[in] candidate Candidate issuer certificate.
 *
 * @return 1 when either identifier is absent or both are equal, 0 when they differ.
 */
static int x509_key_id_matches(const x509_certificate_t *subject_cert, const x509_certificate_t *candidate)
{
    int match = 1;

    if((subject_cert->authority_key_id_len > 0U) && (candidate->subject_key_id_len > 0U)) {
        if(subject_cert->authority_key_id_len != candidate->subject_key_id_len) {
            match = 0;
        } else if(noxtls_ct_memcmp(subject_cert->authority_key_id, candidate->subject_key_id,
                                   (size_t)subject_cert->authority_key_id_len) != 0) {
            match = 0;
        } else {
            /* MISRA 15.7: identifiers are equal */
        }
    }
    return match;
}

/**
 * @brief Find the issuer of a certificate in a chain.
 * @internal
 *
 * Returns only a candidate whose subject name matches the certificate's issuer name, that
 * is not the certificate itself, and whose public key verifies the certificate's signature.
 * Candidates whose SubjectKeyIdentifier matches the AuthorityKeyIdentifier (or that lack
 * one of the identifiers) are tried first; others are tried afterwards so that a stale key
 * identifier does not break an otherwise valid, signature-verified path.
 *
 * @param[in] subject_cert The subject certificate to find the issuer of.
 * @param[in] chain The certificate chain to search in.
 *
 * @return The signature-verified issuer certificate, or NULL when none verifies.
 */
static const x509_certificate_t *x509_find_issuer_in_chain(const x509_certificate_t *subject_cert,
                                                            const x509_certificate_chain_t *chain)
{
    uint32_t pass = 0U;
    uint32_t i = 0U;

    if((subject_cert == NULL) || (chain == NULL) || (chain->certs == NULL)) {
        return NULL;
    }
    for(pass = 0U; pass < 2U; pass += 1U) {
        int want_key_id_match = (pass == 0U) ? 1 : 0;
        for(i = 0U; i < chain->count; i += 1U) {
            const x509_certificate_t *candidate = &chain->certs[i];
            if(x509_cert_identical(subject_cert, candidate) != 0) {
                continue;
            }
            if(x509_issuer_name_matches(subject_cert, candidate) == 0) {
                continue;
            }
            if(x509_key_id_matches(subject_cert, candidate) != want_key_id_match) {
                continue;
            }
            if(noxtls_x509_certificate_verify_signature(subject_cert, candidate) == NOXTLS_RETURN_SUCCESS) {
                return candidate;
            }
        }
    }
    return NULL;
}

/**
 * @brief Check if a certificate chain contains a certificate
 *
 * Membership requires a byte-identical certificate (see x509_cert_identical()).
 *
 * @param[in] chain The certificate chain to check.
 * @param[in] cert The certificate to check for.
 *
 * @return 1 when @p chain contains @p cert, 0 otherwise.
 */
static int x509_chain_contains_cert(const x509_certificate_chain_t *chain, const x509_certificate_t *cert)
{
    uint32_t i = 0U;
    if((chain == NULL) || (cert == NULL) || (chain->certs == NULL)) {
        return 0;
    }
    for(i = 0U; i < chain->count; i += 1U) {
        if(x509_cert_identical(&chain->certs[i], cert) != 0) {
            return 1;
        }
    }
    return 0;
}

/* -------------------------------------------------------------------------- */
/* X.509 CRL (CertificateList) parsing and optional trust verification        */
/* -------------------------------------------------------------------------- */

/**
 * @brief Check if two serial numbers are equal
 *
 * This function checks if two serial numbers are equal.
 *
 * @param[in] a The first serial number.
 * @param[in] alen The length of the first serial number.
 * @param[in] b The second serial number.
 * @param[in] blen The length of the second serial number.
 * @return The return code of the function.
 */
static int x509_serial_equal_normalized(const uint8_t *a, uint32_t alen, const uint8_t *b, uint32_t blen)
{
    uint32_t i = 0U;
    uint32_t j = 0U;
    if((a == NULL) || (b == NULL)) {
        return 0;
    }
    i = 0U;
    while((i < alen) && (a[i] == 0U)) {
        i += 1U;
    }
    j = 0U;
    while((j < blen) && (b[j] == 0U)) {
        j += 1U;
    }
    if((alen - i) != (blen - j)) {
        return 0;
    }
    if((alen - i) == 0U) {
        return 1;
    }
    return (noxtls_ct_memcmp(&a[i], &b[j], (size_t)(alen - i)) == 0) ? 1 : 0;
}

/**
 * @brief Convert PEM CRL to DER
 *
 * This function converts a PEM CRL to DER.
 *
 * @param[in] data The PEM CRL data.
 * @param[in] length The length of the PEM CRL data.
 * @param[out] output The DER CRL data.
 * @param[out] out_len The length of the DER CRL data.
 *
 * @return The return code of the function.
 */
static noxtls_return_t noxtls_x509_crl_pem_to_der(const uint8_t *data, uint32_t length, uint8_t *output, uint32_t *out_len)
{
    static const uint8_t begin_str[] = "-----BEGIN X509 CRL-----";
    static const uint8_t end_str[] = "-----END X509 CRL-----";
    uint32_t bi = 0U;
    uint32_t ei = 0U;
    uint32_t b_len = 0U;
    uint32_t e_len = 0U;

    if((data == NULL) || (length == 0U) || (output == NULL) || (out_len == NULL)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    b_len = (uint32_t)(sizeof(begin_str) - 1U);
    e_len = (uint32_t)(sizeof(end_str) - 1U);
    bi = 0U;
    while((bi + b_len) <= length) {
        if(noxtls_ct_memcmp(&data[bi], begin_str, (size_t)b_len) == 0) {
            break;
        }
        bi += 1U;
    }
    if((bi + b_len) > length) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    ei = bi + b_len;
    while((ei + e_len) <= length) {
        if(noxtls_ct_memcmp(&data[ei], end_str, (size_t)e_len) == 0) {
            break;
        }
        ei += 1U;
    }
    if((ei + e_len) > length) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    {
        uint32_t b64_len = (uint32_t)(ei - (bi + b_len));
        int dec = noxtls_base64_decode(&data[bi + b_len], b64_len, output);
        if(dec < 0) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        *out_len = (uint32_t)dec;
    }
    return NOXTLS_RETURN_SUCCESS;
}


/**
 * @brief Initialize a CRL
 *
 * This function initializes a CRL.
 *
 * @param[in] crl The CRL to initialize.
 *
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_crl_init(noxtls_x509_crl_t *crl)
{
    if(crl == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    noxtls_secure_zero((crl), sizeof(noxtls_x509_crl_t));
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Free a CRL
 *
 * This function frees a CRL.
 *
 * @param[in] crl The CRL to free.
 * @return The return code of the function.
 */
void noxtls_x509_crl_free(noxtls_x509_crl_t *crl)
{
    noxtls_x509_crl_t *cur = crl;
    while(cur != NULL) {
        noxtls_x509_crl_t *nxt = cur->next;
        cur->next = NULL;
        if(cur->signature != NULL) {
            (void)noxtls_free(cur->signature);
            cur->signature = NULL;
        }
        if(cur->tbs_crl != NULL) {
            (void)noxtls_free(cur->tbs_crl);
            cur->tbs_crl = NULL;
        }
        if(cur->raw_data != NULL) {
            (void)noxtls_free(cur->raw_data);
            cur->raw_data = NULL;
        }
        if(cur->revoked_serials != NULL) {
            (void)noxtls_free(cur->revoked_serials);
            cur->revoked_serials = NULL;
        }
        if(cur->revoked_serial_lens != NULL) {
            (void)noxtls_free(cur->revoked_serial_lens);
            cur->revoked_serial_lens = NULL;
        }
        noxtls_secure_zero((cur), sizeof(noxtls_x509_crl_t));
        cur = nxt;
    }
}

/**
 * @brief Parse a CRL from DER
 *
 * This function parses a CRL from DER.
 *
 * @param[in] crl The CRL to parse.
 * @param[in] data The DER data to parse.
 * @param[in] len The length of the DER data.
 *
 * @return The return code of the function.
 */
static noxtls_return_t x509_crl_parse_der_body(noxtls_x509_crl_t *crl)
{
    const uint8_t *ptr = crl->raw_data;
    const uint8_t *end = &crl->raw_data[crl->raw_data_len];
    const uint8_t *seq_data = NULL;
    uint32_t seq_len = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

        const uint8_t *cert_list_end = NULL;
        const uint8_t *tbs_outer_start = NULL;
        const uint8_t *tbs_content = NULL;
        uint32_t tbs_content_len = 0U;
        const uint8_t *tbs_ptr = NULL;
        const uint8_t *tbs_end = NULL;

        if(asn1_get_sequence(&ptr, end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
            return rc;
        }
        cert_list_end = &seq_data[seq_len];
        ptr = seq_data;

        tbs_outer_start = ptr;
        if(asn1_get_sequence(&ptr, cert_list_end, &tbs_content, &tbs_content_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
            return rc;
        }

        crl->tbs_crl_len = (uint32_t)((uintptr_t)ptr - (uintptr_t)tbs_outer_start);
        crl->tbs_crl = (uint8_t*)NOXTLS_MALLOC(crl->tbs_crl_len);
        if(crl->tbs_crl == NULL) {
            rc = NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
            return rc;
        }
        noxtls_copy_u8((uint8_t *)(void *)(crl->tbs_crl), (size_t)crl->tbs_crl_len, (const uint8_t *)(const void *)(tbs_outer_start), (size_t)crl->tbs_crl_len);

        tbs_ptr = tbs_content;
        tbs_end = &tbs_content[tbs_content_len];

        /* Optional version (INTEGER, usually v2 = 1). */
        if(((uintptr_t)tbs_ptr < (uintptr_t)tbs_end) && (*tbs_ptr == (uint8_t)0x02U)) {
            uint8_t version_raw[4];
            uint32_t version_raw_len = (uint32_t)sizeof(version_raw);
            if(asn1_get_integer(&tbs_ptr, tbs_end, version_raw, &version_raw_len) != NOXTLS_RETURN_SUCCESS) {
                rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
                return rc;
            }
        } else if(((uintptr_t)tbs_ptr < (uintptr_t)tbs_end) && (*tbs_ptr == (uint8_t)0xA0U)) {
            /* Backward compatibility for older parser behavior. */
            tbs_ptr = &tbs_ptr[1];
            {
                uint32_t wrap_len = (uint32_t)(asn1_get_length(&tbs_ptr, tbs_end));
                if(wrap_len > (uint32_t)((uintptr_t)tbs_end - (uintptr_t)tbs_ptr)) {
                    rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
                    return rc;
                }
                tbs_ptr = &tbs_ptr[wrap_len];
            }
        }
         else {
             /* MISRA 15.7: no remaining alternative */
         }

        /* signature AlgorithmIdentifier inside TBSCertList */
        if(asn1_get_sequence(&tbs_ptr, tbs_end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
            return rc;
        }
        {
            const uint8_t *alg_end = &seq_data[seq_len];
            const uint8_t *alg_ptr = seq_data;
            if(asn1_get_oid(&alg_ptr, alg_end, crl->signature_algorithm_oid, &crl->signature_algorithm_oid_len) != NOXTLS_RETURN_SUCCESS) {
                rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
                return rc;
            }
        }

        /* issuer */
        if(asn1_get_sequence(&tbs_ptr, tbs_end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
            return rc;
        }
        if(seq_len > X509_MAX_ISSUER_SIZE) {
            rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
            return rc;
        }
        noxtls_copy_u8((uint8_t *)(void *)(crl->issuer), (size_t)seq_len, (const uint8_t *)(const void *)(seq_data), (size_t)seq_len);
        crl->issuer_len = seq_len;
        (void)noxtls_x509_parse_distinguished_name(seq_data, seq_len, crl->issuer_dn, sizeof(crl->issuer_dn));

        /* thisUpdate */
        if(((uintptr_t)tbs_ptr >= (uintptr_t)tbs_end) || ((*tbs_ptr != 0x17U) && (*tbs_ptr != 0x18U))) {
            rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
            return rc;
        }
        {
            tbs_ptr = &tbs_ptr[1];
            {
                uint32_t time_len = (uint32_t)(asn1_get_length(&tbs_ptr, tbs_end));
                if((time_len == 0U) || (x509_bytes_remaining(tbs_ptr, tbs_end) < (size_t)time_len)) {
                    rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
                    return rc;
                }
                noxtls_secure_zero((crl->this_update), sizeof(crl->this_update));
                {
                    uint32_t copy_len = (uint32_t)((time_len > 15U) ? 15U : time_len);
                    noxtls_copy_u8((uint8_t *)(void *)(crl->this_update), (size_t)copy_len, (const uint8_t *)(const void *)(tbs_ptr), (size_t)copy_len);
                    crl->this_update[14] = 0U;
                }
                tbs_ptr = &tbs_ptr[time_len];
            }
        }

        /* optional nextUpdate */
        crl->has_next_update = 0U;
        noxtls_secure_zero((crl->next_update), sizeof(crl->next_update));
        if(((uintptr_t)tbs_ptr < (uintptr_t)tbs_end) && ((*tbs_ptr == 0x17U) || (*tbs_ptr == 0x18U))) {
            tbs_ptr = &tbs_ptr[1];
            {
                uint32_t time_len = (uint32_t)(asn1_get_length(&tbs_ptr, tbs_end));
                if((time_len == 0U) || (x509_bytes_remaining(tbs_ptr, tbs_end) < (size_t)time_len)) {
                    rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
                    return rc;
                }
                {
                    uint32_t copy_len = (uint32_t)((time_len > 15U) ? 15U : time_len);
                    noxtls_copy_u8((uint8_t *)(void *)(crl->next_update), (size_t)copy_len, (const uint8_t *)(const void *)(tbs_ptr), (size_t)copy_len);
                    crl->next_update[14] = 0U;
                }
                crl->has_next_update = 1U;
                tbs_ptr = &tbs_ptr[time_len];
            }
        }

        /* revokedCertificates or crlExtensions */
        if(((uintptr_t)tbs_ptr < (uintptr_t)tbs_end) && (*tbs_ptr == 0x30U)) {
            const uint8_t *save = tbs_ptr;
            const uint8_t *list_body = NULL;
            uint32_t list_len = 0U;
            const uint8_t *list_end = NULL;
            if(asn1_get_sequence(&tbs_ptr, tbs_end, &list_body, &list_len) != NOXTLS_RETURN_SUCCESS) {
                rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
                return rc;
            }
            list_end = &list_body[list_len];
            if(list_len == 0U) {
                /* Empty revokedCertificates SEQUENCE */
            } else if(list_body[0] == 0x30U) {
                const uint8_t *probe = list_body;
                const uint8_t *e0 = NULL;
                uint32_t e0_len = 0U;
                if((asn1_get_sequence(&probe, list_end, &e0, &e0_len) == NOXTLS_RETURN_SUCCESS) && (e0_len > 0U) && (*e0 == 0x02U)) {
                    const uint8_t *walk = list_body;
                    uint32_t cap = NOXTLS_X509_CRL_MAX_REVOKED;
                    crl->revoked_serials = (uint8_t*)NOXTLS_MALLOC((size_t)cap * (size_t)X509_MAX_SERIAL_SIZE);
                    crl->revoked_serial_lens = (uint32_t*)NOXTLS_MALLOC((size_t)cap * sizeof(uint32_t));
                    if((crl->revoked_serials == NULL) || (crl->revoked_serial_lens == NULL)) {
                        rc = NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
                        return rc;
                    }
                    {
                        uint8_t walk_done = 0U;
                        while(((uintptr_t)walk < (uintptr_t)list_end) && (walk_done == 0U)) {
                            const uint8_t *entry = NULL;
                            uint32_t entry_len = 0U;
                            const uint8_t *entry_end = NULL;
                            const uint8_t *ep = NULL;
                            uint8_t serial[X509_MAX_SERIAL_SIZE];
                            uint32_t slen = X509_MAX_SERIAL_SIZE;
                            if(asn1_get_sequence(&walk, list_end, &entry, &entry_len) != NOXTLS_RETURN_SUCCESS) {
                                rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
                                walk_done = 1U;
                            } else {
                                entry_end = &entry[entry_len];
                                ep = entry;
                                slen = X509_MAX_SERIAL_SIZE;
                                if(asn1_get_integer(&ep, entry_end, serial, &slen) != NOXTLS_RETURN_SUCCESS) {
                                    rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
                                    walk_done = 1U;
                                } else if(crl->revoked_count >= cap) {
                                    rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
                                    walk_done = 1U;
                                } else {
                                    noxtls_copy_u8((uint8_t *)(void *)(&crl->revoked_serials[((size_t)crl->revoked_count * (size_t)X509_MAX_SERIAL_SIZE)]), (size_t)slen, (const uint8_t *)(const void *)(serial), (size_t)slen);
                                    if(slen < X509_MAX_SERIAL_SIZE) {
                                        noxtls_secure_zero((&crl->revoked_serials[((size_t)crl->revoked_count * (size_t)X509_MAX_SERIAL_SIZE) + slen]), (size_t)X509_MAX_SERIAL_SIZE - (size_t)slen);
                                    }
                                    crl->revoked_serial_lens[crl->revoked_count] = slen;
                                    crl->revoked_count += 1U;
                                }
                            }
                        }
                    }
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        return rc;
                    }
                } else {
                    tbs_ptr = save;
                }
            } else {
                tbs_ptr = save;
            }
        }

        if(((uintptr_t)tbs_ptr < (uintptr_t)tbs_end) && (*tbs_ptr == (uint8_t)0xA0U)) {
            /* crlExtensions [0] */
            tbs_ptr = &tbs_ptr[1];
            {
                uint32_t ext_len = (uint32_t)(asn1_get_length(&tbs_ptr, tbs_end));
                if(ext_len > (uint32_t)((uintptr_t)tbs_end - (uintptr_t)tbs_ptr)) {
                    rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
                    return rc;
                }
                tbs_ptr = &tbs_ptr[ext_len];
            }
        }

        if(tbs_ptr != tbs_end) {
            rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
            return rc;
        }

        /* Outer signatureAlgorithm + signature */
        {
            const uint8_t *sig_alg_data = NULL;
            uint32_t sig_alg_len = 0U;
            if(asn1_get_sequence(&ptr, cert_list_end, &sig_alg_data, &sig_alg_len) != NOXTLS_RETURN_SUCCESS) {
                rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
                return rc;
            }
        }

        if(asn1_get_tag(&ptr, cert_list_end, 0x03U) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
            return rc;
        }
        {
            uint32_t sig_len = (uint32_t)(asn1_get_length(&ptr, cert_list_end));
            if((sig_len == 0U) || (x509_bytes_remaining(ptr, cert_list_end) < (size_t)sig_len)) {
                rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
                return rc;
            }
            ptr = &ptr[1];
            sig_len -= 1U;
            crl->signature = (uint8_t*)NOXTLS_MALLOC(sig_len);
            if(crl->signature == NULL) {
                rc = NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
                return rc;
            }
            noxtls_copy_u8((uint8_t *)(void *)(crl->signature), (size_t)sig_len, (const uint8_t *)(const void *)(ptr), (size_t)sig_len);
            crl->signature_len = sig_len;
            ptr = &ptr[sig_len];
        }

        if(ptr != cert_list_end) {
            rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
            return rc;
        }

        crl->parsed = 1;
    return rc;
}

noxtls_return_t noxtls_x509_crl_parse_der(noxtls_x509_crl_t *crl, const uint8_t *data, uint32_t len)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if((crl == NULL) || (data == NULL) || (len == 0U)) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_x509_crl_free(crl);

    crl->raw_data = (uint8_t*)NOXTLS_MALLOC(len);
    if(crl->raw_data == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    noxtls_copy_u8((uint8_t *)(void *)(crl->raw_data), (size_t)len, (const uint8_t *)(const void *)(data), (size_t)len);
    crl->raw_data_len = len;

    rc = x509_crl_parse_der_body(crl);

    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_x509_crl_free(crl);
    }

    return rc;
}

/**
 * @brief Parse a CRL from PEM
 *
 * This function parses a CRL from PEM.
 *
 * @param[in] crl The CRL to parse.
 * @param[in] data The PEM data to parse.
 * @param[in] len The length of the PEM data.
 *
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_crl_parse_pem(noxtls_x509_crl_t *crl, const uint8_t *data, uint32_t len)
{
    uint8_t *der = NULL;
    uint32_t der_len = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((crl == NULL) || (data == NULL) || (len == 0U)) {
        return NOXTLS_RETURN_NULL;
    }

    der = (uint8_t*)NOXTLS_MALLOC(len);
    if(der == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    rc = noxtls_x509_crl_pem_to_der(data, len, der, &der_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_free(der);
        return rc;
    }

    rc = noxtls_x509_crl_parse_der(crl, der, der_len);
    (void)noxtls_free(der);
    return rc;
}

/**
 * @brief Load a CRL from a file
 *
 * This function loads a CRL from a file.
 *
 * @param[in] crl The CRL to load.
 * @param[in] filename The name of the file to load the CRL from.
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_crl_load_file(noxtls_x509_crl_t *crl, const uint8_t *filename)
{
#if !NOXTLS_HAVE_FILE_IO
    if((crl == NULL) || (filename == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    (void)crl;
    (void)filename;
    return NOXTLS_RETURN_FAILED;
#else
    FILE *fp;
    uint8_t *data = NULL;
    uint32_t file_len = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((crl == NULL) || (filename == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    fp = noxtls_x509_fopen(filename, "rb");
    if(fp == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    errno = 0;
    if(fseek(fp, 0, SEEK_END) != 0) {
        (void)fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }
    {
        long ftell_len = 0;
        errno = 0;
        ftell_len = ftell(fp);
        if(errno != 0) {
            (void)fclose(fp);
            return NOXTLS_RETURN_FAILED;
        }
        if(ftell_len < 0) {
            (void)fclose(fp);
            return NOXTLS_RETURN_FAILED;
        }
        file_len = (uint32_t)ftell_len;
    }
    errno = 0;
    if(fseek(fp, 0, SEEK_SET) != 0) {
        (void)fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }

    if((file_len == 0U) || (file_len > X509_MAX_CRL_SIZE)) {
        (void)fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }

    data = (uint8_t*)NOXTLS_MALLOC(file_len);
    if(data == NULL) {
        (void)fclose(fp);
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    if(fread(data, 1, file_len, fp) != file_len) {
        (void)noxtls_free(data);
        (void)fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }
    (void)fclose(fp);

    rc = noxtls_x509_crl_parse_der(crl, data, file_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_x509_crl_parse_pem(crl, data, file_len);
    }
    (void)noxtls_free(data);
    return rc;
#endif
}

/**
 * @brief Check if a certificate is revoked
 *
 * This function checks if a certificate is revoked.
 *
 * @param[in] crl The CRL to check.
 * @param[in] cert The certificate to check.
 *
 * @return The return code of the function.
 */
int noxtls_x509_crl_serial_is_revoked(const noxtls_x509_crl_t *crl, const x509_certificate_t *cert)
{
    uint32_t i = 0U;
    if((crl == NULL) || (cert == NULL) || (crl->parsed == 0) || (crl->revoked_serials == NULL) || (crl->revoked_serial_lens == NULL)) {
        return 0;
    }
    for(i = 0U; i < crl->revoked_count; i += 1U) {
        const uint8_t *s = &crl->revoked_serials[((size_t)i * (size_t)X509_MAX_SERIAL_SIZE)];
        uint32_t slen = (uint32_t)(crl->revoked_serial_lens[i]);
        if(x509_serial_equal_normalized(s, slen, cert->serial_number, cert->serial_number_len) != 0) {
            return 1;
        }
    }
    return 0;
}

#if NOXTLS_HAVE_TIME

/**
 * @brief Check the times of a CRL
 *
 * This function checks the times of a CRL.
 *
 * @param[in] crl The CRL to check.
 * @param[in] flags_out The flags to check.
 *
 * @return The return code of the function.
 */
static noxtls_return_t noxtls_x509_crl_check_times(const noxtls_x509_crl_t *crl,
                                                   const noxtls_x509_verify_policy_t *policy,
                                                   noxtls_x509_verify_flags_t *flags_out)
{
    noxtls_unix_time_t now;
    noxtls_unix_time_t tu = 0;
    noxtls_unix_time_t nu = 0;
    uint32_t this_len = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(crl == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    /* Judge CRL freshness at the same instant as certificate validity: the explicit
     * verification time when the policy sets one, the system clock otherwise. */
    if((policy != NULL) && (policy->time_mode == NOXTLS_X509_TIME_EXPLICIT)) {
        if(policy->verify_time < 0) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        now = (noxtls_unix_time_t)policy->verify_time;
    } else {
        now = noxtls_time_unix_seconds();
    }

    this_len = 0U;
    while((this_len < 15U) && (crl->this_update[this_len] != 0U)) {
        this_len += 1U;
    }
    rc = noxtls_x509_asn1_noxtls_unix_time_to_timet(crl->this_update, this_len, &tu);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_CRL_PARSE_FAILED;
    }
    if(now < tu) {
        if(flags_out != NULL) {
            *flags_out |= NOXTLS_X509_VERIFY_FLAG_CRL_EXPIRED;
        }
        return NOXTLS_RETURN_CRL_EXPIRED;
    }

    if(crl->has_next_update != 0U) {
        uint32_t next_len = 0U;
        while((next_len < 15U) && (crl->next_update[next_len] != 0U)) {
            next_len += 1U;
        }
        rc = noxtls_x509_asn1_noxtls_unix_time_to_timet(crl->next_update, next_len, &nu);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_CRL_PARSE_FAILED;
        }
        if(now > nu) {
            if(flags_out != NULL) {
                *flags_out |= NOXTLS_X509_VERIFY_FLAG_CRL_EXPIRED;
            }
            return NOXTLS_RETURN_CRL_EXPIRED;
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}
#else

/**
 * @brief Check the times of a CRL
 *
 * This function checks the times of a CRL.
 *
 * @param[in] crl The CRL to check.
 * @param[in] flags_out The flags to check.
 *
 * @return The return code of the function.
 */
static noxtls_return_t noxtls_x509_crl_check_times(const noxtls_x509_crl_t *crl,
                                                   const noxtls_x509_verify_policy_t *policy,
                                                   const noxtls_x509_verify_flags_t *flags_out)
{
    (void)crl;
    (void)policy;
    (void)flags_out;
    return NOXTLS_RETURN_SUCCESS;
}
#endif

/**
 * @brief Verify the signature of a CRL
 *
 * This function verifies the signature of a CRL.
 *
 * @param[in] crl The CRL to verify.
 * @param[in] issuer The issuer of the CRL.
 * @param[in] flags_out The flags to verify.
 *
 * @return The return code of the function.
 */
static noxtls_return_t noxtls_x509_crl_verify_signature(const noxtls_x509_crl_t *crl, const x509_certificate_t *issuer,
                                                        noxtls_x509_verify_flags_t *flags_out)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    noxtls_hash_algos_t hash_algo = NOXTLS_HASH_SHA_256;
    int is_rsa = 0;

    if((crl == NULL) || (issuer == NULL) || (crl->parsed == 0) || (issuer->parsed == 0)) {
        return NOXTLS_RETURN_NULL;
    }
    if((crl->tbs_crl == NULL) || (crl->tbs_crl_len == 0U) || (crl->signature == NULL) || (crl->signature_len == 0U)) {
        return NOXTLS_RETURN_CRL_VERIFY_FAILED;
    }
    if((issuer->key_usage_bits != 0U) &&
       ((issuer->key_usage_bits & X509_KEY_USAGE_CRL_SIGN) == 0U)) {
        if(flags_out != NULL) {
            *flags_out |= NOXTLS_X509_VERIFY_FLAG_CRL_BAD_SIGNATURE;
        }
        return NOXTLS_RETURN_CRL_VERIFY_FAILED;
    }

    rc = noxtls_x509_map_signature_algorithm(crl->signature_algorithm_oid, crl->signature_algorithm_oid_len, &hash_algo, &is_rsa);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }

    if((hash_algo != NOXTLS_HASH_SHA_256) && (hash_algo != NOXTLS_HASH_SHA_384) &&
       (hash_algo != NOXTLS_HASH_SHA_512)) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }

    if(is_rsa == 1) {
        if((issuer->rsa_modulus == NULL) || (issuer->rsa_exponent == NULL)) {
            if(flags_out != NULL) {
                *flags_out |= NOXTLS_X509_VERIFY_FLAG_CRL_BAD_SIGNATURE;
            }
            return NOXTLS_RETURN_CRL_VERIFY_FAILED;
        }
        {
            const uint8_t *mod_ptr = issuer->rsa_modulus;
            uint32_t mod_len = (uint32_t)(issuer->rsa_modulus_len);
            const uint8_t *exp_ptr = issuer->rsa_exponent;
            uint32_t exp_len = (uint32_t)(issuer->rsa_exponent_len);
            uint32_t key_bytes = 0U;
            rsa_key_size_t key_size = RSA_2048_BIT;
            rsa_key_t rsa_key;
            while((mod_len > 0U) && (mod_ptr[0] == 0U)) {
                mod_ptr = &mod_ptr[1];
                mod_len -= 1U;
            }
            while((exp_len > 0U) && (exp_ptr[0] == 0U)) {
                exp_ptr = &exp_ptr[1];
                exp_len -= 1U;
            }
            key_bytes = mod_len;
            if(key_bytes == X509_RSA_MODULUS_BYTES_1024) {
                key_size = RSA_1024_BIT;
            } else if(key_bytes == X509_RSA_MODULUS_BYTES_2048) {
                key_size = RSA_2048_BIT;
            } else if(key_bytes == X509_RSA_MODULUS_BYTES_3072) {
                key_size = RSA_3072_BIT;
            } else if(key_bytes == X509_RSA_MODULUS_BYTES_4096) {
                key_size = RSA_4096_BIT;
            } else {
                /* MISRA 15.7: final else path */
                return NOXTLS_RETURN_INVALID_PARAM;
            }
            rc = noxtls_rsa_key_init(&rsa_key, key_size);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            if((mod_len == 0U) || (exp_len == 0U) || (mod_len > rsa_key.key_bytes) || (exp_len > rsa_key.key_bytes)) {
                (void)noxtls_rsa_key_free(&rsa_key);
                return NOXTLS_RETURN_INVALID_PARAM;
            }
            noxtls_copy_u8((uint8_t *)(void *)(&rsa_key.n[rsa_key.key_bytes - mod_len]), (size_t)mod_len, (const uint8_t *)(const void *)(mod_ptr), (size_t)mod_len);
            noxtls_copy_u8((uint8_t *)(void *)(&rsa_key.e[(rsa_key.key_bytes - exp_len)]), (size_t)exp_len, (const uint8_t *)(const void *)(exp_ptr), (size_t)exp_len);
            /* PKCS#1 v1.5 verification hashes its message argument internally. */
            rc = noxtls_rsa_verify(&rsa_key, crl->tbs_crl, crl->tbs_crl_len,
                                   crl->signature, crl->signature_len, hash_algo);
            (void)noxtls_rsa_key_free(&rsa_key);
        }
    } else if(is_rsa == 2) {
#if NOXTLS_FEATURE_ML_DSA
        if((issuer->has_mldsa == 0U) || (issuer->mldsa_public_key_len == 0U) || (issuer->mldsa_param == 0U)) {
            if(flags_out != NULL) {
                *flags_out |= NOXTLS_X509_VERIFY_FLAG_CRL_BAD_SIGNATURE;
            }
            return NOXTLS_RETURN_CRL_VERIFY_FAILED;
        }
        rc = noxtls_mldsa_verify(issuer->mldsa_param, issuer->mldsa_public_key,
                                 crl->tbs_crl, crl->tbs_crl_len,
                                 crl->signature, crl->signature_len);
#else
        return NOXTLS_RETURN_INVALID_ALGORITHM;
#endif
    } else {
        ecc_curve_t curve_type = NOXTLS_ECC_SECP256R1;
        ecc_key_t ecc_key;
        const uint8_t *sig_ptr = crl->signature;
        const uint8_t *sig_end = &crl->signature[crl->signature_len];
        const uint8_t *seq_data = NULL;
        uint32_t seq_len = 0U;
        uint8_t r[ECC_MAX_KEY_SIZE];
        uint8_t s[ECC_MAX_KEY_SIZE];
        uint32_t r_len = ECC_MAX_KEY_SIZE;
        uint32_t s_len = ECC_MAX_KEY_SIZE;
        ecdsa_signature_t ecdsa_sig;

        if((issuer->ecc_public_key == NULL) || (issuer->ecc_public_key_len == 0U)) {
            if(flags_out != NULL) {
                *flags_out |= NOXTLS_X509_VERIFY_FLAG_CRL_BAD_SIGNATURE;
            }
            return NOXTLS_RETURN_CRL_VERIFY_FAILED;
        }
        if(issuer->ecc_curve_oid_len > 0U) {
            if(noxtls_x509_ecc_curve_from_oid(issuer->ecc_curve_oid, issuer->ecc_curve_oid_len, &curve_type) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_INVALID_ALGORITHM;
            }
        } else {
            /* MISRA 15.7: final else path */
            if(noxtls_x509_ecc_curve_from_pubkey_len(issuer->ecc_public_key_len, &curve_type) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_INVALID_ALGORITHM;
            }
        }
        rc = noxtls_ecc_key_init(&ecc_key, curve_type);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if(issuer->ecc_public_key[0] != 0x04U) {
            (void)noxtls_ecc_key_free(&ecc_key);
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        {
            uint32_t coord_size = (uint32_t)(ecc_key.curve->size);
            if(issuer->ecc_public_key_len != (1U + (2U * coord_size))) {
                (void)noxtls_ecc_key_free(&ecc_key);
                return NOXTLS_RETURN_INVALID_PARAM;
            }
            noxtls_copy_u8((uint8_t *)(void *)(ecc_key.Q.x), (size_t)coord_size, (const uint8_t *)(const void *)(&issuer->ecc_public_key[1]), (size_t)coord_size);
            noxtls_copy_u8((uint8_t *)(void *)(ecc_key.Q.y), (size_t)coord_size, (const uint8_t *)(const void *)(&issuer->ecc_public_key[1U + coord_size]), (size_t)coord_size);
            ecc_key.Q.size = coord_size;
            if(noxtls_ecc_point_validate_public(&ecc_key.Q, ecc_key.curve) != NOXTLS_RETURN_SUCCESS) {
                (void)noxtls_ecc_key_free(&ecc_key);
                return NOXTLS_RETURN_INVALID_PARAM;
            }
        }

        if(asn1_get_tag(&sig_ptr, sig_end, 0x30U) != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_ecc_key_free(&ecc_key);
            return NOXTLS_RETURN_BAD_DATA;
        }
        seq_len = asn1_get_length(&sig_ptr, sig_end);
        if((seq_len == 0U) || (x509_bytes_remaining(sig_ptr, sig_end) < (size_t)seq_len)) {
            (void)noxtls_ecc_key_free(&ecc_key);
            return NOXTLS_RETURN_BAD_DATA;
        }
        seq_data = sig_ptr;
        {
            const uint8_t *seq_end = &seq_data[seq_len];
            if(asn1_get_integer(&sig_ptr, seq_end, r, &r_len) != NOXTLS_RETURN_SUCCESS) {
                (void)noxtls_ecc_key_free(&ecc_key);
                return NOXTLS_RETURN_BAD_DATA;
            }
            if(asn1_get_integer(&sig_ptr, seq_end, s, &s_len) != NOXTLS_RETURN_SUCCESS) {
                (void)noxtls_ecc_key_free(&ecc_key);
                return NOXTLS_RETURN_BAD_DATA;
            }
        }

        ecdsa_sig.size = ecc_key.curve->size;
        noxtls_secure_zero((ecdsa_sig.r), (size_t)ECC_MAX_KEY_SIZE);
        noxtls_secure_zero((ecdsa_sig.s), (size_t)ECC_MAX_KEY_SIZE);
        {
            uint32_t coord_size = (uint32_t)(ecc_key.curve->size);
            if(r_len <= coord_size) {
                noxtls_copy_u8((uint8_t *)(void *)(&ecdsa_sig.r[coord_size - r_len]), (size_t)r_len, (const uint8_t *)(const void *)(r), (size_t)r_len);
            } else {
                uint32_t skip = (uint32_t)(r_len - coord_size);
                uint32_t i = 0U;
                for(i = 0U; i < skip; i += 1U) {
                    if(r[i] != 0U) {
                        (void)noxtls_ecc_key_free(&ecc_key);
                        return NOXTLS_RETURN_BAD_DATA;
                    }
                }
                noxtls_copy_u8((uint8_t *)(void *)(ecdsa_sig.r), (size_t)coord_size, (const uint8_t *)(const void *)(&r[skip]), (size_t)coord_size);
            }
            if(s_len <= coord_size) {
                noxtls_copy_u8((uint8_t *)(void *)(&ecdsa_sig.s[coord_size - s_len]), (size_t)s_len, (const uint8_t *)(const void *)(s), (size_t)s_len);
            } else {
                uint32_t skip = (uint32_t)(s_len - coord_size);
                uint32_t i = 0U;
                for(i = 0U; i < skip; i += 1U) {
                    if(s[i] != 0U) {
                        (void)noxtls_ecc_key_free(&ecc_key);
                        return NOXTLS_RETURN_BAD_DATA;
                    }
                }
                noxtls_copy_u8((uint8_t *)(void *)(ecdsa_sig.s), (size_t)coord_size, (const uint8_t *)(const void *)(&s[skip]), (size_t)coord_size);
            }
        }

        rc = noxtls_ecdsa_verify(&ecc_key, crl->tbs_crl, crl->tbs_crl_len, &ecdsa_sig, hash_algo);
        (void)noxtls_ecc_key_free(&ecc_key);
    }

    if(rc != NOXTLS_RETURN_SUCCESS) {
        if(flags_out != NULL) {
            *flags_out |= NOXTLS_X509_VERIFY_FLAG_CRL_BAD_SIGNATURE;
        }
        return NOXTLS_RETURN_CRL_VERIFY_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Apply a CRL for a certificate
 *
 * This function applies a CRL for a certificate.
 *
 * @param[in] cert The certificate to apply the CRL to.
 * @param[in] issuer The issuer of the CRL.
 * @param[in] crl_chain The CRL chain to apply.
 * @param[in] flags_out The flags to apply.
 *
 * @return The return code of the function.
 */
static noxtls_return_t x509_apply_crl_for_cert(const x509_certificate_t *cert, const x509_certificate_t *issuer,
                                               const noxtls_x509_crl_t *crl_chain,
                                               const noxtls_x509_verify_policy_t *policy,
                                               noxtls_x509_verify_flags_t *flags_out)
{
    const noxtls_x509_crl_t *c;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((cert == NULL) || (issuer == NULL) || (crl_chain == NULL)) {
        return NOXTLS_RETURN_SUCCESS;
    }

    for(c = crl_chain; c != NULL; c = c->next) {
        if(c->parsed == 0) {
            continue;
        }
        if((x509_dn_equal(c->issuer, c->issuer_len, issuer->subject, issuer->subject_len) == 0)) {
            continue;
        }

        if(flags_out != NULL) {
            *flags_out |= NOXTLS_X509_VERIFY_FLAG_CRL_USED;
        }

        rc = noxtls_x509_crl_verify_signature(c, issuer, flags_out);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            cert_fail_set(NOXTLS_RETURN_CRL_VERIFY_FAILED, cert, NULL, 0, 0);
            return NOXTLS_RETURN_CRL_VERIFY_FAILED;
        }

        rc = noxtls_x509_crl_check_times(c, policy, flags_out);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            cert_fail_set(NOXTLS_RETURN_CRL_EXPIRED, cert, NULL, 0, 0);
            return NOXTLS_RETURN_CRL_EXPIRED;
        }

        if(noxtls_x509_crl_serial_is_revoked(c, cert) != 0) {
            if(flags_out != NULL) {
                *flags_out |= NOXTLS_X509_VERIFY_FLAG_CERT_REVOKED;
            }
            cert_fail_set(NOXTLS_RETURN_CERT_REVOKED, cert, NULL, 0, 0);
            return NOXTLS_RETURN_CERT_REVOKED;
        }

        return NOXTLS_RETURN_SUCCESS;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Clear the trust store
 *
 * This function clears the trust store.
 *
 * @return The return code of the function.
 */
void noxtls_x509_trust_store_clear(void)
{
    x509_certificate_chain_t *old = s_x509_trust_anchors;

    /* Unpublish first, then release the snapshot this store owns (see ownership note above). */
    s_x509_trust_anchors = NULL;
    s_x509_trust_anchors_initialized = 0;
    if(old != NULL) {
        (void)noxtls_x509_certificate_chain_free(old);
        (void)noxtls_free(old);
    }
}

/**
 * @brief Check if the trust store has anchors
 *
 * This function checks if the trust store has anchors.
 *
 * @return The return code of the function.
 */
int noxtls_x509_trust_store_has_anchors(void)
{
    const x509_certificate_chain_t *trust_anchors = s_x509_trust_anchors;
    return (((s_x509_trust_anchors_initialized != 0) && (trust_anchors != NULL) && (trust_anchors->count > 0U)) ? 1 : 0);
}

/**
 * @brief Set the trust store
 *
 * This function sets the trust store.
 *
 * @param[in] trust_anchors The trust store to set.
 *
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_trust_store_set(const x509_certificate_chain_t *trust_anchors)
{
    x509_certificate_chain_t *snapshot;

    noxtls_x509_trust_store_clear();

    if((trust_anchors == NULL) || (trust_anchors->count == 0U)) {
        return NOXTLS_RETURN_SUCCESS;
    }

    snapshot = x509_trust_store_clone(trust_anchors);
    if(snapshot == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    s_x509_trust_anchors = snapshot;
    s_x509_trust_anchors_initialized = 1;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Note if a CRL does not match
 *
 * This function notes if a CRL does not match.
 *
 * @param[in] crl The CRL to note.
 * @param[in] flags_out The flags to note.
 * @return The return code of the function.
 */
static void x509_verify_crl_note_no_match_if_needed(const noxtls_x509_crl_t *crl, noxtls_x509_verify_flags_t *flags_out)
{
    if((crl != NULL) && (flags_out != NULL) && ((*flags_out & NOXTLS_X509_VERIFY_FLAG_CRL_USED) == 0U)) {
        *flags_out |= NOXTLS_X509_VERIFY_FLAG_CRL_NO_MATCH;
    }
}


/**
 * @brief Return the published global trust anchors, or NULL when unset.
 * @internal
 *
 * @return Global trust-anchor snapshot or NULL.
 */
static const x509_certificate_chain_t *x509_global_trust_anchors(void)
{
    return (s_x509_trust_anchors_initialized != 0) ? s_x509_trust_anchors : NULL;
}

/**
 * @brief Check a certificate validity window using the policy time source.
 * @internal
 *
 * @param[in] cert Parsed certificate.
 * @param[in] policy Explicit policy, or NULL for the system clock.
 *
 * @return NOXTLS_RETURN_SUCCESS or the validity failure code.
 */
static noxtls_return_t x509_policy_check_validity(const x509_certificate_t *cert,
                                                  const noxtls_x509_verify_policy_t *policy)
{
    noxtls_return_t rc;

    if((policy != NULL) && (policy->time_mode == NOXTLS_X509_TIME_EXPLICIT)) {
        rc = noxtls_x509_certificate_check_validity_at(cert, policy->verify_time);
        if((rc == NOXTLS_RETURN_CERT_EXPIRED) || (rc == NOXTLS_RETURN_CERT_NOT_YET_VALID)) {
            cert_fail_set(rc, cert, NULL, 0, 0);
        }

        return rc;
    }

    return noxtls_x509_certificate_check_validity(cert);
}

/**
 * @brief Apply explicit leaf constraints from a verification policy.
 * @internal
 *
 * RFC 5280 Section 4.2.1.3 (Key Usage), 4.2.1.9 (Basic Constraints) and
 * 4.2.1.12 (Extended Key Usage).
 *
 * @param[in] leaf Parsed leaf certificate.
 * @param[in] policy Explicit policy.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED.
 */
static noxtls_return_t x509_leaf_explicit_policy_check(const x509_certificate_t *leaf,
                                                       const noxtls_x509_verify_policy_t *policy)
{
    uint32_t any_of_key_usage = X509_KEY_USAGE_DIGITAL_SIGNATURE;

    if(leaf->basic_constraints_ca == 1) {
        cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED, leaf, NULL, 0, 0);
        return NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED;
    }

    if((policy->required_eku != 0U) && (leaf->ext_key_usage_bits != 0U) &&
       ((leaf->ext_key_usage_bits & (policy->required_eku | X509_EKU_ANY)) == 0U)) {
        cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED, leaf, NULL, 0, 0);
        return NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED;
    }

    if(leaf->key_usage_bits == 0U) {
        if(policy->require_key_usage_extension != 0U) {
            cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED, leaf, NULL, 0, 0);
            return NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED;
        }

        return NOXTLS_RETURN_SUCCESS;
    }

    if(policy->required_key_usage != 0U) {
        if((leaf->key_usage_bits & policy->required_key_usage) != policy->required_key_usage) {
            cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED, leaf, NULL, 0, 0);
            return NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED;
        }

        return NOXTLS_RETURN_SUCCESS;
    }

    if(policy->required_eku == X509_EKU_SERVER_AUTH) {
        any_of_key_usage |= X509_KEY_USAGE_KEY_ENCIPHERMENT | X509_KEY_USAGE_KEY_AGREEMENT;
    } else if(policy->required_eku == X509_EKU_CLIENT_AUTH) {
        any_of_key_usage |= X509_KEY_USAGE_KEY_AGREEMENT;
    }

    if((leaf->key_usage_bits & any_of_key_usage) == 0U) {
        cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED, leaf, NULL, 0, 0);
        return NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Verify the trust of a certificate
 *
 * Walks from the leaf to a trust anchor (RFC 5280 Section 6.1 subset).
 *
 * @param[in] leaf The leaf certificate to verify.
 * @param[in] presented_chain The presented chain to verify.
 * @param[in] trust_anchors Anchors that terminate the path; NULL or empty fails closed.
 * @param[in] policy Explicit leaf/time policy, or NULL for the purpose defaults.
 * @param[in] required_eku The required Extended Key Usage (used when @p policy is NULL).
 * @param[in] crl The CRL to verify.
 * @param[in] flags_out The flags to verify.
 *
 * @return The return code of the function.
 */
static noxtls_return_t x509_verify_cert_trust_internal(const x509_certificate_t *leaf,
                                                       const x509_certificate_chain_t *presented_chain,
                                                       const x509_certificate_chain_t *trust_anchors,
                                                       const noxtls_x509_verify_policy_t *policy,
                                                       uint32_t required_eku,
                                                       const noxtls_x509_crl_t *crl,
                                                       noxtls_x509_verify_flags_t *flags_out)
{
    const x509_certificate_t *current = NULL;
    uint32_t depth = 0U;
    const uint32_t max_depth = NOXTLS_MAX_CERT_CHAIN_DEPTH;

    if(flags_out != NULL) {
        *flags_out = 0;
    }

    if(leaf == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(max_depth == 0U) {
        cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED, leaf, NULL, 0, 0);
        return NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED;
    }

    if((trust_anchors == NULL) || (trust_anchors->count == 0U)) {
        cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED, leaf, NULL, 0, 0);
        return NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED;
    }

    {
        noxtls_return_t rc = x509_policy_check_validity(leaf, policy);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    if(policy != NULL) {
        if(x509_leaf_explicit_policy_check(leaf, policy) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED;
        }
    } else if(x509_leaf_policy_check(leaf, required_eku) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED;
    }

    current = leaf;

    /*
     * RFC 5280 Section 6.1: trust is established only when a trust anchor's public key
     * verifies the signature of the last certificate in the path. A presented certificate
     * terminates the path by itself only when it is byte-identical (TBSCertificate and
     * signature) to a configured anchor; names and serial numbers are never sufficient.
     */
    while(depth < max_depth) {
        const x509_certificate_t *issuer = NULL;
        int issuer_is_anchor = 0;
        noxtls_return_t rc = NOXTLS_RETURN_FAILED;

        if(x509_chain_contains_cert(trust_anchors, current) != 0) {
            x509_verify_crl_note_no_match_if_needed(crl, flags_out);
            return NOXTLS_RETURN_SUCCESS;
        }

        /* Prefer an anchor whose key verifies current's signature; else a presented issuer. */
        issuer = x509_find_issuer_in_chain(current, trust_anchors);
        if(issuer != NULL) {
            issuer_is_anchor = 1;
        } else if(presented_chain != NULL) {
            issuer = x509_find_issuer_in_chain(current, presented_chain);
        } else {
            /* MISRA 15.7: no presented chain to search */
        }
        if(issuer == NULL) {
            cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED, current, NULL, 0, depth);
            return NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED;
        }

        if(crl != NULL) {
            rc = x509_apply_crl_for_cert(current, issuer, crl, policy, flags_out);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
        }

        rc = x509_policy_check_validity(issuer, policy);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            s_cert_fail_info.cert_index = depth + 1U;
            return rc;
        }

        if(issuer_is_anchor != 0) {
            x509_verify_crl_note_no_match_if_needed(crl, flags_out);
            return NOXTLS_RETURN_SUCCESS;
        }

        rc = x509_issuer_policy_check(issuer, depth);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }

        current = issuer;
        depth += 1U;
    }

    cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED, leaf, NULL, 0, depth);
    return NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED;
}

/**
 * @brief Verify the trust of a server certificate
 *
 * This function verifies the trust of a server certificate.
 *
 * @param[in] leaf The leaf certificate to verify.
 * @param[in] presented_chain The presented chain to verify.
 *
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_verify_server_cert_trust(const x509_certificate_t *leaf,
                                                     const x509_certificate_chain_t *presented_chain)
{
    return x509_verify_cert_trust_internal(leaf, presented_chain, x509_global_trust_anchors(), NULL,
                                           X509_EKU_SERVER_AUTH, NULL, NULL);
}

/**
 * @brief Verify the trust of a server certificate with a CRL
 *
 * This function verifies the trust of a server certificate with a CRL.
 *
 * @param[in] leaf The leaf certificate to verify.
 * @param[in] presented_chain The presented chain to verify.
 * @param[in] crl The CRL to verify.
 * @param[in] flags_out The flags to verify.
 *
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_verify_server_cert_trust_ex(const x509_certificate_t *leaf,
                                                        const x509_certificate_chain_t *presented_chain,
                                                        const noxtls_x509_crl_t *crl,
                                                        noxtls_x509_verify_flags_t *flags_out)
{
    return x509_verify_cert_trust_internal(leaf, presented_chain, x509_global_trust_anchors(), NULL,
                                           X509_EKU_SERVER_AUTH, crl, flags_out);
}

/**
 * @brief Verify the trust of a client certificate
 *
 * This function verifies the trust of a client certificate.
 *
 * @param[in] leaf The leaf certificate to verify.
 * @param[in] presented_chain The presented chain to verify.
 *
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_verify_client_cert_trust(const x509_certificate_t *leaf,
                                                     const x509_certificate_chain_t *presented_chain)
{
    return x509_verify_cert_trust_internal(leaf, presented_chain, x509_global_trust_anchors(), NULL,
                                           X509_EKU_CLIENT_AUTH, NULL, NULL);
}

/**
 * @brief Verify the trust of a client certificate with a CRL
 *
 * This function verifies the trust of a client certificate with a CRL.
 *
 * @param[in] leaf The leaf certificate to verify.
 * @param[in] presented_chain The presented chain to verify.
 * @param[in] crl The CRL to verify.
 * @param[in] flags_out The flags to verify.
 *
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_verify_client_cert_trust_ex(const x509_certificate_t *leaf,
                                                         const x509_certificate_chain_t *presented_chain,
                                                         const noxtls_x509_crl_t *crl,
                                                         noxtls_x509_verify_flags_t *flags_out)
{
    return x509_verify_cert_trust_internal(leaf, presented_chain, x509_global_trust_anchors(), NULL,
                                           X509_EKU_CLIENT_AUTH, crl, flags_out);
}

/**
 * @brief Verify a certificate against an explicit per-call policy.
 *
 * @param[in] leaf The leaf certificate to verify.
 * @param[in] presented_chain Peer-presented intermediates (leaf excluded), or NULL.
 * @param[in] policy Trust anchors and leaf constraints; anchors are required.
 * @param[out] flags_out Optional NOXTLS_X509_VERIFY_FLAG_* bits.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM for an
 *         unknown time mode, or a CERT_* verification failure.
 */
noxtls_return_t noxtls_x509_verify_cert_with_policy(const x509_certificate_t *leaf,
                                                    const x509_certificate_chain_t *presented_chain,
                                                    const noxtls_x509_verify_policy_t *policy,
                                                    noxtls_x509_verify_flags_t *flags_out)
{
    if(flags_out != NULL) {
        *flags_out = 0;
    }

    if((leaf == NULL) || (policy == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if((policy->time_mode != NOXTLS_X509_TIME_SYSTEM) &&
       (policy->time_mode != NOXTLS_X509_TIME_EXPLICIT)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    return x509_verify_cert_trust_internal(leaf, presented_chain, policy->trust_anchors, policy,
                                           policy->required_eku, policy->crl, flags_out);
}

/**
 * @brief Initialize X.509 private key structure
 *
 * This function initializes a X.509 private key structure.
 *
 * @param[in] key The X.509 private key structure to initialize.
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_private_key_init(x509_private_key_t *key)
{
    if(key == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero((key), sizeof(x509_private_key_t));
    key->parsed = 0;
    key->encrypted = 0;

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Free X.509 private key structure
 *
 * This function frees a X.509 private key structure.
 *
 * @param[in] key The X.509 private key structure to free.
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_private_key_free(x509_private_key_t *key)
{
    if(key == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(key->rsa_modulus != NULL) {
        (void)noxtls_free(key->rsa_modulus);
        key->rsa_modulus = NULL;
    }
    if(key->rsa_public_exponent != NULL) {
        (void)noxtls_free(key->rsa_public_exponent);
        key->rsa_public_exponent = NULL;
    }
    if(key->rsa_private_exponent != NULL) {
        (void)noxtls_free(key->rsa_private_exponent);
        key->rsa_private_exponent = NULL;
    }
    if(key->rsa_prime1 != NULL) {
        (void)noxtls_free(key->rsa_prime1);
        key->rsa_prime1 = NULL;
    }
    if(key->rsa_prime2 != NULL) {
        (void)noxtls_free(key->rsa_prime2);
        key->rsa_prime2 = NULL;
    }
    if(key->rsa_exponent1 != NULL) {
        (void)noxtls_free(key->rsa_exponent1);
        key->rsa_exponent1 = NULL;
    }
    if(key->rsa_exponent2 != NULL) {
        (void)noxtls_free(key->rsa_exponent2);
        key->rsa_exponent2 = NULL;
    }
    if(key->rsa_coefficient != NULL) {
        (void)noxtls_free(key->rsa_coefficient);
        key->rsa_coefficient = NULL;
    }
    if(key->ecc_private_key != NULL) {
        (void)noxtls_free(key->ecc_private_key);
        key->ecc_private_key = NULL;
    }
    if(key->ecc_public_key != NULL) {
        (void)noxtls_free(key->ecc_public_key);
        key->ecc_public_key = NULL;
    }
    if(key->eddsa_seed != NULL) {
        (void)noxtls_free(key->eddsa_seed);
        key->eddsa_seed = NULL;
    }
    if(key->pqc_secret_key != NULL) {
        /* Wipe before free - secret material from FIPS 204 / 205. */
        noxtls_secure_zero((key->pqc_secret_key), (size_t)key->pqc_secret_key_len);
        (void)noxtls_free(key->pqc_secret_key);
        key->pqc_secret_key = NULL;
    }
    if(key->raw_data != NULL) {
        (void)noxtls_free(key->raw_data);
        key->raw_data = NULL;
    }

    noxtls_secure_zero((key), sizeof(x509_private_key_t));

    return NOXTLS_RETURN_SUCCESS;
}

/** Number of INTEGER components after the version in RSAPrivateKey (RFC 8017 Appendix A.1.2). */
#define X509_PKCS1_COMPONENT_COUNT 8U
/** n, e and d are mandatory; p, q, dP, dQ and qInv may be absent in tolerated short encodings. */
#define X509_PKCS1_REQUIRED_COMPONENTS 3U

/**
 * @brief Collect pointers to the RSA component buffers / lengths of a private key, in RFC 8017 order.
 * @internal
 *
 * @param[in] key Private key.
 * @param[out] bufs Component buffer slots.
 * @param[out] lens Component length slots.
 */
static void x509_pkcs1_component_slots(x509_private_key_t *key, uint8_t **bufs[X509_PKCS1_COMPONENT_COUNT],
                                       uint32_t *lens[X509_PKCS1_COMPONENT_COUNT])
{
    bufs[0] = &key->rsa_modulus;          lens[0] = &key->rsa_modulus_len;
    bufs[1] = &key->rsa_public_exponent;  lens[1] = &key->rsa_public_exponent_len;
    bufs[2] = &key->rsa_private_exponent; lens[2] = &key->rsa_private_exponent_len;
    bufs[3] = &key->rsa_prime1;           lens[3] = &key->rsa_prime1_len;
    bufs[4] = &key->rsa_prime2;           lens[4] = &key->rsa_prime2_len;
    bufs[5] = &key->rsa_exponent1;        lens[5] = &key->rsa_exponent1_len;
    bufs[6] = &key->rsa_exponent2;        lens[6] = &key->rsa_exponent2_len;
    bufs[7] = &key->rsa_coefficient;      lens[7] = &key->rsa_coefficient_len;
}

/**
 * @brief Wipe and free every RSA component of a private key and clear its length.
 * @internal
 *
 * @param[in,out] key Private key.
 */
static void x509_pkcs1_release_components(x509_private_key_t *key)
{
    uint8_t **bufs[X509_PKCS1_COMPONENT_COUNT];
    uint32_t *lens[X509_PKCS1_COMPONENT_COUNT];
    uint32_t i = 0U;

    x509_pkcs1_component_slots(key, bufs, lens);
    for(i = 0U; i < X509_PKCS1_COMPONENT_COUNT; i += 1U) {
        if(*bufs[i] != NULL) {
            noxtls_secure_zero(*bufs[i], (size_t)(*lens[i]));
            (void)noxtls_free(*bufs[i]);
            *bufs[i] = NULL;
        }
        *lens[i] = 0U;
    }
}

/**
 * @brief Read one RSAPrivateKey INTEGER into a freshly allocated buffer.
 * @internal
 *
 * @param[in,out] cursor Parse cursor; advanced past the INTEGER only on success.
 * @param[in] end End of the RSAPrivateKey SEQUENCE content.
 * @param[out] out Allocated component (owned by the caller on success).
 * @param[out] out_len Component length.
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_FAILED when the next element is not a valid
 *         INTEGER, or NOXTLS_RETURN_NOT_ENOUGH_MEMORY when the allocation fails.
 */
static noxtls_return_t x509_pkcs1_read_component(const uint8_t **cursor, const uint8_t *end,
                                                 uint8_t **out, uint32_t *out_len)
{
    const uint8_t *probe = *cursor;
    uint32_t len = 0U;
    uint32_t got = 0U;
    uint8_t *buf = NULL;

    if(asn1_get_integer(&probe, end, NULL, &len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    buf = (uint8_t *)NOXTLS_MALLOC(len);
    if(buf == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    probe = *cursor;
    got = len;
    if(asn1_get_integer(&probe, end, buf, &got) != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_free(buf);
        return NOXTLS_RETURN_FAILED;
    }
    *cursor = probe;
    *out = buf;
    *out_len = got;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Parse PKCS#1 RSA Private Key (DER format)
 *
 * This function parses a PKCS#1 RSA private key (DER format). It either succeeds with every
 * mandatory component (n, e, d) allocated, or fails with no RSA component left allocated and
 * key->key_type / key->format unchanged. An allocation failure is reported as
 * NOXTLS_RETURN_NOT_ENOUGH_MEMORY (never as success with missing components).
 *
 * @param[in] key The X.509 private key structure to parse.
 * @param[in] data The DER data to parse.
 * @param[in] len The length of the DER data.
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_FAILED (not PKCS#1) or NOXTLS_RETURN_NOT_ENOUGH_MEMORY.
 */
static noxtls_return_t noxtls_x509_parse_pkcs1_rsa_private_key(x509_private_key_t *key, const uint8_t *data, uint32_t len)
{
    const uint8_t *ptr = data;
    const uint8_t *end = &data[len];
    const uint8_t *seq_data = NULL;
    uint32_t seq_len = 0U;
    uint8_t **bufs[X509_PKCS1_COMPONENT_COUNT];
    uint32_t *lens[X509_PKCS1_COMPONENT_COUNT];
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if(asn1_get_sequence(&ptr, end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    const uint8_t *seq_end = &seq_data[seq_len];
    const uint8_t *seq_ptr = seq_data;

    /* Parse version (should be 0) */
    if(asn1_get_integer(&seq_ptr, seq_end, NULL, &seq_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Start from a clean slate so a failure can release exactly what this call allocated. */
    x509_pkcs1_release_components(key);
    x509_pkcs1_component_slots(key, bufs, lens);

    /* Each component is probed before allocation, so a non-RSA structure (e.g. PKCS#8 EC whose next
     * tag is an OCTET STRING) is rejected without touching the allocator. */
    for(i = 0U; i < X509_PKCS1_COMPONENT_COUNT; i += 1U) {
        rc = x509_pkcs1_read_component(&seq_ptr, seq_end, bufs[i], lens[i]);
        if(rc == NOXTLS_RETURN_NOT_ENOUGH_MEMORY) {
            break;
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(i >= X509_PKCS1_REQUIRED_COMPONENTS) {
                rc = NOXTLS_RETURN_SUCCESS;  /* optional CRT components absent */
            }
            break;
        }
    }

    if(rc != NOXTLS_RETURN_SUCCESS) {
        x509_pkcs1_release_components(key);
        return rc;
    }

    key->key_type = X509_PRIVATE_KEY_RSA;
    key->format = X509_PRIVATE_KEY_FORMAT_PKCS1;
    return NOXTLS_RETURN_SUCCESS;
}

/* Forward declaration (defined below). */
static noxtls_return_t noxtls_x509_parse_sec1_ecc_private_key(x509_private_key_t *key, const uint8_t *data, uint32_t len);

#if NOXTLS_FEATURE_ED25519 || (NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3)
/** PKCS#8 PrivateKey OCTET STRING: raw seed or OCTET STRING-wrapped seed (RFC 8410). */
/**
 * @brief Parse PKCS#8 PrivateKey OCTET STRING: raw seed or OCTET STRING-wrapped seed (RFC 8410)
 *
 * This function parses a PKCS#8 PrivateKey OCTET STRING: raw seed or OCTET STRING-wrapped seed (RFC 8410).
 *
 * @param[in] content The content to parse.
 * @param[in] content_len The length of the content.
 * @param[in] want_len The length of the seed to want.
 * @param[out] seed_out The seed out.
 * @param[out] seed_len_out The length of the seed out.
 *
 * @return The return code of the function.
 */
static noxtls_return_t x509_pkcs8_ed_seed_from_octet(const uint8_t *content, uint32_t content_len,
    uint32_t want_len, const uint8_t **seed_out, uint32_t *seed_len_out)
{
    const uint8_t *p = content;
    const uint8_t *end = &content[content_len];

    if((seed_out == NULL) || (seed_len_out == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(content_len == want_len) {
        *seed_out = content;
        *seed_len_out = want_len;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(asn1_get_tag(&p, end, 0x04U) == NOXTLS_RETURN_SUCCESS) {
        uint32_t inner = (uint32_t)(asn1_get_length(&p, end));
        if((inner == want_len) && (x509_bytes_remaining(p, end) >= (size_t)inner)) {
            *seed_out = p;
            *seed_len_out = inner;
            return NOXTLS_RETURN_SUCCESS;
        }
    }
    return NOXTLS_RETURN_FAILED;
}
#endif

#if NOXTLS_FEATURE_ED25519
/**
 * @brief Check if an OID is Ed25519
 *
 * This function checks if an OID is Ed25519.
 *
 * @param[in] o The OID to check.
 * @param[in] l The length of the OID.
 *
 * @return The return code of the function.
 */
static int x509_oid_is_ed25519(const uint8_t *o, uint32_t l)
{
    static const uint8_t id_ed25519[] = { 0x2BU, 0x65U, 0x70U };
    { int oid_eq = 0; if(l == (uint32_t)(sizeof(id_ed25519))) { oid_eq = (noxtls_ct_memcmp(o, id_ed25519, (size_t)(sizeof(id_ed25519))) == 0) ? 1 : 0; } return oid_eq; }
}
#endif
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
/**
 * @brief Check if an OID is Ed448
 *
 * This function checks if an OID is Ed448.
 *
 * @param[in] o The OID to check.
 * @param[in] l The length of the OID.
 *
 * @return The return code of the function.
 */
static int x509_oid_is_ed448(const uint8_t *o, uint32_t l)
{
    static const uint8_t id_ed448[] = { 0x2BU, 0x65U, 0x71U };
    { int oid_eq = 0; if(l == (uint32_t)(sizeof(id_ed448))) { oid_eq = (noxtls_ct_memcmp(o, id_ed448, (size_t)(sizeof(id_ed448))) == 0) ? 1 : 0; } return oid_eq; }
}
#endif

#if NOXTLS_FEATURE_ML_DSA
/**
 * @brief Check if an OID is ML-DSA
 *
 * This function checks if an OID is ML-DSA.
 *
 * @param[in] o The OID to check.
 * @param[in] l The length of the OID.
 *
 * @return The return code of the function.
 *
 * Detect id-ml-dsa-* OIDs (NIST CSOR 2.16.840.1.101.3.4.3.{17,18,19}).
 * Returns 0 on no match, else the noxtls_mldsa_param_t value (1, 2 or 3).
 */
static int x509_oid_is_mldsa(const uint8_t *o, uint32_t l)
{
    /* DER prefix for 2.16.840.1.101.3.4.3 (id-NIST-sigAlgs-experiments root for FIPS204). */
    static const uint8_t prefix[] = { 0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x03U };
    if((size_t)(l) != (sizeof(prefix) + 1U)) {
        return 0;
    }
    if(noxtls_ct_memcmp(o, prefix, sizeof(prefix)) != 0) {
        return 0;
    }
    if(o[sizeof(prefix)] == 0x11U) {
        return (int)NOXTLS_MLDSA_44;
    }
    if(o[sizeof(prefix)] == 0x12U) {
        return (int)NOXTLS_MLDSA_65;
    }
    if(o[sizeof(prefix)] == 0x13U) {
        return (int)NOXTLS_MLDSA_87;
    }
    return 0;
}
#endif

#if NOXTLS_FEATURE_SLH_DSA
/**
 * Detect id-slh-dsa-* OIDs (NIST CSOR 2.16.840.1.101.3.4.3.{20..31}).
 * Returns 0 on no match, else the noxtls_slhdsa_param_t value (1..12).
 *
 * @param[in] o The OID to check.
 * @param[in] l The length of the OID.
 *
 * @return The return code of the function.
 */
static int x509_oid_is_slhdsa(const uint8_t *o, uint32_t l)
{
    static const uint8_t prefix[] = { 0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x03U };
    uint8_t arc = 0U;
    if((size_t)(l) != (sizeof(prefix) + 1U)) {
        return 0;
    }
    if(noxtls_ct_memcmp(o, prefix, sizeof(prefix)) != 0) {
        return 0;
    }
    arc = o[sizeof(prefix)];
    if((arc < 0x14U) || (arc > 0x1FU)) {
        return 0;
    }
    /* 0x14 → SHA2-128S (1), 0x15 → SHA2-128F (2), ... matches noxtls_slhdsa_param_t numbering. */
    return (int)(arc - 0x13U);
}
#endif

#if NOXTLS_FEATURE_FALCON
/*
 * Detect Falcon OIDs under 1.3.9999.3.{6,7}
 *  - 1.3.9999.3.6 -> Falcon-512
 *  - 1.3.9999.3.7 -> Falcon-1024
 * Returns 0 on no match, else noxtls_falcon_param_t value.
 */

/**
 * @brief Check if an OID is Falcon
 * 
 * @param[in] o The OID to check.
 * @param[in] l The length of the OID.
 * 
 * @return The return code of the function.
 */
static int x509_oid_is_falcon(const uint8_t *o, uint32_t l)
{
    static const uint8_t oid_falcon512[] = { 0x2BU, 0xCEU, 0x0FU, 0x03U, 0x06U };
    static const uint8_t oid_falcon1024[] = { 0x2BU, 0xCEU, 0x0FU, 0x03U, 0x07U };
    if(o == NULL) {
        return 0;
    }
    if((size_t)(l) == sizeof(oid_falcon512)) {
        if(noxtls_ct_memcmp(o, oid_falcon512, sizeof(oid_falcon512)) == 0) {
            return (int)NOXTLS_FALCON_512;
        }
    }
    if((size_t)(l) == sizeof(oid_falcon1024)) {
        if(noxtls_ct_memcmp(o, oid_falcon1024, sizeof(oid_falcon1024)) == 0) {
            return (int)NOXTLS_FALCON_1024;
        }
    }
    return 0;
}
#endif

/**
 * @brief Parse PKCS#8 Private Key (DER format)
 *
 * This function parses a PKCS#8 Private Key (DER format).
 *
 * @param[in] key The X.509 private key structure to parse.
 * @param[in] data The DER data to parse.
 * @param[in] len The length of the DER data.
 *
 * @return The return code of the function.
 */
static noxtls_return_t noxtls_x509_parse_pkcs8_private_key(x509_private_key_t *key, const uint8_t *data, uint32_t len)
{
    const uint8_t *ptr = data;
    const uint8_t *end = &data[len];
    const uint8_t *seq_data = NULL;
    uint32_t seq_len = 0U;
    uint8_t version_buf[1] = { 0U };
    uint32_t version_len = (uint32_t)sizeof(version_buf);
    uint8_t version = 0U;
    uint8_t pkcs8_algorithm_oid[32];
    uint32_t pkcs8_algorithm_oid_len = 0U;
    /* id-ecPublicKey namedCurve from the AlgorithmIdentifier (RFC 5915 Section 3 / RFC 5480). */
    uint8_t alg_curve_oid[32];
    uint32_t alg_curve_oid_len = 0U;

    /* Parse PrivateKeyInfo SEQUENCE */
    if(asn1_get_sequence(&ptr, end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    const uint8_t *info_end = &seq_data[seq_len];
    const uint8_t *info_ptr = seq_data;

    /* Parse version: a one-byte INTEGER; capacity is the size of version_buf, never the input length. */
    if(asn1_get_integer(&info_ptr, info_end, version_buf, &version_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(version_len != 1U) {
        return NOXTLS_RETURN_FAILED;
    }
    version = version_buf[0];

    /* RFC 5208: version 0. Some exporters use version 1 for OneAsymmetricKey. Accept both. */
    if((version != 0U) && (version != 1U)) {
        key->encrypted = 1;
        return NOXTLS_RETURN_FAILED;
    }

    /* version 1 followed directly by an OCTET STRING is an RFC 5915 ECPrivateKey (SEC1), not PKCS#8. */
    if((version == 1U) && ((uintptr_t)info_ptr < (uintptr_t)info_end) && (*info_ptr == 0x04U)) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Standard PKCS#8 order: algorithm then privateKey. Some encodings use: privateKey then [0] curve then [1] public. */
    const uint8_t *alg_end = NULL;
    const uint8_t *alg_ptr = NULL;
    uint32_t private_key_len = 0U;

    if(((uintptr_t)info_ptr >= (uintptr_t)info_end)) {
        return NOXTLS_RETURN_FAILED;
    }

    if(*info_ptr == 0x04U) {
        /* Alternate order: privateKey (OCTET STRING) comes first, then [0] curve OID, then [1] public (optional) */
        CERT_DEBUG_PRINT("x509_parse_pkcs8: alternate order (privateKey before algorithm)\n");
        if(asn1_get_tag(&info_ptr, info_end, 0x04U) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        private_key_len = asn1_get_length(&info_ptr, info_end);
        if((private_key_len == 0U) || (x509_bytes_remaining(info_ptr, info_end) < (size_t)private_key_len)) {
            return NOXTLS_RETURN_FAILED;
        }
        /* info_ptr now points to the key bytes. Curve OID is in the next [0] IMPLICIT. */
        alg_ptr = &info_ptr[private_key_len];
        alg_end = info_end;  /* rest of SEQUENCE for [0] and [1] */
    } else {
        /* Standard order: AlgorithmIdentifier SEQUENCE then PrivateKey OCTET STRING */
        if(asn1_get_sequence(&info_ptr, info_end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
            CERT_DEBUG_PRINT("x509_parse_pkcs8: no AlgorithmIdentifier SEQUENCE (first_byte=0x%02x)\n", ((uintptr_t)info_ptr < (uintptr_t)info_end) ? *info_ptr : 0);
            return NOXTLS_RETURN_FAILED;
        }
        alg_end = &seq_data[seq_len];
        alg_ptr = seq_data;
        if(asn1_get_oid(&alg_ptr, alg_end, pkcs8_algorithm_oid, &pkcs8_algorithm_oid_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        if(((uintptr_t)alg_ptr < (uintptr_t)alg_end) && (*alg_ptr == 0x06U)) {
            const uint8_t *curve_ptr = alg_ptr;
            if(asn1_get_oid(&curve_ptr, alg_end, alg_curve_oid, &alg_curve_oid_len) != NOXTLS_RETURN_SUCCESS) {
                alg_curve_oid_len = 0U;
            }
        }
        if(asn1_get_tag(&info_ptr, info_end, 0x04U) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        private_key_len = asn1_get_length(&info_ptr, info_end);
    }
    if((private_key_len == 0U) || (x509_bytes_remaining(info_ptr, info_end) < (size_t)private_key_len)) {
        CERT_DEBUG_PRINT("x509_parse_pkcs8: bad privateKey length or overflow\n");
        return NOXTLS_RETURN_FAILED;
    }

    CERT_DEBUG_PRINT("x509_parse_pkcs8: privateKey len=%u first_byte=0x%02x (0x30=SEC1, else raw EC)\n",
        private_key_len, info_ptr[0]);

    /* Parse the inner private key structure (OCTET STRING content is PKCS#1 RSA or SEC1 ECPrivateKey or raw EC bytes) */
    noxtls_return_t rc = noxtls_x509_parse_pkcs1_rsa_private_key(key, info_ptr, private_key_len);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        key->format = X509_PRIVATE_KEY_FORMAT_PKCS8;
        CERT_DEBUG_PRINT("x509_parse_pkcs8: parsed as PKCS#1 RSA\n");
        return NOXTLS_RETURN_SUCCESS;
    }
    if(rc == NOXTLS_RETURN_NOT_ENOUGH_MEMORY) {
        return rc;  /* an RSA key that could not be stored must not be retried as another format */
    }

#if NOXTLS_FEATURE_ED25519
    if((pkcs8_algorithm_oid_len > 0U) && (x509_oid_is_ed25519(pkcs8_algorithm_oid, pkcs8_algorithm_oid_len) != 0)) {
        const uint8_t *seed_ptr = NULL;
        uint32_t seed_len = 0U;
        if(x509_pkcs8_ed_seed_from_octet(info_ptr, private_key_len, 32, &seed_ptr, &seed_len) == NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_x509_private_key_free(key);
            key->raw_data = (uint8_t*)NOXTLS_MALLOC(len);
            if(key->raw_data == NULL) {
                return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
            }
            noxtls_copy_u8((uint8_t *)(void *)(key->raw_data), (size_t)len, (const uint8_t *)(const void *)(data), (size_t)len);
            key->raw_data_len = len;
            key->key_type = X509_PRIVATE_KEY_ED25519;
            key->format = X509_PRIVATE_KEY_FORMAT_PKCS8;
            key->eddsa_seed = (uint8_t*)NOXTLS_MALLOC(32);
            if(key->eddsa_seed == NULL) {
                (void)noxtls_x509_private_key_free(key);
                return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
            }
            noxtls_copy_u8((uint8_t *)(void *)(key->eddsa_seed), (size_t)32, (const uint8_t *)(const void *)(seed_ptr), (size_t)32);
            key->eddsa_seed_len = 32U;
            CERT_DEBUG_PRINT("x509_parse_pkcs8: parsed as Ed25519 PKCS#8\n");
            return NOXTLS_RETURN_SUCCESS;
        }
    }
#endif
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
    if((pkcs8_algorithm_oid_len > 0U) && (x509_oid_is_ed448(pkcs8_algorithm_oid, pkcs8_algorithm_oid_len) != 0)) {
        const uint8_t *seed_ptr = NULL;
        uint32_t seed_len = 0U;
        if(x509_pkcs8_ed_seed_from_octet(info_ptr, private_key_len, 57, &seed_ptr, &seed_len) == NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_x509_private_key_free(key);
            key->raw_data = (uint8_t*)NOXTLS_MALLOC(len);
            if(key->raw_data == NULL) {
                return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
            }
            noxtls_copy_u8((uint8_t *)(void *)(key->raw_data), (size_t)len, (const uint8_t *)(const void *)(data), (size_t)len);
            key->raw_data_len = len;
            key->key_type = X509_PRIVATE_KEY_ED448;
            key->format = X509_PRIVATE_KEY_FORMAT_PKCS8;
            key->eddsa_seed = (uint8_t*)NOXTLS_MALLOC(57);
            if(key->eddsa_seed == NULL) {
                (void)noxtls_x509_private_key_free(key);
                return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
            }
            noxtls_copy_u8((uint8_t *)(void *)(key->eddsa_seed), (size_t)57, (const uint8_t *)(const void *)(seed_ptr), (size_t)57);
            key->eddsa_seed_len = 57U;
            CERT_DEBUG_PRINT("x509_parse_pkcs8: parsed as Ed448 PKCS#8\n");
            return NOXTLS_RETURN_SUCCESS;
        }
    }
#endif
#if NOXTLS_FEATURE_ML_DSA
    if(pkcs8_algorithm_oid_len > 0U) {
        int mldsa_param = x509_oid_is_mldsa(pkcs8_algorithm_oid, pkcs8_algorithm_oid_len);
        if(mldsa_param != 0U) {
            /* PKCS#8 OCTET STRING content holds the raw secret key. Some encodings
             * additionally wrap it in another OCTET STRING (draft-ietf-lamps-dilithium-certificates
             * section 5 permits "wrap" + "naked" forms); accept either. */
            const uint8_t *sk_ptr = info_ptr;
            uint32_t sk_len = private_key_len;
            uint32_t expected_sk = noxtls_mldsa_secret_key_len((noxtls_mldsa_param_t)mldsa_param);
            if(expected_sk == 0U) {
                return NOXTLS_RETURN_FAILED;
            }
            if(sk_len != expected_sk) {
                const uint8_t *p = info_ptr;
                if(asn1_get_tag(&p, &info_ptr[private_key_len], 0x04U) == NOXTLS_RETURN_SUCCESS) {
                    uint32_t inner = (uint32_t)(asn1_get_length(&p, &info_ptr[private_key_len]));
                    if((inner == expected_sk) && (x509_bytes_remaining(p, &info_ptr[private_key_len]) >= (size_t)inner)) {
                        sk_ptr = p;
                        sk_len = inner;
                    }
                }
            }
            if(sk_len != expected_sk) {
                CERT_DEBUG_PRINT("x509_parse_pkcs8: ML-DSA secret length mismatch (%u vs %u)\n", sk_len, expected_sk);
                return NOXTLS_RETURN_FAILED;
            }
            (void)noxtls_x509_private_key_free(key);
            key->raw_data = (uint8_t*)NOXTLS_MALLOC(len);
            if(key->raw_data == NULL) {
                return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
            }
            noxtls_copy_u8((uint8_t *)(void *)(key->raw_data), (size_t)len, (const uint8_t *)(const void *)(data), (size_t)len);
            key->raw_data_len = len;
            key->key_type = X509_PRIVATE_KEY_ML_DSA;
            key->format = X509_PRIVATE_KEY_FORMAT_PKCS8;
            key->pqc_param = (uint32_t)mldsa_param;
            key->pqc_secret_key = (uint8_t*)NOXTLS_MALLOC(sk_len);
            if(key->pqc_secret_key == NULL) {
                (void)noxtls_x509_private_key_free(key);
                return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
            }
            noxtls_copy_u8((uint8_t *)(void *)(key->pqc_secret_key), (size_t)sk_len, (const uint8_t *)(const void *)(sk_ptr), (size_t)sk_len);
            key->pqc_secret_key_len = sk_len;
            CERT_DEBUG_PRINT("x509_parse_pkcs8: parsed as ML-DSA PKCS#8 param=%d sk_len=%u\n", mldsa_param, sk_len);
            return NOXTLS_RETURN_SUCCESS;
        }
    }
#endif
#if NOXTLS_FEATURE_SLH_DSA
    if(pkcs8_algorithm_oid_len > 0U) {
        int slhdsa_param = x509_oid_is_slhdsa(pkcs8_algorithm_oid, pkcs8_algorithm_oid_len);
        if(slhdsa_param != 0U) {
            const uint8_t *sk_ptr = info_ptr;
            uint32_t sk_len = private_key_len;
            uint32_t expected_sk = noxtls_slhdsa_secret_key_len((noxtls_slhdsa_param_t)slhdsa_param);
            if(expected_sk == 0U) {
                return NOXTLS_RETURN_FAILED;
            }
            if(sk_len != expected_sk) {
                const uint8_t *p = info_ptr;
                if(asn1_get_tag(&p, &info_ptr[private_key_len], 0x04U) == NOXTLS_RETURN_SUCCESS) {
                    uint32_t inner = (uint32_t)(asn1_get_length(&p, &info_ptr[private_key_len]));
                    if((inner == expected_sk) && (x509_bytes_remaining(p, &info_ptr[private_key_len]) >= (size_t)inner)) {
                        sk_ptr = p;
                        sk_len = inner;
                    }
                }
            }
            if(sk_len != expected_sk) {
                CERT_DEBUG_PRINT("x509_parse_pkcs8: SLH-DSA secret length mismatch (%u vs %u)\n", sk_len, expected_sk);
                return NOXTLS_RETURN_FAILED;
            }
            (void)noxtls_x509_private_key_free(key);
            key->raw_data = (uint8_t*)NOXTLS_MALLOC(len);
            if(key->raw_data == NULL) {
                return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
            }
            noxtls_copy_u8((uint8_t *)(void *)(key->raw_data), (size_t)len, (const uint8_t *)(const void *)(data), (size_t)len);
            key->raw_data_len = len;
            key->key_type = X509_PRIVATE_KEY_SLH_DSA;
            key->format = X509_PRIVATE_KEY_FORMAT_PKCS8;
            key->pqc_param = (uint32_t)slhdsa_param;
            key->pqc_secret_key = (uint8_t*)NOXTLS_MALLOC(sk_len);
            if(key->pqc_secret_key == NULL) {
                (void)noxtls_x509_private_key_free(key);
                return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
            }
            noxtls_copy_u8((uint8_t *)(void *)(key->pqc_secret_key), (size_t)sk_len, (const uint8_t *)(const void *)(sk_ptr), (size_t)sk_len);
            key->pqc_secret_key_len = sk_len;
            CERT_DEBUG_PRINT("x509_parse_pkcs8: parsed as SLH-DSA PKCS#8 param=%d sk_len=%u\n", slhdsa_param, sk_len);
            return NOXTLS_RETURN_SUCCESS;
        }
    }
#endif
#if NOXTLS_FEATURE_FALCON
    if(pkcs8_algorithm_oid_len > 0U) {
        int falcon_param = x509_oid_is_falcon(pkcs8_algorithm_oid, pkcs8_algorithm_oid_len);
        if(falcon_param != 0U) {
            const uint8_t *sk_ptr = info_ptr;
            uint32_t sk_len = private_key_len;
            uint32_t expected_sk = noxtls_falcon_secret_key_len((noxtls_falcon_param_t)falcon_param);
            if(expected_sk == 0U) {
                return NOXTLS_RETURN_FAILED;
            }
            if(sk_len != expected_sk) {
                const uint8_t *p = info_ptr;
                if(asn1_get_tag(&p, &info_ptr[private_key_len], 0x04U) == NOXTLS_RETURN_SUCCESS) {
                    uint32_t inner = (uint32_t)(asn1_get_length(&p, &info_ptr[private_key_len]));
                    if((inner == expected_sk) && (x509_bytes_remaining(p, &info_ptr[private_key_len]) >= (size_t)inner)) {
                        sk_ptr = p;
                        sk_len = inner;
                    }
                }
            }
            if(sk_len != expected_sk) {
                CERT_DEBUG_PRINT("x509_parse_pkcs8: FALCON secret length mismatch (%u vs %u)\n", sk_len, expected_sk);
                return NOXTLS_RETURN_FAILED;
            }
            (void)noxtls_x509_private_key_free(key);
            key->raw_data = (uint8_t*)NOXTLS_MALLOC(len);
            if(key->raw_data == NULL) {
                return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
            }
            noxtls_copy_u8((uint8_t *)(void *)(key->raw_data), (size_t)len, (const uint8_t *)(const void *)(data), (size_t)len);
            key->raw_data_len = len;
            key->key_type = X509_PRIVATE_KEY_FALCON;
            key->format = X509_PRIVATE_KEY_FORMAT_PKCS8;
            key->pqc_param = (uint32_t)falcon_param;
            key->pqc_secret_key = (uint8_t*)NOXTLS_MALLOC(sk_len);
            if(key->pqc_secret_key == NULL) {
                (void)noxtls_x509_private_key_free(key);
                return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
            }
            noxtls_copy_u8((uint8_t *)(void *)(key->pqc_secret_key), (size_t)sk_len, (const uint8_t *)(const void *)(sk_ptr), (size_t)sk_len);
            key->pqc_secret_key_len = sk_len;
            CERT_DEBUG_PRINT("x509_parse_pkcs8: parsed as FALCON PKCS#8 param=%d sk_len=%u\n", falcon_param, sk_len);
            return NOXTLS_RETURN_SUCCESS;
        }
    }
#endif

    /* Try SEC1 ECC (OCTET STRING content is DER ECPrivateKey, starts with 0x30) */
    if(info_ptr[0] == 0x30U) {
        (void)noxtls_x509_private_key_free(key);
        key->raw_data = (uint8_t*)NOXTLS_MALLOC(len);
        if(key->raw_data == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        noxtls_copy_u8((uint8_t *)(void *)(key->raw_data), (size_t)len, (const uint8_t *)(const void *)(data), (size_t)len);
        key->raw_data_len = len;
        rc = noxtls_x509_parse_sec1_ecc_private_key(key, info_ptr, private_key_len);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            key->format = X509_PRIVATE_KEY_FORMAT_PKCS8;
            /* RFC 5915 Section 3: the inner parameters are usually omitted inside PKCS#8. */
            if((key->ecc_curve_oid_len == 0U) && (alg_curve_oid_len > 0U)) {
                noxtls_copy_u8(key->ecc_curve_oid, sizeof(key->ecc_curve_oid), alg_curve_oid, (size_t)alg_curve_oid_len);
                key->ecc_curve_oid_len = alg_curve_oid_len;
            }
            CERT_DEBUG_PRINT("x509_parse_pkcs8: parsed as SEC1 ECC\n");
            return NOXTLS_RETURN_SUCCESS;
        }
        if(rc == NOXTLS_RETURN_NOT_ENOUGH_MEMORY) {
            (void)noxtls_x509_private_key_free(key);
            return rc;
        }
        CERT_DEBUG_PRINT("x509_parse_pkcs8: SEC1 ECC parse failed\n");
    } else {
        /* PKCS#8 EC with raw private key octets (no SEC1 wrapper). Curve OID in [0] params or in algorithm. */
        const uint8_t *params_ptr = alg_ptr;
        const uint8_t *params_end = (alg_end != NULL) ? alg_end : info_end;
        if((((uintptr_t)params_ptr < (uintptr_t)params_end)) && ((*params_ptr & 0xE0U) == 0xA0U)) {
            params_ptr = &params_ptr[1];
            uint32_t params_len = (uint32_t)(asn1_get_length(&params_ptr, params_end));
            CERT_DEBUG_PRINT("x509_parse_pkcs8: [0] params_len=%u\n", params_len);
            if((params_len > 0U) && (x509_bytes_remaining(params_ptr, params_end) >= (size_t)params_len)) {
                uint8_t curve_oid[32];
                uint32_t curve_oid_len = 0U;
                const uint8_t *oid_end = &params_ptr[params_len];
                if(asn1_get_oid(&params_ptr, oid_end, curve_oid, &curve_oid_len) == NOXTLS_RETURN_SUCCESS) {
                    if(curve_oid_len <= 32U) {
                        (void)noxtls_x509_private_key_free(key);
                        key->raw_data = (uint8_t*)NOXTLS_MALLOC(len);
                        if(key->raw_data == NULL) {
                            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
                        }
                        noxtls_copy_u8((uint8_t *)(void *)(key->raw_data), (size_t)len, (const uint8_t *)(const void *)(data), (size_t)len);
                        key->raw_data_len = len;
                        key->key_type = X509_PRIVATE_KEY_ECC;
                        key->format = X509_PRIVATE_KEY_FORMAT_PKCS8;
                        key->ecc_curve_oid_len = curve_oid_len;
                        noxtls_copy_u8((uint8_t *)(void *)(key->ecc_curve_oid), (size_t)curve_oid_len, (const uint8_t *)(const void *)(curve_oid), (size_t)curve_oid_len);
                        key->ecc_private_key = (uint8_t*)NOXTLS_MALLOC(private_key_len);
                        if(key->ecc_private_key == NULL) {
                            (void)noxtls_x509_private_key_free(key);
                            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
                        }
                        key->ecc_private_key_len = private_key_len;
                        noxtls_copy_u8((uint8_t *)(void *)(key->ecc_private_key), (size_t)private_key_len, (const uint8_t *)(const void *)(info_ptr), (size_t)private_key_len);
                        CERT_DEBUG_PRINT("x509_parse_pkcs8: parsed as raw EC key curve_oid_len=%u\n", curve_oid_len);
                        return NOXTLS_RETURN_SUCCESS;
                    }
                }
            }
        }
        CERT_DEBUG_PRINT("x509_parse_pkcs8: raw EC path failed (no/missing params)\n");
    }
    return NOXTLS_RETURN_FAILED;
}

/**
 * @brief Parse SEC1 ECC Private Key (DER format)
 *
 * This function parses a SEC1 ECC Private Key (DER format).
 *
 * @param[in] key The X.509 private key structure to parse.
 * @param[in] data The DER data to parse.
 * @param[in] len The length of the DER data.
 * @return The return code of the function.
 */
static noxtls_return_t noxtls_x509_parse_sec1_ecc_private_key(x509_private_key_t *key, const uint8_t *data, uint32_t len)
{
    /*
     * RFC 5915 Section 3:
     * ECPrivateKey ::= SEQUENCE { version INTEGER { ecPrivkeyVer1(1) }, privateKey OCTET STRING,
     *                             parameters [0] ECParameters OPTIONAL, publicKey [1] BIT STRING OPTIONAL }
     * Malformed optional fields are ignored; the private scalar is mandatory.
     */
    const uint8_t *ptr = data;
    const uint8_t *end = &data[len];
    const uint8_t *seq_data = NULL;
    uint32_t seq_len = 0U;
    uint8_t version_buf[1] = { 0U };
    uint32_t version_len = (uint32_t)sizeof(version_buf);
    uint32_t private_key_len = 0U;

    /* Parse ECPrivateKey SEQUENCE */
    if(asn1_get_sequence(&ptr, end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    const uint8_t *seq_end = &seq_data[seq_len];
    const uint8_t *seq_ptr = seq_data;

    key->key_type = X509_PRIVATE_KEY_ECC;
    key->format = X509_PRIVATE_KEY_FORMAT_SEC1;

    /* Parse version (must be ecPrivkeyVer1) */
    if(asn1_get_integer(&seq_ptr, seq_end, version_buf, &version_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if((version_len != 1U) || (version_buf[0] != 1U)) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Parse private key (OCTET STRING) */
    if(asn1_get_tag(&seq_ptr, seq_end, 0x04U) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    private_key_len = (uint32_t)(asn1_get_length(&seq_ptr, seq_end));
    if((private_key_len == 0U) || (x509_bytes_remaining(seq_ptr, seq_end) < (size_t)private_key_len)) {
        return NOXTLS_RETURN_FAILED;
    }

    key->ecc_private_key = (uint8_t*)NOXTLS_MALLOC(private_key_len);
    if(key->ecc_private_key == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    key->ecc_private_key_len = private_key_len;
    noxtls_copy_u8((uint8_t *)(void *)(key->ecc_private_key), (size_t)private_key_len, (const uint8_t *)(const void *)(seq_ptr), (size_t)private_key_len);
    seq_ptr = &seq_ptr[private_key_len];

    /* parameters [0] EXPLICIT ECParameters (namedCurve OID). */
    if(((uintptr_t)seq_ptr < (uintptr_t)seq_end) && (*seq_ptr == 0xA0U)) {
        uint32_t params_len = 0U;
        seq_ptr = &seq_ptr[1];
        params_len = (uint32_t)(asn1_get_length(&seq_ptr, seq_end));
        if((params_len == 0U) || (x509_bytes_remaining(seq_ptr, seq_end) < (size_t)params_len)) {
            return NOXTLS_RETURN_SUCCESS;  /* malformed optional tail ignored */
        }
        {
            const uint8_t *params_ptr = seq_ptr;
            if(asn1_get_oid(&params_ptr, &seq_ptr[params_len], key->ecc_curve_oid, &key->ecc_curve_oid_len) != NOXTLS_RETURN_SUCCESS) {
                key->ecc_curve_oid_len = 0U;
            }
        }
        seq_ptr = &seq_ptr[params_len];
    }

    /* publicKey [1] EXPLICIT BIT STRING: 0x00 unused-bits octet followed by the encoded point. */
    if(((uintptr_t)seq_ptr < (uintptr_t)seq_end) && (*seq_ptr == 0xA1U)) {
        uint32_t wrap_len = 0U;
        seq_ptr = &seq_ptr[1];
        wrap_len = (uint32_t)(asn1_get_length(&seq_ptr, seq_end));
        if((wrap_len > 0U) && (x509_bytes_remaining(seq_ptr, seq_end) >= (size_t)wrap_len)) {
            const uint8_t *bs_ptr = seq_ptr;
            const uint8_t *bs_end = &seq_ptr[wrap_len];
            if(asn1_get_tag(&bs_ptr, bs_end, 0x03U) == NOXTLS_RETURN_SUCCESS) {
                uint32_t bs_len = (uint32_t)(asn1_get_length(&bs_ptr, bs_end));
                if((bs_len >= 2U) && (x509_bytes_remaining(bs_ptr, bs_end) >= (size_t)bs_len) && (bs_ptr[0] == 0x00U)) {
                    uint32_t public_key_len = bs_len - 1U;
                    key->ecc_public_key = (uint8_t*)NOXTLS_MALLOC(public_key_len);
                    if(key->ecc_public_key == NULL) {
                        /* Release the scalar allocated above: a failed parse owns nothing. */
                        noxtls_secure_zero(key->ecc_private_key, (size_t)key->ecc_private_key_len);
                        (void)noxtls_free(key->ecc_private_key);
                        key->ecc_private_key = NULL;
                        key->ecc_private_key_len = 0U;
                        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
                    }
                    key->ecc_public_key_len = public_key_len;
                    noxtls_copy_u8((uint8_t *)(void *)(key->ecc_public_key), (size_t)public_key_len, (const uint8_t *)(const void *)(&bs_ptr[1]), (size_t)public_key_len);
                }
            }
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

#if NOXTLS_FEATURE_AES_CBC
/** Upper bound accepted for the PBKDF2 iteration count (limits CPU spent on hostile input). */
#define X509_PBES2_MAX_ITERATIONS 10000000U
/** AES-CBC IV length (RFC 3565 Section 4.1 AES-IV). */
#define X509_PBES2_AES_IV_LEN 16U

/**
 * @brief Map a PBKDF2 prf AlgorithmIdentifier OID to an HMAC hash (RFC 8018 Appendix B.1).
 * @internal
 *
 * @param[in] oid DER OID body.
 * @param[in] oid_len OID length.
 * @param[out] hash_algo Hash for HMAC.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_INVALID_ALGORITHM.
 */
static noxtls_return_t x509_pbkdf2_prf_from_oid(const uint8_t *oid, uint32_t oid_len, noxtls_hash_algos_t *hash_algo)
{
    /* 1.2.840.113549.2.{7,8,9,10,11}: hmacWithSHA1/SHA224/SHA256/SHA384/SHA512 */
    static const uint8_t prf_prefix[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x02U };
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if(((size_t)oid_len != (sizeof(prf_prefix) + 1U)) ||
       (noxtls_ct_memcmp(oid, prf_prefix, sizeof(prf_prefix)) != 0)) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    switch(oid[sizeof(prf_prefix)]) {
        case 0x07U:
            *hash_algo = NOXTLS_HASH_SHA1;
            break;
        case 0x08U:
            *hash_algo = NOXTLS_HASH_SHA_224;
            break;
        case 0x09U:
            *hash_algo = NOXTLS_HASH_SHA_256;
            break;
        case 0x0AU:
            *hash_algo = NOXTLS_HASH_SHA_384;
            break;
        case 0x0BU:
            *hash_algo = NOXTLS_HASH_SHA_512;
            break;
        default:
            rc = NOXTLS_RETURN_INVALID_ALGORITHM;
            break;
    }
    return rc;
}

/**
 * @brief Read a small non-negative DER INTEGER (at most 4 content octets).
 * @internal
 *
 * @param[in,out] ptr Cursor, advanced past the INTEGER on success.
 * @param[in] end One past the end of the enclosing element.
 * @param[out] value Decoded value.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_FAILED.
 */
static noxtls_return_t x509_asn1_get_small_uint(const uint8_t **ptr, const uint8_t *end, uint32_t *value)
{
    uint8_t int_buf[4];
    uint32_t int_len = (uint32_t)sizeof(int_buf);
    uint32_t v = 0U;
    uint32_t i = 0U;

    if(asn1_get_integer(ptr, end, int_buf, &int_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if((int_buf[0] & 0x80U) != 0U) {
        return NOXTLS_RETURN_FAILED;  /* negative */
    }
    for(i = 0U; i < int_len; i += 1U) {
        v = (v << 8U) | (uint32_t)int_buf[i];
    }
    *value = v;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Parse EncryptedPrivateKeyInfo (RFC 5958 Section 3), decrypt it with PBES2 and parse the inner key.
 *
 * Supported: PBES2 (RFC 8018 Section 6.2) with PBKDF2 (prf hmacWithSHA1 (default), SHA224,
 * SHA256, SHA384 or SHA512, subject to the PBKDF2 module) and encryptionScheme aes128-CBC,
 * aes192-CBC or aes256-CBC with the IV taken from the scheme parameters (RFC 3565).
 *
 * @param[in] key The X.509 private key structure to parse.
 * @param[in] data The DER data to parse.
 * @param[in] len The length of the DER data.
 * @param[in] password The password to decrypt the key.
 * @param[in] password_len The length of the password.
 *
 * @return NOXTLS_RETURN_SUCCESS and fills key on success; an error code otherwise
 *         (including a wrong password, detected by the padding or inner key parse).
 */
static noxtls_return_t noxtls_x509_parse_encrypted_pkcs8(x509_private_key_t *key, const uint8_t *data, uint32_t len,
                                                         const uint8_t *password, uint32_t password_len)
{
    /* PKCS#8 encryption OIDs local to this function (Rule 8.9). */
    /* id-PBES2  1.2.840.113549.1.5.13 */
    static const uint8_t oid_pbes2[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x05U, 0x0DU };
    /* id-PBKDF2 1.2.840.113549.1.5.12 */
    static const uint8_t oid_pbkdf2[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x05U, 0x0CU };
    /* aes 2.16.840.1.101.3.4.1: .2 aes128-CBC, .22 aes192-CBC, .42 aes256-CBC */
    static const uint8_t oid_aes_prefix[] = { 0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x01U };

    const uint8_t *ptr = data;
    const uint8_t *end = &data[len];
    const uint8_t *epki = NULL;
    uint32_t epki_len = 0U;
    const uint8_t *alg = NULL;
    uint32_t alg_len = 0U;
    const uint8_t *pbes2 = NULL;
    uint32_t pbes2_len = 0U;
    const uint8_t *kdf = NULL;
    uint32_t kdf_len = 0U;
    const uint8_t *kdf_params = NULL;
    uint32_t kdf_params_len = 0U;
    const uint8_t *enc_scheme = NULL;
    uint32_t enc_scheme_len = 0U;
    const uint8_t *salt = NULL;
    uint32_t salt_len = 0U;
    const uint8_t *iv = NULL;
    uint32_t iv_len = 0U;
    const uint8_t *enc_data = NULL;
    uint32_t enc_data_len = 0U;
    uint8_t oid_buf[32];
    uint32_t oid_len = 0U;
    uint32_t iterations = 0U;
    uint32_t key_len_param = 0U;
    uint32_t key_bytes = 0U;
    uint32_t i = 0U;
    noxtls_hash_algos_t prf_hash = NOXTLS_HASH_SHA1;
    noxtls_aes_type_t aes_type = NOXTLS_AES_128_BIT;
    uint8_t derived_key[32];
    uint8_t *decrypted = NULL;
    uint32_t plain_len = 0U;
    uint32_t pad_bad = 0U;
    uint8_t pad = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((key == NULL) || (data == NULL) || (password == NULL) || (password_len == 0U)) {
        return NOXTLS_RETURN_NULL;
    }

    /* EncryptedPrivateKeyInfo ::= SEQUENCE { encryptionAlgorithm AlgorithmIdentifier, encryptedData OCTET STRING } */
    if(asn1_get_sequence(&ptr, end, &epki, &epki_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    ptr = epki;
    end = &epki[epki_len];
    if(asn1_get_sequence(&ptr, end, &alg, &alg_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(asn1_get_octet_string(&ptr, end, &enc_data, &enc_data_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    /* encryptionAlgorithm ::= { id-PBES2, PBES2-params } */
    ptr = alg;
    end = &alg[alg_len];
    if(asn1_get_oid(&ptr, end, oid_buf, &oid_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(oid_equal(oid_buf, oid_len, oid_pbes2, (uint32_t)sizeof(oid_pbes2)) == 0) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;  /* only PBES2 is supported */
    }
    if(asn1_get_sequence(&ptr, end, &pbes2, &pbes2_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    /* PBES2-params ::= SEQUENCE { keyDerivationFunc AlgorithmIdentifier, encryptionScheme AlgorithmIdentifier } */
    ptr = pbes2;
    end = &pbes2[pbes2_len];
    if((asn1_get_sequence(&ptr, end, &kdf, &kdf_len) != NOXTLS_RETURN_SUCCESS) ||
       (asn1_get_sequence(&ptr, end, &enc_scheme, &enc_scheme_len) != NOXTLS_RETURN_SUCCESS)) {
        return NOXTLS_RETURN_FAILED;
    }

    /* keyDerivationFunc ::= { id-PBKDF2, PBKDF2-params } */
    ptr = kdf;
    end = &kdf[kdf_len];
    if(asn1_get_oid(&ptr, end, oid_buf, &oid_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(oid_equal(oid_buf, oid_len, oid_pbkdf2, (uint32_t)sizeof(oid_pbkdf2)) == 0) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;  /* only PBKDF2 is supported */
    }
    if(asn1_get_sequence(&ptr, end, &kdf_params, &kdf_params_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    /* PBKDF2-params ::= SEQUENCE { salt OCTET STRING, iterationCount INTEGER,
     *                              keyLength INTEGER OPTIONAL, prf AlgorithmIdentifier DEFAULT hmacWithSHA1 } */
    ptr = kdf_params;
    end = &kdf_params[kdf_params_len];
    if((asn1_get_octet_string(&ptr, end, &salt, &salt_len) != NOXTLS_RETURN_SUCCESS) || (salt_len == 0U)) {
        return NOXTLS_RETURN_FAILED;
    }
    if(x509_asn1_get_small_uint(&ptr, end, &iterations) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if((iterations == 0U) || (iterations > X509_PBES2_MAX_ITERATIONS)) {
        return NOXTLS_RETURN_FAILED;
    }
    if(((uintptr_t)ptr < (uintptr_t)end) && (*ptr == 0x02U)) {
        if(x509_asn1_get_small_uint(&ptr, end, &key_len_param) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    if(((uintptr_t)ptr < (uintptr_t)end) && (*ptr == 0x30U)) {
        const uint8_t *prf_alg = NULL;
        uint32_t prf_alg_len = 0U;
        const uint8_t *prf_ptr = NULL;
        if(asn1_get_sequence(&ptr, end, &prf_alg, &prf_alg_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        prf_ptr = prf_alg;
        if(asn1_get_oid(&prf_ptr, &prf_alg[prf_alg_len], oid_buf, &oid_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        rc = x509_pbkdf2_prf_from_oid(oid_buf, oid_len, &prf_hash);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    if((uintptr_t)ptr != (uintptr_t)end) {
        return NOXTLS_RETURN_FAILED;  /* trailing or misordered PBKDF2 parameters */
    }

    /* encryptionScheme ::= { aesNNN-CBC, AES-IV OCTET STRING (SIZE(16)) } */
    ptr = enc_scheme;
    end = &enc_scheme[enc_scheme_len];
    if(asn1_get_oid(&ptr, end, oid_buf, &oid_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(((size_t)oid_len != (sizeof(oid_aes_prefix) + 1U)) ||
       (noxtls_ct_memcmp(oid_buf, oid_aes_prefix, sizeof(oid_aes_prefix)) != 0)) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if(oid_buf[sizeof(oid_aes_prefix)] == 0x02U) {
        key_bytes = 16U;
        aes_type = NOXTLS_AES_128_BIT;
    } else if(oid_buf[sizeof(oid_aes_prefix)] == 0x16U) {
        key_bytes = 24U;
        aes_type = NOXTLS_AES_192_BIT;
    } else if(oid_buf[sizeof(oid_aes_prefix)] == 0x2AU) {
        key_bytes = 32U;
        aes_type = NOXTLS_AES_256_BIT;
    } else {
        return NOXTLS_RETURN_INVALID_ALGORITHM;  /* only AES-CBC schemes are supported */
    }
    if((asn1_get_octet_string(&ptr, end, &iv, &iv_len) != NOXTLS_RETURN_SUCCESS) ||
       (iv_len != X509_PBES2_AES_IV_LEN)) {
        return NOXTLS_RETURN_FAILED;
    }
    if((key_len_param != 0U) && (key_len_param != key_bytes)) {
        return NOXTLS_RETURN_FAILED;
    }
    if((enc_data_len == 0U) || ((enc_data_len % (uint32_t)NOXTLS_AES_BLOCK_LEN) != 0U)) {
        return NOXTLS_RETURN_FAILED;
    }

    rc = x509_pbes2_kdf(prf_hash, password, password_len, salt, salt_len, iterations, derived_key, key_bytes);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(derived_key, sizeof(derived_key));
        return rc;
    }

    decrypted = (uint8_t*)NOXTLS_MALLOC((size_t)enc_data_len);
    if(decrypted == NULL) {
        noxtls_secure_zero(derived_key, sizeof(derived_key));
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    rc = noxtls_aes_decrypt_cbc(derived_key, enc_data, enc_data_len, iv, decrypted, aes_type);
    noxtls_secure_zero(derived_key, sizeof(derived_key));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(decrypted, (size_t)enc_data_len);
        (void)noxtls_free(decrypted);
        return NOXTLS_RETURN_FAILED;
    }

    /* RFC 8018 Section 6.1.1 step 4 padding: 1..16 octets, each equal to the padding length. */
    pad = decrypted[enc_data_len - 1U];
    if((pad == 0U) || (pad > (uint8_t)NOXTLS_AES_BLOCK_LEN)) {
        pad_bad = 1U;
    } else {
        for(i = 0U; i < (uint32_t)pad; i += 1U) {
            pad_bad |= (decrypted[(enc_data_len - 1U) - i] != pad) ? 1U : 0U;
        }
    }
    if(pad_bad != 0U) {
        noxtls_secure_zero(decrypted, (size_t)enc_data_len);
        (void)noxtls_free(decrypted);
        return NOXTLS_RETURN_FAILED;  /* wrong password or corrupt data */
    }
    plain_len = enc_data_len - (uint32_t)pad;

    (void)noxtls_x509_private_key_free(key);
    rc = (plain_len > 0U) ? noxtls_x509_private_key_parse_der(key, decrypted, plain_len) : NOXTLS_RETURN_FAILED;
    noxtls_secure_zero(decrypted, (size_t)enc_data_len);
    (void)noxtls_free(decrypted);
    return rc;
}
#endif

/**
 * @brief Parse X.509 private key from DER format (optionally decrypt with password).
 * If \p password is non-NULL and the key is EncryptedPrivateKeyInfo (PBES2/PBKDF2/AES), decrypts then parses.
 * If \p password is NULL and the blob is encrypted, sets key->encrypted=1 and returns NOXTLS_RETURN_FAILED.
 *
 * @param[in] key The X.509 private key structure to parse.
 * @param[in] data The DER data to parse.
 * @param[in] len The length of the DER data.
 * @param[in] password The password to decrypt the key.
 * @param[in] password_len The length of the password.
 *
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_private_key_parse_der_with_password(x509_private_key_t *key, const uint8_t *data, uint32_t len,
                                                                 const uint8_t *password, uint32_t password_len)
{
#if NOXTLS_FEATURE_AES_CBC
    if((key != NULL) && (data != NULL) && (len >= 2U) && (data[0] == 0x30U)) {
        const uint8_t *ptr = data;
        const uint8_t *end = &data[len];
        const uint8_t *seq_data = NULL;
        uint32_t seq_len = 0U;
        if((asn1_get_sequence(&ptr, end, &seq_data, &seq_len) == NOXTLS_RETURN_SUCCESS) && (seq_len > 0U) && (seq_data[0] == 0x30U)) {
            /* EncryptedPrivateKeyInfo: first element is SEQUENCE (AlgorithmIdentifier) */
            if((password != NULL) && (password_len > 0U)) {
                noxtls_return_t dec_rc = noxtls_x509_parse_encrypted_pkcs8(key, data, len, password, password_len);
                if(dec_rc == NOXTLS_RETURN_SUCCESS) {
                    return NOXTLS_RETURN_SUCCESS;
                }
                (void)noxtls_x509_private_key_free(key);
                if(dec_rc == NOXTLS_RETURN_NOT_ENOUGH_MEMORY) {
                    return dec_rc;
                }
                key->raw_data = (uint8_t*)NOXTLS_MALLOC(len);
                if(key->raw_data == NULL) {
                    return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
                }
                noxtls_copy_u8((uint8_t *)(void *)(key->raw_data), (size_t)len, (const uint8_t *)(const void *)(data), (size_t)len);
                key->raw_data_len = len;
                key->encrypted = 1;
                return dec_rc;
            }
            (void)noxtls_x509_private_key_free(key);
            key->raw_data = (uint8_t*)NOXTLS_MALLOC(len);
            if(key->raw_data == NULL) { return NOXTLS_RETURN_NOT_ENOUGH_MEMORY; }
            noxtls_copy_u8((uint8_t *)(void *)(key->raw_data), (size_t)len, (const uint8_t *)(const void *)(data), (size_t)len);
            key->raw_data_len = len;
            key->encrypted = 1;
            return NOXTLS_RETURN_FAILED;
        }
    }
#endif
    return noxtls_x509_private_key_parse_der(key, data, len);
}

/**
 * @brief Parse X.509 private key from DER format
 *
 * This function parses a X.509 private key from DER format.
 *
 * @param[in] key The X.509 private key structure to parse.
 * @param[in] data The DER data to parse.
 * @param[in] len The length of the DER data.
 *
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_private_key_parse_der(x509_private_key_t *key, const uint8_t *data, uint32_t len)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((key == NULL) || (data == NULL) || (len == 0U)) {
        return NOXTLS_RETURN_NULL;
    }

    /* Free any existing data */
    (void)noxtls_x509_private_key_free(key);

    /* Detect EncryptedPrivateKeyInfo (first element of outer SEQUENCE is SEQUENCE, not INTEGER) */
    if((len >= 2U) && (data[0] == 0x30U)) {
        const uint8_t *ptr = data;
        const uint8_t *end = &data[len];
        const uint8_t *seq_data = NULL;
        uint32_t seq_len = 0U;
        if((asn1_get_sequence(&ptr, end, &seq_data, &seq_len) == NOXTLS_RETURN_SUCCESS) && (seq_len > 0U) && (seq_data[0] == 0x30U)) {
            key->raw_data = (uint8_t*)NOXTLS_MALLOC(len);
            if(key->raw_data == NULL) {
                return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
            }
            noxtls_copy_u8((uint8_t *)(void *)(key->raw_data), (size_t)len, (const uint8_t *)(const void *)(data), (size_t)len);
            key->raw_data_len = len;
            key->encrypted = 1;
            return NOXTLS_RETURN_FAILED;
        }
    }

    /* Store raw private key data */
    key->raw_data = (uint8_t*)NOXTLS_MALLOC(len);
    if(key->raw_data == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    noxtls_copy_u8((uint8_t *)(void *)(key->raw_data), (size_t)len, (const uint8_t *)(const void *)(data), (size_t)len);
    key->raw_data_len = len;

    /* Try different formats */
    CERT_DEBUG_PRINT("x509_private_key_parse_der: len=%u first_bytes=0x%02x 0x%02x 0x%02x\n",
        len, len > 0U ? data[0] : 0, len > 1U ? data[1] : 0, len > 2U ? data[2] : 0);
    rc = noxtls_x509_parse_pkcs1_rsa_private_key(key, data, len);

    if(rc == NOXTLS_RETURN_SUCCESS) {
        key->parsed = 1;
        CERT_DEBUG_PRINT("x509_private_key_parse_der: parsed as PKCS#1 RSA\n");
        return NOXTLS_RETURN_SUCCESS;
    }

    /* An allocation failure in any format is final: report it and leave the key unparsed and empty,
     * rather than retrying another format (which could leak or mis-detect the key). */
    if(rc != NOXTLS_RETURN_NOT_ENOUGH_MEMORY) {
        rc = noxtls_x509_parse_pkcs8_private_key(key, data, len);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            key->parsed = 1;
            CERT_DEBUG_PRINT("x509_private_key_parse_der: parsed as PKCS#8 key_type=%d\n", key->key_type);
            return NOXTLS_RETURN_SUCCESS;
        }
    }

    if(rc != NOXTLS_RETURN_NOT_ENOUGH_MEMORY) {
        rc = noxtls_x509_parse_sec1_ecc_private_key(key, data, len);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            key->parsed = 1;
            CERT_DEBUG_PRINT("x509_private_key_parse_der: parsed as SEC1 ECC\n");
            return NOXTLS_RETURN_SUCCESS;
        }
    }

    CERT_DEBUG_PRINT("x509_private_key_parse_der: all formats failed\n");
    (void)noxtls_x509_private_key_free(key);
    return (rc == NOXTLS_RETURN_NOT_ENOUGH_MEMORY) ? NOXTLS_RETURN_NOT_ENOUGH_MEMORY : NOXTLS_RETURN_FAILED;
}

/**
 * Find first occurrence of NUL-terminated \p needle in \p buf[0..len).
 * PEM file contents are not NUL-terminated; using strstr() on them is undefined
 * behavior and may read past the allocation (FORTIFY/ASAN).
 *
 * @param[in] buf The buffer to search.
 * @param[in] len The length of the buffer.
 * @param[in] needle The needle to search for.
 *
 * @return The pointer to the first occurrence of the needle.
 */

static const uint8_t s_pem_begin_rsa[] = "-----BEGIN RSA PRIVATE KEY-----";
static const uint8_t s_pem_end_rsa[] = "-----END RSA PRIVATE KEY-----";
static const uint8_t s_pem_begin_pkcs8[] = "-----BEGIN PRIVATE KEY-----";
static const uint8_t s_pem_end_pkcs8[] = "-----END PRIVATE KEY-----";
static const uint8_t s_pem_begin_ec[] = "-----BEGIN EC PRIVATE KEY-----";
static const uint8_t s_pem_end_ec[] = "-----END EC PRIVATE KEY-----";
static const uint8_t s_pem_begin_enc[] = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
static const uint8_t s_pem_end_enc[] = "-----END ENCRYPTED PRIVATE KEY-----";

static uint32_t x509_u8_noxtls_u8_strlen(const uint8_t *s)
{
    uint32_t n = 0U;
    if(s == NULL) {
        return 0U;
    }
    while(s[n] != 0U) {
        n += 1U;
    }
    return n;
}

static const uint8_t *x509_memfind(const uint8_t *buf, uint32_t len, const uint8_t *needle, uint32_t nlen)
{
    uint32_t i = 0U;

    if((buf == NULL) || (needle == NULL)) {
        return NULL;
    }
    if((nlen == 0U) || (len < nlen)) {
        return NULL;
    }
    for(i = 0U; (i + nlen) <= len; i += 1U) {
        if(noxtls_ct_memcmp(&buf[i], needle, (size_t)nlen) == 0) {
            return &buf[i];
        }
    }
    return NULL;
}

/**
 * @brief Parse X.509 private key from PEM format
 *
 * This function parses a X.509 private key from PEM format.
 *
 * @param[in] key The X.509 private key structure to parse.
 * @param[in] data The PEM data to parse.
 * @param[in] len The length of the PEM data.
 *
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_private_key_parse_pem(x509_private_key_t *key, const uint8_t *data, uint32_t len)
{
    uint8_t *der_data = NULL;
    uint32_t der_len = 0U;
    int decoded_len = 0;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    const uint8_t *begin_marker = NULL;
    const uint8_t *end_marker = NULL;
    const uint8_t *pem_start = NULL;
    const uint8_t *pem_end = NULL;
    uint32_t pem_data_len = 0U;

    if((key == NULL) || (data == NULL) || (len == 0U)) {
        return NOXTLS_RETURN_NULL;
    }

    /* Find PEM markers */
    if(x509_memfind(data, len, s_pem_begin_rsa, x509_u8_noxtls_u8_strlen(s_pem_begin_rsa)) != NULL) {
        begin_marker = s_pem_begin_rsa;
        end_marker = s_pem_end_rsa;
    } else if(x509_memfind(data, len, s_pem_begin_pkcs8, x509_u8_noxtls_u8_strlen(s_pem_begin_pkcs8)) != NULL) {
        begin_marker = s_pem_begin_pkcs8;
        end_marker = s_pem_end_pkcs8;
    } else if(x509_memfind(data, len, s_pem_begin_ec, x509_u8_noxtls_u8_strlen(s_pem_begin_ec)) != NULL) {
        begin_marker = s_pem_begin_ec;
        end_marker = s_pem_end_ec;
    } else if(x509_memfind(data, len, s_pem_begin_enc, x509_u8_noxtls_u8_strlen(s_pem_begin_enc)) != NULL) {
        begin_marker = s_pem_begin_enc;
        end_marker = s_pem_end_enc;
    } else {
        /* MISRA 15.7: final else path */
        return NOXTLS_RETURN_FAILED;
    }

    /* Find start of base64 data */
    pem_start = x509_memfind(data, len, begin_marker, x509_u8_noxtls_u8_strlen(begin_marker));
    if(pem_start == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    pem_start = &pem_start[x509_u8_noxtls_u8_strlen(begin_marker)];

    /* Skip whitespace */
    while(((uintptr_t)pem_start < (uintptr_t)(&data[len])) && ((*pem_start == (uint8_t)'\n') || (*pem_start == (uint8_t)'\r') || (*pem_start == (uint8_t)' '))) {
        pem_start = &pem_start[1];
    }

    /* Find end of base64 data */
    if((uintptr_t)pem_start > (uintptr_t)(&data[len])) {
        return NOXTLS_RETURN_FAILED;
    }
    {
        uintptr_t tail_delta = (uintptr_t)(&data[len]) - (uintptr_t)pem_start;
        uint32_t tail_len = (uint32_t)tail_delta;
        pem_end = x509_memfind(pem_start, tail_len, end_marker, x509_u8_noxtls_u8_strlen(end_marker));
    }
    if(pem_end == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Skip trailing whitespace before end marker */
    while(((uintptr_t)pem_end > (uintptr_t)pem_start) && ((pem_end[-1] == (uint8_t)'\n') || (pem_end[-1] == (uint8_t)'\r') || (pem_end[-1] == (uint8_t)' '))) {
        pem_end = &pem_end[-1];
    }

    {
        uintptr_t pem_end_u = (uintptr_t)pem_end;
        uintptr_t pem_start_u = (uintptr_t)pem_start;
        if(pem_end_u < pem_start_u) {
            return NOXTLS_RETURN_FAILED;
        }
        {
            uintptr_t pem_delta = pem_end_u - pem_start_u;
            if(pem_delta > (uintptr_t)UINT32_MAX) {
                return NOXTLS_RETURN_FAILED;
            }
            pem_data_len = (uint32_t)pem_delta;
        }
    }

    if(pem_data_len == 0U) {
        return NOXTLS_RETURN_FAILED;  /* empty PEM body: nothing to decode */
    }

    /* Allocate buffer for DER data */
    der_data = (uint8_t*)NOXTLS_MALLOC(pem_data_len);
    if(der_data == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    /* Convert PEM to DER */
    decoded_len = noxtls_base64_decode(pem_start, pem_data_len, der_data);
    if(decoded_len <= 0) {
        (void)noxtls_free(der_data);
        return NOXTLS_RETURN_FAILED;
    }
    if((unsigned long)decoded_len > UINT32_MAX) {
        (void)noxtls_free(der_data);
        return NOXTLS_RETURN_FAILED;
    }
    der_len = (uint32_t)decoded_len;

    /* Parse DER */
    rc = noxtls_x509_private_key_parse_der(key, der_data, der_len);

    (void)noxtls_free(der_data);

    return rc;
}

/**
 * @brief Parse X.509 private key from PEM format with optional password.
 * Use for "-----BEGIN ENCRYPTED PRIVATE KEY-----" or when a password might be needed.
 * For unencrypted PEM, \p password may be NULL.
 *
 * @param[in] key The X.509 private key structure to parse.
 * @param[in] data The PEM data to parse.
 * @param[in] len The length of the PEM data.
 * @param[in] password The password to decrypt the key.
 * @param[in] password_len The length of the password.
 *
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_private_key_parse_pem_with_password(x509_private_key_t *key, const uint8_t *data, uint32_t len,
                                                                 const uint8_t *password, uint32_t password_len)
{
    uint8_t *der_data = NULL;
    uint32_t der_len = 0U;
    int decoded_len = 0;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    const uint8_t *begin_marker = NULL;
    const uint8_t *end_marker = NULL;
    const uint8_t *pem_start = NULL;
    const uint8_t *pem_end = NULL;
    uint32_t pem_data_len = 0U;
    int is_encrypted = 0;

    if((key == NULL) || (data == NULL) || (len == 0U)) {
        return NOXTLS_RETURN_NULL;
    }

    if(x509_memfind(data, len, s_pem_begin_enc, x509_u8_noxtls_u8_strlen(s_pem_begin_enc)) != NULL) {
        begin_marker = s_pem_begin_enc;
        end_marker = s_pem_end_enc;
        is_encrypted = 1;
    } else if(x509_memfind(data, len, s_pem_begin_rsa, x509_u8_noxtls_u8_strlen(s_pem_begin_rsa)) != NULL) {
        begin_marker = s_pem_begin_rsa;
        end_marker = s_pem_end_rsa;
    } else if(x509_memfind(data, len, s_pem_begin_pkcs8, x509_u8_noxtls_u8_strlen(s_pem_begin_pkcs8)) != NULL) {
        begin_marker = s_pem_begin_pkcs8;
        end_marker = s_pem_end_pkcs8;
    } else if(x509_memfind(data, len, s_pem_begin_ec, x509_u8_noxtls_u8_strlen(s_pem_begin_ec)) != NULL) {
        begin_marker = s_pem_begin_ec;
        end_marker = s_pem_end_ec;
    } else {
        /* MISRA 15.7: final else path */
        return NOXTLS_RETURN_FAILED;
    }

    pem_start = x509_memfind(data, len, begin_marker, x509_u8_noxtls_u8_strlen(begin_marker));
    if(pem_start == NULL) { return NOXTLS_RETURN_FAILED; }
    pem_start = &pem_start[x509_u8_noxtls_u8_strlen(begin_marker)];

    while(((uintptr_t)pem_start < (uintptr_t)(&data[len])) && ((*pem_start == (uint8_t)'\n') || (*pem_start == (uint8_t)'\r') || (*pem_start == (uint8_t)' '))) {
        pem_start = &pem_start[1];
    }

    if((uintptr_t)pem_start > (uintptr_t)(&data[len])) { return NOXTLS_RETURN_FAILED; }
    {
        uintptr_t tail_delta = (uintptr_t)(&data[len]) - (uintptr_t)pem_start;
        uint32_t tail_len = (uint32_t)tail_delta;
        pem_end = x509_memfind(pem_start, tail_len, end_marker, x509_u8_noxtls_u8_strlen(end_marker));
    }
    if(pem_end == NULL) { return NOXTLS_RETURN_FAILED; }
    while(((uintptr_t)pem_end > (uintptr_t)pem_start) && ((pem_end[-1] == (uint8_t)'\n') || (pem_end[-1] == (uint8_t)'\r') || (pem_end[-1] == (uint8_t)' '))) {
        pem_end = &pem_end[-1];
    }

    {
        uintptr_t pem_end_u = (uintptr_t)pem_end;
        uintptr_t pem_start_u = (uintptr_t)pem_start;
        if(pem_end_u < pem_start_u) { return NOXTLS_RETURN_FAILED; }
        {
            uintptr_t pem_delta = pem_end_u - pem_start_u;
            if(pem_delta > (uintptr_t)UINT32_MAX) { return NOXTLS_RETURN_FAILED; }
            pem_data_len = (uint32_t)pem_delta;
        }
    }

    if(pem_data_len == 0U) { return NOXTLS_RETURN_FAILED; }  /* empty PEM body: nothing to decode */
    der_data = (uint8_t*)NOXTLS_MALLOC(pem_data_len);
    if(der_data == NULL) { return NOXTLS_RETURN_NOT_ENOUGH_MEMORY; }
    decoded_len = noxtls_base64_decode(pem_start, pem_data_len, der_data);
    if(decoded_len <= 0) {
        (void)noxtls_free(der_data);
        return NOXTLS_RETURN_FAILED;
    }
    if((unsigned long)decoded_len > UINT32_MAX) {
        (void)noxtls_free(der_data);
        return NOXTLS_RETURN_FAILED;
    }
    der_len = (uint32_t)decoded_len;

    if(is_encrypted != 0) {
        rc = noxtls_x509_private_key_parse_der_with_password(key, der_data, der_len, password, password_len);
    } else {
        rc = noxtls_x509_private_key_parse_der_with_password(key, der_data, der_len, NULL, 0U);
    }

    (void)noxtls_free(der_data);
    return rc;
}

/**
 * @brief Load X.509 private key from file
 *
 * This function loads a X.509 private key from a file.
 *
 * @param[in] key The X.509 private key structure to load.
 * @param[in] filename The name of the file to load the private key from.
 *
 * @return The return code of the function.
 */
noxtls_return_t noxtls_x509_private_key_load_file(x509_private_key_t *key, const uint8_t *filename)
{
#if !NOXTLS_HAVE_FILE_IO
    if((key == NULL) || (filename == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    (void)key;
    (void)filename;
    return NOXTLS_RETURN_FAILED;
#else
    FILE *fp;
    uint8_t *data = NULL;
    uint32_t len = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((key == NULL) || (filename == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    fp = noxtls_x509_fopen(filename, "rb");
    if(fp == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Get file size */
    errno = 0;
    if(fseek(fp, 0, SEEK_END) != 0) {
        (void)fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }
    {
        long ftell_len = 0;
        errno = 0;
        ftell_len = ftell(fp);
        if(errno != 0) {
            (void)fclose(fp);
            return NOXTLS_RETURN_FAILED;
        }
        if(ftell_len < 0) {
            (void)fclose(fp);
            return NOXTLS_RETURN_FAILED;
        }
        len = (uint32_t)ftell_len;
    }
    errno = 0;
    if(fseek(fp, 0, SEEK_SET) != 0) {
        (void)fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }

    if((len == 0U) || (len > X509_MAX_PRIVATE_KEY_SIZE)) {
        (void)fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }

    data = (uint8_t*)NOXTLS_MALLOC(len);
    if(data == NULL) {
        (void)fclose(fp);
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    if(fread(data, 1, len, fp) != len) {
        (void)noxtls_free(data);
        (void)fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }

    (void)fclose(fp);

    /* Try DER first, then PEM */
    rc = noxtls_x509_private_key_parse_der(key, data, len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        /* If DER parsing failed, try PEM */
        noxtls_return_t pem_rc = noxtls_x509_private_key_parse_pem(key, data, len);
        if(pem_rc == NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_SUCCESS;
        } else {
            /* Both failed - return the DER error as it's more specific */
            rc = NOXTLS_RETURN_BAD_DATA;
        }
    }

    (void)noxtls_free(data);

    return rc;
#endif
}

/**
 * @brief Copy a big-number component into rsa_key buffer (right-aligned, big-endian).
 * dest_len is the allocated size; src_len may be shorter (leading zeros omitted in DER).
 *
 * @param[in] dest The destination buffer.
 * @param[in] dest_len The length of the destination buffer.
 * @param[in] src The source buffer.
 * @param[in] src_len The length of the source buffer.
 *
 */
static void rsa_copy_component(uint8_t *dest, uint32_t dest_len,
                               const uint8_t *src, uint32_t src_len)
{
    if(src_len >= dest_len) {
        noxtls_copy_u8((uint8_t *)(void *)(dest), (size_t)dest_len, (const uint8_t *)(const void *)(&src[(src_len - dest_len)]), (size_t)dest_len);
    } else {
        noxtls_secure_zero((dest), (size_t)(dest_len - src_len));
        noxtls_copy_u8((uint8_t *)(void *)(&dest[(dest_len - src_len)]), (size_t)src_len, (const uint8_t *)(const void *)(src), (size_t)src_len);
    }
}

/**
 * @brief Convert X.509 private key to RSA key structure
 *
 * This function converts a X.509 private key to a RSA key structure.
 *
 * @param[in] key The X.509 private key structure to convert.
 * @param[in] rsa_key The RSA key structure to convert to.
 *
 * @return @see noxtls_return_t
 */
noxtls_return_t noxtls_x509_private_key_to_rsa_key(const x509_private_key_t *key, void *rsa_key)
{
    rsa_key_t *rk = (rsa_key_t *)rsa_key;
    rsa_key_size_t key_size = RSA_2048_BIT;
    uint32_t key_bytes = 0U;
    uint32_t prime_len = 0U;

    if((key == NULL) || (rsa_key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if((key->key_type != X509_PRIVATE_KEY_RSA) || (key->parsed == 0)) {
        return NOXTLS_RETURN_FAILED;
    }

    if((key->rsa_modulus == NULL) || (key->rsa_modulus_len == 0U) ||
       (key->rsa_public_exponent == NULL) || (key->rsa_public_exponent_len == 0U) ||
       (key->rsa_private_exponent == NULL) || (key->rsa_private_exponent_len == 0U)) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Modulus length may include leading zero (DER); use canonical key size */
    if((key->rsa_modulus_len == X509_RSA_MODULUS_BYTES_1024) ||
       (key->rsa_modulus_len == (X509_RSA_MODULUS_BYTES_1024 + 1U))) {
        key_bytes = X509_RSA_MODULUS_BYTES_1024;
        key_size = RSA_1024_BIT;
    } else if((key->rsa_modulus_len == X509_RSA_MODULUS_BYTES_2048) ||
              (key->rsa_modulus_len == (X509_RSA_MODULUS_BYTES_2048 + 1U))) {
        key_bytes = X509_RSA_MODULUS_BYTES_2048;
        key_size = RSA_2048_BIT;
    } else if((key->rsa_modulus_len == X509_RSA_MODULUS_BYTES_3072) ||
              (key->rsa_modulus_len == (X509_RSA_MODULUS_BYTES_3072 + 1U))) {
        key_bytes = X509_RSA_MODULUS_BYTES_3072;
        key_size = RSA_3072_BIT;
    } else if((key->rsa_modulus_len == X509_RSA_MODULUS_BYTES_4096) ||
              (key->rsa_modulus_len == (X509_RSA_MODULUS_BYTES_4096 + 1U))) {
        key_bytes = X509_RSA_MODULUS_BYTES_4096;
        key_size = RSA_4096_BIT;
    } else {
        /* MISRA 15.7: final else path */
        return NOXTLS_RETURN_FAILED;
    }

    prime_len = (uint32_t)key_bytes >> 1U;
    if((key->rsa_prime1 == NULL) || (key->rsa_prime1_len == 0U) ||
       (key->rsa_prime2 == NULL) || (key->rsa_prime2_len == 0U) ||
       (key->rsa_exponent1 == NULL) || (key->rsa_exponent1_len == 0U) ||
       (key->rsa_exponent2 == NULL) || (key->rsa_exponent2_len == 0U) ||
       (key->rsa_coefficient == NULL) || (key->rsa_coefficient_len == 0U)) {
        return NOXTLS_RETURN_FAILED;
    }

    if(noxtls_rsa_key_init(rk, key_size) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    rsa_copy_component(rk->n, key_bytes, key->rsa_modulus, key->rsa_modulus_len);
    rsa_copy_component(rk->e, key_bytes, key->rsa_public_exponent, key->rsa_public_exponent_len);
    rsa_copy_component(rk->d, key_bytes, key->rsa_private_exponent, key->rsa_private_exponent_len);
    rsa_copy_component(rk->p, prime_len, key->rsa_prime1, key->rsa_prime1_len);
    rsa_copy_component(rk->q, prime_len, key->rsa_prime2, key->rsa_prime2_len);
    rsa_copy_component(rk->dp, prime_len, key->rsa_exponent1, key->rsa_exponent1_len);
    rsa_copy_component(rk->dq, prime_len, key->rsa_exponent2, key->rsa_exponent2_len);
    rsa_copy_component(rk->qi, prime_len, key->rsa_coefficient, key->rsa_coefficient_len);

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Check 1 <= d <= n - 1 for an EC private scalar (both big-endian).
 *
 * Runs over every byte without data-dependent branches on d. @p n may be longer than @p d
 * (secp224k1: 29-byte order, 28-byte field), in which case its extra leading bytes are part
 * of the comparison.
 *
 * @param[in] d      Private scalar, @p d_len bytes.
 * @param[in] d_len  Length of @p d.
 * @param[in] n      Group order, @p n_len bytes.
 * @param[in] n_len  Length of @p n (>= @p d_len).
 *
 * @return 1 when d is in [1, n - 1], 0 otherwise (also for invalid arguments).
 */
static int x509_ecc_scalar_in_range(const uint8_t *d, uint32_t d_len, const uint8_t *n, uint32_t n_len)
{
    uint32_t i = 0U;
    uint32_t nonzero = 0U;
    uint32_t lt = 0U;  /* 1 once d < n is decided */
    uint32_t gt = 0U;  /* 1 once d > n is decided */

    if((d == NULL) || (n == NULL) || (d_len == 0U) || (n_len < d_len)) {
        return 0;
    }
    for(i = 0U; i < n_len; i += 1U) {
        /* Align d to the low-order end of n; missing high-order bytes of d are zero. */
        uint32_t a = (i < (n_len - d_len)) ? 0U : (uint32_t)d[i - (n_len - d_len)];
        uint32_t b = (uint32_t)n[i];
        uint32_t undecided = 1U ^ (lt | gt);
        uint32_t a_lt_b = ((a - b) >> 31U) & 1U;
        uint32_t b_lt_a = ((b - a) >> 31U) & 1U;
        lt |= undecided & a_lt_b;
        gt |= undecided & b_lt_a;
        nonzero |= a;
    }
    return ((nonzero != 0U) && (lt != 0U)) ? 1 : 0;
}

/**
 * @brief Convert X.509 private key to ecc_key_t (noxtls_ namespace)
 * Caller provides ecc_key; it is filled and must be freed with noxtls_ecc_key_free.
 *
 * @param[in] key The X.509 private key structure to convert.
 * @param[in] ecc_key The ECC key structure to convert to.
 *
 * @return @see noxtls_return_t
 */
noxtls_return_t noxtls_x509_private_key_to_ecc_key(const x509_private_key_t *key, ecc_key_t *ecc_key)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    ecc_curve_t curve_type = NOXTLS_ECC_SECP256R1;
    uint32_t size = 0U;

    if((key == NULL) || (ecc_key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if((key->key_type != X509_PRIVATE_KEY_ECC) || (key->parsed == 0)) {
        return NOXTLS_RETURN_FAILED;
    }

    if((key->ecc_private_key == NULL) || (key->ecc_private_key_len == 0U)) {
        return NOXTLS_RETURN_FAILED;
    }

    if(key->ecc_curve_oid_len > 0U) {
        rc = noxtls_x509_ecc_curve_from_oid(key->ecc_curve_oid, key->ecc_curve_oid_len, &curve_type);
    } else {
        rc = noxtls_x509_ecc_curve_from_pubkey_len((key->ecc_public_key_len > 0U) ? key->ecc_public_key_len : 65U, &curve_type);
    }

    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = noxtls_ecc_key_init(ecc_key, curve_type);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    size = ecc_key->curve->size;
    if(key->ecc_private_key_len > size) {
        (void)noxtls_ecc_key_free(ecc_key);
        return NOXTLS_RETURN_BAD_DATA;
    }
    noxtls_copy_u8((uint8_t *)(void *)(&ecc_key->d[(size - key->ecc_private_key_len)]), (size_t)key->ecc_private_key_len, (const uint8_t *)(const void *)(key->ecc_private_key), (size_t)key->ecc_private_key_len);
    /* SEC 1 v2 Section 3.2.1 / RFC 5915: the private key d must satisfy 1 <= d <= n - 1. */
    if(x509_ecc_scalar_in_range(ecc_key->d, size, ecc_key->curve->n, noxtls_ecc_curve_order_size(ecc_key->curve)) == 0) {
        (void)noxtls_ecc_key_free(ecc_key);
        return NOXTLS_RETURN_BAD_DATA;
    }

    if((key->ecc_public_key != NULL) && (key->ecc_public_key_len > 0U)) {
        if((key->ecc_public_key[0] != 0x04U) || (key->ecc_public_key_len != (1U + (2U * size)))) {
            (void)noxtls_ecc_key_free(ecc_key);
            return NOXTLS_RETURN_BAD_DATA;
        }
        noxtls_copy_u8((uint8_t *)(void *)(ecc_key->Q.x), (size_t)size, (const uint8_t *)(const void *)(&key->ecc_public_key[1U]), (size_t)size);
        noxtls_copy_u8((uint8_t *)(void *)(ecc_key->Q.y), (size_t)size, (const uint8_t *)(const void *)(&key->ecc_public_key[1U + size]), (size_t)size);
        ecc_key->Q.size = size;
        rc = noxtls_ecc_point_validate_public(&ecc_key->Q, ecc_key->curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_ecc_key_free(ecc_key);
            return rc;
        }
        /* The embedded SEC1 publicKey must belong to the private scalar (Q == d*G). */
        {
            ecc_point_t derived;
            noxtls_secure_zero(&derived, sizeof(derived));
            rc = noxtls_ecc_point_multiply(&derived, ecc_key->d, &ecc_key->curve->G, ecc_key->curve);
            if((rc == NOXTLS_RETURN_SUCCESS) &&
               ((noxtls_ct_memcmp(derived.x, ecc_key->Q.x, (size_t)size) != 0) ||
                (noxtls_ct_memcmp(derived.y, ecc_key->Q.y, (size_t)size) != 0))) {
                rc = NOXTLS_RETURN_BAD_DATA;
            }
            noxtls_secure_zero(&derived, sizeof(derived));
            if(rc != NOXTLS_RETURN_SUCCESS) {
                (void)noxtls_ecc_key_free(ecc_key);
                return rc;
            }
        }
    } else {
        /* MISRA 15.7: final else path */
        rc = noxtls_ecc_point_multiply(&ecc_key->Q, ecc_key->d, &ecc_key->curve->G, ecc_key->curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_ecc_key_free(ecc_key);
            return rc;
        }
        ecc_key->Q.size = size;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief High-level sign data with X.509 private key; output DER signature.
 *
 * This function signs data with a X.509 private key and outputs a DER signature.
 *
 * @param[in] key The X.509 private key structure to sign.
 * @param[in] key_len The length of the X.509 private key.
 * @param[in] data The data to sign.
 * @param[in] data_len The length of the data to sign.
 * @param[in] hash_algo The hash algorithm to use.  
 * @param[out] out_der The output buffer for the DER signature.
 * @param[in] out_max The maximum length of the output buffer.
 * @param[out] out_len The length of the DER signature.
 *
 * @return @see noxtls_return_t
 */
noxtls_return_t noxtls_x509_private_key_sign_data(const uint8_t *key, uint32_t key_len,
    const uint8_t *data, uint32_t data_len, noxtls_hash_algos_t hash_algo,
    uint8_t *out_der, uint32_t out_max, uint32_t *out_len)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    x509_private_key_t pk;
    ecc_key_t ecc_key;
    ecdsa_signature_t sig;
    uint8_t *der_buf = NULL;
    const uint32_t der_buf_size = 256U;
    uint8_t r_enc[ECC_MAX_KEY_SIZE + 2U];
    uint8_t s_enc[ECC_MAX_KEY_SIZE + 2U];
    uint32_t r_enc_len = 0U;
    uint32_t s_enc_len = 0U;
    uint32_t seq_len = 0U;
    uint32_t total = 0U;

    if((key == NULL) || (data == NULL) || (out_der == NULL) || (out_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if(out_max < 8U) {
        return NOXTLS_RETURN_FAILED; /* minimum for tiny DER; Ed/ECDSA paths check larger out_max */
    }

    (void)noxtls_x509_private_key_init(&pk);
    rc = noxtls_x509_private_key_parse_der(&pk, key, key_len);

    if(rc != NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_x509_private_key_parse_pem(&pk, key, key_len);
    }

    if(rc != NOXTLS_RETURN_SUCCESS) {
        CERT_DEBUG_PRINT("x509_private_key_sign_data: parse failed rc=%d\n", rc);
        (void)noxtls_x509_private_key_free(&pk);
        return rc;
    }

    if(pk.key_type == X509_PRIVATE_KEY_ECC) {
        rc = noxtls_x509_private_key_to_ecc_key(&pk, &ecc_key);
        (void)noxtls_x509_private_key_free(&pk);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            CERT_DEBUG_PRINT("x509_private_key_sign_data: to_ecc_key failed rc=%d\n", rc);
            return rc;
        }

        noxtls_secure_zero((&sig), sizeof(sig));
        sig.size = ecc_key.curve->size;
        rc = noxtls_ecdsa_sign(&ecc_key, data, data_len, &sig, hash_algo);
        (void)noxtls_ecc_key_free(&ecc_key);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }

        r_enc_len = noxtls_asn1_put_integer(r_enc, sizeof(r_enc), sig.r, sig.size);
        s_enc_len = noxtls_asn1_put_integer(s_enc, sizeof(s_enc), sig.s, sig.size);
        if((r_enc_len == 0U) || (s_enc_len == 0U)) {
            return NOXTLS_RETURN_FAILED;
        }
        seq_len = r_enc_len + s_enc_len;

        der_buf = (uint8_t *)NOXTLS_MALLOC(der_buf_size);
        if(der_buf == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        if(seq_len > (der_buf_size - 8U)) {
            (void)noxtls_free(der_buf);
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_copy_u8((uint8_t *)(void *)(der_buf), (size_t)r_enc_len, (const uint8_t *)(const void *)(r_enc), (size_t)r_enc_len);
        noxtls_copy_u8((uint8_t *)(void *)(&der_buf[r_enc_len]), (size_t)s_enc_len, (const uint8_t *)(const void *)(s_enc), (size_t)s_enc_len);
        total = noxtls_asn1_put_sequence(out_der, out_max, der_buf, seq_len);
        (void)noxtls_free(der_buf);
        if(total == 0U) {
            return NOXTLS_RETURN_FAILED;
        }
        *out_len = total;
        return NOXTLS_RETURN_SUCCESS;
    }

    if(pk.key_type == X509_PRIVATE_KEY_RSA) {
        /*
         * RSA: PKCS#1 v1.5 signature. The signature is a single big-endian
         * integer of exactly key_bytes; X.509 wraps that raw value in a
         * BIT STRING via the caller (noxtls_asn1_put_bit_string).
         */
        rsa_key_t rsa_key;
        uint32_t sig_len = 0U;

        rc = noxtls_x509_private_key_to_rsa_key(&pk, &rsa_key);
        (void)noxtls_x509_private_key_free(&pk);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            CERT_DEBUG_PRINT("x509_private_key_sign_data: to_rsa_key failed rc=%d\n", rc);
            return rc;
        }

        if(out_max < rsa_key.key_bytes) {
            (void)noxtls_rsa_key_free(&rsa_key);
            return NOXTLS_RETURN_FAILED;
        }

        sig_len = out_max;
        rc = noxtls_rsa_sign(&rsa_key, data, data_len, out_der, &sig_len, hash_algo);
        (void)noxtls_rsa_key_free(&rsa_key);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            CERT_DEBUG_PRINT("x509_private_key_sign_data: rsa_sign failed rc=%d\n", rc);
            return rc;
        }
        *out_len = sig_len;
        return NOXTLS_RETURN_SUCCESS;
    }

#if NOXTLS_FEATURE_ED25519
    if(pk.key_type == X509_PRIVATE_KEY_ED25519) {
        uint8_t seed_buf[32];
        uint32_t slen = 0U;
        const uint8_t *seed = noxtls_x509_private_key_get_eddsa_seed(&pk, &slen);
        (void)hash_algo;
        if((seed == NULL) || (slen != sizeof(seed_buf)) || (out_max < NOXTLS_ED25519_SIGNATURE_SIZE)) {
            (void)noxtls_x509_private_key_free(&pk);
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_copy_u8((uint8_t *)(void *)(seed_buf), sizeof(seed_buf), (const uint8_t *)(const void *)(seed), sizeof(seed_buf));
        (void)noxtls_x509_private_key_free(&pk);
        rc = noxtls_ed25519_sign(seed_buf, data, data_len, out_der);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        *out_len = NOXTLS_ED25519_SIGNATURE_SIZE;
        return NOXTLS_RETURN_SUCCESS;
    }
#endif

#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
    if(pk.key_type == X509_PRIVATE_KEY_ED448) {
        uint8_t seed_buf[57];
        uint32_t slen = 0U;
        const uint8_t *seed = noxtls_x509_private_key_get_eddsa_seed(&pk, &slen);
        (void)hash_algo;
        if((seed == NULL) || (slen != sizeof(seed_buf)) || (out_max < NOXTLS_ED448_SIGNATURE_SIZE)) {
            (void)noxtls_x509_private_key_free(&pk);
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_copy_u8((uint8_t *)(void *)(seed_buf), sizeof(seed_buf), (const uint8_t *)(const void *)(seed), sizeof(seed_buf));
        (void)noxtls_x509_private_key_free(&pk);
        rc = noxtls_ed448_sign(seed_buf, data, data_len, out_der);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        *out_len = NOXTLS_ED448_SIGNATURE_SIZE;
        return NOXTLS_RETURN_SUCCESS;
    }
#endif

#if NOXTLS_FEATURE_ML_DSA
    if(pk.key_type == X509_PRIVATE_KEY_ML_DSA) {
        noxtls_mldsa_param_t param = (noxtls_mldsa_param_t)pk.pqc_param;
        uint32_t sig_max = noxtls_mldsa_signature_len(param);
        uint32_t sig_len = sig_max;
        (void)hash_algo; /* ML-DSA is hash-and-sign internal; caller-supplied digest unused. */
        if(sig_max == 0U || out_max < sig_max ||
           pk.pqc_secret_key == NULL || pk.pqc_secret_key_len == 0U) {
            (void)noxtls_x509_private_key_free(&pk);
            return NOXTLS_RETURN_FAILED;
        }
        rc = noxtls_mldsa_sign(param, pk.pqc_secret_key, data, data_len, out_der, &sig_len);
        (void)noxtls_x509_private_key_free(&pk);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        *out_len = sig_len;
        return NOXTLS_RETURN_SUCCESS;
    }
#endif

#if NOXTLS_FEATURE_SLH_DSA
    if(pk.key_type == X509_PRIVATE_KEY_SLH_DSA) {
        noxtls_slhdsa_param_t param = (noxtls_slhdsa_param_t)pk.pqc_param;
        uint32_t sig_max = noxtls_slhdsa_signature_len(param);
        uint32_t sig_len = sig_max;
        (void)hash_algo;
        if(sig_max == 0U || out_max < sig_max ||
           pk.pqc_secret_key == NULL || pk.pqc_secret_key_len == 0U) {
            (void)noxtls_x509_private_key_free(&pk);
            return NOXTLS_RETURN_FAILED;
        }
        rc = noxtls_slhdsa_sign(param, pk.pqc_secret_key, data, data_len, out_der, &sig_len);
        (void)noxtls_x509_private_key_free(&pk);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        *out_len = sig_len;
        return NOXTLS_RETURN_SUCCESS;
    }
#endif
#if NOXTLS_FEATURE_FALCON
    if(pk.key_type == X509_PRIVATE_KEY_FALCON) {
        noxtls_falcon_param_t param = (noxtls_falcon_param_t)pk.pqc_param;
        uint32_t sig_max = noxtls_falcon_signature_len(param);
        uint32_t sig_len = sig_max;
        (void)hash_algo;
        if(sig_max == 0U || out_max < sig_max ||
           pk.pqc_secret_key == NULL || pk.pqc_secret_key_len == 0U) {
            (void)noxtls_x509_private_key_free(&pk);
            return NOXTLS_RETURN_FAILED;
        }
        rc = noxtls_falcon_sign(param, pk.pqc_secret_key, data, data_len, out_der, &sig_len);
        (void)noxtls_x509_private_key_free(&pk);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        *out_len = sig_len;
        return NOXTLS_RETURN_SUCCESS;
    }
#endif

    CERT_DEBUG_PRINT("x509_private_key_sign_data: key_type=%d (unsupported)\n", pk.key_type);
    (void)noxtls_x509_private_key_free(&pk);
    return NOXTLS_RETURN_FAILED;
}

/**
 * @brief Get the EdDSA seed from a X.509 private key
 *
 * This function gets the EdDSA seed from a X.509 private key.
 *
 * @param[in] key The X.509 private key structure to get the EdDSA seed from.
 * @param[out] out_len The length of the EdDSA seed.
 *
 * @return The EdDSA seed.
 */
const uint8_t *noxtls_x509_private_key_get_eddsa_seed(const x509_private_key_t *key, uint32_t *out_len)
{
    if((key == NULL) || (out_len == NULL)) {
        return NULL;
    }
    *out_len = 0U;
#if NOXTLS_FEATURE_ED25519
    if((key->key_type == X509_PRIVATE_KEY_ED25519) && (key->eddsa_seed != NULL) && (key->eddsa_seed_len == 32U)) {
        *out_len = 32U;
        return key->eddsa_seed;
    }
#endif
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
    if((key->key_type == X509_PRIVATE_KEY_ED448) && (key->eddsa_seed != NULL) && (key->eddsa_seed_len == 57U)) {
        *out_len = 57U;
        return key->eddsa_seed;
    }
#endif
    return NULL;
}

/**
 * @brief Get the PQC secret from a X.509 private key
 *
 * This function gets the PQC secret from a X.509 private key.
 *
 * @param[in] key The X.509 private key structure to get the PQC secret from.
 * @param[out] out_len The length of the PQC secret.
 * @param[out] out_param The parameter set value of the PQC secret.

 * @return The PQC secret as a pointer to the buffer.
 */
const uint8_t *noxtls_x509_private_key_get_pqc_secret(const x509_private_key_t *key, uint32_t *out_len, uint32_t *out_param)
{
    if(out_len != NULL) {
        *out_len = 0U;
    }
    if(out_param != NULL) {
        *out_param = 0;
    }
    if((key == NULL) || (out_len == NULL) || (out_param == NULL)) {
        return NULL;
    }
    if((key->key_type != X509_PRIVATE_KEY_ML_DSA) &&
       (key->key_type != X509_PRIVATE_KEY_SLH_DSA) &&
       (key->key_type != X509_PRIVATE_KEY_FALCON)) {
        return NULL;
    }
    if((key->pqc_secret_key == NULL) || (key->pqc_secret_key_len == 0U)) {
        return NULL;
    }
    *out_len = key->pqc_secret_key_len;
    *out_param = key->pqc_param;
    return key->pqc_secret_key;
}

/**
 * @brief Convert X.509 private key to ECC key structure (legacy wrapper)
 *
 * This function converts a X.509 private key to a ECC key structure.
 *
 * @param[in] key The X.509 private key structure to convert.
 * @param[in] ecc_key The ECC key structure to convert to.
 *
 * @return @see noxtls_return_t
 */
noxtls_return_t x509_private_key_to_ecc_key(const x509_private_key_t *key, void *ecc_key)
{
    if((key == NULL) || (ecc_key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    return noxtls_x509_private_key_to_ecc_key(key, (ecc_key_t *)ecc_key);
}

/**
 * @brief Print OID in readable format
 *
 * This function prints an OID in readable format.
 *
 * @param[in] label The label to print.
 * @param[in] oid The OID to print.
 * @param[in] oid_len The length of the OID.
 *
 */
void noxtls_x509_debug_print_oid(const uint8_t *label, const uint8_t *oid_bytes, uint32_t oid_bytes_len)
{
    if(label != NULL) {
        (void)noxtls_debug_printf((const uint8_t *)"%s: ", label);
    }

    if((oid_bytes == NULL) || (oid_bytes_len == 0U)) {
        (void)noxtls_debug_printf((const uint8_t *)"(empty)\n");
        return;
    }

    /* Print OID in dot notation (oid_bytes_len > 0U guaranteed by check above) */
    {
        uint32_t first = (uint32_t)oid_bytes[0] / 40U;
        uint32_t second = (uint32_t)oid_bytes[0] % 40U;
        (void)noxtls_debug_printf((const uint8_t *)"%u.%u", first, second);

        uint32_t oid_arc = 0U;
        uint32_t i = 0U;
        for(i = 1U; i < oid_bytes_len; i += 1U) {
            oid_arc = (oid_arc << 7U) | ((uint32_t)oid_bytes[i] & 0x7FU);
            if((oid_bytes[i] & 0x80U) == 0U) {
                (void)noxtls_debug_printf((const uint8_t *)".%u", oid_arc);
                oid_arc = 0U;
            }
        }
    }
    (void)noxtls_debug_printf((const uint8_t *)"\n");
}

/**
 * @brief Print hex data with formatting
 *
 * This function prints hex data with formatting.
 *
 * @param[in] label The label to print.
 * @param[in] data The data to print.
 * @param[in] len The length of the data.
 * @param[in] verbose The verbose level.
 *
 */
/* NOLINTNEXTLINE(bugprone-easily-swappable-parameters): debug helper preserves existing (label,data,len,verbose) convention. */
void noxtls_x509_debug_print_hex(const uint8_t *label, const uint8_t *data, uint32_t len, uint8_t verbose)
{
    uint32_t i = 0U;

    if(label != NULL) {
        (void)noxtls_debug_printf((const uint8_t *)"%s", label);
    }

    if((data == NULL) || (len == 0U)) {
        (void)noxtls_debug_printf((const uint8_t *)"(empty)\n");
        return;
    }

    if(verbose != 0U) {
        /* Print with line breaks every 16 bytes */
        (void)noxtls_debug_printf((const uint8_t *)" (%u bytes):\n", len);
        for(i = 0U; i < len; i += 1U) {
            if((i > 0U) && ((i % 16U) == 0U)) {
                (void)noxtls_debug_printf((const uint8_t *)"\n    ");
            }
            (void)noxtls_debug_printf((const uint8_t *)"%02x ", data[i]);
        }
        (void)noxtls_debug_printf((const uint8_t *)"\n");
    } else {
        /* Print compact format */
        (void)noxtls_debug_printf((const uint8_t *)" (%u bytes): ", len);
        for(i = 0U; (i < len) && (i < 32U); i += 1U) {
            (void)noxtls_debug_printf((const uint8_t *)"%02x", data[i]);
        }
        if(len > 32U) {
            (void)noxtls_debug_printf((const uint8_t *)"...");
        }
        (void)noxtls_debug_printf((const uint8_t *)"\n");
    }
}

/**
 * @brief Debug print certificate information
 *
 * This function prints certificate information.
 *
 * @param[in] cert The certificate to print.
 * @param[in] verbose The verbose level.
 *
 * @return @see noxtls_return_t
 */
noxtls_return_t noxtls_x509_certificate_debug_print(x509_certificate_t *cert, uint8_t verbose)
{
    uint32_t i = 0U;

    if(cert == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    (void)noxtls_debug_printf((const uint8_t *)"\n");
    (void)noxtls_debug_printf((const uint8_t *)"========================================\n");
    (void)noxtls_debug_printf((const uint8_t *)"X.509 Certificate Debug Information\n");
    (void)noxtls_debug_printf((const uint8_t *)"========================================\n\n");

    if(cert->parsed == 0) {
        (void)noxtls_debug_printf((const uint8_t *)"Status: NOT PARSED\n");
        if(cert->raw_data != NULL) {
            (void)noxtls_debug_printf((const uint8_t *)"Raw data available: %u bytes\n", cert->raw_data_len);
        }
        return NOXTLS_RETURN_FAILED;
    }

    (void)noxtls_debug_printf((const uint8_t *)"Status: PARSED\n\n");

    /* Basic Information */
    (void)noxtls_debug_printf((const uint8_t *)"--- Basic Information ---\n");
    (void)noxtls_debug_printf((const uint8_t *)"Version: %d", cert->version);
    if(cert->version == 0U) {
        (void)noxtls_debug_printf((const uint8_t *)" (v1)");
    } else if(cert->version == 1U) {
        (void)noxtls_debug_printf((const uint8_t *)" (v2)");
    } else if(cert->version == 2U) {
        (void)noxtls_debug_printf((const uint8_t *)" (v3)");
    }
     else {
         /* MISRA 15.7: no remaining alternative */
     }
    (void)noxtls_debug_printf((const uint8_t *)"\n");

    (void)noxtls_debug_printf((const uint8_t *)"Raw Data Length: %u bytes\n", cert->raw_data_len);
    (void)noxtls_debug_printf((const uint8_t *)"\n");

    /* Serial Number */
    (void)noxtls_debug_printf((const uint8_t *)"--- Serial Number ---\n");
    noxtls_x509_debug_print_hex(NULL, cert->serial_number, cert->serial_number_len, verbose);
    (void)noxtls_debug_printf((const uint8_t *)"\n");

    /* Signature Algorithm */
    (void)noxtls_debug_printf((const uint8_t *)"--- Signature Algorithm ---\n");
    noxtls_x509_debug_print_oid(NULL, cert->signature_algorithm_oid, cert->signature_algorithm_oid_len);
    (void)noxtls_debug_printf((const uint8_t *)"\n");

    /* Issuer */
    (void)noxtls_debug_printf((const uint8_t *)"--- Issuer ---\n");
    (void)noxtls_debug_printf((const uint8_t *)"Distinguished Name: %s\n", (cert->issuer_dn[0] != 0U) ? cert->issuer_dn : "(not parsed)");
    noxtls_x509_debug_print_hex(NULL, cert->issuer, cert->issuer_len, verbose);
    (void)noxtls_debug_printf((const uint8_t *)"\n");

    /* Validity */
    (void)noxtls_debug_printf((const uint8_t *)"--- Validity ---\n");
    (void)noxtls_debug_printf((const uint8_t *)"Not Before: ");
    for(i = 0U; (i < 15U) && (cert->not_before[i] != 0U); i += 1U) {
        (void)noxtls_debug_printf((const uint8_t *)"%c", cert->not_before[i]);
    }
    (void)noxtls_debug_printf((const uint8_t *)"\n");

    (void)noxtls_debug_printf((const uint8_t *)"Not After: ");
    for(i = 0U; (i < 15U) && (cert->not_after[i] != 0U); i += 1U) {
        (void)noxtls_debug_printf((const uint8_t *)"%c", cert->not_after[i]);
    }
    (void)noxtls_debug_printf((const uint8_t *)"\n");
    (void)noxtls_debug_printf((const uint8_t *)"\n");

    /* Subject */
    (void)noxtls_debug_printf((const uint8_t *)"--- Subject ---\n");
    (void)noxtls_debug_printf((const uint8_t *)"Distinguished Name: %s\n", (cert->subject_dn[0] != 0U) ? cert->subject_dn : "(not parsed)");
    noxtls_x509_debug_print_hex(NULL, cert->subject, cert->subject_len, verbose);
    (void)noxtls_debug_printf((const uint8_t *)"\n");

    /* Public Key Information */
    (void)noxtls_debug_printf((const uint8_t *)"--- Public Key Information ---\n");
    noxtls_x509_debug_print_oid(NULL, cert->public_key_algorithm_oid, cert->public_key_algorithm_oid_len);

    if(cert->rsa_modulus != NULL) {
        (void)noxtls_debug_printf((const uint8_t *)"Key Type: RSA\n");
        noxtls_x509_debug_print_hex(NULL, cert->rsa_modulus, cert->rsa_modulus_len, verbose);
        noxtls_x509_debug_print_hex(NULL, cert->rsa_exponent, cert->rsa_exponent_len, verbose);
        (void)noxtls_debug_printf((const uint8_t *)"Key Size: %u bits\n", cert->rsa_modulus_len * 8U);
    } else if(cert->ecc_public_key != NULL) {
        (void)noxtls_debug_printf((const uint8_t *)"Key Type: ECC\n");
        noxtls_x509_debug_print_oid(NULL, cert->ecc_curve_oid, cert->ecc_curve_oid_len);
        noxtls_x509_debug_print_hex(NULL, cert->ecc_public_key, cert->ecc_public_key_len, verbose);
    } else {
        (void)noxtls_debug_printf((const uint8_t *)"Key Type: Unknown\n");
        noxtls_x509_debug_print_hex(NULL, cert->public_key, cert->public_key_len, verbose);
    }
    (void)noxtls_debug_printf((const uint8_t *)"\n");

    /* Extensions (v3) */
    if((cert->version >= 2U) && (cert->extensions != NULL)) {
        (void)noxtls_debug_printf((const uint8_t *)"--- Extensions (v3) ---\n");
        noxtls_x509_debug_print_hex(NULL, cert->extensions, cert->extensions_len, verbose);
        (void)noxtls_debug_printf((const uint8_t *)"\n");
    }

    /* Signature */
    (void)noxtls_debug_printf((const uint8_t *)"--- Signature ---\n");
    if(cert->signature != NULL) {
        noxtls_x509_debug_print_hex(NULL, cert->signature, cert->signature_len, verbose);
    } else {
        /* MISRA 15.7: intentional empty final else */
        (void)0;
    }
    (void)noxtls_debug_printf((const uint8_t *)"\n");

    /* Raw Data (if verbose) */
    if((verbose != 0U) && (cert->raw_data != NULL)) {
        (void)noxtls_debug_printf((const uint8_t *)"--- Raw Certificate Data ---\n");
        noxtls_x509_debug_print_hex(NULL, cert->raw_data, cert->raw_data_len, 1);
        (void)noxtls_debug_printf((const uint8_t *)"\n");
    }

    (void)noxtls_debug_printf((const uint8_t *)"========================================\n");
    (void)noxtls_debug_printf((const uint8_t *)"\n");

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Debug print private key information
 *
 * This function prints private key information.
 *
 * @param[in] key The private key to print.
 * @param[in] verbose The verbose level.
 *
 * @return @see noxtls_return_t
 */
noxtls_return_t noxtls_x509_private_key_debug_print(x509_private_key_t *key, uint8_t verbose)
{
    if(key == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    (void)noxtls_debug_printf((const uint8_t *)"\n");
    (void)noxtls_debug_printf((const uint8_t *)"========================================\n");
    (void)noxtls_debug_printf((const uint8_t *)"X.509 Private Key Debug Information\n");
    (void)noxtls_debug_printf((const uint8_t *)"========================================\n\n");

    if(key->parsed == 0) {
        (void)noxtls_debug_printf((const uint8_t *)"Status: NOT PARSED\n");
        if(key->raw_data != NULL) {
            (void)noxtls_debug_printf((const uint8_t *)"Raw data available: %u bytes\n", key->raw_data_len);
        }
        return NOXTLS_RETURN_FAILED;
    }

    (void)noxtls_debug_printf((const uint8_t *)"Status: PARSED\n\n");

    /* Key Type and Format */
    (void)noxtls_debug_printf((const uint8_t *)"--- Key Information ---\n");
    if(key->key_type == X509_PRIVATE_KEY_RSA) {
        (void)noxtls_debug_printf((const uint8_t *)"Key Type: RSA\n");
    } else if(key->key_type == X509_PRIVATE_KEY_ECC) {
        (void)noxtls_debug_printf((const uint8_t *)"Key Type: ECC\n");
    } else if(key->key_type == X509_PRIVATE_KEY_ED25519) {
        (void)noxtls_debug_printf((const uint8_t *)"Key Type: Ed25519\n");
    } else if(key->key_type == X509_PRIVATE_KEY_ED448) {
        (void)noxtls_debug_printf((const uint8_t *)"Key Type: Ed448\n");
    } else {
        /* MISRA 15.7: intentional empty final else */
        (void)0;
    }

    if(key->format == X509_PRIVATE_KEY_FORMAT_PKCS1) {
        (void)noxtls_debug_printf((const uint8_t *)"Format: PKCS#1\n");
    } else if(key->format == X509_PRIVATE_KEY_FORMAT_PKCS8) {
        (void)noxtls_debug_printf((const uint8_t *)"Format: PKCS#8\n");
    } else if(key->format == X509_PRIVATE_KEY_FORMAT_SEC1) {
        (void)noxtls_debug_printf((const uint8_t *)"Format: SEC1\n");
    } else {
        /* MISRA 15.7: intentional empty final else */
        (void)0;
    }

    (void)noxtls_debug_printf((const uint8_t *)"Encrypted: %s\n", (key->encrypted != 0) ? "YES" : "NO");
    (void)noxtls_debug_printf((const uint8_t *)"Raw Data Length: %u bytes\n", key->raw_data_len);
    (void)noxtls_debug_printf((const uint8_t *)"\n");

    if(key->key_type == X509_PRIVATE_KEY_RSA) {
        (void)noxtls_debug_printf((const uint8_t *)"--- RSA Private Key Components ---\n");

        if(key->rsa_modulus != NULL) {
            noxtls_x509_debug_print_hex(NULL, key->rsa_modulus, key->rsa_modulus_len, verbose);
            (void)noxtls_debug_printf((const uint8_t *)"Key Size: %u bits\n", key->rsa_modulus_len * 8U);
        }

        if(key->rsa_public_exponent != NULL) {
            noxtls_x509_debug_print_hex(NULL, key->rsa_public_exponent, key->rsa_public_exponent_len, verbose);
        }

        if(key->rsa_private_exponent != NULL) {
            noxtls_x509_debug_print_hex(NULL, key->rsa_private_exponent, key->rsa_private_exponent_len, verbose);
        }

        if(key->rsa_prime1 != NULL) {
            noxtls_x509_debug_print_hex(NULL, key->rsa_prime1, key->rsa_prime1_len, verbose);
        }

        if(key->rsa_prime2 != NULL) {
            noxtls_x509_debug_print_hex(NULL, key->rsa_prime2, key->rsa_prime2_len, verbose);
        }

        if(key->rsa_exponent1 != NULL) {
            noxtls_x509_debug_print_hex(NULL, key->rsa_exponent1, key->rsa_exponent1_len, verbose);
        }

        if(key->rsa_exponent2 != NULL) {
            noxtls_x509_debug_print_hex(NULL, key->rsa_exponent2, key->rsa_exponent2_len, verbose);
        }

        if(key->rsa_coefficient != NULL) {
            noxtls_x509_debug_print_hex(NULL, key->rsa_coefficient, key->rsa_coefficient_len, verbose);
        }

    } else if(key->key_type == X509_PRIVATE_KEY_ECC) {
        (void)noxtls_debug_printf((const uint8_t *)"--- ECC Private Key Components ---\n");

        if(key->ecc_private_key != NULL) {
            noxtls_x509_debug_print_hex(NULL, key->ecc_private_key, key->ecc_private_key_len, verbose);
        }

        if(key->ecc_curve_oid_len > 0U) {
            noxtls_x509_debug_print_oid(NULL, key->ecc_curve_oid, key->ecc_curve_oid_len);
        }

        if(key->ecc_public_key != NULL) {
            noxtls_x509_debug_print_hex(NULL, key->ecc_public_key, key->ecc_public_key_len, verbose);
        }
    } else if((key->key_type == X509_PRIVATE_KEY_ED25519) || (key->key_type == X509_PRIVATE_KEY_ED448)) {
        (void)noxtls_debug_printf((const uint8_t *)"--- EdDSA private key (RFC 8410 seed) ---\n");
        if(key->eddsa_seed != NULL) {
            noxtls_x509_debug_print_hex(NULL, key->eddsa_seed, key->eddsa_seed_len, verbose);
        }
    }
     else {
         /* MISRA 15.7: no remaining alternative */
     }

    (void)noxtls_debug_printf((const uint8_t *)"\n");

    /* Encryption Info */
    if(key->encrypted != 0) {
        (void)noxtls_debug_printf((const uint8_t *)"--- Encryption Information ---\n");
        noxtls_x509_debug_print_oid(NULL, key->encryption_algorithm_oid, key->encryption_algorithm_oid_len);
        (void)noxtls_debug_printf((const uint8_t *)"Use noxtls_x509_private_key_parse_der_with_password or parse_pem_with_password to decrypt.\n");
        (void)noxtls_debug_printf((const uint8_t *)"\n");
    }

    /* Raw Data (if verbose) */
    if((verbose != 0U) && (key->raw_data != NULL)) {
        (void)noxtls_debug_printf((const uint8_t *)"--- Raw Private Key Data ---\n");
        noxtls_x509_debug_print_hex(NULL, key->raw_data, key->raw_data_len, 1);
        (void)noxtls_debug_printf((const uint8_t *)"\n");
    }

    (void)noxtls_debug_printf((const uint8_t *)"========================================\n");
    (void)noxtls_debug_printf((const uint8_t *)"\n");

    return NOXTLS_RETURN_SUCCESS;
}
