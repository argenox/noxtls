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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stddef.h>

#include "noxtls_config.h"
#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_x509.h"
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
#include <time.h>
#endif

/* RFC 5280 id-ce extension OIDs (DER) */
/* id-ce-subjectAltName = 2.5.29.17 */
static const uint8_t oid_subject_alt_name[] = { 0x55, 0x1D, 0x11 };
/* id-ce-keyUsage = 2.5.29.15 */
static const uint8_t oid_key_usage[] = { 0x55, 0x1D, 0x0F };
/* id-ce-basicConstraints = 2.5.29.19 */
static const uint8_t oid_basic_constraints[] = { 0x55, 0x1D, 0x13 };
/* id-ce-extKeyUsage = 2.5.29.37 */
static const uint8_t oid_ext_key_usage[] = { 0x55, 0x1D, 0x25 };
/* id-ce-authorityKeyIdentifier = 2.5.29.35 */
static const uint8_t oid_authority_key_id[] = { 0x55, 0x1D, 0x23 };
/* id-ce-subjectKeyIdentifier = 2.5.29.14 */
static const uint8_t oid_subject_key_id[] = { 0x55, 0x1D, 0x0E };
/* id-ce-certificatePolicies = 2.5.29.32 */
static const uint8_t oid_certificate_policies[] = { 0x55, 0x1D, 0x20 };
/* id-ce-cRLDistributionPoints = 2.5.29.31 */
static const uint8_t oid_crl_distribution_points[] = { 0x55, 0x1D, 0x1F };
/* id-ce-nameConstraints = 2.5.29.30 */
static const uint8_t oid_name_constraints[] = { 0x55, 0x1D, 0x1E };
/* id-ce-policyConstraints = 2.5.29.36 */
static const uint8_t oid_policy_constraints[] = { 0x55, 0x1D, 0x24 };
/* id-ce-inhibitAnyPolicy = 2.5.29.54 */
static const uint8_t oid_inhibit_any_policy[] = { 0x55, 0x1D, 0x36 };
/* id-kp OIDs (Extended Key Usage): 1.3.6.1.5.5.7.3.x */
static const uint8_t oid_kp_server_auth[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };
static const uint8_t oid_kp_client_auth[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02 };
static const uint8_t oid_kp_code_signing[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03 };
static const uint8_t oid_kp_email_protection[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04 };
static const uint8_t oid_kp_time_stamping[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08 };
static const uint8_t oid_kp_ocsp_signing[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09 };
/* anyExtendedKeyUsage 2.5.29.37.0 */
static const uint8_t oid_any_eku[] = { 0x55, 0x1D, 0x25, 0x00 };

/* ECC curve OIDs (DER) for noxtls_x509 helpers */
static const uint8_t noxtls_x509_oid_secp192r1[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01};
static const uint8_t noxtls_x509_oid_secp224r1[] = {0x2B, 0x81, 0x04, 0x00, 0x21};
static const uint8_t noxtls_x509_oid_secp256r1[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
static const uint8_t noxtls_x509_oid_secp384r1[] = {0x2B, 0x81, 0x04, 0x00, 0x22};
static const uint8_t noxtls_x509_oid_secp521r1[] = {0x2B, 0x81, 0x04, 0x00, 0x23};
static const uint8_t noxtls_x509_oid_bp256r1[] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07};
static const uint8_t noxtls_x509_oid_bp384r1[] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B};
static const uint8_t noxtls_x509_oid_bp512r1[] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D};
static const uint8_t noxtls_x509_oid_secp192k1[] = {0x2B, 0x81, 0x04, 0x00, 0x1F};
static const uint8_t noxtls_x509_oid_secp224k1[] = {0x2B, 0x81, 0x04, 0x00, 0x20};
static const uint8_t noxtls_x509_oid_secp256k1[] = {0x2B, 0x81, 0x04, 0x00, 0x0A};

static noxtls_x509_unknown_ext_cb_t noxtls_x509_unknown_ext_cb;
static void *noxtls_x509_unknown_ext_user_ctx;

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
 * @brief Open a file
 *
 * @param[in] filename The name of the file to open.
 * @param[in] mode The mode to open the file in.
 *
 * @return The file pointer.
 */
static FILE *noxtls_fopen(const char *filename, const char *mode)
{
#ifdef _MSC_VER
    FILE *fp = NULL;
    if(fopen_s(&fp, filename, mode) != 0) {
        return NULL;
    }
    return fp;
#else
    return fopen(filename, mode);
#endif
}

/* Certificate debug logging disabled (was CERT_DEBUG / CERT_DEBUG_PRINT). */
#define CERT_DEBUG_PRINT(...) ((void)0)

/* Last certificate verification failure detail (single global; not thread-safe). */
static noxtls_cert_verify_failure_info_t s_cert_fail_info;
/*
 * Global trust anchors for TLS certificate verification.
 * Published snapshots are treated as immutable and are never freed in-place,
 * so concurrent verification cannot race a trust-store clear/set into a UAF.
 */
static const x509_certificate_chain_t *s_x509_trust_anchors;
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
    uint32_t i;
    noxtls_return_t rc;
    x509_certificate_chain_t *snapshot;

    if(trust_anchors == NULL || trust_anchors->count == 0U) {
        return NULL;
    }

    snapshot = (x509_certificate_chain_t *)calloc(1, sizeof(x509_certificate_chain_t));
    if(snapshot == NULL) {
        return NULL;
    }
    rc = noxtls_x509_certificate_chain_init(snapshot);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(snapshot);
        return NULL;
    }

    for(i = 0; i < trust_anchors->count; i++) {
        rc = noxtls_x509_certificate_chain_add(snapshot, &trust_anchors->certs[i]);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_x509_certificate_chain_free(snapshot);
            free(snapshot);
            return NULL;
        }
    }

    return snapshot;
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
static void cert_fail_set(noxtls_return_t return_code, const x509_certificate_t *cert, const char *expected_hostname, uint32_t expected_hostname_len, uint32_t cert_index)
{
    memset(&s_cert_fail_info, 0, sizeof(s_cert_fail_info));
    s_cert_fail_info.return_code = return_code;
    s_cert_fail_info.cert_index = cert_index;
    s_cert_fail_info.populated = 1;

    if(cert != NULL) {
        if(cert->not_before[0] != 0) {
            uint32_t n = 0;
            while(n < NOXTLS_CERT_FAIL_TIME_MAX - 1 && cert->not_before[n] != 0) {
                s_cert_fail_info.not_before[n] = (char)cert->not_before[n];
                n++;
            }
            s_cert_fail_info.not_before[n] = '\0';
        }
        if(cert->not_after[0] != 0) {
            uint32_t n = 0;
            while(n < NOXTLS_CERT_FAIL_TIME_MAX - 1 && cert->not_after[n] != 0) {
                s_cert_fail_info.not_after[n] = (char)cert->not_after[n];
                n++;
            }
            s_cert_fail_info.not_after[n] = '\0';
        }
        if(cert->subject_dn[0] != '\0') {
            uint32_t n = 0;
            while(n < NOXTLS_CERT_FAIL_DN_HOSTNAME_MAX - 1 && cert->subject_dn[n] != '\0') {
                s_cert_fail_info.subject_dn[n] = cert->subject_dn[n];
                n++;
            }
            s_cert_fail_info.subject_dn[n] = '\0';
        }
    }

    if(expected_hostname != NULL) {
        uint32_t n = 0;
        if(expected_hostname_len == 0) {
            while(n < NOXTLS_CERT_FAIL_DN_HOSTNAME_MAX - 1 && expected_hostname[n] != '\0') {
                s_cert_fail_info.expected_hostname[n] = expected_hostname[n];
                n++;
            }
        } else {
            while(n < NOXTLS_CERT_FAIL_DN_HOSTNAME_MAX - 1 && n < expected_hostname_len && expected_hostname[n] != '\0') {
                s_cert_fail_info.expected_hostname[n] = expected_hostname[n];
                n++;
            }
        }
        s_cert_fail_info.expected_hostname[n] = '\0';
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
    memset(&s_cert_fail_info, 0, sizeof(s_cert_fail_info));
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
        memcpy(out, &s_cert_fail_info, sizeof(noxtls_cert_verify_failure_info_t));
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
    uint32_t length = 0;

    if(ptr >= end) {
        return 0;
    }

    if(*ptr & 0x80) {
        /* Long form */
        uint8_t len_bytes = *ptr & 0x7F;
        ptr++;

        if(len_bytes == 0 || len_bytes > 4 || (size_t)(end - ptr) < (size_t)len_bytes) {
            return 0;
        }

        uint32_t i;
        for(i = 0; i < len_bytes; i++) {
            length = (length << 8) | *ptr++;
        }
    } else {
        /* Short form */
        length = *ptr & 0x7F;
        ptr++;
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
    if(*data >= end) {
        return NOXTLS_RETURN_FAILED;
    }

    uint8_t tag = **data;
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
static noxtls_return_t asn1_get_oid(const uint8_t **data, const uint8_t *end, uint8_t *oid, uint32_t *oid_len)
{
    uint32_t len;

    if(asn1_get_tag(data, end, 0x06) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    len = asn1_get_length(data, end);
    if(len == 0 || len > 32 || (size_t)(end - *data) < (size_t)len) {
        return NOXTLS_RETURN_FAILED;
    }

    if(oid != NULL && oid_len != NULL) {
        memcpy(oid, *data, len);
        *oid_len = len;
    }
    *data += len;

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
    uint32_t len;

    if(asn1_get_tag(data, end, 0x02) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    len = asn1_get_length(data, end);

    if(len == 0 || (size_t)(end - *data) < (size_t)len) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Check buffer size only if buffer is provided */
    if(integer != NULL && integer_len != NULL) {
        if(len > *integer_len) {
            *integer_len = len;
            *data += len;  /* Skip the data */
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(integer, *data, len);
        *integer_len = len;
    } else if(integer_len != NULL) {
        *integer_len = len;
    }

    *data += len;

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
    if(asn1_get_tag(data, end, 0x30) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    *seq_len = asn1_get_length(data, end);

    /* Zero-length SEQUENCE is valid (e.g. empty X.509 subject DN: 30 00). */
    if((size_t)(end - *data) < (size_t)(*seq_len)) {
        return NOXTLS_RETURN_FAILED;
    }

    *seq_data = *data;
    *data += *seq_len;

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
    if(asn1_get_tag(data, end, 0x04) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    *out_len = asn1_get_length(data, end);
    if((size_t)(end - *data) < (size_t)(*out_len)) {
        return NOXTLS_RETURN_FAILED;
    }

    *out_data = *data;
    *data += *out_len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Gets the boolean of an ASN.1 encoded value.
 *
 * This function gets the boolean of an ASN.1 encoded value by parsing the boolean field.
 *
 * @param[in] data The pointer to the ASN.1 encoded value.
 * @param[in] end The pointer to the end of the ASN.1 encoded value.
 * @param[out] out_value The pointer to the buffer to receive the boolean.
 * @return The return code of the function.
 */
static noxtls_return_t asn1_get_boolean(const uint8_t **data, const uint8_t *end, int *out_value)
{
    uint32_t len;
    if(asn1_get_tag(data, end, 0x01) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    len = asn1_get_length(data, end);
    if(len != 1 || (size_t)(end - *data) < 1U) {
        return NOXTLS_RETURN_FAILED;
    }

    *out_value = (**data != 0) ? 1 : 0;
    *data += 1;
    return NOXTLS_RETURN_SUCCESS;
}

#if NOXTLS_FEATURE_AES_CBC
/* OIDs for EncryptedPrivateKeyInfo (RFC 5208) and PBES2/PBKDF2 (RFC 8018). DER-encoded. */
/* id-PBES2  1.2.840.113549.1.5.13 */
static const uint8_t oid_pbes2[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D };
/* id-PBKDF2 1.2.840.113549.1.5.12 */
static const uint8_t oid_pbkdf2[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C };
/* id-aes128-CBC 2.16.840.1.101.3.4.1.2 */
static const uint8_t oid_aes128_cbc[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02 };
/* id-aes256-CBC 2.16.840.1.101.3.4.1.42 */
static const uint8_t oid_aes256_cbc[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A };

#define SHA1_OUT_LEN 20
#define NOXTLS_AES_BLOCK_LEN 16

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
    return (a_len == b_len && memcmp(a, b, a_len) == 0);
}

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
    static const uint8_t oid_prefix[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03};
    uint8_t last;

    if(oid == NULL || param == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(oid_len != sizeof(oid_prefix) + 1U || memcmp(oid, oid_prefix, sizeof(oid_prefix)) != 0) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    last = oid[sizeof(oid_prefix)];
    if(last < 0x14u || last > 0x1Fu) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    *param = (noxtls_slhdsa_param_t)((uint32_t)NOXTLS_SLHDSA_SHA2_128S + (uint32_t)(last - 0x14u));
    return NOXTLS_RETURN_SUCCESS;
}
#endif

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
    uint32_t i;

    if(key == NULL || msg == NULL || mac == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    memset(ipad, 0x36, 64);
    memset(opad, 0x5C, 64);

    if(key_len > 64) {
        if(noxtls_sha1_init(&ctx, NOXTLS_HASH_SHA1) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if(noxtls_sha1_update(&ctx, (const uint8_t*)key, key_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if(noxtls_sha1_finish(&ctx, tmp) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        key = tmp;
        key_len = SHA1_OUT_LEN;
    }

    for(i = 0; i < key_len; i++) {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    if(noxtls_sha1_init(&ctx, NOXTLS_HASH_SHA1) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(noxtls_sha1_update(&ctx, ipad, 64) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(noxtls_sha1_update(&ctx, (const uint8_t*)msg, msg_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(noxtls_sha1_finish(&ctx, mac) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(noxtls_sha1_init(&ctx, NOXTLS_HASH_SHA1) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(noxtls_sha1_update(&ctx, opad, 64) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(noxtls_sha1_update(&ctx, mac, SHA1_OUT_LEN) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(noxtls_sha1_finish(&ctx, mac) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
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
    uint32_t j;
    uint32_t k;
    uint32_t blocks;
    uint32_t block_index;

    if(password == NULL || salt == NULL || params == NULL || out == NULL || params->iterations == 0) {
        return NOXTLS_RETURN_NULL;
    }

    if(params->salt_len > 0xFFFF - 4) return NOXTLS_RETURN_FAILED;
    block_input = (uint8_t*)malloc(params->salt_len + 4U);
    if(block_input == NULL) return NOXTLS_RETURN_FAILED;
    memcpy(block_input, salt, params->salt_len);
    blocks = (params->key_len + SHA1_OUT_LEN - 1U) / SHA1_OUT_LEN;

    for(block_index = 1; block_index <= blocks; block_index++) {
        block_input[params->salt_len + 0U] = (uint8_t)(block_index >> 24);
        block_input[params->salt_len + 1U] = (uint8_t)(block_index >> 16);
        block_input[params->salt_len + 2U] = (uint8_t)(block_index >> 8);
        block_input[params->salt_len + 3U] = (uint8_t)(block_index);

        if(hmac_sha1(password, password_len, block_input, params->salt_len + 4U, u) != NOXTLS_RETURN_SUCCESS) {
            free(block_input);
            return NOXTLS_RETURN_FAILED;
        }

        for(k = 0; k < SHA1_OUT_LEN; k++)
            t[k] = u[k];

        for(j = 1; j < params->iterations; j++) {
            if(hmac_sha1(password, password_len, u, SHA1_OUT_LEN, u) != NOXTLS_RETURN_SUCCESS) {
                free(block_input);
                return NOXTLS_RETURN_FAILED;
            }
            for(k = 0; k < SHA1_OUT_LEN; k++) t[k] ^= u[k];
        }

        {
            uint32_t copy_len = (block_index * SHA1_OUT_LEN <= params->key_len)
                                    ? SHA1_OUT_LEN
                                    : (params->key_len - (block_index - 1U) * SHA1_OUT_LEN);
            memcpy(out + (size_t)(block_index - 1U) * SHA1_OUT_LEN, t, copy_len);
        }
    }
    free(block_input);
    return NOXTLS_RETURN_SUCCESS;
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
void noxtls_x509_set_unknown_extension_callback(noxtls_x509_unknown_ext_cb_t cb, void *user_ctx)
{
    noxtls_x509_unknown_ext_cb = cb;
    noxtls_x509_unknown_ext_user_ctx = user_ctx;
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
    const uint8_t *ext_ptr;
    const uint8_t *ext_end;
    const uint8_t *seq_data = NULL;
    uint32_t seq_len = 0;

    if(cert == NULL || cert->extensions == NULL || cert->extensions_len < 2) {
        return NOXTLS_RETURN_SUCCESS;
    }
    cert->san_dns_count = 0;
    cert->san_email_count = 0;
    cert->san_uri_count = 0;
    cert->san_ip_count = 0;
    cert->key_usage_bits = 0;
    cert->ext_key_usage_bits = 0;
    cert->basic_constraints_ca = -1;
    cert->basic_constraints_path_len = X509_BC_PATH_LEN_ABSENT;
    cert->authority_key_id_len = 0;
    cert->subject_key_id_len = 0;
    ext_ptr = cert->extensions;
    ext_end = cert->extensions + cert->extensions_len;

    if(asn1_get_sequence(&ext_ptr, ext_end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_SUCCESS;
    }

    {
        const uint8_t *list_ptr = seq_data;
        const uint8_t *list_end = seq_data + seq_len;

        while(list_ptr < list_end) {
            const uint8_t *ext_seq = NULL;
            uint32_t ext_seq_len = 0;
            uint8_t oid_buf[32];
            uint32_t oid_len = 0;
            int critical = 0;
            const uint8_t *val_data = NULL;
            uint32_t val_len = 0;

            if(asn1_get_sequence(&list_ptr, list_end, &ext_seq, &ext_seq_len) != NOXTLS_RETURN_SUCCESS) {
                break;
            }
            {
                const uint8_t *eptr = ext_seq;
                const uint8_t *eend = ext_seq + ext_seq_len;
                if(asn1_get_oid(&eptr, eend, oid_buf, &oid_len) != NOXTLS_RETURN_SUCCESS) {
                    list_ptr = ext_seq + ext_seq_len;
                    continue;
                }
                while(eptr < eend) {
                    if(*eptr == 0x01) {
                        if(asn1_get_boolean(&eptr, eend, &critical) != NOXTLS_RETURN_SUCCESS) {
                            critical = 0;
                            eptr++;
                            { uint32_t blen = asn1_get_length(&eptr, eend);
                              if(blen > (uint32_t)(eend - eptr)) { break; }
                              eptr += blen; }
                        }
                    } else if(*eptr == 0x04) {
                        if(asn1_get_octet_string(&eptr, eend, &val_data, &val_len) != NOXTLS_RETURN_SUCCESS) {
                            break;
                        }
                        break;
                    } else {
                        break;
                    }
                }
            }
            if(val_data == NULL || val_len == 0) {
                list_ptr = ext_seq + ext_seq_len;
                continue;
            }

            if(oid_equal(oid_buf, oid_len, oid_subject_alt_name, sizeof(oid_subject_alt_name))) {
                /* SubjectAltName: GeneralNames; dNSName [2]=0x82, rfc822Name [1]=0x81, uniformResourceIdentifier [6]=0x86, iPAddress [7]=0x87 */
                const uint8_t *san_ptr = val_data;
                const uint8_t *san_end = val_data + val_len;
                const uint8_t *san_seq = NULL;
                uint32_t san_seq_len = 0;
                if(asn1_get_sequence(&san_ptr, san_end, &san_seq, &san_seq_len) == NOXTLS_RETURN_SUCCESS) {
                    const uint8_t *gn_ptr = san_seq;
                    const uint8_t *gn_end = san_seq + san_seq_len;
                    while(gn_ptr < gn_end) {
                        if(*gn_ptr == 0x82) {
                            gn_ptr++;
                            { uint32_t dlen = asn1_get_length(&gn_ptr, gn_end);
                            if(dlen > (uint32_t)(gn_end - gn_ptr)) { break; }
                            if(cert->san_dns_count < X509_SAN_DNS_MAX && dlen > 0 && dlen < X509_SAN_DNS_LEN) {
                                memcpy(cert->san_dns_names[cert->san_dns_count], gn_ptr, dlen);
                                cert->san_dns_names[cert->san_dns_count][dlen] = '\0';
                                cert->san_dns_count++;
                            }
                            gn_ptr += dlen; }
                        } else if(*gn_ptr == 0x81) {
                            gn_ptr++;
                            { uint32_t elen = asn1_get_length(&gn_ptr, gn_end);
                            if(elen > (uint32_t)(gn_end - gn_ptr)) { break; }
                            if(cert->san_email_count < X509_SAN_EMAIL_MAX && elen > 0 && elen < X509_SAN_EMAIL_LEN) {
                                memcpy(cert->san_emails[cert->san_email_count], gn_ptr, elen);
                                cert->san_emails[cert->san_email_count][elen] = '\0';
                                cert->san_email_count++;
                            }
                            gn_ptr += elen; }
                        } else if(*gn_ptr == 0x86) {
                            gn_ptr++;
                            { uint32_t ulen = asn1_get_length(&gn_ptr, gn_end);
                            if(ulen > (uint32_t)(gn_end - gn_ptr)) { break; }
                            if(cert->san_uri_count < X509_SAN_URI_MAX && ulen > 0 && ulen < X509_SAN_URI_LEN) {
                                memcpy(cert->san_uris[cert->san_uri_count], gn_ptr, ulen);
                                cert->san_uris[cert->san_uri_count][ulen] = '\0';
                                cert->san_uri_count++;
                            }
                            gn_ptr += ulen; }
                        } else if(*gn_ptr == 0x87) {
                            gn_ptr++;
                            { uint32_t iplen = asn1_get_length(&gn_ptr, gn_end);
                            if(iplen > (uint32_t)(gn_end - gn_ptr)) { break; }
                            if(cert->san_ip_count < X509_SAN_IP_MAX && (iplen == 4 || iplen == 16)) {
                                cert->san_ip_len[cert->san_ip_count] = (uint8_t)iplen;
                                memcpy(cert->san_ips[cert->san_ip_count], gn_ptr, iplen);
                                cert->san_ip_count++;
                            }
                            gn_ptr += iplen; }
                        } else {
                            (void)*gn_ptr++;
                            uint32_t skip = asn1_get_length(&gn_ptr, gn_end);
                            if(gn_ptr + skip <= gn_end) { gn_ptr += skip; } else { break; }
                        }
                    }
                }
            } else if(oid_equal(oid_buf, oid_len, oid_key_usage, sizeof(oid_key_usage))) {
                const uint8_t *ku_ptr = val_data;
                const uint8_t *ku_end = val_data + val_len;
                if(asn1_get_tag(&ku_ptr, ku_end, 0x03) == NOXTLS_RETURN_SUCCESS) {
                    uint32_t bs_len = asn1_get_length(&ku_ptr, ku_end);
                    if(bs_len >= 1 && ku_ptr + bs_len <= ku_end) {
                        uint32_t unused = ku_ptr[0] & 0x7u;
                        const uint8_t *bits_data = ku_ptr + 1;
                        uint32_t bits_bytes = bs_len - 1U;
                        uint32_t num_bits = bits_bytes * 8U;
                        uint16_t bits = 0;
                        uint32_t i;
                        if(unused <= 7U && num_bits >= unused) {
                            num_bits -= unused;
                        }
                        for(i = 0; i < num_bits && i < 9U; i++) {
                            uint32_t byte_off = i >> 3;
                            uint32_t bit_off = 7U - (i & 7U);
                            if(byte_off < bits_bytes && (bits_data[byte_off] & (1U << bit_off)) != 0U) {
                                bits |= (uint16_t)(1U << i);
                            }
                        }
                        cert->key_usage_bits = bits;
                    }
                }
            } else if(oid_equal(oid_buf, oid_len, oid_basic_constraints, sizeof(oid_basic_constraints))) {
                const uint8_t *bc_ptr = val_data;
                const uint8_t *bc_end = val_data + val_len;
                const uint8_t *bc_seq = NULL;
                uint32_t bc_seq_len = 0;
                if(asn1_get_sequence(&bc_ptr, bc_end, &bc_seq, &bc_seq_len) == NOXTLS_RETURN_SUCCESS) {
                    const uint8_t *p = bc_seq;
                    const uint8_t *pe = bc_seq + bc_seq_len;
                    cert->basic_constraints_ca = 0;
                    while(p < pe) {
                        if(*p == 0x01) {
                            int ca_val = 0;
                            if(asn1_get_boolean(&p, pe, &ca_val) == NOXTLS_RETURN_SUCCESS) {
                                cert->basic_constraints_ca = ca_val ? 1 : 0;
                            } else { p++; { uint32_t L = asn1_get_length(&p, pe); if(L > (uint32_t)(pe - p)) { break; } p += L; } }
                        } else if(*p == 0x02) {
                            uint8_t path_buf[4];
                            uint32_t path_buf_len = sizeof(path_buf);
                            if(asn1_get_integer(&p, pe, path_buf, &path_buf_len) == NOXTLS_RETURN_SUCCESS && path_buf_len > 0 && path_buf_len <= 4) {
                                uint32_t path_len = 0;
                                uint32_t j;
                                for(j = 0; j < path_buf_len; j++) { path_len = (path_len << 8) | path_buf[j]; }
                                cert->basic_constraints_path_len = (int)path_len;
                            }
                        } else {
                            p++;
                            { uint32_t L = asn1_get_length(&p, pe); if(L > (uint32_t)(pe - p)) { break; } p += L; }
                        }
                    }
                }
            } else if(oid_equal(oid_buf, oid_len, oid_ext_key_usage, sizeof(oid_ext_key_usage))) {
                const uint8_t *eku_ptr = val_data;
                const uint8_t *eku_end = val_data + val_len;
                const uint8_t *eku_seq = NULL;
                uint32_t eku_seq_len = 0;
                if(asn1_get_sequence(&eku_ptr, eku_end, &eku_seq, &eku_seq_len) == NOXTLS_RETURN_SUCCESS) {
                    const uint8_t *q = eku_seq;
                    const uint8_t *qe = eku_seq + eku_seq_len;
                    while(q < qe) {
                        uint8_t ko[32];
                        uint32_t ko_len = 0;
                        if(asn1_get_oid(&q, qe, ko, &ko_len) == NOXTLS_RETURN_SUCCESS) {
                            if(oid_equal(ko, ko_len, oid_kp_server_auth, sizeof(oid_kp_server_auth))) cert->ext_key_usage_bits |= X509_EKU_SERVER_AUTH;
                            else if(oid_equal(ko, ko_len, oid_kp_client_auth, sizeof(oid_kp_client_auth))) cert->ext_key_usage_bits |= X509_EKU_CLIENT_AUTH;
                            else if(oid_equal(ko, ko_len, oid_kp_code_signing, sizeof(oid_kp_code_signing))) cert->ext_key_usage_bits |= X509_EKU_CODE_SIGNING;
                            else if(oid_equal(ko, ko_len, oid_kp_email_protection, sizeof(oid_kp_email_protection))) cert->ext_key_usage_bits |= X509_EKU_EMAIL_PROTECTION;
                            else if(oid_equal(
                            ko, ko_len, oid_kp_time_stamping, sizeof(oid_kp_time_stamping))) cert->ext_key_usage_bits |= X509_EKU_TIME_STAMPING;
                            else if(oid_equal(ko, ko_len, oid_kp_ocsp_signing, sizeof(oid_kp_ocsp_signing))) cert->ext_key_usage_bits |= X509_EKU_OCSP_SIGNING;
                            else if(oid_equal(ko, ko_len, oid_any_eku, sizeof(oid_any_eku))) cert->ext_key_usage_bits |= X509_EKU_ANY;
                        } else break;
                    }
                }
            } else if(oid_equal(oid_buf, oid_len, oid_authority_key_id, sizeof(oid_authority_key_id))) {
                const uint8_t *aki_ptr = val_data;
                const uint8_t *aki_end = val_data + val_len;
                const uint8_t *aki_seq = NULL;
                uint32_t aki_seq_len = 0;
                if(asn1_get_sequence(&aki_ptr, aki_end, &aki_seq, &aki_seq_len) == NOXTLS_RETURN_SUCCESS) {
                    const uint8_t *r = aki_seq;
                    const uint8_t *re = aki_seq + aki_seq_len;
                    if(r < re && *r == 0x80) {
                        r++;
                        uint32_t wrap_len = asn1_get_length(&r, re);
                        if(r + wrap_len <= re && wrap_len >= 2) {
                            const uint8_t *oct = NULL;
                            uint32_t oct_len = 0;
                            const uint8_t *r2 = r;
                            if(asn1_get_octet_string(&r2, r + wrap_len, &oct, &oct_len) == NOXTLS_RETURN_SUCCESS &&
                               oct_len > 0 && oct_len <= X509_KEY_ID_MAX_LEN) {
                                cert->authority_key_id_len = (uint8_t)oct_len;
                                memcpy(cert->authority_key_id, oct, oct_len);
                            }
                        }
                    }
                }
            } else if(oid_equal(oid_buf, oid_len, oid_subject_key_id, sizeof(oid_subject_key_id))) {
                if(val_len <= X509_KEY_ID_MAX_LEN) {
                    cert->subject_key_id_len = (uint8_t)val_len;
                    memcpy(cert->subject_key_id, val_data, val_len);
                }
            } else if(oid_equal(oid_buf, oid_len, oid_certificate_policies, sizeof(oid_certificate_policies)) ||
                      oid_equal(oid_buf, oid_len, oid_crl_distribution_points, sizeof(oid_crl_distribution_points)) ||
                      oid_equal(oid_buf, oid_len, oid_name_constraints, sizeof(oid_name_constraints)) ||
                      oid_equal(oid_buf, oid_len, oid_policy_constraints, sizeof(oid_policy_constraints)) ||
                      oid_equal(oid_buf, oid_len, oid_inhibit_any_policy, sizeof(oid_inhibit_any_policy))) {
                /*
                 * These extensions are recognized, but their policy semantics are not
                 * enforced here. Critical instances must fail closed.
                 */
                if(critical) {
                    return NOXTLS_RETURN_BAD_DATA;
                }
            } else {
                /* Unknown or custom OID */
                if(critical) {
                    if(noxtls_x509_unknown_ext_cb) {
                        if(noxtls_x509_unknown_ext_cb(oid_buf, oid_len, val_data, val_len, 1, noxtls_x509_unknown_ext_user_ctx) != NOXTLS_RETURN_SUCCESS) {
                            return NOXTLS_RETURN_BAD_DATA;
                        }
                    } else {
                        return NOXTLS_RETURN_BAD_DATA;
                    }
                } else {
                    if(noxtls_x509_unknown_ext_cb) {
                        (void)noxtls_x509_unknown_ext_cb(oid_buf, oid_len, val_data, val_len, 0, noxtls_x509_unknown_ext_user_ctx);
                    }
                }
            }
            list_ptr = ext_seq + ext_seq_len;
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
static int noxtls_x509_dns_name_equal(const char *hostname, uint32_t hostname_len, const char *dns_name)
{
    uint32_t i = 0;
    uint32_t dns_name_len = 0;
    if(dns_name == NULL) {
        return 0;
    }

    while(dns_name[dns_name_len] != '\0') {
        dns_name_len++;
    }

    if(s_x509_hostname_wildcard_matching != 0 &&
       dns_name_len > X509_HOSTNAME_WILDCARD_PREFIX_LEN &&
       dns_name[0] == X509_HOSTNAME_WILDCARD_PREFIX[0] &&
       dns_name[1] == X509_HOSTNAME_WILDCARD_PREFIX[1]) {
        uint32_t first_dot_index = 0;
        uint32_t suffix_len;
        int has_first_dot = 0;
        int has_second_wildcard = 0;
        uint32_t j = X509_HOSTNAME_WILDCARD_PREFIX_LEN;
        while(j < dns_name_len) {
            if(dns_name[j] == '*') {
                has_second_wildcard = 1;
                break;
            }
            j++;
        }
        if(has_second_wildcard != 0) {
            return 0;
        }

        /* SECURITY (NX-18): the wildcard must not span a whole registry-level domain.
         * Require at least two labels after "*." (e.g. "*.example.com"), rejecting
         * certificates such as "*.com" that would match every second-level name. */
        {
            uint32_t dot_count = 0;
            uint32_t k;
            for(k = 1U; k < dns_name_len; k++) {
                if(dns_name[k] == '.') {
                    dot_count++;
                }
            }
            if(dot_count < 2U) {
                return 0;
            }
        }

        while(first_dot_index < hostname_len) {
            if(hostname[first_dot_index] == '.') {
                has_first_dot = 1;
                break;
            }
            if(hostname[first_dot_index] == '\0') {
                break;
            }
            first_dot_index++;
        }

        if(has_first_dot == 0 || first_dot_index == 0) {
            return 0;
        }

        suffix_len = hostname_len - first_dot_index;
        if(suffix_len != (dns_name_len - 1U)) {
            return 0;
        }

        i = 0;
        while(i < suffix_len) {
            unsigned char a = (unsigned char)hostname[first_dot_index + i];
            unsigned char b = (unsigned char)dns_name[1U + i];
            if(a >= 'A' && a <= 'Z') a += 32;
            if(b >= 'A' && b <= 'Z') b += 32;
            if(a != b) {
                return 0;
            }
            i++;
        }
        return 1;
    }

    while(i < hostname_len && hostname[i] != '\0' && dns_name[i] != '\0') {
        unsigned char a = (unsigned char)hostname[i];
        unsigned char b = (unsigned char)dns_name[i];
        if(a >= 'A' && a <= 'Z') a += 32;
        if(b >= 'A' && b <= 'Z') b += 32;
        if(a != b) return 0;
        i++;
    }

    if(i != hostname_len) {
        return 0;
    }
    return (dns_name[i] == '\0') ? 1 : 0;
}


/**
 * @brief Extract first CN= value from subject_dn string (e.g. "CN=host.example.com, O=Org" -> "host.example.com").
 *
 * This function extracts the first CN= value from the subject_dn string (e.g. "CN=host.example.com, O=Org" -> "host.example.com").
 *
 * @param[in] subject_dn The subject DN to extract the CN from.
 * @param[out] cn_out The buffer to receive the CN.
 * @param[in] cn_out_size The size of the buffer to receive the CN.
 *
 * @return void
 */
static void noxtls_x509_get_cn_from_subject_dn(const char *subject_dn, char *cn_out, uint32_t cn_out_size)
{
    const char *p;
    uint32_t i = 0;
    if(subject_dn == NULL || cn_out == NULL || cn_out_size == 0) {
        if(cn_out && cn_out_size > 0) cn_out[0] = '\0';
        return;
    }

    cn_out[0] = '\0';
    p = strstr(subject_dn, "CN=");
    if(p == NULL) {
        return;
    }

    p += 3;
    while(*p == ' ') p++;
    while(*p != '\0' && *p != ',' && i < cn_out_size - 1) {
        cn_out[i++] = *p++;
    }

    cn_out[i] = '\0';
    /* Trim trailing spaces */
    while(i > 0 && cn_out[i - 1] == ' ') {
        cn_out[--i] = '\0';
    }
}

/**
 * @brief Check whether the certificate is valid for the given hostname (RFC 6125 style).
 * Prefer SAN dNSName; if none, fall back to subject CN. Comparison is case-insensitive for DNS.
 *
 * @param cert Parsed certificate (must have been parsed so subject_dn and optionally san_dns_* are set).
 * @param hostname Expected hostname (need not be null-terminated).
 * @param hostname_len Length of hostname.
 *
 * @return NOXTLS_RETURN_SUCCESS if hostname matches a SAN dNSName or subject CN; NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH otherwise; NOXTLS_RETURN_NULL if cert or hostname is NULL.
 */
noxtls_return_t noxtls_x509_certificate_matches_hostname(const x509_certificate_t *cert, const char *hostname, uint32_t hostname_len)
{
    char *cn_buf;
    const uint32_t cn_buf_size = 256;

    if(cert == NULL || hostname == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(hostname_len == 0) {
        while(hostname_len < 256 && hostname[hostname_len] != '\0') hostname_len++;
    }

    if(hostname_len == 0) {
        cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH, cert, hostname, 0, 0);
        return NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH;
    }

    /* Prefer SAN dNSName */
    if(cert->san_dns_count > 0) {
        uint8_t i;
        for(i = 0; i < cert->san_dns_count; i++) {
            if(noxtls_x509_dns_name_equal(hostname, hostname_len, cert->san_dns_names[i])) {
                return NOXTLS_RETURN_SUCCESS;
            }
        }
        cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH, cert, hostname, hostname_len, 0);
        return NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH;
    }

    /* Fallback: subject CN */
    cn_buf = (char *)noxtls_malloc(cn_buf_size);
    if(cn_buf == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    noxtls_x509_get_cn_from_subject_dn(cert->subject_dn, cn_buf, cn_buf_size);
    if(cn_buf[0] != '\0' && noxtls_x509_dns_name_equal(hostname, hostname_len, cn_buf)) {
        noxtls_free(cn_buf);
        return NOXTLS_RETURN_SUCCESS;
    }

    noxtls_free(cn_buf);
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

    memset(cert, 0, sizeof(x509_certificate_t));
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

    if(cert->rsa_modulus) {
        noxtls_free(cert->rsa_modulus);
        cert->rsa_modulus = NULL;
    }

    if(cert->rsa_exponent) {
        noxtls_free(cert->rsa_exponent);
        cert->rsa_exponent = NULL;
    }

    if(cert->ecc_public_key) {
        noxtls_free(cert->ecc_public_key);
        cert->ecc_public_key = NULL;
    }

    if(cert->extensions) {
        noxtls_free(cert->extensions);
        cert->extensions = NULL;
    }

    if(cert->signature) {
        noxtls_free(cert->signature);
        cert->signature = NULL;
    }

    if(cert->raw_data) {
        noxtls_free(cert->raw_data);
        cert->raw_data = NULL;
    }

    if(cert->tbs_certificate) {
        noxtls_free(cert->tbs_certificate);
        cert->tbs_certificate = NULL;
    }

    memset(cert, 0, sizeof(x509_certificate_t));

    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t noxtls_x509_validate_ecc_public_key_bytes(const uint8_t *pubkey,
                                                                 uint32_t pubkey_len,
                                                                 const uint8_t *curve_oid,
                                                                 uint32_t curve_oid_len);

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
noxtls_return_t noxtls_x509_certificate_parse_der(x509_certificate_t *cert, const uint8_t *data, uint32_t len)
{
    const uint8_t *ptr;
    const uint8_t *end;
    const uint8_t *tbs_cert = NULL;
    uint32_t tbs_cert_len = 0;
    const uint8_t *seq_data = NULL;
    uint32_t seq_len = 0;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if(cert == NULL || data == NULL || len == 0) {
        return NOXTLS_RETURN_NULL;
    }

    ptr = data;
    end = data + len;

    /* Free any existing data */
    noxtls_x509_certificate_free(cert);

    /* Store raw certificate data */
    cert->raw_data = (uint8_t*)malloc(len);
    if(cert->raw_data == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(cert->raw_data, data, len);
    cert->raw_data_len = len;

    do {
        if(asn1_get_sequence(&ptr, end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            break;
        }

        const uint8_t *cert_end = seq_data + seq_len;
        ptr = seq_data;

        {
            const uint8_t *tbs_seq_start = ptr;
            if(asn1_get_sequence(&ptr, cert_end, &tbs_cert, &tbs_cert_len) != NOXTLS_RETURN_SUCCESS) {
                rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
                break;
            }

            /* Signature is computed over full DER TBSCertificate (tag+length+value), not value only. */
            cert->tbs_certificate_len = (uint32_t)(ptr - tbs_seq_start);
            cert->tbs_certificate = (uint8_t*)malloc(cert->tbs_certificate_len);
            if(cert->tbs_certificate == NULL) {
                rc = NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
                break;
            }
            memcpy(cert->tbs_certificate, tbs_seq_start, cert->tbs_certificate_len);
        }

    const uint8_t *tbs_end = tbs_cert + tbs_cert_len;
    const uint8_t *tbs_ptr = tbs_cert;

    /* Parse version (optional, v1 certificates don't have it) */
    if(tbs_ptr < tbs_end && (*tbs_ptr & 0xE0) == 0xA0 && (*tbs_ptr & 0x1F) == 0x00) {
        /* Context-specific tag [0] EXPLICIT for version */
        const uint8_t *version_start = tbs_ptr;
        tbs_ptr++;
        uint32_t version_wrapper_len = asn1_get_length(&tbs_ptr, tbs_end);
        if(version_wrapper_len > 0 && tbs_ptr + version_wrapper_len <= tbs_end) {
            const uint8_t *version_end = tbs_ptr + version_wrapper_len;
            if(asn1_get_tag(&tbs_ptr, version_end, 0x02) == NOXTLS_RETURN_SUCCESS) {
                uint32_t ver_len = asn1_get_length(&tbs_ptr, version_end);
                if(ver_len > 0 && tbs_ptr + ver_len <= version_end) {
                    cert->version = tbs_ptr[ver_len - 1];
                    tbs_ptr = version_end;  /* Advance past the entire version field */
                } else {
                    tbs_ptr = version_end;  /* Skip even if parsing failed */
                }
            } else {
                /* Skip the version wrapper if INTEGER tag not found */
                tbs_ptr = version_end;
            }
        } else {
            /* If length parsing failed, try to recover by skipping */
            tbs_ptr = version_start + 1;  /* At least skip the tag byte */
        }
    } else {
        cert->version = 0;  /* v1 */
    }

        cert->serial_number_len = X509_MAX_SERIAL_SIZE;
        if(asn1_get_integer(&tbs_ptr, tbs_end, cert->serial_number, &cert->serial_number_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            break;
        }

        if(asn1_get_sequence(&tbs_ptr, tbs_end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            break;
        }
        const uint8_t *alg_end = seq_data + seq_len;
        const uint8_t *alg_ptr = seq_data;

        if(asn1_get_oid(&alg_ptr, alg_end, cert->signature_algorithm_oid, &cert->signature_algorithm_oid_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            break;
        }

    if(alg_ptr < alg_end) {
        alg_ptr = alg_end;
    }

        if(asn1_get_sequence(&tbs_ptr, tbs_end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            break;
        }
        if(seq_len > X509_MAX_ISSUER_SIZE) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            break;
        }
    memcpy(cert->issuer, seq_data, seq_len);
    cert->issuer_len = seq_len;
    noxtls_x509_parse_distinguished_name(seq_data, seq_len, cert->issuer_dn, sizeof(cert->issuer_dn));

        if(asn1_get_sequence(&tbs_ptr, tbs_end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            break;
        }
    if(seq_len >= 13) {
        const uint8_t *validity_ptr = seq_data;
        const uint8_t *validity_end = seq_data + seq_len;

        /* Parse notBefore */
        if(validity_ptr < validity_end && (*validity_ptr == 0x17 || *validity_ptr == 0x18)) {
            validity_ptr++;  /* Skip tag */
            uint32_t time_len = asn1_get_length(&validity_ptr, validity_end);
            if(time_len > 0 && validity_ptr + time_len <= validity_end) {
                /* Clear the buffer first */
                memset(cert->not_before, 0, 15);
                /* Copy up to 15 bytes; null-terminate */
                uint32_t copy_len = (time_len > 15) ? 15 : time_len;
                memcpy(cert->not_before, validity_ptr, copy_len);
                cert->not_before[14] = '\0';
                validity_ptr += time_len;
            }
        }

        /* Parse notAfter */
        if(validity_ptr < validity_end && (*validity_ptr == 0x17 || *validity_ptr == 0x18)) {
            validity_ptr++;  /* Skip tag */
            uint32_t time_len = asn1_get_length(&validity_ptr, validity_end);
            if(time_len > 0 && validity_ptr + time_len <= validity_end) {
                /* Clear the buffer first */
                memset(cert->not_after, 0, 15);
                /* Copy up to 15 bytes (e.g. YYYYMMDDHHMMSSZ or YYYYMMDDHHMMSS.); null-terminate */
                uint32_t copy_len = (time_len > 15) ? 15 : time_len;
                memcpy(cert->not_after, validity_ptr, copy_len);
                cert->not_after[14] = '\0';
            }
        }
    }

        if(asn1_get_sequence(&tbs_ptr, tbs_end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            break;
        }
        if(seq_len > X509_MAX_SUBJECT_SIZE) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            break;
        }
    memcpy(cert->subject, seq_data, seq_len);
    cert->subject_len = seq_len;
    noxtls_x509_parse_distinguished_name(seq_data, seq_len, cert->subject_dn, sizeof(cert->subject_dn));

        if(asn1_get_sequence(&tbs_ptr, tbs_end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            break;
        }
    const uint8_t *spki_end = seq_data + seq_len;
    const uint8_t *spki_ptr = seq_data;

        const uint8_t *spki_alg_data = NULL;
        uint32_t spki_alg_len = 0;
        if(asn1_get_sequence(&spki_ptr, spki_end, &spki_alg_data, &spki_alg_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            break;
        }
        const uint8_t *spki_alg_end = spki_alg_data + spki_alg_len;
        const uint8_t *spki_alg_ptr = spki_alg_data;

        if(asn1_get_oid(&spki_alg_ptr, spki_alg_end, cert->public_key_algorithm_oid, &cert->public_key_algorithm_oid_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            break;
        }

    if(spki_alg_ptr < spki_alg_end) {
        spki_alg_ptr = spki_alg_end;
    }

        if(asn1_get_tag(&spki_ptr, spki_end, 0x03) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            break;
        }
    uint32_t public_key_len = asn1_get_length(&spki_ptr, spki_end);
    if(public_key_len > 0 && spki_ptr + public_key_len <= spki_end) {
        /* Skip unused bits byte */
        spki_ptr++;
        public_key_len--;

        if(public_key_len <= X509_MAX_PUBLIC_KEY_SIZE) {
            memcpy(cert->public_key, spki_ptr, public_key_len);
            cert->public_key_len = public_key_len;

            const uint8_t *pk_ptr = spki_ptr;
            const uint8_t *pk_end = spki_ptr + public_key_len;
            if(asn1_get_sequence(&pk_ptr, pk_end, &seq_data, &seq_len) == NOXTLS_RETURN_SUCCESS) {
                /* RSA public key: SEQUENCE { modulus INTEGER, exponent INTEGER } */
                const uint8_t *rsa_seq_end = seq_data + seq_len;
                const uint8_t *rsa_seq_ptr = seq_data;
                const uint8_t *mod_start = rsa_seq_ptr;
                uint32_t mod_len = 0;
                if(asn1_get_integer(&rsa_seq_ptr, rsa_seq_end, NULL, &mod_len) == NOXTLS_RETURN_SUCCESS) {
                    cert->rsa_modulus_len = mod_len;
                    cert->rsa_modulus = (uint8_t*)malloc(mod_len);
                    if(cert->rsa_modulus) {
                        rsa_seq_ptr = mod_start;
                        uint32_t mod_len2 = mod_len;
                        if(asn1_get_integer(&rsa_seq_ptr, rsa_seq_end, cert->rsa_modulus, &mod_len2) != NOXTLS_RETURN_SUCCESS) {
                            free(cert->rsa_modulus);
                            cert->rsa_modulus = NULL;
                        }
                    }
                }
                const uint8_t *exp_start = rsa_seq_ptr;
                uint32_t exp_len = 0;
                if(asn1_get_integer(&rsa_seq_ptr, rsa_seq_end, NULL, &exp_len) == NOXTLS_RETURN_SUCCESS) {
                    cert->rsa_exponent_len = exp_len;
                    cert->rsa_exponent = (uint8_t*)malloc(exp_len);
                    if(cert->rsa_exponent) {
                        rsa_seq_ptr = exp_start;
                        uint32_t exp_len2 = exp_len;
                        if(asn1_get_integer(&rsa_seq_ptr, rsa_seq_end, cert->rsa_exponent, &exp_len2) != NOXTLS_RETURN_SUCCESS) {
                            free(cert->rsa_exponent);
                            cert->rsa_exponent = NULL;
                        }
                    }
                }
            } else if(public_key_len > 0 && spki_ptr[0] == 0x04) {
                /* ECC public key: uncompressed point 0x04 || x || y. */
                rc = noxtls_x509_validate_ecc_public_key_bytes(spki_ptr,
                                                               public_key_len,
                                                               cert->ecc_curve_oid,
                                                               cert->ecc_curve_oid_len);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    CERT_DEBUG_PRINT("x509_certificate_parse_der: invalid ECC public key\n");
                    return NOXTLS_RETURN_BAD_DATA;
                }
                cert->ecc_public_key_len = public_key_len;
                cert->ecc_public_key = (uint8_t*)malloc(public_key_len);
                if(cert->ecc_public_key) {
                    memcpy(cert->ecc_public_key, spki_ptr, public_key_len);
                }
            } else if(public_key_len == 32 && cert->public_key_algorithm_oid_len == 3 &&
                      memcmp(cert->public_key_algorithm_oid, (const uint8_t*)"\x2B\x65\x70", 3) == 0) {
                /* Ed25519 public key (OID 1.3.101.112 id-Ed25519): 32-byte raw key */
                cert->has_ed25519 = 1;
                memcpy(cert->ed25519_public_key, spki_ptr, 32);
            } else if(public_key_len == 57 && cert->public_key_algorithm_oid_len == 3 &&
                      memcmp(cert->public_key_algorithm_oid, (const uint8_t*)"\x2B\x65\x71", 3) == 0) {
                /* Ed448 public key (OID 1.3.101.113 id-Ed448): 57-byte raw key (RFC 8410) */
                cert->has_ed448 = 1;
                memcpy(cert->ed448_public_key, spki_ptr, 57);
            }
#if NOXTLS_FEATURE_ML_DSA
            else if((public_key_len == noxtls_mldsa_public_key_len(NOXTLS_MLDSA_44) ||
                       public_key_len == noxtls_mldsa_public_key_len(NOXTLS_MLDSA_65) ||
                       public_key_len == noxtls_mldsa_public_key_len(NOXTLS_MLDSA_87)) &&
                      cert->public_key_algorithm_oid_len >= 7 &&
                      cert->public_key_algorithm_oid[0] == 0x60 &&
                      cert->public_key_algorithm_oid[1] == 0x86 &&
                      cert->public_key_algorithm_oid[2] == 0x48 &&
                      cert->public_key_algorithm_oid[3] == 0x01 &&
                      cert->public_key_algorithm_oid[4] == 0x65) {
                cert->has_mldsa = 1;
                cert->mldsa_public_key_len = public_key_len;
                cert->mldsa_param = (public_key_len == noxtls_mldsa_public_key_len(NOXTLS_MLDSA_44)) ? NOXTLS_MLDSA_44 :
                                    (public_key_len == noxtls_mldsa_public_key_len(NOXTLS_MLDSA_65)) ? NOXTLS_MLDSA_65 :
                                    NOXTLS_MLDSA_87;
                memcpy(cert->mldsa_public_key, spki_ptr, public_key_len);
            }
#endif
#if NOXTLS_FEATURE_SLH_DSA
            else {
                noxtls_slhdsa_param_t slhdsa_param = NOXTLS_SLHDSA_NONE;
                if(noxtls_x509_slhdsa_param_from_oid(cert->public_key_algorithm_oid,
                                                     cert->public_key_algorithm_oid_len,
                                                     &slhdsa_param) == NOXTLS_RETURN_SUCCESS &&
                   public_key_len == noxtls_slhdsa_public_key_len(slhdsa_param)) {
                    cert->has_slhdsa = 1;
                    cert->slhdsa_public_key_len = public_key_len;
                    cert->slhdsa_param = slhdsa_param;
                    memcpy(cert->slhdsa_public_key, spki_ptr, public_key_len);
                }
            }
#endif
#if NOXTLS_FEATURE_FALCON
            if(!cert->has_mldsa && !cert->has_slhdsa) {
                int falcon_param = x509_oid_is_falcon(cert->public_key_algorithm_oid,
                                                      cert->public_key_algorithm_oid_len);
                if(falcon_param != 0 &&
                   public_key_len == noxtls_falcon_public_key_len((noxtls_falcon_param_t)falcon_param)) {
                    cert->has_falcon = 1;
                    cert->falcon_param = (noxtls_falcon_param_t)falcon_param;
                    cert->falcon_public_key_len = public_key_len;
                    memcpy(cert->falcon_public_key, spki_ptr, public_key_len);
                }
            }
#endif
        }
    }

    if(cert->version >= 2 && tbs_ptr < tbs_end) {
        if((*tbs_ptr & 0xE0) == 0xA0 && (*tbs_ptr & 0x1F) == 0x03) {
            tbs_ptr++;
            uint32_t ext_len = asn1_get_length(&tbs_ptr, tbs_end);
            if(ext_len > 0 && tbs_ptr + ext_len <= tbs_end) {
                cert->extensions = (uint8_t*)malloc(ext_len);
                if(cert->extensions) {
                    noxtls_return_t ext_rc;
                    memcpy(cert->extensions, tbs_ptr, ext_len);
                    cert->extensions_len = ext_len;
                    tbs_ptr += ext_len;
                    ext_rc = noxtls_x509_parse_extensions(cert);
                    if(ext_rc != NOXTLS_RETURN_SUCCESS) {
                        rc = (ext_rc == NOXTLS_RETURN_FAILED) ? NOXTLS_RETURN_CERT_PARSE_FAILED : ext_rc;
                        break;
                    }
                }
            }
        }
    }

        const uint8_t *sig_alg_data = NULL;
        uint32_t sig_alg_len = 0;
        if(asn1_get_sequence(&ptr, cert_end, &sig_alg_data, &sig_alg_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            break;
        }
    const uint8_t *sig_alg_end = sig_alg_data + sig_alg_len;
    const uint8_t *sig_alg_ptr = sig_alg_data;

    (void)asn1_get_oid(&sig_alg_ptr, sig_alg_end, cert->signature_algorithm_oid, &cert->signature_algorithm_oid_len);

        if(asn1_get_tag(&ptr, cert_end, 0x03) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CERT_PARSE_FAILED;
            break;
        }
        uint32_t sig_len = asn1_get_length(&ptr, cert_end);
        if(sig_len > 0 && ptr + sig_len <= cert_end) {
            ptr++;  /* Skip unused bits */
            sig_len--;
            cert->signature = (uint8_t*)malloc(sig_len);
            if(cert->signature) {
                memcpy(cert->signature, ptr, sig_len);
                cert->signature_len = sig_len;
            }
        }

        cert->parsed = 1;

    } while(0);

    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_x509_certificate_free(cert);
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
    uint32_t der_len = 0;
    noxtls_return_t rc;

    if(cert == NULL || data == NULL || len == 0) {
        return NOXTLS_RETURN_NULL;
    }

    /* Allocate buffer for DER data */
    der_data = (uint8_t*)malloc(len);
    if(der_data == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Convert PEM to DER */
    rc = noxtls_certificate_pem_to_der((uint8_t*)data, len, der_data, &der_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(der_data);
        return rc;
    }

    /* Parse DER */
    rc = noxtls_x509_certificate_parse_der(cert, der_data, der_len);

    free(der_data);

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
noxtls_return_t noxtls_x509_certificate_load_file(x509_certificate_t *cert, const char *filename)
{
    FILE *fp;
    uint8_t *data = NULL;
    uint32_t len = 0;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(cert == NULL || filename == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    fp = noxtls_fopen(filename, "rb");
    if(fp == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Get file size */
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if(len == 0 || len > X509_MAX_CERT_SIZE) {
        fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }

    data = (uint8_t*)malloc(len);
    if(data == NULL) {
        fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }

    if(fread(data, 1, len, fp) != len) {
        free(data);
        fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }

    fclose(fp);

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

    free(data);

    return rc;
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
static noxtls_return_t noxtls_x509_map_signature_algorithm(const uint8_t *oid, uint32_t oid_len,
                                                      noxtls_hash_algos_t *hash_algo, int *is_rsa)
{
    /* Common signature algorithm OIDs */
    /* sha256WithRSAEncryption: 1.2.840.113549.1.1.11 */
    const uint8_t oid_sha256_rsa[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B};

    /* sha384WithRSAEncryption: 1.2.840.113549.1.1.12 */
    const uint8_t oid_sha384_rsa[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C};

    /* sha512WithRSAEncryption: 1.2.840.113549.1.1.13 */
    const uint8_t oid_sha512_rsa[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D};

    /* ecdsa-with-SHA256: 1.2.840.10045.4.3.2 */
    const uint8_t oid_ecdsa_sha256[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02};

    /* ecdsa-with-SHA384: 1.2.840.10045.4.3.3 */
    const uint8_t oid_ecdsa_sha384[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03};

    /* ecdsa-with-SHA512: 1.2.840.10045.4.3.4 */
    const uint8_t oid_ecdsa_sha512[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04};

    /* ml-dsa-44 / 65 / 87 (private-use parser mapping for PQ cert experiments) */
    const uint8_t oid_mldsa44[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11};
    const uint8_t oid_mldsa65[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12};
    const uint8_t oid_mldsa87[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13};

    if(oid == NULL || hash_algo == NULL || is_rsa == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(oid_len == sizeof(oid_sha256_rsa) && memcmp(oid, oid_sha256_rsa, oid_len) == 0) {
        *hash_algo = NOXTLS_HASH_SHA_256;
        *is_rsa = 1;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(oid_len == sizeof(oid_sha384_rsa) && memcmp(oid, oid_sha384_rsa, oid_len) == 0) {
        *hash_algo = NOXTLS_HASH_SHA_384;
        *is_rsa = 1;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(oid_len == sizeof(oid_sha512_rsa) && memcmp(oid, oid_sha512_rsa, oid_len) == 0) {
        *hash_algo = NOXTLS_HASH_SHA_512;
        *is_rsa = 1;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(oid_len == sizeof(oid_ecdsa_sha256) && memcmp(oid, oid_ecdsa_sha256, oid_len) == 0) {
        *hash_algo = NOXTLS_HASH_SHA_256;
        *is_rsa = 0;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(oid_len == sizeof(oid_ecdsa_sha384) && memcmp(oid, oid_ecdsa_sha384, oid_len) == 0) {
        *hash_algo = NOXTLS_HASH_SHA_384;
        *is_rsa = 0;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(oid_len == sizeof(oid_ecdsa_sha512) && memcmp(oid, oid_ecdsa_sha512, oid_len) == 0) {
        *hash_algo = NOXTLS_HASH_SHA_512;
        *is_rsa = 0;
        return NOXTLS_RETURN_SUCCESS;
    }

    if((oid_len == sizeof(oid_mldsa44) && memcmp(oid, oid_mldsa44, oid_len) == 0) ||
       (oid_len == sizeof(oid_mldsa65) && memcmp(oid, oid_mldsa65, oid_len) == 0) ||
       (oid_len == sizeof(oid_mldsa87) && memcmp(oid, oid_mldsa87, oid_len) == 0)) {
        *hash_algo = NOXTLS_HASH_SHA_512;
        *is_rsa = 2;
        return NOXTLS_RETURN_SUCCESS;
    }
#if NOXTLS_FEATURE_SLH_DSA
    {
        noxtls_slhdsa_param_t slhdsa_param = NOXTLS_SLHDSA_NONE;
        if(noxtls_x509_slhdsa_param_from_oid(oid, oid_len, &slhdsa_param) == NOXTLS_RETURN_SUCCESS) {
            *hash_algo = NOXTLS_HASH_SHA_512;
            *is_rsa = 3;
            return NOXTLS_RETURN_SUCCESS;
        }
    }
#endif
#if NOXTLS_FEATURE_FALCON
    const uint8_t oid_falcon512[] = {0x2B, 0xCE, 0x0F, 0x03, 0x06};
    const uint8_t oid_falcon1024[] = {0x2B, 0xCE, 0x0F, 0x03, 0x07};

    if((oid_len == sizeof(oid_falcon512) && memcmp(oid, oid_falcon512, oid_len) == 0) ||
       (oid_len == sizeof(oid_falcon1024) && memcmp(oid, oid_falcon1024, oid_len) == 0)) {
        *hash_algo = NOXTLS_HASH_SHA_512;
        *is_rsa = 4;
        return NOXTLS_RETURN_SUCCESS;
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
    noxtls_hash_algos_t mapped;
    int is_rsa;

    if(cert == NULL || hash_algo == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    /* RFC 5929 §4.1: if signature uses MD5 or SHA-1, use SHA-256 */
    /* md5WithRSAEncryption 1.2.840.113549.1.1.4 */
    static const uint8_t oid_md5_rsa[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04};

    /* sha1WithRSAEncryption 1.2.840.113549.1.1.5 */
    static const uint8_t oid_sha1_rsa[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05};

    /* ecdsa-with-SHA1 1.2.840.10045.4.1 */
    static const uint8_t oid_ecdsa_sha1[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01};

    if(cert->signature_algorithm_oid_len == sizeof(oid_md5_rsa) &&
       memcmp(cert->signature_algorithm_oid, oid_md5_rsa, sizeof(oid_md5_rsa)) == 0) {
        *hash_algo = NOXTLS_HASH_SHA_256;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(cert->signature_algorithm_oid_len == sizeof(oid_sha1_rsa) &&
       memcmp(cert->signature_algorithm_oid, oid_sha1_rsa, sizeof(oid_sha1_rsa)) == 0) {
        *hash_algo = NOXTLS_HASH_SHA_256;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(cert->signature_algorithm_oid_len == sizeof(oid_ecdsa_sha1) &&
       memcmp(cert->signature_algorithm_oid, oid_ecdsa_sha1, sizeof(oid_ecdsa_sha1)) == 0) {
        *hash_algo = NOXTLS_HASH_SHA_256;
        return NOXTLS_RETURN_SUCCESS;
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
static noxtls_return_t noxtls_x509_ecc_curve_from_oid(const uint8_t *oid, uint32_t oid_len, ecc_curve_t *curve_type)
{
    if(oid == NULL || curve_type == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(oid_len > 0) {
        if(oid_len == sizeof(noxtls_x509_oid_secp192r1) &&
           memcmp(oid, noxtls_x509_oid_secp192r1, sizeof(noxtls_x509_oid_secp192r1)) == 0) {
            *curve_type = NOXTLS_ECC_SECP192R1;
            return NOXTLS_RETURN_SUCCESS;
        }
        if(oid_len == sizeof(noxtls_x509_oid_secp224r1) &&
           memcmp(oid, noxtls_x509_oid_secp224r1, sizeof(noxtls_x509_oid_secp224r1)) == 0) {
            *curve_type = NOXTLS_ECC_SECP224R1;
            return NOXTLS_RETURN_SUCCESS;
        }
        if(oid_len == sizeof(noxtls_x509_oid_secp256r1) &&
           memcmp(oid, noxtls_x509_oid_secp256r1, sizeof(noxtls_x509_oid_secp256r1)) == 0) {
            *curve_type = NOXTLS_ECC_SECP256R1;
            return NOXTLS_RETURN_SUCCESS;
        }
        if(oid_len == sizeof(noxtls_x509_oid_secp384r1) &&
           memcmp(oid, noxtls_x509_oid_secp384r1, sizeof(noxtls_x509_oid_secp384r1)) == 0) {
            *curve_type = NOXTLS_ECC_SECP384R1;
            return NOXTLS_RETURN_SUCCESS;
        }
        if(oid_len == sizeof(noxtls_x509_oid_secp521r1) &&
           memcmp(oid, noxtls_x509_oid_secp521r1, sizeof(noxtls_x509_oid_secp521r1)) == 0) {
            *curve_type = NOXTLS_ECC_SECP521R1;
            return NOXTLS_RETURN_SUCCESS;
        }
        if(oid_len == sizeof(noxtls_x509_oid_bp256r1) &&
           memcmp(oid, noxtls_x509_oid_bp256r1, sizeof(noxtls_x509_oid_bp256r1)) == 0) {
            *curve_type = NOXTLS_ECC_BP256R1;
            return NOXTLS_RETURN_SUCCESS;
        }
        if(oid_len == sizeof(noxtls_x509_oid_bp384r1) &&
           memcmp(oid, noxtls_x509_oid_bp384r1, sizeof(noxtls_x509_oid_bp384r1)) == 0) {
            *curve_type = NOXTLS_ECC_BP384R1;
            return NOXTLS_RETURN_SUCCESS;
        }
        if(oid_len == sizeof(noxtls_x509_oid_bp512r1) &&
           memcmp(oid, noxtls_x509_oid_bp512r1, sizeof(noxtls_x509_oid_bp512r1)) == 0) {
            *curve_type = NOXTLS_ECC_BP512R1;
            return NOXTLS_RETURN_SUCCESS;
        }
        if(oid_len == sizeof(noxtls_x509_oid_secp192k1) &&
           memcmp(oid, noxtls_x509_oid_secp192k1, sizeof(noxtls_x509_oid_secp192k1)) == 0) {
            *curve_type = NOXTLS_ECC_SECP192K1;
            return NOXTLS_RETURN_SUCCESS;
        }
        if(oid_len == sizeof(noxtls_x509_oid_secp224k1) &&
           memcmp(oid, noxtls_x509_oid_secp224k1, sizeof(noxtls_x509_oid_secp224k1)) == 0) {
            *curve_type = NOXTLS_ECC_SECP224K1;
            return NOXTLS_RETURN_SUCCESS;
        }
        if(oid_len == sizeof(noxtls_x509_oid_secp256k1) &&
           memcmp(oid, noxtls_x509_oid_secp256k1, sizeof(noxtls_x509_oid_secp256k1)) == 0) {
            *curve_type = NOXTLS_ECC_SECP256K1;
            return NOXTLS_RETURN_SUCCESS;
        }
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    *curve_type = NOXTLS_ECC_SECP256R1; /* default */
    return NOXTLS_RETURN_SUCCESS;
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
    if(pubkey_len == 49) {   /* 0x04 || 24-byte X || 24-byte Y */
        *curve_type = NOXTLS_ECC_SECP192R1;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(pubkey_len == 57) {   /* 0x04 || 28-byte X || 28-byte Y */
        *curve_type = NOXTLS_ECC_SECP224R1;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(pubkey_len == 65) {
        *curve_type = NOXTLS_ECC_SECP256R1;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(pubkey_len == 97) {
        *curve_type = NOXTLS_ECC_SECP384R1;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(pubkey_len == 129) {  /* 0x04 || 64-byte X || 64-byte Y */
        *curve_type = NOXTLS_ECC_BP512R1;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(pubkey_len == 133) {
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
    noxtls_return_t rc;
    ecc_curve_t curve_type;
    ecc_curve_params_t curve;
    ecc_point_t point;
    uint32_t coord_size;

    if(pubkey == NULL || pubkey_len == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if(curve_oid_len > 0U) {
        rc = noxtls_x509_ecc_curve_from_oid(curve_oid, curve_oid_len, &curve_type);
    } else {
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
    if(pubkey[0] != 0x04 || pubkey_len != 1U + 2U * coord_size) {
        noxtls_ecc_curve_free(&curve);
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    memset(&point, 0, sizeof(point));
    point.size = coord_size;
    memcpy(point.x, pubkey + 1, coord_size);
    memcpy(point.y, pubkey + 1 + coord_size, coord_size);

    rc = noxtls_ecc_point_validate_public(&point, &curve);
    noxtls_ecc_curve_free(&curve);

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
noxtls_return_t noxtls_x509_certificate_verify_signature(x509_certificate_t *cert, const x509_certificate_t *issuer)
{
    noxtls_return_t rc;
    noxtls_hash_algos_t hash_algo;
    int is_rsa;
    uint8_t hash[64];  /* Max hash size (SHA-512) */

    if(cert == NULL || issuer == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(!cert->parsed || !issuer->parsed) {
        CERT_DEBUG_PRINT("x509_certificate_verify_signature: certificate not parsed\n");
        cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED, cert, NULL, 0, 0);
        return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
    }

    if(cert->tbs_certificate == NULL || cert->tbs_certificate_len == 0) {
        CERT_DEBUG_PRINT("x509_certificate_verify_signature: TBSCertificate not available\n");
        cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED, cert, NULL, 0, 0);
        return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
    }

    if(cert->signature == NULL || cert->signature_len == 0) {
        CERT_DEBUG_PRINT("x509_certificate_verify_signature: signature not available\n");
        cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED, cert, NULL, 0, 0);
        return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
    }

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
        noxtls_sha256_init(&sha_ctx, hash_algo);
        noxtls_sha256_update(&sha_ctx, cert->tbs_certificate, cert->tbs_certificate_len);
        rc = noxtls_sha256_finish(&sha_ctx, hash);
    } else if(hash_algo == NOXTLS_HASH_SHA_384) {
        noxtls_sha512_ctx_t sha_ctx;
        noxtls_sha512_init(&sha_ctx, hash_algo);
        noxtls_sha512_update(&sha_ctx, cert->tbs_certificate, cert->tbs_certificate_len);
        rc = noxtls_sha512_finish(&sha_ctx, hash);
    } else if(hash_algo == NOXTLS_HASH_SHA_512) {
        noxtls_sha512_ctx_t sha_ctx;
        noxtls_sha512_init(&sha_ctx, hash_algo);
        noxtls_sha512_update(&sha_ctx, cert->tbs_certificate, cert->tbs_certificate_len);
        rc = noxtls_sha512_finish(&sha_ctx, hash);
    } else {
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
        if(issuer->rsa_modulus == NULL || issuer->rsa_exponent == NULL) {
            CERT_DEBUG_PRINT("x509_certificate_verify_signature: issuer RSA public key not available\n");
            cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED, cert, NULL, 0, 0);
            return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
        }

        /* Determine RSA key size from normalized modulus length (skip ASN.1 INTEGER sign-padding 0x00). */
        const uint8_t *mod_ptr = issuer->rsa_modulus;
        uint32_t mod_len = issuer->rsa_modulus_len;
        const uint8_t *exp_ptr = issuer->rsa_exponent;
        uint32_t exp_len = issuer->rsa_exponent_len;
        uint32_t key_bytes;
        rsa_key_size_t key_size;
        while(mod_len > 0U && mod_ptr[0] == 0U) {
            mod_ptr++;
            mod_len--;
        }
        while(exp_len > 0U && exp_ptr[0] == 0U) {
            exp_ptr++;
            exp_len--;
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
            CERT_DEBUG_PRINT("x509_certificate_verify_signature: unsupported RSA key size\n");
            return NOXTLS_RETURN_INVALID_PARAM;
        }

        rsa_key_t rsa_key;
        rc = noxtls_rsa_key_init(&rsa_key, key_size);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }

        if(mod_len == 0U || exp_len == 0U || mod_len > rsa_key.key_bytes || exp_len > rsa_key.key_bytes) {
            noxtls_rsa_key_free(&rsa_key);
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        memcpy(rsa_key.n + (rsa_key.key_bytes - mod_len), mod_ptr, mod_len);
        memcpy(rsa_key.e + (rsa_key.key_bytes - exp_len), exp_ptr, exp_len);

        /* noxtls_rsa_verify hashes the message internally (PKCS#1 v1.5 DigestInfo check). */
        rc = noxtls_rsa_verify(&rsa_key,
                               cert->tbs_certificate,
                               cert->tbs_certificate_len,
                               cert->signature,
                               cert->signature_len,
                               hash_algo);
        noxtls_rsa_key_free(&rsa_key);

        CERT_DEBUG_PRINT("x509_certificate_verify_signature: RSA signature verification %s\n",
                         (rc == NOXTLS_RETURN_SUCCESS) ? "SUCCESS" : "FAILED");

        if(rc != NOXTLS_RETURN_SUCCESS) {
            cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED, cert, NULL, 0, 0);
            return (rc == NOXTLS_RETURN_FAILED ? NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED : rc);
        }
        return NOXTLS_RETURN_SUCCESS;
    } else if(is_rsa == 2) {
#if NOXTLS_FEATURE_ML_DSA
        uint32_t hash_len = 0;
        if(!issuer->has_mldsa || issuer->mldsa_public_key_len == 0 || issuer->mldsa_param == 0) {
            cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED, cert, NULL, 0, 0);
            return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
        }
        if(hash_algo == NOXTLS_HASH_SHA_256) {
            hash_len = 32;
        } else if(hash_algo == NOXTLS_HASH_SHA_384) {
            hash_len = 48;
        } else if(hash_algo == NOXTLS_HASH_SHA_512) {
            hash_len = 64;
        } else {
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
    } else if(is_rsa == 3) {
#if NOXTLS_FEATURE_SLH_DSA
        noxtls_slhdsa_param_t sig_param = NOXTLS_SLHDSA_NONE;

        if(noxtls_x509_slhdsa_param_from_oid(cert->signature_algorithm_oid,
                                             cert->signature_algorithm_oid_len,
                                             &sig_param) != NOXTLS_RETURN_SUCCESS ||
           !issuer->has_slhdsa ||
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
    } else if(is_rsa == 4) {
#if NOXTLS_FEATURE_FALCON
        int falcon_param = x509_oid_is_falcon(cert->signature_algorithm_oid, cert->signature_algorithm_oid_len);
        if(falcon_param == 0 ||
           !issuer->has_falcon ||
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
    } else {
        /* ECDSA signature verification */
        if(issuer->ecc_public_key == NULL || issuer->ecc_public_key_len == 0) {
            CERT_DEBUG_PRINT("x509_certificate_verify_signature: issuer ECC public key not available\n");
            cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED, cert, NULL, 0, 0);
            return NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED;
        }

        /* Determine curve from issuer's public key */
        ecc_curve_t curve_type;
        if(issuer->ecc_curve_oid_len > 0) {
            if(noxtls_x509_ecc_curve_from_oid(issuer->ecc_curve_oid, issuer->ecc_curve_oid_len, &curve_type) != NOXTLS_RETURN_SUCCESS) {
                CERT_DEBUG_PRINT("x509_certificate_verify_signature: unsupported ECC curve\n");
                return NOXTLS_RETURN_INVALID_ALGORITHM;
            }
        } else {
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
        if(issuer->ecc_public_key[0] != 0x04) {
            CERT_DEBUG_PRINT("x509_certificate_verify_signature: unsupported ECC point format\n");
            noxtls_ecc_key_free(&ecc_key);
            return NOXTLS_RETURN_INVALID_PARAM;
        }

        uint32_t coord_size = ecc_key.curve->size;
        if(issuer->ecc_public_key_len != 1 + 2 * coord_size) {
            CERT_DEBUG_PRINT("x509_certificate_verify_signature: invalid ECC public key length\n");
            noxtls_ecc_key_free(&ecc_key);
            return NOXTLS_RETURN_INVALID_PARAM;
        }

        memcpy(ecc_key.Q.x, issuer->ecc_public_key + 1, coord_size);
        memcpy(ecc_key.Q.y, issuer->ecc_public_key + 1 + coord_size, coord_size);
        ecc_key.Q.size = coord_size;
        if(noxtls_ecc_point_validate_public(&ecc_key.Q, ecc_key.curve) != NOXTLS_RETURN_SUCCESS) {
            CERT_DEBUG_PRINT("x509_certificate_verify_signature: invalid issuer ECC public key\n");
            noxtls_ecc_key_free(&ecc_key);
            return NOXTLS_RETURN_INVALID_PARAM;
        }

        /* Parse ECDSA signature (DER-encoded) */
        /* ECDSA signature in X.509 is DER-encoded SEQUENCE of two INTEGERs (r, s) */
        const uint8_t *sig_ptr = cert->signature;
        const uint8_t *sig_end = cert->signature + cert->signature_len;
        const uint8_t *seq_data = NULL;
        uint32_t seq_len = 0;

        CERT_DEBUG_PRINT("x509_certificate_verify_signature: signature_len=%u first_byte=0x%02x (expect 0x30 SEQUENCE)\n",
            (unsigned)cert->signature_len, cert->signature_len > 0 ? cert->signature[0] : 0);
        if(asn1_get_tag(&sig_ptr, sig_end, 0x30) != NOXTLS_RETURN_SUCCESS) {  /* SEQUENCE tag = 0x30 */
            CERT_DEBUG_PRINT("x509_certificate_verify_signature: invalid ECDSA signature format (not SEQUENCE 0x30)\n");
            noxtls_ecc_key_free(&ecc_key);
            return NOXTLS_RETURN_BAD_DATA;
        }

        seq_len = asn1_get_length(&sig_ptr, sig_end);
        if(seq_len == 0 || (size_t)(sig_end - sig_ptr) < (size_t)seq_len) {
            CERT_DEBUG_PRINT("x509_certificate_verify_signature: invalid ECDSA signature length\n");
            noxtls_ecc_key_free(&ecc_key);
            return NOXTLS_RETURN_BAD_DATA;
        }

        seq_data = sig_ptr;
        const uint8_t *seq_end = seq_data + seq_len;

        /* Parse r */
        uint8_t r[ECC_MAX_KEY_SIZE];
        uint32_t r_len = ECC_MAX_KEY_SIZE;
        if(asn1_get_integer(&sig_ptr, seq_end, r, &r_len) != NOXTLS_RETURN_SUCCESS) {
            CERT_DEBUG_PRINT("x509_certificate_verify_signature: failed to parse ECDSA r\n");
            noxtls_ecc_key_free(&ecc_key);
            return NOXTLS_RETURN_BAD_DATA;
        }

        /* Parse s */
        uint8_t s[ECC_MAX_KEY_SIZE];
        uint32_t s_len = ECC_MAX_KEY_SIZE;
        if(asn1_get_integer(&sig_ptr, seq_end, s, &s_len) != NOXTLS_RETURN_SUCCESS) {
            CERT_DEBUG_PRINT("x509_certificate_verify_signature: failed to parse ECDSA s\n");
            noxtls_ecc_key_free(&ecc_key);
            return NOXTLS_RETURN_BAD_DATA;
        }

        /* Create ECDSA signature structure */
        ecdsa_signature_t ecdsa_sig;
        ecdsa_sig.size = coord_size;
        memset(ecdsa_sig.r, 0, ECC_MAX_KEY_SIZE);
        memset(ecdsa_sig.s, 0, ECC_MAX_KEY_SIZE);

        /* Copy r and s, handling leading zeros */
        if(r_len <= coord_size) {
            memcpy(ecdsa_sig.r + coord_size - r_len, r, r_len);
        } else {
            /* Skip leading zero padding if r is longer than expected. */
            uint32_t skip = r_len - coord_size;
            uint32_t i;
            for(i = 0; i < skip; i++) {
                if(r[i] != 0) {
                    /* r is too large (non-zero overflow prefix). */
                    noxtls_ecc_key_free(&ecc_key);
                    return NOXTLS_RETURN_BAD_DATA;
                }
            }
            memcpy(ecdsa_sig.r, r + skip, coord_size);
        }

        if(s_len <= coord_size) {
            memcpy(ecdsa_sig.s + coord_size - s_len, s, s_len);
        } else {
            uint32_t skip = s_len - coord_size;
            uint32_t i;
            for(i = 0; i < skip; i++) {
                if(s[i] != 0) {
                    noxtls_ecc_key_free(&ecc_key);
                    return NOXTLS_RETURN_BAD_DATA;
                }
            }
            memcpy(ecdsa_sig.s, s + skip, coord_size);
        }

        /* noxtls_ecdsa_verify hashes its input internally; pass raw TBSCertificate bytes (DER). */
        rc = noxtls_ecdsa_verify(&ecc_key, cert->tbs_certificate, cert->tbs_certificate_len, &ecdsa_sig, hash_algo);
        noxtls_ecc_key_free(&ecc_key);

        CERT_DEBUG_PRINT("x509_certificate_verify_signature: ECDSA signature verification %s\n",
                         (rc == NOXTLS_RETURN_SUCCESS) ? "SUCCESS" : "FAILED");

        if(rc != NOXTLS_RETURN_SUCCESS) {
            cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED, cert, NULL, 0, 0);
            return (rc == NOXTLS_RETURN_FAILED ? NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED : rc);
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
static int x509_asn1_utc_year(const uint8_t *time_data)
{
    int year = (time_data[0] - '0') * 10 + (time_data[1] - '0');
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
static void x509_asn1_utc_load_mdhm(const uint8_t *time_data, int *month, int *day, int *hour, int *minute, int *second)
{
    *month = (time_data[2] - '0') * 10 + (time_data[3] - '0');
    *day = (time_data[4] - '0') * 10 + (time_data[5] - '0');
    *hour = (time_data[6] - '0') * 10 + (time_data[7] - '0');
    *minute = (time_data[8] - '0') * 10 + (time_data[9] - '0');
    *second = (time_data[10] - '0') * 10 + (time_data[11] - '0');
}

/**
 * @brief Decode four-digit GeneralizedTime year (YYYY).
 *
 * This function decodes a four-digit GeneralizedTime year (YYYY).
 *
 * @param[in] time_data The time data to decode.
 * @return The full year.
 */
static int x509_asn1_gt_year(const uint8_t *time_data)
{
    return (time_data[0] - '0') * 1000 + (time_data[1] - '0') * 100 +
           (time_data[2] - '0') * 10 + (time_data[3] - '0');
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
static void x509_asn1_gt_load_mdhm(const uint8_t *time_data, int *month, int *day, int *hour, int *minute, int *second)
{
    *month = (time_data[4] - '0') * 10 + (time_data[5] - '0');
    *day = (time_data[6] - '0') * 10 + (time_data[7] - '0');
    *hour = (time_data[8] - '0') * 10 + (time_data[9] - '0');
    *minute = (time_data[10] - '0') * 10 + (time_data[11] - '0');
    *second = (time_data[12] - '0') * 10 + (time_data[13] - '0');
}

/**
 * @brief Convert ASN.1 time to time_t (Unix timestamp)
 *
 * @param time_data ASN.1 time data (UTCTime or GeneralizedTime)
 * @param time_len Length of time data
 * @param time_out Output time_t value
 * @return NOXTLS_RETURN_SUCCESS on success, error code otherwise
 */
static noxtls_return_t noxtls_x509_asn1_time_to_timet(const uint8_t *time_data, uint32_t time_len, time_t *time_out)
{
    if(time_data == NULL || time_len == 0 || time_out == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    /* Check if time data is valid ASCII; allow '.' or ',' for fractional seconds (GeneralizedTime) */
    uint32_t i;
    for(i = 0; i < time_len; i++) {
        if(time_data[i] < '0' || time_data[i] > '9') {
            if(i == time_len - 1 && (time_data[i] == 'Z' || time_data[i] == '+' || time_data[i] == '-')) {
                /* Valid timezone indicator at end */
                break;
            }
            if(i < time_len - 1 && (time_data[i] == '+' || time_data[i] == '-')) {
                /* Timezone offset */
                break;
            }
            /* GeneralizedTime may have fractional seconds: YYYYMMDDHHMMSS.0Z - 15th byte can be '.' or ',' */
            if((time_data[i] == '.' || time_data[i] == ',') && i == 14) {
                break;
            }
            return NOXTLS_RETURN_BAD_DATA;
        }
    }

    int year;
    int month;
    int day;
    int hour;
    int minute;
    int second;

    /* Parse UTCTime formats: YYMMDDHHMMSSZ or YYMMDDHHMMSS+/-HHMM */
    if((time_len == 13 && time_data[12] == 'Z') ||
       (time_len == 17 && (time_data[12] == '+' || time_data[12] == '-'))) {
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
    else if((time_len == 15 && time_data[14] == 'Z') ||
            (time_len == 14) ||
            (time_len == 15 && (time_data[14] == '.' || time_data[14] == ',')) ||
            (time_len == 19 && (time_data[14] == '+' || time_data[14] == '-'))) {
        year = x509_asn1_gt_year(time_data);
        x509_asn1_gt_load_mdhm(time_data, &month, &day, &hour, &minute, &second);
        /* For timezone offset encodings, we currently ignore the +/-HHMM suffix and assume UTC. */
    } else {
        return NOXTLS_RETURN_BAD_DATA;
    }

    /* Validate parsed values */
    if(month < 1 || month > 12 || day < 1 || day > 31 ||
       hour > 23 || minute > 59 || second > 59) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    /* Calculate Unix timestamp (UTC) manually for portability */
    /* Algorithm based on standard Unix epoch calculation */

    /* Days per month (non-leap year) */
    static const int days_per_month[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    /* Calculate days since epoch (1970-01-01 00:00:00 UTC) */
    int64_t days = 0;
    int y;

    /* Add days for all years since 1970 */
    for(y = 1970; y < year; y++) {
        days += 365;
        /* Add leap day if it's a leap year */
        if(((y & 3) == 0 && y % 100 != 0) || (y % 400 == 0)) {
            days += 1;
        }
    }

    /* Add days for all months in current year before current month */
    for(y = 1; y < month; y++) {
        days += days_per_month[y - 1];
        /* Add leap day for February in leap years */
        if(y == 2 && ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0))) {
            days += 1;
        }
    }

    /* Add days for current month (day - 1, since day 1 is day 0) */
    days += day - 1;

    /* Convert days to seconds and add time of day */
    int64_t seconds = days * 86400LL;  /* 86400 seconds per day */
    seconds += hour * 3600LL;
    seconds += minute * 60LL;
    seconds += second;

    /* Check for overflow/underflow (time_t is typically 32-bit or 64-bit) */
    if(seconds < 0 || seconds > (int64_t)INT32_MAX) {
        /* For 64-bit time_t, we can handle larger values, but check reasonable bounds */
#ifdef _MSC_VER
#if defined(_USE_32BIT_TIME_T)
        if(seconds > INT32_MAX) {
            return NOXTLS_RETURN_FAILED;
        }
#endif
#else
        if(sizeof(time_t) == 4 && seconds > INT32_MAX) {
            return NOXTLS_RETURN_FAILED;
        }
#endif
    }

    *time_out = (time_t)seconds;

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
noxtls_return_t noxtls_x509_certificate_check_validity(const x509_certificate_t *cert)
{
    if(cert == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(!cert->parsed) {
        return NOXTLS_RETURN_FAILED;
    }

#if NOXTLS_HAVE_TIME
    time_t current_time;
    time_t not_before_time = 0;
    time_t not_after_time = 0;
    noxtls_return_t rc;

    /* Get current time */
    current_time = time(NULL);
    if(current_time == (time_t)-1) {
        CERT_DEBUG_PRINT("x509_certificate_check_validity: failed to get current time\n");
        return NOXTLS_RETURN_FAILED;
    }

    /* Parse not_before time */
    if(cert->not_before[0] != 0) {
        /* Find actual length by looking for null terminator or end of buffer */
        uint32_t time_len = 0;
        while(time_len < 15 && cert->not_before[time_len] != 0) {
            time_len++;
        }

        if(time_len > 0) {
            rc = noxtls_x509_asn1_time_to_timet(cert->not_before, time_len, &not_before_time);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                CERT_DEBUG_PRINT("x509_certificate_check_validity: failed to parse not_before time\n");
                return NOXTLS_RETURN_BAD_DATA;
            }

            /* Check if certificate is not yet valid */
            if(current_time < not_before_time) {
                CERT_DEBUG_PRINT("x509_certificate_check_validity: certificate not yet valid\n");
                cert_fail_set(NOXTLS_RETURN_CERT_NOT_YET_VALID, cert, NULL, 0, 0);
                return NOXTLS_RETURN_CERT_NOT_YET_VALID;
            }
        }
    }

    /* Parse not_after time */
    if(cert->not_after[0] != 0) {
        /* Find actual length by looking for null terminator or end of buffer */
        uint32_t time_len = 0;
        while(time_len < 15 && cert->not_after[time_len] != 0) {
            time_len++;
        }

        if(time_len > 0) {
            rc = noxtls_x509_asn1_time_to_timet(cert->not_after, time_len, &not_after_time);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                CERT_DEBUG_PRINT("x509_certificate_check_validity: failed to parse not_after time\n");
                return NOXTLS_RETURN_BAD_DATA;
            }

            /* Check if certificate has expired */
            if(current_time > not_after_time) {
                CERT_DEBUG_PRINT("x509_certificate_check_validity: certificate expired\n");
                cert_fail_set(NOXTLS_RETURN_CERT_EXPIRED, cert, NULL, 0, 0);
                return NOXTLS_RETURN_CERT_EXPIRED;
            }
        }
    }

    /* If we have both times, verify not_before < not_after */
    if(not_before_time > 0 && not_after_time > 0 && not_before_time > not_after_time) {
        CERT_DEBUG_PRINT("x509_certificate_check_validity: invalid validity period (not_before > not_after)\n");
        return NOXTLS_RETURN_BAD_DATA;
    }

    CERT_DEBUG_PRINT("x509_certificate_check_validity: certificate is valid\n");
    return NOXTLS_RETURN_SUCCESS;
#else
    /* Time support not available - cannot check validity period */
    /* Still check that certificate is parsed correctly */
    CERT_DEBUG_PRINT("x509_certificate_check_validity: time support not available, skipping time-based validation\n");
    return NOXTLS_RETURN_SUCCESS;
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
    noxtls_return_t rc;
    ecc_curve_t curve_type;
    ecc_key_t *ecc_key = NULL;
    uint32_t coord_size;

    if(cert == NULL || key == NULL || key_type == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    *key = NULL;
    *key_type = 0;

    if(!cert->parsed) {
        return NOXTLS_RETURN_FAILED;
    }

    /* ECC public key from certificate */
    if(cert->ecc_public_key == NULL || cert->ecc_public_key_len == 0) {
        /* RSA not implemented here */
        return NOXTLS_RETURN_SUCCESS;
    }

    if(cert->ecc_curve_oid_len > 0) {
        rc = noxtls_x509_ecc_curve_from_oid(cert->ecc_curve_oid, cert->ecc_curve_oid_len, &curve_type);
    } else {
        rc = noxtls_x509_ecc_curve_from_pubkey_len(cert->ecc_public_key_len, &curve_type);
    }

    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    ecc_key = (ecc_key_t *)calloc(1, sizeof(ecc_key_t));
    if(ecc_key == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    rc = noxtls_ecc_key_init(ecc_key, curve_type);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(ecc_key);
        return rc;
    }

    coord_size = ecc_key->curve->size;
    if(cert->ecc_public_key[0] != 0x04 || cert->ecc_public_key_len != 1 + 2 * coord_size) {
        noxtls_ecc_key_free(ecc_key);
        free(ecc_key);
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    memcpy(ecc_key->Q.x, cert->ecc_public_key + 1, coord_size);
    memcpy(ecc_key->Q.y, cert->ecc_public_key + 1 + coord_size, coord_size);
    ecc_key->Q.size = coord_size;
    if(noxtls_ecc_point_validate_public(&ecc_key->Q, ecc_key->curve) != NOXTLS_RETURN_SUCCESS) {
        noxtls_ecc_key_free(ecc_key);
        free(ecc_key);
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

static const char* noxtls_x509_get_attr_name_from_oid(const uint8_t *oid, uint32_t oid_len)
{
    /* Common OIDs for DN attributes */
    /* CN = 2.5.4.3 */
    if(oid_len == 3 && oid[0] == 0x55 && oid[1] == 0x04 && oid[2] == 0x03) {
        return "CN";
    }

    /* O = 2.5.4.10 */
    if(oid_len == 3 && oid[0] == 0x55 && oid[1] == 0x04 && oid[2] == 0x0A) {
        return "O";
    }

    /* OU = 2.5.4.11 */
    if(oid_len == 3 && oid[0] == 0x55 && oid[1] == 0x04 && oid[2] == 0x0B) {
        return "OU";
    }

    /* C = 2.5.4.6 */
    if(oid_len == 3 && oid[0] == 0x55 && oid[1] == 0x04 && oid[2] == 0x06) {
        return "C";
    }

    /* ST = 2.5.4.8 */
    if(oid_len == 3 && oid[0] == 0x55 && oid[1] == 0x04 && oid[2] == 0x08) {
        return "ST";
    }

    /* L = 2.5.4.7 */
    if(oid_len == 3 && oid[0] == 0x55 && oid[1] == 0x04 && oid[2] == 0x07) {
        return "L";
    }

    /* E = 1.2.840.113549.1.9.1 (emailAddress) */
    if(oid_len == 9 && oid[0] == 0x2A && oid[1] == 0x86 && oid[2] == 0x48 &&
       oid[3] == 0x86 && oid[4] == 0xF7 && oid[5] == 0x0D && oid[6] == 0x01 &&
       oid[7] == 0x09 && oid[8] == 0x01) {
        return "E";
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
noxtls_return_t noxtls_x509_parse_distinguished_name(const uint8_t *dn_data, uint32_t dn_len, char *output, uint32_t output_size)
{
    uint32_t output_pos = 0;
    int first = 1;

    if(output == NULL || output_size == 0 || dn_data == NULL || dn_len == 0) {
        if(output && output_size > 0) {
            output[0] = '\0';
        }
        return NOXTLS_RETURN_NULL;
    }

    output[0] = '\0';

    /* DN is a SEQUENCE OF RelativeDistinguishedName */
    /* The dn_data already points to the SEQUENCE content, so we don't need to parse it again */
    const uint8_t *dn_end = dn_data + dn_len;
    const uint8_t *dn_ptr = dn_data;

    /* Iterate through RDN sequence */
    while(dn_ptr < dn_end) {
        const uint8_t *rdn_data = NULL;
        uint32_t rdn_len = 0;

        /* Try SET first (RDN is a SET, tag 0x31); loop guarantees dn_ptr < dn_end */
        if(*dn_ptr == 0x31) {
            dn_ptr++;  /* Skip SET tag */
            rdn_len = asn1_get_length(&dn_ptr, dn_end);
            if(rdn_len > 0 && dn_ptr + rdn_len <= dn_end) {
                rdn_data = dn_ptr;
                dn_ptr += rdn_len;
            } else {
                break;  /* Invalid SET */
            }
        } else if(*dn_ptr == 0x30) {
            if(asn1_get_sequence(&dn_ptr, dn_end, &rdn_data, &rdn_len) != NOXTLS_RETURN_SUCCESS) {
                break;  /* End of DN or invalid */
            }
        } else {
            break;  /* Unexpected tag */
        }

        const uint8_t *rdn_end = rdn_data + rdn_len;
        const uint8_t *rdn_ptr = rdn_data;

        /* If RDN is a SET (e.g. Name = SEQUENCE(SET(SEQUENCE(...)))), unwrap to get the AttributeTypeAndValue SEQUENCE */
        if(rdn_len >= 1 && *rdn_data == 0x31) {
            const uint8_t *set_ptr = rdn_data + 1;
            uint32_t set_content_len = asn1_get_length(&set_ptr, rdn_end);
            if(set_content_len == 0 || set_ptr + set_content_len > rdn_end) {
                continue;
            }
            rdn_ptr = set_ptr;
            rdn_end = set_ptr + set_content_len;
        }

        /* Parse AttributeTypeAndValue: SEQUENCE { type OID, value ANY } */
        const uint8_t *attr_data = NULL;
        uint32_t attr_len = 0;

        if(asn1_get_sequence(&rdn_ptr, rdn_end, &attr_data, &attr_len) != NOXTLS_RETURN_SUCCESS) {
            continue;  /* Skip invalid attribute */
        }

        const uint8_t *attr_end = attr_data + attr_len;
        const uint8_t *attr_ptr = attr_data;

        /* Parse OID (attribute type) */
        uint8_t oid[32];
        uint32_t oid_len = sizeof(oid);
        if(asn1_get_oid(&attr_ptr, attr_end, oid, &oid_len) != NOXTLS_RETURN_SUCCESS) {
            continue;  /* Skip if no OID */
        }

        /* Get attribute name */
        const char *attr_name = noxtls_x509_get_attr_name_from_oid(oid, oid_len);
        if(attr_name == NULL) {
            attr_name = "OID";  /* Unknown attribute */
        }

        /* Parse value (can be various types, but usually a string) */
        if(attr_ptr < attr_end) {
            attr_ptr++;  /* Skip value tag */
            uint32_t value_len = asn1_get_length(&attr_ptr, attr_end);

            if(value_len > 0 && attr_ptr + value_len <= attr_end &&
               output_pos < output_size - 1) {

                /* Format: "attr=value, " */
                if(!first && output_pos < output_size - 2) {
                    output[output_pos++] = ',';
                    output[output_pos++] = ' ';
                }
                first = 0;

                /* Add attribute name */
                size_t name_len = strlen(attr_name);
                size_t remaining = (output_pos < output_size) ? (size_t)(output_size - output_pos) : 0;
                if(remaining > 1 && name_len + 1 < remaining) {
                    memcpy(output + output_pos, attr_name, name_len);
                    output_pos += (uint32_t)name_len;
                    output[output_pos++] = '=';
                }

                /* Add value (limit to printable characters and reasonable length) */
                uint32_t i;
                uint32_t max_value_len = (output_size - output_pos - 1) < value_len ?
                                         (output_size - output_pos - 1) : value_len;

                for(i = 0; i < max_value_len && output_pos < output_size - 1; i++) {
                    uint8_t c = attr_ptr[i];
                    if(c >= 32 && c < 127) {  /* Printable ASCII */
                        output[output_pos++] = (char)c;
                    } else {
                        output[output_pos++] = '?';
                    }
                }
            }
        }
    }

    output[output_pos] = '\0';

    if(output_pos == 0) {
        snprintf(output, output_size, "(empty DN)");
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
noxtls_return_t noxtls_x509_parse_time(const uint8_t *time_data, uint32_t time_len, char *output, uint32_t output_size)
{
    if(output == NULL || output_size == 0 || time_data == NULL || time_len == 0) {
        if(output && output_size > 0) {
            output[0] = '\0';
        }
        return NOXTLS_RETURN_NULL;
    }

    /* UTCTime format: YYMMDDHHMMSSZ (13 bytes) or YYMMDDHHMMSS+/-HHMM (17 bytes) */
    /* GeneralizedTime format: YYYYMMDDHHMMSSZ (15 bytes) or YYYYMMDDHHMMSS+/-HHMM (19 bytes) */

    /* First, copy the raw time string to a buffer for processing */
    char time_str[20] = {0};
    uint32_t i;
    for(i = 0; i < time_len && i < sizeof(time_str) - 1; i++) {
        uint8_t c = time_data[i];
        if(c >= 32 && c < 127) {  /* Printable ASCII */
            time_str[i] = (char)c;
        } else {
            time_str[i] = '?';
        }
    }
    time_str[i] = '\0';

    /* Format: YYMMDDHHMMSSZ -> YYYY-MM-DD HH:MM:SS */
    if(time_len == 13 && time_str[12] == 'Z') {
        /* UTCTime: convert YY to YYYY */
        int year = (time_str[0] - '0') * 10 + (time_str[1] - '0');
        if(year < 50) {
            year += 2000;  /* 00-49 = 2000-2049 */
        } else {
            year += 1900;  /* 50-99 = 1950-1999 */
        }

        /* Format: YYYY-MM-DD HH:MM:SS */
        snprintf(output, output_size, "%04d-%c%c-%c%c %c%c:%c%c:%c%c",
                 year, time_str[2], time_str[3], time_str[4], time_str[5],
                 time_str[6], time_str[7], time_str[8], time_str[9],
                 time_str[10], time_str[11]);
    } else if(time_len == 15 && time_str[14] == 'Z') {
        /* GeneralizedTime: YYYYMMDDHHMMSSZ */
        snprintf(output, output_size, "%c%c%c%c-%c%c-%c%c %c%c:%c%c:%c%c",
                 time_str[0], time_str[1], time_str[2], time_str[3],
                 time_str[4], time_str[5], time_str[6], time_str[7],
                 time_str[8], time_str[9], time_str[10], time_str[11],
                 time_str[12], time_str[13]);
    } else {
        /* Invalid or unsupported time format - just show raw */
        size_t time_str_len = strlen(time_str);
        size_t copy_len = (time_str_len > output_size - 1) ? (size_t)(output_size - 1) : time_str_len;
        memcpy(output, time_str, copy_len);
        output[copy_len] = '\0';
    }

    return NOXTLS_RETURN_SUCCESS;
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

    memset(chain, 0, sizeof(x509_certificate_chain_t));
    chain->capacity = 8;
    chain->certs = (x509_certificate_t*)calloc(chain->capacity, sizeof(x509_certificate_t));
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

    if(chain->certs) {
        uint32_t i;
        for(i = 0; i < chain->count; i++) {
            noxtls_x509_certificate_free(&chain->certs[i]);
        }
        free(chain->certs);
        chain->certs = NULL;
    }

    memset(chain, 0, sizeof(x509_certificate_chain_t));

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
    noxtls_return_t rc;
    x509_certificate_t *dst;

    if(chain == NULL || cert == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(chain->count >= chain->capacity) {
        /* Expand capacity */
        if(chain->capacity == 0 || chain->capacity > (UINT32_MAX / 2U)) {
            return NOXTLS_RETURN_FAILED;
        }
        uint32_t new_capacity = chain->capacity * 2;
        if(new_capacity > (UINT32_MAX / (uint32_t)sizeof(x509_certificate_t))) {
            return NOXTLS_RETURN_FAILED;
        }
        x509_certificate_t *new_certs = (x509_certificate_t*)realloc(chain->certs, (size_t)new_capacity * sizeof(x509_certificate_t));
        if(new_certs == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        chain->certs = new_certs;
        chain->capacity = new_capacity;
    }

    dst = &chain->certs[chain->count];
    noxtls_x509_certificate_init(dst);

    /* Allow adding an init-only cert (no raw_data) for empty slot / unit tests. */
    if(cert->raw_data == NULL || cert->raw_data_len == 0) {
        chain->count++;
        return NOXTLS_RETURN_SUCCESS;
    }

    /* Deep-copy by reparsing source DER to avoid shared pointer ownership/double-free. */
    rc = noxtls_x509_certificate_parse_der(dst, cert->raw_data, cert->raw_data_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_x509_certificate_free(dst);
        return rc;
    }

    chain->count++;

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
noxtls_return_t noxtls_x509_certificate_chain_verify(x509_certificate_chain_t *chain)
{
    uint32_t i;

    if(chain == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(chain->count == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Verify each certificate is signed by the next one */
    for(i = 0; i < chain->count - 1; i++) {
        noxtls_return_t rc = noxtls_x509_certificate_verify_signature(&chain->certs[i], &chain->certs[i + 1]);
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
        noxtls_return_t rc = noxtls_x509_certificate_check_validity(&chain->certs[chain->count - 1]);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            s_cert_fail_info.cert_index = chain->count - 1;
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
    if(lhs == NULL || rhs == NULL) {
        return 0;
    }
    if(lhs_len != rhs_len) {
        return 0;
    }
    if(lhs_len == 0) {
        return 1;
    }
    return (memcmp(lhs, rhs, lhs_len) == 0) ? 1 : 0;
}

/**
 * @brief Compare two certificates
 *
 * This function compares two certificates.
 *
 * @param[in] lhs The left-hand side certificate.
 * @param[in] rhs The right-hand side certificate.
 *
 * @return The return code of the function.
 */
static int x509_is_same_cert(const x509_certificate_t *lhs, const x509_certificate_t *rhs)
{
    if(lhs == NULL || rhs == NULL) {
        return 0;
    }
    if(lhs->raw_data != NULL && rhs->raw_data != NULL &&
       lhs->raw_data_len == rhs->raw_data_len &&
       lhs->raw_data_len > 0 &&
       memcmp(lhs->raw_data, rhs->raw_data, lhs->raw_data_len) == 0) {
        return 1;
    }
    if(lhs->subject_len == rhs->subject_len && lhs->serial_number_len == rhs->serial_number_len &&
       lhs->subject_len > 0 && lhs->serial_number_len > 0 &&
       memcmp(lhs->subject, rhs->subject, lhs->subject_len) == 0 &&
       memcmp(lhs->serial_number, rhs->serial_number, lhs->serial_number_len) == 0) {
        return 1;
    }
    if(lhs->subject_len == rhs->subject_len &&
       lhs->subject_len > 0 &&
       memcmp(lhs->subject, rhs->subject, lhs->subject_len) == 0 &&
       lhs->public_key_algorithm_oid_len == rhs->public_key_algorithm_oid_len &&
       lhs->public_key_algorithm_oid_len > 0 &&
       memcmp(lhs->public_key_algorithm_oid, rhs->public_key_algorithm_oid, lhs->public_key_algorithm_oid_len) == 0 &&
       lhs->public_key_len == rhs->public_key_len &&
       lhs->public_key_len > 0 &&
       memcmp(lhs->public_key, rhs->public_key, lhs->public_key_len) == 0) {
        return 1;
    }
    return 0;
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
    if(issuer->key_usage_bits != 0 &&
       (issuer->key_usage_bits & X509_KEY_USAGE_KEY_CERT_SIGN) == 0) {
        cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED, issuer, NULL, 0, path_depth_below + 1U);
        return NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED;
    }
    if(issuer->basic_constraints_path_len != X509_BC_PATH_LEN_ABSENT &&
       path_depth_below > (uint32_t)issuer->basic_constraints_path_len) {
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
    if(leaf->ext_key_usage_bits != 0 &&
       (leaf->ext_key_usage_bits & (required_eku | X509_EKU_ANY)) == 0) {
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
    if(leaf->key_usage_bits != 0 &&
       (leaf->key_usage_bits & required_key_usage) == 0) {
        cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED, leaf, NULL, 0, 0);
        return NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Find issuer in chain
 *
 * This function finds an issuer in a certificate chain.
 *
 * @param[in] subject_cert The subject certificate to find the issuer of.
 * @param[in] chain The certificate chain to search in.
 *
 * @return The issuer certificate.
 */
static const x509_certificate_t *x509_find_issuer_in_chain(const x509_certificate_t *subject_cert,
                                                            const x509_certificate_chain_t *chain)
{
    uint32_t i;
    const x509_certificate_t *fallback = NULL;
    const x509_certificate_t *fallback_sig = NULL;
    int have_aki;
    int saw_dn_candidate;
    int saw_aki_candidate_with_ski;
    if(subject_cert == NULL || chain == NULL || chain->certs == NULL) {
        return NULL;
    }
    have_aki = (subject_cert->authority_key_id_len > 0) ? 1 : 0;
    saw_dn_candidate = 0;
    saw_aki_candidate_with_ski = 0;
    for(i = 0; i < chain->count; i++) {
        int dn_match;

        dn_match = x509_dn_equal(subject_cert->issuer, subject_cert->issuer_len,
                                 chain->certs[i].subject, chain->certs[i].subject_len);
        if(!dn_match &&
           subject_cert->issuer_dn[0] != '\0' &&
           chain->certs[i].subject_dn[0] != '\0' &&
           strcmp(subject_cert->issuer_dn, chain->certs[i].subject_dn) == 0) {
            dn_match = 1;
        }
        if(dn_match) {
            saw_dn_candidate = 1;
            if(fallback == NULL) {
                fallback = &chain->certs[i];
            }
            if(!x509_is_same_cert(subject_cert, &chain->certs[i])) {
                noxtls_return_t sig_rc_any = noxtls_x509_certificate_verify_signature((x509_certificate_t*)subject_cert,
                                                                                       &chain->certs[i]);
                if(sig_rc_any == NOXTLS_RETURN_SUCCESS && fallback_sig == NULL) {
                    fallback_sig = &chain->certs[i];
                }
            }
            if(have_aki) {
                if(chain->certs[i].subject_key_id_len > 0) {
                    saw_aki_candidate_with_ski = 1;
                    if(chain->certs[i].subject_key_id_len != subject_cert->authority_key_id_len ||
                       memcmp(chain->certs[i].subject_key_id,
                              subject_cert->authority_key_id,
                              subject_cert->authority_key_id_len) != 0) {
                        continue;
                    }
                }
            }
            if(fallback_sig == &chain->certs[i]) {
                return &chain->certs[i];
            }
        }
    }
    if(fallback_sig != NULL) {
        return fallback_sig;
    }
    if(have_aki && saw_dn_candidate && saw_aki_candidate_with_ski) {
        return NULL;
    }
    return fallback;
}

/**
 * @brief Check if a certificate chain contains a certificate
 *
 * This function checks if a certificate chain contains a certificate.
 *
 * @param[in] chain The certificate chain to check.
 * @param[in] cert The certificate to check for.
 *
 * @return The return code of the function.
 */
static int x509_chain_contains_cert(const x509_certificate_chain_t *chain, const x509_certificate_t *cert)
{
    uint32_t i;
    if(chain == NULL || cert == NULL || chain->certs == NULL) {
        return 0;
    }
    for(i = 0; i < chain->count; i++) {
        if(x509_is_same_cert(&chain->certs[i], cert)) {
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
    uint32_t i;
    uint32_t j;
    if(a == NULL || b == NULL) {
        return 0;
    }
    i = 0;
    while(i < alen && a[i] == 0) {
        i++;
    }
    j = 0;
    while(j < blen && b[j] == 0) {
        j++;
    }
    if((alen - i) != (blen - j)) {
        return 0;
    }
    if(alen - i == 0) {
        return 1;
    }
    return (memcmp(a + i, b + j, alen - i) == 0) ? 1 : 0;
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
    static const char begin_str[] = "-----BEGIN X509 CRL-----";
    static const char end_str[] = "-----END X509 CRL-----";
    uint32_t bi;
    uint32_t ei;
    uint32_t b_len;
    uint32_t e_len;

    if(data == NULL || length == 0 || output == NULL || out_len == NULL) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    b_len = (uint32_t)strlen(begin_str);
    e_len = (uint32_t)strlen(end_str);
    bi = 0;
    while(bi + b_len <= length) {
        if(memcmp(data + bi, begin_str, b_len) == 0) {
            break;
        }
        bi++;
    }
    if(bi + b_len > length) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    ei = bi + b_len;
    while(ei + e_len <= length) {
        if(memcmp(data + ei, end_str, e_len) == 0) {
            break;
        }
        ei++;
    }
    if(ei + e_len > length) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    {
        uint32_t b64_len = ei - (bi + b_len);
        int dec = (int)noxtls_base64_decode((char *)(data + bi + b_len), b64_len, output);
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
    memset(crl, 0, sizeof(noxtls_x509_crl_t));
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
    if(crl == NULL) {
        return;
    }
    if(crl->next != NULL) {
        noxtls_x509_crl_free(crl->next);
        crl->next = NULL;
    }
    if(crl->signature != NULL) {
        free(crl->signature);
        crl->signature = NULL;
    }
    if(crl->tbs_crl != NULL) {
        free(crl->tbs_crl);
        crl->tbs_crl = NULL;
    }
    if(crl->raw_data != NULL) {
        free(crl->raw_data);
        crl->raw_data = NULL;
    }
    if(crl->revoked_serials != NULL) {
        free(crl->revoked_serials);
        crl->revoked_serials = NULL;
    }
    if(crl->revoked_serial_lens != NULL) {
        free(crl->revoked_serial_lens);
        crl->revoked_serial_lens = NULL;
    }
    memset(crl, 0, sizeof(noxtls_x509_crl_t));
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
noxtls_return_t noxtls_x509_crl_parse_der(noxtls_x509_crl_t *crl, const uint8_t *data, uint32_t len)
{
    const uint8_t *ptr;
    const uint8_t *end;
    const uint8_t *seq_data = NULL;
    uint32_t seq_len = 0;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if(crl == NULL || data == NULL || len == 0) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_x509_crl_free(crl);

    crl->raw_data = (uint8_t*)malloc(len);
    if(crl->raw_data == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    memcpy(crl->raw_data, data, len);
    crl->raw_data_len = len;

    ptr = crl->raw_data;
    end = crl->raw_data + len;

    do {
        const uint8_t *cert_list_end;
        const uint8_t *tbs_outer_start;
        const uint8_t *tbs_content;
        uint32_t tbs_content_len;
        const uint8_t *tbs_ptr;
        const uint8_t *tbs_end;

        if(asn1_get_sequence(&ptr, end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
            break;
        }
        cert_list_end = seq_data + seq_len;
        ptr = seq_data;

        tbs_outer_start = ptr;
        if(asn1_get_sequence(&ptr, cert_list_end, &tbs_content, &tbs_content_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
            break;
        }

        crl->tbs_crl_len = (uint32_t)(ptr - tbs_outer_start);
        crl->tbs_crl = (uint8_t*)malloc(crl->tbs_crl_len);
        if(crl->tbs_crl == NULL) {
            rc = NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
            break;
        }
        memcpy(crl->tbs_crl, tbs_outer_start, crl->tbs_crl_len);

        tbs_ptr = tbs_content;
        tbs_end = tbs_content + tbs_content_len;

        /* Optional version (INTEGER, usually v2 = 1). */
        if(tbs_ptr < tbs_end && *tbs_ptr == (uint8_t)0x02) {
            uint8_t version_raw[4];
            uint32_t version_raw_len = sizeof(version_raw);
            if(asn1_get_integer(&tbs_ptr, tbs_end, version_raw, &version_raw_len) != NOXTLS_RETURN_SUCCESS) {
                rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
                break;
            }
        } else if(tbs_ptr < tbs_end && *tbs_ptr == (uint8_t)0xA0) {
            /* Backward compatibility for older parser behavior. */
            tbs_ptr++;
            {
                uint32_t wrap_len = asn1_get_length(&tbs_ptr, tbs_end);
                if(wrap_len > (uint32_t)(tbs_end - tbs_ptr)) {
                    rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
                    break;
                }
                tbs_ptr += wrap_len;
            }
        }

        /* signature AlgorithmIdentifier inside TBSCertList */
        if(asn1_get_sequence(&tbs_ptr, tbs_end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
            break;
        }
        {
            const uint8_t *alg_end = seq_data + seq_len;
            const uint8_t *alg_ptr = seq_data;
            if(asn1_get_oid(&alg_ptr, alg_end, crl->signature_algorithm_oid, &crl->signature_algorithm_oid_len) != NOXTLS_RETURN_SUCCESS) {
                rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
                break;
            }
        }

        /* issuer */
        if(asn1_get_sequence(&tbs_ptr, tbs_end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
            break;
        }
        if(seq_len > X509_MAX_ISSUER_SIZE) {
            rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
            break;
        }
        memcpy(crl->issuer, seq_data, seq_len);
        crl->issuer_len = seq_len;
        noxtls_x509_parse_distinguished_name(seq_data, seq_len, crl->issuer_dn, sizeof(crl->issuer_dn));

        /* thisUpdate */
        if(tbs_ptr >= tbs_end || (*tbs_ptr != 0x17 && *tbs_ptr != 0x18)) {
            rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
            break;
        }
        {
            tbs_ptr++;
            {
                uint32_t time_len = asn1_get_length(&tbs_ptr, tbs_end);
                if(time_len == 0 || (size_t)(tbs_end - tbs_ptr) < (size_t)time_len) {
                    rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
                    break;
                }
                memset(crl->this_update, 0, sizeof(crl->this_update));
                {
                    uint32_t copy_len = (time_len > 15U) ? 15U : time_len;
                    memcpy(crl->this_update, tbs_ptr, copy_len);
                    crl->this_update[14] = '\0';
                }
                tbs_ptr += time_len;
            }
        }

        /* optional nextUpdate */
        crl->has_next_update = 0;
        memset(crl->next_update, 0, sizeof(crl->next_update));
        if(tbs_ptr < tbs_end && (*tbs_ptr == 0x17 || *tbs_ptr == 0x18)) {
            tbs_ptr++;
            {
                uint32_t time_len = asn1_get_length(&tbs_ptr, tbs_end);
                if(time_len == 0 || (size_t)(tbs_end - tbs_ptr) < (size_t)time_len) {
                    rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
                    break;
                }
                {
                    uint32_t copy_len = (time_len > 15U) ? 15U : time_len;
                    memcpy(crl->next_update, tbs_ptr, copy_len);
                    crl->next_update[14] = '\0';
                }
                crl->has_next_update = 1;
                tbs_ptr += time_len;
            }
        }

        /* revokedCertificates or crlExtensions */
        if(tbs_ptr < tbs_end && *tbs_ptr == 0x30) {
            const uint8_t *save = tbs_ptr;
            const uint8_t *list_body = NULL;
            uint32_t list_len = 0;
            const uint8_t *list_end;
            if(asn1_get_sequence(&tbs_ptr, tbs_end, &list_body, &list_len) != NOXTLS_RETURN_SUCCESS) {
                rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
                break;
            }
            list_end = list_body + list_len;
            if(list_len == 0) {
                /* Empty revokedCertificates SEQUENCE */
            } else if(list_body[0] == 0x30) {
                const uint8_t *probe = list_body;
                const uint8_t *e0 = NULL;
                uint32_t e0_len = 0;
                if(asn1_get_sequence(&probe, list_end, &e0, &e0_len) == NOXTLS_RETURN_SUCCESS && e0_len > 0 && *e0 == 0x02) {
                    const uint8_t *walk = list_body;
                    uint32_t cap = NOXTLS_X509_CRL_MAX_REVOKED;
                    crl->revoked_serials = (uint8_t*)malloc((size_t)cap * (size_t)X509_MAX_SERIAL_SIZE);
                    crl->revoked_serial_lens = (uint32_t*)malloc((size_t)cap * sizeof(uint32_t));
                    if(crl->revoked_serials == NULL || crl->revoked_serial_lens == NULL) {
                        rc = NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
                        break;
                    }
                    while(walk < list_end) {
                        const uint8_t *entry = NULL;
                        uint32_t entry_len = 0;
                        const uint8_t *entry_end;
                        const uint8_t *ep;
                        uint8_t serial[X509_MAX_SERIAL_SIZE];
                        uint32_t slen = X509_MAX_SERIAL_SIZE;
                        if(asn1_get_sequence(&walk, list_end, &entry, &entry_len) != NOXTLS_RETURN_SUCCESS) {
                            rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
                            break;
                        }
                        entry_end = entry + entry_len;
                        ep = entry;
                        slen = X509_MAX_SERIAL_SIZE;
                        if(asn1_get_integer(&ep, entry_end, serial, &slen) != NOXTLS_RETURN_SUCCESS) {
                            rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
                            break;
                        }
                        if(crl->revoked_count >= cap) {
                            rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
                            break;
                        }
                        memcpy(crl->revoked_serials + (size_t)crl->revoked_count * (size_t)X509_MAX_SERIAL_SIZE, serial, slen);
                        if(slen < X509_MAX_SERIAL_SIZE) {
                            memset(crl->revoked_serials + (size_t)crl->revoked_count * (size_t)X509_MAX_SERIAL_SIZE + slen, 0,
                                (size_t)X509_MAX_SERIAL_SIZE - (size_t)slen);
                        }
                        crl->revoked_serial_lens[crl->revoked_count] = slen;
                        crl->revoked_count++;
                    }
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        break;
                    }
                } else {
                    tbs_ptr = save;
                }
            } else {
                tbs_ptr = save;
            }
        }

        if(tbs_ptr < tbs_end && *tbs_ptr == (uint8_t)0xA0) {
            /* crlExtensions [0] */
            tbs_ptr++;
            {
                uint32_t ext_len = asn1_get_length(&tbs_ptr, tbs_end);
                if(ext_len > (uint32_t)(tbs_end - tbs_ptr)) {
                    rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
                    break;
                }
                tbs_ptr += ext_len;
            }
        }

        if(tbs_ptr != tbs_end) {
            rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
            break;
        }

        /* Outer signatureAlgorithm + signature */
        {
            const uint8_t *sig_alg_data = NULL;
            uint32_t sig_alg_len = 0;
            if(asn1_get_sequence(&ptr, cert_list_end, &sig_alg_data, &sig_alg_len) != NOXTLS_RETURN_SUCCESS) {
                rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
                break;
            }
        }

        if(asn1_get_tag(&ptr, cert_list_end, 0x03) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
            break;
        }
        {
            uint32_t sig_len = asn1_get_length(&ptr, cert_list_end);
            if(sig_len == 0 || (size_t)(cert_list_end - ptr) < (size_t)sig_len) {
                rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
                break;
            }
            ptr++;
            sig_len--;
            crl->signature = (uint8_t*)malloc(sig_len);
            if(crl->signature == NULL) {
                rc = NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
                break;
            }
            memcpy(crl->signature, ptr, sig_len);
            crl->signature_len = sig_len;
            ptr += sig_len;
        }

        if(ptr != cert_list_end) {
            rc = NOXTLS_RETURN_CRL_PARSE_FAILED;
            break;
        }

        crl->parsed = 1;
    } while(0);

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
    uint32_t der_len = 0;
    noxtls_return_t rc;

    if(crl == NULL || data == NULL || len == 0) {
        return NOXTLS_RETURN_NULL;
    }

    der = (uint8_t*)malloc(len);
    if(der == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    rc = noxtls_x509_crl_pem_to_der(data, len, der, &der_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(der);
        return rc;
    }

    rc = noxtls_x509_crl_parse_der(crl, der, der_len);
    free(der);
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
noxtls_return_t noxtls_x509_crl_load_file(noxtls_x509_crl_t *crl, const char *filename)
{
    FILE *fp;
    uint8_t *data = NULL;
    uint32_t file_len = 0;
    noxtls_return_t rc;

    if(crl == NULL || filename == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    fp = noxtls_fopen(filename, "rb");
    if(fp == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    fseek(fp, 0, SEEK_END);
    file_len = (uint32_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if(file_len == 0 || file_len > X509_MAX_CRL_SIZE) {
        fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }

    data = (uint8_t*)malloc(file_len);
    if(data == NULL) {
        fclose(fp);
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    if(fread(data, 1, file_len, fp) != file_len) {
        free(data);
        fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }
    fclose(fp);

    rc = noxtls_x509_crl_parse_der(crl, data, file_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_x509_crl_parse_pem(crl, data, file_len);
    }
    free(data);
    return rc;
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
    uint32_t i;
    if(crl == NULL || cert == NULL || !crl->parsed || crl->revoked_serials == NULL || crl->revoked_serial_lens == NULL) {
        return 0;
    }
    for(i = 0; i < crl->revoked_count; i++) {
        const uint8_t *s = crl->revoked_serials + (size_t)i * (size_t)X509_MAX_SERIAL_SIZE;
        uint32_t slen = crl->revoked_serial_lens[i];
        if(x509_serial_equal_normalized(s, slen, cert->serial_number, cert->serial_number_len)) {
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
static noxtls_return_t noxtls_x509_crl_check_times(const noxtls_x509_crl_t *crl, noxtls_x509_verify_flags_t *flags_out)
{
    time_t now;
    time_t tu = 0;
    time_t nu = 0;
    uint32_t this_len;
    noxtls_return_t rc;

    if(crl == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    time(&now);

    this_len = 0;
    while(this_len < 15 && crl->this_update[this_len] != 0) {
        this_len++;
    }
    rc = noxtls_x509_asn1_time_to_timet(crl->this_update, this_len, &tu);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_CRL_PARSE_FAILED;
    }
    if(now < tu) {
        if(flags_out != NULL) {
            *flags_out |= NOXTLS_X509_VERIFY_FLAG_CRL_EXPIRED;
        }
        return NOXTLS_RETURN_CRL_EXPIRED;
    }

    if(crl->has_next_update) {
        uint32_t next_len = 0;
        while(next_len < 15 && crl->next_update[next_len] != 0) {
            next_len++;
        }
        rc = noxtls_x509_asn1_time_to_timet(crl->next_update, next_len, &nu);
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
static noxtls_return_t noxtls_x509_crl_check_times(const noxtls_x509_crl_t *crl, noxtls_x509_verify_flags_t *flags_out)
{
    (void)crl;
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
    noxtls_return_t rc;
    noxtls_hash_algos_t hash_algo;
    int is_rsa;
    uint8_t hash[64];
    uint32_t hash_len = 0;

    if(crl == NULL || issuer == NULL || !crl->parsed || !issuer->parsed) {
        return NOXTLS_RETURN_NULL;
    }
    if(crl->tbs_crl == NULL || crl->tbs_crl_len == 0 || crl->signature == NULL || crl->signature_len == 0) {
        return NOXTLS_RETURN_CRL_VERIFY_FAILED;
    }
    if(issuer->key_usage_bits != 0 &&
       (issuer->key_usage_bits & X509_KEY_USAGE_CRL_SIGN) == 0) {
        if(flags_out != NULL) {
            *flags_out |= NOXTLS_X509_VERIFY_FLAG_CRL_BAD_SIGNATURE;
        }
        return NOXTLS_RETURN_CRL_VERIFY_FAILED;
    }

    rc = noxtls_x509_map_signature_algorithm(crl->signature_algorithm_oid, crl->signature_algorithm_oid_len, &hash_algo, &is_rsa);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }

    if(hash_algo == NOXTLS_HASH_SHA_256) {
        noxtls_sha_ctx_t sha_ctx;
        noxtls_sha256_init(&sha_ctx, hash_algo);
        noxtls_sha256_update(&sha_ctx, crl->tbs_crl, crl->tbs_crl_len);
        hash_len = 32;
        rc = noxtls_sha256_finish(&sha_ctx, hash);
    } else if(hash_algo == NOXTLS_HASH_SHA_384) {
        noxtls_sha512_ctx_t sha_ctx;
        noxtls_sha512_init(&sha_ctx, hash_algo);
        noxtls_sha512_update(&sha_ctx, crl->tbs_crl, crl->tbs_crl_len);
        hash_len = 48;
        rc = noxtls_sha512_finish(&sha_ctx, hash);
    } else if(hash_algo == NOXTLS_HASH_SHA_512) {
        noxtls_sha512_ctx_t sha_ctx;
        noxtls_sha512_init(&sha_ctx, hash_algo);
        noxtls_sha512_update(&sha_ctx, crl->tbs_crl, crl->tbs_crl_len);
        hash_len = 64;
        rc = noxtls_sha512_finish(&sha_ctx, hash);
    } else {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }

    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(is_rsa == 1) {
        if(issuer->rsa_modulus == NULL || issuer->rsa_exponent == NULL) {
            if(flags_out != NULL) {
                *flags_out |= NOXTLS_X509_VERIFY_FLAG_CRL_BAD_SIGNATURE;
            }
            return NOXTLS_RETURN_CRL_VERIFY_FAILED;
        }
        {
            const uint8_t *mod_ptr = issuer->rsa_modulus;
            uint32_t mod_len = issuer->rsa_modulus_len;
            const uint8_t *exp_ptr = issuer->rsa_exponent;
            uint32_t exp_len = issuer->rsa_exponent_len;
            uint32_t key_bytes;
            rsa_key_size_t key_size;
            rsa_key_t rsa_key;
            while(mod_len > 0U && mod_ptr[0] == 0U) {
                mod_ptr++;
                mod_len--;
            }
            while(exp_len > 0U && exp_ptr[0] == 0U) {
                exp_ptr++;
                exp_len--;
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
                return NOXTLS_RETURN_INVALID_PARAM;
            }
            rc = noxtls_rsa_key_init(&rsa_key, key_size);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            if(mod_len == 0U || exp_len == 0U || mod_len > rsa_key.key_bytes || exp_len > rsa_key.key_bytes) {
                noxtls_rsa_key_free(&rsa_key);
                return NOXTLS_RETURN_INVALID_PARAM;
            }
            memcpy(rsa_key.n + (rsa_key.key_bytes - mod_len), mod_ptr, mod_len);
            memcpy(rsa_key.e + (rsa_key.key_bytes - exp_len), exp_ptr, exp_len);
            rc = noxtls_rsa_verify(&rsa_key, hash, hash_len, crl->signature, crl->signature_len, hash_algo);
            noxtls_rsa_key_free(&rsa_key);
        }
    } else if(is_rsa == 2) {
#if NOXTLS_FEATURE_ML_DSA
        if(!issuer->has_mldsa || issuer->mldsa_public_key_len == 0 || issuer->mldsa_param == 0) {
            if(flags_out != NULL) {
                *flags_out |= NOXTLS_X509_VERIFY_FLAG_CRL_BAD_SIGNATURE;
            }
            return NOXTLS_RETURN_CRL_VERIFY_FAILED;
        }
        rc = noxtls_mldsa_verify(issuer->mldsa_param, issuer->mldsa_public_key, hash, hash_len, crl->signature, crl->signature_len);
#else
        return NOXTLS_RETURN_INVALID_ALGORITHM;
#endif
    } else {
        ecc_curve_t curve_type;
        ecc_key_t ecc_key;
        const uint8_t *sig_ptr = crl->signature;
        const uint8_t *sig_end = crl->signature + crl->signature_len;
        const uint8_t *seq_data = NULL;
        uint32_t seq_len = 0;
        uint8_t r[ECC_MAX_KEY_SIZE];
        uint8_t s[ECC_MAX_KEY_SIZE];
        uint32_t r_len = ECC_MAX_KEY_SIZE;
        uint32_t s_len = ECC_MAX_KEY_SIZE;
        ecdsa_signature_t ecdsa_sig;

        if(issuer->ecc_public_key == NULL || issuer->ecc_public_key_len == 0) {
            if(flags_out != NULL) {
                *flags_out |= NOXTLS_X509_VERIFY_FLAG_CRL_BAD_SIGNATURE;
            }
            return NOXTLS_RETURN_CRL_VERIFY_FAILED;
        }
        if(issuer->ecc_curve_oid_len > 0) {
            if(noxtls_x509_ecc_curve_from_oid(issuer->ecc_curve_oid, issuer->ecc_curve_oid_len, &curve_type) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_INVALID_ALGORITHM;
            }
        } else {
            if(noxtls_x509_ecc_curve_from_pubkey_len(issuer->ecc_public_key_len, &curve_type) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_INVALID_ALGORITHM;
            }
        }
        rc = noxtls_ecc_key_init(&ecc_key, curve_type);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if(issuer->ecc_public_key[0] != 0x04) {
            noxtls_ecc_key_free(&ecc_key);
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        {
            uint32_t coord_size = ecc_key.curve->size;
            if(issuer->ecc_public_key_len != 1 + 2 * coord_size) {
                noxtls_ecc_key_free(&ecc_key);
                return NOXTLS_RETURN_INVALID_PARAM;
            }
            memcpy(ecc_key.Q.x, issuer->ecc_public_key + 1, coord_size);
            memcpy(ecc_key.Q.y, issuer->ecc_public_key + 1 + coord_size, coord_size);
            ecc_key.Q.size = coord_size;
            if(noxtls_ecc_point_validate_public(&ecc_key.Q, ecc_key.curve) != NOXTLS_RETURN_SUCCESS) {
                noxtls_ecc_key_free(&ecc_key);
                return NOXTLS_RETURN_INVALID_PARAM;
            }
        }

        if(asn1_get_tag(&sig_ptr, sig_end, 0x30) != NOXTLS_RETURN_SUCCESS) {
            noxtls_ecc_key_free(&ecc_key);
            return NOXTLS_RETURN_BAD_DATA;
        }
        seq_len = asn1_get_length(&sig_ptr, sig_end);
        if(seq_len == 0 || (size_t)(sig_end - sig_ptr) < (size_t)seq_len) {
            noxtls_ecc_key_free(&ecc_key);
            return NOXTLS_RETURN_BAD_DATA;
        }
        seq_data = sig_ptr;
        {
            const uint8_t *seq_end = seq_data + seq_len;
            if(asn1_get_integer(&sig_ptr, seq_end, r, &r_len) != NOXTLS_RETURN_SUCCESS) {
                noxtls_ecc_key_free(&ecc_key);
                return NOXTLS_RETURN_BAD_DATA;
            }
            if(asn1_get_integer(&sig_ptr, seq_end, s, &s_len) != NOXTLS_RETURN_SUCCESS) {
                noxtls_ecc_key_free(&ecc_key);
                return NOXTLS_RETURN_BAD_DATA;
            }
        }

        ecdsa_sig.size = ecc_key.curve->size;
        memset(ecdsa_sig.r, 0, ECC_MAX_KEY_SIZE);
        memset(ecdsa_sig.s, 0, ECC_MAX_KEY_SIZE);
        {
            uint32_t coord_size = ecc_key.curve->size;
            if(r_len <= coord_size) {
                memcpy(ecdsa_sig.r + coord_size - r_len, r, r_len);
            } else {
                uint32_t skip = r_len - coord_size;
                uint32_t i;
                for(i = 0; i < skip; i++) {
                    if(r[i] != 0) {
                        noxtls_ecc_key_free(&ecc_key);
                        return NOXTLS_RETURN_BAD_DATA;
                    }
                }
                memcpy(ecdsa_sig.r, r + skip, coord_size);
            }
            if(s_len <= coord_size) {
                memcpy(ecdsa_sig.s + coord_size - s_len, s, s_len);
            } else {
                uint32_t skip = s_len - coord_size;
                uint32_t i;
                for(i = 0; i < skip; i++) {
                    if(s[i] != 0) {
                        noxtls_ecc_key_free(&ecc_key);
                        return NOXTLS_RETURN_BAD_DATA;
                    }
                }
                memcpy(ecdsa_sig.s, s + skip, coord_size);
            }
        }

        rc = noxtls_ecdsa_verify(&ecc_key, crl->tbs_crl, crl->tbs_crl_len, &ecdsa_sig, hash_algo);
        noxtls_ecc_key_free(&ecc_key);
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
                                               const noxtls_x509_crl_t *crl_chain, noxtls_x509_verify_flags_t *flags_out)
{
    const noxtls_x509_crl_t *c;
    noxtls_return_t rc;

    if(cert == NULL || issuer == NULL || crl_chain == NULL) {
        return NOXTLS_RETURN_SUCCESS;
    }

    for(c = crl_chain; c != NULL; c = c->next) {
        if(!c->parsed) {
            continue;
        }
        if(!x509_dn_equal(c->issuer, c->issuer_len, issuer->subject, issuer->subject_len)) {
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

        rc = noxtls_x509_crl_check_times(c, flags_out);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            cert_fail_set(NOXTLS_RETURN_CRL_EXPIRED, cert, NULL, 0, 0);
            return NOXTLS_RETURN_CRL_EXPIRED;
        }

        if(noxtls_x509_crl_serial_is_revoked(c, cert)) {
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
    /*
     * Do not free published snapshots in-place: concurrent verifiers may still
     * be walking them. New verification calls will observe the cleared store.
     */
    s_x509_trust_anchors = NULL;
    s_x509_trust_anchors_initialized = 0;
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
    return (s_x509_trust_anchors_initialized && trust_anchors != NULL && trust_anchors->count > 0U) ? 1 : 0;
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

    if(trust_anchors == NULL || trust_anchors->count == 0) {
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
    if(crl != NULL && flags_out != NULL && (*flags_out & NOXTLS_X509_VERIFY_FLAG_CRL_USED) == 0) {
        *flags_out |= NOXTLS_X509_VERIFY_FLAG_CRL_NO_MATCH;
    }
}


/**
 * @brief Verify the trust of a certificate
 *
 * This function verifies the trust of a certificate.
 *
 * @param[in] leaf The leaf certificate to verify.
 * @param[in] presented_chain The presented chain to verify.
 * @param[in] required_eku The required Extended Key Usage.
 * @param[in] crl The CRL to verify.
 * @param[in] flags_out The flags to verify.
 * 
 * @return The return code of the function.
 */
static noxtls_return_t x509_verify_cert_trust_internal(const x509_certificate_t *leaf,
                                                       const x509_certificate_chain_t *presented_chain,
                                                       uint32_t required_eku,
                                                       const noxtls_x509_crl_t *crl,
                                                       noxtls_x509_verify_flags_t *flags_out)
{
    const x509_certificate_chain_t *trust_anchors = s_x509_trust_anchors;
    const x509_certificate_t *current;
    uint32_t depth = 0;
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

    if(!s_x509_trust_anchors_initialized || trust_anchors == NULL || trust_anchors->count == 0U) {
        cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED, leaf, NULL, 0, 0);
        return NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED;
    }

    {
        noxtls_return_t rc = noxtls_x509_certificate_check_validity(leaf);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    if(x509_leaf_policy_check(leaf, required_eku) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED;
    }

    current = leaf;

    while(depth < max_depth) {
        const x509_certificate_t *issuer = NULL;
        noxtls_return_t rc;

        if(x509_chain_contains_cert(trust_anchors, current)) {
            x509_verify_crl_note_no_match_if_needed(crl, flags_out);
            return NOXTLS_RETURN_SUCCESS;
        }

        if(presented_chain != NULL) {
            issuer = x509_find_issuer_in_chain(current, presented_chain);
        }
        if(issuer == NULL) {
            issuer = x509_find_issuer_in_chain(current, trust_anchors);
        }
        if(issuer == NULL || x509_is_same_cert(issuer, current)) {
            cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED, current, NULL, 0, depth);
            return NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED;
        }

        rc = noxtls_x509_certificate_verify_signature((x509_certificate_t*)current, issuer);
        if(rc != NOXTLS_RETURN_SUCCESS && presented_chain != NULL) {
            const x509_certificate_t *trust_issuer = x509_find_issuer_in_chain(current, trust_anchors);
            if(trust_issuer != NULL && !x509_is_same_cert(trust_issuer, current)) {
                noxtls_return_t trust_rc = noxtls_x509_certificate_verify_signature((x509_certificate_t*)current, trust_issuer);
                if(trust_rc == NOXTLS_RETURN_SUCCESS) {
                    issuer = trust_issuer;
                    rc = NOXTLS_RETURN_SUCCESS;
                }
            }
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            cert_fail_set(NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED, current, NULL, 0, depth);
            return NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED;
        }

        if(crl != NULL) {
            rc = x509_apply_crl_for_cert(current, issuer, crl, flags_out);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
        }

        rc = noxtls_x509_certificate_check_validity(issuer);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            s_cert_fail_info.cert_index = depth + 1U;
            return rc;
        }

        if(!x509_chain_contains_cert(trust_anchors, issuer)) {
            rc = x509_issuer_policy_check(issuer, depth);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
        }

        if(x509_chain_contains_cert(trust_anchors, issuer)) {
            x509_verify_crl_note_no_match_if_needed(crl, flags_out);
            return NOXTLS_RETURN_SUCCESS;
        }

        current = issuer;
        depth++;
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
    return x509_verify_cert_trust_internal(leaf, presented_chain, X509_EKU_SERVER_AUTH, NULL, NULL);
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
    return x509_verify_cert_trust_internal(leaf, presented_chain, X509_EKU_SERVER_AUTH, crl, flags_out);
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
    return x509_verify_cert_trust_internal(leaf, presented_chain, X509_EKU_CLIENT_AUTH, NULL, NULL);
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
    return x509_verify_cert_trust_internal(leaf, presented_chain, X509_EKU_CLIENT_AUTH, crl, flags_out);
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

    memset(key, 0, sizeof(x509_private_key_t));
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

    if(key->rsa_modulus) {
        free(key->rsa_modulus);
        key->rsa_modulus = NULL;
    }
    if(key->rsa_public_exponent) {
        free(key->rsa_public_exponent);
        key->rsa_public_exponent = NULL;
    }
    if(key->rsa_private_exponent) {
        free(key->rsa_private_exponent);
        key->rsa_private_exponent = NULL;
    }
    if(key->rsa_prime1) {
        free(key->rsa_prime1);
        key->rsa_prime1 = NULL;
    }
    if(key->rsa_prime2) {
        free(key->rsa_prime2);
        key->rsa_prime2 = NULL;
    }
    if(key->rsa_exponent1) {
        free(key->rsa_exponent1);
        key->rsa_exponent1 = NULL;
    }
    if(key->rsa_exponent2) {
        free(key->rsa_exponent2);
        key->rsa_exponent2 = NULL;
    }
    if(key->rsa_coefficient) {
        free(key->rsa_coefficient);
        key->rsa_coefficient = NULL;
    }
    if(key->ecc_private_key) {
        free(key->ecc_private_key);
        key->ecc_private_key = NULL;
    }
    if(key->ecc_public_key) {
        free(key->ecc_public_key);
        key->ecc_public_key = NULL;
    }
    if(key->eddsa_seed) {
        free(key->eddsa_seed);
        key->eddsa_seed = NULL;
    }
    if(key->pqc_secret_key) {
        /* Wipe before free - secret material from FIPS 204 / 205. */
        memset(key->pqc_secret_key, 0, key->pqc_secret_key_len);
        free(key->pqc_secret_key);
        key->pqc_secret_key = NULL;
    }
    if(key->raw_data) {
        free(key->raw_data);
        key->raw_data = NULL;
    }

    memset(key, 0, sizeof(x509_private_key_t));

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Parse PKCS#1 RSA Private Key (DER format)
 *
 * This function parses a PKCS#1 RSA private key (DER format).
 *
 * @param[in] key The X.509 private key structure to parse.
 * @param[in] data The DER data to parse.
 * @param[in] len The length of the DER data.
 * @return The return code of the function.
 */
static noxtls_return_t noxtls_x509_parse_pkcs1_rsa_private_key(x509_private_key_t *key, const uint8_t *data, uint32_t len)
{
    const uint8_t *ptr = data;
    const uint8_t *end = data + len;
    const uint8_t *seq_data = NULL;
    uint32_t seq_len = 0;

    if(asn1_get_sequence(&ptr, end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    const uint8_t *seq_end = seq_data + seq_len;
    const uint8_t *seq_ptr = seq_data;

    key->key_type = X509_PRIVATE_KEY_RSA;
    key->format = X509_PRIVATE_KEY_FORMAT_PKCS1;

    /* Parse version (should be 0) */
    if(asn1_get_integer(&seq_ptr, seq_end, NULL, &seq_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Modulus n (required). Probe first so we reject non-RSA e.g. PKCS#8 EC where next tag is 0x04 OCTET STRING. */
    {
        const uint8_t *probe = seq_ptr;
        if(asn1_get_integer(&probe, seq_end, NULL, &seq_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        key->rsa_modulus_len = seq_len;
        key->rsa_modulus = (uint8_t*)malloc(seq_len);
        if(key->rsa_modulus) {
            asn1_get_integer(&seq_ptr, seq_end, key->rsa_modulus, &key->rsa_modulus_len);
        } else {
            seq_ptr = probe;
        }
    }

    /* Parse public exponent e (required for valid PKCS#1) */
    {
        const uint8_t *probe = seq_ptr;
        if(asn1_get_integer(&probe, seq_end, NULL, &seq_len) != NOXTLS_RETURN_SUCCESS) {
            if(key->rsa_modulus) { free(key->rsa_modulus); key->rsa_modulus = NULL; }
            return NOXTLS_RETURN_FAILED;
        }
        key->rsa_public_exponent_len = seq_len;
        key->rsa_public_exponent = (uint8_t*)malloc(seq_len);
        if(key->rsa_public_exponent) {
            asn1_get_integer(&seq_ptr, seq_end, key->rsa_public_exponent, &key->rsa_public_exponent_len);
        } else {
            seq_ptr = probe;
        }
    }

    /* Parse private exponent d (required) */
    {
        const uint8_t *probe = seq_ptr;
        if(asn1_get_integer(&probe, seq_end, NULL, &seq_len) != NOXTLS_RETURN_SUCCESS) {
            if(key->rsa_modulus) { free(key->rsa_modulus); key->rsa_modulus = NULL; }
            if(key->rsa_public_exponent) { free(key->rsa_public_exponent); key->rsa_public_exponent = NULL; }
            return NOXTLS_RETURN_FAILED;
        }
        key->rsa_private_exponent_len = seq_len;
        key->rsa_private_exponent = (uint8_t*)malloc(seq_len);
        if(key->rsa_private_exponent) {
            asn1_get_integer(&seq_ptr, seq_end, key->rsa_private_exponent, &key->rsa_private_exponent_len);
        } else {
            seq_ptr = probe;
        }
    }

    /* Parse prime1 p */
    {
        const uint8_t *probe = seq_ptr;
        if(asn1_get_integer(&probe, seq_end, NULL, &seq_len) == NOXTLS_RETURN_SUCCESS) {
            key->rsa_prime1_len = seq_len;
            key->rsa_prime1 = (uint8_t*)malloc(seq_len);
            if(key->rsa_prime1) {
                asn1_get_integer(&seq_ptr, seq_end, key->rsa_prime1, &key->rsa_prime1_len);
            } else {
                seq_ptr = probe;
            }
        }
    }

    /* Parse prime2 q */
    {
        const uint8_t *probe = seq_ptr;
        if(asn1_get_integer(&probe, seq_end, NULL, &seq_len) == NOXTLS_RETURN_SUCCESS) {
            key->rsa_prime2_len = seq_len;
            key->rsa_prime2 = (uint8_t*)malloc(seq_len);
            if(key->rsa_prime2) {
                asn1_get_integer(&seq_ptr, seq_end, key->rsa_prime2, &key->rsa_prime2_len);
            } else {
                seq_ptr = probe;
            }
        }
    }

    /* Parse exponent1 (d mod (p-1)) */
    {
        const uint8_t *probe = seq_ptr;
        if(asn1_get_integer(&probe, seq_end, NULL, &seq_len) == NOXTLS_RETURN_SUCCESS) {
            key->rsa_exponent1_len = seq_len;
            key->rsa_exponent1 = (uint8_t*)malloc(seq_len);
            if(key->rsa_exponent1) {
                asn1_get_integer(&seq_ptr, seq_end, key->rsa_exponent1, &key->rsa_exponent1_len);
            } else {
                seq_ptr = probe;
            }
        }
    }

    /* Parse exponent2 (d mod (q-1)) */
    {
        const uint8_t *probe = seq_ptr;
        if(asn1_get_integer(&probe, seq_end, NULL, &seq_len) == NOXTLS_RETURN_SUCCESS) {
            key->rsa_exponent2_len = seq_len;
            key->rsa_exponent2 = (uint8_t*)malloc(seq_len);
            if(key->rsa_exponent2) {
                asn1_get_integer(&seq_ptr, seq_end, key->rsa_exponent2, &key->rsa_exponent2_len);
            } else {
                seq_ptr = probe;
            }
        }
    }

    /* Parse coefficient (q^-1 mod p) */
    {
        const uint8_t *probe = seq_ptr;
        if(asn1_get_integer(&probe, seq_end, NULL, &seq_len) == NOXTLS_RETURN_SUCCESS) {
            key->rsa_coefficient_len = seq_len;
            key->rsa_coefficient = (uint8_t*)malloc(seq_len);
            if(key->rsa_coefficient) {
                asn1_get_integer(&seq_ptr, seq_end, key->rsa_coefficient, &key->rsa_coefficient_len);
            } else {
                seq_ptr = probe;
            }
        }
    }

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
    const uint8_t *end = content + content_len;

    if(seed_out == NULL || seed_len_out == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(content_len == want_len) {
        *seed_out = content;
        *seed_len_out = want_len;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(asn1_get_tag(&p, end, 0x04) == NOXTLS_RETURN_SUCCESS) {
        uint32_t inner = asn1_get_length(&p, end);
        if(inner == want_len && p + inner <= end) {
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
    static const uint8_t id_ed25519[] = { 0x2B, 0x65, 0x70 };
    return l == sizeof(id_ed25519) && memcmp(o, id_ed25519, sizeof(id_ed25519)) == 0;
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
    static const uint8_t id_ed448[] = { 0x2B, 0x65, 0x71 };
    return l == sizeof(id_ed448) && memcmp(o, id_ed448, sizeof(id_ed448)) == 0;
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
    static const uint8_t prefix[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03 };
    if(l != sizeof(prefix) + 1 || memcmp(o, prefix, sizeof(prefix)) != 0) {
        return 0;
    }
    if(o[sizeof(prefix)] == 0x11) return (int)NOXTLS_MLDSA_44;
    if(o[sizeof(prefix)] == 0x12) return (int)NOXTLS_MLDSA_65;
    if(o[sizeof(prefix)] == 0x13) return (int)NOXTLS_MLDSA_87;
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
    static const uint8_t prefix[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03 };
    uint8_t arc;
    if(l != sizeof(prefix) + 1 || memcmp(o, prefix, sizeof(prefix)) != 0) {
        return 0;
    }
    arc = o[sizeof(prefix)];
    if(arc < 0x14 || arc > 0x1F) {
        return 0;
    }
    /* 0x14 → SHA2-128S (1), 0x15 → SHA2-128F (2), ... matches noxtls_slhdsa_param_t numbering. */
    return (int)(arc - 0x13);
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
    static const uint8_t oid_falcon512[] = { 0x2B, 0xCE, 0x0F, 0x03, 0x06 };
    static const uint8_t oid_falcon1024[] = { 0x2B, 0xCE, 0x0F, 0x03, 0x07 };
    if(o == NULL) {
        return 0;
    }
    if(l == sizeof(oid_falcon512) && memcmp(o, oid_falcon512, sizeof(oid_falcon512)) == 0) {
        return (int)NOXTLS_FALCON_512;
    }
    if(l == sizeof(oid_falcon1024) && memcmp(o, oid_falcon1024, sizeof(oid_falcon1024)) == 0) {
        return (int)NOXTLS_FALCON_1024;
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
    const uint8_t *end = data + len;
    const uint8_t *seq_data = NULL;
    uint32_t seq_len = 0;
    uint8_t version;
    uint8_t pkcs8_algorithm_oid[32];
    uint32_t pkcs8_algorithm_oid_len = 0;

    /* Parse PrivateKeyInfo SEQUENCE */
    if(asn1_get_sequence(&ptr, end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    const uint8_t *info_end = seq_data + seq_len;
    const uint8_t *info_ptr = seq_data;

    /* Parse version */
    if(asn1_get_integer(&info_ptr, info_end, &version, &seq_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    /* RFC 5208: version 0. Some exporters use version 1 for OneAsymmetricKey. Accept both. */
    if(version != 0 && version != 1) {
        key->encrypted = 1;
        return NOXTLS_RETURN_FAILED;
    }

    /* Standard PKCS#8 order: algorithm then privateKey. Some encodings use: privateKey then [0] curve then [1] public. */
    const uint8_t *alg_end = NULL;
    const uint8_t *alg_ptr = NULL;
    uint32_t private_key_len = 0;

    if(info_ptr >= info_end) {
        return NOXTLS_RETURN_FAILED;
    }

    if(*info_ptr == 0x04) {
        /* Alternate order: privateKey (OCTET STRING) comes first, then [0] curve OID, then [1] public (optional) */
        CERT_DEBUG_PRINT("x509_parse_pkcs8: alternate order (privateKey before algorithm)\n");
        if(asn1_get_tag(&info_ptr, info_end, 0x04) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        private_key_len = asn1_get_length(&info_ptr, info_end);
        if(private_key_len == 0 || info_ptr + private_key_len > info_end) {
            return NOXTLS_RETURN_FAILED;
        }
        /* info_ptr now points to the key bytes. Curve OID is in the next [0] IMPLICIT. */
        alg_ptr = info_ptr + private_key_len;
        alg_end = info_end;  /* rest of SEQUENCE for [0] and [1] */
    } else {
        /* Standard order: AlgorithmIdentifier SEQUENCE then PrivateKey OCTET STRING */
        if(asn1_get_sequence(&info_ptr, info_end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
            CERT_DEBUG_PRINT("x509_parse_pkcs8: no AlgorithmIdentifier SEQUENCE (first_byte=0x%02x)\n", info_ptr < info_end ? *info_ptr : 0);
            return NOXTLS_RETURN_FAILED;
        }
        alg_end = seq_data + seq_len;
        alg_ptr = seq_data;
        if(asn1_get_oid(&alg_ptr, alg_end, pkcs8_algorithm_oid, &pkcs8_algorithm_oid_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        if(asn1_get_tag(&info_ptr, info_end, 0x04) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        private_key_len = asn1_get_length(&info_ptr, info_end);
    }
    if(private_key_len == 0 || info_ptr + private_key_len > info_end) {
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

#if NOXTLS_FEATURE_ED25519
    if(pkcs8_algorithm_oid_len > 0 && x509_oid_is_ed25519(pkcs8_algorithm_oid, pkcs8_algorithm_oid_len)) {
        const uint8_t *seed_ptr = NULL;
        uint32_t seed_len = 0;
        if(x509_pkcs8_ed_seed_from_octet(info_ptr, private_key_len, 32, &seed_ptr, &seed_len) == NOXTLS_RETURN_SUCCESS) {
            noxtls_x509_private_key_free(key);
            key->raw_data = (uint8_t*)malloc(len);
            if(key->raw_data == NULL) {
                return NOXTLS_RETURN_FAILED;
            }
            memcpy(key->raw_data, data, len);
            key->raw_data_len = len;
            key->key_type = X509_PRIVATE_KEY_ED25519;
            key->format = X509_PRIVATE_KEY_FORMAT_PKCS8;
            key->eddsa_seed = (uint8_t*)malloc(32);
            if(key->eddsa_seed == NULL) {
                noxtls_x509_private_key_free(key);
                return NOXTLS_RETURN_FAILED;
            }
            memcpy(key->eddsa_seed, seed_ptr, 32);
            key->eddsa_seed_len = 32;
            CERT_DEBUG_PRINT("x509_parse_pkcs8: parsed as Ed25519 PKCS#8\n");
            return NOXTLS_RETURN_SUCCESS;
        }
    }
#endif
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
    if(pkcs8_algorithm_oid_len > 0 && x509_oid_is_ed448(pkcs8_algorithm_oid, pkcs8_algorithm_oid_len)) {
        const uint8_t *seed_ptr = NULL;
        uint32_t seed_len = 0;
        if(x509_pkcs8_ed_seed_from_octet(info_ptr, private_key_len, 57, &seed_ptr, &seed_len) == NOXTLS_RETURN_SUCCESS) {
            noxtls_x509_private_key_free(key);
            key->raw_data = (uint8_t*)malloc(len);
            if(key->raw_data == NULL) {
                return NOXTLS_RETURN_FAILED;
            }
            memcpy(key->raw_data, data, len);
            key->raw_data_len = len;
            key->key_type = X509_PRIVATE_KEY_ED448;
            key->format = X509_PRIVATE_KEY_FORMAT_PKCS8;
            key->eddsa_seed = (uint8_t*)malloc(57);
            if(key->eddsa_seed == NULL) {
                noxtls_x509_private_key_free(key);
                return NOXTLS_RETURN_FAILED;
            }
            memcpy(key->eddsa_seed, seed_ptr, 57);
            key->eddsa_seed_len = 57;
            CERT_DEBUG_PRINT("x509_parse_pkcs8: parsed as Ed448 PKCS#8\n");
            return NOXTLS_RETURN_SUCCESS;
        }
    }
#endif
#if NOXTLS_FEATURE_ML_DSA
    if(pkcs8_algorithm_oid_len > 0) {
        int mldsa_param = x509_oid_is_mldsa(pkcs8_algorithm_oid, pkcs8_algorithm_oid_len);
        if(mldsa_param != 0) {
            /* PKCS#8 OCTET STRING content holds the raw secret key. Some encodings
             * additionally wrap it in another OCTET STRING (draft-ietf-lamps-dilithium-certificates
             * section 5 permits "wrap" + "naked" forms); accept either. */
            const uint8_t *sk_ptr = info_ptr;
            uint32_t sk_len = private_key_len;
            uint32_t expected_sk = noxtls_mldsa_secret_key_len((noxtls_mldsa_param_t)mldsa_param);
            if(expected_sk == 0) {
                return NOXTLS_RETURN_FAILED;
            }
            if(sk_len != expected_sk) {
                const uint8_t *p = info_ptr;
                if(asn1_get_tag(&p, info_ptr + private_key_len, 0x04) == NOXTLS_RETURN_SUCCESS) {
                    uint32_t inner = asn1_get_length(&p, info_ptr + private_key_len);
                    if(inner == expected_sk && p + inner <= info_ptr + private_key_len) {
                        sk_ptr = p;
                        sk_len = inner;
                    }
                }
            }
            if(sk_len != expected_sk) {
                CERT_DEBUG_PRINT("x509_parse_pkcs8: ML-DSA secret length mismatch (%u vs %u)\n", sk_len, expected_sk);
                return NOXTLS_RETURN_FAILED;
            }
            noxtls_x509_private_key_free(key);
            key->raw_data = (uint8_t*)malloc(len);
            if(key->raw_data == NULL) {
                return NOXTLS_RETURN_FAILED;
            }
            memcpy(key->raw_data, data, len);
            key->raw_data_len = len;
            key->key_type = X509_PRIVATE_KEY_ML_DSA;
            key->format = X509_PRIVATE_KEY_FORMAT_PKCS8;
            key->pqc_param = (uint32_t)mldsa_param;
            key->pqc_secret_key = (uint8_t*)malloc(sk_len);
            if(key->pqc_secret_key == NULL) {
                noxtls_x509_private_key_free(key);
                return NOXTLS_RETURN_FAILED;
            }
            memcpy(key->pqc_secret_key, sk_ptr, sk_len);
            key->pqc_secret_key_len = sk_len;
            CERT_DEBUG_PRINT("x509_parse_pkcs8: parsed as ML-DSA PKCS#8 param=%d sk_len=%u\n", mldsa_param, sk_len);
            return NOXTLS_RETURN_SUCCESS;
        }
    }
#endif
#if NOXTLS_FEATURE_SLH_DSA
    if(pkcs8_algorithm_oid_len > 0) {
        int slhdsa_param = x509_oid_is_slhdsa(pkcs8_algorithm_oid, pkcs8_algorithm_oid_len);
        if(slhdsa_param != 0) {
            const uint8_t *sk_ptr = info_ptr;
            uint32_t sk_len = private_key_len;
            uint32_t expected_sk = noxtls_slhdsa_secret_key_len((noxtls_slhdsa_param_t)slhdsa_param);
            if(expected_sk == 0) {
                return NOXTLS_RETURN_FAILED;
            }
            if(sk_len != expected_sk) {
                const uint8_t *p = info_ptr;
                if(asn1_get_tag(&p, info_ptr + private_key_len, 0x04) == NOXTLS_RETURN_SUCCESS) {
                    uint32_t inner = asn1_get_length(&p, info_ptr + private_key_len);
                    if(inner == expected_sk && p + inner <= info_ptr + private_key_len) {
                        sk_ptr = p;
                        sk_len = inner;
                    }
                }
            }
            if(sk_len != expected_sk) {
                CERT_DEBUG_PRINT("x509_parse_pkcs8: SLH-DSA secret length mismatch (%u vs %u)\n", sk_len, expected_sk);
                return NOXTLS_RETURN_FAILED;
            }
            noxtls_x509_private_key_free(key);
            key->raw_data = (uint8_t*)malloc(len);
            if(key->raw_data == NULL) {
                return NOXTLS_RETURN_FAILED;
            }
            memcpy(key->raw_data, data, len);
            key->raw_data_len = len;
            key->key_type = X509_PRIVATE_KEY_SLH_DSA;
            key->format = X509_PRIVATE_KEY_FORMAT_PKCS8;
            key->pqc_param = (uint32_t)slhdsa_param;
            key->pqc_secret_key = (uint8_t*)malloc(sk_len);
            if(key->pqc_secret_key == NULL) {
                noxtls_x509_private_key_free(key);
                return NOXTLS_RETURN_FAILED;
            }
            memcpy(key->pqc_secret_key, sk_ptr, sk_len);
            key->pqc_secret_key_len = sk_len;
            CERT_DEBUG_PRINT("x509_parse_pkcs8: parsed as SLH-DSA PKCS#8 param=%d sk_len=%u\n", slhdsa_param, sk_len);
            return NOXTLS_RETURN_SUCCESS;
        }
    }
#endif
#if NOXTLS_FEATURE_FALCON
    if(pkcs8_algorithm_oid_len > 0) {
        int falcon_param = x509_oid_is_falcon(pkcs8_algorithm_oid, pkcs8_algorithm_oid_len);
        if(falcon_param != 0) {
            const uint8_t *sk_ptr = info_ptr;
            uint32_t sk_len = private_key_len;
            uint32_t expected_sk = noxtls_falcon_secret_key_len((noxtls_falcon_param_t)falcon_param);
            if(expected_sk == 0U) {
                return NOXTLS_RETURN_FAILED;
            }
            if(sk_len != expected_sk) {
                const uint8_t *p = info_ptr;
                if(asn1_get_tag(&p, info_ptr + private_key_len, 0x04) == NOXTLS_RETURN_SUCCESS) {
                    uint32_t inner = asn1_get_length(&p, info_ptr + private_key_len);
                    if(inner == expected_sk && p + inner <= info_ptr + private_key_len) {
                        sk_ptr = p;
                        sk_len = inner;
                    }
                }
            }
            if(sk_len != expected_sk) {
                CERT_DEBUG_PRINT("x509_parse_pkcs8: FALCON secret length mismatch (%u vs %u)\n", sk_len, expected_sk);
                return NOXTLS_RETURN_FAILED;
            }
            noxtls_x509_private_key_free(key);
            key->raw_data = (uint8_t*)malloc(len);
            if(key->raw_data == NULL) {
                return NOXTLS_RETURN_FAILED;
            }
            memcpy(key->raw_data, data, len);
            key->raw_data_len = len;
            key->key_type = X509_PRIVATE_KEY_FALCON;
            key->format = X509_PRIVATE_KEY_FORMAT_PKCS8;
            key->pqc_param = (uint32_t)falcon_param;
            key->pqc_secret_key = (uint8_t*)malloc(sk_len);
            if(key->pqc_secret_key == NULL) {
                noxtls_x509_private_key_free(key);
                return NOXTLS_RETURN_FAILED;
            }
            memcpy(key->pqc_secret_key, sk_ptr, sk_len);
            key->pqc_secret_key_len = sk_len;
            CERT_DEBUG_PRINT("x509_parse_pkcs8: parsed as FALCON PKCS#8 param=%d sk_len=%u\n", falcon_param, sk_len);
            return NOXTLS_RETURN_SUCCESS;
        }
    }
#endif

    /* Try SEC1 ECC (OCTET STRING content is DER ECPrivateKey, starts with 0x30) */
    if(info_ptr[0] == 0x30) {
        noxtls_x509_private_key_free(key);
        key->raw_data = (uint8_t*)malloc(len);
        if(key->raw_data == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(key->raw_data, data, len);
        key->raw_data_len = len;
        rc = noxtls_x509_parse_sec1_ecc_private_key(key, info_ptr, private_key_len);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            key->format = X509_PRIVATE_KEY_FORMAT_PKCS8;
            CERT_DEBUG_PRINT("x509_parse_pkcs8: parsed as SEC1 ECC\n");
            return NOXTLS_RETURN_SUCCESS;
        }
        CERT_DEBUG_PRINT("x509_parse_pkcs8: SEC1 ECC parse failed\n");
    } else {
        /* PKCS#8 EC with raw private key octets (no SEC1 wrapper). Curve OID in [0] params or in algorithm. */
        const uint8_t *params_ptr = alg_ptr;
        const uint8_t *params_end = alg_end != NULL ? alg_end : info_end;
        if(params_ptr < params_end && (*params_ptr & 0xE0) == 0xA0) {
            params_ptr++;
            uint32_t params_len = asn1_get_length(&params_ptr, params_end);
            CERT_DEBUG_PRINT("x509_parse_pkcs8: [0] params_len=%u\n", params_len);
            if(params_len > 0 && params_ptr + params_len <= params_end) {
                uint8_t curve_oid[32];
                uint32_t curve_oid_len = 0;
                const uint8_t *oid_end = params_ptr + params_len;
                if(asn1_get_oid(&params_ptr, oid_end, curve_oid, &curve_oid_len) == NOXTLS_RETURN_SUCCESS) {
                    if(curve_oid_len <= 32) {
                        noxtls_x509_private_key_free(key);
                        key->raw_data = (uint8_t*)malloc(len);
                        if(key->raw_data == NULL) {
                            return NOXTLS_RETURN_FAILED;
                        }
                        memcpy(key->raw_data, data, len);
                        key->raw_data_len = len;
                        key->key_type = X509_PRIVATE_KEY_ECC;
                        key->format = X509_PRIVATE_KEY_FORMAT_PKCS8;
                        key->ecc_curve_oid_len = curve_oid_len;
                        memcpy(key->ecc_curve_oid, curve_oid, curve_oid_len);
                        key->ecc_private_key_len = private_key_len;
                        key->ecc_private_key = (uint8_t*)malloc(private_key_len);
                        if(key->ecc_private_key) {
                            memcpy(key->ecc_private_key, info_ptr, private_key_len);
                        }
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
    const uint8_t *ptr = data;
    const uint8_t *end = data + len;
    const uint8_t *seq_data = NULL;
    uint32_t seq_len = 0;

    /* Parse ECPrivateKey SEQUENCE */
    if(asn1_get_sequence(&ptr, end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    const uint8_t *seq_end = seq_data + seq_len;
    const uint8_t *seq_ptr = seq_data;

    key->key_type = X509_PRIVATE_KEY_ECC;
    key->format = X509_PRIVATE_KEY_FORMAT_SEC1;

    /* Parse version (should be 1) */
    if(asn1_get_integer(&seq_ptr, seq_end, NULL, &seq_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Parse private key (OCTET STRING) */
    if(asn1_get_tag(&seq_ptr, seq_end, 0x04) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    uint32_t private_key_len = asn1_get_length(&seq_ptr, seq_end);
    if(private_key_len == 0 || seq_ptr + private_key_len > seq_end) {
        return NOXTLS_RETURN_FAILED;
    }

    key->ecc_private_key_len = private_key_len;
    key->ecc_private_key = (uint8_t*)malloc(private_key_len);
    if(key->ecc_private_key) {
        memcpy(key->ecc_private_key, seq_ptr, private_key_len);
    }
    seq_ptr += private_key_len;

    /* Parse parameters (optional) - [0] IMPLICIT ECParameters */
    if(seq_ptr < seq_end && (*seq_ptr & 0xE0) == 0xA0) {
        seq_ptr++;
        uint32_t params_len = asn1_get_length(&seq_ptr, seq_end);
        if(params_len > 0 && seq_ptr + params_len <= seq_end) {
            /* Parse curve OID */
            const uint8_t *params_ptr = seq_ptr;
            if(asn1_get_oid(&params_ptr, seq_ptr + params_len, key->ecc_curve_oid, &key->ecc_curve_oid_len) == NOXTLS_RETURN_SUCCESS) {
                /* Curve OID parsed */
            }
            seq_ptr += params_len;
        }
    }

    /* Parse public key (optional) - [1] IMPLICIT BIT STRING */
    if(seq_ptr < seq_end && (*seq_ptr & 0xE0) == 0xA0 && (*seq_ptr & 0x1F) == 0x01) {
        seq_ptr++;
        if(asn1_get_tag(&seq_ptr, seq_end, 0x03) == NOXTLS_RETURN_SUCCESS) {
            uint32_t public_key_len = asn1_get_length(&seq_ptr, seq_end);
            if(public_key_len > 0 && seq_ptr + public_key_len <= seq_end) {
                seq_ptr++;  /* Skip unused bits */
                public_key_len--;
                key->ecc_public_key_len = public_key_len;
                key->ecc_public_key = (uint8_t*)malloc(public_key_len);
                if(key->ecc_public_key) {
                    memcpy(key->ecc_public_key, seq_ptr, public_key_len);
                }
            }
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

#if NOXTLS_FEATURE_AES_CBC
/**
 * @brief Parse EncryptedPrivateKeyInfo (RFC 5208), decrypt with password using PBES2/PBKDF2/AES-CBC, then parse inner key.
 *
 * This function parses a EncryptedPrivateKeyInfo (RFC 5208), decrypt with password using PBES2/PBKDF2/AES-CBC, then parse inner key.
 *
 * @param[in] key The X.509 private key structure to parse.
 * @param[in] data The DER data to parse.
 * @param[in] len The length of the DER data.
 * @param[in] password The password to decrypt the key.
 * @param[in] password_len The length of the password.
 *
 * Returns NOXTLS_RETURN_SUCCESS and fills key on success.
 */
static noxtls_return_t noxtls_x509_parse_encrypted_pkcs8(x509_private_key_t *key, const uint8_t *data, uint32_t len,
                                                         const char *password, uint32_t password_len)
{
    const uint8_t *ptr = data;
    const uint8_t *end = data + len;
    const uint8_t *seq_data = NULL;
    uint32_t seq_len = 0;
    const uint8_t *alg_seq = NULL;
    uint32_t alg_len = 0;
    uint8_t oid_buf[32];
    uint32_t oid_len = 0;
    const uint8_t *pbes2_seq = NULL;
    uint32_t pbes2_len = 0;
    const uint8_t *kdf_seq = NULL;
    uint32_t kdf_len = 0;
    const uint8_t *salt = NULL;
    uint32_t salt_len = 0;
    uint8_t iter_buf[4];
    uint32_t iter_len = 0;
    uint32_t iterations = 0;
    const uint8_t *enc_seq = NULL;
    uint32_t enc_len = 0;
    const uint8_t *enc_data = NULL;
    uint32_t enc_data_len = 0;
    uint32_t key_bits = 0;
    noxtls_aes_type_t aes_type = NOXTLS_AES_128_BIT;
    uint8_t derived_key[32];
    uint8_t *decrypted = NULL;
    noxtls_return_t rc;
    uint32_t i;

    if(asn1_get_sequence(&ptr, end, &seq_data, &seq_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    const uint8_t *seq_end = seq_data + seq_len;
    if(seq_data[0] != 0x30) return NOXTLS_RETURN_FAILED;  /* first element must be AlgorithmIdentifier SEQUENCE */

    if(asn1_get_sequence(&ptr, seq_end, &alg_seq, &alg_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(asn1_get_oid(&ptr, alg_seq + alg_len, oid_buf, &oid_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(!oid_equal(oid_buf, oid_len, oid_pbes2, sizeof(oid_pbes2))) {
        return NOXTLS_RETURN_FAILED;  /* only PBES2 supported */
    }
    /* PBES2-params */
    if(asn1_get_sequence(&ptr, seq_end, &pbes2_seq, &pbes2_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    const uint8_t *pbes2_end = pbes2_seq + pbes2_len;
    /* keyDerivationFunc */
    if(asn1_get_sequence(&ptr, pbes2_end, &kdf_seq, &kdf_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(asn1_get_oid(&ptr, kdf_seq + kdf_len, oid_buf, &oid_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(!oid_equal(oid_buf, oid_len, oid_pbkdf2, sizeof(oid_pbkdf2))) {
        return NOXTLS_RETURN_FAILED;  /* only PBKDF2 */
    }
    /* PBKDF2-params: salt, iterationCount */
    if(asn1_get_octet_string(&ptr, pbes2_end, &salt, &salt_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    iter_len = 4;
    if(asn1_get_integer(&ptr, pbes2_end, iter_buf, &iter_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    for(i = 0; i < iter_len && i < 4; i++) {
        iterations = (iterations << 8) | iter_buf[i];
    }
    if(iterations == 0 || iterations > 10000000) {
        return NOXTLS_RETURN_FAILED;
    }
    /* encryptionScheme */
    if(asn1_get_sequence(&ptr, pbes2_end, &enc_seq, &enc_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(asn1_get_oid(&ptr, enc_seq + enc_len, oid_buf, &oid_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(oid_equal(oid_buf, oid_len, oid_aes128_cbc, sizeof(oid_aes128_cbc))) {
        key_bits = 16;
        aes_type = NOXTLS_AES_128_BIT;
    } else if(oid_equal(oid_buf, oid_len, oid_aes256_cbc, sizeof(oid_aes256_cbc))) {
        key_bits = 32;
        aes_type = NOXTLS_AES_256_BIT;
    } else {
        return NOXTLS_RETURN_FAILED;  /* only AES-128-CBC and AES-256-CBC */
    }
    /* encryptedData */
    if(asn1_get_octet_string(&ptr, seq_end, &enc_data, &enc_data_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(enc_data_len < NOXTLS_AES_BLOCK_LEN || (enc_data_len - NOXTLS_AES_BLOCK_LEN) % NOXTLS_AES_BLOCK_LEN != 0) {
        return NOXTLS_RETURN_FAILED;
    }
    {
        pbkdf2_sha1_params_t p = {salt_len, iterations, key_bits};
        if(pbkdf2_hmac_sha1((const uint8_t*)password, password_len, salt, &p, derived_key) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    decrypted = (uint8_t*)malloc(enc_data_len - NOXTLS_AES_BLOCK_LEN);
    if(decrypted == NULL) return NOXTLS_RETURN_FAILED;
    if(noxtls_aes_decrypt_cbc(derived_key, enc_data + NOXTLS_AES_BLOCK_LEN, enc_data_len - NOXTLS_AES_BLOCK_LEN, enc_data, decrypted, aes_type) != NOXTLS_RETURN_SUCCESS) {
        free(decrypted);
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_x509_private_key_free(key);
    rc = noxtls_x509_private_key_parse_der(key, decrypted, enc_data_len - NOXTLS_AES_BLOCK_LEN);
    memset(derived_key, 0, sizeof(derived_key));
    free(decrypted);
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
                                                                 const char *password, uint32_t password_len)
{
#if NOXTLS_FEATURE_AES_CBC
    if(key != NULL && data != NULL && len >= 2 && data[0] == 0x30) {
        const uint8_t *ptr = data;
        const uint8_t *end = data + len;
        const uint8_t *seq_data = NULL;
        uint32_t seq_len = 0;
        if(asn1_get_sequence(&ptr, end, &seq_data, &seq_len) == NOXTLS_RETURN_SUCCESS && seq_len > 0 && seq_data[0] == 0x30) {
            /* EncryptedPrivateKeyInfo: first element is SEQUENCE (AlgorithmIdentifier) */
            if(password != NULL && password_len > 0) {
                noxtls_return_t dec_rc = noxtls_x509_parse_encrypted_pkcs8(key, data, len, password, password_len);
                if(dec_rc == NOXTLS_RETURN_SUCCESS) {
                    return NOXTLS_RETURN_SUCCESS;
                }
                noxtls_x509_private_key_free(key);
                key->raw_data = (uint8_t*)malloc(len);
                if(key->raw_data != NULL) {
                    memcpy(key->raw_data, data, len);
                    key->raw_data_len = len;
                }
                key->encrypted = 1;
                return dec_rc;
            } else {
                noxtls_x509_private_key_free(key);
                key->raw_data = (uint8_t*)malloc(len);
                if(key->raw_data == NULL) return NOXTLS_RETURN_FAILED;
                memcpy(key->raw_data, data, len);
                key->raw_data_len = len;
                key->encrypted = 1;
                return NOXTLS_RETURN_FAILED;
            }
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

    if(key == NULL || data == NULL || len == 0) {
        return NOXTLS_RETURN_NULL;
    }

    /* Free any existing data */
    noxtls_x509_private_key_free(key);

    /* Detect EncryptedPrivateKeyInfo (first element of outer SEQUENCE is SEQUENCE, not INTEGER) */
    if(len >= 2 && data[0] == 0x30) {
        const uint8_t *ptr = data;
        const uint8_t *end = data + len;
        const uint8_t *seq_data = NULL;
        uint32_t seq_len = 0;
        if(asn1_get_sequence(&ptr, end, &seq_data, &seq_len) == NOXTLS_RETURN_SUCCESS && seq_len > 0 && seq_data[0] == 0x30) {
            key->raw_data = (uint8_t*)malloc(len);
            if(key->raw_data != NULL) {
                memcpy(key->raw_data, data, len);
                key->raw_data_len = len;
            }
            key->encrypted = 1;
            return NOXTLS_RETURN_FAILED;
        }
    }

    /* Store raw private key data */
    key->raw_data = (uint8_t*)malloc(len);
    if(key->raw_data == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(key->raw_data, data, len);
    key->raw_data_len = len;

    /* Try different formats */
    CERT_DEBUG_PRINT("x509_private_key_parse_der: len=%u first_bytes=0x%02x 0x%02x 0x%02x\n",
        len, len > 0 ? data[0] : 0, len > 1 ? data[1] : 0, len > 2 ? data[2] : 0);
    rc = noxtls_x509_parse_pkcs1_rsa_private_key(key, data, len);

    if(rc == NOXTLS_RETURN_SUCCESS) {
        key->parsed = 1;
        CERT_DEBUG_PRINT("x509_private_key_parse_der: parsed as PKCS#1 RSA\n");
        return NOXTLS_RETURN_SUCCESS;
    }

    rc = noxtls_x509_parse_pkcs8_private_key(key, data, len);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        key->parsed = 1;
        CERT_DEBUG_PRINT("x509_private_key_parse_der: parsed as PKCS#8 key_type=%d\n", key->key_type);
        return NOXTLS_RETURN_SUCCESS;
    }

    rc = noxtls_x509_parse_sec1_ecc_private_key(key, data, len);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        key->parsed = 1;
        CERT_DEBUG_PRINT("x509_private_key_parse_der: parsed as SEC1 ECC\n");
        return NOXTLS_RETURN_SUCCESS;
    }

    CERT_DEBUG_PRINT("x509_private_key_parse_der: all formats failed\n");
    noxtls_x509_private_key_free(key);
    return NOXTLS_RETURN_FAILED;
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
static const uint8_t *x509_memfind(const uint8_t *buf, uint32_t len, const char *needle)
{
    size_t nlen;
    uint32_t i;

    if(buf == NULL || needle == NULL) {
        return NULL;
    }
    nlen = strlen(needle);
    if(nlen == 0U || (size_t)len < nlen) {
        return NULL;
    }
    for(i = 0; (size_t)i + nlen <= (size_t)len; i++) {
        if(memcmp(buf + i, needle, nlen) == 0) {
            return buf + i;
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
    uint32_t der_len = 0;
    int decoded_len = 0;
    noxtls_return_t rc;
    const char *begin_marker = NULL;
    const char *end_marker = NULL;
    const uint8_t *pem_start = NULL;
    const uint8_t *pem_end = NULL;
    uint32_t pem_data_len = 0;

    if(key == NULL || data == NULL || len == 0) {
        return NOXTLS_RETURN_NULL;
    }

    /* Find PEM markers */
    if(x509_memfind(data, len, "-----BEGIN RSA PRIVATE KEY-----") != NULL) {
        begin_marker = "-----BEGIN RSA PRIVATE KEY-----";
        end_marker = "-----END RSA PRIVATE KEY-----";
    } else if(x509_memfind(data, len, "-----BEGIN PRIVATE KEY-----") != NULL) {
        begin_marker = "-----BEGIN PRIVATE KEY-----";
        end_marker = "-----END PRIVATE KEY-----";
    } else if(x509_memfind(data, len, "-----BEGIN EC PRIVATE KEY-----") != NULL) {
        begin_marker = "-----BEGIN EC PRIVATE KEY-----";
        end_marker = "-----END EC PRIVATE KEY-----";
    } else if(x509_memfind(data, len, "-----BEGIN ENCRYPTED PRIVATE KEY-----") != NULL) {
        begin_marker = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
        end_marker = "-----END ENCRYPTED PRIVATE KEY-----";
    } else {
        return NOXTLS_RETURN_FAILED;
    }

    /* Find start of base64 data */
    pem_start = x509_memfind(data, len, begin_marker);
    if(pem_start == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    pem_start += strlen(begin_marker);

    /* Skip whitespace */
    while(pem_start < data + len && (*pem_start == '\n' || *pem_start == '\r' || *pem_start == ' ')) {
        pem_start++;
    }

    /* Find end of base64 data */
    if(pem_start > data + len) {
        return NOXTLS_RETURN_FAILED;
    }
    {
        uint32_t tail_len = (uint32_t)((size_t)((data + len) - pem_start));
        pem_end = x509_memfind(pem_start, tail_len, end_marker);
    }
    if(pem_end == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Skip trailing whitespace before end marker */
    while(pem_end > pem_start && (*(pem_end - 1) == '\n' || *(pem_end - 1) == '\r' || *(pem_end - 1) == ' ')) {
        pem_end--;
    }

    {
        ptrdiff_t pem_len = pem_end - pem_start;
        if(pem_len < 0 || pem_len > UINT32_MAX) {
            return NOXTLS_RETURN_FAILED;
        }
        pem_data_len = (uint32_t)pem_len;
    }

    /* Allocate buffer for DER data */
    der_data = (uint8_t*)malloc(pem_data_len);
    if(der_data == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Convert PEM to DER */
    decoded_len = noxtls_base64_decode((char*)pem_start, pem_data_len, der_data);
    if(decoded_len <= 0) {
        free(der_data);
        return NOXTLS_RETURN_FAILED;
    }
    if((unsigned long)decoded_len > UINT32_MAX) {
        free(der_data);
        return NOXTLS_RETURN_FAILED;
    }
    der_len = (uint32_t)decoded_len;

    /* Parse DER */
    rc = noxtls_x509_private_key_parse_der(key, der_data, der_len);

    free(der_data);

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
                                                                 const char *password, uint32_t password_len)
{
    uint8_t *der_data = NULL;
    uint32_t der_len = 0;
    int decoded_len = 0;
    noxtls_return_t rc;
    const char *begin_marker = NULL;
    const char *end_marker = NULL;
    const uint8_t *pem_start = NULL;
    const uint8_t *pem_end = NULL;
    uint32_t pem_data_len = 0;
    int is_encrypted = 0;

    if(key == NULL || data == NULL || len == 0) {
        return NOXTLS_RETURN_NULL;
    }

    if(x509_memfind(data, len, "-----BEGIN ENCRYPTED PRIVATE KEY-----") != NULL) {
        begin_marker = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
        end_marker = "-----END ENCRYPTED PRIVATE KEY-----";
        is_encrypted = 1;
    } else if(x509_memfind(data, len, "-----BEGIN RSA PRIVATE KEY-----") != NULL) {
        begin_marker = "-----BEGIN RSA PRIVATE KEY-----";
        end_marker = "-----END RSA PRIVATE KEY-----";
    } else if(x509_memfind(data, len, "-----BEGIN PRIVATE KEY-----") != NULL) {
        begin_marker = "-----BEGIN PRIVATE KEY-----";
        end_marker = "-----END PRIVATE KEY-----";
    } else if(x509_memfind(data, len, "-----BEGIN EC PRIVATE KEY-----") != NULL) {
        begin_marker = "-----BEGIN EC PRIVATE KEY-----";
        end_marker = "-----END EC PRIVATE KEY-----";
    } else {
        return NOXTLS_RETURN_FAILED;
    }

    pem_start = x509_memfind(data, len, begin_marker);
    if(pem_start == NULL) return NOXTLS_RETURN_FAILED;
    pem_start += strlen(begin_marker);

    while(pem_start < data + len && (*pem_start == '\n' || *pem_start == '\r' || *pem_start == ' ')) {
        pem_start++;
    }

    if(pem_start > data + len) return NOXTLS_RETURN_FAILED;
    {
        uint32_t tail_len = (uint32_t)((size_t)((data + len) - pem_start));
        pem_end = x509_memfind(pem_start, tail_len, end_marker);
    }
    if(pem_end == NULL) return NOXTLS_RETURN_FAILED;
    while(pem_end > pem_start && (*(pem_end - 1) == '\n' || *(pem_end - 1) == '\r' || *(pem_end - 1) == ' ')) {
        pem_end--;
    }

    {
        ptrdiff_t pem_len = pem_end - pem_start;
        if(pem_len < 0 || (unsigned long)pem_len > UINT32_MAX) return NOXTLS_RETURN_FAILED;
        pem_data_len = (uint32_t)pem_len;
    }

    der_data = (uint8_t*)malloc(pem_data_len);
    if(der_data == NULL) return NOXTLS_RETURN_FAILED;
    decoded_len = noxtls_base64_decode((char*)pem_start, pem_data_len, der_data);
    if(decoded_len <= 0) {
        free(der_data);
        return NOXTLS_RETURN_FAILED;
    }
    if((unsigned long)decoded_len > UINT32_MAX) {
        free(der_data);
        return NOXTLS_RETURN_FAILED;
    }
    der_len = (uint32_t)decoded_len;

    if(is_encrypted) {
        rc = noxtls_x509_private_key_parse_der_with_password(key, der_data, der_len, password, password_len);
    } else {
        rc = noxtls_x509_private_key_parse_der_with_password(key, der_data, der_len, NULL, 0);
    }

    free(der_data);
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
noxtls_return_t noxtls_x509_private_key_load_file(x509_private_key_t *key, const char *filename)
{
    FILE *fp;
    uint8_t *data = NULL;
    uint32_t len = 0;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(key == NULL || filename == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    fp = noxtls_fopen(filename, "rb");
    if(fp == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Get file size */
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if(len == 0 || len > X509_MAX_PRIVATE_KEY_SIZE) {
        fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }

    data = (uint8_t*)malloc(len);
    if(data == NULL) {
        fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }

    if(fread(data, 1, len, fp) != len) {
        free(data);
        fclose(fp);
        return NOXTLS_RETURN_FAILED;
    }

    fclose(fp);

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

    free(data);

    return rc;
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
        memcpy(dest, src + (src_len - dest_len), dest_len);
    } else {
        memset(dest, 0, dest_len - src_len);
        memcpy(dest + (dest_len - src_len), src, src_len);
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
    rsa_key_size_t key_size;
    uint32_t key_bytes;
    uint32_t prime_len;

    if(key == NULL || rsa_key == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(key->key_type != X509_PRIVATE_KEY_RSA || !key->parsed) {
        return NOXTLS_RETURN_FAILED;
    }

    if(key->rsa_modulus == NULL || key->rsa_modulus_len == 0 ||
       key->rsa_public_exponent == NULL || key->rsa_public_exponent_len == 0 ||
       key->rsa_private_exponent == NULL || key->rsa_private_exponent_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Modulus length may include leading zero (DER); use canonical key size */
    if(key->rsa_modulus_len == X509_RSA_MODULUS_BYTES_1024 ||
       key->rsa_modulus_len == (X509_RSA_MODULUS_BYTES_1024 + 1U)) {
        key_bytes = X509_RSA_MODULUS_BYTES_1024;
        key_size = RSA_1024_BIT;
    } else if(key->rsa_modulus_len == X509_RSA_MODULUS_BYTES_2048 ||
              key->rsa_modulus_len == (X509_RSA_MODULUS_BYTES_2048 + 1U)) {
        key_bytes = X509_RSA_MODULUS_BYTES_2048;
        key_size = RSA_2048_BIT;
    } else if(key->rsa_modulus_len == X509_RSA_MODULUS_BYTES_3072 ||
              key->rsa_modulus_len == (X509_RSA_MODULUS_BYTES_3072 + 1U)) {
        key_bytes = X509_RSA_MODULUS_BYTES_3072;
        key_size = RSA_3072_BIT;
    } else if(key->rsa_modulus_len == X509_RSA_MODULUS_BYTES_4096 ||
              key->rsa_modulus_len == (X509_RSA_MODULUS_BYTES_4096 + 1U)) {
        key_bytes = X509_RSA_MODULUS_BYTES_4096;
        key_size = RSA_4096_BIT;
    } else {
        return NOXTLS_RETURN_FAILED;
    }

    prime_len = key_bytes >> 1;
    if(key->rsa_prime1 == NULL || key->rsa_prime1_len == 0 ||
       key->rsa_prime2 == NULL || key->rsa_prime2_len == 0 ||
       key->rsa_exponent1 == NULL || key->rsa_exponent1_len == 0 ||
       key->rsa_exponent2 == NULL || key->rsa_exponent2_len == 0 ||
       key->rsa_coefficient == NULL || key->rsa_coefficient_len == 0) {
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
    noxtls_return_t rc;
    ecc_curve_t curve_type;
    uint32_t size;

    if(key == NULL || ecc_key == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(key->key_type != X509_PRIVATE_KEY_ECC || !key->parsed) {
        return NOXTLS_RETURN_FAILED;
    }

    if(key->ecc_private_key == NULL || key->ecc_private_key_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    if(key->ecc_curve_oid_len > 0) {
        rc = noxtls_x509_ecc_curve_from_oid(key->ecc_curve_oid, key->ecc_curve_oid_len, &curve_type);
    } else {
        rc = noxtls_x509_ecc_curve_from_pubkey_len(key->ecc_public_key_len > 0 ? key->ecc_public_key_len : 65, &curve_type);
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
        noxtls_ecc_key_free(ecc_key);
        return NOXTLS_RETURN_BAD_DATA;
    }
    memcpy(ecc_key->d + (size - key->ecc_private_key_len), key->ecc_private_key, key->ecc_private_key_len);

    if(key->ecc_public_key != NULL && key->ecc_public_key_len > 0U) {
        if(key->ecc_public_key[0] != 0x04u || key->ecc_public_key_len != 1U + (2U * size)) {
            noxtls_ecc_key_free(ecc_key);
            return NOXTLS_RETURN_BAD_DATA;
        }
        memcpy(ecc_key->Q.x, key->ecc_public_key + 1U, size);
        memcpy(ecc_key->Q.y, key->ecc_public_key + 1U + size, size);
        ecc_key->Q.size = size;
        rc = noxtls_ecc_point_validate_public(&ecc_key->Q, ecc_key->curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_ecc_key_free(ecc_key);
            return rc;
        }
    } else {
        rc = noxtls_ecc_point_multiply(&ecc_key->Q, ecc_key->d, &ecc_key->curve->G, ecc_key->curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_ecc_key_free(ecc_key);
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
    noxtls_return_t rc;
    x509_private_key_t pk;
    ecc_key_t ecc_key;
    ecdsa_signature_t sig;
    uint8_t *der_buf;
    const uint32_t der_buf_size = 256;
    uint8_t r_enc[ECC_MAX_KEY_SIZE + 2];
    uint8_t s_enc[ECC_MAX_KEY_SIZE + 2];
    uint32_t r_enc_len;
    uint32_t s_enc_len;
    uint32_t seq_len;
    uint32_t total;

    if(key == NULL || data == NULL || out_der == NULL || out_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(out_max < 8) {
        return NOXTLS_RETURN_FAILED; /* minimum for tiny DER; Ed/ECDSA paths check larger out_max */
    }

    noxtls_x509_private_key_init(&pk);
    rc = noxtls_x509_private_key_parse_der(&pk, key, key_len);

    if(rc != NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_x509_private_key_parse_pem(&pk, key, key_len);
    }

    if(rc != NOXTLS_RETURN_SUCCESS) {
        CERT_DEBUG_PRINT("x509_private_key_sign_data: parse failed rc=%d\n", rc);
        noxtls_x509_private_key_free(&pk);
        return rc;
    }

    if(pk.key_type == X509_PRIVATE_KEY_ECC) {
        rc = noxtls_x509_private_key_to_ecc_key(&pk, &ecc_key);
        noxtls_x509_private_key_free(&pk);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            CERT_DEBUG_PRINT("x509_private_key_sign_data: to_ecc_key failed rc=%d\n", rc);
            return rc;
        }

        memset(&sig, 0, sizeof(sig));
        sig.size = ecc_key.curve->size;
        rc = noxtls_ecdsa_sign(&ecc_key, data, data_len, &sig, hash_algo);
        noxtls_ecc_key_free(&ecc_key);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }

        r_enc_len = noxtls_asn1_put_integer(r_enc, sizeof(r_enc), sig.r, sig.size);
        s_enc_len = noxtls_asn1_put_integer(s_enc, sizeof(s_enc), sig.s, sig.size);
        if(r_enc_len == 0 || s_enc_len == 0) {
            return NOXTLS_RETURN_FAILED;
        }
        seq_len = r_enc_len + s_enc_len;

        der_buf = (uint8_t *)noxtls_malloc(der_buf_size);
        if(der_buf == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        if(seq_len > der_buf_size - 8) {
            noxtls_free(der_buf);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(der_buf, r_enc, r_enc_len);
        memcpy(der_buf + r_enc_len, s_enc, s_enc_len);
        total = noxtls_asn1_put_sequence(out_der, out_max, der_buf, seq_len);
        noxtls_free(der_buf);
        if(total == 0) {
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
        uint32_t sig_len;

        rc = noxtls_x509_private_key_to_rsa_key(&pk, &rsa_key);
        noxtls_x509_private_key_free(&pk);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            CERT_DEBUG_PRINT("x509_private_key_sign_data: to_rsa_key failed rc=%d\n", rc);
            return rc;
        }

        if(out_max < rsa_key.key_bytes) {
            noxtls_rsa_key_free(&rsa_key);
            return NOXTLS_RETURN_FAILED;
        }

        sig_len = out_max;
        rc = noxtls_rsa_sign(&rsa_key, data, data_len, out_der, &sig_len, hash_algo);
        noxtls_rsa_key_free(&rsa_key);
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
        uint32_t slen = 0;
        const uint8_t *seed = noxtls_x509_private_key_get_eddsa_seed(&pk, &slen);
        (void)hash_algo;
        if(seed == NULL || slen != sizeof(seed_buf) || out_max < NOXTLS_ED25519_SIGNATURE_SIZE) {
            noxtls_x509_private_key_free(&pk);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(seed_buf, seed, sizeof(seed_buf));
        noxtls_x509_private_key_free(&pk);
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
        uint32_t slen = 0;
        const uint8_t *seed = noxtls_x509_private_key_get_eddsa_seed(&pk, &slen);
        (void)hash_algo;
        if(seed == NULL || slen != sizeof(seed_buf) || out_max < NOXTLS_ED448_SIGNATURE_SIZE) {
            noxtls_x509_private_key_free(&pk);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(seed_buf, seed, sizeof(seed_buf));
        noxtls_x509_private_key_free(&pk);
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
        if(sig_max == 0 || out_max < sig_max ||
           pk.pqc_secret_key == NULL || pk.pqc_secret_key_len == 0) {
            noxtls_x509_private_key_free(&pk);
            return NOXTLS_RETURN_FAILED;
        }
        rc = noxtls_mldsa_sign(param, pk.pqc_secret_key, data, data_len, out_der, &sig_len);
        noxtls_x509_private_key_free(&pk);
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
        if(sig_max == 0 || out_max < sig_max ||
           pk.pqc_secret_key == NULL || pk.pqc_secret_key_len == 0) {
            noxtls_x509_private_key_free(&pk);
            return NOXTLS_RETURN_FAILED;
        }
        rc = noxtls_slhdsa_sign(param, pk.pqc_secret_key, data, data_len, out_der, &sig_len);
        noxtls_x509_private_key_free(&pk);
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
            noxtls_x509_private_key_free(&pk);
            return NOXTLS_RETURN_FAILED;
        }
        rc = noxtls_falcon_sign(param, pk.pqc_secret_key, data, data_len, out_der, &sig_len);
        noxtls_x509_private_key_free(&pk);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        *out_len = sig_len;
        return NOXTLS_RETURN_SUCCESS;
    }
#endif

    CERT_DEBUG_PRINT("x509_private_key_sign_data: key_type=%d (unsupported)\n", pk.key_type);
    noxtls_x509_private_key_free(&pk);
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
    if(key == NULL || out_len == NULL) {
        return NULL;
    }
    *out_len = 0;
#if NOXTLS_FEATURE_ED25519
    if(key->key_type == X509_PRIVATE_KEY_ED25519 && key->eddsa_seed != NULL && key->eddsa_seed_len == 32) {
        *out_len = 32;
        return key->eddsa_seed;
    }
#endif
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
    if(key->key_type == X509_PRIVATE_KEY_ED448 && key->eddsa_seed != NULL && key->eddsa_seed_len == 57) {
        *out_len = 57;
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
        *out_len = 0;
    }
    if(out_param != NULL) {
        *out_param = 0;
    }
    if(key == NULL || out_len == NULL || out_param == NULL) {
        return NULL;
    }
    if(key->key_type != X509_PRIVATE_KEY_ML_DSA &&
       key->key_type != X509_PRIVATE_KEY_SLH_DSA &&
       key->key_type != X509_PRIVATE_KEY_FALCON) {
        return NULL;
    }
    if(key->pqc_secret_key == NULL || key->pqc_secret_key_len == 0) {
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
    if(key == NULL || ecc_key == NULL) {
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
void noxtls_x509_debug_print_oid(const char *label, const uint8_t *oid, uint32_t oid_len)
{
    if(label) {
        noxtls_debug_printf("%s: ", label);
    }

    if(oid == NULL || oid_len == 0) {
        noxtls_debug_printf("(empty)\n");
        return;
    }

    /* Print OID in dot notation (oid_len > 0 guaranteed by check above) */
    {
        uint32_t first = oid[0] / 40;
        uint32_t second = oid[0] % 40;
        noxtls_debug_printf("%u.%u", first, second);

        uint32_t value = 0;
        uint32_t i;
        for(i = 1; i < oid_len; i++) {
            value = (value << 7) | (oid[i] & 0x7F);
            if(!(oid[i] & 0x80)) {
                noxtls_debug_printf(".%u", value);
                value = 0;
            }
        }
    }
    noxtls_debug_printf("\n");
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
void noxtls_x509_debug_print_hex(const char *label, const uint8_t *data, uint32_t len, uint8_t verbose)
{
    uint32_t i;

    if(label) {
        noxtls_debug_printf("%s", label);
    }

    if(data == NULL || len == 0) {
        noxtls_debug_printf("(empty)\n");
        return;
    }

    if(verbose) {
        /* Print with line breaks every 16 bytes */
        noxtls_debug_printf(" (%u bytes):\n", len);
        for(i = 0; i < len; i++) {
            if(i > 0 && i % 16 == 0) {
                noxtls_debug_printf("\n    ");
            }
            noxtls_debug_printf("%02x ", data[i]);
        }
        noxtls_debug_printf("\n");
    } else {
        /* Print compact format */
        noxtls_debug_printf(" (%u bytes): ", len);
        for(i = 0; i < len && i < 32; i++) {
            noxtls_debug_printf("%02x", data[i]);
        }
        if(len > 32) {
            noxtls_debug_printf("...");
        }
        noxtls_debug_printf("\n");
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
    uint32_t i;

    if(cert == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_debug_printf("\n");
    noxtls_debug_printf("========================================\n");
    noxtls_debug_printf("X.509 Certificate Debug Information\n");
    noxtls_debug_printf("========================================\n\n");

    if(!cert->parsed) {
        noxtls_debug_printf("Status: NOT PARSED\n");
        if(cert->raw_data) {
            noxtls_debug_printf("Raw data available: %u bytes\n", cert->raw_data_len);
        }
        return NOXTLS_RETURN_FAILED;
    }

    noxtls_debug_printf("Status: PARSED\n\n");

    /* Basic Information */
    noxtls_debug_printf("--- Basic Information ---\n");
    noxtls_debug_printf("Version: %d", cert->version);
    if(cert->version == 0) {
        noxtls_debug_printf(" (v1)");
    } else if(cert->version == 1) {
        noxtls_debug_printf(" (v2)");
    } else if(cert->version == 2) {
        noxtls_debug_printf(" (v3)");
    }
    noxtls_debug_printf("\n");

    noxtls_debug_printf("Raw Data Length: %u bytes\n", cert->raw_data_len);
    noxtls_debug_printf("\n");

    /* Serial Number */
    noxtls_debug_printf("--- Serial Number ---\n");
    noxtls_x509_debug_print_hex("Serial Number", cert->serial_number, cert->serial_number_len, verbose);
    noxtls_debug_printf("\n");

    /* Signature Algorithm */
    noxtls_debug_printf("--- Signature Algorithm ---\n");
    noxtls_x509_debug_print_oid("Algorithm OID", cert->signature_algorithm_oid, cert->signature_algorithm_oid_len);
    noxtls_debug_printf("\n");

    /* Issuer */
    noxtls_debug_printf("--- Issuer ---\n");
    noxtls_debug_printf("Distinguished Name: %s\n", cert->issuer_dn[0] ? cert->issuer_dn : "(not parsed)");
    noxtls_x509_debug_print_hex("Raw Issuer", cert->issuer, cert->issuer_len, verbose);
    noxtls_debug_printf("\n");

    /* Validity */
    noxtls_debug_printf("--- Validity ---\n");
    noxtls_debug_printf("Not Before: ");
    for(i = 0; i < 15 && cert->not_before[i] != 0; i++) {
        noxtls_debug_printf("%c", cert->not_before[i]);
    }
    noxtls_debug_printf("\n");

    noxtls_debug_printf("Not After: ");
    for(i = 0; i < 15 && cert->not_after[i] != 0; i++) {
        noxtls_debug_printf("%c", cert->not_after[i]);
    }
    noxtls_debug_printf("\n");
    noxtls_debug_printf("\n");

    /* Subject */
    noxtls_debug_printf("--- Subject ---\n");
    noxtls_debug_printf("Distinguished Name: %s\n", cert->subject_dn[0] ? cert->subject_dn : "(not parsed)");
    noxtls_x509_debug_print_hex("Raw Subject", cert->subject, cert->subject_len, verbose);
    noxtls_debug_printf("\n");

    /* Public Key Information */
    noxtls_debug_printf("--- Public Key Information ---\n");
    noxtls_x509_debug_print_oid("Algorithm OID", cert->public_key_algorithm_oid, cert->public_key_algorithm_oid_len);

    if(cert->rsa_modulus) {
        noxtls_debug_printf("Key Type: RSA\n");
        noxtls_x509_debug_print_hex("Modulus (n)", cert->rsa_modulus, cert->rsa_modulus_len, verbose);
        noxtls_x509_debug_print_hex("Public Exponent (e)", cert->rsa_exponent, cert->rsa_exponent_len, verbose);
        noxtls_debug_printf("Key Size: %u bits\n", cert->rsa_modulus_len * 8);
    } else if(cert->ecc_public_key) {
        noxtls_debug_printf("Key Type: ECC\n");
        noxtls_x509_debug_print_oid("Curve OID", cert->ecc_curve_oid, cert->ecc_curve_oid_len);
        noxtls_x509_debug_print_hex("Public Key", cert->ecc_public_key, cert->ecc_public_key_len, verbose);
    } else {
        noxtls_debug_printf("Key Type: Unknown\n");
        noxtls_x509_debug_print_hex("Raw Public Key", cert->public_key, cert->public_key_len, verbose);
    }
    noxtls_debug_printf("\n");

    /* Extensions (v3) */
    if(cert->version >= 2 && cert->extensions) {
        noxtls_debug_printf("--- Extensions (v3) ---\n");
        noxtls_x509_debug_print_hex("Extensions Data", cert->extensions, cert->extensions_len, verbose);
        noxtls_debug_printf("\n");
    }

    /* Signature */
    noxtls_debug_printf("--- Signature ---\n");
    if(cert->signature) {
        noxtls_x509_debug_print_hex("Signature", cert->signature, cert->signature_len, verbose);
    } else {
        noxtls_debug_printf("Signature: (not available)\n");
    }
    noxtls_debug_printf("\n");

    /* Raw Data (if verbose) */
    if(verbose && cert->raw_data) {
        noxtls_debug_printf("--- Raw Certificate Data ---\n");
        noxtls_x509_debug_print_hex("DER Data", cert->raw_data, cert->raw_data_len, 1);
        noxtls_debug_printf("\n");
    }

    noxtls_debug_printf("========================================\n");
    noxtls_debug_printf("\n");

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

    noxtls_debug_printf("\n");
    noxtls_debug_printf("========================================\n");
    noxtls_debug_printf("X.509 Private Key Debug Information\n");
    noxtls_debug_printf("========================================\n\n");

    if(!key->parsed) {
        noxtls_debug_printf("Status: NOT PARSED\n");
        if(key->raw_data) {
            noxtls_debug_printf("Raw data available: %u bytes\n", key->raw_data_len);
        }
        return NOXTLS_RETURN_FAILED;
    }

    noxtls_debug_printf("Status: PARSED\n\n");

    /* Key Type and Format */
    noxtls_debug_printf("--- Key Information ---\n");
    if(key->key_type == X509_PRIVATE_KEY_RSA) {
        noxtls_debug_printf("Key Type: RSA\n");
    } else if(key->key_type == X509_PRIVATE_KEY_ECC) {
        noxtls_debug_printf("Key Type: ECC\n");
    } else if(key->key_type == X509_PRIVATE_KEY_ED25519) {
        noxtls_debug_printf("Key Type: Ed25519\n");
    } else if(key->key_type == X509_PRIVATE_KEY_ED448) {
        noxtls_debug_printf("Key Type: Ed448\n");
    } else {
        noxtls_debug_printf("Key Type: Unknown\n");
    }

    if(key->format == X509_PRIVATE_KEY_FORMAT_PKCS1) {
        noxtls_debug_printf("Format: PKCS#1\n");
    } else if(key->format == X509_PRIVATE_KEY_FORMAT_PKCS8) {
        noxtls_debug_printf("Format: PKCS#8\n");
    } else if(key->format == X509_PRIVATE_KEY_FORMAT_SEC1) {
        noxtls_debug_printf("Format: SEC1\n");
    } else {
        noxtls_debug_printf("Format: Unknown\n");
    }

    noxtls_debug_printf("Encrypted: %s\n", key->encrypted ? "YES" : "NO");
    noxtls_debug_printf("Raw Data Length: %u bytes\n", key->raw_data_len);
    noxtls_debug_printf("\n");

    if(key->key_type == X509_PRIVATE_KEY_RSA) {
        noxtls_debug_printf("--- RSA Private Key Components ---\n");

        if(key->rsa_modulus) {
            noxtls_x509_debug_print_hex("Modulus (n)", key->rsa_modulus, key->rsa_modulus_len, verbose);
            noxtls_debug_printf("Key Size: %u bits\n", key->rsa_modulus_len * 8);
        }

        if(key->rsa_public_exponent) {
            noxtls_x509_debug_print_hex("Public Exponent (e)", key->rsa_public_exponent, key->rsa_public_exponent_len, verbose);
        }

        if(key->rsa_private_exponent) {
            noxtls_x509_debug_print_hex("Private Exponent (d)", key->rsa_private_exponent, key->rsa_private_exponent_len, verbose);
        }

        if(key->rsa_prime1) {
            noxtls_x509_debug_print_hex("Prime 1 (p)", key->rsa_prime1, key->rsa_prime1_len, verbose);
        }

        if(key->rsa_prime2) {
            noxtls_x509_debug_print_hex("Prime 2 (q)", key->rsa_prime2, key->rsa_prime2_len, verbose);
        }

        if(key->rsa_exponent1) {
            noxtls_x509_debug_print_hex("Exponent 1 (dp = d mod (p-1))", key->rsa_exponent1, key->rsa_exponent1_len, verbose);
        }

        if(key->rsa_exponent2) {
            noxtls_x509_debug_print_hex("Exponent 2 (dq = d mod (q-1))", key->rsa_exponent2, key->rsa_exponent2_len, verbose);
        }

        if(key->rsa_coefficient) {
            noxtls_x509_debug_print_hex("Coefficient (qi = q^-1 mod p)", key->rsa_coefficient, key->rsa_coefficient_len, verbose);
        }

    } else if(key->key_type == X509_PRIVATE_KEY_ECC) {
        noxtls_debug_printf("--- ECC Private Key Components ---\n");

        if(key->ecc_private_key) {
            noxtls_x509_debug_print_hex("Private Key (d)", key->ecc_private_key, key->ecc_private_key_len, verbose);
        }

        if(key->ecc_curve_oid_len > 0) {
            noxtls_x509_debug_print_oid("Curve OID", key->ecc_curve_oid, key->ecc_curve_oid_len);
        }

        if(key->ecc_public_key) {
            noxtls_x509_debug_print_hex("Public Key (optional)", key->ecc_public_key, key->ecc_public_key_len, verbose);
        }
    } else if(key->key_type == X509_PRIVATE_KEY_ED25519 || key->key_type == X509_PRIVATE_KEY_ED448) {
        noxtls_debug_printf("--- EdDSA private key (RFC 8410 seed) ---\n");
        if(key->eddsa_seed) {
            noxtls_x509_debug_print_hex("Seed", key->eddsa_seed, key->eddsa_seed_len, verbose);
        }
    }

    noxtls_debug_printf("\n");

    /* Encryption Info */
    if(key->encrypted) {
        noxtls_debug_printf("--- Encryption Information ---\n");
        noxtls_x509_debug_print_oid("Encryption Algorithm OID", key->encryption_algorithm_oid, key->encryption_algorithm_oid_len);
        noxtls_debug_printf("Use noxtls_x509_private_key_parse_der_with_password or parse_pem_with_password to decrypt.\n");
        noxtls_debug_printf("\n");
    }

    /* Raw Data (if verbose) */
    if(verbose && key->raw_data) {
        noxtls_debug_printf("--- Raw Private Key Data ---\n");
        noxtls_x509_debug_print_hex("DER Data", key->raw_data, key->raw_data_len, 1);
        noxtls_debug_printf("\n");
    }

    noxtls_debug_printf("========================================\n");
    noxtls_debug_printf("\n");

    return NOXTLS_RETURN_SUCCESS;
}
