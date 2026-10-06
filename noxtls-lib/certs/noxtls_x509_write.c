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
* File:    noxtls_x509_write.c
* Summary: X.509 certificate writing and generation (optional module).
*          Compile with NOXTLS_HAVE_CERT_WRITE defined to enable.
*
*****************************************************************************/

#ifdef NOXTLS_HAVE_CERT_WRITE

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "noxtls_config.h"
#include "noxtls_common.h"
#include "common/noxtls_memory.h"
#include "noxtls_x509.h"
#include "certificates.h"
#include "asn1.h"
#include "noxtls_ct.h"

#ifndef X509_WRITE_TBS_MAX
#  if NOXTLS_FEATURE_ML_DSA
/* ML-DSA-87 SPKI body alone is ~2.6 KB; leave headroom for DN, validity, extensions. */
#    define X509_WRITE_TBS_MAX  8192U
#  else
#    define X509_WRITE_TBS_MAX  4096U
#  endif
#endif

#define X509_EXTENSIONS_MAX  1024U
#define X509_CSR_CRI_MAX  2048U

typedef struct {
    uint8_t val_part[260];
    uint8_t seq_content[260];
    uint8_t seq_attr[280];
    uint8_t set_rdn[300];
} x509_dn_from_cn_ws_t;

/* Per-feature-set sizing for the largest in-flight DER blob during cert/CSR
 * generation. The workspace is heap-allocated, so growing these constants
 * costs nothing on non-PQC builds and avoids stack pressure on PQC builds. */
#ifndef X509_WRITE_SIG_MAX
#  if NOXTLS_FEATURE_SLH_DSA
/* SLH-DSA-SHA2-256F: 49856 bytes — round to 50 KB. */
#    define X509_WRITE_SIG_MAX  51200U
#  elif NOXTLS_FEATURE_ML_DSA
/* ML-DSA-87: 4627 bytes. */
#    define X509_WRITE_SIG_MAX  4736U
#  else
/* RSA-4096 raw signature is 512 bytes; ECDSA DER ≤ 144B; EdDSA ≤ 114B. */
#    define X509_WRITE_SIG_MAX  640U
#  endif
#endif
#ifndef X509_WRITE_SIG_BITSTR_MAX
#  define X509_WRITE_SIG_BITSTR_MAX  (X509_WRITE_SIG_MAX + 16U)
#endif
/* SPKI body: must accommodate the largest subjectPublicKey for any enabled
 * algorithm. Largest is ML-DSA-87 (2592B) when PQC sigs are on. RSA-4096
 * RSAPublicKey is ~520B, EC point ≤ 133B, EdDSA ≤ 57B. */
#ifndef X509_WRITE_SPKI_BODY_MAX
#  if NOXTLS_FEATURE_ML_DSA
#    define X509_WRITE_SPKI_BODY_MAX  2816U
#  else
#    define X509_WRITE_SPKI_BODY_MAX  720U
#  endif
#endif

typedef struct {
    uint8_t tbs_buf[X509_WRITE_TBS_MAX];
    uint8_t spki_buf[X509_WRITE_SPKI_BODY_MAX];
    uint8_t tbs_full[X509_WRITE_TBS_MAX + 8U];
    uint8_t sig_der[X509_WRITE_SIG_MAX];
    uint8_t cert_seq_buf[X509_MAX_CERT_SIZE];
    uint8_t bitstr[X509_WRITE_SPKI_BODY_MAX];
    uint8_t spki_content[X509_WRITE_SPKI_BODY_MAX + 64U];
    uint8_t sig_bitstr[X509_WRITE_SIG_BITSTR_MAX];
} x509_cert_gen_ws_t;

typedef struct {
    uint8_t san_items[480];
    uint8_t san_seq[512];
    uint8_t san_oct[600];
    uint8_t san_ext_seq[640];
    uint8_t eku_oids[256];
    uint8_t eku_seq[280];
    uint8_t eku_oct[300];
    uint8_t eku_ext_seq[340];
    uint8_t ext_content[256];
    uint8_t oct_buf[200];
} x509_ext_build_ws_t;

typedef struct {
    uint8_t ext_buf[X509_EXTENSIONS_MAX];
    uint8_t ext_list[X509_EXTENSIONS_MAX];
    uint8_t ext_seq[X509_EXTENSIONS_MAX];
} x509_ext_wrap_ws_t;

typedef struct {
    uint8_t cri_buf[X509_CSR_CRI_MAX];
    uint8_t bitstr[X509_WRITE_SPKI_BODY_MAX];
    uint8_t spki_content[X509_WRITE_SPKI_BODY_MAX + 64U];
    uint8_t cri_seq[X509_CSR_CRI_MAX + 8U];
    uint8_t sig_der[X509_WRITE_SIG_MAX];
    uint8_t sig_bitstr[X509_WRITE_SIG_BITSTR_MAX];
    uint8_t cr_seq_buf[X509_CSR_CRI_MAX + 400U];
} x509_csr_ws_t;

/**
 * @brief Detect whether @p oid lies under the PKCS#1 arc (1.2.840.113549.1.1.x).
 *
 * The PKCS#1 family covers rsaEncryption (1.2.840.113549.1.1.1),
 * sha256WithRSAEncryption (..11), sha384WithRSAEncryption (..12),
 * sha512WithRSAEncryption (..13), and other RSA signature OIDs. RFC 3279 §2.3.1
 * and RFC 8017 require that AlgorithmIdentifier instances for these OIDs carry
 * explicit ASN.1 NULL parameters. Returning 1 means we should append `05 00`.
 */
static int oid_is_pkcs1_family(const uint8_t *pkcs_oid, uint32_t pkcs_oid_len)
{
    /* DER-encoded prefix for 1.2.840.113549.1.1 (rsaEncryption arc minus terminal arc). */
    static const uint8_t pkcs1_prefix[] = {
        0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x01U
    };

    if((pkcs_oid == NULL) || ((size_t)(pkcs_oid_len) < sizeof(pkcs1_prefix))) {
        return 0;
    }
    return ((noxtls_ct_equal(pkcs_oid, pkcs1_prefix, sizeof(pkcs1_prefix)) != 0)) ? 1 : 0;
}

/**
 * @brief Build an AlgorithmIdentifier SEQUENCE from a raw OID and optional params.
 *
 * Writes `SEQUENCE { OID [, params] }` to @p out.
 * - If @p params is non-NULL it is appended verbatim (caller-supplied DER —
 *   typically an OBJECT IDENTIFIER for EC namedCurve, or any other algorithm
 *   parameters body).
 * - Otherwise, when @p oid is part of the PKCS#1 family, an explicit ASN.1
 *   NULL is appended so the resulting certificate/CSR is RFC 3279 / 8017
 *   compliant and accepted by strict parsers (OpenSSL, mbedTLS, BoringSSL).
 * - For other algorithm families (ECDSA-with-SHA*, id-Ed25519, id-Ed448,
 *   id-ml-dsa-*, id-slh-dsa-*, ...), no parameters are emitted, as required
 *   by RFC 5758, RFC 8410, NIST SP 800-208, etc.
 *
 * @param[out] out         Output buffer.
 * @param[in]  out_max     Capacity of @p out.
 * @param[in]  oid         Raw DER OID octets (without tag/length).
 * @param[in]  oid_len     Length of @p oid.
 * @param[in]  params      Optional DER-encoded parameters to append (or NULL).
 * @param[in]  params_len  Length of @p params.
 * @return Bytes written, or 0 on error.
 */
static uint32_t put_algorithm_identifier(uint8_t *out, uint32_t out_max,
                                         const uint8_t *alg_oid, uint32_t alg_oid_len,
                                         const uint8_t *params, uint32_t params_len)
{
    uint8_t oid_der[48];
    /* Worst case: OID DER + arbitrary params (capped by params_len check). */
    uint8_t content[256];
    uint32_t oid_der_len = 0U;
    uint32_t content_len = 0U;

    if((out == NULL) || (alg_oid == NULL) || (alg_oid_len == 0U)) {
        return 0U;
    }
    oid_der_len = noxtls_asn1_put_oid_raw(oid_der, sizeof(oid_der), alg_oid, alg_oid_len);
    if((oid_der_len == 0U) || ((size_t)(oid_der_len) > sizeof(content))) {
        return 0U;
    }
    noxtls_copy_u8(content, sizeof(content), oid_der, (size_t)(oid_der_len));
    content_len = oid_der_len;

    if((params != NULL) && (params_len > 0U)) {
        if((content_len + params_len) > sizeof(content)) {
            return 0U;
        }
        noxtls_copy_u8(&content[content_len], sizeof(content) - (size_t)(content_len), params, (size_t)(params_len));
        content_len += params_len;
    } else if(oid_is_pkcs1_family(alg_oid, alg_oid_len) != 0) {
        if((content_len + 2U) > sizeof(content)) {
            return 0U;
        }
        content[content_len] = 0x05U; /* ASN.1 NULL tag */
        content_len += 1U;
        content[content_len] = 0x00U; /* ASN.1 NULL length */
        content_len += 1U;
    }
     else {
         /* MISRA 15.7: no remaining alternative */
     }

    return noxtls_asn1_put_sequence(out, out_max, content, content_len);
}

/**
 * @brief Builds a DER Name from a common name (CN).
 *
 * This function constructs a DER Name from a common name (CN) by creating a
 * sequence of SET, SEQUENCE, and OID elements.
 *
 * @param[in] cn      The common name to encode.
 * @param[out] out    Pointer to the buffer to receive the DER-encoded output.
 * @param[in] out_max Maximum length of the output buffer.
 * @param[out] out_len Pointer to a uint32_t that will receive the length of the output (not including null terminator).
 *
 * @return NOXTLS_RETURN_SUCCESS on success, or an appropriate error code from @see noxtls_return_t.
 */
static noxtls_return_t dn_from_cn(const uint8_t *cn, uint8_t *out, uint32_t out_max, uint32_t *out_len)
{
    /* CN OID local to this function (Rule 8.9). */
    static const uint8_t x509w_oid_cn_der[] = { 0x55U, 0x04U, 0x03U };

    uint8_t oid_part[16];
    x509_dn_from_cn_ws_t *ws = NULL;
    uint32_t cn_oid_len = 0U;
    uint32_t val_len = 0U;
    uint32_t seq_len = 0U;
    uint32_t set_len = 0U;
    uint32_t seq_outer_len = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((cn == NULL) || (out == NULL) || (out_len == NULL) || (out_max == 0U)) {
        return NOXTLS_RETURN_NULL;
    }

    ws = (x509_dn_from_cn_ws_t *)NOXTLS_MALLOC(sizeof(x509_dn_from_cn_ws_t));
    if(ws == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    cn_oid_len = noxtls_asn1_put_oid_raw(oid_part, sizeof(oid_part), x509w_oid_cn_der, sizeof(x509w_oid_cn_der));
    if(cn_oid_len == 0U) {
        (void)noxtls_free(ws);
        return rc;
    }
    val_len = noxtls_asn1_put_printable_string(ws->val_part, sizeof(ws->val_part), cn);
    if(val_len == 0U) {
        (void)noxtls_free(ws);
        return rc;
    }
    /* SEQUENCE content = OID + value (use separate buffer to avoid overlap in put_sequence) */
    if((cn_oid_len + val_len) > sizeof(ws->seq_content)) {
        (void)noxtls_free(ws);
        return rc;
    }
    noxtls_copy_u8(ws->seq_content, sizeof(ws->seq_content), oid_part, (size_t)(cn_oid_len));
    noxtls_copy_u8(&ws->seq_content[cn_oid_len], sizeof(ws->seq_content) - (size_t)(cn_oid_len), ws->val_part, (size_t)(val_len));
    seq_len = noxtls_asn1_put_sequence(ws->seq_attr, sizeof(ws->seq_attr), ws->seq_content, cn_oid_len + val_len);
    if(seq_len == 0U) {
        (void)noxtls_free(ws);
        return rc;
    }
    set_len = noxtls_asn1_put_set(ws->set_rdn, sizeof(ws->set_rdn), ws->seq_attr, seq_len);
    if(set_len == 0U) {
        (void)noxtls_free(ws);
        return rc;
    }
    seq_outer_len = noxtls_asn1_put_sequence(out, out_max, ws->set_rdn, set_len);
    if(seq_outer_len == 0U) {
        (void)noxtls_free(ws);
        return rc;
    }
    *out_len = seq_outer_len;
    rc = NOXTLS_RETURN_SUCCESS;

    (void)noxtls_free(ws);
    return rc;
}

/**
 * @brief Builds a DER Name from a common name (CN).
 *
 * This function constructs a DER Name from a common name (CN) by creating a
 * sequence of SET, SEQUENCE, and OID elements.
 *
 * @param[in] cn      The common name to encode.
 * @param[out] out    Pointer to the buffer to receive the DER-encoded output.
 * @param[in] out_max Maximum length of the output buffer.
 * @param[out] out_len Pointer to a uint32_t that will receive the length of the output (not including null terminator).
 *
 * @return NOXTLS_RETURN_SUCCESS on success, or an appropriate error code from @see noxtls_return_t.
 */
noxtls_return_t noxtls_x509_dn_from_cn(const uint8_t *cn, uint8_t *out, uint32_t out_max, uint32_t *out_len)
{
    return dn_from_cn(cn, out, out_max, out_len);
}

/**
 * @brief Writes a certificate to DER format.
 *
 * This function writes a certificate to DER format by copying the raw data from
 * the certificate structure.
 *
 * @param[in] cert      Pointer to the certificate structure to write.
 * @param[out] out      Pointer to the buffer to receive the DER-encoded output.
 * @param[in] out_max   Maximum length of the output buffer.
 * @param[out] out_len  Pointer to a uint32_t that will receive the length of the output (not including null terminator).
 *
 * @return NOXTLS_RETURN_SUCCESS on success, or an appropriate error code from @see noxtls_return_t.
 */
noxtls_return_t noxtls_x509_certificate_write_der(const x509_certificate_t *cert, uint8_t *out, uint32_t out_max, uint32_t *out_len)
{
    if((cert == NULL) || (out == NULL) || (out_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if((cert->raw_data == NULL) || (cert->raw_data_len == 0U)) {
        return NOXTLS_RETURN_FAILED;
    }
    if(cert->raw_data_len > out_max) {
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_copy_u8(out, (size_t)out_max, cert->raw_data, (size_t)cert->raw_data_len);
    *out_len = cert->raw_data_len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
* @brief Writes a certificate to PEM format.
 *
 * This function writes a certificate to PEM format by converting the DER data
 * to PEM using base64 encoding and wrapping with appropriate PEM delimiters.
 *
 * @param[in] cert      Pointer to the certificate structure to write.
 * @param[out] out      Pointer to the buffer to receive the PEM-encoded output (null-terminated).
 * @param[in] out_max   Maximum length of the output buffer.
 * @param[out] out_len  Pointer to a uint32_t that will receive the length of the output (not including null terminator).
 *
 * @return NOXTLS_RETURN_SUCCESS on success, or an appropriate error code from @see noxtls_return_t.
 */
noxtls_return_t noxtls_x509_certificate_write_pem(const x509_certificate_t *cert, uint8_t *out, uint32_t out_max, uint32_t *out_len)
{
    if((cert == NULL) || (out == NULL) || (out_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if((cert->raw_data == NULL) || (cert->raw_data_len == 0U)) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Encode straight from the parsed DER (no X509_MAX_CERT_SIZE heap copy); the bounded
     * encoder rejects an @p out_max that cannot hold the PEM text plus its NUL. */
    return noxtls_certificate_der_to_pem_ex(cert->raw_data, cert->raw_data_len, out, out_max, out_len);
}

/**
 * @brief Generates a self-signed X.509 certificate (v3) and writes it to DER format.
 *
 * This function generates a self-signed X.509 certificate (v3) by creating a
 * TBSCertificate and signing it with the issuer private key.
 *
 * @param[in] serial      The serial number of the certificate.
 * @param[in] serial_len  Length of the serial number.
 * @param[in] issuer_der  Pointer to the DER-encoded issuer name.
 * @param[in] issuer_len  Length of the issuer name.
 * @param[in] subject_der Pointer to the DER-encoded subject name.
 * @param[in] subject_len  Length of the subject name.
 * @param[in] not_before_utc The UTC time string for the not before date.
 * @param[in] not_after_utc The UTC time string for the not after date.
 * @param[in] subject_pk_oid Pointer to the OID of the subject public key algorithm.
 * @param[in] subject_pk_oid_len Length of the subject public key algorithm OID.
 * @param[in] subject_pk Pointer to the raw subject public key.
 * @param[in] subject_pk_len Length of the subject public key.
 * @param[in] sig_oid Pointer to the OID of the signature algorithm.
 * @param[in] sig_oid_len Length of the signature algorithm OID.
 * @param[in] sign_key Pointer to the issuer private key.
 * @param[in] sign_key_len Length of the issuer private key.
 * @param[in] hash_algo The hash algorithm to use for signing.
 * @param[out] out_der Pointer to the buffer to receive the DER-encoded output.
 * @param[in] out_max Maximum length of the output buffer.
 * @param[out] out_len Pointer to a uint32_t that will receive the length of the output (not including null terminator).
 *
 * @return NOXTLS_RETURN_SUCCESS on success, or an appropriate error code from @see noxtls_return_t.
 */
noxtls_return_t noxtls_x509_certificate_generate_self_signed_ex(
    const uint8_t *serial, uint32_t serial_len,
    const uint8_t *issuer_der, uint32_t issuer_len,
    const uint8_t *subject_der, uint32_t subject_len,
    const uint8_t *not_before_utc, const uint8_t *not_after_utc,
    const uint8_t *subject_pk_oid, uint32_t subject_pk_oid_len,
    const uint8_t *subject_pk_params, uint32_t subject_pk_params_len,
    const uint8_t *subject_pk, uint32_t subject_pk_len,
    const uint8_t *sig_oid, uint32_t sig_oid_len,
    const uint8_t *sign_key, uint32_t sign_key_len,
    noxtls_hash_algos_t hash_algo,
    uint8_t *out_der, uint32_t out_max, uint32_t *out_len)
{
    x509_cert_gen_ws_t *ws = NULL;
    uint32_t tbs_len = 0U;
    uint8_t version_buf[8];
    uint32_t version_len = 0U;
    uint8_t serial_enc[64];
    uint32_t serial_enc_len = 0U;
    uint8_t sig_alg_seq[64];
    uint32_t sig_alg_seq_len = 0U;
    uint8_t validity_seq[64];
    uint32_t validity_len = 0U;
    uint32_t spki_len = 0U;
    uint32_t tbs_full_len = 0U;
    uint32_t sig_len = 0U;
    uint32_t cert_seq_len = 0U;
    uint32_t off = 0U;
    noxtls_return_t ret = NOXTLS_RETURN_FAILED;

    if((serial == NULL) || (serial_len == 0U) || (issuer_der == NULL) || (issuer_len == 0U) ||
        (subject_der == NULL) || (subject_len == 0U) || (not_before_utc == NULL) || (not_after_utc == NULL) ||
        (subject_pk_oid == NULL) || (subject_pk_oid_len == 0U) || (subject_pk == NULL) || (subject_pk_len == 0U) ||
        (sig_oid == NULL) || (sig_oid_len == 0U) || (sign_key == NULL) || (sign_key_len == 0U) ||
        (out_der == NULL) || (out_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    ws = (x509_cert_gen_ws_t *)NOXTLS_MALLOC(sizeof(x509_cert_gen_ws_t));
    if(ws == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    /* [0] EXPLICIT version 2 (v3) */
    {
        uint8_t ver_int[] = { 0x02U, 0x01U, 0x02U }; /* INTEGER 2 */
        version_len = noxtls_asn1_put_explicit(version_buf, sizeof(version_buf), 0, ver_int, sizeof(ver_int));
        if(version_len == 0U) {
            (void)noxtls_free(ws);
            return ret;
        }
    }

    serial_enc_len = noxtls_asn1_put_integer(serial_enc, sizeof(serial_enc), serial, serial_len);
    if(serial_enc_len == 0U) {
        (void)noxtls_free(ws);
        return ret;
    }

    /* signatureAlgorithm: AlgorithmIdentifier { algorithm, [parameters] }.
     * Signature OIDs (ecdsa-with-SHA*, id-Ed*, id-ml-dsa-*, id-slh-dsa-*) have
     * no parameters; PKCS#1 sig OIDs get explicit NULL automatically. */
    sig_alg_seq_len = put_algorithm_identifier(sig_alg_seq, sizeof(sig_alg_seq), sig_oid, sig_oid_len, NULL, 0);
    if(sig_alg_seq_len == 0U) {
        (void)noxtls_free(ws);
        return ret;
    }

    /* validity SEQUENCE { notBefore UTCTime, notAfter UTCTime } */
    {
        uint8_t vb[32];
        uint8_t va[32];
        uint8_t validity_content[64];
        uint32_t vbl = noxtls_asn1_put_utc_time(vb, sizeof(vb), not_before_utc);
        uint32_t val = noxtls_asn1_put_utc_time(va, sizeof(va), not_after_utc);
        if((vbl == 0U) || (val == 0U) || ((vbl + val) > (uint32_t)sizeof(validity_content))) {
            (void)noxtls_free(ws);
            return ret;
        }
        noxtls_copy_u8(validity_content, sizeof(validity_content), vb, (size_t)(vbl));
        noxtls_copy_u8(&validity_content[vbl], sizeof(validity_content) - (size_t)(vbl), va, (size_t)(val));
        validity_len = noxtls_asn1_put_sequence(validity_seq, sizeof(validity_seq), validity_content, vbl + val);
    }
    if(validity_len == 0U) {
        (void)noxtls_free(ws);
        return ret;
    }

    /* subjectPublicKeyInfo SEQUENCE { AlgorithmIdentifier, subjectPublicKey BIT STRING } */
    {
        /* alg_seq holds OID DER + optional params (largest is EC namedCurve ≤ 12 bytes). */
        uint8_t alg_seq[96];
        uint32_t alg_seq_len = put_algorithm_identifier(alg_seq, sizeof(alg_seq),
                                                       subject_pk_oid, subject_pk_oid_len,
                                                       subject_pk_params, subject_pk_params_len);
        uint32_t bs_len = 0U;
        if(alg_seq_len == 0U) {
            (void)noxtls_free(ws);
            return ret;
        }
        bs_len = noxtls_asn1_put_bit_string(ws->bitstr, sizeof(ws->bitstr), subject_pk, subject_pk_len);
        if((bs_len == 0U) || ((alg_seq_len + bs_len) > (uint32_t)sizeof(ws->spki_content))) {
            (void)noxtls_free(ws);
            return ret;
        }
        noxtls_copy_u8(ws->spki_content, sizeof(ws->spki_content), alg_seq, (size_t)(alg_seq_len));
        noxtls_copy_u8(&ws->spki_content[alg_seq_len], sizeof(ws->spki_content) - (size_t)(alg_seq_len), ws->bitstr, (size_t)(bs_len));
        spki_len = noxtls_asn1_put_sequence(ws->spki_buf, sizeof(ws->spki_buf), ws->spki_content, alg_seq_len + bs_len);
    }
    if(spki_len == 0U) {
        (void)noxtls_free(ws);
        return ret;
    }

    /* TBS content: version + serial + sigAlg + issuer + validity + subject + spki */
    off = 0U;
    if(version_len > (uint32_t)(sizeof(ws->tbs_buf) - off)) {
        (void)noxtls_free(ws);
        return ret;
    }
    noxtls_copy_u8(&ws->tbs_buf[off], sizeof(ws->tbs_buf) - (size_t)(off), version_buf, (size_t)(version_len));
    off += version_len;

    if(serial_enc_len > (uint32_t)(sizeof(ws->tbs_buf) - off)) {
        (void)noxtls_free(ws);
        return ret;
    }
    noxtls_copy_u8(&ws->tbs_buf[off], sizeof(ws->tbs_buf) - (size_t)(off), serial_enc, (size_t)(serial_enc_len));
    off += serial_enc_len;

    if(sig_alg_seq_len > (uint32_t)(sizeof(ws->tbs_buf) - off)) {
        (void)noxtls_free(ws);
        return ret;
    }
    noxtls_copy_u8(&ws->tbs_buf[off], sizeof(ws->tbs_buf) - (size_t)(off), sig_alg_seq, (size_t)(sig_alg_seq_len));
    off += sig_alg_seq_len;

    if(issuer_len > (uint32_t)(sizeof(ws->tbs_buf) - off)) {
        (void)noxtls_free(ws);
        return ret;
    }
    noxtls_copy_u8(&ws->tbs_buf[off], sizeof(ws->tbs_buf) - (size_t)(off), issuer_der, (size_t)(issuer_len));
    off += issuer_len;

    if(validity_len > (uint32_t)(sizeof(ws->tbs_buf) - off)) {
        (void)noxtls_free(ws);
        return ret;
    }
    noxtls_copy_u8(&ws->tbs_buf[off], sizeof(ws->tbs_buf) - (size_t)(off), validity_seq, (size_t)(validity_len));
    off += validity_len;

    if(subject_len > (uint32_t)(sizeof(ws->tbs_buf) - off)) {
        (void)noxtls_free(ws);
        return ret;
    }
    noxtls_copy_u8(&ws->tbs_buf[off], sizeof(ws->tbs_buf) - (size_t)(off), subject_der, (size_t)(subject_len));
    off += subject_len;

    if(spki_len > (uint32_t)(sizeof(ws->tbs_buf) - off)) {
        (void)noxtls_free(ws);
        return ret;
    }
    noxtls_copy_u8(&ws->tbs_buf[off], sizeof(ws->tbs_buf) - (size_t)(off), ws->spki_buf, (size_t)(spki_len));
    off += spki_len;
    tbs_len = off;

    /* Full TBSCertificate (tag 0x30 + length + content) - this is what we sign */
    tbs_full_len = noxtls_asn1_put_sequence(ws->tbs_full, sizeof(ws->tbs_full), ws->tbs_buf, tbs_len);
    if(tbs_full_len == 0U) {
        (void)noxtls_free(ws);
        return ret;
    }

    /* Sign the TBSCertificate (full DER, including tag and length) */
    {
        noxtls_return_t rc = noxtls_x509_private_key_sign_data(sign_key, sign_key_len,
            ws->tbs_full, tbs_full_len, hash_algo, ws->sig_der, sizeof(ws->sig_der), &sig_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            ret = rc;
            (void)noxtls_free(ws);
            return ret;
        }
    }

    /* Certificate = SEQUENCE { TBSCertificate, signatureAlgorithm, signature BIT STRING } */
    {
        uint32_t sig_bs_len = (uint32_t)(noxtls_asn1_put_bit_string(ws->sig_bitstr, sizeof(ws->sig_bitstr), ws->sig_der, sig_len));
        if(sig_bs_len == 0U) {
            (void)noxtls_free(ws);
            return ret;
        }
        if((tbs_full_len + (sig_alg_seq_len + sig_bs_len)) > sizeof(ws->cert_seq_buf)) {
            (void)noxtls_free(ws);
            return ret;
        }
        off = 0U;
        noxtls_copy_u8(&ws->cert_seq_buf[off], sizeof(ws->cert_seq_buf) - (size_t)(off), ws->tbs_full, (size_t)(tbs_full_len));
        off += tbs_full_len;
        noxtls_copy_u8(&ws->cert_seq_buf[off], sizeof(ws->cert_seq_buf) - (size_t)(off), sig_alg_seq, (size_t)(sig_alg_seq_len));
        off += sig_alg_seq_len;
        noxtls_copy_u8(&ws->cert_seq_buf[off], sizeof(ws->cert_seq_buf) - (size_t)(off), ws->sig_bitstr, (size_t)(sig_bs_len));
        off += sig_bs_len;
        cert_seq_len = noxtls_asn1_put_sequence(out_der, out_max, ws->cert_seq_buf, off);
    }
    if(cert_seq_len == 0U) {
        (void)noxtls_free(ws);
        return ret;
    }
    *out_len = cert_seq_len;
    ret = NOXTLS_RETURN_SUCCESS;

    (void)noxtls_free(ws);
    return ret;
}

/* Backward-compatible thin wrapper: callers that pre-date subject_pk_params
 * (RSA, EdDSA, ML-DSA, SLH-DSA — all algorithms whose AlgorithmIdentifier
 * has either NULL or absent parameters). For ECC the *_ex variant must be
 * used with the namedCurve OID DER as @p subject_pk_params. */

/**
 * @brief Generate a self-signed certificate
 * 
 * @param[in] serial The serial number.
 * @param[in] serial_len The length of the serial number.
 * @param[in] issuer_der The issuer DER.
 * @param[in] issuer_len The length of the issuer DER.
 * @param[in] subject_der The subject DER.
 * @param[in] subject_len The length of the subject DER.
 * @param[in] not_before_utc The not before UTC.
 * @param[in] not_after_utc The not after UTC.
 * @param[in] subject_pk_oid The subject public key OID.
 * @param[in] subject_pk_oid_len The length of the subject public key OID.
 * @param[in] subject_pk The subject public key.
 * @param[in] subject_pk_len The length of the subject public key.
 * @param[in] sig_oid The signature OID.
 * @param[in] sig_oid_len The length of the signature OID.
 * @param[in] sign_key The sign key.
 * @param[in] sign_key_len The length of the sign key.
 * @param[in] hash_algo The hash algorithm.
 * @param[out] out_der The output DER.
 * @param[in] out_max The maximum length of the output DER.
 * @param[out] out_len The length of the output DER.
 * @return The return value.
 */
noxtls_return_t noxtls_x509_certificate_generate_self_signed(
    const uint8_t *serial, uint32_t serial_len,
    const uint8_t *issuer_der, uint32_t issuer_len,
    const uint8_t *subject_der, uint32_t subject_len,
    const uint8_t *not_before_utc, const uint8_t *not_after_utc,
    const uint8_t *subject_pk_oid, uint32_t subject_pk_oid_len,
    const uint8_t *subject_pk, uint32_t subject_pk_len,
    const uint8_t *sig_oid, uint32_t sig_oid_len,
    const uint8_t *sign_key, uint32_t sign_key_len,
    noxtls_hash_algos_t hash_algo,
    uint8_t *out_der, uint32_t out_max, uint32_t *out_len)
{
    return noxtls_x509_certificate_generate_self_signed_ex(
        serial, serial_len,
        issuer_der, issuer_len,
        subject_der, subject_len,
        not_before_utc, not_after_utc,
        subject_pk_oid, subject_pk_oid_len,
        NULL, 0,
        subject_pk, subject_pk_len,
        sig_oid, sig_oid_len,
        sign_key, sign_key_len,
        hash_algo,
        out_der, out_max, out_len);
}


/* Append one EKU OID to the DER OID list used by build_extensions. */
static uint32_t x509_append_eku_oid(uint8_t *eku_oids, uint32_t eku_oids_cap, uint32_t eku_oids_len,
                                    const uint8_t *oid_arr, uint32_t oid_arr_len)
{
    uint32_t n = 0U;
    uint32_t len = eku_oids_len;

    if((len + 16U) >= eku_oids_cap) {
        return len;
    }
    n = (uint32_t)(noxtls_asn1_put_oid_raw(&eku_oids[len],
                                           (uint32_t)(eku_oids_cap - len),
                                           oid_arr, oid_arr_len));
    if(n != 0U) {
        len += n;
    }
    return len;
}


static noxtls_return_t x509_ext_build_fail(x509_ext_build_ws_t *ws)
{
    (void)noxtls_free(ws);
    return NOXTLS_RETURN_INVALID_PARAM;
}

/* Build extension list into ext_list (eoff updated). Returns an error when any requested extension cannot be encoded. */
/**
 * @brief Builds a list of extensions into a buffer.
 *
 * This function builds a list of extensions into a buffer by creating a
 * sequence of OID and value elements.
 *
 * @param[out] ext_list Pointer to the buffer to receive the extension list.
 * @param[in] ext_list_max Maximum length of the extension list buffer.
 * @param[in] san_dns Pointer to the array of DNS names.
 * @param[in] san_dns_count Number of DNS names.
 * @param[in] key_usage_bits Bit mask of key usage bits.
 * @param[in] basic_constraints_ca Boolean indicating if the certificate is a CA.
 * @param[in] basic_constraints_path_len Path length constraint.
 * @param[in] ext_key_usage_bits Bit mask of extended key usage bits.
 * @param[in] custom_exts Pointer to the array of custom extensions.
 * @param[in] custom_ext_count Number of custom extensions.
 * @param[out] eoff Pointer to the offset in the extension list buffer.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NOT_ENOUGH_MEMORY, or NOXTLS_RETURN_INVALID_PARAM when a
 *         requested extension cannot be encoded (unknown EKU bits, oversized SAN list or custom extension).
 */
static noxtls_return_t build_extensions(
    uint8_t *ext_list, uint32_t ext_list_max,
    const uint8_t * const *san_dns, uint32_t san_dns_count,
    uint16_t key_usage_bits,
    int basic_constraints_ca, int basic_constraints_path_len,
    uint32_t ext_key_usage_bits,
    const noxtls_x509_custom_ext_t *custom_exts, uint32_t custom_ext_count,
    uint32_t *eoff)
{
    /* Extension OIDs local to this function (Rule 8.9). */
    static const uint8_t x509w_oid_key_usage[] = { 0x55U, 0x1DU, 0x0FU };
    static const uint8_t x509w_oid_subject_alt_name[] = { 0x55U, 0x1DU, 0x11U };
    static const uint8_t x509w_oid_basic_constraints[] = { 0x55U, 0x1DU, 0x13U };
    static const uint8_t x509w_oid_ext_key_usage[] = { 0x55U, 0x1DU, 0x25U };
    static const uint8_t x509w_oid_kp_server_auth[] = { 0x2BU, 0x06U, 0x01U, 0x05U, 0x05U, 0x07U, 0x03U, 0x01U };
    static const uint8_t x509w_oid_kp_client_auth[] = { 0x2BU, 0x06U, 0x01U, 0x05U, 0x05U, 0x07U, 0x03U, 0x02U };
    static const uint8_t x509w_oid_kp_code_signing[] = { 0x2BU, 0x06U, 0x01U, 0x05U, 0x05U, 0x07U, 0x03U, 0x03U };
    static const uint8_t x509w_oid_kp_email_protection[] = { 0x2BU, 0x06U, 0x01U, 0x05U, 0x05U, 0x07U, 0x03U, 0x04U };
    static const uint8_t x509w_oid_kp_time_stamping[] = { 0x2BU, 0x06U, 0x01U, 0x05U, 0x05U, 0x07U, 0x03U, 0x08U };
    static const uint8_t x509w_oid_kp_ocsp_signing[] = { 0x2BU, 0x06U, 0x01U, 0x05U, 0x05U, 0x07U, 0x03U, 0x09U };
    static const uint8_t x509w_oid_any_eku[] = { 0x55U, 0x1DU, 0x25U, 0x00U };

    uint32_t eoff_local = 0U;
    x509_ext_build_ws_t *ws = NULL;
    ws = (x509_ext_build_ws_t *)NOXTLS_MALLOC(sizeof(x509_ext_build_ws_t));

    if(ws == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    if(key_usage_bits != 0U) {
        /* extnValue must contain DER-encoded BIT STRING (including tag/length), wrapped in OCTET STRING. */
        uint8_t ku_bitstr[8];
        uint8_t ku_oct[16];
        uint32_t ku_oct_len = 0U;
        uint8_t ext_seq[64];
        uint32_t ext_seq_len = 0U;
        uint8_t oid_enc[16];
        uint32_t oid_enc_len = 0U;
        uint32_t i = 0U;
        uint8_t first_byte = 0U;
        for(i = 0U; i < 8U; i += 1U) {
            uint32_t mask = 1U;
            uint32_t sh = 0U;
            uint32_t fb = 0U;
            mask <<= i;
            if((key_usage_bits & mask) != 0U) {
                sh = 7U - i;
                fb = 1U;
                fb <<= sh;
                first_byte |= (uint8_t)fb;
            }
        }
        ku_bitstr[0] = 0x03U; /* BIT STRING */
        ku_bitstr[1] = 0x03U; /* length: unused-bits + 2 data bytes */
        ku_bitstr[2] = 0x07U; /* 7 unused bits in final byte (bit 8 only) */
        ku_bitstr[3] = first_byte;
        {
            uint8_t ku_hi = 0U;
            if((key_usage_bits & 0x100U) != 0U) { ku_hi = 0x80U; }
            ku_bitstr[4] = ku_hi;
        }
        ku_oct_len = noxtls_asn1_put_octet_string(ku_oct, sizeof(ku_oct), ku_bitstr, 5U);
        if(ku_oct_len == 0U) { return x509_ext_build_fail(ws); }
        oid_enc_len = noxtls_asn1_put_oid_raw(oid_enc, sizeof(oid_enc), x509w_oid_key_usage, sizeof(x509w_oid_key_usage));
        noxtls_copy_u8(ext_seq, sizeof(ext_seq), oid_enc, (size_t)(oid_enc_len));
        noxtls_copy_u8(&ext_seq[oid_enc_len], sizeof(ext_seq) - (size_t)(oid_enc_len), ku_oct, (size_t)(ku_oct_len));
        ext_seq_len = noxtls_asn1_put_sequence(&ext_list[eoff_local], ext_list_max - eoff_local, ext_seq, oid_enc_len + ku_oct_len);
        if(ext_seq_len == 0U) { return x509_ext_build_fail(ws); }
        eoff_local += ext_seq_len;
    }

    if((san_dns_count > 0U) && (san_dns != NULL)) {
        uint32_t san_items_len = 0U;
        uint32_t san_seq_len = 0U;
        uint32_t i = 0U;
        uint8_t oid_enc[16];
        uint32_t oid_enc_len = 0U;
        uint32_t san_oct_len = 0U;
        uint32_t ext_seq_len = 0U;

        for(i = 0U; (i < san_dns_count) && (san_dns[i] != NULL); i += 1U) {
            uint8_t ia5_tmp[X509_SAN_DNS_LEN + 8U];
            uint32_t ia5_len = 0U;
            /* dNSName [2] IMPLICT IA5String: encode as IA5 then retag to context-specific 0x82. */
            ia5_len = noxtls_asn1_put_ia5_string(ia5_tmp, (uint32_t)sizeof(ia5_tmp), san_dns[i]);
            if(ia5_len < 2U) { return x509_ext_build_fail(ws); }
            ia5_tmp[0] = 0x82U;
            if((san_items_len + ia5_len) > sizeof(ws->san_items)) { return x509_ext_build_fail(ws); }
            noxtls_copy_u8(&ws->san_items[san_items_len], sizeof(ws->san_items) - (size_t)(san_items_len), ia5_tmp, (size_t)(ia5_len));
            san_items_len += ia5_len;
        }
        if(san_items_len == 0U) { return x509_ext_build_fail(ws); }
        san_seq_len = noxtls_asn1_put_sequence(ws->san_seq, sizeof(ws->san_seq), ws->san_items, san_items_len);
        if(san_seq_len == 0U) { return x509_ext_build_fail(ws); }
        san_oct_len = noxtls_asn1_put_octet_string(ws->san_oct, sizeof(ws->san_oct), ws->san_seq, san_seq_len);
        if(san_oct_len == 0U) { return x509_ext_build_fail(ws); }
        oid_enc_len = noxtls_asn1_put_oid_raw(oid_enc, sizeof(oid_enc), x509w_oid_subject_alt_name, sizeof(x509w_oid_subject_alt_name));
        noxtls_copy_u8(ws->san_ext_seq, sizeof(ws->san_ext_seq), oid_enc, (size_t)(oid_enc_len));
        noxtls_copy_u8(&ws->san_ext_seq[oid_enc_len], sizeof(ws->san_ext_seq) - (size_t)(oid_enc_len), ws->san_oct, (size_t)(san_oct_len));
        ext_seq_len = noxtls_asn1_put_sequence(&ext_list[eoff_local], ext_list_max - eoff_local, ws->san_ext_seq, oid_enc_len + san_oct_len);
        if(ext_seq_len == 0U) { return x509_ext_build_fail(ws); }
        eoff_local += ext_seq_len;
    }

    if(basic_constraints_ca >= 0) {
        uint8_t bc_content[32];
        uint32_t bc_len = 0U;
        uint8_t bc_seq[48];
        uint32_t bc_seq_len = 0U;
        uint8_t bc_oct[56];
        uint32_t bc_oct_len = 0U;
        uint8_t ext_seq[96];
        uint32_t ext_seq_len = 0U;
        uint8_t oid_enc[16];
        uint32_t oid_enc_len = 0U;
        uint8_t ca_boolean[] = { 0x01U, 0x01U, 0xFFU };
        uint8_t ca_false[] = { 0x01U, 0x01U, 0x00U };
        if(basic_constraints_ca != 0) {
            noxtls_copy_u8(bc_content, sizeof(bc_content), ca_boolean, (size_t)(3));
            bc_len = 3U;
        } else {
            noxtls_copy_u8(bc_content, sizeof(bc_content), ca_false, (size_t)(3));
            bc_len = 3U;
        }
        if(basic_constraints_path_len >= 0) {
            /* pathLenConstraint INTEGER (0..MAX): encode every byte of the value; put_integer
             * strips leading zero bytes and adds the sign octet when needed. */
            uint8_t path_enc[8];
            uint8_t path_be[4];
            uint32_t path_u = (uint32_t)basic_constraints_path_len;
            uint32_t path_enc_len = 0U;
            path_be[0] = (uint8_t)(path_u >> 24U);
            path_be[1] = (uint8_t)(path_u >> 16U);
            path_be[2] = (uint8_t)(path_u >> 8U);
            path_be[3] = (uint8_t)path_u;
            path_enc_len = (uint32_t)(noxtls_asn1_put_integer(path_enc, sizeof(path_enc), path_be, (uint32_t)sizeof(path_be)));
            if(path_enc_len == 0U) { return x509_ext_build_fail(ws); }
            if((bc_len + path_enc_len) > sizeof(bc_content)) { return x509_ext_build_fail(ws); }
            noxtls_copy_u8(&bc_content[bc_len], sizeof(bc_content) - (size_t)(bc_len), path_enc, (size_t)(path_enc_len));
            bc_len += path_enc_len;
        }
        bc_seq_len = noxtls_asn1_put_sequence(bc_seq, sizeof(bc_seq), bc_content, bc_len);
        if(bc_seq_len == 0U) { return x509_ext_build_fail(ws); }
        bc_oct_len = noxtls_asn1_put_octet_string(bc_oct, sizeof(bc_oct), bc_seq, bc_seq_len);
        if(bc_oct_len == 0U) { return x509_ext_build_fail(ws); }
        oid_enc_len = noxtls_asn1_put_oid_raw(oid_enc, sizeof(oid_enc), x509w_oid_basic_constraints, sizeof(x509w_oid_basic_constraints));
        noxtls_copy_u8(ext_seq, sizeof(ext_seq), oid_enc, (size_t)(oid_enc_len));
        noxtls_copy_u8(&ext_seq[oid_enc_len], sizeof(ext_seq) - (size_t)(oid_enc_len), bc_oct, (size_t)(bc_oct_len));
        ext_seq_len = noxtls_asn1_put_sequence(&ext_list[eoff_local], ext_list_max - eoff_local, ext_seq, oid_enc_len + bc_oct_len);
        if(ext_seq_len == 0U) { return x509_ext_build_fail(ws); }
        eoff_local += ext_seq_len;
    }

    if(ext_key_usage_bits != 0U) {
        const uint32_t eku_known = X509_EKU_SERVER_AUTH | X509_EKU_CLIENT_AUTH | X509_EKU_CODE_SIGNING |
                                   X509_EKU_EMAIL_PROTECTION | X509_EKU_TIME_STAMPING | X509_EKU_OCSP_SIGNING |
                                   X509_EKU_ANY;
        uint32_t eku_oids_len = 0U;
        uint32_t eku_seq_len = 0U;
        uint32_t eku_oct_len = 0U;
        uint32_t ext_seq_len = 0U;
        uint8_t oid_enc[20];
        uint32_t oid_enc_len = 0U;

        if((ext_key_usage_bits & ~eku_known) != 0U) { return x509_ext_build_fail(ws); }
        if((ext_key_usage_bits & X509_EKU_SERVER_AUTH) != 0U) {
            eku_oids_len = x509_append_eku_oid(ws->eku_oids, (uint32_t)sizeof(ws->eku_oids), eku_oids_len,
                                               x509w_oid_kp_server_auth, (uint32_t)sizeof(x509w_oid_kp_server_auth));
        }
        if((ext_key_usage_bits & X509_EKU_CLIENT_AUTH) != 0U) {
            eku_oids_len = x509_append_eku_oid(ws->eku_oids, (uint32_t)sizeof(ws->eku_oids), eku_oids_len,
                                               x509w_oid_kp_client_auth, (uint32_t)sizeof(x509w_oid_kp_client_auth));
        }
        if((ext_key_usage_bits & X509_EKU_CODE_SIGNING) != 0U) {
            eku_oids_len = x509_append_eku_oid(ws->eku_oids, (uint32_t)sizeof(ws->eku_oids), eku_oids_len,
                                               x509w_oid_kp_code_signing, (uint32_t)sizeof(x509w_oid_kp_code_signing));
        }
        if((ext_key_usage_bits & X509_EKU_EMAIL_PROTECTION) != 0U) {
            eku_oids_len = x509_append_eku_oid(ws->eku_oids, (uint32_t)sizeof(ws->eku_oids), eku_oids_len,
                                               x509w_oid_kp_email_protection, (uint32_t)sizeof(x509w_oid_kp_email_protection));
        }
        if((ext_key_usage_bits & X509_EKU_TIME_STAMPING) != 0U) {
            eku_oids_len = x509_append_eku_oid(ws->eku_oids, (uint32_t)sizeof(ws->eku_oids), eku_oids_len,
                                               x509w_oid_kp_time_stamping, (uint32_t)sizeof(x509w_oid_kp_time_stamping));
        }
        if((ext_key_usage_bits & X509_EKU_OCSP_SIGNING) != 0U) {
            eku_oids_len = x509_append_eku_oid(ws->eku_oids, (uint32_t)sizeof(ws->eku_oids), eku_oids_len,
                                               x509w_oid_kp_ocsp_signing, (uint32_t)sizeof(x509w_oid_kp_ocsp_signing));
        }
        if((ext_key_usage_bits & X509_EKU_ANY) != 0U) {
            eku_oids_len = x509_append_eku_oid(ws->eku_oids, (uint32_t)sizeof(ws->eku_oids), eku_oids_len,
                                               x509w_oid_any_eku, (uint32_t)sizeof(x509w_oid_any_eku));
        }
        if(eku_oids_len == 0U) { return x509_ext_build_fail(ws); }
        eku_seq_len = noxtls_asn1_put_sequence(ws->eku_seq, sizeof(ws->eku_seq), ws->eku_oids, eku_oids_len);
        if(eku_seq_len == 0U) { return x509_ext_build_fail(ws); }
        eku_oct_len = noxtls_asn1_put_octet_string(ws->eku_oct, sizeof(ws->eku_oct), ws->eku_seq, eku_seq_len);
        if(eku_oct_len == 0U) { return x509_ext_build_fail(ws); }
        oid_enc_len = noxtls_asn1_put_oid_raw(oid_enc, sizeof(oid_enc), x509w_oid_ext_key_usage, sizeof(x509w_oid_ext_key_usage));
        noxtls_copy_u8(ws->eku_ext_seq, sizeof(ws->eku_ext_seq), oid_enc, (size_t)(oid_enc_len));
        noxtls_copy_u8(&ws->eku_ext_seq[oid_enc_len], sizeof(ws->eku_ext_seq) - (size_t)(oid_enc_len), ws->eku_oct, (size_t)(eku_oct_len));
        ext_seq_len = noxtls_asn1_put_sequence(&ext_list[eoff_local], ext_list_max - eoff_local, ws->eku_ext_seq, oid_enc_len + eku_oct_len);
        if(ext_seq_len == 0U) { return x509_ext_build_fail(ws); }
        eoff_local += ext_seq_len;
    }

    if((custom_exts != NULL) && (custom_ext_count > 0U)) {
        uint32_t c = 0U;
        for(c = 0U; c < custom_ext_count; c += 1U) {
            uint32_t ext_content_len = 0U;
            uint8_t oid_enc[32];
            uint32_t oid_enc_len = 0U;
            uint32_t oct_len = 0U;
            uint32_t ext_seq_len = 0U;
            const noxtls_x509_custom_ext_t *ce = &custom_exts[c];
            if((ce->oid == NULL) || (ce->oid_len == 0U) || (ce->value == NULL)) { continue; }
            oid_enc_len = noxtls_asn1_put_oid_raw(oid_enc, sizeof(oid_enc), ce->oid, ce->oid_len);
            if(oid_enc_len == 0U) { return x509_ext_build_fail(ws); }
            if((oid_enc_len + 8U + ce->value_len) > sizeof(ws->ext_content)) { return x509_ext_build_fail(ws); }
            noxtls_copy_u8(ws->ext_content, sizeof(ws->ext_content), oid_enc, (size_t)(oid_enc_len));
            ext_content_len = oid_enc_len;
            if(ce->critical != 0) {
                ws->ext_content[ext_content_len] = 0x01U;
                ext_content_len += 1U;
                ws->ext_content[ext_content_len] = 0x01U;
                ext_content_len += 1U;
                ws->ext_content[ext_content_len] = 0xFFU;
                ext_content_len += 1U;
            }
            oct_len = noxtls_asn1_put_octet_string(ws->oct_buf, sizeof(ws->oct_buf), ce->value, ce->value_len);
            if(oct_len == 0U) { return x509_ext_build_fail(ws); }
            if((ext_content_len + oct_len) > sizeof(ws->ext_content)) { return x509_ext_build_fail(ws); }
            noxtls_copy_u8(&ws->ext_content[ext_content_len], sizeof(ws->ext_content) - (size_t)(ext_content_len), ws->oct_buf, (size_t)(oct_len));
            ext_content_len += oct_len;
            ext_seq_len = noxtls_asn1_put_sequence(&ext_list[eoff_local], ext_list_max - eoff_local, ws->ext_content, ext_content_len);
            if(ext_seq_len == 0U) { return x509_ext_build_fail(ws); }
            eoff_local += ext_seq_len;
        }
    }

    *eoff = eoff_local;
    (void)noxtls_free(ws);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Generates a self-signed X.509 certificate (v3) with extensions and writes it to DER format.
 *
 * This function generates a self-signed X.509 certificate (v3) with extensions by creating a
 * TBSCertificate and signing it with the issuer private key.
 *
 * @param[in] serial      The serial number of the certificate.
 * @param[in] serial_len  Length of the serial number.
 * @param[in] issuer_der  Pointer to the DER-encoded issuer name.
 * @param[in] issuer_len  Length of the issuer name.
 * @param[in] subject_der Pointer to the DER-encoded subject name.
 * @param[in] subject_len  Length of the subject name.
 * @param[in] not_before_utc The UTC time string for the not before date.
 * @param[in] not_after_utc The UTC time string for the not after date.
 * @param[in] subject_pk_oid Pointer to the OID of the subject public key algorithm.
 * @param[in] subject_pk_oid_len Length of the subject public key algorithm OID.
 * @param[in] subject_pk Pointer to the raw subject public key.
 * @param[in] subject_pk_len Length of the subject public key.
 * @param[in] sig_oid Pointer to the OID of the signature algorithm.
 * @param[in] sig_oid_len Length of the signature algorithm OID.
 * @param[in] sign_key Pointer to the issuer private key.
 * @param[in] sign_key_len Length of the issuer private key.
 * @param[in] hash_algo The hash algorithm to use for signing.
 * @param[in] san_dns Pointer to the array of DNS names.
 * @param[in] san_dns_count Number of DNS names.
 * @param[in] key_usage_bits Bit mask of key usage bits.
 * @param[out] out_der Pointer to the buffer to receive the DER-encoded output.
 * @param[in] out_max Maximum length of the output buffer.
 * @param[out] out_len Pointer to a uint32_t that will receive the length of the output (not including null terminator).
 *
 * @return NOXTLS_RETURN_SUCCESS on success, or an appropriate error code from @see noxtls_return_t.
 */
noxtls_return_t noxtls_x509_certificate_generate_self_signed_with_extensions(
    const uint8_t *serial, uint32_t serial_len,
    const uint8_t *issuer_der, uint32_t issuer_len,
    const uint8_t *subject_der, uint32_t subject_len,
    const uint8_t *not_before_utc, const uint8_t *not_after_utc,
    const uint8_t *subject_pk_oid, uint32_t subject_pk_oid_len,
    const uint8_t *subject_pk, uint32_t subject_pk_len,
    const uint8_t *sig_oid, uint32_t sig_oid_len,
    const uint8_t *sign_key, uint32_t sign_key_len,
    noxtls_hash_algos_t hash_algo,
    const uint8_t * const *san_dns, uint32_t san_dns_count,
    uint16_t key_usage_bits,
    uint8_t *out_der, uint32_t out_max, uint32_t *out_len)
{
    return noxtls_x509_certificate_generate_self_signed_with_extensions_ex(
        serial, serial_len,
        issuer_der, issuer_len,
        subject_der, subject_len,
        not_before_utc, not_after_utc,
        subject_pk_oid, subject_pk_oid_len,
        subject_pk, subject_pk_len,
        sig_oid, sig_oid_len,
        sign_key, sign_key_len,
        hash_algo,
        san_dns, san_dns_count,
        key_usage_bits,
        -1, X509_BC_PATH_LEN_ABSENT,
        0,
        NULL, 0,
        out_der, out_max, out_len);
}

/**
 * @brief Generates a self-signed X.509 certificate (v3) with extensions and writes it to DER format.
 *
 * This function generates a self-signed X.509 certificate (v3) with extensions by creating a
 * TBSCertificate and signing it with the issuer private key.
 *
 * @param[in] serial      The serial number of the certificate.
 * @param[in] serial_len  Length of the serial number.
 * @param[in] issuer_der  Pointer to the DER-encoded issuer name.
 * @param[in] issuer_len  Length of the issuer name.
 * @param[in] subject_der Pointer to the DER-encoded subject name.
 * @param[in] subject_len  Length of the subject name.
 * @param[in] not_before_utc The UTC time string for the not before date.
 * @param[in] not_after_utc The UTC time string for the not after date.
 * @param[in] subject_pk_oid Pointer to the OID of the subject public key algorithm.
 * @param[in] subject_pk_oid_len Length of the subject public key algorithm OID.
 * @param[in] subject_pk Pointer to the raw subject public key.
 * @param[in] subject_pk_len Length of the subject public key.
 * @param[in] sig_oid Pointer to the OID of the signature algorithm.
 * @param[in] sig_oid_len Length of the signature algorithm OID.
 * @param[in] sign_key Pointer to the issuer private key.
 * @param[in] sign_key_len Length of the issuer private key.
 * @param[in] hash_algo The hash algorithm to use for signing.
 *
 * @return NOXTLS_RETURN_SUCCESS on success, or an appropriate error code from @see noxtls_return_t.
 */
noxtls_return_t noxtls_x509_certificate_generate_self_signed_with_extensions_ex(
    const uint8_t *serial, uint32_t serial_len,
    const uint8_t *issuer_der, uint32_t issuer_len,
    const uint8_t *subject_der, uint32_t subject_len,
    const uint8_t *not_before_utc, const uint8_t *not_after_utc,
    const uint8_t *subject_pk_oid, uint32_t subject_pk_oid_len,
    const uint8_t *subject_pk, uint32_t subject_pk_len,
    const uint8_t *sig_oid, uint32_t sig_oid_len,
    const uint8_t *sign_key, uint32_t sign_key_len,
    noxtls_hash_algos_t hash_algo,
    const uint8_t * const *san_dns, uint32_t san_dns_count,
    uint16_t key_usage_bits,
    int basic_constraints_ca, int basic_constraints_path_len,
    uint32_t ext_key_usage_bits,
    const noxtls_x509_custom_ext_t *custom_exts, uint32_t custom_ext_count,
    uint8_t *out_der, uint32_t out_max, uint32_t *out_len)
{
    x509_ext_wrap_ws_t *ext_ws = NULL;
    x509_cert_gen_ws_t *ws = NULL;
    uint32_t ext_len = 0U;
    uint32_t off = 0U;
    noxtls_return_t ret = NOXTLS_RETURN_FAILED;

    if((serial == NULL) || (serial_len == 0U) || (issuer_der == NULL) || (issuer_len == 0U) ||
        (subject_der == NULL) || (subject_len == 0U) || (not_before_utc == NULL) || (not_after_utc == NULL) ||
        (subject_pk_oid == NULL) || (subject_pk_oid_len == 0U) || (subject_pk == NULL) || (subject_pk_len == 0U) ||
        (sig_oid == NULL) || (sig_oid_len == 0U) || (sign_key == NULL) || (sign_key_len == 0U) ||
        (out_der == NULL) || (out_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(((san_dns_count > 0U) && (san_dns == NULL)) || (san_dns_count > X509_SAN_DNS_MAX)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if((custom_ext_count > 0U) && (custom_exts == NULL)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    ext_ws = (x509_ext_wrap_ws_t *)NOXTLS_MALLOC(sizeof(*ext_ws));
    ws = (x509_cert_gen_ws_t *)NOXTLS_MALLOC(sizeof(x509_cert_gen_ws_t));
    if((ext_ws == NULL) || (ws == NULL)) {
        ret = NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        (void)noxtls_free(ws);
        (void)noxtls_free(ext_ws);
        return ret;
    }

    {
        uint32_t eoff = 0U;
        noxtls_return_t ext_rc;
        /* A requested extension that cannot be encoded must fail the call: issuing the
         * certificate without it would silently drop constraints the caller asked for. */
        ext_rc = build_extensions(ext_ws->ext_list, sizeof(ext_ws->ext_list), san_dns, san_dns_count, key_usage_bits,
                                  basic_constraints_ca, basic_constraints_path_len, ext_key_usage_bits,
                                  custom_exts, custom_ext_count, &eoff);
        if(ext_rc != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_free(ws);
            (void)noxtls_free(ext_ws);
            return ext_rc;
        }
        {
            if(eoff > 0U) {
                uint32_t ext_seq_len = (uint32_t)(noxtls_asn1_put_sequence(ext_ws->ext_seq, sizeof(ext_ws->ext_seq), ext_ws->ext_list, eoff));
                if(ext_seq_len == 0U) { 
                    (void)noxtls_free(ws);
                    (void)noxtls_free(ext_ws);
                    return ret;
                }
                ext_len = noxtls_asn1_put_explicit(ext_ws->ext_buf, sizeof(ext_ws->ext_buf), 3, ext_ws->ext_seq, ext_seq_len);
                if(ext_len == 0U) { 
                    (void)noxtls_free(ws);
                    (void)noxtls_free(ext_ws);
                    return ret;
                }
            }
        }
    }

    {
        uint32_t tbs_len = 0U;
        uint8_t version_buf[8];
        uint32_t version_len = 0U;
        uint8_t serial_enc[64];
        uint32_t serial_enc_len = 0U;
        uint8_t sig_alg_seq[64];
        uint32_t sig_alg_seq_len = 0U;
        uint8_t validity_seq[64];
        uint32_t validity_len = 0U;
        uint32_t spki_len = 0U;
        uint32_t tbs_full_len = 0U;
        uint32_t sig_len = 0U;
        uint32_t cert_seq_len = 0U;

        { uint8_t ver_int[] = { 0x02U, 0x01U, 0x02U };
          version_len = noxtls_asn1_put_explicit(version_buf, sizeof(version_buf), 0, ver_int, sizeof(ver_int)); }
        if(version_len == 0U) { 
            (void)noxtls_free(ws);
            (void)noxtls_free(ext_ws);
            return ret;
        }
        serial_enc_len = noxtls_asn1_put_integer(serial_enc, sizeof(serial_enc), serial, serial_len);
        if(serial_enc_len == 0U) { 
            (void)noxtls_free(ws);
            (void)noxtls_free(ext_ws);
            return ret;
        }
        sig_alg_seq_len = put_algorithm_identifier(sig_alg_seq, sizeof(sig_alg_seq), sig_oid, sig_oid_len, NULL, 0);
        if(sig_alg_seq_len == 0U) { 
            (void)noxtls_free(ws);
            (void)noxtls_free(ext_ws);
            return ret;
        }
        { uint8_t vb[32];
          uint8_t va[32];
          uint8_t validity_content[64];
          uint32_t vbl = noxtls_asn1_put_utc_time(vb, sizeof(vb), not_before_utc);
          uint32_t val = noxtls_asn1_put_utc_time(va, sizeof(va), not_after_utc);
          if((vbl == 0U) || (val == 0U) || ((vbl + val) > (uint32_t)sizeof(validity_content))) { 
              (void)noxtls_free(ws);
              (void)noxtls_free(ext_ws);
              return ret;
          }
          noxtls_copy_u8(validity_content, sizeof(validity_content), vb, (size_t)(vbl));
          noxtls_copy_u8(&validity_content[vbl], sizeof(validity_content) - (size_t)(vbl), va, (size_t)(val));
          validity_len = noxtls_asn1_put_sequence(validity_seq, sizeof(validity_seq), validity_content, vbl + val); }
        if(validity_len == 0U) { 
            (void)noxtls_free(ws);
            (void)noxtls_free(ext_ws);
            return ret;
        }
        { uint8_t alg_seq[96];
          uint32_t alg_seq_len = put_algorithm_identifier(alg_seq, sizeof(alg_seq),
                                                          subject_pk_oid, subject_pk_oid_len,
                                                          NULL, 0);
          uint32_t bs_len = (uint32_t)(noxtls_asn1_put_bit_string(ws->bitstr, sizeof(ws->bitstr), subject_pk, subject_pk_len));
          if((alg_seq_len == 0U) || (bs_len == 0U) || ((alg_seq_len + bs_len) > (uint32_t)sizeof(ws->spki_content))) { 
              (void)noxtls_free(ws);
              (void)noxtls_free(ext_ws);
              return ret;
          }
          noxtls_copy_u8(ws->spki_content, sizeof(ws->spki_content), alg_seq, (size_t)(alg_seq_len));
          noxtls_copy_u8(&ws->spki_content[alg_seq_len], sizeof(ws->spki_content) - (size_t)(alg_seq_len), ws->bitstr, (size_t)(bs_len));
          spki_len = noxtls_asn1_put_sequence(ws->spki_buf, sizeof(ws->spki_buf), ws->spki_content, alg_seq_len + bs_len); }
        if(spki_len == 0U) { 
            (void)noxtls_free(ws);
            (void)noxtls_free(ext_ws);
            return ret;
        }

        off = 0U;
        if(version_len > (uint32_t)(sizeof(ws->tbs_buf) - off)) { 
            (void)noxtls_free(ws);
            (void)noxtls_free(ext_ws);
            return ret;
        }
        noxtls_copy_u8(&ws->tbs_buf[off], sizeof(ws->tbs_buf) - (size_t)(off), version_buf, (size_t)(version_len)); off += version_len;
        if(serial_enc_len > (uint32_t)(sizeof(ws->tbs_buf) - off)) { 
            (void)noxtls_free(ws);
            (void)noxtls_free(ext_ws);
            return ret;
        }
        noxtls_copy_u8(&ws->tbs_buf[off], sizeof(ws->tbs_buf) - (size_t)(off), serial_enc, (size_t)(serial_enc_len)); off += serial_enc_len;
        if(sig_alg_seq_len > (uint32_t)(sizeof(ws->tbs_buf) - off)) { 
            (void)noxtls_free(ws);
            (void)noxtls_free(ext_ws);
            return ret;
        }
        noxtls_copy_u8(&ws->tbs_buf[off], sizeof(ws->tbs_buf) - (size_t)(off), sig_alg_seq, (size_t)(sig_alg_seq_len)); off += sig_alg_seq_len;
        if(issuer_len > (uint32_t)(sizeof(ws->tbs_buf) - off)) { 
            (void)noxtls_free(ws);
            (void)noxtls_free(ext_ws);
            return ret;
        }
        noxtls_copy_u8(&ws->tbs_buf[off], sizeof(ws->tbs_buf) - (size_t)(off), issuer_der, (size_t)(issuer_len)); off += issuer_len;
        if(validity_len > (uint32_t)(sizeof(ws->tbs_buf) - off)) { 
            (void)noxtls_free(ws);
            (void)noxtls_free(ext_ws);
            return ret;
        }
        noxtls_copy_u8(&ws->tbs_buf[off], sizeof(ws->tbs_buf) - (size_t)(off), validity_seq, (size_t)(validity_len)); off += validity_len;
        if(subject_len > (uint32_t)(sizeof(ws->tbs_buf) - off)) { 
            (void)noxtls_free(ws);
            (void)noxtls_free(ext_ws);
            return ret;
        }
        noxtls_copy_u8(&ws->tbs_buf[off], sizeof(ws->tbs_buf) - (size_t)(off), subject_der, (size_t)(subject_len)); off += subject_len;
        if(spki_len > (uint32_t)(sizeof(ws->tbs_buf) - off)) { 
            (void)noxtls_free(ws);
            (void)noxtls_free(ext_ws);
            return ret;
        }
        noxtls_copy_u8(&ws->tbs_buf[off], sizeof(ws->tbs_buf) - (size_t)(off), ws->spki_buf, (size_t)(spki_len)); off += spki_len;
        if(ext_len > 0U) {
            if(ext_len > (uint32_t)(sizeof(ws->tbs_buf) - off)) { 
                (void)noxtls_free(ws);
                (void)noxtls_free(ext_ws);
                return ret;
            }
            noxtls_copy_u8(&ws->tbs_buf[off], sizeof(ws->tbs_buf) - (size_t)(off), ext_ws->ext_buf, (size_t)(ext_len));
            off += ext_len;
        }
        tbs_len = off;

        tbs_full_len = noxtls_asn1_put_sequence(ws->tbs_full, sizeof(ws->tbs_full), ws->tbs_buf, tbs_len);
        if(tbs_full_len == 0U) { 
            (void)noxtls_free(ws);
            (void)noxtls_free(ext_ws);
            return ret;
        }
        if(noxtls_x509_private_key_sign_data(sign_key, sign_key_len, ws->tbs_full, tbs_full_len, hash_algo, ws->sig_der, sizeof(ws->sig_der), &sig_len) != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_free(ws);
            (void)noxtls_free(ext_ws);
            return ret;
        }
        {
          uint32_t sig_bs_len = (uint32_t)(noxtls_asn1_put_bit_string(ws->sig_bitstr, sizeof(ws->sig_bitstr), ws->sig_der, sig_len));
          if((sig_bs_len == 0U) ||
             ((tbs_full_len + (sig_alg_seq_len + sig_bs_len)) > (uint32_t)sizeof(ws->cert_seq_buf))) {
              (void)noxtls_free(ws);
              (void)noxtls_free(ext_ws);
              return ret;
          }
          off = 0U;
          noxtls_copy_u8(&ws->cert_seq_buf[off], sizeof(ws->cert_seq_buf) - (size_t)(off), ws->tbs_full, (size_t)(tbs_full_len)); off += tbs_full_len;
          noxtls_copy_u8(&ws->cert_seq_buf[off], sizeof(ws->cert_seq_buf) - (size_t)(off), sig_alg_seq, (size_t)(sig_alg_seq_len)); off += sig_alg_seq_len;
          noxtls_copy_u8(&ws->cert_seq_buf[off], sizeof(ws->cert_seq_buf) - (size_t)(off), ws->sig_bitstr, (size_t)(sig_bs_len)); off += sig_bs_len;
          cert_seq_len = noxtls_asn1_put_sequence(out_der, out_max, ws->cert_seq_buf, off); }
        if(cert_seq_len == 0U) { 
            (void)noxtls_free(ws);
            (void)noxtls_free(ext_ws);
            return ret;
        }
        *out_len = cert_seq_len;
    }
    ret = NOXTLS_RETURN_SUCCESS;

    (void)noxtls_free(ws);
    (void)noxtls_free(ext_ws);
    return ret;
}

/**
 * Create a PKCS#10 Certificate Signing Request (RFC 2986) in DER form.
 * CertificationRequestInfo is version 0, subject, subjectPKInfo; attributes omitted.
 * Signed with sign_key (ECC private key; RSA not supported by noxtls_x509_private_key_sign_data).
 */
/**
 * @brief Generates a PKCS#10 Certificate Signing Request (RFC 2986) in DER format.
 *
 * This function generates a PKCS#10 Certificate Signing Request (RFC 2986) in DER format by creating a
 * CertificationRequestInfo and signing it with the issuer private key.
 *
 * @param[in] subject_der Pointer to the DER-encoded subject name.
 * @param[in] subject_len  Length of the subject name.
 * @param[in] subject_pk_oid Pointer to the OID of the subject public key algorithm.
 * @param[in] subject_pk_oid_len Length of the subject public key algorithm OID.
 * @param[in] subject_pk Pointer to the raw subject public key.
 * @param[in] subject_pk_len Length of the subject public key.
 * @param[in] sig_oid Pointer to the OID of the signature algorithm.
 * @param[in] sig_oid_len Length of the signature algorithm OID.
 * @param[in] sign_key Pointer to the issuer private key.
 * @param[in] sign_key_len Length of the issuer private key.
 * @param[in] hash_algo The hash algorithm to use for signing.
 * @param[out] out_der Pointer to the buffer to receive the DER-encoded output.
 * @param[in] out_max Maximum length of the output buffer.
 * @param[out] out_len Pointer to a uint32_t that will receive the length of the output (not including null terminator).
 *
 * @return NOXTLS_RETURN_SUCCESS on success, or an appropriate error code from @see noxtls_return_t.
 */
noxtls_return_t noxtls_x509_csr_create_der(
    const uint8_t *subject_der, uint32_t subject_len,
    const uint8_t *subject_pk_oid, uint32_t subject_pk_oid_len,
    const uint8_t *subject_pk, uint32_t subject_pk_len,
    const uint8_t *sig_oid, uint32_t sig_oid_len,
    const uint8_t *sign_key, uint32_t sign_key_len,
    noxtls_hash_algos_t hash_algo,
    uint8_t *out_der, uint32_t out_max, uint32_t *out_len)
{
    x509_csr_ws_t *ws = NULL;
    uint32_t cri_len = 0U;
    uint8_t version_int[] = { 0x02U, 0x01U, 0x00U };  /* INTEGER 0 */
    uint8_t alg_seq[80];
    uint32_t alg_seq_len = 0U;
    uint32_t bs_len = 0U;
    uint32_t spki_len = 0U;
    uint32_t cri_seq_len = 0U;
    uint32_t sig_len = 0U;
    uint8_t sig_alg_seq[80];
    uint32_t sig_alg_seq_len = 0U;
    uint32_t sig_bs_len = 0U;
    uint32_t cr_seq_len = 0U;
    uint32_t off = 0U;
    noxtls_return_t ret = NOXTLS_RETURN_FAILED;

    if((subject_der == NULL) || (subject_len == 0U) ||
        (subject_pk_oid == NULL) || (subject_pk_oid_len == 0U) ||
        (subject_pk == NULL) || (subject_pk_len == 0U) ||
        (sig_oid == NULL) || (sig_oid_len == 0U) ||
        (sign_key == NULL) || (sign_key_len == 0U) ||
        (out_der == NULL) || (out_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    ws = (x509_csr_ws_t *)NOXTLS_MALLOC(sizeof(x509_csr_ws_t));
    if(ws == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    /* CertificationRequestInfo content: version + subject + subjectPKInfo */
    off = 0U;
    if((off + sizeof(version_int)) > sizeof(ws->cri_buf)) {
        (void)noxtls_free(ws);
        return ret;
    }
    noxtls_copy_u8((uint8_t *)(&ws->cri_buf[off]), sizeof(version_int), (const uint8_t *)(version_int), sizeof(version_int));
    off += sizeof(version_int);

    if(subject_len > (uint32_t)(sizeof(ws->cri_buf) - off)) {
        (void)noxtls_free(ws);
        return ret;
    }
    noxtls_copy_u8(&ws->cri_buf[off], sizeof(ws->cri_buf) - (size_t)(off), subject_der, (size_t)(subject_len));
    off += subject_len;

    alg_seq_len = put_algorithm_identifier(alg_seq, sizeof(alg_seq), subject_pk_oid, subject_pk_oid_len, NULL, 0);
    if(alg_seq_len == 0U) {
        (void)noxtls_free(ws);
        return ret;
    }
    bs_len = noxtls_asn1_put_bit_string(ws->bitstr, sizeof(ws->bitstr), subject_pk, subject_pk_len);
    if((bs_len == 0U) || ((alg_seq_len + bs_len) > (uint32_t)sizeof(ws->spki_content))) {
        (void)noxtls_free(ws);
        return ret;
    }
    noxtls_copy_u8(ws->spki_content, sizeof(ws->spki_content), alg_seq, (size_t)(alg_seq_len));
    noxtls_copy_u8(&ws->spki_content[alg_seq_len], sizeof(ws->spki_content) - (size_t)(alg_seq_len), ws->bitstr, (size_t)(bs_len));
    spki_len = noxtls_asn1_put_sequence(&ws->cri_buf[off], (uint32_t)(sizeof(ws->cri_buf) - off), ws->spki_content, alg_seq_len + bs_len);
    if(spki_len == 0U) {
        (void)noxtls_free(ws);
        return ret;
    }
    off += spki_len;
    cri_len = off;

    /* CRI as SEQUENCE (this is the data to be signed) */
    cri_seq_len = noxtls_asn1_put_sequence(ws->cri_seq, sizeof(ws->cri_seq), ws->cri_buf, cri_len);
    if(cri_seq_len == 0U) {
        (void)noxtls_free(ws);
        return ret;
    }

    if(noxtls_x509_private_key_sign_data(sign_key, sign_key_len,
            ws->cri_seq, cri_seq_len, hash_algo, ws->sig_der, sizeof(ws->sig_der), &sig_len) != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_free(ws);
        return ret;
    }

    sig_alg_seq_len = put_algorithm_identifier(sig_alg_seq, sizeof(sig_alg_seq), sig_oid, sig_oid_len, NULL, 0);
    if(sig_alg_seq_len == 0U) {
        (void)noxtls_free(ws);
        return ret;
    }

    sig_bs_len = noxtls_asn1_put_bit_string(ws->sig_bitstr, sizeof(ws->sig_bitstr), ws->sig_der, sig_len);
    if(sig_bs_len == 0U) {
        (void)noxtls_free(ws);
        return ret;
    }

    off = 0U;
    if((off + cri_seq_len + (sig_alg_seq_len + sig_bs_len)) > sizeof(ws->cr_seq_buf)) {
        (void)noxtls_free(ws);
        return ret;
    }
    noxtls_copy_u8(&ws->cr_seq_buf[off], sizeof(ws->cr_seq_buf) - (size_t)(off), ws->cri_seq, (size_t)(cri_seq_len));
    off += cri_seq_len;
    noxtls_copy_u8(&ws->cr_seq_buf[off], sizeof(ws->cr_seq_buf) - (size_t)(off), sig_alg_seq, (size_t)(sig_alg_seq_len));
    off += sig_alg_seq_len;
    noxtls_copy_u8(&ws->cr_seq_buf[off], sizeof(ws->cr_seq_buf) - (size_t)(off), ws->sig_bitstr, (size_t)(sig_bs_len));
    off += sig_bs_len;

    cr_seq_len = noxtls_asn1_put_sequence(out_der, out_max, ws->cr_seq_buf, off);
    if(cr_seq_len == 0U) {
        (void)noxtls_free(ws);
        return ret;
    }
    *out_len = cr_seq_len;
    ret = NOXTLS_RETURN_SUCCESS;

    (void)noxtls_free(ws);
    return ret;
}

/**
 * @brief Generates a PKCS#10 Certificate Signing Request (RFC 2986) in PEM format.
 *
 * This function generates a PKCS#10 Certificate Signing Request (RFC 2986) in PEM format by creating a
 * CertificationRequestInfo and signing it with the issuer private key.
 *
 * @param[in] subject_der Pointer to the DER-encoded subject name.
 * @param[in] subject_len  Length of the subject name.
 * @param[in] subject_pk_oid Pointer to the OID of the subject public key algorithm.
 * @param[in] subject_pk_oid_len Length of the subject public key algorithm OID.
 * @param[in] subject_pk Pointer to the raw subject public key.
 * @param[in] subject_pk_len Length of the subject public key.
 * @param[in] sig_oid Pointer to the OID of the signature algorithm.
 * @param[in] sig_oid_len Length of the signature algorithm OID.
 * @param[in] sign_key Pointer to the issuer private key.
 * @param[in] sign_key_len Length of the issuer private key.
 * @param[in] hash_algo The hash algorithm to use for signing.
 * @param[out] out_pem Pointer to the buffer to receive the PEM-encoded output (null-terminated).
 * @param[in] out_max Maximum length of the output buffer.
 * @param[out] out_len Pointer to a uint32_t that will receive the length of the output (not including null terminator).
 *
 * @return NOXTLS_RETURN_SUCCESS on success, or an appropriate error code from @see noxtls_return_t.
 */
noxtls_return_t noxtls_x509_csr_create_pem(
    const uint8_t *subject_der, uint32_t subject_len,
    const uint8_t *subject_pk_oid, uint32_t subject_pk_oid_len,
    const uint8_t *subject_pk, uint32_t subject_pk_len,
    const uint8_t *sig_oid, uint32_t sig_oid_len,
    const uint8_t *sign_key, uint32_t sign_key_len,
    noxtls_hash_algos_t hash_algo,
    uint8_t *out_pem, uint32_t out_max, uint32_t *out_len)
{
    uint8_t *der_buf = NULL;
    uint32_t der_len = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((out_pem == NULL) || (out_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    der_buf = (uint8_t *)NOXTLS_MALLOC(X509_CSR_CRI_MAX + 400U);
    if(der_buf == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    if(noxtls_x509_csr_create_der(subject_der, subject_len,
            subject_pk_oid, subject_pk_oid_len, subject_pk, subject_pk_len,
            sig_oid, sig_oid_len, sign_key, sign_key_len, hash_algo,
            der_buf, X509_CSR_CRI_MAX + 400U, &der_len) != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_free(der_buf);
        return NOXTLS_RETURN_FAILED;
    }
    rc = noxtls_csr_der_to_pem_ex(der_buf, der_len, out_pem, out_max, out_len);
    (void)noxtls_free(der_buf);
    return rc;
}

#endif /* NOXTLS_HAVE_CERT_WRITE */
