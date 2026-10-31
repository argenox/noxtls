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
*          Enabled when NOXTLS_HAVE_CERT_WRITE is nonzero.
*
*****************************************************************************/

#include "noxtls_config.h"

#if NOXTLS_HAVE_CERT_WRITE

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "noxtls_common.h"
#include "common/noxtls_memory.h"
#include "noxtls_x509.h"
#include "certificates.h"
#include "asn1.h"
#include "noxtls_ct.h"

/*
 * In-place DER writer.
 *
 * Certificates and CSRs are encoded straight into the caller's output buffer: a
 * constructed element reserves X509W_HDR_MAX header bytes when it is opened, its
 * contents are appended after them, and closing it writes the minimal DER header and
 * moves the contents down over the unused reserve. The TBSCertificate is signed where
 * it lies and the signature is written right after it, so no staging copy of the
 * certificate, the TBS or any sub-structure is needed (no heap workspace).
 *
 * While encoding, the buffer must hold the final DER plus the not-yet-reclaimed
 * header reserve of the elements that are open at the same time (at most
 * X509W_HEADROOM bytes).
 */
#define X509W_HDR_MAX   5U   /* tag + 0x83 + 3 length octets (noxtls_asn1_put_length limit) */
#define X509W_HEADROOM  32U  /* documented worst-case slack for 8 nested open elements */

typedef struct {
    uint8_t *buf;
    uint32_t cap;
    uint32_t len;
    uint8_t err;
} x509w_t;

static void x509w_init(x509w_t *w, uint8_t *buf, uint32_t cap)
{
    w->buf = buf;
    w->cap = cap;
    w->len = 0U;
    w->err = (buf == NULL) ? 1U : 0U;
}

/** Remaining room after the current end (0 once an error was recorded). */
static uint32_t x509w_room(const x509w_t *w)
{
    return (w->err != 0U) ? 0U : (w->cap - w->len);
}

/** Account for @p n bytes written at the current end by an asn1_put_* helper (0 = failure). */
static void x509w_commit(x509w_t *w, uint32_t n)
{
    if((w->err != 0U) || (n == 0U) || (n > (w->cap - w->len))) {
        w->err = 1U;
        return;
    }
    w->len += n;
}

static void x509w_raw(x509w_t *w, const uint8_t *data, uint32_t n)
{
    if((w->err != 0U) || ((data == NULL) && (n != 0U)) || (n > (w->cap - w->len))) {
        w->err = 1U;
        return;
    }
    if(n > 0U) {
        noxtls_copy_u8(&w->buf[w->len], (size_t)(w->cap - w->len), data, (size_t)n);
        w->len += n;
    }
}

static void x509w_byte(x509w_t *w, uint8_t b)
{
    x509w_raw(w, &b, 1U);
}

/** Open a constructed element: reserve its header, return the mark for x509w_close(). */
static uint32_t x509w_open(x509w_t *w)
{
    uint32_t mark = w->len;
    if((w->err != 0U) || ((w->cap - w->len) < X509W_HDR_MAX)) {
        w->err = 1U;
        return mark;
    }
    w->len += X509W_HDR_MAX;
    return mark;
}

/** Close the element opened at @p mark with @p tag: write the minimal header, pull contents down. */
static void x509w_close(x509w_t *w, uint32_t mark, uint8_t tag)
{
    uint8_t hdr[X509W_HDR_MAX];
    uint32_t hl = 0U;
    uint32_t content_len = 0U;

    if(w->err != 0U) {
        return;
    }
    content_len = w->len - mark - X509W_HDR_MAX;
    hdr[0] = tag;
    hl = noxtls_asn1_put_length(&hdr[1], X509W_HDR_MAX - 1U, content_len);
    if(hl == 0U) {
        w->err = 1U;
        return;
    }
    hl += 1U;
    if(hl < X509W_HDR_MAX) {
        noxtls_move_u8(&w->buf[mark + hl], (size_t)(w->cap - (mark + hl)), &w->buf[mark + X509W_HDR_MAX],
                       (size_t)content_len);
    }
    noxtls_copy_u8(&w->buf[mark], (size_t)(w->cap - mark), hdr, (size_t)hl);
    w->len = mark + hl + content_len;
}

/** Content length of the element opened at @p mark (still open). */
static uint32_t x509w_open_len(const x509w_t *w, uint32_t mark)
{
    return w->len - mark - X509W_HDR_MAX;
}

static void x509w_oid(x509w_t *w, const uint8_t *oid, uint32_t oid_len)
{
    x509w_commit(w, noxtls_asn1_put_oid_raw(&w->buf[w->len], x509w_room(w), oid, oid_len));
}

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
 * @brief Append an AlgorithmIdentifier SEQUENCE { OID [, params] }.
 *
 * - If @p params is non-NULL it is appended verbatim (caller-supplied DER —
 *   typically an OBJECT IDENTIFIER for EC namedCurve).
 * - Otherwise, when @p oid is part of the PKCS#1 family, an explicit ASN.1
 *   NULL is appended (RFC 3279 / RFC 8017).
 * - For other algorithm families (ECDSA-with-SHA*, id-Ed25519, id-Ed448,
 *   id-ml-dsa-*, id-slh-dsa-*, ...), no parameters are emitted.
 */
static void x509w_algorithm_identifier(x509w_t *w, const uint8_t *alg_oid, uint32_t alg_oid_len,
                                       const uint8_t *params, uint32_t params_len)
{
    static const uint8_t asn1_null[] = { 0x05U, 0x00U };
    uint32_t m = x509w_open(w);

    if((alg_oid == NULL) || (alg_oid_len == 0U)) {
        w->err = 1U;
        return;
    }
    x509w_oid(w, alg_oid, alg_oid_len);
    if((params != NULL) && (params_len > 0U)) {
        x509w_raw(w, params, params_len);
    } else if(oid_is_pkcs1_family(alg_oid, alg_oid_len) != 0) {
        x509w_raw(w, asn1_null, (uint32_t)sizeof(asn1_null));
    } else {
        /* MISRA 15.7: no parameters */
    }
    x509w_close(w, m, 0x30U);
}

/**
 * @brief Append SubjectPublicKeyInfo SEQUENCE { AlgorithmIdentifier, subjectPublicKey BIT STRING }.
 */
static void x509w_spki(x509w_t *w, const uint8_t *pk_oid, uint32_t pk_oid_len,
                       const uint8_t *pk_params, uint32_t pk_params_len,
                       const uint8_t *pk, uint32_t pk_len)
{
    uint32_t m = x509w_open(w);
    x509w_algorithm_identifier(w, pk_oid, pk_oid_len, pk_params, pk_params_len);
    x509w_commit(w, noxtls_asn1_put_bit_string(&w->buf[w->len], x509w_room(w), pk, pk_len));
    x509w_close(w, m, 0x30U);
}

/**
 * @brief Builds a DER Name from a common name (CN) straight into @p out.
 *
 * @param[in] cn      The common name to encode (PrintableString).
 * @param[out] out    Output buffer.
 * @param[in] out_max Capacity of @p out (the Name length plus a few header bytes).
 * @param[out] out_len Length of the Name.
 *
 * @return NOXTLS_RETURN_SUCCESS on success, or an appropriate error code from @see noxtls_return_t.
 */
static noxtls_return_t dn_from_cn(const uint8_t *cn, uint8_t *out, uint32_t out_max, uint32_t *out_len)
{
    /* CN OID local to this function (Rule 8.9). */
    static const uint8_t x509w_oid_cn_der[] = { 0x55U, 0x04U, 0x03U };
    x509w_t w;
    uint32_t name = 0U;
    uint32_t rdn = 0U;
    uint32_t atv = 0U;

    if((cn == NULL) || (out == NULL) || (out_len == NULL) || (out_max == 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    x509w_init(&w, out, out_max);
    name = x509w_open(&w);
    rdn = x509w_open(&w);
    atv = x509w_open(&w);
    x509w_oid(&w, x509w_oid_cn_der, (uint32_t)sizeof(x509w_oid_cn_der));
    x509w_commit(&w, noxtls_asn1_put_printable_string(&w.buf[w.len], x509w_room(&w), cn));
    x509w_close(&w, atv, 0x30U);
    x509w_close(&w, rdn, 0x31U);
    x509w_close(&w, name, 0x30U);
    if(w.err != 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    *out_len = w.len;
    return NOXTLS_RETURN_SUCCESS;
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

/* ------------------------------------------------------------------------- */
/* Extensions                                                                */
/* ------------------------------------------------------------------------- */

/** Extension request of the *_with_extensions* generators. */
typedef struct {
    const uint8_t * const *san_dns;
    uint32_t san_dns_count;
    uint16_t key_usage_bits;
    int basic_constraints_ca;
    int basic_constraints_path_len;
    uint32_t ext_key_usage_bits;
    const noxtls_x509_custom_ext_t *custom_exts;
    uint32_t custom_ext_count;
} x509w_ext_req_t;

/**
 * @brief Append one Extension SEQUENCE { extnID, [critical TRUE], extnValue OCTET STRING { ... } }
 *        whose extnValue contents are written by the caller between the returned marks.
 * @internal
 */
static void x509w_ext_begin(x509w_t *w, const uint8_t *oid, uint32_t oid_len, int critical,
                            uint32_t *ext_mark, uint32_t *oct_mark)
{
    static const uint8_t crit_true[] = { 0x01U, 0x01U, 0xFFU };
    *ext_mark = x509w_open(w);
    x509w_oid(w, oid, oid_len);
    if(critical != 0) {
        x509w_raw(w, crit_true, (uint32_t)sizeof(crit_true));
    }
    *oct_mark = x509w_open(w);
}

static void x509w_ext_end(x509w_t *w, uint32_t ext_mark, uint32_t oct_mark)
{
    x509w_close(w, oct_mark, 0x04U);
    x509w_close(w, ext_mark, 0x30U);
}

/**
 * @brief Append the requested extensions (Extension SEQUENCEs, no outer wrapper).
 *
 * Encodings are byte-compatible with the previous staged implementation (KeyUsage keeps its
 * two-octet BIT STRING, a non-CA basicConstraints keeps an explicit cA FALSE).
 *
 * @return NOXTLS_RETURN_SUCCESS, or NOXTLS_RETURN_INVALID_PARAM when a requested extension
 *         cannot be encoded (unknown EKU bits, empty SAN list). Output overflow is reported
 *         through w->err.
 */
static noxtls_return_t x509w_extensions(x509w_t *w, const x509w_ext_req_t *req)
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
    uint32_t ext_mark = 0U;
    uint32_t oct_mark = 0U;

    if(req->key_usage_bits != 0U) {
        /* extnValue holds a DER BIT STRING: 03 03 07 <bits 0..7> <bit 8>. */
        uint8_t ku_bitstr[5];
        uint32_t i = 0U;
        uint8_t first_byte = 0U;
        for(i = 0U; i < 8U; i += 1U) {
            if((req->key_usage_bits & (uint32_t)(1UL << i)) != 0U) {
                first_byte = (uint8_t)(first_byte | (uint8_t)(1U << (7U - i)));
            }
        }
        ku_bitstr[0] = 0x03U; /* BIT STRING */
        ku_bitstr[1] = 0x03U; /* length: unused-bits + 2 data bytes */
        ku_bitstr[2] = 0x07U; /* 7 unused bits in final byte (bit 8 only) */
        ku_bitstr[3] = first_byte;
        ku_bitstr[4] = ((req->key_usage_bits & 0x100U) != 0U) ? 0x80U : 0x00U;
        x509w_ext_begin(w, x509w_oid_key_usage, (uint32_t)sizeof(x509w_oid_key_usage), 0, &ext_mark, &oct_mark);
        x509w_raw(w, ku_bitstr, (uint32_t)sizeof(ku_bitstr));
        x509w_ext_end(w, ext_mark, oct_mark);
    }

    if((req->san_dns_count > 0U) && (req->san_dns != NULL)) {
        uint32_t i = 0U;
        uint32_t names = 0U;
        x509w_ext_begin(w, x509w_oid_subject_alt_name, (uint32_t)sizeof(x509w_oid_subject_alt_name), 0,
                        &ext_mark, &oct_mark);
        names = x509w_open(w);
        for(i = 0U; (i < req->san_dns_count) && (req->san_dns[i] != NULL) && (w->err == 0U); i += 1U) {
            /* dNSName [2] IMPLICIT IA5String: encode as IA5 then retag to context-specific 0x82. */
            uint32_t at = w->len;
            uint32_t n = noxtls_asn1_put_ia5_string(&w->buf[w->len], x509w_room(w), req->san_dns[i]);
            if(n < 2U) {
                w->err = 1U;
            } else {
                w->buf[at] = 0x82U;
                x509w_commit(w, n);
            }
        }
        if((w->err == 0U) && (x509w_open_len(w, names) == 0U)) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        x509w_close(w, names, 0x30U);
        x509w_ext_end(w, ext_mark, oct_mark);
    }

    if(req->basic_constraints_ca >= 0) {
        static const uint8_t ca_true[] = { 0x01U, 0x01U, 0xFFU };
        static const uint8_t ca_false[] = { 0x01U, 0x01U, 0x00U };
        uint32_t bc = 0U;
        x509w_ext_begin(w, x509w_oid_basic_constraints, (uint32_t)sizeof(x509w_oid_basic_constraints), 0,
                        &ext_mark, &oct_mark);
        bc = x509w_open(w);
        x509w_raw(w, (req->basic_constraints_ca != 0) ? ca_true : ca_false, 3U);
        if(req->basic_constraints_path_len >= 0) {
            /* pathLenConstraint INTEGER (0..MAX): put_integer strips leading zero bytes and adds
             * the sign octet when needed. */
            uint8_t path_be[4];
            uint32_t path_u = (uint32_t)req->basic_constraints_path_len;
            path_be[0] = (uint8_t)(path_u >> 24U);
            path_be[1] = (uint8_t)(path_u >> 16U);
            path_be[2] = (uint8_t)(path_u >> 8U);
            path_be[3] = (uint8_t)path_u;
            x509w_commit(w, noxtls_asn1_put_integer(&w->buf[w->len], x509w_room(w), path_be, (uint32_t)sizeof(path_be)));
        }
        x509w_close(w, bc, 0x30U);
        x509w_ext_end(w, ext_mark, oct_mark);
    }

    if(req->ext_key_usage_bits != 0U) {
        static const struct {
            uint32_t bit;
            const uint8_t *oid;
            uint32_t oid_len;
        } eku_map[] = {
            { X509_EKU_SERVER_AUTH, x509w_oid_kp_server_auth, (uint32_t)sizeof(x509w_oid_kp_server_auth) },
            { X509_EKU_CLIENT_AUTH, x509w_oid_kp_client_auth, (uint32_t)sizeof(x509w_oid_kp_client_auth) },
            { X509_EKU_CODE_SIGNING, x509w_oid_kp_code_signing, (uint32_t)sizeof(x509w_oid_kp_code_signing) },
            { X509_EKU_EMAIL_PROTECTION, x509w_oid_kp_email_protection, (uint32_t)sizeof(x509w_oid_kp_email_protection) },
            { X509_EKU_TIME_STAMPING, x509w_oid_kp_time_stamping, (uint32_t)sizeof(x509w_oid_kp_time_stamping) },
            { X509_EKU_OCSP_SIGNING, x509w_oid_kp_ocsp_signing, (uint32_t)sizeof(x509w_oid_kp_ocsp_signing) },
            { X509_EKU_ANY, x509w_oid_any_eku, (uint32_t)sizeof(x509w_oid_any_eku) },
        };
        const uint32_t eku_known = X509_EKU_SERVER_AUTH | X509_EKU_CLIENT_AUTH | X509_EKU_CODE_SIGNING |
                                   X509_EKU_EMAIL_PROTECTION | X509_EKU_TIME_STAMPING | X509_EKU_OCSP_SIGNING |
                                   X509_EKU_ANY;
        uint32_t i = 0U;
        uint32_t seq = 0U;

        if((req->ext_key_usage_bits & ~eku_known) != 0U) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        x509w_ext_begin(w, x509w_oid_ext_key_usage, (uint32_t)sizeof(x509w_oid_ext_key_usage), 0,
                        &ext_mark, &oct_mark);
        seq = x509w_open(w);
        for(i = 0U; i < (uint32_t)(sizeof(eku_map) / sizeof(eku_map[0])); i += 1U) {
            if((req->ext_key_usage_bits & eku_map[i].bit) != 0U) {
                x509w_oid(w, eku_map[i].oid, eku_map[i].oid_len);
            }
        }
        x509w_close(w, seq, 0x30U);
        x509w_ext_end(w, ext_mark, oct_mark);
    }

    if((req->custom_exts != NULL) && (req->custom_ext_count > 0U)) {
        uint32_t c = 0U;
        for(c = 0U; c < req->custom_ext_count; c += 1U) {
            const noxtls_x509_custom_ext_t *ce = &req->custom_exts[c];
            if((ce->oid == NULL) || (ce->oid_len == 0U) || (ce->value == NULL)) {
                continue;
            }
            x509w_ext_begin(w, ce->oid, ce->oid_len, ce->critical, &ext_mark, &oct_mark);
            x509w_raw(w, ce->value, ce->value_len);
            x509w_ext_end(w, ext_mark, oct_mark);
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* Certificate generation                                                    */
/* ------------------------------------------------------------------------- */

/** Inputs of the shared certificate generator. */
typedef struct {
    const uint8_t *serial;
    uint32_t serial_len;
    const uint8_t *issuer_der;
    uint32_t issuer_len;
    const uint8_t *subject_der;
    uint32_t subject_len;
    const uint8_t *not_before_utc;
    const uint8_t *not_after_utc;
    const uint8_t *subject_pk_oid;
    uint32_t subject_pk_oid_len;
    const uint8_t *subject_pk_params;
    uint32_t subject_pk_params_len;
    const uint8_t *subject_pk;
    uint32_t subject_pk_len;
    const uint8_t *sig_oid;
    uint32_t sig_oid_len;
    const uint8_t *sign_key;
    uint32_t sign_key_len;
    noxtls_hash_algos_t hash_algo;
    const x509w_ext_req_t *ext;      /**< NULL: no extensions */
} x509w_cert_req_t;

/**
 * @brief Encode, sign and emit a v3 certificate directly into @p out_der.
 * @internal
 *
 * @param[out] sign_rc Result of the signing step (NOXTLS_RETURN_SUCCESS when not reached).
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_INVALID_PARAM (extension request),
 *         or NOXTLS_RETURN_FAILED (encoding / output capacity / signing).
 */
static noxtls_return_t x509w_generate_cert(const x509w_cert_req_t *r, uint8_t *out_der, uint32_t out_max,
                                           uint32_t *out_len, noxtls_return_t *sign_rc)
{
    static const uint8_t version_v3[] = { 0xA0U, 0x03U, 0x02U, 0x01U, 0x02U }; /* [0] EXPLICIT INTEGER 2 */
    x509w_t w;
    uint32_t cert = 0U;
    uint32_t tbs = 0U;
    uint32_t tbs_len = 0U;
    uint32_t bits = 0U;
    uint32_t sig_len = 0U;

    *sign_rc = NOXTLS_RETURN_SUCCESS;
    x509w_init(&w, out_der, out_max);
    cert = x509w_open(&w);
    tbs = x509w_open(&w);
    x509w_raw(&w, version_v3, (uint32_t)sizeof(version_v3));
    x509w_commit(&w, noxtls_asn1_put_integer(&w.buf[w.len], x509w_room(&w), r->serial, r->serial_len));
    /* signature AlgorithmIdentifier: signature OIDs have no parameters; PKCS#1 ones get NULL. */
    x509w_algorithm_identifier(&w, r->sig_oid, r->sig_oid_len, NULL, 0U);
    x509w_raw(&w, r->issuer_der, r->issuer_len);
    {
        uint32_t validity = x509w_open(&w);
        x509w_commit(&w, noxtls_asn1_put_utc_time(&w.buf[w.len], x509w_room(&w), r->not_before_utc));
        x509w_commit(&w, noxtls_asn1_put_utc_time(&w.buf[w.len], x509w_room(&w), r->not_after_utc));
        x509w_close(&w, validity, 0x30U);
    }
    x509w_raw(&w, r->subject_der, r->subject_len);
    x509w_spki(&w, r->subject_pk_oid, r->subject_pk_oid_len, r->subject_pk_params, r->subject_pk_params_len,
               r->subject_pk, r->subject_pk_len);
    if(r->ext != NULL) {
        uint32_t wrap = x509w_open(&w);
        uint32_t list = x509w_open(&w);
        noxtls_return_t ext_rc = x509w_extensions(&w, r->ext);
        if(ext_rc != NOXTLS_RETURN_SUCCESS) {
            return ext_rc;
        }
        if((w.err == 0U) && (x509w_open_len(&w, list) == 0U)) {
            w.len = wrap;  /* nothing requested: no [3] extensions field */
        } else {
            x509w_close(&w, list, 0x30U);
            x509w_close(&w, wrap, 0xA3U);
        }
    }
    x509w_close(&w, tbs, 0x30U);
    if(w.err != 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    tbs_len = w.len - tbs;

    /* signatureAlgorithm, then the signature computed over the TBSCertificate in place. */
    x509w_algorithm_identifier(&w, r->sig_oid, r->sig_oid_len, NULL, 0U);
    bits = x509w_open(&w);
    x509w_byte(&w, 0x00U); /* unused bits */
    if(w.err != 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    *sign_rc = noxtls_x509_private_key_sign_data(r->sign_key, r->sign_key_len, &w.buf[tbs], tbs_len, r->hash_algo,
                                                 &w.buf[w.len], x509w_room(&w), &sig_len);
    if(*sign_rc != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    x509w_commit(&w, sig_len);
    x509w_close(&w, bits, 0x03U);
    x509w_close(&w, cert, 0x30U);
    if(w.err != 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    *out_len = w.len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Generates a self-signed X.509 certificate (v3) and writes it to DER format.
 *
 * The certificate is encoded and signed directly in @p out_der (no heap workspace).
 * @p out_max must cover the certificate plus X509W_HEADROOM (32) bytes of encoding slack.
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
 * @param[in] subject_pk_params Optional DER AlgorithmIdentifier parameters (EC namedCurve), or NULL.
 * @param[in] subject_pk_params_len Length of @p subject_pk_params.
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
    x509w_cert_req_t r;
    noxtls_return_t sign_rc = NOXTLS_RETURN_SUCCESS;
    noxtls_return_t rc;

    if((serial == NULL) || (serial_len == 0U) || (issuer_der == NULL) || (issuer_len == 0U) ||
        (subject_der == NULL) || (subject_len == 0U) || (not_before_utc == NULL) || (not_after_utc == NULL) ||
        (subject_pk_oid == NULL) || (subject_pk_oid_len == 0U) || (subject_pk == NULL) || (subject_pk_len == 0U) ||
        (sig_oid == NULL) || (sig_oid_len == 0U) || (sign_key == NULL) || (sign_key_len == 0U) ||
        (out_der == NULL) || (out_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    r.serial = serial;
    r.serial_len = serial_len;
    r.issuer_der = issuer_der;
    r.issuer_len = issuer_len;
    r.subject_der = subject_der;
    r.subject_len = subject_len;
    r.not_before_utc = not_before_utc;
    r.not_after_utc = not_after_utc;
    r.subject_pk_oid = subject_pk_oid;
    r.subject_pk_oid_len = subject_pk_oid_len;
    r.subject_pk_params = subject_pk_params;
    r.subject_pk_params_len = subject_pk_params_len;
    r.subject_pk = subject_pk;
    r.subject_pk_len = subject_pk_len;
    r.sig_oid = sig_oid;
    r.sig_oid_len = sig_oid_len;
    r.sign_key = sign_key;
    r.sign_key_len = sign_key_len;
    r.hash_algo = hash_algo;
    r.ext = NULL;
    rc = x509w_generate_cert(&r, out_der, out_max, out_len, &sign_rc);
    /* As before, a signing failure reports the signer's error code. */
    return (sign_rc != NOXTLS_RETURN_SUCCESS) ? sign_rc : rc;
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

/**
 * @brief namedCurve parameters for an id-ecPublicKey subject key given without parameters.
 * @internal
 *
 * RFC 5480 requires the namedCurve. The *_with_extensions* generators have no parameters
 * argument, so the curve is taken from the signing key when its point size matches the
 * subject key (always true for a self-signed certificate), otherwise from the NIST curve of
 * that point size.
 *
 * @param[in] sign_key Signing key (DER or PEM).
 * @param[in] sign_key_len Length of @p sign_key.
 * @param[in] point_len Length of the subject public key (uncompressed point).
 * @param[out] curve_der namedCurve OBJECT IDENTIFIER TLV.
 * @param[in] curve_der_max Capacity of @p curve_der.
 * @return Length of @p curve_der, or 0 when no curve fits.
 */
static uint32_t x509w_ec_named_curve(const uint8_t *sign_key, uint32_t sign_key_len, uint32_t point_len,
                                     uint8_t *curve_der, uint32_t curve_der_max)
{
    static const uint8_t oid_p192[] = { 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x03U, 0x01U, 0x01U };
    static const uint8_t oid_p224[] = { 0x2BU, 0x81U, 0x04U, 0x00U, 0x21U };
    static const uint8_t oid_p256[] = { 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x03U, 0x01U, 0x07U };
    static const uint8_t oid_p384[] = { 0x2BU, 0x81U, 0x04U, 0x00U, 0x22U };
    static const uint8_t oid_p521[] = { 0x2BU, 0x81U, 0x04U, 0x00U, 0x23U };
    static const uint8_t oid_k256[] = { 0x2BU, 0x81U, 0x04U, 0x00U, 0x0AU };
    static const uint8_t oid_bp256[] = { 0x2BU, 0x24U, 0x03U, 0x03U, 0x02U, 0x08U, 0x01U, 0x01U, 0x07U };
    static const uint8_t oid_bp384[] = { 0x2BU, 0x24U, 0x03U, 0x03U, 0x02U, 0x08U, 0x01U, 0x01U, 0x0BU };
    static const uint8_t oid_bp512[] = { 0x2BU, 0x24U, 0x03U, 0x03U, 0x02U, 0x08U, 0x01U, 0x01U, 0x0DU };
    static const struct {
        const uint8_t *oid;
        uint32_t oid_len;
        uint32_t point_len;
        uint8_t nist_default;
    } curves[] = {
        { oid_p192, (uint32_t)sizeof(oid_p192), 49U, 1U },
        { oid_p224, (uint32_t)sizeof(oid_p224), 57U, 1U },
        { oid_p256, (uint32_t)sizeof(oid_p256), 65U, 1U },
        { oid_p384, (uint32_t)sizeof(oid_p384), 97U, 1U },
        { oid_p521, (uint32_t)sizeof(oid_p521), 133U, 1U },
        { oid_k256, (uint32_t)sizeof(oid_k256), 65U, 0U },
        { oid_bp256, (uint32_t)sizeof(oid_bp256), 65U, 0U },
        { oid_bp384, (uint32_t)sizeof(oid_bp384), 97U, 0U },
        { oid_bp512, (uint32_t)sizeof(oid_bp512), 129U, 1U },
    };
    x509_private_key_t key;
    noxtls_return_t key_rc;
    uint32_t i = 0U;
    uint32_t found = 0xFFFFFFFFU;

    (void)noxtls_x509_private_key_init(&key);
    key_rc = noxtls_x509_private_key_parse_der(&key, sign_key, sign_key_len);
    if(key_rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_x509_private_key_free(&key);
        (void)noxtls_x509_private_key_init(&key);
        key_rc = noxtls_x509_private_key_parse_pem(&key, sign_key, sign_key_len);
    }
    if((key_rc == NOXTLS_RETURN_SUCCESS) && (key.key_type == X509_PRIVATE_KEY_ECC)) {
        for(i = 0U; i < (uint32_t)(sizeof(curves) / sizeof(curves[0])); i += 1U) {
            if((curves[i].point_len == point_len) && (key.ecc_curve_oid_len == curves[i].oid_len) &&
               (noxtls_ct_equal(key.ecc_curve_oid, curves[i].oid, curves[i].oid_len) != 0)) {
                found = i;
            }
        }
    }
    (void)noxtls_x509_private_key_free(&key);
    for(i = 0U; (i < (uint32_t)(sizeof(curves) / sizeof(curves[0]))) && (found == 0xFFFFFFFFU); i += 1U) {
        if((curves[i].point_len == point_len) && (curves[i].nist_default != 0U)) {
            found = i;
        }
    }
    if(found == 0xFFFFFFFFU) {
        return 0U;
    }
    return noxtls_asn1_put_oid_raw(curve_der, curve_der_max, curves[found].oid, curves[found].oid_len);
}

/**
 * @brief Generates a self-signed X.509 certificate (v3) with extensions and writes it to DER format.
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
 * Encoded and signed directly in @p out_der (no heap workspace; @p out_max must cover the
 * certificate plus 32 bytes of encoding slack). For an id-ecPublicKey subject key the RFC 5480
 * namedCurve parameter is emitted (taken from the signing key when its curve matches the
 * subject point size, otherwise the NIST curve of that size).
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
    static const uint8_t ec_public_key_oid[] = { 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x02U, 0x01U };
    x509w_cert_req_t r;
    x509w_ext_req_t ext;
    uint8_t curve_der[16];
    uint32_t curve_der_len = 0U;
    noxtls_return_t sign_rc = NOXTLS_RETURN_SUCCESS;

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
    if((subject_pk_oid_len == (uint32_t)sizeof(ec_public_key_oid)) &&
       (noxtls_ct_equal(subject_pk_oid, ec_public_key_oid, sizeof(ec_public_key_oid)) != 0)) {
        curve_der_len = x509w_ec_named_curve(sign_key, sign_key_len, subject_pk_len, curve_der,
                                             (uint32_t)sizeof(curve_der));
        if(curve_der_len == 0U) {
            return NOXTLS_RETURN_INVALID_PARAM;  /* no RFC 5480 namedCurve for this point size */
        }
    }

    ext.san_dns = san_dns;
    ext.san_dns_count = san_dns_count;
    ext.key_usage_bits = key_usage_bits;
    ext.basic_constraints_ca = basic_constraints_ca;
    ext.basic_constraints_path_len = basic_constraints_path_len;
    ext.ext_key_usage_bits = ext_key_usage_bits;
    ext.custom_exts = custom_exts;
    ext.custom_ext_count = custom_ext_count;

    r.serial = serial;
    r.serial_len = serial_len;
    r.issuer_der = issuer_der;
    r.issuer_len = issuer_len;
    r.subject_der = subject_der;
    r.subject_len = subject_len;
    r.not_before_utc = not_before_utc;
    r.not_after_utc = not_after_utc;
    r.subject_pk_oid = subject_pk_oid;
    r.subject_pk_oid_len = subject_pk_oid_len;
    r.subject_pk_params = (curve_der_len != 0U) ? curve_der : NULL;
    r.subject_pk_params_len = curve_der_len;
    r.subject_pk = subject_pk;
    r.subject_pk_len = subject_pk_len;
    r.sig_oid = sig_oid;
    r.sig_oid_len = sig_oid_len;
    r.sign_key = sign_key;
    r.sign_key_len = sign_key_len;
    r.hash_algo = hash_algo;
    r.ext = &ext;
    return x509w_generate_cert(&r, out_der, out_max, out_len, &sign_rc);
}

/**
 * @brief Generates a PKCS#10 Certificate Signing Request (RFC 2986) in DER format.
 *
 * CertificationRequestInfo is version 0, subject, subjectPKInfo and an empty attributes
 * field. Encoded and signed directly in @p out_der (no heap workspace; @p out_max must cover
 * the request plus 32 bytes of encoding slack).
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
    static const uint8_t version_v1[] = { 0x02U, 0x01U, 0x00U };  /* INTEGER 0 */
    static const uint8_t no_attributes[] = { 0xA0U, 0x00U };     /* [0] IMPLICIT SET OF Attribute */
    static const uint8_t ec_public_key_oid[] = { 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x02U, 0x01U };
    uint8_t curve_der[40] = {0};
    uint32_t curve_der_len = 0U;
    x509w_t w;
    uint32_t cr = 0U;
    uint32_t cri = 0U;
    uint32_t cri_len = 0U;
    uint32_t bits = 0U;
    uint32_t sig_len = 0U;

    if((subject_der == NULL) || (subject_len == 0U) ||
        (subject_pk_oid == NULL) || (subject_pk_oid_len == 0U) ||
        (subject_pk == NULL) || (subject_pk_len == 0U) ||
        (sig_oid == NULL) || (sig_oid_len == 0U) ||
        (sign_key == NULL) || (sign_key_len == 0U) ||
        (out_der == NULL) || (out_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    /* The CSR API has no separate parameters argument. For EC, obtain namedCurve from the
     * signing key rather than omit it from SPKI (the request is signed with the subject key). */
    if((subject_pk_oid_len == sizeof(ec_public_key_oid)) &&
        (memcmp(subject_pk_oid, ec_public_key_oid, sizeof(ec_public_key_oid)) == 0)) {
        x509_private_key_t key;
        noxtls_return_t key_rc;
        (void)noxtls_x509_private_key_init(&key);
        key_rc = noxtls_x509_private_key_parse_der(&key, sign_key, sign_key_len);
        if(key_rc != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_x509_private_key_free(&key);
            (void)noxtls_x509_private_key_init(&key);
            key_rc = noxtls_x509_private_key_parse_pem(&key, sign_key, sign_key_len);
        }
        if((key_rc == NOXTLS_RETURN_SUCCESS) && (key.key_type == X509_PRIVATE_KEY_ECC) &&
            (key.ecc_curve_oid_len > 0U) && (key.ecc_curve_oid_len <= sizeof(key.ecc_curve_oid))) {
            curve_der_len = noxtls_asn1_put_oid_raw(curve_der, sizeof(curve_der),
                key.ecc_curve_oid, key.ecc_curve_oid_len);
        }
        (void)noxtls_x509_private_key_free(&key);
        if(curve_der_len == 0U) {
            return NOXTLS_RETURN_FAILED;
        }
    }

    x509w_init(&w, out_der, out_max);
    cr = x509w_open(&w);
    cri = x509w_open(&w);
    x509w_raw(&w, version_v1, (uint32_t)sizeof(version_v1));
    x509w_raw(&w, subject_der, subject_len);
    x509w_spki(&w, subject_pk_oid, subject_pk_oid_len, (curve_der_len != 0U) ? curve_der : NULL, curve_der_len,
               subject_pk, subject_pk_len);
    x509w_raw(&w, no_attributes, (uint32_t)sizeof(no_attributes));
    x509w_close(&w, cri, 0x30U);
    if(w.err != 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    cri_len = w.len - cri;

    x509w_algorithm_identifier(&w, sig_oid, sig_oid_len, NULL, 0U);
    bits = x509w_open(&w);
    x509w_byte(&w, 0x00U); /* unused bits */
    if(w.err != 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    if(noxtls_x509_private_key_sign_data(sign_key, sign_key_len, &w.buf[cri], cri_len, hash_algo,
                                         &w.buf[w.len], x509w_room(&w), &sig_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    x509w_commit(&w, sig_len);
    x509w_close(&w, bits, 0x03U);
    x509w_close(&w, cr, 0x30U);
    if(w.err != 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    *out_len = w.len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Generates a PKCS#10 Certificate Signing Request (RFC 2986) in PEM format.
 *
 * The DER request is built in @p out_pem, moved to the end of the buffer and encoded forward
 * in place (the base64 writer stays behind the DER it reads), so no DER staging buffer is
 * allocated. On failure the contents of @p out_pem are unspecified.
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
    uint32_t der_len = 0U;
    uint32_t der_off = 0U;

    if((out_pem == NULL) || (out_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if(noxtls_x509_csr_create_der(subject_der, subject_len,
            subject_pk_oid, subject_pk_oid_len, subject_pk, subject_pk_len,
            sig_oid, sig_oid_len, sign_key, sign_key_len, hash_algo,
            out_pem, out_max, &der_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    /* Move the DER to the end of the buffer; the bounded encoder checks the PEM fits before
     * writing and then writes strictly behind the DER bytes it still has to read. */
    der_off = out_max - der_len;
    noxtls_move_u8(&out_pem[der_off], (size_t)der_len, out_pem, (size_t)der_len);
    return noxtls_csr_der_to_pem_ex(&out_pem[der_off], der_len, out_pem, out_max, out_len);
}

#endif /* NOXTLS_HAVE_CERT_WRITE */
