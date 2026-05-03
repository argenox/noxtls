/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* File:    noxtls_x509_write.c
* Summary: X.509 certificate writing and generation (optional module).
*          Compile with NOXTLS_HAVE_CERT_WRITE defined to enable.
*/

#ifdef NOXTLS_HAVE_CERT_WRITE

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "noxtls_common.h"
#include "noxtls_x509.h"
#include "certificates.h"
#include "asn1.h"

#ifndef X509_WRITE_TBS_MAX
#define X509_WRITE_TBS_MAX  4096u
#endif

/* OID id-at-commonName = 2.5.4.3 (DER: 55 04 03) */
static const uint8_t oid_cn_der[] = { 0x55, 0x04, 0x03 };

/* Build minimal DER Name: SEQUENCE( SET( SEQUENCE( OID(2.5.4.3), PrintableString(cn) ) ) ) */
static noxtls_return_t dn_from_cn(const char *cn, uint8_t *out, uint32_t out_max, uint32_t *out_len)
{
    uint8_t oid_part[16];
    uint8_t val_part[260];
    uint8_t seq_content[260];
    uint8_t seq_attr[280];
    uint8_t set_rdn[300];
    uint32_t oid_len, val_len, seq_len, set_len, seq_outer_len;

    if (cn == NULL || out == NULL || out_len == NULL || out_max == 0) {
        return NOXTLS_RETURN_NULL;
    }

    oid_len = noxtls_asn1_put_oid_raw(oid_part, sizeof(oid_part), oid_cn_der, sizeof(oid_cn_der));
    if (oid_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }
    val_len = noxtls_asn1_put_printable_string(val_part, sizeof(val_part), cn);
    if (val_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }
    /* SEQUENCE content = OID + value (use separate buffer to avoid overlap in put_sequence) */
    if (oid_len + val_len > sizeof(seq_content)) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(seq_content, oid_part, oid_len);
    memcpy(seq_content + oid_len, val_part, val_len);
    seq_len = noxtls_asn1_put_sequence(seq_attr, sizeof(seq_attr), seq_content, oid_len + val_len);
    if (seq_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }
    set_len = noxtls_asn1_put_set(set_rdn, sizeof(set_rdn), seq_attr, seq_len);
    if (set_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }
    seq_outer_len = noxtls_asn1_put_sequence(out, out_max, set_rdn, set_len);
    if (seq_outer_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }
    *out_len = seq_outer_len;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_x509_dn_from_cn(const char *cn, uint8_t *out, uint32_t out_max, uint32_t *out_len)
{
    return dn_from_cn(cn, out, out_max, out_len);
}

/**
 * Write certificate to DER. Uses raw_data if present (e.g. after parse).
 */
noxtls_return_t noxtls_x509_certificate_write_der(const x509_certificate_t *cert, uint8_t *out, uint32_t out_max, uint32_t *out_len)
{
    if (cert == NULL || out == NULL || out_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if (cert->raw_data == NULL || cert->raw_data_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }
    if (cert->raw_data_len > out_max) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(out, cert->raw_data, cert->raw_data_len);
    *out_len = cert->raw_data_len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * Write certificate to PEM (DER then base64 with headers).
 */
noxtls_return_t noxtls_x509_certificate_write_pem(const x509_certificate_t *cert, uint8_t *out, uint32_t out_max, uint32_t *out_len)
{
    noxtls_return_t rc;
    uint8_t der_buf[X509_MAX_CERT_SIZE];
    uint32_t der_len;

    if (cert == NULL || out == NULL || out_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_x509_certificate_write_der(cert, der_buf, sizeof(der_buf), &der_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return noxtls_certificate_der_to_pem(der_buf, der_len, out, out_len);
}

/**
 * Generate a self-signed X.509 certificate (v3) and write DER.
 * issuer_der/subject_der are raw DER Name (e.g. from noxtls_x509_dn_from_cn).
 * not_before_utc / not_after_utc: "YYMMDDHHMMSSZ" (13 bytes).
 * subject_pk_oid/subject_pk: SubjectPublicKeyInfo algorithm OID and raw key (e.g. uncompressed ECC point).
 * sig_oid: signature algorithm OID (e.g. ecdsa-with-SHA256).
 * sign_key/sign_key_len: issuer private key (DER or PEM).
 */
noxtls_return_t noxtls_x509_certificate_generate_self_signed(
    const uint8_t *serial, uint32_t serial_len,
    const uint8_t *issuer_der, uint32_t issuer_len,
    const uint8_t *subject_der, uint32_t subject_len,
    const char *not_before_utc, const char *not_after_utc,
    const uint8_t *subject_pk_oid, uint32_t subject_pk_oid_len,
    const uint8_t *subject_pk, uint32_t subject_pk_len,
    const uint8_t *sig_oid, uint32_t sig_oid_len,
    const uint8_t *sign_key, uint32_t sign_key_len,
    noxtls_hash_algos_t hash_algo,
    uint8_t *out_der, uint32_t out_max, uint32_t *out_len)
{
    uint8_t tbs_buf[X509_WRITE_TBS_MAX];
    uint32_t tbs_len = 0;
    uint8_t version_buf[8];
    uint32_t version_len;
    uint8_t serial_enc[64];
    uint32_t serial_enc_len;
    uint8_t sig_alg_seq[64];
    uint32_t sig_alg_seq_len;
    uint8_t validity_seq[64];
    uint32_t validity_len;
    uint8_t spki_buf[600];
    uint32_t spki_len;
    uint8_t tbs_full[X509_WRITE_TBS_MAX + 8];
    uint32_t tbs_full_len;
    uint8_t sig_der[256];
    uint32_t sig_len;
    uint8_t cert_seq_buf[X509_MAX_CERT_SIZE];
    uint32_t cert_seq_len;
    uint32_t off;

    if (serial == NULL || serial_len == 0 || issuer_der == NULL || issuer_len == 0 ||
        subject_der == NULL || subject_len == 0 || not_before_utc == NULL || not_after_utc == NULL ||
        subject_pk_oid == NULL || subject_pk_oid_len == 0 || subject_pk == NULL || subject_pk_len == 0 ||
        sig_oid == NULL || sig_oid_len == 0 || sign_key == NULL || sign_key_len == 0 ||
        out_der == NULL || out_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    /* [0] EXPLICIT version 2 (v3) */
    {
        uint8_t ver_int[] = { 0x02, 0x01, 0x02 }; /* INTEGER 2 */
        version_len = noxtls_asn1_put_explicit(version_buf, sizeof(version_buf), 0, ver_int, sizeof(ver_int));
        if (version_len == 0) {
            return NOXTLS_RETURN_FAILED;
        }
    }

    serial_enc_len = noxtls_asn1_put_integer(serial_enc, sizeof(serial_enc), serial, serial_len);
    if (serial_enc_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    /* signatureAlgorithm SEQUENCE { algorithm OID } */
    {
        uint8_t oid_enc[48];
        uint32_t oid_enc_len = noxtls_asn1_put_oid_raw(oid_enc, sizeof(oid_enc), sig_oid, sig_oid_len);
        if (oid_enc_len == 0) {
            return NOXTLS_RETURN_FAILED;
        }
        sig_alg_seq_len = noxtls_asn1_put_sequence(sig_alg_seq, sizeof(sig_alg_seq), oid_enc, oid_enc_len);
    }
    if (sig_alg_seq_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    /* validity SEQUENCE { notBefore UTCTime, notAfter UTCTime } */
    {
        uint8_t vb[32], va[32], validity_content[64];
        uint32_t vbl = noxtls_asn1_put_utc_time(vb, sizeof(vb), not_before_utc);
        uint32_t val = noxtls_asn1_put_utc_time(va, sizeof(va), not_after_utc);
        if (vbl == 0 || val == 0) {
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(validity_content, vb, vbl);
        memcpy(validity_content + vbl, va, val);
        validity_len = noxtls_asn1_put_sequence(validity_seq, sizeof(validity_seq), validity_content, vbl + val);
    }
    if (validity_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    /* subjectPublicKeyInfo SEQUENCE { algorithm SEQUENCE { OID }, subjectPublicKey BIT STRING } */
    {
        uint8_t alg_oid[48], alg_seq[64], bitstr[520], spki_content[600];
        uint32_t alg_oid_len = noxtls_asn1_put_oid_raw(alg_oid, sizeof(alg_oid), subject_pk_oid, subject_pk_oid_len);
        if (alg_oid_len == 0) {
            return NOXTLS_RETURN_FAILED;
        }
        uint32_t alg_seq_len = noxtls_asn1_put_sequence(alg_seq, sizeof(alg_seq), alg_oid, alg_oid_len);
        if (alg_seq_len == 0) {
            return NOXTLS_RETURN_FAILED;
        }
        uint32_t bs_len = noxtls_asn1_put_bit_string(bitstr, sizeof(bitstr), subject_pk, subject_pk_len);
        if (bs_len == 0) {
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(spki_content, alg_seq, alg_seq_len);
        memcpy(spki_content + alg_seq_len, bitstr, bs_len);
        spki_len = noxtls_asn1_put_sequence(spki_buf, sizeof(spki_buf), spki_content, alg_seq_len + bs_len);
    }
    if (spki_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    /* TBS content: version + serial + sigAlg + issuer + validity + subject + spki */
    off = 0;
    if (off + version_len > sizeof(tbs_buf)) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(tbs_buf + off, version_buf, version_len);
    off += version_len;

    if (off + serial_enc_len > sizeof(tbs_buf)) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(tbs_buf + off, serial_enc, serial_enc_len);
    off += serial_enc_len;

    if (off + sig_alg_seq_len > sizeof(tbs_buf)) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(tbs_buf + off, sig_alg_seq, sig_alg_seq_len);
    off += sig_alg_seq_len;

    if (off + issuer_len > sizeof(tbs_buf)) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(tbs_buf + off, issuer_der, issuer_len);
    off += issuer_len;

    if (off + validity_len > sizeof(tbs_buf)) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(tbs_buf + off, validity_seq, validity_len);
    off += validity_len;

    if (off + subject_len > sizeof(tbs_buf)) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(tbs_buf + off, subject_der, subject_len);
    off += subject_len;

    if (off + spki_len > sizeof(tbs_buf)) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(tbs_buf + off, spki_buf, spki_len);
    off += spki_len;
    tbs_len = off;

    /* Full TBSCertificate (tag 0x30 + length + content) - this is what we sign */
    tbs_full_len = noxtls_asn1_put_sequence(tbs_full, sizeof(tbs_full), tbs_buf, tbs_len);
    if (tbs_full_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Sign the TBSCertificate (full DER, including tag and length) */
    {
        noxtls_return_t rc = noxtls_x509_private_key_sign_data(sign_key, sign_key_len,
            tbs_full, tbs_full_len, hash_algo, sig_der, sizeof(sig_der), &sig_len);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    /* Certificate = SEQUENCE { TBSCertificate, signatureAlgorithm, signature BIT STRING } */
    {
        uint8_t sig_bitstr[300];
        uint32_t sig_bs_len = noxtls_asn1_put_bit_string(sig_bitstr, sizeof(sig_bitstr), sig_der, sig_len);
        if (sig_bs_len == 0) {
            return NOXTLS_RETURN_FAILED;
        }
        if (tbs_full_len + sig_alg_seq_len + sig_bs_len > sizeof(cert_seq_buf)) {
            return NOXTLS_RETURN_FAILED;
        }
        off = 0;
        memcpy(cert_seq_buf + off, tbs_full, tbs_full_len);
        off += tbs_full_len;
        memcpy(cert_seq_buf + off, sig_alg_seq, sig_alg_seq_len);
        off += sig_alg_seq_len;
        memcpy(cert_seq_buf + off, sig_bitstr, sig_bs_len);
        off += sig_bs_len;
        cert_seq_len = noxtls_asn1_put_sequence(out_der, out_max, cert_seq_buf, off);
    }
    if (cert_seq_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }
    *out_len = cert_seq_len;
    return NOXTLS_RETURN_SUCCESS;
}

/* OIDs for extensions (same as in noxtls_x509.c) */
static const uint8_t oid_key_usage[] = { 0x55, 0x1D, 0x0F };
static const uint8_t oid_subject_alt_name[] = { 0x55, 0x1D, 0x11 };
static const uint8_t oid_basic_constraints[] = { 0x55, 0x1D, 0x13 };
static const uint8_t oid_ext_key_usage[] = { 0x55, 0x1D, 0x25 };
/* id-kp (Extended Key Usage) */
static const uint8_t oid_kp_server_auth[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };
static const uint8_t oid_kp_client_auth[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02 };
static const uint8_t oid_kp_code_signing[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03 };
static const uint8_t oid_kp_email_protection[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04 };
static const uint8_t oid_kp_time_stamping[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08 };
static const uint8_t oid_kp_ocsp_signing[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09 };
static const uint8_t oid_any_eku[] = { 0x55, 0x1D, 0x25, 0x00 };

#define X509_EXTENSIONS_MAX  1024u

/* Build extension list into ext_list (eoff updated). Returns 0 on error. */
static uint32_t build_extensions(
    uint8_t *ext_list, uint32_t ext_list_max,
    const char *const *san_dns, uint32_t san_dns_count,
    uint16_t key_usage_bits,
    int basic_constraints_ca, int basic_constraints_path_len,
    uint32_t ext_key_usage_bits,
    const noxtls_x509_custom_ext_t *custom_exts, uint32_t custom_ext_count,
    uint32_t *eoff)
{
    uint32_t eoff_local = 0;

    if (key_usage_bits != 0) {
        /* Key Usage is BIT STRING; parser expects OCTET STRING content = unused (1 byte) + bit bytes */
        uint8_t ku_bs_content[3];
        uint8_t ku_oct[16];
        uint32_t ku_oct_len;
        uint8_t ext_seq[64];
        uint32_t ext_seq_len;
        uint8_t oid_enc[16];
        uint32_t oid_enc_len;
        uint32_t i;
        uint8_t first_byte = 0;
        for (i = 0; i < 8; i++) {
            if (key_usage_bits & (1u << i)) first_byte |= (1u << (7 - i));
        }
        ku_bs_content[0] = 7;  /* 7 unused bits in the last byte (2 bytes = 16 bits, 9 used) */
        ku_bs_content[1] = first_byte;
        ku_bs_content[2] = (key_usage_bits & 0x100) ? 0x80u : 0u;
        ku_oct_len = noxtls_asn1_put_octet_string(ku_oct, sizeof(ku_oct), ku_bs_content, (uint32_t)sizeof(ku_bs_content));
        if (ku_oct_len == 0) return 0;
        oid_enc_len = noxtls_asn1_put_oid_raw(oid_enc, sizeof(oid_enc), oid_key_usage, sizeof(oid_key_usage));
        memcpy(ext_seq, oid_enc, oid_enc_len);
        memcpy(ext_seq + oid_enc_len, ku_oct, ku_oct_len);
        ext_seq_len = noxtls_asn1_put_sequence(ext_list + eoff_local, ext_list_max - eoff_local, ext_seq, oid_enc_len + ku_oct_len);
        if (ext_seq_len == 0) return 0;
        eoff_local += ext_seq_len;
    }

    if (san_dns_count > 0 && san_dns != NULL) {
        uint8_t san_items[480];
        uint32_t san_items_len = 0;
        uint8_t san_seq[512];
        uint32_t san_seq_len;
        uint32_t i;
        uint8_t oid_enc[16];
        uint32_t oid_enc_len;
        uint8_t san_oct[600];
        uint32_t san_oct_len;
        uint8_t ext_seq[640];
        uint32_t ext_seq_len;

        for (i = 0; i < san_dns_count && san_dns[i] != NULL; i++) {
            uint32_t slen = 0;
            while (slen < X509_SAN_DNS_LEN - 1 && san_dns[i][slen] != '\0') slen++;
            if (slen == 0) continue;
            if (san_items_len + 2 + 2 + slen > sizeof(san_items)) return 0;
            san_items[san_items_len++] = 0x82;
            san_items_len += noxtls_asn1_put_length(san_items + san_items_len, slen);
            memcpy(san_items + san_items_len, san_dns[i], slen);
            san_items_len += slen;
        }
        if (san_items_len == 0) return 0;
        san_seq_len = noxtls_asn1_put_sequence(san_seq, sizeof(san_seq), san_items, san_items_len);
        if (san_seq_len == 0) return 0;
        san_oct_len = noxtls_asn1_put_octet_string(san_oct, sizeof(san_oct), san_seq, san_seq_len);
        if (san_oct_len == 0) return 0;
        oid_enc_len = noxtls_asn1_put_oid_raw(oid_enc, sizeof(oid_enc), oid_subject_alt_name, sizeof(oid_subject_alt_name));
        memcpy(ext_seq, oid_enc, oid_enc_len);
        memcpy(ext_seq + oid_enc_len, san_oct, san_oct_len);
        ext_seq_len = noxtls_asn1_put_sequence(ext_list + eoff_local, ext_list_max - eoff_local, ext_seq, oid_enc_len + san_oct_len);
        if (ext_seq_len == 0) return 0;
        eoff_local += ext_seq_len;
    }

    if (basic_constraints_ca >= 0) {
        uint8_t bc_content[32];
        uint32_t bc_len = 0;
        uint8_t bc_seq[48];
        uint32_t bc_seq_len;
        uint8_t bc_oct[56];
        uint32_t bc_oct_len;
        uint8_t ext_seq[96];
        uint32_t ext_seq_len;
        uint8_t oid_enc[16];
        uint32_t oid_enc_len;
        uint8_t ca_boolean[] = { 0x01, 0x01, 0xFF };
        uint8_t ca_false[] = { 0x01, 0x01, 0x00 };
        if (basic_constraints_ca) {
            memcpy(bc_content, ca_boolean, 3);
            bc_len = 3;
        } else {
            memcpy(bc_content, ca_false, 3);
            bc_len = 3;
        }
        if (basic_constraints_path_len >= 0) {
            uint8_t path_enc[8];
            uint8_t path_byte = (uint8_t)(basic_constraints_path_len & 0xFF);
            uint32_t path_enc_len = noxtls_asn1_put_integer(path_enc, sizeof(path_enc), &path_byte, 1);
            if (path_enc_len == 0) return 0;
            if (bc_len + path_enc_len > sizeof(bc_content)) return 0;
            memcpy(bc_content + bc_len, path_enc, path_enc_len);
            bc_len += path_enc_len;
        }
        bc_seq_len = noxtls_asn1_put_sequence(bc_seq, sizeof(bc_seq), bc_content, bc_len);
        if (bc_seq_len == 0) return 0;
        bc_oct_len = noxtls_asn1_put_octet_string(bc_oct, sizeof(bc_oct), bc_seq, bc_seq_len);
        if (bc_oct_len == 0) return 0;
        oid_enc_len = noxtls_asn1_put_oid_raw(oid_enc, sizeof(oid_enc), oid_basic_constraints, sizeof(oid_basic_constraints));
        memcpy(ext_seq, oid_enc, oid_enc_len);
        memcpy(ext_seq + oid_enc_len, bc_oct, bc_oct_len);
        ext_seq_len = noxtls_asn1_put_sequence(ext_list + eoff_local, ext_list_max - eoff_local, ext_seq, oid_enc_len + bc_oct_len);
        if (ext_seq_len == 0) return 0;
        eoff_local += ext_seq_len;
    }

    if (ext_key_usage_bits != 0) {
        uint8_t eku_oids[256];
        uint32_t eku_oids_len = 0;
        uint8_t eku_seq[280];
        uint32_t eku_seq_len;
        uint8_t eku_oct[300];
        uint32_t eku_oct_len;
        uint8_t ext_seq[340];
        uint32_t ext_seq_len;
        uint8_t oid_enc[20];
        uint32_t oid_enc_len;
        const uint8_t *eku_oid;
        uint32_t eku_oid_len;

#define ADD_EKU(oid_arr) do { \
    eku_oid = (oid_arr); eku_oid_len = sizeof(oid_arr); \
    if (eku_oids_len + 16 < sizeof(eku_oids)) { \
        uint32_t n = noxtls_asn1_put_oid_raw(eku_oids + eku_oids_len, (uint32_t)(sizeof(eku_oids) - eku_oids_len), eku_oid, eku_oid_len); \
        if (n) eku_oids_len += n; \
    } } while(0)
        if (ext_key_usage_bits & X509_EKU_SERVER_AUTH) ADD_EKU(oid_kp_server_auth);
        if (ext_key_usage_bits & X509_EKU_CLIENT_AUTH) ADD_EKU(oid_kp_client_auth);
        if (ext_key_usage_bits & X509_EKU_CODE_SIGNING) ADD_EKU(oid_kp_code_signing);
        if (ext_key_usage_bits & X509_EKU_EMAIL_PROTECTION) ADD_EKU(oid_kp_email_protection);
        if (ext_key_usage_bits & X509_EKU_TIME_STAMPING) ADD_EKU(oid_kp_time_stamping);
        if (ext_key_usage_bits & X509_EKU_OCSP_SIGNING) ADD_EKU(oid_kp_ocsp_signing);
        if (ext_key_usage_bits & X509_EKU_ANY) ADD_EKU(oid_any_eku);
#undef ADD_EKU
        if (eku_oids_len == 0) return 0;
        eku_seq_len = noxtls_asn1_put_sequence(eku_seq, sizeof(eku_seq), eku_oids, eku_oids_len);
        if (eku_seq_len == 0) return 0;
        eku_oct_len = noxtls_asn1_put_octet_string(eku_oct, sizeof(eku_oct), eku_seq, eku_seq_len);
        if (eku_oct_len == 0) return 0;
        oid_enc_len = noxtls_asn1_put_oid_raw(oid_enc, sizeof(oid_enc), oid_ext_key_usage, sizeof(oid_ext_key_usage));
        memcpy(ext_seq, oid_enc, oid_enc_len);
        memcpy(ext_seq + oid_enc_len, eku_oct, eku_oct_len);
        ext_seq_len = noxtls_asn1_put_sequence(ext_list + eoff_local, ext_list_max - eoff_local, ext_seq, oid_enc_len + eku_oct_len);
        if (ext_seq_len == 0) return 0;
        eoff_local += ext_seq_len;
    }

    if (custom_exts != NULL && custom_ext_count > 0) {
        uint32_t c;
        for (c = 0; c < custom_ext_count; c++) {
            uint8_t ext_content[256];
            uint32_t ext_content_len = 0;
            uint8_t oid_enc[32];
            uint32_t oid_enc_len;
            uint8_t oct_buf[200];
            uint32_t oct_len;
            uint32_t ext_seq_len;
            const noxtls_x509_custom_ext_t *ce = &custom_exts[c];
            if (ce->oid == NULL || ce->oid_len == 0 || ce->value == NULL) continue;
            oid_enc_len = noxtls_asn1_put_oid_raw(oid_enc, sizeof(oid_enc), ce->oid, ce->oid_len);
            if (oid_enc_len == 0) return 0;
            if (oid_enc_len + 8 + ce->value_len > sizeof(ext_content)) return 0;
            memcpy(ext_content, oid_enc, oid_enc_len);
            ext_content_len = oid_enc_len;
            if (ce->critical) {
                ext_content[ext_content_len++] = 0x01;
                ext_content[ext_content_len++] = 0x01;
                ext_content[ext_content_len++] = 0xFF;
            }
            oct_len = noxtls_asn1_put_octet_string(oct_buf, sizeof(oct_buf), ce->value, ce->value_len);
            if (oct_len == 0) return 0;
            if (ext_content_len + oct_len > sizeof(ext_content)) return 0;
            memcpy(ext_content + ext_content_len, oct_buf, oct_len);
            ext_content_len += oct_len;
            ext_seq_len = noxtls_asn1_put_sequence(ext_list + eoff_local, ext_list_max - eoff_local, ext_content, ext_content_len);
            if (ext_seq_len == 0) return 0;
            eoff_local += ext_seq_len;
        }
    }

    *eoff = eoff_local;
    return 1;
}

noxtls_return_t noxtls_x509_certificate_generate_self_signed_with_extensions(
    const uint8_t *serial, uint32_t serial_len,
    const uint8_t *issuer_der, uint32_t issuer_len,
    const uint8_t *subject_der, uint32_t subject_len,
    const char *not_before_utc, const char *not_after_utc,
    const uint8_t *subject_pk_oid, uint32_t subject_pk_oid_len,
    const uint8_t *subject_pk, uint32_t subject_pk_len,
    const uint8_t *sig_oid, uint32_t sig_oid_len,
    const uint8_t *sign_key, uint32_t sign_key_len,
    noxtls_hash_algos_t hash_algo,
    const char *const *san_dns, uint32_t san_dns_count,
    uint16_t key_usage_bits,
    uint8_t *out_der, uint32_t out_max, uint32_t *out_len)
{
    uint8_t ext_buf[X509_EXTENSIONS_MAX];
    uint32_t ext_len = 0;
    uint32_t off;

    if (serial == NULL || serial_len == 0 || issuer_der == NULL || issuer_len == 0 ||
        subject_der == NULL || subject_len == 0 || not_before_utc == NULL || not_after_utc == NULL ||
        subject_pk_oid == NULL || subject_pk_oid_len == 0 || subject_pk == NULL || subject_pk_len == 0 ||
        sig_oid == NULL || sig_oid_len == 0 || sign_key == NULL || sign_key_len == 0 ||
        out_der == NULL || out_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if ((san_dns_count > 0 && san_dns == NULL) || (san_dns_count > X509_SAN_DNS_MAX)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    {
        uint8_t ext_list[X509_EXTENSIONS_MAX];
        uint8_t ext_seq[X509_EXTENSIONS_MAX];
        uint32_t eoff = 0;
        uint32_t ext_seq_len = 0;
        if (build_extensions(ext_list, sizeof(ext_list), san_dns, san_dns_count, key_usage_bits,
                             -1, X509_BC_PATH_LEN_ABSENT, 0, NULL, 0, &eoff)) {
            if (eoff > 0) {
                ext_seq_len = noxtls_asn1_put_sequence(ext_seq, sizeof(ext_seq), ext_list, eoff);
                if (ext_seq_len == 0) return NOXTLS_RETURN_FAILED;
                ext_len = noxtls_asn1_put_explicit(ext_buf, sizeof(ext_buf), 3, ext_seq, ext_seq_len);
                if (ext_len == 0) return NOXTLS_RETURN_FAILED;
            }
        }
    }

    {
        uint8_t tbs_buf[X509_WRITE_TBS_MAX];
        uint32_t tbs_len = 0;
        uint8_t version_buf[8];
        uint32_t version_len;
        uint8_t serial_enc[64];
        uint32_t serial_enc_len;
        uint8_t sig_alg_seq[64];
        uint32_t sig_alg_seq_len;
        uint8_t validity_seq[64];
        uint32_t validity_len;
        uint8_t spki_buf[600];
        uint32_t spki_len;
        uint8_t tbs_full[X509_WRITE_TBS_MAX + 8];
        uint32_t tbs_full_len;
        uint8_t sig_der[256];
        uint32_t sig_len;
        uint8_t cert_seq_buf[X509_MAX_CERT_SIZE];
        uint32_t cert_seq_len;

        { /* version [0] EXPLICIT 2 */
            uint8_t ver_int[] = { 0x02, 0x01, 0x02 };
            version_len = noxtls_asn1_put_explicit(version_buf, sizeof(version_buf), 0, ver_int, sizeof(ver_int));
        }
        serial_enc_len = noxtls_asn1_put_integer(serial_enc, sizeof(serial_enc), serial, serial_len);
        {
            uint8_t oid_enc[48];
            uint32_t oid_enc_len = noxtls_asn1_put_oid_raw(oid_enc, sizeof(oid_enc), sig_oid, sig_oid_len);
            sig_alg_seq_len = noxtls_asn1_put_sequence(sig_alg_seq, sizeof(sig_alg_seq), oid_enc, oid_enc_len);
        }
        {
            uint8_t vb[32], va[32], validity_content[64];
            uint32_t vbl = noxtls_asn1_put_utc_time(vb, sizeof(vb), not_before_utc);
            uint32_t val = noxtls_asn1_put_utc_time(va, sizeof(va), not_after_utc);
            memcpy(validity_content, vb, vbl);
            memcpy(validity_content + vbl, va, val);
            validity_len = noxtls_asn1_put_sequence(validity_seq, sizeof(validity_seq), validity_content, vbl + val);
        }
        {
            uint8_t alg_oid[48], alg_seq[64], bitstr[520], spki_content[600];
            uint32_t alg_oid_len = noxtls_asn1_put_oid_raw(alg_oid, sizeof(alg_oid), subject_pk_oid, subject_pk_oid_len);
            uint32_t alg_seq_len = noxtls_asn1_put_sequence(alg_seq, sizeof(alg_seq), alg_oid, alg_oid_len);
            uint32_t bs_len = noxtls_asn1_put_bit_string(bitstr, sizeof(bitstr), subject_pk, subject_pk_len);
            memcpy(spki_content, alg_seq, alg_seq_len);
            memcpy(spki_content + alg_seq_len, bitstr, bs_len);
            spki_len = noxtls_asn1_put_sequence(spki_buf, sizeof(spki_buf), spki_content, alg_seq_len + bs_len);
        }

        off = 0;
        memcpy(tbs_buf + off, version_buf, version_len); off += version_len;
        memcpy(tbs_buf + off, serial_enc, serial_enc_len); off += serial_enc_len;
        memcpy(tbs_buf + off, sig_alg_seq, sig_alg_seq_len); off += sig_alg_seq_len;
        memcpy(tbs_buf + off, issuer_der, issuer_len); off += issuer_len;
        memcpy(tbs_buf + off, validity_seq, validity_len); off += validity_len;
        memcpy(tbs_buf + off, subject_der, subject_len); off += subject_len;
        memcpy(tbs_buf + off, spki_buf, spki_len); off += spki_len;
        if (ext_len > 0) {
            if (off + ext_len > sizeof(tbs_buf)) {
                return NOXTLS_RETURN_FAILED;
            }
            memcpy(tbs_buf + off, ext_buf, ext_len);
            off += ext_len;
        }
        tbs_len = off;

        tbs_full_len = noxtls_asn1_put_sequence(tbs_full, sizeof(tbs_full), tbs_buf, tbs_len);
        if (tbs_full_len == 0) {
            return NOXTLS_RETURN_FAILED;
        }
        if (noxtls_x509_private_key_sign_data(sign_key, sign_key_len, tbs_full, tbs_full_len, hash_algo, sig_der, sizeof(sig_der), &sig_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        {
            uint8_t sig_bitstr[300];
            uint32_t sig_bs_len = noxtls_asn1_put_bit_string(sig_bitstr, sizeof(sig_bitstr), sig_der, sig_len);
            off = 0;
            memcpy(cert_seq_buf + off, tbs_full, tbs_full_len); off += tbs_full_len;
            memcpy(cert_seq_buf + off, sig_alg_seq, sig_alg_seq_len); off += sig_alg_seq_len;
            memcpy(cert_seq_buf + off, sig_bitstr, sig_bs_len); off += sig_bs_len;
            cert_seq_len = noxtls_asn1_put_sequence(out_der, out_max, cert_seq_buf, off);
        }
        if (cert_seq_len == 0) {
            return NOXTLS_RETURN_FAILED;
        }
        *out_len = cert_seq_len;
    }
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_x509_certificate_generate_self_signed_with_extensions_ex(
    const uint8_t *serial, uint32_t serial_len,
    const uint8_t *issuer_der, uint32_t issuer_len,
    const uint8_t *subject_der, uint32_t subject_len,
    const char *not_before_utc, const char *not_after_utc,
    const uint8_t *subject_pk_oid, uint32_t subject_pk_oid_len,
    const uint8_t *subject_pk, uint32_t subject_pk_len,
    const uint8_t *sig_oid, uint32_t sig_oid_len,
    const uint8_t *sign_key, uint32_t sign_key_len,
    noxtls_hash_algos_t hash_algo,
    const char *const *san_dns, uint32_t san_dns_count,
    uint16_t key_usage_bits,
    int basic_constraints_ca, int basic_constraints_path_len,
    uint32_t ext_key_usage_bits,
    const noxtls_x509_custom_ext_t *custom_exts, uint32_t custom_ext_count,
    uint8_t *out_der, uint32_t out_max, uint32_t *out_len)
{
    uint8_t ext_buf[X509_EXTENSIONS_MAX];
    uint32_t ext_len = 0;
    uint32_t off;

    if (serial == NULL || serial_len == 0 || issuer_der == NULL || issuer_len == 0 ||
        subject_der == NULL || subject_len == 0 || not_before_utc == NULL || not_after_utc == NULL ||
        subject_pk_oid == NULL || subject_pk_oid_len == 0 || subject_pk == NULL || subject_pk_len == 0 ||
        sig_oid == NULL || sig_oid_len == 0 || sign_key == NULL || sign_key_len == 0 ||
        out_der == NULL || out_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if ((san_dns_count > 0 && san_dns == NULL) || (san_dns_count > X509_SAN_DNS_MAX)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if ((custom_ext_count > 0 && custom_exts == NULL)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    {
        uint8_t ext_list[X509_EXTENSIONS_MAX];
        uint8_t ext_seq[X509_EXTENSIONS_MAX];
        uint32_t eoff = 0;
        uint32_t ext_seq_len = 0;
        if (build_extensions(ext_list, sizeof(ext_list), san_dns, san_dns_count, key_usage_bits,
                             basic_constraints_ca, basic_constraints_path_len, ext_key_usage_bits,
                             custom_exts, custom_ext_count, &eoff)) {
            if (eoff > 0) {
                ext_seq_len = noxtls_asn1_put_sequence(ext_seq, sizeof(ext_seq), ext_list, eoff);
                if (ext_seq_len == 0) return NOXTLS_RETURN_FAILED;
                ext_len = noxtls_asn1_put_explicit(ext_buf, sizeof(ext_buf), 3, ext_seq, ext_seq_len);
                if (ext_len == 0) return NOXTLS_RETURN_FAILED;
            }
        }
    }

    {
        uint8_t tbs_buf[X509_WRITE_TBS_MAX];
        uint32_t tbs_len = 0;
        uint8_t version_buf[8];
        uint32_t version_len;
        uint8_t serial_enc[64];
        uint32_t serial_enc_len;
        uint8_t sig_alg_seq[64];
        uint32_t sig_alg_seq_len;
        uint8_t validity_seq[64];
        uint32_t validity_len;
        uint8_t spki_buf[600];
        uint32_t spki_len;
        uint8_t tbs_full[X509_WRITE_TBS_MAX + 8];
        uint32_t tbs_full_len;
        uint8_t sig_der[256];
        uint32_t sig_len;
        uint8_t cert_seq_buf[X509_MAX_CERT_SIZE];
        uint32_t cert_seq_len;

        { uint8_t ver_int[] = { 0x02, 0x01, 0x02 };
          version_len = noxtls_asn1_put_explicit(version_buf, sizeof(version_buf), 0, ver_int, sizeof(ver_int)); }
        serial_enc_len = noxtls_asn1_put_integer(serial_enc, sizeof(serial_enc), serial, serial_len);
        { uint8_t oid_enc[48];
          uint32_t oid_enc_len = noxtls_asn1_put_oid_raw(oid_enc, sizeof(oid_enc), sig_oid, sig_oid_len);
          sig_alg_seq_len = noxtls_asn1_put_sequence(sig_alg_seq, sizeof(sig_alg_seq), oid_enc, oid_enc_len); }
        { uint8_t vb[32], va[32], validity_content[64];
          uint32_t vbl = noxtls_asn1_put_utc_time(vb, sizeof(vb), not_before_utc);
          uint32_t val = noxtls_asn1_put_utc_time(va, sizeof(va), not_after_utc);
          memcpy(validity_content, vb, vbl);
          memcpy(validity_content + vbl, va, val);
          validity_len = noxtls_asn1_put_sequence(validity_seq, sizeof(validity_seq), validity_content, vbl + val); }
        { uint8_t alg_oid[48], alg_seq[64], bitstr[520], spki_content[600];
          uint32_t alg_oid_len = noxtls_asn1_put_oid_raw(alg_oid, sizeof(alg_oid), subject_pk_oid, subject_pk_oid_len);
          uint32_t alg_seq_len = noxtls_asn1_put_sequence(alg_seq, sizeof(alg_seq), alg_oid, alg_oid_len);
          uint32_t bs_len = noxtls_asn1_put_bit_string(bitstr, sizeof(bitstr), subject_pk, subject_pk_len);
          memcpy(spki_content, alg_seq, alg_seq_len);
          memcpy(spki_content + alg_seq_len, bitstr, bs_len);
          spki_len = noxtls_asn1_put_sequence(spki_buf, sizeof(spki_buf), spki_content, alg_seq_len + bs_len); }

        off = 0;
        memcpy(tbs_buf + off, version_buf, version_len); off += version_len;
        memcpy(tbs_buf + off, serial_enc, serial_enc_len); off += serial_enc_len;
        memcpy(tbs_buf + off, sig_alg_seq, sig_alg_seq_len); off += sig_alg_seq_len;
        memcpy(tbs_buf + off, issuer_der, issuer_len); off += issuer_len;
        memcpy(tbs_buf + off, validity_seq, validity_len); off += validity_len;
        memcpy(tbs_buf + off, subject_der, subject_len); off += subject_len;
        memcpy(tbs_buf + off, spki_buf, spki_len); off += spki_len;
        if (ext_len > 0) {
            if (off + ext_len > sizeof(tbs_buf)) return NOXTLS_RETURN_FAILED;
            memcpy(tbs_buf + off, ext_buf, ext_len);
            off += ext_len;
        }
        tbs_len = off;

        tbs_full_len = noxtls_asn1_put_sequence(tbs_full, sizeof(tbs_full), tbs_buf, tbs_len);
        if (tbs_full_len == 0) return NOXTLS_RETURN_FAILED;
        if (noxtls_x509_private_key_sign_data(sign_key, sign_key_len, tbs_full, tbs_full_len, hash_algo, sig_der, sizeof(sig_der), &sig_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        { uint8_t sig_bitstr[300];
          uint32_t sig_bs_len = noxtls_asn1_put_bit_string(sig_bitstr, sizeof(sig_bitstr), sig_der, sig_len);
          off = 0;
          memcpy(cert_seq_buf + off, tbs_full, tbs_full_len); off += tbs_full_len;
          memcpy(cert_seq_buf + off, sig_alg_seq, sig_alg_seq_len); off += sig_alg_seq_len;
          memcpy(cert_seq_buf + off, sig_bitstr, sig_bs_len); off += sig_bs_len;
          cert_seq_len = noxtls_asn1_put_sequence(out_der, out_max, cert_seq_buf, off); }
        if (cert_seq_len == 0) return NOXTLS_RETURN_FAILED;
        *out_len = cert_seq_len;
    }
    return NOXTLS_RETURN_SUCCESS;
}

#define X509_CSR_CRI_MAX  2048u

/**
 * Create a PKCS#10 Certificate Signing Request (RFC 2986) in DER form.
 * CertificationRequestInfo is version 0, subject, subjectPKInfo; attributes omitted.
 * Signed with sign_key (ECC private key; RSA not supported by noxtls_x509_private_key_sign_data).
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
    uint8_t cri_buf[X509_CSR_CRI_MAX];
    uint32_t cri_len = 0;
    uint8_t version_int[] = { 0x02, 0x01, 0x00 };  /* INTEGER 0 */
    uint8_t alg_oid[48], alg_seq[64], bitstr[520], spki_content[600];
    uint32_t alg_oid_len, alg_seq_len, bs_len, spki_len;
    uint8_t cri_seq[X509_CSR_CRI_MAX + 8];
    uint32_t cri_seq_len;
    uint8_t sig_der[256];
    uint32_t sig_len;
    uint8_t sig_alg_seq[64];
    uint32_t sig_alg_seq_len;
    uint8_t sig_bitstr[300];
    uint32_t sig_bs_len;
    uint8_t cr_seq_buf[X509_CSR_CRI_MAX + 400];
    uint32_t cr_seq_len;
    uint32_t off;

    if (subject_der == NULL || subject_len == 0 ||
        subject_pk_oid == NULL || subject_pk_oid_len == 0 ||
        subject_pk == NULL || subject_pk_len == 0 ||
        sig_oid == NULL || sig_oid_len == 0 ||
        sign_key == NULL || sign_key_len == 0 ||
        out_der == NULL || out_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    /* CertificationRequestInfo content: version + subject + subjectPKInfo */
    off = 0;
    if (off + sizeof(version_int) > sizeof(cri_buf)) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(cri_buf + off, version_int, sizeof(version_int));
    off += sizeof(version_int);

    if (off + subject_len > sizeof(cri_buf)) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(cri_buf + off, subject_der, subject_len);
    off += subject_len;

    alg_oid_len = noxtls_asn1_put_oid_raw(alg_oid, sizeof(alg_oid), subject_pk_oid, subject_pk_oid_len);
    if (alg_oid_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }
    alg_seq_len = noxtls_asn1_put_sequence(alg_seq, sizeof(alg_seq), alg_oid, alg_oid_len);
    if (alg_seq_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }
    bs_len = noxtls_asn1_put_bit_string(bitstr, sizeof(bitstr), subject_pk, subject_pk_len);
    if (bs_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(spki_content, alg_seq, alg_seq_len);
    memcpy(spki_content + alg_seq_len, bitstr, bs_len);
    spki_len = noxtls_asn1_put_sequence(cri_buf + off, (uint32_t)(sizeof(cri_buf) - off), spki_content, alg_seq_len + bs_len);
    if (spki_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }
    off += spki_len;
    cri_len = off;

    /* CRI as SEQUENCE (this is the data to be signed) */
    cri_seq_len = noxtls_asn1_put_sequence(cri_seq, sizeof(cri_seq), cri_buf, cri_len);
    if (cri_seq_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    if (noxtls_x509_private_key_sign_data(sign_key, sign_key_len,
            cri_seq, cri_seq_len, hash_algo, sig_der, sizeof(sig_der), &sig_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    {
        uint8_t soid[48];
        uint32_t soid_len = noxtls_asn1_put_oid_raw(soid, sizeof(soid), sig_oid, sig_oid_len);
        if (soid_len == 0) {
            return NOXTLS_RETURN_FAILED;
        }
        sig_alg_seq_len = noxtls_asn1_put_sequence(sig_alg_seq, sizeof(sig_alg_seq), soid, soid_len);
    }
    if (sig_alg_seq_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    sig_bs_len = noxtls_asn1_put_bit_string(sig_bitstr, sizeof(sig_bitstr), sig_der, sig_len);
    if (sig_bs_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    off = 0;
    if (off + cri_seq_len + sig_alg_seq_len + sig_bs_len > sizeof(cr_seq_buf)) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(cr_seq_buf + off, cri_seq, cri_seq_len);
    off += cri_seq_len;
    memcpy(cr_seq_buf + off, sig_alg_seq, sig_alg_seq_len);
    off += sig_alg_seq_len;
    memcpy(cr_seq_buf + off, sig_bitstr, sig_bs_len);
    off += sig_bs_len;

    cr_seq_len = noxtls_asn1_put_sequence(out_der, out_max, cr_seq_buf, off);
    if (cr_seq_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }
    *out_len = cr_seq_len;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_x509_csr_create_pem(
    const uint8_t *subject_der, uint32_t subject_len,
    const uint8_t *subject_pk_oid, uint32_t subject_pk_oid_len,
    const uint8_t *subject_pk, uint32_t subject_pk_len,
    const uint8_t *sig_oid, uint32_t sig_oid_len,
    const uint8_t *sign_key, uint32_t sign_key_len,
    noxtls_hash_algos_t hash_algo,
    uint8_t *out_pem, uint32_t out_max, uint32_t *out_len)
{
    uint8_t der_buf[X509_CSR_CRI_MAX + 400];
    uint32_t der_len;

    if (out_pem == NULL || out_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if (noxtls_x509_csr_create_der(subject_der, subject_len,
            subject_pk_oid, subject_pk_oid_len, subject_pk, subject_pk_len,
            sig_oid, sig_oid_len, sign_key, sign_key_len, hash_algo,
            der_buf, sizeof(der_buf), &der_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    return noxtls_csr_der_to_pem(der_buf, der_len, out_pem, out_len);
}

#endif /* NOXTLS_HAVE_CERT_WRITE */
