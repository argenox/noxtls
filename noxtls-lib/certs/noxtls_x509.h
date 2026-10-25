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
* File:    noxtls_x509.h
* Summary: X.509 Certificate Parsing and Validation
*
*****************************************************************************/

/**
 * @defgroup noxtls_certs Certificates and X.509
 * @brief ASN.1, certificate parsing (DER/PEM), and X.509 APIs.
 * @addtogroup noxtls
 */
/** @{ */

#ifndef NOXTLS_X509_H_
#define NOXTLS_X509_H_

#include <stdint.h>
#include "noxtls_common.h"
#include "pkc/ecc/noxtls_ecc.h"
#if NOXTLS_FEATURE_ML_DSA
#include "pkc/mldsa/noxtls_mldsa.h"
#endif
#if NOXTLS_FEATURE_SLH_DSA
#include "pkc/slhdsa/noxtls_slhdsa.h"
#endif
#if NOXTLS_FEATURE_FALCON
#include "pkc/falcon/noxtls_falcon.h"
#endif
#include "common/noxtls_pq_param_typedefs.h"
#include "mdigest/noxtls_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum certificate size */
#define X509_MAX_CERT_SIZE        NOXTLS_MAX_CERT_SIZE
/* CRLs can be larger than individual certificates (many revoked entries). */
#define X509_MAX_CRL_SIZE         (X509_MAX_CERT_SIZE * 16U)
#define X509_MAX_SUBJECT_SIZE     512U
#define X509_MAX_ISSUER_SIZE      512U
#define X509_MAX_SERIAL_SIZE      32U
#define X509_MAX_PUBLIC_KEY_SIZE  2048U
#define X509_MAX_PRIVATE_KEY_SIZE 4096U
/* RSA modulus n length in bytes for standard key sizes (1024/2048/3072/4096-bit). DER INTEGER may use this length or one more byte (leading zero). */
#define X509_RSA_MODULUS_BYTES_1024  128U
#define X509_RSA_MODULUS_BYTES_2048  256U
#define X509_RSA_MODULUS_BYTES_3072  384U
#define X509_RSA_MODULUS_BYTES_4096  512U
/* Legacy SAN table limits. The parser no longer stores SAN tables (entries are read from the DER
 * with noxtls_x509_san_iter_next() / noxtls_x509_certificate_get_san(), without a count or length
 * cap); these values are kept only for source compatibility. */
#define X509_SAN_DNS_MAX          8U
#define X509_SAN_DNS_LEN          256U
#define X509_SAN_EMAIL_MAX        4U
#define X509_SAN_EMAIL_LEN        256U
#define X509_SAN_URI_MAX          4U
#define X509_SAN_URI_LEN          256U
#define X509_SAN_IP_MAX           4U
#define X509_SAN_IP_BYTES         16   /* IPv4 or IPv6 */
#define X509_SAN_IP_IS_V6_BIT     0x80 /* flag in stored entry: high bit of first byte of length */
#define X509_HOSTNAME_WILDCARD_PREFIX_LEN 2U
/* Key Usage bits (RFC 5280): bit 0 = digitalSignature, 1 = nonRepudiation, 2 = keyEncipherment, 3 = dataEncipherment, 4 = keyAgreement, 5 = keyCertSign, 6 = cRLSign, 7 = encipherOnly, 8 = decipherOnly */
#define X509_KEY_USAGE_DIGITAL_SIGNATURE    ((uint32_t)1U << 0)
#define X509_KEY_USAGE_NON_REPUDIATION     ((uint32_t)1U << 1)
#define X509_KEY_USAGE_KEY_ENCIPHERMENT    ((uint32_t)1U << 2)
#define X509_KEY_USAGE_DATA_ENCIPHERMENT   ((uint32_t)1U << 3)
#define X509_KEY_USAGE_KEY_AGREEMENT       ((uint32_t)1U << 4)
#define X509_KEY_USAGE_KEY_CERT_SIGN       ((uint32_t)1U << 5)
#define X509_KEY_USAGE_CRL_SIGN            ((uint32_t)1U << 6)
#define X509_KEY_USAGE_ENCIPHER_ONLY       ((uint32_t)1U << 7)
#define X509_KEY_USAGE_DECIPHER_ONLY       ((uint32_t)1U << 8)
/* Extended Key Usage bits (RFC 5280 id-kp-*): serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, OCSPSigning, anyExtendedKeyUsage */
#define X509_EKU_SERVER_AUTH       (1U << 0)
#define X509_EKU_CLIENT_AUTH       (1U << 1)
#define X509_EKU_CODE_SIGNING      (1U << 2)
#define X509_EKU_EMAIL_PROTECTION  (1U << 3)
#define X509_EKU_TIME_STAMPING     (1U << 4)
#define X509_EKU_OCSP_SIGNING      (1U << 5)
#define X509_EKU_ANY               (1U << 6)
/* Basic Constraints path length: use -1 or 0xFFFF when not present */
#define X509_BC_PATH_LEN_ABSENT   (-1)
/* Authority/Subject Key Identifier max stored length */
#define X509_KEY_ID_MAX_LEN        32U

/** Maximum revoked serial entries stored when parsing a CRL (larger CRLs fail parse). */
#define NOXTLS_X509_CRL_MAX_REVOKED 2048U

/**
 * @brief Bitmask for optional X.509 verification details (mbedTLS-style flags).
 * @details Set by noxtls_x509_verify_*_ex when \p flags_out is non-NULL. Bits are ORed on failure paths
 *          and may be set on success (e.g. CRL matched and checked).
 */
typedef uint32_t noxtls_x509_verify_flags_t;
/** Certificate serial matched a revoked entry on an applicable CRL. */
#define NOXTLS_X509_VERIFY_FLAG_CERT_REVOKED       (1U << 0)
/** CRL nextUpdate is present and current time is past nextUpdate (strict stale policy). */
#define NOXTLS_X509_VERIFY_FLAG_CRL_EXPIRED        (1U << 1)
/** CRL signature verification against the issuer failed. */
#define NOXTLS_X509_VERIFY_FLAG_CRL_BAD_SIGNATURE  (1U << 2)
/** A CRL was supplied but no CRL in the list matched any issuer in the validated chain (informational). */
#define NOXTLS_X509_VERIFY_FLAG_CRL_NO_MATCH       (1U << 3)
/** At least one supplied CRL matched an issuer DN and was evaluated (signature/time/revocation). */
#define NOXTLS_X509_VERIFY_FLAG_CRL_USED           (1U << 4)

/** Bits of x509_certificate_t::validity_flags. */
#define X509_VALIDITY_NOT_BEFORE_PRESENT  0x01U  /**< notBefore was found (not_before_time is meaningful unless _BAD). */
#define X509_VALIDITY_NOT_AFTER_PRESENT   0x02U  /**< notAfter was found. */
#define X509_VALIDITY_NOT_BEFORE_BAD      0x04U  /**< notBefore is present but not a valid UTCTime/GeneralizedTime. */
#define X509_VALIDITY_NOT_AFTER_BAD       0x08U  /**< notAfter is present but not a valid UTCTime/GeneralizedTime. */

/**
 * X.509 certificate (zero-copy view).
 *
 * Every pointer member points into the certificate DER held in @ref raw_data; nothing else is
 * allocated. After noxtls_x509_certificate_parse_der() / _pem() / _load_file() the DER is a heap
 * copy owned by the structure (@ref raw_data_owned != NULL) and released by
 * noxtls_x509_certificate_free(). After noxtls_x509_certificate_parse_der_nocopy() the DER is
 * borrowed: the caller must keep it unchanged and alive until the certificate is freed (flash
 * resident CAs, TLS message buffers during verification).
 *
 * Lengths of the variable-size fields are given by the matching *_len member. The structure is
 * read-only for applications: prefer the noxtls_x509_certificate_get_*() accessors, which keep
 * working when the layout changes. Do not copy the structure by value and free both copies.
 *
 * Layout change (memory reduction): the former fixed arrays (serial, OIDs, issuer/subject DER,
 * issuer_dn/subject_dn text, public_key[2048], Ed25519/Ed448/PQ key copies, SAN name tables) are
 * now pointers into @ref raw_data; issuer_dn/subject_dn text is rendered on demand with
 * noxtls_x509_certificate_get_issuer_dn() / _get_subject_dn(); notBefore/notAfter are parsed
 * once into seconds since the Unix epoch (not_before_time / not_after_time, raw strings via
 * noxtls_x509_certificate_get_validity_raw()); SAN entries are read with the noxtls_x509_san_iter_*()
 * iterator or noxtls_x509_certificate_get_san().
 */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    /* Validity, seconds since the Unix epoch (see validity_flags). First for alignment. */
    int64_t not_before_time;
    int64_t not_after_time;

    /* Raw certificate data (complete Certificate SEQUENCE TLV). */
    const uint8_t *raw_data;
    uint32_t raw_data_len;
    /** Heap buffer owned by this structure (== raw_data), or NULL when raw_data is borrowed. */
    uint8_t *raw_data_owned;

    /* TBSCertificate TLV (the signed bytes). */
    const uint8_t *tbs_certificate;
    uint32_t tbs_certificate_len;

    /* Serial number INTEGER contents (serial_number_len octets, at most X509_MAX_SERIAL_SIZE). */
    const uint8_t *serial_number;
    /* Outer signatureAlgorithm OID contents. */
    const uint8_t *signature_algorithm_oid;
    /* Issuer / subject Name: SEQUENCE contents (RDNSequence without the outer tag/length). */
    const uint8_t *issuer;
    const uint8_t *subject;

    /* Subject Public Key Info */
    const uint8_t *public_key_algorithm_oid;  /* AlgorithmIdentifier OID contents */
    const uint8_t *ecc_curve_oid;             /* id-ecPublicKey namedCurve OID contents, or NULL */
    const uint8_t *public_key;                /* subjectPublicKey BIT STRING contents after the unused-bits octet */
    uint32_t public_key_len;

    /* RSA public key (if RSA): INTEGER contents (may carry a leading 0x00). */
    const uint8_t *rsa_modulus;
    uint32_t rsa_modulus_len;
    const uint8_t *rsa_exponent;
    uint32_t rsa_exponent_len;

    /* ECC public key (if id-ecPublicKey): uncompressed point 0x04 || X || Y, validated at parse. */
    const uint8_t *ecc_public_key;
    uint32_t ecc_public_key_len;

    /* Ed25519 (32 bytes, OID 1.3.101.112) / Ed448 (57 bytes, OID 1.3.101.113) raw public key. */
    const uint8_t *ed25519_public_key;
    const uint8_t *ed448_public_key;

#if NOXTLS_FEATURE_ML_DSA
    /* ML-DSA public key (public_key_len bytes; private-use parser support for PQ cert experiments). */
    const uint8_t *mldsa_public_key;
    noxtls_mldsa_param_t mldsa_param;
#endif
#if NOXTLS_FEATURE_SLH_DSA
    /* SLH-DSA public key (public_key_len bytes). */
    const uint8_t *slhdsa_public_key;
    noxtls_slhdsa_param_t slhdsa_param;
#endif
#if NOXTLS_FEATURE_FALCON
    /* FALCON public key (public_key_len bytes). */
    const uint8_t *falcon_public_key;
    noxtls_falcon_param_t falcon_param;
#endif

    /* Extensions (v3): Extensions SEQUENCE TLV inside the [3] wrapper, or NULL. */
    const uint8_t *extensions;
    uint32_t extensions_len;
    /* Parsed: Authority / Subject Key Identifier octets (at most X509_KEY_ID_MAX_LEN), or NULL. */
    const uint8_t *authority_key_id;
    const uint8_t *subject_key_id;

    /* Signature value (BIT STRING contents after the unused-bits octet). */
    const uint8_t *signature;
    uint32_t signature_len;

    /* Parsed: Extended Key Usage (X509_EKU_*); 0 = not present */
    uint32_t ext_key_usage_bits;
    /* Parsed: Basic Constraints pathLenConstraint (values above 32767 are stored as 32767, which
     * exceeds any verifiable depth) or X509_BC_PATH_LEN_ABSENT */
    int16_t basic_constraints_path_len;

    uint16_t issuer_len;
    uint16_t subject_len;
    /* Parsed: Key Usage (bitmask, X509_KEY_USAGE_*); 0 = not present */
    uint16_t key_usage_bits;
    uint8_t serial_number_len;
    uint8_t signature_algorithm_oid_len;
    uint8_t public_key_algorithm_oid_len;
    uint8_t ecc_curve_oid_len;
    uint8_t authority_key_id_len;       /* 0 = absent */
    uint8_t subject_key_id_len;         /* 0 = absent */

    /* Certificate version: 0 = v1, 1 = v2, 2 = v3 */
    uint8_t version;
    /* Parsed: Basic Constraints cA: 0 = not CA, 1 = CA, -1 = extension absent */
    int8_t basic_constraints_ca;
    /* Number of non-empty SAN dNSName entries (saturates at 255). A dNSName containing a NUL
     * octet counts as present (disables the CN fallback in noxtls_x509_certificate_matches_hostname)
     * but never matches a hostname. */
    uint8_t san_dns_count;
    /* X509_VALIDITY_* bits */
    uint8_t validity_flags;
    uint8_t has_ed25519;  /* 1 if subject public key is Ed25519 */
    uint8_t has_ed448;    /* 1 if subject public key is Ed448 */
    uint8_t has_mldsa;
    uint8_t has_slhdsa;
    uint8_t has_falcon;

    /* Parsed flag */
    uint8_t parsed;
} x509_certificate_t;
NOXTLS_MSVC_WARNING_POP

/* X.509 Certificate Chain */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    x509_certificate_t *certs;
    uint32_t count;
    uint32_t capacity;
} x509_certificate_chain_t;
NOXTLS_MSVC_WARNING_POP

/**
 * @brief Parsed X.509 CRL (CertificateList) with optional linked list via \p next (mbedTLS-style chain).
 */
#include "certs/noxtls_x509_crl_fwd.h"
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
/** Bits of noxtls_x509_crl_t::time_flags. */
#define X509_CRL_THIS_UPDATE_BAD  0x01U  /**< thisUpdate is not a valid UTCTime/GeneralizedTime. */
#define X509_CRL_NEXT_UPDATE_BAD  0x02U  /**< nextUpdate is present but not valid. */

/*
 * Zero-copy CRL: every pointer refers into raw_data (owned copy after
 * noxtls_x509_crl_parse_der(), borrowed after noxtls_x509_crl_parse_der_nocopy()).
 * The revoked serial numbers are not copied into a table: revokedCertificates is
 * validated at parse time and scanned in place by noxtls_x509_crl_serial_is_revoked()
 * / noxtls_x509_crl_get_revoked_serial(). Removed members: issuer_dn (render with
 * noxtls_x509_parse_distinguished_name(issuer, issuer_len, ...)), this_update /
 * next_update strings (now this_update_time / next_update_time), revoked_serials /
 * revoked_serial_lens (use noxtls_x509_crl_get_revoked_serial()).
 */
struct noxtls_x509_crl
{
    int64_t this_update_time;               /**< thisUpdate, seconds since the Unix epoch */
    int64_t next_update_time;               /**< nextUpdate (valid when has_next_update) */
    const uint8_t *raw_data;                /**< Complete CertificateList DER */
    uint32_t raw_data_len;
    uint8_t *raw_data_owned;                /**< Heap copy owned by the CRL, or NULL when borrowed */
    const uint8_t *issuer;                  /**< Issuer Name SEQUENCE contents */
    uint32_t issuer_len;
    const uint8_t *signature_algorithm_oid; /**< TBSCertList signature OID contents */
    uint32_t signature_algorithm_oid_len;
    const uint8_t *signature;               /**< Signature BIT STRING contents after the unused-bits octet */
    uint32_t signature_len;
    const uint8_t *tbs_crl;                 /**< TBSCertList TLV (signed bytes) */
    uint32_t tbs_crl_len;
    const uint8_t *revoked_list;            /**< revokedCertificates SEQUENCE contents, or NULL */
    uint32_t revoked_list_len;
    uint32_t revoked_count;
    uint8_t has_next_update;
    uint8_t time_flags;                     /**< X509_CRL_*_BAD bits */
    int parsed;
    struct noxtls_x509_crl *next;
};
NOXTLS_MSVC_WARNING_POP

noxtls_return_t noxtls_x509_crl_init(noxtls_x509_crl_t *crl);
/** Free this CRL and any linked CRLs in \p next. */
void noxtls_x509_crl_free(noxtls_x509_crl_t *crl);
/** Parse a DER CRL (one heap copy of the DER, at most X509_MAX_CRL_SIZE bytes; no other allocation). */
noxtls_return_t noxtls_x509_crl_parse_der(noxtls_x509_crl_t *crl, const uint8_t *data, uint32_t len);
/** Parse a DER CRL without copying it: @p data must outlive the CRL (no heap). */
noxtls_return_t noxtls_x509_crl_parse_der_nocopy(noxtls_x509_crl_t *crl, const uint8_t *data, uint32_t len);
/** The @p index-th revoked serial number (INTEGER contents, in CRL order). */
noxtls_return_t noxtls_x509_crl_get_revoked_serial(const noxtls_x509_crl_t *crl, uint32_t index,
                                                   const uint8_t **serial, uint32_t *serial_len);
noxtls_return_t noxtls_x509_crl_parse_pem(noxtls_x509_crl_t *crl, const uint8_t *data, uint32_t len);
noxtls_return_t noxtls_x509_crl_load_file(noxtls_x509_crl_t *crl, const uint8_t *filename);

/** Returns 1 if \p cert serial appears on \p crl (requires parsed CRL). */
int noxtls_x509_crl_serial_is_revoked(const noxtls_x509_crl_t *crl, const x509_certificate_t *cert);

/** Size of not_before/not_after strings in noxtls_cert_verify_failure_info_t (ASN.1 time, e.g. YYYYMMDDHHMMSSZ). */
#define NOXTLS_CERT_FAIL_TIME_MAX 16
/** Size of subject_dn and expected_hostname in noxtls_cert_verify_failure_info_t. */
#define NOXTLS_CERT_FAIL_DN_HOSTNAME_MAX 256

/**
 * Detailed certificate verification failure information.
 * Populated by X.509 APIs on certificate parse or verification failure; call noxtls_cert_verify_failure_get() after a failure to retrieve.
 * Fields are null-terminated where applicable; unused fields are zeroed.
 */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
	noxtls_return_t return_code;       /**< The return code that was/will be returned (e.g. NOXTLS_RETURN_CERT_EXPIRED). */
	uint8_t not_before[NOXTLS_CERT_FAIL_TIME_MAX];   /**< Certificate notBefore (ASN.1 time string). Set on time/validity failures. */
	uint8_t not_after[NOXTLS_CERT_FAIL_TIME_MAX];    /**< Certificate notAfter (ASN.1 time string). Set on time/validity failures. */
	uint8_t subject_dn[NOXTLS_CERT_FAIL_DN_HOSTNAME_MAX]; /**< Subject DN of the certificate that failed. */
	uint8_t expected_hostname[NOXTLS_CERT_FAIL_DN_HOSTNAME_MAX]; /**< Expected hostname (on hostname mismatch). */
	uint32_t cert_index;                /**< Index in chain (0-based) when chain verification fails; 0 for single-cert. */
	int populated;                      /**< 1 if this struct was filled by a failure; 0 otherwise. */
} noxtls_cert_verify_failure_info_t;
NOXTLS_MSVC_WARNING_POP

/** Clear the last certificate failure detail (e.g. before a new verification). */
void noxtls_cert_verify_failure_clear(void);
/**
 * Get the last certificate verification/parse failure detail.
 * Copy the stored failure info into \p out; sets out->populated to 1 if a failure was ever stored, 0 otherwise.
 * Safe to call after any X.509 API that returns a CERT_* or verification failure.
 */
void noxtls_cert_verify_failure_get(noxtls_cert_verify_failure_info_t *out);

/* X.509 Certificate Functions */
noxtls_return_t noxtls_x509_certificate_init(x509_certificate_t *cert);
noxtls_return_t noxtls_x509_certificate_free(x509_certificate_t *cert);
noxtls_return_t noxtls_x509_certificate_parse_der(x509_certificate_t *cert, const uint8_t *data, uint32_t len);
noxtls_return_t noxtls_x509_certificate_parse_pem(x509_certificate_t *cert, const uint8_t *data, uint32_t len);
noxtls_return_t noxtls_x509_certificate_load_file(x509_certificate_t *cert, const uint8_t *filename);
noxtls_return_t noxtls_x509_certificate_verify_signature(const x509_certificate_t *cert, const x509_certificate_t *issuer);
noxtls_return_t noxtls_x509_certificate_check_validity(const x509_certificate_t *cert);
noxtls_return_t noxtls_x509_certificate_get_public_key(const x509_certificate_t *cert, void **key, uint32_t *key_type);
noxtls_return_t x509_certificate_get_public_key(const x509_certificate_t *cert, void **key, uint32_t *key_type);

/**
 * Parse a DER certificate without copying it (borrow mode).
 * Same checks as noxtls_x509_certificate_parse_der(), but @p data is referenced instead of copied:
 * it must stay valid and unchanged until noxtls_x509_certificate_free() (flash-resident CAs, TLS
 * handshake buffers). No heap is used.
 */
noxtls_return_t noxtls_x509_certificate_parse_der_nocopy(x509_certificate_t *cert, const uint8_t *data, uint32_t len);

/* ---- Accessors (zero-copy views into the certificate DER; valid while the certificate is) ---- */
/** Complete certificate DER. */
noxtls_return_t noxtls_x509_certificate_get_der(const x509_certificate_t *cert, const uint8_t **der, uint32_t *der_len);
/** TBSCertificate TLV (the signed bytes). */
noxtls_return_t noxtls_x509_certificate_get_tbs(const x509_certificate_t *cert, const uint8_t **tbs, uint32_t *tbs_len);
/** Serial number INTEGER contents. */
noxtls_return_t noxtls_x509_certificate_get_serial(const x509_certificate_t *cert, const uint8_t **serial, uint32_t *serial_len);
/** Issuer Name as DER RDNSequence contents (no outer SEQUENCE header). */
noxtls_return_t noxtls_x509_certificate_get_issuer_der(const x509_certificate_t *cert, const uint8_t **name, uint32_t *name_len);
/** Subject Name as DER RDNSequence contents (no outer SEQUENCE header). */
noxtls_return_t noxtls_x509_certificate_get_subject_der(const x509_certificate_t *cert, const uint8_t **name, uint32_t *name_len);
/**
 * Render the issuer / subject Name as text ("CN=..., O=...") into @p out (NUL-terminated,
 * truncated to @p out_size). Formerly the issuer_dn / subject_dn members (256 bytes each).
 */
noxtls_return_t noxtls_x509_certificate_get_issuer_dn(const x509_certificate_t *cert, uint8_t *out, uint32_t out_size);
noxtls_return_t noxtls_x509_certificate_get_subject_dn(const x509_certificate_t *cert, uint8_t *out, uint32_t out_size);
/**
 * notBefore / notAfter in seconds since the Unix epoch. Returns NOXTLS_RETURN_BAD_DATA when a time
 * is present but malformed, NOXTLS_RETURN_FAILED when the certificate has no validity.
 */
noxtls_return_t noxtls_x509_certificate_get_validity(const x509_certificate_t *cert, int64_t *not_before, int64_t *not_after);
/**
 * notBefore / notAfter raw ASN.1 time contents (UTCTime / GeneralizedTime, not NUL-terminated),
 * for noxtls_x509_parse_time(). Outputs may be NULL; an absent time yields NULL / 0.
 */
noxtls_return_t noxtls_x509_certificate_get_validity_raw(const x509_certificate_t *cert,
                                                         const uint8_t **not_before, uint32_t *not_before_len,
                                                         const uint8_t **not_after, uint32_t *not_after_len);
/** Outer signatureAlgorithm OID contents. */
noxtls_return_t noxtls_x509_certificate_get_signature_algorithm(const x509_certificate_t *cert, const uint8_t **oid, uint32_t *oid_len);
/** Signature value (BIT STRING contents after the unused-bits octet). */
noxtls_return_t noxtls_x509_certificate_get_signature(const x509_certificate_t *cert, const uint8_t **sig, uint32_t *sig_len);
/**
 * SubjectPublicKeyInfo: algorithm OID contents and subjectPublicKey bytes (after the
 * unused-bits octet). Either output pair may be NULL.
 */
noxtls_return_t noxtls_x509_certificate_get_public_key_info(const x509_certificate_t *cert,
                                                            const uint8_t **alg_oid, uint32_t *alg_oid_len,
                                                            const uint8_t **key, uint32_t *key_len);
/** Authority / Subject Key Identifier octets; NOXTLS_RETURN_FAILED when absent. */
noxtls_return_t noxtls_x509_certificate_get_authority_key_id(const x509_certificate_t *cert, const uint8_t **kid, uint32_t *kid_len);
noxtls_return_t noxtls_x509_certificate_get_subject_key_id(const x509_certificate_t *cert, const uint8_t **kid, uint32_t *kid_len);

/**
 * Read the SubjectPublicKeyInfo algorithm OID straight from certificate DER with a small ASN.1
 * walk (no parse, no heap, < 100 bytes of stack). @p oid points into @p der.
 */
noxtls_return_t noxtls_x509_der_get_spki_algorithm(const uint8_t *der, uint32_t der_len,
                                                   const uint8_t **oid, uint32_t *oid_len);

/* ---- Subject Alternative Name iteration (GeneralName choice = context tag number) ---- */
#define NOXTLS_X509_SAN_OTHER_NAME   0U  /**< otherName [0] (value = constructed contents) */
#define NOXTLS_X509_SAN_EMAIL        1U  /**< rfc822Name [1] (IA5String bytes) */
#define NOXTLS_X509_SAN_DNS          2U  /**< dNSName [2] (IA5String bytes) */
#define NOXTLS_X509_SAN_DIRECTORY    4U  /**< directoryName [4] */
#define NOXTLS_X509_SAN_URI          6U  /**< uniformResourceIdentifier [6] */
#define NOXTLS_X509_SAN_IP           7U  /**< iPAddress [7] (4 or 16 octets) */
#define NOXTLS_X509_SAN_ANY          0xFFU /**< Filter value for noxtls_x509_certificate_san_count() / _get_san(): any type */

/** Iterator over every GeneralName of every subjectAltName extension; never owns memory. */
typedef struct
{
    const uint8_t *ext_next;   /**< Next unread Extension in the Extensions SEQUENCE. */
    const uint8_t *ext_end;    /**< End of the Extensions SEQUENCE contents. */
    const uint8_t *gn_next;    /**< Next unread GeneralName of the current SAN extension. */
    const uint8_t *gn_end;     /**< End of the current GeneralNames SEQUENCE. */
} noxtls_x509_san_iter_t;

/** Start iterating the SAN entries of a parsed certificate (empty when there is no SAN). */
noxtls_return_t noxtls_x509_san_iter_init(noxtls_x509_san_iter_t *iter, const x509_certificate_t *cert);
/**
 * Return the next GeneralName: @p type is the context tag number (NOXTLS_X509_SAN_*), @p value /
 * @p value_len the raw contents (not NUL-terminated, may contain any octet). *has_entry is 0 at
 * the end; a malformed entry ends the iteration.
 */
noxtls_return_t noxtls_x509_san_iter_next(noxtls_x509_san_iter_t *iter, uint8_t *type,
                                          const uint8_t **value, uint32_t *value_len, int *has_entry);
/** Number of SAN entries of @p type (NOXTLS_X509_SAN_ANY counts all). */
uint32_t noxtls_x509_certificate_san_count(const x509_certificate_t *cert, uint8_t type);
/** The @p index-th (0-based) SAN entry of @p type; NOXTLS_RETURN_FAILED when out of range. */
noxtls_return_t noxtls_x509_certificate_get_san(const x509_certificate_t *cert, uint8_t type, uint32_t index,
                                                const uint8_t **value, uint32_t *value_len);

/* X.509 Certificate Chain Functions */
/** Initialize an empty chain. Allocates nothing: slots are allocated by the first add. */
noxtls_return_t noxtls_x509_certificate_chain_init(x509_certificate_chain_t *chain);
noxtls_return_t noxtls_x509_certificate_chain_free(x509_certificate_chain_t *chain);
/**
 * Append a deep copy of @p cert (re-parsed from its DER into one owned DER copy). The slot array
 * grows linearly by NOXTLS_X509_CHAIN_INITIAL_CAPACITY slots; a capacity-0 (just initialized)
 * chain is valid.
 */
noxtls_return_t noxtls_x509_certificate_chain_add(x509_certificate_chain_t *chain, const x509_certificate_t *cert);
/** Grow the slot array to at least @p capacity slots (exact size; use before adding a known count). */
noxtls_return_t noxtls_x509_certificate_chain_reserve(x509_certificate_chain_t *chain, uint32_t capacity);
/** Parse DER straight into a new chain slot (one owned DER copy, no temporary certificate). */
noxtls_return_t noxtls_x509_certificate_chain_add_der(x509_certificate_chain_t *chain, const uint8_t *der, uint32_t der_len);
/**
 * Parse DER into a new chain slot in borrow mode (no copy): @p der must outlive the chain
 * (TLS Certificate message during verification, flash-resident CAs).
 */
noxtls_return_t noxtls_x509_certificate_chain_add_der_nocopy(x509_certificate_chain_t *chain, const uint8_t *der, uint32_t der_len);
noxtls_return_t noxtls_x509_certificate_chain_verify(const x509_certificate_chain_t *chain);
/**
 * Replace global trust store with a deep copy of provided trust anchors. Pass NULL or empty chain to clear.
 * The caller keeps ownership of @p trust_anchors and may free it right after the call.
 * The copy has exactly trust_anchors->count slots (one allocation of count * sizeof(x509_certificate_t))
 * plus one owned DER copy per anchor. To avoid the copy see noxtls_x509_trust_store_set_borrowed(),
 * noxtls_x509_trust_store_set_move() and noxtls_x509_trust_store_set_der_nocopy().
 * @note Snapshot lifetime: the store owns exactly one copy of the anchors. Each call (and
 *       noxtls_x509_trust_store_clear()) frees the previous copy before installing the new one, so
 *       repeated calls do not grow the heap. Verification functions that use the global store read it
 *       only for the duration of the call (TLS contexts do not cache it); the library has no internal
 *       locking, so do not call set/clear while another thread is inside
 *       noxtls_x509_verify_server_cert_trust*() / noxtls_x509_verify_client_cert_trust*() or a TLS
 *       handshake that verifies against the global store. Per-call anchors can instead be passed through
 *       noxtls_x509_verify_cert_with_policy(), whose lifetime the caller controls.
 *       On allocation failure the store is left empty (fail closed).
 */
noxtls_return_t noxtls_x509_trust_store_set(const x509_certificate_chain_t *trust_anchors);
/**
 * Use @p trust_anchors as the global trust store without copying it (0 bytes of heap). The chain
 * must stay valid and unchanged until the store is cleared or replaced. NULL or empty clears.
 */
noxtls_return_t noxtls_x509_trust_store_set_borrowed(const x509_certificate_chain_t *trust_anchors);
/**
 * Move @p trust_anchors into the global trust store (no copy, no allocation). On return the
 * caller's chain is empty; the store frees the certificates on clear/replace.
 */
noxtls_return_t noxtls_x509_trust_store_set_move(x509_certificate_chain_t *trust_anchors);
/**
 * Lightweight trust anchors over const DER (e.g. flash): parses @p count certificates in borrow
 * mode into one allocation of count * sizeof(x509_certificate_t); the DER is not copied and must
 * outlive the store.
 */
noxtls_return_t noxtls_x509_trust_store_set_der_nocopy(const uint8_t *const *ders, const uint32_t *lens, uint32_t count);
/** Clear global trust store used by noxtls_x509_verify_server_cert_trust and free its snapshot (see noxtls_x509_trust_store_set()). */
void noxtls_x509_trust_store_clear(void);
/** Return 1 when the global trust store has at least one configured trust anchor, 0 otherwise. */
int noxtls_x509_trust_store_has_anchors(void);
/**
 * Verify a server certificate against the configured trust store.
 * presented_chain contains intermediate issuers sent by peer (leaf not included); may be NULL.
 */
noxtls_return_t noxtls_x509_verify_server_cert_trust(const x509_certificate_t *leaf,
                                                     const x509_certificate_chain_t *presented_chain);
/**
 * Verify a server certificate against the configured trust store with optional CRL list.
 * When \p crl is NULL, behavior matches noxtls_x509_verify_server_cert_trust().
 * When \p crl is non-NULL, each CRL may be chained via \p crl->next; issuer DN must match a chain issuer
 * for revocation and CRL signature/time checks to apply.
 * @param flags_out optional; if non-NULL, cleared then ORed with NOXTLS_X509_VERIFY_FLAG_* bits.
 */
noxtls_return_t noxtls_x509_verify_server_cert_trust_ex(const x509_certificate_t *leaf,
                                                        const x509_certificate_chain_t *presented_chain,
                                                        const noxtls_x509_crl_t *crl,
                                                        noxtls_x509_verify_flags_t *flags_out);
/** Verify a client certificate (mTLS) against the configured trust store. */
noxtls_return_t noxtls_x509_verify_client_cert_trust(const x509_certificate_t *leaf,
                                                     const x509_certificate_chain_t *presented_chain);
/** Client certificate trust verification with optional CRL list (see noxtls_x509_verify_server_cert_trust_ex). */
noxtls_return_t noxtls_x509_verify_client_cert_trust_ex(const x509_certificate_t *leaf,
                                                         const x509_certificate_chain_t *presented_chain,
                                                         const noxtls_x509_crl_t *crl,
                                                         noxtls_x509_verify_flags_t *flags_out);

/** Time source for validity checks in noxtls_x509_verify_cert_with_policy(). */
typedef enum
{
    /** Use time(NULL) when NOXTLS_HAVE_TIME is 1; skip time checks when it is 0 (legacy behavior). */
    NOXTLS_X509_TIME_SYSTEM = 0,
    /** Check notBefore/notAfter against noxtls_x509_verify_policy_t::verify_time (needs NOXTLS_HAVE_TIME). */
    NOXTLS_X509_TIME_EXPLICIT = 1,
    /** Explicit clockless bootstrap: parse validity bounds but defer their
     * comparison with UTC. All signature, path and purpose checks still apply.
     * The application must reverify after obtaining UTC. CRLs are refused in
     * this mode because their freshness cannot be established. Never default. */
    NOXTLS_X509_TIME_DEFERRED = 2
} noxtls_x509_time_mode_t;

/**
 * Explicit, per-call certificate verification policy.
 *
 * Unlike noxtls_x509_verify_client_cert_trust(), the trust anchors are supplied
 * by the caller instead of the global trust store, so several independent
 * trust domains (for example a commissioning CA and a web PKI) can coexist.
 * Chain building and issuer checks follow RFC 5280 Section 6.1 as implemented
 * for the global store.
 */
typedef struct noxtls_x509_verify_policy
{
    /** Required, non-empty list of trust anchors (non-owning). */
    const x509_certificate_chain_t *trust_anchors;
    /** Optional CRL list (see noxtls_x509_verify_server_cert_trust_ex), or NULL. */
    const noxtls_x509_crl_t *crl;
    /** X509_EKU_* purpose the leaf must allow when it carries Extended Key Usage; 0 = no EKU constraint. */
    uint32_t required_eku;
    /** X509_KEY_USAGE_* bits that must all be set when the leaf carries Key Usage; 0 = purpose default (any-of). */
    uint16_t required_key_usage;
    /** 1 = reject a leaf without a Key Usage extension. */
    uint8_t require_key_usage_extension;
    /** Time source for certificate validity and CRL thisUpdate/nextUpdate freshness checks. */
    noxtls_x509_time_mode_t time_mode;
    /** Seconds since the Unix epoch used when time_mode is NOXTLS_X509_TIME_EXPLICIT. */
    int64_t verify_time;
} noxtls_x509_verify_policy_t;

/**
 * Check certificate validity at an explicit time (seconds since the Unix epoch).
 * Returns NOXTLS_RETURN_NOT_SUPPORTED when NOXTLS_HAVE_TIME is 0.
 */
noxtls_return_t noxtls_x509_certificate_check_validity_at(const x509_certificate_t *cert, int64_t now);

/**
 * Verify a leaf (plus optional peer-presented intermediates, leaf excluded)
 * against the trust anchors and leaf constraints in \p policy.
 * Fails closed with NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED when the policy has no anchors.
 * @param flags_out optional; cleared then ORed with NOXTLS_X509_VERIFY_FLAG_* bits.
 */
noxtls_return_t noxtls_x509_verify_cert_with_policy(const x509_certificate_t *leaf,
                                                    const x509_certificate_chain_t *presented_chain,
                                                    const noxtls_x509_verify_policy_t *policy,
                                                    noxtls_x509_verify_flags_t *flags_out);

/* Private key types (unsigned for Rule 10.3). */
typedef uint32_t x509_private_key_type_t;
#define X509_PRIVATE_KEY_RSA     ((x509_private_key_type_t)0U)  /* RSA private key */
#define X509_PRIVATE_KEY_ECC     ((x509_private_key_type_t)1U)  /* ECC private key */
#define X509_PRIVATE_KEY_ED25519 ((x509_private_key_type_t)2U)  /* RFC 8410 id-Ed25519, 32-byte seed */
#define X509_PRIVATE_KEY_ED448   ((x509_private_key_type_t)3U)  /* RFC 8410 id-Ed448, 57-byte seed */
#define X509_PRIVATE_KEY_ML_DSA  ((x509_private_key_type_t)4U)  /* NIST FIPS 204 ML-DSA */
#define X509_PRIVATE_KEY_SLH_DSA ((x509_private_key_type_t)5U)  /* NIST FIPS 205 SLH-DSA */
#define X509_PRIVATE_KEY_FALCON  ((x509_private_key_type_t)6U)  /* FALCON-512/1024 */

/* Private key format (unsigned for Rule 10.3). */
typedef uint32_t x509_private_key_format_t;
#define X509_PRIVATE_KEY_FORMAT_PKCS1 ((x509_private_key_format_t)0U)  /* PKCS#1 (RSA only) */
#define X509_PRIVATE_KEY_FORMAT_PKCS8 ((x509_private_key_format_t)1U)  /* PKCS#8 (RSA or ECC) */
#define X509_PRIVATE_KEY_FORMAT_SEC1  ((x509_private_key_format_t)2U)  /* SEC1 (ECC only) */

/* X.509 Private Key Structure */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    x509_private_key_type_t key_type;      /* RSA or ECC */
    x509_private_key_format_t format;       /* PKCS#1, PKCS#8, or SEC1 */

    /* RSA Private Key (if RSA) */
    uint8_t *rsa_modulus;                  /* n */
    uint32_t rsa_modulus_len;
    uint8_t *rsa_public_exponent;           /* e */
    uint32_t rsa_public_exponent_len;
    uint8_t *rsa_private_exponent;          /* d */
    uint32_t rsa_private_exponent_len;
    uint8_t *rsa_prime1;                    /* p */
    uint32_t rsa_prime1_len;
    uint8_t *rsa_prime2;                    /* q */
    uint32_t rsa_prime2_len;
    uint8_t *rsa_exponent1;                 /* d mod (p-1) */
    uint32_t rsa_exponent1_len;
    uint8_t *rsa_exponent2;                 /* d mod (q-1) */
    uint32_t rsa_exponent2_len;
    uint8_t *rsa_coefficient;               /* q^-1 mod p */
    uint32_t rsa_coefficient_len;

    /* ECC Private Key (if ECC) */
    uint8_t *ecc_private_key;               /* Private key scalar d */
    uint32_t ecc_private_key_len;
    uint8_t ecc_curve_oid[32];              /* Curve OID */
    uint32_t ecc_curve_oid_len;
    uint8_t *ecc_public_key;                /* Public key point (optional) */
    uint32_t ecc_public_key_len;

    /* Ed25519 / Ed448 RFC 8410 PKCS#8 seed (not used for RSA/ECC) */
    uint8_t *eddsa_seed;
    uint32_t eddsa_seed_len;

    /* Post-quantum (ML-DSA / SLH-DSA) raw secret key bytes (heap-allocated). */
    uint8_t *pqc_secret_key;
    uint32_t pqc_secret_key_len;
    /* Parameter set value (cast to noxtls_mldsa_param_t/noxtls_slhdsa_param_t/noxtls_falcon_param_t depending on key_type). */
    uint32_t pqc_param;

    /* Encryption info (if encrypted) */
    int encrypted;                           /* Whether key is encrypted */
    uint8_t encryption_algorithm_oid[32];   /* Encryption algorithm OID */
    uint32_t encryption_algorithm_oid_len;

    /* Raw private key data */
    uint8_t *raw_data;
    uint32_t raw_data_len;

    /* Parsed flag */
    int parsed;
} x509_private_key_t;
NOXTLS_MSVC_WARNING_POP

typedef struct {
    uint32_t salt_len;
    uint32_t iterations;
    uint32_t key_len;
} pbkdf2_sha1_params_t;

/* Private Key Functions */
noxtls_return_t noxtls_x509_private_key_init(x509_private_key_t *key);
noxtls_return_t noxtls_x509_private_key_free(x509_private_key_t *key);
noxtls_return_t noxtls_x509_private_key_parse_der(x509_private_key_t *key, const uint8_t *data, uint32_t len);
noxtls_return_t noxtls_x509_private_key_parse_der_with_password(x509_private_key_t *key, const uint8_t *data, uint32_t len,
                                                                  const uint8_t *password, uint32_t password_len);
noxtls_return_t noxtls_x509_private_key_parse_pem(x509_private_key_t *key, const uint8_t *data, uint32_t len);
noxtls_return_t noxtls_x509_private_key_parse_pem_with_password(x509_private_key_t *key, const uint8_t *data, uint32_t len,
                                                                  const uint8_t *password, uint32_t password_len);
noxtls_return_t noxtls_x509_private_key_load_file(x509_private_key_t *key, const uint8_t *filename);
noxtls_return_t noxtls_x509_private_key_to_rsa_key(const x509_private_key_t *key, void *rsa_key);  /* Convert to rsa_key_t */
noxtls_return_t noxtls_x509_private_key_to_ecc_key(const x509_private_key_t *key, ecc_key_t *ecc_key);   /* Convert to ecc_key_t */
noxtls_return_t x509_private_key_to_ecc_key(const x509_private_key_t *key, void *ecc_key);

/** When key_type is Ed25519 or Ed448, returns the raw PKCS#8 seed (32 or 57 bytes); otherwise NULL and *out_len is set to 0. */
const uint8_t *noxtls_x509_private_key_get_eddsa_seed(const x509_private_key_t *key, uint32_t *out_len);

/**
 * When key_type is ML-DSA or SLH-DSA, returns the raw PKCS#8 OCTET-STRING secret key bytes
 * (full expanded form per FIPS 204 / FIPS 205) and writes the parameter set value into @p out_param.
 * Returns NULL and sets both output lengths to 0 for non-PQC keys.
 */
const uint8_t *noxtls_x509_private_key_get_pqc_secret(const x509_private_key_t *key, uint32_t *out_len, uint32_t *out_param);

/**
 * High-level sign data with X.509 private key.
 * Key may be DER or PEM. Supports ECC (ECDSA DER) and Ed25519/Ed448 (raw 64- or 114-byte signature).
 * For Ed keys, hash_algo is ignored; the noxtls_message is signed with PureEdDSA (RFC 8032 / RFC 8410 certificates).
 * Output is ECDSA signature in DER form (SEQUENCE of two INTEGERs r, s) for ECC, or raw R||S for Ed.
 *
 * @param key       Private key bytes (DER or PEM)
 * @param key_len   Length of key buffer
 * @param data      Data to sign (e.g. hash or noxtls_message)
 * @param data_len  Length of data
 * @param hash_algo Hash used for ECDSA (e.g. NOXTLS_HASH_SHA_256)
 * @param out_der   Output buffer for DER signature
 * @param out_max   Size of out_der
 * @param out_len   On success, set to signature length in bytes
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t noxtls_x509_private_key_sign_data(const uint8_t *key, uint32_t key_len,
    const uint8_t *data, uint32_t data_len, noxtls_hash_algos_t hash_algo,
    uint8_t *out_der, uint32_t out_max, uint32_t *out_len);

/* Debug Functions */
noxtls_return_t noxtls_x509_certificate_debug_print(x509_certificate_t *cert, uint8_t verbose);
noxtls_return_t noxtls_x509_private_key_debug_print(x509_private_key_t *key, uint8_t verbose);
void noxtls_x509_debug_print_hex(const uint8_t *label, const uint8_t *data, uint32_t len, uint8_t verbose);
void noxtls_x509_debug_print_oid(const uint8_t *label, const uint8_t *oid_bytes, uint32_t oid_bytes_len);

/* Helper Functions */
noxtls_return_t noxtls_x509_parse_distinguished_name(const uint8_t *dn_data, uint32_t dn_len, uint8_t *output, uint32_t output_size);
/** Format an ASN.1 UTCTime/GeneralizedTime as "YYYY-MM-DD HH:MM:SS" (unrecognised forms are copied raw).
 *  The output is NUL-terminated whenever output_size > 0. Returns NOXTLS_RETURN_INVALID_PARAM when
 *  output_size is smaller than 20 bytes for a recognised time form, NOXTLS_RETURN_BAD_DATA for an
 *  unrepresentable year; output is then the empty string. */
noxtls_return_t noxtls_x509_parse_time(const uint8_t *time_data, uint32_t time_len, uint8_t *output, uint32_t output_size);
/** Parse certificate extensions (SAN, Key Usage, EKU, Basic Constraints, AKI, SKI, etc.) from cert->extensions. */
noxtls_return_t noxtls_x509_parse_extensions(x509_certificate_t *cert);
/**
 * @brief Enable or disable wildcard hostname matching at runtime.
 * @param enabled 1 to allow "*.example.com" matching, 0 to require exact DNS names.
 */
void noxtls_x509_set_hostname_wildcard_matching(int enabled);
/**
 * @brief Get current runtime wildcard hostname matching state.
 * @return 1 if wildcard DNS matching is enabled, 0 otherwise.
 */
int noxtls_x509_get_hostname_wildcard_matching(void);
/** Check whether certificate is valid for hostname (SAN dNSName or subject CN; case-insensitive). hostname_len may be 0 to use noxtls_u8_strlen(hostname). */
noxtls_return_t noxtls_x509_certificate_matches_hostname(const x509_certificate_t *cert, const uint8_t *hostname, uint32_t hostname_len);

/** RFC 5929 tls-server-end-point: get hash algorithm for hashing the server certificate. MD5/SHA-1 → SHA-256; else cert's signature hash. */
noxtls_return_t noxtls_x509_get_channel_binding_hash_algo(const x509_certificate_t *cert, noxtls_hash_algos_t *hash_algo);
/** Same as noxtls_x509_get_channel_binding_hash_algo() but read from certificate DER (ASN.1 walk, no parse). */
noxtls_return_t noxtls_x509_der_get_channel_binding_hash_algo(const uint8_t *der, uint32_t der_len,
                                                              noxtls_hash_algos_t *hash_algo);

/**
 * Callback for unknown/custom certificate extension OIDs during parsing.
 * oid/oid_len: extension OID (DER); value/value_len: extension value (octet string contents); critical: 1 if critical.
 * Return NOXTLS_RETURN_SUCCESS to accept (ignore), NOXTLS_RETURN_FAILED or NOXTLS_RETURN_BAD_DATA to reject (parsing fails if extension is critical).
 */
typedef noxtls_return_t (*noxtls_x509_unknown_ext_cb_t)(const uint8_t *ext_oid_bytes, uint32_t ext_oid_bytes_len, const uint8_t *ext_value_bytes, uint32_t ext_value_bytes_len, int ext_is_critical, void *ext_cb_ctx);
/** Set global callback for unknown extension OIDs. Pass NULL to clear. */
void noxtls_x509_set_unknown_extension_callback(noxtls_x509_unknown_ext_cb_t cb, void *ext_user_ctx);

#if NOXTLS_HAVE_CERT_WRITE
/* Certificate writing and generation (optional; enabled when NOXTLS_HAVE_CERT_WRITE is nonzero).
 * The generators encode straight into the caller's buffer (no heap workspace); out_max must cover
 * the result plus 32 bytes of encoding slack. */
noxtls_return_t noxtls_x509_certificate_write_der(const x509_certificate_t *cert, uint8_t *out, uint32_t out_max, uint32_t *out_len);
noxtls_return_t noxtls_x509_certificate_write_pem(const x509_certificate_t *cert, uint8_t *out, uint32_t out_max, uint32_t *out_len);
noxtls_return_t noxtls_x509_dn_from_cn(const uint8_t *cn, uint8_t *out, uint32_t out_max, uint32_t *out_len);
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
    uint8_t *out_der, uint32_t out_max, uint32_t *out_len);

/**
 * Extended self-signed certificate generator that accepts optional
 * AlgorithmIdentifier parameters for the subjectPublicKeyInfo.
 *
 * For EC keys (id-ecPublicKey), pass the DER-encoded namedCurve OID
 * (e.g. `06 08 2A 86 48 CE 3D 03 01 07` for prime256v1) as
 * @p subject_pk_params. For algorithms whose AlgorithmIdentifier has no
 * parameters (Ed25519, Ed448, ML-DSA, SLH-DSA) or where NULL is the
 * required parameter (RSA / PKCS#1), pass `NULL, 0` and the implementation
 * will emit the correct value.
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
    uint8_t *out_der, uint32_t out_max, uint32_t *out_len);
/**
 * Generate self-signed certificate with optional extensions (SAN dNSName, Key Usage).
 * san_dns may be NULL if san_dns_count is 0. key_usage_bits uses X509_KEY_USAGE_*; 0 = omit extension.
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
    uint8_t *out_der, uint32_t out_max, uint32_t *out_len);

/** Single custom extension for certificate generation (OID + value + critical flag). */
typedef struct {
    const uint8_t *oid;
    uint32_t oid_len;
    const uint8_t *value;
    uint32_t value_len;
    int critical;
} noxtls_x509_custom_ext_t;

/**
 * Generate self-signed certificate with full extensions (SAN, Key Usage, Basic Constraints, EKU, custom).
 * basic_constraints_ca: 0 = not CA, 1 = CA, negative = omit. basic_constraints_path_len: pathLenConstraint or X509_BC_PATH_LEN_ABSENT to omit.
 * ext_key_usage_bits: X509_EKU_* mask; 0 = omit. custom_exts may be NULL if custom_ext_count is 0.
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
    uint8_t *out_der, uint32_t out_max, uint32_t *out_len);
/**
 * Create a PKCS#10 Certificate Signing Request (CSR) in DER form.
 * subject_der: DER-encoded Name (e.g. from noxtls_x509_dn_from_cn).
 * subject_pk_oid / subject_pk: SubjectPublicKeyInfo algorithm OID and raw public key (e.g. ECC point).
 * sig_oid: signature algorithm OID (e.g. ecdsa-with-SHA256).
 * sign_key: private key (DER or PEM) used to sign the request; must be ECC (RSA not yet supported).
 */
noxtls_return_t noxtls_x509_csr_create_der(
    const uint8_t *subject_der, uint32_t subject_len,
    const uint8_t *subject_pk_oid, uint32_t subject_pk_oid_len,
    const uint8_t *subject_pk, uint32_t subject_pk_len,
    const uint8_t *sig_oid, uint32_t sig_oid_len,
    const uint8_t *sign_key, uint32_t sign_key_len,
    noxtls_hash_algos_t hash_algo,
    uint8_t *out_der, uint32_t out_max, uint32_t *out_len);
/**
 * Create a PKCS#10 CSR and encode as PEM.
 */
noxtls_return_t noxtls_x509_csr_create_pem(
    const uint8_t *subject_der, uint32_t subject_len,
    const uint8_t *subject_pk_oid, uint32_t subject_pk_oid_len,
    const uint8_t *subject_pk, uint32_t subject_pk_len,
    const uint8_t *sig_oid, uint32_t sig_oid_len,
    const uint8_t *sign_key, uint32_t sign_key_len,
    noxtls_hash_algos_t hash_algo,
    uint8_t *out_pem, uint32_t out_max, uint32_t *out_len);
#endif /* NOXTLS_HAVE_CERT_WRITE */

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_X509_H_ */

