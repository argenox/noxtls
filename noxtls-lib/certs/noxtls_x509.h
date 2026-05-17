/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
*
* NOTICE:  All information contained herein, source code, binaries and
* derived works is, and remains
* the property of Argenox Technologies and its suppliers,
* if any.  The intellectual and technical concepts contained
* herein are proprietary to Argenox Technologies
* and its suppliers may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Argenox Technologies.
*
* THIS SOFTWARE IS PROVIDED BY ARGENOX "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL ARGENOX TECHNOLOGIES LLC BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
* CONTACT: info@argenox.com
*
*
* File:    noxtls_x509.h
* Summary: X.509 Certificate Parsing and Validation
*
*/

/**
 * @defgroup noxtls_certs Certificates and X.509
 * @brief ASN.1, certificate parsing (DER/PEM), and X.509 APIs.
 * @addtogroup noxtls
 */
/** @{ */

#ifndef _NOXTLS_X509_H_
#define _NOXTLS_X509_H_

#include <stdint.h>
#include "noxtls_common.h"
#include "pkc/ecc/noxtls_ecc.h"
#include "pkc/mldsa/noxtls_mldsa.h"
#include "mdigest/noxtls_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum certificate size */
#define X509_MAX_CERT_SIZE        NOXTLS_MAX_CERT_SIZE
/* CRLs can be larger than individual certificates (many revoked entries). */
#define X509_MAX_CRL_SIZE         (X509_MAX_CERT_SIZE * 16U)
#define X509_MAX_SUBJECT_SIZE     512
#define X509_MAX_ISSUER_SIZE      512
#define X509_MAX_SERIAL_SIZE      32
#define X509_MAX_PUBLIC_KEY_SIZE  2048
#define X509_MAX_PRIVATE_KEY_SIZE 4096
/* RSA modulus n length in bytes for standard key sizes (1024/2048/3072/4096-bit). DER INTEGER may use this length or one more byte (leading zero). */
#define X509_RSA_MODULUS_BYTES_1024  128U
#define X509_RSA_MODULUS_BYTES_2048  256U
#define X509_RSA_MODULUS_BYTES_3072  384U
#define X509_RSA_MODULUS_BYTES_4096  512U
/* Parsed extensions: Subject Alternative Name (SAN) */
#define X509_SAN_DNS_MAX          8
#define X509_SAN_DNS_LEN          256
#define X509_SAN_EMAIL_MAX        4
#define X509_SAN_EMAIL_LEN        256
#define X509_SAN_URI_MAX          4
#define X509_SAN_URI_LEN          256
#define X509_SAN_IP_MAX           4
#define X509_SAN_IP_BYTES         16   /* IPv4 or IPv6 */
#define X509_SAN_IP_IS_V6_BIT     0x80 /* flag in stored entry: high bit of first byte of length */
#define X509_HOSTNAME_WILDCARD_PREFIX "*."
#define X509_HOSTNAME_WILDCARD_PREFIX_LEN 2U
/* Key Usage bits (RFC 5280): bit 0 = digitalSignature, 1 = nonRepudiation, 2 = keyEncipherment, 3 = dataEncipherment, 4 = keyAgreement, 5 = keyCertSign, 6 = cRLSign, 7 = encipherOnly, 8 = decipherOnly */
#define X509_KEY_USAGE_DIGITAL_SIGNATURE    (1u << 0)
#define X509_KEY_USAGE_NON_REPUDIATION     (1u << 1)
#define X509_KEY_USAGE_KEY_ENCIPHERMENT    (1u << 2)
#define X509_KEY_USAGE_DATA_ENCIPHERMENT   (1u << 3)
#define X509_KEY_USAGE_KEY_AGREEMENT       (1u << 4)
#define X509_KEY_USAGE_KEY_CERT_SIGN       (1u << 5)
#define X509_KEY_USAGE_CRL_SIGN            (1u << 6)
#define X509_KEY_USAGE_ENCIPHER_ONLY       (1u << 7)
#define X509_KEY_USAGE_DECIPHER_ONLY       (1u << 8)
/* Extended Key Usage bits (RFC 5280 id-kp-*): serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, OCSPSigning, anyExtendedKeyUsage */
#define X509_EKU_SERVER_AUTH       (1u << 0)
#define X509_EKU_CLIENT_AUTH       (1u << 1)
#define X509_EKU_CODE_SIGNING      (1u << 2)
#define X509_EKU_EMAIL_PROTECTION  (1u << 3)
#define X509_EKU_TIME_STAMPING     (1u << 4)
#define X509_EKU_OCSP_SIGNING      (1u << 5)
#define X509_EKU_ANY               (1u << 6)
/* Basic Constraints path length: use -1 or 0xFFFF when not present */
#define X509_BC_PATH_LEN_ABSENT   (-1)
/* Authority/Subject Key Identifier max stored length */
#define X509_KEY_ID_MAX_LEN        32

/** Maximum revoked serial entries stored when parsing a CRL (larger CRLs fail parse). */
#define NOXTLS_X509_CRL_MAX_REVOKED 2048U

/**
 * @brief Bitmask for optional X.509 verification details (mbedTLS-style flags).
 * @details Set by noxtls_x509_verify_*_ex when \p flags_out is non-NULL. Bits are ORed on failure paths
 *          and may be set on success (e.g. CRL matched and checked).
 */
typedef uint32_t noxtls_x509_verify_flags_t;
/** Certificate serial matched a revoked entry on an applicable CRL. */
#define NOXTLS_X509_VERIFY_FLAG_CERT_REVOKED       (1u << 0)
/** CRL nextUpdate is present and current time is past nextUpdate (strict stale policy). */
#define NOXTLS_X509_VERIFY_FLAG_CRL_EXPIRED        (1u << 1)
/** CRL signature verification against the issuer failed. */
#define NOXTLS_X509_VERIFY_FLAG_CRL_BAD_SIGNATURE  (1u << 2)
/** A CRL was supplied but no CRL in the list matched any issuer in the validated chain (informational). */
#define NOXTLS_X509_VERIFY_FLAG_CRL_NO_MATCH       (1u << 3)
/** At least one supplied CRL matched an issuer DN and was evaluated (signature/time/revocation). */
#define NOXTLS_X509_VERIFY_FLAG_CRL_USED           (1u << 4)

/* X.509 Certificate Structure */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    /* Certificate version */
    uint8_t version;  /* 0 = v1, 1 = v2, 2 = v3 */

    /* Serial number */
    uint8_t serial_number[X509_MAX_SERIAL_SIZE];
    uint32_t serial_number_len;

    /* Signature algorithm OID */
    uint8_t signature_algorithm_oid[32];
    uint32_t signature_algorithm_oid_len;

    /* Issuer */
    uint8_t issuer[X509_MAX_ISSUER_SIZE];
    uint32_t issuer_len;
    char issuer_dn[256];  /* Human-readable Distinguished Name */

    /* Validity */
    uint8_t not_before[15];  /* ASN.1 GeneralizedTime or UTCTime */
    uint8_t not_after[15];

    /* Subject */
    uint8_t subject[X509_MAX_SUBJECT_SIZE];
    uint32_t subject_len;
    char subject_dn[256];  /* Human-readable Distinguished Name */

    /* Subject Public Key Info */
    uint8_t public_key_algorithm_oid[32];
    uint32_t public_key_algorithm_oid_len;
    uint8_t public_key[X509_MAX_PUBLIC_KEY_SIZE];
    uint32_t public_key_len;

    /* RSA Public Key (if RSA) */
    uint8_t *rsa_modulus;
    uint32_t rsa_modulus_len;
    uint8_t *rsa_exponent;
    uint32_t rsa_exponent_len;

    /* ECC Public Key (if ECC) */
    uint8_t *ecc_public_key;
    uint32_t ecc_public_key_len;
    uint8_t ecc_curve_oid[32];
    uint32_t ecc_curve_oid_len;

    /* Ed25519 Public Key (if Ed25519, OID 1.3.101.112) */
    uint8_t ed25519_public_key[32];
    uint8_t has_ed25519;  /* 1 if subject public key is Ed25519 */

    /* Ed448 Public Key (if Ed448, OID 1.3.101.113 id-Ed448) */
    uint8_t ed448_public_key[57];
    uint8_t has_ed448;

    /* ML-DSA public key (if present; private-use parser support for PQ cert experiments). */
    uint8_t mldsa_public_key[NOXTLS_MLDSA_MAX_PUBLIC_KEY_LEN];
    uint32_t mldsa_public_key_len;
    noxtls_mldsa_param_t mldsa_param;
    uint8_t has_mldsa;

    /* Extensions (v3) */
    uint8_t *extensions;
    uint32_t extensions_len;
    /* Parsed: Subject Alternative Name */
    uint8_t san_dns_count;
    char san_dns_names[X509_SAN_DNS_MAX][X509_SAN_DNS_LEN];
    uint8_t san_email_count;
    char san_emails[X509_SAN_EMAIL_MAX][X509_SAN_EMAIL_LEN];
    uint8_t san_uri_count;
    char san_uris[X509_SAN_URI_MAX][X509_SAN_URI_LEN];
    uint8_t san_ip_count;
    uint8_t san_ip_len[X509_SAN_IP_MAX];  /* 4 or 16 */
    uint8_t san_ips[X509_SAN_IP_MAX][X509_SAN_IP_BYTES];
    /* Parsed: Key Usage (bitmask, X509_KEY_USAGE_*); 0 = not present */
    uint16_t key_usage_bits;
    /* Parsed: Extended Key Usage (X509_EKU_*); 0 = not present */
    uint32_t ext_key_usage_bits;
    /* Parsed: Basic Constraints */
    int basic_constraints_ca;           /* 0 = not CA, 1 = CA, -1 = extension absent */
    int basic_constraints_path_len;     /* pathLenConstraint or X509_BC_PATH_LEN_ABSENT */
    /* Parsed: Authority Key Identifier (keyIdentifier octets) */
    uint8_t authority_key_id[X509_KEY_ID_MAX_LEN];
    uint8_t authority_key_id_len;       /* 0 = absent */
    /* Parsed: Subject Key Identifier */
    uint8_t subject_key_id[X509_KEY_ID_MAX_LEN];
    uint8_t subject_key_id_len;        /* 0 = absent */

    /* Signature */
    uint8_t *signature;
    uint32_t signature_len;

    /* Raw certificate data */
    uint8_t *raw_data;
    uint32_t raw_data_len;

    /* TBSCertificate (the part that's signed) */
    uint8_t *tbs_certificate;
    uint32_t tbs_certificate_len;

    /* Parsed flag */
    int parsed;
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
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct noxtls_x509_crl
{
    uint8_t issuer[X509_MAX_ISSUER_SIZE];
    uint32_t issuer_len;
    char issuer_dn[256];
    uint8_t this_update[16];
    uint8_t next_update[16];
    uint8_t has_next_update;
    uint8_t signature_algorithm_oid[32];
    uint32_t signature_algorithm_oid_len;
    uint8_t *signature;
    uint32_t signature_len;
    uint8_t *tbs_crl;
    uint32_t tbs_crl_len;
    uint8_t *raw_data;
    uint32_t raw_data_len;
    uint8_t *revoked_serials;
    uint32_t *revoked_serial_lens;
    uint32_t revoked_count;
    int parsed;
    struct noxtls_x509_crl *next;
} noxtls_x509_crl_t;
NOXTLS_MSVC_WARNING_POP

noxtls_return_t noxtls_x509_crl_init(noxtls_x509_crl_t *crl);
/** Free this CRL and any linked CRLs in \p next. */
void noxtls_x509_crl_free(noxtls_x509_crl_t *crl);
noxtls_return_t noxtls_x509_crl_parse_der(noxtls_x509_crl_t *crl, const uint8_t *data, uint32_t len);
noxtls_return_t noxtls_x509_crl_parse_pem(noxtls_x509_crl_t *crl, const uint8_t *data, uint32_t len);
noxtls_return_t noxtls_x509_crl_load_file(noxtls_x509_crl_t *crl, const char *filename);

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
	char not_before[NOXTLS_CERT_FAIL_TIME_MAX];   /**< Certificate notBefore (ASN.1 time string). Set on time/validity failures. */
	char not_after[NOXTLS_CERT_FAIL_TIME_MAX];    /**< Certificate notAfter (ASN.1 time string). Set on time/validity failures. */
	char subject_dn[NOXTLS_CERT_FAIL_DN_HOSTNAME_MAX]; /**< Subject DN of the certificate that failed. */
	char expected_hostname[NOXTLS_CERT_FAIL_DN_HOSTNAME_MAX]; /**< Expected hostname (on hostname mismatch). */
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
noxtls_return_t noxtls_x509_certificate_load_file(x509_certificate_t *cert, const char *filename);
noxtls_return_t noxtls_x509_certificate_verify_signature(x509_certificate_t *cert, const x509_certificate_t *issuer);
noxtls_return_t noxtls_x509_certificate_check_validity(const x509_certificate_t *cert);
noxtls_return_t noxtls_x509_certificate_get_public_key(const x509_certificate_t *cert, void **key, uint32_t *key_type);

/* X.509 Certificate Chain Functions */
noxtls_return_t noxtls_x509_certificate_chain_init(x509_certificate_chain_t *chain);
noxtls_return_t noxtls_x509_certificate_chain_free(x509_certificate_chain_t *chain);
noxtls_return_t noxtls_x509_certificate_chain_add(x509_certificate_chain_t *chain, const x509_certificate_t *cert);
noxtls_return_t noxtls_x509_certificate_chain_verify(x509_certificate_chain_t *chain);
/** Replace global trust store with a deep copy of provided trust anchors. Pass NULL or empty chain to clear. */
noxtls_return_t noxtls_x509_trust_store_set(const x509_certificate_chain_t *trust_anchors);
/** Clear global trust store used by noxtls_x509_verify_server_cert_trust. */
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

/* Private Key Types */
typedef enum
{
    X509_PRIVATE_KEY_RSA,       /* RSA private key */
    X509_PRIVATE_KEY_ECC,       /* ECC private key */
    X509_PRIVATE_KEY_ED25519,   /* RFC 8410 id-Ed25519, 32-byte seed */
    X509_PRIVATE_KEY_ED448      /* RFC 8410 id-Ed448, 57-byte seed */
} x509_private_key_type_t;

/* Private Key Format */
typedef enum
{
    X509_PRIVATE_KEY_FORMAT_PKCS1,  /* PKCS#1 (RSA only) */
    X509_PRIVATE_KEY_FORMAT_PKCS8,  /* PKCS#8 (RSA or ECC) */
    X509_PRIVATE_KEY_FORMAT_SEC1    /* SEC1 (ECC only) */
} x509_private_key_format_t;

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

typedef struct pbkdf2_sha1_params_t {
    uint32_t salt_len;
    uint32_t iterations;
    uint32_t key_len;
} pbkdf2_sha1_params_t;

/* Private Key Functions */
noxtls_return_t noxtls_x509_private_key_init(x509_private_key_t *key);
noxtls_return_t noxtls_x509_private_key_free(x509_private_key_t *key);
noxtls_return_t noxtls_x509_private_key_parse_der(x509_private_key_t *key, const uint8_t *data, uint32_t len);
noxtls_return_t noxtls_x509_private_key_parse_der_with_password(x509_private_key_t *key, const uint8_t *data, uint32_t len,
                                                                  const char *password, uint32_t password_len);
noxtls_return_t noxtls_x509_private_key_parse_pem(x509_private_key_t *key, const uint8_t *data, uint32_t len);
noxtls_return_t noxtls_x509_private_key_parse_pem_with_password(x509_private_key_t *key, const uint8_t *data, uint32_t len,
                                                                  const char *password, uint32_t password_len);
noxtls_return_t noxtls_x509_private_key_load_file(x509_private_key_t *key, const char *filename);
noxtls_return_t noxtls_x509_private_key_to_rsa_key(const x509_private_key_t *key, void *rsa_key);  /* Convert to rsa_key_t */
noxtls_return_t noxtls_x509_private_key_to_ecc_key(const x509_private_key_t *key, ecc_key_t *ecc_key);   /* Convert to ecc_key_t */

/** When key_type is Ed25519 or Ed448, returns the raw PKCS#8 seed (32 or 57 bytes); otherwise NULL and *out_len is set to 0. */
const uint8_t *noxtls_x509_private_key_get_eddsa_seed(const x509_private_key_t *key, uint32_t *out_len);

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
void noxtls_x509_debug_print_hex(const char *label, const uint8_t *data, uint32_t len, uint8_t verbose);
void noxtls_x509_debug_print_oid(const char *label, const uint8_t *oid, uint32_t oid_len);

/* Helper Functions */
noxtls_return_t noxtls_x509_parse_distinguished_name(const uint8_t *dn_data, uint32_t dn_len, char *output, uint32_t output_size);
noxtls_return_t noxtls_x509_parse_time(const uint8_t *time_data, uint32_t time_len, char *output, uint32_t output_size);
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
/** Check whether certificate is valid for hostname (SAN dNSName or subject CN; case-insensitive). hostname_len may be 0 to use strlen(hostname). */
noxtls_return_t noxtls_x509_certificate_matches_hostname(const x509_certificate_t *cert, const char *hostname, uint32_t hostname_len);

/** RFC 5929 tls-server-end-point: get hash algorithm for hashing the server certificate. MD5/SHA-1 → SHA-256; else cert's signature hash. */
noxtls_return_t noxtls_x509_get_channel_binding_hash_algo(const x509_certificate_t *cert, noxtls_hash_algos_t *hash_algo);

/**
 * Callback for unknown/custom certificate extension OIDs during parsing.
 * oid/oid_len: extension OID (DER); value/value_len: extension value (octet string contents); critical: 1 if critical.
 * Return NOXTLS_RETURN_SUCCESS to accept (ignore), NOXTLS_RETURN_FAILED or NOXTLS_RETURN_BAD_DATA to reject (parsing fails if extension is critical).
 */
typedef noxtls_return_t (*noxtls_x509_unknown_ext_cb_t)(const uint8_t *oid, uint32_t oid_len, const uint8_t *value, uint32_t value_len, int critical, void *user_ctx);
/** Set global callback for unknown extension OIDs. Pass NULL to clear. */
void noxtls_x509_set_unknown_extension_callback(noxtls_x509_unknown_ext_cb_t cb, void *user_ctx);

#ifdef NOXTLS_HAVE_CERT_WRITE
/* Certificate writing and generation (optional; enable with NOXTLS_HAVE_CERT_WRITE) */
noxtls_return_t noxtls_x509_certificate_write_der(const x509_certificate_t *cert, uint8_t *out, uint32_t out_max, uint32_t *out_len);
noxtls_return_t noxtls_x509_certificate_write_pem(const x509_certificate_t *cert, uint8_t *out, uint32_t out_max, uint32_t *out_len);
noxtls_return_t noxtls_x509_dn_from_cn(const char *cn, uint8_t *out, uint32_t out_max, uint32_t *out_len);
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
    uint8_t *out_der, uint32_t out_max, uint32_t *out_len);
/**
 * Generate self-signed certificate with optional extensions (SAN dNSName, Key Usage).
 * san_dns may be NULL if san_dns_count is 0. key_usage_bits uses X509_KEY_USAGE_*; 0 = omit extension.
 */
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

#endif /* _NOXTLS_X509_H_ */

