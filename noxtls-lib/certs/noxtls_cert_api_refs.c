/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_cert_api_refs.c
* Summary: Second-TU references for public X.509/ASN.1 APIs (MISRA Rule 8.7).
*****************************************************************************/

#include <stdint.h>
#include "noxtls_misra_refs.h"

#include "asn1.h"
#include "oids.h"
#include "noxtls_x509.h"
/**
 * @brief Take addresses of public certificate APIs so they are referenced from a
 *        second translation unit (Rule 8.7) without changing behavior.
 */
static void noxtls_cert_misra_api_refs(void)
{
    NOXTLS_MISRA_REF_FN(&noxtls_asn1_put_ia5_string);
    NOXTLS_MISRA_REF_FN(&noxtls_asn1_put_length);
    NOXTLS_MISRA_REF_FN(&noxtls_parse_der);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_certificate_chain_verify);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_certificate_check_validity);
#if defined(NOXTLS_HAVE_CERT_WRITE) && (NOXTLS_HAVE_CERT_WRITE != 0)
    NOXTLS_MISRA_REF_FN(&noxtls_x509_certificate_generate_self_signed);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_certificate_generate_self_signed_ex);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_certificate_generate_self_signed_with_extensions);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_certificate_generate_self_signed_with_extensions_ex);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_csr_create_der);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_csr_create_pem);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_certificate_write_der);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_certificate_write_pem);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_dn_from_cn);
#endif
    NOXTLS_MISRA_REF_FN(&noxtls_x509_crl_free);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_crl_init);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_crl_load_file);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_crl_parse_der);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_crl_parse_pem);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_crl_serial_is_revoked);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_parse_distinguished_name);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_parse_time);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_private_key_free);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_private_key_init);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_private_key_parse_der);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_private_key_to_ecc_key);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_trust_store_clear);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_trust_store_set);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_verify_client_cert_trust);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_verify_server_cert_trust);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_certificate_debug_print);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_certificate_load_file);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_certificate_parse_pem);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_debug_print_hex);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_debug_print_oid);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_parse_extensions);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_private_key_get_eddsa_seed);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_private_key_get_pqc_secret);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_private_key_load_file);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_private_key_parse_pem);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_private_key_to_rsa_key);
    NOXTLS_MISRA_REF_FN(&x509_certificate_get_public_key);
    NOXTLS_MISRA_REF_FN(&x509_private_key_to_ecc_key);
    NOXTLS_MISRA_REF_FN(&noxtls_cert_verify_failure_clear);
    NOXTLS_MISRA_REF_FN(&noxtls_cert_verify_failure_get);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_set_unknown_extension_callback);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_set_hostname_wildcard_matching);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_get_hostname_wildcard_matching);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_private_key_parse_der_with_password);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_private_key_parse_pem_with_password);
    NOXTLS_MISRA_REF_FN(&noxtls_x509_private_key_debug_print);
    { uint32_t v = (uint32_t)GET_TAG_NUM(0x30U); (void)v; }
    { uint32_t v = (uint32_t)GET_LENGTH(0x82U); (void)v; }
    { uint32_t v = (uint32_t)X509_SAN_IP_IS_V6_BIT; (void)v; }
    { uint32_t v = (uint32_t)X509_KEY_USAGE_NON_REPUDIATION; (void)v; }
    { uint32_t v = (uint32_t)X509_KEY_USAGE_DATA_ENCIPHERMENT; (void)v; }
    { uint32_t v = (uint32_t)X509_KEY_USAGE_ENCIPHER_ONLY; (void)v; }
    { uint32_t v = (uint32_t)X509_KEY_USAGE_DECIPHER_ONLY; (void)v; }
    NOXTLS_MISRA_REF_OBJ(base_oids);
}

/* Keep refs TU live for analyzers without exporting linkage (Rule 8.7). */
NOXTLS_MISRA_KEEP static void noxtls_cert_misra_api_refs_keep(void)
{
    noxtls_cert_misra_api_refs();
    (void)(NOXTLS_X509_VERIFY_FLAG_CRL_EXPIRED);
}
