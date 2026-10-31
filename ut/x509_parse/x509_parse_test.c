/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
* Licensed under the GNU General Public License v2.0 or later,
* or alternatively under a commercial license from Argenox Technologies LLC.
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
* File:    x509_parse_test.c
* Summary: X.509 certificate / CRL parsing, field, chain and writer regression tests
*****************************************************************************/
/** @file x509_parse_test.c
 * @brief Pins the observable behaviour of the X.509 module before its
 * certificate structure is reworked: every field the library and the
 * applications read, hostname rules, validity, signatures, public keys, chain
 * and trust-store verification with 1 and 3 anchors, CRLs, the certificate
 * and CSR writers, and malformed input.
 *
 * All direct x509_certificate_t / noxtls_x509_crl_t field reads are isolated
 * in the xf_* helpers below so a structure change only has to update them.
 */
#include "lb_fixture.h"

#include <stdlib.h>
#include <string.h>

#include "pkc/ecdsa/noxtls_ecdsa.h"
#include "pkc/rsa/noxtls_rsa.h"
#include "base64.h"

#ifndef NOXTLS_HAVE_TIME
#define NOXTLS_HAVE_TIME 1
#endif

/* Midpoint of the PKI validity window: 2037-01-01T00:00:00Z. */
#define T_VALID 2114380800LL

static x509_certificate_t s_root;
static x509_certificate_t s_int;
static x509_certificate_t s_leaf;
static x509_certificate_t s_tmp;
static x509_certificate_t s_tmp2;
static x509_certificate_t s_chain_tmp;  /* scratch for chain_of() only */
static x509_certificate_t s_verify_tmp; /* scratch for verify_server() only */
static uint8_t s_buf[32768U];

/* ------------------------------------------------------------------------- */
/* Struct field access (x509_certificate_t / noxtls_x509_crl_t)              */
/* Update these when the certificate structure becomes span-based.           */
/* ------------------------------------------------------------------------- */

static int xf_version(const x509_certificate_t *c) { return (int)c->version; }

static int xf_serial_eq(const x509_certificate_t *c, uint32_t serial)
{
    uint8_t be[4];
    uint32_t n = 0U;
    uint32_t i;
    /* Minimal big-endian encoding of a positive serial without a sign byte. */
    for(i = 0U; i < 4U; i++) {
        uint8_t b = (uint8_t)(serial >> (24U - (8U * i)));
        if((n > 0U) || (b != 0U)) {
            be[n] = b;
            n++;
        }
    }
    if((be[0] & 0x80U) != 0U) {
        return 0; /* not used by this PKI */
    }
    return ((c->serial_number_len == n) && (memcmp(c->serial_number, be, n) == 0)) ? 1 : 0;
}

/** Compare the subject with a full Name DER (SEQUENCE header included); the struct keeps
 *  only the SEQUENCE contents. */
static int xf_subject_eq(const x509_certificate_t *c, const uint8_t *der, uint32_t len)
{
    uint32_t hdr = 2U;
    if((len < 2U) || (der[0] != 0x30U)) {
        return 0;
    }
    if((der[1] & 0x80U) != 0U) {
        hdr = 2U + (uint32_t)(der[1] & 0x7FU);
    }
    if(hdr > len) {
        return 0;
    }
    return ((c->subject_len == (len - hdr)) && (memcmp(c->subject, &der[hdr], len - hdr) == 0)) ? 1 : 0;
}

static int xf_issuer_eq_subject(const x509_certificate_t *child, const x509_certificate_t *parent)
{
    return ((child->issuer_len == parent->subject_len) &&
            (memcmp(child->issuer, parent->subject, child->issuer_len) == 0)) ? 1 : 0;
}

/* DN text and SAN names are rendered on demand from the DER (accessor API). */
static char s_xf_text[2][256];
static const char *xf_subject_dn(const x509_certificate_t *c)
{
    s_xf_text[0][0] = 0;
    (void)noxtls_x509_certificate_get_subject_dn(c, (uint8_t *)s_xf_text[0], sizeof(s_xf_text[0]));
    return s_xf_text[0];
}
static const char *xf_issuer_dn(const x509_certificate_t *c)
{
    s_xf_text[1][0] = 0;
    (void)noxtls_x509_certificate_get_issuer_dn(c, (uint8_t *)s_xf_text[1], sizeof(s_xf_text[1]));
    return s_xf_text[1];
}
static const uint8_t *xf_not_before(const x509_certificate_t *c, uint32_t *len)
{
    const uint8_t *t = NULL;
    *len = 0U;
    (void)noxtls_x509_certificate_get_validity_raw(c, &t, len, NULL, NULL);
    return t;
}
static const uint8_t *xf_not_after(const x509_certificate_t *c, uint32_t *len)
{
    const uint8_t *t = NULL;
    *len = 0U;
    (void)noxtls_x509_certificate_get_validity_raw(c, NULL, NULL, &t, len);
    return t;
}
static uint32_t xf_san_count(const x509_certificate_t *c)
{
    uint32_t n = noxtls_x509_certificate_san_count(c, NOXTLS_X509_SAN_DNS);
    /* The parse-time count of non-empty dNSNames must agree with the iterator. */
    return (n == (uint32_t)c->san_dns_count) ? n : 0xFFFFFFFFU;
}
static const char *xf_san(const x509_certificate_t *c, uint32_t i)
{
    static char name[256];
    const uint8_t *v = NULL;
    uint32_t v_len = 0U;
    name[0] = 0;
    if((noxtls_x509_certificate_get_san(c, NOXTLS_X509_SAN_DNS, i, &v, &v_len) == NOXTLS_RETURN_SUCCESS) &&
       (v_len < sizeof(name))) {
        memcpy(name, v, v_len);
        name[v_len] = 0;
    }
    return name;
}
static uint32_t xf_key_usage(const x509_certificate_t *c) { return c->key_usage_bits; }
static uint32_t xf_eku(const x509_certificate_t *c) { return c->ext_key_usage_bits; }
static int xf_bc_ca(const x509_certificate_t *c) { return c->basic_constraints_ca; }
static int xf_bc_path_len(const x509_certificate_t *c) { return c->basic_constraints_path_len; }

static int xf_ski_eq(const x509_certificate_t *c, const uint8_t *v, uint32_t len)
{
    return ((c->subject_key_id_len == len) && (memcmp(c->subject_key_id, v, len) == 0)) ? 1 : 0;
}

static int xf_aki_eq(const x509_certificate_t *c, const uint8_t *v, uint32_t len)
{
    return ((c->authority_key_id_len == len) && (memcmp(c->authority_key_id, v, len) == 0)) ? 1 : 0;
}

static int xf_ec_point_eq(const x509_certificate_t *c, const uint8_t *v, uint32_t len)
{
    return ((c->ecc_public_key_len == len) && (memcmp(c->ecc_public_key, v, len) == 0)) ? 1 : 0;
}

static int xf_rsa_modulus_eq(const x509_certificate_t *c, const uint8_t *v, uint32_t len)
{
    const uint8_t *n = c->rsa_modulus;
    uint32_t n_len = c->rsa_modulus_len;
    while((n_len > len) && (n[0] == 0U)) {
        n++;
        n_len--;
    }
    return ((n_len == len) && (memcmp(n, v, len) == 0)) ? 1 : 0;
}

static int xf_rsa_exponent_is_65537(const x509_certificate_t *c)
{
    static const uint8_t e[] = { 0x01U, 0x00U, 0x01U };
    return ((c->rsa_exponent_len == 3U) && (memcmp(c->rsa_exponent, e, 3U) == 0)) ? 1 : 0;
}

static int xf_ed25519_eq(const x509_certificate_t *c, const uint8_t *v)
{
    return ((c->has_ed25519 != 0U) && (memcmp(c->ed25519_public_key, v, 32U) == 0)) ? 1 : 0;
}

static int xf_parsed(const x509_certificate_t *c) { return c->parsed; }
static uint32_t xf_chain_count(const x509_certificate_chain_t *chain) { return chain->count; }
static const x509_certificate_t *xf_chain_cert(const x509_certificate_chain_t *chain, uint32_t i)
{
    return &chain->certs[i];
}
static uint32_t xf_crl_count(const noxtls_x509_crl_t *crl) { return crl->revoked_count; }
static int xf_crl_issuer_eq(const noxtls_x509_crl_t *crl, const x509_certificate_t *issuer)
{
    return ((crl->issuer_len == issuer->subject_len) &&
            (memcmp(crl->issuer, issuer->subject, crl->issuer_len) == 0)) ? 1 : 0;
}

/* ------------------------------------------------------------------------- */
/* Helpers                                                                   */
/* ------------------------------------------------------------------------- */

static const uint8_t *memmem_compat(const uint8_t *hay, uint32_t hay_len, const char *needle, uint32_t n)
{
    uint32_t i;
    for(i = 0U; (i + n) <= hay_len; i++) {
        if(memcmp(&hay[i], needle, n) == 0) {
            return &hay[i];
        }
    }
    return NULL;
}

static int parse(x509_certificate_t *c, const uint8_t *der, uint32_t len)
{
    (void)noxtls_x509_certificate_init(c);
    return (noxtls_x509_certificate_parse_der(c, der, len) == NOXTLS_RETURN_SUCCESS) ? 0 : 1;
}

static int parse_pem(x509_certificate_t *c, const uint8_t *pem, uint32_t len)
{
    (void)noxtls_x509_certificate_init(c);
    return (noxtls_x509_certificate_parse_pem(c, pem, len) == NOXTLS_RETURN_SUCCESS) ? 0 : 1;
}

static int parse_ec_chain(void)
{
    LB_RUN(parse(&s_root, lb_ec_root_cert, lb_ec_root_cert_len));
    LB_RUN(parse(&s_int, lb_ec_int_cert, lb_ec_int_cert_len));
    LB_RUN(parse(&s_leaf, lb_ec_server_cert, lb_ec_server_cert_len));
    return 0;
}

static void free_ec_chain(void)
{
    (void)noxtls_x509_certificate_free(&s_root);
    (void)noxtls_x509_certificate_free(&s_int);
    (void)noxtls_x509_certificate_free(&s_leaf);
}

static int chain_of(x509_certificate_chain_t *chain, const uint8_t *const *ders, const uint32_t *lens, uint32_t n)
{
    uint32_t i;
    LB_CHECK_OK(noxtls_x509_certificate_chain_init(chain));
    for(i = 0U; i < n; i++) {
        LB_RUN(parse(&s_chain_tmp, ders[i], lens[i]));
        LB_CHECK_OK(noxtls_x509_certificate_chain_add(chain, &s_chain_tmp));
        (void)noxtls_x509_certificate_free(&s_chain_tmp);
    }
    return 0;
}

static noxtls_return_t verify_server(const uint8_t *der, uint32_t len, const x509_certificate_chain_t *presented)
{
    noxtls_return_t rc;
    if(parse(&s_verify_tmp, der, len) != 0) {
        return NOXTLS_RETURN_CERT_PARSE_FAILED;
    }
    rc = noxtls_x509_verify_server_cert_trust(&s_verify_tmp, presented);
    (void)noxtls_x509_certificate_free(&s_verify_tmp);
    return rc;
}

/* ------------------------------------------------------------------------- */
/* Tests                                                                     */
/* ------------------------------------------------------------------------- */

static int t_ec_chain_fields(void)
{
    size_t base = lb_alloc_live_bytes();
    uint8_t text[64];
    LB_RUN(parse_ec_chain());
    LB_CHECK(xf_parsed(&s_leaf) != 0);
    LB_CHECK_EQ(xf_version(&s_leaf), 2);
    LB_CHECK(xf_serial_eq(&s_leaf, LB_PKI_SERIAL_EC_SERVER));
    /* Subject / issuer DER and the issuer chain. */
    LB_CHECK(xf_subject_eq(&s_leaf, lb_ec_server_subject_der, lb_ec_server_subject_der_len));
    LB_CHECK(xf_subject_eq(&s_int, lb_ec_int_subject_der, lb_ec_int_subject_der_len));
    LB_CHECK(xf_issuer_eq_subject(&s_leaf, &s_int));
    LB_CHECK(xf_issuer_eq_subject(&s_int, &s_root));
    LB_CHECK(xf_issuer_eq_subject(&s_root, &s_root));
    LB_CHECK(!xf_issuer_eq_subject(&s_leaf, &s_root));
    /* Rendered DN strings (fail info, apps/cert). */
    LB_CHECK(strstr(xf_subject_dn(&s_leaf), "server.test") != NULL);
    LB_CHECK(strstr(xf_subject_dn(&s_leaf), "NoxTLS Test") != NULL);
    LB_CHECK(strstr(xf_issuer_dn(&s_leaf), "NoxTLS Test EC Intermediate") != NULL);
    /* The DN parser takes the Name SEQUENCE contents (short-form header here). */
    LB_CHECK(lb_ec_server_subject_der[1] < 0x80U);
    LB_CHECK_OK(noxtls_x509_parse_distinguished_name(&lb_ec_server_subject_der[2], lb_ec_server_subject_der_len - 2U,
                                                     text, sizeof(text)));
    LB_CHECK(strstr((const char *)text, "server.test") != NULL);
    /* Validity strings. */
    {
        uint32_t tlen = 0U;
        const uint8_t *t = xf_not_before(&s_leaf, &tlen);
        LB_CHECK(t != NULL);
        LB_CHECK_OK(noxtls_x509_parse_time(t, tlen, text, sizeof(text)));
        LB_CHECK(strcmp((const char *)text, "2025-01-01 00:00:00") == 0);
        t = xf_not_after(&s_leaf, &tlen);
        LB_CHECK(t != NULL);
        LB_CHECK_OK(noxtls_x509_parse_time(t, tlen, text, sizeof(text)));
        LB_CHECK(strcmp((const char *)text, "2049-12-31 23:59:59") == 0);
    }
    /* SAN DNS names in certificate order. */
    LB_CHECK_EQ(xf_san_count(&s_leaf), 3U);
    LB_CHECK(strcmp(xf_san(&s_leaf, 0U), "server.test") == 0);
    LB_CHECK(strcmp(xf_san(&s_leaf, 1U), "alt.test") == 0);
    LB_CHECK(strcmp(xf_san(&s_leaf, 2U), "*.wild.test") == 0);
    LB_CHECK_EQ(xf_san_count(&s_int), 0U);
    /* Key usage, EKU, basic constraints and path length. */
    LB_CHECK_EQ(xf_key_usage(&s_leaf), X509_KEY_USAGE_DIGITAL_SIGNATURE);
    LB_CHECK_EQ(xf_eku(&s_leaf), X509_EKU_SERVER_AUTH);
    LB_CHECK_EQ(xf_bc_ca(&s_leaf), 0);
    LB_CHECK_EQ(xf_bc_path_len(&s_leaf), X509_BC_PATH_LEN_ABSENT);
    LB_CHECK_EQ(xf_key_usage(&s_int), X509_KEY_USAGE_KEY_CERT_SIGN | X509_KEY_USAGE_CRL_SIGN);
    LB_CHECK_EQ(xf_bc_ca(&s_int), 1);
    LB_CHECK_EQ(xf_bc_path_len(&s_int), 0);
    LB_CHECK_EQ(xf_bc_ca(&s_root), 1);
    LB_CHECK_EQ(xf_bc_path_len(&s_root), 1);
    LB_CHECK_EQ(xf_eku(&s_root), 0U);
    /* Key identifiers. */
    LB_CHECK(xf_ski_eq(&s_root, lb_ec_root_ski, lb_ec_root_ski_len));
    LB_CHECK(xf_ski_eq(&s_int, lb_ec_int_ski, lb_ec_int_ski_len));
    LB_CHECK(xf_aki_eq(&s_int, lb_ec_int_aki, lb_ec_int_aki_len));
    LB_CHECK(xf_aki_eq(&s_int, lb_ec_root_ski, lb_ec_root_ski_len));
    LB_CHECK(xf_ski_eq(&s_leaf, lb_ec_server_ski, lb_ec_server_ski_len));
    LB_CHECK(xf_aki_eq(&s_leaf, lb_ec_int_ski, lb_ec_int_ski_len));
    /* Public key point and channel-binding hash. */
    LB_CHECK(xf_ec_point_eq(&s_leaf, lb_ec_server_point, lb_ec_server_point_len));
    {
        noxtls_hash_algos_t h = NOXTLS_HASH_SHA1;
        LB_CHECK_OK(noxtls_x509_get_channel_binding_hash_algo(&s_leaf, &h));
        LB_CHECK_EQ(h, NOXTLS_HASH_SHA_256);
    }
    /* Re-running extension parsing is idempotent. */
    LB_CHECK_OK(noxtls_x509_parse_extensions(&s_leaf));
    LB_CHECK_EQ(xf_san_count(&s_leaf), 3U);
    LB_CHECK_EQ(xf_eku(&s_leaf), X509_EKU_SERVER_AUTH);
    /* Client certificate EKU. */
    LB_RUN(parse(&s_tmp, lb_ec_client_cert, lb_ec_client_cert_len));
    LB_CHECK_EQ(xf_eku(&s_tmp), X509_EKU_CLIENT_AUTH);
    LB_CHECK(xf_serial_eq(&s_tmp, LB_PKI_SERIAL_EC_CLIENT));
    (void)noxtls_x509_certificate_free(&s_tmp);
    free_ec_chain();
    return lb_expect_no_leak(base, "ec fields");
}

static int t_pem_matches_der(void)
{
    struct { const uint8_t *pem; const uint32_t *pem_len; const uint8_t *der; const uint32_t *der_len; } v[] = {
        { lb_ec_root_pem, &lb_ec_root_pem_len, lb_ec_root_cert, &lb_ec_root_cert_len },
        { lb_ec_int_pem, &lb_ec_int_pem_len, lb_ec_int_cert, &lb_ec_int_cert_len },
        { lb_ec_server_pem, &lb_ec_server_pem_len, lb_ec_server_cert, &lb_ec_server_cert_len },
        { lb_rsa_server_pem, &lb_rsa_server_pem_len, lb_rsa_server_cert, &lb_rsa_server_cert_len },
    };
    uint32_t i;
    size_t base = lb_alloc_live_bytes();
    for(i = 0U; i < 4U; i++) {
        const uint8_t *der;
        uint32_t len = 0U;
        LB_RUN(parse_pem(&s_tmp, v[i].pem, *v[i].pem_len));
        LB_RUN(parse(&s_tmp2, v[i].der, *v[i].der_len));
        der = lb_field_cert_der(&s_tmp, &len);
        LB_CHECK_EQ(len, *v[i].der_len);
        LB_CHECK(memcmp(der, v[i].der, len) == 0);
        LB_CHECK(xf_issuer_eq_subject(&s_tmp, &s_tmp) == xf_issuer_eq_subject(&s_tmp2, &s_tmp2));
        LB_CHECK_EQ(xf_san_count(&s_tmp), xf_san_count(&s_tmp2));
        LB_CHECK(strcmp(xf_subject_dn(&s_tmp), xf_subject_dn(&s_tmp2)) == 0);
        (void)noxtls_x509_certificate_free(&s_tmp);
        (void)noxtls_x509_certificate_free(&s_tmp2);
    }
    /* PEM without the armour, or truncated base64, must be rejected. */
    (void)noxtls_x509_certificate_init(&s_tmp);
    LB_CHECK(noxtls_x509_certificate_parse_pem(&s_tmp, lb_ec_server_pem, lb_ec_server_pem_len / 2U) !=
             NOXTLS_RETURN_SUCCESS);
    (void)noxtls_x509_certificate_free(&s_tmp);
    (void)noxtls_x509_certificate_init(&s_tmp);
    LB_CHECK(noxtls_x509_certificate_parse_pem(&s_tmp, lb_ec_server_cert, lb_ec_server_cert_len) !=
             NOXTLS_RETURN_SUCCESS);
    (void)noxtls_x509_certificate_free(&s_tmp);
    return lb_expect_no_leak(base, "pem");
}

static int t_rsa_fields(void)
{
    size_t base = lb_alloc_live_bytes();
    LB_RUN(parse(&s_leaf, lb_rsa_server_cert, lb_rsa_server_cert_len));
    LB_RUN(parse(&s_root, lb_rsa_root_cert, lb_rsa_root_cert_len));
    LB_CHECK(xf_rsa_modulus_eq(&s_leaf, lb_rsa_server_modulus, lb_rsa_server_modulus_len));
    LB_CHECK(xf_rsa_exponent_is_65537(&s_leaf));
    LB_CHECK_EQ(xf_key_usage(&s_leaf), X509_KEY_USAGE_DIGITAL_SIGNATURE | X509_KEY_USAGE_KEY_ENCIPHERMENT);
    LB_CHECK_EQ(xf_san_count(&s_leaf), 2U);
    LB_CHECK(xf_issuer_eq_subject(&s_leaf, &s_root));
    LB_CHECK_OK(noxtls_x509_certificate_verify_signature(&s_leaf, &s_root));
    LB_CHECK_OK(noxtls_x509_certificate_verify_signature(&s_root, &s_root));
    {
        /* noxtls_x509_certificate_get_public_key() only materializes EC keys. */
        void *key = (void *)&s_buf;
        uint32_t type = 99U;
        LB_CHECK_OK(noxtls_x509_certificate_get_public_key(&s_leaf, &key, &type));
        LB_CHECK(key == NULL);
        LB_CHECK_EQ(type, 0U);
    }
    (void)noxtls_x509_certificate_free(&s_leaf);
    (void)noxtls_x509_certificate_free(&s_root);
    return lb_expect_no_leak(base, "rsa");
}

static int t_ed25519_fields(void)
{
    size_t base = lb_alloc_live_bytes();
    LB_RUN(parse(&s_leaf, lb_ed_server_cert, lb_ed_server_cert_len));
    LB_RUN(parse(&s_root, lb_ec_root_cert, lb_ec_root_cert_len));
    LB_CHECK(xf_ed25519_eq(&s_leaf, lb_ed_server_pub));
    LB_CHECK_OK(noxtls_x509_certificate_verify_signature(&s_leaf, &s_root));
    (void)noxtls_x509_certificate_free(&s_root);
    /* Self-signed certificate carrying an Ed25519 signature. */
    LB_RUN(parse(&s_root, lb_ed_root_cert, lb_ed_root_cert_len));
    LB_CHECK_OK(noxtls_x509_certificate_verify_signature(&s_root, &s_root));
    LB_CHECK(noxtls_x509_certificate_verify_signature(&s_leaf, &s_root) != NOXTLS_RETURN_SUCCESS);
    (void)noxtls_x509_certificate_free(&s_leaf);
    (void)noxtls_x509_certificate_free(&s_root);
    return lb_expect_no_leak(base, "ed25519");
}

static int t_hostname_rules(void)
{
    static const struct { const char *name; int ok; } table[] = {
        { "server.test", 1 }, { "SERVER.TEST", 1 }, { "alt.test", 1 }, { "foo.wild.test", 1 },
        { "FOO.Wild.Test", 1 }, { "wild.test", 0 }, { "a.b.wild.test", 0 }, { ".wild.test", 0 },
        { "evil.test", 0 }, { "server.test.evil", 0 }, { "xserver.test", 0 }, { "", 0 },
        { "NoxTLS Test", 0 },
    };
    uint32_t i;
    size_t base = lb_alloc_live_bytes();
    int saved = noxtls_x509_get_hostname_wildcard_matching();

    LB_RUN(parse(&s_leaf, lb_ec_server_cert, lb_ec_server_cert_len));
    noxtls_x509_set_hostname_wildcard_matching(1);
    for(i = 0U; i < (uint32_t)(sizeof(table) / sizeof(table[0])); i++) {
        noxtls_return_t rc = noxtls_x509_certificate_matches_hostname(&s_leaf, (const uint8_t *)table[i].name,
                                                                      (uint32_t)strlen(table[i].name));
        if((rc == NOXTLS_RETURN_SUCCESS) != (table[i].ok != 0)) {
            lb_log("hostname '%s': rc=%d expected %s", table[i].name, (int)rc, table[i].ok ? "match" : "mismatch");
            return 1;
        }
    }
    /* hostname_len 0 means NUL-terminated. */
    LB_CHECK_OK(noxtls_x509_certificate_matches_hostname(&s_leaf, (const uint8_t *)"alt.test", 0U));
    /* Wildcards can be disabled at runtime. */
    noxtls_x509_set_hostname_wildcard_matching(0);
    LB_CHECK_EQ(noxtls_x509_get_hostname_wildcard_matching(), 0);
    LB_CHECK(noxtls_x509_certificate_matches_hostname(&s_leaf, (const uint8_t *)"foo.wild.test", 0U) !=
             NOXTLS_RETURN_SUCCESS);
    LB_CHECK_OK(noxtls_x509_certificate_matches_hostname(&s_leaf, (const uint8_t *)"server.test", 0U));
    noxtls_x509_set_hostname_wildcard_matching(saved);
    (void)noxtls_x509_certificate_free(&s_leaf);
    /* Without SAN the subject CN is used; with SAN present the CN is not consulted separately. */
    LB_RUN(parse(&s_leaf, lb_ec_cn_only_cert, lb_ec_cn_only_cert_len));
    LB_CHECK_EQ(xf_san_count(&s_leaf), 0U);
    LB_CHECK_OK(noxtls_x509_certificate_matches_hostname(&s_leaf, (const uint8_t *)"cnonly.test", 0U));
    LB_CHECK(noxtls_x509_certificate_matches_hostname(&s_leaf, (const uint8_t *)"server.test", 0U) !=
             NOXTLS_RETURN_SUCCESS);
    (void)noxtls_x509_certificate_free(&s_leaf);
    LB_RUN(parse(&s_leaf, lb_rsa_server_cert, lb_rsa_server_cert_len));
    LB_CHECK_OK(noxtls_x509_certificate_matches_hostname(&s_leaf, (const uint8_t *)"rsa.test", 0U));
    LB_CHECK_OK(noxtls_x509_certificate_matches_hostname(&s_leaf, (const uint8_t *)"server.test", 0U));
    (void)noxtls_x509_certificate_free(&s_leaf);
    return lb_expect_no_leak(base, "hostname");
}

static int t_validity(void)
{
    size_t base = lb_alloc_live_bytes();
#if NOXTLS_HAVE_TIME
    LB_RUN(parse(&s_leaf, lb_ec_server_cert, lb_ec_server_cert_len));
    LB_CHECK_OK(noxtls_x509_certificate_check_validity_at(&s_leaf, T_VALID));
    LB_CHECK_OK(noxtls_x509_certificate_check_validity_at(&s_leaf, LB_PKI_NOT_BEFORE));
    LB_CHECK_OK(noxtls_x509_certificate_check_validity_at(&s_leaf, LB_PKI_NOT_AFTER));
    LB_CHECK_EQ(noxtls_x509_certificate_check_validity_at(&s_leaf, LB_PKI_NOT_BEFORE - 1),
                NOXTLS_RETURN_CERT_NOT_YET_VALID);
    LB_CHECK_EQ(noxtls_x509_certificate_check_validity_at(&s_leaf, LB_PKI_NOT_AFTER + 1),
                NOXTLS_RETURN_CERT_EXPIRED);
    LB_CHECK_OK(noxtls_x509_certificate_check_validity(&s_leaf));
    (void)noxtls_x509_certificate_free(&s_leaf);
    LB_RUN(parse(&s_leaf, lb_ec_expired_cert, lb_ec_expired_cert_len));
    LB_CHECK_EQ(noxtls_x509_certificate_check_validity(&s_leaf), NOXTLS_RETURN_CERT_EXPIRED);
    LB_CHECK_EQ(noxtls_x509_certificate_check_validity_at(&s_leaf, LB_PKI_EXPIRED_NOT_AFTER + 1),
                NOXTLS_RETURN_CERT_EXPIRED);
    LB_CHECK_OK(noxtls_x509_certificate_check_validity_at(&s_leaf, LB_PKI_EXPIRED_NOT_AFTER - 86400));
    {
        noxtls_cert_verify_failure_info_t info;
        noxtls_cert_verify_failure_clear();
        LB_CHECK_EQ(noxtls_x509_certificate_check_validity(&s_leaf), NOXTLS_RETURN_CERT_EXPIRED);
        noxtls_cert_verify_failure_get(&info);
        LB_CHECK_EQ(info.populated, 1);
        LB_CHECK_EQ(info.return_code, NOXTLS_RETURN_CERT_EXPIRED);
#if NOXTLS_X509_FAIL_INFO
        /* Text details are rendered from the DER at failure time. */
        LB_CHECK(info.subject_dn[0] != 0U);
        LB_CHECK((info.not_before[0] != 0U) && (info.not_after[0] != 0U));
        LB_CHECK(strlen((const char *)info.not_after) <= 14U);
#else
        LB_CHECK((info.subject_dn[0] == 0U) && (info.not_after[0] == 0U));
#endif
    }
    {
        noxtls_cert_verify_failure_info_t info;
        noxtls_cert_verify_failure_clear();
        LB_CHECK(noxtls_x509_certificate_matches_hostname(&s_leaf, (const uint8_t *)"nomatch.example", 0U) !=
                 NOXTLS_RETURN_SUCCESS);
        noxtls_cert_verify_failure_get(&info);
        LB_CHECK_EQ(info.return_code, NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH);
#if NOXTLS_X509_FAIL_INFO
        LB_CHECK(strcmp((const char *)info.expected_hostname, "nomatch.example") == 0);
#else
        LB_CHECK(info.expected_hostname[0] == 0U);
#endif
    }
    (void)noxtls_x509_certificate_free(&s_leaf);
#endif
    return lb_expect_no_leak(base, "validity");
}

static int t_signature_verify(void)
{
    size_t base = lb_alloc_live_bytes();
    uint32_t len = lb_ec_server_cert_len;
    LB_RUN(parse_ec_chain());
    LB_CHECK_OK(noxtls_x509_certificate_verify_signature(&s_leaf, &s_int));
    LB_CHECK_OK(noxtls_x509_certificate_verify_signature(&s_int, &s_root));
    LB_CHECK_OK(noxtls_x509_certificate_verify_signature(&s_root, &s_root));
    LB_CHECK(noxtls_x509_certificate_verify_signature(&s_leaf, &s_root) != NOXTLS_RETURN_SUCCESS);
    LB_CHECK(noxtls_x509_certificate_verify_signature(&s_int, &s_int) != NOXTLS_RETURN_SUCCESS);
    LB_CHECK(noxtls_x509_certificate_verify_signature(NULL, &s_root) != NOXTLS_RETURN_SUCCESS);
    /* Flip one byte of the signature value (last byte of the DER) and one TBS byte (inside the SAN). */
    memcpy(s_buf, lb_ec_server_cert, len);
    s_buf[len - 1U] ^= 0x01U;
    if(parse(&s_tmp, s_buf, len) == 0) {
        LB_CHECK(noxtls_x509_certificate_verify_signature(&s_tmp, &s_int) != NOXTLS_RETURN_SUCCESS);
    }
    (void)noxtls_x509_certificate_free(&s_tmp);
    memcpy(s_buf, lb_ec_server_cert, len);
    {
        uint8_t *p = (uint8_t *)memmem_compat(s_buf, len, "alt.test", 8U);
        LB_CHECK(p != NULL);
        p[0] = (uint8_t)'b';
    }
    LB_RUN(parse(&s_tmp, s_buf, len));
    LB_CHECK(noxtls_x509_certificate_verify_signature(&s_tmp, &s_int) != NOXTLS_RETURN_SUCCESS);
    (void)noxtls_x509_certificate_free(&s_tmp);
    free_ec_chain();
    return lb_expect_no_leak(base, "signatures");
}

static int t_public_key_extract_verify(void)
{
    static const uint8_t msg[] = "message signed by the server key";
    void *key = NULL;
    uint32_t type = 0U;
    uint32_t sig_len = 0U;
    ecdsa_signature_t sig;
    size_t base = lb_alloc_live_bytes();

    LB_RUN(parse(&s_leaf, lb_ec_server_cert, lb_ec_server_cert_len));
    LB_CHECK_OK(noxtls_x509_certificate_get_public_key(&s_leaf, &key, &type));
    LB_CHECK(key != NULL);
    LB_CHECK_EQ(type, 2U);
    LB_CHECK(memcmp(((ecc_key_t *)key)->Q.x, &lb_ec_server_point[1], 32U) == 0);
    LB_CHECK(memcmp(((ecc_key_t *)key)->Q.y, &lb_ec_server_point[33], 32U) == 0);
    /* Sign with the private key, verify with the key extracted from the certificate. */
    LB_CHECK_OK(noxtls_x509_private_key_sign_data(lb_ec_server_key, lb_ec_server_key_len, msg, sizeof(msg),
                                                  NOXTLS_HASH_SHA_256, s_buf, sizeof(s_buf), &sig_len));
    LB_CHECK_OK(noxtls_ecdsa_signature_parse_der(s_buf, sig_len, &sig, 32U));
    LB_CHECK_OK(noxtls_ecdsa_verify((const ecc_key_t *)key, msg, sizeof(msg), &sig, NOXTLS_HASH_SHA_256));
    LB_CHECK(noxtls_ecdsa_verify((const ecc_key_t *)key, msg, sizeof(msg) - 1U, &sig, NOXTLS_HASH_SHA_256) !=
             NOXTLS_RETURN_SUCCESS);
    (void)noxtls_ecdsa_signature_free(&sig);
    (void)noxtls_ecc_key_free((ecc_key_t *)key);
    noxtls_free(key);
    (void)noxtls_x509_certificate_free(&s_leaf);
    return lb_expect_no_leak(base, "public key");
}

static int t_trust_one_anchor(void)
{
    x509_certificate_chain_t presented;
    x509_certificate_chain_t deep;
    const uint8_t *ints[2] = { lb_ec_int_cert, lb_ec_int2_cert };
    uint32_t int_lens[2];
    size_t base = lb_alloc_live_bytes();

    int_lens[0] = lb_ec_int_cert_len;
    int_lens[1] = lb_ec_int2_cert_len;
    LB_RUN(lb_trust_ec_root());
    LB_CHECK_EQ(noxtls_x509_trust_store_has_anchors(), 1);
    LB_RUN(chain_of(&presented, ints, int_lens, 1U));
    LB_CHECK_OK(verify_server(lb_ec_server_cert, lb_ec_server_cert_len, &presented));
    LB_CHECK(verify_server(lb_ec_server_cert, lb_ec_server_cert_len, NULL) != NOXTLS_RETURN_SUCCESS);
    LB_CHECK(verify_server(lb_rogue_server_cert, lb_rogue_server_cert_len, &presented) != NOXTLS_RETURN_SUCCESS);
#if NOXTLS_HAVE_TIME
    LB_CHECK_EQ(verify_server(lb_ec_expired_cert, lb_ec_expired_cert_len, &presented), NOXTLS_RETURN_CERT_EXPIRED);
#endif
    /* The intermediate's pathLenConstraint 0 forbids a further CA below it. */
    {
        const uint8_t *ders[2] = { lb_ec_int2_cert, lb_ec_int_cert };
        uint32_t lens[2];
        lens[0] = lb_ec_int2_cert_len;
        lens[1] = lb_ec_int_cert_len;
        LB_RUN(chain_of(&deep, ders, lens, 2U));
        LB_CHECK(verify_server(lb_ec_deep_cert, lb_ec_deep_cert_len, &deep) != NOXTLS_RETURN_SUCCESS);
        (void)noxtls_x509_certificate_chain_free(&deep);
    }
    /* Purpose: a serverAuth-only leaf is not a client certificate and vice versa. */
    LB_RUN(parse(&s_tmp2, lb_ec_server_cert, lb_ec_server_cert_len));
    LB_CHECK(noxtls_x509_verify_client_cert_trust(&s_tmp2, &presented) != NOXTLS_RETURN_SUCCESS);
    (void)noxtls_x509_certificate_free(&s_tmp2);
    LB_RUN(parse(&s_tmp2, lb_ec_client_cert, lb_ec_client_cert_len));
    LB_CHECK_OK(noxtls_x509_verify_client_cert_trust(&s_tmp2, NULL));
    LB_CHECK(noxtls_x509_verify_server_cert_trust(&s_tmp2, NULL) != NOXTLS_RETURN_SUCCESS);
    (void)noxtls_x509_certificate_free(&s_tmp2);
    /* An empty store fails closed. */
    lb_trust_clear();
    LB_CHECK_EQ(noxtls_x509_trust_store_has_anchors(), 0);
    LB_CHECK(verify_server(lb_ec_server_cert, lb_ec_server_cert_len, &presented) != NOXTLS_RETURN_SUCCESS);
    (void)noxtls_x509_certificate_chain_free(&presented);
    return lb_expect_no_leak(base, "trust 1");
}

static int t_trust_three_anchors(void)
{
    x509_certificate_chain_t presented;
    x509_certificate_chain_t anchors;
    noxtls_x509_verify_policy_t policy;
    const uint8_t *roots[3] = { lb_ec_root2_cert, lb_ec_root3_cert, lb_ec_root_cert };
    uint32_t root_lens[3];
    const uint8_t *ints[1] = { lb_ec_int_cert };
    uint32_t int_lens[1];
    size_t base = lb_alloc_live_bytes();

    root_lens[0] = lb_ec_root2_cert_len;
    root_lens[1] = lb_ec_root3_cert_len;
    root_lens[2] = lb_ec_root_cert_len;
    int_lens[0] = lb_ec_int_cert_len;
    LB_RUN(lb_trust_set(roots, root_lens, 3U));
    LB_RUN(chain_of(&presented, ints, int_lens, 1U));
    LB_CHECK_OK(verify_server(lb_ec_server_cert, lb_ec_server_cert_len, &presented));
    LB_CHECK_OK(verify_server(lb_ec_other_server_cert, lb_ec_other_server_cert_len, NULL));
    LB_CHECK(verify_server(lb_rogue_server_cert, lb_rogue_server_cert_len, NULL) != NOXTLS_RETURN_SUCCESS);
    /* The same anchors through an explicit policy, and a 1-anchor policy that excludes root3. */
    LB_RUN(chain_of(&anchors, roots, root_lens, 3U));
    memset(&policy, 0, sizeof(policy));
    policy.trust_anchors = &anchors;
    policy.required_eku = X509_EKU_SERVER_AUTH;
    policy.time_mode = NOXTLS_X509_TIME_EXPLICIT;
    policy.verify_time = T_VALID;
    LB_RUN(parse(&s_tmp2, lb_ec_server_cert, lb_ec_server_cert_len));
    LB_CHECK_OK(noxtls_x509_verify_cert_with_policy(&s_tmp2, &presented, &policy, NULL));
    (void)noxtls_x509_certificate_free(&s_tmp2);
    LB_RUN(parse(&s_tmp2, lb_ec_other_server_cert, lb_ec_other_server_cert_len));
    LB_CHECK_OK(noxtls_x509_verify_cert_with_policy(&s_tmp2, NULL, &policy, NULL));
    (void)noxtls_x509_certificate_chain_free(&anchors);
    LB_RUN(chain_of(&anchors, &roots[2], &root_lens[2], 1U));
    policy.trust_anchors = &anchors;
    LB_CHECK_EQ(noxtls_x509_verify_cert_with_policy(&s_tmp2, NULL, &policy, NULL),
                NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
    (void)noxtls_x509_certificate_free(&s_tmp2);
    LB_RUN(parse(&s_tmp2, lb_ec_server_cert, lb_ec_server_cert_len));
    LB_CHECK_OK(noxtls_x509_verify_cert_with_policy(&s_tmp2, &presented, &policy, NULL));
    (void)noxtls_x509_certificate_free(&s_tmp2);
    (void)noxtls_x509_certificate_chain_free(&anchors);
    (void)noxtls_x509_certificate_chain_free(&presented);
    lb_trust_clear();
    return lb_expect_no_leak(base, "trust 3");
}

static int t_chain_verify_api(void)
{
    x509_certificate_chain_t chain;
    const uint8_t *ders[3] = { lb_ec_server_cert, lb_ec_int_cert, lb_ec_root_cert };
    uint32_t lens[3];
    size_t base = lb_alloc_live_bytes();

    lens[0] = lb_ec_server_cert_len;
    lens[1] = lb_ec_int_cert_len;
    lens[2] = lb_ec_root_cert_len;
    LB_RUN(chain_of(&chain, ders, lens, 3U));
    LB_CHECK_EQ(xf_chain_count(&chain), 3U);
    LB_CHECK_OK(noxtls_x509_certificate_chain_verify(&chain));
    (void)noxtls_x509_certificate_chain_free(&chain);
    /* Wrong order fails. */
    ders[1] = lb_ec_root_cert;
    lens[1] = lb_ec_root_cert_len;
    ders[2] = lb_ec_int_cert;
    lens[2] = lb_ec_int_cert_len;
    LB_RUN(chain_of(&chain, ders, lens, 3U));
    LB_CHECK_EQ(noxtls_x509_certificate_chain_verify(&chain), NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
    (void)noxtls_x509_certificate_chain_free(&chain);
    /* Chains grow beyond their initial capacity and copy the DER. */
    LB_CHECK_OK(noxtls_x509_certificate_chain_init(&chain));
    LB_RUN(parse(&s_tmp2, lb_ec_root_cert, lb_ec_root_cert_len));
    {
        uint32_t i;
        for(i = 0U; i < 10U; i++) {
            LB_CHECK_OK(noxtls_x509_certificate_chain_add(&chain, &s_tmp2));
        }
    }
    (void)noxtls_x509_certificate_free(&s_tmp2);
    LB_CHECK_EQ(xf_chain_count(&chain), 10U);
    LB_CHECK(xf_issuer_eq_subject(xf_chain_cert(&chain, 9U), xf_chain_cert(&chain, 0U)));
    (void)noxtls_x509_certificate_chain_free(&chain);
    LB_CHECK_EQ(noxtls_x509_certificate_chain_verify(NULL), NOXTLS_RETURN_NULL);
    return lb_expect_no_leak(base, "chain api");
}

static int t_crl(void)
{
    noxtls_x509_crl_t crl;
    noxtls_x509_crl_t crl_pem;
    x509_certificate_chain_t presented;
    noxtls_x509_verify_flags_t flags = 0U;
    const uint8_t *ints[1] = { lb_ec_int_cert };
    uint32_t int_lens[1];
    size_t base = lb_alloc_live_bytes();

    int_lens[0] = lb_ec_int_cert_len;
    LB_CHECK_OK(noxtls_x509_crl_init(&crl));
    LB_CHECK_OK(noxtls_x509_crl_parse_der(&crl, lb_ec_int_crl, lb_ec_int_crl_len));
    LB_CHECK_EQ(xf_crl_count(&crl), LB_PKI_CRL_REVOKED_COUNT);
    LB_CHECK_OK(noxtls_x509_crl_init(&crl_pem));
    LB_CHECK_OK(noxtls_x509_crl_parse_pem(&crl_pem, lb_ec_int_crl_pem, lb_ec_int_crl_pem_len));
    LB_CHECK_EQ(xf_crl_count(&crl_pem), LB_PKI_CRL_REVOKED_COUNT);
    noxtls_x509_crl_free(&crl_pem);
    LB_RUN(parse_ec_chain());
    LB_CHECK(xf_crl_issuer_eq(&crl, &s_int));
    LB_RUN(parse(&s_tmp, lb_ec_revoked_cert, lb_ec_revoked_cert_len));
    LB_CHECK_EQ(noxtls_x509_crl_serial_is_revoked(&crl, &s_tmp), 1);
    LB_CHECK_EQ(noxtls_x509_crl_serial_is_revoked(&crl, &s_leaf), 0);
    LB_CHECK_EQ(noxtls_x509_crl_serial_is_revoked(&crl, &s_int), 0);
    /* Trust verification with the CRL. */
    LB_RUN(lb_trust_ec_root());
    LB_RUN(chain_of(&presented, ints, int_lens, 1U));
    {
        noxtls_return_t rc = noxtls_x509_verify_server_cert_trust_ex(&s_tmp, &presented, &crl, &flags);
        if(rc != NOXTLS_RETURN_CERT_REVOKED) {
            noxtls_cert_verify_failure_info_t info;
            noxtls_cert_verify_failure_get(&info);
            lb_log("revoked leaf: rc=%d flags=0x%x fail_rc=%d index=%u", (int)rc, (unsigned)flags,
                   (int)info.return_code, info.cert_index);
        }
        LB_CHECK_EQ(rc, NOXTLS_RETURN_CERT_REVOKED);
    }
    LB_CHECK((flags & NOXTLS_X509_VERIFY_FLAG_CERT_REVOKED) != 0U);
    flags = 0U;
    LB_CHECK_OK(noxtls_x509_verify_server_cert_trust_ex(&s_leaf, &presented, &crl, &flags));
    LB_CHECK((flags & NOXTLS_X509_VERIFY_FLAG_CRL_USED) != 0U);
    LB_CHECK((flags & NOXTLS_X509_VERIFY_FLAG_CERT_REVOKED) == 0U);
    LB_CHECK_OK(noxtls_x509_verify_server_cert_trust(&s_tmp, &presented)); /* no CRL: not revoked */
    noxtls_x509_crl_free(&crl);
    /* A CRL whose signature does not verify is not trusted. */
    memcpy(s_buf, lb_ec_int_crl, lb_ec_int_crl_len);
    s_buf[lb_ec_int_crl_len - 1U] ^= 0x01U;
    LB_CHECK_OK(noxtls_x509_crl_init(&crl));
    if(noxtls_x509_crl_parse_der(&crl, s_buf, lb_ec_int_crl_len) == NOXTLS_RETURN_SUCCESS) {
        flags = 0U;
        LB_CHECK(noxtls_x509_verify_server_cert_trust_ex(&s_leaf, &presented, &crl, &flags) != NOXTLS_RETURN_SUCCESS);
        LB_CHECK((flags & NOXTLS_X509_VERIFY_FLAG_CRL_BAD_SIGNATURE) != 0U);
    }
    noxtls_x509_crl_free(&crl);
    /* Truncated CRLs are rejected. */
    LB_CHECK_OK(noxtls_x509_crl_init(&crl));
    LB_CHECK(noxtls_x509_crl_parse_der(&crl, lb_ec_int_crl, lb_ec_int_crl_len - 5U) != NOXTLS_RETURN_SUCCESS);
    noxtls_x509_crl_free(&crl);
    (void)noxtls_x509_certificate_chain_free(&presented);
    (void)noxtls_x509_certificate_free(&s_tmp);
    free_ec_chain();
    lb_trust_clear();
    return lb_expect_no_leak(base, "crl");
}

#if defined(NOXTLS_HAVE_CERT_WRITE) && NOXTLS_HAVE_CERT_WRITE
static const uint8_t k_oid_ec_public_key[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
static const uint8_t k_oid_ecdsa_sha256[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
static const uint8_t k_prime256v1_params[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static const uint8_t k_oid_ed25519[] = { 0x2B, 0x65, 0x70 };
static const uint8_t k_serial[] = { 0x4E, 0x6F, 0x78, 0x01 };

static const char *s_artifact_dir;

static void write_artifact(const char *name, const uint8_t *data, uint32_t len)
{
    char path[512];
    FILE *f;
    if(s_artifact_dir == NULL) {
        return;
    }
    (void)snprintf(path, sizeof(path), "%s/%s", s_artifact_dir, name);
    f = fopen(path, "wb");
    if(f != NULL) {
        (void)fwrite(data, 1U, len, f);
        (void)fclose(f);
    }
}

static int t_cert_write_roundtrip(void)
{
    uint8_t subject[128];
    uint32_t subject_len = 0U;
    uint8_t out[4096];
    uint32_t out_len = 0U;
    uint8_t again[4096];
    uint32_t again_len = 0U;
    size_t base = lb_alloc_live_bytes();

    /* EC P-256 self-signed (with namedCurve parameters). */
    LB_CHECK_OK(noxtls_x509_dn_from_cn((const uint8_t *)"gen.test", subject, sizeof(subject), &subject_len));
    LB_CHECK_OK(noxtls_x509_certificate_generate_self_signed_ex(
        k_serial, sizeof(k_serial), subject, subject_len, subject, subject_len,
        (const uint8_t *)"250101000000Z", (const uint8_t *)"491231235959Z",
        k_oid_ec_public_key, sizeof(k_oid_ec_public_key), k_prime256v1_params, sizeof(k_prime256v1_params),
        lb_ec_csr_point, lb_ec_csr_point_len, k_oid_ecdsa_sha256, sizeof(k_oid_ecdsa_sha256),
        lb_ec_csr_key, lb_ec_csr_key_len, NOXTLS_HASH_SHA_256, out, sizeof(out), &out_len));
    write_artifact("gen_ec_selfsigned.der", out, out_len);
    LB_RUN(parse(&s_tmp, out, out_len));
    LB_CHECK_OK(noxtls_x509_certificate_verify_signature(&s_tmp, &s_tmp));
    LB_CHECK(xf_ec_point_eq(&s_tmp, lb_ec_csr_point, lb_ec_csr_point_len));
    LB_CHECK(strstr(xf_subject_dn(&s_tmp), "gen.test") != NULL);
    LB_CHECK(xf_issuer_eq_subject(&s_tmp, &s_tmp));
    LB_CHECK_OK(noxtls_x509_certificate_matches_hostname(&s_tmp, (const uint8_t *)"gen.test", 0U));
#if NOXTLS_HAVE_TIME
    LB_CHECK_OK(noxtls_x509_certificate_check_validity_at(&s_tmp, T_VALID));
#endif
    /* write_der(parse(x)) == x and the PEM writer round-trips through the PEM parser. */
    LB_CHECK_OK(noxtls_x509_certificate_write_der(&s_tmp, again, sizeof(again), &again_len));
    LB_CHECK_EQ(again_len, out_len);
    LB_CHECK(memcmp(again, out, out_len) == 0);
    LB_CHECK_OK(noxtls_x509_certificate_write_pem(&s_tmp, s_buf, sizeof(s_buf), &again_len));
    (void)noxtls_x509_certificate_free(&s_tmp);
    LB_RUN(parse_pem(&s_tmp, s_buf, again_len));
    {
        const uint8_t *der;
        uint32_t len = 0U;
        der = lb_field_cert_der(&s_tmp, &len);
        LB_CHECK_EQ(len, out_len);
        LB_CHECK(memcmp(der, out, out_len) == 0);
    }
    (void)noxtls_x509_certificate_free(&s_tmp);

    /* Ed25519 self-signed with SAN, KU, basicConstraints and EKU extensions. */
    {
        static const uint8_t *const san[2] = { (const uint8_t *)"gen.test", (const uint8_t *)"*.gen.test" };
        LB_CHECK_OK(noxtls_x509_certificate_generate_self_signed_with_extensions_ex(
            k_serial, sizeof(k_serial), subject, subject_len, subject, subject_len,
            (const uint8_t *)"250101000000Z", (const uint8_t *)"491231235959Z",
            k_oid_ed25519, sizeof(k_oid_ed25519), lb_ed_server_pub, lb_ed_server_pub_len,
            k_oid_ed25519, sizeof(k_oid_ed25519), lb_ed_server_key, lb_ed_server_key_len, NOXTLS_HASH_SHA_256,
            san, 2U, (uint16_t)(X509_KEY_USAGE_DIGITAL_SIGNATURE | X509_KEY_USAGE_KEY_CERT_SIGN), 1, 2,
            X509_EKU_SERVER_AUTH | X509_EKU_CLIENT_AUTH, NULL, 0U, out, sizeof(out), &out_len));
        write_artifact("gen_ed25519_ext.der", out, out_len);
        LB_RUN(parse(&s_tmp, out, out_len));
        LB_CHECK_OK(noxtls_x509_certificate_verify_signature(&s_tmp, &s_tmp));
        LB_CHECK(xf_ed25519_eq(&s_tmp, lb_ed_server_pub));
        LB_CHECK_EQ(xf_san_count(&s_tmp), 2U);
        LB_CHECK(strcmp(xf_san(&s_tmp, 1U), "*.gen.test") == 0);
        LB_CHECK_EQ(xf_key_usage(&s_tmp), X509_KEY_USAGE_DIGITAL_SIGNATURE | X509_KEY_USAGE_KEY_CERT_SIGN);
        LB_CHECK_EQ(xf_bc_ca(&s_tmp), 1);
        LB_CHECK_EQ(xf_bc_path_len(&s_tmp), 2);
        LB_CHECK_EQ(xf_eku(&s_tmp), X509_EKU_SERVER_AUTH | X509_EKU_CLIENT_AUTH);
        LB_CHECK_OK(noxtls_x509_certificate_matches_hostname(&s_tmp, (const uint8_t *)"a.gen.test", 0U));
        (void)noxtls_x509_certificate_free(&s_tmp);
    }

    /* EC P-256 with extensions: this generator has no SPKI parameters argument, the RFC 5480
     * namedCurve is derived from the (matching) signing key. */
    {
        static const uint8_t *const san[1] = { (const uint8_t *)"gen.test" };
        noxtls_return_t rc = noxtls_x509_certificate_generate_self_signed_with_extensions_ex(
            k_serial, sizeof(k_serial), subject, subject_len, subject, subject_len,
            (const uint8_t *)"250101000000Z", (const uint8_t *)"491231235959Z",
            k_oid_ec_public_key, sizeof(k_oid_ec_public_key), lb_ec_csr_point, lb_ec_csr_point_len,
            k_oid_ecdsa_sha256, sizeof(k_oid_ecdsa_sha256), lb_ec_csr_key, lb_ec_csr_key_len, NOXTLS_HASH_SHA_256,
            san, 1U, (uint16_t)X509_KEY_USAGE_DIGITAL_SIGNATURE, 0, X509_BC_PATH_LEN_ABSENT, X509_EKU_SERVER_AUTH,
            NULL, 0U, out, sizeof(out), &out_len);
        LB_CHECK_OK(rc);
        write_artifact("gen_ec_ext.der", out, out_len);
        LB_RUN(parse(&s_tmp, out, out_len));
        LB_CHECK_OK(noxtls_x509_certificate_verify_signature(&s_tmp, &s_tmp));
        LB_CHECK((s_tmp.ecc_curve_oid_len == 8U) && (memcmp(s_tmp.ecc_curve_oid, &k_prime256v1_params[2], 8U) == 0));
        LB_CHECK_EQ(xf_san_count(&s_tmp), 1U);
        (void)noxtls_x509_certificate_free(&s_tmp);
    }

    /* PKCS#10 CSR (DER and PEM); no CSR parser exists, so check the outer structure. */
    LB_CHECK_OK(noxtls_x509_csr_create_der(subject, subject_len, k_oid_ec_public_key, sizeof(k_oid_ec_public_key),
                                           lb_ec_csr_point, lb_ec_csr_point_len, k_oid_ecdsa_sha256,
                                           sizeof(k_oid_ecdsa_sha256), lb_ec_csr_key, lb_ec_csr_key_len,
                                           NOXTLS_HASH_SHA_256, out, sizeof(out), &out_len));
    write_artifact("gen_ec.csr.der", out, out_len);
    LB_CHECK(out_len > 64U);
    LB_CHECK_EQ(out[0], 0x30);
    LB_CHECK_OK(noxtls_x509_csr_create_pem(subject, subject_len, k_oid_ec_public_key, sizeof(k_oid_ec_public_key),
                                           lb_ec_csr_point, lb_ec_csr_point_len, k_oid_ecdsa_sha256,
                                           sizeof(k_oid_ecdsa_sha256), lb_ec_csr_key, lb_ec_csr_key_len,
                                           NOXTLS_HASH_SHA_256, s_buf, sizeof(s_buf), &out_len));
    LB_CHECK(strstr((const char *)s_buf, "-----BEGIN CERTIFICATE REQUEST-----") != NULL);
    return lb_expect_no_leak(base, "cert write");
}

/* ---- Writer corpus (byte-identical regression vs the pre-change staged writer) ---- */
/* Writer corpus: fixed inputs for every certificate / CSR generator. Ed25519 signatures
 * are deterministic, so those outputs are reproducible byte for byte; ECDSA signatures use
 * a random nonce k from the PKC CTR_DRBG (no RFC 6979), see wc_is_randomized().
 * wc_emit(index, name, der, len) is called for every output (index 0..WC_COUNT-1). */
#define WC_COUNT 9U
static int wc_run(void (*wc_emit)(uint32_t index, const char *name, const uint8_t *der, uint32_t len))
{
    static const uint8_t oid_ec[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
    static const uint8_t oid_sig_ecdsa[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
    static const uint8_t p256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
    static const uint8_t oid_ed[] = { 0x2B, 0x65, 0x70 };
    static const uint8_t serial[] = { 0x00, 0x8E, 0x6F, 0x78, 0x02 };
    static const uint8_t custom_oid1[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDE, 0x6A, 0x01 };
    static const uint8_t custom_val1[] = { 0x04, 0x03, 0x01, 0x02, 0x03 };
    static const uint8_t custom_oid2[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDE, 0x6A, 0x02 };
    static const uint8_t custom_val2[] = { 0x0C, 0x05, 'h', 'e', 'l', 'l', 'o' };
    static const uint8_t *const san3[3] = { (const uint8_t *)"wc.test", (const uint8_t *)"*.wc.test",
                                            (const uint8_t *)"another-name.example.org" };
    static uint8_t out[4096];
    uint8_t subject[128];
    uint8_t issuer[128];
    uint32_t subject_len = 0U;
    uint32_t issuer_len = 0U;
    uint32_t out_len = 0U;
    noxtls_x509_custom_ext_t ce[2];

    if(noxtls_x509_dn_from_cn((const uint8_t *)"corpus.subject.test", subject, sizeof(subject), &subject_len) != NOXTLS_RETURN_SUCCESS) { return 1; }
    if(noxtls_x509_dn_from_cn((const uint8_t *)"Corpus Issuer", issuer, sizeof(issuer), &issuer_len) != NOXTLS_RETURN_SUCCESS) { return 1; }
    wc_emit(0U, "wc_dn.der", subject, subject_len);

    /* 1: plain generator, Ed25519 subject + signer. */
    if(noxtls_x509_certificate_generate_self_signed(serial, sizeof(serial), issuer, issuer_len, subject, subject_len,
           (const uint8_t *)"250101000000Z", (const uint8_t *)"491231235959Z", oid_ed, sizeof(oid_ed),
           lb_ed_server_pub, lb_ed_server_pub_len, oid_ed, sizeof(oid_ed), lb_ed_server_key, lb_ed_server_key_len,
           NOXTLS_HASH_SHA_256, out, sizeof(out), &out_len) != NOXTLS_RETURN_SUCCESS) { return 2; }
    wc_emit(1U, "wc_plain_ed25519.der", out, out_len);

    /* 2: _ex with EC namedCurve, ECDSA signer. */
    if(noxtls_x509_certificate_generate_self_signed_ex(serial, sizeof(serial), subject, subject_len, subject, subject_len,
           (const uint8_t *)"250101000000Z", (const uint8_t *)"491231235959Z", oid_ec, sizeof(oid_ec), p256, sizeof(p256),
           lb_ec_csr_point, lb_ec_csr_point_len, oid_sig_ecdsa, sizeof(oid_sig_ecdsa), lb_ec_csr_key, lb_ec_csr_key_len,
           NOXTLS_HASH_SHA_256, out, sizeof(out), &out_len) != NOXTLS_RETURN_SUCCESS) { return 3; }
    wc_emit(2U, "wc_ex_ec.der", out, out_len);

    /* 3: with_extensions (SAN x3 + KU incl. decipherOnly), Ed25519. */
    if(noxtls_x509_certificate_generate_self_signed_with_extensions(serial, sizeof(serial), issuer, issuer_len,
           subject, subject_len, (const uint8_t *)"250101000000Z", (const uint8_t *)"491231235959Z",
           oid_ed, sizeof(oid_ed), lb_ed_server_pub, lb_ed_server_pub_len, oid_ed, sizeof(oid_ed),
           lb_ed_server_key, lb_ed_server_key_len, NOXTLS_HASH_SHA_256, san3, 3U,
           (uint16_t)(X509_KEY_USAGE_DIGITAL_SIGNATURE | X509_KEY_USAGE_KEY_AGREEMENT | X509_KEY_USAGE_DECIPHER_ONLY),
           out, sizeof(out), &out_len) != NOXTLS_RETURN_SUCCESS) { return 4; }
    wc_emit(3U, "wc_ext_ed25519.der", out, out_len);

    /* 4: with_extensions_ex: every EKU, CA with pathLen 300, two custom extensions, Ed25519. */
    ce[0].oid = custom_oid1; ce[0].oid_len = sizeof(custom_oid1); ce[0].value = custom_val1;
    ce[0].value_len = sizeof(custom_val1); ce[0].critical = 0;
    ce[1].oid = custom_oid2; ce[1].oid_len = sizeof(custom_oid2); ce[1].value = custom_val2;
    ce[1].value_len = sizeof(custom_val2); ce[1].critical = 1;
    if(noxtls_x509_certificate_generate_self_signed_with_extensions_ex(serial, sizeof(serial), issuer, issuer_len,
           subject, subject_len, (const uint8_t *)"250101000000Z", (const uint8_t *)"491231235959Z",
           oid_ed, sizeof(oid_ed), lb_ed_server_pub, lb_ed_server_pub_len, oid_ed, sizeof(oid_ed),
           lb_ed_server_key, lb_ed_server_key_len, NOXTLS_HASH_SHA_256, san3, 1U,
           (uint16_t)(X509_KEY_USAGE_KEY_CERT_SIGN | X509_KEY_USAGE_CRL_SIGN), 1, 300,
           X509_EKU_SERVER_AUTH | X509_EKU_CLIENT_AUTH | X509_EKU_CODE_SIGNING | X509_EKU_EMAIL_PROTECTION |
           X509_EKU_TIME_STAMPING | X509_EKU_OCSP_SIGNING | X509_EKU_ANY, ce, 2U,
           out, sizeof(out), &out_len) != NOXTLS_RETURN_SUCCESS) { return 5; }
    wc_emit(4U, "wc_ext_ex_ed25519.der", out, out_len);

    /* 5: with_extensions_ex, no extension requested at all (no [3] wrapper), Ed25519. */
    if(noxtls_x509_certificate_generate_self_signed_with_extensions_ex(serial, sizeof(serial), issuer, issuer_len,
           subject, subject_len, (const uint8_t *)"250101000000Z", (const uint8_t *)"491231235959Z",
           oid_ed, sizeof(oid_ed), lb_ed_server_pub, lb_ed_server_pub_len, oid_ed, sizeof(oid_ed),
           lb_ed_server_key, lb_ed_server_key_len, NOXTLS_HASH_SHA_256, NULL, 0U, 0U, -1, X509_BC_PATH_LEN_ABSENT,
           0U, NULL, 0U, out, sizeof(out), &out_len) != NOXTLS_RETURN_SUCCESS) { return 6; }
    wc_emit(5U, "wc_noext_ed25519.der", out, out_len);

    /* 6: CSR, EC P-256 (curve taken from the signing key). */
    if(noxtls_x509_csr_create_der(subject, subject_len, oid_ec, sizeof(oid_ec), lb_ec_csr_point, lb_ec_csr_point_len,
           oid_sig_ecdsa, sizeof(oid_sig_ecdsa), lb_ec_csr_key, lb_ec_csr_key_len, NOXTLS_HASH_SHA_256,
           out, sizeof(out), &out_len) != NOXTLS_RETURN_SUCCESS) { return 7; }
    wc_emit(6U, "wc_csr_ec.der", out, out_len);

    /* 7: CSR, Ed25519. */
    if(noxtls_x509_csr_create_der(subject, subject_len, oid_ed, sizeof(oid_ed), lb_ed_server_pub, lb_ed_server_pub_len,
           oid_ed, sizeof(oid_ed), lb_ed_server_key, lb_ed_server_key_len, NOXTLS_HASH_SHA_256,
           out, sizeof(out), &out_len) != NOXTLS_RETURN_SUCCESS) { return 8; }
    wc_emit(7U, "wc_csr_ed25519.der", out, out_len);

    /* 8: CSR PEM (EC). */
    if(noxtls_x509_csr_create_pem(subject, subject_len, oid_ec, sizeof(oid_ec), lb_ec_csr_point, lb_ec_csr_point_len,
           oid_sig_ecdsa, sizeof(oid_sig_ecdsa), lb_ec_csr_key, lb_ec_csr_key_len, NOXTLS_HASH_SHA_256,
           out, sizeof(out), &out_len) != NOXTLS_RETURN_SUCCESS) { return 9; }
    wc_emit(8U, "wc_csr_ec.pem", out, out_len);
    return 0;
}

/* Reference outputs captured from the writer before its in-place rewrite (PR #58). */
/* wc_dn.der */
static const uint8_t k_wc_ref_0[] = {
    0x30, 0x1E, 0x31, 0x1C, 0x30, 0x1A, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x13, 0x63, 0x6F, 0x72,
    0x70, 0x75, 0x73, 0x2E, 0x73, 0x75, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x2E, 0x74, 0x65, 0x73, 0x74,
};
/* wc_plain_ed25519.der */
static const uint8_t k_wc_ref_1[] = {
    0x30, 0x81, 0xE6, 0x30, 0x81, 0x99, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x05, 0x00, 0x8E, 0x6F,
    0x78, 0x02, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x30, 0x18, 0x31, 0x16, 0x30, 0x14, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x13, 0x0D, 0x43, 0x6F, 0x72, 0x70, 0x75, 0x73, 0x20, 0x49, 0x73, 0x73,
    0x75, 0x65, 0x72, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D, 0x34, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39,
    0x35, 0x39, 0x5A, 0x30, 0x1E, 0x31, 0x1C, 0x30, 0x1A, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x13,
    0x63, 0x6F, 0x72, 0x70, 0x75, 0x73, 0x2E, 0x73, 0x75, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x2E, 0x74,
    0x65, 0x73, 0x74, 0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00, 0x76,
    0x47, 0x78, 0xA0, 0xF3, 0x7B, 0x8B, 0x2E, 0xE1, 0x3A, 0x79, 0x66, 0x15, 0xFE, 0x99, 0xED, 0xAD,
    0x1F, 0x83, 0xA6, 0x0E, 0x89, 0xF5, 0x4C, 0x81, 0x26, 0xC2, 0xAC, 0xEE, 0x6D, 0xAD, 0x6D, 0x30,
    0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x41, 0x00, 0x1B, 0x32, 0xB2, 0x52, 0x12, 0xE4, 0x55,
    0x8B, 0x8C, 0x0C, 0x9B, 0x9D, 0x18, 0x29, 0x74, 0x76, 0x65, 0xC3, 0x79, 0xFF, 0x04, 0x52, 0x40,
    0xAB, 0xC2, 0x6B, 0x47, 0x2C, 0x6B, 0x46, 0xC1, 0x2B, 0xDA, 0x8E, 0x05, 0x2D, 0x50, 0x6E, 0xA2,
    0xF2, 0x25, 0xA7, 0x1D, 0x28, 0x44, 0x6E, 0xB0, 0xCE, 0xD9, 0x76, 0x79, 0x4F, 0x73, 0x81, 0x4D,
    0x56, 0x9D, 0xCA, 0xE4, 0xF9, 0x47, 0x49, 0x4C, 0x00,
};
/* wc_ex_ec.der */
static const uint8_t k_wc_ref_2[] = {
    0x30, 0x82, 0x01, 0x2D, 0x30, 0x81, 0xD3, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x05, 0x00, 0x8E,
    0x6F, 0x78, 0x02, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30,
    0x1E, 0x31, 0x1C, 0x30, 0x1A, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x13, 0x63, 0x6F, 0x72, 0x70,
    0x75, 0x73, 0x2E, 0x73, 0x75, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x2E, 0x74, 0x65, 0x73, 0x74, 0x30,
    0x1E, 0x17, 0x0D, 0x32, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A,
    0x17, 0x0D, 0x34, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5A, 0x30,
    0x1E, 0x31, 0x1C, 0x30, 0x1A, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x13, 0x63, 0x6F, 0x72, 0x70,
    0x75, 0x73, 0x2E, 0x73, 0x75, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x2E, 0x74, 0x65, 0x73, 0x74, 0x30,
    0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86,
    0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x33, 0x62, 0x4F, 0x8A, 0x25, 0x5D,
    0xFE, 0x7C, 0x37, 0x0B, 0x67, 0x3A, 0x0D, 0x15, 0x55, 0xF4, 0x1C, 0xBC, 0x5D, 0x99, 0xA3, 0x5D,
    0x86, 0x27, 0xE2, 0x4E, 0x2C, 0xBC, 0xDB, 0x72, 0xF6, 0xD1, 0x00, 0x3D, 0x9B, 0x65, 0xD1, 0xB0,
    0x0A, 0x7D, 0x27, 0x3C, 0x9A, 0xC8, 0xE1, 0xF7, 0x6D, 0x32, 0xA9, 0x77, 0x9A, 0xB8, 0x6E, 0x5F,
    0xC7, 0xFD, 0xAF, 0xE1, 0x79, 0xAB, 0x99, 0x34, 0x45, 0xCE, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86,
    0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0xEF, 0xC1,
    0xAF, 0xB2, 0xCA, 0xA7, 0x28, 0x11, 0x8E, 0x15, 0x8D, 0x0C, 0x8F, 0xCB, 0x2E, 0x63, 0xF7, 0xEA,
    0xCD, 0x67, 0x41, 0x3F, 0x77, 0x28, 0xC6, 0x07, 0xA1, 0x17, 0xC4, 0x9D, 0xAB, 0x36, 0x02, 0x21,
    0x00, 0xE3, 0xD6, 0x62, 0x10, 0xD5, 0x09, 0x86, 0xCF, 0xBA, 0x4C, 0x3B, 0x7F, 0xC1, 0x22, 0x00,
    0x4F, 0x23, 0x5F, 0x84, 0x9B, 0x8A, 0xB9, 0xA9, 0xE8, 0x27, 0xCF, 0xF8, 0x71, 0x22, 0x61, 0x4D,
    0x02,
};
/* wc_ext_ed25519.der */
static const uint8_t k_wc_ref_3[] = {
    0x30, 0x82, 0x01, 0x31, 0x30, 0x81, 0xE4, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x05, 0x00, 0x8E,
    0x6F, 0x78, 0x02, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x30, 0x18, 0x31, 0x16, 0x30, 0x14,
    0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0D, 0x43, 0x6F, 0x72, 0x70, 0x75, 0x73, 0x20, 0x49, 0x73,
    0x73, 0x75, 0x65, 0x72, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D, 0x34, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35,
    0x39, 0x35, 0x39, 0x5A, 0x30, 0x1E, 0x31, 0x1C, 0x30, 0x1A, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
    0x13, 0x63, 0x6F, 0x72, 0x70, 0x75, 0x73, 0x2E, 0x73, 0x75, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x2E,
    0x74, 0x65, 0x73, 0x74, 0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
    0x76, 0x47, 0x78, 0xA0, 0xF3, 0x7B, 0x8B, 0x2E, 0xE1, 0x3A, 0x79, 0x66, 0x15, 0xFE, 0x99, 0xED,
    0xAD, 0x1F, 0x83, 0xA6, 0x0E, 0x89, 0xF5, 0x4C, 0x81, 0x26, 0xC2, 0xAC, 0xEE, 0x6D, 0xAD, 0x6D,
    0xA3, 0x49, 0x30, 0x47, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x04, 0x05, 0x03, 0x03, 0x07,
    0x88, 0x80, 0x30, 0x37, 0x06, 0x03, 0x55, 0x1D, 0x11, 0x04, 0x30, 0x30, 0x2E, 0x82, 0x07, 0x77,
    0x63, 0x2E, 0x74, 0x65, 0x73, 0x74, 0x82, 0x09, 0x2A, 0x2E, 0x77, 0x63, 0x2E, 0x74, 0x65, 0x73,
    0x74, 0x82, 0x18, 0x61, 0x6E, 0x6F, 0x74, 0x68, 0x65, 0x72, 0x2D, 0x6E, 0x61, 0x6D, 0x65, 0x2E,
    0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x6F, 0x72, 0x67, 0x30, 0x05, 0x06, 0x03, 0x2B,
    0x65, 0x70, 0x03, 0x41, 0x00, 0x32, 0x6C, 0xAE, 0xF3, 0x0B, 0x78, 0xC5, 0x4D, 0xFF, 0x21, 0x8A,
    0xBB, 0xB1, 0x75, 0x8B, 0xE9, 0xE3, 0xA4, 0x7B, 0xB4, 0x09, 0xBA, 0x40, 0xB9, 0x66, 0xC5, 0xC2,
    0x7A, 0x1B, 0xE7, 0xF2, 0xDD, 0xD9, 0x67, 0xBA, 0xAE, 0x3B, 0x01, 0x8F, 0xF8, 0xB9, 0x36, 0x4B,
    0x64, 0x35, 0x1C, 0x01, 0x01, 0x39, 0x21, 0x32, 0x30, 0x3E, 0xA3, 0xA2, 0xC8, 0x84, 0xEF, 0xE6,
    0xB6, 0x3D, 0x4D, 0x93, 0x00,
};
/* wc_ext_ex_ed25519.der */
static const uint8_t k_wc_ref_4[] = {
    0x30, 0x82, 0x01, 0x9B, 0x30, 0x82, 0x01, 0x4D, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x05, 0x00,
    0x8E, 0x6F, 0x78, 0x02, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x30, 0x18, 0x31, 0x16, 0x30,
    0x14, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0D, 0x43, 0x6F, 0x72, 0x70, 0x75, 0x73, 0x20, 0x49,
    0x73, 0x73, 0x75, 0x65, 0x72, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D, 0x34, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33,
    0x35, 0x39, 0x35, 0x39, 0x5A, 0x30, 0x1E, 0x31, 0x1C, 0x30, 0x1A, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x13, 0x13, 0x63, 0x6F, 0x72, 0x70, 0x75, 0x73, 0x2E, 0x73, 0x75, 0x62, 0x6A, 0x65, 0x63, 0x74,
    0x2E, 0x74, 0x65, 0x73, 0x74, 0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21,
    0x00, 0x76, 0x47, 0x78, 0xA0, 0xF3, 0x7B, 0x8B, 0x2E, 0xE1, 0x3A, 0x79, 0x66, 0x15, 0xFE, 0x99,
    0xED, 0xAD, 0x1F, 0x83, 0xA6, 0x0E, 0x89, 0xF5, 0x4C, 0x81, 0x26, 0xC2, 0xAC, 0xEE, 0x6D, 0xAD,
    0x6D, 0xA3, 0x81, 0xB1, 0x30, 0x81, 0xAE, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x04, 0x05,
    0x03, 0x03, 0x07, 0x06, 0x00, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1D, 0x11, 0x04, 0x0B, 0x30, 0x09,
    0x82, 0x07, 0x77, 0x63, 0x2E, 0x74, 0x65, 0x73, 0x74, 0x30, 0x10, 0x06, 0x03, 0x55, 0x1D, 0x13,
    0x04, 0x09, 0x30, 0x07, 0x01, 0x01, 0xFF, 0x02, 0x02, 0x01, 0x2C, 0x30, 0x4B, 0x06, 0x03, 0x55,
    0x1D, 0x25, 0x04, 0x44, 0x30, 0x42, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
    0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05,
    0x05, 0x07, 0x03, 0x03, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04, 0x06, 0x08,
    0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07,
    0x03, 0x09, 0x06, 0x04, 0x55, 0x1D, 0x25, 0x00, 0x30, 0x12, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04,
    0x01, 0x82, 0xDE, 0x6A, 0x01, 0x04, 0x05, 0x04, 0x03, 0x01, 0x02, 0x03, 0x30, 0x17, 0x06, 0x09,
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xDE, 0x6A, 0x02, 0x01, 0x01, 0xFF, 0x04, 0x07, 0x0C, 0x05,
    0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x41, 0x00, 0xEC,
    0x73, 0x37, 0x50, 0x5B, 0xEB, 0xEF, 0xF6, 0xA5, 0xD5, 0x77, 0x8B, 0x6A, 0xD3, 0xF6, 0x39, 0x84,
    0xB7, 0x37, 0x97, 0x10, 0xB7, 0x1A, 0x4B, 0x27, 0x0D, 0x01, 0xE1, 0x89, 0x02, 0x2E, 0x61, 0xDA,
    0x3D, 0x41, 0x58, 0xBB, 0x4E, 0x8A, 0x02, 0x0F, 0x58, 0x70, 0xD2, 0xF7, 0xA7, 0xF8, 0x46, 0x9C,
    0x2B, 0xD7, 0x01, 0x62, 0x10, 0x0C, 0xF6, 0xE9, 0xA6, 0xB7, 0x5A, 0x27, 0xBC, 0x5D, 0x0D,
};
/* wc_noext_ed25519.der */
static const uint8_t k_wc_ref_5[] = {
    0x30, 0x81, 0xE6, 0x30, 0x81, 0x99, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x05, 0x00, 0x8E, 0x6F,
    0x78, 0x02, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x30, 0x18, 0x31, 0x16, 0x30, 0x14, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x13, 0x0D, 0x43, 0x6F, 0x72, 0x70, 0x75, 0x73, 0x20, 0x49, 0x73, 0x73,
    0x75, 0x65, 0x72, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D, 0x34, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39,
    0x35, 0x39, 0x5A, 0x30, 0x1E, 0x31, 0x1C, 0x30, 0x1A, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x13,
    0x63, 0x6F, 0x72, 0x70, 0x75, 0x73, 0x2E, 0x73, 0x75, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x2E, 0x74,
    0x65, 0x73, 0x74, 0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00, 0x76,
    0x47, 0x78, 0xA0, 0xF3, 0x7B, 0x8B, 0x2E, 0xE1, 0x3A, 0x79, 0x66, 0x15, 0xFE, 0x99, 0xED, 0xAD,
    0x1F, 0x83, 0xA6, 0x0E, 0x89, 0xF5, 0x4C, 0x81, 0x26, 0xC2, 0xAC, 0xEE, 0x6D, 0xAD, 0x6D, 0x30,
    0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x41, 0x00, 0x1B, 0x32, 0xB2, 0x52, 0x12, 0xE4, 0x55,
    0x8B, 0x8C, 0x0C, 0x9B, 0x9D, 0x18, 0x29, 0x74, 0x76, 0x65, 0xC3, 0x79, 0xFF, 0x04, 0x52, 0x40,
    0xAB, 0xC2, 0x6B, 0x47, 0x2C, 0x6B, 0x46, 0xC1, 0x2B, 0xDA, 0x8E, 0x05, 0x2D, 0x50, 0x6E, 0xA2,
    0xF2, 0x25, 0xA7, 0x1D, 0x28, 0x44, 0x6E, 0xB0, 0xCE, 0xD9, 0x76, 0x79, 0x4F, 0x73, 0x81, 0x4D,
    0x56, 0x9D, 0xCA, 0xE4, 0xF9, 0x47, 0x49, 0x4C, 0x00,
};
/* wc_csr_ec.der */
static const uint8_t k_wc_ref_6[] = {
    0x30, 0x81, 0xD9, 0x30, 0x81, 0x80, 0x02, 0x01, 0x00, 0x30, 0x1E, 0x31, 0x1C, 0x30, 0x1A, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x13, 0x13, 0x63, 0x6F, 0x72, 0x70, 0x75, 0x73, 0x2E, 0x73, 0x75, 0x62,
    0x6A, 0x65, 0x63, 0x74, 0x2E, 0x74, 0x65, 0x73, 0x74, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
    0x03, 0x42, 0x00, 0x04, 0x33, 0x62, 0x4F, 0x8A, 0x25, 0x5D, 0xFE, 0x7C, 0x37, 0x0B, 0x67, 0x3A,
    0x0D, 0x15, 0x55, 0xF4, 0x1C, 0xBC, 0x5D, 0x99, 0xA3, 0x5D, 0x86, 0x27, 0xE2, 0x4E, 0x2C, 0xBC,
    0xDB, 0x72, 0xF6, 0xD1, 0x00, 0x3D, 0x9B, 0x65, 0xD1, 0xB0, 0x0A, 0x7D, 0x27, 0x3C, 0x9A, 0xC8,
    0xE1, 0xF7, 0x6D, 0x32, 0xA9, 0x77, 0x9A, 0xB8, 0x6E, 0x5F, 0xC7, 0xFD, 0xAF, 0xE1, 0x79, 0xAB,
    0x99, 0x34, 0x45, 0xCE, 0xA0, 0x00, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04,
    0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0xA3, 0x0F, 0x72, 0xB8, 0xC3, 0xD6,
    0xE2, 0xA2, 0xFE, 0xC8, 0x8F, 0x4D, 0x2A, 0x26, 0xE1, 0x7E, 0xEB, 0x37, 0x1F, 0xA7, 0x54, 0x44,
    0xDD, 0xF0, 0x7E, 0x61, 0x2E, 0x12, 0x3B, 0x15, 0x7C, 0xC1, 0x02, 0x20, 0x72, 0x18, 0x64, 0x06,
    0xEA, 0x1A, 0x74, 0x05, 0x55, 0xC9, 0xA4, 0x94, 0x7F, 0xF6, 0xBB, 0x34, 0x73, 0xC0, 0x99, 0x50,
    0xC0, 0xB4, 0x7B, 0xF6, 0xE5, 0x99, 0x2E, 0x3C, 0xAC, 0xB2, 0xBB, 0xF1,
};
/* wc_csr_ed25519.der */
static const uint8_t k_wc_ref_7[] = {
    0x30, 0x81, 0x9D, 0x30, 0x51, 0x02, 0x01, 0x00, 0x30, 0x1E, 0x31, 0x1C, 0x30, 0x1A, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x13, 0x13, 0x63, 0x6F, 0x72, 0x70, 0x75, 0x73, 0x2E, 0x73, 0x75, 0x62, 0x6A,
    0x65, 0x63, 0x74, 0x2E, 0x74, 0x65, 0x73, 0x74, 0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65,
    0x70, 0x03, 0x21, 0x00, 0x76, 0x47, 0x78, 0xA0, 0xF3, 0x7B, 0x8B, 0x2E, 0xE1, 0x3A, 0x79, 0x66,
    0x15, 0xFE, 0x99, 0xED, 0xAD, 0x1F, 0x83, 0xA6, 0x0E, 0x89, 0xF5, 0x4C, 0x81, 0x26, 0xC2, 0xAC,
    0xEE, 0x6D, 0xAD, 0x6D, 0xA0, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x41, 0x00,
    0x73, 0x31, 0xA0, 0xF6, 0xFB, 0xEE, 0xFF, 0xEB, 0x3F, 0xF9, 0xB0, 0x08, 0x33, 0xAB, 0xFF, 0xF2,
    0x75, 0x10, 0x18, 0x4F, 0x9D, 0x27, 0x06, 0x54, 0xA2, 0x32, 0x8D, 0x72, 0x21, 0xEB, 0xA1, 0x1A,
    0x47, 0x3B, 0x6D, 0x90, 0x8F, 0x82, 0x99, 0x8F, 0x02, 0x73, 0x1D, 0x46, 0x96, 0x43, 0x91, 0x19,
    0xF4, 0x8D, 0x45, 0xD0, 0xDE, 0x54, 0x81, 0x52, 0x46, 0xEA, 0x3D, 0xB3, 0x24, 0x07, 0x34, 0x0B,
};
/* wc_csr_ec.pem */
static const uint8_t k_wc_ref_8[] = {
    0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x42, 0x45, 0x47, 0x49, 0x4E, 0x20, 0x43, 0x45, 0x52, 0x54, 0x49,
    0x46, 0x49, 0x43, 0x41, 0x54, 0x45, 0x20, 0x52, 0x45, 0x51, 0x55, 0x45, 0x53, 0x54, 0x2D, 0x2D,
    0x2D, 0x2D, 0x2D, 0x0A, 0x4D, 0x49, 0x48, 0x5A, 0x4D, 0x49, 0x47, 0x41, 0x41, 0x67, 0x45, 0x41,
    0x4D, 0x42, 0x34, 0x78, 0x48, 0x44, 0x41, 0x61, 0x42, 0x67, 0x4E, 0x56, 0x42, 0x41, 0x4D, 0x54,
    0x45, 0x32, 0x4E, 0x76, 0x63, 0x6E, 0x42, 0x31, 0x63, 0x79, 0x35, 0x7A, 0x64, 0x57, 0x4A, 0x71,
    0x5A, 0x57, 0x4E, 0x30, 0x4C, 0x6E, 0x52, 0x6C, 0x63, 0x33, 0x51, 0x77, 0x57, 0x54, 0x41, 0x54,
    0x42, 0x67, 0x63, 0x71, 0x0A, 0x68, 0x6B, 0x6A, 0x4F, 0x50, 0x51, 0x49, 0x42, 0x42, 0x67, 0x67,
    0x71, 0x68, 0x6B, 0x6A, 0x4F, 0x50, 0x51, 0x4D, 0x42, 0x42, 0x77, 0x4E, 0x43, 0x41, 0x41, 0x51,
    0x7A, 0x59, 0x6B, 0x2B, 0x4B, 0x4A, 0x56, 0x33, 0x2B, 0x66, 0x44, 0x63, 0x4C, 0x5A, 0x7A, 0x6F,
    0x4E, 0x46, 0x56, 0x58, 0x30, 0x48, 0x4C, 0x78, 0x64, 0x6D, 0x61, 0x4E, 0x64, 0x68, 0x69, 0x66,
    0x69, 0x54, 0x69, 0x79, 0x38, 0x0A, 0x32, 0x33, 0x4C, 0x32, 0x30, 0x51, 0x41, 0x39, 0x6D, 0x32,
    0x58, 0x52, 0x73, 0x41, 0x70, 0x39, 0x4A, 0x7A, 0x79, 0x61, 0x79, 0x4F, 0x48, 0x33, 0x62, 0x54,
    0x4B, 0x70, 0x64, 0x35, 0x71, 0x34, 0x62, 0x6C, 0x2F, 0x48, 0x2F, 0x61, 0x2F, 0x68, 0x65, 0x61,
    0x75, 0x5A, 0x4E, 0x45, 0x58, 0x4F, 0x6F, 0x41, 0x41, 0x77, 0x43, 0x67, 0x59, 0x49, 0x4B, 0x6F,
    0x5A, 0x49, 0x7A, 0x6A, 0x30, 0x45, 0x0A, 0x41, 0x77, 0x49, 0x44, 0x53, 0x41, 0x41, 0x77, 0x52,
    0x51, 0x49, 0x68, 0x41, 0x4D, 0x73, 0x47, 0x41, 0x58, 0x67, 0x52, 0x32, 0x5A, 0x36, 0x76, 0x66,
    0x74, 0x2B, 0x69, 0x61, 0x53, 0x5A, 0x58, 0x38, 0x42, 0x65, 0x30, 0x4E, 0x77, 0x67, 0x34, 0x56,
    0x43, 0x4C, 0x79, 0x75, 0x33, 0x36, 0x74, 0x53, 0x57, 0x6F, 0x75, 0x6A, 0x72, 0x43, 0x33, 0x41,
    0x69, 0x41, 0x58, 0x4F, 0x55, 0x78, 0x59, 0x0A, 0x30, 0x62, 0x57, 0x4C, 0x51, 0x47, 0x72, 0x38,
    0x74, 0x51, 0x78, 0x4C, 0x47, 0x75, 0x4D, 0x61, 0x5A, 0x78, 0x31, 0x52, 0x6F, 0x6C, 0x48, 0x35,
    0x44, 0x7A, 0x46, 0x52, 0x52, 0x4B, 0x4A, 0x62, 0x7A, 0x49, 0x67, 0x7A, 0x35, 0x51, 0x3D, 0x3D,
    0x0A, 0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x45, 0x4E, 0x44, 0x20, 0x43, 0x45, 0x52, 0x54, 0x49, 0x46,
    0x49, 0x43, 0x41, 0x54, 0x45, 0x20, 0x52, 0x45, 0x51, 0x55, 0x45, 0x53, 0x54, 0x2D, 0x2D, 0x2D,
    0x2D, 0x2D,
};
static const uint8_t *const k_wc_ref[WC_COUNT] = { k_wc_ref_0, k_wc_ref_1, k_wc_ref_2, k_wc_ref_3, k_wc_ref_4, k_wc_ref_5, k_wc_ref_6, k_wc_ref_7, k_wc_ref_8 };
static const uint32_t k_wc_ref_len[WC_COUNT] = { sizeof(k_wc_ref_0), sizeof(k_wc_ref_1), sizeof(k_wc_ref_2), sizeof(k_wc_ref_3), sizeof(k_wc_ref_4), sizeof(k_wc_ref_5), sizeof(k_wc_ref_6), sizeof(k_wc_ref_7), sizeof(k_wc_ref_8) };

static uint32_t s_wc_mismatch;

/* Read one DER TLV header at der[*pos]; on success *pos is advanced past the header and the
 * content length is returned in *clen. */
static int wc_der_header(const uint8_t *der, uint32_t len, uint32_t *pos, uint32_t *clen)
{
    uint32_t p = *pos;
    uint32_t n = 0U;
    uint32_t i;
    if((p + 2U) > len) { return -1; }
    p += 1U;  /* tag */
    if((der[p] & 0x80U) == 0U) {
        n = der[p];
        p += 1U;
    } else {
        uint32_t nb = der[p] & 0x7FU;
        p += 1U;
        if((nb == 0U) || (nb > 3U) || ((p + nb) > len)) { return -1; }
        for(i = 0U; i < nb; i++) { n = (n << 8) | der[p + i]; }
        p += nb;
    }
    if((p + n) > len) { return -1; }
    *pos = p;
    *clen = n;
    return 0;
}

/* Locate the to-be-signed part and algorithm of a signed object (SEQUENCE { info, algorithm,
 * signature BIT STRING }): sets *start to the first byte of info and returns the end of the
 * algorithm, i.e. the start of the signature. Returns 0 if the object is malformed. The outer
 * SEQUENCE header is excluded because its length changes with the signature size. */
static uint32_t wc_signed_span(const uint8_t *der, uint32_t len, uint32_t *start)
{
    uint32_t pos = 0U;
    uint32_t clen = 0U;
    if(wc_der_header(der, len, &pos, &clen) != 0) { return 0U; }        /* outer SEQUENCE */
    *start = pos;
    if(wc_der_header(der, len, &pos, &clen) != 0) { return 0U; }        /* info */
    pos += clen;
    if(wc_der_header(der, len, &pos, &clen) != 0) { return 0U; }        /* algorithm */
    pos += clen;
    if((pos >= len) || (der[pos] != 0x03U)) { return 0U; }               /* signature BIT STRING */
    return pos;
}

/* Decode a PEM body into out; returns the DER length or 0. */
static uint32_t wc_pem_to_der(const uint8_t *pem, uint32_t len, uint8_t *out, uint32_t out_max)
{
    static uint8_t b64[4096];
    uint32_t i;
    uint32_t n = 0U;
    int in_body = 0;
    int32_t dec;
    for(i = 0U; i < len; i++) {
        if(pem[i] == '-') {
            /* header or footer line: skip to end of line, toggling body state */
            while((i < len) && (pem[i] != '\n')) { i++; }
            in_body = !in_body;
            continue;
        }
        if((in_body != 0) && (pem[i] != '\r') && (pem[i] != '\n') && (n < sizeof(b64))) {
            b64[n] = pem[i];
            n++;
        }
    }
    if(((n / 4U) * 3U) > out_max) { return 0U; }
    dec = noxtls_base64_decode(b64, n, out);
    return (dec > 0) ? (uint32_t)dec : 0U;
}

/* ECDSA-signed outputs are signed with a random nonce k drawn from the PKC CTR_DRBG, so
 * only their to-be-signed part and algorithm are byte-compared (the signature value depends
 * on the DRBG construction, which changed for SP 800-90A conformance); the openssl
 * crosscheck verifies the signatures themselves. */
static int wc_is_randomized(const char *name)
{
    return ((strcmp(name, "wc_ex_ec.der") == 0) || (strcmp(name, "wc_csr_ec.der") == 0) ||
            (strcmp(name, "wc_csr_ec.pem") == 0)) ? 1 : 0;
}

static int wc_matches(uint32_t index, const char *name, const uint8_t *der, uint32_t len)
{
    static uint8_t a[2048];
    static uint8_t b[2048];
    uint32_t alen;
    uint32_t blen;
    uint32_t pa;
    uint32_t pb;
    uint32_t sa = 0U;
    uint32_t sb = 0U;
    if(wc_is_randomized(name) == 0) {
        return ((len == k_wc_ref_len[index]) && (memcmp(der, k_wc_ref[index], len) == 0)) ? 1 : 0;
    }
    if(strstr(name, ".pem") != NULL) {
        alen = wc_pem_to_der(der, len, a, sizeof(a));
        blen = wc_pem_to_der(k_wc_ref[index], k_wc_ref_len[index], b, sizeof(b));
    } else {
        if((len > sizeof(a)) || (k_wc_ref_len[index] > sizeof(b))) { return 0; }
        memcpy(a, der, len);
        memcpy(b, k_wc_ref[index], k_wc_ref_len[index]);
        alen = len;
        blen = k_wc_ref_len[index];
    }
    pa = wc_signed_span(a, alen, &sa);
    pb = wc_signed_span(b, blen, &sb);
    return ((pa != 0U) && (pb != 0U) && ((pa - sa) == (pb - sb)) && (memcmp(&a[sa], &b[sb], pa - sa) == 0)) ? 1 : 0;
}

static void wc_compare(uint32_t index, const char *name, const uint8_t *der, uint32_t len)
{
    if((index >= WC_COUNT) || (wc_matches(index, name, der, len) == 0)) {
        lb_log("writer output %s differs from the pre-change reference (len %u vs %u)", name, len,
               (index < WC_COUNT) ? k_wc_ref_len[index] : 0U);
        s_wc_mismatch += 1U;
    }
    write_artifact(name, der, len);
}

/* The writers encode in place: output must be byte-identical to the reference DER captured from
 * the previous staged implementation for the same inputs (Ed25519 signatures are deterministic;
 * for ECDSA only the signed part is compared), and no heap workspace is used. */
static int t_cert_write_corpus(void)
{
    lb_alloc_stats_t st;
    size_t base = lb_alloc_live_bytes();
    static uint8_t tight[4096];
    uint32_t out_len = 0U;
    uint8_t subject[64];
    uint32_t subject_len = 0U;
    static const uint8_t oid_ec[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
    static const uint8_t oid_sig_ecdsa[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };

    s_wc_mismatch = 0U;
    lb_alloc_reset_peak();
    LB_CHECK_EQ(wc_run(wc_compare), 0);
    lb_alloc_get_stats(&st);
    LB_CHECK_EQ(s_wc_mismatch, 0U);
    /* Previously 37146 B (28 KB certificate workspace + 7 KB extension workspaces); what remains
     * is the signer's private-key parse and ECC scratch. */
    lb_log("writer corpus heap peak above base: %lu B", (unsigned long)(st.peak_bytes - base));
    LB_CHECK((st.peak_bytes - base) < 12288U);  /* measured 9042 B on the host (signer only) */

    /* CSR PEM is encoded in place: an output buffer of exactly PEM length + NUL suffices
     * (Ed25519 so the signature is identical in both runs). */
    LB_CHECK_OK(noxtls_x509_dn_from_cn((const uint8_t *)"corpus.subject.test", subject, sizeof(subject), &subject_len));
    {
        static const uint8_t oid_ed_csr[] = { 0x2B, 0x65, 0x70 };
        uint32_t pem_len = 0U;
        LB_CHECK_OK(noxtls_x509_csr_create_pem(subject, subject_len, oid_ed_csr, sizeof(oid_ed_csr), lb_ed_server_pub,
                                               lb_ed_server_pub_len, oid_ed_csr, sizeof(oid_ed_csr), lb_ed_server_key,
                                               lb_ed_server_key_len, NOXTLS_HASH_SHA_256, s_buf, sizeof(s_buf), &pem_len));
        memset(tight, 0xA5, sizeof(tight));
        LB_CHECK_OK(noxtls_x509_csr_create_pem(subject, subject_len, oid_ed_csr, sizeof(oid_ed_csr), lb_ed_server_pub,
                                               lb_ed_server_pub_len, oid_ed_csr, sizeof(oid_ed_csr), lb_ed_server_key,
                                               lb_ed_server_key_len, NOXTLS_HASH_SHA_256, tight, pem_len + 1U, &out_len));
        LB_CHECK_EQ(out_len, pem_len);
        LB_CHECK(memcmp(tight, s_buf, pem_len) == 0);
        LB_CHECK_EQ(tight[pem_len], 0U);
        LB_CHECK_EQ(tight[pem_len + 1U], 0xA5U);  /* nothing written past out_max */
        LB_CHECK(noxtls_x509_csr_create_pem(subject, subject_len, oid_ed_csr, sizeof(oid_ed_csr), lb_ed_server_pub,
                                            lb_ed_server_pub_len, oid_ed_csr, sizeof(oid_ed_csr), lb_ed_server_key,
                                            lb_ed_server_key_len, NOXTLS_HASH_SHA_256, tight, pem_len, &out_len) !=
                 NOXTLS_RETURN_SUCCESS);
        (void)oid_ec;
        (void)oid_sig_ecdsa;
    }
    /* Certificate output stays inside out_max and fails cleanly when too small. */
    {
        static const uint8_t oid_ed[] = { 0x2B, 0x65, 0x70 };
        static const uint8_t serial[] = { 0x01 };
        uint32_t need = 0U;
        uint32_t cap;
        int ok_seen = 0;
        LB_CHECK_OK(noxtls_x509_certificate_generate_self_signed(serial, sizeof(serial), subject, subject_len, subject,
                    subject_len, (const uint8_t *)"250101000000Z", (const uint8_t *)"491231235959Z", oid_ed,
                    sizeof(oid_ed), lb_ed_server_pub, lb_ed_server_pub_len, oid_ed, sizeof(oid_ed), lb_ed_server_key,
                    lb_ed_server_key_len, NOXTLS_HASH_SHA_256, tight, sizeof(tight), &need));
        for(cap = need - 4U; cap <= (need + 40U); cap++) {
            noxtls_return_t rc;
            memset(tight, 0x5A, sizeof(tight));
            rc = noxtls_x509_certificate_generate_self_signed(serial, sizeof(serial), subject, subject_len, subject,
                    subject_len, (const uint8_t *)"250101000000Z", (const uint8_t *)"491231235959Z", oid_ed,
                    sizeof(oid_ed), lb_ed_server_pub, lb_ed_server_pub_len, oid_ed, sizeof(oid_ed), lb_ed_server_key,
                    lb_ed_server_key_len, NOXTLS_HASH_SHA_256, tight, cap, &out_len);
            LB_CHECK_EQ(tight[cap], 0x5AU);
            LB_CHECK((cap >= need) || (rc != NOXTLS_RETURN_SUCCESS));
            if(rc == NOXTLS_RETURN_SUCCESS) {
                ok_seen = 1;
                LB_CHECK_EQ(out_len, need);
                LB_CHECK(out_len <= cap);
                LB_RUN(parse(&s_tmp, tight, out_len));
                LB_CHECK_OK(noxtls_x509_certificate_verify_signature(&s_tmp, &s_tmp));
                (void)noxtls_x509_certificate_free(&s_tmp);
            }
        }
        LB_CHECK(ok_seen != 0);
        LB_CHECK(noxtls_x509_certificate_generate_self_signed(serial, sizeof(serial), subject, subject_len, subject,
                    subject_len, (const uint8_t *)"250101000000Z", (const uint8_t *)"491231235959Z", oid_ed,
                    sizeof(oid_ed), lb_ed_server_pub, lb_ed_server_pub_len, oid_ed, sizeof(oid_ed), lb_ed_server_key,
                    lb_ed_server_key_len, NOXTLS_HASH_SHA_256, tight, need - 1U, &out_len) != NOXTLS_RETURN_SUCCESS);
    }
    return lb_expect_no_leak(base, "cert write corpus");
}
#endif

/* openssl-generated EC P-256 self-signed certificate with 10 dNSName, rfc822Name, URI and IPv4/IPv6 SANs. */
static const uint8_t k_san_rich_cert[] = {
    0x30, 0x82, 0x02, 0x0F, 0x30, 0x82, 0x01, 0xB4, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x5A,
    0x11, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x28, 0x31,
    0x11, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x08, 0x73, 0x61, 0x6E, 0x2E, 0x74, 0x65,
    0x73, 0x74, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x0A, 0x4E, 0x6F, 0x78,
    0x54, 0x4C, 0x53, 0x20, 0x53, 0x41, 0x4E, 0x30, 0x20, 0x17, 0x0D, 0x32, 0x36, 0x31, 0x30, 0x32,
    0x34, 0x30, 0x37, 0x34, 0x34, 0x35, 0x32, 0x5A, 0x18, 0x0F, 0x32, 0x30, 0x35, 0x31, 0x30, 0x36,
    0x31, 0x35, 0x30, 0x37, 0x34, 0x34, 0x35, 0x32, 0x5A, 0x30, 0x28, 0x31, 0x11, 0x30, 0x0F, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x0C, 0x08, 0x73, 0x61, 0x6E, 0x2E, 0x74, 0x65, 0x73, 0x74, 0x31, 0x13,
    0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x0A, 0x4E, 0x6F, 0x78, 0x54, 0x4C, 0x53, 0x20,
    0x53, 0x41, 0x4E, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x71, 0x22,
    0x48, 0x62, 0xFA, 0xED, 0xF7, 0x13, 0x75, 0x1D, 0x34, 0x85, 0xAD, 0x5A, 0x95, 0xF0, 0xE5, 0x31,
    0x59, 0x4C, 0x0F, 0x97, 0x50, 0x6A, 0xCA, 0xAF, 0x31, 0xCB, 0xBF, 0x22, 0x01, 0x3D, 0x26, 0xAB,
    0xBD, 0x5B, 0x1A, 0x0A, 0x7F, 0x5E, 0xE1, 0xC2, 0xFC, 0x25, 0xB0, 0x66, 0x64, 0xB9, 0x20, 0xCA,
    0x38, 0xFB, 0x08, 0xEB, 0x1D, 0xAE, 0x9A, 0xF9, 0x53, 0x51, 0x25, 0x58, 0xA5, 0x65, 0xA3, 0x81,
    0xCB, 0x30, 0x81, 0xC8, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x02,
    0x30, 0x00, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30,
    0x81, 0xAA, 0x06, 0x03, 0x55, 0x1D, 0x11, 0x04, 0x81, 0xA2, 0x30, 0x81, 0x9F, 0x82, 0x07, 0x6E,
    0x31, 0x2E, 0x74, 0x65, 0x73, 0x74, 0x82, 0x07, 0x6E, 0x32, 0x2E, 0x74, 0x65, 0x73, 0x74, 0x82,
    0x07, 0x6E, 0x33, 0x2E, 0x74, 0x65, 0x73, 0x74, 0x82, 0x07, 0x6E, 0x34, 0x2E, 0x74, 0x65, 0x73,
    0x74, 0x82, 0x07, 0x6E, 0x35, 0x2E, 0x74, 0x65, 0x73, 0x74, 0x82, 0x07, 0x6E, 0x36, 0x2E, 0x74,
    0x65, 0x73, 0x74, 0x82, 0x07, 0x6E, 0x37, 0x2E, 0x74, 0x65, 0x73, 0x74, 0x82, 0x07, 0x6E, 0x38,
    0x2E, 0x74, 0x65, 0x73, 0x74, 0x82, 0x0A, 0x6E, 0x69, 0x6E, 0x74, 0x68, 0x2E, 0x74, 0x65, 0x73,
    0x74, 0x82, 0x0A, 0x74, 0x65, 0x6E, 0x74, 0x68, 0x2E, 0x74, 0x65, 0x73, 0x74, 0x81, 0x0E, 0x61,
    0x64, 0x6D, 0x69, 0x6E, 0x40, 0x73, 0x61, 0x6E, 0x2E, 0x74, 0x65, 0x73, 0x74, 0x86, 0x15, 0x68,
    0x74, 0x74, 0x70, 0x73, 0x3A, 0x2F, 0x2F, 0x73, 0x61, 0x6E, 0x2E, 0x74, 0x65, 0x73, 0x74, 0x2F,
    0x70, 0x61, 0x74, 0x68, 0x87, 0x04, 0xC0, 0x00, 0x02, 0x07, 0x87, 0x10, 0x20, 0x01, 0x0D, 0xB8,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x30, 0x0A, 0x06, 0x08,
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21, 0x00,
    0x88, 0x2D, 0x47, 0xDF, 0x0A, 0x0E, 0x57, 0x0C, 0xC1, 0xF8, 0xFF, 0x13, 0x80, 0x49, 0x5C, 0xC5,
    0x0C, 0x34, 0x83, 0xB9, 0xB5, 0x86, 0x04, 0xC0, 0xF8, 0xAB, 0x6A, 0x63, 0xB9, 0x90, 0x48, 0x64,
    0x02, 0x21, 0x00, 0xFE, 0x03, 0x58, 0xBE, 0x81, 0xF6, 0xFB, 0x30, 0x0B, 0x4B, 0x44, 0x48, 0x19,
    0xF7, 0x9F, 0x54, 0xE4, 0xF3, 0x68, 0x1E, 0xD7, 0xE7, 0xE4, 0xB5, 0xF4, 0xBA, 0x59, 0x11, 0xB4,
    0xF3, 0x6B, 0x31,
};

/** 1 when [p, p + n) lies inside [base, base + base_len). */
static int in_buf(const uint8_t *p, uint32_t n, const uint8_t *base, uint32_t base_len)
{
    return ((p != NULL) && (p >= base) && ((p + n) <= (base + base_len))) ? 1 : 0;
}

static int t_borrow_accessors(void)
{
    const uint8_t *v = NULL;
    uint32_t v_len = 0U;
    const uint8_t *k = NULL;
    uint32_t k_len = 0U;
    int64_t nb = 0;
    int64_t na = 0;
    lb_alloc_stats_t st;
    size_t base = lb_alloc_live_bytes();
    size_t base_blocks = lb_alloc_live_blocks();
    const uint8_t *der = lb_ec_server_cert;
    const uint32_t der_len = lb_ec_server_cert_len;

    /* Borrow mode: nothing stays allocated, every view points into the caller's DER (EC point
     * validation during parse uses transient ECC scratch only). An RSA leaf needs no heap at all. */
    (void)noxtls_x509_certificate_init(&s_leaf);
    lb_alloc_reset_counters();
    LB_CHECK_OK(noxtls_x509_certificate_parse_der_nocopy(&s_leaf, lb_rsa_server_cert, lb_rsa_server_cert_len));
    lb_alloc_get_stats(&st);
    LB_CHECK_EQ(st.alloc_calls, 0U);
    LB_CHECK(s_leaf.raw_data == lb_rsa_server_cert);
    LB_CHECK(in_buf(s_leaf.rsa_modulus, s_leaf.rsa_modulus_len, lb_rsa_server_cert, lb_rsa_server_cert_len));
    (void)noxtls_x509_certificate_free(&s_leaf);
    LB_CHECK_OK(noxtls_x509_certificate_parse_der_nocopy(&s_leaf, der, der_len));
    LB_CHECK_EQ(lb_alloc_live_bytes(), base);
    LB_CHECK_OK(noxtls_x509_certificate_get_der(&s_leaf, &v, &v_len));
    LB_CHECK((v == der) && (v_len == der_len));
    LB_CHECK_OK(noxtls_x509_certificate_get_tbs(&s_leaf, &v, &v_len));
    LB_CHECK(in_buf(v, v_len, der, der_len) && (v[0] == 0x30U));
    LB_CHECK_OK(noxtls_x509_certificate_get_serial(&s_leaf, &v, &v_len));
    LB_CHECK(in_buf(v, v_len, der, der_len));
    LB_CHECK(xf_serial_eq(&s_leaf, LB_PKI_SERIAL_EC_SERVER));
    LB_CHECK_OK(noxtls_x509_certificate_get_subject_der(&s_leaf, &v, &v_len));
    LB_CHECK(in_buf(v, v_len, der, der_len));
    LB_CHECK((v_len + 2U == lb_ec_server_subject_der_len) && (memcmp(v, &lb_ec_server_subject_der[2], v_len) == 0));
    LB_CHECK_OK(noxtls_x509_certificate_get_issuer_der(&s_leaf, &v, &v_len));
    LB_CHECK(in_buf(v, v_len, der, der_len));
    LB_CHECK_OK(noxtls_x509_certificate_get_signature_algorithm(&s_leaf, &v, &v_len));
    LB_CHECK(in_buf(v, v_len, der, der_len) && (v_len == 8U));
    LB_CHECK_OK(noxtls_x509_certificate_get_signature(&s_leaf, &v, &v_len));
    LB_CHECK(in_buf(v, v_len, der, der_len) && (v[0] == 0x30U));
    LB_CHECK((v + v_len) == (der + der_len));
    LB_CHECK_OK(noxtls_x509_certificate_get_public_key_info(&s_leaf, &v, &v_len, &k, &k_len));
    LB_CHECK(in_buf(v, v_len, der, der_len) && in_buf(k, k_len, der, der_len));
    LB_CHECK((k_len == lb_ec_server_point_len) && (memcmp(k, lb_ec_server_point, k_len) == 0));
    LB_CHECK_OK(noxtls_x509_certificate_get_subject_key_id(&s_leaf, &v, &v_len));
    LB_CHECK((v_len == lb_ec_server_ski_len) && (memcmp(v, lb_ec_server_ski, v_len) == 0));
    LB_CHECK_OK(noxtls_x509_certificate_get_authority_key_id(&s_leaf, &v, &v_len));
    LB_CHECK((v_len == lb_ec_int_ski_len) && (memcmp(v, lb_ec_int_ski, v_len) == 0));
    LB_CHECK_OK(noxtls_x509_certificate_get_validity(&s_leaf, &nb, &na));
    LB_CHECK_EQ(nb, LB_PKI_NOT_BEFORE);
    LB_CHECK_EQ(na, LB_PKI_NOT_AFTER);
    {
        const uint8_t *tb = NULL;
        const uint8_t *ta = NULL;
        uint32_t tb_len = 0U;
        uint32_t ta_len = 0U;
        LB_CHECK_OK(noxtls_x509_certificate_get_validity_raw(&s_leaf, &tb, &tb_len, &ta, &ta_len));
        LB_CHECK(in_buf(tb, tb_len, der, der_len) && in_buf(ta, ta_len, der, der_len));
    }
    LB_CHECK(strstr(xf_subject_dn(&s_leaf), "server.test") != NULL);
    LB_CHECK(strstr(xf_issuer_dn(&s_leaf), "NoxTLS Test EC Intermediate") != NULL);
    /* SPKI OID straight from the DER (used by the TLS 1.3 PSS leaf check). */
    LB_CHECK_OK(noxtls_x509_der_get_spki_algorithm(der, der_len, &k, &k_len));
    LB_CHECK_OK(noxtls_x509_certificate_get_public_key_info(&s_leaf, &v, &v_len, NULL, NULL));
    LB_CHECK((k == v) && (k_len == v_len));
    LB_CHECK(noxtls_x509_der_get_spki_algorithm(der, der_len - 1U, &k, &k_len) != NOXTLS_RETURN_SUCCESS);
    /* Borrowed issuer chain verifies and matches hostnames without heap. */
    (void)noxtls_x509_certificate_init(&s_int);
    (void)noxtls_x509_certificate_init(&s_root);
    LB_CHECK_OK(noxtls_x509_certificate_parse_der_nocopy(&s_int, lb_ec_int_cert, lb_ec_int_cert_len));
    LB_CHECK_OK(noxtls_x509_certificate_parse_der_nocopy(&s_root, lb_ec_root_cert, lb_ec_root_cert_len));
    LB_CHECK_EQ(lb_alloc_live_bytes(), base);
    lb_alloc_reset_counters();
    LB_CHECK_OK(noxtls_x509_certificate_matches_hostname(&s_leaf, (const uint8_t *)"alt.test", 0U));
    LB_CHECK_OK(noxtls_x509_certificate_matches_hostname(&s_leaf, (const uint8_t *)"x.wild.test", 0U));
    lb_alloc_get_stats(&st);
    LB_CHECK_EQ(st.alloc_calls, 0U);  /* hostname matching walks the DER, no heap */
    LB_CHECK_OK(noxtls_x509_certificate_verify_signature(&s_leaf, &s_int));
    LB_CHECK_OK(noxtls_x509_certificate_verify_signature(&s_int, &s_root));
    /* A chain copy of a borrowed certificate owns its DER: it survives freeing the source. */
    {
        x509_certificate_chain_t chain;
        LB_CHECK_OK(noxtls_x509_certificate_chain_init(&chain));
        LB_CHECK_OK(noxtls_x509_certificate_chain_add(&chain, &s_int));
        (void)noxtls_x509_certificate_free(&s_int);
        LB_CHECK(xf_chain_cert(&chain, 0U)->raw_data != lb_ec_int_cert);
        LB_CHECK_OK(noxtls_x509_certificate_verify_signature(&s_leaf, xf_chain_cert(&chain, 0U)));
        (void)noxtls_x509_certificate_chain_free(&chain);
    }
    (void)noxtls_x509_certificate_free(&s_leaf);
    (void)noxtls_x509_certificate_free(&s_root);
    LB_CHECK_EQ(lb_alloc_live_bytes(), base);
    /* Freed certificates expose nothing. */
    LB_CHECK(noxtls_x509_certificate_get_der(&s_leaf, &v, &v_len) != NOXTLS_RETURN_SUCCESS);
    LB_CHECK(noxtls_x509_certificate_get_subject_dn(&s_leaf, (uint8_t *)s_xf_text[0], 8U) != NOXTLS_RETURN_SUCCESS);

    /* Copy mode: the DER copy is the only persistent allocation (no tbs/sig/key/ext duplicates). */
    LB_RUN(parse(&s_leaf, lb_ec_server_cert, lb_ec_server_cert_len));
    LB_CHECK_EQ(lb_alloc_live_bytes() - base, (size_t)lb_ec_server_cert_len);
    LB_CHECK_EQ(lb_alloc_live_blocks(), base_blocks + 1U);
    (void)noxtls_x509_certificate_free(&s_leaf);
    lb_alloc_reset_counters();
    LB_RUN(parse(&s_leaf, lb_rsa_server_cert, lb_rsa_server_cert_len));
    lb_alloc_get_stats(&st);
    LB_CHECK_EQ(st.alloc_calls, 1U);
    LB_CHECK_EQ(lb_alloc_live_bytes() - base, (size_t)lb_rsa_server_cert_len);
    LB_CHECK(xf_rsa_modulus_eq(&s_leaf, lb_rsa_server_modulus, lb_rsa_server_modulus_len));
    (void)noxtls_x509_certificate_free(&s_leaf);
    lb_log("x509_certificate_t = %u bytes on this host; EC leaf heap = %u B (DER), RSA leaf heap = %u B (DER)",
           (unsigned)sizeof(x509_certificate_t), lb_ec_server_cert_len, lb_rsa_server_cert_len);
    return lb_expect_no_leak(base, "borrow/accessors");
}

static int t_san_iterator(void)
{
    static const char *const dns[10] = { "n1.test", "n2.test", "n3.test", "n4.test", "n5.test",
                                         "n6.test", "n7.test", "n8.test", "ninth.test", "tenth.test" };
    static const uint8_t ip4[4] = { 192U, 0U, 2U, 7U };
    static const uint8_t ip6[16] = { 0x20U, 0x01U, 0x0DU, 0xB8U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U };
    noxtls_x509_san_iter_t it;
    const uint8_t *v = NULL;
    uint32_t v_len = 0U;
    uint32_t i;
    int has = 1;
    uint32_t seen = 0U;
    size_t base = lb_alloc_live_bytes();

    LB_RUN(parse(&s_tmp, k_san_rich_cert, (uint32_t)sizeof(k_san_rich_cert)));
    /* Every dNSName is visible (the old table stopped at 8 names). */
    LB_CHECK_EQ(xf_san_count(&s_tmp), 10U);
    for(i = 0U; i < 10U; i++) {
        LB_CHECK(strcmp(xf_san(&s_tmp, i), dns[i]) == 0);
    }
    LB_CHECK(noxtls_x509_certificate_get_san(&s_tmp, NOXTLS_X509_SAN_DNS, 10U, &v, &v_len) == NOXTLS_RETURN_FAILED);
    LB_CHECK_OK(noxtls_x509_certificate_matches_hostname(&s_tmp, (const uint8_t *)"tenth.test", 0U));
    LB_CHECK(noxtls_x509_certificate_matches_hostname(&s_tmp, (const uint8_t *)"san.test", 0U) != NOXTLS_RETURN_SUCCESS);
    /* rfc822Name, URI and iPAddress stay available through the accessor API. */
    LB_CHECK_EQ(noxtls_x509_certificate_san_count(&s_tmp, NOXTLS_X509_SAN_EMAIL), 1U);
    LB_CHECK_OK(noxtls_x509_certificate_get_san(&s_tmp, NOXTLS_X509_SAN_EMAIL, 0U, &v, &v_len));
    LB_CHECK((v_len == 14U) && (memcmp(v, "admin@san.test", 14U) == 0));
    LB_CHECK_EQ(noxtls_x509_certificate_san_count(&s_tmp, NOXTLS_X509_SAN_URI), 1U);
    LB_CHECK_OK(noxtls_x509_certificate_get_san(&s_tmp, NOXTLS_X509_SAN_URI, 0U, &v, &v_len));
    LB_CHECK((v_len == 21U) && (memcmp(v, "https://san.test/path", 21U) == 0));
    LB_CHECK_EQ(noxtls_x509_certificate_san_count(&s_tmp, NOXTLS_X509_SAN_IP), 2U);
    LB_CHECK_OK(noxtls_x509_certificate_get_san(&s_tmp, NOXTLS_X509_SAN_IP, 0U, &v, &v_len));
    LB_CHECK((v_len == 4U) && (memcmp(v, ip4, 4U) == 0));
    LB_CHECK_OK(noxtls_x509_certificate_get_san(&s_tmp, NOXTLS_X509_SAN_IP, 1U, &v, &v_len));
    LB_CHECK((v_len == 16U) && (memcmp(v, ip6, 16U) == 0));
    LB_CHECK_EQ(noxtls_x509_certificate_san_count(&s_tmp, NOXTLS_X509_SAN_ANY), 14U);
    /* Raw iteration returns the entries in certificate order. */
    LB_CHECK_OK(noxtls_x509_san_iter_init(&it, &s_tmp));
    while(has != 0) {
        uint8_t type = 0U;
        LB_CHECK_OK(noxtls_x509_san_iter_next(&it, &type, &v, &v_len, &has));
        if(has != 0) {
            LB_CHECK(in_buf(v, v_len, s_tmp.raw_data, s_tmp.raw_data_len));
            if(seen < 10U) {
                LB_CHECK_EQ(type, NOXTLS_X509_SAN_DNS);
            }
            seen++;
        }
    }
    LB_CHECK_EQ(seen, 14U);
    /* Iteration past the end stays at the end. */
    {
        uint8_t type = 0xEEU;
        LB_CHECK_OK(noxtls_x509_san_iter_next(&it, &type, &v, &v_len, &has));
    }
    LB_CHECK_EQ(has, 0);
    (void)noxtls_x509_certificate_free(&s_tmp);
    /* No SAN extension: empty iteration; not parsed: refused. */
    LB_RUN(parse(&s_tmp, lb_ec_int_cert, lb_ec_int_cert_len));
    LB_CHECK_EQ(noxtls_x509_certificate_san_count(&s_tmp, NOXTLS_X509_SAN_ANY), 0U);
    (void)noxtls_x509_certificate_free(&s_tmp);
    LB_CHECK(noxtls_x509_san_iter_init(&it, &s_tmp) == NOXTLS_RETURN_FAILED);
    LB_CHECK(noxtls_x509_san_iter_init(NULL, &s_tmp) == NOXTLS_RETURN_NULL);
    return lb_expect_no_leak(base, "san iterator");
}

static int t_strict_der(void)
{
    uint32_t len = lb_ec_server_cert_len;
    size_t base = lb_alloc_live_bytes();

    /* Outer SEQUENCE length one short of its contents: the signature BIT STRING would end
     * outside the Certificate SEQUENCE. Strict DER rejects it. */
    memcpy(s_buf, lb_ec_server_cert, len);
    LB_CHECK((s_buf[0] == 0x30U) && (s_buf[1] == 0x82U));
    s_buf[3] = (uint8_t)(s_buf[3] - 1U);
    (void)noxtls_x509_certificate_init(&s_tmp);
    LB_CHECK_EQ(noxtls_x509_certificate_parse_der(&s_tmp, s_buf, len), NOXTLS_RETURN_CERT_PARSE_FAILED);
    LB_CHECK_EQ(noxtls_x509_certificate_parse_der(&s_tmp, s_buf, len - 1U), NOXTLS_RETURN_CERT_PARSE_FAILED);
    /* Outer SEQUENCE longer than the input. */
    memcpy(s_buf, lb_ec_server_cert, len);
    s_buf[3] = (uint8_t)(s_buf[3] + 1U);
    LB_CHECK_EQ(noxtls_x509_certificate_parse_der(&s_tmp, s_buf, len), NOXTLS_RETURN_CERT_PARSE_FAILED);
    /* Outer length covering one extra byte of slack after the signature. */
    memcpy(s_buf, lb_ec_server_cert, len);
    s_buf[3] = (uint8_t)(s_buf[3] + 1U);
    s_buf[len] = 0x00U;
    LB_CHECK_EQ(noxtls_x509_certificate_parse_der(&s_tmp, s_buf, len + 1U), NOXTLS_RETURN_CERT_PARSE_FAILED);
    /* Trailing bytes after a valid Certificate SEQUENCE. */
    memcpy(s_buf, lb_ec_server_cert, len);
    s_buf[len] = 0x00U;
    LB_CHECK_EQ(noxtls_x509_certificate_parse_der(&s_tmp, s_buf, len + 1U), NOXTLS_RETURN_CERT_PARSE_FAILED);
    LB_CHECK_EQ(noxtls_x509_certificate_parse_der_nocopy(&s_tmp, s_buf, len + 1U), NOXTLS_RETURN_CERT_PARSE_FAILED);
    /* The exact input still parses. */
    LB_CHECK_OK(noxtls_x509_certificate_parse_der_nocopy(&s_tmp, s_buf, len));
    (void)noxtls_x509_certificate_free(&s_tmp);
    return lb_expect_no_leak(base, "strict der");
}

#if defined(NOXTLS_HAVE_CERT_WRITE) && NOXTLS_HAVE_CERT_WRITE
/* Names whose DER differs (UTF8String vs PrintableString, case, spaces) but which are equal
 * under RFC 5280 Section 7.1 / RFC 4518 caseIgnoreMatch. */
static const uint8_t k_name_case_root_utf8[] = {
    0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0A,
    'C', 'a', 's', 'e', ' ', ' ', 'R', 'o', 'o', 't'
};
static const uint8_t k_name_case_root_printable[] = {
    0x30, 0x16, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0B,
    ' ', 'c', 'a', 's', 'e', ' ', 'r', 'o', 'o', 't', ' '
};
static const uint8_t k_name_case_other[] = {
    0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0A,
    'C', 'a', 's', 'e', ' ', 'R', 'o', 'o', 'o', 't'
};

static int gen_cert(const uint8_t *issuer, uint32_t issuer_len, const uint8_t *subject, uint32_t subject_len,
                    int ec_subject_key, uint8_t *out, uint32_t out_max, uint32_t *out_len)
{
    static const uint8_t oid_ec[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
    static const uint8_t oid_sig[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
    static const uint8_t p256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
    static const uint8_t oid_ed[] = { 0x2B, 0x65, 0x70 };
    static const uint8_t serial[] = { 0x01, 0x77 };
    return (noxtls_x509_certificate_generate_self_signed_ex(
                serial, sizeof(serial), issuer, issuer_len, subject, subject_len,
                (const uint8_t *)"250101000000Z", (const uint8_t *)"491231235959Z",
                (ec_subject_key != 0) ? oid_ec : oid_ed, (ec_subject_key != 0) ? sizeof(oid_ec) : sizeof(oid_ed),
                (ec_subject_key != 0) ? p256 : NULL, (ec_subject_key != 0) ? sizeof(p256) : 0U,
                (ec_subject_key != 0) ? lb_ec_csr_point : lb_ed_server_pub,
                (ec_subject_key != 0) ? lb_ec_csr_point_len : lb_ed_server_pub_len,
                oid_sig, sizeof(oid_sig), lb_ec_csr_key, lb_ec_csr_key_len, NOXTLS_HASH_SHA_256,
                out, out_max, out_len) == NOXTLS_RETURN_SUCCESS) ? 0 : 1;
}

static int t_issuer_name_rfc5280(void)
{
    uint8_t root_der[1024];
    uint8_t leaf_der[1024];
    uint32_t root_len = 0U;
    uint32_t leaf_len = 0U;
    uint8_t leaf_subject[64];
    uint32_t leaf_subject_len = 0U;
    x509_certificate_chain_t anchors;
    noxtls_x509_verify_policy_t policy;
    size_t base = lb_alloc_live_bytes();

    LB_CHECK_OK(noxtls_x509_dn_from_cn((const uint8_t *)"leaf.case.test", leaf_subject, sizeof(leaf_subject),
                                       &leaf_subject_len));
    LB_RUN(gen_cert(k_name_case_root_utf8, sizeof(k_name_case_root_utf8), k_name_case_root_utf8,
                    sizeof(k_name_case_root_utf8), 1, root_der, sizeof(root_der), &root_len));
    LB_RUN(gen_cert(k_name_case_root_printable, sizeof(k_name_case_root_printable), leaf_subject, leaf_subject_len,
                    0, leaf_der, sizeof(leaf_der), &leaf_len));
    LB_CHECK_OK(noxtls_x509_certificate_chain_init(&anchors));
    LB_RUN(parse(&s_root, root_der, root_len));
    LB_CHECK_OK(noxtls_x509_certificate_chain_add(&anchors, &s_root));
    LB_RUN(parse(&s_leaf, leaf_der, leaf_len));
    /* The DER differs, the leaf signature verifies with the root key. */
    LB_CHECK(!xf_issuer_eq_subject(&s_leaf, &s_root));
    LB_CHECK_OK(noxtls_x509_certificate_verify_signature(&s_leaf, &s_root));
    memset(&policy, 0, sizeof(policy));
    policy.trust_anchors = &anchors;
    policy.time_mode = NOXTLS_X509_TIME_EXPLICIT;
    policy.verify_time = T_VALID;
    /* Name matching is per RDN on the DER (type / case / space insensitive for strings). */
    LB_CHECK_OK(noxtls_x509_verify_cert_with_policy(&s_leaf, NULL, &policy, NULL));
    (void)noxtls_x509_certificate_free(&s_leaf);
    /* A different name never matches, even with a key that verifies. */
    LB_RUN(gen_cert(k_name_case_other, sizeof(k_name_case_other), leaf_subject, leaf_subject_len, 0,
                    leaf_der, sizeof(leaf_der), &leaf_len));
    LB_RUN(parse(&s_leaf, leaf_der, leaf_len));
    LB_CHECK_OK(noxtls_x509_certificate_verify_signature(&s_leaf, &s_root));
    LB_CHECK_EQ(noxtls_x509_verify_cert_with_policy(&s_leaf, NULL, &policy, NULL), NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
    (void)noxtls_x509_certificate_free(&s_leaf);
    (void)noxtls_x509_certificate_free(&s_root);
    (void)noxtls_x509_certificate_chain_free(&anchors);
    return lb_expect_no_leak(base, "issuer name rfc5280");
}
#endif


static int t_chain_lazy(void)
{
    x509_certificate_chain_t chain;
    lb_alloc_stats_t st;
    size_t base = lb_alloc_live_bytes();
    uint32_t i;
    const uint8_t *ders[3] = { lb_ec_server_cert, lb_ec_int_cert, lb_ec_root_cert };
    uint32_t lens[3];

    lens[0] = lb_ec_server_cert_len;
    lens[1] = lb_ec_int_cert_len;
    lens[2] = lb_ec_root_cert_len;
    /* init allocates nothing; free of an empty chain is fine. */
    lb_alloc_reset_counters();
    LB_CHECK_OK(noxtls_x509_certificate_chain_init(&chain));
    lb_alloc_get_stats(&st);
    LB_CHECK_EQ(st.alloc_calls, 0U);
    LB_CHECK((chain.certs == NULL) && (chain.capacity == 0U) && (chain.count == 0U));
    LB_CHECK_OK(noxtls_x509_certificate_chain_free(&chain));
    /* add_der parses straight into a slot: 3 certificates = 3 DER copies + 3 slots, and the
     * largest contiguous block is max(DER, 3 slots) (was one 3 x 8 KB object). */
    LB_CHECK_OK(noxtls_x509_certificate_chain_init(&chain));
    for(i = 0U; i < 3U; i++) {
        LB_CHECK_OK(noxtls_x509_certificate_chain_add_der(&chain, ders[i], lens[i]));
    }
    LB_CHECK_EQ(xf_chain_count(&chain), 3U);
    LB_CHECK_EQ(lb_alloc_live_bytes() - base,
                (size_t)(lens[0] + lens[1] + lens[2]) + (3U * sizeof(x509_certificate_t)));
    lb_alloc_get_stats(&st);
    LB_CHECK(st.largest_block <= ((3U * sizeof(x509_certificate_t) > lens[0]) ? 3U * sizeof(x509_certificate_t) : lens[0]));
    LB_CHECK_OK(noxtls_x509_certificate_chain_verify(&chain));
    /* A bad certificate leaves the chain unchanged. */
    LB_CHECK(noxtls_x509_certificate_chain_add_der(&chain, lb_ec_root_cert, lb_ec_root_cert_len - 1U) != NOXTLS_RETURN_SUCCESS);
    LB_CHECK_EQ(xf_chain_count(&chain), 3U);
    LB_CHECK(noxtls_x509_certificate_chain_add_der(&chain, NULL, 4U) == NOXTLS_RETURN_NULL);
    (void)noxtls_x509_certificate_chain_free(&chain);
    LB_CHECK_EQ(lb_alloc_live_bytes(), base);
    /* Borrow mode: only the slots are allocated; reserve() sizes them exactly. */
    LB_CHECK_OK(noxtls_x509_certificate_chain_init(&chain));
    LB_CHECK_OK(noxtls_x509_certificate_chain_reserve(&chain, 3U));
    for(i = 0U; i < 3U; i++) {
        LB_CHECK_OK(noxtls_x509_certificate_chain_add_der_nocopy(&chain, ders[i], lens[i]));
        LB_CHECK(xf_chain_cert(&chain, i)->raw_data == ders[i]);
    }
    LB_CHECK_EQ(chain.capacity, 3U);
    LB_CHECK_EQ(lb_alloc_live_bytes() - base, 3U * sizeof(x509_certificate_t));
    LB_CHECK_OK(noxtls_x509_certificate_chain_verify(&chain));
    (void)noxtls_x509_certificate_chain_free(&chain);
    return lb_expect_no_leak(base, "chain lazy");
}

/** Build an application chain of the first @p n anchors (owned DER copies). */
static int anchors_of(x509_certificate_chain_t *chain, uint32_t n, uint32_t *der_total)
{
    const uint8_t *roots[5] = { lb_ec_root_cert, lb_ec_root2_cert, lb_ec_root3_cert, lb_rsa_root_cert, lb_ed_root_cert };
    uint32_t lens[5];
    uint32_t i;

    lens[0] = lb_ec_root_cert_len;
    lens[1] = lb_ec_root2_cert_len;
    lens[2] = lb_ec_root3_cert_len;
    lens[3] = lb_rsa_root_cert_len;
    lens[4] = lb_ed_root_cert_len;
    *der_total = 0U;
    LB_CHECK_OK(noxtls_x509_certificate_chain_init(chain));
    for(i = 0U; i < n; i++) {
        LB_CHECK_OK(noxtls_x509_certificate_chain_add_der(chain, roots[i], lens[i]));
        *der_total += lens[i];
    }
    return 0;
}

/** The EC server leaf (with its intermediate) verifies against the current global store. */
static int verify_ec_leaf_with_store(void)
{
    x509_certificate_chain_t presented;
    const uint8_t *ints[1] = { lb_ec_int_cert };
    uint32_t int_lens[1];
    noxtls_return_t rc;

    int_lens[0] = lb_ec_int_cert_len;
    LB_RUN(chain_of(&presented, ints, int_lens, 1U));
    rc = verify_server(lb_ec_server_cert, lb_ec_server_cert_len, &presented);
    (void)noxtls_x509_certificate_chain_free(&presented);
    LB_CHECK_OK(rc);
    return 0;
}

static int t_trust_store_memory(void)
{
    static const uint32_t ns[3] = { 1U, 3U, 5U };
    x509_certificate_chain_t app;
    uint32_t der_total = 0U;
    uint32_t k;
    size_t base = lb_alloc_live_bytes();

    for(k = 0U; k < 3U; k++) {
        uint32_t n = ns[k];
        size_t before;
        size_t before_blocks;
        size_t copy_bytes;
        lb_alloc_stats_t st;

        LB_RUN(anchors_of(&app, n, &der_total));
        /* Copy: exactly n slots + one DER copy per anchor; no doubling, no oversized block. */
        before = lb_alloc_live_bytes();
        before_blocks = lb_alloc_live_blocks();
        lb_alloc_reset_peak();
        lb_alloc_reset_counters();
        LB_CHECK_OK(noxtls_x509_trust_store_set(&app));
        copy_bytes = lb_alloc_live_bytes() - before;
        lb_alloc_get_stats(&st);
        LB_CHECK_EQ(copy_bytes, (size_t)der_total + ((size_t)n * sizeof(x509_certificate_t)));
        LB_CHECK_EQ(lb_alloc_live_blocks() - before_blocks, (size_t)n + 1U);  /* slot array + n DER copies */
        LB_CHECK(st.largest_block <= ((n * sizeof(x509_certificate_t) > 1024U) ? n * sizeof(x509_certificate_t) : 1024U));
        LB_CHECK_EQ(noxtls_x509_trust_store_has_anchors(), 1);
        LB_RUN(verify_ec_leaf_with_store());
        lb_log("trust store N=%u: copy %lu B (DER %u B + %u x %u B slots), app chain %lu B",
               n, (unsigned long)copy_bytes, der_total, n, (unsigned)sizeof(x509_certificate_t),
               (unsigned long)(before - base));
        /* Setting again replaces the copy (no growth). */
        LB_CHECK_OK(noxtls_x509_trust_store_set(&app));
        LB_CHECK_EQ(lb_alloc_live_bytes() - before, copy_bytes);
        /* Borrowed: zero bytes, the application chain is used in place. */
        LB_CHECK_OK(noxtls_x509_trust_store_set_borrowed(&app));
        LB_CHECK_EQ(lb_alloc_live_bytes(), before);
        LB_RUN(verify_ec_leaf_with_store());
        /* Move: zero bytes, the application chain is emptied and owned by the store. */
        LB_CHECK_OK(noxtls_x509_trust_store_set_move(&app));
        LB_CHECK_EQ(lb_alloc_live_bytes(), before);
        LB_CHECK((app.certs == NULL) && (app.count == 0U));
        LB_RUN(verify_ec_leaf_with_store());
        lb_trust_clear();
        LB_CHECK_EQ(lb_alloc_live_bytes(), base);
        LB_CHECK_EQ(noxtls_x509_trust_store_has_anchors(), 0);
        LB_CHECK_OK(noxtls_x509_certificate_chain_free(&app));
    }
    /* Lightweight anchors over const DER: one slot array, the DER is not copied. */
    {
        const uint8_t *roots[3] = { lb_ec_root2_cert, lb_ec_root3_cert, lb_ec_root_cert };
        uint32_t lens[3];
        lens[0] = lb_ec_root2_cert_len;
        lens[1] = lb_ec_root3_cert_len;
        lens[2] = lb_ec_root_cert_len;
        LB_CHECK_OK(noxtls_x509_trust_store_set_der_nocopy(roots, lens, 3U));
        LB_CHECK_EQ(lb_alloc_live_bytes() - base, 3U * sizeof(x509_certificate_t));
        LB_RUN(verify_ec_leaf_with_store());
        LB_CHECK(noxtls_x509_trust_store_set_der_nocopy(roots, lens, 0U) == NOXTLS_RETURN_SUCCESS);
        LB_CHECK_EQ(noxtls_x509_trust_store_has_anchors(), 0);
        lens[0] = 5U;
        LB_CHECK(noxtls_x509_trust_store_set_der_nocopy(roots, lens, 3U) != NOXTLS_RETURN_SUCCESS);
        LB_CHECK_EQ(noxtls_x509_trust_store_has_anchors(), 0);  /* fails closed */
    }
    /* Allocation failure while copying leaves the store empty. */
    LB_RUN(anchors_of(&app, 3U, &der_total));
    lb_alloc_fail_after(2U);
    LB_CHECK(noxtls_x509_trust_store_set(&app) != NOXTLS_RETURN_SUCCESS);
    lb_alloc_fail_after(SIZE_MAX);
    LB_CHECK_EQ(noxtls_x509_trust_store_has_anchors(), 0);
    LB_CHECK_OK(noxtls_x509_certificate_chain_free(&app));
    lb_trust_clear();
    return lb_expect_no_leak(base, "trust store memory");
}

/* openssl-generated RSA-2048 certificate whose SubjectPublicKeyInfo is id-RSASSA-PSS (RFC 4055). */
static const uint8_t k_rsa_pss_cert[] = {
    0x30, 0x82, 0x03, 0x57, 0x30, 0x82, 0x02, 0x0E, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x70,
    0x55, 0x30, 0x3E, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A, 0x30, 0x31,
    0xA0, 0x0D, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0xA1,
    0x1A, 0x30, 0x18, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08, 0x30, 0x0B,
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0xA2, 0x04, 0x02, 0x02, 0x00,
    0xDE, 0x30, 0x13, 0x31, 0x11, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x08, 0x70, 0x73,
    0x73, 0x2E, 0x74, 0x65, 0x73, 0x74, 0x30, 0x20, 0x17, 0x0D, 0x32, 0x36, 0x31, 0x30, 0x32, 0x34,
    0x30, 0x38, 0x30, 0x30, 0x34, 0x32, 0x5A, 0x18, 0x0F, 0x32, 0x30, 0x35, 0x31, 0x30, 0x36, 0x31,
    0x35, 0x30, 0x38, 0x30, 0x30, 0x34, 0x32, 0x5A, 0x30, 0x13, 0x31, 0x11, 0x30, 0x0F, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0C, 0x08, 0x70, 0x73, 0x73, 0x2E, 0x74, 0x65, 0x73, 0x74, 0x30, 0x82, 0x01,
    0x20, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A, 0x03, 0x82,
    0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00, 0xE0, 0x07, 0xED, 0x0D,
    0xA0, 0xCD, 0xA7, 0x95, 0x80, 0x07, 0x55, 0x09, 0x44, 0x7A, 0xA4, 0xF6, 0x73, 0x04, 0x93, 0x05,
    0xDD, 0x4A, 0x6D, 0x99, 0x32, 0x2B, 0x31, 0x93, 0x92, 0xFE, 0x60, 0xAE, 0x93, 0x48, 0x30, 0x96,
    0xF2, 0xE2, 0x2F, 0xB2, 0xCA, 0x46, 0xFD, 0x59, 0x00, 0x72, 0xFD, 0x2A, 0x48, 0x49, 0x87, 0xAF,
    0x7A, 0xB8, 0xA3, 0x44, 0x1D, 0x69, 0xE1, 0x87, 0xCF, 0xF9, 0x28, 0x43, 0x43, 0xE9, 0x0F, 0x76,
    0x68, 0x54, 0x78, 0x2B, 0x34, 0x31, 0xAA, 0xB1, 0xA9, 0xEC, 0xF1, 0xE2, 0xC2, 0xEA, 0x38, 0x10,
    0xD2, 0xF3, 0x1A, 0xE8, 0x54, 0x5F, 0x56, 0xB9, 0xA4, 0xF1, 0xA2, 0xD1, 0xB0, 0xD8, 0x64, 0xAD,
    0xBE, 0xD9, 0x2A, 0xC9, 0x69, 0x02, 0xF2, 0xF3, 0xF9, 0xD3, 0xCD, 0x4E, 0xD2, 0x95, 0x3D, 0x2F,
    0xF8, 0xE9, 0xCE, 0xEE, 0xBC, 0xE4, 0xCD, 0x7A, 0x80, 0x4F, 0xAE, 0xFD, 0x1E, 0x92, 0xA7, 0xC7,
    0x85, 0xCB, 0x40, 0x6C, 0x5A, 0x62, 0x0B, 0x02, 0xB3, 0x4A, 0xE8, 0xC6, 0x7D, 0x12, 0x60, 0x44,
    0x58, 0x90, 0x75, 0x05, 0x89, 0x30, 0x6C, 0xDC, 0xEB, 0x63, 0x44, 0xB7, 0x66, 0x40, 0x2D, 0x8F,
    0x8C, 0xCF, 0x89, 0x6F, 0x48, 0x4B, 0x62, 0xAA, 0x16, 0x65, 0xA5, 0x8B, 0xE6, 0xB5, 0xCB, 0x7A,
    0x0B, 0x28, 0x51, 0x69, 0xC9, 0xEB, 0xFA, 0x02, 0xA5, 0x64, 0x85, 0x69, 0x45, 0xDA, 0xC7, 0x48,
    0xDD, 0x3F, 0x6E, 0xF4, 0xFE, 0x86, 0xCA, 0xAC, 0x3C, 0x55, 0x52, 0x80, 0x33, 0xC4, 0x6A, 0xCC,
    0x16, 0xF6, 0x89, 0xFB, 0x9C, 0x89, 0xB0, 0x78, 0x07, 0x51, 0x0E, 0x9D, 0x9F, 0x96, 0xC1, 0x30,
    0x67, 0xC1, 0xD5, 0xD4, 0x2E, 0xE9, 0xD4, 0x3F, 0x4E, 0x01, 0x70, 0x10, 0x05, 0x02, 0xF6, 0x0E,
    0x63, 0x4D, 0x67, 0x81, 0x05, 0xF7, 0x49, 0x14, 0x88, 0x56, 0x5F, 0x03, 0x02, 0x03, 0x01, 0x00,
    0x01, 0xA3, 0x53, 0x30, 0x51, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14,
    0xF5, 0xBE, 0xB6, 0x04, 0xA4, 0xED, 0x41, 0x12, 0x04, 0x29, 0xD3, 0xF4, 0x7C, 0x77, 0x76, 0xDC,
    0xD5, 0xC8, 0x2C, 0xAE, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80,
    0x14, 0xF5, 0xBE, 0xB6, 0x04, 0xA4, 0xED, 0x41, 0x12, 0x04, 0x29, 0xD3, 0xF4, 0x7C, 0x77, 0x76,
    0xDC, 0xD5, 0xC8, 0x2C, 0xAE, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04,
    0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x3E, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
    0x01, 0x01, 0x0A, 0x30, 0x31, 0xA0, 0x0D, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x01, 0xA1, 0x1A, 0x30, 0x18, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
    0x01, 0x01, 0x08, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0xA2, 0x04, 0x02, 0x02, 0x00, 0xDE, 0x03, 0x82, 0x01, 0x01, 0x00, 0x01, 0xC2, 0x2F, 0xAB, 0x4A,
    0x47, 0x89, 0x14, 0x54, 0x80, 0x98, 0x2F, 0x22, 0xB3, 0xCA, 0xC1, 0xEA, 0xF4, 0x56, 0x2B, 0x7C,
    0xFA, 0xCE, 0xB3, 0xF3, 0xA2, 0x62, 0xDE, 0x69, 0xF8, 0x87, 0xA4, 0xB8, 0x62, 0x2C, 0x17, 0x67,
    0x65, 0xBA, 0x79, 0x1C, 0x24, 0x70, 0xE2, 0x95, 0x30, 0x42, 0x5C, 0xB6, 0x3E, 0x2F, 0x6E, 0x57,
    0xF5, 0x5D, 0xC4, 0x3C, 0x9F, 0x82, 0xC0, 0x61, 0xA3, 0x33, 0xAA, 0xF0, 0x98, 0x88, 0xFA, 0x0C,
    0x08, 0x39, 0xFE, 0xD2, 0x6A, 0xFF, 0xFE, 0x38, 0xBE, 0x50, 0xF7, 0x87, 0x10, 0x89, 0x71, 0x8C,
    0xD2, 0x2E, 0xC9, 0xCD, 0x45, 0xB0, 0xFA, 0x10, 0xC8, 0x7E, 0xC3, 0x5B, 0x15, 0x99, 0xDE, 0x48,
    0xCC, 0x75, 0xF3, 0x3D, 0x10, 0x7F, 0x8F, 0x23, 0xE0, 0x40, 0x45, 0x5F, 0x9A, 0x64, 0x11, 0xBF,
    0x03, 0x25, 0x90, 0xEA, 0x12, 0xB0, 0xF4, 0x0A, 0x2A, 0xA9, 0x6C, 0x01, 0xAE, 0x3E, 0x12, 0x52,
    0xB0, 0x86, 0x03, 0x3A, 0xEC, 0x3A, 0x65, 0xF9, 0x7C, 0xC6, 0xF3, 0x98, 0xA7, 0x18, 0x4B, 0x24,
    0xA1, 0x51, 0xF8, 0x31, 0x90, 0x73, 0xD0, 0x5B, 0xE7, 0x11, 0x37, 0xED, 0x47, 0xA5, 0x15, 0x2D,
    0x32, 0xBF, 0x39, 0x09, 0x53, 0x67, 0x4C, 0x75, 0x73, 0x7A, 0xDC, 0xBF, 0x0B, 0xF9, 0x54, 0x0B,
    0x67, 0xC6, 0xF6, 0x94, 0xA1, 0x25, 0x46, 0x2B, 0xA3, 0x10, 0x9F, 0x29, 0x2F, 0x79, 0x24, 0xF7,
    0xB6, 0x4C, 0xAF, 0x79, 0x91, 0x04, 0xC0, 0x39, 0x7A, 0x54, 0x48, 0x73, 0xB7, 0xF1, 0x8E, 0xD0,
    0x33, 0x48, 0xDA, 0xF1, 0x12, 0x55, 0x51, 0xE6, 0x2B, 0x1A, 0x05, 0x92, 0xF4, 0xDC, 0x77, 0x49,
    0xE5, 0x9F, 0x19, 0x6B, 0xA8, 0x06, 0xA0, 0xFB, 0xCE, 0x0C, 0x40, 0x7A, 0xB6, 0x0B, 0x67, 0x66,
    0xEB, 0x78, 0xBF, 0xFF, 0xA9, 0x2D, 0x5D, 0x44, 0x49, 0xCF, 0xCD,
};

static int t_spki_pss_detect(void)
{
    static const uint8_t oid_pss[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A };
    struct { const uint8_t *der; uint32_t len; int is_pss; } v[6];
    const uint8_t *oid = NULL;
    uint32_t oid_len = 0U;
    uint32_t i;
    size_t base = lb_alloc_live_bytes();

    v[0].der = lb_ec_server_cert;  v[0].len = lb_ec_server_cert_len;  v[0].is_pss = 0;
    v[1].der = lb_rsa_server_cert; v[1].len = lb_rsa_server_cert_len; v[1].is_pss = 0;
    v[2].der = lb_ed_server_cert;  v[2].len = lb_ed_server_cert_len;  v[2].is_pss = 0;
    v[3].der = k_rsa_pss_cert;     v[3].len = (uint32_t)sizeof(k_rsa_pss_cert); v[3].is_pss = 1;
    v[4].der = k_san_rich_cert;    v[4].len = (uint32_t)sizeof(k_san_rich_cert); v[4].is_pss = 0;
    v[5].der = lb_ec_root_cert;    v[5].len = lb_ec_root_cert_len;    v[5].is_pss = 0;
    for(i = 0U; i < 6U; i++) {
        const uint8_t *p_oid = NULL;
        uint32_t p_oid_len = 0U;
        int is_pss;
        /* The TLS 1.3 server checks its leaf for id-RSASSA-PSS on every ClientHello with this
         * walker (no parse, no heap). */
        LB_CHECK_OK(noxtls_x509_der_get_spki_algorithm(v[i].der, v[i].len, &oid, &oid_len));
        LB_CHECK(in_buf(oid, oid_len, v[i].der, v[i].len));
        is_pss = ((oid_len == sizeof(oid_pss)) && (memcmp(oid, oid_pss, sizeof(oid_pss)) == 0)) ? 1 : 0;
        LB_CHECK_EQ(is_pss, v[i].is_pss);
        /* Same answer as a full (borrow-mode) parse. */
        LB_CHECK_OK(noxtls_x509_certificate_parse_der_nocopy(&s_tmp, v[i].der, v[i].len));
        LB_CHECK_OK(noxtls_x509_certificate_get_public_key_info(&s_tmp, &p_oid, &p_oid_len, NULL, NULL));
        LB_CHECK((p_oid == oid) && (p_oid_len == oid_len));
        if(v[i].is_pss != 0) {
            LB_CHECK((s_tmp.rsa_modulus != NULL) && (s_tmp.rsa_exponent != NULL));
        }
        (void)noxtls_x509_certificate_free(&s_tmp);
        /* Truncations are rejected without reading past the buffer. */
        LB_CHECK(noxtls_x509_der_get_spki_algorithm(v[i].der, 40U, &oid, &oid_len) != NOXTLS_RETURN_SUCCESS);
        LB_CHECK(oid == NULL);
    }
    LB_CHECK(noxtls_x509_der_get_spki_algorithm(NULL, 10U, &oid, &oid_len) == NOXTLS_RETURN_NULL);
    LB_CHECK(noxtls_x509_der_get_spki_algorithm(lb_ec_int_crl, lb_ec_int_crl_len, &oid, &oid_len) != NOXTLS_RETURN_SUCCESS);
    return lb_expect_no_leak(base, "spki pss detect");
}


static int t_crl_memory(void)
{
    noxtls_x509_crl_t crl;
    const uint8_t *serial = NULL;
    uint32_t serial_len = 0U;
    uint32_t i;
    int found_revoked = 0;
    size_t base = lb_alloc_live_bytes();
    size_t base_blocks = lb_alloc_live_blocks();
    lb_alloc_stats_t st;

    /* Copy mode: the DER copy is the only allocation (was DER + TBS copy + signature copy +
     * a 2048 x 32 + 2048 x 4 = 73728-byte serial table for any CRL with an entry). */
    LB_CHECK_OK(noxtls_x509_crl_init(&crl));
    lb_alloc_reset_counters();
    LB_CHECK_OK(noxtls_x509_crl_parse_der(&crl, lb_ec_int_crl, lb_ec_int_crl_len));
    lb_alloc_get_stats(&st);
    LB_CHECK_EQ(st.alloc_calls, 1U);
    LB_CHECK_EQ(lb_alloc_live_bytes() - base, (size_t)lb_ec_int_crl_len);
    LB_CHECK_EQ(lb_alloc_live_blocks() - base_blocks, 1U);
    LB_CHECK_EQ(xf_crl_count(&crl), LB_PKI_CRL_REVOKED_COUNT);
    for(i = 0U; i < LB_PKI_CRL_REVOKED_COUNT; i++) {
        LB_CHECK_OK(noxtls_x509_crl_get_revoked_serial(&crl, i, &serial, &serial_len));
        LB_CHECK(in_buf(serial, serial_len, crl.raw_data, crl.raw_data_len));
        if((serial_len == 2U) && (serial[0] == (uint8_t)(LB_PKI_SERIAL_EC_REVOKED >> 8)) &&
           (serial[1] == (uint8_t)LB_PKI_SERIAL_EC_REVOKED)) {
            found_revoked = 1;
        }
    }
    LB_CHECK(found_revoked != 0);
    LB_CHECK(noxtls_x509_crl_get_revoked_serial(&crl, LB_PKI_CRL_REVOKED_COUNT, &serial, &serial_len) ==
             NOXTLS_RETURN_FAILED);
    LB_CHECK((crl.this_update_time > 0) && (crl.has_next_update != 0U) &&
             (crl.next_update_time > crl.this_update_time));
    noxtls_x509_crl_free(&crl);
    LB_CHECK_EQ(lb_alloc_live_bytes(), base);
    /* Borrow mode: no heap at all; revocation lookups scan the DER in place. */
    lb_alloc_reset_counters();
    LB_CHECK_OK(noxtls_x509_crl_parse_der_nocopy(&crl, lb_ec_int_crl, lb_ec_int_crl_len));
    LB_RUN(parse(&s_tmp, lb_ec_revoked_cert, lb_ec_revoked_cert_len));
    lb_alloc_reset_counters();
    LB_CHECK_EQ(noxtls_x509_crl_serial_is_revoked(&crl, &s_tmp), 1);
    lb_alloc_get_stats(&st);
    LB_CHECK_EQ(st.alloc_calls, 0U);
    LB_CHECK(crl.raw_data == lb_ec_int_crl);
    (void)noxtls_x509_certificate_free(&s_tmp);
    noxtls_x509_crl_free(&crl);
    /* Truncated revokedCertificates / trailing bytes are still rejected. */
    LB_CHECK(noxtls_x509_crl_parse_der_nocopy(&crl, lb_ec_int_crl, lb_ec_int_crl_len - 1U) != NOXTLS_RETURN_SUCCESS);
    return lb_expect_no_leak(base, "crl memory");
}


static int t_private_key_memory(void)
{
    static x509_private_key_t key;
    size_t base = lb_alloc_live_bytes();
    size_t base_blocks = lb_alloc_live_blocks();

    /* PKCS#1 RSA: the eight components are spans into the single raw DER copy (were eight
     * separate copies, ~1.2 KB for RSA-2048). */
    LB_CHECK_OK(noxtls_x509_private_key_init(&key));
    LB_CHECK_OK(noxtls_x509_private_key_parse_der(&key, lb_rsa_server_key, lb_rsa_server_key_len));
    LB_CHECK_EQ(key.format, X509_PRIVATE_KEY_FORMAT_PKCS1);
    LB_CHECK_EQ(lb_alloc_live_blocks() - base_blocks, 1U);
    LB_CHECK_EQ(lb_alloc_live_bytes() - base, (size_t)lb_rsa_server_key_len);
    LB_CHECK(in_buf(key.rsa_modulus, key.rsa_modulus_len, key.raw_data, key.raw_data_len));
    LB_CHECK(in_buf(key.rsa_private_exponent, key.rsa_private_exponent_len, key.raw_data, key.raw_data_len));
    LB_CHECK(in_buf(key.rsa_coefficient, key.rsa_coefficient_len, key.raw_data, key.raw_data_len));
    {
        /* The key still converts and matches the certificate public key. */
        rsa_key_t rsa;
        LB_RUN(parse(&s_tmp, lb_rsa_server_cert, lb_rsa_server_cert_len));
        memset(&rsa, 0, sizeof(rsa));
        LB_CHECK_OK(noxtls_x509_private_key_to_rsa_key(&key, &rsa));  /* initializes rsa */
        LB_CHECK(xf_rsa_modulus_eq(&s_tmp, &rsa.n[rsa.key_bytes - lb_rsa_server_modulus_len], lb_rsa_server_modulus_len));
        (void)noxtls_rsa_key_free(&rsa);
        (void)noxtls_x509_certificate_free(&s_tmp);
    }
    LB_CHECK_OK(noxtls_x509_private_key_free(&key));
    LB_CHECK_EQ(lb_alloc_live_bytes(), base);
    /* EC (SEC1 / PKCS#8) keys keep their component copies; freeing releases everything. */
    LB_CHECK_OK(noxtls_x509_private_key_parse_der(&key, lb_ec_server_key, lb_ec_server_key_len));
    LB_CHECK_EQ(key.key_type, X509_PRIVATE_KEY_ECC);
    LB_CHECK_OK(noxtls_x509_private_key_free(&key));
    LB_CHECK(key.raw_data == NULL);
    return lb_expect_no_leak(base, "private key memory");
}

static int t_negative_truncated(void)
{
    uint32_t len;
    size_t base = lb_alloc_live_bytes();
    /* Every proper prefix of a valid certificate must be rejected without crashing or leaking. */
    for(len = 0U; len < lb_ec_server_cert_len; len++) {
        memcpy(s_buf, lb_ec_server_cert, len);
        (void)noxtls_x509_certificate_init(&s_tmp);
        if(noxtls_x509_certificate_parse_der(&s_tmp, s_buf, len) == NOXTLS_RETURN_SUCCESS) {
            lb_log("prefix of %u bytes accepted", len);
            return 1;
        }
        (void)noxtls_x509_certificate_free(&s_tmp);
    }
    for(len = 0U; len < lb_rsa_server_cert_len; len += 7U) {
        (void)noxtls_x509_certificate_init(&s_tmp);
        LB_CHECK(noxtls_x509_certificate_parse_der(&s_tmp, lb_rsa_server_cert, len) != NOXTLS_RETURN_SUCCESS);
        (void)noxtls_x509_certificate_free(&s_tmp);
    }
    (void)noxtls_x509_certificate_init(&s_tmp);
    LB_CHECK(noxtls_x509_certificate_parse_der(&s_tmp, NULL, 10U) != NOXTLS_RETURN_SUCCESS);
    (void)noxtls_x509_certificate_free(&s_tmp);
    LB_CHECK(noxtls_x509_certificate_parse_der(NULL, lb_ec_server_cert, lb_ec_server_cert_len) != NOXTLS_RETURN_SUCCESS);
    return lb_expect_no_leak(base, "truncated");
}

static int t_negative_bad_lengths(void)
{
    uint32_t len = lb_ec_server_cert_len;
    uint32_t i;
    size_t base = lb_alloc_live_bytes();
    static const uint8_t long_len[] = { 0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x30, 0x00 };
    static const uint8_t indefinite[] = { 0x30, 0x80, 0x30, 0x00, 0x00, 0x00 };
    static const uint8_t empty_seq[] = { 0x30, 0x00 };

    /* Outer length larger / smaller than the buffer. */
    memcpy(s_buf, lb_ec_server_cert, len);
    s_buf[3] = (uint8_t)(s_buf[3] + 1U);
    LB_RUN(parse(&s_tmp, s_buf, len) == 0 ? 1 : 0);
    (void)noxtls_x509_certificate_free(&s_tmp);
    /* Outer length one byte short of its contents: the signature BIT STRING then extends
     * past the outer SEQUENCE. Strict DER rejects it (see also x509_strict_der). */
    memcpy(s_buf, lb_ec_server_cert, len);
    s_buf[3] = (uint8_t)(s_buf[3] - 1U);
    LB_RUN(parse(&s_tmp, s_buf, len) == 0 ? 1 : 0);
    (void)noxtls_x509_certificate_free(&s_tmp);
    LB_RUN(parse(&s_tmp, long_len, sizeof(long_len)) == 0 ? 1 : 0);
    (void)noxtls_x509_certificate_free(&s_tmp);
    LB_RUN(parse(&s_tmp, indefinite, sizeof(indefinite)) == 0 ? 1 : 0);
    (void)noxtls_x509_certificate_free(&s_tmp);
    LB_RUN(parse(&s_tmp, empty_seq, sizeof(empty_seq)) == 0 ? 1 : 0);
    (void)noxtls_x509_certificate_free(&s_tmp);
    /* Corrupt every byte in turn (xor 0xFF): parsing may succeed or fail, but must stay
     * memory-safe (lb_alloc checks every free for overruns) and leak-free. */
    for(i = 0U; i < len; i++) {
        memcpy(s_buf, lb_ec_server_cert, len);
        s_buf[i] ^= 0xFFU;
        (void)noxtls_x509_certificate_init(&s_tmp);
        (void)noxtls_x509_certificate_parse_der(&s_tmp, s_buf, len);
        (void)noxtls_x509_certificate_free(&s_tmp);
    }
    return lb_expect_no_leak(base, "bad lengths");
}

/** Reject @p der (len > NOXTLS_MAX_CERT_SIZE) in copy and borrow mode without allocating. */
static int expect_oversized_rejected(const uint8_t *der, uint32_t len)
{
    lb_alloc_stats_t st;

    (void)noxtls_x509_certificate_init(&s_tmp);
    lb_alloc_reset_counters();
    LB_CHECK_EQ(noxtls_x509_certificate_parse_der(&s_tmp, der, len), NOXTLS_RETURN_CERT_PARSE_FAILED);
    lb_alloc_get_stats(&st);
    LB_CHECK_EQ(st.alloc_calls, 0U);  /* rejected before the DER copy */
    LB_CHECK_EQ(noxtls_x509_certificate_parse_der_nocopy(&s_tmp, der, len), NOXTLS_RETURN_CERT_PARSE_FAILED);
    (void)noxtls_x509_certificate_free(&s_tmp);
    return 0;
}

static int t_negative_oversized(void)
{
    FILE *f;
    uint8_t *big;
    const uint32_t big_len = (uint32_t)NOXTLS_MAX_CERT_SIZE + 1U;
    uint32_t body_len = big_len - 5U;
    size_t base = lb_alloc_live_bytes();

    /* Configuration independent: a certificate-shaped DER one byte over NOXTLS_MAX_CERT_SIZE
     * (the limit is 16, 32 or 64 KB depending on the PQ features). */
    big = (uint8_t *)malloc(big_len);
    LB_CHECK(big != NULL);
    memset(big, 0, big_len);
    big[0] = 0x30U;
    big[1] = 0x83U;
    big[2] = (uint8_t)(body_len >> 16);
    big[3] = (uint8_t)(body_len >> 8);
    big[4] = (uint8_t)body_len;
    if(expect_oversized_rejected(big, big_len) != 0) {
        free(big);
        return 1;
    }
    /* The file loader enforces the limit as well. */
    f = fopen("x509_oversized.der", "wb");
    LB_CHECK(f != NULL);
    LB_CHECK_EQ(fwrite(big, 1U, big_len, f), big_len);
    (void)fclose(f);
    free(big);
    (void)noxtls_x509_certificate_init(&s_tmp);
    LB_CHECK(noxtls_x509_certificate_load_file(&s_tmp, (const uint8_t *)"x509_oversized.der") != NOXTLS_RETURN_SUCCESS);
    (void)noxtls_x509_certificate_free(&s_tmp);
    (void)remove("x509_oversized.der");
    /* The real (validly signed) 18 KB fixture, when it exceeds this build's limit. */
    if(lb_ec_oversized_cert_len > NOXTLS_MAX_CERT_SIZE) {
        LB_RUN(expect_oversized_rejected(lb_ec_oversized_cert, lb_ec_oversized_cert_len));
    } else {
        /* Larger limit (PQ builds): the fixture is a regular certificate and parses. */
        LB_RUN(parse(&s_tmp, lb_ec_oversized_cert, lb_ec_oversized_cert_len));
        (void)noxtls_x509_certificate_free(&s_tmp);
    }
    return lb_expect_no_leak(base, "oversized");
}

static int t_debug_print_smoke(void)
{
    size_t base = lb_alloc_live_bytes();
    LB_RUN(parse(&s_leaf, lb_ec_server_cert, lb_ec_server_cert_len));
    (void)noxtls_x509_certificate_debug_print(&s_leaf, 0U);
    (void)noxtls_x509_certificate_free(&s_leaf);
    /* Freed / re-initialized certificates are inert. */
    (void)noxtls_x509_certificate_init(&s_leaf);
    LB_CHECK_EQ(xf_parsed(&s_leaf), 0);
    LB_CHECK(noxtls_x509_certificate_verify_signature(&s_leaf, &s_leaf) != NOXTLS_RETURN_SUCCESS);
    LB_CHECK_OK(noxtls_x509_certificate_free(&s_leaf));
    return lb_expect_no_leak(base, "debug print");
}

static const lb_test_case_t k_cases[] = {
    { "x509_ec_chain_fields", t_ec_chain_fields },
    { "x509_pem_matches_der", t_pem_matches_der },
    { "x509_rsa_fields", t_rsa_fields },
    { "x509_ed25519_fields", t_ed25519_fields },
    { "x509_hostname_rules", t_hostname_rules },
    { "x509_validity", t_validity },
    { "x509_signature_verify", t_signature_verify },
    { "x509_public_key_extract_verify", t_public_key_extract_verify },
    { "x509_trust_one_anchor", t_trust_one_anchor },
    { "x509_trust_three_anchors", t_trust_three_anchors },
    { "x509_chain_verify_api", t_chain_verify_api },
    { "x509_crl_revocation", t_crl },
#if defined(NOXTLS_HAVE_CERT_WRITE) && NOXTLS_HAVE_CERT_WRITE
    { "x509_cert_write_roundtrip", t_cert_write_roundtrip },
    { "x509_cert_write_corpus", t_cert_write_corpus },
#endif
    { "x509_borrow_accessors", t_borrow_accessors },
    { "x509_san_iterator", t_san_iterator },
    { "x509_strict_der", t_strict_der },
    { "x509_chain_lazy", t_chain_lazy },
    { "x509_private_key_memory", t_private_key_memory },
    { "x509_crl_memory", t_crl_memory },
    { "x509_spki_pss_detect", t_spki_pss_detect },
    { "x509_trust_store_memory", t_trust_store_memory },
#if defined(NOXTLS_HAVE_CERT_WRITE) && NOXTLS_HAVE_CERT_WRITE
    { "x509_issuer_name_rfc5280", t_issuer_name_rfc5280 },
#endif
    { "x509_negative_truncated", t_negative_truncated },
    { "x509_negative_bad_lengths", t_negative_bad_lengths },
    { "x509_negative_oversized", t_negative_oversized },
    { "x509_debug_print_smoke", t_debug_print_smoke },
};

int main(int argc, char **argv)
{
#if defined(NOXTLS_HAVE_CERT_WRITE) && NOXTLS_HAVE_CERT_WRITE
    /* --artifacts <dir> <test>: also write generated certificates/CSRs for openssl cross-checks. */
    if((argc > 3) && (strcmp(argv[1], "--artifacts") == 0)) {
        s_artifact_dir = argv[2];
        argv[2] = argv[0];
        return lb_main(argc - 2, &argv[2], "x509_parse", k_cases, sizeof(k_cases) / sizeof(k_cases[0]));
    }
#endif
    return lb_main(argc, argv, "x509_parse", k_cases, sizeof(k_cases) / sizeof(k_cases[0]));
}
