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
* File:    x509_audit_test.c
* Summary: Regression tests for X.509 path validation, extension, CRL and encoding hardening
*****************************************************************************/
/** @file x509_audit_test.c
 * @brief Builds small certificates and CRLs in the test (Ed25519 and ECDSA P-256 issuers) and
 * checks: EKU / Key Usage presence, name constraints, path-building budget, trust anchor
 * constraints, strict ECDSA signature DER, mandatory Validity, strict extension walking,
 * IP-literal host matching, CRL extensions / scope / list order / issuer matching / coverage,
 * pure ML-DSA certificate signatures and the PEM buffer size helper.
 */
#include "lb_fixture.h"

#include <stdlib.h>
#include <string.h>

#include "certificates.h"
#include "pkc/ed25519/noxtls_ed25519.h"
#if NOXTLS_FEATURE_ML_DSA
#include "pkc/mldsa/noxtls_mldsa.h"
#endif

/* 2037-01-01T00:00:00Z, inside every default validity window below. */
#define T_VALID 2114380800LL

#define KEY_EC 100  /* ECDSA P-256 key lb_ec_csr_key / lb_ec_csr_point */

static uint8_t s_tmp[8192];
static uint8_t s_tbs[8192];
#define SLOTS 40U
static uint8_t s_cert_buf[SLOTS][2048];
static uint32_t s_cert_len[SLOTS];
static x509_certificate_t s_certs[SLOTS];

/* ------------------------------------------------------------------------- */
/* Minimal DER builder                                                       */
/* ------------------------------------------------------------------------- */

/** Write tag || length || content at @p out (content may alias @p out). Returns bytes written. */
static uint32_t tlv(uint8_t *out, uint8_t tag, const uint8_t *c, uint32_t n)
{
    uint32_t h = 0U;
    uint8_t hdr[4];
    hdr[h++] = tag;
    if(n < 0x80U) {
        hdr[h++] = (uint8_t)n;
    } else if(n < 0x100U) {
        hdr[h++] = 0x81U;
        hdr[h++] = (uint8_t)n;
    } else {
        hdr[h++] = 0x82U;
        hdr[h++] = (uint8_t)(n >> 8);
        hdr[h++] = (uint8_t)n;
    }
    if(n > 0U) {
        memmove(&out[h], c, n);
    }
    memcpy(out, hdr, h);
    return h + n;
}

/** Append @p n bytes at out[*pos]. */
static void cat(uint8_t *out, uint32_t *pos, const uint8_t *c, uint32_t n)
{
    memcpy(&out[*pos], c, n);
    *pos += n;
}

/** Name with one CN attribute; @p str_tag 0x0C (UTF8String) or 0x13 (PrintableString). */
static uint32_t name_cn_tag(uint8_t *out, const char *cn, uint8_t str_tag)
{
    static const uint8_t oid_cn[] = { 0x06, 0x03, 0x55, 0x04, 0x03 };
    uint8_t atv[160];
    uint32_t n = 0U;
    cat(atv, &n, oid_cn, sizeof(oid_cn));
    n += tlv(&atv[n], str_tag, (const uint8_t *)cn, (uint32_t)strlen(cn));
    n = tlv(atv, 0x30U, atv, n);
    n = tlv(atv, 0x31U, atv, n);
    return tlv(out, 0x30U, atv, n);
}

static uint32_t name_cn(uint8_t *out, const char *cn)
{
    return name_cn_tag(out, cn, 0x0CU);
}

/** Extension TLV. */
static uint32_t ext(uint8_t *out, const uint8_t *oid, uint32_t oid_len, int critical,
                    const uint8_t *val, uint32_t val_len)
{
    static const uint8_t crit_true[] = { 0x01, 0x01, 0xFF };
    uint8_t body[1024];
    uint32_t n = 0U;
    n += tlv(&body[n], 0x06U, oid, oid_len);
    if(critical != 0) {
        cat(body, &n, crit_true, sizeof(crit_true));
    }
    n += tlv(&body[n], 0x04U, val, val_len);
    return tlv(out, 0x30U, body, n);
}

static const uint8_t k_oid_bc[] = { 0x55, 0x1D, 0x13 };
static const uint8_t k_oid_ku[] = { 0x55, 0x1D, 0x0F };
static const uint8_t k_oid_eku[] = { 0x55, 0x1D, 0x25 };
static const uint8_t k_oid_san[] = { 0x55, 0x1D, 0x11 };
static const uint8_t k_oid_nc[] = { 0x55, 0x1D, 0x1E };
static const uint8_t k_oid_crldp[] = { 0x55, 0x1D, 0x1F };
static const uint8_t k_oid_unknown[] = { 0x2A, 0x03, 0x04 }; /* 1.2.3.4 */

static const uint8_t k_bc_ca[] = { 0x30, 0x03, 0x01, 0x01, 0xFF };
static const uint8_t k_bc_ca_path0[] = { 0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00 };
static const uint8_t k_bc_not_ca[] = { 0x30, 0x00 };
static const uint8_t k_ku_ca[] = { 0x03, 0x02, 0x01, 0x06 };         /* keyCertSign | cRLSign */
static const uint8_t k_ku_ds[] = { 0x03, 0x02, 0x07, 0x80 };         /* digitalSignature */
static const uint8_t k_ku_zero[] = { 0x03, 0x01, 0x00 };             /* present, no bits */
static const uint8_t k_eku_server[] = { 0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };
static const uint8_t k_eku_docsign[] = { 0x30, 0x0C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0A, 0x03, 0x0C };
static const uint8_t k_eku_empty[] = { 0x30, 0x00 };

/** SAN with one dNSName. */
static uint32_t san_dns(uint8_t *out, const char *dns)
{
    uint8_t v[300];
    uint32_t n = tlv(v, 0x82U, (const uint8_t *)dns, (uint32_t)strlen(dns));
    n = tlv(v, 0x30U, v, n);
    return ext(out, k_oid_san, sizeof(k_oid_san), 0, v, n);
}

/** SAN with one iPAddress. */
static uint32_t san_ip(uint8_t *out, const uint8_t *ip, uint32_t ip_len)
{
    uint8_t v[64];
    uint32_t n = tlv(v, 0x87U, ip, ip_len);
    n = tlv(v, 0x30U, v, n);
    return ext(out, k_oid_san, sizeof(k_oid_san), 0, v, n);
}

/** nameConstraints with one subtree (@p gn_tag, @p base) in permitted ([0]) or excluded ([1]). */
static uint32_t nc_one(uint8_t *out, int critical, int excluded, uint8_t gn_tag, const uint8_t *base, uint32_t base_len)
{
    uint8_t v[300];
    uint32_t n = tlv(v, gn_tag, base, base_len);
    n = tlv(v, 0x30U, v, n);                                 /* GeneralSubtree */
    n = tlv(v, (excluded != 0) ? 0xA1U : 0xA0U, v, n);       /* GeneralSubtrees */
    n = tlv(v, 0x30U, v, n);                                 /* NameConstraints */
    return ext(out, k_oid_nc, sizeof(k_oid_nc), critical, v, n);
}

/* ------------------------------------------------------------------------- */
/* Keys and certificate builder                                              */
/* ------------------------------------------------------------------------- */

static void ed_seed(int key, uint8_t seed[32])
{
    memset(seed, 0x40 + key, 32);
}

static uint32_t spki(uint8_t *out, int key)
{
    if(key == KEY_EC) {
        static const uint8_t alg[] = { 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
                                       0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
        uint8_t b[128];
        uint32_t n = 0U;
        uint32_t m = 0U;
        b[0] = 0x00U;
        memcpy(&b[1], lb_ec_csr_point, lb_ec_csr_point_len);
        cat(out, &n, alg, sizeof(alg));
        n += tlv(&out[n], 0x03U, b, lb_ec_csr_point_len + 1U);
        m = tlv(out, 0x30U, out, n);
        return m;
    } else {
        static const uint8_t alg[] = { 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70 };
        uint8_t seed[32];
        uint8_t b[33];
        uint32_t n = 0U;
        ed_seed(key, seed);
        b[0] = 0x00U;
        (void)noxtls_ed25519_public_key(seed, &b[1]);
        cat(out, &n, alg, sizeof(alg));
        n += tlv(&out[n], 0x03U, b, sizeof(b));
        return tlv(out, 0x30U, out, n);
    }
}

static uint32_t sig_alg(uint8_t *out, int key)
{
    static const uint8_t ed[] = { 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70 };
    static const uint8_t ec[] = { 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
    if(key == KEY_EC) {
        memcpy(out, ec, sizeof(ec));
        return sizeof(ec);
    }
    memcpy(out, ed, sizeof(ed));
    return sizeof(ed);
}

/** Sign @p tbs with @p key and wrap tbs || alg || BIT STRING into a Certificate/CertificateList. */
static uint32_t sign_wrap(uint8_t *out, const uint8_t *tbs, uint32_t tbs_len, int key)
{
    uint8_t sig[200];
    uint32_t sig_len = 0U;
    uint32_t n = 0U;
    if(key == KEY_EC) {
        if(noxtls_x509_private_key_sign_data(lb_ec_csr_key, lb_ec_csr_key_len, tbs, tbs_len, NOXTLS_HASH_SHA_256,
                                             &sig[1], sizeof(sig) - 1U, &sig_len) != NOXTLS_RETURN_SUCCESS) {
            return 0U;
        }
    } else {
        uint8_t seed[32];
        ed_seed(key, seed);
        if(noxtls_ed25519_sign(seed, tbs, tbs_len, &sig[1]) != NOXTLS_RETURN_SUCCESS) {
            return 0U;
        }
        sig_len = 64U;
    }
    sig[0] = 0x00U;
    cat(out, &n, tbs, tbs_len);
    n += sig_alg(&out[n], key);
    n += tlv(&out[n], 0x03U, sig, sig_len + 1U);
    return tlv(out, 0x30U, out, n);
}

typedef struct {
    const char *issuer_cn;
    const char *subject_cn;
    const uint8_t *subject_name;    /* full Name TLV overriding subject_cn, or NULL */
    uint32_t subject_name_len;
    const uint8_t *validity;        /* full Validity TLV, or NULL for the default */
    uint32_t validity_len;
    const uint8_t *exts;            /* concatenated Extension TLVs (wrapped in SEQUENCE), or NULL */
    uint32_t exts_len;
    int exts_raw;                   /* 1: exts is the full [3] contents */
    int subj_key;
    int signer_key;
    uint8_t serial;
} cspec_t;

static uint32_t build_cert(uint8_t *out, const cspec_t *c)
{
    static const uint8_t version[] = { 0xA0, 0x03, 0x02, 0x01, 0x02 };
    static const uint8_t def_validity[] = { 0x30, 0x1E, 0x17, 0x0D, '2', '5', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z',
                                            0x17, 0x0D, '4', '9', '1', '2', '3', '1', '2', '3', '5', '9', '5', '9', 'Z' };
    uint32_t n = 0U;
    uint8_t serial[3] = { 0x02, 0x01, 0x00 };
    serial[2] = c->serial;
    cat(s_tbs, &n, version, sizeof(version));
    cat(s_tbs, &n, serial, sizeof(serial));
    n += sig_alg(&s_tbs[n], c->signer_key);
    n += name_cn(&s_tbs[n], c->issuer_cn);
    if(c->validity != NULL) {
        cat(s_tbs, &n, c->validity, c->validity_len);
    } else {
        cat(s_tbs, &n, def_validity, sizeof(def_validity));
    }
    if(c->subject_name != NULL) {
        cat(s_tbs, &n, c->subject_name, c->subject_name_len);
    } else {
        n += name_cn(&s_tbs[n], c->subject_cn);
    }
    n += spki(&s_tbs[n], c->subj_key);
    if(c->exts != NULL) {
        uint8_t e[2048];
        uint32_t en = 0U;
        if(c->exts_raw != 0) {
            memcpy(e, c->exts, c->exts_len);
            en = c->exts_len;
        } else {
            en = tlv(e, 0x30U, c->exts, c->exts_len);
        }
        n += tlv(&s_tbs[n], 0xA3U, e, en);
    }
    n = tlv(s_tbs, 0x30U, s_tbs, n);
    return sign_wrap(out, s_tbs, n, c->signer_key);
}

/** Build and parse certificate slot @p i. Returns the parse result. */
static noxtls_return_t make(uint32_t i, const cspec_t *c)
{
    s_cert_len[i] = build_cert(s_cert_buf[i], c);
    if(s_cert_len[i] == 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    (void)noxtls_x509_certificate_init(&s_certs[i]);
    return noxtls_x509_certificate_parse_der_nocopy(&s_certs[i], s_cert_buf[i], s_cert_len[i]);
}

static void free_all(void)
{
    uint32_t i;
    for(i = 0U; i < SLOTS; i++) {
        (void)noxtls_x509_certificate_free(&s_certs[i]);
    }
}

/** Common CA extensions (+ optional extra extension TLVs). */
static uint32_t ca_exts(uint8_t *out, const uint8_t *extra, uint32_t extra_len)
{
    uint32_t n = 0U;
    n += ext(&out[n], k_oid_bc, sizeof(k_oid_bc), 1, k_bc_ca, sizeof(k_bc_ca));
    n += ext(&out[n], k_oid_ku, sizeof(k_oid_ku), 1, k_ku_ca, sizeof(k_ku_ca));
    if(extra != NULL) {
        cat(out, &n, extra, extra_len);
    }
    return n;
}

/** Verify @p leaf with presented intermediates (slots) and anchors (slots), serverAuth, T_VALID. */
static noxtls_return_t verify_ex(uint32_t leaf, const uint32_t *pres, uint32_t npres,
                                 const uint32_t *anch, uint32_t nanch, const noxtls_x509_crl_t *crl,
                                 uint8_t require_cov, noxtls_x509_verify_flags_t *flags)
{
    x509_certificate_chain_t anchors;
    x509_certificate_chain_t presented;
    noxtls_x509_verify_policy_t policy;
    noxtls_return_t rc;
    uint32_t i;

    (void)noxtls_x509_certificate_chain_init(&anchors);
    (void)noxtls_x509_certificate_chain_init(&presented);
    for(i = 0U; i < nanch; i++) {
        (void)noxtls_x509_certificate_chain_add_der_nocopy(&anchors, s_cert_buf[anch[i]], s_cert_len[anch[i]]);
    }
    for(i = 0U; i < npres; i++) {
        (void)noxtls_x509_certificate_chain_add_der_nocopy(&presented, s_cert_buf[pres[i]], s_cert_len[pres[i]]);
    }
    memset(&policy, 0, sizeof(policy));
    policy.trust_anchors = &anchors;
    policy.required_eku = X509_EKU_SERVER_AUTH;
    policy.time_mode = NOXTLS_X509_TIME_EXPLICIT;
    policy.verify_time = T_VALID;
    policy.crl = crl;
    policy.require_crl_coverage = require_cov;
    rc = noxtls_x509_verify_cert_with_policy(&s_certs[leaf], (npres > 0U) ? &presented : NULL, &policy, flags);
    (void)noxtls_x509_certificate_chain_free(&presented);
    (void)noxtls_x509_certificate_chain_free(&anchors);
    return rc;
}

static noxtls_return_t verify(uint32_t leaf, const uint32_t *pres, uint32_t npres, const uint32_t *anch, uint32_t nanch)
{
    return verify_ex(leaf, pres, npres, anch, nanch, NULL, 0U, NULL);
}

/** Root (slot 0, key 1, CN=Root) with CA extensions. */
static int make_root(void)
{
    uint8_t e[256];
    cspec_t c;
    memset(&c, 0, sizeof(c));
    c.issuer_cn = "Root";
    c.subject_cn = "Root";
    c.exts = e;
    c.exts_len = ca_exts(e, NULL, 0U);
    c.subj_key = 1;
    c.signer_key = 1;
    c.serial = 1;
    LB_CHECK_OK(make(0U, &c));
    return 0;
}

/** Leaf in slot @p slot under issuer @p issuer_cn / @p signer with given extension TLVs. */
static noxtls_return_t make_leaf(uint32_t slot, const char *issuer_cn, int signer, const char *cn,
                                 const uint8_t *exts, uint32_t exts_len)
{
    cspec_t c;
    memset(&c, 0, sizeof(c));
    c.issuer_cn = issuer_cn;
    c.subject_cn = cn;
    c.exts = exts;
    c.exts_len = exts_len;
    c.subj_key = 9;
    c.signer_key = signer;
    c.serial = 40;
    return make(slot, &c);
}

/* ------------------------------------------------------------------------- */
/* Issue 93: EKU / Key Usage presence                                        */
/* ------------------------------------------------------------------------- */

static int t_eku_ku_presence(void)
{
    static const uint32_t anch[] = { 0U };
    static const uint32_t pres[] = { 2U };
    uint8_t e[512];
    uint32_t n;
    size_t base = lb_alloc_live_bytes();

    LB_RUN(make_root());
    /* Control: serverAuth EKU and digitalSignature KU pass. */
    n = ext(e, k_oid_eku, sizeof(k_oid_eku), 0, k_eku_server, sizeof(k_eku_server));
    n += ext(&e[n], k_oid_ku, sizeof(k_oid_ku), 1, k_ku_ds, sizeof(k_ku_ds));
    LB_CHECK_OK(make_leaf(1U, "Root", 1, "leaf", e, n));
    LB_CHECK_OK(verify(1U, NULL, 0U, anch, 1U));
    /* EKU listing only an unrecognized purpose (Microsoft document signing). */
    n = ext(e, k_oid_eku, sizeof(k_oid_eku), 0, k_eku_docsign, sizeof(k_eku_docsign));
    LB_CHECK_OK(make_leaf(1U, "Root", 1, "leaf", e, n));
    LB_CHECK_EQ(s_certs[1].ext_key_usage_bits, 0U);
    LB_CHECK_EQ(verify(1U, NULL, 0U, anch, 1U), NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
    /* Empty EKU SEQUENCE. */
    n = ext(e, k_oid_eku, sizeof(k_oid_eku), 0, k_eku_empty, sizeof(k_eku_empty));
    LB_CHECK_OK(make_leaf(1U, "Root", 1, "leaf", e, n));
    LB_CHECK_EQ(verify(1U, NULL, 0U, anch, 1U), NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
    /* Key Usage present with no bit set. */
    n = ext(e, k_oid_ku, sizeof(k_oid_ku), 1, k_ku_zero, sizeof(k_ku_zero));
    LB_CHECK_OK(make_leaf(1U, "Root", 1, "leaf", e, n));
    LB_CHECK_EQ(verify(1U, NULL, 0U, anch, 1U), NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
    /* Sub-CA whose Key Usage has no bit set cannot issue. */
    {
        uint8_t ce[256];
        cspec_t c;
        memset(&c, 0, sizeof(c));
        c.issuer_cn = "Root";
        c.subject_cn = "Sub";
        n = ext(ce, k_oid_bc, sizeof(k_oid_bc), 1, k_bc_ca, sizeof(k_bc_ca));
        n += ext(&ce[n], k_oid_ku, sizeof(k_oid_ku), 1, k_ku_zero, sizeof(k_ku_zero));
        c.exts = ce;
        c.exts_len = n;
        c.subj_key = 2;
        c.signer_key = 1;
        c.serial = 2;
        LB_CHECK_OK(make(2U, &c));
        LB_CHECK_OK(make_leaf(1U, "Sub", 2, "leaf", NULL, 0U));
        LB_CHECK_EQ(verify(1U, pres, 1U, anch, 1U), NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
        /* Control: the same sub-CA with keyCertSign issues. */
        c.exts_len = ca_exts(ce, NULL, 0U);
        LB_CHECK_OK(make(2U, &c));
        LB_CHECK_OK(verify(1U, pres, 1U, anch, 1U));
    }
    /* Malformed Key Usage value (not a BIT STRING) rejects at parse. */
    {
        static const uint8_t bad_ku[] = { 0x04, 0x01, 0x80 };
        n = ext(e, k_oid_ku, sizeof(k_oid_ku), 1, bad_ku, sizeof(bad_ku));
        LB_CHECK(make_leaf(1U, "Root", 1, "leaf", e, n) != NOXTLS_RETURN_SUCCESS);
    }
    free_all();
    return lb_expect_no_leak(base, "eku/ku presence");
}

/* ------------------------------------------------------------------------- */
/* Issue 94: name constraints                                                */
/* ------------------------------------------------------------------------- */

/** Sub-CA (slot 2, key 2, CN=Sub) with the given nameConstraints extension. */
static int make_nc_sub(const uint8_t *nc, uint32_t nc_len)
{
    uint8_t e[512];
    cspec_t c;
    memset(&c, 0, sizeof(c));
    c.issuer_cn = "Root";
    c.subject_cn = "Sub";
    c.exts = e;
    c.exts_len = ca_exts(e, nc, nc_len);
    c.subj_key = 2;
    c.signer_key = 1;
    c.serial = 2;
    LB_CHECK_OK(make(2U, &c));
    return 0;
}

static int t_name_constraints(void)
{
    static const uint32_t anch[] = { 0U };
    static const uint32_t pres[] = { 2U };
    uint8_t nc[300];
    uint8_t e[300];
    uint32_t ncl;
    uint32_t n;
    size_t base = lb_alloc_live_bytes();

    LB_RUN(make_root());
    /* Non-critical permitted dNSName corp.example (the audited shape). */
    ncl = nc_one(nc, 0, 0, 0x82U, (const uint8_t *)"corp.example", 12U);
    LB_RUN(make_nc_sub(nc, ncl));
    LB_CHECK(s_certs[2].ext_flags & X509_EXT_FLAG_NAME_CONSTRAINTS);
    n = san_dns(e, "bank.attacker.test");
    LB_CHECK_OK(make_leaf(1U, "Sub", 2, "leaf", e, n));
    LB_CHECK_EQ(verify(1U, pres, 1U, anch, 1U), NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
    n = san_dns(e, "www.corp.example");
    LB_CHECK_OK(make_leaf(1U, "Sub", 2, "leaf", e, n));
    LB_CHECK_OK(verify(1U, pres, 1U, anch, 1U));
    n = san_dns(e, "corp.example");
    LB_CHECK_OK(make_leaf(1U, "Sub", 2, "leaf", e, n));
    LB_CHECK_OK(verify(1U, pres, 1U, anch, 1U));
    n = san_dns(e, "evilcorp.example");
    LB_CHECK_OK(make_leaf(1U, "Sub", 2, "leaf", e, n));
    LB_CHECK_EQ(verify(1U, pres, 1U, anch, 1U), NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
    /* No SAN: a host-name-like CN is checked as a dNSName (hostname matching falls back to it). */
    LB_CHECK_OK(make_leaf(1U, "Sub", 2, "bank.attacker.test", NULL, 0U));
    LB_CHECK_EQ(verify(1U, pres, 1U, anch, 1U), NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
    LB_CHECK_OK(make_leaf(1U, "Sub", 2, "host.corp.example", NULL, 0U));
    LB_CHECK_OK(verify(1U, pres, 1U, anch, 1U));

    /* Critical nameConstraints is now processed (was refused at parse). */
    ncl = nc_one(nc, 1, 0, 0x82U, (const uint8_t *)"corp.example", 12U);
    LB_RUN(make_nc_sub(nc, ncl));
    n = san_dns(e, "www.corp.example");
    LB_CHECK_OK(make_leaf(1U, "Sub", 2, "leaf", e, n));
    LB_CHECK_OK(verify(1U, pres, 1U, anch, 1U));
    n = san_dns(e, "bank.attacker.test");
    LB_CHECK_OK(make_leaf(1U, "Sub", 2, "leaf", e, n));
    LB_CHECK_EQ(verify(1U, pres, 1U, anch, 1U), NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);

    /* Excluded subtree. */
    ncl = nc_one(nc, 1, 1, 0x82U, (const uint8_t *)"bad.example", 11U);
    LB_RUN(make_nc_sub(nc, ncl));
    n = san_dns(e, "x.bad.example");
    LB_CHECK_OK(make_leaf(1U, "Sub", 2, "leaf", e, n));
    LB_CHECK_EQ(verify(1U, pres, 1U, anch, 1U), NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
    n = san_dns(e, "x.good.example");
    LB_CHECK_OK(make_leaf(1U, "Sub", 2, "leaf", e, n));
    LB_CHECK_OK(verify(1U, pres, 1U, anch, 1U));

    /* iPAddress: permitted 10.0.0.0/8. */
    {
        static const uint8_t net[] = { 10, 0, 0, 0, 255, 0, 0, 0 };
        static const uint8_t in_ip[] = { 10, 1, 2, 3 };
        static const uint8_t out_ip[] = { 192, 168, 1, 1 };
        ncl = nc_one(nc, 1, 0, 0x87U, net, sizeof(net));
        LB_RUN(make_nc_sub(nc, ncl));
        n = san_ip(e, in_ip, sizeof(in_ip));
        LB_CHECK_OK(make_leaf(1U, "Sub", 2, "leaf", e, n));
        LB_CHECK_OK(verify(1U, pres, 1U, anch, 1U));
        n = san_ip(e, out_ip, sizeof(out_ip));
        LB_CHECK_OK(make_leaf(1U, "Sub", 2, "leaf", e, n));
        LB_CHECK_EQ(verify(1U, pres, 1U, anch, 1U), NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
    }
    /* directoryName: permitted CN=leaf only. */
    {
        uint8_t dn[64];
        uint32_t dnl = name_cn(dn, "leaf");
        ncl = nc_one(nc, 1, 0, 0xA4U, dn, dnl);
        LB_RUN(make_nc_sub(nc, ncl));
        LB_CHECK_OK(make_leaf(1U, "Sub", 2, "leaf", NULL, 0U));
        LB_CHECK_OK(verify(1U, pres, 1U, anch, 1U));
        LB_CHECK_OK(make_leaf(1U, "Sub", 2, "other", NULL, 0U));
        LB_CHECK_EQ(verify(1U, pres, 1U, anch, 1U), NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
    }
    /* A constraint form that cannot be processed (URI) fails closed only when the name form appears. */
    {
        uint8_t v[64];
        uint32_t vn;
        ncl = nc_one(nc, 1, 0, 0x86U, (const uint8_t *)"corp.example", 12U);
        LB_RUN(make_nc_sub(nc, ncl));
        n = san_dns(e, "www.anything.example");
        LB_CHECK_OK(make_leaf(1U, "Sub", 2, "leaf", e, n));
        LB_CHECK_OK(verify(1U, pres, 1U, anch, 1U));
        vn = tlv(v, 0x86U, (const uint8_t *)"https://x.test/", 15U);
        vn = tlv(v, 0x30U, v, vn);
        n = ext(e, k_oid_san, sizeof(k_oid_san), 0, v, vn);
        LB_CHECK_OK(make_leaf(1U, "Sub", 2, "leaf", e, n));
        LB_CHECK_EQ(verify(1U, pres, 1U, anch, 1U), NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
    }
    /* Malformed nameConstraints (maximum present) rejects at parse. */
    {
        static const uint8_t bad[] = { 0x30, 0x0B, 0xA0, 0x09, 0x30, 0x07, 0x82, 0x02, 'a', 'b', 0x81, 0x01, 0x01 };
        uint8_t ce[300];
        cspec_t c;
        memset(&c, 0, sizeof(c));
        c.issuer_cn = "Root";
        c.subject_cn = "Sub";
        n = ext(nc, k_oid_nc, sizeof(k_oid_nc), 1, bad, sizeof(bad));
        c.exts = ce;
        c.exts_len = ca_exts(ce, nc, n);
        c.subj_key = 2;
        c.signer_key = 1;
        c.serial = 2;
        LB_CHECK(make(2U, &c) != NOXTLS_RETURN_SUCCESS);
    }
    free_all();
    return lb_expect_no_leak(base, "name constraints");
}

/* ------------------------------------------------------------------------- */
/* Issue 95: presented-chain count and signature budget                      */
/* ------------------------------------------------------------------------- */

static int t_path_budget(void)
{
    uint32_t pres[NOXTLS_X509_MAX_PRESENTED_CERTS + 1U];
    uint32_t anch[32];
    uint32_t i;
    cspec_t c;
    uint8_t e[256];
    size_t base = lb_alloc_live_bytes();

    LB_RUN(make_root());
    LB_CHECK_OK(make_leaf(1U, "Root", 1, "leaf", NULL, 0U));
    anch[0] = 0U;
    LB_CHECK_OK(verify(1U, NULL, 0U, anch, 1U));
    /* More presented certificates than NOXTLS_X509_MAX_PRESENTED_CERTS: refused before any signature. */
    for(i = 0U; i <= NOXTLS_X509_MAX_PRESENTED_CERTS; i++) {
        pres[i] = 0U;
    }
    LB_CHECK_EQ(verify(1U, pres, NOXTLS_X509_MAX_PRESENTED_CERTS + 1U, anch, 1U), NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
    LB_CHECK_OK(verify(1U, pres, NOXTLS_X509_MAX_PRESENTED_CERTS, anch, 1U));
    /* 30 same-name anchors with the wrong key ahead of the right one: the signature budget
     * (NOXTLS_X509_MAX_PATH_SIGNATURE_CHECKS) stops the search before the right anchor. */
    memset(&c, 0, sizeof(c));
    c.issuer_cn = "Root";
    c.subject_cn = "Root";
    c.exts = e;
    c.exts_len = ca_exts(e, NULL, 0U);
    c.serial = 3;
    for(i = 0U; i < 30U; i++) {
        c.subj_key = 20 + (int)i;
        c.signer_key = 20 + (int)i;
        LB_CHECK_OK(make(4U + i, &c));
        anch[i] = 4U + i;
    }
    anch[30] = 0U;
#if NOXTLS_X509_MAX_PATH_SIGNATURE_CHECKS < 31U
    LB_CHECK_EQ(verify(1U, NULL, 0U, anch, 31U), NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
#else
    LB_CHECK_OK(verify(1U, NULL, 0U, anch, 31U));
#endif
    /* A few decoys within the budget do not prevent the path. */
    anch[5] = 0U;
    LB_CHECK_OK(verify(1U, NULL, 0U, anch, 6U));
    /* With the right anchor within the budget the path verifies. */
    anch[0] = 0U;
    LB_CHECK_OK(verify(1U, NULL, 0U, anch, 1U));
    free_all();
    return lb_expect_no_leak(base, "path budget");
}

/* ------------------------------------------------------------------------- */
/* Issue 96: trust anchor constraints                                        */
/* ------------------------------------------------------------------------- */

static int t_anchor_constraints(void)
{
    static const uint32_t anch[] = { 0U };
    static const uint32_t pres[] = { 2U };
    uint8_t e[256];
    uint32_t n;
    cspec_t c;
    size_t base = lb_alloc_live_bytes();

    memset(&c, 0, sizeof(c));
    c.issuer_cn = "Pinned";
    c.subject_cn = "Pinned";
    c.subj_key = 1;
    c.signer_key = 1;
    c.serial = 1;
    c.exts = e;
    /* cA=FALSE anchor (a pinned end-entity certificate). */
    n = ext(e, k_oid_bc, sizeof(k_oid_bc), 1, k_bc_not_ca, sizeof(k_bc_not_ca));
    c.exts_len = n;
    LB_CHECK_OK(make(0U, &c));
    LB_CHECK_OK(make_leaf(1U, "Pinned", 1, "victim.test", NULL, 0U));
    LB_CHECK_EQ(verify(1U, NULL, 0U, anch, 1U), NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
    /* The pinned certificate itself still verifies by byte identity. */
    LB_CHECK_OK(verify(0U, NULL, 0U, anch, 1U));
    /* Anchor with Key Usage digitalSignature only. */
    n = ext(e, k_oid_bc, sizeof(k_oid_bc), 1, k_bc_ca, sizeof(k_bc_ca));
    n += ext(&e[n], k_oid_ku, sizeof(k_oid_ku), 1, k_ku_ds, sizeof(k_ku_ds));
    c.exts_len = n;
    LB_CHECK_OK(make(0U, &c));
    LB_CHECK_EQ(verify(1U, NULL, 0U, anch, 1U), NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
    /* Anchor pathLen=0 with an intermediate below it. */
    n = ext(e, k_oid_bc, sizeof(k_oid_bc), 1, k_bc_ca_path0, sizeof(k_bc_ca_path0));
    n += ext(&e[n], k_oid_ku, sizeof(k_oid_ku), 1, k_ku_ca, sizeof(k_ku_ca));
    c.exts_len = n;
    LB_CHECK_OK(make(0U, &c));
    LB_CHECK_OK(verify(1U, NULL, 0U, anch, 1U)); /* direct leaf is fine */
    {
        uint8_t ce[256];
        cspec_t ic;
        memset(&ic, 0, sizeof(ic));
        ic.issuer_cn = "Pinned";
        ic.subject_cn = "Int";
        ic.exts = ce;
        ic.exts_len = ca_exts(ce, NULL, 0U);
        ic.subj_key = 2;
        ic.signer_key = 1;
        ic.serial = 2;
        LB_CHECK_OK(make(2U, &ic));
        LB_CHECK_OK(make_leaf(1U, "Int", 2, "victim.test", NULL, 0U));
        LB_CHECK_EQ(verify(1U, pres, 1U, anch, 1U), NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
        /* Control: an unconstrained CA anchor accepts the same intermediate. */
        c.exts_len = ca_exts(e, NULL, 0U);
        LB_CHECK_OK(make(0U, &c));
        LB_CHECK_OK(verify(1U, pres, 1U, anch, 1U));
    }
    /* Legacy anchor without basicConstraints still issues. */
    c.exts = NULL;
    c.exts_len = 0U;
    LB_CHECK_OK(make(0U, &c));
    LB_CHECK_OK(make_leaf(1U, "Pinned", 1, "victim.test", NULL, 0U));
    LB_CHECK_OK(verify(1U, NULL, 0U, anch, 1U));
    free_all();
    return lb_expect_no_leak(base, "anchor constraints");
}

/* ------------------------------------------------------------------------- */
/* Issue 116: strict ECDSA signature DER                                     */
/* ------------------------------------------------------------------------- */

/** Read one TLV header at der[*pos]; returns content offset and sets *clen; advances *pos past it. */
static uint32_t tlv_read(const uint8_t *der, uint32_t *pos, uint32_t *clen)
{
    uint32_t p = *pos + 1U;
    uint32_t len = der[p++];
    if(len & 0x80U) {
        uint32_t k = len & 0x7FU;
        len = 0U;
        while(k-- > 0U) {
            len = (len << 8) | der[p++];
        }
    }
    *clen = len;
    *pos = p + len;
    return p;
}

/** Rebuild lb_ec_root_cert with the ECDSA-Sig-Value replaced by @p sig. */
static noxtls_return_t ec_root_with_sig(const uint8_t *sig, uint32_t sig_len)
{
    const uint8_t *der = lb_ec_root_cert;
    uint32_t pos = 0U;
    uint32_t clen = 0U;
    uint32_t body = tlv_read(der, &pos, &clen);
    uint32_t tbs_start = body;
    uint32_t q = body;
    uint32_t n = 0U;
    uint8_t bs[256];

    (void)tlv_read(der, &q, &clen);           /* tbs */
    (void)tlv_read(der, &q, &clen);           /* signatureAlgorithm */
    cat(s_tmp, &n, &der[tbs_start], q - tbs_start);
    bs[0] = 0x00U;
    memcpy(&bs[1], sig, sig_len);
    n += tlv(&s_tmp[n], 0x03U, bs, sig_len + 1U);
    n = tlv(s_tmp, 0x30U, s_tmp, n);
    memcpy(s_cert_buf[1], s_tmp, n);
    s_cert_len[1] = n;
    (void)noxtls_x509_certificate_init(&s_certs[1]);
    if(noxtls_x509_certificate_parse_der_nocopy(&s_certs[1], s_cert_buf[1], n) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_CERT_PARSE_FAILED;
    }
    return noxtls_x509_certificate_verify_signature(&s_certs[1], &s_certs[0]);
}

static int t_ecdsa_sig_strict(void)
{
    const uint8_t *sig = NULL;
    uint32_t sig_len = 0U;
    uint8_t m[256];
    uint32_t pos = 0U;
    uint32_t clen = 0U;
    uint32_t r_off;
    uint32_t r_len;
    uint32_t s_off;
    uint32_t s_len;
    uint32_t seq_body;
    uint32_t n;
    size_t base = lb_alloc_live_bytes();

    LB_CHECK_OK(noxtls_x509_certificate_init(&s_certs[0]));
    LB_CHECK_OK(noxtls_x509_certificate_parse_der_nocopy(&s_certs[0], lb_ec_root_cert, lb_ec_root_cert_len));
    LB_CHECK_OK(noxtls_x509_certificate_get_signature(&s_certs[0], &sig, &sig_len));
    LB_CHECK(sig_len < 200U);
    /* Original encoding verifies. */
    LB_CHECK_OK(ec_root_with_sig(sig, sig_len));
    (void)noxtls_x509_certificate_free(&s_certs[1]);
    /* Locate r and s. */
    seq_body = tlv_read(sig, &pos, &clen);
    pos = seq_body;
    r_off = tlv_read(sig, &pos, &r_len);
    s_off = tlv_read(sig, &pos, &s_len);
    /* Trailing byte after the SEQUENCE. */
    memcpy(m, sig, sig_len);
    m[sig_len] = 0x00U;
    LB_CHECK(ec_root_with_sig(m, sig_len + 1U) != NOXTLS_RETURN_SUCCESS);
    (void)noxtls_x509_certificate_free(&s_certs[1]);
    /* Extra INTEGER inside the SEQUENCE. */
    n = 0U;
    cat(m, &n, &sig[seq_body], sig_len - seq_body);
    m[n++] = 0x02U;
    m[n++] = 0x01U;
    m[n++] = 0x01U;
    n = tlv(m, 0x30U, m, n);
    LB_CHECK(ec_root_with_sig(m, n) != NOXTLS_RETURN_SUCCESS);
    (void)noxtls_x509_certificate_free(&s_certs[1]);
    /* Redundant leading zero on r (or a removed sign octet: negative r). */
    {
        uint8_t body[200];
        uint32_t bn = 0U;
        if(sig[r_off] == 0x00U) {
            body[bn++] = 0x02U;
            body[bn++] = (uint8_t)(r_len - 1U);
            cat(body, &bn, &sig[r_off + 1U], r_len - 1U); /* negative r */
        } else {
            body[bn++] = 0x02U;
            body[bn++] = (uint8_t)(r_len + 1U);
            body[bn++] = 0x00U;
            cat(body, &bn, &sig[r_off], r_len);           /* non-minimal r */
        }
        body[bn++] = 0x02U;
        body[bn++] = (uint8_t)s_len;
        cat(body, &bn, &sig[s_off], s_len);
        n = tlv(m, 0x30U, body, bn);
        LB_CHECK(ec_root_with_sig(m, n) != NOXTLS_RETURN_SUCCESS);
        (void)noxtls_x509_certificate_free(&s_certs[1]);
    }
    /* Non-minimal SEQUENCE length (long form for a short length). */
    {
        uint32_t bl = sig_len - seq_body;
        m[0] = 0x30U;
        m[1] = 0x81U;
        m[2] = (uint8_t)bl;
        memcpy(&m[3], &sig[seq_body], bl);
        LB_CHECK(ec_root_with_sig(m, bl + 3U) != NOXTLS_RETURN_SUCCESS);
        (void)noxtls_x509_certificate_free(&s_certs[1]);
    }
    free_all();
    return lb_expect_no_leak(base, "ecdsa strict");
}

/* ------------------------------------------------------------------------- */
/* Issue 191: Validity                                                       */
/* ------------------------------------------------------------------------- */

static int t_validity_required(void)
{
    static const uint8_t empty[] = { 0x30, 0x00 };
    static const uint8_t ia5[] = { 0x30, 0x1E, 0x16, 0x0D, '2', '5', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z',
                                   0x16, 0x0D, '4', '9', '1', '2', '3', '1', '2', '3', '5', '9', '5', '9', 'Z' };
    static const uint8_t one[] = { 0x30, 0x0F, 0x17, 0x0D, '2', '5', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z' };
    static const uint8_t three[] = { 0x30, 0x2D,
                                     0x17, 0x0D, '2', '5', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z',
                                     0x17, 0x0D, '4', '9', '1', '2', '3', '1', '2', '3', '5', '9', '5', '9', 'Z',
                                     0x17, 0x0D, '4', '9', '1', '2', '3', '1', '2', '3', '5', '9', '5', '9', 'Z' };
    cspec_t c;
    size_t base = lb_alloc_live_bytes();

    memset(&c, 0, sizeof(c));
    c.issuer_cn = "Root";
    c.subject_cn = "leaf";
    c.subj_key = 9;
    c.signer_key = 1;
    c.serial = 7;
    LB_CHECK_OK(make(1U, &c));
    c.validity = empty;
    c.validity_len = sizeof(empty);
    LB_CHECK_EQ(make(1U, &c), NOXTLS_RETURN_CERT_PARSE_FAILED);
    c.validity = ia5;
    c.validity_len = sizeof(ia5);
    LB_CHECK_EQ(make(1U, &c), NOXTLS_RETURN_CERT_PARSE_FAILED);
    c.validity = one;
    c.validity_len = sizeof(one);
    LB_CHECK_EQ(make(1U, &c), NOXTLS_RETURN_CERT_PARSE_FAILED);
    c.validity = three;
    c.validity_len = sizeof(three);
    LB_CHECK_EQ(make(1U, &c), NOXTLS_RETURN_CERT_PARSE_FAILED);
    free_all();
    return lb_expect_no_leak(base, "validity");
}

/* ------------------------------------------------------------------------- */
/* Issue 188: extension walker                                               */
/* ------------------------------------------------------------------------- */

static int t_ext_walker(void)
{
    static const uint8_t null_el[] = { 0x05, 0x00 };
    static const uint8_t eku_code[] = { 0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03 };
    static const uint32_t anch[] = { 0U };
    uint8_t e[512];
    uint32_t n;
    cspec_t c;
    size_t base = lb_alloc_live_bytes();

    LB_RUN(make_root());
    memset(&c, 0, sizeof(c));
    c.issuer_cn = "Root";
    c.subject_cn = "leaf";
    c.subj_key = 9;
    c.signer_key = 1;
    c.serial = 8;
    c.exts = e;
    /* Control: well-formed unknown critical extension is refused. */
    c.exts_len = ext(e, k_oid_unknown, sizeof(k_oid_unknown), 1, null_el, sizeof(null_el));
    LB_CHECK(make(1U, &c) != NOXTLS_RETURN_SUCCESS);
    /* Unknown critical extension with an empty extnValue. */
    c.exts_len = ext(e, k_oid_unknown, sizeof(k_oid_unknown), 1, NULL, 0U);
    LB_CHECK(make(1U, &c) != NOXTLS_RETURN_SUCCESS);
    /* A NULL list element hiding a critical extension. */
    n = 0U;
    cat(e, &n, null_el, sizeof(null_el));
    n += ext(&e[n], k_oid_unknown, sizeof(k_oid_unknown), 1, null_el, sizeof(null_el));
    c.exts_len = n;
    LB_CHECK(make(1U, &c) != NOXTLS_RETURN_SUCCESS);
    /* A NULL list element hiding an EKU restriction. */
    n = 0U;
    cat(e, &n, null_el, sizeof(null_el));
    n += ext(&e[n], k_oid_eku, sizeof(k_oid_eku), 0, eku_code, sizeof(eku_code));
    c.exts_len = n;
    LB_CHECK(make(1U, &c) != NOXTLS_RETURN_SUCCESS);
    /* Trailing octets inside one Extension. */
    {
        uint8_t body[64];
        uint32_t bn = 0U;
        bn += tlv(&body[bn], 0x06U, k_oid_unknown, sizeof(k_oid_unknown));
        bn += tlv(&body[bn], 0x04U, null_el, sizeof(null_el));
        cat(body, &bn, null_el, sizeof(null_el));
        c.exts_len = tlv(e, 0x30U, body, bn);
        LB_CHECK(make(1U, &c) != NOXTLS_RETURN_SUCCESS);
    }
    /* Extensions field that is not a SEQUENCE. */
    c.exts = null_el;
    c.exts_len = sizeof(null_el);
    c.exts_raw = 1;
    LB_CHECK(make(1U, &c) != NOXTLS_RETURN_SUCCESS);
    /* Control: non-critical unknown extension with an empty value is ignored; EKU codeSigning rejects. */
    c.exts = e;
    c.exts_raw = 0;
    n = ext(e, k_oid_unknown, sizeof(k_oid_unknown), 0, NULL, 0U);
    n += ext(&e[n], k_oid_eku, sizeof(k_oid_eku), 0, eku_code, sizeof(eku_code));
    c.exts_len = n;
    LB_CHECK_OK(make(1U, &c));
    LB_CHECK_EQ(verify(1U, NULL, 0U, anch, 1U), NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED);
    free_all();
    return lb_expect_no_leak(base, "ext walker");
}

/* ------------------------------------------------------------------------- */
/* Issue 189: IP literal host names                                          */
/* ------------------------------------------------------------------------- */

static int t_ip_hostname(void)
{
    static const uint8_t ip4[] = { 10, 0, 0, 1 };
    static const uint8_t ip6[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    static const uint8_t ip6b[] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04 };
    uint8_t e[256];
    uint32_t n;
    size_t base = lb_alloc_live_bytes();

    n = san_dns(e, "*.0.0.1");
    LB_CHECK_OK(make_leaf(1U, "Root", 1, "leaf", e, n));
    LB_CHECK_EQ(noxtls_x509_certificate_matches_hostname(&s_certs[1], (const uint8_t *)"10.0.0.1", 0U),
                NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH);
    n = san_dns(e, "10.0.0.1");
    LB_CHECK_OK(make_leaf(1U, "Root", 1, "leaf", e, n));
    LB_CHECK_EQ(noxtls_x509_certificate_matches_hostname(&s_certs[1], (const uint8_t *)"10.0.0.1", 0U),
                NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH);
    LB_CHECK_OK(make_leaf(1U, "Root", 1, "10.0.0.1", NULL, 0U));
    LB_CHECK_EQ(noxtls_x509_certificate_matches_hostname(&s_certs[1], (const uint8_t *)"10.0.0.1", 0U),
                NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH);
    n = san_ip(e, ip4, sizeof(ip4));
    LB_CHECK_OK(make_leaf(1U, "Root", 1, "leaf", e, n));
    LB_CHECK_OK(noxtls_x509_certificate_matches_hostname(&s_certs[1], (const uint8_t *)"10.0.0.1", 0U));
    LB_CHECK_EQ(noxtls_x509_certificate_matches_hostname(&s_certs[1], (const uint8_t *)"10.0.0.2", 0U),
                NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH);
    n = san_ip(e, ip6, sizeof(ip6));
    LB_CHECK_OK(make_leaf(1U, "Root", 1, "leaf", e, n));
    LB_CHECK_OK(noxtls_x509_certificate_matches_hostname(&s_certs[1], (const uint8_t *)"::1", 0U));
    LB_CHECK_OK(noxtls_x509_certificate_matches_hostname(&s_certs[1], (const uint8_t *)"[::1]", 0U));
    LB_CHECK_OK(noxtls_x509_certificate_matches_hostname(&s_certs[1], (const uint8_t *)"0:0:0:0:0:0:0:1", 0U));
    LB_CHECK_EQ(noxtls_x509_certificate_matches_hostname(&s_certs[1], (const uint8_t *)"::2", 0U),
                NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH);
    n = san_ip(e, ip6b, sizeof(ip6b));
    LB_CHECK_OK(make_leaf(1U, "Root", 1, "leaf", e, n));
    LB_CHECK_OK(noxtls_x509_certificate_matches_hostname(&s_certs[1], (const uint8_t *)"2001:db8::1.2.3.4", 0U));
    LB_CHECK_OK(noxtls_x509_certificate_matches_hostname(&s_certs[1], (const uint8_t *)"2001:DB8::102:304", 0U));
    /* DNS names are unaffected. */
    n = san_dns(e, "*.example.test");
    LB_CHECK_OK(make_leaf(1U, "Root", 1, "leaf", e, n));
    LB_CHECK_OK(noxtls_x509_certificate_matches_hostname(&s_certs[1], (const uint8_t *)"www.example.test", 0U));
    free_all();
    return lb_expect_no_leak(base, "ip hostname");
}

/* ------------------------------------------------------------------------- */
/* Issues 184-187: CRLs                                                      */
/* ------------------------------------------------------------------------- */

static uint8_t s_crl_buf[6][1024];

/**
 * Build a CRL issued by the EC root (CN=CRoot) into s_crl_buf[slot]. @p issuer_name overrides the
 * issuer Name TLV; @p serials lists revoked serials; @p entry_ext optional entry Extensions TLV;
 * @p exts optional crlExtensions Extension TLVs.
 */
static uint32_t build_crl(uint32_t slot, const uint8_t *issuer_name, uint32_t issuer_len, const char *next_update,
                          const uint8_t *serials, uint32_t nserials, const uint8_t *entry_ext, uint32_t entry_ext_len,
                          const uint8_t *exts, uint32_t exts_len)
{
    static const uint8_t version[] = { 0x02, 0x01, 0x01 };
    static const uint8_t this_upd[] = { 0x17, 0x0D, '2', '5', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z' };
    uint32_t n = 0U;
    uint32_t i;
    cat(s_tbs, &n, version, sizeof(version));
    n += sig_alg(&s_tbs[n], KEY_EC);
    if(issuer_name != NULL) {
        cat(s_tbs, &n, issuer_name, issuer_len);
    } else {
        n += name_cn(&s_tbs[n], "CRoot");
    }
    cat(s_tbs, &n, this_upd, sizeof(this_upd));
    n += tlv(&s_tbs[n], 0x17U, (const uint8_t *)next_update, 13U);
    if(nserials > 0U) {
        uint8_t list[512];
        uint32_t ln = 0U;
        for(i = 0U; i < nserials; i++) {
            uint8_t ent[128];
            uint32_t en = 0U;
            ent[en++] = 0x02U;
            ent[en++] = 0x01U;
            ent[en++] = serials[i];
            cat(ent, &en, this_upd, sizeof(this_upd));
            if(entry_ext != NULL) {
                cat(ent, &en, entry_ext, entry_ext_len);
            }
            ln += tlv(&list[ln], 0x30U, ent, en);
        }
        n += tlv(&s_tbs[n], 0x30U, list, ln);
    }
    if(exts != NULL) {
        uint8_t e[512];
        uint32_t en = tlv(e, 0x30U, exts, exts_len);
        n += tlv(&s_tbs[n], 0xA0U, e, en);
    }
    n = tlv(s_tbs, 0x30U, s_tbs, n);
    return sign_wrap(s_crl_buf[slot], s_tbs, n, KEY_EC);
}

static noxtls_x509_crl_t s_crl[6];

static noxtls_return_t parse_crl(uint32_t slot, uint32_t len)
{
    (void)noxtls_x509_crl_init(&s_crl[slot]);
    return noxtls_x509_crl_parse_der_nocopy(&s_crl[slot], s_crl_buf[slot], len);
}

static void free_crls(void)
{
    uint32_t i;
    for(i = 0U; i < 6U; i++) {
        s_crl[i].next = NULL;
        noxtls_x509_crl_free(&s_crl[i]);
    }
}

static int t_crl_semantics(void)
{
    static const uint32_t anch[] = { 0U };
    static const uint8_t revoked40[] = { 40 };
    static const char *k_next = "491231235959Z";
    static const char *k_stale = "260101000000Z";
    static const uint8_t oid_delta[] = { 0x55, 0x1D, 0x1B };
    static const uint8_t oid_idp[] = { 0x55, 0x1D, 0x1C };
    static const uint8_t oid_reason[] = { 0x55, 0x1D, 0x15 };
    static const uint8_t delta_val[] = { 0x02, 0x01, 0x05 };
    static const uint8_t idp_ca_only[] = { 0x30, 0x03, 0x82, 0x01, 0xFF };
    static const uint8_t idp_user_only[] = { 0x30, 0x03, 0x81, 0x01, 0xFF };
    static const uint8_t reason_val[] = { 0x0A, 0x01, 0x01 };
    static const uint8_t null_val[] = { 0x05, 0x00 };
    uint8_t e[256];
    uint8_t x[128];
    uint32_t n;
    uint32_t l0;
    uint32_t l1;
    noxtls_x509_verify_flags_t flags = 0U;
    cspec_t c;
    size_t base = lb_alloc_live_bytes();

    /* EC root CN=CRoot (anchor, slot 0) and leaf serial 40 (slot 1). */
    memset(&c, 0, sizeof(c));
    c.issuer_cn = "CRoot";
    c.subject_cn = "CRoot";
    c.exts = e;
    c.exts_len = ca_exts(e, NULL, 0U);
    c.subj_key = KEY_EC;
    c.signer_key = KEY_EC;
    c.serial = 1;
    LB_CHECK_OK(make(0U, &c));
    LB_CHECK_OK(make_leaf(1U, "CRoot", KEY_EC, "leaf", NULL, 0U));
    LB_CHECK_OK(verify(1U, NULL, 0U, anch, 1U));

    /* 185: an older empty CRL ahead of the listing CRL no longer hides the revocation. */
    l0 = build_crl(0U, NULL, 0U, k_next, NULL, 0U, NULL, 0U, NULL, 0U);
    l1 = build_crl(1U, NULL, 0U, k_next, revoked40, 1U, NULL, 0U, NULL, 0U);
    LB_CHECK_OK(parse_crl(0U, l0));
    LB_CHECK_OK(parse_crl(1U, l1));
    s_crl[0].next = &s_crl[1];
    LB_CHECK_EQ(verify_ex(1U, NULL, 0U, anch, 1U, &s_crl[0], 0U, &flags), NOXTLS_RETURN_CERT_REVOKED);
    s_crl[0].next = NULL;
    LB_CHECK_EQ(verify_ex(1U, NULL, 0U, anch, 1U, &s_crl[1], 0U, NULL), NOXTLS_RETURN_CERT_REVOKED);
    LB_CHECK_OK(verify_ex(1U, NULL, 0U, anch, 1U, &s_crl[0], 0U, NULL));
    /* A stale CRL alone still fails closed; next to a current one it does not block. */
    free_crls();
    l0 = build_crl(0U, NULL, 0U, k_stale, NULL, 0U, NULL, 0U, NULL, 0U);
    l1 = build_crl(1U, NULL, 0U, k_next, NULL, 0U, NULL, 0U, NULL, 0U);
    LB_CHECK_OK(parse_crl(0U, l0));
    LB_CHECK_OK(parse_crl(1U, l1));
    LB_CHECK_EQ(verify_ex(1U, NULL, 0U, anch, 1U, &s_crl[0], 0U, NULL), NOXTLS_RETURN_CRL_EXPIRED);
    s_crl[0].next = &s_crl[1];
    LB_CHECK_OK(verify_ex(1U, NULL, 0U, anch, 1U, &s_crl[0], 0U, NULL));
    free_crls();

    /* 186: CRL issuer in PrintableString / different case still designates the CA. */
    n = name_cn_tag(x, "croot", 0x13U);
    l0 = build_crl(0U, x, n, k_next, revoked40, 1U, NULL, 0U, NULL, 0U);
    LB_CHECK_OK(parse_crl(0U, l0));
    LB_CHECK_EQ(verify_ex(1U, NULL, 0U, anch, 1U, &s_crl[0], 0U, NULL), NOXTLS_RETURN_CERT_REVOKED);
    free_crls();

    /* 184: crlExtensions are read. */
    n = ext(x, k_oid_unknown, sizeof(k_oid_unknown), 1, null_val, sizeof(null_val));
    l0 = build_crl(0U, NULL, 0U, k_next, NULL, 0U, NULL, 0U, x, n);
    LB_CHECK_EQ(parse_crl(0U, l0), NOXTLS_RETURN_CRL_PARSE_FAILED);
    n = ext(x, oid_delta, sizeof(oid_delta), 1, delta_val, sizeof(delta_val));
    l0 = build_crl(0U, NULL, 0U, k_next, NULL, 0U, NULL, 0U, x, n);
    LB_CHECK_EQ(parse_crl(0U, l0), NOXTLS_RETURN_CRL_PARSE_FAILED);
    l0 = build_crl(0U, NULL, 0U, k_next, NULL, 0U, NULL, 0U, null_val, sizeof(null_val));
    LB_CHECK_EQ(parse_crl(0U, l0), NOXTLS_RETURN_CRL_PARSE_FAILED);
    /* Non-critical unknown CRL extension and a non-critical entry reasonCode are fine. */
    n = ext(x, k_oid_unknown, sizeof(k_oid_unknown), 0, null_val, sizeof(null_val));
    {
        uint8_t ee[64];
        uint32_t een = ext(ee, oid_reason, sizeof(oid_reason), 0, reason_val, sizeof(reason_val));
        een = tlv(ee, 0x30U, ee, een);
        l0 = build_crl(0U, NULL, 0U, k_next, revoked40, 1U, ee, een, x, n);
        LB_CHECK_OK(parse_crl(0U, l0));
        LB_CHECK_EQ(verify_ex(1U, NULL, 0U, anch, 1U, &s_crl[0], 0U, NULL), NOXTLS_RETURN_CERT_REVOKED);
        free_crls();
        /* A critical entry extension cannot be processed: the CRL is refused. */
        een = ext(ee, k_oid_unknown, sizeof(k_oid_unknown), 1, null_val, sizeof(null_val));
        een = tlv(ee, 0x30U, ee, een);
        l0 = build_crl(0U, NULL, 0U, k_next, revoked40, 1U, ee, een, NULL, 0U);
        LB_CHECK_EQ(parse_crl(0U, l0), NOXTLS_RETURN_CRL_PARSE_FAILED);
    }
    /* IDP onlyContainsCACerts: out of scope for the leaf; it neither revokes nor covers it. */
    n = ext(x, oid_idp, sizeof(oid_idp), 1, idp_ca_only, sizeof(idp_ca_only));
    l0 = build_crl(0U, NULL, 0U, k_next, revoked40, 1U, NULL, 0U, x, n);
    LB_CHECK_OK(parse_crl(0U, l0));
    flags = 0U;
    LB_CHECK_OK(verify_ex(1U, NULL, 0U, anch, 1U, &s_crl[0], 0U, &flags));
    LB_CHECK((flags & NOXTLS_X509_VERIFY_FLAG_CRL_USED) == 0U);
    LB_CHECK((flags & NOXTLS_X509_VERIFY_FLAG_CRL_LEVEL_UNCOVERED) != 0U);
    /* ... and it does not hide a later complete CRL. */
    l1 = build_crl(1U, NULL, 0U, k_next, revoked40, 1U, NULL, 0U, NULL, 0U);
    LB_CHECK_OK(parse_crl(1U, l1));
    s_crl[0].next = &s_crl[1];
    LB_CHECK_EQ(verify_ex(1U, NULL, 0U, anch, 1U, &s_crl[0], 0U, NULL), NOXTLS_RETURN_CERT_REVOKED);
    free_crls();
    /* IDP onlyContainsUserCerts applies to the leaf. */
    n = ext(x, oid_idp, sizeof(oid_idp), 1, idp_user_only, sizeof(idp_user_only));
    l0 = build_crl(0U, NULL, 0U, k_next, revoked40, 1U, NULL, 0U, x, n);
    LB_CHECK_OK(parse_crl(0U, l0));
    LB_CHECK_EQ(verify_ex(1U, NULL, 0U, anch, 1U, &s_crl[0], 0U, NULL), NOXTLS_RETURN_CERT_REVOKED);
    free_crls();
    /* IDP with a distributionPoint: in scope only for certificates naming the same point. */
    {
        static const char *uri = "http://crl.test/a.crl";
        uint8_t gn[64];
        uint8_t idp[96];
        uint8_t dp[128];
        uint32_t gnl = tlv(gn, 0x86U, (const uint8_t *)uri, (uint32_t)strlen(uri));
        uint32_t il = tlv(idp, 0xA0U, gn, gnl);        /* fullName [0] */
        il = tlv(idp, 0xA0U, idp, il);                 /* distributionPoint [0] */
        il = tlv(idp, 0x30U, idp, il);
        n = ext(x, oid_idp, sizeof(oid_idp), 1, idp, il);
        l0 = build_crl(0U, NULL, 0U, k_next, revoked40, 1U, NULL, 0U, x, n);
        LB_CHECK_OK(parse_crl(0U, l0));
        /* Leaf without cRLDistributionPoints: out of scope. */
        LB_CHECK_OK(verify_ex(1U, NULL, 0U, anch, 1U, &s_crl[0], 0U, NULL));
        /* Leaf whose CRLDP names the same URI: revoked. */
        {
            uint32_t dl = tlv(dp, 0xA0U, gn, gnl);
            uint8_t le[200];
            uint32_t len_ext;
            dl = tlv(dp, 0xA0U, dp, dl);
            dl = tlv(dp, 0x30U, dp, dl);
            dl = tlv(dp, 0x30U, dp, dl);
            len_ext = ext(le, k_oid_crldp, sizeof(k_oid_crldp), 0, dp, dl);
            LB_CHECK_OK(make_leaf(2U, "CRoot", KEY_EC, "leaf", le, len_ext));
            LB_CHECK_EQ(verify_ex(2U, NULL, 0U, anch, 1U, &s_crl[0], 0U, NULL), NOXTLS_RETURN_CERT_REVOKED);
        }
        free_crls();
    }

    /* 187: coverage. A CRL for an unrelated issuer leaves the level uncovered. */
    n = name_cn(x, "Unrelated");
    l0 = build_crl(0U, x, n, k_next, NULL, 0U, NULL, 0U, NULL, 0U);
    LB_CHECK_OK(parse_crl(0U, l0));
    flags = 0U;
    LB_CHECK_OK(verify_ex(1U, NULL, 0U, anch, 1U, &s_crl[0], 0U, &flags));
    LB_CHECK((flags & NOXTLS_X509_VERIFY_FLAG_CRL_LEVEL_UNCOVERED) != 0U);
    LB_CHECK_EQ(verify_ex(1U, NULL, 0U, anch, 1U, &s_crl[0], 1U, NULL), NOXTLS_RETURN_CRL_VERIFY_FAILED);
    LB_CHECK_EQ(noxtls_x509_get_crl_require_coverage(), 0);
    noxtls_x509_set_crl_require_coverage(1);
    LB_CHECK_EQ(verify_ex(1U, NULL, 0U, anch, 1U, &s_crl[0], 0U, NULL), NOXTLS_RETURN_CRL_VERIFY_FAILED);
    noxtls_x509_set_crl_require_coverage(0);
    /* A covering CRL satisfies the requirement. */
    l1 = build_crl(1U, NULL, 0U, k_next, NULL, 0U, NULL, 0U, NULL, 0U);
    LB_CHECK_OK(parse_crl(1U, l1));
    s_crl[0].next = &s_crl[1];
    flags = 0U;
    LB_CHECK_OK(verify_ex(1U, NULL, 0U, anch, 1U, &s_crl[0], 1U, &flags));
    LB_CHECK((flags & NOXTLS_X509_VERIFY_FLAG_CRL_LEVEL_UNCOVERED) == 0U);
    free_crls();
    free_all();
    return lb_expect_no_leak(base, "crl semantics");
}

/* ------------------------------------------------------------------------- */
/* Issue 190: ML-DSA certificate signature over the TBSCertificate           */
/* ------------------------------------------------------------------------- */

#if NOXTLS_FEATURE_ML_DSA && defined(NOXTLS_HAVE_CERT_WRITE) && NOXTLS_HAVE_CERT_WRITE
static uint8_t s_mldsa_pk[NOXTLS_MLDSA_MAX_PUBLIC_KEY_LEN];
static uint8_t s_mldsa_sk[4896];
static uint8_t s_mldsa_sig[4627];
static uint8_t s_mldsa_cert[12000];
static uint8_t s_mldsa_pkcs8[5000];

static int t_mldsa_cert_signature(void)
{
    static const uint8_t oid[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11 };
    uint8_t seed[32];
    uint8_t alg[16];
    uint32_t alg_len;
    uint32_t pk_len = noxtls_mldsa_public_key_len(NOXTLS_MLDSA_44);
    uint32_t sk_len = noxtls_mldsa_secret_key_len(NOXTLS_MLDSA_44);
    uint32_t sig_len;
    uint32_t n = 0U;
    uint32_t tbs_len;
    uint8_t name[64];
    uint32_t name_len;
    size_t base = lb_alloc_live_bytes();

    memset(seed, 0x5A, sizeof(seed));
    LB_CHECK_OK(noxtls_mldsa_keygen_ex(NOXTLS_MLDSA_44, seed, s_mldsa_pk, s_mldsa_sk, NULL, 0U));
    alg_len = tlv(alg, 0x06U, oid, sizeof(oid));
    alg_len = tlv(alg, 0x30U, alg, alg_len);
    /* Writer round trip: a certificate the library generates verifies. */
    {
        uint8_t ver[] = { 0x02, 0x01, 0x00 };
        uint32_t k8 = 0U;
        uint32_t out_len = 0U;
        static const uint8_t serial[] = { 0x01 };
        cat(s_mldsa_pkcs8, &k8, ver, sizeof(ver));
        cat(s_mldsa_pkcs8, &k8, alg, alg_len);
        k8 += tlv(&s_mldsa_pkcs8[k8], 0x04U, s_mldsa_sk, sk_len);
        k8 = tlv(s_mldsa_pkcs8, 0x30U, s_mldsa_pkcs8, k8);
        name_len = name_cn(name, "pq");
        LB_CHECK_OK(noxtls_x509_certificate_generate_self_signed_ex(serial, sizeof(serial), name, name_len, name, name_len,
                    (const uint8_t *)"250101000000Z", (const uint8_t *)"491231235959Z",
                    oid, sizeof(oid), NULL, 0U, s_mldsa_pk, pk_len, oid, sizeof(oid),
                    s_mldsa_pkcs8, k8, NOXTLS_HASH_SHA_512, s_mldsa_cert, sizeof(s_mldsa_cert), &out_len));
        LB_CHECK_OK(noxtls_x509_certificate_init(&s_certs[0]));
        LB_CHECK_OK(noxtls_x509_certificate_parse_der_nocopy(&s_certs[0], s_mldsa_cert, out_len));
        LB_CHECK_OK(noxtls_x509_certificate_verify_signature(&s_certs[0], &s_certs[0]));
        (void)noxtls_x509_certificate_free(&s_certs[0]);
    }
    /* A signature over SHA-512(TBS) instead of the TBS is rejected. */
    {
        static const uint8_t version[] = { 0xA0, 0x03, 0x02, 0x01, 0x02 };
        static const uint8_t validity[] = { 0x30, 0x1E, 0x17, 0x0D, '2', '5', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z',
                                            0x17, 0x0D, '4', '9', '1', '2', '3', '1', '2', '3', '5', '9', '5', '9', 'Z' };
        static const uint8_t serial[] = { 0x02, 0x01, 0x05 };
        uint8_t hash[64];
        noxtls_sha512_ctx_t ctx;
        uint8_t *bits = NULL;
        n = 0U;
        cat(s_mldsa_cert, &n, version, sizeof(version));
        cat(s_mldsa_cert, &n, serial, sizeof(serial));
        cat(s_mldsa_cert, &n, alg, alg_len);
        cat(s_mldsa_cert, &n, name, name_len);
        cat(s_mldsa_cert, &n, validity, sizeof(validity));
        cat(s_mldsa_cert, &n, name, name_len);
        {
            uint32_t sp = 0U;
            uint8_t *spk = &s_mldsa_cert[n];
            bits = (uint8_t *)malloc(pk_len + 1U);
            LB_CHECK(bits != NULL);
            bits[0] = 0x00U;
            memcpy(&bits[1], s_mldsa_pk, pk_len);
            cat(spk, &sp, alg, alg_len);
            sp += tlv(&spk[sp], 0x03U, bits, pk_len + 1U);
            free(bits);
            sp = tlv(spk, 0x30U, spk, sp);
            n += sp;
        }
        tbs_len = tlv(s_mldsa_cert, 0x30U, s_mldsa_cert, n);
        (void)noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512);
        (void)noxtls_sha512_update(&ctx, s_mldsa_cert, tbs_len);
        (void)noxtls_sha512_finish(&ctx, hash);
        for(n = 0U; n < 2U; n++) {
            uint32_t total = tbs_len;
            uint32_t cl;
            sig_len = sizeof(s_mldsa_sig);
            LB_CHECK_OK(noxtls_mldsa_sign(NOXTLS_MLDSA_44, s_mldsa_sk, (n == 0U) ? s_mldsa_cert : hash,
                                          (n == 0U) ? tbs_len : 64U, s_mldsa_sig, &sig_len));
            cat(s_mldsa_cert, &total, alg, alg_len);
            bits = (uint8_t *)malloc(sig_len + 1U);
            LB_CHECK(bits != NULL);
            bits[0] = 0x00U;
            memcpy(&bits[1], s_mldsa_sig, sig_len);
            total += tlv(&s_mldsa_cert[total], 0x03U, bits, sig_len + 1U);
            free(bits);
            cl = tlv(s_mldsa_cert, 0x30U, s_mldsa_cert, total);
            LB_CHECK_OK(noxtls_x509_certificate_init(&s_certs[0]));
            LB_CHECK_OK(noxtls_x509_certificate_parse_der_nocopy(&s_certs[0], s_mldsa_cert, cl));
            if(n == 0U) {
                LB_CHECK_OK(noxtls_x509_certificate_verify_signature(&s_certs[0], &s_certs[0]));
            } else {
                LB_CHECK_EQ(noxtls_x509_certificate_verify_signature(&s_certs[0], &s_certs[0]),
                            NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED);
            }
            (void)noxtls_x509_certificate_free(&s_certs[0]);
            /* Unwrap the Certificate SEQUENCE back to the TBS for the next round. */
            {
                uint32_t pos = 0U;
                uint32_t body = tlv_read(s_mldsa_cert, &pos, &cl);
                memmove(s_mldsa_cert, &s_mldsa_cert[body], tbs_len);
            }
        }
    }
    return lb_expect_no_leak(base, "mldsa cert");
}
#endif

/* ------------------------------------------------------------------------- */
/* Issue 102: PEM buffer size                                                */
/* ------------------------------------------------------------------------- */

static int t_pem_buffer_size(void)
{
    static uint8_t der[400];
    static uint8_t pem[1024];
    uint32_t len;
    uint32_t out_len = 0U;

    memset(der, 0xA5, sizeof(der));
    LB_CHECK_EQ(noxtls_certificate_pem_buffer_size(0U), 0U);
    for(len = 1U; len <= sizeof(der); len++) {
        uint32_t need = noxtls_certificate_pem_buffer_size(len);
        LB_CHECK((need > 0U) && (need <= sizeof(pem)));
        LB_CHECK_OK(noxtls_certificate_der_to_pem_ex(der, len, pem, need, &out_len));
        LB_CHECK_EQ(out_len + 1U, need);
        LB_CHECK_EQ(noxtls_certificate_der_to_pem_ex(der, len, pem, need - 1U, &out_len), NOXTLS_RETURN_FAILED);
        if(len < 80U) {
            LB_CHECK(need > (2U * len));  /* the former 2x sizing was too small here */
        }
    }
    return 0;
}

static const lb_test_case_t k_cases[] = {
    { "x509_audit_eku_ku_presence", t_eku_ku_presence },
    { "x509_audit_name_constraints", t_name_constraints },
    { "x509_audit_path_budget", t_path_budget },
    { "x509_audit_anchor_constraints", t_anchor_constraints },
    { "x509_audit_ecdsa_sig_strict", t_ecdsa_sig_strict },
    { "x509_audit_validity_required", t_validity_required },
    { "x509_audit_ext_walker", t_ext_walker },
    { "x509_audit_ip_hostname", t_ip_hostname },
    { "x509_audit_crl_semantics", t_crl_semantics },
#if NOXTLS_FEATURE_ML_DSA && defined(NOXTLS_HAVE_CERT_WRITE) && NOXTLS_HAVE_CERT_WRITE
    { "x509_audit_mldsa_cert_signature", t_mldsa_cert_signature },
#endif
    { "x509_audit_pem_buffer_size", t_pem_buffer_size },
};

int main(int argc, char **argv)
{
    return lb_main(argc, argv, "x509_audit", k_cases, sizeof(k_cases) / sizeof(k_cases[0]));
}
