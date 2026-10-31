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
* File:    pkc_mem_vectors.c
* Summary: PKC correctness gate for the memory-reduction work (known answers + negatives)
*
*****************************************************************************/

/*
 * pkc_mem_vectors: correctness gate for the classic PKC primitives, written so that
 * memory-oriented rewrites (compact tables, shared curve descriptors, CRT, public-only
 * RSA keys, per-curve enables) can be checked against independent known answers.
 * Only the public API is used (no curve-parameter writes), so the test is agnostic to
 * the internal representation.
 *
 *   ECDSA  RFC 6979 A.2.5-A.2.7 and CAVP SigVer verify-only vectors (incl. expected
 *          failures), import/keygen sign+verify round trips, r/s range checks,
 *          corrupted signatures, wrong-size signatures, invalid public keys.
 *   ECDH   CAVP ECC CDH vectors (Q = d*G and Z), keygen round trips, peer-point
 *          validation (off-curve, coordinate >= p, identity, size mismatch).
 *   RSA    OpenSSL-generated 2048/3072/4096 keys: deterministic PKCS#1 v1.5 signatures
 *          on the CRT and the d-only path, PSS verify of OpenSSL signatures and PSS
 *          round trips, decryption of OpenSSL ciphertexts (decrypt, decrypt_crt_only),
 *          public-only keys (noxtls_rsa_key_init_public), CRT fault detection, and
 *          rejection of malformed signatures / private operations on public keys.
 *   X25519 / X448  RFC 7748 5.2 (incl. 1 and 1000 iterations), 6.1, 6.2.
 *   Ed25519        RFC 8032 TEST 3 plus negatives (ed25519_rfc8032_test covers 1 and 2).
 *   FFDHE2048      generate/shared round trip and peer validation.
 *
 * Every feature and every curve is compiled only when enabled (see pkc_mem_data.h).
 * Exit code 0 = all checks passed.
 */

#include <stdio.h>
#include <string.h>

#include "noxtls_common.h"
#include "common/noxtls_ct.h"
#include "mdigest/noxtls_hash.h"
#include "pkc_mem_data.h"

#if PKC_MEM_HAVE_ECC
#include "pkc/ecc/noxtls_ecc.h"
#endif
#if PKC_MEM_HAVE_ECDSA
#include "pkc/ecdsa/noxtls_ecdsa.h"
#endif
#if PKC_MEM_HAVE_ECDH
#include "pkc/ecdh/noxtls_ecdh.h"
#endif
#if PKC_MEM_HAVE_RSA
#include "pkc/rsa/noxtls_rsa.h"
#endif
#if PKC_MEM_HAVE_X25519
#include "pkc/x25519/noxtls_x25519.h"
#endif
#if PKC_MEM_HAVE_X448
#include "pkc/x448/noxtls_x448.h"
#endif
#if PKC_MEM_HAVE_ED25519
#include "pkc/ed25519/noxtls_ed25519.h"
#endif
#if PKC_MEM_HAVE_DH
#include "pkc/dh/noxtls_dh.h"
#endif

#if PKC_MEM_HAVE_ANY
static unsigned g_checks;
static unsigned g_failures;

/**
 * @brief Record one check.
 * @param[in] ok   Non-zero when the check passed.
 * @param[in] what Description printed on failure.
 * @param[in] ctx  Vector / curve context printed on failure (may be NULL).
 * @return @p ok normalized to 0/1.
 */
static int check(int ok, const char *what, const char *ctx)
{
    g_checks++;
    if(ok == 0) {
        g_failures++;
        fprintf(stderr, "FAIL: %s%s%s\n", what, (ctx != NULL) ? " -- " : "", (ctx != NULL) ? ctx : "");
        return 0;
    }
    return 1;
}

#endif /* PKC_MEM_HAVE_ANY */

#if PKC_MEM_HAVE_ECDH || PKC_MEM_HAVE_RSA || PKC_MEM_HAVE_X25519 || PKC_MEM_HAVE_X448
/** @brief 1 if every byte of @p p is zero. */
static int all_zero(const uint8_t *p, uint32_t n)
{
    uint8_t acc = 0U;
    uint32_t i;
    for(i = 0U; i < n; i++) {
        acc |= p[i];
    }
    return acc == 0U;
}

#endif

#if PKC_MEM_HAVE_ECDSA || PKC_MEM_HAVE_RSA
/** @brief Map 256/384/512 to the library hash id; 0 when that hash is not compiled in. */
static int hash_for_bits(uint32_t bits, noxtls_hash_algos_t *out)
{
    if(bits == 256U) {
        *out = NOXTLS_HASH_SHA_256;
        return 1;
    }
#if PKC_MEM_HAVE_SHA384
    if(bits == 384U) {
        *out = NOXTLS_HASH_SHA_384;
        return 1;
    }
#endif
#if PKC_MEM_HAVE_SHA512
    if(bits == 512U) {
        *out = NOXTLS_HASH_SHA_512;
        return 1;
    }
#endif
    return 0;
}
#endif

/* ------------------------------------------------------------------ ECC */
#if PKC_MEM_HAVE_ECC_CURVES

typedef struct
{
    uint32_t bits;
    ecc_curve_t id;
    uint32_t size;
    const char *name;
} curve_info_t;

static const curve_info_t g_curves[] = {
#if PKC_MEM_HAVE_P256
    { 256U, NOXTLS_ECC_SECP256R1, 32U, "P-256" },
#endif
#if PKC_MEM_HAVE_P384
    { 384U, NOXTLS_ECC_SECP384R1, 48U, "P-384" },
#endif
#if PKC_MEM_HAVE_P521
    { 521U, NOXTLS_ECC_SECP521R1, 66U, "P-521" },
#endif
};
#define CURVE_COUNT (sizeof(g_curves) / sizeof(g_curves[0]))

/** @brief Enabled curve for @p bits, or NULL when that curve is compiled out. */
static const curve_info_t *curve_for_bits(uint32_t bits)
{
    size_t i;
    for(i = 0U; i < CURVE_COUNT; i++) {
        if(g_curves[i].bits == bits) {
            return &g_curves[i];
        }
    }
    return NULL;
}

/** @brief Load an affine point from hex (both coordinates right-aligned to the curve size). */
static int load_point(ecc_point_t *pt, const curve_info_t *c, const char *x, const char *y)
{
    (void)memset(pt, 0, sizeof(*pt));
    pt->size = c->size;
    return pkc_mem_unhex_fixed(pt->x, c->size, x) && pkc_mem_unhex_fixed(pt->y, c->size, y);
}

#if PKC_MEM_HAVE_ECDSA
/** @brief Public-only key: noxtls_ecc_key_init + Q copied in (the cert-verify pattern). */
static int load_public_key(ecc_key_t *key, const curve_info_t *c, const char *x, const char *y)
{
    if(noxtls_ecc_key_init(key, c->id) != NOXTLS_RETURN_SUCCESS) {
        return 0;
    }
    if((pkc_mem_unhex_fixed(key->Q.x, c->size, x) == 0) || (pkc_mem_unhex_fixed(key->Q.y, c->size, y) == 0)) {
        (void)noxtls_ecc_key_free(key);
        return 0;
    }
    key->Q.size = c->size;
    return 1;
}
#endif

/** @brief Import an RFC 6979 / CAVP private scalar given as hex. */
static noxtls_return_t import_private_hex(ecc_key_t *key, const curve_info_t *c, const char *d_hex)
{
    uint8_t d[66];
    noxtls_return_t rc;
    (void)memset(key, 0, sizeof(*key)); /* noxtls_ecc_key_free() is then safe on every path */
    if(pkc_mem_unhex_fixed(d, c->size, d_hex) == 0) {
        return NOXTLS_RETURN_FAILED;
    }
    rc = noxtls_ecc_key_import_private(key, c->id, d, c->size);
    noxtls_secure_zero(d, sizeof(d));
    return rc;
}

/** @brief The RFC 6979 key pair for @p bits. */
static const pkc_mem_ecc_keypair_t *rfc6979_key(uint32_t bits)
{
    uint32_t i;
    for(i = 0U; i < PKC_MEM_RFC6979_KEY_COUNT; i++) {
        if(pkc_mem_rfc6979_keys[i].curve_bits == bits) {
            return &pkc_mem_rfc6979_keys[i];
        }
    }
    return NULL;
}

/** @brief out = a + b over @p n big-endian bytes; returns the carry out. */
static uint32_t add_be(uint8_t *out, const uint8_t *a, const uint8_t *b, uint32_t n)
{
    uint32_t carry = 0U;
    int j;
    for(j = (int)n - 1; j >= 0; j--) {
        const uint32_t t = (uint32_t)a[j] + (uint32_t)b[j] + carry;
        out[j] = (uint8_t)t;
        carry = t >> 8U;
    }
    return carry;
}

#define BAD_POINTS_MAX 9U

/**
 * @brief Point validation and ECDH peer checks for one curve: the RFC 6979 public key,
 *        G, -Q and a small-x point are accepted; the identity, an off-curve point, x = p,
 *        y = p, x = 2^k - 1, the non-canonical encodings (x + p, y) and (x, y + p) of valid
 *        points (where they fit the coordinate width) and size-mismatched points are
 *        rejected by noxtls_ecc_point_validate_public and by noxtls_ecdh_compute_shared_secret.
 */
static void test_point_validation(const curve_info_t *c)
{
    const pkc_mem_ecc_keypair_t *kp = rfc6979_key(c->bits);
    const pkc_mem_ecc_point_hex_t *sp = NULL;
    ecc_curve_params_t curve;
    ecc_point_t good;
    ecc_point_t small;
    ecc_point_t bad[BAD_POINTS_MAX];
    const char *bad_name[BAD_POINTS_MAX];
    uint32_t nbad = 0U;
    uint32_t i;

    for(i = 0U; i < PKC_MEM_RFC6979_KEY_COUNT; i++) {
        if(pkc_mem_small_x_points[i].curve_bits == c->bits) {
            sp = &pkc_mem_small_x_points[i];
        }
    }
    if((kp == NULL) || (sp == NULL)) {
        (void)check(0, "point validation vectors", c->name);
        return;
    }
    if(!check(noxtls_ecc_curve_init(&curve, c->id) == NOXTLS_RETURN_SUCCESS, "ecc_curve_init", c->name)) {
        return;
    }
    (void)check(load_point(&good, c, kp->qx, kp->qy) && load_point(&small, c, sp->x, sp->y), "load points", c->name);
    (void)check(noxtls_ecc_point_validate_public(&good, &curve) == NOXTLS_RETURN_SUCCESS, "valid Q accepted", c->name);
    (void)check(noxtls_ecc_point_validate_public(&curve.G, &curve) == NOXTLS_RETURN_SUCCESS, "G accepted", c->name);
    (void)check(noxtls_ecc_point_validate_public(&small, &curve) == NOXTLS_RETURN_SUCCESS, "small-x point accepted", c->name);
    {
        /* -Q = (x, p - y) is on the curve. */
        ecc_point_t neg = good;
        uint32_t borrow = 0U;
        int j;
        for(j = (int)c->size - 1; j >= 0; j--) {
            const uint32_t d = (uint32_t)curve.p[j] - (uint32_t)good.y[j] - borrow;
            neg.y[j] = (uint8_t)d;
            borrow = (d >> 8U) & 1U;
        }
        (void)check(noxtls_ecc_point_validate_public(&neg, &curve) == NOXTLS_RETURN_SUCCESS, "-Q accepted", c->name);
    }

    bad[nbad] = good;
    (void)memset(bad[nbad].x, 0, sizeof(bad[nbad].x));
    (void)memset(bad[nbad].y, 0, sizeof(bad[nbad].y));
    bad_name[nbad++] = "identity (0, 0)";
    bad[nbad] = good;
    bad[nbad].y[c->size - 1U] ^= 1U;
    bad_name[nbad++] = "off-curve (y ^ 1)";
    bad[nbad] = good;
    (void)memcpy(bad[nbad].x, curve.p, c->size);
    bad_name[nbad++] = "x = p";
    bad[nbad] = good;
    (void)memcpy(bad[nbad].y, curve.p, c->size);
    bad_name[nbad++] = "y = p";
    bad[nbad] = good;
    (void)memset(bad[nbad].x, 0xFF, c->size);
    bad_name[nbad++] = "x = 2^k - 1";
    bad[nbad] = small;
    if(add_be(bad[nbad].x, small.x, curve.p, c->size) == 0U) {
        bad_name[nbad++] = "non-canonical (x + p, y)";
    }
    bad[nbad] = good;
    if(add_be(bad[nbad].y, good.y, curve.p, c->size) == 0U) {
        bad_name[nbad++] = "non-canonical (x, y + p)";
    }
    bad[nbad] = good;
    bad[nbad].size = c->size - 1U;
    bad_name[nbad++] = "size - 1";
    if((c->size + 1U) <= (uint32_t)sizeof(good.x)) {
        bad[nbad] = good;
        bad[nbad].size = c->size + 1U;
        bad_name[nbad++] = "size + 1";
    }
    for(i = 0U; i < nbad; i++) {
        char ctx[64];
        (void)snprintf(ctx, sizeof(ctx), "%s %s", c->name, bad_name[i]);
        (void)check(noxtls_ecc_point_validate_public(&bad[i], &curve) != NOXTLS_RETURN_SUCCESS,
                    "invalid point rejected by validate_public", ctx);
    }
    (void)noxtls_ecc_curve_free(&curve);

#if PKC_MEM_HAVE_ECDH
    {
        ecc_key_t priv;
        if(check(import_private_hex(&priv, c, kp->d) == NOXTLS_RETURN_SUCCESS, "import private (ecdh negatives)", c->name)) {
            uint8_t z[66];
            uint32_t zl = (uint32_t)sizeof(z);
            (void)check(noxtls_ecdh_compute_shared_secret(&priv, &small, z, &zl) == NOXTLS_RETURN_SUCCESS, "ECDH with small-x peer", c->name);
            for(i = 0U; i < nbad; i++) {
                char ctx[64];
                zl = (uint32_t)sizeof(z);
                (void)snprintf(ctx, sizeof(ctx), "%s %s", c->name, bad_name[i]);
                (void)check(noxtls_ecdh_compute_shared_secret(&priv, &bad[i], z, &zl) == NOXTLS_RETURN_ECDH_PEER_PUBLIC_KEY_INVALID,
                            "invalid peer rejected by ECDH", ctx);
            }
        }
        (void)noxtls_ecc_key_free(&priv);
    }
#endif
}

#if PKC_MEM_HAVE_ECDSA
/** @brief Verify @p sig (r, s hex, coordinate size of @p sig_size) with a fresh public key. */
static noxtls_return_t verify_hex(const curve_info_t *c, const char *qx, const char *qy, const uint8_t *msg, uint32_t msg_len,
                                  const ecdsa_signature_t *sig, noxtls_hash_algos_t h)
{
    ecc_key_t key;
    noxtls_return_t rc;
    if(load_public_key(&key, c, qx, qy) == 0) {
        return NOXTLS_RETURN_FAILED;
    }
    rc = noxtls_ecdsa_verify(&key, msg, msg_len, sig, h);
    (void)noxtls_ecc_key_free(&key);
    return rc;
}

/** @brief Fill an ECDSA signature from hex. */
static int load_sig(ecdsa_signature_t *sig, uint32_t size, const char *r, const char *s)
{
    (void)noxtls_ecdsa_signature_init(sig, size);
    return pkc_mem_unhex_fixed(sig->r, size, r) && pkc_mem_unhex_fixed(sig->s, size, s);
}

/**
 * @brief Verify-only known answers. Valid vectors must verify, and must stop verifying
 *        when the message, r or s is corrupted, when r and s are swapped, or when the
 *        digest algorithm differs. CAVP failure records must be rejected.
 */
static void test_ecdsa_kats(void)
{
    uint32_t i;
    for(i = 0U; i < PKC_MEM_ECDSA_KAT_COUNT; i++) {
        const pkc_mem_ecdsa_kat_t *v = &pkc_mem_ecdsa_kats[i];
        const curve_info_t *c = curve_for_bits(v->curve_bits);
        noxtls_hash_algos_t h;
        uint8_t msg[256];
        uint32_t ml;
        ecdsa_signature_t sig;
        noxtls_return_t rc;

        if((c == NULL) || (hash_for_bits(v->hash_bits, &h) == 0)) {
            continue;
        }
        ml = pkc_mem_unhex(msg, (uint32_t)sizeof(msg), v->msg);
        if(!check((ml != 0U) && load_sig(&sig, c->size, v->r, v->s), "decode ECDSA vector", v->source)) {
            continue;
        }
        rc = verify_hex(c, v->qx, v->qy, msg, ml, &sig, h);
        if(v->expect_valid != 0U) {
            (void)check(rc == NOXTLS_RETURN_SUCCESS, "ECDSA known answer verifies", v->source);
            if(v->source[0] == 'R') { /* RFC 6979 vectors: the full set of mutations */
                ecdsa_signature_t bad = sig;
                noxtls_hash_algos_t other = NOXTLS_HASH_SHA_256;
                int have_other = (v->hash_bits != 256U);
                msg[0] ^= 0x01U;
                (void)check(verify_hex(c, v->qx, v->qy, msg, ml, &sig, h) != NOXTLS_RETURN_SUCCESS, "modified message rejected", v->source);
                msg[0] ^= 0x01U;
                bad.r[c->size - 1U] ^= 0x01U;
                (void)check(verify_hex(c, v->qx, v->qy, msg, ml, &bad, h) != NOXTLS_RETURN_SUCCESS, "corrupted r rejected", v->source);
                bad = sig;
                bad.s[c->size / 2U] ^= 0x80U;
                (void)check(verify_hex(c, v->qx, v->qy, msg, ml, &bad, h) != NOXTLS_RETURN_SUCCESS, "corrupted s rejected", v->source);
                (void)memcpy(bad.r, sig.s, sizeof(bad.r));
                (void)memcpy(bad.s, sig.r, sizeof(bad.s));
                (void)check(verify_hex(c, v->qx, v->qy, msg, ml, &bad, h) != NOXTLS_RETURN_SUCCESS, "swapped r/s rejected", v->source);
                if(have_other == 0) {
                    have_other = hash_for_bits(384U, &other) || hash_for_bits(512U, &other);
                }
                if(have_other != 0) {
                    (void)check(verify_hex(c, v->qx, v->qy, msg, ml, &sig, other) != NOXTLS_RETURN_SUCCESS, "wrong digest rejected", v->source);
                }
            }
        } else {
            (void)check(rc != NOXTLS_RETURN_SUCCESS, "ECDSA expected-failure record rejected", v->source);
        }
    }
}

/**
 * @brief Range checks on r and s (0, n, all-ones), wrong-size signatures (a signature
 *        of another curve), and verification against invalid public keys.
 */
static void test_ecdsa_negative(const curve_info_t *c)
{
    const pkc_mem_ecc_keypair_t *kp = rfc6979_key(c->bits);
    const pkc_mem_ecdsa_kat_t *ref = NULL;
    static const uint8_t sample[6] = { 's', 'a', 'm', 'p', 'l', 'e' };
    ecdsa_signature_t sig;
    ecdsa_signature_t bad;
    ecc_key_t key;
    uint8_t n[66];
    uint32_t i;

    for(i = 0U; i < PKC_MEM_ECDSA_KAT_COUNT; i++) {
        const pkc_mem_ecdsa_kat_t *v = &pkc_mem_ecdsa_kats[i];
        if((v->curve_bits == c->bits) && (v->hash_bits == 256U) && (v->expect_valid != 0U) && (strcmp(v->msg, "73616d706c65") == 0)) {
            ref = v;
            break;
        }
    }
    if((kp == NULL) || (ref == NULL) || !load_sig(&sig, c->size, ref->r, ref->s)) {
        (void)check(0, "ECDSA negative setup", c->name);
        return;
    }
    if(!check(load_public_key(&key, c, kp->qx, kp->qy), "load public key", c->name)) {
        return;
    }
    (void)check(noxtls_ecdsa_verify(&key, sample, 6U, &sig, NOXTLS_HASH_SHA_256) == NOXTLS_RETURN_SUCCESS, "reference verifies", c->name);
    (void)check(noxtls_ecc_curve_order_size(key.curve) == c->size, "order size", c->name);
    (void)memset(n, 0, sizeof(n));
    (void)memcpy(n, key.curve->n, c->size);

    bad = sig; (void)memset(bad.r, 0, sizeof(bad.r));
    (void)check(noxtls_ecdsa_verify(&key, sample, 6U, &bad, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS, "r = 0 rejected", c->name);
    bad = sig; (void)memset(bad.s, 0, sizeof(bad.s));
    (void)check(noxtls_ecdsa_verify(&key, sample, 6U, &bad, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS, "s = 0 rejected", c->name);
    bad = sig; (void)memcpy(bad.r, n, c->size);
    (void)check(noxtls_ecdsa_verify(&key, sample, 6U, &bad, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS, "r = n rejected", c->name);
    bad = sig; (void)memcpy(bad.s, n, c->size);
    (void)check(noxtls_ecdsa_verify(&key, sample, 6U, &bad, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS, "s = n rejected", c->name);
    /* r + n and s + n (when they still fit in the coordinate size) must not alias r and s. */
    bad = sig;
    if(add_be(bad.r, sig.r, n, c->size) == 0U) {
        (void)check(noxtls_ecdsa_verify(&key, sample, 6U, &bad, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS, "r + n rejected", c->name);
    }
    bad = sig;
    if(add_be(bad.s, sig.s, n, c->size) == 0U) {
        (void)check(noxtls_ecdsa_verify(&key, sample, 6U, &bad, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS, "s + n rejected", c->name);
    }
    bad = sig; (void)memset(bad.r, 0xFF, c->size);
    (void)check(noxtls_ecdsa_verify(&key, sample, 6U, &bad, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS, "r = 2^k-1 rejected", c->name);
    bad = sig; (void)memset(bad.s, 0xFF, c->size);
    (void)check(noxtls_ecdsa_verify(&key, sample, 6U, &bad, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS, "s = 2^k-1 rejected", c->name);

    /* Signatures made on the other enabled curves (different coordinate size). */
    for(i = 0U; i < PKC_MEM_ECDSA_KAT_COUNT; i++) {
        const pkc_mem_ecdsa_kat_t *v = &pkc_mem_ecdsa_kats[i];
        const curve_info_t *oc = curve_for_bits(v->curve_bits);
        if((oc != NULL) && (oc != c) && (v->hash_bits == 256U) && (v->expect_valid != 0U) && (strcmp(v->msg, "73616d706c65") == 0)) {
            char ctx[64];
            if(load_sig(&bad, oc->size, v->r, v->s)) {
                (void)snprintf(ctx, sizeof(ctx), "%s signature on %s key", oc->name, c->name);
                (void)check(noxtls_ecdsa_verify(&key, sample, 6U, &bad, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS,
                            "wrong-size signature rejected", ctx);
            }
        }
    }

    /* The same valid signature against invalid public keys. */
    key.Q.y[c->size - 1U] ^= 0x01U;
    (void)check(noxtls_ecdsa_verify(&key, sample, 6U, &sig, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS, "off-curve public key rejected", c->name);
    (void)memset(key.Q.x, 0, sizeof(key.Q.x));
    (void)memset(key.Q.y, 0, sizeof(key.Q.y));
    (void)check(noxtls_ecdsa_verify(&key, sample, 6U, &sig, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS, "identity public key rejected", c->name);
    (void)noxtls_ecc_key_free(&key);
}

/**
 * @brief Sign/verify round trips: RFC 6979 private keys imported with
 *        noxtls_ecc_key_import_private (Q must match the RFC), and freshly generated keys.
 *        Signatures are verified with separate public-only keys.
 */
static void test_ecdsa_roundtrip(const curve_info_t *c)
{
    static const uint32_t hb[3] = { 256U, 384U, 512U };
    static const uint8_t msg[] = "NoxTLS pkc_mem ECDSA round trip";
    const pkc_mem_ecc_keypair_t *kp = rfc6979_key(c->bits);
    uint8_t qx[66];
    uint8_t qy[66];
    ecc_key_t key;
    uint32_t i;
    int pass;

    if(kp == NULL) {
        return;
    }
    (void)pkc_mem_unhex_fixed(qx, c->size, kp->qx);
    (void)pkc_mem_unhex_fixed(qy, c->size, kp->qy);
    if(check(import_private_hex(&key, c, kp->d) == NOXTLS_RETURN_SUCCESS, "import RFC 6979 private key", c->name)) {
        (void)check((key.Q.size == c->size) && (memcmp(key.Q.x, qx, c->size) == 0) && (memcmp(key.Q.y, qy, c->size) == 0),
                    "imported key Q = dG matches RFC 6979", c->name);
        (void)check(key.curve_kind == c->id, "curve_kind set", c->name);
        for(i = 0U; i < 3U; i++) {
            noxtls_hash_algos_t h;
            ecdsa_signature_t sig;
            ecdsa_signature_t sig2;
            if(hash_for_bits(hb[i], &h) == 0) {
                continue;
            }
            (void)noxtls_ecdsa_signature_init(&sig, c->size);
            (void)noxtls_ecdsa_signature_init(&sig2, c->size);
            pass = check(noxtls_ecdsa_sign(&key, msg, (uint32_t)sizeof(msg), &sig, h) == NOXTLS_RETURN_SUCCESS, "sign (imported key)", c->name);
            pass = pass && check(noxtls_ecdsa_sign(&key, msg, (uint32_t)sizeof(msg), &sig2, h) == NOXTLS_RETURN_SUCCESS, "second sign", c->name);
            if(pass) {
                (void)check(memcmp(sig.r, sig2.r, c->size) != 0, "fresh nonce per signature", c->name);
                (void)check(noxtls_ecdsa_verify(&key, msg, (uint32_t)sizeof(msg), &sig, h) == NOXTLS_RETURN_SUCCESS, "verify with signing key", c->name);
                {
                    ecc_key_t pub;
                    if(check(noxtls_ecc_key_init(&pub, c->id) == NOXTLS_RETURN_SUCCESS, "public key init", c->name)) {
                        (void)memcpy(pub.Q.x, qx, c->size);
                        (void)memcpy(pub.Q.y, qy, c->size);
                        pub.Q.size = c->size;
                        (void)check(noxtls_ecdsa_verify(&pub, msg, (uint32_t)sizeof(msg), &sig2, h) == NOXTLS_RETURN_SUCCESS, "verify with public-only key", c->name);
                        (void)check(noxtls_ecdsa_verify(&pub, msg, (uint32_t)sizeof(msg) - 1U, &sig2, h) != NOXTLS_RETURN_SUCCESS, "truncated message rejected", c->name);
                    }
                    (void)noxtls_ecc_key_free(&pub);
                }
            }
        }
    }
    (void)noxtls_ecc_key_free(&key);

    /* Fresh key generation. */
    (void)memset(&key, 0, sizeof(key));
    if(check(noxtls_ecc_key_generate(&key, c->id) == NOXTLS_RETURN_SUCCESS, "ecc_key_generate", c->name)) {
        ecdsa_signature_t sig;
        (void)check(noxtls_ecc_point_validate_public(&key.Q, key.curve) == NOXTLS_RETURN_SUCCESS, "generated Q valid", c->name);
        (void)noxtls_ecdsa_signature_init(&sig, c->size);
        if(check(noxtls_ecdsa_sign(&key, msg, (uint32_t)sizeof(msg), &sig, NOXTLS_HASH_SHA_256) == NOXTLS_RETURN_SUCCESS, "sign (generated key)", c->name)) {
            (void)check(noxtls_ecdsa_verify(&key, msg, (uint32_t)sizeof(msg), &sig, NOXTLS_HASH_SHA_256) == NOXTLS_RETURN_SUCCESS, "verify (generated key)", c->name);
            sig.s[0] ^= 0x40U;
            (void)check(noxtls_ecdsa_verify(&key, msg, (uint32_t)sizeof(msg), &sig, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS, "corrupted signature rejected", c->name);
        }
    }
    (void)noxtls_ecc_key_free(&key);

    /* Out-of-range private scalars. */
    {
        uint8_t d[67];
        ecc_key_t k2;
        (void)memset(&k2, 0, sizeof(k2));
        (void)memset(d, 0, sizeof(d));
        (void)check(noxtls_ecc_key_import_private(&k2, c->id, d, c->size) != NOXTLS_RETURN_SUCCESS, "d = 0 rejected", c->name);
        (void)noxtls_ecc_key_free(&k2);
        if(check(noxtls_ecc_key_init(&k2, c->id) == NOXTLS_RETURN_SUCCESS, "key init", c->name)) {
            (void)memcpy(d, k2.curve->n, c->size);
        }
        (void)noxtls_ecc_key_free(&k2);
        (void)memset(&k2, 0, sizeof(k2));
        (void)check(noxtls_ecc_key_import_private(&k2, c->id, d, c->size) != NOXTLS_RETURN_SUCCESS, "d = n rejected", c->name);
        (void)noxtls_ecc_key_free(&k2);
        (void)memset(&k2, 0, sizeof(k2));
        d[0] = 0x01U;
        (void)check(noxtls_ecc_key_import_private(&k2, c->id, d, c->size + 1U) != NOXTLS_RETURN_SUCCESS, "oversized d rejected", c->name);
        (void)noxtls_ecc_key_free(&k2);
    }
}
#endif /* PKC_MEM_HAVE_ECDSA */

#if PKC_MEM_HAVE_ECDH
/** @brief CAVP CDH known answers: imported dIUT must give QIUT, and ECDH with QCAVS gives ZIUT. */
static void test_ecdh_kats(void)
{
    uint32_t i;
    for(i = 0U; i < PKC_MEM_ECDH_KAT_COUNT; i++) {
        const pkc_mem_ecdh_kat_t *v = &pkc_mem_ecdh_kats[i];
        const curve_info_t *c = curve_for_bits(v->curve_bits);
        ecc_key_t key;
        ecc_point_t peer;
        ecc_point_t qiut;
        uint8_t z[66];
        uint8_t zref[66];
        uint32_t zl = (uint32_t)sizeof(z);

        if(c == NULL) {
            continue;
        }
        if(!check(load_point(&peer, c, v->peer_x, v->peer_y) && load_point(&qiut, c, v->qx, v->qy) &&
                  pkc_mem_unhex_fixed(zref, c->size, v->z), "decode CDH vector", v->source)) {
            continue;
        }
        if(check(import_private_hex(&key, c, v->d) == NOXTLS_RETURN_SUCCESS, "import dIUT", v->source)) {
            (void)check((memcmp(key.Q.x, qiut.x, c->size) == 0) && (memcmp(key.Q.y, qiut.y, c->size) == 0), "QIUT = dIUT * G", v->source);
            (void)check(noxtls_ecdh_compute_shared_secret(&key, &peer, z, &zl) == NOXTLS_RETURN_SUCCESS, "ECDH", v->source);
            (void)check((zl == c->size) && (memcmp(z, zref, c->size) == 0), "Z matches ZIUT", v->source);
            zl = c->size - 1U;
            (void)check(noxtls_ecdh_compute_shared_secret(&key, &peer, z, &zl) == NOXTLS_RETURN_ECDH_OUTPUT_TOO_SMALL, "short output buffer rejected", v->source);
        }
        (void)noxtls_ecc_key_free(&key);
    }
}

/** @brief Two generated key pairs agree on the shared secret. */
static void test_ecdh_roundtrip(const curve_info_t *c)
{
    ecc_key_t a = { 0 };
    ecc_key_t b = { 0 };
    uint8_t za[66];
    uint8_t zb[66];
    uint32_t la = (uint32_t)sizeof(za);
    uint32_t lb = (uint32_t)sizeof(zb);
    int ok = check(noxtls_ecc_key_generate(&a, c->id) == NOXTLS_RETURN_SUCCESS, "keygen A", c->name);
    ok = check(noxtls_ecc_key_generate(&b, c->id) == NOXTLS_RETURN_SUCCESS, "keygen B", c->name) && ok;
    if(ok) {
        ok = check(noxtls_ecdh_compute_shared_secret(&a, &b.Q, za, &la) == NOXTLS_RETURN_SUCCESS, "ECDH A", c->name);
        ok = check(noxtls_ecdh_compute_shared_secret(&b, &a.Q, zb, &lb) == NOXTLS_RETURN_SUCCESS, "ECDH B", c->name) && ok;
        (void)check(ok && (la == c->size) && (lb == c->size) && (memcmp(za, zb, c->size) == 0) && !all_zero(za, c->size),
                    "ECDH keygen round trip agrees", c->name);
    }
    (void)noxtls_ecc_key_free(&a);
    (void)noxtls_ecc_key_free(&b);
}
#endif /* PKC_MEM_HAVE_ECDH */

#endif /* PKC_MEM_HAVE_ECC_CURVES */

/* ------------------------------------------------------------------ RSA */
#if PKC_MEM_HAVE_RSA

#define RSA_WITH_D   1U
#define RSA_WITH_CRT 2U

/** @brief Full key (noxtls_rsa_key_init) with d and/or the CRT components filled in. */
static int rsa_load(rsa_key_t *k, const pkc_mem_rsa_kat_t *v, uint32_t parts)
{
    const uint32_t kb = v->bits / 8U;
    const uint32_t hb = kb / 2U;
    int ok;
    if(noxtls_rsa_key_init(k, v->bits) != NOXTLS_RETURN_SUCCESS) {
        return 0;
    }
    ok = pkc_mem_unhex_fixed(k->n, kb, v->n) && pkc_mem_unhex_fixed(k->e, k->e_len, v->e);
    if((parts & RSA_WITH_D) != 0U) {
        ok = ok && pkc_mem_unhex_fixed(k->d, kb, v->d);
    }
    if((parts & RSA_WITH_CRT) != 0U) {
        ok = ok && pkc_mem_unhex_fixed(k->p, hb, v->p) && pkc_mem_unhex_fixed(k->q, hb, v->q) &&
             pkc_mem_unhex_fixed(k->dp, hb, v->dp) && pkc_mem_unhex_fixed(k->dq, hb, v->dq) &&
             pkc_mem_unhex_fixed(k->qi, hb, v->qi);
    }
    if(ok == 0) {
        (void)noxtls_rsa_key_free(k);
    }
    return ok;
}

/** @brief Public-only key through noxtls_rsa_key_init_public (n with a DER-style leading zero). */
static int rsa_load_public(rsa_key_t *k, const pkc_mem_rsa_kat_t *v)
{
    uint8_t n[PKC_MEM_MAX_BYTES + 1U];
    uint8_t e[4];
    const uint32_t kb = v->bits / 8U;
    n[0] = 0x00U;
    if((pkc_mem_unhex_fixed(&n[1], kb, v->n) == 0) || (pkc_mem_unhex_fixed(e, 4U, v->e) == 0)) {
        return 0;
    }
    return noxtls_rsa_key_init_public(k, v->bits, n, kb + 1U, e, 4U) == NOXTLS_RETURN_SUCCESS;
}

static void test_rsa(const pkc_mem_rsa_kat_t *v)
{
    static uint8_t msg[128];
    static uint8_t s1[PKC_MEM_MAX_BYTES];
    static uint8_t ps[PKC_MEM_MAX_BYTES];
    static uint8_t ct[PKC_MEM_MAX_BYTES];
    static uint8_t pt[PKC_MEM_MAX_BYTES];
    static uint8_t out[PKC_MEM_MAX_BYTES + 4U];
    static uint8_t out2[PKC_MEM_MAX_BYTES + 4U];
    char name[48];
    const uint32_t kb = v->bits / 8U;
    noxtls_hash_algos_t h1;
    noxtls_hash_algos_t hp;
    rsa_key_t crt;
    rsa_key_t donly;
    rsa_key_t pub;
    uint32_t ml;
    uint32_t ptl;
    uint32_t ol;
    int have_crt;
    int have_donly;
    int have_pub;

    (void)snprintf(name, sizeof(name), "RSA-%u", (unsigned)v->bits);
    if((v->bits > RSA_MAX_KEY_SIZE) || (hash_for_bits(v->pkcs1_hash_bits, &h1) == 0) || (hash_for_bits(v->pss_hash_bits, &hp) == 0)) {
        return;
    }
    ml = pkc_mem_unhex(msg, (uint32_t)sizeof(msg), v->msg);
    ptl = pkc_mem_unhex(pt, (uint32_t)sizeof(pt), v->pt);
    if(!check((ml != 0U) && (ptl != 0U) && (pkc_mem_unhex(s1, kb, v->pkcs1_sig) == kb) && (pkc_mem_unhex(ps, kb, v->pss_sig) == kb) &&
              (pkc_mem_unhex(ct, kb, v->ct) == kb), "decode RSA vector", name)) {
        return;
    }
    have_crt = check(rsa_load(&crt, v, RSA_WITH_D | RSA_WITH_CRT), "load CRT key", name);
    have_donly = check(rsa_load(&donly, v, RSA_WITH_D), "load d-only key", name);
    have_pub = check(rsa_load_public(&pub, v), "noxtls_rsa_key_init_public", name);
    if(!(have_crt && have_donly && have_pub)) {
        if(have_crt) { (void)noxtls_rsa_key_free(&crt); }
        if(have_donly) { (void)noxtls_rsa_key_free(&donly); }
        if(have_pub) { (void)noxtls_rsa_key_free(&pub); }
        return;
    }
    (void)check((pub.d == NULL) && (pub.p == NULL) && (pub.qi == NULL) && (pub.e_len == 3U) && (pub.key_bytes == kb), "public-only key layout", name);

    /* PKCS#1 v1.5 sign is deterministic: both private-key paths must give OpenSSL's signature. */
    ol = (uint32_t)sizeof(out);
    (void)check((noxtls_rsa_sign(&crt, msg, ml, out, &ol, h1) == NOXTLS_RETURN_SUCCESS) && (ol == kb) && (memcmp(out, s1, kb) == 0),
                "PKCS#1 v1.5 sign (blinded CRT) matches OpenSSL", name);
    ol = (uint32_t)sizeof(out);
    (void)check((noxtls_rsa_sign(&donly, msg, ml, out, &ol, h1) == NOXTLS_RETURN_SUCCESS) && (ol == kb) && (memcmp(out, s1, kb) == 0),
                "PKCS#1 v1.5 sign (d only) matches OpenSSL", name);
    ol = kb - 1U;
    (void)check(noxtls_rsa_sign(&crt, msg, ml, out, &ol, h1) != NOXTLS_RETURN_SUCCESS, "sign into short buffer rejected", name);

    /* PKCS#1 v1.5 verify. */
    (void)check(noxtls_rsa_verify(&pub, msg, ml, s1, kb, h1) == NOXTLS_RETURN_SUCCESS, "PKCS#1 verify (public-only key)", name);
    (void)check(noxtls_rsa_verify(&crt, msg, ml, s1, kb, h1) == NOXTLS_RETURN_SUCCESS, "PKCS#1 verify (full key)", name);
    (void)memcpy(out, s1, kb);
    out[kb / 2U] ^= 0x10U;
    (void)check(noxtls_rsa_verify(&pub, msg, ml, out, kb, h1) != NOXTLS_RETURN_SUCCESS, "corrupted PKCS#1 signature rejected", name);
    (void)memcpy(out, s1, kb);
    out[kb - 1U] ^= 0x01U;
    (void)check(noxtls_rsa_verify(&pub, msg, ml, out, kb, h1) != NOXTLS_RETURN_SUCCESS, "PKCS#1 signature with flipped LSB rejected", name);
    (void)check(noxtls_rsa_verify(&pub, msg, ml, s1, kb - 1U, h1) != NOXTLS_RETURN_SUCCESS, "short PKCS#1 signature rejected", name);
    (void)memset(out, 0, sizeof(out));
    (void)memcpy(&out[1], s1, kb);
    (void)check(noxtls_rsa_verify(&pub, msg, ml, out, kb + 1U, h1) != NOXTLS_RETURN_SUCCESS, "long PKCS#1 signature rejected", name);
    (void)check(noxtls_rsa_verify(&pub, msg, ml, pub.n, kb, h1) != NOXTLS_RETURN_SUCCESS, "signature = n rejected", name);
    (void)memset(out, 0xFF, kb);
    (void)check(noxtls_rsa_verify(&pub, msg, ml, out, kb, h1) != NOXTLS_RETURN_SUCCESS, "signature > n rejected", name);
    msg[0] ^= 0x01U;
    (void)check(noxtls_rsa_verify(&pub, msg, ml, s1, kb, h1) != NOXTLS_RETURN_SUCCESS, "PKCS#1 modified message rejected", name);
    msg[0] ^= 0x01U;
    {
        noxtls_hash_algos_t other = (h1 == NOXTLS_HASH_SHA_256) ? NOXTLS_HASH_SHA1 : NOXTLS_HASH_SHA_256;
        (void)check(noxtls_rsa_verify(&pub, msg, ml, s1, kb, other) != NOXTLS_RETURN_SUCCESS, "PKCS#1 wrong digest rejected", name);
    }
    (void)check(noxtls_rsa_verify_pss(&pub, msg, ml, s1, kb, h1) != NOXTLS_RETURN_SUCCESS, "PKCS#1 signature is not a PSS signature", name);

    /* PSS: OpenSSL signature verifies; round trips on both private-key paths. */
    (void)check(noxtls_rsa_verify_pss(&pub, msg, ml, ps, kb, hp) == NOXTLS_RETURN_SUCCESS, "PSS verify OpenSSL signature (public-only key)", name);
    (void)check(noxtls_rsa_verify_pss(&crt, msg, ml, ps, kb, hp) == NOXTLS_RETURN_SUCCESS, "PSS verify OpenSSL signature (full key)", name);
    (void)memcpy(out, ps, kb);
    out[3] ^= 0x04U;
    (void)check(noxtls_rsa_verify_pss(&pub, msg, ml, out, kb, hp) != NOXTLS_RETURN_SUCCESS, "corrupted PSS signature rejected", name);
    (void)check(noxtls_rsa_verify_pss(&pub, msg, ml, ps, kb - 1U, hp) != NOXTLS_RETURN_SUCCESS, "short PSS signature rejected", name);
    (void)check(noxtls_rsa_verify(&pub, msg, ml, ps, kb, hp) != NOXTLS_RETURN_SUCCESS, "PSS signature is not a PKCS#1 signature", name);
    msg[ml - 1U] ^= 0x01U;
    (void)check(noxtls_rsa_verify_pss(&pub, msg, ml, ps, kb, hp) != NOXTLS_RETURN_SUCCESS, "PSS modified message rejected", name);
    msg[ml - 1U] ^= 0x01U;
    {
        noxtls_hash_algos_t other = (hp == NOXTLS_HASH_SHA_256) ? NOXTLS_HASH_SHA_512 : NOXTLS_HASH_SHA_256;
        (void)check(noxtls_rsa_verify_pss(&pub, msg, ml, ps, kb, other) != NOXTLS_RETURN_SUCCESS, "PSS wrong digest rejected", name);
    }
    ol = (uint32_t)sizeof(out);
    if(check(noxtls_rsa_sign_pss(&crt, msg, ml, out, &ol, hp) == NOXTLS_RETURN_SUCCESS, "PSS sign (CRT)", name)) {
        (void)check((ol == kb) && (noxtls_rsa_verify_pss(&pub, msg, ml, out, kb, hp) == NOXTLS_RETURN_SUCCESS), "PSS round trip (CRT)", name);
    }
    ol = (uint32_t)sizeof(out2);
    if(check(noxtls_rsa_sign_pss(&donly, msg, ml, out2, &ol, hp) == NOXTLS_RETURN_SUCCESS, "PSS sign (d only)", name)) {
        (void)check((ol == kb) && (noxtls_rsa_verify_pss(&pub, msg, ml, out2, kb, hp) == NOXTLS_RETURN_SUCCESS), "PSS round trip (d only)", name);
        (void)check(memcmp(out, out2, kb) != 0, "PSS signatures are salted", name);
    }

    /* Decryption of the OpenSSL ciphertext on every private path. */
    ol = (uint32_t)sizeof(out);
    (void)check((noxtls_rsa_decrypt(&crt, ct, kb, out, &ol) == NOXTLS_RETURN_SUCCESS) && (ol == ptl) && (memcmp(out, pt, ptl) == 0),
                "decrypt OpenSSL ciphertext (CRT)", name);
    ol = (uint32_t)sizeof(out);
    (void)check((noxtls_rsa_decrypt(&donly, ct, kb, out, &ol) == NOXTLS_RETURN_SUCCESS) && (ol == ptl) && (memcmp(out, pt, ptl) == 0),
                "decrypt OpenSSL ciphertext (d only)", name);
    ol = (uint32_t)sizeof(out);
    (void)check((noxtls_rsa_decrypt_crt_only(&crt, ct, kb, out, &ol) == NOXTLS_RETURN_SUCCESS) && (ol == ptl) && (memcmp(out, pt, ptl) == 0),
                "decrypt_crt_only OpenSSL ciphertext", name);
    ol = (uint32_t)sizeof(out);
    (void)check(noxtls_rsa_decrypt_crt_only(&donly, ct, kb, out, &ol) != NOXTLS_RETURN_SUCCESS, "decrypt_crt_only without CRT components fails", name);
    ol = (uint32_t)sizeof(out);
    (void)check(noxtls_rsa_decrypt(&crt, ct, kb - 1U, out, &ol) != NOXTLS_RETURN_SUCCESS, "short ciphertext rejected", name);
    ol = (uint32_t)sizeof(out);
    (void)check(noxtls_rsa_decrypt(&crt, crt.n, kb, out, &ol) != NOXTLS_RETURN_SUCCESS, "ciphertext = n rejected", name);
    (void)memcpy(out2, ct, kb);
    out2[kb / 3U] ^= 0x01U;
    ol = (uint32_t)sizeof(out);
    (void)check(noxtls_rsa_decrypt(&crt, out2, kb, out, &ol) != NOXTLS_RETURN_SUCCESS, "corrupted ciphertext rejected (padding)", name);

    /* Encrypt with the public-only key, decrypt with the CRT key. */
    ol = (uint32_t)sizeof(out2);
    if(check((noxtls_rsa_encrypt(&pub, pt, ptl, out2, &ol) == NOXTLS_RETURN_SUCCESS) && (ol == kb), "encrypt (public-only key)", name)) {
        uint32_t dl = (uint32_t)sizeof(out);
        (void)check(memcmp(out2, ct, kb) != 0, "PKCS#1 v1.5 encryption is randomized", name);
        (void)check((noxtls_rsa_decrypt(&crt, out2, kb, out, &dl) == NOXTLS_RETURN_SUCCESS) && (dl == ptl) && (memcmp(out, pt, ptl) == 0),
                    "encrypt/decrypt round trip", name);
    }

    /* Private operations on the public-only key fail cleanly. */
    ol = (uint32_t)sizeof(out);
    (void)check(noxtls_rsa_sign(&pub, msg, ml, out, &ol, h1) == NOXTLS_RETURN_INVALID_PARAM, "sign with public-only key rejected", name);
    ol = (uint32_t)sizeof(out);
    (void)check(noxtls_rsa_sign_pss(&pub, msg, ml, out, &ol, hp) == NOXTLS_RETURN_INVALID_PARAM, "sign_pss with public-only key rejected", name);
    ol = (uint32_t)sizeof(out);
    (void)check(noxtls_rsa_decrypt(&pub, ct, kb, out, &ol) == NOXTLS_RETURN_INVALID_PARAM, "decrypt with public-only key rejected", name);
    ol = (uint32_t)sizeof(out);
    (void)check(noxtls_rsa_decrypt_crt_only(&pub, ct, kb, out, &ol) != NOXTLS_RETURN_SUCCESS, "decrypt_crt_only with public-only key rejected", name);

    /* CRT fault countermeasure: a corrupted dp must never yield a (faulty) signature. */
    crt.dp[kb / 4U] ^= 0x01U;
    ol = (uint32_t)sizeof(out);
    {
        noxtls_return_t rc = noxtls_rsa_sign(&crt, msg, ml, out, &ol, h1);
        (void)check((rc != NOXTLS_RETURN_SUCCESS) ? all_zero(out, kb) : (memcmp(out, s1, kb) == 0),
                    "faulty CRT component never releases a bad signature", name);
    }

    (void)noxtls_rsa_key_free(&crt);
    (void)noxtls_rsa_key_free(&donly);
    (void)noxtls_rsa_key_free(&pub);
}

/** @brief Argument validation of noxtls_rsa_key_init_public. */
static void test_rsa_init_public_args(void)
{
    uint8_t n[257];
    uint8_t e[3] = { 0x01U, 0x00U, 0x01U };
    uint8_t ez[3] = { 0U, 0U, 0U };
    rsa_key_t k;
    (void)memset(n, 0xC5, sizeof(n));
    (void)check(noxtls_rsa_key_init_public(&k, RSA_2048_BIT, n, 257U, e, 3U) == NOXTLS_RETURN_INVALID_PARAM, "init_public: n longer than key", NULL);
    (void)check(noxtls_rsa_key_init_public(&k, RSA_2048_BIT, n, 256U, ez, 3U) == NOXTLS_RETURN_INVALID_PARAM, "init_public: e = 0", NULL);
    (void)check(noxtls_rsa_key_init_public(&k, (rsa_key_size_t)512U, n, 64U, e, 3U) == NOXTLS_RETURN_FAILED, "init_public: 512-bit key", NULL);
    (void)check(noxtls_rsa_key_init_public(&k, RSA_2048_BIT, NULL, 256U, e, 3U) == NOXTLS_RETURN_NULL, "init_public: NULL n", NULL);
}
#endif /* PKC_MEM_HAVE_RSA */

/* ------------------------------------------------------------------ X25519 / X448 */
#if PKC_MEM_HAVE_X25519 || PKC_MEM_HAVE_X448
typedef noxtls_return_t (*xdh_fn_t)(const uint8_t *k, const uint8_t *u, uint8_t *out);
typedef noxtls_return_t (*xdh_pub_fn_t)(const uint8_t *k, uint8_t *out);
typedef noxtls_return_t (*xdh_gen_fn_t)(uint8_t *k, uint8_t *pub);

/** @brief RFC 7748 5.2 / 6.x vectors, the iterated function, keygen and low-order inputs. */
static void test_xdh(const char *name, uint32_t len, xdh_fn_t fn, xdh_pub_fn_t pubfn, xdh_gen_fn_t gen,
                     const pkc_mem_xdh_kat_t *kats, const char *iter1, const char *iter1000, const pkc_mem_xdh_dh_kat_t *dh)
{
    uint8_t k[56];
    uint8_t u[56];
    uint8_t r[56];
    uint8_t ref[56];
    uint8_t a[56];
    uint8_t b[56];
    uint8_t pa[56];
    uint8_t pb[56];
    uint32_t i;
    uint32_t it;

    for(i = 0U; i < 2U; i++) {
        (void)pkc_mem_unhex(k, len, kats[i].scalar);
        (void)pkc_mem_unhex(u, len, kats[i].u);
        (void)pkc_mem_unhex(ref, len, kats[i].out);
        (void)check((fn(k, u, r) == NOXTLS_RETURN_SUCCESS) && (memcmp(r, ref, len) == 0), "RFC 7748 5.2 function vector", name);
    }

    /* Iterated: k = X(k, u), u = old k, starting from the base point. */
    (void)memset(k, 0, sizeof(k));
    k[0] = (len == 32U) ? 9U : 5U;
    (void)memcpy(u, k, len);
    for(it = 1U; it <= 1000U; it++) {
        if(fn(k, u, r) != NOXTLS_RETURN_SUCCESS) {
            (void)check(0, "RFC 7748 iteration", name);
            break;
        }
        (void)memcpy(u, k, len);
        (void)memcpy(k, r, len);
        if(it == 1U) {
            (void)pkc_mem_unhex(ref, len, iter1);
            (void)check(memcmp(k, ref, len) == 0, "RFC 7748 5.2 after 1 iteration", name);
        }
    }
    (void)pkc_mem_unhex(ref, len, iter1000);
    (void)check(memcmp(k, ref, len) == 0, "RFC 7748 5.2 after 1,000 iterations", name);

    /* Diffie-Hellman (RFC 7748 6.1 / 6.2). */
    (void)pkc_mem_unhex(a, len, dh->a);
    (void)pkc_mem_unhex(b, len, dh->b);
    (void)pkc_mem_unhex(ref, len, dh->pub_a);
    (void)check((pubfn(a, pa) == NOXTLS_RETURN_SUCCESS) && (memcmp(pa, ref, len) == 0), "RFC 7748 Alice public key", name);
    (void)pkc_mem_unhex(ref, len, dh->pub_b);
    (void)check((pubfn(b, pb) == NOXTLS_RETURN_SUCCESS) && (memcmp(pb, ref, len) == 0), "RFC 7748 Bob public key", name);
    (void)pkc_mem_unhex(ref, len, dh->k);
    (void)check((fn(a, pb, r) == NOXTLS_RETURN_SUCCESS) && (memcmp(r, ref, len) == 0), "RFC 7748 shared secret (Alice)", name);
    (void)check((fn(b, pa, r) == NOXTLS_RETURN_SUCCESS) && (memcmp(r, ref, len) == 0), "RFC 7748 shared secret (Bob)", name);

    /* Generated keys agree. */
    if(check((gen(a, pa) == NOXTLS_RETURN_SUCCESS) && (gen(b, pb) == NOXTLS_RETURN_SUCCESS), "keygen", name)) {
        (void)check((fn(a, pb, r) == NOXTLS_RETURN_SUCCESS) && (fn(b, pa, ref) == NOXTLS_RETURN_SUCCESS) && (memcmp(r, ref, len) == 0) &&
                    !all_zero(r, len), "keygen round trip agrees", name);
    }

    /* Low-order inputs (u = 0, u = 1): either rejected or the all-zero output (RFC 7748 6). */
    for(i = 0U; i < 2U; i++) {
        noxtls_return_t rc;
        (void)memset(u, 0, sizeof(u));
        u[0] = (uint8_t)i;
        (void)memset(r, 0xA5, sizeof(r));
        rc = fn(a, u, r);
        (void)check((rc != NOXTLS_RETURN_SUCCESS) || all_zero(r, len), "low-order point gives no contributory secret", name);
    }
    noxtls_secure_zero(a, sizeof(a));
    noxtls_secure_zero(b, sizeof(b));
}
#endif

/* ------------------------------------------------------------------ Ed25519 */
#if PKC_MEM_HAVE_ED25519
/** @brief RFC 8032 TEST 3 plus corrupted R/S/message, non-canonical S (S + L) and wrong key. */
static void test_ed25519(void)
{
    /* L = 2^252 + 27742317777372353535851937790883648493, little-endian. */
    static const uint8_t ell[32] = {
        0xedU, 0xd3U, 0xf5U, 0x5cU, 0x1aU, 0x63U, 0x12U, 0x58U, 0xd6U, 0x9cU, 0xf7U, 0xa2U, 0xdeU, 0xf9U, 0xdeU, 0x14U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x10U
    };
    uint8_t sk[32];
    uint8_t pk[32];
    uint8_t pk2[32];
    uint8_t msg[2];
    uint8_t sig[64];
    uint8_t ref[64];
    uint8_t bad[64];
    uint32_t i;
    uint32_t carry = 0U;

    (void)pkc_mem_unhex(sk, 32U, pkc_mem_ed25519_t3_sk);
    (void)pkc_mem_unhex(pk, 32U, pkc_mem_ed25519_t3_pk);
    (void)pkc_mem_unhex(msg, 2U, pkc_mem_ed25519_t3_msg);
    (void)pkc_mem_unhex(ref, 64U, pkc_mem_ed25519_t3_sig);
    (void)check((noxtls_ed25519_public_key(sk, pk2) == NOXTLS_RETURN_SUCCESS) && (memcmp(pk, pk2, 32U) == 0), "RFC 8032 TEST 3 public key", NULL);
    (void)check((noxtls_ed25519_sign(sk, msg, 2U, sig) == NOXTLS_RETURN_SUCCESS) && (memcmp(sig, ref, 64U) == 0), "RFC 8032 TEST 3 signature", NULL);
    (void)check(noxtls_ed25519_verify(pk, msg, 2U, ref) == NOXTLS_RETURN_SUCCESS, "RFC 8032 TEST 3 verify", NULL);
    (void)memcpy(bad, ref, 64U);
    bad[5] ^= 0x20U;
    (void)check(noxtls_ed25519_verify(pk, msg, 2U, bad) != NOXTLS_RETURN_SUCCESS, "Ed25519 corrupted R rejected", NULL);
    (void)memcpy(bad, ref, 64U);
    bad[40] ^= 0x01U;
    (void)check(noxtls_ed25519_verify(pk, msg, 2U, bad) != NOXTLS_RETURN_SUCCESS, "Ed25519 corrupted S rejected", NULL);
    (void)memcpy(bad, ref, 64U);
    for(i = 0U; i < 32U; i++) {
        uint32_t t = (uint32_t)ref[32U + i] + (uint32_t)ell[i] + carry;
        bad[32U + i] = (uint8_t)t;
        carry = t >> 8U;
    }
    (void)check(noxtls_ed25519_verify(pk, msg, 2U, bad) != NOXTLS_RETURN_SUCCESS, "Ed25519 non-canonical S (S + L) rejected", NULL);
    msg[1] ^= 0x01U;
    (void)check(noxtls_ed25519_verify(pk, msg, 2U, ref) != NOXTLS_RETURN_SUCCESS, "Ed25519 modified message rejected", NULL);
    msg[1] ^= 0x01U;
    (void)check(noxtls_ed25519_verify(pk, msg, 1U, ref) != NOXTLS_RETURN_SUCCESS, "Ed25519 truncated message rejected", NULL);
    pk2[0] ^= 0x01U;
    (void)check(noxtls_ed25519_verify(pk2, msg, 2U, ref) != NOXTLS_RETURN_SUCCESS, "Ed25519 wrong public key rejected", NULL);

    if(check(noxtls_ed25519_generate_key(sk, pk) == NOXTLS_RETURN_SUCCESS, "Ed25519 keygen", NULL)) {
        (void)check((noxtls_ed25519_sign(sk, msg, 2U, sig) == NOXTLS_RETURN_SUCCESS) && (noxtls_ed25519_verify(pk, msg, 2U, sig) == NOXTLS_RETURN_SUCCESS),
                    "Ed25519 keygen sign/verify round trip", NULL);
    }
    noxtls_secure_zero(sk, sizeof(sk));
}
#endif

/* ------------------------------------------------------------------ FFDHE */
#if PKC_MEM_HAVE_DH
#define PKC_MEM_FFDHE2048 ((uint16_t)0x0100U) /* TLS NamedGroup ffdhe2048 (RFC 7919) */

static void test_ffdhe2048(void)
{
    static uint8_t xa[256];
    static uint8_t ya[256];
    static uint8_t xb[256];
    static uint8_t yb[256];
    static uint8_t za[256];
    static uint8_t zb[256];
    const uint8_t *p = NULL;
    const uint8_t *g = NULL;
    uint32_t pl = 0U;

    if(!check((noxtls_dh_ffdhe_params(PKC_MEM_FFDHE2048, &p, &g, &pl) == NOXTLS_RETURN_SUCCESS) && (pl == 256U), "ffdhe2048 params", NULL)) {
        return;
    }
    (void)check(noxtls_dh_ffdhe_generate_ephemeral(PKC_MEM_FFDHE2048, xa, ya) == NOXTLS_RETURN_SUCCESS, "ffdhe2048 keygen A", NULL);
    (void)check(noxtls_dh_ffdhe_generate_ephemeral(PKC_MEM_FFDHE2048, xb, yb) == NOXTLS_RETURN_SUCCESS, "ffdhe2048 keygen B", NULL);
    (void)check(noxtls_dh_ffdhe_validate_client_key_share(PKC_MEM_FFDHE2048, ya, 256U) == NOXTLS_RETURN_SUCCESS, "ffdhe2048 valid share accepted", NULL);
    (void)check((noxtls_dh_shared_secret(xa, 256U, yb, 256U, p, pl, za) == NOXTLS_RETURN_SUCCESS) &&
                (noxtls_dh_shared_secret(xb, 256U, ya, 256U, p, pl, zb) == NOXTLS_RETURN_SUCCESS) && (memcmp(za, zb, 256U) == 0),
                "ffdhe2048 shared secrets agree", NULL);
    (void)memset(yb, 0, sizeof(yb));
    yb[255] = 1U;
    (void)check(noxtls_dh_ffdhe_validate_client_key_share(PKC_MEM_FFDHE2048, yb, 256U) != NOXTLS_RETURN_SUCCESS, "ffdhe2048 share = 1 rejected", NULL);
    (void)memcpy(yb, p, 256U);
    yb[255] = (uint8_t)(yb[255] - 1U);
    (void)check(noxtls_dh_ffdhe_validate_client_key_share(PKC_MEM_FFDHE2048, yb, 256U) != NOXTLS_RETURN_SUCCESS, "ffdhe2048 share = p-1 rejected", NULL);
    (void)check(noxtls_dh_ffdhe_validate_client_key_share(PKC_MEM_FFDHE2048, ya, 255U) != NOXTLS_RETURN_SUCCESS, "ffdhe2048 short share rejected", NULL);
    noxtls_secure_zero(xa, sizeof(xa));
    noxtls_secure_zero(xb, sizeof(xb));
}
#endif

int main(void)
{
#if PKC_MEM_HAVE_ECC_CURVES
    size_t ci;
#endif
#if PKC_MEM_HAVE_RSA
    uint32_t ri;
#endif

#if PKC_MEM_HAVE_ECC_CURVES
    for(ci = 0U; ci < CURVE_COUNT; ci++) {
        printf("%s\n", g_curves[ci].name);
        test_point_validation(&g_curves[ci]);
#if PKC_MEM_HAVE_ECDSA
        test_ecdsa_negative(&g_curves[ci]);
        test_ecdsa_roundtrip(&g_curves[ci]);
#endif
#if PKC_MEM_HAVE_ECDH
        test_ecdh_roundtrip(&g_curves[ci]);
#endif
    }
#if PKC_MEM_HAVE_ECDSA
    printf("ECDSA known answers\n");
    test_ecdsa_kats();
#endif
#if PKC_MEM_HAVE_ECDH
    printf("ECDH known answers\n");
    test_ecdh_kats();
#endif
#endif
#if PKC_MEM_HAVE_RSA
    for(ri = 0U; ri < PKC_MEM_RSA_KAT_COUNT; ri++) {
        printf("RSA-%u\n", (unsigned)pkc_mem_rsa_kats[ri].bits);
        test_rsa(&pkc_mem_rsa_kats[ri]);
    }
    test_rsa_init_public_args();
#endif
#if PKC_MEM_HAVE_X25519
    printf("X25519\n");
    test_xdh("X25519", 32U, noxtls_x25519_shared_secret, noxtls_x25519_public_key, noxtls_x25519_generate_key,
             pkc_mem_x25519_kats, pkc_mem_x25519_iter1, pkc_mem_x25519_iter1000, &pkc_mem_x25519_dh);
#endif
#if PKC_MEM_HAVE_X448
    printf("X448\n");
    test_xdh("X448", 56U, noxtls_x448_shared_secret, noxtls_x448_public_key, noxtls_x448_generate_key,
             pkc_mem_x448_kats, pkc_mem_x448_iter1, pkc_mem_x448_iter1000, &pkc_mem_x448_dh);
#endif
#if PKC_MEM_HAVE_ED25519
    printf("Ed25519\n");
    test_ed25519();
#endif
#if PKC_MEM_HAVE_DH
    printf("FFDHE2048\n");
    test_ffdhe2048();
#endif

#if PKC_MEM_HAVE_ANY
    printf("pkc_mem_vectors: %u checks, %u failures\n", g_checks, g_failures);
    return (g_failures == 0U) ? 0 : 1;
#else
    printf("pkc_mem_vectors: no PKC primitive enabled, nothing to check\n");
    return 0;
#endif
}
