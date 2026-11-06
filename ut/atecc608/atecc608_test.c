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
* File:    atecc608_test.c
* Summary: ATECC608 provider unit tests and end-to-end TLS handshakes with keys held in a simulated chip
*****************************************************************************/

/**
 * @file atecc608_test.c
 * @brief Tests of the NoxTLS ATECC608 provider with a fake backend, and TLS 1.2 / 1.3 handshakes where the
 *        server or client key and the ECDHE ephemeral keys live in the (simulated) secure element.
 *
 * The fake chip computes with NoxTLS's own ECC on the host, so signatures and shared secrets are real: the peer
 * verifies them with software ECDSA and derives the same traffic keys.
 */
#include <string.h>

#include "lb_fixture.h"
#include "drbg/noxtls_drbg.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "noxtls_atecc608.h"
#include "pkc/ecc/noxtls_ecc_opaque.h"
#include "pkc/ecdh/noxtls_ecdh.h"
#include "pkc/ecdsa/noxtls_ecdsa.h"
#include "tls/noxtls_tls_key_exchange.h"

#if NOXTLS_FEATURE_ATECC608

#define FAKE_SLOT_COUNT 4U
#define FAKE_EPH_FIRST 8U
#define FAKE_EPH_COUNT 4U

/** Fake secure element: slot keys are NoxTLS software keys, ephemeral keys are generated on demand. */
typedef struct
{
    const ecc_key_t *slot_key[FAKE_SLOT_COUNT];
    ecc_key_t eph[FAKE_EPH_COUNT];
    ecc_key_t own[2];
    uint8_t own_valid;
    uint8_t eph_valid[FAKE_EPH_COUNT];
    uint32_t sign_calls;
    uint32_t keygen_calls;
    uint32_t ecdh_calls;
    uint32_t random_calls;
    uint32_t pub_calls;
    int fail_sign;
    int fail_keygen;
    int fail_ecdh;
    int fail_random;
    int fail_pub;
    int force_rs;
    uint8_t forced_rs[64];
    uint8_t last_digest[32];
} fake_chip_t;

static fake_chip_t g_chip;
static noxtls_atecc608_backend_t g_backend;
static noxtls_atecc608_provider_t g_prov;
static noxtls_atecc608_key_t g_server_handle;
static noxtls_atecc608_key_t g_client_handle;
static ecc_key_t g_server_proxy;
static ecc_key_t g_client_proxy;

static int fake_pub(void *dev, uint8_t slot, uint8_t pub[64])
{
    fake_chip_t *c = (fake_chip_t *)dev;
    const ecc_key_t *k;

    c->pub_calls++;
    if ((c->fail_pub != 0) || (slot >= FAKE_SLOT_COUNT) || (c->slot_key[slot] == NULL)) {
        return -1;
    }

    k = c->slot_key[slot];
    memcpy(pub, k->Q.x, 32U);
    memcpy(&pub[32], k->Q.y, 32U);
    return 0;
}

static int fake_sign(void *dev, uint8_t slot, const uint8_t digest[32], uint8_t rs[64])
{
    fake_chip_t *c = (fake_chip_t *)dev;
    ecdsa_signature_t sig;

    c->sign_calls++;
    memcpy(c->last_digest, digest, 32U);
    if ((c->fail_sign != 0) || (slot >= FAKE_SLOT_COUNT) || (c->slot_key[slot] == NULL)) {
        return -1;
    }

    if (c->force_rs != 0) {
        memcpy(rs, c->forced_rs, 64U);
        return 0;
    }

    if (noxtls_ecdsa_signature_init(&sig, 32U) != NOXTLS_RETURN_SUCCESS) {
        return -1;
    }
    if (noxtls_ecdsa_sign_digest(c->slot_key[slot], digest, 32U, &sig) != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_ecdsa_signature_free(&sig);
        return -1;
    }

    memcpy(rs, sig.r, 32U);
    memcpy(&rs[32], sig.s, 32U);
    (void)noxtls_ecdsa_signature_free(&sig);
    return 0;
}

static int fake_keygen(void *dev, uint16_t id, uint8_t pub[64])
{
    fake_chip_t *c = (fake_chip_t *)dev;
    uint32_t idx = (uint32_t)id - FAKE_EPH_FIRST;

    c->keygen_calls++;
    if ((c->fail_keygen != 0) || (id < FAKE_EPH_FIRST) || (idx >= FAKE_EPH_COUNT)) {
        return -1;
    }

    if (c->eph_valid[idx] != 0U) {
        (void)noxtls_ecc_key_free(&c->eph[idx]);
        c->eph_valid[idx] = 0U;
    }

    if (noxtls_ecc_key_generate(&c->eph[idx], NOXTLS_ECC_SECP256R1) != NOXTLS_RETURN_SUCCESS) {
        return -1;
    }

    c->eph_valid[idx] = 1U;
    memcpy(pub, c->eph[idx].Q.x, 32U);
    memcpy(&pub[32], c->eph[idx].Q.y, 32U);
    return 0;
}

static int fake_ecdh(void *dev, uint16_t id, const uint8_t peer[64], uint8_t secret[32])
{
    fake_chip_t *c = (fake_chip_t *)dev;
    uint32_t idx = (uint32_t)id - FAKE_EPH_FIRST;
    ecc_point_t pt;
    uint32_t len = 32U;

    c->ecdh_calls++;
    if ((c->fail_ecdh != 0) || (id < FAKE_EPH_FIRST) || (idx >= FAKE_EPH_COUNT) || (c->eph_valid[idx] == 0U)) {
        return -1;
    }

    if (noxtls_ecc_point_init(&pt, 32U) != NOXTLS_RETURN_SUCCESS) {
        return -1;
    }

    memcpy(pt.x, peer, 32U);
    memcpy(pt.y, &peer[32], 32U);
    return (noxtls_ecdh_compute_shared_secret(&c->eph[idx], &pt, secret, &len) == NOXTLS_RETURN_SUCCESS) ? 0 : -1;
}

static int fake_random(void *dev, uint8_t *out, uint32_t len)
{
    fake_chip_t *c = (fake_chip_t *)dev;
    uint32_t i;

    c->random_calls++;
    if (c->fail_random != 0) {
        return -1;
    }

    for (i = 0U; i < len; i++) {
        out[i] = (uint8_t)(0xA5U ^ (c->random_calls * 31U) ^ (i * 7U));
    }

    return 0;
}

static void chip_free(void)
{
    uint32_t i;

    for (i = 0U; i < FAKE_EPH_COUNT; i++) {
        if (g_chip.eph_valid[i] != 0U) {
            (void)noxtls_ecc_key_free(&g_chip.eph[i]);
        }
    }

    if (g_chip.own_valid != 0U) {
        (void)noxtls_ecc_key_free(&g_chip.own[0]);
        (void)noxtls_ecc_key_free(&g_chip.own[1]);
    }

    memset(&g_chip, 0, sizeof(g_chip));
}

/** Fresh chip with the test PKI server key in slot 0 and the client key in slot 1; provider with two ephemeral ids. */
static int chip_setup(int register_ecdhe)
{
    static const uint16_t ids[2] = { FAKE_EPH_FIRST, FAKE_EPH_FIRST + 1U };

    chip_free();
    memset(&g_backend, 0, sizeof(g_backend));
    g_chip.slot_key[0] = &g_lb_keys.ec_server;
    g_chip.slot_key[1] = &g_lb_keys.ec_client;
    g_backend.device = &g_chip;
    g_backend.get_public_key = fake_pub;
    g_backend.sign_digest = fake_sign;
    g_backend.ecdh_keygen = fake_keygen;
    g_backend.ecdh = fake_ecdh;
    g_backend.random = fake_random;
    LB_CHECK_OK(noxtls_atecc608_provider_init(&g_prov, &g_backend, ids, 2U));
    noxtls_atecc608_key_init(&g_server_handle, &g_backend, 0U);
    noxtls_atecc608_key_init(&g_client_handle, &g_backend, 1U);
    if (register_ecdhe != 0) {
        noxtls_atecc608_register_ecdhe(&g_prov);
    }

    return 0;
}

/** Unit tests: the chip's slots 0 and 1 hold freshly generated software keys (the PKI keys are only loaded per pair). */
static int chip_setup_unit(int register_ecdhe)
{
    LB_RUN(chip_setup(register_ecdhe));
    LB_CHECK_OK(noxtls_ecc_key_generate(&g_chip.own[0], NOXTLS_ECC_SECP256R1));
    LB_CHECK_OK(noxtls_ecc_key_generate(&g_chip.own[1], NOXTLS_ECC_SECP256R1));
    g_chip.own_valid = 1U;
    g_chip.slot_key[0] = &g_chip.own[0];
    g_chip.slot_key[1] = &g_chip.own[1];
    return 0;
}

static void chip_teardown(void)
{
    noxtls_atecc608_register_ecdhe(NULL);
    noxtls_atecc608_set_entropy_backend(NULL);
    (void)noxtls_ecc_key_free(&g_server_proxy);
    (void)noxtls_ecc_key_free(&g_client_proxy);
    memset(&g_server_proxy, 0, sizeof(g_server_proxy));
    memset(&g_client_proxy, 0, sizeof(g_client_proxy));
    chip_free();
}

/* ------------------------------------------------------------------------- */
/* Provider unit tests                                                       */
/* ------------------------------------------------------------------------- */

static int t_provider_init_args(void)
{
    static const uint16_t ids[5] = { 8U, 9U, 10U, 11U, 12U };
    noxtls_atecc608_provider_t p;

    LB_RUN(chip_setup_unit(0));
    LB_CHECK_EQ(noxtls_atecc608_provider_init(NULL, &g_backend, ids, 1U), NOXTLS_RETURN_NULL);
    LB_CHECK_EQ(noxtls_atecc608_provider_init(&p, NULL, ids, 1U), NOXTLS_RETURN_NULL);
    LB_CHECK_EQ(noxtls_atecc608_provider_init(&p, &g_backend, ids, 5U), NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_EQ(noxtls_atecc608_provider_init(&p, &g_backend, NULL, 1U), NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_OK(noxtls_atecc608_provider_init(&p, &g_backend, NULL, 0U));
    LB_CHECK(noxtls_atecc608_provider_get(&p) == &p.provider);
    LB_CHECK(noxtls_atecc608_provider_get(NULL) == NULL);
    LB_CHECK(p.ops.ecdsa_sign != NULL);
    LB_CHECK(p.ops.ecdh_keygen != NULL);
    LB_CHECK(p.ops.rsa_sign == NULL);
    noxtls_atecc608_key_init(NULL, &g_backend, 0U);
    chip_teardown();
    return 0;
}

static int sign_and_verify(noxtls_crypto_hash_algo_t algo, uint32_t message_len)
{
    uint8_t msg[200];
    uint8_t der[80];
    uint32_t der_len = sizeof(der);
    ecdsa_signature_t sig;
    const noxtls_crypto_provider_t *prov = noxtls_atecc608_provider_get(&g_prov);

    memset(msg, 0x5A, sizeof(msg));
    LB_CHECK_OK(prov->ops->ecdsa_sign(prov->ctx, &g_server_handle, msg, message_len, der, &der_len, algo));
    LB_CHECK(der[0] == 0x30U);
    LB_CHECK_EQ(der[1], der_len - 2U);
    LB_CHECK_OK(noxtls_ecdsa_signature_init(&sig, 32U));
    LB_CHECK_OK(noxtls_ecdsa_signature_parse_der(der, der_len, &sig, 32U));
    if (algo == NOXTLS_CRYPTO_HASH_PREHASHED) {
        /* The digest passed through: software verification of the same digest, left padded/truncated like the chip. */
        LB_CHECK_OK(noxtls_ecdsa_verify_digest(&g_chip.own[0], msg, message_len, &sig));
    } else {
        LB_CHECK_OK(noxtls_ecdsa_verify(&g_chip.own[0], msg, message_len, &sig, (noxtls_hash_algos_t)algo));
    }

    (void)noxtls_ecdsa_signature_free(&sig);
    return 0;
}

static int t_provider_sign_hashes(void)
{
    LB_RUN(chip_setup_unit(0));
    LB_RUN(sign_and_verify(NOXTLS_HASH_SHA_256, 0U + 1U));
    LB_RUN(sign_and_verify(NOXTLS_HASH_SHA_256, 150U));
    LB_RUN(sign_and_verify(NOXTLS_HASH_SHA_384, 120U)); /* leftmost 256 bits of the SHA-384 digest */
    LB_RUN(sign_and_verify(NOXTLS_HASH_SHA_512, 64U));
    LB_RUN(sign_and_verify(NOXTLS_CRYPTO_HASH_PREHASHED, 32U));
    LB_RUN(sign_and_verify(NOXTLS_CRYPTO_HASH_PREHASHED, 48U));
    LB_RUN(sign_and_verify(NOXTLS_CRYPTO_HASH_PREHASHED, 64U));
    LB_CHECK_EQ(g_chip.sign_calls, 7U);
    chip_teardown();
    return 0;
}

static int t_provider_sign_errors(void)
{
    uint8_t msg[32] = { 1U };
    uint8_t der[80];
    uint32_t der_len = sizeof(der);
    noxtls_atecc608_key_t bad_slot;
    noxtls_atecc608_key_t no_backend;
    const noxtls_crypto_provider_t *prov;
    noxtls_atecc608_backend_t no_sign;

    LB_RUN(chip_setup_unit(0));
    prov = noxtls_atecc608_provider_get(&g_prov);
    LB_CHECK_EQ(prov->ops->ecdsa_sign(prov->ctx, NULL, msg, 32U, der, &der_len, NOXTLS_HASH_SHA_256), NOXTLS_RETURN_NULL);
    LB_CHECK_EQ(prov->ops->ecdsa_sign(prov->ctx, &g_server_handle, NULL, 32U, der, &der_len, NOXTLS_HASH_SHA_256), NOXTLS_RETURN_NULL);
    LB_CHECK_EQ(prov->ops->ecdsa_sign(prov->ctx, &g_server_handle, msg, 32U, NULL, &der_len, NOXTLS_HASH_SHA_256), NOXTLS_RETURN_NULL);
    LB_CHECK_EQ(prov->ops->ecdsa_sign(prov->ctx, &g_server_handle, msg, 32U, der, NULL, NOXTLS_HASH_SHA_256), NOXTLS_RETURN_NULL);
    noxtls_atecc608_key_init(&no_backend, NULL, 0U);
    LB_CHECK_EQ(prov->ops->ecdsa_sign(prov->ctx, &no_backend, msg, 32U, der, &der_len, NOXTLS_HASH_SHA_256), NOXTLS_RETURN_NULL);
    no_sign = g_backend;
    no_sign.sign_digest = NULL;
    noxtls_atecc608_key_init(&no_backend, &no_sign, 0U);
    LB_CHECK_EQ(prov->ops->ecdsa_sign(prov->ctx, &no_backend, msg, 32U, der, &der_len, NOXTLS_HASH_SHA_256), NOXTLS_RETURN_NULL);
    noxtls_atecc608_key_init(&bad_slot, &g_backend, 16U);
    LB_CHECK_EQ(prov->ops->ecdsa_sign(prov->ctx, &bad_slot, msg, 32U, der, &der_len, NOXTLS_HASH_SHA_256), NOXTLS_RETURN_INVALID_PARAM);
    noxtls_atecc608_key_init(&bad_slot, &g_backend, NOXTLS_ATECC608_KEYID_TEMPKEY);
    LB_CHECK_EQ(prov->ops->ecdsa_sign(prov->ctx, &bad_slot, msg, 32U, der, &der_len, NOXTLS_HASH_SHA_256), NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_EQ(prov->ops->ecdsa_sign(prov->ctx, &g_server_handle, msg, 32U, der, &der_len, NOXTLS_HASH_SHA1), NOXTLS_RETURN_NOT_SUPPORTED);
    LB_CHECK_EQ(prov->ops->ecdsa_sign(prov->ctx, &g_server_handle, msg, 0U, der, &der_len, NOXTLS_CRYPTO_HASH_PREHASHED), NOXTLS_RETURN_INVALID_PARAM);
    LB_CHECK_EQ(prov->ops->ecdsa_sign(prov->ctx, &g_server_handle, msg, 65U, der, &der_len, NOXTLS_CRYPTO_HASH_PREHASHED), NOXTLS_RETURN_INVALID_PARAM);
    der_len = 8U; /* too small for the DER signature */
    LB_CHECK_EQ(prov->ops->ecdsa_sign(prov->ctx, &g_server_handle, msg, 32U, der, &der_len, NOXTLS_HASH_SHA_256), NOXTLS_RETURN_FAILED);
    der_len = sizeof(der);
    g_chip.fail_sign = 1;
    LB_CHECK_EQ(prov->ops->ecdsa_sign(prov->ctx, &g_server_handle, msg, 32U, der, &der_len, NOXTLS_HASH_SHA_256), NOXTLS_RETURN_FAILED);
    chip_teardown();
    return 0;
}

static int t_provider_sign_der_edge_cases(void)
{
    uint8_t msg[32] = { 7U };
    uint8_t der[80];
    uint32_t der_len = sizeof(der);
    uint32_t i;
    const noxtls_crypto_provider_t *prov;

    LB_RUN(chip_setup_unit(0));
    prov = noxtls_atecc608_provider_get(&g_prov);
    /* R has leading zero bytes (shortest form), S has the high bit set (needs a 0x00 prefix). */
    memset(g_chip.forced_rs, 0, sizeof(g_chip.forced_rs));
    g_chip.forced_rs[31] = 0x01U;
    g_chip.forced_rs[32] = 0x80U;
    g_chip.force_rs = 1;
    LB_CHECK_OK(prov->ops->ecdsa_sign(prov->ctx, &g_server_handle, msg, 32U, der, &der_len, NOXTLS_HASH_SHA_256));
    LB_CHECK_EQ(der_len, 40U);
    LB_CHECK_EQ(der[0], 0x30U);
    LB_CHECK_EQ(der[1], 38U);
    LB_CHECK_EQ(der[2], 0x02U);
    LB_CHECK_EQ(der[3], 1U);
    LB_CHECK_EQ(der[4], 0x01U);
    LB_CHECK_EQ(der[5], 0x02U);
    LB_CHECK_EQ(der[6], 33U);
    LB_CHECK_EQ(der[7], 0x00U);
    LB_CHECK_EQ(der[8], 0x80U);
    for (i = 9U; i < 40U; i++) {
        LB_CHECK_EQ(der[i], 0U);
    }

    /* Both full width with the high bit set: 0x30 0x46. */
    memset(g_chip.forced_rs, 0xFF, sizeof(g_chip.forced_rs));
    der_len = sizeof(der);
    LB_CHECK_OK(prov->ops->ecdsa_sign(prov->ctx, &g_server_handle, msg, 32U, der, &der_len, NOXTLS_HASH_SHA_256));
    LB_CHECK_EQ(der_len, 72U);
    LB_CHECK_EQ(der[1], 70U);
    /* R = 0 and S = 0 encode as one zero byte each. */
    memset(g_chip.forced_rs, 0, sizeof(g_chip.forced_rs));
    der_len = sizeof(der);
    LB_CHECK_OK(prov->ops->ecdsa_sign(prov->ctx, &g_server_handle, msg, 32U, der, &der_len, NOXTLS_HASH_SHA_256));
    LB_CHECK_EQ(der_len, 8U);
    chip_teardown();
    return 0;
}

static int t_bound_key_signs_through_the_chip(void)
{
    uint8_t msg[40];
    uint8_t digest[32];
    ecdsa_signature_t sig;
    ecdsa_signature_t sig2;
    noxtls_sha_ctx_t sha;
    ecc_key_t second;

    LB_RUN(chip_setup_unit(0));
    memset(msg, 0x11, sizeof(msg));
    LB_CHECK_OK(noxtls_atecc608_bind_ecc_key(&g_prov, &g_server_handle, &g_server_proxy));
    LB_CHECK(noxtls_ecc_opaque_is_bound(&g_server_proxy) != 0);
    LB_CHECK(memcmp(g_server_proxy.Q.x, g_chip.own[0].Q.x, 32U) == 0);
    LB_CHECK(memcmp(g_server_proxy.Q.y, g_chip.own[0].Q.y, 32U) == 0);
    /* noxtls_ecdsa_sign on the proxy goes to the chip; the public part verifies the result. */
    LB_CHECK_OK(noxtls_ecdsa_signature_init(&sig, 32U));
    LB_CHECK_OK(noxtls_ecdsa_sign(&g_server_proxy, msg, sizeof(msg), &sig, NOXTLS_HASH_SHA_256));
    LB_CHECK_EQ(g_chip.sign_calls, 1U);
    LB_CHECK_OK(noxtls_ecdsa_verify(&g_server_proxy, msg, sizeof(msg), &sig, NOXTLS_HASH_SHA_256));
    /* The digest form (TLS 1.2 client CertificateVerify). */
    LB_CHECK_OK(noxtls_sha256_init(&sha, NOXTLS_HASH_SHA_256));
    LB_CHECK_OK(noxtls_sha256_update(&sha, msg, sizeof(msg)));
    LB_CHECK_OK(noxtls_sha256_finish(&sha, digest));
    LB_CHECK_OK(noxtls_ecdsa_signature_init(&sig2, 32U));
    LB_CHECK_OK(noxtls_ecdsa_sign_digest(&g_server_proxy, digest, 32U, &sig2));
    LB_CHECK_EQ(g_chip.sign_calls, 2U);
    LB_CHECK(memcmp(g_chip.last_digest, digest, 32U) == 0);
    LB_CHECK_OK(noxtls_ecdsa_verify_digest(&g_server_proxy, digest, 32U, &sig2));
    /* An unbound software key still signs in software and never reaches the chip. */
    LB_CHECK_OK(noxtls_ecdsa_sign(&g_chip.own[1], msg, sizeof(msg), &sig, NOXTLS_HASH_SHA_256));
    LB_CHECK_EQ(g_chip.sign_calls, 2U);
    /* Chip errors surface. */
    g_chip.fail_sign = 1;
    LB_CHECK(noxtls_ecdsa_sign(&g_server_proxy, msg, sizeof(msg), &sig, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS);
    /* Freeing the key removes the binding. */
    LB_CHECK_OK(noxtls_ecc_key_free(&g_server_proxy));
    LB_CHECK(noxtls_ecc_opaque_is_bound(&g_server_proxy) == 0);
    /* Bind API errors. */
    LB_CHECK_EQ(noxtls_atecc608_bind_ecc_key(NULL, &g_server_handle, &second), NOXTLS_RETURN_NULL);
    LB_CHECK_EQ(noxtls_atecc608_bind_ecc_key(&g_prov, NULL, &second), NOXTLS_RETURN_NULL);
    LB_CHECK_EQ(noxtls_atecc608_bind_ecc_key(&g_prov, &g_server_handle, NULL), NOXTLS_RETURN_NULL);
    noxtls_atecc608_key_init(&g_client_handle, &g_backend, 99U);
    LB_CHECK_EQ(noxtls_atecc608_bind_ecc_key(&g_prov, &g_client_handle, &second), NOXTLS_RETURN_INVALID_PARAM);
    noxtls_atecc608_key_init(&g_client_handle, &g_backend, 3U); /* empty slot */
    LB_CHECK_EQ(noxtls_atecc608_bind_ecc_key(&g_prov, &g_client_handle, &second), NOXTLS_RETURN_FAILED);
    (void)noxtls_ecdsa_signature_free(&sig);
    (void)noxtls_ecdsa_signature_free(&sig2);
    chip_teardown();
    return 0;
}

static int t_opaque_table_limits(void)
{
    ecc_key_t keys[NOXTLS_ECC_OPAQUE_MAX + 1U];
    uint32_t i;
    noxtls_crypto_provider_t no_ops;

    LB_RUN(chip_setup_unit(0));
    memset(keys, 0, sizeof(keys));
    for (i = 0U; i < NOXTLS_ECC_OPAQUE_MAX; i++) {
        LB_CHECK_OK(noxtls_ecc_opaque_bind(&keys[i], noxtls_atecc608_provider_get(&g_prov), &g_server_handle));
    }

    LB_CHECK_EQ(noxtls_ecc_opaque_bind(&keys[NOXTLS_ECC_OPAQUE_MAX], noxtls_atecc608_provider_get(&g_prov), &g_server_handle),
                NOXTLS_RETURN_NOT_ENOUGH_MEMORY);
    LB_CHECK_OK(noxtls_ecc_opaque_bind(&keys[0], noxtls_atecc608_provider_get(&g_prov), &g_client_handle)); /* rebind */
    noxtls_ecc_opaque_unbind(&keys[0]);
    LB_CHECK_OK(noxtls_ecc_opaque_bind(&keys[NOXTLS_ECC_OPAQUE_MAX], noxtls_atecc608_provider_get(&g_prov), &g_server_handle));
    LB_CHECK_EQ(noxtls_ecc_opaque_bind(NULL, noxtls_atecc608_provider_get(&g_prov), NULL), NOXTLS_RETURN_NULL);
    LB_CHECK_EQ(noxtls_ecc_opaque_bind(&keys[0], NULL, NULL), NOXTLS_RETURN_NULL);
    no_ops.ctx = NULL;
    no_ops.ops = NULL;
    LB_CHECK_EQ(noxtls_ecc_opaque_bind(&keys[0], &no_ops, NULL), NOXTLS_RETURN_NULL);
    LB_CHECK(noxtls_ecc_opaque_is_bound(NULL) == 0);
    noxtls_ecc_opaque_unbind(NULL);
    for (i = 0U; i <= NOXTLS_ECC_OPAQUE_MAX; i++) {
        noxtls_ecc_opaque_unbind(&keys[i]);
    }

    chip_teardown();
    return 0;
}

static int t_bound_key_does_ecdh_in_the_chip(void)
{
    ecc_key_t eph;
    ecc_key_t peer;
    uint8_t pub[64];
    uint8_t s1[32];
    uint8_t s2[32];
    uint32_t l1 = sizeof(s1);
    uint32_t l2 = sizeof(s2);
    ecc_point_t pt;
    noxtls_crypto_key_handle_t handle = NULL;
    uint32_t pub_len = sizeof(pub);
    noxtls_return_t rc;
    const noxtls_crypto_provider_t *prov;
    noxtls_crypto_provider_t partial;
    noxtls_crypto_provider_ops_t partial_ops;

    LB_RUN(chip_setup_unit(0));
    prov = noxtls_atecc608_provider_get(&g_prov);
    memset(&eph, 0, sizeof(eph));
    memset(&peer, 0, sizeof(peer));
    LB_CHECK_OK(noxtls_ecc_key_generate(&peer, NOXTLS_ECC_SECP256R1));
    LB_CHECK_OK(noxtls_ecc_key_init(&eph, NOXTLS_ECC_SECP256R1));
    LB_CHECK_OK(prov->ops->ecdh_keygen(prov->ctx, 23U, &handle, pub, &pub_len));
    LB_CHECK_EQ(pub_len, 64U);
    memcpy(eph.Q.x, pub, 32U);
    memcpy(eph.Q.y, &pub[32], 32U);
    eph.Q.size = 32U;
    LB_CHECK_OK(noxtls_ecc_opaque_bind(&eph, prov, handle));
    LB_CHECK_OK(noxtls_ecdh_compute_shared_secret(&eph, &peer.Q, s1, &l1));
    LB_CHECK_OK(noxtls_ecc_point_init(&pt, 32U));
    memcpy(pt.x, eph.Q.x, 32U);
    memcpy(pt.y, eph.Q.y, 32U);
    LB_CHECK_OK(noxtls_ecdh_compute_shared_secret(&peer, &pt, s2, &l2)); /* the peer's view */
    LB_CHECK_EQ(l1, 32U);
    LB_CHECK(memcmp(s1, s2, 32U) == 0);
    LB_CHECK_EQ(g_chip.ecdh_calls, 1U);
    /* provider errors */
    pub_len = 10U;
    LB_CHECK_EQ(prov->ops->ecdh_keygen(prov->ctx, 23U, &handle, pub, &pub_len), NOXTLS_RETURN_INVALID_PARAM);
    pub_len = sizeof(pub);
    LB_CHECK_EQ(prov->ops->ecdh_keygen(prov->ctx, 24U, &handle, pub, &pub_len), NOXTLS_RETURN_NOT_SUPPORTED);
    LB_CHECK_EQ(prov->ops->ecdh_keygen(NULL, 23U, &handle, pub, &pub_len), NOXTLS_RETURN_NULL);
    LB_CHECK_EQ(prov->ops->ecdh_keygen(prov->ctx, 23U, NULL, pub, &pub_len), NOXTLS_RETURN_NULL);
    g_chip.fail_keygen = 1;
    LB_CHECK_EQ(prov->ops->ecdh_keygen(prov->ctx, 23U, &handle, pub, &pub_len), NOXTLS_RETURN_FAILED);
    g_chip.fail_keygen = 0;
    LB_CHECK_EQ(prov->ops->ecdh_shared(prov->ctx, NULL, pub, 64U, s1, &l1), NOXTLS_RETURN_NULL);
    l1 = sizeof(s1);
    LB_CHECK_EQ(prov->ops->ecdh_shared(prov->ctx, handle, pub, 63U, s1, &l1), NOXTLS_RETURN_INVALID_PARAM);
    l1 = 16U;
    LB_CHECK_EQ(prov->ops->ecdh_shared(prov->ctx, handle, pub, 64U, s1, &l1), NOXTLS_RETURN_INVALID_PARAM);
    l1 = sizeof(s1);
    g_chip.fail_ecdh = 1;
    LB_CHECK_EQ(prov->ops->ecdh_shared(prov->ctx, handle, pub, 64U, s1, &l1), NOXTLS_RETURN_FAILED);
    g_chip.fail_ecdh = 0;
    /* a provider without ecdh_shared leaves the bound key unsupported */
    memset(&partial_ops, 0, sizeof(partial_ops));
    partial.ctx = NULL;
    partial.ops = &partial_ops;
    LB_CHECK_OK(noxtls_ecc_opaque_bind(&eph, &partial, handle));
    LB_CHECK_EQ(noxtls_ecc_opaque_ecdh(&eph, &peer.Q, s1, &l1), NOXTLS_RETURN_NOT_SUPPORTED);
    LB_CHECK_EQ(noxtls_ecc_opaque_ecdsa_sign(&eph, s1, 32U, NULL, NOXTLS_HASH_SHA_256), NOXTLS_RETURN_NOT_SUPPORTED);
    LB_CHECK_OK(noxtls_ecc_opaque_bind(&eph, prov, handle));
    LB_CHECK_EQ(noxtls_ecc_opaque_ecdh(&eph, NULL, s1, &l1), NOXTLS_RETURN_NULL);
    pt.size = 31U;
    LB_CHECK_EQ(noxtls_ecc_opaque_ecdh(&eph, &pt, s1, &l1), NOXTLS_RETURN_INVALID_PARAM);
    rc = noxtls_ecc_opaque_ecdh(&peer, &pt, s1, &l1); /* unbound key */
    LB_CHECK_EQ(rc, NOXTLS_RETURN_NOT_SUPPORTED);
    LB_CHECK_EQ(noxtls_ecc_opaque_ecdsa_sign(&peer, s1, 32U, NULL, NOXTLS_HASH_SHA_256), NOXTLS_RETURN_NOT_SUPPORTED);
    (void)noxtls_ecc_key_free(&eph);
    (void)noxtls_ecc_key_free(&peer);
    chip_teardown();
    return 0;
}

static int t_tls_ecdhe_generation_uses_the_chip_for_p256_only(void)
{
    tls_ecdhe_context_t e;
    ecc_key_t peer;
    uint8_t s2[32];
    uint32_t l2 = sizeof(s2);
    ecc_point_t pt;

    LB_RUN(chip_setup_unit(1));
    memset(&peer, 0, sizeof(peer));
    LB_CHECK_OK(noxtls_ecc_key_generate(&peer, NOXTLS_ECC_SECP256R1));
    LB_CHECK_OK(noxtls_tls_ecdhe_context_init(&e, TLS_NAMED_GROUP_SECP256R1));
    LB_CHECK_OK(noxtls_tls_ecdhe_generate_ephemeral_key(&e));
    LB_CHECK_EQ(g_chip.keygen_calls, 1U);
    LB_CHECK(noxtls_ecc_opaque_is_bound(&e.ephemeral_key) != 0);
    LB_CHECK_OK(noxtls_tls_ecdhe_compute_shared_secret(&e, &peer.Q));
    LB_CHECK_EQ(g_chip.ecdh_calls, 1U);
    LB_CHECK_EQ(e.shared_secret_len, 32U);
    LB_CHECK_OK(noxtls_ecc_point_init(&pt, 32U));
    memcpy(pt.x, e.ephemeral_key.Q.x, 32U);
    memcpy(pt.y, e.ephemeral_key.Q.y, 32U);
    LB_CHECK_OK(noxtls_ecdh_compute_shared_secret(&peer, &pt, s2, &l2));
    LB_CHECK(memcmp(s2, e.shared_secret, 32U) == 0);
    LB_CHECK_OK(noxtls_tls_ecdhe_context_free(&e));
    LB_CHECK(noxtls_ecc_opaque_is_bound(&e.ephemeral_key) == 0);
    /* Regenerating (HelloRetryRequest style) rebinds without leaking a table entry. */
    LB_CHECK_OK(noxtls_tls_ecdhe_context_init(&e, TLS_NAMED_GROUP_SECP256R1));
    LB_CHECK_OK(noxtls_tls_ecdhe_generate_ephemeral_key(&e));
    LB_CHECK_OK(noxtls_tls_ecdhe_generate_ephemeral_key(&e));
    LB_CHECK_OK(noxtls_tls_ecdhe_context_free(&e));
    /* P-384 is not a chip group: generated in software. */
    LB_CHECK_OK(noxtls_tls_ecdhe_context_init(&e, TLS_NAMED_GROUP_SECP384R1));
    LB_CHECK_OK(noxtls_tls_ecdhe_generate_ephemeral_key(&e));
    LB_CHECK(noxtls_ecc_opaque_is_bound(&e.ephemeral_key) == 0);
    LB_CHECK(e.ephemeral_key.d != NULL);
    LB_CHECK_OK(noxtls_tls_ecdhe_context_free(&e));
    /* A failing chip fails the key generation (no silent software fallback for a configured chip). */
    g_chip.fail_keygen = 1;
    LB_CHECK_OK(noxtls_tls_ecdhe_context_init(&e, TLS_NAMED_GROUP_SECP256R1));
    LB_CHECK(noxtls_tls_ecdhe_generate_ephemeral_key(&e) != NOXTLS_RETURN_SUCCESS);
    LB_CHECK_OK(noxtls_tls_ecdhe_context_free(&e));
    g_chip.fail_keygen = 0;
    /* Without a registered provider it is software again. */
    noxtls_atecc608_register_ecdhe(NULL);
    LB_CHECK_OK(noxtls_tls_ecdhe_context_init(&e, TLS_NAMED_GROUP_SECP256R1));
    LB_CHECK_OK(noxtls_tls_ecdhe_generate_ephemeral_key(&e));
    LB_CHECK(noxtls_ecc_opaque_is_bound(&e.ephemeral_key) == 0);
    LB_CHECK_OK(noxtls_tls_ecdhe_context_free(&e));
    /* A provider with no ephemeral ids also leaves ECDHE to software. */
    {
        noxtls_atecc608_provider_t none;

        LB_CHECK_OK(noxtls_atecc608_provider_init(&none, &g_backend, NULL, 0U));
        noxtls_atecc608_register_ecdhe(&none);
        LB_CHECK_OK(noxtls_tls_ecdhe_context_init(&e, TLS_NAMED_GROUP_SECP256R1));
        LB_CHECK_OK(noxtls_tls_ecdhe_generate_ephemeral_key(&e));
        LB_CHECK(noxtls_ecc_opaque_is_bound(&e.ephemeral_key) == 0);
        LB_CHECK_OK(noxtls_tls_ecdhe_context_free(&e));
    }

    LB_CHECK_EQ(g_chip.keygen_calls, 4U);
    (void)noxtls_ecc_key_free(&peer);
    chip_teardown();
    return 0;
}

#if NOXTLS_FEATURE_ATECC608_ENTROPY
static int t_entropy_port(void)
{
    uint8_t buf[48];
    uint8_t zero[48];

    LB_RUN(chip_setup_unit(0));
    memset(zero, 0, sizeof(zero));
    memset(buf, 0, sizeof(buf));
    LB_CHECK_EQ(noxtls_drbg_entropy_accel_port(buf, sizeof(buf)), NOXTLS_RETURN_NOT_SUPPORTED); /* no backend yet */
    noxtls_atecc608_set_entropy_backend(&g_backend);
    LB_CHECK_OK(noxtls_drbg_entropy_accel_port(buf, sizeof(buf)));
    LB_CHECK_EQ(g_chip.random_calls, 1U);
    LB_CHECK(memcmp(buf, zero, sizeof(buf)) != 0);
    LB_CHECK_EQ(noxtls_drbg_entropy_accel_port(NULL, 8U), NOXTLS_RETURN_NULL);
    LB_CHECK_EQ(noxtls_drbg_entropy_accel_port(buf, 0U), NOXTLS_RETURN_NULL);
    g_chip.fail_random = 1;
    LB_CHECK_EQ(noxtls_drbg_entropy_accel_port(buf, sizeof(buf)), NOXTLS_RETURN_FAILED);
    g_chip.fail_random = 0;
    {
        noxtls_atecc608_backend_t no_random = g_backend;

        no_random.random = NULL;
        noxtls_atecc608_set_entropy_backend(&no_random);
        LB_CHECK_EQ(noxtls_drbg_entropy_accel_port(buf, sizeof(buf)), NOXTLS_RETURN_NOT_SUPPORTED);
    }

    /* The DRBG's AUTO source reaches the chip (the DRBG, not the raw chip output, feeds TLS). */
    noxtls_atecc608_set_entropy_backend(&g_backend);
    noxtls_drbg_set_entropy_source(NOXTLS_ENTROPY_SOURCE_AUTO);
    g_chip.random_calls = 0U;
    LB_CHECK_OK(noxtls_drbg_get_entropy(buf, sizeof(buf)));
    LB_CHECK(g_chip.random_calls >= 1U);
    chip_teardown();
    return 0;
}
#endif

/* ------------------------------------------------------------------------- */
/* End to end                                                                */
/* ------------------------------------------------------------------------- */

static const uint16_t k_p256_group[1] = { TLS_NAMED_GROUP_SECP256R1 };

static int small_exchange(lb_pair_t *pair)
{
    static const uint8_t c2s[] = "client hello data";
    static const uint8_t s2c[] = "server reply data!";

    LB_RUN(lb_transfer(pair, 1, c2s, sizeof(c2s), TLS_MAX_RECORD_SIZE, sizeof(c2s)));
    LB_RUN(lb_transfer(pair, 0, s2c, sizeof(s2c), TLS_MAX_RECORD_SIZE, sizeof(s2c)));
    return 0;
}

/**
 * Handshake with the endpoints' keys optionally replaced by chip-held ones.
 * server_in_chip / client_in_chip bind the proxy keys; ECDHE through the chip is registered by chip_setup().
 */
static int chip_session(lb_proto_t proto, int server_in_chip, int client_in_chip, int ecdhe_in_chip, uint32_t want_sign, uint32_t want_keygen)
{
    lb_cfg_t cfg;
    lb_pair_t pair;
    size_t base;
    uint16_t suite = TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

    LB_RUN(lb_trust_all_roots());
    LB_RUN(chip_setup(ecdhe_in_chip));
    base = lb_alloc_live_bytes();
    lb_cfg_default(&cfg, proto);
    cfg.client_auth = (client_in_chip != 0) ? 2 : 0;
    cfg.client_cert = (client_in_chip != 0) ? LB_AUTH_ECDSA : LB_AUTH_NONE;
    if (proto == LB_PROTO_TLS13) {
        cfg.client_groups = k_p256_group;
        cfg.client_group_count = 1U;
    } else {
        cfg.server_suites = &suite;
        cfg.server_suite_count = 1U;
    }

    LB_RUN(lb_pair_init(&pair, &cfg));
    if (server_in_chip != 0) {
        LB_CHECK_OK(noxtls_atecc608_bind_ecc_key(&g_prov, &g_server_handle, &g_server_proxy));
        if (proto == LB_PROTO_TLS13) {
            noxtls_tls13_set_server_private_ecdsa(pair.server.t13, &g_server_proxy);
        } else {
            noxtls_tls12_set_server_private_ecdsa(pair.server.t12, &g_server_proxy);
        }
    }

    if (client_in_chip != 0) {
        LB_CHECK_OK(noxtls_atecc608_bind_ecc_key(&g_prov, &g_client_handle, &g_client_proxy));
        if (proto == LB_PROTO_TLS13) {
            LB_CHECK_OK(noxtls_tls13_set_client_cert_ecdsa(pair.client.t13, lb_ec_client_cert, lb_ec_client_cert_len, &g_client_proxy));
        } else {
            LB_CHECK_OK(noxtls_tls12_set_client_cert_ecdsa(pair.client.t12, lb_ec_client_cert, lb_ec_client_cert_len, &g_client_proxy));
        }
    }

    if (lb_pair_handshake(&pair) != 0) {
        lb_log("handshake failed: client rc=%d server rc=%d", (int)pair.client.last_rc, (int)pair.server.last_rc);
        lb_pair_free(&pair);
        chip_teardown();
        return 1;
    }

    LB_CHECK_EQ(lb_field_state(&pair.client), TLS_STATE_CONNECTED);
    LB_CHECK_EQ(lb_field_state(&pair.server), TLS_STATE_CONNECTED);
    if (proto == LB_PROTO_TLS13) {
        LB_CHECK_EQ(lb_field_tls13_group(pair.client.t13), TLS_NAMED_GROUP_SECP256R1);
    }

    LB_RUN(small_exchange(&pair));
    LB_RUN(lb_close_and_observe(&pair, 1));
    lb_pair_free(&pair);
    lb_log("chip calls: sign=%u keygen=%u ecdh=%u", (unsigned)g_chip.sign_calls, (unsigned)g_chip.keygen_calls, (unsigned)g_chip.ecdh_calls);
    LB_CHECK_EQ(g_chip.sign_calls, want_sign);
    LB_CHECK_EQ(g_chip.keygen_calls, want_keygen);
    LB_CHECK_EQ(g_chip.ecdh_calls, want_keygen);
    chip_teardown();
    (void)ecdhe_in_chip;
    return lb_expect_no_leak(base, "chip session");
}

static int t_e2e_tls13_server_key_and_ecdhe_in_chip(void)
{
    /* server CertificateVerify signed by the chip; client and server ephemeral keys and ECDH in the chip */
    return chip_session(LB_PROTO_TLS13, 1, 0, 1, 1U, 2U);
}

static int t_e2e_tls13_client_key_in_chip(void)
{
    /* mutual TLS: the client CertificateVerify is signed by the chip as well */
    return chip_session(LB_PROTO_TLS13, 1, 1, 1, 2U, 2U);
}

static int t_e2e_tls13_key_in_chip_software_ecdhe(void)
{
    return chip_session(LB_PROTO_TLS13, 1, 0, 0, 1U, 0U);
}

static int t_e2e_tls13_ecdhe_only_in_chip(void)
{
    return chip_session(LB_PROTO_TLS13, 0, 0, 1, 0U, 2U);
}

static int t_e2e_tls12_server_key_and_ecdhe_in_chip(void)
{
    /* ServerKeyExchange signed by the chip; ECDHE keys in the chip */
    return chip_session(LB_PROTO_TLS12, 1, 0, 1, 1U, 2U);
}

static int t_e2e_tls12_client_key_in_chip(void)
{
    return chip_session(LB_PROTO_TLS12, 1, 1, 1, 2U, 2U);
}

static int t_e2e_tls12_ecdhe_only_in_chip(void)
{
    return chip_session(LB_PROTO_TLS12, 0, 0, 1, 0U, 2U);
}

/** A chip that fails the signature must fail the handshake cleanly (no leak, not connected). */
static int chip_failure_case(lb_proto_t proto, int fail_sign, int fail_keygen)
{
    lb_cfg_t cfg;
    lb_pair_t pair;
    size_t base;
    uint16_t suite = TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

    LB_RUN(lb_trust_all_roots());
    LB_RUN(chip_setup(1));
    base = lb_alloc_live_bytes();
    lb_cfg_default(&cfg, proto);
    if (proto == LB_PROTO_TLS13) {
        cfg.client_groups = k_p256_group;
        cfg.client_group_count = 1U;
    } else {
        cfg.server_suites = &suite;
        cfg.server_suite_count = 1U;
    }

    LB_RUN(lb_pair_init(&pair, &cfg));
    LB_CHECK_OK(noxtls_atecc608_bind_ecc_key(&g_prov, &g_server_handle, &g_server_proxy));
    if (proto == LB_PROTO_TLS13) {
        noxtls_tls13_set_server_private_ecdsa(pair.server.t13, &g_server_proxy);
    } else {
        noxtls_tls12_set_server_private_ecdsa(pair.server.t12, &g_server_proxy);
    }

    g_chip.fail_sign = fail_sign;
    g_chip.fail_keygen = fail_keygen;
    g_lb_quiet = 1;
    LB_CHECK(lb_pair_handshake(&pair) != 0);
    g_lb_quiet = 0;
    LB_CHECK(!((pair.client.done != 0) && (pair.server.done != 0)));
    lb_pair_free(&pair);
    chip_teardown();
    return lb_expect_no_leak(base, "failed chip handshake");
}

static int t_e2e_tls13_chip_sign_failure(void) { return chip_failure_case(LB_PROTO_TLS13, 1, 0); }
static int t_e2e_tls13_chip_keygen_failure(void) { return chip_failure_case(LB_PROTO_TLS13, 0, 1); }
static int t_e2e_tls12_chip_sign_failure(void) { return chip_failure_case(LB_PROTO_TLS12, 1, 0); }
static int t_e2e_tls12_chip_keygen_failure(void) { return chip_failure_case(LB_PROTO_TLS12, 0, 1); }

static const lb_test_case_t k_cases[] = {
    { "atecc608_provider_init_args", t_provider_init_args },
    { "atecc608_provider_sign_hashes", t_provider_sign_hashes },
    { "atecc608_provider_sign_errors", t_provider_sign_errors },
    { "atecc608_provider_sign_der_edge_cases", t_provider_sign_der_edge_cases },
    { "atecc608_bound_key_signs_through_chip", t_bound_key_signs_through_the_chip },
    { "atecc608_opaque_table_limits", t_opaque_table_limits },
    { "atecc608_bound_key_ecdh_in_chip", t_bound_key_does_ecdh_in_the_chip },
    { "atecc608_ecdhe_generation_p256_only", t_tls_ecdhe_generation_uses_the_chip_for_p256_only },
#if NOXTLS_FEATURE_ATECC608_ENTROPY
    { "atecc608_entropy_port", t_entropy_port },
#endif
    { "atecc608_e2e_tls13_server_key_ecdhe", t_e2e_tls13_server_key_and_ecdhe_in_chip },
    { "atecc608_e2e_tls13_client_key", t_e2e_tls13_client_key_in_chip },
    { "atecc608_e2e_tls13_key_software_ecdhe", t_e2e_tls13_key_in_chip_software_ecdhe },
    { "atecc608_e2e_tls13_ecdhe_only", t_e2e_tls13_ecdhe_only_in_chip },
    { "atecc608_e2e_tls12_server_key_ecdhe", t_e2e_tls12_server_key_and_ecdhe_in_chip },
    { "atecc608_e2e_tls12_client_key", t_e2e_tls12_client_key_in_chip },
    { "atecc608_e2e_tls12_ecdhe_only", t_e2e_tls12_ecdhe_only_in_chip },
    { "atecc608_e2e_tls13_chip_sign_failure", t_e2e_tls13_chip_sign_failure },
    { "atecc608_e2e_tls13_chip_keygen_failure", t_e2e_tls13_chip_keygen_failure },
    { "atecc608_e2e_tls12_chip_sign_failure", t_e2e_tls12_chip_sign_failure },
    { "atecc608_e2e_tls12_chip_keygen_failure", t_e2e_tls12_chip_keygen_failure },
};

int main(int argc, char **argv)
{
    return lb_main(argc, argv, "atecc608", k_cases, sizeof(k_cases) / sizeof(k_cases[0]));
}

#else

int main(void)
{
    return 77;
}

#endif
