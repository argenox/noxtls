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
* File:    noxtls_atecc608.c
* Summary: Microchip ATECC608B/C crypto provider (keys that never leave the secure element)
*
*****************************************************************************/

#include <stdint.h>

#include "noxtls_atecc608.h"

#if NOXTLS_FEATURE_ATECC608

#include "common/noxtls_ct.h"
#include "mdigest/noxtls_hash.h"
#include "mdigest/noxtls_sha.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha512/noxtls_sha512.h"
#include "pkc/ecc/noxtls_ecc_opaque.h"

/** TLS NamedGroup secp256r1 (RFC 8422). */
#define ATECC_GROUP_SECP256R1 23U
/** ECDSA P-256 digest and coordinate size. */
#define ATECC_DIGEST 32U
/** Public point X || Y. */
#define ATECC_POINT 64U
/** Highest data slot. */
#define ATECC_SLOT_MAX 15U
/** Largest digest NoxTLS can hand over as a prehashed value. */
#define ATECC_PREHASH_MAX 64U

/**
 * @brief Append one ASN.1 INTEGER holding an unsigned big endian value.
 * @internal
 */
static uint32_t atecc_put_integer(uint8_t *out, const uint8_t *v, uint32_t len)
{
    uint32_t skip = 0U;
    uint32_t n;
    uint32_t pos = 0U;
    uint32_t i;

    while ((skip < (len - 1U)) && (v[skip] == 0U)) {
        skip++;
    }

    n = len - skip;
    out[pos++] = 0x02U;
    if ((v[skip] & 0x80U) != 0U) {
        out[pos++] = (uint8_t)(n + 1U);
        out[pos++] = 0x00U;
    } else {
        out[pos++] = (uint8_t)n;
    }

    for (i = 0U; i < n; i++) {
        out[pos++] = v[skip + i];
    }

    return pos;
}

/**
 * @brief DER encode R || S (32 bytes each) as SEQUENCE { INTEGER r, INTEGER s }.
 * @internal
 */
static noxtls_return_t atecc_der_encode(const uint8_t rs[64], uint8_t *der, uint32_t *der_len)
{
    uint8_t body[2U * (ATECC_DIGEST + 3U)];
    uint32_t n;
    uint32_t i;

    n = atecc_put_integer(body, rs, ATECC_DIGEST);
    n += atecc_put_integer(&body[n], &rs[ATECC_DIGEST], ATECC_DIGEST);
    if ((*der_len < (n + 2U)) || (n >= 128U)) {
        return NOXTLS_RETURN_FAILED;
    }

    der[0] = 0x30U;
    der[1] = (uint8_t)n;
    for (i = 0U; i < n; i++) {
        der[2U + i] = body[i];
    }

    *der_len = n + 2U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Reduce a message or digest to the 32 byte value the chip signs.
 *
 * The leftmost 256 bits of a longer digest are used (FIPS 186-4 6.4); a shorter digest is left padded with
 * zeros, which is the same integer.
 * @internal
 */
static noxtls_return_t atecc_digest(const uint8_t *message, uint32_t message_len, noxtls_crypto_hash_algo_t algo, uint8_t out[ATECC_DIGEST])
{
    uint8_t full[ATECC_PREHASH_MAX];
    uint32_t len = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    uint32_t i;

    if (algo == NOXTLS_CRYPTO_HASH_PREHASHED) {
        if ((message_len == 0U) || (message_len > ATECC_PREHASH_MAX)) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }

        for (i = 0U; i < message_len; i++) {
            full[i] = message[i];
        }

        len = message_len;
        rc = NOXTLS_RETURN_SUCCESS;
    } else if (algo == (noxtls_crypto_hash_algo_t)NOXTLS_HASH_SHA_256) {
        noxtls_sha_ctx_t ctx;

        rc = noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_sha256_update(&ctx, message, message_len);
        }

        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_sha256_finish(&ctx, full);
        }

        len = ATECC_DIGEST;
    } else if ((algo == (noxtls_crypto_hash_algo_t)NOXTLS_HASH_SHA_384) || (algo == (noxtls_crypto_hash_algo_t)NOXTLS_HASH_SHA_512)) {
        noxtls_sha512_ctx_t ctx;

        rc = noxtls_sha512_init(&ctx, (noxtls_hash_algos_t)algo);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_sha512_update(&ctx, message, message_len);
        }

        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_sha512_finish(&ctx, full);
        }

        len = (algo == (noxtls_crypto_hash_algo_t)NOXTLS_HASH_SHA_384) ? 48U : 64U;
    } else {
        /* SHA-1/224 and MD5 are not used with ECDSA in TLS; software handles them if ever needed. */
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
    }

    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if (len >= ATECC_DIGEST) {
        for (i = 0U; i < ATECC_DIGEST; i++) {
            out[i] = full[i];
        }
    } else {
        for (i = 0U; i < ATECC_DIGEST; i++) {
            out[i] = (i < (ATECC_DIGEST - len)) ? 0U : full[i - (ATECC_DIGEST - len)];
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t atecc_ecdsa_sign(noxtls_crypto_provider_ctx_t prov_ctx, noxtls_crypto_key_handle_t key_handle, const uint8_t *message,
                                        uint32_t message_len, uint8_t *signature_der, uint32_t *signature_der_len, noxtls_crypto_hash_algo_t hash_algo)
{
    const noxtls_atecc608_key_t *key = (const noxtls_atecc608_key_t *)key_handle;
    uint8_t digest[ATECC_DIGEST];
    uint8_t rs[ATECC_POINT];
    noxtls_return_t rc;

    (void)prov_ctx;
    if ((key == NULL) || (key->backend == NULL) || (key->backend->sign_digest == NULL) || (message == NULL) || (signature_der == NULL) ||
        (signature_der_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if (key->key_id > ATECC_SLOT_MAX) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    rc = atecc_digest(message, message_len, hash_algo, digest);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if (key->backend->sign_digest(key->backend->device, (uint8_t)key->key_id, digest, rs) != 0) {
        noxtls_secure_zero(digest, sizeof(digest));
        return NOXTLS_RETURN_FAILED;
    }

    rc = atecc_der_encode(rs, signature_der, signature_der_len);
    noxtls_secure_zero(digest, sizeof(digest));
    return rc;
}

static noxtls_return_t atecc_ecdh_keygen(noxtls_crypto_provider_ctx_t prov_ctx, uint16_t named_group, noxtls_crypto_key_handle_t *key_handle,
                                         uint8_t *public_xy, uint32_t *public_len)
{
    noxtls_atecc608_provider_t *p = (noxtls_atecc608_provider_t *)prov_ctx;
    noxtls_atecc608_key_t *key;

    if ((p == NULL) || (key_handle == NULL) || (public_xy == NULL) || (public_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if ((named_group != ATECC_GROUP_SECP256R1) || (p->ephemeral_count == 0U) || (p->backend == NULL) ||
        (p->backend->ecdh_keygen == NULL)) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    if (*public_len < ATECC_POINT) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    key = &p->ephemeral_keys[p->ephemeral_next];
    key->backend = p->backend;
    key->key_id = p->ephemeral_ids[p->ephemeral_next];
    p->ephemeral_next = (uint8_t)((p->ephemeral_next + 1U) % p->ephemeral_count);
    if (p->backend->ecdh_keygen(p->backend->device, key->key_id, public_xy) != 0) {
        return NOXTLS_RETURN_FAILED;
    }

    *public_len = ATECC_POINT;
    *key_handle = key;
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t atecc_ecdh_shared(noxtls_crypto_provider_ctx_t prov_ctx, noxtls_crypto_key_handle_t key_handle, const uint8_t *peer_xy,
                                         uint32_t peer_len, uint8_t *secret, uint32_t *secret_len)
{
    const noxtls_atecc608_key_t *key = (const noxtls_atecc608_key_t *)key_handle;

    (void)prov_ctx;
    if ((key == NULL) || (key->backend == NULL) || (key->backend->ecdh == NULL) || (peer_xy == NULL) || (secret == NULL) || (secret_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if ((peer_len != ATECC_POINT) || (*secret_len < ATECC_DIGEST)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if (key->backend->ecdh(key->backend->device, key->key_id, peer_xy, secret) != 0) {
        return NOXTLS_RETURN_FAILED;
    }

    *secret_len = ATECC_DIGEST;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_atecc608_provider_init(noxtls_atecc608_provider_t *p, const noxtls_atecc608_backend_t *backend,
                                              const uint16_t *ephemeral_ids, uint8_t ephemeral_count)
{
    uint32_t i;

    if ((p == NULL) || (backend == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if ((ephemeral_count > NOXTLS_ATECC608_EPHEMERAL_MAX) || ((ephemeral_count > 0U) && (ephemeral_ids == NULL))) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    noxtls_secure_zero(p, sizeof(*p));
    p->backend = backend;
    p->ephemeral_count = ephemeral_count;
    for (i = 0U; i < ephemeral_count; i++) {
        p->ephemeral_ids[i] = ephemeral_ids[i];
    }

    p->ops.ecdsa_sign = atecc_ecdsa_sign;
    p->ops.ecdh_keygen = atecc_ecdh_keygen;
    p->ops.ecdh_shared = atecc_ecdh_shared;
    p->provider.ctx = p;
    p->provider.ops = &p->ops;
    return NOXTLS_RETURN_SUCCESS;
}

const noxtls_crypto_provider_t *noxtls_atecc608_provider_get(const noxtls_atecc608_provider_t *p)
{
    return (p != NULL) ? &p->provider : NULL;
}

void noxtls_atecc608_key_init(noxtls_atecc608_key_t *key, const noxtls_atecc608_backend_t *backend, uint16_t key_id)
{
    if (key != NULL) {
        key->backend = backend;
        key->key_id = key_id;
    }
}

noxtls_return_t noxtls_atecc608_bind_ecc_key(const noxtls_atecc608_provider_t *p, const noxtls_atecc608_key_t *key, ecc_key_t *ecc_key)
{
    uint8_t xy[ATECC_POINT];
    noxtls_return_t rc;
    uint32_t i;

    if ((p == NULL) || (key == NULL) || (key->backend == NULL) || (key->backend->get_public_key == NULL) || (ecc_key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if (key->key_id > ATECC_SLOT_MAX) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if (key->backend->get_public_key(key->backend->device, (uint8_t)key->key_id, xy) != 0) {
        return NOXTLS_RETURN_FAILED;
    }

    rc = noxtls_ecc_key_init(ecc_key, NOXTLS_ECC_SECP256R1);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for (i = 0U; i < ATECC_DIGEST; i++) {
        ecc_key->Q.x[i] = xy[i];
        ecc_key->Q.y[i] = xy[ATECC_DIGEST + i];
    }

    ecc_key->Q.size = ATECC_DIGEST;
    rc = noxtls_ecc_opaque_bind(ecc_key, &p->provider, (noxtls_crypto_key_handle_t)(uintptr_t)key);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_ecc_key_free(ecc_key);
    }

    return rc;
}

void noxtls_atecc608_register_ecdhe(const noxtls_atecc608_provider_t *p)
{
    noxtls_ecc_opaque_set_ecdhe_provider((p != NULL) ? &p->provider : NULL);
}

#endif /* NOXTLS_FEATURE_ATECC608 */
