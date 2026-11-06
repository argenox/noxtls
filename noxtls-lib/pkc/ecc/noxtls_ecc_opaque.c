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
* File:    noxtls_ecc_opaque.c
* Summary: Opaque (provider held) ECC private keys for ECDSA signing and ECDH
*
*****************************************************************************/

#include <stdint.h>

#include "noxtls_ecc_opaque.h"

#if NOXTLS_FEATURE_ATECC608

/** TLS NamedGroup for secp256r1 (RFC 8422), the only group a 64 byte public point is exchanged for here. */
#define OPAQUE_GROUP_SECP256R1 23U
/** Uncompressed P-256 point as X || Y. */
#define OPAQUE_P256_POINT_LEN 64U
/** P-256 coordinate size in bytes. */
#define OPAQUE_P256_COORD 32U
/** Largest ECDSA DER signature for a 66 byte (P-521) curve is below this. */
#define OPAQUE_DER_MAX 160U

typedef struct
{
    const ecc_key_t *key;
    const noxtls_crypto_provider_t *provider;
    noxtls_crypto_key_handle_t handle;
} opaque_entry_t;

static opaque_entry_t g_opaque[NOXTLS_ECC_OPAQUE_MAX];
static const noxtls_crypto_provider_t *g_ecdhe_provider;

static opaque_entry_t *opaque_find(const ecc_key_t *key)
{
    uint32_t i;

    if (key == NULL) {
        return NULL;
    }

    for (i = 0U; i < NOXTLS_ECC_OPAQUE_MAX; i++) {
        if (g_opaque[i].key == key) {
            return &g_opaque[i];
        }
    }

    return NULL;
}

noxtls_return_t noxtls_ecc_opaque_bind(const ecc_key_t *key, const noxtls_crypto_provider_t *provider, noxtls_crypto_key_handle_t handle)
{
    opaque_entry_t *e;
    uint32_t i;

    if ((key == NULL) || (provider == NULL) || (provider->ops == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    e = opaque_find(key);
    if (e == NULL) {
        for (i = 0U; i < NOXTLS_ECC_OPAQUE_MAX; i++) {
            if (g_opaque[i].key == NULL) {
                e = &g_opaque[i];
                break;
            }
        }
    }

    if (e == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    e->key = key;
    e->provider = provider;
    e->handle = handle;
    return NOXTLS_RETURN_SUCCESS;
}

void noxtls_ecc_opaque_unbind(const ecc_key_t *key)
{
    opaque_entry_t *e = opaque_find(key);

    if (e != NULL) {
        e->key = NULL;
        e->provider = NULL;
        e->handle = NULL;
    }
}

int noxtls_ecc_opaque_is_bound(const ecc_key_t *key)
{
    return (opaque_find(key) != NULL) ? 1 : 0;
}

noxtls_return_t noxtls_ecc_opaque_ecdsa_sign(const ecc_key_t *key, const uint8_t *message, uint32_t message_len, ecdsa_signature_t *signature, uint32_t hash_algo)
{
    const opaque_entry_t *e = opaque_find(key);
    uint8_t der[OPAQUE_DER_MAX];
    uint32_t der_len = (uint32_t)sizeof(der);
    noxtls_return_t rc;

    if ((e == NULL) || (e->provider->ops->ecdsa_sign == NULL)) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    if ((message == NULL) || (signature == NULL) || (key->curve == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    rc = e->provider->ops->ecdsa_sign(e->provider->ctx, e->handle, message, message_len, der, &der_len,
                                      (noxtls_crypto_hash_algo_t)hash_algo);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = noxtls_ecdsa_signature_init(signature, key->curve->size);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    return noxtls_ecdsa_signature_parse_der(der, der_len, signature, key->curve->size);
}

noxtls_return_t noxtls_ecc_opaque_ecdh(const ecc_key_t *key, const ecc_point_t *peer, uint8_t *secret, uint32_t *secret_len)
{
    const opaque_entry_t *e = opaque_find(key);
    uint8_t xy[2U * ECC_MAX_KEY_SIZE];
    uint32_t size;
    uint32_t i;

    if ((e == NULL) || (e->provider->ops->ecdh_shared == NULL)) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    if ((peer == NULL) || (secret == NULL) || (secret_len == NULL) || (key->curve == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    size = key->curve->size;
    if ((size == 0U) || (size > ECC_MAX_KEY_SIZE) || (peer->size != size)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    for (i = 0U; i < size; i++) {
        xy[i] = peer->x[i];
        xy[size + i] = peer->y[i];
    }

    return e->provider->ops->ecdh_shared(e->provider->ctx, e->handle, xy, 2U * size, secret, secret_len);
}

void noxtls_ecc_opaque_set_ecdhe_provider(const noxtls_crypto_provider_t *provider)
{
    g_ecdhe_provider = provider;
}

noxtls_return_t noxtls_ecc_opaque_ecdhe_generate(ecc_key_t *key, uint16_t named_group)
{
    uint8_t xy[OPAQUE_P256_POINT_LEN];
    uint32_t xy_len = (uint32_t)sizeof(xy);
    noxtls_crypto_key_handle_t handle = NULL;
    noxtls_return_t rc;
    uint32_t i;

    if ((g_ecdhe_provider == NULL) || (g_ecdhe_provider->ops == NULL) || (g_ecdhe_provider->ops->ecdh_keygen == NULL) ||
        (g_ecdhe_provider->ops->ecdh_shared == NULL) || (named_group != OPAQUE_GROUP_SECP256R1)) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    if ((key == NULL) || (key->curve == NULL) || (key->curve->size != OPAQUE_P256_COORD)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    rc = g_ecdhe_provider->ops->ecdh_keygen(g_ecdhe_provider->ctx, named_group, &handle, xy, &xy_len);
    if ((rc != NOXTLS_RETURN_SUCCESS) || (xy_len != OPAQUE_P256_POINT_LEN)) {
        return (rc != NOXTLS_RETURN_SUCCESS) ? rc : NOXTLS_RETURN_FAILED;
    }

    for (i = 0U; i < OPAQUE_P256_COORD; i++) {
        key->Q.x[i] = xy[i];
        key->Q.y[i] = xy[OPAQUE_P256_COORD + i];
    }

    key->Q.size = OPAQUE_P256_COORD;
    return noxtls_ecc_opaque_bind(key, g_ecdhe_provider, handle);
}

#endif /* NOXTLS_FEATURE_ATECC608 */
