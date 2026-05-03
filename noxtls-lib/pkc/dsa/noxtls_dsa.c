/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
*
* File:    noxtls_dsa.c
* Summary: Digital Signature Algorithm (DSA) per FIPS 186-4
*
*/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "noxtls_dsa.h"
#include "pkc/rsa/noxtls_bignum.h"
#include "mdigest/md5/noxtls_md5.h"
#include "mdigest/sha1/noxtls_sha1.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha512/noxtls_sha512.h"
#include "drbg/noxtls_drbg.h"

static noxtls_return_t dsa_hash_message(uint8_t *hash, uint32_t *hash_len, const uint8_t *message, uint32_t message_len, noxtls_hash_algos_t hash_algo)
{
    noxtls_sha_ctx_t ctx;
    noxtls_sha512_ctx_t ctx512;

    if (hash == NULL || hash_len == NULL || message == NULL)
        return NOXTLS_RETURN_NULL;

    switch (hash_algo) {
    case NOXTLS_HASH_MD5:
        if (noxtls_md5_init(&ctx) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (noxtls_md5_update(&ctx, (uint8_t *)message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (noxtls_md5_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        *hash_len = 16;
        break;
    case NOXTLS_HASH_SHA1:
        if (noxtls_sha1_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (noxtls_sha1_update(&ctx, (uint8_t *)message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (noxtls_sha1_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        *hash_len = 20;
        break;
    case NOXTLS_HASH_SHA_224:
    case NOXTLS_HASH_SHA_256:
        if (noxtls_sha256_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (noxtls_sha256_update(&ctx, (uint8_t *)message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (noxtls_sha256_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        *hash_len = (hash_algo == NOXTLS_HASH_SHA_224) ? 28 : 32;
        break;
    case NOXTLS_HASH_SHA_384:
    case NOXTLS_HASH_SHA_512:
        if (noxtls_sha512_init(&ctx512, hash_algo) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (noxtls_sha512_update(&ctx512, (uint8_t *)message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if (noxtls_sha512_finish(&ctx512, hash) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        *hash_len = (hash_algo == NOXTLS_HASH_SHA_384) ? 48 : 64;
        break;
    default:
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_dsa_key_init(dsa_key_t *key, const uint8_t *p, uint32_t p_len, const uint8_t *q, uint32_t q_len, const uint8_t *g, uint32_t g_len)
{
    if (key == NULL || p == NULL || q == NULL || g == NULL)
        return NOXTLS_RETURN_NULL;
    if (p_len == 0 || q_len == 0 || q_len > DSA_MAX_Q_BYTES || p_len > DSA_MAX_P_BYTES || g_len != p_len)
        return NOXTLS_RETURN_FAILED;

    key->p_len = p_len;
    key->q_len = q_len;
    key->p = (uint8_t *)noxtls_calloc(p_len, 1);
    key->q = (uint8_t *)noxtls_calloc(q_len, 1);
    key->g = (uint8_t *)noxtls_calloc(p_len, 1);
    key->y = (uint8_t *)noxtls_calloc(p_len, 1);
    key->x = (uint8_t *)noxtls_calloc(q_len, 1);
    if (key->p == NULL || key->q == NULL || key->g == NULL || key->y == NULL || key->x == NULL) {
        noxtls_dsa_key_free(key);
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(key->p, p, p_len);
    memcpy(key->q, q, q_len);
    memcpy(key->g, g, p_len);
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_dsa_key_set_public(dsa_key_t *key, const uint8_t *y)
{
    if (key == NULL || key->y == NULL || y == NULL)
        return NOXTLS_RETURN_NULL;
    memcpy(key->y, y, key->p_len);
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_dsa_key_set_private(dsa_key_t *key, const uint8_t *x)
{
    if (key == NULL || key->x == NULL || x == NULL)
        return NOXTLS_RETURN_NULL;
    memcpy(key->x, x, key->q_len);
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_dsa_key_generate(dsa_key_t *key)
{
    noxtls_return_t rc;
    drbg_state_t drbg;
    uint8_t *x_buf = NULL;
    uint32_t max_attempts = 100;
    uint32_t attempt;

    if (key == NULL || key->p == NULL || key->q == NULL || key->g == NULL || key->y == NULL || key->x == NULL)
        return NOXTLS_RETURN_NULL;

    x_buf = (uint8_t *)noxtls_calloc(key->q_len, 1);
    if (x_buf == NULL)
        return NOXTLS_RETURN_FAILED;

    rc = drbg_instantiate(&drbg, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_free(x_buf);
        return rc;
    }

    for (attempt = 0; attempt < max_attempts; attempt++) {
        if (drbg_generate(&drbg, x_buf, key->q_len * 8u, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
            noxtls_free(x_buf);
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_bn_mod(key->x, x_buf, key->q_len, key->q, key->q_len);
        if (noxtls_bn_is_zero(key->x, key->q_len))
            key->x[key->q_len - 1] = 1;
        /* y = g^x mod p */
        rc = noxtls_bn_mod_exp(key->y, key->g, key->x, key->q_len, key->p, key->p_len);
        if (rc == NOXTLS_RETURN_SUCCESS)
            break;
    }
    noxtls_free(x_buf);
    return rc;
}

noxtls_return_t noxtls_dsa_key_free(dsa_key_t *key)
{
    if (key == NULL)
        return NOXTLS_RETURN_NULL;
    if (key->p) { noxtls_free(key->p); key->p = NULL; }
    if (key->q) { noxtls_free(key->q); key->q = NULL; }
    if (key->g) { noxtls_free(key->g); key->g = NULL; }
    if (key->y) { noxtls_free(key->y); key->y = NULL; }
    if (key->x) { noxtls_free(key->x); key->x = NULL; }
    key->p_len = 0;
    key->q_len = 0;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_dsa_signature_init(dsa_signature_t *sig, uint32_t q_len)
{
    if (sig == NULL || q_len > DSA_MAX_Q_BYTES)
        return NOXTLS_RETURN_NULL;
    memset(sig->r, 0, DSA_MAX_Q_BYTES);
    memset(sig->s, 0, DSA_MAX_Q_BYTES);
    sig->q_len = q_len;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_dsa_signature_free(dsa_signature_t *sig)
{
    if (sig == NULL)
        return NOXTLS_RETURN_NULL;
    memset(sig->r, 0, DSA_MAX_Q_BYTES);
    memset(sig->s, 0, DSA_MAX_Q_BYTES);
    sig->q_len = 0;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_dsa_sign(const dsa_key_t *key, const uint8_t *message, uint32_t message_len, dsa_signature_t *signature, noxtls_hash_algos_t hash_algo)
{
    noxtls_return_t rc;
    uint8_t *hash = NULL;
    uint32_t hash_len;
    uint8_t *z = NULL;
    uint8_t *k = NULL;
    uint8_t *k_inv = NULL;
    uint8_t *g_k = NULL;
    uint8_t *rx = NULL;
    uint8_t *z_rx = NULL;
    uint8_t *random_bytes = NULL;
    drbg_state_t drbg;
    uint32_t p_len, q_len;
    uint32_t max_attempts = 100;
    uint32_t attempt;

    if (key == NULL || key->x == NULL || message == NULL || signature == NULL)
        return NOXTLS_RETURN_NULL;
    p_len = key->p_len;
    q_len = key->q_len;
    if (q_len > DSA_MAX_Q_BYTES || p_len > DSA_MAX_P_BYTES)
        return NOXTLS_RETURN_FAILED;

    hash = (uint8_t *)noxtls_calloc(64, 1);
    z = (uint8_t *)noxtls_calloc(q_len, 1);
    k = (uint8_t *)noxtls_calloc(q_len, 1);
    k_inv = (uint8_t *)noxtls_calloc(q_len, 1);
    g_k = (uint8_t *)noxtls_calloc(p_len, 1);
    rx = (uint8_t *)noxtls_calloc(q_len * 2, 1);
    z_rx = (uint8_t *)noxtls_calloc(q_len + 1, 1);
    random_bytes = (uint8_t *)noxtls_calloc(q_len, 1);
    if (!hash || !z || !k || !k_inv || !g_k || !rx || !z_rx || !random_bytes) {
        rc = NOXTLS_RETURN_FAILED;
        goto cleanup;
    }

    rc = dsa_hash_message(hash, &hash_len, message, message_len, hash_algo);
    if (rc != NOXTLS_RETURN_SUCCESS)
        goto cleanup;
    /* z = leftmost min(q_len, hash_len) bytes of hash; if hash_len < q_len, pad with zeros on left */
    if (hash_len >= q_len)
        memcpy(z, hash, q_len);
    else {
        memcpy(z + q_len - hash_len, hash, hash_len);
    }
    /* Reduce z mod q if z >= q (FIPS 186-4: z may be truncated to N bits; we use bytes) */
    if (noxtls_bn_cmp(z, key->q, q_len) >= 0)
        noxtls_bn_mod(z, z, q_len, key->q, q_len);

    rc = drbg_instantiate(&drbg, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0);
    if (rc != NOXTLS_RETURN_SUCCESS)
        goto cleanup;

    for (attempt = 0; attempt < max_attempts; attempt++) {
        if (drbg_generate(&drbg, random_bytes, q_len * 8u, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_FAILED;
            goto cleanup;
        }
        noxtls_bn_mod(k, random_bytes, q_len, key->q, q_len);
        if (noxtls_bn_is_zero(k, q_len))
            k[q_len - 1] = 1;

        /* r = (g^k mod p) mod q */
        if (noxtls_bn_mod_exp(g_k, key->g, k, q_len, key->p, p_len) != NOXTLS_RETURN_SUCCESS)
            continue;
        noxtls_bn_mod(signature->r, g_k, p_len, key->q, q_len);
        if (noxtls_bn_is_zero(signature->r, q_len))
            continue;

        /* s = k^(-1) * (z + r*x) mod q */
        if (noxtls_bn_mod_inv(k_inv, k, q_len, key->q, q_len) != NOXTLS_RETURN_SUCCESS)
            continue;
        noxtls_bn_mul(rx, signature->r, q_len, key->x, q_len);
        noxtls_bn_mod(rx, rx, q_len * 2, key->q, q_len);
        /* z_rx = z + rx (both q_len; sum may need q_len+1 bytes) */
        {
            uint16_t carry = 0;
            uint32_t i;
            for (i = q_len; i > 0; i--) {
                uint32_t idx = i - 1;
                uint16_t sum = (uint16_t)z[idx] + (uint16_t)rx[idx] + carry;
                z_rx[idx + 1] = (uint8_t)(sum & 0xFF);
                carry = sum >> 8;
            }
            z_rx[0] = (uint8_t)carry;
        }
        {
            uint32_t len = z_rx[0] ? (q_len + 1) : q_len;
            const uint8_t *src = z_rx[0] ? z_rx : (z_rx + 1);
            noxtls_bn_mod(z_rx, src, len, key->q, q_len);
        }
        noxtls_bn_mul(rx, k_inv, q_len, z_rx, q_len);
        noxtls_bn_mod(signature->s, rx, q_len * 2, key->q, q_len);
        if (noxtls_bn_is_zero(signature->s, q_len))
            continue;
        signature->q_len = q_len;
        rc = NOXTLS_RETURN_SUCCESS;
        goto cleanup;
    }
    rc = NOXTLS_RETURN_FAILED;

cleanup:
    if (hash) noxtls_free(hash);
    if (z) noxtls_free(z);
    if (k) noxtls_free(k);
    if (k_inv) noxtls_free(k_inv);
    if (g_k) noxtls_free(g_k);
    if (rx) noxtls_free(rx);
    if (z_rx) noxtls_free(z_rx);
    if (random_bytes) noxtls_free(random_bytes);
    return rc;
}

noxtls_return_t noxtls_dsa_verify(const dsa_key_t *key, const uint8_t *message, uint32_t message_len, const dsa_signature_t *signature, noxtls_hash_algos_t hash_algo)
{
    noxtls_return_t rc;
    uint8_t *hash = NULL;
    uint32_t hash_len;
    uint8_t *z = NULL;
    uint8_t *w = NULL;
    uint8_t *u1 = NULL;
    uint8_t *u2 = NULL;
    uint8_t *g_u1 = NULL;
    uint8_t *y_u2 = NULL;
    uint8_t *v = NULL;
    uint8_t *product = NULL;
    uint32_t p_len, q_len;

    if (key == NULL || key->y == NULL || message == NULL || signature == NULL)
        return NOXTLS_RETURN_NULL;
    p_len = key->p_len;
    q_len = key->q_len;
    if (signature->q_len != q_len || q_len > DSA_MAX_Q_BYTES || p_len > DSA_MAX_P_BYTES)
        return NOXTLS_RETURN_FAILED;

    /* r, s in [1, q-1] */
    if (noxtls_bn_is_zero(signature->r, q_len) || noxtls_bn_cmp(signature->r, key->q, q_len) >= 0)
        return NOXTLS_RETURN_FAILED;
    if (noxtls_bn_is_zero(signature->s, q_len) || noxtls_bn_cmp(signature->s, key->q, q_len) >= 0)
        return NOXTLS_RETURN_FAILED;

    hash = (uint8_t *)noxtls_calloc(64, 1);
    z = (uint8_t *)noxtls_calloc(q_len, 1);
    w = (uint8_t *)noxtls_calloc(q_len, 1);
    u1 = (uint8_t *)noxtls_calloc(q_len * 2, 1);
    u2 = (uint8_t *)noxtls_calloc(q_len * 2, 1);
    g_u1 = (uint8_t *)noxtls_calloc(p_len, 1);
    y_u2 = (uint8_t *)noxtls_calloc(p_len, 1);
    v = (uint8_t *)noxtls_calloc(q_len, 1);
    product = (uint8_t *)noxtls_calloc(p_len * 2, 1);
    if (!hash || !z || !w || !u1 || !u2 || !g_u1 || !y_u2 || !v || !product) {
        rc = NOXTLS_RETURN_FAILED;
        goto cleanup;
    }

    rc = dsa_hash_message(hash, &hash_len, message, message_len, hash_algo);
    if (rc != NOXTLS_RETURN_SUCCESS)
        goto cleanup;
    if (hash_len >= q_len)
        memcpy(z, hash, q_len);
    else
        memcpy(z + q_len - hash_len, hash, hash_len);
    if (noxtls_bn_cmp(z, key->q, q_len) >= 0)
        noxtls_bn_mod(z, z, q_len, key->q, q_len);

    if (noxtls_bn_mod_inv(w, signature->s, q_len, key->q, q_len) != NOXTLS_RETURN_SUCCESS) {
        rc = NOXTLS_RETURN_FAILED;
        goto cleanup;
    }
    noxtls_bn_mul(u1, w, q_len, z, q_len);
    noxtls_bn_mod(u1, u1, q_len * 2, key->q, q_len);
    noxtls_bn_mul(u2, w, q_len, signature->r, q_len);
    noxtls_bn_mod(u2, u2, q_len * 2, key->q, q_len);

    if (noxtls_bn_mod_exp(g_u1, key->g, u1, q_len, key->p, p_len) != NOXTLS_RETURN_SUCCESS ||
        noxtls_bn_mod_exp(y_u2, key->y, u2, q_len, key->p, p_len) != NOXTLS_RETURN_SUCCESS) {
        rc = NOXTLS_RETURN_FAILED;
        goto cleanup;
    }
    noxtls_bn_mul(product, g_u1, p_len, y_u2, p_len);
    noxtls_bn_mod(g_u1, product, p_len * 2, key->p, p_len);  /* g_u1 = (g^u1 * y^u2) mod p */
    noxtls_bn_mod(v, g_u1, p_len, key->q, q_len);             /* v = (…) mod q */

    rc = (noxtls_bn_cmp(v, signature->r, q_len) == 0) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;

cleanup:
    if (hash) noxtls_free(hash);
    if (z) noxtls_free(z);
    if (w) noxtls_free(w);
    if (u1) noxtls_free(u1);
    if (u2) noxtls_free(u2);
    if (g_u1) noxtls_free(g_u1);
    if (y_u2) noxtls_free(y_u2);
    if (v) noxtls_free(v);
    if (product) noxtls_free(product);
    return rc;
}
