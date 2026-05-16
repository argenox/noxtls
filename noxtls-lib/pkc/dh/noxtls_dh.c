/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
*
* File:    noxtls_dh.c
* Summary: Finite-field Diffie-Hellman (FFDHE) per RFC 7919
*/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "noxtls_dh.h"
#include "noxtls_ffdhe_params.h"
#include "noxtls_tls_common.h"
#include "pkc/rsa/noxtls_bignum.h"
#include "drbg/noxtls_drbg.h"
#include "common/noxtls_ct.h"
#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"

/**
 * @brief Returns 1 if modulus matches a built-in RFC 7919 safe-prime group.
 *
 * @param[in] p Prime modulus bytes.
 * @param[in] p_len Length of modulus in bytes.
 * @return 1 when @p p is a known FFDHE prime; otherwise 0.
 */
static int dh_is_known_ffdhe_prime(const uint8_t *p, uint32_t p_len)
{
    if(p == NULL) {
        return 0;
    }
    if(p_len == NOXTLS_FFDHE2048_P_BYTES &&
       noxtls_secret_memcmp(p, noxtls_ffdhe2048_p, p_len) == 0) {
        return 1;
    }
    if(p_len == NOXTLS_FFDHE3072_P_BYTES &&
       noxtls_secret_memcmp(p, noxtls_ffdhe3072_p, p_len) == 0) {
        return 1;
    }
    if(p_len == NOXTLS_FFDHE4096_P_BYTES &&
       noxtls_secret_memcmp(p, noxtls_ffdhe4096_p, p_len) == 0) {
        return 1;
    }
    if(p_len == NOXTLS_FFDHE6144_P_BYTES &&
       noxtls_secret_memcmp(p, noxtls_ffdhe6144_p, p_len) == 0) {
        return 1;
    }
    if(p_len == NOXTLS_FFDHE8192_P_BYTES &&
       noxtls_secret_memcmp(p, noxtls_ffdhe8192_p, p_len) == 0) {
        return 1;
    }
    return 0;
}

/**
 * @brief Validates a DH peer public value for FFDHE key agreement.
 *
 * @param[in] peer_mod Peer public value padded to @p p_len bytes.
 * @param[in] p Prime modulus.
 * @param[in] p_len Length of modulus in bytes.
 * @return NOXTLS_RETURN_SUCCESS when peer value is acceptable; otherwise failure.
 */
static noxtls_return_t dh_validate_peer_public(const uint8_t *peer_mod,
                                               const uint8_t *p,
                                               uint32_t p_len)
{
    uint8_t *two;
    uint8_t *p_minus_2;
    noxtls_return_t rc;

    two = NULL;
    p_minus_2 = NULL;

    if(peer_mod == NULL || p == NULL || p_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    two = (uint8_t*)noxtls_calloc(p_len, 1);
    p_minus_2 = (uint8_t*)noxtls_calloc(p_len, 1);
    if(two == NULL || p_minus_2 == NULL) {
        if(two) {
            noxtls_free(two);
        }
        if(p_minus_2) {
            noxtls_free(p_minus_2);
        }
        return NOXTLS_RETURN_FAILED;
    }

    two[p_len - 1u] = 0x02u;

    rc = noxtls_bn_copy(p_minus_2, p, p_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_free(two);
        noxtls_free(p_minus_2);
        return rc;
    }
    rc = noxtls_bn_sub(p_minus_2, p_minus_2, two, p_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_free(two);
        noxtls_free(p_minus_2);
        return rc;
    }

    if(noxtls_bn_cmp(peer_mod, two, p_len) < 0 || noxtls_bn_cmp(peer_mod, p_minus_2, p_len) > 0) {
        noxtls_free(two);
        noxtls_free(p_minus_2);
        return NOXTLS_RETURN_FAILED;
    }

    noxtls_free(two);
    noxtls_free(p_minus_2);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * RFC 7919 Table 2 — minimum recommended private exponent length (bits) per group.
 */
static uint32_t dh_ffdhe_min_private_bits(uint16_t named_group)
{
    switch(named_group) {
        case TLS_NAMED_GROUP_FFDHE2048:
            return NOXTLS_FFDHE2048_MIN_PRIVATE_BITS;
        case TLS_NAMED_GROUP_FFDHE3072:
            return NOXTLS_FFDHE3072_MIN_PRIVATE_BITS;
        case TLS_NAMED_GROUP_FFDHE4096:
            return NOXTLS_FFDHE4096_MIN_PRIVATE_BITS;
        case TLS_NAMED_GROUP_FFDHE6144:
            return NOXTLS_FFDHE6144_MIN_PRIVATE_BITS;
        case TLS_NAMED_GROUP_FFDHE8192:
            return NOXTLS_FFDHE8192_MIN_PRIVATE_BITS;
        default:
            return 0u;
    }
}

noxtls_return_t noxtls_dh_ffdhe_generate_ephemeral(uint16_t named_group,
                                                   uint8_t *private_out,
                                                   uint8_t *public_out)
{
    const uint8_t *p = NULL;
    const uint8_t *g = NULL;
    uint32_t p_len = 0;
    uint32_t min_bits;
    uint32_t exp_bytes;
    drbg_state_t drbg;
    uint8_t *p_minus_2 = NULL;
    uint8_t *g_padded = NULL;
    noxtls_return_t rc;

    if(private_out == NULL || public_out == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    min_bits = dh_ffdhe_min_private_bits(named_group);
    if(min_bits == 0u ||
       noxtls_dh_ffdhe_params(named_group, &p, &g, &p_len) != NOXTLS_RETURN_SUCCESS ||
       p_len == 0 ||
       !dh_is_known_ffdhe_prime(p, p_len)) {
        return NOXTLS_RETURN_FAILED;
    }
    exp_bytes = (min_bits + 7u) / 8u;
    if(exp_bytes == 0u || exp_bytes > p_len) {
        return NOXTLS_RETURN_FAILED;
    }

    memset(private_out, 0, p_len);
    memset(public_out, 0, p_len);

    p_minus_2 = (uint8_t*)noxtls_calloc(p_len, 1);
    g_padded = (uint8_t*)noxtls_calloc(p_len, 1);
    if(p_minus_2 == NULL || g_padded == NULL) {
        if(p_minus_2) {
            noxtls_free(p_minus_2);
        }
        if(g_padded) {
            noxtls_free(g_padded);
        }
        return NOXTLS_RETURN_FAILED;
    }
    {
        uint8_t *two_buf = (uint8_t*)noxtls_calloc(p_len, 1);
        if(two_buf == NULL) {
            noxtls_free(p_minus_2);
            noxtls_free(g_padded);
            return NOXTLS_RETURN_FAILED;
        }
        two_buf[p_len - 1u] = 0x02u;
        noxtls_bn_copy(p_minus_2, p, p_len);
        rc = noxtls_bn_sub(p_minus_2, p_minus_2, two_buf, p_len);
        noxtls_free(two_buf);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_free(p_minus_2);
        noxtls_free(g_padded);
        return rc;
    }

    if(drbg_instantiate(&drbg, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        noxtls_free(p_minus_2);
        noxtls_free(g_padded);
        return NOXTLS_RETURN_FAILED;
    }

    for(;;) {
        if(drbg_generate(&drbg, private_out + (p_len - exp_bytes), exp_bytes * 8u, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
            noxtls_free(p_minus_2);
            noxtls_free(g_padded);
            return NOXTLS_RETURN_FAILED;
        }
        if((min_bits % 8u) != 0u) {
            private_out[p_len - 1u] &= (uint8_t)((1u << (min_bits % 8u)) - 1u);
        }
        /* Ensure >= 2 */
        if(noxtls_bn_is_zero(private_out, p_len) || noxtls_bn_is_one(private_out, p_len)) {
            private_out[p_len - 1u] = 0x02u;
        }
        if(noxtls_bn_cmp(private_out, p_minus_2, p_len) <= 0) {
            break;
        }
    }

    memset(g_padded, 0, p_len);
    memcpy(g_padded, g, p_len);

    rc = noxtls_bn_mod_exp(public_out, g_padded, private_out, p_len, p, p_len);
    noxtls_free(p_minus_2);
    noxtls_free(g_padded);
    return rc;
}

noxtls_return_t noxtls_dh_ffdhe_validate_client_key_share(uint16_t named_group,
                                                        const uint8_t *key_exchange,
                                                        uint32_t key_exchange_len)
{
    const uint8_t *p = NULL;
    const uint8_t *g = NULL;
    uint32_t p_len = 0;
    uint8_t *peer_mod = NULL;
    noxtls_return_t rc;

    if(key_exchange_len > 0 && key_exchange == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(noxtls_dh_ffdhe_params(named_group, &p, &g, &p_len) != NOXTLS_RETURN_SUCCESS || p_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }
    if(key_exchange_len != p_len || key_exchange == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    peer_mod = (uint8_t*)noxtls_calloc(p_len, 1);
    if(peer_mod == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(peer_mod, key_exchange, p_len);
    rc = dh_validate_peer_public(peer_mod, p, p_len);
    noxtls_free(peer_mod);
    return rc;
}

noxtls_return_t noxtls_dh_ffdhe_params(uint16_t named_group,
                                        const uint8_t **p,
                                        const uint8_t **g,
                                        uint32_t *p_len)
{
    if(p == NULL || g == NULL || p_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    switch(named_group) {
        case TLS_NAMED_GROUP_FFDHE2048:
            *p = noxtls_ffdhe2048_p;
            *g = noxtls_ffdhe_g_2048;
            *p_len = NOXTLS_FFDHE2048_P_BYTES;
            return NOXTLS_RETURN_SUCCESS;
        case TLS_NAMED_GROUP_FFDHE3072:
            *p = noxtls_ffdhe3072_p;
            *g = noxtls_ffdhe_g_3072;
            *p_len = NOXTLS_FFDHE3072_P_BYTES;
            return NOXTLS_RETURN_SUCCESS;
        case TLS_NAMED_GROUP_FFDHE4096:
            *p = noxtls_ffdhe4096_p;
            *g = noxtls_ffdhe_g_4096;
            *p_len = NOXTLS_FFDHE4096_P_BYTES;
            return NOXTLS_RETURN_SUCCESS;
        case TLS_NAMED_GROUP_FFDHE6144:
            *p = noxtls_ffdhe6144_p;
            *g = noxtls_ffdhe_g_6144;
            *p_len = NOXTLS_FFDHE6144_P_BYTES;
            return NOXTLS_RETURN_SUCCESS;
        case TLS_NAMED_GROUP_FFDHE8192:
            *p = noxtls_ffdhe8192_p;
            *g = noxtls_ffdhe_g_8192;
            *p_len = NOXTLS_FFDHE8192_P_BYTES;
            return NOXTLS_RETURN_SUCCESS;
        default:
            return NOXTLS_RETURN_FAILED;
    }
}

/**
 * @brief Generate an ephemeral finite-field DH key pair: private in [2, p-2], public = g^private mod p.
 *
 * @param[in] p Prime modulus p (big-endian, p_len bytes).
 * @param[in] p_len Length of p in bytes; must be positive.
 * @param[in] g Generator g (big-endian, g_len bytes; commonly 2, zero-padded to p_len internally).
 * @param[in] g_len Length of g in bytes; must be positive.
 * @param[out] private_out Private exponent (p_len bytes), suitable for noxtls_dh_shared_secret().
 * @param[out] public_out Public value g^private mod p (p_len bytes, big-endian).
 *
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if p, g, private_out, or public_out is NULL.
 * @return NOXTLS_RETURN_FAILED if p_len or g_len is zero, memory allocation fails, or DRBG setup fails.
 * @return Other noxtls_return_t values propagated from bignum or DRBG operations on failure.
 */
noxtls_return_t noxtls_dh_generate_key(const uint8_t *p, uint32_t p_len,
                                        const uint8_t *g, uint32_t g_len,
                                        uint8_t *private_out,
                                        uint8_t *public_out)
{
    noxtls_return_t rc;
    drbg_state_t drbg;
    uint8_t *p_minus_2 = NULL;
    uint8_t *priv_buf = NULL;
    uint8_t *g_padded = NULL;
    int cmp;

    if(p == NULL || g == NULL || private_out == NULL || public_out == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(p_len == 0 || g_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    if(p_len > (uint32_t)(UINT32_MAX / 8u)) {
        return NOXTLS_RETURN_FAILED;
    }

    /* p-2 for range [2, p-2] */
    p_minus_2 = (uint8_t*)noxtls_calloc(p_len, 1);
    priv_buf = (uint8_t*)noxtls_calloc(p_len, 1);
    g_padded = (uint8_t*)noxtls_calloc(p_len, 1);
    if(p_minus_2 == NULL || priv_buf == NULL || g_padded == NULL) {
        if(p_minus_2) noxtls_free(p_minus_2);
        if(priv_buf) noxtls_free(priv_buf);
        if(g_padded) noxtls_free(g_padded);
        return NOXTLS_RETURN_FAILED;
    }

    /* p_minus_2 = p - 2 (bignum sub uses same len for all operands) */
    {
        uint8_t *two_buf = (uint8_t*)noxtls_calloc(p_len, 1);
        if(two_buf == NULL) {
            noxtls_free(p_minus_2);
            noxtls_free(priv_buf);
            noxtls_free(g_padded);
            return NOXTLS_RETURN_FAILED;
        }
        two_buf[p_len - 1] = 0x02;
        noxtls_bn_copy(p_minus_2, p, p_len);
        rc = noxtls_bn_sub(p_minus_2, p_minus_2, two_buf, p_len);
        noxtls_free(two_buf);
    }

    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_free(p_minus_2);
        noxtls_free(priv_buf);
        noxtls_free(g_padded);
        return rc;
    }

    if(drbg_instantiate(&drbg, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
        noxtls_free(p_minus_2);
        noxtls_free(priv_buf);
        noxtls_free(g_padded);
        return NOXTLS_RETURN_FAILED;
    }

    /* Generate private in [2, p-2]: generate random of p_len bytes, reduce mod (p-2-2+1) = (p-3), then +2.
     * Simpler: generate random p_len bytes until 2 <= x <= p-2.
     */
    for(;;) {
        if(drbg_generate(&drbg, priv_buf, p_len * 8u, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
            noxtls_free(p_minus_2);
            noxtls_free(priv_buf);
            noxtls_free(g_padded);
            return NOXTLS_RETURN_FAILED;
        }
        /* Ensure we're not 0 or 1: set top bits so value is large */
        priv_buf[0] |= 0x80;
        /* Compare priv_buf with p_minus_2 (both p_len). If priv_buf > p_minus_2, regenerate. */
        cmp = noxtls_bn_cmp(priv_buf, p_minus_2, p_len);
        if(cmp <= 0) {
            break;
        }
    }

    /* Ensure at least 2 (in case we got 0 or 1) */
    if(noxtls_bn_is_zero(priv_buf, p_len) || noxtls_bn_is_one(priv_buf, p_len)) {
        priv_buf[p_len - 1] = 0x02;
    }

    memcpy(private_out, priv_buf, p_len);
    /* g_padded: g is 2, so p_len-1 zero bytes then 0x02 */
    memset(g_padded, 0, p_len);
    g_padded[p_len - 1] = 0x02;

    if(g_len < p_len) {
        memcpy(g_padded + (p_len - g_len), g, g_len);
    } else {
        memcpy(g_padded, g, p_len);
    }

    rc = noxtls_bn_mod_exp(public_out, g_padded, private_out, p_len, p, p_len);
    noxtls_free(p_minus_2);
    noxtls_free(priv_buf);
    noxtls_free(g_padded);
    return rc;
}

/**
 * @brief Compute the shared secret Z = peer_public^private_key mod p.
 *
 * @param[in] private_key Local private exponent (private_len bytes, big-endian).
 * @param[in] private_len Length of private_key in bytes.
 * @param[in] peer_public Peer's public DH value (peer_len bytes, big-endian).
 * @param[in] peer_len Length of peer_public in bytes; if greater than p_len, only the low p_len bytes are used.
 * @param[in] p Prime modulus (p_len bytes, big-endian).
 * @param[in] p_len Length of p in bytes; must be positive.
 * @param[out] secret_out Shared secret (p_len bytes, big-endian); caller must provide p_len bytes.
 *
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if private_key, peer_public, p, or secret_out is NULL.
 * @return NOXTLS_RETURN_FAILED if p_len is zero or a temporary buffer cannot be allocated.
 * @return Other noxtls_return_t values propagated from modular exponentiation on failure.
 */
noxtls_return_t noxtls_dh_shared_secret(const uint8_t *private_key,
                                         uint32_t private_len,
                                         const uint8_t *peer_public,
                                         uint32_t peer_len,
                                         const uint8_t *p,
                                         uint32_t p_len,
                                         uint8_t *secret_out)
{
    uint8_t *peer_mod = NULL;
    noxtls_return_t rc;

    if(private_key == NULL || peer_public == NULL || p == NULL || secret_out == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(p_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    if(private_len == 0) {
        return NOXTLS_RETURN_FAILED;
    }

    if(peer_len > p_len) {
        peer_len = p_len;
    }

    peer_mod = (uint8_t*)noxtls_calloc(p_len, 1);
    if(peer_mod == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    memcpy(peer_mod + (p_len - peer_len), peer_public, peer_len);
    rc = dh_validate_peer_public(peer_mod, p, p_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_free(peer_mod);
        return NOXTLS_RETURN_FAILED;
    }
    rc = noxtls_bn_mod_exp(secret_out, peer_mod, private_key, private_len, p, p_len);
    noxtls_free(peer_mod);
    return rc;
}
