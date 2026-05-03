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
#include "pkc/rsa/noxtls_bignum.h"
#include "drbg/noxtls_drbg.h"
#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"

noxtls_return_t noxtls_dh_ffdhe_params(uint16_t named_group,
                                        const uint8_t **p,
                                        const uint8_t **g,
                                        uint32_t *p_len)
{
    if(p == NULL || g == NULL || p_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    switch(named_group) {
        case 256: /* ffdhe2048 */
            *p = noxtls_ffdhe2048_p;
            *g = noxtls_ffdhe_g_2048;
            *p_len = NOXTLS_FFDHE2048_P_BYTES;
            return NOXTLS_RETURN_SUCCESS;
        case 257: /* ffdhe3072 */
            *p = noxtls_ffdhe3072_p;
            *g = noxtls_ffdhe_g_3072;
            *p_len = NOXTLS_FFDHE3072_P_BYTES;
            return NOXTLS_RETURN_SUCCESS;
        case 258: /* ffdhe4096 */
            *p = noxtls_ffdhe4096_p;
            *g = noxtls_ffdhe_g_4096;
            *p_len = NOXTLS_FFDHE4096_P_BYTES;
            return NOXTLS_RETURN_SUCCESS;
        default:
            return NOXTLS_RETURN_FAILED;
    }
}

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
    if(peer_len > p_len) {
        peer_len = p_len;
    }
    peer_mod = (uint8_t*)noxtls_calloc(p_len, 1);
    if(peer_mod == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(peer_mod + (p_len - peer_len), peer_public, peer_len);
    rc = noxtls_bn_mod_exp(secret_out, peer_mod, private_key, private_len, p, p_len);
    noxtls_free(peer_mod);
    return rc;
}
