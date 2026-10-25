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
* File:    noxtls_falcon.c
* Summary: Falcon/FN-DSA API boundary (key generation, padded-format signing
*          and verification) with per-call workspaces.
*
*****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "noxtls_common.h"

#if NOXTLS_FEATURE_FALCON

#include "common/noxtls_memory.h"
#include "drbg/noxtls_drbg.h"
#include "mdigest/sha3/noxtls_sha3.h"
#include "noxtls_falcon.h"
#include "noxtls_falcon_internal.h"
#include "noxtls_ct.h"

/** Maximum number of NTRUGen candidates per key-generation call. */
#define NOXTLS_FALCON_KEYGEN_MAX_ATTEMPTS 4096U
/** Maximum number of fresh-salt signing attempts. */
#define NOXTLS_FALCON_SIGN_MAX_ATTEMPTS 64U
/** Alignment slack added to every public workspace size. */
#define NOXTLS_FALCON_WS_ALIGN 8U

/** Resolved workspace: aligned base plus the allocation to release (if any). */
typedef struct
{
    uint8_t *base;
    void *owned;
    uint32_t owned_len;
} falcon_ws_t;

static noxtls_return_t falcon_ws_acquire(falcon_ws_t *w, void *user, uint32_t user_len,
                                         uint32_t need)
{
    uintptr_t p = 0U;
    uint32_t total = need + NOXTLS_FALCON_WS_ALIGN;

    w->owned = NULL;
    w->owned_len = 0U;
    if(user == NULL) {
        w->owned = NOXTLS_MALLOC((size_t)total);
        if(w->owned == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        w->owned_len = total;
        user = w->owned;
        user_len = total;
    }
    if(user_len < total) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }
    p = (uintptr_t)user;
    p = (p + (uintptr_t)(NOXTLS_FALCON_WS_ALIGN - 1U)) & ~(uintptr_t)(NOXTLS_FALCON_WS_ALIGN - 1U);
    w->base = (uint8_t *)p;
    return NOXTLS_RETURN_SUCCESS;
}

static void falcon_ws_release(falcon_ws_t *w, uint32_t need)
{
    if(w->base != NULL) {
        noxtls_secure_zero(w->base, (size_t)need);
    }
    if(w->owned != NULL) {
        NOXTLS_SECURE_FREE(w->owned, (size_t)w->owned_len);
    }
    w->base = NULL;
}

static uint32_t falcon_keygen_need(const noxtls_falcon_param_spec_t *spec)
{
    return noxtls_falcon_internal_keygen_ws_len(spec->logn) + (6U * (uint32_t)spec->n);
}

uint32_t noxtls_falcon_public_key_len(noxtls_falcon_param_t param)
{
    noxtls_falcon_param_spec_t spec;

    return (noxtls_falcon_internal_get_param_spec(param, &spec) == NOXTLS_RETURN_SUCCESS) ? spec.public_key_len : 0U;
}

uint32_t noxtls_falcon_secret_key_len(noxtls_falcon_param_t param)
{
    noxtls_falcon_param_spec_t spec;

    return (noxtls_falcon_internal_get_param_spec(param, &spec) == NOXTLS_RETURN_SUCCESS) ? spec.secret_key_len : 0U;
}

uint32_t noxtls_falcon_signature_len(noxtls_falcon_param_t param)
{
    noxtls_falcon_param_spec_t spec;

    return (noxtls_falcon_internal_get_param_spec(param, &spec) == NOXTLS_RETURN_SUCCESS) ? spec.signature_len : 0U;
}

uint32_t noxtls_falcon_keygen_workspace_len(noxtls_falcon_param_t param)
{
    noxtls_falcon_param_spec_t spec;

    if(noxtls_falcon_internal_get_param_spec(param, &spec) != NOXTLS_RETURN_SUCCESS) {
        return 0U;
    }
    return falcon_keygen_need(&spec) + NOXTLS_FALCON_WS_ALIGN;
}

uint32_t noxtls_falcon_sign_workspace_len(noxtls_falcon_param_t param)
{
    noxtls_falcon_param_spec_t spec;

    if(noxtls_falcon_internal_get_param_spec(param, &spec) != NOXTLS_RETURN_SUCCESS) {
        return 0U;
    }
    return noxtls_falcon_internal_sign_ws_len(spec.logn) + NOXTLS_FALCON_WS_ALIGN;
}

uint32_t noxtls_falcon_verify_workspace_len(noxtls_falcon_param_t param)
{
    noxtls_falcon_param_spec_t spec;

    if(noxtls_falcon_internal_get_param_spec(param, &spec) != NOXTLS_RETURN_SUCCESS) {
        return 0U;
    }
    return noxtls_falcon_internal_verify_ws_len(spec.logn) + NOXTLS_FALCON_WS_ALIGN;
}

noxtls_return_t noxtls_falcon_keygen_ex(noxtls_falcon_param_t param,
                                        uint8_t *public_key,
                                        uint32_t public_key_len,
                                        uint8_t *secret_key,
                                        uint32_t secret_key_len,
                                        void *workspace,
                                        uint32_t workspace_len)
{
    noxtls_falcon_param_spec_t spec;
    noxtls_sha3_ctx_t rng;
    uint8_t seed[NOXTLS_FALCON_KEYGEN_SEED_LEN];
    falcon_ws_t w;
    uint32_t need = 0U;
    uint32_t n = 0U;
    uint32_t attempt = 0U;
    int8_t *f = NULL;
    int8_t *g = NULL;
    int8_t *F = NULL;
    int8_t *G = NULL;
    uint16_t *h = NULL;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((public_key == NULL) || (secret_key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(noxtls_falcon_internal_get_param_spec(param, &spec) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if((public_key_len != spec.public_key_len) || (secret_key_len != spec.secret_key_len)) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }
    need = falcon_keygen_need(&spec);
    w.base = NULL;
    rc = falcon_ws_acquire(&w, workspace, workspace_len, need);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        falcon_ws_release(&w, 0U);
        return rc;
    }
    n = spec.n;
    f = (int8_t *)(void *)&w.base[noxtls_falcon_internal_keygen_ws_len(spec.logn)];
    g = &f[n];
    F = &g[n];
    G = &F[n];
    h = (uint16_t *)(void *)&G[n];

    rc = noxtls_drbg_get_entropy(seed, (uint32_t)sizeof(seed));
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_init(&rng);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_update(&rng, seed, (uint32_t)sizeof(seed));
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_final(&rng);
    }
    noxtls_secure_zero(seed, sizeof(seed));
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = NOXTLS_RETURN_FAILED;
        for(attempt = 0U; attempt < NOXTLS_FALCON_KEYGEN_MAX_ATTEMPTS; attempt += 1U) {
            rc = noxtls_falcon_internal_keygen(&spec, &rng, f, g, F, G, h, w.base,
                                               noxtls_falcon_internal_keygen_ws_len(spec.logn));
            if(rc != NOXTLS_RETURN_FAILED) {
                break;
            }
        }
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_falcon_encode_private_key(&spec, f, g, F, secret_key, secret_key_len);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_falcon_encode_public_key(&spec, h, public_key, public_key_len);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(secret_key, (size_t)secret_key_len);
    }
    noxtls_secure_zero(&rng, sizeof(rng));
    falcon_ws_release(&w, need);
    return rc;
}

noxtls_return_t noxtls_falcon_keygen(noxtls_falcon_param_t param,
                                     uint8_t *public_key,
                                     uint32_t public_key_len,
                                     uint8_t *secret_key,
                                     uint32_t secret_key_len)
{
    return noxtls_falcon_keygen_ex(param, public_key, public_key_len, secret_key, secret_key_len,
                                   NULL, 0U);
}

noxtls_return_t noxtls_falcon_sign_ex(noxtls_falcon_param_t param,
                                      const uint8_t *secret_key,
                                      const uint8_t *message,
                                      uint32_t message_len,
                                      uint8_t *signature,
                                      uint32_t *signature_len,
                                      void *workspace,
                                      uint32_t workspace_len)
{
    noxtls_falcon_param_spec_t spec;
    noxtls_sha3_ctx_t rng;
    uint8_t entropy[NOXTLS_FALCON_SALT_LEN + NOXTLS_FALCON_SIGN_SEED_LEN];
    falcon_ws_t w;
    uint32_t need = 0U;
    uint32_t n = 0U;
    uint32_t attempt = 0U;
    uint32_t used = 0U;
    int8_t *f = NULL;
    int8_t *g = NULL;
    int8_t *F = NULL;
    int8_t *G = NULL;
    uint16_t *hm = NULL;
    int16_t *s2 = NULL;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((secret_key == NULL) || (signature == NULL) || (signature_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if((message == NULL) && (message_len != 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    if(noxtls_falcon_internal_get_param_spec(param, &spec) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(*signature_len < spec.signature_len) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }
    need = noxtls_falcon_internal_sign_ws_len(spec.logn);
    w.base = NULL;
    rc = falcon_ws_acquire(&w, workspace, workspace_len, need);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        falcon_ws_release(&w, 0U);
        return rc;
    }
    n = spec.n;
    f = (int8_t *)(void *)&w.base[72U * n];
    g = &f[n];
    F = &g[n];
    G = &F[n];
    hm = (uint16_t *)(void *)&w.base[76U * n];
    s2 = (int16_t *)(void *)&w.base[78U * n];

    rc = noxtls_falcon_decode_private_key(&spec, secret_key, spec.secret_key_len, f, g, F);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_falcon_internal_complete_private(&spec, f, g, F, G, (uint16_t *)(void *)w.base);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        rc = NOXTLS_RETURN_BAD_DATA;
    }
    for(attempt = 0U; (rc == NOXTLS_RETURN_SUCCESS) && (attempt < NOXTLS_FALCON_SIGN_MAX_ATTEMPTS);
        attempt += 1U) {
        rc = noxtls_drbg_get_entropy(entropy, (uint32_t)sizeof(entropy));
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_falcon_hash_to_point(entropy, message, message_len, hm, n);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_shake256_init(&rng);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_shake256_update(&rng, &entropy[NOXTLS_FALCON_SALT_LEN], NOXTLS_FALCON_SIGN_SEED_LEN);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_shake256_final(&rng);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_falcon_internal_sign_dyn(&spec, &rng, f, g, F, G, hm, s2, w.base);
            if(rc == NOXTLS_RETURN_FAILED) {
                rc = NOXTLS_RETURN_SUCCESS;
                continue;
            }
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            signature[0] = (uint8_t)(NOXTLS_FALCON_SIG_COMP_HDR | spec.logn);
            (void)memcpy(&signature[1U], entropy, (size_t)NOXTLS_FALCON_SALT_LEN);
            rc = noxtls_falcon_comp_encode(s2, n, &signature[1U + NOXTLS_FALCON_SALT_LEN],
                                           spec.signature_len - 1U - NOXTLS_FALCON_SALT_LEN, &used);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                *signature_len = spec.signature_len;
                break;
            }
            if(rc == NOXTLS_RETURN_INVALID_BLOCK_SIZE) {
                /* Compressed s2 does not fit the padded format: restart with a new salt. */
                rc = NOXTLS_RETURN_SUCCESS;
            }
        }
    }
    if((rc == NOXTLS_RETURN_SUCCESS) && (attempt >= NOXTLS_FALCON_SIGN_MAX_ATTEMPTS)) {
        rc = NOXTLS_RETURN_FAILED;
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(signature, (size_t)spec.signature_len);
    }
    noxtls_secure_zero(entropy, sizeof(entropy));
    noxtls_secure_zero(&rng, sizeof(rng));
    falcon_ws_release(&w, need);
    return rc;
}

noxtls_return_t noxtls_falcon_sign(noxtls_falcon_param_t param,
                                   const uint8_t *secret_key,
                                   const uint8_t *message,
                                   uint32_t message_len,
                                   uint8_t *signature,
                                   uint32_t *signature_len)
{
    return noxtls_falcon_sign_ex(param, secret_key, message, message_len, signature, signature_len,
                                 NULL, 0U);
}

noxtls_return_t noxtls_falcon_verify_ex(noxtls_falcon_param_t param,
                                        const uint8_t *public_key,
                                        const uint8_t *message,
                                        uint32_t message_len,
                                        const uint8_t *signature,
                                        uint32_t signature_len,
                                        void *workspace,
                                        uint32_t workspace_len)
{
    noxtls_falcon_param_spec_t spec;
    falcon_ws_t w;
    uint32_t need = 0U;
    int16_t *s2 = NULL;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((public_key == NULL) || (signature == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if((message == NULL) && (message_len != 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    if(noxtls_falcon_internal_get_param_spec(param, &spec) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if((signature_len != spec.signature_len) ||
       (signature[0] != (uint8_t)(NOXTLS_FALCON_SIG_COMP_HDR | spec.logn))) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    need = noxtls_falcon_internal_verify_ws_len(spec.logn);
    w.base = NULL;
    rc = falcon_ws_acquire(&w, workspace, workspace_len, need);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        falcon_ws_release(&w, 0U);
        return rc;
    }
    s2 = (int16_t *)(void *)&w.base[4U * (uint32_t)spec.n];
    rc = noxtls_falcon_comp_decode(&signature[1U + NOXTLS_FALCON_SALT_LEN],
                                   signature_len - 1U - NOXTLS_FALCON_SALT_LEN, s2, spec.n);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        rc = NOXTLS_RETURN_BAD_DATA;
    } else {
        rc = noxtls_falcon_internal_verify(&spec, public_key, &signature[1U], message, message_len,
                                           s2, w.base);
    }
    falcon_ws_release(&w, need);
    return rc;
}

noxtls_return_t noxtls_falcon_verify(noxtls_falcon_param_t param,
                                     const uint8_t *public_key,
                                     const uint8_t *message,
                                     uint32_t message_len,
                                     const uint8_t *signature,
                                     uint32_t signature_len)
{
    return noxtls_falcon_verify_ex(param, public_key, message, message_len, signature, signature_len,
                                   NULL, 0U);
}

#else /* !NOXTLS_FEATURE_FALCON */

typedef int noxtls_falcon_unused_t;

#endif /* NOXTLS_FEATURE_FALCON */
