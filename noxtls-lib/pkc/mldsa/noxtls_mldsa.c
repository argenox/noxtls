/****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
*
* File:    noxtls_mldsa.c
* Summary: In-house ML-DSA API boundary and backend skeleton.
*/

#include <stdint.h>

#include "noxtls_mldsa.h"
#include "noxtls_mldsa_internal.h"

/**
 * @brief Resolve fixed key/signature sizes for an ML-DSA parameter set.
 * @param[in] param Parameter set selector (44/65/87).
 * @param[out] sizes Output structure populated on success.
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if sizes is NULL.
 * @return NOXTLS_RETURN_INVALID_PARAM if param is unsupported.
 */
static noxtls_return_t mldsa_get_sizes(noxtls_mldsa_param_t param, mldsa_sizes_t *sizes)
{
    noxtls_mldsa_param_spec_t spec;
    noxtls_return_t rc;

    if(sizes == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_mldsa_internal_get_param_spec(param, &spec);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    sizes->public_key_len = spec.public_key_len;
    sizes->secret_key_len = spec.secret_key_len;
    sizes->signature_len = spec.signature_len;
    return NOXTLS_RETURN_SUCCESS;
}

uint32_t noxtls_mldsa_public_key_len(noxtls_mldsa_param_t param)
{
    mldsa_sizes_t sizes;
    return (mldsa_get_sizes(param, &sizes) == NOXTLS_RETURN_SUCCESS) ? sizes.public_key_len : 0u;
}

uint32_t noxtls_mldsa_secret_key_len(noxtls_mldsa_param_t param)
{
    mldsa_sizes_t sizes;
    return (mldsa_get_sizes(param, &sizes) == NOXTLS_RETURN_SUCCESS) ? sizes.secret_key_len : 0u;
}

uint32_t noxtls_mldsa_signature_len(noxtls_mldsa_param_t param)
{
    mldsa_sizes_t sizes;
    return (mldsa_get_sizes(param, &sizes) == NOXTLS_RETURN_SUCCESS) ? sizes.signature_len : 0u;
}

void noxtls_mldsa_set_test_seed_sequence(const uint8_t *bytes, uint32_t byte_len)
{
    (void)bytes;
    (void)byte_len;
}

void noxtls_mldsa_set_test_signing_overrides(const uint8_t *pre,
                                             uint32_t pre_len,
                                             const uint8_t *rnd,
                                             uint32_t rnd_len,
                                             uint8_t externalmu)
{
    (void)pre;
    (void)pre_len;
    (void)rnd;
    (void)rnd_len;
    (void)externalmu;
}

noxtls_return_t noxtls_mldsa_keygen(noxtls_mldsa_param_t param, uint8_t *public_key, uint8_t *secret_key)
{
    if(public_key == NULL || secret_key == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(noxtls_mldsa_public_key_len(param) == 0u) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    return noxtls_mldsa_backend_keygen(param, public_key, secret_key);
}

noxtls_return_t noxtls_mldsa_sign(noxtls_mldsa_param_t param,
                                  const uint8_t *secret_key,
                                  const uint8_t *noxtls_message,
                                  uint32_t message_len,
                                  uint8_t *signature,
                                  uint32_t *signature_len)
{
    if(secret_key == NULL || signature == NULL || signature_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(noxtls_message == NULL && message_len != 0u) {
        return NOXTLS_RETURN_NULL;
    }

    if(noxtls_mldsa_signature_len(param) == 0u) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    return noxtls_mldsa_backend_sign(param, secret_key, noxtls_message, message_len, signature, signature_len);
}

noxtls_return_t noxtls_mldsa_verify(noxtls_mldsa_param_t param,
                                    const uint8_t *public_key,
                                    const uint8_t *noxtls_message,
                                    uint32_t message_len,
                                    const uint8_t *signature,
                                    uint32_t signature_len)
{
    (void)signature_len;

    if(public_key == NULL || signature == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(noxtls_message == NULL && message_len != 0u) {
        return NOXTLS_RETURN_NULL;
    }

    if(noxtls_mldsa_signature_len(param) == 0u) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    return noxtls_mldsa_backend_verify(param, public_key, noxtls_message, message_len, signature, signature_len);
}
