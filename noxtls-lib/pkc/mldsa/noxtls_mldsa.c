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
* File:    noxtls_mldsa.c
* Summary: In-house ML-DSA API boundary and backend skeleton.
*
*
*****************************************************************************/

#include <stdint.h>
#include <stddef.h>

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

/**
 * @brief Get the public key length
 * 
 * @param param The parameter
 * @return The public key length
 */
uint32_t noxtls_mldsa_public_key_len(noxtls_mldsa_param_t param)
{
    mldsa_sizes_t sizes;
    return (mldsa_get_sizes(param, &sizes) == NOXTLS_RETURN_SUCCESS) ? sizes.public_key_len : 0U;
}

/**
 * @brief Get the secret key length
 * 
 * @param param The parameter
 * @return The secret key length
 */
uint32_t noxtls_mldsa_secret_key_len(noxtls_mldsa_param_t param)
{
    mldsa_sizes_t sizes;
    return (mldsa_get_sizes(param, &sizes) == NOXTLS_RETURN_SUCCESS) ? sizes.secret_key_len : 0U;
}

/**
 * @brief Get the signature length
 * 
 * @param param The parameter
 * @return The signature length
 */
uint32_t noxtls_mldsa_signature_len(noxtls_mldsa_param_t param)
{
    mldsa_sizes_t sizes;
    return (mldsa_get_sizes(param, &sizes) == NOXTLS_RETURN_SUCCESS) ? sizes.signature_len : 0U;
}

/**
 * @brief Set the test seed sequence
 * 
 * @param bytes The bytes
 * @param byte_len The length of the bytes
 */
void noxtls_mldsa_set_test_seed_sequence(const uint8_t *bytes, uint32_t byte_len)
{
    (void)bytes;
    (void)byte_len;
}

/**
 * @brief Set the test signing overrides
 * 
 * @param pre The pre
 * @param pre_len The length of the pre
 * @param rnd The rnd
 * @param rnd_len The length of the rnd
 * @param externalmu The externalmu
 */
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

/**
 * @brief Generate a ML-DSA key pair
 * 
 * @param param The parameter
 * @param public_key The public key
 * @param secret_key The secret key
 * @return The return value
 */
noxtls_return_t noxtls_mldsa_keygen(noxtls_mldsa_param_t param, uint8_t *public_key, uint8_t *secret_key)
{
    if(public_key == NULL || secret_key == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(noxtls_mldsa_public_key_len(param) == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    return noxtls_mldsa_backend_keygen(param, public_key, secret_key);
}

/**
 * @brief Sign a message with ML-DSA
 * 
 * @param param The parameter
 * @param secret_key The secret key
 * @param message The message
 * @param message_len The length of the message
 * @param signature The signature
 * @param signature_len The length of the signature 
 * @return The return value
 */
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

    if(noxtls_message == NULL && message_len != 0U) {
        return NOXTLS_RETURN_NULL;
    }

    if(noxtls_mldsa_signature_len(param) == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    return noxtls_mldsa_backend_sign(param, secret_key, noxtls_message, message_len, signature, signature_len);
}

/**
 * @brief Verify a message with ML-DSA
 * 
 * @param param The parameter
 * @param public_key The public key
 * @param message The message
 * @param message_len The length of the message
 * @param signature The signature
 * @param signature_len The length of the signature 
 * @return The return value
 */
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

    if(noxtls_message == NULL && message_len != 0U) {
        return NOXTLS_RETURN_NULL;
    }

    if(noxtls_mldsa_signature_len(param) == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    return noxtls_mldsa_backend_verify(param, public_key, noxtls_message, message_len, signature, signature_len);
}
