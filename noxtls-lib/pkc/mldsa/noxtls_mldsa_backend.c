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
* File:    noxtls_mldsa_backend.c
* Summary: ML-DSA backend entry points
*
*
*****************************************************************************/

#include <string.h>

#include "noxtls_mldsa_internal.h"
#include "drbg/noxtls_drbg.h"
#include "mdigest/sha3/noxtls_sha3.h"

static noxtls_return_t mldsa_make_mu(const uint8_t seed[NOXTLS_MLDSA_INTERNAL_SEED_BYTES],
                                     const uint8_t *noxtls_message,
                                     uint32_t message_len,
                                     uint8_t mu[NOXTLS_MLDSA_INTERNAL_SEED_BYTES])
{
    noxtls_sha3_ctx_t shake;
    noxtls_return_t rc;

    rc = noxtls_shake256_init(&shake);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_shake256_update(&shake, seed, NOXTLS_MLDSA_INTERNAL_SEED_BYTES);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(noxtls_message != NULL && message_len > 0U) {
        rc = noxtls_shake256_update(&shake, noxtls_message, message_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    rc = noxtls_shake256_final(&shake);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return noxtls_shake256_squeeze(&shake, mu, NOXTLS_MLDSA_INTERNAL_SEED_BYTES);
}

/**
 * @brief Generate the key pair
 * 
 * @param[in] param The parameter.
 * @param[out] public_key The public key.
 * @param[out] secret_key The secret key.
 * @return The return value.
 */
noxtls_return_t noxtls_mldsa_backend_keygen(noxtls_mldsa_param_t param,
                                            uint8_t *public_key,
                                            uint8_t *secret_key)
{
    noxtls_mldsa_param_spec_t spec;
    uint8_t master_seed[NOXTLS_MLDSA_INTERNAL_SEED_BYTES];
    uint8_t rho[NOXTLS_MLDSA_INTERNAL_SEED_BYTES];
    uint8_t k[NOXTLS_MLDSA_INTERNAL_SEED_BYTES];
    uint8_t tr[NOXTLS_MLDSA_INTERNAL_SEED_BYTES];
    uint8_t seed_blob[3U * NOXTLS_MLDSA_INTERNAL_SEED_BYTES];
    noxtls_mldsa_polyvecl_t s1;
    noxtls_mldsa_polyveck_t t;
    uint32_t pk_tail_len;
    noxtls_return_t rc;
    drbg_state_t drbg;

    if(public_key == NULL || secret_key == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(noxtls_mldsa_internal_get_param_spec(param, &spec) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    rc = drbg_instantiate(&drbg, DRBG_AES256, NULL, 0U, NULL, 0U, NULL, 0U);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = drbg_generate(&drbg,
                       master_seed,
                       NOXTLS_MLDSA_INTERNAL_SEED_BYTES * 8U,
                       NULL,
                       0U);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_mldsa_derive_seeds(master_seed, rho, k, tr);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_mldsa_pack_seeds(seed_blob, (uint32_t)sizeof(seed_blob), rho, k, tr);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_mldsa_sample_polyvecl_eta(param, k, 0U, &s1);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_mldsa_matrix_vector_mul(param, rho, &s1, &t);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    memset(public_key, 0, spec.public_key_len);
    memset(secret_key, 0, spec.secret_key_len);
    memcpy(public_key, rho, NOXTLS_MLDSA_INTERNAL_SEED_BYTES);
    pk_tail_len = (spec.public_key_len > NOXTLS_MLDSA_INTERNAL_SEED_BYTES)
                    ? (spec.public_key_len - NOXTLS_MLDSA_INTERNAL_SEED_BYTES)
                    : 0U;
    if(pk_tail_len > 0U) {
        rc = noxtls_mldsa_expand_xof((const uint8_t *)&t,
                                     (uint32_t)sizeof(t),
                                     0xE1u,
                                     0U,
                                     public_key + NOXTLS_MLDSA_INTERNAL_SEED_BYTES,
                                     pk_tail_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    memcpy(secret_key, seed_blob, (uint32_t)sizeof(seed_blob));
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

/**
 * @brief Sign the message
 * 
 * @param[in] param The parameter.
 * @param[in] secret_key The secret key.
 * @param[in] noxtls_message The message to sign.
 * @param[in] message_len The length of the message.
 * @param[out] signature The signature.
 * @param[out] signature_len The length of the signature.
 * @return The return value.
 */
noxtls_return_t noxtls_mldsa_backend_sign(noxtls_mldsa_param_t param,
                                          const uint8_t *secret_key,
                                          const uint8_t *noxtls_message,
                                          uint32_t message_len,
                                          uint8_t *signature,
                                          uint32_t *signature_len)
{
    noxtls_mldsa_param_spec_t spec;
    noxtls_mldsa_polyvecl_t y;
    noxtls_mldsa_polyveck_t w;
    noxtls_mldsa_poly_t c;
    noxtls_return_t rc;
    uint8_t rho[NOXTLS_MLDSA_INTERNAL_SEED_BYTES];
    uint8_t k[NOXTLS_MLDSA_INTERNAL_SEED_BYTES];
    uint8_t tr[NOXTLS_MLDSA_INTERNAL_SEED_BYTES];
    uint8_t mu[NOXTLS_MLDSA_INTERNAL_SEED_BYTES];

    if(secret_key == NULL || signature == NULL || signature_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(noxtls_mldsa_internal_get_param_spec(param, &spec) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(*signature_len < spec.signature_len) {
        *signature_len = spec.signature_len;
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    rc = noxtls_mldsa_unpack_seeds(secret_key,
                                   3U * NOXTLS_MLDSA_INTERNAL_SEED_BYTES,
                                   rho,
                                   k,
                                   tr);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_mldsa_sample_polyvecl_eta(param, k, 0U, &y);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_mldsa_matrix_vector_mul(param, rho, &y, &w);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = mldsa_make_mu(tr, noxtls_message, message_len, mu);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_mldsa_make_challenge(param, mu, (uint32_t)sizeof(mu), &c);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    (void)w;
    (void)c;

    return NOXTLS_RETURN_NOT_SUPPORTED;
}

/**
 * @brief Verify the message
 * 
 * @param[in] param The parameter.
 * @param[in] public_key The public key.
 * @param[in] noxtls_message The message to verify.
 * @param[in] message_len The length of the message.
 * @param[in] signature The signature to verify.
 * @param[in] signature_len The length of the signature.
 * @return The return value.
 */
noxtls_return_t noxtls_mldsa_backend_verify(noxtls_mldsa_param_t param,
                                            const uint8_t *public_key,
                                            const uint8_t *noxtls_message,
                                            uint32_t message_len,
                                            const uint8_t *signature,
                                            uint32_t signature_len)
{
    noxtls_mldsa_param_spec_t spec;
    noxtls_mldsa_polyvecl_t y;
    noxtls_mldsa_polyveck_t w;
    noxtls_mldsa_poly_t c;
    noxtls_return_t rc;
    uint8_t rho[NOXTLS_MLDSA_INTERNAL_SEED_BYTES];
    uint8_t mu[NOXTLS_MLDSA_INTERNAL_SEED_BYTES];

    if(public_key == NULL || signature == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(noxtls_mldsa_internal_get_param_spec(param, &spec) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(signature_len != spec.signature_len) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    memcpy(rho, public_key, NOXTLS_MLDSA_INTERNAL_SEED_BYTES);
    rc = noxtls_mldsa_sample_polyvecl_eta(param, rho, 0U, &y);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_mldsa_matrix_vector_mul(param, rho, &y, &w);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = mldsa_make_mu(rho, noxtls_message, message_len, mu);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_mldsa_make_challenge(param, mu, (uint32_t)sizeof(mu), &c);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    (void)w;
    (void)c;
    (void)signature;

    return NOXTLS_RETURN_NOT_SUPPORTED;
}
