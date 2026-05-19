/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
*
* File:    noxtls_mldsa_sampling.c
* Summary: ML-DSA sampling and seed-expansion helpers.
*/

#include <string.h>

#include "noxtls_mldsa_internal.h"
#include "mdigest/sha3/noxtls_sha3.h"

noxtls_return_t noxtls_mldsa_expand_xof(const uint8_t *seed,
                                        uint32_t seed_len,
                                        uint8_t domain_tag,
                                        uint16_t nonce,
                                        uint8_t *out,
                                        uint32_t out_len)
{
    noxtls_sha3_ctx_t shake;
    uint8_t meta[3];
    noxtls_return_t rc;

    if(seed == NULL || out == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    meta[0] = domain_tag;
    meta[1] = (uint8_t)(nonce & 0xFFu);
    meta[2] = (uint8_t)((nonce >> 8) & 0xFFu);

    rc = noxtls_shake256_init(&shake);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_shake256_update(&shake, meta, (uint32_t)sizeof(meta));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_shake256_update(&shake, seed, seed_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_shake256_final(&shake);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return noxtls_shake256_squeeze(&shake, out, out_len);
}

noxtls_return_t noxtls_mldsa_derive_seeds(const uint8_t master_seed[NOXTLS_MLDSA_INTERNAL_SEED_BYTES],
                                          uint8_t rho[NOXTLS_MLDSA_INTERNAL_SEED_BYTES],
                                          uint8_t k[NOXTLS_MLDSA_INTERNAL_SEED_BYTES],
                                          uint8_t tr[NOXTLS_MLDSA_INTERNAL_SEED_BYTES])
{
    uint8_t block[3u * NOXTLS_MLDSA_INTERNAL_SEED_BYTES];
    noxtls_return_t rc;

    if(master_seed == NULL || rho == NULL || k == NULL || tr == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_mldsa_expand_xof(master_seed,
                                 NOXTLS_MLDSA_INTERNAL_SEED_BYTES,
                                 0xA1u,
                                 0u,
                                 block,
                                 (uint32_t)sizeof(block));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    memcpy(rho, block, NOXTLS_MLDSA_INTERNAL_SEED_BYTES);
    memcpy(k, block + NOXTLS_MLDSA_INTERNAL_SEED_BYTES, NOXTLS_MLDSA_INTERNAL_SEED_BYTES);
    memcpy(tr, block + (2u * NOXTLS_MLDSA_INTERNAL_SEED_BYTES), NOXTLS_MLDSA_INTERNAL_SEED_BYTES);
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_mldsa_sample_uniform_q(noxtls_mldsa_param_t param,
                                              const uint8_t seed[NOXTLS_MLDSA_INTERNAL_SEED_BYTES],
                                              uint16_t nonce,
                                              noxtls_mldsa_poly_t *poly)
{
    uint8_t buf[NOXTLS_MLDSA_N * 4u];
    noxtls_mldsa_param_spec_t spec;
    noxtls_return_t rc;
    uint32_t i;

    if(seed == NULL || poly == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_mldsa_internal_get_param_spec(param, &spec);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = noxtls_mldsa_expand_xof(seed,
                                 NOXTLS_MLDSA_INTERNAL_SEED_BYTES,
                                 (uint8_t)(0xB0u + spec.k),
                                 nonce,
                                 buf,
                                 (uint32_t)sizeof(buf));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(i = 0u; i < NOXTLS_MLDSA_N; ++i) {
        uint32_t off = i * 4u;
        uint32_t v = (uint32_t)buf[off]
                   | ((uint32_t)buf[off + 1u] << 8)
                   | ((uint32_t)buf[off + 2u] << 16)
                   | ((uint32_t)buf[off + 3u] << 24);
        poly->coeff[i] = (int32_t)(v % NOXTLS_MLDSA_Q);
    }

    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_mldsa_sample_small_eta(noxtls_mldsa_param_t param,
                                              const uint8_t seed[NOXTLS_MLDSA_INTERNAL_SEED_BYTES],
                                              uint16_t nonce,
                                              noxtls_mldsa_poly_t *poly)
{
    uint8_t buf[NOXTLS_MLDSA_N];
    noxtls_mldsa_param_spec_t spec;
    noxtls_return_t rc;
    uint32_t i;

    if(seed == NULL || poly == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_mldsa_internal_get_param_spec(param, &spec);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = noxtls_mldsa_expand_xof(seed,
                                 NOXTLS_MLDSA_INTERNAL_SEED_BYTES,
                                 (uint8_t)(0xC0u + spec.l),
                                 nonce,
                                 buf,
                                 (uint32_t)sizeof(buf));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(i = 0u; i < NOXTLS_MLDSA_N; ++i) {
        uint8_t span = (uint8_t)((2u * spec.eta) + 1u);
        int32_t centered = (int32_t)(buf[i] % span) - (int32_t)spec.eta;
        poly->coeff[i] = centered;
    }

    return NOXTLS_RETURN_SUCCESS;
}

