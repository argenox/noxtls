/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "noxtls_hkdf.h"
#include "common/noxtls_memory.h"
#include "mac/noxtls_hmac.h"
#include "noxtls_ct.h"

static uint32_t noxtls_hkdf_hash_output_size(noxtls_hash_algos_t hash_algo)
{
    uint32_t size;

    switch (hash_algo) {
        case NOXTLS_HASH_SHA1:
            size = 20U;
            break;
        case NOXTLS_HASH_SHA_256:
            size = 32U;
            break;
        case NOXTLS_HASH_SHA_384:
            size = 48U;
            break;
        case NOXTLS_HASH_SHA_512:
            size = 64U;
            break;
        default:
            size = 0U;
            break;
    }
    return size;
}

noxtls_return_t noxtls_hkdf_extract(noxtls_hash_algos_t hash_algo,
                                    const uint8_t *salt, uint32_t salt_len,
                                    const uint8_t *ikm, uint32_t ikm_len,
                                    uint8_t *prk, uint32_t *prk_len)
{
    uint32_t hash_size = (uint32_t)(noxtls_hkdf_hash_output_size(hash_algo));
    uint8_t zero_salt[64];
    const uint8_t *salt_ptr = salt;
    uint32_t salt_n = (uint32_t)(salt_len);

    if ((ikm == NULL) || (prk == NULL) || (prk_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if (hash_size == 0U) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if (*prk_len < hash_size) {
        *prk_len = hash_size;
        return NOXTLS_RETURN_FAILED;
    }

    if ((salt_ptr == NULL) || (salt_n == 0U)) {
        noxtls_secure_zero((&zero_salt[0]), (size_t)(hash_size));
        salt_ptr = &zero_salt[0];
        salt_n = hash_size;
    }

    return noxtls_hmac_compute(hash_algo, salt_ptr, salt_n, ikm, ikm_len, prk, prk_len);
}

/*
 * Expand builds T(i) = HMAC(PRK, T(i-1) | info | i).
 * Streaming HMAC avoids a per-round message allocation; one keyed HMAC
 * context (reset per block) avoids re-keying.
 */
noxtls_return_t noxtls_hkdf_expand_parts(noxtls_hash_algos_t hash_algo,
                                         const uint8_t *prk, uint32_t prk_len,
                                         const noxtls_hkdf_info_part_t *parts, uint32_t part_count,
                                         uint8_t *okm, uint32_t okm_len)
{
    uint32_t hash_size = (uint32_t)(noxtls_hkdf_hash_output_size(hash_algo));
    noxtls_hmac_context_t ctx;
    uint8_t T[64];
    uint32_t offset = 0U;
    uint32_t i = 1U;
    uint32_t p = 0U;
    noxtls_return_t rc;

    if ((prk == NULL) || (okm == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if (hash_size == 0U) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if (okm_len > (255U * hash_size)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if ((parts == NULL) && (part_count != 0U)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    for (p = 0U; p < part_count; p += 1U) {
        if ((parts[p].data == NULL) && (parts[p].len != 0U)) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
    }

    if (okm_len == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }

    /* Key once; every block T(i) = HMAC(PRK, T(i-1) || info || i) restarts from
     * the stored key-pad midstate instead of re-keying. */
    rc = noxtls_hmac_init(&ctx, hash_algo, prk, prk_len);
    while ((rc == NOXTLS_RETURN_SUCCESS) && (offset < okm_len)) {
        uint8_t counter = (uint8_t)i;
        uint32_t t_len = hash_size;

        if (i > 1U) {
            rc = noxtls_hmac_reset(&ctx);
            if (rc == NOXTLS_RETURN_SUCCESS) {
                rc = noxtls_hmac_update(&ctx, T, hash_size);
            }
        }
        for (p = 0U; (rc == NOXTLS_RETURN_SUCCESS) && (p < part_count); p += 1U) {
            if (parts[p].len > 0U) {
                rc = noxtls_hmac_update(&ctx, parts[p].data, parts[p].len);
            }
        }
        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_hmac_update(&ctx, &counter, 1U);
        }
        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_hmac_final(&ctx, T, &t_len);
        }
        if ((rc == NOXTLS_RETURN_SUCCESS) && (t_len != hash_size)) {
            rc = NOXTLS_RETURN_FAILED;
        }
        if (rc == NOXTLS_RETURN_SUCCESS) {
            uint32_t remain = (uint32_t)(okm_len - offset);
            uint32_t copy_len = (uint32_t)((remain < hash_size) ? remain : hash_size);
            noxtls_copy_u8(&okm[offset], (size_t)copy_len, &T[0], (size_t)copy_len);
            offset += copy_len;
            i += 1U;
        }
    }

    (void)noxtls_hmac_free(&ctx);
    noxtls_secure_zero(&T[0], sizeof(T));
    if (rc != NOXTLS_RETURN_SUCCESS) {
        /* Never release a partial OKM. */
        noxtls_secure_zero(okm, (size_t)okm_len);
    }
    return rc;
}

noxtls_return_t noxtls_hkdf_expand(noxtls_hash_algos_t hash_algo,
                                   const uint8_t *prk, uint32_t prk_len,
                                   const uint8_t *info, uint32_t info_len,
                                   uint8_t *okm, uint32_t okm_len)
{
    noxtls_hkdf_info_part_t part;

    /* A NULL info with a non-zero length is rejected by the parts validation. */
    part.data = info;
    part.len = info_len;
    return noxtls_hkdf_expand_parts(hash_algo, prk, prk_len, &part, 1U, okm, okm_len);
}

noxtls_return_t hkdf_extract(noxtls_hash_algos_t hash_algo,
                             const uint8_t *salt, uint32_t salt_len,
                             const uint8_t *ikm, uint32_t ikm_len,
                             uint8_t *prk, uint32_t *prk_len) { return noxtls_hkdf_extract(hash_algo, salt, salt_len, ikm, ikm_len, prk, prk_len); }

noxtls_return_t hkdf_expand(noxtls_hash_algos_t hash_algo,
                            const uint8_t *prk, uint32_t prk_len,
                            const uint8_t *info, uint32_t info_len,
                            uint8_t *okm, uint32_t okm_len) { return noxtls_hkdf_expand(hash_algo, prk, prk_len, info, info_len, okm, okm_len); }
