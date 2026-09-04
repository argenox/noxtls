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
 * The per-round message buffer is sized from the pool (bucket allocator).
 */
noxtls_return_t noxtls_hkdf_expand(noxtls_hash_algos_t hash_algo,
                                   const uint8_t *prk, uint32_t prk_len,
                                   const uint8_t *info, uint32_t info_len,
                                   uint8_t *okm, uint32_t okm_len)
{
    uint32_t hash_size = (uint32_t)(noxtls_hkdf_hash_output_size(hash_algo));
    uint8_t T[64];
    uint8_t *msg = NULL;
    uint32_t msg_cap;
    uint32_t offset = 0U;
    uint32_t i = 1U;
    uint32_t n;

    if ((prk == NULL) || (okm == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if (hash_size == 0U) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if (okm_len > (255U * hash_size)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if ((info == NULL) && (info_len != 0U)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    msg_cap = hash_size + info_len + 1U;
    msg = (uint8_t *)noxtls_malloc((size_t)msg_cap);
    if (msg == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    n = (okm_len + hash_size - 1U) / hash_size;
    while ((offset < okm_len) && (i <= n)) {
        uint32_t msg_len = 1U;
        uint32_t pos = 0U;
        uint32_t t_len = (uint32_t)(hash_size);
        noxtls_return_t rc;

        if (i != 1U) {
            msg_len += hash_size;
        }
        if ((info != NULL) && (info_len > 0U)) {
            msg_len += info_len;
        }
        if (msg_len > msg_cap) {
            (void)noxtls_free(msg);
            return NOXTLS_RETURN_INVALID_PARAM;
        }

        if (i > 1U) {
            noxtls_copy_u8(&msg[pos], (size_t)msg_cap - (size_t)pos, &T[0], (size_t)hash_size);
            pos += hash_size;
        }
        if ((info != NULL) && (info_len > 0U)) {
            noxtls_copy_u8(&msg[pos], (size_t)msg_cap - (size_t)pos, &info[0], (size_t)info_len);
            pos += info_len;
        }
        msg[pos] = (uint8_t)i;

        rc = noxtls_hmac_compute(hash_algo, prk, prk_len, &msg[0], msg_len, &T[0], &t_len);
        if ((rc != NOXTLS_RETURN_SUCCESS) || (t_len != hash_size)) {
            (void)noxtls_free(msg);
            return NOXTLS_RETURN_FAILED;
        }

        {
            uint32_t remain = (uint32_t)(okm_len - offset);
            uint32_t copy_len = (uint32_t)((remain < hash_size) ? remain : hash_size);
            noxtls_copy_u8(&okm[offset], (size_t)copy_len, &T[0], (size_t)copy_len);
            offset += copy_len;
        }

        i += 1U;
    }

    (void)noxtls_free(msg);
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t hkdf_extract(noxtls_hash_algos_t hash_algo,
                             const uint8_t *salt, uint32_t salt_len,
                             const uint8_t *ikm, uint32_t ikm_len,
                             uint8_t *prk, uint32_t *prk_len) { return noxtls_hkdf_extract(hash_algo, salt, salt_len, ikm, ikm_len, prk, prk_len); }

noxtls_return_t hkdf_expand(noxtls_hash_algos_t hash_algo,
                            const uint8_t *prk, uint32_t prk_len,
                            const uint8_t *info, uint32_t info_len,
                            uint8_t *okm, uint32_t okm_len) { return noxtls_hkdf_expand(hash_algo, prk, prk_len, info, info_len, okm, okm_len); }
