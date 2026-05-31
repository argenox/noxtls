/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "noxtls_hkdf.h"
#include "mac/noxtls_hmac.h"

static uint32_t noxtls_hkdf_hash_output_size(noxtls_hash_algos_t hash_algo)
{
    switch(hash_algo) {
        case NOXTLS_HASH_SHA1: return 20U;
        case NOXTLS_HASH_SHA_256: return 32U;
        case NOXTLS_HASH_SHA_384: return 48U;
        case NOXTLS_HASH_SHA_512: return 64U;
        default: return 0U;
    }
}

noxtls_return_t noxtls_hkdf_extract(noxtls_hash_algos_t hash_algo,
                                    const uint8_t *salt, uint32_t salt_len,
                                    const uint8_t *ikm, uint32_t ikm_len,
                                    uint8_t *prk, uint32_t *prk_len)
{
    uint32_t hash_size = noxtls_hkdf_hash_output_size(hash_algo);
    uint8_t zero_salt[64];

    if(ikm == NULL || prk == NULL || prk_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(hash_size == 0U) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if(*prk_len < hash_size) {
        *prk_len = hash_size;
        return NOXTLS_RETURN_FAILED;
    }

    if(salt == NULL || salt_len == 0U) {
        memset(zero_salt, 0, hash_size);
        salt = zero_salt;
        salt_len = hash_size;
    }

    return noxtls_hmac_compute(hash_algo, salt, salt_len, ikm, ikm_len, prk, prk_len);
}

noxtls_return_t noxtls_hkdf_expand(noxtls_hash_algos_t hash_algo,
                                   const uint8_t *prk, uint32_t prk_len,
                                   const uint8_t *info, uint32_t info_len,
                                   uint8_t *okm, uint32_t okm_len)
{
    uint32_t hash_size = noxtls_hkdf_hash_output_size(hash_algo);
    uint8_t T[64];
    uint32_t offset = 0U;
    uint32_t i = 1U;
    uint32_t n;

    if(prk == NULL || okm == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(hash_size == 0U) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if(okm_len > (255U * hash_size)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    n = (okm_len + hash_size - 1U) / hash_size;
    while(offset < okm_len && i <= n) {
        uint8_t *msg = NULL;
        uint32_t msg_len = (i == 1U ? 0U : hash_size) + ((info != NULL) ? info_len : 0U) + 1U;
        uint32_t pos = 0U;
        uint32_t t_len = hash_size;
        noxtls_return_t rc;

        msg = (uint8_t *)malloc(msg_len);
        if(msg == NULL) {
            return NOXTLS_RETURN_FAILED;
        }

        if(i > 1U) {
            memcpy(msg + pos, T, hash_size);
            pos += hash_size;
        }
        if(info != NULL && info_len > 0U) {
            memcpy(msg + pos, info, info_len);
            pos += info_len;
        }
        msg[pos] = (uint8_t)i;

        rc = noxtls_hmac_compute(hash_algo, prk, prk_len, msg, msg_len, T, &t_len);
        free(msg);
        if(rc != NOXTLS_RETURN_SUCCESS || t_len != hash_size) {
            return NOXTLS_RETURN_FAILED;
        }

        {
            uint32_t copy_len = (okm_len - offset < hash_size) ? (okm_len - offset) : hash_size;
            memcpy(okm + offset, T, copy_len);
            offset += copy_len;
        }

        i++;
    }

    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t hkdf_extract(noxtls_hash_algos_t hash_algo,
                             const uint8_t *salt, uint32_t salt_len,
                             const uint8_t *ikm, uint32_t ikm_len,
                             uint8_t *prk, uint32_t *prk_len)
{
    return noxtls_hkdf_extract(hash_algo, salt, salt_len, ikm, ikm_len, prk, prk_len);
}

noxtls_return_t hkdf_expand(noxtls_hash_algos_t hash_algo,
                            const uint8_t *prk, uint32_t prk_len,
                            const uint8_t *info, uint32_t info_len,
                            uint8_t *okm, uint32_t okm_len)
{
    return noxtls_hkdf_expand(hash_algo, prk, prk_len, info, info_len, okm, okm_len);
}
