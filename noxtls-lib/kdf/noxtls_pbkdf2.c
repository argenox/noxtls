/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*****************************************************************************/

/**
 * @file noxtls_pbkdf2.c
 * @brief PBKDF2 password-based key derivation (RFC 8018 §5.2) over HMAC.
 * @ingroup noxtls_kdf
 */

#include "common/noxtls_ct.h"
#include <stdint.h>
#include <string.h>

#include "noxtls_pbkdf2.h"
#include "mac/noxtls_hmac.h"

/** @brief Largest HMAC output supported (SHA-512). */
#define NOXTLS_PBKDF2_MAX_HLEN 64U
/** @brief Octets of the big-endian block index INT(i) (RFC 8018 §5.2). */
#define NOXTLS_PBKDF2_INDEX_OCTETS 4U

/**
 * @brief Output length of the HMAC PRF for a hash.
 * @internal
 *
 * @param [in] hash_algo Hash algorithm.
 *
 * @return Digest length, or 0 when unsupported.
 */
static uint32_t noxtls_pbkdf2_hlen(noxtls_hash_algos_t hash_algo)
{
    switch(hash_algo) {
        case NOXTLS_HASH_SHA1: return 20U;
        case NOXTLS_HASH_SHA_256: return 32U;
        case NOXTLS_HASH_SHA_384: return 48U;
        case NOXTLS_HASH_SHA_512: return 64U;
        default: return 0U;
    }
}

/**
 * @brief Compute U_1 = PRF(P, S || INT(i)) without concatenating buffers.
 * @internal
 *
 * @param [in] hash_algo Hash algorithm.
 * @param [in] password Password.
 * @param [in] password_len Password length.
 * @param [in] salt Salt.
 * @param [in] salt_len Salt length.
 * @param [in] block_index One-based block index i.
 * @param [out] u Output (hLen octets).
 *
 * @return NOXTLS_RETURN_SUCCESS or the HMAC error.
 */
static noxtls_return_t noxtls_pbkdf2_u1(noxtls_hash_algos_t hash_algo,
                                        const uint8_t *password, uint32_t password_len,
                                        const uint8_t *salt, uint32_t salt_len,
                                        uint32_t block_index, uint8_t *u)
{
    noxtls_hmac_context_t ctx;
    uint8_t index_be[NOXTLS_PBKDF2_INDEX_OCTETS];
    uint32_t mac_len = NOXTLS_PBKDF2_MAX_HLEN;
    noxtls_return_t rc;

    index_be[0] = (uint8_t)(block_index >> 24);
    index_be[1] = (uint8_t)(block_index >> 16);
    index_be[2] = (uint8_t)(block_index >> 8);
    index_be[3] = (uint8_t)block_index;

    rc = noxtls_hmac_init(&ctx, hash_algo, password, password_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(salt_len > 0U) {
        rc = noxtls_hmac_update(&ctx, salt, salt_len);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_hmac_update(&ctx, index_be, NOXTLS_PBKDF2_INDEX_OCTETS);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_hmac_final(&ctx, u, &mac_len);
    }
    (void)noxtls_hmac_free(&ctx);
    return rc;
}

noxtls_return_t noxtls_pbkdf2_hmac(noxtls_hash_algos_t hash_algo,
                                   const uint8_t *password, uint32_t password_len,
                                   const uint8_t *salt, uint32_t salt_len,
                                   uint32_t iterations,
                                   uint8_t *out, uint32_t out_len)
{
    static const uint8_t empty_password = 0U;
    const uint8_t *password_bytes = (password != NULL) ? password : &empty_password;
    uint8_t u[NOXTLS_PBKDF2_MAX_HLEN];
    uint8_t t[NOXTLS_PBKDF2_MAX_HLEN];
    uint32_t hlen = noxtls_pbkdf2_hlen(hash_algo);
    uint32_t done = 0U;
    uint32_t block_index = 1U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if((out == NULL) || ((password == NULL) && (password_len > 0U)) ||
       ((salt == NULL) && (salt_len > 0U))) {
        return NOXTLS_RETURN_NULL;
    }
    if((iterations == 0U) || (out_len == 0U)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(hlen == 0U) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }

    /* RFC 8018 §5.2: T_i = U_1 ^ U_2 ^ ... ^ U_c, DK = T_1 || T_2 || ... */
    while((done < out_len) && (rc == NOXTLS_RETURN_SUCCESS)) {
        uint32_t j;
        uint32_t k;
        uint32_t n;

        rc = noxtls_pbkdf2_u1(hash_algo, password_bytes, password_len, salt, salt_len,
                              block_index, u);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            break;
        }
        (void)noxtls_copy_u8((uint8_t *)(void *)(t), (size_t)(hlen), (const uint8_t *)(const void *)(u), (size_t)(hlen));
        for(j = 1U; j < iterations; j++) {
            uint32_t mac_len = NOXTLS_PBKDF2_MAX_HLEN;

            rc = noxtls_hmac_compute(hash_algo, password_bytes, password_len, u, hlen,
                                     u, &mac_len);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                break;
            }
            for(k = 0U; k < hlen; k++) {
                t[k] ^= u[k];
            }
        }
        n = out_len - done;
        if(n > hlen) {
            n = hlen;
        }
        (void)noxtls_copy_u8((uint8_t *)(void *)(&out[done]), (size_t)(n), (const uint8_t *)(const void *)(t), (size_t)(n));
        done += n;
        block_index++;
    }

    (void)noxtls_secure_zero(u, (size_t)(sizeof(u)));
    (void)noxtls_secure_zero(t, (size_t)(sizeof(t)));
    return rc;
}

noxtls_return_t noxtls_pbkdf2_self_test(void)
{
    /* RFC 6070 §2: P = "password", S = "salt", dkLen = 20. */
    static const uint8_t pw[] = { 112U, 97U, 115U, 115U, 119U, 111U, 114U, 100U };
    static const uint8_t salt[] = { 115U, 97U, 108U, 116U };
    static const uint8_t c1[20] = {
        0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9,
        0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6
    };
    static const uint8_t c2[20] = {
        0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e,
        0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57
    };
    uint8_t dk[20];

    if((noxtls_pbkdf2_hmac(NOXTLS_HASH_SHA1, pw, sizeof(pw), salt, sizeof(salt),
                           1U, dk, sizeof(dk)) != NOXTLS_RETURN_SUCCESS) ||
       (noxtls_ct_memcmp(dk, c1, sizeof(dk)) != 0)) {
        return NOXTLS_RETURN_FAILED;
    }
    if((noxtls_pbkdf2_hmac(NOXTLS_HASH_SHA1, pw, sizeof(pw), salt, sizeof(salt),
                           2U, dk, sizeof(dk)) != NOXTLS_RETURN_SUCCESS) ||
       (noxtls_ct_memcmp(dk, c2, sizeof(dk)) != 0)) {
        return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}
