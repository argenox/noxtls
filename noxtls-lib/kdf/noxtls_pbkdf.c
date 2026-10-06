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
* File:    noxtls_pbkdf.c
* Summary: PBKDF2 password-based key derivation (RFC 8018 section 5.2)
*
*
*****************************************************************************/

/**
 * @file noxtls_pbkdf.c
 * @brief PBKDF2 implementation over the NoxTLS HMAC primitive (RFC 8018 section 5.2).
 * @ingroup noxtls_kdf
 */

#include <stdint.h>
#include <string.h>

#include "noxtls_pbkdf.h"
#include "mac/noxtls_hmac.h"
#include "common/noxtls_ct.h"

/** @brief Bit shift extracting the most significant byte of a 32-bit block index. */
#define NOXTLS_PBKDF2_SHIFT_BYTE3 (24U)
/** @brief Bit shift extracting the second byte of a 32-bit block index. */
#define NOXTLS_PBKDF2_SHIFT_BYTE2 (16U)
/** @brief Bit shift extracting the third byte of a 32-bit block index. */
#define NOXTLS_PBKDF2_SHIFT_BYTE1 (8U)
/** @brief Mask selecting one byte. */
#define NOXTLS_PBKDF2_BYTE_MASK (0xFFU)

/**
 * @brief Return the HMAC output length hLen for a supported PBKDF2 hash.
 * @internal
 *
 * @param[in] hash_algo Hash algorithm identifier.
 *
 * @return hLen in bytes, or 0 when the hash is not supported or is compiled out
 *         of this build.
 */
static uint32_t noxtls_pbkdf2_prf_size(noxtls_hash_algos_t hash_algo)
{
    switch (hash_algo) {
#if NOXTLS_FEATURE_SHA1
        case NOXTLS_HASH_SHA1:
            return 20U;
#endif
#if NOXTLS_FEATURE_SHA256
        case NOXTLS_HASH_SHA_256:
            return 32U;
#endif
#if NOXTLS_FEATURE_SHA384
        case NOXTLS_HASH_SHA_384:
            return 48U;
#endif
#if NOXTLS_FEATURE_SHA512
        case NOXTLS_HASH_SHA_512:
            return 64U;
#endif
        default:
            return 0U;
    }
}

/**
 * @brief Status for a hash PBKDF2 cannot use.
 * @internal
 *
 * @param[in] hash_algo Hash algorithm identifier.
 *
 * @return NOXTLS_RETURN_NOT_SUPPORTED for a PBKDF2 hash compiled out of this
 *         build, NOXTLS_RETURN_INVALID_ALGORITHM for any other hash.
 */
static noxtls_return_t noxtls_pbkdf2_unusable_algorithm(noxtls_hash_algos_t hash_algo)
{
    noxtls_return_t rc = NOXTLS_RETURN_INVALID_ALGORITHM;
    if ((hash_algo == NOXTLS_HASH_SHA1) || (hash_algo == NOXTLS_HASH_SHA_256) ||
        (hash_algo == NOXTLS_HASH_SHA_384) || (hash_algo == NOXTLS_HASH_SHA_512)) {
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
    }
    return rc;
}

/**
 * @brief Compute one PRF invocation HMAC(P, part1 || part2).
 * @internal
 *
 * @param[in] hash_algo HMAC hash.
 * @param[in] password HMAC key P (non-NULL; may be a dummy when password_len is 0).
 * @param[in] password_len Length of P.
 * @param[in] part1 First message part (may be NULL when part1_len is 0).
 * @param[in] part1_len Length of part1.
 * @param[in] part2 Second message part (may be NULL when part2_len is 0).
 * @param[in] part2_len Length of part2.
 * @param[out] out PRF output of hLen bytes.
 * @param[in] out_len hLen.
 *
 * @return NOXTLS_RETURN_SUCCESS, the failing HMAC status, or NOXTLS_RETURN_FAILED
 *         on an unexpected MAC length. @p out is wiped on failure.
 */
static noxtls_return_t noxtls_pbkdf2_prf(noxtls_hash_algos_t hash_algo,
                                         const uint8_t *password, uint32_t password_len,
                                         const uint8_t *part1, uint32_t part1_len,
                                         const uint8_t *part2, uint32_t part2_len,
                                         uint8_t *out, uint32_t out_len)
{
    noxtls_hmac_context_t hmac;
    uint32_t mac_len = out_len;
    noxtls_return_t rc;

    rc = noxtls_hmac_init(&hmac, hash_algo, password, password_len);
    if ((rc == NOXTLS_RETURN_SUCCESS) && (part1_len > 0U)) {
        rc = noxtls_hmac_update(&hmac, part1, part1_len);
    }

    if ((rc == NOXTLS_RETURN_SUCCESS) && (part2_len > 0U)) {
        rc = noxtls_hmac_update(&hmac, part2, part2_len);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_hmac_final(&hmac, out, &mac_len);
    }

    (void)noxtls_hmac_free(&hmac);
    noxtls_secure_zero(&hmac, sizeof(hmac));
    if ((rc == NOXTLS_RETURN_SUCCESS) && (mac_len != out_len)) {
        rc = NOXTLS_RETURN_FAILED;
    }
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(out, (size_t)out_len);
    }

    return rc;
}

noxtls_return_t noxtls_pbkdf2_hmac(noxtls_hash_algos_t hash_algo,
                                   const uint8_t *password, uint32_t password_len,
                                   const uint8_t *salt, uint32_t salt_len,
                                   uint32_t iterations,
                                   uint8_t *dk, uint32_t dk_len)
{
    static const uint8_t empty_key = 0U;
    uint8_t u_block[NOXTLS_PBKDF2_MAX_PRF_SIZE];
    uint8_t t_block[NOXTLS_PBKDF2_MAX_PRF_SIZE];
    uint8_t block_index[NOXTLS_PBKDF2_BLOCK_INDEX_SIZE];
    const uint8_t *key = password;
    uint32_t h_len;
    uint32_t offset = 0U;
    uint32_t block = 1U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if ((dk == NULL) ||
        ((password == NULL) && (password_len > 0U)) ||
        ((salt == NULL) && (salt_len > 0U))) {
        return NOXTLS_RETURN_NULL;
    }

    h_len = noxtls_pbkdf2_prf_size(hash_algo);
    if (h_len == 0U) {
        noxtls_secure_zero(dk, dk_len);
        return noxtls_pbkdf2_unusable_algorithm(hash_algo);
    }

    if ((iterations < NOXTLS_PBKDF2_MIN_ITERATIONS) || (dk_len == 0U)) {
        noxtls_secure_zero(dk, dk_len);
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if (password_len == 0U) {
        key = &empty_key;
    }

    /* RFC 8018 section 5.2 step 3: T_i for i = 1..l, last block truncated (step 4). */
    while ((offset < dk_len) && (rc == NOXTLS_RETURN_SUCCESS)) {
        uint32_t iteration;
        uint32_t copy_len;
        uint32_t index;

        block_index[0] = (uint8_t)((block >> NOXTLS_PBKDF2_SHIFT_BYTE3) & NOXTLS_PBKDF2_BYTE_MASK);
        block_index[1] = (uint8_t)((block >> NOXTLS_PBKDF2_SHIFT_BYTE2) & NOXTLS_PBKDF2_BYTE_MASK);
        block_index[2] = (uint8_t)((block >> NOXTLS_PBKDF2_SHIFT_BYTE1) & NOXTLS_PBKDF2_BYTE_MASK);
        block_index[3] = (uint8_t)(block & NOXTLS_PBKDF2_BYTE_MASK);

        /* U_1 = PRF(P, S || INT(i)). */
        rc = noxtls_pbkdf2_prf(hash_algo, key, password_len, salt, salt_len,
                               block_index, NOXTLS_PBKDF2_BLOCK_INDEX_SIZE, u_block, h_len);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            break;
        }

        memcpy(t_block, u_block, h_len);

        /* U_j = PRF(P, U_{j-1}), T_i ^= U_j for j = 2..c. */
        for (iteration = 1U; iteration < iterations; ++iteration) {
            rc = noxtls_pbkdf2_prf(hash_algo, key, password_len, u_block, h_len,
                                   NULL, 0U, u_block, h_len);
            if (rc != NOXTLS_RETURN_SUCCESS) {
                break;
            }

            for (index = 0U; index < h_len; ++index) {
                t_block[index] ^= u_block[index];
            }
        }

        if (rc != NOXTLS_RETURN_SUCCESS) {
            break;
        }

        copy_len = ((dk_len - offset) < h_len) ? (dk_len - offset) : h_len;
        memcpy(&dk[offset], t_block, copy_len);
        offset += copy_len;
        ++block;
    }

    noxtls_secure_zero(u_block, sizeof(u_block));
    noxtls_secure_zero(t_block, sizeof(t_block));
    noxtls_secure_zero(block_index, sizeof(block_index));
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(dk, dk_len);
    }

    return rc;
}

noxtls_return_t noxtls_pbkdf2_self_test(void)
{
#if NOXTLS_FEATURE_SHA1 || NOXTLS_FEATURE_SHA256
    /* P = "password", S = "salt", c = 1 and c = 2, one PRF block each. */
    static const uint8_t pw[] = { 112U, 97U, 115U, 115U, 119U, 111U, 114U, 100U };
    static const uint8_t salt[] = { 115U, 97U, 108U, 116U };
#if NOXTLS_FEATURE_SHA1
    /* PBKDF2-HMAC-SHA1, RFC 6070 §2 (dkLen = 20). */
    static const noxtls_hash_algos_t kat_hash = NOXTLS_HASH_SHA1;
    static const uint8_t c1[20] = {
        0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9,
        0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6
    };
    static const uint8_t c2[20] = {
        0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e,
        0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57
    };
    uint8_t dk[20];
#else
    /* SHA-1 compiled out: PBKDF2-HMAC-SHA256 with the same inputs (dkLen = 32). */
    static const noxtls_hash_algos_t kat_hash = NOXTLS_HASH_SHA_256;
    static const uint8_t c1[32] = {
        0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
        0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b
    };
    static const uint8_t c2[32] = {
        0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3, 0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0,
        0x2a, 0x30, 0x3f, 0x8e, 0xf3, 0xc2, 0x51, 0xdf, 0xd6, 0xe2, 0xd8, 0x5a, 0x95, 0x47, 0x4c, 0x43
    };
    uint8_t dk[32];
#endif

    if((noxtls_pbkdf2_hmac(kat_hash, pw, sizeof(pw), salt, sizeof(salt),
                           1U, dk, sizeof(dk)) != NOXTLS_RETURN_SUCCESS) ||
       (noxtls_ct_memcmp(dk, c1, sizeof(dk)) != 0)) {
        return NOXTLS_RETURN_FAILED;
    }
    if((noxtls_pbkdf2_hmac(kat_hash, pw, sizeof(pw), salt, sizeof(salt),
                           2U, dk, sizeof(dk)) != NOXTLS_RETURN_SUCCESS) ||
       (noxtls_ct_memcmp(dk, c2, sizeof(dk)) != 0)) {
        return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
#else
    /* Neither SHA-1 nor SHA-256 is compiled into this build. */
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}
