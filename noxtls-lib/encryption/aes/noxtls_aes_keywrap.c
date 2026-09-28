/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*****************************************************************************/

/**
 * @file noxtls_aes_keywrap.c
 * @brief AES Key Wrap / Unwrap (RFC 3394 §2.2).
 * @ingroup noxtls_aes
 */

#include <stdint.h>
#include <string.h>

#include "noxtls_aes_keywrap.h"

/** @brief RFC 3394 §2.2.3.1 default initial value (0xA6 repeated). */
#define NOXTLS_AES_KW_IV_OCTET 0xA6U
/** @brief Rounds of the wrapping process (j = 0..5). */
#define NOXTLS_AES_KW_ROUNDS 6U
/** @brief Minimum semiblocks of key data (n >= 2). */
#define NOXTLS_AES_KW_MIN_N 2U

/**
 * @brief XOR the big-endian 64-bit counter t into A.
 * @internal
 *
 * @param [in,out] a 8-octet register A.
 * @param [in] t Counter value n*j + i.
 */
static void noxtls_aes_kw_xor_t(uint8_t a[NOXTLS_AES_KW_SEMIBLOCK], uint32_t t)
{
    a[4] ^= (uint8_t)(t >> 24);
    a[5] ^= (uint8_t)(t >> 16);
    a[6] ^= (uint8_t)(t >> 8);
    a[7] ^= (uint8_t)t;
}

noxtls_return_t noxtls_aes_key_wrap(const uint8_t *kek, noxtls_aes_type_t type,
                                    const uint8_t *plain, uint32_t plain_len,
                                    uint8_t *wrapped)
{
    uint8_t b[NOXTLS_AES_BLOCK_LENGTH];
    uint8_t *a;
    uint32_t n;
    uint32_t i;
    uint32_t j;

    if((kek == NULL) || (plain == NULL) || (wrapped == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(((plain_len % NOXTLS_AES_KW_SEMIBLOCK) != 0U) ||
       ((plain_len / NOXTLS_AES_KW_SEMIBLOCK) < NOXTLS_AES_KW_MIN_N)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    n = plain_len / NOXTLS_AES_KW_SEMIBLOCK;

    /* §2.2.1: A = IV, R[i] = P[i]; C[0] = A lives in wrapped[0..7]. */
    a = wrapped;
    (void)memset(a, (int)NOXTLS_AES_KW_IV_OCTET, NOXTLS_AES_KW_SEMIBLOCK);
    (void)memmove(&wrapped[NOXTLS_AES_KW_SEMIBLOCK], plain, plain_len);

    for(j = 0U; j < NOXTLS_AES_KW_ROUNDS; j++) {
        for(i = 1U; i <= n; i++) {
            uint8_t *r = &wrapped[i * NOXTLS_AES_KW_SEMIBLOCK];

            (void)memcpy(b, a, NOXTLS_AES_KW_SEMIBLOCK);
            (void)memcpy(&b[NOXTLS_AES_KW_SEMIBLOCK], r, NOXTLS_AES_KW_SEMIBLOCK);
            (void)noxtls_aes_encrypt_ecb(kek, b, NOXTLS_AES_BLOCK_LENGTH, NULL, b, type);
            (void)memcpy(a, b, NOXTLS_AES_KW_SEMIBLOCK);
            noxtls_aes_kw_xor_t(a, (n * j) + i);
            (void)memcpy(r, &b[NOXTLS_AES_KW_SEMIBLOCK], NOXTLS_AES_KW_SEMIBLOCK);
        }
    }
    (void)memset(b, 0, sizeof(b));
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_aes_key_unwrap(const uint8_t *kek, noxtls_aes_type_t type,
                                      const uint8_t *wrapped, uint32_t wrapped_len,
                                      uint8_t *plain)
{
    uint8_t a[NOXTLS_AES_KW_SEMIBLOCK];
    uint8_t b[NOXTLS_AES_BLOCK_LENGTH];
    uint8_t diff = 0U;
    uint32_t n;
    uint32_t i;
    uint32_t j;

    if((kek == NULL) || (wrapped == NULL) || (plain == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(((wrapped_len % NOXTLS_AES_KW_SEMIBLOCK) != 0U) ||
       ((wrapped_len / NOXTLS_AES_KW_SEMIBLOCK) < (NOXTLS_AES_KW_MIN_N + 1U))) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    n = (wrapped_len / NOXTLS_AES_KW_SEMIBLOCK) - 1U;

    /* §2.2.2: A = C[0], R[i] = C[i]; R lives in plain. */
    (void)memcpy(a, wrapped, NOXTLS_AES_KW_SEMIBLOCK);
    (void)memmove(plain, &wrapped[NOXTLS_AES_KW_SEMIBLOCK], wrapped_len - NOXTLS_AES_KW_SEMIBLOCK);

    for(j = NOXTLS_AES_KW_ROUNDS; j > 0U; j--) {
        for(i = n; i > 0U; i--) {
            uint8_t *r = &plain[(i - 1U) * NOXTLS_AES_KW_SEMIBLOCK];

            (void)memcpy(b, a, NOXTLS_AES_KW_SEMIBLOCK);
            noxtls_aes_kw_xor_t(b, (n * (j - 1U)) + i);
            (void)memcpy(&b[NOXTLS_AES_KW_SEMIBLOCK], r, NOXTLS_AES_KW_SEMIBLOCK);
            (void)noxtls_aes_decrypt_ecb(kek, b, NOXTLS_AES_BLOCK_LENGTH, NULL, b, type);
            (void)memcpy(a, b, NOXTLS_AES_KW_SEMIBLOCK);
            (void)memcpy(r, &b[NOXTLS_AES_KW_SEMIBLOCK], NOXTLS_AES_KW_SEMIBLOCK);
        }
    }

    /* §2.2.3: constant-time integrity check A == IV. */
    for(i = 0U; i < NOXTLS_AES_KW_SEMIBLOCK; i++) {
        diff |= (uint8_t)(a[i] ^ NOXTLS_AES_KW_IV_OCTET);
    }
    (void)memset(b, 0, sizeof(b));
    if(diff != 0U) {
        (void)memset(plain, 0, wrapped_len - NOXTLS_AES_KW_SEMIBLOCK);
        return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_aes_keywrap_self_test(void)
{
    /* RFC 3394 §4.1: wrap 128 bits of key data with a 128-bit KEK. */
    static const uint8_t kek[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    static const uint8_t key_data[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    };
    static const uint8_t expected[24] = {
        0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,
        0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
        0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5
    };
    uint8_t wrapped[24];
    uint8_t unwrapped[16];

    if((noxtls_aes_key_wrap(kek, NOXTLS_AES_128_BIT, key_data, sizeof(key_data),
                            wrapped) != NOXTLS_RETURN_SUCCESS) ||
       (memcmp(wrapped, expected, sizeof(expected)) != 0)) {
        return NOXTLS_RETURN_FAILED;
    }
    if((noxtls_aes_key_unwrap(kek, NOXTLS_AES_128_BIT, expected, sizeof(expected),
                              unwrapped) != NOXTLS_RETURN_SUCCESS) ||
       (memcmp(unwrapped, key_data, sizeof(key_data)) != 0)) {
        return NOXTLS_RETURN_FAILED;
    }
    wrapped[0] ^= 0x01U;
    if(noxtls_aes_key_unwrap(kek, NOXTLS_AES_128_BIT, wrapped, sizeof(wrapped),
                             unwrapped) != NOXTLS_RETURN_FAILED) {
        return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}
