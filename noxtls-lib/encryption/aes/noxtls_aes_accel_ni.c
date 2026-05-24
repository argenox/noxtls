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
* File:    noxtls_aes_accel_ni.c
* Summary: AES-NI backend for AES block encrypt/decrypt
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */
/** @{ */

#if NOXTLS_FEATURE_AES_ACCEL_NI && \
    (defined(__AES__) || defined(_MSC_VER)) && \
    (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86))

#include <stdint.h>
#include <string.h>

#if defined(_MSC_VER)
#include <intrin.h>
#include <wmmintrin.h>
#else
#include <wmmintrin.h>
#endif

#include "noxtls_aes.h"
#include "noxtls_aes_accel.h"

/**
 * @brief Resolve AES round count and key-word count for an AES key size.
 *
 * @param type AES key size selector.
 * @param rounds Output round count for the selected AES key size.
 * @param nk Output number of 32-bit key words for the selected AES key size.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL for null outputs,
 *         NOXTLS_RETURN_INVALID_KEY_SIZE for unknown key sizes, or
 *         NOXTLS_RETURN_NOT_SUPPORTED when the selected AES size is disabled.
 */
static noxtls_return_t noxtls_aes_accel_ni_get_rounds_and_nk(noxtls_aes_type_t type, int *rounds, int *nk)
{
    if(rounds == NULL || nk == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    switch(type) {
        case NOXTLS_AES_128_BIT:
#if NOXTLS_FEATURE_AES_128
            *rounds = NOXTLS_AES_128_ROUNDS;
            *nk = 4;
            return NOXTLS_RETURN_SUCCESS;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_AES_192_BIT:
#if NOXTLS_FEATURE_AES_192
            *rounds = NOXTLS_AES_192_ROUNDS;
            *nk = 6;
            return NOXTLS_RETURN_SUCCESS;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_AES_256_BIT:
#if NOXTLS_FEATURE_AES_256
            *rounds = NOXTLS_AES_256_ROUNDS;
            *nk = 8;
            return NOXTLS_RETURN_SUCCESS;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        default:
            return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }
}

/**
 * @brief Store a 32-bit key schedule word as big-endian bytes.
 *
 * @param word Key schedule word to serialize.
 * @param out Output buffer that receives four bytes in big-endian order.
 * @return None.
 */
static void noxtls_aes_accel_ni_word_to_bytes_be(uint32_t word, uint8_t out[4])
{
    out[0] = (uint8_t)((word >> 24) & 0xFFu);
    out[1] = (uint8_t)((word >> 16) & 0xFFu);
    out[2] = (uint8_t)((word >> 8) & 0xFFu);
    out[3] = (uint8_t)(word & 0xFFu);
}

/**
 * @brief Build AES-NI encryption and decryption round-key schedules.
 *
 * @param key AES key bytes for the selected key size.
 * @param type AES key size selector.
 * @param enc_rks Output AES-NI encryption round keys.
 * @param dec_rks Output AES-NI decryption round keys.
 * @param rounds_out Output round count for the generated key schedule.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL for null inputs,
 *         or an error from key-size resolution or AES key expansion.
 */
static noxtls_return_t noxtls_aes_accel_ni_build_round_keys(const uint8_t *key,
                                                            noxtls_aes_type_t type,
                                                            __m128i *enc_rks,
                                                            __m128i *dec_rks,
                                                            int *rounds_out)
{
    uint32_t words[NOXTLS_AES_MAX_KEY_SCHEDULE_WORDS];
    uint8_t round_key_bytes[16];
    int rounds;
    int nk;
    int round;
    noxtls_return_t rc;

    if(key == NULL || enc_rks == NULL || dec_rks == NULL || rounds_out == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_aes_accel_ni_get_rounds_and_nk(type, &rounds, &nk);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = noxtls_aes_key_expansion(key, words, nk, rounds);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    for(round = 0; round <= rounds; round++) {
        int col;
        for(col = 0; col < 4; col++) {
            noxtls_aes_accel_ni_word_to_bytes_be(words[(round * 4) + col], &round_key_bytes[col * 4]);
        }
        enc_rks[round] = _mm_loadu_si128((const __m128i *)round_key_bytes);
    }

    dec_rks[0] = enc_rks[rounds];
    for(round = 1; round < rounds; round++) {
        dec_rks[round] = _mm_aesimc_si128(enc_rks[rounds - round]);
    }
    dec_rks[rounds] = enc_rks[0];
    *rounds_out = rounds;

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Encrypt one AES block with AES-NI backend.
 *
 * @param key AES key.
 * @param data Input plaintext block (16 bytes).
 * @param output Output ciphertext block (16 bytes).
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NOT_SUPPORTED when backend is unavailable.
 */
noxtls_return_t noxtls_aes_accel_ni_encrypt_block(const uint8_t *key,
                                                  const uint8_t *data,
                                                  uint8_t *output,
                                                  noxtls_aes_type_t type)
{
#if NOXTLS_FEATURE_AES_ACCEL_NI && (defined(__AES__) || defined(_MSC_VER)) && (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86))
    __m128i enc_rks[15];
    __m128i dec_rks[15];
    __m128i block;
    int rounds;
    int round;
    noxtls_return_t rc;

    if(key == NULL || data == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_aes_accel_ni_build_round_keys(key, type, enc_rks, dec_rks, &rounds);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    block = _mm_loadu_si128((const __m128i *)data);
    block = _mm_xor_si128(block, enc_rks[0]);
    for(round = 1; round < rounds; round++) {
        block = _mm_aesenc_si128(block, enc_rks[round]);
    }
    block = _mm_aesenclast_si128(block, enc_rks[rounds]);
    _mm_storeu_si128((__m128i *)output, block);

    return NOXTLS_RETURN_SUCCESS;
#else
    (void)key;
    (void)data;
    (void)output;
    (void)type;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

/**
 * @brief Decrypt one AES block with AES-NI backend.
 *
 * @param key AES key.
 * @param data Input ciphertext block (16 bytes).
 * @param output Output plaintext block (16 bytes).
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NOT_SUPPORTED when backend is unavailable.
 */
noxtls_return_t noxtls_aes_accel_ni_decrypt_block(const uint8_t *key,
                                                  const uint8_t *data,
                                                  uint8_t *output,
                                                  noxtls_aes_type_t type)
{
#if NOXTLS_FEATURE_AES_ACCEL_NI && (defined(__AES__) || defined(_MSC_VER)) && (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86))
    __m128i enc_rks[15];
    __m128i dec_rks[15];
    __m128i block;
    int rounds;
    int round;
    noxtls_return_t rc;

    if(key == NULL || data == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_aes_accel_ni_build_round_keys(key, type, enc_rks, dec_rks, &rounds);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    block = _mm_loadu_si128((const __m128i *)data);
    block = _mm_xor_si128(block, dec_rks[0]);
    for(round = 1; round < rounds; round++) {
        block = _mm_aesdec_si128(block, dec_rks[round]);
    }
    block = _mm_aesdeclast_si128(block, dec_rks[rounds]);
    _mm_storeu_si128((__m128i *)output, block);

    return NOXTLS_RETURN_SUCCESS;
#else
    (void)key;
    (void)data;
    (void)output;
    (void)type;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

#endif /* NOXTLS_FEATURE_AES_ACCEL_NI */

/** @} */