/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_aes_accel_apple.c
* Summary: Apple Silicon ARMv8 AES backend for AES block encrypt/decrypt
*
*/

#if NOXTLS_FEATURE_AES_ACCEL_APPLE && \
    defined(__APPLE__) && \
    (defined(__aarch64__) || defined(__arm64__)) && \
    defined(__ARM_FEATURE_CRYPTO)

#include <stdint.h>
#include <string.h>

#include <arm_neon.h>

#include "noxtls_aes.h"
#include "noxtls_aes_accel.h"

static noxtls_return_t noxtls_aes_accel_apple_get_rounds_and_nk(noxtls_aes_type_t type, int *rounds, int *nk)
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

static void noxtls_aes_accel_apple_word_to_bytes_be(uint32_t word, uint8_t out[4])
{
    out[0] = (uint8_t)((word >> 24) & 0xFFu);
    out[1] = (uint8_t)((word >> 16) & 0xFFu);
    out[2] = (uint8_t)((word >> 8) & 0xFFu);
    out[3] = (uint8_t)(word & 0xFFu);
}

static noxtls_return_t noxtls_aes_accel_apple_build_round_keys(const uint8_t *key,
                                                               noxtls_aes_type_t type,
                                                               uint8x16_t *enc_rks,
                                                               uint8x16_t *dec_rks,
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

    rc = noxtls_aes_accel_apple_get_rounds_and_nk(type, &rounds, &nk);
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
            noxtls_aes_accel_apple_word_to_bytes_be(words[(round * 4) + col], &round_key_bytes[col * 4]);
        }
        enc_rks[round] = vld1q_u8(round_key_bytes);
    }

    dec_rks[0] = enc_rks[rounds];
    for(round = 1; round < rounds; round++) {
        dec_rks[round] = vaesimcq_u8(enc_rks[rounds - round]);
    }
    dec_rks[rounds] = enc_rks[0];
    *rounds_out = rounds;

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Encrypt one AES block with Apple Silicon ARMv8 backend.
 * @param key AES key.
 * @param data Input plaintext block (16 bytes).
 * @param output Output ciphertext block (16 bytes).
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NOT_SUPPORTED when backend is unavailable.
 */
noxtls_return_t noxtls_aes_accel_apple_encrypt_block(const uint8_t *key,
                                                     const uint8_t *data,
                                                     uint8_t *output,
                                                     noxtls_aes_type_t type)
{
#if NOXTLS_FEATURE_AES_ACCEL_APPLE && defined(__APPLE__) && (defined(__aarch64__) || defined(__arm64__)) && defined(__ARM_FEATURE_CRYPTO)
    uint8x16_t enc_rks[15];
    uint8x16_t dec_rks[15];
    uint8x16_t state;
    int rounds;
    int round;
    noxtls_return_t rc;

    if(key == NULL || data == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_aes_accel_apple_build_round_keys(key, type, enc_rks, dec_rks, &rounds);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    state = vld1q_u8(data);
    state = veorq_u8(state, enc_rks[0]);
    for(round = 1; round < rounds; round++) {
        state = vaeseq_u8(state, enc_rks[round]);
        state = vaesmcq_u8(state);
    }
    state = vaeseq_u8(state, enc_rks[rounds]);
    vst1q_u8(output, state);

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
 * @brief Decrypt one AES block with Apple Silicon ARMv8 backend.
 * @param key AES key.
 * @param data Input ciphertext block (16 bytes).
 * @param output Output plaintext block (16 bytes).
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NOT_SUPPORTED when backend is unavailable.
 */
noxtls_return_t noxtls_aes_accel_apple_decrypt_block(const uint8_t *key,
                                                     const uint8_t *data,
                                                     uint8_t *output,
                                                     noxtls_aes_type_t type)
{
#if NOXTLS_FEATURE_AES_ACCEL_APPLE && defined(__APPLE__) && (defined(__aarch64__) || defined(__arm64__)) && defined(__ARM_FEATURE_CRYPTO)
    uint8x16_t enc_rks[15];
    uint8x16_t dec_rks[15];
    uint8x16_t state;
    int rounds;
    int round;
    noxtls_return_t rc;

    if(key == NULL || data == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_aes_accel_apple_build_round_keys(key, type, enc_rks, dec_rks, &rounds);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    state = vld1q_u8(data);
    state = veorq_u8(state, dec_rks[0]);
    for(round = 1; round < rounds; round++) {
        state = vaesdq_u8(state, dec_rks[round]);
        state = vaesimcq_u8(state);
    }
    state = vaesdq_u8(state, dec_rks[rounds]);
    vst1q_u8(output, state);

    return NOXTLS_RETURN_SUCCESS;
#else
    (void)key;
    (void)data;
    (void)output;
    (void)type;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

#endif /* NOXTLS_FEATURE_AES_ACCEL_APPLE */
