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
* File:    aes.h
* Summary: Advanced Encryption Standard (AES) Algorithm
*
*****************************************************************************/

/**
 * @defgroup noxtls_encryption Encryption
 * @brief AES, ARIA, Camellia, ChaCha20-Poly1305 block and stream ciphers.
 * @addtogroup noxtls
 */
/** @{ */

#ifndef _AES_H_
#define _AES_H_

/* Standard Includes */
#include <stdint.h>
#include <stdio.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NOXTLS_AES_DEBUG (0)

#define NOXTLS_AES_128_ROUNDS 10
#define NOXTLS_AES_192_ROUNDS 12
#define NOXTLS_AES_256_ROUNDS 14

/** Max key schedule size in 32-bit words (AES-256: (14+1)*4 = 60) */
#define NOXTLS_AES_MAX_KEY_SCHEDULE_WORDS  (4 * (NOXTLS_AES_256_ROUNDS + 1))

#define NOXTLS_AES_BLOCK_LENGTH 16

#define NOXTLS_AES_ROTR(X, N)      ((X >> N) | (X << (32 - N)))
#define NOXTLS_AES_ROTL(X, N)      ((X << N) | (X >> (32 - N)))

typedef enum
{
	NOXTLS_AES_128_BIT = 0,
	NOXTLS_AES_192_BIT = 1,
	NOXTLS_AES_256_BIT = 2,
} noxtls_aes_type_t;

typedef enum
{
	NOXTLS_AES_ECB = 0,
	NOXTLS_AES_CBC = 1,
	NOXTLS_AES_CTR = 2,
	NOXTLS_AES_CFB = 3,
	NOXTLS_AES_OFB = 4,
	NOXTLS_AES_XTS = 5,
	NOXTLS_AES_GCM = 6,
} noxtls_aes_mode_t;

typedef enum
{
    NOXTLS_AES_OP_ENCRYPT = 0,
    NOXTLS_AES_OP_DECRYPT = 1,
} noxtls_aes_operation_t;

typedef struct
{
    uint8_t key[32];
    uint32_t round_keys[NOXTLS_AES_MAX_KEY_SCHEDULE_WORDS];
    uint8_t feedback[NOXTLS_AES_BLOCK_LENGTH];
    uint8_t partial[NOXTLS_AES_BLOCK_LENGTH];
    uint8_t key_len;
    uint8_t partial_len;
    uint8_t rounds;
    uint8_t key_words;
    uint8_t round_keys_ready;
    noxtls_aes_type_t type;
    noxtls_aes_mode_t mode;
    noxtls_aes_operation_t op;
    uint8_t initialized;
} noxtls_aes_context_t;

/**
 * @brief Encrypt data using a selected AES mode.
 * @param key AES key bytes for the selected key size.
 * @param data Input plaintext buffer.
 * @param data_len Input length in bytes.
 * @param iv Initialization vector, nonce, or tweak material required by the selected mode.
 * @param output Output ciphertext buffer.
 * @param type AES key size selector.
 * @param mode AES operation mode selector.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_encrypt_data(const uint8_t* key, 
                     const uint8_t* data, 
                     uint32_t data_len,
                     const uint8_t * iv,
                     uint8_t* output, 
                     noxtls_aes_type_t type,
                     noxtls_aes_mode_t mode);

/**
 * @brief Run AES implementation self-tests.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_self_test(void);
/**
 * @brief Apply the AES SubBytes transform to a state matrix.
 * @param state AES state matrix to update in place.
 * @return None.
 */
void noxtls_aes_sub_bytes(uint8_t state[4][4]);
/**
 * @brief Apply the AES ShiftRows transform to a state matrix.
 * @param state AES state matrix to update in place.
 * @return None.
 */
void noxtls_aes_shift_rows(uint8_t state[4][4]);
/**
 * @brief Apply the AES MixColumns transform to a state matrix.
 * @param state AES state matrix to update in place.
 * @return None.
 */
void noxtls_aes_mix_columns(uint8_t state[4][4]);
/**
 * @brief XOR a round key into an AES state matrix.
 * @param state AES state matrix to update in place.
 * @param w Round-key words to add to the state.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
noxtls_return_t noxtls_aes_add_round_key(uint8_t state[4][4], const uint32_t * w);
/**
 * @brief Expand an AES key into key schedule words.
 * @param key AES key bytes.
 * @param w Output key schedule words.
 * @param nk Number of 32-bit words in the AES key.
 * @param rounds Number of AES rounds for the selected key size.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_key_expansion(const uint8_t* key, uint32_t* w, int nk, int rounds);
/**
 * @brief Initialize an AES state matrix from a 16-byte block.
 * @param state AES state matrix to initialize.
 * @param data Input block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
noxtls_return_t noxtls_aes_init_block(uint8_t state[4][4], const uint8_t* data);
/**
 * @brief Print an AES state matrix for debugging.
 * @param state AES state matrix to print.
 * @return None.
 */
void noxtls_print_state_matrix(const uint8_t state[4][4]);

/* AES Mode-Specific Functions */
/**
 * @brief Encrypt data with AES-ECB.
 * @param key AES key bytes for the selected key size.
 * @param data Input plaintext buffer.
 * @param data_len Input length in bytes.
 * @param iv Unused for ECB; accepted for API consistency.
 * @param output Output ciphertext buffer.
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_encrypt_ecb(const uint8_t* key,
                    const uint8_t* data,
                    uint32_t data_len,
                    const uint8_t * iv,
                    uint8_t* output,
                    noxtls_aes_type_t type);
/**
 * @brief Decrypt data with AES-ECB.
 * @param key AES key bytes for the selected key size.
 * @param data Input ciphertext buffer.
 * @param data_len Input length in bytes.
 * @param iv Unused for ECB; accepted for API consistency.
 * @param output Output plaintext buffer.
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_decrypt_ecb(const uint8_t* key,
                    const uint8_t* data,
                    uint32_t data_len,
                    const uint8_t * iv,
                    uint8_t* output,
                    noxtls_aes_type_t type);
/**
 * @brief Encrypt data with AES-CBC.
 * @param key AES key bytes for the selected key size.
 * @param data Input plaintext buffer.
 * @param data_len Input length in bytes.
 * @param iv Initialization vector of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output ciphertext buffer.
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_encrypt_cbc(const uint8_t* key,
                    const uint8_t* data,
                    uint32_t data_len,
                    const uint8_t * iv,
                    uint8_t* output,
                    noxtls_aes_type_t type);

/**
 * @brief Decrypt data with AES-CBC.
 * @param key AES key bytes for the selected key size.
 * @param data Input ciphertext buffer.
 * @param data_len Input length in bytes.
 * @param iv Initialization vector of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output plaintext buffer.
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_decrypt_cbc(const uint8_t* key,
                    const uint8_t* data,
                    uint32_t data_len,
                    const uint8_t * iv,
                    uint8_t* output,
                    noxtls_aes_type_t type);

/**
 * @brief Encrypt data with AES-CTR.
 * @param key AES key bytes for the selected key size.
 * @param data Input plaintext buffer.
 * @param data_len Input length in bytes.
 * @param iv Initial counter block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output ciphertext buffer.
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_encrypt_ctr(const uint8_t* key,
                    const uint8_t* data,
                    uint32_t data_len,
                    const uint8_t * iv,
                    uint8_t* output,
                    noxtls_aes_type_t type);

/**
 * @brief Initialize a streaming AES context.
 * @param ctx AES context to initialize.
 * @param key AES key bytes for the selected key size.
 * @param iv Initialization vector, nonce, or feedback block required by the mode.
 * @param type AES key size selector.
 * @param mode AES operation mode selector.
 * @param op AES encrypt/decrypt operation selector.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_init(noxtls_aes_context_t *ctx,
             const uint8_t *key,
             const uint8_t *iv,
             noxtls_aes_type_t type,
             noxtls_aes_mode_t mode,
             noxtls_aes_operation_t op);

/**
 * @brief Process data through a streaming AES context.
 * @param ctx Initialized AES context.
 * @param input Input buffer.
 * @param input_len Input length in bytes.
 * @param output Output buffer.
 * @param output_len Output length in bytes.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_update(noxtls_aes_context_t *ctx,
               const uint8_t *input,
               uint32_t input_len,
               uint8_t *output,
               uint32_t *output_len);

/**
 * @brief Finalize a streaming AES operation.
 * @param ctx Initialized AES context.
 * @param output Output buffer for any final bytes.
 * @param output_len Output length in bytes.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_final(noxtls_aes_context_t *ctx,
              uint8_t *output,
              uint32_t *output_len);

#ifdef __cplusplus
}
#endif

#endif /* _AES_H_ */
