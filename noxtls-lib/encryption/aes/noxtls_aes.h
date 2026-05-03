/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
* 
*
* File:    aes.c
* Summary: Advanced Encryption Standard (AES) Algorithm
*
*/

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

#define AES_128_ROUNDS 10
#define AES_192_ROUNDS 12
#define AES_256_ROUNDS 14

/** Max key schedule size in 32-bit words (AES-256: (14+1)*4 = 60) */
#define AES_MAX_KEY_SCHEDULE_WORDS  (4 * (AES_256_ROUNDS + 1))

#define AES_BLOCK_LENGTH 16

#define AES_ROTR(X, N)      ((X >> N) | (X << (32 - N)))
#define AES_ROTL(X, N)      ((X << N) | (X >> (32 - N)))

typedef enum
{
	AES_128_BIT = 0,
	AES_192_BIT = 1,
	AES_256_BIT = 2,
}aes_type_t;

typedef enum
{
	AES_ECB = 0,
	AES_CBC = 1,
	AES_CTR = 2,
	AES_CFB = 3,
	AES_OFB = 4,
	AES_XTS = 5,
	AES_GCM = 6,
}aes_mode_t;

typedef enum
{
    AES_OP_ENCRYPT = 0,
    AES_OP_DECRYPT = 1,
} aes_operation_t;

typedef struct
{
    uint8_t key[32];
    uint8_t feedback[AES_BLOCK_LENGTH];
    uint8_t partial[AES_BLOCK_LENGTH];
    uint8_t key_len;
    uint8_t partial_len;
    aes_type_t type;
    aes_mode_t mode;
    aes_operation_t op;
    uint8_t initialized;
} aes_context_t;

noxtls_return_t aes_encrypt_data(const uint8_t* key, 
                     const uint8_t* data, 
                     uint32_t data_len,
                     const uint8_t * iv,
                     uint8_t* output, 
                     aes_type_t type,
                     aes_mode_t mode);

noxtls_return_t aes_self_test(void);
void aes_sub_bytes(uint8_t state[4][4]);
void aes_shift_rows(uint8_t state[4][4]);
void aes_mix_columns(uint8_t state[4][4]);
noxtls_return_t aes_add_round_key(uint8_t state[4][4], const uint32_t * w);
noxtls_return_t aes_key_expansion(const uint8_t* key, uint32_t* w, int nk, int rounds);
noxtls_return_t aes_init_block(uint8_t state[4][4], const uint8_t* data);
void print_state_matrix(const uint8_t state[4][4]);

/* AES Mode-Specific Functions */
noxtls_return_t aes_encrypt_ecb(const uint8_t* key,
                    const uint8_t* data,
                    uint32_t data_len,
                    const uint8_t * iv,
                    uint8_t* output,
                    aes_type_t type);
noxtls_return_t aes_decrypt_ecb(const uint8_t* key,
                    const uint8_t* data,
                    uint32_t data_len,
                    const uint8_t * iv,
                    uint8_t* output,
                    aes_type_t type);
noxtls_return_t aes_encrypt_cbc(const uint8_t* key,
                    const uint8_t* data,
                    uint32_t data_len,
                    const uint8_t * iv,
                    uint8_t* output,
                    aes_type_t type);

noxtls_return_t aes_decrypt_cbc(const uint8_t* key,
                    const uint8_t* data,
                    uint32_t data_len,
                    const uint8_t * iv,
                    uint8_t* output,
                    aes_type_t type);

noxtls_return_t aes_init(aes_context_t *ctx,
             const uint8_t *key,
             const uint8_t *iv,
             aes_type_t type,
             aes_mode_t mode,
             aes_operation_t op);

noxtls_return_t aes_update(aes_context_t *ctx,
               const uint8_t *input,
               uint32_t input_len,
               uint8_t *output,
               uint32_t *output_len);

noxtls_return_t aes_final(aes_context_t *ctx,
              uint8_t *output,
              uint32_t *output_len);

#ifdef __cplusplus
}
#endif

#endif /* _AES_H_ */
