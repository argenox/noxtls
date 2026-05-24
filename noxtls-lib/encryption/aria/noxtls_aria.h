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
* File:    noxtls_aria.h
* Summary: ARIA Block Cipher Algorithm
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */
/** @{ */

#ifndef _NOXTLS_ARIA_H_
#define _NOXTLS_ARIA_H_

/* Standard Includes */
#include <stdint.h>
#include <stdio.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NOXTLS_ARIA_DEBUG (0)

#define NOXTLS_ARIA_128_ROUNDS 12
#define NOXTLS_ARIA_192_ROUNDS 14
#define NOXTLS_ARIA_256_ROUNDS 16

#define NOXTLS_ARIA_BLOCK_LENGTH 16

typedef enum
{
	NOXTLS_ARIA_128_BIT = 0,
	NOXTLS_ARIA_192_BIT = 1,
	NOXTLS_ARIA_256_BIT = 2,
} noxtls_aria_type_t;

typedef enum
{
	NOXTLS_ARIA_ECB = 0,
	NOXTLS_ARIA_CBC = 1,
	NOXTLS_ARIA_CTR = 2,
	NOXTLS_ARIA_CFB = 3,
	NOXTLS_ARIA_OFB = 4,
} noxtls_aria_mode_t;

typedef enum
{
    NOXTLS_ARIA_OP_ENCRYPT = 0,
    NOXTLS_ARIA_OP_DECRYPT = 1,
} noxtls_aria_operation_t;

/* ARIA Key Schedule Structure */
typedef struct
{
	uint8_t round_key[17][16];  /* Round keys (max 16 rounds + 1 initial key) */
	int rounds;                  /* Number of rounds */
	noxtls_aria_type_t key_type;        /* Key size type */
} noxtls_aria_key_t;

typedef struct
{
    uint8_t key[32];
    uint8_t feedback[NOXTLS_ARIA_BLOCK_LENGTH];
    uint8_t partial[NOXTLS_ARIA_BLOCK_LENGTH];
    uint8_t key_len;
    uint8_t partial_len;
    noxtls_aria_type_t type;
    noxtls_aria_mode_t mode;
    noxtls_aria_operation_t op;
    uint8_t initialized;
    noxtls_aria_key_t enc_key;
    noxtls_aria_key_t dec_key;
} noxtls_aria_context_t;

/* Core ARIA Functions */
noxtls_return_t noxtls_aria_set_encrypt_key(const uint8_t *user_key, noxtls_aria_type_t key_type, noxtls_aria_key_t *key);
noxtls_return_t noxtls_aria_set_decrypt_key(const uint8_t *user_key, noxtls_aria_type_t key_type, noxtls_aria_key_t *key);
void noxtls_aria_encrypt_block(const noxtls_aria_key_t *key, const uint8_t in[16], uint8_t out[16]);
void noxtls_aria_decrypt_block(const noxtls_aria_key_t *key, const uint8_t in[16], uint8_t out[16]);

/* High-level ARIA Functions */
noxtls_return_t noxtls_aria_encrypt_data(const uint8_t* key,
                      const uint8_t* data,
                      uint32_t data_len,
                      const uint8_t * iv,
                      uint8_t* output,
                      noxtls_aria_type_t type,
                      noxtls_aria_mode_t mode);

noxtls_return_t noxtls_aria_decrypt_data(const uint8_t* key,
                      const uint8_t* data,
                      uint32_t data_len,
                      const uint8_t * iv,
                      uint8_t* output,
                      noxtls_aria_type_t type,
                      noxtls_aria_mode_t mode);

noxtls_return_t noxtls_aria_self_test(void);

/* ARIA Mode-Specific Functions */
noxtls_return_t noxtls_aria_encrypt_cbc(const uint8_t* key,
                     const uint8_t* data,
                     uint32_t data_len,
                     const uint8_t * iv,
                     uint8_t* output,
                     noxtls_aria_type_t type);

noxtls_return_t noxtls_aria_decrypt_cbc(const uint8_t* key,
                     const uint8_t* data,
                     uint32_t data_len,
                     const uint8_t * iv,
                     uint8_t* output,
                     noxtls_aria_type_t type);

noxtls_return_t noxtls_aria_init(noxtls_aria_context_t *ctx,
              const uint8_t *key,
              const uint8_t *iv,
              noxtls_aria_type_t type,
              noxtls_aria_mode_t mode,
              noxtls_aria_operation_t op);

noxtls_return_t noxtls_aria_update(noxtls_aria_context_t *ctx,
                const uint8_t *input,
                uint32_t input_len,
                uint8_t *output,
                uint32_t *output_len);

noxtls_return_t noxtls_aria_final(noxtls_aria_context_t *ctx,
               uint8_t *output,
               uint32_t *output_len);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_ARIA_H_ */

