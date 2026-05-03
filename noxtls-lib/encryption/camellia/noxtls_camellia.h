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
* File:    noxtls_camellia.h
* Summary: Camellia Cipher Algorithm
*
*/

/** @addtogroup noxtls_encryption */
/** @{ */

#ifndef _NOXTLS_CAMELLIA_H_
#define _NOXTLS_CAMELLIA_H_

/* Standard Includes */
#include <stdint.h>
#include <stdio.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NOXTLS_CAMELLIA_DEBUG (0)

#define CAMELLIA_128_ROUNDS 18
#define CAMELLIA_192_ROUNDS 24
#define CAMELLIA_256_ROUNDS 24

#define CAMELLIA_BLOCK_LENGTH 16

typedef enum
{
	CAMELLIA_128_BIT = 0,
	CAMELLIA_192_BIT = 1,
	CAMELLIA_256_BIT = 2,
} camellia_type_t;

typedef enum
{
	CAMELLIA_ECB = 0,
	CAMELLIA_CBC = 1,
	CAMELLIA_CTR = 2,
	CAMELLIA_CFB = 3,
	CAMELLIA_OFB = 4,
} camellia_mode_t;

typedef enum
{
    CAMELLIA_OP_ENCRYPT = 0,
    CAMELLIA_OP_DECRYPT = 1,
} camellia_operation_t;

typedef struct
{
    uint8_t key[32];
    uint8_t feedback[CAMELLIA_BLOCK_LENGTH];
    uint8_t partial[CAMELLIA_BLOCK_LENGTH];
    uint8_t key_len;
    uint8_t partial_len;
    camellia_type_t type;
    camellia_mode_t mode;
    camellia_operation_t op;
    uint8_t initialized;
} camellia_context_t;

noxtls_return_t camellia_encrypt_data(const uint8_t* key,
                          const uint8_t* data,
                          uint32_t data_len,
                          const uint8_t * iv,
                          uint8_t* output,
                          camellia_type_t type,
                          camellia_mode_t mode);

noxtls_return_t camellia_decrypt_data(const uint8_t* key,
                          const uint8_t* data,
                          uint32_t data_len,
                          const uint8_t * iv,
                          uint8_t* output,
                          camellia_type_t type,
                          camellia_mode_t mode);

noxtls_return_t camellia_self_test(void);

noxtls_return_t camellia_init(camellia_context_t *ctx,
                  const uint8_t *key,
                  const uint8_t *iv,
                  camellia_type_t type,
                  camellia_mode_t mode,
                  camellia_operation_t op);

noxtls_return_t camellia_update(camellia_context_t *ctx,
                    const uint8_t *input,
                    uint32_t input_len,
                    uint8_t *output,
                    uint32_t *output_len);

noxtls_return_t camellia_final(camellia_context_t *ctx,
                   uint8_t *output,
                   uint32_t *output_len);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_CAMELLIA_H_ */

