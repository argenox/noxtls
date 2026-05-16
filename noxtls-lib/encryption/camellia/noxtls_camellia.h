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

#define NOXTLS_CAMELLIA_128_ROUNDS 18
#define NOXTLS_CAMELLIA_192_ROUNDS 24
#define NOXTLS_CAMELLIA_256_ROUNDS 24

#define NOXTLS_CAMELLIA_BLOCK_LENGTH 16

typedef enum
{
	NOXTLS_CAMELLIA_128_BIT = 0,
	NOXTLS_CAMELLIA_192_BIT = 1,
	NOXTLS_CAMELLIA_256_BIT = 2,
} noxtls_camellia_type_t;

typedef enum
{
	NOXTLS_CAMELLIA_ECB = 0,
	NOXTLS_CAMELLIA_CBC = 1,
	NOXTLS_CAMELLIA_CTR = 2,
	NOXTLS_CAMELLIA_CFB = 3,
	NOXTLS_CAMELLIA_OFB = 4,
} noxtls_camellia_mode_t;

typedef enum
{
    NOXTLS_CAMELLIA_OP_ENCRYPT = 0,
    NOXTLS_CAMELLIA_OP_DECRYPT = 1,
} noxtls_camellia_operation_t;

typedef struct
{
    uint8_t key[32];
    uint8_t feedback[NOXTLS_CAMELLIA_BLOCK_LENGTH];
    uint8_t partial[NOXTLS_CAMELLIA_BLOCK_LENGTH];
    uint8_t key_len;
    uint8_t partial_len;
    noxtls_camellia_type_t type;
    noxtls_camellia_mode_t mode;
    noxtls_camellia_operation_t op;
    uint8_t initialized;
} noxtls_camellia_context_t;

noxtls_return_t noxtls_camellia_encrypt_data(const uint8_t* key,
                          const uint8_t* data,
                          uint32_t data_len,
                          const uint8_t * iv,
                          uint8_t* output,
                          noxtls_camellia_type_t type,
                          noxtls_camellia_mode_t mode);

noxtls_return_t noxtls_camellia_decrypt_data(const uint8_t* key,
                          const uint8_t* data,
                          uint32_t data_len,
                          const uint8_t * iv,
                          uint8_t* output,
                          noxtls_camellia_type_t type,
                          noxtls_camellia_mode_t mode);

noxtls_return_t noxtls_camellia_self_test(void);

noxtls_return_t noxtls_camellia_init(noxtls_camellia_context_t *ctx,
                  const uint8_t *key,
                  const uint8_t *iv,
                  noxtls_camellia_type_t type,
                  noxtls_camellia_mode_t mode,
                  noxtls_camellia_operation_t op);

noxtls_return_t noxtls_camellia_update(noxtls_camellia_context_t *ctx,
                    const uint8_t *input,
                    uint32_t input_len,
                    uint8_t *output,
                    uint32_t *output_len);

noxtls_return_t noxtls_camellia_final(noxtls_camellia_context_t *ctx,
                   uint8_t *output,
                   uint32_t *output_len);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_CAMELLIA_H_ */

