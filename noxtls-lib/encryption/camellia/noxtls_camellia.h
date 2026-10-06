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
* File:    noxtls_camellia.h
* Summary: Camellia Cipher Algorithm
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */
/** @{ */

#ifndef NOXTLS_CAMELLIA_H_
#define NOXTLS_CAMELLIA_H_

/* Standard Includes */
#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NOXTLS_CAMELLIA_DEBUG (0)

#define NOXTLS_CAMELLIA_128_ROUNDS 18
#define NOXTLS_CAMELLIA_192_ROUNDS 24
#define NOXTLS_CAMELLIA_256_ROUNDS 24

#define NOXTLS_CAMELLIA_BLOCK_LENGTH 16U

/* Unsigned identifiers (MISRA C:2025 Rule 10.3); values match historical enums. */
typedef uint32_t noxtls_camellia_type_t;
#define NOXTLS_CAMELLIA_128_BIT ((noxtls_camellia_type_t)0U)
#define NOXTLS_CAMELLIA_192_BIT ((noxtls_camellia_type_t)1U)
#define NOXTLS_CAMELLIA_256_BIT ((noxtls_camellia_type_t)2U)

typedef uint32_t noxtls_camellia_mode_t;
#define NOXTLS_CAMELLIA_ECB ((noxtls_camellia_mode_t)0U)
#define NOXTLS_CAMELLIA_CBC ((noxtls_camellia_mode_t)1U)
#define NOXTLS_CAMELLIA_CTR ((noxtls_camellia_mode_t)2U)
#define NOXTLS_CAMELLIA_CFB ((noxtls_camellia_mode_t)3U)
#define NOXTLS_CAMELLIA_OFB ((noxtls_camellia_mode_t)4U)

typedef uint32_t noxtls_camellia_operation_t;
#define NOXTLS_CAMELLIA_OP_ENCRYPT ((noxtls_camellia_operation_t)0U)
#define NOXTLS_CAMELLIA_OP_DECRYPT ((noxtls_camellia_operation_t)1U)

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


noxtls_return_t noxtls_camellia_encrypt_ecb(const uint8_t* key,
                          const uint8_t* data,
                          uint32_t data_len,
                          const uint8_t * iv,
                          uint8_t* output,
                          noxtls_camellia_type_t type);
noxtls_return_t noxtls_camellia_decrypt_ecb(const uint8_t* key,
                          const uint8_t* data,
                          uint32_t data_len,
                          const uint8_t * iv,
                          uint8_t* output,
                          noxtls_camellia_type_t type);
noxtls_return_t noxtls_camellia_encrypt_cbc(const uint8_t* key,
                          const uint8_t* data,
                          uint32_t data_len,
                          const uint8_t * iv,
                          uint8_t* output,
                          noxtls_camellia_type_t type);
noxtls_return_t noxtls_camellia_decrypt_cbc(const uint8_t* key,
                          const uint8_t* data,
                          uint32_t data_len,
                          const uint8_t * iv,
                          uint8_t* output,
                          noxtls_camellia_type_t type);
noxtls_return_t noxtls_camellia_encrypt_ctr(const uint8_t* key,
                          const uint8_t* data,
                          uint32_t data_len,
                          const uint8_t * iv,
                          uint8_t* output,
                          noxtls_camellia_type_t type);
noxtls_return_t noxtls_camellia_decrypt_ctr(const uint8_t* key,
                          const uint8_t* data,
                          uint32_t data_len,
                          const uint8_t * iv,
                          uint8_t* output,
                          noxtls_camellia_type_t type);
noxtls_return_t noxtls_camellia_encrypt_cfb(const uint8_t* key,
                          const uint8_t* data,
                          uint32_t data_len,
                          const uint8_t * iv,
                          uint8_t* output,
                          noxtls_camellia_type_t type);
noxtls_return_t noxtls_camellia_decrypt_cfb(const uint8_t* key,
                          const uint8_t* data,
                          uint32_t data_len,
                          const uint8_t * iv,
                          uint8_t* output,
                          noxtls_camellia_type_t type);
noxtls_return_t noxtls_camellia_encrypt_ofb(const uint8_t* key,
                          const uint8_t* data,
                          uint32_t data_len,
                          const uint8_t * iv,
                          uint8_t* output,
                          noxtls_camellia_type_t type);
noxtls_return_t noxtls_camellia_decrypt_ofb(const uint8_t* key,
                          const uint8_t* data,
                          uint32_t data_len,
                          const uint8_t * iv,
                          uint8_t* output,
                          noxtls_camellia_type_t type);

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

#endif /* NOXTLS_CAMELLIA_H_ */

