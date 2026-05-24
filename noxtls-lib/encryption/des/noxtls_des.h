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
* File:    noxtls_des.h
* Summary: Data Encryption Standard (DES) and Triple-DES (3DES) Algorithm
*
* The DES and 3DES Algorithms are broken and should not be used for new systems.
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */
/** @{ */

#ifndef _NOXTLS_DES_H_
#define _NOXTLS_DES_H_

#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NOXTLS_DES_BLOCK_LENGTH  8
#define NOXTLS_DES_KEY_LENGTH    8   /* 56-bit key in 8 bytes (parity bits in low bit of each byte) */
#define NOXTLS_DES3_KEY_LENGTH   24  /* 168-bit key: K1||K2||K3 (each 8 bytes). 2-key: K1||K2||K1. */

typedef enum {
    NOXTLS_DES_56_BIT = 0,   /* Single DES: 8-byte key */
    NOXTLS_DES3_2KEY  = 1,   /* 3DES with 2 keys: 16 bytes, used as K1,K2,K1 */
    NOXTLS_DES3_3KEY  = 2,   /* 3DES with 3 keys: 24 bytes */
} noxtls_des_type_t;

/**
 * @brief Encrypt a single 8-byte block with DES.
 * @param key 8-byte key (56-bit effective).
 * @param data 8-byte input block.
 * @param output 8-byte output block.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL or NOXTLS_RETURN_INVALID_BLOCK_SIZE on failure.
 */
noxtls_return_t noxtls_des_encrypt_block(const uint8_t *key, const uint8_t *data, uint8_t *output);

/**
 * @brief Decrypt a single 8-byte block with DES.
 */
noxtls_return_t noxtls_des_decrypt_block(const uint8_t *key, const uint8_t *data, uint8_t *output);

/**
 * @brief Encrypt a single 8-byte block with 3DES (EDE: Encrypt with K1, Decrypt with K2, Encrypt with K3).
 * @param key 16 bytes (2-key: K1,K2) or 24 bytes (3-key: K1,K2,K3). For 2-key, K3 = K1.
 * @param key_len 16 or 24.
 * @param data 8-byte input block.
 * @param output 8-byte output block.
 */
noxtls_return_t noxtls_des3_encrypt_block(const uint8_t *key, uint32_t key_len, const uint8_t *data, uint8_t *output);

/**
 * @brief Decrypt a single 8-byte block with 3DES (DED: Decrypt with K3, Encrypt with K2, Decrypt with K1).
 */
noxtls_return_t noxtls_des3_decrypt_block(const uint8_t *key, uint32_t key_len, const uint8_t *data, uint8_t *output);

/**
 * @brief DES CBC encrypt. IV 8 bytes; data_len must be multiple of 8.
 */
noxtls_return_t noxtls_des_encrypt_cbc(const uint8_t *key,
                    const uint8_t *data,
                    uint32_t data_len,
                    const uint8_t *iv,
                    uint8_t *output);

/**
 * @brief DES CBC decrypt.
 */
noxtls_return_t noxtls_des_decrypt_cbc(const uint8_t *key,
                    const uint8_t *data,
                    uint32_t data_len,
                    const uint8_t *iv,
                    uint8_t *output);

/**
 * @brief 3DES CBC encrypt. key 16 or 24 bytes; IV 8 bytes; data_len multiple of 8.
 */
noxtls_return_t des3_encrypt_cbc(const uint8_t *key,
                     uint32_t key_len,
                     const uint8_t *data,
                     uint32_t data_len,
                     const uint8_t *iv,
                     uint8_t *output);

/**
 * @brief 3DES CBC decrypt.
 */
noxtls_return_t des3_decrypt_cbc(const uint8_t *key,
                     uint32_t key_len,
                     const uint8_t *data,
                     uint32_t data_len,
                     const uint8_t *iv,
                     uint8_t *output);

/**
 * @brief Self-test (known-answer); returns NOXTLS_RETURN_SUCCESS on pass.
 */
noxtls_return_t noxtls_des_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_DES_H_ */
/** @} */
