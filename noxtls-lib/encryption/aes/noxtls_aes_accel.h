/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
*
* File:    noxtls_aes_accel.h
* Summary: Optional AES hardware acceleration backends
*
*/

#ifndef _NOXTLS_AES_ACCEL_H_
#define _NOXTLS_AES_ACCEL_H_

#include <stdint.h>

#include "noxtls_aes.h"
#include "noxtls_common.h"

/**
 * @brief Encrypt one AES block with the AES-NI backend.
 * @param key AES key bytes for the selected key size.
 * @param data Input plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL for null inputs,
 *         or NOXTLS_RETURN_NOT_SUPPORTED when AES-NI is unavailable.
 */
noxtls_return_t noxtls_aes_accel_ni_encrypt_block(const uint8_t *key,
                                                   const uint8_t *data,
                                                   uint8_t *output,
                                                   noxtls_aes_type_t type);
/**
 * @brief Decrypt one AES block with the AES-NI backend.
 * @param key AES key bytes for the selected key size.
 * @param data Input ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL for null inputs,
 *         or NOXTLS_RETURN_NOT_SUPPORTED when AES-NI is unavailable.
 */
noxtls_return_t noxtls_aes_accel_ni_decrypt_block(const uint8_t *key,
                                                   const uint8_t *data,
                                                   uint8_t *output,
                                                   noxtls_aes_type_t type);
/**
 * @brief Encrypt one AES block with the Apple Silicon ARMv8 AES backend.
 * @param key AES key bytes for the selected key size.
 * @param data Input plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL for null inputs,
 *         or NOXTLS_RETURN_NOT_SUPPORTED when ARMv8 AES is unavailable.
 */
noxtls_return_t noxtls_aes_accel_apple_encrypt_block(const uint8_t *key,
                                                      const uint8_t *data,
                                                      uint8_t *output,
                                                      noxtls_aes_type_t type);
/**
 * @brief Decrypt one AES block with the Apple Silicon ARMv8 AES backend.
 * @param key AES key bytes for the selected key size.
 * @param data Input ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL for null inputs,
 *         or NOXTLS_RETURN_NOT_SUPPORTED when ARMv8 AES is unavailable.
 */
noxtls_return_t noxtls_aes_accel_apple_decrypt_block(const uint8_t *key,
                                                      const uint8_t *data,
                                                      uint8_t *output,
                                                      noxtls_aes_type_t type);

#endif /* _NOXTLS_AES_ACCEL_H_ */
