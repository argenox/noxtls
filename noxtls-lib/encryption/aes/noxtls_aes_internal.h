/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
* 
*
* File:    noxtls_aes_internal.h
* Summary: Internal AES functions for mode implementations
*
*/

/** @addtogroup noxtls_encryption */
/** @{ */

#ifndef _AES_INTERNAL_H_
#define _AES_INTERNAL_H_

#include <stdint.h>
#include "noxtls_aes.h"
#include "noxtls_common.h"

typedef enum
{
    NOXTLS_AES_ACCEL_BACKEND_SOFTWARE = 0,
    NOXTLS_AES_ACCEL_BACKEND_NI = 1,
    NOXTLS_AES_ACCEL_BACKEND_APPLE = 2
} noxtls_aes_accel_backend_t;

/**
 * @brief Encrypt one AES block through the configured block backend.
 * @param key AES key bytes for the selected key size.
 * @param data Input plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_encrypt_block_internal(const uint8_t* key, const uint8_t* data, uint8_t* output, noxtls_aes_type_t type);

/**
 * @brief Decrypt one AES block through the configured block backend.
 * @param key AES key bytes for the selected key size.
 * @param data Input ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_decrypt_block_internal(const uint8_t* key, const uint8_t* data, uint8_t* output, noxtls_aes_type_t type);

/**
 * @brief Report which AES block backend is compiled as active for this target.
 * @return The selected AES acceleration backend identifier.
 */
noxtls_aes_accel_backend_t noxtls_aes_get_accel_backend(void);

#endif /* _AES_INTERNAL_H_ */

