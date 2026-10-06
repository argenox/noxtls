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
* File:    noxtls_aes_internal.h
* Summary: Internal AES functions for mode implementations
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */
/** @{ */

#ifndef AES_INTERNAL_H_
#define AES_INTERNAL_H_

#include <stdint.h>
#include "noxtls_aes.h"
#include "noxtls_common.h"
#include "noxtls_ct.h"

/**
 * @brief Return an actual cipher failure after erasing bounded output spans.
 * @internal
 *
 * Every expression is evaluated once. Callers pass known writable spans; zero
 * length / NULL auxiliary output is permitted. This is not a fallback hook.
 */
#define NOXTLS_AES_CHECK(operation, output, length, auxiliary, auxiliary_length) \
    do { \
        const noxtls_return_t noxtls_block_status = (operation); \
        if (noxtls_block_status != NOXTLS_RETURN_SUCCESS) { \
            noxtls_secure_zero((output), (length)); \
            noxtls_secure_zero((auxiliary), (auxiliary_length)); \
            return noxtls_block_status; \
        } \
    } while (0)

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t noxtls_aes_accel_backend_t;
#define NOXTLS_AES_ACCEL_BACKEND_SOFTWARE ((noxtls_aes_accel_backend_t)0U) /**< Software AES implementation. */

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
 * @brief Prepare an internal AES context with cached round keys.
 * @param ctx AES context to populate.
 * @param key AES key bytes for the selected key size.
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_prepare_context(noxtls_aes_context_t *ctx, const uint8_t *key, noxtls_aes_type_t type);

/**
 * @brief Encrypt one AES block through a prepared AES context.
 * @param ctx Prepared AES context with cached round keys.
 * @param data Input plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_encrypt_block_ctx_internal(const noxtls_aes_context_t *ctx, const uint8_t *data, uint8_t *output);

/**
 * @brief Encrypt one AES block through the software backend only.
 * @param ctx Prepared AES context with cached software round keys.
 * @param data Input plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @return NOXTLS_RETURN_SUCCESS on success or a noxtls_return_t error code.
 */
noxtls_return_t noxtls_aes_encrypt_block_ctx_software_internal(const noxtls_aes_context_t *ctx, const uint8_t *data, uint8_t *output);

/**
 * @brief Report which AES block backend is compiled as active for this target.
 * @return The selected AES acceleration backend identifier.
 */
noxtls_aes_accel_backend_t noxtls_aes_get_accel_backend(void);

#ifdef __cplusplus
}
#endif

#endif /* AES_INTERNAL_H_ */
