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
* File:    noxtls_aes_cmac.h
* Summary: AES-CMAC (RFC 4493 / NIST SP 800-38B) for noxtls_message authentication.
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */

#ifndef _NOXTLS_AES_CMAC_H_
#define _NOXTLS_AES_CMAC_H_

#include <stdint.h>
#include "noxtls_aes.h"
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#if NOXTLS_FEATURE_AES_CMAC

typedef struct
{
    uint8_t key[32];
    uint8_t state[NOXTLS_AES_BLOCK_LENGTH];
    uint8_t subkey1[NOXTLS_AES_BLOCK_LENGTH];
    uint8_t subkey2[NOXTLS_AES_BLOCK_LENGTH];
    uint8_t partial[NOXTLS_AES_BLOCK_LENGTH];
    uint64_t total_len;
    uint8_t key_len;
    uint8_t partial_len;
    uint8_t initialized;
    noxtls_aes_type_t type;
} noxtls_aes_cmac_context_t;

/**
 * @brief Initialize a streaming AES-CMAC context.
 *
 * @param ctx   AES-CMAC context to initialize
 * @param key   AES key (16/24/32 bytes based on type)
 * @param type  AES key type
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t noxtls_aes_cmac_init(noxtls_aes_cmac_context_t *ctx,
                                     const uint8_t *key,
                                     noxtls_aes_type_t type);

/**
 * @brief Update a streaming AES-CMAC context.
 *
 * @param ctx      Initialized AES-CMAC context
 * @param msg      Message chunk bytes
 * @param msg_len  Message chunk length
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t noxtls_aes_cmac_update(noxtls_aes_cmac_context_t *ctx,
                                       const uint8_t *msg,
                                       uint32_t msg_len);

/**
 * @brief Finalize a streaming AES-CMAC computation.
 *
 * @param ctx  Initialized AES-CMAC context
 * @param mac  Output 16-byte MAC
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t noxtls_aes_cmac_final(noxtls_aes_cmac_context_t *ctx,
                                      uint8_t *mac);

/**
 * @brief Compute AES-CMAC over a noxtls_message (RFC 4493).
 *
 * Uses AES-128 only (key_len 16). Output is 16 bytes (full MAC).
 * For BLE Signed Write the caller may use only the first 12 bytes.
 *
 * @param key       AES key (16 bytes for AES-128)
 * @param msg       Message to authenticate
 * @param msg_len   Message length in bytes
 * @param mac       Output buffer for 16-byte MAC
 * @param type      AES key type (NOXTLS_AES_128_BIT recommended)
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t noxtls_aes_cmac(const uint8_t *key,
                         const uint8_t *msg,
                         uint32_t msg_len,
                         uint8_t *mac,
                         noxtls_aes_type_t type);

#endif /* NOXTLS_FEATURE_AES_CMAC */

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_AES_CMAC_H_ */
