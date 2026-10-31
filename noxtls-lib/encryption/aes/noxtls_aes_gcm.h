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
* File:    noxtls_aes_gcm.h
* Summary: AES-GCM mode implementation
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */
/** @{ */

#ifndef NOXTLS_AES_GCM_H_
#define NOXTLS_AES_GCM_H_

#include <stdint.h>
#include "noxtls_aes.h"
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief AES-GCM authenticated encryption (SP 800-38D) with a 96-bit IV and a
 *        16-byte tag.
 *
 * In-place operation: the output buffer may be exactly the input buffer
 * (output == input, e.g. TLS records encrypted/decrypted in place). Partially
 * overlapping buffers (output != input but overlapping) are not supported.
 * On any failure the output is wiped, so with in-place use a rejected record's
 * ciphertext is destroyed; no unauthenticated plaintext is ever returned.
 * Accelerator ports selected through the *_accel_port hooks must preserve
 * this exact-aliasing guarantee.
 */
noxtls_return_t noxtls_aes_gcm_encrypt(const uint8_t *key, noxtls_aes_type_t type,
                    const uint8_t *nonce,
                    const uint8_t *aad, uint32_t aad_len,
                    const uint8_t *plaintext, uint32_t plaintext_len,
                    uint8_t *ciphertext,
                    uint8_t *tag);

/**
 * @brief AES-GCM authenticated decryption: the tag over AAD and the whole
 *        ciphertext is verified before any plaintext is written.
 *
 * In-place operation: the output buffer may be exactly the input buffer
 * (output == input, e.g. TLS records encrypted/decrypted in place). Partially
 * overlapping buffers (output != input but overlapping) are not supported.
 * On any failure the output is wiped, so with in-place use a rejected record's
 * ciphertext is destroyed; no unauthenticated plaintext is ever returned.
 * Accelerator ports selected through the *_accel_port hooks must preserve
 * this exact-aliasing guarantee.
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_BAD_DATA on tag mismatch, or an error.
 */
noxtls_return_t noxtls_aes_gcm_decrypt(const uint8_t *key, noxtls_aes_type_t type,
                    const uint8_t *nonce,
                    const uint8_t *aad, uint32_t aad_len,
                    const uint8_t *ciphertext, uint32_t ciphertext_len,
                    const uint8_t *tag,
                    uint8_t *plaintext);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_AES_GCM_H_ */
