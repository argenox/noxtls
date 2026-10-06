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
* File:    noxtls_aes_accel.h
* Summary: Optional AES hardware acceleration backends
*
*****************************************************************************/

#ifndef NOXTLS_AES_ACCEL_H_
#define NOXTLS_AES_ACCEL_H_

#include <stdint.h>

#include "noxtls_aes.h"
#include "noxtls_common.h"

#ifndef NOXTLS_FEATURE_AES_ACCEL_NI
#define NOXTLS_FEATURE_AES_ACCEL_NI 0
#endif
#ifndef NOXTLS_FEATURE_AES_ACCEL_APPLE
#define NOXTLS_FEATURE_AES_ACCEL_APPLE 0
#endif
#ifndef NOXTLS_FEATURE_STM32_HW_AES_ONLY
#define NOXTLS_FEATURE_STM32_HW_AES_ONLY 0
#endif

#if NOXTLS_FEATURE_AES_ACCEL_NI
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
#endif /* NOXTLS_FEATURE_AES_ACCEL_NI */

#if NOXTLS_FEATURE_AES_ACCEL_APPLE
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
#endif /* NOXTLS_FEATURE_AES_ACCEL_APPLE */

#if NOXTLS_FEATURE_STM32_HW_AES_ONLY
noxtls_return_t noxtls_aes_accel_stm32_encrypt_block(const uint8_t *key,
                                                      const uint8_t *data,
                                                      uint8_t *output,
                                                      noxtls_aes_type_t type);
noxtls_return_t noxtls_aes_accel_stm32_decrypt_block(const uint8_t *key,
                                                      const uint8_t *data,
                                                      uint8_t *output,
                                                      noxtls_aes_type_t type);

#endif /* NOXTLS_FEATURE_STM32_HW_AES_ONLY */

/**
 * @brief Encrypt one AES block with the active platform acceleration hook.
 * @param key AES key bytes for the selected key size.
 * @param data Input plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL for null inputs,
 *         or NOXTLS_RETURN_NOT_SUPPORTED when no platform backend is available.
 */
noxtls_return_t noxtls_aes_accel_port_encrypt_block(const uint8_t *key,
                                                     const uint8_t *data,
                                                     uint8_t *output,
                                                     noxtls_aes_type_t type);

/**
 * @brief Decrypt one AES block with the active platform acceleration hook.
 * @param key AES key bytes for the selected key size.
 * @param data Input ciphertext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param output Output plaintext block of NOXTLS_AES_BLOCK_LENGTH bytes.
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL for null inputs,
 *         or NOXTLS_RETURN_NOT_SUPPORTED when no platform backend is available.
 */
noxtls_return_t noxtls_aes_accel_port_decrypt_block(const uint8_t *key,
                                                     const uint8_t *data,
                                                     uint8_t *output,
                                                     noxtls_aes_type_t type);

/**
 * @brief Encrypt a sequence of contiguous AES blocks with one platform setup.
 * @param key AES key bytes for the selected key size.
 * @param input Contiguous input blocks (`block_count * NOXTLS_AES_BLOCK_LENGTH` bytes).
 * @param output Contiguous output blocks (`block_count * NOXTLS_AES_BLOCK_LENGTH` bytes).
 * @param block_count Number of 16-byte blocks to process.
 * @param type AES key size selector.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL for null inputs,
 *         NOXTLS_RETURN_NOT_SUPPORTED when no platform backend is available, or
 *         NOXTLS_RETURN_INVALID_KEY_SIZE for unknown key sizes.
 */
noxtls_return_t noxtls_aes_accel_port_encrypt_blocks(const uint8_t *key,
                                                      const uint8_t *input,
                                                      uint8_t *output,
                                                      uint32_t block_count,
                                                      noxtls_aes_type_t type);

/**
 * @brief Platform hook for AES-GCM encryption.
 * @return NOXTLS_RETURN_SUCCESS when platform AEAD path succeeded,
 *         NOXTLS_RETURN_NOT_SUPPORTED to use software GCM, or other errors.
 */
noxtls_return_t noxtls_aes_gcm_encrypt_accel_port(const uint8_t *key,
                                                   noxtls_aes_type_t type,
                                                   const uint8_t *nonce,
                                                   const uint8_t *aad,
                                                   uint32_t aad_len,
                                                   const uint8_t *plaintext,
                                                   uint32_t plaintext_len,
                                                   uint8_t *ciphertext,
                                                   uint8_t *tag);

/**
 * @brief Platform hook for AES-GCM decryption.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_BAD_DATA on auth failure,
 *         NOXTLS_RETURN_NOT_SUPPORTED to use software GCM, or other errors.
 */
noxtls_return_t noxtls_aes_gcm_decrypt_accel_port(const uint8_t *key,
                                                   noxtls_aes_type_t type,
                                                   const uint8_t *nonce,
                                                   const uint8_t *aad,
                                                   uint32_t aad_len,
                                                   const uint8_t *ciphertext,
                                                   uint32_t ciphertext_len,
                                                   const uint8_t *tag,
                                                   uint8_t *plaintext);

/** Cipher modes routed through noxtls_aes_mode_accel_port(). */
typedef enum
{
    NOXTLS_AES_ACCEL_MODE_ECB = 0, /**< ECB (NIST SP 800-38A §6.1). */
    NOXTLS_AES_ACCEL_MODE_CBC = 1, /**< CBC (NIST SP 800-38A §6.2). */
    NOXTLS_AES_ACCEL_MODE_CTR = 2  /**< CTR with a 128-bit big-endian counter (NIST SP 800-38A §6.5, B.1). */
} noxtls_aes_accel_mode_t;

/**
 * @brief Optional platform hook: a whole ECB / CBC / CTR request in hardware.
 *
 * Called by noxtls_aes_{en,de}crypt_{ecb,cbc,ctr}() when NOXTLS_PORT_AES_MODE_ACCEL
 * is set (common/noxtls_accel_port.h).
 *
 * @param[in]  mode    Cipher mode.
 * @param[in]  decrypt Non-zero to decrypt (ignored by CTR).
 * @param[in]  key     Key bytes.
 * @param[in]  type    AES key size selector.
 * @param[in]  iv      IV / initial counter block (16 bytes; NULL for ECB, or for a zero CBC IV).
 * @param[in]  input   Input.
 * @param[in]  len     Bytes.
 * @param[out] output  Output (may equal @p input).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NOT_SUPPORTED to run the mode in
 *         software, or NOXTLS_RETURN_FAILED (hardware error after output was written).
 */
noxtls_return_t noxtls_aes_mode_accel_port(noxtls_aes_accel_mode_t mode,
                                            uint8_t decrypt,
                                            const uint8_t *key,
                                            noxtls_aes_type_t type,
                                            const uint8_t *iv,
                                            const uint8_t *input,
                                            uint32_t len,
                                            uint8_t *output);

/**
 * @brief Optional platform hook: AES-CCM encryption (NIST SP 800-38C).
 *
 * Same parameters as noxtls_aes_ccm_encrypt(); called when NOXTLS_PORT_AES_MODE_ACCEL is set.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NOT_SUPPORTED to use software, or another error.
 */
noxtls_return_t noxtls_aes_ccm_encrypt_accel_port(const uint8_t *key, noxtls_aes_type_t type,
                                                  const uint8_t *nonce, uint32_t nonce_len,
                                                  const uint8_t *aad, uint32_t aad_len,
                                                  const uint8_t *plaintext, uint32_t plaintext_len,
                                                  uint8_t *ciphertext,
                                                  uint8_t *tag, uint32_t tag_len);

/**
 * @brief Optional platform hook: AES-CCM decryption and verification (NIST SP 800-38C).
 *
 * Same parameters as noxtls_aes_ccm_decrypt(); called when NOXTLS_PORT_AES_MODE_ACCEL is set.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_BAD_DATA (tag mismatch, plaintext
 *         wiped), NOXTLS_RETURN_NOT_SUPPORTED to use software, or another error.
 */
noxtls_return_t noxtls_aes_ccm_decrypt_accel_port(const uint8_t *key, noxtls_aes_type_t type,
                                                  const uint8_t *nonce, uint32_t nonce_len,
                                                  const uint8_t *aad, uint32_t aad_len,
                                                  const uint8_t *ciphertext, uint32_t ciphertext_len,
                                                  const uint8_t *tag, uint32_t tag_len,
                                                  uint8_t *plaintext);

#endif /* NOXTLS_AES_ACCEL_H_ */
