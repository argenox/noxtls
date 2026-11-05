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
* File:    noxtls_stm32wb_port_aes.c
* Summary: NoxTLS AES accelerator ports served by the STM32WB5x AES1
*
*****************************************************************************/

/**
 * @file noxtls_stm32wb_port_aes.c
 * @brief AES block, ECB / CBC / CTR, GCM and CCM accelerator ports (noxtls_aes_accel.h).
 * @ingroup noxtls_stm32wb
 *
 * Every hook returns NOXTLS_RETURN_NOT_SUPPORTED when the request must be
 * served in software: AES-192 (not in the hardware), a mode or length the
 * engine cannot take, AES1 or its semaphore busy, or a hardware error on a
 * request whose input and output buffers differ (the input is intact, so the
 * software path recomputes it). A hardware error on an in-place request is
 * reported as NOXTLS_RETURN_FAILED because the input was already overwritten.
 */

#include <stddef.h>

#include "common/noxtls_ct.h"
#include "encryption/aes/noxtls_aes.h"
#include "encryption/aes/noxtls_aes_accel.h"
#include "noxtls_stm32wb_aes.h"

/** @brief Overflow limit of the block count of noxtls_aes_accel_port_encrypt_blocks(). */
#define NOXTLS_STM32WB_PORT_MAX_BLOCKS  (UINT32_MAX / NOXTLS_STM32WB_AES_BLOCK)

/**
 * @brief Key bytes of an AES key size selector.
 * @internal
 *
 * @param[in] type Selector.
 *
 * @return 16, 32, or 0 when the hardware does not support the size (192 or unknown).
 */
static uint32_t noxtls_stm32wb_port_key_len(noxtls_aes_type_t type)
{
    uint32_t len = 0U;

    if (type == NOXTLS_AES_128_BIT) {
        len = NOXTLS_STM32WB_AES_KEY_128;
    } else if (type == NOXTLS_AES_256_BIT) {
        len = NOXTLS_STM32WB_AES_KEY_256;
    } else {
        /* AES-192 and unknown selectors stay in software. */
    }
    return len;
}

/**
 * @brief Map a driver result to the port contract.
 * @internal
 *
 * @param[in] rc      Driver result.
 * @param[in] in_place Non-zero when the output overwrites the input.
 *
 * @return SUCCESS, BAD_DATA, FAILED (hardware error on an in-place request) or NOT_SUPPORTED.
 */
static noxtls_return_t noxtls_stm32wb_port_map(noxtls_return_t rc, uint32_t in_place)
{
    noxtls_return_t out = NOXTLS_RETURN_NOT_SUPPORTED;

    if ((rc == NOXTLS_RETURN_SUCCESS) || (rc == NOXTLS_RETURN_BAD_DATA)) {
        out = rc;
    } else if ((rc == NOXTLS_RETURN_FAILED) && (in_place != 0U)) {
        out = NOXTLS_RETURN_FAILED;
    } else {
        /* Not started, or failed with the input intact: software recomputes. */
    }
    return out;
}

/**
 * @brief One ECB block.
 * @internal
 *
 * @param[in]  key     Key.
 * @param[in]  data    Input block.
 * @param[out] output  Output block.
 * @param[in]  type    Key size selector.
 * @param[in]  decrypt Non-zero to decrypt.
 *
 * @return Port result.
 */
static noxtls_return_t noxtls_stm32wb_port_block(const uint8_t *key, const uint8_t *data, uint8_t *output,
                                                 noxtls_aes_type_t type, uint8_t decrypt)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;

    if ((key != NULL) && (data != NULL) && (output != NULL)) {
        rc = noxtls_stm32wb_port_map(noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_ECB, decrypt, key,
                                                              noxtls_stm32wb_port_key_len(type), NULL, data, output,
                                                              NOXTLS_STM32WB_AES_BLOCK),
                                     (data == output) ? 1U : 0U);
    }
    return rc;
}

noxtls_return_t noxtls_aes_accel_port_encrypt_block(const uint8_t *key,
                                                     const uint8_t *data,
                                                     uint8_t *output,
                                                     noxtls_aes_type_t type)
{
    return noxtls_stm32wb_port_block(key, data, output, type, 0U);
}

noxtls_return_t noxtls_aes_accel_port_decrypt_block(const uint8_t *key,
                                                     const uint8_t *data,
                                                     uint8_t *output,
                                                     noxtls_aes_type_t type)
{
    return noxtls_stm32wb_port_block(key, data, output, type, 1U);
}

noxtls_return_t noxtls_aes_accel_port_encrypt_blocks(const uint8_t *key,
                                                      const uint8_t *input,
                                                      uint8_t *output,
                                                      uint32_t block_count,
                                                      noxtls_aes_type_t type)
{
    noxtls_return_t rc;

    if ((key == NULL) || (input == NULL) || (output == NULL)) {
        rc = NOXTLS_RETURN_NULL;
    } else if (block_count > NOXTLS_STM32WB_PORT_MAX_BLOCKS) {
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
    } else {
        rc = noxtls_stm32wb_port_map(noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_ECB, 0U, key,
                                                              noxtls_stm32wb_port_key_len(type), NULL, input, output,
                                                              block_count * NOXTLS_STM32WB_AES_BLOCK),
                                     (input == output) ? 1U : 0U);
    }
    return rc;
}

noxtls_return_t noxtls_aes_mode_accel_port(noxtls_aes_accel_mode_t mode,
                                            uint8_t decrypt,
                                            const uint8_t *key,
                                            noxtls_aes_type_t type,
                                            const uint8_t *iv,
                                            const uint8_t *input,
                                            uint32_t len,
                                            uint8_t *output)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    uint8_t zero_iv[NOXTLS_STM32WB_AES_BLOCK] = { 0U };
    noxtls_stm32wb_aes_mode_t hw_mode = NOXTLS_STM32WB_AES_MODE_ECB;
    const uint8_t *chain = iv;
    uint32_t mode_ok = 1U;

    if (mode == NOXTLS_AES_ACCEL_MODE_CBC) {
        hw_mode = NOXTLS_STM32WB_AES_MODE_CBC;
        if (iv == NULL) {
            /* A zero CBC IV is the NoxTLS convention for a NULL IV. */
            chain = zero_iv;
        }
    } else if (mode == NOXTLS_AES_ACCEL_MODE_CTR) {
        hw_mode = NOXTLS_STM32WB_AES_MODE_CTR;
        if (iv == NULL) {
            /* Software keeps its own NULL-IV semantics for CTR. */
            mode_ok = 0U;
        }
    } else if (mode != NOXTLS_AES_ACCEL_MODE_ECB) {
        mode_ok = 0U;
    } else {
        /* ECB. */
    }
    if ((mode_ok != 0U) && (key != NULL) && (input != NULL) && (output != NULL)) {
        rc = noxtls_stm32wb_port_map(noxtls_stm32wb_aes_crypt(hw_mode, decrypt, key,
                                                              noxtls_stm32wb_port_key_len(type),
                                                              (mode == NOXTLS_AES_ACCEL_MODE_ECB) ? NULL : chain,
                                                              input, output, len),
                                     (input == output) ? 1U : 0U);
    }
    return rc;
}

noxtls_return_t noxtls_aes_gcm_encrypt_accel_port(const uint8_t *key,
                                                   noxtls_aes_type_t type,
                                                   const uint8_t *nonce,
                                                   const uint8_t *aad,
                                                   uint32_t aad_len,
                                                   const uint8_t *plaintext,
                                                   uint32_t plaintext_len,
                                                   uint8_t *ciphertext,
                                                   uint8_t *tag)
{
    return noxtls_stm32wb_port_map(noxtls_stm32wb_aes_gcm(0U, key, noxtls_stm32wb_port_key_len(type), nonce, aad,
                                                          aad_len, plaintext, ciphertext, plaintext_len, tag),
                                   (plaintext == ciphertext) ? 1U : 0U);
}

noxtls_return_t noxtls_aes_gcm_decrypt_accel_port(const uint8_t *key,
                                                   noxtls_aes_type_t type,
                                                   const uint8_t *nonce,
                                                   const uint8_t *aad,
                                                   uint32_t aad_len,
                                                   const uint8_t *ciphertext,
                                                   uint32_t ciphertext_len,
                                                   const uint8_t *tag,
                                                   uint8_t *plaintext)
{
    uint8_t expected[NOXTLS_STM32WB_AES_GCM_TAG];
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;

    if (tag != NULL) {
        noxtls_copy_u8(expected, sizeof(expected), tag, sizeof(expected));
        rc = noxtls_stm32wb_port_map(noxtls_stm32wb_aes_gcm(1U, key, noxtls_stm32wb_port_key_len(type), nonce, aad,
                                                            aad_len, ciphertext, plaintext, ciphertext_len, expected),
                                     (ciphertext == plaintext) ? 1U : 0U);
        noxtls_secure_zero(expected, sizeof(expected));
    }
    return rc;
}

noxtls_return_t noxtls_aes_ccm_encrypt_accel_port(const uint8_t *key, noxtls_aes_type_t type,
                                                  const uint8_t *nonce, uint32_t nonce_len,
                                                  const uint8_t *aad, uint32_t aad_len,
                                                  const uint8_t *plaintext, uint32_t plaintext_len,
                                                  uint8_t *ciphertext,
                                                  uint8_t *tag, uint32_t tag_len)
{
    return noxtls_stm32wb_port_map(noxtls_stm32wb_aes_ccm(0U, key, noxtls_stm32wb_port_key_len(type), nonce,
                                                          nonce_len, aad, aad_len, plaintext, ciphertext,
                                                          plaintext_len, tag, tag_len),
                                   (plaintext == ciphertext) ? 1U : 0U);
}

noxtls_return_t noxtls_aes_ccm_decrypt_accel_port(const uint8_t *key, noxtls_aes_type_t type,
                                                  const uint8_t *nonce, uint32_t nonce_len,
                                                  const uint8_t *aad, uint32_t aad_len,
                                                  const uint8_t *ciphertext, uint32_t ciphertext_len,
                                                  const uint8_t *tag, uint32_t tag_len,
                                                  uint8_t *plaintext)
{
    uint8_t expected[NOXTLS_STM32WB_AES_CCM_TAG_MAX];
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;

    if ((tag != NULL) && (tag_len <= sizeof(expected))) {
        noxtls_copy_u8(expected, sizeof(expected), tag, tag_len);
        rc = noxtls_stm32wb_port_map(noxtls_stm32wb_aes_ccm(1U, key, noxtls_stm32wb_port_key_len(type), nonce,
                                                            nonce_len, aad, aad_len, ciphertext, plaintext,
                                                            ciphertext_len, expected, tag_len),
                                     (ciphertext == plaintext) ? 1U : 0U);
        noxtls_secure_zero(expected, sizeof(expected));
    }
    return rc;
}
