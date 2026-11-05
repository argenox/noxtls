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
* File:    noxtls_efr32_port_aes.c
* Summary: NoxTLS AES accelerator ports on the EFR32xG2x RADIOAES
*
*****************************************************************************/

/**
 * @file noxtls_efr32_port_aes.c
 * @brief AES block, ECB / CBC / CTR and CCM accelerator ports (noxtls_aes_accel.h)
 *        served by the RADIOAES BA411E; GCM stays in software.
 * @ingroup noxtls_efr32
 *
 * Every hook returns NOXTLS_RETURN_NOT_SUPPORTED when the hardware cannot take
 * the request (mode or key size not in the engine, engine owned by another
 * driver, buffer not reachable, unit disabled), so NoxTLS falls back to its
 * software AES. A hardware failure after the output was written is reported as
 * NOXTLS_RETURN_FAILED instead, because the input may already be overwritten.
 * The EFR32MG26 BA411E has no GCM mode: the NoxTLS GCM code (CTR keystream
 * through the block hook, GHASH on the CPU) therefore runs in software.
 */

#include <stddef.h>
#include <string.h>

#include "noxtls_aes.h"
#include "noxtls_aes_accel.h"
#include "noxtls_efr32_aes_engine.h"

/** @brief AES-128 key bytes. */
#define NOXTLS_EFR32_PORT_KEY_128       16U
/** @brief AES-192 key bytes. */
#define NOXTLS_EFR32_PORT_KEY_192       24U
/** @brief AES-256 key bytes. */
#define NOXTLS_EFR32_PORT_KEY_256       32U

/**
 * @brief Key bytes of an AES key size selector.
 * @internal
 *
 * @param[in] type Selector.
 *
 * @return 16, 24, 32, or 0 for an unknown selector.
 */
static uint32_t noxtls_efr32_port_key_len(noxtls_aes_type_t type)
{
    uint32_t len = 0U;

    if (type == NOXTLS_AES_128_BIT) {
        len = NOXTLS_EFR32_PORT_KEY_128;
    } else if (type == NOXTLS_AES_192_BIT) {
        len = NOXTLS_EFR32_PORT_KEY_192;
    } else if (type == NOXTLS_AES_256_BIT) {
        len = NOXTLS_EFR32_PORT_KEY_256;
    } else {
        /* Unknown selector. */
    }
    return len;
}

/**
 * @brief Map a backend result of an operation that may have written its output.
 * @internal
 *
 * @param[in] rc Backend result.
 *
 * @return SUCCESS / FAILED (hardware error) / NOT_SUPPORTED (nothing done, use software).
 */
static noxtls_return_t noxtls_efr32_port_map(noxtls_return_t rc)
{
    noxtls_return_t out = NOXTLS_RETURN_NOT_SUPPORTED;

    if (rc == NOXTLS_RETURN_SUCCESS) {
        out = NOXTLS_RETURN_SUCCESS;
    } else if ((rc == NOXTLS_RETURN_FAILED) || (rc == NOXTLS_RETURN_TIMEOUT)) {
        out = NOXTLS_RETURN_FAILED;
    } else {
        /* Not served by the hardware. */
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
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_NOT_SUPPORTED (software computes the block).
 */
static noxtls_return_t noxtls_efr32_port_block(const uint8_t *key, const uint8_t *data, uint8_t *output,
                                               noxtls_aes_type_t type, uint8_t decrypt)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;

    if ((NOXTLS_EFR32_CONFIG_AES_BLOCK_HOOK != 0) && (key != NULL) && (data != NULL) && (output != NULL) &&
        (noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, decrypt, key, noxtls_efr32_port_key_len(type), NULL, data, output,
                                NOXTLS_EFR32_AES_BLOCK) == NOXTLS_RETURN_SUCCESS)) {
        rc = NOXTLS_RETURN_SUCCESS;
    }
    return rc;
}

noxtls_return_t noxtls_aes_accel_port_encrypt_block(const uint8_t *key,
                                                     const uint8_t *data,
                                                     uint8_t *output,
                                                     noxtls_aes_type_t type)
{
    return noxtls_efr32_port_block(key, data, output, type, 0U);
}

noxtls_return_t noxtls_aes_accel_port_decrypt_block(const uint8_t *key,
                                                     const uint8_t *data,
                                                     uint8_t *output,
                                                     noxtls_aes_type_t type)
{
    return noxtls_efr32_port_block(key, data, output, type, 1U);
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
    } else if (block_count > (UINT32_MAX / NOXTLS_EFR32_AES_BLOCK)) {
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
    } else {
        rc = noxtls_efr32_port_map(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, key, noxtls_efr32_port_key_len(type),
                                                          NULL, input, output, block_count * NOXTLS_EFR32_AES_BLOCK));
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
    uint8_t chain[NOXTLS_EFR32_AES_BLOCK] = { 0U };
    noxtls_efr32_aes_mode_t hw_mode = NOXTLS_EFR32_AES_ECB;

    if (mode == NOXTLS_AES_ACCEL_MODE_CBC) {
        hw_mode = NOXTLS_EFR32_AES_CBC;
    } else if (mode == NOXTLS_AES_ACCEL_MODE_CTR) {
        hw_mode = NOXTLS_EFR32_AES_CTR;
    } else {
        /* ECB. */
    }
    if ((key == NULL) || (input == NULL) || (output == NULL) || (len == 0U) ||
        ((mode == NOXTLS_AES_ACCEL_MODE_CTR) && (iv == NULL)) ||
        ((mode != NOXTLS_AES_ACCEL_MODE_ECB) && (mode != NOXTLS_AES_ACCEL_MODE_CBC) &&
         (mode != NOXTLS_AES_ACCEL_MODE_CTR))) {
        /* Software keeps its own argument semantics. */
    } else {
        if (iv != NULL) {
            (void)memcpy(chain, iv, sizeof(chain));
        }
        rc = noxtls_efr32_port_map(noxtls_efr32_aes_crypt(hw_mode, decrypt, key, noxtls_efr32_port_key_len(type),
                                                          (mode == NOXTLS_AES_ACCEL_MODE_ECB) ? NULL : chain,
                                                          input, output, len));
        noxtls_efr32_wipe(chain, (uint32_t)sizeof(chain));
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
    /* The EFR32 BA411E has no GCM mode (BA411E_HW_CFG_1.g_AesModesPoss): software GCM. */
    (void)key;
    (void)type;
    (void)nonce;
    (void)aad;
    (void)aad_len;
    (void)plaintext;
    (void)plaintext_len;
    (void)ciphertext;
    (void)tag;
    return NOXTLS_RETURN_NOT_SUPPORTED;
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
    (void)key;
    (void)type;
    (void)nonce;
    (void)aad;
    (void)aad_len;
    (void)ciphertext;
    (void)ciphertext_len;
    (void)tag;
    (void)plaintext;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_aes_ccm_encrypt_accel_port(const uint8_t *key, noxtls_aes_type_t type,
                                                  const uint8_t *nonce, uint32_t nonce_len,
                                                  const uint8_t *aad, uint32_t aad_len,
                                                  const uint8_t *plaintext, uint32_t plaintext_len,
                                                  uint8_t *ciphertext,
                                                  uint8_t *tag, uint32_t tag_len)
{
    return noxtls_efr32_port_map(noxtls_efr32_aes_ccm(0U, key, noxtls_efr32_port_key_len(type), nonce, nonce_len, aad,
                                                      aad_len, plaintext, ciphertext, plaintext_len, tag, tag_len));
}

noxtls_return_t noxtls_aes_ccm_decrypt_accel_port(const uint8_t *key, noxtls_aes_type_t type,
                                                  const uint8_t *nonce, uint32_t nonce_len,
                                                  const uint8_t *aad, uint32_t aad_len,
                                                  const uint8_t *ciphertext, uint32_t ciphertext_len,
                                                  const uint8_t *tag, uint32_t tag_len,
                                                  uint8_t *plaintext)
{
    uint8_t expected[NOXTLS_EFR32_AES_TAG_MAX];
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;

    if ((tag != NULL) && (tag_len <= sizeof(expected))) {
        (void)memcpy(expected, tag, tag_len);
        rc = noxtls_efr32_aes_ccm(1U, key, noxtls_efr32_port_key_len(type), nonce, nonce_len, aad, aad_len, ciphertext,
                                  plaintext, ciphertext_len, expected, tag_len);
        noxtls_efr32_wipe(expected, (uint32_t)sizeof(expected));
        if (rc != NOXTLS_RETURN_BAD_DATA) {
            rc = noxtls_efr32_port_map(rc);
        }
    }
    return rc;
}
