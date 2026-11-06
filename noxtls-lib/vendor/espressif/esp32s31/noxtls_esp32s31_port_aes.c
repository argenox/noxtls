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
* File:    noxtls_esp32s31_port_aes.c
* Summary: NoxTLS AES accelerator ports on the ESP32-S31 AES engine
*
*****************************************************************************/

/**
 * @file noxtls_esp32s31_port_aes.c
 * @brief AES block, ECB, CBC and CTR hooks served by the ESP32-S31 AES accelerator.
 *
 * AES-128 and AES-256 run in hardware. AES-192 and the GCM / CCM hooks return
 * NOXTLS_RETURN_NOT_SUPPORTED so NoxTLS computes them in software.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "noxtls_aes.h"
#include "noxtls_aes_accel.h"
#include "esp32s31_aes.h"

/** @brief AES block bytes. */
#define NOXTLS_ESP32S31_AES_BLOCK 16U

/** @brief Non-zero once the engine clock was enabled. */
static uint8_t s_noxtls_esp32s31_aes_ready;
/** @brief Requests served by the engine (telemetry). */
static uint32_t s_noxtls_esp32s31_aes_ops;

uint32_t noxtls_esp32s31_aes_op_count(void)
{
    return s_noxtls_esp32s31_aes_ops;
}

/**
 * @brief Key bytes of a selector the engine supports.
 * @internal
 *
 * @param[in] type Key size selector.
 *
 * @return 16 or 32, or 0 for AES-192 / unknown.
 */
static uint16_t noxtls_esp32s31_aes_key_len(noxtls_aes_type_t type)
{
    uint16_t len = 0U;

    if (type == NOXTLS_AES_128_BIT) {
        len = ESP32S31_AES_KEY_128_BYTES;
    } else if (type == NOXTLS_AES_256_BIT) {
        len = ESP32S31_AES_KEY_256_BYTES;
    } else {
        /* AES-192 is not implemented by the engine. */
    }
    return len;
}

/**
 * @brief Enable the engine on first use.
 * @internal
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_NOT_SUPPORTED.
 */
static noxtls_return_t noxtls_esp32s31_aes_prepare(void)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if (s_noxtls_esp32s31_aes_ready == 0U) {
        if (esp32s31_aes_init() == NOXDRV_SUCCESS) {
            s_noxtls_esp32s31_aes_ready = 1U;
        } else {
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
        }
    }
    return rc;
}

/**
 * @brief Map a driver result.
 * @internal
 *
 * @param[in] r Driver result.
 *
 * @return SUCCESS, FAILED (hardware timeout) or NOT_SUPPORTED (software computes it).
 */
static noxtls_return_t noxtls_esp32s31_aes_map(noxdrv_ret_t r)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;

    if (r == NOXDRV_SUCCESS) {
        s_noxtls_esp32s31_aes_ops++;
        rc = NOXTLS_RETURN_SUCCESS;
    } else if (r == NOXDRV_ERROR_TIMEOUT) {
        rc = NOXTLS_RETURN_FAILED;
    } else {
        /* Not served by the hardware. */
    }
    return rc;
}

/**
 * @brief ECB over whole blocks.
 * @internal
 *
 * @param[in]  key     Key.
 * @param[in]  type    Key size selector.
 * @param[in]  encrypt Non-zero to encrypt.
 * @param[in]  in      Input.
 * @param[out] out     Output.
 * @param[in]  len     Bytes (multiple of 16).
 *
 * @return NoxTLS result.
 */
static noxtls_return_t noxtls_esp32s31_aes_ecb_run(const uint8_t *key, noxtls_aes_type_t type, int encrypt,
                                                   const uint8_t *in, uint8_t *out, uint32_t len)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    uint16_t klen = noxtls_esp32s31_aes_key_len(type);

    if ((key != NULL) && (in != NULL) && (out != NULL) && (klen != 0U) &&
        (noxtls_esp32s31_aes_prepare() == NOXTLS_RETURN_SUCCESS)) {
        rc = noxtls_esp32s31_aes_map(esp32s31_aes_ecb(key, klen, encrypt, in, out, len));
    }
    return rc;
}

noxtls_return_t noxtls_aes_accel_port_encrypt_block(const uint8_t *key, const uint8_t *data, uint8_t *output,
                                                     noxtls_aes_type_t type)
{
    return noxtls_esp32s31_aes_ecb_run(key, type, 1, data, output, NOXTLS_ESP32S31_AES_BLOCK);
}

noxtls_return_t noxtls_aes_accel_port_decrypt_block(const uint8_t *key, const uint8_t *data, uint8_t *output,
                                                     noxtls_aes_type_t type)
{
    return noxtls_esp32s31_aes_ecb_run(key, type, 0, data, output, NOXTLS_ESP32S31_AES_BLOCK);
}

noxtls_return_t noxtls_aes_accel_port_encrypt_blocks(const uint8_t *key, const uint8_t *input, uint8_t *output,
                                                      uint32_t block_count, noxtls_aes_type_t type)
{
    noxtls_return_t rc;

    if ((key == NULL) || (input == NULL) || (output == NULL)) {
        rc = NOXTLS_RETURN_NULL;
    } else if (block_count > (UINT32_MAX / NOXTLS_ESP32S31_AES_BLOCK)) {
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
    } else {
        rc = noxtls_esp32s31_aes_ecb_run(key, type, 1, input, output, block_count * NOXTLS_ESP32S31_AES_BLOCK);
    }
    return rc;
}

noxtls_return_t noxtls_aes_mode_accel_port(noxtls_aes_accel_mode_t mode, uint8_t decrypt, const uint8_t *key,
                                            noxtls_aes_type_t type, const uint8_t *iv, const uint8_t *input,
                                            uint32_t len, uint8_t *output)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    uint8_t chain[NOXTLS_ESP32S31_AES_BLOCK] = { 0U };
    uint16_t klen = noxtls_esp32s31_aes_key_len(type);
    int enc = (decrypt == 0U) ? 1 : 0;

    if ((key == NULL) || (input == NULL) || (output == NULL) || (len == 0U) || (klen == 0U) ||
        ((mode == NOXTLS_AES_ACCEL_MODE_CTR) && (iv == NULL)) ||
        (noxtls_esp32s31_aes_prepare() != NOXTLS_RETURN_SUCCESS)) {
        /* Software keeps its own argument semantics. */
    } else {
        if (iv != NULL) {
            (void)memcpy(chain, iv, sizeof(chain));
        }
        if (mode == NOXTLS_AES_ACCEL_MODE_ECB) {
            rc = noxtls_esp32s31_aes_map(esp32s31_aes_ecb(key, klen, enc, input, output, len));
        } else if (mode == NOXTLS_AES_ACCEL_MODE_CBC) {
            rc = noxtls_esp32s31_aes_map(esp32s31_aes_cbc(key, klen, enc, chain, input, output, len));
        } else if (mode == NOXTLS_AES_ACCEL_MODE_CTR) {
            rc = noxtls_esp32s31_aes_map(esp32s31_aes_ctr(key, klen, chain, input, output, len));
        } else {
            /* Unknown mode. */
        }
        (void)memset(chain, 0, sizeof(chain));
    }
    return rc;
}

noxtls_return_t noxtls_aes_gcm_encrypt_accel_port(const uint8_t *key, noxtls_aes_type_t type, const uint8_t *nonce,
                                                   const uint8_t *aad, uint32_t aad_len, const uint8_t *plaintext,
                                                   uint32_t plaintext_len, uint8_t *ciphertext, uint8_t *tag)
{
    (void)key;
    (void)type;
    (void)nonce;
    (void)aad;
    (void)aad_len;
    (void)plaintext;
    (void)plaintext_len;
    (void)ciphertext;
    (void)tag;
    /* GCM runs in software (it still uses the block hook above). */
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_aes_gcm_decrypt_accel_port(const uint8_t *key, noxtls_aes_type_t type, const uint8_t *nonce,
                                                   const uint8_t *aad, uint32_t aad_len, const uint8_t *ciphertext,
                                                   uint32_t ciphertext_len, const uint8_t *tag, uint8_t *plaintext)
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

noxtls_return_t noxtls_aes_ccm_encrypt_accel_port(const uint8_t *key, noxtls_aes_type_t type, const uint8_t *nonce,
                                                  uint32_t nonce_len, const uint8_t *aad, uint32_t aad_len,
                                                  const uint8_t *plaintext, uint32_t plaintext_len,
                                                  uint8_t *ciphertext, uint8_t *tag, uint32_t tag_len)
{
    (void)key;
    (void)type;
    (void)nonce;
    (void)nonce_len;
    (void)aad;
    (void)aad_len;
    (void)plaintext;
    (void)plaintext_len;
    (void)ciphertext;
    (void)tag;
    (void)tag_len;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_aes_ccm_decrypt_accel_port(const uint8_t *key, noxtls_aes_type_t type, const uint8_t *nonce,
                                                  uint32_t nonce_len, const uint8_t *aad, uint32_t aad_len,
                                                  const uint8_t *ciphertext, uint32_t ciphertext_len,
                                                  const uint8_t *tag, uint32_t tag_len, uint8_t *plaintext)
{
    (void)key;
    (void)type;
    (void)nonce;
    (void)nonce_len;
    (void)aad;
    (void)aad_len;
    (void)ciphertext;
    (void)ciphertext_len;
    (void)tag;
    (void)tag_len;
    (void)plaintext;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}
