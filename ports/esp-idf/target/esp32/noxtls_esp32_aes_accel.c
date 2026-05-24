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
* File:    noxtls_esp32_aes_accel.c
* Summary: ESP-IDF AES acceleration hook implementation
*
*
*****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "noxtls_aes_accel.h"

#if defined(ESP_PLATFORM)
#include "noxtls_esp_hw_accel.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "soc/soc_caps.h"
#if defined(SOC_AES_SUPPORTED) && SOC_AES_SUPPORTED
#include "aes/esp_aes.h"
#include "aes/esp_aes_gcm.h"
#include "mbedtls/gcm.h"
#endif
#endif

#if defined(ESP_PLATFORM) && defined(SOC_AES_SUPPORTED) && SOC_AES_SUPPORTED && \
    CONFIG_NOXTLS_ESP_HW_AES
static SemaphoreHandle_t s_aes_mutex;
static esp_aes_context s_aes_ctx;
static uint8_t s_cached_key[32];
static unsigned s_cached_key_bits;
static uint8_t s_ctx_ready;
static uint8_t s_key_ready;

/**
 * @brief Lock the ESP hardware AES
 *
 * @return The return code
 */
static noxtls_return_t noxtls_aes_accel_esp_lock(void)
{
    if(s_aes_mutex == NULL) {
        s_aes_mutex = xSemaphoreCreateMutex();
        if(s_aes_mutex == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    if(xSemaphoreTake(s_aes_mutex, portMAX_DELAY) != pdTRUE) {
        return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Unlock the ESP hardware AES
 *
 * @return void
 */
static void noxtls_aes_accel_esp_unlock(void)
{
    if(s_aes_mutex != NULL) {
        (void)xSemaphoreGive(s_aes_mutex);
    }
}

/**
 * @brief Prepare the ESP hardware AES context
 *
 * @param[in] key The key to prepare the ESP hardware AES context with
 * @param[in] type The type of the ESP hardware AES context to prepare
 * @return The return code
 */
static noxtls_return_t noxtls_aes_accel_esp_prepare_ctx_locked(const uint8_t *key,
                                                                noxtls_aes_type_t type)
{
    unsigned keybits = 0;
    unsigned keybytes = 0;
    int rc;

    switch(type) {
        case NOXTLS_AES_128_BIT:
            keybits = 128;
            keybytes = 16;
            break;
        case NOXTLS_AES_192_BIT:
            keybits = 192;
            keybytes = 24;
            break;
        case NOXTLS_AES_256_BIT:
            keybits = 256;
            keybytes = 32;
            break;
        default:
            return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }

    if(!s_ctx_ready) {
        esp_aes_init(&s_aes_ctx);
        s_ctx_ready = 1U;
    }

    if(!s_key_ready ||
       s_cached_key_bits != keybits ||
       memcmp(s_cached_key, key, keybytes) != 0) {
        rc = esp_aes_setkey(&s_aes_ctx, key, keybits);
        if(rc != 0) {
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(s_cached_key, key, keybytes);
        s_cached_key_bits = keybits;
        s_key_ready = 1U;
    }

    return NOXTLS_RETURN_SUCCESS;
}
#endif

/**
 * @brief Crypt the block using the ESP hardware AES
 *
 * @param[in] key The key to crypt the block with
 * @param[in] data The data to crypt the block with
 * @param[out] output The output to crypt the block into
 * @param[in] type The type of the block to crypt
 * @param[in] mode The mode to crypt the block in
 * @return NOXTLS_RETURN_SUCCESS on success, 
 *         NOXTLS_RETURN_FAILED on failure, 
 *         NOXTLS_RETURN_NULL if the key, data, or output is NULL
 */
static noxtls_return_t noxtls_aes_accel_esp_crypt_block(const uint8_t *key,
                                                         const uint8_t *data,
                                                         uint8_t *output,
                                                         noxtls_aes_type_t type,
                                                         int mode)
{
#if defined(ESP_PLATFORM) && defined(SOC_AES_SUPPORTED) && SOC_AES_SUPPORTED && \
    CONFIG_NOXTLS_ESP_HW_AES
    noxtls_return_t prep_rc;
    int rc;

    if(key == NULL || data == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(noxtls_aes_accel_esp_lock() != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    prep_rc = noxtls_aes_accel_esp_prepare_ctx_locked(key, type);
    if(prep_rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_aes_accel_esp_unlock();
        return prep_rc;
    }

    rc = esp_aes_crypt_ecb(&s_aes_ctx, mode, data, output);
    if(rc != 0) {
        noxtls_aes_accel_esp_unlock();
        return NOXTLS_RETURN_FAILED;
    }

    noxtls_aes_accel_esp_unlock();

    return NOXTLS_RETURN_SUCCESS;
#else
    (void)key;
    (void)data;
    (void)output;
    (void)type;
    (void)mode;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

/**
 * @brief Encrypt the block using the ESP hardware AES
 *
 * @param[in] key The key to encrypt the block with
 * @param[in] data The data to encrypt the block with
 * @param[out] output The output to encrypt the block into
 * @param[in] type The type of the block to encrypt
 * @return The return code
 */
noxtls_return_t noxtls_aes_accel_port_encrypt_block(const uint8_t *key,
                                                     const uint8_t *data,
                                                     uint8_t *output,
                                                     noxtls_aes_type_t type)
{
    return noxtls_aes_accel_esp_crypt_block(key, data, output, type, ESP_AES_ENCRYPT);
}

/**
 * @brief Decrypt the block using the ESP hardware AES
 *
 * @param[in] key The key to decrypt the block with
 * @param[in] data The data to decrypt the block with
 * @param[out] output The output to decrypt the block into
 * @param[in] type The type of the block to decrypt
 * @return NOXTLS_RETURN_SUCCESS on success, 
 *         NOXTLS_RETURN_FAILED on failure, 
 *         NOXTLS_RETURN_NULL if the key, data, or output is NULL
 */
noxtls_return_t noxtls_aes_accel_port_decrypt_block(const uint8_t *key,
                                                     const uint8_t *data,
                                                     uint8_t *output,
                                                     noxtls_aes_type_t type)
{
    return noxtls_aes_accel_esp_crypt_block(key, data, output, type, ESP_AES_DECRYPT);
}

/**
 * @brief Encrypt the blocks using the ESP hardware AES
 *
 * @param[in] key The key to encrypt the blocks with
 * @param[in] input The data to encrypt the blocks with
 * @param[out] output The output to encrypt the blocks into
 * @param[in] block_count The number of blocks to encrypt
 * @param[in] type The type of the blocks to encrypt
 * @return NOXTLS_RETURN_SUCCESS on success, 
 *         NOXTLS_RETURN_FAILED on failure, 
 *         NOXTLS_RETURN_NULL if the key, input, or output is NULL
 */
noxtls_return_t noxtls_aes_accel_port_encrypt_blocks(const uint8_t *key,
                                                      const uint8_t *input,
                                                      uint8_t *output,
                                                      uint32_t block_count,
                                                      noxtls_aes_type_t type)
{
#if defined(ESP_PLATFORM) && defined(SOC_AES_SUPPORTED) && SOC_AES_SUPPORTED && \
    CONFIG_NOXTLS_ESP_HW_AES
    noxtls_return_t prep_rc;
    uint32_t block;
    int rc;

    if(key == NULL || input == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(block_count == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }

    if(noxtls_aes_accel_esp_lock() != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    prep_rc = noxtls_aes_accel_esp_prepare_ctx_locked(key, type);
    if(prep_rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_aes_accel_esp_unlock();
        return prep_rc;
    }

    for(block = 0U; block < block_count; block++) {
        const uint8_t *in_block = input + ((size_t)block * NOXTLS_AES_BLOCK_LENGTH);
        uint8_t *out_block = output + ((size_t)block * NOXTLS_AES_BLOCK_LENGTH);
        rc = esp_aes_crypt_ecb(&s_aes_ctx, ESP_AES_ENCRYPT, in_block, out_block);
        if(rc != 0) {
            noxtls_aes_accel_esp_unlock();
            return NOXTLS_RETURN_FAILED;
        }
    }

    noxtls_aes_accel_esp_unlock();
    return NOXTLS_RETURN_SUCCESS;
#else
    (void)key;
    (void)input;
    (void)output;
    (void)block_count;
    (void)type;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

/**
 * @brief Encrypt the GCM using the ESP hardware AES
 *
 * @param[in] key The key to encrypt the GCM with
 * @param[in] type The type of the GCM to encrypt
 * @param[in] nonce The nonce to encrypt the GCM with
 * @param[in] aad The additional authentication data to encrypt the GCM with
 * @param[in] aad_len The length of the additional authentication data to encrypt the GCM with
 * @param[in] plaintext The plaintext to encrypt the GCM with
 * @param[in] plaintext_len The length of the plaintext to encrypt the GCM with
 * @param[out] ciphertext The ciphertext to encrypt the GCM into
 * @param[out] tag The tag to encrypt the GCM into
 * @return NOXTLS_RETURN_SUCCESS on success, 
 *         NOXTLS_RETURN_FAILED on failure, 
 *         NOXTLS_RETURN_NULL if the key, nonce, plaintext, ciphertext, or tag is NULL
 */
noxtls_return_t noxtls_aes_gcm_encrypt_accel_port(const uint8_t *key,
                                                   noxtls_aes_type_t type,
                                                   const uint8_t nonce[12],
                                                   const uint8_t *aad,
                                                   uint32_t aad_len,
                                                   const uint8_t *plaintext,
                                                   uint32_t plaintext_len,
                                                   uint8_t *ciphertext,
                                                   uint8_t tag[16])
{
#if defined(ESP_PLATFORM) && defined(SOC_AES_SUPPORTED) && SOC_AES_SUPPORTED && \
    CONFIG_NOXTLS_ESP_HW_AES
    esp_gcm_context ctx;
    unsigned key_bits = 0;
    int rc;

    if(key == NULL || nonce == NULL || plaintext == NULL || ciphertext == NULL || tag == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    switch(type) {
        case NOXTLS_AES_128_BIT:
            key_bits = 128;
            break;
        case NOXTLS_AES_192_BIT:
            key_bits = 192;
            break;
        case NOXTLS_AES_256_BIT:
            key_bits = 256;
            break;
        default:
            return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }

    esp_aes_gcm_init(&ctx);
    rc = esp_aes_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, key_bits);
    if(rc != 0) {
        esp_aes_gcm_free(&ctx);
        return NOXTLS_RETURN_FAILED;
    }

    rc = esp_aes_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, (size_t)plaintext_len,
                                   nonce, 12U, aad, (size_t)aad_len,
                                   plaintext, ciphertext, 16U, tag);
    esp_aes_gcm_free(&ctx);
    return (rc == 0) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
#else
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
#endif
}

/**
 * @brief Decrypt the GCM using the ESP hardware AES
 *
 * @param[in] key The key to decrypt the GCM with
 * @param[in] type The type of the GCM to decrypt
 * @param[in] nonce The nonce to decrypt the GCM with
 * @param[in] aad The additional authentication data to decrypt the GCM with
 * @param[in] aad_len The length of the additional authentication data to decrypt the GCM with
 * @param[in] ciphertext The ciphertext to decrypt the GCM with
 * @param[in] ciphertext_len The length of the ciphertext to decrypt the GCM with
 * @param[in] tag The tag to decrypt the GCM with
 * @param[out] plaintext The plaintext to decrypt the GCM into
 * @return NOXTLS_RETURN_SUCCESS on success, 
 *         NOXTLS_RETURN_FAILED on failure, 
 *         NOXTLS_RETURN_NULL if the key, nonce, ciphertext, plaintext, or tag is NULL,
 *         NOXTLS_RETURN_BAD_DATA if the tag verification fails
 */
noxtls_return_t noxtls_aes_gcm_decrypt_accel_port(const uint8_t *key,
                                                   noxtls_aes_type_t type,
                                                   const uint8_t nonce[12],
                                                   const uint8_t *aad,
                                                   uint32_t aad_len,
                                                   const uint8_t *ciphertext,
                                                   uint32_t ciphertext_len,
                                                   const uint8_t tag[16],
                                                   uint8_t *plaintext)
{
#if defined(ESP_PLATFORM) && defined(SOC_AES_SUPPORTED) && SOC_AES_SUPPORTED && \
    CONFIG_NOXTLS_ESP_HW_AES
    esp_gcm_context ctx;
    unsigned key_bits = 0;
    int rc;

    if(key == NULL || nonce == NULL || ciphertext == NULL || plaintext == NULL || tag == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    switch(type) {
        case NOXTLS_AES_128_BIT:
            key_bits = 128;
            break;
        case NOXTLS_AES_192_BIT:
            key_bits = 192;
            break;
        case NOXTLS_AES_256_BIT:
            key_bits = 256;
            break;
        default:
            return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }

    esp_aes_gcm_init(&ctx);
    rc = esp_aes_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, key_bits);
    if(rc != 0) {
        esp_aes_gcm_free(&ctx);
        return NOXTLS_RETURN_FAILED;
    }

    rc = esp_aes_gcm_auth_decrypt(&ctx, (size_t)ciphertext_len, nonce, 12U,
                                  aad, (size_t)aad_len, tag, 16U, ciphertext,
                                  plaintext);
    esp_aes_gcm_free(&ctx);
    if(rc == 0) {
        return NOXTLS_RETURN_SUCCESS;
    }
    if(rc == MBEDTLS_ERR_GCM_AUTH_FAILED) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    return NOXTLS_RETURN_FAILED;
#else
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
#endif
}
