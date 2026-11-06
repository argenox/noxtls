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
#include "noxtls_ct.h"

#if defined(ESP_PLATFORM)
#include "noxtls_esp_hw_accel.h"
#include "soc/soc_caps.h"
#if defined(SOC_AES_SUPPORTED) && SOC_AES_SUPPORTED
#include "aes/esp_aes.h"
#include "aes/esp_aes_gcm.h"

/* Stable values from mbedtls_cipher_id_t / GCM mode (see esp_aes_gcm.h). */
enum {
    NOXTLS_ESP_MBEDTLS_CIPHER_ID_AES = 2,
    NOXTLS_ESP_MBEDTLS_GCM_ENCRYPT = 1
};

#if defined(__has_include)
#if __has_include(<mbedtls/gcm.h>)
#include "mbedtls/gcm.h"
#define NOXTLS_ESP_MBEDTLS_ERR_GCM_AUTH_FAILED MBEDTLS_ERR_GCM_AUTH_FAILED
#else
/* IDF 6 / Mbed TLS 4.x: esp_aes_gcm_auth_decrypt returns PSA_ERROR_INVALID_SIGNATURE. */
#define NOXTLS_ESP_MBEDTLS_ERR_GCM_AUTH_FAILED ((int)-149)
#endif
#else
#include "mbedtls/gcm.h"
#define NOXTLS_ESP_MBEDTLS_ERR_GCM_AUTH_FAILED MBEDTLS_ERR_GCM_AUTH_FAILED
#endif
#endif
#endif

#if defined(ESP_PLATFORM) && defined(SOC_AES_SUPPORTED) && SOC_AES_SUPPORTED && \
    CONFIG_NOXTLS_ESP_HW_AES
/*
 * Every operation uses its own stack context: the key is loaded, used and
 * wiped within the call. There is no process-lifetime key cache and no shared
 * context, so concurrent tasks cannot use each other's key, and no key stays
 * in RAM after the operation. The AES peripheral itself is serialized by
 * ESP-IDF (esp_aes_acquire_hardware inside esp_aes_crypt_ecb).
 */

/**
 * @brief Map a NoxTLS AES key type to its size in bits
 *
 * @param[in] type The AES key type
 * @return The key size in bits, or 0 if the type is not supported
 */
static unsigned noxtls_aes_accel_esp_key_bits(noxtls_aes_type_t type)
{
    unsigned keybits = 0U;

    switch(type) {
        case NOXTLS_AES_128_BIT:
            keybits = 128U;
            break;
        case NOXTLS_AES_192_BIT:
            keybits = 192U;
            break;
        case NOXTLS_AES_256_BIT:
            keybits = 256U;
            break;
        default:
            keybits = 0U;
            break;
    }
    return keybits;
}

/**
 * @brief Run ECB over one or more blocks with a per-call key context
 *
 * @param[in] key The AES key
 * @param[in] input The input blocks
 * @param[out] output The output blocks
 * @param[in] block_count The number of 16-byte blocks
 * @param[in] type The AES key type
 * @param[in] mode ESP_AES_ENCRYPT or ESP_AES_DECRYPT
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_INVALID_KEY_SIZE or NOXTLS_RETURN_FAILED
 */
static noxtls_return_t noxtls_aes_accel_esp_ecb(const uint8_t *key,
                                                const uint8_t *input,
                                                uint8_t *output,
                                                uint32_t block_count,
                                                noxtls_aes_type_t type,
                                                int mode)
{
    esp_aes_context ctx;
    unsigned keybits = noxtls_aes_accel_esp_key_bits(type);
    noxtls_return_t ret = NOXTLS_RETURN_SUCCESS;
    uint32_t block;

    if(keybits == 0U) {
        return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }

    esp_aes_init(&ctx);
    if(esp_aes_setkey(&ctx, key, keybits) != 0) {
        ret = NOXTLS_RETURN_FAILED;
    }
    for(block = 0U; (ret == NOXTLS_RETURN_SUCCESS) && (block < block_count); block++) {
        const uint8_t *in_block = input + ((size_t)block * NOXTLS_AES_BLOCK_LENGTH);
        uint8_t *out_block = output + ((size_t)block * NOXTLS_AES_BLOCK_LENGTH);
        if(esp_aes_crypt_ecb(&ctx, mode, in_block, out_block) != 0) {
            ret = NOXTLS_RETURN_FAILED;
        }
    }
    esp_aes_free(&ctx);
    noxtls_secure_zero(&ctx, sizeof(ctx));
    return ret;
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
    if(key == NULL || data == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    return noxtls_aes_accel_esp_ecb(key, data, output, 1U, type, mode);
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
#if defined(ESP_PLATFORM) && defined(SOC_AES_SUPPORTED) && SOC_AES_SUPPORTED && \
    CONFIG_NOXTLS_ESP_HW_AES
    return noxtls_aes_accel_esp_crypt_block(key, data, output, type, ESP_AES_ENCRYPT);
#else
    (void)key;
    (void)data;
    (void)output;
    (void)type;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
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
#if defined(ESP_PLATFORM) && defined(SOC_AES_SUPPORTED) && SOC_AES_SUPPORTED && \
    CONFIG_NOXTLS_ESP_HW_AES
    return noxtls_aes_accel_esp_crypt_block(key, data, output, type, ESP_AES_DECRYPT);
#else
    (void)key;
    (void)data;
    (void)output;
    (void)type;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
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
    if(key == NULL || input == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(block_count == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }
    return noxtls_aes_accel_esp_ecb(key, input, output, block_count, type, ESP_AES_ENCRYPT);
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
                                                   const uint8_t *nonce,
                                                   const uint8_t *aad,
                                                   uint32_t aad_len,
                                                   const uint8_t *plaintext,
                                                   uint32_t plaintext_len,
                                                   uint8_t *ciphertext,
                                                   uint8_t *tag)
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
    rc = esp_aes_gcm_setkey(&ctx, NOXTLS_ESP_MBEDTLS_CIPHER_ID_AES, key, key_bits);
    if(rc != 0) {
        esp_aes_gcm_free(&ctx);
        noxtls_secure_zero(&ctx, sizeof(ctx));
        return NOXTLS_RETURN_FAILED;
    }

    rc = esp_aes_gcm_crypt_and_tag(&ctx, NOXTLS_ESP_MBEDTLS_GCM_ENCRYPT, (size_t)plaintext_len,
                                   nonce, 12U, aad, (size_t)aad_len,
                                   plaintext, ciphertext, 16U, tag);
    esp_aes_gcm_free(&ctx);
    noxtls_secure_zero(&ctx, sizeof(ctx));
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
                                                   const uint8_t *nonce,
                                                   const uint8_t *aad,
                                                   uint32_t aad_len,
                                                   const uint8_t *ciphertext,
                                                   uint32_t ciphertext_len,
                                                   const uint8_t *tag,
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
    rc = esp_aes_gcm_setkey(&ctx, NOXTLS_ESP_MBEDTLS_CIPHER_ID_AES, key, key_bits);
    if(rc != 0) {
        esp_aes_gcm_free(&ctx);
        noxtls_secure_zero(&ctx, sizeof(ctx));
        return NOXTLS_RETURN_FAILED;
    }

    rc = esp_aes_gcm_auth_decrypt(&ctx, (size_t)ciphertext_len, nonce, 12U,
                                  aad, (size_t)aad_len, tag, 16U, ciphertext,
                                  plaintext);
    esp_aes_gcm_free(&ctx);
    noxtls_secure_zero(&ctx, sizeof(ctx));
    if(rc == 0) {
        return NOXTLS_RETURN_SUCCESS;
    }
    if(rc == NOXTLS_ESP_MBEDTLS_ERR_GCM_AUTH_FAILED) {
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
