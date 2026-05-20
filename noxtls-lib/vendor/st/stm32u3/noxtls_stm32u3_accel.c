/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File: noxtls_stm32u3_accel.c
* Summary: STM32U3 AES acceleration backend (HAL CRYP).
*****************************************************************************/

#include "vendor/st/noxtls_stm32_accel.h"
#include <string.h>

#if defined(NOXTLS_STM32_FAMILY_U3)
#if defined(__has_include)
#if __has_include("stm32u3xx_hal.h")
#include "stm32u3xx_hal.h"
#endif
#if __has_include("stm32u3xx_hal_cryp.h")
#include "stm32u3xx_hal_cryp.h"
#define NOXTLS_STM32U3_HAS_HAL_CRYP_HEADER 1
#endif
#endif
#endif

#if defined(NOXTLS_STM32_FAMILY_U3) && defined(NOXTLS_STM32U3_HAS_HAL_CRYP_HEADER) && \
    defined(HAL_CRYP_MODULE_ENABLED) && (defined(CRYP) || defined(AES) || defined(SAES))
#define NOXTLS_STM32U3_HAL_CRYP_AVAILABLE 1
#else
#define NOXTLS_STM32U3_HAL_CRYP_AVAILABLE 0
#endif

#define NOXTLS_STM32U3_AES_BLOCK_WORDS 4u
#define NOXTLS_STM32U3_CRYP_TIMEOUT_MS 1000u

#if NOXTLS_STM32U3_HAL_CRYP_AVAILABLE
static noxtls_return_t noxtls_stm32u3_map_hal_status(HAL_StatusTypeDef status)
{
    switch(status) {
        case HAL_OK:
            return NOXTLS_RETURN_SUCCESS;
        case HAL_TIMEOUT:
            return NOXTLS_RETURN_TIMEOUT;
        case HAL_BUSY:
            return NOXTLS_RETURN_NOT_INITIALIZED;
        case HAL_ERROR:
        default:
            return NOXTLS_RETURN_FAILED;
    }
}

static noxtls_return_t noxtls_stm32u3_get_key_size(noxtls_aes_type_t type,
                                                    uint32_t *hal_key_size,
                                                    uint32_t *key_bytes)
{
    if(hal_key_size == NULL || key_bytes == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    switch(type) {
        case NOXTLS_AES_128_BIT:
            *hal_key_size = CRYP_KEYSIZE_128B;
            *key_bytes = 16u;
            return NOXTLS_RETURN_SUCCESS;
        case NOXTLS_AES_192_BIT:
#if defined(CRYP_KEYSIZE_192B)
            *hal_key_size = CRYP_KEYSIZE_192B;
            *key_bytes = 24u;
            return NOXTLS_RETURN_SUCCESS;
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_AES_256_BIT:
            *hal_key_size = CRYP_KEYSIZE_256B;
            *key_bytes = 32u;
            return NOXTLS_RETURN_SUCCESS;
        default:
            return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }
}

static noxtls_return_t noxtls_stm32u3_process_block(const uint8_t *key,
                                                     const uint8_t *data,
                                                     uint8_t *output,
                                                     noxtls_aes_type_t type,
                                                     int encrypt)
{
    CRYP_HandleTypeDef hcryp;
    HAL_StatusTypeDef hal_status;
    uint32_t hal_key_size = 0u;
    uint32_t key_bytes = 0u;
    uint32_t key_words[8] = {0u};
    uint32_t iv_words[4] = {0u};
    uint32_t input_words[NOXTLS_STM32U3_AES_BLOCK_WORDS] = {0u};
    uint32_t output_words[NOXTLS_STM32U3_AES_BLOCK_WORDS] = {0u};
    uint16_t size_arg = (uint16_t)NOXTLS_STM32U3_AES_BLOCK_WORDS;
    noxtls_return_t rc;

    if(key == NULL || data == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_stm32u3_get_key_size(type, &hal_key_size, &key_bytes);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

#if defined(__HAL_RCC_CRYP_CLK_ENABLE)
    __HAL_RCC_CRYP_CLK_ENABLE();
#endif
#if defined(__HAL_RCC_AES_CLK_ENABLE)
    __HAL_RCC_AES_CLK_ENABLE();
#endif
#if defined(__HAL_RCC_SAES_CLK_ENABLE)
    __HAL_RCC_SAES_CLK_ENABLE();
#endif

    memset(&hcryp, 0, sizeof(hcryp));
    memcpy(key_words, key, key_bytes);
    memcpy(input_words, data, NOXTLS_AES_BLOCK_LENGTH);

#if defined(SAES)
    hcryp.Instance = SAES;
#elif defined(AES)
    hcryp.Instance = AES;
#elif defined(CRYP)
    hcryp.Instance = CRYP;
#else
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif

    hcryp.Init.DataType = CRYP_DATATYPE_8B;
    hcryp.Init.KeySize = hal_key_size;
    hcryp.Init.pKey = key_words;
    hcryp.Init.pInitVect = iv_words;
    hcryp.Init.Algorithm = CRYP_AES_ECB;
#if defined(CRYP_KEYIVCONFIG_ALWAYS)
    hcryp.Init.KeyIVConfigSkip = CRYP_KEYIVCONFIG_ALWAYS;
#else
    hcryp.Init.KeyIVConfigSkip = 0u;
#endif
#if defined(CRYP_DATAWIDTHUNIT_BYTE)
    hcryp.Init.DataWidthUnit = CRYP_DATAWIDTHUNIT_BYTE;
    size_arg = (uint16_t)NOXTLS_AES_BLOCK_LENGTH;
#endif
#if defined(CRYP_HEADERWIDTHUNIT_WORD)
    hcryp.Init.HeaderWidthUnit = CRYP_HEADERWIDTHUNIT_WORD;
#endif

    hal_status = HAL_CRYP_Init(&hcryp);
    if(hal_status != HAL_OK) {
        return noxtls_stm32u3_map_hal_status(hal_status);
    }

    if(encrypt != 0) {
        hal_status = HAL_CRYP_Encrypt(&hcryp,
                                      input_words,
                                      size_arg,
                                      output_words,
                                      NOXTLS_STM32U3_CRYP_TIMEOUT_MS);
    } else {
        hal_status = HAL_CRYP_Decrypt(&hcryp,
                                      input_words,
                                      size_arg,
                                      output_words,
                                      NOXTLS_STM32U3_CRYP_TIMEOUT_MS);
    }

    (void)HAL_CRYP_DeInit(&hcryp);

    if(hal_status != HAL_OK) {
        return noxtls_stm32u3_map_hal_status(hal_status);
    }

    memcpy(output, output_words, NOXTLS_AES_BLOCK_LENGTH);
    return NOXTLS_RETURN_SUCCESS;
}
#endif /* NOXTLS_STM32U3_HAL_CRYP_AVAILABLE */

noxtls_return_t noxtls_aes_accel_stm32u3_encrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type)
{
#if NOXTLS_STM32U3_HAL_CRYP_AVAILABLE
    return noxtls_stm32u3_process_block(key, data, output, type, 1);
#else
    (void)key;
    (void)data;
    (void)output;
    (void)type;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

noxtls_return_t noxtls_aes_accel_stm32u3_decrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type)
{
#if NOXTLS_STM32U3_HAL_CRYP_AVAILABLE
    return noxtls_stm32u3_process_block(key, data, output, type, 0);
#else
    (void)key;
    (void)data;
    (void)output;
    (void)type;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}
