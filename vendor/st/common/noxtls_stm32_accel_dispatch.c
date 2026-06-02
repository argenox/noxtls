/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_stm32_accel_dispatch.c
* Summary: STM32 family dispatch for AES acceleration backend.
*
*/

#include "vendor/st/noxtls_stm32_accel.h"
#include "vendor/st/noxtls_target_detect.h"
#include "vendor/st/common/noxtls_stm32_hash_core.h"

noxtls_return_t noxtls_aes_accel_stm32_encrypt_block(const uint8_t *key,
                                                      const uint8_t *data,
                                                      uint8_t *output,
                                                      noxtls_aes_type_t type)
{
#if defined(NOXTLS_STM32_FAMILY_F2)
    return noxtls_aes_accel_stm32f2_encrypt_block(key, data, output, type);
#elif defined(NOXTLS_STM32_FAMILY_F4)
    return noxtls_aes_accel_stm32f4_encrypt_block(key, data, output, type);
#elif defined(NOXTLS_STM32_FAMILY_F7)
    return noxtls_aes_accel_stm32f7_encrypt_block(key, data, output, type);
#elif defined(NOXTLS_STM32_FAMILY_H7)
    return noxtls_aes_accel_stm32h7_encrypt_block(key, data, output, type);
#elif defined(NOXTLS_STM32_FAMILY_L4)
    return noxtls_aes_accel_stm32l4_encrypt_block(key, data, output, type);
#elif defined(NOXTLS_STM32_FAMILY_U3)
    return noxtls_aes_accel_stm32u3_encrypt_block(key, data, output, type);
#elif defined(NOXTLS_STM32_FAMILY_U5)
    return noxtls_aes_accel_stm32u5_encrypt_block(key, data, output, type);
#elif defined(NOXTLS_STM32_FAMILY_WB)
    return noxtls_aes_accel_stm32wb_encrypt_block(key, data, output, type);
#else
    (void)key;
    (void)data;
    (void)output;
    (void)type;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

noxtls_return_t noxtls_aes_accel_stm32_decrypt_block(const uint8_t *key,
                                                      const uint8_t *data,
                                                      uint8_t *output,
                                                      noxtls_aes_type_t type)
{
#if defined(NOXTLS_STM32_FAMILY_F2)
    return noxtls_aes_accel_stm32f2_decrypt_block(key, data, output, type);
#elif defined(NOXTLS_STM32_FAMILY_F4)
    return noxtls_aes_accel_stm32f4_decrypt_block(key, data, output, type);
#elif defined(NOXTLS_STM32_FAMILY_F7)
    return noxtls_aes_accel_stm32f7_decrypt_block(key, data, output, type);
#elif defined(NOXTLS_STM32_FAMILY_H7)
    return noxtls_aes_accel_stm32h7_decrypt_block(key, data, output, type);
#elif defined(NOXTLS_STM32_FAMILY_L4)
    return noxtls_aes_accel_stm32l4_decrypt_block(key, data, output, type);
#elif defined(NOXTLS_STM32_FAMILY_U3)
    return noxtls_aes_accel_stm32u3_decrypt_block(key, data, output, type);
#elif defined(NOXTLS_STM32_FAMILY_U5)
    return noxtls_aes_accel_stm32u5_decrypt_block(key, data, output, type);
#elif defined(NOXTLS_STM32_FAMILY_WB)
    return noxtls_aes_accel_stm32wb_decrypt_block(key, data, output, type);
#else
    (void)key;
    (void)data;
    (void)output;
    (void)type;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

noxtls_return_t noxtls_sha256_accel_stm32_round(noxtls_sha_ctx_t *ctx, const uint8_t *input)
{
    return noxtls_stm32_hash_core_sha256_round(ctx, input);
}

noxtls_return_t noxtls_sha256_accel_stm32_blocks(noxtls_sha_ctx_t *ctx,
                                                  const uint8_t *input,
                                                  uint32_t block_count)
{
    return noxtls_stm32_hash_core_sha256_blocks(ctx, input, block_count);
}
