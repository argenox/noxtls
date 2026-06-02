/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File: noxtls_stm32f4_accel.c
* Summary: STM32F4 AES acceleration backend (in-house register-level core).
*****************************************************************************/

#include "vendor/st/common/noxtls_stm32_aes_core.h"

noxtls_return_t noxtls_aes_accel_stm32f4_encrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type)
{
    return noxtls_stm32_aes_core_encrypt_block(NOXTLS_STM32_ACCEL_F4, key, data, output, type);
}

noxtls_return_t noxtls_aes_accel_stm32f4_decrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type)
{
    return noxtls_stm32_aes_core_decrypt_block(NOXTLS_STM32_ACCEL_F4, key, data, output, type);
}
