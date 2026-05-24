/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File: noxtls_stm32l4_accel.c
* Summary: STM32L4 AES acceleration backend stub.
*****************************************************************************/

#include "vendor/st/noxtls_stm32_accel.h"

noxtls_return_t noxtls_aes_accel_stm32l4_encrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type)
{
    (void)key;
    (void)data;
    (void)output;
    (void)type;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_aes_accel_stm32l4_decrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type)
{
    (void)key;
    (void)data;
    (void)output;
    (void)type;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}
