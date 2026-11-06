/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File: noxtls_stm32wb_accel.c
* Summary: STM32WB AES block backend of the generic STM32 dispatch layer.
*****************************************************************************/

/**
 * @file noxtls_stm32wb_accel.c
 * @brief noxtls_aes_accel_stm32wb_*_block() for vendor/st/common/noxtls_stm32_accel_dispatch.c.
 * @ingroup noxtls_stm32wb
 *
 * The generic STM32 dispatch layer (NOXTLS_CFG_FEATURE_STM32_HW_ACCEL) calls
 * these two functions for STM32WB targets. They run one ECB block on AES1
 * through the register-level driver (RM0434 AES chapter; AES1 is at
 * 0x50060000, not at the AES base the shared classic-CRYP core assumes).
 * The full WB backend (modes, AEAD, PKA, RNG) is selected with
 * NOXTLS_CFG_FEATURE_STM32WB_HW_ACCEL and does not use this file.
 */

#include <stddef.h>

#include "vendor/st/noxtls_stm32_accel.h"
#include "noxtls_stm32wb_aes.h"

/**
 * @brief Key bytes of an AES key size selector.
 * @internal
 *
 * @param[in] type Selector.
 *
 * @return 16, 32, or 0 for AES-192 / unknown (not in the hardware).
 */
static uint32_t noxtls_stm32wb_accel_key_len(noxtls_aes_type_t type)
{
    uint32_t len = 0U;

    if (type == NOXTLS_AES_128_BIT) {
        len = NOXTLS_STM32WB_AES_KEY_128;
    } else if (type == NOXTLS_AES_256_BIT) {
        len = NOXTLS_STM32WB_AES_KEY_256;
    } else {
        /* Not supported by AES1. */
    }
    return len;
}

noxtls_return_t noxtls_aes_accel_stm32wb_encrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type)
{
    return noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_ECB, 0U, key, noxtls_stm32wb_accel_key_len(type), NULL,
                                    data, output, NOXTLS_STM32WB_AES_BLOCK);
}

noxtls_return_t noxtls_aes_accel_stm32wb_decrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type)
{
    return noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_ECB, 1U, key, noxtls_stm32wb_accel_key_len(type), NULL,
                                    data, output, NOXTLS_STM32WB_AES_BLOCK);
}
