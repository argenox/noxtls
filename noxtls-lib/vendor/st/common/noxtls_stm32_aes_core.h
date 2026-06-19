/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_stm32_aes_core.h
* Summary: In-house STM32 AES register-level backend helpers.
*****************************************************************************/

#ifndef _NOXTLS_STM32_AES_CORE_H_
#define _NOXTLS_STM32_AES_CORE_H_

#include "vendor/st/noxtls_stm32_accel.h"

#define NOXTLS_STM32_AES_POLL_LIMIT       1000000u
#define NOXTLS_STM32_AES_CR_OFF           0x00u
#define NOXTLS_STM32_AES_SR_OFF           0x04u
#define NOXTLS_STM32_AES_DIN_OFF          0x08u
#define NOXTLS_STM32_AES_DOUT_OFF         0x0Cu
#define NOXTLS_STM32_AES_K0LR_OFF         0x20u
#define NOXTLS_STM32_AES_IV0LR_OFF        0x40u
#define NOXTLS_STM32_AES_CR_ALGODIR       (1u << 2)
#define NOXTLS_STM32_AES_CR_DATATYPE_8B   (2u << 1)
#define NOXTLS_STM32_AES_CR_KEYSIZE_SHIFT 8u
#define NOXTLS_STM32_AES_CR_FFLUSH        (1u << 14)
#define NOXTLS_STM32_AES_CR_EN            (1u << 15)
#define NOXTLS_STM32_AES_SR_IFNF          (1u << 1)
#define NOXTLS_STM32_AES_SR_OFNE          (1u << 2)
#define NOXTLS_STM32_AES_SR_BUSY          (1u << 4)
#define NOXTLS_STM32_WORDS_PER_BLOCK      4u
#define NOXTLS_STM32_AES_WORD_BYTES       4u
#define NOXTLS_STM32_REG32(addr)          (*(volatile uint32_t *)(uintptr_t)(addr))

/* Default bases; may be overridden at compile time for board-specific maps. */
#ifndef NOXTLS_STM32_F2_AES_BASE
#define NOXTLS_STM32_F2_AES_BASE 0x50060000u
#endif
#ifndef NOXTLS_STM32_F4_AES_BASE
#define NOXTLS_STM32_F4_AES_BASE 0x50060000u
#endif
#ifndef NOXTLS_STM32_F7_AES_BASE
#define NOXTLS_STM32_F7_AES_BASE 0x50060000u
#endif
#ifndef NOXTLS_STM32_H7_AES_BASE
#define NOXTLS_STM32_H7_AES_BASE 0x48021000u
#endif
#ifndef NOXTLS_STM32_L4_AES_BASE
#define NOXTLS_STM32_L4_AES_BASE 0x50060000u
#endif
#ifndef NOXTLS_STM32_U3_AES_BASE
#define NOXTLS_STM32_U3_AES_BASE 0x420C0000u
#endif
#ifndef NOXTLS_STM32_U5_AES_BASE
#define NOXTLS_STM32_U5_AES_BASE 0x420C0000u
#endif
#ifndef NOXTLS_STM32_WB_AES_BASE
#define NOXTLS_STM32_WB_AES_BASE 0x58001000u
#endif

noxtls_return_t noxtls_stm32_aes_core_encrypt_block(noxtls_stm32_accel_family_t family,
                                                     const uint8_t *key,
                                                     const uint8_t *data,
                                                     uint8_t *output,
                                                     noxtls_aes_type_t type);

noxtls_return_t noxtls_stm32_aes_core_decrypt_block(noxtls_stm32_accel_family_t family,
                                                     const uint8_t *key,
                                                     const uint8_t *data,
                                                     uint8_t *output,
                                                     noxtls_aes_type_t type);

#endif /* _NOXTLS_STM32_AES_CORE_H_ */
