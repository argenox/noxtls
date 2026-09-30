/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_stm32_u5_aes_core.h
* Summary: STM32U5 AES peripheral (AES-IP) register-level backend.
*****************************************************************************/

#ifndef _NOXTLS_STM32_U5_AES_CORE_H_
#define _NOXTLS_STM32_U5_AES_CORE_H_

#include "vendor/st/noxtls_stm32_accel.h"

noxtls_return_t noxtls_stm32_u5_aes_encrypt_block(const uint8_t *key,
                                                   const uint8_t *data,
                                                   uint8_t *output,
                                                   noxtls_aes_type_t type);

noxtls_return_t noxtls_stm32_u5_aes_decrypt_block(const uint8_t *key,
                                                   const uint8_t *data,
                                                   uint8_t *output,
                                                   noxtls_aes_type_t type);

noxtls_return_t noxtls_stm32_u5_gcm_encrypt(const uint8_t *key,
                                             noxtls_aes_type_t type,
                                             const uint8_t nonce[12],
                                             const uint8_t *aad,
                                             uint32_t aad_len,
                                             const uint8_t *plaintext,
                                             uint32_t plaintext_len,
                                             uint8_t *ciphertext,
                                             uint8_t tag[16]);

noxtls_return_t noxtls_stm32_u5_gcm_decrypt(const uint8_t *key,
                                             noxtls_aes_type_t type,
                                             const uint8_t nonce[12],
                                             const uint8_t *aad,
                                             uint32_t aad_len,
                                             const uint8_t *ciphertext,
                                             uint32_t ciphertext_len,
                                             const uint8_t tag[16],
                                             uint8_t *plaintext);

#endif /* _NOXTLS_STM32_U5_AES_CORE_H_ */
