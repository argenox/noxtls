/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_stm32_gcm_core.h
* Summary: STM32 CRYP AES-GCM register-level backend.
*****************************************************************************/

#ifndef _NOXTLS_STM32_GCM_CORE_H_
#define _NOXTLS_STM32_GCM_CORE_H_

#include "vendor/st/noxtls_stm32_accel.h"

noxtls_return_t noxtls_stm32_gcm_encrypt(noxtls_stm32_accel_family_t family,
                                          const uint8_t *key,
                                          noxtls_aes_type_t type,
                                          const uint8_t nonce[12],
                                          const uint8_t *aad,
                                          uint32_t aad_len,
                                          const uint8_t *plaintext,
                                          uint32_t plaintext_len,
                                          uint8_t *ciphertext,
                                          uint8_t tag[16]);

noxtls_return_t noxtls_stm32_gcm_decrypt(noxtls_stm32_accel_family_t family,
                                          const uint8_t *key,
                                          noxtls_aes_type_t type,
                                          const uint8_t nonce[12],
                                          const uint8_t *aad,
                                          uint32_t aad_len,
                                          const uint8_t *ciphertext,
                                          uint32_t ciphertext_len,
                                          const uint8_t tag[16],
                                          uint8_t *plaintext);

int noxtls_stm32_gcm_is_supported(void);
int noxtls_stm32_gcm_support_status(void);

#define NOXTLS_STM32_GCM_STATUS_READY          1
#define NOXTLS_STM32_GCM_STATUS_FORCED         2
#define NOXTLS_STM32_GCM_STATUS_H7_NO_CRYP     3
#define NOXTLS_STM32_GCM_STATUS_H7_UNSUPPORTED 4
#define NOXTLS_STM32_GCM_STATUS_NOT_STM32H7    5

#endif /* _NOXTLS_STM32_GCM_CORE_H_ */
