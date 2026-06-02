/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_stm32_accel.h
* Summary: STM32 acceleration dispatch API and family backend contracts.
*
*/

#ifndef _NOXTLS_STM32_ACCEL_H_
#define _NOXTLS_STM32_ACCEL_H_

#include <stdint.h>

#include "noxtls_common.h"
#include "encryption/aes/noxtls_aes.h"
#include "mdigest/noxtls_sha.h"

noxtls_return_t noxtls_aes_accel_stm32_encrypt_block(const uint8_t *key,
                                                      const uint8_t *data,
                                                      uint8_t *output,
                                                      noxtls_aes_type_t type);
noxtls_return_t noxtls_aes_accel_stm32_decrypt_block(const uint8_t *key,
                                                      const uint8_t *data,
                                                      uint8_t *output,
                                                      noxtls_aes_type_t type);

noxtls_return_t noxtls_sha256_accel_stm32_round(noxtls_sha_ctx_t *ctx, const uint8_t *input);
noxtls_return_t noxtls_sha256_accel_stm32_blocks(noxtls_sha_ctx_t *ctx,
                                                  const uint8_t *input,
                                                  uint32_t block_count);

/* Family backend API (implemented only in matching family source). */
noxtls_return_t noxtls_aes_accel_stm32f2_encrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type);
noxtls_return_t noxtls_aes_accel_stm32f2_decrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type);

noxtls_return_t noxtls_aes_accel_stm32f4_encrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type);
noxtls_return_t noxtls_aes_accel_stm32f4_decrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type);

noxtls_return_t noxtls_aes_accel_stm32f7_encrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type);
noxtls_return_t noxtls_aes_accel_stm32f7_decrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type);

noxtls_return_t noxtls_aes_accel_stm32h7_encrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type);
noxtls_return_t noxtls_aes_accel_stm32h7_decrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type);

noxtls_return_t noxtls_aes_accel_stm32l4_encrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type);
noxtls_return_t noxtls_aes_accel_stm32l4_decrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type);

noxtls_return_t noxtls_aes_accel_stm32u3_encrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type);
noxtls_return_t noxtls_aes_accel_stm32u3_decrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type);

noxtls_return_t noxtls_aes_accel_stm32u5_encrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type);
noxtls_return_t noxtls_aes_accel_stm32u5_decrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type);

noxtls_return_t noxtls_aes_accel_stm32wb_encrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type);
noxtls_return_t noxtls_aes_accel_stm32wb_decrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type);

#endif /* _NOXTLS_STM32_ACCEL_H_ */
