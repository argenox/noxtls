/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_stm32_hash_core.h
* Summary: In-house STM32 SHA-256 backend helpers.
*****************************************************************************/

#ifndef _NOXTLS_STM32_HASH_CORE_H_
#define _NOXTLS_STM32_HASH_CORE_H_

#include "vendor/st/noxtls_stm32_accel.h"

#define NOXTLS_STM32_SHA256_ROUND_COUNT 64u
#define NOXTLS_STM32_SHA_CH(X, Y, Z)     (((X) & (Y)) ^ ((~(X)) & (Z)))
#define NOXTLS_STM32_SHA_MAJ(X,Y, Z)     (((X) & (Y)) ^ ((X) & (Z)) ^ ((Y) & (Z)))
#define NOXTLS_STM32_SHA_ROTR(X, N)      (((X) >> (N)) | ((X) << (32u - (N))))
#define NOXTLS_STM32_SHA_SUM_FROM_0(X)   (NOXTLS_STM32_SHA_ROTR((X), 2u)  ^ NOXTLS_STM32_SHA_ROTR((X), 13u) ^ NOXTLS_STM32_SHA_ROTR((X), 22u))
#define NOXTLS_STM32_SHA_SUM_FROM_1(X)   (NOXTLS_STM32_SHA_ROTR((X), 6u)  ^ NOXTLS_STM32_SHA_ROTR((X), 11u) ^ NOXTLS_STM32_SHA_ROTR((X), 25u))
#define NOXTLS_STM32_SHA_SIGMA_FROM_0(X) (NOXTLS_STM32_SHA_ROTR((X), 7u)  ^ NOXTLS_STM32_SHA_ROTR((X), 18u) ^ ((X) >> 3u))
#define NOXTLS_STM32_SHA_SIGMA_FROM_1(X) (NOXTLS_STM32_SHA_ROTR((X), 17u) ^ NOXTLS_STM32_SHA_ROTR((X), 19u) ^ ((X) >> 10u))

noxtls_return_t noxtls_stm32_hash_core_sha256_round(noxtls_sha_ctx_t *ctx,
                                                     const uint8_t *input);

noxtls_return_t noxtls_stm32_hash_core_sha256_blocks(noxtls_sha_ctx_t *ctx,
                                                      const uint8_t *input,
                                                      uint32_t block_count);

#endif /* _NOXTLS_STM32_HASH_CORE_H_ */
