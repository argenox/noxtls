/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_stm32_hash_dispatch.c
* Summary: STM32 family dispatch for SHA-256 acceleration backend.
*****************************************************************************/

#include "vendor/st/noxtls_stm32_accel.h"
#include "vendor/st/common/noxtls_stm32_hash_core.h"

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
