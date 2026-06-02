/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_stm32_hash_dispatch.c
* Summary: STM32 family dispatch for SHA-256 acceleration backend.
*****************************************************************************/

#include "vendor/st/noxtls_stm32_accel.h"

noxtls_return_t noxtls_sha256_accel_stm32_round(noxtls_sha_ctx_t *ctx, const uint8_t *input)
{
    (void)ctx;
    (void)input;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_sha256_accel_stm32_blocks(noxtls_sha_ctx_t *ctx,
                                                  const uint8_t *input,
                                                  uint32_t block_count)
{
    (void)ctx;
    (void)input;
    (void)block_count;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}
