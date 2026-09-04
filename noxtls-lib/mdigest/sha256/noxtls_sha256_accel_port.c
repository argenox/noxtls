/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Licensed under the GNU General Public License v2.0 or later,
* or alternatively under a commercial license from
* Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
*
* File:    noxtls_sha256_accel_port.c
* Summary: Platform SHA-224/256 acceleration hook (default fallback)
*
*
*****************************************************************************/

#include <stddef.h>
#include <stdint.h>

#include "noxtls_sha.h"
#include "noxtls_sha256_accel_port.h"
#include "noxtls_common.h"
#include "vendor/st/noxtls_hw_accel_autoconfig.h"
#include "vendor/st/noxtls_stm32_accel.h"

/**
 * @brief SHA-256 round acceleration port
 * 
 * @param ctx The SHA-256 context
 * @param input The input data
 * @return The return value
 */
noxtls_return_t noxtls_sha256_round_accel_port(noxtls_sha_ctx_t *ctx, const uint8_t *input)
{
#if NOXTLS_FEATURE_HASH_ACCEL_STM32
    return noxtls_sha256_accel_stm32_round(ctx, input);
#else
    if(ctx != NULL) { ctx->algo = ctx->algo; }
    (void)input;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

/**
 * @brief SHA-256 blocks acceleration port
 * 
 * @param ctx The SHA-256 context
 * @param input The input data
 * @param block_count The number of blocks
 * @return The return value
 */
noxtls_return_t noxtls_sha256_blocks_accel_port(noxtls_sha_ctx_t *ctx, const uint8_t *input, uint32_t block_count)
{
#if NOXTLS_FEATURE_HASH_ACCEL_STM32
    return noxtls_sha256_accel_stm32_blocks(ctx, input, block_count);
#else
    if(ctx != NULL) { ctx->algo = ctx->algo; }
    (void)input;
    (void)block_count;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}


/* MISRA 8.6: STM32 accel host stubs when hardware backends are not in this build. */
#if (NOXTLS_FEATURE_AES_ACCEL_STM32 == 0)
static noxtls_return_t noxtls_stm32_aes_stub(const uint8_t *key,
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

noxtls_return_t noxtls_aes_accel_stm32_encrypt_block(const uint8_t *key,
                                                      const uint8_t *data,
                                                      uint8_t *output,
                                                      noxtls_aes_type_t type)
{
    return noxtls_stm32_aes_stub(key, data, output, type);
}

noxtls_return_t noxtls_aes_accel_stm32_decrypt_block(const uint8_t *key,
                                                      const uint8_t *data,
                                                      uint8_t *output,
                                                      noxtls_aes_type_t type)
{
    return noxtls_stm32_aes_stub(key, data, output, type);
}

noxtls_return_t noxtls_aes_accel_stm32f2_encrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type)
{
    return noxtls_stm32_aes_stub(key, data, output, type);
}

noxtls_return_t noxtls_aes_accel_stm32f2_decrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type)
{
    return noxtls_stm32_aes_stub(key, data, output, type);
}

noxtls_return_t noxtls_aes_accel_stm32f4_encrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type)
{
    return noxtls_stm32_aes_stub(key, data, output, type);
}

noxtls_return_t noxtls_aes_accel_stm32f4_decrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type)
{
    return noxtls_stm32_aes_stub(key, data, output, type);
}

noxtls_return_t noxtls_aes_accel_stm32f7_encrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type)
{
    return noxtls_stm32_aes_stub(key, data, output, type);
}

noxtls_return_t noxtls_aes_accel_stm32f7_decrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type)
{
    return noxtls_stm32_aes_stub(key, data, output, type);
}

noxtls_return_t noxtls_aes_accel_stm32h7_encrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type)
{
    return noxtls_stm32_aes_stub(key, data, output, type);
}

noxtls_return_t noxtls_aes_accel_stm32h7_decrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type)
{
    return noxtls_stm32_aes_stub(key, data, output, type);
}

noxtls_return_t noxtls_aes_accel_stm32l4_encrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type)
{
    return noxtls_stm32_aes_stub(key, data, output, type);
}

noxtls_return_t noxtls_aes_accel_stm32l4_decrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type)
{
    return noxtls_stm32_aes_stub(key, data, output, type);
}

noxtls_return_t noxtls_aes_accel_stm32u3_encrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type)
{
    return noxtls_stm32_aes_stub(key, data, output, type);
}

noxtls_return_t noxtls_aes_accel_stm32u3_decrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type)
{
    return noxtls_stm32_aes_stub(key, data, output, type);
}

noxtls_return_t noxtls_aes_accel_stm32u5_encrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type)
{
    return noxtls_stm32_aes_stub(key, data, output, type);
}

noxtls_return_t noxtls_aes_accel_stm32u5_decrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type)
{
    return noxtls_stm32_aes_stub(key, data, output, type);
}

noxtls_return_t noxtls_aes_accel_stm32wb_encrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type)
{
    return noxtls_stm32_aes_stub(key, data, output, type);
}

noxtls_return_t noxtls_aes_accel_stm32wb_decrypt_block(const uint8_t *key,
                                                        const uint8_t *data,
                                                        uint8_t *output,
                                                        noxtls_aes_type_t type)
{
    return noxtls_stm32_aes_stub(key, data, output, type);
}

#endif /* NOXTLS_FEATURE_AES_ACCEL_STM32 == 0 */

#if (NOXTLS_FEATURE_HASH_ACCEL_STM32 == 0)
noxtls_return_t noxtls_sha256_accel_stm32_round(noxtls_sha_ctx_t *ctx, const uint8_t *input)
{
    if(ctx != NULL) { ctx->algo = ctx->algo; }
    (void)input;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_sha256_accel_stm32_blocks(noxtls_sha_ctx_t *ctx,
                                                  const uint8_t *input,
                                                  uint32_t block_count)
{
    if(ctx != NULL) { ctx->algo = ctx->algo; }
    (void)input;
    (void)block_count;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}
#endif /* NOXTLS_FEATURE_HASH_ACCEL_STM32 == 0 */
