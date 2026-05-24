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
* File:    noxtls_esp32_sha256_accel.c
* Summary: ESP-IDF SHA-224/256 acceleration hook implementation
*
*
*****************************************************************************/

#include <stdint.h>
#include <stdbool.h>

#include "noxtls_sha.h"
#include "noxtls_sha256.h"
#include "noxtls_common.h"

#if defined(ESP_PLATFORM)
#include "noxtls_esp_hw_accel.h"
#include "soc/soc_caps.h"
#if defined(SOC_SHA_SUPPORTED) && SOC_SHA_SUPPORTED
#include "sha/sha_core.h"
#if defined(SOC_SHA_SUPPORT_DMA) && SOC_SHA_SUPPORT_DMA
#if defined(CONFIG_IDF_TARGET_ESP32P4)
#define NOXTLS_SHA_DMA_MODE_THRESHOLD 512U
#elif defined(CONFIG_IDF_TARGET_ESP32S3)
#define NOXTLS_SHA_DMA_MODE_THRESHOLD 256U
#else
#define NOXTLS_SHA_DMA_MODE_THRESHOLD 128U
#endif
#endif
#endif
#endif

/**
 * @brief Swap 32-bit endianness
 *
 * @param x 32-bit value to swap
 *
 * @return Swapped 32-bit value
 */
static uint32_t noxtls_sha_bswap32(uint32_t x)
{
    return ((x & 0x000000FFu) << 24) |
           ((x & 0x0000FF00u) << 8) |
           ((x & 0x00FF0000u) >> 8) |
           ((x & 0xFF000000u) >> 24);
}

/**
 * @brief SHA-256 round acceleration hook
 *
 * @param ctx SHA-256 context
 * @param input Data to round
 *
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL,
 *         NOXTLS_RETURN_NOT_SUPPORTED if SHA-256 acceleration is not supported
 */
noxtls_return_t noxtls_sha256_round_accel_port(noxtls_sha_ctx_t *ctx, const uint8_t *input)
{
#if defined(ESP_PLATFORM) && defined(SOC_SHA_SUPPORTED) && SOC_SHA_SUPPORTED && \
    defined(SOC_SHA_SUPPORT_RESUME) && SOC_SHA_SUPPORT_RESUME && \
    CONFIG_NOXTLS_ESP_HW_SHA
    esp_sha_type sha_type;
    bool is_first_block;
    uint32_t hw_state[SHA256_STATE_WORDS];
    uint32_t i;

    if(ctx == NULL || input == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->algo == NOXTLS_HASH_SHA_256) {
        sha_type = SHA2_256;
    } else if(ctx->algo == NOXTLS_HASH_SHA_224) {
        sha_type = SHA2_224;
    } else {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    is_first_block = (ctx->length == 0U);

    esp_sha_acquire_hardware();
    esp_sha_set_mode(sha_type);
    if(!is_first_block) {
        for(i = 0; i < SHA256_STATE_WORDS; i++) {
            hw_state[i] = noxtls_sha_bswap32(ctx->h[i]);
        }
        esp_sha_write_digest_state(sha_type, hw_state);
    }
    esp_sha_block(sha_type, input, is_first_block);
    esp_sha_read_digest_state(sha_type, hw_state);
    esp_sha_release_hardware();

    for(i = 0; i < SHA256_STATE_WORDS; i++) {
        ctx->h[i] = noxtls_sha_bswap32(hw_state[i]);
    }

    return NOXTLS_RETURN_SUCCESS;
#else
    (void)ctx;
    (void)input;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

/**
 * @brief SHA-256 blocks acceleration hook
 *
 * @param ctx SHA-256 context
 * @param input Data to process
 * @param block_count Number of blocks to process
 *
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL,
 *         NOXTLS_RETURN_NOT_SUPPORTED if SHA-256 acceleration is not supported
 */
noxtls_return_t noxtls_sha256_blocks_accel_port(noxtls_sha_ctx_t *ctx, const uint8_t *input, uint32_t block_count)
{
#if defined(ESP_PLATFORM) && defined(SOC_SHA_SUPPORTED) && SOC_SHA_SUPPORTED && \
    defined(SOC_SHA_SUPPORT_RESUME) && SOC_SHA_SUPPORT_RESUME && \
    CONFIG_NOXTLS_ESP_HW_SHA
    esp_sha_type sha_type;
    bool is_first_block;
    uint32_t hw_state[SHA256_STATE_WORDS];
    uint32_t i;

    if(ctx == NULL || input == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(block_count == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }

    if(ctx->algo == NOXTLS_HASH_SHA_256) {
        sha_type = SHA2_256;
    } else if(ctx->algo == NOXTLS_HASH_SHA_224) {
        sha_type = SHA2_224;
    } else {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    is_first_block = (ctx->length == 0U);

    esp_sha_acquire_hardware();
    esp_sha_set_mode(sha_type);
    if(!is_first_block) {
        for(i = 0; i < SHA256_STATE_WORDS; i++) {
            hw_state[i] = noxtls_sha_bswap32(ctx->h[i]);
        }
        esp_sha_write_digest_state(sha_type, hw_state);
    }

#if defined(SOC_SHA_SUPPORT_DMA) && SOC_SHA_SUPPORT_DMA
    if((block_count * SHA256_BLOCK_SIZE_BYTES) > NOXTLS_SHA_DMA_MODE_THRESHOLD &&
       esp_sha_dma(sha_type,
                   input,
                   block_count * SHA256_BLOCK_SIZE_BYTES,
                   NULL,
                   0,
                   is_first_block) == 0) {
        /* DMA path completed successfully. */
    } else
#endif
    {
        for(i = 0; i < block_count; i++) {
            esp_sha_block(sha_type, input + (i * SHA256_BLOCK_SIZE_BYTES), is_first_block);
            is_first_block = false;
        }
    }

    esp_sha_read_digest_state(sha_type, hw_state);
    esp_sha_release_hardware();

    for(i = 0; i < SHA256_STATE_WORDS; i++) {
        ctx->h[i] = noxtls_sha_bswap32(hw_state[i]);
    }

    return NOXTLS_RETURN_SUCCESS;
#else
    (void)ctx;
    (void)input;
    (void)block_count;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}
