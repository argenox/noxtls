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
* File:    noxtls_esp32s31_port_hash.c
* Summary: NoxTLS SHA-2 accelerator ports on the ESP32-S31 SHA engine
*
*****************************************************************************/

/**
 * @file noxtls_esp32s31_port_hash.c
 * @brief SHA-256 and SHA-512 block hooks served by the ESP32-S31 SHA accelerator.
 *
 * NoxTLS keeps buffering, padding and the message length; the hooks convert the
 * chaining value between the context words and the engine word image (each H value
 * stored byte-swapped, 64-bit values as high then low word) and run whole blocks
 * through esp32s31_sha_blocks() of nox-driver-lib.
 */

#include <stddef.h>
#include <stdint.h>

#include "noxtls_sha.h"
#include "sha512/noxtls_sha512.h"
#include "esp32s31_sha.h"

/** @brief SHA-256 chaining words. */
#define NOXTLS_ESP32S31_SHA256_WORDS 8U
/** @brief SHA-512 chaining words (64-bit). */
#define NOXTLS_ESP32S31_SHA512_WORDS 8U
/** @brief Bits per 32-bit half. */
#define NOXTLS_ESP32S31_HALF_BITS    32U

/** @brief Non-zero once the engine clock was enabled. */
static uint8_t s_noxtls_esp32s31_sha_ready;
/** @brief Blocks processed by the engine (telemetry). */
static uint32_t s_noxtls_esp32s31_sha_blocks;

uint32_t noxtls_esp32s31_hash_block_count(void)
{
    return s_noxtls_esp32s31_sha_blocks;
}

/**
 * @brief Enable the engine on first use.
 * @internal
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_NOT_SUPPORTED (software runs).
 */
static noxtls_return_t noxtls_esp32s31_sha_prepare(void)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if (s_noxtls_esp32s31_sha_ready == 0U) {
        if (esp32s31_sha_init() == NOXDRV_SUCCESS) {
            s_noxtls_esp32s31_sha_ready = 1U;
        } else {
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
        }
    }
    return rc;
}

/**
 * @brief Byte swap of a 32-bit word.
 * @internal
 *
 * @param[in] v Value.
 *
 * @return Swapped value.
 */
static uint32_t noxtls_esp32s31_bswap32(uint32_t v)
{
    return ((v & 0x000000FFU) << 24) | ((v & 0x0000FF00U) << 8) | ((v >> 8) & 0x0000FF00U) | (v >> 24);
}

noxtls_return_t noxtls_sha256_blocks_accel_port(noxtls_sha_ctx_t *ctx, const uint8_t *input, uint32_t block_count)
{
    uint32_t st[NOXTLS_ESP32S31_SHA256_WORDS];
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    uint32_t i;

    if ((ctx != NULL) && (input != NULL) && (block_count != 0U) &&
        (noxtls_esp32s31_sha_prepare() == NOXTLS_RETURN_SUCCESS)) {
        for (i = 0U; i < NOXTLS_ESP32S31_SHA256_WORDS; i++) {
            st[i] = noxtls_esp32s31_bswap32(ctx->u.md32.h[i]);
        }
        if (esp32s31_sha_blocks(ESP32S31_SHA_ALG_SHA256, st, input, block_count) == NOXDRV_SUCCESS) {
            for (i = 0U; i < NOXTLS_ESP32S31_SHA256_WORDS; i++) {
                ctx->u.md32.h[i] = noxtls_esp32s31_bswap32(st[i]);
            }
            s_noxtls_esp32s31_sha_blocks += block_count;
            rc = NOXTLS_RETURN_SUCCESS;
        }
    }
    return rc;
}

noxtls_return_t noxtls_sha256_round_accel_port(noxtls_sha_ctx_t *ctx, const uint8_t *input)
{
    return noxtls_sha256_blocks_accel_port(ctx, input, 1U);
}

noxtls_return_t noxtls_sha512_blocks_accel_port(noxtls_sha512_ctx_t *ctx, const uint8_t *input, uint32_t block_count)
{
    uint32_t st[2U * NOXTLS_ESP32S31_SHA512_WORDS];
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    uint32_t i;

    if ((ctx != NULL) && (input != NULL) && (block_count != 0U) &&
        (noxtls_esp32s31_sha_prepare() == NOXTLS_RETURN_SUCCESS)) {
        for (i = 0U; i < NOXTLS_ESP32S31_SHA512_WORDS; i++) {
            st[2U * i] = noxtls_esp32s31_bswap32((uint32_t)(ctx->h[i] >> NOXTLS_ESP32S31_HALF_BITS));
            st[(2U * i) + 1U] = noxtls_esp32s31_bswap32((uint32_t)ctx->h[i]);
        }
        if (esp32s31_sha_blocks(ESP32S31_SHA_ALG_SHA512, st, input, block_count) == NOXDRV_SUCCESS) {
            for (i = 0U; i < NOXTLS_ESP32S31_SHA512_WORDS; i++) {
                ctx->h[i] = ((uint64_t)noxtls_esp32s31_bswap32(st[2U * i]) << NOXTLS_ESP32S31_HALF_BITS) |
                            (uint64_t)noxtls_esp32s31_bswap32(st[(2U * i) + 1U]);
            }
            s_noxtls_esp32s31_sha_blocks += block_count;
            rc = NOXTLS_RETURN_SUCCESS;
        }
    }
    return rc;
}
