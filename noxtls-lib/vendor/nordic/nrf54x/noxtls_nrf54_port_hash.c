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
* File:    noxtls_nrf54_port_hash.c
* Summary: NoxTLS SHA-2 accelerator ports on the nRF54L CRACEN
*
*****************************************************************************/

/**
 * @file noxtls_nrf54_port_hash.c
 * @brief SHA-224/256 and SHA-384/512 block hooks served by the CRACEN BA413.
 * @ingroup noxtls_nrf54
 *
 * NoxTLS keeps buffering, padding and the message length; the hooks convert
 * the chaining value between the context words and the FIPS 180-4 byte order
 * used by the engine and run whole blocks in hardware. A message in RRAM is
 * read by the CryptoMaster DMA directly.
 */

#include <stddef.h>

#include "noxtls_sha.h"
#include "sha512/noxtls_sha512.h"
#include "noxtls_nrf54_hash.h"

/** @brief SHA-256 chaining words. */
#define NOXTLS_NRF54_PORT_SHA256_WORDS  8U
/** @brief SHA-512 chaining words. */
#define NOXTLS_NRF54_PORT_SHA512_WORDS  8U
/** @brief Bytes per 32-bit word. */
#define NOXTLS_NRF54_PORT_W32_BYTES     4U
/** @brief Bytes per 64-bit word. */
#define NOXTLS_NRF54_PORT_W64_BYTES     8U
/** @brief Bits per byte. */
#define NOXTLS_NRF54_PORT_BITS_PER_BYTE 8U

noxtls_return_t noxtls_sha256_blocks_accel_port(noxtls_sha_ctx_t *ctx, const uint8_t *input, uint32_t block_count)
{
    uint8_t st[NOXTLS_NRF54_HASH_STATE_256];
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    uint32_t i;
    uint32_t b;

    if ((ctx != NULL) && (input != NULL) && (block_count != 0U)) {
        for (i = 0U; i < NOXTLS_NRF54_PORT_SHA256_WORDS; i++) {
            for (b = 0U; b < NOXTLS_NRF54_PORT_W32_BYTES; b++) {
                st[(i * NOXTLS_NRF54_PORT_W32_BYTES) + b] =
                    (uint8_t)(ctx->h[i] >> ((NOXTLS_NRF54_PORT_W32_BYTES - 1U - b) * NOXTLS_NRF54_PORT_BITS_PER_BYTE));
            }
        }
        if (noxtls_nrf54_hash_blocks(NOXTLS_NRF54_SHA256, st, input, block_count) == NOXTLS_RETURN_SUCCESS) {
            for (i = 0U; i < NOXTLS_NRF54_PORT_SHA256_WORDS; i++) {
                uint32_t w = 0U;

                for (b = 0U; b < NOXTLS_NRF54_PORT_W32_BYTES; b++) {
                    w = (w << NOXTLS_NRF54_PORT_BITS_PER_BYTE) | (uint32_t)st[(i * NOXTLS_NRF54_PORT_W32_BYTES) + b];
                }
                ctx->h[i] = w;
            }
            rc = NOXTLS_RETURN_SUCCESS;
        }
        noxtls_nrf54_wipe(st, (uint32_t)sizeof(st));
    }
    return rc;
}

noxtls_return_t noxtls_sha256_round_accel_port(noxtls_sha_ctx_t *ctx, const uint8_t *input)
{
    return noxtls_sha256_blocks_accel_port(ctx, input, 1U);
}

noxtls_return_t noxtls_sha512_blocks_accel_port(noxtls_sha512_ctx_t *ctx, const uint8_t *input, uint32_t block_count)
{
    uint8_t st[NOXTLS_NRF54_HASH_STATE_512];
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    uint32_t i;
    uint32_t b;

    if ((ctx != NULL) && (input != NULL) && (block_count != 0U)) {
        for (i = 0U; i < NOXTLS_NRF54_PORT_SHA512_WORDS; i++) {
            for (b = 0U; b < NOXTLS_NRF54_PORT_W64_BYTES; b++) {
                st[(i * NOXTLS_NRF54_PORT_W64_BYTES) + b] =
                    (uint8_t)(ctx->h[i] >> ((NOXTLS_NRF54_PORT_W64_BYTES - 1U - b) * NOXTLS_NRF54_PORT_BITS_PER_BYTE));
            }
        }
        if (noxtls_nrf54_hash_blocks(NOXTLS_NRF54_SHA512, st, input, block_count) == NOXTLS_RETURN_SUCCESS) {
            for (i = 0U; i < NOXTLS_NRF54_PORT_SHA512_WORDS; i++) {
                uint64_t w = 0U;

                for (b = 0U; b < NOXTLS_NRF54_PORT_W64_BYTES; b++) {
                    w = (w << NOXTLS_NRF54_PORT_BITS_PER_BYTE) | (uint64_t)st[(i * NOXTLS_NRF54_PORT_W64_BYTES) + b];
                }
                ctx->h[i] = w;
            }
            rc = NOXTLS_RETURN_SUCCESS;
        }
        noxtls_nrf54_wipe(st, (uint32_t)sizeof(st));
    }
    return rc;
}
