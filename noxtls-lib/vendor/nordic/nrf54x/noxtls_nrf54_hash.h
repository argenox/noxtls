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
* File:    noxtls_nrf54_hash.h
* Summary: CRACEN BA413 SHA-2 block function (SHA-224/256/384/512)
*
*****************************************************************************/

/**
 * @file noxtls_nrf54_hash.h
 * @brief SHA-2 compression of whole blocks on the CRACEN BA413 hash engine.
 * @ingroup noxtls_nrf54
 *
 * Specification: FIPS 180-4 (August 2015) §6.2 (SHA-224/256) and §6.4
 * (SHA-384/512). NoxTLS keeps the message buffering, padding and length
 * (FIPS 180-4 §5.1); the engine resumes from the caller's chaining value H,
 * processes whole blocks and returns the new H. SHA-224 and SHA-384 use the
 * SHA-256 and SHA-512 compression functions (only H(0) and the truncation
 * differ, both handled by NoxTLS).
 */

#ifndef NOXTLS_NRF54_HASH_H
#define NOXTLS_NRF54_HASH_H

#include <stdint.h>

#include "noxtls_nrf54_cracen.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Compression function selector. */
typedef enum {
    NOXTLS_NRF54_SHA256 = 0, /**< SHA-224 / SHA-256 compression (64-byte blocks, 32-byte state). */
    NOXTLS_NRF54_SHA512 = 1  /**< SHA-384 / SHA-512 compression (128-byte blocks, 64-byte state). */
} noxtls_nrf54_sha_t;

/** Hash module state (DMA descriptors and buffers; defined in noxtls_nrf54_hash.c). */
typedef struct {
    noxtls_nrf54_desc_t fetch[3];                         /**< Config word, state, message. */
    noxtls_nrf54_desc_t push[1];                          /**< New state. */
    uint32_t cfg;                                         /**< Configuration word. */
    uint8_t state[NOXTLS_NRF54_HASH_STATE_512];           /**< Chaining value (engine byte order). */
    uint8_t bounce[NOXTLS_NRF54_CONFIG_BOUNCE_SIZE];      /**< Message bounce for data outside the DMA window. */
} noxtls_nrf54_hash_t;

/**
 * @brief Process whole blocks: state = compress*(state, data).
 *
 * @param[in]     alg    Compression function.
 * @param[in,out] state  Chaining value, FIPS 180-4 byte order (big-endian
 *                       words): 32 bytes (SHA-256) or 64 bytes (SHA-512).
 * @param[in]     data   Message blocks.
 * @param[in]     blocks Number of blocks (0 returns success).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM,
 *         NOXTLS_RETURN_NOT_SUPPORTED (engine absent, disabled or in use: use
 *         software), NOXTLS_RETURN_FAILED or NOXTLS_RETURN_TIMEOUT. On failure
 *         @p state is unchanged.
 */
noxtls_return_t noxtls_nrf54_hash_blocks(noxtls_nrf54_sha_t alg, uint8_t *state, const uint8_t *data, uint32_t blocks);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_NRF54_HASH_H */
