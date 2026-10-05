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
* File:    noxtls_nrf54_hash.c
* Summary: CRACEN BA413 SHA-2 block function (SHA-224/256/384/512)
*
*****************************************************************************/

/**
 * @file noxtls_nrf54_hash.c
 * @brief SHA-2 compression of whole blocks on the CRACEN BA413 hash engine.
 * @ingroup noxtls_nrf54
 *
 * One CryptoMaster job per chunk (FIPS 180-4 §6.2 / §6.4 hash computation):
 *   fetch: [config word = algorithm, no final flag] [H, header type, LAST]
 *          [message blocks, LAST | REALIGN]
 *   push:  [new H]
 * Message data outside the DMA window is copied through the bounce buffer.
 */

#include <stddef.h>
#include <string.h>

#include "noxtls_nrf54_hash.h"

/** @brief Bytes of the BA413 configuration word. */
#define NOXTLS_NRF54_HASH_CFG_BYTES     4U

/** Module state (data RAM: read and written by the DMA). */
static noxtls_nrf54_hash_t s_noxtls_nrf54_hash;

/**
 * @brief Run one job over @p len bytes (whole blocks) at @p src.
 * @internal
 *
 * @param[in] st  Module state (cfg and state set).
 * @param[in] src Message (DMA readable).
 * @param[in] len Bytes.
 * @param[in] ssz State bytes.
 *
 * @return noxtls_nrf54_cracen_cm_run() result.
 */
static noxtls_return_t noxtls_nrf54_hash_job(noxtls_nrf54_hash_t *st, const uint8_t *src, uint32_t len, uint32_t ssz)
{
    noxtls_nrf54_desc_set(&st->fetch[0], &st->cfg, NOXTLS_NRF54_HASH_CFG_BYTES | NOXTLS_NRF54_DESC_REALIGN,
                          NOXTLS_NRF54_HASH_TAG_CFG);
    noxtls_nrf54_desc_set(&st->fetch[1], st->state, ssz | NOXTLS_NRF54_DESC_REALIGN, NOXTLS_NRF54_HASH_TAG_STATE);
    noxtls_nrf54_desc_set(&st->fetch[2], src, len, NOXTLS_NRF54_HASH_TAG_DATA);
    noxtls_nrf54_desc_link(st->fetch, 3U, 1U);
    noxtls_nrf54_desc_set(&st->push[0], st->state, ssz, 0U);
    noxtls_nrf54_desc_link(st->push, 1U, 0U);
    return noxtls_nrf54_cracen_cm_run(st->fetch, st->push, len);
}

noxtls_return_t noxtls_nrf54_hash_blocks(noxtls_nrf54_sha_t alg, uint8_t *state, const uint8_t *data, uint32_t blocks)
{
    noxtls_nrf54_hash_t *st = &s_noxtls_nrf54_hash;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t bsz = (alg == NOXTLS_NRF54_SHA512) ? NOXTLS_NRF54_HASH_BLOCK_512 : NOXTLS_NRF54_HASH_BLOCK_256;
    uint32_t ssz = (alg == NOXTLS_NRF54_SHA512) ? NOXTLS_NRF54_HASH_STATE_512 : NOXTLS_NRF54_HASH_STATE_256;
    uint32_t algo = (alg == NOXTLS_NRF54_SHA512) ? NOXTLS_NRF54_HASH_ALGO_SHA512 : NOXTLS_NRF54_HASH_ALGO_SHA256;

    if ((state == NULL) || ((data == NULL) && (blocks != 0U))) {
        rc = NOXTLS_RETURN_NULL;
    } else if ((alg != NOXTLS_NRF54_SHA256) && (alg != NOXTLS_NRF54_SHA512)) {
        rc = NOXTLS_RETURN_INVALID_PARAM;
    } else if (blocks == 0U) {
        /* Nothing to process. */
    } else {
        rc = noxtls_nrf54_cracen_acquire(NOXTLS_NRF54_MOD_CM);
        if ((rc == NOXTLS_RETURN_SUCCESS) && ((noxtls_nrf54_cracen_caps()->hash_algos & algo) == 0U)) {
            noxtls_nrf54_cracen_release();
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
        }
        if (rc == NOXTLS_RETURN_SUCCESS) {
            uint64_t remaining = (uint64_t)blocks * (uint64_t)bsz;
            const uint8_t *src = data;

            st->cfg = algo;
            (void)memcpy(st->state, state, ssz);
            while ((remaining != 0U) && (rc == NOXTLS_RETURN_SUCCESS)) {
                uint32_t n = (remaining > (uint64_t)NOXTLS_NRF54_CONFIG_MAX_CHUNK) ?
                             (uint32_t)NOXTLS_NRF54_CONFIG_MAX_CHUNK : (uint32_t)remaining;

                if (noxtls_nrf54_dma_in_ok(src, n) != 0U) {
                    rc = noxtls_nrf54_hash_job(st, src, n, ssz);
                } else {
                    if (n > (uint32_t)NOXTLS_NRF54_CONFIG_BOUNCE_SIZE) {
                        n = (uint32_t)NOXTLS_NRF54_CONFIG_BOUNCE_SIZE;
                    }
                    (void)memcpy(st->bounce, src, n);
                    rc = noxtls_nrf54_hash_job(st, st->bounce, n, ssz);
                }
                src = &src[n];
                remaining -= (uint64_t)n;
            }
            if (rc == NOXTLS_RETURN_SUCCESS) {
                (void)memcpy(state, st->state, ssz);
            }
            noxtls_nrf54_wipe(st->state, (uint32_t)sizeof(st->state));
            noxtls_nrf54_wipe(st->bounce, (uint32_t)sizeof(st->bounce));
            noxtls_nrf54_cracen_release();
        }
    }
    return rc;
}
