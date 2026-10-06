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
* File:    noxtls_nrf54_rng.h
* Summary: CRACEN TRNG entropy source
*
*****************************************************************************/

/**
 * @file noxtls_nrf54_rng.h
 * @brief Entropy from the CRACEN true random number generator (BA431).
 * @ingroup noxtls_nrf54
 *
 * Each request starts the TRNG from reset: warm-up and start-up health tests,
 * a conditioning key taken from the first four FIFO words, a FIFO flush (the
 * words produced so far used the default key), then FIFO words are copied
 * little-endian into the buffer. A repetition-count, adaptive-proportion or
 * start-up test failure discards everything delivered by the request and
 * restarts the TRNG, up to NOXTLS_NRF54_CONFIG_RNG_RESTARTS times (NIST
 * SP 800-90B §4.3: health-test failures must be handled before output is
 * used). The output feeds the NoxTLS CTR-DRBG (NIST SP 800-90A) as entropy
 * input.
 */

#ifndef NOXTLS_NRF54_RNG_H
#define NOXTLS_NRF54_RNG_H

#include <stdint.h>

#include "noxtls_nrf54_cracen.h"

#ifdef __cplusplus
extern "C" {
#endif

/** TRNG health counters (since start-up or noxtls_nrf54_rng_reset_health()). */
typedef struct {
    uint32_t startup_failures;    /**< Start-up test failures. */
    uint32_t repetition_failures; /**< Repetition count test failures. */
    uint32_t proportion_failures; /**< Adaptive proportion test failures. */
    uint32_t restarts;            /**< TRNG restarts after a failure. */
    uint32_t last_status;         /**< STATUS register at the last failure. */
    uint32_t requests;            /**< Requests served. */
} noxtls_nrf54_rng_health_t;

/**
 * @brief Fill a buffer with TRNG output.
 *
 * @param[out] buf Destination.
 * @param[in]  len Bytes (0 returns success).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_NOT_SUPPORTED
 *         (no TRNG, CRACEN disabled or in use), NOXTLS_RETURN_FAILED (health
 *         tests kept failing; the buffer is wiped) or NOXTLS_RETURN_TIMEOUT.
 */
noxtls_return_t noxtls_nrf54_rng_fill(uint8_t *buf, uint32_t len);

/**
 * @brief Health counters.
 *
 * @return Counters (never NULL).
 */
const noxtls_nrf54_rng_health_t *noxtls_nrf54_rng_health(void);

/**
 * @brief Clear the health counters.
 */
void noxtls_nrf54_rng_reset_health(void);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_NRF54_RNG_H */
