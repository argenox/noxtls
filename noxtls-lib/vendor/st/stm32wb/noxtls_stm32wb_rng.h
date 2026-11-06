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
* File:    noxtls_stm32wb_rng.h
* Summary: STM32WB5x true random number generator entropy source
*
*****************************************************************************/

/**
 * @file noxtls_stm32wb_rng.h
 * @brief RNG driver with semaphore ownership and health checks (STM32WB5x).
 * @ingroup noxtls_stm32wb
 *
 * Specification: RM0434 Rev 13, RNG chapter (data register DR, status flags
 * DRDY / SECS / CECS / SEIS / CEIS, seed error and clock error recovery) and
 * the HSEM chapter / AN5289 (the RNG is shared with CPU2; semaphore number
 * NOXTLS_STM32WB_CONFIG_HSEM_ID_RNG).
 *
 * Health policy:
 *  - a seed error (SEIS / SECS) is cleared, NOXTLS_STM32WB_CONFIG_RNG_RECOVERY_WORDS
 *    words are read and discarded, and SECS must then read back clear (RM0434
 *    RNG chapter, seed error recovery); more than
 *    NOXTLS_STM32WB_CONFIG_RNG_MAX_RECOVERIES recoveries fail the request;
 *  - a clock error (CEIS / CECS) discards the pending word; a clock error
 *    that persists after clearing fails the request at once;
 *  - a continuous test rejects a word equal to its predecessor and fails the
 *    request after NOXTLS_STM32WB_CONFIG_RNG_MAX_REPEATS consecutive repeats.
 * RNG_CR is forced to RNGEN with clock-error detection on and the interrupt off for the
 * request and restored to its previous value afterwards.
 */

#ifndef NOXTLS_STM32WB_RNG_H
#define NOXTLS_STM32WB_RNG_H

#include <stdint.h>

#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** RNG health counters. */
typedef struct {
    uint32_t requests;       /**< Fill requests started. */
    uint32_t words;          /**< Words delivered. */
    uint32_t seed_errors;    /**< Seed errors seen. */
    uint32_t clock_errors;   /**< Clock errors seen. */
    uint32_t repeat_faults;  /**< Words rejected by the continuous test. */
    uint32_t failures;       /**< Requests failed on health grounds or timeout. */
    uint32_t busy;           /**< Requests refused because the RNG semaphore was busy. */
} noxtls_stm32wb_rng_health_t;

/**
 * @brief Fill a buffer with true random bytes.
 *
 * @param[out] buf Destination.
 * @param[in]  len Bytes (0 returns success without touching the hardware).
 *
 * @return NOXTLS_RETURN_SUCCESS; NOXTLS_RETURN_NULL for a NULL buffer;
 *         NOXTLS_RETURN_NOT_SUPPORTED when the RNG is in use by CPU2;
 *         NOXTLS_RETURN_FAILED on a health failure or timeout (the buffer is wiped).
 */
noxtls_return_t noxtls_stm32wb_rng_fill(uint8_t *buf, uint32_t len);

/**
 * @brief Health counters.
 *
 * @return Pointer to the (static) counters.
 */
const noxtls_stm32wb_rng_health_t *noxtls_stm32wb_rng_health(void);

/** @brief Forget the continuous-test history (used after a deliberate re-seed or by tests). */
void noxtls_stm32wb_rng_reset_history(void);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_STM32WB_RNG_H */
