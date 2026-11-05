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
* File:    noxtls_stm32wb_hsem.h
* Summary: HSEM-based ownership of the shared crypto peripherals
*
*****************************************************************************/

/**
 * @file noxtls_stm32wb_hsem.h
 * @brief CPU1 ownership of AES1, PKA and RNG through the hardware semaphores.
 * @ingroup noxtls_stm32wb
 *
 * The PKA and the RNG (and the CLK48 clock that feeds the RNG) are also used
 * by the CPU2 wireless stack. CPU1 must hold the matching hardware semaphore
 * (HSEM, RM0434 HSEM chapter, "one-step lock procedure") for the whole time it
 * uses the peripheral, and release it afterwards; AN5289 lists the semaphore
 * numbers CPU2 firmware expects (RNG = 0, PKA = 1). The numbers are build
 * settings in noxtls_stm32wb_config.h.
 *
 * Lock protocol (RM0434 HSEM chapter): reading HSEM_RLRx returns the COREID
 * of the caller with the LOCK bit set when the one-step lock succeeded;
 * writing the COREID (and PROCID 0) to HSEM_Rx releases it.
 *
 * Each resource also carries a software flag that rejects a nested use from
 * the same CPU, so a re-entrant call reports busy instead of corrupting a
 * running operation.
 */

#ifndef NOXTLS_STM32WB_HSEM_H
#define NOXTLS_STM32WB_HSEM_H

#include <stdint.h>

#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Identifier of a shared crypto resource. */
typedef uint32_t noxtls_stm32wb_res_t;

/** @brief AES1 resource. */
#define NOXTLS_STM32WB_RES_AES1     ((noxtls_stm32wb_res_t)0U)
/** @brief PKA resource. */
#define NOXTLS_STM32WB_RES_PKA      ((noxtls_stm32wb_res_t)1U)
/** @brief RNG resource. */
#define NOXTLS_STM32WB_RES_RNG      ((noxtls_stm32wb_res_t)2U)
/** @brief Number of resources. */
#define NOXTLS_STM32WB_RES_COUNT    3U

/** Contention counters of the lock layer. */
typedef struct {
    uint32_t acquired;      /**< Successful locks. */
    uint32_t sw_busy;       /**< Locks refused because this CPU already held the resource. */
    uint32_t hsem_busy;     /**< Locks refused because CPU2 held the semaphore. */
} noxtls_stm32wb_lock_stats_t;

/**
 * @brief Take a resource: software flag first, then the hardware semaphore.
 *
 * @param[in] res Resource identifier.
 *
 * @return NOXTLS_RETURN_SUCCESS when held; NOXTLS_RETURN_TIMEOUT when the
 *         resource is in use (nested call or CPU2 owns the semaphore);
 *         NOXTLS_RETURN_INVALID_PARAM for an unknown resource.
 */
noxtls_return_t noxtls_stm32wb_lock(noxtls_stm32wb_res_t res);

/**
 * @brief Release a resource taken with noxtls_stm32wb_lock().
 *
 * @param[in] res Resource identifier (an unknown or not-held resource is ignored).
 */
void noxtls_stm32wb_unlock(noxtls_stm32wb_res_t res);

/**
 * @brief Counters of the lock layer.
 *
 * @return Pointer to the (static) counters.
 */
const noxtls_stm32wb_lock_stats_t *noxtls_stm32wb_lock_stats(void);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_STM32WB_HSEM_H */
