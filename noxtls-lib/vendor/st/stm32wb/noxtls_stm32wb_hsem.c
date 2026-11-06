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
* File:    noxtls_stm32wb_hsem.c
* Summary: HSEM-based ownership of the shared crypto peripherals
*
*****************************************************************************/

/**
 * @file noxtls_stm32wb_hsem.c
 * @brief CPU1 ownership of AES1, PKA and RNG through the hardware semaphores.
 * @ingroup noxtls_stm32wb
 */

#include <stddef.h>

#include "noxtls_stm32wb_hsem.h"

#include "noxtls_stm32wb_bus.h"
#include "noxtls_stm32wb_config.h"
#include "noxtls_stm32wb_regs.h"

/** @brief Process identifier used with the one-step lock (the lock read always uses PROCID 0). */
#define NOXTLS_STM32WB_HSEM_PROC_ID     UINT32_C(0)

#if (NOXTLS_STM32WB_CONFIG_HSEM_ID_RNG != NOXTLS_STM32WB_HSEM_ID_NONE) && \
    (NOXTLS_STM32WB_CONFIG_HSEM_ID_RNG > NOXTLS_STM32WB_HSEM_ID_MAX)
#error "NOXTLS_STM32WB_CONFIG_HSEM_ID_RNG must be 0..31 or NOXTLS_STM32WB_HSEM_ID_NONE"
#endif
#if (NOXTLS_STM32WB_CONFIG_HSEM_ID_PKA != NOXTLS_STM32WB_HSEM_ID_NONE) && \
    (NOXTLS_STM32WB_CONFIG_HSEM_ID_PKA > NOXTLS_STM32WB_HSEM_ID_MAX)
#error "NOXTLS_STM32WB_CONFIG_HSEM_ID_PKA must be 0..31 or NOXTLS_STM32WB_HSEM_ID_NONE"
#endif
#if (NOXTLS_STM32WB_CONFIG_HSEM_ID_AES1 != NOXTLS_STM32WB_HSEM_ID_NONE) && \
    (NOXTLS_STM32WB_CONFIG_HSEM_ID_AES1 > NOXTLS_STM32WB_HSEM_ID_MAX)
#error "NOXTLS_STM32WB_CONFIG_HSEM_ID_AES1 must be 0..31 or NOXTLS_STM32WB_HSEM_ID_NONE"
#endif

/** Semaphore number of each resource. */
static const uint32_t s_noxtls_stm32wb_sem_id[NOXTLS_STM32WB_RES_COUNT] = {
    NOXTLS_STM32WB_CONFIG_HSEM_ID_AES1,
    NOXTLS_STM32WB_CONFIG_HSEM_ID_PKA,
    NOXTLS_STM32WB_CONFIG_HSEM_ID_RNG
};

/** Software ownership flags. */
static uint8_t s_noxtls_stm32wb_held[NOXTLS_STM32WB_RES_COUNT];

/** Lock counters. */
static noxtls_stm32wb_lock_stats_t s_noxtls_stm32wb_lock_stats;

/**
 * @brief Value read from RLR[n] when this CPU obtained the semaphore.
 * @internal
 *
 * @return COREID with the LOCK bit.
 */
static uint32_t noxtls_stm32wb_hsem_owned_value(void)
{
    return (NOXTLS_STM32WB_CONFIG_HSEM_CORE_ID << NOXTLS_STM32WB_HSEM_COREID_SHIFT) | NOXTLS_STM32WB_HSEM_LOCK;
}

/**
 * @brief Try the one-step lock of a semaphore a bounded number of times.
 * @internal
 *
 * @param[in] sem Semaphore number (0..31).
 *
 * @return Non-zero when the semaphore is now held by CPU1.
 */
static uint32_t noxtls_stm32wb_hsem_try_take(uint32_t sem)
{
    uint32_t spin;
    uint32_t addr = NOXTLS_STM32WB_CONFIG_HSEM_BASE + NOXTLS_STM32WB_HSEM_RLR + (sem * NOXTLS_STM32WB_HSEM_REG_STRIDE);
    uint32_t taken = 0U;

    for (spin = 0U; (spin < NOXTLS_STM32WB_CONFIG_HSEM_TAKE_SPINS) && (taken == 0U); spin++) {
        if (noxtls_stm32wb_bus_rd(addr) == noxtls_stm32wb_hsem_owned_value()) {
            taken = 1U;
        }
    }
    return taken;
}

noxtls_return_t noxtls_stm32wb_lock(noxtls_stm32wb_res_t res)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t sem;

    if (res >= NOXTLS_STM32WB_RES_COUNT) {
        rc = NOXTLS_RETURN_INVALID_PARAM;
    } else if (s_noxtls_stm32wb_held[res] != 0U) {
        s_noxtls_stm32wb_lock_stats.sw_busy++;
        rc = NOXTLS_RETURN_TIMEOUT;
    } else {
        sem = s_noxtls_stm32wb_sem_id[res];
        if (sem == NOXTLS_STM32WB_HSEM_ID_NONE) {
            /* Resource not shared with CPU2: no hardware semaphore. */
        } else if (noxtls_stm32wb_hsem_try_take(sem) == 0U) {
            s_noxtls_stm32wb_lock_stats.hsem_busy++;
            rc = NOXTLS_RETURN_TIMEOUT;
        } else {
            /* Semaphore held. */
        }
        if (rc == NOXTLS_RETURN_SUCCESS) {
            s_noxtls_stm32wb_held[res] = 1U;
            s_noxtls_stm32wb_lock_stats.acquired++;
        }
    }
    return rc;
}

void noxtls_stm32wb_unlock(noxtls_stm32wb_res_t res)
{
    uint32_t sem;
    uint32_t value;

    if ((res < NOXTLS_STM32WB_RES_COUNT) && (s_noxtls_stm32wb_held[res] != 0U)) {
        sem = s_noxtls_stm32wb_sem_id[res];
        if (sem != NOXTLS_STM32WB_HSEM_ID_NONE) {
            value = (NOXTLS_STM32WB_CONFIG_HSEM_CORE_ID << NOXTLS_STM32WB_HSEM_COREID_SHIFT) |
                    NOXTLS_STM32WB_HSEM_PROC_ID;
            noxtls_stm32wb_bus_wr(NOXTLS_STM32WB_CONFIG_HSEM_BASE + NOXTLS_STM32WB_HSEM_R +
                                  (sem * NOXTLS_STM32WB_HSEM_REG_STRIDE), value);
        }
        s_noxtls_stm32wb_held[res] = 0U;
    }
}

const noxtls_stm32wb_lock_stats_t *noxtls_stm32wb_lock_stats(void)
{
    return &s_noxtls_stm32wb_lock_stats;
}
