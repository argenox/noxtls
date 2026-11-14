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
* File:    noxtls_speed_timer.c
* Summary: Cycle timer of the EFR32xG26 NoxTLS speed benchmark
*
*****************************************************************************/

/**
 * @file noxtls_speed_timer.c
 * @brief DWT cycle counter with a SysTick fallback.
 * @ingroup noxtls_speed
 */

#include "noxtls_speed_timer.h"

/** @brief Memory-mapped 32-bit register access. */
#define SPEED_REG(addr) (*(volatile uint32_t *)(addr))

/** @brief Clock in use. */
static noxtls_speed_timer_kind_t s_kind = NOXTLS_SPEED_TIMER_NONE;
/** @brief SysTick wraps seen by the interrupt. */
static volatile uint32_t s_wraps;

/**
 * @brief SysTick interrupt: counts one wrap of the 24-bit counter.
 *
 * Overrides the weak alias of the start-up code.
 */
void SysTick_Handler(void)
{
    s_wraps++;
}

/**
 * @brief Try to run the DWT cycle counter.
 * @internal
 *
 * @return 1 when CYCCNT is present and counting, 0 otherwise.
 */
static uint8_t speed_dwt_start(void)
{
    uint8_t running = 0U;

    SPEED_REG(NOXTLS_SPEED_DEMCR_ADDR) |= NOXTLS_SPEED_DEMCR_TRCENA;
    if ((SPEED_REG(NOXTLS_SPEED_DWT_CTRL_ADDR) & NOXTLS_SPEED_DWT_CTRL_NOCYCCNT) == 0UL) {
        uint32_t i;
        uint32_t second;
        uint32_t first;

        SPEED_REG(NOXTLS_SPEED_DWT_CYCCNT_ADDR) = 0UL;
        SPEED_REG(NOXTLS_SPEED_DWT_CTRL_ADDR) |= NOXTLS_SPEED_DWT_CTRL_CYCCNTENA;
        first = SPEED_REG(NOXTLS_SPEED_DWT_CYCCNT_ADDR);
        for (i = 0U; i < NOXTLS_SPEED_DWT_PROBE_NOPS; i++) {
            __asm volatile("nop");
        }
        second = SPEED_REG(NOXTLS_SPEED_DWT_CYCCNT_ADDR);
        if ((second - first) >= NOXTLS_SPEED_DWT_PROBE_MIN) {
            running = 1U;
        }
    }
    return running;
}

/**
 * @brief Start SysTick as a free-running counter with a wrap interrupt.
 * @internal
 */
static void speed_systick_start(void)
{
    s_wraps = 0UL;
    SPEED_REG(NOXTLS_SPEED_SYST_CTRL_ADDR) = 0UL;
    SPEED_REG(NOXTLS_SPEED_SYST_LOAD_ADDR) = NOXTLS_SPEED_SYST_RELOAD;
    SPEED_REG(NOXTLS_SPEED_SYST_VAL_ADDR) = 0UL;
    SPEED_REG(NOXTLS_SPEED_SYST_CTRL_ADDR) =
        NOXTLS_SPEED_SYST_CTRL_ENABLE | NOXTLS_SPEED_SYST_CTRL_TICKINT | NOXTLS_SPEED_SYST_CTRL_CLKSRC;
}

noxtls_speed_timer_kind_t noxtls_speed_timer_init(void)
{
    if (speed_dwt_start() != 0U) {
        s_kind = NOXTLS_SPEED_TIMER_DWT;
    } else {
        speed_systick_start();
        s_kind = NOXTLS_SPEED_TIMER_SYSTICK;
    }
    return s_kind;
}

uint32_t noxtls_speed_timer_cycles(void)
{
    uint32_t cycles = 0UL;

    if (s_kind == NOXTLS_SPEED_TIMER_DWT) {
        cycles = SPEED_REG(NOXTLS_SPEED_DWT_CYCCNT_ADDR);
    } else if (s_kind == NOXTLS_SPEED_TIMER_SYSTICK) {
        uint32_t wraps_before;
        uint32_t wraps_after;
        uint32_t value;

        do {
            wraps_before = s_wraps;
            value = SPEED_REG(NOXTLS_SPEED_SYST_VAL_ADDR);
            wraps_after = s_wraps;
        } while (wraps_before != wraps_after);
        cycles = (wraps_before << NOXTLS_SPEED_SYST_BITS) + (NOXTLS_SPEED_SYST_RELOAD - value);
    } else {
        /* Not started. */
    }
    return cycles;
}

void noxtls_speed_timer_wait(uint32_t cycles)
{
    const uint32_t start = noxtls_speed_timer_cycles();

    while ((uint32_t)(noxtls_speed_timer_cycles() - start) < cycles) {
    }
}
