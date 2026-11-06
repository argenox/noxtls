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
* File:    noxtls_speed_timer.h
* Summary: Cycle timer of the EFR32xG26 NoxTLS speed benchmark
*
*****************************************************************************/

/**
 * @file noxtls_speed_timer.h
 * @brief Free-running core cycle counter: DWT CYCCNT, or SysTick when the DWT has none.
 * @ingroup noxtls_speed
 *
 * The register maps are Argenox definitions (Armv8-M architecture: DWT, DEMCR, SysTick).
 */
#ifndef NOXTLS_SPEED_TIMER_H
#define NOXTLS_SPEED_TIMER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Armv8-M DEMCR address (debug exception and monitor control). */
#define NOXTLS_SPEED_DEMCR_ADDR         0xE000EDFCUL
/** @brief DEMCR.TRCENA: enables the DWT. */
#define NOXTLS_SPEED_DEMCR_TRCENA       (1UL << 24)
/** @brief DWT_CTRL address. */
#define NOXTLS_SPEED_DWT_CTRL_ADDR      0xE0001000UL
/** @brief DWT_CTRL.CYCCNTENA. */
#define NOXTLS_SPEED_DWT_CTRL_CYCCNTENA (1UL << 0)
/** @brief DWT_CTRL.NOCYCCNT: the implementation has no cycle counter. */
#define NOXTLS_SPEED_DWT_CTRL_NOCYCCNT  (1UL << 25)
/** @brief DWT_CYCCNT address. */
#define NOXTLS_SPEED_DWT_CYCCNT_ADDR    0xE0001004UL
/** @brief SysTick CTRL address. */
#define NOXTLS_SPEED_SYST_CTRL_ADDR     0xE000E010UL
/** @brief SysTick LOAD address. */
#define NOXTLS_SPEED_SYST_LOAD_ADDR     0xE000E014UL
/** @brief SysTick VAL address. */
#define NOXTLS_SPEED_SYST_VAL_ADDR      0xE000E018UL
/** @brief SysTick CTRL.ENABLE. */
#define NOXTLS_SPEED_SYST_CTRL_ENABLE   (1UL << 0)
/** @brief SysTick CTRL.TICKINT. */
#define NOXTLS_SPEED_SYST_CTRL_TICKINT  (1UL << 1)
/** @brief SysTick CTRL.CLKSOURCE (core clock). */
#define NOXTLS_SPEED_SYST_CTRL_CLKSRC   (1UL << 2)
/** @brief SysTick reload value (24-bit counter). */
#define NOXTLS_SPEED_SYST_RELOAD        0x00FFFFFFUL
/** @brief Bits of the SysTick counter. */
#define NOXTLS_SPEED_SYST_BITS          24U
/** @brief Cycles the counter must advance across the start-up probe for the DWT to count as running. */
#define NOXTLS_SPEED_DWT_PROBE_MIN      8UL
/** @brief NOP instructions executed between the two probe reads. */
#define NOXTLS_SPEED_DWT_PROBE_NOPS     16U

/** Clock behind noxtls_speed_timer_cycles(). */
typedef enum {
    NOXTLS_SPEED_TIMER_NONE = 0,    /**< Not started. */
    NOXTLS_SPEED_TIMER_DWT = 1,     /**< DWT cycle counter. */
    NOXTLS_SPEED_TIMER_SYSTICK = 2  /**< SysTick extended to 32 bits by its interrupt. */
} noxtls_speed_timer_kind_t;

/**
 * @brief Start the cycle counter, preferring the DWT and falling back to SysTick.
 *
 * @return The clock in use.
 */
noxtls_speed_timer_kind_t noxtls_speed_timer_init(void);

/**
 * @brief Core cycles since an arbitrary start, modulo 2^32.
 *
 * Subtract two readings as uint32_t for an interval below 2^32 cycles (55 s at 78 MHz).
 *
 * @return Cycle count (low 32 bits).
 */
uint32_t noxtls_speed_timer_cycles(void);

/**
 * @brief Busy wait.
 *
 * @param[in] cycles Core cycles.
 */
void noxtls_speed_timer_wait(uint32_t cycles);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_SPEED_TIMER_H */
