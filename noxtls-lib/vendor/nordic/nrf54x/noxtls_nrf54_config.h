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
* File:    noxtls_nrf54_config.h
* Summary: Build-time settings of the NoxTLS nRF54L CRACEN backend
*
*****************************************************************************/

/**
 * @file noxtls_nrf54_config.h
 * @brief Build-time settings of the nRF54L CRACEN hardware backend.
 * @ingroup noxtls_nrf54
 *
 * Every setting may be overridden by defining it before this header is
 * included (for example with a compiler -D option). The chip is selected with
 * NOXTLS_NRF54_CONFIG_CHIP_L15 (defaults from NOXADK_NRF54_CHIPSET_NRF54L15 or
 * NRF54L15_XXAA); otherwise the nRF54LM20 values are used. The chip can also be
 * changed at run time with noxtls_nrf54_cracen_set_hw() (used by the host tests).
 */

#ifndef NOXTLS_NRF54_CONFIG_H
#define NOXTLS_NRF54_CONFIG_H

#include "noxtls_nrf54_regs.h"

/** @brief Non-zero for the nRF54L15 (CRACEN with loadable PKE microcode), zero for the nRF54LM20 (CRACEN Lite). */
#ifndef NOXTLS_NRF54_CONFIG_CHIP_L15
#if defined(NOXADK_NRF54_CHIPSET_NRF54L15) || defined(NRF54L15_XXAA)
#define NOXTLS_NRF54_CONFIG_CHIP_L15        1
#else
#define NOXTLS_NRF54_CONFIG_CHIP_L15        0
#endif
#endif

/**
 * @brief Non-zero: the backend defines CRACEN_IRQHandler (overriding the weak
 *        startup vector). Zero when another component owns the vector; it must
 *        then call noxtls_nrf54_cracen_irq_handler(). Host builds use 0.
 */
#ifndef NOXTLS_NRF54_CONFIG_DEFINE_VECTOR
#if defined(__ARM_ARCH)
#define NOXTLS_NRF54_CONFIG_DEFINE_VECTOR   1
#else
#define NOXTLS_NRF54_CONFIG_DEFINE_VECTOR   0
#endif
#endif

/**
 * @brief NVIC priority of CRACEN_IRQn (0 most urgent .. 7). 5 is less urgent
 *        than the NoxOS system-call threshold (4), so the port signal hook may
 *        call NoxOS *_from_isr services.
 */
#ifndef NOXTLS_NRF54_CONFIG_IRQ_PRIORITY
#define NOXTLS_NRF54_CONFIG_IRQ_PRIORITY    5U
#endif

/**
 * @brief Start of the window the CryptoMaster DMA may access directly. The
 *        default covers RRAM and data RAM; buffers outside it are copied
 *        through backend RAM.
 */
#ifndef NOXTLS_NRF54_CONFIG_DMA_START
#define NOXTLS_NRF54_CONFIG_DMA_START       NOXTLS_NRF54_RRAM_BASE
#endif

/** @brief Non-zero: data in RRAM is read by the DMA (input only; outputs are always in RAM). */
#ifndef NOXTLS_NRF54_CONFIG_DMA_RRAM
#define NOXTLS_NRF54_CONFIG_DMA_RRAM        1
#endif

/** @brief Bytes of the input / output bounce buffers (multiple of 128, >= 128). */
#ifndef NOXTLS_NRF54_CONFIG_BOUNCE_SIZE
#define NOXTLS_NRF54_CONFIG_BOUNCE_SIZE     512U
#endif

/** @brief Largest message part of one CryptoMaster job (multiple of 128, <= 16 MiB - 128). */
#ifndef NOXTLS_NRF54_CONFIG_MAX_CHUNK
#define NOXTLS_NRF54_CONFIG_MAX_CHUNK       0x00FFFF80U
#endif

/** @brief Fixed part of the CryptoMaster job timeout in microseconds. */
#ifndef NOXTLS_NRF54_CONFIG_CM_TIMEOUT_US
#define NOXTLS_NRF54_CONFIG_CM_TIMEOUT_US   10000U
#endif

/** @brief Additional CryptoMaster timeout per started KiB, in microseconds (>= 1 MB/s). */
#ifndef NOXTLS_NRF54_CONFIG_CM_US_PER_KIB
#define NOXTLS_NRF54_CONFIG_CM_US_PER_KIB   1000U
#endif

/** @brief Timeout of one BA414EP command in microseconds (a P-256 verify takes about 14 ms). */
#ifndef NOXTLS_NRF54_CONFIG_PKE_TIMEOUT_US
#define NOXTLS_NRF54_CONFIG_PKE_TIMEOUT_US  2000000U
#endif

/** @brief Timeout of one TRNG request: start-up plus conditioning-key set-up, in microseconds. */
#ifndef NOXTLS_NRF54_CONFIG_RNG_TIMEOUT_US
#define NOXTLS_NRF54_CONFIG_RNG_TIMEOUT_US  20000U
#endif

/** @brief Additional TRNG timeout per started 64-byte FIFO fill, in microseconds. */
#ifndef NOXTLS_NRF54_CONFIG_RNG_US_PER_FILL
#define NOXTLS_NRF54_CONFIG_RNG_US_PER_FILL 2000U
#endif

/** @brief TRNG restarts allowed per request after a health-test failure. */
#ifndef NOXTLS_NRF54_CONFIG_RNG_RESTARTS
#define NOXTLS_NRF54_CONFIG_RNG_RESTARTS    3U
#endif

/**
 * @brief Longest single sleep of the port wait hook in milliseconds. After
 *        each sleep the backend checks the hardware, so an operation still
 *        completes if its interrupt is lost.
 */
#ifndef NOXTLS_NRF54_CONFIG_WAIT_SLICE_MS
#define NOXTLS_NRF54_CONFIG_WAIT_SLICE_MS   10U
#endif

/** @brief Wake-ups without progress tolerated by one wait (guards a stream of stale signals). */
#ifndef NOXTLS_NRF54_CONFIG_WAIT_WAKES_MAX
#define NOXTLS_NRF54_CONFIG_WAIT_WAKES_MAX  10000U
#endif

/**
 * @brief Poll iterations per microsecond of the bare-metal wait (128 = one per
 *        cycle at 128 MHz; a loop iteration is slower, so the real timeout is
 *        longer, never shorter).
 */
#ifndef NOXTLS_NRF54_CONFIG_SPINS_PER_US
#define NOXTLS_NRF54_CONFIG_SPINS_PER_US    128U
#endif

/** @brief Polls for the PKE / IKG to report idle after power-up and for the clear-memory command. */
#ifndef NOXTLS_NRF54_CONFIG_PKE_READY_SPINS
#define NOXTLS_NRF54_CONFIG_PKE_READY_SPINS 200000U
#endif

/** @brief Register reads forming the >= 1 us CryptoMaster soft-reset pulse. */
#ifndef NOXTLS_NRF54_CONFIG_SOFTRST_SPINS
#define NOXTLS_NRF54_CONFIG_SOFTRST_SPINS   256U
#endif

/** @brief Polls for the soft reset to finish and for the engine to report idle after the push DMA stopped. */
#ifndef NOXTLS_NRF54_CONFIG_IDLE_SPINS
#define NOXTLS_NRF54_CONFIG_IDLE_SPINS      10000U
#endif

/** @brief Polls for the KMU to report ready and for a KMU task result (the KMU has no interrupt). */
#ifndef NOXTLS_NRF54_CONFIG_KMU_SPINS
#define NOXTLS_NRF54_CONFIG_KMU_SPINS       640000U
#endif

/**
 * @brief Non-zero: run every P-256 point multiplication twice with independent
 *        blinding and accept the result only when both agree (fault detection
 *        for key generation and ECDH).
 */
#ifndef NOXTLS_NRF54_CONFIG_PTMUL_DOUBLE_CHECK
#define NOXTLS_NRF54_CONFIG_PTMUL_DOUBLE_CHECK 1
#endif

#if ((NOXTLS_NRF54_CONFIG_BOUNCE_SIZE < 128U) || ((NOXTLS_NRF54_CONFIG_BOUNCE_SIZE % 128U) != 0U))
#error "NOXTLS_NRF54_CONFIG_BOUNCE_SIZE must be a non-zero multiple of 128"
#endif
#if ((NOXTLS_NRF54_CONFIG_MAX_CHUNK < 128U) || ((NOXTLS_NRF54_CONFIG_MAX_CHUNK % 128U) != 0U) || \
     (NOXTLS_NRF54_CONFIG_MAX_CHUNK > NOXTLS_NRF54_DESC_LEN_MAX))
#error "NOXTLS_NRF54_CONFIG_MAX_CHUNK must be a multiple of 128 in 128..16 MiB"
#endif
#if (NOXTLS_NRF54_CONFIG_IRQ_PRIORITY > NOXTLS_NRF54_NVIC_PRIO_MAX)
#error "NOXTLS_NRF54_CONFIG_IRQ_PRIORITY exceeds the implemented NVIC priority range"
#endif
#if ((NOXTLS_NRF54_CONFIG_WAIT_SLICE_MS == 0U) || (NOXTLS_NRF54_CONFIG_SPINS_PER_US == 0U))
#error "NOXTLS_NRF54_CONFIG_WAIT_SLICE_MS and NOXTLS_NRF54_CONFIG_SPINS_PER_US must be at least 1"
#endif

#endif /* NOXTLS_NRF54_CONFIG_H */
