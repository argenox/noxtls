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
* File:    noxtls_stm32wb_config.h
* Summary: Build-time settings of the STM32WB5x hardware crypto backend
*
*****************************************************************************/

/**
 * @file noxtls_stm32wb_config.h
 * @brief Build-time settings of the STM32WB5x AES1 / PKA / RNG backend.
 * @ingroup noxtls_stm32wb
 *
 * Every setting may be overridden by defining it before this header is
 * included (for example with a compiler -D option).
 *
 * Specification sources (revisions used for this port):
 *  - RM0434 Rev 13 (STM32WB55 reference manual; revision as used for this port, confirm against the PDF): the AES1 (AES hardware
 *    accelerator), PKA (public key accelerator), RNG (true random number
 *    generator) and HSEM (hardware semaphore) chapters, and the memory map
 *    (peripheral boundary addresses).
 *  - AN5289 (building wireless applications with STM32WB; revision to confirm): the
 *    hardware-semaphore usage table shared between CPU1 and CPU2.
 *  - STM32CubeWB 1.x hw_conf.h (CFG_HW_RNG_SEMID = 0, CFG_HW_PKA_SEMID = 1,
 *    CFG_HW_CLK48_CONFIG_SEMID = 5), the semaphore numbering used by the
 *    ST CPU2 wireless firmware.
 *
 * The RM0434 / AN5289 chapter numbers cited in the sources name the chapter
 * by title; confirm the numeric section against the PDF revision in use.
 */

#ifndef NOXTLS_STM32WB_CONFIG_H
#define NOXTLS_STM32WB_CONFIG_H

#include <stdint.h>

/**
 * @defgroup noxtls_stm32wb STM32WB5x hardware crypto backend
 * @brief AES1, PKA and RNG drivers and NoxTLS accelerator ports for the STM32WB5x CPU1 (Cortex-M4F).
 */

/** @name Peripheral base addresses (RM0434 memory map; AHB2 / AHB4 peripherals) */
/** @{ */

/** @brief AES1 base address (CPU1 AES, AHB2). */
#ifndef NOXTLS_STM32WB_CONFIG_AES1_BASE
#define NOXTLS_STM32WB_CONFIG_AES1_BASE         UINT32_C(0x50060000)
#endif
/** @brief RNG base address (AHB4). */
#ifndef NOXTLS_STM32WB_CONFIG_RNG_BASE
#define NOXTLS_STM32WB_CONFIG_RNG_BASE          UINT32_C(0x58001000)
#endif
/** @brief HSEM base address (AHB4). */
#ifndef NOXTLS_STM32WB_CONFIG_HSEM_BASE
#define NOXTLS_STM32WB_CONFIG_HSEM_BASE         UINT32_C(0x58001400)
#endif
/** @brief PKA base address (AHB4). */
#ifndef NOXTLS_STM32WB_CONFIG_PKA_BASE
#define NOXTLS_STM32WB_CONFIG_PKA_BASE          UINT32_C(0x58002000)
#endif
/** @} */

/** @name Hardware semaphores (RM0434 HSEM chapter, AN5289 semaphore table) */
/** @{ */

/** @brief Semaphore identifier meaning "do not lock this resource". */
#define NOXTLS_STM32WB_HSEM_ID_NONE             255U
/** @brief Highest semaphore index of the 32-entry HSEM array. */
#define NOXTLS_STM32WB_HSEM_ID_MAX              31U

/**
 * @brief Semaphore guarding the RNG (and CLK48 while the RNG runs).
 *
 * Must equal the value used by the CPU2 wireless firmware (CFG_HW_RNG_SEMID).
 */
#ifndef NOXTLS_STM32WB_CONFIG_HSEM_ID_RNG
#define NOXTLS_STM32WB_CONFIG_HSEM_ID_RNG       0U
#endif
/** @brief Semaphore guarding the PKA (CFG_HW_PKA_SEMID of the CPU2 firmware). */
#ifndef NOXTLS_STM32WB_CONFIG_HSEM_ID_PKA
#define NOXTLS_STM32WB_CONFIG_HSEM_ID_PKA       1U
#endif
/**
 * @brief Semaphore guarding AES1.
 *
 * AES1 belongs to CPU1 (AES2 is the CPU2 wireless-stack instance), so ST
 * defines no AES semaphore; NONE skips locking. Set an application-defined
 * semaphore here if CPU2 firmware shares AES1.
 */
#ifndef NOXTLS_STM32WB_CONFIG_HSEM_ID_AES1
#define NOXTLS_STM32WB_CONFIG_HSEM_ID_AES1      NOXTLS_STM32WB_HSEM_ID_NONE
#endif
/** @brief HSEM core identifier of CPU1 written into the semaphore (RM0434 HSEM_R.COREID). */
#ifndef NOXTLS_STM32WB_CONFIG_HSEM_CORE_ID
#define NOXTLS_STM32WB_CONFIG_HSEM_CORE_ID      UINT32_C(0x4)
#endif
/** @brief One-step lock attempts before a semaphore is reported busy. */
#ifndef NOXTLS_STM32WB_CONFIG_HSEM_TAKE_SPINS
#define NOXTLS_STM32WB_CONFIG_HSEM_TAKE_SPINS   UINT32_C(1000)
#endif
/** @} */

/** @name Polling budgets (loop iterations, not time) */
/** @{ */

/** @brief Status polls for one AES block / phase to complete. */
#ifndef NOXTLS_STM32WB_CONFIG_AES_POLL_LIMIT
#define NOXTLS_STM32WB_CONFIG_AES_POLL_LIMIT    UINT32_C(20000)
#endif
/** @brief Status polls for one PKA operation to complete. */
#ifndef NOXTLS_STM32WB_CONFIG_PKA_POLL_LIMIT
#define NOXTLS_STM32WB_CONFIG_PKA_POLL_LIMIT    UINT32_C(4000000)
#endif
/** @brief Status polls for one RNG data word. */
#ifndef NOXTLS_STM32WB_CONFIG_RNG_POLL_LIMIT
#define NOXTLS_STM32WB_CONFIG_RNG_POLL_LIMIT    UINT32_C(20000)
#endif
/** @} */

/** @name RNG health checks (RM0434 RNG chapter: seed and clock error handling) */
/** @{ */

/** @brief Words read and discarded when recovering from a seed error. */
#ifndef NOXTLS_STM32WB_CONFIG_RNG_RECOVERY_WORDS
#define NOXTLS_STM32WB_CONFIG_RNG_RECOVERY_WORDS UINT32_C(12)
#endif
/** @brief Seed / clock error recoveries tolerated per request before it fails. */
#ifndef NOXTLS_STM32WB_CONFIG_RNG_MAX_RECOVERIES
#define NOXTLS_STM32WB_CONFIG_RNG_MAX_RECOVERIES UINT32_C(3)
#endif
/** @brief Consecutive identical words tolerated before the continuous test fails the request. */
#ifndef NOXTLS_STM32WB_CONFIG_RNG_MAX_REPEATS
#define NOXTLS_STM32WB_CONFIG_RNG_MAX_REPEATS   UINT32_C(2)
#endif
/** @} */

/** @name PKA limits and policy */
/** @{ */

/** @brief Largest modular-exponentiation operand in bytes (3136 bits, RM0434 PKA operation table). */
#ifndef NOXTLS_STM32WB_CONFIG_PKA_MODEXP_MAX_BYTES
#define NOXTLS_STM32WB_CONFIG_PKA_MODEXP_MAX_BYTES UINT32_C(392)
#endif
/** @brief Smallest modular-exponentiation operand in bytes the PKA accepts (RM0434: modulus of at least 64 bits). */
#ifndef NOXTLS_STM32WB_CONFIG_PKA_MODEXP_MIN_BYTES
#define NOXTLS_STM32WB_CONFIG_PKA_MODEXP_MIN_BYTES UINT32_C(8)
#endif
/** @brief Non-zero: verify every scalar-multiplication result with the PKA point-check operation. */
#ifndef NOXTLS_STM32WB_CONFIG_PKA_CHECK_RESULT
#define NOXTLS_STM32WB_CONFIG_PKA_CHECK_RESULT  1
#endif
/** @brief ECDSA signing attempts (fresh nonce each) before the hardware path gives up. */
#ifndef NOXTLS_STM32WB_CONFIG_ECDSA_SIGN_ATTEMPTS
#define NOXTLS_STM32WB_CONFIG_ECDSA_SIGN_ATTEMPTS UINT32_C(4)
#endif
/** @} */

/** @name AES limits */
/** @{ */

/**
 * @brief Largest GCM / CCM payload or header, in bytes.
 *
 * The final GCM block carries bit lengths in single 32-bit words (RM0434 AES
 * GCM final phase), so lengths must stay below 2^29 bytes.
 */
#ifndef NOXTLS_STM32WB_CONFIG_AES_MAX_LEN
#define NOXTLS_STM32WB_CONFIG_AES_MAX_LEN       UINT32_C(0x1FFFFFFF)
#endif
/** @} */

#endif /* NOXTLS_STM32WB_CONFIG_H */
