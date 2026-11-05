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
* File:    noxtls_stm32wb_accel.h
* Summary: Everything an application needs from the STM32WB5x hardware backend
*
*****************************************************************************/

/**
 * @file noxtls_stm32wb_accel.h
 * @brief Umbrella header of the STM32WB5x AES1 / PKA / RNG backend.
 * @ingroup noxtls_stm32wb
 *
 * Build with NOXTLS_CFG_FEATURE_STM32WB_HW_ACCEL=ON (CMake) or define
 * NOXTLS_FEATURE_STM32WB_HW_ACCEL=1 and compile the files of
 * noxtls-lib/vendor/st/stm32wb. NoxTLS then routes AES (block, ECB / CBC /
 * CTR, GCM / GMAC, CCM), CTR-DRBG entropy, P-256 point multiplication (also
 * used by ECDH), ECDSA P-256 sign / verify and (after
 * noxtls_stm32wb_bn_register()) modular exponentiation to the CPU1
 * peripherals, with software fallback. SHA stays in software: the STM32WB55
 * has no HASH peripheral.
 *
 * Application responsibilities (not done by the backend):
 *  - enable the peripheral clocks in RCC (AHB2ENR.AES1EN, AHB3ENR.PKAEN,
 *    AHB3ENR.RNGEN, AHB4ENR.HSEMEN) and the CLK48 source of the RNG, taking
 *    the RCC semaphore when CPU2 is running (RM0434 RCC chapter, AN5289);
 *  - keep the semaphore numbers in noxtls_stm32wb_config.h equal to those used
 *    by the CPU2 wireless firmware.
 */

#ifndef NOXTLS_STM32WB_ACCEL_H
#define NOXTLS_STM32WB_ACCEL_H

#include "noxtls_stm32wb_config.h"
#include "noxtls_stm32wb_hsem.h"
#include "noxtls_stm32wb_aes.h"
#include "noxtls_stm32wb_pka.h"
#include "noxtls_stm32wb_rng.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Install the PKA modular exponentiation as the NoxTLS big-number platform hook.
 *
 * Call once at start-up, after the PKA clock is enabled. RSA, DH and DSA
 * exponentiations of 8..392 byte odd moduli then run on the PKA; other
 * requests, and any PKA error, use the portable code.
 */
void noxtls_stm32wb_bn_register(void);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_STM32WB_ACCEL_H */
