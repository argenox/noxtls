/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_hw_accel_autoconfig.h
* Summary: Automatic HW acceleration feature policy from compile target.
*
*/

#ifndef NOXTLS_HW_ACCEL_AUTOCONFIG_H_
#define NOXTLS_HW_ACCEL_AUTOCONFIG_H_

#include "vendor/st/noxtls_target_detect.h"

/* Default feature macros if upstream config does not provide them yet. */
#ifndef NOXTLS_FEATURE_AES_ACCEL_STM32
#define NOXTLS_FEATURE_AES_ACCEL_STM32 0
#endif
#ifndef NOXTLS_FEATURE_HASH_ACCEL_STM32
#define NOXTLS_FEATURE_HASH_ACCEL_STM32 0
#endif
#ifndef NOXTLS_FEATURE_ECC_ACCEL_STM32
#define NOXTLS_FEATURE_ECC_ACCEL_STM32 0
#endif

/* If the user explicitly sets this, autodetection is bypassed. */
#ifndef NOXTLS_HW_ACCEL_USER_OVERRIDE
#define NOXTLS_HW_ACCEL_USER_OVERRIDE 0
#endif

#if !NOXTLS_HW_ACCEL_USER_OVERRIDE && NOXTLS_TARGET_STM32
/* Auto-enable accel flags by detected family capabilities.
 * Users can still force exact values with top-level defines and
 * NOXTLS_HW_ACCEL_USER_OVERRIDE=1.
 */
#if defined(NOXTLS_STM32_F4_SW_AES_ONLY)
#undef NOXTLS_FEATURE_AES_ACCEL_STM32
#define NOXTLS_FEATURE_AES_ACCEL_STM32 0
#endif

#if defined(NOXTLS_STM32_HAS_AES_PERIPH)
#undef NOXTLS_FEATURE_AES_ACCEL_STM32
#define NOXTLS_FEATURE_AES_ACCEL_STM32 1
#endif

#if defined(NOXTLS_STM32_HAS_HASH_PERIPH)
#undef NOXTLS_FEATURE_HASH_ACCEL_STM32
#define NOXTLS_FEATURE_HASH_ACCEL_STM32 1
#endif

#if defined(NOXTLS_STM32_HAS_PKA_PERIPH)
#undef NOXTLS_FEATURE_ECC_ACCEL_STM32
#define NOXTLS_FEATURE_ECC_ACCEL_STM32 1
#endif

/* STM32WB5x has no HASH peripheral (RM0434): SHA stays in software. */
#if defined(NOXTLS_STM32_WB5X)
#undef NOXTLS_FEATURE_HASH_ACCEL_STM32
#define NOXTLS_FEATURE_HASH_ACCEL_STM32 0
#endif
#endif

/* The STM32WB hardware backend (AES1 / PKA / RNG) only exists for STM32WB5x parts. */
#ifndef NOXTLS_FEATURE_STM32WB_HW_ACCEL
#define NOXTLS_FEATURE_STM32WB_HW_ACCEL 0
#endif
#if NOXTLS_FEATURE_STM32WB_HW_ACCEL && NOXTLS_TARGET_STM32 && !defined(NOXTLS_STM32_WB5X)
#error "NOXTLS_FEATURE_STM32WB_HW_ACCEL is set but the device define is not an STM32WB5x part (STM32WB50xx / STM32WB55xx / STM32WB5Mxx)"
#endif

#endif /* NOXTLS_HW_ACCEL_AUTOCONFIG_H_ */
