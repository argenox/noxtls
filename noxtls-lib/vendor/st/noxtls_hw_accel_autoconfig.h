/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_hw_accel_autoconfig.h
* Summary: Automatic HW acceleration feature policy from compile target.
*
*/

#ifndef _NOXTLS_HW_ACCEL_AUTOCONFIG_H_
#define _NOXTLS_HW_ACCEL_AUTOCONFIG_H_

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
#endif

#endif /* _NOXTLS_HW_ACCEL_AUTOCONFIG_H_ */
