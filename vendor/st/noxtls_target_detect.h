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
* File:    noxtls_target_detect.h
* Summary: Compile-time target detection for platform-specific acceleration.
*
*
*****************************************************************************/

#ifndef _NOXTLS_TARGET_DETECT_H_
#define _NOXTLS_TARGET_DETECT_H_

/* Generic architecture flags */
#if defined(__arm__) || defined(__thumb__) || defined(__arm64__) || defined(__aarch64__)
#define NOXTLS_TARGET_ARM 1
#else
#define NOXTLS_TARGET_ARM 0
#endif

#if defined(__ARM_ARCH_7EM__) || defined(__ARM_ARCH_8M_MAIN__) || defined(__ARM_ARCH_8M_BASE__)
#define NOXTLS_TARGET_CORTEX_M 1
#else
#define NOXTLS_TARGET_CORTEX_M 0
#endif

/* Vendor/family detection (STM32) */
#if defined(STM32F0) || defined(STM32F0xx) || defined(STM32F030x6) || defined(STM32F030x8) || defined(STM32F070xB)
#define NOXTLS_STM32_FAMILY_F0 1
#endif

#if defined(STM32F1) || defined(STM32F1xx) || defined(STM32F103xB) || defined(STM32F103xE)
#define NOXTLS_STM32_FAMILY_F1 1
#endif

#if defined(STM32F2) || defined(STM32F2xx) || defined(STM32F205xx) || defined(STM32F207xx) || \
    defined(STM32F215xx) || defined(STM32F217xx)
#define NOXTLS_STM32_FAMILY_F2 1
#endif

#if defined(STM32F3) || defined(STM32F3xx) || defined(STM32F303xE)
#define NOXTLS_STM32_FAMILY_F3 1
#endif

#if defined(STM32F4) || defined(STM32F4xx) || defined(STM32F401xx) || defined(STM32F405xx) || \
    defined(STM32F407xx) || defined(STM32F410xx) || defined(STM32F411xx) || defined(STM32F412xx) || \
    defined(STM32F413xx) || defined(STM32F415xx) || defined(STM32F417xx) || defined(STM32F423xx) || \
    defined(STM32F427xx) || defined(STM32F429xx) || defined(STM32F437xx) || defined(STM32F439xx) || \
    defined(STM32F446xx) || defined(STM32F469xx) || defined(STM32F479xx)
#define NOXTLS_STM32_FAMILY_F4 1
#endif

#if defined(STM32F7) || defined(STM32F7xx) || defined(STM32F746xx) || defined(STM32F767xx)
#define NOXTLS_STM32_FAMILY_F7 1
#endif

#if defined(STM32H5) || defined(STM32H5xx) || defined(STM32H503xx) || defined(STM32H563xx)
#define NOXTLS_STM32_FAMILY_H5 1
#endif

#if defined(STM32H7) || defined(STM32H7xx) || defined(STM32H723xx) || defined(STM32H725xx) || \
    defined(STM32H730xx) || defined(STM32H733xx) || defined(STM32H735xx) || defined(STM32H742xx) || \
    defined(STM32H743xx) || defined(STM32H745xx) || defined(STM32H747xx) || defined(STM32H750xx) || \
    defined(STM32H753xx) || defined(STM32H755xx) || defined(STM32H757xx) || defined(STM32H7A3xx) || \
    defined(STM32H7B0xx) || defined(STM32H7B3xx) || defined(STM32H7R3xx) || defined(STM32H7S3xx)
#define NOXTLS_STM32_FAMILY_H7 1
#endif

#if defined(STM32L4) || defined(STM32L4xx) || defined(STM32L476xx) || defined(STM32L496xx)
#define NOXTLS_STM32_FAMILY_L4 1
#endif

#if defined(STM32L5) || defined(STM32L5xx) || defined(STM32L552xx) || defined(STM32L562xx)
#define NOXTLS_STM32_FAMILY_L5 1
#endif

#if defined(STM32U3) || defined(STM32U3xx) || defined(STM32U375XX) || defined(STM32U385XX) || \
    defined(STM32U3B5XX) || defined(STM32U3C5XX) || defined(STM32U375xx) || defined(STM32U385xx) || \
    defined(STM32U3B5xx) || defined(STM32U3C5xx)
#define NOXTLS_STM32_FAMILY_U3 1
#endif

#if defined(STM32U5) || defined(STM32U5xx) || defined(STM32U535xx) || defined(STM32U545xx) || \
    defined(STM32U575xx) || defined(STM32U585xx) || defined(STM32U595xx) || defined(STM32U599xx) || \
    defined(STM32U5A5xx) || defined(STM32U5A9xx) || defined(STM32U5F7xx) || defined(STM32U5G7xx) || \
    defined(STM32U5F9xx) || defined(STM32U5G9xx)
#define NOXTLS_STM32_FAMILY_U5 1
#endif

#if defined(STM32WB) || defined(STM32WBxx) || defined(STM32WB10xx) || defined(STM32WB15xx) || \
    defined(STM32WB30xx) || defined(STM32WB35xx) || defined(STM32WB50xx) || defined(STM32WB55xx)
#define NOXTLS_STM32_FAMILY_WB 1
#endif

#if defined(STM32WL) || defined(STM32WLxx) || defined(STM32WLE5xx)
#define NOXTLS_STM32_FAMILY_WL 1
#endif

#if defined(STM32MP1) || defined(STM32MP1xx)
#define NOXTLS_STM32_FAMILY_MP1 1
#endif

#if defined(NOXTLS_STM32_FAMILY_F0) || defined(NOXTLS_STM32_FAMILY_F1) || defined(NOXTLS_STM32_FAMILY_F2) || \
    defined(NOXTLS_STM32_FAMILY_F3) || defined(NOXTLS_STM32_FAMILY_F4) || defined(NOXTLS_STM32_FAMILY_F7) || \
    defined(NOXTLS_STM32_FAMILY_H5) || defined(NOXTLS_STM32_FAMILY_H7) || defined(NOXTLS_STM32_FAMILY_L4) || \
    defined(NOXTLS_STM32_FAMILY_L5) || defined(NOXTLS_STM32_FAMILY_U3) || defined(NOXTLS_STM32_FAMILY_U5) || \
    defined(NOXTLS_STM32_FAMILY_WB) || \
    defined(NOXTLS_STM32_FAMILY_WL) || defined(NOXTLS_STM32_FAMILY_MP1)
#define NOXTLS_TARGET_STM32 1
#else
#define NOXTLS_TARGET_STM32 0
#endif

/* Helpers for families with common crypto peripherals */
/* STM32F2 CRYP-capable variants (hardware crypto/hash block present). */
#if defined(STM32F215xx) || defined(STM32F217xx)
#define NOXTLS_STM32_F2_HAS_CRYP 1
#endif

#if defined(NOXTLS_STM32_FAMILY_F2) && !defined(NOXTLS_STM32_F2_HAS_CRYP)
#define NOXTLS_STM32_F2_SW_AES_ONLY 1
#endif

/* STM32F4 CRYP-capable variants (hardware crypto block present). */
#if defined(STM32F415xx) || defined(STM32F417xx) || defined(STM32F437xx) || defined(STM32F439xx)
#define NOXTLS_STM32_F4_HAS_CRYP 1
#endif

#if defined(NOXTLS_STM32_FAMILY_WB)
#define NOXTLS_STM32_WB_HAS_CRYP 1
#endif

#if defined(NOXTLS_STM32_FAMILY_F4) && !defined(NOXTLS_STM32_F4_HAS_CRYP)
#define NOXTLS_STM32_F4_SW_AES_ONLY 1
#endif

#if defined(NOXTLS_STM32_F2_HAS_CRYP) || defined(NOXTLS_STM32_F4_HAS_CRYP) || defined(NOXTLS_STM32_WB_HAS_CRYP)
#define NOXTLS_STM32_HAS_CRYP_PERIPH 1
#endif

#if defined(NOXTLS_STM32_HAS_CRYP_PERIPH) || defined(NOXTLS_STM32_FAMILY_H5) || \
    defined(NOXTLS_STM32_FAMILY_H7) || defined(NOXTLS_STM32_FAMILY_L5) || defined(NOXTLS_STM32_FAMILY_U5)
#define NOXTLS_STM32_HAS_AES_PERIPH 1
#endif

#if defined(NOXTLS_STM32_FAMILY_U3)
#define NOXTLS_STM32_HAS_AES_PERIPH 1
#endif

#if defined(NOXTLS_STM32_F2_HAS_CRYP) || defined(NOXTLS_STM32_FAMILY_F4) || defined(NOXTLS_STM32_FAMILY_F7) || \
    defined(NOXTLS_STM32_FAMILY_H5) || defined(NOXTLS_STM32_FAMILY_H7) || defined(NOXTLS_STM32_FAMILY_U5)
#define NOXTLS_STM32_HAS_HASH_PERIPH 1
#endif

#if defined(NOXTLS_STM32_FAMILY_H5) || defined(NOXTLS_STM32_FAMILY_U5)
#define NOXTLS_STM32_HAS_PKA_PERIPH 1
#endif

#endif /* _NOXTLS_TARGET_DETECT_H_ */
