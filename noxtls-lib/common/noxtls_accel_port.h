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
* File:    noxtls_accel_port.h
* Summary: Which optional accelerator port hooks the selected platform provides
*
*****************************************************************************/

/**
 * @file noxtls_accel_port.h
 * @brief Compile-time switches of the optional accelerator port hooks.
 * @ingroup noxtls_common
 *
 * The algorithm sources call an optional hook only when the platform port
 * selected by the build implements it, so ports that do not provide a hook
 * need no stub. A build may set a switch explicitly (-D); otherwise it follows
 * the platform feature that implements the hook. Every hook returns
 * NOXTLS_RETURN_NOT_SUPPORTED when the request must be served in software.
 *
 * | Switch                       | Hook(s)                                                     |
 * |------------------------------|-------------------------------------------------------------|
 * | NOXTLS_PORT_AES_MODE_ACCEL   | noxtls_aes_mode_accel_port(), noxtls_aes_ccm_*_accel_port() |
 * | NOXTLS_PORT_SHA256_ACCEL     | noxtls_sha256_round_accel_port(), noxtls_sha256_blocks_accel_port() |
 * | NOXTLS_PORT_SHA512_ACCEL     | noxtls_sha512_blocks_accel_port()                           |
 * | NOXTLS_PORT_ED25519_ACCEL    | noxtls_ed25519_verify_accel_port()                          |
 * | NOXTLS_PORT_ENTROPY_ACCEL    | noxtls_drbg_entropy_accel_port()                            |
 */

#ifndef NOXTLS_ACCEL_PORT_H
#define NOXTLS_ACCEL_PORT_H

#include "noxtls_common.h"

#ifndef NOXTLS_FEATURE_NRF54_HW_ACCEL
#define NOXTLS_FEATURE_NRF54_HW_ACCEL 0
#endif

/** @brief AES ECB / CBC / CTR and CCM mode hooks are provided. */
#ifndef NOXTLS_PORT_AES_MODE_ACCEL
#define NOXTLS_PORT_AES_MODE_ACCEL   NOXTLS_FEATURE_NRF54_HW_ACCEL
#endif

/**
 * @brief SHA-224/256 block hooks are provided by a port other than the STM32
 *        HASH backend (which keeps its own NOXTLS_FEATURE_HASH_ACCEL_STM32 switch).
 */
#ifndef NOXTLS_PORT_SHA256_ACCEL
#define NOXTLS_PORT_SHA256_ACCEL     NOXTLS_FEATURE_NRF54_HW_ACCEL
#endif

/** @brief SHA-384/512 block hook is provided. */
#ifndef NOXTLS_PORT_SHA512_ACCEL
#define NOXTLS_PORT_SHA512_ACCEL     NOXTLS_FEATURE_NRF54_HW_ACCEL
#endif

/** @brief Ed25519 verification hook is provided. */
#ifndef NOXTLS_PORT_ED25519_ACCEL
#define NOXTLS_PORT_ED25519_ACCEL    NOXTLS_FEATURE_NRF54_HW_ACCEL
#endif

/** @brief Hardware entropy hook (used by NOXTLS_ENTROPY_SOURCE_AUTO before the OS sources). */
#ifndef NOXTLS_PORT_ENTROPY_ACCEL
#define NOXTLS_PORT_ENTROPY_ACCEL    NOXTLS_FEATURE_NRF54_HW_ACCEL
#endif

#endif /* NOXTLS_ACCEL_PORT_H */
