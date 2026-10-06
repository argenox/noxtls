/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_cc13xx_crypto_config.h
* Summary: CC13xx injected accelerator resource boundaries
*****************************************************************************/
/**
 * @file noxtls_cc13xx_crypto_config.h
 * @brief Port selection, fixed crypto widths and configurable bounded AES batch size.
 * @ingroup noxtls_cc13xx_crypto
 */
#ifndef NOXTLS_CC13XX_CRYPTO_CONFIG_H
#define NOXTLS_CC13XX_CRYPTO_CONFIG_H

#include "noxtls_common.h"

/**
 * @brief Effective AES port selection: its own switch or the umbrella switch.
 *
 * NOXTLS_FEATURE_CC13XX_HW_ACCEL=1 enables both ports, so the umbrella keeps
 * its pre-split meaning even where a build system defines the per-engine
 * switches as 0 (for example generated Kconfig mappings).
 */
#define NOXTLS_CC13XX_AES_ACCEL_ENABLED     ((NOXTLS_FEATURE_CC13XX_AES_ACCEL != 0) || (NOXTLS_FEATURE_CC13XX_HW_ACCEL != 0))
/** @brief Effective secp256r1 port selection: its own switch or the umbrella switch. */
#define NOXTLS_CC13XX_P256_ACCEL_ENABLED     ((NOXTLS_FEATURE_CC13XX_P256_ACCEL != 0) || (NOXTLS_FEATURE_CC13XX_HW_ACCEL != 0))

/** AES block width from FIPS 197 (2023), Section 3. */
#define NOXTLS_CC13XX_AES_BLOCK_BYTES 16U
/** Supported AES key widths from FIPS 197 (2023), Section 3. */
#define NOXTLS_CC13XX_AES128_KEY_BYTES 16U
#define NOXTLS_CC13XX_AES192_KEY_BYTES 24U
#define NOXTLS_CC13XX_AES256_KEY_BYTES 32U
/** secp256r1 scalar and coordinate encoding width in bytes. */
#define NOXTLS_CC13XX_P256_BYTES 32U
/** Resource bound, not a protocol limit; oversized batches are unsupported. */
#ifndef NOXTLS_CC13XX_AES_MAX_BLOCKS
#define NOXTLS_CC13XX_AES_MAX_BLOCKS 256U
#endif
#if (NOXTLS_CC13XX_AES_MAX_BLOCKS == 0U) || (NOXTLS_CC13XX_AES_MAX_BLOCKS > 268435455U)
#error "CC13xx AES batch bound must fit a nonempty uint32_t byte span"
#endif

#endif
