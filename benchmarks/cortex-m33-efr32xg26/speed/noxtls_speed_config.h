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
* File:    noxtls_speed_config.h
* Summary: Settings of the EFR32xG26 NoxTLS speed benchmark
*
*****************************************************************************/

/**
 * @defgroup noxtls_speed NoxTLS EFR32xG26 speed benchmark
 * @brief On-target software versus hardware (RADIOAES + Secure Engine) timing of NoxTLS crypto.
 */

/**
 * @file noxtls_speed_config.h
 * @brief Build-time settings of the EFR32xG26 (BRD4120A) NoxTLS speed benchmark.
 * @ingroup noxtls_speed
 *
 * Every setting may be overridden with a compiler -D option. Iteration counts
 * trade run time for averaging: the software P-256 operations take seconds, so
 * their counts are small.
 */
#ifndef NOXTLS_SPEED_CONFIG_H
#define NOXTLS_SPEED_CONFIG_H

/** @brief Core clock in Hz the board runs at (HFXO 39 MHz doubled by the DPLL). */
#ifndef NOXTLS_SPEED_CPU_HZ
#define NOXTLS_SPEED_CPU_HZ                 78000000UL
#endif

/** @brief Milliseconds per second. */
#define NOXTLS_SPEED_MS_PER_S               1000UL

/** @brief Wait after enabling the VCOM bridge before the first print, in milliseconds. */
#ifndef NOXTLS_SPEED_VCOM_SETTLE_MS
#define NOXTLS_SPEED_VCOM_SETTLE_MS         50UL
#endif

/** @brief Iterations of one AES-128 ECB block case. */
#ifndef NOXTLS_SPEED_ITERS_AES_BLOCK
#define NOXTLS_SPEED_ITERS_AES_BLOCK        64U
#endif

/** @brief Iterations of one CCM case. */
#ifndef NOXTLS_SPEED_ITERS_CCM
#define NOXTLS_SPEED_ITERS_CCM              32U
#endif

/** @brief Iterations of one SHA-256 case. */
#ifndef NOXTLS_SPEED_ITERS_SHA
#define NOXTLS_SPEED_ITERS_SHA              32U
#endif

/** @brief Iterations of the TRNG / DRBG cases. */
#ifndef NOXTLS_SPEED_ITERS_RNG
#define NOXTLS_SPEED_ITERS_RNG              8U
#endif

/** @brief Iterations of one P-256 case (keygen, ECDH, ECDSA sign, ECDSA verify). */
#ifndef NOXTLS_SPEED_ITERS_ECC
#define NOXTLS_SPEED_ITERS_ECC              2U
#endif

/** @brief Number of CCM payload sizes. */
#define NOXTLS_SPEED_CCM_SIZE_COUNT         5U

/** @brief Payload sizes of the CCM cases in bytes (0 covers the zero-length path; 251 is a BLE LL PDU). */
#define NOXTLS_SPEED_CCM_SIZES              { 0U, 16U, 64U, 251U, 1024U }

/** @brief Number of SHA-256 message sizes. */
#define NOXTLS_SPEED_SHA_SIZE_COUNT         2U

/** @brief Message sizes of the SHA-256 cases in bytes. */
#define NOXTLS_SPEED_SHA_SIZES              { 64U, 1024U }

/** @brief SHA-256 block bytes. */
#define NOXTLS_SPEED_SHA_BLOCK_BYTES        64U

/** @brief Largest buffer any case uses (bytes). */
#define NOXTLS_SPEED_BUF_MAX                1024U

/** @brief Bytes drawn per TRNG / DRBG iteration. */
#ifndef NOXTLS_SPEED_RNG_BYTES
#define NOXTLS_SPEED_RNG_BYTES              1024U
#endif

/** @brief Bits per byte. */
#define NOXTLS_SPEED_BITS_PER_BYTE          8U

/** @brief Allowed deviation of the ones count in a TRNG draw from half the bits (monobit sanity, about 6 sigma at 1024 bytes). */
#ifndef NOXTLS_SPEED_TRNG_MONOBIT_TOL
#define NOXTLS_SPEED_TRNG_MONOBIT_TOL       400U
#endif

/** @brief Bytes of the AES keys used. */
#define NOXTLS_SPEED_KEY_BYTES              16U

/** @brief AES block bytes. */
#define NOXTLS_SPEED_AES_BLOCK_BYTES        16U

/** @brief CCM nonce bytes (BLE uses 13). */
#define NOXTLS_SPEED_CCM_NONCE_BYTES        13U

/** @brief CCM tag bytes (the BLE MIC is 4). */
#ifndef NOXTLS_SPEED_CCM_TAG_BYTES
#define NOXTLS_SPEED_CCM_TAG_BYTES          4U
#endif

/** @brief CCM associated data bytes (the BLE LL header is 1). */
#ifndef NOXTLS_SPEED_CCM_AAD_BYTES
#define NOXTLS_SPEED_CCM_AAD_BYTES          1U
#endif

/** @brief P-256 coordinate / scalar / digest bytes. */
#define NOXTLS_SPEED_P256_BYTES             32U

/** @brief SHA-256 digest bytes. */
#define NOXTLS_SPEED_SHA256_BYTES           32U

/** @brief Bytes of DRBG entropy input for the deterministic DRBG comparison (3/2 x AES-128 key length). */
#define NOXTLS_SPEED_DRBG_ENTROPY_BYTES     24U

/** @brief Seed bytes the software-phase entropy generator takes from the TRNG once at start-up. */
#define NOXTLS_SPEED_SEED_BYTES             16U

/** @brief Largest number of result rows kept. */
#ifndef NOXTLS_SPEED_MAX_ROWS
#define NOXTLS_SPEED_MAX_ROWS               48U
#endif

#endif /* NOXTLS_SPEED_CONFIG_H */
