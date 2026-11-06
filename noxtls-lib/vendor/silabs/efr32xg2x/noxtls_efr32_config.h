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
* File:    noxtls_efr32_config.h
* Summary: Build-time settings of the EFR32xG2x hardware backend
*
*****************************************************************************/

/**
 * @file noxtls_efr32_config.h
 * @brief Build-time settings of the EFR32xG2x (Series 2) hardware backend.
 * @ingroup noxtls_efr32
 *
 * Every setting may be overridden by defining it before this header is
 * included (for example with a compiler -D option). Time budgets are poll
 * counts derived from NOXTLS_EFR32_CONFIG_SPINS_PER_US, so a loop iteration
 * that is slower than assumed only lengthens a timeout, never shortens it.
 */
#ifndef NOXTLS_EFR32_CONFIG_H
#define NOXTLS_EFR32_CONFIG_H

#include "noxtls_efr32_regs.h"

/** @brief Non-zero (default): use the non-secure RADIOAES / CMU aliases. Out of reset the SMU leaves
 *  every peripheral except SMU and SEMAILBOX non-secure, so a normal (non-TrustZone) image must use
 *  the non-secure aliases; set 0 only in a TrustZone secure image that marks them secure. */
#ifndef NOXTLS_EFR32_CONFIG_NONSECURE
#define NOXTLS_EFR32_CONFIG_NONSECURE       1
#endif

/** @brief RADIOAES base address. */
#ifndef NOXTLS_EFR32_CONFIG_RADIOAES_BASE
#if (NOXTLS_EFR32_CONFIG_NONSECURE != 0)
#define NOXTLS_EFR32_CONFIG_RADIOAES_BASE   NOXTLS_EFR32_RADIOAES_BASE_NS
#else
#define NOXTLS_EFR32_CONFIG_RADIOAES_BASE   NOXTLS_EFR32_RADIOAES_BASE_S
#endif
#endif

/** @brief CMU base address. */
#ifndef NOXTLS_EFR32_CONFIG_CMU_BASE
#if (NOXTLS_EFR32_CONFIG_NONSECURE != 0)
#define NOXTLS_EFR32_CONFIG_CMU_BASE        NOXTLS_EFR32_CMU_BASE_NS
#else
#define NOXTLS_EFR32_CONFIG_CMU_BASE        NOXTLS_EFR32_CMU_BASE_S
#endif
#endif

/** @brief SEMAILBOX_HOST base address. */
#ifndef NOXTLS_EFR32_CONFIG_SEMAILBOX_BASE
#define NOXTLS_EFR32_CONFIG_SEMAILBOX_BASE  NOXTLS_EFR32_SEMAILBOX_BASE
#endif

/** @brief Start of the memory the DMA engines read (flash and SRAM are contiguous in this window). */
#ifndef NOXTLS_EFR32_CONFIG_DMA_IN_START
#define NOXTLS_EFR32_CONFIG_DMA_IN_START    NOXTLS_EFR32_FLASH_BASE
#endif

/** @brief Bytes of the input window starting at NOXTLS_EFR32_CONFIG_DMA_IN_START (flash through SRAM). */
#ifndef NOXTLS_EFR32_CONFIG_DMA_IN_SIZE
#define NOXTLS_EFR32_CONFIG_DMA_IN_SIZE     ((NOXTLS_EFR32_SRAM_BASE - NOXTLS_EFR32_FLASH_BASE) + NOXTLS_EFR32_SRAM_SIZE_MG26)
#endif

/** @brief Start of the memory the DMA engines write (SRAM). */
#ifndef NOXTLS_EFR32_CONFIG_DMA_OUT_START
#define NOXTLS_EFR32_CONFIG_DMA_OUT_START   NOXTLS_EFR32_SRAM_BASE
#endif

/** @brief Bytes of the output window. */
#ifndef NOXTLS_EFR32_CONFIG_DMA_OUT_SIZE
#define NOXTLS_EFR32_CONFIG_DMA_OUT_SIZE    NOXTLS_EFR32_SRAM_SIZE_MG26
#endif

/** @brief Address alignment (bytes) the DMA engines require of caller buffers; 1 = any address. Misaligned buffers are bounced. */
#ifndef NOXTLS_EFR32_CONFIG_DMA_ALIGN
#define NOXTLS_EFR32_CONFIG_DMA_ALIGN       1U
#endif

/** @brief Bytes of the AES input / output bounce buffers (multiple of 16, >= 16). */
#ifndef NOXTLS_EFR32_CONFIG_BOUNCE_SIZE
#define NOXTLS_EFR32_CONFIG_BOUNCE_SIZE     512U
#endif

/** @brief Largest AES request served by the hardware; larger requests use software so the engine lock is held for a bounded time. */
#ifndef NOXTLS_EFR32_CONFIG_AES_MAX_REQUEST
#define NOXTLS_EFR32_CONFIG_AES_MAX_REQUEST 16640U
#endif

/** @brief Largest single fetch / push descriptor length used (multiple of 16, below the 28-bit field). */
#ifndef NOXTLS_EFR32_CONFIG_MAX_CHUNK
#define NOXTLS_EFR32_CONFIG_MAX_CHUNK       0x00FFFFF0U
#endif

/** @brief Non-zero: CBC runs in the engine (CTX_LOAD IV); zero: CBC is composed from hardware ECB and CPU XOR. */
#ifndef NOXTLS_EFR32_CONFIG_AES_CBC_NATIVE
#define NOXTLS_EFR32_CONFIG_AES_CBC_NATIVE  1
#endif

/** @brief Non-zero: single-block AES requests (the NoxTLS block hook used by software GCM / CMAC loops) run in hardware. */
#ifndef NOXTLS_EFR32_CONFIG_AES_BLOCK_HOOK
#define NOXTLS_EFR32_CONFIG_AES_BLOCK_HOOK  1
#endif

/** @brief Poll iterations per microsecond (the CPU clock in MHz; a real iteration is slower, so timeouts only grow). */
#ifndef NOXTLS_EFR32_CONFIG_SPINS_PER_US
#define NOXTLS_EFR32_CONFIG_SPINS_PER_US    78U
#endif

/** @brief Fixed part of the RADIOAES job timeout in microseconds. */
#ifndef NOXTLS_EFR32_CONFIG_AES_TIMEOUT_US
#define NOXTLS_EFR32_CONFIG_AES_TIMEOUT_US  10000U
#endif

/** @brief Additional RADIOAES timeout per started KiB in microseconds (>= 1 MB/s). */
#ifndef NOXTLS_EFR32_CONFIG_AES_US_PER_KIB
#define NOXTLS_EFR32_CONFIG_AES_US_PER_KIB  1000U
#endif

/** @brief Register reads forming the soft-reset pulse. */
#ifndef NOXTLS_EFR32_CONFIG_SOFTRST_SPINS
#define NOXTLS_EFR32_CONFIG_SOFTRST_SPINS   64U
#endif

/** @brief Polls for the soft reset to finish. */
#ifndef NOXTLS_EFR32_CONFIG_IDLE_SPINS
#define NOXTLS_EFR32_CONFIG_IDLE_SPINS      10000U
#endif

/** @brief Try-acquire attempts for the Secure Engine before the request goes to software. */
#ifndef NOXTLS_EFR32_CONFIG_SE_ACQUIRE_TRIES
#define NOXTLS_EFR32_CONFIG_SE_ACQUIRE_TRIES 64U
#endif

/** @brief Poll iterations between two Secure Engine try-acquire attempts. */
#ifndef NOXTLS_EFR32_CONFIG_SE_ACQUIRE_SPINS
#define NOXTLS_EFR32_CONFIG_SE_ACQUIRE_SPINS 1000U
#endif

/** @brief Timeout of a mailbox TX-room wait in microseconds. */
#ifndef NOXTLS_EFR32_CONFIG_SE_TX_TIMEOUT_US
#define NOXTLS_EFR32_CONFIG_SE_TX_TIMEOUT_US 10000U
#endif

/** @brief Timeout of a short Secure Engine command (hash block run, TRNG) in microseconds, fixed part. */
#ifndef NOXTLS_EFR32_CONFIG_SE_TIMEOUT_US
#define NOXTLS_EFR32_CONFIG_SE_TIMEOUT_US   100000U
#endif

/** @brief Additional Secure Engine hash timeout per started KiB in microseconds. */
#ifndef NOXTLS_EFR32_CONFIG_SE_US_PER_KIB
#define NOXTLS_EFR32_CONFIG_SE_US_PER_KIB   1000U
#endif

/** @brief Timeout of a Secure Engine public-key command (ECDH, ECDSA) in microseconds. */
#ifndef NOXTLS_EFR32_CONFIG_SE_PK_TIMEOUT_US
#define NOXTLS_EFR32_CONFIG_SE_PK_TIMEOUT_US 2000000U
#endif

/** @brief Fewest SHA blocks of one hook call that are worth a mailbox round trip. */
#ifndef NOXTLS_EFR32_CONFIG_SE_HASH_MIN_BLOCKS
#define NOXTLS_EFR32_CONFIG_SE_HASH_MIN_BLOCKS 6U
#endif

/** @brief Most bytes of one Secure Engine hash command (multiple of 128). */
#ifndef NOXTLS_EFR32_CONFIG_SE_HASH_MAX_BYTES
#define NOXTLS_EFR32_CONFIG_SE_HASH_MAX_BYTES 16384U
#endif

/** @brief Times a point multiplication is retried when the SE reports an internal error (SE point-multiply workaround). */
#ifndef NOXTLS_EFR32_CONFIG_SE_PTMUL_RETRIES
#define NOXTLS_EFR32_CONFIG_SE_PTMUL_RETRIES 3U
#endif

/** @brief Non-zero: ECDSA signing uses the Secure Engine (non-deterministic nonce from the SE TRNG). */
#ifndef NOXTLS_EFR32_CONFIG_SE_ECDSA_SIGN
#define NOXTLS_EFR32_CONFIG_SE_ECDSA_SIGN   1
#endif

/** @brief Non-zero: point multiplication is repeated through the SE and both results must agree (fault detection). */
#ifndef NOXTLS_EFR32_CONFIG_PTMUL_DOUBLE_CHECK
#define NOXTLS_EFR32_CONFIG_PTMUL_DOUBLE_CHECK 0
#endif

#if ((NOXTLS_EFR32_CONFIG_BOUNCE_SIZE < 16U) || ((NOXTLS_EFR32_CONFIG_BOUNCE_SIZE % 16U) != 0U))
#error "NOXTLS_EFR32_CONFIG_BOUNCE_SIZE must be a non-zero multiple of 16"
#endif
#if ((NOXTLS_EFR32_CONFIG_MAX_CHUNK < 16U) || ((NOXTLS_EFR32_CONFIG_MAX_CHUNK % 16U) != 0U) || \
     (NOXTLS_EFR32_CONFIG_MAX_CHUNK > NOXTLS_EFR32_DESC_LEN_MSK))
#error "NOXTLS_EFR32_CONFIG_MAX_CHUNK must be a multiple of 16 below the descriptor length limit"
#endif
#if (NOXTLS_EFR32_CONFIG_DMA_ALIGN == 0U)
#error "NOXTLS_EFR32_CONFIG_DMA_ALIGN must be at least 1"
#endif
#if ((NOXTLS_EFR32_CONFIG_SE_HASH_MAX_BYTES < 128U) || ((NOXTLS_EFR32_CONFIG_SE_HASH_MAX_BYTES % 128U) != 0U))
#error "NOXTLS_EFR32_CONFIG_SE_HASH_MAX_BYTES must be a non-zero multiple of 128"
#endif

#endif /* NOXTLS_EFR32_CONFIG_H */
