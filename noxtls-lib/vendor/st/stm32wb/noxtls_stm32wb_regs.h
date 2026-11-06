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
* File:    noxtls_stm32wb_regs.h
* Summary: STM32WB5x AES1 / PKA / RNG / HSEM register map
*
*****************************************************************************/

/**
 * @file noxtls_stm32wb_regs.h
 * @brief Register offsets and bit fields of AES1, PKA, RNG and HSEM (STM32WB55).
 * @ingroup noxtls_stm32wb
 *
 * Source: RM0434 Rev 13, register description sections of the AES, PKA, RNG
 * and HSEM chapters; cross-checked against the ST CMSIS device header
 * stm32wb55xx.h (cmsis_device_wb) for offsets and bit positions, and the PKA
 * RAM operand map of the same header (PKA RAM starts at offset 0x400).
 */

#ifndef NOXTLS_STM32WB_REGS_H
#define NOXTLS_STM32WB_REGS_H

#include <stdint.h>

/** @name AES1 registers (RM0434 AES chapter, register map) */
/** @{ */
#define NOXTLS_STM32WB_AES_CR           UINT32_C(0x00)  /**< Control register. */
#define NOXTLS_STM32WB_AES_SR           UINT32_C(0x04)  /**< Status register. */
#define NOXTLS_STM32WB_AES_DINR         UINT32_C(0x08)  /**< Data input register. */
#define NOXTLS_STM32WB_AES_DOUTR        UINT32_C(0x0C)  /**< Data output register. */
#define NOXTLS_STM32WB_AES_KEYR_LO      UINT32_C(0x10)  /**< KEYR0..KEYR3 at 0x10, 0x14, 0x18, 0x1C. */
#define NOXTLS_STM32WB_AES_IVR_BASE     UINT32_C(0x20)  /**< IVR0..IVR3 at 0x20, 0x24, 0x28, 0x2C. */
#define NOXTLS_STM32WB_AES_KEYR_HI      UINT32_C(0x30)  /**< KEYR4..KEYR7 at 0x30, 0x34, 0x38, 0x3C. */
#define NOXTLS_STM32WB_AES_REG_STRIDE   UINT32_C(4)     /**< Bytes between consecutive 32-bit registers. */
#define NOXTLS_STM32WB_AES_KEY_REGS_LO  UINT32_C(4)     /**< Key registers in the first bank (KEYR0..KEYR3). */
#define NOXTLS_STM32WB_AES_KEY_REGS_MAX UINT32_C(8)     /**< Key registers in total (KEYR0..KEYR7). */

#define NOXTLS_STM32WB_AES_CR_EN        (UINT32_C(1) << 0)   /**< AES enable. */
#define NOXTLS_STM32WB_AES_CR_MODE_SHIFT UINT32_C(3)         /**< MODE field position. */
#define NOXTLS_STM32WB_AES_CR_MODE_MASK (UINT32_C(3) << 3)   /**< MODE field mask. */
#define NOXTLS_STM32WB_AES_MODE_ENCRYPT UINT32_C(0)          /**< MODE 1: encryption. */
#define NOXTLS_STM32WB_AES_MODE_DECRYPT UINT32_C(2)          /**< MODE 3: decryption. */
#define NOXTLS_STM32WB_AES_MODE_KEYDERIV_DECRYPT UINT32_C(3) /**< MODE 4: key derivation then decryption. */
#define NOXTLS_STM32WB_AES_CR_CHMOD_SHIFT UINT32_C(5)        /**< CHMOD[1:0] position. */
#define NOXTLS_STM32WB_AES_CHMOD_ECB    UINT32_C(0)          /**< Chaining mode ECB. */
#define NOXTLS_STM32WB_AES_CHMOD_CBC    UINT32_C(1)          /**< Chaining mode CBC. */
#define NOXTLS_STM32WB_AES_CHMOD_CTR    UINT32_C(2)          /**< Chaining mode CTR. */
#define NOXTLS_STM32WB_AES_CHMOD_GCM    UINT32_C(3)          /**< Chaining mode GCM / GMAC. */
#define NOXTLS_STM32WB_AES_CR_CHMOD_CCM (UINT32_C(1) << 16)  /**< CHMOD[2]: chaining mode CCM (with CHMOD[1:0] = 0). */
#define NOXTLS_STM32WB_AES_CR_CCFC      (UINT32_C(1) << 7)   /**< Computation-complete flag clear. */
#define NOXTLS_STM32WB_AES_CR_ERRC      (UINT32_C(1) << 8)   /**< Error clear (RDERR, WRERR). */
#define NOXTLS_STM32WB_AES_CR_GCMPH_SHIFT UINT32_C(13)       /**< GCMPH field position. */
#define NOXTLS_STM32WB_AES_CR_GCMPH_MASK (UINT32_C(3) << 13) /**< GCMPH field mask. */
#define NOXTLS_STM32WB_AES_PHASE_INIT   UINT32_C(0)          /**< GCM / CCM init phase. */
#define NOXTLS_STM32WB_AES_PHASE_HEADER UINT32_C(1)          /**< GCM / CCM header phase. */
#define NOXTLS_STM32WB_AES_PHASE_PAYLOAD UINT32_C(2)         /**< GCM / CCM payload phase. */
#define NOXTLS_STM32WB_AES_PHASE_FINAL  UINT32_C(3)          /**< GCM / CCM final phase. */
#define NOXTLS_STM32WB_AES_CR_KEYSIZE   (UINT32_C(1) << 18)  /**< KEYSIZE: 0 = 128-bit, 1 = 256-bit. */
#define NOXTLS_STM32WB_AES_CR_NPBLB_SHIFT UINT32_C(20)       /**< NPBLB (padding bytes in last block) position. */
#define NOXTLS_STM32WB_AES_CR_NPBLB_MASK (UINT32_C(0xF) << 20) /**< NPBLB field mask. */

#define NOXTLS_STM32WB_AES_SR_CCF       (UINT32_C(1) << 0)   /**< Computation complete flag. */
#define NOXTLS_STM32WB_AES_SR_RDERR     (UINT32_C(1) << 1)   /**< Read error flag. */
#define NOXTLS_STM32WB_AES_SR_WRERR     (UINT32_C(1) << 2)   /**< Write error flag. */
#define NOXTLS_STM32WB_AES_SR_BUSY      (UINT32_C(1) << 3)   /**< Busy flag. */
/** @} */

/** @name PKA registers (RM0434 PKA chapter) */
/** @{ */
#define NOXTLS_STM32WB_PKA_CR           UINT32_C(0x00)  /**< Control register. */
#define NOXTLS_STM32WB_PKA_SR           UINT32_C(0x04)  /**< Status register. */
#define NOXTLS_STM32WB_PKA_CLRFR        UINT32_C(0x08)  /**< Clear flag register. */
#define NOXTLS_STM32WB_PKA_RAM          UINT32_C(0x400) /**< PKA RAM base offset. */
#define NOXTLS_STM32WB_PKA_RAM_END      UINT32_C(0x11F8) /**< PKA RAM end offset (exclusive, 894 words). */
#define NOXTLS_STM32WB_PKA_WORD_BYTES   UINT32_C(4)     /**< Bytes per PKA RAM word. */

#define NOXTLS_STM32WB_PKA_CR_EN        (UINT32_C(1) << 0)   /**< PKA enable. */
#define NOXTLS_STM32WB_PKA_CR_START     (UINT32_C(1) << 1)   /**< Start operation. */
#define NOXTLS_STM32WB_PKA_CR_MODE_SHIFT UINT32_C(8)         /**< MODE field position. */
#define NOXTLS_STM32WB_PKA_CR_MODE_MASK (UINT32_C(0x3F) << 8) /**< MODE field mask. */
#define NOXTLS_STM32WB_PKA_SR_BUSY      (UINT32_C(1) << 16)  /**< Operation in progress. */
#define NOXTLS_STM32WB_PKA_SR_PROCENDF  (UINT32_C(1) << 17)  /**< End of operation flag. */
#define NOXTLS_STM32WB_PKA_SR_RAMERRF   (UINT32_C(1) << 19)  /**< PKA RAM access error. */
#define NOXTLS_STM32WB_PKA_SR_ADDRERRF  (UINT32_C(1) << 20)  /**< Address error. */
/** Clear PROCEND, RAMERR and ADDRERR. */
#define NOXTLS_STM32WB_PKA_CLRFR_ALL    ((UINT32_C(1) << 17) | (UINT32_C(1) << 19) | (UINT32_C(1) << 20))

#define NOXTLS_STM32WB_PKA_MODE_MODEXP       UINT32_C(0x00) /**< Modular exponentiation. */
#define NOXTLS_STM32WB_PKA_MODE_ECC_MUL      UINT32_C(0x20) /**< ECC scalar multiplication. */
#define NOXTLS_STM32WB_PKA_MODE_ECDSA_SIGN   UINT32_C(0x24) /**< ECDSA signature generation. */
#define NOXTLS_STM32WB_PKA_MODE_ECDSA_VERIFY UINT32_C(0x26) /**< ECDSA signature verification. */
#define NOXTLS_STM32WB_PKA_MODE_POINT_CHECK  UINT32_C(0x28) /**< Point on curve check. */

/* PKA RAM operand offsets (RM0434 PKA chapter, operand and result tables). */
#define NOXTLS_STM32WB_PKA_MODEXP_EXP_BITS   UINT32_C(0x400) /**< Modexp: exponent length in bits. */
#define NOXTLS_STM32WB_PKA_MODEXP_OP_BITS    UINT32_C(0x404) /**< Modexp: operand (modulus) length in bits. */
#define NOXTLS_STM32WB_PKA_MODEXP_BASE       UINT32_C(0xA44) /**< Modexp: base in, result out. */
#define NOXTLS_STM32WB_PKA_MODEXP_EXP        UINT32_C(0xBD0) /**< Modexp: exponent. */
#define NOXTLS_STM32WB_PKA_MODEXP_MOD        UINT32_C(0xD5C) /**< Modexp: modulus. */

#define NOXTLS_STM32WB_PKA_MUL_EXP_BITS      UINT32_C(0x400) /**< ECC mul: scalar length in bits. */
#define NOXTLS_STM32WB_PKA_MUL_OP_BITS       UINT32_C(0x404) /**< ECC mul: modulus length in bits. */
#define NOXTLS_STM32WB_PKA_MUL_A_SIGN        UINT32_C(0x408) /**< ECC mul: sign of coefficient a. */
#define NOXTLS_STM32WB_PKA_MUL_A             UINT32_C(0x40C) /**< ECC mul: |a|. */
#define NOXTLS_STM32WB_PKA_MUL_P             UINT32_C(0x460) /**< ECC mul: field prime p. */
#define NOXTLS_STM32WB_PKA_MUL_K             UINT32_C(0x508) /**< ECC mul: scalar k. */
#define NOXTLS_STM32WB_PKA_MUL_X             UINT32_C(0x55C) /**< ECC mul: point X in, result X out. */
#define NOXTLS_STM32WB_PKA_MUL_Y             UINT32_C(0x5B0) /**< ECC mul: point Y in, result Y out. */

#define NOXTLS_STM32WB_PKA_CHK_MOD_BITS      UINT32_C(0x404) /**< Point check: modulus length in bits. */
#define NOXTLS_STM32WB_PKA_CHK_A_SIGN        UINT32_C(0x408) /**< Point check: sign of a. */
#define NOXTLS_STM32WB_PKA_CHK_A             UINT32_C(0x40C) /**< Point check: |a|. */
#define NOXTLS_STM32WB_PKA_CHK_B             UINT32_C(0x7FC) /**< Point check: coefficient b. */
#define NOXTLS_STM32WB_PKA_CHK_P             UINT32_C(0x460) /**< Point check: prime p. */
#define NOXTLS_STM32WB_PKA_CHK_X             UINT32_C(0x55C) /**< Point check: point X. */
#define NOXTLS_STM32WB_PKA_CHK_Y             UINT32_C(0x5B0) /**< Point check: point Y. */
#define NOXTLS_STM32WB_PKA_CHK_RESULT        UINT32_C(0x400) /**< Point check: error word (0 = on curve). */

#define NOXTLS_STM32WB_PKA_SIGN_N_BITS       UINT32_C(0x400) /**< ECDSA sign: order length in bits. */
#define NOXTLS_STM32WB_PKA_SIGN_P_BITS       UINT32_C(0x404) /**< ECDSA sign: modulus length in bits. */
#define NOXTLS_STM32WB_PKA_SIGN_A_SIGN       UINT32_C(0x408) /**< ECDSA sign: sign of a. */
#define NOXTLS_STM32WB_PKA_SIGN_A            UINT32_C(0x40C) /**< ECDSA sign: |a|. */
#define NOXTLS_STM32WB_PKA_SIGN_P            UINT32_C(0x460) /**< ECDSA sign: prime p. */
#define NOXTLS_STM32WB_PKA_SIGN_K            UINT32_C(0x508) /**< ECDSA sign: nonce k. */
#define NOXTLS_STM32WB_PKA_SIGN_GX           UINT32_C(0x55C) /**< ECDSA sign: generator X. */
#define NOXTLS_STM32WB_PKA_SIGN_GY           UINT32_C(0x5B0) /**< ECDSA sign: generator Y. */
#define NOXTLS_STM32WB_PKA_SIGN_E            UINT32_C(0xDE8) /**< ECDSA sign: hash e. */
#define NOXTLS_STM32WB_PKA_SIGN_D            UINT32_C(0xE3C) /**< ECDSA sign: private key d. */
#define NOXTLS_STM32WB_PKA_SIGN_N            UINT32_C(0xE94) /**< ECDSA sign: order n. */
#define NOXTLS_STM32WB_PKA_SIGN_ERROR        UINT32_C(0xEE8) /**< ECDSA sign: error word (0 = success). */
#define NOXTLS_STM32WB_PKA_SIGN_R            UINT32_C(0x700) /**< ECDSA sign: r out. */
#define NOXTLS_STM32WB_PKA_SIGN_S            UINT32_C(0x754) /**< ECDSA sign: s out. */

#define NOXTLS_STM32WB_PKA_VER_N_BITS        UINT32_C(0x404) /**< ECDSA verify: order length in bits. */
#define NOXTLS_STM32WB_PKA_VER_P_BITS        UINT32_C(0x4B4) /**< ECDSA verify: modulus length in bits. */
#define NOXTLS_STM32WB_PKA_VER_A_SIGN        UINT32_C(0x45C) /**< ECDSA verify: sign of a. */
#define NOXTLS_STM32WB_PKA_VER_A             UINT32_C(0x460) /**< ECDSA verify: |a|. */
#define NOXTLS_STM32WB_PKA_VER_P             UINT32_C(0x4B8) /**< ECDSA verify: prime p. */
#define NOXTLS_STM32WB_PKA_VER_GX            UINT32_C(0x5E8) /**< ECDSA verify: generator X. */
#define NOXTLS_STM32WB_PKA_VER_GY            UINT32_C(0x63C) /**< ECDSA verify: generator Y. */
#define NOXTLS_STM32WB_PKA_VER_QX            UINT32_C(0xF40) /**< ECDSA verify: public key X. */
#define NOXTLS_STM32WB_PKA_VER_QY            UINT32_C(0xF94) /**< ECDSA verify: public key Y. */
#define NOXTLS_STM32WB_PKA_VER_R             UINT32_C(0x1098) /**< ECDSA verify: signature r. */
#define NOXTLS_STM32WB_PKA_VER_S             UINT32_C(0xA44) /**< ECDSA verify: signature s. */
#define NOXTLS_STM32WB_PKA_VER_E             UINT32_C(0xFE8) /**< ECDSA verify: hash e. */
#define NOXTLS_STM32WB_PKA_VER_N             UINT32_C(0xD5C) /**< ECDSA verify: order n. */
#define NOXTLS_STM32WB_PKA_VER_RESULT        UINT32_C(0x5B0) /**< ECDSA verify: result word (0 = valid). */
/** @} */

/** @name RNG registers (RM0434 RNG chapter) */
/** @{ */
#define NOXTLS_STM32WB_RNG_CR           UINT32_C(0x00)  /**< Control register. */
#define NOXTLS_STM32WB_RNG_SR           UINT32_C(0x04)  /**< Status register. */
#define NOXTLS_STM32WB_RNG_DR           UINT32_C(0x08)  /**< Data register. */

#define NOXTLS_STM32WB_RNG_CR_RNGEN     (UINT32_C(1) << 2)   /**< RNG enable. */
#define NOXTLS_STM32WB_RNG_CR_IE        (UINT32_C(1) << 3)   /**< Interrupt enable. */
#define NOXTLS_STM32WB_RNG_CR_CED       (UINT32_C(1) << 5)   /**< Clock error detection disable. */
#define NOXTLS_STM32WB_RNG_SR_DRDY      (UINT32_C(1) << 0)   /**< Data ready. */
#define NOXTLS_STM32WB_RNG_SR_CECS      (UINT32_C(1) << 1)   /**< Clock error current status. */
#define NOXTLS_STM32WB_RNG_SR_SECS      (UINT32_C(1) << 2)   /**< Seed error current status. */
#define NOXTLS_STM32WB_RNG_SR_CEIS      (UINT32_C(1) << 5)   /**< Clock error interrupt status (cleared by writing 0). */
#define NOXTLS_STM32WB_RNG_SR_SEIS      (UINT32_C(1) << 6)   /**< Seed error interrupt status (cleared by writing 0). */
/** @} */

/** @name HSEM registers (RM0434 HSEM chapter) */
/** @{ */
#define NOXTLS_STM32WB_HSEM_R           UINT32_C(0x00)  /**< R[n]: two-step lock / release, offset 4 * n. */
#define NOXTLS_STM32WB_HSEM_RLR         UINT32_C(0x80)  /**< RLR[n]: one-step lock read, offset 0x80 + 4 * n. */
#define NOXTLS_STM32WB_HSEM_REG_STRIDE  UINT32_C(4)     /**< Bytes between consecutive semaphores. */
#define NOXTLS_STM32WB_HSEM_COREID_SHIFT UINT32_C(8)    /**< COREID field position. */
#define NOXTLS_STM32WB_HSEM_LOCK        (UINT32_C(1) << 31) /**< LOCK indication in RLR[n]. */
/** @} */

#endif /* NOXTLS_STM32WB_REGS_H */
