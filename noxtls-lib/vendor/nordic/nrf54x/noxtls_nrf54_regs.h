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
* File:    noxtls_nrf54_regs.h
* Summary: nRF54L CRACEN / KMU register map used by the NoxTLS hardware backend
*
*****************************************************************************/

/**
 * @file noxtls_nrf54_regs.h
 * @brief Register offsets, bit fields and DMA encodings of the nRF54L CRACEN and KMU.
 * @ingroup noxtls_nrf54
 *
 * Specification: nRF54LM20A/B Product Specification and nRF54L15 Product
 * Specification (Nordic documentation bundles ps_nrf54lm20a / ps_nrf54L15,
 * retrieved 2026-10), chapters "CRACEN - Crypto accelerator engine" and
 * "KMU - Key management unit". The datasheets describe the CryptoMaster,
 * BA411 (AES), BA413 (hash), BA414EP (public key) and BA431 (TRNG) engines at
 * block level; the register offsets below are those of the device register
 * map (MDK NRF_CRACEN_Type / NRF_CRACENCORE_Type / NRF_KMU_Type). Engine
 * command words and DMA tag encodings are documented here with the meaning of
 * every field. Values were confirmed on an nRF54LM20-DK (nRF54LM20B).
 *
 * Names are NoxTLS names; every value is written in its own macro so that no
 * magic number appears in the backend sources.
 */

#ifndef NOXTLS_NRF54_REGS_H
#define NOXTLS_NRF54_REGS_H

#include <stdint.h>

/**
 * @name Instances (secure aliases: CRACEN and the KMU are secure-only peripherals)
 * @{
 */
#define NOXTLS_NRF54_CRACEN_BASE_LM20       UINT32_C(0x50059000) /**< CRACEN wrapper, nRF54LM20. */
#define NOXTLS_NRF54_CRACEN_BASE_L15        UINT32_C(0x50048000) /**< CRACEN wrapper, nRF54L15. */
#define NOXTLS_NRF54_CORE_BASE_LM20         UINT32_C(0x50010000) /**< CRACENCORE, nRF54LM20. */
#define NOXTLS_NRF54_CORE_BASE_L15          UINT32_C(0x51800000) /**< CRACENCORE, nRF54L15. */
#define NOXTLS_NRF54_KMU_BASE_LM20          UINT32_C(0x50049000) /**< KMU, nRF54LM20. */
#define NOXTLS_NRF54_KMU_BASE_L15           UINT32_C(0x50045000) /**< KMU, nRF54L15. */
#define NOXTLS_NRF54_CRACEN_IRQN_LM20       89U                  /**< CRACEN_IRQn, nRF54LM20. */
#define NOXTLS_NRF54_CRACEN_IRQN_L15        72U                  /**< CRACEN_IRQn, nRF54L15. */
/** @} */

/**
 * @name CRACEN wrapper registers
 * @{
 */
#define NOXTLS_NRF54_EVENTS_CRYPTOMASTER    UINT32_C(0x100) /**< EVENTS_CRYPTOMASTER. */
#define NOXTLS_NRF54_EVENTS_RNG             UINT32_C(0x104) /**< EVENTS_RNG. */
#define NOXTLS_NRF54_EVENTS_PKEIKG          UINT32_C(0x108) /**< EVENTS_PKEIKG. */
#define NOXTLS_NRF54_INTENSET               UINT32_C(0x304) /**< INTENSET. */
#define NOXTLS_NRF54_INTENCLR               UINT32_C(0x308) /**< INTENCLR. */
#define NOXTLS_NRF54_ENABLE                 UINT32_C(0x400) /**< ENABLE: module power. */
#define NOXTLS_NRF54_EVENT_CLEAR            UINT32_C(0)     /**< Value that clears an event. */
/** @} */

/**
 * @name Module bits (same position in INTENSET / INTENCLR / ENABLE)
 * @{
 */
#define NOXTLS_NRF54_MOD_CM                 (UINT32_C(1) << 0) /**< CryptoMaster (AES / hash DMA). */
#define NOXTLS_NRF54_MOD_RNG                (UINT32_C(1) << 1) /**< TRNG. */
#define NOXTLS_NRF54_MOD_PKE                (UINT32_C(1) << 2) /**< PKE / IKG. */
#define NOXTLS_NRF54_MOD_ALL                (NOXTLS_NRF54_MOD_CM | NOXTLS_NRF54_MOD_RNG | NOXTLS_NRF54_MOD_PKE) /**< All modules. */
/** @} */

/**
 * @name CryptoMaster DMA registers (CRACENCORE + 0x000)
 * @{
 */
#define NOXTLS_NRF54_CM_FETCHADDR           UINT32_C(0x000) /**< FETCHADDRLSB: first fetch descriptor. */
#define NOXTLS_NRF54_CM_PUSHADDR            UINT32_C(0x010) /**< PUSHADDRLSB: first push descriptor. */
#define NOXTLS_NRF54_CM_INTEN               UINT32_C(0x01C) /**< INTEN. */
#define NOXTLS_NRF54_CM_INTSTATRAW          UINT32_C(0x028) /**< INTSTATRAW. */
#define NOXTLS_NRF54_CM_INTSTATCLR          UINT32_C(0x030) /**< INTSTATCLR. */
#define NOXTLS_NRF54_CM_CONFIG              UINT32_C(0x034) /**< CONFIG. */
#define NOXTLS_NRF54_CM_START               UINT32_C(0x038) /**< START. */
#define NOXTLS_NRF54_CM_STATUS              UINT32_C(0x03C) /**< STATUS. */
/** @} */

/**
 * @name CryptoMaster interrupt, CONFIG, START and STATUS fields
 * @{
 */
#define NOXTLS_NRF54_CM_INT_FETCH_ERR       (UINT32_C(1) << 2) /**< Fetch DMA bus error. */
#define NOXTLS_NRF54_CM_INT_PUSH_STOP       (UINT32_C(1) << 4) /**< Push DMA stopped (job complete). */
#define NOXTLS_NRF54_CM_INT_PUSH_ERR        (UINT32_C(1) << 5) /**< Push DMA bus error. */
#define NOXTLS_NRF54_CM_INT_ERRORS          (NOXTLS_NRF54_CM_INT_FETCH_ERR | NOXTLS_NRF54_CM_INT_PUSH_ERR) /**< Bus errors. */
#define NOXTLS_NRF54_CM_INT_USED            (NOXTLS_NRF54_CM_INT_ERRORS | NOXTLS_NRF54_CM_INT_PUSH_STOP) /**< Completion sources. */
#define NOXTLS_NRF54_CM_INT_NONE            UINT32_C(0)          /**< No interrupt source. */
#define NOXTLS_NRF54_CM_INT_CLEAR_ALL       UINT32_C(0xFFFFFFFF) /**< Clears every status bit. */
#define NOXTLS_NRF54_CM_CFG_FETCH_SG        (UINT32_C(1) << 0)   /**< Fetch DMA in descriptor (scatter/gather) mode. */
#define NOXTLS_NRF54_CM_CFG_PUSH_SG         (UINT32_C(1) << 1)   /**< Push DMA in descriptor mode. */
#define NOXTLS_NRF54_CM_CFG_SOFTRST         (UINT32_C(1) << 4)   /**< Soft reset. */
#define NOXTLS_NRF54_CM_CFG_NONE            UINT32_C(0)          /**< CONFIG cleared. */
#define NOXTLS_NRF54_CM_CFG_SG              (NOXTLS_NRF54_CM_CFG_FETCH_SG | NOXTLS_NRF54_CM_CFG_PUSH_SG) /**< CONFIG of every job. */
#define NOXTLS_NRF54_CM_START_BOTH          UINT32_C(0x3)        /**< Start the fetch and push DMA. */
#define NOXTLS_NRF54_CM_ST_FETCH_BUSY       (UINT32_C(1) << 0)   /**< Fetch DMA busy. */
#define NOXTLS_NRF54_CM_ST_PUSH_BUSY        (UINT32_C(1) << 1)   /**< Push DMA busy. */
#define NOXTLS_NRF54_CM_ST_PUSH_WAIT        (UINT32_C(1) << 5)   /**< Push DMA waiting for FIFO data. */
#define NOXTLS_NRF54_CM_ST_SOFTRST_BUSY     (UINT32_C(1) << 6)   /**< Soft reset in progress. */
#define NOXTLS_NRF54_CM_ST_BUSY             (NOXTLS_NRF54_CM_ST_FETCH_BUSY | NOXTLS_NRF54_CM_ST_PUSH_BUSY | \
                                             NOXTLS_NRF54_CM_ST_PUSH_WAIT) /**< Engine not idle. */
/** @} */

/**
 * @name Hardware configuration registers (CRACENCORE + 0x400)
 * @{
 */
#define NOXTLS_NRF54_HW_INCLIPS             UINT32_C(0x400) /**< Included engines. */
#define NOXTLS_NRF54_HW_BA411_CFG1          UINT32_C(0x404) /**< BA411 modes and key sizes. */
#define NOXTLS_NRF54_HW_BA411_CFG2          UINT32_C(0x408) /**< BA411 CTR counter width (bits). */
#define NOXTLS_NRF54_HW_BA413_CFG           UINT32_C(0x40C) /**< BA413 algorithms. */
#define NOXTLS_NRF54_INCLIPS_BA411          (UINT32_C(1) << 0)  /**< AES engine present. */
#define NOXTLS_NRF54_INCLIPS_BA413          (UINT32_C(1) << 4)  /**< Hash engine present. */
#define NOXTLS_NRF54_INCLIPS_BA414EP        (UINT32_C(1) << 9)  /**< Public-key engine present. */
#define NOXTLS_NRF54_INCLIPS_BA431          (UINT32_C(1) << 10) /**< TRNG present. */
#define NOXTLS_NRF54_BA411_MODE_MSK         UINT32_C(0x1FF)     /**< One bit per BA411 mode. */
#define NOXTLS_NRF54_BA411_KEYSZ_POS        24U                 /**< Key size field position. */
#define NOXTLS_NRF54_BA411_KEYSZ_MSK        UINT32_C(0x7)       /**< Key size field (bit0 128, bit1 192, bit2 256). */
#define NOXTLS_NRF54_BA411_CTRSZ_MSK        UINT32_C(0xFFFF)    /**< Counter width in bits. */
#define NOXTLS_NRF54_BA413_ALGO_MSK         UINT32_C(0x7F)      /**< One bit per hash algorithm. */
/** @} */

/**
 * @name Scatter/gather DMA descriptor encoding
 * A descriptor is four 32-bit words: data address, next descriptor, length
 * with flags and the DMA tag (fetch chains). A chain ends with next == STOP.
 * @{
 */
#define NOXTLS_NRF54_DESC_STOP              UINT32_C(0x1)        /**< End-of-chain marker in the next field. */
#define NOXTLS_NRF54_DESC_REALIGN           (UINT32_C(1) << 29)  /**< Realign the DMA stream after this descriptor. */
#define NOXTLS_NRF54_DESC_DISCARD           (UINT32_C(1) << 30)  /**< Push descriptor: drop the data. */
#define NOXTLS_NRF54_DESC_LEN_MAX           0x00FFFFFFU /**< Largest descriptor length. */
#define NOXTLS_NRF54_TAG_ENGINE_AES         UINT32_C(0x1)  /**< Route to the BA411 (AES). */
#define NOXTLS_NRF54_TAG_ENGINE_HASH        UINT32_C(0x3)  /**< Route to the BA413 (hash). */
#define NOXTLS_NRF54_TAG_ENGINE_MSK         UINT32_C(0xF)  /**< Engine field. */
#define NOXTLS_NRF54_TAG_CONFIG             UINT32_C(0x10) /**< Data goes to the engine configuration interface. */
#define NOXTLS_NRF54_TAG_LAST               UINT32_C(0x20) /**< Last descriptor of the engine input. */
#define NOXTLS_NRF54_TAG_DTYPE_POS          6U             /**< Data type field position. */
#define NOXTLS_NRF54_TAG_DTYPE_MSK          UINT32_C(0x3)  /**< Data type field. */
#define NOXTLS_NRF54_TAG_REG_POS            8U             /**< Configuration register offset (config tags). */
#define NOXTLS_NRF54_TAG_REG_MSK            UINT32_C(0xFF) /**< Configuration register field. */
#define NOXTLS_NRF54_TAG_IGN_POS            8U             /**< Invalid trailing bytes (data tags). */
#define NOXTLS_NRF54_TAG_IGN_MSK            UINT32_C(0x1F) /**< Invalid trailing bytes field. */
#define NOXTLS_NRF54_DTYPE_PAYLOAD          UINT32_C(0)    /**< Payload / message. */
#define NOXTLS_NRF54_DTYPE_HEADER           UINT32_C(1)    /**< AEAD associated data / hash initial state. */
/** @} */

/**
 * @name BA411 (AES) configuration interface
 * @{
 */
#define NOXTLS_NRF54_AES_REG_CONFIG         UINT32_C(0x00) /**< Configuration word. */
#define NOXTLS_NRF54_AES_REG_KEY            UINT32_C(0x08) /**< Key (16 / 24 / 32 bytes). */
#define NOXTLS_NRF54_AES_REG_IV             UINT32_C(0x28) /**< IV / initial counter block. */
#define NOXTLS_NRF54_AES_CFG_DECRYPT        (UINT32_C(1) << 0) /**< Decrypt (clear: encrypt). */
#define NOXTLS_NRF54_AES_CFG_MODE_POS       8U                 /**< Mode field position (one-hot). */
#define NOXTLS_NRF54_AES_MODE_ECB           0U                 /**< Mode number: ECB. */
#define NOXTLS_NRF54_AES_MODE_CBC           1U                 /**< Mode number: CBC. */
#define NOXTLS_NRF54_AES_MODE_CTR           2U                 /**< Mode number: CTR. */
#define NOXTLS_NRF54_AES_MODE_CCM           5U                 /**< Mode number: CCM. */
#define NOXTLS_NRF54_AES_MODE_GCM           6U                 /**< Mode number: GCM. */
/** @} */

/**
 * @name BA413 (hash) configuration word and tags
 * Bits 0..6 of the configuration word select the algorithm (same bit
 * positions as the BA413 hardware configuration register). Without the final
 * flag the engine pushes its intermediate state: the chaining value H in
 * FIPS 180-4 byte order (big-endian words), 32 bytes for SHA-224/256 and
 * 64 bytes for SHA-384/512.
 * @{
 */
#define NOXTLS_NRF54_HASH_ALGO_SHA224       UINT32_C(0x04) /**< SHA-224. */
#define NOXTLS_NRF54_HASH_ALGO_SHA256       UINT32_C(0x08) /**< SHA-256. */
#define NOXTLS_NRF54_HASH_ALGO_SHA384       UINT32_C(0x10) /**< SHA-384. */
#define NOXTLS_NRF54_HASH_ALGO_SHA512       UINT32_C(0x20) /**< SHA-512. */
#define NOXTLS_NRF54_HASH_STATE_256         32U            /**< SHA-224/256 state bytes. */
#define NOXTLS_NRF54_HASH_STATE_512         64U            /**< SHA-384/512 state bytes. */
#define NOXTLS_NRF54_HASH_BLOCK_256         64U            /**< SHA-224/256 block bytes. */
#define NOXTLS_NRF54_HASH_BLOCK_512         128U           /**< SHA-384/512 block bytes. */
/** Tag of the configuration word. */
#define NOXTLS_NRF54_HASH_TAG_CFG           (NOXTLS_NRF54_TAG_ENGINE_HASH | NOXTLS_NRF54_TAG_CONFIG)
/** Tag of the initial (resumed) state: header data type, closes the state input. */
#define NOXTLS_NRF54_HASH_TAG_STATE         (NOXTLS_NRF54_TAG_ENGINE_HASH | NOXTLS_NRF54_TAG_LAST | \
                                             (NOXTLS_NRF54_DTYPE_HEADER << NOXTLS_NRF54_TAG_DTYPE_POS))
/** Tag of message blocks. */
#define NOXTLS_NRF54_HASH_TAG_DATA          (NOXTLS_NRF54_TAG_ENGINE_HASH | \
                                             (NOXTLS_NRF54_DTYPE_PAYLOAD << NOXTLS_NRF54_TAG_DTYPE_POS))
/** @} */

/**
 * @name TRNG (BA431) registers (CRACENCORE + 0x1000)
 * The nRF54L15 and nRF54LM20 TRNG revisions share these offsets; 0x28 is the
 * adaptive-proportion cut-off, 0x34 the warm-up period and 0x44 the sampling
 * divider on both. SWOFFTMRVAL and CONTROL.INTENPROP exist on the nRF54L15.
 * @{
 */
#define NOXTLS_NRF54_RNG_CONTROL            UINT32_C(0x1000) /**< CONTROL. */
#define NOXTLS_NRF54_RNG_FIFOLEVEL          UINT32_C(0x1004) /**< FIFO words available. */
#define NOXTLS_NRF54_RNG_KEY0               UINT32_C(0x1010) /**< Conditioning key word 0. */
#define NOXTLS_NRF54_RNG_REPEAT             UINT32_C(0x1024) /**< Repetition count test cut-off. */
#define NOXTLS_NRF54_RNG_PROPCUT            UINT32_C(0x1028) /**< Adaptive proportion test cut-off. */
#define NOXTLS_NRF54_RNG_STATUS             UINT32_C(0x1030) /**< STATUS. */
#define NOXTLS_NRF54_RNG_WARMUP             UINT32_C(0x1034) /**< Warm-up period. */
#define NOXTLS_NRF54_RNG_OFFTIMER           UINT32_C(0x1040) /**< Switch-off timer (nRF54L15). */
#define NOXTLS_NRF54_RNG_CLKDIV             UINT32_C(0x1044) /**< Sample clock divider. */
#define NOXTLS_NRF54_RNG_FIFO               UINT32_C(0x1080) /**< FIFO read port (each read pops a word). */
#define NOXTLS_NRF54_RNG_KEY_WORDS          4U               /**< Conditioning key words. */
#define NOXTLS_NRF54_RNG_CTRL_ENABLE        (UINT32_C(1) << 0) /**< Enable. */
#define NOXTLS_NRF54_RNG_CTRL_INTENREP      (UINT32_C(1) << 4) /**< Interrupt on repetition test failure. */
#define NOXTLS_NRF54_RNG_CTRL_INTENPROP     (UINT32_C(1) << 5) /**< Interrupt on proportion test failure (nRF54L15). */
#define NOXTLS_NRF54_RNG_CTRL_INTENFULL     (UINT32_C(1) << 7) /**< Interrupt on FIFO full. */
#define NOXTLS_NRF54_RNG_CTRL_SOFTRST       (UINT32_C(1) << 8) /**< Soft reset (flushes the FIFO). */
#define NOXTLS_NRF54_RNG_CTRL_NB128_POS     16U                /**< 128-bit blocks per conditioning output. */
#define NOXTLS_NRF54_RNG_CTRL_NB128_MSK     UINT32_C(0xF)      /**< Conditioning block count field. */
#define NOXTLS_NRF54_RNG_CTRL_OFF           UINT32_C(0)        /**< TRNG stopped. */
#define NOXTLS_NRF54_RNG_ST_STATE_POS       1U                 /**< STATE field position. */
#define NOXTLS_NRF54_RNG_ST_STATE_MSK       UINT32_C(0x7)      /**< STATE field. */
#define NOXTLS_NRF54_RNG_STATE_RESET        UINT32_C(0)        /**< Reset. */
#define NOXTLS_NRF54_RNG_STATE_STARTUP      UINT32_C(1)        /**< Warm-up and start-up tests. */
#define NOXTLS_NRF54_RNG_STATE_ERROR        UINT32_C(5)        /**< Halted on a health-test failure. */
#define NOXTLS_NRF54_RNG_ST_REPFAIL         (UINT32_C(1) << 4)  /**< Repetition count test failed. */
#define NOXTLS_NRF54_RNG_ST_PROPFAIL        (UINT32_C(1) << 5)  /**< Adaptive proportion test failed. */
#define NOXTLS_NRF54_RNG_ST_STARTUPFAIL     (UINT32_C(1) << 10) /**< Start-up test failed. */
#define NOXTLS_NRF54_RNG_NB128_DEFAULT      4U   /**< Conditioning blocks per output. */
#define NOXTLS_NRF54_RNG_WARMUP_DEFAULT     512U /**< Warm-up clock cycles. */
#define NOXTLS_NRF54_RNG_OFFTIMER_DEFAULT   0U   /**< Rings stop as soon as the TRNG is idle. */
#define NOXTLS_NRF54_RNG_CLKDIV_L15         0U   /**< Sampling divider, nRF54L15. */
#define NOXTLS_NRF54_RNG_CLKDIV_LM20        1U   /**< Sampling divider, nRF54LM20. */
/**
 * Health-test cut-offs of the nRF54LM20 TRNG revision. Its cut-off registers
 * do not reset to usable values and are rewritten at every start: a
 * repetition count cut-off of 21 equal samples and an adaptive-proportion
 * cut-off of 311 in a 512-sample window (NIST SP 800-90B §4.4, false-alarm
 * probability 2^-20 at the assessed min-entropy).
 */
#define NOXTLS_NRF54_RNG_LITE_REPEAT_CUTOFF UINT32_C(21)
/** Adaptive-proportion cut-off of the nRF54LM20 TRNG (see NOXTLS_NRF54_RNG_LITE_REPEAT_CUTOFF). */
#define NOXTLS_NRF54_RNG_LITE_PROP_CUTOFF   UINT32_C(311)
/** @} */

/**
 * @name BA414EP public-key engine (CRACENCORE + 0x2000) and IKG (+ 0x3000)
 * @{
 */
#define NOXTLS_NRF54_PK_REGS                UINT32_C(0x2000) /**< PK register block. */
#define NOXTLS_NRF54_PK_POINTERS            UINT32_C(0x2000) /**< Operand slot pointers (A, B, C). */
#define NOXTLS_NRF54_PK_COMMAND             UINT32_C(0x2004) /**< COMMAND. */
#define NOXTLS_NRF54_PK_CONTROL             UINT32_C(0x2008) /**< CONTROL. */
#define NOXTLS_NRF54_PK_STATUS              UINT32_C(0x200C) /**< STATUS. */
#define NOXTLS_NRF54_PK_HWCONFIG            UINT32_C(0x2018) /**< HWCONFIG. */
#define NOXTLS_NRF54_IKG_PKESTATUS          UINT32_C(0x3024) /**< IKG view of the PKE status. */
#define NOXTLS_NRF54_PK_DATA                UINT32_C(0x8000) /**< Operand memory (aligned 32-bit access only). */
#define NOXTLS_NRF54_PK_DATA_SIZE           UINT32_C(0x4000) /**< Operand memory bytes. */
#define NOXTLS_NRF54_PK_CODE                UINT32_C(0xC000) /**< Microcode memory (writable on nRF54L15 only). */
#define NOXTLS_NRF54_PK_CODE_SIZE_L15       UINT32_C(0x1400) /**< Microcode RAM bytes, nRF54L15. */
#define NOXTLS_NRF54_PK_CTRL_START          (UINT32_C(1) << 0) /**< Start the command. */
#define NOXTLS_NRF54_PK_CTRL_CLEARIRQ       (UINT32_C(1) << 1) /**< Clear the completion interrupt. */
#define NOXTLS_NRF54_PK_ST_ERR_MSK          UINT32_C(0x1FFF0)  /**< Error flags. */
#define NOXTLS_NRF54_PK_ST_NOT_ON_CURVE     (UINT32_C(1) << 4)  /**< Point not on the curve. */
#define NOXTLS_NRF54_PK_ST_BAD_UCODE        (UINT32_C(1) << 5)  /**< Microcode missing or invalid. */
#define NOXTLS_NRF54_PK_ST_OUT_OF_RANGE     (UINT32_C(1) << 6)  /**< Operand out of range. */
#define NOXTLS_NRF54_PK_ST_BAD_MODULUS      (UINT32_C(1) << 7)  /**< Invalid modulus. */
#define NOXTLS_NRF54_PK_ST_NOT_IMPL         (UINT32_C(1) << 8)  /**< Operation not implemented. */
#define NOXTLS_NRF54_PK_ST_BAD_SIGNATURE    (UINT32_C(1) << 9)  /**< Signature does not verify. */
#define NOXTLS_NRF54_PK_ST_BAD_CURVE        (UINT32_C(1) << 10) /**< Invalid curve parameter. */
#define NOXTLS_NRF54_PK_ST_NOT_INVERTIBLE   (UINT32_C(1) << 11) /**< Value not invertible. */
#define NOXTLS_NRF54_PK_ST_COMPOSITE        (UINT32_C(1) << 12) /**< Composite value. */
#define NOXTLS_NRF54_PK_ST_NOT_QR           (UINT32_C(1) << 13) /**< Not a quadratic residue (point decode). */
#define NOXTLS_NRF54_PK_ST_BAD_ORDER        (UINT32_C(1) << 14) /**< Point of wrong order. */
#define NOXTLS_NRF54_PK_ST_EXPIRED          (UINT32_C(1) << 15) /**< Engine expired. */
#define NOXTLS_NRF54_PK_ST_BUSY             (UINT32_C(1) << 16) /**< Engine busy. */
#define NOXTLS_NRF54_PK_ST_IRQ              (UINT32_C(1) << 17) /**< Completion interrupt latched. */
/** Error flags that mean "the operands were checked and rejected" (verification result). */
#define NOXTLS_NRF54_PK_ST_REJECT           (NOXTLS_NRF54_PK_ST_NOT_ON_CURVE | NOXTLS_NRF54_PK_ST_OUT_OF_RANGE | \
                                             NOXTLS_NRF54_PK_ST_BAD_SIGNATURE | NOXTLS_NRF54_PK_ST_NOT_INVERTIBLE | \
                                             NOXTLS_NRF54_PK_ST_NOT_QR | NOXTLS_NRF54_PK_ST_BAD_ORDER)
#define NOXTLS_NRF54_IKG_ST_BUSY            (UINT32_C(1) << 16) /**< IKG owns the PKE. */
#define NOXTLS_NRF54_IKG_ST_ERASE           (UINT32_C(1) << 18) /**< IKG erasing after power-up. */
#define NOXTLS_NRF54_IKG_ST_BUSY_MSK        (NOXTLS_NRF54_IKG_ST_BUSY | NOXTLS_NRF54_IKG_ST_ERASE) /**< Not ready. */
#define NOXTLS_NRF54_PK_HW_MAXOPSZ_MSK      UINT32_C(0xFFF)     /**< Largest operand in bytes. */
#define NOXTLS_NRF54_PK_HW_P256             (UINT32_C(1) << 20) /**< NIST P-256 built in. */
#define NOXTLS_NRF54_PK_SLOT_SMALL          UINT32_C(0x200)     /**< Operand slot bytes (operands <= 512 bytes). */
#define NOXTLS_NRF54_PK_SLOT_LARGE          UINT32_C(0x400)     /**< Operand slot bytes (larger engines). */
/** @} */

/**
 * @name BA414EP COMMAND word: opcode | (operand bytes - 1) << 8 | flags
 * @{
 */
#define NOXTLS_NRF54_PK_OPSZ_POS            8U                  /**< (Operand bytes - 1) position. */
#define NOXTLS_NRF54_PK_OP_CLEAR_MEM        UINT32_C(0x0F)      /**< Clear the operand memory (nRF54LM20 only). */
#define NOXTLS_NRF54_PK_OP_ECC_PTMUL        UINT32_C(0x22)      /**< Elliptic-curve point multiplication. */
#define NOXTLS_NRF54_PK_OP_ECDSA_VERIFY     UINT32_C(0x31)      /**< ECDSA signature verification. */
#define NOXTLS_NRF54_PK_OP_EDDSA_VERIFY     UINT32_C(0x3D)      /**< EdDSA (Ed25519) signature verification. */
#define NOXTLS_NRF54_PK_FLAG_RAND_SCALAR    (UINT32_C(1) << 24) /**< Scalar blinding (countermeasure). */
#define NOXTLS_NRF54_PK_FLAG_RAND_PROJ      (UINT32_C(1) << 25) /**< Randomised projective coordinates. */
#define NOXTLS_NRF54_PK_FLAG_BIG_ENDIAN     (UINT32_C(1) << 28) /**< Operands big-endian, right-aligned in the slot. */
#define NOXTLS_NRF54_PK_FLAG_ED_AX_ODD      (UINT32_C(1) << 29) /**< EdDSA: x-coordinate of A is odd. */
#define NOXTLS_NRF54_PK_FLAG_ED_RX_ODD      (UINT32_C(1) << 30) /**< EdDSA: x-coordinate of R is odd. */
#define NOXTLS_NRF54_PK_FLAG_RESQUARE       (UINT32_C(1) << 31) /**< Recompute the Montgomery constant. */
#define NOXTLS_NRF54_PK_CURVE_P256          UINT32_C(0x00100000) /**< Built-in curve select: NIST P-256. */
#define NOXTLS_NRF54_PK_CURVE_ED25519       UINT32_C(0x00600000) /**< Built-in curve select: Edwards25519. */
#define NOXTLS_NRF54_PK_PTR_B_POS           8U                  /**< POINTERS: operand B slot position. */
#define NOXTLS_NRF54_PK_PTR_C_POS           16U                 /**< POINTERS: result C slot position. */
/** @} */

/**
 * @name BA414EP operand slots
 * @{
 */
#define NOXTLS_NRF54_PK_SLOT_ECDSA_QX       8U  /**< ECDSA verify: public key x. */
#define NOXTLS_NRF54_PK_SLOT_ECDSA_QY       9U  /**< ECDSA verify: public key y. */
#define NOXTLS_NRF54_PK_SLOT_ECDSA_R        10U /**< ECDSA verify: r. */
#define NOXTLS_NRF54_PK_SLOT_ECDSA_S        11U /**< ECDSA verify: s. */
#define NOXTLS_NRF54_PK_SLOT_ECDSA_H        12U /**< ECDSA verify: truncated hash. */
#define NOXTLS_NRF54_PK_SLOT_ED_K           6U  /**< EdDSA verify: SHA-512(R || A || M), slots 6 and 7. */
#define NOXTLS_NRF54_PK_SLOT_ED_AY          9U  /**< EdDSA verify: y of A. */
#define NOXTLS_NRF54_PK_SLOT_ED_S           10U /**< EdDSA verify: S. */
#define NOXTLS_NRF54_PK_SLOT_ED_RY          11U /**< EdDSA verify: y of R. */
#define NOXTLS_NRF54_PK_SLOT_PTMUL_K        8U  /**< Point multiply: scalar (operand B). */
#define NOXTLS_NRF54_PK_SLOT_PTMUL_PX       12U /**< Point multiply: input x (operand A). */
#define NOXTLS_NRF54_PK_SLOT_PTMUL_PY       13U /**< Point multiply: input y. */
#define NOXTLS_NRF54_PK_SLOT_PTMUL_RX       10U /**< Point multiply: result x (operand C). */
#define NOXTLS_NRF54_PK_SLOT_PTMUL_RY       11U /**< Point multiply: result y. */
#define NOXTLS_NRF54_PK_SLOT_BLIND          15U /**< Blinding factor (last 8 bytes of the slot). */
#define NOXTLS_NRF54_PK_BLIND_BYTES         8U  /**< Blinding factor bytes. */
/** @} */

/**
 * @name KMU registers
 * @{
 */
#define NOXTLS_NRF54_KMU_TASKS_PROVISION    UINT32_C(0x000) /**< Provision a slot. */
#define NOXTLS_NRF54_KMU_TASKS_PUSH         UINT32_C(0x004) /**< Push a slot to its destination. */
#define NOXTLS_NRF54_KMU_TASKS_REVOKE       UINT32_C(0x008) /**< Revoke a slot. */
#define NOXTLS_NRF54_KMU_TASKS_READMETA     UINT32_C(0x00C) /**< Read the slot metadata. */
#define NOXTLS_NRF54_KMU_TASKS_PUSHBLOCK    UINT32_C(0x010) /**< Block pushes until reset. */
#define NOXTLS_NRF54_KMU_TASKS_BLOCK        UINT32_C(0x014) /**< Block every operation until reset (nRF54LM20). */
#define NOXTLS_NRF54_KMU_EVENTS_PROVISIONED UINT32_C(0x100) /**< Provisioned. */
#define NOXTLS_NRF54_KMU_EVENTS_PUSHED      UINT32_C(0x104) /**< Pushed. */
#define NOXTLS_NRF54_KMU_EVENTS_REVOKED     UINT32_C(0x108) /**< Slot is revoked. */
#define NOXTLS_NRF54_KMU_EVENTS_ERROR       UINT32_C(0x10C) /**< Operation failed (read metadata: slot empty). */
#define NOXTLS_NRF54_KMU_EVENTS_METAREAD    UINT32_C(0x110) /**< Metadata read. */
#define NOXTLS_NRF54_KMU_EVENTS_PUSHBLOCKED UINT32_C(0x114) /**< Pushes blocked. */
#define NOXTLS_NRF54_KMU_EVENTS_BLOCKED     UINT32_C(0x118) /**< Slot blocked (nRF54LM20). */
#define NOXTLS_NRF54_KMU_STATUS             UINT32_C(0x400) /**< STATUS (bit 0 busy). */
#define NOXTLS_NRF54_KMU_KEYSLOT            UINT32_C(0x500) /**< Slot of the next task. */
#define NOXTLS_NRF54_KMU_SRC                UINT32_C(0x504) /**< Provisioning source address. */
#define NOXTLS_NRF54_KMU_METADATA           UINT32_C(0x508) /**< Metadata read by TASKS_READMETADATA. */
#define NOXTLS_NRF54_KMU_TRIGGER            UINT32_C(1)     /**< Task trigger value. */
#define NOXTLS_NRF54_KMU_ST_BUSY            UINT32_C(0x1)   /**< Busy. */
#define NOXTLS_NRF54_KMU_SLOT_MSK           UINT32_C(0xFF)  /**< Slot number field. */
#define NOXTLS_NRF54_KMU_SLOTS              250U            /**< Key slots. */
#define NOXTLS_NRF54_KMU_SLOT_WORDS         4U              /**< 32-bit words per slot. */
/** @} */

/**
 * @name Armv8-M NVIC (3 implemented priority bits on the nRF54L)
 * @{
 */
#define NOXTLS_NRF54_NVIC_ISER              UINT32_C(0xE000E100) /**< Set-enable registers. */
#define NOXTLS_NRF54_NVIC_ICER              UINT32_C(0xE000E180) /**< Clear-enable registers. */
#define NOXTLS_NRF54_NVIC_ICPR              UINT32_C(0xE000E280) /**< Clear-pending registers. */
#define NOXTLS_NRF54_NVIC_IPR               UINT32_C(0xE000E400) /**< Priority bytes. */
#define NOXTLS_NRF54_NVIC_IRQS_PER_WORD     32U  /**< Interrupts per enable / pending word. */
#define NOXTLS_NRF54_NVIC_IRQS_PER_IPR      4U   /**< Interrupts per priority word. */
#define NOXTLS_NRF54_NVIC_WORD_BYTES        4U   /**< Bytes per register. */
#define NOXTLS_NRF54_NVIC_BITS_PER_BYTE     8U   /**< Bits per priority byte. */
#define NOXTLS_NRF54_NVIC_PRIO_BITS         3U   /**< Implemented priority bits. */
#define NOXTLS_NRF54_NVIC_PRIO_MAX          7U   /**< Lowest urgency. */
#define NOXTLS_NRF54_NVIC_BYTE_MSK          UINT32_C(0xFF) /**< One priority byte. */
/** @} */

/**
 * @name Memories reachable by the CryptoMaster DMA
 * The fetch DMA reads RRAM (measured on the nRF54LM20B: SHA-256 of RRAM at
 * about 60 MB/s); the push DMA writes RAM.
 * @{
 */
#define NOXTLS_NRF54_RRAM_BASE              UINT32_C(0x00000000) /**< RRAM (code / constants). */
#define NOXTLS_NRF54_RAM_BASE               UINT32_C(0x20000000) /**< Data RAM. */
#define NOXTLS_NRF54_RAM_SIZE_LM20          UINT32_C(0x00080000) /**< 512 KiB, nRF54LM20. */
#define NOXTLS_NRF54_RAM_SIZE_L15           UINT32_C(0x00040000) /**< 256 KiB, nRF54L15. */
#define NOXTLS_NRF54_PROT_KEY0_LM20         UINT32_C(0x2007FF00) /**< KMU push destination AES key 0, nRF54LM20. */
#define NOXTLS_NRF54_PROT_KEY0_L15          UINT32_C(0x51810040) /**< KMU push destination AES key 0, nRF54L15. */
/** @} */

#endif /* NOXTLS_NRF54_REGS_H */
