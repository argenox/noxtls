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
* File:    noxtls_efr32_regs.h
* Summary: EFR32xG2x RADIOAES / SEMAILBOX / CMU register map of the NoxTLS hardware backend
*
*****************************************************************************/

/**
 * @file noxtls_efr32_regs.h
 * @brief Register offsets, bit fields, DMA descriptor encodings and Secure Engine
 *        command words of the EFR32xG2x (Series 2) NoxTLS hardware backend.
 * @ingroup noxtls_efr32
 *
 * Specification: Silicon Labs EFR32xG26 Reference Manual, chapters "AES -
 * Advanced Encryption Standard Accelerator" (RADIOAES instance: DMA fetcher /
 * pusher, BA411E AES engine, hardware configuration registers), "SEMAILBOX -
 * Secure Engine Mailbox" and "CMU - Clock Management Unit" (CLKEN0, CLKEN1,
 * RADIOCLKCTRL and their SET aliases). Register offsets and base addresses
 * were cross-checked (read only, nothing included or compiled) against the Silicon Labs
 * device headers of Simplicity SDK 2025.6.3 (efr32mg26_aes.h, efr32mg26_semailbox.h,
 * efr32mg26_cmu.h, memory map in efr32mg26b510f3200im68.h). The descriptor, tag and configuration-word
 * encodings, the Secure Engine command words and the key specification
 * encoding were established from the behaviour of the Zlib-licensed reference
 * sources of Simplicity SDK v2025.6.3:
 * platform/security/sl_component/sl_protocol_crypto/src/sli_protocol_crypto_radioaes.c,
 * sli_radioaes_management.c, se_manager/inc/sli_se_manager_mailbox.h,
 * se_manager/src/sl_se_manager_{hash,entropy,signature,key_handling,key_derivation}.c
 * and sl_psa_driver/src/sli_se_driver_key_derivation.c. They are re-expressed
 * here under NoxTLS names; no Silicon Labs code is compiled or copied.
 *
 * Every value is a macro so that no magic number appears in the sources.
 */
#ifndef NOXTLS_EFR32_REGS_H
#define NOXTLS_EFR32_REGS_H

#include <stddef.h>
#include <stdint.h>

/**
 * @name Instances (secure aliases; the non-secure aliases are selected with
 *       NOXTLS_EFR32_CONFIG_NONSECURE)
 * @{
 */
#define NOXTLS_EFR32_RADIOAES_BASE_S        UINT32_C(0x44000000) /**< RADIOAES, secure alias. */
#define NOXTLS_EFR32_RADIOAES_BASE_NS       UINT32_C(0x54000000) /**< RADIOAES, non-secure alias. */
#define NOXTLS_EFR32_SEMAILBOX_BASE         UINT32_C(0x4C000000) /**< SEMAILBOX_HOST (one alias for both worlds). */
#define NOXTLS_EFR32_CMU_BASE_S             UINT32_C(0x40008000) /**< CMU, secure alias. */
#define NOXTLS_EFR32_CMU_BASE_NS            UINT32_C(0x50008000) /**< CMU, non-secure alias. */
#define NOXTLS_EFR32_SRAM_BASE              UINT32_C(0x20000000) /**< SRAM base. */
#define NOXTLS_EFR32_SRAM_SIZE_MG26         UINT32_C(0x00080000) /**< SRAM bytes (EFR32MG26B5xx, 512 KB). */
#define NOXTLS_EFR32_FLASH_BASE             UINT32_C(0x08000000) /**< Flash base. */
#define NOXTLS_EFR32_FLASH_SIZE_MG26        UINT32_C(0x00320000) /**< Flash bytes (xxxF3200, 3200 KB). */
/** @} */

/**
 * @name CMU registers (the SET aliases are atomic and avoid read-modify-write races)
 * @{
 */
#define NOXTLS_EFR32_CMU_CLKEN0_SET         UINT32_C(0x1064)     /**< CLKEN0 set alias. */
#define NOXTLS_EFR32_CMU_CLKEN1_SET         UINT32_C(0x1068)     /**< CLKEN1 set alias. */
#define NOXTLS_EFR32_CMU_RADIOCLKCTRL_SET   UINT32_C(0x1280)     /**< RADIOCLKCTRL set alias. */
#define NOXTLS_EFR32_CMU_CLKEN0_RADIOAES    (UINT32_C(1) << 2)   /**< CLKEN0: RADIOAES bus clock. */
#define NOXTLS_EFR32_CMU_CLKEN1_SEMAILBOX   (UINT32_C(1) << 10)  /**< CLKEN1: SEMAILBOXHOST bus clock. */
#define NOXTLS_EFR32_CMU_RADIOCLK_EN        (UINT32_C(1) << 0)   /**< RADIOCLKCTRL: radio clock tree enable. */
/** @} */

/**
 * @name RADIOAES DMA registers (RM "AES", fetcher / pusher)
 * @{
 */
#define NOXTLS_EFR32_AES_FETCHADDR          UINT32_C(0x000) /**< FETCHADDR: first fetch descriptor. */
#define NOXTLS_EFR32_AES_FETCHLEN           UINT32_C(0x008) /**< FETCHLEN (direct mode only). */
#define NOXTLS_EFR32_AES_FETCHTAG           UINT32_C(0x00C) /**< FETCHTAG (direct mode only). */
#define NOXTLS_EFR32_AES_PUSHADDR           UINT32_C(0x010) /**< PUSHADDR: first push descriptor. */
#define NOXTLS_EFR32_AES_PUSHLEN            UINT32_C(0x018) /**< PUSHLEN (direct mode only). */
#define NOXTLS_EFR32_AES_IEN                UINT32_C(0x01C) /**< IEN: interrupt enable. */
#define NOXTLS_EFR32_AES_IF                 UINT32_C(0x028) /**< IF: interrupt flags. */
#define NOXTLS_EFR32_AES_IF_CLR             UINT32_C(0x030) /**< IF_CLR: flag clear. */
#define NOXTLS_EFR32_AES_CTRL               UINT32_C(0x034) /**< CTRL. */
#define NOXTLS_EFR32_AES_CMD                UINT32_C(0x038) /**< CMD. */
#define NOXTLS_EFR32_AES_STATUS             UINT32_C(0x03C) /**< STATUS. */
#define NOXTLS_EFR32_AES_INCL_IPS_HW_CFG    UINT32_C(0x400) /**< INCL_IPS_HW_CFG: included engines. */
#define NOXTLS_EFR32_AES_BA411E_HW_CFG_1    UINT32_C(0x404) /**< BA411E_HW_CFG_1: modes, key sizes, masking. */
#define NOXTLS_EFR32_AES_BA411E_HW_CFG_2    UINT32_C(0x408) /**< BA411E_HW_CFG_2: CTR counter width. */
#define NOXTLS_EFR32_AES_BA413_HW_CFG       UINT32_C(0x40C) /**< BA413_HW_CFG: hash algorithms. */
/** @} */

/**
 * @name RADIOAES CTRL, CMD, STATUS and IF fields
 * @{
 */
#define NOXTLS_EFR32_AES_CTRL_FETCH_SG      (UINT32_C(1) << 0) /**< Fetcher in scatter/gather (descriptor) mode. */
#define NOXTLS_EFR32_AES_CTRL_PUSH_SG       (UINT32_C(1) << 1) /**< Pusher in scatter/gather mode. */
#define NOXTLS_EFR32_AES_CTRL_SWRESET       (UINT32_C(1) << 4) /**< Software reset. */
#define NOXTLS_EFR32_AES_CTRL_SG            (NOXTLS_EFR32_AES_CTRL_FETCH_SG | NOXTLS_EFR32_AES_CTRL_PUSH_SG) /**< CTRL of every job. */
#define NOXTLS_EFR32_AES_CTRL_NONE          UINT32_C(0)        /**< CTRL cleared. */
#define NOXTLS_EFR32_AES_CMD_START_FETCH    (UINT32_C(1) << 0) /**< Start the fetcher. */
#define NOXTLS_EFR32_AES_CMD_START_PUSH     (UINT32_C(1) << 1) /**< Start the pusher. */
#define NOXTLS_EFR32_AES_CMD_START_BOTH     (NOXTLS_EFR32_AES_CMD_START_FETCH | NOXTLS_EFR32_AES_CMD_START_PUSH) /**< Start both. */
#define NOXTLS_EFR32_AES_ST_FETCH_BUSY      (UINT32_C(1) << 0) /**< Fetcher busy. */
#define NOXTLS_EFR32_AES_ST_PUSH_BUSY       (UINT32_C(1) << 1) /**< Pusher busy. */
#define NOXTLS_EFR32_AES_ST_SOFTRST_BUSY    (UINT32_C(1) << 6) /**< Software reset in progress. */
#define NOXTLS_EFR32_AES_ST_BUSY            (NOXTLS_EFR32_AES_ST_FETCH_BUSY | NOXTLS_EFR32_AES_ST_PUSH_BUSY | \
                                             NOXTLS_EFR32_AES_ST_SOFTRST_BUSY) /**< Engine not idle. */
#define NOXTLS_EFR32_AES_IF_FETCH_ERR       (UINT32_C(1) << 2) /**< Fetcher bus error. */
#define NOXTLS_EFR32_AES_IF_PUSH_ERR        (UINT32_C(1) << 5) /**< Pusher bus error. */
#define NOXTLS_EFR32_AES_IF_ERRORS          (NOXTLS_EFR32_AES_IF_FETCH_ERR | NOXTLS_EFR32_AES_IF_PUSH_ERR) /**< Bus errors. */
#define NOXTLS_EFR32_AES_IF_CLEAR_ALL       UINT32_C(0x3F)     /**< Clears every flag (IF_CLR mask). */
#define NOXTLS_EFR32_AES_IEN_NONE           UINT32_C(0)        /**< All interrupt sources disabled (polled operation). */
/** @} */

/**
 * @name Hardware configuration registers
 * @{
 */
#define NOXTLS_EFR32_INCL_AES               (UINT32_C(1) << 0)  /**< INCL_IPS_HW_CFG: BA411E AES engine present. */
#define NOXTLS_EFR32_INCL_AESGCM            (UINT32_C(1) << 1)  /**< INCL_IPS_HW_CFG: GCM hardware present. */
#define NOXTLS_EFR32_INCL_HASH              (UINT32_C(1) << 4)  /**< INCL_IPS_HW_CFG: BA413 hash engine present. */
#define NOXTLS_EFR32_AES_MODES_MSK          UINT32_C(0x1FF)     /**< BA411E_HW_CFG_1: one bit per mode number. */
#define NOXTLS_EFR32_AES_CFG1_MASKING       (UINT32_C(1) << 17) /**< BA411E_HW_CFG_1: engine requires a mask word. */
#define NOXTLS_EFR32_AES_KEYSZ_POS          24U                 /**< BA411E_HW_CFG_1: key size field position. */
#define NOXTLS_EFR32_AES_KEYSZ_MSK          UINT32_C(0x7)       /**< Key size field (bit0 128, bit1 192, bit2 256). */
#define NOXTLS_EFR32_AES_CTRSZ_MSK          UINT32_C(0xFFFF)    /**< BA411E_HW_CFG_2: counter width in bits. */
#define NOXTLS_EFR32_AES_KEYCAP_128         UINT32_C(0x1)       /**< Key size capability bit: 128. */
#define NOXTLS_EFR32_AES_KEYCAP_192         UINT32_C(0x2)       /**< Key size capability bit: 192. */
#define NOXTLS_EFR32_AES_KEYCAP_256         UINT32_C(0x4)       /**< Key size capability bit: 256. */
/** @} */

/**
 * @name Scatter/gather descriptors (four words: address, next, length | flags, tag)
 * @{
 */
#define NOXTLS_EFR32_DESC_STOP              UINT32_C(0x1)        /**< End-of-chain marker in the next field. */
#define NOXTLS_EFR32_DESC_LEN_MSK           0x0FFFFFFFU /**< Length field. */
#define NOXTLS_EFR32_DESC_CONST_ADDR        (UINT32_C(1) << 28)  /**< Address is constant (FIFO / repeated word). */
#define NOXTLS_EFR32_DESC_REALIGN           (UINT32_C(1) << 29)  /**< Realign the stream after this descriptor. */
#define NOXTLS_EFR32_DESC_DISCARD           (UINT32_C(1) << 30)  /**< Push descriptor: drop the data. */
#define NOXTLS_EFR32_TAG_ENGINE_AES         UINT32_C(0x1)        /**< Route to the BA411E (AES). */
#define NOXTLS_EFR32_TAG_CONFIG             UINT32_C(0x10)       /**< Data goes to the engine configuration interface. */
#define NOXTLS_EFR32_TAG_LAST               UINT32_C(0x20)       /**< Last descriptor of the engine input. */
#define NOXTLS_EFR32_TAG_HEADER             UINT32_C(0x40)       /**< Data type: header (authenticated only). */
#define NOXTLS_EFR32_TAG_PAYLOAD            UINT32_C(0x00)       /**< Data type: payload. */
#define NOXTLS_EFR32_TAG_OFFSET_POS         8U                   /**< Configuration register offset (config tags). */
#define NOXTLS_EFR32_TAG_OFFSET_MSK         UINT32_C(0xFF)       /**< Configuration register offset field. */
#define NOXTLS_EFR32_TAG_INVALID_POS        8U                   /**< Invalid trailing bytes (data tags). */
#define NOXTLS_EFR32_TAG_INVALID_MSK        UINT32_C(0x1F)       /**< Invalid trailing bytes field. */
/** @} */

/**
 * @name BA411E configuration interface (offsets inside the engine configuration space)
 * @{
 */
#define NOXTLS_EFR32_AES_REG_CONFIG         UINT32_C(0)   /**< Configuration word. */
#define NOXTLS_EFR32_AES_REG_KEY            UINT32_C(8)   /**< Key (16 / 24 / 32 bytes). */
#define NOXTLS_EFR32_AES_REG_IV             UINT32_C(40)  /**< IV / initial counter block. */
#define NOXTLS_EFR32_AES_REG_MASK           UINT32_C(104) /**< Mask word (engines that require masking). */
#define NOXTLS_EFR32_AES_CFG_DECRYPT        (UINT32_C(1) << 0)  /**< Decrypt (clear: encrypt). */
#define NOXTLS_EFR32_AES_CFG_KEY_128        UINT32_C(0x0)       /**< Key size 128 bits. */
#define NOXTLS_EFR32_AES_CFG_KEY_256        UINT32_C(0x4)       /**< Key size 256 bits. */
#define NOXTLS_EFR32_AES_CFG_KEY_192        UINT32_C(0x8)       /**< Key size 192 bits. */
#define NOXTLS_EFR32_AES_CFG_CX_LOAD        UINT32_C(0x10)      /**< Load the context (IV / counter) from the IV register. */
#define NOXTLS_EFR32_AES_CFG_MODE_POS       8U                  /**< Mode field position (one-hot, bit = 8 + mode number). */
#define NOXTLS_EFR32_AES_MODE_ECB           0U                  /**< Mode number: ECB. */
#define NOXTLS_EFR32_AES_MODE_CBC           1U                  /**< Mode number: CBC. */
#define NOXTLS_EFR32_AES_MODE_CTR           2U                  /**< Mode number: CTR. */
#define NOXTLS_EFR32_AES_MODE_CCM           5U                  /**< Mode number: CCM. */
#define NOXTLS_EFR32_AES_MODE_GCM           6U                  /**< Mode number: GCM. */
#define NOXTLS_EFR32_AES_MODE_CMAC          8U                  /**< Mode number: CMAC. */
#define NOXTLS_EFR32_AES_MASK_TOP_BIT       (UINT32_C(1) << 31) /**< The mask word must have its top bit set. */
/** @} */

/**
 * @name SEMAILBOX_HOST registers (RM "SEMAILBOX")
 * @{
 */
#define NOXTLS_EFR32_SEM_FIFO               UINT32_C(0x00) /**< FIFO: command words in, response words out. */
#define NOXTLS_EFR32_SEM_TX_STATUS          UINT32_C(0x40) /**< TX_STATUS. */
#define NOXTLS_EFR32_SEM_RX_STATUS          UINT32_C(0x44) /**< RX_STATUS. */
#define NOXTLS_EFR32_SEM_TX_HEADER          UINT32_C(0x50) /**< TX_HEADER: message size starts a transaction. */
#define NOXTLS_EFR32_SEM_RX_HEADER          UINT32_C(0x54) /**< RX_HEADER: response code; reading it acknowledges. */
#define NOXTLS_EFR32_SEM_CONFIGURATION      UINT32_C(0x58) /**< CONFIGURATION: interrupt enables. */
#define NOXTLS_EFR32_SEM_TXINT              (UINT32_C(1) << 20) /**< TX_STATUS: room for a new message. */
#define NOXTLS_EFR32_SEM_RXINT              (UINT32_C(1) << 20) /**< RX_STATUS: response available. */
#define NOXTLS_EFR32_SEM_CFG_INT_NONE       UINT32_C(0)         /**< CONFIGURATION value: mailbox interrupts off (polled). */
#define NOXTLS_EFR32_SEM_WORD_BYTES         4U                  /**< Bytes per FIFO word. */
#define NOXTLS_EFR32_SEM_FIXED_WORDS        3U                  /**< Command, input descriptor and output descriptor words. */
#define NOXTLS_EFR32_SEM_HEADER_WORDS       4U                  /**< TX_HEADER counts one extra word: 4 * (4 + parameters) bytes. */
#define NOXTLS_EFR32_SEM_PARAMS_MAX         5U                  /**< Largest parameter count of the supported commands. */
/** @} */

/**
 * @name SE response codes (RX_HEADER masked with NOXTLS_EFR32_SE_RESPONSE_MASK)
 * @{
 */
#define NOXTLS_EFR32_SE_RESPONSE_MASK       UINT32_C(0x000F0000) /**< Response code field. */
#define NOXTLS_EFR32_SE_RESP_OK             UINT32_C(0x00000000) /**< Command executed / signature valid. */
#define NOXTLS_EFR32_SE_RESP_INVALID_CMD    UINT32_C(0x00010000) /**< Unknown command or not allowed in this context. */
#define NOXTLS_EFR32_SE_RESP_AUTH_ERROR     UINT32_C(0x00020000) /**< Credentials missing. */
#define NOXTLS_EFR32_SE_RESP_INVALID_SIG    UINT32_C(0x00030000) /**< Signature verification failed. */
#define NOXTLS_EFR32_SE_RESP_BUS_ERROR      UINT32_C(0x00040000) /**< The SE could not access a host buffer. */
#define NOXTLS_EFR32_SE_RESP_INTERNAL       UINT32_C(0x00050000) /**< Internal error. */
#define NOXTLS_EFR32_SE_RESP_CRYPTO_ERROR   UINT32_C(0x00060000) /**< Crypto engine error. */
#define NOXTLS_EFR32_SE_RESP_INVALID_PARAM  UINT32_C(0x00070000) /**< A parameter is out of bounds. */
#define NOXTLS_EFR32_SE_RESP_SELFTEST       UINT32_C(0x000A0000) /**< Self-test failure. */
#define NOXTLS_EFR32_SE_RESP_NOT_INIT       UINT32_C(0x000B0000) /**< Feature not initialized or not present. */
#define NOXTLS_EFR32_SE_RESP_ABORT          UINT32_C(0x000F0000) /**< No operation attempted (low nibble of 0x00FF0000). */
/** @} */

/**
 * @name SE command words and options (Series 2 mailbox)
 * @{
 */
#define NOXTLS_EFR32_SE_CMD_HASHUPDATE      UINT32_C(0x03010000) /**< Hash: compress whole blocks into a given state. */
#define NOXTLS_EFR32_SE_CMD_SIGN            UINT32_C(0x06000000) /**< ECDSA sign. */
#define NOXTLS_EFR32_SE_CMD_VERIFY          UINT32_C(0x06010000) /**< ECDSA verify. */
#define NOXTLS_EFR32_SE_CMD_TRNG            UINT32_C(0x07000000) /**< TRNG: get random data. */
#define NOXTLS_EFR32_SE_CMD_DH              UINT32_C(0x0E000000) /**< ECDH (full shared point). */
#define NOXTLS_EFR32_SE_OPT_HASH_SHA256     UINT32_C(0x00000400) /**< Hash option: SHA-256 compression. */
#define NOXTLS_EFR32_SE_OPT_HASH_SHA512     UINT32_C(0x00000600) /**< Hash option: SHA-512 compression (Vault parts). */
#define NOXTLS_EFR32_SE_OPT_NONE            UINT32_C(0x00000000) /**< No option: the message is already a digest. */
/** @} */

/**
 * @name SE DMA transfer descriptors (three words: data, next, length | flags)
 * @{
 */
#define NOXTLS_EFR32_SE_XFER_STOP           UINT32_C(0x00000001) /**< End-of-chain marker. */
#define NOXTLS_EFR32_SE_XFER_REALIGN        UINT32_C(0x20000000) /**< Realign the stream after this transfer. */
#define NOXTLS_EFR32_SE_XFER_LEN_MSK        UINT32_C(0x0FFFFFFF) /**< Length field. */
/** @} */

/**
 * @name SE key specification word (keyspec) for plaintext keys
 * @{
 */
#define NOXTLS_EFR32_KEYSPEC_TYPE_WEIERSTRASS UINT32_C(0x80000000) /**< Type: Weierstrass prime curve. */
#define NOXTLS_EFR32_KEYSPEC_ECC_PRIVATE      UINT32_C(0x00004000) /**< Buffer holds a private key. */
#define NOXTLS_EFR32_KEYSPEC_ECC_PUBLIC       UINT32_C(0x00002000) /**< Buffer holds a public key. */
#define NOXTLS_EFR32_KEYSPEC_ECC_SIGNING      UINT32_C(0x00000400) /**< Key is used for signatures (required by SIGN and VERIFY; found on silicon: without it the SE answers invalid parameter). */
#define NOXTLS_EFR32_KEYSPEC_ECC_SIZE_MSK     UINT32_C(0x0000007F) /**< Curve size field (bytes - 1). */
#define NOXTLS_EFR32_KEYSPEC_RAW_SIZE_MSK     UINT32_C(0x00007FFF) /**< Raw key size field (bytes). */
#define NOXTLS_EFR32_KEYSPEC_DH_RESERVED      UINT32_C(0x00000780) /**< Bits cleared in the DH private keyspec. */
/** @} */


/**
 * @name Register block layouts (Argenox definitions; offsets asserted at compile time)
 * Used only to prove that the offset macros above match the layout of the blocks in
 * the Reference Manual; the drivers access registers by offset through the io seam.
 * @{
 */
typedef struct {
    uint32_t fetchaddr;      /**< 0x000 */
    uint32_t rsv0;           /**< 0x004 */
    uint32_t fetchlen;       /**< 0x008 */
    uint32_t fetchtag;       /**< 0x00C */
    uint32_t pushaddr;       /**< 0x010 */
    uint32_t rsv1;           /**< 0x014 */
    uint32_t pushlen;        /**< 0x018 */
    uint32_t ien;            /**< 0x01C */
    uint32_t rsv2[2];        /**< 0x020 */
    uint32_t if_flags;       /**< 0x028 */
    uint32_t rsv3;           /**< 0x02C */
    uint32_t if_clr;         /**< 0x030 */
    uint32_t ctrl;           /**< 0x034 */
    uint32_t cmd;            /**< 0x038 */
    uint32_t status;         /**< 0x03C */
    uint32_t rsv4[240];      /**< 0x040 */
    uint32_t incl_ips_hw_cfg; /**< 0x400 */
    uint32_t ba411e_hw_cfg_1; /**< 0x404 */
    uint32_t ba411e_hw_cfg_2; /**< 0x408 */
    uint32_t ba413_hw_cfg;    /**< 0x40C */
} noxtls_efr32_aes_regs_t;

typedef struct {
    uint32_t fifo;           /**< 0x00 */
    uint32_t rsv0[15];       /**< 0x04 */
    uint32_t tx_status;      /**< 0x40 */
    uint32_t rx_status;      /**< 0x44 */
    uint32_t tx_prot;        /**< 0x48 */
    uint32_t rx_prot;        /**< 0x4C */
    uint32_t tx_header;      /**< 0x50 */
    uint32_t rx_header;      /**< 0x54 */
    uint32_t configuration;  /**< 0x58 */
} noxtls_efr32_sem_regs_t;
/** @} */

/** Compile-time check that fails the build (negative array size) when the condition is false. */
#define NOXTLS_EFR32_LAYOUT_CHECK(cond, name) extern char noxtls_efr32_layout_check[(cond) ? 1 : -1]

NOXTLS_EFR32_LAYOUT_CHECK(offsetof(noxtls_efr32_aes_regs_t, fetchaddr) == NOXTLS_EFR32_AES_FETCHADDR, fetchaddr);
NOXTLS_EFR32_LAYOUT_CHECK(offsetof(noxtls_efr32_aes_regs_t, fetchlen) == NOXTLS_EFR32_AES_FETCHLEN, fetchlen);
NOXTLS_EFR32_LAYOUT_CHECK(offsetof(noxtls_efr32_aes_regs_t, fetchtag) == NOXTLS_EFR32_AES_FETCHTAG, fetchtag);
NOXTLS_EFR32_LAYOUT_CHECK(offsetof(noxtls_efr32_aes_regs_t, pushaddr) == NOXTLS_EFR32_AES_PUSHADDR, pushaddr);
NOXTLS_EFR32_LAYOUT_CHECK(offsetof(noxtls_efr32_aes_regs_t, pushlen) == NOXTLS_EFR32_AES_PUSHLEN, pushlen);
NOXTLS_EFR32_LAYOUT_CHECK(offsetof(noxtls_efr32_aes_regs_t, ien) == NOXTLS_EFR32_AES_IEN, ien);
NOXTLS_EFR32_LAYOUT_CHECK(offsetof(noxtls_efr32_aes_regs_t, if_flags) == NOXTLS_EFR32_AES_IF, aes_if);
NOXTLS_EFR32_LAYOUT_CHECK(offsetof(noxtls_efr32_aes_regs_t, if_clr) == NOXTLS_EFR32_AES_IF_CLR, if_clr);
NOXTLS_EFR32_LAYOUT_CHECK(offsetof(noxtls_efr32_aes_regs_t, ctrl) == NOXTLS_EFR32_AES_CTRL, ctrl);
NOXTLS_EFR32_LAYOUT_CHECK(offsetof(noxtls_efr32_aes_regs_t, cmd) == NOXTLS_EFR32_AES_CMD, cmd);
NOXTLS_EFR32_LAYOUT_CHECK(offsetof(noxtls_efr32_aes_regs_t, status) == NOXTLS_EFR32_AES_STATUS, status);
NOXTLS_EFR32_LAYOUT_CHECK(offsetof(noxtls_efr32_aes_regs_t, incl_ips_hw_cfg) == NOXTLS_EFR32_AES_INCL_IPS_HW_CFG, incl);
NOXTLS_EFR32_LAYOUT_CHECK(offsetof(noxtls_efr32_aes_regs_t, ba411e_hw_cfg_1) == NOXTLS_EFR32_AES_BA411E_HW_CFG_1, cfg1);
NOXTLS_EFR32_LAYOUT_CHECK(offsetof(noxtls_efr32_aes_regs_t, ba411e_hw_cfg_2) == NOXTLS_EFR32_AES_BA411E_HW_CFG_2, cfg2);
NOXTLS_EFR32_LAYOUT_CHECK(offsetof(noxtls_efr32_aes_regs_t, ba413_hw_cfg) == NOXTLS_EFR32_AES_BA413_HW_CFG, ba413);
NOXTLS_EFR32_LAYOUT_CHECK(offsetof(noxtls_efr32_sem_regs_t, fifo) == NOXTLS_EFR32_SEM_FIFO, sem_fifo);
NOXTLS_EFR32_LAYOUT_CHECK(offsetof(noxtls_efr32_sem_regs_t, tx_status) == NOXTLS_EFR32_SEM_TX_STATUS, sem_txs);
NOXTLS_EFR32_LAYOUT_CHECK(offsetof(noxtls_efr32_sem_regs_t, rx_status) == NOXTLS_EFR32_SEM_RX_STATUS, sem_rxs);
NOXTLS_EFR32_LAYOUT_CHECK(offsetof(noxtls_efr32_sem_regs_t, tx_header) == NOXTLS_EFR32_SEM_TX_HEADER, sem_txh);
NOXTLS_EFR32_LAYOUT_CHECK(offsetof(noxtls_efr32_sem_regs_t, rx_header) == NOXTLS_EFR32_SEM_RX_HEADER, sem_rxh);
NOXTLS_EFR32_LAYOUT_CHECK(offsetof(noxtls_efr32_sem_regs_t, configuration) == NOXTLS_EFR32_SEM_CONFIGURATION, sem_cfg);

#endif /* NOXTLS_EFR32_REGS_H */
