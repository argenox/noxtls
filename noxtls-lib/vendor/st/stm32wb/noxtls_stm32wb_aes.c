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
* File:    noxtls_stm32wb_aes.c
* Summary: STM32WB5x AES1 driver (ECB, CBC, CTR)
*
*****************************************************************************/

/**
 * @file noxtls_stm32wb_aes.c
 * @brief AES1 core driver and the ECB / CBC / CTR modes (RM0434 AES chapter).
 * @ingroup noxtls_stm32wb
 *
 * ECB and CBC decryption use operating mode 4 (key derivation followed by
 * decryption, RM0434 AES chapter "operating modes"). CTR decryption is the
 * encryption operation.
 */

#include <stddef.h>

#include "noxtls_stm32wb_aes.h"

#include "common/noxtls_ct.h"
#include "noxtls_stm32wb_bus.h"
#include "noxtls_stm32wb_config.h"
#include "noxtls_stm32wb_hsem.h"
#include "noxtls_stm32wb_regs.h"

/** @brief Bytes per 32-bit register word. */
#define NOXTLS_STM32WB_WORD_BYTES       4U
/** @brief Words per AES block. */
#define NOXTLS_STM32WB_BLOCK_WORDS      4U
/** @brief Bits per byte. */
#define NOXTLS_STM32WB_BYTE_BITS        8U
/** @brief Mask of one byte. */
#define NOXTLS_STM32WB_BYTE_MASK        0xFFU
/** @brief Number of 32-bit counter wrap values (2^32) in units of blocks. */
#define NOXTLS_STM32WB_CTR_WRAP         ((uint64_t)UINT32_MAX + 1U)
/** @brief Offset of the 32-bit hardware counter inside the counter block. */
#define NOXTLS_STM32WB_CTR_OFFSET       12U

/** Driver counters. */
static noxtls_stm32wb_aes_stats_t s_noxtls_stm32wb_aes_stats;

/**
 * @brief Big-endian 32-bit word from four bytes.
 * @internal
 *
 * @param[in] p Four bytes.
 *
 * @return Word.
 */
static uint32_t noxtls_stm32wb_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/**
 * @brief Store a 32-bit word as four big-endian bytes.
 * @internal
 *
 * @param[out] p Four bytes.
 * @param[in]  v Word.
 */
static void noxtls_stm32wb_put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/**
 * @brief Absolute address of a key register.
 * @internal
 *
 * @param[in] idx Key register index 0..7 (KEYR0..KEYR7).
 *
 * @return Address.
 */
static uint32_t noxtls_stm32wb_key_reg(uint32_t idx)
{
    uint32_t off;

    if (idx < NOXTLS_STM32WB_AES_KEY_REGS_LO) {
        off = NOXTLS_STM32WB_AES_KEYR_LO + (idx * NOXTLS_STM32WB_AES_REG_STRIDE);
    } else {
        off = NOXTLS_STM32WB_AES_KEYR_HI + ((idx - NOXTLS_STM32WB_AES_KEY_REGS_LO) * NOXTLS_STM32WB_AES_REG_STRIDE);
    }
    return NOXTLS_STM32WB_CONFIG_AES1_BASE + off;
}

noxtls_return_t noxtls_stm32wb_aes_account(noxtls_return_t rc)
{
    if (rc == NOXTLS_RETURN_SUCCESS) {
        s_noxtls_stm32wb_aes_stats.operations++;
    } else if (rc == NOXTLS_RETURN_NOT_SUPPORTED) {
        s_noxtls_stm32wb_aes_stats.declined++;
    } else if (rc == NOXTLS_RETURN_FAILED) {
        s_noxtls_stm32wb_aes_stats.hw_errors++;
    } else {
        /* Authentication failures are a valid result, not a hardware event. */
        s_noxtls_stm32wb_aes_stats.operations++;
    }
    return rc;
}

const noxtls_stm32wb_aes_stats_t *noxtls_stm32wb_aes_stats(void)
{
    return &s_noxtls_stm32wb_aes_stats;
}

void noxtls_stm32wb_aes_cr(uint32_t clear, uint32_t set)
{
    uint32_t cr = noxtls_stm32wb_bus_rd(NOXTLS_STM32WB_CONFIG_AES1_BASE + NOXTLS_STM32WB_AES_CR);

    cr = (cr & ~clear) | set;
    noxtls_stm32wb_bus_wr(NOXTLS_STM32WB_CONFIG_AES1_BASE + NOXTLS_STM32WB_AES_CR, cr);
}

void noxtls_stm32wb_aes_load_iv(const uint8_t *iv)
{
    uint32_t i;

    /* IVR3 holds the first (most significant) word of the IV block. */
    for (i = 0U; i < NOXTLS_STM32WB_BLOCK_WORDS; i++) {
        noxtls_stm32wb_bus_wr(NOXTLS_STM32WB_CONFIG_AES1_BASE + NOXTLS_STM32WB_AES_IVR_BASE +
                              ((NOXTLS_STM32WB_BLOCK_WORDS - 1U - i) * NOXTLS_STM32WB_AES_REG_STRIDE),
                              noxtls_stm32wb_be32(&iv[i * NOXTLS_STM32WB_WORD_BYTES]));
    }
}

noxtls_return_t noxtls_stm32wb_aes_open(const uint8_t *key, uint32_t key_len, uint32_t cr, const uint8_t *iv)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    uint32_t words;
    uint32_t i;
    uint32_t keysize_bit = 0U;

    if ((key_len == NOXTLS_STM32WB_AES_KEY_128) || (key_len == NOXTLS_STM32WB_AES_KEY_256)) {
        if (noxtls_stm32wb_lock(NOXTLS_STM32WB_RES_AES1) == NOXTLS_RETURN_SUCCESS) {
            if ((noxtls_stm32wb_bus_rd(NOXTLS_STM32WB_CONFIG_AES1_BASE + NOXTLS_STM32WB_AES_SR) &
                 NOXTLS_STM32WB_AES_SR_BUSY) != 0U) {
                noxtls_stm32wb_unlock(NOXTLS_STM32WB_RES_AES1);
            } else {
                if (key_len == NOXTLS_STM32WB_AES_KEY_256) {
                    keysize_bit = NOXTLS_STM32WB_AES_CR_KEYSIZE;
                }
                /* Disable (resets the state machine), clear stale flags, then configure. */
                noxtls_stm32wb_bus_wr(NOXTLS_STM32WB_CONFIG_AES1_BASE + NOXTLS_STM32WB_AES_CR, 0U);
                noxtls_stm32wb_bus_wr(NOXTLS_STM32WB_CONFIG_AES1_BASE + NOXTLS_STM32WB_AES_CR,
                                      NOXTLS_STM32WB_AES_CR_CCFC | NOXTLS_STM32WB_AES_CR_ERRC);
                noxtls_stm32wb_bus_wr(NOXTLS_STM32WB_CONFIG_AES1_BASE + NOXTLS_STM32WB_AES_CR, cr | keysize_bit);
                words = key_len / NOXTLS_STM32WB_WORD_BYTES;
                /* The first (most significant) key word goes to the highest key register in use. */
                for (i = 0U; i < words; i++) {
                    noxtls_stm32wb_bus_wr(noxtls_stm32wb_key_reg(words - 1U - i),
                                          noxtls_stm32wb_be32(&key[i * NOXTLS_STM32WB_WORD_BYTES]));
                }
                if (iv != NULL) {
                    noxtls_stm32wb_aes_load_iv(iv);
                }
                rc = NOXTLS_RETURN_SUCCESS;
            }
        }
    }
    return rc;
}

void noxtls_stm32wb_aes_close(void)
{
    uint32_t i;

    noxtls_stm32wb_bus_wr(NOXTLS_STM32WB_CONFIG_AES1_BASE + NOXTLS_STM32WB_AES_CR, 0U);
    for (i = 0U; i < NOXTLS_STM32WB_AES_KEY_REGS_MAX; i++) {
        noxtls_stm32wb_bus_wr(noxtls_stm32wb_key_reg(i), 0U);
    }
    for (i = 0U; i < NOXTLS_STM32WB_BLOCK_WORDS; i++) {
        noxtls_stm32wb_bus_wr(NOXTLS_STM32WB_CONFIG_AES1_BASE + NOXTLS_STM32WB_AES_IVR_BASE +
                              (i * NOXTLS_STM32WB_AES_REG_STRIDE), 0U);
    }
    noxtls_stm32wb_unlock(NOXTLS_STM32WB_RES_AES1);
}

void noxtls_stm32wb_aes_put(const uint8_t *blk)
{
    uint32_t i;

    for (i = 0U; i < NOXTLS_STM32WB_BLOCK_WORDS; i++) {
        noxtls_stm32wb_bus_wr(NOXTLS_STM32WB_CONFIG_AES1_BASE + NOXTLS_STM32WB_AES_DINR,
                              noxtls_stm32wb_be32(&blk[i * NOXTLS_STM32WB_WORD_BYTES]));
    }
}

void noxtls_stm32wb_aes_get(uint8_t *blk)
{
    uint32_t i;

    for (i = 0U; i < NOXTLS_STM32WB_BLOCK_WORDS; i++) {
        noxtls_stm32wb_put_be32(&blk[i * NOXTLS_STM32WB_WORD_BYTES],
                                noxtls_stm32wb_bus_rd(NOXTLS_STM32WB_CONFIG_AES1_BASE + NOXTLS_STM32WB_AES_DOUTR));
    }
}

noxtls_return_t noxtls_stm32wb_aes_wait(void)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint32_t poll;
    uint32_t sr;
    uint32_t done = 0U;

    for (poll = 0U; (poll < NOXTLS_STM32WB_CONFIG_AES_POLL_LIMIT) && (done == 0U); poll++) {
        sr = noxtls_stm32wb_bus_rd(NOXTLS_STM32WB_CONFIG_AES1_BASE + NOXTLS_STM32WB_AES_SR);
        if ((sr & (NOXTLS_STM32WB_AES_SR_RDERR | NOXTLS_STM32WB_AES_SR_WRERR)) != 0U) {
            noxtls_stm32wb_aes_cr(0U, NOXTLS_STM32WB_AES_CR_ERRC);
            done = 1U;
        } else if ((sr & NOXTLS_STM32WB_AES_SR_CCF) != 0U) {
            noxtls_stm32wb_aes_cr(0U, NOXTLS_STM32WB_AES_CR_CCFC);
            rc = NOXTLS_RETURN_SUCCESS;
            done = 1U;
        } else {
            /* Still computing. */
        }
    }
    return rc;
}

/**
 * @brief Run a byte range through the engine block by block (a short last block is zero padded).
 * @internal
 *
 * @param[in]  in  Input.
 * @param[out] out Output (may equal @p in).
 * @param[in]  len Bytes.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_FAILED.
 */
static noxtls_return_t noxtls_stm32wb_aes_stream(const uint8_t *in, uint8_t *out, uint32_t len)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint8_t blk[NOXTLS_STM32WB_AES_BLOCK];
    uint32_t off = 0U;
    uint32_t rem;
    uint32_t i;

    while ((off < len) && (rc == NOXTLS_RETURN_SUCCESS)) {
        rem = len - off;
        if (rem >= NOXTLS_STM32WB_AES_BLOCK) {
            noxtls_stm32wb_aes_put(&in[off]);
            rc = noxtls_stm32wb_aes_wait();
            if (rc == NOXTLS_RETURN_SUCCESS) {
                noxtls_stm32wb_aes_get(&out[off]);
            }
            off += NOXTLS_STM32WB_AES_BLOCK;
        } else {
            noxtls_secure_zero(blk, sizeof(blk));
            noxtls_copy_u8(blk, sizeof(blk), &in[off], rem);
            noxtls_stm32wb_aes_put(blk);
            rc = noxtls_stm32wb_aes_wait();
            if (rc == NOXTLS_RETURN_SUCCESS) {
                noxtls_stm32wb_aes_get(blk);
                for (i = 0U; i < rem; i++) {
                    out[off + i] = blk[i];
                }
            }
            off += rem;
        }
    }
    noxtls_secure_zero(blk, sizeof(blk));
    return rc;
}

/**
 * @brief Add a block count to the 128-bit big-endian counter block.
 * @internal
 *
 * @param[in,out] ctr   Counter block (16 bytes).
 * @param[in]     units Blocks to add (at most 2^32).
 */
static void noxtls_stm32wb_ctr_add(uint8_t *ctr, uint64_t units)
{
    uint64_t carry = units;
    uint64_t sum;
    uint32_t i = NOXTLS_STM32WB_AES_BLOCK;

    while ((i > 0U) && (carry != 0U)) {
        i--;
        sum = (uint64_t)ctr[i] + (carry & NOXTLS_STM32WB_BYTE_MASK);
        ctr[i] = (uint8_t)(sum & NOXTLS_STM32WB_BYTE_MASK);
        carry = (carry >> NOXTLS_STM32WB_BYTE_BITS) + (sum >> NOXTLS_STM32WB_BYTE_BITS);
    }
}

/**
 * @brief CTR over a buffer, carrying the 32-bit hardware counter into the upper 96 bits in software.
 * @internal
 *
 * @param[in]  iv  Initial counter block.
 * @param[in]  in  Input.
 * @param[out] out Output.
 * @param[in]  len Bytes.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_FAILED.
 */
static noxtls_return_t noxtls_stm32wb_aes_ctr(const uint8_t *iv, const uint8_t *in, uint8_t *out, uint32_t len)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint8_t ctr[NOXTLS_STM32WB_AES_BLOCK];
    uint64_t to_wrap;
    uint64_t units;
    uint32_t remaining;
    uint32_t chunk;
    uint32_t off = 0U;

    noxtls_copy_u8(ctr, sizeof(ctr), iv, sizeof(ctr));
    while ((off < len) && (rc == NOXTLS_RETURN_SUCCESS)) {
        /* Blocks that can still be produced before the low 32 counter bits wrap. */
        to_wrap = NOXTLS_STM32WB_CTR_WRAP - (uint64_t)noxtls_stm32wb_be32(&ctr[NOXTLS_STM32WB_CTR_OFFSET]);
        remaining = len - off;
        units = remaining;
        units = (units + NOXTLS_STM32WB_AES_BLOCK - 1U) / NOXTLS_STM32WB_AES_BLOCK;
        if (units > to_wrap) {
            units = to_wrap;
        }
        chunk = remaining;
        if (((uint64_t)chunk) > (units * NOXTLS_STM32WB_AES_BLOCK)) {
            chunk = (uint32_t)(units * NOXTLS_STM32WB_AES_BLOCK);
        }
        rc = noxtls_stm32wb_aes_stream(&in[off], &out[off], chunk);
        off += chunk;
        if ((rc == NOXTLS_RETURN_SUCCESS) && (off < len)) {
            noxtls_stm32wb_ctr_add(ctr, units);
            noxtls_stm32wb_aes_cr(NOXTLS_STM32WB_AES_CR_EN, 0U);
            noxtls_stm32wb_aes_load_iv(ctr);
            noxtls_stm32wb_aes_cr(0U, NOXTLS_STM32WB_AES_CR_EN);
        }
    }
    noxtls_secure_zero(ctr, sizeof(ctr));
    return rc;
}

noxtls_return_t noxtls_stm32wb_aes_crypt(noxtls_stm32wb_aes_mode_t mode,
                                         uint8_t decrypt,
                                         const uint8_t *key,
                                         uint32_t key_len,
                                         const uint8_t *iv,
                                         const uint8_t *in,
                                         uint8_t *out,
                                         uint32_t len)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    uint32_t chmod = NOXTLS_STM32WB_AES_CHMOD_ECB;
    uint32_t op = NOXTLS_STM32WB_AES_MODE_ENCRYPT;
    uint32_t block_mode_ok = 1U;

    if (mode == NOXTLS_STM32WB_AES_MODE_CBC) {
        chmod = NOXTLS_STM32WB_AES_CHMOD_CBC;
    } else if (mode == NOXTLS_STM32WB_AES_MODE_CTR) {
        chmod = NOXTLS_STM32WB_AES_CHMOD_CTR;
    } else if (mode != NOXTLS_STM32WB_AES_MODE_ECB) {
        block_mode_ok = 0U;
    } else {
        /* ECB. */
    }
    if ((mode != NOXTLS_STM32WB_AES_MODE_CTR) && ((len % NOXTLS_STM32WB_AES_BLOCK) != 0U)) {
        block_mode_ok = 0U;
    }
    if ((mode != NOXTLS_STM32WB_AES_MODE_ECB) && (iv == NULL)) {
        block_mode_ok = 0U;
    }
    if ((block_mode_ok != 0U) && (key != NULL) && (in != NULL) && (out != NULL) && (len != 0U)) {
        if ((decrypt != 0U) && (mode != NOXTLS_STM32WB_AES_MODE_CTR)) {
            op = NOXTLS_STM32WB_AES_MODE_KEYDERIV_DECRYPT;
        }
        rc = noxtls_stm32wb_aes_open(key, key_len,
                                     (chmod << NOXTLS_STM32WB_AES_CR_CHMOD_SHIFT) |
                                     (op << NOXTLS_STM32WB_AES_CR_MODE_SHIFT),
                                     (mode == NOXTLS_STM32WB_AES_MODE_ECB) ? NULL : iv);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_stm32wb_aes_cr(0U, NOXTLS_STM32WB_AES_CR_EN);
            if (mode == NOXTLS_STM32WB_AES_MODE_CTR) {
                rc = noxtls_stm32wb_aes_ctr(iv, in, out, len);
            } else {
                rc = noxtls_stm32wb_aes_stream(in, out, len);
            }
            noxtls_stm32wb_aes_close();
        }
    }
    return noxtls_stm32wb_aes_account(rc);
}
