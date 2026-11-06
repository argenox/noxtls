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
* File:    noxtls_stm32wb_pka.c
* Summary: STM32WB5x public key accelerator driver (P-256 ECC, ECDSA, modexp)
*
*****************************************************************************/

/**
 * @file noxtls_stm32wb_pka.c
 * @brief PKA register-level driver of the STM32WB5x.
 * @ingroup noxtls_stm32wb
 */

#include <stddef.h>

#include "noxtls_stm32wb_pka.h"

#include "common/noxtls_ct.h"
#include "noxtls_stm32wb_bus.h"
#include "noxtls_stm32wb_config.h"
#include "noxtls_stm32wb_hsem.h"
#include "noxtls_stm32wb_regs.h"

/** @brief Bits of a P-256 field element / order. */
#define NOXTLS_STM32WB_P256_BITS        256U
/** @brief Words of a P-256 operand. */
#define NOXTLS_STM32WB_P256_WORDS       8U
/** @brief Absolute value of the P-256 coefficient a = -3. */
#define NOXTLS_STM32WB_P256_A_ABS       3U
/** @brief Sign word for a negative coefficient a. */
#define NOXTLS_STM32WB_PKA_SIGN_NEG     1U
/** @brief Bytes per word. */
#define NOXTLS_STM32WB_PKA_BYTES_WORD   4U
/** @brief Bits per byte. */
#define NOXTLS_STM32WB_PKA_BYTE_BITS    8U
/** @brief Mask of one byte. */
#define NOXTLS_STM32WB_PKA_BYTE_MASK    0xFFU

/** NIST P-256 field prime p (SP 800-186 3.2.1.3), big-endian. */
static const uint8_t s_noxtls_stm32wb_p256_p[NOXTLS_STM32WB_P256_BYTES] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU
};

/** NIST P-256 coefficient a = p - 3, big-endian. */
static const uint8_t s_noxtls_stm32wb_p256_a[NOXTLS_STM32WB_P256_BYTES] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFCU
};

/** NIST P-256 coefficient b, big-endian. */
static const uint8_t s_noxtls_stm32wb_p256_b[NOXTLS_STM32WB_P256_BYTES] = {
    0x5AU, 0xC6U, 0x35U, 0xD8U, 0xAAU, 0x3AU, 0x93U, 0xE7U, 0xB3U, 0xEBU, 0xBDU, 0x55U, 0x76U, 0x98U, 0x86U, 0xBCU,
    0x65U, 0x1DU, 0x06U, 0xB0U, 0xCCU, 0x53U, 0xB0U, 0xF6U, 0x3BU, 0xCEU, 0x3CU, 0x3EU, 0x27U, 0xD2U, 0x60U, 0x4BU
};

/** NIST P-256 group order n, big-endian. */
static const uint8_t s_noxtls_stm32wb_p256_n[NOXTLS_STM32WB_P256_BYTES] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xBCU, 0xE6U, 0xFAU, 0xADU, 0xA7U, 0x17U, 0x9EU, 0x84U, 0xF3U, 0xB9U, 0xCAU, 0xC2U, 0xFCU, 0x63U, 0x25U, 0x51U
};

/** NIST P-256 generator x coordinate, big-endian. */
static const uint8_t s_noxtls_stm32wb_p256_gx[NOXTLS_STM32WB_P256_BYTES] = {
    0x6BU, 0x17U, 0xD1U, 0xF2U, 0xE1U, 0x2CU, 0x42U, 0x47U, 0xF8U, 0xBCU, 0xE6U, 0xE5U, 0x63U, 0xA4U, 0x40U, 0xF2U,
    0x77U, 0x03U, 0x7DU, 0x81U, 0x2DU, 0xEBU, 0x33U, 0xA0U, 0xF4U, 0xA1U, 0x39U, 0x45U, 0xD8U, 0x98U, 0xC2U, 0x96U
};

/** NIST P-256 generator y coordinate, big-endian. */
static const uint8_t s_noxtls_stm32wb_p256_gy[NOXTLS_STM32WB_P256_BYTES] = {
    0x4FU, 0xE3U, 0x42U, 0xE2U, 0xFEU, 0x1AU, 0x7FU, 0x9BU, 0x8EU, 0xE7U, 0xEBU, 0x4AU, 0x7CU, 0x0FU, 0x9EU, 0x16U,
    0x2BU, 0xCEU, 0x33U, 0x57U, 0x6BU, 0x31U, 0x5EU, 0xCEU, 0xCBU, 0xB6U, 0x40U, 0x68U, 0x37U, 0xBFU, 0x51U, 0xF5U
};

/** PKA counters. */
static noxtls_stm32wb_pka_stats_t s_noxtls_stm32wb_pka_stats;

/**
 * @brief Read a PKA register or RAM word.
 * @internal
 *
 * @param[in] off Offset from the PKA base.
 *
 * @return Value.
 */
static uint32_t noxtls_stm32wb_pka_rd(uint32_t off)
{
    return noxtls_stm32wb_bus_rd(NOXTLS_STM32WB_CONFIG_PKA_BASE + off);
}

/**
 * @brief Write a PKA register or RAM word.
 * @internal
 *
 * @param[in] off   Offset from the PKA base.
 * @param[in] value Value.
 */
static void noxtls_stm32wb_pka_wr(uint32_t off, uint32_t value)
{
    noxtls_stm32wb_bus_wr(NOXTLS_STM32WB_CONFIG_PKA_BASE + off, value);
}

/**
 * @brief Store a big-endian byte string as little-endian words followed by a zero word.
 * @internal
 *
 * @param[in] off  RAM offset of the operand.
 * @param[in] data Big-endian bytes.
 * @param[in] len  Bytes.
 */
static void noxtls_stm32wb_pka_put(uint32_t off, const uint8_t *data, uint32_t len)
{
    uint32_t words = (len + NOXTLS_STM32WB_PKA_BYTES_WORD - 1U) / NOXTLS_STM32WB_PKA_BYTES_WORD;
    uint32_t w;
    uint32_t b;
    uint32_t value;
    uint32_t pos;

    for (w = 0U; w < words; w++) {
        value = 0U;
        for (b = 0U; b < NOXTLS_STM32WB_PKA_BYTES_WORD; b++) {
            pos = (w * NOXTLS_STM32WB_PKA_BYTES_WORD) + b;
            if (pos < len) {
                value |= (uint32_t)data[len - 1U - pos] << (b * NOXTLS_STM32WB_PKA_BYTE_BITS);
            }
        }
        noxtls_stm32wb_pka_wr(off + (w * NOXTLS_STM32WB_PKA_BYTES_WORD), value);
    }
    noxtls_stm32wb_pka_wr(off + (words * NOXTLS_STM32WB_PKA_BYTES_WORD), 0U);
}

/**
 * @brief Store a small integer as an operand of @p words words plus the zero terminator.
 * @internal
 *
 * @param[in] off   RAM offset.
 * @param[in] value Least significant word.
 * @param[in] words Operand words.
 */
static void noxtls_stm32wb_pka_put_small(uint32_t off, uint32_t value, uint32_t words)
{
    uint32_t w;

    noxtls_stm32wb_pka_wr(off, value);
    for (w = 1U; w <= words; w++) {
        noxtls_stm32wb_pka_wr(off + (w * NOXTLS_STM32WB_PKA_BYTES_WORD), 0U);
    }
}

/**
 * @brief Read an operand back as a big-endian byte string.
 * @internal
 *
 * @param[in]  off RAM offset.
 * @param[out] out Bytes.
 * @param[in]  len Bytes.
 */
static void noxtls_stm32wb_pka_get(uint32_t off, uint8_t *out, uint32_t len)
{
    uint32_t words = (len + NOXTLS_STM32WB_PKA_BYTES_WORD - 1U) / NOXTLS_STM32WB_PKA_BYTES_WORD;
    uint32_t w;
    uint32_t b;
    uint32_t value;
    uint32_t pos;

    for (w = 0U; w < words; w++) {
        value = noxtls_stm32wb_pka_rd(off + (w * NOXTLS_STM32WB_PKA_BYTES_WORD));
        for (b = 0U; b < NOXTLS_STM32WB_PKA_BYTES_WORD; b++) {
            pos = (w * NOXTLS_STM32WB_PKA_BYTES_WORD) + b;
            if (pos < len) {
                out[len - 1U - pos] = (uint8_t)((value >> (b * NOXTLS_STM32WB_PKA_BYTE_BITS)) &
                                                NOXTLS_STM32WB_PKA_BYTE_MASK);
            }
        }
    }
}

/**
 * @brief Number of significant bits of a big-endian value.
 * @internal
 *
 * @param[in] data Bytes.
 * @param[in] len  Bytes.
 *
 * @return Bit length (0 for an all-zero value).
 */
static uint32_t noxtls_stm32wb_pka_bitlen(const uint8_t *data, uint32_t len)
{
    uint32_t i = 0U;
    uint32_t bits = 0U;
    uint32_t top;

    while ((i < len) && (data[i] == 0U)) {
        i++;
    }
    if (i < len) {
        top = data[i];
        bits = (len - i - 1U) * NOXTLS_STM32WB_PKA_BYTE_BITS;
        while (top != 0U) {
            bits++;
            top >>= 1;
        }
    }
    return bits;
}

/**
 * @brief Whether a big-endian value is all zero.
 * @internal
 *
 * @param[in] data Bytes.
 * @param[in] len  Bytes.
 *
 * @return Non-zero when zero.
 */
static uint32_t noxtls_stm32wb_pka_is_zero(const uint8_t *data, uint32_t len)
{
    return (noxtls_stm32wb_pka_bitlen(data, len) == 0U) ? 1U : 0U;
}

/**
 * @brief Count an outcome in the PKA counters.
 * @internal
 *
 * @param[in] rc Result.
 *
 * @return @p rc.
 */
static noxtls_return_t noxtls_stm32wb_pka_account(noxtls_return_t rc)
{
    if (rc == NOXTLS_RETURN_NOT_SUPPORTED) {
        s_noxtls_stm32wb_pka_stats.declined++;
    } else if (rc == NOXTLS_RETURN_FAILED) {
        s_noxtls_stm32wb_pka_stats.hw_errors++;
    } else {
        s_noxtls_stm32wb_pka_stats.operations++;
    }
    return rc;
}

const noxtls_stm32wb_pka_stats_t *noxtls_stm32wb_pka_stats(void)
{
    return &s_noxtls_stm32wb_pka_stats;
}

/**
 * @brief Lock the PKA, verify it is idle and enable it.
 * @internal
 *
 * @return NOXTLS_RETURN_SUCCESS, or NOXTLS_RETURN_NOT_SUPPORTED when busy (lock not held).
 */
static noxtls_return_t noxtls_stm32wb_pka_open(void)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;

    if (noxtls_stm32wb_lock(NOXTLS_STM32WB_RES_PKA) == NOXTLS_RETURN_SUCCESS) {
        if ((noxtls_stm32wb_pka_rd(NOXTLS_STM32WB_PKA_SR) & NOXTLS_STM32WB_PKA_SR_BUSY) != 0U) {
            noxtls_stm32wb_unlock(NOXTLS_STM32WB_RES_PKA);
        } else {
            noxtls_stm32wb_pka_wr(NOXTLS_STM32WB_PKA_CR, NOXTLS_STM32WB_PKA_CR_EN);
            noxtls_stm32wb_pka_wr(NOXTLS_STM32WB_PKA_CLRFR, NOXTLS_STM32WB_PKA_CLRFR_ALL);
            rc = NOXTLS_RETURN_SUCCESS;
        }
    }
    return rc;
}

/**
 * @brief Wipe the PKA RAM (private operands), disable the PKA and release the lock.
 * @internal
 */
static void noxtls_stm32wb_pka_close(void)
{
    uint32_t off;

    for (off = NOXTLS_STM32WB_PKA_RAM; off < NOXTLS_STM32WB_PKA_RAM_END; off += NOXTLS_STM32WB_PKA_WORD_BYTES) {
        noxtls_stm32wb_pka_wr(off, 0U);
    }
    noxtls_stm32wb_pka_wr(NOXTLS_STM32WB_PKA_CR, 0U);
    noxtls_stm32wb_unlock(NOXTLS_STM32WB_RES_PKA);
}

/**
 * @brief Start an operation and wait for it to end.
 * @internal
 *
 * @param[in] mode PKA operating mode.
 *
 * @return NOXTLS_RETURN_SUCCESS, or NOXTLS_RETURN_FAILED on timeout, RAM error or address error.
 */
static noxtls_return_t noxtls_stm32wb_pka_run(uint32_t mode)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint32_t cr;
    uint32_t sr;
    uint32_t poll;
    uint32_t done = 0U;

    cr = NOXTLS_STM32WB_PKA_CR_EN | (mode << NOXTLS_STM32WB_PKA_CR_MODE_SHIFT);
    noxtls_stm32wb_pka_wr(NOXTLS_STM32WB_PKA_CR, cr);
    noxtls_stm32wb_pka_wr(NOXTLS_STM32WB_PKA_CR, cr | NOXTLS_STM32WB_PKA_CR_START);
    for (poll = 0U; (poll < NOXTLS_STM32WB_CONFIG_PKA_POLL_LIMIT) && (done == 0U); poll++) {
        sr = noxtls_stm32wb_pka_rd(NOXTLS_STM32WB_PKA_SR);
        if ((sr & (NOXTLS_STM32WB_PKA_SR_RAMERRF | NOXTLS_STM32WB_PKA_SR_ADDRERRF)) != 0U) {
            done = 1U;
        } else if ((sr & NOXTLS_STM32WB_PKA_SR_PROCENDF) != 0U) {
            rc = NOXTLS_RETURN_SUCCESS;
            done = 1U;
        } else {
            /* Still running. */
        }
    }
    if (done == 0U) {
        /* Abort a runaway operation: clearing EN stops it. */
        noxtls_stm32wb_pka_wr(NOXTLS_STM32WB_PKA_CR, 0U);
        noxtls_stm32wb_pka_wr(NOXTLS_STM32WB_PKA_CR, NOXTLS_STM32WB_PKA_CR_EN);
    }
    noxtls_stm32wb_pka_wr(NOXTLS_STM32WB_PKA_CLRFR, NOXTLS_STM32WB_PKA_CLRFR_ALL);
    return rc;
}

uint32_t noxtls_stm32wb_pka_is_p256(const uint8_t *p, const uint8_t *a, const uint8_t *b, const uint8_t *n)
{
    uint32_t is = 0U;

    if ((p != NULL) && (a != NULL) && (b != NULL) && (n != NULL) &&
        (noxtls_ct_memcmp(p, s_noxtls_stm32wb_p256_p, NOXTLS_STM32WB_P256_BYTES) == 0) &&
        (noxtls_ct_memcmp(a, s_noxtls_stm32wb_p256_a, NOXTLS_STM32WB_P256_BYTES) == 0) &&
        (noxtls_ct_memcmp(b, s_noxtls_stm32wb_p256_b, NOXTLS_STM32WB_P256_BYTES) == 0) &&
        (noxtls_ct_memcmp(n, s_noxtls_stm32wb_p256_n, NOXTLS_STM32WB_P256_BYTES) == 0)) {
        is = 1U;
    }
    return is;
}

/**
 * @brief Load the point-check operands and run the operation (PKA already open).
 * @internal
 *
 * @param[in] x Point X.
 * @param[in] y Point Y.
 *
 * @return SUCCESS (on curve), BAD_DATA (off curve) or FAILED.
 */
static noxtls_return_t noxtls_stm32wb_pka_check_locked(const uint8_t *x, const uint8_t *y)
{
    noxtls_return_t rc;

    noxtls_stm32wb_pka_wr(NOXTLS_STM32WB_PKA_CHK_MOD_BITS, NOXTLS_STM32WB_P256_BITS);
    noxtls_stm32wb_pka_wr(NOXTLS_STM32WB_PKA_CHK_A_SIGN, NOXTLS_STM32WB_PKA_SIGN_NEG);
    noxtls_stm32wb_pka_put_small(NOXTLS_STM32WB_PKA_CHK_A, NOXTLS_STM32WB_P256_A_ABS, NOXTLS_STM32WB_P256_WORDS);
    noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_CHK_B, s_noxtls_stm32wb_p256_b, NOXTLS_STM32WB_P256_BYTES);
    noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_CHK_P, s_noxtls_stm32wb_p256_p, NOXTLS_STM32WB_P256_BYTES);
    noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_CHK_X, x, NOXTLS_STM32WB_P256_BYTES);
    noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_CHK_Y, y, NOXTLS_STM32WB_P256_BYTES);
    rc = noxtls_stm32wb_pka_run(NOXTLS_STM32WB_PKA_MODE_POINT_CHECK);
    if ((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_stm32wb_pka_rd(NOXTLS_STM32WB_PKA_CHK_RESULT) != 0U)) {
        rc = NOXTLS_RETURN_BAD_DATA;
    }
    return rc;
}

noxtls_return_t noxtls_stm32wb_pka_p256_check(const uint8_t *x, const uint8_t *y)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;

    if ((x != NULL) && (y != NULL) && (noxtls_stm32wb_pka_open() == NOXTLS_RETURN_SUCCESS)) {
        rc = noxtls_stm32wb_pka_check_locked(x, y);
        noxtls_stm32wb_pka_close();
    }
    return noxtls_stm32wb_pka_account(rc);
}

noxtls_return_t noxtls_stm32wb_pka_p256_mul(const uint8_t *k, const uint8_t *px, const uint8_t *py,
                                            uint8_t *rx, uint8_t *ry)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    uint32_t k_bits = 0U;

    if ((k != NULL) && (px != NULL) && (py != NULL) && (rx != NULL) && (ry != NULL)) {
        k_bits = noxtls_stm32wb_pka_bitlen(k, NOXTLS_STM32WB_P256_BYTES);
    }
    if ((k_bits != 0U) && (noxtls_stm32wb_pka_open() == NOXTLS_RETURN_SUCCESS)) {
        noxtls_stm32wb_pka_wr(NOXTLS_STM32WB_PKA_MUL_EXP_BITS, k_bits);
        noxtls_stm32wb_pka_wr(NOXTLS_STM32WB_PKA_MUL_OP_BITS, NOXTLS_STM32WB_P256_BITS);
        noxtls_stm32wb_pka_wr(NOXTLS_STM32WB_PKA_MUL_A_SIGN, NOXTLS_STM32WB_PKA_SIGN_NEG);
        noxtls_stm32wb_pka_put_small(NOXTLS_STM32WB_PKA_MUL_A, NOXTLS_STM32WB_P256_A_ABS, NOXTLS_STM32WB_P256_WORDS);
        noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_MUL_P, s_noxtls_stm32wb_p256_p, NOXTLS_STM32WB_P256_BYTES);
        noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_MUL_K, k, NOXTLS_STM32WB_P256_BYTES);
        noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_MUL_X, px, NOXTLS_STM32WB_P256_BYTES);
        noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_MUL_Y, py, NOXTLS_STM32WB_P256_BYTES);
        rc = noxtls_stm32wb_pka_run(NOXTLS_STM32WB_PKA_MODE_ECC_MUL);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_stm32wb_pka_get(NOXTLS_STM32WB_PKA_MUL_X, rx, NOXTLS_STM32WB_P256_BYTES);
            noxtls_stm32wb_pka_get(NOXTLS_STM32WB_PKA_MUL_Y, ry, NOXTLS_STM32WB_P256_BYTES);
            if ((noxtls_stm32wb_pka_is_zero(rx, NOXTLS_STM32WB_P256_BYTES) != 0U) &&
                (noxtls_stm32wb_pka_is_zero(ry, NOXTLS_STM32WB_P256_BYTES) != 0U)) {
                /* Point at infinity: leave it to the portable implementation. */
                rc = NOXTLS_RETURN_NOT_SUPPORTED;
            }
#if NOXTLS_STM32WB_CONFIG_PKA_CHECK_RESULT
            else {
                rc = noxtls_stm32wb_pka_check_locked(rx, ry);
                if (rc == NOXTLS_RETURN_BAD_DATA) {
                    s_noxtls_stm32wb_pka_stats.check_failures++;
                    rc = NOXTLS_RETURN_FAILED;
                }
            }
#endif
        }
        noxtls_stm32wb_pka_close();
        if (rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_secure_zero(rx, NOXTLS_STM32WB_P256_BYTES);
            noxtls_secure_zero(ry, NOXTLS_STM32WB_P256_BYTES);
        }
    }
    return noxtls_stm32wb_pka_account(rc);
}

noxtls_return_t noxtls_stm32wb_pka_p256_sign(const uint8_t *d, const uint8_t *k, const uint8_t *e,
                                             uint8_t *r, uint8_t *s)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;

    if ((d != NULL) && (k != NULL) && (e != NULL) && (r != NULL) && (s != NULL) &&
        (noxtls_stm32wb_pka_open() == NOXTLS_RETURN_SUCCESS)) {
        noxtls_stm32wb_pka_wr(NOXTLS_STM32WB_PKA_SIGN_N_BITS, NOXTLS_STM32WB_P256_BITS);
        noxtls_stm32wb_pka_wr(NOXTLS_STM32WB_PKA_SIGN_P_BITS, NOXTLS_STM32WB_P256_BITS);
        noxtls_stm32wb_pka_wr(NOXTLS_STM32WB_PKA_SIGN_A_SIGN, NOXTLS_STM32WB_PKA_SIGN_NEG);
        noxtls_stm32wb_pka_put_small(NOXTLS_STM32WB_PKA_SIGN_A, NOXTLS_STM32WB_P256_A_ABS, NOXTLS_STM32WB_P256_WORDS);
        noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_SIGN_P, s_noxtls_stm32wb_p256_p, NOXTLS_STM32WB_P256_BYTES);
        noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_SIGN_K, k, NOXTLS_STM32WB_P256_BYTES);
        noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_SIGN_GX, s_noxtls_stm32wb_p256_gx, NOXTLS_STM32WB_P256_BYTES);
        noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_SIGN_GY, s_noxtls_stm32wb_p256_gy, NOXTLS_STM32WB_P256_BYTES);
        noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_SIGN_E, e, NOXTLS_STM32WB_P256_BYTES);
        noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_SIGN_D, d, NOXTLS_STM32WB_P256_BYTES);
        noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_SIGN_N, s_noxtls_stm32wb_p256_n, NOXTLS_STM32WB_P256_BYTES);
        rc = noxtls_stm32wb_pka_run(NOXTLS_STM32WB_PKA_MODE_ECDSA_SIGN);
        if ((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_stm32wb_pka_rd(NOXTLS_STM32WB_PKA_SIGN_ERROR) != 0U)) {
            /* Operation error (for example r = 0 or s = 0): a new nonce is needed. */
            rc = NOXTLS_RETURN_FAILED;
        }
        if (rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_stm32wb_pka_get(NOXTLS_STM32WB_PKA_SIGN_R, r, NOXTLS_STM32WB_P256_BYTES);
            noxtls_stm32wb_pka_get(NOXTLS_STM32WB_PKA_SIGN_S, s, NOXTLS_STM32WB_P256_BYTES);
            if ((noxtls_stm32wb_pka_is_zero(r, NOXTLS_STM32WB_P256_BYTES) != 0U) ||
                (noxtls_stm32wb_pka_is_zero(s, NOXTLS_STM32WB_P256_BYTES) != 0U)) {
                rc = NOXTLS_RETURN_FAILED;
            }
        }
        noxtls_stm32wb_pka_close();
        if (rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_secure_zero(r, NOXTLS_STM32WB_P256_BYTES);
            noxtls_secure_zero(s, NOXTLS_STM32WB_P256_BYTES);
        }
    }
    return noxtls_stm32wb_pka_account(rc);
}

noxtls_return_t noxtls_stm32wb_pka_p256_verify(const uint8_t *qx, const uint8_t *qy, const uint8_t *e,
                                               const uint8_t *r, const uint8_t *s)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;

    if ((qx != NULL) && (qy != NULL) && (e != NULL) && (r != NULL) && (s != NULL) &&
        (noxtls_stm32wb_pka_open() == NOXTLS_RETURN_SUCCESS)) {
        rc = noxtls_stm32wb_pka_check_locked(qx, qy);
        if (rc == NOXTLS_RETURN_BAD_DATA) {
            /* A key off the curve is not an invalid signature: let software decide. */
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
        } else if (rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_stm32wb_pka_wr(NOXTLS_STM32WB_PKA_VER_N_BITS, NOXTLS_STM32WB_P256_BITS);
            noxtls_stm32wb_pka_wr(NOXTLS_STM32WB_PKA_VER_P_BITS, NOXTLS_STM32WB_P256_BITS);
            noxtls_stm32wb_pka_wr(NOXTLS_STM32WB_PKA_VER_A_SIGN, NOXTLS_STM32WB_PKA_SIGN_NEG);
            noxtls_stm32wb_pka_put_small(NOXTLS_STM32WB_PKA_VER_A, NOXTLS_STM32WB_P256_A_ABS,
                                         NOXTLS_STM32WB_P256_WORDS);
            noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_VER_P, s_noxtls_stm32wb_p256_p, NOXTLS_STM32WB_P256_BYTES);
            noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_VER_GX, s_noxtls_stm32wb_p256_gx, NOXTLS_STM32WB_P256_BYTES);
            noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_VER_GY, s_noxtls_stm32wb_p256_gy, NOXTLS_STM32WB_P256_BYTES);
            noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_VER_QX, qx, NOXTLS_STM32WB_P256_BYTES);
            noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_VER_QY, qy, NOXTLS_STM32WB_P256_BYTES);
            noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_VER_R, r, NOXTLS_STM32WB_P256_BYTES);
            noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_VER_S, s, NOXTLS_STM32WB_P256_BYTES);
            noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_VER_E, e, NOXTLS_STM32WB_P256_BYTES);
            noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_VER_N, s_noxtls_stm32wb_p256_n, NOXTLS_STM32WB_P256_BYTES);
            rc = noxtls_stm32wb_pka_run(NOXTLS_STM32WB_PKA_MODE_ECDSA_VERIFY);
            if ((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_stm32wb_pka_rd(NOXTLS_STM32WB_PKA_VER_RESULT) != 0U)) {
                rc = NOXTLS_RETURN_BAD_DATA;
            }
        } else {
            /* Hardware failure while checking the key. */
        }
        noxtls_stm32wb_pka_close();
    }
    return noxtls_stm32wb_pka_account(rc);
}

/**
 * @brief Whether big-endian @p a is smaller than @p b (equal length).
 * @internal
 *
 * @param[in] a   First value.
 * @param[in] b   Second value.
 * @param[in] len Bytes.
 *
 * @return Non-zero when a < b.
 */
static uint32_t noxtls_stm32wb_pka_less(const uint8_t *a, const uint8_t *b, uint32_t len)
{
    uint32_t i = 0U;

    while ((i < len) && (a[i] == b[i])) {
        i++;
    }
    return ((i < len) && (a[i] < b[i])) ? 1U : 0U;
}

noxtls_return_t noxtls_stm32wb_pka_modexp(uint8_t *out, const uint8_t *base, const uint8_t *exp, uint32_t exp_len,
                                          const uint8_t *mod, uint32_t mod_len)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    uint32_t z = 0U;
    uint32_t e = 0U;
    uint32_t eff;
    uint32_t eff_exp;
    uint32_t ok = 0U;

    if ((out != NULL) && (base != NULL) && (exp != NULL) && (mod != NULL) &&
        (mod_len >= NOXTLS_STM32WB_CONFIG_PKA_MODEXP_MIN_BYTES) &&
        (mod_len <= NOXTLS_STM32WB_CONFIG_PKA_MODEXP_MAX_BYTES) &&
        (exp_len != 0U) && (exp_len <= NOXTLS_STM32WB_CONFIG_PKA_MODEXP_MAX_BYTES) &&
        ((mod[mod_len - 1U] & 1U) != 0U) && (noxtls_stm32wb_pka_less(base, mod, mod_len) != 0U)) {
        while (mod[z] == 0U) {
            z++;
        }
        while ((e < exp_len) && (exp[e] == 0U)) {
            e++;
        }
        eff = mod_len - z;
        eff_exp = exp_len - e;
        /* Short moduli and a zero exponent are left to software. */
        if ((eff >= NOXTLS_STM32WB_CONFIG_PKA_MODEXP_MIN_BYTES) && (eff_exp != 0U)) {
            ok = 1U;
        }
    }
    if ((ok != 0U) && (noxtls_stm32wb_pka_open() == NOXTLS_RETURN_SUCCESS)) {
        eff = mod_len - z;
        eff_exp = exp_len - e;
        noxtls_stm32wb_pka_wr(NOXTLS_STM32WB_PKA_MODEXP_EXP_BITS, eff_exp * NOXTLS_STM32WB_PKA_BYTE_BITS);
        noxtls_stm32wb_pka_wr(NOXTLS_STM32WB_PKA_MODEXP_OP_BITS, eff * NOXTLS_STM32WB_PKA_BYTE_BITS);
        noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_MODEXP_BASE, &base[z], eff);
        noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_MODEXP_EXP, &exp[e], eff_exp);
        noxtls_stm32wb_pka_put(NOXTLS_STM32WB_PKA_MODEXP_MOD, &mod[z], eff);
        rc = noxtls_stm32wb_pka_run(NOXTLS_STM32WB_PKA_MODE_MODEXP);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_secure_zero(out, z);
            noxtls_stm32wb_pka_get(NOXTLS_STM32WB_PKA_MODEXP_BASE, &out[z], eff);
        }
        noxtls_stm32wb_pka_close();
    }
    return noxtls_stm32wb_pka_account(rc);
}
