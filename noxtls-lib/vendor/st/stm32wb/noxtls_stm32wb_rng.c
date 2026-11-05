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
* File:    noxtls_stm32wb_rng.c
* Summary: STM32WB5x true random number generator entropy source
*
*****************************************************************************/

/**
 * @file noxtls_stm32wb_rng.c
 * @brief RNG driver with semaphore ownership and health checks (STM32WB5x).
 * @ingroup noxtls_stm32wb
 */

#include <stddef.h>

#include "noxtls_stm32wb_rng.h"

#include "common/noxtls_ct.h"
#include "noxtls_stm32wb_bus.h"
#include "noxtls_stm32wb_config.h"
#include "noxtls_stm32wb_hsem.h"
#include "noxtls_stm32wb_regs.h"

/** @brief Bytes per RNG data word. */
#define NOXTLS_STM32WB_RNG_WORD_BYTES   4U
/** @brief Bits per byte. */
#define NOXTLS_STM32WB_RNG_BYTE_BITS    8U
/** @brief Mask of one byte. */
#define NOXTLS_STM32WB_RNG_BYTE_MASK    0xFFU

/** Health counters. */
static noxtls_stm32wb_rng_health_t s_noxtls_stm32wb_rng_health;
/** Previous word of the continuous test. */
static uint32_t s_noxtls_stm32wb_rng_prev;
/** Non-zero when s_noxtls_stm32wb_rng_prev holds a word. */
static uint8_t s_noxtls_stm32wb_rng_prev_valid;
/** Consecutive repeats seen. */
static uint32_t s_noxtls_stm32wb_rng_repeats;

/**
 * @brief Read an RNG register.
 * @internal
 *
 * @param[in] off Register offset.
 *
 * @return Value.
 */
static uint32_t noxtls_stm32wb_rng_rd(uint32_t off)
{
    return noxtls_stm32wb_bus_rd(NOXTLS_STM32WB_CONFIG_RNG_BASE + off);
}

/**
 * @brief Write an RNG register.
 * @internal
 *
 * @param[in] off   Register offset.
 * @param[in] value Value.
 */
static void noxtls_stm32wb_rng_wr(uint32_t off, uint32_t value)
{
    noxtls_stm32wb_bus_wr(NOXTLS_STM32WB_CONFIG_RNG_BASE + off, value);
}

/**
 * @brief Wait for DRDY and read one word (used only to discard words).
 * @internal
 *
 * @param[out] word Word read.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_FAILED on timeout.
 */
static noxtls_return_t noxtls_stm32wb_rng_discard_one(uint32_t *word)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint32_t poll;

    for (poll = 0U; (poll < NOXTLS_STM32WB_CONFIG_RNG_POLL_LIMIT) && (rc != NOXTLS_RETURN_SUCCESS); poll++) {
        if ((noxtls_stm32wb_rng_rd(NOXTLS_STM32WB_RNG_SR) & NOXTLS_STM32WB_RNG_SR_DRDY) != 0U) {
            *word = noxtls_stm32wb_rng_rd(NOXTLS_STM32WB_RNG_DR);
            rc = NOXTLS_RETURN_SUCCESS;
        }
    }
    return rc;
}

/**
 * @brief Seed error recovery (RM0434 RNG chapter): clear SEIS, discard words, require SECS clear.
 * @internal
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_FAILED.
 */
static noxtls_return_t noxtls_stm32wb_rng_recover_seed(void)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t i;
    uint32_t word = 0U;

    /* SEIS is cleared by writing 0; other bits are written as 1 (no effect). */
    noxtls_stm32wb_rng_wr(NOXTLS_STM32WB_RNG_SR, ~NOXTLS_STM32WB_RNG_SR_SEIS);
    for (i = 0U; (i < NOXTLS_STM32WB_CONFIG_RNG_RECOVERY_WORDS) && (rc == NOXTLS_RETURN_SUCCESS); i++) {
        rc = noxtls_stm32wb_rng_discard_one(&word);
    }
    if ((rc == NOXTLS_RETURN_SUCCESS) &&
        ((noxtls_stm32wb_rng_rd(NOXTLS_STM32WB_RNG_SR) & NOXTLS_STM32WB_RNG_SR_SECS) != 0U)) {
        rc = NOXTLS_RETURN_FAILED;
    }
    return rc;
}

/**
 * @brief Continuous test: accept a word unless it repeats its predecessor too often.
 * @internal
 *
 * @param[in]  word     Candidate word.
 * @param[out] accepted Non-zero when the word may be used.
 *
 * @return NOXTLS_RETURN_SUCCESS, or NOXTLS_RETURN_FAILED when the repeat limit is exceeded.
 */
static noxtls_return_t noxtls_stm32wb_rng_continuous(uint32_t word, uint32_t *accepted)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    *accepted = 1U;
    if ((s_noxtls_stm32wb_rng_prev_valid != 0U) && (word == s_noxtls_stm32wb_rng_prev)) {
        s_noxtls_stm32wb_rng_health.repeat_faults++;
        s_noxtls_stm32wb_rng_repeats++;
        *accepted = 0U;
        if (s_noxtls_stm32wb_rng_repeats > NOXTLS_STM32WB_CONFIG_RNG_MAX_REPEATS) {
            rc = NOXTLS_RETURN_FAILED;
        }
    } else {
        s_noxtls_stm32wb_rng_repeats = 0U;
    }
    s_noxtls_stm32wb_rng_prev = word;
    s_noxtls_stm32wb_rng_prev_valid = 1U;
    return rc;
}

/**
 * @brief Produce one healthy word.
 * @internal
 *
 * @param[out] out Word.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_FAILED.
 */
static noxtls_return_t noxtls_stm32wb_rng_word(uint32_t *out)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint32_t active = 1U;
    uint32_t poll = 0U;
    uint32_t recoveries = 0U;
    uint32_t sr;
    uint32_t word;
    uint32_t accepted = 0U;

    while ((active != 0U) && (poll < NOXTLS_STM32WB_CONFIG_RNG_POLL_LIMIT)) {
        poll++;
        sr = noxtls_stm32wb_rng_rd(NOXTLS_STM32WB_RNG_SR);
        if ((sr & (NOXTLS_STM32WB_RNG_SR_SEIS | NOXTLS_STM32WB_RNG_SR_SECS)) != 0U) {
            s_noxtls_stm32wb_rng_health.seed_errors++;
            recoveries++;
            if ((recoveries > NOXTLS_STM32WB_CONFIG_RNG_MAX_RECOVERIES) ||
                (noxtls_stm32wb_rng_recover_seed() != NOXTLS_RETURN_SUCCESS)) {
                active = 0U;
            }
        } else if ((sr & (NOXTLS_STM32WB_RNG_SR_CEIS | NOXTLS_STM32WB_RNG_SR_CECS)) != 0U) {
            s_noxtls_stm32wb_rng_health.clock_errors++;
            recoveries++;
            noxtls_stm32wb_rng_wr(NOXTLS_STM32WB_RNG_SR, ~NOXTLS_STM32WB_RNG_SR_CEIS);
            if ((recoveries > NOXTLS_STM32WB_CONFIG_RNG_MAX_RECOVERIES) ||
                ((noxtls_stm32wb_rng_rd(NOXTLS_STM32WB_RNG_SR) & NOXTLS_STM32WB_RNG_SR_CECS) != 0U)) {
                active = 0U;
            } else if ((sr & NOXTLS_STM32WB_RNG_SR_DRDY) != 0U) {
                /* The pending word was produced under a clock fault: discard it. */
                (void)noxtls_stm32wb_rng_rd(NOXTLS_STM32WB_RNG_DR);
            } else {
                /* Clock recovered; keep polling. */
            }
        } else if ((sr & NOXTLS_STM32WB_RNG_SR_DRDY) != 0U) {
            word = noxtls_stm32wb_rng_rd(NOXTLS_STM32WB_RNG_DR);
            if (noxtls_stm32wb_rng_continuous(word, &accepted) != NOXTLS_RETURN_SUCCESS) {
                active = 0U;
            } else if (accepted != 0U) {
                *out = word;
                rc = NOXTLS_RETURN_SUCCESS;
                active = 0U;
            } else {
                /* Repeated word discarded; ask for the next. */
            }
        } else {
            /* Waiting for data. */
        }
    }
    return rc;
}

noxtls_return_t noxtls_stm32wb_rng_fill(uint8_t *buf, uint32_t len)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t saved_cr;
    uint32_t want_cr;
    uint32_t off = 0U;
    uint32_t word = 0U;
    uint32_t n;
    uint32_t i;

    if (buf == NULL) {
        rc = NOXTLS_RETURN_NULL;
    } else if (len != 0U) {
        s_noxtls_stm32wb_rng_health.requests++;
        if (noxtls_stm32wb_lock(NOXTLS_STM32WB_RES_RNG) != NOXTLS_RETURN_SUCCESS) {
            s_noxtls_stm32wb_rng_health.busy++;
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
        } else {
            saved_cr = noxtls_stm32wb_rng_rd(NOXTLS_STM32WB_RNG_CR);
            /* Enable with clock-error detection on and the interrupt off. */
            want_cr = (saved_cr | NOXTLS_STM32WB_RNG_CR_RNGEN) &
                      ~(NOXTLS_STM32WB_RNG_CR_CED | NOXTLS_STM32WB_RNG_CR_IE);
            noxtls_stm32wb_rng_wr(NOXTLS_STM32WB_RNG_CR, want_cr);
            while ((off < len) && (rc == NOXTLS_RETURN_SUCCESS)) {
                rc = noxtls_stm32wb_rng_word(&word);
                if (rc == NOXTLS_RETURN_SUCCESS) {
                    n = len - off;
                    if (n > NOXTLS_STM32WB_RNG_WORD_BYTES) {
                        n = NOXTLS_STM32WB_RNG_WORD_BYTES;
                    }
                    for (i = 0U; i < n; i++) {
                        buf[off + i] = (uint8_t)((word >> (i * NOXTLS_STM32WB_RNG_BYTE_BITS)) &
                                                 NOXTLS_STM32WB_RNG_BYTE_MASK);
                    }
                    off += n;
                    s_noxtls_stm32wb_rng_health.words++;
                }
            }
            if ((saved_cr & NOXTLS_STM32WB_RNG_CR_RNGEN) == 0U) {
                noxtls_stm32wb_rng_wr(NOXTLS_STM32WB_RNG_CR, saved_cr);
            }
            noxtls_stm32wb_unlock(NOXTLS_STM32WB_RES_RNG);
            if (rc != NOXTLS_RETURN_SUCCESS) {
                s_noxtls_stm32wb_rng_health.failures++;
                noxtls_secure_zero(buf, len);
            }
        }
    } else {
        /* Nothing requested. */
    }
    noxtls_secure_zero(&word, sizeof(word));
    return rc;
}

const noxtls_stm32wb_rng_health_t *noxtls_stm32wb_rng_health(void)
{
    return &s_noxtls_stm32wb_rng_health;
}

void noxtls_stm32wb_rng_reset_history(void)
{
    s_noxtls_stm32wb_rng_prev = 0U;
    s_noxtls_stm32wb_rng_prev_valid = 0U;
    s_noxtls_stm32wb_rng_repeats = 0U;
}
