/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    test_wb_rng.c
* Summary: RNG entropy source tests (locking, health checks, error recovery)
*****************************************************************************/

/**
 * @file test_wb_rng.c
 * @brief Tests of noxtls_stm32wb_rng_fill().
 * @ingroup noxtls_stm32wb_ut
 */

#include "ut_wb_test.h"

#define R_SEIS (1U)
#define R_CEIS (1U)

REGISTER_TEST(test_rng_fill_little_endian_words_and_lock)
{
    uint8_t out[10];
    const noxtls_stm32wb_rng_health_t *h = noxtls_stm32wb_rng_health();
    uint32_t words0;

    UT_SETUP();
    words0 = h->words;
    ut_wb_rng_script_counter(8U);
    UTNOX_EQUALS(noxtls_stm32wb_rng_fill(out, sizeof(out)), NOXTLS_RETURN_SUCCESS);
    /* Word 0 = 0x01020304 is delivered least significant byte first; the last word is truncated. */
    UTNOX_EQUALS(out[0], 0x04U);
    UTNOX_EQUALS(out[3], 0x01U);
    UTNOX_EQUALS(out[4], 0x15U);
    UTNOX_EQUALS(out[8], 0x26U);
    UTNOX_EQUALS(out[9], 0x25U);
    UTNOX_EQUALS(h->words - words0, 3U);
    /* RNG semaphore taken for the request and released after it. */
    UTNOX_EQUALS(g_wb.sem_takes, 1U);
    UTNOX_EQUALS(g_wb.sem_releases, 1U);
    /* The RNG was off: it was enabled with clock-error detection and no interrupt, then switched off again. */
    UTNOX_EQUALS(g_wb.rng_cr_writes, 2U);
    UTNOX_EQUALS(g_wb.rng_cr, 0U);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_rng_restores_the_control_register)
{
    uint8_t out[4];

    UT_SETUP();
    /* The application had RNGEN, IE and CED set: CPU1 forces IE and CED off for the request, then puts them back. */
    g_wb.rng_cr = (1U << 2) | (1U << 3) | (1U << 5);
    ut_wb_rng_script_counter(2U);
    UTNOX_EQUALS(noxtls_stm32wb_rng_fill(out, sizeof(out)), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_wb.rng_cr_writes, 2U);
    UTNOX_EQUALS(g_wb.rng_cr, (1U << 2) | (1U << 3) | (1U << 5));
    /* Already exactly RNGEN: no write at all. */
    UT_SETUP();
    g_wb.rng_cr = (1U << 2);
    ut_wb_rng_script_counter(2U);
    UTNOX_EQUALS(noxtls_stm32wb_rng_fill(out, sizeof(out)), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_wb.rng_cr_writes, 0U);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_rng_parameters)
{
    uint8_t out[4] = { 1, 2, 3, 4 };
    const noxtls_stm32wb_rng_health_t *h = noxtls_stm32wb_rng_health();
    uint32_t req0;

    UT_SETUP();
    UTNOX_EQUALS(noxtls_stm32wb_rng_fill(NULL, 4U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_stm32wb_rng_fill(NULL, 0U), NOXTLS_RETURN_NULL);
    req0 = h->requests;
    UTNOX_EQUALS(noxtls_stm32wb_rng_fill(out, 0U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(h->requests, req0);
    UTNOX_EQUALS(out[0], 1U);
    UTNOX_EQUALS(g_wb.rng_cr_writes, 0U);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_rng_busy_when_cpu2_owns_the_semaphore)
{
    uint8_t out[4] = { 9, 9, 9, 9 };
    const noxtls_stm32wb_rng_health_t *h = noxtls_stm32wb_rng_health();
    uint32_t busy0;

    UT_SETUP();
    busy0 = h->busy;
    ut_wb_rng_script_counter(4U);
    ut_wb_cpu2_take(NOXTLS_STM32WB_CONFIG_HSEM_ID_RNG);
    UTNOX_EQUALS(noxtls_stm32wb_rng_fill(out, sizeof(out)), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(h->busy - busy0, 1U);
    UTNOX_EQUALS(g_wb.rng_cr_writes, 0U);
    UTNOX_EQUALS(g_wb.rng_dr_reads, 0U);
    UTNOX_EQUALS(out[0], 9U);
    g_wb.sem_owner[NOXTLS_STM32WB_CONFIG_HSEM_ID_RNG] = 0U;
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_rng_seed_error_recovery)
{
    uint8_t out[8];
    const noxtls_stm32wb_rng_health_t *h = noxtls_stm32wb_rng_health();
    uint32_t seed0;

    UT_SETUP();
    seed0 = h->seed_errors;
    ut_wb_rng_script_counter(40U);
    g_wb.rng_seis = R_SEIS;
    g_wb.rng_secs = 1U;
    /* SECS clears after the 12 words the recovery reads and discards (RM0434 RNG seed error recovery). */
    g_wb.rng_secs_clear_after = NOXTLS_STM32WB_CONFIG_RNG_RECOVERY_WORDS;
    UTNOX_EQUALS(noxtls_stm32wb_rng_fill(out, sizeof(out)), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(h->seed_errors - seed0, 1U);
    UTNOX_EQUALS(g_wb.rng_seis, 0U);
    UTNOX_EQUALS(g_wb.rng_secs, 0U);
    /* 12 discarded + 2 delivered. */
    UTNOX_EQUALS(g_wb.rng_dr_reads, 14U);
    /* The delivered words are the ones after the discarded block. */
    UTNOX_EQUALS(out[0], (uint8_t)(0x01020304U + (12U * 0x11111111U)));
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_rng_seed_error_that_does_not_clear_fails)
{
    uint8_t out[8] = { 0 };
    const noxtls_stm32wb_rng_health_t *h = noxtls_stm32wb_rng_health();
    uint32_t fail0;

    UT_SETUP();
    fail0 = h->failures;
    ut_wb_rng_script_counter(40U);
    g_wb.rng_seis = R_SEIS;
    g_wb.rng_secs = 1U;      /* SECS stays set: the entropy source is unhealthy */
    UTNOX_EQUALS(noxtls_stm32wb_rng_fill(out, sizeof(out)), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(h->failures - fail0, 1U);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_rng_seed_error_recovery_times_out_without_data)
{
    uint8_t out[8];

    UT_SETUP();
    ut_wb_rng_script_counter(5U);     /* fewer words than the recovery must discard */
    g_wb.rng_seis = R_SEIS;
    g_wb.rng_secs = 1U;
    g_wb.rng_secs_clear_after = 1U;
    UTNOX_EQUALS(noxtls_stm32wb_rng_fill(out, sizeof(out)), NOXTLS_RETURN_FAILED);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_rng_repeated_seed_errors_within_budget_recover)
{
    uint8_t out[4];
    const noxtls_stm32wb_rng_health_t *h = noxtls_stm32wb_rng_health();
    uint32_t seed0;

    UT_SETUP();
    seed0 = h->seed_errors;
    ut_wb_rng_script_counter(UT_WB_RNG_WORDS);
    /* SEIS comes back twice after being cleared, SECS never sticks: three detections, three recoveries. */
    g_wb.rng_seis = R_SEIS;
    g_wb.rng_seis_rearm = NOXTLS_STM32WB_CONFIG_RNG_MAX_RECOVERIES - 1U;
    UTNOX_EQUALS(noxtls_stm32wb_rng_fill(out, sizeof(out)), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(h->seed_errors - seed0, NOXTLS_STM32WB_CONFIG_RNG_MAX_RECOVERIES);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_rng_seed_error_budget_exhausted_fails)
{
    uint8_t out[4] = { 7, 7, 7, 7 };
    const noxtls_stm32wb_rng_health_t *h = noxtls_stm32wb_rng_health();
    uint32_t fail0;

    UT_SETUP();
    fail0 = h->failures;
    ut_wb_rng_script_counter(UT_WB_RNG_WORDS);
    g_wb.rng_seis = R_SEIS;
    g_wb.rng_seis_rearm = NOXTLS_STM32WB_CONFIG_RNG_MAX_RECOVERIES + 4U;
    UTNOX_EQUALS(noxtls_stm32wb_rng_fill(out, sizeof(out)), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(h->failures - fail0, 1U);
    UTNOX_EQUALS(out[0], 0U);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_rng_clock_error_discards_pending_word_and_continues)
{
    uint8_t out[4];
    const noxtls_stm32wb_rng_health_t *h = noxtls_stm32wb_rng_health();
    uint32_t clk0;

    UT_SETUP();
    clk0 = h->clock_errors;
    ut_wb_rng_script_counter(8U);
    g_wb.rng_ceis = R_CEIS;      /* CECS clear: the clock recovered */
    UTNOX_EQUALS(noxtls_stm32wb_rng_fill(out, sizeof(out)), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(h->clock_errors - clk0, 1U);
    UTNOX_EQUALS(g_wb.rng_ceis, 0U);
    /* The word that was ready when the fault was seen is discarded, the next one delivered. */
    UTNOX_EQUALS(g_wb.rng_dr_reads, 2U);
    UTNOX_EQUALS(out[0], 0x15U);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_rng_repeated_clock_errors_exceed_the_budget)
{
    uint8_t out[4] = { 5, 5, 5, 5 };
    const noxtls_stm32wb_rng_health_t *h = noxtls_stm32wb_rng_health();
    uint32_t clk0;

    UT_SETUP();
    clk0 = h->clock_errors;
    ut_wb_rng_script_counter(UT_WB_RNG_WORDS);
    /* The clock fault is flagged again after every clear although CECS reads low. */
    g_wb.rng_ceis = R_CEIS;
    g_wb.rng_ceis_rearm = NOXTLS_STM32WB_CONFIG_RNG_MAX_RECOVERIES + 4U;
    UTNOX_EQUALS(noxtls_stm32wb_rng_fill(out, sizeof(out)), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(h->clock_errors - clk0, NOXTLS_STM32WB_CONFIG_RNG_MAX_RECOVERIES + 1U);
    UTNOX_EQUALS(out[0], 0U);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_rng_clock_error_without_pending_word_keeps_polling)
{
    uint8_t out[4];

    UT_SETUP();
    ut_wb_rng_script_counter(4U);
    g_wb.rng_ceis = R_CEIS;
    g_wb.rng_drdy_block = 1U;
    /* No word ready (DRDY forced low): the clock error is cleared, then the poll limit ends the request. */
    UTNOX_EQUALS(noxtls_stm32wb_rng_fill(out, sizeof(out)), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(g_wb.rng_ceis, 0U);
    UTNOX_EQUALS(g_wb.rng_dr_reads, 0U);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_rng_persistent_clock_error_fails)
{
    uint8_t out[4] = { 1, 1, 1, 1 };
    const noxtls_stm32wb_rng_health_t *h = noxtls_stm32wb_rng_health();
    uint32_t fail0;

    UT_SETUP();
    fail0 = h->failures;
    ut_wb_rng_script_counter(8U);
    g_wb.rng_ceis = R_CEIS;
    g_wb.rng_cecs = 1U;          /* the clock is still too slow after clearing the flag */
    UTNOX_EQUALS(noxtls_stm32wb_rng_fill(out, sizeof(out)), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(h->failures - fail0, 1U);
    /* A failed request leaves no entropy in the caller's buffer. */
    UTNOX_EQUALS(out[0], 0U);
    UTNOX_EQUALS(out[3], 0U);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_rng_times_out_without_data)
{
    uint8_t out[4];

    UT_SETUP();
    UTNOX_EQUALS(noxtls_stm32wb_rng_fill(out, sizeof(out)), NOXTLS_RETURN_FAILED);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_rng_continuous_test_discards_one_repeat)
{
    static const uint32_t words[] = { 0x11111111U, 0x11111111U, 0x22222222U, 0x33333333U };
    uint8_t out[12];
    const noxtls_stm32wb_rng_health_t *h = noxtls_stm32wb_rng_health();
    uint32_t rep0;

    UT_SETUP();
    rep0 = h->repeat_faults;
    ut_wb_rng_script(words, 4U);
    UTNOX_EQUALS(noxtls_stm32wb_rng_fill(out, sizeof(out)), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(h->repeat_faults - rep0, 1U);
    UTNOX_EQUALS(out[0], 0x11U);
    UTNOX_EQUALS(out[4], 0x22U);
    UTNOX_EQUALS(out[8], 0x33U);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_rng_continuous_test_spans_requests)
{
    static const uint32_t first[] = { 0xAAAAAAAAU };
    static const uint32_t second[] = { 0xAAAAAAAAU, 0xBBBBBBBBU };
    uint8_t out[4];

    UT_SETUP();
    ut_wb_rng_script(first, 1U);
    UTNOX_EQUALS(noxtls_stm32wb_rng_fill(out, sizeof(out)), NOXTLS_RETURN_SUCCESS);
    /* The previous word is remembered: a second request that starts with the same word skips it. */
    ut_wb_rng_script(second, 2U);
    UTNOX_EQUALS(noxtls_stm32wb_rng_fill(out, sizeof(out)), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(out[0], 0xBBU);
    noxtls_stm32wb_rng_reset_history();
    ut_wb_rng_script(first, 1U);
    UTNOX_EQUALS(noxtls_stm32wb_rng_fill(out, sizeof(out)), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(out[0], 0xAAU);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_rng_stuck_source_fails_the_request)
{
    static const uint32_t stuck[] = { 0x5A5A5A5AU, 0x5A5A5A5AU, 0x5A5A5A5AU, 0x5A5A5A5AU, 0x5A5A5A5AU, 0x5A5A5A5AU };
    uint8_t out[8] = { 0 };
    const noxtls_stm32wb_rng_health_t *h = noxtls_stm32wb_rng_health();
    uint32_t fail0;

    UT_SETUP();
    fail0 = h->failures;
    ut_wb_rng_script(stuck, 6U);
    UTNOX_EQUALS(noxtls_stm32wb_rng_fill(out, sizeof(out)), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(h->failures - fail0, 1U);
    UTNOX_EQUALS(out[0], 0U);
    UTNOX_EQUALS(out[4], 0U);
    UT_CLEAN();
    return 0;
}
