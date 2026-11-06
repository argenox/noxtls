/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    test_wb_hsem.c
* Summary: HSEM ownership layer tests
*****************************************************************************/

/**
 * @file test_wb_hsem.c
 * @brief Positive and negative tests of noxtls_stm32wb_lock() / noxtls_stm32wb_unlock().
 * @ingroup noxtls_stm32wb_ut
 */

#include "ut_wb_test.h"

REGISTER_TEST(test_hsem_take_release_protocol)
{
    const noxtls_stm32wb_lock_stats_t *st = noxtls_stm32wb_lock_stats();
    uint32_t acquired0;

    UT_SETUP();
    acquired0 = st->acquired;
    UTNOX_EQUALS(noxtls_stm32wb_lock(NOXTLS_STM32WB_RES_PKA), NOXTLS_RETURN_SUCCESS);
    /* One-step lock read of semaphore 1 by CPU1 (RM0434 HSEM chapter). */
    UTNOX_EQUALS(g_wb.sem_owner[NOXTLS_STM32WB_CONFIG_HSEM_ID_PKA], 4U);
    UTNOX_EQUALS(g_wb.sem_takes, 1U);
    UTNOX_EQUALS(noxtls_stm32wb_lock(NOXTLS_STM32WB_RES_RNG), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_wb.sem_owner[NOXTLS_STM32WB_CONFIG_HSEM_ID_RNG], 4U);
    noxtls_stm32wb_unlock(NOXTLS_STM32WB_RES_PKA);
    UTNOX_EQUALS(g_wb.sem_owner[NOXTLS_STM32WB_CONFIG_HSEM_ID_PKA], 0U);
    UTNOX_EQUALS(g_wb.sem_last_id, NOXTLS_STM32WB_CONFIG_HSEM_ID_PKA);
    /* Release writes COREID (CPU1 = 4) in bits 11:8 and PROCID 0. */
    UTNOX_EQUALS(g_wb.sem_last_release, 0x400U);
    noxtls_stm32wb_unlock(NOXTLS_STM32WB_RES_RNG);
    UTNOX_EQUALS(g_wb.sem_releases, 2U);
    UTNOX_EQUALS(st->acquired - acquired0, 2U);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_hsem_aes1_has_no_semaphore)
{
    UT_SETUP();
    UTNOX_EQUALS(noxtls_stm32wb_lock(NOXTLS_STM32WB_RES_AES1), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_wb.sem_takes, 0U);
    noxtls_stm32wb_unlock(NOXTLS_STM32WB_RES_AES1);
    UTNOX_EQUALS(g_wb.sem_releases, 0U);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_hsem_nested_use_is_busy)
{
    const noxtls_stm32wb_lock_stats_t *st = noxtls_stm32wb_lock_stats();
    uint32_t busy0;

    UT_SETUP();
    busy0 = st->sw_busy;
    UTNOX_EQUALS(noxtls_stm32wb_lock(NOXTLS_STM32WB_RES_AES1), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_stm32wb_lock(NOXTLS_STM32WB_RES_AES1), NOXTLS_RETURN_TIMEOUT);
    UTNOX_EQUALS(st->sw_busy - busy0, 1U);
    noxtls_stm32wb_unlock(NOXTLS_STM32WB_RES_AES1);
    UTNOX_EQUALS(noxtls_stm32wb_lock(NOXTLS_STM32WB_RES_AES1), NOXTLS_RETURN_SUCCESS);
    noxtls_stm32wb_unlock(NOXTLS_STM32WB_RES_AES1);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_hsem_cpu2_owner_blocks_cpu1)
{
    const noxtls_stm32wb_lock_stats_t *st = noxtls_stm32wb_lock_stats();
    uint32_t busy0;

    UT_SETUP();
    busy0 = st->hsem_busy;
    ut_wb_cpu2_take(NOXTLS_STM32WB_CONFIG_HSEM_ID_PKA);
    UTNOX_EQUALS(noxtls_stm32wb_lock(NOXTLS_STM32WB_RES_PKA), NOXTLS_RETURN_TIMEOUT);
    UTNOX_EQUALS(st->hsem_busy - busy0, 1U);
    /* CPU1 never wrote the semaphore it failed to take. */
    UTNOX_EQUALS(g_wb.sem_owner[NOXTLS_STM32WB_CONFIG_HSEM_ID_PKA], 8U);
    UTNOX_EQUALS(g_wb.sem_releases, 0U);
    /* Unlocking something not held does not release CPU2's semaphore. */
    noxtls_stm32wb_unlock(NOXTLS_STM32WB_RES_PKA);
    UTNOX_EQUALS(g_wb.sem_owner[NOXTLS_STM32WB_CONFIG_HSEM_ID_PKA], 8U);
    g_wb.sem_owner[NOXTLS_STM32WB_CONFIG_HSEM_ID_PKA] = 0U;
    UTNOX_EQUALS(noxtls_stm32wb_lock(NOXTLS_STM32WB_RES_PKA), NOXTLS_RETURN_SUCCESS);
    noxtls_stm32wb_unlock(NOXTLS_STM32WB_RES_PKA);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_hsem_invalid_resource)
{
    UT_SETUP();
    UTNOX_EQUALS(noxtls_stm32wb_lock(NOXTLS_STM32WB_RES_COUNT), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_stm32wb_lock(UINT32_MAX), NOXTLS_RETURN_INVALID_PARAM);
    noxtls_stm32wb_unlock(NOXTLS_STM32WB_RES_COUNT);
    noxtls_stm32wb_unlock(UINT32_MAX);
    /* Releasing a resource that was never taken does not touch the hardware. */
    noxtls_stm32wb_unlock(NOXTLS_STM32WB_RES_RNG);
    UTNOX_EQUALS(g_wb.sem_releases, 0U);
    UT_CLEAN();
    return 0;
}
