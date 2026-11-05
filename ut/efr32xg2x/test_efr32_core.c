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
* File:    test_efr32_core.c
* Summary: Tests of the register seam, DMA windows and the shared-engine ownership contract
*
*****************************************************************************/

/**
 * @file test_efr32_core.c
 * @brief Register seam, run-time enables, DMA windows, statistics, engine lock
 *        binding (contract section 8), non-blocking AES acquire and bounded SE retry.
 * @ingroup noxtls_efr32_ut
 */

#include <stdint.h>
#include <string.h>

#include "runner.h"
#include "test_assert.h"

#include "ut_efr32_mock.h"

/** Hook that is never called (pair-completeness tests). */
static bool ut_dummy_try(void)
{
    return true;
}

/** Hook that is never called (pair-completeness tests). */
static void ut_dummy_rel(void)
{
}

REGISTER_TEST(test_core_io_and_hw_set)
{
    noxtls_efr32_io_t bad = { NULL, NULL };
    noxtls_efr32_hw_t hw;

    ut_setup();
    UTNOX_EQUALS(noxtls_efr32_io_set(&bad), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_aes_acquire(), NOXTLS_RETURN_SUCCESS);
    /* Replacing the seam while an engine is owned is refused. */
    UTNOX_EQUALS(noxtls_efr32_io_set(NULL), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(noxtls_efr32_hw_set(NULL), NOXTLS_RETURN_FAILED);
    noxtls_efr32_aes_release();
    UTNOX_EQUALS(noxtls_efr32_se_acquire(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_efr32_io_set(NULL), NOXTLS_RETURN_FAILED);
    noxtls_efr32_se_release();
    /* Restoring the memory-mapped default and the build instances works when idle. */
    UTNOX_EQUALS(noxtls_efr32_io_set(NULL), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_efr32_hw_set(NULL), NOXTLS_RETURN_SUCCESS);
    hw.aes = 1U;
    hw.sem = 2U;
    hw.cmu = 3U;
    UTNOX_EQUALS(noxtls_efr32_hw_set(&hw), NOXTLS_RETURN_SUCCESS);
    ut_setup();
    return 0;
}

REGISTER_TEST(test_core_enable_and_ops)
{
    ut_setup();
    UTNOX_EQUALS(noxtls_efr32_is_enabled(NOXTLS_EFR32_UNIT_AES), 1U);
    noxtls_efr32_set_enabled(NOXTLS_EFR32_UNIT_AES, 0U);
    UTNOX_EQUALS(noxtls_efr32_is_enabled(NOXTLS_EFR32_UNIT_AES), 0U);
    UTNOX_EQUALS(noxtls_efr32_is_enabled(NOXTLS_EFR32_UNIT_SE), 1U);
    noxtls_efr32_set_enabled(NOXTLS_EFR32_UNIT_ALL, 0U);
    UTNOX_EQUALS(noxtls_efr32_is_enabled(NOXTLS_EFR32_UNIT_SE), 0U);
    noxtls_efr32_set_enabled(NOXTLS_EFR32_UNIT_ALL, 1U);
    UTNOX_EQUALS(noxtls_efr32_is_enabled(NOXTLS_EFR32_UNIT_SE), 1U);
    UTNOX_EQUALS(noxtls_efr32_op_allowed(NOXTLS_EFR32_OP_SHA256), 1U);
    noxtls_efr32_set_ops_disabled(NOXTLS_EFR32_OP_SHA256 | NOXTLS_EFR32_OP_TRNG);
    UTNOX_EQUALS(noxtls_efr32_op_allowed(NOXTLS_EFR32_OP_SHA256), 0U);
    UTNOX_EQUALS(noxtls_efr32_op_allowed(NOXTLS_EFR32_OP_TRNG), 0U);
    UTNOX_EQUALS(noxtls_efr32_op_allowed(NOXTLS_EFR32_OP_SHA512), 1U);
    noxtls_efr32_set_ops_disabled(0U);
    UTNOX_EQUALS(noxtls_efr32_op_allowed(NOXTLS_EFR32_OP_TRNG), 1U);
    return 0;
}

REGISTER_TEST(test_core_dma_windows)
{
    static uint8_t buf[64];
    uintptr_t base = (uintptr_t)buf;

    ut_setup();
    noxtls_efr32_set_dma_window(base, 64U, base + 16U, 32U, 1U);
    UTNOX_EQUALS(noxtls_efr32_dma_in_ok(buf, 64U), 1U);
    UTNOX_EQUALS(noxtls_efr32_dma_in_ok(buf, 65U), 0U);
    UTNOX_EQUALS(noxtls_efr32_dma_in_ok(&buf[63], 1U), 1U);
    UTNOX_EQUALS(noxtls_efr32_dma_in_ok(&buf[63], 2U), 0U);
    UTNOX_EQUALS(noxtls_efr32_dma_in_ok(NULL, 0U), 0U);
    UTNOX_EQUALS(noxtls_efr32_dma_in_ok(buf, 0U), 1U);
    UTNOX_EQUALS(noxtls_efr32_dma_out_ok(&buf[16], 32U), 1U);
    UTNOX_EQUALS(noxtls_efr32_dma_out_ok(&buf[15], 1U), 0U);
    UTNOX_EQUALS(noxtls_efr32_dma_out_ok(&buf[16], 33U), 0U);
    UTNOX_EQUALS(noxtls_efr32_dma_out_ok(&buf[48], 1U), 0U);
    /* Alignment requirement. */
    noxtls_efr32_set_dma_window(base, 64U, base, 64U, 8U);
    UTNOX_EQUALS(noxtls_efr32_dma_in_ok(&buf[(8U - (base % 8U)) % 8U], 8U), 1U);
    UTNOX_EQUALS(noxtls_efr32_dma_in_ok(&buf[((8U - (base % 8U)) % 8U) + 1U], 8U), 0U);
    /* Alignment 0 means 1. */
    noxtls_efr32_set_dma_window(base, 64U, base, 64U, 0U);
    UTNOX_EQUALS(noxtls_efr32_dma_in_ok(&buf[1], 8U), 1U);
    /* Size 0 restores the build defaults: a host buffer is outside the SRAM / flash windows. */
    noxtls_efr32_set_dma_window(0U, 0U, 0U, 0U, 0U);
    UTNOX_EQUALS(noxtls_efr32_dma_out_ok(buf, 16U), 0U);
    UTNOX_EQUALS(noxtls_efr32_dma_in_ok(buf, 16U), 0U);
    UTNOX_EQUALS(noxtls_efr32_dma_in_ok((const void *)(uintptr_t)NOXTLS_EFR32_FLASH_BASE, 16U), 1U);
    UTNOX_EQUALS(noxtls_efr32_dma_out_ok((const void *)(uintptr_t)NOXTLS_EFR32_FLASH_BASE, 16U), 0U);
    UTNOX_EQUALS(noxtls_efr32_dma_out_ok((const void *)(uintptr_t)NOXTLS_EFR32_SRAM_BASE, 16U), 1U);
    UTNOX_EQUALS(noxtls_efr32_dma_out_ok((const void *)(uintptr_t)(NOXTLS_EFR32_SRAM_BASE + NOXTLS_EFR32_SRAM_SIZE_MG26 - 16U), 16U), 1U);
    UTNOX_EQUALS(noxtls_efr32_dma_out_ok((const void *)(uintptr_t)(NOXTLS_EFR32_SRAM_BASE + NOXTLS_EFR32_SRAM_SIZE_MG26 - 16U), 17U), 0U);
    ut_setup();
    return 0;
}

REGISTER_TEST(test_core_helpers)
{
    uint8_t a[8] = { 1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U };
    uint8_t z[4] = { 0U, 0U, 0U, 0U };

    ut_setup();
    noxtls_efr32_wipe(a, sizeof(a));
    UTNOX_EQUALS(noxtls_efr32_is_zero(a, sizeof(a)), 1U);
    a[7] = 1U;
    UTNOX_EQUALS(noxtls_efr32_is_zero(a, sizeof(a)), 0U);
    UTNOX_EQUALS(noxtls_efr32_is_zero(z, 0U), 1U);
    UTNOX_EQUALS(noxtls_efr32_is_zero(z, sizeof(z)), 1U);
    UTNOX_EQUALS(noxtls_efr32_us_to_spins(0U), 1U);
    UTNOX_EQUALS(noxtls_efr32_us_to_spins(5U), 5U);
    noxtls_efr32_barrier();
    noxtls_efr32_stats_rw()->aes_jobs = 7U;
    UTNOX_EQUALS(noxtls_efr32_stats()->aes_jobs, 7U);
    noxtls_efr32_reset_stats();
    UTNOX_EQUALS(noxtls_efr32_stats()->aes_jobs, 0U);
    return 0;
}

REGISTER_TEST(test_lock_internal_aes_nonblocking)
{
    ut_setup();
    UTNOX_EQUALS(noxtls_efr32_aes_acquire(), NOXTLS_RETURN_SUCCESS);
    /* Clocks of RADIOAES switched on through the atomic SET aliases. */
    UTNOX_EQUALS(g_ut.cmu[UT_IDX(NOXTLS_EFR32_CMU_CLKEN0_SET)] & NOXTLS_EFR32_CMU_CLKEN0_RADIOAES, NOXTLS_EFR32_CMU_CLKEN0_RADIOAES);
    UTNOX_EQUALS(g_ut.cmu[UT_IDX(NOXTLS_EFR32_CMU_RADIOCLKCTRL_SET)] & NOXTLS_EFR32_CMU_RADIOCLK_EN, NOXTLS_EFR32_CMU_RADIOCLK_EN);
    /* A second acquire never waits: it fails at once and is counted. */
    UTNOX_EQUALS(noxtls_efr32_aes_acquire(), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_efr32_stats()->aes_busy, 1U);
    UTNOX_EQUALS(noxtls_efr32_stats()->aes_acquires, 1U);
    noxtls_efr32_aes_release();
    UTNOX_EQUALS(noxtls_efr32_aes_acquire(), NOXTLS_RETURN_SUCCESS);
    noxtls_efr32_aes_release();
    /* A disabled unit is refused without counting a collision. */
    noxtls_efr32_reset_stats();
    noxtls_efr32_set_enabled(NOXTLS_EFR32_UNIT_AES, 0U);
    UTNOX_EQUALS(noxtls_efr32_aes_acquire(), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_efr32_stats()->aes_busy, 0U);
    UTNOX_EQUALS(noxtls_efr32_stats()->aes_acquires, 0U);
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_lock_internal_se_bounded_retry)
{
    ut_setup();
    UTNOX_EQUALS(noxtls_efr32_se_acquire(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_ut.cmu[UT_IDX(NOXTLS_EFR32_CMU_CLKEN1_SET)] & NOXTLS_EFR32_CMU_CLKEN1_SEMAILBOX, NOXTLS_EFR32_CMU_CLKEN1_SEMAILBOX);
    /* Owned for the whole retry budget: gives up (it never blocks forever). */
    UTNOX_EQUALS(noxtls_efr32_se_acquire(), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_efr32_stats()->se_busy, 1U);
    noxtls_efr32_se_release();
    UTNOX_EQUALS(noxtls_efr32_se_acquire(), NOXTLS_RETURN_SUCCESS);
    noxtls_efr32_se_release();
    /* Disabled and hung units are refused. */
    noxtls_efr32_set_enabled(NOXTLS_EFR32_UNIT_SE, 0U);
    UTNOX_EQUALS(noxtls_efr32_se_acquire(), NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_efr32_set_enabled(NOXTLS_EFR32_UNIT_SE, 1U);
    noxtls_efr32_se_set_hung(1U);
    UTNOX_EQUALS(noxtls_efr32_se_is_hung(), 1U);
    UTNOX_EQUALS(noxtls_efr32_se_acquire(), NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_efr32_se_set_hung(0U);
    UTNOX_EQUALS(noxtls_efr32_se_is_hung(), 0U);
    UTNOX_EQUALS(noxtls_efr32_se_acquire(), NOXTLS_RETURN_SUCCESS);
    noxtls_efr32_se_release();
    return 0;
}

REGISTER_TEST(test_lock_bind_pairs_and_owned)
{
    noxtls_efr32_engine_lock_t half_aes = { ut_dummy_try, NULL, NULL, NULL };
    noxtls_efr32_engine_lock_t half_aes2 = { NULL, ut_dummy_rel, NULL, NULL };
    noxtls_efr32_engine_lock_t half_se = { NULL, NULL, ut_dummy_try, NULL };
    noxtls_efr32_engine_lock_t half_se2 = { NULL, NULL, NULL, ut_dummy_rel };
    noxtls_efr32_engine_lock_t only_aes = { ut_dummy_try, ut_dummy_rel, NULL, NULL };

    ut_setup();
    UTNOX_EQUALS(noxtls_efr32_engine_lock_bind(&half_aes), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_engine_lock_bind(&half_aes2), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_engine_lock_bind(&half_se), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_engine_lock_bind(&half_se2), NOXTLS_RETURN_NULL);
    /* Binding while NoxTLS owns an engine is refused and leaves both flags as they were. */
    UTNOX_EQUALS(noxtls_efr32_aes_acquire(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_efr32_engine_lock_bind(ut_bound_lock()), NOXTLS_RETURN_FAILED);
    noxtls_efr32_aes_release();
    UTNOX_EQUALS(noxtls_efr32_se_acquire(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_efr32_engine_lock_bind(ut_bound_lock()), NOXTLS_RETURN_FAILED);
    noxtls_efr32_se_release();
    UTNOX_EQUALS(noxtls_efr32_aes_acquire(), NOXTLS_RETURN_SUCCESS);
    noxtls_efr32_aes_release();
    /* A partial binding keeps the internal flag for the other engine. */
    UTNOX_EQUALS(noxtls_efr32_engine_lock_bind(&only_aes), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_efr32_se_acquire(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_efr32_se_acquire(), NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_efr32_se_release();
    UTNOX_EQUALS(noxtls_efr32_engine_lock_bind(NULL), NOXTLS_RETURN_SUCCESS);
    return 0;
}

REGISTER_TEST(test_lock_bound_functions_are_used)
{
    ut_setup();
    UTNOX_EQUALS(noxtls_efr32_engine_lock_bind(ut_bound_lock()), NOXTLS_RETURN_SUCCESS);
    /* AES: one try-acquire, no retry, and software when the other driver owns the engine. */
    g_ut_bound_aes_busy = 1U;
    UTNOX_EQUALS(noxtls_efr32_aes_acquire(), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(g_ut_bound_calls[0], 1U);
    UTNOX_EQUALS(noxtls_efr32_aes_acquire(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_ut_bound_calls[0], 2U);
    noxtls_efr32_aes_release();
    UTNOX_EQUALS(g_ut_bound_calls[1], 1U);
    /* SE: retried for the bounded budget (4 tries in this build), granted on the third. */
    g_ut_bound_se_busy = 2U;
    UTNOX_EQUALS(noxtls_efr32_se_acquire(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_ut_bound_calls[2], 3U);
    noxtls_efr32_se_release();
    UTNOX_EQUALS(g_ut_bound_calls[3], 1U);
    /* Never granted inside the budget: exactly 4 attempts, then software. */
    g_ut_bound_calls[2] = 0U;
    g_ut_bound_se_busy = 100U;
    UTNOX_EQUALS(noxtls_efr32_se_acquire(), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(g_ut_bound_calls[2], 4U);
    UTNOX_EQUALS(noxtls_efr32_stats()->se_busy, 1U);
    /* The internal flags are unused while bound. */
    UTNOX_EQUALS(noxtls_efr32_flag_op(NOXTLS_EFR32_UNIT_AES, 1U), 1U);
    noxtls_efr32_aes_release();
    UTNOX_EQUALS(g_ut_bound_calls[1], 2U);
    (void)noxtls_efr32_flag_op(NOXTLS_EFR32_UNIT_AES, 0U);
    UTNOX_EQUALS(noxtls_efr32_engine_lock_bind(NULL), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_efr32_aes_acquire(), NOXTLS_RETURN_SUCCESS);
    noxtls_efr32_aes_release();
    return 0;
}

REGISTER_TEST(test_lock_flag_op_semantics)
{
    ut_setup();
    UTNOX_EQUALS(noxtls_efr32_flag_op(NOXTLS_EFR32_UNIT_SE, 1U), 1U);
    UTNOX_EQUALS(noxtls_efr32_flag_op(NOXTLS_EFR32_UNIT_SE, 1U), 0U);
    UTNOX_EQUALS(noxtls_efr32_flag_op(NOXTLS_EFR32_UNIT_AES, 1U), 1U);
    UTNOX_EQUALS(noxtls_efr32_flag_op(NOXTLS_EFR32_UNIT_SE, 0U), 1U);
    UTNOX_EQUALS(noxtls_efr32_flag_op(NOXTLS_EFR32_UNIT_AES, 0U), 1U);
    UTNOX_EQUALS(noxtls_efr32_flag_op(NOXTLS_EFR32_UNIT_SE, 1U), 1U);
    UTNOX_EQUALS(noxtls_efr32_flag_op(NOXTLS_EFR32_UNIT_SE, 0U), 1U);
    return 0;
}

REGISTER_TEST(test_core_default_memory_mapped_access)
{
    static uint32_t aes[8];
    static uint32_t sem[8];
    static uint32_t cmu[8];
    noxtls_efr32_hw_t hw;

    ut_setup();
    hw.aes = (uintptr_t)aes;
    hw.sem = (uintptr_t)sem;
    hw.cmu = (uintptr_t)cmu;
    /* The default layer reads and writes real memory (here: host arrays standing in for the peripherals). */
    UTNOX_EQUALS(noxtls_efr32_io_set(NULL), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_efr32_hw_set(&hw), NOXTLS_RETURN_SUCCESS);
    noxtls_efr32_aes_wr(4U, 0x11223344U);
    noxtls_efr32_sem_wr(8U, 0x55667788U);
    noxtls_efr32_cmu_wr(12U, 0x99AABBCCU);
    UTNOX_EQUALS(noxtls_efr32_aes_rd(4U), 0x11223344U);
    UTNOX_EQUALS(noxtls_efr32_sem_rd(8U), 0x55667788U);
    UTNOX_EQUALS(aes[1], 0x11223344U);
    UTNOX_EQUALS(sem[2], 0x55667788U);
    UTNOX_EQUALS(cmu[3], 0x99AABBCCU);
    ut_setup();
    return 0;
}
