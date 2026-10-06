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
* File:    test_nrf54_core.c
* Summary: Tests of the CRACEN core: ownership, port hooks, waits, interrupt, jobs
*
*****************************************************************************/

/**
 * @file test_nrf54_core.c
 * @brief UTNox tests of noxtls_nrf54_cracen.c.
 * @ingroup noxtls_nrf54_ut
 */

#include <stdint.h>
#include <string.h>

#include "runner.h"
#include "test_assert.h"

#include "ut_nrf54_mock.h"
#include "ut_nrf54_ref.h"

/** Completion check that never completes. */
static uint8_t ut_never(void *ctx)
{
    (void)ctx;
    return 0U;
}

/** Completion check that completes on its n-th call (ctx = remaining calls). */
static uint8_t ut_after(void *ctx)
{
    uint32_t *left = (uint32_t *)ctx;
    uint8_t done = 0U;

    if (*left == 0U) {
        done = 1U;
    } else {
        (*left)--;
    }
    return done;
}

/** Wait hook that always reports a signal (stale-signal storm). */
static noxtls_return_t ut_wait_always(void *ctx, uint32_t ms)
{
    (void)ctx;
    (void)ms;
    g_ut_waits++;
    return NOXTLS_RETURN_SUCCESS;
}

/** Wait hook that declines (OS cannot block): the backend polls. */
static noxtls_return_t ut_wait_decline(void *ctx, uint32_t ms)
{
    (void)ctx;
    (void)ms;
    g_ut_waits++;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

/** Signal hook doing nothing. */
static void ut_sig_nop(void *ctx)
{
    (void)ctx;
}

/** Build a one-descriptor SHA-256 job (cfg, state, one block) in g_ut_ram. */
static void ut_hash_job(noxtls_nrf54_desc_t *f, noxtls_nrf54_desc_t *p, uint32_t *cfg, uint8_t *state)
{
    *cfg = NOXTLS_NRF54_HASH_ALGO_SHA256;
    noxtls_nrf54_desc_set(&f[0], cfg, 4U | NOXTLS_NRF54_DESC_REALIGN, NOXTLS_NRF54_HASH_TAG_CFG);
    noxtls_nrf54_desc_set(&f[1], state, 32U | NOXTLS_NRF54_DESC_REALIGN, NOXTLS_NRF54_HASH_TAG_STATE);
    noxtls_nrf54_desc_set(&f[2], g_ut_ram.in, 64U, NOXTLS_NRF54_HASH_TAG_DATA);
    noxtls_nrf54_desc_link(f, 3U, 1U);
    noxtls_nrf54_desc_set(&p[0], state, 32U, 0U);
    noxtls_nrf54_desc_link(p, 1U, 0U);
}

REGISTER_TEST(test_core_port_and_hw)
{
    noxtls_nrf54_port_t port;
    noxtls_nrf54_hw_t hw;
    noxtls_nrf54_io_t io;

    ut_setup(0U);
    (void)memset(&port, 0, sizeof(port));
    port.wait = ut_wait_always;
    UTNOX_EQUALS(noxtls_nrf54_cracen_set_port(&port), NOXTLS_RETURN_NULL);
    port.wait = NULL;
    port.lock = ut_sig_nop;
    UTNOX_EQUALS(noxtls_nrf54_cracen_set_port(&port), NOXTLS_RETURN_NULL);
    port.unlock = ut_sig_nop;
    UTNOX_EQUALS(noxtls_nrf54_cracen_set_port(&port), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_ut.nvic_enabled, 0U);
    UTNOX_EQUALS(noxtls_nrf54_cracen_set_port(NULL), NOXTLS_RETURN_SUCCESS);
    /* A wait hook enables CRACEN_IRQn with priority 5 (top 3 bits of the byte). */
    ut_port_irq();
    UTNOX_EQUALS(g_ut.nvic_enabled, 1U);
    UTNOX_EQUALS((g_ut.nvic[UT_IDX(0x400U + (NOXTLS_NRF54_CRACEN_IRQN_LM20 & ~3U))] >>
                  ((NOXTLS_NRF54_CRACEN_IRQN_LM20 & 3U) * 8U)) & 0xFFU, 5U << 5);
    /* Changes refused while CRACEN is owned. */
    UTNOX_EQUALS(noxtls_nordic_crypto_try_acquire(), 1);
    UTNOX_EQUALS(noxtls_nordic_crypto_try_acquire(), 0);
    UTNOX_EQUALS(noxtls_nrf54_cracen_set_port(NULL), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(noxtls_nrf54_cracen_set_hw(NULL), NOXTLS_RETURN_FAILED);
    noxtls_nordic_crypto_release();
    /* Build default instance (nRF54LM20 unless NOXTLS_NRF54_CONFIG_CHIP_L15). */
    hw = *noxtls_nrf54_cracen_hw();
    UTNOX_EQUALS(noxtls_nrf54_cracen_set_hw(NULL), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_nrf54_cracen_hw()->core == (uintptr_t)NOXTLS_NRF54_CORE_BASE_LM20, 1);
    UTNOX_EQUALS(noxtls_nrf54_cracen_hw()->variant, NOXTLS_NRF54_VARIANT_LITE);
    UTNOX_EQUALS(noxtls_nrf54_cracen_set_hw(&hw), NOXTLS_RETURN_SUCCESS);
    /* Register layer. */
    io.read32 = NULL;
    io.write32 = NULL;
    io.in_isr = NULL;
    UTNOX_EQUALS(noxtls_nrf54_cracen_set_io(&io), NOXTLS_RETURN_NULL);
    /* NULL restores the MMIO accessors; the mock is re-installed by ut_setup(). */
    UTNOX_EQUALS(noxtls_nrf54_cracen_set_io(NULL), NOXTLS_RETURN_SUCCESS);
    ut_setup(0U);
    UTNOX_EQUALS(g_ut.err[0], 0);
    return 0;
}

REGISTER_TEST(test_core_acquire_release)
{
    const noxtls_nrf54_caps_t *caps;

    ut_setup(1U);
    UTNOX_EQUALS(noxtls_nrf54_cracen_acquire(0U), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_nrf54_cracen_acquire(0x80U), NOXTLS_RETURN_INVALID_PARAM);
    noxtls_nrf54_cracen_set_enabled(0U);
    UTNOX_EQUALS(noxtls_nrf54_cracen_is_enabled(), 0U);
    UTNOX_EQUALS(noxtls_nrf54_cracen_acquire(NOXTLS_NRF54_MOD_CM), NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_nrf54_cracen_set_enabled(1U);
    UTNOX_EQUALS(noxtls_nrf54_cracen_caps()->valid, 0U);
    UTNOX_EQUALS(noxtls_nrf54_cracen_acquire(NOXTLS_NRF54_MOD_PKE), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_ut.wrap[UT_IDX(NOXTLS_NRF54_ENABLE)], NOXTLS_NRF54_MOD_PKE | NOXTLS_NRF54_MOD_CM);
    caps = noxtls_nrf54_cracen_caps();
    UTNOX_EQUALS(caps->valid, 1U);
    UTNOX_EQUALS(caps->aes_keys, 7U);
    UTNOX_EQUALS(caps->ctr_bits, 128U);
    UTNOX_EQUALS(caps->hash_algos, 0x3FU);
    /* Second user while owned: software fallback. */
    UTNOX_EQUALS(noxtls_nrf54_cracen_acquire(NOXTLS_NRF54_MOD_CM), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_nrf54_cracen_stats()->busy, 1U);
    noxtls_nrf54_cracen_release();
    UTNOX_EQUALS(g_ut.wrap[UT_IDX(NOXTLS_NRF54_ENABLE)], 0U);
    UTNOX_EQUALS(noxtls_nrf54_cracen_stats()->acquires, 1U);
    /* With an OS lock: taken and given around ownership, also when busy. */
    ut_port_irq();
    UTNOX_EQUALS(noxtls_nordic_crypto_try_acquire(), 1);
    UTNOX_EQUALS(noxtls_nrf54_cracen_acquire(NOXTLS_NRF54_MOD_CM), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(g_ut_locks, 1U);
    UTNOX_EQUALS(g_ut_unlocks, 1U);
    noxtls_nordic_crypto_release();
    UTNOX_EQUALS(noxtls_nrf54_cracen_acquire(NOXTLS_NRF54_MOD_RNG), NOXTLS_RETURN_SUCCESS);
    noxtls_nrf54_cracen_release();
    UTNOX_EQUALS(g_ut_locks, 2U);
    UTNOX_EQUALS(g_ut_unlocks, 2U);
    /* Interrupt context: no OS lock. */
    g_ut.in_isr = 1U;
    UTNOX_EQUALS(noxtls_nrf54_cracen_acquire(NOXTLS_NRF54_MOD_CM), NOXTLS_RETURN_SUCCESS);
    noxtls_nrf54_cracen_release();
    UTNOX_EQUALS(g_ut_locks, 2U);
    noxtls_nrf54_cracen_reset_stats();
    UTNOX_EQUALS(noxtls_nrf54_cracen_stats()->acquires, 0U);
    return 0;
}

REGISTER_TEST(test_core_wait_paths)
{
    uint32_t left = 3U;
    noxtls_nrf54_port_t storm = { ut_wait_always, ut_sig_nop, NULL, NULL, NULL };

    ut_setup(0U);
    /* Poll mode. */
    UTNOX_EQUALS(noxtls_nrf54_cracen_wait(NOXTLS_NRF54_MOD_CM, ut_after, &left, 100U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_nrf54_cracen_stats()->polled, 1U);
    UTNOX_EQUALS(noxtls_nrf54_cracen_wait(NOXTLS_NRF54_MOD_CM, ut_never, NULL, 3U), NOXTLS_RETURN_TIMEOUT);
    UTNOX_EQUALS(noxtls_nrf54_cracen_stats()->timeouts, 1U);
    /* Already complete: no wait at all. */
    left = 0U;
    UTNOX_EQUALS(noxtls_nrf54_cracen_wait(NOXTLS_NRF54_MOD_CM, ut_after, &left, 0U), NOXTLS_RETURN_SUCCESS);
    /* Interrupt mode, never signalled: each slice times out (timeout 0 still sleeps once). */
    ut_port_irq();
    UTNOX_EQUALS(noxtls_nrf54_cracen_wait(NOXTLS_NRF54_MOD_RNG, ut_never, NULL, 0U), NOXTLS_RETURN_TIMEOUT);
    UTNOX_EQUALS(g_ut_waits, 1U);
    UTNOX_EQUALS(g_ut.inten, 0U);
    g_ut_waits = 0U;
    UTNOX_EQUALS(noxtls_nrf54_cracen_wait(NOXTLS_NRF54_MOD_RNG, ut_never, NULL, 2500U), NOXTLS_RETURN_TIMEOUT);
    UTNOX_EQUALS(g_ut_waits, 3U);
    /* Interrupt context polls even with a port. */
    g_ut.in_isr = 1U;
    left = 2U;
    g_ut_waits = 0U;
    UTNOX_EQUALS(noxtls_nrf54_cracen_wait(NOXTLS_NRF54_MOD_CM, ut_after, &left, 10U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_ut_waits, 0U);
    g_ut.in_isr = 0U;
    /* A storm of stale signals is bounded. */
    UTNOX_EQUALS(noxtls_nrf54_cracen_set_port(&storm), NOXTLS_RETURN_SUCCESS);
    g_ut_waits = 0U;
    UTNOX_EQUALS(noxtls_nrf54_cracen_wait(NOXTLS_NRF54_MOD_CM, ut_never, NULL, 1000000U), NOXTLS_RETURN_TIMEOUT);
    UTNOX_EQUALS(g_ut_waits, NOXTLS_NRF54_CONFIG_WAIT_WAKES_MAX);
    /* Signal stale, then the operation completes on a later wake. */
    left = 2U;
    UTNOX_EQUALS(noxtls_nrf54_cracen_wait(NOXTLS_NRF54_MOD_CM, ut_after, &left, 1000U), NOXTLS_RETURN_SUCCESS);
    /* The OS declines to block: the rest of the budget is polled. */
    storm.wait = ut_wait_decline;
    UTNOX_EQUALS(noxtls_nrf54_cracen_set_port(&storm), NOXTLS_RETURN_SUCCESS);
    g_ut_waits = 0U;
    left = 50U;
    UTNOX_EQUALS(noxtls_nrf54_cracen_wait(NOXTLS_NRF54_MOD_CM, ut_after, &left, 1000U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_ut_waits, 1U);
    UTNOX_EQUALS(noxtls_nrf54_cracen_wait(NOXTLS_NRF54_MOD_CM, ut_never, NULL, 1000U), NOXTLS_RETURN_TIMEOUT);
    return 0;
}

REGISTER_TEST(test_core_cm_jobs)
{
    /* Descriptors are read by the (mock) DMA: static, like the backend's own. */
    static noxtls_nrf54_desc_t f[3];
    static noxtls_nrf54_desc_t p[1];
    static uint32_t cfg;
    static uint8_t state[32];
    uint8_t expect[32];
    uint8_t chip;

    for (chip = 0U; chip < 2U; chip++) {
        ut_setup(chip);
        (void)ut_sha_iv(256U, state);
        (void)ut_sha_iv(256U, expect);
        (void)memset(g_ut_ram.in, 0x61, 64U);
        ut_sha256_block(expect, g_ut_ram.in);
        UTNOX_EQUALS(noxtls_nrf54_cracen_acquire(NOXTLS_NRF54_MOD_CM), NOXTLS_RETURN_SUCCESS);
        /* Plain completion (poll). */
        ut_hash_job(f, p, &cfg, state);
        UTNOX_EQUALS(noxtls_nrf54_cracen_cm_run(f, p, 64U), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(memcmp(state, expect, 32U), 0);
        noxtls_nrf54_cracen_release();
        /* Delayed completion and busy-after-stop, interrupt driven. */
        ut_port_irq();
        UTNOX_EQUALS(noxtls_nrf54_cracen_acquire(NOXTLS_NRF54_MOD_CM), NOXTLS_RETURN_SUCCESS);
        g_ut.delay_reads = 3U;
        g_ut.busy_after_stop = 2U;
        (void)ut_sha_iv(256U, state);
        ut_hash_job(f, p, &cfg, state);
        UTNOX_EQUALS(noxtls_nrf54_cracen_cm_run(f, p, 64U), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(memcmp(state, expect, 32U), 0);
        UTNOX_GREATER_THAN(noxtls_nrf54_cracen_stats()->irq_cm, 0U);
        g_ut.delay_reads = 0U;
        g_ut.busy_after_stop = 0U;
        /* Bus error: soft reset, FAILED. */
        g_ut.inject_error = 1U;
        g_ut.softrst_busy_reads = 3U;
        ut_hash_job(f, p, &cfg, state);
        UTNOX_EQUALS(noxtls_nrf54_cracen_cm_run(f, p, 64U), NOXTLS_RETURN_FAILED);
        UTNOX_EQUALS(g_ut.softresets, 1U);
        /* Engine never idle after the push DMA stopped. */
        g_ut.stuck = 1U;
        ut_hash_job(f, p, &cfg, state);
        UTNOX_EQUALS(noxtls_nrf54_cracen_cm_run(f, p, 64U), NOXTLS_RETURN_FAILED);
        /* Job never completes: timeout (polled). */
        noxtls_nrf54_cracen_release();
        (void)noxtls_nrf54_cracen_set_port(NULL);
        UTNOX_EQUALS(noxtls_nrf54_cracen_acquire(NOXTLS_NRF54_MOD_CM), NOXTLS_RETURN_SUCCESS);
        g_ut.hang = 1U;
        ut_hash_job(f, p, &cfg, state);
        UTNOX_EQUALS(noxtls_nrf54_cracen_cm_run(f, p, 64U), NOXTLS_RETURN_TIMEOUT);
        UTNOX_EQUALS(noxtls_nrf54_cracen_stats()->cm_errors, 3U);
        noxtls_nrf54_cracen_release();
    }
    return 0;
}

REGISTER_TEST(test_core_irq_handler)
{
    ut_setup(0U);
    /* No event: nothing serviced, no signal. */
    noxtls_nrf54_cracen_irq_handler();
    UTNOX_EQUALS(g_ut_signals, 0U);
    /* Events without a port: masked and cleared, no signal hook. */
    g_ut.wrap[UT_IDX(NOXTLS_NRF54_EVENTS_CRYPTOMASTER)] = 1U;
    g_ut.inten = NOXTLS_NRF54_MOD_ALL;
    noxtls_nrf54_cracen_irq_handler();
    UTNOX_EQUALS(g_ut.inten, NOXTLS_NRF54_MOD_RNG | NOXTLS_NRF54_MOD_PKE);
    UTNOX_EQUALS(g_ut.wrap[UT_IDX(NOXTLS_NRF54_EVENTS_CRYPTOMASTER)], 0U);
    ut_port_irq();
    g_ut.wrap[UT_IDX(NOXTLS_NRF54_EVENTS_RNG)] = 1U;
    g_ut.wrap[UT_IDX(NOXTLS_NRF54_EVENTS_PKEIKG)] = 1U;
    noxtls_nrf54_cracen_irq_handler();
    UTNOX_EQUALS(g_ut_signals, 1U);
    UTNOX_EQUALS(g_ut.inten, 0U);
    UTNOX_EQUALS(noxtls_nrf54_cracen_stats()->irq_cm, 1U);
    UTNOX_EQUALS(noxtls_nrf54_cracen_stats()->irq_rng, 1U);
    UTNOX_EQUALS(noxtls_nrf54_cracen_stats()->irq_pke, 1U);
    return 0;
}

REGISTER_TEST(test_core_dma_window)
{
    noxtls_nrf54_desc_t d[3];
    uint32_t i;

    ut_setup(0U);
    UTNOX_EQUALS(noxtls_nrf54_dma_in_ok(g_ut_ram.in, 16U), 1U);
    UTNOX_EQUALS(noxtls_nrf54_dma_out_ok(g_ut_ram.out, sizeof(g_ut_ram.out)), 1U);
    UTNOX_EQUALS(noxtls_nrf54_dma_in_ok(NULL, 0U), 0U);
    UTNOX_EQUALS(noxtls_nrf54_dma_in_ok(&d[0], 16U), 0U);
    UTNOX_EQUALS(noxtls_nrf54_dma_in_ok((const uint8_t *)&g_ut_ram + sizeof(g_ut_ram) - 4U, 8U), 0U);
    UTNOX_EQUALS(noxtls_nrf54_dma_in_ok((const uint8_t *)&g_ut_ram + sizeof(g_ut_ram), 0U), 1U);
    /* Default windows: input RRAM + RAM, output RAM only. */
    noxtls_nrf54_cracen_set_dma_window(0U, 0U);
    UTNOX_EQUALS(noxtls_nrf54_dma_in_ok((const void *)(uintptr_t)0x1000U, 256U), 1U);
    UTNOX_EQUALS(noxtls_nrf54_dma_out_ok((const void *)(uintptr_t)0x1000U, 256U), 0U);
    UTNOX_EQUALS(noxtls_nrf54_dma_out_ok((const void *)(uintptr_t)NOXTLS_NRF54_RAM_BASE, 256U), 1U);
    UTNOX_EQUALS(noxtls_nrf54_dma_in_ok((const void *)(uintptr_t)(NOXTLS_NRF54_RAM_BASE + NOXTLS_NRF54_RAM_SIZE_LM20), 1U), 0U);
    /* Descriptor helpers. */
    for (i = 0U; i < 3U; i++) {
        noxtls_nrf54_desc_set(&d[i], &d[i], 4U, 0x10U);
    }
    noxtls_nrf54_desc_link(d, 3U, 1U);
    UTNOX_EQUALS(d[0].next, (uint32_t)(uintptr_t)&d[1]);
    UTNOX_EQUALS(d[2].next, NOXTLS_NRF54_DESC_STOP);
    UTNOX_EQUALS(d[2].tag, 0x10U | NOXTLS_NRF54_TAG_LAST);
    UTNOX_EQUALS(d[2].length, 4U | NOXTLS_NRF54_DESC_REALIGN);
    noxtls_nrf54_desc_set(&d[0], NULL, 8U, 0U);
    noxtls_nrf54_desc_link(d, 1U, 0U);
    UTNOX_EQUALS(d[0].tag, 0U);
    UTNOX_EQUALS(d[0].addr, 0U);
    return 0;
}

REGISTER_TEST(test_core_edges)
{
    noxtls_nrf54_io_t io = { NULL, NULL, NULL };
    noxtls_nrf54_desc_t *none = NULL;

    ut_setup(1U);
    /* Partial access layers are refused. */
    io.read32 = (uint32_t (*)(uintptr_t))(void (*)(void))ut_never;
    UTNOX_EQUALS(noxtls_nrf54_cracen_set_io(&io), NOXTLS_RETURN_NULL);
    io.write32 = (void (*)(uintptr_t, uint32_t))(void (*)(void))ut_never;
    UTNOX_EQUALS(noxtls_nrf54_cracen_set_io(&io), NOXTLS_RETURN_NULL);
    ut_setup(1U);
    /* Engine without AES and hash: capabilities read as absent. */
    g_ut.core[UT_IDX(NOXTLS_NRF54_HW_INCLIPS)] = 0U;
    UTNOX_EQUALS(noxtls_nrf54_cracen_acquire(NOXTLS_NRF54_MOD_CM), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_nrf54_cracen_caps()->aes_modes, 0U);
    UTNOX_EQUALS(noxtls_nrf54_cracen_caps()->hash_algos, 0U);
    noxtls_nrf54_cracen_release();
    UTNOX_EQUALS(noxtls_nrf54_dma_out_ok(none, 0U), 0U);
    return 0;
}
