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
* File:    test_nrf54_rng.c
* Summary: Tests of the TRNG backend and the NoxTLS entropy port
*
*****************************************************************************/

/**
 * @file test_nrf54_rng.c
 * @brief TRNG start-up, conditioning key, FIFO drain, health-test restarts,
 *        timeouts and the DRBG entropy port on the mocked CRACEN.
 * @ingroup noxtls_nrf54_ut
 */

#include <stdint.h>
#include <string.h>

#include "runner.h"
#include "test_assert.h"

#include "ut_nrf54_mock.h"
#include "drbg/noxtls_drbg.h"

REGISTER_TEST(test_rng_fill_both_chips)
{
    uint8_t chip;
    uint32_t i;

    for (chip = 0U; chip < 2U; chip++) {
        ut_setup(chip);
        if (chip != 0U) {
            ut_port_irq();
        }
        g_ut.rng_startup_reads = 3U;
        UTNOX_EQUALS(noxtls_nrf54_rng_fill(g_ut_ram.out, 70U), NOXTLS_RETURN_SUCCESS);
        /* First fill: four words become the conditioning key, then the FIFO is flushed. */
        UTNOX_EQUALS(g_ut.rng_key_writes, 4U);
        UTNOX_EQUALS(g_ut.rng_softresets, 2U);
        /* Data comes from the second and later fills, little-endian words. */
        UTNOX_EQUALS(g_ut_ram.out[0], 0x10U);
        UTNOX_EQUALS(g_ut_ram.out[3], 0xA5U);
        for (i = 0U; (i + 3U) < 70U; i += 4U) {
            UTNOX_EQUALS(g_ut_ram.out[i + 3U], 0xA5U);
        }
        UTNOX_EQUALS(noxtls_nrf54_rng_health()->requests, 1U);
        UTNOX_EQUALS(g_ut.core[UT_IDX(NOXTLS_NRF54_RNG_CONTROL)], NOXTLS_NRF54_RNG_CTRL_OFF);
        if (chip == 0U) {
            UTNOX_EQUALS(g_ut.core[UT_IDX(NOXTLS_NRF54_RNG_REPEAT)], NOXTLS_NRF54_RNG_LITE_REPEAT_CUTOFF);
            UTNOX_EQUALS(g_ut.core[UT_IDX(NOXTLS_NRF54_RNG_CLKDIV)], NOXTLS_NRF54_RNG_CLKDIV_LM20);
        } else {
            UTNOX_EQUALS(g_ut.core[UT_IDX(NOXTLS_NRF54_RNG_REPEAT)], 0U);
            UTNOX_GREATER_THAN(noxtls_nrf54_cracen_stats()->irq_rng, 0U);
        }
        UTNOX_EQUALS(noxtls_nrf54_rng_fill(g_ut_ram.out, 0U), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(noxtls_nrf54_rng_fill(NULL, 4U), NOXTLS_RETURN_NULL);
        UTNOX_EQUALS(g_ut.err[0], 0);
    }
    return 0;
}

REGISTER_TEST(test_rng_health_and_errors)
{
    uint8_t buf[8];

    ut_setup(1U);
    /* Two start-up failures, then success: restarts counted. */
    g_ut.rng_fail_starts = 2U;
    g_ut.rng_fail_bits = NOXTLS_NRF54_RNG_ST_STARTUPFAIL | NOXTLS_NRF54_RNG_ST_REPFAIL | NOXTLS_NRF54_RNG_ST_PROPFAIL;
    UTNOX_EQUALS(noxtls_nrf54_rng_fill(buf, sizeof(buf)), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_nrf54_rng_health()->restarts, 2U);
    UTNOX_EQUALS(noxtls_nrf54_rng_health()->startup_failures, 2U);
    UTNOX_EQUALS(noxtls_nrf54_rng_health()->repetition_failures, 2U);
    UTNOX_EQUALS(noxtls_nrf54_rng_health()->proportion_failures, 2U);
    /* A start-up failure alone. */
    g_ut.rng_fail_starts = 1U;
    g_ut.rng_fail_bits = NOXTLS_NRF54_RNG_ST_STARTUPFAIL;
    UTNOX_EQUALS(noxtls_nrf54_rng_fill(buf, sizeof(buf)), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_nrf54_rng_health()->repetition_failures, 2U);
    /* Persistent failure: FAILED, buffer wiped. */
    g_ut.rng_fail_starts = 10U;
    g_ut.rng_fail_bits = NOXTLS_NRF54_RNG_ST_REPFAIL;
    (void)memset(buf, 0x55, sizeof(buf));
    UTNOX_EQUALS(noxtls_nrf54_rng_fill(buf, sizeof(buf)), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(buf[0], 0U);
    UTNOX_EQUALS(noxtls_nrf54_rng_health()->last_status, (NOXTLS_NRF54_RNG_STATE_ERROR << NOXTLS_NRF54_RNG_ST_STATE_POS) |
                 NOXTLS_NRF54_RNG_ST_REPFAIL);
    /* The DRBG entropy port reports NOT_SUPPORTED and the auto source fails closed. */
    g_ut.rng_fail_starts = 10U;
    noxtls_drbg_set_entropy_source(NOXTLS_ENTROPY_SOURCE_AUTO);
    UTNOX_EQUALS(noxtls_drbg_entropy_accel_port(buf, sizeof(buf)), NOXTLS_RETURN_NOT_SUPPORTED);
    g_ut.rng_fail_starts = 0U;
    UTNOX_EQUALS(noxtls_drbg_entropy_accel_port(buf, sizeof(buf)), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_drbg_get_entropy(buf, sizeof(buf)), NOXTLS_RETURN_SUCCESS);
    /* Never leaves start-up: timeout. */
    g_ut.rng_never_ready = 1U;
    UTNOX_EQUALS(noxtls_nrf54_rng_fill(buf, sizeof(buf)), NOXTLS_RETURN_TIMEOUT);
    g_ut.rng_never_ready = 0U;
    /* No TRNG in the engine. */
    ut_setup(0U);
    g_ut.core[UT_IDX(NOXTLS_NRF54_HW_INCLIPS)] &= ~NOXTLS_NRF54_INCLIPS_BA431;
    UTNOX_EQUALS(noxtls_nrf54_rng_fill(buf, sizeof(buf)), NOXTLS_RETURN_NOT_SUPPORTED);
    /* Busy. */
    ut_setup(0U);
    UTNOX_EQUALS(noxtls_nordic_crypto_try_acquire(), 1);
    UTNOX_EQUALS(noxtls_nrf54_rng_fill(buf, sizeof(buf)), NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_nordic_crypto_release();
    noxtls_nrf54_rng_reset_health();
    UTNOX_EQUALS(noxtls_nrf54_rng_health()->requests, 0U);
    return 0;
}
