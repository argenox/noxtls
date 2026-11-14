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
* File:    test_nrf54_kmu_lock.c
* Summary: Tests of KMU operation serialisation
*
*****************************************************************************/

/**
 * @file test_nrf54_kmu_lock.c
 * @brief KMU serialisation (audit issue 160): a KMU call made while another
 *        KMU operation owns the registers (simulated by calling it from the
 *        RRAM hook, i.e. between the outer call's start and its task trigger)
 *        must do nothing and report busy, and must not retarget the outer task.
 * @ingroup noxtls_nrf54_ut
 */

#include <stdint.h>
#include <string.h>

#include "runner.h"
#include "test_assert.h"

#include "ut_nrf54_mock.h"

/** Result of the nested revoke attempted from inside the hook. */
static noxtls_return_t s_nested_rc;
/** Nested calls made. */
static uint32_t s_nested_calls;

/**
 * @brief RRAM hook that tries a second KMU operation (revoke of slot 7)
 *        while the outer provision / revoke owns the KMU.
 */
static noxtls_return_t ut_nvm_preempt(void *ctx, uint8_t enable)
{
    uint32_t meta = 0U;
    noxtls_nrf54_kmu_state_t st;

    (void)ctx;
    if (enable != 0U) {
        s_nested_calls++;
        s_nested_rc = noxtls_nrf54_kmu_revoke(7U, 1U);
        if (noxtls_nrf54_kmu_read_metadata(7U, &meta, &st) != NOXTLS_RETURN_TIMEOUT) {
            s_nested_rc = NOXTLS_RETURN_FAILED;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

REGISTER_TEST(test_kmu_nested_call_is_refused)
{
    uint32_t meta = 0U;
    noxtls_nrf54_kmu_state_t st = NOXTLS_NRF54_KMU_SLOT_EMPTY;
    uint8_t chip;

    for (chip = 0U; chip < 2U; chip++) {
        ut_setup(chip);
        noxtls_nrf54_kmu_set_nvm_hook(NULL, NULL);
        (void)memset(g_ut_ram.kdata.value, 0x5A, sizeof(g_ut_ram.kdata.value));
        g_ut_ram.kdata.revoke_policy = NOXTLS_NRF54_KMU_RPOLICY_ROTATING;
        g_ut_ram.kdata.dest = (uint32_t)(uintptr_t)g_ut_ram.prot;
        g_ut_ram.kdata.metadata = 0x0000A5A5U;
        /* Slot 7 is the victim a preempting revoke would hit. */
        UTNOX_EQUALS(noxtls_nrf54_kmu_provision(7U, &g_ut_ram.kdata), NOXTLS_RETURN_SUCCESS);

        noxtls_nrf54_kmu_set_nvm_hook(ut_nvm_preempt, NULL);
        s_nested_calls = 0U;
        s_nested_rc = NOXTLS_RETURN_SUCCESS;
        UTNOX_EQUALS(noxtls_nrf54_kmu_provision(4U, &g_ut_ram.kdata), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(s_nested_calls, 1U);
        UTNOX_EQUALS(s_nested_rc, NOXTLS_RETURN_TIMEOUT);

        s_nested_rc = NOXTLS_RETURN_SUCCESS;
        UTNOX_EQUALS(noxtls_nrf54_kmu_revoke(4U, 1U), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(s_nested_calls, 2U);
        UTNOX_EQUALS(s_nested_rc, NOXTLS_RETURN_TIMEOUT);

        /* The outer revoke hit slot 4 only; slot 7 is still provisioned. */
        noxtls_nrf54_kmu_set_nvm_hook(NULL, NULL);
        UTNOX_EQUALS(noxtls_nrf54_kmu_read_metadata(4U, &meta, &st), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(st, NOXTLS_NRF54_KMU_SLOT_REVOKED);
        UTNOX_EQUALS(noxtls_nrf54_kmu_read_metadata(7U, &meta, &st), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(st, NOXTLS_NRF54_KMU_SLOT_PROVISIONED);
        UTNOX_EQUALS(meta, 0x0000A5A5U);
        /* The lock is released after every call. */
        UTNOX_EQUALS(noxtls_nrf54_kmu_push(7U, 1U), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(g_ut.err[0], 0);
    }
    return 0;
}
