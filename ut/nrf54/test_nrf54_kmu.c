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
* File:    test_nrf54_kmu.c
* Summary: Tests of the KMU driver and of AES with a pushed key
*
*****************************************************************************/

/**
 * @file test_nrf54_kmu.c
 * @brief KMU provision / push / metadata / push-block / block / revoke on the
 *        mock, RRAM hook handling, timeouts, and an AES operation with a key
 *        pushed into (mocked) CRACEN protected RAM.
 * @ingroup noxtls_nrf54_ut
 */

#include <stdint.h>
#include <string.h>

#include "runner.h"
#include "test_assert.h"

#include "ut_nrf54_mock.h"
#include "ut_nrf54_ref.h"

/** RRAM hook calls (enable, disable). */
static uint32_t s_nvm_on;
static uint32_t s_nvm_off;
/** Result returned by the hook when enabling. */
static noxtls_return_t s_nvm_rc;

/**
 * @brief RRAM write hook of the tests.
 *
 * @param[in] ctx    Unused.
 * @param[in] enable 1 before, 0 after.
 *
 * @return s_nvm_rc when enabling.
 */
static noxtls_return_t ut_nvm(void *ctx, uint8_t enable)
{
    (void)ctx;
    if (enable != 0U) {
        s_nvm_on++;
        return s_nvm_rc;
    }
    s_nvm_off++;
    return NOXTLS_RETURN_SUCCESS;
}

REGISTER_TEST(test_kmu_slot_lifecycle)
{
    uint32_t meta = 0U;
    noxtls_nrf54_kmu_state_t st = NOXTLS_NRF54_KMU_SLOT_REVOKED;
    ut_aes_key_t rk;
    uint8_t expect[16];
    uint8_t chip;

    for (chip = 0U; chip < 2U; chip++) {
        ut_setup(chip);
        noxtls_nrf54_kmu_set_nvm_hook(ut_nvm, NULL);
        s_nvm_on = 0U;
        s_nvm_off = 0U;
        s_nvm_rc = NOXTLS_RETURN_SUCCESS;
        g_ut.kmu_busy_reads = 2U;
        UTNOX_EQUALS(noxtls_nrf54_kmu_read_metadata(3U, &meta, &st), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(st, NOXTLS_NRF54_KMU_SLOT_EMPTY);
        /* Provision slot 3 with a 128-bit key pushed to "protected RAM". */
        (void)memset(g_ut_ram.kdata.value, 0x42, sizeof(g_ut_ram.kdata.value));
        g_ut_ram.kdata.revoke_policy = NOXTLS_NRF54_KMU_RPOLICY_ROTATING;
        g_ut_ram.kdata.dest = (uint32_t)(uintptr_t)g_ut_ram.prot;
        g_ut_ram.kdata.metadata = 0x12345678U;
        UTNOX_EQUALS(noxtls_nrf54_kmu_provision(3U, &g_ut_ram.kdata), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(s_nvm_on, 1U);
        UTNOX_EQUALS(s_nvm_off, 1U);
        UTNOX_EQUALS(noxtls_nrf54_kmu_provision(3U, &g_ut_ram.kdata), NOXTLS_RETURN_FAILED);
        UTNOX_EQUALS(noxtls_nrf54_kmu_read_metadata(3U, &meta, &st), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(st, NOXTLS_NRF54_KMU_SLOT_PROVISIONED);
        UTNOX_EQUALS(meta, 0x12345678U);
        UTNOX_EQUALS(noxtls_nrf54_kmu_push(3U, 1U), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(g_ut_ram.prot[15], 0x42U);
        /* AES with the pushed key, read by the DMA only. */
        (void)ut_aes_setkey(&rk, g_ut_ram.prot, 16U);
        ut_aes_encrypt(&rk, g_ut_ram.in, expect);
        UTNOX_EQUALS(noxtls_nrf54_aes_crypt_keyref(NOXTLS_NRF54_AES_ECB, 0U, noxtls_nrf54_cracen_hw()->prot_key0, 16U,
                                                   NULL, g_ut_ram.in, g_ut_ram.out, 16U), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(memcmp(g_ut_ram.out, expect, 16U), 0);
        /* Empty slot in a range: push fails. */
        UTNOX_EQUALS(noxtls_nrf54_kmu_push(3U, 2U), NOXTLS_RETURN_FAILED);
        /* Push block, then the push fails. */
        UTNOX_EQUALS(noxtls_nrf54_kmu_push_block(3U, 1U), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(noxtls_nrf54_kmu_push(3U, 1U), NOXTLS_RETURN_FAILED);
        /* Block (nRF54LM20 only). */
        if (chip == 0U) {
            UTNOX_EQUALS(noxtls_nrf54_kmu_block(5U, 1U), NOXTLS_RETURN_SUCCESS);
            UTNOX_EQUALS(noxtls_nrf54_kmu_provision(5U, &g_ut_ram.kdata), NOXTLS_RETURN_FAILED);
        } else {
            UTNOX_EQUALS(noxtls_nrf54_kmu_block(5U, 1U), NOXTLS_RETURN_NOT_SUPPORTED);
        }
        /* Revoke: permanent. */
        UTNOX_EQUALS(noxtls_nrf54_kmu_revoke(3U, 1U), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(s_nvm_on, s_nvm_off);
        UTNOX_EQUALS(s_nvm_on, (chip == 0U) ? 4U : 3U);
        UTNOX_EQUALS(noxtls_nrf54_kmu_read_metadata(3U, &meta, &st), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(st, NOXTLS_NRF54_KMU_SLOT_REVOKED);
        UTNOX_EQUALS(meta, 0U);
        UTNOX_EQUALS(noxtls_nrf54_kmu_provision(3U, &g_ut_ram.kdata), NOXTLS_RETURN_FAILED);
        UTNOX_EQUALS(noxtls_nrf54_kmu_push(3U, 1U), NOXTLS_RETURN_FAILED);
        UTNOX_EQUALS(g_ut.err[0], 0);
    }
    return 0;
}

REGISTER_TEST(test_kmu_errors)
{
    uint32_t meta;
    noxtls_nrf54_kmu_state_t st;

    ut_setup(0U);
    noxtls_nrf54_kmu_set_nvm_hook(NULL, NULL);
    UTNOX_EQUALS(noxtls_nrf54_kmu_read_metadata(0U, NULL, &st), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_kmu_read_metadata(0U, &meta, NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_kmu_read_metadata(250U, &meta, &st), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_nrf54_kmu_push(0U, 0U), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_nrf54_kmu_push(249U, 2U), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_nrf54_kmu_push(250U, 1U), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_nrf54_kmu_provision(0U, NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_kmu_provision(250U, &g_ut_ram.kdata), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_nrf54_kmu_revoke(250U, 1U), NOXTLS_RETURN_INVALID_PARAM);
    /* Provisioning without a hook. */
    g_ut_ram.kdata.dest = (uint32_t)(uintptr_t)g_ut_ram.prot;
    UTNOX_EQUALS(noxtls_nrf54_kmu_provision(9U, &g_ut_ram.kdata), NOXTLS_RETURN_SUCCESS);
    /* RRAM hook refuses: nothing written. */
    noxtls_nrf54_kmu_set_nvm_hook(ut_nvm, NULL);
    s_nvm_rc = NOXTLS_RETURN_FAILED;
    s_nvm_off = 0U;
    UTNOX_EQUALS(noxtls_nrf54_kmu_provision(10U, &g_ut_ram.kdata), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(noxtls_nrf54_kmu_revoke(9U, 1U), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(s_nvm_off, 0U);
    UTNOX_EQUALS(g_ut.kslot[10].state, 0U);
    UTNOX_EQUALS(g_ut.kslot[9].state, 1U);
    s_nvm_rc = NOXTLS_RETURN_SUCCESS;
    noxtls_nrf54_kmu_set_nvm_hook(NULL, NULL);
    /* No event / never ready: timeouts. */
    g_ut.kmu_no_event = 1U;
    UTNOX_EQUALS(noxtls_nrf54_kmu_read_metadata(9U, &meta, &st), NOXTLS_RETURN_TIMEOUT);
    UTNOX_EQUALS(noxtls_nrf54_kmu_push(9U, 1U), NOXTLS_RETURN_TIMEOUT);
    g_ut.kmu_no_event = 0U;
    g_ut.kmu_never_ready = 1U;
    UTNOX_EQUALS(noxtls_nrf54_kmu_push(9U, 1U), NOXTLS_RETURN_TIMEOUT);
    g_ut.kmu_never_ready = 0U;
    UTNOX_EQUALS(noxtls_nrf54_kmu_push(9U, 1U), NOXTLS_RETURN_SUCCESS);
    return 0;
}
