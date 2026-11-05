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
* File:    noxtls_efr32_engine_lock.c
* Summary: Shared-engine ownership contract of the EFR32xG2x backend
*
*****************************************************************************/

/**
 * @file noxtls_efr32_engine_lock.c
 * @brief Try-acquire / release of the RADIOAES engine and the Secure Engine mailbox.
 * @ingroup noxtls_efr32
 *
 * RADIOAES is acquired once without waiting (the BlueNox link layer uses the
 * same engine between packets and never waits either). The Secure Engine is
 * acquired with a bounded retry budget. Acquisition also switches on the bus
 * clocks the engine needs (EFR32xG26 RM, CMU: CLKEN0.RADIOAES, CLKEN1.SEMAILBOXHOST,
 * RADIOCLKCTRL.EN); the clocks are left on because the other driver shares them.
 */

#include <stddef.h>

#include "noxtls_efr32_engine_lock.h"

/** Bound ownership functions (all NULL: internal flags). */
static noxtls_efr32_engine_lock_t s_noxtls_efr32_lock;

/** Non-zero when the Secure Engine was declared hung. */
static uint8_t s_noxtls_efr32_se_hung;

/**
 * @brief One try-acquire of the AES engine through the bound hook or the internal flag.
 * @internal
 *
 * @return 1 when taken.
 */
static uint8_t noxtls_efr32_aes_take(void)
{
    uint8_t ok;

    if (s_noxtls_efr32_lock.aes_try_acquire != NULL) {
        ok = s_noxtls_efr32_lock.aes_try_acquire() ? 1U : 0U;
    } else {
        ok = noxtls_efr32_flag_op(NOXTLS_EFR32_UNIT_AES, 1U);
    }
    return ok;
}

/**
 * @brief One try-acquire of the Secure Engine through the bound hook or the internal flag.
 * @internal
 *
 * @return 1 when taken.
 */
static uint8_t noxtls_efr32_se_take(void)
{
    uint8_t ok;

    if (s_noxtls_efr32_lock.se_try_acquire != NULL) {
        ok = s_noxtls_efr32_lock.se_try_acquire() ? 1U : 0U;
    } else {
        ok = noxtls_efr32_flag_op(NOXTLS_EFR32_UNIT_SE, 1U);
    }
    return ok;
}

noxtls_return_t noxtls_efr32_engine_lock_bind(const noxtls_efr32_engine_lock_t *ops)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if ((ops != NULL) && (((ops->aes_try_acquire == NULL) != (ops->aes_release == NULL)) ||
                          ((ops->se_try_acquire == NULL) != (ops->se_release == NULL)))) {
        rc = NOXTLS_RETURN_NULL;
    } else if (noxtls_efr32_flag_op(NOXTLS_EFR32_UNIT_AES, 1U) == 0U) {
        rc = NOXTLS_RETURN_FAILED;
    } else if (noxtls_efr32_flag_op(NOXTLS_EFR32_UNIT_SE, 1U) == 0U) {
        (void)noxtls_efr32_flag_op(NOXTLS_EFR32_UNIT_AES, 0U);
        rc = NOXTLS_RETURN_FAILED;
    } else {
        /* Both internal flags are held, so no internal user is inside an engine while the binding changes. */
        if (ops == NULL) {
            s_noxtls_efr32_lock.aes_try_acquire = NULL;
            s_noxtls_efr32_lock.aes_release = NULL;
            s_noxtls_efr32_lock.se_try_acquire = NULL;
            s_noxtls_efr32_lock.se_release = NULL;
        } else {
            s_noxtls_efr32_lock = *ops;
        }
        (void)noxtls_efr32_flag_op(NOXTLS_EFR32_UNIT_SE, 0U);
        (void)noxtls_efr32_flag_op(NOXTLS_EFR32_UNIT_AES, 0U);
    }
    return rc;
}

noxtls_return_t noxtls_efr32_aes_acquire(void)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;

    if (noxtls_efr32_is_enabled(NOXTLS_EFR32_UNIT_AES) != 0U) {
        if (noxtls_efr32_aes_take() == 0U) {
            noxtls_efr32_stats_rw()->aes_busy++;
        } else {
            noxtls_efr32_stats_rw()->aes_acquires++;
            noxtls_efr32_cmu_wr(NOXTLS_EFR32_CMU_CLKEN0_SET, NOXTLS_EFR32_CMU_CLKEN0_RADIOAES);
            noxtls_efr32_cmu_wr(NOXTLS_EFR32_CMU_RADIOCLKCTRL_SET, NOXTLS_EFR32_CMU_RADIOCLK_EN);
            noxtls_efr32_aes_wr(NOXTLS_EFR32_AES_IEN, NOXTLS_EFR32_AES_IEN_NONE);
            rc = NOXTLS_RETURN_SUCCESS;
        }
    }
    return rc;
}

void noxtls_efr32_aes_release(void)
{
    if (s_noxtls_efr32_lock.aes_release != NULL) {
        s_noxtls_efr32_lock.aes_release();
    } else {
        (void)noxtls_efr32_flag_op(NOXTLS_EFR32_UNIT_AES, 0U);
    }
}

noxtls_return_t noxtls_efr32_se_acquire(void)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;

    if ((noxtls_efr32_is_enabled(NOXTLS_EFR32_UNIT_SE) != 0U) && (s_noxtls_efr32_se_hung == 0U)) {
        uint32_t tries = (uint32_t)NOXTLS_EFR32_CONFIG_SE_ACQUIRE_TRIES;
        uint8_t taken = 0U;

        while ((taken == 0U) && (tries > 0U)) {
            uint32_t spins = (uint32_t)NOXTLS_EFR32_CONFIG_SE_ACQUIRE_SPINS;

            taken = noxtls_efr32_se_take();
            tries--;
            while ((taken == 0U) && (tries > 0U) && (spins > 0U)) {
                spins--;
                (void)noxtls_efr32_sem_rd(NOXTLS_EFR32_SEM_TX_STATUS);
            }
        }
        if (taken == 0U) {
            noxtls_efr32_stats_rw()->se_busy++;
        } else {
            noxtls_efr32_stats_rw()->se_acquires++;
            noxtls_efr32_cmu_wr(NOXTLS_EFR32_CMU_CLKEN1_SET, NOXTLS_EFR32_CMU_CLKEN1_SEMAILBOX);
            rc = NOXTLS_RETURN_SUCCESS;
        }
    }
    return rc;
}

void noxtls_efr32_se_release(void)
{
    if (s_noxtls_efr32_lock.se_release != NULL) {
        s_noxtls_efr32_lock.se_release();
    } else {
        (void)noxtls_efr32_flag_op(NOXTLS_EFR32_UNIT_SE, 0U);
    }
}

void noxtls_efr32_se_set_hung(uint8_t hung)
{
    s_noxtls_efr32_se_hung = (hung != 0U) ? 1U : 0U;
}

uint8_t noxtls_efr32_se_is_hung(void)
{
    return s_noxtls_efr32_se_hung;
}
