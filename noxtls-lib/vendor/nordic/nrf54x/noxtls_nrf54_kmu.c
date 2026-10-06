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
* File:    noxtls_nrf54_kmu.c
* Summary: nRF54L KMU key slots (provision, push, block, revoke, read metadata)
*
*****************************************************************************/

/**
 * @file noxtls_nrf54_kmu.c
 * @brief KMU driver (nRF54L product specifications, chapter "KMU - Key management unit").
 * @ingroup noxtls_nrf54
 *
 * Task sequence: wait for STATUS idle, write KEYSLOT, trigger the task, poll
 * for the task event, EVENTS_REVOKED or EVENTS_ERROR, then clear every event.
 */

#include <stddef.h>

#include "noxtls_nrf54_kmu.h"

/** Outcome of one KMU task. */
typedef enum {
    NOXTLS_NRF54_KMU_OK = 0,      /**< Task event. */
    NOXTLS_NRF54_KMU_REVOKED = 1, /**< EVENTS_REVOKED. */
    NOXTLS_NRF54_KMU_ERROR = 2,   /**< EVENTS_ERROR. */
    NOXTLS_NRF54_KMU_TIMEOUT = 3  /**< No event (or never idle). */
} noxtls_nrf54_kmu_res_t;

/** Events cleared after every task (EVENTS_BLOCKED exists on the nRF54LM20 only). */
static const uint32_t s_noxtls_nrf54_kmu_events[] = {
    NOXTLS_NRF54_KMU_EVENTS_PROVISIONED, NOXTLS_NRF54_KMU_EVENTS_PUSHED, NOXTLS_NRF54_KMU_EVENTS_REVOKED,
    NOXTLS_NRF54_KMU_EVENTS_ERROR, NOXTLS_NRF54_KMU_EVENTS_METAREAD, NOXTLS_NRF54_KMU_EVENTS_PUSHBLOCKED,
    NOXTLS_NRF54_KMU_EVENTS_BLOCKED
};

/** @brief Events of the nRF54L15 (all but EVENTS_BLOCKED). */
#define NOXTLS_NRF54_KMU_EVENTS_BASE    6U
/** @brief Events of the nRF54LM20. */
#define NOXTLS_NRF54_KMU_EVENTS_LITE    7U

/** RRAM write hook. */
static noxtls_nrf54_kmu_nvm_fn_t s_noxtls_nrf54_kmu_nvm;
/** Context of the RRAM write hook. */
static void *s_noxtls_nrf54_kmu_nvm_ctx;

/**
 * @brief Clear every KMU event.
 * @internal
 */
static void noxtls_nrf54_kmu_clear_events(void)
{
    uint32_t n = (noxtls_nrf54_cracen_hw()->variant == NOXTLS_NRF54_VARIANT_LITE) ? NOXTLS_NRF54_KMU_EVENTS_LITE :
                 NOXTLS_NRF54_KMU_EVENTS_BASE;
    uint32_t i;

    for (i = 0U; i < n; i++) {
        noxtls_nrf54_kmu_wr(s_noxtls_nrf54_kmu_events[i], NOXTLS_NRF54_EVENT_CLEAR);
    }
}

/**
 * @brief Run one task on one slot.
 * @internal
 *
 * @param[in] slot  Slot.
 * @param[in] task  Task register.
 * @param[in] event Success event register.
 *
 * @return Outcome.
 */
static noxtls_nrf54_kmu_res_t noxtls_nrf54_kmu_task(uint32_t slot, uint32_t task, uint32_t event)
{
    noxtls_nrf54_kmu_res_t res = NOXTLS_NRF54_KMU_TIMEOUT;
    uint32_t spins = (uint32_t)NOXTLS_NRF54_CONFIG_KMU_SPINS;

    while (((noxtls_nrf54_kmu_rd(NOXTLS_NRF54_KMU_STATUS) & NOXTLS_NRF54_KMU_ST_BUSY) != 0U) && (spins > 0U)) {
        spins--;
    }
    if (spins != 0U) {
        noxtls_nrf54_kmu_clear_events();
        noxtls_nrf54_kmu_wr(NOXTLS_NRF54_KMU_KEYSLOT, slot & NOXTLS_NRF54_KMU_SLOT_MSK);
        noxtls_nrf54_kmu_wr(task, NOXTLS_NRF54_KMU_TRIGGER);
        spins = (uint32_t)NOXTLS_NRF54_CONFIG_KMU_SPINS;
        while ((res == NOXTLS_NRF54_KMU_TIMEOUT) && (spins > 0U)) {
            if (noxtls_nrf54_kmu_rd(event) != 0U) {
                res = NOXTLS_NRF54_KMU_OK;
            } else if (noxtls_nrf54_kmu_rd(NOXTLS_NRF54_KMU_EVENTS_REVOKED) != 0U) {
                res = NOXTLS_NRF54_KMU_REVOKED;
            } else if (noxtls_nrf54_kmu_rd(NOXTLS_NRF54_KMU_EVENTS_ERROR) != 0U) {
                res = NOXTLS_NRF54_KMU_ERROR;
            } else {
                spins--;
            }
        }
        noxtls_nrf54_kmu_clear_events();
    }
    return res;
}

/**
 * @brief Map a task outcome of a slot operation.
 * @internal
 *
 * @param[in] res Outcome.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_FAILED or NOXTLS_RETURN_TIMEOUT.
 */
static noxtls_return_t noxtls_nrf54_kmu_map(noxtls_nrf54_kmu_res_t res)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if (res == NOXTLS_NRF54_KMU_OK) {
        rc = NOXTLS_RETURN_SUCCESS;
    } else if (res == NOXTLS_NRF54_KMU_TIMEOUT) {
        rc = NOXTLS_RETURN_TIMEOUT;
    } else {
        /* Revoked or error. */
    }
    return rc;
}

/**
 * @brief Validate a slot range.
 * @internal
 *
 * @param[in] slot  First slot.
 * @param[in] count Slots.
 *
 * @return 1 when valid.
 */
static uint8_t noxtls_nrf54_kmu_range_ok(uint32_t slot, uint32_t count)
{
    return ((count != 0U) && (slot < NOXTLS_NRF54_KMU_SLOTS) && (count <= (NOXTLS_NRF54_KMU_SLOTS - slot))) ? 1U : 0U;
}

/**
 * @brief Run a task on a slot range, stopping at the first failure.
 * @internal
 *
 * @param[in] slot  First slot.
 * @param[in] count Slots.
 * @param[in] task  Task register.
 * @param[in] event Success event register.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_INVALID_PARAM, NOXTLS_RETURN_FAILED or NOXTLS_RETURN_TIMEOUT.
 */
static noxtls_return_t noxtls_nrf54_kmu_range(uint32_t slot, uint32_t count, uint32_t task, uint32_t event)
{
    noxtls_return_t rc = (noxtls_nrf54_kmu_range_ok(slot, count) != 0U) ? NOXTLS_RETURN_SUCCESS :
                         NOXTLS_RETURN_INVALID_PARAM;
    uint32_t i;

    for (i = 0U; (rc == NOXTLS_RETURN_SUCCESS) && (i < count); i++) {
        rc = noxtls_nrf54_kmu_map(noxtls_nrf54_kmu_task(slot + i, task, event));
    }
    return rc;
}

/**
 * @brief Call the RRAM write hook when installed.
 * @internal
 *
 * @param[in] enable 1 before, 0 after.
 *
 * @return Hook result, or NOXTLS_RETURN_SUCCESS without a hook.
 */
static noxtls_return_t noxtls_nrf54_kmu_nvm(uint8_t enable)
{
    return (s_noxtls_nrf54_kmu_nvm != NULL) ? s_noxtls_nrf54_kmu_nvm(s_noxtls_nrf54_kmu_nvm_ctx, enable) :
           NOXTLS_RETURN_SUCCESS;
}

void noxtls_nrf54_kmu_set_nvm_hook(noxtls_nrf54_kmu_nvm_fn_t fn, void *ctx)
{
    s_noxtls_nrf54_kmu_nvm = fn;
    s_noxtls_nrf54_kmu_nvm_ctx = ctx;
}

noxtls_return_t noxtls_nrf54_kmu_read_metadata(uint32_t slot, uint32_t *metadata, noxtls_nrf54_kmu_state_t *state)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if ((metadata == NULL) || (state == NULL)) {
        rc = NOXTLS_RETURN_NULL;
    } else if (noxtls_nrf54_kmu_range_ok(slot, 1U) == 0U) {
        rc = NOXTLS_RETURN_INVALID_PARAM;
    } else {
        noxtls_nrf54_kmu_res_t res = noxtls_nrf54_kmu_task(slot, NOXTLS_NRF54_KMU_TASKS_READMETA,
                                                           NOXTLS_NRF54_KMU_EVENTS_METAREAD);

        *metadata = 0U;
        if (res == NOXTLS_NRF54_KMU_OK) {
            *metadata = noxtls_nrf54_kmu_rd(NOXTLS_NRF54_KMU_METADATA);
            *state = NOXTLS_NRF54_KMU_SLOT_PROVISIONED;
        } else if (res == NOXTLS_NRF54_KMU_REVOKED) {
            *state = NOXTLS_NRF54_KMU_SLOT_REVOKED;
        } else if (res == NOXTLS_NRF54_KMU_ERROR) {
            *state = NOXTLS_NRF54_KMU_SLOT_EMPTY;
        } else {
            rc = NOXTLS_RETURN_TIMEOUT;
        }
    }
    return rc;
}

noxtls_return_t noxtls_nrf54_kmu_push(uint32_t slot, uint32_t count)
{
    return noxtls_nrf54_kmu_range(slot, count, NOXTLS_NRF54_KMU_TASKS_PUSH, NOXTLS_NRF54_KMU_EVENTS_PUSHED);
}

noxtls_return_t noxtls_nrf54_kmu_push_block(uint32_t slot, uint32_t count)
{
    return noxtls_nrf54_kmu_range(slot, count, NOXTLS_NRF54_KMU_TASKS_PUSHBLOCK, NOXTLS_NRF54_KMU_EVENTS_PUSHBLOCKED);
}

noxtls_return_t noxtls_nrf54_kmu_block(uint32_t slot, uint32_t count)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;

    if (noxtls_nrf54_cracen_hw()->variant == NOXTLS_NRF54_VARIANT_LITE) {
        rc = noxtls_nrf54_kmu_range(slot, count, NOXTLS_NRF54_KMU_TASKS_BLOCK, NOXTLS_NRF54_KMU_EVENTS_BLOCKED);
    }
    return rc;
}

noxtls_return_t noxtls_nrf54_kmu_provision(uint32_t slot, const noxtls_nrf54_kmu_slot_data_t *data)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if (data == NULL) {
        rc = NOXTLS_RETURN_NULL;
    } else if (noxtls_nrf54_kmu_range_ok(slot, 1U) == 0U) {
        rc = NOXTLS_RETURN_INVALID_PARAM;
    } else {
        rc = noxtls_nrf54_kmu_nvm(1U);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_nrf54_kmu_wr(NOXTLS_NRF54_KMU_SRC, (uint32_t)(uintptr_t)data);
            rc = noxtls_nrf54_kmu_map(noxtls_nrf54_kmu_task(slot, NOXTLS_NRF54_KMU_TASKS_PROVISION,
                                                            NOXTLS_NRF54_KMU_EVENTS_PROVISIONED));
            (void)noxtls_nrf54_kmu_nvm(0U);
        }
    }
    return rc;
}

noxtls_return_t noxtls_nrf54_kmu_revoke(uint32_t slot, uint32_t count)
{
    noxtls_return_t rc = (noxtls_nrf54_kmu_range_ok(slot, count) != 0U) ? NOXTLS_RETURN_SUCCESS :
                         NOXTLS_RETURN_INVALID_PARAM;

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_nrf54_kmu_nvm(1U);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_nrf54_kmu_range(slot, count, NOXTLS_NRF54_KMU_TASKS_REVOKE, NOXTLS_NRF54_KMU_EVENTS_REVOKED);
            (void)noxtls_nrf54_kmu_nvm(0U);
        }
    }
    return rc;
}
