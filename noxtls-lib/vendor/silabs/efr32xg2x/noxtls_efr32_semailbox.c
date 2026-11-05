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
* File:    noxtls_efr32_semailbox.c
* Summary: EFR32xG2x Secure Engine mailbox transport
*
*****************************************************************************/

/**
 * @file noxtls_efr32_semailbox.c
 * @brief Secure Engine mailbox command transport with bounded waits.
 * @ingroup noxtls_efr32
 */

#include <stddef.h>

#include "noxtls_efr32_semailbox.h"

void noxtls_efr32_se_xfer_set(noxtls_efr32_se_xfer_t *xfer, const void *data, uint32_t len)
{
    xfer->data = (uint32_t)(uintptr_t)data;
    xfer->next = NOXTLS_EFR32_SE_XFER_STOP;
    xfer->length = (len & NOXTLS_EFR32_SE_XFER_LEN_MSK) | NOXTLS_EFR32_SE_XFER_REALIGN;
}

void noxtls_efr32_se_xfer_link(noxtls_efr32_se_xfer_t *xfer, const noxtls_efr32_se_xfer_t *next)
{
    xfer->next = (uint32_t)(uintptr_t)next;
}

noxtls_return_t noxtls_efr32_se_map_response(uint32_t response)
{
    noxtls_return_t rc;

    switch (response) {
    case NOXTLS_EFR32_SE_RESP_OK:
        rc = NOXTLS_RETURN_SUCCESS;
        break;
    case NOXTLS_EFR32_SE_RESP_INVALID_SIG:
        rc = NOXTLS_RETURN_BAD_DATA;
        break;
    case NOXTLS_EFR32_SE_RESP_INVALID_PARAM:
        rc = NOXTLS_RETURN_INVALID_PARAM;
        break;
    case NOXTLS_EFR32_SE_RESP_INVALID_CMD:
    case NOXTLS_EFR32_SE_RESP_AUTH_ERROR:
    case NOXTLS_EFR32_SE_RESP_NOT_INIT:
    case NOXTLS_EFR32_SE_RESP_ABORT:
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
        break;
    default:
        /* Bus error, internal error, crypto error, self-test failure and codes this backend does not know. */
        rc = NOXTLS_RETURN_FAILED;
        break;
    }
    return rc;
}

/**
 * @brief Poll a status register for a flag with a bounded budget.
 * @internal
 *
 * @param[in] reg        Register offset.
 * @param[in] flag       Flag to wait for.
 * @param[in] timeout_us Budget in microseconds.
 *
 * @return 1 when the flag was seen, 0 on timeout.
 */
static uint8_t noxtls_efr32_se_wait(uint32_t reg, uint32_t flag, uint32_t timeout_us)
{
    uint64_t spins = noxtls_efr32_us_to_spins(timeout_us);
    uint32_t value = noxtls_efr32_sem_rd(reg);

    while (((value & flag) == 0U) && (spins > 0U)) {
        spins--;
        value = noxtls_efr32_sem_rd(reg);
    }
    return ((value & flag) != 0U) ? 1U : 0U;
}

noxtls_return_t noxtls_efr32_se_run(const noxtls_efr32_se_cmd_t *cmd, uint32_t timeout_us)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    noxtls_efr32_stats_rw()->se_commands++;
    if (cmd->nparams > NOXTLS_EFR32_SEM_PARAMS_MAX) {
        rc = NOXTLS_RETURN_INVALID_PARAM;
    } else if (noxtls_efr32_se_wait(NOXTLS_EFR32_SEM_TX_STATUS, NOXTLS_EFR32_SEM_TXINT,
                                    (uint32_t)NOXTLS_EFR32_CONFIG_SE_TX_TIMEOUT_US) == 0U) {
        /* The mailbox never offered room: nothing was sent. */
        noxtls_efr32_stats_rw()->se_timeouts++;
        rc = NOXTLS_RETURN_TIMEOUT;
    } else {
        uint32_t i;

        noxtls_efr32_barrier();
        noxtls_efr32_sem_wr(NOXTLS_EFR32_SEM_TX_HEADER,
                            NOXTLS_EFR32_SEM_WORD_BYTES * (NOXTLS_EFR32_SEM_HEADER_WORDS + cmd->nparams));
        noxtls_efr32_sem_wr(NOXTLS_EFR32_SEM_FIFO, cmd->command);
        noxtls_efr32_sem_wr(NOXTLS_EFR32_SEM_FIFO, (uint32_t)(uintptr_t)cmd->in);
        noxtls_efr32_sem_wr(NOXTLS_EFR32_SEM_FIFO, (uint32_t)(uintptr_t)cmd->out);
        for (i = 0U; i < cmd->nparams; i++) {
            noxtls_efr32_sem_wr(NOXTLS_EFR32_SEM_FIFO, cmd->params[i]);
        }
        if (noxtls_efr32_se_wait(NOXTLS_EFR32_SEM_RX_STATUS, NOXTLS_EFR32_SEM_RXINT, timeout_us) == 0U) {
            /* The SE may still be using the host buffers: refuse the mailbox from now on. */
            noxtls_efr32_se_set_hung(1U);
            noxtls_efr32_stats_rw()->se_timeouts++;
            rc = NOXTLS_RETURN_TIMEOUT;
        } else {
            uint32_t response = noxtls_efr32_sem_rd(NOXTLS_EFR32_SEM_RX_HEADER) & NOXTLS_EFR32_SE_RESPONSE_MASK;

            noxtls_efr32_barrier();
            rc = noxtls_efr32_se_map_response(response);
            if (rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_efr32_stats_rw()->se_errors++;
            }
        }
    }
    return rc;
}
