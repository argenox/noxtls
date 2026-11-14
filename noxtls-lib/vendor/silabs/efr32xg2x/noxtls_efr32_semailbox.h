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
* File:    noxtls_efr32_semailbox.h
* Summary: EFR32xG2x Secure Engine mailbox transport
*
*****************************************************************************/

/**
 * @file noxtls_efr32_semailbox.h
 * @brief Command transport of the Secure Engine mailbox (SEMAILBOX_HOST), with
 *        bounded waits and response-code mapping.
 * @ingroup noxtls_efr32
 *
 * A command is the word sequence (EFR32xG26 RM, chapter "SEMAILBOX"; message
 * layout as used by the Zlib-licensed Simplicity SDK v2025.6.3
 * sli_se_manager_mailbox.c): TX_HEADER = 4 * (4 + number of parameters), then
 * the command word, the address of the input transfer chain, the address of
 * the output transfer chain and the parameters, written to the FIFO. The SE
 * reads and writes the host buffers by DMA through the transfer chains and
 * answers with a response code in RX_HEADER.
 *
 * The caller owns the mailbox (noxtls_efr32_se_acquire()) from before the
 * buffers are filled until the results were read. A command that does not
 * answer in time may still be using the buffers, so the mailbox is then
 * declared hung (noxtls_efr32_se_set_hung()) and refused until the application
 * clears the condition.
 */
#ifndef NOXTLS_EFR32_SEMAILBOX_H
#define NOXTLS_EFR32_SEMAILBOX_H

#include <stdint.h>

#include "noxtls_efr32_engine_lock.h"

#ifdef __cplusplus
extern "C" {
#endif

/** One SE DMA transfer (data address, next transfer or NOXTLS_EFR32_SE_XFER_STOP, length | flags). */
typedef struct {
    uint32_t data;   /**< Data address. */
    uint32_t next;   /**< Next transfer or NOXTLS_EFR32_SE_XFER_STOP. */
    uint32_t length; /**< Byte count | NOXTLS_EFR32_SE_XFER_REALIGN. */
} noxtls_efr32_se_xfer_t;

/** One Secure Engine command. */
typedef struct {
    uint32_t command;                                 /**< Command word (with options). */
    const noxtls_efr32_se_xfer_t *in;                 /**< First input transfer (NULL: none). */
    const noxtls_efr32_se_xfer_t *out;                /**< First output transfer (NULL: none). */
    uint32_t params[NOXTLS_EFR32_SEM_PARAMS_MAX];     /**< Parameters. */
    uint32_t nparams;                                 /**< Number of parameters. */
} noxtls_efr32_se_cmd_t;

/**
 * @brief Describe one transfer (last of its chain, realigned).
 *
 * @param[out] xfer Transfer.
 * @param[in]  data Data (may be NULL for a zero-length transfer).
 * @param[in]  len  Bytes.
 */
void noxtls_efr32_se_xfer_set(noxtls_efr32_se_xfer_t *xfer, const void *data, uint32_t len);

/**
 * @brief Link @p xfer in front of @p next.
 *
 * @param[in,out] xfer Transfer that receives the link.
 * @param[in]     next Following transfer.
 */
void noxtls_efr32_se_xfer_link(noxtls_efr32_se_xfer_t *xfer, const noxtls_efr32_se_xfer_t *next);

/**
 * @brief Map a Secure Engine response code to a NoxTLS result.
 *
 * @param[in] response RX_HEADER & NOXTLS_EFR32_SE_RESPONSE_MASK.
 *
 * @return NOXTLS_RETURN_SUCCESS (OK), NOXTLS_RETURN_BAD_DATA (invalid signature),
 *         NOXTLS_RETURN_INVALID_PARAM (invalid parameter), NOXTLS_RETURN_NOT_SUPPORTED
 *         (invalid command, authorization, not initialized, abort) or NOXTLS_RETURN_FAILED.
 */
noxtls_return_t noxtls_efr32_se_map_response(uint32_t response);

/**
 * @brief Send a command and wait for its response (mailbox owned by the caller).
 *
 * @param[in] cmd        Command.
 * @param[in] timeout_us Response budget in microseconds.
 *
 * @return NOXTLS_RETURN_SUCCESS or the mapped response code; NOXTLS_RETURN_TIMEOUT
 *         when the mailbox did not take the command (nothing sent) or did not answer
 *         (the mailbox is then declared hung); NOXTLS_RETURN_INVALID_PARAM for too many parameters.
 */
noxtls_return_t noxtls_efr32_se_run(const noxtls_efr32_se_cmd_t *cmd, uint32_t timeout_us);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_EFR32_SEMAILBOX_H */
