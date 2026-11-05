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
* File:    noxtls_efr32_engine_lock.h
* Summary: Shared-engine ownership contract of the EFR32xG2x backend
*
*****************************************************************************/

/**
 * @file noxtls_efr32_engine_lock.h
 * @brief Ownership of the RADIOAES engine and the Secure Engine mailbox, shared
 *        with other drivers on the chip (for example the BlueNox link layer).
 * @ingroup noxtls_efr32
 *
 * Contract (nox-driver-lib platforms/efr32xg2x/EFR32XG2X_PORT_DESIGN.md §8):
 * every user of an engine takes a lock-free, interrupt-safe, never-blocking
 * try-acquire flag before touching it and gives it back afterwards. The
 * application binds the other driver's try-acquire / release pair with
 * noxtls_efr32_engine_lock_bind() so one flag covers both users; unbound,
 * NoxTLS uses its own internal flags.
 *
 * - RADIOAES: noxtls never waits. When the engine is owned the request is
 *   served by the NoxTLS software implementation.
 * - Secure Engine: noxtls retries the try-acquire for a bounded budget
 *   (NOXTLS_EFR32_CONFIG_SE_ACQUIRE_TRIES attempts, NOXTLS_EFR32_CONFIG_SE_ACQUIRE_SPINS
 *   polls apart), then serves the request in software or, where no software
 *   path exists, reports it unsupported so the caller falls back.
 */
#ifndef NOXTLS_EFR32_ENGINE_LOCK_H
#define NOXTLS_EFR32_ENGINE_LOCK_H

#include <stdbool.h>
#include <stdint.h>

#include "noxtls_efr32_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Try-acquire / release pairs of the engines. Each pair must be complete (both
 * hooks set) or absent (both NULL); an absent pair keeps the internal flag.
 * The functions match noxdrv_efr32_radioaes_try_acquire() / _release() and
 * noxdrv_efr32_semailbox_try_acquire() / _release() of nox-driver-lib.
 */
typedef struct {
    bool (*aes_try_acquire)(void);  /**< RADIOAES try-acquire: true when the caller now owns the engine. */
    void (*aes_release)(void);      /**< RADIOAES release. */
    bool (*se_try_acquire)(void);   /**< SEMAILBOX try-acquire. */
    void (*se_release)(void);       /**< SEMAILBOX release. */
} noxtls_efr32_engine_lock_t;

/**
 * @brief Bind the engine ownership functions of another driver.
 *
 * @param[in] ops Pairs to use; NULL restores the internal flags.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL (an incomplete pair) or
 *         NOXTLS_RETURN_FAILED (an engine is currently owned by NoxTLS).
 */
noxtls_return_t noxtls_efr32_engine_lock_bind(const noxtls_efr32_engine_lock_t *ops);

/**
 * @brief Take the RADIOAES engine once, without waiting, and enable its clocks.
 *
 * @return NOXTLS_RETURN_SUCCESS, or NOXTLS_RETURN_NOT_SUPPORTED when the unit is
 *         disabled or the engine is owned (use software).
 */
noxtls_return_t noxtls_efr32_aes_acquire(void);

/** @brief Give the RADIOAES engine back. */
void noxtls_efr32_aes_release(void);

/**
 * @brief Take the Secure Engine mailbox, retrying for the configured budget, and enable its clock.
 *
 * @return NOXTLS_RETURN_SUCCESS, or NOXTLS_RETURN_NOT_SUPPORTED when the unit is
 *         disabled, was declared hung after a timeout, or stayed owned for the whole budget.
 */
noxtls_return_t noxtls_efr32_se_acquire(void);

/** @brief Give the Secure Engine mailbox back. */
void noxtls_efr32_se_release(void);

/**
 * @brief Declare the Secure Engine hung (or healthy again).
 *
 * A command that timed out may still be writing into the module's buffers, so
 * after a timeout the mailbox is not used again until the application clears
 * the condition.
 *
 * @param[in] hung Non-zero to refuse every further Secure Engine request, zero to clear.
 */
void noxtls_efr32_se_set_hung(uint8_t hung);

/**
 * @brief Whether the Secure Engine was declared hung.
 *
 * @return 1 when hung, 0 otherwise.
 */
uint8_t noxtls_efr32_se_is_hung(void);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_EFR32_ENGINE_LOCK_H */
