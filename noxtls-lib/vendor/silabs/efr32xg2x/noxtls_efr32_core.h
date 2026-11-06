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
* File:    noxtls_efr32_core.h
* Summary: EFR32xG2x backend core: register access seam, DMA windows, engine ownership
*
*****************************************************************************/

/**
 * @defgroup noxtls_efr32 NoxTLS EFR32xG2x hardware backend
 * @brief Register-level RADIOAES (BA411E) and Secure Engine mailbox drivers and
 *        the NoxTLS accelerator ports served by them.
 */

/**
 * @file noxtls_efr32_core.h
 * @brief Register access seam, DMA windows, run-time enables, statistics and the
 *        engine ownership flags shared by the backend modules.
 * @ingroup noxtls_efr32
 *
 * All register accesses go through noxtls_efr32_io_t so the host unit tests can
 * map the peripherals onto memory. The two engines (RADIOAES and the Secure
 * Engine mailbox) are shared with other drivers on the same chip (for example
 * the BlueNox link layer); ownership follows the contract of
 * noxtls_efr32_engine_lock.h.
 */
#ifndef NOXTLS_EFR32_CORE_H
#define NOXTLS_EFR32_CORE_H

#include <stdint.h>

#include "noxtls_common.h"
#include "noxtls_efr32_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Unit selector: the RADIOAES (BA411E) engine. */
#define NOXTLS_EFR32_UNIT_AES       0x1U
/** @brief Unit selector: the Secure Engine (mailbox). */
#define NOXTLS_EFR32_UNIT_SE        0x2U
/** @brief Both units. */
#define NOXTLS_EFR32_UNIT_ALL       (NOXTLS_EFR32_UNIT_AES | NOXTLS_EFR32_UNIT_SE)

/** Register access layer (replaceable for host tests). */
typedef struct {
    uint32_t (*read32)(uintptr_t addr);              /**< Read a 32-bit register. */
    void (*write32)(uintptr_t addr, uint32_t value); /**< Write a 32-bit register. */
} noxtls_efr32_io_t;

/** Peripheral instances used by the backend. */
typedef struct {
    uintptr_t aes;  /**< RADIOAES. */
    uintptr_t sem;  /**< SEMAILBOX_HOST. */
    uintptr_t cmu;  /**< CMU. */
} noxtls_efr32_hw_t;

/** Counters of the backend (read with noxtls_efr32_stats()). */
typedef struct {
    uint32_t aes_acquires;   /**< Successful RADIOAES acquisitions. */
    uint32_t aes_busy;       /**< RADIOAES requests refused because the engine was in use. */
    uint32_t aes_jobs;       /**< RADIOAES jobs started. */
    uint32_t aes_errors;     /**< RADIOAES jobs that failed (bus error). */
    uint32_t aes_timeouts;   /**< RADIOAES jobs that timed out. */
    uint32_t se_acquires;    /**< Successful Secure Engine acquisitions. */
    uint32_t se_busy;        /**< Secure Engine requests refused after the retry budget. */
    uint32_t se_commands;    /**< Secure Engine commands issued. */
    uint32_t se_errors;      /**< Secure Engine commands that returned an error response. */
    uint32_t se_timeouts;    /**< Secure Engine commands that timed out. */
    uint32_t se_rejects;     /**< Secure Engine verify commands that answered "invalid signature" (a valid result, not an error). */
    uint32_t se_last_cmd;    /**< Command word of the last Secure Engine command that returned an error response. */
    uint32_t se_last_resp;   /**< Response code of that command (RX_HEADER masked with NOXTLS_EFR32_SE_RESPONSE_MASK). */
} noxtls_efr32_stats_t;

/**
 * @brief Replace the register access layer.
 *
 * @param[in] io New layer; NULL restores the memory-mapped default.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL (a hook is NULL) or
 *         NOXTLS_RETURN_FAILED (an engine is currently owned).
 */
noxtls_return_t noxtls_efr32_io_set(const noxtls_efr32_io_t *io);

/**
 * @brief Replace the peripheral base addresses (host tests, non-default instances).
 *
 * @param[in] hw New instances; NULL restores the build defaults.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_FAILED (an engine is currently owned).
 */
noxtls_return_t noxtls_efr32_hw_set(const noxtls_efr32_hw_t *hw);

/**
 * @brief Enable or disable the hardware paths of one or both units at run time.
 *
 * @param[in] units   NOXTLS_EFR32_UNIT_* mask.
 * @param[in] enabled Non-zero to enable; a disabled unit makes every operation fall back to software.
 */
void noxtls_efr32_set_enabled(uint32_t units, uint8_t enabled);

/**
 * @brief Whether a unit is enabled.
 *
 * @param[in] unit NOXTLS_EFR32_UNIT_AES or NOXTLS_EFR32_UNIT_SE.
 *
 * @return 1 when enabled, 0 otherwise.
 */
uint8_t noxtls_efr32_is_enabled(uint32_t unit);

/** @brief Secure Engine operation bit: SHA-256 compression. */
#define NOXTLS_EFR32_OP_SHA256      0x01U
/** @brief Secure Engine operation bit: SHA-512 compression. */
#define NOXTLS_EFR32_OP_SHA512      0x02U
/** @brief Secure Engine operation bit: TRNG. */
#define NOXTLS_EFR32_OP_TRNG        0x04U
/** @brief Secure Engine operation bit: point multiplication / ECDH. */
#define NOXTLS_EFR32_OP_ECC_MUL     0x08U
/** @brief Secure Engine operation bit: ECDSA sign. */
#define NOXTLS_EFR32_OP_ECDSA_SIGN  0x10U
/** @brief Secure Engine operation bit: ECDSA verify. */
#define NOXTLS_EFR32_OP_ECDSA_VERIFY 0x20U

/**
 * @brief Refuse Secure Engine operations at run time (for example after a failed self-test); they then use software.
 *
 * @param[in] ops NOXTLS_EFR32_OP_* mask to disable; 0 re-enables everything.
 */
void noxtls_efr32_set_ops_disabled(uint32_t ops);

/**
 * @brief Whether a Secure Engine operation may run.
 *
 * @param[in] op One NOXTLS_EFR32_OP_* bit.
 *
 * @return 1 when allowed, 0 when disabled.
 */
uint8_t noxtls_efr32_op_allowed(uint32_t op);

/**
 * @brief Counters since start-up or the last reset.
 *
 * @return Counters (never NULL).
 */
const noxtls_efr32_stats_t *noxtls_efr32_stats(void);

/** @brief Clear the counters. */
void noxtls_efr32_reset_stats(void);

/**
 * @brief Read a RADIOAES register.
 *
 * @param[in] off Register offset.
 *
 * @return Value.
 */
uint32_t noxtls_efr32_aes_rd(uint32_t off);

/**
 * @brief Write a RADIOAES register.
 *
 * @param[in] off   Register offset.
 * @param[in] value Value.
 */
void noxtls_efr32_aes_wr(uint32_t off, uint32_t value);

/**
 * @brief Read a SEMAILBOX_HOST register.
 *
 * @param[in] off Register offset.
 *
 * @return Value.
 */
uint32_t noxtls_efr32_sem_rd(uint32_t off);

/**
 * @brief Write a SEMAILBOX_HOST register.
 *
 * @param[in] off   Register offset.
 * @param[in] value Value.
 */
void noxtls_efr32_sem_wr(uint32_t off, uint32_t value);

/**
 * @brief Write a CMU register (clock enables use the SET aliases).
 *
 * @param[in] off   Register offset.
 * @param[in] value Value.
 */
void noxtls_efr32_cmu_wr(uint32_t off, uint32_t value);

/** @brief Make descriptor and operand writes visible to the DMA (data synchronisation barrier). */
void noxtls_efr32_barrier(void);

/**
 * @brief Zero a buffer in a way the compiler cannot remove.
 *
 * @param[out] buf Buffer.
 * @param[in]  len Bytes.
 */
void noxtls_efr32_wipe(void *buf, uint32_t len);

/**
 * @brief Whether every byte of a buffer is zero (single pass, no early exit).
 *
 * @param[in] buf Buffer.
 * @param[in] len Bytes.
 *
 * @return 1 when all bytes are zero, 0 otherwise.
 */
uint8_t noxtls_efr32_is_zero(const uint8_t *buf, uint32_t len);

/**
 * @brief Convert a time budget to a poll count.
 *
 * @param[in] timeout_us Microseconds.
 *
 * @return Poll iterations (at least 1).
 */
uint64_t noxtls_efr32_us_to_spins(uint32_t timeout_us);

/**
 * @brief Whether the DMA can read @p len bytes at @p buf (flash or SRAM, aligned as configured).
 *
 * @param[in] buf Buffer.
 * @param[in] len Bytes.
 *
 * @return 1 when reachable, 0 otherwise.
 */
uint8_t noxtls_efr32_dma_in_ok(const void *buf, uint32_t len);

/**
 * @brief Whether the DMA can write @p len bytes at @p buf (SRAM, aligned as configured).
 *
 * @param[in] buf Buffer.
 * @param[in] len Bytes.
 *
 * @return 1 when reachable, 0 otherwise.
 */
uint8_t noxtls_efr32_dma_out_ok(const void *buf, uint32_t len);

/**
 * @brief Override the DMA windows and the required alignment (host tests).
 *
 * @param[in] in_start  Input window start.
 * @param[in] in_size   Input window bytes (0 restores the build defaults for all four values).
 * @param[in] out_start Output window start.
 * @param[in] out_size  Output window bytes.
 * @param[in] align     Required buffer alignment in bytes (>= 1).
 */
void noxtls_efr32_set_dma_window(uintptr_t in_start, uintptr_t in_size, uintptr_t out_start, uintptr_t out_size,
                                 uint32_t align);

/**
 * @brief Take or release the internal ownership flag of a unit (used by noxtls_efr32_engine_lock.c).
 *
 * @param[in] unit  NOXTLS_EFR32_UNIT_AES or NOXTLS_EFR32_UNIT_SE.
 * @param[in] take  Non-zero to take the flag, zero to give it back.
 *
 * @return For a take: 1 when the flag was free and is now taken, 0 when it was already taken. Always 1 for a give.
 */
uint8_t noxtls_efr32_flag_op(uint32_t unit, uint8_t take);

/**
 * @brief Counters for the other modules (mutable access).
 *
 * @return Counters (never NULL).
 */
noxtls_efr32_stats_t *noxtls_efr32_stats_rw(void);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_EFR32_CORE_H */
