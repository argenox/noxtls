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
* File:    noxtls_speed_bench.h
* Summary: Shared framework of the EFR32xG26 NoxTLS speed benchmark
*
*****************************************************************************/

/**
 * @file noxtls_speed_bench.h
 * @brief Backend selection, result rows and pass / fail accounting of the speed benchmark.
 * @ingroup noxtls_speed
 *
 * The NoxTLS EFR32 backend is chosen at run time with noxtls_efr32_set_enabled():
 * with both units disabled every operation takes the portable software path, so
 * one image times both backends on the same inputs.
 */
#ifndef NOXTLS_SPEED_BENCH_H
#define NOXTLS_SPEED_BENCH_H

#include <stdint.h>

#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Column width of the operation name. */
#define NOXTLS_SPEED_COL_OP         20U
/** @brief Column width of the size. */
#define NOXTLS_SPEED_COL_SIZE       6U
/** @brief Column width of the cycle counts. */
#define NOXTLS_SPEED_COL_CYCLES     11U
/** @brief Column width of the speed-up. */
#define NOXTLS_SPEED_COL_SPEEDUP    9U
/** @brief Column width of the hardware-used flag. */
#define NOXTLS_SPEED_COL_HW         5U

/** Backend of the next operations. */
typedef enum {
    NOXTLS_SPEED_BACKEND_SW = 0, /**< Portable NoxTLS software implementation. */
    NOXTLS_SPEED_BACKEND_HW = 1  /**< EFR32 hardware backend (RADIOAES + Secure Engine). */
} noxtls_speed_backend_t;

/** One result row of the table. */
typedef struct {
    const char *op;        /**< Operation name. */
    uint32_t size;         /**< Payload size in bytes (0 when not applicable). */
    uint32_t sw_cycles;    /**< Software cycles per operation (0 when there is no software equivalent). */
    uint32_t hw_cycles;    /**< Hardware-backend cycles per operation. */
    uint8_t has_sw;        /**< Non-zero when sw_cycles is meaningful. */
    uint8_t match;         /**< Non-zero when the outputs agree between the backends. */
    uint8_t hw_expected;   /**< Non-zero when the hardware must have run (an engine job started). */
    uint8_t hw_used;       /**< Non-zero when an engine job started during the hardware run. */
    uint8_t run_ok;        /**< Non-zero when every library call returned success. */
} noxtls_speed_row_t;

/**
 * @brief Select the backend for the following operations (software disables both EFR32 units).
 *
 * @param[in] backend Backend.
 */
void noxtls_speed_backend_set(noxtls_speed_backend_t backend);

/**
 * @brief Backend currently selected.
 *
 * @return Backend.
 */
noxtls_speed_backend_t noxtls_speed_backend_get(void);

/**
 * @brief Engine jobs started since boot (RADIOAES jobs plus Secure Engine commands).
 *
 * @return Counter; a difference of zero over a hardware run means the backend fell back to software.
 */
uint32_t noxtls_speed_hw_activity(void);

/**
 * @brief Install the entropy callback of the benchmark (hardware TRNG in hardware mode, seeded generator in software mode).
 *
 * @return 1 when the generator was seeded from the TRNG, 0 when a fixed seed was used.
 */
uint8_t noxtls_speed_entropy_install(void);

/**
 * @brief Start a result row.
 *
 * @param[in] op          Operation name (static string).
 * @param[in] size        Payload size.
 * @param[in] hw_expected Non-zero when the hardware must serve this case.
 *
 * @return Row to fill in (never NULL; the last row is reused when the table is full).
 */
noxtls_speed_row_t *noxtls_speed_row_begin(const char *op, uint32_t size, uint8_t hw_expected);

/**
 * @brief Finish a row: classify it, print it and update the pass / fail counters.
 *
 * @param[in] row Row.
 */
void noxtls_speed_row_end(const noxtls_speed_row_t *row);

/**
 * @brief Record and print a standalone check.
 *
 * @param[in] name      Check name.
 * @param[in] condition Non-zero when it passed.
 */
void noxtls_speed_check(const char *name, uint8_t condition);

/**
 * @brief Print the table header.
 */
void noxtls_speed_table_header(void);

/**
 * @brief Checks that passed.
 *
 * @return Count.
 */
uint32_t noxtls_speed_pass_count(void);

/**
 * @brief Checks that failed.
 *
 * @return Count.
 */
uint32_t noxtls_speed_fail_count(void);

/**
 * @brief Average cycles per operation.
 *
 * @param[in] start Value of noxtls_speed_timer_cycles() before the loop.
 * @param[in] iters Iterations of the loop (> 0).
 *
 * @return Cycles per iteration.
 */
uint32_t noxtls_speed_avg(uint32_t start, uint32_t iters);

/** @brief Run the AES-ECB, CCM and SHA-256 cases (noxtls_speed_sym.c). */
void noxtls_speed_run_sym(void);

/** @brief Run the P-256 keygen, ECDH and ECDSA cases (noxtls_speed_pk.c). */
void noxtls_speed_run_pk(void);

/** @brief Run the TRNG and DRBG cases (noxtls_speed_rng.c). */
void noxtls_speed_run_rng(void);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_SPEED_BENCH_H */
