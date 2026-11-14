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
* File:    noxtls_speed_bench.c
* Summary: Shared framework of the EFR32xG26 NoxTLS speed benchmark
*
*****************************************************************************/

/**
 * @file noxtls_speed_bench.c
 * @brief Backend selection, entropy callback, result table and pass / fail accounting.
 * @ingroup noxtls_speed
 */

#include <stddef.h>

#include "drbg/noxtls_drbg.h"
#include "noxtls_efr32_accel.h"

#include "noxtls_speed_bench.h"
#include "noxtls_speed_config.h"
#include "noxtls_speed_console.h"
#include "noxtls_speed_timer.h"

/** @brief Xorshift128 generator words. */
#define SPEED_PRNG_WORDS        4U
/** @brief Xorshift128 shifts (Marsaglia 2003). */
#define SPEED_XS_A              11U
/** @brief Xorshift128 shift. */
#define SPEED_XS_B              8U
/** @brief Xorshift128 shift. */
#define SPEED_XS_C              19U
/** @brief Seed used when the TRNG cannot supply one. */
#define SPEED_FALLBACK_SEED     0x9E3779B9UL
/** @brief Bits per byte of a 32-bit word. */
#define SPEED_WORD_BYTES        4U
/** @brief Shift between bytes. */
#define SPEED_BYTE_SHIFT        8U

/** @brief Current backend. */
static noxtls_speed_backend_t s_backend = NOXTLS_SPEED_BACKEND_HW;
/** @brief Generator state of the software phase. */
static uint32_t s_prng[SPEED_PRNG_WORDS];
/** @brief Result rows. */
static noxtls_speed_row_t s_rows[NOXTLS_SPEED_MAX_ROWS];
/** @brief Rows used. */
static uint32_t s_row_count;
/** @brief Checks that passed. */
static uint32_t s_pass;
/** @brief Checks that failed. */
static uint32_t s_fail;

void noxtls_speed_backend_set(noxtls_speed_backend_t backend)
{
    s_backend = backend;
    noxtls_efr32_set_enabled(NOXTLS_EFR32_UNIT_ALL, (backend == NOXTLS_SPEED_BACKEND_HW) ? 1U : 0U);
}

noxtls_speed_backend_t noxtls_speed_backend_get(void)
{
    return s_backend;
}

uint32_t noxtls_speed_hw_activity(void)
{
    const noxtls_efr32_stats_t *st = noxtls_efr32_stats();

    return st->aes_jobs + st->se_commands;
}

/**
 * @brief One step of the xorshift128 generator.
 * @internal
 *
 * @return Next 32-bit value.
 */
static uint32_t speed_prng_next(void)
{
    uint32_t t = s_prng[0] ^ (s_prng[0] << SPEED_XS_A);

    s_prng[0] = s_prng[1];
    s_prng[1] = s_prng[2];
    s_prng[2] = s_prng[3];
    s_prng[3] = (s_prng[3] ^ (s_prng[3] >> SPEED_XS_B)) ^ (t ^ (t >> SPEED_XS_C));
    return s_prng[3];
}

/**
 * @brief Entropy source of the library for the benchmark.
 * @internal
 *
 * Hardware mode calls the backend's own hook (the Secure Engine TRNG). Software
 * mode has no software entropy source, so it uses a generator seeded once from
 * the TRNG; the benchmark times the P-256 and DRBG arithmetic, not entropy.
 *
 * @param[out] entropy_cb_out     Destination.
 * @param[in]  entropy_cb_out_len Bytes.
 *
 * @return NOXTLS_RETURN_SUCCESS or the hook's error.
 */
static noxtls_return_t speed_entropy_cb(uint8_t *entropy_cb_out, uint32_t entropy_cb_out_len)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if (s_backend == NOXTLS_SPEED_BACKEND_HW) {
        rc = noxtls_drbg_entropy_accel_port(entropy_cb_out, entropy_cb_out_len);
    } else {
        uint32_t word = 0U;
        uint32_t i;

        for (i = 0U; i < entropy_cb_out_len; i++) {
            if ((i % SPEED_WORD_BYTES) == 0U) {
                word = speed_prng_next();
            }
            entropy_cb_out[i] = (uint8_t)(word >> ((i % SPEED_WORD_BYTES) * SPEED_BYTE_SHIFT));
        }
    }
    return rc;
}

uint8_t noxtls_speed_entropy_install(void)
{
    uint8_t seed[NOXTLS_SPEED_SEED_BYTES];
    uint8_t from_trng = 0U;
    uint32_t i;
    uint32_t b;

    noxtls_efr32_set_enabled(NOXTLS_EFR32_UNIT_ALL, 1U);
    if (noxtls_efr32_se_trng_fill(seed, (uint32_t)sizeof(seed)) == NOXTLS_RETURN_SUCCESS) {
        from_trng = 1U;
    } else {
        for (i = 0U; i < (uint32_t)sizeof(seed); i++) {
            seed[i] = (uint8_t)(SPEED_FALLBACK_SEED >> ((i % SPEED_WORD_BYTES) * SPEED_BYTE_SHIFT));
        }
    }
    for (i = 0U; i < SPEED_PRNG_WORDS; i++) {
        s_prng[i] = 0U;
        for (b = 0U; b < SPEED_WORD_BYTES; b++) {
            s_prng[i] |= (uint32_t)seed[(i * SPEED_WORD_BYTES) + b] << (b * SPEED_BYTE_SHIFT);
        }
    }
    if ((s_prng[0] | s_prng[1] | s_prng[2] | s_prng[3]) == 0U) {
        s_prng[0] = SPEED_FALLBACK_SEED;
    }
    noxtls_drbg_set_entropy_callback(speed_entropy_cb);
    noxtls_drbg_set_entropy_source(NOXTLS_ENTROPY_SOURCE_CUSTOM);
    return from_trng;
}

noxtls_speed_row_t *noxtls_speed_row_begin(const char *op, uint32_t size, uint8_t hw_expected)
{
    noxtls_speed_row_t *row;

    if (s_row_count < NOXTLS_SPEED_MAX_ROWS) {
        row = &s_rows[s_row_count];
        s_row_count++;
    } else {
        row = &s_rows[NOXTLS_SPEED_MAX_ROWS - 1U];
    }
    row->op = op;
    row->size = size;
    row->sw_cycles = 0U;
    row->hw_cycles = 0U;
    row->has_sw = 1U;
    row->match = 0U;
    row->hw_expected = hw_expected;
    row->hw_used = 0U;
    row->run_ok = 0U;
    return row;
}

void noxtls_speed_table_header(void)
{
    noxtls_speed_puts("\r\n");
    noxtls_speed_putpad("op", NOXTLS_SPEED_COL_OP);
    noxtls_speed_putpad("size", NOXTLS_SPEED_COL_SIZE);
    noxtls_speed_putpad(" sw_cycles", NOXTLS_SPEED_COL_CYCLES + 1U);
    noxtls_speed_putpad(" hw_cycles", NOXTLS_SPEED_COL_CYCLES + 1U);
    noxtls_speed_putpad(" speedup", NOXTLS_SPEED_COL_SPEEDUP);
    noxtls_speed_putpad(" hw", NOXTLS_SPEED_COL_HW);
    noxtls_speed_puts(" match\r\n");
}

void noxtls_speed_row_end(const noxtls_speed_row_t *row)
{
    const uint8_t used_ok = ((row->hw_expected == 0U) || (row->hw_used != 0U)) ? 1U : 0U;
    const uint8_t pass = ((row->match != 0U) && (row->run_ok != 0U) && (used_ok != 0U)) ? 1U : 0U;

    noxtls_speed_putpad(row->op, NOXTLS_SPEED_COL_OP);
    noxtls_speed_putdec(row->size, NOXTLS_SPEED_COL_SIZE - 1U);
    noxtls_speed_puts(" ");
    if (row->has_sw != 0U) {
        noxtls_speed_putdec(row->sw_cycles, NOXTLS_SPEED_COL_CYCLES);
    } else {
        noxtls_speed_putpad("", NOXTLS_SPEED_COL_CYCLES - 1U);
        noxtls_speed_puts("-");
    }
    noxtls_speed_puts(" ");
    noxtls_speed_putdec(row->hw_cycles, NOXTLS_SPEED_COL_CYCLES);
    noxtls_speed_puts(" ");
    if (row->has_sw != 0U) {
        noxtls_speed_putratio(row->sw_cycles, row->hw_cycles, NOXTLS_SPEED_COL_SPEEDUP - 1U);
    } else {
        noxtls_speed_putpad("", NOXTLS_SPEED_COL_SPEEDUP - 4U);
        noxtls_speed_puts("n/a");
    }
    noxtls_speed_puts(" ");
    noxtls_speed_putpad((row->hw_used != 0U) ? "yes" : "no", NOXTLS_SPEED_COL_HW);
    if (pass != 0U) {
        noxtls_speed_puts(" ok\r\n");
        s_pass++;
    } else {
        noxtls_speed_puts((row->match != 0U) ? " FAIL" : " MISMATCH");
        if (row->run_ok == 0U) {
            noxtls_speed_puts(" (library call failed)");
        }
        if (used_ok == 0U) {
            noxtls_speed_puts(" (hardware did not run: software fallback)");
        }
        noxtls_speed_puts("\r\n");
        s_fail++;
    }
}

void noxtls_speed_check(const char *name, uint8_t condition)
{
    noxtls_speed_puts((condition != 0U) ? "PASS " : "FAIL ");
    noxtls_speed_puts(name);
    noxtls_speed_puts("\r\n");
    if (condition != 0U) {
        s_pass++;
    } else {
        s_fail++;
    }
}

uint32_t noxtls_speed_pass_count(void)
{
    return s_pass;
}

uint32_t noxtls_speed_fail_count(void)
{
    return s_fail;
}

uint32_t noxtls_speed_avg(uint32_t start, uint32_t iters)
{
    const uint32_t elapsed = noxtls_speed_timer_cycles() - start;

    return (iters != 0U) ? (elapsed / iters) : 0U;
}
