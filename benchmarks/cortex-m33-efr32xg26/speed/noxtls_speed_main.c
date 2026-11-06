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
* File:    noxtls_speed_main.c
* Summary: Entry point of the EFR32xG26 NoxTLS speed benchmark (brd4120a_noxtls_speed)
*
*****************************************************************************/

/**
 * @file noxtls_speed_main.c
 * @brief Brings the BRD4120A up, binds the shared engine locks, runs every case and prints the table on VCOM.
 * @ingroup noxtls_speed
 *
 * Output (115200 8N1): banner, start-up checks, the table
 * "op size sw_cycles hw_cycles speedup hw match", the engine counters and the
 * final line "SPEED DONE pass=N fail=M".
 */

#include <stdbool.h>
#include <stddef.h>

#include "noxdrv_efr32_radioaes.h"
#include "noxdrv_efr32_semailbox.h"
#include "noxtls_efr32_accel.h"

#include "noxtls_speed_bench.h"
#include "noxtls_speed_config.h"
#include "noxtls_speed_console.h"
#include "noxtls_speed_timer.h"

/** @brief Name of the image, printed in the banner. */
#define SPEED_BANNER    "brd4120a_noxtls_speed"

/** @brief Engine ownership shared with nox-driver-lib: one flag per engine covers both users. */
static const noxtls_efr32_engine_lock_t k_engine_lock = {
    noxdrv_efr32_radioaes_try_acquire,
    noxdrv_efr32_radioaes_release,
    noxdrv_efr32_semailbox_try_acquire,
    noxdrv_efr32_semailbox_release
};

/**
 * @brief Print the engine counters.
 * @internal
 */
static void speed_print_stats(void)
{
    const noxtls_efr32_stats_t *st = noxtls_efr32_stats();

    noxtls_speed_puts("stats aes_jobs=");
    noxtls_speed_putdec(st->aes_jobs, 0U);
    noxtls_speed_puts(" aes_busy=");
    noxtls_speed_putdec(st->aes_busy, 0U);
    noxtls_speed_puts(" aes_errors=");
    noxtls_speed_putdec(st->aes_errors, 0U);
    noxtls_speed_puts(" aes_timeouts=");
    noxtls_speed_putdec(st->aes_timeouts, 0U);
    noxtls_speed_puts(" se_commands=");
    noxtls_speed_putdec(st->se_commands, 0U);
    noxtls_speed_puts(" se_busy=");
    noxtls_speed_putdec(st->se_busy, 0U);
    noxtls_speed_puts(" se_errors=");
    noxtls_speed_putdec(st->se_errors, 0U);
    noxtls_speed_puts(" se_timeouts=");
    noxtls_speed_putdec(st->se_timeouts, 0U);
    noxtls_speed_puts("\r\n");
}

/**
 * @brief Run the backend known-answer self-test through the hardware path and print its masks.
 * @internal
 */
static void speed_selftest(void)
{
    noxtls_efr32_selftest_t result = { 0U, 0U, 0U };
    const noxtls_return_t rc = noxtls_efr32_selftest(&result, 0U);

    noxtls_speed_puts("info selftest ran=0x");
    noxtls_speed_puthex(result.ran);
    noxtls_speed_puts(" passed=0x");
    noxtls_speed_puthex(result.passed);
    noxtls_speed_puts(" skipped=0x");
    noxtls_speed_puthex(result.skipped);
    noxtls_speed_puts("\r\n");
    noxtls_speed_check("efr32.selftest", ((rc == NOXTLS_RETURN_SUCCESS) && (result.ran == result.passed) &&
                                          (result.ran != 0U)) ? 1U : 0U);
}

/**
 * @brief Application entry point.
 *
 * @return Never returns.
 */
int main(void)
{
    const uint8_t board_ok = noxtls_speed_board_init();
    const noxtls_speed_timer_kind_t timer = noxtls_speed_timer_init();
    uint8_t seeded;

    noxtls_speed_console_init();
    noxtls_speed_puts("\r\n" SPEED_BANNER "\r\n");
    noxtls_speed_puts("info timer=");
    noxtls_speed_puts((timer == NOXTLS_SPEED_TIMER_DWT) ? "DWT" : "SysTick");
    noxtls_speed_puts(" cpu_hz=");
    noxtls_speed_putdec((uint32_t)NOXTLS_SPEED_CPU_HZ, 0U);
    noxtls_speed_puts("\r\n");
    noxtls_speed_check("board.init", board_ok);

    noxtls_speed_check("efr32.engine_lock_bind", (noxtls_efr32_engine_lock_bind(&k_engine_lock) == NOXTLS_RETURN_SUCCESS) ? 1U : 0U);
    noxtls_speed_backend_set(NOXTLS_SPEED_BACKEND_HW);
    speed_selftest();
    seeded = noxtls_speed_entropy_install();
    noxtls_speed_puts("info sw_entropy_seed=");
    noxtls_speed_puts((seeded != 0U) ? "trng" : "fixed");
    noxtls_speed_puts("\r\n");

    noxtls_speed_table_header();
    noxtls_speed_run_sym();
    noxtls_speed_run_pk();
    noxtls_speed_run_rng();

    noxtls_speed_backend_set(NOXTLS_SPEED_BACKEND_HW);
    noxtls_speed_puts("\r\n");
    speed_print_stats();
    noxtls_speed_puts("SPEED DONE pass=");
    noxtls_speed_putdec(noxtls_speed_pass_count(), 0U);
    noxtls_speed_puts(" fail=");
    noxtls_speed_putdec(noxtls_speed_fail_count(), 0U);
    noxtls_speed_puts("\r\n");

    for (;;) {
    }
}
