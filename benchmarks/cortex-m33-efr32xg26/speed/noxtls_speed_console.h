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
* File:    noxtls_speed_console.h
* Summary: Board bring-up and VCOM console of the EFR32xG26 NoxTLS speed benchmark
*
*****************************************************************************/

/**
 * @file noxtls_speed_console.h
 * @brief BRD4120A bring-up (clocks, GPIO, VCOM on EUSART0) and text output helpers.
 * @ingroup noxtls_speed
 *
 * Built on the nox-driver-lib EFR32xG2x platform drivers; no vendor code.
 */
#ifndef NOXTLS_SPEED_CONSOLE_H
#define NOXTLS_SPEED_CONSOLE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Decimal base. */
#define NOXTLS_SPEED_DEC_BASE       10U
/** @brief Decimal digits of a 32-bit value. */
#define NOXTLS_SPEED_DEC_DIGITS     10U
/** @brief Hex digits of a 32-bit value. */
#define NOXTLS_SPEED_HEX_DIGITS     8U
/** @brief Bits per hex digit. */
#define NOXTLS_SPEED_NIBBLE_BITS    4U
/** @brief Mask of one hex digit. */
#define NOXTLS_SPEED_NIBBLE_MASK    0xFU
/** @brief Fixed-point scale of the speed-up column (two decimals). */
#define NOXTLS_SPEED_FIXED_SCALE    100U

/**
 * @brief Bring up the core clock (78 MHz), GPIO and the VCOM bridge enable line.
 *
 * @return 1 when the clock tree and the GPIO driver started, 0 otherwise.
 */
uint8_t noxtls_speed_board_init(void);

/**
 * @brief Start the VCOM UART (115200 8N1). The cycle timer must run (used for the bridge settle time).
 */
void noxtls_speed_console_init(void);

/**
 * @brief Print a zero-terminated string.
 *
 * @param[in] text String.
 */
void noxtls_speed_puts(const char *text);

/**
 * @brief Print an unsigned value in decimal, right-aligned in a field.
 *
 * @param[in] value Value.
 * @param[in] width Minimum field width (0 for none).
 */
void noxtls_speed_putdec(uint32_t value, uint32_t width);

/**
 * @brief Print an unsigned value in hexadecimal (8 digits).
 *
 * @param[in] value Value.
 */
void noxtls_speed_puthex(uint32_t value);

/**
 * @brief Print a ratio as a fixed-point number with two decimals.
 *
 * @param[in] numerator   Numerator.
 * @param[in] denominator Denominator (0 prints "n/a").
 * @param[in] width       Minimum field width.
 */
void noxtls_speed_putratio(uint32_t numerator, uint32_t denominator, uint32_t width);

/**
 * @brief Print a string left-aligned in a field.
 *
 * @param[in] text  String.
 * @param[in] width Field width.
 */
void noxtls_speed_putpad(const char *text, uint32_t width);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_SPEED_CONSOLE_H */
