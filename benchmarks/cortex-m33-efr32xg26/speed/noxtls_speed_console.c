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
* File:    noxtls_speed_console.c
* Summary: Board bring-up and VCOM console of the EFR32xG26 NoxTLS speed benchmark
*
*****************************************************************************/

/**
 * @file noxtls_speed_console.c
 * @brief BRD4120A bring-up and VCOM text output.
 * @ingroup noxtls_speed
 */

#include <stdbool.h>
#include <string.h>

#include "noxdrv_efr32_brd4120a.h"
#include "noxdrv_efr32_clock.h"
#include "noxdrv_efr32_emu.h"
#include "noxdrv_efr32_eusart.h"
#include "noxdrv_efr32_gpio.h"
#include "noxdrv_efr32_nvic.h"

#include "noxtls_speed_config.h"
#include "noxtls_speed_console.h"
#include "noxtls_speed_timer.h"

uint8_t noxtls_speed_board_init(void)
{
    uint8_t ok = 1U;

    if (noxdrv_efr32_emu_init(NULL) != NOXDRV_SUCCESS) {
        ok = 0U;
    }
    if (noxdrv_efr32_clock_init(NULL) != NOXDRV_SUCCESS) {
        ok = 0U;
    }
    (void)noxdrv_efr32_nvic_set_default_priorities();
    if (noxdrv_efr32_gpio_init() != NOXDRV_SUCCESS) {
        ok = 0U;
    }
    (void)noxdrv_efr32_gpio_mode_set((noxdrv_efr32_gpio_port_t)NOXDRV_BRD4120A_VCOM_ENABLE_PORT,
                                     NOXDRV_BRD4120A_VCOM_ENABLE_PIN, NOXDRV_EFR32_GPIO_MODE_PUSH_PULL, true);
    return ok;
}

void noxtls_speed_console_init(void)
{
    noxdrv_efr32_eusart_config_t cfg;

    noxtls_speed_timer_wait((uint32_t)((NOXTLS_SPEED_CPU_HZ / NOXTLS_SPEED_MS_PER_S) * NOXTLS_SPEED_VCOM_SETTLE_MS));
    (void)memset(&cfg, 0, sizeof(cfg));
    cfg.instance = NOXDRV_BRD4120A_VCOM_EUSART_INSTANCE;
    cfg.baud = NOXDRV_BRD4120A_VCOM_BAUD;
    cfg.clk_src = NOXDRV_EFR32_EUSART_CLK_EM01GRPC;
    cfg.tx.port = (noxdrv_efr32_gpio_port_t)NOXDRV_BRD4120A_VCOM_TX_PORT;
    cfg.tx.pin = NOXDRV_BRD4120A_VCOM_TX_PIN;
    cfg.rx.port = (noxdrv_efr32_gpio_port_t)NOXDRV_BRD4120A_VCOM_RX_PORT;
    cfg.rx.pin = NOXDRV_BRD4120A_VCOM_RX_PIN;
    cfg.irq_priority = NOXDRV_EFR32_IRQ_PRIO_DEFAULT;
    (void)noxdrv_efr32_eusart_init(&cfg);
}

/**
 * @brief Send one character.
 * @internal
 *
 * @param[in] c Character.
 */
static void speed_putc(char c)
{
    const uint8_t byte = (uint8_t)c;

    (void)noxdrv_efr32_eusart_write(NOXDRV_BRD4120A_VCOM_EUSART_INSTANCE, &byte, 1U);
}

/**
 * @brief Send spaces.
 * @internal
 *
 * @param[in] count Number of spaces.
 */
static void speed_spaces(uint32_t count)
{
    uint32_t i;

    for (i = 0U; i < count; i++) {
        speed_putc(' ');
    }
}

void noxtls_speed_puts(const char *text)
{
    if (text != NULL) {
        while (*text != '\0') {
            speed_putc(*text);
            text++;
        }
    }
}

void noxtls_speed_putdec(uint32_t value, uint32_t width)
{
    char digits[NOXTLS_SPEED_DEC_DIGITS];
    uint32_t count = 0U;
    uint32_t v = value;

    do {
        digits[count] = (char)('0' + (char)(v % NOXTLS_SPEED_DEC_BASE));
        v /= NOXTLS_SPEED_DEC_BASE;
        count++;
    } while (v != 0U);
    if (width > count) {
        speed_spaces(width - count);
    }
    while (count > 0U) {
        count--;
        speed_putc(digits[count]);
    }
}

void noxtls_speed_puthex(uint32_t value)
{
    static const char k_hex[] = "0123456789ABCDEF";
    uint32_t i;

    for (i = NOXTLS_SPEED_HEX_DIGITS; i > 0U; i--) {
        speed_putc(k_hex[(value >> ((i - 1U) * NOXTLS_SPEED_NIBBLE_BITS)) & NOXTLS_SPEED_NIBBLE_MASK]);
    }
}

void noxtls_speed_putratio(uint32_t numerator, uint32_t denominator, uint32_t width)
{
    if (denominator == 0U) {
        noxtls_speed_putpad("n/a", width);
    } else {
        char text[NOXTLS_SPEED_DEC_DIGITS + NOXTLS_SPEED_DEC_DIGITS];
        uint32_t count = 0U;
        uint32_t i;
        const uint64_t scaled = ((uint64_t)numerator * NOXTLS_SPEED_FIXED_SCALE) / denominator;
        uint32_t whole = (uint32_t)(scaled / NOXTLS_SPEED_FIXED_SCALE);
        const uint32_t frac = (uint32_t)(scaled % NOXTLS_SPEED_FIXED_SCALE);

        /* Render right-to-left: two decimals, point, whole part. */
        text[count++] = (char)('0' + (char)(frac % NOXTLS_SPEED_DEC_BASE));
        text[count++] = (char)('0' + (char)(frac / NOXTLS_SPEED_DEC_BASE));
        text[count++] = '.';
        do {
            text[count++] = (char)('0' + (char)(whole % NOXTLS_SPEED_DEC_BASE));
            whole /= NOXTLS_SPEED_DEC_BASE;
        } while ((whole != 0U) && (count < (uint32_t)sizeof(text)));
        if (width > count) {
            speed_spaces(width - count);
        }
        for (i = count; i > 0U; i--) {
            speed_putc(text[i - 1U]);
        }
    }
}

void noxtls_speed_putpad(const char *text, uint32_t width)
{
    uint32_t len = 0U;

    if (text != NULL) {
        len = (uint32_t)strlen(text);
        noxtls_speed_puts(text);
    }
    if (width > len) {
        speed_spaces(width - len);
    }
}
