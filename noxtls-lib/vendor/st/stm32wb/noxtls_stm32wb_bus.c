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
* File:    noxtls_stm32wb_bus.c
* Summary: STM32WB register bus access (volatile MMIO)
*
*****************************************************************************/

/**
 * @file noxtls_stm32wb_bus.c
 * @brief Volatile MMIO implementation of the STM32WB register bus.
 * @ingroup noxtls_stm32wb
 *
 * MISRA C:2025 deviation (Rule 11.4, integer to pointer conversion): the only
 * way to reach a memory-mapped peripheral is through its fixed address. The
 * conversion is confined to this file; the host tests replace the file.
 */

#include "noxtls_stm32wb_bus.h"

uint32_t noxtls_stm32wb_bus_rd(uint32_t addr)
{
    /* cppcheck-suppress [misra-c2012-11.4, misra-c2012-11.6] ; MMIO access, see file header */
    const volatile uint32_t *reg = (const volatile uint32_t *)(uintptr_t)addr;

    return *reg;
}

void noxtls_stm32wb_bus_wr(uint32_t addr, uint32_t value)
{
    /* cppcheck-suppress [misra-c2012-11.4, misra-c2012-11.6] ; MMIO access, see file header */
    volatile uint32_t *reg = (volatile uint32_t *)(uintptr_t)addr;

    *reg = value;
}
