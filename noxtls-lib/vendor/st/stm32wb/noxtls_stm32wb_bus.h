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
* File:    noxtls_stm32wb_bus.h
* Summary: STM32WB register bus access primitives
*
*****************************************************************************/

/**
 * @file noxtls_stm32wb_bus.h
 * @brief 32-bit register access primitives of the STM32WB5x backend.
 * @ingroup noxtls_stm32wb
 *
 * Every peripheral access of the backend goes through these two functions.
 * The firmware implementation (noxtls_stm32wb_bus.c) performs volatile loads
 * and stores; the host unit tests link a register-level peripheral model
 * instead, so all driver logic runs unmodified on the host.
 */

#ifndef NOXTLS_STM32WB_BUS_H
#define NOXTLS_STM32WB_BUS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Read a 32-bit peripheral register.
 *
 * @param[in] addr Absolute register address.
 *
 * @return Register value.
 */
uint32_t noxtls_stm32wb_bus_rd(uint32_t addr);

/**
 * @brief Write a 32-bit peripheral register.
 *
 * @param[in] addr  Absolute register address.
 * @param[in] value Value to store.
 */
void noxtls_stm32wb_bus_wr(uint32_t addr, uint32_t value);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_STM32WB_BUS_H */
