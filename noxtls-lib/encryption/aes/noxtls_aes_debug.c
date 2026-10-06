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
* File:    noxtls_aes_debug.c
* Summary: Advanced Encryption Standard (AES) Algorithm Debug
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */

/* Standard Includes */
#include <stdint.h>
#include <string.h>
#include "common/noxtls_debug_printf.h"

/* Includes */
#include "noxtls_aes.h"
#include "noxtls_aes_debug.h"

#ifdef __cplusplus
extern "C"
{
#endif

#if NOXTLS_FEATURE_AES

/**
 * @brief Prints the State
 *
 * @param cur_round is the current AES round number
 * @param state is the state to print
 * @param prefix is prefix to use
 *
 * @return None.
 */
/* Intentional host-debug stdio printer for AES state dumps. */
void noxtls_print_state(uint32_t cur_round, const uint8_t state[4][4], const uint8_t * prefix)
{
    uint32_t row;
    uint32_t val[4];

    for (row = 0U; row < 4U; row += 1U)
    {
        val[row] = (((uint32_t)state[0][row] <<24U) |
                    ((uint32_t)state[1][row] <<16U) |
                    ((uint32_t)state[2][row] <<8U) |
                    (uint32_t)state[3][row]);
    }

    (void)noxtls_debug_printf((const uint8_t *)"round[%u].%s %08lx%08lx%08lx%08lx\n", (uint32_t)cur_round, prefix,
           (unsigned long)val[0], (unsigned long)val[1], (unsigned long)val[2], (unsigned long)val[3]);
}

/**
 * @brief Print State 
 *
 * @param state is the state to print
 *
 * @return None.
 */    
void noxtls_print_state_matrix(const uint8_t state[4][4])
{
    uint32_t row;
    uint32_t col;

    for (row = 0U; row < 4U; row += 1U)
    {
        for (col = 0U; col < 4U; col += 1U) {
            (void)noxtls_debug_printf((const uint8_t *)"%02x ", state[row][col]);
        }
        (void)noxtls_debug_printf((const uint8_t *)"\n");
    }
}

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_FEATURE_AES */
