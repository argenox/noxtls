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

#ifdef __cplusplus
extern "C"
{
#endif

/* Standard Includes */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Includes */
#include "noxtls_aes.h"

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
void noxtls_print_state(uint32_t cur_round, const uint8_t state[4][4], const char * prefix)
{
    int row;
    uint32_t val[4];
    
    for(row = 0; row < 4; row++)
    {
        val[row] = (state[0][row] << 24) | (state[1][row]<< 16) | (state[2][row] << 8) | state[3][row];
    }
    
    printf("round[%u].%s %08lx%08lx%08lx%08lx\n", (unsigned int)cur_round, prefix,
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
    int row;
    int col;
    
    for(row = 0; row < 4; row++)
    {
        for(col = 0; col < 4; col++) {
            printf("%02x ", state[row][col]);
        }
        printf("\n");
    }
}


#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_FEATURE_AES */
