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
* Summary: Advanced Encryption Standard (AES) Algorithm
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */
/** @{ */

#ifndef _AES_DEBUG_H_
#define _AES_DEBUG_H_

/* Standard Includes */
#include <stdint.h>
#include <stdio.h>


/**
 * @brief Print a compact AES state line for debugging.
 * @param cur_round Current AES round number.
 * @param state AES state matrix to print.
 * @param prefix Label inserted into the debug output.
 * @return None.
 */
void noxtls_print_state(uint32_t cur_round, const uint8_t state[4][4], const char * prefix);
/**
 * @brief Print an AES state matrix for debugging.
 * @param state AES state matrix to print.
 * @return None.
 */
void noxtls_print_state_matrix(uint8_t state[4][4]);

#endif /* _AES_DEBUG_H_ */
