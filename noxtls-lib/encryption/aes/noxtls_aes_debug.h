/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
* 
*
* File:    noxtls_aes_debug.c
* Summary: Advanced Encryption Standard (AES) Algorithm
*
*/

/** @addtogroup noxtls_encryption */
/** @{ */

#ifndef _AES_DEBUG_H_
#define _AES_DEBUG_H_

/* Standard Includes */
#include <stdint.h>
#include <stdio.h>


void noxtls_print_state(uint32_t cur_round, const uint8_t state[4][4], const char * prefix);
void noxtls_print_state_matrix(uint8_t state[4][4]);

#endif /* _AES_DEBUG_H_ */
