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
* File:    noxtls_utility.h
* Summary: NOXTLS Utility Definitions
*
*/

/**
 * @defgroup noxtls_utility Utility
 * @brief File I/O and Base64 encoding/decoding.
 * @addtogroup noxtls
 */
/** @{ */

#ifndef _NOXTLS_UTILITY_H
#define _NOXTLS_UTILITY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int noxtls_load_file(const char * filename, uint8_t ** buffer);
extern int noxtls_load_text_file(const char * filename, uint8_t ** buffer);
extern int noxtls_write_text_file(const char * filename, const uint8_t * buffer, uint32_t len);
extern int noxtls_write_file(const char * filename, const uint8_t * buffer, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
