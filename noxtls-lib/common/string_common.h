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
* File:    string_common.c
* Summary: Common String helper functions
*
*/

/** @addtogroup noxtls_common */
/** @{ */

/**
 * @brief Converts String to bytes
 *
 * @param[in]  string is a pointer to Null terminated hex string
 * @param[out] out_buf is the output buffer to place the bytes
 * @param[in]  out_length is the length of the output buffer
 *
 * @note out_length should be at least as have as long as the
 * 
 * @return on success, number of bytes, otherwise negative error
 */

#ifndef _STRING_COMMON_H_
#define _STRING_COMMON_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HEX_PAIR_CHARS (2u)
#define HEX_PAIR_BUFFER_LEN (3u)
#define HEX_STRING_STRIDE (2u)
#define HEX_RADIX (16u)
#define HEX_OUTLEN_SHIFT (2u)

extern int noxtls_hex_string_to_bytes(const char * string, uint8_t * out_buf, size_t out_length);
void noxtls_print_data(const uint8_t * data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _STRING_COMMON_H_ */
