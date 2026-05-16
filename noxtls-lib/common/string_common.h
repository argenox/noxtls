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

#ifndef _STRING_COMMON_H_
#define _STRING_COMMON_H_

#include <stdint.h>
#include <stddef.h>
#include "noxtls_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HEX_PAIR_CHARS (2u)
#define HEX_PAIR_BUFFER_LEN (3u)
#define HEX_STRING_STRIDE (2u)
#define HEX_RADIX (16u)
#define HEX_OUTLEN_SHIFT (2u)

/**
 * @brief Parse a null-terminated hex string into binary bytes.
 * @param[in] string Null-terminated string of hex digit pairs (no separators); length must be even.
 * @param[out] out_buf Output buffer for decoded bytes.
 * @param[in] out_length Capacity of @p out_buf in bytes; must be at least `strlen(string) / 2`.
 * @return Number of bytes written on success; -1 on NULL input, -2 if @p out_buf is too small, -3 if odd-length string, -4 on overflow guard.
 */
extern int noxtls_hex_string_to_bytes(const char * string, uint8_t * out_buf, size_t out_length);

/**
 * @brief Hex string to bytes using an implicit output length of half the string length.
 * @param[in] string Same format as @ref noxtls_hex_string_to_bytes.
 * @param[out] output Buffer sized for `strlen(string) / 2` bytes.
 * @return Same conventions as @ref noxtls_hex_string_to_bytes; -1 if @p string or @p output is NULL.
 */
extern int noxtls_process_string_to_bytes(const char *string, uint8_t *output);

/**
 * @brief Print a byte buffer as uppercase hex via the library debug printf (for diagnostics).
 * @param[in] data Bytes to print; if NULL or @p len is zero, no output.
 * @param[in] len Number of bytes to print.
 */
void noxtls_print_data(const uint8_t * data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _STRING_COMMON_H_ */
