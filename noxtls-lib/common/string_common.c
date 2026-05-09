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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "string_common.h"
#include "noxtls_debug_printf.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief Converts a hex string to binary bytes.
 *
 * Parses a null-terminated string of hex digit pairs (e.g. "0A1B2C") and
 * writes the corresponding byte values into out_buf. No spaces or
 * separators; string length must be even.
 *
 * @param[in]  string    Null-terminated hex string (e.g. "0123456789abcdef").
 * @param[out] out_buf   Buffer to receive the converted bytes.
 * @param[in]  out_length Maximum number of bytes that out_buf can hold.
 *
 * @note out_length must be at least (strlen(string) / 2) to avoid truncation.
 *
 * @return On success, the number of bytes written. On error: -1 if string or
 *         out_buf is NULL, -2 if out_buf is too small.
 */
int noxtls_hex_string_to_bytes(const char * string, uint8_t * out_buf, size_t out_length)
{
    size_t i = 0;
    size_t j = 0;
    size_t str_len;
    char val[HEX_PAIR_BUFFER_LEN];

    if (string == NULL)
        return -1;

    if (out_buf == NULL)
        return -1;

    str_len = strlen(string);
    if((str_len & 1u) != 0u) {
        return -3;
    }

    /* Require buffer large enough for (string length / 2) bytes */
    if (out_length < (str_len >> 1u))
    {
        return -2;
    }

    /* Parse two hex chars at a time into one byte */
    for (i = 0; i < str_len; i += HEX_STRING_STRIDE)
    {
        val[0] = string[i];
        val[1] = string[i + 1];
        val[2] = 0;
        out_buf[j++] = (uint8_t)strtoul(val, NULL, HEX_RADIX);
    }

    if(j > (size_t)INT_MAX) {
        return -4;
    }
    return (int)j;
}

/**
 * @brief Prints binary data as uppercase hex to the debug output.
 *
 * Each byte is printed as two hex digits (e.g. "0A1B2C...") followed by
 * a newline. Uses noxtls_debug_printf; no output if data is NULL or len is 0.
 *
 * @param[in] data  Pointer to the byte buffer to print.
 * @param[in] len   Number of bytes to print.
 */
void noxtls_print_data(const uint8_t * data, size_t len)
{
    size_t i = 0;

    if (data == NULL || len == 0)
        return;

    for (i = 0; i < len; i++)
    {
        noxtls_debug_printf("%X", data[i]);
    }
    noxtls_debug_printf("\n");
}

    
#ifdef __cplusplus
}
#endif
