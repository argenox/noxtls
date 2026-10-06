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
* File:    string_common.c
* Summary: Common String helper functions
*
*****************************************************************************/

/** @addtogroup noxtls_common */

#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include "string_common.h"
#include "noxtls_debug_printf.h"
#include "noxtls_ct.h"

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
 * @note out_length must be at least (noxtls_u8_strlen(string) / 2) to avoid truncation.
 *
 * @return On success, the number of bytes written. On error: -1 if string or
 *         out_buf is NULL, -2 if out_buf is too small.
 */
/* Public helper; arm DB may omit other TU callers. */
static uint8_t noxtls_hex_nibble(uint8_t c)
{
    if((c >= (uint8_t)'0') && (c <= (uint8_t)'9')) {
        return (uint8_t)(c - (uint8_t)'0');
    }
    if((c >= (uint8_t)'a') && (c <= (uint8_t)'f')) {
        return (uint8_t)(10U + (uint8_t)(c - (uint8_t)'a'));
    }
    if((c >= (uint8_t)'A') && (c <= (uint8_t)'F')) {
        return (uint8_t)(10U + (uint8_t)(c - (uint8_t)'A'));
    }
    return 0xFFU;
}

int noxtls_hex_string_to_bytes(const uint8_t * string, uint8_t * out_buf, size_t out_length)
{
    size_t i = 0U;
    size_t j = 0U;
    size_t str_len;

    if(string == NULL) {
        return -1;
    }

    if(out_buf == NULL) {
        return -1;
    }

    str_len = noxtls_u8_strlen(string);
    if((str_len & 1U) != 0U) {
        return -3;
    }

    /* Require buffer large enough for(string length / 2) bytes */
    if(out_length < (str_len >> 1U))
    {
        return -2;
    }

    /* Parse two hex chars at a time into one byte */
    for(i = 0U; i < str_len; i += (size_t)HEX_STRING_STRIDE)
    {
        uint8_t hi = noxtls_hex_nibble(string[i]);
        uint8_t lo = noxtls_hex_nibble(string[i + 1U]);
        /* Historical behavior: invalid nibbles yield 0. */
        if((hi > 0x0FU) || (lo > 0x0FU)) {
            out_buf[j] = 0U;
        } else {
            out_buf[j] = (uint8_t)((hi << 4) | lo);
        }
        j += 1U;
    }

    if(j > (size_t)INT_MAX) {
        return -4;
    }
    return (int)j;
}

/**
 * @brief Wrapper around @ref noxtls_hex_string_to_bytes with output length `noxtls_u8_strlen(string) / 2`.
 * @param[in] string Hex string (even length, no separators).
 * @param[out] output Buffer sized for half the string length in bytes.
 * @return Same error codes as @ref noxtls_hex_string_to_bytes; -1 if @p string or @p output is NULL.
 */
int noxtls_process_string_to_bytes(const uint8_t *string, uint8_t *output)
{
    size_t str_len;
    size_t out_len;

    if((string == NULL) || (output == NULL)) {
        return -1;
    }

    str_len = (uint32_t)noxtls_u8_strlen(string);
    out_len = (uint32_t)str_len >> 1U;
    return noxtls_hex_string_to_bytes(string, output, out_len);
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
    size_t i = 0U;

    if((data == NULL) || (len == 0U)) {
        return;
    }

    for(i = 0U; i < len; i += 1U)
    {
        (void)noxtls_debug_printf((const uint8_t *)"%X", data[i]);
    }
    (void)noxtls_debug_printf((const uint8_t *)"\n");
}

    
#ifdef __cplusplus
}
#endif
