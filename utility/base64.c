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
* File:    base64.h
* Summary: Base64 Encoding and Decoding
*
*/

/** @addtogroup noxtls_utility */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>

#include "base64.h"



/** Base64 Encoding Table */
const char base64_table[] =
{
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 
    'w', 'x', 'y', 'z', '0', '1', '2', '3', 
    '4', '5', '6', '7', '8', '9', '+', '/'
};

/**
 * @brief Encodes data in Base64
 *
 * @param input is the input data
 * @param len is the length of the input data
 * @param output is a pointer to the buffer where Base64 data will be placed
 * 
 * @return number of bytes encoded, negative error otherwise
 *
 */
int noxtls_base64_encode(const uint8_t * input, uint32_t len, char * output)
{
    uint32_t val;
    const uint8_t * ptr = input;
    char * out_ptr = output;
    int out_len = -1;

    do
    {
        if(input == NULL) {
            break;
        }

        if(output == NULL) {
            break;
        }

        if(len == 0) {
            out_len = 0;
            break;
        }

        while(len >= BASE64_ENCODE_BLOCK_BYTES)
        {
            val = (ptr[0] << BASE64_OCTET_SHIFT_0) | (ptr[1] << BASE64_OCTET_SHIFT_1) | ptr[2];

            *out_ptr++ = base64_table[(val & (BASE64_SEXTET_MASK << BASE64_SEXTET_SHIFT_0)) >> BASE64_SEXTET_SHIFT_0];
            *out_ptr++ = base64_table[(val & (BASE64_SEXTET_MASK << BASE64_SEXTET_SHIFT_1)) >> BASE64_SEXTET_SHIFT_1];
            *out_ptr++ = base64_table[(val & (BASE64_SEXTET_MASK << BASE64_SEXTET_SHIFT_2)) >> BASE64_SEXTET_SHIFT_2];
            *out_ptr++ = base64_table[(val & BASE64_SEXTET_MASK)];
            ptr += BASE64_ENCODE_BLOCK_BYTES;

            len -= BASE64_ENCODE_BLOCK_BYTES;
        }

        if(len == 2) {
            
            val = (ptr[0] << BASE64_OCTET_SHIFT_0) | (ptr[1] << BASE64_OCTET_SHIFT_1);

            *out_ptr++ = base64_table[(val & (BASE64_SEXTET_MASK << BASE64_SEXTET_SHIFT_0)) >> BASE64_SEXTET_SHIFT_0];
            *out_ptr++ = base64_table[(val & (BASE64_SEXTET_MASK << BASE64_SEXTET_SHIFT_1)) >> BASE64_SEXTET_SHIFT_1];
            *out_ptr++ = base64_table[(val & (BASE64_SEXTET_MASK << BASE64_SEXTET_SHIFT_2)) >> BASE64_SEXTET_SHIFT_2];
            *out_ptr++ = BASE64_PAD_CHAR;
        }

        if(len == 1) {
            
            val = (ptr[0] << BASE64_OCTET_SHIFT_0);

            *out_ptr++ = base64_table[(val & (BASE64_SEXTET_MASK << BASE64_SEXTET_SHIFT_0)) >> BASE64_SEXTET_SHIFT_0];
            *out_ptr++ = base64_table[(val & (BASE64_SEXTET_MASK << BASE64_SEXTET_SHIFT_1)) >> BASE64_SEXTET_SHIFT_1];
            *out_ptr++ = BASE64_PAD_CHAR;
            *out_ptr++ = BASE64_PAD_CHAR;
        }

        {
            ptrdiff_t written = out_ptr - output;
            if(written > INT_MAX) {
                out_len = -1;
            } else {
                out_len = (int)written;
            }
        }

    } while(0);

    return out_len;
}


/**
 * @brief Map one Base64 character to a 6-bit value, or sentinel for skip/pad/invalid.
 * @param c Input byte.
 * @return 0..63 data, -1 padding '=', -2 ignorable whitespace, -3 invalid.
 */
static int noxtls_base64_decode_sextet(unsigned char c)
{
    if(c == '\r' || c == '\n' || c == '\t' || c == ' ') {
        return -2;
    }
    if(c == (unsigned char)BASE64_PAD_CHAR) {
        return -1;
    }
    if(c >= 'A' && c <= 'Z') {
        return (int)(c - 'A');
    }
    if(c >= 'a' && c <= 'z') {
        return (int)(c - 'a' + 26);
    }
    if(c >= '0' && c <= '9') {
        return (int)(c - '0' + 52);
    }
    if(c == '+') {
        return 62;
    }
    if(c == '/') {
        return 63;
    }
    return -3;
}

/**
 * @brief Emit up to three bytes from one Base64 quantum (handles '=' padding).
 * @param s Four sextet values, or -1 for padding positions.
 * @param out_ptr In/out write cursor into the decoded output buffer.
 * @return 0 on success, -1 on invalid quantum.
 */
static int noxtls_base64_emit_quantum(const int s[4], uint8_t **out_ptr)
{
    int a;
    int b;
    int c;
    int d;
    uint32_t val;

    a = s[0];
    b = s[1];
    c = s[2];
    d = s[3];
    if(a < 0 || b < 0) {
        return -1;
    }
    if(d == -1) {
        if(c == -1) {
            val = ((uint32_t)a << 18) | ((uint32_t)b << 12);
            *(*out_ptr)++ = (uint8_t)(val >> 16);
        } else {
            if(c < 0) {
                return -1;
            }
            val = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6);
            *(*out_ptr)++ = (uint8_t)(val >> 16);
            *(*out_ptr)++ = (uint8_t)(val >> 8);
        }
    } else {
        if(c < 0 || d < 0) {
            return -1;
        }
        val = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6) | (uint32_t)d;
        *(*out_ptr)++ = (uint8_t)(val >> 16);
        *(*out_ptr)++ = (uint8_t)(val >> 8);
        *(*out_ptr)++ = (uint8_t)val;
    }
    return 0;
}

/**
 * @brief Decodes Base64 data
 *
 * @param input is the Base64 data
 * @param len is the length of the input data
 * @param output is a pointer to the buffer for the decoded data
 * 
 * @return number of bytes decoded, negative error otherwise
 *
 */
int noxtls_base64_decode(char * input, uint32_t len, uint8_t * output)
{
    uint8_t *out_ptr;
    uint32_t i;
    int s[4];
    int ns;
    int v;
    int t;
    int expected_tail_pad;
    int seen_tail_pad;
    ptrdiff_t written;

    if(input == NULL || output == NULL) {
        return -1;
    }
    if(len == 0u) {
        return 0;
    }

    out_ptr = output;
    i = 0u;
    ns = 0;

    while(i < len) {
        v = noxtls_base64_decode_sextet((unsigned char)input[i]);
        i++;
        if(v == -2) {
            continue;
        }
        if(v == -3) {
            return -1;
        }
        if(v == -1) {
            if(ns == 0) {
                return -1;
            }
            expected_tail_pad = (ns == 2) ? 1 : 0;
            seen_tail_pad = 0;
            while(ns < 4) {
                s[ns] = -1;
                ns++;
            }
            if(noxtls_base64_emit_quantum(s, &out_ptr) != 0) {
                return -1;
            }
            ns = 0;
            while(i < len) {
                t = noxtls_base64_decode_sextet((unsigned char)input[i]);
                i++;
                if(t == -2) {
                    continue;
                }
                if(t == -1) {
                    if(seen_tail_pad >= expected_tail_pad) {
                        return -1;
                    }
                    seen_tail_pad++;
                    continue;
                }
                return -1;
            }
            if(seen_tail_pad != expected_tail_pad) {
                return -1;
            }
            break;
        }
        s[ns] = v;
        ns++;
        if(ns == 4) {
            if(noxtls_base64_emit_quantum(s, &out_ptr) != 0) {
                return -1;
            }
            ns = 0;
        }
    }

    if(ns != 0) {
        return -1;
    }

    written = out_ptr - output;
    if(written > INT_MAX) {
        return -1;
    }
    return (int)written;
}

/**
 * @brief Decodes Base64 character to value
 *
 * @param base64 Character to decode
 * 
 * @return value decoded
 */
uint8_t noxtls_base64_decode_char(char c)
{    
    if(c >= BASE64_UPPERCASE_START && c <= 'Z') {
        return (c - BASE64_UPPERCASE_START);
    }
    else if(c >= BASE64_LOWERCASE_START && c <= 'z')
    {
        return (c - BASE64_LOWERCASE_START + BASE64_LOWERCASE_OFFSET);
    }
    else if(c >= BASE64_DIGIT_START && c <= '9')
    {
        return (c - BASE64_DIGIT_START + BASE64_DIGIT_OFFSET);
    }
    else if(c == '+')
    {
        return BASE64_PLUS_VALUE;
    }
    else if(c == '/')
    {
        return BASE64_SLASH_VALUE;
    }
    
    return 0;
}