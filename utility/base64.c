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
int noxtls_base64_encode(uint8_t * input, uint32_t len, char * output)
{
    uint32_t val;
    uint8_t * ptr = input;
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
    uint32_t val;
    char * ptr = input;
    uint8_t * out_ptr = output;
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

        while(len >= BASE64_ENCODE_OUTPUT_BYTES)
        {            
            val = (noxtls_base64_decode_char(ptr[0]) << BASE64_SEXTET_SHIFT_0) |
                  (noxtls_base64_decode_char(ptr[1]) << BASE64_SEXTET_SHIFT_1) |
                  (noxtls_base64_decode_char(ptr[2]) << BASE64_SEXTET_SHIFT_2) |
                  (noxtls_base64_decode_char(ptr[3]));

            *out_ptr++ = (uint8_t)((val & 0x00FF0000) >> 16);
            *out_ptr++ = (uint8_t)((val & 0x0000FF00) >> 8);
            *out_ptr++ = (uint8_t)(val & 0x000000FF);        

            ptr += BASE64_ENCODE_OUTPUT_BYTES;
            len -= BASE64_ENCODE_OUTPUT_BYTES;
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