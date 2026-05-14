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
* Summary: NOXTLS Base64 Definitions
*
*/

/** @addtogroup noxtls_utility */
/** @{ */

#ifndef _NOXTLS_BASE64_H
#define _NOXTLS_BASE64_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BASE64_ENCODE_BLOCK_BYTES (3u)
#define BASE64_ENCODE_OUTPUT_BYTES (4u)
#define BASE64_OCTET_BITS (8u)
#define BASE64_SEXTET_BITS (6u)
#define BASE64_SEXTET_MASK (0x3Fu)
#define BASE64_SEXTET_SHIFT_0 (18u)
#define BASE64_SEXTET_SHIFT_1 (12u)
#define BASE64_SEXTET_SHIFT_2 (6u)
#define BASE64_OCTET_SHIFT_0 (16u)
#define BASE64_OCTET_SHIFT_1 (8u)
#define BASE64_PAD_CHAR ('=')
#define BASE64_UPPERCASE_START ('A')
#define BASE64_LOWERCASE_START ('a')
#define BASE64_DIGIT_START ('0')
#define BASE64_LOWERCASE_OFFSET (26u)
#define BASE64_DIGIT_OFFSET (52u)
#define BASE64_PLUS_VALUE (62u)
#define BASE64_SLASH_VALUE (63u)

int noxtls_base64_encode(uint8_t * input, uint32_t len, char * output);
/** @brief Decode Base64; skips PEM/MIME line breaks (CR, LF, TAB, space) and handles '=' padding. */
int noxtls_base64_decode(char * input, uint32_t len, uint8_t * output);
uint8_t noxtls_base64_decode_char(char c);

#ifdef __cplusplus
}
#endif

#endif
