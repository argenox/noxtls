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
* File:    base64.h
* Summary: Base64 Encoding and Decoding defintions
*
*****************************************************************************/

/** @addtogroup noxtls_utility */
/** @{ */

#ifndef _NOXTLS_BASE64_H
#define _NOXTLS_BASE64_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BASE64_ENCODE_BLOCK_BYTES (3U)
#define BASE64_ENCODE_OUTPUT_BYTES (4U)
#define BASE64_OCTET_BITS (8U)
#define BASE64_SEXTET_BITS (6U)
#define BASE64_SEXTET_MASK (0x3Fu)
#define BASE64_SEXTET_SHIFT_0 (18U)
#define BASE64_SEXTET_SHIFT_1 (12U)
#define BASE64_SEXTET_SHIFT_2 (6U)
#define BASE64_OCTET_SHIFT_0 (16U)
#define BASE64_OCTET_SHIFT_1 (8U)
#define BASE64_PAD_CHAR ('=')
#define BASE64_UPPERCASE_START ('A')
#define BASE64_LOWERCASE_START ('a')
#define BASE64_DIGIT_START ('0')
#define BASE64_LOWERCASE_OFFSET (26U)
#define BASE64_DIGIT_OFFSET (52U)
#define BASE64_PLUS_VALUE (62u)
#define BASE64_SLASH_VALUE (63u)

int noxtls_base64_encode(const uint8_t * input, uint32_t len, char * output);
/** @brief Decode Base64; skips PEM/MIME line breaks (CR, LF, TAB, space) and handles '=' padding. */
int noxtls_base64_decode(const char * input, uint32_t len, uint8_t * output);
uint8_t noxtls_base64_decode_char(char c);

#ifdef __cplusplus
}
#endif

#endif
