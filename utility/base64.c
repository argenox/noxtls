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
* File:    base64.c
* Summary: Base64 Encoding and Decoding
*
*****************************************************************************/

/** @addtogroup noxtls_utility */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <stddef.h>

#include "base64.h"

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
int32_t noxtls_base64_encode(const uint8_t * input, uint32_t len, uint8_t * output)
{
    /* File-local alphabet used only by encode (Rule 8.9). */
    static const uint8_t base64_table[] =
    {
        (uint8_t)'A', (uint8_t)'B', (uint8_t)'C', (uint8_t)'D', (uint8_t)'E', (uint8_t)'F', (uint8_t)'G', (uint8_t)'H',
        (uint8_t)'I', (uint8_t)'J', (uint8_t)'K', (uint8_t)'L', (uint8_t)'M', (uint8_t)'N', (uint8_t)'O', (uint8_t)'P',
        (uint8_t)'Q', (uint8_t)'R', (uint8_t)'S', (uint8_t)'T', (uint8_t)'U', (uint8_t)'V', (uint8_t)'W', (uint8_t)'X',
        (uint8_t)'Y', (uint8_t)'Z', (uint8_t)'a', (uint8_t)'b', (uint8_t)'c', (uint8_t)'d', (uint8_t)'e', (uint8_t)'f',
        (uint8_t)'g', (uint8_t)'h', (uint8_t)'i', (uint8_t)'j', (uint8_t)'k', (uint8_t)'l', (uint8_t)'m', (uint8_t)'n',
        (uint8_t)'o', (uint8_t)'p', (uint8_t)'q', (uint8_t)'r', (uint8_t)'s', (uint8_t)'t', (uint8_t)'u', (uint8_t)'v',
        (uint8_t)'w', (uint8_t)'x', (uint8_t)'y', (uint8_t)'z', (uint8_t)'0', (uint8_t)'1', (uint8_t)'2', (uint8_t)'3',
        (uint8_t)'4', (uint8_t)'5', (uint8_t)'6', (uint8_t)'7', (uint8_t)'8', (uint8_t)'9', (uint8_t)'+', (uint8_t)'/'};
    uint32_t val;
    uint32_t in_ix = 0U;
    uint32_t out_ix = 0U;
    uint32_t remaining;

    if (input == NULL) {
        return -1;
    }
    if (output == NULL) {
        return -1;
    }
    if (len == 0U) {
        return 0;
    }

    remaining = len;
    while (remaining >= BASE64_ENCODE_BLOCK_BYTES)
    {
        val = (((uint32_t)input[in_ix] << BASE64_OCTET_SHIFT_0)
             | ((uint32_t)input[in_ix + 1U] << BASE64_OCTET_SHIFT_1)
             | (uint32_t)input[in_ix + 2U]);

        output[out_ix] = base64_table[(val >> BASE64_SEXTET_SHIFT_0) & BASE64_SEXTET_MASK];
        output[out_ix + 1U] = base64_table[(val >> BASE64_SEXTET_SHIFT_1) & BASE64_SEXTET_MASK];
        output[out_ix + 2U] = base64_table[(val >> BASE64_SEXTET_SHIFT_2) & BASE64_SEXTET_MASK];
        output[out_ix + 3U] = base64_table[val & BASE64_SEXTET_MASK];
        in_ix += BASE64_ENCODE_BLOCK_BYTES;
        out_ix += BASE64_ENCODE_OUTPUT_BYTES;

        remaining -= BASE64_ENCODE_BLOCK_BYTES;
    }

    if (remaining == 2U) {
        val = (((uint32_t)input[in_ix] << BASE64_OCTET_SHIFT_0)
             | ((uint32_t)input[in_ix + 1U] << BASE64_OCTET_SHIFT_1));

        output[out_ix] = base64_table[(val >> BASE64_SEXTET_SHIFT_0) & BASE64_SEXTET_MASK];
        output[out_ix + 1U] = base64_table[(val >> BASE64_SEXTET_SHIFT_1) & BASE64_SEXTET_MASK];
        output[out_ix + 2U] = base64_table[(val >> BASE64_SEXTET_SHIFT_2) & BASE64_SEXTET_MASK];
        output[out_ix + 3U] = (uint8_t)BASE64_PAD_CHAR;
        out_ix += BASE64_ENCODE_OUTPUT_BYTES;
    } else if (remaining == 1U) {
        val = ((uint32_t)input[in_ix] << BASE64_OCTET_SHIFT_0);

        output[out_ix] = base64_table[(val >> BASE64_SEXTET_SHIFT_0) & BASE64_SEXTET_MASK];
        output[out_ix + 1U] = base64_table[(val >> BASE64_SEXTET_SHIFT_1) & BASE64_SEXTET_MASK];
        output[out_ix + 2U] = (uint8_t)BASE64_PAD_CHAR;
        output[out_ix + 3U] = (uint8_t)BASE64_PAD_CHAR;
        out_ix += BASE64_ENCODE_OUTPUT_BYTES;
    } else {
        /* remaining == 0 after full blocks */
    }

    if (out_ix > (uint32_t)INT_MAX) {
        return -1;
    }
    return (int32_t)out_ix;
}

/**
 * @brief Map one Base64 character to a 6-bit value, or sentinel for skip/pad/invalid.
 * @param c Input byte.
 * @return 0..63 data, -1 padding '=', -2 ignorable whitespace, -3 invalid.
 */
static int32_t noxtls_base64_decode_sextet(unsigned char c)
{
    if ((c == (unsigned char)'\r') || (c == (unsigned char)'\n')
        || (c == (unsigned char)'\t') || (c == (unsigned char)' ')) {
        return -2;
    }
    if (c == (unsigned char)BASE64_PAD_CHAR) {
        return -1;
    }
    if ((c >= (unsigned char)'A') && (c <= (unsigned char)'Z')) {
        return (int32_t)c - (int32_t)'A';
    }
    if ((c >= (unsigned char)'a') && (c <= (unsigned char)'z')) {
        return ((int32_t)c - (int32_t)'a') + 26;
    }
    if ((c >= (unsigned char)'0') && (c <= (unsigned char)'9')) {
        return ((int32_t)c - (int32_t)'0') + 52;
    }
    if (c == (unsigned char)'+') {
        return 62;
    }
    if (c == (unsigned char)'/') {
        return 63;
    }
    return -3;
}

/**
 * @brief Emit up to three bytes from one Base64 quantum (handles '=' padding).
 * @param s Four sextet values, or -1 for padding positions.
 * @param output Decoded output buffer.
 * @param out_ix In/out write index into output.
 * @return 0 on success, -1 on invalid quantum.
 */
static int32_t noxtls_base64_emit_quantum(const int32_t s[4], uint8_t *output, uint32_t *out_ix)
{
    int32_t a;
    int32_t b;
    int32_t c;
    int32_t d;
    uint32_t val;
    uint32_t ix;

    a = s[0];
    b = s[1];
    c = s[2];
    d = s[3];
    ix = *out_ix;
    if ((a < 0) || (b < 0)) {
        return -1;
    }
    if (d == -1) {
        if (c == -1) {
            val = (((uint32_t)a << 18) | ((uint32_t)b << 12));
            output[ix] = (uint8_t)(val >> 16);
            ix += 1U;
        } else {
            /* MISRA 15.7: final else path */
            if (c < 0) {
                return -1;
            }
            val = (((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6));
            output[ix] = (uint8_t)(val >> 16);
            ix += 1U;
            output[ix] = (uint8_t)(val >> 8);
            ix += 1U;
        }
    } else {
        /* MISRA 15.7: final else path */
        if ((c < 0) || (d < 0)) {
            return -1;
        }
        val = (((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6) | (uint32_t)d);
        output[ix] = (uint8_t)(val >> 16);
        ix += 1U;
        output[ix] = (uint8_t)(val >> 8);
        ix += 1U;
        output[ix] = (uint8_t)val;
        ix += 1U;
    }
    *out_ix = ix;
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
int32_t noxtls_base64_decode(const uint8_t * input, uint32_t len, uint8_t * output)
{
    uint32_t out_ix;
    uint32_t i;
    int32_t s[4];
    int32_t ns;
    int32_t t;
    int32_t expected_tail_pad;
    int32_t seen_tail_pad;

    if ((input == NULL) || (output == NULL)) {
        return -1;
    }
    if (len == 0U) {
        return 0;
    }

    out_ix = 0U;
    i = 0U;
    ns = 0;

    while (i < len) {
        int32_t v = noxtls_base64_decode_sextet((unsigned char)input[i]);
        i++;
        if (v == -2) {
            continue;
        }
        if (v == -3) {
            return -1;
        }
        if (v == -1) {
            if (ns == 0) {
                return -1;
            }
            expected_tail_pad = (ns == 2) ? 1 : 0;
            seen_tail_pad = 0;
            while (ns < 4) {
                s[ns] = -1;
                ns++;
            }
            if (noxtls_base64_emit_quantum(s, output, &out_ix) != 0) {
                return -1;
            }
            ns = 0;
            while (i < len) {
                t = noxtls_base64_decode_sextet((unsigned char)input[i]);
                i++;
                if (t == -2) {
                    continue;
                }
                if (t == -1) {
                    if (seen_tail_pad >= expected_tail_pad) {
                        return -1;
                    }
                    seen_tail_pad++;
                    continue;
                }
                return -1;
            }
            if (seen_tail_pad != expected_tail_pad) {
                return -1;
            }
            break;
        }
        s[ns] = v;
        ns++;
        if (ns == 4) {
            if (noxtls_base64_emit_quantum(s, output, &out_ix) != 0) {
                return -1;
            }
            ns = 0;
        }
    }

    if (ns != 0) {
        return -1;
    }

    if (out_ix > (uint32_t)INT_MAX) {
        return -1;
    }
    return (int32_t)out_ix;
}

/**
 * @brief Decodes Base64 character to value
 *
 * @param base64 Character to decode
 * 
 * @return value decoded
 */
uint8_t noxtls_base64_decode_char(uint8_t c)
{
    unsigned char uc = (unsigned char)c;
    uint32_t value;

    if ((uc >= (unsigned char)BASE64_UPPERCASE_START) && (uc <= (unsigned char)'Z')) {
        value = (uint32_t)uc - (uint32_t)(unsigned char)BASE64_UPPERCASE_START;
        return (uint8_t)value;
    }
    if ((uc >= (unsigned char)BASE64_LOWERCASE_START) && (uc <= (unsigned char)'z')) {
        value = ((uint32_t)uc - (uint32_t)(unsigned char)BASE64_LOWERCASE_START)
              + (uint32_t)BASE64_LOWERCASE_OFFSET;
        return (uint8_t)value;
    }
    if ((uc >= (unsigned char)BASE64_DIGIT_START) && (uc <= (unsigned char)'9')) {
        value = ((uint32_t)uc - (uint32_t)(unsigned char)BASE64_DIGIT_START)
              + (uint32_t)BASE64_DIGIT_OFFSET;
        return (uint8_t)value;
    }
    if (uc == (unsigned char)'+') {
        return (uint8_t)BASE64_PLUS_VALUE;
    }
    if (uc == (unsigned char)'/') {
        return (uint8_t)BASE64_SLASH_VALUE;
    }

    return 0U;
}
