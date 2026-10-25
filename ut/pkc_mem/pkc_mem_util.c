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
* File:    pkc_mem_util.c
* Summary: Hex decoding helpers for the pkc_mem vector tables
*
*****************************************************************************/

#include <string.h>

#include "pkc_mem_data.h"

/**
 * @brief Value of one hex digit.
 * @param[in] c Character.
 * @return 0..15, or -1 if @p c is not a hex digit.
 */
static int pkc_mem_nibble(char c)
{
    if((c >= '0') && (c <= '9')) {
        return (int)(c - '0');
    }
    if((c >= 'a') && (c <= 'f')) {
        return (int)(c - 'a') + 10;
    }
    if((c >= 'A') && (c <= 'F')) {
        return (int)(c - 'A') + 10;
    }
    return -1;
}

uint32_t pkc_mem_unhex(uint8_t *out, uint32_t cap, const char *hex)
{
    size_t len;
    uint32_t i;

    if((out == NULL) || (hex == NULL)) {
        return 0U;
    }
    len = strlen(hex);
    if(((len & 1U) != 0U) || ((len / 2U) > (size_t)cap)) {
        return 0U;
    }
    for(i = 0U; i < (uint32_t)(len / 2U); i++) {
        const int hi = pkc_mem_nibble(hex[2U * i]);
        const int lo = pkc_mem_nibble(hex[(2U * i) + 1U]);
        if((hi < 0) || (lo < 0)) {
            return 0U;
        }
        out[i] = (uint8_t)(((uint32_t)hi << 4U) | (uint32_t)lo);
    }
    return (uint32_t)(len / 2U);
}

int pkc_mem_unhex_fixed(uint8_t *out, uint32_t width, const char *hex)
{
    uint8_t tmp[PKC_MEM_MAX_BYTES];
    uint32_t n = pkc_mem_unhex(tmp, (uint32_t)sizeof(tmp), hex);

    if((out == NULL) || (n == 0U) || (n > width)) {
        return 0;
    }
    (void)memset(out, 0, (size_t)width);
    (void)memcpy(&out[width - n], tmp, (size_t)n);
    return 1;
}
