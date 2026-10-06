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
* File:    noxtls_hash.c
* Summary: NoxTLS Generic Hash Interface Implementation
*
*
*****************************************************************************/

/** @addtogroup noxtls_mdigest */

#include <stdint.h>
#include <string.h>

#include "noxtls_common.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_sha.h"
#include "noxtls_hash.h"

/**
 * @brief Adds padding length to the data
 *
 * @details the length is the bit length and appended at the end
 *
 *
 * @param[in,out] data is the data to
 * @param[in] block_size is the block size being processed in bytes
 * @param[in] length is the length of the data in bytes
 * @param[in] length_size is the size of length in bytes
 *
 */
/* Hash padding writes length field inside caller block buffer. */

static uint8_t noxtls_hash_bitlen_byte(uint64_t bit_len, uint32_t i)
{
    switch(i) {
    case 0U: return (uint8_t)(bit_len);
    case 1U: return (uint8_t)(bit_len >> 8U);
    case 2U: return (uint8_t)(bit_len >> 16U);
    case 3U: return (uint8_t)(bit_len >> 24U);
    case 4U: return (uint8_t)(bit_len >> 32U);
    case 5U: return (uint8_t)(bit_len >> 40U);
    case 6U: return (uint8_t)(bit_len >> 48U);
    case 7U: return (uint8_t)(bit_len >> 56U);
    default: return 0U;
    }
}

void noxtls_add_padding_length(uint8_t * data, uint32_t block_size, uint64_t length, uint8_t length_size)
{
    uint64_t bit_len = (uint64_t)(length * (uint64_t)NOXTLS_HASH_BITS_PER_BYTE);
    uint32_t i = 0U;

    if ((data == NULL) || (block_size == 0U) || (length_size == 0U) || (length_size > block_size)) {
        return;
    }

    /* Big-endian length. For SHA-512, length_size is 16 but bit_len is 64-bit. */
    if (length_size > (uint8_t)NOXTLS_HASH_BITLEN_UINT64_BYTES) {
        /* High bytes are zero when bit length fits in 64 bits */
        for (i = 0U; i < ((uint32_t)length_size - (uint32_t)NOXTLS_HASH_BITLEN_UINT64_BYTES); i += 1U) {
            data[block_size - (uint32_t)length_size + i] = 0x00U;
        }
        for (i = 0U; i < (uint32_t)NOXTLS_HASH_BITLEN_UINT64_BYTES; i += 1U) {
            data[block_size - 1U - i] =
                noxtls_hash_bitlen_byte(bit_len, i);
        }
    } else {
        for (i = 0U; i < (uint32_t)length_size; i += 1U) {
            data[block_size - 1U - i] =
                noxtls_hash_bitlen_byte(bit_len, i);
        }
    }
}

/**
 * @brief Adds padding length to the data (little-endian length field)
 */
void noxtls_add_padding_length_little(uint8_t * data, uint32_t block_size, uint64_t length, uint8_t length_size)
{
    uint64_t bit_len = (uint64_t)(length * (uint64_t)NOXTLS_HASH_BITS_PER_BYTE);
    uint32_t i = 0U;

    if ((data == NULL) || (block_size == 0U) || (length_size == 0U) || (length_size > block_size)) {
        return;
    }

    for (i = 0U; i < (uint32_t)length_size; i += 1U)
    {
        data[block_size - (uint32_t)length_size + i] =
            noxtls_hash_bitlen_byte(bit_len, i);
    }
}

/**
 * @brief Print the hash
 * 
 * @param[in] hash The hash to print.
 * @param[in] len The length of the hash.
 * @return void
 */
void noxtls_print_hash(const uint8_t * hash, uint16_t len)
{
    uint16_t i = 0U;
    if ((hash == NULL) || (len == 0U)) {
        return;
    }
    for (i = 0U; i < len; i += 1U)
    {
        (void)noxtls_debug_printf((const uint8_t *)"%02x", hash[i]);
    }
    (void)noxtls_debug_printf((const uint8_t *)"\n");
}
