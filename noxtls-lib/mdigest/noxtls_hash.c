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
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
void noxtls_add_padding_length(uint8_t * data, uint32_t block_size, uint64_t length, uint8_t length_size)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint64_t bit_len = length * NOXTLS_HASH_BITS_PER_BYTE;
    uint32_t i = 0;

    if(data == NULL || block_size == 0 || length_size == 0 || length_size > block_size) {
        return;
    }

    /* Big-endian length. For SHA-512, length_size is 16 but bit_len is 64-bit. */
    if(length_size > NOXTLS_HASH_BITLEN_UINT64_BYTES) {
        /* High bytes are zero when bit length fits in 64 bits */
        for(i = 0; i < (uint32_t)(length_size - NOXTLS_HASH_BITLEN_UINT64_BYTES); i++) {
            data[block_size - length_size + i] = 0x00;
        }
        for(i = 0; i < NOXTLS_HASH_BITLEN_UINT64_BYTES; i++) {
            data[block_size - 1U - i] =
                (uint8_t)((bit_len >> (NOXTLS_HASH_BITS_PER_BYTE * i)) & UINT8_MAX);
        }
    } else {
        for(i = 0; i < length_size; i++) {
            data[block_size - 1U - i] =
                (uint8_t)((bit_len >> (NOXTLS_HASH_BITS_PER_BYTE * i)) & UINT8_MAX);
        }
    }
}

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
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
void noxtls_add_padding_length_little(uint8_t * data, uint32_t block_size, uint64_t length, uint8_t length_size)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint64_t bit_len = length * NOXTLS_HASH_BITS_PER_BYTE;
    uint32_t i = 0;

    if(data == NULL || block_size == 0 || length_size == 0 || length_size > block_size) {
        return;
    }

    for(i = 0; i < length_size; i++)
    {
        data[block_size - length_size + i] =
            (uint8_t)((bit_len >> (NOXTLS_HASH_BITS_PER_BYTE * i)) & UINT8_MAX);
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
    int i = 0;
    if(hash == NULL || len == 0) {
        return;
    }
    for(i = 0; i < len; i++)
    {
        noxtls_debug_printf("%02x", hash[i]);
    }
    noxtls_debug_printf("\n");
}
