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
* File:    noxtls_hash.h
* Summary: NOXTLS Hash Definitions
*
*/

/**
 * @defgroup noxtls_mdigest Message Digest
 * @brief Hash algorithms: MD4, MD5, SHA-1, SHA-2, SHA-3, RIPEMD-160, BLAKE2.
 * @addtogroup noxtls
 */
/** @{ */

#ifndef _NOXTLS_HASH_H_
#define _NOXTLS_HASH_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    NOXTLS_HASH_MD4,        /* MD4          RFC 1320 */
    NOXTLS_HASH_MD5,        /* MD5          RFC 1321 */
	NOXTLS_HASH_SHA1,        /* SHA-1        FIPS 180-4 */
	NOXTLS_HASH_SHA_224,     /* SHA-224      FIPS 180-4 */
	NOXTLS_HASH_SHA_256,     /* SHA-256      FIPS 180-4 */
	NOXTLS_HASH_SHA_384,     /* SHA-384      FIPS 180-4 */
	NOXTLS_HASH_SHA_512,     /* SHA-512      FIPS 180-4 */
	NOXTLS_HASH_SHA_512_224, /* SHA-512/224  FIPS 180-4 */
	NOXTLS_HASH_SHA_512_256, /* SHA-512/256  FIPS 180-4 */
	NOXTLS_HASH_SHA3_224,    /* SHA3-224     FIPS 202 */
	NOXTLS_HASH_SHA3_256,    /* SHA3-256     FIPS 202 */
	NOXTLS_HASH_SHA3_384,    /* SHA3-384     FIPS 202 */
	NOXTLS_HASH_SHA3_512,    /* SHA3-512     FIPS 202 */
	NOXTLS_HASH_RIPEMD160,   /* RIPEMD-160   ISO/IEC 10118-3 */
	NOXTLS_HASH_BLAKE2S_256, /* BLAKE2s-256  RFC 7693 */
	NOXTLS_HASH_BLAKE2B_512, /* BLAKE2b-512  RFC 7693 */

} noxtls_hash_algos_t;

void add_padding_length(uint8_t * data, uint32_t block_size, uint64_t length, uint8_t length_size);
void add_padding_length_little(uint8_t * data, uint32_t block_size, uint64_t length, uint8_t length_size);
void print_hash(uint8_t * hash, uint16_t len);

#ifdef __cplusplus
}
#endif

#endif
