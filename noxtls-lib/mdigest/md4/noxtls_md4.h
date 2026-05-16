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
* File:    noxtls_md4.h
* Summary: NOXTLS MD4
*
*/

/** @addtogroup noxtls_mdigest */
/** @{ */

#ifndef _NOXTLS_MD4_H_
#define _NOXTLS_MD4_H_

#include "noxtls_sha.h"
#include "noxtls_common.h"
#include "noxtls_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HASH_MD4_BLOCK_SIZE  (64)
#define HASH_MD4_BLOCK_BITS (512u)
#define HASH_MD4_LENGTH_LEN (8)   /* length in bytes (64-bit) */
#define HASH_MD4_STATE_WORDS (4)   /* 4 x 32-bit words = 128 bits */
#define HASH_MD4_OUT_LEN    (16)
#define MD4_WORD_BYTES (4u)
#define MD4_WORDS_PER_BLOCK (16u)
/* RFC 1320: three compression rounds (F, G, H), 16 left-rotate steps each. */
#define MD4_COMPRESS_ROUNDS (3u)
#define MD4_ROT_SHIFT_TABLE_LEN (MD4_COMPRESS_ROUNDS * MD4_WORDS_PER_BLOCK)
#define MD4_ROT_SHIFT_ROUND2_BASE (MD4_WORDS_PER_BLOCK)
#define MD4_ROT_SHIFT_ROUND3_BASE ((MD4_WORDS_PER_BLOCK) * 2u)
#define MD4_PAD_BYTE (0x80u)
#define MD4_ROUND2_CONST (0x5a827999u)
#define MD4_ROUND3_CONST (0x6ed9eba1u)

noxtls_return_t noxtls_md4_init(noxtls_sha_ctx_t * ctx);
/* data must point to at least len bytes. len > 0x7FFFFFFF or overflow of total length returns NOXTLS_RETURN_INVALID_PARAM. */
noxtls_return_t noxtls_md4_update(noxtls_sha_ctx_t * ctx, const uint8_t * data, uint32_t len);
noxtls_return_t noxtls_md4_finish(noxtls_sha_ctx_t * ctx, uint8_t * hash);
noxtls_return_t noxtls_md4_verify(const uint8_t * data, uint32_t len, const uint8_t * expected);
void noxtls_md4_set_debug(uint8_t lvl);

#ifdef __cplusplus
}
#endif

#endif

