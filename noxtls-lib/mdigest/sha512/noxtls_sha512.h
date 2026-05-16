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
* File:    noxtls_sha512.c
* Summary: NOXTLS SHA512
*
*/

/** @addtogroup noxtls_mdigest */
/** @{ */

#ifndef _NOXTLS_SHA512_H_
#define _NOXTLS_SHA512_H_

#include "noxtls_common.h"
#include "noxtls_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HASH_SHA512_BLOCK_SIZE  (128)
#define HASH_SHA512_OUT_LEN     (64)
#define HASH_SHA512_224_OUT_LEN (28)
#define HASH_SHA512_256_OUT_LEN (32)
#define HASH_SHA512_LENGTH_LEN  (16)
#define SHA512_BLOCK_SIZE_BITS  (1024u)
#define SHA512_PAD_BYTE         (0x80u)
#define SHA512_ROUND_COUNT      (80u)
#define SHA512_STATE_WORDS      (8u)
#define SHA384_STATE_WORDS      (6u)
#define SHA512_WORD_BYTES       (8u)
#define SHA512_WORDS_PER_BLOCK  (16u)

NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    noxtls_hash_algos_t algo;
	uint8_t data[HASH_SHA512_BLOCK_SIZE];  /* Used for holding remainder data */
	uint8_t data_len;  /* Counts data in data */
	uint64_t h[8];      /* holds state */
    uint32_t length;    /* Full data length */
 
} noxtls_sha512_ctx_t;
NOXTLS_MSVC_WARNING_POP

noxtls_return_t noxtls_sha512_init(noxtls_sha512_ctx_t * ctx, noxtls_hash_algos_t algo);
noxtls_return_t noxtls_sha512_update(noxtls_sha512_ctx_t * ctx, const uint8_t * data, uint32_t len);
noxtls_return_t noxtls_sha512_finish(noxtls_sha512_ctx_t * ctx, uint8_t * hash);
noxtls_return_t noxtls_sha512_verify(const uint8_t * data, uint32_t len, const uint8_t * expected);
void noxtls_sha512_set_debug(uint8_t lvl);

#ifdef __cplusplus
}
#endif

#endif
