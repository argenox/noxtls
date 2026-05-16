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
* File:    noxtls_sha256.c
* Summary: NOXTLS SHA256
*
*/

/** @addtogroup noxtls_mdigest */
/** @{ */

#ifndef _NOXTLS_SHA256_H_
#define _NOXTLS_SHA256_H_

#include "noxtls_sha.h"
#include "noxtls_common.h"
#include "noxtls_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HASH_SHA256_OUT_LEN       (32)
#define SHA256_BLOCK_SIZE_BYTES   (64u)
#define SHA256_BLOCK_SIZE_BITS    (512u)
#define SHA256_LENGTH_FIELD_BYTES (8u)
#define SHA256_PAD_BYTE           (0x80u)
#define SHA256_ROUND_COUNT        (64u)
#define SHA256_STATE_WORDS        (8u)
#define SHA224_STATE_WORDS        (7u)
#define SHA256_WORD_BYTES         (4u)
#define SHA256_WORDS_PER_BLOCK    (16u)

noxtls_return_t noxtls_sha256_init(noxtls_sha_ctx_t * ctx, noxtls_hash_algos_t algo);
noxtls_return_t noxtls_sha256_update(noxtls_sha_ctx_t * ctx, const uint8_t * data, uint32_t len);
noxtls_return_t noxtls_sha256_finish(noxtls_sha_ctx_t * ctx, uint8_t * hash);
noxtls_return_t noxtls_sha256_verify(const uint8_t * data, uint32_t len, const uint8_t * expected);
noxtls_return_t noxtls_sha224_verify(const uint8_t * data, uint32_t len, const uint8_t * expected);
void noxtls_sha256_set_debug(uint8_t lvl);

#ifdef __cplusplus
}
#endif

#endif
