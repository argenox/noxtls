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
* File:    noxtls_md5.h
* Summary: Message Digest Algorithm 5 (MD5)
* Defined in RFC 1321
*
* MD5 is cryptographically broken and should not be used.
*
*
*****************************************************************************/

/** @addtogroup noxtls_mdigest */
/** @{ */

#ifndef _NOXTLS_MD5_H_
#define _NOXTLS_MD5_H_

#include "noxtls_sha.h"
#include "noxtls_common.h"
#include "noxtls_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HASH_MD5_OUT_LEN (16)
#define MD5_BLOCK_SIZE_BYTES (64U)
#define MD5_BLOCK_SIZE_BITS (512U)
#define MD5_LENGTH_FIELD_BYTES (8U)
#define MD5_PAD_BYTE (0x80u)
#define MD5_ROUND_COUNT (64U)
#define MD5_STATE_WORDS (4U)
#define MD5_WORD_BYTES (4U)
#define MD5_WORDS_PER_BLOCK (16U)

noxtls_return_t noxtls_md5_init(noxtls_sha_ctx_t * ctx);
noxtls_return_t noxtls_md5_update(noxtls_sha_ctx_t * ctx, const uint8_t * data, uint32_t len);
noxtls_return_t noxtls_md5_finish(noxtls_sha_ctx_t * ctx, uint8_t * hash);
noxtls_return_t noxtls_md5_verify(const uint8_t * data, uint32_t len, const uint8_t * expected);
void noxtls_md5_set_debug(uint8_t lvl);

#ifdef __cplusplus
}
#endif

#endif
