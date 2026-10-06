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
* File:    noxtls_sha512.h
* Summary: SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Hash Definition
*
*
*****************************************************************************/

/** @addtogroup noxtls_mdigest */
/** @{ */

#ifndef NOXTLS_SHA512_H_
#define NOXTLS_SHA512_H_

#include "noxtls_common.h"
#include "noxtls_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HASH_SHA512_BLOCK_SIZE  (128U)
#define HASH_SHA512_OUT_LEN     (64U)
#define HASH_SHA512_224_OUT_LEN (28U)
#define HASH_SHA512_256_OUT_LEN (32U)
#define HASH_SHA512_LENGTH_LEN  (16U)
#define SHA512_BLOCK_SIZE_BITS  (1024U)
#define SHA512_PAD_BYTE         (0x80u)
#define SHA512_ROUND_COUNT      (80U)
#define SHA512_STATE_WORDS      (8U)
#define SHA384_STATE_WORDS      (6U)
#define SHA512_WORD_BYTES       (8U)
#define SHA512_WORDS_PER_BLOCK  (16U)

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

/**
 * @brief Optional platform hook: process whole SHA-384/512 blocks in hardware.
 *
 * Implemented by the selected accelerator port when NOXTLS_PORT_SHA512_ACCEL is
 * set (common/noxtls_accel_port.h). Updates ctx->h only; the caller keeps the
 * buffered data and the message length.
 *
 * @param[in,out] ctx         Context (chaining value ctx->h).
 * @param[in]     input       Whole blocks.
 * @param[in]     block_count Number of 128-byte blocks.
 *
 * @return NOXTLS_RETURN_SUCCESS, or NOXTLS_RETURN_NOT_SUPPORTED to process the blocks in software.
 */
noxtls_return_t noxtls_sha512_blocks_accel_port(noxtls_sha512_ctx_t * ctx, const uint8_t * input, uint32_t block_count);
void noxtls_sha512_set_debug(uint8_t lvl);

#ifdef __cplusplus
}
#endif

#endif
