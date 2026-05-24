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
* File:    noxtls_ripemd160.h
* Summary: RIPEMD-160 (ISO/IEC 10118-3) Implementation
*
*
*****************************************************************************/

/** @addtogroup noxtls_mdigest */
/** @{ */

#ifndef _NOXTLS_RIPEMD160_H_
#define _NOXTLS_RIPEMD160_H_

#include "noxtls_sha.h"
#include "noxtls_common.h"
#include "noxtls_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HASH_RIPEMD160_OUT_LEN    (20)
#define RIPEMD160_BLOCK_SIZE_BYTES (64U)
#define RIPEMD160_BLOCK_SIZE_BITS  (512U)
#define RIPEMD160_STATE_WORDS      (5U)
#define RIPEMD160_WORD_BYTES       (4U)
#define RIPEMD160_WORDS_PER_BLOCK  (16U) /* one 512-bit block as uint32_t little-endian words */

/* Default chaining variables H0..H4 (RIPEMD-160, ISO/IEC 10118-3). */
#define RIPEMD160_IV0 (0x67452301u)
#define RIPEMD160_IV1 (0xEFCDAB89u)
#define RIPEMD160_IV2 (0x98BADCFEu)
#define RIPEMD160_IV3 (0x10325476u)
#define RIPEMD160_IV4 (0xC3D2E1F0u)

/**
 * @brief Initialize RIPEMD-160 hashing (ISO/IEC 10118-3).
 * @param ctx Context to initialize; uses noxtls_sha_ctx_t. Must not be NULL.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL.
 */
noxtls_return_t noxtls_ripemd160_init(noxtls_sha_ctx_t * ctx);

/**
 * @brief Feed data into the RIPEMD-160 hash.
 * @param ctx Initialized RIPEMD-160 context from noxtls_ripemd160_init.
 * @param data Input data; may be NULL only if len is 0.
 * @param len Number of bytes to hash.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL or data is NULL with len non-zero.
 */
noxtls_return_t noxtls_ripemd160_update(noxtls_sha_ctx_t * ctx, const uint8_t * data, uint32_t len);

/**
 * @brief Finalize RIPEMD-160 and write the 20-byte digest.
 * @param ctx Initialized RIPEMD-160 context.
 * @param hash Output buffer; must hold at least HASH_RIPEMD160_OUT_LEN (20) bytes.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx or hash is NULL.
 */
noxtls_return_t noxtls_ripemd160_finish(noxtls_sha_ctx_t * ctx, uint8_t * hash);

/**
 * @brief Compute RIPEMD-160 of data and compare to expected digest.
 * @param data Input data to hash; may be NULL only if len is 0.
 * @param len Number of bytes to hash.
 * @param expected Expected 20-byte RIPEMD-160 digest for comparison.
 * @return NOXTLS_RETURN_SUCCESS if digest matches, NOXTLS_RETURN_FAILED otherwise or on error.
 */
noxtls_return_t noxtls_ripemd160_verify(const uint8_t * data, uint32_t len, const uint8_t * expected);

#ifdef __cplusplus
}
#endif

#endif
