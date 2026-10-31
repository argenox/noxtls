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
* File:    noxtls_sha.h
* Summary: NoxTLS SHA Interface Definition
*
*
*****************************************************************************/

/** @addtogroup noxtls_mdigest */
/** @{ */

#ifndef NOXTLS_SHA_H_
#define NOXTLS_SHA_H_

#include "noxtls_hash.h"
#include "noxtls_common.h"
#ifdef __cplusplus
extern "C" {
#endif
#include "sha3/noxtls_sha3.h"
#include "blake2/noxtls_blake2.h"
#if (NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512)
#include "sha512/noxtls_sha512.h"
#endif
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif

NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
/**
 * @brief Merkle-Damgard 32-bit-word state shared by MD4, MD5, SHA-1,
 *        SHA-224/256 and RIPEMD-160 (accessed as ctx->u.md32.*).
 */
typedef struct
{
    uint32_t h[8];      /* chaining state */
    uint32_t length;    /* bytes compressed so far (full blocks) */
    uint8_t data[64];   /* buffered partial block */
    uint8_t data_len;   /* bytes held in data[] */
} noxtls_sha_md32_ctx_t;

/**
 * @brief Generic hash context (tagged union).
 *
 * @c algo selects which member of @c u is live; noxtls_sha_init() sets it and
 * initialises only that member. The context is therefore as large as the
 * widest hash enabled at build time (MD32 104 B, SHA-384/512 200 B, SHA-3
 * 208 B, BLAKE2 208 B, plus the tag), so code that is linked with the library
 * must be compiled with the same NOXTLS_FEATURE_* hash switches.
 */
typedef struct
{
    noxtls_hash_algos_t algo;
    union {
        noxtls_sha_md32_ctx_t md32;     /* MD4/MD5/SHA-1/SHA-224/SHA-256/RIPEMD-160 */
#if (NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512)
        noxtls_sha512_ctx_t sha512_ctx; /* SHA-384/SHA-512/SHA-512/t */
#endif
#if NOXTLS_FEATURE_SHA3
        noxtls_sha3_ctx_t sha3_ctx;     /* SHA3-224..512 */
#endif
#if NOXTLS_FEATURE_BLAKE2
        noxtls_blake2_ctx_t blake2_ctx; /* BLAKE2s-256/BLAKE2b-512 */
#endif
    } u;
} noxtls_sha_ctx_t;
NOXTLS_MSVC_WARNING_POP

noxtls_return_t noxtls_sha_init(noxtls_sha_ctx_t * ctx, noxtls_hash_algos_t algo);
noxtls_return_t noxtls_sha_update(noxtls_sha_ctx_t * ctx, const uint8_t * data, uint32_t len);
noxtls_return_t noxtls_sha_finish(noxtls_sha_ctx_t * ctx, uint8_t * hash);

#ifdef __cplusplus
}
#endif

#endif
