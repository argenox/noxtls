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
* File:    sha256.h
* Summary: Bluenox Stack Configuration
*
*/

/** @addtogroup noxtls_mdigest */

#include <stdint.h>
#include <stddef.h>
#include "noxtls_common.h"
#include "noxtls_sha.h"
#include "noxtls_hash.h"

#if NOXTLS_FEATURE_MD4
#include "md4/noxtls_md4.h"
#endif
#if NOXTLS_FEATURE_MD5
#include "md5/noxtls_md5.h"
#endif
#if NOXTLS_FEATURE_SHA1
#include "sha1/noxtls_sha1.h"
#endif
#if (NOXTLS_FEATURE_SHA224 || NOXTLS_FEATURE_SHA256)
#include "sha256/noxtls_sha256.h"
#endif
#if (NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512)
#include "sha512/noxtls_sha512.h"
#endif
#if NOXTLS_FEATURE_SHA3
#include "sha3/noxtls_sha3.h"
#endif
#if NOXTLS_FEATURE_RIPEMD160
#include "ripemd160/noxtls_ripemd160.h"
#endif
#if NOXTLS_FEATURE_BLAKE2
#include "blake2/noxtls_blake2.h"
#endif

/**
 * @brief Initialize SHA
 * 
 * @param ctx SHA context
 * @param algo Algorithm to use
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
noxtls_return_t noxtls_sha_init(noxtls_sha_ctx_t * ctx, noxtls_hash_algos_t algo)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    ctx->algo = algo;
    
    switch(ctx->algo)
    {
        case NOXTLS_HASH_MD4:
#if NOXTLS_FEATURE_MD4
            return noxtls_md4_init(ctx);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_HASH_MD5:
#if NOXTLS_FEATURE_MD5
            return noxtls_md5_init(ctx);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_HASH_SHA1:
#if NOXTLS_FEATURE_SHA1
            return noxtls_sha1_init(ctx, algo);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_HASH_SHA_224:
        case NOXTLS_HASH_SHA_256:
#if NOXTLS_FEATURE_SHA224 || NOXTLS_FEATURE_SHA256
            if((algo == NOXTLS_HASH_SHA_224 && !NOXTLS_FEATURE_SHA224) ||
               (algo == NOXTLS_HASH_SHA_256 && !NOXTLS_FEATURE_SHA256)) {
                return NOXTLS_RETURN_NOT_SUPPORTED;
            }
            return noxtls_sha256_init(ctx, algo);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_HASH_SHA_384:
        case NOXTLS_HASH_SHA_512:
        case NOXTLS_HASH_SHA_512_224:
        case NOXTLS_HASH_SHA_512_256:
#if NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512
            if((algo == NOXTLS_HASH_SHA_384 && !NOXTLS_FEATURE_SHA384) ||
               ((algo == NOXTLS_HASH_SHA_512 ||
                 algo == NOXTLS_HASH_SHA_512_224 ||
                 algo == NOXTLS_HASH_SHA_512_256) && !NOXTLS_FEATURE_SHA512)) {
                return NOXTLS_RETURN_NOT_SUPPORTED;
            }
            return noxtls_sha512_init(&ctx->sha512_ctx, algo);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_HASH_SHA3_224:
#if NOXTLS_FEATURE_SHA3
            return noxtls_sha3_224_init(&ctx->sha3_ctx);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_HASH_SHA3_256:
#if NOXTLS_FEATURE_SHA3
            return noxtls_sha3_256_init(&ctx->sha3_ctx);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_HASH_SHA3_384:
#if NOXTLS_FEATURE_SHA3
            return noxtls_sha3_384_init(&ctx->sha3_ctx);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_HASH_SHA3_512:
#if NOXTLS_FEATURE_SHA3
            return noxtls_sha3_512_init(&ctx->sha3_ctx);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_HASH_RIPEMD160:
#if NOXTLS_FEATURE_RIPEMD160
            return noxtls_ripemd160_init(ctx);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_HASH_BLAKE2S_256:
#if NOXTLS_FEATURE_BLAKE2
            return noxtls_blake2s_256_init(&ctx->blake2_ctx);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_HASH_BLAKE2B_512:
#if NOXTLS_FEATURE_BLAKE2
            return noxtls_blake2b_512_init(&ctx->blake2_ctx);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        default:
            return NOXTLS_RETURN_NOT_SUPPORTED;
    }
}

/**
 * @brief Update SHA
 * 
 * @param ctx SHA context
 * @param data Data to update
 * @param len Length of data to update
 * @return int NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
noxtls_return_t noxtls_sha_update(noxtls_sha_ctx_t * ctx, uint8_t * data, uint32_t len)
{
    if(ctx == NULL || data == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    switch(ctx->algo)
    {
        case NOXTLS_HASH_MD4:
#if NOXTLS_FEATURE_MD4
            return noxtls_md4_update(ctx, data, len);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_HASH_MD5:
#if NOXTLS_FEATURE_MD5
            return noxtls_md5_update(ctx, data, len);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_HASH_SHA1:
#if NOXTLS_FEATURE_SHA1
            return noxtls_sha1_update(ctx, data, len);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_HASH_SHA_224:
        case NOXTLS_HASH_SHA_256:
#if (NOXTLS_FEATURE_SHA224 || NOXTLS_FEATURE_SHA256)
            return noxtls_sha256_update(ctx, data, len);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_HASH_SHA_384:
        case NOXTLS_HASH_SHA_512:
        case NOXTLS_HASH_SHA_512_224:
        case NOXTLS_HASH_SHA_512_256:
#if (NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512)
            return noxtls_sha512_update(&ctx->sha512_ctx, data, len);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_HASH_SHA3_224:
        case NOXTLS_HASH_SHA3_256:
        case NOXTLS_HASH_SHA3_384:
        case NOXTLS_HASH_SHA3_512:
#if NOXTLS_FEATURE_SHA3
            return noxtls_sha3_update(&ctx->sha3_ctx, data, len);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_HASH_RIPEMD160:
#if NOXTLS_FEATURE_RIPEMD160
            return noxtls_ripemd160_update(ctx, data, len);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_HASH_BLAKE2S_256:
        case NOXTLS_HASH_BLAKE2B_512:
#if NOXTLS_FEATURE_BLAKE2
            return noxtls_blake2_update(&ctx->blake2_ctx, data, len);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        default:
            return NOXTLS_RETURN_NOT_SUPPORTED;
    }
}

/**
 * @brief Finish SHA
 * 
 * @param ctx SHA context
 * @param hash Hash to finish
 * @return int NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
noxtls_return_t noxtls_sha_finish(noxtls_sha_ctx_t * ctx, uint8_t * hash)
{
    if(ctx == NULL || hash == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    switch(ctx->algo)
    {
        case NOXTLS_HASH_MD4:
#if NOXTLS_FEATURE_MD4
            return noxtls_md4_finish(ctx, hash);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_HASH_MD5:
#if NOXTLS_FEATURE_MD5
            return noxtls_md5_finish(ctx, hash);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_HASH_SHA1:
#if NOXTLS_FEATURE_SHA1
            return noxtls_sha1_finish(ctx, hash);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_HASH_SHA_224:
        case NOXTLS_HASH_SHA_256:
#if (NOXTLS_FEATURE_SHA224 || NOXTLS_FEATURE_SHA256)
            return noxtls_sha256_finish(ctx, hash);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_HASH_SHA_384:
        case NOXTLS_HASH_SHA_512:
        case NOXTLS_HASH_SHA_512_224:
        case NOXTLS_HASH_SHA_512_256:
#if (NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512)
            return noxtls_sha512_finish(&ctx->sha512_ctx, hash);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_HASH_SHA3_224:
        case NOXTLS_HASH_SHA3_256:
        case NOXTLS_HASH_SHA3_384:
        case NOXTLS_HASH_SHA3_512:
#if NOXTLS_FEATURE_SHA3
            return noxtls_sha3_finish(&ctx->sha3_ctx, hash);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_HASH_RIPEMD160:
#if NOXTLS_FEATURE_RIPEMD160
            return noxtls_ripemd160_finish(ctx, hash);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        case NOXTLS_HASH_BLAKE2S_256:
        case NOXTLS_HASH_BLAKE2B_512:
#if NOXTLS_FEATURE_BLAKE2
            return noxtls_blake2_finish(&ctx->blake2_ctx, hash);
#else
            return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
        default:
            return NOXTLS_RETURN_NOT_SUPPORTED;
    }
}
