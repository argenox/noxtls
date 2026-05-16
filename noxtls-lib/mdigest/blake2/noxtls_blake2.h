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
* File:    noxtls_blake2.h
* Summary: NOXTLS BLAKE2s and BLAKE2b (RFC 7693)
*
*/

/** @addtogroup noxtls_mdigest */
/** @{ */

#ifndef _NOXTLS_BLAKE2_H_
#define _NOXTLS_BLAKE2_H_

#include <stdint.h>
#include "noxtls_hash.h"
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HASH_BLAKE2S_256_OUT_LEN (32)
#define HASH_BLAKE2B_512_OUT_LEN (64)
#define BLAKE2S_BLOCK_BYTES (64u)
#define BLAKE2B_BLOCK_BYTES (128u)

/* RFC 7693 compression: noxtls_message schedule words, chaining half, full v[], sigma table */
#define BLAKE2_MSG_WORDS        16
#define BLAKE2_CHAINING_WORDS    8
#define BLAKE2_V_WORDS          16
#define BLAKE2_SIGMA_ROWS       10
#define BLAKE2S_ROUNDS          10
#define BLAKE2B_ROUNDS          12
#define BLAKE2S_WORD_BYTES       4
#define BLAKE2B_WORD_BYTES       8
/* Indices in v[] for t (byte count low/high) and final-block flag f */
#define BLAKE2_V_INDEX_T0       12
#define BLAKE2_V_INDEX_T1       13
#define BLAKE2_V_INDEX_F        14

NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct {
    uint8_t is_blake2b;   /* 1 for BLAKE2b, 0 for BLAKE2s */
    uint8_t outlen;       /* digest size in bytes */
    uint16_t _pad;
    uint8_t buf[128];     /* block buffer */
    uint32_t buflen;      /* bytes in buf */
    uint64_t total;       /* total bytes hashed */
    union {
        uint32_t h32[8];  /* BLAKE2s state */
        uint64_t h64[8];  /* BLAKE2b state */
    } h;
} noxtls_blake2_ctx_t;
NOXTLS_MSVC_WARNING_POP

/**
 * @brief Initialize BLAKE2s for a 256-bit (32-byte) digest (RFC 7693).
 * @param ctx Context to initialize; must not be NULL.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL.
 */
noxtls_return_t noxtls_blake2s_256_init(noxtls_blake2_ctx_t * ctx);

/**
 * @brief Initialize BLAKE2b for a 512-bit (64-byte) digest (RFC 7693).
 * @param ctx Context to initialize; must not be NULL.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL.
 */
noxtls_return_t noxtls_blake2b_512_init(noxtls_blake2_ctx_t * ctx);

/**
 * @brief Feed data into the BLAKE2 (BLAKE2s or BLAKE2b) hash.
 * @param ctx Initialized BLAKE2 context from noxtls_blake2s_256_init or noxtls_blake2b_512_init.
 * @param data Input data; may be NULL only if len is 0.
 * @param len Number of bytes to hash.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL or data is NULL with len non-zero.
 */
noxtls_return_t noxtls_blake2_update(noxtls_blake2_ctx_t * ctx, const uint8_t * data, uint32_t len);

/**
 * @brief Finalize BLAKE2 and write the digest.
 * @param ctx Initialized BLAKE2 context (from noxtls_blake2s_256_init or noxtls_blake2b_512_init).
 * @param hash Output buffer; must hold at least 32 bytes for BLAKE2s-256 or 64 bytes for BLAKE2b-512.
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx or hash is NULL.
 */
noxtls_return_t noxtls_blake2_finish(noxtls_blake2_ctx_t * ctx, uint8_t * hash);

#ifdef __cplusplus
}
#endif

#endif
