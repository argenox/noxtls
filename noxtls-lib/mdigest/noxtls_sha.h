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
* File:    bluenox_config.h
* Summary: Bluenox Stack Configuration
*
*/

/** @addtogroup noxtls_mdigest */
/** @{ */

#ifndef _NOXTLS_SHA_H_
#define _NOXTLS_SHA_H_

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
typedef struct
{
    noxtls_hash_algos_t algo;
	uint8_t data[64];  /* Used for holding remainder data */
	uint8_t data_len;  /* Counts data in data */
	uint32_t h[8];      /* holds state */
    uint32_t length;    /* Full data length */
    noxtls_sha3_ctx_t sha3_ctx;   /* Used when algo is SHA3 */
    noxtls_blake2_ctx_t blake2_ctx; /* Used when algo is BLAKE2s/BLAKE2b */
#if (NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512)
    noxtls_sha512_ctx_t sha512_ctx; /* Used when algo is SHA-384/SHA-512/truncated */
#endif
} noxtls_sha_ctx_t;
NOXTLS_MSVC_WARNING_POP

noxtls_return_t noxtls_sha_init(noxtls_sha_ctx_t * ctx, noxtls_hash_algos_t algo);
noxtls_return_t noxtls_sha_update(noxtls_sha_ctx_t * ctx, uint8_t * data, uint32_t len);
noxtls_return_t noxtls_sha_finish(noxtls_sha_ctx_t * ctx, uint8_t * hash);

#ifdef __cplusplus
}
#endif

#endif
