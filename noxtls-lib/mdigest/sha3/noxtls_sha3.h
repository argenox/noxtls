/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
* 
*
* File:    noxtls_sha3.h
* Summary: NOXTLS SHA3 Hash Definitions
*
*/

/** @addtogroup noxtls_mdigest */
/** @{ */

#ifndef _NOXTLS_SHA3_H
#define _NOXTLS_SHA3_H

#include <stdint.h>
#include "noxtls_hash.h"
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SHA3_STATE_SIZE 200  /* 1600 bits = 200 bytes */
#define SHA3_MAX_X_SIZE 5
#define SHA3_MAX_Y_SIZE 5
#define SHA3_MAX_RATE_BYTES       (144u)
#define SHA3_LANE_BITS            (64u)
#define SHA3_LANE_BYTES           (8u)
#define SHA3_DOMAIN_SEP           (0x06u)
#define SHA3_PAD_FINAL_BYTE       (0x80u)
#define SHA3_KECCAK_ROUNDS        (24u)
#define SHA3_RATE_224_BYTES       (144u)
#define SHA3_CAPACITY_224_BYTES   (56u)
#define SHA3_RATE_256_BYTES       (136u)
#define SHA3_CAPACITY_256_BYTES   (64u)
#define SHA3_RATE_384_BYTES       (104u)
#define SHA3_CAPACITY_384_BYTES   (96u)
#define SHA3_RATE_512_BYTES       (72u)
#define SHA3_CAPACITY_512_BYTES   (128u)
/* SHAKE256 (FIPS 202): rate 1088 bits = 136 bytes, capacity 512 bits = 64 bytes */
#define SHA3_SHAKE128_RATE_BYTES   (168u)
#define SHA3_SHAKE128_CAPACITY_BYTES (32u)
#define SHA3_SHAKE128_DOMAIN_SEP   (0x1Fu)
#define SHA3_SHAKE256_RATE_BYTES   (136u)
#define SHA3_SHAKE256_CAPACITY_BYTES (64u)
#define SHA3_SHAKE256_DOMAIN_SEP   (0x1Fu)

/* SHA-3 output lengths */
#define HASH_SHA3_224_OUT_LEN     (28)
#define HASH_SHA3_256_OUT_LEN     (32)
#define HASH_SHA3_384_OUT_LEN     (48)
#define HASH_SHA3_512_OUT_LEN     (64)

NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    noxtls_hash_algos_t algo;
    uint8_t state[SHA3_STATE_SIZE];  /* 1600-bit state (5x5x64 bits) */
    uint8_t buffer[SHA3_MAX_RATE_BYTES];              /* Buffer for rate bytes (max 136 for SHA3-224) */
    uint32_t buffer_len;              /* Current bytes in buffer */
    uint32_t rate;                    /* Rate in bytes (r/8) */
    uint32_t capacity;                /* Capacity in bytes (c/8) */
    uint32_t output_len;              /* Output length in bytes */
    uint8_t domain_sep;               /* Domain separation suffix (0x06 for SHA-3) */
    uint64_t total_length;            /* Total noxtls_message length in bits */
    uint8_t finalized;                /* Flag to indicate if hash is finalized */
} noxtls_sha3_ctx_t;
NOXTLS_MSVC_WARNING_POP

/* SHA-3 initialization functions */
noxtls_return_t noxtls_sha3_224_init(noxtls_sha3_ctx_t * ctx);
noxtls_return_t noxtls_sha3_256_init(noxtls_sha3_ctx_t * ctx);
noxtls_return_t noxtls_sha3_384_init(noxtls_sha3_ctx_t * ctx);
noxtls_return_t noxtls_sha3_512_init(noxtls_sha3_ctx_t * ctx);

/* SHA-3 update and finish functions */
noxtls_return_t noxtls_sha3_update(noxtls_sha3_ctx_t * ctx, const uint8_t * data, uint32_t len);
noxtls_return_t noxtls_sha3_finish(noxtls_sha3_ctx_t * ctx, uint8_t * hash);

/* SHAKE256 (FIPS 202, extendable output). Used by Ed448 (RFC 8032). */
noxtls_return_t noxtls_shake128_init(noxtls_sha3_ctx_t * ctx);
noxtls_return_t noxtls_shake128_update(noxtls_sha3_ctx_t * ctx, const uint8_t * data, uint32_t len);
noxtls_return_t noxtls_shake128_final(noxtls_sha3_ctx_t * ctx);
noxtls_return_t noxtls_shake128_squeeze(noxtls_sha3_ctx_t * ctx, uint8_t * out, uint32_t out_len);

noxtls_return_t noxtls_shake256_init(noxtls_sha3_ctx_t * ctx);
noxtls_return_t noxtls_shake256_update(noxtls_sha3_ctx_t * ctx, const uint8_t * data, uint32_t len);
noxtls_return_t noxtls_shake256_final(noxtls_sha3_ctx_t * ctx);
noxtls_return_t noxtls_shake256_squeeze(noxtls_sha3_ctx_t * ctx, uint8_t * out, uint32_t out_len);

/* Utility functions */
void noxtls_sha3_set_debug(uint8_t lvl);
noxtls_return_t noxtls_sha3_verify(const uint8_t * data, uint32_t len, const uint8_t * expected, noxtls_hash_algos_t algo);

#ifdef __cplusplus
}
#endif

#endif
