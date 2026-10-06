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
* File:    noxtls_sha3.c
* Summary: SHA-3 (Keccak) Hash Implementation
* Based on FIPS 202
*
*
*****************************************************************************/

/** @addtogroup noxtls_mdigest */

#include <stdint.h>
#include <string.h>

#include "noxtls_common.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_hash.h"
#include "noxtls_sha3.h"
#include "noxtls_ct.h"

#if NOXTLS_FEATURE_SHA3

/* Module Debug Level */
static uint8_t sha3_debug_lvl = 0U;

/* SHA-3 uses 64-bit lanes for Keccak-f[1600] */
typedef uint64_t sha3_lane_t;

/* Number of 64-bit lanes in the Keccak-f[1600] state (5 x 5). */
#define SHA3_LANE_COUNT (SHA3_MAX_X_SIZE * SHA3_MAX_Y_SIZE)

/* Access lane (x, y) of a local lane array. The byte state in the context is
 * never accessed through a wider type: it is only 4-byte aligned inside
 * noxtls_sha3_ctx_t (8-byte loads fault on strict-alignment cores) and FIPS 202
 * defines the lanes as little-endian byte strings, so keccak_f1600() converts
 * with explicit byte loads/stores that are correct on any alignment/endianness. */
#define SHA3_LANE(lanes, x, y) ((lanes)[(SHA3_MAX_X_SIZE * (y)) + (x)])

/**
 * @brief Load a little-endian 64-bit lane from bytes (any alignment).
 *
 * @param p Pointer to 8 bytes
 * @return sha3_lane_t Lane value
 */
static sha3_lane_t sha3_load_le64(const uint8_t *p)
{
    return ((sha3_lane_t)p[0])         | ((sha3_lane_t)p[1] << 8U)  |
           ((sha3_lane_t)p[2] << 16U)  | ((sha3_lane_t)p[3] << 24U) |
           ((sha3_lane_t)p[4] << 32U)  | ((sha3_lane_t)p[5] << 40U) |
           ((sha3_lane_t)p[6] << 48U)  | ((sha3_lane_t)p[7] << 56U);
}

/**
 * @brief Store a 64-bit lane as little-endian bytes (any alignment).
 *
 * @param p Pointer to 8 bytes
 * @param v Lane value
 */
static void sha3_store_le64(uint8_t *p, sha3_lane_t v)
{
    uint32_t i;
    for (i = 0U; i < SHA3_LANE_BYTES; i += 1U) {
        p[i] = (uint8_t)((v >> (8U * i)) & 0xFFU);
    }
}

/**
 * @brief Rotate left for 64-bit values
 *
 * @param x Value to rotate
 * @param n Number of bits to rotate
 * @return sha3_lane_t Rotated value
 */
static inline sha3_lane_t sha3_rotl64(sha3_lane_t x, uint8_t n)
{
    switch(n) {
    case 0U: return x;
    case 1U: return (sha3_lane_t)((x << 1U) | (x >> 63U));
    case 2U: return (sha3_lane_t)((x << 2U) | (x >> 62U));
    case 3U: return (sha3_lane_t)((x << 3U) | (x >> 61U));
    case 6U: return (sha3_lane_t)((x << 6U) | (x >> 58U));
    case 8U: return (sha3_lane_t)((x << 8U) | (x >> 56U));
    case 10U: return (sha3_lane_t)((x << 10U) | (x >> 54U));
    case 14U: return (sha3_lane_t)((x << 14U) | (x >> 50U));
    case 15U: return (sha3_lane_t)((x << 15U) | (x >> 49U));
    case 18U: return (sha3_lane_t)((x << 18U) | (x >> 46U));
    case 20U: return (sha3_lane_t)((x << 20U) | (x >> 44U));
    case 21U: return (sha3_lane_t)((x << 21U) | (x >> 43U));
    case 25U: return (sha3_lane_t)((x << 25U) | (x >> 39U));
    case 27U: return (sha3_lane_t)((x << 27U) | (x >> 37U));
    case 28U: return (sha3_lane_t)((x << 28U) | (x >> 36U));
    case 36U: return (sha3_lane_t)((x << 36U) | (x >> 28U));
    case 39U: return (sha3_lane_t)((x << 39U) | (x >> 25U));
    case 41U: return (sha3_lane_t)((x << 41U) | (x >> 23U));
    case 43U: return (sha3_lane_t)((x << 43U) | (x >> 21U));
    case 44U: return (sha3_lane_t)((x << 44U) | (x >> 20U));
    case 45U: return (sha3_lane_t)((x << 45U) | (x >> 19U));
    case 55U: return (sha3_lane_t)((x << 55U) | (x >> 9U));
    case 56U: return (sha3_lane_t)((x << 56U) | (x >> 8U));
    case 61U: return (sha3_lane_t)((x << 61U) | (x >> 3U));
    case 62U: return (sha3_lane_t)((x << 62U) | (x >> 2U));
    default:
        return x;
    }
}

/**
 * @brief Theta step of Keccak-f permutation
 *
 * @param lanes Keccak state as 25 lanes
 */
static void keccak_theta(sha3_lane_t lanes[SHA3_LANE_COUNT])
{
    sha3_lane_t C[SHA3_MAX_X_SIZE];
    sha3_lane_t D[SHA3_MAX_X_SIZE];
    uint32_t x = 0U;
    uint32_t y = 0U;
    
    /* Compute parity of columns */
    for (x = 0U; x < SHA3_MAX_X_SIZE; x += 1U) {
        C[x] = SHA3_LANE(lanes, x, 0U) ^ SHA3_LANE(lanes, x, 1U) ^ SHA3_LANE(lanes, x, 2U) ^ 
               SHA3_LANE(lanes, x, 3U) ^ SHA3_LANE(lanes, x, 4U);
    }
    
    /* Compute D values */
    for (x = 0U; x < SHA3_MAX_X_SIZE; x += 1U) {
        D[x] = C[(x +4U) % SHA3_MAX_X_SIZE] ^ sha3_rotl64(C[(x +1U) % SHA3_MAX_X_SIZE], 1U);
    }
    
    /* XOR D into each lane */
    for (x = 0U; x < SHA3_MAX_X_SIZE; x += 1U) {
        for (y = 0U; y < SHA3_MAX_Y_SIZE; y += 1U) {
            SHA3_LANE(lanes, x, y) ^= D[x];
        }
    }
}

/**
 * @brief Rho step of Keccak-f permutation
 *
 * @param lanes Keccak state as 25 lanes
 */
static void keccak_rho(sha3_lane_t lanes[SHA3_LANE_COUNT])
{
    /* Tables local to this function (Rule 8.9). */
    /* Rotation offsets for rho step (5x5 grid, indexed by [y][x]) */
    static const uint8_t rho_offsets[SHA3_MAX_Y_SIZE][SHA3_MAX_X_SIZE] = {
        { 0,  1, 62, 28, 27},
        {36, 44,  6, 55, 20},
        { 3, 10, 43, 25, 39},
        {41, 45, 15, 21,  8},
        {18,  2, 61, 56, 14}
    };


    sha3_lane_t temp[SHA3_MAX_X_SIZE][SHA3_MAX_Y_SIZE];
    uint32_t x = 0U;
    uint32_t y = 0U;
    
    /* Copy state */
    for (x = 0U; x < SHA3_MAX_X_SIZE; x += 1U) {
        for (y = 0U; y < SHA3_MAX_Y_SIZE; y += 1U) {
            temp[x][y] = SHA3_LANE(lanes, x, y);
        }
    }
    
    /* Apply rotations using correct offsets */
    for (x = 0U; x < SHA3_MAX_X_SIZE; x += 1U) {
        for (y = 0U; y < SHA3_MAX_Y_SIZE; y += 1U) {
            SHA3_LANE(lanes, x, y) = sha3_rotl64(temp[x][y], rho_offsets[y][x]);
        }
    }
}

/**
 * @brief Pi step of Keccak-f permutation
 *
 * @param lanes Keccak state as 25 lanes
 */
static void keccak_pi(sha3_lane_t lanes[SHA3_LANE_COUNT])
{
    sha3_lane_t temp[SHA3_MAX_X_SIZE][SHA3_MAX_Y_SIZE];
    uint32_t x = 0U;
    uint32_t y = 0U;
    
    /* Copy state */
    for (x = 0U; x < SHA3_MAX_X_SIZE; x += 1U) {
        for (y = 0U; y < SHA3_MAX_Y_SIZE; y += 1U) {
            temp[x][y] = SHA3_LANE(lanes, x, y);
        }
    }
    
    /* Permute lanes */
    for (x = 0U; x < SHA3_MAX_X_SIZE; x += 1U) {
        for (y = 0U; y < SHA3_MAX_Y_SIZE; y += 1U) {
            SHA3_LANE(lanes, x, y) = temp[(x + (3U * y)) % SHA3_MAX_X_SIZE][x];
        }
    }
}

/**
 * @brief Chi step of Keccak-f permutation
 *
 * @param lanes Keccak state as 25 lanes
 */
static void keccak_chi(sha3_lane_t lanes[SHA3_LANE_COUNT])
{
    sha3_lane_t temp[SHA3_MAX_X_SIZE][SHA3_MAX_Y_SIZE];
    uint32_t x = 0U;
    uint32_t y = 0U;
    
    /* Copy state */
    for (x = 0U; x < SHA3_MAX_X_SIZE; x += 1U) {
        for (y = 0U; y < SHA3_MAX_Y_SIZE; y += 1U) {
            temp[x][y] = SHA3_LANE(lanes, x, y);
        }
    }
    
    /* Apply chi transformation */
    for (x = 0U; x < SHA3_MAX_X_SIZE; x += 1U) {
        for (y = 0U; y < SHA3_MAX_Y_SIZE; y += 1U) {
            SHA3_LANE(lanes, x, y) = temp[x][y] ^ ((~temp[(x +1U) % SHA3_MAX_X_SIZE][y]) & temp[(x +2U) % SHA3_MAX_X_SIZE][y]);
        }
    }
}

/**
 * @brief Iota step of Keccak-f permutation
 *
 * @param lanes Keccak state as 25 lanes
 * @param round Round number
 */
static void keccak_iota(sha3_lane_t lanes[SHA3_LANE_COUNT], uint32_t round)
{
    /* Tables local to this function (Rule 8.9). */
    /* Round constants for iota step */
    static const sha3_lane_t round_constants[SHA3_KECCAK_ROUNDS] = {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
        0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
        0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
        0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
        0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
    };


    SHA3_LANE(lanes, 0U, 0U) ^= round_constants[round];
}

/**
 * @brief Keccak-f[1600] permutation (24 rounds)
 *
 * @param ctx SHA-3 context
 */
static void keccak_f1600(noxtls_sha3_ctx_t * ctx)
{
    sha3_lane_t lanes[SHA3_LANE_COUNT];
    uint32_t round = 0U;
    uint32_t i = 0U;

    /* Byte state -> lanes (little-endian, alignment-independent). */
    for (i = 0U; i < SHA3_LANE_COUNT; i += 1U) {
        lanes[i] = sha3_load_le64(&ctx->state[i * SHA3_LANE_BYTES]);
    }

    for (round = 0U; round < SHA3_KECCAK_ROUNDS; round += 1U) {
        keccak_theta(lanes);
        keccak_rho(lanes);
        keccak_pi(lanes);
        keccak_chi(lanes);
        keccak_iota(lanes, round);
    }

    for (i = 0U; i < SHA3_LANE_COUNT; i += 1U) {
        sha3_store_le64(&ctx->state[i * SHA3_LANE_BYTES], lanes[i]);
    }
    noxtls_secure_zero(lanes, sizeof(lanes));
}

/**
 * @brief Absorb data into the sponge
 *
 * @param ctx SHA-3 context
 * @param data Data to absorb
 * @param len Length of data to absorb
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
static noxtls_return_t sha3_absorb(noxtls_sha3_ctx_t * ctx, const uint8_t * data, uint32_t len)
{
    uint32_t i = 0U;
    uint32_t offset = 0U;
    uint32_t remaining = len;

    if ((data == NULL) && (remaining != 0U)) {
        return NOXTLS_RETURN_NULL;
    }

    while (remaining > 0U) {
        uint32_t to_copy = (uint32_t)((remaining < (ctx->rate - ctx->buffer_len)) ? remaining : (ctx->rate - ctx->buffer_len));
        
        /* XOR data into state (first rate bytes) */
        for (i = 0U; i < to_copy; i += 1U) {
            ctx->state[ctx->buffer_len + i] ^= data[offset + i];
        }
        
        ctx->buffer_len += to_copy;
        offset += to_copy;
        remaining -= to_copy;
        
        /* If we've filled a rate block, apply permutation */
        if (ctx->buffer_len == ctx->rate) {
            keccak_f1600(ctx);
            ctx->buffer_len = 0U;
        }
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Initialize SHA3-224
 *
 * @param ctx SHA-3 context
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
noxtls_return_t noxtls_sha3_224_init(noxtls_sha3_ctx_t * ctx)
{
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    noxtls_secure_zero((ctx->state), (size_t)(SHA3_STATE_SIZE));
    noxtls_secure_zero((ctx->buffer), sizeof(ctx->buffer));
    ctx->algo = NOXTLS_HASH_SHA3_224;
    ctx->rate = SHA3_RATE_224_BYTES;        /* 1152 bits / 8 = 144 bytes */
    ctx->capacity = SHA3_CAPACITY_224_BYTES;     /* 448 bits / 8 = 56 bytes */
    ctx->output_len = HASH_SHA3_224_OUT_LEN;
    ctx->domain_sep = SHA3_DOMAIN_SEP; /* SHA-3 domain separation suffix */
    ctx->buffer_len = 0U;
    ctx->total_length = 0U;
    ctx->finalized = 0U;
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Initialize SHA3-256
 *
 * @param ctx SHA-3 context
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
noxtls_return_t noxtls_sha3_256_init(noxtls_sha3_ctx_t * ctx)
{
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    noxtls_secure_zero((ctx->state), (size_t)(SHA3_STATE_SIZE));
    noxtls_secure_zero((ctx->buffer), sizeof(ctx->buffer));
    ctx->algo = NOXTLS_HASH_SHA3_256;
    ctx->rate = SHA3_RATE_256_BYTES;        /* 1088 bits / 8 = 136 bytes */
    ctx->capacity = SHA3_CAPACITY_256_BYTES;     /* 512 bits / 8 = 64 bytes */
    ctx->output_len = HASH_SHA3_256_OUT_LEN;
    ctx->domain_sep = SHA3_DOMAIN_SEP;
    ctx->buffer_len = 0U;
    ctx->total_length = 0U;
    ctx->finalized = 0U;
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Initialize SHA3-384
 *
 * @param ctx SHA-3 context
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
noxtls_return_t noxtls_sha3_384_init(noxtls_sha3_ctx_t * ctx)
{
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    noxtls_secure_zero((ctx->state), (size_t)(SHA3_STATE_SIZE));
    noxtls_secure_zero((ctx->buffer), sizeof(ctx->buffer));
    ctx->algo = NOXTLS_HASH_SHA3_384;
    ctx->rate = SHA3_RATE_384_BYTES;        /* 832 bits / 8 = 104 bytes */
    ctx->capacity = SHA3_CAPACITY_384_BYTES;     /* 768 bits / 8 = 96 bytes */
    ctx->output_len = HASH_SHA3_384_OUT_LEN;
    ctx->domain_sep = SHA3_DOMAIN_SEP;
    ctx->buffer_len = 0U;
    ctx->total_length = 0U;
    ctx->finalized = 0U;
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Initialize SHA3-512
 * @param ctx SHA-3 context
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
noxtls_return_t noxtls_sha3_512_init(noxtls_sha3_ctx_t * ctx)
{
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    noxtls_secure_zero((ctx->state), (size_t)(SHA3_STATE_SIZE));
    noxtls_secure_zero((ctx->buffer), sizeof(ctx->buffer));
    ctx->algo = NOXTLS_HASH_SHA3_512;
    ctx->rate = SHA3_RATE_512_BYTES;         /* 576 bits / 8 = 72 bytes */
    ctx->capacity = SHA3_CAPACITY_512_BYTES;    /* 1024 bits / 8 = 128 bytes */
    ctx->output_len = HASH_SHA3_512_OUT_LEN;
    ctx->domain_sep = SHA3_DOMAIN_SEP;
    ctx->buffer_len = 0U;
    ctx->total_length = 0U;
    ctx->finalized = 0U;
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Update SHA-3 with new data

 * @param ctx SHA-3 context
 * @param data Data to update SHA-3 with
 * @param len Length of data to update SHA-3 with
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL, NOXTLS_RETURN_FAILED if SHA-3 is finalized
 */
noxtls_return_t noxtls_sha3_update(noxtls_sha3_ctx_t * ctx, const uint8_t * data, uint32_t len)
{
    uint32_t in_left = len;
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if (ctx->finalized != 0U) {
        return NOXTLS_RETURN_FAILED; /* Cannot update after finalization */
    }
    
    ctx->total_length += in_left;
    
    return sha3_absorb(ctx, data, in_left);
}

/**
 * @brief Finalize SHA-3 and produce hash
 *  
 * @param ctx SHA-3 context
 * @param hash Hash to produce
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL, NOXTLS_RETURN_FAILED if SHA-3 is finalized
 */
noxtls_return_t noxtls_sha3_finish(noxtls_sha3_ctx_t * ctx, uint8_t * hash)
{
    uint32_t i = 0U;
    
    if ((ctx == NULL) || (hash == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    if (ctx->finalized != 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Apply padding: pad10*1 with domain separation suffix */
    /* SHA-3 padding specification:
     * 1. XOR domain separation suffix (0x06u = bits 01) at current position
     * 2. Pad with zeros (already zero from initialization)
     * 3. Set final bit to 1 (0x80u in last byte of rate block) */
    
    /* XOR domain separation suffix into the current position */
    /* 0x06u = 00000110 in binary = bits 01 (domain sep) + 1 (start of pad10*1) */
    ctx->state[ctx->buffer_len] ^= ctx->domain_sep;
    
    /* Set the last byte of the rate block to 0x80u (pad10*1: final 1 bit) */
    ctx->state[ctx->rate - 1U] ^= SHA3_PAD_FINAL_BYTE;
    
    /* Process the padded block */
    keccak_f1600(ctx);
    
    /* Squeeze: extract output */
    for (i = 0U; i < ctx->output_len; i += 1U) {
        hash[i] = ctx->state[i];
    }
    
    ctx->finalized = 1U;
    
    return NOXTLS_RETURN_SUCCESS;
}

/* SHAKE256 (FIPS 202): extendable-output function. Domain sep 0x1fu, rate 136 bytes. */
/**
 * @brief Initialize SHAKE128
 * 
 * @param ctx The SHAKE128 context
 * @return The return value
 */
noxtls_return_t noxtls_shake128_init(noxtls_sha3_ctx_t * ctx)
{
    if (ctx == NULL) { return NOXTLS_RETURN_NULL; }
    noxtls_secure_zero((ctx->state), (size_t)(SHA3_STATE_SIZE));
    noxtls_secure_zero((ctx->buffer), sizeof(ctx->buffer));
    ctx->rate = SHA3_SHAKE128_RATE_BYTES;
    ctx->capacity = SHA3_SHAKE128_CAPACITY_BYTES;
    ctx->domain_sep = SHA3_SHAKE128_DOMAIN_SEP;
    ctx->output_len = 0U;
    ctx->buffer_len = 0U;
    ctx->total_length = 0U;
    ctx->finalized = 0U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Update SHAKE128
 * 
 * @param ctx The SHAKE128 context
 * @param data The input data
 * @param len The length of the input data
 * @return The return value
 */
noxtls_return_t noxtls_shake128_update(noxtls_sha3_ctx_t * ctx, const uint8_t * data, uint32_t len)
{
    if (ctx == NULL) { return NOXTLS_RETURN_NULL; }
    if (ctx->finalized != 0U) { return NOXTLS_RETURN_FAILED; }
    ctx->total_length += len;
    return sha3_absorb(ctx, data, len);
}

/**
 * @brief Finalize SHAKE128
 * 
 * @param ctx The SHAKE128 context
 * @return The return value
 */
noxtls_return_t noxtls_shake128_final(noxtls_sha3_ctx_t * ctx)
{
    if (ctx == NULL) { return NOXTLS_RETURN_NULL; }
    if (ctx->finalized != 0U) { return NOXTLS_RETURN_SUCCESS; }
    ctx->state[ctx->buffer_len] ^= ctx->domain_sep;
    ctx->state[ctx->rate - 1U] ^= SHA3_PAD_FINAL_BYTE;
    keccak_f1600(ctx);
    ctx->buffer_len = 0U;
    ctx->finalized = 1U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Squeeze SHAKE128
 * 
 * @param ctx The SHAKE128 context
 * @param out The output data
 * @param out_len The length of the output data
 * @return The return value
 */
noxtls_return_t noxtls_shake128_squeeze(noxtls_sha3_ctx_t * ctx, uint8_t * out, uint32_t out_len)
{
    uint32_t copied = 0U;
    if ((ctx == NULL) || ((out == NULL) && (out_len != 0U))) { return NOXTLS_RETURN_NULL; }
    if (ctx->finalized == 0U) { return NOXTLS_RETURN_FAILED; }
    while (copied < out_len) {
        uint32_t from_state = (uint32_t)(ctx->rate - ctx->buffer_len);
        uint32_t remain = out_len - copied;
        uint32_t to_copy = (remain < from_state) ? remain : from_state;
        if (to_copy > 0U) {
            noxtls_copy_u8(&out[copied], (size_t)to_copy, &ctx->state[ctx->buffer_len], (size_t)to_copy);
            copied += to_copy;
            ctx->buffer_len += to_copy;
        }
        if (ctx->buffer_len >= ctx->rate) {
            keccak_f1600(ctx);
            ctx->buffer_len = 0U;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Initialize SHAKE256
 * 
 * @param ctx The SHAKE256 context
 * @return The return value
 */
noxtls_return_t noxtls_shake256_init(noxtls_sha3_ctx_t * ctx)
{
    if (ctx == NULL) { return NOXTLS_RETURN_NULL; }
    noxtls_secure_zero((ctx->state), (size_t)(SHA3_STATE_SIZE));
    noxtls_secure_zero((ctx->buffer), sizeof(ctx->buffer));
    ctx->rate = SHA3_SHAKE256_RATE_BYTES;
    ctx->capacity = SHA3_SHAKE256_CAPACITY_BYTES;
    ctx->domain_sep = SHA3_SHAKE256_DOMAIN_SEP;
    ctx->output_len = 0U;
    ctx->buffer_len = 0U;
    ctx->total_length = 0U;
    ctx->finalized = 0U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Update SHAKE256
 * 
 * @param ctx The SHAKE256 context
 * @param data The input data
 * @param len The length of the input data
 * @return The return value
 */
noxtls_return_t noxtls_shake256_update(noxtls_sha3_ctx_t * ctx, const uint8_t * data, uint32_t len)
{
    if (ctx == NULL) { return NOXTLS_RETURN_NULL; }
    if (ctx->finalized != 0U) { return NOXTLS_RETURN_FAILED; }
    ctx->total_length += len;
    return sha3_absorb(ctx, data, len);
}

/**
 * @brief Finalize SHAKE256
 * 
 * @param ctx The SHAKE256 context
 * @return The return value
 */
noxtls_return_t noxtls_shake256_final(noxtls_sha3_ctx_t * ctx)
{
    if (ctx == NULL) { return NOXTLS_RETURN_NULL; }
    if (ctx->finalized != 0U) { return NOXTLS_RETURN_SUCCESS; }
    ctx->state[ctx->buffer_len] ^= ctx->domain_sep;
    ctx->state[ctx->rate - 1U] ^= SHA3_PAD_FINAL_BYTE;
    keccak_f1600(ctx);
    ctx->buffer_len = 0U;
    ctx->finalized = 1U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Squeeze SHAKE256
 * 
 * @param ctx The SHAKE256 context
 * @param out The output data
 * @param out_len The length of the output data
 * @return The return value
 */
noxtls_return_t noxtls_shake256_squeeze(noxtls_sha3_ctx_t * ctx, uint8_t * out, uint32_t out_len)
{
    uint32_t copied = 0U;
    if ((ctx == NULL) || ((out == NULL) && (out_len != 0U))) { return NOXTLS_RETURN_NULL; }
    if (ctx->finalized == 0U) { return NOXTLS_RETURN_FAILED; }
    while (copied < out_len) {
        uint32_t from_state = (uint32_t)(ctx->rate - ctx->buffer_len);
        uint32_t remain = out_len - copied;
        uint32_t to_copy = (remain < from_state) ? remain : from_state;
        if (to_copy > 0U) {
            noxtls_copy_u8(&out[copied], (size_t)to_copy, &ctx->state[ctx->buffer_len], (size_t)to_copy);
            copied += to_copy;
            ctx->buffer_len += to_copy;
        }
        if (ctx->buffer_len >= ctx->rate) {
            keccak_f1600(ctx);
            ctx->buffer_len = 0U;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Verify data against expected SHA-3 hash
 * 
 * @param data Data to verify
 * @param len Length of data to verify
 * @param expected Expected hash
 * @param algo Algorithm to use
 *
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_FAILED if verification fails
 */
noxtls_return_t noxtls_sha3_verify(const uint8_t * data, uint32_t len, const uint8_t * expected, noxtls_hash_algos_t algo)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    noxtls_sha3_ctx_t ctx;
    uint8_t hash[64] = {0};  /* Max output size */
    uint32_t hash_len = 0U;
    
    /* Determine hash length based on algorithm */
    switch (algo) {
        case NOXTLS_HASH_SHA3_224:
            hash_len = HASH_SHA3_224_OUT_LEN;
            (void)noxtls_sha3_224_init(&ctx);
            break;
        case NOXTLS_HASH_SHA3_256:
            hash_len = HASH_SHA3_256_OUT_LEN;
            (void)noxtls_sha3_256_init(&ctx);
            break;
        case NOXTLS_HASH_SHA3_384:
            hash_len = HASH_SHA3_384_OUT_LEN;
            (void)noxtls_sha3_384_init(&ctx);
            break;
        case NOXTLS_HASH_SHA3_512:
            hash_len = HASH_SHA3_512_OUT_LEN;
            (void)noxtls_sha3_512_init(&ctx);
            break;
        case NOXTLS_HASH_MD4:
        case NOXTLS_HASH_MD5:
        case NOXTLS_HASH_SHA1:
        case NOXTLS_HASH_SHA_224:
        case NOXTLS_HASH_SHA_256:
        case NOXTLS_HASH_SHA_384:
        case NOXTLS_HASH_SHA_512:
        case NOXTLS_HASH_SHA_512_224:
        case NOXTLS_HASH_SHA_512_256:
            return NOXTLS_RETURN_NOT_SUPPORTED;
        default:
            return NOXTLS_RETURN_FAILED;
    }
    
    noxtls_return_t hrc = noxtls_sha3_update(&ctx, data, len);
    if (hrc == NOXTLS_RETURN_SUCCESS) {
        hrc = noxtls_sha3_finish(&ctx, hash);
    }
    
    if (sha3_debug_lvl > 0U) {
        (void)noxtls_debug_printf((const uint8_t *)"Compare: \n");
        (void)noxtls_print_hash(hash, (uint16_t)hash_len);
        (void)noxtls_print_hash(expected, (uint16_t)hash_len);
    }
    
    /* Fail closed: a hashing error is never reported as a match. */
    if ((hrc == NOXTLS_RETURN_SUCCESS) && (noxtls_ct_equal(hash, expected, (size_t)hash_len) != 0)) {
        rc = NOXTLS_RETURN_SUCCESS;
    }
    
    return rc;
}

/**
 * @brief Sets Module Debug level
 *
 * @param lvl Debug level
 */
 void noxtls_sha3_set_debug(uint8_t lvl)
 {
     sha3_debug_lvl = lvl;
 }

#endif /* NOXTLS_FEATURE_SHA3 */
