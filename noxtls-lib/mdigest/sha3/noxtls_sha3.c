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
* File:    noxtls_sha3.c
* Summary: SHA-3 (Keccak) Hash Implementation
* Based on FIPS 202
*
*/

/** @addtogroup noxtls_mdigest */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "noxtls_common.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_hash.h"
#include "noxtls_sha3.h"

#if NOXTLS_FEATURE_SHA3

/* Module Debug Level */
static uint8_t debug_lvl = 0;

/* SHA-3 uses 64-bit lanes for Keccak-f[1600] */
typedef uint64_t sha3_lane_t;

/* Helper macro to access state as 5x5 array of 64-bit lanes */
#define SHA3_LANE(x, y) (((sha3_lane_t*)ctx->state)[SHA3_MAX_X_SIZE * (y) + (x)])

/* Rotation offsets for rho step (5x5 grid, indexed by [y][x]) */
static const uint8_t rho_offsets[SHA3_MAX_Y_SIZE][SHA3_MAX_X_SIZE] = {
    { 0,  1, 62, 28, 27},
    {36, 44,  6, 55, 20},
    { 3, 10, 43, 25, 39},
    {41, 45, 15, 21,  8},
    {18,  2, 61, 56, 14}
};

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



/**
 * @brief Rotate left for 64-bit values
 *
 * @param x Value to rotate
 * @param n Number of bits to rotate
 * @return sha3_lane_t Rotated value
 */
static inline sha3_lane_t sha3_rotl64(sha3_lane_t x, uint8_t n)
{
    return (x << n) | (x >> (SHA3_LANE_BITS - n));
}

/**
 * @brief Theta step of Keccak-f permutation
 *
 * @param ctx SHA-3 context
 */
static void keccak_theta(noxtls_sha3_ctx_t * ctx)
{
    sha3_lane_t C[SHA3_MAX_X_SIZE];
    sha3_lane_t D[SHA3_MAX_X_SIZE];
    int x;
    int y;
    
    /* Compute parity of columns */
    for(x = 0; x < SHA3_MAX_X_SIZE; x++) {
        C[x] = SHA3_LANE(x, 0) ^ SHA3_LANE(x, 1) ^ SHA3_LANE(x, 2) ^ 
               SHA3_LANE(x, 3) ^ SHA3_LANE(x, 4);
    }
    
    /* Compute D values */
    for(x = 0; x < SHA3_MAX_X_SIZE; x++) {
        D[x] = C[(x + 4) % SHA3_MAX_X_SIZE] ^ sha3_rotl64(C[(x + 1) % SHA3_MAX_X_SIZE], 1);
    }
    
    /* XOR D into each lane */
    for(x = 0; x < SHA3_MAX_X_SIZE; x++) {
        for(y = 0; y < SHA3_MAX_Y_SIZE; y++) {
            SHA3_LANE(x, y) ^= D[x];
        }
    }
}

/**
 * @brief Rho step of Keccak-f permutation
 *
 * @param ctx SHA-3 context
 */
static void keccak_rho(noxtls_sha3_ctx_t * ctx)
{
    sha3_lane_t temp[SHA3_MAX_X_SIZE][SHA3_MAX_Y_SIZE];
    int x;
    int y;
    
    /* Copy state */
    for(x = 0; x < SHA3_MAX_X_SIZE; x++) {
        for(y = 0; y < SHA3_MAX_Y_SIZE; y++) {
            temp[x][y] = SHA3_LANE(x, y);
        }
    }
    
    /* Apply rotations using correct offsets */
    for(x = 0; x < SHA3_MAX_X_SIZE; x++) {
        for(y = 0; y < SHA3_MAX_Y_SIZE; y++) {
            SHA3_LANE(x, y) = sha3_rotl64(temp[x][y], rho_offsets[y][x]);
        }
    }
}

/**
 * @brief Pi step of Keccak-f permutation   
 *
 * @param ctx SHA-3 context
 */
static void keccak_pi(noxtls_sha3_ctx_t * ctx)
{
    sha3_lane_t temp[SHA3_MAX_X_SIZE][SHA3_MAX_Y_SIZE];
    int x;
    int y;
    
    /* Copy state */
    for(x = 0; x < SHA3_MAX_X_SIZE; x++) {
        for(y = 0; y < SHA3_MAX_Y_SIZE; y++) {
            temp[x][y] = SHA3_LANE(x, y);
        }
    }
    
    /* Permute lanes */
    for(x = 0; x < SHA3_MAX_X_SIZE; x++) {
        for(y = 0; y < SHA3_MAX_Y_SIZE; y++) {
            SHA3_LANE(x, y) = temp[(x + 3 * y) % SHA3_MAX_X_SIZE][x];
        }
    }
}

/**
 * @brief Chi step of Keccak-f permutation
 *
 * @param ctx SHA-3 context
 */
static void keccak_chi(noxtls_sha3_ctx_t * ctx)
{
    sha3_lane_t temp[SHA3_MAX_X_SIZE][SHA3_MAX_Y_SIZE];
    int x;
    int y;
    
    /* Copy state */
    for(x = 0; x < SHA3_MAX_X_SIZE; x++) {
        for(y = 0; y < SHA3_MAX_Y_SIZE; y++) {
            temp[x][y] = SHA3_LANE(x, y);
        }
    }
    
    /* Apply chi transformation */
    for(x = 0; x < SHA3_MAX_X_SIZE; x++) {
        for(y = 0; y < SHA3_MAX_Y_SIZE; y++) {
            SHA3_LANE(x, y) = temp[x][y] ^ ((~temp[(x + 1) % SHA3_MAX_X_SIZE][y]) & temp[(x + 2) % SHA3_MAX_X_SIZE][y]);
        }
    }
}

/**
 * @brief Iota step of Keccak-f permutation
 *
 * @param ctx SHA-3 context
 * @param round Round number
 */
static void keccak_iota(noxtls_sha3_ctx_t * ctx, int round)
{
    SHA3_LANE(0, 0) ^= round_constants[round];
}

/**
 * @brief Keccak-f[1600] permutation (24 rounds)
 *
 * @param ctx SHA-3 context
 */
static void keccak_f1600(noxtls_sha3_ctx_t * ctx)
{
    int round;

    for(round = 0; round < SHA3_KECCAK_ROUNDS; round++) {
        keccak_theta(ctx);
        keccak_rho(ctx);
        keccak_pi(ctx);
        keccak_chi(ctx);
        keccak_iota(ctx, round);
    }
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
    uint32_t i;
    uint32_t offset = 0;
    
    while(len > 0) {
        uint32_t to_copy = (len < (ctx->rate - ctx->buffer_len)) ? len : (ctx->rate - ctx->buffer_len);
        
        /* XOR data into state (first rate bytes) */
        for(i = 0; i < to_copy; i++) {
            ctx->state[ctx->buffer_len + i] ^= data[offset + i];
        }
        
        ctx->buffer_len += to_copy;
        offset += to_copy;
        len -= to_copy;
        
        /* If we've filled a rate block, apply permutation */
        if(ctx->buffer_len == ctx->rate) {
            keccak_f1600(ctx);
            ctx->buffer_len = 0;
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
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    memset(ctx->state, 0, SHA3_STATE_SIZE);
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
    ctx->algo = NOXTLS_HASH_SHA3_224;
    ctx->rate = SHA3_RATE_224_BYTES;        /* 1152 bits / 8 = 144 bytes */
    ctx->capacity = SHA3_CAPACITY_224_BYTES;     /* 448 bits / 8 = 56 bytes */
    ctx->output_len = HASH_SHA3_224_OUT_LEN;
    ctx->domain_sep = SHA3_DOMAIN_SEP; /* SHA-3 domain separation suffix */
    ctx->buffer_len = 0;
    ctx->total_length = 0;
    ctx->finalized = 0;
    
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
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    memset(ctx->state, 0, SHA3_STATE_SIZE);
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
    ctx->algo = NOXTLS_HASH_SHA3_256;
    ctx->rate = SHA3_RATE_256_BYTES;        /* 1088 bits / 8 = 136 bytes */
    ctx->capacity = SHA3_CAPACITY_256_BYTES;     /* 512 bits / 8 = 64 bytes */
    ctx->output_len = HASH_SHA3_256_OUT_LEN;
    ctx->domain_sep = SHA3_DOMAIN_SEP;
    ctx->buffer_len = 0;
    ctx->total_length = 0;
    ctx->finalized = 0;
    
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
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    memset(ctx->state, 0, SHA3_STATE_SIZE);
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
    ctx->algo = NOXTLS_HASH_SHA3_384;
    ctx->rate = SHA3_RATE_384_BYTES;        /* 832 bits / 8 = 104 bytes */
    ctx->capacity = SHA3_CAPACITY_384_BYTES;     /* 768 bits / 8 = 96 bytes */
    ctx->output_len = HASH_SHA3_384_OUT_LEN;
    ctx->domain_sep = SHA3_DOMAIN_SEP;
    ctx->buffer_len = 0;
    ctx->total_length = 0;
    ctx->finalized = 0;
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Initialize SHA3-512
 * @param ctx SHA-3 context
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
noxtls_return_t noxtls_sha3_512_init(noxtls_sha3_ctx_t * ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    memset(ctx->state, 0, SHA3_STATE_SIZE);
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
    ctx->algo = NOXTLS_HASH_SHA3_512;
    ctx->rate = SHA3_RATE_512_BYTES;         /* 576 bits / 8 = 72 bytes */
    ctx->capacity = SHA3_CAPACITY_512_BYTES;    /* 1024 bits / 8 = 128 bytes */
    ctx->output_len = HASH_SHA3_512_OUT_LEN;
    ctx->domain_sep = SHA3_DOMAIN_SEP;
    ctx->buffer_len = 0;
    ctx->total_length = 0;
    ctx->finalized = 0;
    
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
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->finalized) {
        return NOXTLS_RETURN_FAILED; /* Cannot update after finalization */
    }
    
    ctx->total_length += len;
    
    return sha3_absorb(ctx, data, len);
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
    uint32_t i;
    
    if(ctx == NULL || hash == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->finalized) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Apply padding: pad10*1 with domain separation suffix */
    /* SHA-3 padding specification:
     * 1. XOR domain separation suffix (0x06 = bits 01) at current position
     * 2. Pad with zeros (already zero from initialization)
     * 3. Set final bit to 1 (0x80 in last byte of rate block) */
    
    /* XOR domain separation suffix into the current position */
    /* 0x06 = 00000110 in binary = bits 01 (domain sep) + 1 (start of pad10*1) */
    ctx->state[ctx->buffer_len] ^= ctx->domain_sep;
    
    /* Set the last byte of the rate block to 0x80 (pad10*1: final 1 bit) */
    ctx->state[ctx->rate - 1] ^= SHA3_PAD_FINAL_BYTE;
    
    /* Process the padded block */
    keccak_f1600(ctx);
    
    /* Squeeze: extract output */
    for(i = 0; i < ctx->output_len; i++) {
        hash[i] = ctx->state[i];
    }
    
    ctx->finalized = 1;
    
    return NOXTLS_RETURN_SUCCESS;
}

/* SHAKE256 (FIPS 202): extendable-output function. Domain sep 0x1f, rate 136 bytes. */
noxtls_return_t noxtls_shake128_init(noxtls_sha3_ctx_t * ctx)
{
    if(ctx == NULL) return NOXTLS_RETURN_NULL;
    memset(ctx->state, 0, SHA3_STATE_SIZE);
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
    ctx->rate = SHA3_SHAKE128_RATE_BYTES;
    ctx->capacity = SHA3_SHAKE128_CAPACITY_BYTES;
    ctx->domain_sep = SHA3_SHAKE128_DOMAIN_SEP;
    ctx->output_len = 0;
    ctx->buffer_len = 0;
    ctx->total_length = 0;
    ctx->finalized = 0;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_shake128_update(noxtls_sha3_ctx_t * ctx, const uint8_t * data, uint32_t len)
{
    if(ctx == NULL) return NOXTLS_RETURN_NULL;
    if(ctx->finalized) return NOXTLS_RETURN_FAILED;
    ctx->total_length += len;
    return sha3_absorb(ctx, data, len);
}

noxtls_return_t noxtls_shake128_final(noxtls_sha3_ctx_t * ctx)
{
    if(ctx == NULL) return NOXTLS_RETURN_NULL;
    if(ctx->finalized) return NOXTLS_RETURN_SUCCESS;
    ctx->state[ctx->buffer_len] ^= ctx->domain_sep;
    ctx->state[ctx->rate - 1] ^= SHA3_PAD_FINAL_BYTE;
    keccak_f1600(ctx);
    ctx->buffer_len = 0;
    ctx->finalized = 1;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_shake128_squeeze(noxtls_sha3_ctx_t * ctx, uint8_t * out, uint32_t out_len)
{
    uint32_t copied = 0;
    if(ctx == NULL || (out == NULL && out_len != 0)) return NOXTLS_RETURN_NULL;
    if(!ctx->finalized) return NOXTLS_RETURN_FAILED;
    while(copied < out_len) {
        uint32_t from_state = ctx->rate - ctx->buffer_len;
        uint32_t to_copy = (out_len - copied) < from_state ? (out_len - copied) : from_state;
        if(to_copy > 0) {
            memcpy(out + copied, ctx->state + ctx->buffer_len, to_copy);
            copied += to_copy;
            ctx->buffer_len += to_copy;
        }
        if(ctx->buffer_len >= ctx->rate) {
            keccak_f1600(ctx);
            ctx->buffer_len = 0;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_shake256_init(noxtls_sha3_ctx_t * ctx)
{
    if(ctx == NULL) return NOXTLS_RETURN_NULL;
    memset(ctx->state, 0, SHA3_STATE_SIZE);
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
    ctx->rate = SHA3_SHAKE256_RATE_BYTES;
    ctx->capacity = SHA3_SHAKE256_CAPACITY_BYTES;
    ctx->domain_sep = SHA3_SHAKE256_DOMAIN_SEP;
    ctx->output_len = 0;
    ctx->buffer_len = 0;
    ctx->total_length = 0;
    ctx->finalized = 0;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_shake256_update(noxtls_sha3_ctx_t * ctx, const uint8_t * data, uint32_t len)
{
    if(ctx == NULL) return NOXTLS_RETURN_NULL;
    if(ctx->finalized) return NOXTLS_RETURN_FAILED;
    ctx->total_length += len;
    return sha3_absorb(ctx, data, len);
}

noxtls_return_t noxtls_shake256_final(noxtls_sha3_ctx_t * ctx)
{
    if(ctx == NULL) return NOXTLS_RETURN_NULL;
    if(ctx->finalized) return NOXTLS_RETURN_SUCCESS;
    ctx->state[ctx->buffer_len] ^= ctx->domain_sep;
    ctx->state[ctx->rate - 1] ^= SHA3_PAD_FINAL_BYTE;
    keccak_f1600(ctx);
    ctx->buffer_len = 0;
    ctx->finalized = 1;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_shake256_squeeze(noxtls_sha3_ctx_t * ctx, uint8_t * out, uint32_t out_len)
{
    uint32_t copied = 0;
    if(ctx == NULL || (out == NULL && out_len != 0)) return NOXTLS_RETURN_NULL;
    if(!ctx->finalized) return NOXTLS_RETURN_FAILED;
    while(copied < out_len) {
        uint32_t from_state = ctx->rate - ctx->buffer_len;
        uint32_t to_copy = (out_len - copied) < from_state ? (out_len - copied) : from_state;
        if(to_copy > 0) {
            memcpy(out + copied, ctx->state + ctx->buffer_len, to_copy);
            copied += to_copy;
            ctx->buffer_len += to_copy;
        }
        if(ctx->buffer_len >= ctx->rate) {
            keccak_f1600(ctx);
            ctx->buffer_len = 0;
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
    uint32_t hash_len = 0;
    
    /* Determine hash length based on algorithm */
    switch(algo) {
        case NOXTLS_HASH_SHA3_224:
            hash_len = HASH_SHA3_224_OUT_LEN;
            noxtls_sha3_224_init(&ctx);
            break;
        case NOXTLS_HASH_SHA3_256:
            hash_len = HASH_SHA3_256_OUT_LEN;
            noxtls_sha3_256_init(&ctx);
            break;
        case NOXTLS_HASH_SHA3_384:
            hash_len = HASH_SHA3_384_OUT_LEN;
            noxtls_sha3_384_init(&ctx);
            break;
        case NOXTLS_HASH_SHA3_512:
            hash_len = HASH_SHA3_512_OUT_LEN;
            noxtls_sha3_512_init(&ctx);
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
    
    noxtls_sha3_update(&ctx, data, len);
    noxtls_sha3_finish(&ctx, hash);
    
    if(debug_lvl > 0) {
        noxtls_debug_printf("Compare: \n");
        noxtls_print_hash(hash, (uint16_t)hash_len);
        noxtls_print_hash(expected, (uint16_t)hash_len);
    }
    
    if(memcmp(hash, expected, hash_len) == 0) {
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
     debug_lvl = lvl;
 }

#endif /* NOXTLS_FEATURE_SHA3 */
