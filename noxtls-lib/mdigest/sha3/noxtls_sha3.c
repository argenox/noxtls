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

/* Lane count, kept for the local permutation helpers. */
#define SHA3_LANE_COUNT (SHA3_MAX_X_SIZE * SHA3_MAX_Y_SIZE)

/* Rotate a lane left by a public constant 1..63. */
#define SHA3_ROTL64(x, n) ((sha3_lane_t)(((x) << (n)) | ((x) >> (64U - (n)))))

/*
 * The context keeps the state as 25 native 64-bit lanes: lane x + 5y holds
 * the FIPS 202 state bytes 8(x + 5y) .. 8(x + 5y) + 7 in little-endian
 * order. Bytes are XORed in and read out with shifts, so the code is
 * independent of host endianness and of the context's alignment beyond the
 * natural uint64_t alignment that the compiler guarantees.
 */

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
 * @brief XOR one byte into the state at byte offset @p pos.
 */
static void sha3_xor_byte(sha3_lane_t *state, uint32_t pos, uint8_t b)
{
    state[pos >> 3U] ^= ((sha3_lane_t)b << (8U * (pos & 7U)));
}

/**
 * @brief Read the state byte at byte offset @p pos.
 */
static uint8_t sha3_get_byte(const sha3_lane_t *state, uint32_t pos)
{
    return (uint8_t)((state[pos >> 3U] >> (8U * (pos & 7U))) & 0xFFU);
}

/**
 * @brief Keccak-f[1600] permutation (24 rounds), in place on the lanes.
 *
 * Compact formulation: theta with a 5-lane column parity, rho and pi fused
 * along the pi cycle (one carried lane), chi row by row. Only 6 lanes of
 * scratch are used instead of a full copy of the state per step.
 *
 * @param st Keccak state as 25 lanes (lane x + 5y)
 */
static void keccak_f1600(sha3_lane_t st[SHA3_LANE_COUNT])
{
    /* Tables local to this function (Rule 8.9). */
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
    /* rho rotation offsets along the pi cycle starting at lane 1. */
    static const uint8_t rho_rot[SHA3_KECCAK_ROUNDS] = {
        1U, 3U, 6U, 10U, 15U, 21U, 28U, 36U, 45U, 55U, 2U, 14U,
        27U, 41U, 56U, 8U, 25U, 43U, 62U, 18U, 39U, 61U, 20U, 44U
    };
    /* pi destination lanes along the same cycle. */
    static const uint8_t pi_lane[SHA3_KECCAK_ROUNDS] = {
        10U, 7U, 11U, 17U, 18U, 3U, 5U, 16U, 8U, 21U, 24U, 4U,
        15U, 23U, 19U, 13U, 12U, 2U, 20U, 14U, 22U, 9U, 6U, 1U
    };
    sha3_lane_t bc[SHA3_MAX_X_SIZE];
    sha3_lane_t t = 0U;
    uint32_t round = 0U;
    uint32_t i = 0U;
    uint32_t j = 0U;

    for (round = 0U; round < SHA3_KECCAK_ROUNDS; round += 1U) {
        /* theta */
        for (i = 0U; i < SHA3_MAX_X_SIZE; i += 1U) {
            bc[i] = st[i] ^ st[i + 5U] ^ st[i + 10U] ^ st[i + 15U] ^ st[i + 20U];
        }
        for (i = 0U; i < SHA3_MAX_X_SIZE; i += 1U) {
            t = bc[(i + 4U) % SHA3_MAX_X_SIZE] ^ SHA3_ROTL64(bc[(i + 1U) % SHA3_MAX_X_SIZE], 1U);
            for (j = 0U; j < SHA3_LANE_COUNT; j += SHA3_MAX_X_SIZE) {
                st[j + i] ^= t;
            }
        }

        /* rho and pi */
        t = st[1];
        for (i = 0U; i < SHA3_KECCAK_ROUNDS; i += 1U) {
            j = (uint32_t)pi_lane[i];
            bc[0] = st[j];
            st[j] = SHA3_ROTL64(t, (uint32_t)rho_rot[i]);
            t = bc[0];
        }

        /* chi */
        for (j = 0U; j < SHA3_LANE_COUNT; j += SHA3_MAX_X_SIZE) {
            for (i = 0U; i < SHA3_MAX_X_SIZE; i += 1U) {
                bc[i] = st[j + i];
            }
            for (i = 0U; i < SHA3_MAX_X_SIZE; i += 1U) {
                st[j + i] ^= (~bc[(i + 1U) % SHA3_MAX_X_SIZE]) & bc[(i + 2U) % SHA3_MAX_X_SIZE];
            }
        }

        /* iota */
        st[0] ^= round_constants[round];
    }

    noxtls_secure_zero(bc, sizeof(bc));
    noxtls_secure_zero(&t, sizeof(t));
}

/**
 * @brief Absorb data into the sponge
 *
 * @param ctx SHA-3 context
 * @param data Data to absorb
 * @param len Length of data to absorb
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if data is NULL with len > 0
 */
static noxtls_return_t sha3_absorb(noxtls_sha3_ctx_t * ctx, const uint8_t * data, uint32_t len)
{
    uint32_t offset = 0U;
    uint32_t remaining = len;
    uint32_t pos = (uint32_t)ctx->buffer_len;
    uint32_t rate = (uint32_t)ctx->rate;

    if ((data == NULL) && (remaining != 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    if ((rate == 0U) || (rate > SHA3_STATE_SIZE) || (pos >= rate)) {
        return NOXTLS_RETURN_FAILED;
    }

    while (remaining > 0U) {
        if (((pos & 7U) == 0U) && (remaining >= SHA3_LANE_BYTES)) {
            /* Whole-lane fast path (rates are multiples of 8 bytes). */
            ctx->state[pos >> 3U] ^= sha3_load_le64(&data[offset]);
            pos += SHA3_LANE_BYTES;
            offset += SHA3_LANE_BYTES;
            remaining -= SHA3_LANE_BYTES;
        } else {
            sha3_xor_byte(ctx->state, pos, data[offset]);
            pos += 1U;
            offset += 1U;
            remaining -= 1U;
        }

        /* If we've filled a rate block, apply permutation */
        if (pos == rate) {
            keccak_f1600(ctx->state);
            pos = 0U;
        }
    }

    ctx->buffer_len = (uint8_t)pos;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Apply the pad10*1 padding with the domain suffix and permute.
 *
 * @param ctx SHA-3 context
 */
static void sha3_pad_and_permute(noxtls_sha3_ctx_t * ctx)
{
    sha3_xor_byte(ctx->state, (uint32_t)ctx->buffer_len, ctx->domain_sep);
    sha3_xor_byte(ctx->state, (uint32_t)ctx->rate - 1U, (uint8_t)SHA3_PAD_FINAL_BYTE);
    keccak_f1600(ctx->state);
    ctx->buffer_len = 0U;
}

/**
 * @brief Squeeze output bytes from a finalized sponge.
 *
 * @param ctx SHA-3 context (finalized)
 * @param out Output buffer
 * @param out_len Bytes to produce
 */
static void sha3_squeeze(noxtls_sha3_ctx_t * ctx, uint8_t * out, uint32_t out_len)
{
    uint32_t copied = 0U;
    uint32_t pos = (uint32_t)ctx->buffer_len;
    uint32_t rate = (uint32_t)ctx->rate;

    while (copied < out_len) {
        if (pos >= rate) {
            keccak_f1600(ctx->state);
            pos = 0U;
        }
        if (((pos & 7U) == 0U) && ((out_len - copied) >= SHA3_LANE_BYTES)) {
            sha3_store_le64(&out[copied], ctx->state[pos >> 3U]);
            pos += SHA3_LANE_BYTES;
            copied += SHA3_LANE_BYTES;
        } else {
            out[copied] = sha3_get_byte(ctx->state, pos);
            pos += 1U;
            copied += 1U;
        }
    }
    /* Leave a full block for the next call to trigger the permutation lazily. */
    ctx->buffer_len = (uint8_t)pos;
}

/**
 * @brief Common sponge initialisation.
 *
 * @param ctx SHA-3 context
 * @param algo Hash identifier stored in the context (0 for SHAKE)
 * @param rate Rate in bytes
 * @param output_len Digest length in bytes (0 for SHAKE)
 * @param domain_sep Domain separation suffix
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
static noxtls_return_t sha3_init_common(noxtls_sha3_ctx_t * ctx, noxtls_hash_algos_t algo,
                                        uint32_t rate, uint32_t output_len, uint8_t domain_sep)
{
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero(ctx, sizeof(*ctx));
    ctx->algo = (uint8_t)algo;
    ctx->rate = (uint8_t)rate;
    ctx->output_len = (uint8_t)output_len;
    ctx->domain_sep = domain_sep;
    ctx->buffer_len = 0U;
    ctx->finalized = 0U;

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
    /* rate 1152 bits / 8 = 144 bytes, capacity 56 bytes */
    return sha3_init_common(ctx, NOXTLS_HASH_SHA3_224, SHA3_RATE_224_BYTES,
                            (uint32_t)HASH_SHA3_224_OUT_LEN, SHA3_DOMAIN_SEP);
}

/**
 * @brief Initialize SHA3-256
 *
 * @param ctx SHA-3 context
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
noxtls_return_t noxtls_sha3_256_init(noxtls_sha3_ctx_t * ctx)
{
    /* rate 1088 bits / 8 = 136 bytes, capacity 64 bytes */
    return sha3_init_common(ctx, NOXTLS_HASH_SHA3_256, SHA3_RATE_256_BYTES,
                            (uint32_t)HASH_SHA3_256_OUT_LEN, SHA3_DOMAIN_SEP);
}

/**
 * @brief Initialize SHA3-384
 *
 * @param ctx SHA-3 context
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
noxtls_return_t noxtls_sha3_384_init(noxtls_sha3_ctx_t * ctx)
{
    /* rate 832 bits / 8 = 104 bytes, capacity 96 bytes */
    return sha3_init_common(ctx, NOXTLS_HASH_SHA3_384, SHA3_RATE_384_BYTES,
                            (uint32_t)HASH_SHA3_384_OUT_LEN, SHA3_DOMAIN_SEP);
}

/**
 * @brief Initialize SHA3-512
 * @param ctx SHA-3 context
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
noxtls_return_t noxtls_sha3_512_init(noxtls_sha3_ctx_t * ctx)
{
    /* rate 576 bits / 8 = 72 bytes, capacity 128 bytes */
    return sha3_init_common(ctx, NOXTLS_HASH_SHA3_512, SHA3_RATE_512_BYTES,
                            (uint32_t)HASH_SHA3_512_OUT_LEN, SHA3_DOMAIN_SEP);
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
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if (ctx->finalized != 0U) {
        return NOXTLS_RETURN_FAILED; /* Cannot update after finalization */
    }

    return sha3_absorb(ctx, data, len);
}

/**
 * @brief Finalize SHA-3 and produce hash
 *
 * Padding is pad10*1 with the domain separation suffix: the suffix (0x06,
 * i.e. bits 01 followed by the first pad bit) is XORed at the current
 * position and 0x80 into the last byte of the rate block.
 *
 * @param ctx SHA-3 context
 * @param hash Hash to produce
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL, NOXTLS_RETURN_FAILED if SHA-3 is finalized
 */
noxtls_return_t noxtls_sha3_finish(noxtls_sha3_ctx_t * ctx, uint8_t * hash)
{
    if ((ctx == NULL) || (hash == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if (ctx->finalized != 0U) {
        return NOXTLS_RETURN_FAILED;
    }

    sha3_pad_and_permute(ctx);
    sha3_squeeze(ctx, hash, (uint32_t)ctx->output_len);
    ctx->finalized = 1U;

    return NOXTLS_RETURN_SUCCESS;
}

/* SHAKE128/SHAKE256 (FIPS 202): extendable-output functions, domain sep 0x1F. */
/**
 * @brief Initialize SHAKE128
 *
 * @param ctx The SHAKE128 context
 * @return The return value
 */
noxtls_return_t noxtls_shake128_init(noxtls_sha3_ctx_t * ctx)
{
    return sha3_init_common(ctx, (noxtls_hash_algos_t)0U, SHA3_SHAKE128_RATE_BYTES, 0U,
                            (uint8_t)SHA3_SHAKE128_DOMAIN_SEP);
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
    sha3_pad_and_permute(ctx);
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
    if ((ctx == NULL) || ((out == NULL) && (out_len != 0U))) { return NOXTLS_RETURN_NULL; }
    if (ctx->finalized == 0U) { return NOXTLS_RETURN_FAILED; }
    sha3_squeeze(ctx, out, out_len);
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
    return sha3_init_common(ctx, (noxtls_hash_algos_t)0U, SHA3_SHAKE256_RATE_BYTES, 0U,
                            (uint8_t)SHA3_SHAKE256_DOMAIN_SEP);
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
    sha3_pad_and_permute(ctx);
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
    if ((ctx == NULL) || ((out == NULL) && (out_len != 0U))) { return NOXTLS_RETURN_NULL; }
    if (ctx->finalized == 0U) { return NOXTLS_RETURN_FAILED; }
    sha3_squeeze(ctx, out, out_len);
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
