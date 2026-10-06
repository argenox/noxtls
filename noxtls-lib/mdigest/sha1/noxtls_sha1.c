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
* File:    noxtls_sha1.c
* Summary: Secure Hashing Algorithm SHA-1
* Defined in FIPS
*
* Note: SHA-1 is no longer recommended due to significant cryptographic weaknesses. 
* It is vulnerable to practical collision and chosen-prefix attacks, allowing attackers 
* to create different inputs with the same hash. T
* his makes SHA-1 unsuitable for security-sensitive applications.
*
*
*****************************************************************************/

/** @addtogroup noxtls_mdigest */

#include <stdint.h>
#include <string.h>

#include "noxtls_common.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_sha.h"
#include "noxtls_sha1.h"
#include "noxtls_ct.h"

#if NOXTLS_FEATURE_SHA1

/* Module Debug Level */
static uint8_t sha1_debug_lvl = 0U;

/* SHA-1 Operations */
#define SHA_CH(X, Y, Z)     (((X) & (Y)) ^ ((~(X)) & (Z)))
#define SHA_PARITY(X,Y,Z)   ((X) ^ (Y) ^ (Z))
#define SHA_MAJ(X,Y, Z)     (((X) & (Y)) ^ ((X) & (Z)) ^ ((Y) & (Z)))

#define SHA_ROTL(X, N)      (((X) << ((uint32_t)(N) & 31U)) | ((X) >> ((32U - (uint32_t)(N)) & 31U)))

static noxtls_return_t noxtls_sha1_round(noxtls_sha_ctx_t * ctx, const uint8_t * input);

/**
 * @brief Set the debug level
 * 
 * @param[in] lvl The debug level.
 * @return void
 */
void noxtls_sha1_set_debug(uint8_t lvl)
{
    sha1_debug_lvl = lvl;
}

/**
 * @brief Initialize the SHA1 context
 * 
 * @param[in] ctx The SHA1 context to initialize.
 * @param[in] algo The algorithm to use.
 * @return The return value.
 */
noxtls_return_t noxtls_sha1_init(noxtls_sha_ctx_t * ctx, noxtls_hash_algos_t algo)
{
	if (ctx == NULL) {
		return NOXTLS_RETURN_NULL;
	}
    
    ctx->algo = algo;
    
    if (ctx->algo == NOXTLS_HASH_SHA1) {

        ctx->h[0] = 0x67452301U;
        ctx->h[1] = 0xefcdab89U;
        ctx->h[2] = 0x98badcfeU;
        ctx->h[3] = 0x10325476U;
        ctx->h[4] = 0xc3d2e1f0U;        
    }    
    else
    {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }

    noxtls_secure_zero((&ctx->data), (size_t)(SHA1_BLOCK_SIZE_BYTES));
    ctx->data_len = 0U;
    ctx->length = 0U;
    
    return NOXTLS_RETURN_SUCCESS;
}

/* Runs on every block of 512 bits */

/**
 * @brief Update the SHA1 context
 * 
 * @param[in] ctx The SHA1 context to update.
 * @param[in] data The input data to update.
 * @param[in] len The length of the input data.
 * @return The return value.
 */
noxtls_return_t noxtls_sha1_update(noxtls_sha_ctx_t * ctx, const uint8_t * data, uint32_t len)
{
	noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint32_t total = 0U;
    uint32_t offset = 0U;

	if (ctx == NULL) {
        (void)noxtls_debug_printf((const uint8_t *)"ctx is NULL\n");
		return NOXTLS_RETURN_NULL;
	}

    if (data == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    total = len;

    if (ctx->data_len > 0U) {
        uint32_t space = 0U;
    {
        uint32_t used = ctx->data_len;
        space = SHA1_BLOCK_SIZE_BYTES - used;
    }
        if (total < space) {
            noxtls_copy_u8(&ctx->data[ctx->data_len], sizeof(ctx->data) - (size_t)(ctx->data_len), data, (size_t)total);
            ctx->data_len += (uint8_t)total;
            return NOXTLS_RETURN_SUCCESS;
        }

        noxtls_copy_u8(&ctx->data[ctx->data_len], sizeof(ctx->data) - (size_t)(ctx->data_len), data, (size_t)space);
        rc = noxtls_sha1_round(ctx, ctx->data);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        ctx->length += SHA1_BLOCK_SIZE_BYTES;
        ctx->data_len = 0U;
        offset += space;
        total -= space;
    }

    while (total >= SHA1_BLOCK_SIZE_BYTES) {
        rc = noxtls_sha1_round(ctx, &data[offset]);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        ctx->length += SHA1_BLOCK_SIZE_BYTES;
        offset += SHA1_BLOCK_SIZE_BYTES;
        total -= SHA1_BLOCK_SIZE_BYTES;
    }

    if (total > 0U) {
        noxtls_copy_u8(ctx->data, sizeof(ctx->data), &data[offset], (size_t)total);
        ctx->data_len = (uint8_t)total;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief SHA1 round
 * Accepts only 512-bit data input
 * @param[in] ctx The SHA1 context.
 * @param[in] input The input data.
 * @return The return value.
 */
static noxtls_return_t noxtls_sha1_round(noxtls_sha_ctx_t * ctx, const uint8_t * input)
{
	noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
	uint32_t t = 0U;
	uint32_t w[SHA1_ROUND_COUNT] = {0};

    uint32_t a = 0U;
    uint32_t b = 0U;
    uint32_t c = 0U;
    uint32_t d = 0U;
    uint32_t e = 0U;
    
	if (ctx == NULL) {
		return NOXTLS_RETURN_NULL;
	}    
    if (input == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Copy the noxtls_message to the first 16 words */    
    for (t = 0U; t < 16U; t += 1U) {
        size_t in_off = (size_t)t * 4U;
        w[t] =
            ((uint32_t)input[in_off] <<24U) |
            ((uint32_t)input[in_off + 1U] <<16U) |
            ((uint32_t)input[in_off + 2U] <<8U) |
            ((uint32_t)input[in_off + 3U]);
    }

    for (t = 16U; t < SHA1_ROUND_COUNT; t += 1U) {
        w[t] = SHA_ROTL((w[t - 3U] ^ w[t - 8U] ^ w[t - 14U] ^ w[t - 16U]), 1U);
    }
    
    a = ctx->h[0];
    b = ctx->h[1];
    c = ctx->h[2];
    d = ctx->h[3];
    e = ctx->h[4];
    
    if (sha1_debug_lvl > 0U) {
        (void)noxtls_debug_printf((const uint8_t *)"a\t\t\tb\t\t\tc\t\t\td\t\t\te\n");
    }
    
    for (t = 0U; t < SHA1_ROUND_COUNT; t += 1U)
    {
        uint32_t ft = 0U;
        uint32_t sha1_k = 0U;
        uint32_t T = 0U;
        
        if (t <= 19U) {
            sha1_k = 0x5A827999U;
            ft = SHA_CH(b,c,d);
        }
        else if (t <= 39U) {
            sha1_k = 0x6ED9EBA1U;
            ft = SHA_PARITY(b,c,d);
        }
        else if (t <= 59U) {
            sha1_k = 0x8F1BBCDCU;
            ft = SHA_MAJ(b,c,d);
        }
        else {
            /* t in [60..79] */
            sha1_k = 0xCA62C1D6U;
            ft = SHA_PARITY(b,c,d);
        }
        
        T = (uint32_t)(SHA_ROTL(a, 5U) + ft + e + sha1_k + w[t]);
        e = d;
        d = c;
        c = SHA_ROTL(b, 30U);
        b = a;
        a = T;
        
        if (sha1_debug_lvl > 0U) {
            (void)noxtls_debug_printf((const uint8_t *)"%08x\t%08x\t%08x\t%08x\t%08x\t\n", a,b,c,d,e);
        }
    }
    
    /* Computer the ith intermediate hash value H(i) */
    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;    
    
    return rc;    
}

/**
 * @brief Finish SHA-1 operation
 * 
 * @details this function must be called 
 * 
 *
 * @param[in] ctx is the SHA context object
 * @param[in] hash is a pointer to the buffer where the SHA result will be placed
 *
 * @return NOXTLS_RETURN_SUCCESS on success, noxtls_return_t otherwise
 */
static void sha1_store_bitlen_be(uint8_t *block, uint32_t length_index, uint64_t total_bits)
{
    block[length_index + 0U] = (uint8_t)((total_bits & 0xFF00000000000000ULL) >>56U);
    block[length_index + 1U] = (uint8_t)((total_bits & 0x00FF000000000000ULL) >>48U);
    block[length_index + 2U] = (uint8_t)((total_bits & 0x0000FF0000000000ULL) >>40U);
    block[length_index + 3U] = (uint8_t)((total_bits & 0x000000FF00000000ULL) >>32U);
    block[length_index + 4U] = (uint8_t)((total_bits & 0x00000000FF000000ULL) >>24U);
    block[length_index + 5U] = (uint8_t)((total_bits & 0x0000000000FF0000ULL) >>16U);
    block[length_index + 6U] = (uint8_t)((total_bits & 0x000000000000FF00ULL) >>8U);
    block[length_index + 7U] = (uint8_t)(total_bits & 0x00000000000000FFULL);
}

static noxtls_return_t sha1_finish_two_blocks(noxtls_sha_ctx_t *ctx, uint32_t len,
                                               uint32_t space_for_padding,
                                               uint32_t length_index, uint64_t total_bits)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint32_t zero_padding_first = 0U;

    if ((len <<3U) != SHA1_BLOCK_SIZE_BITS) {
        zero_padding_first = space_for_padding - 1U;
        ctx->data[len] = SHA1_PAD_BYTE;
        if ((len + 1U) < SHA1_BLOCK_SIZE_BYTES) {
            noxtls_secure_zero((&ctx->data[len + 1U]), ((size_t)(SHA1_BLOCK_SIZE_BYTES - (len + 1U))));
        }
        rc = noxtls_sha1_round(ctx, ctx->data);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    } else {
        /* MISRA 15.7: final else path */
        rc = noxtls_sha1_round(ctx, ctx->data);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    noxtls_secure_zero((ctx->data), (size_t)(SHA1_BLOCK_SIZE_BYTES));
    if (zero_padding_first == 0U) {
        ctx->data[0] = SHA1_PAD_BYTE;
    }
    (void)sha1_store_bitlen_be(ctx->data, length_index, total_bits);
    return noxtls_sha1_round(ctx, ctx->data);
}

static noxtls_return_t sha1_finish_one_block(noxtls_sha_ctx_t *ctx, uint32_t space_for_padding,
                                              uint32_t length_index, uint64_t total_bits)
{
    uint32_t pad_byte_idx = (uint32_t)(SHA1_BLOCK_SIZE_BYTES - (space_for_padding >>3U));
    uint32_t zero_count = (uint32_t)(length_index - (pad_byte_idx + 1U));

    ctx->data[pad_byte_idx] = SHA1_PAD_BYTE;
    if (zero_count > 0U) {
        noxtls_secure_zero((&ctx->data[pad_byte_idx + 1U]), (size_t)(zero_count));
    }
    (void)sha1_store_bitlen_be(ctx->data, length_index, total_bits);
    return noxtls_sha1_round(ctx, ctx->data);
}

noxtls_return_t noxtls_sha1_finish(noxtls_sha_ctx_t * ctx, uint8_t * hash)
{
	noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint64_t total_bits = 0U;
    uint32_t len = 0U;
    uint32_t total_length = 0U;
    uint32_t length_index = (uint32_t)(SHA1_BLOCK_SIZE_BYTES - SHA1_LENGTH_FIELD_BYTES);
    uint32_t space_for_padding = 0U;
    uint32_t alg_sz = 0U;
    uint32_t i = 0U;

    if ((ctx == NULL) || (hash == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if (ctx->data_len > 0U) {
        len = ctx->data_len;
        total_length = ctx->length + ctx->data_len;
    } else {
        noxtls_secure_zero((ctx->data), (size_t)(SHA1_BLOCK_SIZE_BYTES));
        total_length = ctx->length;
    }

    space_for_padding = SHA1_BLOCK_SIZE_BITS - ((len <<3U) % SHA1_BLOCK_SIZE_BITS);
    total_bits = (uint64_t)total_length * 8U;

    if (space_for_padding < ((SHA1_LENGTH_FIELD_BYTES + 1U) <<3U)) {
        rc = sha1_finish_two_blocks(ctx, len, space_for_padding, length_index, total_bits);
    } else {
        /* MISRA 15.7: final else path */
        rc = sha1_finish_one_block(ctx, space_for_padding, length_index, total_bits);
    }
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    alg_sz = SHA1_LENGTH_FIELD_BYTES;
    if (ctx->algo == NOXTLS_HASH_SHA_224) {
        alg_sz = 6U;
    }
    if (ctx->algo == NOXTLS_HASH_SHA1) {
        alg_sz = SHA1_STATE_WORDS;
    }
    for (i = 0U; i < alg_sz; i += 1U)
    {
        size_t out_off = (size_t)i * 4U;
        hash[out_off]       = (uint8_t)((ctx->h[i] &0xFF000000U) >>24U);
        hash[out_off + 1U] = (uint8_t)((ctx->h[i] &0x00FF0000U) >>16U);
        hash[out_off + 2U] = (uint8_t)((ctx->h[i] &0x0000FF00U) >>8U);
        hash[out_off + 3U] = (uint8_t)(ctx->h[i] &0x000000FFU);
    }

	return rc;
}

/**
 * @brief Takes data and verifies it matches a SHA1 Digest
 * 
 * @details this function must be called 
 * 
 *
 * @param[in] data is the data to hash
 * @param[in] len is the length of the data
 * @param[in] expected is the expected SHA1 digest
 *
 * @return NOXTLS_RETURN_SUCCESS on success, noxtls_return_t otherwise
 */
noxtls_return_t noxtls_sha1_verify(const uint8_t * data, uint32_t len, const uint8_t * expected)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    uint8_t hash[32] = {0};
    noxtls_sha_ctx_t ctx;
    
    rc = noxtls_sha1_init(&ctx, NOXTLS_HASH_SHA1);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_debug_printf((const uint8_t *)"Failed to initialize SHA1 context\n");
        return rc;
    }
    rc = noxtls_sha1_update(&ctx, data, len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_debug_printf((const uint8_t *)"Failed to update SHA1 context\n");
        return rc;
    }
    rc = noxtls_sha1_finish(&ctx, hash);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_debug_printf((const uint8_t *)"Failed to finish SHA1 context\n");
        return rc;
    }
    
    if (noxtls_ct_equal(hash, expected, sizeof(hash)) != 0) {
        rc = NOXTLS_RETURN_SUCCESS;
    }

    return rc;
}

#endif /* NOXTLS_FEATURE_SHA1 */
