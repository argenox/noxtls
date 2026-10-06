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
* File:    noxtls_md4.c
* Summary: Message Digest Algorithm 4 (MD4)
* Defined in RFC 1320
*
* MD4 is cryptographically broken and should not be used.
*
*
*****************************************************************************/

/** @addtogroup noxtls_mdigest */

#include <stdint.h>
#include <string.h>

#include "string_common.h"
#include "noxtls_common.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_md4.h"
#include "noxtls_ct.h"

#if NOXTLS_FEATURE_MD4

/* Module Debug Level */
static uint8_t md4_debug_lvl = 0U;

/* MD4 Operations */
#define MD4_F(X, Y, Z)     ((X & Y) | ((~X) & Z))
#define MD4_G(X, Y, Z)     ((X & Y) | (X & Z) | (Y & Z))
#define MD4_H(X, Y, Z)     (X ^ Y ^ Z)

#define MD4_ROTL(X, N)      (((X) << ((uint32_t)(N) & 31U)) | ((X) >> ((32U - (uint32_t)(N)) & 31U)))

/* Max bytes per update to avoid misuse (e.g. UINT32_MAX with small buffer). */
#define MD4_MAX_UPDATE_LEN  0x7FFFFFFFu

noxtls_return_t noxtls_md4_round(noxtls_sha_ctx_t * ctx, const uint8_t * input);

/* Shift amounts for MD4 (RFC 1320: MD4_COMPRESS_ROUNDS x MD4_WORDS_PER_BLOCK steps). */
static uint32_t md4_shift[MD4_ROT_SHIFT_TABLE_LEN] =
{
    /* Round 1 */
    3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19,
    /* Round 2 */
    3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13,
    /* Round 3 */
    3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15
};

/**
 * @brief Sets Module Debug level
 *
 *
 * @param[in] lvl is the debug level
 *
 */
void noxtls_md4_set_debug(uint8_t lvl)
{
    md4_debug_lvl = lvl;
}

/**
 * @brief Initialize the MD4 Context
 *
 * @param[in,out] ctx is the context
 *
 * 
 */
noxtls_return_t noxtls_md4_init(noxtls_sha_ctx_t * ctx)
{
	if(ctx == NULL) {
		return NOXTLS_RETURN_NULL;
	}
    
    ctx->algo = NOXTLS_HASH_MD4;
    
    noxtls_secure_zero((ctx->h), sizeof(ctx->h));
        
    /* MD4 initial hash values */
    ctx->h[0] = 0x67452301U;
    ctx->h[1] = 0xefcdab89U;
    ctx->h[2] = 0x98badcfeU;
    ctx->h[3] = 0x10325476U;

    if(md4_debug_lvl > 0U) {
        (void)noxtls_debug_printf((const uint8_t *)"ctx->h[0] = %x\n", ctx->h[0]);
    }

    noxtls_secure_zero((&ctx->data), (size_t)(HASH_MD4_BLOCK_SIZE));
    ctx->data_len = 0U;
    ctx->length = 0U;
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Update the MD4 context
 * 
 * @details Runs on every block of 512 bits.
 * Caller must ensure input points to at least len bytes of valid memory.
 * len is rejected if it would cause ctx->length to overflow (uint32_t).
 * 
 * @param[in] ctx The context.
 * @param[in] input The input.
 * @param[in] len The length of the input.
 * @return The return value.
 */
noxtls_return_t noxtls_md4_update(noxtls_sha_ctx_t * ctx, const uint8_t * input, uint32_t len)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t offset = 0U;
    uint32_t in_left = len;

	if(ctx == NULL) {
		return NOXTLS_RETURN_NULL;
	}
    if((input == NULL) || (in_left == 0U)) {
        return NOXTLS_RETURN_SUCCESS;
    }
    /* Reject lengths that would overflow total length or are commonly misused (e.g. UINT32_MAX). */
    if(in_left > (uint32_t)MD4_MAX_UPDATE_LEN || ((ctx->length + in_left) < ctx->length)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    /* Fill existing buffer if present */
    if(ctx->data_len > 0U) {
        uint32_t to_copy = (uint32_t)(HASH_MD4_BLOCK_SIZE - ctx->data_len);
        if(to_copy > in_left) {
            to_copy = in_left;
        }
        (void)memcpy(&ctx->data[ctx->data_len], input, (size_t)to_copy);
        ctx->data_len += (uint8_t)to_copy; /* Due to 64 subtraction, will always be less than 64 */
        offset += to_copy;
        in_left -= to_copy;
        if(ctx->data_len == HASH_MD4_BLOCK_SIZE) {
            rc = noxtls_md4_round(ctx, ctx->data);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            ctx->length += HASH_MD4_BLOCK_SIZE;
            ctx->data_len = 0U;
        }
    }

    /* Process full blocks directly from input */
    while(in_left >= HASH_MD4_BLOCK_SIZE) {
        rc = noxtls_md4_round(ctx, &input[offset]);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        ctx->length += HASH_MD4_BLOCK_SIZE;
        offset += HASH_MD4_BLOCK_SIZE;
        in_left -= HASH_MD4_BLOCK_SIZE;
    }

    /* Store remainder */
    if(in_left > 0U) {
        (void)memcpy(ctx->data, &input[offset], (size_t)in_left);
        ctx->data_len = (uint8_t)in_left;
    }

    return rc;
}

/**
 * @brief Performs an MD4 round
 *
 *
 * @param[in] ctx is the MD4 context
 * @param[in] input is the 512-bit data
 *
 * @return NOXTLS_RETURN_SUCCESS on success, noxtls_return_t otherwise
 */
noxtls_return_t noxtls_md4_round(noxtls_sha_ctx_t * ctx, const uint8_t * input)
{
	noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
	uint32_t t = 0U;
	uint32_t w[MD4_WORDS_PER_BLOCK] = {0};

    uint32_t A;
    uint32_t B;
    uint32_t C;
    uint32_t D = 0U;
    
	if(ctx == NULL) {
		return NOXTLS_RETURN_NULL;
	}    
    
    /* Copy the noxtls_message to the first 16 words (little-endian) */
    for(t = 0U; t < MD4_WORDS_PER_BLOCK; t += 1U) {
        w[t] = (input[(t * MD4_WORD_BYTES) +3U] <<24U) | ((input[(t * MD4_WORD_BYTES) +2U]) <<16U) | ((uint16_t)input[(t * MD4_WORD_BYTES) + 1U] << 8U) | (uint16_t)input[(t * MD4_WORD_BYTES)];
        if(md4_debug_lvl > 0U) {
            (void)noxtls_debug_printf((const uint8_t *)"w[%d] %u  0x%08x\n", t, w[t], w[t]);
        }
    }

    A = ctx->h[0];
    B = ctx->h[1];
    C = ctx->h[2];
    D = ctx->h[3];
    
    if(md4_debug_lvl > 0U) {
        (void)noxtls_debug_printf((const uint8_t *)"A\t\t\tB\t\t\tC\t\t\tD\t\t\tF\n");
        (void)noxtls_debug_printf((const uint8_t *)"%08x\t%08x\t%08x\t%08x\t\n", A, B, C, D);
    }
    
    /* Round 1: F function */
    for(t = 0U; t < MD4_WORDS_PER_BLOCK; t += 1U)
    {
        uint32_t F = (uint32_t)(MD4_F(B, C, D));
        F = F + A + w[t];
        A = MD4_ROTL(F, md4_shift[t]);
        
        /* Rotate registers */
        uint32_t temp = (uint32_t)(D);
        D = C;
        C = B;
        B = A;
        A = temp;
        
        if(md4_debug_lvl > 0U) {
            (void)noxtls_debug_printf((const uint8_t *)"%u\t%u\t%u\t%u\t\n", A, B, C, D);
        }
    }
    
    /* Round 2: G function */
    /* Word selection: 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15 */
    const uint32_t round2_words[MD4_WORDS_PER_BLOCK] = {0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15};
    for(t = 0U; t < MD4_WORDS_PER_BLOCK; t += 1U)
    {
        uint32_t G = (uint32_t)(MD4_G(B, C, D));
        G = G + A + w[round2_words[t]] + MD4_ROUND2_CONST;  /* MD4 round 2 constant */
        A = MD4_ROTL(G, md4_shift[16U + t]);
        
        /* Rotate registers */
        uint32_t temp = (uint32_t)(D);
        D = C;
        C = B;
        B = A;
        A = temp;
        
        if(md4_debug_lvl > 0U) {
            (void)noxtls_debug_printf((const uint8_t *)"%u\t%u\t%u\t%u\t\n", A, B, C, D);
        }
    }
    
    /* Round 3: H function */
    /* Word selection: 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15 */
    const uint32_t round3_words[MD4_WORDS_PER_BLOCK] = {0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15};
    for(t = 0U; t < MD4_WORDS_PER_BLOCK; t += 1U)
    {
        uint32_t H = (uint32_t)(MD4_H(B, C, D));
        H = H + A + w[round3_words[t]] + MD4_ROUND3_CONST;  /* MD4 round 3 constant */
        A = MD4_ROTL(H, md4_shift[MD4_ROT_SHIFT_ROUND3_BASE + t]);
        
        /* Rotate registers */
        uint32_t temp = (uint32_t)(D);
        D = C;
        C = B;
        B = A;
        A = temp;
        
        if(md4_debug_lvl > 0U) {
            (void)noxtls_debug_printf((const uint8_t *)"%u\t%u\t%u\t%u\t\n", A, B, C, D);
        }
    }
    
    /* Compute the intermediate hash value H(i) */
    ctx->h[0] += A;
    ctx->h[1] += B;
    ctx->h[2] += C;
    ctx->h[3] += D;
    
    return rc;    
}

/**
 * @brief Finish MD4 operation
 * 
 * @details this function must be called 
 * 
 *
 * @param[in] ctx is the SHA context object
 * @param[in] hash is a pointer to the buffer where the MD4 result will be placed
 *
 * @return NOXTLS_RETURN_SUCCESS on success, noxtls_return_t otherwise
 */
noxtls_return_t noxtls_md4_finish(noxtls_sha_ctx_t * ctx, uint8_t * hash)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint32_t len = 0U;
    uint64_t total_length = 0U;
    uint32_t i = 0U;
    uint8_t temp[HASH_MD4_BLOCK_SIZE];

    if((ctx == NULL) || (hash == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    /* Total message length must always include every block already
     * compressed (ctx->length) plus the pending partial block. A non-empty
     * message whose length is a multiple of 64 has data_len == 0 while
     * ctx->length > 0, so the length must not depend on data_len. */
    len = (uint32_t)ctx->data_len;
    total_length = (uint64_t)ctx->length + (uint64_t)len;

    noxtls_secure_zero((temp), sizeof(temp));
    if(len > 0U) {
        noxtls_copy_u8(temp, sizeof(temp), ctx->data, (size_t)len);
    }

    /* len < 64 always, so the 0x80 pad byte always fits in this block */
    temp[len] = (uint8_t)MD4_PAD_BYTE;

    if(((uint32_t)HASH_MD4_BLOCK_SIZE - len) >= ((uint32_t)HASH_MD4_LENGTH_LEN + 1U)) {
        /* Pad byte and 64-bit length fit in this block */
        noxtls_add_padding_length_little(temp, (uint32_t)HASH_MD4_BLOCK_SIZE, total_length, (uint8_t)HASH_MD4_LENGTH_LEN);
        rc = noxtls_md4_round(ctx, temp);
    } else {
        /* Length does not fit: compress this block, then a zero block carrying the length */
        rc = noxtls_md4_round(ctx, temp);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_secure_zero((temp), sizeof(temp));
            noxtls_add_padding_length_little(temp, (uint32_t)HASH_MD4_BLOCK_SIZE, total_length, (uint8_t)HASH_MD4_LENGTH_LEN);
            rc = noxtls_md4_round(ctx, temp);
        }
    }
    noxtls_secure_zero((temp), sizeof(temp));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        /* Never release a partial digest: wipe the output and the state. */
        noxtls_secure_zero(hash, (size_t)HASH_MD4_OUT_LEN);
        noxtls_secure_zero(ctx, sizeof(*ctx));
        return rc;
    }

    for(i = 0U; i < (uint32_t)HASH_MD4_STATE_WORDS; i += 1U)
    {
        hash[(i * 4U) + 3U] = (uint8_t)((ctx->h[i] & 0xFF000000U) >> 24U);
        hash[(i * 4U) + 2U] = (uint8_t)((ctx->h[i] & 0x00FF0000U) >> 16U);
        hash[(i * 4U) + 1U] = (uint8_t)((ctx->h[i] & 0x0000FF00U) >> 8U);
        hash[i * 4U] = (uint8_t)(ctx->h[i] & 0x000000FFU);
    }

    return rc;
}
/**
 * @brief Takes data and verifies it matches a MD4 Digest
 *
 *
 * @param[in] data is the input data
 * @param[in] len is the length of the input data
 * @param[in] expected is the expected MD4 digest
 *
 * @return NOXTLS_RETURN_SUCCESS on success, noxtls_return_t otherwise
 */
noxtls_return_t noxtls_md4_verify(const uint8_t * data, uint32_t len, const uint8_t * expected)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    uint8_t hash[HASH_MD4_OUT_LEN] = {0};
    noxtls_sha_ctx_t ctx;
    
    noxtls_return_t hrc = noxtls_md4_init(&ctx);
    if(hrc == NOXTLS_RETURN_SUCCESS) {
        hrc = noxtls_md4_update(&ctx, data, len);
    }
    if(hrc == NOXTLS_RETURN_SUCCESS) {
        hrc = noxtls_md4_finish(&ctx, hash);
    }
    
    if(md4_debug_lvl > 0U) {
        (void)noxtls_debug_printf((const uint8_t *)"Compare: \n");
        (void)noxtls_print_data(hash, sizeof(hash));
        (void)noxtls_print_data(expected, HASH_MD4_OUT_LEN);
    }
    /* Fail closed: a hashing error is never reported as a match. */
    if((hrc == NOXTLS_RETURN_SUCCESS) && (memcmp(hash, expected, sizeof(hash)) == 0)) {
        rc = NOXTLS_RETURN_SUCCESS;
    }

    return rc;
}

#endif /* NOXTLS_FEATURE_MD4 */

