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
* File:    noxtls_sha512.h
* Summary: SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Hash Implementation
*
*
*****************************************************************************/

/** @addtogroup noxtls_mdigest */

/* SHA-384, SHA-512, SHA-512/224 and SHA-512/256 */

#include <stdint.h>
#include <string.h>

#include "noxtls_common.h"
#include "common/noxtls_accel_port.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_sha.h"
#include "noxtls_sha512.h"
#include "noxtls_ct.h"

#if (NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512)

/* Module Debug Level */
static uint8_t sha512_debug_lvl = 0U;

/* SHA-256 Operations */
#define SHA_CH(X, Y, Z)     (((X) & (Y)) ^ ((~(X)) & (Z)))
#define SHA_MAJ(X,Y, Z)     (((X) & (Y)) ^ ((X) & (Z)) ^ ((Y) & (Z)))
#define SHA_ROTR(X, N)      (((X) >> (N)) | ((X) << (64U - (N))))

#define SHA_SUM_FROM_0(X)   (SHA_ROTR((X), 28U)  ^ SHA_ROTR((X), 34U) ^ SHA_ROTR((X), 39U))
#define SHA_SUM_FROM_1(X)   (SHA_ROTR((X), 14U)  ^ SHA_ROTR((X), 18U) ^ SHA_ROTR((X), 41U))
#define SHA_SIGMA_FROM_0(X) (SHA_ROTR((X), 1U)   ^ SHA_ROTR((X), 8U)  ^ ((X) >> 7U))
#define SHA_SIGMA_FROM_1(X) (SHA_ROTR((X), 19U)  ^ SHA_ROTR((X), 61U) ^ ((X) >> 6U))

static noxtls_return_t noxtls_sha512_round(noxtls_sha512_ctx_t * ctx, const uint8_t * input);
static noxtls_return_t noxtls_sha512_pad(const uint8_t * data, uint32_t zero_pad, uint32_t len);

/**
 * @brief Set SHA-512 debug level
 * 
 * @param lvl Debug level
 */
void noxtls_sha512_set_debug(uint8_t lvl)
{
    sha512_debug_lvl = lvl;
}

/**
 * @brief Initialize SHA-512
 * 
 * @param ctx SHA-512 context
 * @param algo Algorithm to use
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
noxtls_return_t noxtls_sha512_init(noxtls_sha512_ctx_t * ctx, noxtls_hash_algos_t algo)
{
	if (ctx == NULL) {
		return NOXTLS_RETURN_NULL;
	}
    
    ctx->algo = algo;
    
    if (ctx->algo == NOXTLS_HASH_SHA_512) {
        ctx->h[0] = 0x6a09e667f3bcc908ULL;
        ctx->h[1] = 0xbb67ae8584caa73bULL;
        ctx->h[2] = 0x3c6ef372fe94f82bULL;
        ctx->h[3] = 0xa54ff53a5f1d36f1ULL;
        ctx->h[4] = 0x510e527fade682d1ULL;
        ctx->h[5] = 0x9b05688c2b3e6c1fULL;
        ctx->h[6] = 0x1f83d9abfb41bd6bULL;
        ctx->h[7] = 0x5be0cd19137e2179ULL;
    } else if (ctx->algo == NOXTLS_HASH_SHA_384) {
        ctx->h[0] = 0xcbbb9d5dc1059ed8ULL;
        ctx->h[1] = 0x629a292a367cd507ULL;
        ctx->h[2] = 0x9159015a3070dd17ULL;
        ctx->h[3] = 0x152fecd8f70e5939ULL;
        ctx->h[4] = 0x67332667ffc00b31ULL;
        ctx->h[5] = 0x8eb44a8768581511ULL;
        ctx->h[6] = 0xdb0c2e0d64f98fa7ULL;
        ctx->h[7] = 0x47b5481dbefa4fa4ULL;
    } else if (ctx->algo == NOXTLS_HASH_SHA_512_224) {
        ctx->h[0] = 0x8c3d37c819544da2ULL;
        ctx->h[1] = 0x73e1996689dcd4d6ULL;
        ctx->h[2] = 0x1dfab7ae32ff9c82ULL;
        ctx->h[3] = 0x679dd514582f9fcfULL;
        ctx->h[4] = 0x0f6d2b697bd44da8ULL;
        ctx->h[5] = 0x77e36f7304c48942ULL;
        ctx->h[6] = 0x3f9d85a86a1d36c8ULL;
        ctx->h[7] = 0x1112e6ad91d692a1ULL;
    } else if (ctx->algo == NOXTLS_HASH_SHA_512_256) {
        ctx->h[0] = 0x22312194fc2bf72cULL;
        ctx->h[1] = 0x9f555fa3c84c64c2ULL;
        ctx->h[2] = 0x2393b86b6f53b151ULL;
        ctx->h[3] = 0x963877195940eabdULL;
        ctx->h[4] = 0x96283ee2a88effe3ULL;
        ctx->h[5] = 0xbe5e1e2553863992ULL;
        ctx->h[6] = 0x2b0199fc2c85b8aaULL;
        ctx->h[7] = 0x0eb72ddc81c52ca2ULL;
    } else {
         /* MISRA 15.7: final else path */
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }

    noxtls_secure_zero((&ctx->data), (size_t)(HASH_SHA512_BLOCK_SIZE));
    ctx->data_len = 0U;
    ctx->length = 0U;
    
    return NOXTLS_RETURN_SUCCESS;
}

/* Runs on every block of 512 bits */
/**
 * @brief Update SHA-512
 * 
 * @param ctx SHA-512 context
 * @param data Data to update
 * @param len Length of data to update
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
noxtls_return_t noxtls_sha512_update(noxtls_sha512_ctx_t * ctx, const uint8_t * data, uint32_t len)
{
    if (ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if ((data == NULL) || (len == 0U)) {
        return NOXTLS_RETURN_SUCCESS;
    }

    uint32_t offset = 0U;
    uint32_t in_left = len;

    /* Fill existing buffer if present */
    if (ctx->data_len > 0U) {
        uint32_t to_copy = 0U;
    {
        uint32_t used = ctx->data_len;
        to_copy = HASH_SHA512_BLOCK_SIZE - used;
    }
        if (to_copy > in_left) {
            to_copy = in_left;
        }
        noxtls_copy_u8(&ctx->data[ctx->data_len], sizeof(ctx->data) - (size_t)(ctx->data_len), data, (size_t)to_copy);
        ctx->data_len = (uint8_t)(ctx->data_len + to_copy);
        offset += to_copy;
        in_left -= to_copy;
        if (ctx->data_len == HASH_SHA512_BLOCK_SIZE) {
            noxtls_return_t rc = noxtls_sha512_round(ctx, ctx->data);
            if (rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            ctx->length += HASH_SHA512_BLOCK_SIZE;
            ctx->data_len = 0U;
        }
    }

    /* Process full blocks directly from data */
#if NOXTLS_PORT_SHA512_ACCEL
    if (in_left >= HASH_SHA512_BLOCK_SIZE) {
        uint32_t full_blocks = in_left / HASH_SHA512_BLOCK_SIZE;
        uint32_t full_bytes = full_blocks * HASH_SHA512_BLOCK_SIZE;

        /* Platform block hook: all whole blocks in one request (software on NOT_SUPPORTED). */
        if (noxtls_sha512_blocks_accel_port(ctx, &data[offset], full_blocks) == NOXTLS_RETURN_SUCCESS) {
            ctx->length += full_bytes;
            offset += full_bytes;
            in_left -= full_bytes;
        }
    }
#endif
    while (in_left >= HASH_SHA512_BLOCK_SIZE) {
        noxtls_return_t rc = noxtls_sha512_round(ctx, &data[offset]);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        ctx->length += HASH_SHA512_BLOCK_SIZE;
        offset += HASH_SHA512_BLOCK_SIZE;
        in_left -= HASH_SHA512_BLOCK_SIZE;
    }

    /* Store remainder */
    if (in_left > 0U) {
        noxtls_copy_u8(ctx->data, sizeof(ctx->data), &data[offset], (size_t)in_left);
        ctx->data_len = (uint8_t)in_left;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/* Accepts only 1024-bit data input */
/**
 * @brief SHA-512 round
 * 
 * @param ctx SHA-512 context
 * @param input Data to round
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
static noxtls_return_t noxtls_sha512_round(noxtls_sha512_ctx_t * ctx, const uint8_t * input)
{
    /* Tables local to this function (Rule 8.9). */
    /* SHA-384 / SHA-512 / SHA-512/224 / SHA-512/256 round constants K[0..79] (FIPS 180-4); count matches SHA512_ROUND_COUNT. */
    static const uint64_t sha512_k[SHA512_ROUND_COUNT] =
    {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL, 
        0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 
        0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL, 
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL, 
        0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL, 
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL, 
        0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 
        0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL, 
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL, 
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 
        0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL, 
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, 
        0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 
        0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL, 
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL, 
        0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 
        0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL, 
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL, 
        0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
    };


	noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
	uint32_t t = 0U;
	uint64_t w[SHA512_ROUND_COUNT] = {0};

    uint64_t a = 0U;
    uint64_t b = 0U;
    uint64_t c = 0U;
    uint64_t d = 0U;
    uint64_t e = 0U;
    uint64_t f = 0U;
    uint64_t g = 0U;
    uint64_t h = 0U;
    
	if (ctx == NULL) {
		return NOXTLS_RETURN_NULL;
	}    
    
#if NOXTLS_PORT_SHA512_ACCEL
    if((input != NULL) && (noxtls_sha512_blocks_accel_port(ctx, input, 1U) == NOXTLS_RETURN_SUCCESS)) {
        return NOXTLS_RETURN_SUCCESS;
    }
#endif

    /* Copy the noxtls_message to the first 16 words */    
    for (t = 0U; t < SHA512_WORDS_PER_BLOCK; t += 1U) {
        size_t in_off = (size_t)t * (size_t)SHA512_WORD_BYTES;
        w[t] =  ((uint64_t)input[in_off] <<56U)     |
                ((uint64_t)input[in_off + 1U] <<48U) |
                ((uint64_t)input[in_off + 2U] <<40U) |
                ((uint64_t)input[in_off + 3U] <<32U) |
                ((uint64_t)input[in_off + 4U] <<24U) | 
                ((uint64_t)input[in_off + 5U] <<16U) | 
                ((uint64_t)input[in_off + 6U] <<8U)  | 
                ((uint64_t)input[in_off + 7U]);

    }

    for (t = SHA512_WORDS_PER_BLOCK; t < SHA512_ROUND_COUNT; t += 1U) {
        {
            uint64_t s1 = SHA_SIGMA_FROM_1(w[t - 2U]);
            uint64_t s0 = SHA_SIGMA_FROM_0(w[t - 15U]);
            w[t] = s1 + w[t - 7U] + s0 + w[t - 16U];
        }
    }
    
    a = ctx->h[0];
    b = ctx->h[1];
    c = ctx->h[2];
    d = ctx->h[3];
    e = ctx->h[4];
    f = ctx->h[5];
    g = ctx->h[6];
    h = ctx->h[7];
    
    for (t = 0U; t < SHA512_ROUND_COUNT; t += 1U)
    {
        uint64_t t1 = h + SHA_SUM_FROM_1(e) + SHA_CH(e, f, g) + sha512_k[t] + w[t];
        uint64_t t2 = SHA_SUM_FROM_0(a) + SHA_MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    
    /* Computer the ith internmediate hash value H(i) */
    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
    ctx->h[5] += f;
    ctx->h[6] += g;
    ctx->h[7] += h;
    
    
    return rc;    
}

/**
 * @brief Finish SHA-512 operation
 * 
 * @details this function must be called 
 * 
 *
 * @param[in] ctx is the SHA context object
 * @param[in] hash is a pointer to the buffer where the SHA result will be placed
 *
 * @return NOXTLS_RETURN_SUCCESS on success, noxtls_return_t otherwise
 */
noxtls_return_t noxtls_sha512_finish(noxtls_sha512_ctx_t * ctx, uint8_t * hash)
{
	noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    uint32_t len = 0U;
    uint8_t * data = NULL;    
    uint32_t total_length = 0U;
    uint32_t i = 0U;
    
    uint8_t temp[HASH_SHA512_BLOCK_SIZE] = {0};
    /* Process any pending data or */
    if (ctx->data_len > 0U)
    {
        len = ctx->data_len;
        data = ctx->data;
        noxtls_secure_zero((temp), sizeof(temp));
        noxtls_copy_u8(temp, sizeof(temp), ctx->data, (size_t)len);
        total_length = ctx->length + ctx->data_len;
    }
    else
    {
        noxtls_secure_zero((ctx->data), (size_t)(HASH_SHA512_BLOCK_SIZE));
        data = ctx->data;
        total_length = ctx->length;
    }
    
    uint32_t block_size = (uint32_t)(HASH_SHA512_BLOCK_SIZE);
    uint8_t length_size = (uint8_t)(HASH_SHA512_LENGTH_LEN); /* Size of length in bytes 8 bytes / 128-bit */
    
    uint32_t space_occupied = (uint32_t)((len % block_size));
    uint32_t space_left = (uint32_t)(block_size - space_occupied);
    
    
    if (len == 0U) {
        space_occupied = 0U;
        space_left = block_size;
    }
        
    if (space_left >= 1U) {
        temp[space_occupied] = SHA512_PAD_BYTE;
    }
    
    if (space_left >= ((uint32_t)length_size + 1U)) {
        (void)noxtls_add_padding_length(temp, block_size, total_length, length_size);
    }

    if (sha512_debug_lvl > 0U){
        
        for (i = 0U; i < block_size; i += 1U) {
            (void)noxtls_debug_printf((const uint8_t *)"%02x ", temp[i]);
        }
        (void)noxtls_debug_printf((const uint8_t *)"\n");
        
        (void)noxtls_debug_printf((const uint8_t *)"Process here the current block\n");
    }
    
    rc = noxtls_sha512_round(ctx, temp);
    
    if (space_left < ((uint32_t)length_size + 1U))
    {
        noxtls_secure_zero((temp), (size_t)(block_size));
        if (space_left == 0U) {
            /* not previously set */
            data[0] = SHA512_PAD_BYTE;
        }
        
        (void)noxtls_add_padding_length(temp, block_size, total_length, length_size);
            
        if (sha512_debug_lvl > 0U) {
            for (i = 0U; i < block_size; i += 1U) {
                (void)noxtls_debug_printf((const uint8_t *)"%02x", temp[i]);
            }
            (void)noxtls_debug_printf((const uint8_t *)"\n");
            (void)noxtls_debug_printf((const uint8_t *)"Process additional block since could not fit padding\n");
        }
        
        rc = noxtls_sha512_round(ctx, temp);
        
    }
    
    uint8_t digest_len = (uint8_t)(HASH_SHA512_OUT_LEN);
    if (ctx->algo == NOXTLS_HASH_SHA_384) {
        digest_len = 48U;
    } else if (ctx->algo == NOXTLS_HASH_SHA_512_224) {
        digest_len = (uint8_t)HASH_SHA512_224_OUT_LEN;
    } else if (ctx->algo == NOXTLS_HASH_SHA_512_256) {
        digest_len = (uint8_t)HASH_SHA512_256_OUT_LEN;
    }
     else {
         /* MISRA 15.7: no remaining alternative */
     }
    for (i = 0U; i < digest_len; i += 1U)
    {
        uint8_t word_idx = (uint8_t)(i / SHA512_WORD_BYTES);
        uint8_t byte_in_word = (uint8_t)(i % SHA512_WORD_BYTES);
        uint64_t w = ctx->h[word_idx];
        uint8_t b = 0U;

        if (sha512_debug_lvl > 0U) {
            (void)noxtls_debug_printf((const uint8_t *)"ctx[%u] = %08llx\n", word_idx, ctx->h[word_idx]);
        }

        switch(byte_in_word) {
        case 0U: b = (uint8_t)(w >> 56U); break;
        case 1U: b = (uint8_t)(w >> 48U); break;
        case 2U: b = (uint8_t)(w >> 40U); break;
        case 3U: b = (uint8_t)(w >> 32U); break;
        case 4U: b = (uint8_t)(w >> 24U); break;
        case 5U: b = (uint8_t)(w >> 16U); break;
        case 6U: b = (uint8_t)(w >> 8U); break;
        default: b = (uint8_t)w; break;
        }
        hash[i] = b;
    }

	return rc;
}

/**
 * @brief Finish SHA-512 operation
 * 
 * @details this function must be called 
 * 
 *
 * @param[in] data is the HCI controller sink
 * @param[in] zero_pad is the Host Callback
 * @param[in] len is the BT HCI Callback
 *
 * @return NOXTLS_RETURN_SUCCESS on success, noxtls_return_t otherwise
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t noxtls_sha512_pad(const uint8_t * data, uint32_t zero_pad, uint32_t len)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    (void)data;
    (void)zero_pad;
    (void)len;
    
    

    return rc;
}

/**
 * @brief Verify SHA-512
 * 
 * @param data Data to verify
 * @param len Length of data to verify
 * @param expected Expected hash
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_FAILED if verification fails
 */
noxtls_return_t noxtls_sha512_verify(const uint8_t * data, uint32_t len, const uint8_t * expected)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    uint8_t hash[HASH_SHA512_OUT_LEN] = {0};
    noxtls_sha512_ctx_t ctx;
    
    (void)noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512);
    (void)noxtls_sha512_update(&ctx, data, len);
    (void)noxtls_sha512_finish(&ctx, hash);
    
    if (noxtls_ct_equal(hash, expected, sizeof(hash)) != 0) {
        rc = NOXTLS_RETURN_SUCCESS;
    }

    return rc;
}

#endif /* NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512 */
