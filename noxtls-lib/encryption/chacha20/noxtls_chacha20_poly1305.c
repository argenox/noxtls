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
* File:    noxtls_chacha20_poly1305.c
* Summary: ChaCha20-Poly1305 Authenticated Encryption Implementation
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */

#include <stdint.h>
#include <string.h>
#include "common/noxtls_ct.h"
#include "common/noxtls_debug_printf.h"
#include "noxtls_chacha20_poly1305.h"

#if NOXTLS_FEATURE_CHACHA20_POLY1305

#if NOXTLS_CHACHA20_POLY1305_DEBUG
#define NOXTLS_CHACHA20_POLY1305_DEBUG_PRINT(fmt, ...) (void)noxtls_debug_printf((const uint8_t *)"[CHACHA20_POLY1305_DEBUG] " fmt, ##__VA_ARGS__)
#else
#define NOXTLS_CHACHA20_POLY1305_DEBUG_PRINT(fmt, ...) ((void)0)
#endif

/* Poly1305 modulus: 2^130 - 5 */
#define POLY1305_P ((uint64_t)0x3FFFFFFFFFFFFFFFULL)

/**
 * @brief Load the 32-bit little-endian value
 * 
 * @param[in] p The pointer to the value to load.
 * @return The loaded value.
 */
static uint32_t poly1305_load_le32(const uint8_t *p)
{
    return ((uint32_t)p[0])
         | (((uint32_t)p[1]) << 8U)
         | (((uint32_t)p[2]) << 16U)
         | (((uint32_t)p[3]) << 24U);
}

/**
 * @brief Initialize Poly1305 context from a 32-byte one-time key (RFC 8439: r || pad).
 * @param[out] ctx Poly1305 state to reset and fill; must not be NULL.
 * @param[in]  key 32-byte secret (`r` in little-endian clamped form in first 16 bytes, `s` pad in last 16).
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` if @p ctx or @p key is NULL.
 */
noxtls_return_t noxtls_poly1305_init(noxtls_poly1305_context_t *ctx, const uint8_t *key)
{
    if ((ctx == NULL) || (key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    /* Keep field prime symbol referenced (26-bit limb form uses equivalent reductions). */
    (void)POLY1305_P;

    ctx->r[0] = (poly1305_load_le32(&key[0])) & 0x3ffffffU;
    ctx->r[1] = ((poly1305_load_le32(&key[3]) >> 2U) & 0x3ffff03U);
    ctx->r[2] = ((poly1305_load_le32(&key[6]) >> 4U) & 0x3ffc0ffU);
    ctx->r[3] = ((poly1305_load_le32(&key[9]) >> 6U) & 0x3f03fffU);
    ctx->r[4] = ((poly1305_load_le32(&key[12]) >> 8U) & 0x00fffffU);

    /* Extract s (pad) from second half of key (RFC 8439: r || s) */
    ctx->pad[0] = poly1305_load_le32(&key[POLY1305_TAG_SIZE]);
    ctx->pad[1] = poly1305_load_le32(&key[POLY1305_TAG_SIZE + 4U]);
    ctx->pad[2] = poly1305_load_le32(&key[POLY1305_TAG_SIZE + 8U]);
    ctx->pad[3] = poly1305_load_le32(&key[POLY1305_TAG_SIZE + 12U]);

    noxtls_secure_zero((ctx->h), sizeof(ctx->h));
    ctx->buffer_len = 0U;
    ctx->finished = 0U;
    noxtls_secure_zero((ctx->buffer), sizeof(ctx->buffer));

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Process a block in Poly1305
 * @param ctx Poly1305 context
 * @param block Block data (at least block_len bytes)
 * @param block_len Number of bytes in block (1-16). For full block adds 2^128; for partial adds 2^(8*block_len).
 */
static void poly1305_blocks(noxtls_poly1305_context_t *ctx, const uint8_t *block, uint32_t bytes)
{
    const uint32_t hibit = (uint32_t)((ctx->finished != 0U) ? 0U : ((uint32_t)1U << 24U));
    uint32_t r0 = (uint32_t)(ctx->r[0U]);
    uint32_t r1 = (uint32_t)(ctx->r[1U]);
    uint32_t r2 = (uint32_t)(ctx->r[2U]);
    uint32_t r3 = (uint32_t)(ctx->r[3U]);
    uint32_t r4 = (uint32_t)(ctx->r[4U]);
    uint32_t s1 = (uint32_t)(r1 * 5U);
    uint32_t s2 = (uint32_t)(r2 * 5U);
    uint32_t s3 = (uint32_t)(r3 * 5U);
    uint32_t s4 = (uint32_t)(r4 * 5U);
    uint32_t h0 = (uint32_t)(ctx->h[0U]);
    uint32_t h1 = (uint32_t)(ctx->h[1U]);
    uint32_t h2 = (uint32_t)(ctx->h[2U]);
    uint32_t h3 = (uint32_t)(ctx->h[3U]);
    uint32_t h4 = (uint32_t)(ctx->h[4U]);
    uint32_t offset = 0U;
    uint32_t remaining = bytes;

    while (remaining >= (uint32_t)POLY1305_BLOCK_SIZE) {
        h0 += (poly1305_load_le32(&block[offset + 0U])) & 0x3ffffffU;
        h1 += ((poly1305_load_le32(&block[offset + 3U]) >> 2U) & 0x3ffffffU);
        h2 += ((poly1305_load_le32(&block[offset + 6U]) >> 4U) & 0x3ffffffU);
        h3 += ((poly1305_load_le32(&block[offset + 9U]) >> 6U) & 0x3ffffffU);
        h4 += ((poly1305_load_le32(&block[offset + 12U]) >> 8U) | hibit);

        {
            uint64_t d0 = ((uint64_t)h0 * (uint64_t)r0) + ((uint64_t)h1 * (uint64_t)s4)
                        + ((uint64_t)h2 * (uint64_t)s3) + ((uint64_t)h3 * (uint64_t)s2)
                        + ((uint64_t)h4 * (uint64_t)s1);
            uint64_t d1 = ((uint64_t)h0 * (uint64_t)r1) + ((uint64_t)h1 * (uint64_t)r0)
                        + ((uint64_t)h2 * (uint64_t)s4) + ((uint64_t)h3 * (uint64_t)s3)
                        + ((uint64_t)h4 * (uint64_t)s2);
            uint64_t d2 = ((uint64_t)h0 * (uint64_t)r2) + ((uint64_t)h1 * (uint64_t)r1)
                        + ((uint64_t)h2 * (uint64_t)r0) + ((uint64_t)h3 * (uint64_t)s4)
                        + ((uint64_t)h4 * (uint64_t)s3);
            uint64_t d3 = ((uint64_t)h0 * (uint64_t)r3) + ((uint64_t)h1 * (uint64_t)r2)
                        + ((uint64_t)h2 * (uint64_t)r1) + ((uint64_t)h3 * (uint64_t)r0)
                        + ((uint64_t)h4 * (uint64_t)s4);
            uint64_t d4 = ((uint64_t)h0 * (uint64_t)r4) + ((uint64_t)h1 * (uint64_t)r3)
                        + ((uint64_t)h2 * (uint64_t)r2) + ((uint64_t)h3 * (uint64_t)r1)
                        + ((uint64_t)h4 * (uint64_t)r0);
            uint32_t c = 0U;

            c = (uint32_t)(d0 >> 26U);
            h0 = ((uint32_t)d0) & 0x3ffffffU;
            d1 += (uint64_t)c;
            c = (uint32_t)(d1 >> 26U);
            h1 = ((uint32_t)d1) & 0x3ffffffU;
            d2 += (uint64_t)c;
            c = (uint32_t)(d2 >> 26U);
            h2 = ((uint32_t)d2) & 0x3ffffffU;
            d3 += (uint64_t)c;
            c = (uint32_t)(d3 >> 26U);
            h3 = ((uint32_t)d3) & 0x3ffffffU;
            d4 += (uint64_t)c;
            c = (uint32_t)(d4 >> 26U);
            h4 = ((uint32_t)d4) & 0x3ffffffU;
            h0 += (c * 5U);
            c = (uint32_t)h0 >> 26U;
            h0 &= 0x3ffffffU;
            h1 += c;
        }

        offset += (uint32_t)POLY1305_BLOCK_SIZE;
        remaining -= (uint32_t)POLY1305_BLOCK_SIZE;
    }

    ctx->h[0] = h0;
    ctx->h[1] = h1;
    ctx->h[2] = h2;
    ctx->h[3] = h3;
    ctx->h[4] = h4;
}

/**
 * @brief Absorb more noxtls_message bytes into the running Poly1305 MAC (after @ref noxtls_poly1305_init).
 * @param[in,out] ctx Initialized Poly1305 context; must not be NULL.
 * @param[in]     data Next fragment of the noxtls_message; may be NULL only when @p data_len is 0.
 * @param[in]     data_len Number of bytes at @p data to include in the MAC.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` if @p ctx is NULL or @p data is NULL with non-zero @p data_len.
 */
noxtls_return_t noxtls_poly1305_update(noxtls_poly1305_context_t *ctx, const uint8_t *data, uint32_t data_len)
{
    uint32_t data_off = 0U;
    uint32_t in_left = data_len;

    if ((ctx == NULL) || ((data == NULL) && (in_left > 0U))){
        return NOXTLS_RETURN_NULL;
    }

    if (in_left == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }

    /* Process any buffered data first */
    if (ctx->buffer_len > 0U) {
        uint32_t bytes_to_process = (uint32_t)POLY1305_BLOCK_SIZE - ctx->buffer_len;
        if (bytes_to_process > in_left) {
            bytes_to_process = in_left;
        }

        noxtls_copy_u8(&ctx->buffer[ctx->buffer_len], (size_t)((uint32_t)POLY1305_BLOCK_SIZE - ctx->buffer_len), &data[data_off], (size_t)bytes_to_process);
        ctx->buffer_len += bytes_to_process;
        data_off += bytes_to_process;
        in_left -= bytes_to_process;

        if (ctx->buffer_len < (uint32_t)POLY1305_BLOCK_SIZE) {
            return NOXTLS_RETURN_SUCCESS;
        }

        poly1305_blocks(ctx, ctx->buffer, (uint32_t)POLY1305_BLOCK_SIZE);
        ctx->buffer_len = 0U;
    }

    /* Process full blocks */
    if (in_left >= (uint32_t)POLY1305_BLOCK_SIZE) {
        uint32_t block_bytes = (uint32_t)(in_left & (uint32_t)~((uint32_t)POLY1305_BLOCK_SIZE - 1U));
        poly1305_blocks(ctx, &data[data_off], block_bytes);
        data_off += block_bytes;
        in_left -= block_bytes;
    }

    /* Buffer remaining bytes */
    if (in_left > 0U) {
        noxtls_copy_u8(ctx->buffer, (size_t)POLY1305_BLOCK_SIZE, &data[data_off], (size_t)in_left);
        ctx->buffer_len = in_left;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Finalize Poly1305 after @ref noxtls_poly1305_update: processes any buffered bytes, reduces mod p, and writes the 128-bit tag.
 * @param[in,out] ctx Initialized and updated context; internal buffer and state are used and modified.
 * @param[out]    tag Output buffer for `POLY1305_TAG_SIZE` MAC bytes; must not be NULL.
 * @return `NOXTLS_RETURN_SUCCESS` when @p tag is written; `NOXTLS_RETURN_NULL` if @p ctx or @p tag is NULL.
 */
noxtls_return_t noxtls_poly1305_final(noxtls_poly1305_context_t *ctx, uint8_t *tag)
{
    uint32_t h0 = 0U;
    uint32_t h1 = 0U;
    uint32_t h2 = 0U;
    uint32_t h3 = 0U;
    uint32_t h4 = 0U;
    uint32_t g0 = 0U;
    uint32_t g1 = 0U;
    uint32_t g2 = 0U;
    uint32_t g3 = 0U;
    uint32_t g4 = 0U;
    uint32_t c = 0U;
    
    if ((ctx == NULL) || (tag == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Process final partial block if any */
    if (ctx->buffer_len > 0U) {
        ctx->buffer[ctx->buffer_len] = 1U;
        noxtls_secure_zero((&ctx->buffer[ctx->buffer_len + 1U]), (size_t)((uint32_t)POLY1305_BLOCK_SIZE - ctx->buffer_len - 1U));
        ctx->finished = 1U;
        poly1305_blocks(ctx, ctx->buffer, (uint32_t)POLY1305_BLOCK_SIZE);
    }

    /* Fully carry-propagate h */
    h0 = ctx->h[0];
    h1 = ctx->h[1];
    h2 = ctx->h[2];
    h3 = ctx->h[3];
    h4 = ctx->h[4];

    c = (uint32_t)h1 >> 26U; h1 &= 0x3ffffffU; h2 += c;
    c = (uint32_t)h2 >> 26U; h2 &= 0x3ffffffU; h3 += c;
    c = (uint32_t)h3 >> 26U; h3 &= 0x3ffffffU; h4 += c;
    c = (uint32_t)h4 >> 26U; h4 &= 0x3ffffffU; h0 += (c * 5U);
    c = (uint32_t)h0 >> 26U; h0 &= 0x3ffffffU; h1 += c;

    /* Compute h + -p */
    g0 = h0 + 5U; c = (uint32_t)g0 >> 26U; g0 &= 0x3ffffffU;
    g1 = h1 + c; c = (uint32_t)g1 >> 26U; g1 &= 0x3ffffffU;
    g2 = h2 + c; c = (uint32_t)g2 >> 26U; g2 &= 0x3ffffffU;
    g3 = h3 + c; c = (uint32_t)g3 >> 26U; g3 &= 0x3ffffffU;
    g4 = (h4 + c) - ((uint32_t)1U << 26U);

    /* Select h if h < p, or h + -p if h >= p */
    {
        uint32_t mask = (uint32_t)((g4 >> 31U) - 1U);
        g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
        mask = ~mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;
    }

    /* h = h % (2^128) */
    h0 = (h0 | (h1 << 26U)) & 0xFFFFFFFFU;
    h1 = ((h1 >> 6U) | (h2 << 20U)) & 0xFFFFFFFFU;
    h2 = ((h2 >> 12U) | (h3 << 14U)) & 0xFFFFFFFFU;
    h3 = ((h3 >> 18U) | (h4 << 8U)) & 0xFFFFFFFFU;

    /* mac = (h + pad) % (2^128) */
    {
        uint64_t f = 0U;
        f = (uint64_t)h0 + (uint64_t)ctx->pad[0];
        h0 = (uint32_t)f;
        f = (uint64_t)h1 + (uint64_t)ctx->pad[1] + (f >> 32U);
        h1 = (uint32_t)f;
        f = (uint64_t)h2 + (uint64_t)ctx->pad[2] + (f >> 32U);
        h2 = (uint32_t)f;
        f = (uint64_t)h3 + (uint64_t)ctx->pad[3] + (f >> 32U);
        h3 = (uint32_t)f;
    }

    tag[0] = (uint8_t)h0; tag[1] = (uint8_t)(h0 >> 8U); tag[2] = (uint8_t)(h0 >> 16U); tag[3] = (uint8_t)(h0 >> 24U);
    tag[4] = (uint8_t)h1; tag[5] = (uint8_t)(h1 >> 8U); tag[6] = (uint8_t)(h1 >> 16U); tag[7] = (uint8_t)(h1 >> 24U);
    tag[8] = (uint8_t)h2; tag[9] = (uint8_t)(h2 >> 8U); tag[10] = (uint8_t)(h2 >> 16U); tag[11] = (uint8_t)(h2 >> 24U);
    tag[12] = (uint8_t)h3; tag[13] = (uint8_t)(h3 >> 8U); tag[14] = (uint8_t)(h3 >> 16U); tag[15] = (uint8_t)(h3 >> 24U);

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief One-shot Poly1305 MAC: @ref noxtls_poly1305_init, @ref noxtls_poly1305_update, @ref noxtls_poly1305_final on a stack context.
 * @param[in]  key 32-byte one-time Poly1305 key (`r || s`, same layout as @ref noxtls_poly1305_init).
 * @param[in]  data Message bytes to authenticate; may be NULL only if @p data_len is 0.
 * @param[in]  data_len Length of @p data in bytes.
 * @param[out] tag 16-byte MAC output; must not be NULL.
 * @return `NOXTLS_RETURN_SUCCESS` when @p tag is written; `NOXTLS_RETURN_NULL` for invalid arguments; `NOXTLS_RETURN_FAILED` if an internal step fails.
 */
noxtls_return_t noxtls_poly1305_mac(const uint8_t *key, const uint8_t *data, uint32_t data_len, uint8_t *tag)
{
    noxtls_poly1305_context_t ctx;
    
    if ((key == NULL) || ((data == NULL) && (data_len > 0U)) || (tag == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    
    if (noxtls_poly1305_init(&ctx, key) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    
    if (noxtls_poly1305_update(&ctx, data, data_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    
    return noxtls_poly1305_final(&ctx, tag);
}

/**
 * @brief Derives the 32-byte Poly1305 one-time key from the first ChaCha20 block (RFC 8439, counter 0).
 * @param[in]  key 256-bit ChaCha20 key; must not be NULL.
 * @param[in]  nonce 96-bit (12-byte) nonce as in RFC 8439; must not be NULL.
 * @param[out] poly_key Output buffer for 32 bytes (`r || s` for @ref noxtls_poly1305_init); must not be NULL.
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` if `noxtls_chacha20_init` or `noxtls_chacha20_process` fails.
 */
static noxtls_return_t chacha20_poly1305_generate_key(const uint8_t *key, 
                                           const uint8_t *nonce, 
                                           uint8_t *poly_key)
{
    const uint8_t zero_block[64] = {0};
    uint8_t key_block[64] = {0};
    noxtls_chacha20_context_t ctx;
    
    /* Generate one block of ChaCha20 keystream with counter=0 */
    if (noxtls_chacha20_init(&ctx, key, nonce, 0) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_NULL;
    }
    
    if (noxtls_chacha20_process(&ctx, zero_block, key_block, 64) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_NULL;
    }

    /* Per RFC 8439, use first 32 bytes as Poly1305 key */
    noxtls_copy_u8(poly_key, (size_t)POLY1305_KEY_SIZE, key_block, (size_t)POLY1305_KEY_SIZE);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief RFC 8439 ChaCha20-Poly1305 AEAD: encrypts plaintext and writes a 128-bit authentication tag.
 * @param[in]  key 256-bit (32-byte) ChaCha20 key.
 * @param[in]  nonce 96-bit (12-byte) nonce.
 * @param[in]  aad Optional additional authenticated data; may be NULL if @p aad_len is 0.
 * @param[in]  aad_len Length of @p aad in bytes.
 * @param[in]  plaintext Cleartext to encrypt; may be NULL if @p plaintext_len is 0.
 * @param[in]  plaintext_len Length of @p plaintext in bytes.
 * @param[out] ciphertext Encrypted output; must hold at least @p plaintext_len bytes when @p plaintext_len is non-zero.
 * @param[out] tag Authentication tag (`POLY1305_TAG_SIZE` bytes).
 * @return `NOXTLS_RETURN_SUCCESS` on success; `NOXTLS_RETURN_NULL` on invalid arguments or internal failure.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
noxtls_return_t noxtls_chacha20_poly1305_encrypt(const uint8_t *key,
                               const uint8_t *nonce,
                               const uint8_t *aad,
                               uint32_t aad_len,
                               const uint8_t *plaintext,
                               uint32_t plaintext_len,
                               uint8_t *ciphertext,
                               uint8_t *tag)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint8_t poly_key[POLY1305_KEY_SIZE];
    noxtls_poly1305_context_t poly_ctx;
    uint8_t length_block[POLY1305_BLOCK_SIZE];
    
    if ((key == NULL) || (nonce == NULL) || (tag == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    /* A non-zero AAD length with no AAD buffer must not be silently
     * authenticated as an empty/zero-padded AAD. */
    if ((aad == NULL) && (aad_len > 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    
    if ((plaintext == NULL) && (plaintext_len > 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    if ((ciphertext == NULL) && (plaintext_len > 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Generate Poly1305 key from ChaCha20 */
    if (chacha20_poly1305_generate_key(key, nonce, poly_key) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Encrypt plaintext using ChaCha20 (counter starts at 1, not 0) */
    if (plaintext_len > 0U) {
        if (noxtls_chacha20_encrypt(key, nonce, 1, plaintext, plaintext_len, ciphertext) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_NULL;
        }
    }
    
    /* Initialize Poly1305 */
    if (noxtls_poly1305_init(&poly_ctx, poly_key) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Authenticate AAD */
    if ((aad_len > 0U) && (aad != NULL)) {
        if (noxtls_poly1305_update(&poly_ctx, aad, aad_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_NULL;
        }
    }
    /* Pad AAD to 16-byte boundary */
    if ((aad_len & (POLY1305_BLOCK_SIZE - 1U)) != 0U) {
        const uint8_t pad[POLY1305_BLOCK_SIZE] = {0};
        uint32_t pad_len = (uint32_t)(POLY1305_BLOCK_SIZE - (aad_len & (POLY1305_BLOCK_SIZE - 1U)));
        if (noxtls_poly1305_update(&poly_ctx, pad, pad_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_NULL;
        }
    }
    
    /* Authenticate ciphertext */
    if (plaintext_len > 0U) {
        if (noxtls_poly1305_update(&poly_ctx, ciphertext, plaintext_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_NULL;
        }
    }
    /* Pad ciphertext to 16-byte boundary */
    if ((plaintext_len & (POLY1305_BLOCK_SIZE - 1U)) != 0U) {
        const uint8_t pad[POLY1305_BLOCK_SIZE] = {0};
        uint32_t pad_len = (uint32_t)(POLY1305_BLOCK_SIZE - (plaintext_len & (POLY1305_BLOCK_SIZE - 1U)));
        if (noxtls_poly1305_update(&poly_ctx, pad, pad_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_NULL;
        }
    }
    
    /* Authenticate lengths: AAD length (64 bits) + ciphertext length (64 bits) */
    noxtls_secure_zero((length_block), (size_t)POLY1305_BLOCK_SIZE);
    {
        uint64_t aad_len64 = (uint64_t)aad_len;
        uint64_t text_len64 = (uint64_t)plaintext_len;
        length_block[0] = (uint8_t)aad_len64;
        length_block[1] = (uint8_t)(aad_len64 >> 8U);
        length_block[2] = (uint8_t)(aad_len64 >> 16U);
        length_block[3] = (uint8_t)(aad_len64 >> 24U);
        length_block[4] = (uint8_t)(aad_len64 >> 32U);
        length_block[5] = (uint8_t)(aad_len64 >> 40U);
        length_block[6] = (uint8_t)(aad_len64 >> 48U);
        length_block[7] = (uint8_t)(aad_len64 >> 56U);
        length_block[8] = (uint8_t)text_len64;
        length_block[9] = (uint8_t)(text_len64 >> 8U);
        length_block[10] = (uint8_t)(text_len64 >> 16U);
        length_block[11] = (uint8_t)(text_len64 >> 24U);
        length_block[12] = (uint8_t)(text_len64 >> 32U);
        length_block[13] = (uint8_t)(text_len64 >> 40U);
        length_block[14] = (uint8_t)(text_len64 >> 48U);
        length_block[15] = (uint8_t)(text_len64 >> 56U);
    }
    
    if (noxtls_poly1305_update(&poly_ctx, length_block, POLY1305_BLOCK_SIZE) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Generate tag */
    if (noxtls_poly1305_final(&poly_ctx, tag) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_NULL;
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief RFC 8439 ChaCha20-Poly1305 AEAD: verifies the tag over AAD and ciphertext, then decrypts if valid.
 * @param[in]  key 256-bit (32-byte) ChaCha20 key (same as used for encryption).
 * @param[in]  nonce 96-bit (12-byte) nonce.
 * @param[in]  aad Additional authenticated data; may be NULL if @p aad_len is 0 (must match encryption).
 * @param[in]  aad_len Length of @p aad in bytes.
 * @param[in]  ciphertext Encrypted payload; may be NULL if @p ciphertext_len is 0.
 * @param[in]  ciphertext_len Length of @p ciphertext in bytes.
 * @param[in]  tag Authentication tag to verify (`POLY1305_TAG_SIZE` bytes).
 * @param[out] plaintext Cleartext output; must hold at least @p ciphertext_len bytes when @p ciphertext_len is non-zero.
 * @return `NOXTLS_RETURN_SUCCESS` if the tag verifies and decryption succeeds; `NOXTLS_RETURN_BAD_DATA` if authentication fails; `NOXTLS_RETURN_NULL` on invalid arguments or internal failure.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
noxtls_return_t noxtls_chacha20_poly1305_decrypt(const uint8_t *key,
                               const uint8_t *nonce,
                               const uint8_t *aad,
                               uint32_t aad_len,
                               const uint8_t *ciphertext,
                               uint32_t ciphertext_len,
                               const uint8_t *tag,
                               uint8_t *plaintext)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint8_t poly_key[POLY1305_KEY_SIZE];
    noxtls_poly1305_context_t poly_ctx;
    uint8_t computed_tag[POLY1305_TAG_SIZE];
    uint8_t length_block[POLY1305_BLOCK_SIZE];
    int tag_match = 0;
    
    if ((key == NULL) || (nonce == NULL) || (tag == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    /* A non-zero AAD length with no AAD buffer must not be silently
     * authenticated as an empty/zero-padded AAD. */
    if ((aad == NULL) && (aad_len > 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    
    if (((ciphertext == NULL) && (ciphertext_len > 0U)) || ((plaintext == NULL) && (ciphertext_len > 0U))) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Generate Poly1305 key from ChaCha20 */
    if (chacha20_poly1305_generate_key(key, nonce, poly_key) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Initialize Poly1305 */
    if (noxtls_poly1305_init(&poly_ctx, poly_key) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Authenticate AAD */
    if ((aad_len > 0U) && (aad != NULL)) {
        if (noxtls_poly1305_update(&poly_ctx, aad, aad_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_NULL;
        }
    }
    /* Pad AAD to 16-byte boundary */
    if ((aad_len & (POLY1305_BLOCK_SIZE - 1U)) != 0U) {
        const uint8_t pad[POLY1305_BLOCK_SIZE] = {0};
        uint32_t pad_len = (uint32_t)(POLY1305_BLOCK_SIZE - (aad_len & (POLY1305_BLOCK_SIZE - 1U)));
        if (noxtls_poly1305_update(&poly_ctx, pad, pad_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_NULL;
        }
    }
    
    /* Authenticate ciphertext */
    if ((ciphertext_len > 0U) && (ciphertext != NULL)) {
        if (noxtls_poly1305_update(&poly_ctx, ciphertext, ciphertext_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_NULL;
        }
    }
    /* Pad ciphertext to 16-byte boundary */
    if ((ciphertext_len & (POLY1305_BLOCK_SIZE - 1U)) != 0U) {
        const uint8_t pad[POLY1305_BLOCK_SIZE] = {0};
        uint32_t pad_len = (uint32_t)(POLY1305_BLOCK_SIZE - (ciphertext_len & (POLY1305_BLOCK_SIZE - 1U)));
        if (noxtls_poly1305_update(&poly_ctx, pad, pad_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_NULL;
        }
    }
    
    /* Authenticate lengths */
    noxtls_secure_zero((length_block), (size_t)POLY1305_BLOCK_SIZE);
    {
        uint64_t aad_len64 = (uint64_t)aad_len;
        uint64_t text_len64 = (uint64_t)ciphertext_len;
        length_block[0] = (uint8_t)aad_len64;
        length_block[1] = (uint8_t)(aad_len64 >> 8U);
        length_block[2] = (uint8_t)(aad_len64 >> 16U);
        length_block[3] = (uint8_t)(aad_len64 >> 24U);
        length_block[4] = (uint8_t)(aad_len64 >> 32U);
        length_block[5] = (uint8_t)(aad_len64 >> 40U);
        length_block[6] = (uint8_t)(aad_len64 >> 48U);
        length_block[7] = (uint8_t)(aad_len64 >> 56U);
        length_block[8] = (uint8_t)text_len64;
        length_block[9] = (uint8_t)(text_len64 >> 8U);
        length_block[10] = (uint8_t)(text_len64 >> 16U);
        length_block[11] = (uint8_t)(text_len64 >> 24U);
        length_block[12] = (uint8_t)(text_len64 >> 32U);
        length_block[13] = (uint8_t)(text_len64 >> 40U);
        length_block[14] = (uint8_t)(text_len64 >> 48U);
        length_block[15] = (uint8_t)(text_len64 >> 56U);
    }
    
    if (noxtls_poly1305_update(&poly_ctx, length_block, POLY1305_BLOCK_SIZE) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Generate tag */
    if (noxtls_poly1305_final(&poly_ctx, computed_tag) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Verify tag (constant-time comparison) */
    tag_match = (noxtls_ct_memcmp(computed_tag, tag, (size_t)POLY1305_TAG_SIZE) == 0) ? 1 : 0;
    noxtls_secure_zero(computed_tag, sizeof(computed_tag));
    
    if (tag_match == 0) {
        /* Authentication failed - don't decrypt */
        return NOXTLS_RETURN_BAD_DATA;
    }
    
    /* Decrypt ciphertext using ChaCha20 (counter starts at 1, not 0) */
    if (ciphertext_len > 0U) {
        if (noxtls_chacha20_decrypt(key, nonce, 1, ciphertext, ciphertext_len, plaintext) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_NULL;
        }
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Self-test function
 * 
 * Tests against known test vectors from RFC 8439
 */
noxtls_return_t noxtls_chacha20_poly1305_self_test(void)
{
    /* Test vectors from RFC 8439 Section 2.8.2 */
    const uint8_t test_key[POLY1305_KEY_SIZE] = {
        0x80U, 0x81U, 0x82U, 0x83U, 0x84U, 0x85U, 0x86U, 0x87U,
        0x88U, 0x89U, 0x8aU, 0x8bU, 0x8cU, 0x8dU, 0x8eU, 0x8fU,
        0x90U, 0x91U, 0x92U, 0x93U, 0x94U, 0x95U, 0x96U, 0x97U,
        0x98U, 0x99U, 0x9aU, 0x9bU, 0x9cU, 0x9dU, 0x9eU, 0x9fU
    };
    
    const uint8_t test_nonce[12] = {
        0x07U, 0x00U, 0x00U, 0x00U, 0x40U, 0x41U, 0x42U, 0x43U,
        0x44U, 0x45U, 0x46U, 0x47U
    };
    
    const uint8_t test_aad[12] = {
        0x50U, 0x51U, 0x52U, 0x53U, 0xc0U, 0xc1U, 0xc2U, 0xc3U,
        0xc4U, 0xc5U, 0xc6U, 0xc7U
    };
    
    const uint8_t test_plaintext[114] = {
        0x4cU, 0x61U, 0x64U, 0x69U, 0x65U, 0x73U, 0x20U, 0x61U,
        0x6eU, 0x64U, 0x20U, 0x47U, 0x65U, 0x6eU, 0x74U, 0x6cU,
        0x65U, 0x6dU, 0x65U, 0x6eU, 0x20U, 0x6fU, 0x66U, 0x20U,
        0x74U, 0x68U, 0x65U, 0x20U, 0x63U, 0x6cU, 0x61U, 0x73U,
        0x73U, 0x20U, 0x6fU, 0x66U, 0x20U, 0x27U, 0x39U, 0x39U,
        0x3aU, 0x20U, 0x49U, 0x66U, 0x20U, 0x49U, 0x20U, 0x63U,
        0x6fU, 0x75U, 0x6cU, 0x64U, 0x20U, 0x6fU, 0x66U, 0x66U,
        0x65U, 0x72U, 0x20U, 0x79U, 0x6fU, 0x75U, 0x20U, 0x6fU,
        0x6eU, 0x6cU, 0x79U, 0x20U, 0x6fU, 0x6eU, 0x65U, 0x20U,
        0x74U, 0x69U, 0x70U, 0x20U, 0x66U, 0x6fU, 0x72U, 0x20U,
        0x74U, 0x68U, 0x65U, 0x20U, 0x66U, 0x75U, 0x74U, 0x75U,
        0x72U, 0x65U, 0x2cU, 0x20U, 0x73U, 0x75U, 0x6eU, 0x73U,
        0x63U, 0x72U, 0x65U, 0x65U, 0x6eU, 0x20U, 0x77U, 0x6fU,
        0x75U, 0x6cU, 0x64U, 0x20U, 0x62U, 0x65U, 0x20U, 0x69U,
        0x74U, 0x2eU
    };
    
    const uint8_t expected_ciphertext[114] = {
        0xd3U, 0x1aU, 0x8dU, 0x34U, 0x64U, 0x8eU, 0x60U, 0xdbU,
        0x7bU, 0x86U, 0xafU, 0xbcU, 0x53U, 0xefU, 0x7eU, 0xc2U,
        0xa4U, 0xadU, 0xedU, 0x51U, 0x29U, 0x6eU, 0x08U, 0xfeU,
        0xa9U, 0xe2U, 0xb5U, 0xa7U, 0x36U, 0xeeU, 0x62U, 0xd6U,
        0x3dU, 0xbeU, 0xa4U, 0x5eU, 0x8cU, 0xa9U, 0x67U, 0x12U,
        0x82U, 0xfaU, 0xfbU, 0x69U, 0xdaU, 0x92U, 0x72U, 0x8bU,
        0x1aU, 0x71U, 0xdeU, 0x0aU, 0x9eU, 0x06U, 0x0bU, 0x29U,
        0x05U, 0xd6U, 0xa5U, 0xb6U, 0x7eU, 0xcdU, 0x3bU, 0x36U,
        0x92U, 0xddU, 0xbdU, 0x7fU, 0x2dU, 0x77U, 0x8bU, 0x8cU,
        0x98U, 0x03U, 0xaeU, 0xe3U, 0x28U, 0x09U, 0x1bU, 0x58U,
        0xfaU, 0xb3U, 0x24U, 0xe4U, 0xfaU, 0xd6U, 0x75U, 0x94U,
        0x55U, 0x85U, 0x80U, 0x8bU, 0x48U, 0x31U, 0xd7U, 0xbcU,
        0x3fU, 0xf4U, 0xdeU, 0xf0U, 0x8eU, 0x4bU, 0x7aU, 0x9dU,
        0xe5U, 0x76U, 0xd2U, 0x65U, 0x86U, 0xceU, 0xc6U, 0x4bU,
        0x61U, 0x16U
    };
    
    const uint8_t expected_tag[POLY1305_TAG_SIZE] = {
        0x1aU, 0xe1U, 0x0bU, 0x59U, 0x4fU, 0x09U, 0xe2U, 0x6aU,
        0x7eU, 0x90U, 0x2eU, 0xcbU, 0xd0U, 0x60U, 0x06U, 0x91U
    };
    
    uint8_t ciphertext[114];
    uint8_t tag[POLY1305_TAG_SIZE];
    uint8_t decrypted[114];
    uint32_t i = 0U;
    
    NOXTLS_CHACHA20_POLY1305_DEBUG_PRINT("Running ChaCha20-Poly1305 self-test...\n");
    
    /* Test encryption */
    if (noxtls_chacha20_poly1305_encrypt(test_key, test_nonce, test_aad, 12,
                                  test_plaintext, 114, ciphertext, tag) != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_debug_printf((const uint8_t *)"ChaCha20-Poly1305 self-test FAILED: Encryption failed\n");
        return NOXTLS_RETURN_NULL;
    }
    
    /* Verify ciphertext */
    for (i = 0U; i < 114U; i += 1U) {
        if (ciphertext[i] != expected_ciphertext[i]) {
            (void)noxtls_debug_printf((const uint8_t *)"ChaCha20-Poly1305 self-test FAILED: Ciphertext mismatch at byte %u\n", i);
            (void)noxtls_debug_printf((const uint8_t *)"  Expected: 0x%02x, Got: 0x%02x\n", expected_ciphertext[i], ciphertext[i]);
            return NOXTLS_RETURN_NULL;
        }
    }
    
    /* Verify tag */
    for (i = 0U; i < POLY1305_TAG_SIZE; i += 1U) {
        if (tag[i] != expected_tag[i]) {
            (void)noxtls_debug_printf((const uint8_t *)"ChaCha20-Poly1305 self-test FAILED: Tag mismatch at byte %u\n", i);
            (void)noxtls_debug_printf((const uint8_t *)"  Expected: 0x%02x, Got: 0x%02x\n", expected_tag[i], tag[i]);
            return NOXTLS_RETURN_NULL;
        }
    }
    
    /* Test decryption */
    if (noxtls_chacha20_poly1305_decrypt(test_key, test_nonce, test_aad, 12,
                                  ciphertext, 114, tag, decrypted) != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_debug_printf((const uint8_t *)"ChaCha20-Poly1305 self-test FAILED: Decryption failed\n");
        return NOXTLS_RETURN_NULL;
    }
    
    /* Verify plaintext */
    for (i = 0U; i < 114U; i += 1U) {
        if (decrypted[i] != test_plaintext[i]) {
            (void)noxtls_debug_printf((const uint8_t *)"ChaCha20-Poly1305 self-test FAILED: Plaintext mismatch at byte %u\n", i);
            return NOXTLS_RETURN_NULL;
        }
    }
    
    NOXTLS_CHACHA20_POLY1305_DEBUG_PRINT("ChaCha20-Poly1305 self-test PASSED\n");
    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_CHACHA20_POLY1305 */
