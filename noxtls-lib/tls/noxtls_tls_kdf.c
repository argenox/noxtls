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
* File:    noxtls_tls_kdf.c
* Summary: TLS Key Derivation Functions (PRF, HKDF) Implementation
*
*
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "noxtls_tls_kdf.h"
#include "common/noxtls_memory.h"
#include "mac/noxtls_hmac.h"
#include "kdf/noxtls_hkdf.h"
#include "mdigest/md5/noxtls_md5.h"
#include "mdigest/sha1/noxtls_sha1.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha512/noxtls_sha512.h"
#include "noxtls_ct.h"

static uint32_t get_hash_output_size(noxtls_hash_algos_t hash_algo)
{
    switch(hash_algo) {
        case NOXTLS_HASH_MD5: return 16U;
        case NOXTLS_HASH_SHA1: return 20U;
        case NOXTLS_HASH_SHA_224: return 28U;
        case NOXTLS_HASH_SHA_256: return 32U;
        case NOXTLS_HASH_SHA_384: return 48U;
        case NOXTLS_HASH_SHA_512: return 64U;
        case NOXTLS_HASH_SHA_512_224: return 28U;
        case NOXTLS_HASH_SHA_512_256: return 32U;
        case NOXTLS_HASH_SHA3_224: return 28U;
        case NOXTLS_HASH_SHA3_256: return 32U;
        case NOXTLS_HASH_SHA3_384: return 48U;
        case NOXTLS_HASH_SHA3_512: return 64U;
        default: return 0U;
    }
}

static noxtls_return_t hmac_md5_compute(const uint8_t *key, uint32_t key_len,
                                        const uint8_t *data, uint32_t data_len,
                                        uint8_t out[16])
{
    uint8_t key_block[64];
    uint8_t inner_hash[16];
    uint8_t ipad[64];
    uint8_t opad[64];
    uint8_t key_hash[16];
    noxtls_sha_ctx_t ctx;
    uint32_t i = 0U;

    if((key == NULL) || (data == NULL) || (out == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero((key_block), sizeof(key_block));
    if((size_t)(key_len) > sizeof(key_block)) {
        if(noxtls_md5_init(&ctx) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        if(noxtls_md5_update(&ctx, key, key_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        if(noxtls_md5_finish(&ctx, key_hash) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_copy_u8(key_block, sizeof(key_block), key_hash, sizeof(key_hash));
    } else {
        noxtls_copy_u8(key_block, sizeof(key_block), key, (size_t)(key_len));
    }

    for(i = 0U; i < sizeof(key_block); i += 1U) {
        ipad[i] = (uint8_t)(key_block[i] ^ 0x36U);
        opad[i] = (uint8_t)(key_block[i] ^ 0x5CU);
    }

    if(noxtls_md5_init(&ctx) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(noxtls_md5_update(&ctx, ipad, sizeof(ipad)) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(noxtls_md5_update(&ctx, data, data_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(noxtls_md5_finish(&ctx, inner_hash) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    if(noxtls_md5_init(&ctx) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(noxtls_md5_update(&ctx, opad, sizeof(opad)) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(noxtls_md5_update(&ctx, inner_hash, sizeof(inner_hash)) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if(noxtls_md5_finish(&ctx, out) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }

    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t p_hash(noxtls_hash_algos_t hash_algo,
                              const uint8_t *secret, uint32_t secret_len,
                              const uint8_t *seed, uint32_t seed_len,
                              uint8_t *output, uint32_t output_len)
{
    uint32_t hash_len = get_hash_output_size(hash_algo);
    uint8_t *A = NULL;
    uint8_t *chunk = NULL;
    uint32_t produced = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((secret == NULL) || (seed == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(hash_len == 0U) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }

    A = (uint8_t *)NOXTLS_MALLOC(hash_len);
    chunk = (uint8_t *)NOXTLS_MALLOC(hash_len);
    if((A == NULL) || (chunk == NULL)) {
        (void)noxtls_free(A);
        (void)noxtls_free(chunk);
        return NOXTLS_RETURN_FAILED;
    }

    {
        uint32_t tmp_len = hash_len;
        rc = noxtls_hmac_compute(hash_algo, secret, secret_len, seed, seed_len, A, &tmp_len);
        if((rc != NOXTLS_RETURN_SUCCESS) || (tmp_len != hash_len)) {
            (void)noxtls_free(A);
            (void)noxtls_free(chunk);
            return NOXTLS_RETURN_FAILED;
        }
    }

    while(produced < output_len) {
        uint8_t *input = NULL;
        uint32_t input_len = hash_len + seed_len;
        uint32_t tmp_len = hash_len;
        uint32_t copy_len = 0U;

        input = (uint8_t *)NOXTLS_MALLOC(input_len);
        if(input == NULL) {
            (void)noxtls_free(A);
            (void)noxtls_free(chunk);
            return NOXTLS_RETURN_FAILED;
        }

        noxtls_copy_u8(input, (size_t)(hash_len + seed_len), A, (size_t)hash_len);
        noxtls_copy_u8(&input[hash_len], (size_t)input_len - (size_t)hash_len, seed, (size_t)seed_len);

        rc = noxtls_hmac_compute(hash_algo, secret, secret_len, input, input_len, chunk, &tmp_len);
        (void)noxtls_free(input);
        if((rc != NOXTLS_RETURN_SUCCESS) || (tmp_len != hash_len)) {
            (void)noxtls_free(A);
            (void)noxtls_free(chunk);
            return NOXTLS_RETURN_FAILED;
        }

        copy_len = ((output_len - produced) < hash_len) ? (output_len - produced) : hash_len;
        noxtls_copy_u8(&output[produced], (size_t)output_len - (size_t)produced, chunk, (size_t)copy_len);
        produced += copy_len;

        rc = noxtls_hmac_compute(hash_algo, secret, secret_len, A, hash_len, A, &tmp_len);
        if((rc != NOXTLS_RETURN_SUCCESS) || (tmp_len != hash_len)) {
            (void)noxtls_free(A);
            (void)noxtls_free(chunk);
            return NOXTLS_RETURN_FAILED;
        }
    }

    (void)noxtls_free(A);
    (void)noxtls_free(chunk);
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t tls12_prf(const uint8_t *secret, uint32_t secret_len,
                          const uint8_t *label, uint32_t label_len,
                          const uint8_t *seed, uint32_t seed_len,
                          uint8_t *output, uint32_t output_len,
                          noxtls_hash_algos_t hash_algo)
{
    uint8_t *label_seed = NULL;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((secret == NULL) || (label == NULL) || (seed == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    label_seed = (uint8_t *)NOXTLS_MALLOC(label_len + seed_len);
    if(label_seed == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    noxtls_copy_u8(label_seed, (size_t)(label_len + seed_len), label, (size_t)label_len);
    noxtls_copy_u8(&label_seed[label_len], (size_t)(label_len + seed_len) - (size_t)label_len, seed, (size_t)seed_len);

    rc = p_hash(hash_algo, secret, secret_len, label_seed, label_len + seed_len, output, output_len);
    (void)noxtls_free(label_seed);
    return rc;
}

noxtls_return_t tls10_prf(const uint8_t *secret, uint32_t secret_len,
                          const uint8_t *label, uint32_t label_len,
                          const uint8_t *seed, uint32_t seed_len,
                          uint8_t *output, uint32_t output_len)
{
    uint32_t half_len = 0U;
    const uint8_t *s1 = NULL;
    const uint8_t *s2 = NULL;
    uint8_t *label_seed = NULL;
    uint8_t *md5_out = NULL;
    uint8_t *sha1_out = NULL;
    uint32_t i = 0U;

    if((secret == NULL) || (label == NULL) || (seed == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(secret_len == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    half_len = (secret_len + 1U) / 2U;
    s1 = secret;
    s2 = &secret[secret_len - half_len];

    label_seed = (uint8_t *)NOXTLS_MALLOC(label_len + seed_len);
    md5_out = (uint8_t *)NOXTLS_MALLOC(output_len);
    sha1_out = (uint8_t *)NOXTLS_MALLOC(output_len);
    if((label_seed == NULL) || (md5_out == NULL) || (sha1_out == NULL)) {
        (void)noxtls_free(label_seed);
        (void)noxtls_free(md5_out);
        (void)noxtls_free(sha1_out);
        return NOXTLS_RETURN_FAILED;
    }

    noxtls_copy_u8(label_seed, (size_t)(label_len + seed_len), label, (size_t)label_len);
    noxtls_copy_u8(&label_seed[label_len], (size_t)(label_len + seed_len) - (size_t)label_len, seed, (size_t)seed_len);

    {
        uint8_t A_md5[16];
        uint32_t produced = 0U;

        if(hmac_md5_compute(s1, half_len, label_seed, label_len + seed_len, A_md5) != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_free(label_seed);
            (void)noxtls_free(md5_out);
            (void)noxtls_free(sha1_out);
            return NOXTLS_RETURN_FAILED;
        }

        while(produced < output_len) {
            uint8_t chunk[16];
            uint8_t *input = NULL;
            uint32_t copy_len = 0U;
            uint32_t label_seed_len = label_len + seed_len;
            input = (uint8_t *)NOXTLS_MALLOC(16U + label_seed_len);
            if(input == NULL) {
                (void)noxtls_free(label_seed);
                (void)noxtls_free(md5_out);
                (void)noxtls_free(sha1_out);
                return NOXTLS_RETURN_FAILED;
            }
            noxtls_copy_u8(input, (size_t)(16U + label_seed_len), A_md5, (size_t)16U);
            noxtls_copy_u8(&input[16U], (size_t)(16U + label_seed_len) - (size_t)16U, label_seed, (size_t)label_seed_len);
            if(hmac_md5_compute(s1, half_len, input, 16U + label_seed_len, chunk) != NOXTLS_RETURN_SUCCESS) {
                (void)noxtls_free(input);
                (void)noxtls_free(label_seed);
                (void)noxtls_free(md5_out);
                (void)noxtls_free(sha1_out);
                return NOXTLS_RETURN_FAILED;
            }
            (void)noxtls_free(input);
            copy_len = ((output_len - produced) < 16U) ? (output_len - produced) : 16U;
            noxtls_copy_u8(&md5_out[produced], (size_t)output_len - (size_t)produced, chunk, (size_t)copy_len);
            produced += copy_len;
            if(hmac_md5_compute(s1, half_len, A_md5, 16U, A_md5) != NOXTLS_RETURN_SUCCESS) {
                (void)noxtls_free(label_seed);
                (void)noxtls_free(md5_out);
                (void)noxtls_free(sha1_out);
                return NOXTLS_RETURN_FAILED;
            }
        }
    }

    if(p_hash(NOXTLS_HASH_SHA1, s2, half_len, label_seed, label_len + seed_len, sha1_out, output_len) != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_free(label_seed);
        (void)noxtls_free(md5_out);
        (void)noxtls_free(sha1_out);
        return NOXTLS_RETURN_FAILED;
    }

    for(i = 0U; i < output_len; i += 1U) {
        output[i] = (uint8_t)(md5_out[i] ^ sha1_out[i]);
    }

    (void)noxtls_free(label_seed);
    (void)noxtls_free(md5_out);
    (void)noxtls_free(sha1_out);
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t hkdf_expand_label_with_prefix(noxtls_hash_algos_t hash_algo,
                                                     const uint8_t *prefix,
                                                     const uint8_t *secret, uint32_t secret_len,
                                                     const uint8_t *label, uint32_t label_len,
                                                     const uint8_t *context, uint32_t context_len,
                                                     uint8_t *output, uint32_t output_len)
{
    uint8_t hkdf_label[512];
    uint32_t prefix_len = (uint32_t)noxtls_u8_strlen(prefix);
    uint32_t full_label_len = prefix_len + label_len;
    uint32_t offset = 0U;

    if((secret == NULL) || (label == NULL) || (output == NULL) || (full_label_len > 255U) || (context_len > 255U)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if((2U + 1U + full_label_len + 1U + context_len) > sizeof(hkdf_label)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    hkdf_label[offset] = (uint8_t)((output_len >> 8U) & 0xFFU);
    offset += 1U;
    hkdf_label[offset] = (uint8_t)(output_len & 0xFFU);
    offset += 1U;
    hkdf_label[offset] = (uint8_t)full_label_len;
    offset += 1U;
    /* Binary HkdfLabel buffer (not a C string); copy char prefix as bytes. */
    {
        uint32_t pi = 0U;
        for (pi = 0U; pi < prefix_len; pi += 1U) {
            hkdf_label[offset + pi] = (uint8_t)prefix[pi];
        }
    }
    offset += prefix_len;
    noxtls_copy_u8(&hkdf_label[offset], sizeof(hkdf_label) - (size_t)(offset), label, (size_t)(label_len));
    offset += label_len;
    hkdf_label[offset] = (uint8_t)context_len;
    offset += 1U;
    if((context_len > 0U) && (context != NULL)) {
        noxtls_copy_u8(&hkdf_label[offset], sizeof(hkdf_label) - (size_t)(offset), context, (size_t)(context_len));
        offset += context_len;
    }

    return noxtls_hkdf_expand(hash_algo, secret, secret_len, hkdf_label, offset, output, output_len);
}

noxtls_return_t tls13_hkdf_expand_label(noxtls_hash_algos_t hash_algo,
                                        const uint8_t *secret, uint32_t secret_len,
                                        const uint8_t *label, uint32_t label_len,
                                        const uint8_t *context, uint32_t context_len,
                                        uint8_t *output, uint32_t output_len)
{
    return hkdf_expand_label_with_prefix(hash_algo, (const uint8_t[]){ (uint8_t)'t', (uint8_t)'l', (uint8_t)'s', (uint8_t)'1', (uint8_t)'3', (uint8_t)' ', 0 }, secret, secret_len,
                                         label, label_len, context, context_len,
                                         output, output_len);
}

noxtls_return_t dtls13_hkdf_expand_label(noxtls_hash_algos_t hash_algo,
                                         const uint8_t *secret, uint32_t secret_len,
                                         const uint8_t *label, uint32_t label_len,
                                         const uint8_t *context, uint32_t context_len,
                                         uint8_t *output, uint32_t output_len)
{
    return hkdf_expand_label_with_prefix(hash_algo, (const uint8_t[]){ (uint8_t)'d', (uint8_t)'t', (uint8_t)'l', (uint8_t)'s', (uint8_t)'1', (uint8_t)'3', 0 }, secret, secret_len,
                                         label, label_len, context, context_len,
                                         output, output_len);
}

static noxtls_return_t hash_message_sha256(const uint8_t *messages, uint32_t messages_len,
                                           uint8_t *out_digest, uint32_t out_len)
{
    noxtls_sha_ctx_t ctx;

    if(out_len < 32U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if((messages != NULL) && (messages_len > 0U)) {
        if(noxtls_sha256_update(&ctx, messages, messages_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    return noxtls_sha256_finish(&ctx, out_digest);
}

static noxtls_return_t hash_message_sha512(noxtls_hash_algos_t hash_algo,
                                           const uint8_t *messages, uint32_t messages_len,
                                           uint8_t *out_digest, uint32_t out_len)
{
    noxtls_sha512_ctx_t ctx;
    uint32_t need = (hash_algo == NOXTLS_HASH_SHA_384) ? 48U : 64U;

    if(out_len < need) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(noxtls_sha512_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if((messages != NULL) && (messages_len > 0U)) {
        if(noxtls_sha512_update(&ctx, messages, messages_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    return noxtls_sha512_finish(&ctx, out_digest);
}

static noxtls_return_t hash_message_sha1(const uint8_t *messages, uint32_t messages_len,
                                         uint8_t *out_digest, uint32_t out_len)
{
    noxtls_sha_ctx_t ctx;

    if(out_len < 20U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(noxtls_sha1_init(&ctx, NOXTLS_HASH_SHA1) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if((messages != NULL) && (messages_len > 0U)) {
        if(noxtls_sha1_update(&ctx, messages, messages_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    return noxtls_sha1_finish(&ctx, out_digest);
}

static noxtls_return_t hash_message(noxtls_hash_algos_t hash_algo,
                                    const uint8_t *messages, uint32_t messages_len,
                                    uint8_t *out_digest, uint32_t out_len)
{
    if((messages == NULL) || (out_digest == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if(hash_algo == NOXTLS_HASH_SHA_256) {
        return hash_message_sha256(messages, messages_len, out_digest, out_len);
    }
    if((hash_algo == NOXTLS_HASH_SHA_384) || (hash_algo == NOXTLS_HASH_SHA_512)) {
        return hash_message_sha512(hash_algo, messages, messages_len, out_digest, out_len);
    }
    if(hash_algo == NOXTLS_HASH_SHA1) {
        return hash_message_sha1(messages, messages_len, out_digest, out_len);
    }

    return NOXTLS_RETURN_INVALID_ALGORITHM;
}

static noxtls_return_t hash_empty_message(noxtls_hash_algos_t hash_algo,
                                          uint8_t *out_digest, uint32_t out_len)
{
    if(out_digest == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(hash_algo == NOXTLS_HASH_SHA_256) {
        return hash_message_sha256(NULL, 0U, out_digest, out_len);
    }
    if((hash_algo == NOXTLS_HASH_SHA_384) || (hash_algo == NOXTLS_HASH_SHA_512)) {
        return hash_message_sha512(hash_algo, NULL, 0U, out_digest, out_len);
    }
    if(hash_algo == NOXTLS_HASH_SHA1) {
        return hash_message_sha1(NULL, 0U, out_digest, out_len);
    }

    return NOXTLS_RETURN_INVALID_ALGORITHM;
}

noxtls_return_t tls13_derive_secret(noxtls_hash_algos_t hash_algo,
                                    const uint8_t *secret, uint32_t secret_len,
                                    const uint8_t *label, uint32_t label_len,
                                    const uint8_t *messages, uint32_t messages_len,
                                    uint8_t *output, uint32_t output_len)
{
    uint32_t hash_len = get_hash_output_size(hash_algo);
    uint8_t transcript_hash[64];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((secret == NULL) || (label == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if((hash_len == 0U) || ((size_t)(hash_len) > sizeof(transcript_hash))) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if(output_len < hash_len) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if((messages != NULL) && (messages_len > 0U)) {
        rc = hash_message(hash_algo, messages, messages_len, transcript_hash, sizeof(transcript_hash));
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    } else {
        /* MISRA 15.7: final else path */
        rc = hash_empty_message(hash_algo, transcript_hash, sizeof(transcript_hash));
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    return tls13_hkdf_expand_label(hash_algo, secret, secret_len, label, label_len,
                                   transcript_hash, hash_len, output, hash_len);
}

noxtls_return_t dtls13_derive_secret(noxtls_hash_algos_t hash_algo,
                                     const uint8_t *secret, uint32_t secret_len,
                                     const uint8_t *label, uint32_t label_len,
                                     const uint8_t *messages, uint32_t messages_len,
                                     uint8_t *output, uint32_t output_len)
{
    uint32_t hash_len = get_hash_output_size(hash_algo);
    uint8_t transcript_hash[64];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((secret == NULL) || (label == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if((hash_len == 0U) || ((size_t)(hash_len) > sizeof(transcript_hash))) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if(output_len < hash_len) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if((messages != NULL) && (messages_len > 0U)) {
        rc = hash_message(hash_algo, messages, messages_len, transcript_hash, sizeof(transcript_hash));
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    } else {
        /* MISRA 15.7: final else path */
        rc = hash_empty_message(hash_algo, transcript_hash, sizeof(transcript_hash));
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    return dtls13_hkdf_expand_label(hash_algo, secret, secret_len, label, label_len,
                                    transcript_hash, hash_len, output, hash_len);
}
