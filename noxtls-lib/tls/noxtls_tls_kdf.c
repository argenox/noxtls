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
#include "mac/noxtls_hmac.h"
#include "kdf/noxtls_hkdf.h"
#include "mdigest/md5/noxtls_md5.h"
#include "mdigest/sha1/noxtls_sha1.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha512/noxtls_sha512.h"

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
    uint32_t i;

    if(key == NULL || data == NULL || out == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    memset(key_block, 0, sizeof(key_block));
    if(key_len > sizeof(key_block)) {
        if(noxtls_md5_init(&ctx) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        if(noxtls_md5_update(&ctx, key, key_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        if(noxtls_md5_finish(&ctx, key_hash) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(key_block, key_hash, sizeof(key_hash));
    } else {
        memcpy(key_block, key, key_len);
    }

    for(i = 0; i < sizeof(key_block); i++) {
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
    noxtls_return_t rc;

    if(secret == NULL || seed == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(hash_len == 0U) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }

    A = (uint8_t *)malloc(hash_len);
    chunk = (uint8_t *)malloc(hash_len);
    if(A == NULL || chunk == NULL) {
        free(A);
        free(chunk);
        return NOXTLS_RETURN_FAILED;
    }

    {
        uint32_t tmp_len = hash_len;
        rc = noxtls_hmac_compute(hash_algo, secret, secret_len, seed, seed_len, A, &tmp_len);
        if(rc != NOXTLS_RETURN_SUCCESS || tmp_len != hash_len) {
            free(A);
            free(chunk);
            return NOXTLS_RETURN_FAILED;
        }
    }

    while(produced < output_len) {
        uint8_t *input = NULL;
        uint32_t input_len = hash_len + seed_len;
        uint32_t tmp_len = hash_len;
        uint32_t copy_len;

        input = (uint8_t *)malloc(input_len);
        if(input == NULL) {
            free(A);
            free(chunk);
            return NOXTLS_RETURN_FAILED;
        }

        memcpy(input, A, hash_len);
        memcpy(input + hash_len, seed, seed_len);

        rc = noxtls_hmac_compute(hash_algo, secret, secret_len, input, input_len, chunk, &tmp_len);
        free(input);
        if(rc != NOXTLS_RETURN_SUCCESS || tmp_len != hash_len) {
            free(A);
            free(chunk);
            return NOXTLS_RETURN_FAILED;
        }

        copy_len = (output_len - produced < hash_len) ? (output_len - produced) : hash_len;
        memcpy(output + produced, chunk, copy_len);
        produced += copy_len;

        tmp_len = hash_len;
        rc = noxtls_hmac_compute(hash_algo, secret, secret_len, A, hash_len, A, &tmp_len);
        if(rc != NOXTLS_RETURN_SUCCESS || tmp_len != hash_len) {
            free(A);
            free(chunk);
            return NOXTLS_RETURN_FAILED;
        }
    }

    free(A);
    free(chunk);
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t tls12_prf(const uint8_t *secret, uint32_t secret_len,
                          const uint8_t *label, uint32_t label_len,
                          const uint8_t *seed, uint32_t seed_len,
                          uint8_t *output, uint32_t output_len,
                          noxtls_hash_algos_t hash_algo)
{
    uint8_t *label_seed = NULL;
    noxtls_return_t rc;

    if(secret == NULL || label == NULL || seed == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    label_seed = (uint8_t *)malloc(label_len + seed_len);
    if(label_seed == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    memcpy(label_seed, label, label_len);
    memcpy(label_seed + label_len, seed, seed_len);

    rc = p_hash(hash_algo, secret, secret_len, label_seed, label_len + seed_len, output, output_len);
    free(label_seed);
    return rc;
}

noxtls_return_t tls10_prf(const uint8_t *secret, uint32_t secret_len,
                          const uint8_t *label, uint32_t label_len,
                          const uint8_t *seed, uint32_t seed_len,
                          uint8_t *output, uint32_t output_len)
{
    uint32_t half_len;
    const uint8_t *s1;
    const uint8_t *s2;
    uint8_t *label_seed = NULL;
    uint8_t *md5_out = NULL;
    uint8_t *sha1_out = NULL;
    uint32_t i;

    if(secret == NULL || label == NULL || seed == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(secret_len == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    half_len = (secret_len + 1U) / 2U;
    s1 = secret;
    s2 = secret + (secret_len - half_len);

    label_seed = (uint8_t *)malloc(label_len + seed_len);
    md5_out = (uint8_t *)malloc(output_len);
    sha1_out = (uint8_t *)malloc(output_len);
    if(label_seed == NULL || md5_out == NULL || sha1_out == NULL) {
        free(label_seed);
        free(md5_out);
        free(sha1_out);
        return NOXTLS_RETURN_FAILED;
    }

    memcpy(label_seed, label, label_len);
    memcpy(label_seed + label_len, seed, seed_len);

    {
        uint8_t A_md5[16];
        uint32_t produced = 0U;

        if(hmac_md5_compute(s1, half_len, label_seed, label_len + seed_len, A_md5) != NOXTLS_RETURN_SUCCESS) {
            free(label_seed);
            free(md5_out);
            free(sha1_out);
            return NOXTLS_RETURN_FAILED;
        }

        while(produced < output_len) {
            uint8_t chunk[16];
            uint8_t *input = NULL;
            uint32_t copy_len;
            uint32_t label_seed_len = label_len + seed_len;
            input = (uint8_t *)malloc(16U + label_seed_len);
            if(input == NULL) {
                free(label_seed);
                free(md5_out);
                free(sha1_out);
                return NOXTLS_RETURN_FAILED;
            }
            memcpy(input, A_md5, 16U);
            memcpy(input + 16U, label_seed, label_seed_len);
            if(hmac_md5_compute(s1, half_len, input, 16U + label_seed_len, chunk) != NOXTLS_RETURN_SUCCESS) {
                free(input);
                free(label_seed);
                free(md5_out);
                free(sha1_out);
                return NOXTLS_RETURN_FAILED;
            }
            free(input);
            copy_len = (output_len - produced < 16U) ? (output_len - produced) : 16U;
            memcpy(md5_out + produced, chunk, copy_len);
            produced += copy_len;
            if(hmac_md5_compute(s1, half_len, A_md5, 16U, A_md5) != NOXTLS_RETURN_SUCCESS) {
                free(label_seed);
                free(md5_out);
                free(sha1_out);
                return NOXTLS_RETURN_FAILED;
            }
        }
    }

    if(p_hash(NOXTLS_HASH_SHA1, s2, half_len, label_seed, label_len + seed_len, sha1_out, output_len) != NOXTLS_RETURN_SUCCESS) {
        free(label_seed);
        free(md5_out);
        free(sha1_out);
        return NOXTLS_RETURN_FAILED;
    }

    for(i = 0; i < output_len; i++) {
        output[i] = (uint8_t)(md5_out[i] ^ sha1_out[i]);
    }

    free(label_seed);
    free(md5_out);
    free(sha1_out);
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t hkdf_expand_label_with_prefix(noxtls_hash_algos_t hash_algo,
                                                     const char *prefix,
                                                     const uint8_t *secret, uint32_t secret_len,
                                                     const uint8_t *label, uint32_t label_len,
                                                     const uint8_t *context, uint32_t context_len,
                                                     uint8_t *output, uint32_t output_len)
{
    uint8_t hkdf_label[512];
    uint32_t prefix_len = (uint32_t)strlen(prefix);
    uint32_t full_label_len = prefix_len + label_len;
    uint32_t offset = 0U;

    if(secret == NULL || label == NULL || output == NULL || full_label_len > 255U || context_len > 255U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if((2U + 1U + full_label_len + 1U + context_len) > sizeof(hkdf_label)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    hkdf_label[offset++] = (uint8_t)((output_len >> 8) & 0xFFU);
    hkdf_label[offset++] = (uint8_t)(output_len & 0xFFU);
    hkdf_label[offset++] = (uint8_t)full_label_len;
    memcpy(hkdf_label + offset, prefix, prefix_len);
    offset += prefix_len;
    memcpy(hkdf_label + offset, label, label_len);
    offset += label_len;
    hkdf_label[offset++] = (uint8_t)context_len;
    if(context_len > 0U && context != NULL) {
        memcpy(hkdf_label + offset, context, context_len);
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
    return hkdf_expand_label_with_prefix(hash_algo, "tls13 ", secret, secret_len,
                                         label, label_len, context, context_len,
                                         output, output_len);
}

noxtls_return_t dtls13_hkdf_expand_label(noxtls_hash_algos_t hash_algo,
                                         const uint8_t *secret, uint32_t secret_len,
                                         const uint8_t *label, uint32_t label_len,
                                         const uint8_t *context, uint32_t context_len,
                                         uint8_t *output, uint32_t output_len)
{
    return hkdf_expand_label_with_prefix(hash_algo, "dtls13", secret, secret_len,
                                         label, label_len, context, context_len,
                                         output, output_len);
}

static noxtls_return_t hash_message(noxtls_hash_algos_t hash_algo,
                                    const uint8_t *messages, uint32_t messages_len,
                                    uint8_t *out_digest, uint32_t out_len)
{
    if(messages == NULL || out_digest == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(hash_algo == NOXTLS_HASH_SHA_256) {
        noxtls_sha_ctx_t ctx;
        if(out_len < 32U) return NOXTLS_RETURN_INVALID_PARAM;
        if(noxtls_sha256_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if(noxtls_sha256_update(&ctx, messages, messages_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        return noxtls_sha256_finish(&ctx, out_digest);
    }
    if(hash_algo == NOXTLS_HASH_SHA_384 || hash_algo == NOXTLS_HASH_SHA_512) {
        noxtls_sha512_ctx_t ctx;
        uint32_t need = (hash_algo == NOXTLS_HASH_SHA_384) ? 48U : 64U;
        if(out_len < need) return NOXTLS_RETURN_INVALID_PARAM;
        if(noxtls_sha512_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if(noxtls_sha512_update(&ctx, messages, messages_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        return noxtls_sha512_finish(&ctx, out_digest);
    }
    if(hash_algo == NOXTLS_HASH_SHA1) {
        noxtls_sha_ctx_t ctx;
        if(out_len < 20U) return NOXTLS_RETURN_INVALID_PARAM;
        if(noxtls_sha1_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        if(noxtls_sha1_update(&ctx, messages, messages_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
        return noxtls_sha1_finish(&ctx, out_digest);
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
    noxtls_return_t rc;

    if(secret == NULL || label == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(hash_len == 0U || hash_len > sizeof(transcript_hash)) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if(output_len < hash_len) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if(messages != NULL && messages_len > 0U) {
        rc = hash_message(hash_algo, messages, messages_len, transcript_hash, sizeof(transcript_hash));
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    } else {
        memset(transcript_hash, 0, hash_len);
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
    noxtls_return_t rc;

    if(secret == NULL || label == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(hash_len == 0U || hash_len > sizeof(transcript_hash)) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if(output_len < hash_len) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if(messages != NULL && messages_len > 0U) {
        rc = hash_message(hash_algo, messages, messages_len, transcript_hash, sizeof(transcript_hash));
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    } else {
        memset(transcript_hash, 0, hash_len);
    }

    return dtls13_hkdf_expand_label(hash_algo, secret, secret_len, label, label_len,
                                    transcript_hash, hash_len, output, hash_len);
}
