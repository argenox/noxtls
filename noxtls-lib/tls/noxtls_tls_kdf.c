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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "noxtls_tls_kdf.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha512/noxtls_sha512.h"
#include "mdigest/md5/noxtls_md5.h"
#include "mdigest/sha1/noxtls_sha1.h"
#include "mdigest/noxtls_hash.h"

/* Get hash block size and output size */
/**
 * @brief Get the hash block size and output size
 *
 * @param[in] hash_algo The hash algorithm
 * @return The hash block size and output size
 */
static uint32_t get_hash_block_size(noxtls_hash_algos_t hash_algo)
{
    switch(hash_algo) {
        case NOXTLS_HASH_MD4:
        case NOXTLS_HASH_MD5:
        case NOXTLS_HASH_SHA1:
        case NOXTLS_HASH_SHA_256:
        case NOXTLS_HASH_SHA_224:
            return 64;  /* SHA-256 block size */
        case NOXTLS_HASH_SHA_384:
        case NOXTLS_HASH_SHA_512:
        case NOXTLS_HASH_SHA_512_224:
        case NOXTLS_HASH_SHA_512_256:
            return 128;  /* SHA-512 block size */
        case NOXTLS_HASH_SHA3_224:
            return 144;
        case NOXTLS_HASH_SHA3_256:
            return 136;
        case NOXTLS_HASH_SHA3_384:
            return 104;
        case NOXTLS_HASH_SHA3_512:
            return 72;
        default:
            return 0;
    }
}

/**
 * @brief Get the hash output size
 *
 * @param[in] hash_algo The hash algorithm
 * @return The hash output size
 */
static uint32_t get_hash_output_size(noxtls_hash_algos_t hash_algo)
{
    switch(hash_algo) {
        case NOXTLS_HASH_MD4:
        case NOXTLS_HASH_MD5:
            return 16;
        case NOXTLS_HASH_SHA1:
            return 20;
        case NOXTLS_HASH_SHA_224:
            return 28;
        case NOXTLS_HASH_SHA_256:
            return 32;
        case NOXTLS_HASH_SHA_384:
            return 48;
        case NOXTLS_HASH_SHA_512:
            return 64;
        case NOXTLS_HASH_SHA_512_224:
            return 28;
        case NOXTLS_HASH_SHA_512_256:
            return 32;
        case NOXTLS_HASH_SHA3_224:
            return 28;
        case NOXTLS_HASH_SHA3_256:
            return 32;
        case NOXTLS_HASH_SHA3_384:
            return 48;
        case NOXTLS_HASH_SHA3_512:
            return 64;
        default:
            return 0;
    }
}

/**
 * @brief Initialize HMAC context
 *
 * @param[in] ctx The HMAC context
 * @param[in] hash_algo The hash algorithm
 * @param[in] key The key
 * @param[in] key_len The length of the key
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL, NOXTLS_RETURN_INVALID_ALGORITHM if the hash algorithm is not supported, or NOXTLS_RETURN_FAILED if the key cannot be hashed
 */
noxtls_return_t noxtls_hmac_init(hmac_context_t *ctx, noxtls_hash_algos_t hash_algo, const uint8_t *key, uint32_t key_len)
{
    uint32_t block_size;
    uint32_t i;
    uint8_t hashed_key[64];
    
    if(ctx == NULL || key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(hash_algo != NOXTLS_HASH_SHA_256 &&
       hash_algo != NOXTLS_HASH_SHA_384 &&
       hash_algo != NOXTLS_HASH_SHA_512 &&
       hash_algo != NOXTLS_HASH_SHA1) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    
    memset(ctx, 0, sizeof(hmac_context_t));
    ctx->hash_algo = hash_algo;
    block_size = get_hash_block_size(hash_algo);
    
    /* If key is longer than block size, hash it */
    if(key_len > block_size) {
        uint32_t hash_size = get_hash_output_size(hash_algo);
        
        /* Hash the key directly */
        if(hash_algo == NOXTLS_HASH_SHA_256) {
            noxtls_sha_ctx_t sha_ctx;
            noxtls_sha256_init(&sha_ctx, hash_algo);
            noxtls_sha256_update(&sha_ctx, (uint8_t*)key, key_len);
            if(noxtls_sha256_finish(&sha_ctx, hashed_key) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_FAILED;
            }
        } else if(hash_algo == NOXTLS_HASH_SHA_384 || hash_algo == NOXTLS_HASH_SHA_512) {
            noxtls_sha512_ctx_t sha_ctx;
            noxtls_sha512_init(&sha_ctx, hash_algo);
            noxtls_sha512_update(&sha_ctx, (uint8_t*)key, key_len);
            if(noxtls_sha512_finish(&sha_ctx, hashed_key) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_FAILED;
            }
        } else if(hash_algo == NOXTLS_HASH_SHA1) {
            noxtls_sha_ctx_t sha_ctx;
            noxtls_sha1_init(&sha_ctx, hash_algo);
            noxtls_sha1_update(&sha_ctx, (uint8_t*)key, key_len);
            if(noxtls_sha1_finish(&sha_ctx, hashed_key) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_FAILED;
            }
        } else {
            return NOXTLS_RETURN_INVALID_ALGORITHM;
        }
        
        memcpy(ctx->key, hashed_key, hash_size);
        ctx->key_len = hash_size;
    } else {
        memcpy(ctx->key, key, key_len);
        ctx->key_len = key_len;
    }
    
    /* Pad key to block size with zeros */
    if(ctx->key_len < block_size) {
        memset(ctx->key + ctx->key_len, 0, block_size - ctx->key_len);
    }
    
    /* Create inner and outer padding */
    for(i = 0; i < block_size; i++) {
        ctx->i_key_pad[i] = ctx->key[i] ^ 0x36;
        ctx->o_key_pad[i] = ctx->key[i] ^ 0x5C;
    }
    
    /* Initialize hash context */
    if(hash_algo == NOXTLS_HASH_SHA_256) {
        noxtls_sha_ctx_t *sha_ctx = &ctx->hash_ctx_storage.sha_ctx;
        if(noxtls_sha256_init(sha_ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_sha256_update(sha_ctx, ctx->i_key_pad, block_size);
        ctx->hash_ctx = sha_ctx;
    } else if(hash_algo == NOXTLS_HASH_SHA_384 || hash_algo == NOXTLS_HASH_SHA_512) {
        noxtls_sha512_ctx_t *sha_ctx = &ctx->hash_ctx_storage.sha512_ctx;
        if(noxtls_sha512_init(sha_ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_sha512_update(sha_ctx, ctx->i_key_pad, block_size);
        ctx->hash_ctx = sha_ctx;
    } else if(hash_algo == NOXTLS_HASH_SHA1) {
        noxtls_sha_ctx_t *sha_ctx = &ctx->hash_ctx_storage.sha_ctx;
        if(noxtls_sha1_init(sha_ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_sha1_update(sha_ctx, ctx->i_key_pad, block_size);
        ctx->hash_ctx = sha_ctx;
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Update HMAC with data
 *
 * @param[in] ctx The HMAC context
 * @param[in] data The data to update
 * @param[in] data_len The length of the data to update
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL, NOXTLS_RETURN_FAILED if the hash context is NULL, or NOXTLS_RETURN_INVALID_ALGORITHM if the hash algorithm is not supported
 */
noxtls_return_t noxtls_hmac_update(hmac_context_t *ctx, const uint8_t *data, uint32_t data_len)
{
    if(ctx == NULL || data == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->hash_ctx == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    if(ctx->hash_algo == NOXTLS_HASH_SHA_256) {
        return noxtls_sha256_update((noxtls_sha_ctx_t*)ctx->hash_ctx, (uint8_t*)data, data_len);
    } else if(ctx->hash_algo == NOXTLS_HASH_SHA_384 || ctx->hash_algo == NOXTLS_HASH_SHA_512) {
        return noxtls_sha512_update((noxtls_sha512_ctx_t*)ctx->hash_ctx, (uint8_t*)data, data_len);
    } else if(ctx->hash_algo == NOXTLS_HASH_SHA1) {
        return noxtls_sha1_update((noxtls_sha_ctx_t*)ctx->hash_ctx, (uint8_t*)data, data_len);
    }
    
    return NOXTLS_RETURN_INVALID_ALGORITHM;
}

/**
 * @brief Finalize HMAC and compute MAC
 *
 * @param[in] ctx The HMAC context
 * @param[out] mac The MAC
 * @param[in] mac_len The length of the MAC
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL, NOXTLS_RETURN_FAILED if the hash context is NULL, or NOXTLS_RETURN_INVALID_ALGORITHM if the hash algorithm is not supported
 */
noxtls_return_t noxtls_hmac_final(hmac_context_t *ctx, uint8_t *mac, uint32_t *mac_len)
{
    uint32_t hash_size;
    uint8_t inner_hash[64];  /* Max hash size */
    uint32_t block_size;
    noxtls_return_t rc;
    
    if(ctx == NULL || mac == NULL || mac_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(ctx->hash_ctx == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    hash_size = get_hash_output_size(ctx->hash_algo);
    block_size = get_hash_block_size(ctx->hash_algo);
    
    if(*mac_len < hash_size) {
        *mac_len = hash_size;
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Complete inner hash */
    if(ctx->hash_algo == NOXTLS_HASH_SHA_256) {
        rc = noxtls_sha256_finish((noxtls_sha_ctx_t*)ctx->hash_ctx, inner_hash);
        ctx->hash_ctx = NULL;
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    } else if(ctx->hash_algo == NOXTLS_HASH_SHA_384 || ctx->hash_algo == NOXTLS_HASH_SHA_512) {
        rc = noxtls_sha512_finish((noxtls_sha512_ctx_t*)ctx->hash_ctx, inner_hash);
        ctx->hash_ctx = NULL;
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    } else if(ctx->hash_algo == NOXTLS_HASH_SHA1) {
        rc = noxtls_sha1_finish((noxtls_sha_ctx_t*)ctx->hash_ctx, inner_hash);
        ctx->hash_ctx = NULL;
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    } else {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    
    /* Compute outer hash: H(o_key_pad || inner_hash) */
    if(ctx->hash_algo == NOXTLS_HASH_SHA_256) {
        noxtls_sha_ctx_t sha_ctx;
        noxtls_sha256_init(&sha_ctx, ctx->hash_algo);
        noxtls_sha256_update(&sha_ctx, ctx->o_key_pad, block_size);
        noxtls_sha256_update(&sha_ctx, inner_hash, hash_size);
        rc = noxtls_sha256_finish(&sha_ctx, mac);
    } else if(ctx->hash_algo == NOXTLS_HASH_SHA_384 || ctx->hash_algo == NOXTLS_HASH_SHA_512) {
        noxtls_sha512_ctx_t sha_ctx;
        noxtls_sha512_init(&sha_ctx, ctx->hash_algo);
        noxtls_sha512_update(&sha_ctx, ctx->o_key_pad, block_size);
        noxtls_sha512_update(&sha_ctx, inner_hash, hash_size);
        rc = noxtls_sha512_finish(&sha_ctx, mac);
    } else if(ctx->hash_algo == NOXTLS_HASH_SHA1) {
        noxtls_sha_ctx_t sha_ctx;
        noxtls_sha1_init(&sha_ctx, ctx->hash_algo);
        noxtls_sha1_update(&sha_ctx, ctx->o_key_pad, block_size);
        noxtls_sha1_update(&sha_ctx, inner_hash, hash_size);
        rc = noxtls_sha1_finish(&sha_ctx, mac);
    } else {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    
    if(rc == NOXTLS_RETURN_SUCCESS) {
        *mac_len = hash_size;
    }
    
    return rc;
}

/**
 * @brief Free HMAC context
 *
 * @param[in] ctx The HMAC context
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL
 */
noxtls_return_t noxtls_hmac_free(hmac_context_t *ctx)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    ctx->hash_ctx = NULL;
    
    /* Clear sensitive data */
    memset(ctx->key, 0, sizeof(ctx->key));
    memset(ctx->i_key_pad, 0, sizeof(ctx->i_key_pad));
    memset(ctx->o_key_pad, 0, sizeof(ctx->o_key_pad));
    
    memset(ctx, 0, sizeof(hmac_context_t));
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Compute HMAC in one shot
 *
 * @param[in] hash_algo The hash algorithm
 * @param[in] key The key
 * @param[in] key_len The length of the key
 * @param[in] data The data to compute
 * @param[in] data_len The length of the data to compute
 * @param[out] mac The MAC
 * @param[in] mac_len The length of the MAC
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the context is NULL, NOXTLS_RETURN_FAILED if the hash context is NULL, or NOXTLS_RETURN_INVALID_ALGORITHM if the hash algorithm is not supported
*/
noxtls_return_t hmac_compute(noxtls_hash_algos_t hash_algo, const uint8_t *key, uint32_t key_len,
                               const uint8_t *data, uint32_t data_len, uint8_t *mac, uint32_t *mac_len)
{
    hmac_context_t ctx;
    noxtls_return_t rc;
    
    rc = noxtls_hmac_init(&ctx, hash_algo, key, key_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] hmac_compute: noxtls_hmac_init rc=%d algo=%u key_len=%lu\n", rc, (unsigned)hash_algo, (unsigned long)key_len);
        fflush(stdout);
        return rc;
    }
    
    if(data != NULL && data_len > 0) {
        rc = noxtls_hmac_update(&ctx, data, data_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            printf("[TLS12_DEBUG] hmac_compute: noxtls_hmac_update rc=%d algo=%u data_len=%lu\n", rc, (unsigned)hash_algo, (unsigned long)data_len);
            fflush(stdout);
            return rc;
        }
    }
    
    rc = noxtls_hmac_final(&ctx, mac, mac_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("[TLS12_DEBUG] hmac_compute: noxtls_hmac_final rc=%d algo=%u\n", rc, (unsigned)hash_algo);
        fflush(stdout);
    }
    return rc;
}

/**
 * @brief TLS 1.2 PRF (Pseudo-Random Function)
 * 
 * PRF(secret, label, seed) = P_hash(secret, label || seed)
 * P_hash(secret, seed) = HMAC_hash(secret, A(1) || seed) ||
 *                         HMAC_hash(secret, A(2) || seed) ||
 *                         HMAC_hash(secret, A(3) || seed) || ...
 * where A(0) = seed
 *       A(i) = HMAC_hash(secret, A(i-1))
 *
 * @param[in] secret The secret
 * @param[in] secret_len The length of the secret
 * @param[in] label The label
 * @param[in] label_len The length of the label
 * @param[in] seed The seed
 * @param[in] seed_len The length of the seed
 * @param[out] output The output
 * @param[in] output_len The length of the output
 * @param[in] hash_algo The hash algorithm
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the secret is NULL, NOXTLS_RETURN_INVALID_ALGORITHM if the hash algorithm is not supported, or NOXTLS_RETURN_FAILED if the label or seed is NULL
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
noxtls_return_t tls12_prf(const uint8_t *secret, uint32_t secret_len,
                            const uint8_t *label, uint32_t label_len,
                            const uint8_t *seed, uint32_t seed_len, /* NOLINT(bugprone-easily-swappable-parameters): PRF inputs follow RFC tuple order. */
                            uint8_t *output, uint32_t output_len, /* NOLINT(bugprone-easily-swappable-parameters): output_len/hash_algo are intentionally adjacent API controls. */
                            noxtls_hash_algos_t hash_algo)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    /* A(0) holds label||seed (e.g. "master secret"(13) + client_random + server_random(64) = 77 bytes). */
    enum { tls12_prf_a_buflen = 128 };
    uint32_t hash_size = get_hash_output_size(hash_algo);
    uint8_t *label_seed;
    uint32_t label_seed_len;
    uint8_t A[tls12_prf_a_buflen];  /* Current A(i); must fit initial seed material */
    uint8_t temp[tls12_prf_a_buflen];
    uint32_t A_len;
    uint32_t temp_len;
    uint32_t offset = 0;
    uint32_t i;
    
    if(secret == NULL || label == NULL || seed == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(hash_algo != NOXTLS_HASH_SHA_256 && hash_algo != NOXTLS_HASH_SHA_384) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    
    /* Concatenate label and seed */
    if(label_len > UINT32_MAX - seed_len) {
        return NOXTLS_RETURN_FAILED;
    }
    label_seed_len = label_len + seed_len;
    label_seed = (uint8_t*)malloc(label_seed_len);
    if(label_seed == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(label_seed, label, label_len);
    memcpy(label_seed + label_len, seed, seed_len);
    
    /* A(0) = seed (which is label || seed in this case) */
    if(label_seed_len > (uint32_t)tls12_prf_a_buflen) {
        free(label_seed);
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(A, label_seed, label_seed_len);
    A_len = label_seed_len;
    
    /* Generate output in chunks of hash_size */
    i = 0;
    while(offset < output_len) {
        noxtls_return_t rc;
        /* A(i) = HMAC_hash(secret, A(i-1)) */
        temp_len = hash_size;
        rc = hmac_compute(hash_algo, secret, secret_len, A, A_len, A, &temp_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            printf("[TLS12_DEBUG] tls12_prf: A(i) hmac rc=%d i=%lu A_len=%lu\n", rc, i, A_len);
            fflush(stdout);
            free(label_seed);
            return rc;
        }
        A_len = temp_len;
        
        /* HMAC_hash(secret, A(i) || label || seed) */
        if(A_len > UINT32_MAX - label_seed_len) {
            free(label_seed);
            return NOXTLS_RETURN_FAILED;
        }
        uint8_t *A_label_seed = (uint8_t*)malloc(A_len + label_seed_len);
        if(A_label_seed == NULL) {
            free(label_seed);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(A_label_seed, A, A_len);
        memcpy(A_label_seed + A_len, label_seed, label_seed_len);
        
        temp_len = hash_size;
        rc = hmac_compute(hash_algo, secret, secret_len, A_label_seed, A_len + label_seed_len, temp, &temp_len);
        free(A_label_seed);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            printf("[TLS12_DEBUG] tls12_prf: output hmac rc=%d i=%lu A_len=%lu seed_len=%lu\n",
                   rc, (unsigned long)i, (unsigned long)A_len, (unsigned long)label_seed_len);
            fflush(stdout);
            free(label_seed);
            return rc;
        }
        
        /* Copy to output */
        uint32_t copy_len = (output_len - offset < hash_size) ? (output_len - offset) : hash_size;
        memcpy(output + offset, temp, copy_len);
        offset += copy_len;
        i++;
    }
    
    free(label_seed);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Helper: HMAC-MD5 computation
 *
 * @param[in] key The key
 * @param[in] key_len The length of the key
 * @param[in] data The data to compute
 * @param[in] data_len The length of the data to compute
 * @param[out] mac The MAC
 * @return void
 */
static void hmac_md5_compute(const uint8_t *key, uint32_t key_len,
                             const uint8_t *data, uint32_t data_len,
                             uint8_t *mac)
{
    noxtls_sha_ctx_t ctx;
    uint8_t md5_key[64];
    uint8_t md5_ipad[64];
    uint8_t md5_opad[64];
    uint8_t inner_hash[16];
    uint32_t i;
    
    /* Prepare key: if key_len > 64, hash it */
    if(key_len > 64) {
        noxtls_md5_init(&ctx);
        noxtls_md5_update(&ctx, (uint8_t*)key, key_len);
        noxtls_md5_finish(&ctx, md5_key);
        memset(md5_key + 16, 0, 48);
    } else {
        memset(md5_key, 0, 64);
        memcpy(md5_key, key, key_len);
    }
    
    /* Create ipad and opad */
    for(i = 0; i < 64; i++) {
        md5_ipad[i] = md5_key[i] ^ 0x36;
        md5_opad[i] = md5_key[i] ^ 0x5C;
    }
    
    /* Inner hash: MD5(ipad || data) */
    noxtls_md5_init(&ctx);
    noxtls_md5_update(&ctx, md5_ipad, 64);
    if(data != NULL && data_len > 0) {
        noxtls_md5_update(&ctx, (uint8_t*)data, data_len);
    }
    noxtls_md5_finish(&ctx, inner_hash);
    
    /* Outer hash: MD5(opad || inner_hash) */
    noxtls_md5_init(&ctx);
    noxtls_md5_update(&ctx, md5_opad, 64);
    noxtls_md5_update(&ctx, inner_hash, 16);
    noxtls_md5_finish(&ctx, mac);
    
}

/**
 * @brief Helper: HMAC-SHA1 computation
 *
 * @param[in] key The key
 * @param[in] key_len The length of the key
 * @param[in] data The data to compute
 * @param[in] data_len The length of the data to compute
 * @param[out] mac The MAC
 * @return void
*/
static void hmac_sha1_compute(const uint8_t *key, uint32_t key_len,
                              const uint8_t *data, uint32_t data_len,
                              uint8_t *mac)
{
    noxtls_sha_ctx_t ctx;
    uint8_t sha1_key[64];
    uint8_t sha1_ipad[64];
    uint8_t sha1_opad[64];
    uint8_t inner_hash[20];
    uint32_t i;
    
    /* Prepare key: if key_len > 64, hash it */
    if(key_len > 64) {
        noxtls_sha1_init(&ctx, NOXTLS_HASH_SHA1);
        noxtls_sha1_update(&ctx, (uint8_t*)key, key_len);
        noxtls_sha1_finish(&ctx, sha1_key);
        memset(sha1_key + 20, 0, 44);
    } else {
        memset(sha1_key, 0, 64);
        memcpy(sha1_key, key, key_len);
    }
    
    /* Create ipad and opad */
    for(i = 0; i < 64; i++) {
        sha1_ipad[i] = sha1_key[i] ^ 0x36;
        sha1_opad[i] = sha1_key[i] ^ 0x5C;
    }
    
    /* Inner hash: SHA1(ipad || data) */
    noxtls_sha1_init(&ctx, NOXTLS_HASH_SHA1);
    noxtls_sha1_update(&ctx, sha1_ipad, 64);
    if(data != NULL && data_len > 0) {
        noxtls_sha1_update(&ctx, (uint8_t*)data, data_len);
    }
    noxtls_sha1_finish(&ctx, inner_hash);
    
    /* Outer hash: SHA1(opad || inner_hash) */
    noxtls_sha1_init(&ctx, NOXTLS_HASH_SHA1);
    noxtls_sha1_update(&ctx, sha1_opad, 64);
    noxtls_sha1_update(&ctx, inner_hash, 20);
    noxtls_sha1_finish(&ctx, mac);
    
}

/**
 * @brief TLS 1.0/1.1 PRF (Pseudo-Random Function)
 * 
 * PRF(secret, label, seed) = P_MD5(secret, label || seed) XOR P_SHA1(secret, label || seed)
 * 
 * P_MD5 and P_SHA1 are computed the same way as TLS 1.2 PRF but using MD5 and SHA-1 respectively.
 *
 * @param[in] secret The secret
 * @param[in] secret_len The length of the secret
 * @param[in] label The label
 * @param[in] label_len The length of the label
 * @param[in] seed The seed
 * @param[in] seed_len The length of the seed
 * @param[out] output The output
 * @param[in] output_len The length of the output
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the secret is NULL, NOXTLS_RETURN_FAILED if the label or seed is NULL
*/
noxtls_return_t tls10_prf(const uint8_t *secret, uint32_t secret_len,
                            const uint8_t *label, uint32_t label_len,
                            const uint8_t *seed, uint32_t seed_len,
                            uint8_t *output, uint32_t output_len)
{
    uint8_t *label_seed;
    uint32_t label_seed_len;
    uint8_t A_md5[64];
    uint8_t A_sha1[64];
    uint32_t A_md5_len;
    uint32_t A_sha1_len;
    uint32_t offset = 0;
    uint8_t temp_md5[16];
    uint8_t temp_sha1[20];
    uint32_t i;
    
    if(secret == NULL || label == NULL || seed == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Concatenate label and seed */
    if(label_len > UINT32_MAX - seed_len) {
        return NOXTLS_RETURN_FAILED;
    }
    label_seed_len = label_len + seed_len;
    label_seed = (uint8_t*)malloc(label_seed_len);
    if(label_seed == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(label_seed, label, label_len);
    memcpy(label_seed + label_len, seed, seed_len);
    
    /* A(0) = seed (which is label || seed) */
    memcpy(A_md5, label_seed, label_seed_len);
    A_md5_len = label_seed_len;
    memcpy(A_sha1, label_seed, label_seed_len);
    A_sha1_len = label_seed_len;
    
    /* Generate output in chunks */
    while(offset < output_len) {
        /* A(i) = HMAC_MD5(secret, A(i-1)) */
        hmac_md5_compute(secret, secret_len, A_md5, A_md5_len, A_md5);
        A_md5_len = 16;
        
        /* HMAC_MD5(secret, A(i) || label || seed) */
        if(A_md5_len > UINT32_MAX - label_seed_len) {
            free(label_seed);
            return NOXTLS_RETURN_FAILED;
        }
        uint8_t *A_label_seed_md5 = (uint8_t*)malloc(A_md5_len + label_seed_len);
        if(A_label_seed_md5 == NULL) {
            free(label_seed);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(A_label_seed_md5, A_md5, A_md5_len);
        memcpy(A_label_seed_md5 + A_md5_len, label_seed, label_seed_len);
        
        hmac_md5_compute(secret, secret_len, A_label_seed_md5, A_md5_len + label_seed_len, temp_md5);
        free(A_label_seed_md5);
        
        /* A(i) = HMAC_SHA1(secret, A(i-1)) */
        hmac_sha1_compute(secret, secret_len, A_sha1, A_sha1_len, A_sha1);
        A_sha1_len = 20;
        
        /* HMAC_SHA1(secret, A(i) || label || seed) */
        if(A_sha1_len > UINT32_MAX - label_seed_len) {
            free(label_seed);
            return NOXTLS_RETURN_FAILED;
        }
        uint8_t *A_label_seed_sha1 = (uint8_t*)malloc(A_sha1_len + label_seed_len);
        if(A_label_seed_sha1 == NULL) {
            free(label_seed);
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(A_label_seed_sha1, A_sha1, A_sha1_len);
        memcpy(A_label_seed_sha1 + A_sha1_len, label_seed, label_seed_len);
        
        hmac_sha1_compute(secret, secret_len, A_label_seed_sha1, A_sha1_len + label_seed_len, temp_sha1);
        free(A_label_seed_sha1);
        
        /* XOR MD5 and SHA-1 outputs */
        uint32_t chunk_len = 16;  /* Use MD5 length (16) as base */
        uint32_t copy_len = (output_len - offset < chunk_len) ? (output_len - offset) : chunk_len;
        
        for(i = 0; i < copy_len; i++) {
            output[offset + i] = temp_md5[i] ^ temp_sha1[i];
        }
        offset += copy_len;
    }
    
    free(label_seed);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief HKDF-Extract (RFC 5869)
 * 
 * PRK = HMAC-Hash(salt, IKM)
 */
noxtls_return_t hkdf_extract(noxtls_hash_algos_t hash_algo,
                               const uint8_t *salt, uint32_t salt_len,
                               const uint8_t *ikm, uint32_t ikm_len,
                               uint8_t *prk, uint32_t *prk_len)
{
    uint32_t hash_size = get_hash_output_size(hash_algo);
    uint8_t zero_salt[128];  /* Zero salt if not provided */
    
    if(ikm == NULL || prk == NULL || prk_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(*prk_len < hash_size) {
        *prk_len = hash_size;
        return NOXTLS_RETURN_FAILED;
    }
    
    /* If salt is NULL or zero length, use zero salt */
    if(salt == NULL || salt_len == 0) {
        memset(zero_salt, 0, hash_size);
        salt = zero_salt;
        salt_len = hash_size;
    }
    
    /* PRK = HMAC-Hash(salt, IKM) */
    return hmac_compute(hash_algo, salt, salt_len, ikm, ikm_len, prk, prk_len);
}

/**
 * @brief HKDF-Expand (RFC 5869)
 * 
 * OKM = T(1) || T(2) || ... || T(N)
 * where T(0) = empty string
 *       T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
 */
noxtls_return_t hkdf_expand(noxtls_hash_algos_t hash_algo,
                               const uint8_t *prk, uint32_t prk_len,
                               const uint8_t *info, uint32_t info_len,
                               uint8_t *okm, uint32_t okm_len)
{
    uint32_t hash_size = get_hash_output_size(hash_algo);
    uint8_t T[64];  /* Current T(i) */
    uint32_t offset = 0;
    uint32_t i = 1;
    uint32_t N;
    
    if(prk == NULL || okm == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(okm_len > 255 * hash_size) {
        return NOXTLS_RETURN_INVALID_PARAM;  /* RFC 5869 limit */
    }
    
    N = (okm_len + hash_size - 1) / hash_size;  /* Number of hash blocks needed */
    
    while(offset < okm_len && i <= N) {
        noxtls_return_t rc;
        uint32_t T_info_i_len = (i == 1 ? 0 : hash_size) + (info != NULL ? info_len : 0) + 1;
        /* T(i) = HMAC-Hash(PRK, T(i-1) || info || i) */
        /* For i=1: T(0) is empty, so input is info || 1 */
        /* For i>1: input is T(i-1) || info || i */
        uint8_t *T_info_i = (uint8_t*)malloc(T_info_i_len);
        if(T_info_i == NULL) {
            return NOXTLS_RETURN_FAILED;
        }
        
        uint32_t pos = 0;
        if(i > 1) {
            memcpy(T_info_i + pos, T, hash_size);
            pos += hash_size;
        }
        if(info != NULL && info_len > 0) {
            memcpy(T_info_i + pos, info, info_len);
            pos += info_len;
        }
        T_info_i[pos] = (uint8_t)i;  /* Counter */
        
        uint32_t T_len = hash_size;
        rc = hmac_compute(hash_algo, prk, prk_len, T_info_i, T_info_i_len, T, &T_len);
        free(T_info_i);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        
        /* Copy to output */
        uint32_t copy_len = (okm_len - offset < hash_size) ? (okm_len - offset) : hash_size;
        memcpy(okm + offset, T, copy_len);
        offset += copy_len;
        i++;
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief TLS 1.3 HKDF-Expand-Label (RFC 8446 Section 7.1)
 * 
 * HKDF-Expand-Label(Secret, Label, Context, Length) =
 *     HKDF-Expand(Secret, HkdfLabel, Length)
 * 
 * where HkdfLabel = struct {
 *     uint16 length;
 *     opaque label<7..255> = "tls13 " + Label;
 *     opaque context<0..255> = Context;
 * };
 */
static noxtls_return_t hkdf_expand_label_with_prefix(noxtls_hash_algos_t hash_algo,
                                          const uint8_t *secret, uint32_t secret_len,
                                          const uint8_t *prefix, uint32_t prefix_len,
                                          const uint8_t *label, uint32_t label_len,
                                          const uint8_t *context, uint32_t context_len,
                                          uint8_t *output, uint32_t output_len)
{
    uint8_t *hkdf_label;
    uint32_t hkdf_label_len;
    uint32_t offset = 0;
    uint32_t full_label_len;
    noxtls_return_t rc;

    if(secret == NULL || prefix == NULL || label == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(label_len > 255u || context_len > 255u || prefix_len > 255u) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(context == NULL && context_len > 0U) {
        return NOXTLS_RETURN_NULL;
    }
    if(label_len > (255u - prefix_len)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    full_label_len = prefix_len + label_len;

    if(full_label_len > UINT32_MAX - context_len - 4U) {
        return NOXTLS_RETURN_FAILED;
    }
    hkdf_label_len = 2U + 1U + full_label_len + 1U + context_len;
    hkdf_label = (uint8_t *)noxtls_malloc(hkdf_label_len);
    if(hkdf_label == NULL) {
        return NOXTLS_RETURN_FAILED;
    }

    hkdf_label[offset++] = (uint8_t)((output_len >> 8) & 0xFF);
    hkdf_label[offset++] = (uint8_t)(output_len & 0xFF);
    hkdf_label[offset++] = (uint8_t)(full_label_len & 0xFF);
    memcpy(hkdf_label + offset, prefix, prefix_len);
    offset += prefix_len;
    memcpy(hkdf_label + offset, label, label_len);
    offset += label_len;
    hkdf_label[offset++] = (uint8_t)(context_len & 0xFF);
    if(context != NULL && context_len > 0U) {
        memcpy(hkdf_label + offset, context, context_len);
        offset += context_len;
    }

    rc = hkdf_expand(hash_algo, secret, secret_len, hkdf_label, offset, output, output_len);
    noxtls_free(hkdf_label);
    return rc;
}
/**
 * @brief HKDF expand label
 *
 * @param[in] hash_algo The hash algorithm to use for the HKDF expand label
 * @param[in] secret The secret to use for the HKDF expand label
 * @param[in] secret_len The length of the secret to use for the HKDF expand label
 * @param[in] label The label to use for the HKDF expand label
 * @param[in] context The context to use for the HKDF expand label
 * @param[in] context_len The length of the context to use for the HKDF expand label
 * @param[out] output The output to use for the HKDF expand label
 * @param[in] output_len The length of the output to use for the HKDF expand label
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the secret is NULL, 
 * NOXTLS_RETURN_INVALID_PARAM if the label or context is NULL, NOXTLS_RETURN_FAILED if the output is NULL,
 * NOXTLS_RETURN_INVALID_ALGORITHM if the hash algorithm is not supported
 */
noxtls_return_t tls13_hkdf_expand_label(noxtls_hash_algos_t hash_algo,
                                          const uint8_t *secret, uint32_t secret_len,
                                          const uint8_t *label, uint32_t label_len,
                                          const uint8_t *context, uint32_t context_len,
                                          uint8_t *output, uint32_t output_len)
{
    static const uint8_t tls13_prefix[] = { 't', 'l', 's', '1', '3', ' ' };
    return hkdf_expand_label_with_prefix(hash_algo, secret, secret_len,
                                         tls13_prefix, (uint32_t)sizeof(tls13_prefix),
                                         label, label_len, context, context_len, output, output_len);
}

/**
 * @brief HKDF expand label
 *
 * @param[in] hash_algo The hash algorithm to use for the HKDF expand label
 * @param[in] secret The secret to use for the HKDF expand label
 * @param[in] secret_len The length of the secret to use for the HKDF expand label
 * @param[in] label The label to use for the HKDF expand label
 * @param[in] context The context to use for the HKDF expand label
 * @param[in] context_len The length of the context to use for the HKDF expand label
 * @param[out] output The output to use for the HKDF expand label
 * @param[in] output_len The length of the output to use for the HKDF expand label
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the secret is NULL, 
 * NOXTLS_RETURN_INVALID_PARAM if the label or context is NULL, NOXTLS_RETURN_FAILED if the output is NULL,
 * NOXTLS_RETURN_INVALID_ALGORITHM if the hash algorithm is not supported
 */
noxtls_return_t dtls13_hkdf_expand_label(noxtls_hash_algos_t hash_algo,
                                          const uint8_t *secret, uint32_t secret_len,
                                          const uint8_t *label, uint32_t label_len,
                                          const uint8_t *context, uint32_t context_len,
                                          uint8_t *output, uint32_t output_len)
{
    static const uint8_t dtls13_prefix[] = { 'd', 't', 'l', 's', '1', '3' };
    return hkdf_expand_label_with_prefix(hash_algo, secret, secret_len,
                                         dtls13_prefix, (uint32_t)sizeof(dtls13_prefix),
                                         label, label_len, context, context_len, output, output_len);
}

/**
 * @brief TLS 1.3 Derive-Secret (RFC 8446 Section 7.1)
 * 
 * Derive-Secret(Secret, Label, Messages) =
 *     HKDF-Expand-Label(Secret, Label,
 *                      Hash(Messages), Hash.length)
 *
 * @param[in] hash_algo The hash algorithm to use for the HKDF expand label
 * @param[in] secret The secret to use for the HKDF expand label
 * @param[in] secret_len The length of the secret to use for the HKDF expand label
 * @param[in] label The label to use for the HKDF expand label
 * @param[in] messages The messages to use for the HKDF expand label
 * @param[in] messages_len The length of the messages to use for the HKDF expand label
 *
 * @param[out] output The output to use for the HKDF expand label
 * @param[in] output_len The length of the output to use for the HKDF expand label
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the secret is NULL, 
 * NOXTLS_RETURN_INVALID_PARAM if the label or context is NULL, NOXTLS_RETURN_FAILED if the output is NULL,
 * NOXTLS_RETURN_INVALID_ALGORITHM if the hash algorithm is not supported
 */
noxtls_return_t tls13_derive_secret(noxtls_hash_algos_t hash_algo,
                                      const uint8_t *secret, uint32_t secret_len,
                                      const uint8_t *label, uint32_t label_len,
                                      const uint8_t *messages, uint32_t messages_len,
                                      uint8_t *output, uint32_t output_len)
{
    uint8_t hash[64];  /* Max hash size */
    uint32_t hash_len;
    noxtls_return_t rc;
    
    if(secret == NULL || label == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    /* Hash(Messages) */
    if(messages != NULL && messages_len > 0) {
        if(hash_algo == NOXTLS_HASH_SHA_256) {
            noxtls_sha_ctx_t sha_ctx;
            noxtls_sha256_init(&sha_ctx, hash_algo);
            noxtls_sha256_update(&sha_ctx, (uint8_t*)messages, messages_len);
            hash_len = 32;
            rc = noxtls_sha256_finish(&sha_ctx, hash);
        } else if(hash_algo == NOXTLS_HASH_SHA_384) {
            noxtls_sha512_ctx_t sha_ctx;
            noxtls_sha512_init(&sha_ctx, hash_algo);
            noxtls_sha512_update(&sha_ctx, (uint8_t*)messages, messages_len);
            hash_len = 48;
            rc = noxtls_sha512_finish(&sha_ctx, hash);
        } else {
            return NOXTLS_RETURN_INVALID_ALGORITHM;
        }
        
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    } else {
        /* Empty messages - use Hash("") */
        if(hash_algo == NOXTLS_HASH_SHA_256) {
            noxtls_sha_ctx_t sha_ctx;
            noxtls_sha256_init(&sha_ctx, hash_algo);
            hash_len = 32;
            rc = noxtls_sha256_finish(&sha_ctx, hash);
        } else if(hash_algo == NOXTLS_HASH_SHA_384) {
            noxtls_sha512_ctx_t sha_ctx;
            noxtls_sha512_init(&sha_ctx, hash_algo);
            hash_len = 48;
            rc = noxtls_sha512_finish(&sha_ctx, hash);
        } else {
            return NOXTLS_RETURN_INVALID_ALGORITHM;
        }
        
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    
    /* HKDF-Expand-Label(Secret, Label, Hash(Messages), Hash.length) */
    return tls13_hkdf_expand_label(hash_algo, secret, secret_len, label, label_len, hash, hash_len, output, output_len);
}

/**
 * @brief DTLS 1.3 Derive-Secret (RFC 9147 Section 5.9)
 * 
 * Derive-Secret(Secret, Label, Messages) =
 *     HKDF-Expand-Label(Secret, Label,
 *                      Hash(Messages), Hash.length)
 *
 * @param[in] hash_algo The hash algorithm to use for the HKDF expand label
 * @param[in] secret The secret to use for the HKDF expand label
 * @param[in] secret_len The length of the secret to use for the HKDF expand label
 * @param[in] label The label to use for the HKDF expand label
 * @param[in] messages The messages to use for the HKDF expand label
 * @param[in] messages_len The length of the messages to use for the HKDF expand label
 * @param[out] output The output to use for the HKDF expand label
 * @param[in] output_len The length of the output to use for the HKDF expand label
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if the secret is NULL, 
 * NOXTLS_RETURN_INVALID_PARAM if the label or context is NULL, NOXTLS_RETURN_FAILED if the output is NULL,
 * NOXTLS_RETURN_INVALID_ALGORITHM if the hash algorithm is not supported
 */
noxtls_return_t dtls13_derive_secret(noxtls_hash_algos_t hash_algo,
                                      const uint8_t *secret, uint32_t secret_len,
                                      const uint8_t *label, uint32_t label_len,
                                      const uint8_t *messages, uint32_t messages_len,
                                      uint8_t *output, uint32_t output_len)
{
    uint8_t hash[64];
    uint32_t hash_len;
    noxtls_return_t rc;

    if(secret == NULL || label == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(messages != NULL && messages_len > 0U) {
        if(hash_algo == NOXTLS_HASH_SHA_256) {
            noxtls_sha_ctx_t sha_ctx;
            noxtls_sha256_init(&sha_ctx, hash_algo);
            noxtls_sha256_update(&sha_ctx, (uint8_t*)messages, messages_len);
            hash_len = 32;
            rc = noxtls_sha256_finish(&sha_ctx, hash);
        } else if(hash_algo == NOXTLS_HASH_SHA_384) {
            noxtls_sha512_ctx_t sha_ctx;
            noxtls_sha512_init(&sha_ctx, hash_algo);
            noxtls_sha512_update(&sha_ctx, (uint8_t*)messages, messages_len);
            hash_len = 48;
            rc = noxtls_sha512_finish(&sha_ctx, hash);
        } else {
            return NOXTLS_RETURN_INVALID_ALGORITHM;
        }
    } else {
        if(hash_algo == NOXTLS_HASH_SHA_256) {
            noxtls_sha_ctx_t sha_ctx;
            noxtls_sha256_init(&sha_ctx, hash_algo);
            hash_len = 32;
            rc = noxtls_sha256_finish(&sha_ctx, hash);
        } else if(hash_algo == NOXTLS_HASH_SHA_384) {
            noxtls_sha512_ctx_t sha_ctx;
            noxtls_sha512_init(&sha_ctx, hash_algo);
            hash_len = 48;
            rc = noxtls_sha512_finish(&sha_ctx, hash);
        } else {
            return NOXTLS_RETURN_INVALID_ALGORITHM;
        }
    }

    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    return dtls13_hkdf_expand_label(hash_algo, secret, secret_len, label, label_len, hash, hash_len, output, output_len);
}
