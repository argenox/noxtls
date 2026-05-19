/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
*
* File:    noxtls_slhdsa.c
* Summary: SLH-DSA (NIST FIPS 205) API facade and parameter contracts.
*/

#include <stdint.h>
#include <string.h>

#include "common/noxtls_ct.h"
#include "drbg/noxtls_drbg.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha3/noxtls_sha3.h"
#include "mdigest/sha512/noxtls_sha512.h"
#include "noxtls_slhdsa.h"

#define SLHDSA_WOTS_LG_W 4u
#define SLHDSA_WOTS_W 16u
#define SLHDSA_WOTS_LEN2 3u
#define SLHDSA_MAX_N 32u
#define SLHDSA_MAX_WOTS_LEN 67u
#define SLHDSA_MAX_D 22u
#define SLHDSA_MAX_HP 22u
#define SLHDSA_MAX_A 14u
#define SLHDSA_MAX_K 35u
#define SLHDSA_MAX_MD_LEN 49u
#define SLHDSA_ADRS_LEN 32u
#define SLHDSA_SHA2_ADRS_LEN 22u
#define SLHDSA_SHA256_BLOCK_LEN 64u
#define SLHDSA_SHA512_BLOCK_LEN 128u
#define SLHDSA_SHA256_LEN 32u
#define SLHDSA_SHA512_LEN 64u
#define SLHDSA_ADRS_TYPE_WOTS_HASH 0u
#define SLHDSA_ADRS_TYPE_WOTS_PK 1u
#define SLHDSA_ADRS_TYPE_TREE 2u
#define SLHDSA_ADRS_TYPE_FORS_TREE 3u
#define SLHDSA_ADRS_TYPE_FORS_ROOTS 4u
#define SLHDSA_ADRS_TYPE_WOTS_PRF 5u
#define SLHDSA_ADRS_TYPE_FORS_PRF 6u

typedef struct
{
    slhdsa_sizes_t sizes;
    uint32_t n;
    uint32_t h;
    uint32_t d;
    uint32_t hp;
    uint32_t a;
    uint32_t k;
    uint32_t md_len;
    uint32_t wots_len;
} slhdsa_params_t;

/**
 * @brief Resolve fixed key and signature sizes for an SLH-DSA parameter set.
 * @param[in] param FIPS 205 SLH-DSA parameter set.
 * @param[out] sizes Output structure populated on success.
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if sizes is NULL.
 * @return NOXTLS_RETURN_INVALID_PARAM if param is unsupported.
 */
static noxtls_return_t slhdsa_get_sizes(noxtls_slhdsa_param_t param, slhdsa_sizes_t *sizes)
{
    if(sizes == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    memset(sizes, 0, sizeof(*sizes));
    switch(param) {
        case NOXTLS_SLHDSA_SHA2_128S:
        case NOXTLS_SLHDSA_SHAKE_128S:
            sizes->public_key_len = 32u;
            sizes->secret_key_len = 64u;
            sizes->signature_len = 7856u;
            sizes->security_category = 1u;
            sizes->small_variant = 1u;
            break;
        case NOXTLS_SLHDSA_SHA2_128F:
        case NOXTLS_SLHDSA_SHAKE_128F:
            sizes->public_key_len = 32u;
            sizes->secret_key_len = 64u;
            sizes->signature_len = 17088u;
            sizes->security_category = 1u;
            sizes->small_variant = 0u;
            break;
        case NOXTLS_SLHDSA_SHA2_192S:
        case NOXTLS_SLHDSA_SHAKE_192S:
            sizes->public_key_len = 48u;
            sizes->secret_key_len = 96u;
            sizes->signature_len = 16224u;
            sizes->security_category = 3u;
            sizes->small_variant = 1u;
            break;
        case NOXTLS_SLHDSA_SHA2_192F:
        case NOXTLS_SLHDSA_SHAKE_192F:
            sizes->public_key_len = 48u;
            sizes->secret_key_len = 96u;
            sizes->signature_len = 35664u;
            sizes->security_category = 3u;
            sizes->small_variant = 0u;
            break;
        case NOXTLS_SLHDSA_SHA2_256S:
        case NOXTLS_SLHDSA_SHAKE_256S:
            sizes->public_key_len = 64u;
            sizes->secret_key_len = 128u;
            sizes->signature_len = 29792u;
            sizes->security_category = 5u;
            sizes->small_variant = 1u;
            break;
        case NOXTLS_SLHDSA_SHA2_256F:
        case NOXTLS_SLHDSA_SHAKE_256F:
            sizes->public_key_len = 64u;
            sizes->secret_key_len = 128u;
            sizes->signature_len = 49856u;
            sizes->security_category = 5u;
            sizes->small_variant = 0u;
            break;
        default:
            return NOXTLS_RETURN_INVALID_PARAM;
    }

    sizes->hash_family_sha2 = (param >= NOXTLS_SLHDSA_SHA2_128S && param <= NOXTLS_SLHDSA_SHA2_256F) ? 1u : 0u;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Resolve all FIPS 205 parameters used by the SLH-DSA core.
 * @param[in] param FIPS 205 SLH-DSA parameter set.
 * @param[out] p Output parameter metadata.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_get_params(noxtls_slhdsa_param_t param, slhdsa_params_t *p)
{
    noxtls_return_t rc;

    if(p == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    memset(p, 0, sizeof(*p));
    rc = slhdsa_get_sizes(param, &p->sizes);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    switch(param) {
        case NOXTLS_SLHDSA_SHA2_128S:
        case NOXTLS_SLHDSA_SHAKE_128S:
            p->n = 16u;
            p->h = 63u;
            p->d = 7u;
            p->hp = 9u;
            p->a = 12u;
            p->k = 14u;
            p->md_len = 30u;
            p->wots_len = (2u * p->n) + SLHDSA_WOTS_LEN2;
            return NOXTLS_RETURN_SUCCESS;
        case NOXTLS_SLHDSA_SHA2_128F:
        case NOXTLS_SLHDSA_SHAKE_128F:
            p->n = 16u;
            p->h = 66u;
            p->d = 22u;
            p->hp = 3u;
            p->a = 6u;
            p->k = 33u;
            p->md_len = 34u;
            p->wots_len = (2u * p->n) + SLHDSA_WOTS_LEN2;
            return NOXTLS_RETURN_SUCCESS;
        case NOXTLS_SLHDSA_SHA2_192S:
        case NOXTLS_SLHDSA_SHAKE_192S:
            p->n = 24u;
            p->h = 63u;
            p->d = 7u;
            p->hp = 9u;
            p->a = 14u;
            p->k = 17u;
            p->md_len = 39u;
            p->wots_len = (2u * p->n) + SLHDSA_WOTS_LEN2;
            return NOXTLS_RETURN_SUCCESS;
        case NOXTLS_SLHDSA_SHA2_192F:
        case NOXTLS_SLHDSA_SHAKE_192F:
            p->n = 24u;
            p->h = 66u;
            p->d = 22u;
            p->hp = 3u;
            p->a = 8u;
            p->k = 33u;
            p->md_len = 42u;
            p->wots_len = (2u * p->n) + SLHDSA_WOTS_LEN2;
            return NOXTLS_RETURN_SUCCESS;
        case NOXTLS_SLHDSA_SHA2_256S:
        case NOXTLS_SLHDSA_SHAKE_256S:
            p->n = 32u;
            p->h = 64u;
            p->d = 8u;
            p->hp = 8u;
            p->a = 14u;
            p->k = 22u;
            p->md_len = 47u;
            p->wots_len = (2u * p->n) + SLHDSA_WOTS_LEN2;
            return NOXTLS_RETURN_SUCCESS;
        case NOXTLS_SLHDSA_SHA2_256F:
        case NOXTLS_SLHDSA_SHAKE_256F:
            p->n = 32u;
            p->h = 68u;
            p->d = 17u;
            p->hp = 4u;
            p->a = 9u;
            p->k = 35u;
            p->md_len = 49u;
            p->wots_len = (2u * p->n) + SLHDSA_WOTS_LEN2;
            return NOXTLS_RETURN_SUCCESS;
        default:
            return NOXTLS_RETURN_INVALID_PARAM;
    }
}

/**
 * @brief Store a 32-bit integer in big-endian form.
 * @param[out] out Output buffer.
 * @param[in] value Value to encode.
 * @return void.
 */
static void slhdsa_store32(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

/**
 * @brief Store a 64-bit integer in big-endian form.
 * @param[out] out Output buffer.
 * @param[in] value Value to encode.
 * @return void.
 */
static void slhdsa_store64(uint8_t out[8], uint64_t value)
{
    uint32_t i;

    for(i = 0u; i < 8u; i++) {
        out[7u - i] = (uint8_t)(value >> (8u * i));
    }
}

/**
 * @brief Read a big-endian integer from a byte string.
 * @param[in] in Input byte string.
 * @param[in] len Number of bytes to read.
 * @return Decoded integer.
 */
static uint64_t slhdsa_load_be(const uint8_t *in, uint32_t len)
{
    uint64_t value = 0u;
    uint32_t i;

    for(i = 0u; i < len; i++) {
        value = (value << 8u) | in[i];
    }
    return value;
}

/**
 * @brief Set the layer address field in an ADRS object.
 * @param[in,out] adrs Address object.
 * @param[in] layer Layer value.
 * @return void.
 */
static void slhdsa_adrs_set_layer(uint8_t adrs[SLHDSA_ADRS_LEN], uint32_t layer)
{
    slhdsa_store32(adrs, layer);
}

/**
 * @brief Set the tree address field in an ADRS object.
 * @param[in,out] adrs Address object.
 * @param[in] tree Tree value.
 * @return void.
 */
static void slhdsa_adrs_set_tree(uint8_t adrs[SLHDSA_ADRS_LEN], uint64_t tree)
{
    slhdsa_store64(adrs + 8u, tree);
}

/**
 * @brief Set ADRS type and clear type-specific fields.
 * @param[in,out] adrs Address object.
 * @param[in] type Address type.
 * @return void.
 */
static void slhdsa_adrs_set_type(uint8_t adrs[SLHDSA_ADRS_LEN], uint32_t type)
{
    slhdsa_store32(adrs + 16u, type);
    memset(adrs + 20u, 0, 12u);
}

/**
 * @brief Set the key-pair address field.
 * @param[in,out] adrs Address object.
 * @param[in] value Key-pair address.
 * @return void.
 */
static void slhdsa_adrs_set_keypair(uint8_t adrs[SLHDSA_ADRS_LEN], uint32_t value)
{
    slhdsa_store32(adrs + 20u, value);
}

/**
 * @brief Set the chain address field.
 * @param[in,out] adrs Address object.
 * @param[in] value Chain address.
 * @return void.
 */
static void slhdsa_adrs_set_chain(uint8_t adrs[SLHDSA_ADRS_LEN], uint32_t value)
{
    slhdsa_store32(adrs + 24u, value);
}

/**
 * @brief Set the hash address field.
 * @param[in,out] adrs Address object.
 * @param[in] value Hash address.
 * @return void.
 */
static void slhdsa_adrs_set_hash(uint8_t adrs[SLHDSA_ADRS_LEN], uint32_t value)
{
    slhdsa_store32(adrs + 28u, value);
}

/**
 * @brief Set the tree height field.
 * @param[in,out] adrs Address object.
 * @param[in] value Tree height.
 * @return void.
 */
static void slhdsa_adrs_set_tree_height(uint8_t adrs[SLHDSA_ADRS_LEN], uint32_t value)
{
    slhdsa_store32(adrs + 24u, value);
}

/**
 * @brief Set the tree index field.
 * @param[in,out] adrs Address object.
 * @param[in] value Tree index.
 * @return void.
 */
static void slhdsa_adrs_set_tree_index(uint8_t adrs[SLHDSA_ADRS_LEN], uint32_t value)
{
    slhdsa_store32(adrs + 28u, value);
}

/**
 * @brief Get the key-pair address field.
 * @param[in] adrs Address object.
 * @return Key-pair address.
 */
static uint32_t slhdsa_adrs_get_keypair(const uint8_t adrs[SLHDSA_ADRS_LEN])
{
    return (uint32_t)slhdsa_load_be(adrs + 20u, 4u);
}

/**
 * @brief Squeeze SHAKE256 over up to four input fragments.
 * @param[in] a First fragment.
 * @param[in] a_len First fragment length.
 * @param[in] b Second fragment.
 * @param[in] b_len Second fragment length.
 * @param[in] c Third fragment.
 * @param[in] c_len Third fragment length.
 * @param[in] d Fourth fragment.
 * @param[in] d_len Fourth fragment length.
 * @param[out] out Output buffer.
 * @param[in] out_len Output length.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_shake256_4(const uint8_t *a,
                                         uint32_t a_len,
                                         const uint8_t *b,
                                         uint32_t b_len,
                                         const uint8_t *c,
                                         uint32_t c_len,
                                         const uint8_t *d,
                                         uint32_t d_len,
                                         uint8_t *out,
                                         uint32_t out_len)
{
    noxtls_sha3_ctx_t ctx;
    noxtls_return_t rc;

    rc = noxtls_shake256_init(&ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    if(a_len != 0u) {
        rc = noxtls_shake256_update(&ctx, a, a_len);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    }
    if(b_len != 0u) {
        rc = noxtls_shake256_update(&ctx, b, b_len);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    }
    if(c_len != 0u) {
        rc = noxtls_shake256_update(&ctx, c, c_len);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    }
    if(d_len != 0u) {
        rc = noxtls_shake256_update(&ctx, d, d_len);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    }
    rc = noxtls_shake256_final(&ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    return noxtls_shake256_squeeze(&ctx, out, out_len);
}

/**
 * @brief Compress a 32-byte ADRS object for SHA2 SLH-DSA functions.
 * @param[in] adrs Expanded FIPS 205 address.
 * @param[out] out Compressed 22-byte address.
 * @return void.
 */
static void slhdsa_compress_adrs(const uint8_t adrs[SLHDSA_ADRS_LEN], uint8_t out[SLHDSA_SHA2_ADRS_LEN])
{
    out[0] = adrs[3];
    memcpy(out + 1u, adrs + 8u, 8u);
    out[9] = adrs[19];
    memcpy(out + 10u, adrs + 20u, 12u);
}

/**
 * @brief Hash fragments with SHA-256.
 * @param[in] a First fragment.
 * @param[in] a_len First fragment length.
 * @param[in] b Second fragment.
 * @param[in] b_len Second fragment length.
 * @param[in] c Third fragment.
 * @param[in] c_len Third fragment length.
 * @param[in] d Fourth fragment.
 * @param[in] d_len Fourth fragment length.
 * @param[out] out SHA-256 digest.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_sha256_4(const uint8_t *a,
                                       uint32_t a_len,
                                       const uint8_t *b,
                                       uint32_t b_len,
                                       const uint8_t *c,
                                       uint32_t c_len,
                                       const uint8_t *d,
                                       uint32_t d_len,
                                       uint8_t out[SLHDSA_SHA256_LEN])
{
    noxtls_sha_ctx_t ctx;
    noxtls_return_t rc;

    rc = noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    if(a_len != 0u) {
        rc = noxtls_sha256_update(&ctx, a, a_len);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    }
    if(b_len != 0u) {
        rc = noxtls_sha256_update(&ctx, b, b_len);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    }
    if(c_len != 0u) {
        rc = noxtls_sha256_update(&ctx, c, c_len);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    }
    if(d_len != 0u) {
        rc = noxtls_sha256_update(&ctx, d, d_len);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    }
    return noxtls_sha256_finish(&ctx, out);
}

/**
 * @brief Hash fragments with SHA-512.
 * @param[in] a First fragment.
 * @param[in] a_len First fragment length.
 * @param[in] b Second fragment.
 * @param[in] b_len Second fragment length.
 * @param[in] c Third fragment.
 * @param[in] c_len Third fragment length.
 * @param[in] d Fourth fragment.
 * @param[in] d_len Fourth fragment length.
 * @param[out] out SHA-512 digest.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_sha512_4(const uint8_t *a,
                                       uint32_t a_len,
                                       const uint8_t *b,
                                       uint32_t b_len,
                                       const uint8_t *c,
                                       uint32_t c_len,
                                       const uint8_t *d,
                                       uint32_t d_len,
                                       uint8_t out[SLHDSA_SHA512_LEN])
{
    noxtls_sha512_ctx_t ctx;
    noxtls_return_t rc;

    rc = noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    if(a_len != 0u) {
        rc = noxtls_sha512_update(&ctx, a, a_len);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    }
    if(b_len != 0u) {
        rc = noxtls_sha512_update(&ctx, b, b_len);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    }
    if(c_len != 0u) {
        rc = noxtls_sha512_update(&ctx, c, c_len);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    }
    if(d_len != 0u) {
        rc = noxtls_sha512_update(&ctx, d, d_len);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    }
    return noxtls_sha512_finish(&ctx, out);
}

/**
 * @brief HMAC using SHA-256 or SHA-512.
 * @param[in] use_sha512 Non-zero for SHA-512, zero for SHA-256.
 * @param[in] key HMAC key.
 * @param[in] key_len Key length.
 * @param[in] a First message fragment.
 * @param[in] a_len First fragment length.
 * @param[in] b Second message fragment.
 * @param[in] b_len Second fragment length.
 * @param[out] out Output digest.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_hmac(uint8_t use_sha512,
                                   const uint8_t *key,
                                   uint32_t key_len,
                                   const uint8_t *a,
                                   uint32_t a_len,
                                   const uint8_t *b,
                                   uint32_t b_len,
                                   uint8_t out[SLHDSA_SHA512_LEN])
{
    uint8_t key_block[SLHDSA_SHA512_BLOCK_LEN];
    uint8_t ipad[SLHDSA_SHA512_BLOCK_LEN];
    uint8_t opad[SLHDSA_SHA512_BLOCK_LEN];
    uint8_t inner[SLHDSA_SHA512_LEN];
    uint32_t block_len = use_sha512 ? SLHDSA_SHA512_BLOCK_LEN : SLHDSA_SHA256_BLOCK_LEN;
    uint32_t digest_len = use_sha512 ? SLHDSA_SHA512_LEN : SLHDSA_SHA256_LEN;
    uint32_t i;
    noxtls_return_t rc;

    memset(key_block, 0, sizeof(key_block));
    if(key_len > block_len) {
        if(use_sha512) {
            rc = slhdsa_sha512_4(key, key_len, NULL, 0u, NULL, 0u, NULL, 0u, key_block);
        } else {
            rc = slhdsa_sha256_4(key, key_len, NULL, 0u, NULL, 0u, NULL, 0u, key_block);
        }
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    } else {
        memcpy(key_block, key, key_len);
    }
    for(i = 0u; i < block_len; i++) {
        ipad[i] = (uint8_t)(key_block[i] ^ 0x36u);
        opad[i] = (uint8_t)(key_block[i] ^ 0x5cu);
    }
    if(use_sha512) {
        rc = slhdsa_sha512_4(ipad, block_len, a, a_len, b, b_len, NULL, 0u, inner);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        return slhdsa_sha512_4(opad, block_len, inner, digest_len, NULL, 0u, NULL, 0u, out);
    }
    rc = slhdsa_sha256_4(ipad, block_len, a, a_len, b, b_len, NULL, 0u, inner);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    return slhdsa_sha256_4(opad, block_len, inner, digest_len, NULL, 0u, NULL, 0u, out);
}

/**
 * @brief MGF1 using SHA-256 or SHA-512.
 * @param[in] use_sha512 Non-zero for SHA-512, zero for SHA-256.
 * @param[in] seed Seed buffer.
 * @param[in] seed_len Seed length.
 * @param[out] out Output mask.
 * @param[in] out_len Output length.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_mgf1(uint8_t use_sha512,
                                   const uint8_t *seed,
                                   uint32_t seed_len,
                                   uint8_t *out,
                                   uint32_t out_len)
{
    uint8_t counter[4];
    uint8_t digest[SLHDSA_SHA512_LEN];
    uint32_t digest_len = use_sha512 ? SLHDSA_SHA512_LEN : SLHDSA_SHA256_LEN;
    uint32_t produced = 0u;
    uint32_t ctr = 0u;
    noxtls_return_t rc;

    while(produced < out_len) {
        uint32_t take;

        slhdsa_store32(counter, ctr);
        if(use_sha512) {
            rc = slhdsa_sha512_4(seed, seed_len, counter, sizeof(counter), NULL, 0u, NULL, 0u, digest);
        } else {
            rc = slhdsa_sha256_4(seed, seed_len, counter, sizeof(counter), NULL, 0u, NULL, 0u, digest);
        }
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        take = out_len - produced;
        if(take > digest_len) {
            take = digest_len;
        }
        memcpy(out + produced, digest, take);
        produced += take;
        ctr++;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Produce DRBG random bytes.
 * @param[out] out Output buffer.
 * @param[in] out_len Output length in bytes.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_random(uint8_t *out, uint32_t out_len)
{
    drbg_state_t drbg;
    noxtls_return_t rc;

    rc = drbg_instantiate(&drbg, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return drbg_generate(&drbg, out, out_len * 8u, NULL, 0);
}

/**
 * @brief SLH-DSA SHAKE PRF over seed and address.
 * @param[in] p Parameter metadata.
 * @param[in] pk_seed Public seed.
 * @param[in] sk_seed Secret seed.
 * @param[in] adrs Address object.
 * @param[out] out Output n-byte string.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_shake_prf(const slhdsa_params_t *p,
                                        const uint8_t *pk_seed,
                                        const uint8_t *sk_seed,
                                        const uint8_t adrs[SLHDSA_ADRS_LEN],
                                        uint8_t out[SLHDSA_MAX_N])
{
    uint8_t sha_input[SLHDSA_SHA512_BLOCK_LEN + SLHDSA_SHA2_ADRS_LEN];
    uint8_t digest[SLHDSA_SHA256_LEN];
    noxtls_return_t rc;

    if(p->sizes.hash_family_sha2 != 0u) {
        memcpy(sha_input, pk_seed, p->n);
        memset(sha_input + p->n, 0, SLHDSA_SHA256_BLOCK_LEN - p->n);
        slhdsa_compress_adrs(adrs, sha_input + SLHDSA_SHA256_BLOCK_LEN);
        rc = slhdsa_sha256_4(sha_input,
                             SLHDSA_SHA256_BLOCK_LEN + SLHDSA_SHA2_ADRS_LEN,
                             sk_seed,
                             p->n,
                             NULL,
                             0u,
                             NULL,
                             0u,
                             digest);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        memcpy(out, digest, p->n);
        return NOXTLS_RETURN_SUCCESS;
    }
    return slhdsa_shake256_4(pk_seed,
                             p->n,
                             adrs,
                             SLHDSA_ADRS_LEN,
                             sk_seed,
                             p->n,
                             NULL,
                             0u,
                             out,
                             p->n);
}

/**
 * @brief SLH-DSA SHAKE n-byte tweakable hash.
 * @param[in] p Parameter metadata.
 * @param[in] pk_seed Public seed.
 * @param[in] adrs Address object.
 * @param[in] in Input buffer.
 * @param[in] in_len Input length.
 * @param[out] out Output n-byte string.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_shake_thash(const slhdsa_params_t *p,
                                          const uint8_t *pk_seed,
                                          const uint8_t adrs[SLHDSA_ADRS_LEN],
                                          const uint8_t *in,
                                          uint32_t in_len,
                                          uint8_t out[SLHDSA_MAX_N])
{
    uint8_t sha_input[SLHDSA_SHA512_BLOCK_LEN + SLHDSA_SHA2_ADRS_LEN];
    uint8_t digest[SLHDSA_SHA512_LEN];
    uint32_t block_len;
    noxtls_return_t rc;

    if(p->sizes.hash_family_sha2 != 0u) {
        if(in_len == p->n) {
            block_len = SLHDSA_SHA256_BLOCK_LEN;
            memcpy(sha_input, pk_seed, p->n);
            memset(sha_input + p->n, 0, block_len - p->n);
            slhdsa_compress_adrs(adrs, sha_input + block_len);
            rc = slhdsa_sha256_4(sha_input,
                                 block_len + SLHDSA_SHA2_ADRS_LEN,
                                 in,
                                 in_len,
                                 NULL,
                                 0u,
                                 NULL,
                                 0u,
                                 digest);
        } else {
            block_len = SLHDSA_SHA512_BLOCK_LEN;
            memcpy(sha_input, pk_seed, p->n);
            memset(sha_input + p->n, 0, block_len - p->n);
            slhdsa_compress_adrs(adrs, sha_input + block_len);
            rc = slhdsa_sha512_4(sha_input,
                                 block_len + SLHDSA_SHA2_ADRS_LEN,
                                 in,
                                 in_len,
                                 NULL,
                                 0u,
                                 NULL,
                                 0u,
                                 digest);
        }
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        memcpy(out, digest, p->n);
        return NOXTLS_RETURN_SUCCESS;
    }
    return slhdsa_shake256_4(pk_seed,
                             p->n,
                             adrs,
                             SLHDSA_ADRS_LEN,
                             in,
                             in_len,
                             NULL,
                             0u,
                             out,
                             p->n);
}

/**
 * @brief SLH-DSA message randomizer PRF_msg.
 * @param[in] p Parameter metadata.
 * @param[in] sk_prf Secret PRF key.
 * @param[in] opt_rand Optional randomizer.
 * @param[in] msg Message.
 * @param[in] msg_len Message length.
 * @param[out] r Output randomizer.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_prf_msg(const slhdsa_params_t *p,
                                      const uint8_t *sk_prf,
                                      const uint8_t *opt_rand,
                                      const uint8_t *msg,
                                      uint32_t msg_len,
                                      uint8_t r[SLHDSA_MAX_N])
{
    uint8_t digest[SLHDSA_SHA512_LEN];
    noxtls_return_t rc;

    if(p->sizes.hash_family_sha2 != 0u) {
        rc = slhdsa_hmac((uint8_t)(p->n > 16u),
                         sk_prf,
                         p->n,
                         opt_rand,
                         p->n,
                         msg,
                         msg_len,
                         digest);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        memcpy(r, digest, p->n);
        return NOXTLS_RETURN_SUCCESS;
    }
    return slhdsa_shake256_4(sk_prf,
                             p->n,
                             opt_rand,
                             p->n,
                             msg,
                             msg_len,
                             NULL,
                             0u,
                             r,
                             p->n);
}

/**
 * @brief SLH-DSA H_msg digest expansion.
 * @param[in] p Parameter metadata.
 * @param[in] r Message randomizer.
 * @param[in] pk_seed Public seed.
 * @param[in] pk_root Public root.
 * @param[in] msg Message.
 * @param[in] msg_len Message length.
 * @param[out] digest Output digest.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_h_msg(const slhdsa_params_t *p,
                                    const uint8_t *r,
                                    const uint8_t *pk_seed,
                                    const uint8_t *pk_root,
                                    const uint8_t *msg,
                                    uint32_t msg_len,
                                    uint8_t digest[SLHDSA_MAX_MD_LEN])
{
    uint8_t pk[NOXTLS_SLHDSA_MAX_PUBLIC_KEY_LEN];
    uint8_t seed[NOXTLS_SLHDSA_MAX_PUBLIC_KEY_LEN + SLHDSA_SHA512_LEN];
    uint8_t msg_hash[SLHDSA_SHA512_LEN];
    uint32_t hash_len;
    noxtls_return_t rc;

    memcpy(pk, pk_seed, p->n);
    memcpy(pk + p->n, pk_root, p->n);
    if(p->sizes.hash_family_sha2 != 0u) {
        if(p->n == 16u) {
            rc = slhdsa_sha256_4(r,
                                 p->n,
                                 pk,
                                 2u * p->n,
                                 msg,
                                 msg_len,
                                 NULL,
                                 0u,
                                 msg_hash);
            hash_len = SLHDSA_SHA256_LEN;
        } else {
            rc = slhdsa_sha512_4(r,
                                 p->n,
                                 pk,
                                 2u * p->n,
                                 msg,
                                 msg_len,
                                 NULL,
                                 0u,
                                 msg_hash);
            hash_len = SLHDSA_SHA512_LEN;
        }
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        memcpy(seed, r, p->n);
        memcpy(seed + p->n, pk_seed, p->n);
        memcpy(seed + (2u * p->n), msg_hash, hash_len);
        return slhdsa_mgf1((uint8_t)(p->n > 16u),
                           seed,
                           (2u * p->n) + hash_len,
                           digest,
                           p->md_len);
    }
    return slhdsa_shake256_4(r,
                             p->n,
                             pk,
                             2u * p->n,
                             msg,
                             msg_len,
                             NULL,
                             0u,
                             digest,
                             p->md_len);
}

/**
 * @brief Convert an n-byte string to WOTS+ base-16 chain lengths.
 * @param[in] p Parameter metadata.
 * @param[in] msg n-byte input.
 * @param[out] out Output WOTS+ chain lengths.
 * @return void.
 */
static void slhdsa_chain_lengths(const slhdsa_params_t *p, const uint8_t *msg, uint8_t out[SLHDSA_MAX_WOTS_LEN])
{
    uint32_t len1 = 2u * p->n;
    uint32_t csum = 0u;
    uint32_t i;

    for(i = 0u; i < p->n; i++) {
        out[2u * i] = (uint8_t)(msg[i] >> 4);
        out[(2u * i) + 1u] = (uint8_t)(msg[i] & 0x0Fu);
    }
    for(i = 0u; i < len1; i++) {
        csum += (SLHDSA_WOTS_W - 1u) - out[i];
    }
    csum <<= 4u;
    out[len1] = (uint8_t)((csum >> 8u) & 0x0Fu);
    out[len1 + 1u] = (uint8_t)((csum >> 4u) & 0x0Fu);
    out[len1 + 2u] = (uint8_t)(csum & 0x0Fu);
}

/**
 * @brief Iterate a WOTS+ hash chain.
 * @param[in] p Parameter metadata.
 * @param[out] out Output chain value.
 * @param[in] in Input chain value.
 * @param[in] start Start index.
 * @param[in] steps Number of chain steps.
 * @param[in] pk_seed Public seed.
 * @param[in] adrs Address object.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_chain(const slhdsa_params_t *p,
                                    uint8_t out[SLHDSA_MAX_N],
                                    const uint8_t in[SLHDSA_MAX_N],
                                    uint32_t start,
                                    uint32_t steps,
                                    const uint8_t *pk_seed,
                                    const uint8_t adrs[SLHDSA_ADRS_LEN])
{
    uint8_t local_adrs[SLHDSA_ADRS_LEN];
    uint32_t i;
    noxtls_return_t rc;

    memcpy(out, in, p->n);
    memcpy(local_adrs, adrs, SLHDSA_ADRS_LEN);
    for(i = start; i < start + steps; i++) {
        slhdsa_adrs_set_hash(local_adrs, i);
        rc = slhdsa_shake_thash(p, pk_seed, local_adrs, out, p->n, out);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Generate a WOTS+ public key.
 * @param[in] p Parameter metadata.
 * @param[out] pk Output n-byte compressed WOTS+ public key.
 * @param[in] sk_seed Secret seed.
 * @param[in] pk_seed Public seed.
 * @param[in] adrs Address object.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_wots_pkgen(const slhdsa_params_t *p,
                                         uint8_t pk[SLHDSA_MAX_N],
                                         const uint8_t *sk_seed,
                                         const uint8_t *pk_seed,
                                         const uint8_t adrs[SLHDSA_ADRS_LEN])
{
    uint8_t buf[SLHDSA_MAX_WOTS_LEN * SLHDSA_MAX_N];
    uint8_t sk[SLHDSA_MAX_N];
    uint8_t chain_adrs[SLHDSA_ADRS_LEN];
    uint8_t pk_adrs[SLHDSA_ADRS_LEN];
    uint32_t i;
    noxtls_return_t rc;

    for(i = 0u; i < p->wots_len; i++) {
        memcpy(chain_adrs, adrs, SLHDSA_ADRS_LEN);
        slhdsa_adrs_set_type(chain_adrs, SLHDSA_ADRS_TYPE_WOTS_PRF);
        slhdsa_adrs_set_keypair(chain_adrs, slhdsa_adrs_get_keypair(adrs));
        slhdsa_adrs_set_chain(chain_adrs, i);
        rc = slhdsa_shake_prf(p, pk_seed, sk_seed, chain_adrs, sk);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        slhdsa_adrs_set_type(chain_adrs, SLHDSA_ADRS_TYPE_WOTS_HASH);
        slhdsa_adrs_set_keypair(chain_adrs, slhdsa_adrs_get_keypair(adrs));
        slhdsa_adrs_set_chain(chain_adrs, i);
        rc = slhdsa_chain(p, buf + (i * p->n), sk, 0u, SLHDSA_WOTS_W - 1u, pk_seed, chain_adrs);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    }

    memcpy(pk_adrs, adrs, SLHDSA_ADRS_LEN);
    slhdsa_adrs_set_type(pk_adrs, SLHDSA_ADRS_TYPE_WOTS_PK);
    slhdsa_adrs_set_keypair(pk_adrs, slhdsa_adrs_get_keypair(adrs));
    return slhdsa_shake_thash(p, pk_seed, pk_adrs, buf, p->wots_len * p->n, pk);
}

/**
 * @brief Generate a WOTS+ signature.
 * @param[in] p Parameter metadata.
 * @param[out] sig Output WOTS+ signature.
 * @param[in] msg n-byte message digest.
 * @param[in] sk_seed Secret seed.
 * @param[in] pk_seed Public seed.
 * @param[in] adrs Address object.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_wots_sign(const slhdsa_params_t *p,
                                        uint8_t *sig,
                                        const uint8_t *msg,
                                        const uint8_t *sk_seed,
                                        const uint8_t *pk_seed,
                                        const uint8_t adrs[SLHDSA_ADRS_LEN])
{
    uint8_t lengths[SLHDSA_MAX_WOTS_LEN];
    uint8_t sk[SLHDSA_MAX_N];
    uint8_t chain_adrs[SLHDSA_ADRS_LEN];
    uint32_t i;
    noxtls_return_t rc;

    slhdsa_chain_lengths(p, msg, lengths);
    for(i = 0u; i < p->wots_len; i++) {
        memcpy(chain_adrs, adrs, SLHDSA_ADRS_LEN);
        slhdsa_adrs_set_type(chain_adrs, SLHDSA_ADRS_TYPE_WOTS_PRF);
        slhdsa_adrs_set_keypair(chain_adrs, slhdsa_adrs_get_keypair(adrs));
        slhdsa_adrs_set_chain(chain_adrs, i);
        rc = slhdsa_shake_prf(p, pk_seed, sk_seed, chain_adrs, sk);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        slhdsa_adrs_set_type(chain_adrs, SLHDSA_ADRS_TYPE_WOTS_HASH);
        slhdsa_adrs_set_keypair(chain_adrs, slhdsa_adrs_get_keypair(adrs));
        slhdsa_adrs_set_chain(chain_adrs, i);
        rc = slhdsa_chain(p, sig + (i * p->n), sk, 0u, lengths[i], pk_seed, chain_adrs);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Compute a WOTS+ public key from a signature.
 * @param[in] p Parameter metadata.
 * @param[out] pk Output n-byte compressed WOTS+ public key.
 * @param[in] sig WOTS+ signature.
 * @param[in] msg n-byte message digest.
 * @param[in] pk_seed Public seed.
 * @param[in] adrs Address object.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_wots_pk_from_sig(const slhdsa_params_t *p,
                                               uint8_t pk[SLHDSA_MAX_N],
                                               const uint8_t *sig,
                                               const uint8_t *msg,
                                               const uint8_t *pk_seed,
                                               const uint8_t adrs[SLHDSA_ADRS_LEN])
{
    uint8_t lengths[SLHDSA_MAX_WOTS_LEN];
    uint8_t buf[SLHDSA_MAX_WOTS_LEN * SLHDSA_MAX_N];
    uint8_t chain_adrs[SLHDSA_ADRS_LEN];
    uint8_t pk_adrs[SLHDSA_ADRS_LEN];
    uint32_t i;
    noxtls_return_t rc;

    slhdsa_chain_lengths(p, msg, lengths);
    for(i = 0u; i < p->wots_len; i++) {
        memcpy(chain_adrs, adrs, SLHDSA_ADRS_LEN);
        slhdsa_adrs_set_type(chain_adrs, SLHDSA_ADRS_TYPE_WOTS_HASH);
        slhdsa_adrs_set_keypair(chain_adrs, slhdsa_adrs_get_keypair(adrs));
        slhdsa_adrs_set_chain(chain_adrs, i);
        rc = slhdsa_chain(p,
                          buf + (i * p->n),
                          sig + (i * p->n),
                          lengths[i],
                          (SLHDSA_WOTS_W - 1u) - lengths[i],
                          pk_seed,
                          chain_adrs);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    }
    memcpy(pk_adrs, adrs, SLHDSA_ADRS_LEN);
    slhdsa_adrs_set_type(pk_adrs, SLHDSA_ADRS_TYPE_WOTS_PK);
    slhdsa_adrs_set_keypair(pk_adrs, slhdsa_adrs_get_keypair(adrs));
    return slhdsa_shake_thash(p, pk_seed, pk_adrs, buf, p->wots_len * p->n, pk);
}

/**
 * @brief Compute a leaf of the XMSS tree.
 * @param[in] p Parameter metadata.
 * @param[out] leaf Output leaf node.
 * @param[in] sk_seed Secret seed.
 * @param[in] pk_seed Public seed.
 * @param[in] adrs Base address.
 * @param[in] idx Leaf index.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_xmss_leaf(const slhdsa_params_t *p,
                                        uint8_t leaf[SLHDSA_MAX_N],
                                        const uint8_t *sk_seed,
                                        const uint8_t *pk_seed,
                                        const uint8_t adrs[SLHDSA_ADRS_LEN],
                                        uint32_t idx)
{
    uint8_t wots_adrs[SLHDSA_ADRS_LEN];

    memcpy(wots_adrs, adrs, SLHDSA_ADRS_LEN);
    slhdsa_adrs_set_type(wots_adrs, SLHDSA_ADRS_TYPE_WOTS_HASH);
    slhdsa_adrs_set_keypair(wots_adrs, idx);
    return slhdsa_wots_pkgen(p, leaf, sk_seed, pk_seed, wots_adrs);
}

/**
 * @brief Compute an XMSS subtree root and optional auth path.
 * @param[in] p Parameter metadata.
 * @param[out] root Output root.
 * @param[out] auth Optional authentication path output.
 * @param[in] target Target leaf index when auth is non-NULL.
 * @param[in] sk_seed Secret seed.
 * @param[in] pk_seed Public seed.
 * @param[in] adrs Base address.
 * @param[in] start Start leaf index.
 * @param[in] height Subtree height.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_xmss_treehash(const slhdsa_params_t *p,
                                            uint8_t root[SLHDSA_MAX_N],
                                            uint8_t *auth,
                                            uint32_t target,
                                            const uint8_t *sk_seed,
                                            const uint8_t *pk_seed,
                                            const uint8_t adrs[SLHDSA_ADRS_LEN],
                                            uint32_t start,
                                            uint32_t height)
{
    uint8_t stack[(SLHDSA_MAX_HP + 1u) * SLHDSA_MAX_N];
    uint32_t stack_heights[SLHDSA_MAX_HP + 1u];
    uint8_t node[SLHDSA_MAX_N];
    uint8_t parent[2u * SLHDSA_MAX_N];
    uint8_t tree_adrs[SLHDSA_ADRS_LEN];
    uint32_t stack_len = 0u;
    uint32_t leaf_count = 1u << height;
    uint32_t i;
    noxtls_return_t rc;

    for(i = 0u; i < leaf_count; i++) {
        uint32_t leaf_idx = start + i;
        uint32_t node_height = 0u;
        uint32_t node_index = leaf_idx;

        rc = slhdsa_xmss_leaf(p, node, sk_seed, pk_seed, adrs, leaf_idx);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        if(auth != NULL && ((leaf_idx ^ target) == 1u)) {
            memcpy(auth, node, p->n);
        }
        while(stack_len > 0u && stack_heights[stack_len - 1u] == node_height) {
            uint32_t sibling_index = node_index ^ 1u;

            if(auth != NULL && node_height < height && ((target >> node_height) ^ 1u) == sibling_index) {
                memcpy(auth + (node_height * p->n), stack + ((stack_len - 1u) * p->n), p->n);
            }
            memcpy(parent, stack + ((stack_len - 1u) * p->n), p->n);
            memcpy(parent + p->n, node, p->n);
            stack_len--;
            memcpy(tree_adrs, adrs, SLHDSA_ADRS_LEN);
            slhdsa_adrs_set_type(tree_adrs, SLHDSA_ADRS_TYPE_TREE);
            slhdsa_adrs_set_keypair(tree_adrs, slhdsa_adrs_get_keypair(adrs));
            slhdsa_adrs_set_tree_height(tree_adrs, node_height + 1u);
            slhdsa_adrs_set_tree_index(tree_adrs, node_index >> 1u);
            rc = slhdsa_shake_thash(p, pk_seed, tree_adrs, parent, 2u * p->n, node);
            if(rc != NOXTLS_RETURN_SUCCESS) return rc;
            node_height++;
            node_index >>= 1u;
            if(auth != NULL && node_height < height && ((target >> node_height) ^ 1u) == node_index) {
                memcpy(auth + (node_height * p->n), node, p->n);
            }
        }
        memcpy(stack + (stack_len * p->n), node, p->n);
        stack_heights[stack_len] = node_height;
        stack_len++;
    }

    if(stack_len != 1u) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(root, stack, p->n);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Generate an XMSS signature.
 * @param[in] p Parameter metadata.
 * @param[out] sig Output XMSS signature.
 * @param[in] msg n-byte message to sign.
 * @param[in] sk_seed Secret seed.
 * @param[in] pk_seed Public seed.
 * @param[in] idx_leaf Leaf index.
 * @param[in] adrs Base address.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_xmss_sign(const slhdsa_params_t *p,
                                        uint8_t *sig,
                                        const uint8_t *msg,
                                        const uint8_t *sk_seed,
                                        const uint8_t *pk_seed,
                                        uint32_t idx_leaf,
                                        const uint8_t adrs[SLHDSA_ADRS_LEN])
{
    uint8_t wots_adrs[SLHDSA_ADRS_LEN];
    uint8_t *auth = sig + (p->wots_len * p->n);
    uint32_t j;
    noxtls_return_t rc;

    memcpy(wots_adrs, adrs, SLHDSA_ADRS_LEN);
    slhdsa_adrs_set_type(wots_adrs, SLHDSA_ADRS_TYPE_WOTS_HASH);
    slhdsa_adrs_set_keypair(wots_adrs, idx_leaf);
    rc = slhdsa_wots_sign(p, sig, msg, sk_seed, pk_seed, wots_adrs);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    for(j = 0u; j < p->hp; j++) {
        uint32_t sibling = idx_leaf ^ (1u << j);
        uint32_t start = sibling & ~((1u << j) - 1u);

        rc = slhdsa_xmss_treehash(p, auth + (j * p->n), NULL, 0u, sk_seed, pk_seed, adrs, start, j);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Compute an XMSS public key from a signature.
 * @param[in] p Parameter metadata.
 * @param[out] root Output root.
 * @param[in] sig XMSS signature.
 * @param[in] msg Signed n-byte message.
 * @param[in] pk_seed Public seed.
 * @param[in] idx_leaf Leaf index.
 * @param[in] adrs Base address.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_xmss_pk_from_sig(const slhdsa_params_t *p,
                                               uint8_t root[SLHDSA_MAX_N],
                                               const uint8_t *sig,
                                               const uint8_t *msg,
                                               const uint8_t *pk_seed,
                                               uint32_t idx_leaf,
                                               const uint8_t adrs[SLHDSA_ADRS_LEN])
{
    uint8_t node[SLHDSA_MAX_N];
    uint8_t auth_node[SLHDSA_MAX_N];
    uint8_t pair[2u * SLHDSA_MAX_N];
    uint8_t tree_adrs[SLHDSA_ADRS_LEN];
    uint8_t wots_adrs[SLHDSA_ADRS_LEN];
    const uint8_t *auth = sig + (p->wots_len * p->n);
    uint32_t idx = idx_leaf;
    uint32_t i;
    noxtls_return_t rc;

    memcpy(wots_adrs, adrs, SLHDSA_ADRS_LEN);
    slhdsa_adrs_set_type(wots_adrs, SLHDSA_ADRS_TYPE_WOTS_HASH);
    slhdsa_adrs_set_keypair(wots_adrs, idx_leaf);
    rc = slhdsa_wots_pk_from_sig(p, node, sig, msg, pk_seed, wots_adrs);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;

    for(i = 0u; i < p->hp; i++) {
        memcpy(auth_node, auth + (i * p->n), p->n);
        if((idx & 1u) == 0u) {
            memcpy(pair, node, p->n);
            memcpy(pair + p->n, auth_node, p->n);
        } else {
            memcpy(pair, auth_node, p->n);
            memcpy(pair + p->n, node, p->n);
        }
        memcpy(tree_adrs, adrs, SLHDSA_ADRS_LEN);
        slhdsa_adrs_set_type(tree_adrs, SLHDSA_ADRS_TYPE_TREE);
        slhdsa_adrs_set_keypair(tree_adrs, slhdsa_adrs_get_keypair(adrs));
        slhdsa_adrs_set_tree_height(tree_adrs, i + 1u);
        slhdsa_adrs_set_tree_index(tree_adrs, idx >> 1u);
        rc = slhdsa_shake_thash(p, pk_seed, tree_adrs, pair, 2u * p->n, node);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        idx >>= 1u;
    }
    memcpy(root, node, p->n);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Decode FORS message bits into indices.
 * @param[in] p Parameter metadata.
 * @param[out] indices Output FORS indices.
 * @param[in] msg FORS message bytes.
 * @return void.
 */
static void slhdsa_fors_indices(const slhdsa_params_t *p,
                                uint32_t indices[SLHDSA_MAX_K],
                                const uint8_t *msg)
{
    uint32_t i;
    uint32_t j;
    uint32_t offset = 0u;

    for(i = 0u; i < p->k; i++) {
        indices[i] = 0u;
        for(j = 0u; j < p->a; j++) {
            indices[i] |= (uint32_t)((msg[offset >> 3u] >> (offset & 7u)) & 1u) << j;
            offset++;
        }
    }
}

/**
 * @brief Generate a FORS secret-key leaf.
 * @param[in] p Parameter metadata.
 * @param[out] sk Output FORS secret key element.
 * @param[in] sk_seed Secret seed.
 * @param[in] pk_seed Public seed.
 * @param[in] adrs FORS address.
 * @param[in] idx Absolute leaf index.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_fors_skgen(const slhdsa_params_t *p,
                                         uint8_t sk[SLHDSA_MAX_N],
                                         const uint8_t *sk_seed,
                                         const uint8_t *pk_seed,
                                         const uint8_t adrs[SLHDSA_ADRS_LEN],
                                         uint32_t idx)
{
    uint8_t sk_adrs[SLHDSA_ADRS_LEN];

    memcpy(sk_adrs, adrs, SLHDSA_ADRS_LEN);
    slhdsa_adrs_set_type(sk_adrs, SLHDSA_ADRS_TYPE_FORS_PRF);
    slhdsa_adrs_set_keypair(sk_adrs, slhdsa_adrs_get_keypair(adrs));
    slhdsa_adrs_set_tree_index(sk_adrs, idx);
    return slhdsa_shake_prf(p, pk_seed, sk_seed, sk_adrs, sk);
}

/**
 * @brief Compute a FORS leaf node.
 * @param[in] p Parameter metadata.
 * @param[out] leaf Output leaf node.
 * @param[in] sk_seed Secret seed.
 * @param[in] pk_seed Public seed.
 * @param[in] adrs FORS address.
 * @param[in] idx Absolute leaf index.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_fors_leaf(const slhdsa_params_t *p,
                                        uint8_t leaf[SLHDSA_MAX_N],
                                        const uint8_t *sk_seed,
                                        const uint8_t *pk_seed,
                                        const uint8_t adrs[SLHDSA_ADRS_LEN],
                                        uint32_t idx)
{
    uint8_t sk[SLHDSA_MAX_N];
    uint8_t tree_adrs[SLHDSA_ADRS_LEN];
    noxtls_return_t rc;

    rc = slhdsa_fors_skgen(p, sk, sk_seed, pk_seed, adrs, idx);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    memcpy(tree_adrs, adrs, SLHDSA_ADRS_LEN);
    slhdsa_adrs_set_type(tree_adrs, SLHDSA_ADRS_TYPE_FORS_TREE);
    slhdsa_adrs_set_keypair(tree_adrs, slhdsa_adrs_get_keypair(adrs));
    slhdsa_adrs_set_tree_height(tree_adrs, 0u);
    slhdsa_adrs_set_tree_index(tree_adrs, idx);
    return slhdsa_shake_thash(p, pk_seed, tree_adrs, sk, p->n, leaf);
}

/**
 * @brief Compute a FORS subtree root.
 * @param[in] p Parameter metadata.
 * @param[out] root Output root.
 * @param[in] sk_seed Secret seed.
 * @param[in] pk_seed Public seed.
 * @param[in] adrs FORS address.
 * @param[in] start Start leaf index.
 * @param[in] height Subtree height.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_fors_treehash(const slhdsa_params_t *p,
                                            uint8_t root[SLHDSA_MAX_N],
                                            const uint8_t *sk_seed,
                                            const uint8_t *pk_seed,
                                            const uint8_t adrs[SLHDSA_ADRS_LEN],
                                            uint32_t start,
                                            uint32_t height)
{
    uint8_t stack[(SLHDSA_MAX_A + 1u) * SLHDSA_MAX_N];
    uint32_t stack_heights[SLHDSA_MAX_A + 1u];
    uint8_t node[SLHDSA_MAX_N];
    uint8_t pair[2u * SLHDSA_MAX_N];
    uint8_t tree_adrs[SLHDSA_ADRS_LEN];
    uint32_t stack_len = 0u;
    uint32_t leaf_count = 1u << height;
    uint32_t i;
    noxtls_return_t rc;

    for(i = 0u; i < leaf_count; i++) {
        uint32_t leaf_idx = start + i;
        uint32_t node_height = 0u;
        uint32_t node_index = leaf_idx;

        rc = slhdsa_fors_leaf(p, node, sk_seed, pk_seed, adrs, leaf_idx);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        while(stack_len > 0u && stack_heights[stack_len - 1u] == node_height) {
            memcpy(pair, stack + ((stack_len - 1u) * p->n), p->n);
            memcpy(pair + p->n, node, p->n);
            stack_len--;
            memcpy(tree_adrs, adrs, SLHDSA_ADRS_LEN);
            slhdsa_adrs_set_type(tree_adrs, SLHDSA_ADRS_TYPE_FORS_TREE);
            slhdsa_adrs_set_keypair(tree_adrs, slhdsa_adrs_get_keypair(adrs));
            slhdsa_adrs_set_tree_height(tree_adrs, node_height + 1u);
            slhdsa_adrs_set_tree_index(tree_adrs, node_index >> 1u);
            rc = slhdsa_shake_thash(p, pk_seed, tree_adrs, pair, 2u * p->n, node);
            if(rc != NOXTLS_RETURN_SUCCESS) return rc;
            node_height++;
            node_index >>= 1u;
        }
        memcpy(stack + (stack_len * p->n), node, p->n);
        stack_heights[stack_len] = node_height;
        stack_len++;
    }

    if(stack_len != 1u) {
        return NOXTLS_RETURN_FAILED;
    }
    memcpy(root, stack, p->n);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Generate a FORS signature and public key.
 * @param[in] p Parameter metadata.
 * @param[out] sig Output FORS signature.
 * @param[out] pk Output FORS public key.
 * @param[in] msg FORS message bytes.
 * @param[in] sk_seed Secret seed.
 * @param[in] pk_seed Public seed.
 * @param[in] adrs FORS address.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_fors_sign(const slhdsa_params_t *p,
                                        uint8_t *sig,
                                        uint8_t pk[SLHDSA_MAX_N],
                                        const uint8_t *msg,
                                        const uint8_t *sk_seed,
                                        const uint8_t *pk_seed,
                                        const uint8_t adrs[SLHDSA_ADRS_LEN])
{
    uint32_t indices[SLHDSA_MAX_K];
    uint8_t roots[SLHDSA_MAX_K * SLHDSA_MAX_N];
    uint8_t roots_adrs[SLHDSA_ADRS_LEN];
    uint32_t tree_size = 1u << p->a;
    uint32_t i;
    uint32_t j;
    noxtls_return_t rc;

    slhdsa_fors_indices(p, indices, msg);
    for(i = 0u; i < p->k; i++) {
        uint32_t idx = indices[i];
        uint32_t absolute_idx = (i * tree_size) + idx;

        rc = slhdsa_fors_skgen(p, sig, sk_seed, pk_seed, adrs, absolute_idx);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        sig += p->n;
        for(j = 0u; j < p->a; j++) {
            uint32_t sibling = idx ^ (1u << j);
            uint32_t start = (i * tree_size) + (sibling & ~((1u << j) - 1u));

            rc = slhdsa_fors_treehash(p, sig, sk_seed, pk_seed, adrs, start, j);
            if(rc != NOXTLS_RETURN_SUCCESS) return rc;
            sig += p->n;
        }
        rc = slhdsa_fors_treehash(p, roots + (i * p->n), sk_seed, pk_seed, adrs, i * tree_size, p->a);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    }

    memcpy(roots_adrs, adrs, SLHDSA_ADRS_LEN);
    slhdsa_adrs_set_type(roots_adrs, SLHDSA_ADRS_TYPE_FORS_ROOTS);
    slhdsa_adrs_set_keypair(roots_adrs, slhdsa_adrs_get_keypair(adrs));
    return slhdsa_shake_thash(p, pk_seed, roots_adrs, roots, p->k * p->n, pk);
}

/**
 * @brief Compute a FORS public key from a signature.
 * @param[in] p Parameter metadata.
 * @param[out] pk Output FORS public key.
 * @param[in] sig FORS signature.
 * @param[in] msg FORS message bytes.
 * @param[in] pk_seed Public seed.
 * @param[in] adrs FORS address.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_fors_pk_from_sig(const slhdsa_params_t *p,
                                               uint8_t pk[SLHDSA_MAX_N],
                                               const uint8_t *sig,
                                               const uint8_t *msg,
                                               const uint8_t *pk_seed,
                                               const uint8_t adrs[SLHDSA_ADRS_LEN])
{
    uint32_t indices[SLHDSA_MAX_K];
    uint8_t roots[SLHDSA_MAX_K * SLHDSA_MAX_N];
    uint8_t node[SLHDSA_MAX_N];
    uint8_t auth[SLHDSA_MAX_N];
    uint8_t pair[2u * SLHDSA_MAX_N];
    uint8_t tree_adrs[SLHDSA_ADRS_LEN];
    uint8_t roots_adrs[SLHDSA_ADRS_LEN];
    uint32_t tree_size = 1u << p->a;
    uint32_t i;
    uint32_t j;
    noxtls_return_t rc;

    slhdsa_fors_indices(p, indices, msg);
    for(i = 0u; i < p->k; i++) {
        uint32_t idx = indices[i];
        uint32_t absolute_idx = (i * tree_size) + idx;

        memcpy(tree_adrs, adrs, SLHDSA_ADRS_LEN);
        slhdsa_adrs_set_type(tree_adrs, SLHDSA_ADRS_TYPE_FORS_TREE);
        slhdsa_adrs_set_keypair(tree_adrs, slhdsa_adrs_get_keypair(adrs));
        slhdsa_adrs_set_tree_height(tree_adrs, 0u);
        slhdsa_adrs_set_tree_index(tree_adrs, absolute_idx);
        rc = slhdsa_shake_thash(p, pk_seed, tree_adrs, sig, p->n, node);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        sig += p->n;
        for(j = 0u; j < p->a; j++) {
            memcpy(auth, sig, p->n);
            sig += p->n;
            if((idx & 1u) == 0u) {
                memcpy(pair, node, p->n);
                memcpy(pair + p->n, auth, p->n);
            } else {
                memcpy(pair, auth, p->n);
                memcpy(pair + p->n, node, p->n);
            }
            idx >>= 1u;
            absolute_idx >>= 1u;
            memcpy(tree_adrs, adrs, SLHDSA_ADRS_LEN);
            slhdsa_adrs_set_type(tree_adrs, SLHDSA_ADRS_TYPE_FORS_TREE);
            slhdsa_adrs_set_keypair(tree_adrs, slhdsa_adrs_get_keypair(adrs));
            slhdsa_adrs_set_tree_height(tree_adrs, j + 1u);
            slhdsa_adrs_set_tree_index(tree_adrs, absolute_idx);
            rc = slhdsa_shake_thash(p, pk_seed, tree_adrs, pair, 2u * p->n, node);
            if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        }
        memcpy(roots + (i * p->n), node, p->n);
    }

    memcpy(roots_adrs, adrs, SLHDSA_ADRS_LEN);
    slhdsa_adrs_set_type(roots_adrs, SLHDSA_ADRS_TYPE_FORS_ROOTS);
    slhdsa_adrs_set_keypair(roots_adrs, slhdsa_adrs_get_keypair(adrs));
    return slhdsa_shake_thash(p, pk_seed, roots_adrs, roots, p->k * p->n, pk);
}

/**
 * @brief Generate the SLH-DSA hypertree public root.
 * @param[in] p Parameter metadata.
 * @param[out] root Output public root.
 * @param[in] sk_seed Secret seed.
 * @param[in] pk_seed Public seed.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_ht_pkgen(const slhdsa_params_t *p,
                                       uint8_t root[SLHDSA_MAX_N],
                                       const uint8_t *sk_seed,
                                       const uint8_t *pk_seed)
{
    uint8_t adrs[SLHDSA_ADRS_LEN];

    memset(adrs, 0, sizeof(adrs));
    slhdsa_adrs_set_layer(adrs, p->d - 1u);
    slhdsa_adrs_set_tree(adrs, 0u);
    return slhdsa_xmss_treehash(p, root, NULL, 0u, sk_seed, pk_seed, adrs, 0u, p->hp);
}

/**
 * @brief Sign with the SLH-DSA hypertree.
 * @param[in] p Parameter metadata.
 * @param[out] sig Output hypertree signature.
 * @param[in] msg n-byte FORS public key.
 * @param[in] sk_seed Secret seed.
 * @param[in] pk_seed Public seed.
 * @param[in] idx_tree Tree index.
 * @param[in] idx_leaf Leaf index.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_ht_sign(const slhdsa_params_t *p,
                                      uint8_t *sig,
                                      const uint8_t *msg,
                                      const uint8_t *sk_seed,
                                      const uint8_t *pk_seed,
                                      uint64_t idx_tree,
                                      uint32_t idx_leaf)
{
    uint8_t adrs[SLHDSA_ADRS_LEN];
    uint8_t root[SLHDSA_MAX_N];
    uint8_t current_msg[SLHDSA_MAX_N];
    uint32_t xmss_sig_len = (p->wots_len + p->hp) * p->n;
    uint32_t layer;
    noxtls_return_t rc;

    memcpy(current_msg, msg, p->n);
    for(layer = 0u; layer < p->d; layer++) {
        memset(adrs, 0, sizeof(adrs));
        slhdsa_adrs_set_layer(adrs, layer);
        slhdsa_adrs_set_tree(adrs, idx_tree);
        rc = slhdsa_xmss_sign(p, sig, current_msg, sk_seed, pk_seed, idx_leaf, adrs);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        rc = slhdsa_xmss_pk_from_sig(p, root, sig, current_msg, pk_seed, idx_leaf, adrs);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        memcpy(current_msg, root, p->n);
        sig += xmss_sig_len;
        idx_leaf = (uint32_t)(idx_tree & ((1u << p->hp) - 1u));
        idx_tree >>= p->hp;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Verify a hypertree signature and compute its public root.
 * @param[in] p Parameter metadata.
 * @param[out] root Output public root.
 * @param[in] sig Hypertree signature.
 * @param[in] msg n-byte FORS public key.
 * @param[in] pk_seed Public seed.
 * @param[in] idx_tree Tree index.
 * @param[in] idx_leaf Leaf index.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_ht_verify(const slhdsa_params_t *p,
                                        uint8_t root[SLHDSA_MAX_N],
                                        const uint8_t *sig,
                                        const uint8_t *msg,
                                        const uint8_t *pk_seed,
                                        uint64_t idx_tree,
                                        uint32_t idx_leaf)
{
    uint8_t adrs[SLHDSA_ADRS_LEN];
    uint8_t current_msg[SLHDSA_MAX_N];
    uint32_t xmss_sig_len = (p->wots_len + p->hp) * p->n;
    uint32_t layer;
    noxtls_return_t rc;

    memcpy(current_msg, msg, p->n);
    for(layer = 0u; layer < p->d; layer++) {
        memset(adrs, 0, sizeof(adrs));
        slhdsa_adrs_set_layer(adrs, layer);
        slhdsa_adrs_set_tree(adrs, idx_tree);
        rc = slhdsa_xmss_pk_from_sig(p, root, sig, current_msg, pk_seed, idx_leaf, adrs);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
        memcpy(current_msg, root, p->n);
        sig += xmss_sig_len;
        idx_leaf = (uint32_t)(idx_tree & ((1u << p->hp) - 1u));
        idx_tree >>= p->hp;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Extract tree and leaf indices from H_msg digest.
 * @param[in] p Parameter metadata.
 * @param[in] digest H_msg output.
 * @param[out] idx_tree Output tree index.
 * @param[out] idx_leaf Output leaf index.
 * @return Number of FORS message bytes at the front of digest.
 */
static uint32_t slhdsa_digest_indices(const slhdsa_params_t *p,
                                      const uint8_t digest[SLHDSA_MAX_MD_LEN],
                                      uint64_t *idx_tree,
                                      uint32_t *idx_leaf)
{
    uint32_t fors_msg_bytes = ((p->k * p->a) + 7u) / 8u;
    uint32_t tree_bits = p->h - p->hp;
    uint32_t tree_bytes = (tree_bits + 7u) / 8u;
    uint32_t leaf_bytes = (p->hp + 7u) / 8u;
    uint64_t tree_mask;
    uint32_t leaf_mask;

    *idx_tree = slhdsa_load_be(digest + fors_msg_bytes, tree_bytes);
    if(tree_bits < 64u) {
        tree_mask = (1ULL << tree_bits) - 1ULL;
        *idx_tree &= tree_mask;
    }
    *idx_leaf = (uint32_t)slhdsa_load_be(digest + fors_msg_bytes + tree_bytes, leaf_bytes);
    leaf_mask = (1u << p->hp) - 1u;
    *idx_leaf &= leaf_mask;
    return fors_msg_bytes;
}

/**
 * @brief Get the SLH-DSA public-key length for a parameter set.
 * @param[in] param FIPS 205 SLH-DSA parameter set.
 * @return Public-key length in bytes, or 0 for invalid parameter sets.
 */
uint32_t noxtls_slhdsa_public_key_len(noxtls_slhdsa_param_t param)
{
    slhdsa_sizes_t sizes;
    return (slhdsa_get_sizes(param, &sizes) == NOXTLS_RETURN_SUCCESS) ? sizes.public_key_len : 0u;
}

/**
 * @brief Get the SLH-DSA private-key length for a parameter set.
 * @param[in] param FIPS 205 SLH-DSA parameter set.
 * @return Private-key length in bytes, or 0 for invalid parameter sets.
 */
uint32_t noxtls_slhdsa_secret_key_len(noxtls_slhdsa_param_t param)
{
    slhdsa_sizes_t sizes;
    return (slhdsa_get_sizes(param, &sizes) == NOXTLS_RETURN_SUCCESS) ? sizes.secret_key_len : 0u;
}

/**
 * @brief Get the SLH-DSA signature length for a parameter set.
 * @param[in] param FIPS 205 SLH-DSA parameter set.
 * @return Signature length in bytes, or 0 for invalid parameter sets.
 */
uint32_t noxtls_slhdsa_signature_len(noxtls_slhdsa_param_t param)
{
    slhdsa_sizes_t sizes;
    return (slhdsa_get_sizes(param, &sizes) == NOXTLS_RETURN_SUCCESS) ? sizes.signature_len : 0u;
}

/**
 * @brief Get the NIST security category for a parameter set.
 * @param[in] param FIPS 205 SLH-DSA parameter set.
 * @return Security category (1, 3, or 5), or 0 for invalid parameter sets.
 */
uint32_t noxtls_slhdsa_security_category(noxtls_slhdsa_param_t param)
{
    slhdsa_sizes_t sizes;
    return (slhdsa_get_sizes(param, &sizes) == NOXTLS_RETURN_SUCCESS) ? sizes.security_category : 0u;
}

/**
 * @brief Test whether a parameter set uses the SHA-2 hash family.
 * @param[in] param FIPS 205 SLH-DSA parameter set.
 * @return 1 for SHA-2 parameter sets, 0 otherwise.
 */
uint8_t noxtls_slhdsa_is_sha2(noxtls_slhdsa_param_t param)
{
    slhdsa_sizes_t sizes;
    return (slhdsa_get_sizes(param, &sizes) == NOXTLS_RETURN_SUCCESS) ? sizes.hash_family_sha2 : 0u;
}

/**
 * @brief Test whether a parameter set is an "s" (small-signature) variant.
 * @param[in] param FIPS 205 SLH-DSA parameter set.
 * @return 1 for small variants, 0 otherwise.
 */
uint8_t noxtls_slhdsa_is_small(noxtls_slhdsa_param_t param)
{
    slhdsa_sizes_t sizes;
    return (slhdsa_get_sizes(param, &sizes) == NOXTLS_RETURN_SUCCESS) ? sizes.small_variant : 0u;
}

/**
 * @brief Generate an SLH-DSA key pair.
 * @param[in] param FIPS 205 SLH-DSA parameter set.
 * @param[out] public_key Public-key output buffer.
 * @param[out] secret_key Secret-key output buffer.
 * @return NOXTLS_RETURN_NOT_SUPPORTED until the FIPS 205 primitive backend is complete.
 */
noxtls_return_t noxtls_slhdsa_keygen(noxtls_slhdsa_param_t param, uint8_t *public_key, uint8_t *secret_key)
{
    slhdsa_params_t p;
    uint8_t sk_seed[SLHDSA_MAX_N];
    uint8_t sk_prf[SLHDSA_MAX_N];
    uint8_t pk_seed[SLHDSA_MAX_N];
    uint8_t pk_root[SLHDSA_MAX_N];
    noxtls_return_t rc;

    if(public_key == NULL || secret_key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    rc = slhdsa_get_params(param, &p);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = slhdsa_random(sk_seed, p.n);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = slhdsa_random(sk_prf, p.n);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = slhdsa_random(pk_seed, p.n);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = slhdsa_ht_pkgen(&p, pk_root, sk_seed, pk_seed);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    memcpy(public_key, pk_seed, p.n);
    memcpy(public_key + p.n, pk_root, p.n);
    memcpy(secret_key, sk_seed, p.n);
    memcpy(secret_key + p.n, sk_prf, p.n);
    memcpy(secret_key + (2u * p.n), pk_seed, p.n);
    memcpy(secret_key + (3u * p.n), pk_root, p.n);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Sign a message with SLH-DSA.
 * @param[in] param FIPS 205 SLH-DSA parameter set.
 * @param[in] secret_key Secret-key buffer.
 * @param[in] noxtls_message Message to sign.
 * @param[in] message_len Message length in bytes.
 * @param[out] signature Signature output buffer.
 * @param[out] signature_len Signature length output.
 * @return NOXTLS_RETURN_NOT_SUPPORTED until the FIPS 205 primitive backend is complete.
 */
noxtls_return_t noxtls_slhdsa_sign(noxtls_slhdsa_param_t param,
                                   const uint8_t *secret_key,
                                   const uint8_t *noxtls_message,
                                   uint32_t message_len,
                                   uint8_t *signature,
                                   uint32_t *signature_len)
{
    slhdsa_params_t p;
    uint8_t opt_rand[SLHDSA_MAX_N];
    uint8_t r[SLHDSA_MAX_N];
    uint8_t digest[SLHDSA_MAX_MD_LEN];
    uint8_t fors_pk[SLHDSA_MAX_N];
    uint8_t adrs[SLHDSA_ADRS_LEN];
    const uint8_t *sk_seed;
    const uint8_t *sk_prf;
    const uint8_t *pk_seed;
    const uint8_t *pk_root;
    uint64_t idx_tree;
    uint32_t idx_leaf;
    uint32_t fors_msg_bytes;
    uint32_t fors_sig_len;
    uint32_t expected_sig_len;
    noxtls_return_t rc;

    if(secret_key == NULL || signature == NULL || signature_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(noxtls_message == NULL && message_len != 0u) {
        return NOXTLS_RETURN_NULL;
    }
    rc = slhdsa_get_params(param, &p);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    expected_sig_len = p.sizes.signature_len;
    sk_seed = secret_key;
    sk_prf = secret_key + p.n;
    pk_seed = secret_key + (2u * p.n);
    pk_root = secret_key + (3u * p.n);
    rc = slhdsa_random(opt_rand, p.n);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = slhdsa_prf_msg(&p, sk_prf, opt_rand, noxtls_message, message_len, r);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    rc = slhdsa_h_msg(&p, r, pk_seed, pk_root, noxtls_message, message_len, digest);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    fors_msg_bytes = slhdsa_digest_indices(&p, digest, &idx_tree, &idx_leaf);

    memcpy(signature, r, p.n);
    signature += p.n;
    memset(adrs, 0, sizeof(adrs));
    slhdsa_adrs_set_layer(adrs, 0u);
    slhdsa_adrs_set_tree(adrs, idx_tree);
    slhdsa_adrs_set_type(adrs, SLHDSA_ADRS_TYPE_FORS_TREE);
    slhdsa_adrs_set_keypair(adrs, idx_leaf);
    rc = slhdsa_fors_sign(&p, signature, fors_pk, digest, sk_seed, pk_seed, adrs);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    fors_sig_len = p.k * (p.a + 1u) * p.n;
    signature += fors_sig_len;
    rc = slhdsa_ht_sign(&p, signature, fors_pk, sk_seed, pk_seed, idx_tree, idx_leaf);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;

    (void)fors_msg_bytes;
    *signature_len = expected_sig_len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Verify an SLH-DSA signature.
 * @param[in] param FIPS 205 SLH-DSA parameter set.
 * @param[in] public_key Public-key buffer.
 * @param[in] noxtls_message Signed message.
 * @param[in] message_len Message length in bytes.
 * @param[in] signature Signature buffer.
 * @param[in] signature_len Signature length in bytes.
 * @return NOXTLS_RETURN_NOT_SUPPORTED until the FIPS 205 primitive backend is complete.
 */
noxtls_return_t noxtls_slhdsa_verify(noxtls_slhdsa_param_t param,
                                     const uint8_t *public_key,
                                     const uint8_t *noxtls_message,
                                     uint32_t message_len,
                                     const uint8_t *signature,
                                     uint32_t signature_len)
{
    slhdsa_params_t p;
    uint8_t digest[SLHDSA_MAX_MD_LEN];
    uint8_t fors_pk[SLHDSA_MAX_N];
    uint8_t root[SLHDSA_MAX_N];
    uint8_t adrs[SLHDSA_ADRS_LEN];
    const uint8_t *pk_seed;
    const uint8_t *pk_root;
    const uint8_t *r;
    uint64_t idx_tree;
    uint32_t idx_leaf;
    uint32_t fors_msg_bytes;
    uint32_t fors_sig_len;
    noxtls_return_t rc;

    if(public_key == NULL || signature == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(noxtls_message == NULL && message_len != 0u) {
        return NOXTLS_RETURN_NULL;
    }
    rc = slhdsa_get_params(param, &p);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(signature_len != p.sizes.signature_len) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    pk_seed = public_key;
    pk_root = public_key + p.n;
    r = signature;
    signature += p.n;
    rc = slhdsa_h_msg(&p, r, pk_seed, pk_root, noxtls_message, message_len, digest);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    fors_msg_bytes = slhdsa_digest_indices(&p, digest, &idx_tree, &idx_leaf);

    memset(adrs, 0, sizeof(adrs));
    slhdsa_adrs_set_layer(adrs, 0u);
    slhdsa_adrs_set_tree(adrs, idx_tree);
    slhdsa_adrs_set_type(adrs, SLHDSA_ADRS_TYPE_FORS_TREE);
    slhdsa_adrs_set_keypair(adrs, idx_leaf);
    rc = slhdsa_fors_pk_from_sig(&p, fors_pk, signature, digest, pk_seed, adrs);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    fors_sig_len = p.k * (p.a + 1u) * p.n;
    signature += fors_sig_len;
    rc = slhdsa_ht_verify(&p, root, signature, fors_pk, pk_seed, idx_tree, idx_leaf);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;

    (void)fors_msg_bytes;
    return noxtls_secret_memcmp(root, pk_root, p.n) == 0 ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
}
