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
* File:    noxtls_slhdsa.c
* Summary: SLH-DSA (NIST FIPS 205) API and parameter contracts.
*
*
*****************************************************************************/

#include <stdint.h>

#include "drbg/noxtls_drbg.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha3/noxtls_sha3.h"
#include "mdigest/sha512/noxtls_sha512.h"
#include "noxtls_slhdsa.h"
#include "common/noxtls_ct.h"

#if NOXTLS_FEATURE_SLH_DSA

#define SLHDSA_WOTS_LG_W 4U
#define SLHDSA_WOTS_W 16U
#define SLHDSA_WOTS_LEN2 3U
#define SLHDSA_MAX_N 32U
#define SLHDSA_MAX_WOTS_LEN 67u
/* Largest XMSS subtree height h' over all FIPS 205 parameter sets (128s/192s). */
#define SLHDSA_MAX_HP 9U
#define SLHDSA_MAX_A 14U
#define SLHDSA_MAX_K 35U
#define SLHDSA_MAX_MD_LEN 49U
#define SLHDSA_ADRS_LEN 32U
#define SLHDSA_SHA2_ADRS_LEN 22U
#define SLHDSA_SHA256_BLOCK_LEN 64U
#define SLHDSA_SHA512_BLOCK_LEN 128U
#define SLHDSA_SHA256_LEN 32U
#define SLHDSA_SHA512_LEN 64U
#define SLHDSA_ADRS_TYPE_WOTS_HASH 0U
#define SLHDSA_ADRS_TYPE_WOTS_PK 1U
#define SLHDSA_ADRS_TYPE_TREE 2U
#define SLHDSA_ADRS_TYPE_FORS_TREE 3U
#define SLHDSA_ADRS_TYPE_FORS_ROOTS 4U
#define SLHDSA_ADRS_TYPE_WOTS_PRF 5U
#define SLHDSA_ADRS_TYPE_FORS_PRF 6U

/**
 * Message M' handed to the FIPS 205 internal functions, kept as fragments so the
 * external-interface header and context string never need to be copied:
 * M' = hdr[0..hdr_len) || ctx || msg (hdr_len is 0 for the internal interface,
 * 2 for pure slh_sign/slh_verify where hdr = 0x00 || len(ctx)).
 */
typedef struct
{
    uint8_t hdr[2];
    uint32_t hdr_len;
    const uint8_t *ctx;
    uint32_t ctx_len;
    const uint8_t *msg;
    uint32_t msg_len;
} slhdsa_msg_t;

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

    noxtls_secure_zero((sizes), sizeof(*(sizes)));
    switch(param) {
        case NOXTLS_SLHDSA_SHA2_128S:
        case NOXTLS_SLHDSA_SHAKE_128S:
            sizes->public_key_len = 32U;
            sizes->secret_key_len = 64U;
            sizes->signature_len = 7856U;
            sizes->security_category = 1U;
            sizes->small_variant = 1U;
            break;
        case NOXTLS_SLHDSA_SHA2_128F:
        case NOXTLS_SLHDSA_SHAKE_128F:
            sizes->public_key_len = 32U;
            sizes->secret_key_len = 64U;
            sizes->signature_len = 17088U;
            sizes->security_category = 1U;
            sizes->small_variant = 0U;
            break;
        case NOXTLS_SLHDSA_SHA2_192S:
        case NOXTLS_SLHDSA_SHAKE_192S:
            sizes->public_key_len = 48U;
            sizes->secret_key_len = 96U;
            sizes->signature_len = 16224U;
            sizes->security_category = 3U;
            sizes->small_variant = 1U;
            break;
        case NOXTLS_SLHDSA_SHA2_192F:
        case NOXTLS_SLHDSA_SHAKE_192F:
            sizes->public_key_len = 48U;
            sizes->secret_key_len = 96U;
            sizes->signature_len = 35664U;
            sizes->security_category = 3U;
            sizes->small_variant = 0U;
            break;
        case NOXTLS_SLHDSA_SHA2_256S:
        case NOXTLS_SLHDSA_SHAKE_256S:
            sizes->public_key_len = 64U;
            sizes->secret_key_len = 128U;
            sizes->signature_len = 29792U;
            sizes->security_category = 5U;
            sizes->small_variant = 1U;
            break;
        case NOXTLS_SLHDSA_SHA2_256F:
        case NOXTLS_SLHDSA_SHAKE_256F:
            sizes->public_key_len = 64U;
            sizes->secret_key_len = 128U;
            sizes->signature_len = 49856U;
            sizes->security_category = 5U;
            sizes->small_variant = 0U;
            break;
        default:
            return NOXTLS_RETURN_INVALID_PARAM;
    }

    sizes->hash_family_sha2 = ((param >= NOXTLS_SLHDSA_SHA2_128S && param <= NOXTLS_SLHDSA_SHA2_256F) != 0) ? 1U : 0U;
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
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(p == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    noxtls_secure_zero((p), sizeof(*(p)));
    rc = slhdsa_get_sizes(param, &p->sizes);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    switch(param) {
        case NOXTLS_SLHDSA_SHA2_128S:
        case NOXTLS_SLHDSA_SHAKE_128S:
            p->n = 16U;
            p->h = 63U;
            p->d = 7U;
            p->hp = 9U;
            p->a = 12U;
            p->k = 14U;
            p->md_len = 30U;
            p->wots_len = (2U * p->n) + SLHDSA_WOTS_LEN2;
            return NOXTLS_RETURN_SUCCESS;
        case NOXTLS_SLHDSA_SHA2_128F:
        case NOXTLS_SLHDSA_SHAKE_128F:
            p->n = 16U;
            p->h = 66U;
            p->d = 22U;
            p->hp = 3U;
            p->a = 6U;
            p->k = 33U;
            p->md_len = 34U;
            p->wots_len = (2U * p->n) + SLHDSA_WOTS_LEN2;
            return NOXTLS_RETURN_SUCCESS;
        case NOXTLS_SLHDSA_SHA2_192S:
        case NOXTLS_SLHDSA_SHAKE_192S:
            p->n = 24U;
            p->h = 63U;
            p->d = 7U;
            p->hp = 9U;
            p->a = 14U;
            p->k = 17U;
            p->md_len = 39U;
            p->wots_len = (2U * p->n) + SLHDSA_WOTS_LEN2;
            return NOXTLS_RETURN_SUCCESS;
        case NOXTLS_SLHDSA_SHA2_192F:
        case NOXTLS_SLHDSA_SHAKE_192F:
            p->n = 24U;
            p->h = 66U;
            p->d = 22U;
            p->hp = 3U;
            p->a = 8U;
            p->k = 33U;
            p->md_len = 42U;
            p->wots_len = (2U * p->n) + SLHDSA_WOTS_LEN2;
            return NOXTLS_RETURN_SUCCESS;
        case NOXTLS_SLHDSA_SHA2_256S:
        case NOXTLS_SLHDSA_SHAKE_256S:
            p->n = 32U;
            p->h = 64U;
            p->d = 8U;
            p->hp = 8U;
            p->a = 14U;
            p->k = 22U;
            p->md_len = 47U;
            p->wots_len = (2U * p->n) + SLHDSA_WOTS_LEN2;
            return NOXTLS_RETURN_SUCCESS;
        case NOXTLS_SLHDSA_SHA2_256F:
        case NOXTLS_SLHDSA_SHAKE_256F:
            p->n = 32U;
            p->h = 68U;
            p->d = 17U;
            p->hp = 4U;
            p->a = 9U;
            p->k = 35U;
            p->md_len = 49U;
            p->wots_len = (2U * p->n) + SLHDSA_WOTS_LEN2;
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
    out[0] = (uint8_t)(value >>24U);
    out[1] = (uint8_t)(value >>16U);
    out[2] = (uint8_t)(value >>8U);
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
    uint32_t i = 0U;

    for(i = 0U; i < 8U; i += 1U) {
        out[7U - i] = (uint8_t)(value >> (8U * i));
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
    uint64_t value = 0U;
    uint32_t i = 0U;

    for(i = 0U; i < len; i += 1U) {
        value = (value << 8U) | (uint16_t)in[i];
    }
    return value;
}

/**
 * @brief Set the layer address field in an ADRS object.
 * @param[in,out] adrs Address object.
 * @param[in] layer Layer value.
 * @return void.
 */
static void slhdsa_adrs_set_layer(uint8_t *adrs, uint32_t layer)
{
    (void)slhdsa_store32(adrs, layer);
}

/**
 * @brief Set the tree address field in an ADRS object.
 * @param[in,out] adrs Address object.
 * @param[in] tree Tree value.
 * @return void.
 */
static void slhdsa_adrs_set_tree(uint8_t *adrs, uint64_t tree)
{
    (void)slhdsa_store64(&adrs[8U], tree);
}

/**
 * @brief Set ADRS type and clear type-specific fields.
 * @param[in,out] adrs Address object.
 * @param[in] type Address type.
 * @return void.
 */
static void slhdsa_adrs_set_type(uint8_t *adrs, uint32_t type)
{
    (void)slhdsa_store32(&adrs[16U], type);
    noxtls_secure_zero((&adrs[20U]), (size_t)(12U));
}

/**
 * @brief Set the key-pair address field.
 * @param[in,out] adrs Address object.
 * @param[in] value Key-pair address.
 * @return void.
 */
static void slhdsa_adrs_set_keypair(uint8_t *adrs, uint32_t value)
{
    (void)slhdsa_store32(&adrs[20U], value);
}

/**
 * @brief Set the chain address field.
 * @param[in,out] adrs Address object.
 * @param[in] value Chain address.
 * @return void.
 */
static void slhdsa_adrs_set_chain(uint8_t *adrs, uint32_t value)
{
    (void)slhdsa_store32(&adrs[24U], value);
}

/**
 * @brief Set the hash address field.
 * @param[in,out] adrs Address object.
 * @param[in] value Hash address.
 * @return void.
 */
static void slhdsa_adrs_set_hash(uint8_t *adrs, uint32_t value)
{
    (void)slhdsa_store32(&adrs[28U], value);
}

/**
 * @brief Set the tree height field.
 * @param[in,out] adrs Address object.
 * @param[in] value Tree height.
 * @return void.
 */
static void slhdsa_adrs_set_tree_height(uint8_t *adrs, uint32_t value)
{
    (void)slhdsa_store32(&adrs[24U], value);
}

/**
 * @brief Set the tree index field.
 * @param[in,out] adrs Address object.
 * @param[in] value Tree index.
 * @return void.
 */
static void slhdsa_adrs_set_tree_index(uint8_t *adrs, uint32_t value)
{
    (void)slhdsa_store32(&adrs[28U], value);
}

/**
 * @brief Get the key-pair address field.
 * @param[in] adrs Address object.
 * @return Key-pair address.
 */
static uint32_t slhdsa_adrs_get_keypair(const uint8_t *adrs) { return (uint32_t)slhdsa_load_be(&adrs[20U], 4U); }

/**
 * @brief Squeeze SHAKE256 over up to five input fragments.
 * @param[in] a First fragment.
 * @param[in] a_len First fragment length.
 * @param[in] b Second fragment.
 * @param[in] b_len Second fragment length.
 * @param[in] c Third fragment.
 * @param[in] c_len Third fragment length.
 * @param[in] d Fourth fragment.
 * @param[in] d_len Fourth fragment length.
 * @param[in] e Fifth fragment.
 * @param[in] e_len Fifth fragment length.
 * @param[out] out Output buffer.
 * @param[in] out_len Output length.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_shake256_5(const uint8_t *a,
                                         uint32_t a_len,
                                         const uint8_t *b,
                                         uint32_t b_len,
                                         const uint8_t *c,
                                         uint32_t c_len,
                                         const uint8_t *d,
                                         uint32_t d_len,
                                         const uint8_t *e,
                                         uint32_t e_len,
                                         uint8_t *out,
                                         uint32_t out_len)
{
    noxtls_sha3_ctx_t ctx;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    rc = noxtls_shake256_init(&ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(a_len != 0U) {
        rc = noxtls_shake256_update(&ctx, a, a_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    if(b_len != 0U) {
        rc = noxtls_shake256_update(&ctx, b, b_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    if(c_len != 0U) {
        rc = noxtls_shake256_update(&ctx, c, c_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    if(d_len != 0U) {
        rc = noxtls_shake256_update(&ctx, d, d_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    if(e_len != 0U) {
        rc = noxtls_shake256_update(&ctx, e, e_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    rc = noxtls_shake256_final(&ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return noxtls_shake256_squeeze(&ctx, out, out_len);
}

/**
 * @brief Compress a 32-byte ADRS object for SHA2 SLH-DSA functions.
 * @param[in] adrs Expanded FIPS 205 address.
 * @param[out] out Compressed 22-byte address.
 * @return void.
 */
static void slhdsa_compress_adrs(const uint8_t *adrs, uint8_t *out)
{
    out[0] = adrs[3];
    noxtls_copy_u8(&out[1U], (size_t)(SLHDSA_SHA2_ADRS_LEN - 1U), &adrs[8U], (size_t)8U);
    out[9] = adrs[19];
    noxtls_copy_u8(&out[10U], (size_t)(SLHDSA_SHA2_ADRS_LEN - 10U), &adrs[20U], (size_t)12U);
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
 * @param[in] e Fifth fragment.
 * @param[in] e_len Fifth fragment length.
 * @param[out] out SHA-256 digest.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_sha256_5(const uint8_t *a,
                                       uint32_t a_len,
                                       const uint8_t *b,
                                       uint32_t b_len,
                                       const uint8_t *c,
                                       uint32_t c_len,
                                       const uint8_t *d,
                                       uint32_t d_len,
                                       const uint8_t *e,
                                       uint32_t e_len,
                                       uint8_t out[SLHDSA_SHA256_LEN])
{
    noxtls_sha_ctx_t ctx;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    rc = noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(a_len != 0U) {
        rc = noxtls_sha256_update(&ctx, a, a_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    if(b_len != 0U) {
        rc = noxtls_sha256_update(&ctx, b, b_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    if(c_len != 0U) {
        rc = noxtls_sha256_update(&ctx, c, c_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    if(d_len != 0U) {
        rc = noxtls_sha256_update(&ctx, d, d_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    if(e_len != 0U) {
        rc = noxtls_sha256_update(&ctx, e, e_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
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
 * @param[in] e Fifth fragment.
 * @param[in] e_len Fifth fragment length.
 * @param[out] out SHA-512 digest.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_sha512_5(const uint8_t *a,
                                       uint32_t a_len,
                                       const uint8_t *b,
                                       uint32_t b_len,
                                       const uint8_t *c,
                                       uint32_t c_len,
                                       const uint8_t *d,
                                       uint32_t d_len,
                                       const uint8_t *e,
                                       uint32_t e_len,
                                       uint8_t out[SLHDSA_SHA512_LEN])
{
    noxtls_sha512_ctx_t ctx;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    rc = noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(a_len != 0U) {
        rc = noxtls_sha512_update(&ctx, a, a_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    if(b_len != 0U) {
        rc = noxtls_sha512_update(&ctx, b, b_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    if(c_len != 0U) {
        rc = noxtls_sha512_update(&ctx, c, c_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    if(d_len != 0U) {
        rc = noxtls_sha512_update(&ctx, d, d_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    if(e_len != 0U) {
        rc = noxtls_sha512_update(&ctx, e, e_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    return noxtls_sha512_finish(&ctx, out);
}

/**
 * @brief HMAC-SHA-256 / HMAC-SHA-512 over up to four message fragments.
 *
 * Only keys up to one hash block are supported (SLH-DSA keys are n <= 32 bytes).
 * A single pad buffer is reused for ipad and opad and wiped before returning.
 *
 * @param[in] use_sha512 Non-zero for SHA-512, zero for SHA-256.
 * @param[in] key HMAC key.
 * @param[in] key_len Key length (at most one block).
 * @param[in] a First message fragment.
 * @param[in] a_len First fragment length.
 * @param[in] b Second message fragment.
 * @param[in] b_len Second fragment length.
 * @param[in] c Third message fragment.
 * @param[in] c_len Third fragment length.
 * @param[in] d Fourth message fragment.
 * @param[in] d_len Fourth fragment length.
 * @param[out] out Output digest (32 or 64 bytes).
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_hmac(uint8_t use_sha512,
                                   const uint8_t *key,
                                   uint32_t key_len,
                                   const uint8_t *a,
                                   uint32_t a_len,
                                   const uint8_t *b,
                                   uint32_t b_len,
                                   const uint8_t *c,
                                   uint32_t c_len,
                                   const uint8_t *d,
                                   uint32_t d_len,
                                   uint8_t out[SLHDSA_SHA512_LEN])
{
    uint8_t pad[SLHDSA_SHA512_BLOCK_LEN];
    uint8_t inner[SLHDSA_SHA512_LEN];
    uint32_t block_len = (use_sha512 != 0U) ? SLHDSA_SHA512_BLOCK_LEN : SLHDSA_SHA256_BLOCK_LEN;
    uint32_t digest_len = (use_sha512 != 0U) ? SLHDSA_SHA512_LEN : SLHDSA_SHA256_LEN;
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(key_len > block_len) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    for(i = 0U; i < block_len; i += 1U) {
        uint8_t kb = (i < key_len) ? key[i] : 0U;
        pad[i] = (uint8_t)(kb ^ 0x36U);
    }
    if(use_sha512 != 0U) {
        rc = slhdsa_sha512_5(pad, block_len, a, a_len, b, b_len, c, c_len, d, d_len, inner);
    } else {
        rc = slhdsa_sha256_5(pad, block_len, a, a_len, b, b_len, c, c_len, d, d_len, inner);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        for(i = 0U; i < block_len; i += 1U) {
            pad[i] = (uint8_t)(pad[i] ^ (uint8_t)(0x36U ^ 0x5cU));
        }
        if(use_sha512 != 0U) {
            rc = slhdsa_sha512_5(pad, block_len, inner, digest_len, NULL, 0U, NULL, 0U, NULL, 0U, out);
        } else {
            rc = slhdsa_sha256_5(pad, block_len, inner, digest_len, NULL, 0U, NULL, 0U, NULL, 0U, out);
        }
    }
    noxtls_secure_zero((pad), sizeof(pad));
    noxtls_secure_zero((inner), sizeof(inner));
    return rc;
}

/**
 * @brief MGF1-SHA-256 / MGF1-SHA-512 with a three-fragment seed.
 * @param[in] use_sha512 Non-zero for SHA-512, zero for SHA-256.
 * @param[in] a First seed fragment.
 * @param[in] a_len First fragment length.
 * @param[in] b Second seed fragment.
 * @param[in] b_len Second fragment length.
 * @param[in] c Third seed fragment.
 * @param[in] c_len Third fragment length.
 * @param[out] out Output mask.
 * @param[in] out_len Output length.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_mgf1(uint8_t use_sha512,
                                   const uint8_t *a,
                                   uint32_t a_len,
                                   const uint8_t *b,
                                   uint32_t b_len,
                                   const uint8_t *c,
                                   uint32_t c_len,
                                   uint8_t *out,
                                   uint32_t out_len)
{
    uint8_t counter[4];
    uint8_t digest[SLHDSA_SHA512_LEN];
    uint32_t digest_len = (use_sha512 != 0U) ? SLHDSA_SHA512_LEN : SLHDSA_SHA256_LEN;
    uint32_t produced = 0U;
    uint32_t ctr = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    while(produced < out_len) {
        uint32_t take = 0U;

        slhdsa_store32(counter, ctr);
        if(use_sha512 != 0U) {
            rc = slhdsa_sha512_5(a, a_len, b, b_len, c, c_len, counter, (uint32_t)sizeof(counter), NULL, 0U, digest);
        } else {
            rc = slhdsa_sha256_5(a, a_len, b, b_len, c, c_len, counter, (uint32_t)sizeof(counter), NULL, 0U, digest);
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        take = out_len - produced;
        if(take > digest_len) {
            take = digest_len;
        }
        noxtls_copy_u8(&out[produced], (size_t)take, digest, (size_t)take);
        produced += take;
        ctr += 1U;
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
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    rc = drbg_instantiate(&drbg, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = drbg_generate(&drbg, out, out_len * 8U, NULL, 0);
    }
    noxtls_secure_zero((&drbg), sizeof(drbg));
    return rc;
}

/** Zero padding for the SHA-2 `PK.seed || toByte(0, 64/128 - n)` prefix. */
static const uint8_t g_slhdsa_zero_pad[SLHDSA_SHA512_BLOCK_LEN] = { 0U };

/**
 * @brief Whether a SHA-2 tweakable hash with this input length uses SHA-512.
 *
 * FIPS 205 sec. 11.2: category 1 uses SHA-256 for F, H and T_l; categories 3/5
 * use SHA-256 for F (and PRF) only and SHA-512 for H and T_l.
 *
 * @param[in] p Parameter metadata.
 * @param[in] in_len Message length of the tweakable hash (n for F).
 * @return 1 for SHA-512, 0 for SHA-256.
 */
static uint8_t slhdsa_sha2_uses_512(const slhdsa_params_t *p, uint32_t in_len)
{
    return ((p->n != 16U) && (in_len != p->n)) ? 1U : 0U;
}

/**
 * @brief SLH-DSA PRF(PK.seed, SK.seed, ADRS).
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
                                        const uint8_t *adrs,
                                        uint8_t *out)
{
    uint8_t adrsc[SLHDSA_SHA2_ADRS_LEN];
    uint8_t digest[SLHDSA_SHA256_LEN];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(p->sizes.hash_family_sha2 != 0U) {
        slhdsa_compress_adrs(adrs, adrsc);
        rc = slhdsa_sha256_5(pk_seed, p->n,
                             g_slhdsa_zero_pad, SLHDSA_SHA256_BLOCK_LEN - p->n,
                             adrsc, SLHDSA_SHA2_ADRS_LEN,
                             sk_seed, p->n, NULL, 0U,
                             digest);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_copy_u8(out, (size_t)SLHDSA_MAX_N, digest, (size_t)(p->n));
        }
        noxtls_secure_zero((digest), sizeof(digest));
        return rc;
    }
    return slhdsa_shake256_5(pk_seed, p->n, adrs, SLHDSA_ADRS_LEN, sk_seed, p->n, NULL, 0U, NULL, 0U, out, p->n);
}

/**
 * @brief SLH-DSA tweakable hash F / H / T_l over a contiguous input.
 * @param[in] p Parameter metadata.
 * @param[in] pk_seed Public seed.
 * @param[in] adrs Address object.
 * @param[in] in Input buffer (may alias out).
 * @param[in] in_len Input length.
 * @param[out] out Output n-byte string.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_shake_thash(const slhdsa_params_t *p,
                                          const uint8_t *pk_seed,
                                          const uint8_t *adrs,
                                          const uint8_t *in,
                                          uint32_t in_len,
                                          uint8_t *out)
{
    uint8_t adrsc[SLHDSA_SHA2_ADRS_LEN];
    uint8_t digest[SLHDSA_SHA512_LEN];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(p->sizes.hash_family_sha2 != 0U) {
        slhdsa_compress_adrs(adrs, adrsc);
        if(slhdsa_sha2_uses_512(p, in_len) == 0U) {
            rc = slhdsa_sha256_5(pk_seed, p->n,
                                 g_slhdsa_zero_pad, SLHDSA_SHA256_BLOCK_LEN - p->n,
                                 adrsc, SLHDSA_SHA2_ADRS_LEN,
                                 in, in_len, NULL, 0U,
                                 digest);
        } else {
            rc = slhdsa_sha512_5(pk_seed, p->n,
                                 g_slhdsa_zero_pad, SLHDSA_SHA512_BLOCK_LEN - p->n,
                                 adrsc, SLHDSA_SHA2_ADRS_LEN,
                                 in, in_len, NULL, 0U,
                                 digest);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_copy_u8(out, (size_t)SLHDSA_MAX_N, digest, (size_t)(p->n));
        }
        return rc;
    }
    return slhdsa_shake256_5(pk_seed, p->n, adrs, SLHDSA_ADRS_LEN, in, in_len, NULL, 0U, NULL, 0U, out, p->n);
}

/**
 * @brief SLH-DSA message randomizer PRF_msg(SK.prf, opt_rand, M').
 * @param[in] p Parameter metadata.
 * @param[in] sk_prf Secret PRF key.
 * @param[in] opt_rand Optional randomizer.
 * @param[in] m Message M' fragments.
 * @param[out] r Output randomizer.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_prf_msg(const slhdsa_params_t *p,
                                      const uint8_t *sk_prf,
                                      const uint8_t *opt_rand,
                                      const slhdsa_msg_t *m,
                                      uint8_t *r)
{
    uint8_t digest[SLHDSA_SHA512_LEN];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(p->sizes.hash_family_sha2 != 0U) {
        rc = slhdsa_hmac((uint8_t)((p->n > 16U) ? 1U : 0U),
                         sk_prf, p->n,
                         opt_rand, p->n,
                         m->hdr, m->hdr_len,
                         m->ctx, m->ctx_len,
                         m->msg, m->msg_len,
                         digest);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_copy_u8(r, (size_t)SLHDSA_MAX_N, digest, (size_t)(p->n));
        }
        return rc;
    }
    return slhdsa_shake256_5(sk_prf, p->n, opt_rand, p->n, m->hdr, m->hdr_len, m->ctx, m->ctx_len,
                             m->msg, m->msg_len, r, p->n);
}

/**
 * @brief SLH-DSA H_msg(R, PK.seed, PK.root, M').
 * @param[in] p Parameter metadata.
 * @param[in] r Message randomizer.
 * @param[in] pk_seed Public seed.
 * @param[in] pk_root Public root.
 * @param[in] m Message M' fragments.
 * @param[out] digest Output digest (p->md_len bytes).
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_h_msg(const slhdsa_params_t *p,
                                    const uint8_t *r,
                                    const uint8_t *pk_seed,
                                    const uint8_t *pk_root,
                                    const slhdsa_msg_t *m,
                                    uint8_t digest[SLHDSA_MAX_MD_LEN])
{
    uint8_t pk[NOXTLS_SLHDSA_MAX_PUBLIC_KEY_LEN];
    uint8_t msg_hash[SLHDSA_SHA512_LEN];
    uint8_t use_sha512 = (uint8_t)((p->n > 16U) ? 1U : 0U);
    uint32_t hash_len = (use_sha512 != 0U) ? SLHDSA_SHA512_LEN : SLHDSA_SHA256_LEN;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    noxtls_copy_u8(pk, sizeof(pk), pk_seed, (size_t)(p->n));
    noxtls_copy_u8(&pk[p->n], sizeof(pk) - (size_t)(p->n), pk_root, (size_t)p->n);
    if(p->sizes.hash_family_sha2 == 0U) {
        return slhdsa_shake256_5(r, p->n, pk, 2U * p->n, m->hdr, m->hdr_len, m->ctx, m->ctx_len,
                                 m->msg, m->msg_len, digest, p->md_len);
    }
    if(use_sha512 != 0U) {
        rc = slhdsa_sha512_5(r, p->n, pk, 2U * p->n, m->hdr, m->hdr_len, m->ctx, m->ctx_len,
                             m->msg, m->msg_len, msg_hash);
    } else {
        rc = slhdsa_sha256_5(r, p->n, pk, 2U * p->n, m->hdr, m->hdr_len, m->ctx, m->ctx_len,
                             m->msg, m->msg_len, msg_hash);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return slhdsa_mgf1(use_sha512, r, p->n, pk_seed, p->n, msg_hash, hash_len, digest, p->md_len);
}

/**
 * @brief Convert an n-byte string to WOTS+ base-16 chain lengths (with checksum).
 * @param[in] p Parameter metadata.
 * @param[in] msg n-byte input.
 * @param[out] out Output WOTS+ chain lengths.
 * @return void.
 */
static void slhdsa_chain_lengths(const slhdsa_params_t *p, const uint8_t *msg, uint8_t out[SLHDSA_MAX_WOTS_LEN])
{
    uint32_t len1 = (uint32_t)(2U * p->n);
    uint32_t csum = 0U;
    uint32_t i = 0U;

    for(i = 0U; i < p->n; i += 1U) {
        out[2U * i] = (uint8_t)(msg[i] >> 4U);
        out[(2U * i) + 1U] = (uint8_t)(msg[i] & 0x0FU);
    }
    for(i = 0U; i < len1; i += 1U) {
        csum += (SLHDSA_WOTS_W - 1U) - out[i];
    }
    /* FIPS 205 Alg. 7: base_2b(toByte(csum << 4, 2), 4, 3) == the three low
     * nibbles of the unshifted checksum (csum < 2^12). */
    out[len1] = (uint8_t)((csum >> 8U) & 0x0FU);
    out[len1 + 1U] = (uint8_t)((csum >> 4U) & 0x0FU);
    out[len1 + 2U] = (uint8_t)(csum & 0x0FU);
}

/**
 * @brief Iterate a WOTS+ hash chain.
 * @param[in] p Parameter metadata.
 * @param[out] out Output chain value (may alias in).
 * @param[in] in Input chain value.
 * @param[in] start Start index.
 * @param[in] steps Number of chain steps.
 * @param[in] pk_seed Public seed.
 * @param[in] adrs WOTS_HASH address with key pair and chain set.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_chain(const slhdsa_params_t *p,
                                    uint8_t *out,
                                    const uint8_t *in,
                                    uint32_t start,
                                    uint32_t steps,
                                    const uint8_t *pk_seed,
                                    const uint8_t *adrs)
{
    uint8_t local_adrs[SLHDSA_ADRS_LEN];
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    noxtls_move_u8(out, (size_t)SLHDSA_MAX_N, in, (size_t)(p->n));
    noxtls_copy_u8(local_adrs, sizeof(local_adrs), adrs, (size_t)SLHDSA_ADRS_LEN);
    for(i = start; i < start + steps; i += 1U) {
        slhdsa_adrs_set_hash(local_adrs, i);
        rc = slhdsa_shake_thash(p, pk_seed, local_adrs, out, p->n, out);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/** Streaming T_l producers (see slhdsa_t_block). */
#define SLHDSA_T_WOTS_PKGEN   1U
#define SLHDSA_T_WOTS_FROMSIG 2U
#define SLHDSA_T_FORS_SIGN    3U
#define SLHDSA_T_FORS_VERIFY  4U

/**
 * Description of the n-byte blocks fed to a streaming T_l hash.  Streaming
 * avoids materialising the len*n WOTS+ public key (up to 2144 bytes) and the
 * k*n FORS roots (up to 1120 bytes) on the stack.
 */
typedef struct
{
    uint32_t kind;            /**< SLHDSA_T_* producer. */
    const uint8_t *sk_seed;   /**< SK.seed (pkgen / FORS sign). */
    const uint8_t *pk_seed;   /**< PK.seed. */
    const uint8_t *adrs;      /**< WOTS_HASH or FORS_TREE base address. */
    const uint8_t *sig_in;    /**< WOTS+ or FORS signature (verify). */
    uint8_t *sig_out;         /**< FORS signature output (sign). */
    const uint8_t *lengths;   /**< WOTS+ chain lengths (verify). */
    const uint32_t *indices;  /**< FORS indices. */
} slhdsa_t_job_t;

static noxtls_return_t slhdsa_t_stream(const slhdsa_params_t *p,
                                       const slhdsa_t_job_t *job,
                                       uint32_t type,
                                       uint32_t count,
                                       uint8_t *out);

/**
 * @brief Generate a WOTS+ public key (FIPS 205 Alg. 6).
 * @param[in] p Parameter metadata.
 * @param[out] pk Output n-byte compressed WOTS+ public key.
 * @param[in] sk_seed Secret seed.
 * @param[in] pk_seed Public seed.
 * @param[in] adrs WOTS_HASH address with the key-pair index set.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_wots_pkgen(const slhdsa_params_t *p,
                                         uint8_t *pk,
                                         const uint8_t *sk_seed,
                                         const uint8_t *pk_seed,
                                         const uint8_t *adrs)
{
    slhdsa_t_job_t job;

    noxtls_secure_zero((&job), sizeof(job));
    job.kind = SLHDSA_T_WOTS_PKGEN;
    job.sk_seed = sk_seed;
    job.pk_seed = pk_seed;
    job.adrs = adrs;
    return slhdsa_t_stream(p, &job, SLHDSA_ADRS_TYPE_WOTS_PK, p->wots_len, pk);
}

/**
 * @brief Generate a WOTS+ signature (FIPS 205 Alg. 7).
 * @param[in] p Parameter metadata.
 * @param[out] sig Output WOTS+ signature.
 * @param[in] msg n-byte message digest.
 * @param[in] sk_seed Secret seed.
 * @param[in] pk_seed Public seed.
 * @param[in] adrs WOTS_HASH address with the key-pair index set.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_wots_sign(const slhdsa_params_t *p,
                                        uint8_t *sig,
                                        const uint8_t *msg,
                                        const uint8_t *sk_seed,
                                        const uint8_t *pk_seed,
                                        const uint8_t *adrs)
{
    uint8_t lengths[SLHDSA_MAX_WOTS_LEN];
    uint8_t chain_adrs[SLHDSA_ADRS_LEN];
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    slhdsa_chain_lengths(p, msg, lengths);
    for(i = 0U; i < p->wots_len; i += 1U) {
        uint8_t *sk = &sig[(i * p->n)];

        noxtls_copy_u8(chain_adrs, sizeof(chain_adrs), adrs, (size_t)SLHDSA_ADRS_LEN);
        slhdsa_adrs_set_type(chain_adrs, SLHDSA_ADRS_TYPE_WOTS_PRF);
        slhdsa_adrs_set_keypair(chain_adrs, slhdsa_adrs_get_keypair(adrs));
        slhdsa_adrs_set_chain(chain_adrs, i);
        rc = slhdsa_shake_prf(p, pk_seed, sk_seed, chain_adrs, sk);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        slhdsa_adrs_set_type(chain_adrs, SLHDSA_ADRS_TYPE_WOTS_HASH);
        slhdsa_adrs_set_keypair(chain_adrs, slhdsa_adrs_get_keypair(adrs));
        slhdsa_adrs_set_chain(chain_adrs, i);
        rc = slhdsa_chain(p, sk, sk, 0U, lengths[i], pk_seed, chain_adrs);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Compute a WOTS+ public key from a signature (FIPS 205 Alg. 8).
 * @param[in] p Parameter metadata.
 * @param[out] pk Output n-byte compressed WOTS+ public key.
 * @param[in] sig WOTS+ signature.
 * @param[in] msg n-byte message digest.
 * @param[in] pk_seed Public seed.
 * @param[in] adrs WOTS_HASH address with the key-pair index set.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_wots_pk_from_sig(const slhdsa_params_t *p,
                                               uint8_t *pk,
                                               const uint8_t *sig,
                                               const uint8_t *msg,
                                               const uint8_t *pk_seed,
                                               const uint8_t *adrs)
{
    uint8_t lengths[SLHDSA_MAX_WOTS_LEN];
    slhdsa_t_job_t job;

    slhdsa_chain_lengths(p, msg, lengths);
    noxtls_secure_zero((&job), sizeof(job));
    job.kind = SLHDSA_T_WOTS_FROMSIG;
    job.pk_seed = pk_seed;
    job.adrs = adrs;
    job.sig_in = sig;
    job.lengths = lengths;
    return slhdsa_t_stream(p, &job, SLHDSA_ADRS_TYPE_WOTS_PK, p->wots_len, pk);
}

/**
 * @brief Compute an XMSS subtree root xmss_node(start >> height, height) (FIPS 205 Alg. 9).
 * @param[in] p Parameter metadata.
 * @param[out] root Output root.
 * @param[in] sk_seed Secret seed.
 * @param[in] pk_seed Public seed.
 * @param[in] adrs Base address (layer and tree set).
 * @param[in] start First leaf index (multiple of 2^height).
 * @param[in] height Subtree height (at most h').
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_xmss_treehash(const slhdsa_params_t *p,
                                            uint8_t *root,
                                            const uint8_t *sk_seed,
                                            const uint8_t *pk_seed,
                                            const uint8_t *adrs,
                                            uint32_t start,
                                            uint32_t height)
{
    uint8_t stack[(SLHDSA_MAX_HP + 1U) * SLHDSA_MAX_N];
    uint8_t stack_heights[SLHDSA_MAX_HP + 1U];
    uint8_t pair[2U * SLHDSA_MAX_N];
    uint8_t node_adrs[SLHDSA_ADRS_LEN];
    uint32_t stack_len = 0U;
    uint32_t leaf_count = (uint32_t)(1U << height);
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(height > SLHDSA_MAX_HP) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    for(i = 0U; i < leaf_count; i += 1U) {
        uint32_t node_height = 0U;
        uint32_t node_index = start + i;

        noxtls_copy_u8(node_adrs, sizeof(node_adrs), adrs, (size_t)SLHDSA_ADRS_LEN);
        slhdsa_adrs_set_type(node_adrs, SLHDSA_ADRS_TYPE_WOTS_HASH);
        slhdsa_adrs_set_keypair(node_adrs, node_index);
        rc = slhdsa_wots_pkgen(p, &pair[p->n], sk_seed, pk_seed, node_adrs);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        while((stack_len > 0U) && ((uint32_t)stack_heights[stack_len - 1U] == node_height)) {
            stack_len -= 1U;
            noxtls_copy_u8(pair, (size_t)p->n, &stack[(stack_len * p->n)], (size_t)p->n);
            noxtls_copy_u8(node_adrs, sizeof(node_adrs), adrs, (size_t)SLHDSA_ADRS_LEN);
            slhdsa_adrs_set_type(node_adrs, SLHDSA_ADRS_TYPE_TREE);
            slhdsa_adrs_set_tree_height(node_adrs, node_height + 1U);
            slhdsa_adrs_set_tree_index(node_adrs, node_index >> 1U);
            rc = slhdsa_shake_thash(p, pk_seed, node_adrs, pair, 2U * p->n, &pair[p->n]);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            node_height += 1U;
            node_index >>= 1U;
        }
        noxtls_copy_u8(&stack[(stack_len * p->n)], (size_t)p->n, &pair[p->n], (size_t)p->n);
        stack_heights[stack_len] = (uint8_t)node_height;
        stack_len += 1U;
    }
    if(stack_len != 1U) {
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_copy_u8(root, (size_t)SLHDSA_MAX_N, stack, (size_t)p->n);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Generate an XMSS signature (FIPS 205 Alg. 10).
 * @param[in] p Parameter metadata.
 * @param[out] sig Output XMSS signature (WOTS+ signature || AUTH).
 * @param[in] msg n-byte message to sign.
 * @param[in] sk_seed Secret seed.
 * @param[in] pk_seed Public seed.
 * @param[in] idx_leaf Leaf index.
 * @param[in] adrs Base address (layer and tree set).
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_xmss_sign(const slhdsa_params_t *p,
                                        uint8_t *sig,
                                        const uint8_t *msg,
                                        const uint8_t *sk_seed,
                                        const uint8_t *pk_seed,
                                        uint32_t idx_leaf,
                                        const uint8_t *adrs)
{
    uint8_t wots_adrs[SLHDSA_ADRS_LEN];
    uint8_t *auth = &sig[(p->wots_len * p->n)];
    uint32_t j = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    for(j = 0U; j < p->hp; j += 1U) {
        uint32_t start = ((idx_leaf >> j) ^ 1U) << j;

        rc = slhdsa_xmss_treehash(p, &auth[(j * p->n)], sk_seed, pk_seed, adrs, start, j);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    noxtls_copy_u8(wots_adrs, sizeof(wots_adrs), adrs, (size_t)SLHDSA_ADRS_LEN);
    slhdsa_adrs_set_type(wots_adrs, SLHDSA_ADRS_TYPE_WOTS_HASH);
    slhdsa_adrs_set_keypair(wots_adrs, idx_leaf);
    return slhdsa_wots_sign(p, sig, msg, sk_seed, pk_seed, wots_adrs);
}

/**
 * @brief Compute an XMSS public key from a signature (FIPS 205 Alg. 11).
 * @param[in] p Parameter metadata.
 * @param[out] root Output root.
 * @param[in] sig XMSS signature.
 * @param[in] msg Signed n-byte message.
 * @param[in] pk_seed Public seed.
 * @param[in] idx_leaf Leaf index.
 * @param[in] adrs Base address (layer and tree set).
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_xmss_pk_from_sig(const slhdsa_params_t *p,
                                               uint8_t *root,
                                               const uint8_t *sig,
                                               const uint8_t *msg,
                                               const uint8_t *pk_seed,
                                               uint32_t idx_leaf,
                                               const uint8_t *adrs)
{
    uint8_t pair[2U * SLHDSA_MAX_N];
    uint8_t node_adrs[SLHDSA_ADRS_LEN];
    const uint8_t *auth = &sig[(p->wots_len * p->n)];
    uint32_t idx = idx_leaf;
    uint32_t i = 0U;
    uint32_t pos = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    noxtls_copy_u8(node_adrs, sizeof(node_adrs), adrs, (size_t)SLHDSA_ADRS_LEN);
    slhdsa_adrs_set_type(node_adrs, SLHDSA_ADRS_TYPE_WOTS_HASH);
    slhdsa_adrs_set_keypair(node_adrs, idx_leaf);
    /* node[0] lives in the half of pair selected by the current index bit. */
    pos = ((idx & 1U) == 0U) ? 0U : p->n;
    rc = slhdsa_wots_pk_from_sig(p, &pair[pos], sig, msg, pk_seed, node_adrs);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    for(i = 0U; i < p->hp; i += 1U) {
        noxtls_copy_u8(&pair[p->n - pos], (size_t)p->n, &auth[(i * p->n)], (size_t)p->n);
        noxtls_copy_u8(node_adrs, sizeof(node_adrs), adrs, (size_t)SLHDSA_ADRS_LEN);
        slhdsa_adrs_set_type(node_adrs, SLHDSA_ADRS_TYPE_TREE);
        slhdsa_adrs_set_tree_height(node_adrs, i + 1U);
        slhdsa_adrs_set_tree_index(node_adrs, idx >> 1U);
        idx >>= 1U;
        pos = ((idx & 1U) == 0U) ? 0U : p->n;
        rc = slhdsa_shake_thash(p, pk_seed, node_adrs, pair, 2U * p->n, &pair[pos]);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    noxtls_copy_u8(root, (size_t)SLHDSA_MAX_N, &pair[pos], (size_t)p->n);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Decode FORS message bits into indices (FIPS 205 Alg. 4 base_2b, MSB first).
 * @param[in] p Parameter metadata.
 * @param[out] indices Output FORS indices.
 * @param[in] msg FORS message bytes.
 * @return void.
 */
static void slhdsa_fors_indices(const slhdsa_params_t *p,
                                uint32_t indices[SLHDSA_MAX_K],
                                const uint8_t *msg)
{
    uint32_t i = 0U;
    uint32_t j = 0U;
    uint32_t offset = 0U;

    for(i = 0U; i < p->k; i += 1U) {
        indices[i] = 0U;
        for(j = 0U; j < p->a; j += 1U) {
            uint32_t bit = (uint32_t)((uint32_t)msg[offset >> 3U] >> (7U - (offset & 7U))) & 1U;
            indices[i] = (uint32_t)(indices[i] << 1U) | bit;
            offset += 1U;
        }
    }
}

/**
 * @brief Generate a FORS secret-key element (FIPS 205 Alg. 14).
 * @param[in] p Parameter metadata.
 * @param[out] sk Output FORS secret key element.
 * @param[in] sk_seed Secret seed.
 * @param[in] pk_seed Public seed.
 * @param[in] adrs FORS_TREE address.
 * @param[in] idx Absolute leaf index.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_fors_skgen(const slhdsa_params_t *p,
                                         uint8_t *sk,
                                         const uint8_t *sk_seed,
                                         const uint8_t *pk_seed,
                                         const uint8_t *adrs,
                                         uint32_t idx)
{
    uint8_t sk_adrs[SLHDSA_ADRS_LEN];

    noxtls_copy_u8(sk_adrs, sizeof(sk_adrs), adrs, (size_t)SLHDSA_ADRS_LEN);
    slhdsa_adrs_set_type(sk_adrs, SLHDSA_ADRS_TYPE_FORS_PRF);
    slhdsa_adrs_set_keypair(sk_adrs, slhdsa_adrs_get_keypair(adrs));
    slhdsa_adrs_set_tree_index(sk_adrs, idx);
    return slhdsa_shake_prf(p, pk_seed, sk_seed, sk_adrs, sk);
}

/**
 * @brief Compute a FORS subtree root fors_node(start >> height, height) (FIPS 205 Alg. 15).
 * @param[in] p Parameter metadata.
 * @param[out] root Output root.
 * @param[in] sk_seed Secret seed.
 * @param[in] pk_seed Public seed.
 * @param[in] adrs FORS_TREE address.
 * @param[in] start Absolute index of the first leaf.
 * @param[in] height Subtree height (at most a).
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_fors_treehash(const slhdsa_params_t *p,
                                            uint8_t *root,
                                            const uint8_t *sk_seed,
                                            const uint8_t *pk_seed,
                                            const uint8_t *adrs,
                                            uint32_t start,
                                            uint32_t height)
{
    uint8_t stack[(SLHDSA_MAX_A + 1U) * SLHDSA_MAX_N];
    uint8_t stack_heights[SLHDSA_MAX_A + 1U];
    uint8_t pair[2U * SLHDSA_MAX_N];
    uint8_t node_adrs[SLHDSA_ADRS_LEN];
    uint32_t stack_len = 0U;
    uint32_t leaf_count = (uint32_t)(1U << height);
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(height > SLHDSA_MAX_A) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    noxtls_copy_u8(node_adrs, sizeof(node_adrs), adrs, (size_t)SLHDSA_ADRS_LEN);
    for(i = 0U; i < leaf_count; i += 1U) {
        uint32_t node_height = 0U;
        uint32_t node_index = start + i;

        rc = slhdsa_fors_skgen(p, &pair[p->n], sk_seed, pk_seed, adrs, node_index);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        slhdsa_adrs_set_tree_height(node_adrs, 0U);
        slhdsa_adrs_set_tree_index(node_adrs, node_index);
        rc = slhdsa_shake_thash(p, pk_seed, node_adrs, &pair[p->n], p->n, &pair[p->n]);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        while((stack_len > 0U) && ((uint32_t)stack_heights[stack_len - 1U] == node_height)) {
            stack_len -= 1U;
            noxtls_copy_u8(pair, (size_t)p->n, &stack[(stack_len * p->n)], (size_t)p->n);
            slhdsa_adrs_set_tree_height(node_adrs, node_height + 1U);
            slhdsa_adrs_set_tree_index(node_adrs, node_index >> 1U);
            rc = slhdsa_shake_thash(p, pk_seed, node_adrs, pair, 2U * p->n, &pair[p->n]);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            node_height += 1U;
            node_index >>= 1U;
        }
        noxtls_copy_u8(&stack[(stack_len * p->n)], (size_t)p->n, &pair[p->n], (size_t)p->n);
        stack_heights[stack_len] = (uint8_t)node_height;
        stack_len += 1U;
    }
    if(stack_len != 1U) {
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_copy_u8(root, (size_t)SLHDSA_MAX_N, stack, (size_t)p->n);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief FORS tree i: write SK element and AUTH path (sign) and return the tree root.
 * @param[in] p Parameter metadata.
 * @param[in] job Producer description (sig_out, indices, seeds, address).
 * @param[in] i Tree index.
 * @param[out] root Output n-byte root of tree i.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_fors_sign_tree(const slhdsa_params_t *p,
                                             const slhdsa_t_job_t *job,
                                             uint32_t i,
                                             uint8_t *root)
{
    uint8_t *sig = &job->sig_out[(i * (p->a + 1U) * p->n)];
    uint32_t base = i << p->a;
    uint32_t idx = job->indices[i];
    uint32_t j = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    rc = slhdsa_fors_skgen(p, sig, job->sk_seed, job->pk_seed, job->adrs, base + idx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    for(j = 0U; j < p->a; j += 1U) {
        uint32_t start = base + (((idx >> j) ^ 1U) << j);

        rc = slhdsa_fors_treehash(p, &sig[((j + 1U) * p->n)], job->sk_seed, job->pk_seed, job->adrs, start, j);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    return slhdsa_fors_treehash(p, root, job->sk_seed, job->pk_seed, job->adrs, base, p->a);
}

/**
 * @brief FORS tree i: recompute the tree root from the signature (FIPS 205 Alg. 17 inner loop).
 * @param[in] p Parameter metadata.
 * @param[in] job Producer description (sig_in, indices, PK.seed, address).
 * @param[in] i Tree index.
 * @param[out] root Output n-byte root of tree i.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_fors_root_from_sig(const slhdsa_params_t *p,
                                                 const slhdsa_t_job_t *job,
                                                 uint32_t i,
                                                 uint8_t *root)
{
    const uint8_t *sig = &job->sig_in[(i * (p->a + 1U) * p->n)];
    uint8_t pair[2U * SLHDSA_MAX_N];
    uint8_t node_adrs[SLHDSA_ADRS_LEN];
    uint32_t idx = job->indices[i];
    uint32_t tree_index = (i << p->a) + idx;
    uint32_t pos = ((idx & 1U) == 0U) ? 0U : p->n;
    uint32_t j = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    noxtls_copy_u8(node_adrs, sizeof(node_adrs), job->adrs, (size_t)SLHDSA_ADRS_LEN);
    slhdsa_adrs_set_tree_height(node_adrs, 0U);
    slhdsa_adrs_set_tree_index(node_adrs, tree_index);
    rc = slhdsa_shake_thash(p, job->pk_seed, node_adrs, sig, p->n, &pair[pos]);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    for(j = 0U; j < p->a; j += 1U) {
        noxtls_copy_u8(&pair[p->n - pos], (size_t)p->n, &sig[((j + 1U) * p->n)], (size_t)p->n);
        tree_index >>= 1U;
        slhdsa_adrs_set_tree_height(node_adrs, j + 1U);
        slhdsa_adrs_set_tree_index(node_adrs, tree_index);
        pos = ((tree_index & 1U) == 0U) ? 0U : p->n;
        rc = slhdsa_shake_thash(p, job->pk_seed, node_adrs, pair, 2U * p->n, &pair[pos]);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    noxtls_copy_u8(root, (size_t)SLHDSA_MAX_N, &pair[pos], (size_t)p->n);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Produce the i-th n-byte input block of a streaming T_l hash.
 * @param[in] p Parameter metadata.
 * @param[in] job Producer description.
 * @param[in] i Block index.
 * @param[out] block Output n-byte block.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_t_block(const slhdsa_params_t *p,
                                      const slhdsa_t_job_t *job,
                                      uint32_t i,
                                      uint8_t *block)
{
    uint8_t chain_adrs[SLHDSA_ADRS_LEN];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(job->kind == SLHDSA_T_FORS_SIGN) {
        return slhdsa_fors_sign_tree(p, job, i, block);
    }
    if(job->kind == SLHDSA_T_FORS_VERIFY) {
        return slhdsa_fors_root_from_sig(p, job, i, block);
    }
    noxtls_copy_u8(chain_adrs, sizeof(chain_adrs), job->adrs, (size_t)SLHDSA_ADRS_LEN);
    if(job->kind == SLHDSA_T_WOTS_PKGEN) {
        slhdsa_adrs_set_type(chain_adrs, SLHDSA_ADRS_TYPE_WOTS_PRF);
        slhdsa_adrs_set_keypair(chain_adrs, slhdsa_adrs_get_keypair(job->adrs));
        slhdsa_adrs_set_chain(chain_adrs, i);
        rc = slhdsa_shake_prf(p, job->pk_seed, job->sk_seed, chain_adrs, block);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        slhdsa_adrs_set_type(chain_adrs, SLHDSA_ADRS_TYPE_WOTS_HASH);
        slhdsa_adrs_set_keypair(chain_adrs, slhdsa_adrs_get_keypair(job->adrs));
        slhdsa_adrs_set_chain(chain_adrs, i);
        return slhdsa_chain(p, block, block, 0U, SLHDSA_WOTS_W - 1U, job->pk_seed, chain_adrs);
    }
    /* SLHDSA_T_WOTS_FROMSIG */
    slhdsa_adrs_set_type(chain_adrs, SLHDSA_ADRS_TYPE_WOTS_HASH);
    slhdsa_adrs_set_keypair(chain_adrs, slhdsa_adrs_get_keypair(job->adrs));
    slhdsa_adrs_set_chain(chain_adrs, i);
    return slhdsa_chain(p, block, &job->sig_in[(i * p->n)], job->lengths[i],
                        (SLHDSA_WOTS_W - 1U) - job->lengths[i], job->pk_seed, chain_adrs);
}

/**
 * @brief Build the T_l address (WOTS_PK or FORS_ROOTS) from a producer's base address.
 * @param[in] job Producer description.
 * @param[in] type Address type of the T_l call.
 * @param[out] t_adrs Output address.
 * @return void.
 */
static void slhdsa_t_adrs(const slhdsa_t_job_t *job, uint32_t type, uint8_t t_adrs[SLHDSA_ADRS_LEN])
{
    noxtls_copy_u8(t_adrs, (size_t)SLHDSA_ADRS_LEN, job->adrs, (size_t)SLHDSA_ADRS_LEN);
    slhdsa_adrs_set_type(t_adrs, type);
    slhdsa_adrs_set_keypair(t_adrs, slhdsa_adrs_get_keypair(job->adrs));
}

/**
 * @brief Streaming T_l with SHA-256 (category 1 SHA-2 sets).
 * @param[in] p Parameter metadata.
 * @param[in] job Producer description.
 * @param[in] type Address type of the T_l call.
 * @param[in] count Number of n-byte blocks.
 * @param[out] out Output n-byte hash.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_t_stream_sha256(const slhdsa_params_t *p,
                                              const slhdsa_t_job_t *job,
                                              uint32_t type,
                                              uint32_t count,
                                              uint8_t *out)
{
    noxtls_sha_ctx_t ctx;
    uint8_t t_adrs[SLHDSA_ADRS_LEN];
    uint8_t adrsc[SLHDSA_SHA2_ADRS_LEN];
    uint8_t block[SLHDSA_SHA256_LEN];
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    slhdsa_t_adrs(job, type, t_adrs);
    slhdsa_compress_adrs(t_adrs, adrsc);
    rc = noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha256_update(&ctx, job->pk_seed, p->n);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha256_update(&ctx, g_slhdsa_zero_pad, SLHDSA_SHA256_BLOCK_LEN - p->n);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha256_update(&ctx, adrsc, SLHDSA_SHA2_ADRS_LEN);
    }
    for(i = 0U; (i < count) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        rc = slhdsa_t_block(p, job, i, block);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_sha256_update(&ctx, block, p->n);
        }
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha256_finish(&ctx, block);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_copy_u8(out, (size_t)SLHDSA_MAX_N, block, (size_t)p->n);
    }
    noxtls_secure_zero((block), sizeof(block));
    return rc;
}

/**
 * @brief Streaming T_l with SHA-512 (category 3/5 SHA-2 sets).
 * @param[in] p Parameter metadata.
 * @param[in] job Producer description.
 * @param[in] type Address type of the T_l call.
 * @param[in] count Number of n-byte blocks.
 * @param[out] out Output n-byte hash.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_t_stream_sha512(const slhdsa_params_t *p,
                                              const slhdsa_t_job_t *job,
                                              uint32_t type,
                                              uint32_t count,
                                              uint8_t *out)
{
    noxtls_sha512_ctx_t ctx;
    uint8_t t_adrs[SLHDSA_ADRS_LEN];
    uint8_t adrsc[SLHDSA_SHA2_ADRS_LEN];
    uint8_t block[SLHDSA_SHA512_LEN];
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    slhdsa_t_adrs(job, type, t_adrs);
    slhdsa_compress_adrs(t_adrs, adrsc);
    rc = noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha512_update(&ctx, job->pk_seed, p->n);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha512_update(&ctx, g_slhdsa_zero_pad, SLHDSA_SHA512_BLOCK_LEN - p->n);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha512_update(&ctx, adrsc, SLHDSA_SHA2_ADRS_LEN);
    }
    for(i = 0U; (i < count) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        rc = slhdsa_t_block(p, job, i, block);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_sha512_update(&ctx, block, p->n);
        }
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha512_finish(&ctx, block);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_copy_u8(out, (size_t)SLHDSA_MAX_N, block, (size_t)p->n);
    }
    noxtls_secure_zero((block), sizeof(block));
    return rc;
}

/**
 * @brief Streaming T_l with SHAKE256.
 * @param[in] p Parameter metadata.
 * @param[in] job Producer description.
 * @param[in] type Address type of the T_l call.
 * @param[in] count Number of n-byte blocks.
 * @param[out] out Output n-byte hash.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_t_stream_shake(const slhdsa_params_t *p,
                                             const slhdsa_t_job_t *job,
                                             uint32_t type,
                                             uint32_t count,
                                             uint8_t *out)
{
    noxtls_sha3_ctx_t ctx;
    uint8_t t_adrs[SLHDSA_ADRS_LEN];
    uint8_t block[SLHDSA_MAX_N];
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    slhdsa_t_adrs(job, type, t_adrs);
    rc = noxtls_shake256_init(&ctx);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_update(&ctx, job->pk_seed, p->n);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_update(&ctx, t_adrs, SLHDSA_ADRS_LEN);
    }
    for(i = 0U; (i < count) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        rc = slhdsa_t_block(p, job, i, block);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_shake256_update(&ctx, block, p->n);
        }
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_final(&ctx);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_squeeze(&ctx, out, p->n);
    }
    noxtls_secure_zero((block), sizeof(block));
    return rc;
}

/**
 * @brief Streaming tweakable hash T_l over `count` produced n-byte blocks.
 * @param[in] p Parameter metadata.
 * @param[in] job Producer description.
 * @param[in] type Address type of the T_l call (WOTS_PK or FORS_ROOTS).
 * @param[in] count Number of n-byte blocks.
 * @param[out] out Output n-byte hash.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_t_stream(const slhdsa_params_t *p,
                                       const slhdsa_t_job_t *job,
                                       uint32_t type,
                                       uint32_t count,
                                       uint8_t *out)
{
    if(p->sizes.hash_family_sha2 == 0U) {
        return slhdsa_t_stream_shake(p, job, type, count, out);
    }
    if(slhdsa_sha2_uses_512(p, count * p->n) != 0U) {
        return slhdsa_t_stream_sha512(p, job, type, count, out);
    }
    return slhdsa_t_stream_sha256(p, job, type, count, out);
}

/**
 * @brief Generate a FORS signature and public key (FIPS 205 Alg. 16 + 17).
 * @param[in] p Parameter metadata.
 * @param[out] sig Output FORS signature.
 * @param[out] pk Output FORS public key.
 * @param[in] msg FORS message bytes.
 * @param[in] sk_seed Secret seed.
 * @param[in] pk_seed Public seed.
 * @param[in] adrs FORS_TREE address.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_fors_sign(const slhdsa_params_t *p,
                                        uint8_t *sig,
                                        uint8_t *pk,
                                        const uint8_t *msg,
                                        const uint8_t *sk_seed,
                                        const uint8_t *pk_seed,
                                        const uint8_t *adrs)
{
    uint32_t indices[SLHDSA_MAX_K];
    slhdsa_t_job_t job;

    slhdsa_fors_indices(p, indices, msg);
    noxtls_secure_zero((&job), sizeof(job));
    job.kind = SLHDSA_T_FORS_SIGN;
    job.sk_seed = sk_seed;
    job.pk_seed = pk_seed;
    job.adrs = adrs;
    job.sig_out = sig;
    job.indices = indices;
    return slhdsa_t_stream(p, &job, SLHDSA_ADRS_TYPE_FORS_ROOTS, p->k, pk);
}

/**
 * @brief Compute a FORS public key from a signature (FIPS 205 Alg. 17).
 * @param[in] p Parameter metadata.
 * @param[out] pk Output FORS public key.
 * @param[in] sig FORS signature.
 * @param[in] msg FORS message bytes.
 * @param[in] pk_seed Public seed.
 * @param[in] adrs FORS_TREE address.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_fors_pk_from_sig(const slhdsa_params_t *p,
                                               uint8_t *pk,
                                               const uint8_t *sig,
                                               const uint8_t *msg,
                                               const uint8_t *pk_seed,
                                               const uint8_t *adrs)
{
    uint32_t indices[SLHDSA_MAX_K];
    slhdsa_t_job_t job;

    slhdsa_fors_indices(p, indices, msg);
    noxtls_secure_zero((&job), sizeof(job));
    job.kind = SLHDSA_T_FORS_VERIFY;
    job.pk_seed = pk_seed;
    job.adrs = adrs;
    job.sig_in = sig;
    job.indices = indices;
    return slhdsa_t_stream(p, &job, SLHDSA_ADRS_TYPE_FORS_ROOTS, p->k, pk);
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
                                       uint8_t *root,
                                       const uint8_t *sk_seed,
                                       const uint8_t *pk_seed)
{
    uint8_t adrs[SLHDSA_ADRS_LEN];

    noxtls_secure_zero((adrs), sizeof(adrs));
    slhdsa_adrs_set_layer(adrs, p->d - 1U);
    slhdsa_adrs_set_tree(adrs, 0U);
    return slhdsa_xmss_treehash(p, root, sk_seed, pk_seed, adrs, 0U, p->hp);
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
    uint32_t xmss_sig_len = (uint32_t)((p->wots_len + p->hp) * p->n);
    uint32_t layer = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    noxtls_copy_u8(current_msg, sizeof(current_msg), msg, (size_t)p->n);
    for(layer = 0U; layer < p->d; layer += 1U) {
        noxtls_secure_zero((adrs), sizeof(adrs));
        slhdsa_adrs_set_layer(adrs, layer);
        slhdsa_adrs_set_tree(adrs, idx_tree);
        rc = slhdsa_xmss_sign(p, sig, current_msg, sk_seed, pk_seed, idx_leaf, adrs);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if((layer + 1U) == p->d) {
            break;
        }
        rc = slhdsa_xmss_pk_from_sig(p, root, sig, current_msg, pk_seed, idx_leaf, adrs);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        noxtls_copy_u8(current_msg, sizeof(current_msg), root, (size_t)p->n);
        sig = &sig[xmss_sig_len];
        idx_leaf = (uint32_t)(idx_tree & ((1U << p->hp) - 1U));
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
                                        uint8_t *root,
                                        const uint8_t *sig,
                                        const uint8_t *msg,
                                        const uint8_t *pk_seed,
                                        uint64_t idx_tree,
                                        uint32_t idx_leaf)
{
    uint8_t adrs[SLHDSA_ADRS_LEN];
    uint8_t current_msg[SLHDSA_MAX_N];
    uint32_t xmss_sig_len = (uint32_t)((p->wots_len + p->hp) * p->n);
    uint32_t layer = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    noxtls_copy_u8(current_msg, sizeof(current_msg), msg, (size_t)p->n);
    for(layer = 0U; layer < p->d; layer += 1U) {
        noxtls_secure_zero((adrs), sizeof(adrs));
        slhdsa_adrs_set_layer(adrs, layer);
        slhdsa_adrs_set_tree(adrs, idx_tree);
        rc = slhdsa_xmss_pk_from_sig(p, root, sig, current_msg, pk_seed, idx_leaf, adrs);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        noxtls_copy_u8(current_msg, sizeof(current_msg), root, (size_t)p->n);
        sig = &sig[xmss_sig_len];
        idx_leaf = (uint32_t)(idx_tree & ((1U << p->hp) - 1U));
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
    uint32_t fors_msg_bytes = (uint32_t)(((p->k * p->a) + 7U) / 8U);
    uint32_t tree_bits = (uint32_t)(p->h - p->hp);
    uint32_t tree_bytes = (uint32_t)((tree_bits + 7U) / 8U);
    uint32_t leaf_bytes = (uint32_t)((p->hp + 7U) / 8U);
    uint64_t tree_mask = 0U;
    uint32_t leaf_mask = 0U;

    *idx_tree = slhdsa_load_be(&digest[fors_msg_bytes], tree_bytes);
    if(tree_bits < 64U) {
        tree_mask = (1ULL << tree_bits) - 1ULL;
        *idx_tree &= tree_mask;
    }
    *idx_leaf = (uint32_t)slhdsa_load_be(&digest[fors_msg_bytes + tree_bytes], leaf_bytes);
    leaf_mask = (1U << p->hp) - 1U;
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
    return (slhdsa_get_sizes(param, &sizes) == NOXTLS_RETURN_SUCCESS) ? sizes.public_key_len : 0U;
}

/**
 * @brief Get the SLH-DSA private-key length for a parameter set.
 * @param[in] param FIPS 205 SLH-DSA parameter set.
 * @return Private-key length in bytes, or 0 for invalid parameter sets.
 */
uint32_t noxtls_slhdsa_secret_key_len(noxtls_slhdsa_param_t param)
{
    slhdsa_sizes_t sizes;
    return (slhdsa_get_sizes(param, &sizes) == NOXTLS_RETURN_SUCCESS) ? sizes.secret_key_len : 0U;
}

/**
 * @brief Get the SLH-DSA signature length for a parameter set.
 * @param[in] param FIPS 205 SLH-DSA parameter set.
 * @return Signature length in bytes, or 0 for invalid parameter sets.
 */
uint32_t noxtls_slhdsa_signature_len(noxtls_slhdsa_param_t param)
{
    slhdsa_sizes_t sizes;
    return (slhdsa_get_sizes(param, &sizes) == NOXTLS_RETURN_SUCCESS) ? sizes.signature_len : 0U;
}

/**
 * @brief Get the NIST security category for a parameter set.
 * @param[in] param FIPS 205 SLH-DSA parameter set.
 * @return Security category (1, 3, or 5), or 0 for invalid parameter sets.
 */
uint32_t noxtls_slhdsa_security_category(noxtls_slhdsa_param_t param)
{
    slhdsa_sizes_t sizes;
    return (slhdsa_get_sizes(param, &sizes) == NOXTLS_RETURN_SUCCESS) ? sizes.security_category : 0U;
}

/**
 * @brief Test whether a parameter set uses the SHA-2 hash family.
 * @param[in] param FIPS 205 SLH-DSA parameter set.
 * @return 1 for SHA-2 parameter sets, 0 otherwise.
 */
uint8_t noxtls_slhdsa_is_sha2(noxtls_slhdsa_param_t param)
{
    slhdsa_sizes_t sizes;
    return (slhdsa_get_sizes(param, &sizes) == NOXTLS_RETURN_SUCCESS) ? sizes.hash_family_sha2 : 0U;
}

/**
 * @brief Test whether a parameter set is an "s" (small-signature) variant.
 * @param[in] param FIPS 205 SLH-DSA parameter set.
 * @return 1 for small variants, 0 otherwise.
 */
uint8_t noxtls_slhdsa_is_small(noxtls_slhdsa_param_t param)
{
    slhdsa_sizes_t sizes;
    return (slhdsa_get_sizes(param, &sizes) == NOXTLS_RETURN_SUCCESS) ? sizes.small_variant : 0U;
}

/**
 * @brief Describe M' for the internal (external == 0) or pure external interface.
 * @param[out] m Message descriptor.
 * @param[in] external Non-zero for pure slh_sign/slh_verify (M' = 0x00 || len(ctx) || ctx || M).
 * @param[in] ctx Context string (may be NULL when ctx_len is 0).
 * @param[in] ctx_len Context length in bytes (at most 255).
 * @param[in] msg Message (may be NULL when msg_len is 0).
 * @param[in] msg_len Message length.
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL or NOXTLS_RETURN_INVALID_PARAM.
 */
static noxtls_return_t slhdsa_msg_init(slhdsa_msg_t *m,
                                       uint8_t external,
                                       const uint8_t *ctx,
                                       uint32_t ctx_len,
                                       const uint8_t *msg,
                                       uint32_t msg_len)
{
    if((ctx == NULL) && (ctx_len != 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx_len > NOXTLS_SLHDSA_MAX_CONTEXT_LEN) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    m->hdr[0] = 0x00U;
    m->hdr[1] = (uint8_t)ctx_len;
    m->hdr_len = (external != 0U) ? 2U : 0U;
    m->ctx = ctx;
    m->ctx_len = (external != 0U) ? ctx_len : 0U;
    m->msg = msg;
    m->msg_len = msg_len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief FIPS 205 Alg. 18 slh_keygen_internal.
 * @param[in] p Parameter metadata.
 * @param[in] sk_seed SK.seed (n bytes).
 * @param[in] sk_prf SK.prf (n bytes).
 * @param[in] pk_seed PK.seed (n bytes).
 * @param[out] public_key PK.seed || PK.root.
 * @param[out] secret_key SK.seed || SK.prf || PK.seed || PK.root.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_keygen_core(const slhdsa_params_t *p,
                                          const uint8_t *sk_seed,
                                          const uint8_t *sk_prf,
                                          const uint8_t *pk_seed,
                                          uint8_t *public_key,
                                          uint8_t *secret_key)
{
    uint8_t pk_root[SLHDSA_MAX_N];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    rc = slhdsa_ht_pkgen(p, pk_root, sk_seed, pk_seed);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    /* Write the secret key first so overlapping caller buffers cannot lose seeds. */
    noxtls_move_u8(secret_key, (size_t)p->sizes.secret_key_len, sk_seed, (size_t)p->n);
    noxtls_move_u8(&secret_key[p->n], (size_t)(p->sizes.secret_key_len - p->n), sk_prf, (size_t)p->n);
    noxtls_move_u8(&secret_key[(2U * p->n)], (size_t)(p->sizes.secret_key_len - (2U * p->n)), pk_seed, (size_t)p->n);
    noxtls_copy_u8(&secret_key[(3U * p->n)], (size_t)(p->sizes.secret_key_len - (3U * p->n)), pk_root, (size_t)p->n);
    noxtls_copy_u8(public_key, (size_t)p->sizes.public_key_len, &secret_key[(2U * p->n)], (size_t)(2U * p->n));
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief FIPS 205 Alg. 19 slh_sign_internal over M'.
 * @param[in] p Parameter metadata.
 * @param[in] secret_key Serialized secret key.
 * @param[in] m Message M' fragments.
 * @param[in] addrnd Additional randomness (n bytes) or NULL for the deterministic variant.
 * @param[out] signature Output buffer of p->sizes.signature_len bytes.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
static noxtls_return_t slhdsa_sign_core(const slhdsa_params_t *p,
                                        const uint8_t *secret_key,
                                        const slhdsa_msg_t *m,
                                        const uint8_t *addrnd,
                                        uint8_t *signature)
{
    uint8_t digest[SLHDSA_MAX_MD_LEN];
    uint8_t fors_pk[SLHDSA_MAX_N];
    uint8_t adrs[SLHDSA_ADRS_LEN];
    const uint8_t *sk_seed = secret_key;
    const uint8_t *sk_prf = &secret_key[p->n];
    const uint8_t *pk_seed = &secret_key[(2U * p->n)];
    const uint8_t *pk_root = &secret_key[(3U * p->n)];
    const uint8_t *opt_rand = (addrnd != NULL) ? addrnd : pk_seed;
    uint8_t *sig_fors = &signature[p->n];
    uint8_t *sig_ht = &signature[p->n + (p->k * (p->a + 1U) * p->n)];
    uint64_t idx_tree = 0U;
    uint32_t idx_leaf = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    /* R = PRF_msg(SK.prf, opt_rand, M) is written straight into the signature. */
    rc = slhdsa_prf_msg(p, sk_prf, opt_rand, m, signature);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = slhdsa_h_msg(p, signature, pk_seed, pk_root, m, digest);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    (void)slhdsa_digest_indices(p, digest, &idx_tree, &idx_leaf);

    noxtls_secure_zero((adrs), sizeof(adrs));
    slhdsa_adrs_set_tree(adrs, idx_tree);
    slhdsa_adrs_set_type(adrs, SLHDSA_ADRS_TYPE_FORS_TREE);
    slhdsa_adrs_set_keypair(adrs, idx_leaf);
    rc = slhdsa_fors_sign(p, sig_fors, fors_pk, digest, sk_seed, pk_seed, adrs);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return slhdsa_ht_sign(p, sig_ht, fors_pk, sk_seed, pk_seed, idx_tree, idx_leaf);
}

/**
 * @brief FIPS 205 Alg. 20 slh_verify_internal over M'.
 * @param[in] p Parameter metadata.
 * @param[in] public_key Serialized public key.
 * @param[in] m Message M' fragments.
 * @param[in] signature Signature bytes.
 * @param[in] signature_len Signature length.
 * @return NOXTLS_RETURN_SUCCESS if valid, NOXTLS_RETURN_FAILED if invalid.
 */
static noxtls_return_t slhdsa_verify_core(const slhdsa_params_t *p,
                                          const uint8_t *public_key,
                                          const slhdsa_msg_t *m,
                                          const uint8_t *signature,
                                          uint32_t signature_len)
{
    uint8_t digest[SLHDSA_MAX_MD_LEN];
    uint8_t node[SLHDSA_MAX_N];
    uint8_t adrs[SLHDSA_ADRS_LEN];
    const uint8_t *pk_seed = public_key;
    const uint8_t *pk_root = &public_key[p->n];
    const uint8_t *sig_fors = &signature[p->n];
    const uint8_t *sig_ht = &signature[p->n + (p->k * (p->a + 1U) * p->n)];
    uint64_t idx_tree = 0U;
    uint32_t idx_leaf = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(signature_len != p->sizes.signature_len) {
        return NOXTLS_RETURN_FAILED;
    }
    rc = slhdsa_h_msg(p, signature, pk_seed, pk_root, m, digest);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    (void)slhdsa_digest_indices(p, digest, &idx_tree, &idx_leaf);

    noxtls_secure_zero((adrs), sizeof(adrs));
    slhdsa_adrs_set_tree(adrs, idx_tree);
    slhdsa_adrs_set_type(adrs, SLHDSA_ADRS_TYPE_FORS_TREE);
    slhdsa_adrs_set_keypair(adrs, idx_leaf);
    rc = slhdsa_fors_pk_from_sig(p, node, sig_fors, digest, pk_seed, adrs);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = slhdsa_ht_verify(p, node, sig_ht, node, pk_seed, idx_tree, idx_leaf);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return (noxtls_ct_memcmp(node, pk_root, (size_t)(p->n)) == 0) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
}

/**
 * @brief Validate common sign arguments and resolve parameters.
 * @param[in] param Parameter set.
 * @param[in] secret_key Secret key.
 * @param[in] msg Message (may be NULL when msg_len is 0).
 * @param[in] msg_len Message length.
 * @param[in] signature Output buffer.
 * @param[in,out] signature_len Capacity on input.
 * @param[out] p Resolved parameters.
 * @return NOXTLS_RETURN_SUCCESS when the arguments are usable.
 */
static noxtls_return_t slhdsa_sign_args(noxtls_slhdsa_param_t param,
                                        const uint8_t *secret_key,
                                        const uint8_t *msg,
                                        uint32_t msg_len,
                                        const uint8_t *signature,
                                        const uint32_t *signature_len,
                                        slhdsa_params_t *p)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((secret_key == NULL) || (signature == NULL) || (signature_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if((msg == NULL) && (msg_len != 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    rc = slhdsa_get_params(param, p);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(*signature_len < p->sizes.signature_len) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Validate common verify arguments and resolve parameters.
 * @param[in] param Parameter set.
 * @param[in] public_key Public key.
 * @param[in] msg Message (may be NULL when msg_len is 0).
 * @param[in] msg_len Message length.
 * @param[in] signature Signature.
 * @param[out] p Resolved parameters.
 * @return NOXTLS_RETURN_SUCCESS when the arguments are usable.
 */
static noxtls_return_t slhdsa_verify_args(noxtls_slhdsa_param_t param,
                                          const uint8_t *public_key,
                                          const uint8_t *msg,
                                          uint32_t msg_len,
                                          const uint8_t *signature,
                                          slhdsa_params_t *p)
{
    if((public_key == NULL) || (signature == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if((msg == NULL) && (msg_len != 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    return slhdsa_get_params(param, p);
}

/**
 * @brief Generate an SLH-DSA key pair from fresh DRBG randomness.
 * @param[in] param FIPS 205 SLH-DSA parameter set.
 * @param[out] public_key Public-key output buffer (noxtls_slhdsa_public_key_len bytes).
 * @param[out] secret_key Secret-key output buffer (noxtls_slhdsa_secret_key_len bytes).
 * @return NOXTLS_RETURN_SUCCESS on success, or an argument/entropy error.
 */
noxtls_return_t noxtls_slhdsa_keygen(noxtls_slhdsa_param_t param, uint8_t *public_key, uint8_t *secret_key)
{
    slhdsa_params_t p;
    uint8_t seeds[3U * SLHDSA_MAX_N];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((public_key == NULL) || (secret_key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    rc = slhdsa_get_params(param, &p);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = slhdsa_random(seeds, 3U * p.n);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = slhdsa_keygen_core(&p, seeds, &seeds[p.n], &seeds[(2U * p.n)], public_key, secret_key);
    }
    noxtls_secure_zero((seeds), sizeof(seeds));
    return rc;
}

/**
 * @brief Deterministic FIPS 205 slh_keygen_internal(SK.seed, SK.prf, PK.seed).
 * @param[in] param FIPS 205 SLH-DSA parameter set.
 * @param[in] sk_seed SK.seed (n bytes).
 * @param[in] sk_prf SK.prf (n bytes).
 * @param[in] pk_seed PK.seed (n bytes).
 * @param[out] public_key Public-key output buffer.
 * @param[out] secret_key Secret-key output buffer.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
noxtls_return_t noxtls_slhdsa_keygen_from_seed(noxtls_slhdsa_param_t param,
                                               const uint8_t *sk_seed,
                                               const uint8_t *sk_prf,
                                               const uint8_t *pk_seed,
                                               uint8_t *public_key,
                                               uint8_t *secret_key)
{
    slhdsa_params_t p;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((sk_seed == NULL) || (sk_prf == NULL) || (pk_seed == NULL) ||
       (public_key == NULL) || (secret_key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    rc = slhdsa_get_params(param, &p);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return slhdsa_keygen_core(&p, sk_seed, sk_prf, pk_seed, public_key, secret_key);
}

/**
 * @brief Hedged FIPS 205 slh_sign with a context string (pure, external interface).
 * @param[in] param FIPS 205 SLH-DSA parameter set.
 * @param[in] secret_key Secret-key buffer.
 * @param[in] noxtls_message Message to sign.
 * @param[in] message_len Message length in bytes.
 * @param[in] ctx Context string (may be NULL when ctx_len is 0).
 * @param[in] ctx_len Context length (at most 255).
 * @param[out] signature Signature output buffer.
 * @param[in,out] signature_len Buffer capacity on input, signature length on output.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
noxtls_return_t noxtls_slhdsa_sign_ctx(noxtls_slhdsa_param_t param,
                                       const uint8_t *secret_key,
                                       const uint8_t *noxtls_message,
                                       uint32_t message_len,
                                       const uint8_t *ctx,
                                       uint32_t ctx_len,
                                       uint8_t *signature,
                                       uint32_t *signature_len)
{
    slhdsa_params_t p;
    slhdsa_msg_t m;
    uint8_t addrnd[SLHDSA_MAX_N];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    rc = slhdsa_sign_args(param, secret_key, noxtls_message, message_len, signature, signature_len, &p);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = slhdsa_msg_init(&m, 1U, ctx, ctx_len, noxtls_message, message_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = slhdsa_random(addrnd, p.n);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = slhdsa_sign_core(&p, secret_key, &m, addrnd, signature);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        *signature_len = p.sizes.signature_len;
    }
    return rc;
}

/**
 * @brief Sign with SLH-DSA (FIPS 205 pure slh_sign, empty context, hedged).
 * @param[in] param FIPS 205 SLH-DSA parameter set.
 * @param[in] secret_key Secret-key buffer.
 * @param[in] noxtls_message Message to sign.
 * @param[in] message_len Message length in bytes.
 * @param[out] signature Signature output buffer.
 * @param[in,out] signature_len Buffer capacity on input, signature length on output.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
noxtls_return_t noxtls_slhdsa_sign(noxtls_slhdsa_param_t param,
                                   const uint8_t *secret_key,
                                   const uint8_t *noxtls_message,
                                   uint32_t message_len,
                                   uint8_t *signature,
                                   uint32_t *signature_len)
{
    return noxtls_slhdsa_sign_ctx(param, secret_key, noxtls_message, message_len, NULL, 0U,
                                  signature, signature_len);
}

/**
 * @brief FIPS 205 slh_sign_internal on a caller-formatted message M'.
 * @param[in] param FIPS 205 SLH-DSA parameter set.
 * @param[in] secret_key Secret-key buffer.
 * @param[in] noxtls_message Message M' (already prefixed by the caller if required).
 * @param[in] message_len Message length in bytes.
 * @param[in] addrnd n bytes of additional randomness, or NULL for the deterministic variant.
 * @param[out] signature Signature output buffer.
 * @param[in,out] signature_len Buffer capacity on input, signature length on output.
 * @return NOXTLS_RETURN_SUCCESS on success.
 */
noxtls_return_t noxtls_slhdsa_sign_internal(noxtls_slhdsa_param_t param,
                                            const uint8_t *secret_key,
                                            const uint8_t *noxtls_message,
                                            uint32_t message_len,
                                            const uint8_t *addrnd,
                                            uint8_t *signature,
                                            uint32_t *signature_len)
{
    slhdsa_params_t p;
    slhdsa_msg_t m;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    rc = slhdsa_sign_args(param, secret_key, noxtls_message, message_len, signature, signature_len, &p);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    (void)slhdsa_msg_init(&m, 0U, NULL, 0U, noxtls_message, message_len);
    rc = slhdsa_sign_core(&p, secret_key, &m, addrnd, signature);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        *signature_len = p.sizes.signature_len;
    }
    return rc;
}

/**
 * @brief Verify an SLH-DSA signature with a context string (FIPS 205 pure slh_verify).
 * @param[in] param FIPS 205 SLH-DSA parameter set.
 * @param[in] public_key Public-key buffer.
 * @param[in] noxtls_message Signed message.
 * @param[in] message_len Message length in bytes.
 * @param[in] ctx Context string (may be NULL when ctx_len is 0).
 * @param[in] ctx_len Context length (at most 255).
 * @param[in] signature Signature buffer.
 * @param[in] signature_len Signature length in bytes.
 * @return NOXTLS_RETURN_SUCCESS if valid, NOXTLS_RETURN_FAILED if invalid.
 */
noxtls_return_t noxtls_slhdsa_verify_ctx(noxtls_slhdsa_param_t param,
                                         const uint8_t *public_key,
                                         const uint8_t *noxtls_message,
                                         uint32_t message_len,
                                         const uint8_t *ctx,
                                         uint32_t ctx_len,
                                         const uint8_t *signature,
                                         uint32_t signature_len)
{
    slhdsa_params_t p;
    slhdsa_msg_t m;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    rc = slhdsa_verify_args(param, public_key, noxtls_message, message_len, signature, &p);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = slhdsa_msg_init(&m, 1U, ctx, ctx_len, noxtls_message, message_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return slhdsa_verify_core(&p, public_key, &m, signature, signature_len);
}

/**
 * @brief Verify an SLH-DSA signature (FIPS 205 pure slh_verify, empty context).
 * @param[in] param FIPS 205 SLH-DSA parameter set.
 * @param[in] public_key Public-key buffer.
 * @param[in] noxtls_message Signed message.
 * @param[in] message_len Message length in bytes.
 * @param[in] signature Signature buffer.
 * @param[in] signature_len Signature length in bytes.
 * @return NOXTLS_RETURN_SUCCESS if valid, NOXTLS_RETURN_FAILED if invalid.
 */
noxtls_return_t noxtls_slhdsa_verify(noxtls_slhdsa_param_t param,
                                     const uint8_t *public_key,
                                     const uint8_t *noxtls_message,
                                     uint32_t message_len,
                                     const uint8_t *signature,
                                     uint32_t signature_len)
{
    return noxtls_slhdsa_verify_ctx(param, public_key, noxtls_message, message_len, NULL, 0U,
                                    signature, signature_len);
}

/**
 * @brief FIPS 205 slh_verify_internal on a caller-formatted message M'.
 * @param[in] param FIPS 205 SLH-DSA parameter set.
 * @param[in] public_key Public-key buffer.
 * @param[in] noxtls_message Message M'.
 * @param[in] message_len Message length in bytes.
 * @param[in] signature Signature buffer.
 * @param[in] signature_len Signature length in bytes.
 * @return NOXTLS_RETURN_SUCCESS if valid, NOXTLS_RETURN_FAILED if invalid.
 */
noxtls_return_t noxtls_slhdsa_verify_internal(noxtls_slhdsa_param_t param,
                                              const uint8_t *public_key,
                                              const uint8_t *noxtls_message,
                                              uint32_t message_len,
                                              const uint8_t *signature,
                                              uint32_t signature_len)
{
    slhdsa_params_t p;
    slhdsa_msg_t m;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    rc = slhdsa_verify_args(param, public_key, noxtls_message, message_len, signature, &p);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    (void)slhdsa_msg_init(&m, 0U, NULL, 0U, noxtls_message, message_len);
    return slhdsa_verify_core(&p, public_key, &m, signature, signature_len);
}

#endif /* NOXTLS_FEATURE_SLH_DSA */
