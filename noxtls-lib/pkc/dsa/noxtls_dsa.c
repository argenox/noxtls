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
* File:    noxtls_dsa.c
* Summary: Digital Signature Algorithm (DSA) per FIPS 186-4
*
*
*****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "common/noxtls_memory.h"
#include "noxtls_dsa.h"
#include "pkc/rsa/noxtls_bignum.h"
#include "mdigest/md5/noxtls_md5.h"
#include "mdigest/sha1/noxtls_sha1.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha512/noxtls_sha512.h"
#include "drbg/noxtls_drbg.h"
#include "noxtls_ct.h"

/**
 * @brief Compute a noxtls_message digest for DSA signing or verification (FIPS 186-4 noxtls_message hashing).
 *
 * @internal Used by noxtls_dsa_sign() and noxtls_dsa_verify().
 *
 * @param[out] hash Buffer for the digest; must be large enough for the selected algorithm (up to 64 bytes here).
 * @param[out] hash_len Set to the digest length in bytes on success (16, 20, 28, 32, 48, or 64).
 * @param[in] noxtls_message Message to hash.
 * @param[in] message_len Length of noxtls_message in bytes.
 * @param[in] hash_algo Digest: NOXTLS_HASH_MD5, SHA1, SHA_224, SHA_256, SHA_384, or SHA_512.
 *
 * @return NOXTLS_RETURN_SUCCESS with @p hash and @p hash_len populated.
 * @return NOXTLS_RETURN_NULL if hash, hash_len, or noxtls_message is NULL.
 * @return NOXTLS_RETURN_INVALID_ALGORITHM if @p hash_algo is not supported.
 * @return NOXTLS_RETURN_NOT_SUPPORTED if @p hash_algo is compiled out of this build.
 * @return NOXTLS_RETURN_FAILED if the underlying hash init/update/finish fails.
 */
#if NOXTLS_FEATURE_MD5
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t dsa_hash_run_md5(uint8_t *hash, const uint8_t *msg, uint32_t len)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    noxtls_sha_ctx_t ctx;
    if (noxtls_md5_init(&ctx) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if (noxtls_md5_update(&ctx, msg, len) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if (noxtls_md5_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    return NOXTLS_RETURN_SUCCESS;
}
#endif /* NOXTLS_FEATURE_MD5 */

#if NOXTLS_FEATURE_SHA1
static noxtls_return_t dsa_hash_run_sha1(uint8_t *hash, const uint8_t *msg, uint32_t len, noxtls_hash_algos_t hash_algo)
{
    noxtls_sha_ctx_t ctx;
    if (noxtls_sha1_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if (noxtls_sha1_update(&ctx, msg, len) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if (noxtls_sha1_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    return NOXTLS_RETURN_SUCCESS;
}
#endif /* NOXTLS_FEATURE_SHA1 */

#if (NOXTLS_FEATURE_SHA224 || NOXTLS_FEATURE_SHA256)
static noxtls_return_t dsa_hash_run_sha256(uint8_t *hash, const uint8_t *msg, uint32_t len, noxtls_hash_algos_t hash_algo)
{
    noxtls_sha_ctx_t ctx;
    if (noxtls_sha256_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if (noxtls_sha256_update(&ctx, msg, len) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if (noxtls_sha256_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    return NOXTLS_RETURN_SUCCESS;
}
#endif /* NOXTLS_FEATURE_SHA224 || NOXTLS_FEATURE_SHA256 */

#if (NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512)
static noxtls_return_t dsa_hash_run_sha512(uint8_t *hash, const uint8_t *msg, uint32_t len, noxtls_hash_algos_t hash_algo)
{
    noxtls_sha512_ctx_t ctx512;
    if (noxtls_sha512_init(&ctx512, hash_algo) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if (noxtls_sha512_update(&ctx512, msg, len) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if (noxtls_sha512_finish(&ctx512, hash) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    return NOXTLS_RETURN_SUCCESS;
}
#endif /* NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512 */

/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t dsa_hash_message(uint8_t *hash, uint32_t *hash_len, const uint8_t *noxtls_message, uint32_t message_len, noxtls_hash_algos_t hash_algo)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if ((hash == NULL) || (hash_len == NULL) || (noxtls_message == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    /* Digests compiled out of this build are NOT_SUPPORTED. */
    switch (hash_algo) {
    case NOXTLS_HASH_MD5:
#if NOXTLS_FEATURE_MD5
        rc = dsa_hash_run_md5(hash, noxtls_message, message_len);
        if (rc != NOXTLS_RETURN_SUCCESS) { return rc; }
        *hash_len = 16U;
        break;
#else
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    case NOXTLS_HASH_SHA1:
#if NOXTLS_FEATURE_SHA1
        rc = dsa_hash_run_sha1(hash, noxtls_message, message_len, hash_algo);
        if (rc != NOXTLS_RETURN_SUCCESS) { return rc; }
        *hash_len = 20U;
        break;
#else
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    case NOXTLS_HASH_SHA_224:
#if NOXTLS_FEATURE_SHA224
        rc = dsa_hash_run_sha256(hash, noxtls_message, message_len, hash_algo);
        if (rc != NOXTLS_RETURN_SUCCESS) { return rc; }
        *hash_len = 28U;
        break;
#else
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    case NOXTLS_HASH_SHA_256:
#if NOXTLS_FEATURE_SHA256
        rc = dsa_hash_run_sha256(hash, noxtls_message, message_len, hash_algo);
        if (rc != NOXTLS_RETURN_SUCCESS) { return rc; }
        *hash_len = 32U;
        break;
#else
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    case NOXTLS_HASH_SHA_384:
#if NOXTLS_FEATURE_SHA384
        rc = dsa_hash_run_sha512(hash, noxtls_message, message_len, hash_algo);
        if (rc != NOXTLS_RETURN_SUCCESS) { return rc; }
        *hash_len = 48U;
        break;
#else
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    case NOXTLS_HASH_SHA_512:
#if NOXTLS_FEATURE_SHA512
        rc = dsa_hash_run_sha512(hash, noxtls_message, message_len, hash_algo);
        if (rc != NOXTLS_RETURN_SUCCESS) { return rc; }
        *hash_len = 64U;
        break;
#else
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    default:
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Allocate storage and load DSA domain parameters (p, q, g); prepare empty key material buffers.
 *
 * On success, @p key owns heap buffers for p, q, g, y, and x (lengths p_len and q_len as appropriate).
 * Call noxtls_dsa_key_set_public() / noxtls_dsa_key_set_private() or noxtls_dsa_key_generate() next.
 *
 * @param[in,out] key Key object to initialize; must be zeroed or unused on entry.
 * @param[in] p Prime modulus (big-endian, p_len bytes).
 * @param[in] p_len Byte length of p; must not exceed DSA_MAX_P_BYTES.
 * @param[in] q Subgroup order (big-endian, q_len bytes); must not exceed DSA_MAX_Q_BYTES.
 * @param[in] q_len Byte length of q; must be positive.
 * @param[in] g Generator (big-endian); length must equal p_len.
 * @param[in] g_len Byte length of g; must equal p_len.
 *
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if any pointer argument is NULL.
 * @return NOXTLS_RETURN_FAILED if lengths are invalid or allocation fails.
 */
noxtls_return_t noxtls_dsa_key_init(dsa_key_t *key, const uint8_t *p, uint32_t p_len, const uint8_t *q, uint32_t q_len, const uint8_t *g, uint32_t g_len)
{
    if ((key == NULL) || (p == NULL) || (q == NULL) || (g == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if ((p_len == 0U) || (q_len == 0U) || (q_len > DSA_MAX_Q_BYTES) || (p_len > DSA_MAX_P_BYTES) || (g_len != p_len)) {
        return NOXTLS_RETURN_FAILED;
    }

    key->p_len = p_len;
    key->q_len = q_len;
    key->p = (uint8_t *)NOXTLS_CALLOC(p_len, 1U);
    key->q = (uint8_t *)NOXTLS_CALLOC(q_len, 1U);
    key->g = (uint8_t *)NOXTLS_CALLOC(p_len, 1U);
    key->y = (uint8_t *)NOXTLS_CALLOC(p_len, 1U);
    key->x = (uint8_t *)NOXTLS_CALLOC(q_len, 1U);
    if ((key->p == NULL) || (key->q == NULL) || (key->g == NULL) || (key->y == NULL) || (key->x == NULL)) {
        (void)noxtls_dsa_key_free(key);
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    noxtls_copy_u8(key->p, (size_t)p_len, p, (size_t)p_len);
    noxtls_copy_u8(key->q, (size_t)q_len, q, (size_t)q_len);
    noxtls_copy_u8(key->g, (size_t)p_len, g, (size_t)p_len);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Set the DSA public key y (big-endian, p_len bytes).
 *
 * @param[in,out] key Key initialized with noxtls_dsa_key_init().
 * @param[in] y Public value y = g^x mod p.
 *
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if key, key->y, or y is NULL.
 */
noxtls_return_t noxtls_dsa_key_set_public(dsa_key_t *key, const uint8_t *y)
{
    if ((key == NULL) || (key->y == NULL) || (y == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    noxtls_copy_u8(key->y, (size_t)key->p_len, y, (size_t)key->p_len);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Set the DSA private exponent x (big-endian, q_len bytes).
 *
 * @param[in,out] key Key initialized with noxtls_dsa_key_init().
 * @param[in] x Private key in [1, q-1].
 *
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if key, key->x, or x is NULL.
 */
noxtls_return_t noxtls_dsa_key_set_private(dsa_key_t *key, const uint8_t *x)
{
    if ((key == NULL) || (key->x == NULL) || (x == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    noxtls_copy_u8(key->x, (size_t)key->q_len, x, (size_t)key->q_len);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Generate a random DSA private key x and public key y = g^x mod p (FIPS 186-4 style).
 *
 * Requires a key whose domain parameters and buffers were created with noxtls_dsa_key_init().
 *
 * @param[in,out] key Key with valid p, q, g and allocated y and x buffers.
 *
 * @return NOXTLS_RETURN_SUCCESS when y and x are populated.
 * @return NOXTLS_RETURN_NULL if key or required internal pointers are NULL.
 * @return NOXTLS_RETURN_FAILED if memory allocation or DRBG generation fails.
 * @return Other codes (e.g. NOXTLS_RETURN_NOT_ENOUGH_MEMORY) are propagated from the reduction or
 *         modular exponentiation; x and y are wiped on every failure.
 */
noxtls_return_t noxtls_dsa_key_generate(dsa_key_t *key)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    drbg_state_t drbg;
    uint8_t *x_buf = NULL;

    if ((key == NULL) || (key->p == NULL) || (key->q == NULL) || (key->g == NULL) || (key->y == NULL) || (key->x == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if (key->q_len > (uint32_t)(UINT32_MAX / 8U)) {
        return NOXTLS_RETURN_FAILED;
    }

    x_buf = (uint8_t *)NOXTLS_CALLOC(key->q_len, 1U);
    if (x_buf == NULL) {
        rc = NOXTLS_RETURN_FAILED;
    } else {
        rc = drbg_instantiate(&drbg, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            if (drbg_generate(&drbg, x_buf, key->q_len * 8U, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
                rc = NOXTLS_RETURN_FAILED;
            } else {
                /* Every bignum result is checked: a failed reduction must never leave a zeroed x
                 * that is then "fixed up" to x = 1 (y = g) and reported as SUCCESS. */
                rc = noxtls_bn_mod(key->x, x_buf, key->q_len, key->q, key->q_len);
            }
            if (rc == NOXTLS_RETURN_SUCCESS) {
                if (noxtls_bn_is_zero(key->x, key->q_len) != 0) {
                    key->x[key->q_len - 1U] = 1U;
                }
                /* y = g^x mod p */
                rc = noxtls_bn_mod_exp(key->y, key->g, key->x, key->q_len, key->p, key->p_len);
            }
        }
        (void)noxtls_drbg_uninstantiate(&drbg);
        NOXTLS_SECURE_FREE(x_buf, (size_t)key->q_len);
    }
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(key->x, (size_t)key->q_len);
        noxtls_secure_zero(key->y, (size_t)key->p_len);
    }
    return rc;
}

/**
 * @brief Free all heap memory associated with a DSA key and clear lengths.
 *
 * @param[in,out] key Key to release; safe to call on partially initialized keys if pointers are NULL.
 *
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if key is NULL.
 */
noxtls_return_t noxtls_dsa_key_free(dsa_key_t *key)
{
    if (key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if (key->p != NULL) { (void)noxtls_free(key->p); key->p = NULL; }
    if (key->q != NULL) { (void)noxtls_free(key->q); key->q = NULL; }
    if (key->g != NULL) { (void)noxtls_free(key->g); key->g = NULL; }
    if (key->y != NULL) { (void)noxtls_free(key->y); key->y = NULL; }
    /* x is the private exponent: wipe before releasing (NOXTLS_SECURE_FREE also NULLs it). */
    NOXTLS_SECURE_FREE(key->x, (size_t)key->q_len);
    key->p_len = 0U;
    key->q_len = 0U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Zero-initialize a DSA signature structure and set expected component length.
 *
 * @param[in,out] sig Signature object to initialize.
 * @param[in] q_len Byte length for r and s (must not exceed DSA_MAX_Q_BYTES).
 *
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if sig is NULL or q_len is too large.
 */
noxtls_return_t noxtls_dsa_signature_init(dsa_signature_t *sig, uint32_t q_len)
{
    if ((sig == NULL) || (q_len > DSA_MAX_Q_BYTES)) {
        return NOXTLS_RETURN_NULL;
    }
    noxtls_secure_zero((sig->r), (size_t)(DSA_MAX_Q_BYTES));
    noxtls_secure_zero((sig->s), (size_t)(DSA_MAX_Q_BYTES));
    sig->q_len = q_len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Securely clear a DSA signature structure (r, s) and reset q_len.
 *
 * @param[in,out] sig Signature to clear.
 *
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if sig is NULL.
 */
noxtls_return_t noxtls_dsa_signature_free(dsa_signature_t *sig)
{
    if (sig == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    noxtls_secure_zero((sig->r), (size_t)(DSA_MAX_Q_BYTES));
    noxtls_secure_zero((sig->s), (size_t)(DSA_MAX_Q_BYTES));
    sig->q_len = 0U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Map a bignum failure to the DSA API contract.
 *
 * Allocation failures are reported as NOXTLS_RETURN_NOT_ENOUGH_MEMORY so callers can
 * tell them apart; every other bignum failure is reported as NOXTLS_RETURN_FAILED.
 *
 * @param[in] rc Non-success return code from a bignum primitive.
 * @return The mapped return code (never NOXTLS_RETURN_SUCCESS for a failure input).
 */
static noxtls_return_t dsa_bn_error(noxtls_return_t rc)
{
    noxtls_return_t mapped = NOXTLS_RETURN_FAILED;
    if (rc == NOXTLS_RETURN_SUCCESS) {
        mapped = NOXTLS_RETURN_SUCCESS;
    } else if (rc == NOXTLS_RETURN_NOT_ENOUGH_MEMORY) {
        mapped = NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    } else {
        mapped = NOXTLS_RETURN_FAILED;
    }
    return mapped;
}

/**
 * @brief Create a DSA signature (r, s) on a noxtls_message using the private key (FIPS 186-4).
 *
 * @param[in] key Key with domain parameters and private exponent x set.
 * @param[in] noxtls_message Message to sign.
 * @param[in] message_len Length of noxtls_message in bytes.
 * @param[out] signature Output (r, s); q_len set on success. Initialize with noxtls_dsa_signature_init() if desired.
 *                       r and s are wiped on any failure.
 * @param[in] hash_algo Message digest algorithm for computing the hash of noxtls_message.
 *
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if key, key->x, noxtls_message, or signature is NULL.
 * @return NOXTLS_RETURN_FAILED if lengths are invalid, allocation of the working buffers fails, DRBG fails,
 *         a bignum operation fails, or a signature could not be produced.
 * @return NOXTLS_RETURN_NOT_ENOUGH_MEMORY if a bignum operation runs out of memory.
 * @return NOXTLS_RETURN_INVALID_ALGORITHM from the noxtls_message hash step if @p hash_algo is unsupported.
 */
noxtls_return_t noxtls_dsa_sign(const dsa_key_t *key, const uint8_t *noxtls_message, uint32_t message_len, dsa_signature_t *signature, noxtls_hash_algos_t hash_algo)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint8_t *hash = NULL;
    uint32_t hash_len = 0U;
    uint8_t *z = NULL;
    uint8_t *k = NULL;
    uint8_t *k_inv = NULL;
    uint8_t *g_k = NULL;
    uint8_t *rx = NULL;
    uint8_t *z_rx = NULL;
    uint8_t *zr_mod = NULL;
    uint8_t *random_bytes = NULL;
    drbg_state_t drbg;
    uint8_t drbg_ready = 0U;
    uint8_t done = 0U;
    uint32_t p_len = 0U;
    uint32_t q_len = 0U;
    uint32_t max_attempts = 100U;
    uint32_t attempt = 0U;

    if ((key == NULL) || (key->x == NULL) || (noxtls_message == NULL) || (signature == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    p_len = key->p_len;
    q_len = key->q_len;
    if ((q_len > DSA_MAX_Q_BYTES) || (p_len > DSA_MAX_P_BYTES)) {
        return NOXTLS_RETURN_FAILED;
    }
    if ((q_len > (uint32_t)(UINT32_MAX / 8U)) ||
       (q_len > (uint32_t)(UINT32_MAX / 2U)) ||
       (p_len > (uint32_t)(UINT32_MAX / 2U)) ||
       (q_len == UINT32_MAX)) {
        return NOXTLS_RETURN_FAILED;
    }

    hash = (uint8_t *)NOXTLS_CALLOC(64U, 1U);
    z = (uint8_t *)NOXTLS_CALLOC(q_len, 1U);
    k = (uint8_t *)NOXTLS_CALLOC(q_len, 1U);
    k_inv = (uint8_t *)NOXTLS_CALLOC(q_len, 1U);
    g_k = (uint8_t *)NOXTLS_CALLOC(p_len, 1U);
    rx = (uint8_t *)NOXTLS_CALLOC((size_t)q_len * 2U, 1U);
    z_rx = (uint8_t *)NOXTLS_CALLOC(q_len + 1U, 1U);
    zr_mod = (uint8_t *)NOXTLS_CALLOC(q_len, 1U);
    random_bytes = (uint8_t *)NOXTLS_CALLOC(q_len, 1U);
    if ((hash == NULL) || (z == NULL) || (k == NULL) || (k_inv == NULL) || (g_k == NULL) || (rx == NULL) ||
        (z_rx == NULL) || (zr_mod == NULL) || (random_bytes == NULL)) {
        rc = NOXTLS_RETURN_FAILED;
    } else {
        rc = dsa_hash_message(hash, &hash_len, noxtls_message, message_len, hash_algo);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        /* z = leftmost min(q_len, hash_len) bytes of hash; if hash_len < q_len, pad with zeros on left */
        if (hash_len >= q_len) {
            noxtls_copy_u8(z, (size_t)q_len, hash, (size_t)q_len);
        }
        else {
            noxtls_copy_u8(&z[q_len - hash_len], (size_t)hash_len, hash, (size_t)hash_len);
        }
        /* Reduce z mod q if z >= q (FIPS 186-4: z may be truncated to N bits; we use bytes) */
        if (noxtls_bn_cmp(z, key->q, q_len) >= 0) {
            rc = dsa_bn_error(noxtls_bn_mod(z, z, q_len, key->q, q_len));
        }
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = drbg_instantiate(&drbg, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0);
        drbg_ready = 1U;
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = NOXTLS_RETURN_FAILED; /* result when every attempt has to be retried */
        for (attempt = 0U; (attempt < max_attempts) && (done == 0U); attempt += 1U) {
            uint8_t retry = 0U;
            noxtls_return_t step = NOXTLS_RETURN_SUCCESS;

            if (drbg_generate(&drbg, random_bytes, q_len * 8U, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
                step = NOXTLS_RETURN_FAILED;
            }
            if (step == NOXTLS_RETURN_SUCCESS) {
                step = noxtls_bn_mod(k, random_bytes, q_len, key->q, q_len);
            }
            if (step == NOXTLS_RETURN_SUCCESS) {
                if (noxtls_bn_is_zero(k, q_len) != 0) {
                    k[q_len - 1U] = 1U;
                }
                /* r = (g^k mod p) mod q; exp k is q-sized, modulus is p. */
                step = noxtls_bn_mod_exp(g_k, key->g, k, q_len, key->p, p_len);
            }
            if (step == NOXTLS_RETURN_SUCCESS) {
                step = noxtls_bn_mod(signature->r, g_k, p_len, key->q, q_len);
            }
            if ((step == NOXTLS_RETURN_SUCCESS) && (noxtls_bn_is_zero(signature->r, q_len) != 0)) {
                retry = 1U;
            }

            /* s = k^(-1) * (z + r*x) mod q */
            if ((step == NOXTLS_RETURN_SUCCESS) && (retry == 0U)) {
                step = noxtls_bn_mod_inv(k_inv, k, q_len, key->q, q_len);
                if (step == NOXTLS_RETURN_FAILED) {
                    /* gcd(k, q) != 1 (only possible for a non-prime q): draw a new nonce. */
                    retry = 1U;
                    step = NOXTLS_RETURN_SUCCESS;
                }
            }
            if ((step == NOXTLS_RETURN_SUCCESS) && (retry == 0U)) {
                step = noxtls_bn_mul(rx, signature->r, q_len, key->x, q_len);
            }
            if ((step == NOXTLS_RETURN_SUCCESS) && (retry == 0U)) {
                step = noxtls_bn_mod(rx, rx, q_len * 2U, key->q, q_len);
            }
            if ((step == NOXTLS_RETURN_SUCCESS) && (retry == 0U)) {
                /* z_rx = z + rx (both q_len; sum may need q_len+1 bytes) */
                uint16_t carry = 0U;
                uint32_t i = 0U;
                for (i = q_len; i > 0U; i -= 1U) {
                    uint32_t idx = (uint32_t)(i - 1U);
                    uint16_t sum = (uint16_t)((uint16_t)z[idx] + (uint16_t)rx[idx] + carry);
                    z_rx[idx + 1U] = (uint8_t)(sum & 0xFFU);
                    {
                        uint32_t next_carry = (uint32_t)sum;
                        next_carry >>= 8U;
                        carry = (uint16_t)next_carry;
                    }
                }
                z_rx[0] = (uint8_t)carry;
                {
                    /* Reduce into a separate buffer: the source may start one byte into z_rx. */
                    uint32_t len = (z_rx[0U] != 0U) ? (q_len + 1U) : q_len;
                    const uint8_t *src = (z_rx[0] != 0U) ? z_rx : (&z_rx[1U]);
                    step = noxtls_bn_mod(zr_mod, src, len, key->q, q_len);
                }
            }
            if ((step == NOXTLS_RETURN_SUCCESS) && (retry == 0U)) {
                step = noxtls_bn_mul(rx, k_inv, q_len, zr_mod, q_len);
            }
            if ((step == NOXTLS_RETURN_SUCCESS) && (retry == 0U)) {
                step = noxtls_bn_mod(signature->s, rx, q_len * 2U, key->q, q_len);
            }
            if ((step == NOXTLS_RETURN_SUCCESS) && (retry == 0U) && (noxtls_bn_is_zero(signature->s, q_len) != 0)) {
                retry = 1U;
            }

            if (step != NOXTLS_RETURN_SUCCESS) {
                /* Hard failure (allocation, DRBG, arithmetic): stop, never emit (r, s). */
                rc = dsa_bn_error(step);
                done = 1U;
            } else if (retry == 0U) {
                rc = NOXTLS_RETURN_SUCCESS;
                done = 1U;
            } else {
                rc = NOXTLS_RETURN_FAILED;
            }
        }
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        signature->q_len = q_len;
    } else {
        noxtls_secure_zero(signature->r, sizeof(signature->r));
        noxtls_secure_zero(signature->s, sizeof(signature->s));
    }

    if (drbg_ready != 0U) {
        (void)noxtls_drbg_uninstantiate(&drbg);
    }
    /* k, k^-1 and the x-derived products are secret: wipe before releasing. */
    NOXTLS_SECURE_FREE(hash, 64U);
    NOXTLS_SECURE_FREE(z, (size_t)q_len);
    NOXTLS_SECURE_FREE(k, (size_t)q_len);
    NOXTLS_SECURE_FREE(k_inv, (size_t)q_len);
    NOXTLS_SECURE_FREE(g_k, (size_t)p_len);
    NOXTLS_SECURE_FREE(rx, (size_t)q_len * 2U);
    NOXTLS_SECURE_FREE(z_rx, (size_t)q_len + 1U);
    NOXTLS_SECURE_FREE(zr_mod, (size_t)q_len);
    NOXTLS_SECURE_FREE(random_bytes, (size_t)q_len);
    return rc;
}

/**
 * @brief Verify a DSA signature (r, s) on a noxtls_message using the public key (FIPS 186-4).
 *
 * @param[in] key Key with domain parameters and public value y set.
 * @param[in] noxtls_message Message that was signed.
 * @param[in] message_len Length of noxtls_message in bytes.
 * @param[in] signature Signature (r, s); signature->q_len must match key->q_len.
 * @param[in] hash_algo Message digest algorithm used when the signature was created.
 *
 * @return NOXTLS_RETURN_SUCCESS if the signature is valid.
 * @return NOXTLS_RETURN_NULL if key, key->y, noxtls_message, or signature is NULL.
 * @return NOXTLS_RETURN_FAILED if lengths or (r, s) are out of range, allocation of the working buffers fails,
 *         a bignum operation fails, or verification fails.
 * @return NOXTLS_RETURN_NOT_ENOUGH_MEMORY if a bignum operation runs out of memory.
 * @return NOXTLS_RETURN_INVALID_ALGORITHM from the noxtls_message hash step if @p hash_algo is unsupported.
 */
noxtls_return_t noxtls_dsa_verify(const dsa_key_t *key, const uint8_t *noxtls_message, uint32_t message_len, const dsa_signature_t *signature, noxtls_hash_algos_t hash_algo)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint8_t *hash = NULL;
    uint32_t hash_len = 0U;
    uint8_t *z = NULL;
    uint8_t *w = NULL;
    uint8_t *u1 = NULL;
    uint8_t *u2 = NULL;
    uint8_t *g_u1 = NULL;
    uint8_t *y_u2 = NULL;
    uint8_t *v = NULL;
    uint8_t *product = NULL;
    uint32_t p_len = 0U;
    uint32_t q_len = 0U;

    if ((key == NULL) || (key->y == NULL) || (noxtls_message == NULL) || (signature == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    p_len = key->p_len;
    q_len = key->q_len;
    if ((signature->q_len != q_len) || (q_len > DSA_MAX_Q_BYTES) || (p_len > DSA_MAX_P_BYTES)) {
        return NOXTLS_RETURN_FAILED;
    }
    if ((q_len > (uint32_t)(UINT32_MAX / 2U)) ||
       (p_len > (uint32_t)(UINT32_MAX / 2U)) ||
       (q_len == UINT32_MAX)) {
        return NOXTLS_RETURN_FAILED;
    }

    /* r, s in [1, q-1] */
    {
        int r_zero = noxtls_bn_is_zero(signature->r, q_len);
        int r_cmp = noxtls_bn_cmp(signature->r, key->q, q_len);
        if ((r_zero != 0) || (r_cmp >= 0)) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    {
        int s_zero = noxtls_bn_is_zero(signature->s, q_len);
        int s_cmp = noxtls_bn_cmp(signature->s, key->q, q_len);
        if ((s_zero != 0) || (s_cmp >= 0)) {
            return NOXTLS_RETURN_FAILED;
        }
    }

    hash = (uint8_t *)NOXTLS_CALLOC(64U, 1U);
    z = (uint8_t *)NOXTLS_CALLOC(q_len, 1U);
    w = (uint8_t *)NOXTLS_CALLOC(q_len, 1U);
    u1 = (uint8_t *)NOXTLS_CALLOC((size_t)q_len * 2U, 1U);
    u2 = (uint8_t *)NOXTLS_CALLOC((size_t)q_len * 2U, 1U);
    g_u1 = (uint8_t *)NOXTLS_CALLOC(p_len, 1U);
    y_u2 = (uint8_t *)NOXTLS_CALLOC(p_len, 1U);
    v = (uint8_t *)NOXTLS_CALLOC(q_len, 1U);
    product = (uint8_t *)NOXTLS_CALLOC((size_t)p_len * 2U, 1U);
    if ((hash == NULL) || (z == NULL) || (w == NULL) || (u1 == NULL) || (u2 == NULL) || (g_u1 == NULL) ||
        (y_u2 == NULL) || (v == NULL) || (product == NULL)) {
        rc = NOXTLS_RETURN_FAILED;
    } else {
        rc = dsa_hash_message(hash, &hash_len, noxtls_message, message_len, hash_algo);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        if (hash_len >= q_len) {
            noxtls_copy_u8(z, (size_t)q_len, hash, (size_t)q_len);
        }
        else {
            noxtls_copy_u8(&z[q_len - hash_len], (size_t)hash_len, hash, (size_t)hash_len);
        }
        if (noxtls_bn_cmp(z, key->q, q_len) >= 0) {
            rc = dsa_bn_error(noxtls_bn_mod(z, z, q_len, key->q, q_len));
        }
    }

    /* Every bignum step is checked; a failure can never fall through to the final compare. */
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = dsa_bn_error(noxtls_bn_mod_inv(w, signature->s, q_len, key->q, q_len));
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = dsa_bn_error(noxtls_bn_mul(u1, w, q_len, z, q_len));
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = dsa_bn_error(noxtls_bn_mod(u1, u1, q_len * 2U, key->q, q_len));
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = dsa_bn_error(noxtls_bn_mul(u2, w, q_len, signature->r, q_len));
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = dsa_bn_error(noxtls_bn_mod(u2, u2, q_len * 2U, key->q, q_len));
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = dsa_bn_error(noxtls_bn_mod_exp(g_u1, key->g, u1, q_len, key->p, p_len));
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = dsa_bn_error(noxtls_bn_mod_exp(y_u2, key->y, u2, q_len, key->p, p_len));
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = dsa_bn_error(noxtls_bn_mul(product, g_u1, p_len, y_u2, p_len));
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = dsa_bn_error(noxtls_bn_mod(g_u1, product, p_len * 2U, key->p, p_len));  /* g_u1 = (g^u1 * y^u2) mod p */
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = dsa_bn_error(noxtls_bn_mod(v, g_u1, p_len, key->q, q_len));             /* v = (...) mod q */
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = (noxtls_bn_cmp(v, signature->r, q_len) == 0) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
    }

    NOXTLS_SECURE_FREE(hash, 64U);
    NOXTLS_SECURE_FREE(z, (size_t)q_len);
    NOXTLS_SECURE_FREE(w, (size_t)q_len);
    NOXTLS_SECURE_FREE(u1, (size_t)q_len * 2U);
    NOXTLS_SECURE_FREE(u2, (size_t)q_len * 2U);
    NOXTLS_SECURE_FREE(g_u1, (size_t)p_len);
    NOXTLS_SECURE_FREE(y_u2, (size_t)p_len);
    NOXTLS_SECURE_FREE(v, (size_t)q_len);
    NOXTLS_SECURE_FREE(product, (size_t)p_len * 2U);
    return rc;
}
