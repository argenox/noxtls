/****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_mldsa.c
* Summary: In-house ML-DSA implementation backend.
*/

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "noxtls_mldsa.h"
#include "drbg/noxtls_drbg.h"

/* Parameter-set cores are built as separate translation units with these symbol prefixes. */
int noxtls_mldsa44_keypair_internal(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
int noxtls_mldsa65_keypair_internal(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
int noxtls_mldsa87_keypair_internal(uint8_t *pk, uint8_t *sk, const uint8_t *seed);

int noxtls_mldsa44_signature_internal(uint8_t *sig, size_t *siglen,
                                      const uint8_t *m, size_t mlen,
                                      const uint8_t *pre, size_t prelen,
                                      const uint8_t *rnd,
                                      const uint8_t *sk,
                                      int externalmu);
int noxtls_mldsa65_signature_internal(uint8_t *sig, size_t *siglen,
                                      const uint8_t *m, size_t mlen,
                                      const uint8_t *pre, size_t prelen,
                                      const uint8_t *rnd,
                                      const uint8_t *sk,
                                      int externalmu);
int noxtls_mldsa87_signature_internal(uint8_t *sig, size_t *siglen,
                                      const uint8_t *m, size_t mlen,
                                      const uint8_t *pre, size_t prelen,
                                      const uint8_t *rnd,
                                      const uint8_t *sk,
                                      int externalmu);
int noxtls_mldsa44_signature_pre_hash_internal(uint8_t *sig, size_t *siglen,
                                                const uint8_t *ph, size_t phlen,
                                                const uint8_t *ctx, size_t ctxlen,
                                                const uint8_t *rnd,
                                                const uint8_t *sk,
                                                int hashalg);
int noxtls_mldsa65_signature_pre_hash_internal(uint8_t *sig, size_t *siglen,
                                                const uint8_t *ph, size_t phlen,
                                                const uint8_t *ctx, size_t ctxlen,
                                                const uint8_t *rnd,
                                                const uint8_t *sk,
                                                int hashalg);
int noxtls_mldsa87_signature_pre_hash_internal(uint8_t *sig, size_t *siglen,
                                                const uint8_t *ph, size_t phlen,
                                                const uint8_t *ctx, size_t ctxlen,
                                                const uint8_t *rnd,
                                                const uint8_t *sk,
                                                int hashalg);

int noxtls_mldsa44_verify_internal(const uint8_t *sig, size_t siglen,
                                   const uint8_t *m, size_t mlen,
                                   const uint8_t *pre, size_t prelen,
                                   const uint8_t *pk,
                                   int externalmu);
int noxtls_mldsa65_verify_internal(const uint8_t *sig, size_t siglen,
                                   const uint8_t *m, size_t mlen,
                                   const uint8_t *pre, size_t prelen,
                                   const uint8_t *pk,
                                   int externalmu);
int noxtls_mldsa87_verify_internal(const uint8_t *sig, size_t siglen,
                                   const uint8_t *m, size_t mlen,
                                   const uint8_t *pre, size_t prelen,
                                   const uint8_t *pk,
                                   int externalmu);
int noxtls_mldsa44_verify_pre_hash_internal(const uint8_t *sig, size_t siglen,
                                            const uint8_t *ph, size_t phlen,
                                            const uint8_t *ctx, size_t ctxlen,
                                            const uint8_t *pk,
                                            int hashalg);
int noxtls_mldsa65_verify_pre_hash_internal(const uint8_t *sig, size_t siglen,
                                            const uint8_t *ph, size_t phlen,
                                            const uint8_t *ctx, size_t ctxlen,
                                            const uint8_t *pk,
                                            int hashalg);
int noxtls_mldsa87_verify_pre_hash_internal(const uint8_t *sig, size_t siglen,
                                            const uint8_t *ph, size_t phlen,
                                            const uint8_t *ctx, size_t ctxlen,
                                            const uint8_t *pk,
                                            int hashalg);

static const uint8_t *g_mldsa_test_seed_seq = NULL;
static uint32_t g_mldsa_test_seed_seq_len = 0u;
static uint32_t g_mldsa_test_seed_seq_off = 0u;
static uint8_t g_mldsa_test_pre[NOXTLS_MLDSA_TEST_OVERRIDE_PRE_LEN];
static uint32_t g_mldsa_test_pre_len = 0u;
static uint8_t g_mldsa_test_rnd[NOXTLS_MLDSA_RND_LEN];
static uint8_t g_mldsa_test_rnd_set = 0u;
static uint8_t g_mldsa_test_externalmu = 0u;

/**
 * @brief Resolve fixed key/signature sizes for an ML-DSA parameter set.
 * @param[in] param Parameter set selector (44/65/87).
 * @param[out] sizes Output structure populated on success.
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if sizes is NULL.
 * @return NOXTLS_RETURN_INVALID_PARAM if param is unsupported.
 */
static noxtls_return_t mldsa_get_sizes(noxtls_mldsa_param_t param, mldsa_sizes_t *sizes)
{
    if(sizes == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    switch(param) {
        case NOXTLS_MLDSA_44:
            sizes->public_key_len = 1312u;
            sizes->secret_key_len = 2560u;
            sizes->signature_len = 2420u;
            return NOXTLS_RETURN_SUCCESS;
        case NOXTLS_MLDSA_65:
            sizes->public_key_len = 1952u;
            sizes->secret_key_len = 4032u;
            sizes->signature_len = 3309u;
            return NOXTLS_RETURN_SUCCESS;
        case NOXTLS_MLDSA_87:
            sizes->public_key_len = 2592u;
            sizes->secret_key_len = 4896u;
            sizes->signature_len = 4627u;
            return NOXTLS_RETURN_SUCCESS;
        default:
            return NOXTLS_RETURN_INVALID_PARAM;
    }
}

/**
 * @brief Produce a 32-byte seed for ML-DSA key generation.
 * @param[out] out Output seed buffer (NOXTLS_MLDSA_SEED_LEN bytes).
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return Propagated DRBG error code on entropy/DRBG failure.
 */
static noxtls_return_t mldsa_gen_seed32(uint8_t out[NOXTLS_MLDSA_SEED_LEN])
{
    if(g_mldsa_test_seed_seq != NULL &&
       (g_mldsa_test_seed_seq_off + NOXTLS_MLDSA_SEED_LEN) <= g_mldsa_test_seed_seq_len) {
        memcpy(out, g_mldsa_test_seed_seq + g_mldsa_test_seed_seq_off, NOXTLS_MLDSA_SEED_LEN);
        g_mldsa_test_seed_seq_off += NOXTLS_MLDSA_SEED_LEN;
        return NOXTLS_RETURN_SUCCESS;
    }

    {
        drbg_state_t drbg;
        noxtls_return_t rc = drbg_instantiate(&drbg, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        return drbg_generate(&drbg, out, NOXTLS_MLDSA_SEED_LEN * 8u, NULL, 0);
    }
}

/**
 * @brief Random-byte callback used by ML-DSA core wrappers.
 * @param[out] out Destination buffer.
 * @param[in] outlen Number of bytes to generate.
 * @return 0 on success, -1 on failure.
 */
int noxtls_mldsa_randombytes_internal(uint8_t *out, size_t outlen)
{
    size_t seq_off;
    size_t seq_len;

    if(out == NULL) {
        return -1;
    }

    if(outlen > (size_t)UINT32_MAX) {
        return -1;
    }

    seq_off = (size_t)g_mldsa_test_seed_seq_off;
    seq_len = (size_t)g_mldsa_test_seed_seq_len;
    if(g_mldsa_test_seed_seq != NULL) {
        if(seq_off <= seq_len && outlen <= (seq_len - seq_off)) {
            memcpy(out, g_mldsa_test_seed_seq + seq_off, outlen);
            g_mldsa_test_seed_seq_off += (uint32_t)outlen;
            return 0;
        }
    }

    if(outlen > ((size_t)UINT32_MAX / 8u)) {
        return -1;
    }

    {
        drbg_state_t drbg;
        if(drbg_instantiate(&drbg, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
            return -1;
        }
        if(drbg_generate(&drbg, out, (uint32_t)outlen * 8u, NULL, 0) != NOXTLS_RETURN_SUCCESS) {
            return -1;
        }
    }

    return 0;
}

/**
 * @brief Get public key length for a given ML-DSA parameter set.
 * @param[in] param Parameter set selector.
 * @return Public key length in bytes, or 0 for invalid param.
 */
uint32_t noxtls_mldsa_public_key_len(noxtls_mldsa_param_t param)
{
    mldsa_sizes_t sizes;
    return (mldsa_get_sizes(param, &sizes) == NOXTLS_RETURN_SUCCESS) ? sizes.public_key_len : 0u;
}

/**
 * @brief Get secret key length for a given ML-DSA parameter set.
 * @param[in] param Parameter set selector.
 * @return Secret key length in bytes, or 0 for invalid param.
 */
uint32_t noxtls_mldsa_secret_key_len(noxtls_mldsa_param_t param)
{
    mldsa_sizes_t sizes;
    return (mldsa_get_sizes(param, &sizes) == NOXTLS_RETURN_SUCCESS) ? sizes.secret_key_len : 0u;
}

/**
 * @brief Get signature length for a given ML-DSA parameter set.
 * @param[in] param Parameter set selector.
 * @return Signature length in bytes, or 0 for invalid param.
 */
uint32_t noxtls_mldsa_signature_len(noxtls_mldsa_param_t param)
{
    mldsa_sizes_t sizes;
    return (mldsa_get_sizes(param, &sizes) == NOXTLS_RETURN_SUCCESS) ? sizes.signature_len : 0u;
}

/**
 * @brief Install deterministic test-seed bytes consumed by keygen/sign helpers.
 * @param[in] bytes Seed byte stream source (may be NULL to disable).
 * @param[in] byte_len Length of @p bytes.
 */
void noxtls_mldsa_set_test_seed_sequence(const uint8_t *bytes, uint32_t byte_len)
{
    g_mldsa_test_seed_seq = bytes;
    g_mldsa_test_seed_seq_len = byte_len;
    g_mldsa_test_seed_seq_off = 0u;
}

/**
 * @brief Configure test-only signing overrides for pre/domain bytes, rnd, and externalmu mode.
 * @param[in] pre Optional pre/domain override blob.
 * @param[in] pre_len Length of @p pre.
 * @param[in] rnd Optional deterministic random bytes (must be NOXTLS_MLDSA_RND_LEN).
 * @param[in] rnd_len Length of @p rnd.
 * @param[in] externalmu Non-zero to force externalmu path in test mode.
 */
void noxtls_mldsa_set_test_signing_overrides(const uint8_t *pre,
                                             uint32_t pre_len,
                                             const uint8_t *rnd,
                                             uint32_t rnd_len,
                                             uint8_t externalmu)
{
    if(pre != NULL && pre_len <= sizeof(g_mldsa_test_pre)) {
        memcpy(g_mldsa_test_pre, pre, pre_len);
        g_mldsa_test_pre_len = pre_len;
    } else {
        g_mldsa_test_pre_len = 0u;
    }
    if(rnd != NULL && rnd_len == sizeof(g_mldsa_test_rnd)) {
        memcpy(g_mldsa_test_rnd, rnd, sizeof(g_mldsa_test_rnd));
        g_mldsa_test_rnd_set = 1u;
    } else {
        g_mldsa_test_rnd_set = 0u;
    }
    g_mldsa_test_externalmu = externalmu ? 1u : 0u;
}

/**
 * @brief Generate ML-DSA key pair for the requested parameter set.
 * @param[in] param Parameter set selector (44/65/87).
 * @param[out] public_key Output public key buffer (use noxtls_mldsa_public_key_len()).
 * @param[out] secret_key Output secret key buffer (use noxtls_mldsa_secret_key_len()).
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if output pointers are NULL.
 * @return NOXTLS_RETURN_INVALID_PARAM if param is unsupported.
 * @return NOXTLS_RETURN_FAILED if key generation fails in the ML-DSA core.
 */
noxtls_return_t noxtls_mldsa_keygen(noxtls_mldsa_param_t param, uint8_t *public_key, uint8_t *secret_key)
{
    uint8_t seed[NOXTLS_MLDSA_SEED_LEN];
    noxtls_return_t rc;
    int noxtls_mld_rc;

    if(public_key == NULL || secret_key == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = mldsa_gen_seed32(seed);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    switch(param) {
        case NOXTLS_MLDSA_44:
            noxtls_mld_rc = noxtls_mldsa44_keypair_internal(public_key, secret_key, seed);
            break;
        case NOXTLS_MLDSA_65:
            noxtls_mld_rc = noxtls_mldsa65_keypair_internal(public_key, secret_key, seed);
            break;
        case NOXTLS_MLDSA_87:
            noxtls_mld_rc = noxtls_mldsa87_keypair_internal(public_key, secret_key, seed);
            break;
        default:
            return NOXTLS_RETURN_INVALID_PARAM;
    }

    return (noxtls_mld_rc == 0) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
}

/**
 * @brief Sign a noxtls_message with ML-DSA for the selected parameter set.
 * @param[in] param Parameter set selector (44/65/87).
 * @param[in] secret_key Secret key bytes.
 * @param[in] noxtls_message Message bytes to sign.
 * @param[in] message_len Length of @p noxtls_message in bytes.
 * @param[out] signature Output signature buffer.
 * @param[in,out] signature_len Input capacity of @p signature; output actual signature size on success.
 * @return NOXTLS_RETURN_SUCCESS on success.
 * @return NOXTLS_RETURN_NULL if required pointers are NULL.
 * @return NOXTLS_RETURN_INVALID_PARAM if param is unsupported.
 * @return NOXTLS_RETURN_FAILED on backend failure or insufficient output buffer size.
 */
noxtls_return_t noxtls_mldsa_sign(noxtls_mldsa_param_t param,
                                  const uint8_t *secret_key,
                                  const uint8_t *noxtls_message,
                                  uint32_t message_len,
                                  uint8_t *signature,
                                  uint32_t *signature_len)
{
    static const uint8_t pre_prefix[2] = { 0x00u, 0x00u };
    static const uint8_t zero_ctx[1] = { 0u };
    uint8_t pre_local[NOXTLS_MLDSA_PURE_PRE_LEN];
    uint8_t rnd[NOXTLS_MLDSA_RND_LEN];
    const uint8_t *pre = pre_prefix;
    size_t pre_len = sizeof(pre_prefix);
    const uint8_t *ctx = zero_ctx;
    size_t ctx_len = 0u;
    uint8_t mode = 0u;
    int hashalg = 0;
    int externalmu = 0;
    size_t noxtls_mld_sig_len;
    uint32_t needed;
    int noxtls_mld_rc;

    if(secret_key == NULL || noxtls_message == NULL || signature == NULL || signature_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    needed = noxtls_mldsa_signature_len(param);
    if(needed == 0u) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if(*signature_len < needed) {
        *signature_len = needed;
        return NOXTLS_RETURN_FAILED;
    }

    if(g_mldsa_test_pre_len >= 2u) {
        if(g_mldsa_test_pre_len >= 3u) {
            mode = g_mldsa_test_pre[0];
            hashalg = (int)g_mldsa_test_pre[1];
            ctx_len = (size_t)g_mldsa_test_pre[2];
            if(ctx_len > 0u && (3u + ctx_len) <= g_mldsa_test_pre_len) {
                ctx = g_mldsa_test_pre + 3u;
            } else {
                ctx = zero_ctx;
                ctx_len = 0u;
            }
        } else {
            /* Backward-compatible format: [mode, ctxlen, ctx...] */
            mode = g_mldsa_test_pre[0];
            hashalg = 0;
            ctx_len = (size_t)g_mldsa_test_pre[1];
            if(ctx_len > 0u && (2u + ctx_len) <= g_mldsa_test_pre_len) {
                ctx = g_mldsa_test_pre + 2u;
            } else {
                ctx = zero_ctx;
                ctx_len = 0u;
            }
        }
        if(mode == 0u) {
            pre = pre_prefix;
            pre_len = sizeof(pre_prefix);
            if(ctx_len <= 255u) {
                pre_local[0] = 0u;
                pre_local[1] = (uint8_t)ctx_len;
                if(ctx_len > 0u) {
                    memcpy(pre_local + 2u, ctx, ctx_len);
                }
                pre = pre_local;
                pre_len = ctx_len + 2u;
            }
        }
    }
    externalmu = g_mldsa_test_externalmu ? 1 : 0;
    if(g_mldsa_test_rnd_set) {
        memcpy(rnd, g_mldsa_test_rnd, sizeof(rnd));
    } else {
        memset(rnd, 0, sizeof(rnd));
    }
    noxtls_mld_sig_len = (size_t)needed;

    switch(param) {
        case NOXTLS_MLDSA_44:
            if(mode == 1u && externalmu == 0) {
                noxtls_mld_rc = noxtls_mldsa44_signature_pre_hash_internal(signature, &noxtls_mld_sig_len,
                                                                    noxtls_message, (size_t)message_len,
                                                                    ctx, ctx_len,
                                                                    rnd, secret_key, hashalg);
            } else {
                noxtls_mld_rc = noxtls_mldsa44_signature_internal(signature, &noxtls_mld_sig_len,
                                                           noxtls_message, (size_t)message_len,
                                                           pre, pre_len,
                                                           rnd, secret_key, externalmu);
            }
            break;
        case NOXTLS_MLDSA_65:
            if(mode == 1u && externalmu == 0) {
                noxtls_mld_rc = noxtls_mldsa65_signature_pre_hash_internal(signature, &noxtls_mld_sig_len,
                                                                    noxtls_message, (size_t)message_len,
                                                                    ctx, ctx_len,
                                                                    rnd, secret_key, hashalg);
            } else {
                noxtls_mld_rc = noxtls_mldsa65_signature_internal(signature, &noxtls_mld_sig_len,
                                                           noxtls_message, (size_t)message_len,
                                                           pre, pre_len,
                                                           rnd, secret_key, externalmu);
            }
            break;
        case NOXTLS_MLDSA_87:
            if(mode == 1u && externalmu == 0) {
                noxtls_mld_rc = noxtls_mldsa87_signature_pre_hash_internal(signature, &noxtls_mld_sig_len,
                                                                    noxtls_message, (size_t)message_len,
                                                                    ctx, ctx_len,
                                                                    rnd, secret_key, hashalg);
            } else {
                noxtls_mld_rc = noxtls_mldsa87_signature_internal(signature, &noxtls_mld_sig_len,
                                                           noxtls_message, (size_t)message_len,
                                                           pre, pre_len,
                                                           rnd, secret_key, externalmu);
            }
            break;
        default:
            return NOXTLS_RETURN_INVALID_PARAM;
    }

    if(noxtls_mld_rc != 0) {
        return NOXTLS_RETURN_FAILED;
    }

    *signature_len = (uint32_t)noxtls_mld_sig_len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Verify an ML-DSA signature for the selected parameter set.
 * @param[in] param Parameter set selector (44/65/87).
 * @param[in] public_key Public key bytes.
 * @param[in] noxtls_message Signed noxtls_message bytes.
 * @param[in] message_len Length of @p noxtls_message in bytes.
 * @param[in] signature Signature bytes to validate.
 * @param[in] signature_len Length of @p signature in bytes.
 * @return NOXTLS_RETURN_SUCCESS if signature is valid.
 * @return NOXTLS_RETURN_NULL if required pointers are NULL.
 * @return NOXTLS_RETURN_INVALID_PARAM if param is unsupported.
 * @return NOXTLS_RETURN_FAILED on verification failure or malformed length.
 */
noxtls_return_t noxtls_mldsa_verify(noxtls_mldsa_param_t param,
                                    const uint8_t *public_key,
                                    const uint8_t *noxtls_message,
                                    uint32_t message_len,
                                    const uint8_t *signature,
                                    uint32_t signature_len)
{
    static const uint8_t pre_prefix[2] = { 0x00u, 0x00u };
    static const uint8_t zero_ctx[1] = { 0u };
    uint8_t pre_local[NOXTLS_MLDSA_PURE_PRE_LEN];
    const uint8_t *pre = pre_prefix;
    size_t pre_len = sizeof(pre_prefix);
    const uint8_t *ctx = zero_ctx;
    size_t ctx_len = 0u;
    uint8_t mode = 0u;
    int hashalg = 0;
    int externalmu = 0;
    int noxtls_mld_rc;

    if(public_key == NULL || noxtls_message == NULL || signature == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(signature_len != noxtls_mldsa_signature_len(param)) {
        return NOXTLS_RETURN_FAILED;
    }

    if(g_mldsa_test_pre_len >= 2u) {
        if(g_mldsa_test_pre_len >= 3u) {
            mode = g_mldsa_test_pre[0];
            hashalg = (int)g_mldsa_test_pre[1];
            ctx_len = (size_t)g_mldsa_test_pre[2];
            if(ctx_len > 0u && (3u + ctx_len) <= g_mldsa_test_pre_len) {
                ctx = g_mldsa_test_pre + 3u;
            } else {
                ctx = zero_ctx;
                ctx_len = 0u;
            }
        } else {
            mode = g_mldsa_test_pre[0];
            hashalg = 0;
            ctx_len = (size_t)g_mldsa_test_pre[1];
            if(ctx_len > 0u && (2u + ctx_len) <= g_mldsa_test_pre_len) {
                ctx = g_mldsa_test_pre + 2u;
            } else {
                ctx = zero_ctx;
                ctx_len = 0u;
            }
        }
        if(mode == 0u) {
            pre = pre_prefix;
            pre_len = sizeof(pre_prefix);
            if(ctx_len <= 255u) {
                pre_local[0] = 0u;
                pre_local[1] = (uint8_t)ctx_len;
                if(ctx_len > 0u) {
                    memcpy(pre_local + 2u, ctx, ctx_len);
                }
                pre = pre_local;
                pre_len = ctx_len + 2u;
            }
        }
    }
    externalmu = g_mldsa_test_externalmu ? 1 : 0;

    switch(param) {
        case NOXTLS_MLDSA_44:
            if(mode == 1u && externalmu == 0) {
                noxtls_mld_rc = noxtls_mldsa44_verify_pre_hash_internal(signature, (size_t)signature_len,
                                                                  noxtls_message, (size_t)message_len,
                                                                  ctx, ctx_len,
                                                                  public_key, hashalg);
            } else {
                noxtls_mld_rc = noxtls_mldsa44_verify_internal(signature, (size_t)signature_len,
                                                        noxtls_message, (size_t)message_len,
                                                        pre, pre_len,
                                                        public_key, externalmu);
            }
            break;
        case NOXTLS_MLDSA_65:
            if(mode == 1u && externalmu == 0) {
                noxtls_mld_rc = noxtls_mldsa65_verify_pre_hash_internal(signature, (size_t)signature_len,
                                                                  noxtls_message, (size_t)message_len,
                                                                  ctx, ctx_len,
                                                                  public_key, hashalg);
            } else {
                noxtls_mld_rc = noxtls_mldsa65_verify_internal(signature, (size_t)signature_len,
                                                        noxtls_message, (size_t)message_len,
                                                        pre, pre_len,
                                                        public_key, externalmu);
            }
            break;
        case NOXTLS_MLDSA_87:
            if(mode == 1u && externalmu == 0) {
                noxtls_mld_rc = noxtls_mldsa87_verify_pre_hash_internal(signature, (size_t)signature_len,
                                                                  noxtls_message, (size_t)message_len,
                                                                  ctx, ctx_len,
                                                                  public_key, hashalg);
            } else {
                noxtls_mld_rc = noxtls_mldsa87_verify_internal(signature, (size_t)signature_len,
                                                        noxtls_message, (size_t)message_len,
                                                        pre, pre_len,
                                                        public_key, externalmu);
            }
            break;
        default:
            return NOXTLS_RETURN_INVALID_PARAM;
    }

    return (noxtls_mld_rc == 0) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
}

