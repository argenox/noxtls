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
* File:    noxtls_mldsa.c
* Summary: ML-DSA (NIST FIPS 204) public API: pure ML-DSA with context strings,
*          HashML-DSA over a caller-supplied digest, internal interface and
*          workspace management.
*
*
*****************************************************************************/

#include <stdint.h>
#include <stddef.h>

#include "noxtls_mldsa.h"
#include "noxtls_mldsa_internal.h"

#if NOXTLS_FEATURE_ML_DSA

#include "noxtls_ct.h"
#include "noxtls_memory.h"
#include "drbg/noxtls_drbg.h"

/** Length of the DER-encoded hash OIDs 2.16.840.1.101.3.4.2.x. */
#define MLDSA_PH_OID_LEN 11U

/** Operation selector for workspace sizing. */
#define MLDSA_OP_KEYGEN 0U
#define MLDSA_OP_SIGN   1U
#define MLDSA_OP_VERIFY 2U

/** Message description shared by the pure / pre-hash / internal entry points. */
typedef struct
{
    uint32_t has_prefix;      /**< 1: M' = domain || len(ctx) || ctx || oid || msg */
    uint8_t domain;           /**< 0 = pure ML-DSA, 1 = HashML-DSA */
    const uint8_t *ctx;
    uint32_t ctx_len;
    const uint8_t *oid;       /**< NULL for pure ML-DSA */
    const uint8_t *msg;
    uint32_t msg_len;
    uint32_t external_mu;     /**< 1: msg is the 64-byte mu itself */
} mldsa_message_t;

/**
 * @brief Resolve the parameter set and its byte sizes.
 * @param[in] param Parameter set.
 * @param[out] sizes Output sizes.
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL or NOXTLS_RETURN_INVALID_PARAM.
 */
static noxtls_return_t mldsa_get_sizes(noxtls_mldsa_param_t param, mldsa_sizes_t *sizes)
{
    noxtls_mldsa_param_spec_t spec;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(sizes == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    rc = noxtls_mldsa_internal_get_param_spec(param, &spec);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    sizes->public_key_len = spec.public_key_len;
    sizes->secret_key_len = spec.secret_key_len;
    sizes->signature_len = spec.signature_len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Get the encoded public-key length (1312 / 1952 / 2592).
 * @param[in] param Parameter set.
 * @return Length in bytes, 0 for an unsupported parameter set.
 */
uint32_t noxtls_mldsa_public_key_len(noxtls_mldsa_param_t param)
{
    mldsa_sizes_t sizes;
    return (mldsa_get_sizes(param, &sizes) == NOXTLS_RETURN_SUCCESS) ? sizes.public_key_len : 0U;
}

/**
 * @brief Get the encoded secret-key length (2560 / 4032 / 4896).
 * @param[in] param Parameter set.
 * @return Length in bytes, 0 for an unsupported parameter set.
 */
uint32_t noxtls_mldsa_secret_key_len(noxtls_mldsa_param_t param)
{
    mldsa_sizes_t sizes;
    return (mldsa_get_sizes(param, &sizes) == NOXTLS_RETURN_SUCCESS) ? sizes.secret_key_len : 0U;
}

/**
 * @brief Get the signature length (2420 / 3309 / 4627).
 * @param[in] param Parameter set.
 * @return Length in bytes, 0 for an unsupported parameter set.
 */
uint32_t noxtls_mldsa_signature_len(noxtls_mldsa_param_t param)
{
    mldsa_sizes_t sizes;
    return (mldsa_get_sizes(param, &sizes) == NOXTLS_RETURN_SUCCESS) ? sizes.signature_len : 0U;
}

/**
 * @brief Workspace bytes required by one operation.
 * @param[in] spec Parameter set.
 * @param[in] op MLDSA_OP_*.
 * @return Size in bytes.
 */
static uint32_t mldsa_op_ws_len(const noxtls_mldsa_param_spec_t *spec, uint32_t op)
{
    if(op == MLDSA_OP_KEYGEN) {
        return noxtls_mldsa_backend_keygen_ws_len(spec);
    }
    if(op == MLDSA_OP_SIGN) {
        return noxtls_mldsa_backend_sign_ws_len(spec);
    }
    return noxtls_mldsa_backend_verify_ws_len(spec);
}

/**
 * @brief Workspace size that satisfies every ML-DSA operation for a parameter set.
 *
 * Sign needs (k + 3) KiB, verify (l + 3) KiB and key generation 3 KiB.
 *
 * @param[in] param Parameter set.
 * @return Size in bytes (7168 / 9216 / 11264), or 0 for an unsupported set.
 */
uint32_t noxtls_mldsa_workspace_len(noxtls_mldsa_param_t param)
{
    noxtls_mldsa_param_spec_t spec;

    if(noxtls_mldsa_internal_get_param_spec(param, &spec) != NOXTLS_RETURN_SUCCESS) {
        return 0U;
    }
    return mldsa_op_ws_len(&spec, MLDSA_OP_SIGN);
}

/**
 * @brief Use the caller workspace or allocate one.
 * @param[in] spec Parameter set.
 * @param[in] op MLDSA_OP_*.
 * @param[in] ws Caller workspace or NULL.
 * @param[in] ws_len Caller workspace length.
 * @param[out] out Workspace pointer.
 * @param[out] owned 1 when the workspace was allocated here.
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_INVALID_BLOCK_SIZE, NOXTLS_RETURN_INVALID_PARAM
 *         (misaligned) or NOXTLS_RETURN_NOT_ENOUGH_MEMORY.
 */
static noxtls_return_t mldsa_ws_acquire(const noxtls_mldsa_param_spec_t *spec, uint32_t op,
                                        void *ws, uint32_t ws_len,
                                        noxtls_mldsa_poly_t **out, uint32_t *owned)
{
    uint32_t need = mldsa_op_ws_len(spec, op);

    *owned = 0U;
    *out = NULL;
    if(ws != NULL) {
        if(ws_len < need) {
            return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
        }
        if((((uintptr_t)ws) & (uintptr_t)3U) != 0U) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        *out = (noxtls_mldsa_poly_t *)ws;
        return NOXTLS_RETURN_SUCCESS;
    }
    *out = (noxtls_mldsa_poly_t *)NOXTLS_MALLOC((size_t)need);
    if(*out == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    *owned = 1U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Wipe and (if owned) free a workspace.
 * @param[in] spec Parameter set.
 * @param[in] op MLDSA_OP_*.
 * @param[in] ws Workspace.
 * @param[in] owned 1 when allocated by mldsa_ws_acquire.
 */
static void mldsa_ws_release(const noxtls_mldsa_param_spec_t *spec, uint32_t op,
                             noxtls_mldsa_poly_t *ws, uint32_t owned)
{
    if(ws != NULL) {
        noxtls_secure_zero(ws, (size_t)mldsa_op_ws_len(spec, op));
        if(owned != 0U) {
            noxtls_free(ws);
        }
    }
}

/**
 * @brief Draw 32 bytes from a freshly instantiated CTR_DRBG.
 * @param[out] out Output buffer.
 * @return NOXTLS_RETURN_SUCCESS or the DRBG / entropy error.
 */
static noxtls_return_t mldsa_random32(uint8_t out[32])
{
    drbg_state_t drbg;
    noxtls_return_t rc = drbg_instantiate(&drbg, DRBG_AES256, NULL, 0U, NULL, 0U, NULL, 0U);

    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = drbg_generate(&drbg, out, 32U * 8U, NULL, 0U);
    }
    noxtls_secure_zero(&drbg, sizeof(drbg));
    return rc;
}

/**
 * @brief Map a pre-hash identifier to its DER OID and digest length.
 * @param[in] ph Pre-hash identifier.
 * @param[out] oid Output 11-byte OID.
 * @param[out] digest_len Expected digest length.
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_INVALID_ALGORITHM.
 */
static noxtls_return_t mldsa_prehash_info(noxtls_mldsa_prehash_t ph,
                                          uint8_t oid[MLDSA_PH_OID_LEN],
                                          uint32_t *digest_len)
{
    static const uint8_t oid_prefix[MLDSA_PH_OID_LEN - 1U] = {
        0x06U, 0x09U, 0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x02U
    };
    uint8_t arc = 0U;
    uint32_t len = 0U;

    switch(ph) {
        case NOXTLS_MLDSA_PH_SHA2_256:     arc = 0x01U; len = 32U; break;
        case NOXTLS_MLDSA_PH_SHA2_384:     arc = 0x02U; len = 48U; break;
        case NOXTLS_MLDSA_PH_SHA2_512:     arc = 0x03U; len = 64U; break;
        case NOXTLS_MLDSA_PH_SHA2_224:     arc = 0x04U; len = 28U; break;
        case NOXTLS_MLDSA_PH_SHA2_512_224: arc = 0x05U; len = 28U; break;
        case NOXTLS_MLDSA_PH_SHA2_512_256: arc = 0x06U; len = 32U; break;
        case NOXTLS_MLDSA_PH_SHA3_224:     arc = 0x07U; len = 28U; break;
        case NOXTLS_MLDSA_PH_SHA3_256:     arc = 0x08U; len = 32U; break;
        case NOXTLS_MLDSA_PH_SHA3_384:     arc = 0x09U; len = 48U; break;
        case NOXTLS_MLDSA_PH_SHA3_512:     arc = 0x0AU; len = 64U; break;
        case NOXTLS_MLDSA_PH_SHAKE128:     arc = 0x0BU; len = 32U; break;
        case NOXTLS_MLDSA_PH_SHAKE256:     arc = 0x0CU; len = 64U; break;
        default:
            return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    noxtls_copy_u8(oid, MLDSA_PH_OID_LEN, oid_prefix, (size_t)(MLDSA_PH_OID_LEN - 1U));
    oid[MLDSA_PH_OID_LEN - 1U] = arc;
    *digest_len = len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief mu = H(tr || M', 64) where M' is described by msg.
 * @param[in] tr 64-byte public-key hash.
 * @param[in] msg Message description.
 * @param[out] mu Output message representative.
 * @return NOXTLS_RETURN_SUCCESS or a SHAKE error.
 */
static noxtls_return_t mldsa_compute_mu(const uint8_t tr[NOXTLS_MLDSA_TRBYTES],
                                        const mldsa_message_t *msg,
                                        uint8_t mu[NOXTLS_MLDSA_MUBYTES])
{
    noxtls_sha3_ctx_t ctx;
    uint8_t header[2];
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if(msg->external_mu != 0U) {
        noxtls_copy_u8(mu, NOXTLS_MLDSA_MUBYTES, msg->msg, NOXTLS_MLDSA_MUBYTES);
        return NOXTLS_RETURN_SUCCESS;
    }
    rc = noxtls_shake256_init(&ctx);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_update(&ctx, tr, NOXTLS_MLDSA_TRBYTES);
    }
    if((rc == NOXTLS_RETURN_SUCCESS) && (msg->has_prefix != 0U)) {
        header[0] = msg->domain;
        header[1] = (uint8_t)msg->ctx_len;
        rc = noxtls_shake256_update(&ctx, header, 2U);
        if((rc == NOXTLS_RETURN_SUCCESS) && (msg->ctx_len > 0U)) {
            rc = noxtls_shake256_update(&ctx, msg->ctx, msg->ctx_len);
        }
        if((rc == NOXTLS_RETURN_SUCCESS) && (msg->oid != NULL)) {
            rc = noxtls_shake256_update(&ctx, msg->oid, MLDSA_PH_OID_LEN);
        }
    }
    if((rc == NOXTLS_RETURN_SUCCESS) && (msg->msg_len > 0U)) {
        rc = noxtls_shake256_update(&ctx, msg->msg, msg->msg_len);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_final(&ctx);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_squeeze(&ctx, mu, NOXTLS_MLDSA_MUBYTES);
    }
    noxtls_secure_zero(&ctx, sizeof(ctx));
    return rc;
}

/**
 * @brief Common signing path.
 * @return See noxtls_mldsa_sign_ex.
 */
static noxtls_return_t mldsa_sign_common(noxtls_mldsa_param_t param,
                                         const uint8_t *secret_key,
                                         const mldsa_message_t *msg,
                                         const uint8_t *rnd,
                                         uint8_t *signature,
                                         uint32_t *signature_len,
                                         void *ws, uint32_t ws_len)
{
    noxtls_mldsa_param_spec_t spec;
    noxtls_mldsa_poly_t *work = NULL;
    uint32_t owned = 0U;
    uint8_t mu[NOXTLS_MLDSA_MUBYTES];
    uint8_t rnd_buf[NOXTLS_MLDSA_RND_LEN];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((secret_key == NULL) || (signature == NULL) || (signature_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(noxtls_mldsa_internal_get_param_spec(param, &spec) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(*signature_len < spec.signature_len) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(rnd != NULL) {
        noxtls_copy_u8(rnd_buf, sizeof(rnd_buf), rnd, NOXTLS_MLDSA_RND_LEN);
        rc = NOXTLS_RETURN_SUCCESS;
    } else {
        rc = mldsa_random32(rnd_buf);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = mldsa_compute_mu(&secret_key[2U * NOXTLS_MLDSA_SEEDBYTES], msg, mu);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = mldsa_ws_acquire(&spec, MLDSA_OP_SIGN, ws, ws_len, &work, &owned);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_mldsa_backend_sign(&spec, secret_key, mu, rnd_buf, signature, work);
    }
    mldsa_ws_release(&spec, MLDSA_OP_SIGN, work, owned);
    noxtls_secure_zero(mu, sizeof(mu));
    noxtls_secure_zero(rnd_buf, sizeof(rnd_buf));
    if(rc == NOXTLS_RETURN_SUCCESS) {
        *signature_len = spec.signature_len;
    }
    return rc;
}

/**
 * @brief Common verification path.
 * @return See noxtls_mldsa_verify_ex.
 */
static noxtls_return_t mldsa_verify_common(noxtls_mldsa_param_t param,
                                           const uint8_t *public_key,
                                           const mldsa_message_t *msg,
                                           const uint8_t *signature,
                                           uint32_t signature_len,
                                           void *ws, uint32_t ws_len)
{
    noxtls_mldsa_param_spec_t spec;
    noxtls_mldsa_poly_t *work = NULL;
    uint32_t owned = 0U;
    uint8_t tr[NOXTLS_MLDSA_TRBYTES];
    uint8_t mu[NOXTLS_MLDSA_MUBYTES];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((public_key == NULL) || (signature == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(noxtls_mldsa_internal_get_param_spec(param, &spec) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(signature_len != spec.signature_len) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    rc = noxtls_mldsa_shake256(tr, NOXTLS_MLDSA_TRBYTES, public_key, spec.public_key_len, NULL, 0U);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = mldsa_compute_mu(tr, msg, mu);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = mldsa_ws_acquire(&spec, MLDSA_OP_VERIFY, ws, ws_len, &work, &owned);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_mldsa_backend_verify(&spec, public_key, mu, signature, work);
    }
    mldsa_ws_release(&spec, MLDSA_OP_VERIFY, work, owned);
    return rc;
}

/**
 * @brief Validate (msg, ctx) arguments and fill a pure / pre-hash message description.
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL or NOXTLS_RETURN_INVALID_PARAM.
 */
static noxtls_return_t mldsa_message_init(mldsa_message_t *m,
                                          uint8_t domain,
                                          const uint8_t *oid,
                                          const uint8_t *msg, uint32_t msg_len,
                                          const uint8_t *ctx, uint32_t ctx_len)
{
    if((msg == NULL) && (msg_len != 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    if((ctx == NULL) && (ctx_len != 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx_len > NOXTLS_MLDSA_MAX_CONTEXT_LEN) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    m->has_prefix = 1U;
    m->domain = domain;
    m->ctx = ctx;
    m->ctx_len = ctx_len;
    m->oid = oid;
    m->msg = msg;
    m->msg_len = msg_len;
    m->external_mu = 0U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Legacy test hook; intentionally a no-op.
 *
 * Deterministic key generation is available through noxtls_mldsa_keygen_ex()
 * with an explicit seed, so no global state is consulted by key generation.
 *
 * @param[in] bytes Ignored.
 * @param[in] byte_len Ignored.
 */
void noxtls_mldsa_set_test_seed_sequence(const uint8_t *bytes, uint32_t byte_len)
{
    (void)bytes;
    (void)byte_len;
}

/**
 * @brief Legacy test hook; intentionally a no-op.
 *
 * Signing never consults global overrides (they could silently weaken
 * production signatures). Use noxtls_mldsa_sign_ex() (context and rnd),
 * noxtls_mldsa_hash_sign_ex() or noxtls_mldsa_sign_internal() (M' / external
 * mu) for vector harnesses.
 *
 * @param[in] pre Ignored.
 * @param[in] pre_len Ignored.
 * @param[in] rnd Ignored.
 * @param[in] rnd_len Ignored.
 * @param[in] externalmu Ignored.
 */
void noxtls_mldsa_set_test_signing_overrides(const uint8_t *pre,
                                             uint32_t pre_len,
                                             const uint8_t *rnd,
                                             uint32_t rnd_len,
                                             uint8_t externalmu)
{
    (void)pre;
    (void)pre_len;
    (void)rnd;
    (void)rnd_len;
    (void)externalmu;
}

/**
 * @brief ML-DSA.KeyGen with an optional explicit seed and caller workspace.
 *
 * @param[in] param Parameter set.
 * @param[in] seed 32-byte seed xi (KeyGen_internal), or NULL to draw it from the DRBG.
 * @param[out] public_key Public key (noxtls_mldsa_public_key_len bytes).
 * @param[out] secret_key Secret key (noxtls_mldsa_secret_key_len bytes).
 * @param[in] ws Workspace (>= 3 KiB, 4-byte aligned) or NULL to allocate internally.
 * @param[in] ws_len Workspace length in bytes.
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM,
 *         NOXTLS_RETURN_INVALID_BLOCK_SIZE, NOXTLS_RETURN_NOT_ENOUGH_MEMORY or a DRBG error.
 */
noxtls_return_t noxtls_mldsa_keygen_ex(noxtls_mldsa_param_t param,
                                       const uint8_t *seed,
                                       uint8_t *public_key,
                                       uint8_t *secret_key,
                                       void *ws,
                                       uint32_t ws_len)
{
    noxtls_mldsa_param_spec_t spec;
    noxtls_mldsa_poly_t *work = NULL;
    uint32_t owned = 0U;
    uint8_t xi[NOXTLS_MLDSA_SEEDBYTES];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((public_key == NULL) || (secret_key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(noxtls_mldsa_internal_get_param_spec(param, &spec) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(seed != NULL) {
        noxtls_copy_u8(xi, sizeof(xi), seed, NOXTLS_MLDSA_SEEDBYTES);
        rc = NOXTLS_RETURN_SUCCESS;
    } else {
        rc = mldsa_random32(xi);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = mldsa_ws_acquire(&spec, MLDSA_OP_KEYGEN, ws, ws_len, &work, &owned);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_mldsa_backend_keygen(&spec, xi, public_key, secret_key, work);
    }
    mldsa_ws_release(&spec, MLDSA_OP_KEYGEN, work, owned);
    noxtls_secure_zero(xi, sizeof(xi));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(secret_key, spec.secret_key_len);
    }
    return rc;
}

/**
 * @brief Generate an ML-DSA key pair with a DRBG-derived seed.
 *
 * @param[in] param Parameter set.
 * @param[out] public_key Public key buffer.
 * @param[out] secret_key Secret key buffer.
 * @return See noxtls_mldsa_keygen_ex.
 */
noxtls_return_t noxtls_mldsa_keygen(noxtls_mldsa_param_t param, uint8_t *public_key, uint8_t *secret_key)
{
    return noxtls_mldsa_keygen_ex(param, NULL, public_key, secret_key, NULL, 0U);
}

/**
 * @brief ML-DSA.Sign (pure) with context string, optional rnd and caller workspace.
 *
 * @param[in] param Parameter set.
 * @param[in] secret_key Encoded secret key.
 * @param[in] message Message (may be NULL when message_len is 0).
 * @param[in] message_len Message length.
 * @param[in] ctx Context string (may be NULL when ctx_len is 0).
 * @param[in] ctx_len Context length (<= 255).
 * @param[in] rnd 32-byte randomness; NULL = hedged (DRBG); 32 zero bytes = deterministic variant.
 * @param[out] signature Signature buffer.
 * @param[in,out] signature_len In: capacity; out: noxtls_mldsa_signature_len().
 * @param[in] ws Workspace (noxtls_mldsa_workspace_len bytes, 4-byte aligned) or NULL.
 * @param[in] ws_len Workspace length.
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM,
 *         NOXTLS_RETURN_INVALID_BLOCK_SIZE, NOXTLS_RETURN_NOT_ENOUGH_MEMORY,
 *         NOXTLS_RETURN_FAILED or a DRBG error.
 */
noxtls_return_t noxtls_mldsa_sign_ex(noxtls_mldsa_param_t param,
                                     const uint8_t *secret_key,
                                     const uint8_t *message,
                                     uint32_t message_len,
                                     const uint8_t *ctx,
                                     uint32_t ctx_len,
                                     const uint8_t *rnd,
                                     uint8_t *signature,
                                     uint32_t *signature_len,
                                     void *ws,
                                     uint32_t ws_len)
{
    mldsa_message_t m;
    noxtls_return_t rc = mldsa_message_init(&m, 0U, NULL, message, message_len, ctx, ctx_len);

    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return mldsa_sign_common(param, secret_key, &m, rnd, signature, signature_len, ws, ws_len);
}

/**
 * @brief Sign with pure ML-DSA, empty context and hedged randomness.
 *
 * @param[in] param Parameter set.
 * @param[in] secret_key Encoded secret key.
 * @param[in] noxtls_message Message.
 * @param[in] message_len Message length.
 * @param[out] signature Signature buffer.
 * @param[in,out] signature_len In: capacity; out: signature length.
 * @return See noxtls_mldsa_sign_ex.
 */
noxtls_return_t noxtls_mldsa_sign(noxtls_mldsa_param_t param,
                                  const uint8_t *secret_key,
                                  const uint8_t *noxtls_message,
                                  uint32_t message_len,
                                  uint8_t *signature,
                                  uint32_t *signature_len)
{
    return noxtls_mldsa_sign_ex(param, secret_key, noxtls_message, message_len, NULL, 0U, NULL,
                                signature, signature_len, NULL, 0U);
}

/**
 * @brief ML-DSA.Verify (pure) with context string and caller workspace.
 *
 * @param[in] param Parameter set.
 * @param[in] public_key Encoded public key.
 * @param[in] message Message.
 * @param[in] message_len Message length.
 * @param[in] ctx Context string.
 * @param[in] ctx_len Context length (<= 255).
 * @param[in] signature Signature.
 * @param[in] signature_len Signature length (must equal noxtls_mldsa_signature_len()).
 * @param[in] ws Workspace ((l + 3) KiB, 4-byte aligned) or NULL.
 * @param[in] ws_len Workspace length.
 * @return NOXTLS_RETURN_SUCCESS if valid, NOXTLS_RETURN_FAILED if invalid,
 *         NOXTLS_RETURN_INVALID_PARAM for a wrong length / parameter, or another error.
 */
noxtls_return_t noxtls_mldsa_verify_ex(noxtls_mldsa_param_t param,
                                       const uint8_t *public_key,
                                       const uint8_t *message,
                                       uint32_t message_len,
                                       const uint8_t *ctx,
                                       uint32_t ctx_len,
                                       const uint8_t *signature,
                                       uint32_t signature_len,
                                       void *ws,
                                       uint32_t ws_len)
{
    mldsa_message_t m;
    noxtls_return_t rc = mldsa_message_init(&m, 0U, NULL, message, message_len, ctx, ctx_len);

    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return mldsa_verify_common(param, public_key, &m, signature, signature_len, ws, ws_len);
}

/**
 * @brief Verify a pure ML-DSA signature with an empty context.
 *
 * @param[in] param Parameter set.
 * @param[in] public_key Encoded public key.
 * @param[in] noxtls_message Message.
 * @param[in] message_len Message length.
 * @param[in] signature Signature.
 * @param[in] signature_len Signature length.
 * @return See noxtls_mldsa_verify_ex.
 */
noxtls_return_t noxtls_mldsa_verify(noxtls_mldsa_param_t param,
                                    const uint8_t *public_key,
                                    const uint8_t *noxtls_message,
                                    uint32_t message_len,
                                    const uint8_t *signature,
                                    uint32_t signature_len)
{
    return noxtls_mldsa_verify_ex(param, public_key, noxtls_message, message_len, NULL, 0U,
                                  signature, signature_len, NULL, 0U);
}

/**
 * @brief HashML-DSA.Sign over a caller-computed digest PH(M).
 *
 * @param[in] param Parameter set.
 * @param[in] secret_key Encoded secret key.
 * @param[in] ph Pre-hash algorithm (NOXTLS_MLDSA_PH_*).
 * @param[in] digest PH(M) (SHAKE128: 32 bytes, SHAKE256: 64 bytes).
 * @param[in] digest_len Digest length; must match the algorithm.
 * @param[in] ctx Context string.
 * @param[in] ctx_len Context length (<= 255).
 * @param[in] rnd 32-byte randomness or NULL (hedged).
 * @param[out] signature Signature buffer.
 * @param[in,out] signature_len In: capacity; out: signature length.
 * @param[in] ws Workspace or NULL.
 * @param[in] ws_len Workspace length.
 * @return As noxtls_mldsa_sign_ex, plus NOXTLS_RETURN_INVALID_ALGORITHM for an unknown ph.
 */
noxtls_return_t noxtls_mldsa_hash_sign_ex(noxtls_mldsa_param_t param,
                                          const uint8_t *secret_key,
                                          noxtls_mldsa_prehash_t ph,
                                          const uint8_t *digest,
                                          uint32_t digest_len,
                                          const uint8_t *ctx,
                                          uint32_t ctx_len,
                                          const uint8_t *rnd,
                                          uint8_t *signature,
                                          uint32_t *signature_len,
                                          void *ws,
                                          uint32_t ws_len)
{
    mldsa_message_t m;
    uint8_t oid[MLDSA_PH_OID_LEN];
    uint32_t expected = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(digest == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    rc = mldsa_prehash_info(ph, oid, &expected);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(digest_len != expected) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    rc = mldsa_message_init(&m, 1U, oid, digest, digest_len, ctx, ctx_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return mldsa_sign_common(param, secret_key, &m, rnd, signature, signature_len, ws, ws_len);
}

/**
 * @brief HashML-DSA.Verify over a caller-computed digest PH(M).
 *
 * @param[in] param Parameter set.
 * @param[in] public_key Encoded public key.
 * @param[in] ph Pre-hash algorithm (NOXTLS_MLDSA_PH_*).
 * @param[in] digest PH(M).
 * @param[in] digest_len Digest length; must match the algorithm.
 * @param[in] ctx Context string.
 * @param[in] ctx_len Context length (<= 255).
 * @param[in] signature Signature.
 * @param[in] signature_len Signature length.
 * @param[in] ws Workspace or NULL.
 * @param[in] ws_len Workspace length.
 * @return As noxtls_mldsa_verify_ex, plus NOXTLS_RETURN_INVALID_ALGORITHM for an unknown ph.
 */
noxtls_return_t noxtls_mldsa_hash_verify_ex(noxtls_mldsa_param_t param,
                                            const uint8_t *public_key,
                                            noxtls_mldsa_prehash_t ph,
                                            const uint8_t *digest,
                                            uint32_t digest_len,
                                            const uint8_t *ctx,
                                            uint32_t ctx_len,
                                            const uint8_t *signature,
                                            uint32_t signature_len,
                                            void *ws,
                                            uint32_t ws_len)
{
    mldsa_message_t m;
    uint8_t oid[MLDSA_PH_OID_LEN];
    uint32_t expected = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(digest == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    rc = mldsa_prehash_info(ph, oid, &expected);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(digest_len != expected) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    rc = mldsa_message_init(&m, 1U, oid, digest, digest_len, ctx, ctx_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return mldsa_verify_common(param, public_key, &m, signature, signature_len, ws, ws_len);
}

/**
 * @brief ML-DSA.Sign_internal: sign the formatted message M' directly, or an
 *        externally computed mu (external_mu != 0, mprime_len must be 64).
 *
 * @param[in] param Parameter set.
 * @param[in] secret_key Encoded secret key.
 * @param[in] mprime M' (or mu).
 * @param[in] mprime_len Length of mprime.
 * @param[in] external_mu Non-zero when mprime is mu.
 * @param[in] rnd 32-byte randomness or NULL (hedged).
 * @param[out] signature Signature buffer.
 * @param[in,out] signature_len In: capacity; out: signature length.
 * @param[in] ws Workspace or NULL.
 * @param[in] ws_len Workspace length.
 * @return As noxtls_mldsa_sign_ex.
 */
noxtls_return_t noxtls_mldsa_sign_internal(noxtls_mldsa_param_t param,
                                           const uint8_t *secret_key,
                                           const uint8_t *mprime,
                                           uint32_t mprime_len,
                                           uint8_t external_mu,
                                           const uint8_t *rnd,
                                           uint8_t *signature,
                                           uint32_t *signature_len,
                                           void *ws,
                                           uint32_t ws_len)
{
    mldsa_message_t m;

    if((mprime == NULL) && (mprime_len != 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    if((external_mu != 0U) && ((mprime == NULL) || (mprime_len != NOXTLS_MLDSA_MUBYTES))) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    noxtls_secure_zero(&m, sizeof(m));
    m.msg = mprime;
    m.msg_len = mprime_len;
    m.external_mu = (external_mu != 0U) ? 1U : 0U;
    return mldsa_sign_common(param, secret_key, &m, rnd, signature, signature_len, ws, ws_len);
}

/**
 * @brief ML-DSA.Verify_internal over M' (or an external mu).
 *
 * @param[in] param Parameter set.
 * @param[in] public_key Encoded public key.
 * @param[in] mprime M' (or mu).
 * @param[in] mprime_len Length of mprime.
 * @param[in] external_mu Non-zero when mprime is mu.
 * @param[in] signature Signature.
 * @param[in] signature_len Signature length.
 * @param[in] ws Workspace or NULL.
 * @param[in] ws_len Workspace length.
 * @return As noxtls_mldsa_verify_ex.
 */
noxtls_return_t noxtls_mldsa_verify_internal(noxtls_mldsa_param_t param,
                                             const uint8_t *public_key,
                                             const uint8_t *mprime,
                                             uint32_t mprime_len,
                                             uint8_t external_mu,
                                             const uint8_t *signature,
                                             uint32_t signature_len,
                                             void *ws,
                                             uint32_t ws_len)
{
    mldsa_message_t m;

    if((mprime == NULL) && (mprime_len != 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    if((external_mu != 0U) && ((mprime == NULL) || (mprime_len != NOXTLS_MLDSA_MUBYTES))) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    noxtls_secure_zero(&m, sizeof(m));
    m.msg = mprime;
    m.msg_len = mprime_len;
    m.external_mu = (external_mu != 0U) ? 1U : 0U;
    return mldsa_verify_common(param, public_key, &m, signature, signature_len, ws, ws_len);
}

#endif /* NOXTLS_FEATURE_ML_DSA */
