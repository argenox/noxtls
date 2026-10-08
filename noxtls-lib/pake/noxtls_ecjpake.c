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
* File:    noxtls_ecjpake.c
* Summary: EC-JPAKE exchange state machine and TLS message encoding
*
*
*****************************************************************************/

/**
 * @file noxtls_ecjpake.c
 * @brief EC-JPAKE rounds, premaster derivation and random scalars.
 * @ingroup noxtls_ecjpake
 *
 * RFC 8236 section 3.2 (two-round EC J-PAKE) in the TLS form of
 * draft-cragie-tls-ecjpake-01: round one in the ecjpake_key_kp_pair
 * extension (section 7.2.2), round two in ServerKeyExchange (section 7.3)
 * and ClientKeyExchange (section 7.4), calculations of section 8.
 */

#include <stdint.h>

#include "noxtls_ecjpake_internal.h"
#include "drbg/noxtls_drbg.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "common/noxtls_ct.h"

/** @brief DRBG security strength used for EC-JPAKE secrets (256-bit, NIST SP 800-90A table 3). */
#define NOXTLS_ECJPAKE_DRBG_TYPE (DRBG_AES256)
/** @brief Entropy input for DRBG instantiation: AES-256 CTR_DRBG seedlen (48 octets). */
#define NOXTLS_ECJPAKE_DRBG_SEED_SIZE (48U)
/** @brief Bits per byte, for drbg_generate() requests. */
#define NOXTLS_ECJPAKE_BITS_PER_BYTE (8U)
/** @brief Offset of the X coordinate in an uncompressed encoding. */
#define NOXTLS_ECJPAKE_X_OFFSET (1U)
/** @brief Mask selecting one byte. */
#define NOXTLS_ECJPAKE_BYTE_MASK (0xFFU)
/** @brief Bits in one byte shift, for big-endian 16-bit fields. */
#define NOXTLS_ECJPAKE_BYTE_SHIFT (8U)
/** @brief Progress flags required before round two. */
#define NOXTLS_ECJPAKE_FLAGS_ROUND_ONE (NOXTLS_ECJPAKE_FLAG_OWN_ROUND_ONE | NOXTLS_ECJPAKE_FLAG_PEER_ROUND_ONE)
/** @brief Progress flags required before the premaster secret. */
#define NOXTLS_ECJPAKE_FLAGS_ROUND_TWO (NOXTLS_ECJPAKE_FLAG_OWN_ROUND_TWO | NOXTLS_ECJPAKE_FLAG_PEER_ROUND_TWO)

/** @brief P-256 generator G (SEC 2 v2.0 section 2.4.2), uncompressed encoding. */
static const uint8_t s_ecjpake_generator[NOXTLS_ECJPAKE_POINT_SIZE] = {
    0x04U,
    0x6BU, 0x17U, 0xD1U, 0xF2U, 0xE1U, 0x2CU, 0x42U, 0x47U,
    0xF8U, 0xBCU, 0xE6U, 0xE5U, 0x63U, 0xA4U, 0x40U, 0xF2U,
    0x77U, 0x03U, 0x7DU, 0x81U, 0x2DU, 0xEBU, 0x33U, 0xA0U,
    0xF4U, 0xA1U, 0x39U, 0x45U, 0xD8U, 0x98U, 0xC2U, 0x96U,
    0x4FU, 0xE3U, 0x42U, 0xE2U, 0xFEU, 0x1AU, 0x7FU, 0x9BU,
    0x8EU, 0xE7U, 0xEBU, 0x4AU, 0x7CU, 0x0FU, 0x9EU, 0x16U,
    0x2BU, 0xCEU, 0x33U, 0x57U, 0x6BU, 0x31U, 0x5EU, 0xCEU,
    0xCBU, 0xB6U, 0x40U, 0x68U, 0x37U, 0xBFU, 0x51U, 0xF5U
};

/** @brief Client identity (draft-cragie-tls-ecjpake-01 section 8.1). */
static const uint8_t s_ecjpake_id_client[NOXTLS_ECJPAKE_ID_LEN] = {
    0x63U, 0x6CU, 0x69U, 0x65U, 0x6EU, 0x74U
};

/** @brief Server identity (draft-cragie-tls-ecjpake-01 section 8.1). */
static const uint8_t s_ecjpake_id_server[NOXTLS_ECJPAKE_ID_LEN] = {
    0x73U, 0x65U, 0x72U, 0x76U, 0x65U, 0x72U
};

/** @brief Optional test override of the random source (NULL selects the DRBG). */
static noxtls_ecjpake_random_cb_t s_ecjpake_random_cb = NULL;

/** @brief Opaque pointer passed to s_ecjpake_random_cb. */
static void *s_ecjpake_random_user = NULL;

/** @brief Module DRBG instance for EC-JPAKE secrets. */
static drbg_state_t s_ecjpake_drbg;

/** @brief Non-zero once s_ecjpake_drbg has been instantiated. */
static uint32_t s_ecjpake_drbg_ready = 0U;

void noxtls_ecjpake_set_random_source(noxtls_ecjpake_random_cb_t cb, void *user)
{
    s_ecjpake_random_cb = cb;
    s_ecjpake_random_user = user;

    /* Drop the module DRBG so the next draw re-seeds from the entropy source. */
    if (s_ecjpake_drbg_ready != 0U) {
        (void)noxtls_drbg_uninstantiate(&s_ecjpake_drbg);
        s_ecjpake_drbg_ready = 0U;
    }
}

/**
 * @brief Fill out with random octets from the override or from the module DRBG.
 * @internal
 *
 * @param[out] out Destination.
 * @param[in] len Number of octets.
 *
 * @return NOXTLS_RETURN_SUCCESS or an entropy / DRBG error (out erased).
 */
static noxtls_return_t noxtls_ecjpake_random_bytes(uint8_t *out, uint32_t len)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if (s_ecjpake_random_cb != NULL) {
        rc = s_ecjpake_random_cb(s_ecjpake_random_user, out, len);
    } else {
        if (s_ecjpake_drbg_ready == 0U) {
            uint8_t seed[NOXTLS_ECJPAKE_DRBG_SEED_SIZE];

            rc = noxtls_drbg_get_entropy(seed, NOXTLS_ECJPAKE_DRBG_SEED_SIZE);
            if (rc == NOXTLS_RETURN_SUCCESS) {
                rc = drbg_instantiate(&s_ecjpake_drbg, NOXTLS_ECJPAKE_DRBG_TYPE,
                                      seed, NOXTLS_ECJPAKE_DRBG_SEED_SIZE, NULL, 0U, NULL, 0U);
            }

            noxtls_secure_zero(seed, sizeof(seed));
            s_ecjpake_drbg_ready = (rc == NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
        }

        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = drbg_generate(&s_ecjpake_drbg, out, len * NOXTLS_ECJPAKE_BITS_PER_BYTE, NULL, 0U);
            if (rc != NOXTLS_RETURN_SUCCESS) {
                /* A failed generate may leave the state unusable: re-seed next time. */
                (void)noxtls_drbg_uninstantiate(&s_ecjpake_drbg);
                s_ecjpake_drbg_ready = 0U;
            }
        }
    }

    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(out, len);
    }

    return rc;
}

noxtls_return_t noxtls_ecjpake_random_scalar(uint8_t out[NOXTLS_ECJPAKE_SCALAR_SIZE])
{
    uint8_t seed[NOXTLS_ECJPAKE_RANDOM_SEED_SIZE];
    uint32_t attempt = 0U;
    uint32_t done = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if (out == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    /* RFC 8236 section 3.2 / RFC 8235 section 3.2: uniform in [1, n-1]. 320 random
     * bits reduced modulo n (FIPS 186-5 Appendix A.2.1); a zero result is redrawn. */
    while ((done == 0U) && (attempt < NOXTLS_ECJPAKE_MAX_RANDOM_RETRIES)) {
        ++attempt;
        rc = noxtls_ecjpake_random_bytes(seed, NOXTLS_ECJPAKE_RANDOM_SEED_SIZE);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            done = 1U;
        } else {
            noxtls_ecjpake_scalar_reduce(seed, NOXTLS_ECJPAKE_RANDOM_SEED_SIZE, out);
            done = noxtls_ecjpake_scalar_is_valid(out);
            rc = (done != 0U) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
        }
    }

    noxtls_secure_zero(seed, sizeof(seed));
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(out, NOXTLS_ECJPAKE_SCALAR_SIZE);
    }

    return rc;
}

/**
 * @brief Return the ZKP identity of the local or peer role (draft section 8.1).
 * @internal
 *
 * @param[in] ctx Context.
 * @param[in] peer Non-zero for the peer identity.
 *
 * @return Pointer to NOXTLS_ECJPAKE_ID_LEN identity octets.
 */
static const uint8_t *noxtls_ecjpake_id(const noxtls_ecjpake_ctx_t *ctx, uint32_t peer)
{
    uint32_t is_client = (ctx->role == NOXTLS_ECJPAKE_ROLE_CLIENT) ? 1U : 0U;

    return ((is_client ^ peer) != 0U) ? s_ecjpake_id_client : s_ecjpake_id_server;
}

/**
 * @brief Erase every secret and mark the context FAILED.
 * @internal
 *
 * @param[in,out] ctx Context.
 */
static void noxtls_ecjpake_fail(noxtls_ecjpake_ctx_t *ctx)
{
    noxtls_ecjpake_role_t role = ctx->role;

    noxtls_secure_zero(ctx, sizeof(*ctx));
    ctx->role = role;
    ctx->state = NOXTLS_ECJPAKE_STATE_FAILED;
}

/**
 * @brief Check that the context is ACTIVE and its progress flags match.
 * @internal
 *
 * @param[in] ctx Context.
 * @param[in] required Flags that must be set.
 * @param[in] forbidden Flags that must be clear.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_NOT_INITIALIZED.
 */
static noxtls_return_t noxtls_ecjpake_check_state(const noxtls_ecjpake_ctx_t *ctx,
                                                  uint32_t required, uint32_t forbidden)
{
    if ((ctx->state != NOXTLS_ECJPAKE_STATE_ACTIVE) ||
        ((ctx->flags & required) != required) || ((ctx->flags & forbidden) != 0U)) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }

    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_ecjpake_init(noxtls_ecjpake_ctx_t *ctx,
                                    noxtls_ecjpake_role_t role,
                                    const uint8_t *password,
                                    uint32_t password_len)
{
    if ((ctx == NULL) || (password == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero(ctx, sizeof(*ctx));
    if (((role != NOXTLS_ECJPAKE_ROLE_CLIENT) && (role != NOXTLS_ECJPAKE_ROLE_SERVER)) ||
        (password_len < NOXTLS_ECJPAKE_PASSWORD_MIN_LEN) ||
        (password_len > NOXTLS_ECJPAKE_PASSWORD_MAX_LEN)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    /* draft-cragie-tls-ecjpake-01 section 8.3: s = int(password) mod n. s = 0
     * would make round two independent of the password, so it is refused. */
    noxtls_ecjpake_scalar_reduce(password, password_len, ctx->s);
    if (noxtls_ecjpake_scalar_is_valid(ctx->s) == 0U) {
        noxtls_secure_zero(ctx, sizeof(*ctx));
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    ctx->role = role;
    ctx->state = NOXTLS_ECJPAKE_STATE_ACTIVE;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Generate one round-one key pair with its ZKP and append the ECJPAKEKeyKP.
 * @internal
 *
 * @param[in,out] ctx Context (own identity).
 * @param[out] x Private key in [1, n-1].
 * @param[out] X Public key G*x.
 * @param[in,out] offset Write position in ctx->round_one.
 *
 * @return NOXTLS_RETURN_SUCCESS or an error code.
 */
static noxtls_return_t noxtls_ecjpake_generate_key_kp(noxtls_ecjpake_ctx_t *ctx,
                                                      uint8_t x[NOXTLS_ECJPAKE_SCALAR_SIZE],
                                                      uint8_t X[NOXTLS_ECJPAKE_POINT_SIZE],
                                                      uint32_t *offset)
{
    noxtls_ecjpake_key_kp_t kp;
    uint8_t v[NOXTLS_ECJPAKE_SCALAR_SIZE];
    uint32_t written = 0U;
    noxtls_return_t rc;

    /* draft section 8.4.1: x in [1, n-1], X = G*x; section 8.4.2: ZKP with generator G. */
    rc = noxtls_ecjpake_random_scalar(x);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecjpake_point_mul(x, NULL, X);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecjpake_random_scalar(v);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecjpake_zkp_prove(s_ecjpake_generator, x, X, v,
                                      noxtls_ecjpake_id(ctx, 0U), NOXTLS_ECJPAKE_ID_LEN, &kp);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecjpake_kp_write(&kp, &ctx->round_one[*offset],
                                     NOXTLS_ECJPAKE_ROUND_ONE_MAX_SIZE - *offset, &written);
        *offset += written;
    }

    noxtls_secure_zero(v, sizeof(v));
    noxtls_secure_zero(&kp, sizeof(kp));
    return rc;
}

noxtls_return_t noxtls_ecjpake_write_round_one(noxtls_ecjpake_ctx_t *ctx,
                                               uint8_t *out,
                                               uint32_t out_size,
                                               uint32_t *out_len)
{
    uint32_t offset = 0U;
    noxtls_return_t rc;

    if ((ctx == NULL) || (out == NULL) || (out_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_ecjpake_check_state(ctx, 0U, 0U);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if ((ctx->flags & NOXTLS_ECJPAKE_FLAG_OWN_ROUND_ONE) == 0U) {
        rc = noxtls_ecjpake_generate_key_kp(ctx, ctx->xm1, ctx->Xm1, &offset);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_ecjpake_generate_key_kp(ctx, ctx->xm2, ctx->Xm2, &offset);
        }

        if (rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_ecjpake_fail(ctx);
            return rc;
        }

        ctx->round_one_len = offset;
        ctx->flags |= NOXTLS_ECJPAKE_FLAG_OWN_ROUND_ONE;
    }

    /* The same octets are returned on every call (RFC 6347 section 4.2.1 resend). */
    if (out_size < ctx->round_one_len) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    noxtls_copy_u8(out, out_size, ctx->round_one, ctx->round_one_len);
    *out_len = ctx->round_one_len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Parse one ECJPAKEKeyKP and verify its ZKP for a given generator and identity.
 * @internal
 *
 * @param[in] in Input.
 * @param[in] in_len Octets available.
 * @param[in,out] offset Read position.
 * @param[in] gen Generator encoding.
 * @param[in] id Prover identity.
 * @param[out] X Verified public value.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR or
 *         NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER.
 */
static noxtls_return_t noxtls_ecjpake_read_key_kp(const uint8_t *in, uint32_t in_len, uint32_t *offset,
                                                  const uint8_t gen[NOXTLS_ECJPAKE_POINT_SIZE],
                                                  const uint8_t *id,
                                                  uint8_t X[NOXTLS_ECJPAKE_POINT_SIZE])
{
    noxtls_ecjpake_key_kp_t kp;
    uint32_t used = 0U;
    noxtls_return_t rc;

    rc = noxtls_ecjpake_kp_read(&in[*offset], in_len - *offset, &kp, &used);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecjpake_zkp_verify(gen, &kp, id, NOXTLS_ECJPAKE_ID_LEN);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_copy_u8(X, NOXTLS_ECJPAKE_POINT_SIZE, kp.X, NOXTLS_ECJPAKE_POINT_SIZE);
        *offset += used;
    }

    noxtls_secure_zero(&kp, sizeof(kp));
    return rc;
}

noxtls_return_t noxtls_ecjpake_read_round_one(noxtls_ecjpake_ctx_t *ctx,
                                              const uint8_t *in,
                                              uint32_t in_len)
{
    uint32_t offset = 0U;
    const uint8_t *peer_id;
    noxtls_return_t rc;

    if ((ctx == NULL) || (in == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_ecjpake_check_state(ctx, 0U, NOXTLS_ECJPAKE_FLAG_PEER_ROUND_ONE);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    /* draft section 7.2.2 (identity elided) and section 8.4.3 (ZKP over G, peer identity). */
    peer_id = noxtls_ecjpake_id(ctx, 1U);
    rc = noxtls_ecjpake_read_key_kp(in, in_len, &offset, s_ecjpake_generator, peer_id, ctx->Xp1);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecjpake_read_key_kp(in, in_len, &offset, s_ecjpake_generator, peer_id, ctx->Xp2);
    }

    if ((rc == NOXTLS_RETURN_SUCCESS) && (offset != in_len)) {
        rc = NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR;
    }

    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_ecjpake_fail(ctx);
        return rc;
    }

    ctx->flags |= NOXTLS_ECJPAKE_FLAG_PEER_ROUND_ONE;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Compute the round-two generator first + second + third (RFC 8236 section 3.2).
 * @internal
 *
 * @param[in] first First point.
 * @param[in] second Second point.
 * @param[in] third Third point.
 * @param[out] gen Sum; must not be the identity.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER for the
 *         identity, or an ECC error.
 */
static noxtls_return_t noxtls_ecjpake_round_two_generator(const uint8_t first[NOXTLS_ECJPAKE_POINT_SIZE],
                                                          const uint8_t second[NOXTLS_ECJPAKE_POINT_SIZE],
                                                          const uint8_t third[NOXTLS_ECJPAKE_POINT_SIZE],
                                                          uint8_t gen[NOXTLS_ECJPAKE_POINT_SIZE])
{
    uint8_t partial[NOXTLS_ECJPAKE_POINT_SIZE];
    noxtls_return_t rc;

    rc = noxtls_ecjpake_point_add(first, second, 0U, partial);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecjpake_point_add(partial, third, 0U, gen);
    }

    /* RFC 8236 section 3.2: the new generators must not be the point at infinity. */
    if ((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_ecjpake_point_is_identity(gen) != 0U)) {
        rc = NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
    }

    return rc;
}

noxtls_return_t noxtls_ecjpake_write_round_two(noxtls_ecjpake_ctx_t *ctx,
                                               uint8_t *out,
                                               uint32_t out_size,
                                               uint32_t *out_len)
{
    noxtls_ecjpake_key_kp_t kp;
    uint8_t gen[NOXTLS_ECJPAKE_POINT_SIZE];
    uint8_t xs[NOXTLS_ECJPAKE_SCALAR_SIZE];
    uint8_t v[NOXTLS_ECJPAKE_SCALAR_SIZE];
    uint8_t X[NOXTLS_ECJPAKE_POINT_SIZE];
    uint32_t offset = 0U;
    uint32_t written = 0U;
    uint32_t needed;
    noxtls_return_t rc;

    if ((ctx == NULL) || (out == NULL) || (out_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_ecjpake_check_state(ctx, NOXTLS_ECJPAKE_FLAGS_ROUND_ONE, NOXTLS_ECJPAKE_FLAG_OWN_ROUND_TWO);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    needed = NOXTLS_ECJPAKE_KEY_KP_MAX_SIZE;
    if (ctx->role == NOXTLS_ECJPAKE_ROLE_SERVER) {
        needed += NOXTLS_ECJPAKE_EC_PARAMETERS_SIZE;
    }

    if (out_size < needed) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    /* draft section 8.5.1 (server GB = X1 + X2 + X3) and 8.6.1 (client GA = X1 + X3 + X4):
     * own first key plus both peer keys. xs = x2*s (client) or x4*s (server). */
    rc = noxtls_ecjpake_round_two_generator(ctx->Xm1, ctx->Xp1, ctx->Xp2, gen);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_ecjpake_scalar_mul(ctx->xm2, ctx->s, xs);
        rc = noxtls_ecjpake_point_mul(xs, gen, X);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecjpake_random_scalar(v);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecjpake_zkp_prove(gen, xs, X, v, noxtls_ecjpake_id(ctx, 0U), NOXTLS_ECJPAKE_ID_LEN, &kp);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        if (ctx->role == NOXTLS_ECJPAKE_ROLE_SERVER) {
            /* draft section 7.3: ECParameters { named_curve, secp256r1 } (RFC 4492 section 5.4). */
            out[offset] = (uint8_t)NOXTLS_ECJPAKE_EC_CURVE_TYPE_NAMED_CURVE;
            out[offset + 1U] = (uint8_t)(((uint32_t)NOXTLS_ECJPAKE_NAMED_CURVE_SECP256R1 >> NOXTLS_ECJPAKE_BYTE_SHIFT) &
                                         NOXTLS_ECJPAKE_BYTE_MASK);
            out[offset + 2U] = (uint8_t)((uint32_t)NOXTLS_ECJPAKE_NAMED_CURVE_SECP256R1 & NOXTLS_ECJPAKE_BYTE_MASK);
            offset = NOXTLS_ECJPAKE_EC_PARAMETERS_SIZE;
        }

        rc = noxtls_ecjpake_kp_write(&kp, &out[offset], out_size - offset, &written);
    }

    noxtls_secure_zero(&kp, sizeof(kp));
    noxtls_secure_zero(xs, sizeof(xs));
    noxtls_secure_zero(v, sizeof(v));
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_ecjpake_fail(ctx);
        return rc;
    }

    *out_len = offset + written;
    ctx->flags |= NOXTLS_ECJPAKE_FLAG_OWN_ROUND_TWO;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_ecjpake_read_round_two(noxtls_ecjpake_ctx_t *ctx,
                                              const uint8_t *in,
                                              uint32_t in_len)
{
    uint8_t gen[NOXTLS_ECJPAKE_POINT_SIZE];
    uint32_t offset = 0U;
    noxtls_return_t rc;

    if ((ctx == NULL) || (in == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_ecjpake_check_state(ctx, NOXTLS_ECJPAKE_FLAGS_ROUND_ONE, NOXTLS_ECJPAKE_FLAG_PEER_ROUND_TWO);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if (ctx->role == NOXTLS_ECJPAKE_ROLE_CLIENT) {
        /* draft section 7.3: ServerECJPAKEParams starts with ECParameters. */
        if (in_len < NOXTLS_ECJPAKE_EC_PARAMETERS_SIZE) {
            rc = NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR;
        } else if ((in[0] != (uint8_t)NOXTLS_ECJPAKE_EC_CURVE_TYPE_NAMED_CURVE) ||
                   ((((uint32_t)in[1] << NOXTLS_ECJPAKE_BYTE_SHIFT) | (uint32_t)in[2]) !=
                    NOXTLS_ECJPAKE_NAMED_CURVE_SECP256R1)) {
            rc = NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
        } else {
            offset = NOXTLS_ECJPAKE_EC_PARAMETERS_SIZE;
        }
    }

    /* Peer generator: peer first key plus both own keys (draft sections 8.5.3, 8.6.3). */
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecjpake_round_two_generator(ctx->Xp1, ctx->Xm1, ctx->Xm2, gen);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecjpake_read_key_kp(in, in_len, &offset, gen, noxtls_ecjpake_id(ctx, 1U), ctx->Xp);
    }

    if ((rc == NOXTLS_RETURN_SUCCESS) && (offset != in_len)) {
        rc = NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR;
    }

    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_ecjpake_fail(ctx);
        return rc;
    }

    ctx->flags |= NOXTLS_ECJPAKE_FLAG_PEER_ROUND_TWO;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_ecjpake_derive_premaster(noxtls_ecjpake_ctx_t *ctx,
                                                uint8_t *out,
                                                uint32_t out_size,
                                                uint32_t *out_len)
{
    noxtls_sha_ctx_t sha;
    uint8_t xs[NOXTLS_ECJPAKE_SCALAR_SIZE];
    uint8_t t[NOXTLS_ECJPAKE_POINT_SIZE];
    uint8_t k[NOXTLS_ECJPAKE_POINT_SIZE];
    noxtls_return_t rc;

    if ((ctx == NULL) || (out == NULL) || (out_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_ecjpake_check_state(ctx, NOXTLS_ECJPAKE_FLAGS_ROUND_TWO, 0U);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if (out_size < NOXTLS_ECJPAKE_PREMASTER_SIZE) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    /* draft section 8.7 / RFC 8236 section 3.2: K = (Xp - Xp2*(xm2*s)) * xm2. */
    noxtls_ecjpake_scalar_mul(ctx->xm2, ctx->s, xs);
    rc = noxtls_ecjpake_point_mul(xs, ctx->Xp2, t);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecjpake_point_add(ctx->Xp, t, 1U, k);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecjpake_point_mul(ctx->xm2, k, t);
    }

    if ((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_ecjpake_point_is_identity(t) != 0U)) {
        rc = NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
    }

    /* PMS = SHA-256(str(32, X coordinate of K)). */
    if (rc == NOXTLS_RETURN_SUCCESS) {
        if ((noxtls_sha256_init(&sha, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS) ||
            (noxtls_sha256_update(&sha, &t[NOXTLS_ECJPAKE_X_OFFSET], NOXTLS_ECJPAKE_SCALAR_SIZE) !=
             NOXTLS_RETURN_SUCCESS) ||
            (noxtls_sha256_finish(&sha, out) != NOXTLS_RETURN_SUCCESS)) {
            rc = NOXTLS_RETURN_FAILED;
        }

        noxtls_secure_zero(&sha, sizeof(sha));
    }

    noxtls_secure_zero(xs, sizeof(xs));
    noxtls_secure_zero(t, sizeof(t));
    noxtls_secure_zero(k, sizeof(k));
    if (rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(out, NOXTLS_ECJPAKE_PREMASTER_SIZE);
        noxtls_ecjpake_fail(ctx);
        return rc;
    }

    *out_len = NOXTLS_ECJPAKE_PREMASTER_SIZE;
    noxtls_secure_zero(ctx->s, sizeof(ctx->s));
    noxtls_secure_zero(ctx->xm1, sizeof(ctx->xm1));
    noxtls_secure_zero(ctx->xm2, sizeof(ctx->xm2));
    ctx->state = NOXTLS_ECJPAKE_STATE_DONE;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_ecjpake_state_t noxtls_ecjpake_get_state(const noxtls_ecjpake_ctx_t *ctx)
{
    return (ctx == NULL) ? NOXTLS_ECJPAKE_STATE_EMPTY : ctx->state;
}

void noxtls_ecjpake_free(noxtls_ecjpake_ctx_t *ctx)
{
    if (ctx != NULL) {
        noxtls_secure_zero(ctx, sizeof(*ctx));
    }
}
