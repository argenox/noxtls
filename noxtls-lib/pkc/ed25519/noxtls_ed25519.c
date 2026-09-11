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
* File:    noxtls_ed25519.c
* Summary: Ed25519 digital signatures (RFC 8032)
*
*
*****************************************************************************/

/**
 * @file noxtls_ed25519.c
 * @brief Ed25519 sign/verify API and scalar helpers (RFC 8032).
 * @ingroup noxtls_ed25519
 */

#include <stdint.h>
#include <string.h>

#include "common/noxtls_ct.h"
#include "drbg/noxtls_drbg.h"
#include "mdigest/sha512/noxtls_sha512.h"
#include "noxtls_common.h"
#include "noxtls_ed25519.h"
#include "noxtls_ed25519_ge.h"
#include "noxtls_ed25519_sc.h"

/* L = order of base point = 2^252 + 27742317777372353535851937790883648493, big-endian.
 * Used only for the RFC 8032 S < L canonical check on verify. */
static const uint8_t ed25519_L[NOXTLS_ED25519_FE25519_BYTES] = {
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xDE, 0xF9, 0xDE, 0xA2, 0xF7, 0x9C, 0xD6,
    0x58, 0x12, 0x63, 0x1A, 0x5C, 0xF5, 0xD3, 0xED
};

/**
 * @brief Convert 32 little-endian bytes to big-endian.
 * @internal
 *
 * @param[out] be Big-endian output.
 * @param[in] le Little-endian input.
 */
static void le32_to_be32(uint8_t be[NOXTLS_ED25519_FE25519_BYTES], const uint8_t le[NOXTLS_ED25519_FE25519_BYTES])
{
    for(int i = 0; i < (int)NOXTLS_ED25519_FE25519_BYTES; i++) {
        be[i] = le[(int)NOXTLS_ED25519_FE25519_BYTES - 1 - i];
    }
}

/**
 * @brief Compare two big-endian byte strings of equal length.
 * @internal
 *
 * @param[in] a First buffer.
 * @param[in] b Second buffer.
 * @param[in] len Length in bytes.
 *
 * @return 1 if a > b, -1 if a < b, 0 if equal.
 */
static int ed25519_cmp_be(const uint8_t *a, const uint8_t *b, uint32_t len)
{
    for(uint32_t i = 0; i < len; i++) {
        if(a[i] != b[i]) {
            return (a[i] > b[i]) ? 1 : -1;
        }
    }
    return 0;
}

/* RFC 8032 dom2 prefix (32 bytes, no NUL); avoids MSVC C4295 on char[32] = "..." */
static const uint8_t ed25519_dom2_literal[NOXTLS_ED25519_DOM2_LITERAL_BYTES] = {
    'S', 'i', 'g', 'E', 'd', '2', '5', '5', '1', '9', ' ', 'n', 'o', ' ', 'E', 'd',
    '2', '5', '5', '1', '9', ' ', 'c', 'o', 'l', 'l', 'i', 's', 'i', 'o', 'n', 's'
};

/**
 * @brief Core Ed25519 signing using an already-expanded key (cached A / s / prefix).
 * @internal
 *
 * Does not recompute A = [s]B. Matches wolfSSL-style cached-pubkey signing.
 *
 * @param[in] s_le Clamped signing scalar (32-byte LE).
 * @param[in] prefix Hash prefix (second half of SHA-512(seed)).
 * @param[in] public_key Encoded public key A.
 * @param[in] noxtls_message Message bytes (or prehash input when @p phflag is prehash).
 * @param[in] message_len Length of @p noxtls_message.
 * @param[out] signature 64-byte signature (`R || S` wire encoding).
 * @param[in] phflag `NOXTLS_ED25519_PH_FLAG_PURE` or `NOXTLS_ED25519_PH_FLAG_PREHASH`.
 * @param[in] ctx_str Optional context string (Ed25519ctx); may be NULL when @p ctx_len is 0.
 * @param[in] ctx_len Context length; must be 0 for prehash variant.
 *
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
static noxtls_return_t ed25519_sign_expanded(const uint8_t s_le[NOXTLS_ED25519_FE25519_BYTES],
                                             const uint8_t prefix[NOXTLS_ED25519_FE25519_BYTES],
                                             const uint8_t public_key[NOXTLS_ED25519_FE25519_BYTES],
                                             const uint8_t *noxtls_message,
                                             uint32_t message_len,
                                             uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE],
                                             uint8_t phflag,
                                             const uint8_t *ctx_str,
                                             uint32_t ctx_len)
{
    uint8_t r_in[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
    uint8_t r_le[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t k_in[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
    uint8_t k_le[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t S_le[NOXTLS_ED25519_FE25519_BYTES];
    ge25519_pt_t R;
    noxtls_sha512_ctx_t ctx;
    uint8_t dom_buf[NOXTLS_ED25519_DOM2_BUFFER_BYTES];
    uint32_t dom_len = 0;
    uint8_t ph_digest[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
    const uint8_t *m_body = noxtls_message;
    uint32_t m_len = message_len;

    if(s_le == NULL || prefix == NULL || public_key == NULL || signature == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(noxtls_message == NULL && message_len != 0) {
        return NOXTLS_RETURN_NULL;
    }
    if(phflag > NOXTLS_ED25519_PH_FLAG_PREHASH) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(phflag == NOXTLS_ED25519_PH_FLAG_PREHASH && ctx_len != 0) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ctx_len > NOXTLS_ED25519_CONTEXT_MAX) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ctx_len > 0 && ctx_str == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(phflag != NOXTLS_ED25519_PH_FLAG_PURE || ctx_len > 0) {
        memcpy(dom_buf, ed25519_dom2_literal, NOXTLS_ED25519_DOM2_LITERAL_BYTES);
        dom_buf[NOXTLS_ED25519_DOM2_PHFLAG_OCTET_INDEX] = phflag;
        dom_buf[NOXTLS_ED25519_DOM2_CTX_LEN_OCTET_INDEX] = (uint8_t)ctx_len;
        if(ctx_len > 0) {
            memcpy(dom_buf + NOXTLS_ED25519_DOM2_CTX_START_OCTET_INDEX, ctx_str, ctx_len);
        }
        dom_len = NOXTLS_ED25519_DOM2_PREFIX_BYTES + ctx_len;
    }

    if(phflag == NOXTLS_ED25519_PH_FLAG_PREHASH) {
        if(noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        if(message_len != 0U && noxtls_sha512_update(&ctx, noxtls_message, message_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        if(noxtls_sha512_finish(&ctx, ph_digest) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        m_body = ph_digest;
        m_len = NOXTLS_ED25519_SHA512_DIGEST_BYTES;
    }

    /* RFC 8032 §5.1.6: r = SHA-512(dom2 || prefix || M) mod L; R = [r]B. */
    if(noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(dom_len != 0U && noxtls_sha512_update(&ctx, dom_buf, dom_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(noxtls_sha512_update(&ctx, prefix, NOXTLS_ED25519_FE25519_BYTES) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(m_len != 0U && noxtls_sha512_update(&ctx, m_body, m_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(noxtls_sha512_finish(&ctx, r_in) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    sc25519_reduce(r_le, r_in);
    ge25519_scalarmult_base(&R, r_le);
    ge25519_encode(signature, &R);

    /* k = SHA-512(dom2 || R || A || M) mod L; S = (r + k*s) mod L (ref10 sc_muladd). */
    if(noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }
    if(dom_len != 0U && noxtls_sha512_update(&ctx, dom_buf, dom_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }
    if(noxtls_sha512_update(&ctx, signature, NOXTLS_ED25519_FE25519_BYTES) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }
    if(noxtls_sha512_update(&ctx, public_key, NOXTLS_ED25519_FE25519_BYTES) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }
    if(m_len != 0U && noxtls_sha512_update(&ctx, m_body, m_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }
    if(noxtls_sha512_finish(&ctx, k_in) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }
    sc25519_reduce(k_le, k_in);
    sc25519_muladd(S_le, k_le, s_le, r_le);
    memcpy(signature + NOXTLS_ED25519_FE25519_BYTES, S_le, NOXTLS_ED25519_FE25519_BYTES);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Expand a 32-byte seed into clamped s, prefix, and public key A.
 * @internal
 *
 * @param[in] seed 32-byte private seed.
 * @param[out] s_le Clamped signing scalar.
 * @param[out] prefix Hash prefix.
 * @param[out] public_key Encoded public key.
 *
 * @return `NOXTLS_RETURN_SUCCESS` on success, or an error code.
 */
static noxtls_return_t ed25519_expand_seed(const uint8_t seed[NOXTLS_ED25519_FE25519_BYTES],
                                           uint8_t s_le[NOXTLS_ED25519_FE25519_BYTES],
                                           uint8_t prefix[NOXTLS_ED25519_FE25519_BYTES],
                                           uint8_t public_key[NOXTLS_ED25519_FE25519_BYTES])
{
    uint8_t h[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
    ge25519_pt_t A_pt;
    noxtls_sha512_ctx_t ctx;

    if(seed == NULL || s_le == NULL || prefix == NULL || public_key == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    /* RFC 8032 §5.1.5: SHA-512(seed); clamp s; A = [s]B. */
    if(noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if(noxtls_sha512_update(&ctx, seed, NOXTLS_ED25519_FE25519_BYTES) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if(noxtls_sha512_finish(&ctx, h) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    h[0] &= NOXTLS_ED25519_SCALAR_CLAMP_BYTE0_MASK;
    h[NOXTLS_ED25519_FE25519_BYTES - 1U] &= NOXTLS_ED25519_SCALAR_CLAMP_BYTE31_AND;
    h[NOXTLS_ED25519_FE25519_BYTES - 1U] |= NOXTLS_ED25519_SCALAR_CLAMP_BYTE31_OR;
    memcpy(s_le, h, NOXTLS_ED25519_FE25519_BYTES);
    memcpy(prefix, h + NOXTLS_ED25519_FE25519_BYTES, NOXTLS_ED25519_FE25519_BYTES);
    ge25519_scalarmult_base(&A_pt, s_le);
    ge25519_encode(public_key, &A_pt);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Core Ed25519 signing: pure, ctx, or prehash variant controlled by @p phflag and @p ctx_str.
 *
 * @param[in] private_key 32-byte seed/private key material.
 * @param[in] noxtls_message Message bytes (or prehash input when @p phflag is prehash).
 * @param[in] message_len Length of @p noxtls_message.
 * @param[out] signature 64-byte signature (`R || S` wire encoding).
 * @param[in] phflag `NOXTLS_ED25519_PH_FLAG_PURE` or `NOXTLS_ED25519_PH_FLAG_PREHASH`.
 * @param[in] ctx_str Optional context string (Ed25519ctx); may be NULL when @p ctx_len is 0.
 * @param[in] ctx_len Context length; must be 0 for prehash variant.
 *
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on validation or crypto failure.
 */
static noxtls_return_t ed25519_sign_internal(const uint8_t private_key[NOXTLS_ED25519_FE25519_BYTES],
                                             const uint8_t *noxtls_message,
                                             uint32_t message_len,
                                             uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE],
                                             uint8_t phflag,
                                             const uint8_t *ctx_str,
                                             uint32_t ctx_len)
{
    uint8_t prefix[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t s_le[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t public_key[NOXTLS_ED25519_FE25519_BYTES];
    noxtls_return_t rc;

    if(private_key == NULL || signature == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = ed25519_expand_seed(private_key, s_le, prefix, public_key);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    return ed25519_sign_expanded(s_le, prefix, public_key, noxtls_message, message_len,
                                 signature, phflag, ctx_str, ctx_len);
}

/**
 * @brief Check [S]B - [k]A == R (with cofactor-8 fallback).
 * @internal
 *
 * Uses interleaved double-scalar multiplication (RFC 8032 §5.1.7 equation).
 *
 * @param[in] A Decoded public point.
 * @param[in] R Decoded commitment point.
 * @param[in] k_le Challenge scalar (little-endian).
 * @param[in] S_le Response scalar (little-endian).
 *
 * @return `NOXTLS_RETURN_SUCCESS` if the equation holds, else `NOXTLS_RETURN_FAILED`.
 */
static noxtls_return_t ed25519_check_verify_equation(const ge25519_pt_t *A,
                                                     const ge25519_pt_t *R,
                                                     const uint8_t k_le[NOXTLS_ED25519_FE25519_BYTES],
                                                     const uint8_t S_le[NOXTLS_ED25519_FE25519_BYTES])
{
    ge25519_n_t A_n;
    ge25519_n_t Aneg_n;
    ge25519_pt_t Aneg;
    ge25519_pt_t check;
    uint8_t enc_check[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t enc_R[NOXTLS_ED25519_FE25519_BYTES];

    /* check = [k](-A) + [S]B = [S]B - [k]A */
    ge25519_n_from_pt(&A_n, A);
    ge25519_n_neg(&Aneg_n, &A_n);
    ge25519_n_to_pt(&Aneg, &Aneg_n);
    ge25519_double_scalarmult(&check, k_le, &Aneg, S_le);

    ge25519_encode(enc_check, &check);
    ge25519_encode(enc_R, R);
    if(noxtls_secret_memcmp(enc_check, enc_R, NOXTLS_ED25519_FE25519_BYTES) == 0) {
        return NOXTLS_RETURN_SUCCESS;
    }

    /* Cofactor clear: accept if [8]check == [8]R (existing fallback behavior). */
    {
        uint8_t cofactor_le[NOXTLS_ED25519_FE25519_BYTES];
        ge25519_pt_t lhs8;
        ge25519_pt_t rhs8;
        uint8_t enc_lhs8[NOXTLS_ED25519_FE25519_BYTES];
        uint8_t enc_rhs8[NOXTLS_ED25519_FE25519_BYTES];

        memset(cofactor_le, 0, sizeof(cofactor_le));
        cofactor_le[0] = NOXTLS_ED25519_SUBGROUP_COFACTOR;
        ge25519_scalar_mult(&lhs8, cofactor_le, &check);
        ge25519_scalar_mult(&rhs8, cofactor_le, R);
        ge25519_encode(enc_lhs8, &lhs8);
        ge25519_encode(enc_rhs8, &rhs8);
        if(noxtls_secret_memcmp(enc_lhs8, enc_rhs8, NOXTLS_ED25519_FE25519_BYTES) == 0) {
            return NOXTLS_RETURN_SUCCESS;
        }
    }
    return NOXTLS_RETURN_FAILED;
}

/**
 * @brief Core Ed25519 verification with the same dom2 / prehash rules as `ed25519_sign_internal`.
 * @param[in] public_key 32-byte public key encoding.
 * @param[in] noxtls_message Message bytes (or prehash input when @p phflag is prehash).
 * @param[in] message_len Length of @p noxtls_message.
 * @param[in] signature 64-byte signature to verify.
 * @param[in] phflag `NOXTLS_ED25519_PH_FLAG_PURE` or `NOXTLS_ED25519_PH_FLAG_PREHASH`.
 * @param[in] ctx_str Optional context string; may be NULL when @p ctx_len is 0.
 * @param[in] ctx_len Context length; must be 0 for prehash variant.
 * @return `NOXTLS_RETURN_SUCCESS` if the signature is valid, otherwise an error `noxtls_return_t`.
 */
static noxtls_return_t ed25519_verify_internal(const uint8_t public_key[NOXTLS_ED25519_FE25519_BYTES],
                                                const uint8_t *noxtls_message,
                                                uint32_t message_len,
                                                const uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE],
                                                uint8_t phflag,
                                                const uint8_t *ctx_str,
                                                uint32_t ctx_len)
{
    uint8_t k_in[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
    uint8_t k_le[NOXTLS_ED25519_FE25519_BYTES];
    ge25519_pt_t A;
    ge25519_pt_t R;
    noxtls_sha512_ctx_t ctx;
    uint8_t dom_buf[NOXTLS_ED25519_DOM2_BUFFER_BYTES];
    uint32_t dom_len = 0;
    uint8_t ph_digest[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
    const uint8_t *m_body = noxtls_message;
    uint32_t m_len = message_len;
    uint8_t S_le[NOXTLS_ED25519_FE25519_BYTES];

    if(public_key == NULL || signature == NULL) { return NOXTLS_RETURN_NULL; }
    if(noxtls_message == NULL && message_len != 0) { return NOXTLS_RETURN_NULL; }
    if(phflag > NOXTLS_ED25519_PH_FLAG_PREHASH) { return NOXTLS_RETURN_INVALID_PARAM; }
    if(phflag == NOXTLS_ED25519_PH_FLAG_PREHASH && ctx_len != 0) { return NOXTLS_RETURN_INVALID_PARAM; }
    if(ctx_len > NOXTLS_ED25519_CONTEXT_MAX) { return NOXTLS_RETURN_INVALID_PARAM; }
    if(ctx_len > 0 && ctx_str == NULL) { return NOXTLS_RETURN_NULL; }

    if(phflag != NOXTLS_ED25519_PH_FLAG_PURE || ctx_len > 0) {
        memcpy(dom_buf, ed25519_dom2_literal, NOXTLS_ED25519_DOM2_LITERAL_BYTES);
        dom_buf[NOXTLS_ED25519_DOM2_PHFLAG_OCTET_INDEX] = phflag;
        dom_buf[NOXTLS_ED25519_DOM2_CTX_LEN_OCTET_INDEX] = (uint8_t)ctx_len;
        if(ctx_len > 0) {
            memcpy(dom_buf + NOXTLS_ED25519_DOM2_CTX_START_OCTET_INDEX, ctx_str, ctx_len);
        }
        dom_len = NOXTLS_ED25519_DOM2_PREFIX_BYTES + ctx_len;
    }

    if(phflag == NOXTLS_ED25519_PH_FLAG_PREHASH) {
        if(noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
        if(message_len != 0U && noxtls_sha512_update(&ctx, noxtls_message, message_len) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
        if(noxtls_sha512_finish(&ctx, ph_digest) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
        m_body = ph_digest;
        m_len = NOXTLS_ED25519_SHA512_DIGEST_BYTES;
    }

    /* RFC 8032 §5.1.7 */
    if(ge25519_decode(&A, public_key) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if(ge25519_decode(&R, signature) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }

    {
        uint8_t S_be[NOXTLS_ED25519_FE25519_BYTES];
        memcpy(S_le, signature + NOXTLS_ED25519_FE25519_BYTES, NOXTLS_ED25519_FE25519_BYTES);
        le32_to_be32(S_be, S_le);
        if(ed25519_cmp_be(S_be, ed25519_L, NOXTLS_ED25519_FE25519_BYTES) >= 0) { return NOXTLS_RETURN_FAILED; }
    }

    if(noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if(dom_len != 0U && noxtls_sha512_update(&ctx, dom_buf, dom_len) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_sha512_update(&ctx, signature, NOXTLS_ED25519_FE25519_BYTES) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_sha512_update(&ctx, public_key, NOXTLS_ED25519_FE25519_BYTES) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if(m_len != 0U && noxtls_sha512_update(&ctx, m_body, m_len) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    if(noxtls_sha512_finish(&ctx, k_in) != NOXTLS_RETURN_SUCCESS) { return NOXTLS_RETURN_FAILED; }
    sc25519_reduce(k_le, k_in);

    return ed25519_check_verify_equation(&A, &R, k_le, S_le);
}

/**
 * @brief Derives the Ed25519 public key from a 32-byte private key seed (RFC 8032).
 * @param[in]  private_key 32-byte private key / seed.
 * @param[out] public_key 32-byte compressed public key encoding.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_ed25519_public_key(const uint8_t private_key[NOXTLS_ED25519_FE25519_BYTES], uint8_t public_key[NOXTLS_ED25519_FE25519_BYTES])
{
    uint8_t s_le[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t prefix[NOXTLS_ED25519_FE25519_BYTES];

    return ed25519_expand_seed(private_key, s_le, prefix, public_key);
}

/**
 * @brief Expand a 32-byte seed into a reusable keypair context (cached A / s / prefix).
 *
 * @param[out] keypair Keypair context to fill.
 * @param[in] seed 32-byte private seed (RFC 8032).
 *
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_ed25519_keypair_from_seed(noxtls_ed25519_keypair_t *keypair,
                                                 const uint8_t seed[NOXTLS_ED25519_PRIVATE_KEY_SIZE])
{
    noxtls_return_t rc;

    if(keypair == NULL || seed == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    memset(keypair, 0, sizeof(*keypair));
    memcpy(keypair->seed, seed, NOXTLS_ED25519_PRIVATE_KEY_SIZE);
    rc = ed25519_expand_seed(seed, keypair->s, keypair->prefix, keypair->public_key);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    keypair->ready = 1U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Sign with a prepared keypair without recomputing A = [s]B.
 *
 * @param[in] keypair Prepared keypair from `noxtls_ed25519_keypair_from_seed`.
 * @param[in] noxtls_message Message to sign.
 * @param[in] message_len Message length in bytes.
 * @param[out] signature 64-byte signature output.
 *
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_ed25519_sign_keypair(const noxtls_ed25519_keypair_t *keypair,
                                           const uint8_t *noxtls_message,
                                           uint32_t message_len,
                                           uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE])
{
    if(keypair == NULL || signature == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(keypair->ready == 0U) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
    return ed25519_sign_expanded(keypair->s, keypair->prefix, keypair->public_key,
                                 noxtls_message, message_len, signature,
                                 NOXTLS_ED25519_PH_FLAG_PURE, NULL, 0);
}

/**
 * @brief Signs a noxtls_message with Ed25519 (pure variant, no context, no prehash).
 * @param[in]  private_key 32-byte private key.
 * @param[in]  noxtls_message Message to sign.
 * @param[in]  message_len Length of @p noxtls_message in bytes.
 * @param[out] signature 64-byte signature output.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_ed25519_sign(const uint8_t private_key[NOXTLS_ED25519_FE25519_BYTES],
                                     const uint8_t *noxtls_message,
                                     uint32_t message_len,
                                     uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE])
{
    return ed25519_sign_internal(private_key, noxtls_message, message_len, signature, NOXTLS_ED25519_PH_FLAG_PURE, NULL, 0);
}

/**
 * @brief Verifies an Ed25519 signature (pure variant).
 * @param[in] public_key 32-byte public key encoding.
 * @param[in] noxtls_message Message that was signed.
 * @param[in] message_len Length of @p noxtls_message in bytes.
 * @param[in] signature 64-byte signature.
 * @return `NOXTLS_RETURN_SUCCESS` if valid, otherwise an error `noxtls_return_t`.
 */
noxtls_return_t noxtls_ed25519_verify(const uint8_t public_key[NOXTLS_ED25519_FE25519_BYTES],
                                      const uint8_t *noxtls_message,
                                      uint32_t message_len,
                                      const uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE])
{
    return ed25519_verify_internal(public_key, noxtls_message, message_len, signature, NOXTLS_ED25519_PH_FLAG_PURE, NULL, 0);
}

static noxtls_return_t ed25519_verify_finalize(const uint8_t public_key[NOXTLS_ED25519_FE25519_BYTES],
                                               const uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE],
                                               const uint8_t k_in[NOXTLS_ED25519_SHA512_DIGEST_BYTES])
{
    uint8_t k_le[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t S_le[NOXTLS_ED25519_FE25519_BYTES];
    ge25519_pt_t A;
    ge25519_pt_t R;

    if(public_key == NULL || signature == NULL || k_in == NULL) return NOXTLS_RETURN_NULL;

    if(ge25519_decode(&A, public_key) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(ge25519_decode(&R, signature) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    {
        uint8_t S_be[NOXTLS_ED25519_FE25519_BYTES];
        memcpy(S_le, signature + NOXTLS_ED25519_FE25519_BYTES, NOXTLS_ED25519_FE25519_BYTES);
        le32_to_be32(S_be, S_le);
        if(ed25519_cmp_be(S_be, ed25519_L, NOXTLS_ED25519_FE25519_BYTES) >= 0) return NOXTLS_RETURN_FAILED;
    }

    sc25519_reduce(k_le, k_in);

    return ed25519_check_verify_equation(&A, &R, k_le, S_le);
}

noxtls_return_t noxtls_ed25519_verify_stream_init(noxtls_ed25519_verify_stream_ctx_t *ctx,
                                                  const uint8_t public_key[NOXTLS_ED25519_FE25519_BYTES],
                                                  const uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE])
{
    if(ctx == NULL || public_key == NULL || signature == NULL) return NOXTLS_RETURN_NULL;

    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->public_key, public_key, NOXTLS_ED25519_FE25519_BYTES);
    memcpy(ctx->signature, signature, NOXTLS_ED25519_SIGNATURE_SIZE);

    if(noxtls_sha512_init(&ctx->hash_ctx, NOXTLS_HASH_SHA_512) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(noxtls_sha512_update(&ctx->hash_ctx, signature, NOXTLS_ED25519_FE25519_BYTES) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
    if(noxtls_sha512_update(&ctx->hash_ctx, public_key, NOXTLS_ED25519_FE25519_BYTES) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    ctx->initialized = 1U;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_ed25519_verify_stream_update(noxtls_ed25519_verify_stream_ctx_t *ctx,
                                                    const uint8_t *message_part,
                                                    uint32_t message_part_len)
{
    if(ctx == NULL) return NOXTLS_RETURN_NULL;
    if(ctx->initialized == 0U) return NOXTLS_RETURN_FAILED;
    if(message_part == NULL && message_part_len != 0U) return NOXTLS_RETURN_NULL;
    if(message_part_len == 0U) return NOXTLS_RETURN_SUCCESS;

    return noxtls_sha512_update(&ctx->hash_ctx, message_part, message_part_len);
}

noxtls_return_t noxtls_ed25519_verify_stream_final(noxtls_ed25519_verify_stream_ctx_t *ctx)
{
    uint8_t k_in[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
    noxtls_return_t rc;

    if(ctx == NULL) return NOXTLS_RETURN_NULL;
    if(ctx->initialized == 0U) return NOXTLS_RETURN_FAILED;

    rc = noxtls_sha512_finish(&ctx->hash_ctx, k_in);
    if(rc != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;

    ctx->initialized = 0U;
    return ed25519_verify_finalize(ctx->public_key, ctx->signature, k_in);
}

noxtls_return_t noxtls_ed25519_verify_split(const uint8_t public_key[NOXTLS_ED25519_FE25519_BYTES],
                                            const uint8_t *message_part_a,
                                            uint32_t message_part_a_len,
                                            const uint8_t *message_part_b,
                                            uint32_t message_part_b_len,
                                            const uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE])
{
    noxtls_ed25519_verify_stream_ctx_t stream_ctx;
    noxtls_return_t rc;

    rc = noxtls_ed25519_verify_stream_init(&stream_ctx, public_key, signature);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;

    rc = noxtls_ed25519_verify_stream_update(&stream_ctx, message_part_a, message_part_a_len);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;

    rc = noxtls_ed25519_verify_stream_update(&stream_ctx, message_part_b, message_part_b_len);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;

    return noxtls_ed25519_verify_stream_final(&stream_ctx);
}

/**
 * @brief Signs a noxtls_message with Ed25519ctx (RFC 8032 context string, not prehashed).
 * @param[in]  private_key 32-byte private key.
 * @param[in]  noxtls_message Message to sign.
 * @param[in]  message_len Length of @p noxtls_message in bytes.
 * @param[in]  context Context string (length at most `NOXTLS_ED25519_CONTEXT_MAX`).
 * @param[in]  context_len Length of @p context in bytes.
 * @param[out] signature 64-byte signature output.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_ed25519ctx_sign(const uint8_t private_key[NOXTLS_ED25519_FE25519_BYTES],
                                       const uint8_t *context,
                                       uint32_t context_len,
                                       const uint8_t *noxtls_message,
                                       uint32_t message_len,
                                       uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE])
{
    if(context == NULL && context_len != 0) { return NOXTLS_RETURN_NULL; }
    if(context_len < 1U || context_len > NOXTLS_ED25519_CONTEXT_MAX) { return NOXTLS_RETURN_INVALID_PARAM; }
    return ed25519_sign_internal(private_key, noxtls_message, message_len, signature, NOXTLS_ED25519_PH_FLAG_PURE, context, context_len);
}

/**
 * @brief Verifies an Ed25519ctx signature.
 * @param[in] public_key 32-byte public key encoding.
 * @param[in] noxtls_message Message that was signed.
 * @param[in] message_len Length of @p noxtls_message in bytes.
 * @param[in] context Context string used when signing.
 * @param[in] context_len Length of @p context in bytes.
 * @param[in] signature 64-byte signature.
 * @return `NOXTLS_RETURN_SUCCESS` if valid, otherwise an error `noxtls_return_t`.
 */
noxtls_return_t noxtls_ed25519ctx_verify(const uint8_t public_key[NOXTLS_ED25519_FE25519_BYTES],
                                         const uint8_t *context,
                                         uint32_t context_len,
                                         const uint8_t *noxtls_message,
                                         uint32_t message_len,
                                         const uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE])
{
    if(context == NULL && context_len != 0) { return NOXTLS_RETURN_NULL; }
    if(context_len < 1U || context_len > NOXTLS_ED25519_CONTEXT_MAX) { return NOXTLS_RETURN_INVALID_PARAM; }
    return ed25519_verify_internal(public_key, noxtls_message, message_len, signature, NOXTLS_ED25519_PH_FLAG_PURE, context, context_len);
}

/**
 * @brief Signs with Ed25519ph: @p noxtls_message is hashed with SHA-512 first, then signed.
 * @param[in]  private_key 32-byte private key.
 * @param[in]  noxtls_message Input to SHA-512 (typically the raw noxtls_message bytes).
 * @param[in]  message_len Length of @p noxtls_message in bytes.
 * @param[out] signature 64-byte signature output.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_ed25519ph_sign(const uint8_t private_key[NOXTLS_ED25519_FE25519_BYTES],
                                      const uint8_t *noxtls_message,
                                      uint32_t message_len,
                                      uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE])
{
    return ed25519_sign_internal(private_key, noxtls_message, message_len, signature, NOXTLS_ED25519_PH_FLAG_PREHASH, NULL, 0);
}

/**
 * @brief Verifies an Ed25519ph signature (SHA-512 prehash of @p noxtls_message).
 * @param[in] public_key 32-byte public key encoding.
 * @param[in] noxtls_message Same prehash input that was signed.
 * @param[in] message_len Length of @p noxtls_message in bytes.
 * @param[in] signature 64-byte signature.
 * @return `NOXTLS_RETURN_SUCCESS` if valid, otherwise an error `noxtls_return_t`.
 */
noxtls_return_t noxtls_ed25519ph_verify(const uint8_t public_key[NOXTLS_ED25519_FE25519_BYTES],
                                        const uint8_t *noxtls_message,
                                        uint32_t message_len,
                                        const uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE])
{
    return ed25519_verify_internal(public_key, noxtls_message, message_len, signature, NOXTLS_ED25519_PH_FLAG_PREHASH, NULL, 0);
}

/**
 * @brief Generates a random Ed25519 key pair using the library DRBG.
 * @param[out] private_key 32-byte random private key / seed.
 * @param[out] public_key 32-byte derived public key encoding.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_ed25519_generate_key(uint8_t private_key[NOXTLS_ED25519_FE25519_BYTES], uint8_t public_key[NOXTLS_ED25519_FE25519_BYTES])
{
    static drbg_state_t drbg_state;
    static int drbg_initialized = 0;
    noxtls_return_t rc;

    if(private_key == NULL || public_key == NULL) { return NOXTLS_RETURN_NULL; }
    if(!drbg_initialized) {
        rc = drbg_instantiate(&drbg_state, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0);
        if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }
        drbg_initialized = 1;
    }
    rc = drbg_generate(&drbg_state, private_key, NOXTLS_ED25519_DRBG_SEED_BITS, NULL, 0);
    if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }
    return noxtls_ed25519_public_key(private_key, public_key);
}
