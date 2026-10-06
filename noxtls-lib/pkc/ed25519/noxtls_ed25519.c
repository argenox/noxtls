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

#include "common/noxtls_accel_port.h"
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
    0x10U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x14U, 0xDEU, 0xF9U, 0xDEU, 0xA2U, 0xF7U, 0x9CU, 0xD6U,
    0x58U, 0x12U, 0x63U, 0x1AU, 0x5CU, 0xF5U, 0xD3U, 0xEDU
};

/**
 * @brief Convert 32 little-endian bytes to big-endian.
 * @internal
 *
 * @param[out] be Big-endian output.
 * @param[in] le Little-endian input.
 */
static void le32_to_be32(uint8_t *be, const uint8_t *le)
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
    for(uint32_t i = 0U; i < len; i += 1U) {
        if(a[i] != b[i]) {
            return (a[i] > b[i]) ? 1 : -1;
        }
    }
    return 0;
}

/* RFC 8032 dom2 prefix (32 bytes, no NUL); avoids MSVC C4295 on char[32] = "..." */
static const uint8_t ed25519_dom2_literal[NOXTLS_ED25519_DOM2_LITERAL_BYTES] = {
    (uint8_t)'S', (uint8_t)'i', (uint8_t)'g', (uint8_t)'E', (uint8_t)'d', (uint8_t)'2', (uint8_t)'5', (uint8_t)'5', (uint8_t)'1', (uint8_t)'9', (uint8_t)' ', (uint8_t)'n', (uint8_t)'o', (uint8_t)' ', (uint8_t)'E', (uint8_t)'d',
    (uint8_t)'2', (uint8_t)'5', (uint8_t)'5', (uint8_t)'1', (uint8_t)'9', (uint8_t)' ', (uint8_t)'c', (uint8_t)'o', (uint8_t)'l', (uint8_t)'l', (uint8_t)'i', (uint8_t)'s', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', (uint8_t)'s'
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
static noxtls_return_t ed25519_sign_expanded(const uint8_t *s_le,
                                             const uint8_t *prefix,
                                             const uint8_t *public_key,
                                             const uint8_t *noxtls_message,
                                             uint32_t message_len,
                                             uint8_t *signature,
                                             uint8_t phflag,
                                             const uint8_t *ctx_str,
                                             uint32_t ctx_len)
{
    uint8_t r_in[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
    uint8_t r_le[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t k_in[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
    uint8_t k_le[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t S_le[NOXTLS_ED25519_FE25519_BYTES];
    noxtls_sha512_ctx_t ctx;
    uint8_t dom_buf[NOXTLS_ED25519_DOM2_BUFFER_BYTES];
    uint32_t dom_len = 0U;
    uint8_t ph_digest[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
    const uint8_t *m_body = noxtls_message;
    uint32_t m_len = message_len;

    if(s_le == NULL || prefix == NULL || public_key == NULL || signature == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(noxtls_message == NULL && message_len != 0U) {
        return NOXTLS_RETURN_NULL;
    }
    if(phflag > NOXTLS_ED25519_PH_FLAG_PREHASH) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(phflag == NOXTLS_ED25519_PH_FLAG_PREHASH && ctx_len != 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ctx_len > NOXTLS_ED25519_CONTEXT_MAX) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ctx_len > 0U && ctx_str == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if((phflag != NOXTLS_ED25519_PH_FLAG_PURE) || (ctx_len > 0U)) {
        noxtls_copy_u8(dom_buf, sizeof(dom_buf), ed25519_dom2_literal, (size_t)NOXTLS_ED25519_DOM2_LITERAL_BYTES);
        dom_buf[NOXTLS_ED25519_DOM2_PHFLAG_OCTET_INDEX] = phflag;
        dom_buf[NOXTLS_ED25519_DOM2_CTX_LEN_OCTET_INDEX] = (uint8_t)ctx_len;
        if(ctx_len > 0U) {
            noxtls_copy_u8(&dom_buf[NOXTLS_ED25519_DOM2_CTX_START_OCTET_INDEX], sizeof(dom_buf) - (size_t)(NOXTLS_ED25519_DOM2_CTX_START_OCTET_INDEX), ctx_str, (size_t)ctx_len);
        }
        dom_len = NOXTLS_ED25519_DOM2_PREFIX_BYTES + ctx_len;
    }

    if(phflag == NOXTLS_ED25519_PH_FLAG_PREHASH) {
        if(noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        if(message_len != 0U) {
        if(noxtls_sha512_update(&ctx, noxtls_message, message_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
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
    if(dom_len != 0U) {
        if(noxtls_sha512_update(&ctx, dom_buf, dom_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_BAD_DATA;
        }
    }
    if(noxtls_sha512_update(&ctx, prefix, NOXTLS_ED25519_FE25519_BYTES) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(m_len != 0U) {
        if(noxtls_sha512_update(&ctx, m_body, m_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_BAD_DATA;
        }
    }
    if(noxtls_sha512_finish(&ctx, r_in) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    sc25519_reduce(r_le, r_in);
    {
        ge25519_n_t R_n;
        ge25519_scalarmult_base_n(&R_n, r_le);
        ge25519_encode_n(signature, &R_n);
    }

    /* k = SHA-512(dom2 || R || A || M) mod L; S = (r + k*s) mod L (ref10 sc_muladd). */
    if(noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }
    if(dom_len != 0U) {
        if(noxtls_sha512_update(&ctx, dom_buf, dom_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
        }
    }
    if(noxtls_sha512_update(&ctx, signature, NOXTLS_ED25519_FE25519_BYTES) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }
    if(noxtls_sha512_update(&ctx, public_key, NOXTLS_ED25519_FE25519_BYTES) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }
    if(m_len != 0U) {
        if(noxtls_sha512_update(&ctx, m_body, m_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
        }
    }
    if(noxtls_sha512_finish(&ctx, k_in) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    }
    sc25519_reduce(k_le, k_in);
    sc25519_muladd(S_le, k_le, s_le, r_le);
    noxtls_copy_u8((uint8_t *)(void *)(&signature[NOXTLS_ED25519_FE25519_BYTES]), (size_t)(NOXTLS_ED25519_FE25519_BYTES), (const uint8_t *)(const void *)(S_le), (size_t)(NOXTLS_ED25519_FE25519_BYTES));
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
static noxtls_return_t ed25519_expand_seed(const uint8_t *seed,
                                           uint8_t *s_le,
                                           uint8_t *prefix,
                                           uint8_t *public_key)
{
    uint8_t h[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
    ge25519_n_t A_n;
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
    noxtls_copy_u8((uint8_t *)(void *)(s_le), (size_t)(NOXTLS_ED25519_FE25519_BYTES), (const uint8_t *)(const void *)(h), (size_t)(NOXTLS_ED25519_FE25519_BYTES));
    noxtls_copy_u8((uint8_t *)(void *)(prefix), (size_t)(NOXTLS_ED25519_FE25519_BYTES), (const uint8_t *)(const void *)(&h[NOXTLS_ED25519_FE25519_BYTES]), (size_t)(NOXTLS_ED25519_FE25519_BYTES));
    ge25519_scalarmult_base_n(&A_n, s_le);
    ge25519_encode_n(public_key, &A_n);
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
static noxtls_return_t ed25519_sign_internal(const uint8_t *private_key,
                                             const uint8_t *noxtls_message,
                                             uint32_t message_len,
                                             uint8_t *signature,
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
 * @brief Check [S]B - [k]A == R by encoding (RFC 8032 §5.1.7 / wolfSSL path).
 * @internal
 *
 * Decodes and negates A only. Does not decode R: after
 * @c double_scalarmult computes [S]B - [k]A, encodes once and compares to
 * @p R_bytes (`signature[0..31]`). Matches RFC 8032 §5.1.7 equation check
 * as implemented by wolfSSL (encode result vs signature R octets).
 *
 * @param[in] A_n Decoded public point (native).
 * @param[in] R_bytes Commitment R as 32 wire bytes (not decoded as a point).
 * @param[in] k_le Challenge scalar (little-endian).
 * @param[in] S_le Response scalar (little-endian), already checked S < L.
 *
 * @return `NOXTLS_RETURN_SUCCESS` if the equation holds, else `NOXTLS_RETURN_FAILED`.
 */
static noxtls_return_t ed25519_check_verify_equation(const ge25519_n_t *A_n,
                                                     const uint8_t *R_bytes,
                                                     const uint8_t *k_le,
                                                     const uint8_t *S_le)
{
    ge25519_n_t Aneg;
    ge25519_n_t check;
    uint8_t enc_check[NOXTLS_ED25519_FE25519_BYTES];

    /* check = [k](-A) + [S]B = [S]B - [k]A  (RFC 8032 §5.1.7) */
    ge25519_n_neg(&Aneg, A_n);
    ge25519_double_scalarmult_n(&check, k_le, &Aneg, S_le);
    ge25519_encode_n(enc_check, &check);

    if(noxtls_secret_memcmp(enc_check, R_bytes, NOXTLS_ED25519_FE25519_BYTES) == 0) {
        return NOXTLS_RETURN_SUCCESS;
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
static noxtls_return_t ed25519_verify_internal(const uint8_t *public_key,
                                                const uint8_t *noxtls_message,
                                                uint32_t message_len,
                                                const uint8_t *signature,
                                                uint8_t phflag,
                                                const uint8_t *ctx_str,
                                                uint32_t ctx_len)
{
    noxtls_return_t rc;
    uint8_t k_in[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
    uint8_t k_le[NOXTLS_ED25519_FE25519_BYTES];
    ge25519_n_t A_n;
    noxtls_sha512_ctx_t ctx;
    uint8_t dom_buf[NOXTLS_ED25519_DOM2_BUFFER_BYTES];
    uint32_t dom_len = 0U;
    uint8_t ph_digest[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
    const uint8_t *m_body = noxtls_message;
    uint32_t m_len = message_len;
    uint8_t S_le[NOXTLS_ED25519_FE25519_BYTES];

    if((public_key == NULL) || (signature == NULL)) { return NOXTLS_RETURN_NULL; }
    if((noxtls_message == NULL) && (message_len != 0U)) { return NOXTLS_RETURN_NULL; }
    if(phflag > NOXTLS_ED25519_PH_FLAG_PREHASH) { return NOXTLS_RETURN_INVALID_PARAM; }
    if((phflag == NOXTLS_ED25519_PH_FLAG_PREHASH) && (ctx_len != 0U)) { return NOXTLS_RETURN_INVALID_PARAM; }
    if(ctx_len > NOXTLS_ED25519_CONTEXT_MAX) { return NOXTLS_RETURN_INVALID_PARAM; }
    if((ctx_len > 0U) && (ctx_str == NULL)) { return NOXTLS_RETURN_NULL; }

    if((phflag != NOXTLS_ED25519_PH_FLAG_PURE) || (ctx_len > 0U)) {
        noxtls_copy_u8(dom_buf, sizeof(dom_buf), ed25519_dom2_literal, (size_t)NOXTLS_ED25519_DOM2_LITERAL_BYTES);
        dom_buf[NOXTLS_ED25519_DOM2_PHFLAG_OCTET_INDEX] = phflag;
        dom_buf[NOXTLS_ED25519_DOM2_CTX_LEN_OCTET_INDEX] = (uint8_t)ctx_len;
        if(ctx_len > 0U) {
            noxtls_copy_u8(&dom_buf[NOXTLS_ED25519_DOM2_CTX_START_OCTET_INDEX], sizeof(dom_buf) - (size_t)(NOXTLS_ED25519_DOM2_CTX_START_OCTET_INDEX), ctx_str, (size_t)ctx_len);
        }
        dom_len = NOXTLS_ED25519_DOM2_PREFIX_BYTES + ctx_len;
    }

    if(phflag == NOXTLS_ED25519_PH_FLAG_PREHASH) {
        rc = noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512);
    if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }

        if(message_len != 0U) {
        rc = noxtls_sha512_update(&ctx, noxtls_message, message_len);
    if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }

    }
        rc = noxtls_sha512_finish(&ctx, ph_digest);
    if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }

        m_body = ph_digest;
        m_len = NOXTLS_ED25519_SHA512_DIGEST_BYTES;
    }

    /*
     * RFC 8032 §5.1.7: decode A; reject if S >= L; compute k = SHA512(R||A||M);
     * check encode([S]B - [k]A) == R. R is not decoded as a curve point for the
     * equation check (wolfSSL-compatible); only its 32 encoding bytes are used.
     */
    {
        uint8_t S_be[NOXTLS_ED25519_FE25519_BYTES];
        noxtls_copy_u8((uint8_t *)(void *)(S_le), (size_t)(NOXTLS_ED25519_FE25519_BYTES), (const uint8_t *)(const void *)(&signature[NOXTLS_ED25519_FE25519_BYTES]), (size_t)(NOXTLS_ED25519_FE25519_BYTES));
        le32_to_be32(S_be, S_le);
        if(ed25519_cmp_be(S_be, ed25519_L, NOXTLS_ED25519_FE25519_BYTES) >= 0) { return NOXTLS_RETURN_FAILED; }
    }

    rc = noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512);
    if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }

    if(dom_len != 0U) {
        rc = noxtls_sha512_update(&ctx, dom_buf, dom_len);
    if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }

    }
    rc = noxtls_sha512_update(&ctx, signature, NOXTLS_ED25519_FE25519_BYTES);
    if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }

    rc = noxtls_sha512_update(&ctx, public_key, NOXTLS_ED25519_FE25519_BYTES);
    if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }

    if(m_len != 0U) {
        rc = noxtls_sha512_update(&ctx, m_body, m_len);
    if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }

    }
    rc = noxtls_sha512_finish(&ctx, k_in);
    if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }

#if NOXTLS_PORT_ED25519_ACCEL
    {
        /* Platform verifier: a definitive answer skips the software group arithmetic. */
        noxtls_return_t port_rc = noxtls_ed25519_verify_accel_port(public_key, signature, k_in);
        if(port_rc == NOXTLS_RETURN_SUCCESS || port_rc == NOXTLS_RETURN_FAILED) { return port_rc; }
    }
#endif
    rc = ge25519_decode_n(&A_n, public_key);
    if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }
    sc25519_reduce(k_le, k_in);

    return ed25519_check_verify_equation(&A_n, signature, k_le, S_le);
}

/**
 * @brief Derives the Ed25519 public key from a 32-byte private key seed (RFC 8032).
 * @param[in]  private_key 32-byte private key / seed.
 * @param[out] public_key 32-byte compressed public key encoding.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_ed25519_public_key(const uint8_t *private_key, uint8_t *public_key)
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
                                                 const uint8_t *seed)
{
    noxtls_return_t rc;

    if(keypair == NULL || seed == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero(keypair, (size_t)(sizeof(*keypair)));
    noxtls_copy_u8((uint8_t *)(void *)(keypair->seed), (size_t)(NOXTLS_ED25519_PRIVATE_KEY_SIZE), (const uint8_t *)(const void *)(seed), (size_t)(NOXTLS_ED25519_PRIVATE_KEY_SIZE));
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
                                           uint8_t *signature)
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
noxtls_return_t noxtls_ed25519_sign(const uint8_t *private_key,
                                     const uint8_t *noxtls_message,
                                     uint32_t message_len,
                                     uint8_t *signature)
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
noxtls_return_t noxtls_ed25519_verify(const uint8_t *public_key,
                                      const uint8_t *noxtls_message,
                                      uint32_t message_len,
                                      const uint8_t *signature)
{
    return ed25519_verify_internal(public_key, noxtls_message, message_len, signature, NOXTLS_ED25519_PH_FLAG_PURE, NULL, 0);
}

static noxtls_return_t ed25519_verify_finalize(const uint8_t *public_key,
                                               const uint8_t *signature,
                                               const uint8_t *k_in)
{
    noxtls_return_t rc;
    uint8_t k_le[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t S_le[NOXTLS_ED25519_FE25519_BYTES];
    ge25519_n_t A_n;

    if(public_key == NULL || signature == NULL || k_in == NULL) { return NOXTLS_RETURN_NULL; }

    {
        uint8_t S_be[NOXTLS_ED25519_FE25519_BYTES];
        noxtls_copy_u8((uint8_t *)(void *)(S_le), (size_t)(NOXTLS_ED25519_FE25519_BYTES), (const uint8_t *)(const void *)(&signature[NOXTLS_ED25519_FE25519_BYTES]), (size_t)(NOXTLS_ED25519_FE25519_BYTES));
        le32_to_be32(S_be, S_le);
        if(ed25519_cmp_be(S_be, ed25519_L, NOXTLS_ED25519_FE25519_BYTES) >= 0) {
            return NOXTLS_RETURN_FAILED;
        }
    }
#if NOXTLS_PORT_ED25519_ACCEL
    {
        /* Platform verifier: a definitive answer skips the software group arithmetic. */
        noxtls_return_t port_rc = noxtls_ed25519_verify_accel_port(public_key, signature, k_in);
        if((port_rc == NOXTLS_RETURN_SUCCESS) || (port_rc == NOXTLS_RETURN_FAILED)) { return port_rc; }
    }
#endif

    rc = ge25519_decode_n(&A_n, public_key);
    if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }

    sc25519_reduce(k_le, k_in);

    return ed25519_check_verify_equation(&A_n, signature, k_le, S_le);
}

noxtls_return_t noxtls_ed25519_verify_stream_init(noxtls_ed25519_verify_stream_ctx_t *ctx,
                                                  const uint8_t *public_key,
                                                  const uint8_t *signature)
{
    noxtls_return_t rc;
    if((ctx == NULL) || (public_key == NULL) || (signature == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero((ctx), sizeof(*(ctx)));
    noxtls_copy_u8((uint8_t *)(void *)(ctx->public_key), (size_t)NOXTLS_ED25519_FE25519_BYTES, (const uint8_t *)(const void *)(public_key), (size_t)NOXTLS_ED25519_FE25519_BYTES);
    noxtls_copy_u8(ctx->signature, sizeof(ctx->signature), signature, (size_t)NOXTLS_ED25519_SIGNATURE_SIZE);

    rc = noxtls_sha512_init(&ctx->hash_ctx, NOXTLS_HASH_SHA_512);
    if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }

    rc = noxtls_sha512_update(&ctx->hash_ctx, signature, NOXTLS_ED25519_FE25519_BYTES);
    if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }

    rc = noxtls_sha512_update(&ctx->hash_ctx, public_key, NOXTLS_ED25519_FE25519_BYTES);
    if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }


    ctx->initialized = 1U;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_ed25519_verify_stream_update(noxtls_ed25519_verify_stream_ctx_t *ctx,
                                                    const uint8_t *message_part,
                                                    uint32_t message_part_len)
{
    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->initialized == 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    if((message_part == NULL) && (message_part_len != 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    if(message_part_len == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }

    return noxtls_sha512_update(&ctx->hash_ctx, message_part, message_part_len);
}

noxtls_return_t noxtls_ed25519_verify_stream_final(noxtls_ed25519_verify_stream_ctx_t *ctx)
{
    uint8_t k_in[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->initialized == 0U) {
        return NOXTLS_RETURN_FAILED;
    }

    rc = noxtls_sha512_finish(&ctx->hash_ctx, k_in);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    ctx->initialized = 0U;
    return ed25519_verify_finalize(ctx->public_key, ctx->signature, k_in);
}

noxtls_return_t noxtls_ed25519_verify_split(const uint8_t *public_key,
                                            const uint8_t *message_part_a,
                                            uint32_t message_part_a_len,
                                            const uint8_t *message_part_b,
                                            uint32_t message_part_b_len,
                                            const uint8_t *signature)
{
    noxtls_ed25519_verify_stream_ctx_t stream_ctx;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    rc = noxtls_ed25519_verify_stream_init(&stream_ctx, public_key, signature);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = noxtls_ed25519_verify_stream_update(&stream_ctx, message_part_a, message_part_a_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = noxtls_ed25519_verify_stream_update(&stream_ctx, message_part_b, message_part_b_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

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
noxtls_return_t noxtls_ed25519ctx_sign(const uint8_t *private_key,
                                       const uint8_t *context,
                                       uint32_t context_len,
                                       const uint8_t *noxtls_message,
                                       uint32_t message_len,
                                       uint8_t *signature)
{
    if((context == NULL) && (context_len != 0U)) { return NOXTLS_RETURN_NULL; }
    if((context_len < 1U) || (context_len > NOXTLS_ED25519_CONTEXT_MAX)) { return NOXTLS_RETURN_INVALID_PARAM; }
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
noxtls_return_t noxtls_ed25519ctx_verify(const uint8_t *public_key,
                                         const uint8_t *context,
                                         uint32_t context_len,
                                         const uint8_t *noxtls_message,
                                         uint32_t message_len,
                                         const uint8_t *signature)
{
    if((context == NULL) && (context_len != 0U)) { return NOXTLS_RETURN_NULL; }
    if((context_len < 1U) || (context_len > NOXTLS_ED25519_CONTEXT_MAX)) { return NOXTLS_RETURN_INVALID_PARAM; }
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
noxtls_return_t noxtls_ed25519ph_sign(const uint8_t *private_key,
                                      const uint8_t *noxtls_message,
                                      uint32_t message_len,
                                      uint8_t *signature)
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
noxtls_return_t noxtls_ed25519ph_verify(const uint8_t *public_key,
                                        const uint8_t *noxtls_message,
                                        uint32_t message_len,
                                        const uint8_t *signature)
{
    return ed25519_verify_internal(public_key, noxtls_message, message_len, signature, NOXTLS_ED25519_PH_FLAG_PREHASH, NULL, 0);
}

/**
 * @brief Generates a random Ed25519 key pair using the library DRBG.
 * @param[out] private_key 32-byte random private key / seed.
 * @param[out] public_key 32-byte derived public key encoding.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_ed25519_generate_key(uint8_t *private_key, uint8_t *public_key)
{
    static drbg_state_t drbg_state;
    static int drbg_initialized = 0;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((private_key == NULL) || (public_key == NULL)) { return NOXTLS_RETURN_NULL; }
    if(drbg_initialized == 0) {
        rc = drbg_instantiate(&drbg_state, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0);
        if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }
        drbg_initialized = 1;
    }
    rc = drbg_generate(&drbg_state, private_key, NOXTLS_ED25519_DRBG_SEED_BITS, NULL, 0);
    if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }
    return noxtls_ed25519_public_key(private_key, public_key);
}
