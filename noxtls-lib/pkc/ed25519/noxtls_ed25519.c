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
#include "mdigest/sha512/noxtls_sha512.h"
#include "noxtls_common.h"
#include "noxtls_ed25519.h"
#include "noxtls_ed25519_ge.h"
#include "noxtls_ed25519_sc.h"
#include "pkc/noxtls_pkc_rng.h"

#if NOXTLS_FEATURE_ED25519

/* L = order of base point = 2^252 + 27742317777372353535851937790883648493, big-endian.
 * Used only for the RFC 8032 S < L canonical check on verify. */
static const uint8_t ed25519_L[NOXTLS_ED25519_FE25519_BYTES] = {
    0x10U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x14U, 0xDEU, 0xF9U, 0xDEU, 0xA2U, 0xF7U, 0x9CU, 0xD6U,
    0x58U, 0x12U, 0x63U, 0x1AU, 0x5CU, 0xF5U, 0xD3U, 0xEDU
};

/* RFC 8032 dom2 prefix (32 bytes, no NUL); avoids MSVC C4295 on char[32] = "..." */
static const uint8_t ed25519_dom2_literal[NOXTLS_ED25519_DOM2_LITERAL_BYTES] = {
    (uint8_t)'S', (uint8_t)'i', (uint8_t)'g', (uint8_t)'E', (uint8_t)'d', (uint8_t)'2', (uint8_t)'5', (uint8_t)'5', (uint8_t)'1', (uint8_t)'9', (uint8_t)' ', (uint8_t)'n', (uint8_t)'o', (uint8_t)' ', (uint8_t)'E', (uint8_t)'d',
    (uint8_t)'2', (uint8_t)'5', (uint8_t)'5', (uint8_t)'1', (uint8_t)'9', (uint8_t)' ', (uint8_t)'c', (uint8_t)'o', (uint8_t)'l', (uint8_t)'l', (uint8_t)'i', (uint8_t)'s', (uint8_t)'i', (uint8_t)'o', (uint8_t)'n', (uint8_t)'s'
};

/**
 * @brief Check the dom2 / prehash parameters shared by sign and verify.
 * @internal
 *
 * @param[in] phflag `NOXTLS_ED25519_PH_FLAG_PURE` or `NOXTLS_ED25519_PH_FLAG_PREHASH`.
 * @param[in] ctx_str Optional context string; may be NULL when @p ctx_len is 0.
 * @param[in] ctx_len Context length; must be 0 for prehash variant.
 *
 * @return `NOXTLS_RETURN_SUCCESS`, `NOXTLS_RETURN_INVALID_PARAM` or `NOXTLS_RETURN_NULL`.
 */
static noxtls_return_t ed25519_check_dom_params(uint8_t phflag,
                                                const uint8_t *ctx_str,
                                                uint32_t ctx_len)
{
    if(phflag > NOXTLS_ED25519_PH_FLAG_PREHASH) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if((phflag == NOXTLS_ED25519_PH_FLAG_PREHASH) && (ctx_len != 0U)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ctx_len > NOXTLS_ED25519_CONTEXT_MAX) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if((ctx_len > 0U) && (ctx_str == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief SHA-512(dom2(phflag, ctx) || a || b || m) with an optional dom2 prefix.
 * @internal
 *
 * dom2 = "SigEd25519 no Ed25519 collisions" || phflag || len(ctx) || ctx
 * (RFC 8032 5.1) is hashed only for Ed25519ctx / Ed25519ph (non-pure flag or
 * a non-empty context), in three pieces instead of through a 289-byte buffer.
 * Zero-length parts are skipped. Kept out of line so the hash context lives
 * only while hashing, not under the group arithmetic of the caller; it is
 * wiped before returning (it holds secret-derived state when signing).
 *
 * @param[out] digest 64-byte SHA-512 output.
 * @param[in] phflag Prehash flag (dom2 octet).
 * @param[in] ctx_str Context string (may be NULL when @p ctx_len is 0).
 * @param[in] ctx_len Context length.
 * @param[in] a First part (may be NULL when @p a_len is 0).
 * @param[in] a_len First part length.
 * @param[in] b Second part (may be NULL when @p b_len is 0).
 * @param[in] b_len Second part length.
 * @param[in] m Message part (may be NULL when @p m_len is 0).
 * @param[in] m_len Message part length.
 *
 * @return `NOXTLS_RETURN_SUCCESS`, or the first failing SHA-512 return code.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static NOXTLS_ED25519_NOINLINE noxtls_return_t ed25519_hash_parts(uint8_t *digest,
                                                                  uint8_t phflag,
                                                                  const uint8_t *ctx_str,
                                                                  uint32_t ctx_len,
                                                                  const uint8_t *a,
                                                                  uint32_t a_len,
                                                                  const uint8_t *b,
                                                                  uint32_t b_len,
                                                                  const uint8_t *m,
                                                                  uint32_t m_len)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    noxtls_sha512_ctx_t ctx;
    uint8_t dom_hdr[NOXTLS_ED25519_DOM2_PREFIX_BYTES - NOXTLS_ED25519_DOM2_LITERAL_BYTES];
    noxtls_return_t rc;

    rc = noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512);
    if((rc == NOXTLS_RETURN_SUCCESS) &&
       ((phflag != NOXTLS_ED25519_PH_FLAG_PURE) || (ctx_len > 0U))) {
        dom_hdr[0] = phflag;
        dom_hdr[1] = (uint8_t)ctx_len;
        rc = noxtls_sha512_update(&ctx, ed25519_dom2_literal, NOXTLS_ED25519_DOM2_LITERAL_BYTES);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_sha512_update(&ctx, dom_hdr, (uint32_t)sizeof(dom_hdr));
        }
        if((rc == NOXTLS_RETURN_SUCCESS) && (ctx_len > 0U)) {
            rc = noxtls_sha512_update(&ctx, ctx_str, ctx_len);
        }
    }
    if((rc == NOXTLS_RETURN_SUCCESS) && (a_len > 0U)) {
        rc = noxtls_sha512_update(&ctx, a, a_len);
    }
    if((rc == NOXTLS_RETURN_SUCCESS) && (b_len > 0U)) {
        rc = noxtls_sha512_update(&ctx, b, b_len);
    }
    if((rc == NOXTLS_RETURN_SUCCESS) && (m_len > 0U)) {
        rc = noxtls_sha512_update(&ctx, m, m_len);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha512_finish(&ctx, digest);
    }
    noxtls_secure_zero(&ctx, sizeof(ctx));
    return rc;
}

/**
 * @brief Encode [s]B (fixed-base, constant time) into 32 bytes.
 * @internal
 *
 * Out of line so the extended-point temporary is not part of the callers'
 * frames (it is live only under the fixed-base multiplication). The point is
 * wiped: for signing it is [r]B with the secret nonce r.
 *
 * @param[out] out 32-byte point encoding.
 * @param[in] s_le Little-endian scalar (clamped or reduced mod L).
 */
static NOXTLS_ED25519_NOINLINE void ed25519_base_encode(uint8_t *out, const uint8_t *s_le)
{
    ge25519_n_t P_n;

    ge25519_scalarmult_base_n(&P_n, s_le);
    ge25519_encode_n(out, &P_n);
    noxtls_secure_zero(&P_n, sizeof(P_n));
}

/**
 * @brief Core Ed25519 signing using an already-expanded key (cached A / s / prefix).
 * @internal
 *
 * Does not recompute A = [s]B. Matches wolfSSL-style cached-pubkey signing.
 * Secret temporaries (nonce digest, nonce r) are wiped before returning.
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
    uint8_t digest[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
    uint8_t r_le[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t k_le[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t ph_digest[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
    const uint8_t *m_body = noxtls_message;
    uint32_t m_len = message_len;
    noxtls_return_t rc;

    if(s_le == NULL || prefix == NULL || public_key == NULL || signature == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(noxtls_message == NULL && message_len != 0U) {
        return NOXTLS_RETURN_NULL;
    }
    rc = ed25519_check_dom_params(phflag, ctx_str, ctx_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(phflag == NOXTLS_ED25519_PH_FLAG_PREHASH) {
        if(ed25519_hash_parts(ph_digest, NOXTLS_ED25519_PH_FLAG_PURE, NULL, 0U, NULL, 0U, NULL, 0U,
                              noxtls_message, message_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
        m_body = ph_digest;
        m_len = NOXTLS_ED25519_SHA512_DIGEST_BYTES;
    }

    /* RFC 8032 §5.1.6: r = SHA-512(dom2 || prefix || M) mod L; R = [r]B. */
    if(ed25519_hash_parts(digest, phflag, ctx_str, ctx_len, prefix, NOXTLS_ED25519_FE25519_BYTES,
                          NULL, 0U, m_body, m_len) != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(digest, sizeof(digest));
        return NOXTLS_RETURN_BAD_DATA;
    }
    sc25519_reduce(r_le, digest);
    ed25519_base_encode(signature, r_le);

    /* k = SHA-512(dom2 || R || A || M) mod L; S = (r + k*s) mod L (ref10 sc_muladd). */
    if(ed25519_hash_parts(digest, phflag, ctx_str, ctx_len, signature, NOXTLS_ED25519_FE25519_BYTES,
                          public_key, NOXTLS_ED25519_FE25519_BYTES, m_body, m_len) != NOXTLS_RETURN_SUCCESS) {
        rc = NOXTLS_RETURN_INVALID_BLOCK_SIZE;
    } else {
        sc25519_reduce(k_le, digest);
        sc25519_muladd(&signature[NOXTLS_ED25519_FE25519_BYTES], k_le, s_le, r_le);
    }
    noxtls_secure_zero(digest, sizeof(digest));
    noxtls_secure_zero(r_le, sizeof(r_le));
    return rc;
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

    if(seed == NULL || s_le == NULL || prefix == NULL || public_key == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    /* RFC 8032 §5.1.5: SHA-512(seed); clamp s; A = [s]B. */
    if(ed25519_hash_parts(h, NOXTLS_ED25519_PH_FLAG_PURE, NULL, 0U, seed, NOXTLS_ED25519_FE25519_BYTES,
                          NULL, 0U, NULL, 0U) != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(h, sizeof(h));
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    h[0] &= NOXTLS_ED25519_SCALAR_CLAMP_BYTE0_MASK;
    h[NOXTLS_ED25519_FE25519_BYTES - 1U] &= NOXTLS_ED25519_SCALAR_CLAMP_BYTE31_AND;
    h[NOXTLS_ED25519_FE25519_BYTES - 1U] |= NOXTLS_ED25519_SCALAR_CLAMP_BYTE31_OR;
    noxtls_copy_u8((uint8_t *)(void *)(s_le), (size_t)(NOXTLS_ED25519_FE25519_BYTES), (const uint8_t *)(const void *)(h), (size_t)(NOXTLS_ED25519_FE25519_BYTES));
    noxtls_copy_u8((uint8_t *)(void *)(prefix), (size_t)(NOXTLS_ED25519_FE25519_BYTES), (const uint8_t *)(const void *)(&h[NOXTLS_ED25519_FE25519_BYTES]), (size_t)(NOXTLS_ED25519_FE25519_BYTES));
    noxtls_secure_zero(h, sizeof(h));
    ed25519_base_encode(public_key, s_le);
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
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = ed25519_sign_expanded(s_le, prefix, public_key, noxtls_message, message_len,
                                   signature, phflag, ctx_str, ctx_len);
    }
    noxtls_secure_zero(prefix, sizeof(prefix));
    noxtls_secure_zero(s_le, sizeof(s_le));
    return rc;
}

/**
 * @brief RFC 8032 §5.1.7 canonical-S check: S (signature octets 32..63, LE) < L.
 * @internal
 *
 * @param[in] signature 64-byte signature.
 *
 * @return 1 if S < L, else 0. Variable time (public data).
 */
static int ed25519_s_is_canonical(const uint8_t *signature)
{
    uint32_t i;
    for(i = 0U; i < NOXTLS_ED25519_FE25519_BYTES; i++) {
        const uint8_t s_byte = signature[(2U * NOXTLS_ED25519_FE25519_BYTES) - 1U - i];
        if(s_byte != ed25519_L[i]) {
            return (s_byte < ed25519_L[i]) ? 1 : 0;
        }
    }
    return 0;
}

/**
 * @brief Check [S]B - [k]A == R by encoding (RFC 8032 §5.1.7 / wolfSSL path).
 * @internal
 *
 * Does not decode R: after @c double_scalarmult computes [S]B + [k](-A),
 * encodes once and compares to @p R_bytes (`signature[0..31]`). Matches
 * RFC 8032 §5.1.7 equation check as implemented by wolfSSL (encode result vs
 * signature R octets).
 *
 * @param[in] Aneg Decoded and negated public point -A (native).
 * @param[in] R_bytes Commitment R as 32 wire bytes (not decoded as a point).
 * @param[in] k_le Challenge scalar (little-endian).
 * @param[in] S_le Response scalar (little-endian), already checked S < L.
 *
 * @return `NOXTLS_RETURN_SUCCESS` if the equation holds, else `NOXTLS_RETURN_FAILED`.
 */
static NOXTLS_ED25519_NOINLINE noxtls_return_t ed25519_check_verify_equation(const ge25519_n_t *Aneg,
                                                                             const uint8_t *R_bytes,
                                                                             const uint8_t *k_le,
                                                                             const uint8_t *S_le)
{
    ge25519_n_t check;
    uint8_t enc_check[NOXTLS_ED25519_FE25519_BYTES];

    /* check = [k](-A) + [S]B = [S]B - [k]A  (RFC 8032 §5.1.7) */
    ge25519_double_scalarmult_n(&check, k_le, Aneg, S_le);
    ge25519_encode_n(enc_check, &check);

    if(noxtls_secret_memcmp(enc_check, R_bytes, NOXTLS_ED25519_FE25519_BYTES) == 0) {
        return NOXTLS_RETURN_SUCCESS;
    }
    return NOXTLS_RETURN_FAILED;
}

/**
 * @brief Finish a verification from the challenge digest k = SHA-512(dom2 || R || A || M).
 * @internal
 *
 * Shared by the one-shot and streaming verifiers; out of line so the callers'
 * hash contexts are not stacked under the group arithmetic.
 *
 * @param[in] public_key 32-byte public key encoding.
 * @param[in] signature 64-byte signature.
 * @param[in] k_in 64-byte challenge digest.
 *
 * @return `NOXTLS_RETURN_SUCCESS` if valid, otherwise an error `noxtls_return_t`.
 */
static NOXTLS_ED25519_NOINLINE noxtls_return_t ed25519_verify_finalize(const uint8_t *public_key,
                                                                       const uint8_t *signature,
                                                                       const uint8_t *k_in)
{
    noxtls_return_t rc;
    uint8_t k_le[NOXTLS_ED25519_FE25519_BYTES];
    ge25519_n_t A_n;

    if(public_key == NULL || signature == NULL || k_in == NULL) { return NOXTLS_RETURN_NULL; }

    if(ed25519_s_is_canonical(signature) == 0) {
        return NOXTLS_RETURN_FAILED;
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
    ge25519_n_neg(&A_n, &A_n);

    return ed25519_check_verify_equation(&A_n, signature, k_le, &signature[NOXTLS_ED25519_FE25519_BYTES]);
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
    uint8_t ph_digest[NOXTLS_ED25519_SHA512_DIGEST_BYTES];
    const uint8_t *m_body = noxtls_message;
    uint32_t m_len = message_len;

    if((public_key == NULL) || (signature == NULL)) { return NOXTLS_RETURN_NULL; }
    if((noxtls_message == NULL) && (message_len != 0U)) { return NOXTLS_RETURN_NULL; }
    rc = ed25519_check_dom_params(phflag, ctx_str, ctx_len);
    if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }

    if(phflag == NOXTLS_ED25519_PH_FLAG_PREHASH) {
        rc = ed25519_hash_parts(ph_digest, NOXTLS_ED25519_PH_FLAG_PURE, NULL, 0U, NULL, 0U, NULL, 0U,
                                noxtls_message, message_len);
        if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }
        m_body = ph_digest;
        m_len = NOXTLS_ED25519_SHA512_DIGEST_BYTES;
    }

    /*
     * RFC 8032 §5.1.7: decode A; reject if S >= L; compute k = SHA512(R||A||M);
     * check encode([S]B - [k]A) == R. R is not decoded as a curve point for the
     * equation check (wolfSSL-compatible); only its 32 encoding bytes are used.
     * S is checked before hashing so non-canonical signatures are rejected early.
     */
    if(ed25519_s_is_canonical(signature) == 0) { return NOXTLS_RETURN_FAILED; }

    rc = ed25519_hash_parts(k_in, phflag, ctx_str, ctx_len, signature, NOXTLS_ED25519_FE25519_BYTES,
                            public_key, NOXTLS_ED25519_FE25519_BYTES, m_body, m_len);
    if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }

    return ed25519_verify_finalize(public_key, signature, k_in);
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
    noxtls_return_t rc;

    rc = ed25519_expand_seed(private_key, s_le, prefix, public_key);
    noxtls_secure_zero(s_le, sizeof(s_le));
    noxtls_secure_zero(prefix, sizeof(prefix));
    return rc;
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
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((private_key == NULL) || (public_key == NULL)) { return NOXTLS_RETURN_NULL; }
    /* Shared PKC CTR-DRBG seeded from noxtls_drbg_get_entropy() (the same source
     * drbg_instantiate() used for the former NULL-entropy private instance);
     * a failed generate fails closed, wipes the seed and re-instantiates next call. */
    rc = noxtls_pkc_rng_generate(NOXTLS_PKC_RNG_SLOT_ED25519, private_key, NOXTLS_ED25519_DRBG_SEED_BITS);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = noxtls_ed25519_public_key(private_key, public_key);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(private_key, (size_t)(NOXTLS_ED25519_DRBG_SEED_BITS / 8U));
    }
    return rc;
}

#endif /* NOXTLS_FEATURE_ED25519 */
