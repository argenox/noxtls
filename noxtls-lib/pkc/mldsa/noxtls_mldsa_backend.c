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
* File:    noxtls_mldsa_backend.c
* Summary: ML-DSA KeyGen_internal, Sign_internal and Verify_internal
*          (FIPS 204 Alg. 6-8) in a streaming, low-RAM form.
*
* Memory strategy
*   - The matrix A is never materialised: every entry A[i][j] is regenerated
*     from rho when it is consumed (one polynomial of scratch).
*   - Secret polynomials s1, s2, t0 are unpacked from the encoded secret key
*     one polynomial at a time.
*   - Signing keeps only w (k polynomials) between the commitment and the
*     hint computation; y is regenerated from rho'' instead of being stored,
*     and z / the hint are written straight into the signature buffer.
*   - Verification keeps NTT(z) (l polynomials) and streams w1' into SHAKE256.
*   All large state lives in a caller-provided workspace of 1 KiB polynomials.
*
*****************************************************************************/

#include <stdint.h>
#include <stddef.h>

#include "noxtls_mldsa_internal.h"

#if NOXTLS_FEATURE_ML_DSA

#include "noxtls_ct.h"

/**
 * @brief Workspace bytes needed by noxtls_mldsa_backend_keygen.
 * @param[in] spec Parameter set.
 * @return Size in bytes.
 */
uint32_t noxtls_mldsa_backend_keygen_ws_len(const noxtls_mldsa_param_spec_t *spec)
{
    (void)spec;
    return 3U * NOXTLS_MLDSA_POLY_BYTES;
}

/**
 * @brief Workspace bytes needed by noxtls_mldsa_backend_sign.
 * @param[in] spec Parameter set.
 * @return Size in bytes.
 */
uint32_t noxtls_mldsa_backend_sign_ws_len(const noxtls_mldsa_param_spec_t *spec)
{
    return (spec->k + 3U) * NOXTLS_MLDSA_POLY_BYTES;
}

/**
 * @brief Workspace bytes needed by noxtls_mldsa_backend_verify.
 * @param[in] spec Parameter set.
 * @return Size in bytes.
 */
uint32_t noxtls_mldsa_backend_verify_ws_len(const noxtls_mldsa_param_spec_t *spec)
{
    return (spec->l + 3U) * NOXTLS_MLDSA_POLY_BYTES;
}

/**
 * @brief ML-DSA.KeyGen_internal(xi).
 *
 * @param[in] spec Parameter set.
 * @param[in] xi 32-byte seed.
 * @param[out] public_key Encoded public key (spec->public_key_len bytes).
 * @param[out] secret_key Encoded secret key (spec->secret_key_len bytes).
 * @param[in] ws Workspace of noxtls_mldsa_backend_keygen_ws_len() bytes.
 * @return NOXTLS_RETURN_SUCCESS or a hashing error.
 */
noxtls_return_t noxtls_mldsa_backend_keygen(const noxtls_mldsa_param_spec_t *spec,
                                            const uint8_t xi[NOXTLS_MLDSA_SEEDBYTES],
                                            uint8_t *public_key,
                                            uint8_t *secret_key,
                                            noxtls_mldsa_poly_t *ws)
{
    noxtls_mldsa_poly_t *acc = &ws[0];
    noxtls_mldsa_poly_t *a_tmp = &ws[1];
    noxtls_mldsa_poly_t *v = &ws[2];
    uint8_t seed_in[NOXTLS_MLDSA_SEEDBYTES + 2U];
    uint8_t seeds[2U * NOXTLS_MLDSA_SEEDBYTES + NOXTLS_MLDSA_CRHBYTES];
    const uint8_t *rho = &seeds[0];
    const uint8_t *rhoprime = &seeds[NOXTLS_MLDSA_SEEDBYTES];
    const uint8_t *key = &seeds[NOXTLS_MLDSA_SEEDBYTES + NOXTLS_MLDSA_CRHBYTES];
    uint32_t i = 0U;
    uint32_t j = 0U;
    uint32_t c = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    noxtls_copy_u8(seed_in, sizeof(seed_in), xi, NOXTLS_MLDSA_SEEDBYTES);
    seed_in[NOXTLS_MLDSA_SEEDBYTES] = (uint8_t)spec->k;
    seed_in[NOXTLS_MLDSA_SEEDBYTES + 1U] = (uint8_t)spec->l;
    rc = noxtls_mldsa_shake256(seeds, (uint32_t)sizeof(seeds), seed_in, (uint32_t)sizeof(seed_in), NULL, 0U);

    if(rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_copy_u8(public_key, NOXTLS_MLDSA_SEEDBYTES, rho, NOXTLS_MLDSA_SEEDBYTES);
        noxtls_copy_u8(secret_key, NOXTLS_MLDSA_SEEDBYTES, rho, NOXTLS_MLDSA_SEEDBYTES);
        noxtls_copy_u8(&secret_key[NOXTLS_MLDSA_SEEDBYTES], NOXTLS_MLDSA_SEEDBYTES, key, NOXTLS_MLDSA_SEEDBYTES);
    }
    /* s1 and s2 go straight into the secret key encoding. */
    for(j = 0U; (rc == NOXTLS_RETURN_SUCCESS) && (j < (spec->l + spec->k)); j += 1U) {
        rc = noxtls_mldsa_poly_uniform_eta(spec, v, rhoprime, j);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_mldsa_polyeta_pack(spec, &secret_key[noxtls_mldsa_sk_s1_offset(spec, j)], v);
        }
    }
    /* t = NTT^-1(A o NTT(s1)) + s2, one row at a time. */
    for(i = 0U; (rc == NOXTLS_RETURN_SUCCESS) && (i < spec->k); i += 1U) {
        noxtls_mldsa_poly_zero(acc);
        for(j = 0U; (rc == NOXTLS_RETURN_SUCCESS) && (j < spec->l); j += 1U) {
            noxtls_mldsa_polyeta_unpack(spec, v, &secret_key[noxtls_mldsa_sk_s1_offset(spec, j)]);
            noxtls_mldsa_poly_ntt(v);
            rc = noxtls_mldsa_matrix_acc(acc, a_tmp, rho, i, j, v);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_mldsa_poly_reduce(acc);
            noxtls_mldsa_poly_invntt_tomont(acc);
            noxtls_mldsa_polyeta_unpack(spec, v, &secret_key[noxtls_mldsa_sk_s2_offset(spec, i)]);
            noxtls_mldsa_poly_add(acc, v);
            noxtls_mldsa_poly_caddq(acc);
            for(c = 0U; c < NOXTLS_MLDSA_N; c += 1U) {
                a_tmp->coeff[c] = noxtls_mldsa_power2round(acc->coeff[c], &v->coeff[c]);
            }
            noxtls_mldsa_bitpack(&public_key[NOXTLS_MLDSA_SEEDBYTES + (i * NOXTLS_MLDSA_POLYT1_BYTES)],
                                 a_tmp, 10U, 0, 0U);
            noxtls_mldsa_bitpack(&secret_key[noxtls_mldsa_sk_t0_offset(spec, i)],
                                 v, NOXTLS_MLDSA_D, (int32_t)1 << (NOXTLS_MLDSA_D - 1U), 1U);
        }
    }
    /* tr = H(pk, 64) */
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_mldsa_shake256(&secret_key[2U * NOXTLS_MLDSA_SEEDBYTES], NOXTLS_MLDSA_TRBYTES,
                                   public_key, spec->public_key_len, NULL, 0U);
    }
    noxtls_secure_zero(seed_in, sizeof(seed_in));
    noxtls_secure_zero(seeds, sizeof(seeds));
    return rc;
}

/**
 * @brief One signing attempt for nonce offset kappa.
 *
 * @param[in] spec Parameter set.
 * @param[in] secret_key Encoded secret key.
 * @param[in] mu Message representative.
 * @param[in] rhopp Private random seed rho''.
 * @param[in] kappa ExpandMask nonce offset.
 * @param[out] signature Signature buffer (overwritten on every attempt).
 * @param[in] ws Workspace (k + 3 polynomials).
 * @param[out] accepted 1 when the attempt produced a valid signature.
 * @return NOXTLS_RETURN_SUCCESS (check *accepted) or a hashing error.
 */
static noxtls_return_t mldsa_sign_attempt(const noxtls_mldsa_param_spec_t *spec,
                                          const uint8_t *secret_key,
                                          const uint8_t mu[NOXTLS_MLDSA_MUBYTES],
                                          const uint8_t rhopp[NOXTLS_MLDSA_CRHBYTES],
                                          uint32_t kappa,
                                          uint8_t *signature,
                                          noxtls_mldsa_poly_t *ws,
                                          uint32_t *accepted)
{
    noxtls_mldsa_poly_t *w = &ws[0];
    noxtls_mldsa_poly_t *chat = &ws[spec->k];
    noxtls_mldsa_poly_t *t1 = &ws[spec->k + 1U];
    noxtls_mldsa_poly_t *t2 = &ws[spec->k + 2U];
    const uint8_t *rho = secret_key;
    uint8_t *zsig = &signature[spec->ctilde_len];
    uint8_t *hsig = &signature[spec->ctilde_len + (spec->l * spec->poly_z_bytes)];
    uint8_t w1buf[192];
    noxtls_sha3_ctx_t ctx;
    uint32_t i = 0U;
    uint32_t j = 0U;
    uint32_t c = 0U;
    uint32_t n = 0U;
    uint32_t ok = 1U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    *accepted = 0U;

    /* w = NTT^-1(A o NTT(y)), column by column so y_j is generated once. */
    for(i = 0U; i < spec->k; i += 1U) {
        noxtls_mldsa_poly_zero(&w[i]);
    }
    for(j = 0U; (rc == NOXTLS_RETURN_SUCCESS) && (j < spec->l); j += 1U) {
        rc = noxtls_mldsa_poly_uniform_gamma1(spec, t1, rhopp, kappa + j);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_mldsa_poly_ntt(t1);
        }
        for(i = 0U; (rc == NOXTLS_RETURN_SUCCESS) && (i < spec->k); i += 1U) {
            rc = noxtls_mldsa_matrix_acc(&w[i], t2, rho, i, j, t1);
        }
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    for(i = 0U; i < spec->k; i += 1U) {
        noxtls_mldsa_poly_reduce(&w[i]);
        noxtls_mldsa_poly_invntt_tomont(&w[i]);
        noxtls_mldsa_poly_caddq(&w[i]);
    }

    /* c~ = H(mu || w1Encode(HighBits(w))) */
    rc = noxtls_shake256_init(&ctx);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_update(&ctx, mu, NOXTLS_MLDSA_MUBYTES);
    }
    for(i = 0U; (rc == NOXTLS_RETURN_SUCCESS) && (i < spec->k); i += 1U) {
        noxtls_mldsa_polyw1_pack(spec, w1buf, &w[i], NULL, 0U, 0U);
        rc = noxtls_shake256_update(&ctx, w1buf, spec->poly_w1_bytes);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_final(&ctx);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_squeeze(&ctx, signature, spec->ctilde_len);
    }
    noxtls_secure_zero(&ctx, sizeof(ctx));
    noxtls_secure_zero(w1buf, sizeof(w1buf));
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_mldsa_poly_challenge(spec, chat, signature);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    noxtls_mldsa_poly_ntt(chat);

    /* z = y + c*s1, checked and encoded polynomial by polynomial. */
    for(j = 0U; (ok != 0U) && (j < spec->l); j += 1U) {
        noxtls_mldsa_polyeta_unpack(spec, t1, &secret_key[noxtls_mldsa_sk_s1_offset(spec, j)]);
        noxtls_mldsa_poly_ntt(t1);
        noxtls_mldsa_poly_pointwise_montgomery(t1, chat, t1);
        noxtls_mldsa_poly_invntt_tomont(t1);
        rc = noxtls_mldsa_poly_uniform_gamma1(spec, t2, rhopp, kappa + j);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        noxtls_mldsa_poly_add(t1, t2);
        noxtls_mldsa_poly_reduce(t1);
        if(noxtls_mldsa_poly_chknorm(t1, spec->gamma1 - spec->beta) != 0U) {
            ok = 0U;
        } else {
            noxtls_mldsa_polyz_pack(spec, &zsig[j * spec->poly_z_bytes], t1);
        }
    }

    /* Low-bits check, c*t0 check and hint, row by row. */
    noxtls_fill_u8(hsig, spec->omega + spec->k, 0U, spec->omega + spec->k);
    for(i = 0U; (ok != 0U) && (i < spec->k); i += 1U) {
        /* t1 <- c*s2 */
        noxtls_mldsa_polyeta_unpack(spec, t1, &secret_key[noxtls_mldsa_sk_s2_offset(spec, i)]);
        noxtls_mldsa_poly_ntt(t1);
        noxtls_mldsa_poly_pointwise_montgomery(t1, chat, t1);
        noxtls_mldsa_poly_invntt_tomont(t1);
        /* t2 <- c*t0 */
        noxtls_mldsa_bitunpack(t2, &secret_key[noxtls_mldsa_sk_t0_offset(spec, i)],
                               NOXTLS_MLDSA_D, (int32_t)1 << (NOXTLS_MLDSA_D - 1U), 1U);
        noxtls_mldsa_poly_ntt(t2);
        noxtls_mldsa_poly_pointwise_montgomery(t2, chat, t2);
        noxtls_mldsa_poly_invntt_tomont(t2);
        noxtls_mldsa_poly_reduce(t2);
        if(noxtls_mldsa_poly_chknorm(t2, spec->gamma2) != 0U) {
            ok = 0U;
        }
        if(ok != 0U) {
            /* t1 <- r0 = LowBits(w) - c*s2 */
            for(c = 0U; c < NOXTLS_MLDSA_N; c += 1U) {
                int32_t a0 = 0;

                (void)noxtls_mldsa_decompose(w[i].coeff[c], spec->gamma2, &a0);
                t1->coeff[c] = noxtls_mldsa_reduce32(a0 - t1->coeff[c]);
            }
            if(noxtls_mldsa_poly_chknorm(t1, spec->gamma2 - spec->beta) != 0U) {
                ok = 0U;
            }
        }
        for(c = 0U; (ok != 0U) && (c < NOXTLS_MLDSA_N); c += 1U) {
            int32_t a0 = 0;
            int32_t a1 = noxtls_mldsa_decompose(w[i].coeff[c], spec->gamma2, &a0);

            if(noxtls_mldsa_make_hint(t1->coeff[c] + t2->coeff[c], a1, spec->gamma2) != 0U) {
                if(n >= spec->omega) {
                    ok = 0U;
                } else {
                    hsig[n] = (uint8_t)c;
                    n += 1U;
                }
            }
        }
        hsig[spec->omega + i] = (uint8_t)n;
    }
    *accepted = ok;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief ML-DSA.Sign_internal with a precomputed message representative mu.
 *
 * @param[in] spec Parameter set.
 * @param[in] secret_key Encoded secret key.
 * @param[in] mu 64-byte message representative.
 * @param[in] rnd 32 bytes of fresh randomness (all-zero for deterministic signing).
 * @param[out] signature Output signature (spec->signature_len bytes).
 * @param[in] ws Workspace of noxtls_mldsa_backend_sign_ws_len() bytes.
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_FAILED (attempt cap) or a hashing error.
 */
noxtls_return_t noxtls_mldsa_backend_sign(const noxtls_mldsa_param_spec_t *spec,
                                          const uint8_t *secret_key,
                                          const uint8_t mu[NOXTLS_MLDSA_MUBYTES],
                                          const uint8_t rnd[NOXTLS_MLDSA_RND_LEN],
                                          uint8_t *signature,
                                          noxtls_mldsa_poly_t *ws)
{
    uint8_t keyrnd[NOXTLS_MLDSA_SEEDBYTES + NOXTLS_MLDSA_RND_LEN];
    uint8_t rhopp[NOXTLS_MLDSA_CRHBYTES];
    uint32_t attempt = 0U;
    uint32_t accepted = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    noxtls_copy_u8(keyrnd, sizeof(keyrnd), &secret_key[NOXTLS_MLDSA_SEEDBYTES], NOXTLS_MLDSA_SEEDBYTES);
    noxtls_copy_u8(&keyrnd[NOXTLS_MLDSA_SEEDBYTES], NOXTLS_MLDSA_RND_LEN, rnd, NOXTLS_MLDSA_RND_LEN);
    rc = noxtls_mldsa_shake256(rhopp, NOXTLS_MLDSA_CRHBYTES, keyrnd, (uint32_t)sizeof(keyrnd),
                               mu, NOXTLS_MLDSA_MUBYTES);
    noxtls_secure_zero(keyrnd, sizeof(keyrnd));

    for(attempt = 0U; (rc == NOXTLS_RETURN_SUCCESS) && (accepted == 0U) &&
                      (attempt < NOXTLS_MLDSA_SIGN_MAX_ATTEMPTS); attempt += 1U) {
        rc = mldsa_sign_attempt(spec, secret_key, mu, rhopp, attempt * spec->l, signature, ws, &accepted);
    }
    noxtls_secure_zero(rhopp, sizeof(rhopp));
    if((rc == NOXTLS_RETURN_SUCCESS) && (accepted == 0U)) {
        rc = NOXTLS_RETURN_FAILED;
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(signature, spec->signature_len);
    }
    return rc;
}

/**
 * @brief ML-DSA.Verify_internal with a precomputed message representative mu.
 *
 * @param[in] spec Parameter set.
 * @param[in] public_key Encoded public key.
 * @param[in] mu 64-byte message representative (computed with tr = H(pk)).
 * @param[in] signature Signature of exactly spec->signature_len bytes.
 * @param[in] ws Workspace of noxtls_mldsa_backend_verify_ws_len() bytes.
 * @return NOXTLS_RETURN_SUCCESS if valid, NOXTLS_RETURN_FAILED if invalid, or a hashing error.
 */
noxtls_return_t noxtls_mldsa_backend_verify(const noxtls_mldsa_param_spec_t *spec,
                                            const uint8_t *public_key,
                                            const uint8_t mu[NOXTLS_MLDSA_MUBYTES],
                                            const uint8_t *signature,
                                            noxtls_mldsa_poly_t *ws)
{
    noxtls_mldsa_poly_t *zhat = &ws[0];
    noxtls_mldsa_poly_t *chat = &ws[spec->l];
    noxtls_mldsa_poly_t *acc = &ws[spec->l + 1U];
    noxtls_mldsa_poly_t *tmp = &ws[spec->l + 2U];
    const uint8_t *rho = public_key;
    const uint8_t *zsig = &signature[spec->ctilde_len];
    const uint8_t *hsig = &signature[spec->ctilde_len + (spec->l * spec->poly_z_bytes)];
    uint8_t w1buf[192];
    uint8_t c2[64];
    noxtls_sha3_ctx_t ctx;
    uint32_t i = 0U;
    uint32_t j = 0U;
    noxtls_return_t rc = noxtls_mldsa_hint_validate(spec, hsig);

    for(j = 0U; (rc == NOXTLS_RETURN_SUCCESS) && (j < spec->l); j += 1U) {
        noxtls_mldsa_polyz_unpack(spec, &zhat[j], &zsig[j * spec->poly_z_bytes]);
        if(noxtls_mldsa_poly_chknorm(&zhat[j], spec->gamma1 - spec->beta) != 0U) {
            rc = NOXTLS_RETURN_FAILED;
        } else {
            noxtls_mldsa_poly_ntt(&zhat[j]);
        }
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_mldsa_poly_challenge(spec, chat, signature);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    noxtls_mldsa_poly_ntt(chat);

    rc = noxtls_shake256_init(&ctx);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_update(&ctx, mu, NOXTLS_MLDSA_MUBYTES);
    }
    for(i = 0U; (rc == NOXTLS_RETURN_SUCCESS) && (i < spec->k); i += 1U) {
        uint32_t start = (i == 0U) ? 0U : (uint32_t)hsig[spec->omega + i - 1U];
        uint32_t end = (uint32_t)hsig[spec->omega + i];

        noxtls_mldsa_poly_zero(acc);
        for(j = 0U; (rc == NOXTLS_RETURN_SUCCESS) && (j < spec->l); j += 1U) {
            rc = noxtls_mldsa_matrix_acc(acc, tmp, rho, i, j, &zhat[j]);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            /* acc -= c * t1 * 2^d */
            noxtls_mldsa_bitunpack(tmp, &public_key[NOXTLS_MLDSA_SEEDBYTES + (i * NOXTLS_MLDSA_POLYT1_BYTES)],
                                   10U, 0, 0U);
            noxtls_mldsa_poly_shiftl(tmp);
            noxtls_mldsa_poly_ntt(tmp);
            noxtls_mldsa_poly_pointwise_montgomery(tmp, chat, tmp);
            noxtls_mldsa_poly_sub(acc, tmp);
            noxtls_mldsa_poly_reduce(acc);
            noxtls_mldsa_poly_invntt_tomont(acc);
            noxtls_mldsa_poly_caddq(acc);
            noxtls_mldsa_polyw1_pack(spec, w1buf, acc, hsig, start, end);
            rc = noxtls_shake256_update(&ctx, w1buf, spec->poly_w1_bytes);
        }
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_final(&ctx);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_shake256_squeeze(&ctx, c2, spec->ctilde_len);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = (noxtls_ct_memcmp(c2, signature, (size_t)spec->ctilde_len) == 0) ?
             NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
    }
    noxtls_secure_zero(&ctx, sizeof(ctx));
    return rc;
}

#endif /* NOXTLS_FEATURE_ML_DSA */
