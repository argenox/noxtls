/*****************************************************************************
* This file is part of the NoxTLS Library.
*/

﻿/*
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* References
 * ==========
 *
 * - [FIPS140_3_IG]
 *   Implementation Guidance for FIPS 140-3 and the Cryptographic Module
 *   Validation Program
 *   National Institute of Standards and Technology
 *   https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-3-ig-announcements
 *
 * - [FIPS204]
 *   FIPS 204 Module-Lattice-Based Digital Signature Standard
 *   National Institute of Standards and Technology
 *   https://csrc.nist.gov/pubs/fips/204/final
 *
 * - [Round3_Spec]
 *   CRYSTALS-Dilithium Algorithm Specifications and Supporting Documentation
 *   (Version 3.1)
 *   Bai, Ducas, Kiltz, Lepoint, Lyubashevsky, Schwabe, Seiler, StehlÃƒÂ©
 *   https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf
 */

#if defined(MLD_CONFIG_PARAMETER_SET)

#include "noxtls_sign.h"

#include "noxtls_cbmc.h"
#include "noxtls_ct.h"
#include "noxtls_debug.h"
#include "noxtls_packing.h"
#include "noxtls_poly.h"
#include "noxtls_poly_kl.h"
#include "noxtls_polyvec.h"
#include "noxtls_randombytes.h"
#include "noxtls_symmetric.h"

/* Parameter set namespacing
 * This is to facilitate building multiple instances
 * of mldsa-native (e.g. with varying parameter sets)
 * within a single compilation unit. */
#define noxtls_mld_check_pct MLD_ADD_PARAM_SET(noxtls_mld_check_pct) MLD_CONTEXT_PARAMETERS_2
#define noxtls_mld_sample_s1_s2 MLD_ADD_PARAM_SET(noxtls_mld_sample_s1_s2)
#define noxtls_mld_validate_hash_length MLD_ADD_PARAM_SET(noxtls_mld_validate_hash_length)
#define noxtls_mld_get_hash_oid MLD_ADD_PARAM_SET(noxtls_mld_get_hash_oid)
#define noxtls_mld_H MLD_ADD_PARAM_SET(noxtls_mld_H)
#define noxtls_mld_compute_pack_z MLD_ADD_PARAM_SET(noxtls_mld_compute_pack_z)
#define noxtls_mld_attempt_signature_generation \
  MLD_ADD_PARAM_SET(noxtls_mld_attempt_signature_generation) MLD_CONTEXT_PARAMETERS_8
#define noxtls_mld_compute_t0_t1_tr_from_sk_components              \
  MLD_ADD_PARAM_SET(noxtls_mld_compute_t0_t1_tr_from_sk_components) \
  MLD_CONTEXT_PARAMETERS_7
/* End of parameter set namespacing */


static int noxtls_mld_check_pct(uint8_t const pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                         uint8_t const sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                         MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
__contract__(
  requires(memory_no_alias(pk, MLDSA_CRYPTO_PUBLICKEYBYTES))
  requires(memory_no_alias(sk, MLDSA_CRYPTO_SECRETKEYBYTES))
  ensures(return_value == 0
	  || return_value == MLD_ERR_FAIL
	  || return_value == MLD_ERR_OUT_OF_MEMORY
    || return_value == MLD_ERR_RNG_FAIL)
);

#if defined(MLD_CONFIG_KEYGEN_PCT)
/*************************************************
 * @[FIPS140_3_IG]
 * (https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf)
 *
 * TE10.35.02: Pair-wise Consistency Test (PCT) for DSA keypairs
 *
 * Purpose: Validates that a generated public/private key pair can correctly
 * sign and verify data. Test performs signature generation using the private
 * key (sk), followed by signature verification using the public key (pk).
 * Returns 0 if the signature was successfully verified, non-zero if it cannot.
 *
 * Note: @[FIPS204] requires that public/private key pairs are to be used only
 * for the calculation and/of verification of digital signatures.
 **************************************************/
static int noxtls_mld_check_pct(uint8_t const pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                         uint8_t const sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                         MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  MLD_ALIGN uint8_t noxtls_message[1] = {0};
  size_t siglen;
  int ret;
  MLD_ALLOC(signature, uint8_t, MLDSA_CRYPTO_BYTES, context);
  MLD_ALLOC(pk_test, uint8_t, MLDSA_CRYPTO_PUBLICKEYBYTES, context);

  if(signature == NULL || pk_test == NULL)
  {
    ret = MLD_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  /* Copy public key for testing */
  noxtls_mld_memcpy(pk_test, pk, MLDSA_CRYPTO_PUBLICKEYBYTES);

  /* Sign a test noxtls_message using the original secret key */
  ret = noxtls_mld_sign_signature(signature, &siglen, noxtls_message, sizeof(noxtls_message), NULL,
                           0, sk, context);
  if(ret != 0)
  {
    goto cleanup;
  }

#if defined(MLD_CONFIG_KEYGEN_PCT_BREAKAGE_TEST)
  /* Deliberately break public key for testing purposes */
  if(noxtls_mld_break_pct())
  {
    pk_test[0] = ~pk_test[0];
  }
#endif /* MLD_CONFIG_KEYGEN_PCT_BREAKAGE_TEST */

  /* Verify the signature using the (potentially corrupted) public key */
  ret = noxtls_mld_sign_verify(signature, siglen, noxtls_message, sizeof(noxtls_message), NULL, 0,
                        pk_test, context);

cleanup:
  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  MLD_FREE(pk_test, uint8_t, MLDSA_CRYPTO_PUBLICKEYBYTES, context);
  MLD_FREE(signature, uint8_t, MLDSA_CRYPTO_BYTES, context);

  return ret;
}
#else /* MLD_CONFIG_KEYGEN_PCT */
static int noxtls_mld_check_pct(uint8_t const pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                         uint8_t const sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                         MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  /* Skip PCT */
  ((void)pk);
  ((void)sk);
#if defined(MLD_CONFIG_CONTEXT_PARAMETER)
  ((void)context);
#endif
  return 0;
}
#endif /* !MLD_CONFIG_KEYGEN_PCT */

static void noxtls_mld_sample_s1_s2(noxtls_mld_polyvecl *s1, noxtls_mld_polyveck *s2,
                             const uint8_t seed[MLDSA_CRHBYTES])
__contract__(
  requires(memory_no_alias(s1, sizeof(noxtls_mld_polyvecl)))
  requires(memory_no_alias(s2, sizeof(noxtls_mld_polyveck)))
  requires(memory_no_alias(seed, MLDSA_CRHBYTES))
  assigns(object_whole(s1), object_whole(s2))
  ensures(forall(l0, 0, MLDSA_L, array_abs_bound(s1->vec[l0].coeffs, 0, MLDSA_N, MLDSA_ETA + 1)))
  ensures(forall(k0, 0, MLDSA_K, array_abs_bound(s2->vec[k0].coeffs, 0, MLDSA_N, MLDSA_ETA + 1)))
)
{
/* Sample short vectors s1 and s2 */
#if defined(MLD_CONFIG_SERIAL_FIPS202_ONLY)
  int i;
  uint16_t nonce = 0;
  /* Safety: The nonces are at most 14 (MLDSA_L + MLDSA_K - 1), and, hence, the
   * casts are safe. */
  for(i = 0; i < MLDSA_L; i++)
  {
    noxtls_mld_poly_uniform_eta(&s1->vec[i], seed, (uint8_t)(nonce + i));
  }
  for(i = 0; i < MLDSA_K; i++)
  {
    noxtls_mld_poly_uniform_eta(&s2->vec[i], seed, (uint8_t)(nonce + MLDSA_L + i));
  }
#else /* MLD_CONFIG_SERIAL_FIPS202_ONLY */
#if MLD_CONFIG_PARAMETER_SET == 44
  noxtls_mld_poly_uniform_eta_4x(&s1->vec[0], &s1->vec[1], &s1->vec[2], &s1->vec[3],
                          seed, 0, 1, 2, 3);
  noxtls_mld_poly_uniform_eta_4x(&s2->vec[0], &s2->vec[1], &s2->vec[2], &s2->vec[3],
                          seed, 4, 5, 6, 7);
#elif MLD_CONFIG_PARAMETER_SET == 65
  noxtls_mld_poly_uniform_eta_4x(&s1->vec[0], &s1->vec[1], &s1->vec[2], &s1->vec[3],
                          seed, 0, 1, 2, 3);
  noxtls_mld_poly_uniform_eta_4x(&s1->vec[4], &s2->vec[0], &s2->vec[1],
                          &s2->vec[2] /* irrelevant */, seed, 4, 5, 6,
                          0xFF /* irrelevant */);
  noxtls_mld_poly_uniform_eta_4x(&s2->vec[2], &s2->vec[3], &s2->vec[4], &s2->vec[5],
                          seed, 7, 8, 9, 10);
#elif MLD_CONFIG_PARAMETER_SET == 87
  noxtls_mld_poly_uniform_eta_4x(&s1->vec[0], &s1->vec[1], &s1->vec[2], &s1->vec[3],
                          seed, 0, 1, 2, 3);
  noxtls_mld_poly_uniform_eta_4x(&s1->vec[4], &s1->vec[5], &s1->vec[6],
                          &s2->vec[0] /* irrelevant */, seed, 4, 5, 6,
                          0xFF /* irrelevant */);
  noxtls_mld_poly_uniform_eta_4x(&s2->vec[0], &s2->vec[1], &s2->vec[2], &s2->vec[3],
                          seed, 7, 8, 9, 10);
  noxtls_mld_poly_uniform_eta_4x(&s2->vec[4], &s2->vec[5], &s2->vec[6], &s2->vec[7],
                          seed, 11, 12, 13, 14);
#endif /* MLD_CONFIG_PARAMETER_SET == 87 */
#endif /* !MLD_CONFIG_SERIAL_FIPS202_ONLY */
}

/*************************************************
 * Name:        noxtls_mld_compute_t0_t1_tr_from_sk_components
 *
 * Description: Computes t0, t1, tr, and pk from secret key components
 *              rho, s1, s2. This is the shared computation used by
 *              both keygen and generating the public key from the
 *              secret key.
 *
 * Arguments:   - noxtls_mld_polyveck *t0: output t0
 *              - noxtls_mld_polyveck *t1: output t1
 *              - uint8_t tr[MLDSA_TRBYTES]: output tr
 *              - uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES]: output public key
 *              - const uint8_t rho[MLDSA_SEEDBYTES]: input rho
 *              - const noxtls_mld_polyvecl *s1: input s1
 *              - const noxtls_mld_polyveck *s2: input s2
 **************************************************/
MLD_MUST_CHECK_RETURN_VALUE
static int noxtls_mld_compute_t0_t1_tr_from_sk_components(
    noxtls_mld_polyveck *t0, noxtls_mld_polyveck *t1, uint8_t tr[MLDSA_TRBYTES],
    uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES], const uint8_t rho[MLDSA_SEEDBYTES],
    const noxtls_mld_polyvecl *s1, const noxtls_mld_polyveck *s2,
    MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
__contract__(
  requires(memory_no_alias(t0, sizeof(noxtls_mld_polyveck)))
  requires(memory_no_alias(t1, sizeof(noxtls_mld_polyveck)))
  requires(memory_no_alias(tr, MLDSA_TRBYTES))
  requires(memory_no_alias(pk, MLDSA_CRYPTO_PUBLICKEYBYTES))
  requires(memory_no_alias(rho, MLDSA_SEEDBYTES))
  requires(memory_no_alias(s1, sizeof(noxtls_mld_polyvecl)))
  requires(memory_no_alias(s2, sizeof(noxtls_mld_polyveck)))
  requires(forall(l0, 0, MLDSA_L, array_bound(s1->vec[l0].coeffs, 0, MLDSA_N, MLD_POLYETA_UNPACK_LOWER_BOUND, MLDSA_ETA + 1)))
  requires(forall(k0, 0, MLDSA_K, array_bound(s2->vec[k0].coeffs, 0, MLDSA_N, MLD_POLYETA_UNPACK_LOWER_BOUND, MLDSA_ETA + 1)))
  assigns(memory_slice(t0, sizeof(noxtls_mld_polyveck)))
  assigns(memory_slice(t1, sizeof(noxtls_mld_polyveck)))
  assigns(memory_slice(tr, MLDSA_TRBYTES))
  assigns(memory_slice(pk, MLDSA_CRYPTO_PUBLICKEYBYTES))
  ensures(forall(k1, 0, MLDSA_K, array_bound(t0->vec[k1].coeffs, 0, MLDSA_N, -(1<<(MLDSA_D-1)) + 1, (1<<(MLDSA_D-1)) + 1)))
  ensures(forall(k2, 0, MLDSA_K, array_bound(t1->vec[k2].coeffs, 0, MLDSA_N, 0, 1 << 10)))
  ensures(return_value == 0 || return_value == MLD_ERR_OUT_OF_MEMORY))
{
  int ret;
  MLD_ALLOC(mat, noxtls_mld_polymat, 1, context);
  MLD_ALLOC(s1hat, noxtls_mld_polyvecl, 1, context);
  MLD_ALLOC(t, noxtls_mld_polyveck, 1, context);

  if(mat == NULL || s1hat == NULL || t == NULL)
  {
    ret = MLD_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  /* Expand matrix */
  noxtls_mld_polyvec_matrix_expand(mat, rho);

  /* Matrix-vector multiplication */
  *s1hat = *s1;
  noxtls_mld_polyvecl_ntt(s1hat);
  noxtls_mld_polyvec_matrix_pointwise_montgomery(t, mat, s1hat);
  noxtls_mld_polyveck_invntt_tomont(t);

  /* Add error vector s2 */
  noxtls_mld_polyveck_add(t, s2);

  /* Reference: The following reduction is not present in the reference
   *            implementation. Omitting this reduction requires the output of
   *            the invntt to be small enough such that the addition of s2 does
   *            not result in absolute values >= MLDSA_Q. While our C, x86_64,
   *            and AArch64 invntt implementations produce small enough
   *            values for this to work out, it complicates the bounds
   *            reasoning. We instead add an additional reduction, and can
   *            consequently, relax the bounds requirements for the invntt.
   */
  noxtls_mld_polyveck_reduce(t);

  /* Decompose to get t1, t0 */
  noxtls_mld_polyveck_caddq(t);
  noxtls_mld_polyveck_power2round(t1, t0, t);

  /* Pack public key and compute tr */
  noxtls_mld_pack_pk(pk, rho, t1);
  noxtls_mld_shake256(tr, MLDSA_TRBYTES, pk, MLDSA_CRYPTO_PUBLICKEYBYTES);

  ret = 0;

cleanup:
  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  MLD_FREE(t, noxtls_mld_polyveck, 1, context);
  MLD_FREE(s1hat, noxtls_mld_polyvecl, 1, context);
  MLD_FREE(mat, noxtls_mld_polymat, 1, context);
  return ret;
}

MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_keypair_internal(uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                              uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                              const uint8_t seed[MLDSA_SEEDBYTES],
                              MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  int ret;
  const uint8_t *rho;
  const uint8_t *rhoprime;
  const uint8_t *key;
  MLD_ALLOC(seedbuf, uint8_t, 2 * MLDSA_SEEDBYTES + MLDSA_CRHBYTES, context);
  MLD_ALLOC(inbuf, uint8_t, MLDSA_SEEDBYTES + 2, context);
  MLD_ALLOC(tr, uint8_t, MLDSA_TRBYTES, context);
  MLD_ALLOC(s1, noxtls_mld_polyvecl, 1, context);
  MLD_ALLOC(s2, noxtls_mld_polyveck, 1, context);
  MLD_ALLOC(t1, noxtls_mld_polyveck, 1, context);
  MLD_ALLOC(t0, noxtls_mld_polyveck, 1, context);

  if(seedbuf == NULL || inbuf == NULL || tr == NULL || s1 == NULL ||
      s2 == NULL || t1 == NULL || t0 == NULL)
  {
    ret = MLD_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  /* Get randomness for rho, rhoprime and key */
  noxtls_mld_memcpy(inbuf, seed, MLDSA_SEEDBYTES);
  inbuf[MLDSA_SEEDBYTES + 0] = MLDSA_K;
  inbuf[MLDSA_SEEDBYTES + 1] = MLDSA_L;
  noxtls_mld_shake256(seedbuf, 2 * MLDSA_SEEDBYTES + MLDSA_CRHBYTES, inbuf,
               MLDSA_SEEDBYTES + 2);
  rho = seedbuf;
  rhoprime = rho + MLDSA_SEEDBYTES;
  key = rhoprime + MLDSA_CRHBYTES;

  /* Constant time: rho is part of the public key and, hence, public. */
  MLD_CT_TESTING_DECLASSIFY(rho, MLDSA_SEEDBYTES);

  /* Sample s1 and s2 */
  noxtls_mld_sample_s1_s2(s1, s2, rhoprime);

  /* Compute t0, t1, tr, and pk from rho, s1, s2 */
  ret = noxtls_mld_compute_t0_t1_tr_from_sk_components(t0, t1, tr, pk, rho, s1, s2,
                                                context);
  if(ret != 0)
  {
    goto cleanup;
  }

  /* Pack secret key */
  noxtls_mld_pack_sk(sk, rho, tr, key, t0, s1, s2);

  /* Constant time: pk is the public key, inherently public data */
  MLD_CT_TESTING_DECLASSIFY(pk, MLDSA_CRYPTO_PUBLICKEYBYTES);

cleanup:
  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  MLD_FREE(t0, noxtls_mld_polyveck, 1, context);
  MLD_FREE(t1, noxtls_mld_polyveck, 1, context);
  MLD_FREE(s2, noxtls_mld_polyveck, 1, context);
  MLD_FREE(s1, noxtls_mld_polyvecl, 1, context);
  MLD_FREE(tr, uint8_t, MLDSA_TRBYTES, context);
  MLD_FREE(inbuf, uint8_t, MLDSA_SEEDBYTES + 2, context);
  MLD_FREE(seedbuf, uint8_t, 2 * MLDSA_SEEDBYTES + MLDSA_CRHBYTES, context);

  if(ret != 0)
  {
    return ret;
  }

  /* Pairwise Consistency Test (PCT) @[FIPS140_3_IG, p.87] */
  /* Do this after freeing all temporaries. */
  return noxtls_mld_check_pct(pk, sk, context);
}

#if !defined(MLD_CONFIG_NO_RANDOMIZED_API)
MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_keypair(uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                     uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                     MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  MLD_ALIGN uint8_t seed[MLDSA_SEEDBYTES];
  int ret;
  if(noxtls_mld_randombytes(seed, MLDSA_SEEDBYTES) != 0)
  {
    ret = MLD_ERR_RNG_FAIL;
    goto cleanup;
  }
  MLD_CT_TESTING_SECRET(seed, sizeof(seed));
  ret = noxtls_mld_sign_keypair_internal(pk, sk, seed, context);

cleanup:
  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  noxtls_mld_zeroize(seed, sizeof(seed));
  return ret;
}
#endif /* !MLD_CONFIG_NO_RANDOMIZED_API */

/*************************************************
 * Name:        noxtls_mld_H
 *
 * Description: Abstracts application of SHAKE256 to
 *              one, two or three blocks of data,
 *              yielding a user-requested size of
 *              output.
 *
 * Arguments:   - uint8_t *out: pointer to output
 *              - size_t outlen: requested output length in bytes
 *              - const uint8_t *in1: pointer to input block 1
 *                                    Must NOT be NULL
 *              - size_t in1len: length of input in1 bytes
 *              - const uint8_t *in2: pointer to input block 2
 *                                    May be NULL if in2len=0, in which case
 *                                    this block is ignored
 *              - size_t in2len: length of input in2 bytes
 *              - const uint8_t *in3: pointer to input block 3
 *                                    May be NULL if in3len=0, in which case
 *                                    this block is ignored
 *              - size_t in3len: length of input in3 bytes
 **************************************************/
static void noxtls_mld_H(uint8_t *out, size_t outlen, const uint8_t *in1,
                  size_t in1len, const uint8_t *in2, size_t in2len,
                  const uint8_t *in3, size_t in3len)
__contract__(
  requires(in1len <= MLD_MAX_BUFFER_SIZE)
  requires(in2len <= MLD_MAX_BUFFER_SIZE)
  requires(in3len <= MLD_MAX_BUFFER_SIZE)
  requires(outlen <= 8 * SHAKE256_RATE /* somewhat arbitrary bound */)
  requires(memory_no_alias(in1, in1len))
  requires(in2len == 0 || memory_no_alias(in2, in2len))
  requires(in3len == 0 || memory_no_alias(in3, in3len))
  requires(memory_no_alias(out, outlen))
  assigns(memory_slice(out, outlen))
)
{
  noxtls_mld_shake256ctx state;
  noxtls_mld_shake256_init(&state);
  noxtls_mld_shake256_absorb(&state, in1, in1len);
  if(in2len != 0)
  {
    noxtls_mld_shake256_absorb(&state, in2, in2len);
  }
  if(in3len != 0)
  {
    noxtls_mld_shake256_absorb(&state, in3, in3len);
  }
  noxtls_mld_shake256_finalize(&state);
  noxtls_mld_shake256_squeeze(out, outlen, &state);
  noxtls_mld_shake256_release(&state);

  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  noxtls_mld_zeroize(&state, sizeof(state));
}

/*************************************************
 * Name:        noxtls_mld_compute_pack_z
 *
 * Description: Computes z = y + s1*c, checks that z has coefficients smaller
 *              than MLDSA_GAMMA1 - MLDSA_BETA, and packs z into the
 *              signature buffer.
 *
 * Arguments:   - uint8_t *sig: output signature
 *              - const noxtls_mld_poly *cp: challenge polynomial
 *              - const polyvecl *s1: secret vector s1
 *              - const polyvecl *y: masking vector y
 *
 * Returns:     - 0: Success (z has coefficients smaller than
 *                   MLDSA_GAMMA1 - MLDSA_BETA,)
 *              - MLD_ERR_FAIL: z rejected (norm check failed)
 *              - MLD_ERR_OUT_OF_MEMORY: If MLD_CONFIG_CUSTOM_ALLOC_FREE is
 *                  used and an allocation via MLD_CUSTOM_ALLOC returned NULL.
 *
 * Reference: This function is inlined into noxtls_mld_sign_signature in the
 *            reference implementation.
 **************************************************/
MLD_MUST_CHECK_RETURN_VALUE
static int noxtls_mld_compute_pack_z(uint8_t sig[MLDSA_CRYPTO_BYTES],
                              const noxtls_mld_poly *cp, const noxtls_mld_polyvecl *s1,
                              const noxtls_mld_polyvecl *y, noxtls_mld_poly *z)
__contract__(
  requires(memory_no_alias(sig, MLDSA_CRYPTO_BYTES))
  requires(memory_no_alias(cp, sizeof(noxtls_mld_poly)))
  requires(memory_no_alias(s1, sizeof(noxtls_mld_polyvecl)))
  requires(memory_no_alias(y, sizeof(noxtls_mld_polyvecl)))
  requires(memory_no_alias(z, sizeof(noxtls_mld_poly)))
  requires(array_abs_bound(cp->coeffs, 0, MLDSA_N, MLD_NTT_BOUND))
  requires(forall(k0, 0, MLDSA_L,
    array_bound(y->vec[k0].coeffs, 0, MLDSA_N, -(MLDSA_GAMMA1 - 1), MLDSA_GAMMA1 + 1)))
  requires(forall(k1, 0, MLDSA_L, array_abs_bound(s1->vec[k1].coeffs, 0, MLDSA_N, MLD_NTT_BOUND)))
  assigns(memory_slice(sig, MLDSA_CRYPTO_BYTES))
  assigns(memory_slice(z, sizeof(noxtls_mld_poly)))
  ensures(return_value == 0 || return_value == MLD_ERR_FAIL ||
          return_value == MLD_ERR_OUT_OF_MEMORY)
)
{
  unsigned int i;
  uint32_t z_invalid;
  for(i = 0; i < MLDSA_L; i++)
  __loop__(
    assigns(i, memory_slice(z, sizeof(noxtls_mld_poly)), memory_slice(sig, MLDSA_CRYPTO_BYTES))
    invariant(i <= MLDSA_L)
    decreases(MLDSA_L - i)
  )
  {
    noxtls_mld_poly_pointwise_montgomery(z, cp, &s1->vec[i]);
    noxtls_mld_poly_invntt_tomont(z);
    noxtls_mld_poly_add(z, &y->vec[i]);
    noxtls_mld_poly_reduce(z);

    z_invalid = noxtls_mld_poly_chknorm(z, MLDSA_GAMMA1 - MLDSA_BETA);
    /* Constant time: It is fine (and prohibitively expensive to avoid)
     * to leak the result of the norm check and which polynomial in z caused a
     * rejection. It would even be okay to leak which coefficient led to
     * rejection as the candidate signature will be discarded anyway.
     * See Section 5.5 of @[Round3_Spec]. */
    MLD_CT_TESTING_DECLASSIFY(&z_invalid, sizeof(uint32_t));
    if(z_invalid)
    {
      return MLD_ERR_FAIL; /* reject */
    }
    /* If z is valid, then its coefficients are bounded by
     * MLDSA_GAMMA1 - MLDSA_BETA. This will be needed below
     * to prove the pre-condition of pack_sig_z() */
    noxtls_mld_assert_abs_bound(z, MLDSA_N, (MLDSA_GAMMA1 - MLDSA_BETA));

    /* After the norm check, the distribution of each coefficient of z is
     * independent of the secret key and it can, hence, be considered
     * public. It is, hence, okay to immediately pack it into the user-provided
     * signature buffer. */
    noxtls_mld_pack_sig_z(sig, z, i);
  }
  return 0;
}

/* Reference: The reference implementation does not explicitly check the
 * maximum nonce value, but instead loops indefinitely (even when the nonce
 * would overflow). Internally, sampling of y uses
 * (nonceL), (nonceL+1), ... (nonce*L+L-1).
 * Hence, there are no overflows if nonce < (UINT16_MAX - L)/L.
 * Explicitly checking for this explicitly allows us to prove type-safety.
 * Note that FIPS204 explicitly allows an upper-bound this loop of
 * 814 (< (UINT16_MAX - L)/L) - see @[FIPS204, Appendix C]. */
#define MLD_NONCE_UB ((UINT16_MAX - MLDSA_L) / MLDSA_L)

/*************************************************
 * Name:        attempt_signature_generation
 *
 * Description: Attempts to generate a single signature.
 *
 * Arguments:   - uint8_t *sig: pointer to output signature
 *              - const uint8_t *mu: pointer to noxtls_message or hash
 *                                   of exactly MLDSA_CRHBYTES bytes
 *              - const uint8_t *rhoprime: pointer to randomness seed
 *              - uint16_t nonce: current nonce value
 *              - const noxtls_mld_polymat *mat: expanded matrix
 *              - const polyvecl *s1: secret vector s1
 *              - const polyveck *s2: secret vector s2
 *              - const polyveck *t0: vector t0
 *
 * Returns:     - 0: Signature generation succeeded
 *              - MLD_ERR_FAIL: Signature rejected (norm check failed)
 *              - MLD_ERR_OUT_OF_MEMORY: If MLD_CONFIG_CUSTOM_ALLOC_FREE is
 *                  used and an allocation via MLD_CUSTOM_ALLOC returned NULL.
 *
 * Reference: This code differs from the reference implementation
 *            in that it factors out the core signature generation
 *            step into a distinct function here in order to improve
 *            efficiency of CBMC proof.
 **************************************************/
MLD_MUST_CHECK_RETURN_VALUE
static int noxtls_mld_attempt_signature_generation(
    uint8_t sig[MLDSA_CRYPTO_BYTES], const uint8_t *mu,
    const uint8_t rhoprime[MLDSA_CRHBYTES], uint16_t nonce, noxtls_mld_polymat *mat,
    const noxtls_mld_polyvecl *s1, const noxtls_mld_polyveck *s2, const noxtls_mld_polyveck *t0,
    MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
__contract__(
  requires(memory_no_alias(sig, MLDSA_CRYPTO_BYTES))
  requires(memory_no_alias(mu, MLDSA_CRHBYTES))
  requires(memory_no_alias(rhoprime, MLDSA_CRHBYTES))
  requires(memory_no_alias(mat, sizeof(noxtls_mld_polymat)))
  requires(memory_no_alias(s1, sizeof(noxtls_mld_polyvecl)))
  requires(memory_no_alias(s2, sizeof(noxtls_mld_polyveck)))
  requires(memory_no_alias(t0, sizeof(noxtls_mld_polyveck)))
  requires(nonce <= MLD_NONCE_UB)
  requires(forall(k1, 0, MLDSA_K, forall(l1, 0, MLDSA_L,
                                         array_bound(mat->vec[k1].vec[l1].coeffs, 0, MLDSA_N, 0, MLDSA_Q))))
  requires(forall(k2, 0, MLDSA_K, array_abs_bound(t0->vec[k2].coeffs, 0, MLDSA_N, MLD_NTT_BOUND)))
  requires(forall(k3, 0, MLDSA_L, array_abs_bound(s1->vec[k3].coeffs, 0, MLDSA_N, MLD_NTT_BOUND)))
  requires(forall(k4, 0, MLDSA_K, array_abs_bound(s2->vec[k4].coeffs, 0, MLDSA_N, MLD_NTT_BOUND)))
  assigns(memory_slice(sig, MLDSA_CRYPTO_BYTES))
  ensures(return_value == 0 || return_value == MLD_ERR_FAIL ||
          return_value == MLD_ERR_OUT_OF_MEMORY)
)
{
  unsigned int n;
  uint32_t w0_invalid;
  uint32_t h_invalid;
  int ret;
  /* TODO: Remove the following workaround for
   * https://github.com/diffblue/cbmc/issues/8813 */
  typedef MLD_UNION_OR_STRUCT
  {
    noxtls_mld_polyvecl y;
    noxtls_mld_polyveck h;
  }
  yh_u;
  noxtls_mld_polyvecl *y;
  noxtls_mld_polyveck *h;

  /* TODO: Remove the following workaround for
   * https://github.com/diffblue/cbmc/issues/8813 */
  typedef MLD_UNION_OR_STRUCT
  {
    noxtls_mld_polyveck w1;
    noxtls_mld_polyvecl tmp;
  }
  w1tmp_u;
  noxtls_mld_polyveck *w1;
  noxtls_mld_polyvecl *tmp;

  MLD_ALLOC(challenge_bytes, uint8_t, MLDSA_CTILDEBYTES, context);
  MLD_ALLOC(yh, yh_u, 1, context);
  MLD_ALLOC(z, noxtls_mld_poly, 1, context);
  MLD_ALLOC(w1tmp, w1tmp_u, 1, context);
  MLD_ALLOC(w0, noxtls_mld_polyveck, 1, context);
  MLD_ALLOC(cp, noxtls_mld_poly, 1, context);
  MLD_ALLOC(t, noxtls_mld_poly, 1, context);

  if(challenge_bytes == NULL || yh == NULL || z == NULL || w1tmp == NULL ||
      w0 == NULL || cp == NULL || t == NULL)
  {
    ret = MLD_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }
  y = &yh->y;
  h = &yh->h;
  w1 = &w1tmp->w1;
  tmp = &w1tmp->tmp;

  /* Sample intermediate vector y */
  noxtls_mld_polyvecl_uniform_gamma1(y, rhoprime, nonce);

  /* Matrix-vector multiplication */
  *tmp = *y;
  noxtls_mld_polyvecl_ntt(tmp);
  noxtls_mld_polyvec_matrix_pointwise_montgomery(w0, mat, tmp);
  noxtls_mld_polyveck_invntt_tomont(w0);

  /* Decompose w and call the random oracle */
  noxtls_mld_polyveck_caddq(w0);
  noxtls_mld_polyveck_decompose(w1, w0);
  noxtls_mld_polyveck_pack_w1(sig, w1);

  noxtls_mld_H(challenge_bytes, MLDSA_CTILDEBYTES, mu, MLDSA_CRHBYTES, sig,
        MLDSA_K * MLDSA_POLYW1_PACKEDBYTES, NULL, 0);
  /* Constant time: Leaking challenge_bytes does not reveal any information
   * about the secret key as H() is modelled as random oracle.
   * This also applies to challenges for rejected signatures.
   * See Section 5.5 of @[Round3_Spec]. */
  MLD_CT_TESTING_DECLASSIFY(challenge_bytes, MLDSA_CTILDEBYTES);
  noxtls_mld_poly_challenge(cp, challenge_bytes);
  noxtls_mld_poly_ntt(cp);

  /* Compute z, reject if it reveals secret */
  ret = noxtls_mld_compute_pack_z(sig, cp, s1, y, t);
  if(ret)
  {
    goto cleanup;
  }

  /* Check that subtracting cs2 does not change high bits of w and low bits
   * do not reveal secret information */
  noxtls_mld_polyveck_pointwise_poly_montgomery(h, cp, s2);
  noxtls_mld_polyveck_invntt_tomont(h);
  noxtls_mld_polyveck_sub(w0, h);
  noxtls_mld_polyveck_reduce(w0);

  w0_invalid = noxtls_mld_polyveck_chknorm(w0, MLDSA_GAMMA2 - MLDSA_BETA);
  /* Constant time: w0_invalid may be leaked - see comment for z_invalid. */
  MLD_CT_TESTING_DECLASSIFY(&w0_invalid, sizeof(uint32_t));
  if(w0_invalid)
  {
    ret = MLD_ERR_FAIL; /* reject */
    goto cleanup;
  }

  /* Compute hints for w1 */
  noxtls_mld_polyveck_pointwise_poly_montgomery(h, cp, t0);
  noxtls_mld_polyveck_invntt_tomont(h);
  noxtls_mld_polyveck_reduce(h);

  h_invalid = noxtls_mld_polyveck_chknorm(h, MLDSA_GAMMA2);
  /* Constant time: h_invalid may be leaked - see comment for z_invalid. */
  MLD_CT_TESTING_DECLASSIFY(&h_invalid, sizeof(uint32_t));
  if(h_invalid)
  {
    ret = MLD_ERR_FAIL; /* reject */
    goto cleanup;
  }

  noxtls_mld_polyveck_add(w0, h);

  /* Constant time: At this point all norm checks have passed and we, hence,
   * know that the signature does not leak any secret information.
   * Consequently, any value that can be computed from the signature and public
   * key is considered public.
   * w0 and w1 are public as they can be computed from Az - ct = \alpha w1 + w0.
   * h=c*t0 is public as both c and t0 are public.
   * For a more detailed discussion, refer to https://eprint.iacr.org/2022/1406.
   */
  MLD_CT_TESTING_DECLASSIFY(w0, sizeof(*w0));
  MLD_CT_TESTING_DECLASSIFY(w1, sizeof(*w1));
  n = noxtls_mld_polyveck_make_hint(h, w0, w1);
  if(n > MLDSA_OMEGA)
  {
    ret = MLD_ERR_FAIL; /* reject */
    goto cleanup;
  }

  /* All is well - write signature */
  noxtls_mld_pack_sig_c_h(sig, challenge_bytes, h, n);
  /* Constant time: At this point it is clear that the signature is valid - it
   * can, hence, be considered public. */
  MLD_CT_TESTING_DECLASSIFY(sig, MLDSA_CRYPTO_BYTES);
  ret = 0; /* success */

cleanup:
  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  MLD_FREE(t, noxtls_mld_poly, 1, context);
  MLD_FREE(cp, noxtls_mld_poly, 1, context);
  MLD_FREE(w0, noxtls_mld_polyveck, 1, context);
  MLD_FREE(w1tmp, w1tmp_u, 1, context);
  MLD_FREE(z, noxtls_mld_poly, 1, context);
  MLD_FREE(yh, yh_u, 1, context);
  MLD_FREE(challenge_bytes, uint8_t, MLDSA_CTILDEBYTES, context);

  return ret;
}
MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_signature_internal(uint8_t sig[MLDSA_CRYPTO_BYTES], size_t *siglen,
                                const uint8_t *m, size_t mlen,
                                const uint8_t *pre, size_t prelen,
                                const uint8_t rnd[MLDSA_RNDBYTES],
                                const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                                int externalmu,
                                MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  int ret;
  uint8_t *rho;
  uint8_t *tr;
  uint8_t *key;
  uint8_t *mu;
  uint8_t *rhoprime;
  uint16_t nonce = 0;
  MLD_ALLOC(seedbuf, uint8_t,
            2 * MLDSA_SEEDBYTES + MLDSA_TRBYTES + 2 * MLDSA_CRHBYTES, context);
  MLD_ALLOC(mat, noxtls_mld_polymat, 1, context);
  MLD_ALLOC(s1, noxtls_mld_polyvecl, 1, context);
  MLD_ALLOC(t0, noxtls_mld_polyveck, 1, context);
  MLD_ALLOC(s2, noxtls_mld_polyveck, 1, context);

  if(seedbuf == NULL || mat == NULL || s1 == NULL || t0 == NULL || s2 == NULL)
  {
    ret = MLD_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  rho = seedbuf;
  tr = rho + MLDSA_SEEDBYTES;
  key = tr + MLDSA_TRBYTES;
  mu = key + MLDSA_SEEDBYTES;
  rhoprime = mu + MLDSA_CRHBYTES;
  noxtls_mld_unpack_sk(rho, tr, key, t0, s1, s2, sk);

  if(!externalmu)
  {
    /* Compute mu = CRH(tr, pre, msg) */
    noxtls_mld_H(mu, MLDSA_CRHBYTES, tr, MLDSA_TRBYTES, pre, prelen, m, mlen);
  }
  else
  {
    /* mu has been provided directly */
    noxtls_mld_memcpy(mu, m, MLDSA_CRHBYTES);
  }

  /* Compute rhoprime = CRH(key, rnd, mu) */
  noxtls_mld_H(rhoprime, MLDSA_CRHBYTES, key, MLDSA_SEEDBYTES, rnd, MLDSA_RNDBYTES, mu,
        MLDSA_CRHBYTES);

  /* Constant time: rho is part of the public key and, hence, public. */
  MLD_CT_TESTING_DECLASSIFY(rho, MLDSA_SEEDBYTES);
  /* Expand matrix and transform vectors */
  noxtls_mld_polyvec_matrix_expand(mat, rho);
  noxtls_mld_polyvecl_ntt(s1);
  noxtls_mld_polyveck_ntt(s2);
  noxtls_mld_polyveck_ntt(t0);

  /* By default, return failure. Flip to success and write output
   * once signature generation succeeds. */
  ret = MLD_ERR_FAIL;

  /* Reference: This code is re-structured using a while(1),  */
  /* with explicit "continue" statements (rather than "goto") */
  /* to implement rejection of invalid signatures.            */
  while(1)
  __loop__(
    assigns(nonce, ret, object_whole(siglen), memory_slice(sig, MLDSA_CRYPTO_BYTES))
    invariant(nonce <= MLD_NONCE_UB)

    /* t0, s1, s2, and mat are initialized above and are NOT changed by this */
    /* loop. We can therefore re-assert their bounds here as part of the     */
    /* loop invariant. This makes proof noticeably faster with CBMC          */
    invariant(forall(k1, 0, MLDSA_K, forall(l1, 0, MLDSA_L,
              array_bound(mat->vec[k1].vec[l1].coeffs, 0, MLDSA_N, 0, MLDSA_Q))))
    invariant(forall(k2, 0, MLDSA_K, array_abs_bound(t0->vec[k2].coeffs, 0, MLDSA_N, MLD_NTT_BOUND)))
    invariant(forall(k3, 0, MLDSA_L, array_abs_bound(s1->vec[k3].coeffs, 0, MLDSA_N, MLD_NTT_BOUND)))
    invariant(forall(k4, 0, MLDSA_K, array_abs_bound(s2->vec[k4].coeffs, 0, MLDSA_N, MLD_NTT_BOUND)))
    invariant(ret == MLD_ERR_FAIL)
    decreases(MLD_NONCE_UB - nonce)
  )
  {
    /* Reference: this code explicitly checks for exhaustion of nonce     */
    /* values to provide predictable termination and results in that case */
    /* Checking here also means that incrementing nonce below can also    */
    /* be proven to be type-safe.                                         */
    if(nonce == MLD_NONCE_UB)
    {
      /* Note that ret == MLD_ERR_FAIL by default, so we
       * don't need to set it here. */
      break;
    }

    ret = noxtls_mld_attempt_signature_generation(sig, mu, rhoprime, nonce, mat, s1,
                                           s2, t0, context);
    nonce++;
    if(ret == 0)
    {
      *siglen = MLDSA_CRYPTO_BYTES;
      break;
    }
    else if(ret != MLD_ERR_FAIL)
    {
      /* For failures such as out-of-memory, propagate and exit immediately. */
      break;
    }

    /* Otherwise, try again. */
  }

cleanup:

  if(ret != 0)
  {
    /* To be on the safe-side, we zeroize the signature buffer. */
    *siglen = 0;
    noxtls_mld_memset(sig, 0, MLDSA_CRYPTO_BYTES);
  }

  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  MLD_FREE(s2, noxtls_mld_polyveck, 1, context);
  MLD_FREE(t0, noxtls_mld_polyveck, 1, context);
  MLD_FREE(s1, noxtls_mld_polyvecl, 1, context);
  MLD_FREE(mat, noxtls_mld_polymat, 1, context);
  MLD_FREE(seedbuf, uint8_t,
           2 * MLDSA_SEEDBYTES + MLDSA_TRBYTES + 2 * MLDSA_CRHBYTES, context);
  return ret;
}

#if !defined(MLD_CONFIG_NO_RANDOMIZED_API)
MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_signature(uint8_t sig[MLDSA_CRYPTO_BYTES], size_t *siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *ctx,
                       size_t ctxlen,
                       const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                       MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  size_t pre_len;
  int ret;
  MLD_ALLOC(pre, uint8_t, MLD_DOMAIN_SEPARATION_MAX_BYTES, context);
  MLD_ALLOC(rnd, uint8_t, MLDSA_RNDBYTES, context);

  if(pre == NULL || rnd == NULL)
  {
    ret = MLD_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  /* Prepare domain separation prefix for pure ML-DSA */
  pre_len = noxtls_mld_prepare_domain_separation_prefix(pre, NULL, 0, ctx, ctxlen,
                                                 MLD_PREHASH_NONE);
  if(pre_len == 0)
  {
    ret = MLD_ERR_FAIL;
    goto cleanup;
  }

  /* Randomized variant of ML-DSA. If you need the deterministic variant,
   * call noxtls_mld_sign_signature_internal directly with all-zero rnd. */
  if(noxtls_mld_randombytes(rnd, MLDSA_RNDBYTES) != 0)
  {
    ret = MLD_ERR_RNG_FAIL;
    goto cleanup;
  }
  MLD_CT_TESTING_SECRET(rnd, sizeof(rnd));

  ret = noxtls_mld_sign_signature_internal(sig, siglen, m, mlen, pre, pre_len, rnd, sk,
                                    0, context);

cleanup:
  if(ret != 0)
  {
    /* To be on the safe-side, make sure *siglen and sig have a well-defined
     * value, even in the case of error.
     *
     * If we come from noxtls_mld_sign_signature_internal, both are redundant,
     * but the error case should not be the norm, and the added cost of the
     * memset insignificant. */
    *siglen = 0;
    noxtls_mld_memset(sig, 0, MLDSA_CRYPTO_BYTES);
  }

  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  MLD_FREE(rnd, uint8_t, MLDSA_RNDBYTES, context);
  MLD_FREE(pre, uint8_t, MLD_DOMAIN_SEPARATION_MAX_BYTES, context);

  return ret;
}
#endif /* !MLD_CONFIG_NO_RANDOMIZED_API */

#if !defined(MLD_CONFIG_NO_RANDOMIZED_API)
MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_signature_extmu(uint8_t sig[MLDSA_CRYPTO_BYTES], size_t *siglen,
                             const uint8_t mu[MLDSA_CRHBYTES],
                             const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                             MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  MLD_ALIGN uint8_t rnd[MLDSA_RNDBYTES];
  int ret;

  /* Randomized variant of ML-DSA. If you need the deterministic variant,
   * call noxtls_mld_sign_signature_internal directly with all-zero rnd. */
  if(noxtls_mld_randombytes(rnd, MLDSA_RNDBYTES) != 0)
  {
    *siglen = 0;
    ret = MLD_ERR_RNG_FAIL;
    goto cleanup;
  }
  MLD_CT_TESTING_SECRET(rnd, sizeof(rnd));

  ret = noxtls_mld_sign_signature_internal(sig, siglen, mu, MLDSA_CRHBYTES, NULL, 0,
                                    rnd, sk, 1, context);

cleanup:
  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  noxtls_mld_zeroize(rnd, sizeof(rnd));

  return ret;
}
#endif /* !MLD_CONFIG_NO_RANDOMIZED_API */

#if !defined(MLD_CONFIG_NO_RANDOMIZED_API)
MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen,
             const uint8_t *ctx, size_t ctxlen,
             const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
             MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  int ret;
  size_t i;

  for(i = 0; i < mlen; ++i)
  __loop__(
    assigns(i, object_whole(sm))
    invariant(i <= mlen)
    decreases(mlen - i)
  )
  {
    sm[MLDSA_CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
  }
  ret = noxtls_mld_sign_signature(sm, smlen, sm + MLDSA_CRYPTO_BYTES, mlen, ctx,
                           ctxlen, sk, context);
  *smlen += mlen;
  return ret;
}
#endif /* !MLD_CONFIG_NO_RANDOMIZED_API */

MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_verify_internal(const uint8_t *sig, size_t siglen,
                             const uint8_t *m, size_t mlen, const uint8_t *pre,
                             size_t prelen,
                             const uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                             int externalmu,
                             MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  int ret;
  int cmp;

  /* TODO: Remove the following workaround for
   * https://github.com/diffblue/cbmc/issues/8813 */
  typedef MLD_UNION_OR_STRUCT
  {
    noxtls_mld_polyveck t1;
    noxtls_mld_polyveck w1;
  }
  t1w1_u;
  noxtls_mld_polyveck *t1;
  noxtls_mld_polyveck *w1;

  MLD_ALLOC(buf, uint8_t, (MLDSA_K * MLDSA_POLYW1_PACKEDBYTES), context);
  MLD_ALLOC(rho, uint8_t, MLDSA_SEEDBYTES, context);
  MLD_ALLOC(mu, uint8_t, MLDSA_CRHBYTES, context);
  MLD_ALLOC(c, uint8_t, MLDSA_CTILDEBYTES, context);
  MLD_ALLOC(c2, uint8_t, MLDSA_CTILDEBYTES, context);
  MLD_ALLOC(cp, noxtls_mld_poly, 1, context);
  MLD_ALLOC(mat, noxtls_mld_polymat, 1, context);
  MLD_ALLOC(z, noxtls_mld_polyvecl, 1, context);
  MLD_ALLOC(t1w1, t1w1_u, 1, context);
  MLD_ALLOC(tmp, noxtls_mld_polyveck, 1, context);
  MLD_ALLOC(h, noxtls_mld_polyveck, 1, context);

  if(buf == NULL || rho == NULL || mu == NULL || c == NULL || c2 == NULL ||
      cp == NULL || mat == NULL || z == NULL || t1w1 == NULL || tmp == NULL ||
      h == NULL)
  {
    ret = MLD_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }
  t1 = &t1w1->t1;
  w1 = &t1w1->w1;

  if(siglen != MLDSA_CRYPTO_BYTES)
  {
    ret = MLD_ERR_FAIL;
    goto cleanup;
  }

  noxtls_mld_unpack_pk(rho, t1, pk);

  /* noxtls_mld_unpack_sig and noxtls_mld_polyvecl_chknorm signal failure through a
   * single non-zero error code that's not yet aligned with MLD_ERR_XXX.
   * Map it to MLD_ERR_FAIL explicitly. */
  if(noxtls_mld_unpack_sig(c, z, h, sig))
  {
    ret = MLD_ERR_FAIL;
    goto cleanup;
  }
  if(noxtls_mld_polyvecl_chknorm(z, MLDSA_GAMMA1 - MLDSA_BETA))
  {
    ret = MLD_ERR_FAIL;
    goto cleanup;
  }

  if(!externalmu)
  {
    /* Compute CRH(H(rho, t1), pre, msg) */
    MLD_ALIGN uint8_t hpk[MLDSA_CRHBYTES];
    noxtls_mld_H(hpk, MLDSA_TRBYTES, pk, MLDSA_CRYPTO_PUBLICKEYBYTES, NULL, 0, NULL,
          0);
    noxtls_mld_H(mu, MLDSA_CRHBYTES, hpk, MLDSA_TRBYTES, pre, prelen, m, mlen);

    /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
    noxtls_mld_zeroize(hpk, sizeof(hpk));
  }
  else
  {
    /* mu has been provided directly */
    noxtls_mld_memcpy(mu, m, MLDSA_CRHBYTES);
  }

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  noxtls_mld_poly_challenge(cp, c);
  noxtls_mld_poly_ntt(cp);
  noxtls_mld_polyveck_shiftl(t1);
  noxtls_mld_polyveck_ntt(t1);
  noxtls_mld_polyveck_pointwise_poly_montgomery(tmp, cp, t1);

  noxtls_mld_polyvec_matrix_expand(mat, rho);
  noxtls_mld_polyvecl_ntt(z);
  noxtls_mld_polyvec_matrix_pointwise_montgomery(w1, mat, z);
  noxtls_mld_polyveck_sub(w1, tmp);
  noxtls_mld_polyveck_reduce(w1);
  noxtls_mld_polyveck_invntt_tomont(w1);

  /* Reconstruct w1 */
  noxtls_mld_polyveck_caddq(w1);
  noxtls_mld_polyveck_use_hint(tmp, w1, h);
  noxtls_mld_polyveck_pack_w1(buf, tmp);
  /* Call random oracle and verify challenge */
  noxtls_mld_H(c2, MLDSA_CTILDEBYTES, mu, MLDSA_CRHBYTES, buf,
        MLDSA_K * MLDSA_POLYW1_PACKEDBYTES, NULL, 0);

  cmp = noxtls_mld_ct_memcmp(c, c2, MLDSA_CTILDEBYTES);

  /* Declassify the result of the verification. */
  MLD_CT_TESTING_DECLASSIFY(&cmp, sizeof(cmp));

  ret = cmp == 0 ? 0 : MLD_ERR_FAIL;

cleanup:
  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  MLD_FREE(h, noxtls_mld_polyveck, 1, context);
  MLD_FREE(tmp, noxtls_mld_polyveck, 1, context);
  MLD_FREE(t1w1, t1w1_u, 1, context);
  MLD_FREE(z, noxtls_mld_polyvecl, 1, context);
  MLD_FREE(mat, noxtls_mld_polymat, 1, context);
  MLD_FREE(cp, noxtls_mld_poly, 1, context);
  MLD_FREE(c2, uint8_t, MLDSA_CTILDEBYTES, context);
  MLD_FREE(c, uint8_t, MLDSA_CTILDEBYTES, context);
  MLD_FREE(mu, uint8_t, MLDSA_CRHBYTES, context);
  MLD_FREE(rho, uint8_t, MLDSA_SEEDBYTES, context);
  MLD_FREE(buf, uint8_t, (MLDSA_K * MLDSA_POLYW1_PACKEDBYTES), context);
  return ret;
}

MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                    size_t mlen, const uint8_t *ctx, size_t ctxlen,
                    const uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                    MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  int ret;
  size_t pre_len;
  MLD_ALIGN uint8_t pre[MLD_DOMAIN_SEPARATION_MAX_BYTES];

  pre_len = noxtls_mld_prepare_domain_separation_prefix(pre, NULL, 0, ctx, ctxlen, MLD_PREHASH_NONE);
  if(pre_len == 0) {
    noxtls_mld_zeroize(pre, sizeof(pre));
    return MLD_ERR_FAIL;
  }

  ret = noxtls_mld_sign_verify_internal(sig, siglen, m, mlen, pre, pre_len, pk, 0, context);
  noxtls_mld_zeroize(pre, sizeof(pre));
  return ret;
}

MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_verify_extmu(const uint8_t *sig, size_t siglen,
                          const uint8_t mu[MLDSA_CRHBYTES],
                          const uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                          MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  return noxtls_mld_sign_verify_internal(sig, siglen, mu, MLDSA_CRHBYTES, NULL, 0, pk,
                                  1, context);
}

MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_open(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen,
                  const uint8_t *ctx, size_t ctxlen,
                  const uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                  MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  int ret;
  size_t i;

  if(smlen < MLDSA_CRYPTO_BYTES) {
    *mlen = 0;
    return MLD_ERR_FAIL;
  }

  *mlen = smlen - MLDSA_CRYPTO_BYTES;
  ret = noxtls_mld_sign_verify(sm, MLDSA_CRYPTO_BYTES, sm + MLDSA_CRYPTO_BYTES, *mlen,
                        ctx, ctxlen, pk, context);
  if(ret == 0) {
    for(i = 0; i < *mlen; ++i) {
      m[i] = sm[MLDSA_CRYPTO_BYTES + i];
    }
    return 0;
  }

  *mlen = 0;
  noxtls_mld_memset(m, 0, smlen);
  return ret;
}


MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_signature_pre_hash_internal(
    uint8_t sig[MLDSA_CRYPTO_BYTES], size_t *siglen, const uint8_t *ph,
    size_t phlen, const uint8_t *ctx, size_t ctxlen,
    const uint8_t rnd[MLDSA_RNDBYTES],
    const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES], int hashalg,
    MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  int ret;
  size_t pre_len;
  MLD_ALIGN uint8_t pre[MLD_DOMAIN_SEPARATION_MAX_BYTES];

  pre_len = noxtls_mld_prepare_domain_separation_prefix(pre, ph, phlen, ctx, ctxlen, hashalg);
  if(pre_len == 0) {
    *siglen = 0;
    noxtls_mld_memset(sig, 0, MLDSA_CRYPTO_BYTES);
    noxtls_mld_zeroize(pre, sizeof(pre));
    return MLD_ERR_FAIL;
  }

  ret = noxtls_mld_sign_signature_internal(sig, siglen, pre, pre_len, NULL, 0, rnd, sk, 0, context);
  if(ret != 0) {
    *siglen = 0;
    noxtls_mld_memset(sig, 0, MLDSA_CRYPTO_BYTES);
  }
  noxtls_mld_zeroize(pre, sizeof(pre));
  return ret;
}

MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_verify_pre_hash_internal(
    const uint8_t *sig, size_t siglen, const uint8_t *ph, size_t phlen,
    const uint8_t *ctx, size_t ctxlen,
    const uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES], int hashalg,
    MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  int ret;
  size_t pre_len;
  MLD_ALIGN uint8_t pre[MLD_DOMAIN_SEPARATION_MAX_BYTES];

  pre_len = noxtls_mld_prepare_domain_separation_prefix(pre, ph, phlen, ctx, ctxlen, hashalg);
  if(pre_len == 0) {
    noxtls_mld_zeroize(pre, sizeof(pre));
    return MLD_ERR_FAIL;
  }

  ret = noxtls_mld_sign_verify_internal(sig, siglen, pre, pre_len, NULL, 0, pk, 0, context);
  noxtls_mld_zeroize(pre, sizeof(pre));
  return ret;
}

MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_signature_pre_hash_shake256(
    uint8_t sig[MLDSA_CRYPTO_BYTES], size_t *siglen, const uint8_t *m,
    size_t mlen, const uint8_t *ctx, size_t ctxlen,
    const uint8_t rnd[MLDSA_RNDBYTES],
    const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
    MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  MLD_ALIGN uint8_t ph[64];
  int ret;
  noxtls_mld_shake256(ph, sizeof(ph), m, mlen);
  ret = noxtls_mld_sign_signature_pre_hash_internal(sig, siglen, ph, sizeof(ph), ctx,
                                             ctxlen, rnd, sk,
                                             MLD_PREHASH_SHAKE_256, context);
  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  noxtls_mld_zeroize(ph, sizeof(ph));
  return ret;
}

MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int noxtls_mld_sign_verify_pre_hash_shake256(
    const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
    const uint8_t *ctx, size_t ctxlen,
    const uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
    MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  MLD_ALIGN uint8_t ph[64];
  int ret;
  noxtls_mld_shake256(ph, sizeof(ph), m, mlen);
  ret = noxtls_mld_sign_verify_pre_hash_internal(sig, siglen, ph, sizeof(ph), ctx,
                                          ctxlen, pk, MLD_PREHASH_SHAKE_256,
                                          context);
  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  noxtls_mld_zeroize(ph, sizeof(ph));
  return ret;
}


#define MLD_PRE_HASH_OID_LEN 11

static void noxtls_mld_get_hash_oid(uint8_t oid[MLD_PRE_HASH_OID_LEN], int hashalg)
{
  static const uint8_t base_oid[MLD_PRE_HASH_OID_LEN] =
      {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x00};
  uint8_t suffix;

  suffix = 0u;
  switch(hashalg) {
    case MLD_PREHASH_SHA2_256:      suffix = 0x01; break;
    case MLD_PREHASH_SHA2_384:      suffix = 0x02; break;
    case MLD_PREHASH_SHA2_512:      suffix = 0x03; break;
    case MLD_PREHASH_SHA2_224:      suffix = 0x04; break;
    case MLD_PREHASH_SHA2_512_224:  suffix = 0x05; break;
    case MLD_PREHASH_SHA2_512_256:  suffix = 0x06; break;
    case MLD_PREHASH_SHA3_224:      suffix = 0x07; break;
    case MLD_PREHASH_SHA3_256:      suffix = 0x08; break;
    case MLD_PREHASH_SHA3_384:      suffix = 0x09; break;
    case MLD_PREHASH_SHA3_512:      suffix = 0x0A; break;
    case MLD_PREHASH_SHAKE_128:     suffix = 0x0B; break;
    case MLD_PREHASH_SHAKE_256:     suffix = 0x0C; break;
    default:
      noxtls_mld_memset(oid, 0, MLD_PRE_HASH_OID_LEN);
      return;
  }

  noxtls_mld_memcpy(oid, base_oid, MLD_PRE_HASH_OID_LEN);
  oid[MLD_PRE_HASH_OID_LEN - 1] = suffix;
}

static int noxtls_mld_validate_hash_length(int hashalg, size_t len)
{
  switch(hashalg) {
    case MLD_PREHASH_SHA2_224:
    case MLD_PREHASH_SHA2_512_224:
    case MLD_PREHASH_SHA3_224:
      return (len == 28u) ? 0 : -1;
    case MLD_PREHASH_SHA2_256:
    case MLD_PREHASH_SHA2_512_256:
    case MLD_PREHASH_SHA3_256:
    case MLD_PREHASH_SHAKE_128:
      return (len == 32u) ? 0 : -1;
    case MLD_PREHASH_SHA2_384:
    case MLD_PREHASH_SHA3_384:
      return (len == 48u) ? 0 : -1;
    case MLD_PREHASH_SHA2_512:
    case MLD_PREHASH_SHA3_512:
    case MLD_PREHASH_SHAKE_256:
      return (len == 64u) ? 0 : -1;
    default:
      return -1;
  }
}

size_t noxtls_mld_prepare_domain_separation_prefix(
    uint8_t prefix[MLD_DOMAIN_SEPARATION_MAX_BYTES], const uint8_t *ph,
    size_t phlen, const uint8_t *ctx, size_t ctxlen, int hashalg)
{
  if(ctxlen > 255u) {
    return 0;
  }

  if(hashalg != MLD_PREHASH_NONE) {
    if(ph == NULL || noxtls_mld_validate_hash_length(hashalg, phlen) != 0) {
      return 0;
    }
  }

  prefix[0] = (hashalg == MLD_PREHASH_NONE) ? 0 : 1;
  prefix[1] = (uint8_t)ctxlen;
  if(ctxlen > 0u) {
    noxtls_mld_memcpy(prefix + 2, ctx, ctxlen);
  }

  if(hashalg == MLD_PREHASH_NONE) {
    return 2u + ctxlen;
  }

  noxtls_mld_get_hash_oid(prefix + 2 + ctxlen, hashalg);
  noxtls_mld_memcpy(prefix + 2 + ctxlen + MLD_PRE_HASH_OID_LEN, ph, phlen);
  return 2u + ctxlen + MLD_PRE_HASH_OID_LEN + phlen;
}

MLD_EXTERNAL_API
int noxtls_mld_sign_pk_from_sk(uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                        const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                        MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  uint8_t check;
  uint8_t cmp0;
  uint8_t cmp1;
  uint8_t chk1;
  uint8_t chk2;
  int ret;
  MLD_ALLOC(rho, uint8_t, MLDSA_SEEDBYTES, context);
  MLD_ALLOC(tr, uint8_t, MLDSA_TRBYTES, context);
  MLD_ALLOC(tr_computed, uint8_t, MLDSA_TRBYTES, context);
  MLD_ALLOC(key, uint8_t, MLDSA_SEEDBYTES, context);
  MLD_ALLOC(s1, noxtls_mld_polyvecl, 1, context);
  MLD_ALLOC(s2, noxtls_mld_polyveck, 1, context);
  MLD_ALLOC(t0, noxtls_mld_polyveck, 1, context);
  MLD_ALLOC(t0_computed, noxtls_mld_polyveck, 1, context);
  MLD_ALLOC(t1, noxtls_mld_polyveck, 1, context);

  if(rho == NULL || tr == NULL || tr_computed == NULL || key == NULL ||
      s1 == NULL || s2 == NULL || t0 == NULL || t0_computed == NULL ||
      t1 == NULL)
  {
    ret = MLD_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  /* Unpack secret key */
  noxtls_mld_unpack_sk(rho, tr, key, t0, s1, s2, sk);

  /* Validate s1 and s2 coefficients are within [-MLDSA_ETA, MLDSA_ETA] */
  chk1 = noxtls_mld_polyvecl_chknorm(s1, MLDSA_ETA + 1) & 0xFF;
  chk2 = noxtls_mld_polyveck_chknorm(s2, MLDSA_ETA + 1) & 0xFF;

  /* Recompute t0, t1, tr, and pk from rho, s1, s2 */
  ret = noxtls_mld_compute_t0_t1_tr_from_sk_components(t0_computed, t1, tr_computed,
                                                pk, rho, s1, s2, context);
  if(ret != 0)
  {
    goto cleanup;
  }

  /* Validate t0 and tr using constant-time comparisons */
  cmp0 = noxtls_mld_ct_memcmp((const uint8_t *)t0, (const uint8_t *)t0_computed,
                       sizeof(noxtls_mld_polyveck));
  cmp1 = noxtls_mld_ct_memcmp((const uint8_t *)tr, (const uint8_t *)tr_computed,
                       MLDSA_TRBYTES);
  check = noxtls_mld_value_barrier_u8(cmp0 | cmp1 | chk1 | chk2);

  /* Declassify the final result of the validity check. */
  MLD_CT_TESTING_DECLASSIFY(&check, sizeof(check));
  ret = (check != 0) ? MLD_ERR_FAIL : 0;

cleanup:

  if(ret != 0)
  {
    noxtls_mld_zeroize(pk, MLDSA_CRYPTO_PUBLICKEYBYTES);
  }

  /* Constant time: pk is either the valid public key or zeroed on error */
  MLD_CT_TESTING_DECLASSIFY(pk, MLDSA_CRYPTO_PUBLICKEYBYTES);

  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  MLD_FREE(t1, noxtls_mld_polyveck, 1, context);
  MLD_FREE(t0_computed, noxtls_mld_polyveck, 1, context);
  MLD_FREE(t0, noxtls_mld_polyveck, 1, context);
  MLD_FREE(s2, noxtls_mld_polyveck, 1, context);
  MLD_FREE(s1, noxtls_mld_polyvecl, 1, context);
  MLD_FREE(key, uint8_t, MLDSA_SEEDBYTES, context);
  MLD_FREE(tr_computed, uint8_t, MLDSA_TRBYTES, context);
  MLD_FREE(tr, uint8_t, MLDSA_TRBYTES, context);
  MLD_FREE(rho, uint8_t, MLDSA_SEEDBYTES, context);

  return ret;
}

/* To facilitate single-compilation-unit (SCU) builds, undefine all macros.
 * Don't modify by hand -- this is auto-generated by scripts/autogen. */
#undef noxtls_mld_check_pct
#undef noxtls_mld_sample_s1_s2
#undef noxtls_mld_validate_hash_length
#undef noxtls_mld_get_hash_oid
#undef noxtls_mld_H
#undef noxtls_mld_compute_pack_z
#undef noxtls_mld_attempt_signature_generation
#undef noxtls_mld_compute_t0_t1_tr_from_sk_components
#undef MLD_NONCE_UB
#undef MLD_PRE_HASH_OID_LEN

#endif /* defined(MLD_CONFIG_PARAMETER_SET) */


