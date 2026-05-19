/*****************************************************************************
* This file is part of the NoxTLS Library.
*/

﻿/*
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#ifndef MLD_POLYVEC_H
#define MLD_POLYVEC_H

#include "noxtls_cbmc.h"
#include "noxtls_mldsa_internal_common.h"
#include "noxtls_poly.h"
#include "noxtls_poly_kl.h"

/* Parameter set namespacing
 * This is to facilitate building multiple instances
 * of mldsa-native (e.g. with varying parameter sets)
 * within a single compilation unit. */
#define noxtls_mld_polyvecl MLD_ADD_PARAM_SET(noxtls_mld_polyvecl)
#define noxtls_mld_polyveck MLD_ADD_PARAM_SET(noxtls_mld_polyveck)
#define noxtls_mld_polymat MLD_ADD_PARAM_SET(noxtls_mld_polymat)
/* End of parameter set namespacing */

/* Vectors of polynomials of length MLDSA_L */
typedef struct
{
  noxtls_mld_poly vec[MLDSA_L];
} noxtls_mld_polyvecl;


#define noxtls_mld_polyvecl_uniform_gamma1 MLD_NAMESPACE_KL(polyvecl_uniform_gamma1)
/*************************************************
 * Name:        noxtls_mld_polyvecl_uniform_gamma1
 *
 * Description: Sample vector of polynomials with uniformly random coefficients
 *              in [-(MLDSA_GAMMA1 - 1), MLDSA_GAMMA1] by unpacking output
 *              stream of SHAKE256(seed|nonce)
 *
 * Arguments:   - noxtls_mld_polyvecl *v: pointer to output vector
 *              - const uint8_t seed[]: byte array with seed of length
 *                MLDSA_CRHBYTES
 *              - uint16_t nonce: 16-bit nonce
 *************************************************/
MLD_INTERNAL_API
void noxtls_mld_polyvecl_uniform_gamma1(noxtls_mld_polyvecl *v,
                                 const uint8_t seed[MLDSA_CRHBYTES],
                                 uint16_t nonce)
__contract__(
  requires(memory_no_alias(v, sizeof(noxtls_mld_polyvecl)))
  requires(memory_no_alias(seed, MLDSA_CRHBYTES))
  requires(nonce <= (UINT16_MAX - MLDSA_L) / MLDSA_L)
  assigns(memory_slice(v, sizeof(noxtls_mld_polyvecl)))
  ensures(forall(k0, 0, MLDSA_L,
    array_bound(v->vec[k0].coeffs, 0, MLDSA_N, -(MLDSA_GAMMA1 - 1), MLDSA_GAMMA1 + 1)))
);

#define noxtls_mld_polyvecl_ntt MLD_NAMESPACE_KL(polyvecl_ntt)
/*************************************************
 * Name:        noxtls_mld_polyvecl_ntt
 *
 * Description: Forward NTT of all polynomials in vector of length MLDSA_L.
 *              Coefficients can grow by 8*MLDSA_Q in absolute value.
 *
 * Arguments:   - noxtls_mld_polyvecl *v: pointer to input/output vector
 **************************************************/
MLD_INTERNAL_API
void noxtls_mld_polyvecl_ntt(noxtls_mld_polyvecl *v)
__contract__(
  requires(memory_no_alias(v, sizeof(noxtls_mld_polyvecl)))
  requires(forall(k0, 0, MLDSA_L, array_abs_bound(v->vec[k0].coeffs, 0, MLDSA_N, MLDSA_Q)))
  assigns(memory_slice(v, sizeof(noxtls_mld_polyvecl)))
  ensures(forall(k1, 0, MLDSA_L, array_abs_bound(v->vec[k1].coeffs, 0, MLDSA_N, MLD_NTT_BOUND)))
);

#define noxtls_mld_polyvecl_pointwise_acc_montgomery \
  MLD_NAMESPACE_KL(polyvecl_pointwise_acc_montgomery)
/*************************************************
 * Name:        noxtls_mld_polyvecl_pointwise_acc_montgomery
 *
 * Description: Pointwise multiply vectors of polynomials of length MLDSA_L,
 *              multiply resulting vector by 2^{-32} and add (accumulate)
 *              polynomials in it.
 *              Input/output vectors are in NTT domain representation.
 *
 *              The first input "u" must be the output of
 *              polyvec_matrix_expand() and so have coefficients in [0, Q-1]
 *              inclusive.
 *
 *              The second input "v" is assumed to be output of an NTT, and
 *              hence must have coefficients bounded by [-9q+1, +9q-1]
 *              inclusive.
 *
 *
 * Arguments:   - noxtls_mld_poly *w: output polynomial
 *              - const noxtls_mld_polyvecl *u: pointer to first input vector
 *              - const noxtls_mld_polyvecl *v: pointer to second input vector
 **************************************************/
MLD_INTERNAL_API
void noxtls_mld_polyvecl_pointwise_acc_montgomery(noxtls_mld_poly *w, const noxtls_mld_polyvecl *u,
                                           const noxtls_mld_polyvecl *v)
__contract__(
  requires(memory_no_alias(w, sizeof(noxtls_mld_poly)))
  requires(memory_no_alias(u, sizeof(noxtls_mld_polyvecl)))
  requires(memory_no_alias(v, sizeof(noxtls_mld_polyvecl)))
  requires(forall(l0, 0, MLDSA_L,
                  array_bound(u->vec[l0].coeffs, 0, MLDSA_N, 0, MLDSA_Q)))
  requires(forall(l1, 0, MLDSA_L,
    array_abs_bound(v->vec[l1].coeffs, 0, MLDSA_N, MLD_NTT_BOUND)))
  assigns(memory_slice(w, sizeof(noxtls_mld_poly)))
  ensures(array_abs_bound(w->coeffs, 0, MLDSA_N, MLDSA_Q))
);


#define noxtls_mld_polyvecl_chknorm MLD_NAMESPACE_KL(polyvecl_chknorm)
/*************************************************
 * Name:        noxtls_mld_polyvecl_chknorm
 *
 * Description: Check infinity norm of polynomials in vector of length MLDSA_L.
 *              Assumes input noxtls_mld_polyvecl to be reduced by polyvecl_reduce().
 *
 * Arguments:   - const noxtls_mld_polyvecl *v: pointer to vector
 *              - int32_t B: norm bound
 *
 * Returns 0 if norm of all polynomials is strictly smaller than B <=
 * (MLDSA_Q-1)/8 and 0xFFFFFFFF otherwise.
 **************************************************/
MLD_INTERNAL_API
MLD_MUST_CHECK_RETURN_VALUE
uint32_t noxtls_mld_polyvecl_chknorm(const noxtls_mld_polyvecl *v, int32_t B)
__contract__(
  requires(memory_no_alias(v, sizeof(noxtls_mld_polyvecl)))
  requires(0 <= B && B <= (MLDSA_Q - 1) / 8)
  requires(forall(k0, 0, MLDSA_L,
    array_bound(v->vec[k0].coeffs, 0, MLDSA_N, -MLD_REDUCE32_RANGE_MAX, MLD_REDUCE32_RANGE_MAX)))
  ensures(return_value == 0 || return_value == 0xFFFFFFFF)
  ensures((return_value == 0) == forall(k1, 0, MLDSA_L, array_abs_bound(v->vec[k1].coeffs, 0, MLDSA_N, B)))
);

/* Vectors of polynomials of length MLDSA_K */
typedef struct
{
  noxtls_mld_poly vec[MLDSA_K];
} noxtls_mld_polyveck;

/* Matrix of polynomials (K x L) */
typedef struct
{
#if defined(MLD_CONFIG_REDUCE_RAM)
  noxtls_mld_polyvecl row_buffer;
  uint8_t rho[MLDSA_SEEDBYTES];
#else
  noxtls_mld_polyvecl vec[MLDSA_K];
#endif
} noxtls_mld_polymat;

#define noxtls_mld_polyveck_reduce MLD_NAMESPACE_KL(polyveck_reduce)
/*************************************************
 * Name:        polyveck_reduce
 *
 * Description: Reduce coefficients of polynomials in vector of length MLDSA_K
 *              to representatives in
 *[-MLD_REDUCE32_RANGE_MAX,MLD_REDUCE32_RANGE_MAX].
 *
 * Arguments:   - noxtls_mld_polyveck *v: pointer to input/output vector
 **************************************************/
MLD_INTERNAL_API
void noxtls_mld_polyveck_reduce(noxtls_mld_polyveck *v)
__contract__(
  requires(memory_no_alias(v, sizeof(noxtls_mld_polyveck)))
  requires(forall(k0, 0, MLDSA_K,
    array_bound(v->vec[k0].coeffs, 0, MLDSA_N, INT32_MIN, MLD_REDUCE32_DOMAIN_MAX)))
  assigns(memory_slice(v, sizeof(noxtls_mld_polyveck)))
  ensures(forall(k1, 0, MLDSA_K,
    array_bound(v->vec[k1].coeffs, 0, MLDSA_N, -MLD_REDUCE32_RANGE_MAX, MLD_REDUCE32_RANGE_MAX)))
);

#define noxtls_mld_polyveck_caddq MLD_NAMESPACE_KL(polyveck_caddq)
/*************************************************
 * Name:        noxtls_mld_polyveck_caddq
 *
 * Description: For all coefficients of polynomials in vector of length MLDSA_K
 *              add MLDSA_Q if coefficient is negative.
 *
 * Arguments:   - noxtls_mld_polyveck *v: pointer to input/output vector
 **************************************************/
MLD_INTERNAL_API
void noxtls_mld_polyveck_caddq(noxtls_mld_polyveck *v)
__contract__(
  requires(memory_no_alias(v, sizeof(noxtls_mld_polyveck)))
  requires(forall(k0, 0, MLDSA_K,
    array_abs_bound(v->vec[k0].coeffs, 0, MLDSA_N, MLDSA_Q)))
  assigns(memory_slice(v, sizeof(noxtls_mld_polyveck)))
  ensures(forall(k1, 0, MLDSA_K,
    array_bound(v->vec[k1].coeffs, 0, MLDSA_N, 0, MLDSA_Q)))
);

#define noxtls_mld_polyveck_add MLD_NAMESPACE_KL(polyveck_add)
/*************************************************
 * Name:        noxtls_mld_polyveck_add
 *
 * Description: Add vectors of polynomials of length MLDSA_K.
 *              No modular reduction is performed.
 *
 * Arguments:   - noxtls_mld_polyveck *u: pointer to input-output vector of polynomials
 *                                 to be added to
 *              - const noxtls_mld_polyveck *v: pointer to second input vector of
 *                                       polynomials
 **************************************************/
MLD_INTERNAL_API
void noxtls_mld_polyveck_add(noxtls_mld_polyveck *u, const noxtls_mld_polyveck *v)
__contract__(
  requires(memory_no_alias(u, sizeof(noxtls_mld_polyveck)))
  requires(memory_no_alias(v, sizeof(noxtls_mld_polyveck)))
  requires(forall(p0, 0, MLDSA_K, array_abs_bound(u->vec[p0].coeffs, 0, MLDSA_N, MLD_INTT_BOUND)))
  requires(forall(p1, 0, MLDSA_K,
    array_bound(v->vec[p1].coeffs, 0, MLDSA_N, -MLD_REDUCE32_RANGE_MAX, MLD_REDUCE32_RANGE_MAX)))
  assigns(memory_slice(u, sizeof(noxtls_mld_polyveck)))
  ensures(forall(q2, 0, MLDSA_K,
                array_bound(u->vec[q2].coeffs, 0, MLDSA_N, INT32_MIN, MLD_REDUCE32_DOMAIN_MAX)))
);

#define noxtls_mld_polyveck_sub MLD_NAMESPACE_KL(polyveck_sub)
/*************************************************
 * Name:        noxtls_mld_polyveck_sub
 *
 * Description: Subtract vectors of polynomials of length MLDSA_K.
 *              No modular reduction is performed.
 *
 * Arguments:   - noxtls_mld_polyveck *u: pointer to first input vector
 *              - const noxtls_mld_polyveck *v: pointer to second input vector to be
 *                                   subtracted from first input vector
 **************************************************/
MLD_INTERNAL_API
void noxtls_mld_polyveck_sub(noxtls_mld_polyveck *u, const noxtls_mld_polyveck *v)
__contract__(
  requires(memory_no_alias(u, sizeof(noxtls_mld_polyveck)))
  requires(memory_no_alias(v, sizeof(noxtls_mld_polyveck)))
  requires(forall(k0, 0, MLDSA_K, array_abs_bound(u->vec[k0].coeffs, 0, MLDSA_N, MLDSA_Q)))
  requires(forall(k1, 0, MLDSA_K, array_abs_bound(v->vec[k1].coeffs, 0, MLDSA_N, MLDSA_Q)))
  assigns(memory_slice(u, sizeof(noxtls_mld_polyveck)))
  ensures(forall(k0, 0, MLDSA_K,
                 array_bound(u->vec[k0].coeffs, 0, MLDSA_N, INT32_MIN, MLD_REDUCE32_DOMAIN_MAX)))
);

#define noxtls_mld_polyveck_shiftl MLD_NAMESPACE_KL(polyveck_shiftl)
/*************************************************
 * Name:        noxtls_mld_polyveck_shiftl
 *
 * Description: Multiply vector of polynomials of Length MLDSA_K by 2^MLDSA_D
 *without modular reduction. Assumes input coefficients to be less than
 *2^{31-MLDSA_D}.
 *
 * Arguments:   - noxtls_mld_polyveck *v: pointer to input/output vector
 **************************************************/
MLD_INTERNAL_API
void noxtls_mld_polyveck_shiftl(noxtls_mld_polyveck *v)
__contract__(
  requires(memory_no_alias(v, sizeof(noxtls_mld_polyveck)))
  requires(forall(k0, 0, MLDSA_K, array_bound(v->vec[k0].coeffs, 0, MLDSA_N, 0, 1 << 10)))
  assigns(memory_slice(v, sizeof(noxtls_mld_polyveck)))
  ensures(forall(k1, 0, MLDSA_K, array_bound(v->vec[k1].coeffs, 0, MLDSA_N, 0, MLDSA_Q)))
);

#define noxtls_mld_polyveck_ntt MLD_NAMESPACE_KL(polyveck_ntt)
/*************************************************
 * Name:        noxtls_mld_polyveck_ntt
 *
 * Description: Forward NTT of all polynomials in vector of length MLDSA_K.
 *              Coefficients can grow by 8*MLDSA_Q in absolute value.
 *
 * Arguments:   - noxtls_mld_polyveck *v: pointer to input/output vector
 **************************************************/
MLD_INTERNAL_API
void noxtls_mld_polyveck_ntt(noxtls_mld_polyveck *v)
__contract__(
  requires(memory_no_alias(v, sizeof(noxtls_mld_polyveck)))
  requires(forall(k0, 0, MLDSA_K, array_abs_bound(v->vec[k0].coeffs, 0, MLDSA_N, MLDSA_Q)))
  assigns(memory_slice(v, sizeof(noxtls_mld_polyveck)))
  ensures(forall(k1, 0, MLDSA_K, array_abs_bound(v->vec[k1].coeffs, 0, MLDSA_N, MLD_NTT_BOUND)))
);

#define noxtls_mld_polyveck_invntt_tomont MLD_NAMESPACE_KL(polyveck_invntt_tomont)
/*************************************************
 * Name:        noxtls_mld_polyveck_invntt_tomont
 *
 * Description: Inverse NTT and multiplication by 2^{32} of polynomials
 *              in vector of length MLDSA_K.
 *              Input coefficients need to be less than MLDSA_Q, and
 *              Output coefficients are bounded by MLD_INTT_BOUND.
 * Arguments:   - noxtls_mld_polyveck *v: pointer to input/output vector
 **************************************************/
MLD_INTERNAL_API
void noxtls_mld_polyveck_invntt_tomont(noxtls_mld_polyveck *v)
__contract__(
  requires(memory_no_alias(v, sizeof(noxtls_mld_polyveck)))
  requires(forall(k0, 0, MLDSA_K, array_abs_bound(v->vec[k0].coeffs, 0, MLDSA_N, MLDSA_Q)))
  assigns(memory_slice(v, sizeof(noxtls_mld_polyveck)))
  ensures(forall(k1, 0, MLDSA_K, array_abs_bound(v->vec[k1].coeffs, 0, MLDSA_N, MLD_INTT_BOUND)))
);

#define noxtls_mld_polyveck_pointwise_poly_montgomery \
  MLD_NAMESPACE_KL(polyveck_pointwise_poly_montgomery)
/*************************************************
 * Name:        noxtls_mld_polyveck_pointwise_poly_montgomery
 *
 * Description: Pointwise multiplication of a polynomial vector of length
 *              MLDSA_K by a single polynomial in NTT domain and multiplication
 *              of the resulting polynomial vector by 2^{-32}.
 *
 * Arguments:   - noxtls_mld_polyveck *r: pointer to output vector
 *              - noxtls_mld_poly *a: pointer to input polynomial
 *              - noxtls_mld_polyveck *v: pointer to input vector
 **************************************************/
MLD_INTERNAL_API
void noxtls_mld_polyveck_pointwise_poly_montgomery(noxtls_mld_polyveck *r, const noxtls_mld_poly *a,
                                            const noxtls_mld_polyveck *v)
__contract__(
  requires(memory_no_alias(r, sizeof(noxtls_mld_polyveck)))
  requires(memory_no_alias(a, sizeof(noxtls_mld_poly)))
  requires(memory_no_alias(v, sizeof(noxtls_mld_polyveck)))
  requires(array_abs_bound(a->coeffs, 0, MLDSA_N, MLD_NTT_BOUND))
  requires(forall(k0, 0, MLDSA_K, array_abs_bound(v->vec[k0].coeffs, 0, MLDSA_N, MLD_NTT_BOUND)))
  assigns(memory_slice(r, sizeof(noxtls_mld_polyveck)))
  ensures(forall(k1, 0, MLDSA_K, array_abs_bound(r->vec[k1].coeffs, 0, MLDSA_N, MLDSA_Q)))
);

#define noxtls_mld_polyveck_chknorm MLD_NAMESPACE_KL(polyveck_chknorm)
/*************************************************
 * Name:        noxtls_mld_polyveck_chknorm
 *
 * Description: Check infinity norm of polynomials in vector of length MLDSA_K.
 *              Assumes input noxtls_mld_polyveck to be reduced by polyveck_reduce().
 *
 * Arguments:   - const noxtls_mld_polyveck *v: pointer to vector
 *              - int32_t B: norm bound
 *
 * Returns 0 if norm of all polynomials are strictly smaller than B <=
 *(MLDSA_Q-1)/8 and 0xFFFFFFFF otherwise.
 **************************************************/
MLD_INTERNAL_API
MLD_MUST_CHECK_RETURN_VALUE
uint32_t noxtls_mld_polyveck_chknorm(const noxtls_mld_polyveck *v, int32_t B)
__contract__(
  requires(memory_no_alias(v, sizeof(noxtls_mld_polyveck)))
  requires(0 <= B && B <= (MLDSA_Q - 1) / 8)
  requires(forall(k0, 0, MLDSA_K,
                  array_bound(v->vec[k0].coeffs, 0, MLDSA_N,
                              -MLD_REDUCE32_RANGE_MAX, MLD_REDUCE32_RANGE_MAX)))
  ensures(return_value == 0 || return_value == 0xFFFFFFFF)
  ensures((return_value == 0) == forall(k1, 0, MLDSA_K, array_abs_bound(v->vec[k1].coeffs, 0, MLDSA_N, B)))
);

#define noxtls_mld_polyveck_power2round MLD_NAMESPACE_KL(polyveck_power2round)
/*************************************************
 * Name:        noxtls_mld_polyveck_power2round
 *
 * Description: For all coefficients a of polynomials in vector of length
 *MLDSA_K, compute a0, a1 such that a mod^+ MLDSA_Q = a1*2^MLDSA_D + a0 with
 *-2^{MLDSA_D-1} < a0 <= 2^{MLDSA_D-1}. Assumes coefficients to be standard
 *representatives.
 *
 * Arguments:   - noxtls_mld_polyveck *v1: pointer to output vector of polynomials with
 *                              coefficients a1
 *              - noxtls_mld_polyveck *v0: pointer to output vector of polynomials with
 *                              coefficients a0
 *              - const noxtls_mld_polyveck *v: pointer to input vector
 **************************************************/
MLD_INTERNAL_API
void noxtls_mld_polyveck_power2round(noxtls_mld_polyveck *v1, noxtls_mld_polyveck *v0,
                              const noxtls_mld_polyveck *v)
__contract__(
  requires(memory_no_alias(v1, sizeof(noxtls_mld_polyveck)))
  requires(memory_no_alias(v0, sizeof(noxtls_mld_polyveck)))
  requires(memory_no_alias(v, sizeof(noxtls_mld_polyveck)))
  requires(forall(k0, 0, MLDSA_K, array_bound(v->vec[k0].coeffs, 0, MLDSA_N, 0, MLDSA_Q)))
  assigns(memory_slice(v1, sizeof(noxtls_mld_polyveck)))
  assigns(memory_slice(v0, sizeof(noxtls_mld_polyveck)))
  ensures(forall(k1, 0, MLDSA_K, array_bound(v0->vec[k1].coeffs, 0, MLDSA_N, -(MLD_2_POW_D/2)+1, (MLD_2_POW_D/2)+1)))
  ensures(forall(k2, 0, MLDSA_K, array_bound(v1->vec[k2].coeffs, 0, MLDSA_N, 0, ((MLDSA_Q - 1) / MLD_2_POW_D) + 1)))
);

#define noxtls_mld_polyveck_decompose MLD_NAMESPACE_KL(polyveck_decompose)
/*************************************************
 * Name:        noxtls_mld_polyveck_decompose
 *
 * Description: For all coefficients a of polynomials in vector of length
 * MLDSA_K, compute high and low bits a0, a1 such a mod^+ MLDSA_Q = a1*ALPHA
 * + a0 with -ALPHA/2 < a0 <= ALPHA/2 except a1 = (MLDSA_Q-1)/ALPHA where we set
 * a1 = 0 and -ALPHA/2 <= a0 = a mod MLDSA_Q - MLDSA_Q < 0. Assumes coefficients
 * to be standard representatives.
 *
 * Arguments:   - noxtls_mld_polyveck *v1: pointer to output vector of polynomials with
 *                                  coefficients a1
 *              - noxtls_mld_polyveck *v0: pointer to input/output vector of
 *                                  polynomials with. Output polynomial has
 *                                  coefficients a0
 *
 * Reference: The reference implementation has the input polynomial as a
 *            separate argument that may be aliased with either of the outputs.
 *            Removing the aliasing eases CBMC proofs.
 *
 **************************************************/
MLD_INTERNAL_API
void noxtls_mld_polyveck_decompose(noxtls_mld_polyveck *v1, noxtls_mld_polyveck *v0)
__contract__(
  requires(memory_no_alias(v1,  sizeof(noxtls_mld_polyveck)))
  requires(memory_no_alias(v0, sizeof(noxtls_mld_polyveck)))
  requires(forall(k0, 0, MLDSA_K,
    array_bound(v0->vec[k0].coeffs, 0, MLDSA_N, 0, MLDSA_Q)))
  assigns(memory_slice(v1, sizeof(noxtls_mld_polyveck)))
  assigns(memory_slice(v0, sizeof(noxtls_mld_polyveck)))
  ensures(forall(k1, 0, MLDSA_K,
                 array_bound(v1->vec[k1].coeffs, 0, MLDSA_N, 0, (MLDSA_Q-1)/(2*MLDSA_GAMMA2))))
  ensures(forall(k2, 0, MLDSA_K,
                 array_abs_bound(v0->vec[k2].coeffs, 0, MLDSA_N, MLDSA_GAMMA2+1)))
);

#define noxtls_mld_polyveck_make_hint MLD_NAMESPACE_KL(polyveck_make_hint)
/*************************************************
 * Name:        noxtls_mld_polyveck_make_hint
 *
 * Description: Compute hint vector.
 *
 * Arguments:   - noxtls_mld_polyveck *h: pointer to output vector
 *              - const noxtls_mld_polyveck *v0: pointer to low part of input vector
 *              - const noxtls_mld_polyveck *v1: pointer to high part of input vector
 *
 * Returns number of 1 bits.
 **************************************************/
MLD_INTERNAL_API
MLD_MUST_CHECK_RETURN_VALUE
unsigned int noxtls_mld_polyveck_make_hint(noxtls_mld_polyveck *h, const noxtls_mld_polyveck *v0,
                                    const noxtls_mld_polyveck *v1)
__contract__(
  requires(memory_no_alias(h,  sizeof(noxtls_mld_polyveck)))
  requires(memory_no_alias(v0, sizeof(noxtls_mld_polyveck)))
  requires(memory_no_alias(v1, sizeof(noxtls_mld_polyveck)))
  assigns(memory_slice(h, sizeof(noxtls_mld_polyveck)))
  ensures(return_value <= MLDSA_N * MLDSA_K)
  ensures(forall(k1, 0, MLDSA_K, array_bound(h->vec[k1].coeffs, 0, MLDSA_N, 0, 2)))
);

#define noxtls_mld_polyveck_use_hint MLD_NAMESPACE_KL(polyveck_use_hint)
/*************************************************
 * Name:        noxtls_mld_polyveck_use_hint
 *
 * Description: Use hint vector to correct the high bits of input vector.
 *
 * Arguments:   - noxtls_mld_polyveck *w: pointer to output vector of polynomials with
 *                             corrected high bits
 *              - const noxtls_mld_polyveck *u: pointer to input vector
 *              - const noxtls_mld_polyveck *h: pointer to input hint vector
 **************************************************/
MLD_INTERNAL_API
void noxtls_mld_polyveck_use_hint(noxtls_mld_polyveck *w, const noxtls_mld_polyveck *v,
                           const noxtls_mld_polyveck *h)
__contract__(
  requires(memory_no_alias(w,  sizeof(noxtls_mld_polyveck)))
  requires(memory_no_alias(v, sizeof(noxtls_mld_polyveck)))
  requires(memory_no_alias(h, sizeof(noxtls_mld_polyveck)))
  requires(forall(k0, 0, MLDSA_K,
    array_bound(v->vec[k0].coeffs, 0, MLDSA_N, 0, MLDSA_Q)))
  requires(forall(k1, 0, MLDSA_K,
    array_bound(h->vec[k1].coeffs, 0, MLDSA_N, 0, 2)))
  assigns(memory_slice(w, sizeof(noxtls_mld_polyveck)))
  ensures(forall(k2, 0, MLDSA_K,
    array_bound(w->vec[k2].coeffs, 0, MLDSA_N, 0, (MLDSA_Q-1)/(2*MLDSA_GAMMA2))))
);

#define noxtls_mld_polyveck_pack_w1 MLD_NAMESPACE_KL(polyveck_pack_w1)
/*************************************************
 * Name:        noxtls_mld_polyveck_pack_w1
 *
 * Description: Bit-pack polynomial vector w1 with coefficients in [0,15] or
 *              [0,43].
 *              Input coefficients are assumed to be standard representatives.
 *
 * Arguments:   - uint8_t *r: pointer to output byte array with at least
 *                            MLDSA_K* MLDSA_POLYW1_PACKEDBYTES bytes
 *              - const noxtls_mld_polyveck *a: pointer to input polynomial vector
 **************************************************/
MLD_INTERNAL_API
void noxtls_mld_polyveck_pack_w1(uint8_t r[MLDSA_K * MLDSA_POLYW1_PACKEDBYTES],
                          const noxtls_mld_polyveck *w1)
__contract__(
  requires(memory_no_alias(r, MLDSA_K * MLDSA_POLYW1_PACKEDBYTES))
  requires(memory_no_alias(w1, sizeof(noxtls_mld_polyveck)))
  requires(forall(k1, 0, MLDSA_K,
    array_bound(w1->vec[k1].coeffs, 0, MLDSA_N, 0, (MLDSA_Q-1)/(2*MLDSA_GAMMA2))))
  assigns(memory_slice(r, MLDSA_K * MLDSA_POLYW1_PACKEDBYTES))
);

#define noxtls_mld_polyveck_pack_eta MLD_NAMESPACE_KL(polyveck_pack_eta)
/*************************************************
 * Name:        noxtls_mld_polyveck_pack_eta
 *
 * Description: Bit-pack polynomial vector with coefficients
 *              in [-MLDSA_ETA,MLDSA_ETA].
 *
 * Arguments:   - uint8_t *r: pointer to output byte array with
 *                            MLDSA_K * MLDSA_POLYETA_PACKEDBYTES bytes
 *              - const polyveck *p: pointer to input polynomial vector
 **************************************************/
MLD_INTERNAL_API
void noxtls_mld_polyveck_pack_eta(uint8_t r[MLDSA_K * MLDSA_POLYETA_PACKEDBYTES],
                           const noxtls_mld_polyveck *p)
__contract__(
  requires(memory_no_alias(r,  MLDSA_K * MLDSA_POLYETA_PACKEDBYTES))
  requires(memory_no_alias(p, sizeof(noxtls_mld_polyveck)))
  requires(forall(k1, 0, MLDSA_K,
    array_abs_bound(p->vec[k1].coeffs, 0, MLDSA_N, MLDSA_ETA + 1)))
  assigns(memory_slice(r, MLDSA_K * MLDSA_POLYETA_PACKEDBYTES))
);

#define noxtls_mld_polyvecl_pack_eta MLD_NAMESPACE_KL(polyvecl_pack_eta)
/*************************************************
 * Name:        noxtls_mld_polyvecl_pack_eta
 *
 * Description: Bit-pack polynomial vector with coefficients in
 *              [-MLDSA_ETA,MLDSA_ETA].
 *
 * Arguments:   - uint8_t *r: pointer to output byte array with
 *                            MLDSA_L * MLDSA_POLYETA_PACKEDBYTES bytes
 *              - const polyveck *p: pointer to input polynomial vector
 **************************************************/
MLD_INTERNAL_API
void noxtls_mld_polyvecl_pack_eta(uint8_t r[MLDSA_L * MLDSA_POLYETA_PACKEDBYTES],
                           const noxtls_mld_polyvecl *p)
__contract__(
  requires(memory_no_alias(r,  MLDSA_L * MLDSA_POLYETA_PACKEDBYTES))
  requires(memory_no_alias(p, sizeof(noxtls_mld_polyvecl)))
  requires(forall(k1, 0, MLDSA_L,
    array_abs_bound(p->vec[k1].coeffs, 0, MLDSA_N, MLDSA_ETA + 1)))
  assigns(memory_slice(r, MLDSA_L * MLDSA_POLYETA_PACKEDBYTES))
);

#define noxtls_mld_polyveck_pack_t0 MLD_NAMESPACE_KL(polyveck_pack_t0)
/*************************************************
 * Name:        noxtls_mld_polyveck_pack_t0
 *
 * Description: Bit-pack polynomial vector to with coefficients in
 *              ]-2^{MLDSA_D-1}, 2^{MLDSA_D-1}].
 *
 * Arguments:   - uint8_t *r: pointer to output byte array with
 *                            MLDSA_K * MLDSA_POLYT0_PACKEDBYTES bytes
 *              - const noxtls_mld_poly *p: pointer to input polynomial vector
 **************************************************/
MLD_INTERNAL_API
void noxtls_mld_polyveck_pack_t0(uint8_t r[MLDSA_K * MLDSA_POLYT0_PACKEDBYTES],
                          const noxtls_mld_polyveck *p)
__contract__(
  requires(memory_no_alias(r,  MLDSA_K * MLDSA_POLYT0_PACKEDBYTES))
  requires(memory_no_alias(p, sizeof(noxtls_mld_polyveck)))
  requires(forall(k0, 0, MLDSA_K,
    array_bound(p->vec[k0].coeffs, 0, MLDSA_N, -(1<<(MLDSA_D-1)) + 1, (1<<(MLDSA_D-1)) + 1)))
  assigns(memory_slice(r, MLDSA_K * MLDSA_POLYT0_PACKEDBYTES))
);

#define noxtls_mld_polyvecl_unpack_eta MLD_NAMESPACE_KL(polyvecl_unpack_eta)
/*************************************************
 * Name:        noxtls_mld_polyvecl_unpack_eta
 *
 * Description: Unpack polynomial vector with coefficients in
 *              [-MLDSA_ETA,MLDSA_ETA].
 *
 * Arguments:   - noxtls_mld_polyvecl *p: pointer to output polynomial vector
 *              - const uint8_t *r: input byte array with
 *                                  bit-packed polynomial vector
 **************************************************/
MLD_INTERNAL_API
void noxtls_mld_polyvecl_unpack_eta(
    noxtls_mld_polyvecl *p, const uint8_t r[MLDSA_L * MLDSA_POLYETA_PACKEDBYTES])
__contract__(
  requires(memory_no_alias(r,  MLDSA_L * MLDSA_POLYETA_PACKEDBYTES))
  requires(memory_no_alias(p, sizeof(noxtls_mld_polyvecl)))
  assigns(memory_slice(p, sizeof(noxtls_mld_polyvecl)))
  ensures(forall(k1, 0, MLDSA_L,
    array_bound(p->vec[k1].coeffs, 0, MLDSA_N, MLD_POLYETA_UNPACK_LOWER_BOUND, MLDSA_ETA + 1)))
);

#define noxtls_mld_polyvecl_unpack_z MLD_NAMESPACE_KL(polyvecl_unpack_z)
/*************************************************
 * Name:        noxtls_mld_polyvecl_unpack_z
 *
 * Description: Unpack polynomial vector with coefficients in
 *              [-(MLDSA_GAMMA1 - 1), MLDSA_GAMMA1].
 *
 * Arguments:   - noxtls_mld_polyvecl *z: pointer to output polynomial vector
 *              - const uint8_t *r: input byte array with
 *                                  bit-packed polynomial vector
 **************************************************/
MLD_INTERNAL_API
void noxtls_mld_polyvecl_unpack_z(noxtls_mld_polyvecl *z,
                           const uint8_t r[MLDSA_L * MLDSA_POLYZ_PACKEDBYTES])
__contract__(
  requires(memory_no_alias(r,  MLDSA_L * MLDSA_POLYZ_PACKEDBYTES))
  requires(memory_no_alias(z, sizeof(noxtls_mld_polyvecl)))
  assigns(memory_slice(z, sizeof(noxtls_mld_polyvecl)))
  ensures(forall(k1, 0, MLDSA_L,
    array_bound(z->vec[k1].coeffs, 0, MLDSA_N, -(MLDSA_GAMMA1 - 1), MLDSA_GAMMA1 + 1)))
);

#define noxtls_mld_polyveck_unpack_eta MLD_NAMESPACE_KL(polyveck_unpack_eta)
/*************************************************
 * Name:        noxtls_mld_polyveck_unpack_eta
 *
 * Description: Unpack polynomial vector with coefficients in
 *              [-MLDSA_ETA,MLDSA_ETA].
 *
 * Arguments:   - noxtls_mld_polyveck *p: pointer to output polynomial vector
 *              - const uint8_t *r: input byte array with
 *                                  bit-packed polynomial vector
 **************************************************/
MLD_INTERNAL_API
void noxtls_mld_polyveck_unpack_eta(
    noxtls_mld_polyveck *p, const uint8_t r[MLDSA_K * MLDSA_POLYETA_PACKEDBYTES])
__contract__(
  requires(memory_no_alias(r,  MLDSA_K * MLDSA_POLYETA_PACKEDBYTES))
  requires(memory_no_alias(p, sizeof(noxtls_mld_polyveck)))
  assigns(memory_slice(p, sizeof(noxtls_mld_polyveck)))
  ensures(forall(k1, 0, MLDSA_K,
    array_bound(p->vec[k1].coeffs, 0, MLDSA_N, MLD_POLYETA_UNPACK_LOWER_BOUND, MLDSA_ETA + 1)))
);

#define noxtls_mld_polyveck_unpack_t0 MLD_NAMESPACE_KL(polyveck_unpack_t0)
/*************************************************
 * Name:        noxtls_mld_polyveck_unpack_t0
 *
 * Description: Unpack polynomial vector with coefficients in
 *              ]-2^{MLDSA_D-1}, 2^{MLDSA_D-1}].
 *
 * Arguments:   - noxtls_mld_polyveck *p: pointer to output polynomial vector
 *              - const uint8_t *r: input byte array with
 *                                  bit-packed polynomial vector
 **************************************************/
MLD_INTERNAL_API
void noxtls_mld_polyveck_unpack_t0(noxtls_mld_polyveck *p,
                            const uint8_t r[MLDSA_K * MLDSA_POLYT0_PACKEDBYTES])
__contract__(
  requires(memory_no_alias(r,  MLDSA_K * MLDSA_POLYT0_PACKEDBYTES))
  requires(memory_no_alias(p, sizeof(noxtls_mld_polyveck)))
  assigns(memory_slice(p, sizeof(noxtls_mld_polyveck)))
  ensures(forall(k1, 0, MLDSA_K,
    array_bound(p->vec[k1].coeffs, 0, MLDSA_N, -(1<<(MLDSA_D-1)) + 1, (1<<(MLDSA_D-1)) + 1)))
);

#define noxtls_mld_polymat_get_row MLD_NAMESPACE_KL(polymat_get_row)
/*************************************************
 * Name:        noxtls_mld_polymat_get_row
 *
 * Description: Retrieve a pointer to a specific row of the matrix.
 *              In MLD_CONFIG_REDUCE_RAM mode, generates the row on-demand.
 *
 * Arguments:   - noxtls_mld_polymat *mat: pointer to matrix
 *              - unsigned int row: row index (must be < MLDSA_K)
 *
 * Returns pointer to the row (noxtls_mld_polyvecl)
 **************************************************/
MLD_INTERNAL_API
MLD_MUST_CHECK_RETURN_VALUE
const noxtls_mld_polyvecl *noxtls_mld_polymat_get_row(noxtls_mld_polymat *mat, unsigned int row);

#define noxtls_mld_polyvec_matrix_expand MLD_NAMESPACE_KL(polyvec_matrix_expand)
/*************************************************
 * Name:        noxtls_mld_polyvec_matrix_expand
 *
 * Description: Implementation of ExpandA. Generates matrix A with uniformly
 *              random coefficients a_{i,j} by performing rejection
 *              sampling on the output stream of SHAKE128(rho|j|i)
 *
 * Arguments:   - noxtls_mld_polymat *mat: pointer to output matrix
 *              - const uint8_t rho[]: byte array containing seed rho
 **************************************************/
MLD_INTERNAL_API
void noxtls_mld_polyvec_matrix_expand(noxtls_mld_polymat *mat,
                               const uint8_t rho[MLDSA_SEEDBYTES])
__contract__(
  requires(memory_no_alias(mat, sizeof(noxtls_mld_polymat)))
  requires(memory_no_alias(rho, MLDSA_SEEDBYTES))
  assigns(memory_slice(mat, sizeof(noxtls_mld_polymat)))
  ensures(forall(k1, 0, MLDSA_K, forall(l1, 0, MLDSA_L,
    array_bound(mat->vec[k1].vec[l1].coeffs, 0, MLDSA_N, 0, MLDSA_Q))))
);



#define noxtls_mld_polyvec_matrix_pointwise_montgomery \
  MLD_NAMESPACE_KL(polyvec_matrix_pointwise_montgomery)
/*************************************************
 * Name:        noxtls_mld_polyvec_matrix_pointwise_montgomery
 *
 * Description: Compute matrix-vector multiplication in NTT domain with
 *              pointwise multiplication and multiplication by 2^{-32}.
 *              Input matrix and vector must be in NTT domain representation.
 *
 *              The first input "mat" must be the output of
 *              polyvec_matrix_expand() and so have coefficients in [0, Q-1]
 *              inclusive.
 *
 *              The second input "v" is assumed to be output of an NTT, and
 *              hence must have coefficients bounded by [-9q+1, +9q-1]
 *              inclusive.
 *
 *              Note: In MLD_CONFIG_REDUCE_RAM mode, mat cannot be const
 *              as rows are generated on-demand.
 *
 * Arguments:   - noxtls_mld_polyveck *t: pointer to output vector t
 *              - noxtls_mld_polymat *mat: pointer to input matrix
 *              - const noxtls_mld_polyvecl *v: pointer to input vector v
 **************************************************/
MLD_INTERNAL_API
void noxtls_mld_polyvec_matrix_pointwise_montgomery(noxtls_mld_polyveck *t, noxtls_mld_polymat *mat,
                                             const noxtls_mld_polyvecl *v)
__contract__(
  requires(memory_no_alias(t, sizeof(noxtls_mld_polyveck)))
  requires(memory_no_alias(mat, sizeof(noxtls_mld_polymat)))
  requires(memory_no_alias(v, sizeof(noxtls_mld_polyvecl)))
  requires(forall(k1, 0, MLDSA_K, forall(l1, 0, MLDSA_L,
                                         array_bound(mat->vec[k1].vec[l1].coeffs, 0, MLDSA_N, 0, MLDSA_Q))))
  requires(forall(l1, 0, MLDSA_L,
                  array_abs_bound(v->vec[l1].coeffs, 0, MLDSA_N, MLD_NTT_BOUND)))
  assigns(memory_slice(t, sizeof(noxtls_mld_polyveck)))
  ensures(forall(k0, 0, MLDSA_K,
                 array_abs_bound(t->vec[k0].coeffs, 0, MLDSA_N, MLDSA_Q)))
);

#endif /* !MLD_POLYVEC_H */


