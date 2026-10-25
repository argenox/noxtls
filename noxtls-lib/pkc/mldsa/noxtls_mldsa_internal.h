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
* File:    noxtls_mldsa_internal.h
* Summary: Internal ML-DSA (FIPS 204) building blocks shared by the module
*          translation units. Not part of the public API.
*
*
*****************************************************************************/

#ifndef NOXTLS_MLDSA_INTERNAL_H_
#define NOXTLS_MLDSA_INTERNAL_H_

#include <stdint.h>
#include <stddef.h>

#include "noxtls_config.h"
#include "noxtls_mldsa.h"

#if NOXTLS_FEATURE_ML_DSA

#include "mdigest/sha3/noxtls_sha3.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Polynomial degree n. */
#define NOXTLS_MLDSA_N 256U
/** Modulus q = 2^23 - 2^13 + 1. */
#define NOXTLS_MLDSA_Q 8380417
/** q^-1 mod 2^32 used by the Montgomery reduction. */
#define NOXTLS_MLDSA_QINV 58728449U
/** Number of dropped bits of t (d). */
#define NOXTLS_MLDSA_D 13U
/** Seed length (rho, K) in bytes. */
#define NOXTLS_MLDSA_SEEDBYTES 32U
/** Length of rho' / rho'' / mu / tr in bytes. */
#define NOXTLS_MLDSA_CRHBYTES 64U
/** Length of tr in bytes. */
#define NOXTLS_MLDSA_TRBYTES 64U
/** Length of mu in bytes. */
#define NOXTLS_MLDSA_MUBYTES 64U
/** Packed t1 polynomial size (10 bits per coefficient). */
#define NOXTLS_MLDSA_POLYT1_BYTES 320U
/** Packed t0 polynomial size (13 bits per coefficient). */
#define NOXTLS_MLDSA_POLYT0_BYTES 416U
/** Largest supported k and l. */
#define NOXTLS_MLDSA_K_MAX 8U
#define NOXTLS_MLDSA_L_MAX 7U
/** Size in bytes of one workspace polynomial. */
#define NOXTLS_MLDSA_POLY_BYTES (NOXTLS_MLDSA_N * 4U)
/** Attempt cap for the signing rejection loop (expected attempts are < 5). */
#define NOXTLS_MLDSA_SIGN_MAX_ATTEMPTS 1000U

/** Polynomial in Z_q[X]/(X^256 + 1); 1 KiB. */
typedef struct
{
    int32_t coeff[NOXTLS_MLDSA_N];
} noxtls_mldsa_poly_t;

/** Resolved FIPS 204 parameter set (Table 1 and 2). */
typedef struct
{
    noxtls_mldsa_param_t param;
    uint32_t public_key_len;
    uint32_t secret_key_len;
    uint32_t signature_len;
    uint32_t k;
    uint32_t l;
    uint32_t eta;
    uint32_t tau;
    uint32_t omega;
    int32_t beta;
    int32_t gamma1;
    int32_t gamma2;
    uint32_t ctilde_len;     /**< lambda / 4 bytes */
    uint32_t eta_bits;       /**< 3 (eta = 2) or 4 (eta = 4) */
    uint32_t poly_eta_bytes; /**< 96 or 128 */
    uint32_t gamma1_bits;    /**< 18 (2^17) or 20 (2^19) */
    uint32_t poly_z_bytes;   /**< 576 or 640 */
    uint32_t w1_bits;        /**< 6 ((q-1)/88) or 4 ((q-1)/32) */
    uint32_t poly_w1_bytes;  /**< 192 or 128 */
} noxtls_mldsa_param_spec_t;

/* ---- parameters / hashing (noxtls_mldsa_internal.c) ---- */
noxtls_return_t noxtls_mldsa_internal_get_param_spec(noxtls_mldsa_param_t param,
                                                     noxtls_mldsa_param_spec_t *spec);
noxtls_return_t noxtls_mldsa_shake256(uint8_t *out, uint32_t out_len,
                                      const uint8_t *in1, uint32_t in1_len,
                                      const uint8_t *in2, uint32_t in2_len);
uint32_t noxtls_mldsa_sk_s1_offset(const noxtls_mldsa_param_spec_t *spec, uint32_t j);
uint32_t noxtls_mldsa_sk_s2_offset(const noxtls_mldsa_param_spec_t *spec, uint32_t i);
uint32_t noxtls_mldsa_sk_t0_offset(const noxtls_mldsa_param_spec_t *spec, uint32_t i);

/* ---- modular arithmetic and NTT (noxtls_mldsa_ntt.c) ---- */
int32_t noxtls_mldsa_montgomery_reduce(int64_t a);
int32_t noxtls_mldsa_reduce32(int32_t a);
int32_t noxtls_mldsa_caddq(int32_t a);
void noxtls_mldsa_poly_ntt(noxtls_mldsa_poly_t *p);
void noxtls_mldsa_poly_invntt_tomont(noxtls_mldsa_poly_t *p);
void noxtls_mldsa_poly_pointwise_montgomery(noxtls_mldsa_poly_t *r,
                                            const noxtls_mldsa_poly_t *a,
                                            const noxtls_mldsa_poly_t *b);
void noxtls_mldsa_poly_pointwise_acc_montgomery(noxtls_mldsa_poly_t *r,
                                                const noxtls_mldsa_poly_t *a,
                                                const noxtls_mldsa_poly_t *b);

/* ---- polynomial arithmetic (noxtls_mldsa_polyarith.c) ---- */
void noxtls_mldsa_poly_zero(noxtls_mldsa_poly_t *p);
void noxtls_mldsa_poly_add(noxtls_mldsa_poly_t *r, const noxtls_mldsa_poly_t *a);
void noxtls_mldsa_poly_sub(noxtls_mldsa_poly_t *r, const noxtls_mldsa_poly_t *a);
void noxtls_mldsa_poly_reduce(noxtls_mldsa_poly_t *p);
void noxtls_mldsa_poly_caddq(noxtls_mldsa_poly_t *p);
void noxtls_mldsa_poly_shiftl(noxtls_mldsa_poly_t *p);
uint32_t noxtls_mldsa_poly_chknorm(const noxtls_mldsa_poly_t *p, int32_t bound);

/* ---- sampling (noxtls_mldsa_sampling.c, noxtls_mldsa_challenge.c) ---- */
noxtls_return_t noxtls_mldsa_poly_uniform(noxtls_mldsa_poly_t *a,
                                          const uint8_t rho[NOXTLS_MLDSA_SEEDBYTES],
                                          uint32_t row, uint32_t col);
noxtls_return_t noxtls_mldsa_poly_uniform_eta(const noxtls_mldsa_param_spec_t *spec,
                                              noxtls_mldsa_poly_t *a,
                                              const uint8_t rhoprime[NOXTLS_MLDSA_CRHBYTES],
                                              uint32_t nonce);
noxtls_return_t noxtls_mldsa_poly_uniform_gamma1(const noxtls_mldsa_param_spec_t *spec,
                                                 noxtls_mldsa_poly_t *a,
                                                 const uint8_t rhoprime[NOXTLS_MLDSA_CRHBYTES],
                                                 uint32_t nonce);
noxtls_return_t noxtls_mldsa_poly_challenge(const noxtls_mldsa_param_spec_t *spec,
                                            noxtls_mldsa_poly_t *c,
                                            const uint8_t *ctilde);

/* ---- rounding and hints (noxtls_mldsa_hint.c) ---- */
int32_t noxtls_mldsa_power2round(int32_t a, int32_t *a0);
int32_t noxtls_mldsa_decompose(int32_t a, int32_t gamma2, int32_t *a0);
uint32_t noxtls_mldsa_make_hint(int32_t a0, int32_t a1, int32_t gamma2);
int32_t noxtls_mldsa_use_hint(int32_t a, uint32_t hint, int32_t gamma2);

/* ---- bit packing (noxtls_mldsa_packing.c) ---- */
void noxtls_mldsa_bitpack(uint8_t *out, const noxtls_mldsa_poly_t *p,
                          uint32_t bits, int32_t base, uint32_t subtract);
void noxtls_mldsa_bitunpack(noxtls_mldsa_poly_t *p, const uint8_t *in,
                            uint32_t bits, int32_t base, uint32_t subtract);
void noxtls_mldsa_polyeta_unpack(const noxtls_mldsa_param_spec_t *spec,
                                 noxtls_mldsa_poly_t *p, const uint8_t *in);
void noxtls_mldsa_polyeta_pack(const noxtls_mldsa_param_spec_t *spec,
                               uint8_t *out, const noxtls_mldsa_poly_t *p);

/* ---- signature encoding (noxtls_mldsa_sigcodec.c) ---- */
void noxtls_mldsa_polyz_pack(const noxtls_mldsa_param_spec_t *spec,
                             uint8_t *out, const noxtls_mldsa_poly_t *p);
void noxtls_mldsa_polyz_unpack(const noxtls_mldsa_param_spec_t *spec,
                               noxtls_mldsa_poly_t *p, const uint8_t *in);
void noxtls_mldsa_polyw1_pack(const noxtls_mldsa_param_spec_t *spec,
                              uint8_t *out, const noxtls_mldsa_poly_t *w,
                              const uint8_t *hints, uint32_t hint_start, uint32_t hint_end);
noxtls_return_t noxtls_mldsa_hint_validate(const noxtls_mldsa_param_spec_t *spec,
                                           const uint8_t *h);

/* ---- matrix helpers (noxtls_mldsa_polyvec.c) ---- */
noxtls_return_t noxtls_mldsa_matrix_acc(noxtls_mldsa_poly_t *acc,
                                        noxtls_mldsa_poly_t *a_tmp,
                                        const uint8_t rho[NOXTLS_MLDSA_SEEDBYTES],
                                        uint32_t row, uint32_t col,
                                        const noxtls_mldsa_poly_t *vhat);

/* ---- algorithms (noxtls_mldsa_backend.c) ---- */
uint32_t noxtls_mldsa_backend_keygen_ws_len(const noxtls_mldsa_param_spec_t *spec);
uint32_t noxtls_mldsa_backend_sign_ws_len(const noxtls_mldsa_param_spec_t *spec);
uint32_t noxtls_mldsa_backend_verify_ws_len(const noxtls_mldsa_param_spec_t *spec);
noxtls_return_t noxtls_mldsa_backend_keygen(const noxtls_mldsa_param_spec_t *spec,
                                            const uint8_t xi[NOXTLS_MLDSA_SEEDBYTES],
                                            uint8_t *public_key,
                                            uint8_t *secret_key,
                                            noxtls_mldsa_poly_t *ws);
noxtls_return_t noxtls_mldsa_backend_sign(const noxtls_mldsa_param_spec_t *spec,
                                          const uint8_t *secret_key,
                                          const uint8_t mu[NOXTLS_MLDSA_MUBYTES],
                                          const uint8_t rnd[NOXTLS_MLDSA_RND_LEN],
                                          uint8_t *signature,
                                          noxtls_mldsa_poly_t *ws);
noxtls_return_t noxtls_mldsa_backend_verify(const noxtls_mldsa_param_spec_t *spec,
                                            const uint8_t *public_key,
                                            const uint8_t mu[NOXTLS_MLDSA_MUBYTES],
                                            const uint8_t *signature,
                                            noxtls_mldsa_poly_t *ws);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_FEATURE_ML_DSA */

#endif /* NOXTLS_MLDSA_INTERNAL_H_ */
