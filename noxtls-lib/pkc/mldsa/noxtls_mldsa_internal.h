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
* File:    noxtls_mldsa_internal.c
* Summary: ML-DSA parameter definitions and basic arithmetic definitions
*
*
*****************************************************************************/

#ifndef _NOXTLS_MLDSA_INTERNAL_H_
#define _NOXTLS_MLDSA_INTERNAL_H_

#include <stdint.h>

#include "noxtls_mldsa.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NOXTLS_MLDSA_N 256
#define NOXTLS_MLDSA_Q 8380417
#define NOXTLS_MLDSA_INTERNAL_SEED_BYTES 32U
#define NOXTLS_MLDSA_K_MAX 8U
#define NOXTLS_MLDSA_L_MAX 7U

typedef struct
{
    int32_t coeff[NOXTLS_MLDSA_N];
} noxtls_mldsa_poly_t;

typedef struct
{
    noxtls_mldsa_poly_t v[NOXTLS_MLDSA_L_MAX];
} noxtls_mldsa_polyvecl_t;

typedef struct
{
    noxtls_mldsa_poly_t v[NOXTLS_MLDSA_K_MAX];
} noxtls_mldsa_polyveck_t;

typedef struct
{
    uint8_t c_seed[64];
    noxtls_mldsa_poly_t c;
    noxtls_mldsa_polyvecl_t z;
    noxtls_mldsa_polyveck_t h;
} noxtls_mldsa_sig_parts_t;

typedef struct
{
    noxtls_mldsa_param_t param;
    uint32_t public_key_len;
    uint32_t secret_key_len;
    uint32_t signature_len;
    uint8_t k;
    uint8_t l;
    uint8_t eta;
    uint8_t omega;
    uint16_t tau;
    uint16_t beta;
    int32_t gamma1;
    int32_t gamma2;
} noxtls_mldsa_param_spec_t;

noxtls_return_t noxtls_mldsa_internal_get_param_spec(noxtls_mldsa_param_t param,
                                                     noxtls_mldsa_param_spec_t *spec);

int32_t noxtls_mldsa_coeff_normalize(int32_t a);
void noxtls_mldsa_poly_zero(noxtls_mldsa_poly_t *p);
void noxtls_mldsa_poly_add(noxtls_mldsa_poly_t *r,
                           const noxtls_mldsa_poly_t *a,
                           const noxtls_mldsa_poly_t *b);
void noxtls_mldsa_poly_sub(noxtls_mldsa_poly_t *r,
                           const noxtls_mldsa_poly_t *a,
                           const noxtls_mldsa_poly_t *b);
void noxtls_mldsa_poly_reduce(noxtls_mldsa_poly_t *p);
void noxtls_mldsa_poly_ntt(noxtls_mldsa_poly_t *p);
void noxtls_mldsa_poly_invntt_to_mont(noxtls_mldsa_poly_t *p);
void noxtls_mldsa_poly_pointwise_montgomery(noxtls_mldsa_poly_t *r,
                                            const noxtls_mldsa_poly_t *a,
                                            const noxtls_mldsa_poly_t *b);
noxtls_return_t noxtls_mldsa_poly_mul_challenge(const noxtls_mldsa_poly_t *a,
                                                const noxtls_mldsa_poly_t *c,
                                                noxtls_mldsa_poly_t *r);
noxtls_return_t noxtls_mldsa_make_z(noxtls_mldsa_param_t param,
                                    const noxtls_mldsa_polyvecl_t *y,
                                    const noxtls_mldsa_poly_t *c,
                                    const noxtls_mldsa_polyvecl_t *s1,
                                    noxtls_mldsa_polyvecl_t *z);

noxtls_return_t noxtls_mldsa_expand_xof(const uint8_t *seed,
                                        uint32_t seed_len,
                                        uint8_t domain_tag,
                                        uint16_t nonce,
                                        uint8_t *out,
                                        uint32_t out_len);
noxtls_return_t noxtls_mldsa_derive_seeds(const uint8_t master_seed[NOXTLS_MLDSA_INTERNAL_SEED_BYTES],
                                          uint8_t rho[NOXTLS_MLDSA_INTERNAL_SEED_BYTES],
                                          uint8_t k[NOXTLS_MLDSA_INTERNAL_SEED_BYTES],
                                          uint8_t tr[NOXTLS_MLDSA_INTERNAL_SEED_BYTES]);
noxtls_return_t noxtls_mldsa_sample_uniform_q(noxtls_mldsa_param_t param,
                                              const uint8_t seed[NOXTLS_MLDSA_INTERNAL_SEED_BYTES],
                                              uint16_t nonce,
                                              noxtls_mldsa_poly_t *poly);
noxtls_return_t noxtls_mldsa_sample_small_eta(noxtls_mldsa_param_t param,
                                              const uint8_t seed[NOXTLS_MLDSA_INTERNAL_SEED_BYTES],
                                              uint16_t nonce,
                                              noxtls_mldsa_poly_t *poly);
noxtls_return_t noxtls_mldsa_sample_polyvecl_eta(noxtls_mldsa_param_t param,
                                                  const uint8_t seed[NOXTLS_MLDSA_INTERNAL_SEED_BYTES],
                                                  uint16_t nonce_base,
                                                  noxtls_mldsa_polyvecl_t *out);
noxtls_return_t noxtls_mldsa_expand_matrix_row(noxtls_mldsa_param_t param,
                                                const uint8_t rho[NOXTLS_MLDSA_INTERNAL_SEED_BYTES],
                                                uint8_t row_index,
                                                noxtls_mldsa_polyvecl_t *row_out);
noxtls_return_t noxtls_mldsa_matrix_vector_mul(noxtls_mldsa_param_t param,
                                                const uint8_t rho[NOXTLS_MLDSA_INTERNAL_SEED_BYTES],
                                                const noxtls_mldsa_polyvecl_t *s1,
                                                noxtls_mldsa_polyveck_t *t_out);
noxtls_return_t noxtls_mldsa_make_challenge(noxtls_mldsa_param_t param,
                                            const uint8_t *mu,
                                            uint32_t mu_len,
                                            noxtls_mldsa_poly_t *c);
noxtls_return_t noxtls_mldsa_decompose_poly(const noxtls_mldsa_poly_t *w,
                                            int32_t gamma2,
                                            noxtls_mldsa_poly_t *w1,
                                            noxtls_mldsa_poly_t *w0);
noxtls_return_t noxtls_mldsa_make_hint_poly(const noxtls_mldsa_poly_t *w0,
                                            int32_t gamma2,
                                            noxtls_mldsa_poly_t *h,
                                            uint32_t *weight);
noxtls_return_t noxtls_mldsa_use_hint_poly(const noxtls_mldsa_poly_t *w,
                                           const noxtls_mldsa_poly_t *h,
                                           int32_t gamma2,
                                           noxtls_mldsa_poly_t *w1_adj);
noxtls_return_t noxtls_mldsa_pack_signature_internal(noxtls_mldsa_param_t param,
                                                     const noxtls_mldsa_sig_parts_t *parts,
                                                     uint8_t *sig,
                                                     uint32_t *sig_len);
noxtls_return_t noxtls_mldsa_unpack_signature_internal(noxtls_mldsa_param_t param,
                                                       const uint8_t *sig,
                                                       uint32_t sig_len,
                                                       noxtls_mldsa_sig_parts_t *parts);

noxtls_return_t noxtls_mldsa_pack_seeds(uint8_t *out,
                                        uint32_t out_len,
                                        const uint8_t rho[NOXTLS_MLDSA_INTERNAL_SEED_BYTES],
                                        const uint8_t k[NOXTLS_MLDSA_INTERNAL_SEED_BYTES],
                                        const uint8_t tr[NOXTLS_MLDSA_INTERNAL_SEED_BYTES]);
noxtls_return_t noxtls_mldsa_unpack_seeds(const uint8_t *in,
                                          uint32_t in_len,
                                          uint8_t rho[NOXTLS_MLDSA_INTERNAL_SEED_BYTES],
                                          uint8_t k[NOXTLS_MLDSA_INTERNAL_SEED_BYTES],
                                          uint8_t tr[NOXTLS_MLDSA_INTERNAL_SEED_BYTES]);

noxtls_return_t noxtls_mldsa_backend_keygen(noxtls_mldsa_param_t param,
                                            uint8_t *public_key,
                                            uint8_t *secret_key);
noxtls_return_t noxtls_mldsa_backend_sign(noxtls_mldsa_param_t param,
                                          const uint8_t *secret_key,
                                          const uint8_t *noxtls_message,
                                          uint32_t message_len,
                                          uint8_t *signature,
                                          uint32_t *signature_len);
noxtls_return_t noxtls_mldsa_backend_verify(noxtls_mldsa_param_t param,
                                            const uint8_t *public_key,
                                            const uint8_t *noxtls_message,
                                            uint32_t message_len,
                                            const uint8_t *signature,
                                            uint32_t signature_len);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_MLDSA_INTERNAL_H_ */
