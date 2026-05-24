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
* File:    noxtls_falcon_internal.h
* Summary: Falcon/FN-DSA internal helpers derived from the public specification.
*
*****************************************************************************/

#ifndef _NOXTLS_FALCON_INTERNAL_H_
#define _NOXTLS_FALCON_INTERNAL_H_

#include <stdint.h>
#include "mdigest/sha3/noxtls_sha3.h"
#include "noxtls_falcon.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Falcon modulus `q`. */
#define NOXTLS_FALCON_Q                12289u
/** Falcon circle constant used by the complex transform helpers. */
#define NOXTLS_FALCON_PI               3.14159265358979323846
/** Maximum supported Falcon ring degree. */
#define NOXTLS_FALCON_MAX_N            1024U
/** Maximum flattened complex-entry count for a normalized Falcon LDL tree. */
#define NOXTLS_FALCON_MAX_TREE_LEN     11264u
/** Falcon nonce/salt length in bytes for compressed signatures. */
#define NOXTLS_FALCON_SALT_LEN         40U
/** Serialized public-key header high nibble. */
#define NOXTLS_FALCON_PUBLIC_KEY_HDR   0x00u
/** Serialized secret-key header high nibble. */
#define NOXTLS_FALCON_PRIVATE_KEY_HDR  0x50u
/** Serialized compressed-signature header high nibble. */
#define NOXTLS_FALCON_SIG_COMP_HDR     0x30u
/** Serialized constant-time-signature header high nibble. */
#define NOXTLS_FALCON_SIG_CT_HDR       0x50u

/**
 * @brief Resolved Falcon parameter-set constants.
 */
typedef struct
{
    noxtls_falcon_param_t param;
    uint8_t logn;
    uint16_t n;
    uint8_t fg_bits;
    uint8_t F_bits;
    uint32_t public_key_len;
    uint32_t secret_key_len;
    uint32_t signature_len;
    uint32_t signature_comp_max_len;
} noxtls_falcon_param_spec_t;

/**
 * @brief Bit-level writer used by Falcon serialization helpers.
 */
typedef struct
{
    uint8_t *buf;
    uint32_t bit_len;
    uint32_t bit_pos;
} falcon_bit_writer_t;

/**
 * @brief Bit-level reader used by Falcon serialization helpers.
 */
typedef struct
{
    const uint8_t *buf;
    uint32_t bit_len;
    uint32_t bit_pos;
} falcon_bit_reader_t;

/**
 * @brief Complex value used by Falcon's numerical transform helpers.
 */
typedef struct
{
    double re;
    double im;
} noxtls_falcon_complex_t;

/**
 * @brief Expanded Falcon private-key state derived from `f`, `g`, `F`, and `G`.
 *
 * The `B` rows follow the conventional Falcon lattice basis layout:
 * `B = [[g, -f], [G, -F]]`.
 */
typedef struct
{
    noxtls_falcon_param_spec_t spec;
    int16_t f[NOXTLS_FALCON_MAX_N];
    int16_t g[NOXTLS_FALCON_MAX_N];
    int16_t F[NOXTLS_FALCON_MAX_N];
    int16_t G[NOXTLS_FALCON_MAX_N];
    int16_t b00[NOXTLS_FALCON_MAX_N];
    int16_t b01[NOXTLS_FALCON_MAX_N];
    int16_t b10[NOXTLS_FALCON_MAX_N];
    int16_t b11[NOXTLS_FALCON_MAX_N];
    uint16_t h[NOXTLS_FALCON_MAX_N];
} noxtls_falcon_expanded_key_t;

/**
 * @brief Deterministic SHAKE-backed random source for Falcon sampling.
 */
typedef struct
{
    noxtls_sha3_ctx_t shake;
    double sigma_min;
} noxtls_falcon_sampler_ctx_t;

/**
 * @brief Resolve the fixed constants for a supported Falcon parameter set.
 *
 * @param[in] param Falcon parameter selector.
 * @param[out] spec Output specification record.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` if `spec` is `NULL`,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `param` is unsupported.
 */
noxtls_return_t noxtls_falcon_internal_get_param_spec(noxtls_falcon_param_t param,
                                                      noxtls_falcon_param_spec_t *spec);

/**
 * @brief Reduce a signed 32-bit integer into the canonical Falcon residue range `[0, q)`.
 *
 * @param[in] value Signed value to reduce.
 * @return Reduced residue modulo `q`.
 */
uint16_t noxtls_falcon_mod_q_reduce_i32(int32_t value);
/**
 * @brief Add two Falcon residues modulo `q`.
 *
 * @param[in] a First addend in `[0, q)`.
 * @param[in] b Second addend in `[0, q)`.
 * @return `(a + b) mod q`.
 */
uint16_t noxtls_falcon_mod_q_add(uint16_t a, uint16_t b);
/**
 * @brief Subtract two Falcon residues modulo `q`.
 *
 * @param[in] a Minuend in `[0, q)`.
 * @param[in] b Subtrahend in `[0, q)`.
 * @return `(a - b) mod q`.
 */
uint16_t noxtls_falcon_mod_q_sub(uint16_t a, uint16_t b);
/**
 * @brief Multiply two Falcon residues modulo `q`.
 *
 * @param[in] a First factor in `[0, q)`.
 * @param[in] b Second factor in `[0, q)`.
 * @return `(a * b) mod q`.
 */
uint16_t noxtls_falcon_mod_q_mul(uint16_t a, uint16_t b);
/**
 * @brief Map a Falcon residue into the centered signed representative interval.
 *
 * @param[in] value Residue in `[0, q)`.
 * @return Centered representative in `[-q/2, q/2]`.
 */
int16_t noxtls_falcon_mod_q_center(uint16_t value);

/**
 * @brief Hash arbitrary input bytes into Falcon challenge coefficients with SHAKE256.
 *
 * @param[in] input Message to hash. May be `NULL` only when `input_len` is `0`.
 * @param[in] input_len Length of `input` in bytes.
 * @param[out] coeffs Output coefficient array.
 * @param[in] coeff_count Number of coefficients to generate.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or a SHAKE error code.
 */
noxtls_return_t noxtls_falcon_hash_to_point(const uint8_t *input,
                                            uint32_t input_len,
                                            uint16_t *coeffs,
                                            uint32_t coeff_count);

/**
 * @brief Recompute the missing Falcon secret polynomial `G` from `f`, `g`, and `F`.
 *
 * This reconstructs the centered small-coefficient solution `G` such that
 * `fG - gF = q mod (x^n + 1)`.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[in] F Secret polynomial `F`.
 * @param[out] G Output reconstructed polynomial `G`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` if `param` is unsupported, or `NOXTLS_RETURN_FAILED`
 *         if no valid small `G` can be reconstructed.
 */
noxtls_return_t noxtls_falcon_complete_private_key(noxtls_falcon_param_t param,
                                                   const int16_t *f,
                                                   const int16_t *g,
                                                   const int16_t *F,
                                                   int16_t *G);

/**
 * @brief Expand a complete Falcon private key into signing-basis form.
 *
 * This validates `(f, g, F)` by recomputing `G`, derives the public polynomial `h`,
 * and fills the conventional basis rows `[[g, -f], [G, -F]]`.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[in] F Secret polynomial `F`.
 * @param[out] expanded Output expanded-key record.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` if `param` is unsupported, or `NOXTLS_RETURN_FAILED`
 *         if the secret key is mathematically invalid.
 */
noxtls_return_t noxtls_falcon_expand_complete_private_key(noxtls_falcon_param_t param,
                                                          const int16_t *f,
                                                          const int16_t *g,
                                                          const int16_t *F,
                                                          noxtls_falcon_expanded_key_t *expanded);

/**
 * @brief Expand a serialized Falcon secret key into signing-basis form.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] secret_key Serialized Falcon secret key.
 * @param[in] secret_key_len Length of `secret_key` in bytes.
 * @param[out] expanded Output expanded-key record.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` or `NOXTLS_RETURN_INVALID_BLOCK_SIZE` on a size/parameter
 *         mismatch, or `NOXTLS_RETURN_BAD_DATA` if the serialized secret key is malformed or invalid.
 */
noxtls_return_t noxtls_falcon_expand_private_key(noxtls_falcon_param_t param,
                                                 const uint8_t *secret_key,
                                                 uint32_t secret_key_len,
                                                 noxtls_falcon_expanded_key_t *expanded);

/**
 * @brief Map a signed Falcon polynomial into the negacyclic complex FFT domain.
 *
 * @param[in] poly Input polynomial coefficients.
 * @param[in] n Polynomial degree. Must be a supported power of two.
 * @param[out] fft Output complex FFT samples.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
noxtls_return_t noxtls_falcon_poly_forward_fft(const int16_t *poly,
                                               uint16_t n,
                                               noxtls_falcon_complex_t *fft);

/**
 * @brief Map a negacyclic complex FFT vector back to signed Falcon coefficients.
 *
 * @param[in] fft Input complex FFT samples.
 * @param[in] n Polynomial degree. Must be a supported power of two.
 * @param[out] poly Output rounded signed coefficients.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported, or `NOXTLS_RETURN_FAILED`
 *         if a reconstructed coefficient falls outside the signed 16-bit range.
 */
noxtls_return_t noxtls_falcon_poly_inverse_fft(const noxtls_falcon_complex_t *fft,
                                               uint16_t n,
                                               int16_t *poly);

/**
 * @brief Multiply two Falcon FFT vectors pointwise.
 *
 * @param[in] a First FFT vector.
 * @param[in] b Second FFT vector.
 * @param[in] n Number of coefficients.
 * @param[out] out Output FFT vector.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
noxtls_return_t noxtls_falcon_fft_pointwise_mul(const noxtls_falcon_complex_t *a,
                                                const noxtls_falcon_complex_t *b,
                                                uint16_t n,
                                                noxtls_falcon_complex_t *out);

/**
 * @brief Transform the expanded Falcon lattice basis into the FFT domain.
 *
 * The output rows correspond to the basis `[[g, -f], [G, -F]]`.
 *
 * @param[in] expanded Expanded Falcon private key.
 * @param[out] b00_fft FFT of `g`.
 * @param[out] b01_fft FFT of `-f`.
 * @param[out] b10_fft FFT of `G`.
 * @param[out] b11_fft FFT of `-F`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if the embedded degree is unsupported.
 */
noxtls_return_t noxtls_falcon_expand_basis_fft(const noxtls_falcon_expanded_key_t *expanded,
                                               noxtls_falcon_complex_t *b00_fft,
                                               noxtls_falcon_complex_t *b01_fft,
                                               noxtls_falcon_complex_t *b10_fft,
                                               noxtls_falcon_complex_t *b11_fft);

/**
 * @brief Compute the Falcon basis Gram matrix in the FFT domain.
 *
 * The returned Hermitian matrix is `G = B * adj(B)` for the conventional basis
 * `B = [[g, -f], [G, -F]]`.
 *
 * @param[in] b00_fft FFT of `g`.
 * @param[in] b01_fft FFT of `-f`.
 * @param[in] b10_fft FFT of `G`.
 * @param[in] b11_fft FFT of `-F`.
 * @param[in] n Number of FFT samples.
 * @param[out] g00_fft FFT samples of the `(0,0)` Gram entry.
 * @param[out] g01_fft FFT samples of the `(0,1)` Gram entry.
 * @param[out] g10_fft FFT samples of the `(1,0)` Gram entry.
 * @param[out] g11_fft FFT samples of the `(1,1)` Gram entry.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
noxtls_return_t noxtls_falcon_compute_gram_fft(const noxtls_falcon_complex_t *b00_fft,
                                               const noxtls_falcon_complex_t *b01_fft,
                                               const noxtls_falcon_complex_t *b10_fft,
                                               const noxtls_falcon_complex_t *b11_fft,
                                               uint16_t n,
                                               noxtls_falcon_complex_t *g00_fft,
                                               noxtls_falcon_complex_t *g01_fft,
                                               noxtls_falcon_complex_t *g10_fft,
                                               noxtls_falcon_complex_t *g11_fft);

/**
 * @brief Compute a pointwise Falcon LDL decomposition of a Hermitian Gram matrix.
 *
 * For each FFT sample, this decomposes the 2x2 Hermitian matrix
 * `[[g00, g01], [g10, g11]]` into `L * D * adj(L)` with
 * `L = [[1, 0], [l10, 1]]` and diagonal `D = diag(d00, d11)`.
 *
 * @param[in] g00_fft FFT samples of the `(0,0)` Gram entry.
 * @param[in] g01_fft FFT samples of the `(0,1)` Gram entry.
 * @param[in] g10_fft FFT samples of the `(1,0)` Gram entry.
 * @param[in] g11_fft FFT samples of the `(1,1)` Gram entry.
 * @param[in] n Number of FFT samples.
 * @param[out] d00_fft FFT samples of the first diagonal entry.
 * @param[out] l10_fft FFT samples of the lower-triangular entry.
 * @param[out] d11_fft FFT samples of the second diagonal entry.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported, or `NOXTLS_RETURN_FAILED`
 *         if the Gram matrix is not numerically positive definite.
 */
noxtls_return_t noxtls_falcon_ldl_decompose_fft(const noxtls_falcon_complex_t *g00_fft,
                                                const noxtls_falcon_complex_t *g01_fft,
                                                const noxtls_falcon_complex_t *g10_fft,
                                                const noxtls_falcon_complex_t *g11_fft,
                                                uint16_t n,
                                                noxtls_falcon_complex_t *d00_fft,
                                                noxtls_falcon_complex_t *l10_fft,
                                                noxtls_falcon_complex_t *d11_fft);

/**
 * @brief Split a real Falcon FFT polynomial into even and odd half-size FFT polynomials.
 *
 * This applies the algebraic decomposition
 * `f(x) = f0(x^2) + x f1(x^2)` by mapping the input FFT back to real coefficients,
 * separating even and odd coefficients, and transforming the halves back to the FFT domain.
 *
 * @param[in] fft Input FFT polynomial of degree `n`.
 * @param[in] n Input polynomial degree. Must be an even supported power of two.
 * @param[out] fft0 Output FFT polynomial for the even part.
 * @param[out] fft1 Output FFT polynomial for the odd part.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
noxtls_return_t noxtls_falcon_split_fft_real(const noxtls_falcon_complex_t *fft,
                                             uint16_t n,
                                             noxtls_falcon_complex_t *fft0,
                                             noxtls_falcon_complex_t *fft1);

/**
 * @brief Merge even and odd half-size real Falcon FFT polynomials into a full-size FFT polynomial.
 *
 * This inverts `noxtls_falcon_split_fft_real()` by reconstructing
 * `f(x) = f0(x^2) + x f1(x^2)` in the coefficient domain and transforming it back to the FFT domain.
 *
 * @param[in] fft0 Input FFT polynomial for the even part.
 * @param[in] fft1 Input FFT polynomial for the odd part.
 * @param[in] n Output polynomial degree. Must be an even supported power of two.
 * @param[out] fft Output merged FFT polynomial of degree `n`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
noxtls_return_t noxtls_falcon_merge_fft_real(const noxtls_falcon_complex_t *fft0,
                                             const noxtls_falcon_complex_t *fft1,
                                             uint16_t n,
                                             noxtls_falcon_complex_t *fft);

/**
 * @brief Return the number of complex FFT entries needed to store a recursive Falcon LDL tree.
 *
 * The storage layout used by Falcon stores `n` samples at each internal node and one sample at each leaf,
 * for a total of `n * (log2(n) + 1)` complex values when `n` is a supported power of two.
 *
 * @param[in] n Polynomial degree.
 * @return Required complex-entry count, or `0` if `n` is unsupported.
 */
uint32_t noxtls_falcon_ldl_tree_complex_len(uint16_t n);

/**
 * @brief Build an unnormalized Falcon LDL tree from a Gram matrix in the FFT domain.
 *
 * The tree layout matches the Falcon reference recursion: each internal node stores the
 * `L10` polynomial for the current matrix, followed by the left subtree derived from `D00`
 * and the right subtree derived from `D11`.
 *
 * @param[in] g00_fft FFT samples of the `(0,0)` Gram entry.
 * @param[in] g01_fft FFT samples of the `(0,1)` Gram entry.
 * @param[in] g10_fft FFT samples of the `(1,0)` Gram entry.
 * @param[in] g11_fft FFT samples of the `(1,1)` Gram entry.
 * @param[in] n Polynomial degree.
 * @param[out] tree Output flattened LDL tree.
 * @param[in] tree_len Number of complex entries available in `tree`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` on an unsupported size or undersized output buffer,
 *         or `NOXTLS_RETURN_FAILED` if the Gram matrix is not numerically valid.
 */
noxtls_return_t noxtls_falcon_build_ldl_tree_fft(const noxtls_falcon_complex_t *g00_fft,
                                                 const noxtls_falcon_complex_t *g01_fft,
                                                 const noxtls_falcon_complex_t *g10_fft,
                                                 const noxtls_falcon_complex_t *g11_fft,
                                                 uint16_t n,
                                                 noxtls_falcon_complex_t *tree,
                                                 uint32_t tree_len);

/**
 * @brief Build an unnormalized Falcon LDL tree directly from an expanded private key.
 *
 * This transforms the expanded basis to the FFT domain, computes its Gram matrix,
 * and then builds the recursive LDL tree needed by the Falcon sampler.
 *
 * @param[in] expanded Expanded Falcon private key.
 * @param[out] tree Output flattened LDL tree.
 * @param[in] tree_len Number of complex entries available in `tree`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` on an unsupported size or undersized output buffer,
 *         or `NOXTLS_RETURN_FAILED` if the expanded basis is numerically invalid.
 */
noxtls_return_t noxtls_falcon_build_expanded_key_ldl_tree(const noxtls_falcon_expanded_key_t *expanded,
                                                          noxtls_falcon_complex_t *tree,
                                                          uint32_t tree_len);

/**
 * @brief Normalize a Falcon LDL tree in place for sampler use.
 *
 * Only the leaves are modified. Each leaf value `x` is replaced with the inverse
 * standard deviation term `sqrt(x) / sigma`, using the Falcon parameter-set `sigma`
 * attached to the original top-level degree.
 *
 * @param[in,out] tree Flattened LDL tree to normalize.
 * @param[in] n Original top-level polynomial degree for the tree.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported, or `NOXTLS_RETURN_FAILED`
 *         if a leaf is non-real or non-positive.
 */
noxtls_return_t noxtls_falcon_normalize_ldl_tree(noxtls_falcon_complex_t *tree,
                                                 uint16_t n);

/**
 * @brief Build a normalized Falcon LDL tree directly from an expanded private key.
 *
 * This is the sampler-ready form derived by building the unnormalized tree from the expanded
 * basis Gram matrix and then normalizing its leaves with the Falcon parameter-set sigma.
 *
 * @param[in] expanded Expanded Falcon private key.
 * @param[out] tree Output flattened normalized LDL tree.
 * @param[in] tree_len Number of complex entries available in `tree`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` on an unsupported size or undersized output buffer,
 *         or `NOXTLS_RETURN_FAILED` if the expanded basis is numerically invalid.
 */
noxtls_return_t noxtls_falcon_build_normalized_expanded_key_ldl_tree(const noxtls_falcon_expanded_key_t *expanded,
                                                                     noxtls_falcon_complex_t *tree,
                                                                     uint32_t tree_len);

/**
 * @brief Initialize a Falcon sampler context from a seed and parameter set.
 *
 * The context uses SHAKE256 as a deterministic byte stream and records the
 * Falcon `sigma_min` value for the selected degree.
 *
 * @param[out] ctx Sampler context to initialize.
 * @param[in] param Falcon parameter selector.
 * @param[in] seed Seed bytes for the deterministic sampler stream.
 * @param[in] seed_len Length of `seed` in bytes. May be `0`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null context
 *         or invalid seed pointer, or `NOXTLS_RETURN_INVALID_PARAM` if `param` is unsupported.
 */
noxtls_return_t noxtls_falcon_sampler_init(noxtls_falcon_sampler_ctx_t *ctx,
                                           noxtls_falcon_param_t param,
                                           const uint8_t *seed,
                                           uint32_t seed_len);

/**
 * @brief Sample Falcon's half-Gaussian base distribution from an explicit 72-bit value.
 *
 * @param[in] v0 Low 24 bits of the sampled 72-bit value.
 * @param[in] v1 Middle 24 bits of the sampled 72-bit value.
 * @param[in] v2 High 24 bits of the sampled 72-bit value.
 * @return Non-negative sampled integer.
 */
int noxtls_falcon_gaussian0_sample_from_u72(uint32_t v0,
                                            uint32_t v1,
                                            uint32_t v2);

/**
 * @brief Sample Falcon's half-Gaussian base distribution from the sampler context.
 *
 * @param[in,out] ctx Sampler context.
 * @param[out] sample Output sampled integer.
 * @return `NOXTLS_RETURN_SUCCESS` on success or `NOXTLS_RETURN_NULL` on a null pointer.
 */
noxtls_return_t noxtls_falcon_sampler_gaussian0(noxtls_falcon_sampler_ctx_t *ctx,
                                                int *sample);

/**
 * @brief Sample a Bernoulli bit with probability `exp(-x)`.
 *
 * The acceptance scale `ccs` should be `sigma_min / sigma` for the surrounding
 * Falcon rejection sampler.
 *
 * @param[in,out] ctx Sampler context.
 * @param[in] x Non-negative exponent argument.
 * @param[in] ccs Falcon acceptance scale.
 * @param[out] bit Output sampled bit, `0` or `1`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `x` or `ccs` is invalid.
 */
noxtls_return_t noxtls_falcon_sampler_ber_exp(noxtls_falcon_sampler_ctx_t *ctx,
                                              double x,
                                              double ccs,
                                              int *bit);

/**
 * @brief Sample a discrete Gaussian integer centered on `mu` with inverse sigma `isigma`.
 *
 * This is Falcon's one-dimensional sampler used inside the recursive FFT sampler.
 *
 * @param[in,out] ctx Sampler context.
 * @param[in] mu Gaussian center.
 * @param[in] isigma Inverse standard deviation `1/sigma`.
 * @param[out] sample Output sampled integer.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `isigma` is outside Falcon's supported range.
 */
noxtls_return_t noxtls_falcon_sampler_z(noxtls_falcon_sampler_ctx_t *ctx,
                                        double mu,
                                        double isigma,
                                        int32_t *sample);

/**
 * @brief Sample one small Falcon secret polynomial for key generation.
 *
 * Coefficients are drawn from a symmetric discrete distribution derived from
 * Falcon's half-Gaussian sampler and rejected until they fit the serialized
 * `f/g` coefficient range for the selected parameter set.
 *
 * @param[in,out] ctx Sampler context.
 * @param[in] param Falcon parameter selector.
 * @param[out] poly Output coefficient array of length `n`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `param` is unsupported.
 */
noxtls_return_t noxtls_falcon_keygen_sample_short_poly(noxtls_falcon_sampler_ctx_t *ctx,
                                                       noxtls_falcon_param_t param,
                                                       int16_t *poly);

/**
 * @brief Check whether a sampled Falcon `(f, g)` candidate passes keygen preconditions.
 *
 * This enforces the serialized `f/g` coefficient bounds, rejects the impossible
 * mod-2 case where both polynomials are divisible by `x + 1`, and checks that
 * `f` is invertible modulo `q` so a public key `h = g/f mod (x^n + 1, q)` exists.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] f Candidate secret polynomial `f`.
 * @param[in] g Candidate secret polynomial `g`.
 * @return `NOXTLS_RETURN_SUCCESS` if the candidate passes these prechecks,
 *         `NOXTLS_RETURN_NULL` on a null pointer, `NOXTLS_RETURN_INVALID_PARAM`
 *         on an unsupported parameter or out-of-range coefficient, or
 *         `NOXTLS_RETURN_FAILED` if the candidate is mathematically invalid.
 */
noxtls_return_t noxtls_falcon_keygen_check_fg(noxtls_falcon_param_t param,
                                              const int16_t *f,
                                              const int16_t *g);

/**
 * @brief Sample Falcon keygen candidates until a prechecked `(f, g)` pair is found.
 *
 * This repeatedly samples short `f` and `g` polynomials and applies
 * @ref noxtls_falcon_keygen_check_fg to reject invalid candidates before the
 * later NTRU-solving stage.
 *
 * @param[in,out] ctx Sampler context.
 * @param[in] param Falcon parameter selector.
 * @param[out] f Output prechecked secret polynomial `f`.
 * @param[out] g Output prechecked secret polynomial `g`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` on an unsupported parameter, or
 *         `NOXTLS_RETURN_FAILED` if no acceptable candidate is found in the bounded
 *         number of sampling attempts.
 */
noxtls_return_t noxtls_falcon_keygen_sample_prechecked_fg(noxtls_falcon_sampler_ctx_t *ctx,
                                                          noxtls_falcon_param_t param,
                                                          int16_t *f,
                                                          int16_t *g);

/**
 * @brief Compute the first Falcon keygen field norm reduction for a signed polynomial.
 *
 * For an even power-of-two degree `n`, this returns the half-degree polynomial
 * `N(f)` such that `N(f)(x^2) = f(x) * f(-x) mod (x^n + 1)`.
 *
 * @param[in] src Source polynomial of degree `n`.
 * @param[in] n Polynomial degree. Must be an even supported power of two.
 * @param[out] norm Output norm polynomial of degree `n/2`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
noxtls_return_t noxtls_falcon_keygen_field_norm(const int16_t *src,
                                                uint16_t n,
                                                int32_t *norm);

/**
 * @brief Solve the exact `n = 1` Falcon NTRU base case with B\'ezout coefficients.
 *
 * This finds integers `F` and `G` such that `f*G - g*F = q` when `gcd(f, g) = 1`.
 *
 * @param[in] f Scalar secret coefficient `f`.
 * @param[in] g Scalar secret coefficient `g`.
 * @param[out] F Output scalar `F`.
 * @param[out] G Output scalar `G`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if `f` and `g` are not coprime.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_base(int32_t f,
                                                     int32_t g,
                                                     int32_t *F,
                                                     int32_t *G);

/**
 * @brief Solve the exact `n = 1` Falcon NTRU base case on signed big-endian magnitudes.
 *
 * The inputs `f_mag` and `g_mag` are non-negative magnitudes encoded in `len`
 * big-endian bytes, with `f_negative` and `g_negative` indicating the signs of
 * the corresponding signed scalars. The outputs `F_mag` and `G_mag` use the same
 * signed-magnitude convention and satisfy `f*G - g*F = q` when the inputs are
 * coprime. This is intended as a clean-room substrate for moving Falcon keygen
 * beyond the bounded signed-64 validation path.
 *
 * @param[in] f_mag Magnitude of scalar `f` in big-endian bytes.
 * @param[in] f_negative Non-zero if scalar `f` is negative.
 * @param[in] g_mag Magnitude of scalar `g` in big-endian bytes.
 * @param[in] g_negative Non-zero if scalar `g` is negative.
 * @param[in] len Byte length of all input and output magnitudes.
 * @param[out] F_mag Output magnitude of scalar `F`.
 * @param[out] F_negative Output sign flag for scalar `F`.
 * @param[out] G_mag Output magnitude of scalar `G`.
 * @param[out] G_negative Output sign flag for scalar `G`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the scalars are not coprime or the exact
 *         signed result does not fit in `len` bytes.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_base_bn(const uint8_t *f_mag,
                                                        uint8_t f_negative,
                                                        const uint8_t *g_mag,
                                                        uint8_t g_negative,
                                                        uint32_t len,
                                                        uint8_t *F_mag,
                                                        uint8_t *F_negative,
                                                        uint8_t *G_mag,
                                                        uint8_t *G_negative);

/**
 * @brief Compute the Falcon keygen field norm for a degree-2 signed polynomial on big-endian magnitudes.
 *
 * For `f(x) = a0 + a1*x` in `Z[x]/(x^2 + 1)`, the field norm is the scalar
 * `N(f) = a0^2 + a1^2`. This helper computes that exact non-negative scalar from
 * the input magnitudes and writes it as a big-endian magnitude of length
 * `norm_len`, which must be at least `2*len + 1`.
 *
 * @param[in] a0_mag Magnitude of coefficient `a0`.
 * @param[in] a1_mag Magnitude of coefficient `a1`.
 * @param[in] len Byte length of each input magnitude.
 * @param[out] norm_mag Output norm magnitude.
 * @param[in] norm_len Length of `norm_mag` in bytes. Must be at least `2*len + 1`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the output buffer is too short.
 */
noxtls_return_t noxtls_falcon_keygen_field_norm_bn_n2(const uint8_t *a0_mag,
                                                      const uint8_t *a1_mag,
                                                      uint32_t len,
                                                      uint8_t *norm_mag,
                                                      uint32_t norm_len);

/**
 * @brief Compute the Falcon keygen field norm for a degree-4 signed polynomial on big-endian coefficients.
 *
 * The input `a_mag` contains four big-endian coefficient magnitudes laid out as
 * `[c0 || c1 || c2 || c3]`, each coefficient using `coeff_len` bytes. The
 * corresponding `a_negative` array contains one sign flag per coefficient. The
 * output is the half-degree norm polynomial `N(a)` with two signed coefficients
 * laid out as `[n0 || n1]`, each coefficient occupying `norm_len` bytes and one
 * sign flag in `norm_negative`.
 *
 * @param[in] a_mag Input coefficient magnitudes for the degree-4 polynomial.
 * @param[in] a_negative Input sign flags for the four coefficients.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] norm_mag Output coefficient magnitudes for the degree-2 norm polynomial.
 * @param[out] norm_negative Output sign flags for the two norm coefficients.
 * @param[in] norm_len Byte length of each output coefficient magnitude. Must be
 *            at least `2*coeff_len + 1`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if an intermediate exact value does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_field_norm_bn_n4(const uint8_t *a_mag,
                                                      const uint8_t *a_negative,
                                                      uint32_t coeff_len,
                                                      uint8_t *norm_mag,
                                                      uint8_t *norm_negative,
                                                      uint32_t norm_len);

/**
 * @brief Compute the Falcon keygen field norm for a degree-8 signed polynomial on big-endian coefficients.
 *
 * The input `a_mag` contains eight big-endian coefficient magnitudes laid out as
 * `[c0 || c1 || ... || c7]`, each coefficient using `coeff_len` bytes. The
 * corresponding `a_negative` array contains one sign flag per coefficient. The
 * output is the half-degree norm polynomial `N(a)` with four signed coefficients
 * laid out as `[n0 || n1 || n2 || n3]`, each coefficient occupying `norm_len`
 * bytes and one sign flag in `norm_negative`.
 *
 * @param[in] a_mag Input coefficient magnitudes for the degree-8 polynomial.
 * @param[in] a_negative Input sign flags for the eight coefficients.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] norm_mag Output coefficient magnitudes for the degree-4 norm polynomial.
 * @param[out] norm_negative Output sign flags for the four norm coefficients.
 * @param[in] norm_len Byte length of each output coefficient magnitude. Must be
 *            at least `2*coeff_len + 1`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if an intermediate exact value does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_field_norm_bn_n8(const uint8_t *a_mag,
                                                      const uint8_t *a_negative,
                                                      uint32_t coeff_len,
                                                      uint8_t *norm_mag,
                                                      uint8_t *norm_negative,
                                                      uint32_t norm_len);

/**
 * @brief Compute the Falcon keygen field norm for a degree-16 signed polynomial on big-endian coefficients.
 *
 * The input `a_mag` contains sixteen big-endian coefficient magnitudes laid out as
 * `[c0 || c1 || ... || c15]`, each coefficient using `coeff_len` bytes. The
 * corresponding `a_negative` array contains one sign flag per coefficient. The
 * output is the half-degree norm polynomial `N(a)` with eight signed coefficients
 * laid out as `[n0 || n1 || ... || n7]`, each coefficient occupying `norm_len`
 * bytes and one sign flag in `norm_negative`.
 *
 * @param[in] a_mag Input coefficient magnitudes for the degree-16 polynomial.
 * @param[in] a_negative Input sign flags for the sixteen coefficients.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] norm_mag Output coefficient magnitudes for the degree-8 norm polynomial.
 * @param[out] norm_negative Output sign flags for the eight norm coefficients.
 * @param[in] norm_len Byte length of each output coefficient magnitude. Must be
 *            at least `2*coeff_len + 1`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if an intermediate exact value does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_field_norm_bn_n16(const uint8_t *a_mag,
                                                       const uint8_t *a_negative,
                                                       uint32_t coeff_len,
                                                       uint8_t *norm_mag,
                                                       uint8_t *norm_negative,
                                                       uint32_t norm_len);

/**
 * @brief Compute the Falcon keygen field norm for a degree-32 signed polynomial on big-endian coefficients.
 *
 * The input `a_mag` contains thirty-two big-endian coefficient magnitudes laid out as
 * `[c0 || c1 || ... || c31]`, each coefficient using `coeff_len` bytes. The
 * corresponding `a_negative` array contains one sign flag per coefficient. The
 * output is the half-degree norm polynomial `N(a)` with sixteen signed coefficients
 * laid out as `[n0 || n1 || ... || n15]`, each coefficient occupying `norm_len`
 * bytes and one sign flag in `norm_negative`.
 *
 * @param[in] a_mag Input coefficient magnitudes for the degree-32 polynomial.
 * @param[in] a_negative Input sign flags for the thirty-two coefficients.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] norm_mag Output coefficient magnitudes for the degree-16 norm polynomial.
 * @param[out] norm_negative Output sign flags for the sixteen norm coefficients.
 * @param[in] norm_len Byte length of each output coefficient magnitude. Must be
 *            at least `2*coeff_len + 1`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if an intermediate exact value does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_field_norm_bn_n32(const uint8_t *a_mag,
                                                       const uint8_t *a_negative,
                                                       uint32_t coeff_len,
                                                       uint8_t *norm_mag,
                                                       uint8_t *norm_negative,
                                                       uint32_t norm_len);

/**
 * @brief Compute the Falcon keygen field norm for a degree-64 signed polynomial on big-endian coefficients.
 *
 * The input `a_mag` contains sixty-four big-endian coefficient magnitudes laid out as
 * `[c0 || c1 || ... || c63]`, each coefficient using `coeff_len` bytes. The
 * corresponding `a_negative` array contains one sign flag per coefficient. The
 * output is the half-degree norm polynomial `N(a)` with thirty-two signed coefficients
 * laid out as `[n0 || n1 || ... || n31]`, each coefficient occupying `norm_len`
 * bytes and one sign flag in `norm_negative`.
 *
 * @param[in] a_mag Input coefficient magnitudes for the degree-64 polynomial.
 * @param[in] a_negative Input sign flags for the sixty-four coefficients.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] norm_mag Output coefficient magnitudes for the degree-32 norm polynomial.
 * @param[out] norm_negative Output sign flags for the thirty-two norm coefficients.
 * @param[in] norm_len Byte length of each output coefficient magnitude. Must be
 *            at least `2*coeff_len + 1`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if an intermediate exact value does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_field_norm_bn_n64(const uint8_t *a_mag,
                                                       const uint8_t *a_negative,
                                                       uint32_t coeff_len,
                                                       uint8_t *norm_mag,
                                                       uint8_t *norm_negative,
                                                       uint32_t norm_len);

/**
 * @brief Compute the Falcon keygen field norm for a degree-128 signed polynomial on big-endian coefficients.
 *
 * The input `a_mag` contains one hundred twenty-eight big-endian coefficient magnitudes
 * laid out as `[c0 || c1 || ... || c127]`, each coefficient using `coeff_len`
 * bytes. The corresponding `a_negative` array contains one sign flag per coefficient.
 * The output is the half-degree norm polynomial `N(a)` with sixty-four signed
 * coefficients laid out as `[n0 || n1 || ... || n63]`, each coefficient occupying
 * `norm_len` bytes and one sign flag in `norm_negative`.
 *
 * @param[in] a_mag Input coefficient magnitudes for the degree-128 polynomial.
 * @param[in] a_negative Input sign flags for the one hundred twenty-eight coefficients.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] norm_mag Output coefficient magnitudes for the degree-64 norm polynomial.
 * @param[out] norm_negative Output sign flags for the sixty-four norm coefficients.
 * @param[in] norm_len Byte length of each output coefficient magnitude. Must be
 *            at least `2*coeff_len + 1`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if an intermediate exact value does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_field_norm_bn_n128(const uint8_t *a_mag,
                                                        const uint8_t *a_negative,
                                                        uint32_t coeff_len,
                                                        uint8_t *norm_mag,
                                                        uint8_t *norm_negative,
                                                        uint32_t norm_len);

/**
 * @brief Compute the Falcon keygen field norm for a degree-256 signed polynomial on big-endian coefficients.
 *
 * The input `a_mag` contains two hundred fifty-six big-endian coefficient
 * magnitudes laid out as `[c0 || c1 || ... || c255]`, each coefficient using
 * `coeff_len` bytes. The corresponding `a_negative` array contains one sign flag
 * per coefficient. The output is the half-degree norm polynomial `N(a)` with
 * one hundred twenty-eight signed coefficients laid out as
 * `[n0 || n1 || ... || n127]`, each coefficient occupying `norm_len` bytes and
 * one sign flag in `norm_negative`.
 *
 * @param[in] a_mag Input coefficient magnitudes for the degree-256 polynomial.
 * @param[in] a_negative Input sign flags for the two hundred fifty-six coefficients.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] norm_mag Output coefficient magnitudes for the degree-128 norm polynomial.
 * @param[out] norm_negative Output sign flags for the one hundred twenty-eight norm coefficients.
 * @param[in] norm_len Byte length of each output coefficient magnitude. Must be
 *            at least `2*coeff_len + 1`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if an intermediate exact value does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_field_norm_bn_n256(const uint8_t *a_mag,
                                                        const uint8_t *a_negative,
                                                        uint32_t coeff_len,
                                                        uint8_t *norm_mag,
                                                        uint8_t *norm_negative,
                                                        uint32_t norm_len);

/**
 * @brief Compute the Falcon keygen field norm for a degree-512 signed polynomial on big-endian coefficients.
 *
 * The input `a_mag` contains five hundred twelve big-endian coefficient magnitudes
 * laid out as `[c0 || c1 || ... || c511]`, each coefficient using `coeff_len`
 * bytes. The corresponding `a_negative` array contains one sign flag per coefficient.
 * The output is the half-degree norm polynomial `N(a)` with two hundred fifty-six
 * signed coefficients laid out as `[n0 || n1 || ... || n255]`, each coefficient
 * occupying `norm_len` bytes and one sign flag in `norm_negative`.
 *
 * @param[in] a_mag Input coefficient magnitudes for the degree-512 polynomial.
 * @param[in] a_negative Input sign flags for the five hundred twelve coefficients.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] norm_mag Output coefficient magnitudes for the degree-256 norm polynomial.
 * @param[out] norm_negative Output sign flags for the two hundred fifty-six norm coefficients.
 * @param[in] norm_len Byte length of each output coefficient magnitude. Must be
 *            at least `2*coeff_len + 1`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if an intermediate exact value does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_field_norm_bn_n512(const uint8_t *a_mag,
                                                        const uint8_t *a_negative,
                                                        uint32_t coeff_len,
                                                        uint8_t *norm_mag,
                                                        uint8_t *norm_negative,
                                                        uint32_t norm_len);

/**
 * @brief Solve the exact Falcon NTRU equation for degree `n = 2` on signed big-endian coefficients.
 *
 * The inputs `f_mag` and `g_mag` contain two big-endian coefficient magnitudes
 * laid out as `[c0 || c1]`, each coefficient using `coeff_len` bytes. The
 * corresponding `f_negative` and `g_negative` arrays contain one sign flag per
 * coefficient. The outputs `F_mag` and `G_mag` use the same layout, but each
 * coefficient occupies `result_len` bytes and may exceed 64-bit range.
 *
 * @param[in] f_mag Input coefficient magnitudes for `f`.
 * @param[in] f_negative Input sign flags for `f`.
 * @param[in] g_mag Input coefficient magnitudes for `g`.
 * @param[in] g_negative Input sign flags for `g`.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] F_mag Output coefficient magnitudes for `F`.
 * @param[out] F_negative Output sign flags for `F`.
 * @param[out] G_mag Output coefficient magnitudes for `G`.
 * @param[out] G_negative Output sign flags for `G`.
 * @param[in] result_len Byte length of each output coefficient magnitude. Must
 *            be at least `3*coeff_len + 1`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the intermediate exact solution does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_bn_n2(const uint8_t *f_mag,
                                                      const uint8_t *f_negative,
                                                      const uint8_t *g_mag,
                                                      const uint8_t *g_negative,
                                                      uint32_t coeff_len,
                                                      uint8_t *F_mag,
                                                      uint8_t *F_negative,
                                                      uint8_t *G_mag,
                                                      uint8_t *G_negative,
                                                      uint32_t result_len);

/**
 * @brief Solve the exact Falcon NTRU equation for degree `n = 4` on signed big-endian coefficients.
 *
 * The inputs `f_mag` and `g_mag` contain four big-endian coefficient magnitudes
 * laid out as `[c0 || c1 || c2 || c3]`, each coefficient using `coeff_len`
 * bytes. The corresponding `f_negative` and `g_negative` arrays contain one
 * sign flag per coefficient. The outputs `F_mag` and `G_mag` use the same
 * layout, but each coefficient occupies `result_len` bytes and may exceed
 * 64-bit range.
 *
 * @param[in] f_mag Input coefficient magnitudes for `f`.
 * @param[in] f_negative Input sign flags for `f`.
 * @param[in] g_mag Input coefficient magnitudes for `g`.
 * @param[in] g_negative Input sign flags for `g`.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] F_mag Output coefficient magnitudes for `F`.
 * @param[out] F_negative Output sign flags for `F`.
 * @param[out] G_mag Output coefficient magnitudes for `G`.
 * @param[out] G_negative Output sign flags for `G`.
 * @param[in] result_len Byte length of each output coefficient magnitude. Must
 *            be at least `7*coeff_len + 4`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the intermediate exact solution does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_bn_n4(const uint8_t *f_mag,
                                                      const uint8_t *f_negative,
                                                      const uint8_t *g_mag,
                                                      const uint8_t *g_negative,
                                                      uint32_t coeff_len,
                                                      uint8_t *F_mag,
                                                      uint8_t *F_negative,
                                                      uint8_t *G_mag,
                                                      uint8_t *G_negative,
                                                      uint32_t result_len);

/**
 * @brief Solve the exact Falcon NTRU equation for degree `n = 8` on signed big-endian coefficients.
 *
 * The inputs `f_mag` and `g_mag` contain eight big-endian coefficient magnitudes
 * laid out as `[c0 || c1 || ... || c7]`, each coefficient using `coeff_len`
 * bytes. The corresponding `f_negative` and `g_negative` arrays contain one
 * sign flag per coefficient. The outputs `F_mag` and `G_mag` use the same
 * layout, but each coefficient occupies `result_len` bytes and may exceed
 * 64-bit range.
 *
 * @param[in] f_mag Input coefficient magnitudes for `f`.
 * @param[in] f_negative Input sign flags for `f`.
 * @param[in] g_mag Input coefficient magnitudes for `g`.
 * @param[in] g_negative Input sign flags for `g`.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] F_mag Output coefficient magnitudes for `F`.
 * @param[out] F_negative Output sign flags for `F`.
 * @param[out] G_mag Output coefficient magnitudes for `G`.
 * @param[out] G_negative Output sign flags for `G`.
 * @param[in] result_len Byte length of each output coefficient magnitude. Must
 *            be at least `15*coeff_len + 11`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the intermediate exact solution does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_bn_n8(const uint8_t *f_mag,
                                                      const uint8_t *f_negative,
                                                      const uint8_t *g_mag,
                                                      const uint8_t *g_negative,
                                                      uint32_t coeff_len,
                                                      uint8_t *F_mag,
                                                      uint8_t *F_negative,
                                                      uint8_t *G_mag,
                                                      uint8_t *G_negative,
                                                      uint32_t result_len);

/**
 * @brief Solve the exact Falcon NTRU equation for degree `n = 16` on signed big-endian coefficients.
 *
 * The inputs `f_mag` and `g_mag` contain sixteen big-endian coefficient magnitudes
 * laid out as `[c0 || c1 || ... || c15]`, each coefficient using `coeff_len`
 * bytes. The corresponding `f_negative` and `g_negative` arrays contain one
 * sign flag per coefficient. The outputs `F_mag` and `G_mag` use the same
 * layout, but each coefficient occupies `result_len` bytes and may exceed
 * 64-bit range.
 *
 * @param[in] f_mag Input coefficient magnitudes for `f`.
 * @param[in] f_negative Input sign flags for `f`.
 * @param[in] g_mag Input coefficient magnitudes for `g`.
 * @param[in] g_negative Input sign flags for `g`.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] F_mag Output coefficient magnitudes for `F`.
 * @param[out] F_negative Output sign flags for `F`.
 * @param[out] G_mag Output coefficient magnitudes for `G`.
 * @param[out] G_negative Output sign flags for `G`.
 * @param[in] result_len Byte length of each output coefficient magnitude. Must
 *            be at least `31*coeff_len + 26`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the intermediate exact solution does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_bn_n16(const uint8_t *f_mag,
                                                       const uint8_t *f_negative,
                                                       const uint8_t *g_mag,
                                                       const uint8_t *g_negative,
                                                       uint32_t coeff_len,
                                                       uint8_t *F_mag,
                                                       uint8_t *F_negative,
                                                       uint8_t *G_mag,
                                                       uint8_t *G_negative,
                                                       uint32_t result_len);

/**
 * @brief Solve the exact Falcon NTRU equation for degree `n = 32` on signed big-endian coefficients.
 *
 * The inputs `f_mag` and `g_mag` contain thirty-two big-endian coefficient magnitudes
 * laid out as `[c0 || c1 || ... || c31]`, each coefficient using `coeff_len`
 * bytes. The corresponding `f_negative` and `g_negative` arrays contain one
 * sign flag per coefficient. The outputs `F_mag` and `G_mag` use the same
 * layout, but each coefficient occupies `result_len` bytes and may exceed
 * 64-bit range.
 *
 * @param[in] f_mag Input coefficient magnitudes for `f`.
 * @param[in] f_negative Input sign flags for `f`.
 * @param[in] g_mag Input coefficient magnitudes for `g`.
 * @param[in] g_negative Input sign flags for `g`.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] F_mag Output coefficient magnitudes for `F`.
 * @param[out] F_negative Output sign flags for `F`.
 * @param[out] G_mag Output coefficient magnitudes for `G`.
 * @param[out] G_negative Output sign flags for `G`.
 * @param[in] result_len Byte length of each output coefficient magnitude. Must
 *            be at least `63*coeff_len + 57`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the intermediate exact solution does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_bn_n32(const uint8_t *f_mag,
                                                       const uint8_t *f_negative,
                                                       const uint8_t *g_mag,
                                                       const uint8_t *g_negative,
                                                       uint32_t coeff_len,
                                                       uint8_t *F_mag,
                                                       uint8_t *F_negative,
                                                       uint8_t *G_mag,
                                                       uint8_t *G_negative,
                                                       uint32_t result_len);

/**
 * @brief Solve the exact Falcon NTRU equation for degree `n = 64` on signed big-endian coefficients.
 *
 * The inputs `f_mag` and `g_mag` contain sixty-four big-endian coefficient magnitudes
 * laid out as `[c0 || c1 || ... || c63]`, each coefficient using `coeff_len`
 * bytes. The corresponding `f_negative` and `g_negative` arrays contain one
 * sign flag per coefficient. The outputs `F_mag` and `G_mag` use the same
 * layout, but each coefficient occupies `result_len` bytes and may exceed
 * 64-bit range.
 *
 * @param[in] f_mag Input coefficient magnitudes for `f`.
 * @param[in] f_negative Input sign flags for `f`.
 * @param[in] g_mag Input coefficient magnitudes for `g`.
 * @param[in] g_negative Input sign flags for `g`.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] F_mag Output coefficient magnitudes for `F`.
 * @param[out] F_negative Output sign flags for `F`.
 * @param[out] G_mag Output coefficient magnitudes for `G`.
 * @param[out] G_negative Output sign flags for `G`.
 * @param[in] result_len Byte length of each output coefficient magnitude. Must
 *            be at least `127*coeff_len + 120`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the intermediate exact solution does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_bn_n64(const uint8_t *f_mag,
                                                       const uint8_t *f_negative,
                                                       const uint8_t *g_mag,
                                                       const uint8_t *g_negative,
                                                       uint32_t coeff_len,
                                                       uint8_t *F_mag,
                                                       uint8_t *F_negative,
                                                       uint8_t *G_mag,
                                                       uint8_t *G_negative,
                                                       uint32_t result_len);

/**
 * @brief Solve the exact Falcon NTRU equation for degree `n = 128` on signed big-endian coefficients.
 *
 * The inputs `f_mag` and `g_mag` contain one hundred twenty-eight big-endian
 * coefficient magnitudes laid out as `[c0 || c1 || ... || c127]`, each coefficient
 * using `coeff_len` bytes. The corresponding `f_negative` and `g_negative` arrays
 * contain one sign flag per coefficient. The outputs `F_mag` and `G_mag` use the
 * same layout, but each coefficient occupies `result_len` bytes and may exceed
 * 64-bit range.
 *
 * @param[in] f_mag Input coefficient magnitudes for `f`.
 * @param[in] f_negative Input sign flags for `f`.
 * @param[in] g_mag Input coefficient magnitudes for `g`.
 * @param[in] g_negative Input sign flags for `g`.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] F_mag Output coefficient magnitudes for `F`.
 * @param[out] F_negative Output sign flags for `F`.
 * @param[out] G_mag Output coefficient magnitudes for `G`.
 * @param[out] G_negative Output sign flags for `G`.
 * @param[in] result_len Byte length of each output coefficient magnitude. Must
 *            be at least `255*coeff_len + 247`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the intermediate exact solution does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_bn_n128(const uint8_t *f_mag,
                                                        const uint8_t *f_negative,
                                                        const uint8_t *g_mag,
                                                        const uint8_t *g_negative,
                                                        uint32_t coeff_len,
                                                        uint8_t *F_mag,
                                                        uint8_t *F_negative,
                                                        uint8_t *G_mag,
                                                        uint8_t *G_negative,
                                                        uint32_t result_len);

/**
 * @brief Solve the exact Falcon NTRU equation for degree `n = 256` on signed big-endian coefficients.
 *
 * The inputs `f_mag` and `g_mag` contain two hundred fifty-six big-endian
 * coefficient magnitudes laid out as `[c0 || c1 || ... || c255]`, each coefficient
 * using `coeff_len` bytes. The corresponding `f_negative` and `g_negative` arrays
 * contain one sign flag per coefficient. The outputs `F_mag` and `G_mag` use the
 * same layout, but each coefficient occupies `result_len` bytes and may exceed
 * 64-bit range.
 *
 * @param[in] f_mag Input coefficient magnitudes for `f`.
 * @param[in] f_negative Input sign flags for `f`.
 * @param[in] g_mag Input coefficient magnitudes for `g`.
 * @param[in] g_negative Input sign flags for `g`.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] F_mag Output coefficient magnitudes for `F`.
 * @param[out] F_negative Output sign flags for `F`.
 * @param[out] G_mag Output coefficient magnitudes for `G`.
 * @param[out] G_negative Output sign flags for `G`.
 * @param[in] result_len Byte length of each output coefficient magnitude. Must
 *            be at least `511*coeff_len + 502`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the intermediate exact solution does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_bn_n256(const uint8_t *f_mag,
                                                        const uint8_t *f_negative,
                                                        const uint8_t *g_mag,
                                                        const uint8_t *g_negative,
                                                        uint32_t coeff_len,
                                                        uint8_t *F_mag,
                                                        uint8_t *F_negative,
                                                        uint8_t *G_mag,
                                                        uint8_t *G_negative,
                                                        uint32_t result_len);

/**
 * @brief Solve the exact Falcon NTRU equation for degree `n = 512` on signed big-endian coefficients.
 *
 * The inputs `f_mag` and `g_mag` contain five hundred twelve big-endian
 * coefficient magnitudes laid out as `[c0 || c1 || ... || c511]`, each coefficient
 * using `coeff_len` bytes. The corresponding `f_negative` and `g_negative` arrays
 * contain one sign flag per coefficient. The outputs `F_mag` and `G_mag` use the
 * same layout, but each coefficient occupies `result_len` bytes and may exceed
 * 64-bit range.
 *
 * @param[in] f_mag Input coefficient magnitudes for `f`.
 * @param[in] f_negative Input sign flags for `f`.
 * @param[in] g_mag Input coefficient magnitudes for `g`.
 * @param[in] g_negative Input sign flags for `g`.
 * @param[in] coeff_len Byte length of each input coefficient magnitude.
 * @param[out] F_mag Output coefficient magnitudes for `F`.
 * @param[out] F_negative Output sign flags for `F`.
 * @param[out] G_mag Output coefficient magnitudes for `G`.
 * @param[out] G_negative Output sign flags for `G`.
 * @param[in] result_len Byte length of each output coefficient magnitude. Must
 *            be at least `1023*coeff_len + 1013`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_FAILED` if the intermediate exact solution does not fit
 *         in the requested output width.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_bn_n512(const uint8_t *f_mag,
                                                        const uint8_t *f_negative,
                                                        const uint8_t *g_mag,
                                                        const uint8_t *g_negative,
                                                        uint32_t coeff_len,
                                                        uint8_t *F_mag,
                                                        uint8_t *F_negative,
                                                        uint8_t *G_mag,
                                                        uint8_t *G_negative,
                                                        uint32_t result_len);

/**
 * @brief Evaluate a signed Falcon keygen polynomial at `-x`.
 *
 * @param[in] src Source polynomial of degree `n`.
 * @param[in] n Polynomial degree.
 * @param[out] out Output polynomial `src(-x)` with 32-bit coefficients.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
noxtls_return_t noxtls_falcon_keygen_apply_negx(const int16_t *src,
                                                uint16_t n,
                                                int32_t *out);

/**
 * @brief Lift a half-degree signed polynomial into the full Falcon ring through `x^2`.
 *
 * @param[in] src Source polynomial of degree `n/2`.
 * @param[in] n Target full degree. Must be an even supported power of two.
 * @param[out] out Output polynomial `src(x^2)` with 32-bit coefficients.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
noxtls_return_t noxtls_falcon_keygen_lift_x2(const int32_t *src,
                                             uint16_t n,
                                             int32_t *out);

/**
 * @brief Lift a child Falcon NTRU solution back to the parent degree.
 *
 * Given a degree-`n/2` solution `(Fp, Gp)` for the field norms of `(f, g)`,
 * this computes the unreduced parent-degree candidate:
 * `F = Fp(x^2) * g(-x)` and `G = Gp(x^2) * f(-x)`.
 *
 * @param[in] f Parent secret polynomial `f`.
 * @param[in] g Parent secret polynomial `g`.
 * @param[in] n Parent degree. Must be an even supported power of two.
 * @param[in] Fp Child solution polynomial `F'` of degree `n/2`.
 * @param[in] Gp Child solution polynomial `G'` of degree `n/2`.
 * @param[out] F Output parent candidate `F`.
 * @param[out] G Output parent candidate `G`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` if `n` is unsupported.
 */
noxtls_return_t noxtls_falcon_keygen_combine_from_child(const int16_t *f,
                                                        const int16_t *g,
                                                        uint16_t n,
                                                        const int32_t *Fp,
                                                        const int32_t *Gp,
                                                        int32_t *F,
                                                        int32_t *G);

/**
 * @brief Recursively solve the exact Falcon NTRU equation on small power-of-two degrees.
 *
 * This clean-room validation path uses field norms, the exact `n = 1` base case,
 * and child-to-parent lifting without coefficient reduction. It is intentionally
 * bounded to small degrees that fit comfortably in signed 32-bit coefficients.
 *
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[in] n Polynomial degree. Must be a supported power of two and no more than `16`.
 * @param[out] F Output polynomial `F` with signed 32-bit coefficients.
 * @param[out] G Output polynomial `G` with signed 32-bit coefficients.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` on an unsupported degree, or
 *         `NOXTLS_RETURN_FAILED` if no exact solution exists.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_exact_small(const int16_t *f,
                                                            const int16_t *g,
                                                            uint16_t n,
                                                            int32_t *F,
                                                            int32_t *G);

/**
 * @brief Solve the exact Falcon NTRU equation with a widened 64-bit output substrate.
 *
 * This clean-room validation path extends the exact recursive norm/lift solve one
 * level beyond @ref noxtls_falcon_keygen_solve_ntru_exact_small by keeping the
 * parent-degree result in signed 64-bit coefficients. It is currently bounded to
 * supported power-of-two degrees no more than `512`.
 *
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[in] n Polynomial degree. Must be a supported power of two and no more than `512`.
 * @param[out] F Output polynomial `F` with signed 64-bit coefficients.
 * @param[out] G Output polynomial `G` with signed 64-bit coefficients.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` on an unsupported degree, or
 *         `NOXTLS_RETURN_FAILED` if no exact solution exists.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_exact_wide(const int16_t *f,
                                                           const int16_t *g,
                                                           uint16_t n,
                                                           int64_t *F,
                                                           int64_t *G);

/**
 * @brief Reduce an exact small-degree Falcon NTRU solution by subtracting lattice multiples.
 *
 * This keeps the exact equation `fG - gF = q` unchanged while heuristically shrinking
 * `F` and `G` through FFT-based nearest-plane rounding. It is intended for the same
 * bounded validation degrees as @ref noxtls_falcon_keygen_solve_ntru_exact_small.
 *
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[in] n Polynomial degree. Must be a supported power of two and no more than `16`.
 * @param[in,out] F Solution polynomial `F` to reduce in place.
 * @param[in,out] G Solution polynomial `G` to reduce in place.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         or `NOXTLS_RETURN_INVALID_PARAM` on an unsupported degree.
 */
noxtls_return_t noxtls_falcon_keygen_reduce_solution_small(const int16_t *f,
                                                           const int16_t *g,
                                                           uint16_t n,
                                                           int32_t *F,
                                                           int32_t *G);

/**
 * @brief Recursively solve and reduce the Falcon NTRU equation on supported power-of-two degrees.
 *
 * This clean-room path exposes a general recursive norm/lift/reduce interface
 * that mirrors Falcon's `NTRUSolve` structure while still failing closed if
 * coefficient growth exceeds the signed 32-bit validation substrate.
 *
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[in] n Polynomial degree. Must be a supported power of two no more than
 *            @ref NOXTLS_FALCON_MAX_N.
 * @param[out] F Output polynomial `F` with signed 32-bit coefficients.
 * @param[out] G Output polynomial `G` with signed 32-bit coefficients.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` on an unsupported degree, or
 *         `NOXTLS_RETURN_FAILED` if no exact reduced solution is found within the
 *         signed 32-bit validation path.
 */
noxtls_return_t noxtls_falcon_keygen_solve_ntru_reduced(const int16_t *f,
                                                        const int16_t *g,
                                                        uint16_t n,
                                                        int32_t *F,
                                                        int32_t *G);

/**
 * @brief Sample an FFT-domain Falcon vector from a normalized LDL tree and FFT targets.
 *
 * The inputs `t0` and `t1` are FFT-domain targets. The outputs `z0` and `z1`
 * are FFT-domain sampled vectors corresponding to real integer coefficient polynomials.
 *
 * @param[in,out] ctx Sampler context.
 * @param[in] tree Normalized Falcon LDL tree.
 * @param[in] t0 First FFT-domain target.
 * @param[in] t1 Second FFT-domain target.
 * @param[in] n Polynomial degree.
 * @param[out] z0 Output sampled FFT-domain vector for the first component.
 * @param[out] z1 Output sampled FFT-domain vector for the second component.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` on an unsupported size, or a sampler/numerical error code.
 */
noxtls_return_t noxtls_falcon_sample_fft_tree(noxtls_falcon_sampler_ctx_t *ctx,
                                              const noxtls_falcon_complex_t *tree,
                                              const noxtls_falcon_complex_t *t0,
                                              const noxtls_falcon_complex_t *t1,
                                              uint16_t n,
                                              noxtls_falcon_complex_t *z0,
                                              noxtls_falcon_complex_t *z1);

/**
 * @brief Compute a Falcon public polynomial from secret polynomials `f` and `g`.
 *
 * This computes `h = g / f mod (x^n + 1, q)` for a supported Falcon parameter set.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[out] h Output public polynomial coefficients modulo `q`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` if `param` is unsupported, or `NOXTLS_RETURN_FAILED`
 *         if `f` is not invertible in the Falcon ring.
 */
noxtls_return_t noxtls_falcon_compute_public(noxtls_falcon_param_t param,
                                             const int16_t *f,
                                             const int16_t *g,
                                             uint16_t *h);

/**
 * @brief Derive and encode a Falcon public key from a serialized Falcon secret key.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] secret_key Serialized Falcon secret key.
 * @param[in] secret_key_len Length of `secret_key` in bytes.
 * @param[out] public_key Output buffer for the serialized public key.
 * @param[in] public_key_len Exact output length in bytes.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` or `NOXTLS_RETURN_INVALID_BLOCK_SIZE` on a size/parameter
 *         mismatch, or `NOXTLS_RETURN_BAD_DATA` if the secret key is malformed or mathematically invalid.
 */
noxtls_return_t noxtls_falcon_derive_public_key_from_secret_key(noxtls_falcon_param_t param,
                                                                const uint8_t *secret_key,
                                                                uint32_t secret_key_len,
                                                                uint8_t *public_key,
                                                                uint32_t public_key_len);

/**
 * @brief Build serialized Falcon secret and public keys from secret polynomials.
 *
 * This validates the secret triple `(f, g, F)` by reconstructing the missing
 * `G`, derives the public polynomial `h`, then emits the serialized secret and
 * public key encodings for the selected parameter set.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] f Secret polynomial `f`.
 * @param[in] g Secret polynomial `g`.
 * @param[in] F Secret polynomial `F`.
 * @param[out] secret_key Output serialized Falcon secret key.
 * @param[in] secret_key_len Exact output length in bytes.
 * @param[out] public_key Output serialized Falcon public key.
 * @param[in] public_key_len Exact output length in bytes.
 * @return `NOXTLS_RETURN_SUCCESS` on success, `NOXTLS_RETURN_NULL` on a null pointer,
 *         `NOXTLS_RETURN_INVALID_PARAM` or `NOXTLS_RETURN_INVALID_BLOCK_SIZE` on a size/parameter
 *         mismatch, or `NOXTLS_RETURN_BAD_DATA` if the secret polynomials are malformed or
 *         mathematically invalid.
 */
noxtls_return_t noxtls_falcon_build_keypair_from_secret_components(noxtls_falcon_param_t param,
                                                                   const int16_t *f,
                                                                   const int16_t *g,
                                                                   const int16_t *F,
                                                                   uint8_t *secret_key,
                                                                   uint32_t secret_key_len,
                                                                   uint8_t *public_key,
                                                                   uint32_t public_key_len);

/**
 * @brief Serialize a Falcon public key.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] h Public-key polynomial coefficients modulo `q`.
 * @param[out] encoded Output buffer for the serialized key.
 * @param[in] encoded_len Exact output length in bytes.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or a parameter/size error code.
 */
noxtls_return_t noxtls_falcon_encode_public_key(noxtls_falcon_param_t param,
                                                const uint16_t *h,
                                                uint8_t *encoded,
                                                uint32_t encoded_len);
/**
 * @brief Parse a serialized Falcon public key.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] encoded Serialized key bytes.
 * @param[in] encoded_len Length of `encoded` in bytes.
 * @param[out] h Output public-key polynomial coefficients modulo `q`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or a parameter/format error code.
 */
noxtls_return_t noxtls_falcon_decode_public_key(noxtls_falcon_param_t param,
                                                const uint8_t *encoded,
                                                uint32_t encoded_len,
                                                uint16_t *h);

/**
 * @brief Serialize the `f`, `g`, and `F` polynomials of a Falcon secret key.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] f Secret-key polynomial `f`.
 * @param[in] g Secret-key polynomial `g`.
 * @param[in] F Secret-key polynomial `F`.
 * @param[out] encoded Output buffer for the serialized key.
 * @param[in] encoded_len Exact output length in bytes.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or a parameter/size error code.
 */
noxtls_return_t noxtls_falcon_encode_private_key(noxtls_falcon_param_t param,
                                                 const int16_t *f,
                                                 const int16_t *g,
                                                 const int16_t *F,
                                                 uint8_t *encoded,
                                                 uint32_t encoded_len);
/**
 * @brief Parse the `f`, `g`, and `F` polynomials from a serialized Falcon secret key.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] encoded Serialized key bytes.
 * @param[in] encoded_len Length of `encoded` in bytes.
 * @param[out] f Output polynomial `f`.
 * @param[out] g Output polynomial `g`.
 * @param[out] F Output polynomial `F`.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or a parameter/format error code.
 */
noxtls_return_t noxtls_falcon_decode_private_key(noxtls_falcon_param_t param,
                                                 const uint8_t *encoded,
                                                 uint32_t encoded_len,
                                                 int16_t *f,
                                                 int16_t *g,
                                                 int16_t *F);

/**
 * @brief Serialize a Falcon `s2` signature vector in compressed form.
 *
 * @param[in] s2 Signed coefficients to encode.
 * @param[in] coeff_count Number of coefficients in `s2`.
 * @param[out] encoded Output byte buffer.
 * @param[in] encoded_len Length of `encoded` in bytes.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or a parameter/size error code.
 */
noxtls_return_t noxtls_falcon_comp_encode(const int16_t *s2,
                                          uint32_t coeff_count,
                                          uint8_t *encoded,
                                          uint32_t encoded_len);
/**
 * @brief Parse a compressed Falcon `s2` signature vector.
 *
 * @param[in] encoded Serialized bytes.
 * @param[in] encoded_len Length of `encoded` in bytes.
 * @param[out] s2 Output signed coefficients.
 * @param[in] coeff_count Number of coefficients to decode.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or a parameter/format error code.
 */
noxtls_return_t noxtls_falcon_comp_decode(const uint8_t *encoded,
                                          uint32_t encoded_len,
                                          int16_t *s2,
                                          uint32_t coeff_count);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_FALCON_INTERNAL_H_ */
