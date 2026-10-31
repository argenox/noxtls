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
* File:    noxtls_mldsa_ntt.c
* Summary: ML-DSA modular reduction and negacyclic NTT (FIPS 204 Alg. 41-42,
*          Montgomery domain as in the reference implementation).
*
*
*****************************************************************************/

#include <stdint.h>
#include <stddef.h>

#include "noxtls_mldsa_internal.h"

#if NOXTLS_FEATURE_ML_DSA

/** zetas[i] = 2^32 * 1753^brv8(i) mod q, centred (index 0 unused). */
static const int32_t g_mldsa_zetas[NOXTLS_MLDSA_N] = {
    0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468,
    1826347, 2353451, -359251, -2091905, 3119733, -2884855, 3111497, 2680103,
    2725464, 1024112, -1079900, 3585928, -549488, -1119584, 2619752, -2108549,
    -2118186, -3859737, -1399561, -3277672, 1757237, -19422, 4010497, 280005,
    2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439,
    -3861115, -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299,
    -1699267, -1643818, 3505694, -3821735, 3507263, -2140649, -1600420, 3699596,
    811944, 531354, 954230, 3881043, 3900724, -2556880, 2071892, -2797779,
    -3930395, -1528703, -3677745, -3041255, -1452451, 3475950, 2176455, -1585221,
    -1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922,
    3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047,
    -671102, -1228525, -22981, -1308169, -381987, 1349076, 1852771, -1430430,
    -3343383, 264944, 508951, 3097992, 44288, -1100098, 904516, 3958618,
    -3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969, -1316856,
    189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330,
    1285669, -1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961,
    2091667, 3407706, 2316500, 3817976, -3342478, 2244091, -2446433, -3562462,
    266997, 2434439, -1235728, 3513181, -3520352, -3759364, -1197226, -3193378,
    900702, 1859098, 909542, 819034, 495491, -1613174, -43260, -522500,
    -655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838,
    342297, 286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044,
    2842341, 2691481, -2590150, 1265009, 4055324, 1247620, 2486353, 1595974,
    -3767016, 1250494, 2635921, -3548272, -2994039, 1869119, 1903435, -1050970,
    -1333058, 1237275, -3318210, -1430225, -451100, 1312455, 3306115, -1962642,
    -1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031,
    -542412, -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993,
    -2013608, 2432395, 2454455, -164721, 1957272, 3369112, 185531, -1207385,
    -3183426, 162844, 1616392, 3014001, 810149, 1652634, -3694233, -1799107,
    -3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735, 472078,
    -426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893,
    -2939036, -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687,
    -554416, 3919660, -48306, -1362209, 3937738, 1400424, -846154, 1976782,
};

/**
 * @brief Interpret the low 32 bits of a value as a two's complement int32 without
 *        implementation-defined conversions.
 * @param[in] u Unsigned 32-bit pattern.
 * @return Signed value with the same bit pattern.
 */
static int64_t mldsa_u32_to_signed(uint32_t u)
{
    return (int64_t)u - (int64_t)((uint64_t)(u >> 31U) << 32U);
}

/**
 * @brief Montgomery reduction: returns r = a * 2^-32 mod q with |r| < q
 *        for |a| < 2^31 * q.
 * @param[in] a Input value.
 * @return Reduced value.
 */
int32_t noxtls_mldsa_montgomery_reduce(int64_t a)
{
    uint32_t lo = (uint32_t)((uint64_t)a & 0xFFFFFFFFU);
    int64_t t = mldsa_u32_to_signed(lo * NOXTLS_MLDSA_QINV);

    return (int32_t)((a - (t * (int64_t)NOXTLS_MLDSA_Q)) >> 32U);
}

/**
 * @brief Reduce to a representative in [-6283008, 6283008] (a <= 2^31 - 2^22 - 1).
 * @param[in] a Input value.
 * @return Value congruent to a modulo q.
 */
int32_t noxtls_mldsa_reduce32(int32_t a)
{
    int32_t t = (a + ((int32_t)1 << 22)) >> 23U;

    return a - (t * NOXTLS_MLDSA_Q);
}

/**
 * @brief Add q if the input is negative (constant time).
 * @param[in] a Input value.
 * @return a or a + q.
 */
int32_t noxtls_mldsa_caddq(int32_t a)
{
    return a + ((a >> 31U) & NOXTLS_MLDSA_Q);
}

/**
 * @brief Forward NTT in place (bit-reversed output, no reduction).
 * @param[in,out] p Polynomial; output coefficients bounded by 9q in magnitude.
 */
void noxtls_mldsa_poly_ntt(noxtls_mldsa_poly_t *p)
{
    uint32_t len = 0U;
    uint32_t start = 0U;
    uint32_t j = 0U;
    uint32_t k = 0U;

    for(len = 128U; len > 0U; len >>= 1U) {
        for(start = 0U; start < NOXTLS_MLDSA_N; start = j + len) {
            int32_t zeta = 0;

            k += 1U;
            zeta = g_mldsa_zetas[k];
            for(j = start; j < (start + len); j += 1U) {
                int32_t t = noxtls_mldsa_montgomery_reduce((int64_t)zeta * (int64_t)p->coeff[j + len]);

                p->coeff[j + len] = p->coeff[j] - t;
                p->coeff[j] = p->coeff[j] + t;
            }
        }
    }
}

/**
 * @brief Inverse NTT, multiplying by the Montgomery factor 2^32.
 * @param[in,out] p Polynomial with |coeff| < q; output |coeff| < q.
 */
void noxtls_mldsa_poly_invntt_tomont(noxtls_mldsa_poly_t *p)
{
    const int32_t f = 41978; /* mont^2 / 256 */
    uint32_t len = 0U;
    uint32_t start = 0U;
    uint32_t j = 0U;
    uint32_t k = NOXTLS_MLDSA_N;

    for(len = 1U; len < NOXTLS_MLDSA_N; len <<= 1U) {
        for(start = 0U; start < NOXTLS_MLDSA_N; start = j + len) {
            int32_t zeta = 0;

            k -= 1U;
            zeta = -g_mldsa_zetas[k];
            for(j = start; j < (start + len); j += 1U) {
                int32_t t = p->coeff[j];

                p->coeff[j] = t + p->coeff[j + len];
                p->coeff[j + len] = t - p->coeff[j + len];
                p->coeff[j + len] = noxtls_mldsa_montgomery_reduce((int64_t)zeta * (int64_t)p->coeff[j + len]);
            }
        }
    }
    for(j = 0U; j < NOXTLS_MLDSA_N; j += 1U) {
        p->coeff[j] = noxtls_mldsa_montgomery_reduce((int64_t)f * (int64_t)p->coeff[j]);
    }
}

/**
 * @brief r = a * b * 2^-32 (pointwise, NTT domain).
 * @param[out] r Output polynomial (may alias a or b).
 * @param[in] a First operand.
 * @param[in] b Second operand.
 */
void noxtls_mldsa_poly_pointwise_montgomery(noxtls_mldsa_poly_t *r,
                                            const noxtls_mldsa_poly_t *a,
                                            const noxtls_mldsa_poly_t *b)
{
    uint32_t i = 0U;

    for(i = 0U; i < NOXTLS_MLDSA_N; i += 1U) {
        r->coeff[i] = noxtls_mldsa_montgomery_reduce((int64_t)a->coeff[i] * (int64_t)b->coeff[i]);
    }
}

/**
 * @brief r += a * b * 2^-32 (pointwise, NTT domain).
 * @param[in,out] r Accumulator.
 * @param[in] a First operand.
 * @param[in] b Second operand.
 */
void noxtls_mldsa_poly_pointwise_acc_montgomery(noxtls_mldsa_poly_t *r,
                                                const noxtls_mldsa_poly_t *a,
                                                const noxtls_mldsa_poly_t *b)
{
    uint32_t i = 0U;

    for(i = 0U; i < NOXTLS_MLDSA_N; i += 1U) {
        r->coeff[i] += noxtls_mldsa_montgomery_reduce((int64_t)a->coeff[i] * (int64_t)b->coeff[i]);
    }
}

#endif /* NOXTLS_FEATURE_ML_DSA */
