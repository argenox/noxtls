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
* File:    noxtls_camellia.c
* Summary: Camellia Cipher Algorithm Implementation (RFC 3713)
*
*****************************************************************************/

/** @addtogroup noxtls_encryption */

#ifdef __cplusplus
extern "C"
{
#endif

/* Standard Includes */
#include <stdint.h>
#include <string.h>
#include "common/noxtls_debug_printf.h"

/* Includes */
#include "noxtls_camellia.h"
#include "noxtls_camellia_internal.h"
#include "noxtls_ct.h"

#if NOXTLS_FEATURE_CAMELLIA

/* Forward declarations for mode-specific functions */

/* RFC 3713 SBOX1 (8-bit in/out) */
static const uint8_t camellia_sbox1[256] = {
    0x70U, 0x82U, 0x2cU, 0xecU, 0xb3U, 0x27U, 0xc0U, 0xe5U, 0xe4U, 0x85U, 0x57U, 0x35U, 0xeaU, 0x0cU, 0xaeU, 0x41U,
    0x23U, 0xefU, 0x6bU, 0x93U, 0x45U, 0x19U, 0xa5U, 0x21U, 0xedU, 0x0eU, 0x4fU, 0x4eU, 0x1dU, 0x65U, 0x92U, 0xbdU,
    0x86U, 0xb8U, 0xafU, 0x8fU, 0x7cU, 0xebU, 0x1fU, 0xceU, 0x3eU, 0x30U, 0xdcU, 0x5fU, 0x5eU, 0xc5U, 0x0bU, 0x1aU,
    0xa6U, 0xe1U, 0x39U, 0xcaU, 0xd5U, 0x47U, 0x5dU, 0x3dU, 0xd9U, 0x01U, 0x5aU, 0xd6U, 0x51U, 0x56U, 0x6cU, 0x4dU,
    0x8bU, 0x0dU, 0x9aU, 0x66U, 0xfbU, 0xccU, 0xb0U, 0x2dU, 0x74U, 0x12U, 0x2bU, 0x20U, 0xf0U, 0xb1U, 0x84U, 0x99U,
    0xdfU, 0x4cU, 0xcbU, 0xc2U, 0x34U, 0x7eU, 0x76U, 0x05U, 0x6dU, 0xb7U, 0xa9U, 0x31U, 0xd1U, 0x17U, 0x04U, 0xd7U,
    0x14U, 0x58U, 0x3aU, 0x61U, 0xdeU, 0x1bU, 0x11U, 0x1cU, 0x32U, 0x0fU, 0x9cU, 0x16U, 0x53U, 0x18U, 0xf2U, 0x22U,
    0xfeU, 0x44U, 0xcfU, 0xb2U, 0xc3U, 0xb5U, 0x7aU, 0x91U, 0x24U, 0x08U, 0xe8U, 0xa8U, 0x60U, 0xfcU, 0x69U, 0x50U,
    0xaaU, 0xd0U, 0xa0U, 0x7dU, 0xa1U, 0x89U, 0x62U, 0x97U, 0x54U, 0x5bU, 0x1eU, 0x95U, 0xe0U, 0xffU, 0x64U, 0xd2U,
    0x10U, 0xc4U, 0x00U, 0x48U, 0xa3U, 0xf7U, 0x75U, 0xdbU, 0x8aU, 0x03U, 0xe6U, 0xdaU, 0x09U, 0x3fU, 0xddU, 0x94U,
    0x87U, 0x5cU, 0x83U, 0x02U, 0xcdU, 0x4aU, 0x90U, 0x33U, 0x73U, 0x67U, 0xf6U, 0xf3U, 0x9dU, 0x7fU, 0xbfU, 0xe2U,
    0x52U, 0x9bU, 0xd8U, 0x26U, 0xc8U, 0x37U, 0xc6U, 0x3bU, 0x81U, 0x96U, 0x6fU, 0x4bU, 0x13U, 0xbeU, 0x63U, 0x2eU,
    0xe9U, 0x79U, 0xa7U, 0x8cU, 0x9fU, 0x6eU, 0xbcU, 0x8eU, 0x29U, 0xf5U, 0xf9U, 0xb6U, 0x2fU, 0xfdU, 0xb4U, 0x59U,
    0x78U, 0x98U, 0x06U, 0x6aU, 0xe7U, 0x46U, 0x71U, 0xbaU, 0xd4U, 0x25U, 0xabU, 0x42U, 0x88U, 0xa2U, 0x8dU, 0xfaU,
    0x72U, 0x07U, 0xb9U, 0x55U, 0xf8U, 0xeeU, 0xacU, 0x0aU, 0x36U, 0x49U, 0x2aU, 0x68U, 0x3cU, 0x38U, 0xf1U, 0xa4U,
    0x40U, 0x28U, 0xd3U, 0x7bU, 0xbbU, 0xc9U, 0x43U, 0xc1U, 0x15U, 0xe3U, 0xadU, 0xf4U, 0x77U, 0xc7U, 0x80U, 0x9eU
};

/* RFC 3713: SBOX2[x] = SBOX1[x] <<<1U, SBOX3[x] = SBOX1[x] <<<7U, SBOX4[x] = SBOX1[x <<<1U] */
static uint8_t camellia_sbox2[256];
static uint8_t camellia_sbox3[256];
static uint8_t camellia_sbox4[256];

/**
 * @brief Initialize the Camellia S-boxes.
 *
 * @return void
 */
static void camellia_init_sboxes(void)
{
    static int camellia_sboxes_initialized = 0;
    uint32_t i = 0U;
    if (camellia_sboxes_initialized != 0) { return; }
    for (i = 0U; i < 256U; i += 1U) {
        {
            uint32_t s = (uint32_t)camellia_sbox1[i];
            camellia_sbox2[i] = (uint8_t)(((s << 1U) | (s >> 7U)) & 0xFFU);
            camellia_sbox3[i] = (uint8_t)(((s << 7U) | (s >> 1U)) & 0xFFU);
            camellia_sbox4[i] = camellia_sbox1[(uint8_t)(((i << 1U) | (i >> 7U)) & 0xFFU)];
        }
    }
    camellia_sboxes_initialized = 1;
}

/* RFC 3713 F-function: 64-bit input, 64-bit subkey, 64-bit output */
/**
 * @brief The F-function.
 *
 * @param[in] F_IN The F_IN value.
 * @param[in] KE The KE value.
 * @return The return value.
 */
static uint64_t camellia_f64(uint64_t F_IN, uint64_t KE)
{
    uint64_t x = (uint64_t)(F_IN ^ KE);
    uint8_t t1 = 0U;
    uint8_t t2 = 0U;
    uint8_t t3 = 0U;
    uint8_t t4 = 0U;
    uint8_t t5 = 0U;
    uint8_t t6 = 0U;
    uint8_t t7 = 0U;
    uint8_t t8 = 0U;
    uint8_t y1 = 0U;
    uint8_t y2 = 0U;
    uint8_t y3 = 0U;
    uint8_t y4 = 0U;
    uint8_t y5 = 0U;
    uint8_t y6 = 0U;
    uint8_t y7 = 0U;
    uint8_t y8 = 0U;

    t1 = (uint8_t)(x >>56U);
    t2 = (uint8_t)(x >>48U);
    t3 = (uint8_t)(x >>40U);
    t4 = (uint8_t)(x >>32U);
    t5 = (uint8_t)(x >>24U);
    t6 = (uint8_t)(x >>16U);
    t7 = (uint8_t)(x >>8U);
    t8 = (uint8_t)x;

    t1 = camellia_sbox1[t1];
    t2 = camellia_sbox2[t2];
    t3 = camellia_sbox3[t3];
    t4 = camellia_sbox4[t4];
    t5 = camellia_sbox2[t5];
    t6 = camellia_sbox3[t6];
    t7 = camellia_sbox4[t7];
    t8 = camellia_sbox1[t8];

    y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8;
    y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8;
    y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8;
    y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7;
    y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8;
    y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8;
    y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8;
    y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;

    return (((uint64_t)y1) << 56U) | (((uint64_t)y2) << 48U) | (((uint64_t)y3) << 40U) | (((uint64_t)y4) << 32U)
         | (((uint64_t)y5) << 24U) | (((uint64_t)y6) << 16U) | (((uint64_t)y7) << 8U) | (uint64_t)y8;
}

/* 128-bit rotate left by r bits (0 <= r < 128); output high 64 and low 64 */
/**
 * @brief Rotate left by r bits.
 *
 * @param[in] hi The hi value.
 * @param[in] lo The lo value.
 * @param[in] r The r value.
 * @param[out] out_hi The out_hi value.
 * @param[out] out_lo The out_lo value.
 * @return void
 */
static void rotl128(uint64_t hi, uint64_t lo, uint32_t r, uint64_t *out_hi, uint64_t *out_lo)
{
    uint64_t nhi = 0U;
    uint64_t nlo = 0U;

    /* Key schedule uses only fixed distances; hard-code for MISRA 12.2. */
    switch(r) {
    case 0U:
        nhi = hi;
        nlo = lo;
        break;
    case 13U: /* from 77 via hi/lo swap */
        nhi = (uint64_t)((hi << 13U) | (lo >> 51U));
        nlo = (uint64_t)((lo << 13U) | (hi >> 51U));
        break;
    case 15U:
        nhi = (uint64_t)((hi << 15U) | (lo >> 49U));
        nlo = (uint64_t)((lo << 15U) | (hi >> 49U));
        break;
    case 30U:
        nhi = (uint64_t)((hi << 30U) | (lo >> 34U));
        nlo = (uint64_t)((lo << 30U) | (hi >> 34U));
        break;
    case 45U:
        nhi = (uint64_t)((hi << 45U) | (lo >> 19U));
        nlo = (uint64_t)((lo << 45U) | (hi >> 19U));
        break;
    case 47U: /* from 111 via hi/lo swap */
        nhi = (uint64_t)((hi << 47U) | (lo >> 17U));
        nlo = (uint64_t)((lo << 47U) | (hi >> 17U));
        break;
    case 60U:
        nhi = (uint64_t)((hi << 60U) | (lo >> 4U));
        nlo = (uint64_t)((lo << 60U) | (hi >> 4U));
        break;
    case 64U:
        nhi = lo;
        nlo = hi;
        break;
    case 77U: /* lo/hi swapped + 13 */
        nhi = (uint64_t)((lo << 13U) | (hi >> 51U));
        nlo = (uint64_t)((hi << 13U) | (lo >> 51U));
        break;
    case 94U: /* lo/hi swapped + 30 */
        nhi = (uint64_t)((lo << 30U) | (hi >> 34U));
        nlo = (uint64_t)((hi << 30U) | (lo >> 34U));
        break;
    case 111U: /* lo/hi swapped + 47 */
        nhi = (uint64_t)((lo << 47U) | (hi >> 17U));
        nlo = (uint64_t)((hi << 47U) | (lo >> 17U));
        break;
    default:
        nhi = hi;
        nlo = lo;
        break;
    }
    *out_hi = nhi;
    *out_lo = nlo;
}

/**
 * @brief Camellia Key Schedule (RFC 3713)
 * kw: 4 x 64-bit (pre/post whitening), ke: 6 x 64-bit (FL/FLINV), k: 24 x 64-bit (round keys)
 *
 * @param[in] key The key value.
 * @param[out] kw The kw value.
 * @param[out] ke The ke value.
 * @param[out] k The k value.
 * @param[in] type The type value.
 * @return The return value. 
 */
noxtls_return_t noxtls_camellia_key_schedule(const uint8_t* key, uint64_t* kw, uint64_t* ke, uint64_t* k, noxtls_camellia_type_t type)
{
    /* RFC 3713 Sigma constants (64-bit); block-scope for Rule 8.9. */
    static const uint64_t sigma1 = 0xA09E667F3BCC908BULL;
    static const uint64_t sigma2 = 0xB67AE8584CAA73B2ULL;
    static const uint64_t sigma3 = 0xC6EF372FE94F82BEULL;
    static const uint64_t sigma4 = 0x54FF53A5F1D36F1CULL;
    static const uint64_t sigma5 = 0x10E527FADE682D1DULL;
    static const uint64_t sigma6 = 0xB05688C2B3E6C1FDULL;
    uint64_t kl_hi = 0U;
    uint64_t kl_lo = 0U;
    uint64_t kr_hi = 0U;
    uint64_t kr_lo = 0U;
    uint64_t ka_hi = 0U;
    uint64_t ka_lo = 0U;
    uint64_t kb_hi = 0ULL;
    uint64_t kb_lo = 0ULL;
    uint64_t d1 = 0U;
    uint64_t d2 = 0U;
    uint32_t key_bytes = (type == NOXTLS_CAMELLIA_128_BIT) ? 16U : 32U;

    if ((key == NULL) || (kw == NULL) || (ke == NULL) || (k == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if ((type != NOXTLS_CAMELLIA_128_BIT) &&
       (type != NOXTLS_CAMELLIA_192_BIT) &&
       (type != NOXTLS_CAMELLIA_256_BIT)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    camellia_init_sboxes();

    /* Load KL (left 128 bits of key), big-endian */
    kl_hi = (((uint64_t)key[0]) << 56U) | (((uint64_t)key[1]) << 48U) | (((uint64_t)key[2]) << 40U) | (((uint64_t)key[3]) << 32U)
          | (((uint64_t)key[4]) << 24U) | (((uint64_t)key[5]) << 16U) | (((uint64_t)key[6]) << 8U) | (uint64_t)key[7];
    kl_lo = (((uint64_t)key[8]) << 56U) | (((uint64_t)key[9]) << 48U) | (((uint64_t)key[10]) << 40U) | (((uint64_t)key[11]) << 32U)
          | (((uint64_t)key[12]) << 24U) | (((uint64_t)key[13]) << 16U) | (((uint64_t)key[14]) << 8U) | (uint64_t)key[15];

    if (type == NOXTLS_CAMELLIA_128_BIT) {
        kr_hi = 0U;
        kr_lo = 0U;
    } else if (type == NOXTLS_CAMELLIA_192_BIT) {
        /* KR = (rightmost 64 bits of K) || (~(rightmost 64 bits of K)); high 64 of KR = key[16..23], low 64 = ~ */
        kr_hi = (((uint64_t)key[16]) << 56U) | (((uint64_t)key[17]) << 48U) | (((uint64_t)key[18]) << 40U) | (((uint64_t)key[19]) << 32U)
              | (((uint64_t)key[20]) << 24U) | (((uint64_t)key[21]) << 16U) | (((uint64_t)key[22]) << 8U) | (uint64_t)key[23];
        kr_lo = ~kr_hi;
    } else {
        kr_hi = (((uint64_t)key[16]) << 56U) | (((uint64_t)key[17]) << 48U) | (((uint64_t)key[18]) << 40U) | (((uint64_t)key[19]) << 32U)
              | (((uint64_t)key[20]) << 24U) | (((uint64_t)key[21]) << 16U) | (((uint64_t)key[22]) << 8U) | (uint64_t)key[23];
        kr_lo = (((uint64_t)key[24]) << 56U) | (((uint64_t)key[25]) << 48U) | (((uint64_t)key[26]) << 40U) | (((uint64_t)key[27]) << 32U)
              | (((uint64_t)key[28]) << 24U) | (((uint64_t)key[29]) << 16U) | (((uint64_t)key[30]) << 8U) | (uint64_t)key[31];
    }

    /* KA from KL, KR and Sigma1..4 */
    d1 = kl_hi ^ kr_hi;
    d2 = kl_lo ^ kr_lo;
    d2 ^= camellia_f64(d1, sigma1);
    d1 ^= camellia_f64(d2, sigma2);
    d1 ^= kl_hi;
    d2 ^= kl_lo;
    d2 ^= camellia_f64(d1, sigma3);
    d1 ^= camellia_f64(d2, sigma4);
    ka_hi = d1;
    ka_lo = d2;

    if (type != NOXTLS_CAMELLIA_128_BIT) {
        d1 = ka_hi ^ kr_hi;
        d2 = ka_lo ^ kr_lo;
        d2 ^= camellia_f64(d1, sigma5);
        d1 ^= camellia_f64(d2, sigma6);
        kb_hi = d1;
        kb_lo = d2;
    }

    if (type == NOXTLS_CAMELLIA_128_BIT) {
        uint64_t h = 0ULL;
        /* kw1, kw2 */
        (void)rotl128(kl_hi, kl_lo, 0U, &kw[0], &kw[1]);
        /* k1..k18, ke1..ke4, kw3, kw4. Note: k9=(KA<<<45U)>>64U, k10=(KL<<<60U)&MASK64 (different rotations). */
        (void)rotl128(ka_hi, ka_lo, 0U, &k[0], &k[1]);
        (void)rotl128(kl_hi, kl_lo, 15U, &k[2], &k[3]);
        (void)rotl128(ka_hi, ka_lo, 15U, &k[4], &k[5]);
        (void)rotl128(ka_hi, ka_lo, 30U, &ke[0], &ke[1]);
        (void)rotl128(kl_hi, kl_lo, 45U, &k[6], &k[7]);
        rotl128(ka_hi, ka_lo, 45U, &k[8], &h);           /* k[8]=k9; discard low(KA<<<45U) */
        rotl128(kl_hi, kl_lo, 60U, &h, &k[9]);          /* k[9]=k10=low(KL<<<60U) */
        rotl128(ka_hi, ka_lo, 60U, &k[10], &k[11]);      /* k[10]=k11, k[11]=k12 */
        (void)rotl128(kl_hi, kl_lo, 77U, &ke[2], &ke[3]);
        rotl128(kl_hi, kl_lo, 94U, &k[12], &k[13]);      /* k13, k14 */
        rotl128(ka_hi, ka_lo, 94U, &k[14], &k[15]);      /* k15, k16 */
        rotl128(kl_hi, kl_lo, 111U, &k[16], &k[17]);     /* k17, k18 */
        (void)rotl128(ka_hi, ka_lo, 111U, &kw[2], &kw[3]);
        (void)h;
    } else {
        /* 192/256: kw1,kw2 from KL; k1..k24, ke1..ke6, kw3,kw4 from KB/KR/KA/KL */
        (void)rotl128(kl_hi, kl_lo, 0U, &kw[0], &kw[1]);
        (void)rotl128(kb_hi, kb_lo, 0U, &k[0], &k[1]);
        (void)rotl128(kr_hi, kr_lo, 15U, &k[2], &k[3]);
        (void)rotl128(ka_hi, ka_lo, 15U, &k[4], &k[5]);
        (void)rotl128(kr_hi, kr_lo, 30U, &ke[0], &ke[1]);
        (void)rotl128(kb_hi, kb_lo, 30U, &k[6], &k[7]);
        (void)rotl128(kl_hi, kl_lo, 45U, &k[8], &k[9]);
        (void)rotl128(ka_hi, ka_lo, 45U, &k[10], &k[11]);
        (void)rotl128(kl_hi, kl_lo, 60U, &ke[2], &ke[3]);
        (void)rotl128(kr_hi, kr_lo, 60U, &k[12], &k[13]);
        (void)rotl128(kb_hi, kb_lo, 60U, &k[14], &k[15]);
        (void)rotl128(kl_hi, kl_lo, 77U, &k[16], &k[17]);
        (void)rotl128(ka_hi, ka_lo, 77U, &ke[4], &ke[5]);
        (void)rotl128(kr_hi, kr_lo, 94U, &k[18], &k[19]);
        (void)rotl128(ka_hi, ka_lo, 94U, &k[20], &k[21]);
        (void)rotl128(kl_hi, kl_lo, 111U, &k[22], &k[23]);
        (void)rotl128(kb_hi, kb_lo, 111U, &kw[2], &kw[3]);
    }
    (void)key_bytes;
    return NOXTLS_RETURN_SUCCESS;
}

/* FL: 64-bit input, 64-bit key KE */
/**
 * @brief The FL function.
 *
 * @param[in] FL_IN The FL_IN value.
 * @param[in] KE The KE value.
 * @return The return value.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static uint64_t camellia_fl(uint64_t FL_IN, uint64_t KE)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint32_t x1 = (uint32_t)(FL_IN >>32U);
    uint32_t x2 = (uint32_t)(FL_IN & 0xFFFFFFFFULL);
    uint32_t k1 = (uint32_t)(KE >>32U);
    uint32_t k2 = (uint32_t)(KE & 0xFFFFFFFFULL);
    {
        uint32_t anded = x1 & k1;
        uint64_t t64 = (uint64_t)anded;
        uint64_t shifted = (t64 << 1U) | (t64 >> 31U);
        uint32_t rot = (uint32_t)shifted;
        x2 ^= rot;
    }
    x1 ^= (x2 | k2);
    return (((uint64_t)x1) << 32U) | (uint64_t)x2;
}

/* FLINV: inverse of FL */
/**
 * @brief The FLINV function.
 *
 * @param[in] FLINV_IN The FLINV_IN value.
 * @param[in] KE The KE value.
 * @return The return value.
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static uint64_t camellia_flinv(uint64_t FLINV_IN, uint64_t KE)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint32_t y1 = (uint32_t)(FLINV_IN >>32U);
    uint32_t y2 = (uint32_t)(FLINV_IN & 0xFFFFFFFFULL);
    uint32_t k1 = (uint32_t)(KE >>32U);
    uint32_t k2 = (uint32_t)(KE & 0xFFFFFFFFULL);
    y1 ^= (y2 | k2);
    {
        uint32_t anded = y1 & k1;
        uint64_t t64 = (uint64_t)anded;
        uint64_t shifted = (t64 << 1U) | (t64 >> 31U);
        uint32_t rot = (uint32_t)shifted;
        y2 ^= rot;
    }
    return (((uint64_t)y1) << 32U) | (uint64_t)y2;
}

/* Load 128-bit block from big-endian bytes into D1 (high 64), D2 (low 64) */
/**
 * @brief Load the block from big-endian bytes.
 *
 * @param[in] data The data value.
 * @param[out] D1 The D1 value.
 * @param[out] D2 The D2 value.
 * @return void
 */
static void load_block_be(const uint8_t* data, uint64_t* D1, uint64_t* D2)
{
    *D1 = (((uint64_t)data[0]) << 56U) | (((uint64_t)data[1]) << 48U) | (((uint64_t)data[2]) << 40U) | (((uint64_t)data[3]) << 32U)
        | (((uint64_t)data[4]) << 24U) | (((uint64_t)data[5]) << 16U) | (((uint64_t)data[6]) << 8U) | (uint64_t)data[7];
    *D2 = (((uint64_t)data[8]) << 56U) | (((uint64_t)data[9]) << 48U) | (((uint64_t)data[10]) << 40U) | (((uint64_t)data[11]) << 32U)
        | (((uint64_t)data[12]) << 24U) | (((uint64_t)data[13]) << 16U) | (((uint64_t)data[14]) << 8U) | (uint64_t)data[15];
}

/* Store D2 (high 64), D1 (low 64) to big-endian bytes (C = (D2<<64U)|D1) */
/**
 * @brief Store the block in big-endian bytes.
 *
 * @param[out] output The output value.
 * @param[in] D1 The D1 value.
 * @param[in] D2 The D2 value.
 * @return void
 */
static void store_block_be(uint8_t* output, uint64_t D1, uint64_t D2)
{
    output[0] = (uint8_t)(D2 >>56U);
    output[1] = (uint8_t)(D2 >>48U);
    output[2] = (uint8_t)(D2 >>40U);
    output[3] = (uint8_t)(D2 >>32U);
    output[4] = (uint8_t)(D2 >>24U);
    output[5] = (uint8_t)(D2 >>16U);
    output[6] = (uint8_t)(D2 >>8U);
    output[7] = (uint8_t)D2;
    output[8] = (uint8_t)(D1 >>56U);
    output[9] = (uint8_t)(D1 >>48U);
    output[10] = (uint8_t)(D1 >>40U);
    output[11] = (uint8_t)(D1 >>32U);
    output[12] = (uint8_t)(D1 >>24U);
    output[13] = (uint8_t)(D1 >>16U);
    output[14] = (uint8_t)(D1 >>8U);
    output[15] = (uint8_t)D1;
}

/**
 * @brief Print the block in hexadecimal.
 *
 * @param[in] label The label value.
 * @param[in] block The block value.
 * @return void
 */
static void camellia_print_block_hex(const uint8_t *label, const uint8_t *block)
{
    uint32_t i = 0U;
    if (label != NULL) {
        (void)noxtls_debug_printf((const uint8_t *)"%s", label);
    }
    for (i = 0U; i < NOXTLS_CAMELLIA_BLOCK_LENGTH; i += 1U) {
        (void)noxtls_debug_printf((const uint8_t *)"%02x", block[i]);
    }
    (void)noxtls_debug_printf((const uint8_t *)"\n");
}

/**
 * @brief Camellia Encrypt Block (RFC 3713)
 *
 * @param[in] key The key value.
 * @param[in] data The data value.
 * @param[out] output The output value.
 * @param[in] type The type value.
 * @return The return value.
*/
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
noxtls_return_t noxtls_camellia_encrypt_block_internal(const uint8_t* key, const uint8_t* data, uint8_t* output, noxtls_camellia_type_t type)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint64_t kw[4];
    uint64_t ke[6];
    uint64_t k[24];
    uint64_t D1 = 0ULL;
    uint64_t D2 = 0ULL;
    if ((key == NULL) || (data == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_camellia_key_schedule(key, kw, ke, k, type);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    (void)load_block_be(data, &D1, &D2);

    D1 ^= kw[0];
    D2 ^= kw[1];

    if (type == NOXTLS_CAMELLIA_128_BIT) {
        D2 ^= camellia_f64(D1, k[0]);
        D1 ^= camellia_f64(D2, k[1]);
        D2 ^= camellia_f64(D1, k[2]);
        D1 ^= camellia_f64(D2, k[3]);
        D2 ^= camellia_f64(D1, k[4]);
        D1 ^= camellia_f64(D2, k[5]);
        D1 = camellia_fl(D1, ke[0]);
        D2 = camellia_flinv(D2, ke[1]);
        D2 ^= camellia_f64(D1, k[6]);
        D1 ^= camellia_f64(D2, k[7]);
        D2 ^= camellia_f64(D1, k[8]);
        D1 ^= camellia_f64(D2, k[9]);
        D2 ^= camellia_f64(D1, k[10]);
        D1 ^= camellia_f64(D2, k[11]);
        D1 = camellia_fl(D1, ke[2]);
        D2 = camellia_flinv(D2, ke[3]);
        D2 ^= camellia_f64(D1, k[12]);
        D1 ^= camellia_f64(D2, k[13]);
        D2 ^= camellia_f64(D1, k[14]);
        D1 ^= camellia_f64(D2, k[15]);
        D2 ^= camellia_f64(D1, k[16]);   /* round 17: k17 */
        D1 ^= camellia_f64(D2, k[17]);   /* round 18: k18 */
    } else {
        D2 ^= camellia_f64(D1, k[0]);
        D1 ^= camellia_f64(D2, k[1]);
        D2 ^= camellia_f64(D1, k[2]);
        D1 ^= camellia_f64(D2, k[3]);
        D2 ^= camellia_f64(D1, k[4]);
        D1 ^= camellia_f64(D2, k[5]);
        D1 = camellia_fl(D1, ke[0]);
        D2 = camellia_flinv(D2, ke[1]);
        D2 ^= camellia_f64(D1, k[6]);
        D1 ^= camellia_f64(D2, k[7]);
        D2 ^= camellia_f64(D1, k[8]);
        D1 ^= camellia_f64(D2, k[9]);
        D2 ^= camellia_f64(D1, k[10]);
        D1 ^= camellia_f64(D2, k[11]);
        D1 = camellia_fl(D1, ke[2]);
        D2 = camellia_flinv(D2, ke[3]);
        D2 ^= camellia_f64(D1, k[12]);
        D1 ^= camellia_f64(D2, k[13]);
        D2 ^= camellia_f64(D1, k[14]);
        D1 ^= camellia_f64(D2, k[15]);
        D2 ^= camellia_f64(D1, k[16]);
        D1 ^= camellia_f64(D2, k[17]);
        D1 = camellia_fl(D1, ke[4]);
        D2 = camellia_flinv(D2, ke[5]);
        D2 ^= camellia_f64(D1, k[18]);
        D1 ^= camellia_f64(D2, k[19]);
        D2 ^= camellia_f64(D1, k[20]);
        D1 ^= camellia_f64(D2, k[21]);
        D2 ^= camellia_f64(D1, k[22]);
        D1 ^= camellia_f64(D2, k[23]);
    }

    D2 ^= kw[2];
    D1 ^= kw[3];
    (void)store_block_be(output, D1, D2);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Camellia Decrypt Block (RFC 3713: reverse subkey order)
 *
 * @param[in] key The key value.
 * @param[in] data The data value.
 * @param[out] output The output value.
 * @param[in] type The type value.
 * @return The return value.
*/
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
noxtls_return_t noxtls_camellia_decrypt_block_internal(const uint8_t* key, const uint8_t* data, uint8_t* output, noxtls_camellia_type_t type)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint64_t kw[4];
    uint64_t ke[6];
    uint64_t k[24];
    uint64_t D1 = 0ULL;
    uint64_t D2 = 0ULL;
    uint64_t kw_dec[4];
    /* Full init so analyzers see ke_dec[4..5] defined; 128-bit Camellia only uses ke_dec[0..3]. */
    uint64_t ke_dec[6] = { 0 };
    uint64_t k_dec[24];
    uint32_t i = 0U;

    if ((key == NULL) || (data == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_camellia_key_schedule(key, kw, ke, k, type);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    /* Decryption: swap subkeys per RFC 2.3.3 */
    kw_dec[0] = kw[2];
    kw_dec[1] = kw[3];
    kw_dec[2] = kw[0];
    kw_dec[3] = kw[1];
    if (type == NOXTLS_CAMELLIA_128_BIT) {
        ke_dec[0] = ke[3];
        ke_dec[1] = ke[2];
        ke_dec[2] = ke[1];
        ke_dec[3] = ke[0];
        for (i = 0U; i < 18U; i += 1U) { k_dec[i] = k[17U - i]; }  /* k1<->k18: k_dec[0]=k18, k_dec[17]=k1 */
    } else {
        ke_dec[0] = ke[5];
        ke_dec[1] = ke[4];
        ke_dec[2] = ke[3];
        ke_dec[3] = ke[2];
        ke_dec[4] = ke[1];
        ke_dec[5] = ke[0];
        for (i = 0U; i < 24U; i += 1U) { k_dec[i] = k[23U - i]; }
    }

    (void)load_block_be(data, &D1, &D2);
    D1 ^= kw_dec[0];
    D2 ^= kw_dec[1];

    if (type == NOXTLS_CAMELLIA_128_BIT) {
        D2 ^= camellia_f64(D1, k_dec[0]);
        D1 ^= camellia_f64(D2, k_dec[1]);
        D2 ^= camellia_f64(D1, k_dec[2]);
        D1 ^= camellia_f64(D2, k_dec[3]);
        D2 ^= camellia_f64(D1, k_dec[4]);
        D1 ^= camellia_f64(D2, k_dec[5]);
        D1 = camellia_fl(D1, ke_dec[0]);
        D2 = camellia_flinv(D2, ke_dec[1]);
        D2 ^= camellia_f64(D1, k_dec[6]);
        D1 ^= camellia_f64(D2, k_dec[7]);
        D2 ^= camellia_f64(D1, k_dec[8]);
        D1 ^= camellia_f64(D2, k_dec[9]);
        D2 ^= camellia_f64(D1, k_dec[10]);
        D1 ^= camellia_f64(D2, k_dec[11]);
        D1 = camellia_fl(D1, ke_dec[2]);
        D2 = camellia_flinv(D2, ke_dec[3]);
        D2 ^= camellia_f64(D1, k_dec[12]);
        D1 ^= camellia_f64(D2, k_dec[13]);
        D2 ^= camellia_f64(D1, k_dec[14]);
        D1 ^= camellia_f64(D2, k_dec[15]);
        D2 ^= camellia_f64(D1, k_dec[16]);
        D1 ^= camellia_f64(D2, k_dec[17]);
    } else {
        D2 ^= camellia_f64(D1, k_dec[0]);
        D1 ^= camellia_f64(D2, k_dec[1]);
        D2 ^= camellia_f64(D1, k_dec[2]);
        D1 ^= camellia_f64(D2, k_dec[3]);
        D2 ^= camellia_f64(D1, k_dec[4]);
        D1 ^= camellia_f64(D2, k_dec[5]);
        D1 = camellia_fl(D1, ke_dec[0]);
        D2 = camellia_flinv(D2, ke_dec[1]);
        D2 ^= camellia_f64(D1, k_dec[6]);
        D1 ^= camellia_f64(D2, k_dec[7]);
        D2 ^= camellia_f64(D1, k_dec[8]);
        D1 ^= camellia_f64(D2, k_dec[9]);
        D2 ^= camellia_f64(D1, k_dec[10]);
        D1 ^= camellia_f64(D2, k_dec[11]);
        D1 = camellia_fl(D1, ke_dec[2]);
        D2 = camellia_flinv(D2, ke_dec[3]);
        D2 ^= camellia_f64(D1, k_dec[12]);
        D1 ^= camellia_f64(D2, k_dec[13]);
        D2 ^= camellia_f64(D1, k_dec[14]);
        D1 ^= camellia_f64(D2, k_dec[15]);
        D2 ^= camellia_f64(D1, k_dec[16]);
        D1 ^= camellia_f64(D2, k_dec[17]);
        D1 = camellia_fl(D1, ke_dec[4]);
        D2 = camellia_flinv(D2, ke_dec[5]);
        D2 ^= camellia_f64(D1, k_dec[18]);
        D1 ^= camellia_f64(D2, k_dec[19]);
        D2 ^= camellia_f64(D1, k_dec[20]);
        D1 ^= camellia_f64(D2, k_dec[21]);
        D2 ^= camellia_f64(D1, k_dec[22]);
        D1 ^= camellia_f64(D2, k_dec[23]);
    }

    D2 ^= kw_dec[2];
    D1 ^= kw_dec[3];
    (void)store_block_be(output, D1, D2);
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Camellia Encrypt Data
 *
 * @param[in] key The key value.
 * @param[in] data The data value.
 * @param[in] data_len The data length value.
 * @param[in] iv The iv value.
 * @param[out] output The output value.
 * @param[in] type The type value.
 * @param[in] mode The mode value.
 * @return The return value.
*/
noxtls_return_t noxtls_camellia_encrypt_data(const uint8_t* key,
                          const uint8_t* data,
                          uint32_t data_len,
                          const uint8_t * iv,
                          uint8_t* output,
                          noxtls_camellia_type_t type,
                          noxtls_camellia_mode_t mode)
{
    {
        uint32_t mode_u = (uint32_t)mode;
        switch (mode_u) {
            case (uint32_t)NOXTLS_CAMELLIA_ECB:
                return noxtls_camellia_encrypt_ecb(key, data, data_len, iv, output, type);
            case (uint32_t)NOXTLS_CAMELLIA_CBC:
                return noxtls_camellia_encrypt_cbc(key, data, data_len, iv, output, type);
            case (uint32_t)NOXTLS_CAMELLIA_CTR:
                return noxtls_camellia_encrypt_ctr(key, data, data_len, iv, output, type);
            case (uint32_t)NOXTLS_CAMELLIA_CFB:
                return noxtls_camellia_encrypt_cfb(key, data, data_len, iv, output, type);
            case (uint32_t)NOXTLS_CAMELLIA_OFB:
                return noxtls_camellia_encrypt_ofb(key, data, data_len, iv, output, type);
            default:
                return NOXTLS_RETURN_INVALID_MODE;
        }
    }
}

/**
 * @brief Camellia Decrypt Data
 *
 * @param[in] key The key value.
 * @param[in] data The data value.
 * @param[in] data_len The data length value.
 * @param[in] iv The iv value.
 * @param[out] output The output value.
 * @param[in] type The type value.
 * @param[in] mode The mode value.
 * @return The return value.
*/
noxtls_return_t noxtls_camellia_decrypt_data(const uint8_t* key,
                          const uint8_t* data,
                          uint32_t data_len,
                          const uint8_t * iv,
                          uint8_t* output,
                          noxtls_camellia_type_t type,
                          noxtls_camellia_mode_t mode)
{
    {
        uint32_t mode_u = (uint32_t)mode;
        switch (mode_u) {
            case (uint32_t)NOXTLS_CAMELLIA_ECB:
                return noxtls_camellia_decrypt_ecb(key, data, data_len, iv, output, type);
            case (uint32_t)NOXTLS_CAMELLIA_CBC:
                return noxtls_camellia_decrypt_cbc(key, data, data_len, iv, output, type);
            case (uint32_t)NOXTLS_CAMELLIA_CTR:
                return noxtls_camellia_decrypt_ctr(key, data, data_len, iv, output, type);
            case (uint32_t)NOXTLS_CAMELLIA_CFB:
                return noxtls_camellia_decrypt_cfb(key, data, data_len, iv, output, type);
            case (uint32_t)NOXTLS_CAMELLIA_OFB:
                return noxtls_camellia_decrypt_ofb(key, data, data_len, iv, output, type);
            default:
                return NOXTLS_RETURN_INVALID_MODE;
        }
    }
}

/**
 * @brief Get the key size in bytes.
 *
 * @param[in] type The type value.
 * @return The key size in bytes.
 */
static uint8_t camellia_key_size_bytes(noxtls_camellia_type_t type)
{
    {
        uint32_t type_u = (uint32_t)type;
        switch (type_u) {
        case (uint32_t)NOXTLS_CAMELLIA_128_BIT:
            return 16;
        case (uint32_t)NOXTLS_CAMELLIA_192_BIT:
            return 24;
        case (uint32_t)NOXTLS_CAMELLIA_256_BIT:
            return 32;
        default:
            return 0U;
    }
    }
}

/**
 * @brief Increment the counter.
 *
 * @param[in] counter The counter value.
 * @return void
 */
static void camellia_counter_inc(uint8_t counter[NOXTLS_CAMELLIA_BLOCK_LENGTH])
{
    int i = 0;
    for (i = (int)NOXTLS_CAMELLIA_BLOCK_LENGTH - 1; i >= 0; i -= 1) {
        counter[i] = (uint8_t)(counter[i] + 1U);
        if (counter[i] != 0U) {
            break;
        }
    }
}

/**
 * @brief Initialize the Camellia context.
 *
 * @param[out] ctx The context value.
 * @param[in] key The key value.
 * @param[in] iv The iv value.
 * @param[in] type The type value.
 * @param[in] mode The mode value.
 * @param[in] op The operation value.
 * @return The return value.
*/
noxtls_return_t noxtls_camellia_init(noxtls_camellia_context_t *ctx,
                  const uint8_t *key,
                  const uint8_t *iv,
                  noxtls_camellia_type_t type,
                  noxtls_camellia_mode_t mode,
                  noxtls_camellia_operation_t op)
{
    if ((ctx == NULL) || (key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero((ctx), sizeof(*(ctx)));
    ctx->type = type;
    ctx->mode = mode;
    ctx->op = op;
    ctx->key_len = camellia_key_size_bytes(type);
    if (ctx->key_len == 0U) {
        return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }
    noxtls_copy_u8(ctx->key, sizeof(ctx->key), key, (size_t)ctx->key_len);

    {
        uint32_t mode_u = (uint32_t)mode;
        switch (mode_u) {
        case (uint32_t)NOXTLS_CAMELLIA_ECB:
            break;
        case (uint32_t)NOXTLS_CAMELLIA_CBC:
            if (iv != NULL) {
                noxtls_copy_u8(ctx->feedback, sizeof(ctx->feedback), iv, (size_t)NOXTLS_CAMELLIA_BLOCK_LENGTH);
            } else {
                /* MISRA 15.7: final else path */
                noxtls_secure_zero((ctx->feedback), (size_t)(NOXTLS_CAMELLIA_BLOCK_LENGTH));
            }
            break;
        case (uint32_t)NOXTLS_CAMELLIA_CTR:
        case (uint32_t)NOXTLS_CAMELLIA_CFB:
        case (uint32_t)NOXTLS_CAMELLIA_OFB:
            if (iv == NULL) {
                return NOXTLS_RETURN_INVALID_PARAM;
            }
            noxtls_copy_u8(ctx->feedback, sizeof(ctx->feedback), iv, (size_t)NOXTLS_CAMELLIA_BLOCK_LENGTH);
            ctx->partial_len = NOXTLS_CAMELLIA_BLOCK_LENGTH;
            break;
        default:
            return NOXTLS_RETURN_INVALID_MODE;
    }
    }

    ctx->initialized = 1U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Update the Camellia context.
 *
 * @param[in] ctx The context value.
 * @param[in] input The input value.
 * @param[in] input_len The input length value.
 * @param[out] output The output value.
 * @param[out] output_len The output length value.
 * @return The return value.
*/
noxtls_return_t noxtls_camellia_update(noxtls_camellia_context_t *ctx,
                    const uint8_t *input,
                    uint32_t input_len,
                    uint8_t *output,
                    uint32_t *output_len)
{
    uint32_t produced = 0U;
    uint32_t i = 0U;
    const uint8_t *in_ptr = input;
    uint32_t in_left = input_len;

    if ((ctx == NULL) || (output_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    *output_len = 0U;

    if (ctx->initialized == 0U) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
    if ((in_left > 0U) && ((in_ptr == NULL) || (output == NULL))) {
        return NOXTLS_RETURN_NULL;
    }
    if (in_left == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }

    if ((ctx->mode == NOXTLS_CAMELLIA_ECB) || (ctx->mode == NOXTLS_CAMELLIA_CBC)) {
            while (in_left > 0U) {
                uint32_t need = (uint32_t)NOXTLS_CAMELLIA_BLOCK_LENGTH - ctx->partial_len;
                uint32_t take = (uint32_t)((in_left < need) ? in_left : need);
                noxtls_copy_u8(&ctx->partial[ctx->partial_len], sizeof(ctx->partial) - (size_t)(ctx->partial_len), in_ptr, (size_t)take);
                ctx->partial_len = (uint8_t)(ctx->partial_len + take);
                in_ptr = &in_ptr[take];
                in_left -= take;

                if (ctx->partial_len == NOXTLS_CAMELLIA_BLOCK_LENGTH) {
                    if (ctx->mode == NOXTLS_CAMELLIA_ECB) {
                        if (ctx->op == NOXTLS_CAMELLIA_OP_ENCRYPT) {
                            if (noxtls_camellia_encrypt_block_internal(ctx->key, ctx->partial, &output[produced], ctx->type) != NOXTLS_RETURN_SUCCESS) {
                                return NOXTLS_RETURN_FAILED;
                            }
                        } else {
                            /* MISRA 15.7: final else path */
                            if (noxtls_camellia_decrypt_block_internal(ctx->key, ctx->partial, &output[produced], ctx->type) != NOXTLS_RETURN_SUCCESS) {
                                return NOXTLS_RETURN_FAILED;
                            }
                        }
                    } else {
                        if (ctx->op == NOXTLS_CAMELLIA_OP_ENCRYPT) {
                            uint8_t block[NOXTLS_CAMELLIA_BLOCK_LENGTH];
                            for (i = 0U; i < NOXTLS_CAMELLIA_BLOCK_LENGTH; i += 1U) {
                                block[i] = (uint8_t)(ctx->partial[i] ^ ctx->feedback[i]);
                            }
                            if (noxtls_camellia_encrypt_block_internal(ctx->key, block, &output[produced], ctx->type) != NOXTLS_RETURN_SUCCESS) {
                                return NOXTLS_RETURN_FAILED;
                            }
                            noxtls_copy_u8(ctx->feedback, sizeof(ctx->feedback), &output[produced], (size_t)NOXTLS_CAMELLIA_BLOCK_LENGTH);
                        } else {
                            /* MISRA 15.7: final else path */
                            uint8_t block[NOXTLS_CAMELLIA_BLOCK_LENGTH];
                            if (noxtls_camellia_decrypt_block_internal(ctx->key, ctx->partial, block, ctx->type) != NOXTLS_RETURN_SUCCESS) {
                                return NOXTLS_RETURN_FAILED;
                            }
                            for (i = 0U; i < NOXTLS_CAMELLIA_BLOCK_LENGTH; i += 1U) {
                                output[produced + i] = (uint8_t)(block[i] ^ ctx->feedback[i]);
                            }
                            noxtls_copy_u8(ctx->feedback, sizeof(ctx->feedback), ctx->partial, (size_t)NOXTLS_CAMELLIA_BLOCK_LENGTH);
                        }
                    }
                    produced += NOXTLS_CAMELLIA_BLOCK_LENGTH;
                    ctx->partial_len = 0U;
                }
            }
    } else if ((ctx->mode == NOXTLS_CAMELLIA_CTR) || (ctx->mode == NOXTLS_CAMELLIA_CFB) || (ctx->mode == NOXTLS_CAMELLIA_OFB)) {
            while (in_left > 0U) {
                if (ctx->partial_len == NOXTLS_CAMELLIA_BLOCK_LENGTH) {
                    if (ctx->mode == NOXTLS_CAMELLIA_CTR) {
                        if (noxtls_camellia_encrypt_block_internal(ctx->key, ctx->feedback, ctx->partial, ctx->type) != NOXTLS_RETURN_SUCCESS) {
                            return NOXTLS_RETURN_FAILED;
                        }
                        camellia_counter_inc(ctx->feedback);
                    } else if (ctx->mode == NOXTLS_CAMELLIA_CFB) {
                        if (noxtls_camellia_encrypt_block_internal(ctx->key, ctx->feedback, ctx->partial, ctx->type) != NOXTLS_RETURN_SUCCESS) {
                            return NOXTLS_RETURN_FAILED;
                        }
                    } else {
                        /* MISRA 15.7: final else path */
                        if (noxtls_camellia_encrypt_block_internal(ctx->key, ctx->feedback, ctx->partial, ctx->type) != NOXTLS_RETURN_SUCCESS) {
                            return NOXTLS_RETURN_FAILED;
                        }
                        noxtls_copy_u8(ctx->feedback, sizeof(ctx->feedback), ctx->partial, (size_t)NOXTLS_CAMELLIA_BLOCK_LENGTH);
                    }
                    ctx->partial_len = 0U;
                }

                {
                    uint32_t available = (uint32_t)NOXTLS_CAMELLIA_BLOCK_LENGTH - ctx->partial_len;
                    uint32_t take = (uint32_t)((in_left < available) ? in_left : available);
                    for (i = 0U; i < take; i += 1U) {
                        uint8_t out_byte = (uint8_t)(in_ptr[i] ^ ctx->partial[ctx->partial_len + i]);
                        output[produced + i] = out_byte;
                        if (ctx->mode == NOXTLS_CAMELLIA_CFB) {
                            {
            uint8_t fb_tmp[NOXTLS_CAMELLIA_BLOCK_LENGTH];
            noxtls_copy_u8(fb_tmp, sizeof(fb_tmp), &ctx->feedback[1], (size_t)(NOXTLS_CAMELLIA_BLOCK_LENGTH - 1U));
            noxtls_copy_u8(ctx->feedback, sizeof(ctx->feedback), fb_tmp, (size_t)(NOXTLS_CAMELLIA_BLOCK_LENGTH - 1U));
        }
                            ctx->feedback[NOXTLS_CAMELLIA_BLOCK_LENGTH - 1U] = (ctx->op == NOXTLS_CAMELLIA_OP_ENCRYPT) ? out_byte : in_ptr[i];
                        }
                    }
                    in_ptr = &in_ptr[take];
                    in_left -= take;
                    produced += take;
                    ctx->partial_len = (uint8_t)(ctx->partial_len + take);
                }
            }
    } else {
         /* MISRA 15.7: final else path */
            return NOXTLS_RETURN_INVALID_MODE;
    }

    *output_len = produced;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Finalize the Camellia context.
 *
 * @param[in] ctx The context value.
 * @param[out] output The output value.
 * @param[out] output_len The output length value.
 * @return The return value.
*/
noxtls_return_t noxtls_camellia_final(noxtls_camellia_context_t *ctx,
                   uint8_t *output,
                   uint32_t *output_len)
{
    if ((ctx == NULL) || (output_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    *output_len = 0U;

    if (ctx->initialized == 0U) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }

    if ((ctx->mode == NOXTLS_CAMELLIA_CTR) || (ctx->mode == NOXTLS_CAMELLIA_CFB) || (ctx->mode == NOXTLS_CAMELLIA_OFB)) {
        ctx->initialized = 0U;
        return NOXTLS_RETURN_SUCCESS;
    }

    if (ctx->op == NOXTLS_CAMELLIA_OP_DECRYPT) {
        if (ctx->partial_len != 0U) {
            return NOXTLS_RETURN_INVALID_BLOCK_SIZE;
        }
        ctx->initialized = 0U;
        return NOXTLS_RETURN_SUCCESS;
    }

    if (ctx->partial_len > 0U) {
        uint8_t block[NOXTLS_CAMELLIA_BLOCK_LENGTH];
        uint32_t i = 0U;

        if (output == NULL) {
            return NOXTLS_RETURN_NULL;
        }

        noxtls_secure_zero((block), sizeof(block));
        noxtls_copy_u8(block, sizeof(block), ctx->partial, (size_t)ctx->partial_len);

        if (ctx->mode == NOXTLS_CAMELLIA_ECB) {
            if (noxtls_camellia_encrypt_block_internal(ctx->key, block, output, ctx->type) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_FAILED;
            }
        } else if (ctx->mode == NOXTLS_CAMELLIA_CBC) {
            for (i = 0U; i < NOXTLS_CAMELLIA_BLOCK_LENGTH; i += 1U) {
                block[i] ^= ctx->feedback[i];
            }
            if (noxtls_camellia_encrypt_block_internal(ctx->key, block, output, ctx->type) != NOXTLS_RETURN_SUCCESS) {
                return NOXTLS_RETURN_FAILED;
            }
        } else {
             /* MISRA 15.7: final else path */
            return NOXTLS_RETURN_INVALID_MODE;
        }

        *output_len = NOXTLS_CAMELLIA_BLOCK_LENGTH;
    }

    ctx->initialized = 0U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Camellia Self Test (RFC 3713 Appendix A vectors)
 *
 * @return The return value.
*/
noxtls_return_t noxtls_camellia_self_test(void)
{
    uint8_t key[32];
    uint8_t pt[16];
    uint8_t ct[16];
    uint8_t out[16];
    uint8_t dec[16];

    /* 128-bit key */
    noxtls_secure_zero((key), sizeof(key));
    key[0] = 0x01U; key[1] = 0x23U; key[2] = 0x45U; key[3] = 0x67U;
    key[4] = 0x89U; key[5] = 0xabU; key[6] = 0xcdU; key[7] = 0xefU;
    key[8] = 0xfeU; key[9] = 0xdcU; key[10] = 0xbaU; key[11] = 0x98U;
    key[12] = 0x76U; key[13] = 0x54U; key[14] = 0x32U; key[15] = 0x10U;
    noxtls_copy_u8(pt, sizeof(pt), key, 16U);
    (void)noxtls_camellia_encrypt_block_internal(key, pt, out, NOXTLS_CAMELLIA_128_BIT);
    ct[0] = 0x67U; ct[1] = 0x67U; ct[2] = 0x31U; ct[3] = 0x38U;
    ct[4] = 0x54U; ct[5] = 0x96U; ct[6] = 0x69U; ct[7] = 0x73U;
    ct[8] = 0x08U; ct[9] = 0x57U; ct[10] = 0x06U; ct[11] = 0x56U;
    ct[12] = 0x48U; ct[13] = 0xeaU; ct[14] = 0xbeU; ct[15] = 0x43U;
    if (memcmp(out, ct, (size_t)16U) != 0) {
        (void)camellia_print_block_hex(NULL, ct);
        (void)camellia_print_block_hex(NULL, out);
        return NOXTLS_RETURN_FAILED;
    }

    /* 192-bit key */
    key[16] = 0x00U; key[17] = 0x11U; key[18] = 0x22U; key[19] = 0x33U;
    key[20] = 0x44U; key[21] = 0x55U; key[22] = 0x66U; key[23] = 0x77U;
    (void)noxtls_camellia_encrypt_block_internal(key, pt, out, NOXTLS_CAMELLIA_192_BIT);
    ct[0] = 0xb4U; ct[1] = 0x99U; ct[2] = 0x34U; ct[3] = 0x01U;
    ct[4] = 0xb3U; ct[5] = 0xe9U; ct[6] = 0x96U; ct[7] = 0xf8U;
    ct[8] = 0x4eU; ct[9] = 0xe5U; ct[10] = 0xceU; ct[11] = 0xe7U;
    ct[12] = 0xd7U; ct[13] = 0x9bU; ct[14] = 0x09U; ct[15] = 0xb9U;
    if (memcmp(out, ct, (size_t)16U) != 0) {
        (void)camellia_print_block_hex(NULL, ct);
        (void)camellia_print_block_hex(NULL, out);
        return NOXTLS_RETURN_FAILED;
    }

    /* 256-bit key */
    key[24] = 0x88U; key[25] = 0x99U; key[26] = 0xaaU; key[27] = 0xbbU;
    key[28] = 0xccU; key[29] = 0xddU; key[30] = 0xeeU; key[31] = 0xffU;
    (void)noxtls_camellia_encrypt_block_internal(key, pt, out, NOXTLS_CAMELLIA_256_BIT);
    ct[0] = 0x9aU; ct[1] = 0xccU; ct[2] = 0x23U; ct[3] = 0x7dU;
    ct[4] = 0xffU; ct[5] = 0x16U; ct[6] = 0xd7U; ct[7] = 0x6cU;
    ct[8] = 0x20U; ct[9] = 0xefU; ct[10] = 0x7cU; ct[11] = 0x91U;
    ct[12] = 0x9eU; ct[13] = 0x3aU; ct[14] = 0x75U; ct[15] = 0x09U;
    if (memcmp(out, ct, (size_t)16U) != 0) {
        (void)camellia_print_block_hex(NULL, ct);
        (void)camellia_print_block_hex(NULL, out);
        return NOXTLS_RETURN_FAILED;
    }

    /* Decrypt roundtrip: decrypt 256-bit ciphertext and compare to original plaintext */
    {
        const uint8_t *data = out;
        uint8_t *output = dec;
        (void)noxtls_camellia_decrypt_block_internal(key, data, output, NOXTLS_CAMELLIA_256_BIT);
    }
    if (memcmp(dec, pt, (size_t)16U) != 0) {
        (void)camellia_print_block_hex(NULL, pt);
        (void)camellia_print_block_hex(NULL, dec);
        return NOXTLS_RETURN_FAILED;
    }

    return NOXTLS_RETURN_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_FEATURE_CAMELLIA */
