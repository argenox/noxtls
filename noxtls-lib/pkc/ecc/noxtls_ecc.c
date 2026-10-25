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
* File:    noxtls_ecc.c
* Summary: Elliptic Curve Cryptography (ECC) Base Implementation
*
*
*****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/noxtls_memory.h"
#include "common/noxtls_ct.h"
#include "common/noxtls_memory_compat.h"
#include "noxtls_ecc.h"

#if NOXTLS_FEATURE_ECC

#if defined(_MSC_VER)
/* MSVC has no weak function attribute. Keep the fallback separately named
 * so a port or regression can supply the strong service hook. */
void noxtls_ecc_default_yield(void) { }
#if defined(_M_IX86)
#pragma comment(linker, "/alternatename:_noxtls_ecc_yield=_noxtls_ecc_default_yield")
#else
#pragma comment(linker, "/alternatename:noxtls_ecc_yield=noxtls_ecc_default_yield")
#endif
#else
#if defined(__GNUC__) || defined(__clang__)
void noxtls_ecc_yield(void) __attribute__((weak));
#endif
void noxtls_ecc_yield(void) { }
#endif
#include "pkc/rsa/noxtls_bignum.h"
#include "drbg/noxtls_drbg.h"
#include "pkc/noxtls_pkc_rng.h"
#include "noxtls_common.h"
#include "common/noxtls_ct.h"

/* The read-only P-256 generator table and the low-RAM verify path are windowed algorithms:
 * a ladder-only build (NOXTLS_ECC_POINT_MUL_WINDOW_SIZE < 2) uses neither. */
#if (NOXTLS_ECC_POINT_MUL_WINDOW_SIZE >= 2) && NOXTLS_ECC_P256_FLASH_PRECOMPUTE
#define ECC_P256_USE_FLASH_TABLE 1
#else
#define ECC_P256_USE_FLASH_TABLE 0
#endif
#if ECC_P256_USE_FLASH_TABLE && NOXTLS_ECC_P256_LOW_RAM_VERIFY
#define ECC_P256_USE_LOW_RAM_VERIFY 1
#else
#define ECC_P256_USE_LOW_RAM_VERIFY 0
#endif

#if ECC_P256_USE_FLASH_TABLE
#include "noxtls_p256_precomputed_g.h"
#endif

/* Out-of-line helpers keep large generic-curve temporaries out of the P-256 hot-path frames. */
#if defined(__GNUC__) || defined(__clang__)
#define ECC_NOINLINE __attribute__((noinline))
#else
#define ECC_NOINLINE
#endif

/* Disable verbose stderr debug prints in this file. */
#define NOXTLS_ECC_TRACE(...) ((void)0)

#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
#if defined(__GNUC__) || defined(__clang__)
#define NOXTLS_ECC_DIAG_WEAK __attribute__((weak))
#else
#define NOXTLS_ECC_DIAG_WEAK
#endif

/*
 * Test applications may override this with a monotonic microsecond timer.
 * The default keeps NoxTLS portable and adds no timing dependency to products.
 */
NOXTLS_ECC_DIAG_WEAK uint64_t noxtls_ecc_diagnostic_time_us(void)
{
    return 0U;
}

static uint32_t noxtls_ecc_diagnostic_elapsed_us(uint64_t start_us)
{
    const uint64_t end_us = noxtls_ecc_diagnostic_time_us();

    return (start_us != 0U && end_us >= start_us) ?
        (uint32_t)(end_us - start_us) : 0U;
}
#endif

#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
volatile uint32_t noxtls_ecc_keygen_last_init_us = 0U;
volatile uint32_t noxtls_ecc_keygen_last_private_us = 0U;
volatile uint32_t noxtls_ecc_keygen_last_multiply_us = 0U;
volatile uint32_t noxtls_ecc_keygen_last_validate_us = 0U;
volatile uint32_t noxtls_ecc_keygen_last_total_us = 0U;
volatile uint32_t noxtls_ecc_point_multiply_last_accel_us = 0U;
volatile uint32_t noxtls_ecc_point_multiply_last_precompute_us = 0U;
volatile uint32_t noxtls_ecc_point_multiply_last_comb_us = 0U;
volatile uint32_t noxtls_ecc_point_multiply_last_total_us = 0U;
volatile uint32_t noxtls_ecc_point_multiply_last_used_cache = 0U;
volatile uint32_t noxtls_ecc_point_multiply_last_used_accel = 0U;
#endif

/* PTS status ABI. Values report control-flow only and never key material. */
#if NOXTLS_ECC_STATUS_WORDS
volatile int32_t noxtls_ecc_keygen_last_rc = (int32_t)NOXTLS_RETURN_SUCCESS;
volatile uint32_t noxtls_ecc_keygen_last_stage = 0U;
volatile int32_t noxtls_ecc_keygen_last_entropy_rc = (int32_t)NOXTLS_RETURN_SUCCESS;
volatile int32_t noxtls_ecc_keygen_last_multiply_rc = (int32_t)NOXTLS_RETURN_SUCCESS;
volatile uint32_t noxtls_ecc_keygen_last_drbg_type = DRBG_AES256;
volatile int32_t noxtls_ecc_keyinit_last_rc = (int32_t)NOXTLS_RETURN_SUCCESS;
volatile uint32_t noxtls_ecc_keyinit_last_stage = 0U;
#endif
/* nRF52's ECB peripheral is AES-128 only. A CTR-DRBG does not require
 * AES-256; select an enabled primitive for constrained builds. */
#if NOXTLS_FEATURE_AES_256
#define NOXTLS_ECC_KEYGEN_DRBG_TYPE     DRBG_AES256
#else
#define NOXTLS_ECC_KEYGEN_DRBG_TYPE     DRBG_AES128
#endif
/* Upper bound on private-scalar draws (d == 0 / d >= n is rejected and
 * redrawn; the probability of needing more than one draw is negligible). */
#ifndef NOXTLS_ECC_KEYGEN_MAX_ATTEMPTS
#define NOXTLS_ECC_KEYGEN_MAX_ATTEMPTS  64U
#endif

/**
 * @brief Generate bits using the DRBG
 *
 * @param out The output buffer
 * @param requested_bits The number of bits to generate
 * @return The return value
 */
static noxtls_return_t ecc_keygen_drbg_generate_bits(uint8_t *out, uint32_t requested_bits)
{
    noxtls_return_t rc;

    if(out == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    NOXTLS_ECC_STATUS_SET(noxtls_ecc_keygen_last_drbg_type, NOXTLS_ECC_KEYGEN_DRBG_TYPE);
    rc = noxtls_pkc_rng_generate(NOXTLS_PKC_RNG_SLOT_ECC, out, requested_bits);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_ECC_STATUS_SET(noxtls_ecc_keygen_last_entropy_rc, (int32_t)rc);
    }
    return rc;
}

/**
 * @brief Point multiply acceleration port
 *
 * @param result The result
 * @param scalar The scalar
 * @param point The point
 * @param curve The curve
 */
#include "noxtls_ecc_accel_port.h"
static int ecc_curve_is_secp256r1(const ecc_curve_params_t *curve);
static int ecc_modulus_is_secp256r1(const uint8_t *p, uint32_t size);
static int ecc_modulus_is_secp384r1(const uint8_t *p, uint32_t size);
static int ecc_modulus_is_secp521r1(const uint8_t *p, uint32_t size);
static void ecc_fe_inv_fermat(uint8_t *out, const uint8_t *a, const uint8_t *p, uint32_t size, uint32_t field);
#define ECC_FE_P384 1U
#define ECC_FE_P521 2U

/* Modular inverse for prime field using Fermat: a^(p-2) mod p */
/**
 * @brief Modular inverse for prime field using Fermat: a^(p-2) mod p
 *
 * @param result Result of the modular inverse
 * @param a Value to invert
 * @param p Modulus
 * @param size Size of the modulus
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if result is NULL, NOXTLS_RETURN_FAILED if allocation fails
 */
static noxtls_return_t ecc_mod_inv_prime(uint8_t *result,
                                         const uint8_t *a,
                                         const uint8_t *p,
                                         uint32_t size)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    int verified = 0;

    if((result == NULL) || (a == NULL) || (p == NULL) || (size == 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    if(size > ECC_MAX_KEY_SIZE) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Shared storage is opt-in and requires external serialization. */
#if NOXTLS_ECC_SHARED_SCRATCH
    static
#endif
    struct {
        uint8_t p_minus_2[ECC_MAX_KEY_SIZE];
        uint8_t two[ECC_MAX_KEY_SIZE];
        uint8_t a_mod[ECC_MAX_KEY_SIZE];
        uint8_t prod[ECC_MAX_KEY_SIZE * 2U];
        uint8_t check[ECC_MAX_KEY_SIZE];
        uint8_t one[ECC_MAX_KEY_SIZE];
    } scratch;
    noxtls_secure_zero(&scratch, sizeof(scratch));

    /* Every bignum status is checked: an allocation failure inside the
     * reduction or the verification product must never be mistaken for a
     * valid inverse (or for a non-invertible input). */
    rc = noxtls_bn_mod(scratch.a_mod, a, size, p, size);
    if((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_bn_is_zero(scratch.a_mod, size) != 0)) {
        rc = NOXTLS_RETURN_FAILED;
    }

    if(rc == NOXTLS_RETURN_SUCCESS) {
        scratch.two[size - 1U] = 0x02U;
        scratch.one[size - 1U] = 0x01U;
        (void)noxtls_bn_copy(scratch.p_minus_2, p, size);
        (void)noxtls_bn_sub(scratch.p_minus_2, scratch.p_minus_2, scratch.two, size);

        /* The P-256 inverse is already Fermat exponentiation in the bignum
         * backend. Pass the per-call service hook through its public loop
         * boundaries instead of blocking a cooperative worker for the whole
         * power. Other prime fields retain their generic inverse fast path. */
        noxtls_return_t inverse_rc;
        if(ecc_modulus_is_secp384r1(p, size) != 0) {
            ecc_fe_inv_fermat(result, scratch.a_mod, p, size, ECC_FE_P384);
            inverse_rc = NOXTLS_RETURN_SUCCESS;
        } else if(ecc_modulus_is_secp521r1(p, size) != 0) {
            ecc_fe_inv_fermat(result, scratch.a_mod, p, size, ECC_FE_P521);
            inverse_rc = NOXTLS_RETURN_SUCCESS;
        } else if(ecc_modulus_is_secp256r1(p, size) != 0) {
            inverse_rc = noxtls_bn_mod_exp_service(result, scratch.a_mod,
                scratch.p_minus_2, size, p, size, noxtls_ecc_yield);
        } else {
            inverse_rc = noxtls_bn_mod_inv(result, scratch.a_mod, size, p, size);
        }
        if(inverse_rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_bn_mul(scratch.prod, scratch.a_mod, size, result, size);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                rc = noxtls_bn_mod(scratch.check, scratch.prod, size * 2U, p, size);
            }
            if((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_bn_cmp(scratch.check, scratch.one, size) == 0)) {
                verified = 1;
            }
        }
    }

    if((rc == NOXTLS_RETURN_SUCCESS) && (verified == 0)) {
        /* Fallback for edge cases: Fermat inverse. */
        rc = noxtls_bn_mod_exp_service(result, scratch.a_mod, scratch.p_minus_2, size, p, size, noxtls_ecc_yield);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_bn_mul(scratch.prod, scratch.a_mod, size, result, size);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_bn_mod(scratch.check, scratch.prod, size * 2U, p, size);
        }
        if((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_bn_cmp(scratch.check, scratch.one, size) == 0)) {
            verified = 1;
        }
    }

    if((rc == NOXTLS_RETURN_SUCCESS) && (verified == 0)) {
        rc = noxtls_bn_mod_inv(result, scratch.a_mod, size, p, size);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_bn_mul(scratch.prod, scratch.a_mod, size, result, size);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_bn_mod(scratch.check, scratch.prod, size * 2U, p, size);
        }
        if((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_bn_cmp(scratch.check, scratch.one, size) == 0)) {
            verified = 1;
        }
        if((rc == NOXTLS_RETURN_SUCCESS) && (verified == 0)) {
            rc = NOXTLS_RETURN_FAILED;
        }
    }

    noxtls_secure_zero(&scratch, sizeof(scratch));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(result, (size_t)size);
        if(rc != NOXTLS_RETURN_NOT_ENOUGH_MEMORY) {
            rc = NOXTLS_RETURN_FAILED;
        }
    }
    return rc;
}

/**
 * @brief Check if ECC point multiply uses reference implementation
 *
 * @return int 1 if using reference implementation, 0 otherwise
 */
int noxtls_ecc_point_multiply_uses_ref(void)
{
#ifdef NOXTLS_ECC_USE_REF_POINT_MUL
    return 1;
#else
    return 0;
#endif
}

/**
 * @brief Get the point multiplication window size
 * Return configured window size (0 = ladder only, 2+ = windowed precomputation).
 * @return The point multiplication window size
 */
int noxtls_ecc_point_mul_window_size(void)
{
#if NOXTLS_ECC_POINT_MUL_WINDOW_SIZE >= 2
    return (int)NOXTLS_ECC_POINT_MUL_WINDOW_SIZE;
#else
    return 0;
#endif
}

#if NOXTLS_ECC_POINT_MUL_WINDOW_SIZE >= 2
/**
 * @brief Get the point multiplication window size for the curve
 *
 * @param[in] curve The curve
 * @param[in] is_fixed_base Whether the curve is fixed base
 * @return The point multiplication window size
 */
static uint32_t ecc_point_mul_window_size_for_curve(const ecc_curve_params_t *curve, int is_fixed_base)
{
#if NOXTLS_ECC_POINT_MUL_WINDOW_SIZE >= 2
    if(curve != NULL) {
        if(ecc_curve_is_secp256r1(curve) != 0) {
            return (is_fixed_base != 0) ? 5U : 4U;
        }
    }
    return (uint32_t)NOXTLS_ECC_POINT_MUL_WINDOW_SIZE;
#else
    (void)curve;
    (void)is_fixed_base;
    return 0U;
#endif
}
#endif

/**
 * @brief Initialize ECC curve parameters
 *
 * @param curve ECC curve parameters
 * @param curve_type Curve type
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if curve is NULL
 */

#if NOXTLS_ECC_POINT_MUL_WINDOW_SIZE > 0
/**
 * @brief Table length for a window width (Rule 12.2: shift count bounded).
 */
static uint32_t ecc_window_table_len(uint32_t w)
{
    static const uint32_t s_pow2[32] = {
        1U, 2U, 4U, 8U, 16U, 32U, 64U, 128U,
        256U, 512U, 1024U, 2048U, 4096U, 8192U, 16384U, 32768U,
        65536U, 131072U, 262144U, 524288U, 1048576U, 2097152U, 4194304U, 8388608U,
        16777216U, 33554432U, 67108864U, 134217728U, 268435456U, 536870912U,
        1073741824U, 2147483648U
    };
    uint32_t width = w;
    if(width > 31U) {
        width = 31U;
    }
    return s_pow2[width];
}
#endif

/* ------------------------------------------------------------------------------------------
 * Curve parameters: one shared read-only descriptor per enabled curve (SEC 2 v2, RFC 5639,
 * FIPS 186-4). Keys and noxtls_ecc_curve_init() point at these constants; nothing is copied
 * to the heap. A curve disabled with NOXTLS_ECC_ENABLE_<curve>=0 is not linked.
 * ------------------------------------------------------------------------------------------ */
#if NOXTLS_ECC_ENABLE_SECP192R1
static const uint8_t s_ecc_secp192r1_p[24] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFEU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU
};
static const uint8_t s_ecc_secp192r1_a[24] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFEU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFCU
};
static const uint8_t s_ecc_secp192r1_b[24] = {
    0x64U, 0x21U, 0x05U, 0x19U, 0xE5U, 0x9CU, 0x80U, 0xE7U, 0x0FU, 0xA7U, 0xE9U, 0xABU,
    0x72U, 0x24U, 0x30U, 0x49U, 0xFEU, 0xB8U, 0xDEU, 0xECU, 0xC1U, 0x46U, 0xB9U, 0xB1U
};
static const uint8_t s_ecc_secp192r1_n[24] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0x99U, 0xDEU, 0xF8U, 0x36U, 0x14U, 0x6BU, 0xC9U, 0xB1U, 0xB4U, 0xD2U, 0x28U, 0x31U
};
static const ecc_curve_params_t s_ecc_curve_secp192r1 = {
    s_ecc_secp192r1_p, s_ecc_secp192r1_a, s_ecc_secp192r1_b,
    {
        {
            0x18U, 0x8DU, 0xA8U, 0x0EU, 0xB0U, 0x30U, 0x90U, 0xF6U, 0x7CU, 0xBFU, 0x20U, 0xEBU,
            0x43U, 0xA1U, 0x88U, 0x00U, 0xF4U, 0xFFU, 0x0AU, 0xFDU, 0x82U, 0xFFU, 0x10U, 0x12U
        },
        {
            0x07U, 0x19U, 0x2BU, 0x95U, 0xFFU, 0xC8U, 0xDAU, 0x78U, 0x63U, 0x10U, 0x11U, 0xEDU,
            0x6BU, 0x24U, 0xCDU, 0xD5U, 0x73U, 0xF9U, 0x77U, 0xA1U, 0x1EU, 0x79U, 0x48U, 0x11U
        },
        24U
    },
    s_ecc_secp192r1_n, 24U, 24U, NOXTLS_ECC_CURVE_TAG(NOXTLS_ECC_SECP192R1)
};
#endif

#if NOXTLS_ECC_ENABLE_SECP224R1
static const uint8_t s_ecc_secp224r1_p[28] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x01U
};
static const uint8_t s_ecc_secp224r1_a[28] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFEU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFEU
};
static const uint8_t s_ecc_secp224r1_b[28] = {
    0xB4U, 0x05U, 0x0AU, 0x85U, 0x0CU, 0x04U, 0xB3U, 0xABU, 0xF5U, 0x41U, 0x32U, 0x56U,
    0x50U, 0x44U, 0xB0U, 0xB7U, 0xD7U, 0xBFU, 0xD8U, 0xBAU, 0x27U, 0x0BU, 0x39U, 0x43U,
    0x23U, 0x55U, 0xFFU, 0xB4U
};
static const uint8_t s_ecc_secp224r1_n[28] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0x16U, 0xA2U, 0xE0U, 0xB8U, 0xF0U, 0x3EU, 0x13U, 0xDDU, 0x29U, 0x45U,
    0x5CU, 0x5CU, 0x2AU, 0x3DU
};
static const ecc_curve_params_t s_ecc_curve_secp224r1 = {
    s_ecc_secp224r1_p, s_ecc_secp224r1_a, s_ecc_secp224r1_b,
    {
        {
            0xB7U, 0x0EU, 0x0CU, 0xBDU, 0x6BU, 0xB4U, 0xBFU, 0x7FU, 0x32U, 0x13U, 0x90U, 0xB9U,
            0x4AU, 0x03U, 0xC1U, 0xD3U, 0x56U, 0xC2U, 0x11U, 0x22U, 0x34U, 0x32U, 0x80U, 0xD6U,
            0x11U, 0x5CU, 0x1DU, 0x21U
        },
        {
            0xBDU, 0x37U, 0x63U, 0x88U, 0xB5U, 0xF7U, 0x23U, 0xFBU, 0x4CU, 0x22U, 0xDFU, 0xE6U,
            0xCDU, 0x43U, 0x75U, 0xA0U, 0x5AU, 0x07U, 0x47U, 0x64U, 0x44U, 0xD5U, 0x81U, 0x99U,
            0x85U, 0x00U, 0x7EU, 0x34U
        },
        28U
    },
    s_ecc_secp224r1_n, 28U, 28U, NOXTLS_ECC_CURVE_TAG(NOXTLS_ECC_SECP224R1)
};
#endif

#if NOXTLS_ECC_ENABLE_SECP256R1
static const uint8_t s_ecc_secp256r1_p[32] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU
};
static const uint8_t s_ecc_secp256r1_a[32] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFCU
};
static const uint8_t s_ecc_secp256r1_b[32] = {
    0x5AU, 0xC6U, 0x35U, 0xD8U, 0xAAU, 0x3AU, 0x93U, 0xE7U, 0xB3U, 0xEBU, 0xBDU, 0x55U,
    0x76U, 0x98U, 0x86U, 0xBCU, 0x65U, 0x1DU, 0x06U, 0xB0U, 0xCCU, 0x53U, 0xB0U, 0xF6U,
    0x3BU, 0xCEU, 0x3CU, 0x3EU, 0x27U, 0xD2U, 0x60U, 0x4BU
};
static const uint8_t s_ecc_secp256r1_n[32] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xBCU, 0xE6U, 0xFAU, 0xADU, 0xA7U, 0x17U, 0x9EU, 0x84U,
    0xF3U, 0xB9U, 0xCAU, 0xC2U, 0xFCU, 0x63U, 0x25U, 0x51U
};
static const ecc_curve_params_t s_ecc_curve_secp256r1 = {
    s_ecc_secp256r1_p, s_ecc_secp256r1_a, s_ecc_secp256r1_b,
    {
        {
            0x6BU, 0x17U, 0xD1U, 0xF2U, 0xE1U, 0x2CU, 0x42U, 0x47U, 0xF8U, 0xBCU, 0xE6U, 0xE5U,
            0x63U, 0xA4U, 0x40U, 0xF2U, 0x77U, 0x03U, 0x7DU, 0x81U, 0x2DU, 0xEBU, 0x33U, 0xA0U,
            0xF4U, 0xA1U, 0x39U, 0x45U, 0xD8U, 0x98U, 0xC2U, 0x96U
        },
        {
            0x4FU, 0xE3U, 0x42U, 0xE2U, 0xFEU, 0x1AU, 0x7FU, 0x9BU, 0x8EU, 0xE7U, 0xEBU, 0x4AU,
            0x7CU, 0x0FU, 0x9EU, 0x16U, 0x2BU, 0xCEU, 0x33U, 0x57U, 0x6BU, 0x31U, 0x5EU, 0xCEU,
            0xCBU, 0xB6U, 0x40U, 0x68U, 0x37U, 0xBFU, 0x51U, 0xF5U
        },
        32U
    },
    s_ecc_secp256r1_n, 32U, 32U, NOXTLS_ECC_CURVE_TAG(NOXTLS_ECC_SECP256R1)
};
#endif

#if NOXTLS_ECC_ENABLE_SECP384R1
static const uint8_t s_ecc_secp384r1_p[48] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFEU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU
};
static const uint8_t s_ecc_secp384r1_a[48] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFEU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFCU
};
static const uint8_t s_ecc_secp384r1_b[48] = {
    0xB3U, 0x31U, 0x2FU, 0xA7U, 0xE2U, 0x3EU, 0xE7U, 0xE4U, 0x98U, 0x8EU, 0x05U, 0x6BU,
    0xE3U, 0xF8U, 0x2DU, 0x19U, 0x18U, 0x1DU, 0x9CU, 0x6EU, 0xFEU, 0x81U, 0x41U, 0x12U,
    0x03U, 0x14U, 0x08U, 0x8FU, 0x50U, 0x13U, 0x87U, 0x5AU, 0xC6U, 0x56U, 0x39U, 0x8DU,
    0x8AU, 0x2EU, 0xD1U, 0x9DU, 0x2AU, 0x85U, 0xC8U, 0xEDU, 0xD3U, 0xECU, 0x2AU, 0xEFU
};
static const uint8_t s_ecc_secp384r1_n[48] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xC7U, 0x63U, 0x4DU, 0x81U, 0xF4U, 0x37U, 0x2DU, 0xDFU, 0x58U, 0x1AU, 0x0DU, 0xB2U,
    0x48U, 0xB0U, 0xA7U, 0x7AU, 0xECU, 0xECU, 0x19U, 0x6AU, 0xCCU, 0xC5U, 0x29U, 0x73U
};
static const ecc_curve_params_t s_ecc_curve_secp384r1 = {
    s_ecc_secp384r1_p, s_ecc_secp384r1_a, s_ecc_secp384r1_b,
    {
        {
            0xAAU, 0x87U, 0xCAU, 0x22U, 0xBEU, 0x8BU, 0x05U, 0x37U, 0x8EU, 0xB1U, 0xC7U, 0x1EU,
            0xF3U, 0x20U, 0xADU, 0x74U, 0x6EU, 0x1DU, 0x3BU, 0x62U, 0x8BU, 0xA7U, 0x9BU, 0x98U,
            0x59U, 0xF7U, 0x41U, 0xE0U, 0x82U, 0x54U, 0x2AU, 0x38U, 0x55U, 0x02U, 0xF2U, 0x5DU,
            0xBFU, 0x55U, 0x29U, 0x6CU, 0x3AU, 0x54U, 0x5EU, 0x38U, 0x72U, 0x76U, 0x0AU, 0xB7U
        },
        {
            0x36U, 0x17U, 0xDEU, 0x4AU, 0x96U, 0x26U, 0x2CU, 0x6FU, 0x5DU, 0x9EU, 0x98U, 0xBFU,
            0x92U, 0x92U, 0xDCU, 0x29U, 0xF8U, 0xF4U, 0x1DU, 0xBDU, 0x28U, 0x9AU, 0x14U, 0x7CU,
            0xE9U, 0xDAU, 0x31U, 0x13U, 0xB5U, 0xF0U, 0xB8U, 0xC0U, 0x0AU, 0x60U, 0xB1U, 0xCEU,
            0x1DU, 0x7EU, 0x81U, 0x9DU, 0x7AU, 0x43U, 0x1DU, 0x7CU, 0x90U, 0xEAU, 0x0EU, 0x5FU
        },
        48U
    },
    s_ecc_secp384r1_n, 48U, 48U, NOXTLS_ECC_CURVE_TAG(NOXTLS_ECC_SECP384R1)
};
#endif

#if NOXTLS_ECC_ENABLE_SECP521R1
static const uint8_t s_ecc_secp521r1_p[66] = {
    0x01U, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU
};
static const uint8_t s_ecc_secp521r1_a[66] = {
    0x01U, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFCU
};
static const uint8_t s_ecc_secp521r1_b[66] = {
    0x00U, 0x51U, 0x95U, 0x3EU, 0xB9U, 0x61U, 0x8EU, 0x1CU, 0x9AU, 0x1FU, 0x92U, 0x9AU,
    0x21U, 0xA0U, 0xB6U, 0x85U, 0x40U, 0xEEU, 0xA2U, 0xDAU, 0x72U, 0x5BU, 0x99U, 0xB3U,
    0x15U, 0xF3U, 0xB8U, 0xB4U, 0x89U, 0x91U, 0x8EU, 0xF1U, 0x09U, 0xE1U, 0x56U, 0x19U,
    0x39U, 0x51U, 0xECU, 0x7EU, 0x93U, 0x7BU, 0x16U, 0x52U, 0xC0U, 0xBDU, 0x3BU, 0xB1U,
    0xBFU, 0x07U, 0x35U, 0x73U, 0xDFU, 0x88U, 0x3DU, 0x2CU, 0x34U, 0xF1U, 0xEFU, 0x45U,
    0x1FU, 0xD4U, 0x6BU, 0x50U, 0x3FU, 0x00U
};
static const uint8_t s_ecc_secp521r1_n[66] = {
    0x01U, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFAU, 0x51U, 0x86U,
    0x87U, 0x83U, 0xBFU, 0x2FU, 0x96U, 0x6BU, 0x7FU, 0xCCU, 0x01U, 0x48U, 0xF7U, 0x09U,
    0xA5U, 0xD0U, 0x3BU, 0xB5U, 0xC9U, 0xB8U, 0x89U, 0x9CU, 0x47U, 0xAEU, 0xBBU, 0x6FU,
    0xB7U, 0x1EU, 0x91U, 0x38U, 0x64U, 0x09U
};
static const ecc_curve_params_t s_ecc_curve_secp521r1 = {
    s_ecc_secp521r1_p, s_ecc_secp521r1_a, s_ecc_secp521r1_b,
    {
        {
            0x00U, 0xC6U, 0x85U, 0x8EU, 0x06U, 0xB7U, 0x04U, 0x04U, 0xE9U, 0xCDU, 0x9EU, 0x3EU,
            0xCBU, 0x66U, 0x23U, 0x95U, 0xB4U, 0x42U, 0x9CU, 0x64U, 0x81U, 0x39U, 0x05U, 0x3FU,
            0xB5U, 0x21U, 0xF8U, 0x28U, 0xAFU, 0x60U, 0x6BU, 0x4DU, 0x3DU, 0xBAU, 0xA1U, 0x4BU,
            0x5EU, 0x77U, 0xEFU, 0xE7U, 0x59U, 0x28U, 0xFEU, 0x1DU, 0xC1U, 0x27U, 0xA2U, 0xFFU,
            0xA8U, 0xDEU, 0x33U, 0x48U, 0xB3U, 0xC1U, 0x85U, 0x6AU, 0x42U, 0x9BU, 0xF9U, 0x7EU,
            0x7EU, 0x31U, 0xC2U, 0xE5U, 0xBDU, 0x66U
        },
        {
            0x01U, 0x18U, 0x39U, 0x29U, 0x6AU, 0x78U, 0x9AU, 0x3BU, 0xC0U, 0x04U, 0x5CU, 0x8AU,
            0x5FU, 0xB4U, 0x2CU, 0x7DU, 0x1BU, 0xD9U, 0x98U, 0xF5U, 0x44U, 0x49U, 0x57U, 0x9BU,
            0x44U, 0x68U, 0x17U, 0xAFU, 0xBDU, 0x17U, 0x27U, 0x3EU, 0x66U, 0x2CU, 0x97U, 0xEEU,
            0x72U, 0x99U, 0x5EU, 0xF4U, 0x26U, 0x40U, 0xC5U, 0x50U, 0xB9U, 0x01U, 0x3FU, 0xADU,
            0x07U, 0x61U, 0x35U, 0x3CU, 0x70U, 0x86U, 0xA2U, 0x72U, 0xC2U, 0x40U, 0x88U, 0xBEU,
            0x94U, 0x76U, 0x9FU, 0xD1U, 0x66U, 0x50U
        },
        66U
    },
    s_ecc_secp521r1_n, 66U, 66U, NOXTLS_ECC_CURVE_TAG(NOXTLS_ECC_SECP521R1)
};
#endif

#if NOXTLS_ECC_ENABLE_BP256R1
static const uint8_t s_ecc_brainpoolP256r1_p[32] = {
    0xA9U, 0xFBU, 0x57U, 0xDBU, 0xA1U, 0xEEU, 0xA9U, 0xBCU, 0x3EU, 0x66U, 0x0AU, 0x90U,
    0x9DU, 0x83U, 0x8DU, 0x72U, 0x6EU, 0x3BU, 0xF6U, 0x23U, 0xD5U, 0x26U, 0x20U, 0x28U,
    0x20U, 0x13U, 0x48U, 0x1DU, 0x1FU, 0x6EU, 0x53U, 0x77U
};
static const uint8_t s_ecc_brainpoolP256r1_a[32] = {
    0x7DU, 0x5AU, 0x09U, 0x75U, 0xFCU, 0x2CU, 0x30U, 0x57U, 0xEEU, 0xF6U, 0x75U, 0x30U,
    0x41U, 0x7AU, 0xFFU, 0xE7U, 0xFBU, 0x80U, 0x55U, 0xC1U, 0x26U, 0xDCU, 0x5CU, 0x6CU,
    0xE9U, 0x4AU, 0x4BU, 0x44U, 0xF3U, 0x30U, 0xB5U, 0xD9U
};
static const uint8_t s_ecc_brainpoolP256r1_b[32] = {
    0x26U, 0xDCU, 0x5CU, 0x6CU, 0xE9U, 0x4AU, 0x4BU, 0x44U, 0xF3U, 0x30U, 0xB5U, 0xD9U,
    0xBBU, 0xD7U, 0x7CU, 0xBFU, 0x95U, 0x84U, 0x16U, 0x29U, 0x5CU, 0xF7U, 0xE1U, 0xCEU,
    0x6BU, 0xCCU, 0xDCU, 0x18U, 0xFFU, 0x8CU, 0x07U, 0xB6U
};
static const uint8_t s_ecc_brainpoolP256r1_n[32] = {
    0xA9U, 0xFBU, 0x57U, 0xDBU, 0xA1U, 0xEEU, 0xA9U, 0xBCU, 0x3EU, 0x66U, 0x0AU, 0x90U,
    0x9DU, 0x83U, 0x8DU, 0x71U, 0x8CU, 0x39U, 0x7AU, 0xA3U, 0xB5U, 0x61U, 0xA6U, 0xF7U,
    0x90U, 0x1EU, 0x0EU, 0x82U, 0x97U, 0x48U, 0x56U, 0xA7U
};
static const ecc_curve_params_t s_ecc_curve_brainpoolP256r1 = {
    s_ecc_brainpoolP256r1_p, s_ecc_brainpoolP256r1_a, s_ecc_brainpoolP256r1_b,
    {
        {
            0x8BU, 0xD2U, 0xAEU, 0xB9U, 0xCBU, 0x7EU, 0x57U, 0xCBU, 0x2CU, 0x4BU, 0x48U, 0x2FU,
            0xFCU, 0x81U, 0xB7U, 0xAFU, 0xB9U, 0xDEU, 0x27U, 0xE1U, 0xE3U, 0xBDU, 0x23U, 0xC2U,
            0x3AU, 0x44U, 0x53U, 0xBDU, 0x9AU, 0xCEU, 0x32U, 0x62U
        },
        {
            0x54U, 0x7EU, 0xF8U, 0x35U, 0xC3U, 0xDAU, 0xC4U, 0xFDU, 0x97U, 0xF8U, 0x46U, 0x1AU,
            0x14U, 0x61U, 0x1DU, 0xC9U, 0xC2U, 0x77U, 0x45U, 0x13U, 0x2DU, 0xEDU, 0x8EU, 0x54U,
            0x5CU, 0x1DU, 0x54U, 0xC7U, 0x2FU, 0x04U, 0x69U, 0x97U
        },
        32U
    },
    s_ecc_brainpoolP256r1_n, 32U, 32U, NOXTLS_ECC_CURVE_TAG(NOXTLS_ECC_BP256R1)
};
#endif

#if NOXTLS_ECC_ENABLE_BP384R1
static const uint8_t s_ecc_brainpoolP384r1_p[48] = {
    0x8CU, 0xB9U, 0x1EU, 0x82U, 0xA3U, 0x38U, 0x6DU, 0x28U, 0x0FU, 0x5DU, 0x6FU, 0x7EU,
    0x50U, 0xE6U, 0x41U, 0xDFU, 0x15U, 0x2FU, 0x71U, 0x09U, 0xEDU, 0x54U, 0x56U, 0xB4U,
    0x12U, 0xB1U, 0xDAU, 0x19U, 0x7FU, 0xB7U, 0x11U, 0x23U, 0xACU, 0xD3U, 0xA7U, 0x29U,
    0x90U, 0x1DU, 0x1AU, 0x71U, 0x87U, 0x47U, 0x00U, 0x13U, 0x31U, 0x07U, 0xECU, 0x53U
};
static const uint8_t s_ecc_brainpoolP384r1_a[48] = {
    0x7BU, 0xC3U, 0x82U, 0xC6U, 0x3DU, 0x8CU, 0x15U, 0x0CU, 0x3CU, 0x72U, 0x08U, 0x0AU,
    0xCEU, 0x05U, 0xAFU, 0xA0U, 0xC2U, 0xBEU, 0xA2U, 0x8EU, 0x4FU, 0xB2U, 0x27U, 0x87U,
    0x13U, 0x91U, 0x65U, 0xEFU, 0xBAU, 0x91U, 0xF9U, 0x0FU, 0x8AU, 0xA5U, 0x81U, 0x4AU,
    0x50U, 0x3AU, 0xD4U, 0xEBU, 0x04U, 0xA8U, 0xC7U, 0xDDU, 0x22U, 0xCEU, 0x28U, 0x26U
};
static const uint8_t s_ecc_brainpoolP384r1_b[48] = {
    0x04U, 0xA8U, 0xC7U, 0xDDU, 0x22U, 0xCEU, 0x28U, 0x26U, 0x8BU, 0x39U, 0xB5U, 0x54U,
    0x16U, 0xF0U, 0x44U, 0x7CU, 0x2FU, 0xB7U, 0x7DU, 0xE1U, 0x07U, 0xDCU, 0xD2U, 0xA6U,
    0x2EU, 0x88U, 0x0EU, 0xA5U, 0x3EU, 0xEBU, 0x62U, 0xD5U, 0x7CU, 0xB4U, 0x39U, 0x02U,
    0x95U, 0xDBU, 0xC9U, 0x94U, 0x3AU, 0xB7U, 0x86U, 0x96U, 0xFAU, 0x50U, 0x4CU, 0x11U
};
static const uint8_t s_ecc_brainpoolP384r1_n[48] = {
    0x8CU, 0xB9U, 0x1EU, 0x82U, 0xA3U, 0x38U, 0x6DU, 0x28U, 0x0FU, 0x5DU, 0x6FU, 0x7EU,
    0x50U, 0xE6U, 0x41U, 0xDFU, 0x15U, 0x2FU, 0x71U, 0x09U, 0xEDU, 0x54U, 0x56U, 0xB3U,
    0x1FU, 0x16U, 0x6EU, 0x6CU, 0xACU, 0x04U, 0x25U, 0xA7U, 0xCFU, 0x3AU, 0xB6U, 0xAFU,
    0x6BU, 0x7FU, 0xC3U, 0x10U, 0x3BU, 0x88U, 0x32U, 0x02U, 0xE9U, 0x04U, 0x65U, 0x65U
};
static const ecc_curve_params_t s_ecc_curve_brainpoolP384r1 = {
    s_ecc_brainpoolP384r1_p, s_ecc_brainpoolP384r1_a, s_ecc_brainpoolP384r1_b,
    {
        {
            0x1DU, 0x1CU, 0x64U, 0xF0U, 0x68U, 0xCFU, 0x45U, 0xFFU, 0xA2U, 0xA6U, 0x3AU, 0x81U,
            0xB7U, 0xC1U, 0x3FU, 0x6BU, 0x88U, 0x47U, 0xA3U, 0xE7U, 0x7EU, 0xF1U, 0x4FU, 0xE3U,
            0xDBU, 0x7FU, 0xCAU, 0xFEU, 0x0CU, 0xBDU, 0x10U, 0xE8U, 0xE8U, 0x26U, 0xE0U, 0x34U,
            0x36U, 0xD6U, 0x46U, 0xAAU, 0xEFU, 0x87U, 0xB2U, 0xE2U, 0x47U, 0xD4U, 0xAFU, 0x1EU
        },
        {
            0x8AU, 0xBEU, 0x1DU, 0x75U, 0x20U, 0xF9U, 0xC2U, 0xA4U, 0x5CU, 0xB1U, 0xEBU, 0x8EU,
            0x95U, 0xCFU, 0xD5U, 0x52U, 0x62U, 0xB7U, 0x0BU, 0x29U, 0xFEU, 0xECU, 0x58U, 0x64U,
            0xE1U, 0x9CU, 0x05U, 0x4FU, 0xF9U, 0x91U, 0x29U, 0x28U, 0x0EU, 0x46U, 0x46U, 0x21U,
            0x77U, 0x91U, 0x81U, 0x11U, 0x42U, 0x82U, 0x03U, 0x41U, 0x26U, 0x3CU, 0x53U, 0x15U
        },
        48U
    },
    s_ecc_brainpoolP384r1_n, 48U, 48U, NOXTLS_ECC_CURVE_TAG(NOXTLS_ECC_BP384R1)
};
#endif

#if NOXTLS_ECC_ENABLE_BP512R1
static const uint8_t s_ecc_brainpoolP512r1_p[64] = {
    0xAAU, 0xDDU, 0x9DU, 0xB8U, 0xDBU, 0xE9U, 0xC4U, 0x8BU, 0x3FU, 0xD4U, 0xE6U, 0xAEU,
    0x33U, 0xC9U, 0xFCU, 0x07U, 0xCBU, 0x30U, 0x8DU, 0xB3U, 0xB3U, 0xC9U, 0xD2U, 0x0EU,
    0xD6U, 0x63U, 0x9CU, 0xCAU, 0x70U, 0x33U, 0x08U, 0x71U, 0x7DU, 0x4DU, 0x9BU, 0x00U,
    0x9BU, 0xC6U, 0x68U, 0x42U, 0xAEU, 0xCDU, 0xA1U, 0x2AU, 0xE6U, 0xA3U, 0x80U, 0xE6U,
    0x28U, 0x81U, 0xFFU, 0x2FU, 0x2DU, 0x82U, 0xC6U, 0x85U, 0x28U, 0xAAU, 0x60U, 0x56U,
    0x58U, 0x3AU, 0x48U, 0xF3U
};
static const uint8_t s_ecc_brainpoolP512r1_a[64] = {
    0x78U, 0x30U, 0xA3U, 0x31U, 0x8BU, 0x60U, 0x3BU, 0x89U, 0xE2U, 0x32U, 0x71U, 0x45U,
    0xACU, 0x23U, 0x4CU, 0xC5U, 0x94U, 0xCBU, 0xDDU, 0x8DU, 0x3DU, 0xF9U, 0x16U, 0x10U,
    0xA8U, 0x34U, 0x41U, 0xCAU, 0xEAU, 0x98U, 0x63U, 0xBCU, 0x2DU, 0xEDU, 0x5DU, 0x5AU,
    0xA8U, 0x25U, 0x3AU, 0xA1U, 0x0AU, 0x2EU, 0xF1U, 0xC9U, 0x8BU, 0x9AU, 0xC8U, 0xB5U,
    0x7FU, 0x11U, 0x17U, 0xA7U, 0x2BU, 0xF2U, 0xC7U, 0xB9U, 0xE7U, 0xC1U, 0xACU, 0x4DU,
    0x77U, 0xFCU, 0x94U, 0xCAU
};
static const uint8_t s_ecc_brainpoolP512r1_b[64] = {
    0x3DU, 0xF9U, 0x16U, 0x10U, 0xA8U, 0x34U, 0x41U, 0xCAU, 0xEAU, 0x98U, 0x63U, 0xBCU,
    0x2DU, 0xEDU, 0x5DU, 0x5AU, 0xA8U, 0x25U, 0x3AU, 0xA1U, 0x0AU, 0x2EU, 0xF1U, 0xC9U,
    0x8BU, 0x9AU, 0xC8U, 0xB5U, 0x7FU, 0x11U, 0x17U, 0xA7U, 0x2BU, 0xF2U, 0xC7U, 0xB9U,
    0xE7U, 0xC1U, 0xACU, 0x4DU, 0x77U, 0xFCU, 0x94U, 0xCAU, 0xDCU, 0x08U, 0x3EU, 0x67U,
    0x98U, 0x40U, 0x50U, 0xB7U, 0x5EU, 0xBAU, 0xE5U, 0xDDU, 0x28U, 0x09U, 0xBDU, 0x63U,
    0x80U, 0x16U, 0xF7U, 0x23U
};
static const uint8_t s_ecc_brainpoolP512r1_n[64] = {
    0xAAU, 0xDDU, 0x9DU, 0xB8U, 0xDBU, 0xE9U, 0xC4U, 0x8BU, 0x3FU, 0xD4U, 0xE6U, 0xAEU,
    0x33U, 0xC9U, 0xFCU, 0x07U, 0xCBU, 0x30U, 0x8DU, 0xB3U, 0xB3U, 0xC9U, 0xD2U, 0x0EU,
    0xD6U, 0x63U, 0x9CU, 0xCAU, 0x70U, 0x33U, 0x08U, 0x70U, 0x55U, 0x3EU, 0x5CU, 0x41U,
    0x4CU, 0xA9U, 0x26U, 0x19U, 0x41U, 0x86U, 0x61U, 0x19U, 0x7FU, 0xACU, 0x10U, 0x47U,
    0x1DU, 0xB1U, 0xD3U, 0x81U, 0x08U, 0x5DU, 0xDAU, 0xDDU, 0xB5U, 0x87U, 0x96U, 0x82U,
    0x9CU, 0xA9U, 0x00U, 0x69U
};
static const ecc_curve_params_t s_ecc_curve_brainpoolP512r1 = {
    s_ecc_brainpoolP512r1_p, s_ecc_brainpoolP512r1_a, s_ecc_brainpoolP512r1_b,
    {
        {
            0x81U, 0xAEU, 0xE4U, 0xBDU, 0xD8U, 0x2EU, 0xD9U, 0x64U, 0x5AU, 0x21U, 0x32U, 0x2EU,
            0x9CU, 0x4CU, 0x6AU, 0x93U, 0x85U, 0xEDU, 0x9FU, 0x70U, 0xB5U, 0xD9U, 0x16U, 0xC1U,
            0xB4U, 0x3BU, 0x62U, 0xEEU, 0xF4U, 0xD0U, 0x09U, 0x8EU, 0xFFU, 0x3BU, 0x1FU, 0x78U,
            0xE2U, 0xD0U, 0xD4U, 0x8DU, 0x50U, 0xD1U, 0x68U, 0x7BU, 0x93U, 0xB9U, 0x7DU, 0x5FU,
            0x7CU, 0x6DU, 0x50U, 0x47U, 0x40U, 0x6AU, 0x5EU, 0x68U, 0x8BU, 0x35U, 0x22U, 0x09U,
            0xBCU, 0xB9U, 0xF8U, 0x22U
        },
        {
            0x7DU, 0xDEU, 0x38U, 0x5DU, 0x56U, 0x63U, 0x32U, 0xECU, 0xC0U, 0xEAU, 0xBFU, 0xA9U,
            0xCFU, 0x78U, 0x22U, 0xFDU, 0xF2U, 0x09U, 0xF7U, 0x00U, 0x24U, 0xA5U, 0x7BU, 0x1AU,
            0xA0U, 0x00U, 0xC5U, 0x5BU, 0x88U, 0x1FU, 0x81U, 0x11U, 0xB2U, 0xDCU, 0xDEU, 0x49U,
            0x4AU, 0x5FU, 0x48U, 0x5EU, 0x5BU, 0xCAU, 0x4BU, 0xD8U, 0x8AU, 0x27U, 0x63U, 0xAEU,
            0xD1U, 0xCAU, 0x2BU, 0x2FU, 0xA8U, 0xF0U, 0x54U, 0x06U, 0x78U, 0xCDU, 0x1EU, 0x0FU,
            0x3AU, 0xD8U, 0x08U, 0x92U
        },
        64U
    },
    s_ecc_brainpoolP512r1_n, 64U, 64U, NOXTLS_ECC_CURVE_TAG(NOXTLS_ECC_BP512R1)
};
#endif

#if NOXTLS_ECC_ENABLE_SECP192K1
static const uint8_t s_ecc_secp192k1_p[24] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFEU, 0xFFU, 0xFFU, 0xEEU, 0x37U
};
static const uint8_t s_ecc_secp192k1_a[24] = {
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
};
static const uint8_t s_ecc_secp192k1_b[24] = {
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x03U
};
static const uint8_t s_ecc_secp192k1_n[24] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFEU,
    0x26U, 0xF2U, 0xFCU, 0x17U, 0x0FU, 0x69U, 0x46U, 0x6AU, 0x74U, 0xDEU, 0xFDU, 0x8DU
};
static const ecc_curve_params_t s_ecc_curve_secp192k1 = {
    s_ecc_secp192k1_p, s_ecc_secp192k1_a, s_ecc_secp192k1_b,
    {
        {
            0xDBU, 0x4FU, 0xF1U, 0x0EU, 0xC0U, 0x57U, 0xE9U, 0xAEU, 0x26U, 0xB0U, 0x7DU, 0x02U,
            0x80U, 0xB7U, 0xF4U, 0x34U, 0x1DU, 0xA5U, 0xD1U, 0xB1U, 0xEAU, 0xE0U, 0x6CU, 0x7DU
        },
        {
            0x9BU, 0x2FU, 0x2FU, 0x6DU, 0x9CU, 0x56U, 0x28U, 0xA7U, 0x84U, 0x41U, 0x63U, 0xD0U,
            0x15U, 0xBEU, 0x86U, 0x34U, 0x40U, 0x82U, 0xAAU, 0x88U, 0xD9U, 0x5EU, 0x2FU, 0x9DU
        },
        24U
    },
    s_ecc_secp192k1_n, 24U, 24U, NOXTLS_ECC_CURVE_TAG(NOXTLS_ECC_SECP192K1)
};
#endif

#if NOXTLS_ECC_ENABLE_SECP224K1
static const uint8_t s_ecc_secp224k1_p[28] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFEU,
    0xFFU, 0xFFU, 0xE5U, 0x6DU
};
static const uint8_t s_ecc_secp224k1_a[28] = {
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U
};
static const uint8_t s_ecc_secp224k1_b[28] = {
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x05U
};
static const uint8_t s_ecc_secp224k1_n[29] = {
    0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x01U, 0xDCU, 0xE8U, 0xD2U, 0xECU, 0x61U, 0x84U, 0xCAU, 0xF0U, 0xA9U,
    0x71U, 0x76U, 0x9FU, 0xB1U, 0xF7U
};
static const ecc_curve_params_t s_ecc_curve_secp224k1 = {
    s_ecc_secp224k1_p, s_ecc_secp224k1_a, s_ecc_secp224k1_b,
    {
        {
            0xA1U, 0x45U, 0x5BU, 0x33U, 0x4DU, 0xF0U, 0x99U, 0xDFU, 0x30U, 0xFCU, 0x28U, 0xA1U,
            0x69U, 0xA4U, 0x67U, 0xE9U, 0xE4U, 0x70U, 0x75U, 0xA9U, 0x0FU, 0x7EU, 0x65U, 0x0EU,
            0xB6U, 0xB7U, 0xA4U, 0x5CU
        },
        {
            0x7EU, 0x08U, 0x9FU, 0xEDU, 0x7FU, 0xBAU, 0x34U, 0x42U, 0x82U, 0xCAU, 0xFBU, 0xD6U,
            0xF7U, 0xE3U, 0x19U, 0xF7U, 0xC0U, 0xB0U, 0xBDU, 0x59U, 0xE2U, 0xCAU, 0x4BU, 0xDBU,
            0x55U, 0x6DU, 0x61U, 0xA5U
        },
        28U
    },
    s_ecc_secp224k1_n, 28U, 29U, NOXTLS_ECC_CURVE_TAG(NOXTLS_ECC_SECP224K1)
};
#endif

#if NOXTLS_ECC_ENABLE_SECP256K1
static const uint8_t s_ecc_secp256k1_p[32] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFEU, 0xFFU, 0xFFU, 0xFCU, 0x2FU
};
static const uint8_t s_ecc_secp256k1_a[32] = {
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
};
static const uint8_t s_ecc_secp256k1_b[32] = {
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x07U
};
static const uint8_t s_ecc_secp256k1_n[32] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFEU, 0xBAU, 0xAEU, 0xDCU, 0xE6U, 0xAFU, 0x48U, 0xA0U, 0x3BU,
    0xBFU, 0xD2U, 0x5EU, 0x8CU, 0xD0U, 0x36U, 0x41U, 0x41U
};
static const ecc_curve_params_t s_ecc_curve_secp256k1 = {
    s_ecc_secp256k1_p, s_ecc_secp256k1_a, s_ecc_secp256k1_b,
    {
        {
            0x79U, 0xBEU, 0x66U, 0x7EU, 0xF9U, 0xDCU, 0xBBU, 0xACU, 0x55U, 0xA0U, 0x62U, 0x95U,
            0xCEU, 0x87U, 0x0BU, 0x07U, 0x02U, 0x9BU, 0xFCU, 0xDBU, 0x2DU, 0xCEU, 0x28U, 0xD9U,
            0x59U, 0xF2U, 0x81U, 0x5BU, 0x16U, 0xF8U, 0x17U, 0x98U
        },
        {
            0x48U, 0x3AU, 0xDAU, 0x77U, 0x26U, 0xA3U, 0xC4U, 0x65U, 0x5DU, 0xA4U, 0xFBU, 0xFCU,
            0x0EU, 0x11U, 0x08U, 0xA8U, 0xFDU, 0x17U, 0xB4U, 0x48U, 0xA6U, 0x85U, 0x54U, 0x19U,
            0x9CU, 0x47U, 0xD0U, 0x8FU, 0xFBU, 0x10U, 0xD4U, 0xB8U
        },
        32U
    },
    s_ecc_secp256k1_n, 32U, 32U, NOXTLS_ECC_CURVE_TAG(NOXTLS_ECC_SECP256K1)
};
#endif

/**
 * @brief Shared read-only parameters of a curve.
 *
 * @param curve_type Curve id (NOXTLS_ECC_*)
 * @return The descriptor, or NULL for an unknown curve or one disabled at build time
 */
const ecc_curve_params_t *noxtls_ecc_curve_get(ecc_curve_t curve_type)
{
    const ecc_curve_params_t *desc = NULL;

    switch((uint32_t)curve_type) {
#if NOXTLS_ECC_ENABLE_SECP192R1
    case (uint32_t)NOXTLS_ECC_SECP192R1:
        desc = &s_ecc_curve_secp192r1;
        break;
#endif
#if NOXTLS_ECC_ENABLE_SECP224R1
    case (uint32_t)NOXTLS_ECC_SECP224R1:
        desc = &s_ecc_curve_secp224r1;
        break;
#endif
#if NOXTLS_ECC_ENABLE_SECP256R1
    case (uint32_t)NOXTLS_ECC_SECP256R1:
        desc = &s_ecc_curve_secp256r1;
        break;
#endif
#if NOXTLS_ECC_ENABLE_SECP384R1
    case (uint32_t)NOXTLS_ECC_SECP384R1:
        desc = &s_ecc_curve_secp384r1;
        break;
#endif
#if NOXTLS_ECC_ENABLE_SECP521R1
    case (uint32_t)NOXTLS_ECC_SECP521R1:
        desc = &s_ecc_curve_secp521r1;
        break;
#endif
#if NOXTLS_ECC_ENABLE_BP256R1
    case (uint32_t)NOXTLS_ECC_BP256R1:
        desc = &s_ecc_curve_brainpoolP256r1;
        break;
#endif
#if NOXTLS_ECC_ENABLE_BP384R1
    case (uint32_t)NOXTLS_ECC_BP384R1:
        desc = &s_ecc_curve_brainpoolP384r1;
        break;
#endif
#if NOXTLS_ECC_ENABLE_BP512R1
    case (uint32_t)NOXTLS_ECC_BP512R1:
        desc = &s_ecc_curve_brainpoolP512r1;
        break;
#endif
#if NOXTLS_ECC_ENABLE_SECP192K1
    case (uint32_t)NOXTLS_ECC_SECP192K1:
        desc = &s_ecc_curve_secp192k1;
        break;
#endif
#if NOXTLS_ECC_ENABLE_SECP224K1
    case (uint32_t)NOXTLS_ECC_SECP224K1:
        desc = &s_ecc_curve_secp224k1;
        break;
#endif
#if NOXTLS_ECC_ENABLE_SECP256K1
    case (uint32_t)NOXTLS_ECC_SECP256K1:
        desc = &s_ecc_curve_secp256k1;
        break;
#endif
    default:
        desc = NULL;
        break;
    }
    return desc;
}

/**
 * @brief Initialize ECC curve parameters
 *
 * The parameter pointers reference the shared read-only constants (no allocation).
 *
 * @param curve ECC curve parameters
 * @param curve_type Curve type
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL if curve is NULL, NOXTLS_RETURN_FAILED
 *         for an unknown or disabled curve
 */
noxtls_return_t noxtls_ecc_curve_init(ecc_curve_params_t *curve, ecc_curve_t curve_type)
{
    const ecc_curve_params_t *desc;

    if(curve == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_fill_u8((uint8_t *)(void *)(curve), sizeof(ecc_curve_params_t), 0U, sizeof(ecc_curve_params_t));
    desc = noxtls_ecc_curve_get(curve_type);
    if(desc == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    *curve = *desc;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Free ECC curve parameters
 *
 * @param curve ECC curve parameters
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if curve is NULL
 */
noxtls_return_t noxtls_ecc_curve_free(ecc_curve_params_t *curve)
{
    if(curve == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    /* Precompute caches are keyed by curve id (curve_tag), not by the address of
     * a parameter structure, so nothing has to be invalidated here. */

    /* p, a, b and n reference read-only constants (or caller-owned buffers):
     * nothing to free. */
    noxtls_fill_u8((uint8_t *)(void *)(curve), sizeof(ecc_curve_params_t), 0U, sizeof(ecc_curve_params_t));

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Length of the group order n in bytes.
 *
 * @param curve ECC curve parameters
 * @return uint32_t curve->n_size when set, otherwise curve->size (0 if curve is NULL)
 */
uint32_t noxtls_ecc_curve_order_size(const ecc_curve_params_t *curve)
{
    uint32_t n_size = 0U;

    if(curve != NULL) {
        n_size = curve->size;
        if((curve->n_size >= curve->size) && (curve->n_size <= ECC_MAX_KEY_SIZE)) {
            n_size = curve->n_size;
        }
    }
    return n_size;
}

/**
 * @brief Initialize ECC point
 *
 * @param point ECC point
 * @param size Size of the point
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if point is NULL
 */
noxtls_return_t noxtls_ecc_point_init(ecc_point_t *point, uint32_t size)
{
    if(point == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_fill_u8((uint8_t *)(void *)(point), sizeof(ecc_point_t), 0U, sizeof(ecc_point_t));
    point->size = size;

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Check if point is at infinity (zero point)
 *
 * @param[in] point The point.
 * @param[in] size The size of the point.
 * @return int 1 if the point is at infinity, 0 otherwise
 */
static int ecc_point_is_infinity(const ecc_point_t *point, uint32_t size)
{
    uint32_t i = 0U;
    for(i = 0U; i < size; i += 1U) {
        if((point->x[i] != 0U) || (point->y[i] != 0U)) {
            return 0;
        }
    }
    return 1;
}

/**
 * @brief Check if Jacobian point is identity (Z=0)
 *
 * @param J Jacobian point
 * @param size Size of the point
 * @return int 1 if the point is identity, 0 otherwise
 */
static int ecc_jpoint_is_infinity(const ecc_jpoint_t *J, uint32_t size)
{
    return (noxtls_bn_is_zero(J->Z, size) != 0) ? 1 : 0;
}

/**
 * @brief Check if two points are equal
 *
 * @param p1 First point
 * @param p2 Second point
 * @param size Size of the points
 * @return int 1 if the points are equal, 0 otherwise
 */
static int ecc_point_equal(const ecc_point_t *p1, const ecc_point_t *p2, uint32_t size)
{
    return ((noxtls_bn_cmp(p1->x, p2->x, size) == 0) &&
           (noxtls_bn_cmp(p1->y, p2->y, size) == 0)) ? 1 : 0;
}

/**
 * @brief Constant-time conditional copy: out = b ? src1 : src2 (byte-wise, no branches on b)
 *
 * @param out Output buffer
 * @param src1 Source buffer 1
 * @param src2 Source buffer 2
 * @param len Length of the buffers
 * @param b Condition
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static void ecc_cond_select(uint8_t *out, const uint8_t *src1, const uint8_t *src2, uint32_t len, uint8_t b)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint8_t mask = (uint8_t)(0U - (uint8_t)(b & 1U));
    uint32_t i = 0U;
    for(i = 0U; i < len; i += 1U) {
        out[i] = (uint8_t)(src2[i] ^ (mask & (src1[i] ^ src2[i])));
    }
}

/** Get bit at bit_index (0 = MSB of scalar[0]) from big-endian scalar. */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static uint8_t ecc_scalar_getbit(const uint8_t *scalar, uint32_t size_bytes, uint32_t bit_index)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    static const uint8_t s_msb_masks[8] = {
        0x80U, 0x40U, 0x20U, 0x10U, 0x08U, 0x04U, 0x02U, 0x01U
    };
    uint32_t byte_idx = (uint32_t)(bit_index >> 3U);
    uint32_t bit_in_byte = (uint32_t)(bit_index & 7U);
    if(byte_idx >= size_bytes) { return 0; }
    return (((uint32_t)scalar[byte_idx] & (uint32_t)s_msb_masks[bit_in_byte]) != 0U) ? 1U : 0U;
}

/** Extract a big-endian digit from bit range [start_bit, start_bit + width). */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
#if NOXTLS_ECC_POINT_MUL_WINDOW_SIZE > 0
static uint32_t ecc_scalar_digit_range(const uint8_t *scalar,
                                       uint32_t size_bytes,
                                       uint32_t start_bit,
                                       uint32_t width)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint32_t d = 0U;
    uint32_t b = 0U;
    uint32_t n_bits = 0U;

    if(size_bytes > (uint32_t)(UINT32_MAX / 8U)) {
        return 0;
    }
    n_bits = size_bytes * 8U;
    if(start_bit >= n_bits) {
        return 0;
    }
    for(b = 0U; (b < width) && ((start_bit + b) < n_bits); b += 1U) {
        d = (d << 1U) | ecc_scalar_getbit(scalar, size_bytes, start_bit + b);
    }
    return d;
}
#endif

/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t ecc_mod_add(uint8_t *out, const uint8_t *a, const uint8_t *b, const uint8_t *p, uint32_t size);
/* NOLINTEND(bugprone-easily-swappable-parameters) */

static const uint8_t s_p256_prime_be[32] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x01U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU
};

static const uint32_t s_p256_prime_words[8] = {
    0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U,
    0x00000000U, 0x00000000U, 0x00000001U, 0xFFFFFFFFU
};

#if NOXTLS_ECC_POINT_MUL_WINDOW_SIZE >= 2
static const uint32_t s_p256_order_words[8] = {
    0xFC632551U, 0xF3B9CAC2U, 0xA7179E84U, 0xBCE6FAADU,
    0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U, 0xFFFFFFFFU
};
#endif

/**
 * @brief Check if the modulus is P-256
 *
 * @param p The modulus
 * @param size The size of the modulus
 * @return The return value
 */
static int ecc_modulus_is_secp256r1(const uint8_t *p, uint32_t size)
{
#if defined(NOXTLS_P256_GENERIC_ARITHMETIC) && NOXTLS_P256_GENERIC_ARITHMETIC
    (void)p;
    (void)size;
    return 0;
#else
    if((size != 32U) || (p == NULL)) {
        return 0;
    }
#if NOXTLS_ECC_ENABLE_SECP256R1
    if(p == s_ecc_secp256r1_p) {
        return 1;   /* the shared descriptor's prime: skip the compare */
    }
#endif
    return (noxtls_ct_memcmp(p, s_p256_prime_be, (size_t)32U) == 0) ? 1 : 0;
#endif
}

/**
 * @brief Check if the curve is P-256
 *
 * @param curve The curve
 * @return The return value
 */
static int ecc_curve_is_secp256r1(const ecc_curve_params_t *curve)
{
#if defined(NOXTLS_P256_GENERIC_ARITHMETIC) && NOXTLS_P256_GENERIC_ARITHMETIC
    (void)curve;
    return 0;
#else
    /* P-256 a (Rule 8.9). */
    static const uint8_t s_p256_a_be[32] = {
        0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x01U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
        0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFCU
    };


    if((curve == NULL) || (curve->size != 32U) || (curve->p == NULL) || (curve->a == NULL)) {
        return 0;
    }
#if NOXTLS_ECC_ENABLE_SECP256R1
    if((curve->p == s_ecc_secp256r1_p) && (curve->a == s_ecc_secp256r1_a)) {
        return 1;   /* shared descriptor constants: skip the compares */
    }
#endif
    if(noxtls_ct_memcmp(curve->p, s_p256_prime_be, (size_t)32U) != 0) {
        return 0;
    }
    return (noxtls_ct_memcmp(curve->a, s_p256_a_be, (size_t)32U) == 0) ? 1 : 0;
#endif
}

/**
 * @brief Convert big-endian words to 32-bit words
 *
 * @param out The output buffer
 * @param in The input buffer
 */
static void p256_words_from_be(uint32_t *out, const uint8_t *in)
{
    uint32_t i = 0U;

    for(i = 0U; i < 8U; i += 1U) {
        uint32_t o = (uint32_t)(32U - ((i + 1U) * 4U));
        out[i] = ((uint32_t)in[o] << 24U) |
                 ((uint32_t)in[o + 1U] << 16U) |
                 ((uint32_t)in[o + 2U] << 8U) |
                 ((uint32_t)in[o + 3U]);
    }
}

/**
 * @brief Convert 32-bit words to big-endian bytes
 *
 * @param out The output buffer
 * @param in The input buffer
 */
static void p256_words_to_be(uint8_t *out, const uint32_t *in)
{
    uint32_t i = 0U;

    for(i = 0U; i < 8U; i += 1U) {
        uint32_t w = in[i];
        uint32_t o = (uint32_t)(32U - ((i + 1U) * 4U));
        out[o] = (uint8_t)(w >> 24U);
        out[o + 1U] = (uint8_t)(w >> 16U);
        out[o + 2U] = (uint8_t)(w >> 8U);
        out[o + 3U] = (uint8_t)w;
    }
}

/**
 * @brief Check if the words are zero
 *
 * @param a The input buffer
 * @return The return value
 */
static int p256_words_is_zero(const uint32_t *a)
{
    uint32_t i = 0U;

    for(i = 0U; i < 8U; i += 1U) {
        if(a[i] != 0U) {
            return 0;
        }
    }
    return 1;
}

/**
 * @brief Compare two words
 *
 * @param a The first word
 * @param b The second word
 * @return The return value
 */
static int p256_words_cmp(const uint32_t *a, const uint32_t *b)
{
    uint32_t i = 0U;

    for(i = 8U; i > 0U; i -= 1U) {
        uint32_t idx = (uint32_t)(i - 1U);
        if(a[idx] > b[idx]) {
            return 1;
        }
        if(a[idx] < b[idx]) {
            return -1;
        }
    }
    return 0;
}

/**
 * @brief Subtract two words
 *
 * @param out The output buffer
 * @param a The first word
 * @param b The second word
 */
static void p256_words_sub_raw(uint32_t *out, const uint32_t *a, const uint32_t *b)
{
    uint64_t borrow = 0U;
    uint32_t i = 0U;

    for(i = 0U; i < 8U; i += 1U) {
        uint64_t ai = (uint64_t)a[i];
        uint64_t bi = (uint64_t)b[i] + borrow;
        if(ai < bi) {
            out[i] = (uint32_t)(ai + (1ULL << 32U) - bi);
            borrow = 1U;
        } else {
            out[i] = (uint32_t)(ai - bi);
            borrow = 0U;
        }
    }
}

static void p256_fold_acc(int64_t *acc, uint32_t idx);

/**
 * @brief Reduce the accumulated words
 *
 * @param out The output buffer
 * @param acc The accumulated words
 */
static void p256_reduce_acc_words(uint32_t *out, int64_t *acc)
{
    uint32_t i = 0U;
    int changed = 1;
    const int64_t base = 0x100000000LL;

    while(changed != 0) {
        changed = 0;

        for(i = 8U; i < 24U; i += 1U) {
            if(acc[i] != 0) {
                p256_fold_acc(acc, i);
                changed = 1;
            }
        }

        for(i = 0U; i < 8U; i += 1U) {
            int64_t v = acc[i];
            if((v < 0) || (v >= base)) {
                int64_t carry = v / base;
                int64_t rem = v % base;
                if(rem < 0) {
                    rem += base;
                    carry -= 1;
                }
                acc[i] = rem;
                acc[i + 1U] += carry;
                changed = 1;
            }
        }
    }

    for(i = 0U; i < 8U; i += 1U) {
        out[i] = (uint32_t)acc[i];
    }

    while(p256_words_cmp(out, s_p256_prime_words) >= 0) {
        p256_words_sub_raw(out, out, s_p256_prime_words);
    }
}

/**
 * @brief Add two words
 *
 * @param out The output buffer
 * @param a The first word
 * @param b The second word
 */
static void p256_words_add_mod(uint32_t *out, const uint32_t *a, const uint32_t *b)
{
    uint32_t sum[8];
    uint64_t carry = 0U;
    uint32_t i = 0U;

    for(i = 0U; i < 8U; i += 1U) {
        uint64_t v = (uint64_t)a[i] + (uint64_t)b[i] + carry;
        sum[i] = (uint32_t)v;
        carry = v >> 32U;
    }

    if((carry == 0U) && (p256_words_cmp(sum, s_p256_prime_words) < 0)) {
        noxtls_copy_u8((uint8_t *)(void *)(out), (size_t)(8U * sizeof(uint32_t)), (const uint8_t *)(const void *)(sum), (size_t)(8U * sizeof(uint32_t)));
        return;
    }

    {
        int64_t acc[24];
        noxtls_fill_u8((uint8_t *)(void *)(acc), sizeof(acc), 0U, sizeof(acc));
        for(i = 0U; i < 8U; i += 1U) {
            acc[i] = (int64_t)sum[i];
        }
        acc[8] = (int64_t)carry;
        p256_reduce_acc_words(out, acc);
    }
}

/**
 * @brief Subtract two words modulo the order
 *
 * @param out The output buffer
 * @param a The first word
 * @param b The second word
 */
static void p256_words_sub_mod(uint32_t *out, const uint32_t *a, const uint32_t *b)
{
    uint32_t diff[8];
    uint64_t borrow = 0U;
    uint32_t i = 0U;

    for(i = 0U; i < 8U; i += 1U) {
        uint64_t ai = (uint64_t)a[i];
        uint64_t bi = (uint64_t)b[i] + borrow;
        if(ai < bi) {
            diff[i] = (uint32_t)(ai + (1ULL << 32U) - bi);
            borrow = 1U;
        } else {
            diff[i] = (uint32_t)(ai - bi);
            borrow = 0U;
        }
    }

    if(borrow == 0U) {
        noxtls_copy_u8((uint8_t *)(void *)(out), (size_t)(8U * sizeof(uint32_t)), (const uint8_t *)(const void *)(diff), (size_t)(8U * sizeof(uint32_t)));
        return;
    }

    {
        int64_t acc[24];
        noxtls_fill_u8((uint8_t *)(void *)(acc), sizeof(acc), 0U, sizeof(acc));
        for(i = 0U; i < 8U; i += 1U) {
            acc[i] = (int64_t)diff[i];
        }
        acc[8] = -1;
        p256_reduce_acc_words(out, acc);
    }
}

/**
 * @brief Multiply two words
 *
 * @param out The output buffer
 * @param a The first word
 * @param b The second word
 */
static void p256_mul_words(uint32_t *out, const uint32_t *a, const uint32_t *b)
{
    uint32_t i = 0U;
    uint32_t j = 0U;
    uint32_t k = 0U;

    noxtls_fill_u8((uint8_t *)(void *)(out), (size_t)(16U * sizeof(uint32_t)), 0U, (size_t)(16U * sizeof(uint32_t)));

    for(i = 0U; i < 8U; i += 1U) {
        uint64_t carry = 0U;
        for(j = 0U; j < 8U; j += 1U) {
            uint64_t t = (uint64_t)out[i + j] + ((uint64_t)a[i] * (uint64_t)b[j]) + carry;
            out[i + j] = (uint32_t)t;
            carry = t >> 32U;
        }
        k = i + 8U;
        while((carry != 0U) && (k < 16U)) {
            uint64_t t = (uint64_t)out[k] + carry;
            out[k] = (uint32_t)t;
            carry = t >> 32U;
            k += 1U;
        }
    }
}

/**
 * @brief Fold the accumulated words
 *
 * @param acc The accumulated words
 * @param idx The index
 */
static void p256_fold_acc(int64_t *acc, uint32_t idx)
{
    int64_t c = acc[idx];
    uint32_t k = (uint32_t)(idx - 8U);

    acc[idx] = 0;
    acc[k] += c;
    acc[k + 7U] += c;
    acc[k + 6U] -= c;
    acc[k + 3U] -= c;
}

/**
 * @brief Reduce the words
 *
 * @param out The output buffer
 * @param in The input buffer
 */
static void p256_reduce_words(uint32_t *out, const uint32_t *in)
{
    int64_t acc[24];
    uint32_t i = 0U;

    noxtls_fill_u8((uint8_t *)(void *)(acc), sizeof(acc), 0U, sizeof(acc));
    for(i = 0U; i < 16U; i += 1U) {
        acc[i] = (int64_t)in[i];
    }
    p256_reduce_acc_words(out, acc);
}

/**
 * @brief Add two field elements
 *
 * @param out The output buffer
 * @param a The first field element
 * @param b The second field element
 */
static void p256_fe_add(uint8_t *out, const uint8_t *a, const uint8_t *b)
{
    uint32_t aw[8];
    uint32_t bw[8];
    uint32_t rw[8];

    p256_words_from_be(aw, a);
    p256_words_from_be(bw, b);
    p256_words_add_mod(rw, aw, bw);
    p256_words_to_be(out, rw);
}

/**
 * @brief Subtract two field elements
 *
 * @param out The output buffer
 * @param a The first field element
 * @param b The second field element
 */
static void p256_fe_sub(uint8_t *out, const uint8_t *a, const uint8_t *b)
{
    uint32_t aw[8];
    uint32_t bw[8];
    uint32_t rw[8];

    p256_words_from_be(aw, a);
    p256_words_from_be(bw, b);
    p256_words_sub_mod(rw, aw, bw);
    p256_words_to_be(out, rw);
}

/**
 * @brief Multiply two field elements
 *
 * @param out The output buffer
 * @param a The first field element
 * @param b The second field element
 */
static void p256_fe_mul(uint8_t *out, const uint8_t *a, const uint8_t *b)
{
    /* Point formulas can themselves exceed a radio queue budget on a small
     * CPU. Service between complete field multiplies, with per-call scratch
     * still owned by the suspended arithmetic invocation. */
    noxtls_ecc_yield();
    uint32_t aw[8];
    uint32_t bw[8];
    uint32_t prod[16];
    uint32_t rw[8];

    p256_words_from_be(aw, a);
    p256_words_from_be(bw, b);
    p256_mul_words(prod, aw, bw);
    p256_reduce_words(rw, prod);
    p256_words_to_be(out, rw);
}

/**
 * @brief Square a field element
 *
 * @param out The output buffer
 * @param a The field element
 */
static void p256_fe_sqr(uint8_t *out, const uint8_t *a)
{
    p256_fe_mul(out, a, a);
}

/**
 * @brief Double a field element
 *
 * @param out The output buffer
 * @param a The field element
 */
static void p256_fe_double(uint8_t *out, const uint8_t *a)
{
    p256_fe_add(out, a, a);
}

/**
 * @brief Triple a field element
 *
 * @param out The output buffer
 * @param a The field element
 */
static void p256_fe_triple(uint8_t *out, const uint8_t *a)
{
    uint8_t twice[32];

    p256_fe_double(twice, a);
    p256_fe_add(out, twice, a);
}

/**
 * @brief Quadruple a field element
 *
 * @param out The output buffer
 * @param a The field element
 */
static void p256_fe_quad(uint8_t *out, const uint8_t *a)
{
    uint8_t twice[32];

    p256_fe_double(twice, a);
    p256_fe_double(out, twice);
}

/**
 * @brief Octuple a field element
 *
 * @param out The output buffer
 * @param a The field element
 */
static void p256_fe_oct(uint8_t *out, const uint8_t *a)
{
    uint8_t twice[32];
    uint8_t four[32];

    p256_fe_double(twice, a);
    p256_fe_double(four, twice);
    p256_fe_double(out, four);
}

/* Fixed-size 256-bit multiply (BE bytes) -> 512-bit product (BE bytes), no heap allocation. */
/**
 * @brief Multiply two 256-bit field elements
 *
 * @param out The output buffer
 * @param a The first field element
 * @param b The second field element
 */
static void ecc_mul_256_to_512(uint8_t *out64, const uint8_t *a32, const uint8_t *b32)
{
    uint32_t a[8];
    uint32_t b[8];
    uint32_t limbs[16];
    uint64_t carry = 0U;
    uint64_t t = 0U;
    uint32_t i = 0U;
    uint32_t j = 0U;
    uint32_t k = 0U;

    noxtls_fill_u8((uint8_t *)(void *)(limbs), sizeof(limbs), 0U, sizeof(limbs));

    for(i = 0U; i < 8U; i += 1U) {
        uint32_t o = (uint32_t)(32U - ((i + 1U) * 4U));
        a[i] = ((uint32_t)a32[o] << 24U) |
               ((uint32_t)a32[o + 1U] << 16U) |
               ((uint32_t)a32[o + 2U] << 8U) |
               ((uint32_t)a32[o + 3U]);
        b[i] = ((uint32_t)b32[o] << 24U) |
               ((uint32_t)b32[o + 1U] << 16U) |
               ((uint32_t)b32[o + 2U] << 8U) |
               ((uint32_t)b32[o + 3U]);
    }

    for(i = 0U; i < 8U; i += 1U) {
        carry = 0U;
        for(j = 0U; j < 8U; j += 1U) {
            t = (uint64_t)limbs[i + j] + ((uint64_t)a[i] * (uint64_t)b[j]) + carry;
            limbs[i + j] = (uint32_t)(t & 0xFFFFFFFFU);
            carry = t >> 32U;
        }
        k = i + 8U;
        while((carry != 0U) && (k < 16U)) {
            t = (uint64_t)limbs[k] + carry;
            limbs[k] = (uint32_t)(t & 0xFFFFFFFFU);
            carry = t >> 32U;
            k += 1U;
        }
    }

    for(i = 0U; i < 16U; i += 1U) {
        uint32_t w = limbs[i];
        uint32_t o = (uint32_t)(64U - ((i + 1U) * 4U));
        out64[o] = (uint8_t)(w >> 24U);
        out64[o + 1U] = (uint8_t)(w >> 16U);
        out64[o + 2U] = (uint8_t)(w >> 8U);
        out64[o + 3U] = (uint8_t)w;
    }
}

/* ------------------------------------------------------------------------------------------
 * P-521 field multiplication. p = 2^521 - 1 is a Mersenne prime, so with V = H * 2^521 + L,
 * V == H + L (mod p): two folds and a constant-time final step replace the generic bignum
 * division (about 25x faster per field multiply, no heap use).
 * ------------------------------------------------------------------------------------------ */
#define P521_FE_BYTES   66U
#define P521_FE_LIMBS   17U   /* 17 x 32 = 544 bits >= 528-bit (66-octet) operands */
#define P521_PROD_LIMBS 34U
#define P521_TOP_MASK   0x1FFU /* bits 512..520 of limb 16 */

/**
 * @brief Check if the modulus is P-521 (2^521 - 1, 66 octets big-endian)
 *
 * @param p The modulus (public)
 * @param size The size of the modulus
 * @return 1 for P-521, 0 otherwise
 */
static int ecc_modulus_is_secp521r1(const uint8_t *p, uint32_t size)
{
#if defined(NOXTLS_P521_GENERIC_ARITHMETIC) && NOXTLS_P521_GENERIC_ARITHMETIC
    (void)p;
    (void)size;
    return 0;
#else
    uint32_t i;

    if((size != P521_FE_BYTES) || (p == NULL) || (p[0] != 0x01U)) {
        return 0;
    }
    for(i = 1U; i < P521_FE_BYTES; i += 1U) {
        if(p[i] != 0xFFU) {
            return 0;
        }
    }
    return 1;
#endif
}

/**
 * @brief Load a 66-octet big-endian value into 17 little-endian 32-bit limbs
 */
static void p521_limbs_from_be(uint32_t out[P521_FE_LIMBS], const uint8_t in[P521_FE_BYTES])
{
    uint32_t k;

    for(k = 0U; k < P521_FE_LIMBS; k += 1U) {
        out[k] = 0U;
    }
    for(k = 0U; k < P521_FE_BYTES; k += 1U) {
        /* k is the little-endian byte index */
        out[k >> 2U] |= (uint32_t)in[P521_FE_BYTES - 1U - k] << (8U * (k & 3U));
    }
}

/**
 * @brief out = a * b mod (2^521 - 1), canonical, for any 66-octet operands (also >= p).
 *
 * @param out Output, 66 octets big-endian (may alias @p a or @p b)
 * @param a First operand, 66 octets big-endian
 * @param b Second operand, 66 octets big-endian
 */
static void p521_fe_mul(uint8_t *out, const uint8_t *a, const uint8_t *b)
{
    uint32_t al[P521_FE_LIMBS];
    uint32_t bl[P521_FE_LIMBS];
    uint32_t prod[P521_PROD_LIMBS];
    uint32_t s[P521_FE_LIMBS];
    uint64_t t;
    uint64_t carry;
    uint32_t top;
    uint32_t i;
    uint32_t j;

    p521_limbs_from_be(al, a);
    p521_limbs_from_be(bl, b);
    for(i = 0U; i < P521_PROD_LIMBS; i += 1U) {
        prod[i] = 0U;
    }
    for(i = 0U; i < P521_FE_LIMBS; i += 1U) {
        carry = 0U;
        for(j = 0U; j < P521_FE_LIMBS; j += 1U) {
            t = (uint64_t)prod[i + j] + ((uint64_t)al[i] * (uint64_t)bl[j]) + carry;
            prod[i + j] = (uint32_t)(t & 0xFFFFFFFFU);
            carry = t >> 32U;
        }
        prod[i + P521_FE_LIMBS] = (uint32_t)carry;
    }

    /* Fold 1: s = L + H with L = prod mod 2^521 and H = prod >> 521 (< 2^535 since
     * prod < 2^1056). s < 2^536. */
    carry = 0U;
    for(i = 0U; i < P521_FE_LIMBS; i += 1U) {
        uint32_t lo = (i < (P521_FE_LIMBS - 1U)) ? prod[i] : (prod[i] & P521_TOP_MASK);
        uint32_t hi = (prod[16U + i] >> 9U) | (prod[17U + i] << 23U);
        t = (uint64_t)lo + (uint64_t)hi + carry;
        s[i] = (uint32_t)(t & 0xFFFFFFFFU);
        carry = t >> 32U;
    }
    /* Fold 2: bits >= 521 of s (< 2^15, plus the limb carry) go back to bit 0. */
    top = (s[P521_FE_LIMBS - 1U] >> 9U) | ((uint32_t)carry << 23U);
    s[P521_FE_LIMBS - 1U] &= P521_TOP_MASK;
    carry = (uint64_t)top;
    for(i = 0U; i < P521_FE_LIMBS; i += 1U) {
        t = (uint64_t)s[i] + carry;
        s[i] = (uint32_t)(t & 0xFFFFFFFFU);
        carry = t >> 32U;
    }
    /* Fold 3: s < 2^521 + 2^24, so at most one more bit 521. */
    top = s[P521_FE_LIMBS - 1U] >> 9U;
    s[P521_FE_LIMBS - 1U] &= P521_TOP_MASK;
    carry = (uint64_t)top;
    for(i = 0U; i < P521_FE_LIMBS; i += 1U) {
        t = (uint64_t)s[i] + carry;
        s[i] = (uint32_t)(t & 0xFFFFFFFFU);
        carry = t >> 32U;
    }
    /* Now 0 <= s <= p. s == p (all ones) iff s + 1 carries into bit 521; then s + 1 masked
     * to 521 bits is the canonical 0. Branch-free. */
    {
        uint32_t d[P521_FE_LIMBS];
        uint32_t is_p;
        carry = 1U;
        for(i = 0U; i < P521_FE_LIMBS; i += 1U) {
            t = (uint64_t)s[i] + carry;
            d[i] = (uint32_t)(t & 0xFFFFFFFFU);
            carry = t >> 32U;
        }
        is_p = (d[P521_FE_LIMBS - 1U] >> 9U) & 1U;
        carry = (uint64_t)is_p;
        for(i = 0U; i < P521_FE_LIMBS; i += 1U) {
            t = (uint64_t)s[i] + carry;
            s[i] = (uint32_t)(t & 0xFFFFFFFFU);
            carry = t >> 32U;
        }
        s[P521_FE_LIMBS - 1U] &= P521_TOP_MASK;
    }
    for(i = 0U; i < P521_FE_BYTES; i += 1U) {
        out[P521_FE_BYTES - 1U - i] = (uint8_t)(s[i >> 2U] >> (8U * (i & 3U)));
    }
    noxtls_secure_zero(al, sizeof(al));
    noxtls_secure_zero(bl, sizeof(bl));
    noxtls_secure_zero(prod, sizeof(prod));
    noxtls_secure_zero(s, sizeof(s));
}

/* ------------------------------------------------------------------------------------------
 * P-384 field multiplication. p = 2^384 - 2^128 - 2^96 + 2^32 - 1. The 768-bit product is
 * reduced with the NIST fast reduction (FIPS 186-4 D.2.4) on 32-bit words: a fixed sequence
 * of word additions/subtractions, three carry folds of 2^384 == 2^128 + 2^96 - 2^32 + 1 and
 * one masked final subtraction (no data-dependent branches, no heap use).
 * ------------------------------------------------------------------------------------------ */
#define P384_FE_BYTES   48U
#define P384_FE_LIMBS   12U
#define P384_PROD_LIMBS 24U
/* Bias making every carry-propagation input non-negative (|word sum| < 2^37). */
#define P384_CARRY_BIAS ((int64_t)1 << 40)

static const uint8_t s_p384_prime_be[P384_FE_BYTES] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFEU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU
};

static const uint32_t s_p384_prime_words[P384_FE_LIMBS] = {
    0xFFFFFFFFU, 0x00000000U, 0x00000000U, 0xFFFFFFFFU, 0xFFFFFFFEU, 0xFFFFFFFFU,
    0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU
};

/**
 * @brief Check if the modulus is P-384 (48 octets big-endian)
 *
 * @param p The modulus (public)
 * @param size The size of the modulus
 * @return 1 for P-384, 0 otherwise
 */
static int ecc_modulus_is_secp384r1(const uint8_t *p, uint32_t size)
{
#if defined(NOXTLS_P384_GENERIC_ARITHMETIC) && NOXTLS_P384_GENERIC_ARITHMETIC
    (void)p;
    (void)size;
    return 0;
#else
    if((size != P384_FE_BYTES) || (p == NULL)) {
        return 0;
    }
#if NOXTLS_ECC_ENABLE_SECP384R1
    if(p == s_ecc_secp384r1_p) {
        return 1;
    }
#endif
    return (noxtls_ct_memcmp(p, s_p384_prime_be, (size_t)P384_FE_BYTES) == 0) ? 1 : 0;
#endif
}

/** Load a 48-octet big-endian value into 12 little-endian 32-bit limbs. */
static void p384_limbs_from_be(uint32_t out[P384_FE_LIMBS], const uint8_t in[P384_FE_BYTES])
{
    uint32_t k;

    for(k = 0U; k < P384_FE_LIMBS; k += 1U) {
        const uint32_t o = P384_FE_BYTES - (4U * (k + 1U));
        out[k] = ((uint32_t)in[o] << 24U) | ((uint32_t)in[o + 1U] << 16U) |
                 ((uint32_t)in[o + 2U] << 8U) | (uint32_t)in[o + 3U];
    }
}

/**
 * @brief Propagate carries of signed word sums into 12 limbs; returns the carry out of limb 11.
 *
 * Each input word satisfies |acc[i]| < 2^37, so acc[i] + carry + P384_CARRY_BIAS is a
 * non-negative value and the split into limb and carry uses only unsigned operations.
 */
static int64_t p384_carry_words(uint32_t r[P384_FE_LIMBS], const int64_t acc[P384_FE_LIMBS])
{
    int64_t carry = 0;
    uint32_t i;

    for(i = 0U; i < P384_FE_LIMBS; i += 1U) {
        const uint64_t u = (uint64_t)(acc[i] + carry + P384_CARRY_BIAS);
        r[i] = (uint32_t)(u & 0xFFFFFFFFU);
        carry = (int64_t)(u >> 32U) - (P384_CARRY_BIAS >> 32U);
    }
    return carry;
}

/**
 * @brief r = c mod p for a 768-bit product c (24 limbs), canonical, constant time.
 */
static void p384_reduce_words(uint32_t r[P384_FE_LIMBS], const uint32_t c[P384_PROD_LIMBS])
{
    /* Source word of each term at positions 0..11 (24 = zero), FIPS 186-4 D.2.4. */
    static const uint8_t s_terms_add[7][P384_FE_LIMBS] = {
        /* T  */ { 0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U, 9U, 10U, 11U },
        /* S1 (added twice) */ { 24U, 24U, 24U, 24U, 21U, 22U, 23U, 24U, 24U, 24U, 24U, 24U },
        /* S2 */ { 12U, 13U, 14U, 15U, 16U, 17U, 18U, 19U, 20U, 21U, 22U, 23U },
        /* S3 */ { 21U, 22U, 23U, 12U, 13U, 14U, 15U, 16U, 17U, 18U, 19U, 20U },
        /* S4 */ { 24U, 23U, 24U, 20U, 12U, 13U, 14U, 15U, 16U, 17U, 18U, 19U },
        /* S5 */ { 24U, 24U, 24U, 24U, 20U, 21U, 22U, 23U, 24U, 24U, 24U, 24U },
        /* S6 */ { 20U, 24U, 24U, 21U, 22U, 23U, 24U, 24U, 24U, 24U, 24U, 24U }
    };
    static const uint8_t s_terms_sub[3][P384_FE_LIMBS] = {
        /* D1 */ { 23U, 12U, 13U, 14U, 15U, 16U, 17U, 18U, 19U, 20U, 21U, 22U },
        /* D2 */ { 24U, 20U, 21U, 22U, 23U, 24U, 24U, 24U, 24U, 24U, 24U, 24U },
        /* D3 */ { 24U, 24U, 24U, 23U, 23U, 24U, 24U, 24U, 24U, 24U, 24U, 24U }
    };
    uint32_t cz[P384_PROD_LIMBS + 1U];
    int64_t acc[P384_FE_LIMBS];
    uint32_t d[P384_FE_LIMBS];
    int64_t carry;
    uint64_t borrow;
    uint32_t mask;
    uint32_t i;
    uint32_t t;
    uint32_t round;

    for(i = 0U; i < P384_PROD_LIMBS; i += 1U) {
        cz[i] = c[i];
    }
    cz[P384_PROD_LIMBS] = 0U;

    for(i = 0U; i < P384_FE_LIMBS; i += 1U) {
        int64_t v = 0;
        for(t = 0U; t < 7U; t += 1U) {
            v += (int64_t)cz[s_terms_add[t][i]];
        }
        v += (int64_t)cz[s_terms_add[1][i]];   /* 2 * S1 */
        for(t = 0U; t < 3U; t += 1U) {
            v -= (int64_t)cz[s_terms_sub[t][i]];
        }
        acc[i] = v;
    }
    carry = p384_carry_words(r, acc);

    /* Fold the carry (|carry| <= 8) back: carry * 2^384 == carry * (2^128 + 2^96 - 2^32 + 1).
     * Three rounds always clear it (see the bound in the comment above p384_fe_mul). */
    for(round = 0U; round < 3U; round += 1U) {
        for(i = 0U; i < P384_FE_LIMBS; i += 1U) {
            acc[i] = (int64_t)r[i];
        }
        acc[0] += carry;
        acc[1] -= carry;
        acc[3] += carry;
        acc[4] += carry;
        carry = p384_carry_words(r, acc);
    }

    /* r < 2^384 < 2p: subtract p once, keep the difference unless it borrowed. */
    borrow = 0U;
    for(i = 0U; i < P384_FE_LIMBS; i += 1U) {
        const uint64_t v = ((uint64_t)r[i] - (uint64_t)s_p384_prime_words[i]) - borrow;
        d[i] = (uint32_t)(v & 0xFFFFFFFFU);
        borrow = (v >> 63U) & 1U;
    }
    mask = (uint32_t)0U - (uint32_t)borrow;   /* all-ones: r < p, keep r */
    for(i = 0U; i < P384_FE_LIMBS; i += 1U) {
        r[i] = (r[i] & mask) | (d[i] & ~mask);
    }
    noxtls_secure_zero(cz, sizeof(cz));
    noxtls_secure_zero(acc, sizeof(acc));
    noxtls_secure_zero(d, sizeof(d));
}

/**
 * @brief out = a * b mod p384, canonical, for 48-octet operands below 2^384.
 *
 * Bound for the carry folds: after the first propagation the value is r + c * 2^384 with
 * r < 2^384 and -3 <= c <= 8; one fold leaves r' + c' * 2^384 with c' in {-1, 0, 1}, a second
 * fold makes c'' = 0, the third is a no-op kept for a fixed operation sequence.
 *
 * @param out Output, 48 octets big-endian (may alias @p a or @p b)
 * @param a First operand, 48 octets big-endian
 * @param b Second operand, 48 octets big-endian
 */
static void p384_fe_mul(uint8_t *out, const uint8_t *a, const uint8_t *b)
{
    uint32_t al[P384_FE_LIMBS];
    uint32_t bl[P384_FE_LIMBS];
    uint32_t prod[P384_PROD_LIMBS];
    uint32_t r[P384_FE_LIMBS];
    uint64_t t;
    uint64_t carry;
    uint32_t i;
    uint32_t j;

    noxtls_ecc_yield();
    p384_limbs_from_be(al, a);
    p384_limbs_from_be(bl, b);
    for(i = 0U; i < P384_PROD_LIMBS; i += 1U) {
        prod[i] = 0U;
    }
    for(i = 0U; i < P384_FE_LIMBS; i += 1U) {
        carry = 0U;
        for(j = 0U; j < P384_FE_LIMBS; j += 1U) {
            t = (uint64_t)prod[i + j] + ((uint64_t)al[i] * (uint64_t)bl[j]) + carry;
            prod[i + j] = (uint32_t)(t & 0xFFFFFFFFU);
            carry = t >> 32U;
        }
        prod[i + P384_FE_LIMBS] = (uint32_t)carry;
    }
    p384_reduce_words(r, prod);
    for(i = 0U; i < P384_FE_LIMBS; i += 1U) {
        const uint32_t o = P384_FE_BYTES - (4U * (i + 1U));
        out[o] = (uint8_t)(r[i] >> 24U);
        out[o + 1U] = (uint8_t)(r[i] >> 16U);
        out[o + 2U] = (uint8_t)(r[i] >> 8U);
        out[o + 3U] = (uint8_t)r[i];
    }
    noxtls_secure_zero(al, sizeof(al));
    noxtls_secure_zero(bl, sizeof(bl));
    noxtls_secure_zero(prod, sizeof(prod));
    noxtls_secure_zero(r, sizeof(r));
}

/**
 * @brief out = a^(p - 2) mod p (Fermat inverse) with the dedicated P-384 / P-521 multiply.
 *
 * Square-and-multiply over the fixed public exponent p - 2: the operation sequence does
 * not depend on @p a. No heap use. @p a must be reduced (< p); a == 0 yields 0.
 */
static void ecc_fe_inv_fermat(uint8_t *out, const uint8_t *a, const uint8_t *p, uint32_t size, uint32_t field)
{
    uint8_t e[ECC_MAX_KEY_SIZE];
    uint8_t r[ECC_MAX_KEY_SIZE];
    uint8_t base[ECC_MAX_KEY_SIZE];
    uint32_t i;
    uint32_t started = 0U;

    /* e = p - 2 (p is odd and > 2, so only the last byte can borrow) */
    noxtls_copy_u8(e, sizeof(e), p, (size_t)size);
    {
        uint32_t borrow = 2U;
        for(i = size; (i > 0U) && (borrow != 0U); i -= 1U) {
            const uint32_t v = (uint32_t)e[i - 1U];
            e[i - 1U] = (uint8_t)((v - borrow) & 0xFFU);
            borrow = (v < borrow) ? 1U : 0U;
        }
    }
    noxtls_copy_u8(base, sizeof(base), a, (size_t)size);
    (void)noxtls_bn_zero(r, size);
    r[size - 1U] = 0x01U;
    for(i = 0U; i < (size * 8U); i += 1U) {
        const uint32_t bit = ((uint32_t)e[i >> 3U] >> (7U - (i & 7U))) & 1U;
        if(started != 0U) {
            if(field == ECC_FE_P384) { p384_fe_mul(r, r, r); } else { p521_fe_mul(r, r, r); }
        }
        if(bit != 0U) {
            if(field == ECC_FE_P384) { p384_fe_mul(r, r, base); } else { p521_fe_mul(r, r, base); }
            started = 1U;
        }
    }
    noxtls_copy_u8(out, (size_t)size, r, (size_t)size);
    noxtls_secure_zero(r, sizeof(r));
    noxtls_secure_zero(base, sizeof(base));
}

/**
 * @brief Merge a field/point operation status into a running status
 *
 * The first failure is sticky: once @p acc reports an error, later statuses
 * are ignored, so a chain of field operations reports the first failure.
 *
 * @param acc The running status
 * @param rc The status of the latest operation
 * @return The merged status
 */
static noxtls_return_t ecc_rc_merge(noxtls_return_t acc, noxtls_return_t rc)
{
    return (acc != NOXTLS_RETURN_SUCCESS) ? acc : rc;
}

/* Field multiply + reduce helper. Uses specialized 32-byte multiply on P-256-class curves. */
/**
 * @brief Multiply two field elements modulo the modulus
 *
 * @param out The output buffer
 * @param a The first field element
 * @param b The second field element
 * @param p The modulus
 * @param size The size of the operands and modulus
 * @param tmp2n The temporary buffer
 * @return NOXTLS_RETURN_SUCCESS, or the bignum error (the output is zeroed on failure)
 */
static noxtls_return_t ecc_mul_mod(uint8_t *out, const uint8_t *a, const uint8_t *b, const uint8_t *p, uint32_t size, uint8_t *tmp2n)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if((size == 0U) || (size > ECC_MAX_KEY_SIZE)) {
        return NOXTLS_RETURN_FAILED;
    }
    if(ecc_modulus_is_secp256r1(p, size) != 0) {
        p256_fe_mul(out, a, b);
    } else if(ecc_modulus_is_secp384r1(p, size) != 0) {
        p384_fe_mul(out, a, b);
    } else if(ecc_modulus_is_secp521r1(p, size) != 0) {
        (void)tmp2n;
        p521_fe_mul(out, a, b);
    } else if(size == 32U) {
        uint8_t prod64[64];
        ecc_mul_256_to_512(prod64, a, b);
        rc = noxtls_bn_mod(out, prod64, 64U, p, 32U);
    } else {
        rc = noxtls_bn_mul(tmp2n, a, size, b, size);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_bn_mod(out, tmp2n, size * 2U, p, size);
        }
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_bn_zero(out, size);
    }
    return rc;
}

/**
 * @brief Multiply a field element by a one-byte constant modulo the modulus
 *
 * @param out The output buffer (may alias @p tmp)
 * @param a The field element
 * @param k The one-byte constant
 * @param p The modulus
 * @param size The size of the operands and modulus
 * @param tmp Temporary buffer of at least size + 1 bytes
 * @return NOXTLS_RETURN_SUCCESS, or the bignum error (the output is zeroed on failure)
 */
static noxtls_return_t ecc_mul_small_mod(uint8_t *out, const uint8_t *a, const uint8_t *k,
                                         const uint8_t *p, uint32_t size, uint8_t *tmp)
{
    noxtls_return_t rc;

    if(ecc_modulus_is_secp384r1(p, size) != 0) {
        uint8_t k_fe[P384_FE_BYTES];
        (void)noxtls_bn_zero(k_fe, P384_FE_BYTES);
        k_fe[P384_FE_BYTES - 1U] = k[0];
        p384_fe_mul(out, a, k_fe);
        (void)tmp;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(ecc_modulus_is_secp521r1(p, size) != 0) {
        uint8_t k_fe[P521_FE_BYTES];
        (void)noxtls_bn_zero(k_fe, P521_FE_BYTES);
        k_fe[P521_FE_BYTES - 1U] = k[0];
        p521_fe_mul(out, a, k_fe);
        return NOXTLS_RETURN_SUCCESS;
    }
    rc = noxtls_bn_mul(tmp, a, size, k, 1U);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_bn_mod(out, tmp, size + 1U, p, size);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_bn_zero(out, size);
    }
    return rc;
}

/**
 * @brief Compute (a - b) mod p (big-endian)
 *
 * Uses (a - b) mod p = (a + (p - b)) mod p when a < b to avoid unsigned wrap handling.
 *
 * @param out The output buffer
 * @param a The first field element
 * @param b The second field element
 * @param p The modulus
 * @param size The size of the operands and modulus
 * @return NOXTLS_RETURN_SUCCESS, or NOXTLS_RETURN_FAILED for an invalid size
 */
static noxtls_return_t ecc_mod_sub(uint8_t *out, const uint8_t *a, const uint8_t *b, const uint8_t *p, uint32_t size)
{
    if(ecc_modulus_is_secp256r1(p, size) != 0) {
        p256_fe_sub(out, a, b);
        return NOXTLS_RETURN_SUCCESS;
    }
    if((size == 0U) || (size > ECC_MAX_KEY_SIZE)) {
        return NOXTLS_RETURN_FAILED;
    }
    if(noxtls_bn_cmp(a, b, size) >= 0) {
        /* a,b < p so (a-b) is already canonical. */
        (void)noxtls_bn_sub(out, a, b, size);
    } else {
        uint8_t p_minus_b[ECC_MAX_KEY_SIZE];
        (void)noxtls_bn_zero(p_minus_b, size);
        (void)noxtls_bn_sub(p_minus_b, p, b, size);  /* p >= b, so p_minus_b = p - b */
        (void)noxtls_bn_add(out, a, p_minus_b, size); /* (a - b) mod p = a + (p - b); result < p */
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Compute (a + b) mod p (big-endian)
 *
 * @param out Output buffer
 * @param a First operand
 * @param b Second operand
 * @param p Modulus
 * @param size Size of the operands and modulus
 * @return NOXTLS_RETURN_SUCCESS, or NOXTLS_RETURN_FAILED for an invalid size
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static noxtls_return_t ecc_mod_add(uint8_t *out, const uint8_t *a, const uint8_t *b, const uint8_t *p, uint32_t size)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint16_t carry = 0U;
    uint16_t borrow = 0U;
    uint32_t i = 0U;

    if(ecc_modulus_is_secp256r1(p, size) != 0) {
        p256_fe_add(out, a, b);
        return NOXTLS_RETURN_SUCCESS;
    }

    if((size == 0U) || (size == UINT32_MAX) || (size > ECC_MAX_KEY_SIZE)) {
        return NOXTLS_RETURN_FAILED;
    }

    for(i = size; i > 0U; i -= 1U) {
        uint16_t sum = (uint16_t)a[i - 1U] + (uint16_t)b[i - 1U] + carry;
        out[i - 1U] = (uint8_t)(sum & 0xFFU);
        carry = (uint16_t)((uint32_t)sum >> 8U);
    }
    /* Since a,b < p, sum < 2p. Reduce with a single conditional subtraction. */
    if((carry != 0U) || (noxtls_bn_cmp(out, p, size) >= 0)) {
        for(i = size; i > 0U; i -= 1U) {
            uint16_t ai = (uint16_t)out[i - 1U];
            uint16_t bi = (uint16_t)p[i - 1U] + borrow;
            if(ai < bi) {
                out[i - 1U] = (uint8_t)(ai + 256U - bi);
                borrow = 1U;
            } else {
                out[i - 1U] = (uint8_t)(ai - bi);
                borrow = 0U;
            }
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Double a Jacobian point
 *
 * @param out The output buffer
 * @param P The input point
 * @return The return value
 */
static noxtls_return_t p256_jpoint_double(ecc_jpoint_t *out, const ecc_jpoint_t *P)
{
    uint32_t y_words[8];
    uint8_t delta[32];
    uint8_t gamma[32];
    uint8_t beta[32];
    uint8_t alpha[32];
    uint8_t gamma2[32];
    uint8_t tmp1[32];
    uint8_t tmp2[32];
    uint8_t tmp3[32];

    p256_words_from_be(y_words, P->Y);
    if((p256_words_is_zero(y_words) != 0) || (noxtls_bn_is_zero(P->Z, 32U) != 0)) {
        (void)noxtls_bn_zero(out->X, 32U);
        (void)noxtls_bn_zero(out->Y, 32U);
        (void)noxtls_bn_zero(out->Z, 32U);
        out->size = 32U;
        return NOXTLS_RETURN_SUCCESS;
    }

    p256_fe_sqr(delta, P->Z);          /* delta = Z^2 */
    p256_fe_sqr(gamma, P->Y);          /* gamma = Y^2 */
    p256_fe_mul(beta, P->X, gamma);    /* beta = X*gamma */

    p256_fe_sub(tmp1, P->X, delta);
    p256_fe_add(tmp2, P->X, delta);
    p256_fe_mul(alpha, tmp1, tmp2);
    p256_fe_triple(alpha, alpha);      /* alpha = 3U * (X-delta)*(X+delta) */

    p256_fe_sqr(out->X, alpha);
    p256_fe_oct(tmp3, beta);           /* 8*beta */
    p256_fe_sub(out->X, out->X, tmp3);

    p256_fe_add(tmp1, P->Y, P->Z);
    p256_fe_sqr(out->Z, tmp1);
    p256_fe_sub(out->Z, out->Z, gamma);
    p256_fe_sub(out->Z, out->Z, delta);

    p256_fe_quad(tmp1, beta);          /* 4*beta */
    p256_fe_sub(tmp1, tmp1, out->X);
    p256_fe_mul(tmp1, alpha, tmp1);
    p256_fe_sqr(gamma2, gamma);
    p256_fe_oct(tmp2, gamma2);         /* 8*gamma^2 */
    p256_fe_sub(out->Y, tmp1, tmp2);

    out->size = 32U;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Add a Jacobian point to an affine point
 *
 * @param out The output buffer
 * @param P The input point
 * @param Q_affine The affine point
 * @return The return value
 */
static noxtls_return_t p256_jpoint_add_mixed(ecc_jpoint_t *out,
                                             const ecc_jpoint_t *P,
                                             const ecc_jpoint_t *Q_affine)
{
    uint8_t Z1Z1[32];
    uint8_t U2[32];
    uint8_t S2[32];
    uint8_t H[32];
    uint8_t HH[32];
    uint8_t I[32];
    uint8_t J[32];
    uint8_t R[32];
    uint8_t r[32];
    uint8_t V[32];
    uint8_t tmp1[32];
    uint8_t tmp2[32];
    uint32_t h_words[8];
    uint32_t r_words[8];

    if(noxtls_bn_is_zero(P->Z, 32U) != 0) {
        (void)noxtls_bn_copy(out->X, Q_affine->X, 32U);
        (void)noxtls_bn_copy(out->Y, Q_affine->Y, 32U);
        (void)noxtls_bn_zero(out->Z, 32U);
        out->Z[31] = 0x01U;
        out->size = 32U;
        return NOXTLS_RETURN_SUCCESS;
    }

    if(noxtls_bn_is_zero(Q_affine->Z, 32U) != 0) {
        (void)noxtls_bn_copy(out->X, P->X, 32U);
        (void)noxtls_bn_copy(out->Y, P->Y, 32U);
        (void)noxtls_bn_copy(out->Z, P->Z, 32U);
        out->size = 32U;
        return NOXTLS_RETURN_SUCCESS;
    }

    p256_fe_sqr(Z1Z1, P->Z);
    p256_fe_mul(U2, Q_affine->X, Z1Z1);
    p256_fe_mul(tmp1, Z1Z1, P->Z);
    p256_fe_mul(S2, Q_affine->Y, tmp1);

    p256_fe_sub(H, U2, P->X);
    p256_fe_sub(R, S2, P->Y);
    p256_words_from_be(h_words, H);
    p256_words_from_be(r_words, R);
    if(p256_words_is_zero(h_words) != 0) {
        if(p256_words_is_zero(r_words) != 0) {
            return p256_jpoint_double(out, P);
        }
        (void)noxtls_bn_zero(out->X, 32U);
        (void)noxtls_bn_zero(out->Y, 32U);
        (void)noxtls_bn_zero(out->Z, 32U);
        out->size = 32U;
        return NOXTLS_RETURN_SUCCESS;
    }

    p256_fe_sqr(HH, H);
    p256_fe_quad(I, HH);               /* I = 4*HH */
    p256_fe_mul(J, H, I);
    p256_fe_double(r, R);              /* r = 2U * (S2 - Y1) */
    p256_fe_mul(V, P->X, I);

    p256_fe_sqr(out->X, r);
    p256_fe_sub(out->X, out->X, J);
    p256_fe_double(tmp1, V);
    p256_fe_sub(out->X, out->X, tmp1);

    p256_fe_sub(tmp1, V, out->X);
    p256_fe_mul(tmp1, r, tmp1);
    p256_fe_mul(tmp2, P->Y, J);
    p256_fe_double(tmp2, tmp2);
    p256_fe_sub(out->Y, tmp1, tmp2);

    p256_fe_add(tmp1, P->Z, H);
    p256_fe_sqr(out->Z, tmp1);
    p256_fe_sub(out->Z, out->Z, Z1Z1);
    p256_fe_sub(out->Z, out->Z, HH);

    out->size = 32U;
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t p256_jpoint_add(ecc_jpoint_t *out,
                                       const ecc_jpoint_t *P,
                                       const ecc_jpoint_t *Q)
{
    uint8_t Z1Z1[32];
    uint8_t Z2Z2[32];
    uint8_t U1[32];
    uint8_t U2[32];
    uint8_t S1[32];
    uint8_t S2[32];
    uint8_t H[32];
    uint8_t HH[32];
    uint8_t HHH[32];
    uint8_t R[32];
    uint8_t V[32];
    uint8_t tmp1[32];
    uint32_t h_words[8];
    uint32_t r_words[8];

    if(noxtls_bn_is_zero(P->Z, 32U) != 0) {
        (void)noxtls_bn_copy(out->X, Q->X, 32U);
        (void)noxtls_bn_copy(out->Y, Q->Y, 32U);
        (void)noxtls_bn_copy(out->Z, Q->Z, 32U);
        out->size = 32U;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(noxtls_bn_is_zero(Q->Z, 32U) != 0) {
        (void)noxtls_bn_copy(out->X, P->X, 32U);
        (void)noxtls_bn_copy(out->Y, P->Y, 32U);
        (void)noxtls_bn_copy(out->Z, P->Z, 32U);
        out->size = 32U;
        return NOXTLS_RETURN_SUCCESS;
    }

    p256_fe_sqr(Z1Z1, P->Z);
    p256_fe_sqr(Z2Z2, Q->Z);
    p256_fe_mul(U1, P->X, Z2Z2);
    p256_fe_mul(U2, Q->X, Z1Z1);
    p256_fe_mul(tmp1, Z2Z2, Q->Z);
    p256_fe_mul(S1, P->Y, tmp1);
    p256_fe_mul(tmp1, Z1Z1, P->Z);
    p256_fe_mul(S2, Q->Y, tmp1);
    p256_fe_sub(H, U2, U1);
    p256_fe_sub(R, S2, S1);
    p256_words_from_be(h_words, H);
    p256_words_from_be(r_words, R);
    if(p256_words_is_zero(h_words) != 0) {
        if(p256_words_is_zero(r_words) != 0) {
            return p256_jpoint_double(out, P);
        }
        (void)noxtls_bn_zero(out->X, 32U);
        (void)noxtls_bn_zero(out->Y, 32U);
        (void)noxtls_bn_zero(out->Z, 32U);
        out->size = 32U;
        return NOXTLS_RETURN_SUCCESS;
    }

    p256_fe_sqr(HH, H);
    p256_fe_mul(HHH, H, HH);
    p256_fe_mul(V, U1, HH);
    p256_fe_sqr(out->X, R);
    p256_fe_sub(out->X, out->X, HHH);
    p256_fe_double(tmp1, V);
    p256_fe_sub(out->X, out->X, tmp1);
    p256_fe_sub(tmp1, V, out->X);
    p256_fe_mul(tmp1, R, tmp1);
    p256_fe_mul(out->Y, S1, HHH);
    p256_fe_sub(out->Y, tmp1, out->Y);
    p256_fe_mul(tmp1, P->Z, Q->Z);
    p256_fe_mul(out->Z, tmp1, H);
    out->size = 32U;
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t ecc_jpoint_to_affine(uint8_t *x, uint8_t *y, const ecc_jpoint_t *J, const ecc_curve_params_t *curve);

/**
 * @brief Jacobian doubling: out = 2*P. No inversion. Identity (Z=0) remains identity.
 *
 * @param out Output buffer
 * @param P Input point
 * @param curve Curve parameters
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if ctx is NULL
 */
static ECC_NOINLINE noxtls_return_t ecc_jpoint_double_generic(ecc_jpoint_t *out, const ecc_jpoint_t *P, const ecc_curve_params_t *curve)
{
    uint32_t size = (uint32_t)(curve->size);
    const uint8_t *p = curve->p;
    const uint8_t *a = curve->a;
    uint8_t t1[ECC_MAX_KEY_SIZE * 2U];
    uint8_t t2[ECC_MAX_KEY_SIZE * 2U];
    uint8_t t3[ECC_MAX_KEY_SIZE * 2U];
    uint8_t S[ECC_MAX_KEY_SIZE];
    uint8_t M[ECC_MAX_KEY_SIZE];
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    static const uint8_t two_arr[1] = {0x02U};
    static const uint8_t three_arr[1] = {0x03U};
    static const uint8_t four_arr[1] = {0x04U};
    static const uint8_t eight_arr[1] = {0x08U};
    if((size == 0U) || (size > ECC_MAX_KEY_SIZE) || (size > (uint32_t)(UINT32_MAX / 2U)) || (size == UINT32_MAX)) {
        return NOXTLS_RETURN_FAILED;
    }

    if((ecc_jpoint_is_infinity(P, size) != 0)) {
        (void)noxtls_bn_zero(out->X, size);
        (void)noxtls_bn_zero(out->Y, size);
        (void)noxtls_bn_zero(out->Z, size);
        out->size = size;
        return NOXTLS_RETURN_SUCCESS;
    }

    (void)noxtls_bn_zero(t1, size * 2U);
    (void)noxtls_bn_zero(t2, size * 2U);
    (void)noxtls_bn_zero(t3, size * 2U);
    (void)noxtls_bn_zero(S, size);
    (void)noxtls_bn_zero(M, size);

    /* Every field operation can fail (bignum allocation); the first failure
     * is kept in rc and the output is wiped instead of returning a wrong point. */
    /* S = 4*X1*Y1^2 mod p */
    rc = ecc_rc_merge(rc, ecc_mul_mod(t2, P->Y, P->Y, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mul_mod(t2, P->X, t2, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mul_small_mod(S, t2, four_arr, p, size, t1));

    /* M = 3*X1^2 + a*Z1^4 mod p */
    rc = ecc_rc_merge(rc, ecc_mul_mod(t2, P->X, P->X, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mul_small_mod(t2, t2, three_arr, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mul_mod(t3, P->Z, P->Z, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mul_mod(t3, t3, t3, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mul_mod(t3, a, t3, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mod_add(M, t2, t3, p, size));

    /* X3 = M^2 - 2*S mod p */
    rc = ecc_rc_merge(rc, ecc_mul_mod(t2, M, M, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mul_small_mod(t3, S, two_arr, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mod_sub(out->X, t2, t3, p, size));

    /* Y3 = M*(S - X3) - 8*Y1^4 mod p */
    rc = ecc_rc_merge(rc, ecc_mod_sub(t2, S, out->X, p, size));
    rc = ecc_rc_merge(rc, ecc_mul_mod(t2, M, t2, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mul_mod(t3, P->Y, P->Y, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mul_mod(t3, t3, t3, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mul_small_mod(t3, t3, eight_arr, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mod_sub(out->Y, t2, t3, p, size));

    /* Z3 = 2*Y1*Z1 mod p */
    rc = ecc_rc_merge(rc, ecc_mul_mod(t2, P->Y, P->Z, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mul_small_mod(out->Z, t2, two_arr, p, size, t1));

    if(rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_bn_zero(out->X, size);
        (void)noxtls_bn_zero(out->Y, size);
        (void)noxtls_bn_zero(out->Z, size);
    }
    out->size = size;
    return rc;
}

static ECC_NOINLINE noxtls_return_t ecc_jpoint_add_generic(ecc_jpoint_t *out, const ecc_jpoint_t *P, const ecc_jpoint_t *Q, const ecc_curve_params_t *curve)
{
    uint32_t size = (uint32_t)(curve->size);
    const uint8_t *p = curve->p;
    uint8_t U1[ECC_MAX_KEY_SIZE];
    uint8_t U2[ECC_MAX_KEY_SIZE];
    uint8_t S1[ECC_MAX_KEY_SIZE];
    uint8_t S2[ECC_MAX_KEY_SIZE];
    uint8_t H[ECC_MAX_KEY_SIZE];
    uint8_t R[ECC_MAX_KEY_SIZE];
    uint8_t t1[ECC_MAX_KEY_SIZE * 2U];
    uint8_t t2[ECC_MAX_KEY_SIZE * 2U];
    uint8_t t3[ECC_MAX_KEY_SIZE * 2U];
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    static const uint8_t two_arr[1] = {0x02U};
    if((size == 0U) || (size > ECC_MAX_KEY_SIZE) || (size > (uint32_t)(UINT32_MAX / 2U))) {
        return NOXTLS_RETURN_FAILED;
    }

    (void)noxtls_bn_zero(U1, size);
    (void)noxtls_bn_zero(U2, size);
    (void)noxtls_bn_zero(S1, size);
    (void)noxtls_bn_zero(S2, size);
    (void)noxtls_bn_zero(H, size);
    (void)noxtls_bn_zero(R, size);
    (void)noxtls_bn_zero(t1, size * 2U);
    (void)noxtls_bn_zero(t2, size * 2U);
    (void)noxtls_bn_zero(t3, size * 2U);

    /* Z1^2, Z2^2 */
    rc = ecc_rc_merge(rc, ecc_mul_mod(t2, P->Z, P->Z, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mul_mod(t3, Q->Z, Q->Z, p, size, t1));
    /* U1 = X1*Z2^2, U2 = X2*Z1^2 */
    rc = ecc_rc_merge(rc, ecc_mul_mod(U1, P->X, t3, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mul_mod(U2, Q->X, t2, p, size, t1));
    /* Z2^3 = Z2^2*Z2, Z1^3 = Z1^2*Z1 */
    rc = ecc_rc_merge(rc, ecc_mul_mod(t3, t3, Q->Z, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mul_mod(t2, t2, P->Z, p, size, t1));
    /* S1 = Y1*Z2^3, S2 = Y2*Z1^3 */
    rc = ecc_rc_merge(rc, ecc_mul_mod(S1, P->Y, t3, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mul_mod(S2, Q->Y, t2, p, size, t1));

    /* H = U2 - U1, R = S2 - S1 */
    rc = ecc_rc_merge(rc, ecc_mod_sub(H, U2, U1, p, size));
    rc = ecc_rc_merge(rc, ecc_mod_sub(R, S2, S1, p, size));

    /* H and R select the special cases below: they are only meaningful when
     * every operation above succeeded. */
    if(rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_bn_zero(out->X, size);
        (void)noxtls_bn_zero(out->Y, size);
        (void)noxtls_bn_zero(out->Z, size);
        out->size = size;
        return rc;
    }

    if(noxtls_bn_is_zero(H, size) != 0) {
        /* Same x coordinate: P == Q (R == 0) or P == -Q (R != 0). Precompute
         * tables and joint (Shamir) tables legitimately hit P == Q, e.g. when one
         * muladd operand is a small multiple of the other, so double here
         * instead of failing. P is copied first so out may alias it. */
        if(noxtls_bn_is_zero(R, size) != 0) {
            ecc_jpoint_t P_copy;
            noxtls_copy_u8((uint8_t *)(void *)(&P_copy), sizeof(P_copy), (const uint8_t *)(const void *)(P), sizeof(ecc_jpoint_t));
            return ecc_jpoint_double_generic(out, &P_copy, curve);
        }
        (void)noxtls_bn_zero(out->X, size);
        (void)noxtls_bn_zero(out->Y, size);
        (void)noxtls_bn_zero(out->Z, size);
        out->size = size; /* infinity */
        return NOXTLS_RETURN_SUCCESS;
    }

    /* X3 = R^2 - H^3 - 2*U1*H^2; also keep U1*H^2 and H^3 for Y3 */
    rc = ecc_rc_merge(rc, ecc_mul_mod(t2, H, H, p, size, t1));         /* t2 = H^2 */
    rc = ecc_rc_merge(rc, ecc_mul_mod(t3, t2, H, p, size, t1));        /* t3 = H^3 */
    rc = ecc_rc_merge(rc, ecc_mul_mod(t2, R, R, p, size, t1));         /* t2 = R^2 */
    rc = ecc_rc_merge(rc, ecc_mod_sub(t2, t2, t3, p, size));           /* t2 = R^2 - H^3 */
    rc = ecc_rc_merge(rc, ecc_mul_mod(t3, U1, H, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mul_mod(t3, t3, H, p, size, t1));        /* t3 = U1*H^2 */
    rc = ecc_rc_merge(rc, ecc_mul_small_mod(t1, t3, two_arr, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mod_sub(out->X, t2, t1, p, size));
    /* Y3 = R*(U1*H^2 - X3) - S1*H^3; t3 = U1*H^2, need H^3 again */
    rc = ecc_rc_merge(rc, ecc_mod_sub(t2, t3, out->X, p, size));       /* t2 = U1*H^2 - X3 */
    rc = ecc_rc_merge(rc, ecc_mul_mod(t2, R, t2, p, size, t1));        /* t2 = R*(U1*H^2 - X3) */
    rc = ecc_rc_merge(rc, ecc_mul_mod(t3, H, H, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mul_mod(t3, t3, H, p, size, t1));        /* t3 = H^3 */
    rc = ecc_rc_merge(rc, ecc_mul_mod(t3, S1, t3, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mod_sub(out->Y, t2, t3, p, size));

    /* Z3 = Z1*Z2*H */
    rc = ecc_rc_merge(rc, ecc_mul_mod(t2, P->Z, Q->Z, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mul_mod(out->Z, t2, H, p, size, t1));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_bn_zero(out->X, size);
        (void)noxtls_bn_zero(out->Y, size);
        (void)noxtls_bn_zero(out->Z, size);
    }
    out->size = size;
    return rc;
}

/**
 * @brief Jacobian doubling dispatch: dedicated P-256 formulas, otherwise the generic body.
 */
static noxtls_return_t ecc_jpoint_double(ecc_jpoint_t *out, const ecc_jpoint_t *P, const ecc_curve_params_t *curve)
{
    if(ecc_curve_is_secp256r1(curve) != 0) {
        return p256_jpoint_double(out, P);
    }
    return ecc_jpoint_double_generic(out, P, curve);
}

/* Jacobian add: out = P + Q. No inversion. Handles identity, P == Q (doubles) and P == -Q (identity). */
/**
 * @brief Add two Jacobian points
 *
 * @param out The output buffer
 * @param P The first point
 * @param Q The second point
 * @param curve The curve
 * @return The return value
 */
/**
 * @brief Jacobian add dispatch: identities, then the dedicated P-256 (mixed) formulas,
 *        otherwise the generic body. The generic temporaries live only in the
 *        out-of-line generic frame, never on the P-256 path.
 */
static noxtls_return_t ecc_jpoint_add(ecc_jpoint_t *out, const ecc_jpoint_t *P, const ecc_jpoint_t *Q, const ecc_curve_params_t *curve)
{
    uint32_t size = (uint32_t)(curve->size);

    if((size == 0U) || (size > ECC_MAX_KEY_SIZE)) {
        return NOXTLS_RETURN_FAILED;
    }
    if((ecc_jpoint_is_infinity(P, size) != 0)) {
        (void)noxtls_bn_copy(out->X, Q->X, size);
        (void)noxtls_bn_copy(out->Y, Q->Y, size);
        (void)noxtls_bn_copy(out->Z, Q->Z, size);
        out->size = size;
        return NOXTLS_RETURN_SUCCESS;
    }
    if((ecc_jpoint_is_infinity(Q, size) != 0)) {
        (void)noxtls_bn_copy(out->X, P->X, size);
        (void)noxtls_bn_copy(out->Y, P->Y, size);
        (void)noxtls_bn_copy(out->Z, P->Z, size);
        out->size = size;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(ecc_curve_is_secp256r1(curve) != 0) {
        if(noxtls_bn_is_one(Q->Z, size) != 0) {
            return p256_jpoint_add_mixed(out, P, Q);
        }
        if(noxtls_bn_is_one(P->Z, size) != 0) {
            return p256_jpoint_add_mixed(out, Q, P);
        }
        return p256_jpoint_add(out, P, Q);
    }
    return ecc_jpoint_add_generic(out, P, Q, curve);
}

/**
 * @brief ECC Point Addition: R = P + Q
 *
 * Uses chord-tangent method for P != Q, or point doubling for P == Q
 *
 * @param result The result
 * @param p1 The first point
 * @param p2 The second point
 * @param curve The curve
 * @return The return value
 */
noxtls_return_t noxtls_ecc_point_add(ecc_point_t *result, const ecc_point_t *p1, const ecc_point_t *p2, const ecc_curve_params_t *curve)
{
    uint8_t temp1[ECC_MAX_KEY_SIZE];
    uint8_t temp2[ECC_MAX_KEY_SIZE];
    uint32_t size = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if((result == NULL) || (p1 == NULL) || (p2 == NULL) || (curve == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    size = curve->size;
    if((size == 0U) || (size > ECC_MAX_KEY_SIZE) || (size > (uint32_t)(UINT32_MAX / 2U))) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Handle point at infinity cases */
    if((ecc_point_is_infinity(p1, size) != 0)) {
        (void)noxtls_bn_copy(result->x, p2->x, size);
        (void)noxtls_bn_copy(result->y, p2->y, size);
        result->size = size;
        return rc;
    }

    if((ecc_point_is_infinity(p2, size) != 0)) {
        (void)noxtls_bn_copy(result->x, p1->x, size);
        (void)noxtls_bn_copy(result->y, p1->y, size);
        result->size = size;
        return rc;
    }

    /* Check if P == -Q (P + (-Q) = infinity) */
    (void)noxtls_bn_copy(temp1, p2->y, size);
    (void)noxtls_bn_sub(temp2, curve->p, temp1, size);  /* temp2 = p - y2 */
    rc = noxtls_bn_mod(temp2, temp2, size, curve->p, size);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_bn_zero(result->x, size);
        (void)noxtls_bn_zero(result->y, size);
        result->size = size;
        return rc;
    }

    if((noxtls_bn_cmp(p1->x, p2->x, size) == 0) && (noxtls_bn_cmp(p1->y, temp2, size) == 0)) {
        /* Result is point at infinity */
        (void)noxtls_bn_zero(result->x, size);
        (void)noxtls_bn_zero(result->y, size);
        result->size = size;
        return rc;
    }

    /* Use Jacobian add/double + to_affine for correct, consistent results (same formulas as scalar mult path). */
    {
        ecc_jpoint_t J1;
        ecc_jpoint_t J2;
        ecc_jpoint_t Jout;
        noxtls_fill_u8((uint8_t *)(void *)(&J1), sizeof(J1), 0U, sizeof(J1));
        noxtls_fill_u8((uint8_t *)(void *)(&J2), sizeof(J2), 0U, sizeof(J2));
        noxtls_fill_u8((uint8_t *)(void *)(&Jout), sizeof(Jout), 0U, sizeof(Jout));
        J1.size = size;
        J2.size = size;
        Jout.size = size;
        (void)noxtls_bn_copy(J1.X, p1->x, size);
        (void)noxtls_bn_copy(J1.Y, p1->y, size);
        (void)noxtls_bn_zero(J1.Z, size);
        J1.Z[size - 1U] = 1U;
        (void)noxtls_bn_copy(J2.X, p2->x, size);
        (void)noxtls_bn_copy(J2.Y, p2->y, size);
        (void)noxtls_bn_zero(J2.Z, size);
        J2.Z[size - 1U] = 1U;

        if(ecc_point_equal(p1, p2, size) != 0) {
            rc = ecc_jpoint_double(&Jout, &J1, curve);
        } else {
            rc = ecc_jpoint_add(&Jout, &J1, &J2, curve);
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_bn_zero(result->x, size);
            (void)noxtls_bn_zero(result->y, size);
            result->size = size;
            return rc;
        }
        if((ecc_jpoint_is_infinity(&Jout, size) != 0)) {
            (void)noxtls_bn_zero(result->x, size);
            (void)noxtls_bn_zero(result->y, size);
            result->size = size;
            return rc;
        }
        rc = ecc_jpoint_to_affine(result->x, result->y, &Jout, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_bn_zero(result->x, size);
            (void)noxtls_bn_zero(result->y, size);
            result->size = size;
            return rc;
        }
        result->size = size;
    }

    return rc;
}

/**
 * @brief ECC Point Doubling: R = 2P
 *
 * @param result Output point
 * @param p Input point
 * @param curve Curve parameters
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if result is NULL
 */
noxtls_return_t noxtls_ecc_point_double(ecc_point_t *result, const ecc_point_t *p, const ecc_curve_params_t *curve)
{
    /* Point doubling is a special case of point addition (P + P) */
    return noxtls_ecc_point_add(result, p, p, curve);
}

/**
 * @brief Convert Jacobian (X,Y,Z) to affine (x,y). Single mod_inv(Z); then x = X*inv^2, y = Y*inv^3.
 *
 * @param x Output x coordinate
 * @param y Output y coordinate
 * @param J Input Jacobian point
 * @param curve Curve parameters
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if result is NULL
 */
static noxtls_return_t ecc_jpoint_to_affine(uint8_t *x, uint8_t *y, const ecc_jpoint_t *J, const ecc_curve_params_t *curve)
{
    uint32_t size = (uint32_t)(curve->size);
    const uint8_t *p = curve->p;
    uint8_t inv[ECC_MAX_KEY_SIZE];
    uint8_t z2[ECC_MAX_KEY_SIZE];
    uint8_t z3[ECC_MAX_KEY_SIZE];
    uint8_t t1[ECC_MAX_KEY_SIZE * 2U];
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    if((size == 0U) || (size > ECC_MAX_KEY_SIZE) || (size > (uint32_t)(UINT32_MAX / 2U))) {
        return NOXTLS_RETURN_FAILED;
    }

    if((ecc_jpoint_is_infinity(J, size) != 0)) {
        (void)noxtls_bn_zero(x, size);
        (void)noxtls_bn_zero(y, size);
        return NOXTLS_RETURN_SUCCESS;
    }

    (void)noxtls_bn_zero(inv, size);
    (void)noxtls_bn_zero(z2, size);
    (void)noxtls_bn_zero(z3, size);
    (void)noxtls_bn_zero(t1, size * 2U);

    rc = ecc_mod_inv_prime(inv, J->Z, p, size);
    if((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_bn_is_zero(inv, size) != 0)) {
        rc = NOXTLS_RETURN_FAILED;
    }
    rc = ecc_rc_merge(rc, ecc_mul_mod(z2, inv, inv, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mul_mod(z3, z2, inv, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mul_mod(x, J->X, z2, p, size, t1));
    rc = ecc_rc_merge(rc, ecc_mul_mod(y, J->Y, z3, p, size, t1));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        /* Never hand back a partially converted (wrong) affine point. */
        (void)noxtls_bn_zero(x, size);
        (void)noxtls_bn_zero(y, size);
    }
    noxtls_secure_zero(inv, sizeof(inv));
    return rc;
}

#if NOXTLS_ECC_POINT_MUL_WINDOW_SIZE > 0

/* ------------------------------------------------------------------------------------------
 * Compact affine precompute tables.
 *
 * Every precompute table (fixed-base comb, variable-point window, joint verify table and its
 * side tables) stores each entry as affine X || Y (2 * size bytes) plus one identity bit,
 * instead of a full ecc_jpoint_t (3 * ECC_MAX_KEY_SIZE + 6 bytes) whose Z is always 1 or 0.
 * For P-256 with every curve enabled that is 64 instead of 204 bytes per entry. Entries are
 * selected with a constant-time scan over the whole table (ecc_ctable_select).
 *
 * While a table is built its entries are Jacobian: X, Y live in the table and Z in a
 * temporary array; ecc_ctable_normalize() converts all of them to affine with one shared
 * inversion (Montgomery's trick) and releases nothing itself.
 * ------------------------------------------------------------------------------------------ */
#define ECC_CTABLE_MAX_LEN 64U

typedef struct {
    uint8_t *xy;                                   /* len entries of X || Y (2 * size bytes) */
    uint32_t id_mask[ECC_CTABLE_MAX_LEN / 32U];    /* bit j set: entry j is the identity */
    uint32_t len;
    uint32_t size;
} ecc_ctable_t;

#if (NOXTLS_ECC_FIXED_POINT_OPTIM) && (NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE)
/* Opt-in process-global caches, keyed by curve id (curve_tag), never by the address of a
 * parameter structure. Shared mutable state: callers must serialize ECC use. */
#if NOXTLS_ECC_POINT_MUL_WINDOW_SIZE >= 2
typedef struct {
    uint32_t curve_tag;   /* curve id + 1 (never 0 for a valid entry) */
    ecc_ctable_t table;
    uint32_t w;
    uint8_t gx[ECC_MAX_KEY_SIZE];
    uint8_t gy[ECC_MAX_KEY_SIZE];
    int valid;
} ecc_fixed_base_cache_t;
static ecc_fixed_base_cache_t s_fixed_base_cache;
#endif

typedef struct {
    uint32_t curve_tag;   /* curve id + 1 (never 0 for a valid entry) */
    ecc_ctable_t table;
    uint32_t w;
    uint8_t p1x[ECC_MAX_KEY_SIZE];
    uint8_t p1y[ECC_MAX_KEY_SIZE];
    uint8_t p2x[ECC_MAX_KEY_SIZE];
    uint8_t p2y[ECC_MAX_KEY_SIZE];
    int valid;
} ecc_muladd_cache_t;
static ecc_muladd_cache_t s_muladd_cache;
#endif

/** All-ones when a == b, 0 otherwise, without a data-dependent branch. */
static uint32_t ecc_ct_eq_mask_u32(uint32_t a, uint32_t b)
{
    uint32_t x = a ^ b;
    /* x == 0 -> (0 - 1) >> 31 == 1 ; x != 0 -> top bit of (x | -x) is 1 */
    uint32_t nz = (x | (0U - x)) >> 31U;
    return (uint32_t)0U - (nz ^ 1U);
}

/** Constant-time select of entry @p idx (0 <= idx < len) into Jacobian @p out (Z = 1 or 0). */
static void ecc_ctable_select_raw(ecc_jpoint_t *out,
                                  const uint8_t *xy,
                                  const uint32_t *id_mask,
                                  uint32_t len,
                                  uint32_t size,
                                  uint32_t idx)
{
    uint32_t j;
    uint32_t is_id = 0U;
    const uint32_t stride = 2U * size;

    (void)noxtls_bn_zero(out->X, size);
    (void)noxtls_bn_zero(out->Y, size);
    (void)noxtls_bn_zero(out->Z, size);
    for(j = 0U; j < len; j += 1U) {
        const uint32_t m = ecc_ct_eq_mask_u32(j, idx);
        const uint8_t sel = (uint8_t)(m & 1U);
        const uint32_t id_bit = (id_mask[j >> 5U] >> (j & 31U)) & 1U;
        ecc_cond_select(out->X, &xy[(size_t)j * stride], out->X, size, sel);
        ecc_cond_select(out->Y, &xy[((size_t)j * stride) + size], out->Y, size, sel);
        is_id |= m & ((uint32_t)0U - id_bit);
    }
    out->Z[size - 1U] = (uint8_t)(1U & ~is_id);
    out->size = size;
}

static void ecc_ctable_select(ecc_jpoint_t *out, const ecc_ctable_t *t, uint32_t idx)
{
    ecc_ctable_select_raw(out, t->xy, t->id_mask, t->len, t->size, idx);
}

/** Allocate an all-identity table of @p len entries. */
static noxtls_return_t ecc_ctable_alloc(ecc_ctable_t *t, uint32_t len, uint32_t size)
{
    uint32_t j;

    noxtls_fill_u8((uint8_t *)(void *)t, sizeof(*t), 0U, sizeof(*t));
    if((len < 2U) || (len > ECC_CTABLE_MAX_LEN) || (size == 0U) || (size > ECC_MAX_KEY_SIZE)) {
        return NOXTLS_RETURN_FAILED;
    }
    t->xy = (uint8_t*)NOXTLS_CALLOC((size_t)len * 2U, size);
    if(t->xy == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    t->len = len;
    t->size = size;
    for(j = 0U; j < len; j += 1U) {
        t->id_mask[j >> 5U] |= (uint32_t)1U << (j & 31U);
    }
    return NOXTLS_RETURN_SUCCESS;
}

static void ecc_ctable_free(ecc_ctable_t *t)
{
    if(t->xy != NULL) {
        (void)noxtls_free(t->xy);
    }
    noxtls_fill_u8((uint8_t *)(void *)t, sizeof(*t), 0U, sizeof(*t));
}

/** Store Jacobian @p P as build entry @p j (X, Y in the table, Z in @p z). */
static void ecc_ctable_store_j(ecc_ctable_t *t, uint8_t *z, uint32_t j, const ecc_jpoint_t *P)
{
    const uint32_t size = t->size;
    uint8_t *e = &t->xy[(size_t)j * 2U * size];

    noxtls_copy_u8(e, (size_t)size, P->X, (size_t)size);
    noxtls_copy_u8(&e[size], (size_t)size, P->Y, (size_t)size);
    noxtls_copy_u8(&z[(size_t)j * size], (size_t)size, P->Z, (size_t)size);
}

#if NOXTLS_ECC_POINT_MUL_WINDOW_SIZE >= 2
/** Load build entry @p j as a Jacobian point (X, Y from the table, Z from @p z). */
static void ecc_ctable_load_j(ecc_jpoint_t *out, const ecc_ctable_t *t, const uint8_t *z, uint32_t j)
{
    const uint32_t size = t->size;
    const uint8_t *e = &t->xy[(size_t)j * 2U * size];

    noxtls_copy_u8(out->X, sizeof(out->X), e, (size_t)size);
    noxtls_copy_u8(out->Y, sizeof(out->Y), &e[size], (size_t)size);
    noxtls_copy_u8(out->Z, sizeof(out->Z), &z[(size_t)j * size], (size_t)size);
    out->size = size;
}
#endif

/** Load normalized entry @p j (public index) as a Jacobian point with Z = 1, or Z = 0 for the identity. */
static void ecc_ctable_load_affine(ecc_jpoint_t *out, const ecc_ctable_t *t, uint32_t j)
{
    const uint32_t size = t->size;
    const uint8_t *e = &t->xy[(size_t)j * 2U * size];

    noxtls_copy_u8(out->X, sizeof(out->X), e, (size_t)size);
    noxtls_copy_u8(out->Y, sizeof(out->Y), &e[size], (size_t)size);
    (void)noxtls_bn_zero(out->Z, size);
    if(((t->id_mask[j >> 5U] >> (j & 31U)) & 1U) == 0U) {
        out->Z[size - 1U] = 0x01U;
    }
    out->size = size;
}

/**
 * @brief Convert every build entry to affine with one inversion (Montgomery's trick).
 *
 * Entries whose Z is 0 become identity entries (X = Y = 0, identity bit set); all others
 * become (X / Z^2, Y / Z^3). On failure the table content is undefined (callers discard it).
 */
static noxtls_return_t ecc_ctable_normalize(ecc_ctable_t *t, const uint8_t *z, const ecc_curve_params_t *curve)
{
    const uint32_t size = t->size;
    const uint32_t len = t->len;
    const uint8_t *p = curve->p;
    uint8_t *prefix;
    uint8_t acc[ECC_MAX_KEY_SIZE];
    uint8_t inv_z[ECC_MAX_KEY_SIZE];
    uint8_t z2[ECC_MAX_KEY_SIZE];
    uint8_t z3[ECC_MAX_KEY_SIZE];
    uint8_t tmp2n[ECC_MAX_KEY_SIZE * 2U];
    uint32_t i;
    int have_acc = 0;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    prefix = (uint8_t*)NOXTLS_CALLOC(len, size);
    if(prefix == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    noxtls_fill_u8((uint8_t *)(void *)(t->id_mask), sizeof(t->id_mask), 0U, sizeof(t->id_mask));
    (void)noxtls_bn_zero(acc, size);
    (void)noxtls_bn_zero(tmp2n, size * 2U);

    /* prefix[i] = product of the non-zero Z[0..i] (identity entries contribute 1). */
    for(i = 0U; (i < len) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        const uint8_t *zi = &z[(size_t)i * size];
        noxtls_ecc_yield();
        if(noxtls_bn_is_zero(zi, size) != 0) {
            t->id_mask[i >> 5U] |= (uint32_t)1U << (i & 31U);
            (void)noxtls_bn_zero(&t->xy[(size_t)i * 2U * size], size * 2U);
        } else if(have_acc == 0) {
            (void)noxtls_bn_copy(acc, zi, size);
            have_acc = 1;
        } else {
            rc = ecc_mul_mod(acc, acc, zi, p, size, tmp2n);
        }
        (void)noxtls_bn_copy(&prefix[(size_t)i * size], acc, size);
    }
    if((rc != NOXTLS_RETURN_SUCCESS) || (have_acc == 0)) {
        (void)noxtls_free(prefix);
        return rc;
    }

    /* acc = 1 / (product of all non-zero Z) */
    rc = ecc_mod_inv_prime(inv_z, acc, p, size);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_bn_copy(acc, inv_z, size);
    }

    for(i = len; (i > 0U) && (rc == NOXTLS_RETURN_SUCCESS); i -= 1U) {
        const uint32_t k = i - 1U;
        const uint8_t *zk = &z[(size_t)k * size];
        uint8_t *e = &t->xy[(size_t)k * 2U * size];
        uint32_t prev;
        int has_prev = 0;

        noxtls_ecc_yield();
        if(((t->id_mask[k >> 5U] >> (k & 31U)) & 1U) != 0U) {
            continue;
        }
        /* inv_z = acc * prefix[previous non-identity entry] (or acc for the first one) */
        for(prev = k; prev > 0U; prev -= 1U) {
            if(((t->id_mask[(prev - 1U) >> 5U] >> ((prev - 1U) & 31U)) & 1U) == 0U) {
                has_prev = 1;
                break;
            }
        }
        if(has_prev != 0) {
            rc = ecc_rc_merge(rc, ecc_mul_mod(inv_z, acc, &prefix[(size_t)(prev - 1U) * size], p, size, tmp2n));
            rc = ecc_rc_merge(rc, ecc_mul_mod(acc, acc, zk, p, size, tmp2n));
        } else {
            (void)noxtls_bn_copy(inv_z, acc, size);
        }
        rc = ecc_rc_merge(rc, ecc_mul_mod(z2, inv_z, inv_z, p, size, tmp2n));
        rc = ecc_rc_merge(rc, ecc_mul_mod(z3, z2, inv_z, p, size, tmp2n));
        rc = ecc_rc_merge(rc, ecc_mul_mod(e, e, z2, p, size, tmp2n));
        rc = ecc_rc_merge(rc, ecc_mul_mod(&e[size], &e[size], z3, p, size, tmp2n));
    }

    noxtls_secure_zero(acc, sizeof(acc));
    noxtls_secure_zero(inv_z, sizeof(inv_z));
    (void)noxtls_free(prefix);
    return rc;
}

/**
 * @brief Build the window table T[i] = i * P (i = 0 .. len-1), normalized to affine.
 *
 * Peak memory: the table (len * 2 * size) plus the Z array and the inversion prefix array
 * (len * size each), both released before returning.
 */
static noxtls_return_t ecc_ctable_build_window(ecc_ctable_t *t, uint32_t len, const ecc_point_t *point,
                                               const ecc_curve_params_t *curve)
{
    const uint32_t size = curve->size;
    ecc_jpoint_t P1;
    ecc_jpoint_t acc;
    ecc_jpoint_t next;
    uint8_t *z = NULL;
    uint32_t i;
    noxtls_return_t rc;

    rc = ecc_ctable_alloc(t, len, size);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    z = (uint8_t*)NOXTLS_CALLOC(len, size);
    if(z == NULL) {
        ecc_ctable_free(t);
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    noxtls_fill_u8((uint8_t *)(void *)(&P1), sizeof(P1), 0U, sizeof(P1));
    noxtls_fill_u8((uint8_t *)(void *)(&acc), sizeof(acc), 0U, sizeof(acc));
    noxtls_fill_u8((uint8_t *)(void *)(&next), sizeof(next), 0U, sizeof(next));
    P1.size = size;
    (void)noxtls_bn_copy(P1.X, point->x, size);
    (void)noxtls_bn_copy(P1.Y, point->y, size);
    P1.Z[size - 1U] = 0x01U;

    /* T[0] = identity (Z = 0, already zero), T[1] = P, T[2] = 2P, T[i] = T[i-1] + P */
    ecc_ctable_store_j(t, z, 1U, &P1);
    rc = ecc_jpoint_double(&acc, &P1, curve);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        ecc_ctable_store_j(t, z, 2U, &acc);
    }
    for(i = 3U; (i < len) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        noxtls_ecc_yield();
        rc = ecc_jpoint_add(&next, &acc, &P1, curve);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            ecc_ctable_store_j(t, z, i, &next);
            noxtls_copy_u8((uint8_t *)(void *)(&acc), sizeof(acc), (const uint8_t *)(const void *)(&next), sizeof(acc));
        }
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = ecc_ctable_normalize(t, z, curve);
    }
    (void)noxtls_free(z);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        ecc_ctable_free(t);
    }
    return rc;
}

/**
 * @brief Build the P-256 joint table J[a * 2^w + b] = a * P1 + b * P2 (normalized to affine).
 *
 * The two 2^w-entry side tables are compact too; they are released before returning.
 */
static noxtls_return_t p256_ctable_build_joint(ecc_ctable_t *joint,
                                               uint32_t w,
                                               const ecc_point_t *point1,
                                               const ecc_point_t *point2,
                                               const ecc_curve_params_t *curve)
{
    const uint32_t size = (uint32_t)(curve->size);
    const uint32_t side_len = ecc_window_table_len(w);
    const uint32_t joint_len = (uint32_t)(side_len * side_len);
    ecc_ctable_t t1;
    ecc_ctable_t t2;
    ecc_jpoint_t A;
    ecc_jpoint_t B;
    ecc_jpoint_t S;
    uint8_t *z = NULL;
    noxtls_return_t rc;
    uint32_t a = 0U;
    uint32_t b = 0U;

    noxtls_fill_u8((uint8_t *)(void *)(&t1), sizeof(t1), 0U, sizeof(t1));
    noxtls_fill_u8((uint8_t *)(void *)(&t2), sizeof(t2), 0U, sizeof(t2));
    noxtls_fill_u8((uint8_t *)(void *)(&S), sizeof(S), 0U, sizeof(S));
    S.size = size;

    rc = ecc_ctable_build_window(&t1, side_len, point1, curve);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = ecc_ctable_build_window(&t2, side_len, point2, curve);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = ecc_ctable_alloc(joint, joint_len, size);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        z = (uint8_t*)NOXTLS_CALLOC(joint_len, size);
        if(z == NULL) {
            rc = NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    for(a = 0U; (a < side_len) && (rc == NOXTLS_RETURN_SUCCESS); a += 1U) {
        noxtls_ecc_yield();
        ecc_ctable_load_affine(&A, &t1, a);
        for(b = 0U; (b < side_len) && (rc == NOXTLS_RETURN_SUCCESS); b += 1U) {
            ecc_ctable_load_affine(&B, &t2, b);
            if((a == 0U) && (b == 0U)) {
                continue; /* identity: Z stays 0 */
            }
            rc = ecc_jpoint_add(&S, &A, &B, curve);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                ecc_ctable_store_j(joint, z, (a * side_len) + b, &S);
            }
        }
    }
    ecc_ctable_free(&t1);
    ecc_ctable_free(&t2);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = ecc_ctable_normalize(joint, z, curve);
    }
    if(z != NULL) {
        (void)noxtls_free(z);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        ecc_ctable_free(joint);
    }
    return rc;
}

/**
 * @brief P-256 joint multiplication k1*P1 + k2*P2 with the joint window table (Shamir).
 *
 * @param[out] result The result
 * @param[in] scalar1 The first scalar
 * @param[in] point1 The first point
 * @param[in] scalar2 The second scalar
 * @param[in] point2 The second point
 * @param[in] curve The curve
 * @return The return value
 */
static ECC_NOINLINE noxtls_return_t p256_ecc_point_muladd_windowed(ecc_point_t *result,
                                                      const uint8_t *scalar1,
                                                      const ecc_point_t *point1,
                                                      const uint8_t *scalar2,
                                                      const ecc_point_t *point2,
                                                      const ecc_curve_params_t *curve)
{
    const uint32_t w = 3U;
    uint32_t size = (uint32_t)(curve->size);
    uint32_t side_len = ecc_window_table_len(w);
    uint32_t n_bits = (uint32_t)(size * 8U);
    uint32_t t = (uint32_t)((n_bits + w - 1U) / w);
    uint32_t first_w = (uint32_t)(n_bits - ((t - 1U) * w));
    ecc_ctable_t owned;
    const ecc_ctable_t *table = NULL;
    ecc_jpoint_t R;
    ecc_jpoint_t T_sel;
    ecc_jpoint_t T_dbl;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t i = 0U;
    uint32_t j = 0U;
    uint32_t idx = 0U;

    noxtls_fill_u8((uint8_t *)(void *)(&owned), sizeof(owned), 0U, sizeof(owned));
    noxtls_fill_u8((uint8_t *)(void *)(&R), sizeof(R), 0U, sizeof(R));
    noxtls_fill_u8((uint8_t *)(void *)(&T_sel), sizeof(T_sel), 0U, sizeof(T_sel));
    noxtls_fill_u8((uint8_t *)(void *)(&T_dbl), sizeof(T_dbl), 0U, sizeof(T_dbl));
    R.size = size;
    T_sel.size = size;
    T_dbl.size = size;

    if(first_w == 0U) {
        first_w = w;
    }

#if (NOXTLS_ECC_FIXED_POINT_OPTIM) && (NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE)
    if((s_muladd_cache.valid != 0) &&
       (curve->curve_tag != 0U) && (s_muladd_cache.curve_tag == curve->curve_tag) &&
       (s_muladd_cache.w == w) &&
       (s_muladd_cache.table.size == size) &&
       (noxtls_ct_memcmp(s_muladd_cache.p1x, point1->x, (size_t)size) == 0) &&
       (noxtls_ct_memcmp(s_muladd_cache.p1y, point1->y, (size_t)size) == 0) &&
       (noxtls_ct_memcmp(s_muladd_cache.p2x, point2->x, (size_t)size) == 0) &&
       (noxtls_ct_memcmp(s_muladd_cache.p2y, point2->y, (size_t)size) == 0)) {
        table = &s_muladd_cache.table;
    }
#endif

    if(table == NULL) {
        rc = p256_ctable_build_joint(&owned, w, point1, point2, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        table = &owned;
#if (NOXTLS_ECC_FIXED_POINT_OPTIM) && (NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE)
        if(curve->curve_tag != 0U) {
            ecc_ctable_free(&s_muladd_cache.table);
            s_muladd_cache.table = owned;
            s_muladd_cache.curve_tag = curve->curve_tag;
            s_muladd_cache.w = w;
            noxtls_copy_u8(s_muladd_cache.p1x, sizeof(s_muladd_cache.p1x), point1->x, (size_t)size);
            noxtls_copy_u8(s_muladd_cache.p1y, sizeof(s_muladd_cache.p1y), point1->y, (size_t)size);
            noxtls_copy_u8(s_muladd_cache.p2x, sizeof(s_muladd_cache.p2x), point2->x, (size_t)size);
            noxtls_copy_u8(s_muladd_cache.p2y, sizeof(s_muladd_cache.p2y), point2->y, (size_t)size);
            s_muladd_cache.valid = 1;
            table = &s_muladd_cache.table;
            noxtls_fill_u8((uint8_t *)(void *)(&owned), sizeof(owned), 0U, sizeof(owned));
        }
#endif
    }

    idx = (ecc_scalar_digit_range(scalar1, size, 0U, first_w) * side_len) +
          ecc_scalar_digit_range(scalar2, size, 0U, first_w);
    ecc_ctable_select(&R, table, idx);

    for(i = 1U; (i < t) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        noxtls_ecc_yield();
        for(j = 0U; (j < w) && (rc == NOXTLS_RETURN_SUCCESS); j += 1U) {
            rc = ecc_jpoint_double(&T_dbl, &R, curve);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                noxtls_copy_u8((uint8_t *)(void *)(&R), sizeof(R), (const uint8_t *)(const void *)(&T_dbl), sizeof(ecc_jpoint_t));
            }
        }

        if(rc == NOXTLS_RETURN_SUCCESS) {
            idx = (ecc_scalar_digit_range(scalar1, size, first_w + ((i - 1U) * w), w) * side_len) +
                  ecc_scalar_digit_range(scalar2, size, first_w + ((i - 1U) * w), w);
            ecc_ctable_select(&T_sel, table, idx);
            rc = ecc_jpoint_add(&T_dbl, &R, &T_sel, curve);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                noxtls_copy_u8((uint8_t *)(void *)(&R), sizeof(R), (const uint8_t *)(const void *)(&T_dbl), sizeof(ecc_jpoint_t));
            }
        }
    }

    ecc_ctable_free(&owned);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if((ecc_jpoint_is_infinity(&R, size) != 0)) {
        (void)noxtls_bn_zero(result->x, size);
        (void)noxtls_bn_zero(result->y, size);
        result->size = size;
        return NOXTLS_RETURN_SUCCESS;
    }

    rc = ecc_jpoint_to_affine(result->x, result->y, &R, curve);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        result->size = size;
    } else {
        (void)noxtls_bn_zero(result->x, size);
        (void)noxtls_bn_zero(result->y, size);
    }
    return rc;
}

#endif /* NOXTLS_ECC_POINT_MUL_WINDOW_SIZE > 0 */

#if NOXTLS_ECC_POINT_MUL_WINDOW_SIZE >= 2
/**
 * @brief Get the bit at the given index
 *
 * @param[in] scalar The scalar
 * @param[in] bit_index The index of the bit
 * @return The bit
 */
static uint8_t p256_scalar_getbit_lsb(const uint8_t *scalar, uint32_t bit_index)
{
    static const uint8_t s_lsb_masks[8] = {
        0x01U, 0x02U, 0x04U, 0x08U, 0x10U, 0x20U, 0x40U, 0x80U
    };
    uint32_t byte_from_end = 0U;
    uint32_t byte_idx = 0U;
    uint32_t bit_in_byte = 0U;

    if((scalar == NULL) || (bit_index >= 256U)) {
        return 0U;
    }

    byte_from_end = bit_index >> 3U;
    byte_idx = 31U - byte_from_end;
    bit_in_byte = bit_index & 7U;
    return (((uint32_t)scalar[byte_idx] & (uint32_t)s_lsb_masks[bit_in_byte]) != 0U) ? 1U : 0U;
}

/**
 * @brief Recode the scalar
 *
 * @param[in] digits The digits
 * @param[in] d The number of digits
 * @param[in] w The width
 * @param[in] scalar The scalar
 */
static void p256_comb_recode_core(uint8_t *digits,
                                  uint32_t d,
                                  uint32_t w,
                                  const uint8_t scalar[32])
{
    uint32_t i = 0U;
    uint32_t j = 0U;

    noxtls_fill_u8(digits, (size_t)d, 0U, (size_t)d);

    for(i = 0U; i < d; i += 1U) {
        for(j = 0U; j < w; j += 1U) {
            uint32_t bit_j = j & 7U;
            static const uint8_t s_bit_masks[8] = {
                0x01U, 0x02U, 0x04U, 0x08U, 0x10U, 0x20U, 0x40U, 0x80U
            };
            if(p256_scalar_getbit_lsb(scalar, i + (d * j)) != 0U) {
                digits[i] = (uint8_t)(digits[i] | s_bit_masks[bit_j]);
            }
        }
    }
}

/**
 * @brief Reduce the scalar modulo the order
 *
 * @param[out] out The output
 * @param[in] in The input
 */
static void p256_scalar_reduce_mod_order(uint8_t *out, const uint8_t *in)
{
    uint32_t words[8];

    p256_words_from_be(words, in);
    if(p256_words_cmp(words, s_p256_order_words) >= 0) {
        p256_words_sub_raw(words, words, s_p256_order_words);
    }
    p256_words_to_be(out, words);
}

/**
 * @brief Build the P-256 comb table for @p point (normalized to affine).
 *
 * table[2^i] = 2^(i*d) * P, table[i + j] = table[i] + table[j] for j < i (subset sums).
 *
 * @param[out] t The table (allocated here, 2^w entries)
 * @param[in] point The point
 * @param[in] curve The curve (P-256)
 * @param[in] w The comb width
 * @param[in] d The number of comb teeth spacing (ceil(256 / w))
 * @return The return value
 */
static noxtls_return_t p256_ctable_build_comb(ecc_ctable_t *t,
                                              const ecc_point_t *point,
                                              const ecc_curve_params_t *curve,
                                              uint32_t w,
                                              uint32_t d)
{
    const uint32_t table_len = ecc_window_table_len(w);
    ecc_jpoint_t cur;
    ecc_jpoint_t tmp;
    ecc_jpoint_t a_pt;
    ecc_jpoint_t b_pt;
    uint8_t *z = NULL;
    uint32_t i = 0U;
    uint32_t j = 0U;
    noxtls_return_t rc;

    rc = ecc_ctable_alloc(t, table_len, 32U);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    z = (uint8_t*)NOXTLS_CALLOC(table_len, 32U);
    if(z == NULL) {
        ecc_ctable_free(t);
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    noxtls_fill_u8((uint8_t *)(void *)(&cur), sizeof(cur), 0U, sizeof(cur));
    noxtls_fill_u8((uint8_t *)(void *)(&tmp), sizeof(tmp), 0U, sizeof(tmp));
    noxtls_fill_u8((uint8_t *)(void *)(&a_pt), sizeof(a_pt), 0U, sizeof(a_pt));
    noxtls_fill_u8((uint8_t *)(void *)(&b_pt), sizeof(b_pt), 0U, sizeof(b_pt));
    cur.size = 32U;
    tmp.size = 32U;
    (void)noxtls_bn_copy(cur.X, point->x, 32U);
    (void)noxtls_bn_copy(cur.Y, point->y, 32U);
    cur.Z[31] = 0x01U;
    ecc_ctable_store_j(t, z, 1U, &cur);

    for(i = 1U; i < w; i += 1U) {
        noxtls_ecc_yield();
        for(j = 0U; j < d; j += 1U) {
            noxtls_ecc_yield();
            (void)p256_jpoint_double(&tmp, &cur);
            noxtls_copy_u8((uint8_t *)(void *)(&cur), sizeof(cur), (const uint8_t *)(const void *)(&tmp), sizeof(cur));
        }
        ecc_ctable_store_j(t, z, ecc_window_table_len(i), &cur);
    }

    /* Powers of two to affine, then the subset sums use mixed additions. */
    rc = ecc_ctable_normalize(t, z, curve);
    for(i = 1U; (i < table_len) && (rc == NOXTLS_RETURN_SUCCESS); i <<= 1U) {
        noxtls_ecc_yield();
        /* table[i] is affine now; table[j] (j < i) may be an earlier Jacobian sum. */
        (void)noxtls_bn_zero(&z[(size_t)i * 32U], 32U);
        z[((size_t)i * 32U) + 31U] = 0x01U;
        ecc_ctable_load_j(&a_pt, t, z, i);
        for(j = 1U; (j < i) && (rc == NOXTLS_RETURN_SUCCESS); j += 1U) {
            noxtls_ecc_yield();
            ecc_ctable_load_j(&b_pt, t, z, j);
            rc = ecc_jpoint_add(&tmp, &b_pt, &a_pt, curve);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                ecc_ctable_store_j(t, z, i + j, &tmp);
            }
        }
    }
    /* Entries 1, 2, 4, ... are affine (Z = 1); re-normalize the sums. */
    for(i = 1U; i < table_len; i <<= 1U) {
        (void)noxtls_bn_zero(&z[(size_t)i * 32U], 32U);
        z[((size_t)i * 32U) + 31U] = 0x01U;
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = ecc_ctable_normalize(t, z, curve);
    }
    (void)noxtls_free(z);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        ecc_ctable_free(t);
    }
    return rc;
}

/**
 * @brief P-256 comb multiplication R = k * P from a compact affine comb table.
 *
 * @param[out] result Jacobian result
 * @param[in] scalar The scalar (32 bytes, reduced mod n here)
 * @param[in] curve The curve (P-256)
 * @param[in] xy Table entries (X || Y)
 * @param[in] id_mask Identity bits of the entries
 * @param[in] w The comb width (table has 2^w entries)
 * @return The return value
 */
static noxtls_return_t p256_ecc_jpoint_mul_comb(ecc_jpoint_t *result,
                                                const uint8_t *scalar,
                                                const ecc_curve_params_t *curve,
                                                const uint8_t *xy,
                                                const uint32_t *id_mask,
                                                uint32_t w)
{
    const uint32_t d = (uint32_t)((256U + w - 1U) / w);
    const uint32_t table_len = ecc_window_table_len(w);
    uint8_t digits[64];
    ecc_jpoint_t R;
    ecc_jpoint_t Txi;
    ecc_jpoint_t Tdbl;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t i = 0U;
    uint8_t reduced[32];

    if((d > sizeof(digits)) || (table_len > ECC_CTABLE_MAX_LEN)) {
        return NOXTLS_RETURN_FAILED;
    }
    noxtls_fill_u8((uint8_t *)(void *)(&R), sizeof(R), 0U, sizeof(R));
    noxtls_fill_u8((uint8_t *)(void *)(&Txi), sizeof(Txi), 0U, sizeof(Txi));
    noxtls_fill_u8((uint8_t *)(void *)(&Tdbl), sizeof(Tdbl), 0U, sizeof(Tdbl));
    R.size = 32U;
    Txi.size = 32U;
    Tdbl.size = 32U;

    p256_scalar_reduce_mod_order(reduced, scalar);
    p256_comb_recode_core(digits, d, w, reduced);

    for(i = d; (i > 0U) && (rc == NOXTLS_RETURN_SUCCESS); i -= 1U) {
        noxtls_ecc_yield();
        (void)p256_jpoint_double(&Tdbl, &R);
        noxtls_copy_u8((uint8_t *)(void *)(&R), sizeof(R), (const uint8_t *)(const void *)(&Tdbl), sizeof(R));

        ecc_ctable_select_raw(&Txi, xy, id_mask, table_len, 32U, digits[i - 1U]);
        rc = ecc_jpoint_add(&Tdbl, &R, &Txi, curve);
        noxtls_copy_u8((uint8_t *)(void *)(&R), sizeof(R), (const uint8_t *)(const void *)(&Tdbl), sizeof(R));
    }
    noxtls_secure_zero(digits, sizeof(digits));
    noxtls_secure_zero(reduced, sizeof(reduced));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    noxtls_copy_u8((uint8_t *)(void *)(result), sizeof(*result), (const uint8_t *)(const void *)(&R), sizeof(R));
    result->size = 32U;
    return NOXTLS_RETURN_SUCCESS;
}

#if ECC_P256_USE_FLASH_TABLE
/* Identity bits of the read-only generator comb table (entry 0 only). */
static const uint32_t s_p256_flash_g_id_mask[ECC_CTABLE_MAX_LEN / 32U] = { 0x00000001U, 0x00000000U };

/* P-256 fixed-base comb multiplication using the compact read-only G table. */
static noxtls_return_t p256_ecc_jpoint_mul_comb_flash(
    ecc_jpoint_t *result,
    const uint8_t *scalar,
    const ecc_curve_params_t *curve)
{
    return p256_ecc_jpoint_mul_comb(result, scalar, curve, &s_noxtls_p256_g_comb_w5[0][0],
                                    s_p256_flash_g_id_mask, NOXTLS_P256_FLASH_G_WINDOW);
}
#endif

/**
 * @brief Fixed-window multiplication R = k * P from a compact affine window table T[i] = i * P.
 *
 * @param[out] result Jacobian result
 * @param[in] scalar The scalar (curve->size bytes, big-endian)
 * @param[in] curve The curve
 * @param[in] table The window table (2^w entries)
 * @param[in] w The window width
 * @return The return value
 */
static noxtls_return_t ecc_jpoint_mul_windowed(ecc_jpoint_t *result,
                                               const uint8_t *scalar,
                                               const ecc_curve_params_t *curve,
                                               const ecc_ctable_t *table,
                                               uint32_t w)
{
    uint32_t size = (uint32_t)(curve->size);
    uint32_t n_bits = (uint32_t)(size * 8U);
    uint32_t t = (uint32_t)((n_bits + w - 1U) / w);  /* number of windows */
    uint32_t first_w = (uint32_t)(n_bits - ((t - 1U) * w));
    ecc_jpoint_t R;
    ecc_jpoint_t T_sel;
    ecc_jpoint_t T_dbl;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t i = 0U;
    uint32_t j = 0U;
    uint32_t d = 0U;

    noxtls_fill_u8((uint8_t *)(void *)(&R), sizeof(R), 0U, sizeof(R));
    noxtls_fill_u8((uint8_t *)(void *)(&T_sel), sizeof(T_sel), 0U, sizeof(T_sel));
    noxtls_fill_u8((uint8_t *)(void *)(&T_dbl), sizeof(T_dbl), 0U, sizeof(T_dbl));
    R.size = size;
    T_sel.size = size;
    T_dbl.size = size;
    if(first_w == 0U) {
        first_w = w;
    }

    /* First window: R = T[d_0] (constant-time selection). */
    d = ecc_scalar_digit_range(scalar, size, 0U, first_w);
    ecc_ctable_select(&R, table, d);

    for(i = 1U; (i < t) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        noxtls_ecc_yield();
        /* R = 2^w * R (w doubles) */
        for(j = 0U; (j < w) && (rc == NOXTLS_RETURN_SUCCESS); j += 1U) {
            rc = ecc_jpoint_double(&T_dbl, &R, curve);
            noxtls_copy_u8((uint8_t *)(void *)(&R), sizeof(R), (const uint8_t *)(const void *)(&T_dbl), sizeof(ecc_jpoint_t));
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            /* R = R + T[d_i] */
            d = ecc_scalar_digit_range(scalar, size, first_w + ((i - 1U) * w), w);
            ecc_ctable_select(&T_sel, table, d);
            rc = ecc_jpoint_add(&T_dbl, &R, &T_sel, curve);
            noxtls_copy_u8((uint8_t *)(void *)(&R), sizeof(R), (const uint8_t *)(const void *)(&T_dbl), sizeof(ecc_jpoint_t));
        }
    }
    d = 0U;
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    noxtls_copy_u8((uint8_t *)(void *)(result), sizeof(*result), (const uint8_t *)(const void *)(&R), sizeof(ecc_jpoint_t));
    result->size = size;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Windowed / comb scalar multiplication R = k * P into a Jacobian result.
 *
 * P-256 uses the read-only generator comb (G) or a compact comb table built for P; other
 * curves use a fixed window table. The optional fixed-base cache keeps the generator table
 * of curves without a read-only table (keyed by curve id).
 *
 * @return NOXTLS_RETURN_SUCCESS, or an error (table allocation / arithmetic) after which the
 *         caller falls back to the Montgomery ladder
 */
static noxtls_return_t ecc_point_mul_windowed_jpoint(ecc_jpoint_t *result,
                                                     const uint8_t *scalar,
                                                     const ecc_point_t *point,
                                                     const ecc_curve_params_t *curve)
{
    const uint32_t size = curve->size;
    const int is_fixed_base = ecc_point_equal(point, &curve->G, size);
    const int is_p256 = ecc_curve_is_secp256r1(curve);
    const uint32_t w = ecc_point_mul_window_size_for_curve(curve, is_fixed_base);
    const uint32_t table_len = ecc_window_table_len(w);
    ecc_ctable_t owned;
    const ecc_ctable_t *table = NULL;
    noxtls_return_t rc;

#if ECC_P256_USE_FLASH_TABLE
    if((is_fixed_base != 0) && (is_p256 != 0)) {
        return p256_ecc_jpoint_mul_comb_flash(result, scalar, curve);
    }
#endif
    if((w < 2U) || (table_len > ECC_CTABLE_MAX_LEN)) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    noxtls_fill_u8((uint8_t *)(void *)(&owned), sizeof(owned), 0U, sizeof(owned));

#if NOXTLS_ECC_FIXED_POINT_OPTIM && NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE
    if((is_fixed_base != 0) && (s_fixed_base_cache.valid != 0) && (curve->curve_tag != 0U) &&
       (s_fixed_base_cache.curve_tag == curve->curve_tag) &&
       (s_fixed_base_cache.w == w) && (s_fixed_base_cache.table.size == size) &&
       (noxtls_ct_memcmp(s_fixed_base_cache.gx, curve->G.x, (size_t)size) == 0) &&
       (noxtls_ct_memcmp(s_fixed_base_cache.gy, curve->G.y, (size_t)size) == 0)) {
        table = &s_fixed_base_cache.table;
    }
#endif
    if(table == NULL) {
        if(is_p256 != 0) {
            rc = p256_ctable_build_comb(&owned, point, curve, w, (256U + w - 1U) / w);
        } else {
            rc = ecc_ctable_build_window(&owned, table_len, point, curve);
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        table = &owned;
#if NOXTLS_ECC_FIXED_POINT_OPTIM && NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE
        if((is_fixed_base != 0) && (curve->curve_tag != 0U)) {
            ecc_ctable_free(&s_fixed_base_cache.table);
            s_fixed_base_cache.table = owned;
            s_fixed_base_cache.curve_tag = curve->curve_tag;
            s_fixed_base_cache.w = w;
            noxtls_copy_u8(s_fixed_base_cache.gx, sizeof(s_fixed_base_cache.gx), curve->G.x, (size_t)size);
            noxtls_copy_u8(s_fixed_base_cache.gy, sizeof(s_fixed_base_cache.gy), curve->G.y, (size_t)size);
            s_fixed_base_cache.valid = 1;
            table = &s_fixed_base_cache.table;
            noxtls_fill_u8((uint8_t *)(void *)(&owned), sizeof(owned), 0U, sizeof(owned));
        }
#endif
    }

    if(is_p256 != 0) {
        rc = p256_ecc_jpoint_mul_comb(result, scalar, curve, table->xy, table->id_mask, w);
    } else {
        rc = ecc_jpoint_mul_windowed(result, scalar, curve, table, w);
    }
    ecc_ctable_free(&owned);
    return rc;
}
#endif /* NOXTLS_ECC_POINT_MUL_WINDOW_SIZE >= 2 */

/**
 * @brief Scalar multiplication into a Jacobian result (no final inversion)
 *
 * @param[out] result The result
 * @param[in] scalar The scalar
 * @param[in] point The point
 * @param[in] curve The curve
 * @return The return value
 */
static noxtls_return_t ecc_point_multiply_jpoint(ecc_jpoint_t *result,
                                                 const uint8_t *scalar,
                                                 const ecc_point_t *point,
                                                 const ecc_curve_params_t *curve)
{
    uint32_t size = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if((result == NULL) || (scalar == NULL) || (point == NULL) || (curve == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    size = curve->size;
    if((size == 0U) || (size > ECC_MAX_KEY_SIZE)) {
        return NOXTLS_RETURN_FAILED;
    }

    noxtls_fill_u8((uint8_t *)(void *)(result), sizeof(*result), 0U, sizeof(*result));
    result->size = size;

    if((noxtls_bn_is_zero(scalar, size) != 0) || (ecc_point_is_infinity(point, size) != 0)) {
        return NOXTLS_RETURN_SUCCESS;
    }

    if(noxtls_bn_is_one(scalar, size) != 0) {
        (void)noxtls_bn_copy(result->X, point->x, size);
        (void)noxtls_bn_copy(result->Y, point->y, size);
        (void)noxtls_bn_zero(result->Z, size);
        result->Z[size - 1U] = 0x01U;
        return NOXTLS_RETURN_SUCCESS;
    }

#if NOXTLS_ECC_POINT_MUL_WINDOW_SIZE >= 2
    if((size != 66U) && (size != 64U)) {
        rc = ecc_point_mul_windowed_jpoint(result, scalar, point, curve);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        noxtls_fill_u8((uint8_t *)(void *)(result), sizeof(*result), 0U, sizeof(*result));
        result->size = size;
    }
#endif

    {
        ecc_point_t affine;

        (void)noxtls_ecc_point_init(&affine, size);
        rc = noxtls_ecc_point_multiply(&affine, scalar, point, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if((ecc_point_is_infinity(&affine, size) != 0)) {
            return NOXTLS_RETURN_SUCCESS;
        }
        (void)noxtls_bn_copy(result->X, affine.x, size);
        (void)noxtls_bn_copy(result->Y, affine.y, size);
        (void)noxtls_bn_zero(result->Z, size);
        result->Z[size - 1U] = 0x01U;
    }

    return NOXTLS_RETURN_SUCCESS;
}

#if NOXTLS_ECC_POINT_MUL_WINDOW_SIZE >= 2
/**
 * @brief Windowed / comb multiplication with the final affine conversion.
 *
 * Out of line so its Jacobian temporaries are not part of the caller's frame.
 */
static ECC_NOINLINE noxtls_return_t ecc_point_mul_windowed_affine(ecc_point_t *result,
                                                                  const uint8_t *scalar,
                                                                  const ecc_point_t *point,
                                                                  const ecc_curve_params_t *curve)
{
    const uint32_t size = curve->size;
    ecc_jpoint_t R;
    noxtls_return_t rc;

    noxtls_fill_u8((uint8_t *)(void *)(&R), sizeof(R), 0U, sizeof(R));
    R.size = size;
    rc = ecc_point_mul_windowed_jpoint(&R, scalar, point, curve);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = ecc_jpoint_to_affine(result->x, result->y, &R, curve);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        result->size = size;
    }
    noxtls_secure_zero(&R, sizeof(R));
    return rc;
}
#endif

/**
 * @brief Constant-time Montgomery ladder R = k * P (fallback and P-521 / brainpoolP512r1 path).
 */
static ECC_NOINLINE noxtls_return_t ecc_point_mul_ladder(ecc_point_t *result,
                                                         const uint8_t *scalar,
                                                         const ecc_point_t *point,
                                                         const ecc_curve_params_t *curve)
{
    const uint32_t size = curve->size;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    /* Montgomery ladder path */
    {
        ecc_jpoint_t R0;
        ecc_jpoint_t R1;
        ecc_jpoint_t T_sum;
        ecc_jpoint_t T_dbl0;
        ecc_jpoint_t T_dbl1;
        uint32_t i = 0U;
        uint32_t j = 0U;
        uint8_t bit = 0U;

        noxtls_fill_u8((uint8_t *)(void *)(&R0), sizeof(R0), 0U, sizeof(R0));
        noxtls_fill_u8((uint8_t *)(void *)(&R1), sizeof(R1), 0U, sizeof(R1));
        noxtls_fill_u8((uint8_t *)(void *)(&T_sum), sizeof(T_sum), 0U, sizeof(T_sum));
        noxtls_fill_u8((uint8_t *)(void *)(&T_dbl0), sizeof(T_dbl0), 0U, sizeof(T_dbl0));
        noxtls_fill_u8((uint8_t *)(void *)(&T_dbl1), sizeof(T_dbl1), 0U, sizeof(T_dbl1));

        R0.size = size;
        R1.size = size;
        T_sum.size = size;
        T_dbl0.size = size;
        T_dbl1.size = size;

        (void)noxtls_bn_zero(R0.X, size);
        (void)noxtls_bn_zero(R0.Y, size);
        (void)noxtls_bn_zero(R0.Z, size);
        (void)noxtls_bn_copy(R1.X, point->x, size);
        (void)noxtls_bn_copy(R1.Y, point->y, size);
        (void)noxtls_bn_zero(R1.Z, size);
        R1.Z[size - 1U] = 0x01U;

        for(i = 0U; (i < size) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
            for(j = 8U; (j > 0U) && (rc == NOXTLS_RETURN_SUCCESS); j -= 1U) {
                noxtls_ecc_yield();
                /* MSB-first bit select without variable shift count (MISRA 12.2). */
                {
                    static const uint8_t s_msb_masks[8] = {
                        0x01U, 0x02U, 0x04U, 0x08U, 0x10U, 0x20U, 0x40U, 0x80U
                    };
                    bit = (uint8_t)(((uint32_t)scalar[i] & (uint32_t)s_msb_masks[j - 1U]) != 0U ? 1U : 0U);
                }
                rc = ecc_jpoint_add(&T_sum, &R0, &R1, curve);
                if(rc == NOXTLS_RETURN_SUCCESS) {
                    rc = ecc_jpoint_double(&T_dbl0, &R0, curve);
                }
                if(rc == NOXTLS_RETURN_SUCCESS) {
                    rc = ecc_jpoint_double(&T_dbl1, &R1, curve);
                }
                if(rc == NOXTLS_RETURN_SUCCESS) {
                    ecc_cond_select(R0.X, T_sum.X, T_dbl0.X, size, bit);
                    ecc_cond_select(R0.Y, T_sum.Y, T_dbl0.Y, size, bit);
                    ecc_cond_select(R0.Z, T_sum.Z, T_dbl0.Z, size, bit);
                    ecc_cond_select(R1.X, T_dbl1.X, T_sum.X, size, bit);
                    ecc_cond_select(R1.Y, T_dbl1.Y, T_sum.Y, size, bit);
                    ecc_cond_select(R1.Z, T_dbl1.Z, T_sum.Z, size, bit);
                }
            }
        }

        if(rc != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_bn_zero(result->x, size);
            (void)noxtls_bn_zero(result->y, size);
            return rc;
        }

        rc = ecc_jpoint_to_affine(result->x, result->y, &R0, curve);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_bn_zero(result->x, size);
        (void)noxtls_bn_zero(result->y, size);
        return rc;
    }
    result->size = size;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief ECC Scalar Multiplication: R = k * P
 *
 * Uses windowed precomputation when NOXTLS_ECC_POINT_MUL_WINDOW_SIZE >= 2,
 * with optional fixed-base cache for G. Falls back to constant-time Montgomery ladder otherwise.
 */
static noxtls_return_t ecc_point_multiply_core(ecc_point_t *result, const uint8_t *scalar, const ecc_point_t *point, const ecc_curve_params_t *curve)
{
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
    uint64_t total_start_us;
    uint64_t phase_start_us;

    noxtls_ecc_point_multiply_last_accel_us = 0U;
    noxtls_ecc_point_multiply_last_precompute_us = 0U;
    noxtls_ecc_point_multiply_last_comb_us = 0U;
    noxtls_ecc_point_multiply_last_total_us = 0U;
    noxtls_ecc_point_multiply_last_used_cache = 0U;
    noxtls_ecc_point_multiply_last_used_accel = 0U;
    total_start_us = noxtls_ecc_diagnostic_time_us();
#endif

    /* Check for null pointers BEFORE accessing any fields */
    if((result == NULL) || (scalar == NULL) || (point == NULL) || (curve == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    uint32_t size = (uint32_t)(curve->size);
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    (void)noxtls_bn_zero(result->x, size);
    (void)noxtls_bn_zero(result->y, size);
    result->size = size;

    if(noxtls_bn_is_zero(scalar, size) != 0) {
        return NOXTLS_RETURN_SUCCESS;
    }
    /* k*O = O. The affine encoding of the identity, (0, 0), must never reach the
     * precompute/ladder code, which would treat it as the Jacobian point (0, 0, 1). */
    if((size != 0U) && (size <= ECC_MAX_KEY_SIZE) && (ecc_point_is_infinity(point, size) != 0)) {
        return NOXTLS_RETURN_SUCCESS;
    }
    /* 1*P = P: avoid full scalar loop for key gen and any 1*point case */
    if(noxtls_bn_is_one(scalar, size) != 0) {
        noxtls_copy_u8(result->x, sizeof(result->x), point->x, (size_t)size);
        noxtls_copy_u8(result->y, sizeof(result->y), point->y, (size_t)size);
        return NOXTLS_RETURN_SUCCESS;
    }

#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
    phase_start_us = noxtls_ecc_diagnostic_time_us();
#endif
    rc = noxtls_ecc_point_multiply_accel_port(result, scalar, point, curve);
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
    noxtls_ecc_point_multiply_last_accel_us =
        noxtls_ecc_diagnostic_elapsed_us(phase_start_us);
#endif
    if(rc == NOXTLS_RETURN_SUCCESS) {
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
        noxtls_ecc_point_multiply_last_used_accel = 1U;
        noxtls_ecc_point_multiply_last_total_us =
            noxtls_ecc_diagnostic_elapsed_us(total_start_us);
#endif
        return rc;
    }
    /* Only an unavailable capability permits software fallback. Preserve
     * actual accelerator failures and timeouts rather than reporting a
     * successful software calculation after failed physical execution. */
    if(rc != NOXTLS_RETURN_NOT_SUPPORTED) {
        noxtls_secure_zero(result->x, sizeof(result->x));
        noxtls_secure_zero(result->y, sizeof(result->y));
        result->size = 0U;
        return rc;
    }

    noxtls_ecc_accel_note_fallback();
    rc = (noxtls_return_t)NOXTLS_RETURN_SUCCESS;

#if NOXTLS_ECC_POINT_MUL_WINDOW_SIZE >= 2
    /*
     * secp521r1 (66-byte coordinates) and brainpoolP512r1 (64-byte coordinates):
     * windowed / fixed-base precomputation has produced incorrect points in TLS 1.3
     * ECDSA CertificateVerify interop; use the Montgomery ladder only for these sizes.
     */
    if((size != 66U) && (size != 64U)) {
        rc = ecc_point_mul_windowed_affine(result, scalar, point, curve);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        /* Table allocation or arithmetic failure: fall back to the ladder. */
        (void)noxtls_bn_zero(result->x, size);
        (void)noxtls_bn_zero(result->y, size);
    }
#endif

    return ecc_point_mul_ladder(result, scalar, point, curve);
}

/**
 * @brief ECC Scalar Multiplication: R = k * P (public entry point)
 *
 * On any failure (including a field-arithmetic allocation failure deep in
 * the point formulas) the result is wiped, so a caller never sees a
 * partially computed point together with an error.
 */
noxtls_return_t noxtls_ecc_point_multiply(ecc_point_t *result, const uint8_t *scalar, const ecc_point_t *point, const ecc_curve_params_t *curve)
{
    noxtls_return_t rc = ecc_point_multiply_core(result, scalar, point, curve);
    if((rc != NOXTLS_RETURN_SUCCESS) && (result != NULL)) {
        noxtls_secure_zero(result->x, sizeof(result->x));
        noxtls_secure_zero(result->y, sizeof(result->y));
    }
    return rc;
}

#if ECC_P256_USE_LOW_RAM_VERIFY
/* Compute k1*G + k2*Q without the 64-entry joint table. G comes from the
 * read-only comb table; only an 8-entry compact table for runtime Q is kept. */
static ECC_NOINLINE noxtls_return_t p256_ecc_point_muladd_low_ram(
    ecc_point_t *result,
    const uint8_t *scalar_g,
    const uint8_t *scalar_q,
    const ecc_point_t *point_q,
    const ecc_curve_params_t *curve)
{
    const uint32_t q_window = 3U;
    const uint32_t q_table_len = 1U << q_window;
    ecc_ctable_t q_table;
    ecc_jpoint_t Jg;
    ecc_jpoint_t Jq;
    ecc_jpoint_t sum;
    noxtls_return_t rc;

    noxtls_secure_zero(&Jg, (size_t)(sizeof(Jg)));
    noxtls_secure_zero(&Jq, (size_t)(sizeof(Jq)));
    noxtls_secure_zero(&sum, (size_t)(sizeof(sum)));
    Jg.size = Jq.size = sum.size = NOXTLS_P256_AFFINE_COORD_SIZE;

    /* Compact 8-entry affine table for Q (512 B) */
    rc = ecc_ctable_build_window(&q_table, q_table_len, point_q, curve);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = p256_ecc_jpoint_mul_comb_flash(&Jg, scalar_g, curve);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = ecc_jpoint_mul_windowed(&Jq, scalar_q, curve, &q_table, q_window);
    }
    ecc_ctable_free(&q_table);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(ecc_jpoint_is_infinity(&Jg, NOXTLS_P256_AFFINE_COORD_SIZE)) {
        noxtls_copy_u8((uint8_t *)(void *)(&sum), (size_t)(sizeof(sum)), (const uint8_t *)(const void *)(&Jq), (size_t)(sizeof(sum)));
    } else if(ecc_jpoint_is_infinity(&Jq, NOXTLS_P256_AFFINE_COORD_SIZE)) {
        noxtls_copy_u8((uint8_t *)(void *)(&sum), (size_t)(sizeof(sum)), (const uint8_t *)(const void *)(&Jg), (size_t)(sizeof(sum)));
    } else {
        rc = ecc_jpoint_add(&sum, &Jg, &Jq, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    if(ecc_jpoint_is_infinity(&sum, NOXTLS_P256_AFFINE_COORD_SIZE)) {
        (void)noxtls_bn_zero(result->x, NOXTLS_P256_AFFINE_COORD_SIZE);
        (void)noxtls_bn_zero(result->y, NOXTLS_P256_AFFINE_COORD_SIZE);
        result->size = NOXTLS_P256_AFFINE_COORD_SIZE;
        return NOXTLS_RETURN_SUCCESS;
    }

    rc = ecc_jpoint_to_affine(result->x, result->y, &sum, curve);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        result->size = NOXTLS_P256_AFFINE_COORD_SIZE;
    } else {
        (void)noxtls_bn_zero(result->x, NOXTLS_P256_AFFINE_COORD_SIZE);
        (void)noxtls_bn_zero(result->y, NOXTLS_P256_AFFINE_COORD_SIZE);
    }
    return rc;
}
#endif

/**
 * @brief Joint multiplication for 32-byte curves: P-256 low-RAM path (G + Q), the joint
 *        window table, or two single multiplications plus one add. Out of line.
 */
static ECC_NOINLINE noxtls_return_t ecc_point_muladd_split(ecc_point_t *result,
                                                             const uint8_t *scalar1, const ecc_point_t *point1,
                                                             const uint8_t *scalar2, const ecc_point_t *point2,
                                                             const ecc_curve_params_t *curve);

static ECC_NOINLINE noxtls_return_t ecc_point_muladd_32(ecc_point_t *result,
                                                          const uint8_t *scalar1, const ecc_point_t *point1,
                                                          const uint8_t *scalar2, const ecc_point_t *point2,
                                                          const ecc_curve_params_t *curve)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
#if ECC_P256_USE_LOW_RAM_VERIFY
    const uint32_t size = curve->size;
#endif

#if ECC_P256_USE_LOW_RAM_VERIFY
    if(ecc_curve_is_secp256r1(curve) &&
       ecc_point_equal(point1, &curve->G, size)) {
        rc = p256_ecc_point_muladd_low_ram(result, scalar1, scalar2,
                                           point2, curve);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if(rc != NOXTLS_RETURN_NOT_ENOUGH_MEMORY) {
            return rc;
        }
    } else if(ecc_curve_is_secp256r1(curve) &&
              ecc_point_equal(point2, &curve->G, size)) {
        rc = p256_ecc_point_muladd_low_ram(result, scalar2, scalar1,
                                           point1, curve);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if(rc != NOXTLS_RETURN_NOT_ENOUGH_MEMORY) {
            return rc;
        }
    } else
#endif
    {
#if NOXTLS_ECC_POINT_MUL_WINDOW_SIZE > 0
        rc = p256_ecc_point_muladd_windowed(result, scalar1, point1,
                                            scalar2, point2, curve);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if(rc != NOXTLS_RETURN_NOT_ENOUGH_MEMORY) {
            return rc;
        }
#endif
    }

    (void)rc;
    return ecc_point_muladd_split(result, scalar1, point1, scalar2, point2, curve);
}

/**
 * @brief Memory-constrained joint multiplication fallback: both scalar multiplies in
 *        Jacobian form, one side converted to affine, one mixed add, one final inversion.
 */
static ECC_NOINLINE noxtls_return_t ecc_point_muladd_split(ecc_point_t *result,
                                                             const uint8_t *scalar1, const ecc_point_t *point1,
                                                             const uint8_t *scalar2, const ecc_point_t *point2,
                                                             const ecc_curve_params_t *curve)
{
    const uint32_t size = curve->size;
    ecc_jpoint_t R;
    ecc_jpoint_t J1;
    ecc_jpoint_t J2;
    noxtls_return_t rc;

    noxtls_fill_u8((uint8_t *)(void *)(&R), sizeof(R), 0U, sizeof(R));
    R.size = size;
    rc = ecc_point_multiply_jpoint(&J1, scalar1, point1, curve);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = ecc_point_multiply_jpoint(&J2, scalar2, point2, curve);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if((ecc_jpoint_is_infinity(&J2, size) == 0)) {
        rc = ecc_jpoint_to_affine(J2.X, J2.Y, &J2, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        (void)noxtls_bn_zero(J2.Z, size);
        J2.Z[size - 1U] = 0x01U;
    }

    rc = ecc_jpoint_add(&R, &J1, &J2, curve);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if((ecc_jpoint_is_infinity(&R, size) != 0)) {
        (void)noxtls_bn_zero(result->x, size);
        (void)noxtls_bn_zero(result->y, size);
        result->size = size;
        return NOXTLS_RETURN_SUCCESS;
    }

    rc = ecc_jpoint_to_affine(result->x, result->y, &R, curve);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        result->size = size;
    } else {
        (void)noxtls_bn_zero(result->x, size);
        (void)noxtls_bn_zero(result->y, size);
    }
    return rc;
}

/**
 * @brief Generic joint multiplication (1-bit Shamir trick) for curves other than the
 *        32-byte ones. Out of line so its five Jacobian temporaries stay off the P-256 path.
 */
static ECC_NOINLINE noxtls_return_t ecc_point_muladd_shamir(ecc_point_t *result,
                                                              const uint8_t *scalar1, const ecc_point_t *point1,
                                                              const uint8_t *scalar2, const ecc_point_t *point2,
                                                              const ecc_curve_params_t *curve)
{
    const uint32_t size = curve->size;
    ecc_jpoint_t R;
    ecc_jpoint_t J1;
    ecc_jpoint_t J2;
    ecc_jpoint_t J12;
    ecc_jpoint_t T;
    uint32_t n_bits = 0U;
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    noxtls_fill_u8((uint8_t *)(void *)(&R), sizeof(R), 0U, sizeof(R));
    noxtls_fill_u8((uint8_t *)(void *)(&J1), sizeof(J1), 0U, sizeof(J1));
    noxtls_fill_u8((uint8_t *)(void *)(&J2), sizeof(J2), 0U, sizeof(J2));
    noxtls_fill_u8((uint8_t *)(void *)(&J12), sizeof(J12), 0U, sizeof(J12));
    noxtls_fill_u8((uint8_t *)(void *)(&T), sizeof(T), 0U, sizeof(T));
    R.size = size;
    J1.size = size;
    J2.size = size;
    J12.size = size;
    T.size = size;

    /* R = infinity */
    (void)noxtls_bn_zero(R.X, size);
    (void)noxtls_bn_zero(R.Y, size);
    (void)noxtls_bn_zero(R.Z, size);

    /* J1 <- P1 (affine to Jacobian) */
    (void)noxtls_bn_copy(J1.X, point1->x, size);
    (void)noxtls_bn_copy(J1.Y, point1->y, size);
    (void)noxtls_bn_zero(J1.Z, size);
    if((ecc_point_is_infinity(point1, size) == 0)) {
        J1.Z[size - 1U] = 0x01U;
    }

    /* J2 <- P2 (affine to Jacobian) */
    (void)noxtls_bn_copy(J2.X, point2->x, size);
    (void)noxtls_bn_copy(J2.Y, point2->y, size);
    (void)noxtls_bn_zero(J2.Z, size);
    if((ecc_point_is_infinity(point2, size) == 0)) {
        J2.Z[size - 1U] = 0x01U;
    }

    n_bits = size * 8U;
    /* Generic path: 1-bit Shamir trick. */
    if((ecc_jpoint_is_infinity(&J1, size) != 0)) {
        noxtls_copy_u8((uint8_t *)(void *)(&J12), sizeof(J12), (const uint8_t *)(const void *)(&J2), sizeof(ecc_jpoint_t));
    } else if((ecc_jpoint_is_infinity(&J2, size) != 0)) {
        noxtls_copy_u8((uint8_t *)(void *)(&J12), sizeof(J12), (const uint8_t *)(const void *)(&J1), sizeof(ecc_jpoint_t));
    } else if(ecc_point_equal(point1, point2, size) != 0) {
        rc = ecc_jpoint_double(&J12, &J1, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    } else {
        rc = ecc_jpoint_add(&J12, &J1, &J2, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    for(i = 0U; i < n_bits; i += 1U) {
        uint8_t b1 = 0U;
        uint8_t b2 = 0U;
        const ecc_jpoint_t *A = NULL;

        rc = ecc_jpoint_double(&T, &R, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        noxtls_copy_u8((uint8_t *)(void *)(&R), sizeof(R), (const uint8_t *)(const void *)(&T), sizeof(ecc_jpoint_t));

        b1 = ecc_scalar_getbit(scalar1, size, i);
        b2 = ecc_scalar_getbit(scalar2, size, i);
        if((b1 == 0U) && (b2 == 0U)) {
            continue;
        }
        if((b1 != 0U) && (b2 != 0U)) {
            A = &J12;
        } else if(b1 != 0U) {
            A = &J1;
        } else {
            A = &J2;
        }

        if((ecc_jpoint_is_infinity(A, size) != 0)) {
            continue;
        }
        if((ecc_jpoint_is_infinity(&R, size) != 0)) {
            noxtls_copy_u8((uint8_t *)(void *)(&R), sizeof(R), (const uint8_t *)(const void *)(A), sizeof(ecc_jpoint_t));
            continue;
        }
        rc = ecc_jpoint_add(&T, &R, A, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        noxtls_copy_u8((uint8_t *)(void *)(&R), sizeof(R), (const uint8_t *)(const void *)(&T), sizeof(ecc_jpoint_t));
    }
    if((ecc_jpoint_is_infinity(&R, size) != 0)) {
        (void)noxtls_bn_zero(result->x, size);
        (void)noxtls_bn_zero(result->y, size);
        result->size = size;
        return NOXTLS_RETURN_SUCCESS;
    }

    rc = ecc_jpoint_to_affine(result->x, result->y, &R, curve);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        result->size = size;
    } else {
        (void)noxtls_bn_zero(result->x, size);
        (void)noxtls_bn_zero(result->y, size);
    }
    return rc;
}

/**
 * @brief Joint scalar multiplication: R = k1*P1 + (k2 * P2)
 *
 * Uses Jacobian arithmetic internally to avoid repeated inversions and performs
 * a single affine conversion at the end.
 */
static noxtls_return_t ecc_point_muladd_core(ecc_point_t *result,
                                              const uint8_t *scalar1, const ecc_point_t *point1,
                                              const uint8_t *scalar2, const ecc_point_t *point2,
                                              const ecc_curve_params_t *curve)
{
    uint32_t size = 0U;

    if((result == NULL) || (scalar1 == NULL) || (point1 == NULL) || (scalar2 == NULL) || (point2 == NULL) || (curve == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    size = curve->size;
    if((size == 0U) || (size > ECC_MAX_KEY_SIZE)) {
        return NOXTLS_RETURN_FAILED;
    }
    if((point1->size != size) || (point2->size != size)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    (void)noxtls_bn_zero(result->x, size);
    (void)noxtls_bn_zero(result->y, size);
    result->size = size;

    {
        /* A term whose scalar is zero or whose point is the identity (affine
         * (0, 0)) contributes nothing. Strip it here: the joint-table (size 32)
         * path would otherwise treat (0, 0) as a real affine point. */
        const int term1_zero = ((noxtls_bn_is_zero(scalar1, size) != 0) || (ecc_point_is_infinity(point1, size) != 0)) ? 1 : 0;
        const int term2_zero = ((noxtls_bn_is_zero(scalar2, size) != 0) || (ecc_point_is_infinity(point2, size) != 0)) ? 1 : 0;

        if((term1_zero != 0) && (term2_zero != 0)) {
            return NOXTLS_RETURN_SUCCESS;
        }
        if(term1_zero != 0) {
            return noxtls_ecc_point_multiply(result, scalar2, point2, curve);
        }
        if(term2_zero != 0) {
            return noxtls_ecc_point_multiply(result, scalar1, point1, curve);
        }
    }

    if(size > (UINT32_MAX / 8U)) {
        return NOXTLS_RETURN_FAILED;
    }
    if(size == 32U) {
        return ecc_point_muladd_32(result, scalar1, point1, scalar2, point2, curve);
    }
    return ecc_point_muladd_shamir(result, scalar1, point1, scalar2, point2, curve);
}

/**
 * @brief Joint scalar multiplication: R = k1*P1 + (k2 * P2)
 *
 * On any failure (including a field-arithmetic allocation failure deep in
 * the point formulas) the result is wiped, so a caller never sees a
 * partially computed point together with an error.
 */
noxtls_return_t noxtls_ecc_point_muladd(ecc_point_t *result,
                                        const uint8_t *scalar1, const ecc_point_t *point1,
                                        const uint8_t *scalar2, const ecc_point_t *point2,
                                        const ecc_curve_params_t *curve)
{
    noxtls_return_t rc = ecc_point_muladd_core(result, scalar1, point1, scalar2, point2, curve);
    if((rc != NOXTLS_RETURN_SUCCESS) && (result != NULL)) {
        noxtls_secure_zero(result->x, sizeof(result->x));
        noxtls_secure_zero(result->y, sizeof(result->y));
    }
    return rc;
}

/**
 * @brief Check if point is on curve
 *
 * Verifies that y^2 = x^3 + ax + b (mod p) with the field multiply used by the point
 * formulas (dedicated P-256 / P-384 / P-521 arithmetic, bignum otherwise). The scratch is
 * on the stack (about 5 x ECC_MAX_KEY_SIZE bytes); with NOXTLS_ECC_SHARED_SCRATCH it is
 * shared static storage like the other ECC scratch (callers then serialize ECC use).
 */
noxtls_return_t noxtls_ecc_point_is_on_curve(const ecc_point_t *point, const ecc_curve_params_t *curve)
{
#if NOXTLS_ECC_SHARED_SCRATCH
    static
#endif
    struct {
        uint8_t left[ECC_MAX_KEY_SIZE];
        uint8_t right[ECC_MAX_KEY_SIZE];
        uint8_t t1[ECC_MAX_KEY_SIZE];
        uint8_t tmp2n[ECC_MAX_KEY_SIZE * 2U];
    } scratch;
    uint32_t size;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((point == NULL) || (curve == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    size = curve->size;
    if((size == 0U) || (size > ECC_MAX_KEY_SIZE) || (curve->p == NULL) || (curve->a == NULL) || (curve->b == NULL)) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Check if point is at infinity. The identity is a group element, so this
     * internal helper accepts it; public-key validation
     * (noxtls_ecc_point_validate_public) and key generation reject it. */
    if(ecc_point_is_infinity(point, size) != 0) {
        return NOXTLS_RETURN_SUCCESS;
    }

    noxtls_fill_u8((uint8_t *)(void *)(&scratch), sizeof(scratch), 0U, sizeof(scratch));

    /* Every status is checked: a failed multiply/reduction leaves a meaningless
     * value that must never be compared as if it were valid. */
    /* left = y^2 mod p */
    rc = ecc_mul_mod(scratch.left, point->y, point->y, curve->p, size, scratch.tmp2n);
    /* right = x^3 + a*x + b mod p (use curve->a so it matches add/double) */
    rc = ecc_rc_merge(rc, ecc_mul_mod(scratch.t1, point->x, point->x, curve->p, size, scratch.tmp2n));
    rc = ecc_rc_merge(rc, ecc_mul_mod(scratch.right, scratch.t1, point->x, curve->p, size, scratch.tmp2n));
    rc = ecc_rc_merge(rc, ecc_mul_mod(scratch.t1, curve->a, point->x, curve->p, size, scratch.tmp2n));
    rc = ecc_rc_merge(rc, ecc_mod_add(scratch.right, scratch.right, scratch.t1, curve->p, size));
    rc = ecc_rc_merge(rc, ecc_mod_add(scratch.right, scratch.right, curve->b, curve->p, size));

    if((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_bn_cmp(scratch.left, scratch.right, size) != 0)) {
        rc = NOXTLS_RETURN_FAILED;
    }
    noxtls_secure_zero(&scratch, sizeof(scratch));

    return rc;
}

/**
 * @brief Validate the public point
 *
 * @param[in] point The point to validate.
 * @param[in] curve The curve.
 * @return The return value.
 */
noxtls_return_t noxtls_ecc_point_validate_public(const ecc_point_t *point, const ecc_curve_params_t *curve)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((point == NULL) || (curve == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if((point->size != curve->size) || (curve->size == 0U) || (curve->size > ECC_MAX_KEY_SIZE)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    /* The identity (affine encoding (0, 0)) is never a valid public key. */
    if((ecc_point_is_infinity(point, curve->size) != 0)) {
        return NOXTLS_RETURN_FAILED;
    }
    /* Coordinates must be canonical field elements (x, y < p). */
    if((curve->p == NULL) ||
       (noxtls_bn_cmp(point->x, curve->p, curve->size) >= 0) ||
       (noxtls_bn_cmp(point->y, curve->p, curve->size) >= 0)) {
        return NOXTLS_RETURN_FAILED;
    }

    rc = noxtls_ecc_point_is_on_curve(point, curve);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        /* Keep an allocation failure distinguishable from an invalid point. */
        return (rc == NOXTLS_RETURN_NOT_ENOUGH_MEMORY) ? rc : NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Initialize ECC key
 *
 * @param key ECC key
 * @param curve_type Curve type
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if key is NULL
 */
noxtls_return_t noxtls_ecc_key_init(ecc_key_t *key, ecc_curve_t curve_type)
{
    noxtls_return_t rc;

    NOXTLS_ECC_STATUS_SET(noxtls_ecc_keyinit_last_stage, 1U);
    NOXTLS_ECC_STATUS_SET(noxtls_ecc_keyinit_last_rc, (int32_t)NOXTLS_RETURN_SUCCESS);
    if(key == NULL) {
        NOXTLS_ECC_STATUS_SET(noxtls_ecc_keyinit_last_rc, (int32_t)NOXTLS_RETURN_NULL);
        return NOXTLS_RETURN_NULL;
    }

    noxtls_fill_u8((uint8_t *)(void *)(key), sizeof(ecc_key_t), 0U, sizeof(ecc_key_t));
    NOXTLS_ECC_STATUS_SET(noxtls_ecc_keyinit_last_stage, 2U);

    /* Shared read-only curve descriptor: no per-key copy of p, a, b, n or G. */
    key->curve = noxtls_ecc_curve_get(curve_type);
    NOXTLS_ECC_STATUS_SET(noxtls_ecc_keyinit_last_stage, 3U);
    if(key->curve == NULL) {
        rc = NOXTLS_RETURN_FAILED;
        NOXTLS_ECC_STATUS_SET(noxtls_ecc_keyinit_last_rc, (int32_t)rc);
        return rc;
    }
    key->curve_kind = curve_type;

    NOXTLS_ECC_STATUS_SET(noxtls_ecc_keyinit_last_stage, 4U);
    key->d = (uint8_t*)NOXTLS_CALLOC(key->curve->size, 1);
    key->d_size = (key->d != NULL) ? key->curve->size : 0U;
    if(key->d == NULL) {
        key->curve = NULL;
        NOXTLS_ECC_STATUS_SET(noxtls_ecc_keyinit_last_rc, (int32_t)NOXTLS_RETURN_NOT_ENOUGH_MEMORY);
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    
    NOXTLS_ECC_STATUS_SET(noxtls_ecc_keyinit_last_stage, 5U);
    (void)noxtls_ecc_point_init(&key->Q, key->curve->size);
    NOXTLS_ECC_STATUS_SET(noxtls_ecc_keyinit_last_stage, 9U);
    NOXTLS_ECC_STATUS_SET(noxtls_ecc_keyinit_last_rc, (int32_t)NOXTLS_RETURN_SUCCESS);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Generate ECC key pair
 *
 * Generates a random private key d in range [1, n-1] using DRBG,
 * then computes the public key Q = d * G
 *
 * @param key ECC key
 * @param curve_type Curve type
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if key is NULL
 */
noxtls_return_t noxtls_ecc_key_generate(ecc_key_t *key, ecc_curve_t curve_type)
{
    uint8_t random_bytes[ECC_MAX_KEY_SIZE];
    uint32_t size;
    uint32_t bits;
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
    uint64_t total_start_us;
    uint64_t phase_start_us;
#endif
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
    total_start_us = noxtls_ecc_diagnostic_time_us();
#endif

    NOXTLS_ECC_STATUS_SET(noxtls_ecc_keygen_last_stage, 1U);
    NOXTLS_ECC_STATUS_SET(noxtls_ecc_keygen_last_rc, (int32_t)NOXTLS_RETURN_SUCCESS);
    NOXTLS_ECC_STATUS_SET(noxtls_ecc_keygen_last_entropy_rc, (int32_t)NOXTLS_RETURN_SUCCESS);
    NOXTLS_ECC_STATUS_SET(noxtls_ecc_keygen_last_multiply_rc, (int32_t)NOXTLS_RETURN_SUCCESS);
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
    noxtls_ecc_keygen_last_init_us = 0U;
    noxtls_ecc_keygen_last_private_us = 0U;
    noxtls_ecc_keygen_last_multiply_us = 0U;
    noxtls_ecc_keygen_last_validate_us = 0U;
    noxtls_ecc_keygen_last_total_us = 0U;
#endif

    if(key == NULL) {
        NOXTLS_ECC_STATUS_SET(noxtls_ecc_keygen_last_rc, (int32_t)NOXTLS_RETURN_NULL);
        return NOXTLS_RETURN_NULL;
    }

    NOXTLS_ECC_STATUS_SET(noxtls_ecc_keygen_last_stage, 2U);
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
    phase_start_us = noxtls_ecc_diagnostic_time_us();
#endif
    rc = noxtls_ecc_key_init(key, curve_type);
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
    noxtls_ecc_keygen_last_init_us =
        noxtls_ecc_diagnostic_elapsed_us(phase_start_us);
#endif
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_ECC_STATUS_SET(noxtls_ecc_keygen_last_stage, 3U);
        NOXTLS_ECC_STATUS_SET(noxtls_ecc_keygen_last_rc, (int32_t)rc);
        return rc;
    }
    NOXTLS_ECC_STATUS_SET(noxtls_ecc_keygen_last_stage, 4U);
    size = key->curve->size;
    if(size == 0U || size > ECC_MAX_KEY_SIZE) {
        rc = NOXTLS_RETURN_FAILED;
        NOXTLS_ECC_STATUS_SET(noxtls_ecc_keygen_last_stage, 5U);
        goto cleanup_keygen;
    }
    bits = size * 8U;

    noxtls_secure_zero(random_bytes, (size_t)(sizeof(random_bytes)));
    NOXTLS_ECC_STATUS_SET(noxtls_ecc_keygen_last_stage, 6U);
    do {
        uint32_t attempts = 0U;
        int d_valid = 0;
        /* Generate private key d in range [1, n-1] */
        /* Generate random private key */
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
        phase_start_us = noxtls_ecc_diagnostic_time_us();
#endif
        while((d_valid == 0) && (attempts < NOXTLS_ECC_KEYGEN_MAX_ATTEMPTS)) {
            attempts += 1U;
            rc = ecc_keygen_drbg_generate_bits(random_bytes, bits);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                NOXTLS_ECC_STATUS_SET(noxtls_ecc_keygen_last_stage, 7U);
                break;
            }

            if(noxtls_ecc_curve_order_size(key->curve) > size) {
                /* Order longer than the field (secp224k1): every size-byte value is
                 * already below n, so no reduction is needed. */
                noxtls_copy_u8(key->d, (size_t)size, random_bytes, (size_t)size);
            } else {
                /* Reduce mod n (gives [0, n-1]); a failed reduction must not
                 * leave a stale or zero d behind as the "generated" key. */
                rc = noxtls_bn_mod(key->d, random_bytes, size, key->curve->n, size);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    NOXTLS_ECC_STATUS_SET(noxtls_ecc_keygen_last_stage, 7U);
                    break;
                }
            }

            /* d == 0 (or, defensively, d >= n) is rejected and redrawn. */
            if((noxtls_bn_is_zero(key->d, size) == 0) &&
               ((noxtls_ecc_curve_order_size(key->curve) != size) ||
                (noxtls_bn_cmp(key->d, key->curve->n, size) < 0))) {
                d_valid = 1;
            }
        }
        if((rc == NOXTLS_RETURN_SUCCESS) && (d_valid == 0)) {
            NOXTLS_ECC_STATUS_SET(noxtls_ecc_keygen_last_stage, 7U);
            rc = NOXTLS_RETURN_FAILED;
        }
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
        noxtls_ecc_keygen_last_private_us =
            noxtls_ecc_diagnostic_elapsed_us(phase_start_us);
#endif

        if(rc != NOXTLS_RETURN_SUCCESS) {
            break;
        }

        /* Compute public key Q = d * G */
        /* This is the expensive operation - scalar multiplication */
        NOXTLS_ECC_STATUS_SET(noxtls_ecc_keygen_last_stage, 8U);
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
        phase_start_us = noxtls_ecc_diagnostic_time_us();
#endif
        rc = noxtls_ecc_point_multiply(&key->Q, key->d, &key->curve->G, key->curve);
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
        noxtls_ecc_keygen_last_multiply_us =
            noxtls_ecc_diagnostic_elapsed_us(phase_start_us);
#endif
        NOXTLS_ECC_STATUS_SET(noxtls_ecc_keygen_last_multiply_rc, (int32_t)rc);
    } while(0 == 1);

    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup_keygen;
    }

    /* Verify the generated public key: on the curve and not the identity
     * (noxtls_ecc_point_is_on_curve() accepts the identity by itself). */
    NOXTLS_ECC_STATUS_SET(noxtls_ecc_keygen_last_stage, 9U);
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
    phase_start_us = noxtls_ecc_diagnostic_time_us();
#endif
    rc = noxtls_ecc_point_validate_public(&key->Q, key->curve);
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
    noxtls_ecc_keygen_last_validate_us =
        noxtls_ecc_diagnostic_elapsed_us(phase_start_us);
#endif
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup_keygen;
    }

cleanup_keygen:
    noxtls_secure_zero(random_bytes, (size_t)(sizeof(random_bytes)));
    if((rc != NOXTLS_RETURN_SUCCESS) && (key->d != NULL)) {
        /* Fail closed: never leave a half-generated key pair behind. The key
         * stays initialized (noxtls_ecc_key_free() is still required). */
        noxtls_secure_zero(key->d, (size_t)key->d_size);
        noxtls_secure_zero(key->Q.x, sizeof(key->Q.x));
        noxtls_secure_zero(key->Q.y, sizeof(key->Q.y));
    }
    NOXTLS_ECC_STATUS_SET(noxtls_ecc_keygen_last_rc, (int32_t)rc);
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
    noxtls_ecc_keygen_last_total_us =
        noxtls_ecc_diagnostic_elapsed_us(total_start_us);
#endif

    return rc;
}

/**
 * @brief Import an ECC private scalar and derive its public key.
 *
 * The input is an unsigned, big-endian scalar. Values shorter than the curve
 * coordinate size are left-padded with zeroes. Scalars outside [1, n-1] are
 * rejected. The key is initialized by this function and must be uninitialized
 * on entry; if an error occurs after initialization, the caller must free it.
 *
 * @param key ECC key to initialize
 * @param curve_type Curve type
 * @param private_scalar Big-endian private scalar
 * @param private_scalar_len Length of private_scalar in bytes
 * @return NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL for null
 *         pointers, NOXTLS_RETURN_INVALID_KEY_SIZE for an invalid length,
 *         NOXTLS_RETURN_INVALID_PARAM for a scalar outside [1, n-1], or an
 *         error from key initialization or public-key derivation.
 */
noxtls_return_t noxtls_ecc_key_import_private(ecc_key_t *key, ecc_curve_t curve_type,
                                               const uint8_t *private_scalar, uint32_t private_scalar_len)
{
    noxtls_return_t rc;
    uint32_t size;

    if((key == NULL) || (private_scalar == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(private_scalar_len == 0U) {
        return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }

    rc = noxtls_ecc_key_init(key, curve_type);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    size = key->curve->size;
    if((size == 0U) || (size > ECC_MAX_KEY_SIZE) || (private_scalar_len > size)) {
        rc = NOXTLS_RETURN_INVALID_KEY_SIZE;
    } else {
        noxtls_secure_zero(key->d, (size_t)key->d_size);
        noxtls_copy_u8(key->d + (size - private_scalar_len), (size_t)private_scalar_len,
                       private_scalar, (size_t)private_scalar_len);

        if(noxtls_bn_is_zero(key->d, size) != 0) {
            rc = NOXTLS_RETURN_INVALID_PARAM;
        } else if((noxtls_ecc_curve_order_size(key->curve) == size) &&
                  (noxtls_bn_cmp(key->d, key->curve->n, size) >= 0)) {
            rc = NOXTLS_RETURN_INVALID_PARAM;
        }
    }

    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecc_point_multiply(&key->Q, key->d, &key->curve->G, key->curve);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecc_point_validate_public(&key->Q, key->curve);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(key->d, (size_t)key->d_size);
        noxtls_secure_zero(key->Q.x, sizeof(key->Q.x));
        noxtls_secure_zero(key->Q.y, sizeof(key->Q.y));
    }

    return rc;
}

/**
 * @brief Free ECC key
 *
 * @param key ECC key
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if key is NULL
*/
noxtls_return_t noxtls_ecc_key_free(ecc_key_t *key)
{
    if(key == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(key->d != NULL) {
        /* Wipe exactly the allocated length recorded by noxtls_ecc_key_init().
         * The curve may be detached or replaced, so its size is not a safe
         * bound; an unknown length (0) skips the wipe rather than overrunning. */
        if((key->d_size != 0U) && (key->d_size <= ECC_MAX_KEY_SIZE)) {
            noxtls_secure_zero(key->d, (size_t)key->d_size);
        }
        (void)noxtls_free(key->d);
        key->d = NULL;
    }
    key->d_size = 0U;

    /* key->curve is the shared read-only descriptor (or a caller-provided curve):
     * it is not owned by the key and is never freed here. */
    key->curve = NULL;
    /* Do not noxtls_fill_u8((uint8_t *)(void *)(key), sizeof(ecc_key_t), 0U, sizeof(ecc_key_t)): key may be on the caller's stack and
     * sizeof(ecc_key_t) can differ between translation units (e.g. C vs C++), which
     * can corrupt the stack and crash when the test returns. */
    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_FEATURE_ECC */
