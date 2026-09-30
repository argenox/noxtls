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
#include "common/noxtls_memory_compat.h"
#include "noxtls_ecc.h"

#if defined(__GNUC__) || defined(__clang__)
void noxtls_ecc_yield(void) __attribute__((weak));
#endif
void noxtls_ecc_yield(void)
{
}
#include "pkc/rsa/noxtls_bignum.h"
#include "drbg/noxtls_drbg.h"
#include "noxtls_common.h"
#include "common/noxtls_ct.h"

#if NOXTLS_ECC_P256_FLASH_PRECOMPUTE
#include "noxtls_p256_precomputed_g.h"
#endif

/* Disable verbose stderr debug prints in this file. */
#define NOXTLS_ECC_TRACE(...) ((void)0)

/* PTS status ABI. Values report control-flow only and never key material. */
volatile int32_t noxtls_ecc_keygen_last_rc = (int32_t)NOXTLS_RETURN_SUCCESS;
volatile uint32_t noxtls_ecc_keygen_last_stage = 0U;
volatile int32_t noxtls_ecc_keygen_last_entropy_rc = (int32_t)NOXTLS_RETURN_SUCCESS;
volatile int32_t noxtls_ecc_keygen_last_multiply_rc = (int32_t)NOXTLS_RETURN_SUCCESS;
volatile uint32_t noxtls_ecc_keygen_last_drbg_type = DRBG_AES256;
volatile int32_t noxtls_ecc_keyinit_last_rc = (int32_t)NOXTLS_RETURN_SUCCESS;
volatile uint32_t noxtls_ecc_keyinit_last_stage = 0U;
/* nRF52's ECB peripheral is AES-128 only. A CTR-DRBG does not require
 * AES-256; select an enabled primitive for constrained builds. */
#if NOXTLS_FEATURE_AES_256
#define NOXTLS_ECC_KEYGEN_DRBG_TYPE     DRBG_AES256
#define NOXTLS_ECC_KEYGEN_DRBG_SEEDLEN  DRBG_SEEDLEN_AES256
#else
#define NOXTLS_ECC_KEYGEN_DRBG_TYPE     DRBG_AES128
#define NOXTLS_ECC_KEYGEN_DRBG_SEEDLEN  DRBG_SEEDLEN_AES128
#endif
#if (NOXTLS_ECC_POINT_MUL_WINDOW_SIZE > 0) && (NOXTLS_ECC_FIXED_POINT_OPTIM) && (NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE)
typedef struct {
    const ecc_curve_params_t *curve;
    ecc_jpoint_t *table;
    uint32_t w;
    uint32_t size;
    uint8_t p1x[ECC_MAX_KEY_SIZE];
    uint8_t p1y[ECC_MAX_KEY_SIZE];
    uint8_t p2x[ECC_MAX_KEY_SIZE];
    uint8_t p2y[ECC_MAX_KEY_SIZE];
    int valid;
} ecc_muladd_cache_t;

static ecc_fixed_base_cache_t s_fixed_base_cache = { 0 };
static ecc_fixed_base_cache_t s_point_cache = { 0 };
static ecc_muladd_cache_t s_muladd_cache = { 0 };
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
    static drbg_state_t s_ecc_keygen_drbg_state;
    static int s_ecc_keygen_drbg_initialized = 0;
    uint8_t seed[NOXTLS_ECC_KEYGEN_DRBG_SEEDLEN];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(out == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_ecc_keygen_last_drbg_type = NOXTLS_ECC_KEYGEN_DRBG_TYPE;
    if(s_ecc_keygen_drbg_initialized == 0) {
        rc = noxtls_drbg_get_entropy(seed, sizeof(seed));
        noxtls_ecc_keygen_last_entropy_rc = (int32_t)rc;
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = drbg_instantiate(&s_ecc_keygen_drbg_state, NOXTLS_ECC_KEYGEN_DRBG_TYPE,
                              seed, sizeof(seed), NULL, 0, NULL, 0);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        s_ecc_keygen_drbg_initialized = 1;
    }

    rc = drbg_generate(&s_ecc_keygen_drbg_state, out, requested_bits, NULL, 0);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_SUCCESS;
    }

    noxtls_fill_u8((uint8_t *)(void *)(&s_ecc_keygen_drbg_state), sizeof(s_ecc_keygen_drbg_state), 0U, sizeof(s_ecc_keygen_drbg_state));
    s_ecc_keygen_drbg_initialized = 0;

    rc = noxtls_drbg_get_entropy(seed, sizeof(seed));
    noxtls_ecc_keygen_last_entropy_rc = (int32_t)rc;
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = drbg_instantiate(&s_ecc_keygen_drbg_state, NOXTLS_ECC_KEYGEN_DRBG_TYPE,
                          seed, sizeof(seed), NULL, 0, NULL, 0);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    s_ecc_keygen_drbg_initialized = 1;
    return drbg_generate(&s_ecc_keygen_drbg_state, out, requested_bits, NULL, 0);
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

    (void)noxtls_bn_mod(scratch.a_mod, a, size, p, size);
    if(noxtls_bn_is_zero(scratch.a_mod, size) != 0) {
        noxtls_secure_zero(&scratch, sizeof(scratch));
        return NOXTLS_RETURN_FAILED;
    }

    scratch.two[size - 1U] = 0x02U;
    scratch.one[size - 1U] = 0x01U;
    (void)noxtls_bn_copy(scratch.p_minus_2, p, size);
    (void)noxtls_bn_sub(scratch.p_minus_2, scratch.p_minus_2, scratch.two, size);

    /* Fast path: use generic modular inverse first. */
    if(noxtls_bn_mod_inv(result, scratch.a_mod, size, p, size) == NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_bn_mul(scratch.prod, scratch.a_mod, size, result, size);
        (void)noxtls_bn_mod(scratch.check, scratch.prod, size * 2U, p, size);
        if(noxtls_bn_cmp(scratch.check, scratch.one, size) == 0) {
            noxtls_secure_zero(&scratch, sizeof(scratch));
            return NOXTLS_RETURN_SUCCESS;
        }
    }

    /* Fallback for edge cases: Fermat inverse. */
    (void)noxtls_bn_mod_exp(result, scratch.a_mod, scratch.p_minus_2, size, p, size);
    (void)noxtls_bn_mul(scratch.prod, scratch.a_mod, size, result, size);
    (void)noxtls_bn_mod(scratch.check, scratch.prod, size * 2U, p, size);
    if(noxtls_bn_cmp(scratch.check, scratch.one, size) != 0) {
        noxtls_return_t rc = noxtls_bn_mod_inv(result, scratch.a_mod, size, p, size);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_secure_zero(&scratch, sizeof(scratch));
            return NOXTLS_RETURN_FAILED;
        }
        (void)noxtls_bn_mul(scratch.prod, scratch.a_mod, size, result, size);
        (void)noxtls_bn_mod(scratch.check, scratch.prod, size * 2U, p, size);
        if(noxtls_bn_cmp(scratch.check, scratch.one, size) != 0) {
            noxtls_secure_zero(&scratch, sizeof(scratch));
            return NOXTLS_RETURN_FAILED;
        }
    }

    noxtls_secure_zero(&scratch, sizeof(scratch));

    return NOXTLS_RETURN_SUCCESS;
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

/**
 * @brief Initialize ECC curve parameters
 *
 * @param curve ECC curve parameters
 * @param curve_type Curve type
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if curve is NULL
 */

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

noxtls_return_t noxtls_ecc_curve_init(ecc_curve_params_t *curve, ecc_curve_t curve_type)
{
    NOXTLS_ECC_TRACE("misra-ref");

    if(curve == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_fill_u8((uint8_t *)(void *)(curve), sizeof(ecc_curve_params_t), 0U, sizeof(ecc_curve_params_t));

    /* Set curve size based on type */
    {
        uint32_t curve_type_u = (uint32_t)curve_type;
        switch (curve_type_u) {
        case (uint32_t)NOXTLS_ECC_SECP192R1:
            curve->size = 24U;  /* 192 bits = 24 bytes */
            break;
        case (uint32_t)NOXTLS_ECC_SECP224R1:
            curve->size = 28U;  /* 224 bits = 28 bytes */
            break;
        case (uint32_t)NOXTLS_ECC_SECP256R1:
            curve->size = 32U;  /* 256 bits = 32 bytes */
            break;
        case (uint32_t)NOXTLS_ECC_SECP384R1:
            curve->size = 48U;  /* 384 bits = 48 bytes */
            break;
        case (uint32_t)NOXTLS_ECC_SECP521R1:
            curve->size = 66U;  /* 521 bits = 66 bytes */
            break;
        case (uint32_t)NOXTLS_ECC_BP256R1:
            curve->size = 32U;  /* 256 bits = 32 bytes */
            break;
        case (uint32_t)NOXTLS_ECC_BP384R1:
            curve->size = 48U;  /* 384 bits = 48 bytes */
            break;
        case (uint32_t)NOXTLS_ECC_BP512R1:
            curve->size = 64U;  /* 512 bits = 64 bytes */
            break;
        case (uint32_t)NOXTLS_ECC_SECP192K1:
            curve->size = 24U;  /* 192 bits = 24 bytes */
            break;
        case (uint32_t)NOXTLS_ECC_SECP224K1:
            curve->size = 28U;  /* 224 bits = 28 bytes */
            break;
        case (uint32_t)NOXTLS_ECC_SECP256K1:
            curve->size = 32U;  /* 256 bits = 32 bytes */
            break;
        default:
            return NOXTLS_RETURN_FAILED;
    }
    }

    /* Allocate memory for curve parameters */
    curve->p = (uint8_t*)NOXTLS_CALLOC(curve->size, 1);
    curve->a = (uint8_t*)NOXTLS_CALLOC(curve->size, 1);
    curve->b = (uint8_t*)NOXTLS_CALLOC(curve->size, 1);
    curve->n = (uint8_t*)NOXTLS_CALLOC(curve->size, 1);

    if((curve->p == NULL) || (curve->a == NULL) || (curve->b == NULL) || (curve->n == NULL)) {
        (void)noxtls_ecc_curve_free(curve);
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    /* Initialize curve parameters for specific curves */
    uint32_t size = (uint32_t)(curve->size);

    {
        uint32_t curve_type_u = (uint32_t)curve_type;
        switch (curve_type_u) {
        case (uint32_t)NOXTLS_ECC_SECP192R1: {
            static const uint8_t p_secp192r1[24] = {
                0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                0xFFU, 0xFFU, 0xFFU, 0xFEU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU
            };
            static const uint8_t a_secp192r1[24] = {
                0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                0xFFU, 0xFFU, 0xFFU, 0xFEU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFCU
            };
            static const uint8_t b_secp192r1[24] = {
                0x64U, 0x21U, 0x05U, 0x19U, 0xE5U, 0x9CU, 0x80U, 0xE7U, 0x0FU, 0xA7U, 0xE9U, 0xABU,
                0x72U, 0x24U, 0x30U, 0x49U, 0xFEU, 0xB8U, 0xDEU, 0xECU, 0xC1U, 0x46U, 0xB9U, 0xB1U
            };
            static const uint8_t gx_secp192r1[24] = {
                0x18U, 0x8DU, 0xA8U, 0x0EU, 0xB0U, 0x30U, 0x90U, 0xF6U, 0x7CU, 0xBFU, 0x20U, 0xEBU,
                0x43U, 0xA1U, 0x88U, 0x00U, 0xF4U, 0xFFU, 0x0AU, 0xFDU, 0x82U, 0xFFU, 0x10U, 0x12U
            };
            static const uint8_t gy_secp192r1[24] = {
                0x07U, 0x19U, 0x2BU, 0x95U, 0xFFU, 0xC8U, 0xDAU, 0x78U, 0x63U, 0x10U, 0x11U, 0xEDU,
                0x6BU, 0x24U, 0xCDU, 0xD5U, 0x73U, 0xF9U, 0x77U, 0xA1U, 0x1EU, 0x79U, 0x48U, 0x11U
            };
            static const uint8_t n_secp192r1[24] = {
                0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                0x99U, 0xDEU, 0xF8U, 0x36U, 0x14U, 0x6BU, 0xC9U, 0xB1U, 0xB4U, 0xD2U, 0x28U, 0x31U
            };
            noxtls_copy_u8(curve->p, (size_t)size, p_secp192r1, (size_t)size);
            noxtls_copy_u8(curve->a, (size_t)size, a_secp192r1, (size_t)size);
            noxtls_copy_u8(curve->b, (size_t)size, b_secp192r1, (size_t)size);
            noxtls_copy_u8(curve->G.x, sizeof(curve->G.x), gx_secp192r1, (size_t)size);
            noxtls_copy_u8(curve->G.y, sizeof(curve->G.y), gy_secp192r1, (size_t)size);
            curve->G.size = size;
            noxtls_copy_u8(curve->n, (size_t)size, n_secp192r1, (size_t)size);
            break;
        }
        case (uint32_t)NOXTLS_ECC_SECP224R1: {
            static const uint8_t p_secp224r1[28] = {
                0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x01U
            };
            static const uint8_t a_secp224r1[28] = {
                0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                0xFFU, 0xFFU, 0xFFU, 0xFEU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                0xFFU, 0xFFU, 0xFFU, 0xFEU
            };
            static const uint8_t b_secp224r1[28] = {
                0xB4U, 0x05U, 0x0AU, 0x85U, 0x0CU, 0x04U, 0xB3U, 0xABU, 0xF5U, 0x41U, 0x32U, 0x56U,
                0x50U, 0x44U, 0xB0U, 0xB7U, 0xD7U, 0xBFU, 0xD8U, 0xBAU, 0x27U, 0x0BU, 0x39U, 0x43U,
                0x23U, 0x55U, 0xFFU, 0xB4U
            };
            static const uint8_t gx_secp224r1[28] = {
                0xB7U, 0x0EU, 0x0CU, 0xBDU, 0x6BU, 0xB4U, 0xBFU, 0x7FU, 0x32U, 0x13U, 0x90U, 0xB9U,
                0x4AU, 0x03U, 0xC1U, 0xD3U, 0x56U, 0xC2U, 0x11U, 0x22U, 0x34U, 0x32U, 0x80U, 0xD6U,
                0x11U, 0x5CU, 0x1DU, 0x21U
            };
            static const uint8_t gy_secp224r1[28] = {
                0xBDU, 0x37U, 0x63U, 0x88U, 0xB5U, 0xF7U, 0x23U, 0xFBU, 0x4CU, 0x22U, 0xDFU, 0xE6U,
                0xCDU, 0x43U, 0x75U, 0xA0U, 0x5AU, 0x07U, 0x47U, 0x64U, 0x44U, 0xD5U, 0x81U, 0x99U,
                0x85U, 0x00U, 0x7EU, 0x34U
            };
            static const uint8_t n_secp224r1[28] = {
                0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                0xFFU, 0xFFU, 0x16U, 0xA2U, 0xE0U, 0xB8U, 0xF0U, 0x3EU, 0x13U, 0xDDU, 0x29U, 0x45U,
                0x5CU, 0x5CU, 0x2AU, 0x3DU
            };
            noxtls_copy_u8(curve->p, (size_t)size, p_secp224r1, (size_t)size);
            noxtls_copy_u8(curve->a, (size_t)size, a_secp224r1, (size_t)size);
            noxtls_copy_u8(curve->b, (size_t)size, b_secp224r1, (size_t)size);
            noxtls_copy_u8(curve->G.x, sizeof(curve->G.x), gx_secp224r1, (size_t)size);
            noxtls_copy_u8(curve->G.y, sizeof(curve->G.y), gy_secp224r1, (size_t)size);
            curve->G.size = size;
            noxtls_copy_u8(curve->n, (size_t)size, n_secp224r1, (size_t)size);
            break;
        }
        case (uint32_t)NOXTLS_ECC_SECP256R1: {
            /* NIST P-256 curve parameters */
            /* p = 2^256 - 2^224 + 2^192 + 2^96 - 1 */
            curve->p[31] = 0xFFU; curve->p[30] = 0xFFU; curve->p[29] = 0xFFU; curve->p[28] = 0xFFU;
            curve->p[27] = 0x00U; curve->p[26] = 0x00U; curve->p[25] = 0x00U; curve->p[24] = 0x01U;
            curve->p[23] = 0x00U; curve->p[22] = 0x00U; curve->p[21] = 0x00U; curve->p[20] = 0x00U;
            curve->p[19] = 0x00U; curve->p[18] = 0x00U; curve->p[17] = 0x00U; curve->p[16] = 0x00U;
            curve->p[15] = 0x00U; curve->p[14] = 0x00U; curve->p[13] = 0x00U; curve->p[12] = 0x00U;
            curve->p[11] = 0x00U; curve->p[10] = 0x00U; curve->p[9] = 0x00U; curve->p[8] = 0x00U;
            curve->p[7] = 0xFFU; curve->p[6] = 0xFFU; curve->p[5] = 0xFFU; curve->p[4] = 0xFFU;
            curve->p[3] = 0xFFU; curve->p[2] = 0xFFU; curve->p[1] = 0xFFU; curve->p[0] = 0xFFU;

            /* a = -3 mod p (which is p - 3) */
            (void)noxtls_bn_copy(curve->a, curve->p, size);
            uint8_t three[32];
            noxtls_fill_u8((uint8_t *)(void *)(three), sizeof(three), 0U, sizeof(three));
            three[0] = 0x03U;
            (void)noxtls_bn_sub(curve->a, curve->a, three, size);

            /* b = 0x5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E 27D2604B */
            curve->b[31] = 0x4BU; curve->b[30] = 0x60U; curve->b[29] = 0xD2U; curve->b[28] = 0x7EU;
            curve->b[27] = 0x3EU; curve->b[26] = 0x3CU; curve->b[25] = 0xCEU; curve->b[24] = 0x3BU;
            curve->b[23] = 0xF6U; curve->b[22] = 0xB0U; curve->b[21] = 0x53U; curve->b[20] = 0xCCU;
            curve->b[19] = 0xB0U; curve->b[18] = 0x06U; curve->b[17] = 0x1DU; curve->b[16] = 0x65U;
            curve->b[15] = 0xBCU; curve->b[14] = 0x86U; curve->b[13] = 0x98U; curve->b[12] = 0x76U;
            curve->b[11] = 0x55U; curve->b[10] = 0xBDU; curve->b[9] = 0xEBU; curve->b[8] = 0xB3U;
            curve->b[7] = 0xE7U; curve->b[6] = 0x93U; curve->b[5] = 0x3AU; curve->b[4] = 0xAAU;
            curve->b[3] = 0xD8U; curve->b[2] = 0x35U; curve->b[1] = 0xC6U; curve->b[0] = 0x5AU;

            /* G (generator point) - compressed form: 0x03 + x coordinate */
            /* Gx = 0x6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0 F4A13945 D898C296 */
            curve->G.x[31] = 0x96U; curve->G.x[30] = 0xC2U; curve->G.x[29] = 0x98U; curve->G.x[28] = 0xD8U;
            curve->G.x[27] = 0x45U; curve->G.x[26] = 0x39U; curve->G.x[25] = 0xA1U; curve->G.x[24] = 0xF4U;
            curve->G.x[23] = 0xA0U; curve->G.x[22] = 0x33U; curve->G.x[21] = 0xEBU; curve->G.x[20] = 0x2DU;
            curve->G.x[19] = 0x81U; curve->G.x[18] = 0x7DU; curve->G.x[17] = 0x03U; curve->G.x[16] = 0x77U;
            curve->G.x[15] = 0xF2U; curve->G.x[14] = 0x40U; curve->G.x[13] = 0xA4U; curve->G.x[12] = 0x63U;
            curve->G.x[11] = 0xE5U; curve->G.x[10] = 0xE6U; curve->G.x[9] = 0xBCU; curve->G.x[8] = 0xF8U;
            curve->G.x[7] = 0x47U; curve->G.x[6] = 0x24U; curve->G.x[5] = 0xC4U; curve->G.x[4] = 0x12U;
            curve->G.x[3] = 0xE1U; curve->G.x[2] = 0xF2U; curve->G.x[1] = 0xD1U; curve->G.x[0] = 0x6BU;

            /* Gy = 0x4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16 2BCE3357 6B315ECE CBB64068 37BF51F5 */
            curve->G.y[31] = 0xF5U; curve->G.y[30] = 0x51U; curve->G.y[29] = 0xBFU; curve->G.y[28] = 0x37U;
            curve->G.y[27] = 0x68U; curve->G.y[26] = 0x40U; curve->G.y[25] = 0xB6U; curve->G.y[24] = 0xCBU;
            curve->G.y[23] = 0xCEU; curve->G.y[22] = 0x5EU; curve->G.y[21] = 0x31U; curve->G.y[20] = 0x6BU;
            curve->G.y[19] = 0x57U; curve->G.y[18] = 0x33U; curve->G.y[17] = 0xCEU; curve->G.y[16] = 0x2BU;
            curve->G.y[15] = 0x16U; curve->G.y[14] = 0x9EU; curve->G.y[13] = 0x0FU; curve->G.y[12] = 0x7CU;
            curve->G.y[11] = 0x4AU; curve->G.y[10] = 0xEBU; curve->G.y[9] = 0xE7U; curve->G.y[8] = 0x8EU;
            curve->G.y[7] = 0x9BU; curve->G.y[6] = 0xF9U; curve->G.y[5] = 0x7AU; curve->G.y[4] = 0xF1U;
            curve->G.y[3] = 0xE1U; curve->G.y[2] = 0x42U; curve->G.y[1] = 0xE3U; curve->G.y[0] = 0x4FU;
            curve->G.size = size;

            /* n (order) = 0xFFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551 */
            curve->n[31] = 0x51U; curve->n[30] = 0x25U; curve->n[29] = 0x63U; curve->n[28] = 0xFCU;
            curve->n[27] = 0xC2U; curve->n[26] = 0xCAU; curve->n[25] = 0xC9U; curve->n[24] = 0xB3U;
            curve->n[23] = 0xF4U; curve->n[22] = 0x84U; curve->n[21] = 0x9EU; curve->n[20] = 0x17U;
            curve->n[19] = 0xA7U; curve->n[18] = 0xADU; curve->n[17] = 0xFAU; curve->n[16] = 0xE6U;
            curve->n[15] = 0xBCU; curve->n[14] = 0xFFU; curve->n[13] = 0xFFU; curve->n[12] = 0xFFU;
            curve->n[11] = 0xFFU; curve->n[10] = 0xFFU; curve->n[9] = 0xFFU; curve->n[8] = 0xFFU;
            curve->n[7] = 0x00U; curve->n[6] = 0x00U; curve->n[5] = 0x00U; curve->n[4] = 0x00U;
            curve->n[3] = 0xFFU; curve->n[2] = 0xFFU; curve->n[1] = 0xFFU; curve->n[0] = 0xFFU;

            /* Use big-endian constants to match bignum operations. */
            static const uint8_t p_secp256r1[32] = {
                0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x01U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU
            };
            /* a = p - 3 for secp256r1 (avoids reliance on bn_sub in curve init). */
            static const uint8_t a_secp256r1[32] = {
                0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x01U,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFCU
            };
            static const uint8_t b_secp256r1[32] = {
                0x5AU, 0xC6U, 0x35U, 0xD8U, 0xAAU, 0x3AU, 0x93U, 0xE7U,
                0xB3U, 0xEBU, 0xBDU, 0x55U, 0x76U, 0x98U, 0x86U, 0xBCU,
                0x65U, 0x1DU, 0x06U, 0xB0U, 0xCCU, 0x53U, 0xB0U, 0xF6U,
                0x3BU, 0xCEU, 0x3CU, 0x3EU, 0x27U, 0xD2U, 0x60U, 0x4BU
            };
            static const uint8_t gx_secp256r1[32] = {
                0x6BU, 0x17U, 0xD1U, 0xF2U, 0xE1U, 0x2CU, 0x42U, 0x47U,
                0xF8U, 0xBCU, 0xE6U, 0xE5U, 0x63U, 0xA4U, 0x40U, 0xF2U,
                0x77U, 0x03U, 0x7DU, 0x81U, 0x2DU, 0xEBU, 0x33U, 0xA0U,
                0xF4U, 0xA1U, 0x39U, 0x45U, 0xD8U, 0x98U, 0xC2U, 0x96U
            };
            static const uint8_t gy_secp256r1[32] = {
                0x4FU, 0xE3U, 0x42U, 0xE2U, 0xFEU, 0x1AU, 0x7FU, 0x9BU,
                0x8EU, 0xE7U, 0xEBU, 0x4AU, 0x7CU, 0x0FU, 0x9EU, 0x16U,
                0x2BU, 0xCEU, 0x33U, 0x57U, 0x6BU, 0x31U, 0x5EU, 0xCEU,
                0xCBU, 0xB6U, 0x40U, 0x68U, 0x37U, 0xBFU, 0x51U, 0xF5U
            };
            static const uint8_t n_secp256r1[32] = {
                0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x00U,
                0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                0xBCU, 0xE6U, 0xFAU, 0xADU, 0xA7U, 0x17U, 0x9EU, 0x84U,
                0xF3U, 0xB9U, 0xCAU, 0xC2U, 0xFCU, 0x63U, 0x25U, 0x51U
            };

            noxtls_copy_u8(curve->p, (size_t)size, p_secp256r1, (size_t)size);
            noxtls_copy_u8(curve->a, (size_t)size, a_secp256r1, (size_t)size);
            noxtls_copy_u8(curve->b, (size_t)size, b_secp256r1, (size_t)size);
            noxtls_copy_u8(curve->G.x, sizeof(curve->G.x), gx_secp256r1, (size_t)size);
            noxtls_copy_u8(curve->G.y, sizeof(curve->G.y), gy_secp256r1, (size_t)size);
            curve->G.size = size;
            noxtls_copy_u8(curve->n, (size_t)size, n_secp256r1, (size_t)size);
            break;
        }
        case (uint32_t)NOXTLS_ECC_SECP384R1:
            {
                /* NIST P-384 (secp384r1), 48 bytes, big-endian. */
                static const uint8_t p_secp384r1[48] = {
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFEU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x00U,
                    0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFFU
                };
                static const uint8_t a_secp384r1[48] = {
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFEU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x00U, 0x00U, 0x00U, 0x00U,
                    0x00U, 0x00U, 0x00U, 0x00U, 0xFFU, 0xFFU, 0xFFU, 0xFCU
                };
                static const uint8_t b_secp384r1[48] = {
                    0xB3U, 0x31U, 0x2FU, 0xA7U, 0xE2U, 0x3EU, 0xE7U, 0xE4U,
                    0x98U, 0x8EU, 0x05U, 0x6BU, 0xE3U, 0xF8U, 0x2DU, 0x19U,
                    0x18U, 0x1DU, 0x9CU, 0x6EU, 0xFEU, 0x81U, 0x41U, 0x12U,
                    0x03U, 0x14U, 0x08U, 0x8FU, 0x50U, 0x13U, 0x87U, 0x5AU,
                    0xC6U, 0x56U, 0x39U, 0x8DU, 0x8AU, 0x2EU, 0xD1U, 0x9DU,
                    0x2AU, 0x85U, 0xC8U, 0xEDU, 0xD3U, 0xECU, 0x2AU, 0xEFU
                };
                static const uint8_t gx_secp384r1[48] = {
                    0xAAU, 0x87U, 0xCAU, 0x22U, 0xBEU, 0x8BU, 0x05U, 0x37U,
                    0x8EU, 0xB1U, 0xC7U, 0x1EU, 0xF3U, 0x20U, 0xADU, 0x74U,
                    0x6EU, 0x1DU, 0x3BU, 0x62U, 0x8BU, 0xA7U, 0x9BU, 0x98U,
                    0x59U, 0xF7U, 0x41U, 0xE0U, 0x82U, 0x54U, 0x2AU, 0x38U,
                    0x55U, 0x02U, 0xF2U, 0x5DU, 0xBFU, 0x55U, 0x29U, 0x6CU,
                    0x3AU, 0x54U, 0x5EU, 0x38U, 0x72U, 0x76U, 0x0AU, 0xB7U
                };
                static const uint8_t gy_secp384r1[48] = {
                    0x36U, 0x17U, 0xDEU, 0x4AU, 0x96U, 0x26U, 0x2CU, 0x6FU,
                    0x5DU, 0x9EU, 0x98U, 0xBFU, 0x92U, 0x92U, 0xDCU, 0x29U,
                    0xF8U, 0xF4U, 0x1DU, 0xBDU, 0x28U, 0x9AU, 0x14U, 0x7CU,
                    0xE9U, 0xDAU, 0x31U, 0x13U, 0xB5U, 0xF0U, 0xB8U, 0xC0U,
                    0x0AU, 0x60U, 0xB1U, 0xCEU, 0x1DU, 0x7EU, 0x81U, 0x9DU,
                    0x7AU, 0x43U, 0x1DU, 0x7CU, 0x90U, 0xEAU, 0x0EU, 0x5FU
                };
                static const uint8_t n_secp384r1[48] = {
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xC7U, 0x63U, 0x4DU, 0x81U, 0xF4U, 0x37U, 0x2DU, 0xDFU,
                    0x58U, 0x1AU, 0x0DU, 0xB2U, 0x48U, 0xB0U, 0xA7U, 0x7AU,
                    0xECU, 0xECU, 0x19U, 0x6AU, 0xCCU, 0xC5U, 0x29U, 0x73U
                };
                noxtls_copy_u8(curve->p, (size_t)size, p_secp384r1, (size_t)size);
                noxtls_copy_u8(curve->a, (size_t)size, a_secp384r1, (size_t)size);
                noxtls_copy_u8(curve->b, (size_t)size, b_secp384r1, (size_t)size);
                noxtls_copy_u8(curve->G.x, sizeof(curve->G.x), gx_secp384r1, (size_t)size);
                noxtls_copy_u8(curve->G.y, sizeof(curve->G.y), gy_secp384r1, (size_t)size);
                curve->G.size = size;
                noxtls_copy_u8(curve->n, (size_t)size, n_secp384r1, (size_t)size);
            }
            break;
        case (uint32_t)NOXTLS_ECC_SECP521R1:
            {
                /* NIST P-521 (secp521r1), 66 bytes, big-endian. */
                static const uint8_t p_secp521r1[66] = {
                    0x01U, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU
                };
                static const uint8_t a_secp521r1[66] = {
                    0x01U, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFCU
                };
                static const uint8_t b_secp521r1[66] = {
                    0x00U, 0x51U, 0x95U, 0x3EU, 0xB9U, 0x61U, 0x8EU, 0x1CU,
                    0x9AU, 0x1FU, 0x92U, 0x9AU, 0x21U, 0xA0U, 0xB6U, 0x85U,
                    0x40U, 0xEEU, 0xA2U, 0xDAU, 0x72U, 0x5BU, 0x99U, 0xB3U,
                    0x15U, 0xF3U, 0xB8U, 0xB4U, 0x89U, 0x91U, 0x8EU, 0xF1U,
                    0x09U, 0xE1U, 0x56U, 0x19U, 0x39U, 0x51U, 0xECU, 0x7EU,
                    0x93U, 0x7BU, 0x16U, 0x52U, 0xC0U, 0xBDU, 0x3BU, 0xB1U,
                    0xBFU, 0x07U, 0x35U, 0x73U, 0xDFU, 0x88U, 0x3DU, 0x2CU,
                    0x34U, 0xF1U, 0xEFU, 0x45U, 0x1FU, 0xD4U, 0x6BU, 0x50U,
                    0x3FU, 0x00U
                };
                static const uint8_t gx_secp521r1[66] = {
                    0x00U, 0xC6U, 0x85U, 0x8EU, 0x06U, 0xB7U, 0x04U, 0x04U,
                    0xE9U, 0xCDU, 0x9EU, 0x3EU, 0xCBU, 0x66U, 0x23U, 0x95U,
                    0xB4U, 0x42U, 0x9CU, 0x64U, 0x81U, 0x39U, 0x05U, 0x3FU,
                    0xB5U, 0x21U, 0xF8U, 0x28U, 0xAFU, 0x60U, 0x6BU, 0x4DU,
                    0x3DU, 0xBAU, 0xA1U, 0x4BU, 0x5EU, 0x77U, 0xEFU, 0xE7U,
                    0x59U, 0x28U, 0xFEU, 0x1DU, 0xC1U, 0x27U, 0xA2U, 0xFFU,
                    0xA8U, 0xDEU, 0x33U, 0x48U, 0xB3U, 0xC1U, 0x85U, 0x6AU,
                    0x42U, 0x9BU, 0xF9U, 0x7EU, 0x7EU, 0x31U, 0xC2U, 0xE5U,
                    0xBDU, 0x66U
                };
                static const uint8_t gy_secp521r1[66] = {
                    0x01U, 0x18U, 0x39U, 0x29U, 0x6AU, 0x78U, 0x9AU, 0x3BU,
                    0xC0U, 0x04U, 0x5CU, 0x8AU, 0x5FU, 0xB4U, 0x2CU, 0x7DU,
                    0x1BU, 0xD9U, 0x98U, 0xF5U, 0x44U, 0x49U, 0x57U, 0x9BU,
                    0x44U, 0x68U, 0x17U, 0xAFU, 0xBDU, 0x17U, 0x27U, 0x3EU,
                    0x66U, 0x2CU, 0x97U, 0xEEU, 0x72U, 0x99U, 0x5EU, 0xF4U,
                    0x26U, 0x40U, 0xC5U, 0x50U, 0xB9U, 0x01U, 0x3FU, 0xADU,
                    0x07U, 0x61U, 0x35U, 0x3CU, 0x70U, 0x86U, 0xA2U, 0x72U,
                    0xC2U, 0x40U, 0x88U, 0xBEU, 0x94U, 0x76U, 0x9FU, 0xD1U,
                    0x66U, 0x50U
                };
                static const uint8_t n_secp521r1[66] = {
                    0x01U, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFAU, 0x51U, 0x86U, 0x87U, 0x83U, 0xBFU, 0x2FU,
                    0x96U, 0x6BU, 0x7FU, 0xCCU, 0x01U, 0x48U, 0xF7U, 0x09U,
                    0xA5U, 0xD0U, 0x3BU, 0xB5U, 0xC9U, 0xB8U, 0x89U, 0x9CU,
                    0x47U, 0xAEU, 0xBBU, 0x6FU, 0xB7U, 0x1EU, 0x91U, 0x38U,
                    0x64U, 0x09U
                };
                noxtls_copy_u8(curve->p, (size_t)size, p_secp521r1, (size_t)size);
                noxtls_copy_u8(curve->a, (size_t)size, a_secp521r1, (size_t)size);
                noxtls_copy_u8(curve->b, (size_t)size, b_secp521r1, (size_t)size);
                noxtls_copy_u8(curve->G.x, sizeof(curve->G.x), gx_secp521r1, (size_t)size);
                noxtls_copy_u8(curve->G.y, sizeof(curve->G.y), gy_secp521r1, (size_t)size);
                curve->G.size = size;
                noxtls_copy_u8(curve->n, (size_t)size, n_secp521r1, (size_t)size);
            }
            break;
        case (uint32_t)NOXTLS_ECC_BP256R1:
            {
                static const uint8_t p_brainpoolP256r1[32] = {
                    0xA9U, 0xFBU, 0x57U, 0xDBU, 0xA1U, 0xEEU, 0xA9U, 0xBCU, 0x3EU, 0x66U, 0x0AU, 0x90U, 0x9DU, 0x83U, 0x8DU, 0x72U,
                    0x6EU, 0x3BU, 0xF6U, 0x23U, 0xD5U, 0x26U, 0x20U, 0x28U, 0x20U, 0x13U, 0x48U, 0x1DU, 0x1FU, 0x6EU, 0x53U, 0x77U
                };
                static const uint8_t a_brainpoolP256r1[32] = {
                    0x7DU, 0x5AU, 0x09U, 0x75U, 0xFCU, 0x2CU, 0x30U, 0x57U, 0xEEU, 0xF6U, 0x75U, 0x30U, 0x41U, 0x7AU, 0xFFU, 0xE7U,
                    0xFBU, 0x80U, 0x55U, 0xC1U, 0x26U, 0xDCU, 0x5CU, 0x6CU, 0xE9U, 0x4AU, 0x4BU, 0x44U, 0xF3U, 0x30U, 0xB5U, 0xD9U
                };
                static const uint8_t b_brainpoolP256r1[32] = {
                    0x26U, 0xDCU, 0x5CU, 0x6CU, 0xE9U, 0x4AU, 0x4BU, 0x44U, 0xF3U, 0x30U, 0xB5U, 0xD9U, 0xBBU, 0xD7U, 0x7CU, 0xBFU,
                    0x95U, 0x84U, 0x16U, 0x29U, 0x5CU, 0xF7U, 0xE1U, 0xCEU, 0x6BU, 0xCCU, 0xDCU, 0x18U, 0xFFU, 0x8CU, 0x07U, 0xB6U
                };
                static const uint8_t gx_brainpoolP256r1[32] = {
                    0x8BU, 0xD2U, 0xAEU, 0xB9U, 0xCBU, 0x7EU, 0x57U, 0xCBU, 0x2CU, 0x4BU, 0x48U, 0x2FU, 0xFCU, 0x81U, 0xB7U, 0xAFU,
                    0xB9U, 0xDEU, 0x27U, 0xE1U, 0xE3U, 0xBDU, 0x23U, 0xC2U, 0x3AU, 0x44U, 0x53U, 0xBDU, 0x9AU, 0xCEU, 0x32U, 0x62U
                };
                static const uint8_t gy_brainpoolP256r1[32] = {
                    0x54U, 0x7EU, 0xF8U, 0x35U, 0xC3U, 0xDAU, 0xC4U, 0xFDU, 0x97U, 0xF8U, 0x46U, 0x1AU, 0x14U, 0x61U, 0x1DU, 0xC9U,
                    0xC2U, 0x77U, 0x45U, 0x13U, 0x2DU, 0xEDU, 0x8EU, 0x54U, 0x5CU, 0x1DU, 0x54U, 0xC7U, 0x2FU, 0x04U, 0x69U, 0x97U
                };
                static const uint8_t n_brainpoolP256r1[32] = {
                    0xA9U, 0xFBU, 0x57U, 0xDBU, 0xA1U, 0xEEU, 0xA9U, 0xBCU, 0x3EU, 0x66U, 0x0AU, 0x90U, 0x9DU, 0x83U, 0x8DU, 0x71U,
                    0x8CU, 0x39U, 0x7AU, 0xA3U, 0xB5U, 0x61U, 0xA6U, 0xF7U, 0x90U, 0x1EU, 0x0EU, 0x82U, 0x97U, 0x48U, 0x56U, 0xA7U
                };
                noxtls_copy_u8(curve->p, (size_t)size, p_brainpoolP256r1, (size_t)size);
                noxtls_copy_u8(curve->a, (size_t)size, a_brainpoolP256r1, (size_t)size);
                noxtls_copy_u8(curve->b, (size_t)size, b_brainpoolP256r1, (size_t)size);
                noxtls_copy_u8(curve->G.x, sizeof(curve->G.x), gx_brainpoolP256r1, (size_t)size);
                noxtls_copy_u8(curve->G.y, sizeof(curve->G.y), gy_brainpoolP256r1, (size_t)size);
                curve->G.size = size;
                noxtls_copy_u8(curve->n, (size_t)size, n_brainpoolP256r1, (size_t)size);
            }
            break;
        case (uint32_t)NOXTLS_ECC_BP384R1:
            {
                static const uint8_t p_brainpoolP384r1[48] = {
                    0x8CU, 0xB9U, 0x1EU, 0x82U, 0xA3U, 0x38U, 0x6DU, 0x28U, 0x0FU, 0x5DU, 0x6FU, 0x7EU, 0x50U, 0xE6U, 0x41U, 0xDFU,
                    0x15U, 0x2FU, 0x71U, 0x09U, 0xEDU, 0x54U, 0x56U, 0xB4U, 0x12U, 0xB1U, 0xDAU, 0x19U, 0x7FU, 0xB7U, 0x11U, 0x23U,
                    0xACU, 0xD3U, 0xA7U, 0x29U, 0x90U, 0x1DU, 0x1AU, 0x71U, 0x87U, 0x47U, 0x00U, 0x13U, 0x31U, 0x07U, 0xECU, 0x53U
                };
                static const uint8_t a_brainpoolP384r1[48] = {
                    0x7BU, 0xC3U, 0x82U, 0xC6U, 0x3DU, 0x8CU, 0x15U, 0x0CU, 0x3CU, 0x72U, 0x08U, 0x0AU, 0xCEU, 0x05U, 0xAFU, 0xA0U,
                    0xC2U, 0xBEU, 0xA2U, 0x8EU, 0x4FU, 0xB2U, 0x27U, 0x87U, 0x13U, 0x91U, 0x65U, 0xEFU, 0xBAU, 0x91U, 0xF9U, 0x0FU,
                    0x8AU, 0xA5U, 0x81U, 0x4AU, 0x50U, 0x3AU, 0xD4U, 0xEBU, 0x04U, 0xA8U, 0xC7U, 0xDDU, 0x22U, 0xCEU, 0x28U, 0x26U
                };
                static const uint8_t b_brainpoolP384r1[48] = {
                    0x04U, 0xA8U, 0xC7U, 0xDDU, 0x22U, 0xCEU, 0x28U, 0x26U, 0x8BU, 0x39U, 0xB5U, 0x54U, 0x16U, 0xF0U, 0x44U, 0x7CU,
                    0x2FU, 0xB7U, 0x7DU, 0xE1U, 0x07U, 0xDCU, 0xD2U, 0xA6U, 0x2EU, 0x88U, 0x0EU, 0xA5U, 0x3EU, 0xEBU, 0x62U, 0xD5U,
                    0x7CU, 0xB4U, 0x39U, 0x02U, 0x95U, 0xDBU, 0xC9U, 0x94U, 0x3AU, 0xB7U, 0x86U, 0x96U, 0xFAU, 0x50U, 0x4CU, 0x11U
                };
                static const uint8_t gx_brainpoolP384r1[48] = {
                    0x1DU, 0x1CU, 0x64U, 0xF0U, 0x68U, 0xCFU, 0x45U, 0xFFU, 0xA2U, 0xA6U, 0x3AU, 0x81U, 0xB7U, 0xC1U, 0x3FU, 0x6BU,
                    0x88U, 0x47U, 0xA3U, 0xE7U, 0x7EU, 0xF1U, 0x4FU, 0xE3U, 0xDBU, 0x7FU, 0xCAU, 0xFEU, 0x0CU, 0xBDU, 0x10U, 0xE8U,
                    0xE8U, 0x26U, 0xE0U, 0x34U, 0x36U, 0xD6U, 0x46U, 0xAAU, 0xEFU, 0x87U, 0xB2U, 0xE2U, 0x47U, 0xD4U, 0xAFU, 0x1EU
                };
                static const uint8_t gy_brainpoolP384r1[48] = {
                    0x8AU, 0xBEU, 0x1DU, 0x75U, 0x20U, 0xF9U, 0xC2U, 0xA4U, 0x5CU, 0xB1U, 0xEBU, 0x8EU, 0x95U, 0xCFU, 0xD5U, 0x52U,
                    0x62U, 0xB7U, 0x0BU, 0x29U, 0xFEU, 0xECU, 0x58U, 0x64U, 0xE1U, 0x9CU, 0x05U, 0x4FU, 0xF9U, 0x91U, 0x29U, 0x28U,
                    0x0EU, 0x46U, 0x46U, 0x21U, 0x77U, 0x91U, 0x81U, 0x11U, 0x42U, 0x82U, 0x03U, 0x41U, 0x26U, 0x3CU, 0x53U, 0x15U
                };
                static const uint8_t n_brainpoolP384r1[48] = {
                    0x8CU, 0xB9U, 0x1EU, 0x82U, 0xA3U, 0x38U, 0x6DU, 0x28U, 0x0FU, 0x5DU, 0x6FU, 0x7EU, 0x50U, 0xE6U, 0x41U, 0xDFU,
                    0x15U, 0x2FU, 0x71U, 0x09U, 0xEDU, 0x54U, 0x56U, 0xB3U, 0x1FU, 0x16U, 0x6EU, 0x6CU, 0xACU, 0x04U, 0x25U, 0xA7U,
                    0xCFU, 0x3AU, 0xB6U, 0xAFU, 0x6BU, 0x7FU, 0xC3U, 0x10U, 0x3BU, 0x88U, 0x32U, 0x02U, 0xE9U, 0x04U, 0x65U, 0x65U
                };
                noxtls_copy_u8(curve->p, (size_t)size, p_brainpoolP384r1, (size_t)size);
                noxtls_copy_u8(curve->a, (size_t)size, a_brainpoolP384r1, (size_t)size);
                noxtls_copy_u8(curve->b, (size_t)size, b_brainpoolP384r1, (size_t)size);
                noxtls_copy_u8(curve->G.x, sizeof(curve->G.x), gx_brainpoolP384r1, (size_t)size);
                noxtls_copy_u8(curve->G.y, sizeof(curve->G.y), gy_brainpoolP384r1, (size_t)size);
                curve->G.size = size;
                noxtls_copy_u8(curve->n, (size_t)size, n_brainpoolP384r1, (size_t)size);
            }
            break;
        case (uint32_t)NOXTLS_ECC_BP512R1:
            {
                static const uint8_t p_brainpoolP512r1[64] = {
                    0xAAU, 0xDDU, 0x9DU, 0xB8U, 0xDBU, 0xE9U, 0xC4U, 0x8BU, 0x3FU, 0xD4U, 0xE6U, 0xAEU, 0x33U, 0xC9U, 0xFCU, 0x07U,
                    0xCBU, 0x30U, 0x8DU, 0xB3U, 0xB3U, 0xC9U, 0xD2U, 0x0EU, 0xD6U, 0x63U, 0x9CU, 0xCAU, 0x70U, 0x33U, 0x08U, 0x71U,
                    0x7DU, 0x4DU, 0x9BU, 0x00U, 0x9BU, 0xC6U, 0x68U, 0x42U, 0xAEU, 0xCDU, 0xA1U, 0x2AU, 0xE6U, 0xA3U, 0x80U, 0xE6U,
                    0x28U, 0x81U, 0xFFU, 0x2FU, 0x2DU, 0x82U, 0xC6U, 0x85U, 0x28U, 0xAAU, 0x60U, 0x56U, 0x58U, 0x3AU, 0x48U, 0xF3U
                };
                static const uint8_t a_brainpoolP512r1[64] = {
                    0x78U, 0x30U, 0xA3U, 0x31U, 0x8BU, 0x60U, 0x3BU, 0x89U, 0xE2U, 0x32U, 0x71U, 0x45U, 0xACU, 0x23U, 0x4CU, 0xC5U,
                    0x94U, 0xCBU, 0xDDU, 0x8DU, 0x3DU, 0xF9U, 0x16U, 0x10U, 0xA8U, 0x34U, 0x41U, 0xCAU, 0xEAU, 0x98U, 0x63U, 0xBCU,
                    0x2DU, 0xEDU, 0x5DU, 0x5AU, 0xA8U, 0x25U, 0x3AU, 0xA1U, 0x0AU, 0x2EU, 0xF1U, 0xC9U, 0x8BU, 0x9AU, 0xC8U, 0xB5U,
                    0x7FU, 0x11U, 0x17U, 0xA7U, 0x2BU, 0xF2U, 0xC7U, 0xB9U, 0xE7U, 0xC1U, 0xACU, 0x4DU, 0x77U, 0xFCU, 0x94U, 0xCAU
                };
                static const uint8_t b_brainpoolP512r1[64] = {
                    0x3DU, 0xF9U, 0x16U, 0x10U, 0xA8U, 0x34U, 0x41U, 0xCAU, 0xEAU, 0x98U, 0x63U, 0xBCU, 0x2DU, 0xEDU, 0x5DU, 0x5AU,
                    0xA8U, 0x25U, 0x3AU, 0xA1U, 0x0AU, 0x2EU, 0xF1U, 0xC9U, 0x8BU, 0x9AU, 0xC8U, 0xB5U, 0x7FU, 0x11U, 0x17U, 0xA7U,
                    0x2BU, 0xF2U, 0xC7U, 0xB9U, 0xE7U, 0xC1U, 0xACU, 0x4DU, 0x77U, 0xFCU, 0x94U, 0xCAU, 0xDCU, 0x08U, 0x3EU, 0x67U,
                    0x98U, 0x40U, 0x50U, 0xB7U, 0x5EU, 0xBAU, 0xE5U, 0xDDU, 0x28U, 0x09U, 0xBDU, 0x63U, 0x80U, 0x16U, 0xF7U, 0x23U
                };
                static const uint8_t gx_brainpoolP512r1[64] = {
                    0x81U, 0xAEU, 0xE4U, 0xBDU, 0xD8U, 0x2EU, 0xD9U, 0x64U, 0x5AU, 0x21U, 0x32U, 0x2EU, 0x9CU, 0x4CU, 0x6AU, 0x93U,
                    0x85U, 0xEDU, 0x9FU, 0x70U, 0xB5U, 0xD9U, 0x16U, 0xC1U, 0xB4U, 0x3BU, 0x62U, 0xEEU, 0xF4U, 0xD0U, 0x09U, 0x8EU,
                    0xFFU, 0x3BU, 0x1FU, 0x78U, 0xE2U, 0xD0U, 0xD4U, 0x8DU, 0x50U, 0xD1U, 0x68U, 0x7BU, 0x93U, 0xB9U, 0x7DU, 0x5FU,
                    0x7CU, 0x6DU, 0x50U, 0x47U, 0x40U, 0x6AU, 0x5EU, 0x68U, 0x8BU, 0x35U, 0x22U, 0x09U, 0xBCU, 0xB9U, 0xF8U, 0x22U
                };
                static const uint8_t gy_brainpoolP512r1[64] = {
                    0x7DU, 0xDEU, 0x38U, 0x5DU, 0x56U, 0x63U, 0x32U, 0xECU, 0xC0U, 0xEAU, 0xBFU, 0xA9U, 0xCFU, 0x78U, 0x22U, 0xFDU,
                    0xF2U, 0x09U, 0xF7U, 0x00U, 0x24U, 0xA5U, 0x7BU, 0x1AU, 0xA0U, 0x00U, 0xC5U, 0x5BU, 0x88U, 0x1FU, 0x81U, 0x11U,
                    0xB2U, 0xDCU, 0xDEU, 0x49U, 0x4AU, 0x5FU, 0x48U, 0x5EU, 0x5BU, 0xCAU, 0x4BU, 0xD8U, 0x8AU, 0x27U, 0x63U, 0xAEU,
                    0xD1U, 0xCAU, 0x2BU, 0x2FU, 0xA8U, 0xF0U, 0x54U, 0x06U, 0x78U, 0xCDU, 0x1EU, 0x0FU, 0x3AU, 0xD8U, 0x08U, 0x92U
                };
                static const uint8_t n_brainpoolP512r1[64] = {
                    0xAAU, 0xDDU, 0x9DU, 0xB8U, 0xDBU, 0xE9U, 0xC4U, 0x8BU, 0x3FU, 0xD4U, 0xE6U, 0xAEU, 0x33U, 0xC9U, 0xFCU, 0x07U,
                    0xCBU, 0x30U, 0x8DU, 0xB3U, 0xB3U, 0xC9U, 0xD2U, 0x0EU, 0xD6U, 0x63U, 0x9CU, 0xCAU, 0x70U, 0x33U, 0x08U, 0x70U,
                    0x55U, 0x3EU, 0x5CU, 0x41U, 0x4CU, 0xA9U, 0x26U, 0x19U, 0x41U, 0x86U, 0x61U, 0x19U, 0x7FU, 0xACU, 0x10U, 0x47U,
                    0x1DU, 0xB1U, 0xD3U, 0x81U, 0x08U, 0x5DU, 0xDAU, 0xDDU, 0xB5U, 0x87U, 0x96U, 0x82U, 0x9CU, 0xA9U, 0x00U, 0x69U
                };
                noxtls_copy_u8(curve->p, (size_t)size, p_brainpoolP512r1, (size_t)size);
                noxtls_copy_u8(curve->a, (size_t)size, a_brainpoolP512r1, (size_t)size);
                noxtls_copy_u8(curve->b, (size_t)size, b_brainpoolP512r1, (size_t)size);
                noxtls_copy_u8(curve->G.x, sizeof(curve->G.x), gx_brainpoolP512r1, (size_t)size);
                noxtls_copy_u8(curve->G.y, sizeof(curve->G.y), gy_brainpoolP512r1, (size_t)size);
                curve->G.size = size;
                noxtls_copy_u8(curve->n, (size_t)size, n_brainpoolP512r1, (size_t)size);
            }
            break;
        case (uint32_t)NOXTLS_ECC_SECP192K1:
            {
                static const uint8_t p_secp192k1[24] = {
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFEU, 0xFFU, 0xFFU, 0xEEU, 0x37U
                };
                static const uint8_t a_secp192k1[24] = {0};
                static const uint8_t b_secp192k1[24] = {
                    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x03U
                };
                static const uint8_t gx_secp192k1[24] = {
                    0xDBU, 0x4FU, 0xF1U, 0x0EU, 0xC0U, 0x57U, 0xE9U, 0xAEU, 0x26U, 0xB0U, 0x7DU, 0x02U,
                    0x80U, 0xB7U, 0xF4U, 0x34U, 0x1DU, 0xA5U, 0xD1U, 0xB1U, 0xEAU, 0xE0U, 0x6CU, 0x7DU
                };
                static const uint8_t gy_secp192k1[24] = {
                    0x9BU, 0x2FU, 0x2FU, 0x6DU, 0x9CU, 0x56U, 0x28U, 0xA7U, 0x84U, 0x41U, 0x63U, 0xD0U,
                    0x15U, 0xBEU, 0x86U, 0x34U, 0x40U, 0x82U, 0xAAU, 0x88U, 0xD9U, 0x5EU, 0x2FU, 0x9DU
                };
                static const uint8_t n_secp192k1[24] = {
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFEU,
                    0x26U, 0xF2U, 0xFCU, 0x17U, 0x0FU, 0x69U, 0x46U, 0x6AU, 0x74U, 0xDEU, 0xFDU, 0x8DU
                };
                noxtls_copy_u8(curve->p, (size_t)size, p_secp192k1, (size_t)size);
                noxtls_copy_u8(curve->a, (size_t)size, a_secp192k1, (size_t)size);
                noxtls_copy_u8(curve->b, (size_t)size, b_secp192k1, (size_t)size);
                noxtls_copy_u8(curve->G.x, sizeof(curve->G.x), gx_secp192k1, (size_t)size);
                noxtls_copy_u8(curve->G.y, sizeof(curve->G.y), gy_secp192k1, (size_t)size);
                curve->G.size = size;
                noxtls_copy_u8(curve->n, (size_t)size, n_secp192k1, (size_t)size);
            }
            break;
        case (uint32_t)NOXTLS_ECC_SECP224K1:
            {
                static const uint8_t p_secp224k1[28] = {
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFEU,
                    0xFFU, 0xFFU, 0xE5U, 0x6DU
                };
                static const uint8_t a_secp224k1[28] = {0};
                static const uint8_t b_secp224k1[28] = {
                    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                    0x00U, 0x00U, 0x00U, 0x05U
                };
                static const uint8_t gx_secp224k1[28] = {
                    0xA1U, 0x45U, 0x5BU, 0x33U, 0x4DU, 0xF0U, 0x99U, 0xDFU, 0x30U, 0xFCU, 0x28U, 0xA1U,
                    0x69U, 0xA4U, 0x67U, 0xE9U, 0xE4U, 0x70U, 0x75U, 0xA9U, 0x0FU, 0x7EU, 0x65U, 0x0EU,
                    0xB6U, 0xB7U, 0xA4U, 0x5CU
                };
                static const uint8_t gy_secp224k1[28] = {
                    0x7EU, 0x08U, 0x9FU, 0xEDU, 0x7FU, 0xBAU, 0x34U, 0x42U, 0x82U, 0xCAU, 0xFBU, 0xD6U,
                    0xF7U, 0xE3U, 0x19U, 0xF7U, 0xC0U, 0xB0U, 0xBDU, 0x59U, 0xE2U, 0xCAU, 0x4BU, 0xDBU,
                    0x55U, 0x6DU, 0x61U, 0xA5U
                };
                static const uint8_t n_secp224k1[28] = {
                    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                    0x00U, 0x01U, 0xDCU, 0xE8U, 0xD2U, 0xECU, 0x61U, 0x84U, 0xCAU, 0xF0U, 0xA9U, 0x71U,
                    0x76U, 0x9FU, 0xB1U, 0xF7U
                };
                noxtls_copy_u8(curve->p, (size_t)size, p_secp224k1, (size_t)size);
                noxtls_copy_u8(curve->a, (size_t)size, a_secp224k1, (size_t)size);
                noxtls_copy_u8(curve->b, (size_t)size, b_secp224k1, (size_t)size);
                noxtls_copy_u8(curve->G.x, sizeof(curve->G.x), gx_secp224k1, (size_t)size);
                noxtls_copy_u8(curve->G.y, sizeof(curve->G.y), gy_secp224k1, (size_t)size);
                curve->G.size = size;
                noxtls_copy_u8(curve->n, (size_t)size, n_secp224k1, (size_t)size);
            }
            break;
        case (uint32_t)NOXTLS_ECC_SECP256K1:
            {
                static const uint8_t p_secp256k1[32] = {
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFEU, 0xFFU, 0xFFU, 0xFCU, 0x2FU
                };
                static const uint8_t a_secp256k1[32] = {0};
                static const uint8_t b_secp256k1[32] = {
                    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x07U
                };
                static const uint8_t gx_secp256k1[32] = {
                    0x79U, 0xBEU, 0x66U, 0x7EU, 0xF9U, 0xDCU, 0xBBU, 0xACU, 0x55U, 0xA0U, 0x62U, 0x95U,
                    0xCEU, 0x87U, 0x0BU, 0x07U, 0x02U, 0x9BU, 0xFCU, 0xDBU, 0x2DU, 0xCEU, 0x28U, 0xD9U,
                    0x59U, 0xF2U, 0x81U, 0x5BU, 0x16U, 0xF8U, 0x17U, 0x98U
                };
                static const uint8_t gy_secp256k1[32] = {
                    0x48U, 0x3AU, 0xDAU, 0x77U, 0x26U, 0xA3U, 0xC4U, 0x65U, 0x5DU, 0xA4U, 0xFBU, 0xFCU,
                    0x0EU, 0x11U, 0x08U, 0xA8U, 0xFDU, 0x17U, 0xB4U, 0x48U, 0xA6U, 0x85U, 0x54U, 0x19U,
                    0x9CU, 0x47U, 0xD0U, 0x8FU, 0xFBU, 0x10U, 0xD4U, 0xB8U
                };
                static const uint8_t n_secp256k1[32] = {
                    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
                    0xFFU, 0xFFU, 0xFFU, 0xFEU, 0xBAU, 0xAEU, 0xDCU, 0xE6U, 0xAFU, 0x48U, 0xA0U, 0x3BU,
                    0xBFU, 0xD2U, 0x5EU, 0x8CU, 0xD0U, 0x36U, 0x41U, 0x41U
                };
                noxtls_copy_u8(curve->p, (size_t)size, p_secp256k1, (size_t)size);
                noxtls_copy_u8(curve->a, (size_t)size, a_secp256k1, (size_t)size);
                noxtls_copy_u8(curve->b, (size_t)size, b_secp256k1, (size_t)size);
                noxtls_copy_u8(curve->G.x, sizeof(curve->G.x), gx_secp256k1, (size_t)size);
                noxtls_copy_u8(curve->G.y, sizeof(curve->G.y), gy_secp256k1, (size_t)size);
                curve->G.size = size;
                noxtls_copy_u8(curve->n, (size_t)size, n_secp256k1, (size_t)size);
            }
            break;
        default:
            return NOXTLS_RETURN_FAILED;
    }
    }

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

#if (NOXTLS_ECC_POINT_MUL_WINDOW_SIZE > 0) && (NOXTLS_ECC_FIXED_POINT_OPTIM) && (NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE)
    /*
     * Invalidate fixed-base precompute only for the curve that owns the cache.
     * Clearing cache on *every* curve free left s_fixed_base_cache.table allocated
     * while valid=0, so a later multiply could free/replace the wrong table and
     * break unrelated curves (observed with P-521 in a multi-key ECDSA matrix).
     */
    if((s_fixed_base_cache.valid != 0) && (s_fixed_base_cache.curve == curve)) {
        if(s_fixed_base_cache.table != NULL) {
            (void)noxtls_free(s_fixed_base_cache.table);
            s_fixed_base_cache.table = NULL;
        }
        s_fixed_base_cache.curve = NULL;
        s_fixed_base_cache.size = 0U;
        s_fixed_base_cache.valid = 0;
    }
    if((s_point_cache.valid != 0) && (s_point_cache.curve == curve)) {
        if(s_point_cache.table != NULL) {
            (void)noxtls_free(s_point_cache.table);
            s_point_cache.table = NULL;
        }
        s_point_cache.curve = NULL;
        s_point_cache.size = 0U;
        s_point_cache.valid = 0;
    }
    if((s_muladd_cache.valid != 0) && (s_muladd_cache.curve == curve)) {
        if(s_muladd_cache.table != NULL) {
            (void)noxtls_free(s_muladd_cache.table);
            s_muladd_cache.table = NULL;
        }
        s_muladd_cache.curve = NULL;
        s_muladd_cache.size = 0U;
        s_muladd_cache.valid = 0;
    }
#endif

    if(curve->p != NULL) { (void)noxtls_free(curve->p); curve->p = NULL; }
    if(curve->a != NULL) { (void)noxtls_free(curve->a); curve->a = NULL; }
    if(curve->b != NULL) { (void)noxtls_free(curve->b); curve->b = NULL; }
    if(curve->n != NULL) { (void)noxtls_free(curve->n); curve->n = NULL; }

    noxtls_fill_u8((uint8_t *)(void *)(curve), sizeof(ecc_curve_params_t), 0U, sizeof(ecc_curve_params_t));

    return NOXTLS_RETURN_SUCCESS;
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

/** Constant-time select Jacobian point: out = cond ? P : Q */
static void ecc_jpoint_cond_select(ecc_jpoint_t *out, const ecc_jpoint_t *P, const ecc_jpoint_t *Q, uint32_t size, uint8_t cond)
{
    ecc_cond_select(out->X, P->X, Q->X, size, cond);
    ecc_cond_select(out->Y, P->Y, Q->Y, size, cond);
    ecc_cond_select(out->Z, P->Z, Q->Z, size, cond);
}

/**
 * @brief Select the affine table
 *
 * @param[out] out The output point.
 * @param[in] table The table to select.
 * @param[in] table_len The length of the table.
 * @param[in] size The size of the point.
 * @param[in] idx The index to select.
 */
static void ecc_jpoint_select_affine_table(ecc_jpoint_t *out,
                                           const ecc_jpoint_t *table,
                                           uint32_t table_len,
                                           uint32_t size,
                                           uint32_t idx)
{
    uint8_t z_one[ECC_MAX_KEY_SIZE];
    uint32_t j = 0U;

    (void)noxtls_bn_zero(out->X, size);
    (void)noxtls_bn_zero(out->Y, size);
    (void)noxtls_bn_zero(out->Z, size);
    (void)noxtls_bn_zero(z_one, size);
    z_one[size - 1U] = 0x01U;

    for(j = 1U; j < table_len; j += 1U) {
        ecc_cond_select(out->X, table[j].X, out->X, size, ((idx == j) ? 1U : 0U));
        ecc_cond_select(out->Y, table[j].Y, out->Y, size, ((idx == j) ? 1U : 0U));
    }
    ecc_cond_select(out->Z, z_one, out->Z, size, ((idx != 0U) ? 1U : 0U));
}

#if NOXTLS_ECC_P256_FLASH_PRECOMPUTE
/** Constant-time selection from a compact P-256 affine table (X || Y). */
static void p256_select_compact_affine_table(ecc_jpoint_t *out,
                                             const uint8_t (*table)[NOXTLS_P256_AFFINE_POINT_SIZE],
                                             uint32_t table_len,
                                             uint32_t idx)
{
    uint8_t z_one[NOXTLS_P256_AFFINE_COORD_SIZE];
    uint32_t j;

    noxtls_secure_zero(out, (size_t)(sizeof(*out)));
    out->size = NOXTLS_P256_AFFINE_COORD_SIZE;
    noxtls_secure_zero(z_one, (size_t)(sizeof(z_one)));
    z_one[NOXTLS_P256_AFFINE_COORD_SIZE - 1U] = 0x01U;

    for(j = 1U; j < table_len; j++) {
        uint8_t selected = (uint8_t)(idx == j);
        ecc_cond_select(out->X, table[j], out->X,
                        NOXTLS_P256_AFFINE_COORD_SIZE, selected);
        ecc_cond_select(out->Y, table[j] + NOXTLS_P256_AFFINE_COORD_SIZE, out->Y,
                        NOXTLS_P256_AFFINE_COORD_SIZE, selected);
    }
    ecc_cond_select(out->Z, z_one, out->Z,
                    NOXTLS_P256_AFFINE_COORD_SIZE, (uint8_t)(idx != 0U));
}
#endif

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

/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static void ecc_mod_add(uint8_t *out, const uint8_t *a, const uint8_t *b, const uint8_t *p, uint32_t size);
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

static const uint32_t s_p256_order_words[8] = {
    0xFC632551U, 0xF3B9CAC2U, 0xA7179E84U, 0xBCE6FAADU,
    0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U, 0xFFFFFFFFU
};

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
 */
static void ecc_mul_mod(uint8_t *out, const uint8_t *a, const uint8_t *b, const uint8_t *p, uint32_t size, uint8_t *tmp2n)
{
    if(ecc_modulus_is_secp256r1(p, size) != 0) {
        p256_fe_mul(out, a, b);
        return;
    }
    if(size == 32U) {
        uint8_t prod64[64];
        ecc_mul_256_to_512(prod64, a, b);
        (void)noxtls_bn_mod(out, prod64, 64U, p, 32U);
        return;
    }
    (void)noxtls_bn_mul(tmp2n, a, size, b, size);
    (void)noxtls_bn_mod(out, tmp2n, size * 2U, p, size);
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
 */
static void ecc_mod_sub(uint8_t *out, const uint8_t *a, const uint8_t *b, const uint8_t *p, uint32_t size)
{
    if(ecc_modulus_is_secp256r1(p, size) != 0) {
        p256_fe_sub(out, a, b);
        return;
    }
    if((size == 0U) || (size > ECC_MAX_KEY_SIZE)) {
        if(out != NULL) {
            (void)noxtls_bn_zero(out, size);
        }
        return;
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
}

/**
 * @brief Compute (a + b) mod p (big-endian)
 *
 * @param out Output buffer
 * @param a First operand
 * @param b Second operand
 * @param p Modulus
 * @param size Size of the operands and modulus
 */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static void ecc_mod_add(uint8_t *out, const uint8_t *a, const uint8_t *b, const uint8_t *p, uint32_t size)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint16_t carry = 0U;
    uint16_t borrow = 0U;
    uint32_t i = 0U;

    if(ecc_modulus_is_secp256r1(p, size) != 0) {
        p256_fe_add(out, a, b);
        return;
    }

    if((size == 0U) || (size == UINT32_MAX) || (size > ECC_MAX_KEY_SIZE)) {
        return;
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
static noxtls_return_t ecc_jpoint_double(ecc_jpoint_t *out, const ecc_jpoint_t *P, const ecc_curve_params_t *curve)
{
    uint32_t size = (uint32_t)(curve->size);
    const uint8_t *p = curve->p;
    const uint8_t *a = curve->a;
    uint8_t t1[ECC_MAX_KEY_SIZE * 2U];
    uint8_t t2[ECC_MAX_KEY_SIZE * 2U];
    uint8_t t3[ECC_MAX_KEY_SIZE * 2U];
    uint8_t S[ECC_MAX_KEY_SIZE];
    uint8_t M[ECC_MAX_KEY_SIZE];
    static const uint8_t two_arr[1] = {0x02U};
    static const uint8_t three_arr[1] = {0x03U};
    static const uint8_t four_arr[1] = {0x04U};
    static const uint8_t eight_arr[1] = {0x08U};
    if((size == 0U) || (size > ECC_MAX_KEY_SIZE) || (size > (uint32_t)(UINT32_MAX / 2U)) || (size == UINT32_MAX)) {
        return NOXTLS_RETURN_FAILED;
    }

    if(ecc_curve_is_secp256r1(curve) != 0) {
        return p256_jpoint_double(out, P);
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

    /* S = 4*X1*Y1^2 mod p */
        ecc_mul_mod(t2, P->Y, P->Y, p, size, t1);
        ecc_mul_mod(t2, P->X, t2, p, size, t1);
        (void)noxtls_bn_mul(t1, t2, size, four_arr, 1);
        (void)noxtls_bn_mod(S, t1, size + 1U, p, size);

        /* M = 3*X1^2 + a*Z1^4 mod p */
        ecc_mul_mod(t2, P->X, P->X, p, size, t1);
        (void)noxtls_bn_mul(t1, t2, size, three_arr, 1);
        (void)noxtls_bn_mod(t2, t1, size + 1U, p, size);
        ecc_mul_mod(t3, P->Z, P->Z, p, size, t1);
        ecc_mul_mod(t3, t3, t3, p, size, t1);
        ecc_mul_mod(t3, a, t3, p, size, t1);
        ecc_mod_add(M, t2, t3, p, size);

        /* X3 = M^2 - 2*S mod p */
        ecc_mul_mod(t2, M, M, p, size, t1);
        (void)noxtls_bn_mul(t1, S, size, two_arr, 1);
        (void)noxtls_bn_mod(t3, t1, size + 1U, p, size);
        ecc_mod_sub(out->X, t2, t3, p, size);

        /* Y3 = M*(S - X3) - 8*Y1^4 mod p */
        ecc_mod_sub(t2, S, out->X, p, size);
        ecc_mul_mod(t2, M, t2, p, size, t1);
        ecc_mul_mod(t3, P->Y, P->Y, p, size, t1);
        ecc_mul_mod(t3, t3, t3, p, size, t1);
        (void)noxtls_bn_mul(t1, t3, size, eight_arr, 1);
        (void)noxtls_bn_mod(t3, t1, size + 1U, p, size);
        ecc_mod_sub(out->Y, t2, t3, p, size);

        /* Z3 = 2*Y1*Z1 mod p */
        ecc_mul_mod(t2, P->Y, P->Z, p, size, t1);
        (void)noxtls_bn_mul(t1, t2, size, two_arr, 1);
        (void)noxtls_bn_mod(out->Z, t1, size + 1U, p, size);

    out->size = size;
    return NOXTLS_RETURN_SUCCESS;
}

/* Jacobian add: out = P + Q. No inversion. Handles identity and P==Q is invalid (use double). */
/**
 * @brief Add two Jacobian points
 *
 * @param out The output buffer
 * @param P The first point
 * @param Q The second point
 * @param curve The curve
 * @return The return value
 */
static noxtls_return_t ecc_jpoint_add(ecc_jpoint_t *out, const ecc_jpoint_t *P, const ecc_jpoint_t *Q, const ecc_curve_params_t *curve)
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
    if((size == 0U) || (size > ECC_MAX_KEY_SIZE) || (size > (uint32_t)(UINT32_MAX / 2U))) {
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
    ecc_mul_mod(t2, P->Z, P->Z, p, size, t1);
    ecc_mul_mod(t3, Q->Z, Q->Z, p, size, t1);
    /* U1 = X1*Z2^2, U2 = X2*Z1^2 */
    ecc_mul_mod(U1, P->X, t3, p, size, t1);
    ecc_mul_mod(U2, Q->X, t2, p, size, t1);
    /* Z2^3 = Z2^2*Z2, Z1^3 = Z1^2*Z1 */
    ecc_mul_mod(t3, t3, Q->Z, p, size, t1);
    ecc_mul_mod(t2, t2, P->Z, p, size, t1);
    /* S1 = Y1*Z2^3, S2 = Y2*Z1^3 */
    ecc_mul_mod(S1, P->Y, t3, p, size, t1);
    ecc_mul_mod(S2, Q->Y, t2, p, size, t1);

    /* H = U2 - U1, R = S2 - S1 */
    ecc_mod_sub(H, U2, U1, p, size);
    ecc_mod_sub(R, S2, S1, p, size);

    if(noxtls_bn_is_zero(H, size) != 0) {
        /* P == Q or P == -Q. Caller must not use add for doubling. */
        if(noxtls_bn_is_zero(R, size) != 0) {
            return NOXTLS_RETURN_FAILED; /* would be doubling */
        }
        (void)noxtls_bn_zero(out->X, size);
        (void)noxtls_bn_zero(out->Y, size);
        (void)noxtls_bn_zero(out->Z, size);
        out->size = size; /* infinity */
        return NOXTLS_RETURN_SUCCESS;
    }

    /* X3 = R^2 - H^3 - 2*U1*H^2; also keep U1*H^2 and H^3 for Y3 */
    ecc_mul_mod(t2, H, H, p, size, t1);         /* t2 = H^2 */
    ecc_mul_mod(t3, t2, H, p, size, t1);        /* t3 = H^3 */
    ecc_mul_mod(t2, R, R, p, size, t1);         /* t2 = R^2 */
    ecc_mod_sub(t2, t2, t3, p, size);             /* t2 = R^2 - H^3 */
    ecc_mul_mod(t3, U1, H, p, size, t1);
    ecc_mul_mod(t3, t3, H, p, size, t1);        /* t3 = U1*H^2 */
    {
        const uint8_t two_arr[1] = {0x02U};
        (void)noxtls_bn_mul(t1, t3, size, two_arr, 1);
        (void)noxtls_bn_mod(t1, t1, size + 1U, p, size);
        ecc_mod_sub(out->X, t2, t1, p, size);
    }
    /* Y3 = R*(U1*H^2 - X3) - S1*H^3; t3 = U1*H^2, need H^3 again */
    ecc_mod_sub(t2, t3, out->X, p, size);         /* t2 = U1*H^2 - X3 */
    ecc_mul_mod(t2, R, t2, p, size, t1);        /* t2 = R*(U1*H^2 - X3) */
    ecc_mul_mod(t3, H, H, p, size, t1);
    ecc_mul_mod(t3, t3, H, p, size, t1);        /* t3 = H^3 */
    ecc_mul_mod(t3, S1, t3, p, size, t1);
    ecc_mod_sub(out->Y, t2, t3, p, size);

    /* Z3 = Z1*Z2*H */
    ecc_mul_mod(t2, P->Z, Q->Z, p, size, t1);
    ecc_mul_mod(out->Z, t2, H, p, size, t1);
    out->size = size;
    return NOXTLS_RETURN_SUCCESS;
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
    if((size == 0U) || (size > (uint32_t)(UINT32_MAX / 2U))) {
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
    (void)noxtls_bn_mod(temp2, temp2, size, curve->p, size);

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
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(noxtls_bn_is_zero(inv, size) != 0) {
        return NOXTLS_RETURN_FAILED;
    }
    ecc_mul_mod(z2, inv, inv, p, size, t1);
    ecc_mul_mod(z3, z2, inv, p, size, t1);
    ecc_mul_mod(x, J->X, z2, p, size, t1);
    ecc_mul_mod(y, J->Y, z3, p, size, t1);
    return rc;
}

#if NOXTLS_ECC_POINT_MUL_WINDOW_SIZE > 0

/**
 * @brief Precompute the table to affine
 *
 * @param[out] T The table to precompute.
 * @param[in] table_len The length of the table.
 * @param[in] curve The curve.
 * @return The return value.
 */
static noxtls_return_t ecc_precompute_table_to_affine(ecc_jpoint_t *T, uint32_t table_len, const ecc_curve_params_t *curve)
{
    uint32_t size = (uint32_t)(curve->size);
    const uint8_t *p = curve->p;
    uint32_t *active_idx = NULL;
    uint8_t *prefix = NULL;
    uint8_t acc[ECC_MAX_KEY_SIZE];
    uint8_t inv_z[ECC_MAX_KEY_SIZE];
    uint8_t next_acc[ECC_MAX_KEY_SIZE];
    uint8_t z2[ECC_MAX_KEY_SIZE];
    uint8_t z3[ECC_MAX_KEY_SIZE];
    uint8_t tmp2n[ECC_MAX_KEY_SIZE * 2U];
    uint32_t count = 0U;
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((size == 0U) || (size > ECC_MAX_KEY_SIZE) || (table_len < 2U)) {
        return NOXTLS_RETURN_FAILED;
    }

    active_idx = (uint32_t*)NOXTLS_CALLOC(table_len, sizeof(uint32_t));
    prefix = (uint8_t*)NOXTLS_CALLOC((size_t)table_len, size);
    if((active_idx == NULL) || (prefix == NULL)) {
        if(active_idx != NULL) {
            (void)noxtls_free(active_idx);
        }
        if(prefix != NULL) {
            (void)noxtls_free(prefix);
        }
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    noxtls_fill_u8((uint8_t *)(void *)(acc), sizeof(acc), 0U, sizeof(acc));
    noxtls_fill_u8((uint8_t *)(void *)(inv_z), sizeof(inv_z), 0U, sizeof(inv_z));
    noxtls_fill_u8((uint8_t *)(void *)(next_acc), sizeof(next_acc), 0U, sizeof(next_acc));
    noxtls_fill_u8((uint8_t *)(void *)(z2), sizeof(z2), 0U, sizeof(z2));
    noxtls_fill_u8((uint8_t *)(void *)(z3), sizeof(z3), 0U, sizeof(z3));
    noxtls_fill_u8((uint8_t *)(void *)(tmp2n), sizeof(tmp2n), 0U, sizeof(tmp2n));

    for(i = 1U; i < table_len; i += 1U) {
        uint8_t *prefix_i = NULL;

        if((ecc_jpoint_is_infinity(&T[i], size) != 0)) {
            continue;
        }

        active_idx[count] = i;
        prefix_i = &prefix[((size_t)count * size)];
        if(count == 0U) {
            (void)noxtls_bn_copy(prefix_i, T[i].Z, size);
        } else {
            ecc_mul_mod(prefix_i, &prefix[(((size_t)count - 1U) * size)], T[i].Z, p, size, tmp2n);
        }
        count += 1U;
    }

    if(count == 0U) {
        (void)noxtls_free(prefix);
        (void)noxtls_free(active_idx);
        return NOXTLS_RETURN_SUCCESS;
    }

    rc = ecc_mod_inv_prime(acc, &prefix[(((size_t)count - 1U) * size)], p, size);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_free(prefix);
        (void)noxtls_free(active_idx);
        return rc;
    }

    for(i = count; i > 0U; i -= 1U) {
        uint32_t pos = (uint32_t)(i - 1U);
        uint32_t point_idx = active_idx[pos];

        if(pos == 0U) {
            (void)noxtls_bn_copy(inv_z, acc, size);
        } else {
            ecc_mul_mod(inv_z, acc, &prefix[(((size_t)pos - 1U) * size)], p, size, tmp2n);
            ecc_mul_mod(next_acc, acc, T[point_idx].Z, p, size, tmp2n);
            (void)noxtls_bn_copy(acc, next_acc, size);
        }

        ecc_mul_mod(z2, inv_z, inv_z, p, size, tmp2n);
        ecc_mul_mod(z3, z2, inv_z, p, size, tmp2n);
        ecc_mul_mod(T[point_idx].X, T[point_idx].X, z2, p, size, tmp2n);
        ecc_mul_mod(T[point_idx].Y, T[point_idx].Y, z3, p, size, tmp2n);
        (void)noxtls_bn_zero(T[point_idx].Z, size);
        T[point_idx].Z[size - 1U] = 0x01U;
    }

    (void)noxtls_free(prefix);
    (void)noxtls_free(active_idx);
    return NOXTLS_RETURN_SUCCESS;
}

/** Build precomputation table T[0..2^w-1]: T[0]=identity, T[1]=P, T[i]=i*P in Jacobian. */
/**
 * @brief Build the precomputation table
 *
 * @param[in] T The precomputation table
 * @param[in] table_len The length of the precomputation table
 * @param[in] point The point
 * @param[in] curve The curve
 * @return The return value
 */
static noxtls_return_t ecc_build_precompute_table(ecc_jpoint_t *T, uint32_t table_len, const ecc_point_t *point, const ecc_curve_params_t *curve)
{
    uint32_t size = (uint32_t)(curve->size);
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint32_t i = 0U;

    if(table_len < 2U) { return NOXTLS_RETURN_FAILED; }
    noxtls_fill_u8((uint8_t *)(void *)(T), (size_t)(table_len * sizeof(ecc_jpoint_t)), 0U, (size_t)(table_len * sizeof(ecc_jpoint_t)));
    for(i = 0U; i < table_len; i += 1U) { T[i].size = size; }

    /* T[0] = identity (Z=0) */
    (void)noxtls_bn_zero(T[0].X, size);
    (void)noxtls_bn_zero(T[0].Y, size);
    (void)noxtls_bn_zero(T[0].Z, size);

    /* T[1] = P in Jacobian */
    (void)noxtls_bn_copy(T[1].X, point->x, size);
    (void)noxtls_bn_copy(T[1].Y, point->y, size);
    (void)noxtls_bn_zero(T[1].Z, size);
    T[1].Z[size - 1U] = 0x01U;

    /* T[2] = 2*P */
    rc = ecc_jpoint_double(&T[2], &T[1], curve);
    if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }

    for(i = 3U; i < table_len; i += 1U) {
        rc = ecc_jpoint_add(&T[i], &T[i - 1U], &T[1], curve);
        if(rc != NOXTLS_RETURN_SUCCESS) { return rc; }
    }

    if(ecc_curve_is_secp256r1(curve) != 0) {
        rc = ecc_precompute_table_to_affine(T, table_len, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

#if NOXTLS_ECC_P256_LOW_RAM_VERIFY
/* Build a compact runtime table for a public P-256 point. The temporary
 * Jacobian table is released after its affine coordinates are packed. */
static noxtls_return_t p256_build_compact_window_table(
    uint8_t (*compact)[NOXTLS_P256_AFFINE_POINT_SIZE],
    uint32_t table_len,
    const ecc_point_t *point,
    const ecc_curve_params_t *curve)
{
    ecc_jpoint_t *work;
    noxtls_return_t rc;
    uint32_t i;

    work = (ecc_jpoint_t*)NOXTLS_CALLOC(table_len, sizeof(ecc_jpoint_t));
    if(work == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    rc = ecc_build_precompute_table(work, table_len, point, curve);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(compact, (size_t)((size_t)table_len * NOXTLS_P256_AFFINE_POINT_SIZE));
        for(i = 1U; i < table_len; i++) {
            noxtls_copy_u8((uint8_t *)(void *)(compact[i]), (size_t)(NOXTLS_P256_AFFINE_COORD_SIZE), (const uint8_t *)(const void *)(work[i].X), (size_t)(NOXTLS_P256_AFFINE_COORD_SIZE));
            noxtls_copy_u8((uint8_t *)(void *)(compact[i] + NOXTLS_P256_AFFINE_COORD_SIZE), (size_t)(NOXTLS_P256_AFFINE_COORD_SIZE), (const uint8_t *)(const void *)(work[i].Y), (size_t)(NOXTLS_P256_AFFINE_COORD_SIZE));
        }
    }

    noxtls_free(work);
    return rc;
}
#endif

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
 * @brief Build the combination precomputation table
 *
 * @param[in] table The precomputation table
 * @param[in] table_len The length of the precomputation table
 * @param[in] point The point
 * @param[in] curve The curve
 * @param[in] w The width
 * @param[in] d The number of digits
 * @return The return value
 */
static noxtls_return_t p256_build_comb_precompute_table(ecc_jpoint_t *table,
                                                        uint32_t table_len,
                                                        const ecc_point_t *point,
                                                        const ecc_curve_params_t *curve,
                                                        uint32_t w,
                                                        uint32_t d)
{
    ecc_jpoint_t cur;
    ecc_jpoint_t tmp;
    uint32_t i = 0U;
    uint32_t j = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    noxtls_fill_u8((uint8_t *)(void *)(&cur), sizeof(cur), 0U, sizeof(cur));
    noxtls_fill_u8((uint8_t *)(void *)(&tmp), sizeof(tmp), 0U, sizeof(tmp));
    cur.size = 32U;
    tmp.size = 32U;

    noxtls_fill_u8((uint8_t *)(void *)(table), (size_t)(table_len * sizeof(ecc_jpoint_t)), 0U, (size_t)(table_len * sizeof(ecc_jpoint_t)));
    for(i = 0U; i < table_len; i += 1U) {
        table[i].size = 32U;
    }

    (void)noxtls_bn_zero(table[0].X, 32U);
    (void)noxtls_bn_zero(table[0].Y, 32U);
    (void)noxtls_bn_zero(table[0].Z, 32U);
    (void)noxtls_bn_copy(table[1].X, point->x, 32U);
    (void)noxtls_bn_copy(table[1].Y, point->y, 32U);
    (void)noxtls_bn_zero(table[1].Z, 32U);
    table[1].Z[31] = 0x01U;

    (void)noxtls_bn_copy(cur.X, point->x, 32U);
    (void)noxtls_bn_copy(cur.Y, point->y, 32U);
    (void)noxtls_bn_zero(cur.Z, 32U);
    cur.Z[31] = 0x01U;

    for(i = 1U; i < w; i += 1U) {
        for(j = 0U; j < d; j += 1U) {
                (void)p256_jpoint_double(&tmp, &cur);
            noxtls_copy_u8((uint8_t *)(void *)(&cur), sizeof(cur), (const uint8_t *)(const void *)(&tmp), sizeof(cur));
        }
        noxtls_copy_u8((uint8_t *)(void *)&table[ecc_window_table_len(i)], sizeof(cur), (const uint8_t *)(const void *)&cur, sizeof(cur));
    }

    if(table_len > 1U) {
        rc = ecc_precompute_table_to_affine(table, table_len, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    for(i = 1U; i < table_len; i <<= 1U) {
        for(j = 0U; j < i; j += 1U) {
            rc = ecc_jpoint_add(&table[i + j], &table[j], &table[i], curve);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
        }
    }

    if(table_len > 1U) {
        rc = ecc_precompute_table_to_affine(table, table_len, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Multiply the point by the scalar using the combination precomputation table
 *
 * @param[out] result The result
 * @param[in] scalar The scalar
 * @param[in] curve The curve
 * @param[in] table The precomputation table
 * @param[in] w The width
 * @return The return value
 */
static noxtls_return_t p256_ecc_jpoint_mul_comb(ecc_jpoint_t *result,
                                                const uint8_t *scalar,
                                                const ecc_curve_params_t *curve,
                                                const ecc_jpoint_t *table,
                                                uint32_t w)
{
    uint32_t d = (uint32_t)((256U + w - 1U) / w);
    uint8_t digits[64];
    ecc_jpoint_t R;
    ecc_jpoint_t Txi;
    ecc_jpoint_t Tdbl;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint32_t i = 0U;
    uint8_t reduced[32];

    noxtls_fill_u8((uint8_t *)(void *)(&R), sizeof(R), 0U, sizeof(R));
    noxtls_fill_u8((uint8_t *)(void *)(&Txi), sizeof(Txi), 0U, sizeof(Txi));
    noxtls_fill_u8((uint8_t *)(void *)(&Tdbl), sizeof(Tdbl), 0U, sizeof(Tdbl));
    R.size = 32U;
    Txi.size = 32U;
    Tdbl.size = 32U;

    p256_scalar_reduce_mod_order(reduced, scalar);
    p256_comb_recode_core(digits, d, w, reduced);

    for(i = d; i > 0U; i -= 1U) {
        (void)p256_jpoint_double(&Tdbl, &R);
        noxtls_copy_u8((uint8_t *)(void *)(&R), sizeof(R), (const uint8_t *)(const void *)(&Tdbl), sizeof(R));

        ecc_jpoint_select_affine_table(&Txi, table, ecc_window_table_len(w), 32U, digits[i - 1U]);
        Txi.size = 32U;
        rc = ecc_jpoint_add(&Tdbl, &R, &Txi, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        noxtls_copy_u8((uint8_t *)(void *)(&R), sizeof(R), (const uint8_t *)(const void *)(&Tdbl), sizeof(R));
    }

    noxtls_copy_u8((uint8_t *)(void *)(result), sizeof(*result), (const uint8_t *)(const void *)(&R), sizeof(R));
    result->size = 32U;
    return NOXTLS_RETURN_SUCCESS;
}

#if NOXTLS_ECC_P256_FLASH_PRECOMPUTE
/* P-256 fixed-base comb multiplication using the compact read-only G table. */
static noxtls_return_t p256_ecc_jpoint_mul_comb_flash(
    ecc_jpoint_t *result,
    const uint8_t *scalar,
    const ecc_curve_params_t *curve)
{
    const uint32_t w = NOXTLS_P256_FLASH_G_WINDOW;
    const uint32_t d = (256U + w - 1U) / w;
    uint8_t digits[64];
    uint8_t reduced[32];
    ecc_jpoint_t R;
    ecc_jpoint_t selected;
    ecc_jpoint_t doubled;
    noxtls_return_t rc;
    uint32_t i;

    noxtls_secure_zero(&R, (size_t)(sizeof(R)));
    noxtls_secure_zero(&selected, (size_t)(sizeof(selected)));
    noxtls_secure_zero(&doubled, (size_t)(sizeof(doubled)));
    R.size = selected.size = doubled.size = NOXTLS_P256_AFFINE_COORD_SIZE;

    p256_scalar_reduce_mod_order(reduced, scalar);
    p256_comb_recode_core(digits, d, w, reduced);

    for(i = d; i > 0U; i--) {
        rc = p256_jpoint_double(&doubled, &R);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        noxtls_copy_u8((uint8_t *)(void *)(&R), (size_t)(sizeof(R)), (const uint8_t *)(const void *)(&doubled), (size_t)(sizeof(R)));

        p256_select_compact_affine_table(&selected, s_noxtls_p256_g_comb_w5,
                                         NOXTLS_P256_FLASH_G_TABLE_LEN,
                                         digits[i - 1U]);
        rc = ecc_jpoint_add(&doubled, &R, &selected, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        noxtls_copy_u8((uint8_t *)(void *)(&R), (size_t)(sizeof(R)), (const uint8_t *)(const void *)(&doubled), (size_t)(sizeof(R)));
    }

    noxtls_copy_u8((uint8_t *)(void *)(result), (size_t)(sizeof(R)), (const uint8_t *)(const void *)(&R), (size_t)(sizeof(R)));
    result->size = NOXTLS_P256_AFFINE_COORD_SIZE;
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t p256_ecc_point_mul_comb_flash(
    ecc_point_t *result,
    const uint8_t *scalar,
    const ecc_curve_params_t *curve)
{
    ecc_jpoint_t R;
    noxtls_return_t rc;

    noxtls_secure_zero(&R, (size_t)(sizeof(R)));
    R.size = NOXTLS_P256_AFFINE_COORD_SIZE;
    rc = p256_ecc_jpoint_mul_comb_flash(&R, scalar, curve);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = ecc_jpoint_to_affine(result->x, result->y, &R, curve);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        result->size = NOXTLS_P256_AFFINE_COORD_SIZE;
    }
    return rc;
}
#endif

/**
 * @brief Multiply the point by the scalar using the combination precomputation table
 *
 * @param[out] result The result
 * @param[in] scalar The scalar
 * @param[in] curve The curve
 * @param[in] table The precomputation table
 * @param[in] w The width
 * @return The return value
 */
static noxtls_return_t p256_ecc_point_mul_comb(ecc_point_t *result,
                                               const uint8_t *scalar,
                                               const ecc_curve_params_t *curve,
                                               const ecc_jpoint_t *table,
                                               uint32_t w)
{
    ecc_jpoint_t R;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    noxtls_fill_u8((uint8_t *)(void *)(&R), sizeof(R), 0U, sizeof(R));
    R.size = 32U;

    rc = p256_ecc_jpoint_mul_comb(&R, scalar, curve, table, w);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = ecc_jpoint_to_affine(result->x, result->y, &R, curve);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        result->size = 32U;
    }
    return rc;
}

/**
 * @brief Build the joint precomputation table
 *
 * @param[in] joint_table The joint precomputation table
 * @param[in] w The width
 * @param[in] point1 The first point
 * @param[in] point2 The second point
 * @param[in] curve The curve
 * @return The return value
 */
static noxtls_return_t p256_build_joint_precompute_table(ecc_jpoint_t *joint_table,
                                                         uint32_t w,
                                                         const ecc_point_t *point1,
                                                         const ecc_point_t *point2,
                                                         const ecc_curve_params_t *curve)
{
    uint32_t size = (uint32_t)(curve->size);
    uint32_t side_len = ecc_window_table_len(w);
    uint32_t joint_len = (uint32_t)(side_len * side_len);
    ecc_jpoint_t *table1 = NULL;
    ecc_jpoint_t *table2 = NULL;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t a = 0U;
    uint32_t b = 0U;

    table1 = (ecc_jpoint_t*)NOXTLS_CALLOC(side_len, sizeof(ecc_jpoint_t));
    table2 = (ecc_jpoint_t*)NOXTLS_CALLOC(side_len, sizeof(ecc_jpoint_t));
    if((table1 == NULL) || (table2 == NULL)) {
        rc = NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        if(table1 != NULL) {
        (void)noxtls_free(table1);
    }
    if(table2 != NULL) {
        (void)noxtls_free(table2);
    }
    return rc;
    }

    rc = ecc_build_precompute_table(table1, side_len, point1, curve);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        if(table1 != NULL) {
        (void)noxtls_free(table1);
    }
    if(table2 != NULL) {
        (void)noxtls_free(table2);
    }
    return rc;
    }
    rc = ecc_build_precompute_table(table2, side_len, point2, curve);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        if(table1 != NULL) {
        (void)noxtls_free(table1);
    }
    if(table2 != NULL) {
        (void)noxtls_free(table2);
    }
    return rc;
    }

    noxtls_fill_u8((uint8_t *)(void *)(joint_table), (size_t)(joint_len * sizeof(ecc_jpoint_t)), 0U, (size_t)(joint_len * sizeof(ecc_jpoint_t)));
    for(a = 0U; a < side_len; a += 1U) {
        for(b = 0U; b < side_len; b += 1U) {
            uint32_t idx = (uint32_t)((a * side_len) + b);
            joint_table[idx].size = size;

            if((a == 0U) && (b == 0U)) {
                continue;
            }
            if(a == 0U) {
                noxtls_copy_u8((uint8_t *)(void *)(&joint_table[idx]), sizeof(joint_table[idx]), (const uint8_t *)(const void *)(&table2[b]), sizeof(ecc_jpoint_t));
                continue;
            }
            if(b == 0U) {
                noxtls_copy_u8((uint8_t *)(void *)(&joint_table[idx]), sizeof(joint_table[idx]), (const uint8_t *)(const void *)(&table1[a]), sizeof(ecc_jpoint_t));
                continue;
            }

            rc = ecc_jpoint_add(&joint_table[idx], &table1[a], &table2[b], curve);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                if(table1 != NULL) {
        (void)noxtls_free(table1);
    }
    if(table2 != NULL) {
        (void)noxtls_free(table2);
    }
    return rc;
            }
        }
    }

    rc = ecc_precompute_table_to_affine(joint_table, joint_len, curve);

cleanup_joint_table:
if(table1 != NULL) {
        (void)noxtls_free(table1);
    }
    if(table2 != NULL) {
        (void)noxtls_free(table2);
    }
    return rc;
}

/**
 * @brief Multiply the point by the scalar using the windowed precomputation table
 *
 * @param[out] result The result
 * @param[in] scalar1 The first scalar
 * @param[in] point1 The first point
 * @param[in] scalar2 The second scalar
 * @param[in] point2 The second point
 * @param[in] curve The curve
 * @return The return value
 */
static noxtls_return_t p256_ecc_point_muladd_windowed(ecc_point_t *result,
                                                      const uint8_t *scalar1,
                                                      const ecc_point_t *point1,
                                                      const uint8_t *scalar2,
                                                      const ecc_point_t *point2,
                                                      const ecc_curve_params_t *curve)
{
    const uint32_t w = 3U;
    uint32_t size = (uint32_t)(curve->size);
    uint32_t side_len = ecc_window_table_len(w);
    uint32_t joint_len = (uint32_t)(side_len * side_len);
    uint32_t n_bits = (uint32_t)(size * 8U);
    uint32_t t = (uint32_t)((n_bits + w - 1U) / w);
    uint32_t first_w = (uint32_t)(n_bits - ((t - 1U) * w));
    ecc_jpoint_t *table = NULL;
    ecc_jpoint_t *owned_table = NULL;
    ecc_jpoint_t R;
    ecc_jpoint_t T_sel;
    ecc_jpoint_t T_dbl;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    int use_cache = 0;
    uint32_t i = 0U;
    uint32_t j = 0U;
    uint32_t idx = 0U;

    noxtls_fill_u8((uint8_t *)(void *)(&R), sizeof(R), 0U, sizeof(R));
    noxtls_fill_u8((uint8_t *)(void *)(&T_sel), sizeof(T_sel), 0U, sizeof(T_sel));
    noxtls_fill_u8((uint8_t *)(void *)(&T_dbl), sizeof(T_dbl), 0U, sizeof(T_dbl));
    R.size = size;
    T_sel.size = size;
    T_dbl.size = size;

    if(first_w == 0U) {
        first_w = w;
    }

#if (NOXTLS_ECC_POINT_MUL_WINDOW_SIZE > 0) && (NOXTLS_ECC_FIXED_POINT_OPTIM) && (NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE)
    if((s_muladd_cache.valid != 0) &&
       (s_muladd_cache.curve == curve) &&
       (s_muladd_cache.w == w) &&
       (s_muladd_cache.size == size) &&
       (s_muladd_cache.table != NULL)) {
        if(noxtls_ct_memcmp(s_muladd_cache.p1x, point1->x, (size_t)size) == 0) {
            if(noxtls_ct_memcmp(s_muladd_cache.p1y, point1->y, (size_t)size) == 0) {
                if(noxtls_ct_memcmp(s_muladd_cache.p2x, point2->x, (size_t)size) == 0) {
                    if(noxtls_ct_memcmp(s_muladd_cache.p2y, point2->y, (size_t)size) == 0) {
                        table = s_muladd_cache.table;
                        use_cache = 1;
                    }
                }
            }
        }
    }
#endif

    if(table == NULL) {
        owned_table = (ecc_jpoint_t*)NOXTLS_CALLOC(joint_len, sizeof(ecc_jpoint_t));
        if(owned_table == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }

        rc = p256_build_joint_precompute_table(owned_table, w, point1, point2, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            (void)noxtls_free(owned_table);
            return rc;
        }
        table = owned_table;

#if (NOXTLS_ECC_POINT_MUL_WINDOW_SIZE > 0) && (NOXTLS_ECC_FIXED_POINT_OPTIM) && (NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE)
        if(s_muladd_cache.table != NULL) {
            (void)noxtls_free(s_muladd_cache.table);
        }
        s_muladd_cache.curve = curve;
        s_muladd_cache.table = owned_table;
        s_muladd_cache.w = w;
        s_muladd_cache.size = size;
        noxtls_copy_u8(s_muladd_cache.p1x, sizeof(s_muladd_cache.p1x), point1->x, (size_t)size);
        noxtls_copy_u8(s_muladd_cache.p1y, sizeof(s_muladd_cache.p1y), point1->y, (size_t)size);
        noxtls_copy_u8(s_muladd_cache.p2x, sizeof(s_muladd_cache.p2x), point2->x, (size_t)size);
        noxtls_copy_u8(s_muladd_cache.p2y, sizeof(s_muladd_cache.p2y), point2->y, (size_t)size);
        s_muladd_cache.valid = 1;
        use_cache = 1;
        owned_table = NULL;
#endif
    }

    idx = (ecc_scalar_digit_range(scalar1, size, 0U, first_w) * side_len) +
          ecc_scalar_digit_range(scalar2, size, 0U, first_w);
    ecc_jpoint_select_affine_table(&T_sel, table, joint_len, size, idx);
    T_sel.size = size;
    noxtls_copy_u8((uint8_t *)(void *)(&R), sizeof(R), (const uint8_t *)(const void *)(&T_sel), sizeof(ecc_jpoint_t));

    for(i = 1U; (i < t) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        for(j = 0U; (j < w) && (rc == NOXTLS_RETURN_SUCCESS); j += 1U) {
            rc = ecc_jpoint_double(&T_dbl, &R, curve);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                noxtls_copy_u8((uint8_t *)(void *)(&R), sizeof(R), (const uint8_t *)(const void *)(&T_dbl), sizeof(ecc_jpoint_t));
            }
        }

        if(rc == NOXTLS_RETURN_SUCCESS) {
            idx = (ecc_scalar_digit_range(scalar1, size, first_w + ((i - 1U) * w), w) * side_len) +
                  ecc_scalar_digit_range(scalar2, size, first_w + ((i - 1U) * w), w);
            ecc_jpoint_select_affine_table(&T_sel, table, joint_len, size, idx);
            T_sel.size = size;
            rc = ecc_jpoint_add(&T_dbl, &R, &T_sel, curve);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                noxtls_copy_u8((uint8_t *)(void *)(&R), sizeof(R), (const uint8_t *)(const void *)(&T_dbl), sizeof(ecc_jpoint_t));
            }
        }
    }

    if((owned_table != NULL) && (use_cache == 0)) {
        (void)noxtls_free(owned_table);
    }
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
 * @brief Multiply the point by the scalar using the windowed precomputation table
 *
 * @param[out] result The result
 * @param[in] scalar The scalar
 * @param[in] curve The curve
 * @param[in] table The precomputation table
 * @param[in] w The width
 * @return The return value
 */
static noxtls_return_t ecc_jpoint_mul_windowed(ecc_jpoint_t *result,
                                               const uint8_t *scalar,
                                               const ecc_curve_params_t *curve,
                                               const ecc_jpoint_t *table,
                                               uint32_t w)
{
    uint32_t size = (uint32_t)(curve->size);
    uint32_t n_bits = (uint32_t)(size * 8U);
    uint32_t t = (uint32_t)((n_bits + w - 1U) / w);  /* number of windows */
    uint32_t first_w = (uint32_t)(n_bits - ((t - 1U) * w));
    uint32_t table_len = ecc_window_table_len(w);
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

    /* First window: R = T[d_0]. Constant-time select T[d_0] into T_sel. */
    d = ecc_scalar_digit_range(scalar, size, 0U, first_w);
    if(ecc_curve_is_secp256r1(curve) != 0) {
        ecc_jpoint_select_affine_table(&T_sel, table, table_len, size, d);
        T_sel.size = size;
    } else {
        noxtls_copy_u8((uint8_t *)(void *)(&T_sel), sizeof(T_sel), (const uint8_t *)(const void *)(&table[0]), sizeof(ecc_jpoint_t));
        for(j = 1U; j < table_len; j += 1U) {
            ecc_jpoint_cond_select(&T_sel, &table[j], &T_sel, size, ((d == j) ? 1U : 0U));
        }
    }
    noxtls_copy_u8((uint8_t *)(void *)(&R), sizeof(R), (const uint8_t *)(const void *)(&T_sel), sizeof(ecc_jpoint_t));

    for(i = 1U; (i < t) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        /* R = 2^w * R (w doubles) */
        for(j = 0U; j < w; j += 1U) {
            rc = ecc_jpoint_double(&T_dbl, &R, curve);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            noxtls_copy_u8((uint8_t *)(void *)(&R), sizeof(R), (const uint8_t *)(const void *)(&T_dbl), sizeof(ecc_jpoint_t));
        }
        /* R = &R[T][d_i] */
        d = ecc_scalar_digit_range(scalar, size, first_w + ((i - 1U) * w), w);
        if(ecc_curve_is_secp256r1(curve) != 0) {
            ecc_jpoint_select_affine_table(&T_sel, table, table_len, size, d);
            T_sel.size = size;
        } else {
            noxtls_copy_u8((uint8_t *)(void *)(&T_sel), sizeof(T_sel), (const uint8_t *)(const void *)(&table[0]), sizeof(ecc_jpoint_t));
            for(j = 1U; j < table_len; j += 1U) {
                ecc_jpoint_cond_select(&T_sel, &table[j], &T_sel, size, ((d == j) ? 1U : 0U));
            }
        }
        rc = ecc_jpoint_add(&T_dbl, &R, &T_sel, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        noxtls_copy_u8((uint8_t *)(void *)(&R), sizeof(R), (const uint8_t *)(const void *)(&T_dbl), sizeof(ecc_jpoint_t));
    }

    noxtls_copy_u8((uint8_t *)(void *)(result), sizeof(*result), (const uint8_t *)(const void *)(&R), sizeof(ecc_jpoint_t));
    result->size = size;
    return NOXTLS_RETURN_SUCCESS;
}

#if NOXTLS_ECC_P256_LOW_RAM_VERIFY
/* Variable-base P-256 multiplication using a compact affine runtime table. */
static noxtls_return_t p256_ecc_jpoint_mul_windowed_compact(
    ecc_jpoint_t *result,
    const uint8_t *scalar,
    const ecc_curve_params_t *curve,
    const uint8_t (*table)[NOXTLS_P256_AFFINE_POINT_SIZE],
    uint32_t w)
{
    const uint32_t n_bits = 256U;
    const uint32_t windows = (n_bits + w - 1U) / w;
    uint32_t first_w = n_bits - ((windows - 1U) * w);
    const uint32_t table_len = 1U << w;
    ecc_jpoint_t R;
    ecc_jpoint_t selected;
    ecc_jpoint_t doubled;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t i;
    uint32_t j;
    uint32_t digit;

    noxtls_secure_zero(&R, (size_t)(sizeof(R)));
    noxtls_secure_zero(&selected, (size_t)(sizeof(selected)));
    noxtls_secure_zero(&doubled, (size_t)(sizeof(doubled)));
    R.size = selected.size = doubled.size = NOXTLS_P256_AFFINE_COORD_SIZE;
    if(first_w == 0U) {
        first_w = w;
    }

    digit = ecc_scalar_digit_range(scalar, NOXTLS_P256_AFFINE_COORD_SIZE,
                                    0U, first_w);
    p256_select_compact_affine_table(&R, table, table_len, digit);

    for(i = 1U; i < windows; i++) {
        for(j = 0U; j < w; j++) {
            rc = p256_jpoint_double(&doubled, &R);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            noxtls_copy_u8((uint8_t *)(void *)(&R), (size_t)(sizeof(R)), (const uint8_t *)(const void *)(&doubled), (size_t)(sizeof(R)));
        }

        digit = ecc_scalar_digit_range(scalar, NOXTLS_P256_AFFINE_COORD_SIZE,
                                        first_w + ((i - 1U) * w), w);
        p256_select_compact_affine_table(&selected, table, table_len, digit);
        rc = ecc_jpoint_add(&doubled, &R, &selected, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        noxtls_copy_u8((uint8_t *)(void *)(&R), (size_t)(sizeof(R)), (const uint8_t *)(const void *)(&doubled), (size_t)(sizeof(R)));
    }

    noxtls_copy_u8((uint8_t *)(void *)(result), (size_t)(sizeof(R)), (const uint8_t *)(const void *)(&R), (size_t)(sizeof(R)));
    result->size = NOXTLS_P256_AFFINE_COORD_SIZE;
    return NOXTLS_RETURN_SUCCESS;
}
#endif

/**
 * @brief Multiply the point by the scalar using the windowed precomputation table
 *
 * @param[out] result The result
 * @param[in] scalar The scalar
 * @param[in] curve The curve
 * @param[in] table The precomputation table
 * @param[in] w The width
 * @return The return value
 */
static noxtls_return_t ecc_point_mul_windowed(ecc_point_t *result, const uint8_t *scalar, const ecc_curve_params_t *curve,
                                               const ecc_jpoint_t *table, uint32_t w)
{
    ecc_jpoint_t R;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    noxtls_fill_u8((uint8_t *)(void *)(&R), sizeof(R), 0U, sizeof(R));
    R.size = curve->size;

    rc = ecc_jpoint_mul_windowed(&R, scalar, curve, table, w);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = ecc_jpoint_to_affine(result->x, result->y, &R, curve);
    if(rc == NOXTLS_RETURN_SUCCESS) { result->size = curve->size; }
    return rc;
}
#endif /* NOXTLS_ECC_POINT_MUL_WINDOW_SIZE > 0 */

/**
 * @brief Multiply the point by the scalar using the windowed precomputation table
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
        const int is_fixed_base = ecc_point_equal(point, &curve->G, size);
        const uint32_t w = ecc_point_mul_window_size_for_curve(curve, is_fixed_base);
        uint32_t table_len = ecc_window_table_len(w);
        ecc_jpoint_t *table = NULL;
        int use_cache = 0;
        int use_flash = 0;

#if NOXTLS_ECC_P256_FLASH_PRECOMPUTE
        if(is_fixed_base && ecc_curve_is_secp256r1(curve)) {
            use_flash = 1;
            rc = p256_ecc_jpoint_mul_comb_flash(result, scalar, curve);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
        }
#endif

#if NOXTLS_ECC_FIXED_POINT_OPTIM && NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE
        if((is_fixed_base != 0) && (s_fixed_base_cache.valid != 0) && (s_fixed_base_cache.curve == curve) &&
           (s_fixed_base_cache.w == w) && (s_fixed_base_cache.size == size) &&
           (s_fixed_base_cache.table != NULL)) {
            if(noxtls_ct_memcmp(s_fixed_base_cache.gx, curve->G.x, (size_t)size) == 0) {
                if(noxtls_ct_memcmp(s_fixed_base_cache.gy, curve->G.y, (size_t)size) == 0) {
                    table = s_fixed_base_cache.table;
                    use_cache = 1;
                }
            }
        } else if((s_point_cache.valid != 0) && (s_point_cache.curve == curve) &&
                  (s_point_cache.w == w) && (s_point_cache.size == size) &&
                  (s_point_cache.table != NULL)) {
            if(noxtls_ct_memcmp(s_point_cache.gx, point->x, (size_t)size) == 0) {
                if(noxtls_ct_memcmp(s_point_cache.gy, point->y, (size_t)size) == 0) {
                    table = s_point_cache.table;
                    use_cache = 1;
                }
            }
        } else {
            /* MISRA 15.7: no precompute cache hit */
        }
#endif
        if((use_cache == 0) && (use_flash == 0)) {
            table = (ecc_jpoint_t*)NOXTLS_CALLOC(table_len, sizeof(ecc_jpoint_t));
            if(table != NULL) {
                if(ecc_curve_is_secp256r1(curve) != 0) {
                    rc = p256_build_comb_precompute_table(table, table_len, point, curve, w, (256U + w - 1U) / w);
                } else {
                    rc = ecc_build_precompute_table(table, table_len, point, curve);
                }
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    (void)noxtls_free(table);
                    table = NULL;
                }
#if NOXTLS_ECC_FIXED_POINT_OPTIM && NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE
                else if(is_fixed_base != 0) {
                    if(s_fixed_base_cache.table != NULL) { (void)noxtls_free(s_fixed_base_cache.table); }
                    s_fixed_base_cache.curve = curve;
                    s_fixed_base_cache.table = table;
                    s_fixed_base_cache.w = w;
                    s_fixed_base_cache.size = size;
                    noxtls_copy_u8(s_fixed_base_cache.gx, sizeof(s_fixed_base_cache.gx), curve->G.x, (size_t)size);
                    noxtls_copy_u8(s_fixed_base_cache.gy, sizeof(s_fixed_base_cache.gy), curve->G.y, (size_t)size);
                    s_fixed_base_cache.valid = 1;
                    use_cache = 1;
                } else {
                    if(s_point_cache.table != NULL) { (void)noxtls_free(s_point_cache.table); }
                    s_point_cache.curve = curve;
                    s_point_cache.table = table;
                    s_point_cache.w = w;
                    s_point_cache.size = size;
                    noxtls_copy_u8(s_point_cache.gx, sizeof(s_point_cache.gx), point->x, (size_t)size);
                    noxtls_copy_u8(s_point_cache.gy, sizeof(s_point_cache.gy), point->y, (size_t)size);
                    s_point_cache.valid = 1;
                    use_cache = 1;
                }
#endif
            }
        }
        if(table != NULL) {
            if(ecc_curve_is_secp256r1(curve) != 0) {
                rc = p256_ecc_jpoint_mul_comb(result, scalar, curve, table, w);
            } else {
                rc = ecc_jpoint_mul_windowed(result, scalar, curve, table, w);
            }
#if !(NOXTLS_ECC_FIXED_POINT_OPTIM && NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE)
            (void)noxtls_free(table);
#else
            if(use_cache == 0) { (void)noxtls_free(table); }
#endif
            if(rc == NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
        }
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

/**
 * @brief ECC Scalar Multiplication: R = k * P
 *
 * Uses windowed precomputation when NOXTLS_ECC_POINT_MUL_WINDOW_SIZE >= 2,
 * with optional fixed-base cache for G. Falls back to constant-time Montgomery ladder otherwise.
 */
noxtls_return_t noxtls_ecc_point_multiply(ecc_point_t *result, const uint8_t *scalar, const ecc_point_t *point, const ecc_curve_params_t *curve)
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
    noxtls_ecc_accel_note_fallback();
    /* HW failed or disabled: fall back to software path. */
    if(rc != NOXTLS_RETURN_NOT_SUPPORTED) {
        (void)noxtls_bn_zero(result->x, size);
        (void)noxtls_bn_zero(result->y, size);
    }
    rc = NOXTLS_RETURN_SUCCESS;

#if NOXTLS_ECC_POINT_MUL_WINDOW_SIZE >= 2
    /*
     * secp521r1 (66-byte coordinates) and brainpoolP512r1 (64-byte coordinates):
     * windowed / fixed-base precomputation has produced incorrect points in TLS 1.3
     * ECDSA CertificateVerify interop; use the Montgomery ladder only for these sizes.
     */
    if((size != 66U) && (size != 64U)) {
        {
            const int is_fixed_base = ecc_point_equal(point, &curve->G, size);
            const uint32_t w = ecc_point_mul_window_size_for_curve(curve, is_fixed_base);
            uint32_t table_len = ecc_window_table_len(w);
            ecc_jpoint_t *table = NULL;
            int use_cache = 0;
            int use_flash = 0;

#if NOXTLS_ECC_P256_FLASH_PRECOMPUTE
            if(is_fixed_base && ecc_curve_is_secp256r1(curve)) {
                use_flash = 1;
                rc = p256_ecc_point_mul_comb_flash(result, scalar, curve);
                if(rc == NOXTLS_RETURN_SUCCESS) {
                    return rc;
                }
            }
#endif

#if NOXTLS_ECC_FIXED_POINT_OPTIM && NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE
            if((is_fixed_base != 0) && (s_fixed_base_cache.valid != 0) && (s_fixed_base_cache.curve == curve) &&
                (s_fixed_base_cache.w == w) && (s_fixed_base_cache.size == size) &&
                (s_fixed_base_cache.table != NULL)) {
                if(noxtls_ct_memcmp(s_fixed_base_cache.gx, curve->G.x, (size_t)size) == 0) {
                    if(noxtls_ct_memcmp(s_fixed_base_cache.gy, curve->G.y, (size_t)size) == 0) {
                        table = s_fixed_base_cache.table;
                        use_cache = 1;
                    }
                }
            } else if((s_point_cache.valid != 0) && (s_point_cache.curve == curve) &&
                      (s_point_cache.w == w) && (s_point_cache.size == size) &&
                      (s_point_cache.table != NULL)) {
                if(noxtls_ct_memcmp(s_point_cache.gx, point->x, (size_t)size) == 0) {
                    if(noxtls_ct_memcmp(s_point_cache.gy, point->y, (size_t)size) == 0) {
                        table = s_point_cache.table;
                        use_cache = 1;
                    }
                }
            } else {
                /* MISRA 15.7: no precompute cache hit */
            }
#endif
            if((use_cache == 0) && (use_flash == 0)) {
                table = (ecc_jpoint_t*)NOXTLS_CALLOC(table_len, sizeof(ecc_jpoint_t));
                if(table != NULL) {
                    if(ecc_curve_is_secp256r1(curve) != 0) {
                        rc = p256_build_comb_precompute_table(table, table_len, point, curve, w, (256U + w - 1U) / w);
                    } else {
                        rc = ecc_build_precompute_table(table, table_len, point, curve);
                    }
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        (void)noxtls_free(table);
                        table = NULL;
                    }
#if NOXTLS_ECC_FIXED_POINT_OPTIM && NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE
                    else if(is_fixed_base != 0) {
                        /* Evict previous cache */
                        if(s_fixed_base_cache.table != NULL) { (void)noxtls_free(s_fixed_base_cache.table); }
                        s_fixed_base_cache.curve = curve;
                        s_fixed_base_cache.table = table;
                        s_fixed_base_cache.w = w;
                        s_fixed_base_cache.size = size;
                        noxtls_copy_u8(s_fixed_base_cache.gx, sizeof(s_fixed_base_cache.gx), curve->G.x, (size_t)size);
                        noxtls_copy_u8(s_fixed_base_cache.gy, sizeof(s_fixed_base_cache.gy), curve->G.y, (size_t)size);
                        s_fixed_base_cache.valid = 1;
                        use_cache = 1;  /* don't free table below */
                    }
                    else {
                        if(s_point_cache.table != NULL) { (void)noxtls_free(s_point_cache.table); }
                        s_point_cache.curve = curve;
                        s_point_cache.table = table;
                        s_point_cache.w = w;
                        s_point_cache.size = size;
                        noxtls_copy_u8(s_point_cache.gx, sizeof(s_point_cache.gx), point->x, (size_t)size);
                        noxtls_copy_u8(s_point_cache.gy, sizeof(s_point_cache.gy), point->y, (size_t)size);
                        s_point_cache.valid = 1;
                        use_cache = 1;  /* don't free table below */
                    }
#endif
                }
            }
            if(table != NULL) {
                if(ecc_curve_is_secp256r1(curve) != 0) {
                    rc = p256_ecc_point_mul_comb(result, scalar, curve, table, w);
                } else {
                    rc = ecc_point_mul_windowed(result, scalar, curve, table, w);
                }
#if !(NOXTLS_ECC_FIXED_POINT_OPTIM && NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE)
                (void)noxtls_free(table);
#else
                if(use_cache == 0) { (void)noxtls_free(table); }
#endif
                if(rc == NOXTLS_RETURN_SUCCESS) { return rc; }
                /* Fall through to ladder on failure (e.g. add returned failure) */
                (void)noxtls_bn_zero(result->x, size);
                (void)noxtls_bn_zero(result->y, size);
            }
            /* If table alloc failed or windowed path failed, fall back to ladder */
        }
    }
#endif

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

#if NOXTLS_ECC_P256_LOW_RAM_VERIFY
/* Compute k1*G + k2*Q without the 64-entry joint table. G comes from the
 * read-only comb table; only an 8-entry compact table for runtime Q is kept. */
static noxtls_return_t p256_ecc_point_muladd_low_ram(
    ecc_point_t *result,
    const uint8_t *scalar_g,
    const uint8_t *scalar_q,
    const ecc_point_t *point_q,
    const ecc_curve_params_t *curve)
{
    const uint32_t q_window = 3U;
    const uint32_t q_table_len = 1U << q_window;
    uint8_t (*q_table)[NOXTLS_P256_AFFINE_POINT_SIZE] = NULL;
    ecc_jpoint_t Jg;
    ecc_jpoint_t Jq;
    ecc_jpoint_t sum;
    noxtls_return_t rc;

    noxtls_secure_zero(&Jg, (size_t)(sizeof(Jg)));
    noxtls_secure_zero(&Jq, (size_t)(sizeof(Jq)));
    noxtls_secure_zero(&sum, (size_t)(sizeof(sum)));
    Jg.size = Jq.size = sum.size = NOXTLS_P256_AFFINE_COORD_SIZE;

    q_table = (uint8_t (*)[NOXTLS_P256_AFFINE_POINT_SIZE])
        NOXTLS_CALLOC(q_table_len, NOXTLS_P256_AFFINE_POINT_SIZE);
    if(q_table == NULL) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    rc = p256_build_compact_window_table(q_table, q_table_len, point_q, curve);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = p256_ecc_jpoint_mul_comb_flash(&Jg, scalar_g, curve);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = p256_ecc_jpoint_mul_windowed_compact(&Jq, scalar_q, curve,
                                                   q_table, q_window);
    }
    noxtls_free(q_table);
    q_table = NULL;
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
 * @brief Joint scalar multiplication: R = k1*P1 + (k2 * P2)
 *
 * Uses Jacobian arithmetic internally to avoid repeated inversions and performs
 * a single affine conversion at the end.
 */
noxtls_return_t noxtls_ecc_point_muladd(ecc_point_t *result,
                                        const uint8_t *scalar1, const ecc_point_t *point1,
                                        const uint8_t *scalar2, const ecc_point_t *point2,
                                        const ecc_curve_params_t *curve)
{
    ecc_jpoint_t R;
    ecc_jpoint_t J1;
    ecc_jpoint_t J2;
    ecc_jpoint_t J12;
    ecc_jpoint_t T;
    uint32_t size = 0U;
    uint32_t n_bits = 0U;
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

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

    if((noxtls_bn_is_zero(scalar1, size) != 0) && (noxtls_bn_is_zero(scalar2, size) != 0)) {
        return NOXTLS_RETURN_SUCCESS;
    }
    if(noxtls_bn_is_zero(scalar1, size) != 0) {
        return noxtls_ecc_point_multiply(result, scalar2, point2, curve);
    }
    if(noxtls_bn_is_zero(scalar2, size) != 0) {
        return noxtls_ecc_point_multiply(result, scalar1, point1, curve);
    }

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

    if(size > (UINT32_MAX / 8U)) {
        return NOXTLS_RETURN_FAILED;
    }
    n_bits = size * 8U;
    if(size == 32U) {
#if NOXTLS_ECC_P256_LOW_RAM_VERIFY
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

        /*
         * Memory-constrained fallback: compute both scalar multiplies in Jacobian
         * form, convert one side to affine once, then use the secp256r1 mixed-add
         * formula and a single affine conversion at the end.
         */
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
    } else {
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
 * @brief Check if point is on curve
 *
 * Verifies that y^2 = x^3 + ax + b (mod p). Uses curve params from noxtls_ecc_curve_init
 * and in-house bignum (noxtls_bn_mul, noxtls_bn_mod, ecc_mod_add).
 */
noxtls_return_t noxtls_ecc_point_is_on_curve(const ecc_point_t *point, const ecc_curve_params_t *curve)
{
    static uint8_t left[ECC_MAX_KEY_SIZE];
    static uint8_t right[ECC_MAX_KEY_SIZE];
    static uint8_t temp1[ECC_MAX_KEY_SIZE * 2U];
    static uint8_t temp2[ECC_MAX_KEY_SIZE * 2U];
    uint32_t size;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((point == NULL) || (curve == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    size = curve->size;
    if(size == 0U || size > ECC_MAX_KEY_SIZE) {
        return NOXTLS_RETURN_FAILED;
    }

    noxtls_secure_zero(left, (size_t)(sizeof(left)));
    noxtls_secure_zero(right, (size_t)(sizeof(right)));
    noxtls_secure_zero(temp1, (size_t)(sizeof(temp1)));
    noxtls_secure_zero(temp2, (size_t)(sizeof(temp2)));

    /* Check if point is at infinity */
    if(ecc_point_is_infinity(point, size) != 0) {
        return NOXTLS_RETURN_SUCCESS;
    }

    /* Compute left side: y^2 mod p */
    (void)noxtls_bn_mul(temp1, point->y, size, point->y, size);
    (void)noxtls_bn_mod(left, temp1, size * 2U, curve->p, size);

    /* Compute right side: x^3 + ax + b mod p (use curve->a so it matches add/double) */
    (void)noxtls_bn_mul(temp1, point->x, size, point->x, size);
    (void)noxtls_bn_mod(temp1, temp1, size * 2U, curve->p, size);
    (void)noxtls_bn_mul(temp2, temp1, size, point->x, size);
    (void)noxtls_bn_mod(temp2, temp2, size * 2U, curve->p, size);
    (void)noxtls_bn_mul(temp1, curve->a, size, point->x, size);
    (void)noxtls_bn_mod(temp1, temp1, size * 2U, curve->p, size);
    ecc_mod_add(temp2, temp2, temp1, curve->p, size);
    ecc_mod_add(right, temp2, curve->b, curve->p, size);

    if(noxtls_bn_cmp(left, right, size) == 0) {
        rc = NOXTLS_RETURN_SUCCESS;
    }

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
    if((ecc_point_is_infinity(point, curve->size) != 0)) {
        return NOXTLS_RETURN_FAILED;
    }

    rc = noxtls_ecc_point_is_on_curve(point, curve);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
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

    noxtls_ecc_keyinit_last_stage = 1U;
    noxtls_ecc_keyinit_last_rc = (int32_t)NOXTLS_RETURN_SUCCESS;
    if(key == NULL) {
        noxtls_ecc_keyinit_last_rc = (int32_t)NOXTLS_RETURN_NULL;
        return NOXTLS_RETURN_NULL;
    }

    noxtls_fill_u8((uint8_t *)(void *)(key), sizeof(ecc_key_t), 0U, sizeof(ecc_key_t));
    noxtls_ecc_keyinit_last_stage = 2U;

    key->curve = (ecc_curve_params_t*)NOXTLS_MALLOC(sizeof(ecc_curve_params_t));
    if(key->curve == NULL) {
        noxtls_ecc_keyinit_last_rc = (int32_t)NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    noxtls_ecc_keyinit_last_stage = 3u;

    noxtls_ecc_keyinit_last_stage = 3U;
    rc = noxtls_ecc_curve_init(key->curve, curve_type);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        (void)noxtls_free(key->curve);
        key->curve = NULL;
        noxtls_ecc_keyinit_last_rc = (int32_t)rc;
        return rc;
    }
    key->curve_kind = curve_type;
    noxtls_ecc_keyinit_last_stage = 4u;

    noxtls_ecc_keyinit_last_stage = 4U;
    key->d = (uint8_t*)NOXTLS_CALLOC(key->curve->size, 1);
    if(key->d == NULL) {
        (void)noxtls_ecc_curve_free(key->curve);
        (void)noxtls_free(key->curve);
        key->curve = NULL;
        noxtls_ecc_keyinit_last_rc = (int32_t)NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    noxtls_ecc_keyinit_last_stage = 5u;

    noxtls_ecc_keyinit_last_stage = 5U;
    (void)noxtls_ecc_point_init(&key->Q, key->curve->size);
    noxtls_ecc_keyinit_last_stage = 9U;
    noxtls_ecc_keyinit_last_rc = (int32_t)NOXTLS_RETURN_SUCCESS;
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

    noxtls_ecc_keygen_last_stage = 1U;
    noxtls_ecc_keygen_last_rc = (int32_t)NOXTLS_RETURN_SUCCESS;
    noxtls_ecc_keygen_last_entropy_rc = (int32_t)NOXTLS_RETURN_SUCCESS;
    noxtls_ecc_keygen_last_multiply_rc = (int32_t)NOXTLS_RETURN_SUCCESS;
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
    noxtls_ecc_keygen_last_init_us = 0U;
    noxtls_ecc_keygen_last_private_us = 0U;
    noxtls_ecc_keygen_last_multiply_us = 0U;
    noxtls_ecc_keygen_last_validate_us = 0U;
    noxtls_ecc_keygen_last_total_us = 0U;
#endif

    if(key == NULL) {
        noxtls_ecc_keygen_last_rc = (int32_t)NOXTLS_RETURN_NULL;
        return NOXTLS_RETURN_NULL;
    }

    noxtls_ecc_keygen_last_stage = 2U;
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
    phase_start_us = noxtls_ecc_diagnostic_time_us();
#endif
    rc = noxtls_ecc_key_init(key, curve_type);
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
    noxtls_ecc_keygen_last_init_us =
        noxtls_ecc_diagnostic_elapsed_us(phase_start_us);
#endif
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_ecc_keygen_last_stage = 3U;
        noxtls_ecc_keygen_last_rc = (int32_t)rc;
        return rc;
    }
    noxtls_ecc_keygen_last_stage = 4U;
    size = key->curve->size;
    if(size == 0U || size > ECC_MAX_KEY_SIZE) {
        rc = NOXTLS_RETURN_FAILED;
        noxtls_ecc_keygen_last_stage = 5U;
        goto cleanup_keygen;
    }
    bits = size * 8U;

    noxtls_secure_zero(random_bytes, (size_t)(sizeof(random_bytes)));
    noxtls_ecc_keygen_last_stage = 6U;
    do {
        /* Generate private key d in range [1, n-1] */
        /* Generate random private key */
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
        phase_start_us = noxtls_ecc_diagnostic_time_us();
#endif
        do {
            rc = ecc_keygen_drbg_generate_bits(random_bytes, bits);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_ecc_keygen_last_stage = 7U;
                break;
            }

            /* Ensure d is in range [1, n-1] by reducing mod (n-1) and adding 1 */
            /* First, reduce mod n (which gives [0, n-1]) */
            (void)noxtls_bn_mod(key->d, random_bytes, size, key->curve->n, size);

            /* If d is zero, set to 1 */
            if(noxtls_bn_is_zero(key->d, size) != 0) {
                (void)noxtls_bn_one(key->d, size);
            }

            /* Ensure d < n (should already be true after mod, but check anyway) */
        } while(noxtls_bn_cmp(key->d, key->curve->n, size) >= 0 || (noxtls_bn_is_zero(key->d, size) != 0));
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
        noxtls_ecc_keygen_last_private_us =
            noxtls_ecc_diagnostic_elapsed_us(phase_start_us);
#endif

        if(rc != NOXTLS_RETURN_SUCCESS) {
            break;
        }

        /* Compute public key Q = d * G */
        /* This is the expensive operation - scalar multiplication */
    noxtls_ecc_keygen_last_stage = 8U;
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
    phase_start_us = noxtls_ecc_diagnostic_time_us();
#endif
    rc = noxtls_ecc_point_multiply(&key->Q, key->d, &key->curve->G, key->curve);
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
    noxtls_ecc_keygen_last_multiply_us =
        noxtls_ecc_diagnostic_elapsed_us(phase_start_us);
#endif
    noxtls_ecc_keygen_last_multiply_rc = (int32_t)rc;
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup_keygen;
    }

    } while(0 == 1);

    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup_keygen;
    }

    /* Verify the generated public key is on the curve */
    noxtls_ecc_keygen_last_stage = 9U;
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
    phase_start_us = noxtls_ecc_diagnostic_time_us();
#endif
    rc = noxtls_ecc_point_is_on_curve(&key->Q, key->curve);
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
    noxtls_ecc_keygen_last_validate_us =
        noxtls_ecc_diagnostic_elapsed_us(phase_start_us);
#endif
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup_keygen;
    }

cleanup_keygen:
    noxtls_secure_zero(random_bytes, (size_t)(sizeof(random_bytes)));
    noxtls_ecc_keygen_last_rc = (int32_t)rc;
#if NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
    noxtls_ecc_keygen_last_total_us =
        noxtls_ecc_diagnostic_elapsed_us(total_start_us);
#endif

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
        {
            size_t d_cap = (key->curve != NULL) ? (size_t)key->curve->size : (size_t)ECC_MAX_KEY_SIZE;
            noxtls_fill_u8(key->d, d_cap, 0U, d_cap);
        }
        (void)noxtls_free(key->d);
        key->d = NULL;
    }

    if(key->curve != NULL) {
        (void)noxtls_ecc_curve_free(key->curve);
        (void)noxtls_free(key->curve);
        key->curve = NULL;
    }
    /* Do not noxtls_fill_u8((uint8_t *)(void *)(key), sizeof(ecc_key_t), 0U, sizeof(ecc_key_t)): key may be on the caller's stack and
     * sizeof(ecc_key_t) can differ between translation units (e.g. C vs C++), which
     * can corrupt the stack and crash when the test returns. */
    return NOXTLS_RETURN_SUCCESS;
}
