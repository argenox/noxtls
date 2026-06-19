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
#include "pkc/rsa/noxtls_bignum.h"
#include "drbg/noxtls_drbg.h"
#include "noxtls_common.h"

/* Disable verbose stderr debug prints in this file. */
#undef fprintf
#define fprintf(...) ((void)0)

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
    uint8_t seed[DRBG_SEEDLEN_AES256];
    noxtls_return_t rc;

    if(out == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(!s_ecc_keygen_drbg_initialized) {
        rc = noxtls_drbg_get_entropy(seed, sizeof(seed));
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        rc = drbg_instantiate(&s_ecc_keygen_drbg_state, DRBG_AES256,
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

    memset(&s_ecc_keygen_drbg_state, 0, sizeof(s_ecc_keygen_drbg_state));
    s_ecc_keygen_drbg_initialized = 0;

    rc = noxtls_drbg_get_entropy(seed, sizeof(seed));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = drbg_instantiate(&s_ecc_keygen_drbg_state, DRBG_AES256,
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
noxtls_return_t noxtls_ecc_point_multiply_accel_port(ecc_point_t *result,
                                                      const uint8_t *scalar,
                                                      const ecc_point_t *point,
                                                      const ecc_curve_params_t *curve);
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
    if(result == NULL || a == NULL || p == NULL || size == 0) {
        return NOXTLS_RETURN_NULL;
    }

    uint8_t *p_minus_2 = (uint8_t*)calloc(size, 1);
    uint8_t *two = (uint8_t*)calloc(size, 1);
    uint8_t *a_mod = (uint8_t*)calloc(size, 1);
    uint8_t *prod = (uint8_t*)calloc((size_t)size * 2U, 1);
    uint8_t *check = (uint8_t*)calloc(size, 1);
    uint8_t *one = (uint8_t*)calloc(size, 1);
    if(!p_minus_2 || !two || !a_mod || !prod || !check || !one) {
        if(p_minus_2) free(p_minus_2);
        if(two) free(two);
        if(a_mod) free(a_mod);
        if(prod) free(prod);
        if(check) free(check);
        if(one) free(one);
        return NOXTLS_RETURN_FAILED;
    }

    noxtls_bn_mod(a_mod, a, size, p, size);
    if(noxtls_bn_is_zero(a_mod, size)) {
        free(p_minus_2);
        free(two);
        free(a_mod);
        return NOXTLS_RETURN_FAILED;
    }

    two[size - 1] = 0x02;
    one[size - 1] = 0x01;
    noxtls_bn_copy(p_minus_2, p, size);
    noxtls_bn_sub(p_minus_2, p_minus_2, two, size);

    /* Fast path: use generic modular inverse first. */
    if(noxtls_bn_mod_inv(result, a_mod, size, p, size) == NOXTLS_RETURN_SUCCESS) {
        noxtls_bn_mul(prod, a_mod, size, result, size);
        noxtls_bn_mod(check, prod, size * 2U, p, size);
        if(noxtls_bn_cmp(check, one, size) == 0) {
            free(p_minus_2);
            free(two);
            free(a_mod);
            free(prod);
            free(check);
            free(one);
            return NOXTLS_RETURN_SUCCESS;
        }
    }

    /* Fallback for edge cases: Fermat inverse. */
    noxtls_bn_mod_exp(result, a_mod, p_minus_2, size, p, size);
    noxtls_bn_mul(prod, a_mod, size, result, size);
    noxtls_bn_mod(check, prod, size * 2U, p, size);
    if(noxtls_bn_cmp(check, one, size) != 0) {
        noxtls_return_t rc = noxtls_bn_mod_inv(result, a_mod, size, p, size);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            free(p_minus_2);
            free(two);
            free(a_mod);
            free(prod);
            free(check);
            free(one);
            return NOXTLS_RETURN_FAILED;
        }
        noxtls_bn_mul(prod, a_mod, size, result, size);
        noxtls_bn_mod(check, prod, size * 2U, p, size);
        if(noxtls_bn_cmp(check, one, size) != 0) {
            free(p_minus_2);
            free(two);
            free(a_mod);
            free(prod);
            free(check);
            free(one);
            return NOXTLS_RETURN_FAILED;
        }
    }

    free(p_minus_2);
    free(two);
    free(a_mod);
    free(prod);
    free(check);
    free(one);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Check if ECC point multiply uses reference implementation
 * 
 * @return int 1 if using reference implementation, 0 otherwise
 */
int noxtls_ecc_point_multiply_uses_ref(void)
{
#if defined(NOXTLS_ECC_USE_REF_POINT_MUL)
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
    if(curve != NULL && ecc_curve_is_secp256r1(curve)) {
        return is_fixed_base ? 5U : 4U;
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
noxtls_return_t noxtls_ecc_curve_init(ecc_curve_params_t *curve, ecc_curve_t curve_type)
{
    if(curve == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    memset(curve, 0, sizeof(ecc_curve_params_t));
    
    /* Set curve size based on type */
    switch(curve_type) {
        case NOXTLS_ECC_SECP192R1:
            curve->size = 24;  /* 192 bits = 24 bytes */
            break;
        case NOXTLS_ECC_SECP224R1:
            curve->size = 28;  /* 224 bits = 28 bytes */
            break;
        case NOXTLS_ECC_SECP256R1:
            curve->size = 32;  /* 256 bits = 32 bytes */
            break;
        case NOXTLS_ECC_SECP384R1:
            curve->size = 48;  /* 384 bits = 48 bytes */
            break;
        case NOXTLS_ECC_SECP521R1:
            curve->size = 66;  /* 521 bits = 66 bytes */
            break;
        case NOXTLS_ECC_BP256R1:
            curve->size = 32;  /* 256 bits = 32 bytes */
            break;
        case NOXTLS_ECC_BP384R1:
            curve->size = 48;  /* 384 bits = 48 bytes */
            break;
        case NOXTLS_ECC_BP512R1:
            curve->size = 64;  /* 512 bits = 64 bytes */
            break;
        case NOXTLS_ECC_SECP192K1:
            curve->size = 24;  /* 192 bits = 24 bytes */
            break;
        case NOXTLS_ECC_SECP224K1:
            curve->size = 28;  /* 224 bits = 28 bytes */
            break;
        case NOXTLS_ECC_SECP256K1:
            curve->size = 32;  /* 256 bits = 32 bytes */
            break;
        default:
            return NOXTLS_RETURN_FAILED;
    }
    
    /* Allocate memory for curve parameters */
    curve->p = (uint8_t*)calloc(curve->size, 1);
    curve->a = (uint8_t*)calloc(curve->size, 1);
    curve->b = (uint8_t*)calloc(curve->size, 1);
    curve->n = (uint8_t*)calloc(curve->size, 1);
    
    if(!curve->p || !curve->a || !curve->b || !curve->n) {
        noxtls_ecc_curve_free(curve);
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Initialize curve parameters for specific curves */
    uint32_t size = curve->size;
    
    switch(curve_type) {
        case NOXTLS_ECC_SECP192R1: {
            static const uint8_t p_secp192r1[24] = {
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
            };
            static const uint8_t a_secp192r1[24] = {
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
            };
            static const uint8_t b_secp192r1[24] = {
                0x64, 0x21, 0x05, 0x19, 0xE5, 0x9C, 0x80, 0xE7, 0x0F, 0xA7, 0xE9, 0xAB,
                0x72, 0x24, 0x30, 0x49, 0xFE, 0xB8, 0xDE, 0xEC, 0xC1, 0x46, 0xB9, 0xB1
            };
            static const uint8_t gx_secp192r1[24] = {
                0x18, 0x8D, 0xA8, 0x0E, 0xB0, 0x30, 0x90, 0xF6, 0x7C, 0xBF, 0x20, 0xEB,
                0x43, 0xA1, 0x88, 0x00, 0xF4, 0xFF, 0x0A, 0xFD, 0x82, 0xFF, 0x10, 0x12
            };
            static const uint8_t gy_secp192r1[24] = {
                0x07, 0x19, 0x2B, 0x95, 0xFF, 0xC8, 0xDA, 0x78, 0x63, 0x10, 0x11, 0xED,
                0x6B, 0x24, 0xCD, 0xD5, 0x73, 0xF9, 0x77, 0xA1, 0x1E, 0x79, 0x48, 0x11
            };
            static const uint8_t n_secp192r1[24] = {
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0x99, 0xDE, 0xF8, 0x36, 0x14, 0x6B, 0xC9, 0xB1, 0xB4, 0xD2, 0x28, 0x31
            };
            memcpy(curve->p, p_secp192r1, size);
            memcpy(curve->a, a_secp192r1, size);
            memcpy(curve->b, b_secp192r1, size);
            memcpy(curve->G.x, gx_secp192r1, size);
            memcpy(curve->G.y, gy_secp192r1, size);
            curve->G.size = size;
            memcpy(curve->n, n_secp192r1, size);
            break;
        }
        case NOXTLS_ECC_SECP224R1: {
            static const uint8_t p_secp224r1[28] = {
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01
            };
            static const uint8_t a_secp224r1[28] = {
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFE
            };
            static const uint8_t b_secp224r1[28] = {
                0xB4, 0x05, 0x0A, 0x85, 0x0C, 0x04, 0xB3, 0xAB, 0xF5, 0x41, 0x32, 0x56,
                0x50, 0x44, 0xB0, 0xB7, 0xD7, 0xBF, 0xD8, 0xBA, 0x27, 0x0B, 0x39, 0x43,
                0x23, 0x55, 0xFF, 0xB4
            };
            static const uint8_t gx_secp224r1[28] = {
                0xB7, 0x0E, 0x0C, 0xBD, 0x6B, 0xB4, 0xBF, 0x7F, 0x32, 0x13, 0x90, 0xB9,
                0x4A, 0x03, 0xC1, 0xD3, 0x56, 0xC2, 0x11, 0x22, 0x34, 0x32, 0x80, 0xD6,
                0x11, 0x5C, 0x1D, 0x21
            };
            static const uint8_t gy_secp224r1[28] = {
                0xBD, 0x37, 0x63, 0x88, 0xB5, 0xF7, 0x23, 0xFB, 0x4C, 0x22, 0xDF, 0xE6,
                0xCD, 0x43, 0x75, 0xA0, 0x5A, 0x07, 0x47, 0x64, 0x44, 0xD5, 0x81, 0x99,
                0x85, 0x00, 0x7E, 0x34
            };
            static const uint8_t n_secp224r1[28] = {
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0x16, 0xA2, 0xE0, 0xB8, 0xF0, 0x3E, 0x13, 0xDD, 0x29, 0x45,
                0x5C, 0x5C, 0x2A, 0x3D
            };
            memcpy(curve->p, p_secp224r1, size);
            memcpy(curve->a, a_secp224r1, size);
            memcpy(curve->b, b_secp224r1, size);
            memcpy(curve->G.x, gx_secp224r1, size);
            memcpy(curve->G.y, gy_secp224r1, size);
            curve->G.size = size;
            memcpy(curve->n, n_secp224r1, size);
            break;
        }
        case NOXTLS_ECC_SECP256R1: {
            /* NIST P-256 curve parameters */
            /* p = 2^256 - 2^224 + 2^192 + 2^96 - 1 */
            curve->p[31] = 0xFF; curve->p[30] = 0xFF; curve->p[29] = 0xFF; curve->p[28] = 0xFF;
            curve->p[27] = 0x00; curve->p[26] = 0x00; curve->p[25] = 0x00; curve->p[24] = 0x01;
            curve->p[23] = 0x00; curve->p[22] = 0x00; curve->p[21] = 0x00; curve->p[20] = 0x00;
            curve->p[19] = 0x00; curve->p[18] = 0x00; curve->p[17] = 0x00; curve->p[16] = 0x00;
            curve->p[15] = 0x00; curve->p[14] = 0x00; curve->p[13] = 0x00; curve->p[12] = 0x00;
            curve->p[11] = 0x00; curve->p[10] = 0x00; curve->p[9] = 0x00; curve->p[8] = 0x00;
            curve->p[7] = 0xFF; curve->p[6] = 0xFF; curve->p[5] = 0xFF; curve->p[4] = 0xFF;
            curve->p[3] = 0xFF; curve->p[2] = 0xFF; curve->p[1] = 0xFF; curve->p[0] = 0xFF;
            
            /* a = -3 mod p (which is p - 3) */
            noxtls_bn_copy(curve->a, curve->p, size);
            const uint8_t three[32] = {0x03};
            noxtls_bn_sub(curve->a, curve->a, three, size);
            
            /* b = 0x5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E 27D2604B */
            curve->b[31] = 0x4B; curve->b[30] = 0x60; curve->b[29] = 0xD2; curve->b[28] = 0x7E;
            curve->b[27] = 0x3E; curve->b[26] = 0x3C; curve->b[25] = 0xCE; curve->b[24] = 0x3B;
            curve->b[23] = 0xF6; curve->b[22] = 0xB0; curve->b[21] = 0x53; curve->b[20] = 0xCC;
            curve->b[19] = 0xB0; curve->b[18] = 0x06; curve->b[17] = 0x1D; curve->b[16] = 0x65;
            curve->b[15] = 0xBC; curve->b[14] = 0x86; curve->b[13] = 0x98; curve->b[12] = 0x76;
            curve->b[11] = 0x55; curve->b[10] = 0xBD; curve->b[9] = 0xEB; curve->b[8] = 0xB3;
            curve->b[7] = 0xE7; curve->b[6] = 0x93; curve->b[5] = 0x3A; curve->b[4] = 0xAA;
            curve->b[3] = 0xD8; curve->b[2] = 0x35; curve->b[1] = 0xC6; curve->b[0] = 0x5A;
            
            /* G (generator point) - compressed form: 0x03 + x coordinate */
            /* Gx = 0x6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0 F4A13945 D898C296 */
            curve->G.x[31] = 0x96; curve->G.x[30] = 0xC2; curve->G.x[29] = 0x98; curve->G.x[28] = 0xD8;
            curve->G.x[27] = 0x45; curve->G.x[26] = 0x39; curve->G.x[25] = 0xA1; curve->G.x[24] = 0xF4;
            curve->G.x[23] = 0xA0; curve->G.x[22] = 0x33; curve->G.x[21] = 0xEB; curve->G.x[20] = 0x2D;
            curve->G.x[19] = 0x81; curve->G.x[18] = 0x7D; curve->G.x[17] = 0x03; curve->G.x[16] = 0x77;
            curve->G.x[15] = 0xF2; curve->G.x[14] = 0x40; curve->G.x[13] = 0xA4; curve->G.x[12] = 0x63;
            curve->G.x[11] = 0xE5; curve->G.x[10] = 0xE6; curve->G.x[9] = 0xBC; curve->G.x[8] = 0xF8;
            curve->G.x[7] = 0x47; curve->G.x[6] = 0x24; curve->G.x[5] = 0xC4; curve->G.x[4] = 0x12;
            curve->G.x[3] = 0xE1; curve->G.x[2] = 0xF2; curve->G.x[1] = 0xD1; curve->G.x[0] = 0x6B;
            
            /* Gy = 0x4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16 2BCE3357 6B315ECE CBB64068 37BF51F5 */
            curve->G.y[31] = 0xF5; curve->G.y[30] = 0x51; curve->G.y[29] = 0xBF; curve->G.y[28] = 0x37;
            curve->G.y[27] = 0x68; curve->G.y[26] = 0x40; curve->G.y[25] = 0xB6; curve->G.y[24] = 0xCB;
            curve->G.y[23] = 0xCE; curve->G.y[22] = 0x5E; curve->G.y[21] = 0x31; curve->G.y[20] = 0x6B;
            curve->G.y[19] = 0x57; curve->G.y[18] = 0x33; curve->G.y[17] = 0xCE; curve->G.y[16] = 0x2B;
            curve->G.y[15] = 0x16; curve->G.y[14] = 0x9E; curve->G.y[13] = 0x0F; curve->G.y[12] = 0x7C;
            curve->G.y[11] = 0x4A; curve->G.y[10] = 0xEB; curve->G.y[9] = 0xE7; curve->G.y[8] = 0x8E;
            curve->G.y[7] = 0x9B; curve->G.y[6] = 0xF9; curve->G.y[5] = 0x7A; curve->G.y[4] = 0xF1;
            curve->G.y[3] = 0xE1; curve->G.y[2] = 0x42; curve->G.y[1] = 0xE3; curve->G.y[0] = 0x4F;
            curve->G.size = size;
            
            /* n (order) = 0xFFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551 */
            curve->n[31] = 0x51; curve->n[30] = 0x25; curve->n[29] = 0x63; curve->n[28] = 0xFC;
            curve->n[27] = 0xC2; curve->n[26] = 0xCA; curve->n[25] = 0xC9; curve->n[24] = 0xB3;
            curve->n[23] = 0xF4; curve->n[22] = 0x84; curve->n[21] = 0x9E; curve->n[20] = 0x17;
            curve->n[19] = 0xA7; curve->n[18] = 0xAD; curve->n[17] = 0xFA; curve->n[16] = 0xE6;
            curve->n[15] = 0xBC; curve->n[14] = 0xFF; curve->n[13] = 0xFF; curve->n[12] = 0xFF;
            curve->n[11] = 0xFF; curve->n[10] = 0xFF; curve->n[9] = 0xFF; curve->n[8] = 0xFF;
            curve->n[7] = 0x00; curve->n[6] = 0x00; curve->n[5] = 0x00; curve->n[4] = 0x00;
            curve->n[3] = 0xFF; curve->n[2] = 0xFF; curve->n[1] = 0xFF; curve->n[0] = 0xFF;

            /* Use big-endian constants to match bignum operations. */
            static const uint8_t p_secp256r1[32] = {
                0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
            };
            /* a = p - 3 for secp256r1 (avoids reliance on bn_sub in curve init). */
            static const uint8_t a_secp256r1[32] = {
                0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
            };
            static const uint8_t b_secp256r1[32] = {
                0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7,
                0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
                0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
                0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B
            };
            static const uint8_t gx_secp256r1[32] = {
                0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
                0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
                0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
                0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96
            };
            static const uint8_t gy_secp256r1[32] = {
                0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
                0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
                0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
                0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
            };
            static const uint8_t n_secp256r1[32] = {
                0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
                0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
            };

            memcpy(curve->p, p_secp256r1, size);
            memcpy(curve->a, a_secp256r1, size);
            memcpy(curve->b, b_secp256r1, size);
            memcpy(curve->G.x, gx_secp256r1, size);
            memcpy(curve->G.y, gy_secp256r1, size);
            curve->G.size = size;
            memcpy(curve->n, n_secp256r1, size);
            break;
        }
        case NOXTLS_ECC_SECP384R1:
            {
                /* NIST P-384 (secp384r1), 48 bytes, big-endian. */
                static const uint8_t p_secp384r1[48] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
                };
                static const uint8_t a_secp384r1[48] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFC
                };
                static const uint8_t b_secp384r1[48] = {
                    0xB3, 0x31, 0x2F, 0xA7, 0xE2, 0x3E, 0xE7, 0xE4,
                    0x98, 0x8E, 0x05, 0x6B, 0xE3, 0xF8, 0x2D, 0x19,
                    0x18, 0x1D, 0x9C, 0x6E, 0xFE, 0x81, 0x41, 0x12,
                    0x03, 0x14, 0x08, 0x8F, 0x50, 0x13, 0x87, 0x5A,
                    0xC6, 0x56, 0x39, 0x8D, 0x8A, 0x2E, 0xD1, 0x9D,
                    0x2A, 0x85, 0xC8, 0xED, 0xD3, 0xEC, 0x2A, 0xEF
                };
                static const uint8_t gx_secp384r1[48] = {
                    0xAA, 0x87, 0xCA, 0x22, 0xBE, 0x8B, 0x05, 0x37,
                    0x8E, 0xB1, 0xC7, 0x1E, 0xF3, 0x20, 0xAD, 0x74,
                    0x6E, 0x1D, 0x3B, 0x62, 0x8B, 0xA7, 0x9B, 0x98,
                    0x59, 0xF7, 0x41, 0xE0, 0x82, 0x54, 0x2A, 0x38,
                    0x55, 0x02, 0xF2, 0x5D, 0xBF, 0x55, 0x29, 0x6C,
                    0x3A, 0x54, 0x5E, 0x38, 0x72, 0x76, 0x0A, 0xB7
                };
                static const uint8_t gy_secp384r1[48] = {
                    0x36, 0x17, 0xDE, 0x4A, 0x96, 0x26, 0x2C, 0x6F,
                    0x5D, 0x9E, 0x98, 0xBF, 0x92, 0x92, 0xDC, 0x29,
                    0xF8, 0xF4, 0x1D, 0xBD, 0x28, 0x9A, 0x14, 0x7C,
                    0xE9, 0xDA, 0x31, 0x13, 0xB5, 0xF0, 0xB8, 0xC0,
                    0x0A, 0x60, 0xB1, 0xCE, 0x1D, 0x7E, 0x81, 0x9D,
                    0x7A, 0x43, 0x1D, 0x7C, 0x90, 0xEA, 0x0E, 0x5F
                };
                static const uint8_t n_secp384r1[48] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37, 0x2D, 0xDF,
                    0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A,
                    0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x73
                };
                memcpy(curve->p, p_secp384r1, size);
                memcpy(curve->a, a_secp384r1, size);
                memcpy(curve->b, b_secp384r1, size);
                memcpy(curve->G.x, gx_secp384r1, size);
                memcpy(curve->G.y, gy_secp384r1, size);
                curve->G.size = size;
                memcpy(curve->n, n_secp384r1, size);
            }
            break;
        case NOXTLS_ECC_SECP521R1:
            {
                /* NIST P-521 (secp521r1), 66 bytes, big-endian. */
                static const uint8_t p_secp521r1[66] = {
                    0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF
                };
                static const uint8_t a_secp521r1[66] = {
                    0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFC
                };
                static const uint8_t b_secp521r1[66] = {
                    0x00, 0x51, 0x95, 0x3E, 0xB9, 0x61, 0x8E, 0x1C,
                    0x9A, 0x1F, 0x92, 0x9A, 0x21, 0xA0, 0xB6, 0x85,
                    0x40, 0xEE, 0xA2, 0xDA, 0x72, 0x5B, 0x99, 0xB3,
                    0x15, 0xF3, 0xB8, 0xB4, 0x89, 0x91, 0x8E, 0xF1,
                    0x09, 0xE1, 0x56, 0x19, 0x39, 0x51, 0xEC, 0x7E,
                    0x93, 0x7B, 0x16, 0x52, 0xC0, 0xBD, 0x3B, 0xB1,
                    0xBF, 0x07, 0x35, 0x73, 0xDF, 0x88, 0x3D, 0x2C,
                    0x34, 0xF1, 0xEF, 0x45, 0x1F, 0xD4, 0x6B, 0x50,
                    0x3F, 0x00
                };
                static const uint8_t gx_secp521r1[66] = {
                    0x00, 0xC6, 0x85, 0x8E, 0x06, 0xB7, 0x04, 0x04,
                    0xE9, 0xCD, 0x9E, 0x3E, 0xCB, 0x66, 0x23, 0x95,
                    0xB4, 0x42, 0x9C, 0x64, 0x81, 0x39, 0x05, 0x3F,
                    0xB5, 0x21, 0xF8, 0x28, 0xAF, 0x60, 0x6B, 0x4D,
                    0x3D, 0xBA, 0xA1, 0x4B, 0x5E, 0x77, 0xEF, 0xE7,
                    0x59, 0x28, 0xFE, 0x1D, 0xC1, 0x27, 0xA2, 0xFF,
                    0xA8, 0xDE, 0x33, 0x48, 0xB3, 0xC1, 0x85, 0x6A,
                    0x42, 0x9B, 0xF9, 0x7E, 0x7E, 0x31, 0xC2, 0xE5,
                    0xBD, 0x66
                };
                static const uint8_t gy_secp521r1[66] = {
                    0x01, 0x18, 0x39, 0x29, 0x6A, 0x78, 0x9A, 0x3B,
                    0xC0, 0x04, 0x5C, 0x8A, 0x5F, 0xB4, 0x2C, 0x7D,
                    0x1B, 0xD9, 0x98, 0xF5, 0x44, 0x49, 0x57, 0x9B,
                    0x44, 0x68, 0x17, 0xAF, 0xBD, 0x17, 0x27, 0x3E,
                    0x66, 0x2C, 0x97, 0xEE, 0x72, 0x99, 0x5E, 0xF4,
                    0x26, 0x40, 0xC5, 0x50, 0xB9, 0x01, 0x3F, 0xAD,
                    0x07, 0x61, 0x35, 0x3C, 0x70, 0x86, 0xA2, 0x72,
                    0xC2, 0x40, 0x88, 0xBE, 0x94, 0x76, 0x9F, 0xD1,
                    0x66, 0x50
                };
                static const uint8_t n_secp521r1[66] = {
                    0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFA, 0x51, 0x86, 0x87, 0x83, 0xBF, 0x2F,
                    0x96, 0x6B, 0x7F, 0xCC, 0x01, 0x48, 0xF7, 0x09,
                    0xA5, 0xD0, 0x3B, 0xB5, 0xC9, 0xB8, 0x89, 0x9C,
                    0x47, 0xAE, 0xBB, 0x6F, 0xB7, 0x1E, 0x91, 0x38,
                    0x64, 0x09
                };
                memcpy(curve->p, p_secp521r1, size);
                memcpy(curve->a, a_secp521r1, size);
                memcpy(curve->b, b_secp521r1, size);
                memcpy(curve->G.x, gx_secp521r1, size);
                memcpy(curve->G.y, gy_secp521r1, size);
                curve->G.size = size;
                memcpy(curve->n, n_secp521r1, size);
            }
            break;
        case NOXTLS_ECC_BP256R1:
            {
                static const uint8_t p_brainpoolP256r1[32] = {
                    0xA9, 0xFB, 0x57, 0xDB, 0xA1, 0xEE, 0xA9, 0xBC, 0x3E, 0x66, 0x0A, 0x90, 0x9D, 0x83, 0x8D, 0x72,
                    0x6E, 0x3B, 0xF6, 0x23, 0xD5, 0x26, 0x20, 0x28, 0x20, 0x13, 0x48, 0x1D, 0x1F, 0x6E, 0x53, 0x77
                };
                static const uint8_t a_brainpoolP256r1[32] = {
                    0x7D, 0x5A, 0x09, 0x75, 0xFC, 0x2C, 0x30, 0x57, 0xEE, 0xF6, 0x75, 0x30, 0x41, 0x7A, 0xFF, 0xE7,
                    0xFB, 0x80, 0x55, 0xC1, 0x26, 0xDC, 0x5C, 0x6C, 0xE9, 0x4A, 0x4B, 0x44, 0xF3, 0x30, 0xB5, 0xD9
                };
                static const uint8_t b_brainpoolP256r1[32] = {
                    0x26, 0xDC, 0x5C, 0x6C, 0xE9, 0x4A, 0x4B, 0x44, 0xF3, 0x30, 0xB5, 0xD9, 0xBB, 0xD7, 0x7C, 0xBF,
                    0x95, 0x84, 0x16, 0x29, 0x5C, 0xF7, 0xE1, 0xCE, 0x6B, 0xCC, 0xDC, 0x18, 0xFF, 0x8C, 0x07, 0xB6
                };
                static const uint8_t gx_brainpoolP256r1[32] = {
                    0x8B, 0xD2, 0xAE, 0xB9, 0xCB, 0x7E, 0x57, 0xCB, 0x2C, 0x4B, 0x48, 0x2F, 0xFC, 0x81, 0xB7, 0xAF,
                    0xB9, 0xDE, 0x27, 0xE1, 0xE3, 0xBD, 0x23, 0xC2, 0x3A, 0x44, 0x53, 0xBD, 0x9A, 0xCE, 0x32, 0x62
                };
                static const uint8_t gy_brainpoolP256r1[32] = {
                    0x54, 0x7E, 0xF8, 0x35, 0xC3, 0xDA, 0xC4, 0xFD, 0x97, 0xF8, 0x46, 0x1A, 0x14, 0x61, 0x1D, 0xC9,
                    0xC2, 0x77, 0x45, 0x13, 0x2D, 0xED, 0x8E, 0x54, 0x5C, 0x1D, 0x54, 0xC7, 0x2F, 0x04, 0x69, 0x97
                };
                static const uint8_t n_brainpoolP256r1[32] = {
                    0xA9, 0xFB, 0x57, 0xDB, 0xA1, 0xEE, 0xA9, 0xBC, 0x3E, 0x66, 0x0A, 0x90, 0x9D, 0x83, 0x8D, 0x71,
                    0x8C, 0x39, 0x7A, 0xA3, 0xB5, 0x61, 0xA6, 0xF7, 0x90, 0x1E, 0x0E, 0x82, 0x97, 0x48, 0x56, 0xA7
                };
                memcpy(curve->p, p_brainpoolP256r1, size);
                memcpy(curve->a, a_brainpoolP256r1, size);
                memcpy(curve->b, b_brainpoolP256r1, size);
                memcpy(curve->G.x, gx_brainpoolP256r1, size);
                memcpy(curve->G.y, gy_brainpoolP256r1, size);
                curve->G.size = size;
                memcpy(curve->n, n_brainpoolP256r1, size);
            }
            break;
        case NOXTLS_ECC_BP384R1:
            {
                static const uint8_t p_brainpoolP384r1[48] = {
                    0x8C, 0xB9, 0x1E, 0x82, 0xA3, 0x38, 0x6D, 0x28, 0x0F, 0x5D, 0x6F, 0x7E, 0x50, 0xE6, 0x41, 0xDF,
                    0x15, 0x2F, 0x71, 0x09, 0xED, 0x54, 0x56, 0xB4, 0x12, 0xB1, 0xDA, 0x19, 0x7F, 0xB7, 0x11, 0x23,
                    0xAC, 0xD3, 0xA7, 0x29, 0x90, 0x1D, 0x1A, 0x71, 0x87, 0x47, 0x00, 0x13, 0x31, 0x07, 0xEC, 0x53
                };
                static const uint8_t a_brainpoolP384r1[48] = {
                    0x7B, 0xC3, 0x82, 0xC6, 0x3D, 0x8C, 0x15, 0x0C, 0x3C, 0x72, 0x08, 0x0A, 0xCE, 0x05, 0xAF, 0xA0,
                    0xC2, 0xBE, 0xA2, 0x8E, 0x4F, 0xB2, 0x27, 0x87, 0x13, 0x91, 0x65, 0xEF, 0xBA, 0x91, 0xF9, 0x0F,
                    0x8A, 0xA5, 0x81, 0x4A, 0x50, 0x3A, 0xD4, 0xEB, 0x04, 0xA8, 0xC7, 0xDD, 0x22, 0xCE, 0x28, 0x26
                };
                static const uint8_t b_brainpoolP384r1[48] = {
                    0x04, 0xA8, 0xC7, 0xDD, 0x22, 0xCE, 0x28, 0x26, 0x8B, 0x39, 0xB5, 0x54, 0x16, 0xF0, 0x44, 0x7C,
                    0x2F, 0xB7, 0x7D, 0xE1, 0x07, 0xDC, 0xD2, 0xA6, 0x2E, 0x88, 0x0E, 0xA5, 0x3E, 0xEB, 0x62, 0xD5,
                    0x7C, 0xB4, 0x39, 0x02, 0x95, 0xDB, 0xC9, 0x94, 0x3A, 0xB7, 0x86, 0x96, 0xFA, 0x50, 0x4C, 0x11
                };
                static const uint8_t gx_brainpoolP384r1[48] = {
                    0x1D, 0x1C, 0x64, 0xF0, 0x68, 0xCF, 0x45, 0xFF, 0xA2, 0xA6, 0x3A, 0x81, 0xB7, 0xC1, 0x3F, 0x6B,
                    0x88, 0x47, 0xA3, 0xE7, 0x7E, 0xF1, 0x4F, 0xE3, 0xDB, 0x7F, 0xCA, 0xFE, 0x0C, 0xBD, 0x10, 0xE8,
                    0xE8, 0x26, 0xE0, 0x34, 0x36, 0xD6, 0x46, 0xAA, 0xEF, 0x87, 0xB2, 0xE2, 0x47, 0xD4, 0xAF, 0x1E
                };
                static const uint8_t gy_brainpoolP384r1[48] = {
                    0x8A, 0xBE, 0x1D, 0x75, 0x20, 0xF9, 0xC2, 0xA4, 0x5C, 0xB1, 0xEB, 0x8E, 0x95, 0xCF, 0xD5, 0x52,
                    0x62, 0xB7, 0x0B, 0x29, 0xFE, 0xEC, 0x58, 0x64, 0xE1, 0x9C, 0x05, 0x4F, 0xF9, 0x91, 0x29, 0x28,
                    0x0E, 0x46, 0x46, 0x21, 0x77, 0x91, 0x81, 0x11, 0x42, 0x82, 0x03, 0x41, 0x26, 0x3C, 0x53, 0x15
                };
                static const uint8_t n_brainpoolP384r1[48] = {
                    0x8C, 0xB9, 0x1E, 0x82, 0xA3, 0x38, 0x6D, 0x28, 0x0F, 0x5D, 0x6F, 0x7E, 0x50, 0xE6, 0x41, 0xDF,
                    0x15, 0x2F, 0x71, 0x09, 0xED, 0x54, 0x56, 0xB3, 0x1F, 0x16, 0x6E, 0x6C, 0xAC, 0x04, 0x25, 0xA7,
                    0xCF, 0x3A, 0xB6, 0xAF, 0x6B, 0x7F, 0xC3, 0x10, 0x3B, 0x88, 0x32, 0x02, 0xE9, 0x04, 0x65, 0x65
                };
                memcpy(curve->p, p_brainpoolP384r1, size);
                memcpy(curve->a, a_brainpoolP384r1, size);
                memcpy(curve->b, b_brainpoolP384r1, size);
                memcpy(curve->G.x, gx_brainpoolP384r1, size);
                memcpy(curve->G.y, gy_brainpoolP384r1, size);
                curve->G.size = size;
                memcpy(curve->n, n_brainpoolP384r1, size);
            }
            break;
        case NOXTLS_ECC_BP512R1:
            {
                static const uint8_t p_brainpoolP512r1[64] = {
                    0xAA, 0xDD, 0x9D, 0xB8, 0xDB, 0xE9, 0xC4, 0x8B, 0x3F, 0xD4, 0xE6, 0xAE, 0x33, 0xC9, 0xFC, 0x07,
                    0xCB, 0x30, 0x8D, 0xB3, 0xB3, 0xC9, 0xD2, 0x0E, 0xD6, 0x63, 0x9C, 0xCA, 0x70, 0x33, 0x08, 0x71,
                    0x7D, 0x4D, 0x9B, 0x00, 0x9B, 0xC6, 0x68, 0x42, 0xAE, 0xCD, 0xA1, 0x2A, 0xE6, 0xA3, 0x80, 0xE6,
                    0x28, 0x81, 0xFF, 0x2F, 0x2D, 0x82, 0xC6, 0x85, 0x28, 0xAA, 0x60, 0x56, 0x58, 0x3A, 0x48, 0xF3
                };
                static const uint8_t a_brainpoolP512r1[64] = {
                    0x78, 0x30, 0xA3, 0x31, 0x8B, 0x60, 0x3B, 0x89, 0xE2, 0x32, 0x71, 0x45, 0xAC, 0x23, 0x4C, 0xC5,
                    0x94, 0xCB, 0xDD, 0x8D, 0x3D, 0xF9, 0x16, 0x10, 0xA8, 0x34, 0x41, 0xCA, 0xEA, 0x98, 0x63, 0xBC,
                    0x2D, 0xED, 0x5D, 0x5A, 0xA8, 0x25, 0x3A, 0xA1, 0x0A, 0x2E, 0xF1, 0xC9, 0x8B, 0x9A, 0xC8, 0xB5,
                    0x7F, 0x11, 0x17, 0xA7, 0x2B, 0xF2, 0xC7, 0xB9, 0xE7, 0xC1, 0xAC, 0x4D, 0x77, 0xFC, 0x94, 0xCA
                };
                static const uint8_t b_brainpoolP512r1[64] = {
                    0x3D, 0xF9, 0x16, 0x10, 0xA8, 0x34, 0x41, 0xCA, 0xEA, 0x98, 0x63, 0xBC, 0x2D, 0xED, 0x5D, 0x5A,
                    0xA8, 0x25, 0x3A, 0xA1, 0x0A, 0x2E, 0xF1, 0xC9, 0x8B, 0x9A, 0xC8, 0xB5, 0x7F, 0x11, 0x17, 0xA7,
                    0x2B, 0xF2, 0xC7, 0xB9, 0xE7, 0xC1, 0xAC, 0x4D, 0x77, 0xFC, 0x94, 0xCA, 0xDC, 0x08, 0x3E, 0x67,
                    0x98, 0x40, 0x50, 0xB7, 0x5E, 0xBA, 0xE5, 0xDD, 0x28, 0x09, 0xBD, 0x63, 0x80, 0x16, 0xF7, 0x23
                };
                static const uint8_t gx_brainpoolP512r1[64] = {
                    0x81, 0xAE, 0xE4, 0xBD, 0xD8, 0x2E, 0xD9, 0x64, 0x5A, 0x21, 0x32, 0x2E, 0x9C, 0x4C, 0x6A, 0x93,
                    0x85, 0xED, 0x9F, 0x70, 0xB5, 0xD9, 0x16, 0xC1, 0xB4, 0x3B, 0x62, 0xEE, 0xF4, 0xD0, 0x09, 0x8E,
                    0xFF, 0x3B, 0x1F, 0x78, 0xE2, 0xD0, 0xD4, 0x8D, 0x50, 0xD1, 0x68, 0x7B, 0x93, 0xB9, 0x7D, 0x5F,
                    0x7C, 0x6D, 0x50, 0x47, 0x40, 0x6A, 0x5E, 0x68, 0x8B, 0x35, 0x22, 0x09, 0xBC, 0xB9, 0xF8, 0x22
                };
                static const uint8_t gy_brainpoolP512r1[64] = {
                    0x7D, 0xDE, 0x38, 0x5D, 0x56, 0x63, 0x32, 0xEC, 0xC0, 0xEA, 0xBF, 0xA9, 0xCF, 0x78, 0x22, 0xFD,
                    0xF2, 0x09, 0xF7, 0x00, 0x24, 0xA5, 0x7B, 0x1A, 0xA0, 0x00, 0xC5, 0x5B, 0x88, 0x1F, 0x81, 0x11,
                    0xB2, 0xDC, 0xDE, 0x49, 0x4A, 0x5F, 0x48, 0x5E, 0x5B, 0xCA, 0x4B, 0xD8, 0x8A, 0x27, 0x63, 0xAE,
                    0xD1, 0xCA, 0x2B, 0x2F, 0xA8, 0xF0, 0x54, 0x06, 0x78, 0xCD, 0x1E, 0x0F, 0x3A, 0xD8, 0x08, 0x92
                };
                static const uint8_t n_brainpoolP512r1[64] = {
                    0xAA, 0xDD, 0x9D, 0xB8, 0xDB, 0xE9, 0xC4, 0x8B, 0x3F, 0xD4, 0xE6, 0xAE, 0x33, 0xC9, 0xFC, 0x07,
                    0xCB, 0x30, 0x8D, 0xB3, 0xB3, 0xC9, 0xD2, 0x0E, 0xD6, 0x63, 0x9C, 0xCA, 0x70, 0x33, 0x08, 0x70,
                    0x55, 0x3E, 0x5C, 0x41, 0x4C, 0xA9, 0x26, 0x19, 0x41, 0x86, 0x61, 0x19, 0x7F, 0xAC, 0x10, 0x47,
                    0x1D, 0xB1, 0xD3, 0x81, 0x08, 0x5D, 0xDA, 0xDD, 0xB5, 0x87, 0x96, 0x82, 0x9C, 0xA9, 0x00, 0x69
                };
                memcpy(curve->p, p_brainpoolP512r1, size);
                memcpy(curve->a, a_brainpoolP512r1, size);
                memcpy(curve->b, b_brainpoolP512r1, size);
                memcpy(curve->G.x, gx_brainpoolP512r1, size);
                memcpy(curve->G.y, gy_brainpoolP512r1, size);
                curve->G.size = size;
                memcpy(curve->n, n_brainpoolP512r1, size);
            }
            break;
        case NOXTLS_ECC_SECP192K1:
            {
                static const uint8_t p_secp192k1[24] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xEE, 0x37
                };
                static const uint8_t a_secp192k1[24] = {0};
                static const uint8_t b_secp192k1[24] = {
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03
                };
                static const uint8_t gx_secp192k1[24] = {
                    0xDB, 0x4F, 0xF1, 0x0E, 0xC0, 0x57, 0xE9, 0xAE, 0x26, 0xB0, 0x7D, 0x02,
                    0x80, 0xB7, 0xF4, 0x34, 0x1D, 0xA5, 0xD1, 0xB1, 0xEA, 0xE0, 0x6C, 0x7D
                };
                static const uint8_t gy_secp192k1[24] = {
                    0x9B, 0x2F, 0x2F, 0x6D, 0x9C, 0x56, 0x28, 0xA7, 0x84, 0x41, 0x63, 0xD0,
                    0x15, 0xBE, 0x86, 0x34, 0x40, 0x82, 0xAA, 0x88, 0xD9, 0x5E, 0x2F, 0x9D
                };
                static const uint8_t n_secp192k1[24] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                    0x26, 0xF2, 0xFC, 0x17, 0x0F, 0x69, 0x46, 0x6A, 0x74, 0xDE, 0xFD, 0x8D
                };
                memcpy(curve->p, p_secp192k1, size);
                memcpy(curve->a, a_secp192k1, size);
                memcpy(curve->b, b_secp192k1, size);
                memcpy(curve->G.x, gx_secp192k1, size);
                memcpy(curve->G.y, gy_secp192k1, size);
                curve->G.size = size;
                memcpy(curve->n, n_secp192k1, size);
            }
            break;
        case NOXTLS_ECC_SECP224K1:
            {
                static const uint8_t p_secp224k1[28] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                    0xFF, 0xFF, 0xE5, 0x6D
                };
                static const uint8_t a_secp224k1[28] = {0};
                static const uint8_t b_secp224k1[28] = {
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x05
                };
                static const uint8_t gx_secp224k1[28] = {
                    0xA1, 0x45, 0x5B, 0x33, 0x4D, 0xF0, 0x99, 0xDF, 0x30, 0xFC, 0x28, 0xA1,
                    0x69, 0xA4, 0x67, 0xE9, 0xE4, 0x70, 0x75, 0xA9, 0x0F, 0x7E, 0x65, 0x0E,
                    0xB6, 0xB7, 0xA4, 0x5C
                };
                static const uint8_t gy_secp224k1[28] = {
                    0x7E, 0x08, 0x9F, 0xED, 0x7F, 0xBA, 0x34, 0x42, 0x82, 0xCA, 0xFB, 0xD6,
                    0xF7, 0xE3, 0x19, 0xF7, 0xC0, 0xB0, 0xBD, 0x59, 0xE2, 0xCA, 0x4B, 0xDB,
                    0x55, 0x6D, 0x61, 0xA5
                };
                static const uint8_t n_secp224k1[28] = {
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x01, 0xDC, 0xE8, 0xD2, 0xEC, 0x61, 0x84, 0xCA, 0xF0, 0xA9, 0x71,
                    0x76, 0x9F, 0xB1, 0xF7
                };
                memcpy(curve->p, p_secp224k1, size);
                memcpy(curve->a, a_secp224k1, size);
                memcpy(curve->b, b_secp224k1, size);
                memcpy(curve->G.x, gx_secp224k1, size);
                memcpy(curve->G.y, gy_secp224k1, size);
                curve->G.size = size;
                memcpy(curve->n, n_secp224k1, size);
            }
            break;
        case NOXTLS_ECC_SECP256K1:
            {
                static const uint8_t p_secp256k1[32] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F
                };
                static const uint8_t a_secp256k1[32] = {0};
                static const uint8_t b_secp256k1[32] = {
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07
                };
                static const uint8_t gx_secp256k1[32] = {
                    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95,
                    0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
                    0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98
                };
                static const uint8_t gy_secp256k1[32] = {
                    0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC,
                    0x0E, 0x11, 0x08, 0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
                    0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8
                };
                static const uint8_t n_secp256k1[32] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
                    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
                };
                memcpy(curve->p, p_secp256k1, size);
                memcpy(curve->a, a_secp256k1, size);
                memcpy(curve->b, b_secp256k1, size);
                memcpy(curve->G.x, gx_secp256k1, size);
                memcpy(curve->G.y, gy_secp256k1, size);
                curve->G.size = size;
                memcpy(curve->n, n_secp256k1, size);
            }
            break;
        default:
            return NOXTLS_RETURN_FAILED;
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
    if(s_fixed_base_cache.valid && s_fixed_base_cache.curve == curve) {
        if(s_fixed_base_cache.table) {
            free(s_fixed_base_cache.table);
            s_fixed_base_cache.table = NULL;
        }
        s_fixed_base_cache.curve = NULL;
        s_fixed_base_cache.size = 0;
        s_fixed_base_cache.valid = 0;
    }
    if(s_point_cache.valid && s_point_cache.curve == curve) {
        if(s_point_cache.table) {
            free(s_point_cache.table);
            s_point_cache.table = NULL;
        }
        s_point_cache.curve = NULL;
        s_point_cache.size = 0;
        s_point_cache.valid = 0;
    }
    if(s_muladd_cache.valid && s_muladd_cache.curve == curve) {
        if(s_muladd_cache.table) {
            free(s_muladd_cache.table);
            s_muladd_cache.table = NULL;
        }
        s_muladd_cache.curve = NULL;
        s_muladd_cache.size = 0;
        s_muladd_cache.valid = 0;
    }
#endif

    if(curve->p) { free(curve->p); curve->p = NULL; }
    if(curve->a) { free(curve->a); curve->a = NULL; }
    if(curve->b) { free(curve->b); curve->b = NULL; }
    if(curve->n) { free(curve->n); curve->n = NULL; }
    
    memset(curve, 0, sizeof(ecc_curve_params_t));
    
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
    
    memset(point, 0, sizeof(ecc_point_t));
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
    uint32_t i;
    for(i = 0; i < size; i++) {
        if(point->x[i] != 0 || point->y[i] != 0) {
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
    return noxtls_bn_is_zero(J->Z, size);
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
    return (noxtls_bn_cmp(p1->x, p2->x, size) == 0) && 
           (noxtls_bn_cmp(p1->y, p2->y, size) == 0);
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
    uint8_t mask = (uint8_t)(-(int)(b & 1));
    uint32_t i;
    for(i = 0; i < len; i++) {
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
    uint32_t j;

    noxtls_bn_zero(out->X, size);
    noxtls_bn_zero(out->Y, size);
    noxtls_bn_zero(out->Z, size);
    noxtls_bn_zero(z_one, size);
    z_one[size - 1U] = 0x01;

    for(j = 1U; j < table_len; j++) {
        ecc_cond_select(out->X, table[j].X, out->X, size, (uint8_t)(idx == j));
        ecc_cond_select(out->Y, table[j].Y, out->Y, size, (uint8_t)(idx == j));
    }
    ecc_cond_select(out->Z, z_one, out->Z, size, (uint8_t)(idx != 0U));
}

/** Get bit at bit_index (0 = MSB of scalar[0]) from big-endian scalar. */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static uint8_t ecc_scalar_getbit(const uint8_t *scalar, uint32_t size_bytes, uint32_t bit_index)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint32_t byte_idx = bit_index >> 3;
    uint32_t bit_in_byte = 7 - (bit_index & 7);
    if(byte_idx >= size_bytes) return 0;
    return (uint8_t)((scalar[byte_idx] >> bit_in_byte) & 1);
}

/** Extract a big-endian digit from bit range [start_bit, start_bit + width). */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static uint32_t ecc_scalar_digit_range(const uint8_t *scalar,
                                       uint32_t size_bytes,
                                       uint32_t start_bit,
                                       uint32_t width)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint32_t d = 0;
    uint32_t b;
    uint32_t n_bits;

    if(size_bytes > (uint32_t)(UINT32_MAX / 8U)) {
        return 0;
    }
    n_bits = size_bytes * 8U;
    if(start_bit >= n_bits) {
        return 0;
    }
    for(b = 0; b < width && (start_bit + b) < n_bits; b++) {
        d = (d << 1) | ecc_scalar_getbit(scalar, size_bytes, start_bit + b);
    }
    return d;
}

/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static void ecc_mod_add(uint8_t *out, const uint8_t *a, const uint8_t *b, const uint8_t *p, uint32_t size);
/* NOLINTEND(bugprone-easily-swappable-parameters) */

static const uint8_t s_p256_prime_be[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static const uint8_t s_p256_a_be[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
};

static const uint32_t s_p256_prime_words[8] = {
    0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000001u, 0xFFFFFFFFu
};

static const uint32_t s_p256_order_words[8] = {
    0xFC632551u, 0xF3B9CAC2u, 0xA7179E84u, 0xBCE6FAADu,
    0xFFFFFFFFu, 0xFFFFFFFFu, 0x00000000u, 0xFFFFFFFFu
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
    return (size == 32U && p != NULL && memcmp(p, s_p256_prime_be, 32U) == 0);
}

/**
 * @brief Check if the curve is P-256
 * 
 * @param curve The curve
 * @return The return value
 */
static int ecc_curve_is_secp256r1(const ecc_curve_params_t *curve)
{
    if(curve == NULL || curve->size != 32U || curve->p == NULL || curve->a == NULL) {
        return 0;
    }
    return memcmp(curve->p, s_p256_prime_be, 32U) == 0 &&
           memcmp(curve->a, s_p256_a_be, 32U) == 0;
}

/**
 * @brief Convert big-endian words to 32-bit words
 * 
 * @param out The output buffer
 * @param in The input buffer
 */
static void p256_words_from_be(uint32_t out[8], const uint8_t in[32])
{
    uint32_t i;

    for(i = 0; i < 8U; i++) {
        uint32_t o = 32U - ((i + 1U) * 4U);
        out[i] = ((uint32_t)in[o] << 24) |
                 ((uint32_t)in[o + 1U] << 16) |
                 ((uint32_t)in[o + 2U] << 8) |
                 ((uint32_t)in[o + 3U]);
    }
}

/**
 * @brief Convert 32-bit words to big-endian bytes
 * 
 * @param out The output buffer
 * @param in The input buffer
 */
static void p256_words_to_be(uint8_t out[32], const uint32_t in[8])
{
    uint32_t i;

    for(i = 0; i < 8U; i++) {
        uint32_t w = in[i];
        uint32_t o = 32U - ((i + 1U) * 4U);
        out[o] = (uint8_t)(w >> 24);
        out[o + 1U] = (uint8_t)(w >> 16);
        out[o + 2U] = (uint8_t)(w >> 8);
        out[o + 3U] = (uint8_t)w;
    }
}

/**
 * @brief Check if the words are zero
 * 
 * @param a The input buffer
 * @return The return value
 */
static int p256_words_is_zero(const uint32_t a[8])
{
    uint32_t i;

    for(i = 0; i < 8U; i++) {
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
static int p256_words_cmp(const uint32_t a[8], const uint32_t b[8])
{
    uint32_t i;

    for(i = 8U; i > 0U; i--) {
        uint32_t idx = i - 1U;
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
static void p256_words_sub_raw(uint32_t out[8], const uint32_t a[8], const uint32_t b[8])
{
    uint64_t borrow = 0U;
    uint32_t i;

    for(i = 0; i < 8U; i++) {
        uint64_t ai = (uint64_t)a[i];
        uint64_t bi = (uint64_t)b[i] + borrow;
        if(ai < bi) {
            out[i] = (uint32_t)(ai + (1ULL << 32) - bi);
            borrow = 1U;
        } else {
            out[i] = (uint32_t)(ai - bi);
            borrow = 0U;
        }
    }
}

static void p256_fold_acc(int64_t acc[24], uint32_t idx);

/**
 * @brief Reduce the accumulated words
 * 
 * @param out The output buffer
 * @param acc The accumulated words
 */
static void p256_reduce_acc_words(uint32_t out[8], int64_t acc[24])
{
    uint32_t i;
    int changed = 1;
    const int64_t base = 0x100000000LL;

    while(changed) {
        changed = 0;

        for(i = 8U; i < 24U; i++) {
            if(acc[i] != 0) {
                p256_fold_acc(acc, i);
                changed = 1;
            }
        }

        for(i = 0; i < 8U; i++) {
            int64_t v = acc[i];
            if(v < 0 || v >= base) {
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

    for(i = 0; i < 8U; i++) {
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
static void p256_words_add_mod(uint32_t out[8], const uint32_t a[8], const uint32_t b[8])
{
    uint32_t sum[8];
    uint64_t carry = 0U;
    uint32_t i;

    for(i = 0; i < 8U; i++) {
        uint64_t v = (uint64_t)a[i] + (uint64_t)b[i] + carry;
        sum[i] = (uint32_t)v;
        carry = v >> 32;
    }

    if(carry == 0U && p256_words_cmp(sum, s_p256_prime_words) < 0) {
        memcpy(out, sum, 8U * sizeof(uint32_t));
        return;
    }

    {
        int64_t acc[24];
        memset(acc, 0, sizeof(acc));
        for(i = 0; i < 8U; i++) {
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
static void p256_words_sub_mod(uint32_t out[8], const uint32_t a[8], const uint32_t b[8])
{
    uint32_t diff[8];
    uint64_t borrow = 0U;
    uint32_t i;

    for(i = 0; i < 8U; i++) {
        uint64_t ai = (uint64_t)a[i];
        uint64_t bi = (uint64_t)b[i] + borrow;
        if(ai < bi) {
            diff[i] = (uint32_t)(ai + (1ULL << 32) - bi);
            borrow = 1U;
        } else {
            diff[i] = (uint32_t)(ai - bi);
            borrow = 0U;
        }
    }

    if(borrow == 0U) {
        memcpy(out, diff, 8U * sizeof(uint32_t));
        return;
    }

    {
        int64_t acc[24];
        memset(acc, 0, sizeof(acc));
        for(i = 0; i < 8U; i++) {
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
static void p256_mul_words(uint32_t out[16], const uint32_t a[8], const uint32_t b[8])
{
    uint32_t i;
    uint32_t j;
    uint32_t k;

    memset(out, 0, 16U * sizeof(uint32_t));

    for(i = 0; i < 8U; i++) {
        uint64_t carry = 0U;
        for(j = 0; j < 8U; j++) {
            uint64_t t = (uint64_t)out[i + j] + ((uint64_t)a[i] * (uint64_t)b[j]) + carry;
            out[i + j] = (uint32_t)t;
            carry = t >> 32;
        }
        k = i + 8U;
        while(carry != 0U && k < 16U) {
            uint64_t t = (uint64_t)out[k] + carry;
            out[k] = (uint32_t)t;
            carry = t >> 32;
            k++;
        }
    }
}

/**
 * @brief Fold the accumulated words
 * 
 * @param acc The accumulated words
 * @param idx The index
 */
static void p256_fold_acc(int64_t acc[24], uint32_t idx)
{
    int64_t c = acc[idx];
    uint32_t k = idx - 8U;

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
static void p256_reduce_words(uint32_t out[8], const uint32_t in[16])
{
    int64_t acc[24];
    uint32_t i;

    memset(acc, 0, sizeof(acc));
    for(i = 0; i < 16U; i++) {
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
static void p256_fe_add(uint8_t out[32], const uint8_t a[32], const uint8_t b[32])
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
static void p256_fe_sub(uint8_t out[32], const uint8_t a[32], const uint8_t b[32])
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
static void p256_fe_mul(uint8_t out[32], const uint8_t a[32], const uint8_t b[32])
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
static void p256_fe_sqr(uint8_t out[32], const uint8_t a[32])
{
    p256_fe_mul(out, a, a);
}

/**
 * @brief Double a field element
 * 
 * @param out The output buffer
 * @param a The field element
 */
static void p256_fe_double(uint8_t out[32], const uint8_t a[32])
{
    p256_fe_add(out, a, a);
}

/**
 * @brief Triple a field element
 * 
 * @param out The output buffer
 * @param a The field element
 */
static void p256_fe_triple(uint8_t out[32], const uint8_t a[32])
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
static void p256_fe_quad(uint8_t out[32], const uint8_t a[32])
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
static void p256_fe_oct(uint8_t out[32], const uint8_t a[32])
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
static void ecc_mul_256_to_512(uint8_t out64[64], const uint8_t a32[32], const uint8_t b32[32])
{
    uint32_t a[8];
    uint32_t b[8];
    uint32_t limbs[16];
    uint64_t carry;
    uint64_t t;
    uint32_t i;
    uint32_t j;
    uint32_t k;

    memset(limbs, 0, sizeof(limbs));

    for(i = 0; i < 8U; i++) {
        uint32_t o = 32U - ((i + 1U) * 4U);
        a[i] = ((uint32_t)a32[o] << 24) |
               ((uint32_t)a32[o + 1U] << 16) |
               ((uint32_t)a32[o + 2U] << 8) |
               ((uint32_t)a32[o + 3U]);
        b[i] = ((uint32_t)b32[o] << 24) |
               ((uint32_t)b32[o + 1U] << 16) |
               ((uint32_t)b32[o + 2U] << 8) |
               ((uint32_t)b32[o + 3U]);
    }

    for(i = 0; i < 8U; i++) {
        carry = 0U;
        for(j = 0; j < 8U; j++) {
            t = (uint64_t)limbs[i + j] + ((uint64_t)a[i] * (uint64_t)b[j]) + carry;
            limbs[i + j] = (uint32_t)(t & 0xFFFFFFFFu);
            carry = t >> 32;
        }
        k = i + 8U;
        while(carry != 0U && k < 16U) {
            t = (uint64_t)limbs[k] + carry;
            limbs[k] = (uint32_t)(t & 0xFFFFFFFFu);
            carry = t >> 32;
            k++;
        }
    }

    for(i = 0; i < 16U; i++) {
        uint32_t w = limbs[i];
        uint32_t o = 64U - ((i + 1U) * 4U);
        out64[o] = (uint8_t)(w >> 24);
        out64[o + 1U] = (uint8_t)(w >> 16);
        out64[o + 2U] = (uint8_t)(w >> 8);
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
    if(ecc_modulus_is_secp256r1(p, size)) {
        p256_fe_mul(out, a, b);
        return;
    }
    if(size == 32U) {
        uint8_t prod64[64];
        ecc_mul_256_to_512(prod64, a, b);
        noxtls_bn_mod(out, prod64, 64U, p, 32U);
        return;
    }
    noxtls_bn_mul(tmp2n, a, size, b, size);
    noxtls_bn_mod(out, tmp2n, size * 2U, p, size);
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
    if(ecc_modulus_is_secp256r1(p, size)) {
        p256_fe_sub(out, a, b);
        return;
    }
    if(size == 0U || size > ECC_MAX_KEY_SIZE) {
        if(out != NULL) {
            noxtls_bn_zero(out, size);
        }
        return;
    }
    if(noxtls_bn_cmp(a, b, size) >= 0) {
        /* a,b < p so (a-b) is already canonical. */
        noxtls_bn_sub(out, a, b, size);
    } else {
        uint8_t p_minus_b[ECC_MAX_KEY_SIZE];
        noxtls_bn_zero(p_minus_b, size);
        noxtls_bn_sub(p_minus_b, p, b, size);  /* p >= b, so p_minus_b = p - b */
        noxtls_bn_add(out, a, p_minus_b, size); /* (a - b) mod p = a + (p - b); result < p */
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
    uint16_t carry = 0;
    uint16_t borrow = 0;
    uint32_t i;

    if(ecc_modulus_is_secp256r1(p, size)) {
        p256_fe_add(out, a, b);
        return;
    }

    if(size == 0U || size == UINT32_MAX || size > ECC_MAX_KEY_SIZE) {
        return;
    }

    for(i = size; i > 0; i--) {
        uint16_t sum = (uint16_t)a[i - 1] + (uint16_t)b[i - 1] + carry;
        out[i - 1] = (uint8_t)(sum & 0xFF);
        carry = sum >> 8;
    }
    /* Since a,b < p, sum < 2p. Reduce with a single conditional subtraction. */
    if(carry || noxtls_bn_cmp(out, p, size) >= 0) {
        for(i = size; i > 0; i--) {
            uint16_t ai = (uint16_t)out[i - 1];
            uint16_t bi = (uint16_t)p[i - 1] + borrow;
            if(ai < bi) {
                out[i - 1] = (uint8_t)(ai + 256u - bi);
                borrow = 1U;
            } else {
                out[i - 1] = (uint8_t)(ai - bi);
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
    if(p256_words_is_zero(y_words) || noxtls_bn_is_zero(P->Z, 32U)) {
        noxtls_bn_zero(out->X, 32U);
        noxtls_bn_zero(out->Y, 32U);
        noxtls_bn_zero(out->Z, 32U);
        out->size = 32U;
        return NOXTLS_RETURN_SUCCESS;
    }

    p256_fe_sqr(delta, P->Z);          /* delta = Z^2 */
    p256_fe_sqr(gamma, P->Y);          /* gamma = Y^2 */
    p256_fe_mul(beta, P->X, gamma);    /* beta = X*gamma */

    p256_fe_sub(tmp1, P->X, delta);
    p256_fe_add(tmp2, P->X, delta);
    p256_fe_mul(alpha, tmp1, tmp2);
    p256_fe_triple(alpha, alpha);      /* alpha = 3*(X-delta)*(X+delta) */

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

    if(noxtls_bn_is_zero(P->Z, 32U)) {
        noxtls_bn_copy(out->X, Q_affine->X, 32U);
        noxtls_bn_copy(out->Y, Q_affine->Y, 32U);
        noxtls_bn_zero(out->Z, 32U);
        out->Z[31] = 0x01;
        out->size = 32U;
        return NOXTLS_RETURN_SUCCESS;
    }

    if(noxtls_bn_is_zero(Q_affine->Z, 32U)) {
        noxtls_bn_copy(out->X, P->X, 32U);
        noxtls_bn_copy(out->Y, P->Y, 32U);
        noxtls_bn_copy(out->Z, P->Z, 32U);
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
    if(p256_words_is_zero(h_words)) {
        if(p256_words_is_zero(r_words)) {
            return p256_jpoint_double(out, P);
        }
        noxtls_bn_zero(out->X, 32U);
        noxtls_bn_zero(out->Y, 32U);
        noxtls_bn_zero(out->Z, 32U);
        out->size = 32U;
        return NOXTLS_RETURN_SUCCESS;
    }

    p256_fe_sqr(HH, H);
    p256_fe_quad(I, HH);               /* I = 4*HH */
    p256_fe_mul(J, H, I);
    p256_fe_double(r, R);              /* r = 2*(S2 - Y1) */
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
    uint32_t size = curve->size;
    const uint8_t *p = curve->p;
    const uint8_t *a = curve->a;
    uint8_t t1[ECC_MAX_KEY_SIZE * 2U];
    uint8_t t2[ECC_MAX_KEY_SIZE * 2U];
    uint8_t t3[ECC_MAX_KEY_SIZE * 2U];
    uint8_t S[ECC_MAX_KEY_SIZE];
    uint8_t M[ECC_MAX_KEY_SIZE];
    static const uint8_t two_arr[1] = {0x02};
    static const uint8_t three_arr[1] = {0x03};
    static const uint8_t four_arr[1] = {0x04};
    static const uint8_t eight_arr[1] = {0x08};
    if(size == 0U || size > ECC_MAX_KEY_SIZE || size > (uint32_t)(UINT32_MAX / 2U) || size == UINT32_MAX) {
        return NOXTLS_RETURN_FAILED;
    }

    if(ecc_curve_is_secp256r1(curve)) {
        return p256_jpoint_double(out, P);
    }

    if(ecc_jpoint_is_infinity(P, size)) {
        noxtls_bn_zero(out->X, size);
        noxtls_bn_zero(out->Y, size);
        noxtls_bn_zero(out->Z, size);
        out->size = size;
        return NOXTLS_RETURN_SUCCESS;
    }

    noxtls_bn_zero(t1, size * 2U);
    noxtls_bn_zero(t2, size * 2U);
    noxtls_bn_zero(t3, size * 2U);
    noxtls_bn_zero(S, size);
    noxtls_bn_zero(M, size);

    /* S = 4*X1*Y1^2 mod p */
        ecc_mul_mod(t2, P->Y, P->Y, p, size, t1);
        ecc_mul_mod(t2, P->X, t2, p, size, t1);
        noxtls_bn_mul(t1, t2, size, four_arr, 1);
        noxtls_bn_mod(S, t1, size + 1, p, size);

        /* M = 3*X1^2 + a*Z1^4 mod p */
        ecc_mul_mod(t2, P->X, P->X, p, size, t1);
        noxtls_bn_mul(t1, t2, size, three_arr, 1);
        noxtls_bn_mod(t2, t1, size + 1, p, size);
        ecc_mul_mod(t3, P->Z, P->Z, p, size, t1);
        ecc_mul_mod(t3, t3, t3, p, size, t1);
        ecc_mul_mod(t3, a, t3, p, size, t1);
        ecc_mod_add(M, t2, t3, p, size);

        /* X3 = M^2 - 2*S mod p */
        ecc_mul_mod(t2, M, M, p, size, t1);
        noxtls_bn_mul(t1, S, size, two_arr, 1);
        noxtls_bn_mod(t3, t1, size + 1, p, size);
        ecc_mod_sub(out->X, t2, t3, p, size);

        /* Y3 = M*(S - X3) - 8*Y1^4 mod p */
        ecc_mod_sub(t2, S, out->X, p, size);
        ecc_mul_mod(t2, M, t2, p, size, t1);
        ecc_mul_mod(t3, P->Y, P->Y, p, size, t1);
        ecc_mul_mod(t3, t3, t3, p, size, t1);
        noxtls_bn_mul(t1, t3, size, eight_arr, 1);
        noxtls_bn_mod(t3, t1, size + 1, p, size);
        ecc_mod_sub(out->Y, t2, t3, p, size);

        /* Z3 = 2*Y1*Z1 mod p */
        ecc_mul_mod(t2, P->Y, P->Z, p, size, t1);
        noxtls_bn_mul(t1, t2, size, two_arr, 1);
        noxtls_bn_mod(out->Z, t1, size + 1, p, size);

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
    uint32_t size = curve->size;
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
    if(size == 0U || size > ECC_MAX_KEY_SIZE || size > (uint32_t)(UINT32_MAX / 2U)) {
        return NOXTLS_RETURN_FAILED;
    }

    if(ecc_jpoint_is_infinity(P, size)) {
        noxtls_bn_copy(out->X, Q->X, size);
        noxtls_bn_copy(out->Y, Q->Y, size);
        noxtls_bn_copy(out->Z, Q->Z, size);
        out->size = size;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(ecc_jpoint_is_infinity(Q, size)) {
        noxtls_bn_copy(out->X, P->X, size);
        noxtls_bn_copy(out->Y, P->Y, size);
        noxtls_bn_copy(out->Z, P->Z, size);
        out->size = size;
        return NOXTLS_RETURN_SUCCESS;
    }

    if(ecc_curve_is_secp256r1(curve)) {
        if(noxtls_bn_is_one(Q->Z, size)) {
            return p256_jpoint_add_mixed(out, P, Q);
        }
        if(noxtls_bn_is_one(P->Z, size)) {
            return p256_jpoint_add_mixed(out, Q, P);
        }
    }

    noxtls_bn_zero(U1, size);
    noxtls_bn_zero(U2, size);
    noxtls_bn_zero(S1, size);
    noxtls_bn_zero(S2, size);
    noxtls_bn_zero(H, size);
    noxtls_bn_zero(R, size);
    noxtls_bn_zero(t1, size * 2U);
    noxtls_bn_zero(t2, size * 2U);
    noxtls_bn_zero(t3, size * 2U);

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

    if(noxtls_bn_is_zero(H, size)) {
        /* P == Q or P == -Q. Caller must not use add for doubling. */
        if(noxtls_bn_is_zero(R, size)) {
            return NOXTLS_RETURN_FAILED; /* would be doubling */
        }
        noxtls_bn_zero(out->X, size);
        noxtls_bn_zero(out->Y, size);
        noxtls_bn_zero(out->Z, size);
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
        const uint8_t two_arr[1] = {0x02};
        noxtls_bn_mul(t1, t3, size, two_arr, 1);
        noxtls_bn_mod(t1, t1, size + 1, p, size);
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

static noxtls_return_t ecc_jpoint_to_affine(uint8_t *x, uint8_t *y, const ecc_jpoint_t *J, const ecc_curve_params_t *curve);

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
    uint32_t size;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    
    if(result == NULL || p1 == NULL || p2 == NULL || curve == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    size = curve->size;
    if(size == 0U || size > (uint32_t)(UINT32_MAX / 2U)) {
        return NOXTLS_RETURN_FAILED;
    }

    /* Handle point at infinity cases */
    if(ecc_point_is_infinity(p1, size)) {
        noxtls_bn_copy(result->x, p2->x, size);
        noxtls_bn_copy(result->y, p2->y, size);
        result->size = size;
        goto cleanup_ptadd;
    }

    if(ecc_point_is_infinity(p2, size)) {
        noxtls_bn_copy(result->x, p1->x, size);
        noxtls_bn_copy(result->y, p1->y, size);
        result->size = size;
        goto cleanup_ptadd;
    }

    /* Check if P == -Q (P + (-Q) = infinity) */
    noxtls_bn_copy(temp1, p2->y, size);
    noxtls_bn_sub(temp2, curve->p, temp1, size);  /* temp2 = p - y2 */
    noxtls_bn_mod(temp2, temp2, size, curve->p, size);

    if(noxtls_bn_cmp(p1->x, p2->x, size) == 0 && noxtls_bn_cmp(p1->y, temp2, size) == 0) {
        /* Result is point at infinity */
        noxtls_bn_zero(result->x, size);
        noxtls_bn_zero(result->y, size);
        result->size = size;
        goto cleanup_ptadd;
    }

    /* Use Jacobian add/double + to_affine for correct, consistent results (same formulas as scalar mult path). */
    {
        ecc_jpoint_t J1;
        ecc_jpoint_t J2;
        ecc_jpoint_t Jout;
        memset(&J1, 0, sizeof(J1));
        memset(&J2, 0, sizeof(J2));
        memset(&Jout, 0, sizeof(Jout));
        J1.size = J2.size = Jout.size = size;
        noxtls_bn_copy(J1.X, p1->x, size);
        noxtls_bn_copy(J1.Y, p1->y, size);
        noxtls_bn_zero(J1.Z, size);
        J1.Z[size - 1] = 1;
        noxtls_bn_copy(J2.X, p2->x, size);
        noxtls_bn_copy(J2.Y, p2->y, size);
        noxtls_bn_zero(J2.Z, size);
        J2.Z[size - 1] = 1;

        if(ecc_point_equal(p1, p2, size)) {
            rc = ecc_jpoint_double(&Jout, &J1, curve);
        } else {
            rc = ecc_jpoint_add(&Jout, &J1, &J2, curve);
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_bn_zero(result->x, size);
            noxtls_bn_zero(result->y, size);
            result->size = size;
            goto cleanup_ptadd;
        }
        if(ecc_jpoint_is_infinity(&Jout, size)) {
            noxtls_bn_zero(result->x, size);
            noxtls_bn_zero(result->y, size);
            result->size = size;
            goto cleanup_ptadd;
        }
        rc = ecc_jpoint_to_affine(result->x, result->y, &Jout, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_bn_zero(result->x, size);
            noxtls_bn_zero(result->y, size);
            result->size = size;
            goto cleanup_ptadd;
        }
        result->size = size;
    }

cleanup_ptadd:
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
    uint32_t size = curve->size;
    const uint8_t *p = curve->p;
    uint8_t inv[ECC_MAX_KEY_SIZE];
    uint8_t z2[ECC_MAX_KEY_SIZE];
    uint8_t z3[ECC_MAX_KEY_SIZE];
    uint8_t t1[ECC_MAX_KEY_SIZE * 2U];
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    if(size == 0U || size > ECC_MAX_KEY_SIZE || size > (uint32_t)(UINT32_MAX / 2U)) {
        return NOXTLS_RETURN_FAILED;
    }

    if(ecc_jpoint_is_infinity(J, size)) {
        noxtls_bn_zero(x, size);
        noxtls_bn_zero(y, size);
        return NOXTLS_RETURN_SUCCESS;
    }

    noxtls_bn_zero(inv, size);
    noxtls_bn_zero(z2, size);
    noxtls_bn_zero(z3, size);
    noxtls_bn_zero(t1, size * 2U);

    rc = ecc_mod_inv_prime(inv, J->Z, p, size);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(noxtls_bn_is_zero(inv, size)) {
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
    uint32_t size = curve->size;
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
    uint32_t i;
    noxtls_return_t rc;

    if(size == 0U || size > ECC_MAX_KEY_SIZE || table_len < 2U) {
        return NOXTLS_RETURN_FAILED;
    }

    active_idx = (uint32_t*)calloc(table_len, sizeof(uint32_t));
    prefix = (uint8_t*)calloc((size_t)table_len, size);
    if(active_idx == NULL || prefix == NULL) {
        if(active_idx != NULL) {
            free(active_idx);
        }
        if(prefix != NULL) {
            free(prefix);
        }
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }

    memset(acc, 0, sizeof(acc));
    memset(inv_z, 0, sizeof(inv_z));
    memset(next_acc, 0, sizeof(next_acc));
    memset(z2, 0, sizeof(z2));
    memset(z3, 0, sizeof(z3));
    memset(tmp2n, 0, sizeof(tmp2n));

    for(i = 1U; i < table_len; i++) {
        uint8_t *prefix_i;

        if(ecc_jpoint_is_infinity(&T[i], size)) {
            continue;
        }

        active_idx[count] = i;
        prefix_i = prefix + ((size_t)count * size);
        if(count == 0U) {
            noxtls_bn_copy(prefix_i, T[i].Z, size);
        } else {
            ecc_mul_mod(prefix_i, prefix + (((size_t)count - 1U) * size), T[i].Z, p, size, tmp2n);
        }
        count++;
    }

    if(count == 0U) {
        free(prefix);
        free(active_idx);
        return NOXTLS_RETURN_SUCCESS;
    }

    rc = ecc_mod_inv_prime(acc, prefix + (((size_t)count - 1U) * size), p, size);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(prefix);
        free(active_idx);
        return rc;
    }

    for(i = count; i > 0U; i--) {
        uint32_t pos = i - 1U;
        uint32_t point_idx = active_idx[pos];

        if(pos == 0U) {
            noxtls_bn_copy(inv_z, acc, size);
        } else {
            ecc_mul_mod(inv_z, acc, prefix + (((size_t)pos - 1U) * size), p, size, tmp2n);
            ecc_mul_mod(next_acc, acc, T[point_idx].Z, p, size, tmp2n);
            noxtls_bn_copy(acc, next_acc, size);
        }

        ecc_mul_mod(z2, inv_z, inv_z, p, size, tmp2n);
        ecc_mul_mod(z3, z2, inv_z, p, size, tmp2n);
        ecc_mul_mod(T[point_idx].X, T[point_idx].X, z2, p, size, tmp2n);
        ecc_mul_mod(T[point_idx].Y, T[point_idx].Y, z3, p, size, tmp2n);
        noxtls_bn_zero(T[point_idx].Z, size);
        T[point_idx].Z[size - 1U] = 0x01;
    }

    free(prefix);
    free(active_idx);
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
    uint32_t size = curve->size;
    noxtls_return_t rc;
    uint32_t i;

    if(table_len < 2) return NOXTLS_RETURN_FAILED;
    memset(T, 0, table_len * sizeof(ecc_jpoint_t));
    for(i = 0; i < table_len; i++) T[i].size = size;

    /* T[0] = identity (Z=0) */
    noxtls_bn_zero(T[0].X, size);
    noxtls_bn_zero(T[0].Y, size);
    noxtls_bn_zero(T[0].Z, size);

    /* T[1] = P in Jacobian */
    noxtls_bn_copy(T[1].X, point->x, size);
    noxtls_bn_copy(T[1].Y, point->y, size);
    noxtls_bn_zero(T[1].Z, size);
    T[1].Z[size - 1] = 0x01;

    /* T[2] = 2*P */
    rc = ecc_jpoint_double(&T[2], &T[1], curve);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;

    for(i = 3; i < table_len; i++) {
        rc = ecc_jpoint_add(&T[i], &T[i - 1], &T[1], curve);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    }

    if(ecc_curve_is_secp256r1(curve)) {
        rc = ecc_precompute_table_to_affine(T, table_len, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Get the bit at the given index
 * 
 * @param[in] scalar The scalar
 * @param[in] bit_index The index of the bit
 * @return The bit
 */
static uint8_t p256_scalar_getbit_lsb(const uint8_t *scalar, uint32_t bit_index)
{
    uint32_t byte_from_end;
    uint32_t byte_idx;

    if(scalar == NULL || bit_index >= 256u) {
        return 0U;
    }

    byte_from_end = bit_index >> 3;
    byte_idx = 31U - byte_from_end;
    return (uint8_t)((scalar[byte_idx] >> (bit_index & 7U)) & 1U);
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
    uint32_t i;
    uint32_t j;

    memset(digits, 0, d);

    for(i = 0U; i < d; i++) {
        for(j = 0U; j < w; j++) {
            digits[i] |= (uint8_t)(p256_scalar_getbit_lsb(scalar, i + (d * j)) << j);
        }
    }
}

/**
 * @brief Reduce the scalar modulo the order
 * 
 * @param[out] out The output
 * @param[in] in The input
 */
static void p256_scalar_reduce_mod_order(uint8_t out[32], const uint8_t in[32])
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
    uint32_t i;
    uint32_t j;
    noxtls_return_t rc;

    memset(&cur, 0, sizeof(cur));
    memset(&tmp, 0, sizeof(tmp));
    cur.size = 32U;
    tmp.size = 32U;

    memset(table, 0, table_len * sizeof(ecc_jpoint_t));
    for(i = 0U; i < table_len; i++) {
        table[i].size = 32U;
    }

    noxtls_bn_zero(table[0].X, 32U);
    noxtls_bn_zero(table[0].Y, 32U);
    noxtls_bn_zero(table[0].Z, 32U);
    noxtls_bn_copy(table[1].X, point->x, 32U);
    noxtls_bn_copy(table[1].Y, point->y, 32U);
    noxtls_bn_zero(table[1].Z, 32U);
    table[1].Z[31] = 0x01;

    noxtls_bn_copy(cur.X, point->x, 32U);
    noxtls_bn_copy(cur.Y, point->y, 32U);
    noxtls_bn_zero(cur.Z, 32U);
    cur.Z[31] = 0x01;

    for(i = 1U; i < w; i++) {
        for(j = 0U; j < d; j++) {
            rc = p256_jpoint_double(&tmp, &cur);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            memcpy(&cur, &tmp, sizeof(cur));
        }
        memcpy(&table[1U << i], &cur, sizeof(cur));
    }

    if(table_len > 1U) {
        rc = ecc_precompute_table_to_affine(table, table_len, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    for(i = 1U; i < table_len; i <<= 1U) {
        for(j = 0U; j < i; j++) {
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
    uint32_t d = (256u + w - 1U) / w;
    uint8_t digits[64];
    ecc_jpoint_t R;
    ecc_jpoint_t Txi;
    ecc_jpoint_t Tdbl;
    noxtls_return_t rc;
    uint32_t i;
    uint8_t reduced[32];

    memset(&R, 0, sizeof(R));
    memset(&Txi, 0, sizeof(Txi));
    memset(&Tdbl, 0, sizeof(Tdbl));
    R.size = 32U;
    Txi.size = 32U;
    Tdbl.size = 32U;

    p256_scalar_reduce_mod_order(reduced, scalar);
    p256_comb_recode_core(digits, d, w, reduced);

    for(i = d; i > 0U; i--) {
        rc = p256_jpoint_double(&Tdbl, &R);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        memcpy(&R, &Tdbl, sizeof(R));

        ecc_jpoint_select_affine_table(&Txi, table, 1U << w, 32U, digits[i - 1U]);
        Txi.size = 32U;
        rc = ecc_jpoint_add(&Tdbl, &R, &Txi, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        memcpy(&R, &Tdbl, sizeof(R));
    }

    memcpy(result, &R, sizeof(R));
    result->size = 32U;
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
static noxtls_return_t p256_ecc_point_mul_comb(ecc_point_t *result,
                                               const uint8_t *scalar,
                                               const ecc_curve_params_t *curve,
                                               const ecc_jpoint_t *table,
                                               uint32_t w)
{
    ecc_jpoint_t R;
    noxtls_return_t rc;

    memset(&R, 0, sizeof(R));
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
    uint32_t size = curve->size;
    uint32_t side_len = 1U << w;
    uint32_t joint_len = side_len * side_len;
    ecc_jpoint_t *table1 = NULL;
    ecc_jpoint_t *table2 = NULL;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t a;
    uint32_t b;

    table1 = (ecc_jpoint_t*)calloc(side_len, sizeof(ecc_jpoint_t));
    table2 = (ecc_jpoint_t*)calloc(side_len, sizeof(ecc_jpoint_t));
    if(table1 == NULL || table2 == NULL) {
        rc = NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        goto cleanup_joint_table;
    }

    rc = ecc_build_precompute_table(table1, side_len, point1, curve);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup_joint_table;
    }
    rc = ecc_build_precompute_table(table2, side_len, point2, curve);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup_joint_table;
    }

    memset(joint_table, 0, joint_len * sizeof(ecc_jpoint_t));
    for(a = 0U; a < side_len; a++) {
        for(b = 0U; b < side_len; b++) {
            uint32_t idx = (a << w) | b;
            joint_table[idx].size = size;

            if(a == 0U && b == 0U) {
                continue;
            }
            if(a == 0U) {
                memcpy(&joint_table[idx], &table2[b], sizeof(ecc_jpoint_t));
                continue;
            }
            if(b == 0U) {
                memcpy(&joint_table[idx], &table1[a], sizeof(ecc_jpoint_t));
                continue;
            }

            rc = ecc_jpoint_add(&joint_table[idx], &table1[a], &table2[b], curve);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                goto cleanup_joint_table;
            }
        }
    }

    rc = ecc_precompute_table_to_affine(joint_table, joint_len, curve);

cleanup_joint_table:
    if(table1 != NULL) {
        free(table1);
    }
    if(table2 != NULL) {
        free(table2);
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
    uint32_t size = curve->size;
    uint32_t side_len = 1U << w;
    uint32_t joint_len = side_len * side_len;
    uint32_t n_bits = size * 8U;
    uint32_t t = (n_bits + w - 1U) / w;
    uint32_t first_w = n_bits - ((t - 1U) * w);
    ecc_jpoint_t *table = NULL;
    ecc_jpoint_t *owned_table = NULL;
    ecc_jpoint_t R;
    ecc_jpoint_t T_sel;
    ecc_jpoint_t T_dbl;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    int use_cache = 0;
    uint32_t i;
    uint32_t j;
    uint32_t idx;

    memset(&R, 0, sizeof(R));
    memset(&T_sel, 0, sizeof(T_sel));
    memset(&T_dbl, 0, sizeof(T_dbl));
    R.size = T_sel.size = T_dbl.size = size;

    if(first_w == 0U) {
        first_w = w;
    }

#if (NOXTLS_ECC_POINT_MUL_WINDOW_SIZE > 0) && (NOXTLS_ECC_FIXED_POINT_OPTIM) && (NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE)
    if(s_muladd_cache.valid &&
       s_muladd_cache.curve == curve &&
       s_muladd_cache.w == w &&
       s_muladd_cache.size == size &&
       s_muladd_cache.table != NULL &&
       memcmp(s_muladd_cache.p1x, point1->x, size) == 0 &&
       memcmp(s_muladd_cache.p1y, point1->y, size) == 0 &&
       memcmp(s_muladd_cache.p2x, point2->x, size) == 0 &&
       memcmp(s_muladd_cache.p2y, point2->y, size) == 0) {
        table = s_muladd_cache.table;
        use_cache = 1;
    }
#endif

    if(table == NULL) {
        owned_table = (ecc_jpoint_t*)calloc(joint_len, sizeof(ecc_jpoint_t));
        if(owned_table == NULL) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }

        rc = p256_build_joint_precompute_table(owned_table, w, point1, point2, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            free(owned_table);
            return rc;
        }
        table = owned_table;

#if (NOXTLS_ECC_POINT_MUL_WINDOW_SIZE > 0) && (NOXTLS_ECC_FIXED_POINT_OPTIM) && (NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE)
        if(s_muladd_cache.table != NULL) {
            free(s_muladd_cache.table);
        }
        s_muladd_cache.curve = curve;
        s_muladd_cache.table = owned_table;
        s_muladd_cache.w = w;
        s_muladd_cache.size = size;
        memcpy(s_muladd_cache.p1x, point1->x, size);
        memcpy(s_muladd_cache.p1y, point1->y, size);
        memcpy(s_muladd_cache.p2x, point2->x, size);
        memcpy(s_muladd_cache.p2y, point2->y, size);
        s_muladd_cache.valid = 1;
        use_cache = 1;
        owned_table = NULL;
#endif
    }

    idx = (ecc_scalar_digit_range(scalar1, size, 0U, first_w) << w) |
          ecc_scalar_digit_range(scalar2, size, 0U, first_w);
    ecc_jpoint_select_affine_table(&T_sel, table, joint_len, size, idx);
    T_sel.size = size;
    memcpy(&R, &T_sel, sizeof(ecc_jpoint_t));

    for(i = 1U; i < t && rc == NOXTLS_RETURN_SUCCESS; i++) {
        for(j = 0U; j < w; j++) {
            rc = ecc_jpoint_double(&T_dbl, &R, curve);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                break;
            }
            memcpy(&R, &T_dbl, sizeof(ecc_jpoint_t));
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            break;
        }

        idx = (ecc_scalar_digit_range(scalar1, size, first_w + ((i - 1U) * w), w) << w) |
              ecc_scalar_digit_range(scalar2, size, first_w + ((i - 1U) * w), w);
        ecc_jpoint_select_affine_table(&T_sel, table, joint_len, size, idx);
        T_sel.size = size;
        rc = ecc_jpoint_add(&T_dbl, &R, &T_sel, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            break;
        }
        memcpy(&R, &T_dbl, sizeof(ecc_jpoint_t));
    }

    if(owned_table != NULL && !use_cache) {
        free(owned_table);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(ecc_jpoint_is_infinity(&R, size)) {
        noxtls_bn_zero(result->x, size);
        noxtls_bn_zero(result->y, size);
        result->size = size;
        return NOXTLS_RETURN_SUCCESS;
    }

    rc = ecc_jpoint_to_affine(result->x, result->y, &R, curve);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        result->size = size;
    } else {
        noxtls_bn_zero(result->x, size);
        noxtls_bn_zero(result->y, size);
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
    uint32_t size = curve->size;
    uint32_t n_bits = size * 8;
    uint32_t t = (n_bits + w - 1) / w;  /* number of windows */
    uint32_t first_w = n_bits - ((t - 1U) * w);
    uint32_t table_len = 1U << w;
    ecc_jpoint_t R;
    ecc_jpoint_t T_sel;
    ecc_jpoint_t T_dbl;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t i;
    uint32_t j;
    uint32_t d;

    memset(&R, 0, sizeof(R));
    memset(&T_sel, 0, sizeof(T_sel));
    memset(&T_dbl, 0, sizeof(T_dbl));
    R.size = T_sel.size = T_dbl.size = size;
    if(first_w == 0U) {
        first_w = w;
    }

    /* First window: R = T[d_0]. Constant-time select T[d_0] into T_sel. */
    d = ecc_scalar_digit_range(scalar, size, 0U, first_w);
    if(ecc_curve_is_secp256r1(curve)) {
        ecc_jpoint_select_affine_table(&T_sel, table, table_len, size, d);
        T_sel.size = size;
    } else {
        memcpy(&T_sel, &table[0], sizeof(ecc_jpoint_t));
        for(j = 1; j < table_len; j++) {
            ecc_jpoint_cond_select(&T_sel, &table[j], &T_sel, size, (uint8_t)(d == j));
        }
    }
    memcpy(&R, &T_sel, sizeof(ecc_jpoint_t));

    for(i = 1; i < t && rc == NOXTLS_RETURN_SUCCESS; i++) {
        /* R = 2^w * R (w doubles) */
        for(j = 0; j < w; j++) {
            rc = ecc_jpoint_double(&T_dbl, &R, curve);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            memcpy(&R, &T_dbl, sizeof(ecc_jpoint_t));
        }
        /* R = R + T[d_i] */
        d = ecc_scalar_digit_range(scalar, size, first_w + ((i - 1U) * w), w);
        if(ecc_curve_is_secp256r1(curve)) {
            ecc_jpoint_select_affine_table(&T_sel, table, table_len, size, d);
            T_sel.size = size;
        } else {
            memcpy(&T_sel, &table[0], sizeof(ecc_jpoint_t));
            for(j = 1; j < table_len; j++) {
                ecc_jpoint_cond_select(&T_sel, &table[j], &T_sel, size, (uint8_t)(d == j));
            }
        }
        rc = ecc_jpoint_add(&T_dbl, &R, &T_sel, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        memcpy(&R, &T_dbl, sizeof(ecc_jpoint_t));
    }

    memcpy(result, &R, sizeof(ecc_jpoint_t));
    result->size = size;
    return NOXTLS_RETURN_SUCCESS;
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
static noxtls_return_t ecc_point_mul_windowed(ecc_point_t *result, const uint8_t *scalar, const ecc_curve_params_t *curve,
                                               const ecc_jpoint_t *table, uint32_t w)
{
    ecc_jpoint_t R;
    noxtls_return_t rc;

    memset(&R, 0, sizeof(R));
    R.size = curve->size;

    rc = ecc_jpoint_mul_windowed(&R, scalar, curve, table, w);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = ecc_jpoint_to_affine(result->x, result->y, &R, curve);
    if(rc == NOXTLS_RETURN_SUCCESS) result->size = curve->size;
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
    uint32_t size = curve->size;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if(result == NULL || scalar == NULL || point == NULL || curve == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(size == 0U || size > ECC_MAX_KEY_SIZE) {
        return NOXTLS_RETURN_FAILED;
    }

    memset(result, 0, sizeof(*result));
    result->size = size;

    if(noxtls_bn_is_zero(scalar, size) || ecc_point_is_infinity(point, size)) {
        return NOXTLS_RETURN_SUCCESS;
    }

    if(noxtls_bn_is_one(scalar, size)) {
        noxtls_bn_copy(result->X, point->x, size);
        noxtls_bn_copy(result->Y, point->y, size);
        noxtls_bn_zero(result->Z, size);
        result->Z[size - 1U] = 0x01;
        return NOXTLS_RETURN_SUCCESS;
    }

#if NOXTLS_ECC_POINT_MUL_WINDOW_SIZE >= 2
    if(size != 66u && size != 64U) {
        const int is_fixed_base = ecc_point_equal(point, &curve->G, size);
        const uint32_t w = ecc_point_mul_window_size_for_curve(curve, is_fixed_base);
        uint32_t table_len = 1U << w;
        ecc_jpoint_t *table = NULL;
        int use_cache = 0;

#if NOXTLS_ECC_FIXED_POINT_OPTIM && NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE
        if(is_fixed_base && s_fixed_base_cache.valid && s_fixed_base_cache.curve == curve &&
           s_fixed_base_cache.w == w && s_fixed_base_cache.size == size &&
           s_fixed_base_cache.table != NULL &&
           memcmp(s_fixed_base_cache.gx, curve->G.x, size) == 0 &&
           memcmp(s_fixed_base_cache.gy, curve->G.y, size) == 0) {
            table = s_fixed_base_cache.table;
            use_cache = 1;
        } else if(s_point_cache.valid && s_point_cache.curve == curve &&
                  s_point_cache.w == w && s_point_cache.size == size &&
                  s_point_cache.table != NULL &&
                  memcmp(s_point_cache.gx, point->x, size) == 0 &&
                  memcmp(s_point_cache.gy, point->y, size) == 0) {
            table = s_point_cache.table;
            use_cache = 1;
        }
#endif
        if(!use_cache) {
            table = (ecc_jpoint_t*)calloc(table_len, sizeof(ecc_jpoint_t));
            if(table) {
                if(ecc_curve_is_secp256r1(curve)) {
                    rc = p256_build_comb_precompute_table(table, table_len, point, curve, w, (256u + w - 1U) / w);
                } else {
                    rc = ecc_build_precompute_table(table, table_len, point, curve);
                }
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    free(table);
                    table = NULL;
                }
#if NOXTLS_ECC_FIXED_POINT_OPTIM && NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE
                else if(is_fixed_base) {
                    if(s_fixed_base_cache.table) free(s_fixed_base_cache.table);
                    s_fixed_base_cache.curve = curve;
                    s_fixed_base_cache.table = table;
                    s_fixed_base_cache.w = w;
                    s_fixed_base_cache.size = size;
                    memcpy(s_fixed_base_cache.gx, curve->G.x, size);
                    memcpy(s_fixed_base_cache.gy, curve->G.y, size);
                    s_fixed_base_cache.valid = 1;
                    use_cache = 1;
                } else {
                    if(s_point_cache.table) free(s_point_cache.table);
                    s_point_cache.curve = curve;
                    s_point_cache.table = table;
                    s_point_cache.w = w;
                    s_point_cache.size = size;
                    memcpy(s_point_cache.gx, point->x, size);
                    memcpy(s_point_cache.gy, point->y, size);
                    s_point_cache.valid = 1;
                    use_cache = 1;
                }
#endif
            }
        }
        if(table) {
            if(ecc_curve_is_secp256r1(curve)) {
                rc = p256_ecc_jpoint_mul_comb(result, scalar, curve, table, w);
            } else {
                rc = ecc_jpoint_mul_windowed(result, scalar, curve, table, w);
            }
#if !(NOXTLS_ECC_FIXED_POINT_OPTIM && NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE)
            free(table);
#else
            if(!use_cache) free(table);
#endif
            if(rc == NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
        }
    }
#endif

    {
        ecc_point_t affine;

        noxtls_ecc_point_init(&affine, size);
        rc = noxtls_ecc_point_multiply(&affine, scalar, point, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if(ecc_point_is_infinity(&affine, size)) {
            return NOXTLS_RETURN_SUCCESS;
        }
        noxtls_bn_copy(result->X, affine.x, size);
        noxtls_bn_copy(result->Y, affine.y, size);
        noxtls_bn_zero(result->Z, size);
        result->Z[size - 1U] = 0x01;
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
    /* Check for null pointers BEFORE accessing any fields */
    if(result == NULL || scalar == NULL || point == NULL || curve == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    uint32_t size = curve->size;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    noxtls_bn_zero(result->x, size);
    noxtls_bn_zero(result->y, size);
    result->size = size;

    if(noxtls_bn_is_zero(scalar, size)) {
        return NOXTLS_RETURN_SUCCESS;
    }
    /* 1*P = P: avoid full scalar loop for key gen and any 1*point case */
    if(noxtls_bn_is_one(scalar, size)) {
        memcpy(result->x, point->x, size);
        memcpy(result->y, point->y, size);
        return NOXTLS_RETURN_SUCCESS;
    }

    rc = noxtls_ecc_point_multiply_accel_port(result, scalar, point, curve);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    /* HW failed or disabled: fall back to software path. */
    if(rc != NOXTLS_RETURN_NOT_SUPPORTED) {
        noxtls_bn_zero(result->x, size);
        noxtls_bn_zero(result->y, size);
    }
    rc = NOXTLS_RETURN_SUCCESS;

#if NOXTLS_ECC_POINT_MUL_WINDOW_SIZE >= 2
    /*
     * secp521r1 (66-byte coordinates) and brainpoolP512r1 (64-byte coordinates):
     * windowed / fixed-base precomputation has produced incorrect points in TLS 1.3
     * ECDSA CertificateVerify interop; use the Montgomery ladder only for these sizes.
     */
    if(size != 66u && size != 64U) {
        {
            const int is_fixed_base = ecc_point_equal(point, &curve->G, size);
            const uint32_t w = ecc_point_mul_window_size_for_curve(curve, is_fixed_base);
            uint32_t table_len = 1U << w;
            ecc_jpoint_t *table = NULL;
            int use_cache = 0;

#if NOXTLS_ECC_FIXED_POINT_OPTIM && NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE
            if(is_fixed_base && s_fixed_base_cache.valid && s_fixed_base_cache.curve == curve &&
                s_fixed_base_cache.w == w && s_fixed_base_cache.size == size &&
                s_fixed_base_cache.table != NULL &&
                memcmp(s_fixed_base_cache.gx, curve->G.x, size) == 0 &&
                memcmp(s_fixed_base_cache.gy, curve->G.y, size) == 0) {
                table = s_fixed_base_cache.table;
                use_cache = 1;
            } else if(s_point_cache.valid && s_point_cache.curve == curve &&
                      s_point_cache.w == w && s_point_cache.size == size &&
                      s_point_cache.table != NULL &&
                      memcmp(s_point_cache.gx, point->x, size) == 0 &&
                      memcmp(s_point_cache.gy, point->y, size) == 0) {
                table = s_point_cache.table;
                use_cache = 1;
            }
#endif
            if(!use_cache) {
                table = (ecc_jpoint_t*)calloc(table_len, sizeof(ecc_jpoint_t));
                if(table) {
                    if(ecc_curve_is_secp256r1(curve)) {
                        rc = p256_build_comb_precompute_table(table, table_len, point, curve, w, (256u + w - 1U) / w);
                    } else {
                        rc = ecc_build_precompute_table(table, table_len, point, curve);
                    }
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        free(table);
                        table = NULL;
                    }
#if NOXTLS_ECC_FIXED_POINT_OPTIM && NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE
                    else if(is_fixed_base) {
                        /* Evict previous cache */
                        if(s_fixed_base_cache.table) free(s_fixed_base_cache.table);
                        s_fixed_base_cache.curve = curve;
                        s_fixed_base_cache.table = table;
                        s_fixed_base_cache.w = w;
                        s_fixed_base_cache.size = size;
                        memcpy(s_fixed_base_cache.gx, curve->G.x, size);
                        memcpy(s_fixed_base_cache.gy, curve->G.y, size);
                        s_fixed_base_cache.valid = 1;
                        use_cache = 1;  /* don't free table below */
                    }
                    else {
                        if(s_point_cache.table) free(s_point_cache.table);
                        s_point_cache.curve = curve;
                        s_point_cache.table = table;
                        s_point_cache.w = w;
                        s_point_cache.size = size;
                        memcpy(s_point_cache.gx, point->x, size);
                        memcpy(s_point_cache.gy, point->y, size);
                        s_point_cache.valid = 1;
                        use_cache = 1;  /* don't free table below */
                    }
#endif
                }
            }
            if(table) {
                if(ecc_curve_is_secp256r1(curve)) {
                    rc = p256_ecc_point_mul_comb(result, scalar, curve, table, w);
                } else {
                    rc = ecc_point_mul_windowed(result, scalar, curve, table, w);
                }
#if !(NOXTLS_ECC_FIXED_POINT_OPTIM && NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE)
                free(table);
#else
                if(!use_cache) free(table);
#endif
                if(rc == NOXTLS_RETURN_SUCCESS) return rc;
                /* Fall through to ladder on failure (e.g. add returned failure) */
                noxtls_bn_zero(result->x, size);
                noxtls_bn_zero(result->y, size);
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
        uint32_t i;
        uint32_t j;
        uint8_t bit;

        memset(&R0, 0, sizeof(R0));
        memset(&R1, 0, sizeof(R1));
        memset(&T_sum, 0, sizeof(T_sum));
        memset(&T_dbl0, 0, sizeof(T_dbl0));
        memset(&T_dbl1, 0, sizeof(T_dbl1));

        R0.size = R1.size = size;
        T_sum.size = T_dbl0.size = T_dbl1.size = size;

        noxtls_bn_zero(R0.X, size);
        noxtls_bn_zero(R0.Y, size);
        noxtls_bn_zero(R0.Z, size);
        noxtls_bn_copy(R1.X, point->x, size);
        noxtls_bn_copy(R1.Y, point->y, size);
        noxtls_bn_zero(R1.Z, size);
        R1.Z[size - 1] = 0x01;

        for(i = 0; i < size && rc == NOXTLS_RETURN_SUCCESS; i++) {
            for(j = 8; j > 0; j--) {
                bit = (scalar[i] >> (j - 1)) & 1;
                rc = ecc_jpoint_add(&T_sum, &R0, &R1, curve);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    break;
                }
                rc = ecc_jpoint_double(&T_dbl0, &R0, curve);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    break;
                }
                rc = ecc_jpoint_double(&T_dbl1, &R1, curve);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    break;
                }
                ecc_cond_select(R0.X, T_sum.X, T_dbl0.X, size, bit);
                ecc_cond_select(R0.Y, T_sum.Y, T_dbl0.Y, size, bit);
                ecc_cond_select(R0.Z, T_sum.Z, T_dbl0.Z, size, bit);
                ecc_cond_select(R1.X, T_dbl1.X, T_sum.X, size, bit);
                ecc_cond_select(R1.Y, T_dbl1.Y, T_sum.Y, size, bit);
                ecc_cond_select(R1.Z, T_dbl1.Z, T_sum.Z, size, bit);
            }
        }

        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_bn_zero(result->x, size);
            noxtls_bn_zero(result->y, size);
            return rc;
        }

        rc = ecc_jpoint_to_affine(result->x, result->y, &R0, curve);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_bn_zero(result->x, size);
        noxtls_bn_zero(result->y, size);
        return rc;
    }
    result->size = size;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Joint scalar multiplication: R = k1*P1 + k2*P2
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
    uint32_t size;
    uint32_t n_bits;
    uint32_t i;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if(result == NULL || scalar1 == NULL || point1 == NULL || scalar2 == NULL || point2 == NULL || curve == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    size = curve->size;
    if(size == 0U || size > ECC_MAX_KEY_SIZE) {
        return NOXTLS_RETURN_FAILED;
    }
    if(point1->size != size || point2->size != size) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    noxtls_bn_zero(result->x, size);
    noxtls_bn_zero(result->y, size);
    result->size = size;

    if(noxtls_bn_is_zero(scalar1, size) && noxtls_bn_is_zero(scalar2, size)) {
        return NOXTLS_RETURN_SUCCESS;
    }
    if(noxtls_bn_is_zero(scalar1, size)) {
        return noxtls_ecc_point_multiply(result, scalar2, point2, curve);
    }
    if(noxtls_bn_is_zero(scalar2, size)) {
        return noxtls_ecc_point_multiply(result, scalar1, point1, curve);
    }

    memset(&R, 0, sizeof(R));
    memset(&J1, 0, sizeof(J1));
    memset(&J2, 0, sizeof(J2));
    memset(&J12, 0, sizeof(J12));
    memset(&T, 0, sizeof(T));
    R.size = J1.size = J2.size = J12.size = T.size = size;

    /* R = infinity */
    noxtls_bn_zero(R.X, size);
    noxtls_bn_zero(R.Y, size);
    noxtls_bn_zero(R.Z, size);

    /* J1 <- P1 (affine to Jacobian) */
    noxtls_bn_copy(J1.X, point1->x, size);
    noxtls_bn_copy(J1.Y, point1->y, size);
    noxtls_bn_zero(J1.Z, size);
    if(!ecc_point_is_infinity(point1, size)) {
        J1.Z[size - 1] = 0x01;
    }

    /* J2 <- P2 (affine to Jacobian) */
    noxtls_bn_copy(J2.X, point2->x, size);
    noxtls_bn_copy(J2.Y, point2->y, size);
    noxtls_bn_zero(J2.Z, size);
    if(!ecc_point_is_infinity(point2, size)) {
        J2.Z[size - 1] = 0x01;
    }

    if(size > (UINT32_MAX / 8U)) {
        return NOXTLS_RETURN_FAILED;
    }
    n_bits = size * 8U;
    if(size == 32U) {
#if NOXTLS_ECC_POINT_MUL_WINDOW_SIZE > 0
        rc = p256_ecc_point_muladd_windowed(result, scalar1, point1, scalar2, point2, curve);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        if(rc != NOXTLS_RETURN_NOT_ENOUGH_MEMORY) {
            return rc;
        }
#endif

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

        if(!ecc_jpoint_is_infinity(&J2, size)) {
            rc = ecc_jpoint_to_affine(J2.X, J2.Y, &J2, curve);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            noxtls_bn_zero(J2.Z, size);
            J2.Z[size - 1U] = 0x01;
        }

        rc = ecc_jpoint_add(&R, &J1, &J2, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    } else {
        /* Generic path: 1-bit Shamir trick. */
        if(ecc_jpoint_is_infinity(&J1, size)) {
            memcpy(&J12, &J2, sizeof(ecc_jpoint_t));
        } else if(ecc_jpoint_is_infinity(&J2, size)) {
            memcpy(&J12, &J1, sizeof(ecc_jpoint_t));
        } else if(ecc_point_equal(point1, point2, size)) {
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

        for(i = 0; i < n_bits; i++) {
            uint8_t b1;
            uint8_t b2;
            const ecc_jpoint_t *A = NULL;

            rc = ecc_jpoint_double(&T, &R, curve);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            memcpy(&R, &T, sizeof(ecc_jpoint_t));

            b1 = ecc_scalar_getbit(scalar1, size, i);
            b2 = ecc_scalar_getbit(scalar2, size, i);
            if(b1 == 0U && b2 == 0U) {
                continue;
            }
            if(b1 && b2) {
                A = &J12;
            } else if(b1) {
                A = &J1;
            } else {
                A = &J2;
            }

            if(ecc_jpoint_is_infinity(A, size)) {
                continue;
            }
            if(ecc_jpoint_is_infinity(&R, size)) {
                memcpy(&R, A, sizeof(ecc_jpoint_t));
                continue;
            }
            rc = ecc_jpoint_add(&T, &R, A, curve);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
            memcpy(&R, &T, sizeof(ecc_jpoint_t));
        }
    }

    if(ecc_jpoint_is_infinity(&R, size)) {
        noxtls_bn_zero(result->x, size);
        noxtls_bn_zero(result->y, size);
        result->size = size;
        return NOXTLS_RETURN_SUCCESS;
    }

    rc = ecc_jpoint_to_affine(result->x, result->y, &R, curve);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        result->size = size;
    } else {
        noxtls_bn_zero(result->x, size);
        noxtls_bn_zero(result->y, size);
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
    uint8_t *left = NULL;
    uint8_t *right = NULL;
    uint8_t *temp1 = NULL;
    uint8_t *temp2 = NULL;
    uint32_t size;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    if(point == NULL || curve == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    size = curve->size;
    if(size == 0U || size > (uint32_t)(UINT32_MAX / 2U)) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Allocate temporary buffers */
    left = (uint8_t*)calloc(size, 1);
    right = (uint8_t*)calloc(size, 1);
    temp1 = (uint8_t*)calloc((size_t)size * 2U, 1);
    temp2 = (uint8_t*)calloc((size_t)size * 2U, 1);
    
    do {
        if(!left || !right || !temp1 || !temp2) {
            rc = NOXTLS_RETURN_FAILED;
            goto cleanup_curve;
        }
        
        /* Check if point is at infinity */
        if(ecc_point_is_infinity(point, size)) {
            rc = NOXTLS_RETURN_SUCCESS;  /* Point at infinity is valid */
            goto cleanup_curve;
        }
        
        /* Compute left side: y^2 mod p */
        noxtls_bn_mul(temp1, point->y, size, point->y, size);
        noxtls_bn_mod(left, temp1, size * 2, curve->p, size);
        
        /* Compute right side: x^3 + ax + b mod p (use curve->a so it matches add/double) */
        noxtls_bn_mul(temp1, point->x, size, point->x, size);
        noxtls_bn_mod(temp1, temp1, size * 2, curve->p, size);
        noxtls_bn_mul(temp2, temp1, size, point->x, size);
        noxtls_bn_mod(temp2, temp2, size * 2, curve->p, size);
        noxtls_bn_mul(temp1, curve->a, size, point->x, size);
        noxtls_bn_mod(temp1, temp1, size * 2, curve->p, size);
        ecc_mod_add(temp2, temp2, temp1, curve->p, size);
        ecc_mod_add(right, temp2, curve->b, curve->p, size);
        
        /* Compare left and right sides */
        if(noxtls_bn_cmp(left, right, size) == 0) {
            rc = NOXTLS_RETURN_SUCCESS;
        } else {
            rc = NOXTLS_RETURN_FAILED;
        }

    } while(0);

cleanup_curve:
    if(left) free(left);
    if(right) free(right);
    if(temp1) free(temp1);
    if(temp2) free(temp2);

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
    noxtls_return_t rc;

    if(point == NULL || curve == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(point->size != curve->size || curve->size == 0U || curve->size > ECC_MAX_KEY_SIZE) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(ecc_point_is_infinity(point, curve->size)) {
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
    if(key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    memset(key, 0, sizeof(ecc_key_t));
    
    key->curve = (ecc_curve_params_t*)malloc(sizeof(ecc_curve_params_t));
    if(key->curve == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    noxtls_return_t rc = noxtls_ecc_curve_init(key->curve, curve_type);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(key->curve);
        key->curve = NULL;
        return rc;
    }
    key->curve_kind = curve_type;

    key->d = (uint8_t*)calloc(key->curve->size, 1);
    if(key->d == NULL) {
        noxtls_ecc_curve_free(key->curve);
        free(key->curve);
        key->curve = NULL;
        return NOXTLS_RETURN_FAILED;
    }
    
    noxtls_ecc_point_init(&key->Q, key->curve->size);
    
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
    uint8_t *random_bytes = NULL;
    uint32_t size;
    uint32_t bits;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    
    if(key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    rc = noxtls_ecc_key_init(key, curve_type);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    size = key->curve->size;
    if(size == 0U || size > (uint32_t)(UINT32_MAX / 8U)) {
        rc = NOXTLS_RETURN_FAILED;
        goto cleanup_keygen;
    }
    bits = size * 8U;
    
    /* Allocate buffers */
    random_bytes = (uint8_t*)calloc(size, 1);
    do {
        if(!random_bytes) {
            rc = NOXTLS_RETURN_FAILED;
            break;
        }

        /* Generate private key d in range [1, n-1] */
        /* Generate random private key */
        do {
            rc = ecc_keygen_drbg_generate_bits(random_bytes, bits);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                break;
            }
            
            /* Ensure d is in range [1, n-1] by reducing mod (n-1) and adding 1 */
            /* First, reduce mod n (which gives [0, n-1]) */
            noxtls_bn_mod(key->d, random_bytes, size, key->curve->n, size);
            
            /* If d is zero, set to 1 */
            if(noxtls_bn_is_zero(key->d, size)) {
                noxtls_bn_one(key->d, size);
            }
            
            /* Ensure d < n (should already be true after mod, but check anyway) */
        } while(noxtls_bn_cmp(key->d, key->curve->n, size) >= 0 || noxtls_bn_is_zero(key->d, size));
        
        if(rc != NOXTLS_RETURN_SUCCESS) {
            break;
        }
        
        /* Compute public key Q = d * G */
        /* This is the expensive operation - scalar multiplication */
    rc = noxtls_ecc_point_multiply(&key->Q, key->d, &key->curve->G, key->curve);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup_keygen;
    }

    } while(0);

    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup_keygen;
    }

    /* Verify the generated public key is on the curve */
    rc = noxtls_ecc_point_is_on_curve(&key->Q, key->curve);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup_keygen;
    }

cleanup_keygen:
    if(random_bytes) free(random_bytes);

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
    
    if(key->d) {
        memset(key->d, 0, key->curve ? key->curve->size : ECC_MAX_KEY_SIZE);
        free(key->d);
        key->d = NULL;
    }
    
    if(key->curve) {
        noxtls_ecc_curve_free(key->curve);
        free(key->curve);
        key->curve = NULL;
    }
    /* Do not memset(key, 0, sizeof(ecc_key_t)): key may be on the caller's stack and
     * sizeof(ecc_key_t) can differ between translation units (e.g. C vs C++), which
     * can corrupt the stack and crash when the test returns. */
    return NOXTLS_RETURN_SUCCESS;
}
