/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
* 
*
* File:    noxtls_ecc.c
* Summary: Elliptic Curve Cryptography (ECC) Base Implementation
*
*/

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

#if (NOXTLS_ECC_POINT_MUL_WINDOW_SIZE > 0) && (NOXTLS_ECC_FIXED_POINT_OPTIM)
static ecc_fixed_base_cache_t s_fixed_base_cache = { NULL, NULL, 0, 0 };
#endif

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
    if(!p_minus_2 || !two || !a_mod) {
        if(p_minus_2) free(p_minus_2);
        if(two) free(two);
        if(a_mod) free(a_mod);
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
    noxtls_bn_copy(p_minus_2, p, size);
    noxtls_bn_sub(p_minus_2, p_minus_2, two, size);

    noxtls_bn_mod_exp(result, a_mod, p_minus_2, size, p, size);

    free(p_minus_2);
    free(two);
    free(a_mod);
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

/** Return configured window size (0 = ladder only, 2+ = windowed precomputation). */
int noxtls_ecc_point_mul_window_size(void)
{
#if NOXTLS_ECC_POINT_MUL_WINDOW_SIZE >= 2
    return (int)NOXTLS_ECC_POINT_MUL_WINDOW_SIZE;
#else
    return 0;
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
        case ECC_SECP192R1:
            curve->size = 24;  /* 192 bits = 24 bytes */
            break;
        case ECC_SECP224R1:
            curve->size = 28;  /* 224 bits = 28 bytes */
            break;
        case ECC_SECP256R1:
            curve->size = 32;  /* 256 bits = 32 bytes */
            break;
        case ECC_SECP384R1:
            curve->size = 48;  /* 384 bits = 48 bytes */
            break;
        case ECC_SECP521R1:
            curve->size = 66;  /* 521 bits = 66 bytes */
            break;
        case ECC_BP256R1:
            curve->size = 32;  /* 256 bits = 32 bytes */
            break;
        case ECC_BP384R1:
            curve->size = 48;  /* 384 bits = 48 bytes */
            break;
        case ECC_BP512R1:
            curve->size = 64;  /* 512 bits = 64 bytes */
            break;
        case ECC_SECP192K1:
            curve->size = 24;  /* 192 bits = 24 bytes */
            break;
        case ECC_SECP224K1:
            curve->size = 28;  /* 224 bits = 28 bytes */
            break;
        case ECC_SECP256K1:
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
        case ECC_SECP192R1: {
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
        case ECC_SECP224R1: {
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
        case ECC_SECP256R1: {
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
        case ECC_SECP384R1:
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
        case ECC_SECP521R1:
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
        case ECC_BP256R1:
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
        case ECC_BP384R1:
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
        case ECC_BP512R1:
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
        case ECC_SECP192K1:
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
        case ECC_SECP224K1:
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
        case ECC_SECP256K1:
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

#if (NOXTLS_ECC_POINT_MUL_WINDOW_SIZE > 0) && (NOXTLS_ECC_FIXED_POINT_OPTIM)
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

/* Helper: Check if point is at infinity (zero point) */
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

/** Extract w-bit digit at window index win (0 = MSB window). */
/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static uint32_t ecc_scalar_digit(const uint8_t *scalar, uint32_t size_bytes, uint32_t w, uint32_t win)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    uint32_t n_bits;
    uint32_t start_bit = win * w;
    uint32_t d = 0;
    uint32_t b;
    if(size_bytes > (uint32_t)(UINT32_MAX / 8u)) return 0;
    n_bits = size_bytes * 8u;
    if(start_bit >= n_bits) return 0;
    for(b = 0; b < w && (start_bit + b) < n_bits; b++) {
        d = (d << 1) | ecc_scalar_getbit(scalar, size_bytes, start_bit + b);
    }
    return d;
}

/* NOLINTBEGIN(bugprone-easily-swappable-parameters) */
static void ecc_mod_add(uint8_t *out, const uint8_t *a, const uint8_t *b, const uint8_t *p, uint32_t size);
/* NOLINTEND(bugprone-easily-swappable-parameters) */

/**
 * @brief Compute (a - b) mod p (big-endian)
 *
 * Uses (a - b) mod p = (a + (p - b)) mod p when a < b to avoid unsigned wrap handling.
 */
static void ecc_mod_sub(uint8_t *out, const uint8_t *a, const uint8_t *b, const uint8_t *p, uint32_t size)
{
    if(noxtls_bn_cmp(a, b, size) >= 0) {
        noxtls_bn_sub(out, a, b, size);
        if(noxtls_bn_cmp(out, p, size) >= 0)
            noxtls_bn_mod(out, out, size, p, size);
    } else {
        uint8_t *p_minus_b = (uint8_t*)calloc(size, 1);
        if(p_minus_b) {
            noxtls_bn_sub(p_minus_b, p, b, size);  /* p >= b, so p_minus_b = p - b */
            noxtls_bn_mod(p_minus_b, p_minus_b, size, p, size);
            ecc_mod_add(out, a, p_minus_b, p, size);  /* (a - b) mod p = a + (p - b) mod p */
            free(p_minus_b);
        } else {
            noxtls_bn_zero(out, size);
        }
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
    if(size == UINT32_MAX) {
        return;
    }
    uint8_t *tmp = (uint8_t*)calloc(size + 1, 1);
    if(!tmp) {
        noxtls_bn_zero(out, size);
        return;
    }

    uint16_t carry = 0;
    for(uint32_t i = size; i > 0; i--) {
        uint16_t sum = (uint16_t)a[i - 1] + (uint16_t)b[i - 1] + carry;
        tmp[i] = (uint8_t)(sum & 0xFF);
        carry = sum >> 8;
    }
    tmp[0] = (uint8_t)carry;

    noxtls_bn_mod(out, tmp, size + 1, p, size);
    free(tmp);
}

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
    uint8_t *t1 = NULL;
    uint8_t *t2 = NULL;
    uint8_t *t3 = NULL;
    uint8_t *S = NULL;
    uint8_t *M = NULL;
    static const uint8_t two_arr[1] = {0x02};
    static const uint8_t three_arr[1] = {0x03};
    static const uint8_t four_arr[1] = {0x04};
    static const uint8_t eight_arr[1] = {0x08};
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    if(size == 0u || size > (uint32_t)(UINT32_MAX / 2u) || size == UINT32_MAX) {
        return NOXTLS_RETURN_FAILED;
    }

    if(ecc_jpoint_is_infinity(P, size)) {
        noxtls_bn_zero(out->X, size);
        noxtls_bn_zero(out->Y, size);
        noxtls_bn_zero(out->Z, size);
        out->size = size;
        return NOXTLS_RETURN_SUCCESS;
    }

    t1 = (uint8_t*)calloc((size_t)size * 2u, 1);
    t2 = (uint8_t*)calloc((size_t)size * 2u, 1);
    t3 = (uint8_t*)calloc((size_t)size * 2u, 1);
    S  = (uint8_t*)calloc(size, 1);
    M  = (uint8_t*)calloc(size, 1);
    if(!t1 || !t2 || !t3 || !S || !M) {
        rc = NOXTLS_RETURN_FAILED;
        goto cleanup_double;
    }

    /* S = 4*X1*Y1^2 mod p */
        noxtls_bn_mul(t1, P->Y, size, P->Y, size);
        noxtls_bn_mod(t2, t1, size * 2, p, size);
        noxtls_bn_mul(t1, P->X, size, t2, size);
        noxtls_bn_mod(t2, t1, size * 2, p, size);
        noxtls_bn_mul(t1, t2, size, four_arr, 1);
        noxtls_bn_mod(S, t1, size + 1, p, size);

        /* M = 3*X1^2 + a*Z1^4 mod p */
        noxtls_bn_mul(t1, P->X, size, P->X, size);
        noxtls_bn_mod(t2, t1, size * 2, p, size);
        noxtls_bn_mul(t1, t2, size, three_arr, 1);
        noxtls_bn_mod(t2, t1, size + 1, p, size);
        noxtls_bn_mul(t1, P->Z, size, P->Z, size);
        noxtls_bn_mod(t3, t1, size * 2, p, size);
        noxtls_bn_mul(t1, t3, size, t3, size);
        noxtls_bn_mod(t3, t1, size * 2, p, size);
        noxtls_bn_mul(t1, a, size, t3, size);
        noxtls_bn_mod(t3, t1, size * 2, p, size);
        ecc_mod_add(M, t2, t3, p, size);

        /* X3 = M^2 - 2*S mod p */
        noxtls_bn_mul(t1, M, size, M, size);
        noxtls_bn_mod(t2, t1, size * 2, p, size);
        noxtls_bn_mul(t1, S, size, two_arr, 1);
        noxtls_bn_mod(t3, t1, size + 1, p, size);
        ecc_mod_sub(out->X, t2, t3, p, size);

        /* Y3 = M*(S - X3) - 8*Y1^4 mod p */
        ecc_mod_sub(t2, S, out->X, p, size);
        noxtls_bn_mul(t1, M, size, t2, size);
        noxtls_bn_mod(t2, t1, size * 2, p, size);
        noxtls_bn_mul(t1, P->Y, size, P->Y, size);
        noxtls_bn_mod(t3, t1, size * 2, p, size);
        noxtls_bn_mul(t1, t3, size, t3, size);
        noxtls_bn_mod(t3, t1, size * 2, p, size);
        noxtls_bn_mul(t1, t3, size, eight_arr, 1);
        noxtls_bn_mod(t3, t1, size + 1, p, size);
        ecc_mod_sub(out->Y, t2, t3, p, size);

        /* Z3 = 2*Y1*Z1 mod p */
        noxtls_bn_mul(t1, P->Y, size, P->Z, size);
        noxtls_bn_mod(t2, t1, size * 2, p, size);
        noxtls_bn_mul(t1, t2, size, two_arr, 1);
        noxtls_bn_mod(out->Z, t1, size + 1, p, size);

        out->size = size;

cleanup_double:
    if(t1) free(t1);
    if(t2) free(t2);
    if(t3) free(t3);
    if(S)  free(S);
    if(M)  free(M);
    return rc;
}

/* Jacobian add: out = P + Q. No inversion. Handles identity and P==Q is invalid (use double). */
static noxtls_return_t ecc_jpoint_add(ecc_jpoint_t *out, const ecc_jpoint_t *P, const ecc_jpoint_t *Q, const ecc_curve_params_t *curve)
{
    uint32_t size = curve->size;
    const uint8_t *p = curve->p;
    uint8_t *U1 = NULL;
    uint8_t *U2 = NULL;
    uint8_t *S1 = NULL;
    uint8_t *S2 = NULL;
    uint8_t *H = NULL;
    uint8_t *R = NULL;
    uint8_t *t1 = NULL;
    uint8_t *t2 = NULL;
    uint8_t *t3 = NULL;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    if(size == 0u || size > (uint32_t)(UINT32_MAX / 2u)) {
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

    U1 = (uint8_t*)calloc(size, 1);
    U2 = (uint8_t*)calloc(size, 1);
    S1 = (uint8_t*)calloc(size, 1);
    S2 = (uint8_t*)calloc(size, 1);
    H  = (uint8_t*)calloc(size, 1);
    R  = (uint8_t*)calloc(size, 1);
    t1 = (uint8_t*)calloc((size_t)size * 2u, 1);
    t2 = (uint8_t*)calloc((size_t)size * 2u, 1);
    t3 = (uint8_t*)calloc((size_t)size * 2u, 1);
    do {
        if(!U1 || !U2 || !S1 || !S2 || !H || !R || !t1 || !t2 || !t3) {
            rc = NOXTLS_RETURN_FAILED;
            break;
        }

        /* Z1^2, Z2^2 */
        noxtls_bn_mul(t1, P->Z, size, P->Z, size);
        noxtls_bn_mod(t2, t1, size * 2, p, size);
        noxtls_bn_mul(t1, Q->Z, size, Q->Z, size);
        noxtls_bn_mod(t3, t1, size * 2, p, size);
        /* U1 = X1*Z2^2, U2 = X2*Z1^2 */
        noxtls_bn_mul(t1, P->X, size, t3, size);
        noxtls_bn_mod(U1, t1, size * 2, p, size);
        noxtls_bn_mul(t1, Q->X, size, t2, size);
        noxtls_bn_mod(U2, t1, size * 2, p, size);
        /* Z2^3 = Z2^2*Z2, Z1^3 = Z1^2*Z1 */
        noxtls_bn_mul(t1, t3, size, Q->Z, size);
        noxtls_bn_mod(t3, t1, size * 2, p, size);
        noxtls_bn_mul(t1, t2, size, P->Z, size);
        noxtls_bn_mod(t2, t1, size * 2, p, size);
        /* S1 = Y1*Z2^3, S2 = Y2*Z1^3 */
        noxtls_bn_mul(t1, P->Y, size, t3, size);
        noxtls_bn_mod(S1, t1, size * 2, p, size);
        noxtls_bn_mul(t1, Q->Y, size, t2, size);
        noxtls_bn_mod(S2, t1, size * 2, p, size);

        /* H = U2 - U1, R = S2 - S1 */
        ecc_mod_sub(H, U2, U1, p, size);
        ecc_mod_sub(R, S2, S1, p, size);

        if(noxtls_bn_is_zero(H, size)) {
            /* P == Q or P == -Q. Caller must not use add for doubling. */
            if(noxtls_bn_is_zero(R, size)) {
                rc = NOXTLS_RETURN_FAILED; /* would be doubling */
            } else {
                noxtls_bn_zero(out->X, size);
                noxtls_bn_zero(out->Y, size);
                noxtls_bn_zero(out->Z, size);
                out->size = size; /* infinity */
            }
            goto cleanup_add;
        }

        /* X3 = R^2 - H^3 - 2*U1*H^2; also keep U1*H^2 and H^3 for Y3 */
        noxtls_bn_mul(t1, H, size, H, size);
        noxtls_bn_mod(t2, t1, size * 2, p, size);   /* t2 = H^2 */
        noxtls_bn_mul(t1, t2, size, H, size);
        noxtls_bn_mod(t3, t1, size * 2, p, size);   /* t3 = H^3 */
        noxtls_bn_mul(t1, R, size, R, size);
        noxtls_bn_mod(t2, t1, size * 2, p, size);   /* t2 = R^2 */
        ecc_mod_sub(t2, t2, t3, p, size);             /* t2 = R^2 - H^3 */
        noxtls_bn_mul(t1, U1, size, H, size);
        noxtls_bn_mod(t3, t1, size * 2, p, size);
        noxtls_bn_mul(t1, t3, size, H, size);
        noxtls_bn_mod(t3, t1, size * 2, p, size);   /* t3 = U1*H^2 */
        {
            const uint8_t two_arr[1] = {0x02};
            noxtls_bn_mul(t1, t3, size, two_arr, 1);
            noxtls_bn_mod(t1, t1, size + 1, p, size);
            ecc_mod_sub(out->X, t2, t1, p, size);
        }
        /* Y3 = R*(U1*H^2 - X3) - S1*H^3; t3 = U1*H^2, need H^3 again */
        ecc_mod_sub(t2, t3, out->X, p, size);         /* t2 = U1*H^2 - X3 */
        noxtls_bn_mul(t1, R, size, t2, size);
        noxtls_bn_mod(t2, t1, size * 2, p, size);   /* t2 = R*(U1*H^2 - X3) */
        noxtls_bn_mul(t1, H, size, H, size);
        noxtls_bn_mod(t3, t1, size * 2, p, size);
        noxtls_bn_mul(t1, t3, size, H, size);
        noxtls_bn_mod(t3, t1, size * 2, p, size);   /* t3 = H^3 */
        noxtls_bn_mul(t1, S1, size, t3, size);
        noxtls_bn_mod(t3, t1, size * 2, p, size);
        ecc_mod_sub(out->Y, t2, t3, p, size);

        /* Z3 = Z1*Z2*H */
        noxtls_bn_mul(t1, P->Z, size, Q->Z, size);
        noxtls_bn_mod(t2, t1, size * 2, p, size);
        noxtls_bn_mul(t1, t2, size, H, size);
        noxtls_bn_mod(out->Z, t1, size * 2, p, size);
        out->size = size;
        rc = NOXTLS_RETURN_SUCCESS;

    } while(0);

cleanup_add:
    if(U1) free(U1);
    if(U2) free(U2);
    if(S1) free(S1);
    if(S2) free(S2);
    if(H)  free(H);
    if(R)  free(R);
    if(t1) free(t1);
    if(t2) free(t2);
    if(t3) free(t3);
    return rc;
}

static noxtls_return_t ecc_jpoint_to_affine(uint8_t *x, uint8_t *y, const ecc_jpoint_t *J, const ecc_curve_params_t *curve);

/**
 * @brief ECC Point Addition: R = P + Q
 * 
 * Uses chord-tangent method for P != Q, or point doubling for P == Q
 */
noxtls_return_t noxtls_ecc_point_add(ecc_point_t *result, const ecc_point_t *p1, const ecc_point_t *p2, const ecc_curve_params_t *curve)
{
    uint8_t *lambda = NULL;
    uint8_t *x3 = NULL;
    uint8_t *y3 = NULL;
    uint8_t *temp1 = NULL;
    uint8_t *temp2 = NULL;
    uint8_t *temp3 = NULL;
    uint32_t size;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    
    if(result == NULL || p1 == NULL || p2 == NULL || curve == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    size = curve->size;
    if(size == 0u || size > (uint32_t)(UINT32_MAX / 2u)) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Allocate temporary buffers */
    lambda = (uint8_t*)calloc((size_t)size * 2u, 1);
    x3 = (uint8_t*)calloc(size, 1);
    y3 = (uint8_t*)calloc(size, 1);
    temp1 = (uint8_t*)calloc((size_t)size * 2u, 1);
    temp2 = (uint8_t*)calloc((size_t)size * 2u, 1);
    temp3 = (uint8_t*)calloc(size, 1);
    
    if(!lambda || !x3 || !y3 || !temp1 || !temp2 || !temp3) {
        rc = NOXTLS_RETURN_FAILED;
        goto cleanup_ptadd;
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
    if(lambda) free(lambda);
    if(x3) free(x3);
    if(y3) free(y3);
    if(temp1) free(temp1);
    if(temp2) free(temp2);
    if(temp3) free(temp3);
    
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
    uint8_t *inv = NULL;
    uint8_t *z2 = NULL;
    uint8_t *z3 = NULL;
    uint8_t *t1 = NULL;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    if(size == 0u || size > (uint32_t)(UINT32_MAX / 2u)) {
        return NOXTLS_RETURN_FAILED;
    }

    if(ecc_jpoint_is_infinity(J, size)) {
        noxtls_bn_zero(x, size);
        noxtls_bn_zero(y, size);
        return NOXTLS_RETURN_SUCCESS;
    }

    inv = (uint8_t*)calloc(size, 1);
    z2  = (uint8_t*)calloc(size, 1);
    z3  = (uint8_t*)calloc(size, 1);
    t1  = (uint8_t*)calloc((size_t)size * 2u, 1);
    if(!inv || !z2 || !z3 || !t1) {
        rc = NOXTLS_RETURN_FAILED;
        goto cleanup_affine;
    }
    rc = ecc_mod_inv_prime(inv, J->Z, p, size);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup_affine;
    }
    if(noxtls_bn_is_zero(inv, size)) {
        rc = NOXTLS_RETURN_FAILED;
        goto cleanup_affine;
    }
    noxtls_bn_mul(t1, inv, size, inv, size);
    noxtls_bn_mod(z2, t1, size * 2, p, size);
    noxtls_bn_mul(t1, z2, size, inv, size);
    noxtls_bn_mod(z3, t1, size * 2, p, size);
    noxtls_bn_mul(t1, J->X, size, z2, size);
    noxtls_bn_mod(x, t1, size * 2, p, size);
    noxtls_bn_mul(t1, J->Y, size, z3, size);
    noxtls_bn_mod(y, t1, size * 2, p, size);

cleanup_affine:
    if(inv) free(inv);
    if(z2)  free(z2);
    if(z3)  free(z3);
    if(t1)  free(t1);
    return rc;
}

#if NOXTLS_ECC_POINT_MUL_WINDOW_SIZE > 0
/** Build precomputation table T[0..2^w-1]: T[0]=identity, T[1]=P, T[i]=i*P in Jacobian. */
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
    return NOXTLS_RETURN_SUCCESS;
}

/** Fixed-window scalar multiplication using precomputed table. Constant-time. */
static noxtls_return_t ecc_point_mul_windowed(ecc_point_t *result, const uint8_t *scalar, const ecc_curve_params_t *curve,
                                               const ecc_jpoint_t *table, uint32_t w)
{
    uint32_t size = curve->size;
    uint32_t n_bits = size * 8;
    uint32_t t = (n_bits + w - 1) / w;  /* number of windows */
    uint32_t table_len = 1u << w;
    ecc_jpoint_t *R = NULL;
    ecc_jpoint_t *T_sel = NULL;
    ecc_jpoint_t *T_dbl = NULL;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t i;
    uint32_t j;
    uint32_t d;

    R = (ecc_jpoint_t*)calloc(1, sizeof(ecc_jpoint_t));
    T_sel = (ecc_jpoint_t*)calloc(1, sizeof(ecc_jpoint_t));
    T_dbl = (ecc_jpoint_t*)calloc(1, sizeof(ecc_jpoint_t));
    if(!R || !T_sel || !T_dbl) {
        rc = NOXTLS_RETURN_FAILED;
        goto cleanup;
    }
    R->size = T_sel->size = T_dbl->size = size;

    /* First window: R = T[d_0]. Constant-time select T[d_0] into T_sel. */
    d = ecc_scalar_digit(scalar, size, w, 0);
    memcpy(T_sel, &table[0], sizeof(ecc_jpoint_t));
    for(j = 1; j < table_len; j++) {
        ecc_jpoint_cond_select(T_sel, &table[j], T_sel, size, (uint8_t)(d == j));
    }
    memcpy(R, T_sel, sizeof(ecc_jpoint_t));

    for(i = 1; i < t && rc == NOXTLS_RETURN_SUCCESS; i++) {
        /* R = 2^w * R (w doubles) */
        for(j = 0; j < w; j++) {
            rc = ecc_jpoint_double(T_dbl, R, curve);
            if(rc != NOXTLS_RETURN_SUCCESS) goto cleanup;
            memcpy(R, T_dbl, sizeof(ecc_jpoint_t));
        }
        /* R = R + T[d_i] */
        d = ecc_scalar_digit(scalar, size, w, i);
        memcpy(T_sel, &table[0], sizeof(ecc_jpoint_t));
        for(j = 1; j < table_len; j++) {
            ecc_jpoint_cond_select(T_sel, &table[j], T_sel, size, (uint8_t)(d == j));
        }
        rc = ecc_jpoint_add(T_dbl, R, T_sel, curve);
        if(rc != NOXTLS_RETURN_SUCCESS) goto cleanup;
        memcpy(R, T_dbl, sizeof(ecc_jpoint_t));
    }

    if(rc != NOXTLS_RETURN_SUCCESS) goto cleanup;
    rc = ecc_jpoint_to_affine(result->x, result->y, R, curve);
    if(rc == NOXTLS_RETURN_SUCCESS) result->size = size;

cleanup:
    if(R) free(R);
    if(T_sel) free(T_sel);
    if(T_dbl) free(T_dbl);
    return rc;
}
#endif /* NOXTLS_ECC_POINT_MUL_WINDOW_SIZE > 0 */

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

#if NOXTLS_ECC_POINT_MUL_WINDOW_SIZE >= 2
    /*
     * secp521r1 (66-byte coordinates) and brainpoolP512r1 (64-byte coordinates):
     * windowed / fixed-base precomputation has produced incorrect points in TLS 1.3
     * ECDSA CertificateVerify interop; use the Montgomery ladder only for these sizes.
     */
    if(size != 66u && size != 64u) {
        {
            const uint32_t w = (uint32_t)NOXTLS_ECC_POINT_MUL_WINDOW_SIZE;
            uint32_t table_len = 1u << w;
            ecc_jpoint_t *table = NULL;
            int use_cache = 0;
            int is_fixed_base = 0;

#if NOXTLS_ECC_FIXED_POINT_OPTIM
            is_fixed_base = ecc_point_equal(point, &curve->G, size);
            if(is_fixed_base && s_fixed_base_cache.valid && s_fixed_base_cache.curve == curve &&
                s_fixed_base_cache.w == w && s_fixed_base_cache.size == size &&
                s_fixed_base_cache.table != NULL &&
                memcmp(s_fixed_base_cache.gx, curve->G.x, size) == 0 &&
                memcmp(s_fixed_base_cache.gy, curve->G.y, size) == 0) {
                table = s_fixed_base_cache.table;
                use_cache = 1;
            }
#endif
            if(!use_cache) {
                table = (ecc_jpoint_t*)calloc(table_len, sizeof(ecc_jpoint_t));
                if(table) {
                    rc = ecc_build_precompute_table(table, table_len, point, curve);
                    if(rc != NOXTLS_RETURN_SUCCESS) {
                        free(table);
                        table = NULL;
                    }
#if NOXTLS_ECC_FIXED_POINT_OPTIM
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
#endif
                }
            }
            if(table) {
                rc = ecc_point_mul_windowed(result, scalar, curve, table, w);
#if !NOXTLS_ECC_FIXED_POINT_OPTIM
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
        ecc_jpoint_t *R0 = NULL;
        ecc_jpoint_t *R1 = NULL;
        ecc_jpoint_t *T_sum = NULL;
        ecc_jpoint_t *T_dbl0 = NULL;
        ecc_jpoint_t *T_dbl1 = NULL;
        uint32_t i;
        uint32_t j;
        uint8_t bit;

        R0 = (ecc_jpoint_t*)calloc(1, sizeof(ecc_jpoint_t));
        R1 = (ecc_jpoint_t*)calloc(1, sizeof(ecc_jpoint_t));
        T_sum = (ecc_jpoint_t*)calloc(1, sizeof(ecc_jpoint_t));
        T_dbl0 = (ecc_jpoint_t*)calloc(1, sizeof(ecc_jpoint_t));
        T_dbl1 = (ecc_jpoint_t*)calloc(1, sizeof(ecc_jpoint_t));
        if(!R0 || !R1 || !T_sum || !T_dbl0 || !T_dbl1) {
            if(R0) free(R0);
            if(R1) free(R1);
            if(T_sum) free(T_sum);
            if(T_dbl0) free(T_dbl0);
            if(T_dbl1) free(T_dbl1);
            return NOXTLS_RETURN_FAILED;
        }

        R0->size = R1->size = size;
        T_sum->size = T_dbl0->size = T_dbl1->size = size;

        noxtls_bn_zero(R0->X, size);
        noxtls_bn_zero(R0->Y, size);
        noxtls_bn_zero(R0->Z, size);
        noxtls_bn_copy(R1->X, point->x, size);
        noxtls_bn_copy(R1->Y, point->y, size);
        noxtls_bn_zero(R1->Z, size);
        R1->Z[size - 1] = 0x01;

        for(i = 0; i < size && rc == NOXTLS_RETURN_SUCCESS; i++) {
            for(j = 8; j > 0; j--) {
                bit = (scalar[i] >> (j - 1)) & 1;
                rc = ecc_jpoint_add(T_sum, R0, R1, curve);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    break;
                }
                rc = ecc_jpoint_double(T_dbl0, R0, curve);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    break;
                }
                rc = ecc_jpoint_double(T_dbl1, R1, curve);
                if(rc != NOXTLS_RETURN_SUCCESS) {
                    break;
                }
                ecc_cond_select(R0->X, T_sum->X, T_dbl0->X, size, bit);
                ecc_cond_select(R0->Y, T_sum->Y, T_dbl0->Y, size, bit);
                ecc_cond_select(R0->Z, T_sum->Z, T_dbl0->Z, size, bit);
                ecc_cond_select(R1->X, T_dbl1->X, T_sum->X, size, bit);
                ecc_cond_select(R1->Y, T_dbl1->Y, T_sum->Y, size, bit);
                ecc_cond_select(R1->Z, T_dbl1->Z, T_sum->Z, size, bit);
            }
        }

        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_bn_zero(result->x, size);
            noxtls_bn_zero(result->y, size);
            free(R0); free(R1); free(T_sum); free(T_dbl0); free(T_dbl1);
            return rc;
        }

        rc = ecc_jpoint_to_affine(result->x, result->y, R0, curve);
        free(R0);
        free(R1);
        free(T_sum);
        free(T_dbl0);
        free(T_dbl1);
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
    if(size == 0u || size > (uint32_t)(UINT32_MAX / 2u)) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Allocate temporary buffers */
    left = (uint8_t*)calloc(size, 1);
    right = (uint8_t*)calloc(size, 1);
    temp1 = (uint8_t*)calloc((size_t)size * 2u, 1);
    temp2 = (uint8_t*)calloc((size_t)size * 2u, 1);
    
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
    drbg_state_t drbg_state;
    uint8_t *random_bytes = NULL;
    uint8_t *n_minus_1 = NULL;
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
    if(size == 0u || size > (uint32_t)(UINT32_MAX / 8u)) {
        rc = NOXTLS_RETURN_FAILED;
        goto cleanup_keygen;
    }
    bits = size * 8u;
    
    /* Allocate buffers */
    random_bytes = (uint8_t*)calloc(size, 1);
    n_minus_1 = (uint8_t*)calloc(size, 1);
    
    do {
        if(!random_bytes || !n_minus_1) {
            rc = NOXTLS_RETURN_FAILED;
            break;
        }
        
        /* Initialize DRBG with AES-256 */
        rc = drbg_instantiate(&drbg_state, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            break;
        }
        
        /* Generate private key d in range [1, n-1] */
        /* Compute n - 1 */
        noxtls_bn_copy(n_minus_1, key->curve->n, size);
        uint8_t one[ECC_MAX_KEY_SIZE] = {0};
        one[size - 1] = 0x01;
        noxtls_bn_sub(n_minus_1, n_minus_1, one, size);
        
        /* Generate random private key */
        do {
            /* Generate random bytes */
            rc = drbg_generate(&drbg_state, random_bytes, bits, NULL, 0);
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
    if(n_minus_1) free(n_minus_1);

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
