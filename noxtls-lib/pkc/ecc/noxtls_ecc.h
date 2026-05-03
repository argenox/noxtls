/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
* 
*
* File:    noxtls_ecc.h
* Summary: Elliptic Curve Cryptography (ECC) Base Implementation
*
*/

/** @addtogroup noxtls_pkc */
/** @{ */

#ifndef _NOXTLS_ECC_H_
#define _NOXTLS_ECC_H_

#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ECC_MAX_KEY_SIZE 66  /* 521 bits = 66 bytes */

typedef enum
{
    ECC_SECP192R1,  /* NIST P-192 */
    ECC_SECP224R1,  /* NIST P-224 */
    ECC_SECP256R1,  /* NIST P-256 */
    ECC_SECP384R1,  /* NIST P-384 */
    ECC_SECP521R1,  /* NIST P-521 */
    ECC_BP256R1,    /* Brainpool P-256r1 */
    ECC_BP384R1,    /* Brainpool P-384r1 */
    ECC_BP512R1,    /* Brainpool P-512r1 */
    ECC_SECP192K1,  /* secp192k1 */
    ECC_SECP224K1,  /* secp224k1 */
    ECC_SECP256K1,  /* secp256k1 */
} ecc_curve_t;

NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    uint8_t x[ECC_MAX_KEY_SIZE];
    uint8_t y[ECC_MAX_KEY_SIZE];
    uint32_t size;  /* Size in bytes */
} ecc_point_t;

typedef struct
{
    uint8_t *p;     /* Prime modulus */
    uint8_t *a;     /* Curve parameter a */
    uint8_t *b;     /* Curve parameter b */
    ecc_point_t G;  /* Generator point */
    uint8_t *n;     /* Order of generator */
    uint32_t size;  /* Size in bytes */
} ecc_curve_params_t;

typedef struct
{
    uint8_t *d;              /* Private key (scalar) */
    ecc_point_t Q;           /* Public key (point) */
    ecc_curve_params_t *curve; /* Curve parameters */
} ecc_key_t;

/* Jacobian point (X, Y, Z) with x = X/Z^2, y = Y/Z^3. Identity is Z=0. */
typedef struct {
    uint32_t size;  /* placed first to avoid padding before aligned member (C4820) */
    uint8_t X[ECC_MAX_KEY_SIZE];
    uint8_t Y[ECC_MAX_KEY_SIZE];
    uint8_t Z[ECC_MAX_KEY_SIZE];
    uint16_t padding; /* explicit padding to avoid C4820 after Z */
} ecc_jpoint_t;
NOXTLS_MSVC_WARNING_POP

/* Curve Operations */
noxtls_return_t noxtls_ecc_curve_init(ecc_curve_params_t *curve, ecc_curve_t curve_type);
noxtls_return_t noxtls_ecc_curve_free(ecc_curve_params_t *curve);

/* Point Operations */
noxtls_return_t noxtls_ecc_point_init(ecc_point_t *point, uint32_t size);
noxtls_return_t noxtls_ecc_point_add(ecc_point_t *result, const ecc_point_t *p1, const ecc_point_t *p2, const ecc_curve_params_t *curve);
noxtls_return_t noxtls_ecc_point_double(ecc_point_t *result, ecc_point_t *p, ecc_curve_params_t *curve);
noxtls_return_t noxtls_ecc_point_multiply(ecc_point_t *result, const uint8_t *scalar, const ecc_point_t *point, const ecc_curve_params_t *curve);
/* Point multiply uses in-house implementation. */
int noxtls_ecc_point_multiply_uses_ref(void);
/** Return configured window size for point mul (0 = ladder only, 2+ = windowed). */
int noxtls_ecc_point_mul_window_size(void);
noxtls_return_t noxtls_ecc_point_is_on_curve(const ecc_point_t *point, const ecc_curve_params_t *curve);

/* Key Management */
noxtls_return_t noxtls_ecc_key_init(ecc_key_t *key, ecc_curve_t curve_type);
noxtls_return_t noxtls_ecc_key_generate(ecc_key_t *key, ecc_curve_t curve_type);
noxtls_return_t noxtls_ecc_key_free(ecc_key_t *key);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_ECC_H_ */


