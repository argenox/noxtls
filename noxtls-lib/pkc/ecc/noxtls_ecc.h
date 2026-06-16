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
* File:    noxtls_ecc.h
* Summary: Elliptic Curve Cryptography (ECC) Base Implementation
*
*
*****************************************************************************/

/** @addtogroup noxtls_pkc */
/** @{ */

#ifndef _NOXTLS_ECC_H_
#define _NOXTLS_ECC_H_

#include <stdint.h>
#include "noxtls_common.h"

#ifdef __has_include
#  if __has_include("noxtls_config.h")
#    include "noxtls_config.h"
#  endif
#endif
#ifndef NOXTLS_ECC_POINT_MUL_WINDOW_SIZE
#define NOXTLS_ECC_POINT_MUL_WINDOW_SIZE 4
#endif
#ifndef NOXTLS_ECC_FIXED_POINT_OPTIM
#define NOXTLS_ECC_FIXED_POINT_OPTIM 1
#endif
/* Process-global ECC precompute caches are disabled by default because the
 * shared mutable state is not synchronized for concurrent TLS use. Only enable
 * this for single-threaded builds or when external synchronization is present. */
#ifndef NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE
#define NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE 0
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ECC_MAX_KEY_SIZE 66  /* 521 bits = 66 bytes */

typedef enum
{
    NOXTLS_ECC_SECP192R1,  /* NIST P-192 */
    NOXTLS_ECC_SECP224R1,  /* NIST P-224 */
    NOXTLS_ECC_SECP256R1,  /* NIST P-256 */
    NOXTLS_ECC_SECP384R1,  /* NIST P-384 */
    NOXTLS_ECC_SECP521R1,  /* NIST P-521 */
    NOXTLS_ECC_BP256R1,    /* Brainpool P-256r1 */
    NOXTLS_ECC_BP384R1,    /* Brainpool P-384r1 */
    NOXTLS_ECC_BP512R1,    /* Brainpool P-512r1 */
    NOXTLS_ECC_SECP192K1,  /* secp192k1 */
    NOXTLS_ECC_SECP224K1,  /* secp224k1 */
    NOXTLS_ECC_SECP256K1,  /* secp256k1 */
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
    /** Populated by noxtls_ecc_key_init / noxtls_ecc_key_generate; used for TLS 1.3 signature scheme selection. */
    ecc_curve_t curve_kind;
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

#if (NOXTLS_ECC_POINT_MUL_WINDOW_SIZE > 0) && (NOXTLS_ECC_FIXED_POINT_OPTIM) && (NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE)
/**
 * Fixed-base point multiplication cache (windowed precompute for generator G).
 * Used only inside noxtls_ecc.c; not part of the public API surface.
 */
typedef struct {
    const ecc_curve_params_t *curve;
    ecc_jpoint_t *table;
    uint32_t w;
    uint32_t size;
    uint8_t gx[ECC_MAX_KEY_SIZE];
    uint8_t gy[ECC_MAX_KEY_SIZE];
    int valid;
} ecc_fixed_base_cache_t;
#endif

/* Curve Operations */
noxtls_return_t noxtls_ecc_curve_init(ecc_curve_params_t *curve, ecc_curve_t curve_type);
noxtls_return_t noxtls_ecc_curve_free(ecc_curve_params_t *curve);

/* Point Operations */
noxtls_return_t noxtls_ecc_point_init(ecc_point_t *point, uint32_t size);
noxtls_return_t noxtls_ecc_point_add(ecc_point_t *result, const ecc_point_t *p1, const ecc_point_t *p2, const ecc_curve_params_t *curve);
noxtls_return_t noxtls_ecc_point_double(ecc_point_t *result, const ecc_point_t *p, const ecc_curve_params_t *curve);
noxtls_return_t noxtls_ecc_point_multiply(ecc_point_t *result, const uint8_t *scalar, const ecc_point_t *point, const ecc_curve_params_t *curve);
/* Joint scalar multiplication: result = scalar1*point1 + scalar2*point2. */
noxtls_return_t noxtls_ecc_point_muladd(ecc_point_t *result,
                                        const uint8_t *scalar1, const ecc_point_t *point1,
                                        const uint8_t *scalar2, const ecc_point_t *point2,
                                        const ecc_curve_params_t *curve);
/* Point multiply uses in-house implementation. */
int noxtls_ecc_point_multiply_uses_ref(void);
/** Return configured window size for point mul (0 = ladder only, 2+ = windowed). */
int noxtls_ecc_point_mul_window_size(void);
noxtls_return_t noxtls_ecc_point_is_on_curve(const ecc_point_t *point, const ecc_curve_params_t *curve);
noxtls_return_t noxtls_ecc_point_validate_public(const ecc_point_t *point, const ecc_curve_params_t *curve);

/* Key Management */
noxtls_return_t noxtls_ecc_key_init(ecc_key_t *key, ecc_curve_t curve_type);
noxtls_return_t noxtls_ecc_key_generate(ecc_key_t *key, ecc_curve_t curve_type);
noxtls_return_t noxtls_ecc_key_free(ecc_key_t *key);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_ECC_H_ */

