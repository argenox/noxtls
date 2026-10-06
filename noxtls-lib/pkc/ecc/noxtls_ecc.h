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

#ifndef NOXTLS_ECC_H_
#define NOXTLS_ECC_H_

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
/* Process-global ECC precompute caches materially improve P-256 ECDSA
 * sign/verify throughput by reusing generator and joint tables. The cache is
 * shared mutable state, so multi-threaded users must serialize ECC calls
 * externally or override this to 0 in noxtls_config.h. */
#ifndef NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE
#define NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE 1
#endif
#ifndef NOXTLS_ECC_P256_FLASH_PRECOMPUTE
#define NOXTLS_ECC_P256_FLASH_PRECOMPUTE 0
#endif
#ifndef NOXTLS_ECC_P256_LOW_RAM_VERIFY
#define NOXTLS_ECC_P256_LOW_RAM_VERIFY 0
#endif
#if NOXTLS_ECC_P256_LOW_RAM_VERIFY && !NOXTLS_ECC_P256_FLASH_PRECOMPUTE
#error "NOXTLS_ECC_P256_LOW_RAM_VERIFY requires NOXTLS_ECC_P256_FLASH_PRECOMPUTE"
#endif
/* Timing and accelerator counters are intended for targeted investigations.
 * Keep them out of normal products unless explicitly requested at build time. */
#ifndef NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
#define NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS 0
#endif

/* On-target operation diagnostics. */
extern volatile int32_t noxtls_ecc_keygen_last_rc;
extern volatile uint32_t noxtls_ecc_keygen_last_stage;
extern volatile int32_t noxtls_ecc_keygen_last_entropy_rc;
extern volatile int32_t noxtls_ecc_keygen_last_multiply_rc;
extern volatile uint32_t noxtls_ecc_keygen_last_drbg_type;
extern volatile int32_t noxtls_ecc_keyinit_last_rc;
extern volatile uint32_t noxtls_ecc_keyinit_last_stage;

#ifdef __cplusplus
extern "C" {
#endif

#define ECC_MAX_KEY_SIZE 66U  /* 521 bits = 66 bytes */

/* Unsigned curve ids (MISRA C:2025 Rule 10.3); values match historical enum order. */
typedef uint32_t ecc_curve_t;
#define NOXTLS_ECC_SECP192R1 ((ecc_curve_t)0U)  /* NIST P-192 */
#define NOXTLS_ECC_SECP224R1 ((ecc_curve_t)1U)  /* NIST P-224 */
#define NOXTLS_ECC_SECP256R1 ((ecc_curve_t)2U)  /* NIST P-256 */
#define NOXTLS_ECC_SECP384R1 ((ecc_curve_t)3U)  /* NIST P-384 */
#define NOXTLS_ECC_SECP521R1 ((ecc_curve_t)4U)  /* NIST P-521 */
#define NOXTLS_ECC_BP256R1   ((ecc_curve_t)5U)  /* Brainpool P-256r1 */
#define NOXTLS_ECC_BP384R1   ((ecc_curve_t)6U)  /* Brainpool P-384r1 */
#define NOXTLS_ECC_BP512R1   ((ecc_curve_t)7U)  /* Brainpool P-512r1 */
#define NOXTLS_ECC_SECP192K1 ((ecc_curve_t)8U)  /* secp192k1 */
#define NOXTLS_ECC_SECP224K1 ((ecc_curve_t)9U)  /* secp224k1 */
#define NOXTLS_ECC_SECP256K1 ((ecc_curve_t)10U) /* secp256k1 */

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
    uint8_t *n;     /* Order of generator (n_size bytes, big-endian) */
    uint32_t size;  /* Coordinate (field element) size in bytes */
    /** Length of n in bytes. Equals size for every curve except secp224k1, whose
     *  225-bit order is one byte longer than its 224-bit field. 0 is treated as size
     *  (structures not created by noxtls_ecc_curve_init). */
    uint32_t n_size;
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
/** Length in bytes of the group order n (curve->n_size, or curve->size when unset). */
uint32_t noxtls_ecc_curve_order_size(const ecc_curve_params_t *curve);

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

/* Optional platform point-multiplication accelerator telemetry.  These
 * values expose control flow only: no key, scalar, or point material is
 * retained or reported.  A successful operation count is the authoritative
 * indication that the selected accelerator completed a request. */
int noxtls_ecc_accel_is_ready(void);
uint32_t noxtls_ecc_accel_operation_count(void);
uint32_t noxtls_ecc_accel_fallback_count(void);
void noxtls_ecc_accel_note_fallback(void);
int32_t noxtls_ecc_accel_last_rc(void);
uint32_t noxtls_ecc_accel_last_status(void);
uint32_t noxtls_ecc_accel_last_stage(void);
int noxtls_ecc_accel_input_echo_ok(void);

/* Key Management */
noxtls_return_t noxtls_ecc_key_init(ecc_key_t *key, ecc_curve_t curve_type);
noxtls_return_t noxtls_ecc_key_generate(ecc_key_t *key, ecc_curve_t curve_type);
noxtls_return_t noxtls_ecc_key_free(ecc_key_t *key);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_ECC_H_ */

