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
/* The configuration must be seen before ECC_MAX_KEY_SIZE is derived below: every
 * translation unit (whether it includes this header as "noxtls_ecc.h" or as
 * "pkc/ecc/noxtls_ecc.h") must see the same curve set, or struct layouts differ. */
#include "noxtls_config.h"
#include "noxtls_common.h"
#ifndef NOXTLS_ECC_POINT_MUL_WINDOW_SIZE
#define NOXTLS_ECC_POINT_MUL_WINDOW_SIZE 4
#endif
#ifndef NOXTLS_ECC_FIXED_POINT_OPTIM
#define NOXTLS_ECC_FIXED_POINT_OPTIM 1
#endif
/* Defaults favour RAM: P-256 uses the read-only generator table and the low-RAM
 * verify path, and no process-global precompute tables are retained (see
 * noxtls_config.h; the cache is shared mutable state that multi-threaded users
 * must serialize externally when enabled). */
#ifndef NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE
#define NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE 0
#endif
#ifndef NOXTLS_ECC_P256_FLASH_PRECOMPUTE
#define NOXTLS_ECC_P256_FLASH_PRECOMPUTE 1
#endif
#ifndef NOXTLS_ECC_P256_LOW_RAM_VERIFY
#define NOXTLS_ECC_P256_LOW_RAM_VERIFY NOXTLS_ECC_P256_FLASH_PRECOMPUTE
#endif
#if NOXTLS_ECC_P256_LOW_RAM_VERIFY && !NOXTLS_ECC_P256_FLASH_PRECOMPUTE
#error "NOXTLS_ECC_P256_LOW_RAM_VERIFY requires NOXTLS_ECC_P256_FLASH_PRECOMPUTE"
#endif
/* Timing and accelerator counters are intended for targeted investigations.
 * Keep them out of normal products unless explicitly requested at build time. */
#ifndef NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS
#define NOXTLS_ECC_PERFORMANCE_DIAGNOSTICS 0
#endif

/* On-target operation diagnostics (PTS status ABI: control flow only, never key
 * material). NOXTLS_ECC_STATUS_WORDS=0 drops these words (and the ECDSA signer's
 * noxtls_ecdsa_sign_last_rc/_stage), 36 bytes of RAM. */
#ifndef NOXTLS_ECC_STATUS_WORDS
#define NOXTLS_ECC_STATUS_WORDS 1
#endif
#if NOXTLS_ECC_STATUS_WORDS
extern volatile int32_t noxtls_ecc_keygen_last_rc;
extern volatile uint32_t noxtls_ecc_keygen_last_stage;
extern volatile int32_t noxtls_ecc_keygen_last_entropy_rc;
extern volatile int32_t noxtls_ecc_keygen_last_multiply_rc;
extern volatile uint32_t noxtls_ecc_keygen_last_drbg_type;
extern volatile int32_t noxtls_ecc_keyinit_last_rc;
extern volatile uint32_t noxtls_ecc_keyinit_last_stage;
#define NOXTLS_ECC_STATUS_SET(word, value) ((word) = (value))
#else
#define NOXTLS_ECC_STATUS_SET(word, value) ((void)(value))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Per-curve enable knobs (see noxtls_config.h). A disabled curve is rejected by
 * noxtls_ecc_curve_init()/noxtls_ecc_key_init() and its constants are not linked. */
#ifndef NOXTLS_ECC_ENABLE_SECP192R1
#define NOXTLS_ECC_ENABLE_SECP192R1 1
#endif
#ifndef NOXTLS_ECC_ENABLE_SECP224R1
#define NOXTLS_ECC_ENABLE_SECP224R1 1
#endif
#ifndef NOXTLS_ECC_ENABLE_SECP256R1
#define NOXTLS_ECC_ENABLE_SECP256R1 1
#endif
#ifndef NOXTLS_ECC_ENABLE_SECP384R1
#define NOXTLS_ECC_ENABLE_SECP384R1 1
#endif
#ifndef NOXTLS_ECC_ENABLE_SECP521R1
#define NOXTLS_ECC_ENABLE_SECP521R1 1
#endif
#ifndef NOXTLS_ECC_ENABLE_BP256R1
#define NOXTLS_ECC_ENABLE_BP256R1 1
#endif
#ifndef NOXTLS_ECC_ENABLE_BP384R1
#define NOXTLS_ECC_ENABLE_BP384R1 1
#endif
#ifndef NOXTLS_ECC_ENABLE_BP512R1
#define NOXTLS_ECC_ENABLE_BP512R1 1
#endif
#ifndef NOXTLS_ECC_ENABLE_SECP192K1
#define NOXTLS_ECC_ENABLE_SECP192K1 1
#endif
#ifndef NOXTLS_ECC_ENABLE_SECP224K1
#define NOXTLS_ECC_ENABLE_SECP224K1 1
#endif
#ifndef NOXTLS_ECC_ENABLE_SECP256K1
#define NOXTLS_ECC_ENABLE_SECP256K1 1
#endif

/* Largest coordinate / order length (bytes) over the enabled curves. secp224k1
 * needs 29: its 225-bit group order is one byte longer than its field. */
#if NOXTLS_ECC_ENABLE_SECP521R1
#define NOXTLS_ECC_MAX_CURVE_BYTES 66U
#elif NOXTLS_ECC_ENABLE_BP512R1
#define NOXTLS_ECC_MAX_CURVE_BYTES 64U
#elif NOXTLS_ECC_ENABLE_SECP384R1 || NOXTLS_ECC_ENABLE_BP384R1
#define NOXTLS_ECC_MAX_CURVE_BYTES 48U
#elif NOXTLS_ECC_ENABLE_SECP256R1 || NOXTLS_ECC_ENABLE_BP256R1 || NOXTLS_ECC_ENABLE_SECP256K1
#define NOXTLS_ECC_MAX_CURVE_BYTES 32U
#elif NOXTLS_ECC_ENABLE_SECP224K1
#define NOXTLS_ECC_MAX_CURVE_BYTES 29U
#elif NOXTLS_ECC_ENABLE_SECP224R1
#define NOXTLS_ECC_MAX_CURVE_BYTES 28U
#elif NOXTLS_ECC_ENABLE_SECP192R1 || NOXTLS_ECC_ENABLE_SECP192K1
#define NOXTLS_ECC_MAX_CURVE_BYTES 24U
#else
/* No curve enabled: keep the types usable (every curve init fails). */
#define NOXTLS_ECC_MAX_CURVE_BYTES 32U
#endif

/* Size of the coordinate arrays in ecc_point_t / ecc_jpoint_t / ecdsa_signature_t.
 * Derived from the enabled curves (66 with every curve, 32 for a P-256-only build).
 * It may be overridden only with a value that is at least the derived size. */
#ifndef ECC_MAX_KEY_SIZE
#define ECC_MAX_KEY_SIZE NOXTLS_ECC_MAX_CURVE_BYTES
#endif
#if ECC_MAX_KEY_SIZE < NOXTLS_ECC_MAX_CURVE_BYTES
#error "ECC_MAX_KEY_SIZE is smaller than the largest enabled ECC curve"
#endif

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
/** ecc_curve_params_t.curve_tag value of library-initialized parameters (0 = caller-built). */
#define NOXTLS_ECC_CURVE_TAG(curve_type) ((uint32_t)(curve_type) + 1U)

NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    uint8_t x[ECC_MAX_KEY_SIZE];
    uint8_t y[ECC_MAX_KEY_SIZE];
    uint32_t size;  /* Size in bytes */
} ecc_point_t;

/* Curve parameters. Library-initialized parameters point at shared read-only
 * constants (no allocation): never write through p, a, b or n. A caller that
 * builds parameters itself owns the buffers it points at. */
typedef struct
{
    const uint8_t *p;     /* Prime modulus */
    const uint8_t *a;     /* Curve parameter a */
    const uint8_t *b;     /* Curve parameter b */
    ecc_point_t G;        /* Generator point */
    const uint8_t *n;     /* Order of generator (n_size bytes, big-endian) */
    uint32_t size;        /* Coordinate (field element) size in bytes */
    /** Length of n in bytes. Equals size for every curve except secp224k1, whose
     *  225-bit order is one byte longer than its 224-bit field. 0 is treated as size
     *  (structures not created by noxtls_ecc_curve_init). */
    uint32_t n_size;
    /** Internal: curve id + 1 for parameters created by the library, 0 for
     *  caller-built parameters (used to key precompute caches by curve, not by pointer). */
    uint32_t curve_tag;
} ecc_curve_params_t;

typedef struct
{
    uint8_t *d;              /* Private key (scalar) */
    ecc_point_t Q;           /* Public key (point) */
    /** Curve parameters: the library's shared read-only descriptor for the curve
     *  (set by noxtls_ecc_key_init; not owned by the key, nothing to free). */
    const ecc_curve_params_t *curve;
    /** Populated by ECC key initialization, generation, or private-scalar import; used for TLS 1.3 signature scheme selection. */
    ecc_curve_t curve_kind;
    /** Allocated length of @c d in bytes (set by noxtls_ecc_key_init). noxtls_ecc_key_free
     *  wipes exactly this many bytes, independent of @c curve; 0 means unknown (no wipe). */
    uint32_t d_size;
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
/** Shared read-only parameters of @p curve_type, or NULL when the curve is unknown
 *  or disabled at build time (NOXTLS_ECC_ENABLE_<curve>=0). Never freed. */
const ecc_curve_params_t *noxtls_ecc_curve_get(ecc_curve_t curve_type);
/** Fill @p curve with the parameters of @p curve_type. p, a, b and n point at
 *  shared read-only constants (no allocation); NOXTLS_RETURN_FAILED for an
 *  unknown or disabled curve. */
noxtls_return_t noxtls_ecc_curve_init(ecc_curve_params_t *curve, ecc_curve_t curve_type);
/** Clear @p curve. Parameter buffers are not freed (library parameters are
 *  read-only constants; caller-built buffers stay owned by the caller). */
noxtls_return_t noxtls_ecc_curve_free(ecc_curve_params_t *curve);
/** Length in bytes of the group order n (curve->n_size, or curve->size when unset). */
uint32_t noxtls_ecc_curve_order_size(const ecc_curve_params_t *curve);

/* Point Operations */
noxtls_return_t noxtls_ecc_point_init(ecc_point_t *point, uint32_t size);
noxtls_return_t noxtls_ecc_point_add(ecc_point_t *result, const ecc_point_t *p1, const ecc_point_t *p2, const ecc_curve_params_t *curve);
noxtls_return_t noxtls_ecc_point_double(ecc_point_t *result, const ecc_point_t *p, const ecc_curve_params_t *curve);
/** Optional cooperative service hook; the portable implementation is a no-op.
 * Called at software arithmetic boundaries, never with scalar bits as arguments.
 * Overrides must preserve inputs, run in task context, and either serialize
 * other ECC callers or disable global precompute caches and shared scratch.
 * Hardware accelerator calls and individual field multiplies are not sliced.
 */
#define NOXTLS_ECC_COOPERATIVE_SERVICE_VERSION 3
void noxtls_ecc_yield(void);

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
/** Import a big-endian private scalar and derive its public point. The scalar
 *  must be 1..n-1 and at most the coordinate size in bytes; shorter values are
 *  left-padded with zeroes. Like key_generate, this initializes @p key, which
 *  must be uninitialized. If import fails after initialization, free @p key. */
noxtls_return_t noxtls_ecc_key_import_private(ecc_key_t *key, ecc_curve_t curve_type,
                                               const uint8_t *private_scalar, uint32_t private_scalar_len);
noxtls_return_t noxtls_ecc_key_free(ecc_key_t *key);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_ECC_H_ */

