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
* File:    noxtls_ecdh.h
* Summary: Elliptic Curve Diffie-Hellman (ECDH) Key Exchange
*
*
*****************************************************************************/

/** @addtogroup noxtls_pkc */
/** @{ */

#ifndef _NOXTLS_ECDH_H_
#define _NOXTLS_ECDH_H_

#include <stdint.h>

#include "noxtls_common.h"
#include "pkc/ecc/noxtls_ecc.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Non-secret ECDH failure provenance.
 *
 * This is intentionally limited to control-flow information.  It never
 * contains a scalar, a point coordinate, or a shared secret, so callers can
 * safely use it for field diagnostics.
 */
typedef enum
{
    NOXTLS_ECDH_DIAGNOSTIC_NONE = 0,
    NOXTLS_ECDH_DIAGNOSTIC_ARGUMENT,
    NOXTLS_ECDH_DIAGNOSTIC_PRIVATE_KEY,
    NOXTLS_ECDH_DIAGNOSTIC_OUTPUT_BUFFER,
    NOXTLS_ECDH_DIAGNOSTIC_PEER_PUBLIC_KEY,
    NOXTLS_ECDH_DIAGNOSTIC_SCALAR_MULTIPLY,
    NOXTLS_ECDH_DIAGNOSTIC_SHARED_POINT_INFINITY,
    NOXTLS_ECDH_DIAGNOSTIC_SHARED_SECRET_LENGTH,
    /* TLS ECDHE wrapper could not allocate its output secret buffer. */
    NOXTLS_ECDH_DIAGNOSTIC_ALLOCATION
} noxtls_ecdh_diagnostic_stage_t;

/**
 * @brief Optional diagnostic result for an ECDH operation.
 *
 * @p internal_rc is the result from the failing internal operation when
 * applicable.  The public function return value remains authoritative.
 */
typedef struct
{
    noxtls_ecdh_diagnostic_stage_t stage;
    noxtls_return_t internal_rc;
} noxtls_ecdh_diagnostic_t;

/**
 * @brief ECDH shared secret with optional non-secret failure provenance.
 *
 * This is the diagnostic form of noxtls_ecdh_compute_shared_secret().  Pass
 * NULL for @p diagnostic when no additional information is required.
 */
noxtls_return_t noxtls_ecdh_compute_shared_secret_ex(
    ecc_key_t *private_key,
    const ecc_point_t *peer_public_key,
    uint8_t *shared_secret,
    uint32_t *shared_secret_len,
    noxtls_ecdh_diagnostic_t *diagnostic);

/**
 * @brief ECDH shared secret: scalar multiplication of peer public point by our private key.
 * @param private_key Our ECC private key (curve must match peer point).
 * @param peer_public_key Peer's public curve point.
 * @param shared_secret Output buffer for the x-coordinate (or implementation-defined encoding).
 * @param shared_secret_len In: buffer size in bytes; out: bytes written on success.
 * @return `NOXTLS_RETURN_SUCCESS` on success, or another `noxtls_return_t` on failure.
 */
noxtls_return_t noxtls_ecdh_compute_shared_secret(ecc_key_t *private_key,
                                                  const ecc_point_t *peer_public_key,
                                                  uint8_t *shared_secret,
                                                  uint32_t *shared_secret_len);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_ECDH_H_ */


