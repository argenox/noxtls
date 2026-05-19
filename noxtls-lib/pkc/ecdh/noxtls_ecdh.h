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
* File:    noxtls_ecdh.h
* Summary: Elliptic Curve Diffie-Hellman (ECDH) Key Exchange
*
*/

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


