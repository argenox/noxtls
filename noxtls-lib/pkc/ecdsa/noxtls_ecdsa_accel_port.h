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
* File:    noxtls_ecdsa_accel_port.h
* Summary: Platform ECDSA acceleration hook (optional, per-port implementation)
*
*
*****************************************************************************/

#ifndef _NOXTLS_ECDSA_ACCEL_PORT_H_
#define _NOXTLS_ECDSA_ACCEL_PORT_H_

#include "noxtls_ecdsa.h"

#ifdef __cplusplus
extern "C" {
#endif

noxtls_return_t noxtls_ecdsa_sign_accel_port(const ecc_key_t *key,
                                             const uint8_t *hash,
                                             uint32_t hash_len,
                                             ecdsa_signature_t *signature);

noxtls_return_t noxtls_ecdsa_verify_accel_port(const ecc_key_t *key,
                                               const uint8_t *hash,
                                               uint32_t hash_len,
                                               const ecdsa_signature_t *signature);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_ECDSA_ACCEL_PORT_H_ */

