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

/* ECDH Key Exchange */
noxtls_return_t noxtls_ecdh_compute_shared_secret(ecc_key_t *private_key, const ecc_point_t *peer_public_key, uint8_t *shared_secret, uint32_t *shared_secret_len);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_ECDH_H_ */


