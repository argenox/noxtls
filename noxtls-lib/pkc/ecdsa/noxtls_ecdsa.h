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
* File:    noxtls_ecdsa.h
* Summary: Elliptic Curve Digital Signature Algorithm (ECDSA)
*
*
*****************************************************************************/

/** @addtogroup noxtls_pkc */
/** @{ */

#ifndef _NOXTLS_ECDSA_H_
#define _NOXTLS_ECDSA_H_

#include <stdint.h>
#include "noxtls_common.h"
#include "pkc/ecc/noxtls_ecc.h"
#include "mdigest/noxtls_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    uint8_t r[ECC_MAX_KEY_SIZE];
    uint8_t s[ECC_MAX_KEY_SIZE];
    uint32_t size;  /* Size in bytes */
} ecdsa_signature_t;

typedef struct
{
    uint64_t hash_prepare_us;
    uint64_t accel_port_us;
    uint64_t nonce_generate_us;
    uint64_t base_point_mul_us;
    uint64_t r_reduce_us;
    uint64_t nonce_inv_us;
    uint64_t s_compute_us;
    uint64_t self_verify_us;
    uint64_t total_us;
    uint32_t attempts;
} noxtls_ecdsa_sign_timing_t;

/* ECDSA Signature Operations */
noxtls_return_t noxtls_ecdsa_sign(ecc_key_t *key, const uint8_t *noxtls_message, uint32_t message_len, ecdsa_signature_t *signature, noxtls_hash_algos_t hash_algo);
noxtls_return_t noxtls_ecdsa_verify(ecc_key_t *key, const uint8_t *noxtls_message, uint32_t message_len, const ecdsa_signature_t *signature, noxtls_hash_algos_t hash_algo);

/* ECDSA Signature Format */
noxtls_return_t noxtls_ecdsa_signature_init(ecdsa_signature_t *sig, uint32_t size);
noxtls_return_t noxtls_ecdsa_signature_free(ecdsa_signature_t *sig);

/** Parse DER-encoded ECDSA signature (SEQUENCE of two INTEGERs r, s) into ecdsa_signature_t. coord_size is the curve size in bytes (e.g. 32 for P-256). */
noxtls_return_t noxtls_ecdsa_signature_parse_der(const uint8_t *der, uint32_t der_len, ecdsa_signature_t *out, uint32_t coord_size);

/** Last ECDSA sign timing breakdown recorded by noxtls_ecdsa_sign(). */
const noxtls_ecdsa_sign_timing_t *noxtls_ecdsa_last_sign_timing(void);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_ECDSA_H_ */

