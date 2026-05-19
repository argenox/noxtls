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
* File:    noxtls_dsa.h
* Summary: Digital Signature Algorithm (DSA) per FIPS 186-4
*
*/

/** @addtogroup noxtls_pkc */
/** @{ */

#ifndef _NOXTLS_DSA_H_
#define _NOXTLS_DSA_H_

#include <stdint.h>
#include "noxtls_common.h"
#include "mdigest/noxtls_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum length of DSA prime q in bytes (256-bit q). */
#define DSA_MAX_Q_BYTES 32
/** Maximum length of DSA prime modulus p in bytes (3072-bit p). */
#define DSA_MAX_P_BYTES 384

/**
 * DSA domain parameters and key.
 * p, q, g are the domain parameters; y is the public key; x is the private key (NULL for public-only).
 * All values are big-endian. Use noxtls_dsa_key_init / noxtls_dsa_key_free to manage storage.
 */
typedef struct
{
    uint32_t p_len;   /**< Length of p, g, and y in bytes */
    uint32_t q_len;   /**< Length of q and private key x in bytes */
    uint8_t *p;       /**< Prime modulus (domain parameter) */
    uint8_t *q;       /**< Prime order, q | (p-1) (domain parameter) */
    uint8_t *g;       /**< Generator (domain parameter) */
    uint8_t *y;       /**< Public key: y = g^x mod p */
    uint8_t *x;       /**< Private key in [1, q-1]; NULL for verification-only key */
} dsa_key_t;

/**
 * DSA signature (r, s).
 * r and s are q_len bytes each, big-endian.
 */
typedef struct
{
    uint8_t r[DSA_MAX_Q_BYTES];
    uint8_t s[DSA_MAX_Q_BYTES];
    uint32_t q_len;   /**< Actual length of r and s in bytes */
} dsa_signature_t;

/* DSA key management */
noxtls_return_t noxtls_dsa_key_init(dsa_key_t *key, const uint8_t *p, uint32_t p_len, const uint8_t *q, uint32_t q_len, const uint8_t *g, uint32_t g_len);
noxtls_return_t noxtls_dsa_key_set_public(dsa_key_t *key, const uint8_t *y);
noxtls_return_t noxtls_dsa_key_set_private(dsa_key_t *key, const uint8_t *x);
noxtls_return_t noxtls_dsa_key_generate(dsa_key_t *key);
noxtls_return_t noxtls_dsa_key_free(dsa_key_t *key);

/* DSA signature operations */
noxtls_return_t noxtls_dsa_sign(const dsa_key_t *key, const uint8_t *noxtls_message, uint32_t message_len, dsa_signature_t *signature, noxtls_hash_algos_t hash_algo);
noxtls_return_t noxtls_dsa_verify(const dsa_key_t *key, const uint8_t *noxtls_message, uint32_t message_len, const dsa_signature_t *signature, noxtls_hash_algos_t hash_algo);

/* DSA signature helpers */
noxtls_return_t noxtls_dsa_signature_init(dsa_signature_t *sig, uint32_t q_len);
noxtls_return_t noxtls_dsa_signature_free(dsa_signature_t *sig);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_DSA_H_ */
