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
* File:    noxtls_tls_kdf.h
* Summary: TLS Key Derivation Functions (PRF, HKDF)
*
*
*****************************************************************************/

#ifndef _NOXTLS_TLS_KDF_H_
#define _NOXTLS_TLS_KDF_H_

#include <stdint.h>

#include "noxtls_common.h"
#include "mdigest/noxtls_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TLS 1.2 PRF (Pseudo-Random Function) */
noxtls_return_t tls12_prf(const uint8_t *secret, uint32_t secret_len,
                           const uint8_t *label, uint32_t label_len,
                           const uint8_t *seed, uint32_t seed_len,
                           uint8_t *output, uint32_t output_len,
                           noxtls_hash_algos_t hash_algo);

/* TLS 1.0/1.1 PRF (uses MD5 and SHA-1) */
noxtls_return_t tls10_prf(const uint8_t *secret, uint32_t secret_len,
                           const uint8_t *label, uint32_t label_len,
                           const uint8_t *seed, uint32_t seed_len,
                           uint8_t *output, uint32_t output_len);

/* TLS 1.3 HKDF-Expand-Label (RFC 8446 Section 7.1) */
noxtls_return_t tls13_hkdf_expand_label(noxtls_hash_algos_t hash_algo,
                                          const uint8_t *secret, uint32_t secret_len,
                                          const uint8_t *label, uint32_t label_len,
                                          const uint8_t *context, uint32_t context_len,
                                          uint8_t *output, uint32_t output_len);

/* DTLS 1.3 HKDF-Expand-Label (RFC 9147 Section 5.9, "dtls13" prefix) */
noxtls_return_t dtls13_hkdf_expand_label(noxtls_hash_algos_t hash_algo,
                                          const uint8_t *secret, uint32_t secret_len,
                                          const uint8_t *label, uint32_t label_len,
                                          const uint8_t *context, uint32_t context_len,
                                          uint8_t *output, uint32_t output_len);

/* TLS 1.3 Derive-Secret (RFC 8446 Section 7.1) */
noxtls_return_t tls13_derive_secret(noxtls_hash_algos_t hash_algo,
                                      const uint8_t *secret, uint32_t secret_len,
                                      const uint8_t *label, uint32_t label_len,
                                      const uint8_t *messages, uint32_t messages_len,
                                      uint8_t *output, uint32_t output_len);

noxtls_return_t dtls13_derive_secret(noxtls_hash_algos_t hash_algo,
                                      const uint8_t *secret, uint32_t secret_len,
                                      const uint8_t *label, uint32_t label_len,
                                      const uint8_t *messages, uint32_t messages_len,
                                      uint8_t *output, uint32_t output_len);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_TLS_KDF_H_ */

