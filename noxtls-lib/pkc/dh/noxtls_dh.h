/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
* File:    noxtls_dh.h
* Summary: Finite-field Diffie-Hellman (FFDHE) per RFC 7919
*/

/** @addtogroup noxtls_pkc */
/** @{ */

#ifndef _NOXTLS_DH_H_
#define _NOXTLS_DH_H_

#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Get FFDHE group parameters (p, g) for a TLS named group.
 * @param named_group TLS NamedGroup (e.g. TLS_NAMED_GROUP_FFDHE2048 .. TLS_NAMED_GROUP_FFDHE8192)
 * @param p output: pointer to prime modulus (p_len bytes, big-endian)
 * @param g output: pointer to generator (p_len bytes, big-endian; value 2)
 * @param p_len output: length of p in bytes
 * @return NOXTLS_RETURN_SUCCESS if group is supported
 */
noxtls_return_t noxtls_dh_ffdhe_params(uint16_t named_group,
                                        const uint8_t **p,
                                        const uint8_t **g,
                                        uint32_t *p_len);

/**
 * RFC 7919 FFDHE ephemeral key pair using a minimum-length private exponent (Table 2)
 * for safe-prime groups. This matches common TLS stacks and keeps large-group handshakes
 * practical while remaining within FFDHE guidance.
 *
 * @param named_group TLS NamedGroup (TLS_NAMED_GROUP_FFDHE2048 .. TLS_NAMED_GROUP_FFDHE8192)
 * @param private_out p_len bytes, big-endian (high bytes zero-padded)
 * @param public_out p_len bytes, big-endian
 */
noxtls_return_t noxtls_dh_ffdhe_generate_ephemeral(uint16_t named_group,
                                                   uint8_t *private_out,
                                                   uint8_t *public_out);

noxtls_return_t noxtls_dh_ffdhe_validate_client_key_share(uint16_t named_group,
                                                        const uint8_t *key_exchange,
                                                        uint32_t key_exchange_len);

/**
 * Generate ephemeral DH key pair.
 * private = random in [2, p-2], public = g^private mod p.
 * @param p prime modulus (big-endian)
 * @param p_len length of p in bytes
 * @param g generator (big-endian, typically 2)
 * @param g_len length of g in bytes (use p_len, g zero-padded)
 * @param private_out output: private exponent (p_len bytes)
 * @param public_out output: public value g^private mod p (p_len bytes)
 */
noxtls_return_t noxtls_dh_generate_key(const uint8_t *p, uint32_t p_len,
                                        const uint8_t *g, uint32_t g_len,
                                        uint8_t *private_out,
                                        uint8_t *public_out);

/**
 * Compute DH shared secret: Z = peer_public^private mod p.
 * @param private_key our private exponent (p_len bytes)
 * @param private_len length of private key
 * @param peer_public peer's public value
 * @param peer_len length of peer public
 * @param p prime modulus
 * @param p_len length of p
 * @param secret_out output buffer (must be at least p_len bytes)
 */
noxtls_return_t noxtls_dh_shared_secret(const uint8_t *private_key,
                                         uint32_t private_len,
                                         const uint8_t *peer_public,
                                         uint32_t peer_len,
                                         const uint8_t *p,
                                         uint32_t p_len,
                                         uint8_t *secret_out);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_DH_H_ */
