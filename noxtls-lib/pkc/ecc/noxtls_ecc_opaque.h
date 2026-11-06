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
* File:    noxtls_ecc_opaque.h
* Summary: Opaque (provider held) ECC private keys for ECDSA signing and ECDH
*
*****************************************************************************/

/** @addtogroup noxtls_pkc */
/** @{ */

#ifndef NOXTLS_ECC_OPAQUE_H_
#define NOXTLS_ECC_OPAQUE_H_

#include <stdint.h>

#include "noxtls_common.h"
#include "common/noxtls_crypto_provider.h"
#include "pkc/ecc/noxtls_ecc.h"
#include "pkc/ecdsa/noxtls_ecdsa.h"

#ifdef __cplusplus
extern "C" {
#endif

#if NOXTLS_FEATURE_ATECC608

/**
 * @file noxtls_ecc_opaque.h
 * @brief Binds an ecc_key_t (public key only) to a crypto-provider key handle.
 *
 * A bound key keeps its public point in @c Q so certificate and group checks work, while the private
 * scalar never exists in host memory. noxtls_ecdsa_sign() / noxtls_ecdsa_sign_digest() on a bound key
 * call the provider's @c ecdsa_sign operation, and noxtls_ecdh_compute_shared_secret*() call its
 * @c ecdh_shared operation. TLS (client and server, 1.2 and 1.3) reaches the provider through those
 * two functions, so no TLS code needs to know about opaque keys.
 *
 * The binding is keyed by the address of the ecc_key_t: the key must stay at the same address while
 * it is bound (noxtls_ecc_key_free() unbinds it). The table has NOXTLS_ECC_OPAQUE_MAX entries.
 */

/** Maximum number of simultaneously bound keys. */
#ifndef NOXTLS_ECC_OPAQUE_MAX
#define NOXTLS_ECC_OPAQUE_MAX 8U
#endif

/**
 * @brief Bind a public-only key to a provider key.
 * @param[in] key Key whose address identifies the binding.
 * @param[in] provider Provider with an @c ecdsa_sign (and optionally @c ecdh_shared) operation; must outlive the binding.
 * @param[in] handle Provider key handle.
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, or NOXTLS_RETURN_NOT_ENOUGH_MEMORY when the table is full.
 */
noxtls_return_t noxtls_ecc_opaque_bind(const ecc_key_t *key, const noxtls_crypto_provider_t *provider, noxtls_crypto_key_handle_t handle);

/** @brief Remove a binding (no effect if the key is not bound). */
void noxtls_ecc_opaque_unbind(const ecc_key_t *key);

/** @brief Non-zero when @p key is bound. */
int noxtls_ecc_opaque_is_bound(const ecc_key_t *key);

/**
 * @brief ECDSA sign through the provider.
 * @param[in] key Bound key.
 * @param[in] message Message, or digest when @p hash_algo is NOXTLS_CRYPTO_HASH_PREHASHED.
 * @param[in] message_len Length.
 * @param[out] signature R and S, curve sized.
 * @param[in] hash_algo NOXTLS_HASH_* or NOXTLS_CRYPTO_HASH_PREHASHED.
 * @return NOXTLS_RETURN_NOT_SUPPORTED when the key is not bound or the provider lacks the operation, else the provider result.
 */
noxtls_return_t noxtls_ecc_opaque_ecdsa_sign(const ecc_key_t *key, const uint8_t *message, uint32_t message_len, ecdsa_signature_t *signature, uint32_t hash_algo);

/**
 * @brief ECDH through the provider.
 * @param[in] key Bound key.
 * @param[in] peer Peer public point.
 * @param[out] secret Shared secret (X coordinate).
 * @param[in,out] secret_len In: capacity, out: length.
 * @return NOXTLS_RETURN_NOT_SUPPORTED when the key is not bound or the provider lacks the operation, else the provider result.
 */
noxtls_return_t noxtls_ecc_opaque_ecdh(const ecc_key_t *key, const ecc_point_t *peer, uint8_t *secret, uint32_t *secret_len);

/**
 * @brief Select the provider that generates TLS ECDHE ephemeral keys (NULL restores software generation).
 * @param[in] provider Provider with @c ecdh_keygen and @c ecdh_shared, or NULL.
 */
void noxtls_ecc_opaque_set_ecdhe_provider(const noxtls_crypto_provider_t *provider);

/**
 * @brief Generate an ephemeral key in the ECDHE provider and bind @p key to it.
 * @param[in,out] key Initialised key (noxtls_ecc_key_init); receives the public point.
 * @param[in] named_group TLS NamedGroup.
 * @return NOXTLS_RETURN_NOT_SUPPORTED when no provider is selected, the provider lacks the operations or serves
 *         other groups (caller uses software); else success or the provider/binding error.
 */
noxtls_return_t noxtls_ecc_opaque_ecdhe_generate(ecc_key_t *key, uint16_t named_group);

#endif /* NOXTLS_FEATURE_ATECC608 */

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_ECC_OPAQUE_H_ */

/** @} */
