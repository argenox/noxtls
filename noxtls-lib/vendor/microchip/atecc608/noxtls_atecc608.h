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
* File:    noxtls_atecc608.h
* Summary: Microchip ATECC608B/C crypto provider (keys that never leave the secure element)
*
*****************************************************************************/

/**
 * @file noxtls_atecc608.h
 * @brief NoxTLS crypto provider for the Microchip ATECC608B / ATECC608C secure element.
 *
 * Enabled with NOXTLS_FEATURE_ATECC608 (CMake NOXTLS_CFG_FEATURE_ATECC608, default OFF).
 *
 * The provider delegates three things to the chip:
 *  - ECDSA P-256 signing with a slot key (TLS CertificateVerify, ServerKeyExchange): a key bound with
 *    noxtls_atecc608_bind_ecc_key() looks like an ordinary public ecc_key_t to NoxTLS, so
 *    noxtls_tls13_set_server_private_ecdsa(), noxtls_tls13_set_client_cert_ecdsa() and the TLS 1.2
 *    equivalents accept it unchanged.
 *  - ECDHE: noxtls_atecc608_register_ecdhe() makes TLS generate its P-256 ephemeral keys inside the chip
 *    (GenKey into a configured ephemeral slot or TempKey) and compute the shared secret there. Other groups
 *    keep using software.
 *  - Entropy for the DRBG (NOXTLS_FEATURE_ATECC608_ENTROPY): noxtls_atecc608_set_entropy_backend().
 *
 * The chip is reached through a small backend table so this code does not depend on any driver. The NoxSensor
 * ATECC608 driver binding is in noxtls_atecc608_noxsensor.h (NOXTLS_CFG_ATECC608_NOXSENSOR).
 *
 * SHA-256 and HKDF are deliberately NOT offloaded: each I2C command moves at least a 64 byte block plus about
 * 1 ms of protocol overhead and the chip needs a watchdog-bounded session, while software SHA-256 on a Cortex-M
 * class MCU takes a few microseconds per block (hardware engines such as CRACEN are faster still).
 */
#ifndef NOXTLS_ATECC608_H_
#define NOXTLS_ATECC608_H_

#include <stdint.h>

#include "noxtls_common.h"
#include "common/noxtls_crypto_provider.h"
#include "pkc/ecc/noxtls_ecc.h"

#ifdef __cplusplus
extern "C" {
#endif

#if NOXTLS_FEATURE_ATECC608

/** Key id selecting TempKey (a volatile ephemeral key) instead of a slot. */
#define NOXTLS_ATECC608_KEYID_TEMPKEY 0xFFFFU

/** Largest number of ephemeral key ids a provider rotates through. */
#ifndef NOXTLS_ATECC608_EPHEMERAL_MAX
#define NOXTLS_ATECC608_EPHEMERAL_MAX 4U
#endif

/**
 * @brief Operations the provider needs from the chip. Every function returns 0 on success.
 *
 * The backend must serialise access to the device (a mutex around the whole call is enough: the NoxSensor
 * helpers already wrap each operation in one wake/sleep session).
 */
typedef struct
{
    void *device;                                                                                      /**< Opaque device context. */
    int (*get_public_key)(void *device, uint8_t slot, uint8_t pub_xy[64]);                             /**< Public key of a slot. */
    int (*sign_digest)(void *device, uint8_t slot, const uint8_t digest[32], uint8_t sig_rs[64]);      /**< ECDSA sign a 32 byte digest. */
    int (*ecdh_keygen)(void *device, uint16_t key_id, uint8_t pub_xy[64]);                             /**< GenKey into a slot or TempKey. */
    int (*ecdh)(void *device, uint16_t key_id, const uint8_t peer_xy[64], uint8_t secret[32]);         /**< ECDH with a slot or the TempKey key. */
    int (*random)(void *device, uint8_t *out, uint32_t len);                                           /**< Chip RNG. */
} noxtls_atecc608_backend_t;

/** @brief Handle for a key in the chip: the device and the slot (or NOXTLS_ATECC608_KEYID_TEMPKEY). */
typedef struct
{
    const noxtls_atecc608_backend_t *backend; /**< Device. */
    uint16_t key_id;                          /**< Slot 0..15 or NOXTLS_ATECC608_KEYID_TEMPKEY. */
} noxtls_atecc608_key_t;

/** @brief Provider instance (caller allocated, must outlive every context that uses it). */
typedef struct
{
    noxtls_crypto_provider_ops_t ops;                              /**< Operations table. */
    noxtls_crypto_provider_t provider;                             /**< Value to register with NoxTLS. */
    const noxtls_atecc608_backend_t *backend;                      /**< Device for ephemeral keys. */
    uint16_t ephemeral_ids[NOXTLS_ATECC608_EPHEMERAL_MAX];         /**< Key ids tried round robin. */
    noxtls_atecc608_key_t ephemeral_keys[NOXTLS_ATECC608_EPHEMERAL_MAX]; /**< Handles handed to NoxTLS. */
    uint8_t ephemeral_count;                                       /**< Number of ephemeral ids. */
    uint8_t ephemeral_next;                                        /**< Next id to use. */
} noxtls_atecc608_provider_t;

/**
 * @brief Initialise a provider.
 * @param[out] p Provider instance.
 * @param[in] backend Device backend (must outlive @p p).
 * @param[in] ephemeral_ids Key ids for TLS ECDHE ephemeral keys (slots with GenKey + ECDH enabled, or
 *            NOXTLS_ATECC608_KEYID_TEMPKEY); NULL or count 0 disables opaque ECDHE. Using several ids lets
 *            concurrent handshakes (client and server in one process) hold distinct keys.
 * @param[in] ephemeral_count Number of ids (at most NOXTLS_ATECC608_EPHEMERAL_MAX).
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_NULL / NOXTLS_RETURN_INVALID_PARAM.
 */
noxtls_return_t noxtls_atecc608_provider_init(noxtls_atecc608_provider_t *p, const noxtls_atecc608_backend_t *backend,
                                              const uint16_t *ephemeral_ids, uint8_t ephemeral_count);

/** @brief The provider value to register (valid while @p p lives). */
const noxtls_crypto_provider_t *noxtls_atecc608_provider_get(const noxtls_atecc608_provider_t *p);

/** @brief Fill a key handle. */
void noxtls_atecc608_key_init(noxtls_atecc608_key_t *key, const noxtls_atecc608_backend_t *backend, uint16_t key_id);

/**
 * @brief Make @p ecc_key a public-only P-256 key whose private part lives in the chip.
 *
 * Reads the slot's public key, initialises @p ecc_key (noxtls_ecc_key_init) and binds it to the provider
 * (noxtls_ecc_opaque_bind). Pass the key to the usual NoxTLS setters; noxtls_ecc_key_free() unbinds it.
 *
 * @param[in] p Provider.
 * @param[in] key Chip key handle (must outlive the binding).
 * @param[out] ecc_key Key to fill (must stay at this address while bound).
 * @return NOXTLS_RETURN_SUCCESS or an error (NOXTLS_RETURN_FAILED when the chip cannot be read).
 */
noxtls_return_t noxtls_atecc608_bind_ecc_key(const noxtls_atecc608_provider_t *p, const noxtls_atecc608_key_t *key, ecc_key_t *ecc_key);

/** @brief Make TLS ECDHE (secp256r1) use the chip's ephemeral keys; pass NULL to go back to software. */
void noxtls_atecc608_register_ecdhe(const noxtls_atecc608_provider_t *p);

#if NOXTLS_FEATURE_ATECC608_ENTROPY
/**
 * @brief Select the chip RNG as the DRBG entropy hook (noxtls_drbg_entropy_accel_port).
 * @param[in] backend Backend with @c random, or NULL to disable (the hook then reports NOT_SUPPORTED).
 */
void noxtls_atecc608_set_entropy_backend(const noxtls_atecc608_backend_t *backend);
#endif

#endif /* NOXTLS_FEATURE_ATECC608 */

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_ATECC608_H_ */
