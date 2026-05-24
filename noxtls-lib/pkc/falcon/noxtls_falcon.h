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
* File:    noxtls_falcon.h
* Summary: Falcon/FN-DSA API surface.
*
*****************************************************************************/

#ifndef _NOXTLS_FALCON_H_
#define _NOXTLS_FALCON_H_

#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Supported Falcon parameter sets.
 */
typedef enum
{
    NOXTLS_FALCON_NONE = 0,
    NOXTLS_FALCON_512 = 1,
    NOXTLS_FALCON_1024 = 2
} noxtls_falcon_param_t;

/** Maximum serialized Falcon public-key length across supported parameter sets. */
#define NOXTLS_FALCON_MAX_PUBLIC_KEY_LEN 1793u
/** Maximum serialized Falcon secret-key length across supported parameter sets. */
#define NOXTLS_FALCON_MAX_SECRET_KEY_LEN 2305u
/** Maximum serialized Falcon signature length across supported encodings. */
#define NOXTLS_FALCON_MAX_SIGNATURE_LEN 1577u

/**
 * @brief Get the exact serialized public-key length for a Falcon parameter set.
 *
 * @param[in] param Falcon parameter selector.
 * @return Public-key length in bytes, or `0` for an unsupported parameter.
 */
uint32_t noxtls_falcon_public_key_len(noxtls_falcon_param_t param);

/**
 * @brief Get the exact serialized secret-key length for a Falcon parameter set.
 *
 * @param[in] param Falcon parameter selector.
 * @return Secret-key length in bytes, or `0` for an unsupported parameter.
 */
uint32_t noxtls_falcon_secret_key_len(noxtls_falcon_param_t param);

/**
 * @brief Get the default fixed-width Falcon signature length for a parameter set.
 *
 * The current NoxTLS Falcon API uses the fixed-width padded signature form.
 *
 * @param[in] param Falcon parameter selector.
 * @return Signature length in bytes, or `0` for an unsupported parameter.
 */
uint32_t noxtls_falcon_signature_len(noxtls_falcon_param_t param);

/**
 * @brief Generate a Falcon keypair.
 *
 * @param[in] param Falcon parameter selector.
 * @param[out] public_key Output buffer for the serialized public key.
 * @param[in] public_key_len Size of `public_key` in bytes.
 * @param[out] secret_key Output buffer for the serialized secret key.
 * @param[in] secret_key_len Size of `secret_key` in bytes.
 * @return `NOXTLS_RETURN_SUCCESS` on success.
 * @return `NOXTLS_RETURN_NULL` if a required pointer is `NULL`.
 * @return `NOXTLS_RETURN_INVALID_PARAM` if `param` is unsupported.
 * @return `NOXTLS_RETURN_INVALID_BLOCK_SIZE` if a buffer length is incorrect.
 * @return `NOXTLS_RETURN_FAILED` if no valid Falcon keypair is found within the bounded retry loop.
 * @return `NOXTLS_RETURN_NOT_ENOUGH_ENTROPY` if the configured entropy source fails.
 */
noxtls_return_t noxtls_falcon_keygen(noxtls_falcon_param_t param,
                                     uint8_t *public_key,
                                     uint32_t public_key_len,
                                     uint8_t *secret_key,
                                     uint32_t secret_key_len);

/**
 * @brief Sign a message with a Falcon secret key.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] secret_key Serialized Falcon secret key.
 * @param[in] message Message bytes to sign. May be `NULL` only when `message_len` is `0`.
 * @param[in] message_len Length of `message` in bytes.
 * @param[out] signature Output buffer for the serialized signature.
 * @param[in,out] signature_len On input, signature buffer capacity. On output, actual signature length.
 * @return `NOXTLS_RETURN_SUCCESS` on success.
 * @return `NOXTLS_RETURN_NULL` if a required pointer is `NULL`.
 * @return `NOXTLS_RETURN_INVALID_PARAM` if `param` is unsupported.
 * @return `NOXTLS_RETURN_INVALID_BLOCK_SIZE` if the output buffer is too small.
 * @return `NOXTLS_RETURN_BAD_DATA` if the serialized secret key is malformed.
 * @return `NOXTLS_RETURN_FAILED` if signing cannot produce an acceptable short signature.
 * @return `NOXTLS_RETURN_NOT_ENOUGH_ENTROPY` if the configured entropy source fails.
 */
noxtls_return_t noxtls_falcon_sign(noxtls_falcon_param_t param,
                                   const uint8_t *secret_key,
                                   const uint8_t *message,
                                   uint32_t message_len,
                                   uint8_t *signature,
                                   uint32_t *signature_len);

/**
 * @brief Verify a Falcon signature.
 *
 * @param[in] param Falcon parameter selector.
 * @param[in] public_key Serialized Falcon public key.
 * @param[in] message Message bytes that were signed. May be `NULL` only when `message_len` is `0`.
 * @param[in] message_len Length of `message` in bytes.
 * @param[in] signature Serialized Falcon signature.
 * @param[in] signature_len Length of `signature` in bytes.
 * @return `NOXTLS_RETURN_SUCCESS` if the signature is valid.
 * @return `NOXTLS_RETURN_FAILED` if the signature is well-formed but invalid.
 * @return `NOXTLS_RETURN_BAD_DATA` if a serialized input is malformed.
 * @return `NOXTLS_RETURN_NULL` if a required pointer is `NULL`.
 * @return `NOXTLS_RETURN_INVALID_PARAM` if `param` is unsupported.
 */
noxtls_return_t noxtls_falcon_verify(noxtls_falcon_param_t param,
                                     const uint8_t *public_key,
                                     const uint8_t *message,
                                     uint32_t message_len,
                                     const uint8_t *signature,
                                     uint32_t signature_len);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_FALCON_H_ */
