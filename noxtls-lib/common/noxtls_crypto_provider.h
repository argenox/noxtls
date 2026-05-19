/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
*
* File:    noxtls_crypto_provider.h
* Summary: Optional abstraction for PKCS#11, TPM, or other hardware crypto.
*          When a provider is set on a TLS context, private-key operations
*          (sign, decrypt) can be delegated to the provider instead of
*          software keys. Leave provider NULL to use built-in software PKC.
*/

#ifndef _NOXTLS_CRYPTO_PROVIDER_H_
#define _NOXTLS_CRYPTO_PROVIDER_H_

#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Hash algorithm identifier for sign/verify. Values match noxtls_hash_algos_t
 * (e.g. NOXTLS_HASH_SHA_256 = 4). Include mdigest/noxtls_hash.h for the enum.
 */
typedef unsigned int noxtls_crypto_hash_algo_t;

/**
 * Opaque handle for a private key held by the provider (e.g. PKCS#11 object
 * handle, TPM key ref). The provider interprets this when performing ops.
 */
typedef void *noxtls_crypto_key_handle_t;

/**
 * Provider-specific context (e.g. PKCS#11 session, TPM connection).
 * Passed as first argument to all ops.
 */
typedef void *noxtls_crypto_provider_ctx_t;

/**
 * RSA sign with PSS (TLS 1.3 CertificateVerify, server/client).
 * \p key_handle  Provider's handle for the RSA private key.
 * \p noxtls_message    Data to sign (e.g. hash or full noxtls_message; same as noxtls_rsa_sign_pss).
 * \p message_len Length of \p noxtls_message.
 * \p signature  Output buffer for signature.
 * \p signature_len In: size of buffer; Out: actual signature length.
 * \p hash_algo  noxtls_crypto_hash_algo_t (e.g. NOXTLS_HASH_SHA_256).
 * Return NOXTLS_RETURN_SUCCESS on success.
 */
typedef noxtls_return_t (*noxtls_crypto_rsa_sign_pss_t)(
    noxtls_crypto_provider_ctx_t prov_ctx,
    noxtls_crypto_key_handle_t key_handle,
    const uint8_t *noxtls_message,
    uint32_t message_len,
    uint8_t *signature,
    uint32_t *signature_len,
    noxtls_crypto_hash_algo_t hash_algo);

/**
 * RSA sign with PKCS#1 v1.5 (TLS 1.2 ServerKeyExchange, DHE/ECDHE).
 * Same semantics as noxtls_rsa_sign.
 */
typedef noxtls_return_t (*noxtls_crypto_rsa_sign_t)(
    noxtls_crypto_provider_ctx_t prov_ctx,
    noxtls_crypto_key_handle_t key_handle,
    const uint8_t *noxtls_message,
    uint32_t message_len,
    uint8_t *signature,
    uint32_t *signature_len,
    noxtls_crypto_hash_algo_t hash_algo);

/**
 * RSA decrypt (TLS 1.2 RSA key exchange: Client Key Exchange).
 * \p ciphertext_len Typically key size in bytes (e.g. 256 for 2048-bit).
 * \p plaintext_len In: size of \p plaintext buffer; Out: actual plaintext length.
 */
typedef noxtls_return_t (*noxtls_crypto_rsa_decrypt_t)(
    noxtls_crypto_provider_ctx_t prov_ctx,
    noxtls_crypto_key_handle_t key_handle,
    const uint8_t *ciphertext,
    uint32_t ciphertext_len,
    uint8_t *plaintext,
    uint32_t *plaintext_len);

/**
 * Optional: RSA verify (public key). Used when verifying peer certs with
 * a key held in the provider. NULL = NoxTLS uses software verify.
 */
typedef noxtls_return_t (*noxtls_crypto_rsa_verify_pss_t)(
    noxtls_crypto_provider_ctx_t prov_ctx,
    noxtls_crypto_key_handle_t key_handle,
    const uint8_t *noxtls_message,
    uint32_t message_len,
    const uint8_t *signature,
    uint32_t signature_len,
    noxtls_crypto_hash_algo_t hash_algo);

/**
 * Optional: ECDSA sign (TLS 1.3 client CertificateVerify with ECDSA cert).
 * NULL = use software ECDSA when client key is software.
 */
typedef noxtls_return_t (*noxtls_crypto_ecdsa_sign_t)(
    noxtls_crypto_provider_ctx_t prov_ctx,
    noxtls_crypto_key_handle_t key_handle,
    const uint8_t *noxtls_message,
    uint32_t message_len,
    uint8_t *signature_der,
    uint32_t *signature_der_len,
    noxtls_crypto_hash_algo_t hash_algo);

/**
 * Optional: Ed25519 sign. NULL = use software Ed25519.
 */
typedef noxtls_return_t (*noxtls_crypto_ed25519_sign_t)(
    noxtls_crypto_provider_ctx_t prov_ctx,
    noxtls_crypto_key_handle_t key_handle,
    const uint8_t *noxtls_message,
    uint32_t message_len,
    uint8_t signature[64]);

/**
 * Optional: ML-DSA sign. signature_len is IN/OUT like RSA callbacks.
 */
typedef noxtls_return_t (*noxtls_crypto_mldsa_sign_t)(
    noxtls_crypto_provider_ctx_t prov_ctx,
    noxtls_crypto_key_handle_t key_handle,
    uint16_t mldsa_param,
    const uint8_t *noxtls_message,
    uint32_t message_len,
    uint8_t *signature,
    uint32_t *signature_len);

/**
 * Optional: ML-KEM encapsulation using provider-held public key.
 */
typedef noxtls_return_t (*noxtls_crypto_mlkem_encaps_t)(
    noxtls_crypto_provider_ctx_t prov_ctx,
    noxtls_crypto_key_handle_t key_handle,
    uint16_t mlkem_param,
    uint8_t *ciphertext,
    uint32_t *ciphertext_len,
    uint8_t shared_secret[32]);

/**
 * Optional: ML-KEM decapsulation using provider-held private key.
 */
typedef noxtls_return_t (*noxtls_crypto_mlkem_decaps_t)(
    noxtls_crypto_provider_ctx_t prov_ctx,
    noxtls_crypto_key_handle_t key_handle,
    uint16_t mlkem_param,
    const uint8_t *ciphertext,
    uint32_t ciphertext_len,
    uint8_t shared_secret[32]);

/**
 * Operations table for a crypto provider. Set unused ops to NULL;
 * NoxTLS will use software for those operations.
 */
typedef struct noxtls_crypto_provider_ops_s
{
    noxtls_crypto_rsa_sign_pss_t   rsa_sign_pss;
    noxtls_crypto_rsa_sign_t       rsa_sign;
    noxtls_crypto_rsa_decrypt_t    rsa_decrypt;
    noxtls_crypto_rsa_verify_pss_t rsa_verify_pss;   /* optional */
    noxtls_crypto_ecdsa_sign_t     ecdsa_sign;       /* optional */
    noxtls_crypto_ed25519_sign_t   ed25519_sign;     /* optional */
    noxtls_crypto_mldsa_sign_t     mldsa_sign;       /* optional */
    noxtls_crypto_mlkem_encaps_t   mlkem_encaps;     /* optional */
    noxtls_crypto_mlkem_decaps_t   mlkem_decaps;     /* optional */
} noxtls_crypto_provider_ops_t;

/**
 * Crypto provider: context + ops. Register this on a TLS context to use
 * hardware or external keys for sign/decrypt. Leave NULL to use only software.
 */
typedef struct noxtls_crypto_provider_s
{
    noxtls_crypto_provider_ctx_t       ctx;
    const noxtls_crypto_provider_ops_t *ops;
} noxtls_crypto_provider_t;

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_CRYPTO_PROVIDER_H_ */
