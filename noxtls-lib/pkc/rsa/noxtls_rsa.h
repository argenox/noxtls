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
* File:    noxtls_rsa.h
* Summary: RSA Public Key Cryptography
*
*/

/** @addtogroup noxtls_pkc */
/** @{ */

#ifndef _NOXTLS_RSA_H_
#define _NOXTLS_RSA_H_

#include <stdint.h>
#include "noxtls_common.h"
#include "mdigest/noxtls_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RSA_MAX_KEY_SIZE 4096
#define RSA_MIN_KEY_SIZE 1024

typedef enum
{
    RSA_1024_BIT = 1024,
    RSA_2048_BIT = 2048,
    RSA_3072_BIT = 3072,
    RSA_4096_BIT = 4096,
} rsa_key_size_t;

typedef struct
{
    uint8_t *n;          /* Modulus */
    uint8_t *e;          /* Public exponent */
    uint8_t *d;          /* Private exponent */
    uint8_t *p;          /* Prime p (for CRT) */
    uint8_t *q;          /* Prime q (for CRT) */
    uint8_t *dp;         /* d mod (p-1) */
    uint8_t *dq;         /* d mod (q-1) */
    uint8_t *qi;         /* q^-1 mod p */
    uint32_t key_size;   /* Key size in bits */
    uint32_t key_bytes;  /* Key size in bytes */
} rsa_key_t;

/* RSA Key Management */
noxtls_return_t noxtls_rsa_key_init(rsa_key_t *key, rsa_key_size_t key_size);
noxtls_return_t noxtls_rsa_key_generate(rsa_key_t *key, rsa_key_size_t key_size);
noxtls_return_t noxtls_rsa_key_free(rsa_key_t *key);

/* RSA Encryption/Decryption */
noxtls_return_t noxtls_rsa_encrypt(const rsa_key_t *key, const uint8_t *plaintext, uint32_t plaintext_len, uint8_t *ciphertext, uint32_t *ciphertext_len);
noxtls_return_t noxtls_rsa_decrypt(const rsa_key_t *key, const uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *plaintext, uint32_t *plaintext_len);

/**
 * RSA decrypt using CRT path only (for unit testing).
 * Returns FAILED if key has no CRT params or CRT decryption fails.
 */
noxtls_return_t noxtls_rsa_decrypt_crt_only(const rsa_key_t *key, const uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *plaintext, uint32_t *plaintext_len);

/* RSA Signatures */
noxtls_return_t noxtls_rsa_sign(const rsa_key_t *key, const uint8_t *message, uint32_t message_len, uint8_t *signature, uint32_t *signature_len, noxtls_hash_algos_t hash_algo);
noxtls_return_t noxtls_rsa_verify(const rsa_key_t *key, const uint8_t *message, uint32_t message_len, const uint8_t *signature, uint32_t signature_len, noxtls_hash_algos_t hash_algo);

/* RSA-PSS Signatures (RFC 8017; TLS 1.3 CertificateVerify) */
noxtls_return_t noxtls_rsa_sign_pss(const rsa_key_t *key, const uint8_t *message, uint32_t message_len, uint8_t *signature, uint32_t *signature_len, noxtls_hash_algos_t hash_algo);
noxtls_return_t noxtls_rsa_verify_pss(const rsa_key_t *key, const uint8_t *message, uint32_t message_len, const uint8_t *signature, uint32_t signature_len, noxtls_hash_algos_t hash_algo);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_RSA_H_ */

