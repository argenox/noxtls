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
* File:    noxtls_rsa.h
* Summary: RSA Public Key Cryptography
*
*
*****************************************************************************/

/** @addtogroup noxtls_pkc */
/** @{ */

#ifndef NOXTLS_RSA_H_
#define NOXTLS_RSA_H_

#include <stdint.h>
#include "noxtls_common.h"
#include "mdigest/noxtls_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RSA_MAX_KEY_SIZE 4096U
#define RSA_MIN_KEY_SIZE 1024U

typedef uint32_t rsa_key_size_t;
#define RSA_1024_BIT ((rsa_key_size_t)1024U)
#define RSA_2048_BIT ((rsa_key_size_t)2048U)
#define RSA_3072_BIT ((rsa_key_size_t)3072U)
#define RSA_4096_BIT ((rsa_key_size_t)4096U)

typedef struct
{
    uint8_t *n;          /* Modulus (key_bytes, big-endian) */
    uint8_t *e;          /* Public exponent (e_len bytes, big-endian) */
    uint8_t *d;          /* Private exponent (key_bytes); NULL for a public-only key */
    uint8_t *p;          /* Prime p (for CRT, key_bytes / 2); NULL for a public-only key */
    uint8_t *q;          /* Prime q (for CRT) */
    uint8_t *dp;         /* d mod (p-1) */
    uint8_t *dq;         /* d mod (q-1) */
    uint8_t *qi;         /* q^-1 mod p */
    uint32_t key_size;   /* Key size in bits */
    uint32_t key_bytes;  /* Key size in bytes */
    uint32_t e_len;      /* Length of the e buffer in bytes; key_bytes after noxtls_rsa_key_init
                          * (0 is treated as key_bytes for keys built without an init call) */
} rsa_key_t;

/* RSA Key Management */
/* Full key: allocates n, e, d (key_bytes each) and p, q, dp, dq, qi (key_bytes / 2 each),
 * all zeroed except e = 65537; the caller fills the components. */
noxtls_return_t noxtls_rsa_key_init(rsa_key_t *key, rsa_key_size_t key_size);
/**
 * Public-only key for verify / verify_pss / encrypt: allocates only n (key_bytes) and e
 * (e_len bytes after stripping leading zeros) and copies both in; d, p, q, dp, dq and qi
 * stay NULL. Private-key operations on such a key fail with NOXTLS_RETURN_INVALID_PARAM;
 * free it with noxtls_rsa_key_free(). @p n may have leading zero bytes (DER INTEGER
 * padding); its significant length must not exceed key_size / 8.
 * RSA-2048: 256 + 3 bytes of key buffers instead of 1408 (RSA-4096: 515 instead of 2816).
 *
 * @return NOXTLS_RETURN_SUCCESS; NOXTLS_RETURN_NULL for NULL pointers; NOXTLS_RETURN_FAILED
 *         for an unsupported key_size; NOXTLS_RETURN_INVALID_PARAM for an empty/zero or
 *         oversized n or e; NOXTLS_RETURN_NOT_ENOUGH_MEMORY.
 */
noxtls_return_t noxtls_rsa_key_init_public(rsa_key_t *key, rsa_key_size_t key_size,
                                           const uint8_t *n, uint32_t n_len,
                                           const uint8_t *e, uint32_t e_len);
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
noxtls_return_t noxtls_rsa_sign(const rsa_key_t *key, const uint8_t *noxtls_message, uint32_t message_len, uint8_t *signature, uint32_t *signature_len, noxtls_hash_algos_t hash_algo);
noxtls_return_t noxtls_rsa_verify(const rsa_key_t *key, const uint8_t *noxtls_message, uint32_t message_len, const uint8_t *signature, uint32_t signature_len, noxtls_hash_algos_t hash_algo);
/** PKCS#1 v1.5 signature over a precomputed digest of @p hash_algo (e.g. TLS 1.2 CertificateVerify). */
noxtls_return_t noxtls_rsa_sign_digest(const rsa_key_t *key, const uint8_t *digest, uint32_t digest_len, uint8_t *signature, uint32_t *signature_len, noxtls_hash_algos_t hash_algo);

/* RSA-PSS Signatures (RFC 8017; TLS 1.3 CertificateVerify) */
noxtls_return_t noxtls_rsa_sign_pss(const rsa_key_t *key, const uint8_t *noxtls_message, uint32_t message_len, uint8_t *signature, uint32_t *signature_len, noxtls_hash_algos_t hash_algo);
noxtls_return_t noxtls_rsa_verify_pss(const rsa_key_t *key, const uint8_t *noxtls_message, uint32_t message_len, const uint8_t *signature, uint32_t signature_len, noxtls_hash_algos_t hash_algo);
/** RSASSA-PSS verification against a precomputed digest of @p hash_algo (SHA-256/384/512, salt = hash length). */
noxtls_return_t noxtls_rsa_verify_pss_digest(const rsa_key_t *key, const uint8_t *digest, uint32_t digest_len, const uint8_t *signature, uint32_t signature_len, noxtls_hash_algos_t hash_algo);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_RSA_H_ */

