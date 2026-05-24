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
* File:    noxtls_ed448.h
* Summary: Ed448 digital signatures (RFC 8032)
*
*
*****************************************************************************/

/** @addtogroup noxtls_pkc */
/** @{ */

#ifndef _NOXTLS_ED448_H_
#define _NOXTLS_ED448_H_

#include <stdint.h>

#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Private key (seed) length in bytes (RFC 8032). */
#define NOXTLS_ED448_PRIVATE_KEY_SIZE       57U
/** Public key / encoded point length in bytes (RFC 8032). */
#define NOXTLS_ED448_PUBLIC_KEY_SIZE        57U
/** Signature length in bytes (R || S, RFC 8032). */
#define NOXTLS_ED448_SIGNATURE_SIZE         114U
/** Max context string length for Ed448ctx (RFC 8032). */
#define NOXTLS_ED448_CONTEXT_MAX            255U
/** Field element size in bytes (big-endian internal limb, RFC 8032). */
#define NOXTLS_ED448_FE448_BYTES            56U
/** SHAKE256 wide output used for scalar hashing (RFC 8032). */
#define NOXTLS_ED448_SHAKE_WIDE_BYTES       114U
/** Ed448ph: first octets of SHAKE256(M) used as noxtls_message representative (RFC 8032). */
#define NOXTLS_ED448_PH_DIGEST_BYTES         64U
/** Bignum product buffer for 56-by-56 multiply modulo p. */
#define NOXTLS_ED448_BN_PRODUCT_BYTES        112U
/** dom4() fixed ASCII literal length ("SigEd448"). */
#define NOXTLS_ED448_DOM4_LITERAL_BYTES       8U
/** dom4() fixed prefix length: literal + phflag + ctx_len octets. */
#define NOXTLS_ED448_DOM4_PREFIX_BYTES       10U
/** Maximum dom4() buffer size: prefix plus maximum context string. */
#define NOXTLS_ED448_DOM4_BUFFER_BYTES      (NOXTLS_ED448_DOM4_PREFIX_BYTES + NOXTLS_ED448_CONTEXT_MAX)
/** Scalar multiplication loop count (448 scalar bits, RFC 8032). */
#define NOXTLS_ED448_SCALAR_MULT_BITS       448U
/** Ed448 pure mode phflag for dom4 (RFC 8032). */
#define NOXTLS_ED448_PH_FLAG_PURE             0U
/** Ed448ph mode phflag for dom4 (RFC 8032). */
#define NOXTLS_ED448_PH_FLAG_PREHASH         1U
/** Clamp low byte of expanded scalar (RFC 8032). */
#define NOXTLS_ED448_SCALAR_CLAMP_BYTE0_MASK    0xFCU
/** Clamp high byte of expanded scalar, AND mask (RFC 8032). */
#define NOXTLS_ED448_SCALAR_CLAMP_BYTE55_AND    0x7FU
/** Clamp high byte of expanded scalar, OR mask (RFC 8032). */
#define NOXTLS_ED448_SCALAR_CLAMP_BYTE55_OR    0x40U
/** Clear sign bit when decoding compressed Y (RFC 8032). */
#define NOXTLS_ED448_COMPRESSED_Y_SIGN_MASK    0x7FU
/** Cofactor ladder for verification (RFC 8032). */
#define NOXTLS_ED448_VERIFY_COFACTOR            4U
/** DRBG entropy length in bits for a 57-byte private seed. */
#define NOXTLS_ED448_DRBG_SEED_BITS           456U

/**
 * @brief Generate an Ed448 key pair using the library DRBG.
 * @param private_key Output 57-byte seed.
 * @param public_key Output 57-byte public key encoding.
 * @return NOXTLS_RETURN_SUCCESS on success, or an error code on failure.
 */
noxtls_return_t noxtls_ed448_generate_key(uint8_t private_key[NOXTLS_ED448_PRIVATE_KEY_SIZE],
                                          uint8_t public_key[NOXTLS_ED448_PUBLIC_KEY_SIZE]);

/**
 * @brief Derive the public key from a 57-byte private seed (RFC 8032).
 * @param private_key Input 57-byte seed.
 * @param public_key Output 57-byte public key encoding.
 * @return NOXTLS_RETURN_SUCCESS on success, or an error code on failure.
 */
noxtls_return_t noxtls_ed448_public_key(const uint8_t private_key[NOXTLS_ED448_PRIVATE_KEY_SIZE],
                                        uint8_t public_key[NOXTLS_ED448_PUBLIC_KEY_SIZE]);

/**
 * @brief Sign a noxtls_message with Ed448 (PureEdDSA, RFC 8032).
 * @param private_key 57-byte private key.
 * @param noxtls_message Message bytes.
 * @param message_len Length of @p noxtls_message in bytes.
 * @param signature Output 114-byte signature (R || S).
 * @return NOXTLS_RETURN_SUCCESS on success, or an error code on failure.
 */
noxtls_return_t noxtls_ed448_sign(const uint8_t private_key[NOXTLS_ED448_PRIVATE_KEY_SIZE],
                                  const uint8_t *noxtls_message,
                                  uint32_t message_len,
                                  uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE]);

/**
 * @brief Verify an Ed448 signature (RFC 8032).
 * @param public_key 57-byte public key encoding.
 * @param noxtls_message Message that was signed.
 * @param message_len Length of @p noxtls_message in bytes.
 * @param signature 114-byte signature.
 * @return NOXTLS_RETURN_SUCCESS if valid, otherwise an error code.
 */
noxtls_return_t noxtls_ed448_verify(const uint8_t public_key[NOXTLS_ED448_PUBLIC_KEY_SIZE],
                                    const uint8_t *noxtls_message,
                                    uint32_t message_len,
                                    const uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE]);

/**
 * @brief Sign with Ed448ctx (RFC 8032); context length 1..NOXTLS_ED448_CONTEXT_MAX.
 * @param private_key 57-byte private key.
 * @param context Context string.
 * @param context_len Length of @p context in bytes.
 * @param noxtls_message Message to sign.
 * @param message_len Length of @p noxtls_message in bytes.
 * @param signature Output 114-byte signature.
 * @return NOXTLS_RETURN_SUCCESS on success, or an error code on failure.
 */
noxtls_return_t noxtls_ed448ctx_sign(const uint8_t private_key[NOXTLS_ED448_PRIVATE_KEY_SIZE],
                                     const uint8_t *context,
                                     uint32_t context_len,
                                     const uint8_t *noxtls_message,
                                     uint32_t message_len,
                                     uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE]);

/**
 * @brief Verify an Ed448ctx signature (RFC 8032).
 * @param public_key 57-byte public key encoding.
 * @param context Context string used when signing.
 * @param context_len Length of @p context in bytes.
 * @param noxtls_message Message that was signed.
 * @param message_len Length of @p noxtls_message in bytes.
 * @param signature 114-byte signature.
 * @return NOXTLS_RETURN_SUCCESS if valid, otherwise an error code.
 */
noxtls_return_t noxtls_ed448ctx_verify(const uint8_t public_key[NOXTLS_ED448_PUBLIC_KEY_SIZE],
                                       const uint8_t *context,
                                       uint32_t context_len,
                                       const uint8_t *noxtls_message,
                                       uint32_t message_len,
                                       const uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE]);

/**
 * @brief Sign with Ed448ph: PH(M) is the first 64 bytes of SHAKE256(M) (RFC 8032).
 * @param private_key 57-byte private key.
 * @param noxtls_message Input to SHAKE256.
 * @param message_len Length of @p noxtls_message in bytes.
 * @param signature Output 114-byte signature.
 * @return NOXTLS_RETURN_SUCCESS on success, or an error code on failure.
 */
noxtls_return_t noxtls_ed448ph_sign(const uint8_t private_key[NOXTLS_ED448_PRIVATE_KEY_SIZE],
                                    const uint8_t *noxtls_message,
                                    uint32_t message_len,
                                    uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE]);

/**
 * @brief Verify an Ed448ph signature (RFC 8032).
 * @param public_key 57-byte public key encoding.
 * @param noxtls_message Same prehash input that was signed.
 * @param message_len Length of @p noxtls_message in bytes.
 * @param signature 114-byte signature.
 * @return NOXTLS_RETURN_SUCCESS if valid, otherwise an error code.
 */
noxtls_return_t noxtls_ed448ph_verify(const uint8_t public_key[NOXTLS_ED448_PUBLIC_KEY_SIZE],
                                      const uint8_t *noxtls_message,
                                      uint32_t message_len,
                                      const uint8_t signature[NOXTLS_ED448_SIGNATURE_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_ED448_H_ */
