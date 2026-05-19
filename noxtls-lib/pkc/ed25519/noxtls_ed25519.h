/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
*
* This file is part of the NoxTLS Library.
*
* File:    noxtls_ed25519.h
* Summary: Ed25519 digital signatures (RFC 8032)
*
*/

/** @addtogroup noxtls_pkc */
/** @{ */

#ifndef _NOXTLS_ED25519_H_
#define _NOXTLS_ED25519_H_

#include <stdint.h>

#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Private key (seed) length in bytes (RFC 8032). */
#define NOXTLS_ED25519_PRIVATE_KEY_SIZE  32U
/** Public key / encoded point length in bytes (RFC 8032). */
#define NOXTLS_ED25519_PUBLIC_KEY_SIZE     32U
/** Signature length in bytes (R || S, RFC 8032). */
#define NOXTLS_ED25519_SIGNATURE_SIZE      64U
/** Max context string length for Ed25519ctx (RFC 8032). */
#define NOXTLS_ED25519_CONTEXT_MAX         255U
/** Field element size in bytes (same as encoded curve point, RFC 8032). */
#define NOXTLS_ED25519_FE25519_BYTES       NOXTLS_ED25519_PRIVATE_KEY_SIZE
/** SHA-512 digest length in bytes. */
#define NOXTLS_ED25519_SHA512_DIGEST_BYTES 64U
/** Wide scalar buffer (product of two 32-byte scalars, LE). */
#define NOXTLS_ED25519_SCALAR_WIDE_BYTES   64U
/** Bignum product buffer for 32-by-32 multiply modulo p. */
#define NOXTLS_ED25519_BN_PRODUCT_BYTES    64U
/** Working buffer for fe25519_add partial sum (RFC 8032 field over GF(p)). */
#define NOXTLS_ED25519_BN_SUM_WORK_BYTES   64U
/** dom2() fixed ASCII literal length (RFC 8032). */
#define NOXTLS_ED25519_DOM2_LITERAL_BYTES  32U
/** dom2() prefix length: literal + phflag octet + ctx_len octet. */
#define NOXTLS_ED25519_DOM2_PREFIX_BYTES   34U
/** Byte index of phflag in dom2() buffer (after 32-byte literal). */
#define NOXTLS_ED25519_DOM2_PHFLAG_OCTET_INDEX NOXTLS_ED25519_DOM2_LITERAL_BYTES
/** Byte index of context length octet in dom2() buffer. */
#define NOXTLS_ED25519_DOM2_CTX_LEN_OCTET_INDEX (NOXTLS_ED25519_DOM2_LITERAL_BYTES + 1U)
/** Byte index where context bytes begin in dom2() buffer. */
#define NOXTLS_ED25519_DOM2_CTX_START_OCTET_INDEX NOXTLS_ED25519_DOM2_PREFIX_BYTES
/** Maximum dom2() buffer size: prefix plus maximum context string. */
#define NOXTLS_ED25519_DOM2_BUFFER_BYTES   (NOXTLS_ED25519_DOM2_LITERAL_BYTES + 1U + 1U + NOXTLS_ED25519_CONTEXT_MAX)
/** Scalar multiplication double-and-add loop count (255-bit field, LE bits). */
#define NOXTLS_ED25519_SCALAR_MULT_BITS    256U
/** Subgroup cofactor used in verification (RFC 8032). */
#define NOXTLS_ED25519_SUBGROUP_COFACTOR   8U
/** Ed25519 pure mode phflag for dom2 (RFC 8032). */
#define NOXTLS_ED25519_PH_FLAG_PURE        0U
/** Ed25519ph mode phflag for dom2 (RFC 8032). */
#define NOXTLS_ED25519_PH_FLAG_PREHASH     1U
/** Clamp low byte of expanded scalar (RFC 8032). */
#define NOXTLS_ED25519_SCALAR_CLAMP_BYTE0_MASK   0xF8U
/** Clamp high byte of expanded scalar, AND mask (RFC 8032). */
#define NOXTLS_ED25519_SCALAR_CLAMP_BYTE31_AND  0x7FU
/** Clamp high byte of expanded scalar, OR mask (RFC 8032). */
#define NOXTLS_ED25519_SCALAR_CLAMP_BYTE31_OR   0x40U
/** Clear sign bit when decoding compressed Y (RFC 8032). */
#define NOXTLS_ED25519_COMPRESSED_Y_SIGN_MASK     0x7FU
/** DRBG output length for private seed in bits (32 bytes). */
#define NOXTLS_ED25519_DRBG_SEED_BITS       256U


/* Extended homogeneous point (X, Y, Z, T) with T = X*Y/Z. All 32-byte BE. */
typedef struct 
{ 
    uint8_t X[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t Y[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t Z[NOXTLS_ED25519_FE25519_BYTES];
    uint8_t T[NOXTLS_ED25519_FE25519_BYTES];
     
} ge25519_pt_t;


/**
 * @brief Generate an Ed25519 key pair using the library DRBG.
 * @param private_key Output 32-byte seed (little-endian).
 * @param public_key Output 32-byte public key encoding.
 * @return NOXTLS_RETURN_SUCCESS on success, or an error code on failure.
 */
noxtls_return_t noxtls_ed25519_generate_key(uint8_t private_key[NOXTLS_ED25519_PRIVATE_KEY_SIZE],
                                            uint8_t public_key[NOXTLS_ED25519_PUBLIC_KEY_SIZE]);

/**
 * @brief Derive the public key from a 32-byte private seed (RFC 8032).
 * @param private_key Input 32-byte seed (little-endian).
 * @param public_key Output 32-byte public key encoding.
 * @return NOXTLS_RETURN_SUCCESS on success, or an error code on failure.
 */
noxtls_return_t noxtls_ed25519_public_key(const uint8_t private_key[NOXTLS_ED25519_PRIVATE_KEY_SIZE],
                                          uint8_t public_key[NOXTLS_ED25519_PUBLIC_KEY_SIZE]);

/**
 * @brief Sign a noxtls_message with Ed25519 (PureEdDSA, RFC 8032).
 * @param private_key Input 32-byte seed.
 * @param noxtls_message Message bytes (may be NULL if message_len is 0).
 * @param message_len Message length in bytes.
 * @param signature Output 64-byte signature (R || S).
 * @return NOXTLS_RETURN_SUCCESS on success, or an error code on failure.
 */
noxtls_return_t noxtls_ed25519_sign(const uint8_t private_key[NOXTLS_ED25519_PRIVATE_KEY_SIZE],
                                    const uint8_t *noxtls_message,
                                    uint32_t message_len,
                                    uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE]);

/**
 * @brief Verify an Ed25519 signature (RFC 8032).
 * @param public_key Input 32-byte public key encoding.
 * @param noxtls_message Message bytes (may be NULL if message_len is 0).
 * @param message_len Message length in bytes.
 * @param signature Input 64-byte signature (R || S).
 * @return NOXTLS_RETURN_SUCCESS if valid, NOXTLS_RETURN_FAILED if invalid, or another error code.
 */
noxtls_return_t noxtls_ed25519_verify(const uint8_t public_key[NOXTLS_ED25519_PUBLIC_KEY_SIZE],
                                      const uint8_t *noxtls_message,
                                      uint32_t message_len,
                                      const uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE]);

/**
 * @brief Sign with Ed25519ctx (RFC 8032): dom2(0, context) prepended to SHA-512 inputs.
 * @param private_key Input 32-byte seed.
 * @param context Context string (must be non-NULL if context_len is in 1..NOXTLS_ED25519_CONTEXT_MAX).
 * @param context_len Context length in bytes (1 through NOXTLS_ED25519_CONTEXT_MAX).
 * @param noxtls_message Message bytes (may be NULL if message_len is 0).
 * @param message_len Message length in bytes.
 * @param signature Output 64-byte signature (R || S).
 * @return NOXTLS_RETURN_SUCCESS on success, or an error code on failure.
 */
noxtls_return_t noxtls_ed25519ctx_sign(const uint8_t private_key[NOXTLS_ED25519_PRIVATE_KEY_SIZE],
                                       const uint8_t *context,
                                       uint32_t context_len,
                                       const uint8_t *noxtls_message,
                                       uint32_t message_len,
                                       uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE]);

/**
 * @brief Verify Ed25519ctx signature (RFC 8032).
 * @param public_key Input 32-byte public key encoding.
 * @param context Context string used when signing.
 * @param context_len Context length in bytes (1 through NOXTLS_ED25519_CONTEXT_MAX).
 * @param noxtls_message Message bytes (may be NULL if message_len is 0).
 * @param message_len Message length in bytes.
 * @param signature Input 64-byte signature (R || S).
 * @return NOXTLS_RETURN_SUCCESS if valid, NOXTLS_RETURN_FAILED if invalid, or another error code.
 */
noxtls_return_t noxtls_ed25519ctx_verify(const uint8_t public_key[NOXTLS_ED25519_PUBLIC_KEY_SIZE],
                                         const uint8_t *context,
                                         uint32_t context_len,
                                         const uint8_t *noxtls_message,
                                         uint32_t message_len,
                                         const uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE]);

/**
 * @brief Sign with Ed25519ph (RFC 8032): PH(M) = SHA-512(M); dom2(1, "") prepended to hash inputs.
 * @param private_key Input 32-byte seed.
 * @param noxtls_message Message bytes (may be NULL if message_len is 0).
 * @param message_len Message length in bytes.
 * @param signature Output 64-byte signature (R || S).
 * @return NOXTLS_RETURN_SUCCESS on success, or an error code on failure.
 */
noxtls_return_t noxtls_ed25519ph_sign(const uint8_t private_key[NOXTLS_ED25519_PRIVATE_KEY_SIZE],
                                      const uint8_t *noxtls_message,
                                      uint32_t message_len,
                                      uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE]);

/**
 * @brief Verify Ed25519ph signature (RFC 8032).
 * @param public_key Input 32-byte public key encoding.
 * @param noxtls_message Message bytes (may be NULL if message_len is 0).
 * @param message_len Message length in bytes.
 * @param signature Input 64-byte signature (R || S).
 * @return NOXTLS_RETURN_SUCCESS if valid, NOXTLS_RETURN_FAILED if invalid, or another error code.
 */
noxtls_return_t noxtls_ed25519ph_verify(const uint8_t public_key[NOXTLS_ED25519_PUBLIC_KEY_SIZE],
                                        const uint8_t *noxtls_message,
                                        uint32_t message_len,
                                        const uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_ED25519_H_ */
