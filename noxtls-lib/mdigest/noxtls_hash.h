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
* File:    noxtls_hash.h
* Summary: NoxTLS Generic Hash Interface Definition
*
*
*****************************************************************************/

/**
 * @defgroup noxtls_mdigest Message Digest
 * @brief Hash algorithms: MD4, MD5, SHA-1, SHA-2, SHA-3, RIPEMD-160, BLAKE2.
 * @addtogroup noxtls
 */
/** @{ */

#ifndef NOXTLS_HASH_H_
#define NOXTLS_HASH_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Byte length to bit length for Merkle–Damgård padding (octets carry 8 bits). */
#define NOXTLS_HASH_BITS_PER_BYTE (8U)
/** Bytes needed to store a 64-bit noxtls_message bit counter (SHA-1, SHA-256, MD5, etc.). */
#define NOXTLS_HASH_BITLEN_UINT64_BYTES (8U)

/**
 * Hash algorithm identifiers as unsigned macros (MISRA C:2025 Rule 10.3).
 * Numeric values match the historical enum order.
 */
typedef uint32_t noxtls_hash_algos_t;

#define NOXTLS_HASH_MD4          ((noxtls_hash_algos_t)0U)  /* MD4          RFC 1320 */
#define NOXTLS_HASH_MD5          ((noxtls_hash_algos_t)1U)  /* MD5          RFC 1321 */
#define NOXTLS_HASH_SHA1         ((noxtls_hash_algos_t)2U)  /* SHA-1        FIPS 180-4 */
#define NOXTLS_HASH_SHA_224      ((noxtls_hash_algos_t)3U)  /* SHA-224      FIPS 180-4 */
#define NOXTLS_HASH_SHA_256      ((noxtls_hash_algos_t)4U)  /* SHA-256      FIPS 180-4 */
#define NOXTLS_HASH_SHA_384      ((noxtls_hash_algos_t)5U)  /* SHA-384      FIPS 180-4 */
#define NOXTLS_HASH_SHA_512      ((noxtls_hash_algos_t)6U)  /* SHA-512      FIPS 180-4 */
#define NOXTLS_HASH_SHA_512_224  ((noxtls_hash_algos_t)7U)  /* SHA-512/224  FIPS 180-4 */
#define NOXTLS_HASH_SHA_512_256  ((noxtls_hash_algos_t)8U)  /* SHA-512/256  FIPS 180-4 */
#define NOXTLS_HASH_SHA3_224     ((noxtls_hash_algos_t)9U)  /* SHA3-224     FIPS 202 */
#define NOXTLS_HASH_SHA3_256     ((noxtls_hash_algos_t)10U) /* SHA3-256     FIPS 202 */
#define NOXTLS_HASH_SHA3_384     ((noxtls_hash_algos_t)11U) /* SHA3-384     FIPS 202 */
#define NOXTLS_HASH_SHA3_512     ((noxtls_hash_algos_t)12U) /* SHA3-512     FIPS 202 */
#define NOXTLS_HASH_RIPEMD160    ((noxtls_hash_algos_t)13U) /* RIPEMD-160   ISO/IEC 10118-3 */
#define NOXTLS_HASH_BLAKE2S_256  ((noxtls_hash_algos_t)14U) /* BLAKE2s-256  RFC 7693 */
#define NOXTLS_HASH_BLAKE2B_512  ((noxtls_hash_algos_t)15U) /* BLAKE2b-512  RFC 7693 */

void noxtls_add_padding_length(uint8_t * data, uint32_t block_size, uint64_t length, uint8_t length_size);
void noxtls_add_padding_length_little(uint8_t * data, uint32_t block_size, uint64_t length, uint8_t length_size);
void noxtls_print_hash(const uint8_t * hash, uint16_t len);

#ifdef __cplusplus
}
#endif

#endif
