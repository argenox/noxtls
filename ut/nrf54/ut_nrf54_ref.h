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
* File:    ut_nrf54_ref.h
* Summary: Reference AES / SHA-2 / GCM / CCM used as the oracle of the CRACEN mock
*
*****************************************************************************/


/**
 * @file ut_nrf54_ref.h
 * @brief Small reference implementations of AES (FIPS 197) and the SHA-2
 *        compression functions (FIPS 180-4) used by the CRACEN mock.
 * @ingroup noxtls_nrf54_ut
 *
 * Test code only (not for production use: no side-channel protection). The
 * implementations are themselves checked against the FIPS 197 Appendix C and
 * FIPS 180-4 example vectors in test_ut_ref.c.
 */

/**
 * @defgroup noxtls_nrf54_ut NoxTLS nRF54 CRACEN unit tests
 * @brief UTNox host tests of the NoxTLS nRF54L CRACEN backend against a functional CRACEN mock.
 */

#ifndef UT_NRF54_REF_H
#define UT_NRF54_REF_H

#include <stdint.h>

/** AES block size. */
#define UT_AES_BLOCK        16U
/** Largest expanded key (AES-256: 15 round keys). */
#define UT_AES_RK_WORDS     60U

/** Expanded AES key. */
typedef struct {
    uint32_t rk[UT_AES_RK_WORDS]; /**< Round keys (big-endian words). */
    uint32_t rounds;              /**< 10, 12 or 14. */
} ut_aes_key_t;

/**
 * @brief Expand an AES key (FIPS 197 §5.2).
 *
 * @param[out] k       Expanded key.
 * @param[in]  key     Key bytes.
 * @param[in]  key_len 16, 24 or 32.
 *
 * @return 0 on success, -1 for a bad length.
 */
int ut_aes_setkey(ut_aes_key_t * k, const uint8_t * key, uint32_t key_len);

/**
 * @brief Encrypt one block (FIPS 197 §5.1).
 *
 * @param[in]  k   Expanded key.
 * @param[in]  in  Plaintext block.
 * @param[out] out Ciphertext block.
 */
void ut_aes_encrypt(const ut_aes_key_t * k, const uint8_t * in, uint8_t * out);

/**
 * @brief Decrypt one block (FIPS 197 §5.3 inverse cipher).
 *
 * @param[in]  k   Expanded key.
 * @param[in]  in  Ciphertext block.
 * @param[out] out Plaintext block.
 */
void ut_aes_decrypt(const ut_aes_key_t * k, const uint8_t * in, uint8_t * out);

/**
 * @brief Load the FIPS 180-4 §5.3 initial hash value of an algorithm.
 *
 * @param[in]  bits  Digest bits: 224, 256, 384 or 512.
 * @param[out] state State bytes (32 or 64, big-endian words as the BA413 exports them).
 *
 * @return State size in bytes, 0 for an unknown algorithm.
 */
uint32_t ut_sha_iv(uint32_t bits, uint8_t * state);

/**
 * @brief SHA-256 compression of one 64-byte block on a byte-serialised state.
 *
 * @param[in,out] state 32-byte big-endian state.
 * @param[in]     block 64-byte block.
 */
void ut_sha256_block(uint8_t * state, const uint8_t * block);

/**
 * @brief SHA-512 compression of one 128-byte block on a byte-serialised state.
 *
 * @param[in,out] state 64-byte big-endian state.
 * @param[in]     block 128-byte block.
 */
void ut_sha512_block(uint8_t * state, const uint8_t * block);

/**
 * @brief Whole-message SHA-2 (software reference, used to cross-check the driver).
 *
 * @param[in]  bits   224, 256, 384 or 512.
 * @param[in]  msg    Message.
 * @param[in]  len    Bytes.
 * @param[out] digest Digest (bits / 8 bytes).
 */
void ut_sha(uint32_t bits, const uint8_t * msg, uint32_t len, uint8_t * digest);

/**
 * @brief Parse a hex string (spaces ignored) into bytes.
 *
 * @param[in]  hex Hex text.
 * @param[out] out Destination.
 * @param[in]  max Destination size.
 *
 * @return Bytes written.
 */
uint32_t ut_hex(const char * hex, uint8_t * out, uint32_t max);

/**
 * @brief AES-GCM with a 96-bit IV (NIST SP 800-38D §7.1 / §7.2), full 16-byte tag.
 *
 * @param[in]  key     Key.
 * @param[in]  key_len 16, 24 or 32.
 * @param[in]  iv      12-byte IV.
 * @param[in]  aad     Additional data.
 * @param[in]  aad_len AAD bytes.
 * @param[in]  in      Input (plaintext when encrypting, ciphertext when decrypting).
 * @param[in]  len     Payload bytes.
 * @param[out] out     Output (may equal @p in).
 * @param[in]  dec     Non-zero to decrypt.
 * @param[out] tag     16-byte tag over AAD and ciphertext.
 */
void ut_gcm(const uint8_t * key, uint32_t key_len, const uint8_t * iv, const uint8_t * aad, uint32_t aad_len,
            const uint8_t * in, uint32_t len, uint8_t * out, uint8_t dec, uint8_t * tag);

/**
 * @brief AES-CCM from a formatted header (NIST SP 800-38C §6.1 / §6.2).
 *
 * @p hdr is B0 followed by the encoded AAD length and the AAD (§A.2.1-A.2.2,
 * zero padding implied); the nonce and the length field size q are taken from B0.
 *
 * @param[in]  key     Key.
 * @param[in]  key_len 16, 24 or 32.
 * @param[in]  hdr     Formatted header (>= 16 bytes).
 * @param[in]  hdr_len Header bytes.
 * @param[in]  in      Input payload.
 * @param[in]  len     Payload bytes.
 * @param[out] out     Output payload (may equal @p in).
 * @param[in]  dec     Non-zero to decrypt.
 * @param[out] tag     16-byte T XOR S0 (truncate to the tag length).
 */
void ut_ccm(const uint8_t * key, uint32_t key_len, const uint8_t * hdr, uint32_t hdr_len,
            const uint8_t * in, uint32_t len, uint8_t * out, uint8_t dec, uint8_t * tag);

#endif /* UT_NRF54_REF_H */
