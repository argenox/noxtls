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
* File:    noxtls_nrf54_aead.h
* Summary: CRACEN BA411 AES-GCM and AES-CCM
*
*****************************************************************************/

/**
 * @file noxtls_nrf54_aead.h
 * @brief One-shot AES-GCM (NIST SP 800-38D) and AES-CCM (NIST SP 800-38C) on the CRACEN BA411.
 * @ingroup noxtls_nrf54
 *
 * GCM: 96-bit IV (SP 800-38D §7.1, J0 = IV || 0^31 || 1), 16-byte tag.
 * CCM: nonce 7..13 bytes, tag 4..16 bytes (even), formatting of B0 and of the
 * associated-data length per SP 800-38C Appendix A.2. A failed tag check
 * returns NOXTLS_RETURN_BAD_DATA and wipes the output: unauthenticated
 * plaintext is never released. With the 16-bit counter of CRACEN Lite the
 * payload is limited so the counter cannot wrap inside the engine
 * (2^16 - 2 blocks); longer messages return NOXTLS_RETURN_NOT_SUPPORTED so
 * NoxTLS uses software.
 */

#ifndef NOXTLS_NRF54_AEAD_H
#define NOXTLS_NRF54_AEAD_H

#include <stdint.h>

#include "noxtls_nrf54_cracen.h"

#ifdef __cplusplus
extern "C" {
#endif

/** AEAD block bytes. */
#define NOXTLS_NRF54_AEAD_BLOCK         16U
/** GCM IV bytes. */
#define NOXTLS_NRF54_GCM_IV_BYTES       12U
/** Largest tag. */
#define NOXTLS_NRF54_AEAD_TAG_MAX       16U
/** CCM header buffer: B0, the encoded AAD length and the first AAD bytes. */
#define NOXTLS_NRF54_CCM_HDR_BYTES      32U

/** AEAD module state (defined in noxtls_nrf54_aead.c; read and written by the DMA). */
typedef struct {
    noxtls_nrf54_desc_t fetch[8];                     /**< Config, key, IV, AAD (2), data, final block. */
    noxtls_nrf54_desc_t push[6];                      /**< AAD discard, data, pad discard, tag, tag pad. */
    uint32_t cfg;                                     /**< Configuration word. */
    uint8_t key[32];                                  /**< Key copy. */
    uint8_t iv[NOXTLS_NRF54_GCM_IV_BYTES];            /**< GCM IV copy. */
    uint8_t hdr[NOXTLS_NRF54_CCM_HDR_BYTES];          /**< CCM formatted header start. */
    uint8_t lens[NOXTLS_NRF54_AEAD_BLOCK];            /**< GCM len(A) || len(C) / CCM received tag. */
    uint8_t tag[NOXTLS_NRF54_AEAD_TAG_MAX];           /**< Engine tag output. */
    uint8_t bin[NOXTLS_NRF54_CONFIG_BOUNCE_SIZE];     /**< Payload bounce (input). */
    uint8_t bout[NOXTLS_NRF54_CONFIG_BOUNCE_SIZE];    /**< Payload bounce (output). */
    uint8_t baad[NOXTLS_NRF54_CONFIG_BOUNCE_SIZE];    /**< AAD bounce. */
} noxtls_nrf54_aead_t;

/**
 * @brief AES-GCM encrypt or decrypt (16-byte tag).
 *
 * @param[in]     decrypt Non-zero to decrypt and verify.
 * @param[in]     key     Key.
 * @param[in]     key_len 16, 24 or 32.
 * @param[in]     iv      12-byte IV.
 * @param[in]     aad     Associated data (NULL when @p aad_len is 0).
 * @param[in]     aad_len AAD bytes.
 * @param[in]     in      Plaintext (encrypt) or ciphertext (decrypt).
 * @param[out]    out     Output (may equal @p in).
 * @param[in]     len     Payload bytes.
 * @param[in,out] tag     Encrypt: receives the tag. Decrypt: tag to verify.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_BAD_DATA (tag mismatch, output
 *         wiped), NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_KEY_SIZE,
 *         NOXTLS_RETURN_NOT_SUPPORTED (use software), NOXTLS_RETURN_FAILED or
 *         NOXTLS_RETURN_TIMEOUT.
 */
noxtls_return_t noxtls_nrf54_aead_gcm(uint8_t decrypt, const uint8_t *key, uint32_t key_len, const uint8_t *iv,
                                      const uint8_t *aad, uint32_t aad_len, const uint8_t *in, uint8_t *out,
                                      uint32_t len, uint8_t *tag);

/**
 * @brief AES-CCM encrypt or decrypt.
 *
 * @param[in]     decrypt   Non-zero to decrypt and verify.
 * @param[in]     key       Key.
 * @param[in]     key_len   16, 24 or 32.
 * @param[in]     nonce     Nonce.
 * @param[in]     nonce_len 7..13.
 * @param[in]     aad       Associated data (NULL when @p aad_len is 0).
 * @param[in]     aad_len   AAD bytes.
 * @param[in]     in        Input payload.
 * @param[out]    out       Output payload (may equal @p in).
 * @param[in]     len       Payload bytes (< 2^(8 * (15 - nonce_len))).
 * @param[in,out] tag       Encrypt: receives the tag. Decrypt: tag to verify.
 * @param[in]     tag_len   4, 6, 8, 10, 12, 14 or 16.
 *
 * @return As noxtls_nrf54_aead_gcm(), plus NOXTLS_RETURN_INVALID_PARAM for a
 *         bad nonce / tag length or a payload too long for the length field.
 */
noxtls_return_t noxtls_nrf54_aead_ccm(uint8_t decrypt, const uint8_t *key, uint32_t key_len, const uint8_t *nonce,
                                      uint32_t nonce_len, const uint8_t *aad, uint32_t aad_len, const uint8_t *in,
                                      uint8_t *out, uint32_t len, uint8_t *tag, uint32_t tag_len);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_NRF54_AEAD_H */
