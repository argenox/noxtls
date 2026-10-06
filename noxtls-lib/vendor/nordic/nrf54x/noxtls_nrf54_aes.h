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
* File:    noxtls_nrf54_aes.h
* Summary: CRACEN BA411 AES-ECB / CBC / CTR
*
*****************************************************************************/

/**
 * @file noxtls_nrf54_aes.h
 * @brief AES (FIPS 197) ECB, CBC and CTR (NIST SP 800-38A) on the CRACEN BA411.
 * @ingroup noxtls_nrf54
 *
 * ECB and CBC take whole blocks. CTR takes any length; the counter block is
 * the full 16-byte IV incremented as a 128-bit big-endian integer (SP 800-38A
 * Appendix B.1 with m = 128). With a 128-bit engine counter (nRF54L15) CTR runs
 * natively; with the 16-bit counter of CRACEN Lite (nRF54LM20) the keystream
 * is produced by hardware ECB over counter blocks built by the CPU, so the
 * counter never wraps inside the engine. AES-192 is rejected when the engine
 * lacks it (CRACEN Lite).
 */

#ifndef NOXTLS_NRF54_AES_H
#define NOXTLS_NRF54_AES_H

#include <stdint.h>

#include "noxtls_nrf54_cracen.h"

#ifdef __cplusplus
extern "C" {
#endif

/** AES block bytes. */
#define NOXTLS_NRF54_AES_BLOCK          16U
/** Largest AES key. */
#define NOXTLS_NRF54_AES_KEY_MAX        32U

/** Cipher mode of noxtls_nrf54_aes_crypt(). */
typedef enum {
    NOXTLS_NRF54_AES_ECB = 0, /**< ECB (SP 800-38A §6.1). */
    NOXTLS_NRF54_AES_CBC = 1, /**< CBC (SP 800-38A §6.2). */
    NOXTLS_NRF54_AES_CTR = 2  /**< CTR (SP 800-38A §6.5). */
} noxtls_nrf54_aes_mode_t;

/** AES module state (defined in noxtls_nrf54_aes.c; read by the DMA). */
typedef struct {
    noxtls_nrf54_desc_t fetch[4];                       /**< Config, key, IV, data. */
    noxtls_nrf54_desc_t push[1];                        /**< Output. */
    uint32_t cfg;                                       /**< Configuration word. */
    uint8_t key[NOXTLS_NRF54_AES_KEY_MAX];              /**< Key copy. */
    uint8_t iv[NOXTLS_NRF54_AES_BLOCK];                 /**< IV / counter of the job. */
    uint8_t bin[NOXTLS_NRF54_CONFIG_BOUNCE_SIZE];       /**< Input bounce / CTR counter blocks. */
    uint8_t bout[NOXTLS_NRF54_CONFIG_BOUNCE_SIZE];      /**< Output bounce / CTR keystream. */
} noxtls_nrf54_aes_t;

/**
 * @brief Encrypt or decrypt with a key given by value.
 *
 * @param[in]     mode    Cipher mode.
 * @param[in]     decrypt Non-zero to decrypt (ignored by CTR).
 * @param[in]     key     Key.
 * @param[in]     key_len 16, 24 or 32.
 * @param[in,out] iv      CBC / CTR: 16-byte IV, updated to the next chaining
 *                        value / counter block; NULL for ECB.
 * @param[in]     in      Input.
 * @param[out]    out     Output (may equal @p in).
 * @param[in]     len     Bytes (ECB / CBC: multiple of 16; 0 returns success).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM,
 *         NOXTLS_RETURN_INVALID_KEY_SIZE, NOXTLS_RETURN_NOT_SUPPORTED (mode or
 *         key size not in the engine, CRACEN disabled or in use),
 *         NOXTLS_RETURN_FAILED or NOXTLS_RETURN_TIMEOUT. On failure the output
 *         is wiped and @p iv is unchanged.
 */
noxtls_return_t noxtls_nrf54_aes_crypt(noxtls_nrf54_aes_mode_t mode, uint8_t decrypt, const uint8_t *key,
                                       uint32_t key_len, uint8_t *iv, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @brief As noxtls_nrf54_aes_crypt() with a key the CPU cannot read (CRACEN
 *        protected RAM filled by a KMU push, see noxtls_nrf54_kmu_push()).
 *
 * @param[in]     mode     Cipher mode.
 * @param[in]     decrypt  Non-zero to decrypt.
 * @param[in]     key_addr Key address read by the DMA only.
 * @param[in]     key_len  16, 24 or 32.
 * @param[in,out] iv       As noxtls_nrf54_aes_crypt().
 * @param[in]     in       Input.
 * @param[out]    out      Output.
 * @param[in]     len      Bytes.
 *
 * @return As noxtls_nrf54_aes_crypt().
 */
noxtls_return_t noxtls_nrf54_aes_crypt_keyref(noxtls_nrf54_aes_mode_t mode, uint8_t decrypt, uintptr_t key_addr,
                                              uint32_t key_len, uint8_t *iv, const uint8_t *in, uint8_t *out,
                                              uint32_t len);

/**
 * @brief Whether the engine supports a key size (after the first acquire; 1 before it).
 *
 * @param[in] key_len 16, 24 or 32.
 *
 * @return 1 when supported.
 */
uint8_t noxtls_nrf54_aes_key_supported(uint32_t key_len);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_NRF54_AES_H */
