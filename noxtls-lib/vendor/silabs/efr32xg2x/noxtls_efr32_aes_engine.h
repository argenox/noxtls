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
* File:    noxtls_efr32_aes_engine.h
* Summary: EFR32xG2x RADIOAES (BA411E) driver: ECB, CBC, CTR and CCM
*
*****************************************************************************/

/**
 * @file noxtls_efr32_aes_engine.h
 * @brief AES (FIPS 197) ECB / CBC / CTR (NIST SP 800-38A) and CCM (NIST SP 800-38C)
 *        on the EFR32xG2x RADIOAES peripheral.
 * @ingroup noxtls_efr32
 *
 * The RADIOAES instance contains a BA411E engine behind a scatter/gather
 * fetcher / pusher DMA (EFR32xG26 RM, chapter "AES"). The hardware
 * configuration registers report which modes the instance implements; on the
 * EFR32MG26 they are ECB, CBC, CTR, CCM and CMAC (no GCM, no hash), with
 * 128-bit and 256-bit keys (no 192-bit keys). The driver reads them and
 * answers NOXTLS_RETURN_NOT_SUPPORTED for anything else so NoxTLS uses its
 * software implementation.
 *
 * Every request takes the engine once without waiting
 * (noxtls_efr32_engine_lock.h); a busy engine is NOXTLS_RETURN_NOT_SUPPORTED.
 */
#ifndef NOXTLS_EFR32_AES_ENGINE_H
#define NOXTLS_EFR32_AES_ENGINE_H

#include <stdint.h>

#include "noxtls_efr32_core.h"
#include "noxtls_efr32_engine_lock.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief AES block bytes. */
#define NOXTLS_EFR32_AES_BLOCK          16U
/** @brief Largest AES key. */
#define NOXTLS_EFR32_AES_KEY_MAX        32U
/** @brief Largest CCM tag. */
#define NOXTLS_EFR32_AES_TAG_MAX        16U

/** Cipher mode of noxtls_efr32_aes_crypt(). */
typedef enum {
    NOXTLS_EFR32_AES_ECB = 0, /**< ECB (SP 800-38A §6.1). */
    NOXTLS_EFR32_AES_CBC = 1, /**< CBC (SP 800-38A §6.2). */
    NOXTLS_EFR32_AES_CTR = 2  /**< CTR (SP 800-38A §6.5, 128-bit big-endian counter). */
} noxtls_efr32_aes_mode_t;

/** Capabilities read from the hardware configuration registers. */
typedef struct {
    uint32_t inclips;   /**< INCL_IPS_HW_CFG: included engines. */
    uint32_t modes;     /**< BA411E modes, bit n = mode number n (ECB 0, CBC 1, CTR 2, CCM 5, GCM 6, CMAC 8). */
    uint32_t keys;      /**< Key sizes: bit0 128, bit1 192, bit2 256. */
    uint32_t ctr_bits;  /**< CTR counter width in bits. */
    uint8_t masking;    /**< Non-zero when the engine requires a mask word before each job. */
    uint8_t valid;      /**< Non-zero once read. */
} noxtls_efr32_aes_caps_t;

/**
 * @brief Capabilities of the engine (valid after the first successful acquisition).
 *
 * @return Capabilities (never NULL).
 */
const noxtls_efr32_aes_caps_t *noxtls_efr32_aes_caps(void);

/** @brief Forget the cached capabilities and the mask seed (hardware replaced, host tests); the next request re-reads them. */
void noxtls_efr32_aes_reset(void);

/**
 * @brief Select native engine CBC or CBC composed from hardware ECB (default NOXTLS_EFR32_CONFIG_AES_CBC_NATIVE).
 *
 * @param[in] native Non-zero: the engine chains (context load of the IV); zero: ECB blocks chained by the CPU.
 */
void noxtls_efr32_aes_set_cbc_native(uint8_t native);

/**
 * @brief Refuse modes at run time (for example after a failed self-test); the request then uses software.
 *
 * @param[in] mode_bits Bit n disables BA411E mode number n (NOXTLS_EFR32_AES_MODE_*); 0 re-enables everything.
 */
void noxtls_efr32_aes_set_modes_disabled(uint32_t mode_bits);

/**
 * @brief Encrypt or decrypt with ECB, CBC or CTR.
 *
 * @param[in]     mode    Cipher mode.
 * @param[in]     decrypt Non-zero to decrypt (ignored by CTR).
 * @param[in]     key     Key.
 * @param[in]     key_len 16, 24 or 32.
 * @param[in,out] iv      CBC / CTR: 16-byte IV, updated to the next chaining value / counter block; NULL for ECB.
 * @param[in]     in      Input.
 * @param[out]    out     Output (may equal @p in).
 * @param[in]     len     Bytes (ECB / CBC: multiple of 16; 0 returns success).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM,
 *         NOXTLS_RETURN_INVALID_KEY_SIZE, NOXTLS_RETURN_NOT_SUPPORTED (nothing was
 *         done: mode, key size or request size not served, buffers unreachable, engine
 *         disabled or in use), NOXTLS_RETURN_FAILED or NOXTLS_RETURN_TIMEOUT (job
 *         failed; the output is wiped and @p iv is unchanged).
 */
noxtls_return_t noxtls_efr32_aes_crypt(noxtls_efr32_aes_mode_t mode, uint8_t decrypt, const uint8_t *key,
                                       uint32_t key_len, uint8_t *iv, const uint8_t *in, uint8_t *out, uint32_t len);

/**
 * @brief One-shot CCM encryption or decryption (NIST SP 800-38C).
 *
 * @param[in]     decrypt   Non-zero to decrypt and verify.
 * @param[in]     key       Key.
 * @param[in]     key_len   16, 24 or 32.
 * @param[in]     nonce     Nonce.
 * @param[in]     nonce_len 7..13.
 * @param[in]     aad       Associated data (NULL when @p aad_len is 0).
 * @param[in]     aad_len   Associated data bytes.
 * @param[in]     in        Plaintext (encrypt) or ciphertext (decrypt).
 * @param[out]    out       Ciphertext (encrypt) or plaintext (decrypt); may equal @p in.
 * @param[in]     len       Payload bytes (0 allowed).
 * @param[in,out] tag       Encrypt: receives the tag. Decrypt: the received tag.
 * @param[in]     tag_len   4, 6, ..., 16.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM,
 *         NOXTLS_RETURN_INVALID_KEY_SIZE, NOXTLS_RETURN_NOT_SUPPORTED (nothing was done),
 *         NOXTLS_RETURN_BAD_DATA (authentication failed; the output is wiped),
 *         NOXTLS_RETURN_FAILED or NOXTLS_RETURN_TIMEOUT (job failed; output wiped).
 */
noxtls_return_t noxtls_efr32_aes_ccm(uint8_t decrypt, const uint8_t *key, uint32_t key_len, const uint8_t *nonce,
                                     uint32_t nonce_len, const uint8_t *aad, uint32_t aad_len, const uint8_t *in,
                                     uint8_t *out, uint32_t len, uint8_t *tag, uint32_t tag_len);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_EFR32_AES_ENGINE_H */
