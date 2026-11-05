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
* File:    noxtls_stm32wb_aes.h
* Summary: STM32WB5x AES1 driver (ECB, CBC, CTR, GCM/GMAC, CCM)
*
*****************************************************************************/

/**
 * @file noxtls_stm32wb_aes.h
 * @brief AES1 register-level driver of the STM32WB5x.
 * @ingroup noxtls_stm32wb
 *
 * Specification: RM0434 Rev 13, AES chapter (AES1; 128- and 256-bit keys;
 * ECB, CBC, CTR, GCM/GMAC and CCM chaining modes; 4-word data input and
 * output registers; computation-complete flag CCF; read / write error flags;
 * GCM and CCM init / header / payload / final phases and the NPBLB padding
 * field). The phase sequences follow the CCM / GCM flows of the ST
 * stm32wbxx_hal_cryp driver. Data are exchanged with DATATYPE = 0 (32-bit,
 * no swapping); this driver converts bytes to big-endian words itself.
 *
 * Return convention of every driver function:
 *  - NOXTLS_RETURN_SUCCESS: operation done.
 *  - NOXTLS_RETURN_NOT_SUPPORTED: nothing was started (unsupported key size,
 *    parameter outside the hardware limits, peripheral or semaphore busy);
 *    the caller may run the request in software with unchanged buffers.
 *  - NOXTLS_RETURN_FAILED: the hardware reported an error or timed out after
 *    the operation started; the output buffer may hold partial data.
 *  - NOXTLS_RETURN_BAD_DATA: authentication tag mismatch (decryption); the
 *    plaintext output has been wiped.
 */

#ifndef NOXTLS_STM32WB_AES_H
#define NOXTLS_STM32WB_AES_H

#include <stdint.h>

#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief AES block size in bytes. */
#define NOXTLS_STM32WB_AES_BLOCK        16U
/** @brief AES-128 key size in bytes. */
#define NOXTLS_STM32WB_AES_KEY_128      16U
/** @brief AES-256 key size in bytes. */
#define NOXTLS_STM32WB_AES_KEY_256      32U
/** @brief GCM nonce size in bytes (96-bit IV, NIST SP 800-38D 8.2). */
#define NOXTLS_STM32WB_AES_GCM_NONCE    12U
/** @brief GCM tag size in bytes. */
#define NOXTLS_STM32WB_AES_GCM_TAG      16U
/** @brief Smallest CCM nonce size in bytes (NIST SP 800-38C A.1). */
#define NOXTLS_STM32WB_AES_CCM_NONCE_MIN 7U
/** @brief Largest CCM nonce size in bytes (NIST SP 800-38C A.1). */
#define NOXTLS_STM32WB_AES_CCM_NONCE_MAX 13U
/** @brief Smallest CCM tag size in bytes (NIST SP 800-38C A.1). */
#define NOXTLS_STM32WB_AES_CCM_TAG_MIN  4U
/** @brief Largest CCM tag size in bytes. */
#define NOXTLS_STM32WB_AES_CCM_TAG_MAX  16U

/** Chaining mode of noxtls_stm32wb_aes_crypt(). */
typedef uint32_t noxtls_stm32wb_aes_mode_t;
/** @brief Electronic codebook (NIST SP 800-38A 6.1). */
#define NOXTLS_STM32WB_AES_MODE_ECB     ((noxtls_stm32wb_aes_mode_t)0U)
/** @brief Cipher block chaining (NIST SP 800-38A 6.2). */
#define NOXTLS_STM32WB_AES_MODE_CBC     ((noxtls_stm32wb_aes_mode_t)1U)
/** @brief Counter mode with a 128-bit big-endian counter (NIST SP 800-38A 6.5). */
#define NOXTLS_STM32WB_AES_MODE_CTR     ((noxtls_stm32wb_aes_mode_t)2U)

/** Driver counters. */
typedef struct {
    uint32_t operations;    /**< Requests completed in hardware. */
    uint32_t declined;      /**< Requests refused before start (NOT_SUPPORTED). */
    uint32_t hw_errors;     /**< Requests that failed after start. */
} noxtls_stm32wb_aes_stats_t;

/**
 * @brief ECB / CBC / CTR over a buffer.
 *
 * ECB and CBC need a whole number of blocks. CTR accepts any length and uses
 * the NIST SP 800-38A 128-bit big-endian counter: the 32-bit hardware counter
 * is carried into the upper words in software. @p out may equal @p in.
 *
 * @param[in]  mode    NOXTLS_STM32WB_AES_MODE_*.
 * @param[in]  decrypt Non-zero to decrypt (ignored by CTR).
 * @param[in]  key     Key bytes (16 or 32).
 * @param[in]  key_len Key size in bytes.
 * @param[in]  iv      IV / initial counter block (16 bytes); NULL for ECB.
 * @param[in]  in      Input.
 * @param[out] out     Output (same length as the input).
 * @param[in]  len     Bytes (> 0).
 *
 * @return See the return convention in the file header.
 */
noxtls_return_t noxtls_stm32wb_aes_crypt(noxtls_stm32wb_aes_mode_t mode,
                                         uint8_t decrypt,
                                         const uint8_t *key,
                                         uint32_t key_len,
                                         const uint8_t *iv,
                                         const uint8_t *in,
                                         uint8_t *out,
                                         uint32_t len);

/**
 * @brief AES-GCM encryption or decryption with a 96-bit nonce (also GMAC when @p len is 0).
 *
 * For decryption @p tag holds the expected tag and a mismatch returns
 * NOXTLS_RETURN_BAD_DATA with @p out wiped; for encryption @p tag receives
 * the tag. @p out may equal @p in.
 *
 * @param[in]     decrypt Non-zero to decrypt and verify.
 * @param[in]     key     Key bytes (16 or 32).
 * @param[in]     key_len Key size in bytes.
 * @param[in]     nonce   12-byte nonce.
 * @param[in]     aad     Additional data (may be NULL when @p aad_len is 0).
 * @param[in]     aad_len Additional data bytes.
 * @param[in]     in      Plaintext / ciphertext (may be NULL when @p len is 0).
 * @param[out]    out     Ciphertext / plaintext (may be NULL when @p len is 0).
 * @param[in]     len     Payload bytes.
 * @param[in,out] tag     16-byte tag (out for encryption, in for decryption).
 *
 * @return See the return convention in the file header.
 */
noxtls_return_t noxtls_stm32wb_aes_gcm(uint8_t decrypt,
                                       const uint8_t *key,
                                       uint32_t key_len,
                                       const uint8_t *nonce,
                                       const uint8_t *aad,
                                       uint32_t aad_len,
                                       const uint8_t *in,
                                       uint8_t *out,
                                       uint32_t len,
                                       uint8_t *tag);

/**
 * @brief AES-CCM encryption or decryption (NIST SP 800-38C).
 *
 * For decryption @p tag holds the expected tag and a mismatch returns
 * NOXTLS_RETURN_BAD_DATA with @p out wiped; for encryption @p tag receives
 * @p tag_len bytes. @p out may equal @p in.
 *
 * @param[in]     decrypt   Non-zero to decrypt and verify.
 * @param[in]     key       Key bytes (16 or 32).
 * @param[in]     key_len   Key size in bytes.
 * @param[in]     nonce     Nonce (7..13 bytes).
 * @param[in]     nonce_len Nonce bytes.
 * @param[in]     aad       Additional data (may be NULL when @p aad_len is 0).
 * @param[in]     aad_len   Additional data bytes.
 * @param[in]     in        Plaintext / ciphertext (may be NULL when @p len is 0).
 * @param[out]    out       Ciphertext / plaintext (may be NULL when @p len is 0).
 * @param[in]     len       Payload bytes (must fit the 15 - nonce_len length field).
 * @param[in,out] tag       Tag (out for encryption, in for decryption).
 * @param[in]     tag_len   Tag bytes (4, 6, ..., 16).
 *
 * @return See the return convention in the file header.
 */
noxtls_return_t noxtls_stm32wb_aes_ccm(uint8_t decrypt,
                                       const uint8_t *key,
                                       uint32_t key_len,
                                       const uint8_t *nonce,
                                       uint32_t nonce_len,
                                       const uint8_t *aad,
                                       uint32_t aad_len,
                                       const uint8_t *in,
                                       uint8_t *out,
                                       uint32_t len,
                                       uint8_t *tag,
                                       uint32_t tag_len);

/**
 * @brief Driver counters.
 *
 * @return Pointer to the (static) counters.
 */
const noxtls_stm32wb_aes_stats_t *noxtls_stm32wb_aes_stats(void);

/** @name Driver internals shared by the AEAD file (not an application API) */
/** @{ */

/**
 * @brief Lock AES1, verify it is idle, program CR, key and IV.
 *
 * @param[in] key     Key bytes.
 * @param[in] key_len Key size in bytes (16 or 32).
 * @param[in] cr      CR value without EN (chaining mode, mode, phase).
 * @param[in] iv      16-byte IV block, or NULL for none.
 *
 * @return NOXTLS_RETURN_SUCCESS, or NOXTLS_RETURN_NOT_SUPPORTED when the
 *         key size is unsupported, the semaphore is busy or the peripheral
 *         still reports BUSY (the lock is not held in that case).
 */
noxtls_return_t noxtls_stm32wb_aes_open(const uint8_t *key, uint32_t key_len, uint32_t cr, const uint8_t *iv);

/** @brief Disable AES1, wipe the key and IV registers and release the lock. */
void noxtls_stm32wb_aes_close(void);

/**
 * @brief Read-modify-write CR.
 *
 * @param[in] clear Bits to clear.
 * @param[in] set   Bits to set afterwards.
 */
void noxtls_stm32wb_aes_cr(uint32_t clear, uint32_t set);

/**
 * @brief Load the IV registers (EN must be clear).
 *
 * @param[in] iv 16-byte IV block.
 */
void noxtls_stm32wb_aes_load_iv(const uint8_t *iv);

/**
 * @brief Write one 16-byte block to DINR.
 *
 * @param[in] blk Block (16 bytes).
 */
void noxtls_stm32wb_aes_put(const uint8_t *blk);

/**
 * @brief Read one 16-byte block from DOUTR.
 *
 * @param[out] blk Block (16 bytes).
 */
void noxtls_stm32wb_aes_get(uint8_t *blk);

/**
 * @brief Wait for CCF, check the error flags and clear them.
 *
 * @return NOXTLS_RETURN_SUCCESS, or NOXTLS_RETURN_FAILED on timeout or RDERR / WRERR.
 */
noxtls_return_t noxtls_stm32wb_aes_wait(void);

/**
 * @brief Record the outcome of a request in the driver counters.
 *
 * @param[in] rc Result of the request.
 *
 * @return @p rc.
 */
noxtls_return_t noxtls_stm32wb_aes_account(noxtls_return_t rc);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_STM32WB_AES_H */
