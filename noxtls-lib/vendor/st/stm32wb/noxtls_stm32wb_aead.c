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
* File:    noxtls_stm32wb_aead.c
* Summary: STM32WB5x AES1 AES-GCM / GMAC / AES-CCM driver
*
*****************************************************************************/

/**
 * @file noxtls_stm32wb_aead.c
 * @brief AES-GCM (NIST SP 800-38D) and AES-CCM (NIST SP 800-38C) on AES1.
 * @ingroup noxtls_stm32wb
 *
 * Phase sequence (RM0434 AES chapter, GCM and CCM sections; stm32wbxx_hal_cryp):
 *  1. init phase: IVR = J0-derived counter block (GCM: nonce || 0x00000002)
 *     or B0 (CCM), EN = 1, wait CCF;
 *  2. header phase: additional data in zero-padded blocks (CCM: preceded by
 *     the encoded length, NIST SP 800-38C A.2.2), wait CCF per block;
 *  3. payload phase: data blocks; NPBLB = padding bytes of the last block
 *     when the hardware must not authenticate the padding (GCM encryption,
 *     CCM decryption);
 *  4. final phase in encryption mode: GCM takes the 128-bit length block
 *     (bit lengths of header and payload), CCM takes no input; the tag is read
 *     from DOUTR.
 */

#include <stddef.h>

#include "common/noxtls_ct.h"
#include "noxtls_stm32wb_aes.h"
#include "noxtls_stm32wb_config.h"
#include "noxtls_stm32wb_regs.h"

/** @brief Counter value the GCM init phase expects in the last IV word (J0 + 1, SP 800-38D 7.1). */
#define NOXTLS_STM32WB_GCM_ICB_COUNTER  2U
/** @brief Offset of the counter word in the 16-byte GCM IV block. */
#define NOXTLS_STM32WB_GCM_ICB_OFFSET   12U
/** @brief Bits per byte. */
#define NOXTLS_STM32WB_BYTE_BITS        8U
/** @brief Bytes of the 32-bit length words of the GCM final block. */
#define NOXTLS_STM32WB_WORD_BYTES       4U
/** @brief Offset of the second 32-bit length word in the GCM final block. */
#define NOXTLS_STM32WB_GCM_LEN2_OFFSET  12U
/** @brief Offset of the first 32-bit length word in the GCM final block. */
#define NOXTLS_STM32WB_GCM_LEN1_OFFSET  4U

/** @brief CCM B0 flags: Adata present. */
#define NOXTLS_STM32WB_CCM_FLAG_ADATA   0x40U
/** @brief CCM B0 flags: position of the encoded tag length (t - 2) / 2. */
#define NOXTLS_STM32WB_CCM_FLAG_T_SHIFT 3U
/** @brief Total CCM nonce + length field bytes (15). */
#define NOXTLS_STM32WB_CCM_NL_BYTES     15U
/** @brief Smallest CCM length-field size for which every 32-bit length fits. */
#define NOXTLS_STM32WB_CCM_L_FULL       4U
/** @brief First CCM header length that needs the 6-byte encoding (SP 800-38C A.2.2). */
#define NOXTLS_STM32WB_CCM_ADATA_SHORT_MAX 0xFF00U
/** @brief Bytes of the short CCM header length encoding. */
#define NOXTLS_STM32WB_CCM_ADATA_SHORT_LEN 2U
/** @brief Bytes of the long CCM header length encoding. */
#define NOXTLS_STM32WB_CCM_ADATA_LONG_LEN 6U
/** @brief First marker byte of the long CCM header length encoding. */
#define NOXTLS_STM32WB_CCM_ADATA_MARK0  0xFFU
/** @brief Second marker byte of the long CCM header length encoding. */
#define NOXTLS_STM32WB_CCM_ADATA_MARK1  0xFEU

/** @brief CR value of the GCM chaining mode. */
#define NOXTLS_STM32WB_CR_GCM           (NOXTLS_STM32WB_AES_CHMOD_GCM << NOXTLS_STM32WB_AES_CR_CHMOD_SHIFT)
/** @brief CR phase field value. */
#define NOXTLS_STM32WB_CR_PHASE(ph)     ((ph) << NOXTLS_STM32WB_AES_CR_GCMPH_SHIFT)

/**
 * @brief Store a 32-bit value big-endian.
 * @internal
 *
 * @param[out] p Four bytes.
 * @param[in]  v Value.
 */
static void noxtls_stm32wb_aead_put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/**
 * @brief Select a phase and keep the engine enabled.
 * @internal
 *
 * @param[in] phase NOXTLS_STM32WB_AES_PHASE_*.
 */
static void noxtls_stm32wb_aead_phase(uint32_t phase)
{
    noxtls_stm32wb_aes_cr(NOXTLS_STM32WB_AES_CR_GCMPH_MASK | NOXTLS_STM32WB_AES_CR_NPBLB_MASK,
                          NOXTLS_STM32WB_CR_PHASE(phase) | NOXTLS_STM32WB_AES_CR_EN);
}

/**
 * @brief Feed header bytes (optional prefix then data) as zero-padded blocks.
 * @internal
 *
 * @param[in] prefix     Bytes placed before the data (CCM length encoding), or NULL.
 * @param[in] prefix_len Prefix bytes.
 * @param[in] data       Header data.
 * @param[in] data_len   Header data bytes.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_FAILED.
 */
static noxtls_return_t noxtls_stm32wb_aead_header(const uint8_t *prefix, uint32_t prefix_len,
                                                  const uint8_t *data, uint32_t data_len)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint8_t blk[NOXTLS_STM32WB_AES_BLOCK];
    uint32_t total = prefix_len + data_len;
    uint32_t off = 0U;
    uint32_t j;
    uint32_t idx;

    while ((off < total) && (rc == NOXTLS_RETURN_SUCCESS)) {
        for (j = 0U; j < NOXTLS_STM32WB_AES_BLOCK; j++) {
            idx = off + j;
            if (idx < prefix_len) {
                blk[j] = prefix[idx];
            } else if (idx < total) {
                blk[j] = data[idx - prefix_len];
            } else {
                blk[j] = 0U;
            }
        }
        noxtls_stm32wb_aes_put(blk);
        rc = noxtls_stm32wb_aes_wait();
        off += NOXTLS_STM32WB_AES_BLOCK;
    }
    noxtls_secure_zero(blk, sizeof(blk));
    return rc;
}

/**
 * @brief Payload phase: whole blocks, then a zero-padded last block.
 * @internal
 *
 * @param[in]  npblb_tail Non-zero to program NPBLB for a short last block.
 * @param[in]  in         Input.
 * @param[out] out        Output (may equal @p in).
 * @param[in]  len        Bytes (may be 0).
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_FAILED.
 */
static noxtls_return_t noxtls_stm32wb_aead_payload(uint32_t npblb_tail, const uint8_t *in, uint8_t *out, uint32_t len)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint8_t blk[NOXTLS_STM32WB_AES_BLOCK];
    uint32_t off = 0U;
    uint32_t rem = len % NOXTLS_STM32WB_AES_BLOCK;
    uint32_t full = len - rem;
    uint32_t i;

    while ((off < full) && (rc == NOXTLS_RETURN_SUCCESS)) {
        noxtls_stm32wb_aes_put(&in[off]);
        rc = noxtls_stm32wb_aes_wait();
        if (rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_stm32wb_aes_get(&out[off]);
        }
        off += NOXTLS_STM32WB_AES_BLOCK;
    }
    if ((rc == NOXTLS_RETURN_SUCCESS) && (rem != 0U)) {
        if (npblb_tail != 0U) {
            noxtls_stm32wb_aes_cr(NOXTLS_STM32WB_AES_CR_NPBLB_MASK,
                                  (NOXTLS_STM32WB_AES_BLOCK - rem) << NOXTLS_STM32WB_AES_CR_NPBLB_SHIFT);
        }
        noxtls_secure_zero(blk, sizeof(blk));
        noxtls_copy_u8(blk, sizeof(blk), &in[full], rem);
        noxtls_stm32wb_aes_put(blk);
        rc = noxtls_stm32wb_aes_wait();
        if (rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_stm32wb_aes_get(blk);
            for (i = 0U; i < rem; i++) {
                out[full + i] = blk[i];
            }
        }
    }
    noxtls_secure_zero(blk, sizeof(blk));
    return rc;
}

/**
 * @brief Finish an AEAD operation: leave the final phase and read the tag.
 * @internal
 *
 * @param[in]  block Final-phase input block, or NULL when the mode takes none.
 * @param[out] calc  Computed tag (16 bytes).
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_FAILED.
 */
static noxtls_return_t noxtls_stm32wb_aead_final(const uint8_t *block, uint8_t *calc)
{
    noxtls_return_t rc;

    /* The tag is always produced in encryption mode (stm32wbxx_hal_cryp_ex AuthTAG). */
    noxtls_stm32wb_aes_cr(NOXTLS_STM32WB_AES_CR_GCMPH_MASK | NOXTLS_STM32WB_AES_CR_NPBLB_MASK |
                          NOXTLS_STM32WB_AES_CR_MODE_MASK,
                          NOXTLS_STM32WB_CR_PHASE(NOXTLS_STM32WB_AES_PHASE_FINAL) | NOXTLS_STM32WB_AES_CR_EN);
    if (block != NULL) {
        noxtls_stm32wb_aes_put(block);
    }
    rc = noxtls_stm32wb_aes_wait();
    if (rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_stm32wb_aes_get(calc);
    }
    return rc;
}

/**
 * @brief Compare the computed tag, publish it or wipe the plaintext.
 * @internal
 *
 * @param[in]     decrypt Non-zero when verifying.
 * @param[in]     calc    Computed tag.
 * @param[in,out] tag     Tag buffer (out when encrypting, expected tag when decrypting).
 * @param[in]     tag_len Tag bytes.
 * @param[out]    out     Plaintext (wiped on mismatch).
 * @param[in]     len     Plaintext bytes.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_BAD_DATA.
 */
static noxtls_return_t noxtls_stm32wb_aead_tag(uint8_t decrypt, const uint8_t *calc, uint8_t *tag, uint32_t tag_len,
                                               uint8_t *out, uint32_t len)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if (decrypt == 0U) {
        noxtls_copy_u8(tag, tag_len, calc, tag_len);
    } else if (noxtls_ct_memcmp(calc, tag, tag_len) != 0) {
        noxtls_secure_zero(out, len);
        rc = NOXTLS_RETURN_BAD_DATA;
    } else {
        /* Authentic. */
    }
    return rc;
}

/**
 * @brief GCM phases after the engine is configured.
 * @internal
 *
 * @param[in]  decrypt Non-zero when decrypting.
 * @param[in]  aad     Additional data.
 * @param[in]  aad_len Additional data bytes.
 * @param[in]  in      Input.
 * @param[out] out     Output.
 * @param[in]  len     Payload bytes.
 * @param[out] calc    Computed tag.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_FAILED.
 */
static noxtls_return_t noxtls_stm32wb_gcm_run(uint8_t decrypt, const uint8_t *aad, uint32_t aad_len,
                                              const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *calc)
{
    noxtls_return_t rc;
    uint8_t lens[NOXTLS_STM32WB_AES_BLOCK];

    noxtls_stm32wb_aes_cr(0U, NOXTLS_STM32WB_AES_CR_EN);
    rc = noxtls_stm32wb_aes_wait();
    if (rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_stm32wb_aead_phase(NOXTLS_STM32WB_AES_PHASE_HEADER);
        rc = noxtls_stm32wb_aead_header(NULL, 0U, aad, aad_len);
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_stm32wb_aead_phase(NOXTLS_STM32WB_AES_PHASE_PAYLOAD);
        rc = noxtls_stm32wb_aead_payload((decrypt == 0U) ? 1U : 0U, in, out, len);
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        /* Final block: 0 || bits(header) || 0 || bits(payload) as four 32-bit words. */
        noxtls_secure_zero(lens, sizeof(lens));
        noxtls_stm32wb_aead_put_be32(&lens[NOXTLS_STM32WB_GCM_LEN1_OFFSET], aad_len * NOXTLS_STM32WB_BYTE_BITS);
        noxtls_stm32wb_aead_put_be32(&lens[NOXTLS_STM32WB_GCM_LEN2_OFFSET], len * NOXTLS_STM32WB_BYTE_BITS);
        rc = noxtls_stm32wb_aead_final(lens, calc);
    }
    return rc;
}

noxtls_return_t noxtls_stm32wb_aes_gcm(uint8_t decrypt,
                                       const uint8_t *key,
                                       uint32_t key_len,
                                       const uint8_t *nonce,
                                       const uint8_t *aad,
                                       uint32_t aad_len,
                                       const uint8_t *in,
                                       uint8_t *out,
                                       uint32_t len,
                                       uint8_t *tag)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    uint8_t iv[NOXTLS_STM32WB_AES_BLOCK];
    uint8_t calc[NOXTLS_STM32WB_AES_GCM_TAG];
    uint32_t op = (decrypt != 0U) ? NOXTLS_STM32WB_AES_MODE_DECRYPT : NOXTLS_STM32WB_AES_MODE_ENCRYPT;

    if ((key != NULL) && (nonce != NULL) && (tag != NULL) &&
        ((aad_len == 0U) || (aad != NULL)) && ((len == 0U) || ((in != NULL) && (out != NULL))) &&
        (aad_len <= NOXTLS_STM32WB_CONFIG_AES_MAX_LEN) && (len <= NOXTLS_STM32WB_CONFIG_AES_MAX_LEN)) {
        noxtls_copy_u8(iv, sizeof(iv), nonce, NOXTLS_STM32WB_AES_GCM_NONCE);
        noxtls_stm32wb_aead_put_be32(&iv[NOXTLS_STM32WB_GCM_ICB_OFFSET], NOXTLS_STM32WB_GCM_ICB_COUNTER);
        rc = noxtls_stm32wb_aes_open(key, key_len,
                                     NOXTLS_STM32WB_CR_GCM | (op << NOXTLS_STM32WB_AES_CR_MODE_SHIFT) |
                                     NOXTLS_STM32WB_CR_PHASE(NOXTLS_STM32WB_AES_PHASE_INIT), iv);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_stm32wb_gcm_run(decrypt, aad, aad_len, in, out, len, calc);
            noxtls_stm32wb_aes_close();
            if (rc == NOXTLS_RETURN_SUCCESS) {
                rc = noxtls_stm32wb_aead_tag(decrypt, calc, tag, NOXTLS_STM32WB_AES_GCM_TAG, out, len);
            }
        }
    }
    noxtls_secure_zero(iv, sizeof(iv));
    noxtls_secure_zero(calc, sizeof(calc));
    return noxtls_stm32wb_aes_account(rc);
}

/**
 * @brief Whether the CCM parameters are valid and the payload fits the length field.
 * @internal
 *
 * @param[in] nonce_len Nonce bytes.
 * @param[in] tag_len   Tag bytes.
 * @param[in] len       Payload bytes.
 *
 * @return Non-zero when valid.
 */
static uint32_t noxtls_stm32wb_ccm_params_ok(uint32_t nonce_len, uint32_t tag_len, uint32_t len)
{
    uint32_t ok = 0U;
    uint32_t l_size;

    if ((nonce_len >= NOXTLS_STM32WB_AES_CCM_NONCE_MIN) && (nonce_len <= NOXTLS_STM32WB_AES_CCM_NONCE_MAX) &&
        (tag_len >= NOXTLS_STM32WB_AES_CCM_TAG_MIN) && (tag_len <= NOXTLS_STM32WB_AES_CCM_TAG_MAX) &&
        ((tag_len % 2U) == 0U)) {
        l_size = NOXTLS_STM32WB_CCM_NL_BYTES - nonce_len;
        if ((l_size >= NOXTLS_STM32WB_CCM_L_FULL) || (len < (UINT32_C(1) << (l_size * NOXTLS_STM32WB_BYTE_BITS)))) {
            ok = 1U;
        }
    }
    return ok;
}

/**
 * @brief Build the CCM B0 block (NIST SP 800-38C A.2.1).
 * @internal
 *
 * @param[out] b0        Block (16 bytes).
 * @param[in]  nonce     Nonce.
 * @param[in]  nonce_len Nonce bytes.
 * @param[in]  aad_len   Additional data bytes.
 * @param[in]  len       Payload bytes.
 * @param[in]  tag_len   Tag bytes.
 */
static void noxtls_stm32wb_ccm_b0(uint8_t *b0, const uint8_t *nonce, uint32_t nonce_len, uint32_t aad_len,
                                  uint32_t len, uint32_t tag_len)
{
    uint32_t l_size = NOXTLS_STM32WB_CCM_NL_BYTES - nonce_len;
    uint32_t i;
    uint32_t v = len;

    noxtls_secure_zero(b0, NOXTLS_STM32WB_AES_BLOCK);
    b0[0] = (uint8_t)(((aad_len != 0U) ? NOXTLS_STM32WB_CCM_FLAG_ADATA : 0U) |
                      (((tag_len - 2U) / 2U) << NOXTLS_STM32WB_CCM_FLAG_T_SHIFT) | (l_size - 1U));
    noxtls_copy_u8(&b0[1], nonce_len, nonce, nonce_len);
    for (i = 0U; (i < l_size) && (i < NOXTLS_STM32WB_WORD_BYTES); i++) {
        b0[NOXTLS_STM32WB_AES_BLOCK - 1U - i] = (uint8_t)(v & 0xFFU);
        v >>= NOXTLS_STM32WB_BYTE_BITS;
    }
}

/**
 * @brief Encode the CCM additional-data length (NIST SP 800-38C A.2.2).
 * @internal
 *
 * @param[out] prefix  Encoding (up to 6 bytes).
 * @param[in]  aad_len Additional data bytes (non-zero).
 *
 * @return Encoding length.
 */
static uint32_t noxtls_stm32wb_ccm_prefix(uint8_t *prefix, uint32_t aad_len)
{
    uint32_t n;

    if (aad_len < NOXTLS_STM32WB_CCM_ADATA_SHORT_MAX) {
        prefix[0] = (uint8_t)(aad_len >> NOXTLS_STM32WB_BYTE_BITS);
        prefix[1] = (uint8_t)aad_len;
        n = NOXTLS_STM32WB_CCM_ADATA_SHORT_LEN;
    } else {
        prefix[0] = NOXTLS_STM32WB_CCM_ADATA_MARK0;
        prefix[1] = NOXTLS_STM32WB_CCM_ADATA_MARK1;
        noxtls_stm32wb_aead_put_be32(&prefix[2], aad_len);
        n = NOXTLS_STM32WB_CCM_ADATA_LONG_LEN;
    }
    return n;
}

/**
 * @brief CCM phases after the engine is configured.
 * @internal
 *
 * @param[in]  decrypt Non-zero when decrypting.
 * @param[in]  aad     Additional data.
 * @param[in]  aad_len Additional data bytes.
 * @param[in]  in      Input.
 * @param[out] out     Output.
 * @param[in]  len     Payload bytes.
 * @param[out] calc    Computed tag (16 bytes).
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_FAILED.
 */
static noxtls_return_t noxtls_stm32wb_ccm_run(uint8_t decrypt, const uint8_t *aad, uint32_t aad_len,
                                              const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *calc)
{
    noxtls_return_t rc;
    uint8_t prefix[NOXTLS_STM32WB_CCM_ADATA_LONG_LEN];
    uint32_t prefix_len = 0U;

    noxtls_stm32wb_aes_cr(0U, NOXTLS_STM32WB_AES_CR_EN);
    rc = noxtls_stm32wb_aes_wait();
    if (rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_stm32wb_aead_phase(NOXTLS_STM32WB_AES_PHASE_HEADER);
        if (aad_len != 0U) {
            prefix_len = noxtls_stm32wb_ccm_prefix(prefix, aad_len);
        }
        rc = noxtls_stm32wb_aead_header(prefix, prefix_len, aad, aad_len);
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_stm32wb_aead_phase(NOXTLS_STM32WB_AES_PHASE_PAYLOAD);
        rc = noxtls_stm32wb_aead_payload((decrypt != 0U) ? 1U : 0U, in, out, len);
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_stm32wb_aead_final(NULL, calc);
    }
    return rc;
}

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
                                       uint32_t tag_len)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;
    uint8_t b0[NOXTLS_STM32WB_AES_BLOCK];
    uint8_t calc[NOXTLS_STM32WB_AES_BLOCK];
    uint32_t op = (decrypt != 0U) ? NOXTLS_STM32WB_AES_MODE_DECRYPT : NOXTLS_STM32WB_AES_MODE_ENCRYPT;

    if ((key != NULL) && (nonce != NULL) && (tag != NULL) &&
        ((aad_len == 0U) || (aad != NULL)) && ((len == 0U) || ((in != NULL) && (out != NULL))) &&
        (aad_len <= NOXTLS_STM32WB_CONFIG_AES_MAX_LEN) && (len <= NOXTLS_STM32WB_CONFIG_AES_MAX_LEN) &&
        (noxtls_stm32wb_ccm_params_ok(nonce_len, tag_len, len) != 0U)) {
        noxtls_stm32wb_ccm_b0(b0, nonce, nonce_len, aad_len, len, tag_len);
        rc = noxtls_stm32wb_aes_open(key, key_len,
                                     NOXTLS_STM32WB_AES_CR_CHMOD_CCM | (op << NOXTLS_STM32WB_AES_CR_MODE_SHIFT) |
                                     NOXTLS_STM32WB_CR_PHASE(NOXTLS_STM32WB_AES_PHASE_INIT), b0);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_stm32wb_ccm_run(decrypt, aad, aad_len, in, out, len, calc);
            noxtls_stm32wb_aes_close();
            if (rc == NOXTLS_RETURN_SUCCESS) {
                rc = noxtls_stm32wb_aead_tag(decrypt, calc, tag, tag_len, out, len);
            }
        }
    }
    noxtls_secure_zero(b0, sizeof(b0));
    noxtls_secure_zero(calc, sizeof(calc));
    return noxtls_stm32wb_aes_account(rc);
}
