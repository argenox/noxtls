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
* File:    noxtls_nrf54_aead.c
* Summary: CRACEN BA411 AES-GCM and AES-CCM
*
*****************************************************************************/

/**
 * @file noxtls_nrf54_aead.c
 * @brief One-shot AES-GCM (NIST SP 800-38D) and AES-CCM (NIST SP 800-38C) on the CRACEN BA411.
 * @ingroup noxtls_nrf54
 *
 * One CryptoMaster job per message. Every input segment is padded to the
 * 16-byte block with "invalid byte" marks in its DMA tag, which the engine
 * treats as the zero padding of the specifications:
 *   fetch: [config: GCM or CCM mode bit, decrypt bit] [key] (GCM: [IV, 12 bytes])
 *          [associated data, header data type]... [payload]
 *          GCM: [len(A) || len(C), 16 bytes]   CCM decrypt: [received tag]
 *   push:  [associated data: discarded] [payload output] (+ padding discarded)
 *          [tag] (+ padding discarded)
 * CCM: the header stream is B0 || encoded AAD length || AAD (SP 800-38C
 * §A.2.1-A.2.2); the first header descriptor is a whole number of blocks
 * whenever more AAD follows, so only the last header descriptor carries
 * padding. The engine derives the counter blocks from B0. For a CCM
 * decryption it returns tag XOR received tag (all zero when authentic); for
 * GCM the computed tag is compared by the CPU in constant time.
 */

#include <stddef.h>
#include <string.h>

#include "noxtls_nrf54_aead.h"

/** @brief Bytes of the BA411 configuration word. */
#define NOXTLS_NRF54_AEAD_CFG_BYTES     4U
/** @brief Mask of the offset inside a block. */
#define NOXTLS_NRF54_AEAD_BLOCK_MSK     (NOXTLS_NRF54_AEAD_BLOCK - 1U)
/** @brief Bits per byte. */
#define NOXTLS_NRF54_AEAD_BITS_PER_BYTE 8U
/** @brief Bytes of each half of the GCM length block. */
#define NOXTLS_NRF54_GCM_LEN_BYTES      8U
/** @brief AES-128 key bytes. */
#define NOXTLS_NRF54_AEAD_KEY_128       16U
/** @brief AES-192 key bytes. */
#define NOXTLS_NRF54_AEAD_KEY_192       24U
/** @brief AES-256 key bytes. */
#define NOXTLS_NRF54_AEAD_KEY_256       32U
/** @brief Smallest CCM nonce (SP 800-38C §A.1). */
#define NOXTLS_NRF54_CCM_NONCE_MIN      7U
/** @brief Largest CCM nonce. */
#define NOXTLS_NRF54_CCM_NONCE_MAX      13U
/** @brief Smallest CCM tag. */
#define NOXTLS_NRF54_CCM_TAG_MIN        4U
/** @brief n + q = 15 (SP 800-38C §A.2.1). */
#define NOXTLS_NRF54_CCM_NQ             15U
/** @brief B0 flags: Adata. */
#define NOXTLS_NRF54_CCM_FLAG_ADATA     0x40U
/** @brief B0 flags: position of (t - 2) / 2. */
#define NOXTLS_NRF54_CCM_FLAG_T_POS     3U
/** @brief Largest q (bytes of the payload length field) not limiting a 32-bit length. */
#define NOXTLS_NRF54_CCM_Q_FULL         4U
/** @brief AAD lengths below this use the 2-byte encoding (SP 800-38C §A.2.2). */
#define NOXTLS_NRF54_CCM_ALEN_SHORT_MAX 0xFF00U
/** @brief Bytes of the short AAD length encoding. */
#define NOXTLS_NRF54_CCM_ALEN_SHORT     2U
/** @brief Marker of the 32-bit AAD length encoding (0xFF 0xFE). */
#define NOXTLS_NRF54_CCM_ALEN_MARK0     0xFFU
/** @brief Second marker byte. */
#define NOXTLS_NRF54_CCM_ALEN_MARK1     0xFEU
/** @brief Bytes of the 32-bit AAD length value. */
#define NOXTLS_NRF54_CCM_ALEN_LONG      4U
/** @brief Counter blocks reserved below the engine counter wrap (J0 / A0 for the tag, first data block). */
#define NOXTLS_NRF54_AEAD_CTR_RESERVED  2U
/** @brief Counter widths at or above this never limit a 32-bit length. */
#define NOXTLS_NRF54_AEAD_CTR_UNLIMITED 32U

/** Tag of the configuration word. */
#define NOXTLS_NRF54_AEAD_TAG_CFG       (NOXTLS_NRF54_TAG_ENGINE_AES | NOXTLS_NRF54_TAG_CONFIG | \
                                         (NOXTLS_NRF54_AES_REG_CONFIG << NOXTLS_NRF54_TAG_REG_POS))
/** Tag of the key. */
#define NOXTLS_NRF54_AEAD_TAG_KEY       (NOXTLS_NRF54_TAG_ENGINE_AES | NOXTLS_NRF54_TAG_CONFIG | \
                                         (NOXTLS_NRF54_AES_REG_KEY << NOXTLS_NRF54_TAG_REG_POS))
/** Tag of the GCM IV. */
#define NOXTLS_NRF54_AEAD_TAG_IV        (NOXTLS_NRF54_TAG_ENGINE_AES | NOXTLS_NRF54_TAG_CONFIG | \
                                         (NOXTLS_NRF54_AES_REG_IV << NOXTLS_NRF54_TAG_REG_POS))
/** Tag of associated data (header data type). */
#define NOXTLS_NRF54_AEAD_TAG_AAD       (NOXTLS_NRF54_TAG_ENGINE_AES | \
                                         (NOXTLS_NRF54_DTYPE_HEADER << NOXTLS_NRF54_TAG_DTYPE_POS))
/** Tag of the payload, the GCM length block and the CCM received tag. */
#define NOXTLS_NRF54_AEAD_TAG_DATA      (NOXTLS_NRF54_TAG_ENGINE_AES | \
                                         (NOXTLS_NRF54_DTYPE_PAYLOAD << NOXTLS_NRF54_TAG_DTYPE_POS))

/** Module state (data RAM). */
static noxtls_nrf54_aead_t s_noxtls_nrf54_aead;

/** Descriptor chain under construction. */
typedef struct {
    uint32_t nf;          /**< Fetch descriptors used. */
    uint32_t np;          /**< Push descriptors used. */
    uint32_t hdr_padded;  /**< Header bytes including padding (discarded from the output). */
    const uint8_t *in;    /**< Payload input used by the DMA. */
    uint8_t *out;         /**< Payload output used by the DMA. */
    uint8_t out_bounced;  /**< Non-zero when the output goes through the bounce buffer. */
} noxtls_nrf54_aead_chain_t;

/**
 * @brief Round up to a whole block.
 * @internal
 *
 * @param[in] n Bytes.
 *
 * @return Rounded bytes (64-bit so a 32-bit length cannot overflow).
 */
static uint64_t noxtls_nrf54_aead_align(uint32_t n)
{
    return ((uint64_t)n + NOXTLS_NRF54_AEAD_BLOCK_MSK) & ~(uint64_t)NOXTLS_NRF54_AEAD_BLOCK_MSK;
}

/**
 * @brief Add one padded input segment to the fetch chain.
 * @internal
 *
 * @param[in,out] ch  Chain.
 * @param[in]     src Data (DMA readable for the padded length).
 * @param[in]     len Bytes (>= 1).
 * @param[in]     tag Data tag.
 */
static void noxtls_nrf54_aead_in(noxtls_nrf54_aead_chain_t *ch, const uint8_t *src, uint32_t len, uint32_t tag)
{
    uint32_t padded = (uint32_t)noxtls_nrf54_aead_align(len);

    noxtls_nrf54_desc_set(&s_noxtls_nrf54_aead.fetch[ch->nf], src, padded | NOXTLS_NRF54_DESC_REALIGN,
                          tag | (((padded - len) & NOXTLS_NRF54_TAG_IGN_MSK) << NOXTLS_NRF54_TAG_IGN_POS));
    ch->nf++;
}

/**
 * @brief Add one output segment and the discard of its padding to the push chain.
 * @internal
 *
 * @param[in,out] ch  Chain.
 * @param[out]    dst Destination (NULL: discard everything).
 * @param[in]     len Bytes kept.
 * @param[in]     padded Bytes produced by the engine (>= len).
 */
/* cppcheck-suppress constParameterPointer ; dst is written by the CryptoMaster push DMA. */
static void noxtls_nrf54_aead_out(noxtls_nrf54_aead_chain_t *ch, uint8_t *dst, uint32_t len, uint32_t padded)
{
    noxtls_nrf54_aead_t *st = &s_noxtls_nrf54_aead;

    if ((dst != NULL) && (len != 0U)) {
        noxtls_nrf54_desc_set(&st->push[ch->np], dst, len, 0U);
        ch->np++;
    }
    if (padded > len) {
        uint32_t drop = (dst != NULL) ? (padded - len) : padded;

        noxtls_nrf54_desc_set(&st->push[ch->np], NULL, drop | NOXTLS_NRF54_DESC_DISCARD, 0U);
        ch->np++;
    }
}

/**
 * @brief Pick the DMA source of an input segment (direct or bounced).
 * @internal
 *
 * @param[in]  src    Caller data.
 * @param[in]  len    Bytes.
 * @param[in]  bounce Bounce buffer (NOXTLS_NRF54_CONFIG_BOUNCE_SIZE bytes).
 * @param[out] dma    Receives the address the DMA reads.
 *
 * @return 1 on success, 0 when the data is unreachable and too long to bounce.
 */
static uint8_t noxtls_nrf54_aead_source(const uint8_t *src, uint32_t len, uint8_t *bounce, const uint8_t **dma)
{
    uint64_t padded = noxtls_nrf54_aead_align(len);
    uint8_t ok = 1U;

    if ((padded <= (uint64_t)NOXTLS_NRF54_DESC_LEN_MAX) && (noxtls_nrf54_dma_in_ok(src, (uint32_t)padded) != 0U)) {
        *dma = src;
    } else if (padded <= (uint64_t)NOXTLS_NRF54_CONFIG_BOUNCE_SIZE) {
        (void)memset(bounce, 0, (size_t)padded);
        (void)memcpy(bounce, src, len);
        *dma = bounce;
    } else {
        ok = 0U;
    }
    return ok;
}

/**
 * @brief Common checks: key size, engine mode, counter range, segment sizes.
 * @internal
 *
 * @param[in] mode_no BA411 mode number.
 * @param[in] key_len Key bytes.
 * @param[in] len     Payload bytes.
 * @param[in] hdr_len Header bytes (AAD, CCM B0 included).
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_NOT_SUPPORTED (caller releases).
 */
static noxtls_return_t noxtls_nrf54_aead_caps_ok(uint32_t mode_no, uint32_t key_len, uint32_t len, uint64_t hdr_len)
{
    const noxtls_nrf54_caps_t *caps = noxtls_nrf54_cracen_caps();
    uint32_t key_cap = (key_len == NOXTLS_NRF54_AEAD_KEY_128) ? 1U : ((key_len == NOXTLS_NRF54_AEAD_KEY_192) ? 2U : 4U);
    uint64_t blocks = noxtls_nrf54_aead_align(len) / NOXTLS_NRF54_AEAD_BLOCK;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if (((caps->aes_keys & key_cap) == 0U) || ((caps->aes_modes & (UINT32_C(1) << mode_no)) == 0U)) {
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
    } else if ((caps->ctr_bits < NOXTLS_NRF54_AEAD_CTR_UNLIMITED) &&
               (blocks > (((uint64_t)1U << caps->ctr_bits) - NOXTLS_NRF54_AEAD_CTR_RESERVED))) {
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
    } else if ((noxtls_nrf54_aead_align(len) > (uint64_t)NOXTLS_NRF54_DESC_LEN_MAX) ||
               (hdr_len > (uint64_t)NOXTLS_NRF54_DESC_LEN_MAX)) {
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
    } else {
        /* Engine can run the request. */
    }
    return rc;
}

/**
 * @brief Add the payload input / output to the chain (direct or bounced).
 * @internal
 *
 * @param[in,out] ch  Chain.
 * @param[in]     in  Input.
 * @param[out]    out Output.
 * @param[in]     len Bytes.
 *
 * @return 1 on success, 0 when a buffer is unreachable and too long to bounce.
 */
static uint8_t noxtls_nrf54_aead_payload(noxtls_nrf54_aead_chain_t *ch, const uint8_t *in, uint8_t *out, uint32_t len)
{
    noxtls_nrf54_aead_t *st = &s_noxtls_nrf54_aead;
    uint8_t ok = 1U;

    ch->out = out;
    ch->out_bounced = 0U;
    if (len != 0U) {
        ok = noxtls_nrf54_aead_source(in, len, st->bin, &ch->in);
        if ((ok != 0U) && (noxtls_nrf54_dma_out_ok(out, len) == 0U)) {
            if (len <= (uint32_t)NOXTLS_NRF54_CONFIG_BOUNCE_SIZE) {
                ch->out = st->bout;
                ch->out_bounced = 1U;
            } else {
                ok = 0U;
            }
        }
    }
    return ok;
}

/**
 * @brief Run the chain, then release the tag / payload and check authenticity.
 * @internal
 *
 * @param[in]     ch      Chain (fetch / push complete except linking).
 * @param[out]    out     Caller output.
 * @param[in]     len     Payload bytes.
 * @param[in]     decrypt Non-zero to verify.
 * @param[in]     gcm     Non-zero for GCM (compare tags), zero for CCM (XOR must be zero).
 * @param[in,out] tag     Caller tag.
 * @param[in]     tag_len Tag bytes.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_BAD_DATA or the job error.
 */
static noxtls_return_t noxtls_nrf54_aead_finish(const noxtls_nrf54_aead_chain_t *ch, uint8_t *out, uint32_t len,
                                                uint8_t decrypt, uint8_t gcm, uint8_t *tag, uint32_t tag_len)
{
    noxtls_nrf54_aead_t *st = &s_noxtls_nrf54_aead;
    noxtls_return_t rc;
    uint32_t total = (uint32_t)(ch->hdr_padded + noxtls_nrf54_aead_align(len));

    noxtls_nrf54_desc_link(st->fetch, ch->nf, 1U);
    noxtls_nrf54_desc_link(st->push, ch->np, 0U);
    rc = noxtls_nrf54_cracen_cm_run(st->fetch, st->push, total);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        uint8_t diff = 0U;
        uint32_t i;

        if ((ch->out_bounced != 0U) && (len != 0U)) {
            (void)memcpy(out, st->bout, len);
        }
        if (decrypt == 0U) {
            (void)memcpy(tag, st->tag, tag_len);
        } else {
            for (i = 0U; i < tag_len; i++) {
                diff |= (gcm != 0U) ? (uint8_t)(st->tag[i] ^ tag[i]) : st->tag[i];
            }
            if (diff != 0U) {
                /* Never release unauthenticated plaintext. */
                noxtls_nrf54_wipe(out, len);
                rc = NOXTLS_RETURN_BAD_DATA;
            }
        }
    } else if (len != 0U) {
        noxtls_nrf54_wipe(out, len);
    } else {
        /* No payload to wipe. */
    }
    return rc;
}

/**
 * @brief Wipe every buffer of the module and release CRACEN.
 * @internal
 */
static void noxtls_nrf54_aead_cleanup(void)
{
    noxtls_nrf54_aead_t *st = &s_noxtls_nrf54_aead;

    noxtls_nrf54_wipe(st->key, (uint32_t)sizeof(st->key));
    noxtls_nrf54_wipe(st->iv, (uint32_t)sizeof(st->iv));
    noxtls_nrf54_wipe(st->hdr, (uint32_t)sizeof(st->hdr));
    noxtls_nrf54_wipe(st->lens, (uint32_t)sizeof(st->lens));
    noxtls_nrf54_wipe(st->tag, (uint32_t)sizeof(st->tag));
    noxtls_nrf54_wipe(st->bin, (uint32_t)sizeof(st->bin));
    noxtls_nrf54_wipe(st->bout, (uint32_t)sizeof(st->bout));
    noxtls_nrf54_wipe(st->baad, (uint32_t)sizeof(st->baad));
    noxtls_nrf54_cracen_release();
}

/**
 * @brief Start a chain with the configuration word and the key.
 * @internal
 *
 * @param[out] ch      Chain.
 * @param[in]  mode_no BA411 mode number.
 * @param[in]  decrypt Non-zero to decrypt.
 * @param[in]  key     Key.
 * @param[in]  key_len Key bytes.
 */
static void noxtls_nrf54_aead_head(noxtls_nrf54_aead_chain_t *ch, uint32_t mode_no, uint8_t decrypt,
                                   const uint8_t *key, uint32_t key_len)
{
    noxtls_nrf54_aead_t *st = &s_noxtls_nrf54_aead;

    (void)memset(ch, 0, sizeof(*ch));
    st->cfg = (UINT32_C(1) << (NOXTLS_NRF54_AES_CFG_MODE_POS + mode_no)) |
              ((decrypt != 0U) ? NOXTLS_NRF54_AES_CFG_DECRYPT : 0U);
    (void)memcpy(st->key, key, key_len);
    noxtls_nrf54_desc_set(&st->fetch[0], &st->cfg, NOXTLS_NRF54_AEAD_CFG_BYTES | NOXTLS_NRF54_DESC_REALIGN,
                          NOXTLS_NRF54_AEAD_TAG_CFG);
    noxtls_nrf54_desc_set(&st->fetch[1], st->key, key_len | NOXTLS_NRF54_DESC_REALIGN, NOXTLS_NRF54_AEAD_TAG_KEY);
    ch->nf = 2U;
}

/**
 * @brief Whether a key length is an AES key length.
 * @internal
 *
 * @param[in] key_len Bytes.
 *
 * @return 1 for 16, 24 or 32.
 */
static uint8_t noxtls_nrf54_aead_key_len_ok(uint32_t key_len)
{
    return ((key_len == NOXTLS_NRF54_AEAD_KEY_128) || (key_len == NOXTLS_NRF54_AEAD_KEY_192) ||
            (key_len == NOXTLS_NRF54_AEAD_KEY_256)) ? 1U : 0U;
}

/**
 * @brief Write a big-endian integer.
 * @internal
 *
 * @param[out] dst   Destination.
 * @param[in]  value Value.
 * @param[in]  bytes Field bytes (<= 8).
 */
static void noxtls_nrf54_aead_put_be(uint8_t *dst, uint64_t value, uint32_t bytes)
{
    uint32_t i;

    for (i = 0U; i < bytes; i++) {
        dst[bytes - 1U - i] = (uint8_t)(value >> (i * NOXTLS_NRF54_AEAD_BITS_PER_BYTE));
    }
}

noxtls_return_t noxtls_nrf54_aead_gcm(uint8_t decrypt, const uint8_t *key, uint32_t key_len, const uint8_t *iv,
                                      const uint8_t *aad, uint32_t aad_len, const uint8_t *in, uint8_t *out,
                                      uint32_t len, uint8_t *tag)
{
    noxtls_nrf54_aead_t *st = &s_noxtls_nrf54_aead;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if ((key == NULL) || (iv == NULL) || (tag == NULL) || ((aad == NULL) && (aad_len != 0U)) ||
        (((in == NULL) || (out == NULL)) && (len != 0U))) {
        rc = NOXTLS_RETURN_NULL;
    } else if (noxtls_nrf54_aead_key_len_ok(key_len) == 0U) {
        rc = NOXTLS_RETURN_INVALID_KEY_SIZE;
    } else {
        rc = noxtls_nrf54_cracen_acquire(NOXTLS_NRF54_MOD_CM);
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_nrf54_aead_chain_t ch;
        const uint8_t *aad_dma = NULL;

        rc = noxtls_nrf54_aead_caps_ok(NOXTLS_NRF54_AES_MODE_GCM, key_len, len, noxtls_nrf54_aead_align(aad_len));
        if (rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_nrf54_aead_head(&ch, NOXTLS_NRF54_AES_MODE_GCM, decrypt, key, key_len);
            (void)memcpy(st->iv, iv, NOXTLS_NRF54_GCM_IV_BYTES);
            noxtls_nrf54_desc_set(&st->fetch[ch.nf], st->iv, NOXTLS_NRF54_GCM_IV_BYTES | NOXTLS_NRF54_DESC_REALIGN,
                                  NOXTLS_NRF54_AEAD_TAG_IV);
            ch.nf++;
            if (((aad_len != 0U) && (noxtls_nrf54_aead_source(aad, aad_len, st->baad, &aad_dma) == 0U)) ||
                (noxtls_nrf54_aead_payload(&ch, in, out, len) == 0U)) {
                rc = NOXTLS_RETURN_NOT_SUPPORTED;
            }
        }
        if (rc == NOXTLS_RETURN_SUCCESS) {
            if (aad_len != 0U) {
                noxtls_nrf54_aead_in(&ch, aad_dma, aad_len, NOXTLS_NRF54_AEAD_TAG_AAD);
                ch.hdr_padded = (uint32_t)noxtls_nrf54_aead_align(aad_len);
                noxtls_nrf54_aead_out(&ch, NULL, 0U, ch.hdr_padded);
            }
            if (len != 0U) {
                noxtls_nrf54_aead_in(&ch, ch.in, len, NOXTLS_NRF54_AEAD_TAG_DATA);
                noxtls_nrf54_aead_out(&ch, ch.out, len, (uint32_t)noxtls_nrf54_aead_align(len));
            }
            /* SP 800-38D §7.1 step 5: [len(A)]64 || [len(C)]64 in bits. */
            noxtls_nrf54_aead_put_be(st->lens, (uint64_t)aad_len * NOXTLS_NRF54_AEAD_BITS_PER_BYTE,
                                     NOXTLS_NRF54_GCM_LEN_BYTES);
            noxtls_nrf54_aead_put_be(&st->lens[NOXTLS_NRF54_GCM_LEN_BYTES], (uint64_t)len * NOXTLS_NRF54_AEAD_BITS_PER_BYTE,
                                     NOXTLS_NRF54_GCM_LEN_BYTES);
            noxtls_nrf54_aead_in(&ch, st->lens, NOXTLS_NRF54_AEAD_BLOCK, NOXTLS_NRF54_AEAD_TAG_DATA);
            noxtls_nrf54_aead_out(&ch, st->tag, NOXTLS_NRF54_AEAD_TAG_MAX, NOXTLS_NRF54_AEAD_BLOCK);
            rc = noxtls_nrf54_aead_finish(&ch, out, len, decrypt, 1U, tag, NOXTLS_NRF54_AEAD_TAG_MAX);
        }
        noxtls_nrf54_aead_cleanup();
    }
    return rc;
}

/**
 * @brief Validate the CCM-specific parameters.
 * @internal
 *
 * @param[in] nonce_len Nonce bytes.
 * @param[in] len       Payload bytes.
 * @param[in] tag_len   Tag bytes.
 *
 * @return 1 when valid.
 */
static uint8_t noxtls_nrf54_ccm_params_ok(uint32_t nonce_len, uint32_t len, uint32_t tag_len)
{
    uint8_t ok = 1U;

    if ((nonce_len < NOXTLS_NRF54_CCM_NONCE_MIN) || (nonce_len > NOXTLS_NRF54_CCM_NONCE_MAX) ||
        (tag_len < NOXTLS_NRF54_CCM_TAG_MIN) || (tag_len > NOXTLS_NRF54_AEAD_TAG_MAX) || ((tag_len & 1U) != 0U)) {
        ok = 0U;
    } else {
        uint32_t q = NOXTLS_NRF54_CCM_NQ - nonce_len;

        if ((q < NOXTLS_NRF54_CCM_Q_FULL) && (((uint64_t)len >> (q * NOXTLS_NRF54_AEAD_BITS_PER_BYTE)) != 0U)) {
            ok = 0U;
        }
    }
    return ok;
}

/**
 * @brief Format B0 and the AAD length encoding, then the first AAD bytes (SP 800-38C §A.2).
 * @internal
 *
 * @param[in] nonce     Nonce.
 * @param[in] nonce_len Nonce bytes.
 * @param[in] aad       AAD.
 * @param[in] aad_len   AAD bytes.
 * @param[in] len       Payload bytes.
 * @param[in] tag_len   Tag bytes.
 *
 * @return AAD bytes copied into the header.
 */
static uint32_t noxtls_nrf54_ccm_header(const uint8_t *nonce, uint32_t nonce_len, const uint8_t *aad, uint32_t aad_len,
                                        uint32_t len, uint32_t tag_len, uint32_t *hdr_len)
{
    uint8_t *hdr = s_noxtls_nrf54_aead.hdr;
    uint32_t q = NOXTLS_NRF54_CCM_NQ - nonce_len;
    uint32_t n = NOXTLS_NRF54_AEAD_BLOCK;
    uint32_t fed;
    uint32_t flags = (((tag_len - 2U) / 2U) << NOXTLS_NRF54_CCM_FLAG_T_POS) | (q - 1U);

    (void)memset(hdr, 0, NOXTLS_NRF54_CCM_HDR_BYTES);
    if (aad_len != 0U) {
        flags |= NOXTLS_NRF54_CCM_FLAG_ADATA;
    }
    hdr[0] = (uint8_t)flags;
    (void)memcpy(&hdr[1], nonce, nonce_len);
    noxtls_nrf54_aead_put_be(&hdr[1U + nonce_len], (uint64_t)len, q);
    if (aad_len >= NOXTLS_NRF54_CCM_ALEN_SHORT_MAX) {
        hdr[n] = (uint8_t)NOXTLS_NRF54_CCM_ALEN_MARK0;
        hdr[n + 1U] = (uint8_t)NOXTLS_NRF54_CCM_ALEN_MARK1;
        noxtls_nrf54_aead_put_be(&hdr[n + NOXTLS_NRF54_CCM_ALEN_SHORT], (uint64_t)aad_len, NOXTLS_NRF54_CCM_ALEN_LONG);
        n += NOXTLS_NRF54_CCM_ALEN_SHORT + NOXTLS_NRF54_CCM_ALEN_LONG;
    } else if (aad_len != 0U) {
        noxtls_nrf54_aead_put_be(&hdr[n], (uint64_t)aad_len, NOXTLS_NRF54_CCM_ALEN_SHORT);
        n += NOXTLS_NRF54_CCM_ALEN_SHORT;
    } else {
        /* No AAD: B0 only. */
    }
    fed = NOXTLS_NRF54_CCM_HDR_BYTES - n;
    if (fed > aad_len) {
        fed = aad_len;
    }
    if (fed != 0U) {
        (void)memcpy(&hdr[n], aad, fed);
    }
    *hdr_len = n + fed;
    return fed;
}

noxtls_return_t noxtls_nrf54_aead_ccm(uint8_t decrypt, const uint8_t *key, uint32_t key_len, const uint8_t *nonce,
                                      uint32_t nonce_len, const uint8_t *aad, uint32_t aad_len, const uint8_t *in,
                                      uint8_t *out, uint32_t len, uint8_t *tag, uint32_t tag_len)
{
    noxtls_nrf54_aead_t *st = &s_noxtls_nrf54_aead;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if ((key == NULL) || (nonce == NULL) || (tag == NULL) || ((aad == NULL) && (aad_len != 0U)) ||
        (((in == NULL) || (out == NULL)) && (len != 0U))) {
        rc = NOXTLS_RETURN_NULL;
    } else if (noxtls_nrf54_aead_key_len_ok(key_len) == 0U) {
        rc = NOXTLS_RETURN_INVALID_KEY_SIZE;
    } else if (noxtls_nrf54_ccm_params_ok(nonce_len, len, tag_len) == 0U) {
        rc = NOXTLS_RETURN_INVALID_PARAM;
    } else {
        rc = noxtls_nrf54_cracen_acquire(NOXTLS_NRF54_MOD_CM);
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_nrf54_aead_chain_t ch;
        uint32_t hdr_len = 0U;
        uint32_t fed = noxtls_nrf54_ccm_header(nonce, nonce_len, aad, aad_len, len, tag_len, &hdr_len);
        uint32_t rest = aad_len - fed;
        const uint8_t *rest_dma = NULL;

        rc = noxtls_nrf54_aead_caps_ok(NOXTLS_NRF54_AES_MODE_CCM, key_len, len,
                                       noxtls_nrf54_aead_align(hdr_len) + noxtls_nrf54_aead_align(rest));
        if (rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_nrf54_aead_head(&ch, NOXTLS_NRF54_AES_MODE_CCM, decrypt, key, key_len);
            if (((rest != 0U) && (noxtls_nrf54_aead_source(&aad[fed], rest, st->baad, &rest_dma) == 0U)) ||
                (noxtls_nrf54_aead_payload(&ch, in, out, len) == 0U)) {
                rc = NOXTLS_RETURN_NOT_SUPPORTED;
            }
        }
        if (rc == NOXTLS_RETURN_SUCCESS) {
            /* With more AAD to come the header is exactly two blocks, so only the last part is padded. */
            noxtls_nrf54_aead_in(&ch, st->hdr, hdr_len, NOXTLS_NRF54_AEAD_TAG_AAD);
            ch.hdr_padded = (uint32_t)noxtls_nrf54_aead_align(hdr_len);
            if (rest != 0U) {
                noxtls_nrf54_aead_in(&ch, rest_dma, rest, NOXTLS_NRF54_AEAD_TAG_AAD);
                ch.hdr_padded += (uint32_t)noxtls_nrf54_aead_align(rest);
            }
            noxtls_nrf54_aead_out(&ch, NULL, 0U, ch.hdr_padded);
            if (len != 0U) {
                noxtls_nrf54_aead_in(&ch, ch.in, len, NOXTLS_NRF54_AEAD_TAG_DATA);
                noxtls_nrf54_aead_out(&ch, ch.out, len, (uint32_t)noxtls_nrf54_aead_align(len));
            }
            if (decrypt != 0U) {
                /* The engine returns computed tag XOR received tag. */
                (void)memcpy(st->lens, tag, tag_len);
                noxtls_nrf54_aead_in(&ch, st->lens, tag_len, NOXTLS_NRF54_AEAD_TAG_DATA);
            }
            noxtls_nrf54_aead_out(&ch, st->tag, tag_len, NOXTLS_NRF54_AEAD_BLOCK);
            rc = noxtls_nrf54_aead_finish(&ch, out, len, decrypt, 0U, tag, tag_len);
        }
        noxtls_nrf54_aead_cleanup();
    }
    return rc;
}
