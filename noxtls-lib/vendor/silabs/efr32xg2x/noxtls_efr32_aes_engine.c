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
* File:    noxtls_efr32_aes_engine.c
* Summary: EFR32xG2x RADIOAES (BA411E) driver: ECB, CBC, CTR and CCM
*
*****************************************************************************/

/**
 * @file noxtls_efr32_aes_engine.c
 * @brief AES (FIPS 197) ECB / CBC / CTR (NIST SP 800-38A) and CCM (NIST SP 800-38C)
 *        on the EFR32xG2x RADIOAES peripheral.
 * @ingroup noxtls_efr32
 *
 * One fetcher / pusher job per request (EFR32xG26 RM, chapter "AES"):
 *   fetch: [configuration word @0] [key @8] ([IV @40]) [data...]
 *   push:  [output...]
 * Descriptor layout, tags and the configuration word follow the behaviour of
 * the Zlib-licensed reference sli_protocol_crypto_radioaes.c (Simplicity SDK
 * v2025.6.3), re-expressed here. A fetch descriptor carries REALIGN unless a
 * header descriptor is followed by more header data; the LAST tag marks the
 * final data descriptor. CCM streams B0 || encoded AAD length || AAD as header
 * data, the payload, and (decrypt) the received tag; the engine returns
 * header+padding (discarded), the payload, and the tag (decrypt: tag XOR
 * received tag, all zero when authentic). A zero-length payload still needs
 * one (fully invalid) payload block.
 */

#include <stddef.h>
#include <string.h>

#include "noxtls_efr32_aes_engine.h"
#include "noxtls_efr32_se_ops.h"

/** @brief Bytes of the BA411E configuration word. */
#define NOXTLS_EFR32_AES_CFG_BYTES      4U
/** @brief Bytes of the mask word. */
#define NOXTLS_EFR32_AES_MASK_BYTES     4U
/** @brief Mask of the offset inside an AES block. */
#define NOXTLS_EFR32_AES_BLOCK_MSK      (NOXTLS_EFR32_AES_BLOCK - 1U)
/** @brief Counter width at which CTR runs natively. */
#define NOXTLS_EFR32_AES_CTR_NATIVE_BITS 128U
/** @brief Bytes per KiB. */
#define NOXTLS_EFR32_AES_BYTES_PER_KIB  1024U
/** @brief Bits per byte. */
#define NOXTLS_EFR32_AES_BITS_PER_BYTE  8U
/** @brief Byte mask. */
#define NOXTLS_EFR32_AES_BYTE_MSK       0xFFU
/** @brief Fetch descriptors of one job (configuration, key, IV, header, AAD, data, tag, spare). */
#define NOXTLS_EFR32_AES_FETCH_MAX      8U
/** @brief Push descriptors of one job. */
#define NOXTLS_EFR32_AES_PUSH_MAX       8U
/** @brief Bytes reserved for B0 and the encoded AAD length. */
#define NOXTLS_EFR32_AES_HDR_BYTES      32U
/** @brief Smallest CCM nonce (SP 800-38C §A.1). */
#define NOXTLS_EFR32_CCM_NONCE_MIN      7U
/** @brief Largest CCM nonce. */
#define NOXTLS_EFR32_CCM_NONCE_MAX      13U
/** @brief Smallest CCM tag. */
#define NOXTLS_EFR32_CCM_TAG_MIN        4U
/** @brief n + q = 15 (SP 800-38C §A.2.1). */
#define NOXTLS_EFR32_CCM_NQ             15U
/** @brief B0 flags: Adata. */
#define NOXTLS_EFR32_CCM_FLAG_ADATA     0x40U
/** @brief B0 flags: position of (t - 2) / 2. */
#define NOXTLS_EFR32_CCM_FLAG_T_POS     3U
/** @brief Largest q (bytes of the payload length field) not limiting a 32-bit length. */
#define NOXTLS_EFR32_CCM_Q_FULL         4U
/** @brief AAD lengths below this use the 2-byte encoding (SP 800-38C §A.2.2). */
#define NOXTLS_EFR32_CCM_ALEN_SHORT_MAX 0xFF00U
/** @brief Bytes of the short AAD length encoding. */
#define NOXTLS_EFR32_CCM_ALEN_SHORT     2U
/** @brief First marker byte of the 32-bit AAD length encoding. */
#define NOXTLS_EFR32_CCM_ALEN_MARK0     0xFFU
/** @brief Second marker byte. */
#define NOXTLS_EFR32_CCM_ALEN_MARK1     0xFEU
/** @brief Bytes of the 32-bit AAD length value. */
#define NOXTLS_EFR32_CCM_ALEN_LONG      4U

/** Tag of the configuration word. */
#define NOXTLS_EFR32_AES_TAG_CFG        (NOXTLS_EFR32_TAG_ENGINE_AES | NOXTLS_EFR32_TAG_CONFIG | \
                                         (NOXTLS_EFR32_AES_REG_CONFIG << NOXTLS_EFR32_TAG_OFFSET_POS))
/** Tag of the key. */
#define NOXTLS_EFR32_AES_TAG_KEY        (NOXTLS_EFR32_TAG_ENGINE_AES | NOXTLS_EFR32_TAG_CONFIG | \
                                         (NOXTLS_EFR32_AES_REG_KEY << NOXTLS_EFR32_TAG_OFFSET_POS))
/** Tag of the IV / counter block. */
#define NOXTLS_EFR32_AES_TAG_IV         (NOXTLS_EFR32_TAG_ENGINE_AES | NOXTLS_EFR32_TAG_CONFIG | \
                                         (NOXTLS_EFR32_AES_REG_IV << NOXTLS_EFR32_TAG_OFFSET_POS))
/** Tag of the mask word. */
#define NOXTLS_EFR32_AES_TAG_MASK       (NOXTLS_EFR32_TAG_ENGINE_AES | NOXTLS_EFR32_TAG_CONFIG | \
                                         (NOXTLS_EFR32_AES_REG_MASK << NOXTLS_EFR32_TAG_OFFSET_POS))
/** Tag of payload data. */
#define NOXTLS_EFR32_AES_TAG_DATA       (NOXTLS_EFR32_TAG_ENGINE_AES | NOXTLS_EFR32_TAG_PAYLOAD)
/** Tag of header (authenticated-only) data. */
#define NOXTLS_EFR32_AES_TAG_HDR        (NOXTLS_EFR32_TAG_ENGINE_AES | NOXTLS_EFR32_TAG_HEADER)

/** One scatter/gather descriptor. */
typedef struct {
    uint32_t addr;   /**< Data address. */
    uint32_t next;   /**< Next descriptor or NOXTLS_EFR32_DESC_STOP. */
    uint32_t length; /**< Byte count | NOXTLS_EFR32_DESC_* flags. */
    uint32_t tag;    /**< DMA tag (fetch descriptors). */
} noxtls_efr32_desc_t;

/** Module state (SRAM; read and written by the DMA). */
typedef struct {
    noxtls_efr32_desc_t mask_desc;                        /**< Mask word fetch (engines that require masking). */
    noxtls_efr32_desc_t fetch[NOXTLS_EFR32_AES_FETCH_MAX]; /**< Fetch chain. */
    noxtls_efr32_desc_t push[NOXTLS_EFR32_AES_PUSH_MAX];   /**< Push chain. */
    uint32_t cfg;                                          /**< Configuration word. */
    uint32_t mask;                                         /**< Mask word. */
    uint8_t key[NOXTLS_EFR32_AES_KEY_MAX];                 /**< Key copy. */
    uint8_t iv[NOXTLS_EFR32_AES_BLOCK];                    /**< IV / counter of the job. */
    uint8_t hdr[NOXTLS_EFR32_AES_HDR_BYTES];               /**< CCM B0 and AAD length encoding. */
    uint8_t tag[NOXTLS_EFR32_AES_BLOCK];                   /**< Engine tag output. */
    uint8_t rtag[NOXTLS_EFR32_AES_BLOCK];                  /**< Received tag fed to a CCM decryption. */
    uint8_t bin[NOXTLS_EFR32_CONFIG_BOUNCE_SIZE];          /**< Input bounce / CTR counter blocks. */
    uint8_t bout[NOXTLS_EFR32_CONFIG_BOUNCE_SIZE];         /**< Output bounce / CTR keystream. */
    uint8_t baad[NOXTLS_EFR32_CONFIG_BOUNCE_SIZE];         /**< AAD bounce. */
} noxtls_efr32_aes_t;

/** Module state. */
static noxtls_efr32_aes_t s_noxtls_efr32_aes;

/** Capabilities. */
static noxtls_efr32_aes_caps_t s_noxtls_efr32_aes_caps;

/** Modes refused at run time. */
static uint32_t s_noxtls_efr32_aes_off;

/** Non-zero: CBC runs natively in the engine. */
static uint8_t s_noxtls_efr32_aes_cbc_native = (uint8_t)NOXTLS_EFR32_CONFIG_AES_CBC_NATIVE;

/** Last mask word (0: not seeded). */
static uint32_t s_noxtls_efr32_aes_mask;

/** Parameters of one ECB / CBC / CTR request. */
typedef struct {
    noxtls_efr32_aes_mode_t mode; /**< Mode. */
    uint8_t decrypt;              /**< Non-zero to decrypt. */
    uint32_t key_len;             /**< Key bytes. */
    uint8_t chain[NOXTLS_EFR32_AES_BLOCK]; /**< Chaining value / next counter block. */
} noxtls_efr32_aes_req_t;

const noxtls_efr32_aes_caps_t *noxtls_efr32_aes_caps(void)
{
    return &s_noxtls_efr32_aes_caps;
}

void noxtls_efr32_aes_reset(void)
{
    s_noxtls_efr32_aes_caps.valid = 0U;
    s_noxtls_efr32_aes_mask = 0U;
    s_noxtls_efr32_aes_off = 0U;
    s_noxtls_efr32_aes_cbc_native = (uint8_t)NOXTLS_EFR32_CONFIG_AES_CBC_NATIVE;
}

void noxtls_efr32_aes_set_cbc_native(uint8_t native)
{
    s_noxtls_efr32_aes_cbc_native = (native != 0U) ? 1U : 0U;
}

void noxtls_efr32_aes_set_modes_disabled(uint32_t mode_bits)
{
    s_noxtls_efr32_aes_off = mode_bits;
}

/**
 * @brief Read the engine capabilities (clocks on).
 * @internal
 */
static void noxtls_efr32_aes_read_caps(void)
{
    noxtls_efr32_aes_caps_t *caps = &s_noxtls_efr32_aes_caps;
    uint32_t cfg1 = noxtls_efr32_aes_rd(NOXTLS_EFR32_AES_BA411E_HW_CFG_1);

    caps->inclips = noxtls_efr32_aes_rd(NOXTLS_EFR32_AES_INCL_IPS_HW_CFG);
    caps->modes = ((caps->inclips & NOXTLS_EFR32_INCL_AES) != 0U) ? (cfg1 & NOXTLS_EFR32_AES_MODES_MSK) : 0U;
    caps->keys = (cfg1 >> NOXTLS_EFR32_AES_KEYSZ_POS) & NOXTLS_EFR32_AES_KEYSZ_MSK;
    caps->ctr_bits = noxtls_efr32_aes_rd(NOXTLS_EFR32_AES_BA411E_HW_CFG_2) & NOXTLS_EFR32_AES_CTRSZ_MSK;
    caps->masking = ((cfg1 & NOXTLS_EFR32_AES_CFG1_MASKING) != 0U) ? 1U : 0U;
    caps->valid = 1U;
}

/**
 * @brief Acquire the engine and make sure the capabilities are known.
 * @internal
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_NOT_SUPPORTED.
 */
static noxtls_return_t noxtls_efr32_aes_begin(void)
{
    noxtls_return_t rc = noxtls_efr32_aes_acquire();

    if ((rc == NOXTLS_RETURN_SUCCESS) && (s_noxtls_efr32_aes_caps.valid == 0U)) {
        noxtls_efr32_aes_read_caps();
    }
    return rc;
}

/**
 * @brief Wipe every buffer of the module and release the engine.
 * @internal
 */
static void noxtls_efr32_aes_end(void)
{
    noxtls_efr32_aes_t *st = &s_noxtls_efr32_aes;

    noxtls_efr32_wipe(st->key, (uint32_t)sizeof(st->key));
    noxtls_efr32_wipe(st->iv, (uint32_t)sizeof(st->iv));
    noxtls_efr32_wipe(st->hdr, (uint32_t)sizeof(st->hdr));
    noxtls_efr32_wipe(st->tag, (uint32_t)sizeof(st->tag));
    noxtls_efr32_wipe(st->rtag, (uint32_t)sizeof(st->rtag));
    noxtls_efr32_wipe(st->bin, (uint32_t)sizeof(st->bin));
    noxtls_efr32_wipe(st->bout, (uint32_t)sizeof(st->bout));
    noxtls_efr32_wipe(st->baad, (uint32_t)sizeof(st->baad));
    noxtls_efr32_aes_release();
}

/**
 * @brief Key size capability bit and configuration field.
 * @internal
 *
 * @param[in]  key_len Key bytes.
 * @param[out] cfg_key Receives the configuration word key-size bits.
 *
 * @return Capability bit, 0 for an invalid size.
 */
static uint32_t noxtls_efr32_aes_key_cap(uint32_t key_len, uint32_t *cfg_key)
{
    uint32_t cap = 0U;

    *cfg_key = 0U;
    if (key_len == 16U) {
        cap = NOXTLS_EFR32_AES_KEYCAP_128;
        *cfg_key = NOXTLS_EFR32_AES_CFG_KEY_128;
    } else if (key_len == 24U) {
        cap = NOXTLS_EFR32_AES_KEYCAP_192;
        *cfg_key = NOXTLS_EFR32_AES_CFG_KEY_192;
    } else if (key_len == 32U) {
        cap = NOXTLS_EFR32_AES_KEYCAP_256;
        *cfg_key = NOXTLS_EFR32_AES_CFG_KEY_256;
    } else {
        /* Invalid size. */
    }
    return cap;
}

/**
 * @brief Fill one descriptor.
 * @internal
 *
 * @param[out] desc   Descriptor.
 * @param[in]  addr   Data address (NULL for a discard).
 * @param[in]  length Byte count | flags.
 * @param[in]  tag    DMA tag.
 */
static void noxtls_efr32_desc_set(noxtls_efr32_desc_t *desc, const void *addr, uint32_t length, uint32_t tag)
{
    desc->addr = (uint32_t)(uintptr_t)addr;
    desc->next = NOXTLS_EFR32_DESC_STOP;
    desc->length = length;
    desc->tag = tag;
}

/**
 * @brief Chain @p count descriptors.
 * @internal
 *
 * @param[in,out] desc  First descriptor.
 * @param[in]     count Descriptors (>= 1).
 */
static void noxtls_efr32_desc_link(noxtls_efr32_desc_t *desc, uint32_t count)
{
    uint32_t i;

    for (i = 0U; (i + 1U) < count; i++) {
        desc[i].next = (uint32_t)(uintptr_t)&desc[i + 1U];
    }
    desc[count - 1U].next = NOXTLS_EFR32_DESC_STOP;
}

/**
 * @brief Put the mask word in front of the fetch chain when the engine requires it.
 * @internal
 *
 * @param[in]  fetch First fetch descriptor.
 * @param[out] first  Receives the descriptor to start the fetcher with.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_NOT_SUPPORTED (no mask entropy).
 */
static noxtls_return_t noxtls_efr32_aes_mask(const noxtls_efr32_desc_t *fetch, const noxtls_efr32_desc_t **first)
{
    noxtls_efr32_aes_t *st = &s_noxtls_efr32_aes;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    *first = fetch;
    if (s_noxtls_efr32_aes_caps.masking != 0U) {
        if (s_noxtls_efr32_aes_mask == 0U) {
            rc = noxtls_efr32_se_trng_fill((uint8_t *)&s_noxtls_efr32_aes_mask, (uint32_t)sizeof(s_noxtls_efr32_aes_mask));
            if (rc != NOXTLS_RETURN_SUCCESS) {
                s_noxtls_efr32_aes_mask = 0U;
                rc = NOXTLS_RETURN_NOT_SUPPORTED;
            }
        }
        if (rc == NOXTLS_RETURN_SUCCESS) {
            /* A different mask per job; the engine requires the top bit set. */
            s_noxtls_efr32_aes_mask = (s_noxtls_efr32_aes_mask + 1U) | NOXTLS_EFR32_AES_MASK_TOP_BIT;
            st->mask = s_noxtls_efr32_aes_mask;
            noxtls_efr32_desc_set(&st->mask_desc, &st->mask, NOXTLS_EFR32_AES_MASK_BYTES | NOXTLS_EFR32_DESC_REALIGN,
                                  NOXTLS_EFR32_AES_TAG_MASK);
            st->mask_desc.next = (uint32_t)(uintptr_t)fetch;
            *first = &st->mask_desc;
        }
    }
    return rc;
}

/**
 * @brief Soft-reset the fetcher / pusher (aborts the job in flight).
 * @internal
 */
static void noxtls_efr32_aes_softreset(void)
{
    uint32_t spins;

    noxtls_efr32_aes_wr(NOXTLS_EFR32_AES_CTRL, NOXTLS_EFR32_AES_CTRL_SWRESET);
    for (spins = 0U; spins < (uint32_t)NOXTLS_EFR32_CONFIG_SOFTRST_SPINS; spins++) {
        (void)noxtls_efr32_aes_rd(NOXTLS_EFR32_AES_STATUS);
    }
    noxtls_efr32_aes_wr(NOXTLS_EFR32_AES_CTRL, NOXTLS_EFR32_AES_CTRL_NONE);
    spins = (uint32_t)NOXTLS_EFR32_CONFIG_IDLE_SPINS;
    while (((noxtls_efr32_aes_rd(NOXTLS_EFR32_AES_STATUS) & NOXTLS_EFR32_AES_ST_SOFTRST_BUSY) != 0U) && (spins > 0U)) {
        spins--;
    }
}

/**
 * @brief Run one fetch / push job and wait for it.
 * @internal
 *
 * @param[in] fetch First fetch descriptor (chain already linked).
 * @param[in] push  First push descriptor (chain already linked).
 * @param[in] bytes Bytes moved (scales the timeout).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_FAILED (bus error), NOXTLS_RETURN_TIMEOUT,
 *         or NOXTLS_RETURN_NOT_SUPPORTED (no entropy for the mask word; nothing was started).
 */
static noxtls_return_t noxtls_efr32_aes_run(const noxtls_efr32_desc_t *fetch, const noxtls_efr32_desc_t *push,
                                            uint32_t bytes)
{
    const noxtls_efr32_desc_t *first = fetch;
    uint64_t timeout_us = (uint64_t)NOXTLS_EFR32_CONFIG_AES_TIMEOUT_US +
                          ((((uint64_t)bytes + (NOXTLS_EFR32_AES_BYTES_PER_KIB - 1U)) / NOXTLS_EFR32_AES_BYTES_PER_KIB) *
                           (uint64_t)NOXTLS_EFR32_CONFIG_AES_US_PER_KIB);
    noxtls_return_t rc = noxtls_efr32_aes_mask(fetch, &first);

    if (rc == NOXTLS_RETURN_SUCCESS) {
        uint64_t spins = noxtls_efr32_us_to_spins((timeout_us > (uint64_t)UINT32_MAX) ? UINT32_MAX : (uint32_t)timeout_us);
        uint32_t status;
        uint32_t flags;

        noxtls_efr32_stats_rw()->aes_jobs++;
        noxtls_efr32_aes_wr(NOXTLS_EFR32_AES_IF_CLR, NOXTLS_EFR32_AES_IF_CLEAR_ALL);
        noxtls_efr32_aes_wr(NOXTLS_EFR32_AES_CTRL, NOXTLS_EFR32_AES_CTRL_SG);
        noxtls_efr32_barrier();
        noxtls_efr32_aes_wr(NOXTLS_EFR32_AES_FETCHADDR, (uint32_t)(uintptr_t)first);
        noxtls_efr32_aes_wr(NOXTLS_EFR32_AES_PUSHADDR, (uint32_t)(uintptr_t)push);
        noxtls_efr32_aes_wr(NOXTLS_EFR32_AES_CMD, NOXTLS_EFR32_AES_CMD_START_BOTH);
        status = noxtls_efr32_aes_rd(NOXTLS_EFR32_AES_STATUS);
        while (((status & NOXTLS_EFR32_AES_ST_BUSY) != 0U) && (spins > 0U)) {
            spins--;
            status = noxtls_efr32_aes_rd(NOXTLS_EFR32_AES_STATUS);
        }
        flags = noxtls_efr32_aes_rd(NOXTLS_EFR32_AES_IF);
        if ((status & NOXTLS_EFR32_AES_ST_BUSY) != 0U) {
            rc = NOXTLS_RETURN_TIMEOUT;
            noxtls_efr32_stats_rw()->aes_timeouts++;
        } else if ((flags & NOXTLS_EFR32_AES_IF_ERRORS) != 0U) {
            rc = NOXTLS_RETURN_FAILED;
            noxtls_efr32_stats_rw()->aes_errors++;
        } else {
            /* Job complete. */
        }
        if (rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_efr32_aes_softreset();
        }
        noxtls_efr32_aes_wr(NOXTLS_EFR32_AES_IF_CLR, NOXTLS_EFR32_AES_IF_CLEAR_ALL);
        noxtls_efr32_barrier();
    }
    return rc;
}

/**
 * @brief Add @p blocks to a 128-bit big-endian counter block.
 * @internal
 *
 * @param[in,out] ctr    Counter block.
 * @param[in]     blocks Increment.
 */
static void noxtls_efr32_aes_ctr_add(uint8_t *ctr, uint32_t blocks)
{
    uint32_t carry = blocks;
    uint32_t i = NOXTLS_EFR32_AES_BLOCK;

    while ((carry != 0U) && (i > 0U)) {
        uint32_t sum;

        i--;
        sum = (uint32_t)ctr[i] + (carry & NOXTLS_EFR32_AES_BYTE_MSK);
        ctr[i] = (uint8_t)(sum & NOXTLS_EFR32_AES_BYTE_MSK);
        carry = (carry >> NOXTLS_EFR32_AES_BITS_PER_BYTE) + (sum >> NOXTLS_EFR32_AES_BITS_PER_BYTE);
    }
}

/**
 * @brief Run one ECB / CBC / CTR engine job over whole blocks.
 * @internal
 *
 * @param[in]  req     Request.
 * @param[in]  mode_no BA411E mode number.
 * @param[in]  decrypt Non-zero to decrypt.
 * @param[in]  with_iv Non-zero to load the IV and the context.
 * @param[in]  src     Input (DMA readable).
 * @param[out] dst     Output (DMA writable).
 * @param[in]  n       Bytes (whole blocks).
 *
 * @return noxtls_efr32_aes_run() result.
 */
static noxtls_return_t noxtls_efr32_aes_job(const noxtls_efr32_aes_req_t *req, uint32_t mode_no, uint8_t decrypt,
                                            /* cppcheck-suppress constParameterPointer ; dst is written by the pusher DMA. */
                                            uint8_t with_iv, const uint8_t *src, uint8_t *dst, uint32_t n)
{
    noxtls_efr32_aes_t *st = &s_noxtls_efr32_aes;
    uint32_t cfg_key = 0U;
    uint32_t nf = 2U;

    (void)noxtls_efr32_aes_key_cap(req->key_len, &cfg_key);
    st->cfg = (UINT32_C(1) << (NOXTLS_EFR32_AES_CFG_MODE_POS + mode_no)) | cfg_key |
              ((decrypt != 0U) ? NOXTLS_EFR32_AES_CFG_DECRYPT : 0U) |
              ((with_iv != 0U) ? NOXTLS_EFR32_AES_CFG_CX_LOAD : 0U);
    noxtls_efr32_desc_set(&st->fetch[0], &st->cfg, NOXTLS_EFR32_AES_CFG_BYTES | NOXTLS_EFR32_DESC_REALIGN,
                          NOXTLS_EFR32_AES_TAG_CFG);
    noxtls_efr32_desc_set(&st->fetch[1], st->key, req->key_len | NOXTLS_EFR32_DESC_REALIGN, NOXTLS_EFR32_AES_TAG_KEY);
    if (with_iv != 0U) {
        noxtls_efr32_desc_set(&st->fetch[nf], st->iv, NOXTLS_EFR32_AES_BLOCK | NOXTLS_EFR32_DESC_REALIGN,
                              NOXTLS_EFR32_AES_TAG_IV);
        nf++;
    }
    noxtls_efr32_desc_set(&st->fetch[nf], src, n | NOXTLS_EFR32_DESC_REALIGN,
                          NOXTLS_EFR32_AES_TAG_DATA | NOXTLS_EFR32_TAG_LAST);
    nf++;
    noxtls_efr32_desc_link(st->fetch, nf);
    noxtls_efr32_desc_set(&st->push[0], dst, n, 0U);
    noxtls_efr32_desc_link(st->push, 1U);
    return noxtls_efr32_aes_run(st->fetch, st->push, n);
}

/**
 * @brief ECB / CBC / native CTR over whole blocks, in jobs of the bounce size when buffers are not reachable.
 * @internal
 *
 * @param[in,out] req Request (chain updated).
 * @param[in]     in  Input.
 * @param[out]    out Output.
 * @param[in]     len Bytes (whole blocks).
 *
 * @return noxtls_efr32_aes_run() result of the first failing job.
 */
static noxtls_return_t noxtls_efr32_aes_native(noxtls_efr32_aes_req_t *req, const uint8_t *in, uint8_t *out,
                                               uint32_t len)
{
    noxtls_efr32_aes_t *st = &s_noxtls_efr32_aes;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t mode_no = (req->mode == NOXTLS_EFR32_AES_ECB) ? NOXTLS_EFR32_AES_MODE_ECB :
                       ((req->mode == NOXTLS_EFR32_AES_CBC) ? NOXTLS_EFR32_AES_MODE_CBC : NOXTLS_EFR32_AES_MODE_CTR);
    uint8_t decrypt = ((req->mode != NOXTLS_EFR32_AES_CTR) && (req->decrypt != 0U)) ? 1U : 0U;
    uint32_t done = 0U;

    while ((done < len) && (rc == NOXTLS_RETURN_SUCCESS)) {
        uint32_t n = ((len - done) > (uint32_t)NOXTLS_EFR32_CONFIG_MAX_CHUNK) ? (uint32_t)NOXTLS_EFR32_CONFIG_MAX_CHUNK :
                     (len - done);
        const uint8_t *src = &in[done];
        uint8_t *dst = &out[done];
        uint8_t bounce_in = (noxtls_efr32_dma_in_ok(src, n) == 0U) ? 1U : 0U;
        uint8_t bounce_out = (noxtls_efr32_dma_out_ok(dst, n) == 0U) ? 1U : 0U;
        uint8_t next_iv[NOXTLS_EFR32_AES_BLOCK];

        if (((bounce_in | bounce_out) != 0U) && (n > (uint32_t)NOXTLS_EFR32_CONFIG_BOUNCE_SIZE)) {
            n = (uint32_t)NOXTLS_EFR32_CONFIG_BOUNCE_SIZE;
        }
        if (bounce_in != 0U) {
            (void)memcpy(st->bin, src, n);
            src = st->bin;
        }
        /* CBC decrypt: the next chaining value is the last input block (saved before an in-place job). */
        (void)memcpy(next_iv, &src[n - NOXTLS_EFR32_AES_BLOCK], NOXTLS_EFR32_AES_BLOCK);
        (void)memcpy(st->iv, req->chain, NOXTLS_EFR32_AES_BLOCK);
        rc = noxtls_efr32_aes_job(req, mode_no, decrypt, (req->mode != NOXTLS_EFR32_AES_ECB) ? 1U : 0U, src,
                                  (bounce_out != 0U) ? st->bout : dst, n);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            if (bounce_out != 0U) {
                (void)memcpy(dst, st->bout, n);
            }
            if (req->mode == NOXTLS_EFR32_AES_CBC) {
                (void)memcpy(req->chain, (decrypt != 0U) ? next_iv : &dst[n - NOXTLS_EFR32_AES_BLOCK],
                             NOXTLS_EFR32_AES_BLOCK);
            } else if (req->mode == NOXTLS_EFR32_AES_CTR) {
                noxtls_efr32_aes_ctr_add(req->chain, n / NOXTLS_EFR32_AES_BLOCK);
            } else {
                /* ECB has no chaining value. */
            }
        }
        noxtls_efr32_wipe(next_iv, (uint32_t)sizeof(next_iv));
        done += n;
    }
    return rc;
}

/**
 * @brief CBC composed from hardware ECB (used when NOXTLS_EFR32_CONFIG_AES_CBC_NATIVE is 0).
 * @internal
 *
 * Decryption runs ECB over the whole request and chains in software; encryption is
 * serial and runs one ECB block per job.
 *
 * @param[in,out] req Request (chain updated).
 * @param[in]     in  Input.
 * @param[out]    out Output.
 * @param[in]     len Bytes (whole blocks).
 *
 * @return noxtls_efr32_aes_run() result of the first failing job.
 */
static noxtls_return_t noxtls_efr32_aes_cbc_composed(noxtls_efr32_aes_req_t *req, const uint8_t *in, uint8_t *out,
                                                     uint32_t len)
{
    noxtls_efr32_aes_t *st = &s_noxtls_efr32_aes;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t off = 0U;
    uint32_t i;

    while ((off < len) && (rc == NOXTLS_RETURN_SUCCESS)) {
        if (req->decrypt != 0U) {
            uint32_t n = ((len - off) > (uint32_t)NOXTLS_EFR32_CONFIG_BOUNCE_SIZE) ?
                         (uint32_t)NOXTLS_EFR32_CONFIG_BOUNCE_SIZE : (len - off);
            uint8_t last[NOXTLS_EFR32_AES_BLOCK];

            (void)memcpy(st->bin, &in[off], n);
            (void)memcpy(last, &in[(off + n) - NOXTLS_EFR32_AES_BLOCK], sizeof(last));
            rc = noxtls_efr32_aes_job(req, NOXTLS_EFR32_AES_MODE_ECB, 1U, 0U, st->bin, st->bout, n);
            if (rc == NOXTLS_RETURN_SUCCESS) {
                for (i = 0U; i < n; i++) {
                    uint8_t prev = (i < NOXTLS_EFR32_AES_BLOCK) ? req->chain[i] : in[(off + i) - NOXTLS_EFR32_AES_BLOCK];

                    out[off + i] = (uint8_t)(st->bout[i] ^ prev);
                }
                (void)memcpy(req->chain, last, sizeof(last));
            }
            off += n;
        } else {
            for (i = 0U; i < NOXTLS_EFR32_AES_BLOCK; i++) {
                st->bin[i] = (uint8_t)(in[off + i] ^ req->chain[i]);
            }
            rc = noxtls_efr32_aes_job(req, NOXTLS_EFR32_AES_MODE_ECB, 0U, 0U, st->bin, st->bout, NOXTLS_EFR32_AES_BLOCK);
            if (rc == NOXTLS_RETURN_SUCCESS) {
                (void)memcpy(&out[off], st->bout, NOXTLS_EFR32_AES_BLOCK);
                (void)memcpy(req->chain, st->bout, NOXTLS_EFR32_AES_BLOCK);
            }
            off += NOXTLS_EFR32_AES_BLOCK;
        }
    }
    return rc;
}

/**
 * @brief CTR through hardware ECB keystream (counter built by the CPU).
 * @internal
 *
 * @param[in,out] req Request (chain = next counter block).
 * @param[in]     in  Input.
 * @param[out]    out Output.
 * @param[in]     len Bytes (any length).
 *
 * @return noxtls_efr32_aes_run() result of the first failing job.
 */
static noxtls_return_t noxtls_efr32_aes_ctr_keystream(noxtls_efr32_aes_req_t *req, const uint8_t *in, uint8_t *out,
                                                      uint32_t len)
{
    noxtls_efr32_aes_t *st = &s_noxtls_efr32_aes;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t done = 0U;

    while ((done < len) && (rc == NOXTLS_RETURN_SUCCESS)) {
        uint32_t n = ((len - done) > (uint32_t)NOXTLS_EFR32_CONFIG_BOUNCE_SIZE) ?
                     (uint32_t)NOXTLS_EFR32_CONFIG_BOUNCE_SIZE : (len - done);
        uint32_t blocks = (n + NOXTLS_EFR32_AES_BLOCK_MSK) / NOXTLS_EFR32_AES_BLOCK;
        uint32_t i;

        for (i = 0U; i < blocks; i++) {
            (void)memcpy(&st->bin[i * NOXTLS_EFR32_AES_BLOCK], req->chain, NOXTLS_EFR32_AES_BLOCK);
            noxtls_efr32_aes_ctr_add(req->chain, 1U);
        }
        rc = noxtls_efr32_aes_job(req, NOXTLS_EFR32_AES_MODE_ECB, 0U, 0U, st->bin, st->bout,
                                  blocks * NOXTLS_EFR32_AES_BLOCK);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            for (i = 0U; i < n; i++) {
                out[done + i] = (uint8_t)(in[done + i] ^ st->bout[i]);
            }
        }
        done += n;
    }
    return rc;
}

/**
 * @brief Run an accepted request (engine held, capabilities known).
 * @internal
 *
 * @param[in,out] req Request (mode, direction and key length set).
 * @param[in,out] iv  IV / counter or NULL (ECB).
 * @param[in]     in  Input.
 * @param[out]    out Output.
 * @param[in]     len Bytes.
 *
 * @return As noxtls_efr32_aes_crypt().
 */
static noxtls_return_t noxtls_efr32_aes_execute(noxtls_efr32_aes_req_t *req, uint8_t *iv, const uint8_t *in,
                                                uint8_t *out, uint32_t len)
{
    const noxtls_efr32_aes_caps_t *caps = &s_noxtls_efr32_aes_caps;
    uint32_t cfg_key = 0U;
    uint32_t cap = noxtls_efr32_aes_key_cap(req->key_len, &cfg_key);
    uint8_t keystream = ((req->mode == NOXTLS_EFR32_AES_CTR) && (caps->ctr_bits < NOXTLS_EFR32_AES_CTR_NATIVE_BITS)) ? 1U : 0U;
    uint8_t composed = ((req->mode == NOXTLS_EFR32_AES_CBC) && (s_noxtls_efr32_aes_cbc_native == 0U)) ? 1U : 0U;
    uint32_t mode_no = ((keystream != 0U) || (composed != 0U) || (req->mode == NOXTLS_EFR32_AES_ECB)) ?
                       NOXTLS_EFR32_AES_MODE_ECB :
                       ((req->mode == NOXTLS_EFR32_AES_CBC) ? NOXTLS_EFR32_AES_MODE_CBC : NOXTLS_EFR32_AES_MODE_CTR);
    uint32_t user_mode = (req->mode == NOXTLS_EFR32_AES_ECB) ? NOXTLS_EFR32_AES_MODE_ECB :
                         ((req->mode == NOXTLS_EFR32_AES_CBC) ? NOXTLS_EFR32_AES_MODE_CBC : NOXTLS_EFR32_AES_MODE_CTR);
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if (((caps->keys & cap) == 0U) || ((caps->modes & (UINT32_C(1) << mode_no)) == 0U) ||
        ((s_noxtls_efr32_aes_off & ((UINT32_C(1) << mode_no) | (UINT32_C(1) << user_mode))) != 0U)) {
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
    } else {
        uint32_t full = (req->mode == NOXTLS_EFR32_AES_CTR) ? (len & ~NOXTLS_EFR32_AES_BLOCK_MSK) : len;

        if (iv != NULL) {
            (void)memcpy(req->chain, iv, NOXTLS_EFR32_AES_BLOCK);
        }
        if (keystream != 0U) {
            rc = noxtls_efr32_aes_ctr_keystream(req, in, out, len);
        } else if (composed != 0U) {
            rc = noxtls_efr32_aes_cbc_composed(req, in, out, len);
        } else {
            if (full != 0U) {
                rc = noxtls_efr32_aes_native(req, in, out, full);
            }
            if ((rc == NOXTLS_RETURN_SUCCESS) && (full != len)) {
                /* Native CTR partial last block: one zero-padded block through the bounce buffers. */
                noxtls_efr32_aes_t *st = &s_noxtls_efr32_aes;

                (void)memset(st->bin, 0, NOXTLS_EFR32_AES_BLOCK);
                (void)memcpy(st->bin, &in[full], len - full);
                (void)memcpy(st->iv, req->chain, NOXTLS_EFR32_AES_BLOCK);
                rc = noxtls_efr32_aes_job(req, NOXTLS_EFR32_AES_MODE_CTR, 0U, 1U, st->bin, st->bout, NOXTLS_EFR32_AES_BLOCK);
                if (rc == NOXTLS_RETURN_SUCCESS) {
                    (void)memcpy(&out[full], st->bout, len - full);
                    noxtls_efr32_aes_ctr_add(req->chain, 1U);
                }
            }
        }
        if (rc == NOXTLS_RETURN_SUCCESS) {
            if (iv != NULL) {
                (void)memcpy(iv, req->chain, NOXTLS_EFR32_AES_BLOCK);
            }
        } else if (rc != NOXTLS_RETURN_NOT_SUPPORTED) {
            noxtls_efr32_wipe(out, len);
        } else {
            /* Nothing was started. */
        }
    }
    return rc;
}

noxtls_return_t noxtls_efr32_aes_crypt(noxtls_efr32_aes_mode_t mode, uint8_t decrypt, const uint8_t *key,
                                       uint32_t key_len, uint8_t *iv, const uint8_t *in, uint8_t *out, uint32_t len)
{
    noxtls_efr32_aes_req_t req;
    uint32_t cfg_key = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    req.mode = mode;
    req.decrypt = decrypt;
    req.key_len = key_len;
    (void)memset(req.chain, 0, sizeof(req.chain));
    if ((key == NULL) || (((in == NULL) || (out == NULL)) && (len != 0U)) ||
        ((mode != NOXTLS_EFR32_AES_ECB) && (iv == NULL))) {
        rc = NOXTLS_RETURN_NULL;
    } else if ((mode != NOXTLS_EFR32_AES_ECB) && (mode != NOXTLS_EFR32_AES_CBC) && (mode != NOXTLS_EFR32_AES_CTR)) {
        rc = NOXTLS_RETURN_INVALID_PARAM;
    } else if (noxtls_efr32_aes_key_cap(key_len, &cfg_key) == 0U) {
        rc = NOXTLS_RETURN_INVALID_KEY_SIZE;
    } else if ((mode != NOXTLS_EFR32_AES_CTR) && ((len & NOXTLS_EFR32_AES_BLOCK_MSK) != 0U)) {
        rc = NOXTLS_RETURN_INVALID_PARAM;
    } else if (len == 0U) {
        /* Nothing to do. */
    } else if (len > (uint32_t)NOXTLS_EFR32_CONFIG_AES_MAX_REQUEST) {
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
    } else {
        rc = noxtls_efr32_aes_begin();
        if (rc == NOXTLS_RETURN_SUCCESS) {
            (void)memcpy(s_noxtls_efr32_aes.key, key, key_len);
            rc = noxtls_efr32_aes_execute(&req, iv, in, out, len);
            noxtls_efr32_aes_end();
        }
    }
    noxtls_efr32_wipe(req.chain, (uint32_t)sizeof(req.chain));
    return rc;
}

/**
 * @brief Padding bytes that complete the last block.
 * @internal
 *
 * @param[in] n Bytes.
 *
 * @return 0..15.
 */
static uint32_t noxtls_efr32_ccm_pad(uint32_t n)
{
    return (NOXTLS_EFR32_AES_BLOCK - (n & NOXTLS_EFR32_AES_BLOCK_MSK)) & NOXTLS_EFR32_AES_BLOCK_MSK;
}

/**
 * @brief Write a big-endian integer.
 * @internal
 *
 * @param[out] dst   Destination.
 * @param[in]  value Value.
 * @param[in]  bytes Field bytes (<= 8).
 */
static void noxtls_efr32_put_be(uint8_t *dst, uint64_t value, uint32_t bytes)
{
    uint32_t i;

    for (i = 0U; i < bytes; i++) {
        dst[bytes - 1U - i] = (uint8_t)(value >> (i * NOXTLS_EFR32_AES_BITS_PER_BYTE));
    }
}

/**
 * @brief Validate the CCM parameters.
 * @internal
 *
 * @param[in] nonce_len Nonce bytes.
 * @param[in] len       Payload bytes.
 * @param[in] tag_len   Tag bytes.
 *
 * @return 1 when valid.
 */
static uint8_t noxtls_efr32_ccm_params_ok(uint32_t nonce_len, uint32_t len, uint32_t tag_len)
{
    uint8_t ok = 1U;

    if ((nonce_len < NOXTLS_EFR32_CCM_NONCE_MIN) || (nonce_len > NOXTLS_EFR32_CCM_NONCE_MAX) ||
        (tag_len < NOXTLS_EFR32_CCM_TAG_MIN) || (tag_len > NOXTLS_EFR32_AES_TAG_MAX) || ((tag_len & 1U) != 0U)) {
        ok = 0U;
    } else {
        uint32_t q = NOXTLS_EFR32_CCM_NQ - nonce_len;

        if ((q < NOXTLS_EFR32_CCM_Q_FULL) && (((uint64_t)len >> (q * NOXTLS_EFR32_AES_BITS_PER_BYTE)) != 0U)) {
            ok = 0U;
        }
    }
    return ok;
}

/**
 * @brief Format B0 and the AAD length encoding (SP 800-38C §A.2.1, §A.2.2).
 * @internal
 *
 * @param[out] hdr       NOXTLS_EFR32_AES_HDR_BYTES destination.
 * @param[in]  nonce     Nonce.
 * @param[in]  nonce_len Nonce bytes.
 * @param[in]  aad_len   AAD bytes.
 * @param[in]  len       Payload bytes.
 * @param[in]  tag_len   Tag bytes.
 *
 * @return Header bytes written (B0 plus the AAD length encoding).
 */
static uint32_t noxtls_efr32_ccm_header(uint8_t *hdr, const uint8_t *nonce, uint32_t nonce_len, uint32_t aad_len,
                                        uint32_t len, uint32_t tag_len)
{
    uint32_t q = NOXTLS_EFR32_CCM_NQ - nonce_len;
    uint32_t n = NOXTLS_EFR32_AES_BLOCK;
    uint32_t flags = (((tag_len - 2U) / 2U) << NOXTLS_EFR32_CCM_FLAG_T_POS) | (q - 1U);

    (void)memset(hdr, 0, NOXTLS_EFR32_AES_HDR_BYTES);
    if (aad_len != 0U) {
        flags |= NOXTLS_EFR32_CCM_FLAG_ADATA;
    }
    hdr[0] = (uint8_t)flags;
    (void)memcpy(&hdr[1], nonce, nonce_len);
    noxtls_efr32_put_be(&hdr[1U + nonce_len], (uint64_t)len, q);
    if (aad_len >= NOXTLS_EFR32_CCM_ALEN_SHORT_MAX) {
        hdr[n] = (uint8_t)NOXTLS_EFR32_CCM_ALEN_MARK0;
        hdr[n + 1U] = (uint8_t)NOXTLS_EFR32_CCM_ALEN_MARK1;
        noxtls_efr32_put_be(&hdr[n + NOXTLS_EFR32_CCM_ALEN_SHORT], (uint64_t)aad_len, NOXTLS_EFR32_CCM_ALEN_LONG);
        n += NOXTLS_EFR32_CCM_ALEN_SHORT + NOXTLS_EFR32_CCM_ALEN_LONG;
    } else if (aad_len != 0U) {
        noxtls_efr32_put_be(&hdr[n], (uint64_t)aad_len, NOXTLS_EFR32_CCM_ALEN_SHORT);
        n += NOXTLS_EFR32_CCM_ALEN_SHORT;
    } else {
        /* No AAD: B0 only. */
    }
    return n;
}

/**
 * @brief Pick the DMA source of an input segment (direct or bounced).
 * @internal
 *
 * @param[in]  src    Caller data.
 * @param[in]  len    Bytes.
 * @param[in]  bounce Bounce buffer (NOXTLS_EFR32_CONFIG_BOUNCE_SIZE bytes).
 * @param[out] dma    Receives the address the DMA reads.
 *
 * @return 1 on success, 0 when the data is unreachable and too long to bounce.
 */
static uint8_t noxtls_efr32_ccm_source(const uint8_t *src, uint32_t len, uint8_t *bounce, const uint8_t **dma)
{
    uint8_t ok = 1U;

    if (noxtls_efr32_dma_in_ok(src, len) != 0U) {
        *dma = src;
    } else if (len <= (uint32_t)NOXTLS_EFR32_CONFIG_BOUNCE_SIZE) {
        (void)memcpy(bounce, src, len);
        *dma = bounce;
    } else {
        ok = 0U;
    }
    return ok;
}

/** CCM chain under construction. */
typedef struct {
    uint32_t nf;          /**< Fetch descriptors used. */
    uint32_t np;          /**< Push descriptors used. */
    const uint8_t *aad;   /**< AAD used by the DMA. */
    const uint8_t *in;    /**< Payload input used by the DMA. */
    uint8_t *out;         /**< Payload output used by the DMA. */
    uint8_t out_bounced;  /**< Non-zero when the output goes through the bounce buffer. */
} noxtls_efr32_ccm_chain_t;

/**
 * @brief Append one push descriptor.
 * @internal
 *
 * @param[in,out] ch     Chain.
 * @param[out]    dst    Destination (NULL: discard).
 * @param[in]     len    Bytes.
 */
/* cppcheck-suppress constParameterPointer ; dst is written by the pusher DMA. */
static void noxtls_efr32_ccm_push(noxtls_efr32_ccm_chain_t *ch, uint8_t *dst, uint32_t len)
{
    noxtls_efr32_desc_set(&s_noxtls_efr32_aes.push[ch->np], dst, (dst == NULL) ? (len | NOXTLS_EFR32_DESC_DISCARD) : len, 0U);
    ch->np++;
}

/**
 * @brief Append one fetch descriptor.
 * @internal
 *
 * @param[in,out] ch      Chain.
 * @param[in]     src     Data.
 * @param[in]     len     Bytes.
 * @param[in]     tag     DMA tag.
 * @param[in]     realign Non-zero to set REALIGN.
 */
static void noxtls_efr32_ccm_fetch(noxtls_efr32_ccm_chain_t *ch, const uint8_t *src, uint32_t len, uint32_t tag,
                                   uint8_t realign)
{
    noxtls_efr32_desc_set(&s_noxtls_efr32_aes.fetch[ch->nf], src, len | ((realign != 0U) ? NOXTLS_EFR32_DESC_REALIGN : 0U),
                          tag);
    ch->nf++;
}

/**
 * @brief Build the fetch / push chains of a CCM request.
 * @internal
 *
 * @param[in,out] ch       Chain (buffers chosen).
 * @param[in]     decrypt  Non-zero to decrypt.
 * @param[in]     hdr_len  Bytes of B0 + AAD length encoding.
 * @param[in]     aad_len  AAD bytes.
 * @param[in]     len      Payload bytes.
 * @param[out]    tag      Caller tag (decrypt: the received tag, copied to the module).
 * @param[in]     tag_len  Tag bytes.
 */
static void noxtls_efr32_ccm_build(noxtls_efr32_ccm_chain_t *ch, uint8_t decrypt, uint32_t hdr_len, uint32_t aad_len,
                                   uint32_t len, const uint8_t *tag, uint32_t tag_len)
{
    noxtls_efr32_aes_t *st = &s_noxtls_efr32_aes;
    uint32_t hdr_pad = noxtls_efr32_ccm_pad(hdr_len + aad_len);
    uint32_t data_pad = noxtls_efr32_ccm_pad(len);
    uint8_t last_data = ((decrypt == 0U) || (tag_len == 0U)) ? 1U : 0U;
    uint32_t data_tag = NOXTLS_EFR32_AES_TAG_DATA | ((last_data != 0U) ? NOXTLS_EFR32_TAG_LAST : 0U) |
                        (data_pad << NOXTLS_EFR32_TAG_INVALID_POS);

    /* Header: B0 and the AAD length encoding; the padding belongs to the last header descriptor. */
    noxtls_efr32_ccm_fetch(ch, st->hdr, hdr_len, NOXTLS_EFR32_AES_TAG_HDR |
                           ((aad_len == 0U) ? (hdr_pad << NOXTLS_EFR32_TAG_INVALID_POS) : 0U), (aad_len == 0U) ? 1U : 0U);
    if (aad_len != 0U) {
        noxtls_efr32_ccm_fetch(ch, ch->aad, aad_len, NOXTLS_EFR32_AES_TAG_HDR | (hdr_pad << NOXTLS_EFR32_TAG_INVALID_POS), 1U);
    }
    noxtls_efr32_ccm_fetch(ch, ch->in, len, data_tag, 1U);
    if (last_data == 0U) {
        (void)memcpy(st->rtag, tag, tag_len);
        noxtls_efr32_ccm_fetch(ch, st->rtag, tag_len, NOXTLS_EFR32_AES_TAG_DATA | NOXTLS_EFR32_TAG_LAST |
                               ((NOXTLS_EFR32_AES_BLOCK - tag_len) << NOXTLS_EFR32_TAG_INVALID_POS), 1U);
    }
    /* Push: header and padding are returned and discarded. */
    noxtls_efr32_ccm_push(ch, NULL, hdr_len + aad_len + hdr_pad);
    noxtls_efr32_ccm_push(ch, ch->out, len);
    if (data_pad != 0U) {
        noxtls_efr32_ccm_push(ch, NULL, data_pad);
    }
}

/**
 * @brief Byte @p pos of the stream "AAD length encoding | AAD | zero padding".
 * @internal
 *
 * @param[in] enc     Encoded AAD length bytes.
 * @param[in] enc_len Bytes of @p enc.
 * @param[in] aad     AAD.
 * @param[in] aad_len AAD bytes.
 * @param[in] pos     Stream position.
 *
 * @return The byte, or 0 in the padding.
 */
static uint8_t noxtls_efr32_ccm_stream_byte(const uint8_t *enc, uint32_t enc_len, const uint8_t *aad, uint32_t aad_len,
                                            uint32_t pos)
{
    uint8_t b = 0U;

    if (pos < enc_len) {
        b = enc[pos];
    } else if ((pos - enc_len) < aad_len) {
        b = aad[pos - enc_len];
    } else {
        /* Padding. */
    }
    return b;
}

/**
 * @brief CCM with an empty payload from CBC-MAC and one ECB block.
 * @internal
 *
 * The engine's empty-payload chain (one fully invalid payload block) is the
 * only CCM shape that did not reproduce the NIST / PyCryptodome MIC on silicon
 * (EFR32MG26 bench, nox-driver-lib RADIOAES), while every other length did. With no payload the tag is
 * T xor E(A0) where T is the CBC-MAC of B0 | AAD encoding | AAD | padding,
 * so it is built from the already validated CBC and ECB services. Runs outside
 * the engine lock; each service takes it for its own call.
 *
 * @param[in]     decrypt   Non-zero to verify.
 * @param[in]     key       Key.
 * @param[in]     key_len   16, 24 or 32.
 * @param[in]     nonce     Nonce.
 * @param[in]     nonce_len 7..13.
 * @param[in]     aad       AAD.
 * @param[in]     aad_len   AAD bytes.
 * @param[in,out] tag       Encrypt: receives the tag. Decrypt: the received tag.
 * @param[in]     tag_len   Tag bytes.
 *
 * @return See noxtls_efr32_aes_ccm().
 */
static noxtls_return_t noxtls_efr32_ccm_empty(uint8_t decrypt, const uint8_t *key, uint32_t key_len, const uint8_t *nonce,
                                              uint32_t nonce_len, const uint8_t *aad, uint32_t aad_len, uint8_t *tag,
                                              uint32_t tag_len)
{
    uint8_t hdr[NOXTLS_EFR32_AES_HDR_BYTES];
    uint8_t mac[NOXTLS_EFR32_AES_BLOCK] = {0};
    uint8_t blk[NOXTLS_EFR32_AES_BLOCK];
    uint8_t sink[NOXTLS_EFR32_AES_BLOCK];
    uint8_t s0[NOXTLS_EFR32_AES_BLOCK];
    uint32_t hdr_len = noxtls_efr32_ccm_header(hdr, nonce, nonce_len, aad_len, 0U, tag_len);
    uint32_t enc_len = hdr_len - NOXTLS_EFR32_AES_BLOCK;
    uint32_t total = enc_len + aad_len;
    uint32_t pos = 0U;
    uint32_t i;
    uint32_t q = NOXTLS_EFR32_CCM_NQ - nonce_len;
    uint8_t diff = 0U;
    noxtls_return_t rc = noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_CBC, 0U, key, key_len, mac, hdr, sink, NOXTLS_EFR32_AES_BLOCK);

    while ((rc == NOXTLS_RETURN_SUCCESS) && (pos < total)) {
        for (i = 0U; i < NOXTLS_EFR32_AES_BLOCK; i++) {
            blk[i] = noxtls_efr32_ccm_stream_byte(&hdr[NOXTLS_EFR32_AES_BLOCK], enc_len, aad, aad_len, pos + i);
        }
        rc = noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_CBC, 0U, key, key_len, mac, blk, sink, NOXTLS_EFR32_AES_BLOCK);
        pos += NOXTLS_EFR32_AES_BLOCK;
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        /* A0: flags = q - 1, nonce, counter 0. */
        (void)memset(blk, 0, sizeof(blk));
        blk[0] = (uint8_t)(q - 1U);
        (void)memcpy(&blk[1], nonce, nonce_len);
        rc = noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, key, key_len, NULL, blk, s0, NOXTLS_EFR32_AES_BLOCK);
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        for (i = 0U; i < tag_len; i++) {
            uint8_t t = (uint8_t)(mac[i] ^ s0[i]);

            if (decrypt == 0U) {
                tag[i] = t;
            } else {
                diff |= (uint8_t)(t ^ tag[i]);
            }
        }
        if (diff != 0U) {
            rc = NOXTLS_RETURN_BAD_DATA;
        }
    }
    noxtls_efr32_wipe(mac, (uint32_t)sizeof(mac));
    noxtls_efr32_wipe(s0, (uint32_t)sizeof(s0));
    return rc;
}

noxtls_return_t noxtls_efr32_aes_ccm(uint8_t decrypt, const uint8_t *key, uint32_t key_len, const uint8_t *nonce,
                                     uint32_t nonce_len, const uint8_t *aad, uint32_t aad_len, const uint8_t *in,
                                     uint8_t *out, uint32_t len, uint8_t *tag, uint32_t tag_len)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t cfg_key = 0U;
    uint32_t cap = noxtls_efr32_aes_key_cap(key_len, &cfg_key);
    uint8_t empty = 0U;

    if ((key == NULL) || (nonce == NULL) || (tag == NULL) || ((aad == NULL) && (aad_len != 0U)) ||
        (((in == NULL) || (out == NULL)) && (len != 0U))) {
        rc = NOXTLS_RETURN_NULL;
    } else if (cap == 0U) {
        rc = NOXTLS_RETURN_INVALID_KEY_SIZE;
    } else if (noxtls_efr32_ccm_params_ok(nonce_len, len, tag_len) == 0U) {
        rc = NOXTLS_RETURN_INVALID_PARAM;
    } else if ((len > (uint32_t)NOXTLS_EFR32_CONFIG_AES_MAX_REQUEST) ||
               (aad_len > (uint32_t)NOXTLS_EFR32_CONFIG_AES_MAX_REQUEST)) {
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
    } else if (len == 0U) {
        /* Authentication only: composed from CBC-MAC and ECB (see noxtls_efr32_ccm_empty()). */
        empty = 1U;
        if ((s_noxtls_efr32_aes_off & (UINT32_C(1) << NOXTLS_EFR32_AES_MODE_CCM)) != 0U) {
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
        } else {
            rc = noxtls_efr32_ccm_empty(decrypt, key, key_len, nonce, nonce_len, aad, aad_len, tag, tag_len);
        }
    } else {
        rc = noxtls_efr32_aes_begin();
    }
    if ((rc == NOXTLS_RETURN_SUCCESS) && (empty == 0U)) {
        noxtls_efr32_aes_t *st = &s_noxtls_efr32_aes;
        const noxtls_efr32_aes_caps_t *caps = &s_noxtls_efr32_aes_caps;
        noxtls_efr32_ccm_chain_t ch;
        uint32_t hdr_len;

        (void)memset(&ch, 0, sizeof(ch));
        ch.aad = aad;
        ch.in = in;
        ch.out = out;
        if (((caps->keys & cap) == 0U) || ((caps->modes & (UINT32_C(1) << NOXTLS_EFR32_AES_MODE_CCM)) == 0U) ||
            ((s_noxtls_efr32_aes_off & (UINT32_C(1) << NOXTLS_EFR32_AES_MODE_CCM)) != 0U)) {
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
        } else if (((aad_len != 0U) && (noxtls_efr32_ccm_source(aad, aad_len, st->baad, &ch.aad) == 0U)) ||
                   (noxtls_efr32_ccm_source(in, len, st->bin, &ch.in) == 0U) ||
                   ((noxtls_efr32_dma_out_ok(out, len) == 0U) &&
                    (len > (uint32_t)NOXTLS_EFR32_CONFIG_BOUNCE_SIZE))) {
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
        } else {
            uint32_t i;
            uint8_t diff = 0U;

            if (noxtls_efr32_dma_out_ok(out, len) == 0U) {
                ch.out = st->bout;
                ch.out_bounced = 1U;
            }
            hdr_len = noxtls_efr32_ccm_header(st->hdr, nonce, nonce_len, aad_len, len, tag_len);
            (void)memcpy(st->key, key, key_len);
            st->cfg = (UINT32_C(1) << (NOXTLS_EFR32_AES_CFG_MODE_POS + NOXTLS_EFR32_AES_MODE_CCM)) | cfg_key |
                      ((decrypt != 0U) ? NOXTLS_EFR32_AES_CFG_DECRYPT : 0U);
            noxtls_efr32_desc_set(&st->fetch[0], &st->cfg, NOXTLS_EFR32_AES_CFG_BYTES | NOXTLS_EFR32_DESC_REALIGN,
                                  NOXTLS_EFR32_AES_TAG_CFG);
            noxtls_efr32_desc_set(&st->fetch[1], st->key, key_len | NOXTLS_EFR32_DESC_REALIGN, NOXTLS_EFR32_AES_TAG_KEY);
            ch.nf = 2U;
            noxtls_efr32_ccm_build(&ch, decrypt, hdr_len, aad_len, len, tag, tag_len);
            /* Tag push: straight into the module buffer, then the padding of the last block is dropped. */
            noxtls_efr32_desc_set(&st->push[ch.np], st->tag, tag_len, 0U);
            ch.np++;
            if (tag_len < NOXTLS_EFR32_AES_BLOCK) {
                noxtls_efr32_desc_set(&st->push[ch.np], NULL, (NOXTLS_EFR32_AES_BLOCK - tag_len) | NOXTLS_EFR32_DESC_DISCARD, 0U);
                ch.np++;
            }
            noxtls_efr32_desc_link(st->fetch, ch.nf);
            noxtls_efr32_desc_link(st->push, ch.np);
            rc = noxtls_efr32_aes_run(st->fetch, st->push, hdr_len + aad_len + len);
            if (rc == NOXTLS_RETURN_SUCCESS) {
                if (ch.out_bounced != 0U) {
                    (void)memcpy(out, st->bout, len);
                }
                if (decrypt == 0U) {
                    (void)memcpy(tag, st->tag, tag_len);
                } else {
                    for (i = 0U; i < tag_len; i++) {
                        diff |= st->tag[i];
                    }
                    if (diff != 0U) {
                        /* Never release unauthenticated plaintext. */
                        noxtls_efr32_wipe(out, len);
                        rc = NOXTLS_RETURN_BAD_DATA;
                    }
                }
            } else if (rc != NOXTLS_RETURN_NOT_SUPPORTED) {
                noxtls_efr32_wipe(out, len);
            } else {
                /* The mask word could not be seeded; nothing was started. */
            }
        }
        noxtls_efr32_aes_end();
    }
    return rc;
}
