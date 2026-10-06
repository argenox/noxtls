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
* File:    noxtls_nrf54_aes.c
* Summary: CRACEN BA411 AES-ECB / CBC / CTR
*
*****************************************************************************/

/**
 * @file noxtls_nrf54_aes.c
 * @brief AES (FIPS 197) ECB / CBC / CTR (NIST SP 800-38A) on the CRACEN BA411.
 * @ingroup noxtls_nrf54
 *
 * One CryptoMaster job per chunk:
 *   fetch: [config word: mode bit, decrypt bit] [key] ([IV / counter block])
 *          [payload, LAST | REALIGN]
 *   push:  [output]
 * CBC carries the chaining value between chunks in software (encrypt: last
 * output block; decrypt: last input block, saved before the job so that
 * in-place decryption works). Native CTR advances the 128-bit counter by the
 * number of blocks of the chunk.
 */

#include <stddef.h>
#include <string.h>

#include "noxtls_nrf54_aes.h"

/** @brief Bytes of the BA411 configuration word. */
#define NOXTLS_NRF54_AES_CFG_BYTES      4U
/** @brief Bytes of an AES-128 key. */
#define NOXTLS_NRF54_AES_KEY_128        16U
/** @brief Bytes of an AES-192 key. */
#define NOXTLS_NRF54_AES_KEY_192        24U
/** @brief Bytes of an AES-256 key. */
#define NOXTLS_NRF54_AES_KEY_256        32U
/** @brief Capability bit of 128-bit keys. */
#define NOXTLS_NRF54_AES_CAP_128        (UINT32_C(1) << 0)
/** @brief Capability bit of 192-bit keys. */
#define NOXTLS_NRF54_AES_CAP_192        (UINT32_C(1) << 1)
/** @brief Capability bit of 256-bit keys. */
#define NOXTLS_NRF54_AES_CAP_256        (UINT32_C(1) << 2)
/** @brief Counter width at which CTR runs natively (never wraps inside a 2^32-byte request). */
#define NOXTLS_NRF54_AES_CTR_NATIVE_BITS 128U
/** @brief Mask of the offset inside an AES block. */
#define NOXTLS_NRF54_AES_BLOCK_MSK      (NOXTLS_NRF54_AES_BLOCK - 1U)
/** @brief Largest chunk of one job (whole blocks). */
#define NOXTLS_NRF54_AES_CHUNK          (NOXTLS_NRF54_CONFIG_MAX_CHUNK & ~NOXTLS_NRF54_AES_BLOCK_MSK)
/** @brief Bits per byte. */
#define NOXTLS_NRF54_AES_BITS_PER_BYTE  8U
/** @brief Byte mask. */
#define NOXTLS_NRF54_AES_BYTE_MSK       0xFFU

/** Tag of the configuration word. */
#define NOXTLS_NRF54_AES_TAG_CFG        (NOXTLS_NRF54_TAG_ENGINE_AES | NOXTLS_NRF54_TAG_CONFIG | \
                                         (NOXTLS_NRF54_AES_REG_CONFIG << NOXTLS_NRF54_TAG_REG_POS))
/** Tag of the key. */
#define NOXTLS_NRF54_AES_TAG_KEY        (NOXTLS_NRF54_TAG_ENGINE_AES | NOXTLS_NRF54_TAG_CONFIG | \
                                         (NOXTLS_NRF54_AES_REG_KEY << NOXTLS_NRF54_TAG_REG_POS))
/** Tag of the IV / counter block. */
#define NOXTLS_NRF54_AES_TAG_IV         (NOXTLS_NRF54_TAG_ENGINE_AES | NOXTLS_NRF54_TAG_CONFIG | \
                                         (NOXTLS_NRF54_AES_REG_IV << NOXTLS_NRF54_TAG_REG_POS))
/** Tag of the payload. */
#define NOXTLS_NRF54_AES_TAG_DATA       (NOXTLS_NRF54_TAG_ENGINE_AES | \
                                         (NOXTLS_NRF54_DTYPE_PAYLOAD << NOXTLS_NRF54_TAG_DTYPE_POS))

/** Module state (data RAM). */
static noxtls_nrf54_aes_t s_noxtls_nrf54_aes;

/** Parameters of one request. */
typedef struct {
    noxtls_nrf54_aes_mode_t mode; /**< Mode. */
    uint8_t decrypt;              /**< Non-zero to decrypt. */
    const uint8_t *key;           /**< Key address used by the DMA. */
    uint32_t key_len;             /**< Key bytes. */
    uint8_t chain[NOXTLS_NRF54_AES_BLOCK]; /**< Chaining value / next counter block. */
} noxtls_nrf54_aes_req_t;

/**
 * @brief Key-size capability bit.
 * @internal
 *
 * @param[in] key_len Key bytes.
 *
 * @return Capability bit, 0 for an invalid size.
 */
static uint32_t noxtls_nrf54_aes_key_cap(uint32_t key_len)
{
    uint32_t cap = 0U;

    if (key_len == NOXTLS_NRF54_AES_KEY_128) {
        cap = NOXTLS_NRF54_AES_CAP_128;
    } else if (key_len == NOXTLS_NRF54_AES_KEY_192) {
        cap = NOXTLS_NRF54_AES_CAP_192;
    } else if (key_len == NOXTLS_NRF54_AES_KEY_256) {
        cap = NOXTLS_NRF54_AES_CAP_256;
    } else {
        /* Invalid size. */
    }
    return cap;
}

uint8_t noxtls_nrf54_aes_key_supported(uint32_t key_len)
{
    const noxtls_nrf54_caps_t *caps = noxtls_nrf54_cracen_caps();
    uint32_t cap = noxtls_nrf54_aes_key_cap(key_len);

    return ((cap != 0U) && ((caps->valid == 0U) || ((caps->aes_keys & cap) != 0U))) ? 1U : 0U;
}

/**
 * @brief Add @p blocks to a 128-bit big-endian counter block.
 * @internal
 *
 * @param[in,out] ctr    Counter block.
 * @param[in]     blocks Increment.
 */
static void noxtls_nrf54_aes_ctr_add(uint8_t *ctr, uint32_t blocks)
{
    uint32_t carry = blocks;
    uint32_t i = NOXTLS_NRF54_AES_BLOCK;

    while ((carry != 0U) && (i > 0U)) {
        uint32_t sum;

        i--;
        sum = (uint32_t)ctr[i] + (carry & NOXTLS_NRF54_AES_BYTE_MSK);
        ctr[i] = (uint8_t)(sum & NOXTLS_NRF54_AES_BYTE_MSK);
        carry = (carry >> NOXTLS_NRF54_AES_BITS_PER_BYTE) + (sum >> NOXTLS_NRF54_AES_BITS_PER_BYTE);
    }
}

/**
 * @brief Run one engine job.
 * @internal
 *
 * @param[in]  req     Request.
 * @param[in]  mode_no BA411 mode number.
 * @param[in]  decrypt Non-zero to decrypt.
 * @param[in]  with_iv Non-zero to load s_noxtls_nrf54_aes.iv.
 * @param[in]  src     Input (DMA readable).
 * @param[out] dst     Output (DMA writable).
 * @param[in]  n       Bytes (whole blocks).
 *
 * @return noxtls_nrf54_cracen_cm_run() result.
 */
static noxtls_return_t noxtls_nrf54_aes_job(const noxtls_nrf54_aes_req_t *req, uint32_t mode_no, uint8_t decrypt,
                                            /* cppcheck-suppress constParameterPointer ; dst is written by the push DMA. */
                                            uint8_t with_iv, const uint8_t *src, uint8_t *dst, uint32_t n)
{
    noxtls_nrf54_aes_t *st = &s_noxtls_nrf54_aes;
    uint32_t nf = 2U;

    st->cfg = (UINT32_C(1) << (NOXTLS_NRF54_AES_CFG_MODE_POS + mode_no)) |
              ((decrypt != 0U) ? NOXTLS_NRF54_AES_CFG_DECRYPT : 0U);
    noxtls_nrf54_desc_set(&st->fetch[0], &st->cfg, NOXTLS_NRF54_AES_CFG_BYTES | NOXTLS_NRF54_DESC_REALIGN,
                          NOXTLS_NRF54_AES_TAG_CFG);
    noxtls_nrf54_desc_set(&st->fetch[1], req->key, req->key_len | NOXTLS_NRF54_DESC_REALIGN, NOXTLS_NRF54_AES_TAG_KEY);
    if (with_iv != 0U) {
        noxtls_nrf54_desc_set(&st->fetch[nf], st->iv, NOXTLS_NRF54_AES_BLOCK | NOXTLS_NRF54_DESC_REALIGN,
                              NOXTLS_NRF54_AES_TAG_IV);
        nf++;
    }
    noxtls_nrf54_desc_set(&st->fetch[nf], src, n, NOXTLS_NRF54_AES_TAG_DATA);
    nf++;
    noxtls_nrf54_desc_link(st->fetch, nf, 1U);
    noxtls_nrf54_desc_set(&st->push[0], dst, n, 0U);
    noxtls_nrf54_desc_link(st->push, 1U, 0U);
    return noxtls_nrf54_cracen_cm_run(st->fetch, st->push, n);
}

/**
 * @brief ECB / CBC / native CTR over whole blocks, chunked and bounced as needed.
 * @internal
 *
 * @param[in,out] req Request (chain updated).
 * @param[in]     in  Input.
 * @param[out]    out Output.
 * @param[in]     len Bytes (whole blocks).
 *
 * @return noxtls_nrf54_cracen_cm_run() result of the first failing job.
 */
static noxtls_return_t noxtls_nrf54_aes_native(noxtls_nrf54_aes_req_t *req, const uint8_t *in, uint8_t *out,
                                               uint32_t len)
{
    noxtls_nrf54_aes_t *st = &s_noxtls_nrf54_aes;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t mode_no = (req->mode == NOXTLS_NRF54_AES_ECB) ? NOXTLS_NRF54_AES_MODE_ECB :
                       ((req->mode == NOXTLS_NRF54_AES_CBC) ? NOXTLS_NRF54_AES_MODE_CBC : NOXTLS_NRF54_AES_MODE_CTR);
    uint8_t decrypt = ((req->mode != NOXTLS_NRF54_AES_CTR) && (req->decrypt != 0U)) ? 1U : 0U;
    uint32_t done = 0U;

    while ((done < len) && (rc == NOXTLS_RETURN_SUCCESS)) {
        uint32_t n = ((len - done) > NOXTLS_NRF54_AES_CHUNK) ? NOXTLS_NRF54_AES_CHUNK : (len - done);
        const uint8_t *src = &in[done];
        uint8_t *dst = &out[done];
        uint8_t bounce_in = (noxtls_nrf54_dma_in_ok(src, n) == 0U) ? 1U : 0U;
        uint8_t bounce_out = (noxtls_nrf54_dma_out_ok(dst, n) == 0U) ? 1U : 0U;
        uint8_t next_iv[NOXTLS_NRF54_AES_BLOCK];

        if (((bounce_in | bounce_out) != 0U) && (n > (uint32_t)NOXTLS_NRF54_CONFIG_BOUNCE_SIZE)) {
            n = (uint32_t)NOXTLS_NRF54_CONFIG_BOUNCE_SIZE;
        }
        if (bounce_in != 0U) {
            (void)memcpy(st->bin, src, n);
            src = st->bin;
        }
        /* CBC decrypt: the next chaining value is the last input block (saved before an in-place job). */
        (void)memcpy(next_iv, &src[n - NOXTLS_NRF54_AES_BLOCK], NOXTLS_NRF54_AES_BLOCK);
        (void)memcpy(st->iv, req->chain, NOXTLS_NRF54_AES_BLOCK);
        rc = noxtls_nrf54_aes_job(req, mode_no, decrypt, (req->mode != NOXTLS_NRF54_AES_ECB) ? 1U : 0U, src,
                                  (bounce_out != 0U) ? st->bout : dst, n);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            if (bounce_out != 0U) {
                (void)memcpy(dst, st->bout, n);
            }
            if (req->mode == NOXTLS_NRF54_AES_CBC) {
                (void)memcpy(req->chain, (decrypt != 0U) ? next_iv : &dst[n - NOXTLS_NRF54_AES_BLOCK],
                             NOXTLS_NRF54_AES_BLOCK);
            } else if (req->mode == NOXTLS_NRF54_AES_CTR) {
                noxtls_nrf54_aes_ctr_add(req->chain, n / NOXTLS_NRF54_AES_BLOCK);
            } else {
                /* ECB has no chaining value. */
            }
        }
        noxtls_nrf54_wipe(next_iv, (uint32_t)sizeof(next_iv));
        done += n;
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
 * @return noxtls_nrf54_cracen_cm_run() result of the first failing job.
 */
static noxtls_return_t noxtls_nrf54_aes_ctr_keystream(noxtls_nrf54_aes_req_t *req, const uint8_t *in, uint8_t *out,
                                                      uint32_t len)
{
    noxtls_nrf54_aes_t *st = &s_noxtls_nrf54_aes;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t done = 0U;

    while ((done < len) && (rc == NOXTLS_RETURN_SUCCESS)) {
        uint32_t n = ((len - done) > (uint32_t)NOXTLS_NRF54_CONFIG_BOUNCE_SIZE) ?
                     (uint32_t)NOXTLS_NRF54_CONFIG_BOUNCE_SIZE : (len - done);
        uint32_t blocks = (n + NOXTLS_NRF54_AES_BLOCK_MSK) / NOXTLS_NRF54_AES_BLOCK;
        uint32_t i;

        for (i = 0U; i < blocks; i++) {
            (void)memcpy(&st->bin[i * NOXTLS_NRF54_AES_BLOCK], req->chain, NOXTLS_NRF54_AES_BLOCK);
            noxtls_nrf54_aes_ctr_add(req->chain, 1U);
        }
        rc = noxtls_nrf54_aes_job(req, NOXTLS_NRF54_AES_MODE_ECB, 0U, 0U, st->bin, st->bout,
                                  blocks * NOXTLS_NRF54_AES_BLOCK);
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
 * @brief Validate, acquire and run a request.
 * @internal
 *
 * @param[in,out] req Request (key and mode set).
 * @param[in]     by_value Non-zero when req->key must be copied to module RAM.
 * @param[in,out] iv  IV / counter or NULL (ECB).
 * @param[in]     in  Input.
 * @param[out]    out Output.
 * @param[in]     len Bytes.
 *
 * @return As noxtls_nrf54_aes_crypt().
 */
static noxtls_return_t noxtls_nrf54_aes_run(noxtls_nrf54_aes_req_t *req, uint8_t by_value, uint8_t *iv,
                                            const uint8_t *in, uint8_t *out, uint32_t len)
{
    noxtls_nrf54_aes_t *st = &s_noxtls_nrf54_aes;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t cap = noxtls_nrf54_aes_key_cap(req->key_len);

    if ((req->key == NULL) || (((in == NULL) || (out == NULL)) && (len != 0U)) ||
        ((req->mode != NOXTLS_NRF54_AES_ECB) && (iv == NULL))) {
        rc = NOXTLS_RETURN_NULL;
    } else if ((req->mode != NOXTLS_NRF54_AES_ECB) && (req->mode != NOXTLS_NRF54_AES_CBC) &&
               (req->mode != NOXTLS_NRF54_AES_CTR)) {
        rc = NOXTLS_RETURN_INVALID_PARAM;
    } else if (cap == 0U) {
        rc = NOXTLS_RETURN_INVALID_KEY_SIZE;
    } else if ((req->mode != NOXTLS_NRF54_AES_CTR) && ((len & NOXTLS_NRF54_AES_BLOCK_MSK) != 0U)) {
        rc = NOXTLS_RETURN_INVALID_PARAM;
    } else if (len == 0U) {
        /* Nothing to do. */
    } else {
        rc = noxtls_nrf54_cracen_acquire(NOXTLS_NRF54_MOD_CM);
    }
    if ((rc == NOXTLS_RETURN_SUCCESS) && (len != 0U)) {
        const noxtls_nrf54_caps_t *caps = noxtls_nrf54_cracen_caps();
        uint8_t keystream = ((req->mode == NOXTLS_NRF54_AES_CTR) && (caps->ctr_bits < NOXTLS_NRF54_AES_CTR_NATIVE_BITS)) ?
                            1U : 0U;
        uint32_t mode_bit = UINT32_C(1) << ((keystream != 0U) ? NOXTLS_NRF54_AES_MODE_ECB :
                                            ((req->mode == NOXTLS_NRF54_AES_ECB) ? NOXTLS_NRF54_AES_MODE_ECB :
                                             ((req->mode == NOXTLS_NRF54_AES_CBC) ? NOXTLS_NRF54_AES_MODE_CBC :
                                              NOXTLS_NRF54_AES_MODE_CTR)));

        if (((caps->aes_keys & cap) == 0U) || ((caps->aes_modes & mode_bit) == 0U)) {
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
        } else {
            uint32_t full = (req->mode == NOXTLS_NRF54_AES_CTR) ? (len & ~NOXTLS_NRF54_AES_BLOCK_MSK) : len;

            if (by_value != 0U) {
                (void)memcpy(st->key, req->key, req->key_len);
                req->key = st->key;
            }
            if (iv != NULL) {
                (void)memcpy(req->chain, iv, NOXTLS_NRF54_AES_BLOCK);
            }
            if (keystream != 0U) {
                rc = noxtls_nrf54_aes_ctr_keystream(req, in, out, len);
            } else {
                if (full != 0U) {
                    rc = noxtls_nrf54_aes_native(req, in, out, full);
                }
                if ((rc == NOXTLS_RETURN_SUCCESS) && (full != len)) {
                    /* Native CTR partial last block: one zero-padded block through the bounce buffers. */
                    (void)memset(st->bin, 0, NOXTLS_NRF54_AES_BLOCK);
                    (void)memcpy(st->bin, &in[full], len - full);
                    (void)memcpy(st->iv, req->chain, NOXTLS_NRF54_AES_BLOCK);
                    rc = noxtls_nrf54_aes_job(req, NOXTLS_NRF54_AES_MODE_CTR, 0U, 1U, st->bin, st->bout,
                                              NOXTLS_NRF54_AES_BLOCK);
                    if (rc == NOXTLS_RETURN_SUCCESS) {
                        (void)memcpy(&out[full], st->bout, len - full);
                        noxtls_nrf54_aes_ctr_add(req->chain, 1U);
                    }
                }
            }
            if ((rc == NOXTLS_RETURN_SUCCESS) && (iv != NULL)) {
                (void)memcpy(iv, req->chain, NOXTLS_NRF54_AES_BLOCK);
            }
        }
        noxtls_nrf54_wipe(st->key, (uint32_t)sizeof(st->key));
        noxtls_nrf54_wipe(st->iv, (uint32_t)sizeof(st->iv));
        noxtls_nrf54_wipe(st->bin, (uint32_t)sizeof(st->bin));
        noxtls_nrf54_wipe(st->bout, (uint32_t)sizeof(st->bout));
        noxtls_nrf54_cracen_release();
    }
    noxtls_nrf54_wipe(req->chain, (uint32_t)sizeof(req->chain));
    return rc;
}

noxtls_return_t noxtls_nrf54_aes_crypt(noxtls_nrf54_aes_mode_t mode, uint8_t decrypt, const uint8_t *key,
                                       uint32_t key_len, uint8_t *iv, const uint8_t *in, uint8_t *out, uint32_t len)
{
    noxtls_nrf54_aes_req_t req;

    req.mode = mode;
    req.decrypt = decrypt;
    req.key = key;
    req.key_len = key_len;
    return noxtls_nrf54_aes_run(&req, 1U, iv, in, out, len);
}

noxtls_return_t noxtls_nrf54_aes_crypt_keyref(noxtls_nrf54_aes_mode_t mode, uint8_t decrypt, uintptr_t key_addr,
                                              uint32_t key_len, uint8_t *iv, const uint8_t *in, uint8_t *out,
                                              uint32_t len)
{
    noxtls_nrf54_aes_req_t req;

    req.mode = mode;
    req.decrypt = decrypt;
    /* MISRA C:2025 Rule 11.6 deviation: the key is addressed by its bus address only. */
    req.key = (const uint8_t *)key_addr;
    req.key_len = key_len;
    return noxtls_nrf54_aes_run(&req, 0U, iv, in, out, len);
}
