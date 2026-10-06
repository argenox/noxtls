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
* File:    ut_nrf54_mock.c
* Summary: Functional CRACEN / KMU / NVIC register mock for the backend host tests
*
*****************************************************************************/

/**
 * @file ut_nrf54_mock.c
 * @brief Functional mock of CRACEN, the KMU and the NVIC (see ut_nrf54_mock.h).
 * @ingroup noxtls_nrf54_ut
 */

#include <stdio.h>
#include <string.h>

#include "ut_nrf54_mock.h"
#include "ut_nrf54_ref.h"

/** NVIC mock base. */
#define UT_NVIC_BASE        UINT32_C(0xE000E000)
/** Largest stream of one job. */
#define UT_STREAM_MAX       (0x12000U)
/** Largest descriptor chain. */
#define UT_MAX_DESCS        16U
/** Descriptor length field. */
#define UT_LEN_MSK          UINT32_C(0x00FFFFFF)
/** Mode field of the BA411 configuration word. */
#define UT_AES_MODE(cfg)    (((cfg) >> NOXTLS_NRF54_AES_CFG_MODE_POS) & NOXTLS_NRF54_BA411_MODE_MSK)
/** Mode bit of a mode number. */
#define UT_MODE_BIT(n)      (UINT32_C(1) << (n))
/** Invalid-bytes field of a data tag. */
#define UT_TAG_IGN(tag)     (((tag) >> NOXTLS_NRF54_TAG_IGN_POS) & NOXTLS_NRF54_TAG_IGN_MSK)
/** Round up to the AES block. */
#define UT_ALIGN16(n)       (((n) + 15U) & ~15U)
/** Opcode field of COMMAND. */
#define UT_PK_OP_MSK        0xFFU
/** AEAD data descriptors of one job (payload and final block). */
#define UT_AEAD_DATA_DESCS  4U

ut_mock_t g_ut;
ut_ram_t g_ut_ram;
volatile uint32_t g_ut_signals;
uint32_t g_ut_waits;
uint32_t g_ut_locks;
uint32_t g_ut_unlocks;

/** Job streams (data type 0 and 1). */
static uint8_t s_stream0[UT_STREAM_MAX];
static uint8_t s_stream1[256];
/** Engine output. */
static uint8_t s_out[UT_STREAM_MAX + 64U];
/** AEAD header stream. */
static uint8_t s_hdr[UT_STREAM_MAX];

/** One AEAD data descriptor. */
typedef struct {
    const uint8_t *src; /**< Data. */
    uint32_t len;       /**< Descriptor length. */
    uint32_t ign;       /**< Invalid bytes. */
} ut_aead_desc_t;

/** AEAD descriptors of the job being walked. */
static struct {
    ut_aead_desc_t data[UT_AEAD_DATA_DESCS]; /**< Payload-type descriptors. */
    uint32_t ndata;                          /**< Entries. */
    uint32_t hlen;                           /**< Header bytes (without padding). */
    uint32_t hpadded;                        /**< Header descriptor bytes. */
    uint8_t hdr_ign;                         /**< A header descriptor with invalid bytes was seen. */
} s_aead;

uint8_t *ut_ptr(uint32_t lo)
{
    uintptr_t hi = (uintptr_t)&g_ut & ~(uintptr_t)UINT32_MAX;

    return (uint8_t *)(hi | (uintptr_t)lo);
}

/**
 * @brief Record the first rule violation.
 *
 * @param[in] msg Message.
 */
static void ut_fail(const char *msg)
{
    if (g_ut.err[0] == '\0') {
        (void)snprintf(g_ut.err, sizeof(g_ut.err), "%s", msg);
    }
}

/**
 * @brief Operand memory (CPU view).
 *
 * @return Pointer.
 */
static uint8_t *ut_pk_mem(void)
{
    return (uint8_t *)&g_ut.core[UT_IDX(NOXTLS_NRF54_PK_DATA)];
}

const uint8_t *ut_pk_be(uint32_t slot)
{
    return &g_ut.pk_snap[(slot * NOXTLS_NRF54_PK_SLOT_SMALL) + NOXTLS_NRF54_PK_SLOT_SMALL - 32U];
}

const uint8_t *ut_pk_le(uint32_t slot)
{
    return &g_ut.pk_snap[slot * NOXTLS_NRF54_PK_SLOT_SMALL];
}

uint8_t ut_pk_wiped(void)
{
    const uint8_t *m = ut_pk_mem();
    uint32_t i;
    uint8_t acc = 0U;

    for (i = 0U; i < NOXTLS_NRF54_PK_DATA_SIZE; i++) {
        acc |= m[i];
    }
    return (acc == 0U) ? 1U : 0U;
}

/**
 * @brief Increment the low @p bits of a big-endian counter (wrap without carry above).
 *
 * @param[in,out] ctr  Counter block.
 * @param[in]     bits Counter width.
 */
static void ut_ctr_inc(uint8_t *ctr, uint32_t bits)
{
    uint32_t bit;
    uint32_t carry = 1U;

    for (bit = 0U; (bit < bits) && (carry != 0U); bit += 8U) {
        uint32_t idx = 15U - (bit / 8U);
        uint32_t width = ((bits - bit) >= 8U) ? 8U : (bits - bit);
        uint32_t mask = (width == 8U) ? 0xFFU : ((1U << width) - 1U);
        uint32_t low = ((uint32_t)ctr[idx] & mask) + carry;

        carry = (low > mask) ? 1U : 0U;
        ctr[idx] = (uint8_t)((ctr[idx] & ~mask) | (low & mask));
    }
}

/**
 * @brief Whether the engine supports a key length (BA411 configuration register).
 *
 * @param[in] keylen Key bytes.
 *
 * @return 1 when supported.
 */
static uint8_t ut_key_ok(uint32_t keylen)
{
    uint32_t caps = (g_ut.core[UT_IDX(NOXTLS_NRF54_HW_BA411_CFG1)] >> NOXTLS_NRF54_BA411_KEYSZ_POS) & 7U;
    uint32_t cap = (keylen == 16U) ? 1U : ((keylen == 24U) ? 2U : ((keylen == 32U) ? 4U : 0U));

    return ((cap != 0U) && ((caps & cap) != 0U)) ? 1U : 0U;
}

/**
 * @brief Run the AES engine model (ECB / CBC / CTR).
 *
 * @param[in] cfg    Config word.
 * @param[in] key    Key.
 * @param[in] keylen Key bytes.
 * @param[in] iv     IV or NULL.
 * @param[in] len    Payload bytes.
 *
 * @return Output bytes, 0 on a rule violation.
 */
static uint32_t ut_aes_model(uint32_t cfg, const uint8_t *key, uint32_t keylen, const uint8_t *iv, uint32_t len)
{
    ut_aes_key_t k;
    uint32_t mode = UT_AES_MODE(cfg);
    uint32_t dec = cfg & NOXTLS_NRF54_AES_CFG_DECRYPT;
    uint8_t chain[16];
    uint32_t off;

    if ((cfg & ~((NOXTLS_NRF54_BA411_MODE_MSK << NOXTLS_NRF54_AES_CFG_MODE_POS) | NOXTLS_NRF54_AES_CFG_DECRYPT)) != 0U) {
        ut_fail("aes: unexpected config bits");
        return 0U;
    }
    if ((ut_key_ok(keylen) == 0U) || (ut_aes_setkey(&k, key, keylen) != 0)) {
        ut_fail("aes: key size not supported");
        return 0U;
    }
    if ((len == 0U) || ((len % 16U) != 0U)) {
        ut_fail("aes: payload not block aligned");
        return 0U;
    }
    if ((mode == UT_MODE_BIT(NOXTLS_NRF54_AES_MODE_ECB)) != (iv == NULL)) {
        ut_fail("aes: IV presence does not match the mode");
        return 0U;
    }
    if ((mode & g_ut.core[UT_IDX(NOXTLS_NRF54_HW_BA411_CFG1)]) == 0U) {
        ut_fail("aes: mode not in the engine");
        return 0U;
    }
    if (iv != NULL) {
        (void)memcpy(chain, iv, 16U);
    }
    for (off = 0U; off < len; off += 16U) {
        const uint8_t *in = &s_stream0[off];
        uint8_t *out = &s_out[off];
        uint32_t i;

        if (mode == UT_MODE_BIT(NOXTLS_NRF54_AES_MODE_ECB)) {
            if (dec != 0U) {
                ut_aes_decrypt(&k, in, out);
            } else {
                ut_aes_encrypt(&k, in, out);
            }
        } else if (mode == UT_MODE_BIT(NOXTLS_NRF54_AES_MODE_CBC)) {
            if (dec != 0U) {
                ut_aes_decrypt(&k, in, out);
                for (i = 0U; i < 16U; i++) {
                    out[i] ^= chain[i];
                }
                (void)memcpy(chain, in, 16U);
            } else {
                uint8_t x[16];

                for (i = 0U; i < 16U; i++) {
                    x[i] = in[i] ^ chain[i];
                }
                ut_aes_encrypt(&k, x, out);
                (void)memcpy(chain, out, 16U);
            }
        } else if (mode == UT_MODE_BIT(NOXTLS_NRF54_AES_MODE_CTR)) {
            uint8_t ks[16];

            ut_aes_encrypt(&k, chain, ks);
            for (i = 0U; i < 16U; i++) {
                out[i] = in[i] ^ ks[i];
            }
            ut_ctr_inc(chain, g_ut.ctr_bits);
        } else {
            ut_fail("aes: unsupported mode");
            return 0U;
        }
    }
    return len;
}

/**
 * @brief Run the BA413 model: resume from the state, compress the blocks, push the state.
 *
 * @param[in] cfg       Config word.
 * @param[in] state_in  Resumed state or NULL.
 * @param[in] state_len State bytes.
 * @param[in] len       Message bytes.
 *
 * @return Output bytes, 0 on a rule violation.
 */
static uint32_t ut_hash_model(uint32_t cfg, const uint8_t *state_in, uint32_t state_len, uint32_t len)
{
    uint32_t bits;
    uint32_t bsz;
    uint32_t ssz;
    uint8_t state[64];
    uint32_t off;

    if ((cfg & g_ut.core[UT_IDX(NOXTLS_NRF54_HW_BA413_CFG)] & NOXTLS_NRF54_BA413_ALGO_MSK) != cfg) {
        ut_fail("hash: algorithm not in the engine");
        return 0U;
    }
    if (cfg == NOXTLS_NRF54_HASH_ALGO_SHA256) {
        bits = 256U;
    } else if (cfg == NOXTLS_NRF54_HASH_ALGO_SHA512) {
        bits = 512U;
    } else {
        ut_fail("hash: bad config word");
        return 0U;
    }
    bsz = (bits > 256U) ? 128U : 64U;
    ssz = ut_sha_iv(bits, state);
    if ((state_in == NULL) || (state_len != ssz)) {
        ut_fail("hash: state missing or of the wrong size");
        return 0U;
    }
    (void)memcpy(state, state_in, ssz);
    if ((len == 0U) || ((len % bsz) != 0U)) {
        ut_fail("hash: stream is not whole blocks");
        return 0U;
    }
    for (off = 0U; off < len; off += bsz) {
        if (bsz == 64U) {
            ut_sha256_block(state, &s_stream0[off]);
        } else {
            ut_sha512_block(state, &s_stream0[off]);
        }
    }
    (void)memcpy(s_out, state, ssz);
    return ssz;
}

/**
 * @brief Route one AEAD data descriptor.
 *
 * @param[in] src Data.
 * @param[in] len Descriptor length.
 * @param[in] tag DMA tag.
 *
 * @return 1 on success, 0 on a rule violation.
 */
static uint8_t ut_aead_collect(const uint8_t *src, uint32_t len, uint32_t tag)
{
    uint32_t dtype = (tag >> NOXTLS_NRF54_TAG_DTYPE_POS) & NOXTLS_NRF54_TAG_DTYPE_MSK;
    uint32_t ign = UT_TAG_IGN(tag);
    uint32_t allowed = NOXTLS_NRF54_TAG_ENGINE_MSK | NOXTLS_NRF54_TAG_LAST |
                       (NOXTLS_NRF54_TAG_DTYPE_MSK << NOXTLS_NRF54_TAG_DTYPE_POS) |
                       (NOXTLS_NRF54_TAG_IGN_MSK << NOXTLS_NRF54_TAG_IGN_POS);

    if (((tag & ~allowed) != 0U) || (ign > len) || (len == 0U) || ((len % 16U) != 0U)) {
        ut_fail("aead: bad data descriptor");
        return 0U;
    }
    if (dtype == NOXTLS_NRF54_DTYPE_HEADER) {
        if ((s_aead.ndata != 0U) || (s_aead.hdr_ign != 0U) || ((s_aead.hlen + len) > sizeof(s_hdr))) {
            ut_fail("aead: AAD order / padding");
            return 0U;
        }
        (void)memcpy(&s_hdr[s_aead.hlen], src, len - ign);
        s_aead.hlen += len - ign;
        s_aead.hpadded += len;
        s_aead.hdr_ign = (ign != 0U) ? 1U : 0U;
    } else if ((dtype == NOXTLS_NRF54_DTYPE_PAYLOAD) && (s_aead.ndata < UT_AEAD_DATA_DESCS)) {
        s_aead.data[s_aead.ndata].src = src;
        s_aead.data[s_aead.ndata].len = len;
        s_aead.data[s_aead.ndata].ign = ign;
        s_aead.ndata++;
    } else {
        ut_fail("aead: unexpected data type");
        return 0U;
    }
    return 1U;
}

/**
 * @brief Run the BA411 GCM / CCM model on the collected streams.
 *
 * @param[in] cfg    Config word.
 * @param[in] key    Key.
 * @param[in] keylen Key bytes.
 * @param[in] iv     GCM IV or NULL.
 * @param[in] ivlen  IV bytes.
 *
 * @return Output bytes, 0 on a rule violation.
 */
static uint32_t ut_aead_model(uint32_t cfg, const uint8_t *key, uint32_t keylen, const uint8_t *iv, uint32_t ivlen)
{
    uint8_t dec = ((cfg & NOXTLS_NRF54_AES_CFG_DECRYPT) != 0U) ? 1U : 0U;
    uint8_t gcm = (UT_AES_MODE(cfg) == UT_MODE_BIT(NOXTLS_NRF54_AES_MODE_GCM)) ? 1U : 0U;
    uint32_t npay = s_aead.ndata;
    const ut_aead_desc_t *fin = NULL;
    uint32_t plen = 0U;
    uint32_t aoff = UT_ALIGN16(s_aead.hlen);
    uint8_t tag[16];
    uint32_t i;

    if (ut_key_ok(keylen) == 0U) {
        ut_fail("aead: key size not supported");
        return 0U;
    }
    if ((gcm != 0U) != (iv != NULL)) {
        ut_fail("aead: IV presence does not match the mode");
        return 0U;
    }
    if ((gcm != 0U) && (ivlen != 12U)) {
        ut_fail("aead: GCM IV length");
        return 0U;
    }
    if (s_aead.hpadded != aoff) {
        ut_fail("aead: AAD descriptors not padded to the block");
        return 0U;
    }
    if ((gcm != 0U) || (dec != 0U)) {
        if (npay == 0U) {
            ut_fail("aead: final block missing");
            return 0U;
        }
        npay--;
        fin = &s_aead.data[npay];
    }
    for (i = 0U; i < npay; i++) {
        const ut_aead_desc_t *d = &s_aead.data[i];

        if (((d->ign != 0U) && ((i + 1U) != npay)) || ((plen + d->len) > (UT_STREAM_MAX / 2U))) {
            ut_fail("aead: payload descriptor");
            return 0U;
        }
        (void)memcpy(&s_stream0[plen], d->src, d->len - d->ign);
        plen += d->len - d->ign;
    }
    (void)memset(s_out, 0, aoff + UT_ALIGN16(plen) + 16U);
    if (gcm != 0U) {
        uint8_t lens[16];

        for (i = 0U; i < 8U; i++) {
            lens[7U - i] = (uint8_t)(((uint64_t)s_aead.hlen * 8U) >> (8U * i));
            lens[15U - i] = (uint8_t)(((uint64_t)plen * 8U) >> (8U * i));
        }
        if (((fin->len - fin->ign) != 16U) || (memcmp(fin->src, lens, 16U) != 0)) {
            ut_fail("gcm: len(A) || len(C) block");
            return 0U;
        }
        ut_gcm(key, keylen, iv, s_hdr, s_aead.hlen, s_stream0, plen, &s_out[aoff], dec, tag);
    } else {
        if (s_aead.hlen < 16U) {
            ut_fail("ccm: B0 missing");
            return 0U;
        }
        ut_ccm(key, keylen, s_hdr, s_aead.hlen, s_stream0, plen, &s_out[aoff], dec, tag);
        if (fin != NULL) {
            if ((fin->len - fin->ign) > 16U) {
                ut_fail("ccm: received tag too long");
                return 0U;
            }
            for (i = 0U; i < (fin->len - fin->ign); i++) {
                tag[i] ^= fin->src[i];
            }
        }
    }
    (void)memcpy(&s_out[aoff + UT_ALIGN16(plen)], tag, 16U);
    g_ut.last_aad_len = s_aead.hlen;
    g_ut.last_data_len = plen;
    return aoff + UT_ALIGN16(plen) + 16U;
}

/**
 * @brief Check and route one configuration descriptor.
 *
 * @param[in]     engine Engine of the job.
 * @param[in]     d      Descriptor.
 * @param[in,out] cfg    Config word.
 * @param[out]    key    Key buffer.
 * @param[out]    keylen Key bytes.
 * @param[out]    iv     IV buffer.
 * @param[out]    ivlen  IV bytes (0: none).
 *
 * @return 1 on success.
 */
static uint8_t ut_cm_config(uint32_t engine, const noxtls_nrf54_desc_t *d, uint32_t *cfg, uint8_t *key,
                            uint32_t *keylen, uint8_t *iv, uint32_t *ivlen)
{
    uint32_t reg = (d->tag >> NOXTLS_NRF54_TAG_REG_POS) & NOXTLS_NRF54_TAG_REG_MSK;
    uint32_t len = d->length & UT_LEN_MSK;
    const uint8_t *src = ut_ptr(d->addr);
    uint8_t ok = 1U;

    if ((d->length & NOXTLS_NRF54_DESC_REALIGN) == 0U) {
        ut_fail("config descriptor without REALIGN");
        ok = 0U;
    } else if (reg == 0U) {
        (void)memcpy(cfg, src, 4U);
    } else if ((engine == NOXTLS_NRF54_TAG_ENGINE_AES) && (reg == NOXTLS_NRF54_AES_REG_KEY) && (len <= 32U)) {
        (void)memcpy(key, src, len);
        *keylen = len;
        g_ut.last_key_addr = d->addr;
    } else if ((engine == NOXTLS_NRF54_TAG_ENGINE_AES) && (reg == NOXTLS_NRF54_AES_REG_IV) &&
               ((len == 16U) || ((len == 12U) && (UT_AES_MODE(*cfg) == UT_MODE_BIT(NOXTLS_NRF54_AES_MODE_GCM))))) {
        (void)memcpy(iv, src, len);
        *ivlen = len;
    } else {
        ut_fail("unexpected config register");
        ok = 0U;
    }
    return ok;
}

/**
 * @brief Execute the job described by FETCHADDR / PUSHADDR.
 *
 * @return 1 on success, 0 on a rule violation.
 */
static uint8_t ut_cm_execute(void)
{
    uint32_t addr = g_ut.core[UT_IDX(NOXTLS_NRF54_CM_FETCHADDR)];
    uint32_t n = 0U;
    uint32_t engine = 0U;
    uint32_t cfg = 0U;
    uint8_t key[32];
    uint32_t keylen = 0U;
    uint8_t iv[16];
    uint32_t ivlen = 0U;
    uint32_t len0 = 0U;
    uint32_t len1 = 0U;
    uint32_t out_len;
    uint32_t pos = 0U;

    (void)memset(&s_aead, 0, sizeof(s_aead));
    while (addr != NOXTLS_NRF54_DESC_STOP) {
        const noxtls_nrf54_desc_t *d = (const noxtls_nrf54_desc_t *)(void *)ut_ptr(addr);
        uint32_t len = d->length & UT_LEN_MSK;
        uint32_t tag = d->tag;
        uint32_t eng = tag & NOXTLS_NRF54_TAG_ENGINE_MSK;
        const uint8_t *src = ut_ptr(d->addr);
        uint8_t last = (d->next == NOXTLS_NRF54_DESC_STOP) ? 1U : 0U;
        uint32_t dtype = (tag >> NOXTLS_NRF54_TAG_DTYPE_POS) & NOXTLS_NRF54_TAG_DTYPE_MSK;

        if (n >= UT_MAX_DESCS) {
            ut_fail("chain too long");
            return 0U;
        }
        if ((n == 0U) && (((tag & NOXTLS_NRF54_TAG_CONFIG) == 0U) ||
                          (((tag >> NOXTLS_NRF54_TAG_REG_POS) & NOXTLS_NRF54_TAG_REG_MSK) != 0U) || (len != 4U))) {
            ut_fail("first descriptor is not the config word");
            return 0U;
        }
        if (n == 0U) {
            engine = eng;
        }
        if (eng != engine) {
            ut_fail("engine changes inside a job");
            return 0U;
        }
        if ((((tag & NOXTLS_NRF54_TAG_LAST) != 0U) != (last != 0U)) &&
            !((engine == NOXTLS_NRF54_TAG_ENGINE_HASH) && (dtype == NOXTLS_NRF54_DTYPE_HEADER))) {
            ut_fail("LAST tag misplaced");
            return 0U;
        }
        if ((last != 0U) && ((d->length & NOXTLS_NRF54_DESC_REALIGN) == 0U)) {
            ut_fail("last fetch descriptor without REALIGN");
            return 0U;
        }
        if ((tag & NOXTLS_NRF54_TAG_CONFIG) != 0U) {
            if (ut_cm_config(engine, d, &cfg, key, &keylen, iv, &ivlen) == 0U) {
                return 0U;
            }
        } else if ((engine == NOXTLS_NRF54_TAG_ENGINE_AES) &&
                   ((UT_AES_MODE(cfg) == UT_MODE_BIT(NOXTLS_NRF54_AES_MODE_GCM)) ||
                    (UT_AES_MODE(cfg) == UT_MODE_BIT(NOXTLS_NRF54_AES_MODE_CCM)))) {
            if (ut_aead_collect(src, len, tag) == 0U) {
                return 0U;
            }
        } else {
            if ((tag & ~(NOXTLS_NRF54_TAG_ENGINE_MSK | NOXTLS_NRF54_TAG_LAST |
                         (NOXTLS_NRF54_TAG_DTYPE_MSK << NOXTLS_NRF54_TAG_DTYPE_POS))) != 0U) {
                ut_fail("unexpected data tag bits");
                return 0U;
            }
            if (dtype == NOXTLS_NRF54_DTYPE_PAYLOAD) {
                if ((len0 + len) > UT_STREAM_MAX) {
                    ut_fail("stream too long");
                    return 0U;
                }
                (void)memcpy(&s_stream0[len0], src, len);
                len0 += len;
            } else if ((engine == NOXTLS_NRF54_TAG_ENGINE_HASH) && (len <= sizeof(s_stream1))) {
                (void)memcpy(s_stream1, src, len);
                len1 = len;
            } else {
                ut_fail("unexpected data type");
                return 0U;
            }
        }
        addr = d->next;
        n++;
    }
    g_ut.last_cfg = cfg;
    g_ut.last_fetch_descs = n;
    g_ut.last_data_len = len0;
    if (engine == NOXTLS_NRF54_TAG_ENGINE_AES) {
        uint32_t mode = UT_AES_MODE(cfg);

        g_ut.last_keylen = keylen;
        if ((mode == UT_MODE_BIT(NOXTLS_NRF54_AES_MODE_GCM)) || (mode == UT_MODE_BIT(NOXTLS_NRF54_AES_MODE_CCM))) {
            out_len = ut_aead_model(cfg, key, keylen, (ivlen != 0U) ? iv : NULL, ivlen);
        } else {
            out_len = ut_aes_model(cfg, key, keylen, (ivlen != 0U) ? iv : NULL, len0);
        }
    } else if (engine == NOXTLS_NRF54_TAG_ENGINE_HASH) {
        g_ut.last_had_state = (len1 != 0U) ? 1U : 0U;
        out_len = ut_hash_model(cfg, (len1 != 0U) ? s_stream1 : NULL, len1, len0);
    } else {
        ut_fail("unknown engine");
        out_len = 0U;
    }
    if (out_len == 0U) {
        return 0U;
    }
    addr = g_ut.core[UT_IDX(NOXTLS_NRF54_CM_PUSHADDR)];
    n = 0U;
    while (addr != NOXTLS_NRF54_DESC_STOP) {
        const noxtls_nrf54_desc_t *d = (const noxtls_nrf54_desc_t *)(void *)ut_ptr(addr);
        uint32_t len = d->length & UT_LEN_MSK;

        if ((n >= UT_MAX_DESCS) || ((pos + len) > out_len)) {
            ut_fail("push space exceeds the output");
            return 0U;
        }
        if ((d->length & NOXTLS_NRF54_DESC_DISCARD) == 0U) {
            (void)memcpy(ut_ptr(d->addr), &s_out[pos], len);
        }
        if ((d->next == NOXTLS_NRF54_DESC_STOP) && ((d->length & NOXTLS_NRF54_DESC_REALIGN) == 0U)) {
            ut_fail("last push descriptor without REALIGN");
            return 0U;
        }
        pos += len;
        addr = d->next;
        n++;
    }
    if (pos != out_len) {
        ut_fail("push space shorter than the output");
        return 0U;
    }
    return 1U;
}

/**
 * @brief Make the job in flight complete.
 *
 * @param[in] ok Non-zero for success.
 */
static void ut_cm_complete(uint8_t ok)
{
    g_ut.core[UT_IDX(NOXTLS_NRF54_CM_INTSTATRAW)] |= NOXTLS_NRF54_CM_INT_PUSH_STOP |
                                                     ((ok != 0U) ? 0U : NOXTLS_NRF54_CM_INT_FETCH_ERR);
    if (g_ut.core[UT_IDX(NOXTLS_NRF54_CM_INTEN)] != 0U) {
        g_ut.wrap[UT_IDX(NOXTLS_NRF54_EVENTS_CRYPTOMASTER)] = 1U;
    }
    g_ut.busy_left = g_ut.busy_after_stop;
}

/**
 * @brief START written.
 */
static void ut_cm_start(void)
{
    uint8_t ok;

    g_ut.starts++;
    if ((g_ut.wrap[UT_IDX(NOXTLS_NRF54_ENABLE)] & NOXTLS_NRF54_MOD_CM) == 0U) {
        ut_fail("START with the CryptoMaster powered down");
    }
    if (g_ut.core[UT_IDX(NOXTLS_NRF54_CM_CONFIG)] != NOXTLS_NRF54_CM_CFG_SG) {
        ut_fail("START without scatter/gather CONFIG");
    }
    ok = ut_cm_execute();
    if ((g_ut.inject_error != 0U) && (g_ut.fail_skip != 0U)) {
        g_ut.fail_skip--;
    } else if (g_ut.inject_error != 0U) {
        g_ut.inject_error--;
        ok = 0U;
    } else {
        /* No injected failure. */
    }
    if (g_ut.hang == 0U) {
        if (g_ut.delay_reads == 0U) {
            ut_cm_complete(ok);
        } else {
            g_ut.pending = g_ut.delay_reads;
            g_ut.core[UT_IDX(NOXTLS_NRF54_CM_INTSTATRAW)] = (ok != 0U) ? 0U : NOXTLS_NRF54_CM_INT_FETCH_ERR;
        }
    }
}

/**
 * @brief Let time pass for a delayed job (register read or interrupt poll).
 *
 * @return Non-zero while the job is still running.
 */
static uint8_t ut_cm_tick(void)
{
    uint8_t running = 0U;

    if (g_ut.pending != 0U) {
        g_ut.pending--;
        running = 1U;
        if (g_ut.pending == 0U) {
            ut_cm_complete((g_ut.core[UT_IDX(NOXTLS_NRF54_CM_INTSTATRAW)] & NOXTLS_NRF54_CM_INT_FETCH_ERR) == 0U);
        }
    }
    return running;
}

/**
 * @brief CryptoMaster STATUS read.
 *
 * @return STATUS.
 */
static uint32_t ut_cm_status(void)
{
    uint32_t v = 0U;

    if (g_ut.softrst_left != 0U) {
        g_ut.softrst_left--;
        v |= NOXTLS_NRF54_CM_ST_SOFTRST_BUSY;
    }
    if (g_ut.hang != 0U) {
        v |= NOXTLS_NRF54_CM_ST_FETCH_BUSY | NOXTLS_NRF54_CM_ST_PUSH_BUSY;
    } else if (ut_cm_tick() != 0U) {
        v |= NOXTLS_NRF54_CM_ST_FETCH_BUSY;
    } else if (g_ut.stuck != 0U) {
        v |= NOXTLS_NRF54_CM_ST_PUSH_WAIT;
    } else if (g_ut.busy_left != 0U) {
        g_ut.busy_left--;
        v |= NOXTLS_NRF54_CM_ST_PUSH_BUSY;
    } else {
        /* Idle. */
    }
    return v;
}

/**
 * @brief Fill the TRNG FIFO and raise EVENTS_RNG.
 */
static void ut_rng_fill(void)
{
    uint32_t i;

    for (i = 0U; i < 16U; i++) {
        g_ut.rng_fifo[i] = UINT32_C(0xA5000000) | g_ut.rng_counter;
        g_ut.rng_counter++;
    }
    g_ut.rng_head = 0U;
    g_ut.rng_level = 16U;
    g_ut.rng_state = 2U;
    g_ut.wrap[UT_IDX(NOXTLS_NRF54_EVENTS_RNG)] = 1U;
}

/**
 * @brief Advance the TRNG model by one step.
 */
static void ut_rng_tick(void)
{
    uint32_t control = g_ut.core[UT_IDX(NOXTLS_NRF54_RNG_CONTROL)];

    if (((control & NOXTLS_NRF54_RNG_CTRL_ENABLE) == 0U) ||
        ((g_ut.wrap[UT_IDX(NOXTLS_NRF54_ENABLE)] & NOXTLS_NRF54_MOD_RNG) == 0U)) {
        return;
    }
    if (g_ut.rng_state == NOXTLS_NRF54_RNG_STATE_STARTUP) {
        if (g_ut.rng_never_ready != 0U) {
            /* Stuck in start-up. */
        } else if (g_ut.rng_startup_left != 0U) {
            g_ut.rng_startup_left--;
        } else if (g_ut.rng_fail_starts != 0U) {
            g_ut.rng_fail_starts--;
            g_ut.rng_state = NOXTLS_NRF54_RNG_STATE_ERROR;
            g_ut.rng_status_bits = g_ut.rng_fail_bits;
            g_ut.wrap[UT_IDX(NOXTLS_NRF54_EVENTS_RNG)] = 1U;
        } else {
            ut_rng_fill();
        }
    } else if ((g_ut.rng_state == 2U) && (g_ut.rng_level == 0U)) {
        ut_rng_fill();
    } else {
        /* Data available, or error. */
    }
}

/**
 * @brief TRNG CONTROL written.
 *
 * @param[in] v Value.
 */
static void ut_rng_control(uint32_t v)
{
    g_ut.core[UT_IDX(NOXTLS_NRF54_RNG_CONTROL)] = v;
    if ((v & NOXTLS_NRF54_RNG_CTRL_SOFTRST) != 0U) {
        g_ut.rng_softresets++;
        g_ut.rng_state = NOXTLS_NRF54_RNG_STATE_RESET;
        g_ut.rng_level = 0U;
        g_ut.rng_status_bits = 0U;
    } else if ((v & NOXTLS_NRF54_RNG_CTRL_ENABLE) != 0U) {
        if (g_ut.rng_state == NOXTLS_NRF54_RNG_STATE_RESET) {
            g_ut.rng_state = NOXTLS_NRF54_RNG_STATE_STARTUP;
            g_ut.rng_startup_left = g_ut.rng_startup_reads;
        }
    } else {
        g_ut.rng_state = NOXTLS_NRF54_RNG_STATE_RESET;
        g_ut.rng_level = 0U;
    }
}

/**
 * @brief KMU task triggered.
 *
 * @param[in] off Task offset.
 */
static void ut_kmu_task(uint32_t off)
{
    uint32_t slot = g_ut.kmu[UT_IDX(NOXTLS_NRF54_KMU_KEYSLOT)];
    ut_kmu_slot_t *s = &g_ut.kslot[slot % UT_KMU_SLOTS];
    uint32_t ev = NOXTLS_NRF54_KMU_EVENTS_ERROR;

    g_ut.kmu_tasks++;
    if (g_ut.kmu_no_event != 0U) {
        return;
    }
    if ((s->blocked != 0U) && (off != NOXTLS_NRF54_KMU_TASKS_READMETA)) {
        ev = NOXTLS_NRF54_KMU_EVENTS_ERROR;
    } else if (off == NOXTLS_NRF54_KMU_TASKS_PROVISION) {
        if (s->state == 2U) {
            ev = NOXTLS_NRF54_KMU_EVENTS_REVOKED;
        } else if (s->state == 0U) {
            const noxtls_nrf54_kmu_slot_data_t *src =
                (const noxtls_nrf54_kmu_slot_data_t *)(void *)ut_ptr(g_ut.kmu[UT_IDX(NOXTLS_NRF54_KMU_SRC)]);

            (void)memcpy(s->value, src->value, sizeof(s->value));
            s->rpolicy = src->revoke_policy;
            s->dest = src->dest;
            s->md = src->metadata;
            s->state = 1U;
            ev = NOXTLS_NRF54_KMU_EVENTS_PROVISIONED;
        } else {
            /* Not empty. */
        }
    } else if (off == NOXTLS_NRF54_KMU_TASKS_PUSH) {
        if (s->state == 2U) {
            ev = NOXTLS_NRF54_KMU_EVENTS_REVOKED;
        } else if ((s->state == 1U) && (s->pushblocked == 0U)) {
            (void)memcpy(ut_ptr(s->dest), s->value, sizeof(s->value));
            ev = NOXTLS_NRF54_KMU_EVENTS_PUSHED;
        } else {
            /* Empty or blocked. */
        }
    } else if (off == NOXTLS_NRF54_KMU_TASKS_REVOKE) {
        if (s->state != 0U) {
            s->state = 2U;
            ev = NOXTLS_NRF54_KMU_EVENTS_REVOKED;
        }
    } else if (off == NOXTLS_NRF54_KMU_TASKS_READMETA) {
        if (s->state == 2U) {
            ev = NOXTLS_NRF54_KMU_EVENTS_REVOKED;
        } else if (s->state == 1U) {
            g_ut.kmu[UT_IDX(NOXTLS_NRF54_KMU_METADATA)] = s->md;
            ev = NOXTLS_NRF54_KMU_EVENTS_METAREAD;
        } else {
            /* Empty. */
        }
    } else if (off == NOXTLS_NRF54_KMU_TASKS_PUSHBLOCK) {
        s->pushblocked = 1U;
        ev = NOXTLS_NRF54_KMU_EVENTS_PUSHBLOCKED;
    } else {
        s->blocked = 1U;
        ev = NOXTLS_NRF54_KMU_EVENTS_BLOCKED;
    }
    g_ut.kmu[UT_IDX(ev)] = 1U;
}

/** Error flags of the BA414EP command in flight. */
static uint32_t s_pk_result;
/** Non-zero: the command in flight never completes. */
static uint8_t s_pk_stuck;

/**
 * @brief Complete the BA414EP command in flight.
 */
static void ut_pk_complete(void)
{
    g_ut.pk_status = s_pk_result | NOXTLS_NRF54_PK_ST_IRQ;
    g_ut.wrap[UT_IDX(NOXTLS_NRF54_EVENTS_PKEIKG)] = 1U;
}

/**
 * @brief Produce the point-multiply result R = P XOR k (right-aligned 32-byte operands).
 */
static void ut_pk_ptmul(void)
{
    uint8_t *m = ut_pk_mem();
    uint32_t tail = NOXTLS_NRF54_PK_SLOT_SMALL - 32U;
    uint32_t i;

    for (i = 0U; i < 32U; i++) {
        uint8_t k = m[(NOXTLS_NRF54_PK_SLOT_PTMUL_K * NOXTLS_NRF54_PK_SLOT_SMALL) + tail + i];

        m[(NOXTLS_NRF54_PK_SLOT_PTMUL_RX * NOXTLS_NRF54_PK_SLOT_SMALL) + tail + i] =
            (uint8_t)(m[(NOXTLS_NRF54_PK_SLOT_PTMUL_PX * NOXTLS_NRF54_PK_SLOT_SMALL) + tail + i] ^ k);
        m[(NOXTLS_NRF54_PK_SLOT_PTMUL_RY * NOXTLS_NRF54_PK_SLOT_SMALL) + tail + i] =
            (uint8_t)(m[(NOXTLS_NRF54_PK_SLOT_PTMUL_PY * NOXTLS_NRF54_PK_SLOT_SMALL) + tail + i] ^ k);
    }
    if (((g_ut.pk_ptmul_corrupt >> (g_ut.pk_ptmul_runs & 31U)) & 1U) != 0U) {
        m[(NOXTLS_NRF54_PK_SLOT_PTMUL_RX * NOXTLS_NRF54_PK_SLOT_SMALL) + tail] ^= 0x01U;
    }
    g_ut.pk_ptmul_runs++;
}

/**
 * @brief CONTROL.START written.
 */
static void ut_pk_start(void)
{
    uint32_t cmd = g_ut.core[UT_IDX(NOXTLS_NRF54_PK_COMMAND)];
    uint32_t i;

    g_ut.pk_starts++;
    if ((g_ut.wrap[UT_IDX(NOXTLS_NRF54_ENABLE)] & NOXTLS_NRF54_MOD_PKE) == 0U) {
        ut_fail("pke: START with the module powered down");
    }
    s_pk_result = 0U;
    if ((cmd & UT_PK_OP_MSK) == NOXTLS_NRF54_PK_OP_CLEAR_MEM) {
        g_ut.pk_clears++;
        if (g_ut.l15 != 0U) {
            ut_fail("pke: clear-memory command on the nRF54L15");
            s_pk_result = NOXTLS_NRF54_PK_ST_NOT_IMPL;
        } else {
            (void)memset(ut_pk_mem(), 0, NOXTLS_NRF54_PK_DATA_SIZE);
        }
    } else {
        g_ut.pk_cmd = cmd;
        g_ut.pk_ptrs = g_ut.core[UT_IDX(NOXTLS_NRF54_PK_POINTERS)];
        (void)memcpy(g_ut.pk_snap, ut_pk_mem(), NOXTLS_NRF54_PK_DATA_SIZE);
        s_pk_result = g_ut.pk_status_bits;
        if (g_ut.l15 != 0U) {
            for (i = 0U; i < NOXTLS_NRF54_BA414EP_UCODE_WORDS; i++) {
                if (g_ut.core[UT_IDX(NOXTLS_NRF54_PK_CODE) + i] != noxtls_nrf54_ba414ep_ucode[i]) {
                    s_pk_result = NOXTLS_NRF54_PK_ST_BAD_UCODE;
                    break;
                }
            }
        }
        if (((cmd & UT_PK_OP_MSK) == NOXTLS_NRF54_PK_OP_ECC_PTMUL) && (s_pk_result == 0U)) {
            ut_pk_ptmul();
        }
    }
    g_ut.pk_status = NOXTLS_NRF54_PK_ST_BUSY;
    g_ut.pk_pending = g_ut.pk_delay;
    s_pk_stuck = ((g_ut.pk_hang != 0U) ||
                  ((g_ut.pk_clear_hang != 0U) && ((cmd & UT_PK_OP_MSK) == NOXTLS_NRF54_PK_OP_CLEAR_MEM))) ? 1U : 0U;
    if ((s_pk_stuck == 0U) && (g_ut.pk_pending == 0U)) {
        ut_pk_complete();
    }
}

/**
 * @brief PK STATUS read.
 *
 * @return STATUS.
 */
static uint32_t ut_pk_status_read(void)
{
    uint32_t v = g_ut.pk_status;

    if ((s_pk_stuck == 0U) && (g_ut.pk_pending != 0U)) {
        g_ut.pk_pending--;
        if (g_ut.pk_pending == 0U) {
            ut_pk_complete();
        }
    }
    return v;
}

/**
 * @brief CRACENCORE read.
 *
 * @param[in] off Offset.
 *
 * @return Value.
 */
static uint32_t ut_core_read(uint32_t off)
{
    uint32_t v;

    if (off == NOXTLS_NRF54_CM_STATUS) {
        v = ut_cm_status();
    } else if (off == NOXTLS_NRF54_CM_INTSTATRAW) {
        (void)ut_cm_tick();
        v = g_ut.core[UT_IDX(off)];
    } else if (off == NOXTLS_NRF54_PK_STATUS) {
        v = ut_pk_status_read();
    } else if (off == NOXTLS_NRF54_IKG_PKESTATUS) {
        if (g_ut.ikg_never_ready != 0U) {
            v = NOXTLS_NRF54_IKG_ST_BUSY;
        } else if (g_ut.ikg_busy_reads != 0U) {
            g_ut.ikg_busy_reads--;
            v = NOXTLS_NRF54_IKG_ST_ERASE;
        } else {
            v = 0U;
        }
    } else if (off == NOXTLS_NRF54_RNG_STATUS) {
        ut_rng_tick();
        v = (g_ut.rng_state << NOXTLS_NRF54_RNG_ST_STATE_POS) | g_ut.rng_status_bits;
    } else if (off == NOXTLS_NRF54_RNG_FIFOLEVEL) {
        v = g_ut.rng_level;
    } else if (off == NOXTLS_NRF54_RNG_FIFO) {
        v = 0U;
        if (g_ut.rng_level == 0U) {
            ut_fail("rng: FIFO read while empty");
        } else {
            v = g_ut.rng_fifo[g_ut.rng_head];
            g_ut.rng_head++;
            g_ut.rng_level--;
        }
    } else {
        v = g_ut.core[UT_IDX(off)];
    }
    return v;
}

/**
 * @brief Mock register read.
 *
 * @param[in] addr Address.
 *
 * @return Value.
 */
static uint32_t ut_read32(uintptr_t addr)
{
    uintptr_t wrap = (uintptr_t)g_ut.wrap;
    uintptr_t core = (uintptr_t)g_ut.core;
    uintptr_t kmu = (uintptr_t)g_ut.kmu;
    uint32_t v = 0U;

    if ((addr >= wrap) && (addr < (wrap + sizeof(g_ut.wrap)))) {
        uint32_t off = (uint32_t)(addr - wrap);

        v = (off == NOXTLS_NRF54_INTENSET) ? g_ut.inten : g_ut.wrap[UT_IDX(off)];
    } else if ((addr >= core) && (addr < (core + sizeof(g_ut.core)))) {
        v = ut_core_read((uint32_t)(addr - core));
    } else if ((addr >= kmu) && (addr < (kmu + sizeof(g_ut.kmu)))) {
        uint32_t off = (uint32_t)(addr - kmu);

        if (off == NOXTLS_NRF54_KMU_STATUS) {
            if (g_ut.kmu_never_ready != 0U) {
                v = NOXTLS_NRF54_KMU_ST_BUSY;
            } else if (g_ut.kmu_busy_reads != 0U) {
                g_ut.kmu_busy_reads--;
                v = NOXTLS_NRF54_KMU_ST_BUSY;
            } else {
                v = 0U;
            }
        } else {
            v = g_ut.kmu[UT_IDX(off)];
        }
    } else if ((addr >= UT_NVIC_BASE) && (addr < (UT_NVIC_BASE + sizeof(g_ut.nvic)))) {
        v = g_ut.nvic[UT_IDX(addr - UT_NVIC_BASE)];
    } else {
        ut_fail("read outside the mocked blocks");
    }
    return v;
}

/**
 * @brief Wrapper register written.
 *
 * @param[in] off   Offset.
 * @param[in] value Value.
 */
static void ut_wrap_write(uint32_t off, uint32_t value)
{
    if (off == NOXTLS_NRF54_INTENSET) {
        g_ut.inten |= value;
    } else if (off == NOXTLS_NRF54_INTENCLR) {
        g_ut.inten &= ~value;
    } else {
        if (off == NOXTLS_NRF54_ENABLE) {
            uint32_t was = g_ut.wrap[UT_IDX(NOXTLS_NRF54_ENABLE)];

            g_ut.max_enable |= value;
            if ((value & NOXTLS_NRF54_MOD_PKE) == 0U) {
                g_ut.pk_status = 0U;
                g_ut.pk_pending = 0U;
                s_pk_stuck = 0U;
            } else if (((was & NOXTLS_NRF54_MOD_PKE) == 0U) && (g_ut.pk_irq_at_power != 0U)) {
                /* Power-up latches a stale completion (CRACEN Lite). */
                g_ut.pk_status = NOXTLS_NRF54_PK_ST_IRQ;
                g_ut.wrap[UT_IDX(NOXTLS_NRF54_EVENTS_PKEIKG)] = 1U;
            } else {
                /* Already powered. */
            }
        }
        g_ut.wrap[UT_IDX(off)] = value;
    }
}

/**
 * @brief CRACENCORE register written.
 *
 * @param[in] off   Offset.
 * @param[in] value Value.
 */
static void ut_core_write(uint32_t off, uint32_t value)
{
    if (off == NOXTLS_NRF54_CM_INTSTATCLR) {
        g_ut.core[UT_IDX(NOXTLS_NRF54_CM_INTSTATRAW)] &= ~value;
    } else if (off == NOXTLS_NRF54_CM_START) {
        if (value != NOXTLS_NRF54_CM_START_BOTH) {
            ut_fail("START value");
        }
        ut_cm_start();
    } else if (off == NOXTLS_NRF54_CM_CONFIG) {
        if ((value & NOXTLS_NRF54_CM_CFG_SOFTRST) != 0U) {
            g_ut.softresets++;
            g_ut.hang = 0U;
            g_ut.stuck = 0U;
            g_ut.pending = 0U;
            g_ut.busy_left = 0U;
            g_ut.softrst_left = g_ut.softrst_busy_reads;
        }
        g_ut.core[UT_IDX(off)] = value;
    } else if (off == NOXTLS_NRF54_PK_CONTROL) {
        if ((value & NOXTLS_NRF54_PK_CTRL_CLEARIRQ) != 0U) {
            g_ut.pk_status &= ~NOXTLS_NRF54_PK_ST_IRQ;
        }
        if ((value & NOXTLS_NRF54_PK_CTRL_START) != 0U) {
            ut_pk_start();
        }
    } else if ((off >= NOXTLS_NRF54_PK_CODE) && (g_ut.l15 == 0U)) {
        ut_fail("pke: write to the read-only microcode memory");
    } else if (off == NOXTLS_NRF54_RNG_CONTROL) {
        ut_rng_control(value);
    } else if ((off >= NOXTLS_NRF54_RNG_KEY0) && (off < (NOXTLS_NRF54_RNG_KEY0 + 16U))) {
        g_ut.rng_key_writes++;
        g_ut.core[UT_IDX(off)] = value;
    } else {
        g_ut.core[UT_IDX(off)] = value;
    }
}

/**
 * @brief Mock register write.
 *
 * @param[in] addr  Address.
 * @param[in] value Value.
 */
static void ut_write32(uintptr_t addr, uint32_t value)
{
    uintptr_t wrap = (uintptr_t)g_ut.wrap;
    uintptr_t core = (uintptr_t)g_ut.core;
    uintptr_t kmu = (uintptr_t)g_ut.kmu;

    if ((addr >= wrap) && (addr < (wrap + sizeof(g_ut.wrap)))) {
        ut_wrap_write((uint32_t)(addr - wrap), value);
    } else if ((addr >= core) && (addr < (core + sizeof(g_ut.core)))) {
        ut_core_write((uint32_t)(addr - core), value);
    } else if ((addr >= kmu) && (addr < (kmu + sizeof(g_ut.kmu)))) {
        uint32_t off = (uint32_t)(addr - kmu);

        if ((off <= NOXTLS_NRF54_KMU_TASKS_BLOCK) && (value == NOXTLS_NRF54_KMU_TRIGGER)) {
            ut_kmu_task(off);
        } else {
            g_ut.kmu[UT_IDX(off)] = value;
        }
    } else if ((addr >= UT_NVIC_BASE) && (addr < (UT_NVIC_BASE + sizeof(g_ut.nvic)))) {
        uint32_t off = (uint32_t)(addr - UT_NVIC_BASE);
        uint32_t word = UT_IDX(0x100U) + (g_ut.irqn / 32U);
        uint32_t bit = UINT32_C(1) << (g_ut.irqn % 32U);

        if ((UT_IDX(off) == word) && ((value & bit) != 0U)) {
            g_ut.nvic_enabled = 1U;
        }
        if ((UT_IDX(off) == (word + UT_IDX(0x80U))) && ((value & bit) != 0U)) {
            g_ut.nvic_enabled = 0U;
        }
        g_ut.nvic[UT_IDX(off)] = value;
    } else {
        ut_fail("write outside the mocked blocks");
    }
}

/**
 * @brief CPU context probe of the mock.
 *
 * @return g_ut.in_isr.
 */
static uint8_t ut_in_isr(void)
{
    return g_ut.in_isr;
}

void ut_setup(uint8_t l15)
{
    static const noxtls_nrf54_io_t io = { ut_read32, ut_write32, ut_in_isr };
    noxtls_nrf54_hw_t hw;

    /* A failed assertion may have left CRACEN owned: start every test from a free engine. */
    noxtls_nordic_crypto_release();
    (void)noxtls_nrf54_cracen_set_port(NULL);
    (void)memset(&g_ut, 0, sizeof(g_ut));
    g_ut.l15 = l15;
    g_ut.irqn = (l15 != 0U) ? NOXTLS_NRF54_CRACEN_IRQN_L15 : NOXTLS_NRF54_CRACEN_IRQN_LM20;
    if (l15 != 0U) {
        /* nRF54L15 reset values: every AES key size, 128-bit counter. */
        g_ut.core[UT_IDX(NOXTLS_NRF54_HW_INCLIPS)] = UINT32_C(0x00000771);
        g_ut.core[UT_IDX(NOXTLS_NRF54_HW_BA411_CFG1)] = UINT32_C(0x070301FF);
        g_ut.core[UT_IDX(NOXTLS_NRF54_HW_BA411_CFG2)] = UINT32_C(0x00000080);
        g_ut.core[UT_IDX(NOXTLS_NRF54_HW_BA413_CFG)] = UINT32_C(0x0003003F);
        g_ut.core[UT_IDX(NOXTLS_NRF54_PK_HWCONFIG)] = UINT32_C(0x01F72200);
        g_ut.ctr_bits = 128U;
    } else {
        /* nRF54LM20B reset values (CRACEN Lite): no AES-192, 16-bit counter. */
        g_ut.core[UT_IDX(NOXTLS_NRF54_HW_INCLIPS)] = UINT32_C(0x00000671);
        g_ut.core[UT_IDX(NOXTLS_NRF54_HW_BA411_CFG1)] = UINT32_C(0x1D020167);
        g_ut.core[UT_IDX(NOXTLS_NRF54_HW_BA411_CFG2)] = UINT32_C(0x02000010);
        g_ut.core[UT_IDX(NOXTLS_NRF54_HW_BA413_CFG)] = UINT32_C(0x0001003E);
        g_ut.core[UT_IDX(NOXTLS_NRF54_PK_HWCONFIG)] = UINT32_C(0x01F31200);
        g_ut.ctr_bits = 16U;
    }
    hw.base = (uintptr_t)g_ut.wrap;
    hw.core = (uintptr_t)g_ut.core;
    hw.kmu = (uintptr_t)g_ut.kmu;
    hw.prot_key0 = (uintptr_t)g_ut_ram.prot;
    hw.irqn = g_ut.irqn;
    hw.ram_size = NOXTLS_NRF54_RAM_SIZE_LM20;
    hw.variant = (uint8_t)((l15 != 0U) ? NOXTLS_NRF54_VARIANT_BASE : NOXTLS_NRF54_VARIANT_LITE);
    (void)noxtls_nrf54_cracen_set_io(&io);
    (void)noxtls_nrf54_cracen_set_hw(&hw);
    noxtls_nrf54_cracen_set_dma_window((uintptr_t)&g_ut_ram, sizeof(g_ut_ram));
    noxtls_nrf54_cracen_set_enabled(1U);
    noxtls_nrf54_cracen_reset_stats();
    noxtls_nrf54_pke_invalidate_ucode();
    noxtls_nrf54_rng_reset_health();
    (void)memset(&g_ut_ram, 0, sizeof(g_ut_ram));
    g_ut_signals = 0U;
    g_ut_waits = 0U;
    g_ut_locks = 0U;
    g_ut_unlocks = 0U;
}

uint8_t ut_mock_run_irq(void)
{
    uint8_t ran = 0U;
    uint32_t pend;

    ut_rng_tick();
    (void)ut_cm_tick();
    (void)ut_pk_status_read();
    pend = ((g_ut.wrap[UT_IDX(NOXTLS_NRF54_EVENTS_CRYPTOMASTER)] != 0U) ? NOXTLS_NRF54_MOD_CM : 0U) |
           ((g_ut.wrap[UT_IDX(NOXTLS_NRF54_EVENTS_RNG)] != 0U) ? NOXTLS_NRF54_MOD_RNG : 0U) |
           ((g_ut.wrap[UT_IDX(NOXTLS_NRF54_EVENTS_PKEIKG)] != 0U) ? NOXTLS_NRF54_MOD_PKE : 0U);
    if (((pend & g_ut.inten) != 0U) && (g_ut.nvic_enabled != 0U)) {
        noxtls_nrf54_cracen_irq_handler();
        ran = 1U;
    }
    return ran;
}

/**
 * @brief Port wait hook: runs the pending interrupt like a sleeping task would be woken.
 *
 * @param[in] ctx        Unused.
 * @param[in] timeout_ms Unused.
 *
 * @return NOXTLS_RETURN_SUCCESS when signalled, NOXTLS_RETURN_TIMEOUT otherwise.
 */
static noxtls_return_t ut_port_wait(void *ctx, uint32_t timeout_ms)
{
    uint32_t n;
    noxtls_return_t rc = NOXTLS_RETURN_TIMEOUT;

    (void)ctx;
    (void)timeout_ms;
    g_ut_waits++;
    for (n = 0U; (n < 64U) && (g_ut_signals == 0U); n++) {
        (void)ut_mock_run_irq();
    }
    if (g_ut_signals != 0U) {
        g_ut_signals--;
        rc = NOXTLS_RETURN_SUCCESS;
    }
    return rc;
}

/**
 * @brief Port signal hook.
 *
 * @param[in] ctx Unused.
 */
static void ut_port_signal(void *ctx)
{
    (void)ctx;
    g_ut_signals++;
}

/**
 * @brief Port lock hook.
 *
 * @param[in] ctx Unused.
 */
static void ut_port_lock(void *ctx)
{
    (void)ctx;
    g_ut_locks++;
}

/**
 * @brief Port unlock hook.
 *
 * @param[in] ctx Unused.
 */
static void ut_port_unlock(void *ctx)
{
    (void)ctx;
    g_ut_unlocks++;
}

void ut_port_irq(void)
{
    static const noxtls_nrf54_port_t port = { ut_port_wait, ut_port_signal, ut_port_lock, ut_port_unlock, NULL };

    (void)noxtls_nrf54_cracen_set_port(&port);
}
