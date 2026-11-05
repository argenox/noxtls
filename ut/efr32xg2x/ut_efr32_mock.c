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
* File:    ut_efr32_mock.c
* Summary: Functional RADIOAES / SEMAILBOX / CMU register mock for the backend host tests
*
*****************************************************************************/

/**
 * @file ut_efr32_mock.c
 * @brief Implementation of the EFR32xG2x register mock (see ut_efr32_mock.h).
 * @ingroup noxtls_efr32_ut
 */

#include <stdio.h>
#include <string.h>

#include "ut_efr32_mock.h"

#include "noxtls_aes.h"
#include "noxtls_aes_ccm.h"
#include "noxtls_ecc.h"
#include "noxtls_ecdsa.h"
#include "noxtls_sha.h"

/** @brief Largest AES stream the mock handles. */
#define UT_STREAM_MAX       0x12000U
/** @brief Fetch descriptors accepted in one job. */
#define UT_DESC_MAX         16U
/** @brief Data segments recorded per job. */
#define UT_SEG_MAX          8U

/** One DMA descriptor as laid out in memory. */
typedef struct {
    uint32_t addr; /**< Address. */
    uint32_t next; /**< Next or STOP. */
    uint32_t len;  /**< Length | flags. */
    uint32_t tag;  /**< Tag. */
} ut_desc_t;

/** One data segment of a job. */
typedef struct {
    const uint8_t *p; /**< Data. */
    uint32_t len;     /**< Real bytes. */
    uint32_t inv;     /**< Invalid trailing bytes. */
    uint8_t hdr;      /**< Header data type. */
    uint8_t last;     /**< LAST tag. */
} ut_seg_t;

ut_mock_t g_ut;
ut_ram_t g_ut_ram;

volatile uint32_t g_ut_bound_aes_busy;
volatile uint32_t g_ut_bound_se_busy;
volatile uint32_t g_ut_bound_calls[4];

/** Job streams. */
static uint8_t s_hdr[UT_STREAM_MAX];
/** Payload stream. */
static uint8_t s_pay[UT_STREAM_MAX];
/** Engine output stream. */
static uint8_t s_out[UT_STREAM_MAX + 64U];

/**
 * @brief Reconstruct a 64-bit host pointer from a 32-bit descriptor address.
 * @internal
 *
 * @param[in] lo Low 32 bits.
 *
 * @return Pointer into the test image.
 */
static uint8_t *ut_ptr(uint32_t lo)
{
    uintptr_t hi = (uintptr_t)&g_ut & ~(uintptr_t)UINT32_MAX;

    return (uint8_t *)(hi | (uintptr_t)lo);
}

/**
 * @brief Record the first rule violation.
 * @internal
 *
 * @param[in] msg Message.
 */
static void ut_fail(const char *msg)
{
    if (g_ut.err[0] == '\0') {
        (void)snprintf(g_ut.err, sizeof(g_ut.err), "%s", msg);
    }
}

uint8_t ut_clean(void)
{
    return (g_ut.err[0] == '\0') ? 1U : 0U;
}

uint32_t ut_hex(const char *hex, uint8_t *out)
{
    uint32_t n = 0U;

    while ((hex[0] != '\0') && (hex[1] != '\0')) {
        unsigned int v = 0U;

        (void)sscanf(hex, "%2x", &v);
        out[n] = (uint8_t)v;
        n++;
        hex += 2;
    }
    return n;
}

/**
 * @brief AES key selector of a key length.
 * @internal
 *
 * @param[in] klen Bytes.
 *
 * @return Selector.
 */
static noxtls_aes_type_t ut_type(uint32_t klen)
{
    return (klen == 16U) ? NOXTLS_AES_128_BIT : ((klen == 24U) ? NOXTLS_AES_192_BIT : NOXTLS_AES_256_BIT);
}

/**
 * @brief Walk a push chain and write the engine output through it.
 * @internal
 *
 * @param[in] stream Engine output.
 * @param[in] n      Engine output bytes.
 *
 * @return 1 when the push chain consumed exactly the stream.
 */
static uint8_t ut_push(const uint8_t *stream, uint32_t n)
{
    const ut_desc_t *d = (const ut_desc_t *)ut_ptr(g_ut.aes[UT_IDX(NOXTLS_EFR32_AES_PUSHADDR)]);
    uint32_t used = 0U;
    uint32_t count = 0U;
    uint8_t ok = 1U;

    for (;;) {
        uint32_t len = d->len & NOXTLS_EFR32_DESC_LEN_MSK;

        count++;
        if ((used + len) > n) {
            ut_fail("push chain longer than the engine output");
            ok = 0U;
            break;
        }
        if ((d->len & NOXTLS_EFR32_DESC_DISCARD) == 0U) {
            (void)memcpy(ut_ptr(d->addr), &stream[used], len);
        }
        used += len;
        if ((d->next == NOXTLS_EFR32_DESC_STOP) || (count >= UT_DESC_MAX)) {
            break;
        }
        d = (const ut_desc_t *)ut_ptr(d->next);
    }
    if ((ok != 0U) && (used != n)) {
        ut_fail("push chain shorter than the engine output");
        ok = 0U;
    }
    g_ut.aes_push_descs = count;
    return ok;
}

/**
 * @brief Run CCM through the software implementation.
 * @internal
 *
 * @param[in] decrypt  Direction.
 * @param[in] key      Key.
 * @param[in] klen     Key bytes.
 * @param[in] seg      Segments.
 * @param[in] nseg     Segment count.
 *
 * @return Output stream bytes, 0 on a rule violation.
 */
static uint32_t ut_ccm(uint8_t decrypt, const uint8_t *key, uint32_t klen, const ut_seg_t *seg, uint32_t nseg)
{
    uint32_t hdr_total = 0U;
    uint32_t hdr_real = 0U;
    uint32_t pay_total = 0U;
    uint32_t pay_real = 0U;
    uint32_t hdr_inv = 0U;
    uint32_t pay_inv = 0U;
    uint32_t i;
    uint32_t nhdr = 0U;
    uint32_t npay = 0U;
    uint32_t flags;
    uint32_t q;
    uint32_t t;
    uint32_t nlen;
    uint32_t plen = 0U;
    uint32_t enc = 0U;
    uint32_t alen = 0U;
    uint32_t data_pad;
    uint32_t out_n = 0U;
    uint8_t tag[16] = { 0U };
    uint8_t rx_tag[16] = { 0U };
    uint32_t data_segs;
    noxtls_return_t rc;

    for (i = 0U; i < nseg; i++) {
        if (seg[i].hdr != 0U) {
            if (npay != 0U) {
                ut_fail("ccm header after payload");
                return 0U;
            }
            if ((seg[i].inv != 0U) && (i + 1U < nseg) && (seg[i + 1U].hdr != 0U)) {
                ut_fail("ccm invalid bytes inside the header stream");
                return 0U;
            }
            (void)memcpy(&s_hdr[hdr_real], seg[i].p, seg[i].len);
            hdr_real += seg[i].len;
            hdr_inv = seg[i].inv;
            nhdr++;
        } else {
            npay++;
        }
    }
    hdr_total = ((hdr_real + 15U) / 16U) * 16U;
    if ((nhdr == 0U) || (hdr_real < 16U) || (hdr_inv != (hdr_total - hdr_real))) {
        ut_fail("ccm header stream padding wrong");
        return 0U;
    }
    flags = s_hdr[0];
    q = (flags & 7U) + 1U;
    t = (((flags >> 3) & 7U) * 2U) + 2U;
    nlen = 15U - q;
    for (i = 0U; i < q; i++) {
        plen = (plen << 8) | s_hdr[16U - q + i];
    }
    if ((flags & 0x40U) != 0U) {
        if ((s_hdr[16] == 0xFFU) && (s_hdr[17] == 0xFEU)) {
            enc = 6U;
            alen = ((uint32_t)s_hdr[18] << 24) | ((uint32_t)s_hdr[19] << 16) | ((uint32_t)s_hdr[20] << 8) | s_hdr[21];
        } else {
            enc = 2U;
            alen = ((uint32_t)s_hdr[16] << 8) | s_hdr[17];
        }
    }
    if (hdr_real != (16U + enc + alen)) {
        ut_fail("ccm header length does not match B0 / AAD length");
        return 0U;
    }
    data_segs = npay - ((decrypt != 0U) ? 1U : 0U);
    if (npay == 0U) {
        ut_fail("ccm without payload descriptor");
        return 0U;
    }
    for (i = 0U; i < nseg; i++) {
        if (seg[i].hdr == 0U) {
            uint32_t idx = i - nhdr;

            if (idx < data_segs) {
                (void)memcpy(&s_pay[pay_real], seg[i].p, seg[i].len);
                pay_real += seg[i].len;
                pay_inv = seg[i].inv;
            } else {
                if ((seg[i].len != t) || (seg[i].inv != (16U - t)) || (seg[i].last == 0U)) {
                    ut_fail("ccm decrypt tag descriptor malformed");
                    return 0U;
                }
                (void)memcpy(rx_tag, seg[i].p, t);
            }
        }
    }
    pay_total = ((pay_real + 15U) / 16U) * 16U;
    if (plen == 0U) {
        if ((pay_real != 16U) || (pay_inv != 16U)) {
            ut_fail("ccm empty payload needs one fully invalid block");
            return 0U;
        }
        data_pad = 16U;
    } else {
        if ((pay_real != plen) || (pay_inv != (pay_total - plen))) {
            ut_fail("ccm payload descriptor does not match B0");
            return 0U;
        }
        data_pad = pay_inv;
    }
    if (decrypt == 0U) {
        rc = noxtls_aes_ccm_encrypt(key, ut_type(klen), &s_hdr[1], nlen, &s_hdr[16U + enc], alen, s_pay, plen, &s_out[hdr_total],
                                    tag, t);
    } else {
        rc = noxtls_aes_ccm_decrypt(key, ut_type(klen), &s_hdr[1], nlen, &s_hdr[16U + enc], alen, s_pay, plen, rx_tag, t,
                                    &s_out[hdr_total]);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            (void)memset(&s_out[hdr_total], 0, plen);
            (void)memset(tag, 0x5A, sizeof(tag));
        }
    }
    (void)memset(s_out, 0, hdr_total);
    (void)memset(&s_out[hdr_total + plen], 0, data_pad);
    out_n = hdr_total + plen + data_pad;
    (void)memcpy(&s_out[out_n], tag, t);
    (void)memset(&s_out[out_n + t], 0, 16U - t);
    return out_n + 16U;
}

/**
 * @brief Execute the job described by FETCHADDR / PUSHADDR.
 * @internal
 */
static void ut_aes_run(void)
{
    const ut_desc_t *d = (const ut_desc_t *)ut_ptr(g_ut.aes[UT_IDX(NOXTLS_EFR32_AES_FETCHADDR)]);
    ut_seg_t seg[UT_SEG_MAX];
    uint32_t nseg = 0U;
    uint32_t cfg = 0U;
    uint8_t cfg_seen = 0U;
    uint8_t key[32] = { 0U };
    uint32_t klen = 0U;
    uint8_t iv[16] = { 0U };
    uint32_t ivlen = 0U;
    uint32_t count = 0U;
    uint32_t out_n = 0U;
    uint8_t masking = ((g_ut.aes[UT_IDX(NOXTLS_EFR32_AES_BA411E_HW_CFG_1)] & NOXTLS_EFR32_AES_CFG1_MASKING) != 0U) ? 1U : 0U;
    uint8_t err = 0U;

    g_ut.aes_jobs++;
    g_ut.aes_mask_seen = 0U;
    (void)memset(seg, 0, sizeof(seg));
    for (;;) {
        uint32_t tag = d->tag;
        uint32_t len = d->len & NOXTLS_EFR32_DESC_LEN_MSK;

        count++;
        if ((count == 1U) && (masking != 0U) && ((tag & NOXTLS_EFR32_TAG_CONFIG) == 0U)) {
            ut_fail("masking engine without the mask word first");
            err = 1U;
        }
        if ((tag & NOXTLS_EFR32_TAG_ENGINE_AES) == 0U) {
            ut_fail("descriptor not routed to the AES engine");
            err = 1U;
        }
        if ((tag & NOXTLS_EFR32_TAG_CONFIG) != 0U) {
            uint32_t off = (tag >> NOXTLS_EFR32_TAG_OFFSET_POS) & NOXTLS_EFR32_TAG_OFFSET_MSK;

            if ((d->len & NOXTLS_EFR32_DESC_REALIGN) == 0U) {
                ut_fail("configuration descriptor without REALIGN");
                err = 1U;
            }
            if (nseg != 0U) {
                ut_fail("configuration after data");
                err = 1U;
            }
            if (off == NOXTLS_EFR32_AES_REG_CONFIG) {
                if (len != 4U) {
                    ut_fail("configuration word is not 4 bytes");
                    err = 1U;
                } else {
                    (void)memcpy(&cfg, ut_ptr(d->addr), 4U);
                    cfg_seen = 1U;
                }
            } else if (off == NOXTLS_EFR32_AES_REG_KEY) {
                klen = len;
                if ((len != 16U) && (len != 24U) && (len != 32U)) {
                    ut_fail("key length is not an AES key length");
                    err = 1U;
                } else {
                    (void)memcpy(key, ut_ptr(d->addr), len);
                }
            } else if (off == NOXTLS_EFR32_AES_REG_IV) {
                ivlen = len;
                if (len != 16U) {
                    ut_fail("IV is not 16 bytes");
                    err = 1U;
                } else {
                    (void)memcpy(iv, ut_ptr(d->addr), len);
                }
            } else if (off == NOXTLS_EFR32_AES_REG_MASK) {
                (void)memcpy(&g_ut.aes_mask_seen, ut_ptr(d->addr), 4U);
                if ((len != 4U) || ((g_ut.aes_mask_seen & NOXTLS_EFR32_AES_MASK_TOP_BIT) == 0U)) {
                    ut_fail("mask word malformed");
                    err = 1U;
                }
            } else {
                ut_fail("unknown configuration offset");
                err = 1U;
            }
        } else if (nseg < UT_SEG_MAX) {
            seg[nseg].p = ut_ptr(d->addr);
            seg[nseg].len = len;
            seg[nseg].inv = (tag >> NOXTLS_EFR32_TAG_INVALID_POS) & NOXTLS_EFR32_TAG_INVALID_MSK;
            seg[nseg].hdr = ((tag & NOXTLS_EFR32_TAG_HEADER) != 0U) ? 1U : 0U;
            seg[nseg].last = ((tag & NOXTLS_EFR32_TAG_LAST) != 0U) ? 1U : 0U;
            nseg++;
        } else {
            ut_fail("too many data descriptors");
            err = 1U;
        }
        if ((d->next == NOXTLS_EFR32_DESC_STOP) || (count >= UT_DESC_MAX)) {
            break;
        }
        d = (const ut_desc_t *)ut_ptr(d->next);
    }
    g_ut.aes_fetch_descs = count;
    g_ut.aes_last_cfg = cfg;
    if ((cfg_seen == 0U) || (nseg == 0U) || (klen == 0U)) {
        ut_fail("job without configuration, key or data");
        err = 1U;
    }
    if ((err == 0U) && (nseg != 0U) && (seg[nseg - 1U].last == 0U)) {
        ut_fail("final data descriptor without LAST");
        err = 1U;
    }
    if (err == 0U) {
        uint32_t mode = (cfg >> NOXTLS_EFR32_AES_CFG_MODE_POS) & NOXTLS_EFR32_AES_MODES_MSK;
        uint32_t ksel = cfg & 0xCU;
        uint8_t decrypt = (uint8_t)(cfg & NOXTLS_EFR32_AES_CFG_DECRYPT);
        uint8_t cx = ((cfg & NOXTLS_EFR32_AES_CFG_CX_LOAD) != 0U) ? 1U : 0U;

        if (((ksel == NOXTLS_EFR32_AES_CFG_KEY_128) && (klen != 16U)) || ((ksel == NOXTLS_EFR32_AES_CFG_KEY_256) && (klen != 32U)) ||
            ((ksel == NOXTLS_EFR32_AES_CFG_KEY_192) && (klen != 24U))) {
            ut_fail("key size bits do not match the key length");
            err = 1U;
        } else if (mode == (UINT32_C(1) << NOXTLS_EFR32_AES_MODE_CCM)) {
            out_n = ut_ccm(decrypt, key, klen, seg, nseg);
            err = (out_n == 0U) ? 1U : 0U;
        } else if ((mode == (UINT32_C(1) << NOXTLS_EFR32_AES_MODE_ECB)) || (mode == (UINT32_C(1) << NOXTLS_EFR32_AES_MODE_CBC)) ||
                   (mode == (UINT32_C(1) << NOXTLS_EFR32_AES_MODE_CTR))) {
            uint32_t total = 0U;
            uint32_t i;
            uint8_t need_iv = (mode == (UINT32_C(1) << NOXTLS_EFR32_AES_MODE_ECB)) ? 0U : 1U;

            for (i = 0U; i < nseg; i++) {
                if ((seg[i].hdr != 0U) || (seg[i].inv != 0U)) {
                    ut_fail("header or invalid bytes in a plain cipher job");
                    err = 1U;
                } else if ((total + seg[i].len) <= UT_STREAM_MAX) {
                    (void)memcpy(&s_pay[total], seg[i].p, seg[i].len);
                    total += seg[i].len;
                } else {
                    ut_fail("stream too long for the mock");
                    err = 1U;
                }
            }
            if ((total % 16U) != 0U) {
                ut_fail("plain cipher job not whole blocks");
                err = 1U;
            } else if ((need_iv != 0U) != (ivlen == 16U)) {
                ut_fail("IV presence does not match the mode");
                err = 1U;
            } else if (need_iv != cx) {
                ut_fail("context load does not match the IV");
                err = 1U;
            } else if (err == 0U) {
                if (mode == (UINT32_C(1) << NOXTLS_EFR32_AES_MODE_ECB)) {
                    (void)((decrypt != 0U) ? noxtls_aes_decrypt_ecb(key, s_pay, total, NULL, s_out, ut_type(klen)) :
                           noxtls_aes_encrypt_ecb(key, s_pay, total, NULL, s_out, ut_type(klen)));
                } else if (mode == (UINT32_C(1) << NOXTLS_EFR32_AES_MODE_CBC)) {
                    (void)((decrypt != 0U) ? noxtls_aes_decrypt_cbc(key, s_pay, total, iv, s_out, ut_type(klen)) :
                           noxtls_aes_encrypt_cbc(key, s_pay, total, iv, s_out, ut_type(klen)));
                } else {
                    (void)noxtls_aes_encrypt_ctr(key, s_pay, total, iv, s_out, ut_type(klen));
                }
                out_n = total;
            } else {
                /* Rule violation already recorded. */
            }
        } else {
            ut_fail("mode not implemented by the model");
            err = 1U;
        }
    }
    if ((err == 0U) && (ut_push(s_out, out_n) == 0U)) {
        err = 1U;
    }
    if (err != 0U) {
        g_ut.aes_if |= NOXTLS_EFR32_AES_IF_FETCH_ERR;
    }
}

/**
 * @brief Mailbox transfer chain walker.
 * @internal
 *
 * @param[in]  first First transfer address (0: none).
 * @param[out] p     Receives data pointers.
 * @param[out] len   Receives lengths.
 * @param[in]  max   Capacity.
 *
 * @return Transfers found.
 */
static uint32_t ut_xfers(uint32_t first, uint8_t **p, uint32_t *len, uint32_t max)
{
    uint32_t n = 0U;
    const uint32_t *x = (first != 0U) ? (const uint32_t *)ut_ptr(first) : NULL;

    while ((x != NULL) && (n < max)) {
        p[n] = ut_ptr(x[0]);
        len[n] = x[2] & NOXTLS_EFR32_SE_XFER_LEN_MSK;
        if ((x[2] & NOXTLS_EFR32_SE_XFER_REALIGN) == 0U) {
            ut_fail("SE transfer without REALIGN");
        }
        n++;
        x = (x[1] == NOXTLS_EFR32_SE_XFER_STOP) ? NULL : (const uint32_t *)ut_ptr(x[1]);
    }
    return n;
}

/**
 * @brief Software point multiplication for the DH model.
 * @internal
 *
 * @param[in]  sz Coordinate bytes.
 * @param[in]  k  Scalar.
 * @param[in]  px x.
 * @param[in]  py y.
 * @param[out] r  Receives x || y.
 *
 * @return 1 on success.
 */
static uint8_t ut_mul(uint32_t sz, const uint8_t *k, const uint8_t *px, const uint8_t *py, uint8_t *r)
{
    const ecc_curve_params_t *curve = noxtls_ecc_curve_get((sz == 32U) ? NOXTLS_ECC_SECP256R1 : NOXTLS_ECC_SECP384R1);
    ecc_point_t p;
    ecc_point_t res;
    uint8_t ok = 0U;

    if (curve != NULL) {
        (void)memset(&p, 0, sizeof(p));
        (void)memset(&res, 0, sizeof(res));
        p.size = sz;
        res.size = sz;
        (void)memcpy(p.x, px, sz);
        (void)memcpy(p.y, py, sz);
        if (noxtls_ecc_point_multiply(&res, k, &p, curve) == NOXTLS_RETURN_SUCCESS) {
            (void)memcpy(r, res.x, sz);
            (void)memcpy(&r[sz], res.y, sz);
            ok = 1U;
        }
    }
    return ok;
}

/**
 * @brief Load an ECDSA key for the software model.
 * @internal
 *
 * @param[out] key  Key.
 * @param[in]  sz   Coordinate bytes.
 * @param[in]  d    Private scalar (NULL: public only).
 * @param[in]  q    Public x || y (used when @p d is NULL).
 *
 * @return 1 on success.
 */
static uint8_t ut_key(ecc_key_t *key, uint32_t sz, const uint8_t *d, const uint8_t *q)
{
    ecc_curve_t id = (sz == 32U) ? NOXTLS_ECC_SECP256R1 : NOXTLS_ECC_SECP384R1;
    uint8_t ok = 0U;

    if (d != NULL) {
        ok = (noxtls_ecc_key_import_private(key, id, d, sz) == NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    } else if (noxtls_ecc_key_init(key, id) == NOXTLS_RETURN_SUCCESS) {
        (void)memcpy(key->Q.x, q, sz);
        (void)memcpy(key->Q.y, &q[sz], sz);
        key->Q.size = sz;
        ok = 1U;
    } else {
        /* Key init failed. */
    }
    return ok;
}

/**
 * @brief Execute the SE command held in the FIFO words.
 * @internal
 */
static void ut_se_exec(void)
{
    uint32_t cmd = g_ut.sem_words[0];
    uint32_t in_addr = g_ut.sem_words[1];
    uint32_t out_addr = g_ut.sem_words[2];
    uint32_t np = g_ut.sem_nwords - 3U;
    const uint32_t *par = &g_ut.sem_words[3];
    uint8_t *ip[6];
    uint32_t il[6];
    uint8_t *op[2];
    uint32_t ol[2];
    uint32_t ni;
    uint32_t no;
    uint32_t resp = NOXTLS_EFR32_SE_RESP_OK;
    uint32_t i;

    g_ut.se_cmds++;
    g_ut.se_last_cmd = cmd;
    g_ut.se_last_nparams = np;
    for (i = 0U; (i < np) && (i < 5U); i++) {
        g_ut.se_last_params[i] = par[i];
    }
    ni = ut_xfers(in_addr, ip, il, 6U);
    no = ut_xfers(out_addr, op, ol, 2U);
    if (g_ut.se_fail_first != 0U) {
        g_ut.se_fail_first--;
        resp = NOXTLS_EFR32_SE_RESP_INTERNAL;
    } else if ((g_ut.se_fail_at != 0U) && (g_ut.se_cmds == g_ut.se_fail_at)) {
        resp = NOXTLS_EFR32_SE_RESP_INTERNAL;
    } else if (g_ut.se_force != 0U) {
        resp = g_ut.se_force_resp;
    } else if (cmd == NOXTLS_EFR32_SE_CMD_TRNG) {
        if ((np != 1U) || (no != 1U) || (ol[0] != par[0]) || ((par[0] % 4U) != 0U)) {
            ut_fail("TRNG command malformed");
            resp = NOXTLS_EFR32_SE_RESP_INVALID_PARAM;
        } else {
            for (i = 0U; i < par[0]; i += 4U) {
                uint32_t w;

                g_ut.rng_state ^= g_ut.rng_state << 13;
                g_ut.rng_state ^= g_ut.rng_state >> 17;
                g_ut.rng_state ^= g_ut.rng_state << 5;
                w = (g_ut.se_trng_zero != 0U) ? 0U : g_ut.rng_state;
                (void)memcpy(&op[0][i], &w, 4U);
            }
        }
    } else if ((cmd & 0xFFFF0000U) == NOXTLS_EFR32_SE_CMD_HASHUPDATE) {
        uint32_t opt = cmd & 0xFFFFU;
        uint32_t slen = (opt == NOXTLS_EFR32_SE_OPT_HASH_SHA512) ? 64U : 32U;
        uint32_t blk = (opt == NOXTLS_EFR32_SE_OPT_HASH_SHA512) ? 128U : 64U;

        if (((opt != NOXTLS_EFR32_SE_OPT_HASH_SHA256) && (opt != NOXTLS_EFR32_SE_OPT_HASH_SHA512)) || (np != 1U) || (ni != 2U) ||
            (no != 1U) || (il[0] != slen) || (il[1] != par[0]) || (ol[0] != slen) || ((par[0] % blk) != 0U)) {
            if ((opt != NOXTLS_EFR32_SE_OPT_HASH_SHA256) && (opt != NOXTLS_EFR32_SE_OPT_HASH_SHA512)) {
                resp = NOXTLS_EFR32_SE_RESP_INVALID_CMD;
            } else {
                ut_fail("HASHUPDATE command malformed");
                resp = NOXTLS_EFR32_SE_RESP_INVALID_PARAM;
            }
        } else {
            noxtls_sha_ctx_t ctx;
            uint8_t st[64] = { 0U };
            uint32_t wb = (opt == NOXTLS_EFR32_SE_OPT_HASH_SHA512) ? 8U : 4U;
            uint32_t b;

            (void)noxtls_sha_init(&ctx, (opt == NOXTLS_EFR32_SE_OPT_HASH_SHA512) ? NOXTLS_HASH_SHA_512 : NOXTLS_HASH_SHA_256);
            for (i = 0U; i < 8U; i++) {
                uint64_t w = 0U;

                for (b = 0U; b < wb; b++) {
                    w = (w << 8) | ip[0][(i * wb) + b];
                }
                if (wb == 8U) {
                    ctx.u.sha512_ctx.h[i] = w;
                } else {
                    ctx.u.md32.h[i] = (uint32_t)w;
                }
            }
            (void)noxtls_sha_update(&ctx, ip[1], par[0]);
            for (i = 0U; i < 8U; i++) {
                uint64_t w = (wb == 8U) ? ctx.u.sha512_ctx.h[i] : (uint64_t)ctx.u.md32.h[i];

                for (b = 0U; b < wb; b++) {
                    st[(i * wb) + b] = (uint8_t)(w >> (8U * (wb - 1U - b)));
                }
            }
            (void)memcpy(op[0], st, slen);
            g_ut.se_hash_blocks += par[0] / blk;
        }
    } else if (cmd == NOXTLS_EFR32_SE_CMD_DH) {
        uint32_t sz = (np == 2U) ? ((par[0] & NOXTLS_EFR32_KEYSPEC_ECC_SIZE_MSK) + 1U) : 0U;

        if ((np != 2U) || ((sz != 32U) && (sz != 48U)) ||
            (par[0] != (NOXTLS_EFR32_KEYSPEC_TYPE_WEIERSTRASS | NOXTLS_EFR32_KEYSPEC_ECC_PRIVATE | (sz - 1U))) ||
            (par[1] != (2U * sz)) || (ni != 3U) || (no != 1U) || (il[0] != 0U) || (il[1] != sz) || (il[2] != (2U * sz)) ||
            (ol[0] != (2U * sz))) {
            ut_fail("DH command malformed");
            resp = NOXTLS_EFR32_SE_RESP_INVALID_PARAM;
        } else if (ut_mul(sz, ip[1], ip[2], &ip[2][sz], op[0]) == 0U) {
            resp = NOXTLS_EFR32_SE_RESP_CRYPTO_ERROR;
        } else if (g_ut.se_wrong_mul != 0U) {
            op[0][0] ^= (uint8_t)(g_ut.se_cmds & 1U);
        } else if (g_ut.se_infinity != 0U) {
            (void)memset(op[0], 0, 2U * sz);
        } else {
            /* Exact result. */
        }
    } else if ((cmd == NOXTLS_EFR32_SE_CMD_SIGN) || (cmd == NOXTLS_EFR32_SE_CMD_VERIFY)) {
        uint8_t sign = (cmd == NOXTLS_EFR32_SE_CMD_SIGN) ? 1U : 0U;
        uint32_t sz = (np == 2U) ? ((par[0] & NOXTLS_EFR32_KEYSPEC_ECC_SIZE_MSK) + 1U) : 0U;
        uint32_t flag = (sign != 0U) ? NOXTLS_EFR32_KEYSPEC_ECC_PRIVATE : NOXTLS_EFR32_KEYSPEC_ECC_PUBLIC;
        uint32_t klen = (sign != 0U) ? sz : (2U * sz);
        uint8_t shape = (sign != 0U) ? (uint8_t)((ni == 3U) && (no == 1U) && (ol[0] == (2U * sz))) :
                        (uint8_t)((ni == 4U) && (no == 0U) && (il[3] == (2U * sz)));

        if ((np != 2U) || ((sz != 32U) && (sz != 48U)) ||
            (par[0] != (NOXTLS_EFR32_KEYSPEC_TYPE_WEIERSTRASS | flag | (sz - 1U))) || (par[1] != sz) || (shape == 0U) ||
            (il[0] != 0U) || (il[1] != klen) || (il[2] != sz)) {
            ut_fail("ECDSA command malformed");
            resp = NOXTLS_EFR32_SE_RESP_INVALID_PARAM;
        } else {
            ecc_key_t key;
            ecdsa_signature_t sig;
            uint8_t ok = ut_key(&key, sz, (sign != 0U) ? ip[1] : NULL, ip[1]);

            (void)memset(&sig, 0, sizeof(sig));
            sig.size = sz;
            if (ok == 0U) {
                resp = NOXTLS_EFR32_SE_RESP_INVALID_PARAM;
            } else if (sign != 0U) {
                if (noxtls_ecdsa_sign_digest(&key, ip[2], sz, &sig) != NOXTLS_RETURN_SUCCESS) {
                    resp = NOXTLS_EFR32_SE_RESP_CRYPTO_ERROR;
                } else {
                    (void)memcpy(op[0], sig.r, sz);
                    (void)memcpy(&op[0][sz], sig.s, sz);
                }
                (void)noxtls_ecc_key_free(&key);
            } else {
                (void)memcpy(sig.r, ip[3], sz);
                (void)memcpy(sig.s, &ip[3][sz], sz);
                if (noxtls_ecdsa_verify_digest(&key, ip[2], sz, &sig) != NOXTLS_RETURN_SUCCESS) {
                    resp = NOXTLS_EFR32_SE_RESP_INVALID_SIG;
                }
                (void)noxtls_ecc_key_free(&key);
            }
        }
    } else {
        resp = NOXTLS_EFR32_SE_RESP_INVALID_CMD;
    }
    g_ut.sem_rx_header = resp;
    g_ut.sem_rx_ready = 1U;
}

/**
 * @brief Register read model.
 * @internal
 *
 * @param[in] addr Address.
 *
 * @return Value.
 */
static uint32_t ut_read32(uintptr_t addr)
{
    uintptr_t aes = (uintptr_t)g_ut.aes;
    uintptr_t sem = (uintptr_t)g_ut.sem;
    uint32_t v = 0U;

    if ((addr >= aes) && (addr < (aes + sizeof(g_ut.aes)))) {
        uint32_t off = (uint32_t)(addr - aes);

        if (off == NOXTLS_EFR32_AES_STATUS) {
            v = (g_ut.aes_hang != 0U) ? NOXTLS_EFR32_AES_ST_FETCH_BUSY : 0U;
            if ((g_ut.aes[UT_IDX(NOXTLS_EFR32_AES_CTRL)] & NOXTLS_EFR32_AES_CTRL_SWRESET) != 0U) {
                v |= NOXTLS_EFR32_AES_ST_SOFTRST_BUSY;
            } else if (g_ut.aes_softrst_stuck != 0U) {
                v |= (g_ut.aes_resets != 0U) ? NOXTLS_EFR32_AES_ST_SOFTRST_BUSY : 0U;
            } else {
                /* Idle. */
            }
        } else if (off == NOXTLS_EFR32_AES_IF) {
            v = g_ut.aes_if;
        } else {
            v = g_ut.aes[UT_IDX(off)];
        }
    } else if ((addr >= sem) && (addr < (sem + sizeof(g_ut.sem)))) {
        uint32_t off = (uint32_t)(addr - sem);

        if (off == NOXTLS_EFR32_SEM_TX_STATUS) {
            if (g_ut.sem_tx_never != 0U) {
                v = 0U;
            } else if (g_ut.sem_tx_polls != 0U) {
                g_ut.sem_tx_polls--;
            } else {
                v = NOXTLS_EFR32_SEM_TXINT;
            }
        } else if (off == NOXTLS_EFR32_SEM_RX_STATUS) {
            if ((g_ut.sem_rx_ready == 0U) || (g_ut.sem_rx_never != 0U)) {
                v = 0U;
            } else if (g_ut.sem_rx_polls != 0U) {
                g_ut.sem_rx_polls--;
            } else {
                v = NOXTLS_EFR32_SEM_RXINT;
            }
        } else if (off == NOXTLS_EFR32_SEM_RX_HEADER) {
            v = g_ut.sem_rx_header;
            g_ut.sem_rx_ready = 0U;
        } else {
            v = g_ut.sem[UT_IDX(off)];
        }
    } else {
        uintptr_t cmu = (uintptr_t)g_ut.cmu;

        v = ((addr >= cmu) && (addr < (cmu + sizeof(g_ut.cmu)))) ? g_ut.cmu[UT_IDX(addr - cmu)] : 0U;
    }
    return v;
}

/**
 * @brief Register write model.
 * @internal
 *
 * @param[in] addr  Address.
 * @param[in] value Value.
 */
static void ut_write32(uintptr_t addr, uint32_t value)
{
    uintptr_t aes = (uintptr_t)g_ut.aes;
    uintptr_t sem = (uintptr_t)g_ut.sem;
    uintptr_t cmu = (uintptr_t)g_ut.cmu;

    if ((addr >= aes) && (addr < (aes + sizeof(g_ut.aes)))) {
        uint32_t off = (uint32_t)(addr - aes);

        if (off == NOXTLS_EFR32_AES_CMD) {
            if ((value == NOXTLS_EFR32_AES_CMD_START_BOTH) && (g_ut.aes_no_start == 0U)) {
                if ((g_ut.aes[UT_IDX(NOXTLS_EFR32_AES_CTRL)] & NOXTLS_EFR32_AES_CTRL_SG) != NOXTLS_EFR32_AES_CTRL_SG) {
                    ut_fail("job started without scatter/gather mode");
                    g_ut.aes_if |= NOXTLS_EFR32_AES_IF_FETCH_ERR;
                } else if ((g_ut.aes_jobs_fail_after != 0U) && ((g_ut.aes_jobs + 1U) == g_ut.aes_jobs_fail_after)) {
                    g_ut.aes_jobs++;
                    g_ut.aes_if |= NOXTLS_EFR32_AES_IF_PUSH_ERR;
                } else if (g_ut.aes_bus_error != 0U) {
                    g_ut.aes_jobs++;
                    g_ut.aes_if |= NOXTLS_EFR32_AES_IF_PUSH_ERR;
                } else if (g_ut.aes_hang != 0U) {
                    g_ut.aes_jobs++;
                } else {
                    ut_aes_run();
                }
            } else if (g_ut.aes_no_start == 0U) {
                ut_fail("CMD value is not START_BOTH");
            } else {
                /* Ignored on purpose. */
            }
        } else if (off == NOXTLS_EFR32_AES_IF_CLR) {
            g_ut.aes_if &= ~value;
        } else if (off == NOXTLS_EFR32_AES_CTRL) {
            if ((value & NOXTLS_EFR32_AES_CTRL_SWRESET) != 0U) {
                g_ut.aes_resets++;
                g_ut.aes_hang = 0U;
            }
            g_ut.aes[UT_IDX(off)] = value;
        } else if ((off < NOXTLS_EFR32_AES_INCL_IPS_HW_CFG)) {
            g_ut.aes[UT_IDX(off)] = value;
        } else {
            ut_fail("write to a read-only hardware configuration register");
        }
    } else if ((addr >= sem) && (addr < (sem + sizeof(g_ut.sem)))) {
        uint32_t off = (uint32_t)(addr - sem);

        if (off == NOXTLS_EFR32_SEM_TX_HEADER) {
            g_ut.sem_nwords = 0U;
            g_ut.sem_expect = (value / NOXTLS_EFR32_SEM_WORD_BYTES) - 1U;
            if (((value % NOXTLS_EFR32_SEM_WORD_BYTES) != 0U) || (g_ut.sem_expect < 3U) || (g_ut.sem_expect > 8U)) {
                ut_fail("TX_HEADER announces an impossible message size");
                g_ut.sem_expect = 3U;
            }
        } else if (off == NOXTLS_EFR32_SEM_FIFO) {
            if (g_ut.sem_nwords < 16U) {
                g_ut.sem_words[g_ut.sem_nwords] = value;
            }
            g_ut.sem_nwords++;
            if (g_ut.sem_nwords == g_ut.sem_expect) {
                ut_se_exec();
            }
        } else {
            g_ut.sem[UT_IDX(off)] = value;
        }
    } else if ((addr >= cmu) && (addr < (cmu + sizeof(g_ut.cmu)))) {
        g_ut.cmu[UT_IDX(addr - cmu)] |= value;
    } else {
        ut_fail("write outside the mocked peripherals");
    }
}

/** Register access layer given to the backend. */
static const noxtls_efr32_io_t s_ut_io = { ut_read32, ut_write32 };

void ut_set_caps(uint32_t incl, uint32_t cfg1, uint32_t cfg2)
{
    g_ut.aes[UT_IDX(NOXTLS_EFR32_AES_INCL_IPS_HW_CFG)] = incl;
    g_ut.aes[UT_IDX(NOXTLS_EFR32_AES_BA411E_HW_CFG_1)] = cfg1;
    g_ut.aes[UT_IDX(NOXTLS_EFR32_AES_BA411E_HW_CFG_2)] = cfg2;
    noxtls_efr32_aes_reset();
}

/** Bound lock: AES try-acquire. */
static bool ut_bound_aes_try(void)
{
    g_ut_bound_calls[0]++;
    if (g_ut_bound_aes_busy != 0U) {
        g_ut_bound_aes_busy--;
        return false;
    }
    return true;
}

/** Bound lock: AES release. */
static void ut_bound_aes_rel(void)
{
    g_ut_bound_calls[1]++;
}

/** Bound lock: SE try-acquire. */
static bool ut_bound_se_try(void)
{
    g_ut_bound_calls[2]++;
    if (g_ut_bound_se_busy != 0U) {
        g_ut_bound_se_busy--;
        return false;
    }
    return true;
}

/** Bound lock: SE release. */
static void ut_bound_se_rel(void)
{
    g_ut_bound_calls[3]++;
}

const noxtls_efr32_engine_lock_t *ut_bound_lock(void)
{
    static const noxtls_efr32_engine_lock_t ops = { ut_bound_aes_try, ut_bound_aes_rel, ut_bound_se_try, ut_bound_se_rel };

    return &ops;
}

void ut_sw_begin(void)
{
    (void)noxtls_efr32_flag_op(NOXTLS_EFR32_UNIT_AES, 1U);
    (void)noxtls_efr32_flag_op(NOXTLS_EFR32_UNIT_SE, 1U);
}

void ut_sw_end(void)
{
    (void)noxtls_efr32_flag_op(NOXTLS_EFR32_UNIT_AES, 0U);
    (void)noxtls_efr32_flag_op(NOXTLS_EFR32_UNIT_SE, 0U);
}

void ut_setup(void)
{
    noxtls_efr32_hw_t hw;

    (void)noxtls_efr32_flag_op(NOXTLS_EFR32_UNIT_AES, 0U);
    (void)noxtls_efr32_flag_op(NOXTLS_EFR32_UNIT_SE, 0U);
    (void)noxtls_efr32_engine_lock_bind(NULL);
    (void)memset(&g_ut, 0, sizeof(g_ut));
    (void)memset(&g_ut_ram, 0, sizeof(g_ut_ram));
    g_ut_bound_aes_busy = 0U;
    g_ut_bound_se_busy = 0U;
    (void)memset((void *)g_ut_bound_calls, 0, sizeof(g_ut_bound_calls));
    g_ut.rng_state = 0x1234ABCDU;
    hw.aes = (uintptr_t)g_ut.aes;
    hw.sem = (uintptr_t)g_ut.sem;
    hw.cmu = (uintptr_t)g_ut.cmu;
    (void)noxtls_efr32_io_set(&s_ut_io);
    (void)noxtls_efr32_hw_set(&hw);
    /* Window: the whole 4 GiB region of the test image (stack buffers fall outside and are bounced). */
    noxtls_efr32_set_dma_window((uintptr_t)&g_ut & ~(uintptr_t)UINT32_MAX, (uintptr_t)UINT32_MAX,
                                (uintptr_t)&g_ut & ~(uintptr_t)UINT32_MAX, (uintptr_t)UINT32_MAX, 1U);
    noxtls_efr32_set_enabled(NOXTLS_EFR32_UNIT_ALL, 1U);
    noxtls_efr32_set_ops_disabled(0U);
    noxtls_efr32_se_set_hung(0U);
    noxtls_efr32_reset_stats();
    ut_set_caps(NOXTLS_EFR32_INCL_AES, 0x05010127U, 0x80U);
}
