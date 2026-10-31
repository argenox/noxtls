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
* File:    noxtls_xmss_wots.c
* Summary: WOTS+ one-time signatures (RFC 8391 Section 3.1, SP 800-208
*          Section 7.2.1 key derivation), streaming L-tree compression
*          (Algorithm 8) and XMSS_rootFromSig (Algorithm 13).
*
*          The WOTS+ public key is never stored: each chain end is pushed
*          into an L-tree accumulator of floor(log2(len)) + 1 nodes, so a
*          leaf costs 8 * n bytes of stack instead of len * n.
*
*****************************************************************************/

#include <stdint.h>

#include "noxtls_xmss_internal.h"
#include "common/noxtls_ct.h"

#if NOXTLS_FEATURE_XMSS

uint32_t xmss_wots_checksum(const xmss_params_t *p, const uint8_t *msg)
{
    uint32_t csum = 0U;
    uint32_t i = 0U;

    for(i = 0U; i < (uint32_t)p->len1; i += 2U) {
        uint32_t b = (uint32_t)msg[i >> 1U];
        csum += (XMSS_W - 1U) - (b >> 4U);
        csum += (XMSS_W - 1U) - (b & 0x0FU);
    }
    return csum;
}

uint32_t xmss_wots_digit(const xmss_params_t *p, const uint8_t *msg, uint32_t csum, uint32_t i)
{
    if(i < (uint32_t)p->len1) {
        uint32_t b = (uint32_t)msg[i >> 1U];
        return ((i & 1U) == 0U) ? (b >> 4U) : (b & 0x0FU);
    }
    /*
     * csum << (8 - ((len2 * lg(w)) % 8)) encoded in ceil(12 / 8) = 2 bytes and
     * read as 3 base-16 digits, most significant first.
     */
    return (csum >> (8U - (4U * (i - (uint32_t)p->len1)))) & 0x0FU;
}

/* x <- chain(x, start, steps) (Algorithm 2); adrs is an OTS address with the chain set. */
static noxtls_return_t xmss_chain(const xmss_hctx_t *hc, uint8_t adrs[XMSS_ADRS_LEN],
                                  uint8_t *x, uint32_t start, uint32_t steps)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t j = 0U;

    if((start + steps) > (XMSS_W - 1U)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    for(j = start; (j < (start + steps)) && (rc == NOXTLS_RETURN_SUCCESS); j += 1U) {
        xmss_adrs_set_word(adrs, XMSS_ADRS_W_HASH, j);
        rc = xmss_thash_f(hc, adrs, x, x);
    }
    return rc;
}

/* WOTS+ secret key element i (SP 800-208: PRF_keygen(SK_SEED, PUB_SEED || ADRS)). */
static noxtls_return_t xmss_wots_sk(const xmss_hctx_t *hc, uint8_t adrs[XMSS_ADRS_LEN], uint32_t i, uint8_t *out)
{
    xmss_adrs_set_word(adrs, XMSS_ADRS_W_CHAIN, i);
    xmss_adrs_set_word(adrs, XMSS_ADRS_W_HASH, 0U);
    xmss_adrs_set_word(adrs, XMSS_ADRS_W_KEYMASK, 0U);
    return xmss_prf_keygen(hc, adrs, out);
}

static void xmss_ltree_init(xmss_ltree_t *lt)
{
    lt->top = 0U;
    lt->count = 0U;
}

/* Combine left || right at L-tree height `level`, parent index `index`. */
static noxtls_return_t xmss_ltree_hash(const xmss_hctx_t *hc, uint8_t adrs[XMSS_ADRS_LEN],
                                       uint32_t level, uint32_t index, const uint8_t *left,
                                       const uint8_t *right, uint8_t *out)
{
    xmss_adrs_set_word(adrs, XMSS_ADRS_W_CHAIN, level);
    xmss_adrs_set_word(adrs, XMSS_ADRS_W_HASH, index);
    return xmss_thash_h(hc, adrs, left, right, out);
}

/*
 * Push the next WOTS+ public key element.  Equal-height neighbours are merged
 * immediately (treehash), which yields exactly the pairs of Algorithm 8 for
 * every complete subtree; the odd elements Algorithm 8 lifts unchanged are
 * merged in xmss_ltree_finish().
 */
static noxtls_return_t xmss_ltree_push(const xmss_hctx_t *hc, xmss_ltree_t *lt,
                                       uint8_t adrs[XMSS_ADRS_LEN], const uint8_t *node)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t t = (uint32_t)lt->top;

    if(t >= XMSS_LTREE_STACK) {
        return NOXTLS_RETURN_FAILED;
    }
    xmss_copy(lt->node[t], node, hc->p->n);
    lt->level[t] = 0U;
    lt->index[t] = lt->count;
    t += 1U;
    lt->count = (uint8_t)(lt->count + 1U);
    while((t >= 2U) && (lt->level[t - 1U] == lt->level[t - 2U]) && (rc == NOXTLS_RETURN_SUCCESS)) {
        uint32_t lv = (uint32_t)lt->level[t - 1U];
        uint32_t parent = (uint32_t)lt->index[t - 1U] >> 1U;

        rc = xmss_ltree_hash(hc, adrs, lv, parent, lt->node[t - 2U], lt->node[t - 1U], lt->node[t - 2U]);
        t -= 1U;
        lt->level[t - 1U] = (uint8_t)(lv + 1U);
        lt->index[t - 1U] = (uint8_t)parent;
    }
    lt->top = (uint8_t)t;
    return rc;
}

/*
 * Finish the L-tree.  The remaining stack holds complete subtrees of strictly
 * decreasing height.  In Algorithm 8 the right-most (top) node is lifted to the
 * height of its left neighbour, keeping index >> (levels lifted), and then
 * hashed with it at that height.
 */
static noxtls_return_t xmss_ltree_finish(const xmss_hctx_t *hc, xmss_ltree_t *lt,
                                         uint8_t adrs[XMSS_ADRS_LEN], uint8_t *out)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t t = (uint32_t)lt->top;

    if(t == 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    while((t >= 2U) && (rc == NOXTLS_RETURN_SUCCESS)) {
        uint32_t ln = (uint32_t)lt->level[t - 2U];
        uint32_t in = (uint32_t)lt->index[t - 2U];

        rc = xmss_ltree_hash(hc, adrs, ln, in >> 1U, lt->node[t - 2U], lt->node[t - 1U], lt->node[t - 2U]);
        t -= 1U;
        lt->level[t - 1U] = (uint8_t)(ln + 1U);
        lt->index[t - 1U] = (uint8_t)(in >> 1U);
    }
    xmss_copy(out, lt->node[0], hc->p->n);
    lt->top = 0U;
    return rc;
}

noxtls_return_t xmss_gen_leaf(const xmss_hctx_t *hc, uint32_t layer, uint64_t tree, uint32_t leaf, uint8_t *out)
{
    uint8_t ots[XMSS_ADRS_LEN];
    uint8_t ltr[XMSS_ADRS_LEN];
    uint8_t x[NOXTLS_XMSS_MAX_N];
    xmss_ltree_t lt;
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    xmss_adrs_init(ots, layer, tree, XMSS_ADRS_TYPE_OTS);
    xmss_adrs_set_word(ots, XMSS_ADRS_W_OTS, leaf);
    xmss_adrs_init(ltr, layer, tree, XMSS_ADRS_TYPE_LTREE);
    xmss_adrs_set_word(ltr, XMSS_ADRS_W_OTS, leaf);
    xmss_ltree_init(&lt);
    for(i = 0U; (i < (uint32_t)hc->p->len) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        rc = xmss_wots_sk(hc, ots, i, x);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = xmss_chain(hc, ots, x, 0U, XMSS_W - 1U);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = xmss_ltree_push(hc, &lt, ltr, x);
        }
    }
    noxtls_secure_zero(x, sizeof(x));
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = xmss_ltree_finish(hc, &lt, ltr, out);
    }
    return rc;
}

noxtls_return_t xmss_wots_sign(const xmss_hctx_t *hc, uint32_t layer, uint64_t tree, uint32_t leaf,
                               const uint8_t *msg, uint8_t *sig)
{
    uint8_t ots[XMSS_ADRS_LEN];
    const xmss_params_t *p = hc->p;
    uint32_t csum = xmss_wots_checksum(p, msg);
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    xmss_adrs_init(ots, layer, tree, XMSS_ADRS_TYPE_OTS);
    xmss_adrs_set_word(ots, XMSS_ADRS_W_OTS, leaf);
    for(i = 0U; (i < (uint32_t)p->len) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        uint8_t *x = &sig[i * (uint32_t)p->n];

        rc = xmss_wots_sk(hc, ots, i, x);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = xmss_chain(hc, ots, x, 0U, xmss_wots_digit(p, msg, csum, i));
        }
    }
    return rc;
}

noxtls_return_t xmss_root_from_sig(const xmss_hctx_t *hc, uint32_t layer, uint64_t tree, uint32_t leaf,
                                   const uint8_t *msg, const uint8_t *sig, uint8_t *root)
{
    uint8_t ots[XMSS_ADRS_LEN];
    uint8_t adrs[XMSS_ADRS_LEN];
    uint8_t x[NOXTLS_XMSS_MAX_N];
    xmss_ltree_t lt;
    const xmss_params_t *p = hc->p;
    uint32_t n = (uint32_t)p->n;
    uint32_t csum = xmss_wots_checksum(p, msg);
    const uint8_t *auth = &sig[(uint32_t)p->len * n];
    uint32_t i = 0U;
    uint32_t k = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    /* WOTS_pkFromSig (Algorithm 6) streamed into the L-tree. */
    xmss_adrs_init(ots, layer, tree, XMSS_ADRS_TYPE_OTS);
    xmss_adrs_set_word(ots, XMSS_ADRS_W_OTS, leaf);
    xmss_adrs_init(adrs, layer, tree, XMSS_ADRS_TYPE_LTREE);
    xmss_adrs_set_word(adrs, XMSS_ADRS_W_OTS, leaf);
    xmss_ltree_init(&lt);
    for(i = 0U; (i < (uint32_t)p->len) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        uint32_t digit = xmss_wots_digit(p, msg, csum, i);

        xmss_copy(x, &sig[i * n], n);
        xmss_adrs_set_word(ots, XMSS_ADRS_W_CHAIN, i);
        rc = xmss_chain(hc, ots, x, digit, (XMSS_W - 1U) - digit);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = xmss_ltree_push(hc, &lt, adrs, x);
        }
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = xmss_ltree_finish(hc, &lt, adrs, x);
    }

    /* Authentication path (Algorithm 13). */
    xmss_adrs_init(adrs, layer, tree, XMSS_ADRS_TYPE_HASHTREE);
    for(k = 0U; (k < (uint32_t)p->th) && (rc == NOXTLS_RETURN_SUCCESS); k += 1U) {
        xmss_adrs_set_word(adrs, XMSS_ADRS_W_CHAIN, k);
        xmss_adrs_set_word(adrs, XMSS_ADRS_W_HASH, leaf >> (k + 1U));
        if(((leaf >> k) & 1U) == 0U) {
            rc = xmss_thash_h(hc, adrs, x, &auth[k * n], x);
        } else {
            rc = xmss_thash_h(hc, adrs, &auth[k * n], x, x);
        }
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        xmss_copy(root, x, n);
    }
    return rc;
}

#endif /* NOXTLS_FEATURE_XMSS */
