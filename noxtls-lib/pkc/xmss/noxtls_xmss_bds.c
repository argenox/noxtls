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
* File:    noxtls_xmss_bds.c
* Summary: XMSS subtree passes (TreeHash, RFC 8391 Algorithm 9) and the BDS
*          tree traversal (Buchmann, Dahmen, Schneider, "Merkle Tree Traversal
*          Revisited", PQCrypto 2008) with the XMSS^MT next-tree scheduling of
*          the XMSS reference implementation (xmss_core_fast.c), kept in a
*          caller-supplied byte buffer.
*
*          Differences from xmss_core_fast.c:
*           - the state can be built directly for any index (one pass over the
*             current subtree captures the auth path, Keep, TreeHash and Retain
*             nodes that the traversal would hold at that index), so a signer
*             can (re)attach a traversal without replaying old signatures;
*           - XMSS^MT keeps the roots of the current subtrees (n bytes per
*             layer) instead of cached WOTS+ signatures (len * n per layer);
*             upper-layer WOTS+ signatures are recomputed (and covered by the
*             sign-time self check);
*           - next-tree / current-tree slots are swapped by index, not copied.
*
*****************************************************************************/

#include <stdint.h>

#include "noxtls_xmss_internal.h"
#include "common/noxtls_ct.h"

#if NOXTLS_FEATURE_XMSS && NOXTLS_XMSS_ENABLE_SIGN

/* ---- full subtree pass with node capture ------------------------------- */

static void xmss_capture(const xmss_params_t *p, const xmss_capture_t *cap,
                         uint32_t level, uint32_t index, const uint8_t *node)
{
    uint32_t th = (uint32_t)p->th;
    uint32_t n = (uint32_t)p->n;
    uint32_t s = cap->s;

    if(level >= th) {
        return;
    }
    if((cap->auth != NULL) && (index == ((s >> level) ^ 1U))) {
        xmss_copy(&cap->auth[level * n], node, n);
    }
    if(cap->keep != NULL) {
        /* Keep[level] is live while s mod 2^(level+2) is in [2^level, 2^(level+1)). */
        uint32_t m = s & ((1U << (level + 2U)) - 1U);
        if((level < (th - 1U)) && (m >= (1U << level)) && (m < (1U << (level + 1U))) && (index == (s >> level))) {
            xmss_copy(&cap->keep[(level >> 1U) * n], node, n);
        }
    }
    if((cap->th_node != NULL) && (level < (th - cap->k))) {
        /* TreeHash_level holds node (base >> level) + 3, base = s rounded down to 2^(level+1). */
        uint32_t base = s & ~((1U << (level + 1U)) - 1U);
        if(index == ((base >> level) + 3U)) {
            xmss_copy(&cap->th_node[level * n], node, n);
        }
    }
    if((cap->retain != NULL) && (level >= (th - cap->k)) && (level <= (th - 2U)) && (th >= 2U)) {
        if(((index & 1U) == 1U) && (index >= 3U)) {
            uint32_t off = (1U << (th - 1U - level)) - (th - level);
            xmss_copy(&cap->retain[(off + ((index - 3U) >> 1U)) * n], node, n);
        }
    }
}

noxtls_return_t xmss_tree_pass(const xmss_hctx_t *hc, uint32_t layer, uint64_t tree,
                               const xmss_capture_t *cap, uint8_t *root)
{
    const xmss_params_t *p = hc->p;
    uint32_t n = (uint32_t)p->n;
    uint32_t th = (uint32_t)p->th;
    uint8_t stack[(XMSS_MAX_TREE_HEIGHT + 1U) * NOXTLS_XMSS_MAX_N];
    uint8_t levels[XMSS_MAX_TREE_HEIGHT + 1U];
    uint8_t adrs[XMSS_ADRS_LEN];
    uint32_t sp = 0U;
    uint32_t idx = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    xmss_adrs_init(adrs, layer, tree, XMSS_ADRS_TYPE_HASHTREE);
    for(idx = 0U; (idx < (1U << th)) && (rc == NOXTLS_RETURN_SUCCESS); idx += 1U) {
        rc = xmss_gen_leaf(hc, layer, tree, idx, &stack[sp * n]);
        levels[sp] = 0U;
        sp += 1U;
        if((rc == NOXTLS_RETURN_SUCCESS) && (cap != NULL)) {
            xmss_capture(p, cap, 0U, idx, &stack[(sp - 1U) * n]);
        }
        while((rc == NOXTLS_RETURN_SUCCESS) && (sp >= 2U) && (levels[sp - 1U] == levels[sp - 2U])) {
            uint32_t lv = (uint32_t)levels[sp - 1U];
            uint32_t parent = idx >> (lv + 1U);

            xmss_adrs_set_word(adrs, XMSS_ADRS_W_CHAIN, lv);
            xmss_adrs_set_word(adrs, XMSS_ADRS_W_HASH, parent);
            rc = xmss_thash_h(hc, adrs, &stack[(sp - 2U) * n], &stack[(sp - 1U) * n], &stack[(sp - 2U) * n]);
            sp -= 1U;
            levels[sp - 1U] = (uint8_t)(lv + 1U);
            if((rc == NOXTLS_RETURN_SUCCESS) && (cap != NULL)) {
                xmss_capture(p, cap, lv + 1U, parent, &stack[(sp - 1U) * n]);
            }
        }
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        xmss_copy(root, stack, n);
    }
    return rc;
}

/* ---- BDS state layout --------------------------------------------------- */
/*
 * Buffer = header || roots[(d - 1) * n] || 2d - 1 tree states.
 * header: magic[4] "XBDS" | param[4] | k[1] | valid[1] | rsv[2] | idx[8]
 *         | slot map: cur[d], next[d] (slot number of each layer's current /
 *           next tree state)
 * tree state (all multi-byte fields big-endian):
 *   stackoffset[1] | levels[th + 1] | next_leaf[4]
 *   | treehash meta[(th - k) * 7] = { h, completed, stackusage, next_idx[4] }
 *   | stack[(th + 1) * n] | auth[th * n] | keep[(th / 2) * n]
 *   | th_node[(th - k) * n] | retain[(2^k - k - 1) * n]
 */
#define XMSS_BDS_MAGIC_0 0x58U /* 'X' */
#define XMSS_BDS_MAGIC_1 0x42U /* 'B' */
#define XMSS_BDS_MAGIC_2 0x44U /* 'D' */
#define XMSS_BDS_MAGIC_3 0x53U /* 'S' */
#define XMSS_BDS_HDR_FIXED 20U
#define XMSS_BDS_TH_META 7U

typedef struct
{
    uint8_t *meta;      /* stackoffset */
    uint8_t *levels;
    uint8_t *next_leaf;
    uint8_t *th_meta;
    uint8_t *stack;
    uint8_t *auth;
    uint8_t *keep;
    uint8_t *th_node;
    uint8_t *retain;
} xmss_bds_tree_t;

static uint32_t xmss_bds_retain_nodes(uint32_t k)
{
    return (k == 0U) ? 0U : (((1U << k) - k) - 1U);
}

static uint32_t xmss_bds_tree_len(const xmss_params_t *p, uint32_t k)
{
    uint32_t th = (uint32_t)p->th;
    uint32_t n = (uint32_t)p->n;

    return 1U + (th + 1U) + 4U + ((th - k) * XMSS_BDS_TH_META) +
           (((th + 1U) + th + (th >> 1U) + (th - k) + xmss_bds_retain_nodes(k)) * n);
}

static uint32_t xmss_bds_hdr_len(const xmss_params_t *p)
{
    return XMSS_BDS_HDR_FIXED + (2U * (uint32_t)p->d) + (((uint32_t)p->d - 1U) * (uint32_t)p->n);
}

uint32_t xmss_bds_state_len(const xmss_params_t *p, uint32_t k)
{
    uint32_t th = (uint32_t)p->th;

    if((k > th) || (((th - k) & 1U) != 0U) || (k > 20U)) {
        return 0U;
    }
    return xmss_bds_hdr_len(p) + (((2U * (uint32_t)p->d) - 1U) * xmss_bds_tree_len(p, k));
}

static uint8_t *xmss_bds_roots(const xmss_params_t *p, uint8_t *buf)
{
    return &buf[XMSS_BDS_HDR_FIXED + (2U * (uint32_t)p->d)];
}

static void xmss_bds_view(const xmss_params_t *p, uint32_t k, uint8_t *buf, uint32_t slot, xmss_bds_tree_t *v)
{
    uint32_t th = (uint32_t)p->th;
    uint32_t n = (uint32_t)p->n;
    uint8_t *t = &buf[xmss_bds_hdr_len(p) + (slot * xmss_bds_tree_len(p, k))];

    v->meta = t;
    v->levels = &t[1];
    v->next_leaf = &v->levels[th + 1U];
    v->th_meta = &v->next_leaf[4];
    v->stack = &v->th_meta[(th - k) * XMSS_BDS_TH_META];
    v->auth = &v->stack[(th + 1U) * n];
    v->keep = &v->auth[th * n];
    v->th_node = &v->keep[(th >> 1U) * n];
    v->retain = &v->th_node[(th - k) * n];
}

static uint32_t xmss_bds_slot_cur(const xmss_params_t *p, const uint8_t *buf, uint32_t layer)
{
    (void)p;
    return (uint32_t)buf[XMSS_BDS_HDR_FIXED + layer];
}

static uint32_t xmss_bds_slot_next(const xmss_params_t *p, const uint8_t *buf, uint32_t layer)
{
    return (uint32_t)buf[XMSS_BDS_HDR_FIXED + (uint32_t)p->d + layer];
}

/* Treehash instance meta accessors. */
static uint8_t *xmss_bds_th(const xmss_bds_tree_t *v, uint32_t j)
{
    return &v->th_meta[j * XMSS_BDS_TH_META];
}

static uint32_t xmss_bds_th_next_idx(const xmss_bds_tree_t *v, uint32_t j)
{
    return (uint32_t)xmss_load_be(&xmss_bds_th(v, j)[3], 4U);
}

static void xmss_bds_th_set(const xmss_bds_tree_t *v, uint32_t j, uint32_t h, uint32_t completed,
                            uint32_t stackusage, uint32_t next_idx)
{
    uint8_t *m = xmss_bds_th(v, j);

    m[0] = (uint8_t)h;
    m[1] = (uint8_t)completed;
    m[2] = (uint8_t)stackusage;
    xmss_store_be(&m[3], 4U, (uint64_t)next_idx);
}

/* Reset a tree state to "empty, all treehash instances completed". */
static void xmss_bds_tree_reset(const xmss_params_t *p, uint32_t k, const xmss_bds_tree_t *v)
{
    uint32_t j = 0U;

    v->meta[0] = 0U;
    xmss_store_be(v->next_leaf, 4U, 0U);
    for(j = 0U; j < ((uint32_t)p->th - k); j += 1U) {
        xmss_bds_th_set(v, j, j, 1U, 0U, 0U);
    }
}

/* ---- BDS algorithm (ported from xmss_core_fast.c) ---------------------- */

static uint32_t xmss_bds_minheight(const xmss_params_t *p, const xmss_bds_tree_t *v, uint32_t usage)
{
    uint32_t r = (uint32_t)p->th;
    uint32_t off = (uint32_t)v->meta[0];
    uint32_t i = 0U;

    for(i = 0U; (i < usage) && (i < off); i += 1U) {
        if((uint32_t)v->levels[off - i - 1U] < r) {
            r = (uint32_t)v->levels[off - i - 1U];
        }
    }
    return r;
}

/* One leaf of treehash instance j (its nodes are on top of the shared stack). */
static noxtls_return_t xmss_bds_th_update(const xmss_hctx_t *hc, uint32_t layer, uint64_t tree,
                                          const xmss_bds_tree_t *v, uint32_t j)
{
    const xmss_params_t *p = hc->p;
    uint32_t n = (uint32_t)p->n;
    uint8_t *m = xmss_bds_th(v, j);
    uint32_t next_idx = xmss_bds_th_next_idx(v, j);
    uint32_t usage = (uint32_t)m[2];
    uint32_t off = (uint32_t)v->meta[0];
    uint32_t height = 0U;
    uint8_t buf[2U * NOXTLS_XMSS_MAX_N];
    uint8_t adrs[XMSS_ADRS_LEN];
    noxtls_return_t rc = xmss_gen_leaf(hc, layer, tree, next_idx, buf);

    xmss_adrs_init(adrs, layer, tree, XMSS_ADRS_TYPE_HASHTREE);
    while((rc == NOXTLS_RETURN_SUCCESS) && (usage > 0U) && (off > 0U) && ((uint32_t)v->levels[off - 1U] == height)) {
        xmss_copy(&buf[n], buf, n);
        xmss_copy(buf, &v->stack[(off - 1U) * n], n);
        xmss_adrs_set_word(adrs, XMSS_ADRS_W_CHAIN, height);
        xmss_adrs_set_word(adrs, XMSS_ADRS_W_HASH, next_idx >> (height + 1U));
        rc = xmss_thash_h(hc, adrs, buf, &buf[n], buf);
        height += 1U;
        usage -= 1U;
        off -= 1U;
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(height == (uint32_t)m[0]) {
        xmss_copy(&v->th_node[j * n], buf, n);
        m[1] = 1U;
    } else {
        if(off > (uint32_t)p->th) {
            return NOXTLS_RETURN_FAILED;
        }
        xmss_copy(&v->stack[off * n], buf, n);
        usage += 1U;
        v->levels[off] = (uint8_t)height;
        off += 1U;
        xmss_store_be(&m[3], 4U, (uint64_t)next_idx + 1U);
    }
    m[2] = (uint8_t)usage;
    v->meta[0] = (uint8_t)off;
    return NOXTLS_RETURN_SUCCESS;
}

/* Spend up to `updates` leaf computations on the neediest instances; returns the unused budget. */
static noxtls_return_t xmss_bds_th_updates(const xmss_hctx_t *hc, uint32_t layer, uint64_t tree,
                                           const xmss_bds_tree_t *v, uint32_t k, uint32_t *updates)
{
    const xmss_params_t *p = hc->p;
    uint32_t th = (uint32_t)p->th;
    uint32_t inst = th - k;
    uint32_t used = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    while((used < *updates) && (rc == NOXTLS_RETURN_SUCCESS)) {
        uint32_t l_min = th;
        uint32_t level = inst;
        uint32_t i = 0U;

        for(i = 0U; i < inst; i += 1U) {
            const uint8_t *m = xmss_bds_th(v, i);
            uint32_t low = 0U;

            if(m[1] != 0U) {
                low = th;
            } else if(m[2] == 0U) {
                low = i;
            } else {
                low = xmss_bds_minheight(p, v, (uint32_t)m[2]);
            }
            if(low < l_min) {
                level = i;
                l_min = low;
            }
        }
        if(level == inst) {
            break;
        }
        rc = xmss_bds_th_update(hc, layer, tree, v, level);
        used += 1U;
    }
    *updates -= used;
    return rc;
}

/*
 * Auth path for leaf_idx + 1 from the state for leaf_idx (BDS round,
 * Algorithm 4.6 of Buchmann/Dahmen/Szydlo with Keep compressed to th/2 slots).
 */
static noxtls_return_t xmss_bds_round(const xmss_hctx_t *hc, uint32_t layer, uint64_t tree,
                                      const xmss_bds_tree_t *v, uint32_t k, uint32_t leaf_idx)
{
    const xmss_params_t *p = hc->p;
    uint32_t n = (uint32_t)p->n;
    uint32_t th = (uint32_t)p->th;
    uint32_t tau = th;
    uint32_t i = 0U;
    uint8_t buf[2U * NOXTLS_XMSS_MAX_N];
    uint8_t adrs[XMSS_ADRS_LEN];
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    for(i = 0U; i < th; i += 1U) {
        if(((leaf_idx >> i) & 1U) == 0U) {
            tau = i;
            break;
        }
    }
    if(tau >= th) {
        return NOXTLS_RETURN_FAILED; /* last leaf: no next auth path */
    }
    if(tau > 0U) {
        xmss_copy(buf, &v->auth[(tau - 1U) * n], n);
        /* read Keep before it may be overwritten below */
        xmss_copy(&buf[n], &v->keep[((tau - 1U) >> 1U) * n], n);
    }
    if((((leaf_idx >> (tau + 1U)) & 1U) == 0U) && (tau < (th - 1U))) {
        xmss_copy(&v->keep[(tau >> 1U) * n], &v->auth[tau * n], n);
    }
    if(tau == 0U) {
        rc = xmss_gen_leaf(hc, layer, tree, leaf_idx, v->auth);
    } else {
        xmss_adrs_init(adrs, layer, tree, XMSS_ADRS_TYPE_HASHTREE);
        xmss_adrs_set_word(adrs, XMSS_ADRS_W_CHAIN, tau - 1U);
        xmss_adrs_set_word(adrs, XMSS_ADRS_W_HASH, leaf_idx >> tau);
        rc = xmss_thash_h(hc, adrs, buf, &buf[n], &v->auth[tau * n]);
        for(i = 0U; (i < tau) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
            if(i < (th - k)) {
                if(xmss_bds_th(v, i)[1] == 0U) {
                    rc = NOXTLS_RETURN_FAILED; /* treehash instance late: never use a wrong node */
                } else {
                    xmss_copy(&v->auth[i * n], &v->th_node[i * n], n);
                }
            } else {
                uint32_t off = (1U << (th - 1U - i)) - (th - i);
                uint32_t row = ((leaf_idx >> i) - 1U) >> 1U;
                xmss_copy(&v->auth[i * n], &v->retain[(off + row) * n], n);
            }
        }
        for(i = 0U; (i < tau) && (i < (th - k)); i += 1U) {
            uint32_t start = leaf_idx + 1U + (3U << i);
            if(start < (1U << th)) {
                xmss_bds_th_set(v, i, i, 0U, 0U, start);
            }
        }
    }
    return rc;
}

/* Add the next leaf of an incrementally built (next) tree; *done = 1 once complete. */
static noxtls_return_t xmss_bds_build_step(const xmss_hctx_t *hc, uint32_t layer, uint64_t tree,
                                           const xmss_bds_tree_t *v, uint32_t k, uint32_t *done)
{
    const xmss_params_t *p = hc->p;
    uint32_t n = (uint32_t)p->n;
    uint32_t th = (uint32_t)p->th;
    uint32_t idx = (uint32_t)xmss_load_be(v->next_leaf, 4U);
    uint32_t off = (uint32_t)v->meta[0];
    uint8_t adrs[XMSS_ADRS_LEN];
    xmss_capture_t cap;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    *done = 0U;
    if(idx >= (1U << th)) {
        *done = 1U;
        return NOXTLS_RETURN_SUCCESS;
    }
    if(off > th) {
        return NOXTLS_RETURN_FAILED;
    }
    cap.s = 0U;
    cap.auth = v->auth;
    cap.keep = NULL;
    cap.th_node = v->th_node;
    cap.retain = v->retain;
    cap.k = k;
    rc = xmss_gen_leaf(hc, layer, tree, idx, &v->stack[off * n]);
    v->levels[off] = 0U;
    off += 1U;
    if(rc == NOXTLS_RETURN_SUCCESS) {
        xmss_capture(p, &cap, 0U, idx, &v->stack[(off - 1U) * n]);
    }
    xmss_adrs_init(adrs, layer, tree, XMSS_ADRS_TYPE_HASHTREE);
    while((rc == NOXTLS_RETURN_SUCCESS) && (off >= 2U) && (v->levels[off - 1U] == v->levels[off - 2U])) {
        uint32_t lv = (uint32_t)v->levels[off - 1U];
        uint32_t parent = idx >> (lv + 1U);

        xmss_adrs_set_word(adrs, XMSS_ADRS_W_CHAIN, lv);
        xmss_adrs_set_word(adrs, XMSS_ADRS_W_HASH, parent);
        rc = xmss_thash_h(hc, adrs, &v->stack[(off - 2U) * n], &v->stack[(off - 1U) * n], &v->stack[(off - 2U) * n]);
        off -= 1U;
        v->levels[off - 1U] = (uint8_t)(lv + 1U);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            xmss_capture(p, &cap, lv + 1U, parent, &v->stack[(off - 1U) * n]);
        }
    }
    v->meta[0] = (uint8_t)off;
    xmss_store_be(v->next_leaf, 4U, (uint64_t)idx + 1U);
    if((idx + 1U) == (1U << th)) {
        *done = 1U;
    }
    return rc;
}

/* Canonical state of one tree ready to sign leaf s; returns its root. */
static noxtls_return_t xmss_bds_tree_init(const xmss_hctx_t *hc, uint32_t layer, uint64_t tree,
                                          const xmss_bds_tree_t *v, uint32_t k, uint32_t s, uint8_t *root)
{
    xmss_capture_t cap;

    xmss_bds_tree_reset(hc->p, k, v);
    cap.s = s;
    cap.auth = v->auth;
    cap.keep = v->keep;
    cap.th_node = v->th_node;
    cap.retain = v->retain;
    cap.k = k;
    return xmss_tree_pass(hc, layer, tree, &cap, root);
}

/* Complete next tree (as if built leaf by leaf); its root is left in stack[0]. */
static noxtls_return_t xmss_bds_next_init(const xmss_hctx_t *hc, uint32_t layer, uint64_t tree,
                                          const xmss_bds_tree_t *v, uint32_t k)
{
    noxtls_return_t rc = xmss_bds_tree_init(hc, layer, tree, v, k, 0U, v->stack);

    if(rc == NOXTLS_RETURN_SUCCESS) {
        v->meta[0] = 1U;
        v->levels[0] = hc->p->th;
        xmss_store_be(v->next_leaf, 4U, 1ULL << hc->p->th);
    }
    return rc;
}

noxtls_return_t xmss_bds_init(const xmss_hctx_t *hc, uint8_t *buf, uint32_t buf_len, uint32_t k, uint64_t idx,
                              uint8_t *top_root)
{
    const xmss_params_t *p = hc->p;
    uint32_t th = (uint32_t)p->th;
    uint32_t d = (uint32_t)p->d;
    uint32_t n = (uint32_t)p->n;
    uint32_t mask = (1U << th) - 1U;
    uint8_t root[NOXTLS_XMSS_MAX_N];
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t need = xmss_bds_state_len(p, k);

    if((need == 0U) || (buf_len < need)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    noxtls_secure_zero(buf, need);
    buf[0] = XMSS_BDS_MAGIC_0;
    buf[1] = XMSS_BDS_MAGIC_1;
    buf[2] = XMSS_BDS_MAGIC_2;
    buf[3] = XMSS_BDS_MAGIC_3;
    xmss_store_be(&buf[4], 4U, (uint64_t)p->id);
    buf[8] = (uint8_t)k;
    for(i = 0U; i < d; i += 1U) {
        buf[XMSS_BDS_HDR_FIXED + i] = (uint8_t)i;
        buf[XMSS_BDS_HDR_FIXED + d + i] = (i < (d - 1U)) ? (uint8_t)(d + i) : 0U; /* top layer: no next tree */
    }
    for(i = 0U; i < ((2U * d) - 1U); i += 1U) {
        xmss_bds_tree_t v;

        xmss_bds_view(p, k, buf, i, &v);
        xmss_bds_tree_reset(p, k, &v);
    }
    for(i = 0U; (i < d) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        xmss_bds_tree_t v;
        uint64_t tree = idx >> (th * (i + 1U));
        uint32_t s = (uint32_t)(idx >> (th * i)) & mask;

        xmss_bds_view(p, k, buf, i, &v);
        rc = xmss_bds_tree_init(hc, i, tree, &v, k, s, root);
        if((rc == NOXTLS_RETURN_SUCCESS) && (i == (d - 1U))) {
            xmss_copy(top_root, root, n);
        }
        if((rc == NOXTLS_RETURN_SUCCESS) && (i < (d - 1U))) {
            xmss_copy(&xmss_bds_roots(p, buf)[i * n], root, n);
            /* Next tree of this layer, if the layer has one. */
            if((tree + 1U) < (1ULL << ((uint32_t)p->h - (th * (i + 1U))))) {
                xmss_bds_view(p, k, buf, d + i, &v);
                rc = xmss_bds_next_init(hc, i, tree + 1U, &v, k);
            }
        }
    }
    noxtls_secure_zero(root, sizeof(root));
    if(rc == NOXTLS_RETURN_SUCCESS) {
        xmss_store_be(&buf[12], 8U, idx);
        buf[9] = 1U;
    } else {
        buf[9] = 0U;
    }
    return rc;
}

/* Check that buf holds a valid state for this key and index. */
static noxtls_return_t xmss_bds_check(const xmss_params_t *p, const uint8_t *buf, uint64_t idx, uint32_t *k)
{
    uint32_t i = 0U;
    uint32_t d = (uint32_t)p->d;

    if((buf[0] != XMSS_BDS_MAGIC_0) || (buf[1] != XMSS_BDS_MAGIC_1) || (buf[2] != XMSS_BDS_MAGIC_2) ||
       (buf[3] != XMSS_BDS_MAGIC_3) || (buf[9] != 1U) || ((uint32_t)xmss_load_be(&buf[4], 4U) != p->id) ||
       (xmss_load_be(&buf[12], 8U) != idx)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    *k = (uint32_t)buf[8];
    if(xmss_bds_state_len(p, *k) == 0U) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    for(i = 0U; i < (2U * d); i += 1U) {
        if((uint32_t)buf[XMSS_BDS_HDR_FIXED + i] >= ((2U * d) - 1U)) {
            return NOXTLS_RETURN_BAD_DATA;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

/* Bounds of every index-like field of every tree state (the buffer is caller memory). */
static noxtls_return_t xmss_bds_check_trees(const xmss_params_t *p, uint8_t *buf, uint32_t k)
{
    uint32_t th = (uint32_t)p->th;
    uint32_t slot = 0U;
    uint32_t j = 0U;
    xmss_bds_tree_t v;

    for(slot = 0U; slot < ((2U * (uint32_t)p->d) - 1U); slot += 1U) {
        xmss_bds_view(p, k, buf, slot, &v);
        if(((uint32_t)v.meta[0] > (th + 1U)) || (xmss_load_be(v.next_leaf, 4U) > (1ULL << th))) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        for(j = 0U; j < (th + 1U); j += 1U) {
            if((uint32_t)v.levels[j] > th) {
                return NOXTLS_RETURN_BAD_DATA;
            }
        }
        for(j = 0U; j < (th - k); j += 1U) {
            const uint8_t *m = xmss_bds_th(&v, j);
            if(((uint32_t)m[0] != j) || ((uint32_t)m[1] > 1U) || ((uint32_t)m[2] > (uint32_t)v.meta[0]) ||
               (xmss_bds_th_next_idx(&v, j) >= (1U << th))) {
                return NOXTLS_RETURN_BAD_DATA;
            }
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t xmss_bds_get(const xmss_hctx_t *hc, uint8_t *buf, uint32_t layer, uint64_t idx,
                             uint8_t *auth, uint8_t *root)
{
    const xmss_params_t *p = hc->p;
    uint32_t k = 0U;
    xmss_bds_tree_t v;
    noxtls_return_t rc = xmss_bds_check(p, buf, idx, &k);

    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = xmss_bds_check_trees(p, buf, k);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    xmss_bds_view(p, k, buf, xmss_bds_slot_cur(p, buf, layer), &v);
    xmss_copy(auth, v.auth, (uint32_t)p->th * (uint32_t)p->n);
    if((root != NULL) && (layer < ((uint32_t)p->d - 1U))) {
        xmss_copy(root, &xmss_bds_roots(p, buf)[layer * (uint32_t)p->n], p->n);
    }
    return NOXTLS_RETURN_SUCCESS;
}

/* Finish the next tree of a layer synchronously (only if the schedule fell behind). */
static noxtls_return_t xmss_bds_finish_next(const xmss_hctx_t *hc, uint32_t layer, uint64_t tree,
                                            const xmss_bds_tree_t *v, uint32_t k)
{
    uint32_t done = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    while((done == 0U) && (rc == NOXTLS_RETURN_SUCCESS)) {
        rc = xmss_bds_build_step(hc, layer, tree, v, k, &done);
    }
    return rc;
}

noxtls_return_t xmss_bds_advance(const xmss_hctx_t *hc, uint8_t *buf, uint64_t idx)
{
    const xmss_params_t *p = hc->p;
    uint32_t th = (uint32_t)p->th;
    uint32_t d = (uint32_t)p->d;
    uint32_t n = (uint32_t)p->n;
    uint32_t h = (uint32_t)p->h;
    uint64_t mask = (1ULL << th) - 1U;
    uint32_t k = 0U;
    uint32_t updates = 0U;
    uint32_t i = 0U;
    uint32_t done = 0U;
    int32_t swapped_upto = -1;
    xmss_bds_tree_t v;
    noxtls_return_t rc = xmss_bds_check(p, buf, idx, &k);

    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = xmss_bds_check_trees(p, buf, k);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    buf[9] = 0U; /* invalid until the update completes */
    if(idx >= ((1ULL << h) - 1U)) {
        return NOXTLS_RETURN_SUCCESS; /* key exhausted after this signature: nothing to prepare */
    }
    updates = (th - k) >> 1U;

    /* Mandatory step of the layer-0 next tree (one leaf per signature). */
    if((d > 1U) && ((((idx >> th) + 1U) << th) + (idx & mask) < (1ULL << h))) {
        xmss_bds_view(p, k, buf, xmss_bds_slot_next(p, buf, 0U), &v);
        rc = xmss_bds_build_step(hc, 0U, (idx >> th) + 1U, &v, k, &done);
    }

    for(i = 0U; (i < d) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        uint64_t idx_tree = idx >> (th * (i + 1U));
        uint32_t idx_leaf = (uint32_t)((idx >> (th * i)) & mask);
        uint64_t layer_mask = (1ULL << (th * (i + 1U))) - 1U; /* th * d <= 60 */

        if(((idx + 1U) & layer_mask) != 0U) {
            /* Current tree of layer i continues. */
            xmss_bds_view(p, k, buf, xmss_bds_slot_cur(p, buf, i), &v);
            if((int32_t)i == (swapped_upto + 1)) {
                rc = xmss_bds_round(hc, i, idx_tree, &v, k, idx_leaf);
            }
            if(rc == NOXTLS_RETURN_SUCCESS) {
                rc = xmss_bds_th_updates(hc, i, idx_tree, &v, k, &updates);
            }
            if((rc == NOXTLS_RETURN_SUCCESS) && (i > 0U) && (updates > 0U) && (i < (d - 1U)) &&
               ((idx_tree + 1U) < (1ULL << (h - (th * (i + 1U)))))) {
                xmss_bds_view(p, k, buf, xmss_bds_slot_next(p, buf, i), &v);
                if(xmss_load_be(v.next_leaf, 4U) < (1ULL << th)) {
                    rc = xmss_bds_build_step(hc, i, idx_tree + 1U, &v, k, &done);
                    updates -= 1U;
                }
            }
        } else {
            /* Tree of layer i is finished: its next tree becomes current. */
            uint32_t cur = xmss_bds_slot_cur(p, buf, i);
            uint32_t nxt = xmss_bds_slot_next(p, buf, i);
            uint32_t j = 0U;

            if(i >= (d - 1U)) {
                rc = NOXTLS_RETURN_FAILED; /* top tree cannot end before the key */
                break;
            }
            xmss_bds_view(p, k, buf, nxt, &v);
            rc = xmss_bds_finish_next(hc, i, idx_tree + 1U, &v, k);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                xmss_copy(&xmss_bds_roots(p, buf)[i * n], v.stack, n);
                v.meta[0] = 0U;
                for(j = 0U; j < (th - k); j += 1U) {
                    xmss_bds_th_set(&v, j, j, 1U, 0U, 0U);
                }
                buf[XMSS_BDS_HDR_FIXED + i] = (uint8_t)nxt;
                buf[XMSS_BDS_HDR_FIXED + d + i] = (uint8_t)cur;
                xmss_bds_view(p, k, buf, cur, &v);
                xmss_bds_tree_reset(p, k, &v);
                swapped_upto = (int32_t)i;
                if(updates > 0U) {
                    updates -= 1U; /* the upper-layer WOTS+ signature counts as one update */
                }
            }
        }
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        xmss_store_be(&buf[12], 8U, idx + 1U);
        buf[9] = 1U;
    }
    return rc;
}

#endif /* NOXTLS_FEATURE_XMSS && NOXTLS_XMSS_ENABLE_SIGN */
