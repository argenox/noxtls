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
* File:    noxtls_xmss_internal.h
* Summary: XMSS / XMSS^MT internals shared by the module's translation units
*          (parameters, hash address, tweakable hashes, WOTS+, trees, BDS).
*
*****************************************************************************/

#ifndef NOXTLS_XMSS_INTERNAL_H_
#define NOXTLS_XMSS_INTERNAL_H_

#include <stdint.h>
#include "noxtls_xmss.h"

#if NOXTLS_FEATURE_XMSS

#ifdef __cplusplus
extern "C" {
#endif

#define XMSS_W 16U
#define XMSS_LOG_W 4U
#define XMSS_LEN2 3U                 /* checksum chains for n = 24 / 32 / 64 and w = 16 */
#define XMSS_ADRS_LEN 32U
#define XMSS_MAX_LEN ((8U * NOXTLS_XMSS_MAX_N / XMSS_LOG_W) + XMSS_LEN2)
#define XMSS_MAX_TREE_HEIGHT 20U     /* largest h / d over all RFC 8391 sets */
#define XMSS_MAX_LAYERS 12U
/* L-tree accumulator depth: floor(log2(len)) + 1 entries (len <= 131). */
#define XMSS_LTREE_STACK 8U

/* Hash address types (RFC 8391 Section 2.5). */
#define XMSS_ADRS_TYPE_OTS 0U
#define XMSS_ADRS_TYPE_LTREE 1U
#define XMSS_ADRS_TYPE_HASHTREE 2U

/* toByte(X, pad) domain separators (RFC 8391 Section 5.1). */
#define XMSS_PAD_F 0U
#define XMSS_PAD_H 1U
#define XMSS_PAD_HASH 2U
#define XMSS_PAD_PRF 3U
#define XMSS_PAD_PRF_KEYGEN 4U

/** Resolved parameter set. */
typedef struct
{
    noxtls_xmss_param_t id;
    uint32_t oid;
    uint32_t sig_len;
    uint32_t pk_len;
    uint32_t sk_len;
    uint8_t is_mt;
    uint8_t hash;        /* NOXTLS_XMSS_HASH_* */
    uint8_t n;
    uint8_t pad;         /* toByte() padding length: n, or 4 for n = 24 (SP 800-208) */
    uint8_t h;
    uint8_t d;
    uint8_t th;          /* tree height h / d */
    uint8_t len1;
    uint8_t len;
    uint8_t idx_bytes;
    uint8_t sp800_208;
} xmss_params_t;

/** Look up an enabled parameter set; returns NULL when unsupported. */
const xmss_params_t *xmss_params_get(noxtls_xmss_param_t param, xmss_params_t *out);

/* ---- hash address (32 bytes, big-endian words) ------------------------- */
void xmss_adrs_set_word(uint8_t adrs[XMSS_ADRS_LEN], uint32_t word, uint32_t value);
void xmss_adrs_set_tree(uint8_t adrs[XMSS_ADRS_LEN], uint64_t tree);
/** Set layer/tree/type and clear words 4..7. */
void xmss_adrs_init(uint8_t adrs[XMSS_ADRS_LEN], uint32_t layer, uint64_t tree, uint32_t type);

#define XMSS_ADRS_W_LAYER 0U
#define XMSS_ADRS_W_TYPE 3U
#define XMSS_ADRS_W_OTS 4U          /* OTS address / L-tree address */
#define XMSS_ADRS_W_CHAIN 5U        /* chain address / tree height */
#define XMSS_ADRS_W_HASH 6U         /* hash address / tree index */
#define XMSS_ADRS_W_KEYMASK 7U

/* ---- tweakable hash functions ----------------------------------------- */

/**
 * Hash context of one key: PUB_SEED (and SK_SEED for signing) plus SHA-2
 * midstates of the constant first block of PRF(PUB_SEED, .) and
 * PRF_keygen(SK_SEED, .) when pad + n equals the hash block size.
 */
typedef struct
{
    const xmss_params_t *p;
    const uint8_t *pub_seed;
    const uint8_t *sk_seed;
#if NOXTLS_XMSS_HAVE_SHA512
    uint64_t prf_mid[8];
    uint64_t kg_mid[8];
#else
    uint32_t prf_mid[8];
    uint32_t kg_mid[8];
#endif
    uint8_t prf_mid_ok;
    uint8_t kg_mid_ok;
} xmss_hctx_t;

noxtls_return_t xmss_hctx_init(xmss_hctx_t *hc, const xmss_params_t *p, const uint8_t *pub_seed, const uint8_t *sk_seed);
void xmss_hctx_wipe(xmss_hctx_t *hc);

/** out = F(PUB_SEED, ADRS, in) (thash_f, Algorithm 2 inner step). adrs is modified (keyAndMask). */
noxtls_return_t xmss_thash_f(const xmss_hctx_t *hc, uint8_t adrs[XMSS_ADRS_LEN], const uint8_t *in, uint8_t *out);
/** out = RAND_HASH(left, right, PUB_SEED, ADRS) (Algorithm 7). out may alias left or right. */
noxtls_return_t xmss_thash_h(const xmss_hctx_t *hc, uint8_t adrs[XMSS_ADRS_LEN],
                             const uint8_t *left, const uint8_t *right, uint8_t *out);
/** out = PRF_keygen(SK_SEED, PUB_SEED || ADRS) (SP 800-208 WOTS+ secret key element). */
noxtls_return_t xmss_prf_keygen(const xmss_hctx_t *hc, const uint8_t adrs[XMSS_ADRS_LEN], uint8_t *out);
/** out = PRF(key, toByte(idx, 32)) (randomizer r). */
noxtls_return_t xmss_prf_idx(const xmss_params_t *p, const uint8_t *key, uint64_t idx, uint8_t *out);

/** Start H_msg(r || root || toByte(idx, n), M) (RFC 8391 Section 5.1). */
noxtls_return_t xmss_hmsg_init(noxtls_xmss_hash_state_t *hs, const xmss_params_t *p,
                               const uint8_t *r, const uint8_t *root, uint64_t idx);
noxtls_return_t xmss_hmsg_update(noxtls_xmss_hash_state_t *hs, const uint8_t *data, uint32_t len);
noxtls_return_t xmss_hmsg_final(noxtls_xmss_hash_state_t *hs, const xmss_params_t *p, uint8_t *out);

/* ---- WOTS+ and trees --------------------------------------------------- */

/** Streaming L-tree (Algorithm 8) over the len WOTS+ public key elements. */
typedef struct
{
    uint8_t node[XMSS_LTREE_STACK][NOXTLS_XMSS_MAX_N];
    uint8_t level[XMSS_LTREE_STACK];
    uint8_t index[XMSS_LTREE_STACK];
    uint8_t top;
    uint8_t count;
} xmss_ltree_t;

/** Message digits (base_w of msg || checksum) for chain i. */
uint32_t xmss_wots_digit(const xmss_params_t *p, const uint8_t *msg, uint32_t csum, uint32_t i);
/** WOTS+ checksum of msg. */
uint32_t xmss_wots_checksum(const xmss_params_t *p, const uint8_t *msg);

/** Compute the leaf (L-tree root of the WOTS+ public key) of key pair `leaf`. */
noxtls_return_t xmss_gen_leaf(const xmss_hctx_t *hc, uint32_t layer, uint64_t tree, uint32_t leaf, uint8_t *out);
/** WOTS+ signature of an n-byte message with key pair `leaf`, written to sig (len * n bytes). */
noxtls_return_t xmss_wots_sign(const xmss_hctx_t *hc, uint32_t layer, uint64_t tree, uint32_t leaf,
                               const uint8_t *msg, uint8_t *sig);
/**
 * Root of a subtree from a WOTS+ signature on msg and its authentication path
 * (Algorithm 13).  sig points at sig_ots || auth.
 */
noxtls_return_t xmss_root_from_sig(const xmss_hctx_t *hc, uint32_t layer, uint64_t tree, uint32_t leaf,
                                   const uint8_t *msg, const uint8_t *sig, uint8_t *root);

#if NOXTLS_XMSS_ENABLE_SIGN

/**
 * Optional node capture during a full subtree pass: auth path of leaf s and,
 * for the BDS state, the canonical keep / treehash / retain nodes.
 */
typedef struct
{
    uint32_t s;
    uint8_t *auth;            /* th nodes, or NULL */
    uint8_t *keep;            /* (th / 2) nodes, or NULL */
    uint8_t *th_node;         /* (th - k) nodes, or NULL */
    uint8_t *retain;          /* (2^k - k - 1) nodes, or NULL */
    uint32_t k;
} xmss_capture_t;

/**
 * Treehash over all 2^th leaves of subtree (layer, tree) with a bounded stack
 * ((th + 1) nodes), returning the root and capturing nodes per cap.
 */
noxtls_return_t xmss_tree_pass(const xmss_hctx_t *hc, uint32_t layer, uint64_t tree,
                               const xmss_capture_t *cap, uint8_t *root);

/* ---- BDS traversal state ----------------------------------------------- */
uint32_t xmss_bds_state_len(const xmss_params_t *p, uint32_t k);
noxtls_return_t xmss_bds_init(const xmss_hctx_t *hc, uint8_t *buf, uint32_t buf_len, uint32_t k, uint64_t idx,
                              uint8_t *top_root);
/** Copy the auth path of layer `layer` (th nodes) and, for layer < d-1, its tree root. */
noxtls_return_t xmss_bds_get(const xmss_hctx_t *hc, uint8_t *buf, uint32_t layer, uint64_t idx,
                             uint8_t *auth, uint8_t *root);
/** Advance the traversal after signing index idx. */
noxtls_return_t xmss_bds_advance(const xmss_hctx_t *hc, uint8_t *buf, uint64_t idx);

#endif /* NOXTLS_XMSS_ENABLE_SIGN */

/* ---- small helpers ----------------------------------------------------- */
uint64_t xmss_load_be(const uint8_t *in, uint32_t len);
void xmss_store_be(uint8_t *out, uint32_t len, uint64_t v);
void xmss_copy(uint8_t *dst, const uint8_t *src, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_FEATURE_XMSS */

#endif /* NOXTLS_XMSS_INTERNAL_H_ */
