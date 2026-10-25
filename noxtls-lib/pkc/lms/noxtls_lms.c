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
* File:    noxtls_lms.c
* Summary: LM-OTS / LMS / HSS (RFC 8554, NIST SP 800-208): streaming
*          verification, key generation and stateful signing with a
*          bounded-memory tree traversal.
*
*****************************************************************************/

#include <stdint.h>
#include <stddef.h>

#include "noxtls_lms.h"
#include "common/noxtls_ct.h"
#include "common/noxtls_memory.h"
#include "drbg/noxtls_drbg.h"
#include "mdigest/sha256/noxtls_sha256.h"
#if NOXTLS_FEATURE_SHA3
#include "mdigest/sha3/noxtls_sha3.h"
#endif

#if NOXTLS_FEATURE_LMS_HSS

#define LMS_HASH_SHA256 1U
#define LMS_HASH_SHAKE 2U
#define LMS_N_MAX 32U
#define LMS_P_MAX 265U
#define LMS_H_MAX 25U
#define LMS_ID_LEN 16U
#define LMS_MAX_SUBLEVELS 25U
/* I || u32str(q) || u16str(i) || u8str(j): the fixed prefix of every chain hash. */
#define LMS_PFX_LEN 23U
#define LMS_D_PBLC 0x8080U
#define LMS_D_MESG 0x8181U
#define LMS_D_LEAF 0x8282U
#define LMS_D_INTR 0x8383U
/* Pseudo-random derivations (RFC 8554 Appendix A style, j = 0xFF). */
#define LMS_D_PRG_C 0xFFFDU
#define LMS_D_CHILD_SEED 0xFFFEU
#define LMS_D_CHILD_I 0xFFFFU
#define LMS_PRG_J 0xFFU
/* Total tree height limit for signing keys (64-bit counter). */
#define LMS_MAX_TOTAL_HEIGHT 63U
/* Keep the signing frames apart (peak stack = largest frame, not their sum). */
#if defined(__GNUC__) || defined(__clang__)
#define LMS_NOINLINE __attribute__((noinline))
#else
#define LMS_NOINLINE
#endif
/* 2^x as a 32-bit value (x <= 26 everywhere it is used). */
#define LMS_BIT(x) ((uint32_t)1U << (x))

/* Private key blob layout (NOXTLS_HSS_PRIVATE_KEY_LEN bytes). */
#define LMS_SK_MAGIC 0x4E584853U /* "NXHS" */
#define LMS_SK_VERSION 1U
#define LMS_SK_OFF_TYPES 8U
#define LMS_SK_OFF_COUNTER 72U
#define LMS_SK_OFF_ID 80U
#define LMS_SK_OFF_SEED 96U
#define LMS_SK_OFF_ROOT 128U
#define LMS_SK_OFF_CHECK 160U
#define LMS_SK_CHECK_LEN 8U

/* Workspace header. */
#define LMS_WS_MAGIC 0x4E58575AU /* "NXWZ" */
#define LMS_WS_VERSION 1U

/* Working key states. */
#define LMS_KEY_STATE_NONE 0U
#define LMS_KEY_STATE_READY 0x4C4D5352U

/* Streaming verify states. */
#define LMS_VCTX_READY 0x4C4D5356U

typedef struct
{
    uint32_t hash;
    uint32_t n;
    uint32_t h;
} lms_tree_param_t;

typedef struct
{
    uint32_t hash;
    uint32_t n;
    uint32_t w;
    uint32_t p;
    uint32_t ls;
} lms_ots_param_t;

/* Scratch state of the signing side (kept off the hot verify path). */
typedef struct
{
    noxtls_lms_hash_t ha;
    noxtls_lms_hash_t hb;
    uint8_t buf[LMS_PFX_LEN + LMS_N_MAX];
    uint8_t q_cksm[LMS_N_MAX + 2U];
    uint8_t node[LMS_N_MAX];
} lms_work_t;

/* Per-tree traversal metadata stored in the workspace (public data only). */
typedef struct
{
    uint32_t next_leaf;                    /* prepared leaf; 2^h when exhausted */
    uint32_t swap;                         /* bit l: buffer B holds sublevel l's active subtree */
    uint32_t progress[LMS_MAX_SUBLEVELS];  /* leaves done for sublevel l's next subtree */
    uint8_t root[LMS_N_MAX];
} lms_tree_meta_t;

typedef struct
{
    uint32_t magic;
    uint32_t version;
    uint32_t len;
    uint32_t subtree;
    uint32_t g_hi;
    uint32_t g_lo;
    uint32_t valid;
    uint8_t binding[32];
} lms_ws_hdr_t;

typedef struct
{
    uint32_t meta_off;
    uint32_t scratch_off;
    uint32_t nodes_off[NOXTLS_HSS_MAX_LEVELS];
    uint32_t spk_off[NOXTLS_HSS_MAX_LEVELS];
    uint32_t spk_len[NOXTLS_HSS_MAX_LEVELS];
    uint32_t total;
} lms_ws_layout_t;

/* View of one LMS tree of a working key. */
typedef struct
{
    lms_tree_param_t tp;
    lms_ots_param_t op;
    uint32_t lms_type;
    uint32_t ots_type;
    const uint8_t *id;
    const uint8_t *seed;
    lms_tree_meta_t *meta;
    uint8_t *nodes;
    uint8_t *scratch;
    uint32_t s;
    uint32_t nsub;
} lms_tree_t;

/* ======================================================================== */
/* Byte helpers                                                             */
/* ======================================================================== */

static void lms_put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24U);
    p[1] = (uint8_t)(v >> 16U);
    p[2] = (uint8_t)(v >> 8U);
    p[3] = (uint8_t)v;
}

static void lms_put16(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 8U);
    p[1] = (uint8_t)v;
}

static uint32_t lms_get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24U) | ((uint32_t)p[1] << 16U) | ((uint32_t)p[2] << 8U) | (uint32_t)p[3];
}

static void lms_put64(uint8_t *p, uint64_t v)
{
    lms_put32(p, (uint32_t)(v >> 32U));
    lms_put32(&p[4], (uint32_t)v);
}

static uint64_t lms_get64(const uint8_t *p)
{
    return ((uint64_t)lms_get32(p) << 32U) | (uint64_t)lms_get32(&p[4]);
}

/* ======================================================================== */
/* Parameter tables                                                         */
/* ======================================================================== */

/**
 * @brief Resolve an LMS typecode (RFC 8554 Table 2, SP 800-208 Table 3).
 * @return 1 if supported, 0 otherwise.
 */
static uint32_t lms_tree_param(uint32_t type, lms_tree_param_t *out)
{
    uint32_t idx = 0U;
    uint32_t family = 0U;

    if((type < NOXTLS_LMS_TYPE_SHA256_M32_H5) || (type > NOXTLS_LMS_TYPE_SHAKE_M24_H25)) {
        return 0U;
    }
    idx = type - NOXTLS_LMS_TYPE_SHA256_M32_H5;
    family = idx / 5U;
    out->hash = (family < 2U) ? LMS_HASH_SHA256 : LMS_HASH_SHAKE;
    out->n = ((family & 1U) == 0U) ? 32U : 24U;
    out->h = 5U * ((idx % 5U) + 1U);
#if !NOXTLS_FEATURE_SHA3
    if(out->hash == LMS_HASH_SHAKE) {
        return 0U;
    }
#endif
    return 1U;
}

/**
 * @brief Resolve an LM-OTS typecode (RFC 8554 Table 1, SP 800-208 Table 2).
 * @return 1 if supported, 0 otherwise.
 */
static uint32_t lms_ots_param(uint32_t type, lms_ots_param_t *out)
{
    static const uint16_t p_n32[4] = { 265U, 133U, 67U, 34U };
    static const uint8_t ls_n32[4] = { 7U, 6U, 4U, 0U };
    static const uint16_t p_n24[4] = { 200U, 101U, 51U, 26U };
    static const uint8_t ls_n24[4] = { 8U, 6U, 4U, 0U };
    uint32_t idx = 0U;
    uint32_t family = 0U;
    uint32_t wi = 0U;

    if((type < NOXTLS_LMOTS_TYPE_SHA256_N32_W1) || (type > NOXTLS_LMOTS_TYPE_SHAKE_N24_W8)) {
        return 0U;
    }
    idx = type - NOXTLS_LMOTS_TYPE_SHA256_N32_W1;
    family = idx / 4U;
    wi = idx % 4U;
    out->hash = (family < 2U) ? LMS_HASH_SHA256 : LMS_HASH_SHAKE;
    out->w = 1U << wi;
    if((family & 1U) == 0U) {
        out->n = 32U;
        out->p = (uint32_t)p_n32[wi];
        out->ls = (uint32_t)ls_n32[wi];
    } else {
        out->n = 24U;
        out->p = (uint32_t)p_n24[wi];
        out->ls = (uint32_t)ls_n24[wi];
    }
#if !NOXTLS_FEATURE_SHA3
    if(out->hash == LMS_HASH_SHAKE) {
        return 0U;
    }
#endif
    return 1U;
}

/**
 * @brief Resolve an LMS / LM-OTS typecode pair; both must use the same hash
 *        function and output length (SP 800-208).
 * @return 1 if valid and supported, 0 otherwise.
 */
static uint32_t lms_pair_param(uint32_t lms_type, uint32_t ots_type, lms_tree_param_t *tp, lms_ots_param_t *op)
{
    if((lms_tree_param(lms_type, tp) == 0U) || (lms_ots_param(ots_type, op) == 0U)) {
        return 0U;
    }
    if((tp->hash != op->hash) || (tp->n != op->n)) {
        return 0U;
    }
    return 1U;
}

static uint32_t lms_ots_sig_len(const lms_ots_param_t *op)
{
    return 4U + (op->n * (op->p + 1U));
}

static uint32_t lms_sig_len_p(const lms_tree_param_t *tp, const lms_ots_param_t *op)
{
    return 4U + lms_ots_sig_len(op) + 4U + (tp->n * tp->h);
}

uint32_t noxtls_lms_type_signature_len(uint32_t lms_type, uint32_t ots_type)
{
    lms_tree_param_t tp;
    lms_ots_param_t op;

    if(lms_pair_param(lms_type, ots_type, &tp, &op) == 0U) {
        return 0U;
    }
    return lms_sig_len_p(&tp, &op);
}

noxtls_return_t noxtls_hss_params_check(const noxtls_hss_params_t *params, uint32_t for_signing)
{
    lms_tree_param_t tp;
    lms_tree_param_t tp0;
    lms_ots_param_t op;
    uint32_t i = 0U;
    uint32_t total_h = 0U;

    if(params == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if((params->levels < 1U) || (params->levels > NOXTLS_HSS_MAX_LEVELS)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(params->format == NOXTLS_LMS_FORMAT_LMS) {
        if(params->levels != 1U) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
    } else if(params->format != NOXTLS_LMS_FORMAT_HSS) {
        return NOXTLS_RETURN_INVALID_PARAM;
    } else {
        /* HSS */
    }
    tp0.hash = 0U;
    tp0.n = 0U;
    tp0.h = 0U;
    for(i = 0U; i < params->levels; i += 1U) {
        if(lms_pair_param(params->lms_type[i], params->ots_type[i], &tp, &op) == 0U) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        if(i == 0U) {
            tp0 = tp;
        }
        if((for_signing != 0U) && ((tp.hash != tp0.hash) || (tp.n != tp0.n))) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        total_h += tp.h;
    }
    if((for_signing != 0U) && (total_h > LMS_MAX_TOTAL_HEIGHT)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    return NOXTLS_RETURN_SUCCESS;
}

uint32_t noxtls_hss_public_key_len(const noxtls_hss_params_t *params)
{
    lms_tree_param_t tp;

    if(noxtls_hss_params_check(params, 0U) != NOXTLS_RETURN_SUCCESS) {
        return 0U;
    }
    (void)lms_tree_param(params->lms_type[0], &tp);
    return ((params->format == NOXTLS_LMS_FORMAT_HSS) ? 4U : 0U) + 24U + tp.n;
}

uint32_t noxtls_hss_signature_len(const noxtls_hss_params_t *params)
{
    lms_tree_param_t tp;
    lms_ots_param_t op;
    uint32_t i = 0U;
    uint32_t len = 0U;

    if(noxtls_hss_params_check(params, 0U) != NOXTLS_RETURN_SUCCESS) {
        return 0U;
    }
    if(params->format == NOXTLS_LMS_FORMAT_HSS) {
        len = 4U;
    }
    for(i = 0U; i < params->levels; i += 1U) {
        (void)lms_pair_param(params->lms_type[i], params->ots_type[i], &tp, &op);
        len += lms_sig_len_p(&tp, &op);
        if(i > 0U) {
            len += 24U + tp.n; /* signed public key of level i */
        }
    }
    return len;
}

uint64_t noxtls_hss_max_signatures(const noxtls_hss_params_t *params)
{
    lms_tree_param_t tp;
    uint32_t i = 0U;
    uint32_t total_h = 0U;

    if(noxtls_hss_params_check(params, 0U) != NOXTLS_RETURN_SUCCESS) {
        return 0U;
    }
    for(i = 0U; i < params->levels; i += 1U) {
        (void)lms_tree_param(params->lms_type[i], &tp);
        total_h += tp.h;
    }
    if(total_h > LMS_MAX_TOTAL_HEIGHT) {
        return 0U;
    }
    return (uint64_t)1U << total_h;
}

/* ======================================================================== */
/* Hash function H (SHA-256, SHA-256/192, SHAKE256/256, SHAKE256/192)      */
/* ======================================================================== */

static noxtls_return_t lms_h_init(noxtls_lms_hash_t *h, uint32_t alg, uint32_t n)
{
    h->alg = alg;
    h->n = n;
    if(alg == LMS_HASH_SHA256) {
        return noxtls_sha256_init(&h->sha, NOXTLS_HASH_SHA_256);
    }
#if NOXTLS_FEATURE_SHA3
    if(alg == LMS_HASH_SHAKE) {
        return noxtls_shake256_init(&h->sha.u.sha3_ctx);
    }
#endif
    return NOXTLS_RETURN_INVALID_ALGORITHM;
}

static noxtls_return_t lms_h_update(noxtls_lms_hash_t *h, const uint8_t *data, uint32_t len)
{
    if(len == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }
#if NOXTLS_FEATURE_SHA3
    if(h->alg == LMS_HASH_SHAKE) {
        return noxtls_shake256_update(&h->sha.u.sha3_ctx, data, len);
    }
#endif
    return noxtls_sha256_update(&h->sha, data, len);
}

/* Writes h->n bytes. */
static noxtls_return_t lms_h_final(noxtls_lms_hash_t *h, uint8_t *out)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    uint8_t tmp[HASH_SHA256_OUT_LEN];

#if NOXTLS_FEATURE_SHA3
    if(h->alg == LMS_HASH_SHAKE) {
        rc = noxtls_shake256_final(&h->sha.u.sha3_ctx);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_shake256_squeeze(&h->sha.u.sha3_ctx, out, h->n);
        }
        return rc;
    }
#endif
    if(h->n == HASH_SHA256_OUT_LEN) {
        return noxtls_sha256_finish(&h->sha, out);
    }
    rc = noxtls_sha256_finish(&h->sha, tmp);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_copy_u8(out, (size_t)h->n, tmp, (size_t)h->n);
    }
    noxtls_secure_zero(tmp, sizeof(tmp));
    return rc;
}

static noxtls_return_t lms_h_oneshot(noxtls_lms_hash_t *h, uint32_t alg, uint32_t n,
                                     const uint8_t *data, uint32_t len, uint8_t *out)
{
    noxtls_return_t rc = lms_h_init(h, alg, n);

    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = lms_h_update(h, data, len);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = lms_h_final(h, out);
    }
    return rc;
}

/* Fill buf with I || u32str(q) || u16str(i) || u8str(j). */
static void lms_prefix(uint8_t *buf, const uint8_t *id, uint32_t q, uint32_t i, uint32_t j)
{
    noxtls_copy_u8(buf, (size_t)LMS_ID_LEN, id, (size_t)LMS_ID_LEN);
    lms_put32(&buf[16], q);
    lms_put16(&buf[20], i);
    buf[22] = (uint8_t)j;
}

/**
 * @brief Coefficient i of S for Winternitz parameter w (RFC 8554 section 3.1.3).
 */
static uint32_t lms_coef(const uint8_t *s, uint32_t i, uint32_t w)
{
    uint32_t per_byte = 8U / w;
    uint32_t byte = (uint32_t)s[(i * w) / 8U];
    uint32_t shift = 8U - ((w * (i % per_byte)) + w);

    return (byte >> shift) & ((1U << w) - 1U);
}

/* Append the 16-bit checksum of Q (n bytes) at q_cksm[n]. */
static void lms_cksm(uint8_t *q_cksm, const lms_ots_param_t *op)
{
    uint32_t i = 0U;
    uint32_t sum = 0U;
    uint32_t maxc = (1U << op->w) - 1U;
    uint32_t count = (op->n * 8U) / op->w;

    for(i = 0U; i < count; i += 1U) {
        sum += maxc - lms_coef(q_cksm, i, op->w);
    }
    sum = (sum << op->ls) & 0xFFFFU;
    lms_put16(&q_cksm[op->n], sum);
}

/**
 * @brief Interior or leaf node hash:
 *        H(I || u32str(r) || u16str(D) || left [|| right]).
 */
static noxtls_return_t lms_node_hash(noxtls_lms_hash_t *h, uint32_t alg, uint32_t n, const uint8_t *id,
                                     uint32_t r, uint32_t d, const uint8_t *left, const uint8_t *right,
                                     uint8_t *out)
{
    uint8_t pfx[22];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    noxtls_copy_u8(pfx, (size_t)LMS_ID_LEN, id, (size_t)LMS_ID_LEN);
    lms_put32(&pfx[16], r);
    lms_put16(&pfx[20], d);
    rc = lms_h_init(h, alg, n);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = lms_h_update(h, pfx, (uint32_t)sizeof(pfx));
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = lms_h_update(h, left, n);
    }
    if((rc == NOXTLS_RETURN_SUCCESS) && (right != NULL)) {
        rc = lms_h_update(h, right, n);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = lms_h_final(h, out);
    }
    return rc;
}

/* ======================================================================== */
/* Verification                                                             */
/* ======================================================================== */

/**
 * @brief Parse an LMS public key (24 + m bytes): types must be supported and
 *        consistent.  @return 1 if valid.
 */
static uint32_t lms_pk_parse(const uint8_t *pk, uint32_t pk_len, lms_tree_param_t *tp, lms_ots_param_t *op)
{
    if(pk_len < 8U) {
        return 0U;
    }
    if(lms_pair_param(lms_get32(pk), lms_get32(&pk[4]), tp, op) == 0U) {
        return 0U;
    }
    return (pk_len == (24U + tp->n)) ? 1U : 0U;
}

/**
 * @brief Structural checks of an LMS signature against its public key
 *        (Algorithm 6a step 2): exact length, typecodes, q < 2^h.
 */
static uint32_t lms_sig_check(const lms_tree_param_t *tp, const lms_ots_param_t *op, const uint8_t *pk,
                              const uint8_t *sig, uint32_t sig_len)
{
    uint32_t ots_len = lms_ots_sig_len(op);

    if(sig_len != lms_sig_len_p(tp, op)) {
        return 0U;
    }
    if(lms_get32(&sig[4]) != lms_get32(&pk[4])) {
        return 0U;
    }
    if(lms_get32(&sig[4U + ots_len]) != lms_get32(pk)) {
        return 0U;
    }
    if(lms_get32(sig) >= LMS_BIT(tp->h)) {
        return 0U;
    }
    return 1U;
}

/* Start Q = H(I || u32str(q) || u16str(D_MESG) || C || message). */
static noxtls_return_t lms_msg_hash_begin(noxtls_lms_hash_t *h, const lms_ots_param_t *op, const uint8_t *pk,
                                          const uint8_t *sig)
{
    uint8_t pfx[22];
    noxtls_return_t rc = lms_h_init(h, op->hash, op->n);

    noxtls_copy_u8(pfx, (size_t)LMS_ID_LEN, &pk[8], (size_t)LMS_ID_LEN);
    noxtls_copy_u8(&pfx[16], 4U, sig, 4U);
    lms_put16(&pfx[20], LMS_D_MESG);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = lms_h_update(h, pfx, (uint32_t)sizeof(pfx));
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = lms_h_update(h, &sig[8], op->n); /* C */
    }
    return rc;
}

/**
 * @brief Finish an LMS verification: q_cksm[0..n) holds Q.  Computes the
 *        LM-OTS candidate Kc (Algorithm 4b) and the root candidate Tc
 *        (Algorithm 6a) and compares it with T[1].
 * @param ha,hb Two hash contexts (ha may be the one that produced Q).
 * @return NOXTLS_RETURN_SUCCESS if valid, NOXTLS_RETURN_FAILED if not.
 */
static noxtls_return_t lms_verify_finish(noxtls_lms_hash_t *ha, noxtls_lms_hash_t *hb,
                                         const lms_tree_param_t *tp, const lms_ots_param_t *op,
                                         const uint8_t *pk, const uint8_t *sig, uint8_t *q_cksm)
{
    uint8_t buf[LMS_PFX_LEN + LMS_N_MAX];
    uint8_t node[LMS_N_MAX];
    const uint8_t *id = &pk[8];
    const uint8_t *y = &sig[8U + op->n];
    const uint8_t *path = &sig[4U + lms_ots_sig_len(op) + 4U];
    uint32_t q = lms_get32(sig);
    uint32_t maxc = (1U << op->w) - 1U;
    uint32_t i = 0U;
    uint32_t j = 0U;
    uint32_t a = 0U;
    uint32_t r = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    lms_cksm(q_cksm, op);
    /* Kc = H(I || u32str(q) || u16str(D_PBLC) || z[0] || ... || z[p-1]) */
    lms_prefix(buf, id, q, LMS_D_PBLC, 0U);
    rc = lms_h_init(ha, op->hash, op->n);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = lms_h_update(ha, buf, 22U);
    }
    for(i = 0U; (i < op->p) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        a = lms_coef(q_cksm, i, op->w);
        lms_put16(&buf[20], i);
        noxtls_copy_u8(&buf[LMS_PFX_LEN], (size_t)op->n, &y[i * op->n], (size_t)op->n);
        for(j = a; (j < maxc) && (rc == NOXTLS_RETURN_SUCCESS); j += 1U) {
            buf[22] = (uint8_t)j;
            rc = lms_h_oneshot(hb, op->hash, op->n, buf, LMS_PFX_LEN + op->n, &buf[LMS_PFX_LEN]);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = lms_h_update(ha, &buf[LMS_PFX_LEN], op->n);
        }
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = lms_h_final(ha, node); /* Kc */
    }
    /* Tc: leaf then climb the authentication path. */
    r = LMS_BIT(tp->h) + q;
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = lms_node_hash(ha, tp->hash, tp->n, id, r, LMS_D_LEAF, node, NULL, node);
    }
    for(i = 0U; (i < tp->h) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        if((r & 1U) != 0U) {
            rc = lms_node_hash(ha, tp->hash, tp->n, id, r >> 1U, LMS_D_INTR, &path[i * tp->n], node, node);
        } else {
            rc = lms_node_hash(ha, tp->hash, tp->n, id, r >> 1U, LMS_D_INTR, node, &path[i * tp->n], node);
        }
        r >>= 1U;
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = (noxtls_ct_memcmp(node, &pk[24], (size_t)tp->n) == 0) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
    } else {
        rc = NOXTLS_RETURN_FAILED;
    }
    noxtls_secure_zero(buf, sizeof(buf));
    noxtls_secure_zero(node, sizeof(node));
    return rc;
}

/* Verify one LMS signature over an in-memory message. */
static noxtls_return_t lms_verify_one(noxtls_lms_hash_t *ha, noxtls_lms_hash_t *hb, const uint8_t *pk,
                                      const uint8_t *msg, uint32_t msg_len, const uint8_t *sig)
{
    lms_tree_param_t tp;
    lms_ots_param_t op;
    uint8_t q_cksm[LMS_N_MAX + 2U];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    (void)lms_pair_param(lms_get32(pk), lms_get32(&pk[4]), &tp, &op);
    rc = lms_msg_hash_begin(ha, &op, pk, sig);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = lms_h_update(ha, msg, msg_len);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = lms_h_final(ha, q_cksm);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = lms_verify_finish(ha, hb, &tp, &op, pk, sig, q_cksm);
    } else {
        rc = NOXTLS_RETURN_FAILED;
    }
    return rc;
}

noxtls_return_t noxtls_hss_verify_init(noxtls_hss_verify_ctx_t *ctx, uint32_t format,
                                       const uint8_t *public_key, uint32_t public_key_len,
                                       const uint8_t *signature, uint32_t signature_len)
{
    noxtls_lms_hash_t hb;
    lms_tree_param_t tp;
    lms_tree_param_t ntp;
    lms_ots_param_t op;
    lms_ots_param_t nop;
    const uint8_t *cur_pk = NULL;
    const uint8_t *next_pk = NULL;
    uint32_t levels = 1U;
    uint32_t nspk = 0U;
    uint32_t off = 0U;
    uint32_t i = 0U;
    uint32_t len = 0U;
    uint32_t next_len = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    noxtls_secure_zero(ctx, sizeof(*ctx));
    if((public_key == NULL) || (signature == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    /* ---- public key (trusted input, still validated) ---- */
    if(format == NOXTLS_LMS_FORMAT_HSS) {
        if(public_key_len < 4U) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        levels = lms_get32(public_key);
        if((levels < 1U) || (levels > NOXTLS_HSS_MAX_LEVELS)) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        cur_pk = &public_key[4];
        len = public_key_len - 4U;
    } else if(format == NOXTLS_LMS_FORMAT_LMS) {
        cur_pk = public_key;
        len = public_key_len;
    } else {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(lms_pk_parse(cur_pk, len, &tp, &op) == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    /* ---- signature (untrusted): structural pass over all levels ---- */
    if(format == NOXTLS_LMS_FORMAT_HSS) {
        if(signature_len < 4U) {
            return NOXTLS_RETURN_FAILED;
        }
        nspk = lms_get32(signature);
        if(nspk != (levels - 1U)) {
            return NOXTLS_RETURN_FAILED;
        }
        off = 4U;
    }
    for(i = 0U; i < nspk; i += 1U) {
        len = lms_sig_len_p(&tp, &op);
        if(((signature_len - off) < len) || ((signature_len - off - len) < 8U)) {
            return NOXTLS_RETURN_FAILED;
        }
        if(lms_sig_check(&tp, &op, cur_pk, &signature[off], len) == 0U) {
            return NOXTLS_RETURN_FAILED;
        }
        next_pk = &signature[off + len];
        if(lms_pair_param(lms_get32(next_pk), lms_get32(&next_pk[4]), &ntp, &nop) == 0U) {
            return NOXTLS_RETURN_FAILED;
        }
        next_len = 24U + ntp.n;
        if((signature_len - off - len) < next_len) {
            return NOXTLS_RETURN_FAILED;
        }
        off += len + next_len;
        cur_pk = next_pk;
        tp = ntp;
        op = nop;
    }
    len = signature_len - off;
    if(lms_sig_check(&tp, &op, cur_pk, &signature[off], len) == 0U) {
        return NOXTLS_RETURN_FAILED;
    }
    /* ---- cryptographic pass over the signed public keys ---- */
    if(format == NOXTLS_LMS_FORMAT_HSS) {
        cur_pk = &public_key[4];
        off = 4U;
    }
    for(i = 0U; (i < nspk) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        (void)lms_pair_param(lms_get32(cur_pk), lms_get32(&cur_pk[4]), &tp, &op);
        len = lms_sig_len_p(&tp, &op);
        next_pk = &signature[off + len];
        (void)lms_tree_param(lms_get32(next_pk), &ntp);
        next_len = 24U + ntp.n;
        rc = lms_verify_one(&ctx->msg, &hb, cur_pk, next_pk, next_len, &signature[off]);
        off += len + next_len;
        cur_pk = next_pk;
    }
    noxtls_secure_zero(&hb, sizeof(hb));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(ctx, sizeof(*ctx));
        return NOXTLS_RETURN_FAILED;
    }
    (void)lms_pair_param(lms_get32(cur_pk), lms_get32(&cur_pk[4]), &tp, &op);
    rc = lms_msg_hash_begin(&ctx->msg, &op, cur_pk, &signature[off]);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(ctx, sizeof(*ctx));
        return NOXTLS_RETURN_FAILED;
    }
    ctx->lms_pk = cur_pk;
    ctx->lms_sig = &signature[off];
    ctx->state = LMS_VCTX_READY;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_hss_verify_update(noxtls_hss_verify_ctx_t *ctx, const uint8_t *data, uint32_t len)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->state != LMS_VCTX_READY) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
    if((data == NULL) && (len != 0U)) {
        noxtls_secure_zero(ctx, sizeof(*ctx));
        return NOXTLS_RETURN_NULL;
    }
    rc = lms_h_update(&ctx->msg, data, len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(ctx, sizeof(*ctx));
    }
    return rc;
}

noxtls_return_t noxtls_hss_verify_final(noxtls_hss_verify_ctx_t *ctx)
{
    noxtls_lms_hash_t hb;
    lms_tree_param_t tp;
    lms_ots_param_t op;
    uint8_t q_cksm[LMS_N_MAX + 2U];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(ctx == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->state != LMS_VCTX_READY) {
        noxtls_secure_zero(ctx, sizeof(*ctx));
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
    (void)lms_pair_param(lms_get32(ctx->lms_pk), lms_get32(&ctx->lms_pk[4]), &tp, &op);
    rc = lms_h_final(&ctx->msg, q_cksm);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = lms_verify_finish(&ctx->msg, &hb, &tp, &op, ctx->lms_pk, ctx->lms_sig, q_cksm);
    } else {
        rc = NOXTLS_RETURN_FAILED;
    }
    noxtls_secure_zero(&hb, sizeof(hb));
    noxtls_secure_zero(ctx, sizeof(*ctx));
    return rc;
}

noxtls_return_t noxtls_hss_verify(uint32_t format,
                                  const uint8_t *public_key, uint32_t public_key_len,
                                  const uint8_t *message, uint32_t message_len,
                                  const uint8_t *signature, uint32_t signature_len)
{
    noxtls_hss_verify_ctx_t ctx;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((message == NULL) && (message_len != 0U)) {
        return NOXTLS_RETURN_NULL;
    }
    rc = noxtls_hss_verify_init(&ctx, format, public_key, public_key_len, signature, signature_len);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_hss_verify_update(&ctx, message, message_len);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_hss_verify_final(&ctx);
    }
    noxtls_secure_zero(&ctx, sizeof(ctx));
    return rc;
}

/* ======================================================================== */
/* LM-OTS key derivation and signing (secret data)                          */
/* ======================================================================== */

/**
 * @brief buf[23..23+n) = H(I || u32str(q) || u16str(i) || u8str(0xFF) || SEED)
 *        (RFC 8554 Appendix A).  With i = 0xFFFD/0xFFFE/0xFFFF the same
 *        construction derives C and the child SEED / I.
 */
static noxtls_return_t lms_prg(lms_work_t *w, uint32_t alg, uint32_t n, const uint8_t *id, const uint8_t *seed,
                               uint32_t q, uint32_t i)
{
    lms_prefix(w->buf, id, q, i, LMS_PRG_J);
    noxtls_copy_u8(&w->buf[LMS_PFX_LEN], (size_t)n, seed, (size_t)n);
    return lms_h_oneshot(&w->hb, alg, n, w->buf, LMS_PFX_LEN + n, &w->buf[LMS_PFX_LEN]);
}

/* Iterate the chain of element i from step `from` to `to` (exclusive), value in buf tail. */
static noxtls_return_t lms_chain(lms_work_t *w, const lms_ots_param_t *op, uint32_t from, uint32_t to)
{
    uint32_t j = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    for(j = from; (j < to) && (rc == NOXTLS_RETURN_SUCCESS); j += 1U) {
        w->buf[22] = (uint8_t)j;
        rc = lms_h_oneshot(&w->hb, op->hash, op->n, w->buf, LMS_PFX_LEN + op->n, &w->buf[LMS_PFX_LEN]);
    }
    return rc;
}

/**
 * @brief Leaf node of leaf q: H(I || u32str(2^h + q) || D_LEAF || K) with K
 *        the LM-OTS public key (Algorithm 1 + section 5.3).
 */
static noxtls_return_t lms_leaf(lms_work_t *w, const lms_tree_t *t, uint32_t q, uint8_t *out)
{
    uint8_t pfx[22];
    uint32_t maxc = (1U << t->op.w) - 1U;
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    noxtls_copy_u8(pfx, (size_t)LMS_ID_LEN, t->id, (size_t)LMS_ID_LEN);
    lms_put32(&pfx[16], q);
    lms_put16(&pfx[20], LMS_D_PBLC);
    rc = lms_h_init(&w->ha, t->op.hash, t->op.n);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = lms_h_update(&w->ha, pfx, (uint32_t)sizeof(pfx));
    }
    for(i = 0U; (i < t->op.p) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        rc = lms_prg(w, t->op.hash, t->op.n, t->id, t->seed, q, i);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = lms_chain(w, &t->op, 0U, maxc);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = lms_h_update(&w->ha, &w->buf[LMS_PFX_LEN], t->op.n);
        }
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = lms_h_final(&w->ha, out);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = lms_node_hash(&w->ha, t->tp.hash, t->tp.n, t->id, LMS_BIT(t->tp.h) + q, LMS_D_LEAF, out, NULL, out);
    }
    return rc;
}

/**
 * @brief LM-OTS signature of leaf q (Algorithm 3) written to out:
 *        u32str(otstype) || C || y[0] || ... || y[p-1].
 */
static noxtls_return_t lms_ots_sign(lms_work_t *w, const lms_tree_t *t, uint32_t q, const uint8_t *msg,
                                    uint32_t msg_len, uint8_t *out)
{
    const lms_ots_param_t *op = &t->op;
    uint8_t pfx[22];
    uint8_t *c = &out[4];
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    lms_put32(out, t->ots_type);
    /* C = H(I || u32str(q) || u16str(0xFFFD) || u8str(0xFF) || SEED) */
    rc = lms_prg(w, op->hash, op->n, t->id, t->seed, q, LMS_D_PRG_C);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_copy_u8(c, (size_t)op->n, &w->buf[LMS_PFX_LEN], (size_t)op->n);
        noxtls_copy_u8(pfx, (size_t)LMS_ID_LEN, t->id, (size_t)LMS_ID_LEN);
        lms_put32(&pfx[16], q);
        lms_put16(&pfx[20], LMS_D_MESG);
        rc = lms_h_init(&w->ha, op->hash, op->n);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = lms_h_update(&w->ha, pfx, (uint32_t)sizeof(pfx));
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = lms_h_update(&w->ha, c, op->n);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = lms_h_update(&w->ha, msg, msg_len);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = lms_h_final(&w->ha, w->q_cksm);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        lms_cksm(w->q_cksm, op);
    }
    for(i = 0U; (i < op->p) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        rc = lms_prg(w, op->hash, op->n, t->id, t->seed, q, i);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = lms_chain(w, op, 0U, lms_coef(w->q_cksm, i, op->w));
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_copy_u8(&out[4U + op->n + (i * op->n)], (size_t)op->n, &w->buf[LMS_PFX_LEN], (size_t)op->n);
        }
    }
    return rc;
}

/* ======================================================================== */
/* Tree traversal (sublevel / fractal cache, see noxtls_lms.h)              */
/* ======================================================================== */

static uint32_t lms_min_u32(uint32_t a, uint32_t b)
{
    return (a < b) ? a : b;
}

static uint32_t lms_nsub(uint32_t h, uint32_t s)
{
    return (h + s - 1U) / s;
}

/* Base height b and top height t of sublevel l. */
static void lms_sub_geom(uint32_t h, uint32_t s, uint32_t l, uint32_t *b, uint32_t *top)
{
    *b = l * s;
    *top = lms_min_u32((l + 1U) * s, h);
}

/* Bytes of the node region of one tree (all sublevels), 64-bit to detect overflow. */
static uint64_t lms_tree_nodes_len(uint32_t h, uint32_t n, uint32_t s)
{
    uint32_t nsub = lms_nsub(h, s);
    uint32_t l = 0U;
    uint32_t b = 0U;
    uint32_t top = 0U;
    uint64_t total = 0U;
    uint64_t sub = 0U;

    for(l = 0U; l < nsub; l += 1U) {
        lms_sub_geom(h, s, l, &b, &top);
        sub = (((uint64_t)1U << ((top - b) + 1U)) - 1U) * (uint64_t)n;
        if((l + 1U) < nsub) {
            total += (2U * sub) + ((uint64_t)b * (uint64_t)n);
        } else {
            total += sub;
        }
    }
    return total;
}

/* Offset of sublevel l's buffer `sel` (0 = A, 1 = B, 2 = pending slots). */
static uint8_t *lms_sub_ptr(const lms_tree_t *t, uint32_t l, uint32_t sel)
{
    uint32_t i = 0U;
    uint32_t b = 0U;
    uint32_t top = 0U;
    uint32_t off = 0U;
    uint32_t sub = 0U;

    for(i = 0U; i < l; i += 1U) {
        lms_sub_geom(t->tp.h, t->s, i, &b, &top);
        sub = (LMS_BIT((top - b) + 1U) - 1U) * t->tp.n;
        off += (2U * sub) + (b * t->tp.n); /* i < l < nsub: not the top sublevel */
    }
    lms_sub_geom(t->tp.h, t->s, l, &b, &top);
    sub = (LMS_BIT((top - b) + 1U) - 1U) * t->tp.n;
    off += sel * sub;
    return &t->nodes[off];
}

/* Node (relative height r, relative index j) of a subtree buffer of height sh. */
static uint8_t *lms_buf_node(uint8_t *buf, uint32_t sh, uint32_t n, uint32_t r, uint32_t j)
{
    uint32_t idx = (LMS_BIT((sh + 1U)) - LMS_BIT((sh - r) + 1U)) + j;

    return &buf[idx * n];
}

static uint32_t lms_active_sel(const lms_tree_t *t, uint32_t l)
{
    return (t->meta->swap >> l) & 1U;
}

/* Store node (k, idx) produced by a full pass prepared for leaf x. */
static void lms_capture(const lms_tree_t *t, uint32_t x, uint32_t k, uint32_t idx, const uint8_t *node)
{
    uint32_t l = 0U;
    uint32_t b = 0U;
    uint32_t top = 0U;
    uint32_t a = 0U;
    uint32_t anc = 0U;
    uint32_t sel = 0U;
    uint32_t n = t->tp.n;

    for(l = 0U; l < t->nsub; l += 1U) {
        lms_sub_geom(t->tp.h, t->s, l, &b, &top);
        if((k < b) || (k > top)) {
            continue;
        }
        a = x >> top;
        anc = idx >> (top - k);
        if(anc == a) {
            sel = 0U;
        } else if(((l + 1U) < t->nsub) && (anc == (a + 1U))) {
            sel = 1U;
        } else {
            continue;
        }
        noxtls_copy_u8(lms_buf_node(lms_sub_ptr(t, l, sel), top - b, n, k - b, idx - (anc << (top - k))),
                       (size_t)n, node, (size_t)n);
    }
}

/**
 * @brief Treehash over all 2^h leaves (one pending node per height in
 *        t->scratch).  With capture != 0 the traversal state is prepared for
 *        leaf x (active and next subtrees of every sublevel).
 */
static noxtls_return_t lms_tree_build(lms_work_t *w, const lms_tree_t *t, uint32_t x, uint32_t capture,
                                      uint8_t *root)
{
    uint32_t h = t->tp.h;
    uint32_t n = t->tp.n;
    uint32_t leaves = LMS_BIT(h);
    uint32_t j = 0U;
    uint32_t k = 0U;
    uint32_t idx = 0U;
    uint32_t l = 0U;
    uint32_t b = 0U;
    uint32_t top = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if(capture != 0U) {
        t->meta->next_leaf = x;
        t->meta->swap = 0U;
        for(l = 0U; l < LMS_MAX_SUBLEVELS; l += 1U) {
            lms_sub_geom(h, t->s, lms_min_u32(l, t->nsub - 1U), &b, &top);
            t->meta->progress[l] = LMS_BIT(top);
        }
    }
    for(j = 0U; (j < leaves) && (rc == NOXTLS_RETURN_SUCCESS); j += 1U) {
        rc = lms_leaf(w, t, j, w->node);
        k = 0U;
        idx = j;
        if((rc == NOXTLS_RETURN_SUCCESS) && (capture != 0U)) {
            lms_capture(t, x, 0U, idx, w->node);
        }
        while(((idx & 1U) != 0U) && (rc == NOXTLS_RETURN_SUCCESS)) {
            rc = lms_node_hash(&w->ha, t->tp.hash, n, t->id, LMS_BIT((h - k - 1U)) + (idx >> 1U), LMS_D_INTR,
                               &t->scratch[k * n], w->node, w->node);
            k += 1U;
            idx >>= 1U;
            if((rc == NOXTLS_RETURN_SUCCESS) && (capture != 0U)) {
                lms_capture(t, x, k, idx, w->node);
            }
        }
        if((rc == NOXTLS_RETURN_SUCCESS) && (k < h)) {
            noxtls_copy_u8(&t->scratch[k * n], (size_t)n, w->node, (size_t)n);
        }
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_copy_u8(root, (size_t)n, w->node, (size_t)n);
    }
    return rc;
}

/* One leaf of incremental work on sublevel l's next subtree (index nidx). */
static noxtls_return_t lms_tree_step(lms_work_t *w, const lms_tree_t *t, uint32_t l, uint32_t nidx)
{
    uint32_t h = t->tp.h;
    uint32_t n = t->tp.n;
    uint32_t b = 0U;
    uint32_t top = 0U;
    uint32_t k = 0U;
    uint32_t idx = 0U;
    uint8_t *nbuf = NULL;
    uint8_t *pend = lms_sub_ptr(t, l, 2U);
    const uint8_t *left = NULL;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    lms_sub_geom(h, t->s, l, &b, &top);
    nbuf = lms_sub_ptr(t, l, lms_active_sel(t, l) ^ 1U);
    idx = (nidx << top) + t->meta->progress[l];
    rc = lms_leaf(w, t, idx, w->node);
    while(rc == NOXTLS_RETURN_SUCCESS) {
        if(k >= b) {
            noxtls_copy_u8(lms_buf_node(nbuf, top - b, n, k - b, idx - (nidx << (top - k))), (size_t)n,
                           w->node, (size_t)n);
        }
        if(k == top) {
            break;
        }
        if((idx & 1U) == 0U) {
            if(k < b) {
                noxtls_copy_u8(&pend[k * n], (size_t)n, w->node, (size_t)n);
            }
            break;
        }
        if(k < b) {
            left = &pend[k * n];
        } else {
            left = lms_buf_node(nbuf, top - b, n, k - b, (idx - 1U) - (nidx << (top - k)));
        }
        rc = lms_node_hash(&w->ha, t->tp.hash, n, t->id, LMS_BIT((h - k - 1U)) + (idx >> 1U), LMS_D_INTR,
                           left, w->node, w->node);
        k += 1U;
        idx >>= 1U;
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        t->meta->progress[l] += 1U;
    }
    return rc;
}

/**
 * @brief Move the traversal from leaf x = next_leaf to x + 1: one step on
 *        every unfinished next subtree, then switch sublevels whose active
 *        subtree ends.
 */
static noxtls_return_t lms_tree_advance(lms_work_t *w, const lms_tree_t *t)
{
    uint32_t h = t->tp.h;
    uint32_t x = t->meta->next_leaf;
    uint32_t l = 0U;
    uint32_t b = 0U;
    uint32_t top = 0U;
    uint32_t a = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if(x >= LMS_BIT(h)) {
        return NOXTLS_RETURN_FAILED;
    }
    for(l = 0U; ((l + 1U) < t->nsub) && (rc == NOXTLS_RETURN_SUCCESS); l += 1U) {
        lms_sub_geom(h, t->s, l, &b, &top);
        a = x >> top;
        if(((a + 1U) < LMS_BIT((h - top))) && (t->meta->progress[l] < LMS_BIT(top))) {
            rc = lms_tree_step(w, t, l, a + 1U);
        }
    }
    if((rc == NOXTLS_RETURN_SUCCESS) && ((x + 1U) < LMS_BIT(h))) {
        for(l = 0U; ((l + 1U) < t->nsub) && (rc == NOXTLS_RETURN_SUCCESS); l += 1U) {
            lms_sub_geom(h, t->s, l, &b, &top);
            if(((x + 1U) >> top) != (x >> top)) {
                if(t->meta->progress[l] != LMS_BIT(top)) {
                    rc = NOXTLS_RETURN_FAILED;
                } else {
                    t->meta->swap ^= LMS_BIT(l);
                    /* A new next subtree starts; the last one of a level has none. */
                    t->meta->progress[l] = ((((x + 1U) >> top) + 1U) < LMS_BIT((h - top))) ? 0U : LMS_BIT(top);
                }
            }
        }
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        t->meta->next_leaf = x + 1U;
    }
    return rc;
}

/**
 * @brief LMS signature (Algorithm 5) with leaf next_leaf:
 *        u32str(q) || LM-OTS signature || u32str(type) || path[0..h-1].
 *        The caller advances the traversal afterwards.
 */
static noxtls_return_t lms_tree_sign(lms_work_t *w, const lms_tree_t *t, const uint8_t *msg, uint32_t msg_len,
                                     uint8_t *out)
{
    uint32_t h = t->tp.h;
    uint32_t n = t->tp.n;
    uint32_t x = t->meta->next_leaf;
    uint32_t k = 0U;
    uint32_t l = 0U;
    uint32_t b = 0U;
    uint32_t top = 0U;
    uint32_t sib = 0U;
    uint32_t a = 0U;
    uint8_t *path = NULL;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(x >= LMS_BIT(h)) {
        return NOXTLS_RETURN_FAILED;
    }
    lms_put32(out, x);
    rc = lms_ots_sign(w, t, x, msg, msg_len, &out[4]);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    lms_put32(&out[4U + lms_ots_sig_len(&t->op)], t->lms_type);
    path = &out[8U + lms_ots_sig_len(&t->op)];
    for(k = 0U; k < h; k += 1U) {
        l = k / t->s;
        lms_sub_geom(h, t->s, l, &b, &top);
        sib = (x >> k) ^ 1U;
        a = x >> top;
        noxtls_copy_u8(&path[k * n], (size_t)n,
                       lms_buf_node(lms_sub_ptr(t, l, lms_active_sel(t, l)), top - b, n, k - b,
                                    sib - (a << (top - k))),
                       (size_t)n);
    }
    return NOXTLS_RETURN_SUCCESS;
}

/* ======================================================================== */
/* Private key blob                                                         */
/* ======================================================================== */

static noxtls_return_t lms_sha256(const uint8_t *data, uint32_t len, uint8_t out[32])
{
    noxtls_sha_ctx_t ctx;
    noxtls_return_t rc = noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256);

    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha256_update(&ctx, data, len);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha256_finish(&ctx, out);
    }
    noxtls_secure_zero(&ctx, sizeof(ctx));
    return rc;
}

static noxtls_return_t lms_blob_write(const noxtls_hss_params_t *p, uint64_t counter, const uint8_t *id,
                                      const uint8_t *seed, const uint8_t *root, uint32_t n, uint8_t *out)
{
    uint8_t digest[32];
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    noxtls_secure_zero(out, (size_t)NOXTLS_HSS_PRIVATE_KEY_LEN);
    lms_put32(out, LMS_SK_MAGIC);
    out[4] = (uint8_t)LMS_SK_VERSION;
    out[5] = (uint8_t)p->format;
    out[6] = (uint8_t)p->levels;
    for(i = 0U; i < p->levels; i += 1U) {
        lms_put32(&out[LMS_SK_OFF_TYPES + (8U * i)], p->lms_type[i]);
        lms_put32(&out[LMS_SK_OFF_TYPES + (8U * i) + 4U], p->ots_type[i]);
    }
    lms_put64(&out[LMS_SK_OFF_COUNTER], counter);
    noxtls_copy_u8(&out[LMS_SK_OFF_ID], (size_t)LMS_ID_LEN, id, (size_t)LMS_ID_LEN);
    noxtls_copy_u8(&out[LMS_SK_OFF_SEED], (size_t)n, seed, (size_t)n);
    noxtls_copy_u8(&out[LMS_SK_OFF_ROOT], (size_t)n, root, (size_t)n);
    rc = lms_sha256(out, LMS_SK_OFF_CHECK, digest);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_copy_u8(&out[LMS_SK_OFF_CHECK], (size_t)LMS_SK_CHECK_LEN, digest, (size_t)LMS_SK_CHECK_LEN);
    }
    noxtls_secure_zero(digest, sizeof(digest));
    return rc;
}

/* Parse and validate a blob; params is fully initialized on success. */
static noxtls_return_t lms_blob_parse(const uint8_t *blob, uint32_t len, noxtls_hss_params_t *p, uint64_t *counter)
{
    uint8_t digest[32];
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(blob == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(len != NOXTLS_HSS_PRIVATE_KEY_LEN) {
        return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }
    rc = lms_sha256(blob, LMS_SK_OFF_CHECK, digest);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if((noxtls_ct_memcmp(digest, &blob[LMS_SK_OFF_CHECK], (size_t)LMS_SK_CHECK_LEN) != 0) ||
       (lms_get32(blob) != LMS_SK_MAGIC) || (blob[4] != (uint8_t)LMS_SK_VERSION) || (blob[7] != 0U)) {
        noxtls_secure_zero(digest, sizeof(digest));
        return NOXTLS_RETURN_BAD_DATA;
    }
    noxtls_secure_zero(digest, sizeof(digest));
    noxtls_secure_zero(p, sizeof(*p));
    p->format = (uint32_t)blob[5];
    p->levels = (uint32_t)blob[6];
    if((p->levels < 1U) || (p->levels > NOXTLS_HSS_MAX_LEVELS)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    for(i = 0U; i < p->levels; i += 1U) {
        p->lms_type[i] = lms_get32(&blob[LMS_SK_OFF_TYPES + (8U * i)]);
        p->ots_type[i] = lms_get32(&blob[LMS_SK_OFF_TYPES + (8U * i) + 4U]);
    }
    if(noxtls_hss_params_check(p, 1U) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    *counter = lms_get64(&blob[LMS_SK_OFF_COUNTER]);
    if(*counter > noxtls_hss_max_signatures(p)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_hss_private_key_info(const uint8_t *private_key, uint32_t private_key_len,
                                            noxtls_hss_params_t *params, uint64_t *next_index,
                                            uint64_t *remaining)
{
    noxtls_hss_params_t p;
    uint64_t counter = 0U;
    noxtls_return_t rc = lms_blob_parse(private_key, private_key_len, &p, &counter);

    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(params != NULL) {
        *params = p;
    }
    if(next_index != NULL) {
        *next_index = counter;
    }
    if(remaining != NULL) {
        *remaining = noxtls_hss_max_signatures(&p) - counter;
    }
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t lms_random(uint8_t *out, uint32_t len)
{
    drbg_state_t drbg;
    noxtls_return_t rc = drbg_instantiate(&drbg, DRBG_AES256, NULL, 0U, NULL, 0U, NULL, 0U);

    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = drbg_generate(&drbg, out, len * 8U, NULL, 0U);
    }
    noxtls_secure_zero(&drbg, sizeof(drbg));
    return rc;
}

/* Encode an LMS public key type || otstype || I || T (24 + n bytes). */
static void lms_pub_write(uint8_t *out, uint32_t lms_type, uint32_t ots_type, const uint8_t *id,
                          const uint8_t *root, uint32_t n)
{
    lms_put32(out, lms_type);
    lms_put32(&out[4], ots_type);
    noxtls_copy_u8(&out[8], (size_t)LMS_ID_LEN, id, (size_t)LMS_ID_LEN);
    noxtls_copy_u8(&out[24], (size_t)n, root, (size_t)n);
}

noxtls_return_t noxtls_hss_keygen(const noxtls_hss_params_t *params,
                                  const uint8_t *seed, const uint8_t *id,
                                  uint8_t *public_key, uint32_t public_key_len,
                                  uint8_t *private_key, uint32_t private_key_len)
{
    lms_work_t w;
    lms_tree_t t;
    uint8_t scratch[LMS_H_MAX * LMS_N_MAX];
    uint8_t key_id[LMS_ID_LEN];
    uint8_t key_seed[LMS_N_MAX];
    uint8_t root[LMS_N_MAX];
    uint32_t pk_len = 0U;
    uint32_t off = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((params == NULL) || (public_key == NULL) || (private_key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    rc = noxtls_hss_params_check(params, 1U);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    pk_len = noxtls_hss_public_key_len(params);
    if((public_key_len < pk_len) || (private_key_len < NOXTLS_HSS_PRIVATE_KEY_LEN)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    noxtls_secure_zero(&t, sizeof(t));
    (void)lms_pair_param(params->lms_type[0], params->ots_type[0], &t.tp, &t.op);
    t.lms_type = params->lms_type[0];
    t.ots_type = params->ots_type[0];
    rc = NOXTLS_RETURN_SUCCESS;
    if(id != NULL) {
        noxtls_copy_u8(key_id, sizeof(key_id), id, (size_t)LMS_ID_LEN);
    } else {
        rc = lms_random(key_id, LMS_ID_LEN);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        if(seed != NULL) {
            noxtls_copy_u8(key_seed, sizeof(key_seed), seed, (size_t)t.tp.n);
        } else {
            rc = lms_random(key_seed, t.tp.n);
        }
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        t.id = key_id;
        t.seed = key_seed;
        t.scratch = scratch;
        t.s = t.tp.h;
        t.nsub = 1U;
        rc = lms_tree_build(&w, &t, 0U, 0U, root);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        if(params->format == NOXTLS_LMS_FORMAT_HSS) {
            lms_put32(public_key, params->levels);
            off = 4U;
        }
        lms_pub_write(&public_key[off], t.lms_type, t.ots_type, key_id, root, t.tp.n);
        rc = lms_blob_write(params, 0U, key_id, key_seed, root, t.tp.n, private_key);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(private_key, (size_t)NOXTLS_HSS_PRIVATE_KEY_LEN);
    }
    noxtls_secure_zero(&w, sizeof(w));
    noxtls_secure_zero(scratch, sizeof(scratch));
    noxtls_secure_zero(key_seed, sizeof(key_seed));
    noxtls_secure_zero(key_id, sizeof(key_id));
    noxtls_secure_zero(root, sizeof(root));
    return rc;
}

/* ======================================================================== */
/* Working key: workspace layout and HSS state machine                      */
/* ======================================================================== */

static uint32_t lms_align4(uint32_t v)
{
    return (v + 3U) & ~3U;
}

static uint32_t lms_eff_s(uint32_t subtree_height)
{
    return (subtree_height == 0U) ? NOXTLS_HSS_DEFAULT_SUBTREE_HEIGHT : subtree_height;
}

static noxtls_return_t lms_ws_layout(const noxtls_hss_params_t *p, uint32_t subtree_height, lms_ws_layout_t *lay)
{
    lms_tree_param_t tp;
    lms_ots_param_t op;
    lms_tree_param_t ntp;
    uint32_t s = lms_eff_s(subtree_height);
    uint32_t i = 0U;
    uint32_t max_h = 0U;
    uint64_t off = 0U;

    noxtls_secure_zero(lay, sizeof(*lay));
    if(noxtls_hss_params_check(p, 1U) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    lay->meta_off = lms_align4((uint32_t)sizeof(lms_ws_hdr_t));
    off = (uint64_t)lay->meta_off + ((uint64_t)p->levels * (uint64_t)sizeof(lms_tree_meta_t));
    for(i = 0U; i < p->levels; i += 1U) {
        (void)lms_tree_param(p->lms_type[i], &tp);
        if(tp.h > max_h) {
            max_h = tp.h;
        }
    }
    lay->scratch_off = (uint32_t)off;
    off += (uint64_t)max_h * LMS_N_MAX;
    for(i = 0U; i < p->levels; i += 1U) {
        (void)lms_pair_param(p->lms_type[i], p->ots_type[i], &tp, &op);
        lay->nodes_off[i] = (uint32_t)off;
        off += lms_tree_nodes_len(tp.h, tp.n, lms_min_u32(s, tp.h));
        if(off > 0xFFFFFFF0U) {
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
    }
    for(i = 0U; (i + 1U) < p->levels; i += 1U) {
        (void)lms_pair_param(p->lms_type[i], p->ots_type[i], &tp, &op);
        (void)lms_tree_param(p->lms_type[i + 1U], &ntp);
        lay->spk_off[i] = (uint32_t)off;
        lay->spk_len[i] = lms_sig_len_p(&tp, &op) + 24U + ntp.n;
        off += lay->spk_len[i];
    }
    off = (off + 3U) & ~(uint64_t)3U;
    if(off > 0xFFFFFFF0U) {
        return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
    }
    lay->total = (uint32_t)off;
    return NOXTLS_RETURN_SUCCESS;
}

uint32_t noxtls_hss_workspace_len(const noxtls_hss_params_t *params, uint32_t subtree_height)
{
    lms_ws_layout_t lay;

    if(lms_ws_layout(params, subtree_height, &lay) != NOXTLS_RETURN_SUCCESS) {
        return 0U;
    }
    return lay.total;
}

static lms_ws_hdr_t *lms_ws_hdr(const noxtls_hss_key_t *key)
{
    return (lms_ws_hdr_t *)(void *)key->ws;
}

/* Fill a tree view for level i of a working key. */
static void lms_key_tree(const noxtls_hss_key_t *key, const lms_ws_layout_t *lay, uint32_t i, lms_tree_t *t)
{
    (void)lms_pair_param(key->params.lms_type[i], key->params.ots_type[i], &t->tp, &t->op);
    t->lms_type = key->params.lms_type[i];
    t->ots_type = key->params.ots_type[i];
    t->id = key->id[i];
    t->seed = key->seed[i];
    t->meta = (lms_tree_meta_t *)(void *)&key->ws[lay->meta_off + (i * (uint32_t)sizeof(lms_tree_meta_t))];
    t->nodes = &key->ws[lay->nodes_off[i]];
    t->scratch = &key->ws[lay->scratch_off];
    t->s = lms_min_u32(key->subtree_height, t->tp.h);
    t->nsub = lms_nsub(t->tp.h, t->s);
}

/* Bits of the global index below level i. */
static uint32_t lms_below(const noxtls_hss_params_t *p, uint32_t i)
{
    lms_tree_param_t tp;
    uint32_t j = 0U;
    uint32_t bits = 0U;

    for(j = i + 1U; j < p->levels; j += 1U) {
        (void)lms_tree_param(p->lms_type[j], &tp);
        bits += tp.h;
    }
    return bits;
}

/* Leaf index of level i for global index g. */
static uint32_t lms_level_q(const noxtls_hss_params_t *p, uint32_t i, uint64_t g)
{
    lms_tree_param_t tp;

    (void)lms_tree_param(p->lms_type[i], &tp);
    return (uint32_t)((g >> lms_below(p, i)) & (((uint64_t)1U << tp.h) - 1U));
}

/* Derive I / SEED of level i + 1 from level i and its leaf q. */
static noxtls_return_t lms_derive_child(lms_work_t *w, noxtls_hss_key_t *key, uint32_t i, uint32_t q)
{
    lms_tree_param_t tp;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    (void)lms_tree_param(key->params.lms_type[i], &tp);
    rc = lms_prg(w, tp.hash, tp.n, key->id[i], key->seed[i], q, LMS_D_CHILD_SEED);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_copy_u8(key->seed[i + 1U], sizeof(key->seed[0]), &w->buf[LMS_PFX_LEN], (size_t)tp.n);
        rc = lms_prg(w, tp.hash, tp.n, key->id[i], key->seed[i], q, LMS_D_CHILD_I);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_copy_u8(key->id[i + 1U], sizeof(key->id[0]), &w->buf[LMS_PFX_LEN], (size_t)LMS_ID_LEN);
    }
    return rc;
}

/**
 * @brief Build level i's tree prepared for leaf x (capturing the traversal
 *        state).  With fault hardening the root is computed a second time.
 */
static noxtls_return_t lms_level_build(lms_work_t *w, const noxtls_hss_key_t *key, const lms_ws_layout_t *lay,
                                       uint32_t i, uint32_t x)
{
    lms_tree_t t;
    uint8_t check[LMS_N_MAX];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    lms_key_tree(key, lay, i, &t);
    rc = lms_tree_build(w, &t, x, 1U, t.meta->root);
    if((rc == NOXTLS_RETURN_SUCCESS) && ((key->flags & NOXTLS_HSS_KEY_FAULT_HARDENING) != 0U)) {
        rc = lms_tree_build(w, &t, x, 0U, check);
        if((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_ct_memcmp(check, t.meta->root, (size_t)t.tp.n) != 0)) {
            rc = NOXTLS_RETURN_FAILED;
        }
    }
    noxtls_secure_zero(check, sizeof(check));
    return rc;
}

/**
 * @brief Level i - 1 signs the public key of level i (signed_pub_key[i - 1])
 *        with its next leaf, which must be leaf q, then advances.
 */
static noxtls_return_t lms_level_sign_child(lms_work_t *w, const noxtls_hss_key_t *key, const lms_ws_layout_t *lay,
                                            uint32_t i, uint32_t q)
{
    lms_tree_t parent;
    lms_tree_t child;
    uint8_t *spk = &key->ws[lay->spk_off[i - 1U]];
    uint8_t *pub = NULL;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    lms_key_tree(key, lay, i - 1U, &parent);
    lms_key_tree(key, lay, i, &child);
    if(parent.meta->next_leaf != q) {
        return NOXTLS_RETURN_FAILED;
    }
    pub = &spk[lms_sig_len_p(&parent.tp, &parent.op)];
    lms_pub_write(pub, child.lms_type, child.ots_type, child.id, child.meta->root, child.tp.n);
    rc = lms_tree_sign(w, &parent, pub, 24U + child.tp.n, spk);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = lms_tree_advance(w, &parent);
    }
    return rc;
}

/* Full rebuild of the workspace for global index g. */
static noxtls_return_t lms_rebuild(lms_work_t *w, noxtls_hss_key_t *key, const lms_ws_layout_t *lay, uint64_t g)
{
    lms_ws_hdr_t *hdr = lms_ws_hdr(key);
    lms_tree_t t;
    uint32_t i = 0U;
    uint32_t q = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    hdr->valid = 0U;
    for(i = 0U; (i < key->params.levels) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        q = lms_level_q(&key->params, i, g);
        if(i > 0U) {
            rc = lms_derive_child(w, key, i - 1U, lms_level_q(&key->params, i - 1U, g));
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = lms_level_build(w, key, lay, i, q);
        }
        if((rc == NOXTLS_RETURN_SUCCESS) && (i == 0U)) {
            lms_key_tree(key, lay, 0U, &t);
            if(noxtls_ct_memcmp(t.meta->root, key->root, (size_t)t.tp.n) != 0) {
                rc = NOXTLS_RETURN_BAD_DATA; /* private key does not match its public key */
            }
        }
        if((rc == NOXTLS_RETURN_SUCCESS) && (i > 0U)) {
            rc = lms_level_sign_child(w, key, lay, i, lms_level_q(&key->params, i - 1U, g));
        }
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        hdr->g_hi = (uint32_t)(g >> 32U);
        hdr->g_lo = (uint32_t)g;
        hdr->valid = 1U;
    }
    return rc;
}

/**
 * @brief After the bottom tree is exhausted at global index g (< max):
 *        replace every exhausted lower tree and sign the new public keys.
 */
static noxtls_return_t lms_rollover(lms_work_t *w, noxtls_hss_key_t *key, const lms_ws_layout_t *lay, uint64_t g)
{
    lms_tree_t t;
    uint32_t d = key->params.levels - 1U;
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    /* d = shallowest exhausted level (levels d..L-1 are exhausted). */
    while(d > 0U) {
        lms_key_tree(key, lay, d - 1U, &t);
        if(t.meta->next_leaf < LMS_BIT(t.tp.h)) {
            break;
        }
        d -= 1U;
    }
    if(d == 0U) {
        return NOXTLS_RETURN_FAILED; /* top tree exhausted: g would be >= max */
    }
    for(i = d; (i < key->params.levels) && (rc == NOXTLS_RETURN_SUCCESS); i += 1U) {
        if(lms_level_q(&key->params, i, g) != 0U) {
            rc = NOXTLS_RETURN_FAILED;
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = lms_derive_child(w, key, i - 1U, lms_level_q(&key->params, i - 1U, g));
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = lms_level_build(w, key, lay, i, 0U);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = lms_level_sign_child(w, key, lay, i, lms_level_q(&key->params, i - 1U, g));
        }
    }
    return rc;
}

/* Advance the workspace from global index g to g + 1 (bottom leaf g is done). */
static noxtls_return_t lms_advance_one(lms_work_t *w, noxtls_hss_key_t *key, const lms_ws_layout_t *lay)
{
    lms_ws_hdr_t *hdr = lms_ws_hdr(key);
    lms_tree_t t;
    uint64_t g = ((uint64_t)hdr->g_hi << 32U) | (uint64_t)hdr->g_lo;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    lms_key_tree(key, lay, key->params.levels - 1U, &t);
    rc = lms_tree_advance(w, &t);
    g += 1U;
    if((rc == NOXTLS_RETURN_SUCCESS) && (t.meta->next_leaf == LMS_BIT(t.tp.h)) && (g < key->max_index)) {
        rc = lms_rollover(w, key, lay, g);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        hdr->g_hi = (uint32_t)(g >> 32U);
        hdr->g_lo = (uint32_t)g;
    } else {
        hdr->valid = 0U;
    }
    return rc;
}

/* Bring the workspace to global index g (rebuild, or advance skipped indices). */
static noxtls_return_t lms_prepare(lms_work_t *w, noxtls_hss_key_t *key, const lms_ws_layout_t *lay, uint64_t g)
{
    lms_ws_hdr_t *hdr = lms_ws_hdr(key);
    lms_tree_t t;
    lms_tree_param_t tp;
    uint64_t cur = 0U;
    uint64_t rebuild_cost = 0U;
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if(hdr->valid != 1U) {
        return lms_rebuild(w, key, lay, g);
    }
    cur = ((uint64_t)hdr->g_hi << 32U) | (uint64_t)hdr->g_lo;
    if(cur > g) {
        hdr->valid = 0U;
        return NOXTLS_RETURN_BAD_DATA;
    }
    for(i = 0U; i < key->params.levels; i += 1U) {
        (void)lms_tree_param(key->params.lms_type[i], &tp);
        rebuild_cost += (uint64_t)1U << tp.h;
    }
    lms_key_tree(key, lay, key->params.levels - 1U, &t);
    if(((g - cur) * (uint64_t)t.nsub) > rebuild_cost) {
        return lms_rebuild(w, key, lay, g);
    }
    while((cur < g) && (rc == NOXTLS_RETURN_SUCCESS)) {
        rc = lms_advance_one(w, key, lay);
        cur += 1U;
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        rc = lms_rebuild(w, key, lay, g);
    }
    return rc;
}

/* Binding of a workspace to a key: SHA-256 over blob header fields, I, T and s. */
static noxtls_return_t lms_ws_binding(const noxtls_hss_key_t *key, uint32_t total, uint8_t out[32])
{
    uint8_t buf[LMS_SK_OFF_TYPES + 64U + LMS_ID_LEN + LMS_N_MAX + 8U];
    uint32_t i = 0U;
    uint32_t off = 0U;

    noxtls_secure_zero(buf, sizeof(buf));
    buf[0] = (uint8_t)key->params.format;
    buf[1] = (uint8_t)key->params.levels;
    off = LMS_SK_OFF_TYPES;
    for(i = 0U; i < key->params.levels; i += 1U) {
        lms_put32(&buf[off + (8U * i)], key->params.lms_type[i]);
        lms_put32(&buf[off + (8U * i) + 4U], key->params.ots_type[i]);
    }
    off += 64U;
    noxtls_copy_u8(&buf[off], (size_t)LMS_ID_LEN, key->id[0], (size_t)LMS_ID_LEN);
    off += LMS_ID_LEN;
    noxtls_copy_u8(&buf[off], (size_t)LMS_N_MAX, key->root, (size_t)LMS_N_MAX);
    off += LMS_N_MAX;
    lms_put32(&buf[off], key->subtree_height);
    lms_put32(&buf[off + 4U], total);
    return lms_sha256(buf, (uint32_t)sizeof(buf), out);
}

/**
 * @brief Accept a workspace from an earlier session if it belongs to this key
 *        and its traversal state is consistent with its index.
 * @return SUCCESS (usable), FAILED (rebuild), BAD_DATA (rollback detected).
 */
static noxtls_return_t lms_ws_check(lms_work_t *w, noxtls_hss_key_t *key, const lms_ws_layout_t *lay)
{
    lms_ws_hdr_t *hdr = lms_ws_hdr(key);
    lms_tree_t t;
    uint8_t binding[32];
    uint64_t g = 0U;
    uint32_t i = 0U;
    uint32_t l = 0U;
    uint32_t b = 0U;
    uint32_t top = 0U;
    uint32_t want = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((hdr->magic != LMS_WS_MAGIC) || (hdr->version != LMS_WS_VERSION) || (hdr->len != lay->total) ||
       (hdr->subtree != key->subtree_height) || (hdr->valid != 1U)) {
        return NOXTLS_RETURN_FAILED;
    }
    rc = lms_ws_binding(key, lay->total, binding);
    if((rc != NOXTLS_RETURN_SUCCESS) || (noxtls_ct_memcmp(binding, hdr->binding, sizeof(binding)) != 0)) {
        return NOXTLS_RETURN_FAILED;
    }
    g = ((uint64_t)hdr->g_hi << 32U) | (uint64_t)hdr->g_lo;
    if(g > key->next_index) {
        return NOXTLS_RETURN_BAD_DATA; /* workspace ahead of the persisted counter */
    }
    if(g >= key->max_index) {
        return NOXTLS_RETURN_FAILED;
    }
    for(i = 0U; i < key->params.levels; i += 1U) {
        if(i > 0U) {
            rc = lms_derive_child(w, key, i - 1U, lms_level_q(&key->params, i - 1U, g));
            if(rc != NOXTLS_RETURN_SUCCESS) {
                return rc;
            }
        }
        lms_key_tree(key, lay, i, &t);
        want = lms_level_q(&key->params, i, g) + (((i + 1U) < key->params.levels) ? 1U : 0U);
        if(t.meta->next_leaf != want) {
            return NOXTLS_RETURN_FAILED;
        }
        for(l = 0U; l < LMS_MAX_SUBLEVELS; l += 1U) {
            lms_sub_geom(t.tp.h, t.s, lms_min_u32(l, t.nsub - 1U), &b, &top);
            if(t.meta->progress[l] > LMS_BIT(top)) {
                return NOXTLS_RETURN_FAILED;
            }
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

void noxtls_hss_key_free(noxtls_hss_key_t *key)
{
    if(key == NULL) {
        return;
    }
    if((key->ws != NULL) && (key->ws_owned != 0U)) {
        noxtls_secure_zero(key->ws, (size_t)key->ws_len);
        noxtls_free(key->ws);
    }
    noxtls_secure_zero(key, sizeof(*key));
}

noxtls_return_t noxtls_hss_key_load(noxtls_hss_key_t *key,
                                    const uint8_t *private_key, uint32_t private_key_len,
                                    uint8_t *workspace, uint32_t workspace_len,
                                    uint32_t subtree_height, uint32_t flags,
                                    noxtls_hss_persist_fn persist, void *persist_user)
{
    lms_work_t w;
    lms_ws_layout_t lay;
    lms_tree_param_t tp;
    lms_ws_hdr_t *hdr = NULL;
    uint64_t counter = 0U;
    uint32_t reuse = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    noxtls_secure_zero(key, sizeof(*key));
    if((private_key == NULL) || (persist == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if((flags & ~(NOXTLS_HSS_LOAD_REUSE_WORKSPACE | NOXTLS_HSS_KEY_FAULT_HARDENING |
                  NOXTLS_HSS_KEY_NO_SELF_VERIFY)) != 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if((subtree_height > LMS_H_MAX) || ((workspace != NULL) && ((((uintptr_t)workspace) & 3U) != 0U))) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    rc = lms_blob_parse(private_key, private_key_len, &key->params, &counter);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(key, sizeof(*key));
        return rc;
    }
    key->subtree_height = lms_eff_s(subtree_height);
    rc = lms_ws_layout(&key->params, key->subtree_height, &lay);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(key, sizeof(*key));
        return rc;
    }
    if(workspace == NULL) {
        key->ws = (uint8_t *)NOXTLS_MALLOC((size_t)lay.total);
        if(key->ws == NULL) {
            noxtls_secure_zero(key, sizeof(*key));
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        key->ws_owned = 1U;
        noxtls_secure_zero(key->ws, (size_t)lay.total);
    } else {
        if(workspace_len < lay.total) {
            noxtls_secure_zero(key, sizeof(*key));
            return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
        }
        key->ws = workspace;
        reuse = flags & NOXTLS_HSS_LOAD_REUSE_WORKSPACE;
    }
    key->ws_len = lay.total;
    (void)lms_tree_param(key->params.lms_type[0], &tp);
    noxtls_copy_u8(key->id[0], sizeof(key->id[0]), &private_key[LMS_SK_OFF_ID], (size_t)LMS_ID_LEN);
    noxtls_copy_u8(key->seed[0], sizeof(key->seed[0]), &private_key[LMS_SK_OFF_SEED], (size_t)tp.n);
    noxtls_copy_u8(key->root, sizeof(key->root), &private_key[LMS_SK_OFF_ROOT], (size_t)tp.n);
    key->next_index = counter;
    key->reserved_index = counter;
    key->max_index = noxtls_hss_max_signatures(&key->params);
    key->reserve = 1U;
    key->flags = flags & (NOXTLS_HSS_KEY_FAULT_HARDENING | NOXTLS_HSS_KEY_NO_SELF_VERIFY);
    key->persist = persist;
    key->persist_user = persist_user;

    hdr = lms_ws_hdr(key);
    rc = NOXTLS_RETURN_FAILED;
    if(reuse != 0U) {
        rc = lms_ws_check(&w, key, &lay);
    }
    if(rc == NOXTLS_RETURN_BAD_DATA) {
        noxtls_secure_zero(&w, sizeof(w));
        noxtls_hss_key_free(key);
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(key->ws, (size_t)lay.total);
        hdr->magic = LMS_WS_MAGIC;
        hdr->version = LMS_WS_VERSION;
        hdr->len = lay.total;
        hdr->subtree = key->subtree_height;
        rc = lms_ws_binding(key, lay.total, hdr->binding);
        if((rc == NOXTLS_RETURN_SUCCESS) && (counter < key->max_index)) {
            rc = lms_rebuild(&w, key, &lay, counter);
        }
    }
    noxtls_secure_zero(&w, sizeof(w));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_hss_key_free(key);
        return rc;
    }
    key->state = LMS_KEY_STATE_READY;
    return NOXTLS_RETURN_SUCCESS;
}

/* Persist counter = min(next_index + count, max) if it extends the reservation. */
static noxtls_return_t lms_persist(noxtls_hss_key_t *key, uint32_t count)
{
    uint8_t blob[NOXTLS_HSS_PRIVATE_KEY_LEN];
    lms_tree_param_t tp;
    uint64_t target = key->next_index + (uint64_t)count;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((target > key->max_index) || (target < key->next_index)) {
        target = key->max_index;
    }
    if(target <= key->reserved_index) {
        return NOXTLS_RETURN_SUCCESS;
    }
    (void)lms_tree_param(key->params.lms_type[0], &tp);
    rc = lms_blob_write(&key->params, target, key->id[0], key->seed[0], key->root, tp.n, blob);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = key->persist(key->persist_user, blob, NOXTLS_HSS_PRIVATE_KEY_LEN);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            key->reserved_index = target;
        }
        /* otherwise the callback's error code is returned unchanged */
    }
    noxtls_secure_zero(blob, sizeof(blob));
    return rc;
}

noxtls_return_t noxtls_hss_key_reserve(noxtls_hss_key_t *key, uint32_t count)
{
    if(key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(key->state != LMS_KEY_STATE_READY) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
    if(count == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(key->next_index >= key->max_index) {
        return NOXTLS_RETURN_KEY_EXHAUSTED;
    }
    return lms_persist(key, count);
}

noxtls_return_t noxtls_hss_key_set_reserve(noxtls_hss_key_t *key, uint32_t count)
{
    if(key == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(key->state != LMS_KEY_STATE_READY) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
    if(count == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    key->reserve = count;
    return NOXTLS_RETURN_SUCCESS;
}

uint64_t noxtls_hss_key_remaining(const noxtls_hss_key_t *key)
{
    if((key == NULL) || (key->state != LMS_KEY_STATE_READY) || (key->next_index >= key->max_index)) {
        return 0U;
    }
    return key->max_index - key->next_index;
}

noxtls_return_t noxtls_hss_key_public_key(const noxtls_hss_key_t *key, uint8_t *public_key,
                                          uint32_t public_key_cap, uint32_t *public_key_len)
{
    lms_tree_param_t tp;
    uint32_t len = 0U;
    uint32_t off = 0U;

    if((key == NULL) || (public_key == NULL) || (public_key_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    *public_key_len = 0U;
    if(key->state != LMS_KEY_STATE_READY) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
    len = noxtls_hss_public_key_len(&key->params);
    if(public_key_cap < len) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    (void)lms_tree_param(key->params.lms_type[0], &tp);
    if(key->params.format == NOXTLS_LMS_FORMAT_HSS) {
        lms_put32(public_key, key->params.levels);
        off = 4U;
    }
    lms_pub_write(&public_key[off], key->params.lms_type[0], key->params.ots_type[0], key->id[0], key->root, tp.n);
    *public_key_len = len;
    return NOXTLS_RETURN_SUCCESS;
}

/*
 * Signing is split into frames that never nest (core signing, the self-check
 * verification and the traversal update), so the peak stack is the largest
 * of them rather than their sum.
 */
static LMS_NOINLINE noxtls_return_t lms_sign_core(noxtls_hss_key_t *key, const lms_ws_layout_t *lay, uint64_t g,
                                                  const uint8_t *message, uint32_t message_len, uint8_t *signature)
{
    lms_work_t w;
    lms_tree_t t;
    uint32_t off = 0U;
    uint32_t i = 0U;
    noxtls_return_t rc = lms_prepare(&w, key, lay, g);

    /* signed public keys of the upper levels, then the bottom signature */
    if(rc == NOXTLS_RETURN_SUCCESS) {
        if(key->params.format == NOXTLS_LMS_FORMAT_HSS) {
            lms_put32(signature, key->params.levels - 1U);
            off = 4U;
        }
        for(i = 0U; (i + 1U) < key->params.levels; i += 1U) {
            noxtls_copy_u8(&signature[off], (size_t)lay->spk_len[i], &key->ws[lay->spk_off[i]],
                           (size_t)lay->spk_len[i]);
            off += lay->spk_len[i];
        }
        lms_key_tree(key, lay, key->params.levels - 1U, &t);
        if(t.meta->next_leaf != lms_level_q(&key->params, key->params.levels - 1U, g)) {
            rc = NOXTLS_RETURN_FAILED;
        } else {
            rc = lms_tree_sign(&w, &t, message, message_len, &signature[off]);
        }
    }
    noxtls_secure_zero(&w, sizeof(w));
    return rc;
}

static LMS_NOINLINE noxtls_return_t lms_sign_selfcheck(const noxtls_hss_key_t *key, const uint8_t *message,
                                                       uint32_t message_len, const uint8_t *signature,
                                                       uint32_t signature_len)
{
    uint8_t pk[NOXTLS_HSS_MAX_PUBLIC_KEY_LEN];
    uint32_t pk_len = 0U;
    noxtls_return_t rc = noxtls_hss_key_public_key(key, pk, (uint32_t)sizeof(pk), &pk_len);

    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_hss_verify(key->params.format, pk, pk_len, message, message_len, signature, signature_len);
    }
    return (rc == NOXTLS_RETURN_SUCCESS) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
}

static LMS_NOINLINE noxtls_return_t lms_sign_advance(noxtls_hss_key_t *key, const lms_ws_layout_t *lay)
{
    lms_work_t w;
    noxtls_return_t rc = lms_advance_one(&w, key, lay);

    noxtls_secure_zero(&w, sizeof(w));
    return rc;
}

noxtls_return_t noxtls_hss_sign(noxtls_hss_key_t *key,
                                const uint8_t *message, uint32_t message_len,
                                uint8_t *signature, uint32_t signature_cap,
                                uint32_t *signature_len)
{
    lms_ws_layout_t lay;
    uint32_t need = 0U;
    uint64_t g = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(signature_len != NULL) {
        *signature_len = 0U;
    }
    if((key == NULL) || (signature == NULL) || (signature_len == NULL) ||
       ((message == NULL) && (message_len != 0U))) {
        return NOXTLS_RETURN_NULL;
    }
    if((key->state != LMS_KEY_STATE_READY) || (key->persist == NULL)) {
        return NOXTLS_RETURN_NOT_INITIALIZED;
    }
    need = noxtls_hss_signature_len(&key->params);
    if(signature_cap < need) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(key->next_index >= key->max_index) {
        return NOXTLS_RETURN_KEY_EXHAUSTED;
    }
    rc = lms_ws_layout(&key->params, key->subtree_height, &lay);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    /* 1. Make sure index next_index is covered by persisted state. */
    if(key->next_index >= key->reserved_index) {
        rc = lms_persist(key, key->reserve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    /* 2. Consume the index before computing anything with it. */
    g = key->next_index;
    key->next_index = g + 1U;
    rc = lms_sign_core(key, &lay, g, message, message_len, signature);
    /* 3. Self-check against the public key before release. */
    if((rc == NOXTLS_RETURN_SUCCESS) && ((key->flags & NOXTLS_HSS_KEY_NO_SELF_VERIFY) == 0U)) {
        rc = lms_sign_selfcheck(key, message, message_len, signature, need);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(signature, (size_t)signature_cap);
        lms_ws_hdr(key)->valid = 0U;
        return rc;
    }
    /* 4. Prepare the traversal for the next index (failures only force a rebuild). */
    if(lms_sign_advance(key, &lay) != NOXTLS_RETURN_SUCCESS) {
        lms_ws_hdr(key)->valid = 0U;
    }
    *signature_len = need;
    return NOXTLS_RETURN_SUCCESS;
}

/* ======================================================================== */
/* Legacy preset API                                                        */
/* ======================================================================== */

noxtls_return_t noxtls_hss_params_from_preset(noxtls_lms_param_t param, noxtls_hss_params_t *params)
{
    uint32_t lms_type = 0U;
    uint32_t levels = 1U;
    uint32_t i = 0U;

    if(params == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    noxtls_secure_zero(params, sizeof(*params));
    switch(param) {
        case NOXTLS_LMS_SHA256_M32_H5:
            lms_type = NOXTLS_LMS_TYPE_SHA256_M32_H5;
            break;
        case NOXTLS_LMS_SHA256_M32_H10:
            lms_type = NOXTLS_LMS_TYPE_SHA256_M32_H10;
            break;
        case NOXTLS_LMS_SHA256_M32_H15:
            lms_type = NOXTLS_LMS_TYPE_SHA256_M32_H15;
            break;
        case NOXTLS_HSS_SHA256_M32_H10_D2:
            lms_type = NOXTLS_LMS_TYPE_SHA256_M32_H10;
            levels = 2U;
            break;
        case NOXTLS_HSS_SHA256_M32_H15_D2:
            lms_type = NOXTLS_LMS_TYPE_SHA256_M32_H15;
            levels = 2U;
            break;
        default:
            return NOXTLS_RETURN_INVALID_PARAM;
    }
    params->format = (levels == 1U) ? NOXTLS_LMS_FORMAT_LMS : NOXTLS_LMS_FORMAT_HSS;
    params->levels = levels;
    for(i = 0U; i < levels; i += 1U) {
        params->lms_type[i] = lms_type;
        params->ots_type[i] = NOXTLS_LMOTS_TYPE_SHA256_N32_W8;
    }
    return NOXTLS_RETURN_SUCCESS;
}

uint32_t noxtls_lms_public_key_len(noxtls_lms_param_t param)
{
    noxtls_hss_params_t p;

    if(noxtls_hss_params_from_preset(param, &p) != NOXTLS_RETURN_SUCCESS) {
        return 0U;
    }
    return noxtls_hss_public_key_len(&p);
}

uint32_t noxtls_lms_secret_key_len(noxtls_lms_param_t param)
{
    noxtls_hss_params_t p;

    if(noxtls_hss_params_from_preset(param, &p) != NOXTLS_RETURN_SUCCESS) {
        return 0U;
    }
    return NOXTLS_HSS_PRIVATE_KEY_LEN;
}

uint32_t noxtls_lms_signature_len(noxtls_lms_param_t param)
{
    noxtls_hss_params_t p;

    if(noxtls_hss_params_from_preset(param, &p) != NOXTLS_RETURN_SUCCESS) {
        return 0U;
    }
    return noxtls_hss_signature_len(&p);
}

noxtls_return_t noxtls_lms_keygen(noxtls_lms_param_t param,
                                  uint8_t *public_key,
                                  uint32_t public_key_len,
                                  uint8_t *secret_key,
                                  uint32_t secret_key_len)
{
    noxtls_hss_params_t p;
    noxtls_return_t rc = noxtls_hss_params_from_preset(param, &p);

    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if((public_key == NULL) || (secret_key == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if((public_key_len != noxtls_hss_public_key_len(&p)) || (secret_key_len != NOXTLS_HSS_PRIVATE_KEY_LEN)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    return noxtls_hss_keygen(&p, NULL, NULL, public_key, public_key_len, secret_key, secret_key_len);
}

noxtls_return_t noxtls_lms_sign(noxtls_lms_param_t param,
                                const uint8_t *secret_key,
                                const uint8_t *message,
                                uint32_t message_len,
                                uint8_t *signature,
                                uint32_t *signature_len)
{
    (void)param;
    (void)secret_key;
    (void)message;
    (void)message_len;
    (void)signature;
    if(signature_len != NULL) {
        *signature_len = 0U;
    }
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_lms_verify(noxtls_lms_param_t param,
                                  const uint8_t *public_key,
                                  const uint8_t *message,
                                  uint32_t message_len,
                                  const uint8_t *signature,
                                  uint32_t signature_len)
{
    noxtls_hss_params_t p;
    uint32_t pk_len = 0U;
    uint32_t off = 0U;
    uint32_t i = 0U;
    noxtls_return_t rc = noxtls_hss_params_from_preset(param, &p);

    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if((public_key == NULL) || (signature == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    pk_len = noxtls_hss_public_key_len(&p);
    if(p.format == NOXTLS_LMS_FORMAT_HSS) {
        if(lms_get32(public_key) != p.levels) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
        off = 4U;
    }
    if((lms_get32(&public_key[off]) != p.lms_type[0]) || (lms_get32(&public_key[off + 4U]) != p.ots_type[0])) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(signature_len != noxtls_hss_signature_len(&p)) {
        return NOXTLS_RETURN_FAILED;
    }
    /* Signed lower-level keys must use the preset's types as well. */
    off = (p.format == NOXTLS_LMS_FORMAT_HSS) ? 4U : 0U;
    for(i = 0U; (i + 1U) < p.levels; i += 1U) {
        off += noxtls_lms_type_signature_len(p.lms_type[i], p.ots_type[i]);
        if((lms_get32(&signature[off]) != p.lms_type[i + 1U]) ||
           (lms_get32(&signature[off + 4U]) != p.ots_type[i + 1U])) {
            return NOXTLS_RETURN_FAILED;
        }
        off += 24U + 32U;
    }
    return noxtls_hss_verify(p.format, public_key, pk_len, message, message_len, signature, signature_len);
}

#endif /* NOXTLS_FEATURE_LMS_HSS */
