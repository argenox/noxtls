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
* File:    noxtls_xmss_hash.c
* Summary: XMSS hash functions F, H, H_msg, PRF and PRF_keygen (RFC 8391
*          Section 5.1, SP 800-208 Section 5) over SHA-256 (n = 32, and n = 24
*          truncated), SHA-512, SHAKE128 and SHAKE256, plus the hash address
*          helpers.
*
*****************************************************************************/

#include <stdint.h>

#include "noxtls_xmss_internal.h"
#include "common/noxtls_ct.h"
#include "mdigest/sha256/noxtls_sha256.h"

#if NOXTLS_FEATURE_XMSS

/* Zero bytes for the toByte(X, pad) prefixes (pad <= 64). */
static const uint8_t g_xmss_zero[64] = { 0U };

/* ---- small helpers ----------------------------------------------------- */

uint64_t xmss_load_be(const uint8_t *in, uint32_t len)
{
    uint64_t v = 0U;
    uint32_t i = 0U;

    for(i = 0U; i < len; i += 1U) {
        v = (v << 8U) | (uint64_t)in[i];
    }
    return v;
}

void xmss_store_be(uint8_t *out, uint32_t len, uint64_t v)
{
    uint32_t i = len;
    uint64_t x = v;

    while(i > 0U) {
        i -= 1U;
        out[i] = (uint8_t)(x & 0xFFU);
        x >>= 8U;
    }
}

void xmss_copy(uint8_t *dst, const uint8_t *src, uint32_t len)
{
    uint32_t i = 0U;

    if(dst == src) {
        return;
    }
    for(i = 0U; i < len; i += 1U) {
        dst[i] = src[i];
    }
}

void xmss_adrs_set_word(uint8_t adrs[XMSS_ADRS_LEN], uint32_t word, uint32_t value)
{
    xmss_store_be(&adrs[word * 4U], 4U, (uint64_t)value);
}

void xmss_adrs_set_tree(uint8_t adrs[XMSS_ADRS_LEN], uint64_t tree)
{
    xmss_store_be(&adrs[4], 8U, tree);
}

void xmss_adrs_init(uint8_t adrs[XMSS_ADRS_LEN], uint32_t layer, uint64_t tree, uint32_t type)
{
    uint32_t i = 0U;

    for(i = 0U; i < XMSS_ADRS_LEN; i += 1U) {
        adrs[i] = 0U;
    }
    xmss_adrs_set_word(adrs, XMSS_ADRS_W_LAYER, layer);
    xmss_adrs_set_tree(adrs, tree);
    xmss_adrs_set_word(adrs, XMSS_ADRS_W_TYPE, type);
}

/* ---- hash core --------------------------------------------------------- */

static noxtls_return_t xmss_h_init(noxtls_xmss_hash_state_t *hs, uint8_t hash)
{
    hs->hash = hash;
    switch(hash) {
#if NOXTLS_XMSS_ENABLE_SHA2
        case NOXTLS_XMSS_HASH_SHA256:
            return noxtls_sha256_init(&hs->u.sha2, NOXTLS_HASH_SHA_256);
#if NOXTLS_XMSS_HAVE_SHA512
        case NOXTLS_XMSS_HASH_SHA512:
            return noxtls_sha512_init(&hs->u.sha512, NOXTLS_HASH_SHA_512);
#endif
#endif
#if NOXTLS_XMSS_HAVE_SHAKE
        case NOXTLS_XMSS_HASH_SHAKE128:
            return noxtls_shake128_init(&hs->u.shake);
        case NOXTLS_XMSS_HASH_SHAKE256:
            return noxtls_shake256_init(&hs->u.shake);
#endif
        default:
            return NOXTLS_RETURN_NOT_SUPPORTED;
    }
}

static noxtls_return_t xmss_h_update(noxtls_xmss_hash_state_t *hs, const uint8_t *data, uint32_t len)
{
    if(len == 0U) {
        return NOXTLS_RETURN_SUCCESS;
    }
    switch(hs->hash) {
#if NOXTLS_XMSS_ENABLE_SHA2
        case NOXTLS_XMSS_HASH_SHA256:
            return noxtls_sha256_update(&hs->u.sha2, data, len);
#if NOXTLS_XMSS_HAVE_SHA512
        case NOXTLS_XMSS_HASH_SHA512:
            return noxtls_sha512_update(&hs->u.sha512, data, len);
#endif
#endif
#if NOXTLS_XMSS_HAVE_SHAKE
        case NOXTLS_XMSS_HASH_SHAKE128:
            return noxtls_shake128_update(&hs->u.shake, data, len);
        case NOXTLS_XMSS_HASH_SHAKE256:
            return noxtls_shake256_update(&hs->u.shake, data, len);
#endif
        default:
            return NOXTLS_RETURN_NOT_SUPPORTED;
    }
}

/* Finish and write the first n bytes of the digest (SHA-256/192 truncation). */
static noxtls_return_t xmss_h_final(noxtls_xmss_hash_state_t *hs, uint32_t n, uint8_t *out)
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;

    switch(hs->hash) {
#if NOXTLS_XMSS_ENABLE_SHA2
        case NOXTLS_XMSS_HASH_SHA256:
            if(n == 32U) {
                rc = noxtls_sha256_finish(&hs->u.sha2, out);
            } else {
                uint8_t full[32];
                rc = noxtls_sha256_finish(&hs->u.sha2, full);
                xmss_copy(out, full, n);
                noxtls_secure_zero(full, sizeof(full));
            }
            break;
#if NOXTLS_XMSS_HAVE_SHA512
        case NOXTLS_XMSS_HASH_SHA512:
            rc = noxtls_sha512_finish(&hs->u.sha512, out);
            break;
#endif
#endif
#if NOXTLS_XMSS_HAVE_SHAKE
        case NOXTLS_XMSS_HASH_SHAKE128:
            rc = noxtls_shake128_final(&hs->u.shake);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                rc = noxtls_shake128_squeeze(&hs->u.shake, out, n);
            }
            break;
        case NOXTLS_XMSS_HASH_SHAKE256:
            rc = noxtls_shake256_final(&hs->u.shake);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                rc = noxtls_shake256_squeeze(&hs->u.shake, out, n);
            }
            break;
#endif
        default:
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
            break;
    }
    return rc;
}

/* Remove what a finished hash keeps of its (possibly secret) input. */
static void xmss_h_wipe(noxtls_xmss_hash_state_t *hs)
{
    switch(hs->hash) {
#if NOXTLS_XMSS_ENABLE_SHA2
        case NOXTLS_XMSS_HASH_SHA256:
            noxtls_secure_zero(hs->u.sha2.u.md32.h, sizeof(hs->u.sha2.u.md32.h));
            break;
#if NOXTLS_XMSS_HAVE_SHA512
        case NOXTLS_XMSS_HASH_SHA512:
            noxtls_secure_zero(hs->u.sha512.h, sizeof(hs->u.sha512.h));
            break;
#endif
#endif
        default:
            noxtls_secure_zero(hs, sizeof(*hs));
            break;
    }
}

/* Absorb toByte(x, pad). */
static noxtls_return_t xmss_h_pad(noxtls_xmss_hash_state_t *hs, const xmss_params_t *p, uint8_t x)
{
    noxtls_return_t rc = xmss_h_update(hs, g_xmss_zero, (uint32_t)p->pad - 1U);

    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = xmss_h_update(hs, &x, 1U);
    }
    return rc;
}

#if NOXTLS_XMSS_ENABLE_SHA2
/* Save / restore the chaining value after exactly one block (SHA-256 or SHA-512). */
static void xmss_mid_save(const noxtls_xmss_hash_state_t *hs, xmss_hctx_t *hc, uint8_t which)
{
    uint32_t i = 0U;

    for(i = 0U; i < 8U; i += 1U) {
#if NOXTLS_XMSS_HAVE_SHA512
        uint64_t v = (hs->hash == NOXTLS_XMSS_HASH_SHA512) ? hs->u.sha512.h[i] : (uint64_t)hs->u.sha2.u.md32.h[i];
#else
        uint32_t v = hs->u.sha2.u.md32.h[i];
#endif
        if(which == 0U) {
            hc->prf_mid[i] = v;
        } else {
            hc->kg_mid[i] = v;
        }
    }
}

static noxtls_return_t xmss_mid_start(noxtls_xmss_hash_state_t *hs, const xmss_hctx_t *hc, uint8_t which)
{
    uint32_t i = 0U;
    noxtls_return_t rc = xmss_h_init(hs, hc->p->hash);

    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
#if NOXTLS_XMSS_HAVE_SHA512
    if(hs->hash == NOXTLS_XMSS_HASH_SHA512) {
        for(i = 0U; i < 8U; i += 1U) {
            hs->u.sha512.h[i] = (which == 0U) ? hc->prf_mid[i] : hc->kg_mid[i];
        }
        hs->u.sha512.length = 128U;
        return NOXTLS_RETURN_SUCCESS;
    }
#endif
    for(i = 0U; i < 8U; i += 1U) {
        hs->u.sha2.u.md32.h[i] = (uint32_t)((which == 0U) ? hc->prf_mid[i] : hc->kg_mid[i]);
    }
    hs->u.sha2.u.md32.length = 64U;
    return NOXTLS_RETURN_SUCCESS;
}
#endif

noxtls_return_t xmss_hctx_init(xmss_hctx_t *hc, const xmss_params_t *p, const uint8_t *pub_seed, const uint8_t *sk_seed)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    noxtls_secure_zero(hc, sizeof(*hc));
    hc->p = p;
    hc->pub_seed = pub_seed;
    hc->sk_seed = sk_seed;
#if NOXTLS_XMSS_ENABLE_SHA2
    /* toByte(X, n) || seed fills exactly one block for SHA-256 n = 32 and SHA-512 n = 64. */
    if(((p->hash == NOXTLS_XMSS_HASH_SHA256) && (p->n == 32U)) ||
       ((p->hash == NOXTLS_XMSS_HASH_SHA512) && (p->n == 64U))) {
        noxtls_xmss_hash_state_t hs;

        rc = xmss_h_init(&hs, p->hash);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = xmss_h_pad(&hs, p, (uint8_t)XMSS_PAD_PRF);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = xmss_h_update(&hs, pub_seed, p->n);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            xmss_mid_save(&hs, hc, 0U);
            hc->prf_mid_ok = 1U;
        }
        if((rc == NOXTLS_RETURN_SUCCESS) && (sk_seed != NULL)) {
            rc = xmss_h_init(&hs, p->hash);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                rc = xmss_h_pad(&hs, p, (uint8_t)XMSS_PAD_PRF_KEYGEN);
            }
            if(rc == NOXTLS_RETURN_SUCCESS) {
                rc = xmss_h_update(&hs, sk_seed, p->n);
            }
            if(rc == NOXTLS_RETURN_SUCCESS) {
                xmss_mid_save(&hs, hc, 1U);
                hc->kg_mid_ok = 1U;
            }
        }
        noxtls_secure_zero(&hs, sizeof(hs));
    }
#endif
    return rc;
}

void xmss_hctx_wipe(xmss_hctx_t *hc)
{
    noxtls_secure_zero(hc, sizeof(*hc));
}

/*
 * PRF(PUB_SEED, ADRS) = H_n(toByte(3, pad) || PUB_SEED || ADRS).  hs is the
 * caller's hash state, reused so that only one hash context is live on the
 * stack at a time.
 */
static noxtls_return_t xmss_prf_seed(const xmss_hctx_t *hc, const uint8_t adrs[XMSS_ADRS_LEN], uint8_t *out,
                                     noxtls_xmss_hash_state_t *hs)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    const xmss_params_t *p = hc->p;

#if NOXTLS_XMSS_ENABLE_SHA2
    if(hc->prf_mid_ok != 0U) {
        rc = xmss_mid_start(hs, hc, 0U);
    } else
#endif
    {
        rc = xmss_h_init(hs, p->hash);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = xmss_h_pad(hs, p, (uint8_t)XMSS_PAD_PRF);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = xmss_h_update(hs, hc->pub_seed, p->n);
        }
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = xmss_h_update(hs, adrs, XMSS_ADRS_LEN);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = xmss_h_final(hs, p->n, out);
    }
    return rc;
}

noxtls_return_t xmss_thash_f(const xmss_hctx_t *hc, uint8_t adrs[XMSS_ADRS_LEN], const uint8_t *in, uint8_t *out)
{
    noxtls_xmss_hash_state_t hs;
    uint8_t key[NOXTLS_XMSS_MAX_N];
    uint8_t buf[NOXTLS_XMSS_MAX_N];
    const xmss_params_t *p = hc->p;
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    xmss_adrs_set_word(adrs, XMSS_ADRS_W_KEYMASK, 0U);
    rc = xmss_prf_seed(hc, adrs, key, &hs);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        xmss_adrs_set_word(adrs, XMSS_ADRS_W_KEYMASK, 1U);
        rc = xmss_prf_seed(hc, adrs, buf, &hs);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        for(i = 0U; i < p->n; i += 1U) {
            buf[i] ^= in[i];
        }
        rc = xmss_h_init(&hs, p->hash);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = xmss_h_pad(&hs, p, (uint8_t)XMSS_PAD_F);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = xmss_h_update(&hs, key, p->n);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = xmss_h_update(&hs, buf, p->n);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = xmss_h_final(&hs, p->n, out);
        }
        if(hc->sk_seed != NULL) {
            /* Chain values below the released position are secret. */
            xmss_h_wipe(&hs);
            noxtls_secure_zero(buf, sizeof(buf));
        }
    }
    return rc;
}

noxtls_return_t xmss_thash_h(const xmss_hctx_t *hc, uint8_t adrs[XMSS_ADRS_LEN],
                             const uint8_t *left, const uint8_t *right, uint8_t *out)
{
    noxtls_xmss_hash_state_t hs;
    uint8_t key[NOXTLS_XMSS_MAX_N];
    uint8_t buf[2U * NOXTLS_XMSS_MAX_N];
    const xmss_params_t *p = hc->p;
    uint32_t n = p->n;
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    xmss_adrs_set_word(adrs, XMSS_ADRS_W_KEYMASK, 0U);
    rc = xmss_prf_seed(hc, adrs, key, &hs);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        xmss_adrs_set_word(adrs, XMSS_ADRS_W_KEYMASK, 1U);
        rc = xmss_prf_seed(hc, adrs, buf, &hs);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        xmss_adrs_set_word(adrs, XMSS_ADRS_W_KEYMASK, 2U);
        rc = xmss_prf_seed(hc, adrs, &buf[n], &hs);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        for(i = 0U; i < n; i += 1U) {
            buf[i] ^= left[i];
            buf[n + i] ^= right[i];
        }
        rc = xmss_h_init(&hs, p->hash);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = xmss_h_pad(&hs, p, (uint8_t)XMSS_PAD_H);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = xmss_h_update(&hs, key, n);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = xmss_h_update(&hs, buf, 2U * n);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = xmss_h_final(&hs, n, out);
        }
    }
    return rc;
}

noxtls_return_t xmss_prf_keygen(const xmss_hctx_t *hc, const uint8_t adrs[XMSS_ADRS_LEN], uint8_t *out)
{
    noxtls_xmss_hash_state_t hs;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    const xmss_params_t *p = hc->p;

    if(hc->sk_seed == NULL) {
        return NOXTLS_RETURN_NULL;
    }
#if NOXTLS_XMSS_ENABLE_SHA2
    if(hc->kg_mid_ok != 0U) {
        rc = xmss_mid_start(&hs, hc, 1U);
    } else
#endif
    {
        rc = xmss_h_init(&hs, p->hash);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = xmss_h_pad(&hs, p, (uint8_t)XMSS_PAD_PRF_KEYGEN);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = xmss_h_update(&hs, hc->sk_seed, p->n);
        }
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = xmss_h_update(&hs, hc->pub_seed, p->n);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = xmss_h_update(&hs, adrs, XMSS_ADRS_LEN);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = xmss_h_final(&hs, p->n, out);
    }
    noxtls_secure_zero(&hs, sizeof(hs));
    return rc;
}

noxtls_return_t xmss_prf_idx(const xmss_params_t *p, const uint8_t *key, uint64_t idx, uint8_t *out)
{
    noxtls_xmss_hash_state_t hs;
    uint8_t idx32[32];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    noxtls_secure_zero(idx32, sizeof(idx32));
    xmss_store_be(&idx32[24], 8U, idx);
    rc = xmss_h_init(&hs, p->hash);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = xmss_h_pad(&hs, p, (uint8_t)XMSS_PAD_PRF);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = xmss_h_update(&hs, key, p->n);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = xmss_h_update(&hs, idx32, 32U);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = xmss_h_final(&hs, p->n, out);
    }
    noxtls_secure_zero(&hs, sizeof(hs));
    return rc;
}

noxtls_return_t xmss_hmsg_init(noxtls_xmss_hash_state_t *hs, const xmss_params_t *p,
                               const uint8_t *r, const uint8_t *root, uint64_t idx)
{
    uint8_t idxn[NOXTLS_XMSS_MAX_N];
    uint32_t i = 0U;
    noxtls_return_t rc = xmss_h_init(hs, p->hash);

    for(i = 0U; i < p->n; i += 1U) {
        idxn[i] = 0U;
    }
    xmss_store_be(&idxn[p->n - 8U], 8U, idx);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = xmss_h_pad(hs, p, (uint8_t)XMSS_PAD_HASH);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = xmss_h_update(hs, r, p->n);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = xmss_h_update(hs, root, p->n);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = xmss_h_update(hs, idxn, p->n);
    }
    return rc;
}

noxtls_return_t xmss_hmsg_update(noxtls_xmss_hash_state_t *hs, const uint8_t *data, uint32_t len)
{
    return xmss_h_update(hs, data, len);
}

noxtls_return_t xmss_hmsg_final(noxtls_xmss_hash_state_t *hs, const xmss_params_t *p, uint8_t *out)
{
    noxtls_return_t rc = xmss_h_final(hs, p->n, out);

    noxtls_secure_zero(hs, sizeof(*hs));
    return rc;
}

#endif /* NOXTLS_FEATURE_XMSS */
